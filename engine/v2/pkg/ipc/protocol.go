// Package ipc implements the Blackout Kit v2 local control channel.
//
// The v1 core exposed a cgo C ABI loaded in-process through ctypes. That model
// had three structural problems this package exists to remove:
//
//   - a panic inside the Go core terminated the Python CLI;
//   - every call returned a bare int, so error context was discarded;
//   - there was no way for the core to push data back, so Python had to poll
//     TCP ports to guess whether an engine was alive.
//
// v2 replaces it with a supervised daemon speaking a framed, versioned JSON
// protocol over a local transport: a Windows named pipe or a Unix domain
// socket. No cgo, no C strings, no untracked allocations crossing a language
// boundary.
package ipc

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// APIVersion is the protocol version spoken by this build. Clients must
// request a compatible major version during the handshake.
const APIVersion = "2.0.0"

// MaxFrameSize bounds a single protocol frame. It exists because the frame
// length prefix is attacker/client controlled: without a cap a malformed peer
// could ask the daemon to allocate arbitrarily before ever sending a body.
const MaxFrameSize = 4 * 1024 * 1024

// Kind discriminates the three envelope shapes on the wire.
type Kind string

const (
	KindRequest  Kind = "request"
	KindResponse Kind = "response"
	KindEvent    Kind = "event"
)

// EngineStatus is the lifecycle state reported by the core.
type EngineStatus string

const (
	StatusIdle     EngineStatus = "idle"
	StatusStarting EngineStatus = "starting"
	StatusRunning  EngineStatus = "running"
	StatusStopping EngineStatus = "stopping"
	StatusStopped  EngineStatus = "stopped"
	StatusFailed   EngineStatus = "failed"
)

// Method names accepted by the daemon.
const (
	MethodHandshake   = "handshake"
	MethodPing        = "ping"
	MethodStart       = "start"
	MethodStop        = "stop"
	MethodTune        = "tune"
	MethodStatus      = "status"
	MethodSubscribe   = "subscribe"
	MethodUnsubscribe = "unsubscribe"
	MethodShutdown    = "shutdown"
)

// Methods is the advertised method table, used in the handshake response so a
// client can discover capabilities instead of guessing.
var Methods = []string{
	MethodHandshake,
	MethodPing,
	MethodStart,
	MethodStop,
	MethodTune,
	MethodStatus,
	MethodSubscribe,
	MethodUnsubscribe,
	MethodShutdown,
}

// Error codes. These are stable strings, not ints — the v1 ABI returned a bare
// 0/1 and every caller had to invent its own message.
const (
	CodeUnsupportedVersion = "unsupported_api_version"
	CodeUnknownMethod      = "unknown_method"
	CodeBadRequest         = "bad_request"
	CodeMalformedFrame     = "malformed_frame"
	CodeEngineFailure      = "engine_failure"
	CodeNotSubscribed      = "not_subscribed"
	CodeInternal           = "internal_error"
)

// Error is the structured wire error.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	if e.Message == "" {
		return e.Code
	}
	return e.Code + ": " + e.Message
}

// Envelope is the single top-level message shape. Requests, responses and
// events all use it; Kind plus the presence of ID/Method/Payload/Error
// disambiguates. One shape keeps the codec trivial and makes unknown-field
// handling uniform.
type Envelope struct {
	Version string          `json:"v"`
	Kind    Kind            `json:"kind"`
	ID      string          `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Payload json.RawMessage `json:"payload,omitempty"`
	Error   *Error          `json:"error,omitempty"`
	Seq     uint64          `json:"seq,omitempty"`
}

// HandshakeParams is sent by the client to open a session.
type HandshakeParams struct {
	// APIVersion is the version the client wants to speak. Empty means "whatever
	// the server supports", which is only useful for diagnostics tooling.
	APIVersion    string `json:"api_version,omitempty"`
	ClientName    string `json:"client_name,omitempty"`
	ClientVersion string `json:"client_version,omitempty"`
}

// HandshakeResult describes the daemon on the other end of the pipe.
type HandshakeResult struct {
	APIVersion string   `json:"api_version"`
	Methods    []string `json:"methods"`
	Endpoint   string   `json:"endpoint"`
	PID        int      `json:"pid"`
}

// StartParams selects an engine and hands it its per-launch configuration.
type StartParams struct {
	Engine string            `json:"engine"`
	Config map[string]string `json:"config,omitempty"`
}

// StartResult reports what actually came up.
type StartResult struct {
	Engine string `json:"engine"`
	Status string `json:"status"`
	// Listen is the bound address when the engine is a local listener
	// (socks-tunnel); empty otherwise.
	Listen string `json:"listen,omitempty"`
}

// TuneParams carries live tuning knobs. The defaults mirror the v2 dialer
// config; the point of Bug #11 remediation is that these are values, not
// constants baked into the packet path.
type TuneParams struct {
	Engine    string `json:"engine,omitempty"`
	MinChunk  int    `json:"min_chunk,omitempty"`
	MaxChunk  int    `json:"max_chunk,omitempty"`
	MinDelay  int    `json:"min_delay_us,omitempty"`
	MaxDelay  int    `json:"max_delay_us,omitempty"`
	FakeSNI   string `json:"fake_sni,omitempty"`
	Fragments *bool  `json:"fragments,omitempty"`
}

// TuneResult echoes the effective settings after clamping.
type TuneResult struct {
	MinChunk  int    `json:"min_chunk"`
	MaxChunk  int    `json:"max_chunk"`
	MinDelay  int    `json:"min_delay_us"`
	MaxDelay  int    `json:"max_delay_us"`
	FakeSNI   string `json:"fake_sni"`
	Fragments bool   `json:"fragments"`
}

// No "decoy" knob is exposed on purpose. Forging a fake ClientHello into the
// *same* TCP stream requires raw packet injection (WinDivert on Windows,
// NFQUEUE on Linux), which a userspace dialer cannot do; sending one on a
// separate connection produces a different flow tuple and does not fool any
// DPI box that tracks state per flow. The two primitives that do work from
// userspace are SNI rewriting and segmentation, and those are exposed above.
// A raw-packet decoy belongs in the v2 packet-path component, not here.

// StatusResult is the point-in-time answer to "what is running".
type StatusResult struct {
	Engine    string       `json:"engine"`
	Status    EngineStatus `json:"status"`
	UpSince   int64        `json:"up_since_ms,omitempty"`
	Telemetry Telemetry    `json:"telemetry"`
}

// Telemetry is the streaming event body. Field names are fixed by the v2 spec:
// rtt_ms, bytes_in, bytes_out, status.
type Telemetry struct {
	Engine   string       `json:"engine,omitempty"`
	Status   EngineStatus `json:"status"`
	RTTMs    float64      `json:"rtt_ms"`
	BytesIn  uint64       `json:"bytes_in"`
	BytesOut uint64       `json:"bytes_out"`
	At       int64        `json:"at_ms"`
}

// SubscribeResult confirms the telemetry stream is open.
type SubscribeResult struct {
	Subscribed bool   `json:"subscribed"`
	Endpoint   string `json:"endpoint,omitempty"`
}

// PongResult answers a ping.
type PongResult struct {
	OK bool `json:"ok"`
}

// MajorVersion returns the leading component of a semver-ish string.
func MajorVersion(v string) string {
	if v == "" {
		return ""
	}
	if i := strings.IndexByte(v, '.'); i >= 0 {
		return v[:i]
	}
	return v
}

// Compatible reports whether the client and daemon versions can talk. Rules:
// an empty client version means "accept whatever"; otherwise the major
// component must match. This is the version negotiation v1 never had — a v1
// client calling a v2 daemon used to fail with an AttributeError at runtime.
func Compatible(clientVersion, serverVersion string) bool {
	if clientVersion == "" {
		return true
	}
	return MajorVersion(clientVersion) == MajorVersion(serverVersion)
}

// ErrNoController is returned when the daemon has no engine controller wired.
var ErrNoController = errors.New("ipc: no engine controller configured")

// Validate checks the fields every well-formed frame must carry.
func (e *Envelope) Validate() error {
	if e == nil {
		return &Error{Code: CodeMalformedFrame, Message: "nil envelope"}
	}
	switch e.Kind {
	case KindRequest:
		if e.Method == "" {
			return &Error{Code: CodeBadRequest, Message: "request is missing 'method'"}
		}
	case KindResponse, KindEvent:
		// A response may be purely an error; an event may carry only a payload.
	default:
		return &Error{Code: CodeMalformedFrame, Message: fmt.Sprintf("unknown kind %q", e.Kind)}
	}
	if e.Version == "" {
		return &Error{Code: CodeBadRequest, Message: "envelope is missing 'v'"}
	}
	return nil
}

// DecodeParams unmarshals the request params into out.
func (e *Envelope) DecodeParams(out any) error {
	if len(e.Params) == 0 {
		return nil
	}
	if err := json.Unmarshal(e.Params, out); err != nil {
		return &Error{Code: CodeBadRequest, Message: "params: " + err.Error()}
	}
	return nil
}

// DecodePayload unmarshals the response/event payload into out.
func (e *Envelope) DecodePayload(out any) error {
	if len(e.Payload) == 0 {
		return nil
	}
	if err := json.Unmarshal(e.Payload, out); err != nil {
		return &Error{Code: CodeInternal, Message: "payload: " + err.Error()}
	}
	return nil
}

// NewRequest builds a request envelope.
func NewRequest(id, method string, params any) (*Envelope, error) {
	env := &Envelope{
		Version: APIVersion,
		Kind:    KindRequest,
		ID:      id,
		Method:  method,
	}
	if params != nil {
		raw, err := json.Marshal(params)
		if err != nil {
			return nil, err
		}
		env.Params = raw
	}
	return env, nil
}

// NewResponse builds a response envelope carrying a result payload.
func NewResponse(id string, payload any) (*Envelope, error) {
	env := &Envelope{Version: APIVersion, Kind: KindResponse, ID: id}
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		env.Payload = raw
	}
	return env, nil
}

// NewErrorResponse builds a response envelope carrying a structured error.
func NewErrorResponse(id string, err error) *Envelope {
	e, ok := err.(*Error)
	if !ok {
		e = &Error{Code: CodeInternal, Message: err.Error()}
	}
	return &Envelope{Version: APIVersion, Kind: KindResponse, ID: id, Error: e}
}

// NewEvent builds a telemetry/event envelope.
func NewEvent(seq uint64, payload any) (*Envelope, error) {
	env := &Envelope{Version: APIVersion, Kind: KindEvent, Seq: seq}
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		env.Payload = raw
	}
	return env, nil
}
