package ipc

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"testing"
)

func TestEncodeDecodeRoundtrip(t *testing.T) {
	env, err := NewRequest("1", MethodStart, StartParams{Engine: "sni"})
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	frame, err := EncodeFrame(env)
	if err != nil {
		t.Fatalf("EncodeFrame: %v", err)
	}

	got, err := ReadFrame(bytes.NewReader(frame), 0)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if got.Kind != KindRequest || got.Method != MethodStart || got.ID != "1" {
		t.Fatalf("roundtrip mismatch: %+v", got)
	}
	var p StartParams
	if err := got.DecodeParams(&p); err != nil {
		t.Fatalf("DecodeParams: %v", err)
	}
	if p.Engine != "sni" {
		t.Fatalf("engine = %q, want sni", p.Engine)
	}
}

func TestFrameHeaderLayout(t *testing.T) {
	env, _ := NewRequest("1", MethodPing, nil)
	frame, err := EncodeFrame(env)
	if err != nil {
		t.Fatalf("EncodeFrame: %v", err)
	}
	if string(frame[0:4]) != "BKV2" {
		t.Fatalf("magic = %q, want BKV2", frame[0:4])
	}
	declared := binary.BigEndian.Uint32(frame[4:8])
	if int(declared) != len(frame)-frameHeaderSize {
		t.Fatalf("declared length %d, body is %d bytes", declared, len(frame)-frameHeaderSize)
	}
}

func TestReadFrameRejectsBadMagic(t *testing.T) {
	frame, _ := EncodeFrame(&Envelope{Version: APIVersion, Kind: KindRequest, Method: MethodPing})
	frame[0] = 'X'
	if _, err := ReadFrame(bytes.NewReader(frame), 0); !errors.Is(err, errBadMagic) {
		t.Fatalf("err = %v, want errBadMagic", err)
	}
}

func TestReadFrameRejectsOversizedLength(t *testing.T) {
	var header [8]byte
	copy(header[0:4], frameMagic[:])
	binary.BigEndian.PutUint32(header[4:8], MaxFrameSize+1)

	_, err := ReadFrame(bytes.NewReader(header[:]), 0)
	var tooLarge *FrameTooLargeError
	if !errors.As(err, &tooLarge) {
		t.Fatalf("err = %v, want *FrameTooLargeError", err)
	}
	// The rejection must happen before any allocation of the declared size.
	if tooLarge.Length != MaxFrameSize+1 {
		t.Fatalf("length = %d, want %d", tooLarge.Length, MaxFrameSize+1)
	}
}

func TestReadFrameRejectsMalformedJSON(t *testing.T) {
	body := []byte(`{"v":"2.0.0","kind":`)
	frame := make([]byte, 8+len(body))
	copy(frame[0:4], frameMagic[:])
	binary.BigEndian.PutUint32(frame[4:8], uint32(len(body)))
	copy(frame[8:], body)

	_, err := ReadFrame(bytes.NewReader(frame), 0)
	var protoErr *Error
	if !errors.As(err, &protoErr) || protoErr.Code != CodeMalformedFrame {
		t.Fatalf("err = %v, want CodeMalformedFrame", err)
	}
}

func TestReadFrameRejectsUnknownKind(t *testing.T) {
	raw, _ := json.Marshal(map[string]any{"v": APIVersion, "kind": "nonsense"})
	frame := make([]byte, 8+len(raw))
	copy(frame[0:4], frameMagic[:])
	binary.BigEndian.PutUint32(frame[4:8], uint32(len(raw)))
	copy(frame[8:], raw)

	if _, err := ReadFrame(bytes.NewReader(frame), 0); err == nil {
		t.Fatal("expected an error for an unknown kind")
	}
}

// TestFramingOverStream proves the codec survives a real byte stream: several
// frames back to back must come back in order with no drift. A length-prefixed
// protocol that mis-frames here would desynchronise every later message.
func TestFramingOverStream(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	want := []string{"alpha", "beta", "gamma", "delta"}
	go func() {
		w := newFrameWriter(a)
		for _, id := range want {
			if err := w.Write(&Envelope{Version: APIVersion, Kind: KindRequest, ID: id, Method: MethodPing}); err != nil {
				return
			}
		}
	}()

	r := newFrameReader(b, 0)
	for _, id := range want {
		env, err := r.Read()
		if err != nil {
			t.Fatalf("read %s: %v", id, err)
		}
		if env.ID != id {
			t.Fatalf("got ID %q, want %q", env.ID, id)
		}
	}
}

func TestEnvelopeValidate(t *testing.T) {
	cases := []struct {
		name    string
		env     *Envelope
		wantErr bool
	}{
		{"request without method", &Envelope{Version: APIVersion, Kind: KindRequest}, true},
		{"request with method", &Envelope{Version: APIVersion, Kind: KindRequest, Method: MethodPing}, false},
		{"missing version", &Envelope{Kind: KindRequest, Method: MethodPing}, true},
		{"unknown kind", &Envelope{Version: APIVersion, Kind: Kind("x")}, true},
		{"event", &Envelope{Version: APIVersion, Kind: KindEvent}, false},
	}
	for _, tc := range cases {
		err := tc.env.Validate()
		if (err != nil) != tc.wantErr {
			t.Errorf("%s: err = %v, wantErr = %v", tc.name, err, tc.wantErr)
		}
	}
}

func TestVersionCompatibility(t *testing.T) {
	cases := []struct {
		client, server string
		want           bool
	}{
		{"2.0.0", "2.0.0", true},
		{"2.1.0", "2.0.0", true},  // minor drift within a major is fine
		{"1.0.0", "2.0.0", false}, // major mismatch is not
		{"", "2.0.0", true},       // diagnostics client accepts anything
		{"2", "2.0.0", true},
	}
	for _, tc := range cases {
		if got := Compatible(tc.client, tc.server); got != tc.want {
			t.Errorf("Compatible(%q, %q) = %v, want %v", tc.client, tc.server, got, tc.want)
		}
	}
}

func TestMajorVersion(t *testing.T) {
	if got := MajorVersion("2.0.0"); got != "2" {
		t.Fatalf("MajorVersion(2.0.0) = %q", got)
	}
	if got := MajorVersion(""); got != "" {
		t.Fatalf("MajorVersion(\"\") = %q", got)
	}
	if got := MajorVersion("2"); got != "2" {
		t.Fatalf("MajorVersion(2) = %q", got)
	}
}
