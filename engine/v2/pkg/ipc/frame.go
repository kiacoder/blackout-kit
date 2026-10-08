package ipc

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Frame layout:
//
//	+--------+--------+----------------------+
//	| magic  | length | JSON body            |
//	| 4 bytes| 4 bytes| `length` bytes       |
//	+--------+--------+----------------------+
//
// magic is the ASCII string "BKV2" and length is a big-endian uint32.
//
// The magic is not decoration. A v1 client, a stale socket file or a stray
// process occasionally speaks garbage on a reused endpoint; without a tag the
// daemon would read the first four bytes as a length and allocate a nonsense
// buffer before failing. With it we reject immediately and cheaply.
var frameMagic = [4]byte{'B', 'K', 'V', '2'}

const frameHeaderSize = 8

// errBadMagic is returned when a frame does not start with the expected tag.
var errBadMagic = errors.New("ipc: bad frame magic")

// FrameTooLargeError reports a declared length above the negotiated cap.
type FrameTooLargeError struct {
	Length uint32
	Limit  uint32
}

func (e *FrameTooLargeError) Error() string {
	return fmt.Sprintf("ipc: frame length %d exceeds limit %d", e.Length, e.Limit)
}

// Is rejects a peer whose declared length is absurd before allocating.
func (e *FrameTooLargeError) Is(target error) bool {
	_, ok := target.(*FrameTooLargeError)
	return ok
}

// EncodeFrame renders an envelope as a complete wire frame.
func EncodeFrame(env *Envelope) ([]byte, error) {
	if err := env.Validate(); err != nil {
		return nil, err
	}
	body, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("ipc: marshal envelope: %w", err)
	}
	if len(body) > MaxFrameSize {
		return nil, &FrameTooLargeError{Length: uint32(len(body)), Limit: MaxFrameSize}
	}
	frame := make([]byte, frameHeaderSize+len(body))
	copy(frame[0:4], frameMagic[:])
	binary.BigEndian.PutUint32(frame[4:8], uint32(len(body)))
	copy(frame[frameHeaderSize:], body)
	return frame, nil
}

// WriteFrame encodes and writes one frame. The header and body are emitted in
// a single Write so concurrent writers on one connection cannot interleave a
// header with another goroutine's body; callers still serialise writes.
func WriteFrame(w io.Writer, env *Envelope) error {
	frame, err := EncodeFrame(env)
	if err != nil {
		return err
	}
	_, err = w.Write(frame)
	return err
}

// ReadFrame reads exactly one frame and decodes it.
//
// limit caps the declared body length. Passing 0 uses MaxFrameSize.
func ReadFrame(r io.Reader, limit uint32) (*Envelope, error) {
	if limit == 0 {
		limit = MaxFrameSize
	}
	header := make([]byte, frameHeaderSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}
	if header[0] != frameMagic[0] || header[1] != frameMagic[1] ||
		header[2] != frameMagic[2] || header[3] != frameMagic[3] {
		return nil, errBadMagic
	}
	length := binary.BigEndian.Uint32(header[4:8])
	if length > limit {
		return nil, &FrameTooLargeError{Length: length, Limit: limit}
	}
	if length == 0 {
		return nil, &Error{Code: CodeMalformedFrame, Message: "empty frame body"}
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	var env Envelope
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, &Error{Code: CodeMalformedFrame, Message: "json: " + err.Error()}
	}
	if err := env.Validate(); err != nil {
		return nil, err
	}
	return &env, nil
}

// frameReader adapts an io.Reader to framed reads with a reusable buffer.
type frameReader struct {
	src   io.Reader
	limit uint32
	buf   *bufio.Reader
}

func newFrameReader(r io.Reader, limit uint32) *frameReader {
	if limit == 0 {
		limit = MaxFrameSize
	}
	return &frameReader{src: r, limit: limit, buf: bufio.NewReaderSize(r, 64*1024)}
}

func (fr *frameReader) Read() (*Envelope, error) {
	return ReadFrame(fr.buf, fr.limit)
}

// frameWriter serialises framed writes behind one lock.
type frameWriter struct {
	dst *bufio.Writer
}

func newFrameWriter(w io.Writer) *frameWriter {
	return &frameWriter{dst: bufio.NewWriterSize(w, 64*1024)}
}

func (fw *frameWriter) Write(env *Envelope) error {
	frame, err := EncodeFrame(env)
	if err != nil {
		return err
	}
	if _, err := fw.dst.Write(frame); err != nil {
		return err
	}
	return fw.dst.Flush()
}
