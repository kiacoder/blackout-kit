package dialer

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

// buildHello synthesises a TLS ClientHello record. It is the fixture the SNI
// tests run against: a real handshake captured from Go's crypto/tls would work
// too, but a hand-built record keeps the assertions exact and offline.
func buildHello(t *testing.T, sni string, includeSNI bool) []byte {
	t.Helper()

	var exts []byte
	if includeSNI {
		host := []byte(sni)
		list := make([]byte, 2+3+len(host))
		binary.BigEndian.PutUint16(list[0:2], uint16(3+len(host)))
		list[2] = serverNameTypeHost
		binary.BigEndian.PutUint16(list[3:5], uint16(len(host)))
		copy(list[5:], host)

		ext := []byte{byte(extensionServerName >> 8), byte(extensionServerName & 0xff)}
		ext = append(ext, byte(len(list)>>8), byte(len(list)&0xff))
		ext = append(ext, list...)
		exts = append(exts, ext...)
	}
	// A second extension that must survive the rewrite untouched.
	exts = append(exts, 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04)

	hs := []byte{0x03, 0x03}                // client_version
	hs = append(hs, make([]byte, 32)...)    // random
	hs = append(hs, 0x00)                   // session_id length
	hs = append(hs, 0x00, 0x02, 0x13, 0x01) // one cipher suite
	hs = append(hs, 0x01, 0x00)             // one compression method
	hs = append(hs, byte(len(exts)>>8), byte(len(exts)&0xff))
	hs = append(hs, exts...)

	recordLen := handshakeHeaderLen + len(hs)
	rec := []byte{recordTypeHandshake, 0x03, 0x01, byte(recordLen >> 8), byte(recordLen & 0xff)}
	rec = append(rec, handshakeClientHello,
		byte(len(hs)>>16), byte(len(hs)>>8), byte(len(hs)&0xff))
	rec = append(rec, hs...)
	return rec
}

// extensionTypes lists the extension type codes present in a hello.
func extensionTypes(t *testing.T, hello []byte) []uint16 {
	t.Helper()
	_, hs, err := splitHandshake(hello)
	if err != nil {
		t.Fatalf("splitHandshake: %v", err)
	}
	_, exts, err := parseExtensions(hs)
	if err != nil {
		t.Fatalf("parseExtensions: %v", err)
	}
	var out []uint16
	for off := 0; off+4 <= len(exts); {
		typ := binary.BigEndian.Uint16(exts[off : off+2])
		ln := int(binary.BigEndian.Uint16(exts[off+2 : off+4]))
		out = append(out, typ)
		off += 4 + ln
	}
	return out
}

func TestExtractSNI(t *testing.T) {
	hello := buildHello(t, "blocked.example.com", true)
	got, err := ExtractSNI(hello)
	if err != nil {
		t.Fatalf("ExtractSNI: %v", err)
	}
	if got != "blocked.example.com" {
		t.Fatalf("SNI = %q", got)
	}
}

func TestClientHelloSNIHostBounds(t *testing.T) {
	const host = "blocked.example.com"
	hello := buildHello(t, host, true)
	wantStart := bytes.Index(hello, []byte(host))
	wantEnd := wantStart + len(host)

	start, end, ok := clientHelloSNIHostBounds(hello)
	if !ok {
		t.Fatal("clientHelloSNIHostBounds did not find the parsed hostname")
	}
	if start != wantStart || end != wantEnd {
		t.Fatalf("hostname bounds = [%d,%d), want [%d,%d)", start, end, wantStart, wantEnd)
	}

	if _, _, ok := clientHelloSNIHostBounds(buildHello(t, "", false)); ok {
		t.Fatal("clientHelloSNIHostBounds found a hostname without an SNI extension")
	}
	if _, _, ok := clientHelloSNIHostBounds([]byte{recordTypeHandshake, 0x03}); ok {
		t.Fatal("clientHelloSNIHostBounds accepted a malformed ClientHello")
	}
}

// TestRewriteSNI is the Bug #12 regression test. v1 parsed FAKE_SNI and never
// put it on the wire; this asserts the name actually changes and that the
// record is still internally consistent afterwards.
func TestRewriteSNI(t *testing.T) {
	hello := buildHello(t, "blocked.example.com", true)
	const fake = "www.microsoft.com"

	out, err := RewriteSNI(hello, fake)
	if err != nil {
		t.Fatalf("RewriteSNI: %v", err)
	}

	got, err := ExtractSNI(out)
	if err != nil {
		t.Fatalf("ExtractSNI after rewrite: %v", err)
	}
	if got != fake {
		t.Fatalf("SNI after rewrite = %q, want %q", got, fake)
	}
	if bytes.Equal(out, hello) {
		t.Fatal("rewrite produced identical bytes — SNI was not substituted")
	}
}

// TestRewriteSNIFramingStaysConsistent guards the part a naive byte swap
// breaks: every enclosing length field must be recomputed, or the server will
// mis-frame the record and reset the connection.
func TestRewriteSNIFramingStaysConsistent(t *testing.T) {
	hello := buildHello(t, "a.example", true)

	for _, fake := range []string{"b", "www.microsoft.com", "a-much-longer-fronting-name.example.org"} {
		out, err := RewriteSNI(hello, fake)
		if err != nil {
			t.Fatalf("RewriteSNI(%q): %v", fake, err)
		}
		declared := int(binary.BigEndian.Uint16(out[3:5]))
		if len(out) != recordHeaderLen+declared {
			t.Fatalf("fake %q: record declares %d bytes, buffer has %d", fake, declared, len(out)-recordHeaderLen)
		}
		if got, err := ExtractSNI(out); err != nil || got != fake {
			t.Fatalf("fake %q: re-read SNI = %q, err = %v", fake, got, err)
		}
	}
}

func TestRewriteSNIKeepsOtherExtensions(t *testing.T) {
	hello := buildHello(t, "blocked.example.com", true)
	before := extensionTypes(t, hello)

	out, err := RewriteSNI(hello, "www.microsoft.com")
	if err != nil {
		t.Fatalf("RewriteSNI: %v", err)
	}
	after := extensionTypes(t, out)

	if len(before) != len(after) {
		t.Fatalf("extension count changed: %v -> %v", before, after)
	}
	for i := range before {
		if before[i] != after[i] {
			t.Fatalf("extension %d changed: %#x -> %#x", i, before[i], after[i])
		}
	}
}

func TestRewriteSNIPreservesTrailingBytes(t *testing.T) {
	hello := buildHello(t, "blocked.example.com", true)
	tail := []byte{0x17, 0x03, 0x03, 0x00, 0x10}
	buf := append(append([]byte{}, hello...), tail...)

	out, err := RewriteSNI(buf, "www.microsoft.com")
	if err != nil {
		t.Fatalf("RewriteSNI: %v", err)
	}
	if !bytes.HasSuffix(out, tail) {
		t.Fatal("trailing bytes were dropped or altered")
	}
}

func TestRewriteSNIRejectsInvalidFake(t *testing.T) {
	hello := buildHello(t, "blocked.example.com", true)
	if _, err := RewriteSNI(hello, ""); !errors.Is(err, ErrEmptySNI) {
		t.Fatalf("err = %v, want ErrEmptySNI", err)
	}
	if _, err := RewriteSNI(hello, "has space.example"); err == nil {
		t.Fatal("expected an error for a name containing a space")
	}
}

func TestRewriteSNIWithoutExtension(t *testing.T) {
	hello := buildHello(t, "", false)
	if _, err := RewriteSNI(hello, "www.microsoft.com"); !errors.Is(err, ErrNoSNIExtension) {
		t.Fatalf("err = %v, want ErrNoSNIExtension", err)
	}
	if _, err := ExtractSNI(hello); !errors.Is(err, ErrNoSNIExtension) {
		t.Fatalf("err = %v, want ErrNoSNIExtension", err)
	}
}

func TestParseErrors(t *testing.T) {
	if _, err := ExtractSNI([]byte{0x16, 0x03, 0x01}); !errors.Is(err, ErrTruncated) {
		t.Fatalf("short buffer: err = %v, want ErrTruncated", err)
	}
	if _, err := ExtractSNI([]byte{0x17, 0x03, 0x03, 0x00, 0x02, 0x00, 0x00}); !errors.Is(err, ErrNotHandshake) {
		t.Fatalf("non-handshake: err = %v, want ErrNotHandshake", err)
	}

	// A handshake record that is not a ClientHello.
	notHello := []byte{recordTypeHandshake, 0x03, 0x03, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00}
	if _, err := ExtractSNI(notHello); !errors.Is(err, ErrNotClientHello) {
		t.Fatalf("non-ClientHello: err = %v, want ErrNotClientHello", err)
	}
}

func TestValidateSNIHost(t *testing.T) {
	if err := ValidateSNIHost("www.microsoft.com"); err != nil {
		t.Fatalf("valid host rejected: %v", err)
	}
	if err := ValidateSNIHost(""); !errors.Is(err, ErrEmptySNI) {
		t.Fatalf("empty: err = %v", err)
	}
	long := make([]byte, 256)
	for i := range long {
		long[i] = 'a'
	}
	if err := ValidateSNIHost(string(long)); err == nil {
		t.Fatal("256-byte name should be rejected")
	}
}

func TestDescribeSNI(t *testing.T) {
	if got := DescribeSNI(buildHello(t, "x.example", true)); got != "x.example" {
		t.Fatalf("DescribeSNI = %q", got)
	}
	if got := DescribeSNI(buildHello(t, "", false)); got == "" {
		t.Fatal("DescribeSNI should describe the failure, not return empty")
	}
}
