package main

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// buildClientHello assembles a minimal but structurally valid TLS 1.2
// ClientHello carrying one server_name extension, plus trailing bytes so the
// "preserve what follows the record" behaviour can be checked.
func buildClientHello(host string) []byte {
	// server_name extension: type(2) length(2) listLen(2) nameType(1) nameLen(2) host
	data := make([]byte, 0, 5+len(host))
	data = append(data, 0, 0) // list length, filled below
	data = append(data, 0x00)
	data = append(data, byte(len(host)>>8), byte(len(host)))
	data = append(data, host...)
	binary.BigEndian.PutUint16(data[0:2], uint16(len(data)-2))

	ext := make([]byte, 0, 4+len(data))
	ext = append(ext, 0x00, 0x00) // extension type: server_name
	ext = append(ext, byte(len(data)>>8), byte(len(data)))
	ext = append(ext, data...)

	// one more extension so the walk has to skip past it
	other := []byte{0x00, 0x0b, 0x00, 0x02, 0x01, 0x00} // ec_point_formats

	exts := append(append([]byte{}, ext...), other...)

	hs := make([]byte, 0, 64)
	hs = append(hs, 0x03, 0x03)            // client_version
	hs = append(hs, make([]byte, 32)...)   // random
	hs = append(hs, 0)                     // session id length
	hs = append(hs, 0x00, 0x02, 0x13, 0x01) // cipher suites
	hs = append(hs, 0x01, 0x00)            // compression: null
	hs = append(hs, byte(len(exts)>>8), byte(len(exts)))
	hs = append(hs, exts...)

	out := []byte{0x16, 0x03, 0x01, 0, 0}
	binary.BigEndian.PutUint16(out[3:5], uint16(4+len(hs)))
	out = append(out, 0x01, byte(len(hs)>>16), byte(len(hs)>>8), byte(len(hs)))
	out = append(out, hs...)
	return out
}

func TestRewriteClientHelloSNIReplacesName(t *testing.T) {
	hello := buildClientHello("real.example.com")
	trailer := []byte{0x16, 0x03, 0x03, 0x00, 0x02, 0xAA, 0xBB}
	input := append(append([]byte{}, hello...), trailer...)

	out, err := rewriteClientHelloSNI(input, "www.hcaptcha.com")
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}

	// The record must still be self-consistent.
	if out[0] != 0x16 {
		t.Fatalf("record type = %#x", out[0])
	}
	recLen := int(binary.BigEndian.Uint16(out[3:5]))
	hsLen := int(out[6])<<16 | int(out[7])<<8 | int(out[8])
	if recLen != 4+hsLen {
		t.Fatalf("record length %d != 4+handshake %d", recLen, hsLen)
	}
	if len(out) != 5+recLen+len(trailer) {
		t.Fatalf("total length %d, record says %d plus trailer %d", len(out), recLen, len(trailer))
	}

	// The name on the wire is the fake one, and the real one is gone.
	if !bytes.Contains(out, []byte("www.hcaptcha.com")) {
		t.Fatal("fake SNI missing from the rewritten hello")
	}
	if bytes.Contains(out, []byte("real.example.com")) {
		t.Fatal("real SNI still present")
	}

	// Bytes after the first record are untouched.
	if !bytes.Equal(out[5+recLen:], trailer) {
		t.Fatal("trailing bytes were modified")
	}
}

func TestRewriteClientHelloSNIHandlesShorterAndLongerNames(t *testing.T) {
	for _, fake := range []string{"a.co", "a-much-longer-fake-name-than-the-original.example"} {
		out, err := rewriteClientHelloSNI(buildClientHello("real.example.com"), fake)
		if err != nil {
			t.Fatalf("%s: %v", fake, err)
		}
		recLen := int(binary.BigEndian.Uint16(out[3:5]))
		if len(out) != 5+recLen {
			t.Fatalf("%s: length mismatch", fake)
		}
		if !bytes.Contains(out, []byte(fake)) {
			t.Fatalf("%s: not present", fake)
		}
	}
}

func TestRewriteClientHelloSNIRejectsJunk(t *testing.T) {
	if _, err := rewriteClientHelloSNI([]byte("GET / HTTP/1.1\r\n"), "x.com"); err == nil {
		t.Fatal("plain HTTP accepted as a ClientHello")
	}
	if _, err := rewriteClientHelloSNI(buildClientHello("a.com"), ""); err == nil {
		t.Fatal("empty fake SNI accepted")
	}
	if _, err := rewriteClientHelloSNI(buildClientHello("a.com"), "bad name"); err == nil {
		t.Fatal("SNI with a space accepted")
	}
}
