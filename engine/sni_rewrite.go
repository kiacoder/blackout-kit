package main

// TLS ClientHello SNI rewriting for the native SNI engine.
//
// The engine parsed FAKE_SNI out of its config and never used it: handleClient
// only ever received (ConnectIP, ConnectPort), so the advertised "SNI
// spoofing" was a plain TCP relay that chopped the first write into 10-byte
// pieces. The fake name never reached the wire.
//
// This is the missing half: locate the server_name extension inside the real
// ClientHello, replace it, and recompute every enclosing length field. A
// byte-for-byte substitution would leave the record claiming its old length
// and break the handshake.

import (
	"encoding/binary"
	"errors"
	"fmt"
)

var (
	errSNITruncated     = errors.New("sni: truncated TLS record")
	errSNINotHandshake  = errors.New("sni: not a TLS handshake record")
	errSNINotClientHello = errors.New("sni: not a ClientHello")
	errSNINoExtension   = errors.New("sni: ClientHello has no SNI extension")
	errSNIEmpty         = errors.New("sni: replacement SNI is empty")
)

const (
	tlsRecordHandshake = 0x16
	tlsClientHello     = 0x01
	tlsExtServerName   = 0x0000
)

// validateSNIHost rejects names that would corrupt the record. RFC 6066 caps a
// host_name at 255 bytes and it must not carry NUL or whitespace.
func validateSNIHost(host string) error {
	if host == "" {
		return errSNIEmpty
	}
	if len(host) > 255 {
		return fmt.Errorf("sni: %q exceeds 255 bytes", host)
	}
	for _, r := range host {
		switch r {
		case 0, ' ', '\t', '\n', '\r':
			return fmt.Errorf("sni: %q contains an illegal character", host)
		}
	}
	return nil
}

// rewriteClientHelloSNI returns a copy of b whose ClientHello server_name is
// replaced by fake. Bytes after the first record are preserved verbatim.
func rewriteClientHelloSNI(b []byte, fake string) ([]byte, error) {
	if err := validateSNIHost(fake); err != nil {
		return nil, err
	}
	if len(b) < 5+4 {
		return nil, errSNITruncated
	}
	if b[0] != tlsRecordHandshake {
		return nil, errSNINotHandshake
	}
	recLen := int(binary.BigEndian.Uint16(b[3:5]))
	if len(b) < 5+recLen {
		return nil, errSNITruncated
	}
	if b[5] != tlsClientHello {
		return nil, errSNINotClientHello
	}
	hsLen := int(b[6])<<16 | int(b[7])<<8 | int(b[8])
	if 4+hsLen > recLen {
		return nil, errSNITruncated
	}

	// handshake body, starting at client_version
	hs := b[9 : 9+hsLen]
	if len(hs) < 34 {
		return nil, errSNITruncated
	}
	off := 34 // client_version(2) + random(32)
	if off >= len(hs) {
		return nil, errSNITruncated
	}
	sidLen := int(hs[off])
	off++
	if off+sidLen+2 > len(hs) {
		return nil, errSNITruncated
	}
	off += sidLen
	csLen := int(binary.BigEndian.Uint16(hs[off:]))
	off += 2
	if off+csLen+1 > len(hs) {
		return nil, errSNITruncated
	}
	off += csLen
	compLen := int(hs[off])
	off++
	if off+compLen+2 > len(hs) {
		return nil, errSNITruncated
	}
	off += compLen
	extLen := int(binary.BigEndian.Uint16(hs[off:]))
	extLenOff := off
	extStart := off + 2
	if extStart+extLen > len(hs) {
		return nil, errSNITruncated
	}
	exts := hs[extStart : extStart+extLen]

	// Walk the extension list looking for server_name.
	pos := 0
	for pos+4 <= len(exts) {
		extType := binary.BigEndian.Uint16(exts[pos:])
		length := int(binary.BigEndian.Uint16(exts[pos+2:]))
		dataStart := pos + 4
		dataEnd := dataStart + length
		if dataEnd > len(exts) {
			return nil, errSNITruncated
		}
		if extType == tlsExtServerName {
			// server_name_list(2) | name_type(1) | host_name(2 + n)
			data := exts[dataStart:dataEnd]
			if len(data) < 5 || data[2] != 0x00 {
				return nil, errSNINoExtension
			}
			nameLen := int(binary.BigEndian.Uint16(data[3:]))
			if 5+nameLen > len(data) {
				return nil, errSNITruncated
			}

			newName := []byte(fake)
			newData := make([]byte, 0, 5+len(newName))
			newData = append(newData, 0, 0) // list length, filled below
			newData = append(newData, 0x00)
			newData = append(newData, byte(len(newName)>>8), byte(len(newName)))
			newData = append(newData, newName...)
			binary.BigEndian.PutUint16(newData[0:2], uint16(len(newData)-2))

			// Rebuild the extensions block with the new extension length.
			newExts := make([]byte, 0, len(exts)+len(newData)-length)
			newExts = append(newExts, exts[:pos]...)
			newExts = append(newExts, 0x00, 0x00) // extension type, filled below
			binary.BigEndian.PutUint16(newExts[len(newExts)-2:], tlsExtServerName)
			newExts = append(newExts, byte(len(newData)>>8), byte(len(newData)))
			newExts = append(newExts, newData...)
			newExts = append(newExts, exts[dataEnd:]...)

			// hs[:extLenOff] is everything before extensions_length.
			newHS := make([]byte, 0, extLenOff+2+len(newExts))
			newHS = append(newHS, hs[:extLenOff]...)
			newHS = append(newHS, byte(len(newExts)>>8), byte(len(newExts)))
			newHS = append(newHS, newExts...)

			// record = 5-byte header + 4-byte handshake header + body
			out := make([]byte, 0, 9+len(newHS)+len(b)-(9+hsLen))
			out = append(out, b[:5]...)
			out = append(out, b[5:9]...)
			out = append(out, newHS...)
			out = append(out, b[9+hsLen:]...)

			binary.BigEndian.PutUint16(out[3:5], uint16(4+len(newHS)))
			out[6] = byte(len(newHS) >> 16)
			out[7] = byte(len(newHS) >> 8)
			out[8] = byte(len(newHS))
			return out, nil
		}
		pos = dataEnd
	}
	return nil, errSNINoExtension
}
