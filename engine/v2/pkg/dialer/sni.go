// Package dialer implements the v2 packet-shaping layer: raw socket options,
// TLS ClientHello segmentation, and genuine SNI rewriting.
//
// Bug #12 (v1): engine/sni.go parsed FAKE_SNI out of its config and then never
// used it. handleClient only ever received (ConnectIP, ConnectPort), so the
// advertised "SNI spoofing" was in fact a plain TCP relay that chopped the
// first write into 10-byte pieces. The fake name never reached the wire.
//
// This package fixes that by rewriting the Server Name Indication inside the
// real ClientHello before it is sent. That is the actual evasion: a DPI box
// keying on the SNI of an outbound handshake sees the innocuous name, while
// the connection still completes normally against the fronting endpoint.
package dialer

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// TLS wire constants.
const (
	recordTypeHandshake   = 0x16
	handshakeClientHello  = 0x01
	extensionServerName   = 0x0000
	serverNameTypeHost    = 0x00
	recordHeaderLen       = 5
	handshakeHeaderLen    = 4
	clientHelloFixedBytes = 2 + 32 // client_version + random
)

var (
	// ErrTruncated means the buffer ends mid-record; callers should read more
	// and retry rather than treat it as fatal.
	ErrTruncated = errors.New("dialer: truncated TLS record")
	// ErrNotHandshake means the first byte is not 0x16.
	ErrNotHandshake = errors.New("dialer: not a TLS handshake record")
	// ErrNotClientHello means the record is a handshake but not a ClientHello.
	ErrNotClientHello = errors.New("dialer: not a ClientHello")
	// ErrNoSNIExtension means the hello carries no server_name extension, so
	// there is nothing to rewrite.
	ErrNoSNIExtension = errors.New("dialer: ClientHello has no SNI extension")
	// ErrEmptySNI rejects an empty replacement name.
	ErrEmptySNI = errors.New("dialer: replacement SNI is empty")
)

// ValidateSNIHost rejects names that would corrupt the record: RFC 6066 caps a
// host_name at 255 bytes and it must not contain NUL or whitespace, since a
// DPI box or server will reject (or a parser will mis-frame) a malformed name.
func ValidateSNIHost(host string) error {
	if host == "" {
		return ErrEmptySNI
	}
	if len(host) > 255 {
		return fmt.Errorf("dialer: SNI %q exceeds 255 bytes", host)
	}
	for _, r := range host {
		if r == 0 || r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			return fmt.Errorf("dialer: SNI %q contains an illegal character", host)
		}
	}
	return nil
}

// ExtractSNI returns the host_name the peer is asking for, if any.
// It is the read-only counterpart of RewriteSNI and is what lets the daemon
// log or audit what a connection claimed before it was rewritten.
func ExtractSNI(b []byte) (string, error) {
	_, hs, err := splitHandshake(b)
	if err != nil {
		return "", err
	}
	_, exts, err := parseExtensions(hs)
	if err != nil {
		return "", err
	}
	if len(exts) == 0 {
		return "", ErrNoSNIExtension
	}
	host, ok := findHostName(exts)
	if !ok {
		return "", ErrNoSNIExtension
	}
	return host, nil
}

// RewriteSNI returns a copy of b in which the ClientHello's server_name has
// been replaced with fake.
//
// The rewrite is length-safe: the server_name_list, the extension and every
// enclosing length field (extensions_length, handshake length, record length)
// are recomputed from the new payload. A naive byte-for-byte substitution
// would leave the record claiming its old length and break the handshake.
//
// Bytes after the first ClientHello record are preserved verbatim, so a buffer
// carrying multiple records stays intact.
func RewriteSNI(b []byte, fake string) ([]byte, error) {
	if err := ValidateSNIHost(fake); err != nil {
		return nil, err
	}
	body, hs, err := splitHandshake(b)
	if err != nil {
		return nil, err
	}
	extLenOff, exts, err := parseExtensions(hs)
	if err != nil {
		return nil, err
	}
	if len(exts) == 0 {
		return nil, ErrNoSNIExtension
	}
	newExts, err := rewriteHostName(exts, fake)
	if err != nil {
		return nil, err
	}

	// hs[:extLenOff] is everything up to but excluding the extensions_length
	// field; the extensions block is rebuilt from scratch.
	newHS := make([]byte, 0, extLenOff+2+len(newExts))
	newHS = append(newHS, hs[:extLenOff]...)
	newHS = append(newHS, byte(len(newExts)>>8), byte(len(newExts)&0xff))
	newHS = append(newHS, newExts...)

	recordLen := handshakeHeaderLen + len(newHS)
	out := make([]byte, 0, recordHeaderLen+recordLen+len(b)-(recordHeaderLen+len(body)))
	out = append(out,
		recordTypeHandshake,
		b[1], b[2], // record version, preserved
		byte(recordLen>>8), byte(recordLen&0xff),
		handshakeClientHello,
		byte(len(newHS)>>16), byte(len(newHS)>>8), byte(len(newHS)&0xff),
	)
	out = append(out, newHS...)
	// Anything the caller buffered past the first record is copied through.
	if tail := b[recordHeaderLen+len(body):]; len(tail) > 0 {
		out = append(out, tail...)
	}
	return out, nil
}

// splitHandshake validates the record framing and returns the record body and
// the ClientHello handshake body within it.
func splitHandshake(b []byte) (body, hs []byte, err error) {
	if len(b) < recordHeaderLen {
		return nil, nil, ErrTruncated
	}
	if b[0] != recordTypeHandshake {
		return nil, nil, ErrNotHandshake
	}
	recordLen := int(binary.BigEndian.Uint16(b[3:5]))
	if recordLen == 0 {
		return nil, nil, ErrTruncated
	}
	if len(b) < recordHeaderLen+recordLen {
		return nil, nil, ErrTruncated
	}
	body = b[recordHeaderLen : recordHeaderLen+recordLen]
	if len(body) < handshakeHeaderLen {
		return nil, nil, ErrTruncated
	}
	if body[0] != handshakeClientHello {
		return nil, nil, ErrNotClientHello
	}
	hsLen := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
	if len(body) < handshakeHeaderLen+hsLen {
		return nil, nil, ErrTruncated
	}
	return body, body[handshakeHeaderLen : handshakeHeaderLen+hsLen], nil
}

// parseExtensions walks the fixed ClientHello prefix and returns the offset of
// the extensions_length field plus the extensions block. exts is empty when
// the hello predates extensions (TLS 1.0/1.1 without SNI).
func parseExtensions(hs []byte) (extLenOff int, exts []byte, err error) {
	off := clientHelloFixedBytes
	if len(hs) < off+1 {
		return 0, nil, ErrTruncated
	}
	sessionIDLen := int(hs[off])
	off += 1 + sessionIDLen
	if len(hs) < off+2 {
		return 0, nil, ErrTruncated
	}
	cipherLen := int(binary.BigEndian.Uint16(hs[off : off+2]))
	off += 2 + cipherLen
	if len(hs) < off+1 {
		return 0, nil, ErrTruncated
	}
	compLen := int(hs[off])
	off += 1 + compLen
	if len(hs) < off+2 {
		return off, nil, nil // no extensions block at all
	}
	extLen := int(binary.BigEndian.Uint16(hs[off : off+2]))
	if off+2+extLen > len(hs) {
		return 0, nil, ErrTruncated
	}
	return off, hs[off+2 : off+2+extLen], nil
}

// findHostName walks the extension list for a server_name entry.
func findHostName(exts []byte) (string, bool) {
	for off := 0; off+4 <= len(exts); {
		typ := binary.BigEndian.Uint16(exts[off : off+2])
		ln := int(binary.BigEndian.Uint16(exts[off+2 : off+4]))
		if off+4+ln > len(exts) {
			return "", false
		}
		data := exts[off+4 : off+4+ln]
		if typ == extensionServerName {
			if host, ok := firstHostName(data); ok {
				return host, true
			}
		}
		off += 4 + ln
	}
	return "", false
}

// clientHelloSNIHostBounds returns the hostname's byte offsets in the original
// record. It shares the existing ClientHello and extension framing parsers so
// callers do not infer boundaries from an unvalidated byte search.
func clientHelloSNIHostBounds(b []byte) (int, int, bool) {
	_, hs, err := splitHandshake(b)
	if err != nil {
		return 0, 0, false
	}
	extLenOff, exts, err := parseExtensions(hs)
	if err != nil {
		return 0, 0, false
	}
	extensionsStart := recordHeaderLen + handshakeHeaderLen + extLenOff + 2
	for off := 0; off+4 <= len(exts); {
		typ := binary.BigEndian.Uint16(exts[off : off+2])
		length := int(binary.BigEndian.Uint16(exts[off+2 : off+4]))
		if off+4+length > len(exts) {
			return 0, 0, false
		}
		if typ == extensionServerName {
			data := exts[off+4 : off+4+length]
			if start, end, ok := firstHostNameByteBounds(data); ok {
				return extensionsStart + off + 4 + start, extensionsStart + off + 4 + end, true
			}
		}
		off += 4 + length
	}
	return 0, 0, false
}

func firstHostNameByteBounds(data []byte) (int, int, bool) {
	if len(data) < 2 {
		return 0, 0, false
	}
	listEnd := 2 + int(binary.BigEndian.Uint16(data[:2]))
	if listEnd > len(data) {
		return 0, 0, false
	}
	hostStart, hostEnd := 0, 0
	foundHost := false
	for off := 2; off < listEnd; {
		if off+3 > listEnd {
			return 0, 0, false
		}
		nameType := data[off]
		nameLen := int(binary.BigEndian.Uint16(data[off+1 : off+3]))
		nameStart := off + 3
		nameEnd := nameStart + nameLen
		if nameEnd > listEnd {
			return 0, 0, false
		}
		if nameType == serverNameTypeHost && !foundHost {
			hostStart, hostEnd = nameStart, nameEnd
			foundHost = true
		}
		off = nameEnd
	}
	if !foundHost {
		return 0, 0, false
	}
	return hostStart, hostEnd, true
}

// firstHostName reads the first host_name entry out of a server_name_list.
func firstHostName(data []byte) (string, bool) {
	if len(data) < 2 {
		return "", false
	}
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	if 2+listLen > len(data) {
		return "", false
	}
	off := 2
	for off+3 <= len(data) {
		nameType := data[off]
		nameLen := int(binary.BigEndian.Uint16(data[off+1 : off+3]))
		if off+3+nameLen > len(data) {
			return "", false
		}
		if nameType == serverNameTypeHost {
			return string(data[off+3 : off+3+nameLen]), true
		}
		off += 3 + nameLen
	}
	return "", false
}

// rewriteHostName rebuilds the extension list with a substituted server_name,
// copying every other extension through unchanged.
func rewriteHostName(exts []byte, fake string) ([]byte, error) {
	list := make([]byte, 2+3+len(fake))
	binary.BigEndian.PutUint16(list[0:2], uint16(3+len(fake)))
	list[2] = serverNameTypeHost
	binary.BigEndian.PutUint16(list[3:5], uint16(len(fake)))
	copy(list[5:], fake)

	out := make([]byte, 0, len(exts)+len(list))
	replaced := false
	for off := 0; off+4 <= len(exts); {
		typ := binary.BigEndian.Uint16(exts[off : off+2])
		ln := int(binary.BigEndian.Uint16(exts[off+2 : off+4]))
		if off+4+ln > len(exts) {
			return nil, ErrTruncated
		}
		if typ == extensionServerName && !replaced {
			out = append(out, byte(extensionServerName>>8), byte(extensionServerName&0xff))
			out = append(out, byte(len(list)>>8), byte(len(list)&0xff))
			out = append(out, list...)
			replaced = true
		} else {
			out = append(out, exts[off:off+4+ln]...)
		}
		off += 4 + ln
	}
	if !replaced {
		return nil, ErrNoSNIExtension
	}
	return out, nil
}

// DescribeSNI is a diagnostic helper: it reports the SNI a buffer claims,
// without allocating a rewrite.
func DescribeSNI(b []byte) string {
	host, err := ExtractSNI(b)
	if err != nil {
		return "<" + strings.TrimPrefix(err.Error(), "dialer: ") + ">"
	}
	return host
}
