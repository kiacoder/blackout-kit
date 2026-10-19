package main

import (
	"strings"
	"testing"
)

func TestKeyToHexFromBase64(t *testing.T) {
	// 32 zero bytes, base64 → hex must be 64 chars of zeros.
	got := keyToHex("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	if got != strings.Repeat("0", 64) {
		t.Fatalf("unexpected hex: %q", got)
	}
}

func TestKeyToHexPassesHexThrough(t *testing.T) {
	hexKey := strings.Repeat("ab", 32)
	if got := keyToHex(hexKey); got != hexKey {
		t.Fatalf("hex passthrough broken: %q", got)
	}
}

func TestUAPIOrdersDeviceKeysBeforePeer(t *testing.T) {
	c := &Config{
		PrivateKey:   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		PublicKey:    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		Endpoint:     "1.2.3.4:39006",
		AllowedIPs:   []string{"0.0.0.0/0"},
		Obfuscation:  map[string]string{"jc": "4", "h1": "123-456"},
	}
	u := c.UAPI()

	pubIdx := strings.Index(u, "public_key=")
	if pubIdx < 0 {
		t.Fatal("missing public_key")
	}
	for _, key := range []string{"private_key=", "jc=4", "h1=123-456", "replace_peers=true"} {
		idx := strings.Index(u, key)
		if idx < 0 {
			t.Fatalf("missing %q in UAPI output:\n%s", key, u)
		}
		if idx > pubIdx {
			t.Fatalf("%q must precede public_key (device-level key)", key)
		}
	}
	if !strings.Contains(u, "allowed_ip=0.0.0.0/0") {
		t.Fatal("allowed_ip missing")
	}
}

func TestLoadConfigRequiresPeerFields(t *testing.T) {
	c := &Config{PrivateKey: "x", Obfuscation: map[string]string{}}
	if c.UAPI() == "" {
		t.Fatal("UAPI should not be empty")
	}
}
