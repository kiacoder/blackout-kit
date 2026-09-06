package stun

import (
	"errors"
	"io"
	"testing"
)

func TestXORMappedAddressRejectsZeroLengthAttribute(t *testing.T) {
	message := New()
	message.SetType(BindingSuccess)
	message.WriteHeader()
	message.Add(AttrXORMappedAddress, nil)

	var address XORMappedAddress
	err := address.GetFrom(message)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("GetFrom() error = %v, want %v", err, io.ErrUnexpectedEOF)
	}
}
