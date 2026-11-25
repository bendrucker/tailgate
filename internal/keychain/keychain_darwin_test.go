//go:build darwin && cgo

package keychain

import (
	"bytes"
	"errors"
	"os"
	"testing"
)

// TestItem writes to the login keychain. It runs only when asked to.
func TestItem(t *testing.T) {
	if os.Getenv("TAILGATE_KEYCHAIN_TEST") == "" {
		t.Skip("set TAILGATE_KEYCHAIN_TEST=1 to exercise the login keychain")
	}
	item := Item{Service: "dev.bendrucker.tailgate.test", Account: t.Name()}
	_ = item.Delete()
	t.Cleanup(func() { _ = item.Delete() })

	if _, err := item.Read(); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Read before Add = %v, want ErrNotFound", err)
	}
	secret := []byte{0, 1, 2, 3, 255}
	if err := item.Add("tailgate test secret", secret); err != nil {
		t.Fatalf("Add: %v", err)
	}
	got, err := item.Read()
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Errorf("Read = %x, want %x", got, secret)
	}
	if err := item.Add("tailgate test secret", secret); err == nil {
		t.Error("a second Add succeeded, want a duplicate item error")
	}
	if err := item.Delete(); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := item.Delete(); !errors.Is(err, ErrNotFound) {
		t.Errorf("Delete after Delete = %v, want ErrNotFound", err)
	}
}
