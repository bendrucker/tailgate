//go:build !darwin || !cgo

package keychain

func (Item) Read() ([]byte, error) { return nil, ErrUnsupported }

func (Item) Add(string, []byte) error { return ErrUnsupported }

func (Item) Delete() error { return ErrUnsupported }
