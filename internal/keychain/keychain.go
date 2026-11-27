// Package keychain keeps small secrets in the macOS login keychain, readable
// only by the binary that created them.
//
// An item is created with an access control list trusting the calling binary
// alone, by its code signature's designated requirement. A binary signed with
// a stable identity keeps access across rebuilds. An ad hoc signed build is
// trusted by its cdhash, so the next build is a different application to the
// keychain. Every call disables user interaction. An untrusted binary gets
// an error instead of a prompt that would block a launchd job.
package keychain

import "errors"

var (
	// ErrNotFound means no item exists for the service and account.
	ErrNotFound = errors.New("keychain: item not found")
	// ErrUnsupported means this build has no keychain support: it is not darwin,
	// or it was built without cgo.
	ErrUnsupported = errors.New("keychain: unsupported on this build, which needs darwin and cgo")
)

// Item names one generic password by its service and account attributes.
type Item struct {
	Service string
	Account string
}
