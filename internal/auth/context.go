package auth

import "context"

type identityKey struct{}

// WithIdentity returns a context carrying the authorized caller. The router
// sets it after verification and authorization succeed, so downstream code can
// treat its presence as proof the request was authorized.
func WithIdentity(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, identityKey{}, id)
}

// IdentityFrom returns the authorized caller, or false if the context carries
// none. Transports use it to scope per-identity session caps and audit fields.
func IdentityFrom(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(identityKey{}).(Identity)
	return id, ok
}
