// Tideland Go JSON Web Token
//
// Copyright (C) 2016-2021 Frank Mueller / Tideland / Oldenburg / Germany
//
// All rights reserved. Use of this source code is governed
// by the new BSD license.

package jwt // import "tideland.dev/go/jwt"

//--------------------
// IMPORTS
//--------------------

import (
	"context"
)

//--------------------
// CONTEXT
//--------------------

// key for the storage of values in a context.
type key int

const (
	jwtKey key = iota
)

// NewContext returns a new context that carries a token.
func NewContext(ctx context.Context, token *JWT) context.Context {
	return context.WithValue(ctx, jwtKey, token)
}

// FromContext returns the token stored in ctx, if any.
func FromContext(ctx context.Context) (*JWT, bool) {
	token, ok := ctx.Value(jwtKey).(*JWT)
	return token, ok
}

// EOF
