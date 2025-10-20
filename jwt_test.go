// Tideland Go JSON Web Token - Unit Tests
//
// Copyright (C) 2016-2025 Frank Mueller / Tideland / Germany
//
// All rights reserved. Use of this source code is governed
// by the new BSD license.

package jwt_test // import "tideland.dev/go/jwt"


import (
	"testing"
	"time"

	"tideland.dev/go/asserts/verify"

	"tideland.dev/go/jwt"
)


const (
	subClaim   = "1234567890"
	nameClaim  = "John Doe"
	adminClaim = true
	iatClaim   = 1600000000
	rawToken   = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9." +
		"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTYwMDAwMDAwMH0." +
		"P50peTbENKIPw0tjuHLgosFmJRYGTh_kNA9IcyWIoJ39uYMa4JfKYhnQw5mkgSLB2WYVT68QaDeWWErn4lU69g"
)


// TestDecode verifies a token decoding without internal verification the signature.
func TestDecode(t *testing.T) {
	// Decode.
	token, err := jwt.Decode(rawToken)
	verify.NoError(t, err)
	verify.Equal(t, token.Algorithm(), jwt.HS512)
	key, err := token.Key()
	verify.Nil(t, key)
	verify.ErrorMatch(t, err, ".*no key available, only after encoding or verifying.*")
	verify.Length(t, token.Claims(), 4)

	sub, ok := token.Claims().GetString("sub")
	verify.True(t, ok)
	verify.Equal(t, sub, subClaim)
	name, ok := token.Claims().GetString("name")
	verify.True(t, ok)
	verify.Equal(t, name, nameClaim)
	admin, ok := token.Claims().GetBool("admin")
	verify.True(t, ok)
	verify.Equal(t, admin, adminClaim)
	iat, ok := token.Claims().IssuedAt()
	verify.True(t, ok)
	verify.Equal(t, iat, time.Unix(iatClaim, 0))
	exp, ok := token.Claims().Expiration()
	verify.False(t, ok)
	verify.Equal(t, exp, time.Time{})
}

// TestIsValid verifies the time validation of a token.
func TestIsValid(t *testing.T) {
	now := time.Now()
	leeway := time.Minute
	key := []byte("secret")
	// Create token with no times set, encode, decode, validate ok.
	claims := jwt.NewClaims()
	tokenEnc, err := jwt.Encode(claims, key, jwt.HS512)
	verify.NoError(t, err)
	tokenDec, err := jwt.Decode(tokenEnc.String())
	verify.NoError(t, err)
	ok := tokenDec.IsValid(leeway)
	verify.True(t, ok)
	// Now a token with a long timespan, still valid.
	claims = jwt.NewClaims()
	claims.SetNotBefore(now.Add(-time.Hour))
	claims.SetExpiration(now.Add(time.Hour))
	tokenEnc, err = jwt.Encode(claims, key, jwt.HS512)
	verify.NoError(t, err)
	tokenDec, err = jwt.Decode(tokenEnc.String())
	verify.NoError(t, err)
	ok = tokenDec.IsValid(leeway)
	verify.True(t, ok)
	// Now a token with a long timespan in the past, not valid.
	claims = jwt.NewClaims()
	claims.SetNotBefore(now.Add(-2 * time.Hour))
	claims.SetExpiration(now.Add(-time.Hour))
	tokenEnc, err = jwt.Encode(claims, key, jwt.HS512)
	verify.NoError(t, err)
	tokenDec, err = jwt.Decode(tokenEnc.String())
	verify.NoError(t, err)
	ok = tokenDec.IsValid(leeway)
	verify.False(t, ok)
	// And at last a token with a long timespan in the future, not valid.
	claims = jwt.NewClaims()
	claims.SetNotBefore(now.Add(time.Hour))
	claims.SetExpiration(now.Add(2 * time.Hour))
	tokenEnc, err = jwt.Encode(claims, key, jwt.HS512)
	verify.NoError(t, err)
	tokenDec, err = jwt.Decode(tokenEnc.String())
	verify.NoError(t, err)
	ok = tokenDec.IsValid(leeway)
	verify.False(t, ok)
}

