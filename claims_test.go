// Tideland Go JSON Web Token - Unit Tests
//
// Copyright (C) 2016-2025 Frank Mueller / Tideland / Germany
//
// All rights reserved. Use of this source code is governed
// by the new BSD license.

package jwt_test // import "tideland.dev/go/jwt"


import (
	"encoding/json"
	"slices"
	"testing"
	"time"

	"tideland.dev/go/asserts/verify"

	"tideland.dev/go/jwt"
)


// TestClaimsMarshalling verifies the marshalling of claims to JSON and back.
func TestClaimsMarshalling(t *testing.T) {
	// First with uninitialised or empty jwt.
	var c jwt.Claims
	jsonValue, err := json.Marshal(c)
	verify.Equal(t, string(jsonValue), "{}")
	verify.NoError(t, err)
	c = jwt.NewClaims()
	jsonValue, err = json.Marshal(c)
	verify.Equal(t, string(jsonValue), "{}")
	verify.NoError(t, err)
	// Now fill it.
	c.Set("foo", "yadda")
	c.Set("bar", 12345)
	verify.Length(t, c, 2)
	jsonValue, err = json.Marshal(c)
	verify.NotNil(t, jsonValue)
	verify.NoError(t, err)
	var uc jwt.Claims
	err = json.Unmarshal(jsonValue, &uc)
	verify.NoError(t, err)
	verify.Length(t, uc, 2)
	foo, ok := uc.Get("foo")
	verify.Equal(t, foo, "yadda")
	verify.True(t, ok)
	bar, ok := uc.GetInt("bar")
	verify.Equal(t, bar, 12345)
	verify.True(t, ok)
}

// TestClaimsBasic verifies the low level operations on claims.
func TestClaimsBasic(t *testing.T) {
	// First with uninitialised jwt.
	var c jwt.Claims
	ok := c.Contains("foo")
	verify.False(t, ok)
	nothing, ok := c.Get("foo")
	verify.Nil(t, nothing)
	verify.False(t, ok)
	old := c.Set("foo", "bar")
	verify.Nil(t, old)
	old = c.Delete("foo")
	verify.Nil(t, old)
	// Now initialise it.
	c = jwt.NewClaims()
	ok = c.Contains("foo")
	verify.False(t, ok)
	nothing, ok = c.Get("foo")
	verify.Nil(t, nothing)
	verify.False(t, ok)
	old = c.Set("foo", "bar")
	verify.Nil(t, old)
	ok = c.Contains("foo")
	verify.True(t, ok)
	foo, ok := c.Get("foo")
	verify.Equal(t, foo, "bar")
	verify.True(t, ok)
	old = c.Set("foo", "yadda")
	verify.Equal(t, old, "bar")
	// Finally delete it.
	old = c.Delete("foo")
	verify.Equal(t, old, "yadda")
	old = c.Delete("foo")
	verify.Nil(t, old)
	ok = c.Contains("foo")
	verify.False(t, ok)
}

// TestClaimsString verifies the string operations on claims.
func TestClaimsString(t *testing.T) {
	c := jwt.NewClaims()
	nothing := c.Set("foo", "bar")
	verify.Nil(t, nothing)
	var foo string
	foo, ok := c.GetString("foo")
	verify.Equal(t, foo, "bar")
	verify.True(t, ok)
	c.Set("foo", 4711)
	foo, ok = c.GetString("foo")
	verify.Equal(t, foo, "4711")
	verify.True(t, ok)
}

// TestClaimsBool verifies the bool operations on claims.
func TestClaimsBool(t *testing.T) {
	c := jwt.NewClaims()
	c.Set("foo", true)
	c.Set("bar", false)
	c.Set("baz", "T")
	c.Set("bingo", "0")
	c.Set("yadda", "nope")
	foo, ok := c.GetBool("foo")
	verify.True(t, foo)
	verify.True(t, ok)
	bar, ok := c.GetBool("bar")
	verify.False(t, bar)
	verify.True(t, ok)
	baz, ok := c.GetBool("baz")
	verify.True(t, baz)
	verify.True(t, ok)
	bingo, ok := c.GetBool("bingo")
	verify.False(t, bingo)
	verify.True(t, ok)
	yadda, ok := c.GetBool("yadda")
	verify.False(t, yadda)
	verify.False(t, ok)
}

// TestClaimsInt verifies the int operations on claims.
func TestClaimsInt(t *testing.T) {
	c := jwt.NewClaims()
	c.Set("foo", 4711)
	c.Set("bar", "4712")
	c.Set("baz", 4713.0)
	c.Set("yadda", "nope")
	foo, ok := c.GetInt("foo")
	verify.Equal(t, foo, 4711)
	verify.True(t, ok)
	bar, ok := c.GetInt("bar")
	verify.Equal(t, bar, 4712)
	verify.True(t, ok)
	baz, ok := c.GetInt("baz")
	verify.Equal(t, baz, 4713)
	verify.True(t, ok)
	yadda, ok := c.GetInt("yadda")
	verify.Equal(t, yadda, 0)
	verify.False(t, ok)
}

// TestClaimsFloat64 verifies the float64 operations on claims.
func TestClaimsFloat64(t *testing.T) {
	c := jwt.NewClaims()
	c.Set("foo", 4711)
	c.Set("bar", "4712")
	c.Set("baz", 4713.0)
	c.Set("yadda", "nope")
	foo, ok := c.GetFloat64("foo")
	verify.Equal(t, foo, 4711.0)
	verify.True(t, ok)
	bar, ok := c.GetFloat64("bar")
	verify.Equal(t, bar, 4712.0)
	verify.True(t, ok)
	baz, ok := c.GetFloat64("baz")
	verify.Equal(t, baz, 4713.0)
	verify.True(t, ok)
	yadda, ok := c.GetFloat64("yadda")
	verify.Equal(t, yadda, 0.0)
	verify.False(t, ok)
}

// TestClaimsTime verifies the time operations on claims.
func TestClaimsTime(t *testing.T) {
	goLaunch := time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC)
	c := jwt.NewClaims()
	c.SetTime("foo", goLaunch)
	c.Set("bar", goLaunch.Unix())
	c.Set("baz", goLaunch.Format(time.RFC3339))
	c.Set("yadda", "nope")
	foo, ok := c.GetTime("foo")
	verify.Equal(t, foo.Unix(), goLaunch.Unix())
	verify.True(t, ok)
	bar, ok := c.GetTime("bar")
	verify.Equal(t, bar.Unix(), goLaunch.Unix())
	verify.True(t, ok)
	baz, ok := c.GetTime("baz")
	verify.Equal(t, baz.Unix(), goLaunch.Unix())
	verify.True(t, ok)
	yadda, ok := c.GetTime("yadda")
	verify.Equal(t, yadda, time.Time{})
	verify.False(t, ok)
}

// TestClaimsMarshalledValue verifies the marshalling and
// unmarshalling of structures as values.
func TestClaimsMarshalledValue(t *testing.T) {
	type nestedValue struct {
		Name  string
		Value int
	}

	baz := []*nestedValue{
		{"one", 1},
		{"two", 2},
		{"three", 3},
	}
	c := jwt.NewClaims()
	c.Set("foo", "bar")
	c.Set("baz", baz)
	// Now marshal and unmarshal the claim.
	jsonValue, err := json.Marshal(c)
	verify.NotNil(t, jsonValue)
	verify.NoError(t, err)
	var uc jwt.Claims
	err = json.Unmarshal(jsonValue, &uc)
	verify.NoError(t, err)
	verify.Length(t, uc, 2)
	foo, ok := uc.Get("foo")
	verify.Equal(t, foo, "bar")
	verify.True(t, ok)
	var ubaz []*nestedValue
	ok, err = uc.GetMarshalled("baz", &ubaz)
	verify.True(t, ok)
	verify.NoError(t, err)
	verify.Length(t, ubaz, 3)
	verify.Equal(t, ubaz[0].Name, "one")
	verify.Equal(t, ubaz[2].Value, 3)
}

// TestClaimsAudience verifies the setting, getting, and
// deleting of the audience claim.
func TestClaimsAudience(t *testing.T) {
	audience := []string{"foo", "bar", "baz"}
	c := jwt.NewClaims()
	aud, ok := c.Audience()
	verify.False(t, ok)
	verify.Length(t, aud, 0)
	none := c.SetAudience(audience...)
	verify.Length(t, none, 0)
	aud, ok = c.Audience()
	verify.True(t, slices.Equal(aud, audience))
	verify.True(t, ok)
	old := c.DeleteAudience()
	verify.True(t, slices.Equal(old, aud))
	_, ok = c.Audience()
	verify.False(t, ok)
}

// TestClaimsExpiration verifies the setting, getting, and
// deleting of the expiration claim.
func TestClaimsExpiration(t *testing.T) {
	goLaunch := time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC)
	c := jwt.NewClaims()
	exp, ok := c.Expiration()
	verify.False(t, ok)
	none := c.SetExpiration(goLaunch)
	verify.Equal(t, none, time.Time{})
	exp, ok = c.Expiration()
	verify.Equal(t, exp.Unix(), goLaunch.Unix())
	verify.True(t, ok)
	old := c.DeleteExpiration()
	verify.Equal(t, old.Unix(), exp.Unix())
	exp, ok = c.Expiration()
	verify.False(t, ok)
}

// TestClaimsIdentifier verifies the setting, getting, and
// deleting of the identifier claim.
func TestClaimsIdentifier(t *testing.T) {
	identifier := "foo"
	c := jwt.NewClaims()
	jti, ok := c.Identifier()
	verify.False(t, ok)
	verify.Empty(t, jti)
	none := c.SetIdentifier(identifier)
	verify.Equal(t, none, "")
	jti, ok = c.Identifier()
	verify.Equal(t, jti, identifier)
	verify.True(t, ok)
	old := c.DeleteIdentifier()
	verify.Equal(t, old, jti)
	_, ok = c.Identifier()
	verify.False(t, ok)
}

// TestClaimsIssuedAt verifies the setting, getting, and
// deleting of the issued at claim.
func TestClaimsIssuedAt(t *testing.T) {
	goLaunch := time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC)
	c := jwt.NewClaims()
	iat, ok := c.IssuedAt()
	verify.False(t, ok)
	none := c.SetIssuedAt(goLaunch)
	verify.Equal(t, none, time.Time{})
	iat, ok = c.IssuedAt()
	verify.Equal(t, iat.Unix(), goLaunch.Unix())
	verify.True(t, ok)
	old := c.DeleteIssuedAt()
	verify.Equal(t, old.Unix(), iat.Unix())
	iat, ok = c.IssuedAt()
	verify.False(t, ok)
}

// TestClaimsIssuer verifies the setting, getting, and
// deleting of the issuer claim.
func TestClaimsIssuer(t *testing.T) {
	issuer := "foo"
	c := jwt.NewClaims()
	iss, ok := c.Issuer()
	verify.False(t, ok)
	verify.Empty(t, iss)
	none := c.SetIssuer(issuer)
	verify.Equal(t, none, "")
	iss, ok = c.Issuer()
	verify.Equal(t, iss, issuer)
	verify.True(t, ok)
	old := c.DeleteIssuer()
	verify.Equal(t, old, iss)
	_, ok = c.Issuer()
	verify.False(t, ok)
}

// TestClaimsNotBefore verifies the setting, getting, and
// deleting of the not before claim.
func TestClaimsNotBefore(t *testing.T) {
	goLaunch := time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC)
	c := jwt.NewClaims()
	nbf, ok := c.NotBefore()
	verify.False(t, ok)
	none := c.SetNotBefore(goLaunch)
	verify.Equal(t, none, time.Time{})
	nbf, ok = c.NotBefore()
	verify.Equal(t, nbf.Unix(), goLaunch.Unix())
	verify.True(t, ok)
	old := c.DeleteNotBefore()
	verify.Equal(t, old.Unix(), nbf.Unix())
	_, ok = c.NotBefore()
	verify.False(t, ok)
}

// TestClaimsSubject verifies the setting, getting, and
// deleting of the subject claim.
func TestClaimsSubject(t *testing.T) {
	subject := "foo"
	c := jwt.NewClaims()
	sub, ok := c.Subject()
	verify.False(t, ok)
	verify.Empty(t, sub)
	none := c.SetSubject(subject)
	verify.Equal(t, none, "")
	sub, ok = c.Subject()
	verify.Equal(t, sub, subject)
	verify.True(t, ok)
	old := c.DeleteSubject()
	verify.Equal(t, old, sub)
	_, ok = c.Subject()
	verify.False(t, ok)
}

// TestClaimsValidity verifies the validation of the not before
// and the expiring time.
func TestClaimsValidity(t *testing.T) {
	// Fresh jwt.
	now := time.Now()
	leeway := time.Minute
	c := jwt.NewClaims()
	valid := c.IsAlreadyValid(leeway)
	verify.True(t, valid)
	valid = c.IsStillValid(leeway)
	verify.True(t, valid)
	valid = c.IsValid(leeway)
	verify.True(t, valid)
	// Set times.
	nbf := now.Add(-time.Hour)
	exp := now.Add(time.Hour)
	c.SetNotBefore(nbf)
	valid = c.IsAlreadyValid(leeway)
	verify.True(t, valid)
	c.SetExpiration(exp)
	valid = c.IsStillValid(leeway)
	verify.True(t, valid)
	valid = c.IsValid(leeway)
	verify.True(t, valid)
	// Invalid token.
	nbf = now.Add(time.Hour)
	exp = now.Add(-time.Hour)
	c.SetNotBefore(nbf)
	c.DeleteExpiration()
	valid = c.IsAlreadyValid(leeway)
	verify.False(t, valid)
	valid = c.IsValid(leeway)
	verify.False(t, valid)
	c.DeleteNotBefore()
	c.SetExpiration(exp)
	valid = c.IsStillValid(leeway)
	verify.False(t, valid)
	valid = c.IsValid(leeway)
	verify.False(t, valid)
	c.SetNotBefore(nbf)
	valid = c.IsValid(leeway)
	verify.False(t, valid)
}

