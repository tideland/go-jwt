// Tideland Go JSON Web Token - Unit Tests
//
// Copyright (C) 2016-2025 Frank Mueller / Tideland / Germany
//
// All rights reserved. Use of this source code is governed
// by the new BSD license.

package jwt_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"tideland.dev/go/asserts/verify"

	"tideland.dev/go/jwt"
)

var (
	esTests = []jwt.Algorithm{jwt.ES256, jwt.ES384, jwt.ES512}
	hsTests = []jwt.Algorithm{jwt.HS256, jwt.HS384, jwt.HS512}
	psTests = []jwt.Algorithm{jwt.PS256, jwt.PS384, jwt.PS512}
	rsTests = []jwt.Algorithm{jwt.RS256, jwt.RS384, jwt.RS512}
	data    = []byte("the quick brown fox jumps over the lazy dog")
)

// TestESAlgorithms verifies the ECDSA algorithms.
func TestESAlgorithms(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	verify.NoError(t, err)
	for _, algo := range esTests {
		// Sign.
		signature, err := algo.Sign(data, privateKey)
		verify.NoError(t, err)
		verify.NotEmpty(t, signature)
		// Verify.
		err = algo.Verify(data, signature, privateKey.Public())
		verify.NoError(t, err)
	}
}

// TestHSAlgorithms verifies the HMAC algorithms.
func TestHSAlgorithms(t *testing.T) {
	key := []byte("secret")
	for _, algo := range hsTests {
		// Sign.
		signature, err := algo.Sign(data, key)
		verify.NoError(t, err)
		verify.NotEmpty(t, signature)
		// Verify.
		err = algo.Verify(data, signature, key)
		verify.NoError(t, err)
	}
}

// TestPSAlgorithms verifies the RSAPSS algorithms.
func TestPSAlgorithms(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	verify.NoError(t, err)
	for _, algo := range psTests {
		// Sign.
		signature, err := algo.Sign(data, privateKey)
		verify.NoError(t, err)
		verify.NotEmpty(t, signature)
		// Verify.
		err = algo.Verify(data, signature, privateKey.Public())
		verify.NoError(t, err)
	}
}

// TestRSAlgorithms verifies the RSA algorithms.
func TestRSAlgorithms(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	verify.NoError(t, err)
	for _, algo := range rsTests {
		// Sign.
		signature, err := algo.Sign(data, privateKey)
		verify.NoError(t, err)
		verify.NotEmpty(t, signature)
		// Verify.
		err = algo.Verify(data, signature, privateKey.Public())
		verify.NoError(t, err)
	}
}

// TestNoneAlgorithm verifies the none algorithm.
func TestNoneAlgorithm(t *testing.T) {
	// Sign.
	signature, err := jwt.NONE.Sign(data, "")
	verify.NoError(t, err)
	verify.Empty(t, signature)
	// Verify.
	err = jwt.NONE.Verify(data, signature, "")
	verify.NoError(t, err)
}

// TestNotMatchingAlgorithm checks when algorithms of
// signing and verifying don't match.'
func TestNotMatchingAlgorithm(t *testing.T) {
	esPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	esPublicKey := esPrivateKey.Public()
	verify.NoError(t, err)
	hsKey := []byte("secret")
	rsPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	rsPublicKey := rsPrivateKey.Public()
	verify.NoError(t, err)
	noneKey := ""
	errorMatch := ".* combination of algorithm .* and key type .*"
	tests := []struct {
		description string
		algorithm   jwt.Algorithm
		key         jwt.Key
		signKeys    []jwt.Key
		verifyKeys  []jwt.Key
	}{
		{"ECDSA", jwt.ES512, esPrivateKey,
			[]jwt.Key{hsKey, rsPrivateKey, noneKey}, []jwt.Key{hsKey, rsPublicKey, noneKey}},
		{"HMAC", jwt.HS512, hsKey,
			[]jwt.Key{esPrivateKey, rsPrivateKey, noneKey}, []jwt.Key{esPublicKey, rsPublicKey, noneKey}},
		{"RSA", jwt.RS512, rsPrivateKey,
			[]jwt.Key{esPrivateKey, hsKey, noneKey}, []jwt.Key{esPublicKey, hsKey, noneKey}},
		{"RSAPSS", jwt.PS512, rsPrivateKey,
			[]jwt.Key{esPrivateKey, hsKey, noneKey}, []jwt.Key{esPublicKey, hsKey, noneKey}},
		{"none", jwt.NONE, noneKey,
			[]jwt.Key{esPrivateKey, hsKey, rsPrivateKey}, []jwt.Key{esPublicKey, hsKey, rsPublicKey}},
	}
	// Run the tests.
	for _, test := range tests {
		for _, key := range test.signKeys {
			_, err := test.algorithm.Sign(data, key)
			verify.ErrorMatch(t, err, errorMatch)
		}
		signature, err := test.algorithm.Sign(data, test.key)
		verify.NoError(t, err)
		for _, key := range test.verifyKeys {
			err = test.algorithm.Verify(data, signature, key)
			verify.ErrorMatch(t, err, errorMatch)
		}
	}
}

// TestESTools verifies the tools for the reading of PEM encoded
func TestESTools(t *testing.T) {
	// Generate keys and PEMs.
	privateKeyIn, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	verify.NoError(t, err)
	privateBytes, err := x509.MarshalECPrivateKey(privateKeyIn)
	verify.NoError(t, err)
	privateBlock := pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateBytes,
	}
	privatePEM := pem.EncodeToMemory(&privateBlock)
	publicBytes, err := x509.MarshalPKIXPublicKey(privateKeyIn.Public())
	verify.NoError(t, err)
	publicBlock := pem.Block{
		Type:  "EC PUBLIC KEY",
		Bytes: publicBytes,
	}
	publicPEM := pem.EncodeToMemory(&publicBlock)
	verify.NotNil(t, publicPEM)
	// Now read them.
	buf := bytes.NewBuffer(privatePEM)
	privateKeyOut, err := jwt.ReadECPrivateKey(buf)
	verify.NoError(t, err)
	buf = bytes.NewBuffer(publicPEM)
	publicKeyOut, err := jwt.ReadECPublicKey(buf)
	verify.NoError(t, err)
	// And as a last step check if they are correctly usable.
	signature, err := jwt.ES512.Sign(data, privateKeyOut)
	verify.NoError(t, err)
	err = jwt.ES512.Verify(data, signature, publicKeyOut)
	verify.NoError(t, err)
}

// TestRSTools verifies the tools for the reading of PEM encoded
func TestRSTools(t *testing.T) {
	// Generate keys and PEMs.
	privateKeyIn, err := rsa.GenerateKey(rand.Reader, 2048)
	verify.NoError(t, err)
	privateBytes := x509.MarshalPKCS1PrivateKey(privateKeyIn)
	privateBlock := pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateBytes,
	}
	privatePEM := pem.EncodeToMemory(&privateBlock)
	publicBytes, err := x509.MarshalPKIXPublicKey(privateKeyIn.Public())
	verify.NoError(t, err)
	publicBlock := pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicBytes,
	}
	publicPEM := pem.EncodeToMemory(&publicBlock)
	verify.NotNil(t, publicPEM)
	// Now read them.
	buf := bytes.NewBuffer(privatePEM)
	privateKeyOut, err := jwt.ReadRSAPrivateKey(buf)
	verify.NoError(t, err)
	buf = bytes.NewBuffer(publicPEM)
	publicKeyOut, err := jwt.ReadRSAPublicKey(buf)
	verify.NoError(t, err)
	// And as a last step check if they are correctly usable.
	signature, err := jwt.RS512.Sign(data, privateKeyOut)
	verify.NoError(t, err)
	err = jwt.RS512.Verify(data, signature, publicKeyOut)
	verify.NoError(t, err)
}
