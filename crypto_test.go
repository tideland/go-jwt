// Tideland Go JSON Web Token - Unit Tests
//
// Copyright (C) 2016-2021 Frank Mueller / Tideland / Oldenburg / Germany
//
// All rights reserved. Use of this source code is governed
// by the new BSD license.

package jwt_test // import "tideland.dev/go/jwt"

//--------------------
// IMPORTS
//--------------------

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"tideland.dev/go/audit/asserts"

	"tideland.dev/go/jwt"
)

//--------------------
// TESTS
//--------------------

var (
	esTests = []jwt.Algorithm{jwt.ES256, jwt.ES384, jwt.ES512}
	hsTests = []jwt.Algorithm{jwt.HS256, jwt.HS384, jwt.HS512}
	psTests = []jwt.Algorithm{jwt.PS256, jwt.PS384, jwt.PS512}
	rsTests = []jwt.Algorithm{jwt.RS256, jwt.RS384, jwt.RS512}
	data    = []byte("the quick brown fox jumps over the lazy dog")
)

// TestESAlgorithms verifies the ECDSA algorithms.
func TestESAlgorithms(t *testing.T) {
	assert := asserts.NewTesting(t, asserts.FailStop)
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.Nil(err)
	for _, algo := range esTests {
		assert.Logf("testing algorithm %q", algo)
		// Sign.
		signature, err := algo.Sign(data, privateKey)
		assert.Nil(err)
		assert.NotEmpty(signature)
		// Verify.
		err = algo.Verify(data, signature, privateKey.Public())
		assert.Nil(err)
	}
}

// TestHSAlgorithms verifies the HMAC algorithms.
func TestHSAlgorithms(t *testing.T) {
	assert := asserts.NewTesting(t, asserts.FailStop)
	key := []byte("secret")
	for _, algo := range hsTests {
		assert.Logf("testing algorithm %q", algo)
		// Sign.
		signature, err := algo.Sign(data, key)
		assert.Nil(err)
		assert.NotEmpty(signature)
		// Verify.
		err = algo.Verify(data, signature, key)
		assert.Nil(err)
	}
}

// TestPSAlgorithms verifies the RSAPSS algorithms.
func TestPSAlgorithms(t *testing.T) {
	assert := asserts.NewTesting(t, asserts.FailStop)
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.Nil(err)
	for _, algo := range psTests {
		assert.Logf("testing algorithm %q", algo)
		// Sign.
		signature, err := algo.Sign(data, privateKey)
		assert.Nil(err)
		assert.NotEmpty(signature)
		// Verify.
		err = algo.Verify(data, signature, privateKey.Public())
		assert.Nil(err)
	}
}

// TestRSAlgorithms verifies the RSA algorithms.
func TestRSAlgorithms(t *testing.T) {
	assert := asserts.NewTesting(t, asserts.FailStop)
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.Nil(err)
	for _, algo := range rsTests {
		assert.Logf("testing algorithm %q", algo)
		// Sign.
		signature, err := algo.Sign(data, privateKey)
		assert.Nil(err)
		assert.NotEmpty(signature)
		// Verify.
		err = algo.Verify(data, signature, privateKey.Public())
		assert.Nil(err)
	}
}

// TestNoneAlgorithm verifies the none algorithm.
func TestNoneAlgorithm(t *testing.T) {
	assert := asserts.NewTesting(t, asserts.FailStop)
	assert.Logf("testing algorithm \"none\"")
	// Sign.
	signature, err := jwt.NONE.Sign(data, "")
	assert.Nil(err)
	assert.Empty(signature)
	// Verify.
	err = jwt.NONE.Verify(data, signature, "")
	assert.Nil(err)
}

// TestNotMatchingAlgorithm checks when algorithms of
// signing and verifying don't match.'
func TestNotMatchingAlgorithm(t *testing.T) {
	assert := asserts.NewTesting(t, asserts.FailStop)
	esPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	esPublicKey := esPrivateKey.Public()
	assert.Nil(err)
	hsKey := []byte("secret")
	rsPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	rsPublicKey := rsPrivateKey.Public()
	assert.Nil(err)
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
		assert.Logf("testing %q algorithm key type mismatch", test.description)
		for _, key := range test.signKeys {
			_, err := test.algorithm.Sign(data, key)
			assert.ErrorMatch(err, errorMatch)
		}
		signature, err := test.algorithm.Sign(data, test.key)
		assert.Nil(err)
		for _, key := range test.verifyKeys {
			err = test.algorithm.Verify(data, signature, key)
			assert.ErrorMatch(err, errorMatch)
		}
	}
}

// TestESTools verifies the tools for the reading of PEM encoded
// ECDSA keys.
func TestESTools(t *testing.T) {
	assert := asserts.NewTesting(t, asserts.FailStop)
	assert.Logf("testing \"ECDSA\" tools")
	// Generate keys and PEMs.
	privateKeyIn, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.Nil(err)
	privateBytes, err := x509.MarshalECPrivateKey(privateKeyIn)
	assert.Nil(err)
	privateBlock := pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateBytes,
	}
	privatePEM := pem.EncodeToMemory(&privateBlock)
	publicBytes, err := x509.MarshalPKIXPublicKey(privateKeyIn.Public())
	assert.Nil(err)
	publicBlock := pem.Block{
		Type:  "EC PUBLIC KEY",
		Bytes: publicBytes,
	}
	publicPEM := pem.EncodeToMemory(&publicBlock)
	assert.NotNil(publicPEM)
	// Now read them.
	buf := bytes.NewBuffer(privatePEM)
	privateKeyOut, err := jwt.ReadECPrivateKey(buf)
	assert.Nil(err)
	buf = bytes.NewBuffer(publicPEM)
	publicKeyOut, err := jwt.ReadECPublicKey(buf)
	assert.Nil(err)
	// And as a last step check if they are correctly usable.
	signature, err := jwt.ES512.Sign(data, privateKeyOut)
	assert.Nil(err)
	err = jwt.ES512.Verify(data, signature, publicKeyOut)
	assert.Nil(err)
}

// TestRSTools verifies the tools for the reading of PEM encoded
// RSA keys.
func TestRSTools(t *testing.T) {
	assert := asserts.NewTesting(t, asserts.FailStop)
	assert.Logf("testing \"RSA\" tools")
	// Generate keys and PEMs.
	privateKeyIn, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.Nil(err)
	privateBytes := x509.MarshalPKCS1PrivateKey(privateKeyIn)
	privateBlock := pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateBytes,
	}
	privatePEM := pem.EncodeToMemory(&privateBlock)
	publicBytes, err := x509.MarshalPKIXPublicKey(privateKeyIn.Public())
	assert.Nil(err)
	publicBlock := pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicBytes,
	}
	publicPEM := pem.EncodeToMemory(&publicBlock)
	assert.NotNil(publicPEM)
	// Now read them.
	buf := bytes.NewBuffer(privatePEM)
	privateKeyOut, err := jwt.ReadRSAPrivateKey(buf)
	assert.Nil(err)
	buf = bytes.NewBuffer(publicPEM)
	publicKeyOut, err := jwt.ReadRSAPublicKey(buf)
	assert.Nil(err)
	// And as a last step check if they are correctly usable.
	signature, err := jwt.RS512.Sign(data, privateKeyOut)
	assert.Nil(err)
	err = jwt.RS512.Verify(data, signature, publicKeyOut)
	assert.Nil(err)
}

// EOF
