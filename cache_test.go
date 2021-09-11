// Tideland Go JSON Web Token - Cache - Unit Tests
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
	"context"
	"fmt"
	"testing"
	"time"

	"tideland.dev/go/audit/asserts"

	"tideland.dev/go/jwt"
)

//--------------------
// TESTS
//--------------------

// TestCachePutGet verifies the putting and getting of tokens
// to the cache.
func TestCachePutGet(t *testing.T) {
	assert := asserts.NewTesting(t, asserts.FailStop)
	assert.Logf("testing cache put and get")
	ctx := context.Background()
	cache := jwt.NewCache(ctx, time.Minute, time.Minute, time.Minute, 10)
	key := []byte("secret")
	claims := initClaims()
	jwtIn, err := jwt.Encode(claims, key, jwt.HS512)
	assert.Nil(err)
	_, err = cache.Put(jwtIn)
	assert.NoError(err)
	jwt := jwtIn.String()
	jwtOut, err := cache.Get(jwt)
	assert.NoError(err)
	assert.Equal(jwtIn, jwtOut)
	jwtOut, err = cache.Get("is.not.there")
	assert.NoError(err)
	assert.Nil(jwtOut)
}

// TestCacheAccessCleanup verifies the access based cleanup
// of the JWT cache.
func TestCacheAccessCleanup(t *testing.T) {
	assert := asserts.NewTesting(t, asserts.FailStop)
	assert.Logf("testing cache access based cleanup")
	ctx := context.Background()
	cache := jwt.NewCache(ctx, time.Second, time.Second, time.Second, 10)
	key := []byte("secret")
	claims := initClaims()
	jwtIn, err := jwt.Encode(claims, key, jwt.HS512)
	assert.NoError(err)
	_, err = cache.Put(jwtIn)
	assert.NoError(err)
	jwt := jwtIn.String()
	jwtOut, err := cache.Get(jwt)
	assert.NoError(err)
	assert.Equal(jwtIn, jwtOut)
	// Now wait a bit an try again.
	time.Sleep(5 * time.Second)
	jwtOut, err = cache.Get(jwt)
	assert.NoError(err)
	assert.Nil(jwtOut)
}

// TestCacheValidityCleanup verifies the validity based cleanup
// of the JWT cache.
func TestCacheValidityCleanup(t *testing.T) {
	assert := asserts.NewTesting(t, asserts.FailStop)
	assert.Logf("testing cache validity based cleanup")
	ctx := context.Background()
	cache := jwt.NewCache(ctx, time.Minute, time.Second, time.Second, 10)
	key := []byte("secret")
	now := time.Now()
	nbf := now.Add(-2 * time.Second)
	exp := now.Add(2 * time.Second)
	claims := initClaims()
	claims.SetNotBefore(nbf)
	claims.SetExpiration(exp)
	jwtIn, err := jwt.Encode(claims, key, jwt.HS512)
	assert.Nil(err)
	_, err = cache.Put(jwtIn)
	assert.NoError(err)
	jwt := jwtIn.String()
	jwtOut, err := cache.Get(jwt)
	assert.NoError(err)
	assert.Equal(jwtOut, jwtIn)
	// Now access until it is invalid and not
	// available anymore.
	var i int
	for i = 0; i < 5; i++ {
		time.Sleep(time.Second)
		jwtOut, err = cache.Get(jwt)
		assert.NoError(err)
		if jwtOut == nil {
			break
		}
		assert.Equal(jwtOut, jwtIn)
	}
	assert.True(i > 1 && i < 4)
}

// TestCacheLoad verifies the cache load based cleanup.
func TestCacheLoad(t *testing.T) {
	assert := asserts.NewTesting(t, asserts.FailStop)
	assert.Logf("testing cache load based cleanup")
	cacheTime := 100 * time.Millisecond
	ctx := context.Background()
	cache := jwt.NewCache(ctx, 2*cacheTime, cacheTime, cacheTime, 4)
	claims := initClaims()
	// Now fill the cache and check that it doesn't
	// grow too high.
	var i int
	for i = 0; i < 10; i++ {
		time.Sleep(50 * time.Millisecond)
		key := []byte(fmt.Sprintf("secret-%d", i))
		jwtIn, err := jwt.Encode(claims, key, jwt.HS512)
		assert.Nil(err)
		size, err := cache.Put(jwtIn)
		assert.NoError(err)
		assert.True(size < 6)
	}
}

// TestCacheContext verifies the cache stopping by context.
func TestCacheContext(t *testing.T) {
	assert := asserts.NewTesting(t, asserts.FailStop)
	assert.Logf("testing cache stopping by context")
	ctx, cancel := context.WithCancel(context.Background())
	cache := jwt.NewCache(ctx, time.Minute, time.Minute, time.Minute, 10)
	key := []byte("secret")
	claims := initClaims()
	jwtIn, err := jwt.Encode(claims, key, jwt.HS512)
	assert.NoError(err)
	_, err = cache.Put(jwtIn)
	assert.NoError(err)
	// Now cancel and test to get jwt.
	cancel()
	time.Sleep(10 * time.Millisecond)
	jwt := jwtIn.String()
	jwtOut, err := cache.Get(jwt)
	assert.ErrorContains(err, "cache action timeout")
	assert.Nil(jwtOut)
}

//--------------------
// HELPERS
//--------------------

// initClaims creates test claims.
func initClaims() jwt.Claims {
	c := jwt.NewClaims()
	c.SetSubject("1234567890")
	c.Set("name", "John Doe")
	c.Set("admin", true)
	return c
}

// EOF
