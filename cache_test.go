// Tideland Go JSON Web Token - Cache - Unit Tests
//
// Copyright (C) 2016-2025 Frank Mueller / Tideland / Germany
//
// All rights reserved. Use of this source code is governed
// by the new BSD license.

package jwt_test // import "tideland.dev/go/jwt"


import (
	"context"
	"fmt"
	"testing"
	"time"

	"tideland.dev/go/asserts/verify"

	"tideland.dev/go/jwt"
)


// TestCachePutGet verifies the putting and getting of tokens
// to the cache.
func TestCachePutGet(t *testing.T) {
	ctx := context.Background()
	cache := jwt.NewCache(ctx, time.Minute, time.Minute, time.Minute, 10)
	key := []byte("secret")
	claims := initClaims()
	jwtIn, err := jwt.Encode(claims, key, jwt.HS512)
	verify.NoError(t, err)
	_, err = cache.Put(jwtIn)
	verify.NoError(t, err)
	jwt := jwtIn.String()
	jwtOut, err := cache.Get(jwt)
	verify.NoError(t, err)
	verify.Equal(t, jwtIn, jwtOut)
	jwtOut, err = cache.Get("is.not.there")
	verify.NoError(t, err)
	verify.True(t, jwtOut == nil)
}

// TestCacheAccessCleanup verifies the access based cleanup
// of the JWT cache.
func TestCacheAccessCleanup(t *testing.T) {
	ctx := context.Background()
	cache := jwt.NewCache(ctx, time.Second, time.Second, time.Second, 10)
	key := []byte("secret")
	claims := initClaims()
	jwtIn, err := jwt.Encode(claims, key, jwt.HS512)
	verify.NoError(t, err)
	_, err = cache.Put(jwtIn)
	verify.NoError(t, err)
	jwt := jwtIn.String()
	jwtOut, err := cache.Get(jwt)
	verify.NoError(t, err)
	verify.Equal(t, jwtIn, jwtOut)
	// Now wait a bit an try again.
	time.Sleep(5 * time.Second)
	jwtOut, err = cache.Get(jwt)
	verify.NoError(t, err)
	verify.True(t, jwtOut == nil)
}

// TestCacheValidityCleanup verifies the validity based cleanup
// of the JWT cache.
func TestCacheValidityCleanup(t *testing.T) {
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
	verify.NoError(t, err)
	_, err = cache.Put(jwtIn)
	verify.NoError(t, err)
	jwt := jwtIn.String()
	jwtOut, err := cache.Get(jwt)
	verify.NoError(t, err)
	verify.Equal(t, jwtOut, jwtIn)
	// Now access until it is invalid and not
	// available anymore.
	var i int
	for i = 0; i < 5; i++ {
		time.Sleep(time.Second)
		jwtOut, err = cache.Get(jwt)
		verify.NoError(t, err)
		if jwtOut == nil {
			break
		}
		verify.Equal(t, jwtOut, jwtIn)
	}
	verify.True(t, i > 1 && i < 4)
}

// TestCacheLoad verifies the cache load based cleanup.
func TestCacheLoad(t *testing.T) {
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
		verify.NoError(t, err)
		size, err := cache.Put(jwtIn)
		verify.NoError(t, err)
		verify.True(t, size < 6)
	}
}

// TestCacheContext verifies the cache stopping by context.
func TestCacheContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cache := jwt.NewCache(ctx, time.Minute, time.Minute, time.Minute, 10)
	key := []byte("secret")
	claims := initClaims()
	jwtIn, err := jwt.Encode(claims, key, jwt.HS512)
	verify.NoError(t, err)
	_, err = cache.Put(jwtIn)
	verify.NoError(t, err)
	// Now cancel and test to get jwt.
	cancel()
	time.Sleep(10 * time.Millisecond)
	jwt := jwtIn.String()
	jwtOut, err := cache.Get(jwt)
	verify.ErrorContains(t, err, "cache action timeout")
	verify.True(t, jwtOut == nil)
}


// initClaims creates test claims.
func initClaims() jwt.Claims {
	c := jwt.NewClaims()
	c.SetSubject("1234567890")
	c.Set("name", "John Doe")
	c.Set("admin", true)
	return c
}

