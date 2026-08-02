/*
 *  Copyright (c) 2026, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package jwtauth

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// createMockRequestHeaderContextWithAPI is like createMockRequestHeaderContext but sets an API
// identity, needed to prove the verdict cache is isolated per API.
func createMockRequestHeaderContextWithAPI(headers map[string][]string, apiId, apiName string) *policy.RequestHeaderContext {
	return &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{
			RequestID: "test-request-id",
			Metadata:  make(map[string]interface{}),
			APIId:     apiId,
			APIName:   apiName,
		},
		Headers: policy.NewHeaders(headers),
		Path:    "/api/test",
		Method:  "GET",
	}
}

// expectedCacheKey reconstructs the cache key OnRequestHeaders would compute for the default
// mock request context (empty APIId/APIName), so tests can inspect the cache directly.
func expectedCacheKey(params map[string]interface{}, token string, validateIssuer bool, issuers []string, leeway time.Duration) string {
	fingerprint := tokenConfigFingerprint("", "", params["keyManagers"], validateIssuer, issuers, leeway)
	return buildTokenCacheKey(fingerprint, token)
}

// clearJWKSFetchCache wipes the unrelated, pre-existing JWKS-fetch cache (cacheStore/cacheTTLs)
// without touching the token verdict cache. Tests that prove the verdict cache is what's being
// exercised must clear this too — otherwise a token-verdict-cache miss can still "succeed"
// because the JWKS keys for that URI are separately warm from an earlier request.
func clearJWKSFetchCache() {
	ins.cacheMutex.Lock()
	defer ins.cacheMutex.Unlock()
	ins.cacheStore = make(map[string]*CachedJWKS)
	ins.cacheTTLs = make(map[string]time.Time)
}

func TestTokenCache_PositiveHit_SkipsVerification(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	var fetchCount int32
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/jwks.json" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		atomic.AddInt32(&fetchCount, 1)
		writeJWKSResponse(t, w, publicKey, "test-kid")
	}))

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub": "user-cache-1",
		"iss": "https://issuer.example.com",
	})

	p := mustGetPolicy(t, params)

	ctx1 := createMockRequestHeaderContext(authHeader("Authorization", "Bearer", token))
	action1 := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx1, params)
	assertAuthSuccess(t, ctx1, action1)
	if got := atomic.LoadInt32(&fetchCount); got != 1 {
		t.Fatalf("expected exactly 1 JWKS fetch after the first request, got %d", got)
	}

	// Clear the unrelated JWKS-fetch cache and take down the endpoint, so that anything which
	// falls through to full re-verification is forced to hit the (now-dead) network.
	clearJWKSFetchCache()
	jwksServer.Close()

	ctx2 := createMockRequestHeaderContext(authHeader("Authorization", "Bearer", token))
	action2 := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx2, params)
	assertAuthSuccess(t, ctx2, action2)

	// A different API identity must miss the verdict cache and attempt full re-verification,
	// which now fails because the JWKS endpoint is down and its fetch cache was cleared.
	ctx3 := createMockRequestHeaderContextWithAPI(authHeader("Authorization", "Bearer", token), "api-2", "OtherAPI")
	action3 := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx3, params)
	assertAuthFailure(t, ctx3, action3, 401)
}

func TestTokenCache_NegativeHit_Expired(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	expiredToken := createTestTokenWithExpiry(t, privateKey, map[string]interface{}{
		"sub": "user-expired",
		"iss": "https://issuer.example.com",
	}, time.Now().Add(-time.Hour))

	p := mustGetPolicy(t, params)

	ctx1 := createMockRequestHeaderContext(authHeader("Authorization", "Bearer", expiredToken))
	action1 := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx1, params)
	assertAuthFailure(t, ctx1, action1, 401)

	key := expectedCacheKey(params, expiredToken, true, []string{}, 30*time.Second)
	verdict, hit := ins.getCachedVerdict(context.Background(), key)
	if !hit {
		t.Fatalf("expected a cached verdict for the expired token")
	}
	if verdict.ok {
		t.Fatalf("expected a negative verdict, got a positive one")
	}
	const wantReason = "token validation failed: token expired"
	if verdict.reason != wantReason {
		t.Fatalf("expected reason %q, got %q", wantReason, verdict.reason)
	}

	// Second identical request must be served from the negative cache.
	ctx2 := createMockRequestHeaderContext(authHeader("Authorization", "Bearer", expiredToken))
	action2 := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx2, params)
	assertAuthFailure(t, ctx2, action2, 401)
}

func TestTokenCache_NegativeHit_Malformed(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	_, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	malformedToken := "not-a-jwt-token"

	p := mustGetPolicy(t, params)

	ctx1 := createMockRequestHeaderContext(authHeader("Authorization", "Bearer", malformedToken))
	action1 := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx1, params)
	assertAuthFailure(t, ctx1, action1, 401)

	key := expectedCacheKey(params, malformedToken, true, []string{}, 30*time.Second)
	verdict, hit := ins.getCachedVerdict(context.Background(), key)
	if !hit || verdict.ok || verdict.reason != "invalid token format" {
		t.Fatalf("expected cached negative verdict with reason %q, got hit=%v verdict=%+v", "invalid token format", hit, verdict)
	}

	ctx2 := createMockRequestHeaderContext(authHeader("Authorization", "Bearer", malformedToken))
	action2 := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx2, params)
	assertAuthFailure(t, ctx2, action2, 401)
}

func TestTokenCache_SignatureMismatch_NotCached(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	_, publicKey := generateTestKeys(t)
	wrongPrivateKey, _ := generateTestKeys(t)

	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	token := createTestToken(t, wrongPrivateKey, map[string]interface{}{
		"sub": "user-bad-sig",
		"iss": "https://issuer.example.com",
	})

	p := mustGetPolicy(t, params)
	ctx := createMockRequestHeaderContext(authHeader("Authorization", "Bearer", token))
	action := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx, params)
	assertAuthFailure(t, ctx, action, 401)

	key := expectedCacheKey(params, token, true, []string{}, 30*time.Second)
	if _, hit := ins.getCachedVerdict(context.Background(), key); hit {
		t.Fatalf("signature-mismatch failures must not be negatively cached")
	}
}

func TestTokenCache_JWKSFetchFailure_NotCached(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, _ := generateTestKeys(t)

	params := newRemoteParams("http://127.0.0.1:1/jwks.json") // reserved port, connection refused
	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub": "user-fetch-fail",
		"iss": "https://issuer.example.com",
	})

	p := mustGetPolicy(t, params)
	ctx := createMockRequestHeaderContext(authHeader("Authorization", "Bearer", token))
	action := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx, params)
	assertAuthFailure(t, ctx, action, 401)

	key := expectedCacheKey(params, token, true, []string{}, 30*time.Second)
	if _, hit := ins.getCachedVerdict(context.Background(), key); hit {
		t.Fatalf("JWKS fetch failures must not be negatively cached")
	}
}

func TestTokenCache_NotYetValid_NotCached(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub": "user-nbf",
		"iss": "https://issuer.example.com",
		"nbf": time.Now().Add(time.Hour).Unix(),
	})

	p := mustGetPolicy(t, params)
	ctx := createMockRequestHeaderContext(authHeader("Authorization", "Bearer", token))
	action := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx, params)
	assertAuthFailure(t, ctx, action, 401)

	key := expectedCacheKey(params, token, true, []string{}, 30*time.Second)
	if _, hit := ins.getCachedVerdict(context.Background(), key); hit {
		t.Fatalf("not-yet-valid (nbf) failures must not be negatively cached")
	}
}

func TestTokenCache_Disabled_NoCacheEntries(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	params["tokenCaching"] = false

	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub": "user-disabled",
		"iss": "https://issuer.example.com",
	})

	p := mustGetPolicy(t, params)
	for i := 0; i < 2; i++ {
		ctx := createMockRequestHeaderContext(authHeader("Authorization", "Bearer", token))
		action := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx, params)
		assertAuthSuccess(t, ctx, action)
	}

	if got := ins.currentTokenCache().GetStats().Size; got != 0 {
		t.Fatalf("expected no cache entries when tokenCaching=false, got %d", got)
	}
}

func TestTokenCache_PositiveTTL_CappedByTokenCacheTtl(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	params["tokenCacheTtl"] = "300ms"

	// Token exp is far in the future, so the cap must come from tokenCacheTtl, not the token.
	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub": "user-ttl-cap",
		"iss": "https://issuer.example.com",
	})

	p := mustGetPolicy(t, params)

	before := time.Now()
	ctx := createMockRequestHeaderContext(authHeader("Authorization", "Bearer", token))
	action := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx, params)
	assertAuthSuccess(t, ctx, action)

	key := expectedCacheKey(params, token, true, []string{}, 30*time.Second)
	verdict, hit := ins.getCachedVerdict(context.Background(), key)
	if !hit || !verdict.ok {
		t.Fatalf("expected a cached positive verdict")
	}
	if verdict.expiresAt.After(before.Add(1 * time.Second)) {
		t.Fatalf("expected cache expiry capped near tokenCacheTtl (300ms), got expiresAt=%v (now=%v)", verdict.expiresAt, before)
	}

	time.Sleep(500 * time.Millisecond)
	// Clear the unrelated JWKS-fetch cache and take down the endpoint: if the verdict-cache
	// entry had survived, the second call would still succeed regardless of these two lines.
	clearJWKSFetchCache()
	jwksServer.Close()

	ctx2 := createMockRequestHeaderContext(authHeader("Authorization", "Bearer", token))
	action2 := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx2, params)
	assertAuthFailure(t, ctx2, action2, 401)
}

func TestTokenCache_PositiveTTL_NeverExceedsTokenExpiry(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	// tokenCacheTtl stays at its 5m default; the token itself expires in 3s, so the cache
	// entry's expiry must be bounded by the token's exp, not the far larger 5m cap.
	params["leeway"] = "0s"
	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub": "user-short-exp",
		"iss": "https://issuer.example.com",
		"exp": time.Now().Add(3 * time.Second).Unix(),
	})

	p := mustGetPolicy(t, params)
	ctx := createMockRequestHeaderContext(authHeader("Authorization", "Bearer", token))
	action := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx, params)
	assertAuthSuccess(t, ctx, action)

	key := expectedCacheKey(params, token, true, []string{}, 0)
	verdict, hit := ins.getCachedVerdict(context.Background(), key)
	if !hit || !verdict.ok {
		t.Fatalf("expected a cached positive verdict")
	}
	if verdict.expiresAt.After(time.Now().Add(4 * time.Second)) {
		t.Fatalf("expected cache expiry bounded by the token's short exp, not the 5m tokenCacheTtl default; got %v", verdict.expiresAt)
	}
}

func TestTokenCache_NegativeTTL_ExpiresAfterWindow(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	params["negativeCacheTtl"] = "300ms"

	expiredToken := createTestTokenWithExpiry(t, privateKey, map[string]interface{}{
		"sub": "user-neg-ttl",
		"iss": "https://issuer.example.com",
	}, time.Now().Add(-time.Hour))

	p := mustGetPolicy(t, params)
	ctx := createMockRequestHeaderContext(authHeader("Authorization", "Bearer", expiredToken))
	action := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx, params)
	assertAuthFailure(t, ctx, action, 401)

	key := expectedCacheKey(params, expiredToken, true, []string{}, 30*time.Second)
	if _, hit := ins.getCachedVerdict(context.Background(), key); !hit {
		t.Fatalf("expected a negative cache entry immediately after the failed request")
	}

	time.Sleep(500 * time.Millisecond)

	if _, hit := ins.getCachedVerdict(context.Background(), key); hit {
		t.Fatalf("expected the negative cache entry to have expired after negativeCacheTtl")
	}
}

func TestTokenConfigFingerprint_ChangesInvalidateCache(t *testing.T) {
	km := []interface{}{
		map[string]interface{}{
			"name":   "km-primary",
			"issuer": "https://issuer.example.com",
			"jwks": map[string]interface{}{
				"remote": map[string]interface{}{"uri": "https://idp.example/jwks.json"},
			},
		},
	}
	base := tokenConfigFingerprint("api-1", "PetStore", km, true, []string{"km-primary"}, 30*time.Second)

	cases := []struct {
		name string
		fp   string
	}{
		{"different apiId", tokenConfigFingerprint("api-2", "PetStore", km, true, []string{"km-primary"}, 30*time.Second)},
		{"different apiName", tokenConfigFingerprint("api-1", "Other", km, true, []string{"km-primary"}, 30*time.Second)},
		{"different validateIssuer", tokenConfigFingerprint("api-1", "PetStore", km, false, []string{"km-primary"}, 30*time.Second)},
		{"different issuers", tokenConfigFingerprint("api-1", "PetStore", km, true, []string{"other"}, 30*time.Second)},
		{"different leeway", tokenConfigFingerprint("api-1", "PetStore", km, true, []string{"km-primary"}, time.Minute)},
	}
	for _, tc := range cases {
		if tc.fp == base {
			t.Errorf("%s: expected a different fingerprint, got the same value", tc.name)
		}
	}

	kmChanged := []interface{}{
		map[string]interface{}{
			"name":   "km-primary",
			"issuer": "https://issuer.example.com",
			"jwks": map[string]interface{}{
				"remote": map[string]interface{}{"uri": "https://idp.example/OTHER.json"},
			},
		},
	}
	if fp := tokenConfigFingerprint("api-1", "PetStore", kmChanged, true, []string{"km-primary"}, 30*time.Second); fp == base {
		t.Errorf("different key manager config: expected a different fingerprint, got the same value")
	}

	if again := tokenConfigFingerprint("api-1", "PetStore", km, true, []string{"km-primary"}, 30*time.Second); again != base {
		t.Errorf("expected tokenConfigFingerprint to be deterministic for identical inputs")
	}
}

func TestGetPolicy_TokenCacheMaxSizeApplied(t *testing.T) {
	resetJWTAuthSingletonCache(t)
	t.Cleanup(func() {
		ins.ensureTokenCache(defaultTokenCacheMaxSize)
	})

	params := newRemoteParams("http://127.0.0.1:1/jwks.json")
	params["cacheMaxSize"] = 5

	mustGetPolicy(t, params)

	if got := ins.currentTokenCache().GetStats().MaxSize; got != 5 {
		t.Fatalf("expected token cache MaxSize=5, got %d", got)
	}
}

func TestCacheMaxSize_GloballyBounded_TokenCache(t *testing.T) {
	resetJWTAuthSingletonCache(t)
	t.Cleanup(func() {
		ins.ensureTokenCache(defaultTokenCacheMaxSize)
	})

	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	params["cacheMaxSize"] = 2

	p := mustGetPolicy(t, params)

	for i := 0; i < 5; i++ {
		token := createTestToken(t, privateKey, map[string]interface{}{
			"sub": fmt.Sprintf("user-bound-%d", i),
			"iss": "https://issuer.example.com",
		})
		ctx := createMockRequestHeaderContext(authHeader("Authorization", "Bearer", token))
		action := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx, params)
		assertAuthSuccess(t, ctx, action)
	}

	stats := ins.currentTokenCache().GetStats()
	if stats.Size > 2 {
		t.Fatalf("expected cache size bounded at 2, got %d", stats.Size)
	}
	if stats.EvictCount == 0 {
		t.Fatalf("expected at least one eviction once 5 distinct tokens exceeded the size-2 bound")
	}
}
