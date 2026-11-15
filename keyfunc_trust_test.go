package jwt_test

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/golang-jwt/jwt/v5/test"
)

// errUnknownKeyID is returned by the trusted key store when a token's kid
// does not identify a key that is already trusted.
var errUnknownKeyID = errors.New("unknown key id")

// trustFixtures holds the key material for the keyfunc trust boundary tests.
// "Trusted" keys model a key set a verifier has pinned out-of-band (e.g. a
// JWKS it fetched from its own IdP); "attacker" keys are only known to the
// token issuer and must never be selected by a kid lookup.
var (
	trustOldRSAPrivate *rsa.PrivateKey // kid "rsa-old", retired during rotation
	trustOldRSAPublic  *rsa.PublicKey
	trustNewRSAPrivate *rsa.PrivateKey // kid "rsa-new"
	trustNewRSAPublic  *rsa.PublicKey
	trustECPrivate     any // kid "ec-1"
	trustECPublic      any
	trustHMACSecret    = []byte("trusted-hmac-secret") // kid "hmac-1"

	attackerRSAPrivate *rsa.PrivateKey
	attackerHMACSecret = []byte("attacker-hmac-secret")
)

// trustedKeys is the verifier-side key set. kid values are only ever used to
// look up keys that are already in this map; a kid can never add a key to it.
// It is populated in init(), once the key material has been loaded.
var trustedKeys map[string]jwt.VerificationKey

func init() {
	trustOldRSAPrivate = test.LoadRSAPrivateKeyFromDisk("test/sample_key")
	trustOldRSAPublic = test.LoadRSAPublicKeyFromDisk("test/sample_key.pub")
	trustECPrivate = test.LoadECPrivateKeyFromDisk("test/ec256-private.pem")
	trustECPublic = test.LoadECPublicKeyFromDisk("test/ec256-public.pem")

	var err error
	if trustNewRSAPrivate, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
		panic(err)
	}
	trustNewRSAPublic = &trustNewRSAPrivate.PublicKey
	if attackerRSAPrivate, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
		panic(err)
	}

	trustedKeys = map[string]jwt.VerificationKey{
		"rsa-old": trustOldRSAPublic,
		"rsa-new": trustNewRSAPublic,
		"ec-1":    trustECPublic,
		"hmac-1":  trustHMACSecret,
	}
}

// trustedStoreKeyFunc models a verifier that pins a trusted key set and uses
// the token's kid header only to select a key from that set.
func trustedStoreKeyFunc(store map[string]jwt.VerificationKey) jwt.Keyfunc {
	return func(t *jwt.Token) (any, error) {
		kid, ok := t.Header[jwt.HeaderKeyID].(string)
		if !ok {
			return nil, errUnknownKeyID
		}
		key, ok := store[kid]
		if !ok {
			return nil, errUnknownKeyID
		}
		return key, nil
	}
}

// signWithKID creates a signed token carrying the given kid header.
func signWithKID(t *testing.T, method jwt.SigningMethod, key any, kid string, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(method, claims)
	if kid != "" {
		token.Header[jwt.HeaderKeyID] = kid
	}
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	return signed
}

// assertRejected checks the invariants every failed parse must uphold: an
// error is returned, it matches all expected sentinel errors, and the token
// is never marked valid.
func assertRejected(t *testing.T, token *jwt.Token, err error, wantErrs ...error) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error(s) %v, got none", wantErrs)
	}
	for _, want := range wantErrs {
		if !errors.Is(err, want) {
			t.Errorf("error %v does not contain expected %v", err, want)
		}
	}
	if token != nil && token.Valid {
		t.Errorf("failed parse must never mark the token valid")
	}
}

// TestKeyfuncTrustErrorPropagation verifies that empty key sets, wrong key
// types, cross-algorithm keys and keyfunc errors all surface with the
// documented error semantics, and that a matching key verifies regardless of
// its position in a VerificationKeySet.
func TestKeyfuncTrustErrorPropagation(t *testing.T) {
	rsaToken := signWithKID(t, jwt.SigningMethodRS256, trustNewRSAPrivate, "rsa-new", jwt.MapClaims{"foo": "bar"})

	tests := []struct {
		name     string
		token    string
		keyfunc  jwt.Keyfunc
		valid    bool
		wantErrs []error
	}{
		{
			name:  "empty verification key set",
			token: rsaToken,
			keyfunc: func(t *jwt.Token) (any, error) {
				return jwt.VerificationKeySet{}, nil
			},
			wantErrs: []error{jwt.ErrTokenUnverifiable},
		},
		{
			name:  "keyfunc error is propagated",
			token: rsaToken,
			keyfunc: func(t *jwt.Token) (any, error) {
				return nil, errUnknownKeyID
			},
			wantErrs: []error{jwt.ErrTokenUnverifiable, errUnknownKeyID},
		},
		{
			name:  "wrong key type (HMAC secret for RSA token)",
			token: rsaToken,
			keyfunc: func(t *jwt.Token) (any, error) {
				return trustHMACSecret, nil
			},
			wantErrs: []error{jwt.ErrTokenSignatureInvalid, jwt.ErrInvalidKeyType},
		},
		{
			name:  "cross-algorithm key (EC key for RSA token)",
			token: rsaToken,
			keyfunc: func(t *jwt.Token) (any, error) {
				return trustECPublic, nil
			},
			wantErrs: []error{jwt.ErrTokenSignatureInvalid, jwt.ErrInvalidKeyType},
		},
		{
			name:  "cross-algorithm key (RSA key for ECDSA token)",
			token: signWithKID(t, jwt.SigningMethodES256, trustECPrivate, "ec-1", jwt.MapClaims{"foo": "bar"}),
			keyfunc: func(t *jwt.Token) (any, error) {
				return trustNewRSAPublic, nil
			},
			wantErrs: []error{jwt.ErrTokenSignatureInvalid, jwt.ErrInvalidKeyType},
		},
		{
			name:  "nil key",
			token: rsaToken,
			keyfunc: func(t *jwt.Token) (any, error) {
				return nil, nil
			},
			wantErrs: []error{jwt.ErrTokenSignatureInvalid},
		},
		{
			name:  "matching key first in set",
			token: rsaToken,
			keyfunc: func(t *jwt.Token) (any, error) {
				return jwt.VerificationKeySet{Keys: []jwt.VerificationKey{trustNewRSAPublic, trustOldRSAPublic, trustECPublic}}, nil
			},
			valid: true,
		},
		{
			name:  "matching key in the middle of set",
			token: rsaToken,
			keyfunc: func(t *jwt.Token) (any, error) {
				return jwt.VerificationKeySet{Keys: []jwt.VerificationKey{trustOldRSAPublic, trustNewRSAPublic, trustECPublic}}, nil
			},
			valid: true,
		},
		{
			name:  "matching key last in set",
			token: rsaToken,
			keyfunc: func(t *jwt.Token) (any, error) {
				return jwt.VerificationKeySet{Keys: []jwt.VerificationKey{trustECPublic, trustOldRSAPublic, trustNewRSAPublic}}, nil
			},
			valid: true,
		},
		{
			name:  "no key in set matches",
			token: rsaToken,
			keyfunc: func(t *jwt.Token) (any, error) {
				return jwt.VerificationKeySet{Keys: []jwt.VerificationKey{trustECPublic, trustOldRSAPublic}}, nil
			},
			wantErrs: []error{jwt.ErrTokenSignatureInvalid},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := jwt.ParseWithClaims(tt.token, jwt.MapClaims{}, tt.keyfunc)
			if tt.valid {
				if err != nil {
					t.Fatalf("expected valid token, got error: %v", err)
				}
				if !token.Valid {
					t.Errorf("token.Valid = false, want true")
				}
				if got := token.Claims.(jwt.MapClaims)["foo"]; got != "bar" {
					t.Errorf("claim foo = %v, want bar", got)
				}
				return
			}
			assertRejected(t, token, err, tt.wantErrs...)
		})
	}
}

// TestKeyfuncTrustAlgWhitelist verifies that the algorithm whitelist rejects
// tokens before the keyfunc is even consulted, and that an alg-confusion
// attempt (HS256 token naming an RSA key's kid) fails on every path.
func TestKeyfuncTrustAlgWhitelist(t *testing.T) {
	rsaToken := signWithKID(t, jwt.SigningMethodRS256, trustNewRSAPrivate, "rsa-new", jwt.MapClaims{"foo": "bar"})

	t.Run("token alg not in whitelist", func(t *testing.T) {
		keyfuncCalled := false
		keyfunc := func(token *jwt.Token) (any, error) {
			keyfuncCalled = true
			return trustNewRSAPublic, nil
		}
		parser := jwt.NewParser(jwt.WithValidMethods([]string{"ES256"}))
		token, err := parser.ParseWithClaims(rsaToken, jwt.MapClaims{}, keyfunc)
		assertRejected(t, token, err, jwt.ErrTokenSignatureInvalid)
		if keyfuncCalled {
			t.Errorf("keyfunc must not be called when the alg whitelist rejects the token")
		}
	})

	t.Run("token alg in whitelist", func(t *testing.T) {
		parser := jwt.NewParser(jwt.WithValidMethods([]string{"RS256"}))
		token, err := parser.ParseWithClaims(rsaToken, jwt.MapClaims{}, trustedStoreKeyFunc(trustedKeys))
		if err != nil {
			t.Fatalf("expected valid token, got error: %v", err)
		}
		if !token.Valid {
			t.Errorf("token.Valid = false, want true")
		}
	})

	// Classic algorithm confusion: the attacker signs with HMAC, using the
	// kid of a trusted RSA key, hoping the verifier hands its RSA public key
	// to the HMAC verifier as the shared secret.
	confusedToken := signWithKID(t, jwt.SigningMethodHS256, attackerHMACSecret, "rsa-new", jwt.MapClaims{"foo": "bar"})

	t.Run("alg confusion without whitelist fails on key type", func(t *testing.T) {
		token, err := jwt.ParseWithClaims(confusedToken, jwt.MapClaims{}, trustedStoreKeyFunc(trustedKeys))
		assertRejected(t, token, err, jwt.ErrTokenSignatureInvalid, jwt.ErrInvalidKeyType)
	})

	t.Run("alg confusion with whitelist fails before keyfunc", func(t *testing.T) {
		keyfuncCalled := false
		keyfunc := func(token *jwt.Token) (any, error) {
			keyfuncCalled = true
			return trustedStoreKeyFunc(trustedKeys)(token)
		}
		parser := jwt.NewParser(jwt.WithValidMethods([]string{"RS256"}))
		token, err := parser.ParseWithClaims(confusedToken, jwt.MapClaims{}, keyfunc)
		assertRejected(t, token, err, jwt.ErrTokenSignatureInvalid)
		if keyfuncCalled {
			t.Errorf("keyfunc must not be called when the alg whitelist rejects the token")
		}
	})
}

// TestKeyfuncTrustKIDSelection proves that kid can only filter a pre-trusted
// key set: it cannot pull in attacker-controlled keys, cannot substitute a
// key across algorithms, and cannot make a wrongly-signed token verify.
func TestKeyfuncTrustKIDSelection(t *testing.T) {
	keyfunc := trustedStoreKeyFunc(trustedKeys)

	t.Run("unknown kid is rejected", func(t *testing.T) {
		tokenString := signWithKID(t, jwt.SigningMethodHS256, attackerHMACSecret, "attacker-kid", jwt.MapClaims{"foo": "bar"})
		token, err := jwt.ParseWithClaims(tokenString, jwt.MapClaims{}, keyfunc)
		assertRejected(t, token, err, jwt.ErrTokenUnverifiable, errUnknownKeyID)
	})

	t.Run("missing kid is rejected", func(t *testing.T) {
		tokenString := signWithKID(t, jwt.SigningMethodRS256, trustNewRSAPrivate, "", jwt.MapClaims{"foo": "bar"})
		token, err := jwt.ParseWithClaims(tokenString, jwt.MapClaims{}, keyfunc)
		assertRejected(t, token, err, jwt.ErrTokenUnverifiable, errUnknownKeyID)
	})

	t.Run("known kid but signed with untrusted key", func(t *testing.T) {
		// The attacker knows a valid kid but not the corresponding private key.
		tokenString := signWithKID(t, jwt.SigningMethodRS256, attackerRSAPrivate, "rsa-new", jwt.MapClaims{"foo": "bar"})
		token, err := jwt.ParseWithClaims(tokenString, jwt.MapClaims{}, keyfunc)
		assertRejected(t, token, err, jwt.ErrTokenSignatureInvalid)
	})

	t.Run("kid cannot cross algorithms", func(t *testing.T) {
		// kid names the trusted EC key, but the token claims RS256: the
		// selected key must not verify a different algorithm's signature.
		tokenString := signWithKID(t, jwt.SigningMethodRS256, trustNewRSAPrivate, "ec-1", jwt.MapClaims{"foo": "bar"})
		token, err := jwt.ParseWithClaims(tokenString, jwt.MapClaims{}, keyfunc)
		assertRejected(t, token, err, jwt.ErrTokenSignatureInvalid, jwt.ErrInvalidKeyType)
	})

	t.Run("kid of wrong key in same algorithm", func(t *testing.T) {
		// Signed with the new RSA key but naming the old one: kid selects a
		// key, not a signature, so verification must fail.
		tokenString := signWithKID(t, jwt.SigningMethodRS256, trustNewRSAPrivate, "rsa-old", jwt.MapClaims{"foo": "bar"})
		token, err := jwt.ParseWithClaims(tokenString, jwt.MapClaims{}, keyfunc)
		assertRejected(t, token, err, jwt.ErrTokenSignatureInvalid)
	})

	t.Run("trusted kid verifies", func(t *testing.T) {
		tokenString := signWithKID(t, jwt.SigningMethodRS256, trustNewRSAPrivate, "rsa-new", jwt.MapClaims{"foo": "bar"})
		token, err := jwt.ParseWithClaims(tokenString, jwt.MapClaims{}, keyfunc)
		if err != nil {
			t.Fatalf("expected valid token, got error: %v", err)
		}
		if !token.Valid {
			t.Errorf("token.Valid = false, want true")
		}
	})
}

// TestKeyfuncTrustRotation covers legitimate key rotation: overlapping key
// sets, retirement of the old key, duplicate kids and single-entry sets must
// all keep verifying genuine tokens and parsing their claims.
func TestKeyfuncTrustRotation(t *testing.T) {
	oldToken := signWithKID(t, jwt.SigningMethodRS256, trustOldRSAPrivate, "rsa-old", jwt.MapClaims{"sub": "alice"})
	newToken := signWithKID(t, jwt.SigningMethodRS256, trustNewRSAPrivate, "rsa-new", jwt.MapClaims{"sub": "alice"})

	t.Run("both keys accepted during rotation window", func(t *testing.T) {
		keyfunc := trustedStoreKeyFunc(trustedKeys)
		for name, tokenString := range map[string]string{"old key": oldToken, "new key": newToken} {
			t.Run(name, func(t *testing.T) {
				token, err := jwt.ParseWithClaims(tokenString, jwt.MapClaims{}, keyfunc)
				if err != nil {
					t.Fatalf("expected valid token, got error: %v", err)
				}
				if !token.Valid {
					t.Errorf("token.Valid = false, want true")
				}
				if got := token.Claims.(jwt.MapClaims)["sub"]; got != "alice" {
					t.Errorf("claim sub = %v, want alice", got)
				}
			})
		}
	})

	t.Run("old key rejected after rotation completes", func(t *testing.T) {
		rotated := map[string]jwt.VerificationKey{"rsa-new": trustNewRSAPublic}
		keyfunc := trustedStoreKeyFunc(rotated)

		token, err := jwt.ParseWithClaims(oldToken, jwt.MapClaims{}, keyfunc)
		assertRejected(t, token, err, jwt.ErrTokenUnverifiable, errUnknownKeyID)

		token, err = jwt.ParseWithClaims(newToken, jwt.MapClaims{}, keyfunc)
		if err != nil {
			t.Fatalf("expected valid token, got error: %v", err)
		}
		if !token.Valid {
			t.Errorf("token.Valid = false, want true")
		}
	})

	t.Run("duplicate kid entries in key set", func(t *testing.T) {
		keyfunc := func(t *jwt.Token) (any, error) {
			return jwt.VerificationKeySet{Keys: []jwt.VerificationKey{trustNewRSAPublic, trustNewRSAPublic}}, nil
		}
		token, err := jwt.ParseWithClaims(newToken, jwt.MapClaims{}, keyfunc)
		if err != nil {
			t.Fatalf("expected valid token, got error: %v", err)
		}
		if !token.Valid {
			t.Errorf("token.Valid = false, want true")
		}
	})

	t.Run("single valid key in set", func(t *testing.T) {
		keyfunc := func(t *jwt.Token) (any, error) {
			return jwt.VerificationKeySet{Keys: []jwt.VerificationKey{trustNewRSAPublic}}, nil
		}
		token, err := jwt.ParseWithClaims(newToken, jwt.MapClaims{}, keyfunc)
		if err != nil {
			t.Fatalf("expected valid token, got error: %v", err)
		}
		if !token.Valid {
			t.Errorf("token.Valid = false, want true")
		}
		if got := token.Claims.(jwt.MapClaims)["sub"]; got != "alice" {
			t.Errorf("claim sub = %v, want alice", got)
		}
	})

	t.Run("set with only unrelated keys rejects", func(t *testing.T) {
		keyfunc := func(t *jwt.Token) (any, error) {
			return jwt.VerificationKeySet{Keys: []jwt.VerificationKey{trustOldRSAPublic, trustECPublic}}, nil
		}
		token, err := jwt.ParseWithClaims(newToken, jwt.MapClaims{}, keyfunc)
		assertRejected(t, token, err, jwt.ErrTokenSignatureInvalid)
	})
}
