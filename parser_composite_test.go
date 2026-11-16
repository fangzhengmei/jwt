package jwt_test

import (
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// compositePolicyErr simulates an application-specific identity check failing
// inside a custom Claims implementation.
var compositePolicyErr = errors.New("custom claims policy rejected")

// compositeKeyfuncErr simulates a key lookup backend (KMS, JWKS cache, ...)
// failing while the parser asks for a verification key.
var compositeKeyfuncErr = errors.New("key lookup backend unavailable")

// compositePolicyClaims is a custom claims type whose Validate implements
// jwt.ClaimsValidator. The unexported fields are test instrumentation and are
// never serialized into the signed token.
type compositePolicyClaims struct {
	Foo string `json:"foo"`

	validateCalls int
	validateErr   error

	jwt.RegisteredClaims
}

func (c *compositePolicyClaims) Validate() error {
	c.validateCalls++
	return c.validateErr
}

var _ jwt.ClaimsValidator = (*compositePolicyClaims)(nil)

var (
	compositeSigningKey = []byte("composite validation signing key, 32+ bytes")
	compositeOtherKey   = []byte("a different key that must not verify the token")
)

// signCompositeToken produces a genuinely signed token (never a hand-crafted
// string), so every signature failure below is the result of real
// cryptographic verification.
func signCompositeToken(t *testing.T, claims jwt.Claims, method jwt.SigningMethod, key any) string {
	t.Helper()

	raw, err := jwt.NewWithClaims(method, claims).SignedString(key)
	if err != nil {
		t.Fatalf("failed to sign test token: %v", err)
	}

	return raw
}

// countErrors walks the (possibly joined) error tree and counts leaves equal to
// target. The parser wraps every sentinel error via fmt.Errorf, so the leaves
// are the sentinels themselves; walking them lets a test assert that *multiple*
// distinct validation failures were aggregated, which errors.Is alone cannot
// show.
func countErrors(err, target error) int {
	if err == nil {
		return 0
	}

	count := 0
	if err == target {
		count++
	}

	switch e := err.(type) {
	case interface{ Unwrap() []error }:
		for _, child := range e.Unwrap() {
			count += countErrors(child, target)
		}
	case interface{ Unwrap() error }:
		count += countErrors(e.Unwrap(), target)
	}

	return count
}

// requireRejectedToken asserts that a failed parse cannot be mistaken for a
// successful one: a token is either absent or explicitly marked invalid.
func requireRejectedToken(t *testing.T, token *jwt.Token, err error) {
	t.Helper()

	if err == nil {
		t.Fatal("expected parsing to fail, got nil error")
	}
	if token == nil {
		return
	}
	if token.Valid {
		t.Fatal("token marked valid although parsing returned an error")
	}
}

// TestParseWithClaims_CompositeSignatureKeyfuncAndClaimsFailures covers the
// three ways a parse can fail around verification: the signature doesn't
// verify, the Keyfunc itself fails, or required claims are missing. Each cause
// must stay distinguishable through errors.Is, claims validation must never run
// once verification failed, and no failure may leave an acceptable token.
func TestParseWithClaims_CompositeSignatureKeyfuncAndClaimsFailures(t *testing.T) {
	// requiredClaimsParser demands exp and iss, which the base claims below do
	// not carry. Using it in the signature and keyfunc cases proves claims
	// validation is never reached after those failures.
	requiredClaimsParser := func() *jwt.Parser {
		return jwt.NewParser(jwt.WithExpirationRequired(), jwt.WithIssuer("expected-issuer"))
	}

	baseClaims := func() *compositePolicyClaims {
		return &compositePolicyClaims{Foo: "bar"}
	}

	type errorCount struct {
		err   error
		count int
	}

	tests := []struct {
		name              string
		claims            func() *compositePolicyClaims
		keyfunc           jwt.Keyfunc
		newParser         func() *jwt.Parser
		wantErrors        []error
		wantNotErrors     []error
		wantCounts        []errorCount
		wantValid         bool
		wantValidateCalls int
	}{
		{
			name:              "valid signature and passing claims checks",
			claims:            baseClaims,
			keyfunc:           func(*jwt.Token) (any, error) { return compositeSigningKey, nil },
			wantValid:         true,
			wantValidateCalls: 1,
		},
		{
			name:   "signature mismatch against a real signature",
			claims: baseClaims,
			keyfunc: func(*jwt.Token) (any, error) {
				return compositeOtherKey, nil
			},
			newParser:     requiredClaimsParser,
			wantErrors:    []error{jwt.ErrTokenSignatureInvalid, jwt.ErrSignatureInvalid},
			wantNotErrors: []error{jwt.ErrTokenUnverifiable, jwt.ErrTokenInvalidClaims, jwt.ErrTokenRequiredClaimMissing},
		},
		{
			name:   "signature verification rejects a faulty key type",
			claims: baseClaims,
			keyfunc: func(*jwt.Token) (any, error) {
				return "not-a-byte-slice", nil
			},
			newParser:     requiredClaimsParser,
			wantErrors:    []error{jwt.ErrTokenSignatureInvalid, jwt.ErrInvalidKeyType},
			wantNotErrors: []error{jwt.ErrTokenUnverifiable, jwt.ErrTokenInvalidClaims},
		},
		{
			name:   "keyfunc backend failure",
			claims: baseClaims,
			keyfunc: func(*jwt.Token) (any, error) {
				return nil, compositeKeyfuncErr
			},
			newParser:     requiredClaimsParser,
			wantErrors:    []error{jwt.ErrTokenUnverifiable, compositeKeyfuncErr},
			wantNotErrors: []error{jwt.ErrTokenSignatureInvalid, jwt.ErrTokenInvalidClaims, jwt.ErrTokenRequiredClaimMissing},
		},
		{
			name:   "empty verification key set",
			claims: baseClaims,
			keyfunc: func(*jwt.Token) (any, error) {
				return jwt.VerificationKeySet{}, nil
			},
			newParser:     requiredClaimsParser,
			wantErrors:    []error{jwt.ErrTokenUnverifiable},
			wantNotErrors: []error{jwt.ErrTokenSignatureInvalid, jwt.ErrTokenInvalidClaims},
		},
		{
			name:              "nil keyfunc",
			claims:            baseClaims,
			keyfunc:           nil,
			newParser:         requiredClaimsParser,
			wantErrors:        []error{jwt.ErrTokenUnverifiable},
			wantNotErrors:     []error{jwt.ErrTokenSignatureInvalid, jwt.ErrTokenInvalidClaims},
			wantValidateCalls: 0,
		},
		{
			name:              "valid signature but required claims missing",
			claims:            baseClaims,
			keyfunc:           func(*jwt.Token) (any, error) { return compositeSigningKey, nil },
			newParser:         requiredClaimsParser,
			wantErrors:        []error{jwt.ErrTokenInvalidClaims, jwt.ErrTokenRequiredClaimMissing},
			wantNotErrors:     []error{jwt.ErrTokenSignatureInvalid, jwt.ErrTokenUnverifiable},
			wantCounts:        []errorCount{{jwt.ErrTokenRequiredClaimMissing, 2}},
			wantValidateCalls: 1,
		},
		{
			name: "valid signature with missing required claims and a failing custom check",
			claims: func() *compositePolicyClaims {
				return &compositePolicyClaims{Foo: "bar", validateErr: compositePolicyErr}
			},
			keyfunc:           func(*jwt.Token) (any, error) { return compositeSigningKey, nil },
			newParser:         requiredClaimsParser,
			wantErrors:        []error{jwt.ErrTokenInvalidClaims, jwt.ErrTokenRequiredClaimMissing, compositePolicyErr},
			wantNotErrors:     []error{jwt.ErrTokenSignatureInvalid, jwt.ErrTokenUnverifiable},
			wantCounts:        []errorCount{{jwt.ErrTokenRequiredClaimMissing, 2}},
			wantValidateCalls: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := tt.claims()
			raw := signCompositeToken(t, claims, jwt.SigningMethodHS256, compositeSigningKey)

			parser := jwt.NewParser()
			if tt.newParser != nil {
				parser = tt.newParser()
			}

			token, err := parser.ParseWithClaims(raw, claims, tt.keyfunc)

			if tt.wantValid {
				if err != nil {
					t.Fatalf("expected token to parse, got error: %v", err)
				}
				if token == nil || !token.Valid {
					t.Fatalf("expected a valid token, got %+v", token)
				}
			} else {
				requireRejectedToken(t, token, err)
			}

			for _, want := range tt.wantErrors {
				if !errors.Is(err, want) {
					t.Errorf("errors.Is(err, %v) = false, want true (err = %v)", want, err)
				}
			}
			for _, notWant := range tt.wantNotErrors {
				if errors.Is(err, notWant) {
					t.Errorf("errors.Is(err, %v) = true, want false: failure causes must stay distinguishable (err = %v)", notWant, err)
				}
			}
			for _, wc := range tt.wantCounts {
				if got := countErrors(err, wc.err); got != wc.count {
					t.Errorf("error %v appears %d times, want %d (err = %v)", wc.err, got, wc.count, err)
				}
			}

			if claims.validateCalls != tt.wantValidateCalls {
				t.Errorf("custom Validate called %d times, want %d", claims.validateCalls, tt.wantValidateCalls)
			}

			if !tt.wantValid && token != nil {
				// The parser still exposes the raw token and its signature after
				// a failure; only Valid may be used to decide acceptance.
				if token.Raw != raw {
					t.Errorf("token.Raw = %q, want the parsed token string", token.Raw)
				}
				if len(token.Signature) == 0 {
					t.Error("token.Signature is empty after a failed parse, want it populated for diagnostics")
				}
			}
		})
	}
}

// TestParseWithClaims_TimeErrorDoesNotMaskClaimsFailure pins down that a
// handleable time error (expired / not yet valid) never stands in for a
// successful identity check. Callers commonly special-case time errors as
// "refresh and retry"; the same error value must still carry the claims
// failure, and the token must stay invalid.
func TestParseWithClaims_TimeErrorDoesNotMaskClaimsFailure(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	expired := now.Add(-time.Hour)
	notYetValid := now.Add(time.Hour)

	tests := []struct {
		name          string
		configure     func(*compositePolicyClaims)
		wantErrors    []error
		wantNotErrors []error
	}{
		{
			name: "expired token with failing custom claims check",
			configure: func(c *compositePolicyClaims) {
				c.ExpiresAt = jwt.NewNumericDate(expired)
				c.validateErr = compositePolicyErr
			},
			wantErrors:    []error{jwt.ErrTokenInvalidClaims, jwt.ErrTokenExpired, compositePolicyErr},
			wantNotErrors: []error{jwt.ErrTokenSignatureInvalid, jwt.ErrTokenUnverifiable},
		},
		{
			name: "expired token with passing custom claims check",
			configure: func(c *compositePolicyClaims) {
				c.ExpiresAt = jwt.NewNumericDate(expired)
			},
			wantErrors:    []error{jwt.ErrTokenInvalidClaims, jwt.ErrTokenExpired},
			wantNotErrors: []error{compositePolicyErr},
		},
		{
			name: "valid times with failing custom claims check",
			configure: func(c *compositePolicyClaims) {
				c.ExpiresAt = jwt.NewNumericDate(now.Add(time.Hour))
				c.validateErr = compositePolicyErr
			},
			wantErrors:    []error{jwt.ErrTokenInvalidClaims, compositePolicyErr},
			wantNotErrors: []error{jwt.ErrTokenExpired},
		},
		{
			name: "not-yet-valid token with failing custom claims check",
			configure: func(c *compositePolicyClaims) {
				c.NotBefore = jwt.NewNumericDate(notYetValid)
				c.validateErr = compositePolicyErr
			},
			wantErrors:    []error{jwt.ErrTokenInvalidClaims, jwt.ErrTokenNotValidYet, compositePolicyErr},
			wantNotErrors: []error{jwt.ErrTokenExpired},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := &compositePolicyClaims{Foo: "bar"}
			tt.configure(claims)
			raw := signCompositeToken(t, claims, jwt.SigningMethodHS256, compositeSigningKey)

			parser := jwt.NewParser(jwt.WithTimeFunc(func() time.Time { return now }))
			token, err := parser.ParseWithClaims(raw, claims, func(*jwt.Token) (any, error) {
				return compositeSigningKey, nil
			})

			requireRejectedToken(t, token, err)

			for _, want := range tt.wantErrors {
				if !errors.Is(err, want) {
					t.Errorf("errors.Is(err, %v) = false, want true (err = %v)", want, err)
				}
			}
			for _, notWant := range tt.wantNotErrors {
				if errors.Is(err, notWant) {
					t.Errorf("errors.Is(err, %v) = true, want false (err = %v)", notWant, err)
				}
			}

			if claims.validateCalls != 1 {
				t.Errorf("custom Validate called %d times, want 1", claims.validateCalls)
			}
		})
	}

	// Simulate the unsafe caller pattern explicitly: an expired token is
	// treated as recoverable and the claims are kept. That branch must still
	// observe the failed custom check and an invalid token, so recovering from
	// the time error cannot mask an identity failure.
	t.Run("expired-token recovery path still sees the claims failure", func(t *testing.T) {
		claims := &compositePolicyClaims{
			Foo:         "bar",
			validateErr: compositePolicyErr,
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(expired),
			},
		}
		raw := signCompositeToken(t, claims, jwt.SigningMethodHS256, compositeSigningKey)

		parser := jwt.NewParser(jwt.WithTimeFunc(func() time.Time { return now }))
		token, err := parser.ParseWithClaims(raw, claims, func(*jwt.Token) (any, error) {
			return compositeSigningKey, nil
		})

		if !errors.Is(err, jwt.ErrTokenExpired) {
			t.Fatalf("expected a recoverable ErrTokenExpired, got: %v", err)
		}
		if !errors.Is(err, compositePolicyErr) {
			t.Errorf("recoverable time error hid the failed custom claims check (err = %v)", err)
		}
		if !errors.Is(err, jwt.ErrTokenInvalidClaims) {
			t.Errorf("errors.Is(err, ErrTokenInvalidClaims) = false, want true (err = %v)", err)
		}
		if token == nil || token.Valid {
			t.Fatal("token is acceptable after a failed identity check despite the time-error recovery path")
		}
	})
}

// TestParseWithClaims_MultipleClaimsErrorsDoNotLeaveValidToken uses a real RSA
// signature and a token whose every claim is wrong, plus a failing custom
// check, to verify that all claims failures are aggregated into one error and
// that neither early returns nor aggregation leave a token a caller could
// accept.
func TestParseWithClaims_MultipleClaimsErrorsDoNotLeaveValidToken(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()

	newClaims := func() *compositePolicyClaims {
		return &compositePolicyClaims{
			Foo:         "bar",
			validateErr: compositePolicyErr,
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    "token-issuer",
				Subject:   "token-subject",
				Audience:  jwt.ClaimStrings{"token-audience"},
				ExpiresAt: jwt.NewNumericDate(now.Add(-time.Hour)),
				NotBefore: jwt.NewNumericDate(now.Add(time.Hour)),
				IssuedAt:  jwt.NewNumericDate(now.Add(time.Hour)),
			},
		}
	}

	// The token is signed with the real RSA test key: the cryptographic part is
	// valid, only the claims and the application policy are not.
	raw := signCompositeToken(t, newClaims(), jwt.SigningMethodRS256, jwtTestRSAPrivateKey)

	keyfunc := func(*jwt.Token) (any, error) { return jwtTestDefaultKey, nil }

	parser := jwt.NewParser(
		jwt.WithTimeFunc(func() time.Time { return now }),
		jwt.WithExpirationRequired(),
		jwt.WithNotBeforeRequired(),
		jwt.WithIssuedAt(),
		jwt.WithAudience("expected-audience"),
		jwt.WithIssuer("expected-issuer"),
		jwt.WithSubject("expected-subject"),
	)

	claims := newClaims()
	token, err := parser.ParseWithClaims(raw, claims, keyfunc)

	requireRejectedToken(t, token, err)

	wantErrors := []error{
		jwt.ErrTokenInvalidClaims,
		jwt.ErrTokenExpired,
		jwt.ErrTokenNotValidYet,
		jwt.ErrTokenUsedBeforeIssued,
		jwt.ErrTokenInvalidAudience,
		jwt.ErrTokenInvalidIssuer,
		jwt.ErrTokenInvalidSubject,
		compositePolicyErr,
	}
	for _, want := range wantErrors {
		if !errors.Is(err, want) {
			t.Errorf("errors.Is(err, %v) = false, want true (err = %v)", want, err)
		}
		if got := countErrors(err, want); got != 1 {
			t.Errorf("error %v appears %d times, want exactly 1 (err = %v)", want, got, err)
		}
	}

	if claims.validateCalls != 1 {
		t.Errorf("custom Validate called %d times, want 1", claims.validateCalls)
	}
	if token != nil {
		if token.Raw != raw {
			t.Errorf("token.Raw = %q, want the parsed token string", token.Raw)
		}
		if len(token.Signature) == 0 {
			t.Error("token.Signature is empty after a failed parse, want it populated for diagnostics")
		}
		// The parser populates claims even when validation fails; this is
		// exactly why faithful rejection requires checking Valid.
		if claims.Issuer != "token-issuer" {
			t.Errorf("claims were not parsed despite the failure: Issuer = %q", claims.Issuer)
		}
	}

	// Sanity check: the very same token passes when claims validation is
	// explicitly disabled, proving the signature is genuine and every failure
	// above comes from claims or application policy.
	unchecked := newClaims()
	validToken, err := jwt.NewParser(jwt.WithoutClaimsValidation()).ParseWithClaims(raw, unchecked, keyfunc)
	if err != nil {
		t.Fatalf("signature should be valid, got error: %v", err)
	}
	if validToken == nil || !validToken.Valid {
		t.Fatal("expected a valid token when claims validation is disabled")
	}
	if unchecked.validateCalls != 0 {
		t.Errorf("custom Validate called %d times with claims validation disabled, want 0", unchecked.validateCalls)
	}

	t.Run("keyfunc failure short-circuits claims aggregation", func(t *testing.T) {
		claims := newClaims()
		token, err := parser.ParseWithClaims(raw, claims, func(*jwt.Token) (any, error) {
			return nil, compositeKeyfuncErr
		})

		requireRejectedToken(t, token, err)

		if !errors.Is(err, jwt.ErrTokenUnverifiable) || !errors.Is(err, compositeKeyfuncErr) {
			t.Errorf("want ErrTokenUnverifiable wrapping the keyfunc error, got: %v", err)
		}
		for _, claimsErr := range []error{
			jwt.ErrTokenInvalidClaims,
			jwt.ErrTokenExpired,
			jwt.ErrTokenNotValidYet,
			compositePolicyErr,
		} {
			if errors.Is(err, claimsErr) {
				t.Errorf("claims error %v reported although verification never ran", claimsErr)
			}
		}
		if claims.validateCalls != 0 {
			t.Errorf("custom Validate called %d times after a keyfunc failure, want 0", claims.validateCalls)
		}
	})

	t.Run("signature failure short-circuits claims aggregation", func(t *testing.T) {
		claims := newClaims()
		token, err := parser.ParseWithClaims(raw, claims, func(*jwt.Token) (any, error) {
			// Wrong key type for an RS256 token.
			return jwtTestEC256PublicKey, nil
		})

		requireRejectedToken(t, token, err)

		if !errors.Is(err, jwt.ErrTokenSignatureInvalid) || !errors.Is(err, jwt.ErrInvalidKeyType) {
			t.Errorf("want ErrTokenSignatureInvalid wrapping ErrInvalidKeyType, got: %v", err)
		}
		if errors.Is(err, jwt.ErrTokenInvalidClaims) {
			t.Errorf("claims validation ran although signature verification failed: %v", err)
		}
		if claims.validateCalls != 0 {
			t.Errorf("custom Validate called %d times after a signature failure, want 0", claims.validateCalls)
		}
	})
}
