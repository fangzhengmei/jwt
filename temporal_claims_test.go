package jwt_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// temporalClaimsKey is a static HMAC key used to sign the hand-crafted tokens
// in these tests. HMAC keeps the tests self-contained: no key fixtures are
// needed and a valid signature means every observed rejection comes from
// claims parsing/validation rather than signature verification.
var temporalClaimsKey = []byte("temporal-claims-test-key")

// temporalParsePath describes one of the four ways the same token string can
// be parsed: the two claims representations (MapClaims vs. RegisteredClaims)
// crossed with the two JSON decoding modes (default float64 vs.
// WithJSONNumber, which keeps the original digits as json.Number).
type temporalParsePath struct {
	name       string
	jsonNumber bool
	newClaims  func() jwt.Claims
}

var temporalParsePaths = []temporalParsePath{
	{
		name:       "MapClaims/default",
		jsonNumber: false,
		newClaims:  func() jwt.Claims { return jwt.MapClaims{} },
	},
	{
		name:       "MapClaims/JSONNumber",
		jsonNumber: true,
		newClaims:  func() jwt.Claims { return jwt.MapClaims{} },
	},
	{
		name:       "RegisteredClaims/default",
		jsonNumber: false,
		newClaims:  func() jwt.Claims { return &jwt.RegisteredClaims{} },
	},
	{
		name:       "RegisteredClaims/JSONNumber",
		jsonNumber: true,
		newClaims:  func() jwt.Claims { return &jwt.RegisteredClaims{} },
	},
}

// signRawClaims builds an HS256 token around an untouched claims payload. The
// payload is embedded verbatim, so it can contain encodings that the library's
// own marshaller could never produce: extreme exponents, duplicate claim keys
// or non-numeric temporal claims.
func signRawClaims(t *testing.T, rawClaims string) string {
	t.Helper()

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	claims := base64.RawURLEncoding.EncodeToString([]byte(rawClaims))
	signingInput := header + "." + claims

	sig, err := jwt.SigningMethodHS256.Sign(signingInput, temporalClaimsKey)
	if err != nil {
		t.Fatalf("signing token: %v", err)
	}

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// parseOnPath parses tokenString on the given path and returns the token and
// validation error.
func parseOnPath(t *testing.T, path temporalParsePath, tokenString string, opts ...jwt.ParserOption) (*jwt.Token, error) {
	t.Helper()

	if path.jsonNumber {
		opts = append(opts, jwt.WithJSONNumber())
	}

	return jwt.NewParser(opts...).ParseWithClaims(tokenString, path.newClaims(), func(*jwt.Token) (any, error) {
		return temporalClaimsKey, nil
	})
}

// hmacKeyFunc is the key func used for tokens signed through the public API.
func hmacKeyFunc(*jwt.Token) (any, error) { return temporalClaimsKey, nil }

// TestTemporalClaims_RawEncodingsAgreeAcrossParsePaths feeds the same hand
// crafted token through every parse path. The encoding of a temporal claim
// (extreme exponent, long fraction, duplicate keys, non-numeric value) must
// never turn an invalid token into a valid one, and payloads every path can
// decode must yield identical parsed times regardless of the intermediate
// float64/json.Number representation. Where paths reject at different stages,
// the precise reason is asserted per path.
func TestTemporalClaims_RawEncodingsAgreeAcrossParsePaths(t *testing.T) {
	tests := []struct {
		name      string
		rawClaims string
		// wantErr is the sentinel expected on a path. nil means accepted.
		wantErr error
		// pathWant overrides wantErr for the named parse path.
		pathWant map[string]error
		// numericTypeCheck asserts how a numeric exp is materialized in
		// MapClaims (float64 vs. json.Number). It only applies to payloads that
		// survive decoding on the MapClaims paths.
		numericTypeCheck bool
	}{
		{
			name:             "ordinary integer expiry in the future",
			rawClaims:        `{"exp":4102444800}`,
			wantErr:          nil,
			numericTypeCheck: true,
		},
		{
			name:             "fractional expiry in the future",
			rawClaims:        `{"exp":4102444800.123456789}`,
			wantErr:          nil,
			numericTypeCheck: true,
		},
		{
			// 1e308 fits in float64 but overflows int64 when converted to a
			// UNIX timestamp, landing at the minimum time. All paths must
			// reject it as expired rather than treat it as never-expiring.
			name:             "extreme positive exponent overflows into the past",
			rawClaims:        `{"exp":1e308}`,
			wantErr:          jwt.ErrTokenExpired,
			numericTypeCheck: true,
		},
		{
			// 1e309 exceeds float64. The default decoder cannot decode the
			// document at all. WithJSONNumber preserves the digits, but the
			// later Float64 conversion fails and is represented as zero, i.e.
			// the epoch. Either way the token must not be accepted.
			name:      "overflowing exponent is rejected on every path",
			rawClaims: `{"exp":1e309}`,
			wantErr:   jwt.ErrTokenMalformed,
			pathWant: map[string]error{
				"MapClaims/JSONNumber": jwt.ErrTokenExpired,
			},
		},
		{
			name:             "extreme negative exponent is the epoch and therefore expired",
			rawClaims:        `{"exp":1e-308}`,
			wantErr:          jwt.ErrTokenExpired,
			numericTypeCheck: true,
		},
		{
			name:             "fractional epoch is the epoch and therefore expired",
			rawClaims:        `{"exp":0.000000001}`,
			wantErr:          jwt.ErrTokenExpired,
			numericTypeCheck: true,
		},
		{
			name:             "integer beyond float64 precision rounds but stays in the future",
			rawClaims:        `{"exp":9007199254740993}`,
			wantErr:          nil,
			numericTypeCheck: true,
		},
		{
			name:             "duplicate exp keys, last value wins and is in the future",
			rawClaims:        `{"exp":1,"exp":4102444800}`,
			wantErr:          nil,
			numericTypeCheck: true,
		},
		{
			name:             "duplicate exp keys, last value wins and is expired",
			rawClaims:        `{"exp":4102444800,"exp":1}`,
			wantErr:          jwt.ErrTokenExpired,
			numericTypeCheck: true,
		},
		{
			// A quoted numeric value is a JSON string. MapClaims only accepts
			// JSON numbers, so it reports ErrInvalidType during validation.
			// NumericDate unmarshals through json.Number, which accepts a
			// quoted number, so the structured paths decode it successfully
			// and evaluate the represented time (here: still in the future).
			// This divergence is intentional library behavior worth pinning.
			name:      "quoted numeric exp is typed on MapClaims but decoded on RegisteredClaims",
			rawClaims: `{"exp":"4102444800"}`,
			wantErr:   nil,
			pathWant: map[string]error{
				"MapClaims/default":    jwt.ErrInvalidType,
				"MapClaims/JSONNumber": jwt.ErrInvalidType,
			},
		},
		{
			// Booleans are not numbers on either representation. MapClaims
			// keeps the value and rejects it during validation; NumericDate
			// cannot decode it and the token is malformed.
			name:      "non-numeric exp as boolean is rejected",
			rawClaims: `{"exp":true}`,
			wantErr:   jwt.ErrTokenMalformed,
			pathWant: map[string]error{
				"MapClaims/default":    jwt.ErrInvalidType,
				"MapClaims/JSONNumber": jwt.ErrInvalidType,
			},
		},
		{
			name:      "non-numeric exp as object is rejected",
			rawClaims: `{"exp":{"seconds":4102444800}}`,
			wantErr:   jwt.ErrTokenMalformed,
			pathWant: map[string]error{
				"MapClaims/default":    jwt.ErrInvalidType,
				"MapClaims/JSONNumber": jwt.ErrInvalidType,
			},
		},
		{
			// Map decoders apply last-wins, so the numeric second value is
			// used and the token is accepted. Structured decoding visits
			// members in order and fails on the first, non-numeric value.
			name:      "duplicate exp with non-numeric first value",
			rawClaims: `{"exp":"not-a-date","exp":4102444800}`,
			wantErr:   jwt.ErrTokenMalformed,
			pathWant: map[string]error{
				"MapClaims/default":    nil,
				"MapClaims/JSONNumber": nil,
			},
			numericTypeCheck: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenString := signRawClaims(t, tt.rawClaims)

			var referenceExp *jwt.NumericDate

			for _, path := range temporalParsePaths {
				t.Run(path.name, func(t *testing.T) {
					wantErr, ok := tt.pathWant[path.name]
					if !ok {
						wantErr = tt.wantErr
					}

					token, err := parseOnPath(t, path, tokenString)

					if wantErr == nil {
						if err != nil {
							t.Fatalf("expected valid token, got error %v", err)
						}
						if token == nil || !token.Valid {
							t.Fatalf("expected token.Valid to be true, got token=%v err=%v", token, err)
						}
					} else {
						if err == nil {
							t.Fatalf("expected error containing %v, got nil", wantErr)
						}
						if !errors.Is(err, wantErr) {
							t.Fatalf("expected error containing %v, got %v", wantErr, err)
						}
						if token != nil && token.Valid {
							t.Fatalf("rejected token must not be reported as valid")
						}
					}

					// On paths that reject during JSON decoding there is no
					// usable claims set to inspect.
					if errors.Is(err, jwt.ErrTokenMalformed) {
						return
					}

					exp, expErr := token.Claims.(jwt.Claims).GetExpirationTime()
					if expErr != nil {
						// MapClaims surfaces a non-numeric exp as an
						// ErrInvalidType accessor error rather than a parsed
						// time. That path has no instant to compare.
						if !errors.Is(expErr, jwt.ErrInvalidType) {
							t.Fatalf("GetExpirationTime returned unexpected error: %v", expErr)
						}
						return
					}
					if exp == nil {
						t.Fatalf("expected non-nil expiration time")
					}

					// Every surviving path must resolve the same instant even
					// though MapClaims and RegisteredClaims reach it through
					// different intermediate representations.
					if referenceExp == nil {
						referenceExp = exp
					} else if !exp.Time.Equal(referenceExp.Time) {
						t.Errorf("expiration time %v does not match reference %v", exp.Time, referenceExp.Time)
					}

					// For MapClaims payloads that decode to a JSON number, the
					// default mode must materialize float64 while
					// WithJSONNumber must preserve the original json.Number.
					if !tt.numericTypeCheck {
						return
					}
					mapClaims, isMap := token.Claims.(jwt.MapClaims)
					if !isMap {
						return
					}
					rawValue, ok := mapClaims["exp"]
					if !ok {
						t.Fatalf("exp claim missing from decoded MapClaims")
					}
					switch rawValue.(type) {
					case float64:
						if path.jsonNumber {
							t.Errorf("expected json.Number in WithJSONNumber mode, got float64")
						}
					case json.Number:
						if !path.jsonNumber {
							t.Errorf("unexpected json.Number in default mode, wanted float64")
						}
					default:
						t.Errorf("unexpected decoded exp type %T", rawValue)
					}
				})
			}
		})
	}
}

// TestTemporalClaims_FixedClockValidation exercises exp, nbf and iat against a
// fixed clock, crossing leeway windows and the required-claim options. Every
// scenario is parsed on all four paths and must produce the same verdict with
// the same precise rejection reason.
func TestTemporalClaims_FixedClockValidation(t *testing.T) {
	// All reference times are whole seconds so the default second precision of
	// NumericDate does not perturb the boundary checks.
	now := time.Unix(1700000000, 0)
	fixedClock := func() time.Time { return now }

	tests := []struct {
		name    string
		claims  jwt.RegisteredClaims
		opts    []jwt.ParserOption
		wantErr error // nil means the token must be accepted
	}{
		{
			name: "valid token with iat, nbf and exp around the fixed clock",
			claims: jwt.RegisteredClaims{
				IssuedAt:  jwt.NewNumericDate(now.Add(-60 * time.Second)),
				NotBefore: jwt.NewNumericDate(now.Add(-30 * time.Second)),
				ExpiresAt: jwt.NewNumericDate(now.Add(30 * time.Second)),
			},
			opts:    []jwt.ParserOption{jwt.WithIssuedAt()},
			wantErr: nil,
		},
		{
			name: "expired token",
			claims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(now.Add(-10 * time.Second)),
			},
			wantErr: jwt.ErrTokenExpired,
		},
		{
			name: "not yet valid token",
			claims: jwt.RegisteredClaims{
				NotBefore: jwt.NewNumericDate(now.Add(10 * time.Second)),
			},
			wantErr: jwt.ErrTokenNotValidYet,
		},
		{
			name: "token issued in the future",
			claims: jwt.RegisteredClaims{
				IssuedAt: jwt.NewNumericDate(now.Add(10 * time.Second)),
			},
			opts:    []jwt.ParserOption{jwt.WithIssuedAt()},
			wantErr: jwt.ErrTokenUsedBeforeIssued,
		},
		{
			name: "future iat is ignored unless verification is enabled",
			claims: jwt.RegisteredClaims{
				IssuedAt: jwt.NewNumericDate(now.Add(10 * time.Second)),
			},
			wantErr: nil,
		},
		{
			name: "expired token rescued by leeway",
			claims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(now.Add(-10 * time.Second)),
			},
			opts:    []jwt.ParserOption{jwt.WithLeeway(15 * time.Second)},
			wantErr: nil,
		},
		{
			name: "expired token still rejected at the edge of the leeway window",
			claims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(now.Add(-10 * time.Second)),
			},
			opts:    []jwt.ParserOption{jwt.WithLeeway(10 * time.Second)},
			wantErr: jwt.ErrTokenExpired,
		},
		{
			name: "not yet valid token rescued by leeway",
			claims: jwt.RegisteredClaims{
				NotBefore: jwt.NewNumericDate(now.Add(10 * time.Second)),
			},
			opts:    []jwt.ParserOption{jwt.WithLeeway(15 * time.Second)},
			wantErr: nil,
		},
		{
			name: "future iat rescued by leeway",
			claims: jwt.RegisteredClaims{
				IssuedAt: jwt.NewNumericDate(now.Add(10 * time.Second)),
			},
			opts:    []jwt.ParserOption{jwt.WithIssuedAt(), jwt.WithLeeway(15 * time.Second)},
			wantErr: nil,
		},
		{
			name: "required exp is missing",
			claims: jwt.RegisteredClaims{
				NotBefore: jwt.NewNumericDate(now.Add(-10 * time.Second)),
			},
			opts:    []jwt.ParserOption{jwt.WithExpirationRequired()},
			wantErr: jwt.ErrTokenRequiredClaimMissing,
		},
		{
			name: "required nbf is missing",
			claims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(now.Add(10 * time.Second)),
			},
			opts:    []jwt.ParserOption{jwt.WithNotBeforeRequired()},
			wantErr: jwt.ErrTokenRequiredClaimMissing,
		},
		{
			name: "expired and not yet valid at the same time",
			claims: jwt.RegisteredClaims{
				NotBefore: jwt.NewNumericDate(now.Add(10 * time.Second)),
				ExpiresAt: jwt.NewNumericDate(now.Add(-10 * time.Second)),
			},
			wantErr: jwt.ErrTokenExpired,
		},
		{
			name: "expiry exactly at the clock is already expired",
			claims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(now),
			},
			wantErr: jwt.ErrTokenExpired,
		},
		{
			name: "not-before exactly at the clock is accepted",
			claims: jwt.RegisteredClaims{
				NotBefore: jwt.NewNumericDate(now),
				ExpiresAt: jwt.NewNumericDate(now.Add(10 * time.Second)),
			},
			wantErr: nil,
		},
		{
			name: "issued-at exactly at the clock is accepted",
			claims: jwt.RegisteredClaims{
				IssuedAt:  jwt.NewNumericDate(now),
				ExpiresAt: jwt.NewNumericDate(now.Add(10 * time.Second)),
			},
			opts:    []jwt.ParserOption{jwt.WithIssuedAt()},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenString, err := jwt.NewWithClaims(jwt.SigningMethodHS256, tt.claims).SignedString(temporalClaimsKey)
			if err != nil {
				t.Fatalf("signing token: %v", err)
			}

			opts := append(tt.opts, jwt.WithTimeFunc(fixedClock))

			for _, path := range temporalParsePaths {
				t.Run(path.name, func(t *testing.T) {
					token, parseErr := parseOnPath(t, path, tokenString, opts...)

					if tt.wantErr == nil {
						if parseErr != nil {
							t.Fatalf("expected valid token, got error %v", parseErr)
						}
						if token == nil || !token.Valid {
							t.Fatalf("expected token.Valid to be true, got token=%v err=%v", token, parseErr)
						}
						return
					}

					if parseErr == nil {
						t.Fatalf("expected error containing %v, got nil", tt.wantErr)
					}
					if !errors.Is(parseErr, tt.wantErr) {
						t.Fatalf("expected error containing %v, got %v", tt.wantErr, parseErr)
					}
					if token != nil && token.Valid {
						t.Fatalf("rejected token must not be reported as valid")
					}

					// Every temporal rejection must surface through the
					// invalid-claims wrapper rather than a malformed token,
					// since these payloads are well-formed.
					if !errors.Is(parseErr, jwt.ErrTokenInvalidClaims) {
						t.Fatalf("expected ErrTokenInvalidClaims wrapper around %v, got %v", tt.wantErr, parseErr)
					}

					// When both exp and nbf fail, the joined error must retain
					// both reasons instead of dropping one.
					if tt.name == "expired and not yet valid at the same time" {
						if !errors.Is(parseErr, jwt.ErrTokenNotValidYet) {
							t.Fatalf("expected joined error to also contain ErrTokenNotValidYet, got %v", parseErr)
						}
					}
				})
			}
		})
	}
}

// TestTemporalClaims_NormalClaimsAcceptedAndRejectionReasons pins down the
// accept path for well-formed temporal claims and asserts the exact rejection
// reason of each parsing path, including the split between validation-time
// type errors (MapClaims) and decode-time malformed-token errors
// (RegisteredClaims).
func TestTemporalClaims_NormalClaimsAcceptedAndRejectionReasons(t *testing.T) {
	now := time.Unix(1700000000, 0)
	fixedClock := func() time.Time { return now }

	normalClaims := jwt.RegisteredClaims{
		IssuedAt:  jwt.NewNumericDate(now.Add(-time.Minute)),
		NotBefore: jwt.NewNumericDate(now.Add(-30 * time.Second)),
		ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute)),
	}
	tokenString, err := jwt.NewWithClaims(jwt.SigningMethodHS256, normalClaims).SignedString(temporalClaimsKey)
	if err != nil {
		t.Fatalf("signing token: %v", err)
	}

	t.Run("normal temporal claims accepted on every path", func(t *testing.T) {
		for _, path := range temporalParsePaths {
			t.Run(path.name, func(t *testing.T) {
				token, parseErr := jwt.NewParser(jwt.WithTimeFunc(fixedClock)).
					ParseWithClaims(tokenString, path.newClaims(), hmacKeyFunc)
				if parseErr != nil {
					t.Fatalf("expected valid token, got %v", parseErr)
				}
				if !token.Valid {
					t.Fatalf("expected token.Valid to be true")
				}

				exp, err := token.Claims.(jwt.Claims).GetExpirationTime()
				if err != nil || exp == nil || !exp.Time.Equal(normalClaims.ExpiresAt.Time) {
					t.Fatalf("exp mismatch: exp=%v err=%v", exp, err)
				}
				nbf, err := token.Claims.(jwt.Claims).GetNotBefore()
				if err != nil || nbf == nil || !nbf.Time.Equal(normalClaims.NotBefore.Time) {
					t.Fatalf("nbf mismatch: nbf=%v err=%v", nbf, err)
				}
				iat, err := token.Claims.(jwt.Claims).GetIssuedAt()
				if err != nil || iat == nil || !iat.Time.Equal(normalClaims.IssuedAt.Time) {
					t.Fatalf("iat mismatch: iat=%v err=%v", iat, err)
				}
			})
		}
	})

	// A boolean exp is not a JSON number on either representation. MapClaims
	// keeps it and rejects it during claims validation; RegisteredClaims cannot
	// decode it into a NumericDate, so the token is malformed. Both decoding
	// modes behave identically within a claims representation.
	booleanExpToken := signRawClaims(t, `{"exp":true}`)

	t.Run("MapClaims reports invalid type during validation", func(t *testing.T) {
		for _, useJSONNumber := range []bool{false, true} {
			name := "default"
			opts := []jwt.ParserOption{jwt.WithTimeFunc(fixedClock)}
			if useJSONNumber {
				name = "JSONNumber"
				opts = append(opts, jwt.WithJSONNumber())
			}

			t.Run(name, func(t *testing.T) {
				token, parseErr := jwt.NewParser(opts...).
					ParseWithClaims(booleanExpToken, jwt.MapClaims{}, hmacKeyFunc)
				if parseErr == nil {
					t.Fatalf("expected rejection, got valid token")
				}
				if !errors.Is(parseErr, jwt.ErrInvalidType) {
					t.Fatalf("expected ErrInvalidType, got %v", parseErr)
				}
				if !errors.Is(parseErr, jwt.ErrTokenInvalidClaims) {
					t.Fatalf("expected ErrTokenInvalidClaims wrapper, got %v", parseErr)
				}
				if errors.Is(parseErr, jwt.ErrTokenMalformed) {
					t.Fatalf("MapClaims must not report a decodable payload as malformed")
				}
				if token != nil && token.Valid {
					t.Fatalf("rejected token must not be reported as valid")
				}
			})
		}
	})

	t.Run("RegisteredClaims reports malformed token during decoding", func(t *testing.T) {
		for _, useJSONNumber := range []bool{false, true} {
			name := "default"
			opts := []jwt.ParserOption{jwt.WithTimeFunc(fixedClock)}
			if useJSONNumber {
				name = "JSONNumber"
				opts = append(opts, jwt.WithJSONNumber())
			}

			t.Run(name, func(t *testing.T) {
				token, parseErr := jwt.NewParser(opts...).
					ParseWithClaims(booleanExpToken, &jwt.RegisteredClaims{}, hmacKeyFunc)
				if parseErr == nil {
					t.Fatalf("expected rejection, got valid token")
				}
				if !errors.Is(parseErr, jwt.ErrTokenMalformed) {
					t.Fatalf("expected ErrTokenMalformed, got %v", parseErr)
				}
				if errors.Is(parseErr, jwt.ErrInvalidType) {
					t.Fatalf("decode failure must surface as malformed, not ErrInvalidType")
				}
				if token != nil && token.Valid {
					t.Fatalf("rejected token must not be reported as valid")
				}
			})
		}
	})

	// A quoted numeric value splits the two representations: MapClaims sees a
	// JSON string and rejects with ErrInvalidType, whereas NumericDate decodes
	// through json.Number, which accepts the quoted digits and evaluates the
	// represented time normally. Pinning this down makes the representation
	// difference explicit rather than accidental.
	quotedNumberToken := signRawClaims(t, `{"exp":"4102444800"}`)

	t.Run("quoted numeric exp splits MapClaims and RegisteredClaims", func(t *testing.T) {
		t.Run("MapClaims rejects as invalid type", func(t *testing.T) {
			token, parseErr := jwt.NewParser(jwt.WithTimeFunc(fixedClock)).
				ParseWithClaims(quotedNumberToken, jwt.MapClaims{}, hmacKeyFunc)
			if parseErr == nil {
				t.Fatalf("expected rejection, got valid token")
			}
			if !errors.Is(parseErr, jwt.ErrInvalidType) {
				t.Fatalf("expected ErrInvalidType, got %v", parseErr)
			}
			if token != nil && token.Valid {
				t.Fatalf("rejected token must not be reported as valid")
			}
		})

		t.Run("RegisteredClaims decodes and evaluates the time", func(t *testing.T) {
			token, parseErr := jwt.NewParser(jwt.WithTimeFunc(fixedClock)).
				ParseWithClaims(quotedNumberToken, &jwt.RegisteredClaims{}, hmacKeyFunc)
			if parseErr != nil {
				t.Fatalf("expected quoted number to decode, got %v", parseErr)
			}
			if !token.Valid {
				t.Fatalf("expected token.Valid to be true")
			}
			exp, err := token.Claims.(*jwt.RegisteredClaims).GetExpirationTime()
			if err != nil || exp == nil {
				t.Fatalf("expected decoded expiration time, got exp=%v err=%v", exp, err)
			}
			if got := exp.Unix(); got != 4102444800 {
				t.Fatalf("expected exp unix 4102444800, got %d", got)
			}
		})
	})
}
