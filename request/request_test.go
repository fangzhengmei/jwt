package request

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/golang-jwt/jwt/v5/test"
)

var requestTestData = []struct {
	name      string
	claims    jwt.MapClaims
	extractor Extractor
	headers   map[string]string
	query     url.Values
	valid     bool
}{
	{
		"authorization bearer token",
		jwt.MapClaims{"foo": "bar"},
		AuthorizationHeaderExtractor,
		map[string]string{"Authorization": "Bearer %v"},
		url.Values{},
		true,
	},
	{
		"oauth bearer token - header",
		jwt.MapClaims{"foo": "bar"},
		OAuth2Extractor,
		map[string]string{"Authorization": "Bearer %v"},
		url.Values{},
		true,
	},
	{
		"oauth bearer token - url",
		jwt.MapClaims{"foo": "bar"},
		OAuth2Extractor,
		map[string]string{},
		url.Values{"access_token": {"%v"}},
		true,
	},
	{
		"url token",
		jwt.MapClaims{"foo": "bar"},
		ArgumentExtractor{"token"},
		map[string]string{},
		url.Values{"token": {"%v"}},
		true,
	},
}

func TestParseRequest(t *testing.T) {
	// load keys from disk
	privateKey := test.LoadRSAPrivateKeyFromDisk("../test/sample_key")
	publicKey := test.LoadRSAPublicKeyFromDisk("../test/sample_key.pub")
	keyfunc := func(*jwt.Token) (any, error) {
		return publicKey, nil
	}

	// Bearer token request
	for _, data := range requestTestData {
		// Make token from claims
		tokenString := test.MakeSampleToken(data.claims, jwt.SigningMethodRS256, privateKey)

		// Make query string
		for k, vv := range data.query {
			for i, v := range vv {
				if strings.Contains(v, "%v") {
					data.query[k][i] = fmt.Sprintf(v, tokenString)
				}
			}
		}

		// Make request from test struct
		r, _ := http.NewRequest("GET", fmt.Sprintf("/?%v", data.query.Encode()), nil)
		for k, v := range data.headers {
			if strings.Contains(v, "%v") {
				r.Header.Set(k, fmt.Sprintf(v, tokenString))
			} else {
				r.Header.Set(k, tokenString)
			}
		}
		token, err := ParseFromRequestWithClaims(r, data.extractor, jwt.MapClaims{}, keyfunc)

		if token == nil {
			t.Errorf("[%v] Token was not found: %v", data.name, err)
			continue
		}
		if !reflect.DeepEqual(data.claims, token.Claims) {
			t.Errorf("[%v] Claims mismatch. Expecting: %v  Got: %v", data.name, data.claims, token.Claims)
		}
		if data.valid && err != nil {
			t.Errorf("[%v] Error while verifying token: %v", data.name, err)
		}
		if !data.valid && err == nil {
			t.Errorf("[%v] Invalid token passed validation", data.name)
		}
	}
}

// TestParseRequestStrict covers the strict extraction mode end to end: a
// conflicting or malformed request must be rejected before the key function
// runs, while identical tokens, a single token source and a request without a
// token keep their documented outcomes.
func TestParseRequestStrict(t *testing.T) {
	privateKey := test.LoadRSAPrivateKeyFromDisk("../test/sample_key")
	publicKey := test.LoadRSAPublicKeyFromDisk("../test/sample_key.pub")

	tokenA := test.MakeSampleToken(jwt.MapClaims{"sub": "alice"}, jwt.SigningMethodRS256, privateKey)
	tokenB := test.MakeSampleToken(jwt.MapClaims{"sub": "mallory"}, jwt.SigningMethodRS256, privateKey)

	tests := []struct {
		name        string
		extractor   Extractor
		options     []ParseFromRequestOption
		headers     []string
		query       url.Values
		form        url.Values
		wantSubject string
		wantErr     error
		wantNoKey   bool
	}{
		{
			name:        "strict single bearer header",
			extractor:   OAuth2Extractor,
			options:     []ParseFromRequestOption{WithStrictExtraction()},
			headers:     []string{"Bearer " + tokenA},
			wantSubject: "alice",
		},
		{
			name:        "strict single query parameter",
			extractor:   OAuth2Extractor,
			options:     []ParseFromRequestOption{WithStrictExtraction()},
			query:       url.Values{"access_token": {tokenA}},
			wantSubject: "alice",
		},
		{
			name:        "strict identical header and query",
			extractor:   OAuth2Extractor,
			options:     []ParseFromRequestOption{WithStrictExtraction()},
			headers:     []string{"Bearer " + tokenA},
			query:       url.Values{"access_token": {tokenA}},
			wantSubject: "alice",
		},
		{
			name:      "strict conflicting header and query",
			extractor: OAuth2Extractor,
			options:   []ParseFromRequestOption{WithStrictExtraction()},
			headers:   []string{"Bearer " + tokenA},
			query:     url.Values{"access_token": {tokenB}},
			wantErr:   ErrConflictingTokens,
			wantNoKey: true,
		},
		{
			name:      "strict conflicting repeated header",
			extractor: OAuth2Extractor,
			options:   []ParseFromRequestOption{WithStrictExtraction()},
			headers:   []string{"Bearer " + tokenA, "Bearer " + tokenB},
			wantErr:   ErrConflictingTokens,
			wantNoKey: true,
		},
		{
			name:        "strict identical repeated header",
			extractor:   OAuth2Extractor,
			options:     []ParseFromRequestOption{WithStrictExtraction()},
			headers:     []string{"Bearer " + tokenA, "Bearer " + tokenA},
			wantSubject: "alice",
		},
		{
			name:      "strict malformed bearer",
			extractor: OAuth2Extractor,
			options:   []ParseFromRequestOption{WithStrictExtraction()},
			headers:   []string{"Basic " + tokenA},
			wantErr:   ErrMalformedBearer,
			wantNoKey: true,
		},
		{
			name:      "strict no token",
			extractor: OAuth2Extractor,
			options:   []ParseFromRequestOption{WithStrictExtraction()},
			wantErr:   ErrNoTokenInRequest,
			wantNoKey: true,
		},
		{
			name:        "strict extractor with default parse options",
			extractor:   StrictOAuth2Extractor,
			headers:     []string{"Bearer " + tokenA},
			wantSubject: "alice",
		},
		{
			name:      "strict extractor conflicting form and query",
			extractor: StrictOAuth2Extractor,
			query:     url.Values{"access_token": {tokenA}},
			form:      url.Values{"access_token": {tokenB}},
			wantErr:   ErrConflictingTokens,
			wantNoKey: true,
		},
		{
			name:        "default precedence keeps header token",
			extractor:   OAuth2Extractor,
			headers:     []string{"Bearer " + tokenA},
			query:       url.Values{"access_token": {tokenB}},
			wantSubject: "alice",
		},
		{
			name:        "default precedence keeps header token with distinct form",
			extractor:   OAuth2Extractor,
			headers:     []string{"Bearer " + tokenA},
			form:        url.Values{"access_token": {tokenB}},
			wantSubject: "alice",
		},
		{
			name:      "strict malformed token does not reach keyfunc",
			extractor: OAuth2Extractor,
			options:   []ParseFromRequestOption{WithStrictExtraction()},
			headers:   []string{"Bearer not-a-jwt"},
			wantErr:   jwt.ErrTokenMalformed,
			wantNoKey: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyfuncCalled := false
			keyfunc := func(*jwt.Token) (any, error) {
				keyfuncCalled = true
				return publicKey, nil
			}

			r := makeStrictRequest("POST", nil, tt.query, tt.form)
			for _, value := range tt.headers {
				r.Header.Add("Authorization", value)
			}

			token, err := ParseFromRequest(r, tt.extractor, keyfunc, tt.options...)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("expected error %v, got %v", tt.wantErr, err)
				}
				if token != nil {
					t.Errorf("expected no token, got %v", token)
				}
				if tt.wantNoKey && keyfuncCalled {
					t.Errorf("keyfunc must not be called when extraction fails")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !token.Valid {
				t.Errorf("token.Valid = false, want true")
			}
			if got := token.Claims.(jwt.MapClaims)["sub"]; got != tt.wantSubject {
				t.Errorf("sub = %v, want %v", got, tt.wantSubject)
			}
		})
	}
}
