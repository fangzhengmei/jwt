package request

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

var extractorTestTokenA = "A"
var extractorTestTokenB = "B"

var extractorTestData = []struct {
	name      string
	extractor Extractor
	headers   map[string]string
	query     url.Values
	token     string
	err       error
}{
	{
		name:      "simple header",
		extractor: HeaderExtractor{"Foo"},
		headers:   map[string]string{"Foo": extractorTestTokenA},
		query:     nil,
		token:     extractorTestTokenA,
		err:       nil,
	},
	{
		name:      "simple argument",
		extractor: ArgumentExtractor{"token"},
		headers:   map[string]string{},
		query:     url.Values{"token": {extractorTestTokenA}},
		token:     extractorTestTokenA,
		err:       nil,
	},
	{
		name: "multiple extractors",
		extractor: MultiExtractor{
			HeaderExtractor{"Foo"},
			ArgumentExtractor{"token"},
		},
		headers: map[string]string{"Foo": extractorTestTokenA},
		query:   url.Values{"token": {extractorTestTokenB}},
		token:   extractorTestTokenA,
		err:     nil,
	},
	{
		name:      "simple miss",
		extractor: HeaderExtractor{"This-Header-Is-Not-Set"},
		headers:   map[string]string{"Foo": extractorTestTokenA},
		query:     nil,
		token:     "",
		err:       ErrNoTokenInRequest,
	},
	{
		name:      "filter",
		extractor: AuthorizationHeaderExtractor,
		headers:   map[string]string{"Authorization": "Bearer " + extractorTestTokenA},
		query:     nil,
		token:     extractorTestTokenA,
		err:       nil,
	},
}

func TestExtractor(t *testing.T) {
	// Bearer token request
	for _, data := range extractorTestData {
		// Make request from test struct
		r := makeExampleRequest("GET", "/", data.headers, data.query)

		// Test extractor
		token, err := data.extractor.ExtractToken(r)
		if token != data.token {
			t.Errorf("[%v] Expected token '%v'.  Got '%v'", data.name, data.token, token)
			continue
		}
		if err != data.err {
			t.Errorf("[%v] Expected error '%v'.  Got '%v'", data.name, data.err, err)
			continue
		}
	}
}

func makeExampleRequest(method, path string, headers map[string]string, urlArgs url.Values) *http.Request {
	r, _ := http.NewRequest(method, fmt.Sprintf("%v?%v", path, urlArgs.Encode()), nil)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func TestBearerExtractor(t *testing.T) {
	request := makeExampleRequest("POST", "https://example.com/", map[string]string{"Authorization": "Bearer ToKen"}, nil)
	token, err := BearerExtractor{}.ExtractToken(request)
	if err != nil || token != "ToKen" {
		t.Errorf("ExtractToken did not return token, returned: %v, %v", token, err)
	}

	request = makeExampleRequest("POST", "https://example.com/", map[string]string{"Authorization": "Bearo ToKen"}, nil)
	token, err = BearerExtractor{}.ExtractToken(request)
	if err == nil || token != "" {
		t.Errorf("ExtractToken did not return error, returned: %v, %v", token, err)
	}

	request = makeExampleRequest("POST", "https://example.com/", map[string]string{"Authorization": "BeArEr HeLO"}, nil)
	token, err = BearerExtractor{}.ExtractToken(request)
	if err != nil || token != "HeLO" {
		t.Errorf("ExtractToken did not return token, returned: %v, %v", token, err)
	}
}

// makeStrictRequest builds a request from raw header values (which may repeat
// a header) and query values.
func makeStrictRequest(method string, headers http.Header, query url.Values, form url.Values) *http.Request {
	target := "/"
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	var body string
	if len(form) > 0 {
		body = form.Encode()
	}
	r, _ := http.NewRequest(method, target, strings.NewReader(body))
	if len(form) > 0 {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, values := range headers {
		for _, v := range values {
			r.Header.Add(k, v)
		}
	}
	return r
}

func TestStrictExtractor(t *testing.T) {
	header := func(values ...string) http.Header {
		h := http.Header{}
		for _, v := range values {
			h.Add("Authorization", v)
		}
		return h
	}
	tests := []struct {
		name      string
		extractor Extractor
		req       *http.Request
		token     string
		err       error
	}{
		{
			name:      "no token",
			extractor: StrictExtractor{},
			req:       makeStrictRequest("GET", http.Header{}, nil, nil),
			err:       ErrNoTokenInRequest,
		},
		{
			name:      "single bearer header",
			extractor: StrictExtractor{},
			req:       makeStrictRequest("GET", header("Bearer "+extractorTestTokenA), nil, nil),
			token:     extractorTestTokenA,
		},
		{
			name:      "single query parameter",
			extractor: StrictExtractor{},
			req:       makeStrictRequest("GET", http.Header{}, url.Values{"access_token": {extractorTestTokenA}}, nil),
			token:     extractorTestTokenA,
		},
		{
			name:      "same token in header and query",
			extractor: StrictExtractor{},
			req: makeStrictRequest("GET", header("Bearer "+extractorTestTokenA),
				url.Values{"access_token": {extractorTestTokenA}}, nil),
			token: extractorTestTokenA,
		},
		{
			name:      "different token in header and query",
			extractor: StrictExtractor{},
			req: makeStrictRequest("GET", header("Bearer "+extractorTestTokenA),
				url.Values{"access_token": {extractorTestTokenB}}, nil),
			err: ErrConflictingTokens,
		},
		{
			name:      "same token in form and query",
			extractor: StrictExtractor{},
			req: makeStrictRequest("POST", http.Header{},
				url.Values{"access_token": {extractorTestTokenA}},
				url.Values{"access_token": {extractorTestTokenA}}),
			token: extractorTestTokenA,
		},
		{
			name:      "different token in form and query",
			extractor: StrictExtractor{},
			req: makeStrictRequest("POST", http.Header{},
				url.Values{"access_token": {extractorTestTokenA}},
				url.Values{"access_token": {extractorTestTokenB}}),
			err: ErrConflictingTokens,
		},
		{
			name:      "repeated identical header",
			extractor: StrictExtractor{},
			req:       makeStrictRequest("GET", header("Bearer "+extractorTestTokenA, "Bearer "+extractorTestTokenA), nil, nil),
			token:     extractorTestTokenA,
		},
		{
			name:      "repeated header with different tokens",
			extractor: StrictExtractor{},
			req:       makeStrictRequest("GET", header("Bearer "+extractorTestTokenA, "Bearer "+extractorTestTokenB), nil, nil),
			err:       ErrConflictingTokens,
		},
		{
			name:      "repeated query parameter with different tokens",
			extractor: StrictExtractor{},
			req: makeStrictRequest("GET", http.Header{},
				url.Values{"access_token": {extractorTestTokenA, extractorTestTokenB}}, nil),
			err: ErrConflictingTokens,
		},
		{
			name:      "repeated query parameter with identical tokens",
			extractor: StrictExtractor{},
			req: makeStrictRequest("GET", http.Header{},
				url.Values{"access_token": {extractorTestTokenA, extractorTestTokenA}}, nil),
			token: extractorTestTokenA,
		},
		{
			name:      "malformed bearer",
			extractor: StrictExtractor{},
			req:       makeStrictRequest("GET", header("Basic "+extractorTestTokenA), nil, nil),
			err:       ErrMalformedBearer,
		},
		{
			name:      "empty bearer",
			extractor: StrictExtractor{},
			req:       makeStrictRequest("GET", header("Bearer "), nil, nil),
			err:       ErrMalformedBearer,
		},
		{
			name:      "malformed bearer blocks otherwise valid token",
			extractor: StrictExtractor{},
			req: makeStrictRequest("GET", header("Bearer "+extractorTestTokenA, "Basic "+extractorTestTokenB),
				url.Values{"access_token": {extractorTestTokenA}}, nil),
			err: ErrMalformedBearer,
		},
		{
			name:      "credentials folded into one header field",
			extractor: StrictExtractor{},
			req:       makeStrictRequest("GET", header("Bearer "+extractorTestTokenA+", Bearer "+extractorTestTokenB), nil, nil),
			err:       ErrMalformedBearer,
		},
		{
			name:      "bearer scheme with no token",
			extractor: StrictExtractor{},
			req:       makeStrictRequest("GET", header("Bearer"), nil, nil),
			err:       ErrMalformedBearer,
		},
		{
			name:      "explicit headers and arguments",
			extractor: StrictExtractor{Headers: []string{"X-Token"}, Arguments: []string{"token"}},
			req: makeStrictRequest("GET", http.Header{"X-Token": {extractorTestTokenA}},
				url.Values{"token": {extractorTestTokenA}}, nil),
			token: extractorTestTokenA,
		},
		{
			name:      "explicit headers ignore Authorization",
			extractor: StrictExtractor{Headers: []string{"X-Token"}, Arguments: []string{}},
			req: makeStrictRequest("GET", http.Header{
				"X-Token":       {extractorTestTokenA},
				"Authorization": {"Bearer " + extractorTestTokenB},
			}, nil, nil),
			token: extractorTestTokenA,
		},
		{
			name:      "explicit headers with nil arguments inspect only headers",
			extractor: StrictExtractor{Headers: []string{"X-Token"}},
			req: makeStrictRequest("GET", http.Header{"X-Token": {extractorTestTokenA}},
				url.Values{"access_token": {extractorTestTokenB}}, nil),
			token: extractorTestTokenA,
		},
		{
			name:      "non-Bearer header is used verbatim",
			extractor: StrictExtractor{Headers: []string{"X-Token"}},
			req:       makeStrictRequest("GET", http.Header{"X-Token": {extractorTestTokenA}}, nil, nil),
			token:     extractorTestTokenA,
		},
		{
			name:      "extractors composition detects conflict",
			extractor: StrictExtractor{Extractors: []Extractor{AuthorizationHeaderExtractor, ArgumentExtractor{"access_token"}}},
			req: makeStrictRequest("GET", header("Bearer "+extractorTestTokenA),
				url.Values{"access_token": {extractorTestTokenB}}, nil),
			err: ErrConflictingTokens,
		},
		{
			name:      "extractors composition accepts identical token",
			extractor: StrictExtractor{Extractors: []Extractor{AuthorizationHeaderExtractor, ArgumentExtractor{"access_token"}}},
			req: makeStrictRequest("GET", header("Bearer "+extractorTestTokenA),
				url.Values{"access_token": {extractorTestTokenA}}, nil),
			token: extractorTestTokenA,
		},
		{
			name:      "multi extractor conflict is visible",
			extractor: StrictExtractor{Extractors: []Extractor{MultiExtractor{HeaderExtractor{"Foo"}, ArgumentExtractor{"token"}}}},
			req: makeStrictRequest("GET", http.Header{"Foo": {extractorTestTokenA}},
				url.Values{"token": {extractorTestTokenB}}, nil),
			err: ErrConflictingTokens,
		},
		{
			name: "strict multi extractor accepts identical token",
			extractor: StrictMultiExtractor{
				HeaderExtractor{"Foo"},
				ArgumentExtractor{"token"},
			},
			req: makeStrictRequest("GET", http.Header{"Foo": {extractorTestTokenA}},
				url.Values{"token": {extractorTestTokenA}}, nil),
			token: extractorTestTokenA,
		},
		{
			name: "strict multi extractor detects conflict",
			extractor: StrictMultiExtractor{
				HeaderExtractor{"Foo"},
				ArgumentExtractor{"token"},
			},
			req: makeStrictRequest("GET", http.Header{"Foo": {extractorTestTokenA}},
				url.Values{"token": {extractorTestTokenB}}, nil),
			err: ErrConflictingTokens,
		},
		{
			name:      "strict multi extractor with no token",
			extractor: StrictMultiExtractor{HeaderExtractor{"Foo"}, ArgumentExtractor{"token"}},
			req:       makeStrictRequest("GET", http.Header{}, nil, nil),
			err:       ErrNoTokenInRequest,
		},
		{
			name:      "strict OAuth2 extractor",
			extractor: StrictOAuth2Extractor,
			req: makeStrictRequest("GET", header("Bearer "+extractorTestTokenA),
				url.Values{"access_token": {extractorTestTokenA}}, nil),
			token: extractorTestTokenA,
		},
		{
			name:      "bearer extractor sees repeated headers",
			extractor: StrictExtractor{Extractors: []Extractor{BearerExtractor{}}},
			req:       makeStrictRequest("GET", header("Bearer "+extractorTestTokenA, "Bearer "+extractorTestTokenB), nil, nil),
			err:       ErrConflictingTokens,
		},
		{
			name:      "bearer extractor rejects non-Bearer header",
			extractor: StrictExtractor{Extractors: []Extractor{BearerExtractor{}}},
			req:       makeStrictRequest("GET", header("Basic "+extractorTestTokenA), nil, nil),
			err:       ErrMalformedBearer,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := tt.extractor.ExtractToken(tt.req)
			if token != tt.token {
				t.Errorf("expected token %q, got %q", tt.token, token)
			}
			if !errors.Is(err, tt.err) {
				t.Errorf("expected error %v, got %v", tt.err, err)
			}
		})
	}
}
