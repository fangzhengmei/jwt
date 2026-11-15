package request

import (
	"errors"
	"net/http"
	"strings"
)

// Errors
var (
	ErrNoTokenInRequest = errors.New("no token present in request")

	// ErrConflictingTokens is returned by StrictExtractor when a request
	// carries different tokens in different places, for example in both the
	// Authorization header and a query parameter.
	ErrConflictingTokens = errors.New("conflicting tokens present in request")

	// ErrMalformedBearer is returned by StrictExtractor when a header that is
	// expected to carry a Bearer credential does not have the "Bearer <token>"
	// form.
	ErrMalformedBearer = errors.New("malformed bearer token in request")
)

// Extractor is an interface for extracting a token from an HTTP request.
// The ExtractToken method should return a token string or an error.
// If no token is present, you must return ErrNoTokenInRequest.
type Extractor interface {
	ExtractToken(*http.Request) (string, error)
}

// HeaderExtractor is an extractor for finding a token in a header.
// Looks at each specified header in order until there's a match
type HeaderExtractor []string

func (e HeaderExtractor) ExtractToken(req *http.Request) (string, error) {
	// loop over header names and return the first one that contains data
	for _, header := range e {
		if ah := req.Header.Get(header); ah != "" {
			return ah, nil
		}
	}
	return "", ErrNoTokenInRequest
}

// ArgumentExtractor extracts a token from request arguments.  This includes a POSTed form or
// GET URL arguments.  Argument names are tried in order until there's a match.
// This extractor calls `ParseMultipartForm` on the request
type ArgumentExtractor []string

func (e ArgumentExtractor) ExtractToken(req *http.Request) (string, error) {
	// Make sure form is parsed. We are explicitly ignoring errors at this point
	_ = req.ParseMultipartForm(10e6)

	// loop over arg names and return the first one that contains data
	for _, arg := range e {
		if ah := req.Form.Get(arg); ah != "" {
			return ah, nil
		}
	}

	return "", ErrNoTokenInRequest
}

// MultiExtractor tries Extractors in order until one returns a token string or an error occurs
type MultiExtractor []Extractor

func (e MultiExtractor) ExtractToken(req *http.Request) (string, error) {
	// loop over header names and return the first one that contains data
	for _, extractor := range e {
		if tok, err := extractor.ExtractToken(req); tok != "" {
			return tok, nil
		} else if !errors.Is(err, ErrNoTokenInRequest) {
			return "", err
		}
	}
	return "", ErrNoTokenInRequest
}

// PostExtractionFilter wraps an Extractor in this to post-process the value before it's handed off.
// See AuthorizationHeaderExtractor for an example
type PostExtractionFilter struct {
	Extractor
	Filter func(string) (string, error)
}

func (e *PostExtractionFilter) ExtractToken(req *http.Request) (string, error) {
	if tok, err := e.Extractor.ExtractToken(req); tok != "" {
		return e.Filter(tok)
	} else {
		return "", err
	}
}

// BearerExtractor extracts a token from the Authorization header.
// The header is expected to match the format "Bearer XX", where "XX" is the
// JWT token.
type BearerExtractor struct{}

func (e BearerExtractor) ExtractToken(req *http.Request) (string, error) {
	tokenHeader := req.Header.Get("Authorization")
	// The usual convention is for "Bearer" to be title-cased. However, there's no
	// strict rule around this, and it's best to follow the robustness principle here.
	if len(tokenHeader) < 7 || !strings.EqualFold(tokenHeader[:7], "bearer ") {
		return "", ErrNoTokenInRequest
	}
	return tokenHeader[7:], nil
}

// listTokens implements tokenLister for BearerExtractor. Every Authorization
// value must be a Bearer credential; their tokens are all returned so that
// strict extraction can spot a conflict.
func (e BearerExtractor) listTokens(req *http.Request) ([]string, error) {
	var tokens []string
	for _, value := range req.Header.Values("Authorization") {
		if value == "" {
			continue
		}
		token, err := bearerToken(value)
		if err != nil {
			return nil, err
		}
		tokens = append(tokens, token)
	}
	return tokens, nil
}

// StrictExtractor extracts a token from every configured location of a request
// and rejects the request if those locations carry more than one distinct
// token. It is meant for endpoints, such as single-sign-on endpoints, where a
// token is accepted from several places and silently preferring one of them
// would let an attacker choose which identity is verified.
//
// Unlike MultiExtractor, which returns the first token it finds, StrictExtractor:
//
//   - inspects every value of a repeated header, not just the first one,
//   - inspects every query parameter and submitted form value, not just the
//     first one,
//   - returns ErrConflictingTokens when different tokens are found, and
//   - returns ErrMalformedBearer when an Authorization header does not carry a
//     "Bearer <token>" credential as required by RFC 6750.
//
// Repeating the same token, for example the same value in the Authorization
// header and the access_token parameter, or a duplicated header, is accepted.
// A request without any token returns ErrNoTokenInRequest, like the other
// extractors.
//
// Headers and Arguments name the locations to inspect. When both are nil the
// Authorization header and the access_token parameter are used, which matches
// OAuth2Extractor; otherwise exactly the given locations are inspected. When
// Extractors is non-empty those extractors are inspected instead of Headers and
// Arguments, and every token each of them can find takes part in the conflict
// check.
type StrictExtractor struct {
	// Headers are header names that carry a token. Authorization values must
	// use the "Bearer <token>" form; other headers are used as-is.
	Headers []string

	// Arguments are query parameter and form names that carry a token.
	Arguments []string

	// Extractors, when non-empty, are inspected instead of Headers and
	// Arguments.
	Extractors []Extractor
}

// StrictOAuth2Extractor is a StrictExtractor for OAuth2 access tokens at the
// same locations as OAuth2Extractor: the Authorization header and the
// access_token argument.
var StrictOAuth2Extractor = &StrictExtractor{
	Headers:   []string{"Authorization"},
	Arguments: []string{"access_token"},
}

// StrictMultiExtractor is the strict counterpart of MultiExtractor. It inspects
// every extractor instead of stopping at the first match, and returns
// ErrConflictingTokens if they find different tokens.
type StrictMultiExtractor []Extractor

func (e StrictMultiExtractor) ExtractToken(req *http.Request) (string, error) {
	return StrictExtractor{Extractors: e}.ExtractToken(req)
}

func (e StrictExtractor) ExtractToken(req *http.Request) (string, error) {
	tokens, err := e.listTokens(req)
	if err != nil {
		return "", err
	}

	var unique []string
	for _, token := range tokens {
		if token == "" {
			continue
		}
		if !containsToken(unique, token) {
			unique = append(unique, token)
		}
	}

	switch len(unique) {
	case 0:
		return "", ErrNoTokenInRequest
	case 1:
		return unique[0], nil
	default:
		return "", ErrConflictingTokens
	}
}

func (e StrictExtractor) listTokens(req *http.Request) ([]string, error) {
	if len(e.Extractors) > 0 {
		var tokens []string
		for _, extractor := range e.Extractors {
			found, err := extractTokens(extractor, req)
			if err != nil {
				return nil, err
			}
			tokens = append(tokens, found...)
		}
		return tokens, nil
	}

	headers := e.Headers
	arguments := e.Arguments
	if headers == nil && arguments == nil {
		headers = []string{"Authorization"}
		arguments = []string{"access_token"}
	}

	tokens, err := HeaderExtractor(headers).listTokens(req)
	if err != nil {
		return nil, err
	}
	if len(arguments) == 0 {
		return tokens, nil
	}

	args, err := ArgumentExtractor(arguments).listTokens(req)
	if err != nil {
		return nil, err
	}

	return append(tokens, args...), nil
}

// bearerToken returns the token part of a "Bearer <token>" header value. A
// value that does not use the Bearer scheme, or that carries no token, is
// rejected with ErrMalformedBearer.
func bearerToken(value string) (string, error) {
	if len(value) < 7 || !strings.EqualFold(value[:7], "bearer ") {
		return "", ErrMalformedBearer
	}
	if value[7:] == "" {
		return "", ErrMalformedBearer
	}
	return value[7:], nil
}

func containsToken(tokens []string, token string) bool {
	for _, t := range tokens {
		if t == token {
			return true
		}
	}
	return false
}

// tokenLister is implemented by the built-in extractors so that strict
// extraction can see every token a request carries rather than only the first
// one ExtractToken would return.
type tokenLister interface {
	listTokens(*http.Request) ([]string, error)
}

// extractTokens returns every token extractor can find. An extractor that does
// not implement tokenLister contributes at most the single token ExtractToken
// returns.
func extractTokens(extractor Extractor, req *http.Request) ([]string, error) {
	if lister, ok := extractor.(tokenLister); ok {
		return lister.listTokens(req)
	}
	token, err := extractor.ExtractToken(req)
	if err != nil {
		if errors.Is(err, ErrNoTokenInRequest) {
			return nil, nil
		}
		return nil, err
	}
	if token == "" {
		return nil, nil
	}
	return []string{token}, nil
}

// listTokens implements tokenLister for HeaderExtractor. Authorization values
// are treated as bearer credentials, so they must use the "Bearer <token>"
// form.
func (e HeaderExtractor) listTokens(req *http.Request) ([]string, error) {
	var tokens []string
	for _, header := range e {
		for _, value := range req.Header.Values(header) {
			if value == "" {
				continue
			}
			if strings.EqualFold(header, "Authorization") {
				token, err := bearerToken(value)
				if err != nil {
					return nil, err
				}
				tokens = append(tokens, token)
				continue
			}
			tokens = append(tokens, value)
		}
	}
	return tokens, nil
}

// listTokens implements tokenLister for ArgumentExtractor.
func (e ArgumentExtractor) listTokens(req *http.Request) ([]string, error) {
	// This covers both query parameters and submitted form values.
	_ = req.ParseMultipartForm(10e6)
	if req.Form == nil {
		return nil, nil
	}

	var tokens []string
	for _, argument := range e {
		for _, value := range req.Form[argument] {
			if value != "" {
				tokens = append(tokens, value)
			}
		}
	}
	return tokens, nil
}

// listTokens implements tokenLister for StrictMultiExtractor.
func (e StrictMultiExtractor) listTokens(req *http.Request) ([]string, error) {
	return StrictExtractor{Extractors: e}.listTokens(req)
}

// listTokens implements tokenLister for MultiExtractor. Unlike ExtractToken,
// it keeps going after the first match so that tokens in the remaining
// locations take part in conflict detection.
func (e MultiExtractor) listTokens(req *http.Request) ([]string, error) {
	var tokens []string
	for _, extractor := range e {
		found, err := extractTokens(extractor, req)
		if err != nil {
			return nil, err
		}
		tokens = append(tokens, found...)
	}
	return tokens, nil
}

// listTokens implements tokenLister for PostExtractionFilter.
func (e *PostExtractionFilter) listTokens(req *http.Request) ([]string, error) {
	tokens, err := extractTokens(e.Extractor, req)
	if err != nil {
		return nil, err
	}
	filtered := make([]string, 0, len(tokens))
	for _, token := range tokens {
		token, err = e.Filter(token)
		if err != nil {
			return nil, err
		}
		filtered = append(filtered, token)
	}
	return filtered, nil
}
