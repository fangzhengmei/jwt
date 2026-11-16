package request

import (
	"net/http"

	"github.com/golang-jwt/jwt/v5"
)

// ParseFromRequest extracts and parses a JWT token from an HTTP request.
// This behaves the same as Parse, but accepts a request and an extractor
// instead of a token string.  The Extractor interface allows you to define
// the logic for extracting a token.  Several useful implementations are provided.
//
// You can provide options to modify parsing behavior.
//
// By default the extractor chooses a single token, using its own precedence
// rules. Pass WithStrictExtraction to instead reject requests that carry a
// different token in more than one of the locations the extractor inspects.
func ParseFromRequest(req *http.Request, extractor Extractor, keyFunc jwt.Keyfunc, options ...ParseFromRequestOption) (token *jwt.Token, err error) {
	// Create basic parser struct
	p := &fromRequestParser{req, extractor, nil, nil, false}

	// Handle options
	for _, option := range options {
		option(p)
	}

	// Set defaults
	if p.claims == nil {
		p.claims = jwt.MapClaims{}
	}
	if p.parser == nil {
		p.parser = &jwt.Parser{}
	}

	// perform extract
	extractor = p.extractor
	if p.strict {
		extractor = StrictExtractor{Extractors: []Extractor{p.extractor}}
	}
	tokenString, err := extractor.ExtractToken(req)
	if err != nil {
		return nil, err
	}

	// perform parse
	return p.parser.ParseWithClaims(tokenString, p.claims, keyFunc)
}

// ParseFromRequestWithClaims is an alias for ParseFromRequest but with custom Claims type.
//
// Deprecated: use ParseFromRequest and the WithClaims option
func ParseFromRequestWithClaims(req *http.Request, extractor Extractor, claims jwt.Claims, keyFunc jwt.Keyfunc) (token *jwt.Token, err error) {
	return ParseFromRequest(req, extractor, keyFunc, WithClaims(claims))
}

type fromRequestParser struct {
	req       *http.Request
	extractor Extractor
	claims    jwt.Claims
	parser    *jwt.Parser
	strict    bool
}

type ParseFromRequestOption func(*fromRequestParser)

// WithClaims parses with custom claims
func WithClaims(claims jwt.Claims) ParseFromRequestOption {
	return func(p *fromRequestParser) {
		p.claims = claims
	}
}

// WithParser parses using a custom parser
func WithParser(parser *jwt.Parser) ParseFromRequestOption {
	return func(p *fromRequestParser) {
		p.parser = parser
	}
}

// WithStrictExtraction makes ParseFromRequest reject a request that carries
// different tokens in more than one of the locations the extractor inspects.
// Extraction errors, including ErrConflictingTokens and ErrMalformedBearer, are
// returned before the key function is called, so a conflicting request never
// reaches signature verification.
//
// The option only changes how the token is extracted. An extractor that cannot
// report more than one token is unaffected, so combine it with an extractor
// that can, such as StrictExtractor, OAuth2Extractor or a MultiExtractor.
func WithStrictExtraction() ParseFromRequestOption {
	return func(p *fromRequestParser) {
		p.strict = true
	}
}
