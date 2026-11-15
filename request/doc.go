// Utility package for extracting JWT tokens from
// HTTP requests.
//
// The main function is ParseFromRequest and it's WithClaims variant.
// See examples for how to use the various Extractor implementations
// or roll your own.
//
// The extractors that scan several locations (MultiExtractor, OAuth2Extractor)
// return the first token they find, so a request that carries a different
// token in another location is accepted with the first one. Endpoints that
// must not let a caller choose which identity is verified, such as
// single-sign-on endpoints, can either use StrictExtractor or
// StrictMultiExtractor directly, or pass WithStrictExtraction to
// ParseFromRequest. Strict extraction rejects a request whose locations
// disagree with ErrConflictingTokens, and rejects a malformed Authorization
// header with ErrMalformedBearer, both before the key function runs. Repeating
// the same token is still accepted, and a request without a token returns
// ErrNoTokenInRequest.
package request
