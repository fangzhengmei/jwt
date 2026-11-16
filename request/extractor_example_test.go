package request

import (
	"fmt"
	"net/url"
)

const (
	exampleTokenA = "A"
)

func ExampleHeaderExtractor() {
	req := makeExampleRequest("GET", "/", map[string]string{"Token": exampleTokenA}, nil)
	tokenString, err := HeaderExtractor{"Token"}.ExtractToken(req)
	if err == nil {
		fmt.Println(tokenString)
	} else {
		fmt.Println(err)
	}
	// Output: A
}

func ExampleArgumentExtractor() {
	req := makeExampleRequest("GET", "/", nil, url.Values{"token": {extractorTestTokenA}})
	tokenString, err := ArgumentExtractor{"token"}.ExtractToken(req)
	if err == nil {
		fmt.Println(tokenString)
	} else {
		fmt.Println(err)
	}
	// Output: A
}

func ExampleStrictExtractor() {
	req := makeExampleRequest("GET", "/", map[string]string{"Authorization": "Bearer A"},
		url.Values{"access_token": {"B"}})

	tokenString, err := StrictOAuth2Extractor.ExtractToken(req)
	if err == nil {
		fmt.Println(tokenString)
	} else {
		fmt.Println(err)
	}
	// Output: conflicting tokens present in request
}
