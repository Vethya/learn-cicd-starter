package auth

import (
	"errors"
	"net/http"
	"reflect"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := map[string]struct {
		headers    http.Header
		errWant    error
		apiKeyWant string
	}{
		"valid": {
			headers:    makeHeader("Authorization", "ApiKey my-secret-key-123"),
			errWant:    nil,
			apiKeyWant: "my-secret-key-123",
		},
		"header missing": {
			headers:    http.Header{},
			errWant:    ErrNoAuthHeaderIncluded,
			apiKeyWant: "",
		},
		"doesn't start with ApiKey": {
			headers:    makeHeader("Authorization", "Bearer my-token"),
			errWant:    errors.New("malformed authorization header"),
			apiKeyWant: "",
		},
		"no ApiKey": {
			headers:    makeHeader("Authorization", "ApiKey"),
			errWant:    errors.New("malformed authorization header"),
			apiKeyWant: "",
		},
		"empty ApiKey": {
			headers:    makeHeader("Authorization", "ApiKey "),
			errWant:    nil,
			apiKeyWant: "",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			apiKeyGot, errGot := GetAPIKey(tc.headers)

			if !reflect.DeepEqual(tc.apiKeyWant, apiKeyGot) {
				t.Fatalf("api key expected: %v, got: %v", tc.apiKeyWant, apiKeyGot)
			}

			if tc.errWant == nil && errGot != nil {
				t.Fatalf("expected no error, got: %v", errGot)
			}
			if tc.errWant != nil && errGot == nil {
				t.Fatalf("expected error: %v, got nil", tc.errWant)
			}
			if tc.errWant != nil && errGot != nil {
				if tc.errWant.Error() != errGot.Error() {
					t.Fatalf("err expected: %v, got: %v", tc.errWant, errGot)
				}
			}
		})
	}
}

func makeHeader(key, value string) http.Header {
	h := http.Header{}
	h.Set(key, value)
	return h
}
