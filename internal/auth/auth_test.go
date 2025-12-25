package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError error
		errorContains string
	}{
		{
			name:          "no authorization header",
			headers:       http.Header{},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name: "empty authorization header",
			headers: http.Header{
				"Authorization": []string{""},
			},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name: "malformed header - missing ApiKey prefix",
			headers: http.Header{
				"Authorization": []string{"Bearer token123"},
			},
			expectedKey:   "",
			errorContains: "malformed authorization header",
		},
		{
			name: "malformed header - only ApiKey without value",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			expectedKey:   "",
			errorContains: "malformed authorization header",
		},
		{
			name: "valid ApiKey header",
			headers: http.Header{
				"Authorization": []string{"ApiKey my-secret-key"},
			},
			expectedKey:   "my-secret-key",
			expectedError: nil,
		},
		{
			name: "valid ApiKey header with extra spaces",
			headers: http.Header{
				"Authorization": []string{"ApiKey key-with-extra parts"},
			},
			expectedKey:   "key-with-extra",
			expectedError: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetAPIKey(tt.headers)

			if key != tt.expectedKey {
				t.Errorf("expected key %q, got %q", tt.expectedKey, key)
			}

			if tt.expectedError != nil {
				if err != tt.expectedError {
					t.Errorf("expected error %v, got %v", tt.expectedError, err)
				}
			} else if tt.errorContains != "" {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.errorContains)
				} else if err.Error() != tt.errorContains {
					t.Errorf("expected error %q, got %q", tt.errorContains, err.Error())
				}
			} else if err != nil {
				t.Errorf("expected no error, got %v", err)
			}
		})
	}
}
