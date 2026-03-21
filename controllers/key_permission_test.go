package controllers

import (
	"testing"

	"github.com/casdoor/casdoor/object"
)

func TestShouldExpireTokensForKeyUpdate(t *testing.T) {
	baseKey := &object.Key{
		Owner:        "admin",
		Name:         "key1",
		Type:         object.KeyTypeOrganization,
		Organization: "org1",
		Application:  "app1",
		Scopes:       []string{"read"},
		IsEnabled:    true,
		ExpiresTime:  "",
	}

	tests := []struct {
		name     string
		oldKey   *object.Key
		newKey   *object.Key
		expected bool
	}{
		{
			name:     "no security relevant change",
			oldKey:   baseKey,
			newKey:   &object.Key{Owner: "admin", Name: "key1", Type: object.KeyTypeOrganization, Organization: "org1", Application: "app1", Scopes: []string{"read"}, IsEnabled: true, ExpiresTime: "", DisplayName: "new name"},
			expected: false,
		},
		{
			name:     "disabled key expires tokens",
			oldKey:   baseKey,
			newKey:   &object.Key{Owner: "admin", Name: "key1", Type: object.KeyTypeOrganization, Organization: "org1", Application: "app1", Scopes: []string{"read"}, IsEnabled: false, ExpiresTime: ""},
			expected: true,
		},
		{
			name:     "scope change expires tokens",
			oldKey:   baseKey,
			newKey:   &object.Key{Owner: "admin", Name: "key1", Type: object.KeyTypeOrganization, Organization: "org1", Application: "app1", Scopes: []string{"write"}, IsEnabled: true, ExpiresTime: ""},
			expected: true,
		},
		{
			name:     "application change expires tokens",
			oldKey:   baseKey,
			newKey:   &object.Key{Owner: "admin", Name: "key1", Type: object.KeyTypeOrganization, Organization: "org1", Application: "app2", Scopes: []string{"read"}, IsEnabled: true, ExpiresTime: ""},
			expected: true,
		},
		{
			name:     "nil keys do not expire",
			oldKey:   nil,
			newKey:   baseKey,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := shouldExpireTokensForKeyUpdate(tt.oldKey, tt.newKey)
			if actual != tt.expected {
				t.Fatalf("expected %v, got %v", tt.expected, actual)
			}
		})
	}
}
