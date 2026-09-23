package main

import "testing"

func TestCredential(t *testing.T) {
	tests := []struct {
		name    string
		env     map[string]string
		wantErr bool
	}{
		{"API token only", map[string]string{tokenEnv: "tskey-api-x"}, false},
		{"OAuth pair", map[string]string{oauthClientIDEnv: "id", oauthClientSecretEnv: "secret"}, false},
		{"OAuth pair and token", map[string]string{oauthClientIDEnv: "id", oauthClientSecretEnv: "secret", tokenEnv: "tskey-api-x"}, false},
		{"client ID without secret", map[string]string{oauthClientIDEnv: "id", tokenEnv: "tskey-api-x"}, true},
		{"secret without client ID", map[string]string{oauthClientSecretEnv: "secret"}, true},
		{"nothing", map[string]string{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			getenv := func(k string) string { return tt.env[k] }
			opt, err := credential(getenv)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && opt == nil {
				t.Fatal("no error but no credential option either")
			}
		})
	}
}
