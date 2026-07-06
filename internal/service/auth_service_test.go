package service

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetBasicAuth(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name          string
		xAPIKey       string
		authorization string
		wantUsername  string
		wantPassword  string
		wantAuth      bool
	}{
		{
			name:          "uses X-Api-Key basic auth first",
			xAPIKey:       basicAuthHeader("api-user", "api-password"),
			authorization: basicAuthHeader("app-user", "app-password"),
			wantUsername:  "api-user",
			wantPassword:  "api-password",
			wantAuth:      true,
		},
		{
			name:          "falls back to Authorization",
			authorization: basicAuthHeader("fallback-user", "fallback-password"),
			wantUsername:  "fallback-user",
			wantPassword:  "fallback-password",
			wantAuth:      true,
		},
		{
			name:         "supports colon in password",
			xAPIKey:      basicAuthHeader("api-user", "password:with:colons"),
			wantUsername: "api-user",
			wantPassword: "password:with:colons",
			wantAuth:     true,
		},
		{
			name:         "accepts case-insensitive basic scheme",
			xAPIKey:      "basic " + base64.StdEncoding.EncodeToString([]byte("api-user:api-password")),
			wantUsername: "api-user",
			wantPassword: "api-password",
			wantAuth:     true,
		},
		{
			name:          "does not fall back when X-Api-Key is malformed",
			xAPIKey:       "Basic not-base64",
			authorization: basicAuthHeader("fallback-user", "fallback-password"),
		},
		{
			name:          "does not fall back when X-Api-Key uses another scheme",
			xAPIKey:       "Bearer token",
			authorization: basicAuthHeader("fallback-user", "fallback-password"),
		},
		{
			name: "returns no user without credentials",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(recorder)
			req := httptest.NewRequest(http.MethodGet, "/api/auth/nginx", nil)

			if tt.xAPIKey != "" {
				req.Header.Set("X-Api-Key", tt.xAPIKey)
			}
			if tt.authorization != "" {
				req.Header.Set("Authorization", tt.authorization)
			}

			ctx.Request = req
			got := (&AuthService{}).GetBasicAuth(ctx)

			if !tt.wantAuth {
				assert.Nil(t, got)
				return
			}

			require.NotNil(t, got)
			assert.Equal(t, tt.wantUsername, got.Username)
			assert.Equal(t, tt.wantPassword, got.Password)
			assert.Equal(t, tt.authorization, req.Header.Get("Authorization"))
		})
	}
}

func basicAuthHeader(username, password string) string {
	credentials := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	return "Basic " + credentials
}
