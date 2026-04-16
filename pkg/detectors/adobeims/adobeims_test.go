package adobeims

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

// Pre-built test JWTs (not cryptographically valid, but structurally correct).
// Payload for accessToken decodes to:
//
//	{"type":"access_token","client_id":"testclient123","user_id":"ABCDEF1234567890ABCDEF@AdobeID","as":"ims-na1","scope":"openid,email,profile"}
const (
	accessToken  = "eyJhbGciOiAiUlMyNTYiLCAidHlwIjogIkpXVCJ9.eyJ0eXBlIjogImFjY2Vzc190b2tlbiIsICJjbGllbnRfaWQiOiAidGVzdGNsaWVudDEyMyIsICJ1c2VyX2lkIjogIkFCQ0RFRjEyMzQ1Njc4OTBBQkNERUZAQWRvYmVJRCIsICJhcyI6ICJpbXMtbmExIiwgInNjb3BlIjogIm9wZW5pZCxlbWFpbCxwcm9maWxlIn0.AAABBBCCCDDDEEEFFFGGGHHHIIIJJJKKKLLLMMMNNNOOOPPPQQQRRRSSST"
	refreshToken = "eyJhbGciOiAiUlMyNTYiLCAidHlwIjogIkpXVCJ9.eyJ0eXBlIjogInJlZnJlc2hfdG9rZW4iLCAiY2xpZW50X2lkIjogInRlc3RjbGllbnQxMjMiLCAidXNlcl9pZCI6ICJBQkNERUYxMjM0NTY3ODkwQUJDREVGQEFkb2JlSUQiLCAiYXMiOiAiaW1zLW5hMSIsICJzY29wZSI6ICJvcGVuaWQsZW1haWwscHJvZmlsZSxvZmZsaW5lX2FjY2VzcyJ9.AAABBBCCCDDDEEEFFFGGGHHHIIIJJJKKKLLLMMMNNNOOOPPPQQQRRRSSST"
)

// --- Pattern tests ---

func TestAdobeIMS_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "access_token in JSON",
			input: `{
				"access_token": "` + accessToken + `",
				"token_type": "bearer",
				"adobelogin": true
			}`,
			want: []string{accessToken},
		},
		{
			name:  "access_token as env var",
			input: "ACCESS_TOKEN=" + accessToken + "\n# adobelogin\n",
			want:  []string{accessToken},
		},
		{
			name: "refresh_token in JSON",
			input: `{
				"refresh_token": "` + refreshToken + `",
				"adobelogin": true
			}`,
			want: []string{refreshToken},
		},
		{
			name: "both tokens present",
			input: `{
				"access_token": "` + accessToken + `",
				"refresh_token": "` + refreshToken + `",
				"adobelogin": true
			}`,
			want: []string{accessToken, refreshToken},
		},
		{
			name:  "no adobelogin keyword — should not match",
			input: `{"access_token": "` + accessToken + `"}`,
			want:  nil,
		},
		{
			name:  "non-JWT value — should not match",
			input: `{"access_token": "notajwt", "adobelogin": true}`,
			want:  nil,
		},
		{
			name:  "malformed JWT payload — should not match",
			input: `{"access_token": "eyJhbGci.eyJOT1RWQUxJREpTT04.AAABBBCCCDDDEEEFFFGGG", "adobelogin": true}`,
			want:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(tt.input))

			if len(tt.want) == 0 {
				if len(matchedDetectors) == 0 {
					// Aho-Corasick correctly filtered out this input — keyword absent.
					return
				}
				// Keyword present but content should still yield no results 
				results, err := d.FromData(context.Background(), false, []byte(tt.input))
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if len(results) != 0 {
					t.Errorf("expected no results, got %d", len(results))
				}
				return
			}

			if len(matchedDetectors) == 0 {
				t.Errorf("keywords %v not matched by input", d.Keywords())
				return
			}

			results, err := d.FromData(context.Background(), false, []byte(tt.input))
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			got := make(map[string]struct{}, len(results))
			for _, r := range results {
				got[string(r.Raw)] = struct{}{}
			}
			want := make(map[string]struct{}, len(tt.want))
			for _, v := range tt.want {
				want[v] = struct{}{}
			}

			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// --- Verification tests ---

func TestAdobeIMS_Verification_AccessToken_Valid(t *testing.T) {
	// Mock server: validates token and returns userinfo.
	mux := http.NewServeMux()

	mux.HandleFunc("/ims/validate_token/v1", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"valid": true})
	})

	mux.HandleFunc("/ims/userinfo/v2", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"sub":   "ABCDEF1234567890ABCDEF@AdobeID",
			"email": "test@example.com",
			"name":  "Test User",
		})
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	s := Scanner{client: srv.Client()}

	// We can't redirect imsBaseURL (built from the token's `as` claim) to the mock server,
	// so we call validateToken and getUserInfo directly, passing srv.URL as the base URL.
	payload, err := decodeJWTPayload(accessToken)
	if err != nil {
		t.Fatalf("decodeJWTPayload: %v", err)
	}

	valid, err := validateToken(context.Background(), s.client, srv.URL, accessToken, payload)
	if err != nil {
		t.Fatalf("validateToken error: %v", err)
	}
	if !valid {
		t.Error("expected token to be valid")
	}

	userInfo, err := getUserInfo(context.Background(), s.client, srv.URL, accessToken)
	if err != nil {
		t.Fatalf("getUserInfo error: %v", err)
	}

	wantUserInfo := map[string]string{
		"sub":   "ABCDEF1234567890ABCDEF@AdobeID",
		"email": "test@example.com",
		"name":  "Test User",
	}
	if diff := cmp.Diff(wantUserInfo, userInfo); diff != "" {
		t.Errorf("userInfo mismatch (-want +got):\n%s", diff)
	}
}

func TestAdobeIMS_Verification_AccessToken_Invalid(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	payload, err := decodeJWTPayload(accessToken)
	if err != nil {
		t.Fatalf("decodeJWTPayload: %v", err)
	}

	valid, err := validateToken(context.Background(), srv.Client(), srv.URL, accessToken, payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if valid {
		t.Error("expected token to be invalid")
	}
}

func TestAdobeIMS_Verification_ValidateTokenFalse(t *testing.T) {
	// Server returns 200 but {"valid": false}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"valid": false, "reason": "bad_signature"})
	}))
	defer srv.Close()

	payload, err := decodeJWTPayload(accessToken)
	if err != nil {
		t.Fatalf("decodeJWTPayload: %v", err)
	}

	valid, err := validateToken(context.Background(), srv.Client(), srv.URL, accessToken, payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if valid {
		t.Error("expected token to be invalid when valid=false")
	}
}

func TestAdobeIMS_Verification_RefreshToken_Valid(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"valid": true})
	}))
	defer srv.Close()

	payload, err := decodeJWTPayload(refreshToken)
	if err != nil {
		t.Fatalf("decodeJWTPayload: %v", err)
	}

	valid, err := validateToken(context.Background(), srv.Client(), srv.URL, refreshToken, payload)
	if err != nil {
		t.Fatalf("validateToken error: %v", err)
	}
	if !valid {
		t.Error("expected refresh token to be valid")
	}
}

// --- FromData integration test with mock server ---

func TestAdobeIMS_FromData(t *testing.T) {
	// verify=false: no HTTP calls are made, so no mock server needed.
	// Verification helpers (validateToken, getUserInfo) are tested directly above.
	input := `{
		"access_token": "` + accessToken + `",
		"refresh_token": "` + refreshToken + `",
		"adobelogin": "ims-na1.adobelogin.com"
	}`

	s := Scanner{}
	results, err := s.FromData(context.Background(), false, []byte(input))
	if err != nil {
		t.Fatalf("FromData error: %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	wantTypes := map[string]struct{}{
		"access_token":  {},
		"refresh_token": {},
	}
	gotTypes := make(map[string]struct{}, len(results))
	for _, r := range results {
		if r.DetectorType != detector_typepb.DetectorType_AdobeIMS {
			t.Errorf("unexpected detector type: %v", r.DetectorType)
		}
		gotTypes[r.ExtraData["token_type"]] = struct{}{}
	}

	if diff := cmp.Diff(wantTypes, gotTypes, cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("token_type mismatch (-want +got):\n%s", diff)
	}
}

// --- decodeJWTPayload unit test ---

func TestDecodeJWTPayload(t *testing.T) {
	payload, err := decodeJWTPayload(accessToken)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if payload.Type != "access_token" {
		t.Errorf("expected type=access_token, got %q", payload.Type)
	}
	if payload.ClientID != "testclient123" {
		t.Errorf("expected client_id=testclient123, got %q", payload.ClientID)
	}
	if payload.AuthorizationServer != "ims-na1" {
		t.Errorf("expected as=ims-na1, got %q", payload.AuthorizationServer)
	}

	_, err = decodeJWTPayload("notajwt")
	if err == nil {
		t.Error("expected error for non-JWT input")
	}
}
