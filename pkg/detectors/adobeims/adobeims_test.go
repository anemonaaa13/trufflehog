package adobeims

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

// Pre-built test JWTs (not cryptographically valid, but structurally correct).
// Payload for accessToken decodes to:
//
//	{"type":"access_token","client_id":"testclient123","user_id":"ABCDEF1234567890ABCDEF@AdobeID","as":"ims-na1","scope":"openid,email,profile"}
const (
	accessToken  = "eyJhbGciOiAiUlMyNTYiLCAidHlwIjogIkpXVCJ9.eyJ0eXBlIjogImFjY2Vzc190b2tlbiIsICJjbGllbnRfaWQiOiAidGVzdGNsaWVudDEyMyIsICJ1c2VyX2lkIjogIkFCQ0RFRjEyMzQ1Njc4OTBBQkNERUZAQWRvYmVJRCIsICJhcyI6ICJpbXMtbmExIiwgInNjb3BlIjogIm9wZW5pZCxlbWFpbCxwcm9maWxlIn0.AAABBBCCCDDDEEEFFFGGGHHHIIIJJJKKKLLLMMMNNNOOOPPPQQQRRRSSST"
	refreshToken = "eyJhbGciOiAiUlMyNTYiLCAidHlwIjogIkpXVCJ9.eyJ0eXBlIjogInJlZnJlc2hfdG9rZW4iLCAiY2xpZW50X2lkIjogInRlc3RjbGllbnQxMjMiLCAidXNlcl9pZCI6ICJBQkNERUYxMjM0NTY3ODkwQUJDREVGQEFkb2JlSUQiLCAiYXMiOiAiaW1zLW5hMSIsICJzY29wZSI6ICJvcGVuaWQsZW1haWwscHJvZmlsZSxvZmZsaW5lX2FjY2VzcyJ9.AAABBBCCCDDDEEEFFFGGGHHHIIIJJJKKKLLLMMMNNNOOOPPPQQQRRRSSST"
	keyword      = "adobelogin"
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
				"` + keyword + `": true
			}`,
			want: []string{accessToken},
		},
		{
			name:  "access_token as env var",
			input: "ACCESS_TOKEN=" + accessToken + "\n# " + keyword + "\n",
			want:  []string{accessToken},
		},
		{
			name: "refresh_token in JSON",
			input: `{
				"refresh_token": "` + refreshToken + `",
				"` + keyword + `": true
			}`,
			want: []string{refreshToken},
		},
		{
			name: "both tokens present",
			input: `{
				"access_token": "` + accessToken + `",
				"refresh_token": "` + refreshToken + `",
				"` + keyword + `": true
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
			input: `{"access_token": "notajwt", "` + keyword + `": true}`,
			want:  nil,
		},
		{
			name:  "malformed JWT payload — should not match",
			input: `{"access_token": "eyJhbGci.eyJOT1RWQUxJREpTT04.AAABBBCCCDDDEEEFFFGGG", "` + keyword + `": true}`,
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

func TestAdobeIMS_Verification_Indeterminate_UnexpectedStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	payload, err := decodeJWTPayload(accessToken)
	if err != nil {
		t.Fatalf("decodeJWTPayload: %v", err)
	}

	valid, verifyErr := validateToken(context.Background(), srv.Client(), srv.URL, accessToken, payload)
	if verifyErr == nil {
		t.Error("expected a verification error for unexpected API response")
	}
	if valid {
		t.Error("expected token to be unverified")
	}
}


func TestAdobeIMS_Verification_Indeterminate_Timeout(t *testing.T) {
	handlerDone := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-handlerDone
	}))
	defer srv.Close()
	defer close(handlerDone)

	payload, err := decodeJWTPayload(accessToken)
	if err != nil {
		t.Fatalf("decodeJWTPayload: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	valid, verifyErr := validateToken(ctx, srv.Client(), srv.URL, accessToken, payload)
	if verifyErr == nil {
		t.Error("expected a verification error for timeout")
	}
	if valid {
		t.Error("expected token to be unverified")
	}
}
