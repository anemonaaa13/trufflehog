package adobeims

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	client *http.Client
}


var _ detectors.Detector = (*Scanner)(nil)


var (

	defaultClient = common.SaneHttpClient()

	accessTokenPat = regexp.MustCompile(`(?i)access_token["'\s]*[:=]["'\s]*(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})`)
	refreshTokenPat = regexp.MustCompile(`(?i)refresh_token["'\s]*[:=]["'\s]*(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})`)
)


func (s Scanner) Keywords() []string {
	return []string{"adobelogin"}
}


func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_AdobeIMS
}


func (s Scanner) Description() string {
	return "Adobe IMS issues OAuth2 tokens for user authentication across Adobe services. Leaked tokens can grant unauthorized access to a user's Adobe account."
}


type jwtPayload struct {
	Type                string `json:"type"`       // "access_token" or "refresh_token"
	ClientID            string `json:"client_id"`  
	UserID              string `json:"user_id"`    
	AuthorizationServer string `json:"as"`         // IMS region, e.g. "ims-na1", "ims-eu1"
	Scope               string `json:"scope"`      // comma-separated list of granted scopes
}


func decodeJWTPayload(token string) (*jwtPayload, error) {
	// Split the token into three parts: header, payload, signature.
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("not a JWT: expected 3 parts, got %d", len(parts))
	}

	seg := parts[1]
	seg = strings.ReplaceAll(seg, "-", "+")
	seg = strings.ReplaceAll(seg, "_", "/")
	// Add back the '=' padding that base64url omits.
	// base64 strings must have a length that is a multiple of 4.
	switch len(seg) % 4 {
	case 2:
		seg += "=="
	case 3:
		seg += "="
	}

	// Decode the base64 string into raw bytes.
	decoded, err := base64.StdEncoding.DecodeString(seg)
	if err != nil {
		return nil, fmt.Errorf("base64 decode failed: %w", err)
	}

	// Parse the JSON bytes into our jwtPayload struct.
	var payload jwtPayload
	if err := json.Unmarshal(decoded, &payload); err != nil {
		return nil, fmt.Errorf("JSON unmarshal failed: %w", err)
	}
	return &payload, nil
}


func imsBaseURL(as string) string {
	if as != "" {
		return fmt.Sprintf("https://%s.adobelogin.com", as)
	}
	return "https://ims-na1.adobelogin.com"
}


func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}


func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	dataStr := string(data)
	var results []detectors.Result

	// seen prevents the same JWT from being reported twice
	seen := make(map[string]struct{})

	type candidate struct {
		token     string
		tokenType string // "access_token" or "refresh_token"
	}

	var candidates []candidate

	for _, m := range accessTokenPat.FindAllStringSubmatch(dataStr, -1) {
		tok := m[1] // m[0] is the full match, m[1] is the captured JWT
		if _, ok := seen[tok]; !ok {
			seen[tok] = struct{}{}
			candidates = append(candidates, candidate{tok, "access_token"})
		}
	}

	for _, m := range refreshTokenPat.FindAllStringSubmatch(dataStr, -1) {
		tok := m[1]
		if _, ok := seen[tok]; !ok {
			seen[tok] = struct{}{}
			candidates = append(candidates, candidate{tok, "refresh_token"})
		}
	}

	for _, c := range candidates {
		payload, err := decodeJWTPayload(c.token)
		if err != nil {
			// Not a structurally valid JWT — skip it silently.
			continue
		}

		// Build the result with information already available from the JWT payload.
		// This is reported even if verification is disabled or fails.
		result := detectors.Result{
			DetectorType: detector_typepb.DetectorType_AdobeIMS,
			Raw:          []byte(c.token),
			ExtraData: map[string]string{
				"token_type": c.tokenType,
				"user_id":    payload.UserID,
				"client_id":  payload.ClientID,
				"as":         payload.AuthorizationServer,
				"scope":      payload.Scope,
			},
		}

		if verify {
			client := s.getClient()
			baseURL := imsBaseURL(payload.AuthorizationServer)

			// confirm the token is still active via /ims/validate_token/v1.
			isVerified, verifyErr := validateToken(ctx, client, baseURL, c.token, payload)
			result.Verified = isVerified
			result.SetVerificationError(verifyErr, c.token)

		}

		results = append(results, result)
	}

	return results, nil
}

// validateToken calls POST /ims/validate_token/v1 to check whether a token is still active.
// It works for both access tokens and refresh tokens.
//
// The request requires:
//   - Authorization: Bearer <token>  (the token itself in the header)
//   - type=<token_type>              (extracted from the JWT payload)
//   - client_id=<client_id>         (extracted from the JWT payload)
//
// Return values:
//   - (true, nil)  — token is valid and active
//   - (false, nil) — token is definitively invalid (expired, revoked, bad signature)
//   - (false, err) — unexpected error (network failure, unexpected HTTP status)
func validateToken(ctx context.Context, client *http.Client, baseURL, token string, payload *jwtPayload) (bool, error) {
	endpoint := baseURL + "/ims/validate_token/v1"

	// Build the POST body as form data: type=access_token&client_id=abc123
	form := url.Values{}
	form.Set("type", payload.Type)
	form.Set("client_id", payload.ClientID)

	// Create the HTTP request with context so it can be cancelled if TruffleHog is stopped
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Send the request to Adobe
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}

	defer resp.Body.Close()

	// Read the full response body into memory.
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	switch resp.StatusCode {
	case http.StatusOK:
		var result struct {
			Valid bool `json:"valid"`
		}
		if err := json.Unmarshal(body, &result); err != nil {
			return false, fmt.Errorf("failed to decode validate_token response: %w", err)
		}
		return result.Valid, nil

	case http.StatusUnauthorized, http.StatusForbidden:
		return false, nil

	default:
		return false, fmt.Errorf("unexpected status %d from validate_token", resp.StatusCode)
	}
}


