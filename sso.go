package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var ssoTokenTTL = time.Hour

type SSOTokenData struct {
	UserID    string `json:"user_id"`
	ClientID  string `json:"client_id"`
	SessionID string `json:"session_id"`
	UserAgent string `json:"user_agent"`
	Created   string `json:"created"`
}

func generateCode() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// SSOAuthorize handles the SSO authorization request.
// GET /api/pub/sso/authorize?client_id=X&redirect_uri=URI&state=STATE[&sid=SID]
//
// If sid is provided and valid, it generates an auth code and redirects to redirect_uri.
// Otherwise, it redirects to the login page with SSO params preserved.
func SSOAuthorize(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("client_id")
	redirectURI := r.URL.Query().Get("redirect_uri")
	state := r.URL.Query().Get("state")

	client, err := GetSSOClient(clientID)
	if err != nil {
		http.Error(w, "Invalid client_id", http.StatusBadRequest)
		return
	}

	if redirectURI != client.RedirectURI {
		http.Error(w, "Invalid redirect_uri", http.StatusBadRequest)
		return
	}

	// Check if user already has a valid session via cookie
	sid := getSessionID(r)
	if sid != "" {
		session, err := GetSession(sid)
		if err == nil && !session.Expires.Before(time.Now()) {
			code := generateCode()
			userID := string(session.UserID)
			// Store userID|sessionID so the token exchange can track which SSO session created it
			redisClient.Set(ctx, fmt.Sprintf("sso_code:%s", code), userID+"|"+sid, 5*time.Minute)

			redirectURL := fmt.Sprintf("%s?code=%s&state=%s",
				redirectURI, url.QueryEscape(code), url.QueryEscape(state))
			http.Redirect(w, r, redirectURL, http.StatusFound)
			return
		}
		// Session cookie present but invalid — clear stale cookies
		// so the login page JS doesn't auto-redirect and loop
		clearSessionCookies(w)
	}

	redirectToLogin(w, r, clientID, redirectURI, state)
}

func redirectToLogin(w http.ResponseWriter, r *http.Request, clientID, redirectURI, state string) {
	loginURL := fmt.Sprintf("/?sso_client_id=%s&sso_redirect_uri=%s&sso_state=%s",
		url.QueryEscape(clientID),
		url.QueryEscape(redirectURI),
		url.QueryEscape(state))
	http.Redirect(w, r, loginURL, http.StatusFound)
}

// SSOToken exchanges an auth code for an opaque token.
// POST /api/pub/sso/token
func SSOToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code         string `json:"code"`
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		JSONResponse(w, "Invalid request", http.StatusBadRequest)
		return
	}

	client, err := GetSSOClient(req.ClientID)
	if err != nil || client.ClientSecret != req.ClientSecret {
		JSONResponse(w, "Invalid client credentials", http.StatusUnauthorized)
		return
	}

	codeKey := fmt.Sprintf("sso_code:%s", req.Code)
	codeVal, err := redisClient.Get(ctx, codeKey).Result()
	if err != nil {
		JSONResponse(w, "Invalid or expired code", http.StatusBadRequest)
		return
	}

	// One-time use
	redisClient.Del(ctx, codeKey)

	// Parse userID|sessionID
	parts := strings.SplitN(codeVal, "|", 2)
	userID := parts[0]
	sessionID := ""
	if len(parts) == 2 {
		sessionID = parts[1]
	}

	// Generate opaque token with metadata
	token := generateCode()
	tokenData := SSOTokenData{
		UserID:    userID,
		ClientID:  req.ClientID,
		SessionID: sessionID,
		UserAgent: r.UserAgent(),
		Created:   time.Now().Format("2006-01-02 15:04"),
	}
	dataJSON, _ := json.Marshal(tokenData)

	tokenKey := fmt.Sprintf("sso_token:%s", token)
	redisClient.Set(ctx, tokenKey, dataJSON, ssoTokenTTL)

	// Track token in per-user set
	userTokensKey := fmt.Sprintf("sso_user_tokens:%s", userID)
	redisClient.SAdd(ctx, userTokensKey, token)

	JSONResponse(w, map[string]any{
		"access_token": token,
		"token_type":   "Bearer",
		"expires_in":   int(ssoTokenTTL.Seconds()),
	}, http.StatusOK)
}

// SSOValidate validates an opaque token and returns user info.
// Every successful validation extends the token TTL.
// GET /api/pub/sso/validate (Authorization: Bearer <token>)
func SSOValidate(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		JSONResponse(w, "Missing or invalid Authorization header", http.StatusUnauthorized)
		return
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")
	tokenData, err := getSSOTokenData(token)
	if err != nil {
		JSONResponse(w, "Invalid or expired token", http.StatusUnauthorized)
		return
	}

	// Extend TTL on every valid request
	redisClient.Expire(ctx, fmt.Sprintf("sso_token:%s", token), ssoTokenTTL)

	user, err := GetUser(tokenData.UserID)
	if err != nil {
		JSONResponse(w, "User not found", http.StatusInternalServerError)
		return
	}

	JSONResponse(w, map[string]any{
		"sub":          user.ID,
		"email":        user.Email,
		"name":         user.Name,
		"display_name": user.DisplayName,
	}, http.StatusOK)
}

// SSOLogout clears the SSO session and redirects back to the client.
// GET /api/pub/sso/logout?redirect_uri=URI
func SSOLogout(w http.ResponseWriter, r *http.Request) {
	sid := getSessionID(r)
	if sid != "" {
		DeleteSession(sid)
	}
	clearSessionCookies(w)

	redirectURI := r.URL.Query().Get("redirect_uri")
	if redirectURI == "" {
		redirectURI = "/"
	}
	http.Redirect(w, r, redirectURI, http.StatusFound)
}

func getSSOTokenData(token string) (*SSOTokenData, error) {
	val, err := redisClient.Get(ctx, fmt.Sprintf("sso_token:%s", token)).Result()
	if err != nil {
		return nil, err
	}
	var data SSOTokenData
	if err := json.Unmarshal([]byte(val), &data); err != nil {
		return nil, err
	}
	return &data, nil
}

func revokeSSOToken(token string) {
	tokenData, err := getSSOTokenData(token)
	if err == nil {
		redisClient.SRem(ctx, fmt.Sprintf("sso_user_tokens:%s", tokenData.UserID), token)
	}
	redisClient.Del(ctx, fmt.Sprintf("sso_token:%s", token))
}

// revokeSSOTokenAndSession revokes the token and also deletes the SSO session
// that created it, forcing re-authentication. Used when kicking out from dashboard.
func revokeSSOTokenAndSession(token string) {
	tokenData, err := getSSOTokenData(token)
	if err == nil {
		redisClient.SRem(ctx, fmt.Sprintf("sso_user_tokens:%s", tokenData.UserID), token)
		if tokenData.SessionID != "" {
			DeleteSession(tokenData.SessionID)
		}
	}
	redisClient.Del(ctx, fmt.Sprintf("sso_token:%s", token))
}

// SSORevoke revokes an opaque token immediately.
// POST /api/pub/sso/revoke (Authorization: Bearer <token>)
func SSORevoke(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		JSONResponse(w, "Missing or invalid Authorization header", http.StatusUnauthorized)
		return
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")
	revokeSSOToken(token)

	JSONResponse(w, "Token revoked", http.StatusOK)
}

// SSOSessions returns all active SSO sessions for the authenticated user.
// GET /api/sso/sessions (requires sid header)
func SSOSessions(w http.ResponseWriter, r *http.Request) {
	sid := getSessionID(r)
	session, err := GetSession(sid)
	if err != nil {
		JSONResponse(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	userID := string(session.UserID)
	userTokensKey := fmt.Sprintf("sso_user_tokens:%s", userID)
	tokens, err := redisClient.SMembers(ctx, userTokensKey).Result()
	if err != nil {
		JSONResponse(w, "Failed to get sessions", http.StatusInternalServerError)
		return
	}

	type sessionInfo struct {
		Token     string `json:"token"`
		ClientID  string `json:"client_id"`
		URL       string `json:"url"`
		UserAgent string `json:"user_agent"`
		Created   string `json:"created"`
	}

	var sessions []sessionInfo
	for _, token := range tokens {
		data, err := getSSOTokenData(token)
		if err != nil {
			// Token expired, clean up from set
			redisClient.SRem(ctx, userTokensKey, token)
			continue
		}
		clientURL := ""
		if client, err := GetSSOClient(data.ClientID); err == nil {
			if u, err := url.Parse(client.RedirectURI); err == nil {
				clientURL = u.Scheme + "://" + u.Host
			}
		}
		sessions = append(sessions, sessionInfo{
			Token:     token,
			ClientID:  data.ClientID,
			URL:       clientURL,
			UserAgent: data.UserAgent,
			Created:   data.Created,
		})
	}

	JSONResponse(w, sessions, http.StatusOK)
}

// SSORevokeSession revokes a specific SSO session by token.
// DELETE /api/sso/sessions?token=X (requires sid header)
func SSORevokeSession(w http.ResponseWriter, r *http.Request) {
	sid := getSessionID(r)
	session, err := GetSession(sid)
	if err != nil {
		JSONResponse(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	token := r.URL.Query().Get("token")
	if token == "" {
		JSONResponse(w, "Missing token", http.StatusBadRequest)
		return
	}

	// Verify the token belongs to this user
	tokenData, err := getSSOTokenData(token)
	if err != nil {
		JSONResponse(w, "Session not found", http.StatusNotFound)
		return
	}
	if tokenData.UserID != string(session.UserID) {
		JSONResponse(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	revokeSSOTokenAndSession(token)
	JSONResponse(w, "Session revoked", http.StatusOK)
}
