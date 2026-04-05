package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
)

func setupTestServer(t *testing.T) (*httptest.Server, string, func()) {
	t.Helper()

	initRedis()
	initDB()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/pub/sso/authorize", SSOAuthorize)
	mux.HandleFunc("POST /api/pub/sso/token", SSOToken)
	mux.HandleFunc("GET /api/pub/sso/validate", SSOValidate)
	mux.HandleFunc("POST /api/pub/sso/revoke", SSORevoke)
	mux.HandleFunc("GET /api/pub/sso/logout", SSOLogout)
	mux.HandleFunc("GET /api/sso/sessions", SSOSessions)
	mux.HandleFunc("DELETE /api/sso/session", SSORevokeSession)

	ts := httptest.NewServer(Auth(mux))

	// Create test client in DB with the test server URL
	redirectURI := ts.URL + "/sso/callback"
	db.Exec("DELETE FROM sso_client WHERE id = 'testclient'")
	db.Exec("INSERT INTO sso_client (id, client_secret, redirect_uri, name) VALUES (?, ?, ?, ?)",
		"testclient", "testsecret", redirectURI, "Test Client")

	return ts, redirectURI, func() {
		db.Exec("DELETE FROM sso_client WHERE id = 'testclient'")
		ts.Close()
		redisClient.Close()
		db.Close()
	}
}

// createTestUser creates a user in the database and returns userID + cleanup func
func createTestUser(t *testing.T) (string, func()) {
	t.Helper()
	email := fmt.Sprintf("test_%s@example.com", uuid.New().String()[:8])
	user, err := CreateUser(email, "Test User", "Test")
	if err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}
	return user.ID, func() {
		db.Exec("DELETE FROM user WHERE id = ?", user.ID)
	}
}

// createTestSession creates a valid session in Redis and returns the session ID
func createTestSession(t *testing.T, userID string) string {
	t.Helper()
	sessionID := uuid.New().String()
	err := SaveSession(sessionID, &webauthn.SessionData{
		UserID:  []byte(userID),
		Expires: time.Now().Add(time.Hour),
	}, time.Hour)
	if err != nil {
		t.Fatalf("failed to create test session: %v", err)
	}
	return sessionID
}

func TestSSOAuthorize_InvalidClientID(t *testing.T) {
	ts, _, cleanup := setupTestServer(t)
	defer cleanup()

	resp, err := http.Get(ts.URL + "/api/pub/sso/authorize?client_id=invalid&redirect_uri=http://example.com&state=abc")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

func TestSSOAuthorize_InvalidRedirectURI(t *testing.T) {
	ts, _, cleanup := setupTestServer(t)
	defer cleanup()

	resp, err := http.Get(ts.URL + "/api/pub/sso/authorize?client_id=testclient&redirect_uri=http://evil.com&state=abc")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

func TestSSOAuthorize_NoSession_RedirectsToLogin(t *testing.T) {
	ts, redirectURI, cleanup := setupTestServer(t)
	defer cleanup()

	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	resp, err := client.Get(ts.URL + "/api/pub/sso/authorize?client_id=testclient&redirect_uri=" + url.QueryEscape(redirectURI) + "&state=mystate")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302, got %d", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.Contains(loc, "sso_client_id=testclient") {
		t.Errorf("expected redirect to login with SSO params, got: %s", loc)
	}
}

func TestSSOAuthorize_WithValidSession_IssuesCode(t *testing.T) {
	ts, redirectURI, cleanup := setupTestServer(t)
	defer cleanup()

	userID, cleanupUser := createTestUser(t)
	defer cleanupUser()

	sessionID := createTestSession(t, userID)

	jar, _ := cookiejar.New(nil)
	tsURL, _ := url.Parse(ts.URL)
	jar.SetCookies(tsURL, []*http.Cookie{{Name: "sso_session", Value: sessionID}})

	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Get(ts.URL + "/api/pub/sso/authorize?client_id=testclient&redirect_uri=" + url.QueryEscape(redirectURI) + "&state=mystate")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302, got %d", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.Contains(loc, "code=") || !strings.Contains(loc, "state=mystate") {
		t.Errorf("expected redirect with code and state, got: %s", loc)
	}
}

func TestSSOToken_InvalidCredentials(t *testing.T) {
	ts, _, cleanup := setupTestServer(t)
	defer cleanup()

	body := `{"code":"fake","client_id":"testclient","client_secret":"wrongsecret"}`
	resp, err := http.Post(ts.URL+"/api/pub/sso/token", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
}

func TestSSOToken_InvalidCode(t *testing.T) {
	ts, _, cleanup := setupTestServer(t)
	defer cleanup()

	body := `{"code":"fake","client_id":"testclient","client_secret":"testsecret"}`
	resp, err := http.Post(ts.URL+"/api/pub/sso/token", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

func TestSSOToken_CodeIsOneTimeUse(t *testing.T) {
	ts, _, cleanup := setupTestServer(t)
	defer cleanup()

	userID, cleanupUser := createTestUser(t)
	defer cleanupUser()

	// Plant a code in Redis
	code := generateCode()
	redisClient.Set(ctx, fmt.Sprintf("sso_code:%s", code), userID, 5*time.Minute)

	body := fmt.Sprintf(`{"code":"%s","client_id":"testclient","client_secret":"testsecret"}`, code)

	// First use should succeed
	resp, err := http.Post(ts.URL+"/api/pub/sso/token", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on first use, got %d", resp.StatusCode)
	}

	// Second use should fail
	resp, err = http.Post(ts.URL+"/api/pub/sso/token", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 on second use, got %d", resp.StatusCode)
	}
}

func TestSSOValidate_InvalidToken(t *testing.T) {
	ts, _, cleanup := setupTestServer(t)
	defer cleanup()

	req, _ := http.NewRequest("GET", ts.URL+"/api/pub/sso/validate", nil)
	req.Header.Set("Authorization", "Bearer invalidtoken")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
}

func TestSSOValidate_MissingAuthHeader(t *testing.T) {
	ts, _, cleanup := setupTestServer(t)
	defer cleanup()

	resp, err := http.Get(ts.URL + "/api/pub/sso/validate")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
}

// TestSSOFullLoginFlow tests the complete SSO workflow:
// authorize -> code exchange -> validate -> revoke
func TestSSOFullLoginFlow(t *testing.T) {
	ts, redirectURI, cleanup := setupTestServer(t)
	defer cleanup()

	userID, cleanupUser := createTestUser(t)
	defer cleanupUser()

	// Step 1: Create an SSO session (simulates successful passkey login)
	sessionID := createTestSession(t, userID)

	// Step 2: Authorize — should redirect with code
	jar, _ := cookiejar.New(nil)
	tsURL, _ := url.Parse(ts.URL)
	jar.SetCookies(tsURL, []*http.Cookie{{Name: "sso_session", Value: sessionID}})

	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Get(ts.URL + "/api/pub/sso/authorize?client_id=testclient&redirect_uri=" + url.QueryEscape(redirectURI) + "&state=teststate")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize: expected 302, got %d", resp.StatusCode)
	}

	// Extract code from redirect
	loc, _ := url.Parse(resp.Header.Get("Location"))
	code := loc.Query().Get("code")
	state := loc.Query().Get("state")
	if code == "" {
		t.Fatal("authorize: no code in redirect")
	}
	if state != "teststate" {
		t.Errorf("authorize: expected state=teststate, got %s", state)
	}

	// Step 3: Exchange code for token
	tokenBody := fmt.Sprintf(`{"code":"%s","client_id":"testclient","client_secret":"testsecret"}`, code)
	resp, err = http.Post(ts.URL+"/api/pub/sso/token", "application/json", strings.NewReader(tokenBody))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token exchange: expected 200, got %d", resp.StatusCode)
	}

	var tokenResp map[string]any
	json.NewDecoder(resp.Body).Decode(&tokenResp)
	accessToken, ok := tokenResp["access_token"].(string)
	if !ok || accessToken == "" {
		t.Fatal("token exchange: no access_token in response")
	}
	if tokenResp["token_type"] != "Bearer" {
		t.Errorf("token exchange: expected token_type=Bearer, got %v", tokenResp["token_type"])
	}

	// Step 4: Validate token — should return user info
	req, _ := http.NewRequest("GET", ts.URL+"/api/pub/sso/validate", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("validate: expected 200, got %d", resp.StatusCode)
	}

	var userInfo map[string]any
	json.NewDecoder(resp.Body).Decode(&userInfo)
	if userInfo["sub"] != userID {
		t.Errorf("validate: expected sub=%s, got %v", userID, userInfo["sub"])
	}
	if userInfo["email"] == nil || userInfo["email"] == "" {
		t.Error("validate: expected email in response")
	}

	// Step 5: Validate again — should still work (TTL extended)
	req, _ = http.NewRequest("GET", ts.URL+"/api/pub/sso/validate", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("validate (second call): expected 200, got %d", resp.StatusCode)
	}

	// Step 6: Revoke token
	req, _ = http.NewRequest("POST", ts.URL+"/api/pub/sso/revoke", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke: expected 200, got %d", resp.StatusCode)
	}

	// Step 7: Validate after revoke — should fail
	req, _ = http.NewRequest("GET", ts.URL+"/api/pub/sso/validate", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("validate after revoke: expected 401, got %d", resp.StatusCode)
	}
}

// TestSSOLogout tests that SSO logout clears the session cookie
func TestSSOLogout(t *testing.T) {
	ts, _, cleanup := setupTestServer(t)
	defer cleanup()

	userID, cleanupUser := createTestUser(t)
	defer cleanupUser()

	sessionID := createTestSession(t, userID)

	jar, _ := cookiejar.New(nil)
	tsURL, _ := url.Parse(ts.URL)
	jar.SetCookies(tsURL, []*http.Cookie{{Name: "sso_session", Value: sessionID}})

	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Logout
	resp, err := client.Get(ts.URL + "/api/pub/sso/logout?redirect_uri=http://example.com/done")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("logout: expected 302, got %d", resp.StatusCode)
	}
	if resp.Header.Get("Location") != "http://example.com/done" {
		t.Errorf("logout: expected redirect to http://example.com/done, got %s", resp.Header.Get("Location"))
	}

	// Verify session cookies are cleared
	found := false
	for _, c := range resp.Cookies() {
		if c.Name == "sso_session" && c.MaxAge < 0 {
			found = true
		}
	}
	if !found {
		t.Error("logout: expected sso_session cookie to be cleared")
	}

	// Verify Redis session is deleted
	_, err = GetSession(sessionID)
	if err == nil {
		t.Error("logout: expected session to be deleted from Redis")
	}
}

// TestSSOLogout_DefaultRedirect tests that logout redirects to / when no redirect_uri
func TestSSOLogout_DefaultRedirect(t *testing.T) {
	ts, _, cleanup := setupTestServer(t)
	defer cleanup()

	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	resp, err := client.Get(ts.URL + "/api/pub/sso/logout")
	if err != nil {
		t.Fatal(err)
	}
	if resp.Header.Get("Location") != "/" {
		t.Errorf("expected redirect to /, got %s", resp.Header.Get("Location"))
	}
}

// TestSSOSessions tests listing and revoking sessions from the dashboard
func TestSSOSessions(t *testing.T) {
	ts, _, cleanup := setupTestServer(t)
	defer cleanup()

	userID, cleanupUser := createTestUser(t)
	defer cleanupUser()

	// Create SSO session for dashboard access
	sessionID := createTestSession(t, userID)

	// Create two SSO tokens manually
	token1 := generateCode()
	token2 := generateCode()
	for _, token := range []string{token1, token2} {
		data, _ := json.Marshal(SSOTokenData{
			UserID:   userID,
			ClientID: "testclient",
			Created:  time.Now().Format("2006-01-02 15:04"),
		})
		redisClient.Set(ctx, fmt.Sprintf("sso_token:%s", token), data, ssoTokenTTL)
		redisClient.SAdd(ctx, fmt.Sprintf("sso_user_tokens:%s", userID), token)
	}
	defer func() {
		redisClient.Del(ctx, fmt.Sprintf("sso_token:%s", token1))
		redisClient.Del(ctx, fmt.Sprintf("sso_token:%s", token2))
		redisClient.Del(ctx, fmt.Sprintf("sso_user_tokens:%s", userID))
	}()

	jar, _ := cookiejar.New(nil)
	tsURL, _ := url.Parse(ts.URL)
	jar.SetCookies(tsURL, []*http.Cookie{{Name: "sso_session", Value: sessionID}})
	client := &http.Client{Jar: jar}

	// List sessions
	resp, err := client.Get(ts.URL + "/api/sso/sessions")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("sessions: expected 200, got %d", resp.StatusCode)
	}

	var sessions []map[string]any
	json.NewDecoder(resp.Body).Decode(&sessions)
	if len(sessions) != 2 {
		t.Fatalf("sessions: expected 2, got %d", len(sessions))
	}

	// Revoke one session
	req, _ := http.NewRequest("DELETE", ts.URL+"/api/sso/session?token="+token1, nil)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke session: expected 200, got %d", resp.StatusCode)
	}

	// Verify only 1 session remains
	resp, err = client.Get(ts.URL + "/api/sso/sessions")
	if err != nil {
		t.Fatal(err)
	}
	json.NewDecoder(resp.Body).Decode(&sessions)
	if len(sessions) != 1 {
		t.Errorf("sessions after revoke: expected 1, got %d", len(sessions))
	}

	// Verify the revoked token is no longer valid
	req, _ = http.NewRequest("GET", ts.URL+"/api/pub/sso/validate", nil)
	req.Header.Set("Authorization", "Bearer "+token1)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("validate revoked token: expected 401, got %d", resp.StatusCode)
	}
}

// TestSSOSessions_Unauthorized tests that unauthenticated users can't list sessions
func TestSSOSessions_Unauthorized(t *testing.T) {
	ts, _, cleanup := setupTestServer(t)
	defer cleanup()

	resp, err := http.Get(ts.URL + "/api/sso/sessions")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
}

// TestSSORevokeSession_WrongUser tests that a user can't revoke another user's session
func TestSSORevokeSession_WrongUser(t *testing.T) {
	ts, _, cleanup := setupTestServer(t)
	defer cleanup()

	// Create two users
	user1ID, cleanupUser1 := createTestUser(t)
	defer cleanupUser1()
	user2ID, cleanupUser2 := createTestUser(t)
	defer cleanupUser2()

	// Create a token belonging to user2
	token := generateCode()
	data, _ := json.Marshal(SSOTokenData{
		UserID:   user2ID,
		ClientID: "testclient",
		Created:  time.Now().Format("2006-01-02 15:04"),
	})
	redisClient.Set(ctx, fmt.Sprintf("sso_token:%s", token), data, ssoTokenTTL)
	redisClient.SAdd(ctx, fmt.Sprintf("sso_user_tokens:%s", user2ID), token)
	defer func() {
		redisClient.Del(ctx, fmt.Sprintf("sso_token:%s", token))
		redisClient.Del(ctx, fmt.Sprintf("sso_user_tokens:%s", user2ID))
	}()

	// Login as user1
	sessionID := createTestSession(t, user1ID)
	jar, _ := cookiejar.New(nil)
	tsURL, _ := url.Parse(ts.URL)
	jar.SetCookies(tsURL, []*http.Cookie{{Name: "sso_session", Value: sessionID}})
	client := &http.Client{Jar: jar}

	// Try to revoke user2's token
	req, _ := http.NewRequest("DELETE", ts.URL+"/api/sso/session?token="+token, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 when revoking another user's session, got %d", resp.StatusCode)
	}

	// Verify token still valid
	req, _ = http.NewRequest("GET", ts.URL+"/api/pub/sso/validate", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("token should still be valid, got %d", resp.StatusCode)
	}
}
