package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
)

// GetUserCredentials returns credentials for a user
func GetUserCredentials(w http.ResponseWriter, r *http.Request) {
	sid := getSessionID(r)
	session, err := GetSession(sid)
	if err != nil {
		JSONResponse(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	user, err := GetUser(string(session.UserID))
	if err != nil {
		JSONResponse(w, "User not found", http.StatusNotFound)
		return
	}
	creds := user.Credentials()
	type credInfo struct {
		ID      string `json:"id"`
		AAGUID  string `json:"aaguid"`
		Label   string `json:"label"`
		Created string `json:"created"`
	}
	var result []credInfo
	for _, cred := range creds {
		aaguid := ""
		if cred.AAGUID != nil {
			aaguid = *cred.AAGUID
		}
		label := ""
		if cred.Label != nil {
			label = *cred.Label
		}
		created := ""
		if cred.Created != nil {
			created = cred.Created.Format("2006-01-02 15:04")
		}
		result = append(result, credInfo{ID: cred.ID, AAGUID: aaguid, Label: label, Created: created})
	}
	JSONResponse(w, result, http.StatusOK)
}

// DeleteUserCredential deletes a credential by ID
func DeleteUserCredential(w http.ResponseWriter, r *http.Request) {
	sid := getSessionID(r)
	session, err := GetSession(sid)
	if err != nil {
		JSONResponse(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	user, err := GetUser(string(session.UserID))
	if err != nil {
		JSONResponse(w, "User not found", http.StatusNotFound)
		return
	}

	credID := r.URL.Query().Get("id")
	if credID == "" {
		JSONResponse(w, "Missing credential id", http.StatusBadRequest)
		return
	}

	// Verify the credential belongs to this user
	creds := user.Credentials()
	found := false
	for _, cred := range creds {
		if cred.ID == credID {
			found = true
			break
		}
	}
	if !found {
		JSONResponse(w, "Credential not found", http.StatusNotFound)
		return
	}

	user.RemoveCredential([]byte(credID))
	JSONResponse(w, "Credential deleted", http.StatusOK)
}

// UpdateProfile updates user name and display name
func UpdateProfile(w http.ResponseWriter, r *http.Request) {
	sid := getSessionID(r)
	session, err := GetSession(sid)
	if err != nil {
		JSONResponse(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	user, err := GetUser(string(session.UserID))
	if err != nil {
		JSONResponse(w, "User not found", http.StatusNotFound)
		return
	}

	var req struct {
		Name        string `json:"name"`
		DisplayName string `json:"display_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		JSONResponse(w, "Invalid request", http.StatusBadRequest)
		return
	}

	user.Name = req.Name
	user.DisplayName = req.DisplayName
	if err := SaveUser(user); err != nil {
		log.Printf("[ERRO] can't update user: %s", err.Error())
		JSONResponse(w, "Failed to update profile", http.StatusInternalServerError)
		return
	}

	JSONResponse(w, user, http.StatusOK)
}

/////////////////////////////
//                         //
//    BeginEmailLogin      //
//                         //
/////////////////////////////

func BeginEmailLogin(w http.ResponseWriter, r *http.Request) {
	log.Printf("[INFO] begin email login ----------------------\\")

	u, err := getUserData(r)
	if err != nil {
		log.Printf("[ERRO] can't get user data: %s", err.Error())
		JSONResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	if u.Email == "" {
		JSONResponse(w, "Email is required", http.StatusBadRequest)
		return
	}

	// Check if user exists; if not, create one
	_, err = GetUserByEmail(u.Email)
	if err != nil {
		// User doesn't exist, create a new one with email as name
		_, err = CreateUser(u.Email, u.Email, u.Email)
		if err != nil {
			msg := fmt.Sprintf("can't create user: %s", err.Error())
			log.Printf("[ERRO] %s", msg)
			JSONResponse(w, msg, http.StatusInternalServerError)
			return
		}
		log.Printf("[INFO] created new user for email: %s", u.Email)
	}

	// Generate a random token for the magic link
	token := uuid.New().String()
	expires := time.Now().Add(10 * time.Minute)

	_, err = CreateUserLogin(u.Email, token, expires)
	if err != nil {
		log.Printf("[ERRO] can't create login token: %s", err.Error())
		JSONResponse(w, "Failed to create login token", http.StatusInternalServerError)
		return
	}

	// Build the magic link URL
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if fwdProto := r.Header.Get("X-Forwarded-Proto"); fwdProto != "" {
		scheme = fwdProto
	}
	loginLink := fmt.Sprintf("%s://%s/api/pub/verify_login?token=%s", scheme, r.Host, token)

	log.Printf("[INFO] login link: %s", loginLink)

	// Send the magic link to the user's email
	err = SendMail(u.Email, "Your login link", fmt.Sprintf("Click the link below to log in:\n\n%s\n\nThis link expires in 10 minutes.", loginLink))
	if err != nil {
		log.Printf("[ERRO] can't send login email: %s", err.Error())
		JSONResponse(w, "Failed to send login email", http.StatusInternalServerError)
		return
	}

	JSONResponse(w, "Login link sent to your email", http.StatusOK)
	log.Printf("[INFO] end email login ----------------------/")
}

/////////////////////////////
//                         //
//    VerifyLoginLink      //
//                         //
/////////////////////////////

func VerifyLoginLink(w http.ResponseWriter, r *http.Request) {
	log.Printf("[INFO] verify login link ----------------------\\")

	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "Missing token", http.StatusBadRequest)
		return
	}

	// Look up the token in the user_login table
	userLogin, err := GetUserLoginByToken(token)
	if err != nil {
		log.Printf("[ERRO] invalid login token: %s", err.Error())
		http.Error(w, "Invalid or expired login link", http.StatusBadRequest)
		return
	}

	// Mark the token as used
	err = MarkUserLoginUsed(userLogin.ID)
	if err != nil {
		log.Printf("[ERRO] can't mark login token as used: %s", err.Error())
	}

	// Find the user
	user, err := GetUserByEmail(*userLogin.Email)
	if err != nil {
		log.Printf("[ERRO] can't get user: %s", err.Error())
		http.Error(w, "User not found", http.StatusBadRequest)
		return
	}

	// Create a session for the user
	sessionID := uuid.New().String()
	SaveSession(sessionID, &webauthn.SessionData{
		UserID:  []byte(user.ID),
		Expires: time.Now().Add(time.Hour),
	}, time.Hour)

	setSessionCookies(w, sessionID, time.Hour)
	http.Redirect(w, r, "/", http.StatusFound)

	log.Printf("[INFO] verify login link ----------------------/")
}

/////////////////////////////
//                         //
//    BeginRegistration    //
//                         //
/////////////////////////////

func BeginRegistration(w http.ResponseWriter, r *http.Request) {
	log.Printf("[INFO] begin registration ----------------------\\")

	u, err := getUserData(r)
	if err != nil {
		log.Printf("[ERRO]can't get user name: %s", err.Error())
		JSONResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	user, err := GetUserByEmail(u.Email) // Find the user
	if err != nil {
		log.Printf("[ERRO] can't get user: %s", err.Error())
		JSONResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Begin the registration process, which will return options to be sent to the client
	// along with session data to be stored on the server until verification is finished
	options, session, err := webAuthn.BeginRegistration(user)
	if err != nil {
		msg := fmt.Sprintf("can't begin registration: %s", err.Error())
		log.Printf("[ERRO] %s", msg)
		JSONResponse(w, msg, http.StatusBadRequest)
		return
	}

	sessionID := uuid.New().String()
	err = SaveSession(sessionID, session, time.Minute*5) // save session for 5 minutes
	if err != nil {
		log.Printf("[ERRO] can't save session: %s", err.Error())
		JSONResponse(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Add("Access-Control-Expose-Headers", "register_sid")
	w.Header().Set("register_sid", sessionID)
	JSONResponse(w, options, http.StatusOK) // return the options generated with the session key
	// options.publicKey contain our registration options
}

//////////////////////////////
//                          //
//    FinishRegistration    //
//                          //
//////////////////////////////

func FinishRegistration(w http.ResponseWriter, r *http.Request) {
	// read register_sid from header
	registerSid := r.Header.Get("register_sid")
	if registerSid == "" {
		log.Printf("[ERRO] missing register_sid header")
		JSONResponse(w, "missing register_sid header", http.StatusBadRequest)
		return
	}

	session, err := GetSession(registerSid)
	if err != nil {
		log.Printf("[ERRO] can't get session: %s", err.Error())
		JSONResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	user, err := GetUser(string(session.UserID))
	if err != nil {
		log.Printf("[ERRO] can't get user: %s", err.Error())
		JSONResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	credential, err := webAuthn.FinishRegistration(user, *session, r)
	if err != nil {
		msg := fmt.Sprintf("can't finish registration: %s", err.Error())
		log.Printf("[ERRO] %s", msg)
		JSONResponse(w, msg, http.StatusBadRequest)
		return
	}

	// Check if an existing credential uses the same authenticator (AAGUID).
	// Platform authenticators (e.g. Touch ID) overwrite the old key pair internally.
	aaguid := credential.Authenticator.AAGUID
	newAAGUID := fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", aaguid[0:4], aaguid[4:6], aaguid[6:8], aaguid[8:10], aaguid[10:16])
	var duplicateIDs []string
	for _, existing := range user.Credentials() {
		if existing.AAGUID != nil && *existing.AAGUID == newAAGUID {
			duplicateIDs = append(duplicateIDs, existing.ID)
		}
	}

	if len(duplicateIDs) > 0 {
		// Store new credential temporarily in Redis, ask user to confirm replacement
		confirmToken := uuid.New().String()
		credJSON, _ := json.Marshal(credential)
		redisClient.Set(ctx, fmt.Sprintf("passkey_confirm:%s", confirmToken),
			fmt.Sprintf("%s|%s|%s", user.ID, r.UserAgent(), string(credJSON)),
			time.Minute*5)

		DeleteSession(registerSid)
		log.Printf("[INFO] duplicate authenticator detected, awaiting confirmation")
		JSONResponse(w, map[string]any{
			"status":        "duplicate",
			"confirm_token": confirmToken,
			"message":       "A passkey from the same authenticator already exists. Replace it?",
		}, http.StatusOK)
		return
	}

	user.AddCredential(credential, r.UserAgent())
	DeleteSession(registerSid)
	log.Printf("[INFO] finish registration ----------------------/")
	JSONResponse(w, map[string]any{"status": "ok", "message": "Registration Success"}, http.StatusOK)

	// SendMail(user.WebAuthnEmail(), "Welcome to Go Passkey", "Thank you for registering with Go Passkey!")
}

///////////////////////////////////
//                               //
//    ConfirmRegistration        //
//                               //
///////////////////////////////////

func ConfirmRegistration(w http.ResponseWriter, r *http.Request) {
	log.Printf("[INFO] confirm registration ----------------------\\")

	var req struct {
		ConfirmToken string `json:"confirm_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		JSONResponse(w, "Invalid request", http.StatusBadRequest)
		return
	}

	val, err := redisClient.Get(ctx, fmt.Sprintf("passkey_confirm:%s", req.ConfirmToken)).Result()
	if err != nil {
		JSONResponse(w, "Invalid or expired confirmation token", http.StatusBadRequest)
		return
	}

	// Parse: userID|userAgent|credentialJSON
	parts := strings.SplitN(val, "|", 3)
	if len(parts) != 3 {
		JSONResponse(w, "Invalid confirmation data", http.StatusBadRequest)
		return
	}

	userID, userAgent, credJSON := parts[0], parts[1], parts[2]

	user, err := GetUser(userID)
	if err != nil {
		log.Printf("[ERRO] can't get user: %s", err.Error())
		JSONResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	var credential webauthn.Credential
	if err := json.Unmarshal([]byte(credJSON), &credential); err != nil {
		log.Printf("[ERRO] can't unmarshal credential: %s", err.Error())
		JSONResponse(w, "Invalid credential data", http.StatusBadRequest)
		return
	}

	// Remove old credentials with the same AAGUID
	aaguid := credential.Authenticator.AAGUID
	newAAGUID := fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", aaguid[0:4], aaguid[4:6], aaguid[6:8], aaguid[8:10], aaguid[10:16])
	for _, existing := range user.Credentials() {
		if existing.AAGUID != nil && *existing.AAGUID == newAAGUID {
			user.RemoveCredential([]byte(existing.ID))
			log.Printf("[INFO] removed old credential %s (same authenticator)", existing.ID)
		}
	}

	user.AddCredential(&credential, userAgent)

	// Clean up confirmation token
	redisClient.Del(ctx, fmt.Sprintf("passkey_confirm:%s", req.ConfirmToken))

	log.Printf("[INFO] confirm registration ----------------------/")
	JSONResponse(w, map[string]any{"status": "ok", "message": "Passkey replaced"}, http.StatusOK)
}

//////////////////////
//                  //
//    BeginLogin    //
//                  //
//////////////////////

func BeginLogin(w http.ResponseWriter, r *http.Request) {
	log.Printf("[INFO] begin login ----------------------\\")

	u, err := getUserData(r)
	if err != nil {
		log.Printf("[ERRO]can't get user name: %s", err.Error())
		JSONResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	user, err := GetUserByEmail(u.Email) // Find the user
	if err != nil {
		log.Printf("[ERRO] can't get user: %s", err.Error())
		JSONResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	options, session, err := webAuthn.BeginLogin(user)
	if err != nil {
		msg := fmt.Sprintf("can't begin login: %s", err.Error())
		log.Printf("[ERRO] %s", msg)
		JSONResponse(w, msg, http.StatusBadRequest)
		return
	}

	// Make a session key and store the sessionData values
	sessionID := uuid.New().String()
	err = SaveSession(sessionID, session, time.Minute*5) // save session for 5 minutes
	if err != nil {
		log.Printf("[ERRO] can't save session: %s", err.Error())
		JSONResponse(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Add("Access-Control-Expose-Headers", "login_sid")
	w.Header().Set("login_sid", sessionID)

	JSONResponse(w, options, http.StatusOK) // return the options generated with the session key
	// options.publicKey contain our registration options
}

///////////////////////
//                   //
//    FinishLogin    //
//                   //
///////////////////////

func FinishLogin(w http.ResponseWriter, r *http.Request) {
	loginSid := r.Header.Get("login_sid")
	if loginSid == "" {
		log.Printf("[ERRO] missing login_sid header")
		JSONResponse(w, "missing login_sid header", http.StatusBadRequest)
		return
	}
	// Get the session data stored from the function above
	session, err := GetSession(loginSid)
	if err != nil {
		log.Printf("[ERRO] can't get session: %s", err.Error())
		JSONResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	// In out example username == userID, but in real world it should be different
	user, err := GetUser(string(session.UserID))
	if err != nil {
		log.Printf("[ERRO] can't get user: %s", err.Error())
		JSONResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	credential, err := webAuthn.FinishLogin(user, *session, r)
	if err != nil {
		log.Printf("[ERRO] can't finish login: %s", err.Error())
		JSONResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Handle credential.Authenticator.CloneWarning
	if credential.Authenticator.CloneWarning {
		log.Printf("[WARN] can't finish login: %s", "CloneWarning")
		JSONResponse(w, "CloneWarning", http.StatusBadRequest)
		return
	}

	// If login was successful, update the credential object
	user.UpdateCredential(credential)
	// SaveUser(user)

	// Delete the login session data
	DeleteSession(loginSid)

	/////////////////////////////////////////////////////////////////
	sessionID := uuid.New().String()
	SaveSession(sessionID, &webauthn.SessionData{
		UserID:  user.WebAuthnID(),
		Expires: time.Now().Add(time.Hour),
	}, time.Hour) // save session for 1 hour
	setSessionCookies(w, sessionID, time.Hour)
	/////////////////////////////////////////////////////////////////

	log.Printf("[INFO] finish login ----------------------/")
	JSONResponse(w, "Login Success", http.StatusOK)
}

//////////////////
//              //
//    Logout    //
//              //
//////////////////

func Logout(w http.ResponseWriter, r *http.Request) {
	sid := getSessionID(r)
	if sid == "" {
		log.Printf("[ERRO] can't get session id")
		JSONResponse(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	log.Println("Logging out session", sid)
	DeleteSession(sid)
	clearSessionCookies(w)
	JSONResponse(w, "Logout Success", http.StatusOK)
}

///////////////////
//               //
//    Private    //
//               //
///////////////////

func Private(w http.ResponseWriter, r *http.Request) {
	JSONResponse(w, "This is a private page", http.StatusOK)
}

///////////////////////
//                   //
//    Middlewares    //
//                   //
///////////////////////

func Auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// TODO: url to redirect to should be passed as a parameter

		if !strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/api/pub/") {
			next.ServeHTTP(w, r)
			return
		}

		sid := getSessionID(r)
		if sid == "" {
			JSONResponse(w, "Unauthorized", http.StatusUnauthorized)
			log.Println("[ERRO] can't get session id")
			return
		}

		session, err := GetSession(sid)
		if err != nil {
			JSONResponse(w, "Unauthorized", http.StatusUnauthorized)
			log.Println("[ERRO] can't get session")
			return
		}

		if session.Expires.Before(time.Now()) {
			JSONResponse(w, "Unauthorized", http.StatusUnauthorized)
			log.Println("[ERRO] session expired")
			return
		}

		next.ServeHTTP(w, r)
	})
}

func getSessionID(r *http.Request) string {
	cookie, err := r.Cookie("sid")
	if err != nil {
		return ""
	}
	return cookie.Value
}

func setSessionCookies(w http.ResponseWriter, sid string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     "sid",
		Value:    sid,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(ttl.Seconds()),
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "logged_in",
		Value:    "1",
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(ttl.Seconds()),
	})
}

func clearSessionCookies(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: "sid", MaxAge: -1, Path: "/"})
	http.SetCookie(w, &http.Cookie{Name: "logged_in", MaxAge: -1, Path: "/"})
}

// JSONResponse is a helper function to send json response
func JSONResponse(w http.ResponseWriter, data any, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

// getUserData is a helper function to extract the user data from json request
func getUserData(r *http.Request) (*PasskeyUser, error) {
	var u PasskeyUser
	if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
		return nil, err
	}
	return &u, nil
}

func CORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Access-Control-Allow-Origin", "*")
		w.Header().Add("Access-Control-Allow-Headers", "*")

		if r.Method == "OPTIONS" {
			w.Header().Set("Allow", "GET,POST,PUT,PATCH,DELETE,OPTIONS")
			return
		}

		next.ServeHTTP(w, r)
	})
}

//////////////
//          //
//    Me    //
//          //
//////////////

func Me(w http.ResponseWriter, r *http.Request) {
	sid := getSessionID(r)
	if sid == "" {
		log.Printf("[ERRO] can't get session id")
		JSONResponse(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	session, err := GetSession(sid)
	if err != nil {
		JSONResponse(w, "Unauthorized", http.StatusUnauthorized)
		log.Println("[ERRO] can't get session")
		return
	}

	if session.Expires.Before(time.Now()) {
		JSONResponse(w, "Unauthorized", http.StatusUnauthorized)
		log.Println("[ERRO] session expired")
		return
	}

	user, err := GetUser(string(session.UserID))
	if err != nil {
		log.Printf("[ERRO] can't get user: %s", err.Error())
		JSONResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	JSONResponse(w, user, http.StatusOK)
}
