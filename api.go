package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/elgs/gosqlcrud"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
)

// GetUserCredentials returns credential IDs for a user as base64url strings
func GetUserCredentials(w http.ResponseWriter, r *http.Request) {
	req := &Req{}
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		JSONResponse(w, "Invalid request", http.StatusBadRequest)
		return
	}
	user, err := GetUserByEmail(req.Email)
	if err != nil {
		JSONResponse(w, "User not found", http.StatusNotFound)
		return
	}
	creds := user.Credentials()
	var credentialIds []string
	for _, cred := range creds {
		credentialIds = append(credentialIds, cred.Label)
	}
	JSONResponse(w, map[string]any{"credentialIds": credentialIds}, http.StatusOK)
}

///////////////////////
//                   //
//    BeginSignup    //
//                   //
///////////////////////

func BeginSignup(w http.ResponseWriter, r *http.Request) {
	log.Printf("[INFO] begin sign up ----------------------\\")
	u, err := getUserData(r)
	if err != nil {
		log.Printf("[ERRO] can't get user name: %s", err.Error())
		JSONResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Check if user already exists
	existingUser, err := GetUserByEmail(u.Email)
	if err == nil && existingUser != nil {
		msg := fmt.Sprintf("user with email %s already exists", u.Email)
		log.Printf("[ERRO] %s", msg)
		JSONResponse(w, msg, http.StatusBadRequest)
		return
	}

	// create a random verification code, and together with the user data, save it in redis with a 10 minute expiration, and send the code to the user's email
	verificationCode := uuid.New().String()
	redisClient.Set(ctx, fmt.Sprintf("passkey_signup_code:%s", verificationCode), fmt.Sprintf("%s|%s|%s", u.Email, u.Name, u.DisplayName), time.Minute*10)

	// Log the verification code to the console (for testing purposes only)
	log.Printf("[INFO] verification code: %s", verificationCode)

	// Send the verification code to the user's email
	err = SendMail(u.Email, "Your verification code", fmt.Sprintf("Your verification code is: %s", verificationCode))
	if err != nil {
		log.Printf("[ERRO] can't send verification email: %s", err.Error())
		JSONResponse(w, err.Error(), http.StatusBadRequest)
		return
	}
	JSONResponse(w, "Verification code sent to email", http.StatusOK)

}

////////////////////////
//                    //
//    FinishSignup    //
//                    //
////////////////////////

func FinishSignup(w http.ResponseWriter, r *http.Request) {
	req := &Req{}
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		JSONResponse(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Check if the verification code is valid
	val, err := redisClient.Get(ctx, fmt.Sprintf("passkey_signup_code:%s", req.Code)).Result()
	if err != nil {
		JSONResponse(w, "Invalid or expired verification code", http.StatusBadRequest)
		return
	}

	// Parse the user data from the Redis value
	parts := strings.Split(val, "|")
	if len(parts) != 3 {
		JSONResponse(w, "Invalid verification code data", http.StatusBadRequest)
		return
	}
	u := &PasskeyUser{
		Email:       parts[0],
		Name:        parts[1],
		DisplayName: parts[2],
	}

	if u.Email != req.Email {
		JSONResponse(w, "Invalid or expired verification code", http.StatusBadRequest)
		return
	}

	_, err = CreateUser(u.Email, u.Name, u.DisplayName)
	if err != nil {
		msg := fmt.Sprintf("can't create user: %s", err.Error())
		log.Printf("[ERRO] %s", msg)
		JSONResponse(w, msg, http.StatusBadRequest)
		return
	}

	// Delete the signup code
	redisClient.Del(ctx, fmt.Sprintf("passkey_signup_code:%s", req.Code))

	JSONResponse(w, "Signup successful", http.StatusOK)

	log.Printf("[INFO] finish sign up ----------------------/")
}

//////////////////////////////
//                          //
//    BeginLoginWithCode    //
//                          //
//////////////////////////////

func BeginLoginWithCode(w http.ResponseWriter, r *http.Request) {
	log.Printf("[INFO] begin login with code ----------------------\\")

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

	// create a random verification code, and together with the user data, save it in redis with a 10 minute expiration, and send the code to the user's email
	verificationCode := uuid.New().String()
	redisClient.Set(ctx, fmt.Sprintf("passkey_login_code:%s", verificationCode), user.DB_ID, time.Minute*10)

	// Log the verification code to the console (for testing purposes only)
	log.Printf("[INFO] login verification code: %s", verificationCode)

	// Send the verification code to the user's email
	err = SendMail(u.Email, "Your login verification code", fmt.Sprintf("Your login verification code is: %s", verificationCode))
	if err != nil {
		log.Printf("[ERRO] can't send verification email: %s", err.Error())
		JSONResponse(w, err.Error(), http.StatusBadRequest)
		return
	}
	JSONResponse(w, "Login verification code sent to email", http.StatusOK) // return the options generated with the session key
	// options.publicKey contain our registration options
}

///////////////////////////////
//                           //
//    FinishLoginWithCode    //
//                           //
///////////////////////////////

func FinishLoginWithCode(w http.ResponseWriter, r *http.Request) {
	req := &Req{}
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		JSONResponse(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Check if the verification code is valid
	userDBID, err := redisClient.Get(ctx, fmt.Sprintf("passkey_login_code:%s", req.Code)).Result()
	if err != nil {
		JSONResponse(w, "Invalid or expired verification code", http.StatusBadRequest)
		return
	}

	user, err := GetUser([]byte(userDBID))
	if err != nil {
		log.Printf("[ERRO] can't get user: %s", err.Error())
		JSONResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	if user.Email != req.Email {
		JSONResponse(w, "Invalid or expired verification code", http.StatusBadRequest)
		return
	}

	// create a session for the user
	sessionID := uuid.New().String()
	SaveSession(sessionID, &webauthn.SessionData{
		Expires: time.Now().Add(time.Hour),
	}, user.DB_ID, time.Hour) // save session for 1 hour
	w.Header().Set("sid", sessionID)

	// Delete the login code
	redisClient.Del(ctx, fmt.Sprintf("passkey_login_code:%s", req.Code))

	JSONResponse(w, "Login successful", http.StatusOK)

	log.Printf("[INFO] finish login with code ----------------------/")
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
	err = SaveSession(sessionID, session, user.DB_ID, time.Minute*5) // save session for 5 minutes
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
		log.Printf("[ERRO] can't get session id: %s", err.Error())
		JSONResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	session, err := GetSession(registerSid)
	if err != nil {
		log.Printf("[ERRO] can't get session: %s", err.Error())
		JSONResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	user, err := GetUser(session.UserID)
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

	user.AddCredential(credential, r.UserAgent())
	// SaveUser(user)
	DeleteSession(registerSid)
	log.Printf("[INFO] finish registration ----------------------/")
	JSONResponse(w, "Registration Success", http.StatusOK) // Handle next steps

	gosqlcrud.Create(db, user, "user")

	// SendMail(user.WebAuthnEmail(), "Welcome to Go Passkey", "Thank you for registering with Go Passkey!")
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
	SaveSession(sessionID, session, user.DB_ID, time.Minute*5) // save session for 5 minutes
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
		log.Printf("[ERRO] can't get session id: %s", err.Error())
		JSONResponse(w, err.Error(), http.StatusBadRequest)
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
	user, err := GetUser(session.UserID)
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
	}

	// If login was successful, update the credential object
	user.UpdateCredential(credential, r.UserAgent())
	// SaveUser(user)

	// Delete the login session data
	DeleteSession(loginSid)

	/////////////////////////////////////////////////////////////////
	sessionID := uuid.New().String()
	SaveSession(sessionID, &webauthn.SessionData{
		Expires: time.Now().Add(time.Hour),
	}, user.DB_ID, time.Hour) // save session for 1 hour
	w.Header().Set("sid", sessionID)
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
	sid := r.Header.Get("sid")
	if sid == "" {
		log.Printf("[ERRO] can't get session id")
		JSONResponse(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	log.Println("Logging out session", sid)
	DeleteSession(sid)
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

func LoggedInMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// TODO: url to redirect to should be passed as a parameter

		sid := r.Header.Get("sid")
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
	}
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

func CORS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Access-Control-Allow-Origin", "*")
		w.Header().Add("Access-Control-Allow-Headers", "*")
		w.Header().Add("Access-Control-Expose-Headers", "sid")
		// w.Header().Add("Access-Control-Allow-Credentials", "true")

		if r.Method == "OPTIONS" {
			w.Header().Set("Allow", "GET,POST,PUT,PATCH,DELETE,OPTIONS")
			return
		}

		next(w, r)
	}
}

//////////////
//          //
//    Me    //
//          //
//////////////

func Me(w http.ResponseWriter, r *http.Request) {
	sid := r.Header.Get("sid")
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

	user, err := GetUser(session.UserID)
	if err != nil {
		log.Printf("[ERRO] can't get user: %s", err.Error())
		JSONResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	JSONResponse(w, user, http.StatusOK)
}
