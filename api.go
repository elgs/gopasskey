package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

/////////////////////////////
//                         //
//    BeginRegistration    //
//                         //
/////////////////////////////

func BeginRegistration(w http.ResponseWriter, r *http.Request) {
	log.Printf("[INFO] begin registration ----------------------\\")
	username, err := getUsername(r)
	if err != nil {
		log.Printf("[ERRO] can't get user name: %s", err.Error())
		JSONResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	user := passkeyStore.GetOrCreateUser(username)

	options, session, err := webAuthn.BeginRegistration(user)
	if err != nil {
		msg := fmt.Sprintf("can't begin registration: %s", err.Error())
		log.Printf("[ERRO] %s", msg)
		JSONResponse(w, msg, http.StatusBadRequest)
		return
	}

	sessionID := GenSessionID()
	passkeyStore.SaveSession(sessionID, session)
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
	sid := r.Header.Get("register_sid")
	if sid == "" {
		log.Printf("[ERRO] can't get session id: %s", err.Error())
		JSONResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Get the session data stored from the function above
	session := passkeyStore.GetSession(sid)

	// In out example username == userID, but in real world it should be different
	user := passkeyStore.GetOrCreateUser(string(session.UserID))

	credential, err := webAuthn.FinishRegistration(user, *session, r)
	if err != nil {
		msg := fmt.Sprintf("can't finish registration: %s", err.Error())
		log.Printf("[ERRO] %s", msg)
		JSONResponse(w, msg, http.StatusBadRequest)
		return
	}

	user.AddCredential(credential)
	passkeyStore.SaveUser(user)
	passkeyStore.DeleteSession(sid)
	log.Printf("[INFO] finish registration ----------------------/")
	JSONResponse(w, "Registration Success", http.StatusOK) // Handle next steps
}

//////////////////////
//                  //
//    BeginLogin    //
//                  //
//////////////////////

func BeginLogin(w http.ResponseWriter, r *http.Request) {
	log.Printf("[INFO] begin login ----------------------\\")

	username, err := getUsername(r)
	if err != nil {
		log.Printf("[ERRO]can't get user name: %s", err.Error())
		JSONResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	user := passkeyStore.GetOrCreateUser(username) // Find the user

	options, session, err := webAuthn.BeginLogin(user)
	if err != nil {
		msg := fmt.Sprintf("can't begin login: %s", err.Error())
		log.Printf("[ERRO] %s", msg)
		JSONResponse(w, msg, http.StatusBadRequest)
		return
	}

	// Make a session key and store the sessionData values
	sessionID := GenSessionID()
	passkeyStore.SaveSession(sessionID, session)
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
	sid := r.Header.Get("login_sid")
	if sid == "" {
		log.Printf("[ERRO] can't get session id: %s", err.Error())
		JSONResponse(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Get the session data stored from the function above
	session := passkeyStore.GetSession(sid)

	// In out example username == userID, but in real world it should be different
	user := passkeyStore.GetOrCreateUser(string(session.UserID)) // Get the user

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
	user.UpdateCredential(credential)
	passkeyStore.SaveUser(user)

	// Delete the login session data
	passkeyStore.DeleteSession(sid)
	sessionID := GenSessionID()

	passkeyStore.SaveSession(sessionID, &webauthn.SessionData{
		Expires: time.Now().Add(time.Hour),
	})

	w.Header().Set("sid", sessionID)

	log.Printf("[INFO] finish login ----------------------/")
	JSONResponse(w, "Login Success", http.StatusOK)
}

//////////////////
//              //
//    logout    //
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
	passkeyStore.DeleteSession(sid)
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

		session := passkeyStore.GetSession(sid)
		if session == nil {
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

// getUsername is a helper function to extract the username from json request
func getUsername(r *http.Request) (string, error) {
	type Username struct {
		Username string `json:"username"`
	}
	var u Username
	if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
		return "", err
	}

	return u.Username, nil
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
