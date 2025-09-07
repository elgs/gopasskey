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
	http.SetCookie(w, &http.Cookie{
		Name:     "register_sid",
		Value:    sessionID,
		Path:     "/api/passkey/registerFinish",
		MaxAge:   3600,
		Secure:   true,
		HttpOnly: true,
	})

	JSONResponse(w, options, http.StatusOK) // return the options generated with the session key
	// options.publicKey contain our registration options
}

//////////////////////////////
//                          //
//    FinishRegistration    //
//                          //
//////////////////////////////

func FinishRegistration(w http.ResponseWriter, r *http.Request) {
	// defer delete register_sid cookie
	defer func() {
		http.SetCookie(w, &http.Cookie{
			Name:     "register_sid",
			Value:    "",
			Path:     "/api/passkey/registerFinish",
			MaxAge:   -1,
			Secure:   true,
			HttpOnly: true,
		})
	}()
	// Get the session key from cookie
	sid, err := r.Cookie("register_sid")
	if err != nil {
		log.Printf("[ERRO] can't get session id: %s", err.Error())
		JSONResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Get the session data stored from the function above
	session := passkeyStore.GetSession(sid.Value)

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
	passkeyStore.DeleteSession(sid.Value)
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
	http.SetCookie(w, &http.Cookie{
		Name:     "login_sid",
		Value:    sessionID,
		Path:     "/api/passkey/loginFinish",
		MaxAge:   3600,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	JSONResponse(w, options, http.StatusOK) // return the options generated with the session key
	// options.publicKey contain our registration options
}

///////////////////////
//                   //
//    FinishLogin    //
//                   //
///////////////////////

func FinishLogin(w http.ResponseWriter, r *http.Request) {
	defer func() {
		http.SetCookie(w, &http.Cookie{
			Name:     "login_sid",
			Value:    "",
			Path:     "/api/passkey/loginFinish",
			MaxAge:   -1,
			Secure:   true,
			HttpOnly: true,
		})
	}()
	// Get the session key from cookie
	sid, err := r.Cookie("login_sid")
	if err != nil {
		log.Printf("[ERRO] can't get session id: %s", err.Error())
		JSONResponse(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Get the session data stored from the function above
	session := passkeyStore.GetSession(sid.Value)

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
	passkeyStore.DeleteSession(sid.Value)
	// Add the new session cookie
	sessionID := GenSessionID()

	passkeyStore.SaveSession(sessionID, &webauthn.SessionData{
		Expires: time.Now().Add(time.Hour),
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "sid",
		Value:    sessionID,
		Path:     "/",
		MaxAge:   3600,
		Secure:   true,
		HttpOnly: true,
	})
	log.Println(sid, session)

	log.Printf("[INFO] finish login ----------------------/")
	JSONResponse(w, "Login Success", http.StatusOK)
}

//////////////////
//              //
//    logout    //
//              //
//////////////////

func Logout(w http.ResponseWriter, r *http.Request) {
	sid, err := r.Cookie("sid")
	if err != nil {
		log.Printf("[ERRO] can't get session id: %s", err.Error())
		JSONResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	log.Println("Logging out session", sid)
	passkeyStore.DeleteSession(sid.Value)
	http.SetCookie(w, &http.Cookie{
		Name:     "sid",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
	})

	JSONResponse(w, "Logout Success", http.StatusOK)
}

func LoggedInMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// TODO: url to redirect to should be passed as a parameter

		sid, err := r.Cookie("sid")
		if err != nil {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			log.Println("[ERRO] can't get session id")
			return
		}

		session := passkeyStore.GetSession(sid.Value)
		if session == nil {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			log.Println("[ERRO] can't get session")
			return
		}

		if session.Expires.Before(time.Now()) {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			log.Println("[ERRO] session expired")
			return
		}
		log.Println(sid, session)

		next.ServeHTTP(w, r)
	})
}

func PrivatePage(w http.ResponseWriter, r *http.Request) {
	// just show "Hello, World!" for now
	_, _ = w.Write([]byte("Hello, World!"))
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
