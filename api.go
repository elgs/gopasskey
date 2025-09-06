package main

import (
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

	user := datastore.GetOrCreateUser(username)

	options, session, err := webAuthn.BeginRegistration(user)
	if err != nil {
		msg := fmt.Sprintf("can't begin registration: %s", err.Error())
		log.Printf("[ERRO] %s", msg)
		JSONResponse(w, msg, http.StatusBadRequest)
		return
	}

	sessionID := GenSessionID()
	datastore.SaveSession(sessionID, session)
	http.SetCookie(w, &http.Cookie{
		Name:     "sid",
		Value:    sessionID,
		Path:     "/api/passkey/registerFinish",
		MaxAge:   3600,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
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
	// Get the session key from cookie
	sid, err := r.Cookie("sid")
	if err != nil {
		log.Printf("[ERRO] can't get session id: %s", err.Error())
		JSONResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Get the session data stored from the function above
	session := datastore.GetSession(sid.Value)

	// In out example username == userID, but in real world it should be different
	user := datastore.GetOrCreateUser(string(session.UserID))

	credential, err := webAuthn.FinishRegistration(user, *session, r)
	if err != nil {
		msg := fmt.Sprintf("can't finish registration: %s", err.Error())
		log.Printf("[ERRO] %s", msg)
		// clean up sid cookie
		http.SetCookie(w, &http.Cookie{
			Name:  "sid",
			Value: "",
		})
		JSONResponse(w, msg, http.StatusBadRequest)

		return
	}

	user.AddCredential(credential)
	datastore.SaveUser(user)
	datastore.DeleteSession(sid.Value)
	http.SetCookie(w, &http.Cookie{
		Name:  "sid",
		Value: "",
	})

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

	user := datastore.GetOrCreateUser(username) // Find the user

	options, session, err := webAuthn.BeginLogin(user)
	if err != nil {
		msg := fmt.Sprintf("can't begin login: %s", err.Error())
		log.Printf("[ERRO] %s", msg)
		JSONResponse(w, msg, http.StatusBadRequest)
		return
	}

	// Make a session key and store the sessionData values
	sessionID := GenSessionID()
	datastore.SaveSession(sessionID, session)
	http.SetCookie(w, &http.Cookie{
		Name:     "sid",
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
	// Get the session key from cookie
	sid, err := r.Cookie("sid")
	if err != nil {
		log.Printf("[ERRO] can't get session id: %s", err.Error())
		JSONResponse(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Get the session data stored from the function above
	session := datastore.GetSession(sid.Value)

	// In out example username == userID, but in real world it should be different
	user := datastore.GetOrCreateUser(string(session.UserID)) // Get the user

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
	datastore.SaveUser(user)

	// Delete the login session data
	datastore.DeleteSession(sid.Value)
	http.SetCookie(w, &http.Cookie{
		Name:  "sid",
		Value: "",
	})

	// Add the new session cookie
	sessionID := GenSessionID()

	datastore.SaveSession(sessionID, &webauthn.SessionData{
		Expires: time.Now().Add(time.Hour),
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "sid",
		Value:    sessionID,
		Path:     "/",
		MaxAge:   3600,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode, // TODO: SameSiteStrictMode maybe?
	})

	log.Printf("[INFO] finish login ----------------------/")
	JSONResponse(w, "Login Success", http.StatusOK)
}

// logout

func Logout(w http.ResponseWriter, r *http.Request) {
	sid, err := r.Cookie("sid")
	if err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	datastore.DeleteSession(sid.Value)
	http.SetCookie(w, &http.Cookie{
		Name:  "sid",
		Value: "",
	})

	http.Redirect(w, r, "/", http.StatusSeeOther)
}
