package main

import (
	"sync"

	"github.com/go-webauthn/webauthn/webauthn"
)

///////////////////////
//                   //
//    PasskeyUser    //
//                   //
///////////////////////

type PasskeyUser struct { // implements webauthn.User
	ID          []byte                `json:"id"` // must be set to a unique value for each user
	DisplayName string                `json:"display_name"`
	Name        string                `json:"name"`
	Email       string                `json:"email"`
	Creds       []webauthn.Credential `json:"credentials"`
	credsMutex  sync.RWMutex
}

func (this *PasskeyUser) WebAuthnID() []byte {
	return this.ID
}

func (this *PasskeyUser) WebAuthnName() string {
	return this.Name
}

func (this *PasskeyUser) WebAuthnEmail() string {
	return this.Email
}

func (this *PasskeyUser) WebAuthnDisplayName() string {
	return this.DisplayName
}

func (this *PasskeyUser) WebAuthnCredentials() []webauthn.Credential {
	this.credsMutex.RLock()
	defer this.credsMutex.RUnlock()
	return this.Creds
}

func (this *PasskeyUser) AddCredential(credential *webauthn.Credential) {
	this.credsMutex.Lock()
	defer this.credsMutex.Unlock()
	this.Creds = append(this.Creds, *credential)
}

func (this *PasskeyUser) UpdateCredential(credential *webauthn.Credential) {
	this.credsMutex.Lock()
	defer this.credsMutex.Unlock()
	for i, c := range this.Creds {
		if string(c.ID) == string(credential.ID) {
			this.Creds[i] = *credential
		}
	}
}

func (this *PasskeyUser) RemoveCredential(credentialID []byte) {
	this.credsMutex.Lock()
	defer this.credsMutex.Unlock()
	for i, c := range this.Creds {
		if string(c.ID) == string(credentialID) {
			this.Creds = append(this.Creds[:i], this.Creds[i+1:]...)
			return
		}
	}
}

////////////////////////
//                    //
//    PasskeyStore    //
//                    //
////////////////////////

type PasskeyStore struct {
	users    sync.Map
	sessions sync.Map
}

func New() *PasskeyStore {
	return &PasskeyStore{
		users:    sync.Map{},
		sessions: sync.Map{},
	}
}

func (this *PasskeyStore) GetSession(sessionID string) *webauthn.SessionData {
	if v, ok := this.sessions.Load(sessionID); ok {
		if session, ok := v.(*webauthn.SessionData); ok {
			return session
		}
	}
	return nil
}

func (this *PasskeyStore) SaveSession(sessionID string, data *webauthn.SessionData) {
	this.sessions.Store(sessionID, data)
}

func (this *PasskeyStore) DeleteSession(sessionID string) {
	this.sessions.Delete(sessionID)
}

func (this *PasskeyStore) GetOrCreateUser(username string) *PasskeyUser {
	if v, ok := this.users.Load(username); ok {
		if user, ok := v.(*PasskeyUser); ok {
			return user
		}
	}
	user := &PasskeyUser{
		ID:          []byte(username),
		DisplayName: username,
		Name:        username,
	}
	this.users.Store(username, user)
	return user
}

func (this *PasskeyStore) SaveUser(user *PasskeyUser) {
	this.users.Store(user.WebAuthnName(), user)
}
