package main

import (
	"github.com/go-webauthn/webauthn/webauthn"
)

///////////////////////
//                   //
//    PasskeyUser    //
//                   //
///////////////////////

type PasskeyUser struct { // implements webauthn.User
	ID          []byte
	DisplayName string
	Name        string
	Email       string
	creds       []webauthn.Credential
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

func (this *PasskeyUser) WebAuthnIcon() string {
	return "https://pics.com/avatar.png"
}

func (this *PasskeyUser) WebAuthnCredentials() []webauthn.Credential {
	return this.creds
}

func (this *PasskeyUser) AddCredential(credential *webauthn.Credential) {
	this.creds = append(this.creds, *credential)
}

func (this *PasskeyUser) UpdateCredential(credential *webauthn.Credential) {
	for i, c := range this.creds {
		if string(c.ID) == string(credential.ID) {
			this.creds[i] = *credential
		}
	}
}

////////////////////////
//                    //
//    PasskeyStore    //
//                    //
////////////////////////

type PasskeyStore struct {
	// TODO: it would be nice to have a mutex here
	users    map[string]*PasskeyUser
	sessions map[string]*webauthn.SessionData
}

func NewInMem() *PasskeyStore {
	return &PasskeyStore{
		users:    make(map[string]*PasskeyUser),
		sessions: make(map[string]*webauthn.SessionData),
	}
}

func (this *PasskeyStore) GetSession(sessionID string) *webauthn.SessionData {
	return this.sessions[sessionID]
}

func (this *PasskeyStore) SaveSession(sessionID string, data *webauthn.SessionData) {
	this.sessions[sessionID] = data
}

func (this *PasskeyStore) DeleteSession(sessionID string) {
	delete(this.sessions, sessionID)
}

func (this *PasskeyStore) GetOrCreateUser(username string) *PasskeyUser {
	user := this.users[username]
	if user == nil {
		user = &PasskeyUser{
			ID:          []byte(username),
			DisplayName: username,
			Name:        username,
		}
		this.users[username] = user
	}
	return user
}

func (this *PasskeyStore) SaveUser(user *PasskeyUser) {
	this.users[user.WebAuthnName()] = user
}
