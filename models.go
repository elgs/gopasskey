package main

import (
	"log"

	"github.com/go-webauthn/webauthn/webauthn"
)

///////////////////////
//                   //
//    PasskeyUser    //
//                   //
///////////////////////

type PasskeyUser interface {
	webauthn.User
	AddCredential(*webauthn.Credential)
	UpdateCredential(*webauthn.Credential)
}

type User struct {
	ID          []byte
	DisplayName string
	Name        string

	creds []webauthn.Credential
}

func (this *User) WebAuthnID() []byte {
	return this.ID
}

func (this *User) WebAuthnName() string {
	return this.Name
}

func (this *User) WebAuthnDisplayName() string {
	return this.DisplayName
}

func (this *User) WebAuthnIcon() string {
	return "https://pics.com/avatar.png"
}

func (this *User) WebAuthnCredentials() []webauthn.Credential {
	return this.creds
}

func (this *User) AddCredential(credential *webauthn.Credential) {
	this.creds = append(this.creds, *credential)
}

func (this *User) UpdateCredential(credential *webauthn.Credential) {
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

type PasskeyStore interface {
	GetOrCreateUser(username string) PasskeyUser
	SaveUser(PasskeyUser)
	GetSession(token string) (*webauthn.SessionData, bool)
	SaveSession(token string, data *webauthn.SessionData)
	DeleteSession(token string)
}

type InMem struct {
	// TODO: it would be nice to have a mutex here
	users    map[string]PasskeyUser
	sessions map[string]*webauthn.SessionData
}

func NewInMem() *InMem {
	return &InMem{
		users:    make(map[string]PasskeyUser),
		sessions: make(map[string]*webauthn.SessionData),
	}
}

func (this *InMem) GetSession(token string) (*webauthn.SessionData, bool) {
	log.Printf("[DEBUG] GetSession: %v", this.sessions[token])
	val, ok := this.sessions[token]

	return val, ok
}

func (this *InMem) SaveSession(token string, data *webauthn.SessionData) {
	log.Printf("[DEBUG] SaveSession: %s - %v", token, data)
	this.sessions[token] = data
}

func (this *InMem) DeleteSession(token string) {
	log.Printf("[DEBUG] DeleteSession: %v", token)
	delete(this.sessions, token)
}

func (this *InMem) GetOrCreateUser(username string) PasskeyUser {
	log.Printf("[DEBUG] GetOrCreateUser: %v", username)
	if _, ok := this.users[username]; !ok {
		log.Printf("[DEBUG] GetOrCreateUser: creating new user: %v", username)
		this.users[username] = &User{
			ID:          []byte(username),
			DisplayName: username,
			Name:        username,
		}
	}

	return this.users[username]
}

func (this *InMem) SaveUser(user PasskeyUser) {
	log.Printf("[DEBUG] SaveUser: %v", user.WebAuthnName())
	// log.Printf("[DEBUG] SaveUser: %v", user)
	this.users[user.WebAuthnName()] = user
}
