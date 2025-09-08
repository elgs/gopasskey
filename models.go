package main

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/elgs/gosqlcrud"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
)

///////////////////////
//                   //
//    PasskeyUser    //
//                   //
///////////////////////

type PasskeyUser struct { // implements webauthn.User
	ID          []byte
	DB_ID       string    `json:"id" db:"id" pk:"true"`
	DisplayName string    `json:"display_name" db:"display_name"`
	Name        string    `json:"name" db:"name"`
	Email       string    `json:"email" db:"email"`
	Balance     float64   `json:"balance" db:"balance"`
	Created     time.Time `json:"created" db:"created"`
	Status      string    `json:"status" db:"status"`
	IsVerified  bool      `json:"is_verified" db:"is_verified"`
	IsActive    bool      `json:"is_active" db:"is_active"`
	IsDeleted   bool      `json:"is_deleted" db:"is_deleted"`
	creds       []webauthn.Credential
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
	return this.creds
}

func (this *PasskeyUser) AddCredential(credential *webauthn.Credential) {
	this.credsMutex.Lock()
	defer this.credsMutex.Unlock()
	this.creds = append(this.creds, *credential)
}

func (this *PasskeyUser) UpdateCredential(credential *webauthn.Credential) {
	this.credsMutex.Lock()
	defer this.credsMutex.Unlock()
	for i, c := range this.creds {
		if string(c.ID) == string(credential.ID) {
			this.creds[i] = *credential
		}
	}
}

func (this *PasskeyUser) RemoveCredential(credentialID []byte) {
	this.credsMutex.Lock()
	defer this.credsMutex.Unlock()
	for i, c := range this.creds {
		if string(c.ID) == string(credentialID) {
			this.creds = append(this.creds[:i], this.creds[i+1:]...)
			return
		}
	}
}

//////////////////////////////
//                          //
//    PasskeyUserSession    //
//                          //
//////////////////////////////

type PasskeyUserSession struct {
	ID      string          `json:"id" db:"id" pk:"true"`
	UserID  string          `json:"user_id" db:"user_id"`
	Session json.RawMessage `json:"session" db:"session"`
	Created time.Time       `json:"created" db:"created"`
}

/////////////////////////////////
//                             //
//    PasskeyUserCredential    //
//                             //
/////////////////////////////////

type PasskeyUserCredential struct {
	ID         string          `json:"id" db:"id" pk:"true"`
	UserID     string          `json:"user_id" db:"user_id"`
	Credential json.RawMessage `json:"credential" db:"credential"`
	Created    time.Time       `json:"created" db:"created"`
}

////////////////////////
//                    //
//    PasskeyStore    //
//                    //
////////////////////////

type PasskeyStore struct {
}

func NewPasskeyStore() *PasskeyStore {
	return &PasskeyStore{}
}

func (this *PasskeyStore) GetSession(sessionID string) (*webauthn.SessionData, error) {
	session := &PasskeyUserSession{
		ID: sessionID,
	}
	err := gosqlcrud.Retrieve(db, session, "user_session")
	if err != nil {
		return nil, err
	}

	if session.Session != nil {
		var data webauthn.SessionData
		err := json.Unmarshal(session.Session, &data)
		if err != nil {
			return nil, err
		}
		return &data, nil
	}
	return nil, fmt.Errorf("session not found")
}

func (this *PasskeyStore) SaveSession(sessionID string, data *webauthn.SessionData, userDBID string) error {
	sessionJSON, err := json.Marshal(data)
	if err != nil {
		return err
	}
	session := &PasskeyUserSession{
		ID:      sessionID,
		UserID:  userDBID,
		Session: sessionJSON,
		Created: time.Now(),
	}
	result, err := gosqlcrud.Create(db, session, "user_session")
	if err != nil {
		return err
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("no rows affected")
	}
	return nil
}

func (this *PasskeyStore) DeleteSession(sessionID string) error {
	session := &PasskeyUserSession{
		ID: sessionID,
	}
	result, err := gosqlcrud.Delete(db, session, "user_session")
	if err != nil {
		return err
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("no rows affected")
	}
	return nil
}

func (this *PasskeyStore) CreateUser(email, name, displayName string) (*PasskeyUser, error) {
	id := uuid.New().String()
	user := &PasskeyUser{
		ID:          []byte(id),
		DB_ID:       id,
		DisplayName: displayName,
		Name:        name,
		Email:       email,
		Balance:     0,
		Created:     time.Now(),
		Status:      "",
		IsVerified:  false,
		IsActive:    true,
		IsDeleted:   false,
	}
	result, err := gosqlcrud.Create(db, user, "user")
	if err != nil {
		return nil, err
	}
	if result.RowsAffected == 0 {
		return nil, fmt.Errorf("no rows affected")
	}
	return user, nil
}

func (this *PasskeyStore) GetUser(id []byte) (*PasskeyUser, error) {
	user := &PasskeyUser{
		DB_ID: string(id),
	}
	err := gosqlcrud.Retrieve(db, user, "user")
	if err != nil {
		return nil, err
	}
	user.ID = id
	return user, nil
}

func (this *PasskeyStore) GetUserByEmail(email string) (*PasskeyUser, error) {
	user := &PasskeyUser{
		Email: email,
	}
	err := gosqlcrud.Retrieve(db, user, "user")
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (this *PasskeyStore) SaveUser(user *PasskeyUser) error {
	result, err := gosqlcrud.Update(db, user, "user")
	if err != nil {
		return err
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("no rows affected")
	}
	return nil
}
