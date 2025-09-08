package main

import (
	"encoding/json"
	"fmt"
	"log"
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
	creds := []PasskeyUserCredential{}
	err := gosqlcrud.QueryToStructs(db, &creds, "SELECT * FROM user_credential WHERE user_id = ?", this.DB_ID)
	if err != nil {
		log.Printf("Error retrieving credentials: %s", err.Error())
		return nil
	}

	var webAuthnCreds []webauthn.Credential
	for _, c := range creds {
		var credential webauthn.Credential
		err := json.Unmarshal(c.Credential, &credential)
		if err != nil {
			log.Printf("Error unmarshaling credential: %s", err.Error())
			return nil
		}
		webAuthnCreds = append(webAuthnCreds, credential)
	}
	return webAuthnCreds
}

func (this *PasskeyUser) AddCredential(credential *webauthn.Credential) {
	credJSON, err := json.Marshal(credential)
	if err != nil {
		log.Printf("Error marshaling credential: %s", err.Error())
		return
	}
	cred := &PasskeyUserCredential{
		ID:         fmt.Sprintf("%x", credential.ID),
		UserID:     this.DB_ID,
		Credential: credJSON,
		Created:    time.Now(),
	}
	result, err := gosqlcrud.Create(db, cred, "user_credential")
	if err != nil {
		log.Printf("Error adding credential: %s", err.Error())
		return
	}
	if result.RowsAffected == 0 {
		log.Printf("Error adding credential: no rows affected")
	}
}

func (this *PasskeyUser) UpdateCredential(credential *webauthn.Credential) {
	credJSON, err := json.Marshal(credential)
	if err != nil {
		log.Printf("Error marshaling credential: %s", err.Error())
		return
	}
	cred := &PasskeyUserCredential{
		ID:         fmt.Sprintf("%x", credential.ID),
		UserID:     this.DB_ID,
		Credential: credJSON,
		Updated:    time.Now(),
	}
	result, err := gosqlcrud.Update(db, cred, "user_credential")
	if err != nil {
		log.Printf("Error updating credential: %s", err.Error())
		return
	}
	if result.RowsAffected == 0 {
		log.Printf("Error updating credential: no rows affected")
	}
}

func (this *PasskeyUser) RemoveCredential(credentialID []byte) {
	result, err := gosqlcrud.Delete(db, &PasskeyUserCredential{
		ID: string(credentialID),
	}, "user_credential")
	if err != nil {
		log.Printf("Error removing credential: %s", err.Error())
		return
	}
	if result.RowsAffected == 0 {
		log.Printf("Error removing credential: no rows affected")
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
	Updated    time.Time       `json:"updated" db:"updated"`
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
	log.Printf("Getting user with ID: %s", string(id))
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
	users := []PasskeyUser{}
	err := gosqlcrud.QueryToStructs(db, &users, "SELECT * FROM user WHERE email = ?", email)
	if err != nil {
		log.Printf("Error looking up user by email: %s", err.Error())
		return nil, err
	}
	if len(users) > 0 {
		user := &users[0]
		user.ID = []byte(user.DB_ID)
		return user, nil
	}
	return nil, fmt.Errorf("user not found")
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
