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
		webAuthnCreds = append(webAuthnCreds, c.Credential)
	}
	return webAuthnCreds
}

func (this *PasskeyUser) AddCredential(credential *webauthn.Credential, label string) {
	now := time.Now()
	cred := &PasskeyUserCredential{
		ID:         fmt.Sprintf("%x", credential.ID),
		UserID:     this.DB_ID,
		Label:      label,
		Credential: *credential,
		Created:    &now,
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

func (this *PasskeyUser) UpdateCredential(credential *webauthn.Credential, label string) {
	now := time.Now()
	cred := &PasskeyUserCredential{
		ID:         fmt.Sprintf("%x", credential.ID),
		UserID:     this.DB_ID,
		Label:      label,
		Credential: *credential,
		Updated:    &now,
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

type Req struct {
	Email string `json:"email"`
	Code  string `json:"code"`
}

/////////////////////////////////
//                             //
//    PasskeyUserCredential    //
//                             //
/////////////////////////////////

type PasskeyUserCredential struct {
	ID         string              `json:"id" db:"id" pk:"true"`
	UserID     string              `json:"user_id" db:"user_id"`
	Label      string              `json:"label" db:"label"`
	Credential webauthn.Credential `json:"credential" db:"credential"`
	Created    *time.Time          `json:"created" db:"created"`
	Updated    *time.Time          `json:"updated" db:"updated"`
}

////////////////////////
//                    //
//    PasskeyStore    //
//                    //
////////////////////////

func GetSession(sessionID string) (*webauthn.SessionData, error) {
	val, err := redisClient.Get(ctx, fmt.Sprintf("passkey_session:%s", sessionID)).Result()
	if err != nil {
		return nil, err
	}

	if val != "" {
		var data webauthn.SessionData
		err := json.Unmarshal([]byte(val), &data)
		if err != nil {
			return nil, err
		}
		return &data, nil
	}
	return nil, fmt.Errorf("session not found")
}

func SaveSession(sessionID string, data *webauthn.SessionData, userDBID string, ttl time.Duration) error {
	dataJSON, err := json.Marshal(data)
	if err != nil {
		return err
	}
	val, err := redisClient.Set(ctx, fmt.Sprintf("passkey_session:%s", sessionID), dataJSON, ttl).Result()
	if err != nil {
		return err
	}
	log.Printf("Save session result: %s", val)
	return nil
}

func DeleteSession(sessionID string) error {
	val, err := redisClient.Del(ctx, fmt.Sprintf("passkey_session:%s", sessionID)).Result()
	if err != nil {
		return err
	}
	log.Printf("Delete session result: %d", val)
	return nil
}

func CreateUser(email, name, displayName string) (*PasskeyUser, error) {
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

func GetUser(id []byte) (*PasskeyUser, error) {
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

func GetUserByEmail(email string) (*PasskeyUser, error) {
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

func SaveUser(user *PasskeyUser) error {
	result, err := gosqlcrud.Update(db, user, "user")
	if err != nil {
		return err
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("no rows affected")
	}
	return nil
}
