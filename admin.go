package main

import (
	"encoding/json"
	"net/http"
)

// requireAdmin returns the current user if they are an admin, else writes 401/403 and returns nil.
func requireAdmin(w http.ResponseWriter, r *http.Request) *PasskeyUser {
	sid := getSessionID(r)
	session, err := GetSession(sid)
	if err != nil {
		JSONResponse(w, "Unauthorized", http.StatusUnauthorized)
		return nil
	}
	user, err := GetUser(string(session.UserID))
	if err != nil {
		JSONResponse(w, "User not found", http.StatusUnauthorized)
		return nil
	}
	if !user.IsAdmin {
		JSONResponse(w, "Forbidden", http.StatusForbidden)
		return nil
	}
	return user
}

/////////////////////////////
//                         //
//    SSO Client Admin     //
//                         //
/////////////////////////////

func AdminListClients(w http.ResponseWriter, r *http.Request) {
	if requireAdmin(w, r) == nil {
		return
	}
	clients, err := GetAllSSOClients()
	if err != nil {
		JSONResponse(w, "Failed to list clients", http.StatusInternalServerError)
		return
	}
	JSONResponse(w, clients, http.StatusOK)
}

func AdminCreateClient(w http.ResponseWriter, r *http.Request) {
	if requireAdmin(w, r) == nil {
		return
	}
	var client SSOClient
	if err := json.NewDecoder(r.Body).Decode(&client); err != nil {
		JSONResponse(w, "Invalid request", http.StatusBadRequest)
		return
	}
	if client.ID == "" || client.ClientSecret == "" || client.RedirectURI == "" {
		JSONResponse(w, "id, client_secret, and redirect_uri are required", http.StatusBadRequest)
		return
	}
	if err := CreateSSOClient(&client); err != nil {
		JSONResponse(w, "Failed to create client: "+err.Error(), http.StatusInternalServerError)
		return
	}
	JSONResponse(w, "Client created", http.StatusOK)
}

func AdminUpdateClient(w http.ResponseWriter, r *http.Request) {
	if requireAdmin(w, r) == nil {
		return
	}
	clientID := r.URL.Query().Get("id")
	if clientID == "" {
		JSONResponse(w, "Missing id", http.StatusBadRequest)
		return
	}
	var client SSOClient
	if err := json.NewDecoder(r.Body).Decode(&client); err != nil {
		JSONResponse(w, "Invalid request", http.StatusBadRequest)
		return
	}
	client.ID = clientID
	if err := UpdateSSOClient(&client); err != nil {
		JSONResponse(w, "Failed to update client: "+err.Error(), http.StatusInternalServerError)
		return
	}
	JSONResponse(w, "Client updated", http.StatusOK)
}

func AdminDeleteClient(w http.ResponseWriter, r *http.Request) {
	if requireAdmin(w, r) == nil {
		return
	}
	clientID := r.URL.Query().Get("id")
	if clientID == "" {
		JSONResponse(w, "Missing id", http.StatusBadRequest)
		return
	}
	if err := DeleteSSOClient(clientID); err != nil {
		JSONResponse(w, "Failed to delete client: "+err.Error(), http.StatusInternalServerError)
		return
	}
	JSONResponse(w, "Client deleted", http.StatusOK)
}

/////////////////////////////
//                         //
//    User Admin           //
//                         //
/////////////////////////////

func AdminListUsers(w http.ResponseWriter, r *http.Request) {
	if requireAdmin(w, r) == nil {
		return
	}
	users, err := GetAllUsers()
	if err != nil {
		JSONResponse(w, "Failed to list users", http.StatusInternalServerError)
		return
	}
	JSONResponse(w, users, http.StatusOK)
}

func AdminUpdateUser(w http.ResponseWriter, r *http.Request) {
	admin := requireAdmin(w, r)
	if admin == nil {
		return
	}
	userID := r.URL.Query().Get("id")
	if userID == "" {
		JSONResponse(w, "Missing id", http.StatusBadRequest)
		return
	}
	user, err := GetUser(userID)
	if err != nil {
		JSONResponse(w, "User not found", http.StatusNotFound)
		return
	}

	var req struct {
		Name        *string `json:"name"`
		DisplayName *string `json:"display_name"`
		IsActive    *bool   `json:"is_active"`
		IsAdmin     *bool   `json:"is_admin"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		JSONResponse(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if req.Name != nil {
		user.Name = *req.Name
	}
	if req.DisplayName != nil {
		user.DisplayName = *req.DisplayName
	}
	if req.IsActive != nil {
		user.IsActive = *req.IsActive
	}
	if req.IsAdmin != nil {
		// Prevent admin from demoting themselves
		if user.ID == admin.ID && !*req.IsAdmin {
			JSONResponse(w, "Cannot remove admin from yourself", http.StatusBadRequest)
			return
		}
		user.IsAdmin = *req.IsAdmin
	}

	if err := SaveUser(user); err != nil {
		JSONResponse(w, "Failed to update user: "+err.Error(), http.StatusInternalServerError)
		return
	}
	JSONResponse(w, "User updated", http.StatusOK)
}

func AdminDeleteUser(w http.ResponseWriter, r *http.Request) {
	admin := requireAdmin(w, r)
	if admin == nil {
		return
	}
	userID := r.URL.Query().Get("id")
	if userID == "" {
		JSONResponse(w, "Missing id", http.StatusBadRequest)
		return
	}
	if userID == admin.ID {
		JSONResponse(w, "Cannot delete yourself", http.StatusBadRequest)
		return
	}
	if err := DeleteUser(userID); err != nil {
		JSONResponse(w, "Failed to delete user: "+err.Error(), http.StatusInternalServerError)
		return
	}
	JSONResponse(w, "User deleted", http.StatusOK)
}
