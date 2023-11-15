package main

import (
	"encoding/json"
	"net/http"
	"time"
)

type Credentials struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

// HandleSignin - http handler for /signin endpoint, signs in a user
// sets a cookie with a json encoded struct with
// status, token and expiratiom time
func (s *AuthService) HandleSignin(w http.ResponseWriter, r *http.Request) {
	var creds Credentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	expectedUser, ok := s.Users[creds.Login]

	// If the username/password combination is wrong, return an error
	if !ok || expectedUser.Password != creds.Password {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	token, err := s.Tokens.New(creds.Login)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   token.Token,
		Expires: token.ExpiresAt,
	})
	// w.WriteHeader(http.StatusOK)

	json.NewEncoder(w).Encode(map[string]string{"status": "OK", "token": token.Token, "expires_at": token.ExpiresAt.Format(time.RFC3339)})
}

// HandleSignup - http handler for /signup endpoint, creates a new user,
// sets a cookie with a json encoded struct with status and a username
func (s *AuthService) HandleSignup(w http.ResponseWriter, r *http.Request) {
	var creds Credentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	s.Users[creds.Login] = User{Login: creds.Login, Password: creds.Password}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "OK", "login": creds.Login})
}

// HandleCheck - http handler for /check endpoint, checks if the token is valid,
// returns a json encoded struct with status, username and expiration time
func (s *AuthService) HandleCheck(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("token")
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	login, err := s.Check(c.Value)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	validated, err := s.Tokens.Validate(c.Value)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "OK", "login": login, "ExpiresAt": validated.ExpiresAt.Format(time.RFC3339)})
}

// HandleLogout - http handler for logout, clears the token cookie
func (s *AuthService) Logout(w http.ResponseWriter, r *http.Request) {
	// immediately clear the token cookie
	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Expires: time.Now(),
	})
}

// Handlers - returns a http.Handler with all the handlers,
// prefix default is "/auth", the handlers will be available at
// /auth/signin, /auth/signup, /auth/check, /auth/logout
func (s *AuthService) Handlers(prefix string) http.Handler {
	if prefix == "" {
		prefix = "/auth"
	}
	mux := http.NewServeMux()
	mux.HandleFunc(prefix+"/signin", s.HandleSignin)
	mux.HandleFunc(prefix+"/signup", s.HandleSignup)
	mux.HandleFunc(prefix+"/check", s.HandleCheck)
	mux.HandleFunc(prefix+"/logout", s.Logout)
	return mux
}
