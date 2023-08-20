package main

import (
	"encoding/json"
	"net/http"
	"time"
)

type Credentials struct {
	Password string `json:"password"`
	Username string `json:"username"`
}

// HandleSignin - http handler for signin
func (s *AuthService) HandleSignin(w http.ResponseWriter, r *http.Request) {
	var creds Credentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	expectedUser, ok := s.Users[creds.Username]

	// If the username/password combination is wrong, return an error
	if !ok || expectedUser.Password != creds.Password {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	token, err := s.Tokens.New(creds.Username)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   token.Token,
		Expires: token.ExpiresAt,
	})

	json.NewEncoder(w).Encode(map[string]string{"status": "OK", "token": token.Token, "expires_at": token.ExpiresAt.Format(time.RFC3339)})
	return
}

// HandleSignup - http handler for signup
func (s *AuthService) HandleSignup(w http.ResponseWriter, r *http.Request) {
	var creds Credentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	s.Users[creds.Username] = User{Login: creds.Username, Password: creds.Password}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "OK", "user": creds.Username})
	return
}

// HandleCheck - http handler for check
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

	return
}

// HandleLogout - http handler for logout
func (s *AuthService) Logout(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	// immediately clear the token cookie
	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Expires: time.Now(),
	})
}

func (s *AuthService) Handlers(prefix string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(prefix+"/signin", s.HandleSignin)
	mux.HandleFunc(prefix+"/signup", s.HandleSignup)
	mux.HandleFunc(prefix+"/check", s.HandleCheck)
	mux.HandleFunc(prefix+"/logout", s.Logout)
	return mux
}
