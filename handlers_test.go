package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
)

func NewServer() (*http.Server, *AuthService) {
	tp := NewJwtProvider(ExpirationTime(2*time.Second), Key("my_secret_key"))
	up := NewUsers()
	authService := NewAuthService(tp, up)
	handlers := authService.Handlers("/auth")

	router := chi.NewRouter()
	router.Mount("/auth", handlers)

	httpServer := &http.Server{
		Addr:              ":8001",
		Handler:           router,
		ReadHeaderTimeout: time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       time.Second,
	}

	return httpServer, authService
}

func TestServerSignupSignin(t *testing.T) {

	var server *http.Server
	var authService *AuthService
	server, authService = NewServer()
	go func() {
		err := server.ListenAndServe()
		if err != nil {
			panic(err)
		}
		defer server.Close()
	}()

	// Create a new HTTP request with JSON body
	reqBody := map[string]string{
		"login":    "user1",
		"password": "password1",
	}
	reqBodyBytes, _ := json.Marshal(reqBody)

	// Signup test
	// Signing up with test credentials
	req, _ := http.NewRequest("POST", "/auth/signup", bytes.NewBuffer(reqBodyBytes))
	req.Header.Set("Content-Type", "application/json")

	// Create a new HTTP recorder to capture the response
	response := httptest.NewRecorder()

	// Call the signup handler function
	authService.HandleSignup(response, req)

	// parse the response body
	var respBody map[string]string
	json.Unmarshal(response.Body.Bytes(), &respBody)

	assert.Equal(t, http.StatusOK, response.Code, "Expected status code %d but got %d", http.StatusOK, response.Code)
	assert.Equal(t, reqBody["login"], respBody["login"], "Expected login %s but got %s", reqBody["login"], respBody["login"])
	assert.Equal(t, "OK", respBody["status"], "Expected status OK but got %s", respBody["status"])

	// Signin test
	// Signin with the same credentials
	req, _ = http.NewRequest("POST", "/auth/signin", bytes.NewBuffer(reqBodyBytes))
	req.Header.Set("Content-Type", "application/json")
	response = httptest.NewRecorder()
	authService.HandleSignin(response, req)
	json.Unmarshal(response.Body.Bytes(), &respBody)
	token := respBody["token"]

	assert.Equal(t, http.StatusOK, response.Code, "Expected status code %d but got %d", http.StatusOK, response.Code)
	assert.Equal(t, reqBody["login"], respBody["login"], "Expected login %s but got %s", reqBody["login"], respBody["login"])
	assert.Equal(t, "OK", respBody["status"], "Expected status OK but got %s", respBody["status"])
	assert.NotEmpty(t, respBody["token"], "Expected token not empty but got %s", respBody["token"])
	assert.NotEmpty(t, respBody["expires_at"], "Expected expires_at not empty but got %s", respBody["expires_at"])

	// Signin with wrong credentials
	reqBodyInv := map[string]string{
		"login":    "invalid_user",
		"password": "password2",
	}

	reqBodyBytes, _ = json.Marshal(reqBodyInv)
	req, _ = http.NewRequest("POST", "/auth/signin", bytes.NewBuffer(reqBodyBytes))
	req.Header.Set("Content-Type", "application/json")
	response = httptest.NewRecorder()
	authService.HandleSignin(response, req)
	json.Unmarshal(response.Body.Bytes(), &respBody)

	assert.Equal(t, http.StatusUnauthorized, response.Code, "Expected status code %d but got %d", http.StatusUnauthorized, response.Code)
	assert.Zero(t, response.Body.Len(), "Expected empty response body but got %s", response.Body.String())

	// Check test
	// Check with valid token
	req, _ = http.NewRequest("GET", "/auth/check", nil)
	req.Header.Set("Cookie", "token="+token)
	response = httptest.NewRecorder()
	authService.HandleCheck(response, req)
	json.Unmarshal(response.Body.Bytes(), &respBody)

	assert.Equal(t, http.StatusOK, response.Code, "Expected status code %d but got %d", http.StatusOK, response.Code)
	assert.Equal(t, reqBody["login"], respBody["login"], "Expected login %s but got %s", reqBody["login"], respBody["login"])
	assert.Equal(t, "OK", respBody["status"], "Expected status OK but got %s", respBody["status"])
	assert.NotEmpty(t, respBody["expires_at"], "Expected expires_at not empty but got %s", respBody["expires_at"])

	// Check with invalid token
	req, _ = http.NewRequest("GET", "/auth/check", nil)
	req.Header.Set("Cookie", "token=invalid_token")
	response = httptest.NewRecorder()
	authService.HandleCheck(response, req)
	json.Unmarshal(response.Body.Bytes(), &respBody)

	assert.Equal(t, http.StatusUnauthorized, response.Code, "Expected status code %d but got %d", http.StatusUnauthorized, response.Code)
	assert.Zero(t, response.Body.Len(), "Expected empty response body but got %s", response.Body.String())

	// Logout test
	// Logout
	req, _ = http.NewRequest("GET", "/auth/logout", nil)
	response = httptest.NewRecorder()
	authService.Logout(response, req)
	json.Unmarshal(response.Body.Bytes(), &respBody)

	assert.Equal(t, http.StatusOK, response.Code, "Expected status code %d but got %d", http.StatusOK, response.Code)
	assert.Equal(t, "OK", respBody["status"], "Expected status OK but got %s", respBody["status"])

	// check response cookie
	cookies := response.Result().Cookies()
	assert.Equal(t, 1, len(cookies), "Expected 1 cookie but got %d", len(cookies))
	assert.Equal(t, "token", cookies[0].Name, "Expected cookie name token but got %s", cookies[0].Name)
	assert.Equal(t, "", cookies[0].Value, "Expected empty cookie value but got %s", cookies[0].Value)
}
