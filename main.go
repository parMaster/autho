package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/argon2"
)

type User struct {
	Login    string
	Password string
}

type Token struct {
	Login     string    `json:"login"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

type TokenProviderInterface interface {
	// New() creates a new token for a given username
	New(username string) (*Token, error)
	// Validate() validates a given token and returns a username
	Validate(token string) (*Token, error)
	// Refresh() returns a new token with a new expiration time
	Refresh(token string) (*Token, error)
}

type AuthService struct {
	Tokens TokenProviderInterface
	Users  map[string]User
}

func NewAuthService(tp TokenProviderInterface) *AuthService {
	u := make(map[string]User, 0)
	return &AuthService{Users: u, Tokens: tp}
}

const (
	ErrUserNotFound  = "user not found"
	ErrWrongPassword = "wrong password"
)

// Signin - signs in a user with a given login and password
func (s *AuthService) Signin(login, password string) (string, error) {
	user, ok := s.Users[login]
	if !ok {
		return "", errors.New(ErrUserNotFound)
	}

	salt := user.Password[:16]

	if user.Password != s.Hash(salt, password) {
		return "", fmt.Errorf("%s: %s", ErrWrongPassword, password)
	}
	t, err := s.Tokens.New(login)
	if err != nil {
		return "", err
	}
	return t.Token, nil
}

// Signup - signs up a user with a given login and password
func (s *AuthService) Signup(login, password string) (string, error) {
	salt := make([]byte, 16)
	rand.Read(salt)

	s.Users[login] = User{Login: login, Password: s.Hash(string(salt), password)}
	return "", nil
}

// Check - checks validity of a token
func (s *AuthService) Check(token string) (string, error) {

	validated, err := s.Tokens.Validate(token)
	if err != nil {
		return "", err
	}

	if user, ok := s.Users[validated.Login]; ok {
		return user.Login, nil
	}

	return "", errors.New(ErrUserNotFound)
}

// Hash - hashes a password
func (s *AuthService) Hash(salt string, password string) string {
	key := argon2.IDKey([]byte(password), []byte(salt), 1, 64*1024, 4, 32)
	return string(salt) + string(key)
}
