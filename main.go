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

type UserProvider interface {
	// Get() returns a user by a given username
	Get(login string) (*User, error)
	// Create() creates a new user
	Create(user User) error
}

type AuthService struct {
	Tokens TokenProviderInterface
	Users  UserProvider
}

func NewAuthService(tp TokenProviderInterface, up UserProvider) *AuthService {
	return &AuthService{Users: up, Tokens: tp}
}

const (
	ErrUserNotFound  = "user not found"
	ErrWrongPassword = "wrong password"
)

// Signin - signs in a user with a given login and password
func (s *AuthService) Signin(login, password string) (string, error) {
	user, err := s.Users.Get(login)
	if err != nil {
		return "", err
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

	s.Users.Create(User{Login: login, Password: s.Hash(string(salt), password)})
	return "", nil
}

// Check - checks validity of a token
func (s *AuthService) Check(token string) (string, error) {

	validated, err := s.Tokens.Validate(token)
	if err != nil {
		return "", err
	}

	if user, err := s.Users.Get(validated.Login); err == nil {
		return user.Login, nil
	}

	return "", errors.New(ErrUserNotFound)
}

// Hash - hashes a password
func (s *AuthService) Hash(salt string, password string) string {
	key := argon2.IDKey([]byte(password), []byte(salt), 1, 64*1024, 4, 32)
	return string(salt) + string(key)
}
