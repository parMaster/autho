package main

import (
	"errors"
	"fmt"
)

type User struct {
	Login    string
	Password string
}

type TokenProviderInterface interface {
	New(username string) (*Token, error)
	Validate(token string) (*Claims, error)
	Refresh(token string) (*Token, error)
}

type AuthService struct {
	tokens TokenProviderInterface
	Users  map[string]User
}

func NewAuthService(tp TokenProviderInterface) *AuthService {
	u := make(map[string]User, 0)
	return &AuthService{Users: u}
}

const (
	ErrUserNotFound  = "user not found"
	ErrWrongPassword = "wrong password"
)

// Signin - signs in a user with a given login and password
func (s *AuthService) Signin(login, password string) (string, error) {
	if user, ok := s.Users[login]; ok {
		if user.Password == password {
			return "token", nil
		}
		return "", fmt.Errorf("%s: %s", ErrWrongPassword, password)
	}
	return "", errors.New(ErrUserNotFound)
}

// Signup - signs up a user with a given login and password
func (s *AuthService) Signup(login, password string) (string, error) {
	s.Users[login] = User{Login: login, Password: password}
	return "", nil
}

// Check - checks validity of a token
func (s *AuthService) Check(token string) (string, error) {

	claims, err := s.tokens.Validate(token)
	if err != nil {
		return "", err
	}

	if user, ok := s.Users[claims.Username]; ok {
		return user.Login, nil
	}
}
