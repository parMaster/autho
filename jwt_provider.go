package main

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var jwtKey = []byte("my_secret_key")

type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

type Token struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

type JwtProvider struct {
	ExpirationTime time.Duration
}

func NewJwtProvider(exp time.Duration) TokenProviderInterface {
	return &JwtProvider{
		ExpirationTime: exp,
	}
}

// New() creates a new token for a given username
func (t *JwtProvider) New(username string) (*Token, error) {
	expirationTime := time.Now().Add(t.ExpirationTime)
	claims := &Claims{
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			// In JWT, the expiry time is expressed as unix milliseconds
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		return nil, err
	}

	return &Token{
		Token:     tokenString,
		ExpiresAt: expirationTime,
	}, nil
}

func checkToken(token string, claims *Claims) (bool, error) {
	tkn, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil {
		return false, err
	}
	if !tkn.Valid {
		return false, nil
	}
	return true, nil
}

// Validate() validates a given token
func (t *JwtProvider) Validate(token string) (*Claims, error) {
	claims := &Claims{}

	valid, err := checkToken(token, claims)
	if err != nil {
		return nil, err
	}
	if !valid {
		return nil, fmt.Errorf("invalid token")
	}

	return claims, nil
}

// Refresh() refreshes a given token - validate it and create a new one if it's valid
func (t *JwtProvider) Refresh(token string) (*Token, error) {
	claims, err := t.Validate(token)
	if err == nil {
		return t.New(claims.Username)
	}
	return nil, err
}
