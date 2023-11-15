package main

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	Login string `json:"login"`
	jwt.RegisteredClaims
}

type JwtProvider struct {
	ExpirationTime time.Duration
	Key            []byte
}

func NewJwtProvider(opts ...JWTProviderOption) TokenProviderInterface {
	tp := JwtProvider{}
	for _, opt := range opts {
		opt(&tp)
	}
	return &tp
}

// New() creates a new token for a given username
func (t *JwtProvider) New(login string) (*Token, error) {
	expirationTime := time.Now().Add(t.ExpirationTime)
	claims := &Claims{
		Login: login,
		RegisteredClaims: jwt.RegisteredClaims{
			// In JWT, the expiry time is expressed as unix milliseconds
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(t.Key)
	if err != nil {
		return nil, err
	}

	return &Token{
		Token:     tokenString,
		ExpiresAt: expirationTime,
		Login:     login,
	}, nil
}

// Validate() validates a given token
func (t *JwtProvider) Validate(token string) (*Token, error) {
	claims := &Claims{}

	tkn, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return t.Key, nil
	})
	if err != nil {
		return nil, err
	}
	if !tkn.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return &Token{
		Token:     token,
		ExpiresAt: claims.ExpiresAt.Time,
		Login:     claims.Login,
	}, nil
}

// Refresh() refreshes a given token - validate it and create a new one if it's valid
func (t *JwtProvider) Refresh(token string) (*Token, error) {
	validated, err := t.Validate(token)
	if err == nil {
		return t.New(validated.Login)
	}
	return nil, err
}

// JWTProviderOption is a function that configures a JwtProvider.
type JWTProviderOption func(*JwtProvider)

// ExpirationTime sets the expiration time for a token
func ExpirationTime(exp time.Duration) JWTProviderOption {
	return func(j *JwtProvider) {
		j.ExpirationTime = exp
	}
}

// Key sets the key for a token
func Key(key string) JWTProviderOption {
	return func(j *JwtProvider) {
		j.Key = []byte(key)
	}
}
