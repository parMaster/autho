package main

import (
	"log"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func Test_New_Validate_Expire(t *testing.T) {

	tp := NewJwtProvider(1 * time.Second)
	token, err := tp.New("username")

	assert.NoError(t, err, "error creating token")
	assert.NotEmpty(t, token.Token)

	claims, err := tp.Validate(token.Token)
	assert.NoError(t, err)
	assert.NotEmpty(t, claims)

	time.Sleep(2 * time.Second)
	claims, err = tp.Validate(token.Token)
	assert.Error(t, err)
	assert.Empty(t, claims)
}

func Test_Refresh(t *testing.T) {

	// Making token that expires in 3 seconds
	tp := NewJwtProvider(3 * time.Second)
	token, err := tp.New("username")

	assert.NoError(t, err)
	assert.NotEmpty(t, token.Token)
	log.Printf("token: %s", token.Token)

	claims, err := tp.Validate(token.Token)
	assert.NoError(t, err)
	assert.NotEmpty(t, claims)

	// Refreshing token after 2 seconds
	time.Sleep(2 * time.Second)
	refreshedToken, err := tp.Refresh(token.Token)
	assert.NoError(t, err)
	assert.NotEmpty(t, refreshedToken.Token)

	claims, err = tp.Validate(refreshedToken.Token)
	assert.NoError(t, err)
	assert.NotEmpty(t, claims)

	// Waiting for token to expire
	time.Sleep(2 * time.Second)

	// original token is not valid anymore
	claims, err = tp.Validate(token.Token)
	assert.Error(t, err)
	assert.Empty(t, claims)

	// refreshed token is still valid
	claims, err = tp.Validate(refreshedToken.Token)
	assert.NoError(t, err)
	assert.NotEmpty(t, claims)

	// Invalid token validation error
	claims, err = tp.Validate("invalid token")
	assert.Error(t, err)
	assert.Empty(t, claims)

	// Invalid token refresh error
	ir, err := tp.Refresh("invalid token")
	assert.Error(t, err)
	assert.Empty(t, ir)
}

func Test_Check(t *testing.T) {

	tp := NewJwtProvider(3 * time.Second)

	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InVzZXIxIiwiZXhwIjoxNjkxNzg4NjY0fQ.oCJv56AtJ4mG6VMAboEsykC1ML2DZBVGX4GFakuukV0"
	log.Printf("token: %s", token)

	claims, err := tp.Validate(token)

	assert.Error(t, err)
	log.Printf("error: %s", err)

	assert.Empty(t, claims)
}
