package main

import (
	"log"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func Test_New_Validate_Expire(t *testing.T) {

	tp := NewTokenProvider(3 * time.Second)
	token, err := tp.New("username")

	assert.NoError(t, err)
	assert.NotEmpty(t, token.Token)
	log.Printf("token: %s", token.Token)

	claims, err := tp.Validate(token.Token)
	assert.NoError(t, err)
	assert.NotEmpty(t, claims)

	time.Sleep(4 * time.Second)
	claims, err = tp.Validate(token.Token)
	assert.Error(t, err)
	assert.Empty(t, claims)
}

func Test_Refresh(t *testing.T) {

	tp := NewTokenProvider(3 * time.Second)
	token, err := tp.New("username")

	assert.NoError(t, err)
	assert.NotEmpty(t, token.Token)
	log.Printf("token: %s", token.Token)

	claims, err := tp.Validate(token.Token)
	assert.NoError(t, err)
	assert.NotEmpty(t, claims)

	time.Sleep(2 * time.Second)

	refreshedToken, err := tp.Refresh(token.Token)
	assert.NoError(t, err)
	assert.NotEmpty(t, refreshedToken.Token)

	time.Sleep(2 * time.Second)

	claims, err = tp.Validate(refreshedToken.Token)
	assert.NoError(t, err)
	assert.NotEmpty(t, claims)

	// old token is not valid anymore
	claims, err = tp.Validate(token.Token)
	assert.Error(t, err)
	assert.Empty(t, claims)

	claims, err = tp.Validate("invalid token")
	assert.Error(t, err)
	assert.Empty(t, claims)

	ir, err := tp.Refresh("invalid token")
	assert.Error(t, err)
	assert.Empty(t, ir)
}
