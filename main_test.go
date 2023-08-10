// Path: main_test.go
package main

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSignup(t *testing.T) {
	tp := NewJwtProvider(3 * time.Second)
	service := NewAuthService(tp)

	token, err := service.Signup("login", "password")
	assert.NoError(t, err)
	assert.Empty(t, token)
}

func TestSignin(t *testing.T) {
	tp := NewJwtProvider(3 * time.Second)
	service := NewAuthService(tp)

	token, err := service.Signin("login", "password")
	assert.Error(t, err)
	assert.Empty(t, token)
}

func TestSignupSignin(t *testing.T) {
	tp := NewJwtProvider(3 * time.Second)
	service := NewAuthService(tp)

	_, err := service.Signup("login", "password")
	assert.NoError(t, err)

	token, err := service.Signin("login", "password")
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	result, err := service.Check(token)
	assert.NoError(t, err)
	assert.NotEmpty(t, result)
	assert.Equal(t, "login", result)

	token, err = service.Signin("wrong login", "password")
	assert.Error(t, err)
	assert.Empty(t, token)

	token, err = service.Signin("login", "wrong password")
	assert.Error(t, err)
	assert.Empty(t, token)

	token, err = service.Signin("wrong login", "wrong password")
	assert.Error(t, err)
	assert.Empty(t, token)

}
