// Path: main_test.go
package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSignup(t *testing.T) {
	service := NewAuthService()
	token, err := service.Signup("login", "password")
	assert.NoError(t, err)
	assert.Empty(t, token)
}

func TestSignin(t *testing.T) {
	service := NewAuthService()
	token, err := service.Signin("login", "password")
	assert.Error(t, err)
	assert.Empty(t, token)
}

func TestSignupSignin(t *testing.T) {
	service := NewAuthService()
	_, err := service.Signup("login", "password")
	assert.NoError(t, err)

	token, err := service.Signin("login", "password")
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	result, err := service.Check(token)
	assert.NoError(t, err)
	assert.NotEmpty(t, result)

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
