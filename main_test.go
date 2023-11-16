// Path: main_test.go
package main

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSignup(t *testing.T) {
	tp := NewJwtProvider(ExpirationTime(3*time.Second), Key("my_secret_key"))
	up := NewUsers()
	service := NewAuthService(tp, up)

	token, err := service.Signup("login", "password")
	assert.NoError(t, err)
	assert.Empty(t, token)
}

func TestSignin(t *testing.T) {
	tp := NewJwtProvider(ExpirationTime(3*time.Second), Key("my_secret_key"))
	up := NewUsers()
	service := NewAuthService(tp, up)

	token, err := service.Signin("login", "password")
	assert.Error(t, err)
	assert.Empty(t, token)
}

func TestSignupSignin(t *testing.T) {
	tp := NewJwtProvider(ExpirationTime(3*time.Second), Key("my_secret_key"))
	up := NewUsers()
	service := NewAuthService(tp, up)

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

func TestStaticUsers(t *testing.T) {

	// Service just to hash passwords
	tp := NewJwtProvider(ExpirationTime(3*time.Second), Key("my_secret_key"))
	up := NewUsers()
	service := NewAuthService(tp, up)

	// Create a map of users
	users := make(map[string]User, 3)
	users["user1"] = User{Login: "user1", Password: service.Hash("salt456789012345", "password1")}
	users["user2"] = User{Login: "user2", Password: service.Hash("salt456789012345", "password2")}
	users["user3"] = User{Login: "user3", Password: service.Hash("salt456789012345", "password3")}

	// test AuthService wiер static users provider
	sup := NewStaticUsers(users)
	s := NewAuthService(tp, sup)

	token, err := s.Signin("user1", "password1")
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	token, err = s.Signin("user2", "password2")
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	token, err = s.Signin("user3", "password3")
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	token, err = s.Signin("user_unknown", "password_unknown")
	assert.Error(t, err)
	assert.Empty(t, token)
}
