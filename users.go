package main

import "errors"

type Users struct {
	Users map[string]User
}

func NewUsers() *Users {
	u := make(map[string]User, 0)
	return &Users{Users: u}
}

func (u *Users) Get(login string) (*User, error) {
	user, ok := u.Users[login]
	if !ok {
		return nil, errors.New(ErrUserNotFound)
	}
	return &user, nil
}

func (u *Users) Create(user User) error {
	u.Users[user.Login] = user
	return nil
}
