package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
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
	Tokens TokenProviderInterface
	Users  map[string]User
}

func NewAuthService(tp TokenProviderInterface) *AuthService {
	u := make(map[string]User, 0)
	return &AuthService{Users: u, Tokens: tp}
}

const (
	ErrUserNotFound  = "user not found"
	ErrWrongPassword = "wrong password"
)

// Signin - signs in a user with a given login and password
func (s *AuthService) Signin(login, password string) (string, error) {
	user, ok := s.Users[login]
	if !ok {
		return "", errors.New(ErrUserNotFound)
	}
	if user.Password != password {
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
	s.Users[login] = User{Login: login, Password: password}
	return "", nil
}

// Check - checks validity of a token
func (s *AuthService) Check(token string) (string, error) {

	claims, err := s.Tokens.Validate(token)
	if err != nil {
		return "", err
	}

	if user, ok := s.Users[claims.Username]; ok {
		return user.Login, nil
	}

	return "", errors.New(ErrUserNotFound)
}

func main() {
	tp := NewJwtProvider(5 * time.Minute)
	service := NewAuthService(tp)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		if x := recover(); x != nil {
			log.Printf("[WARN] run time panic:\n%v", x)
			panic(x)
		}

		// catch signal and invoke graceful termination
		stop := make(chan os.Signal, 1)
		signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
		<-stop
		log.Printf("[INFO] shutting down")
		cancel()
	}()

	router := chi.NewRouter()
	router.Mount("/auth", service.Handlers("/auth"))

	httpServer := &http.Server{
		Addr:              ":8000",
		Handler:           router,
		ReadHeaderTimeout: time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       time.Second,
	}
	log.Printf("[INFO] Listening: %s", "8000")

	go func() {
		<-ctx.Done()
		if httpServer != nil {
			if err := httpServer.Shutdown(ctx); err != nil {
				log.Printf("[ERROR] failed to close http server, %v", err)
			}
		}
	}()

	httpServer.ListenAndServe()
}
