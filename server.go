package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
)

func main() {
	tp := NewJwtProvider(ExpirationTime(5*time.Minute), Key("my_secret_key"))
	handlers := NewAuthService(tp).Handlers("/auth")

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
	router.Mount("/auth", handlers)

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
