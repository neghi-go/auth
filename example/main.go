package main

import (
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/neghi-go/database/mongodb"
	"github.com/neghi-go/iam/auth"
	"github.com/neghi-go/iam/auth/models"
	"github.com/neghi-go/iam/auth/providers/password"
	"github.com/neghi-go/iam/auth/providers/passwordless"
	"github.com/neghi-go/session"
)

func main() {
	mgd, err := mongodb.New("mongodb://localhost:27017", "test-db")
	if err != nil {
		panic(err)
	}
	userModel, err := mongodb.RegisterModel(mgd, "users", models.User{})
	if err != nil {
		panic(err)
	}

	ses := session.NewServerSession()

	r, err := auth.New(
		auth.RegisterStrategy(
			password.PasswordProvider(password.WithStore(userModel)),
			passwordless.PasswordlessProvider(passwordless.WithStore(userModel)),
		),
		auth.RegisterSession(ses),
	).Build()
	if err != nil {
		panic(err)
	}
	fmt.Println("Server up and running")
	chi.Walk(r, func(method, route string, handler http.Handler, middlewares ...func(http.Handler) http.Handler) error {
		fmt.Printf("method : %v, route: %v\n", method, route)
		return nil
	})
	http.ListenAndServe(":8080", r)
}
