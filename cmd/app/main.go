package main

import (
	"google-sso-golang/internal/handlers"
	"log"
	"net/http"
)

func main() {
	log.Println("Server running on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", handlers.New()))
}
