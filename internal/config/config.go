package config

import (
	"log"
	"os"

	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type Config struct {
	GoogleClientID     string
	GoogleClientSecret string
	GoogleRedirectURL  string
	JWTSecretKey       string
	OAuthStateString   string
	ServerPort         string
	GoogleOAuthConfig  *oauth2.Config // Add this field
}

func Load() *Config {
	if err := godotenv.Load(); err != nil {
		log.Printf("Warning: .env file not found: %v", err)
	}

	return &Config{
		GoogleClientID:     getEnvOrDie("GOOGLE_CLIENT_ID"),
		GoogleClientSecret: getEnvOrDie("GOOGLE_CLIENT_SECRET"),
		GoogleRedirectURL:  getEnvOrDie("GOOGLE_REDIRECT_URL"),
		JWTSecretKey:       getEnvOrDie("JWT_SECRET_KEY"),
		OAuthStateString:   getEnvOrDie("OAUTH_STATE_STRING"),
		ServerPort:         getEnvOrDefault("SERVER_PORT", "8080"),
		GoogleOAuthConfig: &oauth2.Config{ // Initialize Google OAuth configuration
			ClientID:     getEnvOrDie("GOOGLE_CLIENT_ID"),
			ClientSecret: getEnvOrDie("GOOGLE_CLIENT_SECRET"),
			RedirectURL:  getEnvOrDie("GOOGLE_REDIRECT_URL"),
			Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email"},
			Endpoint:     google.Endpoint,
		},
	}
}

func getEnvOrDie(key string) string {
	value, exists := os.LookupEnv(key)
	if !exists {
		log.Fatalf("Environment variable %s not set", key)
	}
	return value
}

func getEnvOrDefault(key, defaultValue string) string {
	value, exists := os.LookupEnv(key)
	if !exists {
		return defaultValue
	}
	return value
}
