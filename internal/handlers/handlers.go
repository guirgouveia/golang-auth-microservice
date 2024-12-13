package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"google-sso-golang/internal/config"
	"google-sso-golang/internal/models"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
)

// Global configuration variable
var cfg *config.Config

// Custom errors for better error handling
var (
	ErrInvalidToken       = errors.New("invalid token")
	ErrTokenExpired       = errors.New("token expired")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserNotFound       = errors.New("user not found")
	ErrInvalidSession     = errors.New("invalid session")
)

// UserContextKey is the key type for context values
type UserContextKey string

const (
	CtxUserKey UserContextKey = "user"
)

// Handler structure
type Handler struct {
	sm *SessionManager
}

// Initialize the global configuration variable
func init() {
	cfg = config.Load()
}

// New creates and configures a new handler
func New() http.Handler {
	sm := NewSessionManager()

	h := &Handler{
		sm: sm,
	}

	r := mux.NewRouter()

	// Public routes
	r.HandleFunc("/login", h.logRequest(h.loginHandler())).Methods("POST")
	r.HandleFunc("/signup", h.logRequest(h.signUpHandler())).Methods("POST")
	r.HandleFunc("/login/google", h.logRequest(h.googleLoginHandler())).Methods("GET")
	r.HandleFunc("/login/google/callback", h.logRequest(h.googleCallbackHandler())).Methods("GET")

	// Protected routes
	protected := r.PathPrefix("/api").Subrouter()
	protected.Use(h.sm.SessionMiddleware)
	protected.HandleFunc("/logout", h.logRequest(h.logoutHandler())).Methods("POST")
	protected.HandleFunc("/console", h.logRequest(h.homeHandler())).Methods("GET")

	return r
}

// SessionManager structure handles session operations
type SessionManager struct {
	users    map[string]models.User
	sessions map[string]string
	logger   *logrus.Logger
}

// NewSessionManager initializes a SessionManager
func NewSessionManager() *SessionManager {
	logger := logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{})
	return &SessionManager{
		users:    make(map[string]models.User),
		sessions: make(map[string]string),
		logger:   logger,
	}
}

// Middleware to log requests
func (h *Handler) logRequest(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	}
}

// Home handler for protected routes
func (h *Handler) homeHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, err := GetUserFromContext(r.Context())
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		w.Write([]byte(fmt.Sprintf("Welcome %s!", user.Name)))
	}
}

// LoginHandler authenticates user credentials
func (h *Handler) loginHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var creds models.Credentials
		if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
			h.sm.logger.WithError(err).Error("Failed to decode credentials")
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		user, exists := h.sm.users[creds.Email]
		if !exists || bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(creds.Password)) != nil {
			h.sm.logger.WithField("email", creds.Email).Warn("Invalid credentials")
			http.Error(w, ErrInvalidCredentials.Error(), http.StatusUnauthorized)
			return
		}

		token, err := h.sm.generateJWTToken(user)
		if err != nil {
			h.sm.logger.WithError(err).Error("Failed to generate token")
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		h.sm.setSessionCookie(w, token)
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(models.LoginResponse{Token: token, User: user}); err != nil {
			h.sm.logger.WithError(err).Error("Failed to encode response")
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
	}
}

// SignUpHandler registers a new user
func (h *Handler) signUpHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var newUser models.User
		if err := json.NewDecoder(r.Body).Decode(&newUser); err != nil {
			h.sm.logger.WithError(err).Error("Failed to decode user data")
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		if _, exists := h.sm.users[newUser.Email]; exists {
			h.sm.logger.WithField("email", newUser.Email).Warn("Email already exists")
			http.Error(w, "Email already registered", http.StatusConflict)
			return
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newUser.Password), bcrypt.DefaultCost)
		if err != nil {
			h.sm.logger.WithError(err).Error("Failed to hash password")
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		newUser.Password = string(hashedPassword)
		h.sm.users[newUser.Email] = newUser

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(newUser)
	}
}

// LogoutHandler clears the user session
func (h *Handler) logoutHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session_token")
		if err != nil {
			http.Error(w, "No session found", http.StatusBadRequest)
			return
		}

		delete(h.sm.sessions, cookie.Value)

		http.SetCookie(w, &http.Cookie{
			Name:     "session_token",
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
		})

		w.WriteHeader(http.StatusOK)
	}
}

// Generate a JWT token for a user
func (sm *SessionManager) generateJWTToken(user models.User) (string, error) {
	claims := jwt.MapClaims{
		"email": user.Email,
		"name":  user.Name,
		"exp":   time.Now().Add(72 * time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(cfg.JWTSecretKey))
}

// Set the session cookie
func (sm *SessionManager) setSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    token,
		Path:     "/",
		MaxAge:   int(12 * time.Hour.Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}

// Validate JWT token and extract claims
func (sm *SessionManager) validateToken(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		return []byte(cfg.JWTSecretKey), nil
	})

	if err != nil {
		return nil, fmt.Errorf("token parsing error: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	return claims, nil
}

// Retrieve user from context
func GetUserFromContext(ctx context.Context) (models.User, error) {
	user, ok := ctx.Value(CtxUserKey).(models.User)
	if !ok {
		return models.User{}, ErrUserNotFound
	}
	return user, nil
}

// GoogleLoginHandler initiates OAuth flow
func (h *Handler) googleLoginHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		url := cfg.GoogleOAuthConfig.AuthCodeURL(cfg.OAuthStateString)
		http.Redirect(w, r, url, http.StatusTemporaryRedirect)
	}
}

// GoogleCallbackHandler handles OAuth callback
func (h *Handler) googleCallbackHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		state := r.FormValue("state")
		if state != cfg.OAuthStateString {
			h.sm.logger.Error("Invalid OAuth state")
			http.Error(w, "Invalid OAuth state", http.StatusBadRequest)
			return
		}

		code := r.FormValue("code")
		token, err := cfg.GoogleOAuthConfig.Exchange(r.Context(), code)
		if err != nil {
			h.sm.logger.WithError(err).Error("Code exchange failed")
			http.Error(w, "Failed to complete OAuth flow", http.StatusInternalServerError)
			return
		}

		userInfo, err := h.sm.getGoogleUserInfo(token)
		if err != nil {
			h.sm.logger.WithError(err).Error("Failed to get user info")
			http.Error(w, "Failed to get user info", http.StatusInternalServerError)
			return
		}

		_, jwtToken, err := h.sm.handleGoogleUser(userInfo)
		if err != nil {
			h.sm.logger.WithError(err).Error("Failed to handle Google user")
			http.Error(w, "Authentication failed", http.StatusInternalServerError)
			return
		}

		h.sm.setSessionCookie(w, jwtToken)

		// Redirect to the console page after successful login
		http.Redirect(w, r, "/console", http.StatusTemporaryRedirect)
	}
}

// Add missing SessionMiddleware implementation:
func (sm *SessionManager) SessionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session_token")
		if err != nil {
			sm.logger.WithError(err).Warn("No session cookie")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		claims, err := sm.validateToken(cookie.Value)
		if err != nil {
			sm.logger.WithError(err).Warn("Invalid token")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		email, ok := claims["email"].(string)
		if !ok {
			sm.logger.Warn("Email claim missing")
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		user, exists := sm.users[email]
		if !exists {
			sm.logger.WithField("email", email).Warn("User not found")
			http.Error(w, "User not found", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), CtxUserKey, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Add helper method for Google user info:
func (sm *SessionManager) getGoogleUserInfo(token *oauth2.Token) (*models.GoogleUserInfo, error) {
	client := cfg.GoogleOAuthConfig.Client(context.Background(), token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	var userInfo models.GoogleUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, fmt.Errorf("failed to decode user info: %w", err)
	}

	return &userInfo, nil
}

// Add helper method for handling Google users:
func (sm *SessionManager) handleGoogleUser(userInfo *models.GoogleUserInfo) (models.User, string, error) {
	user, exists := sm.users[userInfo.Email]
	if !exists {
		user = models.User{
			Email: userInfo.Email,
			Name:  userInfo.Name,
		}
		sm.users[user.Email] = user
	}

	token, err := sm.generateJWTToken(user)
	if err != nil {
		return models.User{}, "", fmt.Errorf("generating token: %w", err)
	}

	sm.sessions[token] = user.Email
	return user, token, nil
}
