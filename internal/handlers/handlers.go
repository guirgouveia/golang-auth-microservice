package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
type UserContextKey struct {
	user string
}

var CtxUserKey = &UserContextKey{
	user: "user",
}

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
	r.HandleFunc("/logout", h.logRequest(h.logoutHandler())).Methods("GET")
	r.HandleFunc("/signup", h.logRequest(h.signUpHandler())).Methods("POST")
	r.HandleFunc("/console", h.logRequest(h.consoleHandler())).Methods("GET")

	// Protected routes
	login := r.PathPrefix("/auth").Subrouter()
	login.HandleFunc("/login", h.logRequest(loginPage)).Methods("GET")
	login.HandleFunc("/login", h.logRequest(h.loginHandler())).Methods("POST")
	login.HandleFunc("/login/google", h.logRequest(h.googleLoginHandler())).Methods("GET")
	login.HandleFunc("/login/google/callback", h.logRequest(h.googleCallbackHandler())).Methods("GET")

	protected := r.PathPrefix("/console").Subrouter()
	protected.Use(sm.SessionMiddleware)
	r.HandleFunc("", h.logRequest(h.consoleHandler())).Methods("GET")

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
		h.sm.logger.WithFields(logrus.Fields{
			"method": r.Method,
			"path":   r.URL.Path,
		}).Info("Request received")
		next.ServeHTTP(w, r)
	}
}

// Home handler for protected routes
func (h *Handler) consoleHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session_token")
		if err != nil {
			h.sm.logger.WithError(err).Error("Failed to get session cookie")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		user, err := h.sm.GetUserFromJWTToken(cookie.Value)
		if err != nil {
			h.sm.logger.WithError(err).Error("Failed to get user from token")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		w.Write([]byte(fmt.Sprintf("Welcome, %s!", user.Email)))
	}
}

// LoginHandler authenticates user credentials
func (h *Handler) loginHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var creds models.Credentials

		creds.Email = r.FormValue("username")
		creds.Password = r.FormValue("password")
		if creds.Email == "" || creds.Password == "" {
			h.sm.logger.WithError(errors.New("Failed to decode credentials"))
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		user, exists := h.sm.users[creds.Email]
		if !exists || bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(creds.Password)) != nil {
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

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newUser.PasswordHash), bcrypt.DefaultCost)
		if err != nil {
			h.sm.logger.WithError(err).Error("Failed to hash password")
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		newUser.PasswordHash = string(hashedPassword)
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
	logrus.WithField("email", user.Email).Info("Generating JWT token")
	claims := jwt.MapClaims{
		"email": user.Email,
		"name":  user.Name,
		"exp":   time.Now().Add(72 * time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(cfg.JWTSecretKey))
}

// DecryptJWT decrypts the JWT token and returns the user
func (sm *SessionManager) GetUserFromJWTToken(tokenString string) (models.User, error) {
	claims, err := sm.validateToken(tokenString)
	if err != nil {
		return models.User{}, err
	}

	email, ok := claims["email"].(string)
	if !ok {
		return models.User{}, ErrInvalidToken
	}

	user, exists := sm.users[email]
	if !exists {
		return models.User{}, ErrUserNotFound
	}

	return user, nil
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
		SameSite: http.SameSiteLaxMode,
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

		user, jwtToken, err := h.sm.handleGoogleUser(userInfo)
		if err != nil {
			h.sm.logger.WithError(err).Error("Failed to handle Google user")
			http.Error(w, "Authentication failed", http.StatusInternalServerError)
			return
		}

		h.sm.setSessionCookie(w, jwtToken)

		// Add the user to the request context and redirect to the console
		ctx := context.WithValue(r.Context(), CtxUserKey, user)
		http.Redirect(w, r.WithContext(ctx), "/console", http.StatusTemporaryRedirect)
	}
}

func CreateUserContext(context context.Context, user models.User) any {
	panic("unimplemented")
}

func (sm *SessionManager) SessionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session_token")
		if err != nil {
			// If no session token exists, allow the request to proceed
			logrus.Warn("No session token found")
			next.ServeHTTP(w, r)
			return
		}

		claims, err := sm.validateToken(cookie.Value)
		if err != nil {
			// If the token is invalid, allow the request to proceed
			sm.logger.WithError(err).Warn("Invalid token")
			next.ServeHTTP(w, r)
			return
		}

		email, ok := claims["email"].(string)
		if !ok {
			// If the token doesn't contain the email claim, allow the request to proceed
			sm.logger.Warn("Email claim missing")
			next.ServeHTTP(w, r)
			return
		}

		user, exists := sm.users[email]
		if !exists {
			// If the user doesn't exist, allow the request to proceed
			sm.logger.WithField("email", email).Warn("User not found")
			next.ServeHTTP(w, r)
			return
		}

		// Add the user to the request context and allow the request to proceed
		logrus.WithField("email", email).Info("Adding user to context")
		ctx := context.WithValue(r.Context(), CtxUserKey, user)

		// // // Redirect authenticated users to /console if they try to access public routes
		// if r.URL.Path == "/login" || r.URL.Path == "/login/google" || r.URL.Path == "/login/google/callback" {
		// 	http.Redirect(w, r.WithContext(ctx), "/console", http.StatusTemporaryRedirect)
		// 	return
		// }

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (sm *SessionManager) getGoogleUserInfo(token *oauth2.Token) (*models.GoogleUserInfo, error) {
	userInfoAPIEndpoint := "https://www.googleapis.com/oauth2/v2/userinfo"

	client := cfg.GoogleOAuthConfig.Client(context.Background(), token)
	resp, err := client.Get(userInfoAPIEndpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	userInfo := models.GoogleUserInfo{}
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return nil, fmt.Errorf("failed to decode user info: %w", err)
	}

	return &userInfo, nil
}

// Add helper method for handling Google users:
func (sm *SessionManager) handleGoogleUser(userInfo *models.GoogleUserInfo) (models.User, string, error) {
	user, exists := sm.users[userInfo.Email]
	if !exists {
		user = models.User{
			Username:      userInfo.Email,
			Email:         userInfo.Email,
			Name:          userInfo.Name,
			PasswordHash:  "",
			VerifiedEmail: userInfo.VerifiedEmail,
		}
		if err := sm.CreateUser(user); err != nil {
			return models.User{}, "", fmt.Errorf("creating user: %w", err)
		}
	}

	token, err := sm.generateJWTToken(user)
	if err != nil {
		return models.User{}, "", fmt.Errorf("generating token: %w", err)
	}

	sm.sessions[token] = user.Email
	return user, token, nil
}

// CreateUser creates a new user and stores it in the session manager
func (sm *SessionManager) CreateUser(newUser models.User) error {

	if newUser.PasswordHash != "" {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newUser.PasswordHash), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("failed to hash password: %w", err)
		}
		newUser.PasswordHash = string(hashedPassword)
	}

	sm.users[newUser.Email] = newUser
	return nil
}
