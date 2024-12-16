package handlers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// -------------------------------------------------------------------
// MODELS
// -------------------------------------------------------------------

type User struct {
	ID       primitive.ObjectID `bson:"_id,omitempty"`
	Email    string             `bson:"email"`
	Password string             `bson:"password"` // hashed password
	GoogleID string             `bson:"googleId"` // stored if user logs in via Google
}

// -------------------------------------------------------------------
// GLOBALS
// -------------------------------------------------------------------

// DB & Collection references
var mongoClient *mongo.Client
var userCollection *mongo.Collection

var googleOauthConfig *oauth2.Config
var oauthStateString = generateRandomString(16)

// For JWT session management
var jwtSecret = []byte("REPLACE_WITH_A_LONG_SECURE_RANDOM_KEY")

func init() {
	// Load environment variables
	err := godotenv.Load()
	if err != nil {
		log.Println("Warning: .env file not found. Falling back to environment vars if set.")
	}

	// Configure MongoDB client
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	mongoURI := os.Getenv("MONGO_URI") // e.g., "mongodb://localhost:27017"
	if mongoURI == "" {
		mongoURI = "mongodb://localhost:27017"
	}
	mongoClient, err = mongo.Connect(ctx, options.Client().ApplyURI(mongoURI))
	if err != nil {
		log.Fatal("Failed to connect to MongoDB: ", err)
	}

	// Create or use an existing database and collection (e.g. "authdb", "users")
	dbName := os.Getenv("MONGO_DB_NAME")
	if dbName == "" {
		dbName = "authdb"
	}
	userCollection = mongoClient.Database(dbName).Collection("users")

	// Set up Google OAuth2 config
	googleOauthConfig = &oauth2.Config{
		ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		RedirectURL:  os.Getenv("GOOGLE_REDIRECT_URL"), // e.g. "http://localhost:8080/auth/google/callback"
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
		Endpoint: google.Endpoint,
	}
}

func New() *http.ServeMux {
	mux := http.NewServeMux()

	// Public routes
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/signup", handleSignup)        // GET/POST
	mux.HandleFunc("/login-form", handleLoginForm) // GET
	mux.HandleFunc("/login", handleLogin)          // POST
	mux.HandleFunc("/auth/google", handleGoogleLogin)
	mux.HandleFunc("/auth/google/callback", handleGoogleCallback)

	// Protected routes (JWT middleware)
	mux.Handle("/profile", jwtMiddleware(http.HandlerFunc(handleProfile)))
	mux.Handle("/logout", jwtMiddleware(http.HandlerFunc(handleLogout)))

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	fmt.Printf("Server running on port %s...\n", port)
	log.Fatal(http.ListenAndServe(":"+port, mux))

	return mux
}

// -------------------------------------------------------------------
// HANDLERS
// -------------------------------------------------------------------

func handleIndex(w http.ResponseWriter, r *http.Request) {
	html := `<html>
	<head><title>Golang Auth (NoSQL & JWT)</title></head>
	<body>
		<h1>Welcome to the Golang Auth Service (MongoDB + JWT + Google OAuth)</h1>
		<ul>
			<li><a href="/login-form">Local Login</a></li>
			<li><a href="/signup">Signup</a></li>
			<li><a href="/auth/google">Login with Google</a></li>
		</ul>
	</body>
	</html>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, html)
}

// handleSignup - GET form or POST to create a new user
func handleSignup(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		html := `<html>
			<head><title>Sign Up</title></head>
			<body>
				<h1>Sign Up</h1>
				<form method="POST" action="/signup">
					<label>Email:</label><br>
					<input type="email" name="email" required><br><br>
					<label>Password:</label><br>
					<input type="password" name="password" required><br><br>
					<button type="submit">Sign Up</button>
				</form>
			</body>
			</html>`
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, html)
		return

	case http.MethodPost:
		email := strings.ToLower(r.FormValue("email"))
		password := r.FormValue("password")

		if email == "" || password == "" {
			http.Error(w, "Invalid email or password", http.StatusBadRequest)
			return
		}

		// Check if user already exists
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		var existing User
		err := userCollection.FindOne(ctx, bson.M{"email": email}).Decode(&existing)
		if err == nil {
			// means user found
			http.Error(w, "User already exists", http.StatusConflict)
			return
		}

		hashedPass, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Failed to hash password", http.StatusInternalServerError)
			return
		}

		newUser := User{
			Email:    email,
			Password: string(hashedPass),
		}

		_, err = userCollection.InsertOne(ctx, newUser)
		if err != nil {
			http.Error(w, "Failed to create user", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/login-form", http.StatusSeeOther)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleLoginForm - GET login form
func handleLoginForm(w http.ResponseWriter, r *http.Request) {
	html := `<html>
	<head><title>Login</title></head>
	<body>
		<h1>Local Login</h1>
		<form method="POST" action="/login">
			<label>Email:</label><br>
			<input type="email" name="email" required><br><br>
			<label>Password:</label><br>
			<input type="password" name="password" required><br><br>
			<button type="submit">Login</button>
		</form>
		<p><a href="/signup">Sign Up</a> | <a href="/auth/google">Login with Google</a></p>
	</body>
	</html>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, html)
}

// handleLogin - POST local login
func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	email := strings.ToLower(r.FormValue("email"))
	password := r.FormValue("password")

	if email == "" || password == "" {
		http.Error(w, "Invalid email or password", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var user User
	err := userCollection.FindOne(ctx, bson.M{"email": email}).Decode(&user)
	if err != nil {
		http.Error(w, "User not found", http.StatusUnauthorized)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		http.Error(w, "Incorrect password", http.StatusUnauthorized)
		return
	}

	// Generate JWT
	tokenString, err := createJWTToken(user.Email)
	if err != nil {
		http.Error(w, "Failed to create token", http.StatusInternalServerError)
		return
	}

	// Set JWT as an HTTP-only cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "jwt_token",
		Value:    tokenString,
		HttpOnly: true,
		Path:     "/",
		Expires:  time.Now().Add(24 * time.Hour),
	})
	http.Redirect(w, r, "/profile", http.StatusSeeOther)
}

// handleGoogleLogin - initiates Google OAuth2 login
func handleGoogleLogin(w http.ResponseWriter, r *http.Request) {
	url := googleOauthConfig.AuthCodeURL(oauthStateString, oauth2.AccessTypeOffline)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// handleGoogleCallback - OAuth2 callback from Google
func handleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	state := r.FormValue("state")
	if state != oauthStateString {
		http.Error(w, "Invalid OAuth state", http.StatusBadRequest)
		return
	}

	code := r.FormValue("code")
	if code == "" {
		http.Error(w, "Code not found", http.StatusBadRequest)
		return
	}

	token, err := googleOauthConfig.Exchange(context.Background(), code)
	if err != nil {
		http.Error(w, "Failed to exchange code: "+err.Error(), http.StatusInternalServerError)
		return
	}

	client := googleOauthConfig.Client(context.Background(), token)
	userInfo, err := fetchGoogleUserInfo(client)
	if err != nil {
		http.Error(w, "Failed to fetch user info: "+err.Error(), http.StatusInternalServerError)
		return
	}

	var googleData struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	}

	if err := json.Unmarshal([]byte(userInfo), &googleData); err != nil {
		http.Error(w, "Failed to parse user info", http.StatusInternalServerError)
		return
	}
	if googleData.Email == "" {
		http.Error(w, "No email found in Google profile", http.StatusInternalServerError)
		return
	}

	// Check if user exists, if not create
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var user User
	err = userCollection.FindOne(ctx, bson.M{"email": strings.ToLower(googleData.Email)}).Decode(&user)
	if err != nil {
		// means user doesn't exist, create new one
		user = User{
			Email:    strings.ToLower(googleData.Email),
			Password: "", // login not used locally
			GoogleID: googleData.ID,
		}
		_, err = userCollection.InsertOne(ctx, user)
		if err != nil {
			http.Error(w, "Failed to create user", http.StatusInternalServerError)
			return
		}
	} else {
		// If user exists but no GoogleID, update
		if user.GoogleID == "" {
			user.GoogleID = googleData.ID
			_, _ = userCollection.UpdateOne(ctx, bson.M{"_id": user.ID}, bson.M{"$set": bson.M{"googleId": googleData.ID}})
		}
	}

	tokenString, err := createJWTToken(googleData.Email)
	if err != nil {
		http.Error(w, "Failed to create token", http.StatusInternalServerError)
		return
	}

	// Set JWT cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "jwt_token",
		Value:    tokenString,
		HttpOnly: true,
		Path:     "/",
		Expires:  time.Now().Add(24 * time.Hour),
	})
	http.Redirect(w, r, "/profile", http.StatusSeeOther)
}

// handleProfile - JWT-protected route
func handleProfile(w http.ResponseWriter, r *http.Request) {
	userEmail := r.Context().Value("user_email").(string)

	// Retrieve the user from DB
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var user User
	if err := userCollection.FindOne(ctx, bson.M{"email": userEmail}).Decode(&user); err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	html := `<html>
	<head><title>Profile</title></head>
	<body>
		<h1>User Profile</h1>
		<p>Email: ` + user.Email + `</p>
		<p>GoogleID: ` + user.GoogleID + `</p>
		<a href="/logout">Logout</a>
	</body>
	</html>`

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, html)
}

// handleLogout - JWT-protected route
func handleLogout(w http.ResponseWriter, r *http.Request) {
	// Invalidate the cookie by setting an expired cookie
	http.SetCookie(w, &http.Cookie{
		Name:    "jwt_token",
		Value:   "",
		Expires: time.Unix(0, 0),
		Path:    "/",
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// -------------------------------------------------------------------
// MIDDLEWARE
// -------------------------------------------------------------------

func jwtMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("jwt_token")
		if err != nil || cookie.Value == "" {
			http.Redirect(w, r, "/login-form", http.StatusSeeOther)
			return
		}

		claims := &jwt.RegisteredClaims{}
		token, err := jwt.ParseWithClaims(cookie.Value, claims, func(t *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})

		if err != nil || !token.Valid {
			http.Redirect(w, r, "/login-form", http.StatusSeeOther)
			return
		}

		if claims.Subject == "" {
			http.Redirect(w, r, "/login-form", http.StatusSeeOther)
			return
		}

		ctx := context.WithValue(r.Context(), "user_email", claims.Subject)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// -------------------------------------------------------------------
// HELPER FUNCTIONS
// -------------------------------------------------------------------

func fetchGoogleUserInfo(client *http.Client) (string, error) {
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// It's safer to read in streaming fashion with io.ReadAll(resp.Body)
	// We'll do a quick approach here
	data := make([]byte, resp.ContentLength)
	_, err = resp.Body.Read(data)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// createJWTToken - builds a JWT token with user email as 'sub' claim
func createJWTToken(userEmail string) (string, error) {
	claims := &jwt.RegisteredClaims{
		Subject:   userEmail,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		Issuer:    "golang-nosql-jwt",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

// generateRandomString - random string for OAuth2 state or any other usage
func generateRandomString(length int) string {
	b := make([]byte, length)
	_, _ = rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}
