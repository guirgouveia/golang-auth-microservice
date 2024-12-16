# Google SSO with Golang

This project demonstrates how to implement Google Single Sign-On (SSO) in a Golang web application using MongoDB for user storage and JWT for session management.

## Table of Contents

- [Google SSO with Golang](#google-sso-with-golang)
  - [Table of Contents](#table-of-contents)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Configuration](#configuration)
  - [Running the Application](#running-the-application)
  - [API Endpoints](#api-endpoints)
    - [Public Endpoints](#public-endpoints)
    - [Protected Endpoints](#protected-endpoints)
  - [Usage](#usage)
    - [Signup](#signup)
    - [Login](#login)
      - [Local Login](#local-login)
      - [Google Login](#google-login)
    - [Profile](#profile)
    - [Logout](#logout)
  - [License](#license)

## Prerequisites

- Docker
- Docker Compose
- Google Cloud Platform account for OAuth2 credentials

## Installation

1. Clone the repository:

    ```sh
    git clone https://github.com/yourusername/google-sso-golang.git
    cd google-sso-golang
    ```

2. Install dependencies:

    ```sh
    go mod tidy
    ```

## Configuration

1. Create a `.env` file in the root directory and add the following environment variables:

    ```env
    GOOGLE_CLIENT_ID=your-google-client-id
    GOOGLE_CLIENT_SECRET=your-google-client-secret
    GOOGLE_REDIRECT_URL=http://localhost:8080/auth/google/callback
    MONGO_URI=mongodb://mongo:27017
    MONGO_DB_NAME=authdb
    JWT_SECRET_KEY=your-jwt-secret-key
    OAUTH_STATE_STRING=random-string
    PORT=8080
    ```

2. Replace the placeholder values with your actual credentials.

## Running the Application

1. Start the application using Docker Compose:

    ```sh
    docker-compose up --build
    ```

2. Open your browser and navigate to `http://localhost:8080`.

## API Endpoints

### Public Endpoints

- `GET /` - Home page
- `GET /signup` - Signup form
- `POST /signup` - Create a new user
- `GET /login-form` - Login form
- `POST /login` - Local login
- `GET /auth/google` - Initiate Google OAuth2 login
- `GET /auth/google/callback` - Google OAuth2 callback

### Protected Endpoints

- `GET /profile` - User profile (requires JWT)
- `GET /logout` - Logout (requires JWT)

## Usage

### Signup

1. Navigate to `http://localhost:8080/signup`.
2. Fill in the form with your email and password.
3. Submit the form to create a new user.

### Login

#### Local Login

1. Navigate to `http://localhost:8080/login-form`.
2. Fill in the form with your email and password.
3. Submit the form to log in.

#### Google Login

1. Navigate to `http://localhost:8080/auth/google`.
2. You will be redirected to Google for authentication.
3. After successful authentication, you will be redirected back to the application.

### Profile

1. After logging in, navigate to `http://localhost:8080/profile` to view your profile.

### Logout

1. Navigate to `http://localhost:8080/logout` to log out.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.