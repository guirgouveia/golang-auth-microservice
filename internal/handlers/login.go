package handlers

import (
	"net/http"
	"text/template"
)

func loginPage(w http.ResponseWriter, r *http.Request) {
	loginTemplate.Execute(w, nil)
}

var loginTemplate = template.Must(template.New("login").Parse(`
<!DOCTYPE html>
<html>
<head>
	<title>Login Page</title>
</head>
<body>
	<h2>Login</h2>
	<form action="/auth/login" method="post">
		<label for="username">Username:</label>
		<input type="text" id="username" name="username" required><br>
		<label for="password">Password:</label>
		<input type="password" id="password" name="password" required><br>
		<input type="submit" value="Login">
	</form>
</body>
</html>
`))
