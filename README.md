# echo-keycloak
Keycloak authorization middleware for echo v4

The echo-keycloak middleware validates a token given by header, query & url param or cookie with a keycloak server token endpoint and adds the token to context as *jwt.Token (default key is "user").

The echo-keycloak-roles middleware validates given roles with keycloak client or user roles and adds all roles to context as []string (default key is "roles").

## General
* echo-keycloak middleware must be executed before echo-keycloak-roles middleware
* Context key of echo-keycloak middleware and echo-keycloak-roles middleware must be equal
* Client and user roles are supported
* The client or user must have *one* of the given roles to get access

## Example
```go
package main

import (
	"fmt"
	"net/http"

	"github.com/baba2k/echo-keycloak"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func main() {
	e := echo.New()

	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	restricted := e.Group("/restricted",
		keycloak.Keycloak("http://localhost:8080", "test"))

	restricted.GET("", func(c echo.Context) error {
		return c.String(http.StatusOK, "Hello, World!")
	})

	restricted.GET("/admin", func(c echo.Context) error {
		return c.String(http.StatusOK, fmt.Sprintf("Hello, Admin! My roles are: %+v", c.Get("roles").([]string)))
	}, keycloak.KeycloakRoles([]string{"admin"}))

	e.Logger.Fatal(e.Start(":8080"))
}
```