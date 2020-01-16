package main

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/baba2k/echo-keycloak"
	"github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func main() {
	e := echo.New()

	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	restricted := e.Group("/restricted",
		// init echo-keycloak middleware with keycloak host and realm
		keycloak.Keycloak("http://localhost:8080", "test"))

	restricted.GET("", func(c echo.Context) error {
		token := c.Get("user").(*jwt.Token)
		claims := token.Claims.(jwt.MapClaims)
		prettyJSONClaims, _ := json.MarshalIndent(claims, "", "   ")
		return c.String(http.StatusOK, fmt.Sprintf(
			"Hello, User! Your claims are:\n%+v\n", string(prettyJSONClaims)))
	})

	restricted.GET("/admin", func(c echo.Context) error {
		return c.String(http.StatusOK,
			fmt.Sprintf("Hello, Admin! Your roles are: %+v\n",
				c.Get("roles").([]string)))
		// init echo-keycloak-roles middleware with role "admin"
	}, keycloak.KeycloakRoles([]string{"admin"}))

	e.Logger.Fatal(e.Start(":8080"))
}
