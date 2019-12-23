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
		// init echo-keycloak middleware with keycloak host and realm
		keycloak.Keycloak("http://localhost:8080", "test"))

	restricted.GET("", func(c echo.Context) error {
		return c.String(http.StatusOK, "Hello, World!")
	})

	restricted.GET("/admin", func(c echo.Context) error {
		return c.String(http.StatusOK,
			fmt.Sprintf("Hello, Admin! My roles are: %+v",
				c.Get("roles").([]string)))
		// init echo-keycloak-roles middleware with role "admin"
	}, keycloak.KeycloakRoles([]string{"admin"}))

	e.Logger.Fatal(e.Start(":8080"))
}
