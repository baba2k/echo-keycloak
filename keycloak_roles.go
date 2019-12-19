package keycloak

import (
	"net/http"

	"github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/thoas/go-funk"
)

type (
	// KeycloakRolesConfig defines the config for the KeycloakRoles roles middleware.
	KeycloakRolesConfig struct {
		// Skipper defines a function to skip middleware.
		Skipper middleware.Skipper

		// BeforeFunc defines a function which is executed just before the middleware.
		BeforeFunc middleware.BeforeFunc

		// SuccessHandler defines a function which is executed for a valid token.
		SuccessHandler KeycloakSuccessHandler

		// ErrorHandler defines a function which is executed for an invalid token.
		// It may be used to define a custom KeycloakRoles error.
		ErrorHandler KeycloakErrorHandler

		// ErrorHandlerWithContext is almost identical to ErrorHandler, but it's passed the current context.
		ErrorHandlerWithContext KeycloakErrorHandlerWithContext

		// KeycloakRoles defines the KeycloakRoles roles having access.
		KeycloakRoles []string

		// TokenContextKey is the context key which stores the keycloak jwt token
		// Optional. Default value "user".
		TokenContextKey string

		// RolesContextKey is the context key which stores the roles as []string
		// Optional. Default value "roles".
		RolesContextKey string
	}
)

// Errors
var (
	ErrClaimsMissing      = echo.NewHTTPError(http.StatusInternalServerError, "no claims in context found")
	ErrRealmAccessMissing = echo.NewHTTPError(http.StatusInternalServerError, "no realm_access in claims found")
	ErrRolesMissing       = echo.NewHTTPError(http.StatusInternalServerError, "no roles in realm_access claim found")
	ErrRolesInvalid       = echo.NewHTTPError(http.StatusForbidden, "invalid roles")
)

var (
	// DefaultKeycloakRolesConfig is the default KeycloakRoles roles middleware config.
	DefaultKeycloakRolesConfig = KeycloakRolesConfig{
		Skipper:         middleware.DefaultSkipper,
		TokenContextKey: "user",
		RolesContextKey: "roles",
	}
)

// KeycloakRoles returns a KeycloakRoles auth middleware.
//
// For valid token, it sets the user in context and calls next handler.
// For invalid roles, it returns "403 - Forbidden" error.
// For missing token in context, it returns "500 - Internal Server Error" error.
func KeycloakRoles(roles []string) echo.MiddlewareFunc {
	c := DefaultKeycloakRolesConfig
	c.KeycloakRoles = roles
	return KeycloakRolesWithConfig(c)
}

// KeycloakRolesWithConfig returns a KeycloakRoles auth middleware with config.
// See: `KeycloakRoles()`.
func KeycloakRolesWithConfig(config KeycloakRolesConfig) echo.MiddlewareFunc {
	// Defaults
	if config.Skipper == nil {
		config.Skipper = DefaultKeycloakRolesConfig.Skipper
	}
	if len(config.KeycloakRoles) == 0 {
		panic("echo: keycloak roles middleware requires keycloak roles")
	}
	if config.TokenContextKey == "" {
		config.TokenContextKey = DefaultKeycloakRolesConfig.TokenContextKey
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if config.Skipper(c) {
				return next(c)
			}

			if config.BeforeFunc != nil {
				config.BeforeFunc(c)
			}

			var err error
			var roles []string
			token := c.Get(DefaultKeycloakRolesConfig.TokenContextKey).(*jwt.Token)
			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok {
				err = ErrClaimsMissing
			} else {
				realmAcces, ok := claims["realm_access"].(map[string]interface{})
				if !ok {
					err = ErrRealmAccessMissing
				} else {
					rolesRaw, ok := realmAcces["roles"].([]interface{})
					if !ok {
						err = ErrRolesMissing
					} else {
						for _, r := range rolesRaw {
							roles = append(roles, r.(string))
						}
						for _, r := range config.KeycloakRoles {
							if !funk.ContainsString(roles, r) {
								err = ErrRolesInvalid
								break
							}
						}
					}
				}
			}
			if err == nil && token.Valid {
				c.Set(config.RolesContextKey, roles)
				if config.SuccessHandler != nil {
					config.SuccessHandler(c)
				}
				return next(c)
			}
			if config.ErrorHandler != nil {
				return config.ErrorHandler(err)
			}
			if config.ErrorHandlerWithContext != nil {
				return config.ErrorHandlerWithContext(err, c)
			}
			return &echo.HTTPError{
				Code:     http.StatusForbidden,
				Message:  ErrRolesInvalid.Error(),
				Internal: err,
			}
		}
	}
}
