package keycloak

import (
	"net/http"
	"strings"

	"github.com/Nerzal/gocloak/v4"
	"github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

type (
	// KeycloakRolesConfig defines the config for the KeycloakRoles middleware.
	KeycloakConfig struct {
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

		// KeycloakURL defines the URL of the KeycloakRoles server.
		KeycloakURL string

		// KeycloakRealm defines the realm of the KeycloakRoles server.
		KeycloakRealm string

		// Context key to store user information from the token into context.
		// Optional. Default value "user".
		ContextKey string

		// Claims are extendable claims data defining token content.
		// Optional. Default value jwt.MapClaims
		Claims jwt.Claims

		// TokenLookup is a string in the form of "<source>:<name>" that is used
		// to extract token from the request.
		// Optional. Default value "header:Authorization".
		// Possible values:
		// - "header:<name>"
		// - "query:<name>"
		// - "param:<name>"
		// - "cookie:<name>"
		TokenLookup string

		// AuthScheme to be used in the Authorization header.
		// Optional. Default value "Bearer".
		AuthScheme string

		gocloakClient gocloak.GoCloak
	}

	// KeycloakSuccessHandler defines a function which is executed for a valid token.
	KeycloakSuccessHandler func(echo.Context)

	// KeycloakErrorHandler defines a function which is executed for an invalid token.
	KeycloakErrorHandler func(error) error

	// KeycloakErrorHandlerWithContext is almost identical to KeycloakErrorHandler, but it's passed the current context.
	KeycloakErrorHandlerWithContext func(error, echo.Context) error

	tokenExtractor func(echo.Context) (string, error)
)

// Errors
var (
	ErrTokenMissing = echo.NewHTTPError(http.StatusBadRequest, "missing or malformed token")
)

var (
	// DefaultKeycloakRolesConfig is the default KeycloakRoles auth middleware config.
	DefaultKeycloakConfig = KeycloakConfig{
		Skipper:     middleware.DefaultSkipper,
		ContextKey:  "user",
		TokenLookup: "header:" + echo.HeaderAuthorization,
		AuthScheme:  "Bearer",
		Claims:      jwt.MapClaims{},
	}
)

// KeycloakRoles returns a KeycloakRoles auth middleware.
//
// For valid token, it sets the user in context and calls next handler.
// For invalid token, it returns "401 - Unauthorized" error.
// For missing token, it returns "400 - Bad Request" error.
//
// See `KeycloakRolesConfig.TokenLookup`
func Keycloak(url, realm string) echo.MiddlewareFunc {
	c := DefaultKeycloakConfig
	c.KeycloakURL = url
	c.KeycloakRealm = realm
	return KeycloakWithConfig(c)
}

// KeycloakRolesWithConfig returns a KeycloakRoles auth middleware with config.
// See: `KeycloakRoles()`.
func KeycloakWithConfig(config KeycloakConfig) echo.MiddlewareFunc {
	// Defaults
	if config.Skipper == nil {
		config.Skipper = DefaultKeycloakConfig.Skipper
	}
	if config.KeycloakURL == "" {
		panic("echo: keycloak middleware requires keycloak url")
	}
	if config.ContextKey == "" {
		config.ContextKey = DefaultKeycloakConfig.ContextKey
	}
	if config.Claims == nil {
		config.Claims = DefaultKeycloakConfig.Claims
	}
	if config.TokenLookup == "" {
		config.TokenLookup = DefaultKeycloakConfig.TokenLookup
	}
	if config.AuthScheme == "" {
		config.AuthScheme = DefaultKeycloakConfig.AuthScheme
	}
	config.gocloakClient = gocloak.NewClient(config.KeycloakURL)

	// Initialize
	parts := strings.Split(config.TokenLookup, ":")
	extractor := tokenFromHeader(parts[1], config.AuthScheme)
	switch parts[0] {
	case "query":
		extractor = tokenFromQuery(parts[1])
	case "param":
		extractor = tokenFromParam(parts[1])
	case "cookie":
		extractor = tokenFromCookie(parts[1])
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if config.Skipper(c) {
				return next(c)
			}

			if config.BeforeFunc != nil {
				config.BeforeFunc(c)
			}

			auth, err := extractor(c)
			if err != nil {
				if config.ErrorHandler != nil {
					return config.ErrorHandler(err)
				}

				if config.ErrorHandlerWithContext != nil {
					return config.ErrorHandlerWithContext(err, c)
				}
				return err
			}
			token := new(jwt.Token)
			if _, ok := config.Claims.(jwt.Claims); ok {
				token, err = config.gocloakClient.DecodeAccessTokenCustomClaims(auth, config.KeycloakRealm, config.Claims)
			} else {
				token, config.Claims, err = config.gocloakClient.DecodeAccessToken(auth, config.KeycloakRealm)
			}
			if err == nil && token.Valid {
				c.Set(config.ContextKey, token)
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
				Code:     http.StatusUnauthorized,
				Message:  "invalid or expired token",
				Internal: err,
			}
		}
	}
}

// tokenFromHeader returns a `tokenExtractor` that extracts token from the request header.
func tokenFromHeader(header string, authScheme string) tokenExtractor {
	return func(c echo.Context) (string, error) {
		auth := c.Request().Header.Get(header)
		l := len(authScheme)
		if len(auth) > l+1 && strings.ToLower(auth[:l]) == strings.ToLower(authScheme) {
			return auth[l+1:], nil
		}
		return "", ErrTokenMissing
	}
}

// tokenFromQuery returns a `tokenExtractor` that extracts token from the query string.
func tokenFromQuery(param string) tokenExtractor {
	return func(c echo.Context) (string, error) {
		token := c.QueryParam(param)
		if token == "" {
			return "", ErrTokenMissing
		}
		return token, nil
	}
}

// tokenFromParam returns a `tokenExtractor` that extracts token from the url param string.
func tokenFromParam(param string) tokenExtractor {
	return func(c echo.Context) (string, error) {
		token := c.Param(param)
		if token == "" {
			return "", ErrTokenMissing
		}
		return token, nil
	}
}

// tokenFromCookie returns a `tokenExtractor` that extracts token from the named cookie.
func tokenFromCookie(name string) tokenExtractor {
	return func(c echo.Context) (string, error) {
		cookie, err := c.Cookie(name)
		if err != nil {
			return "", ErrTokenMissing
		}
		return cookie.Value, nil
	}
}
