# echo-keycloak
Keycloak authorization middleware for echo v4

The echo-keycloak middleware validates a token given by header, query & url param or cookie with a keycloak server token endpoint and adds the token to context as *jwt.Token (default key is "user").

The echo-keycloak-roles middleware validates given roles with keycloak client or user roles and adds all roles to context as []string (default key is "roles").

## General
* echo-keycloak middleware must be executed before echo-keycloak-roles middleware
* Context key of echo-keycloak middleware and echo-keycloak-roles middleware must be equal
* Client and user roles are supported
* The client or user must have *one* of the given roles to get access. Use multiple instances of echo-keycloak-roles middleware if a route requires multiple roles

## Examples
[Simple example](./example/main.go)