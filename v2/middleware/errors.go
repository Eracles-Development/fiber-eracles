package middleware

import "errors"

// Errores predefinidos para mejor performance
var (
	errMissingAuth      = errors.New("missing or invalid authorization header")
	errInvalidSigning   = errors.New("invalid signing method")
	errInvalidToken     = errors.New("invalid token")
	errInvalidClaims    = errors.New("invalid token claims")
	errTokenExpired     = errors.New("token has expired")
	errInvalidIP        = errors.New("token IP does not match request IP")
	errInvalidRoleClaim = errors.New("invalid role claim")
	errInvalidRole      = errors.New("insufficient permissions")
)
