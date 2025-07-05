package middleware

import "errors"

// Constantes para mensajes de error (evita allocaciones repetidas)
const (
	ErrMissingAuth      = "unauthorized - missing or invalid authorization header"
	ErrInvalidSigning   = "unauthorized - invalid signing method"
	ErrInvalidToken     = "unauthorized - invalid token"
	ErrInvalidClaims    = "unauthorized - invalid claims"
	ErrTokenExpired     = "unauthorized - token expired"
	ErrInvalidIP        = "unauthorized - invalid ip"
	ErrUserNotVerif     = "unauthorized - user not verified"
	ErrInvalidRole      = "unauthorized - invalid role"
	ErrInvalidRoleClaim = "unauthorized - invalid role claim"
)

// Variables de error reutilizables
var (
	errMissingAuth      = errors.New(ErrMissingAuth)
	errInvalidSigning   = errors.New(ErrInvalidSigning)
	errInvalidToken     = errors.New(ErrInvalidToken)
	errInvalidClaims    = errors.New(ErrInvalidClaims)
	errTokenExpired     = errors.New(ErrTokenExpired)
	errInvalidIP        = errors.New(ErrInvalidIP)
	errUserNotVerif     = errors.New(ErrUserNotVerif)
	errInvalidRole      = errors.New(ErrInvalidRole)
	errInvalidRoleClaim = errors.New(ErrInvalidRoleClaim)
)
