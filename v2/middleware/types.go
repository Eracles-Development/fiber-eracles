package middleware

// JwtRoleMiddlewareConfig holds the configuration for the JWT role middleware
type jwtRoleMiddlewareConfig struct {
	secret     string
	validateIP bool // Nueva opción para hacer la validación de IP opcional
}
