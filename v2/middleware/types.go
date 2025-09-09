package middleware

import "crypto/ed25519"

// JwtRoleMiddlewareConfig holds the configuration for the JWT role middleware
type jwtRoleMiddlewareConfig struct {
	publicKey  ed25519.PublicKey
	validateIP bool
}

type jwtRoleMiddlewareConfigVionet struct {
	publicKey  ed25519.PublicKey
	validateIP bool
}
