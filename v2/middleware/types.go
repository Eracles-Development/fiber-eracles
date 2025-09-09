package middleware

import "crypto/ed25519"

// JwtRoleMiddlewareConfig holds the configuration for the JWT role middleware
type JwtRoleMiddlewareConfig struct {
	publicKey  ed25519.PublicKey
	validateIP bool
}

type JwtRoleMiddlewareConfigVionet struct {
	publicKey  ed25519.PublicKey
	validateIP bool
}
