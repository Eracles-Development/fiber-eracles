package middleware

import (
	"crypto/ed25519"
	"crypto/sha256"
	"log"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
)

// FiberNewJwtRoleMiddleware creates middleware using environment variables
// Panics if JWT_SECRET is not set to fail fast on misconfiguration
func FiberNewJwtRoleMiddleware(validateIP bool, secret string) *JwtRoleMiddlewareConfig {
	if secret == "" {
		log.Fatal("JWT_SECRET is necessary")
	}

	log.Printf("Initializing JWT middleware with IP validation: %v", validateIP)

	// Derivar clave pública Ed25519 desde JWT_SECRET
	hash := sha256.Sum256([]byte(secret))
	privateKey := ed25519.NewKeyFromSeed(hash[:])
	publicKey := privateKey.Public().(ed25519.PublicKey)

	log.Println("JWT middleware initialized successfully")
	return &JwtRoleMiddlewareConfig{
		publicKey:  publicKey,
		validateIP: validateIP,
	}
}

// Handler returns a Fiber handler that validates JWT tokens and roles
func (config *JwtRoleMiddlewareConfig) Handler(pass bool, roles ...string) fiber.Handler {
	// Pre-computar roles permitidos para evitar allocaciones en cada request
	allowedRoles := make(map[string]bool, len(roles)+1)
	allowedRoles["superadmin"] = true // superadmin siempre tiene acceso

	for _, role := range roles {
		allowedRoles[role] = true
	}

	return func(c *fiber.Ctx) error {
		log.Printf("JWT middleware: Processing request %s %s from IP %s", c.Method(), c.Path(), c.IP())

		// Extraer y validar el JWT del header Authorization
		claims, err := config.parseAndValidateJWT(c)
		if err != nil {
			log.Printf("JWT middleware: JWT parsing failed for %s %s - %v", c.Method(), c.Path(), err)
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		log.Printf("JWT middleware: JWT parsed successfully for %s %s", c.Method(), c.Path())

		// Verificación básica de JWT
		if err := config.basicAuth(c, claims); err != nil {
			log.Printf("JWT middleware: Basic auth failed for %s %s - %v", c.Method(), c.Path(), err)
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		log.Printf("JWT middleware: Basic auth passed for %s %s", c.Method(), c.Path())

		// Verificar el rol del usuario
		if err := config.jwtRoleVerification(c, pass, claims, allowedRoles); err != nil {
			log.Printf("JWT middleware: Role verification failed for %s %s - %v", c.Method(), c.Path(), err)
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		log.Printf("JWT middleware: Authentication successful for %s %s", c.Method(), c.Path())
		return c.Next()
	}
}

// parseAndValidateJWT extrae y valida el JWT del header Authorization
func (config *JwtRoleMiddlewareConfig) parseAndValidateJWT(c *fiber.Ctx) (jwt.MapClaims, error) {
	authHeader := c.Get("Authorization")
	if len(authHeader) < 7 || !strings.HasPrefix(authHeader, "Bearer ") {
		log.Printf("JWT middleware: Missing or invalid authorization header for %s %s", c.Method(), c.Path())
		return nil, errMissingAuth
	}

	tokenStr := authHeader[7:] // Más eficiente que TrimPrefix
	log.Printf("JWT middleware: Extracted token for %s %s", c.Method(), c.Path())

	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
			log.Printf("JWT middleware: Invalid signing method for %s %s", c.Method(), c.Path())
			return nil, errInvalidSigning
		}
		return config.publicKey, nil
	})

	if err != nil || !token.Valid {
		log.Printf("JWT middleware: Token validation failed for %s %s - %v", c.Method(), c.Path(), err)
		return nil, errInvalidToken
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		log.Printf("JWT middleware: Invalid claims format for %s %s", c.Method(), c.Path())
		return nil, errInvalidClaims
	}

	log.Printf("JWT middleware: Token validated successfully for %s %s", c.Method(), c.Path())
	return claims, nil
}

// basicAuth performs basic JWT validation
func (config *JwtRoleMiddlewareConfig) basicAuth(c *fiber.Ctx, claims jwt.MapClaims) error {
	// Verificar la expiración del token
	exp, ok := claims["exp"].(float64)
	if !ok {
		log.Printf("JWT middleware: Missing expiration claim for %s %s", c.Method(), c.Path())
		return errInvalidClaims
	}
	if exp < float64(time.Now().Unix()) {
		log.Printf("JWT middleware: Token expired for %s %s (exp: %f, now: %d)", c.Method(), c.Path(), exp, time.Now().Unix())
		return errTokenExpired
	}

	log.Printf("JWT middleware: Token expiration check passed for %s %s", c.Method(), c.Path())

	// Verificación de IP (opcional)
	if config.validateIP {
		if ip, ok := claims["ip"].(string); !ok || ip != c.IP() {
			log.Printf("JWT middleware: IP validation failed for %s %s (token IP: %s, request IP: %s)", c.Method(), c.Path(), ip, c.IP())
			return errInvalidIP
		}
		log.Printf("JWT middleware: IP validation passed for %s %s", c.Method(), c.Path())
	}

	return nil
}

// jwtRoleVerification verifica si el usuario tiene un rol permitido y setea los datos locales si corresponde
func (config *JwtRoleMiddlewareConfig) jwtRoleVerification(c *fiber.Ctx, pass bool, claims jwt.MapClaims, allowedRoles map[string]bool) error {
	// Extraer roles del usuario (puede ser un array)
	userRoles, ok := claims["rol"].([]interface{})
	if !ok {
		log.Printf("JWT middleware: Invalid role claim format for %s %s", c.Method(), c.Path())
		return errInvalidRoleClaim
	}

	log.Printf("JWT middleware: User roles extracted for %s %s: %v", c.Method(), c.Path(), userRoles)

	// Verificar si el usuario tiene al menos uno de los roles permitidos
	hasValidRole := false
	var userRoleStrings []string

	for _, roleInterface := range userRoles {
		if roleStr, ok := roleInterface.(string); ok {
			userRoleStrings = append(userRoleStrings, roleStr)
			if allowedRoles[roleStr] {
				hasValidRole = true
				log.Printf("JWT middleware: Valid role found for %s %s: %s", c.Method(), c.Path(), roleStr)
			}
		}
	}

	if !hasValidRole {
		log.Printf("JWT middleware: No valid roles found for %s %s. User roles: %v, Allowed roles: %v", c.Method(), c.Path(), userRoleStrings, allowedRoles)
		return errInvalidRole
	}

	// Guardar datos en locals si se requiere
	if pass {
		if email, ok := claims["email"].(string); ok {
			c.Locals("email", email)
			log.Printf("JWT middleware: Email saved to locals for %s %s: %s", c.Method(), c.Path(), email)
		}
	}

	log.Printf("JWT middleware: Role verification successful for %s %s", c.Method(), c.Path())
	return nil
}
