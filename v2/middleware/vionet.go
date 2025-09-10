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
func FiberNewJwtRoleMiddlewareVionetLegacy(validateIP bool, secret string) *JwtRoleMiddlewareConfigVionet {
	if secret == "" {
		log.Fatal("JWT_SECRET is necessary")
	}

	log.Printf("Initializing Vionet JWT middleware with IP validation: %v", validateIP)

	// Derivar clave pública Ed25519 desde JWT_SECRET
	hash := sha256.Sum256([]byte(secret))
	privateKey := ed25519.NewKeyFromSeed(hash[:])
	publicKey := privateKey.Public().(ed25519.PublicKey)

	log.Println("Vionet JWT middleware initialized successfully")
	return &JwtRoleMiddlewareConfigVionet{
		publicKey:  publicKey,
		validateIP: validateIP,
	}
}

// Handler returns a Fiber handler that validates JWT tokens and roles
func (config *JwtRoleMiddlewareConfigVionet) HandlerVionet(pass bool, roles ...string) fiber.Handler {
	// Pre-computar roles permitidos para evitar allocaciones en cada request
	allowedRoles := make(map[string]bool, len(roles)+1)
	allowedRoles["superadmin"] = true // superadmin siempre tiene acceso

	for _, role := range roles {
		allowedRoles[role] = true
	}

	return func(c *fiber.Ctx) error {
		log.Printf("Vionet JWT middleware: Processing request %s %s from IP %s", c.Method(), c.Path(), c.IP())

		// Extraer y validar el JWT del header Authorization
		claims, err := config.parseAndValidateJWT(c)
		if err != nil {
			log.Printf("Vionet JWT middleware: JWT parsing failed for %s %s - %v", c.Method(), c.Path(), err)
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		log.Printf("Vionet JWT middleware: JWT parsed successfully for %s %s", c.Method(), c.Path())

		// Verificación básica de JWT
		if err := config.basicAuth(c, claims); err != nil {
			log.Printf("Vionet JWT middleware: Basic auth failed for %s %s - %v", c.Method(), c.Path(), err)
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		log.Printf("Vionet JWT middleware: Basic auth passed for %s %s", c.Method(), c.Path())

		// Verificar el rol del usuario
		if err := config.jwtRoleVerification(c, pass, claims, allowedRoles); err != nil {
			log.Printf("Vionet JWT middleware: Role verification failed for %s %s - %v", c.Method(), c.Path(), err)
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		log.Printf("Vionet JWT middleware: Authentication successful for %s %s", c.Method(), c.Path())
		return c.Next()
	}
}

// parseAndValidateJWT extrae y valida el JWT del header Authorization
func (config *JwtRoleMiddlewareConfigVionet) parseAndValidateJWT(c *fiber.Ctx) (jwt.MapClaims, error) {
	authHeader := c.Get("Authorization")
	if len(authHeader) < 7 || !strings.HasPrefix(authHeader, "Bearer ") {
		log.Printf("Vionet JWT middleware: Missing or invalid authorization header for %s %s", c.Method(), c.Path())
		return nil, errMissingAuth
	}

	tokenStr := authHeader[7:] // Más eficiente que TrimPrefix
	log.Printf("Vionet JWT middleware: Extracted token for %s %s", c.Method(), c.Path())

	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
			log.Printf("Vionet JWT middleware: Invalid signing method for %s %s", c.Method(), c.Path())
			return nil, errInvalidSigning
		}
		return config.publicKey, nil
	})

	if err != nil || !token.Valid {
		log.Printf("Vionet JWT middleware: Token validation failed for %s %s - %v", c.Method(), c.Path(), err)
		return nil, errInvalidToken
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		log.Printf("Vionet JWT middleware: Invalid claims format for %s %s", c.Method(), c.Path())
		return nil, errInvalidClaims
	}

	log.Printf("Vionet JWT middleware: Token validated successfully for %s %s", c.Method(), c.Path())
	return claims, nil
}

// basicAuth performs basic JWT validation
func (config *JwtRoleMiddlewareConfigVionet) basicAuth(c *fiber.Ctx, claims jwt.MapClaims) error {
	// Verificar la expiración del token
	exp, ok := claims["exp"].(float64)
	if !ok {
		log.Printf("Vionet JWT middleware: Missing expiration claim for %s %s", c.Method(), c.Path())
		return errInvalidClaims
	}
	if exp < float64(time.Now().Unix()) {
		log.Printf("Vionet JWT middleware: Token expired for %s %s (exp: %f, now: %d)", c.Method(), c.Path(), exp, time.Now().Unix())
		return errTokenExpired
	}

	log.Printf("Vionet JWT middleware: Token expiration check passed for %s %s", c.Method(), c.Path())

	// Verificación de IP (opcional)
	if config.validateIP {
		if ip, ok := claims["ip"].(string); !ok || ip != c.IP() {
			log.Printf("Vionet JWT middleware: IP validation failed for %s %s (token IP: %s, request IP: %s)", c.Method(), c.Path(), ip, c.IP())
			return errInvalidIP
		}
		log.Printf("Vionet JWT middleware: IP validation passed for %s %s", c.Method(), c.Path())
	}

	return nil
}

// jwtRoleVerification verifica si el usuario tiene un rol permitido y setea los datos locales si corresponde
func (config *JwtRoleMiddlewareConfigVionet) jwtRoleVerification(c *fiber.Ctx, pass bool, claims jwt.MapClaims, allowedRoles map[string]bool) error {
	// Extraer roles del usuario (puede ser un array)
	userRoles, ok := claims["rol"].([]interface{})
	if !ok {
		log.Printf("Vionet JWT middleware: Invalid role claim format for %s %s", c.Method(), c.Path())
		return errInvalidRoleClaim
	}

	log.Printf("Vionet JWT middleware: User roles extracted for %s %s: %v", c.Method(), c.Path(), userRoles)

	// Verificar si el usuario tiene al menos uno de los roles permitidos
	hasValidRole := false
	var userRoleStrings []string

	for _, roleInterface := range userRoles {
		if roleStr, ok := roleInterface.(string); ok {
			userRoleStrings = append(userRoleStrings, roleStr)
			if allowedRoles[roleStr] {
				hasValidRole = true
				log.Printf("Vionet JWT middleware: Valid role found for %s %s: %s", c.Method(), c.Path(), roleStr)
			}
		}
	}

	if !hasValidRole {
		log.Printf("Vionet JWT middleware: No valid roles found for %s %s. User roles: %v, Allowed roles: %v", c.Method(), c.Path(), userRoleStrings, allowedRoles)
		return errInvalidRole
	}

	// Guardar datos en locals si se requiere
	if pass {
		// Intentar obtener cedula desde diferentes claims para compatibilidad
		if cedula, ok := claims["cedula"]; ok {
			c.Locals("cedula", cedula)
			log.Printf("Vionet JWT middleware: Cedula saved to locals for %s %s: %v", c.Method(), c.Path(), cedula)
		}

		// Guardar el primer rol válido para compatibilidad con v1
		if len(userRoleStrings) > 0 {
			c.Locals("rol", userRoleStrings[0])
			log.Printf("Vionet JWT middleware: Role saved to locals for %s %s: %s", c.Method(), c.Path(), userRoleStrings[0])
		}
	}

	log.Printf("Vionet JWT middleware: Role verification successful for %s %s", c.Method(), c.Path())
	return nil
}
