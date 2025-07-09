package middleware

import (
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
)

// JwtRoleMiddlewareConfig holds the configuration for the JWT role middleware
type JwtRoleMiddlewareConfig struct {
	devops bool
	secret string
}

// NewJwtRoleMiddleware creates a new JWT role middleware with the specified configuration
func NewJwtRoleMiddleware(devops bool, secret string) *JwtRoleMiddlewareConfig {
	return &JwtRoleMiddlewareConfig{
		devops: devops,
		secret: secret,
	}
}

// Handler returns a Fiber handler that validates JWT tokens and roles
func (config *JwtRoleMiddlewareConfig) Handler(pass bool, role ...string) fiber.Handler {
	// Pre-computar roles permitidos para evitar allocaciones en cada request
	allowedRoles := make(map[string]bool, len(role)+3)
	allowedRoles["superadmin"] = true

	hasSpecialRoles := false
	for _, r := range role {
		allowedRoles[r] = true
		if r == "conductor" || r == "dueño" {
			hasSpecialRoles = true
		}
	}

	// Añadir owner_driver si hay roles especiales
	if hasSpecialRoles {
		allowedRoles["owner_driver"] = true
	}

	return func(c *fiber.Ctx) error {
		// Extraer y validar el JWT del header Authorization
		claims, err := parseAndValidateJWT(c, config.secret)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		// Verificación básica de JWT
		err = basicAuth(c, claims, config.devops)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		// Verificar el rol del usuario
		if err := jwtRolVerification(c, pass, claims, allowedRoles); err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		return c.Next()
	}
}

// parseAndValidateJWT extrae y valida el JWT del header Authorization
func parseAndValidateJWT(c *fiber.Ctx, secret string) (jwt.MapClaims, error) {
	authHeader := c.Get("Authorization")
	if len(authHeader) < 7 || !strings.HasPrefix(authHeader, "Bearer ") {
		return nil, errMissingAuth
	}

	tokenStr := authHeader[7:] // Más eficiente que TrimPrefix
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errInvalidSigning
		}
		return []byte(secret), nil
	})

	if err != nil || !token.Valid {
		return nil, errInvalidToken
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errInvalidClaims
	}

	return claims, nil
}

func basicAuth(c *fiber.Ctx, claims jwt.MapClaims, devops bool) error {
	// Verificar la expiración del token
	exp, ok := claims["exp"].(float64)
	if !ok {
		return errInvalidClaims
	}
	if exp < float64(time.Now().Unix()) {
		return errTokenExpired
	}

	// Verificación de IP
	if ip, ok := claims["ip"].(string); !ok || ip != c.IP() {
		return errInvalidIP
	}

	// Verificar si el usuario ha sido verificado
	if !devops {
		if verif, ok := claims["verif"].(bool); !ok || !verif {
			return errUserNotVerif
		}
	}

	return nil
}

// jwtRolVerification verifica si el usuario tiene un rol permitido y setea los datos locales si corresponde
func jwtRolVerification(c *fiber.Ctx, pass bool, claims jwt.MapClaims, allowedRoles map[string]bool) error {
	userRole, ok := claims["rol"].(string)
	if !ok {
		return errInvalidRoleClaim
	}

	if !allowedRoles[userRole] {
		return errInvalidRole
	}

	if pass {
		if cedula, ok := claims["cedula"]; ok {
			c.Locals("cedula", cedula)
		}
		c.Locals("rol", userRole)
	}

	return nil
}
