package middleware

import (
	"crypto/ed25519"
	"crypto/sha256"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
)

// FiberNewJwtRoleMiddleware creates middleware using environment variables
// Panics if JWT_SECRET is not set to fail fast on misconfiguration
func FiberNewJwtRoleMiddlewareVionetLegacy(validateIP bool, secret string) *JwtRoleMiddlewareConfigVionet {
	if secret == "" {
		panic("JWT_SECRET is neccesary")
	}

	// Derivar clave pública Ed25519 desde JWT_SECRET
	hash := sha256.Sum256([]byte(secret))
	privateKey := ed25519.NewKeyFromSeed(hash[:])
	publicKey := privateKey.Public().(ed25519.PublicKey)

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
		// Extraer y validar el JWT del header Authorization
		claims, err := config.parseAndValidateJWT(c)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		// Verificación básica de JWT
		if err := config.basicAuth(c, claims); err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		// Verificar el rol del usuario
		if err := config.jwtRoleVerification(c, pass, claims, allowedRoles); err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		return c.Next()
	}
}

// parseAndValidateJWT extrae y valida el JWT del header Authorization
func (config *JwtRoleMiddlewareConfigVionet) parseAndValidateJWT(c *fiber.Ctx) (jwt.MapClaims, error) {
	authHeader := c.Get("Authorization")
	if len(authHeader) < 7 || !strings.HasPrefix(authHeader, "Bearer ") {
		return nil, errMissingAuth
	}

	tokenStr := authHeader[7:] // Más eficiente que TrimPrefix

	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, errInvalidSigning
		}
		return config.publicKey, nil
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

// basicAuth performs basic JWT validation
func (config *JwtRoleMiddlewareConfigVionet) basicAuth(c *fiber.Ctx, claims jwt.MapClaims) error {
	// Verificar la expiración del token
	exp, ok := claims["exp"].(float64)
	if !ok {
		return errInvalidClaims
	}
	if exp < float64(time.Now().Unix()) {
		return errTokenExpired
	}

	// Verificación de IP (opcional)
	if config.validateIP {
		if ip, ok := claims["ip"].(string); !ok || ip != c.IP() {
			return errInvalidIP
		}
	}

	return nil
}

// jwtRoleVerification verifica si el usuario tiene un rol permitido y setea los datos locales si corresponde
func (config *JwtRoleMiddlewareConfigVionet) jwtRoleVerification(c *fiber.Ctx, pass bool, claims jwt.MapClaims, allowedRoles map[string]bool) error {
	// Extraer roles del usuario (puede ser un array)
	userRoles, ok := claims["rol"].([]interface{})
	if !ok {
		return errInvalidRoleClaim
	}

	// Verificar si el usuario tiene al menos uno de los roles permitidos
	hasValidRole := false
	var userRoleStrings []string

	for _, roleInterface := range userRoles {
		if roleStr, ok := roleInterface.(string); ok {
			userRoleStrings = append(userRoleStrings, roleStr)
			if allowedRoles[roleStr] {
				hasValidRole = true
			}
		}
	}

	if !hasValidRole {
		return errInvalidRole
	}

	// Guardar datos en locals si se requiere
	if pass {
		// Intentar obtener cedula desde diferentes claims para compatibilidad
		if cedula, ok := claims["cedula"]; ok {
			c.Locals("cedula", cedula)
		}

		// Guardar el primer rol válido para compatibilidad con v1
		if len(userRoleStrings) > 0 {
			c.Locals("rol", userRoleStrings[0])
		}
	}

	return nil
}
