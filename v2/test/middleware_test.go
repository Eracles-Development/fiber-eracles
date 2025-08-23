package middleware_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Eracles-Development/fiber-eracles/v2/middleware"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
)

const (
	testSecret = "test-secret-key-for-testing"
	testIP     = "192.168.1.1"
)

// TestData contiene datos de prueba comunes
type TestData struct {
	validToken   string
	expiredToken string
	invalidToken string
	noRoleToken  string
	wrongIPToken string
	privateKey   ed25519.PrivateKey
	publicKey    ed25519.PublicKey
}

// setupTestData inicializa tokens de prueba
func setupTestData() *TestData {
	// Generar clave Ed25519 desde el secret de prueba
	hash := sha256.Sum256([]byte(testSecret))
	privateKey := ed25519.NewKeyFromSeed(hash[:])
	publicKey := privateKey.Public().(ed25519.PublicKey)

	td := &TestData{
		privateKey: privateKey,
		publicKey:  publicKey,
	}

	// Token válido con rol admin
	td.validToken = td.generateToken(jwt.MapClaims{
		"email": "test@example.com",
		"rol":   []interface{}{"admin", "user"},
		"ip":    testIP,
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Unix(),
	})

	// Token expirado - crear con el mismo método pero tiempo expirado
	expiredToken := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
		"email": "test@example.com",
		"rol":   []interface{}{"admin"},
		"ip":    testIP,
		"exp":   time.Now().Add(-time.Hour).Unix(), // Expirado hace 1 hora
		"iat":   time.Now().Add(-2 * time.Hour).Unix(),
	})
	td.expiredToken, _ = expiredToken.SignedString(td.privateKey)

	// Token sin roles
	td.noRoleToken = td.generateToken(jwt.MapClaims{
		"email": "test@example.com",
		"ip":    testIP,
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Unix(),
	})

	// Token con IP incorrecta
	td.wrongIPToken = td.generateToken(jwt.MapClaims{
		"email": "test@example.com",
		"rol":   []interface{}{"admin"},
		"ip":    "10.0.0.1", // IP diferente
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Unix(),
	})

	// Token inválido (firmado con clave diferente)
	_, wrongKey, _ := ed25519.GenerateKey(nil)
	td.invalidToken = generateTokenWithKey(jwt.MapClaims{
		"email": "test@example.com",
		"rol":   []interface{}{"admin"},
		"ip":    testIP,
		"exp":   time.Now().Add(time.Hour).Unix(),
	}, wrongKey)

	return td
}

// generateToken genera un token JWT válido para testing
func (td *TestData) generateToken(claims jwt.MapClaims) string {
	return generateTokenWithKey(claims, td.privateKey)
}

// generateTokenWithKey genera un token con una clave específica
func generateTokenWithKey(claims jwt.MapClaims, key ed25519.PrivateKey) string {
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tokenString, err := token.SignedString(key)
	if err != nil {
		panic(fmt.Sprintf("Error generating test token: %v", err))
	}
	return tokenString
}

// createTestApp crea una aplicación Fiber para testing
func createTestApp(middleware func(c *fiber.Ctx) error) *fiber.App {
	app := fiber.New(fiber.Config{
		EnableTrustedProxyCheck: true,
		TrustedProxies:          []string{"0.0.0.0/0"}, // Trust all proxies for testing
		ProxyHeader:             fiber.HeaderXForwardedFor,
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": err.Error(),
			})
		},
	})

	app.Use(middleware)

	app.Get("/test", func(c *fiber.Ctx) error {
		email := c.Locals("email")
		return c.JSON(fiber.Map{
			"success": true,
			"email":   email,
		})
	})

	return app
}

// makeRequest realiza una request HTTP de prueba
func makeRequest(app *fiber.App, token string, remoteAddr string) (*http.Response, []byte, error) {
	req, err := http.NewRequest("GET", "/test", nil)
	if err != nil {
		return nil, nil, err
	}

	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	if remoteAddr != "" {
		req.Header.Set("X-Forwarded-For", remoteAddr)
		req.Header.Set("X-Real-IP", remoteAddr)
		req.RemoteAddr = remoteAddr + ":12345"
	}

	// Configurar Fiber con trust proxy para que use X-Forwarded-For
	resp, err := app.Test(req, -1) // -1 indica timeout infinito
	if err != nil {
		return nil, nil, err
	}

	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()

	return resp, body, err
}

// TestFiberNewJwtRoleMiddleware tests the middleware constructor
func TestFiberNewJwtRoleMiddleware(t *testing.T) {
	// Guardar valor original del env
	originalSecret := os.Getenv("JWT_SECRET")
	defer os.Setenv("JWT_SECRET", originalSecret)

	t.Run("ValidSecret", func(t *testing.T) {
		os.Setenv("JWT_SECRET", testSecret)

		config := middleware.FiberNewJwtRoleMiddleware(true)
		if config == nil {
			t.Fatal("Expected config to be created, got nil")
		}
	})

	t.Run("MissingSecret", func(t *testing.T) {
		os.Unsetenv("JWT_SECRET")

		defer func() {
			if r := recover(); r == nil {
				t.Fatal("Expected panic when JWT_SECRET is missing")
			}
		}()

		middleware.FiberNewJwtRoleMiddleware(false)
	})

	t.Run("EmptySecret", func(t *testing.T) {
		os.Setenv("JWT_SECRET", "")

		defer func() {
			if r := recover(); r == nil {
				t.Fatal("Expected panic when JWT_SECRET is empty")
			}
		}()

		middleware.FiberNewJwtRoleMiddleware(true)
	})
}

// TestMiddlewareHandler tests the main middleware handler
func TestMiddlewareHandler(t *testing.T) {
	os.Setenv("JWT_SECRET", testSecret)
	defer os.Unsetenv("JWT_SECRET")

	td := setupTestData()
	config := middleware.FiberNewJwtRoleMiddleware(false)

	t.Run("ValidTokenWithRole", func(t *testing.T) {
		handler := config.Handler(true, "admin")
		app := createTestApp(handler)

		resp, body, err := makeRequest(app, td.validToken, testIP)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d. Body: %s", resp.StatusCode, body)
		}

		var response map[string]interface{}
		if err := json.Unmarshal(body, &response); err != nil {
			t.Fatalf("Failed to unmarshal response: %v", err)
		}

		if response["success"] != true {
			t.Error("Expected success to be true")
		}

		if response["email"] != "test@example.com" {
			t.Errorf("Expected email to be test@example.com, got %v", response["email"])
		}
	})

	t.Run("ValidTokenWithSuperadmin", func(t *testing.T) {
		superadminToken := td.generateToken(jwt.MapClaims{
			"email": "superadmin@example.com",
			"rol":   []interface{}{"superadmin"},
			"ip":    testIP,
			"exp":   time.Now().Add(time.Hour).Unix(),
		})

		handler := config.Handler(true, "different-role")
		app := createTestApp(handler)

		resp, _, err := makeRequest(app, superadminToken, testIP)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200 for superadmin, got %d", resp.StatusCode)
		}
	})

	t.Run("NoAuthorizationHeader", func(t *testing.T) {
		handler := config.Handler(false, "admin")
		app := createTestApp(handler)

		resp, body, err := makeRequest(app, "", testIP)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}

		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("Expected status 401, got %d. Body: %s", resp.StatusCode, body)
		}

		var response map[string]interface{}
		if err := json.Unmarshal(body, &response); err != nil {
			t.Fatalf("Failed to unmarshal response: %v", err)
		}

		if !strings.Contains(response["error"].(string), "missing or invalid authorization header") {
			t.Error("Expected missing authorization header error")
		}
	})

	t.Run("InvalidAuthorizationFormat", func(t *testing.T) {
		handler := config.Handler(false, "admin")
		app := createTestApp(handler)

		req, _ := http.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Invalid format")

		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}

		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("Expected status 401, got %d", resp.StatusCode)
		}
	})

	t.Run("ExpiredToken", func(t *testing.T) {
		handler := config.Handler(false, "admin")
		app := createTestApp(handler)

		resp, body, err := makeRequest(app, td.expiredToken, testIP)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}

		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("Expected status 401, got %d. Body: %s", resp.StatusCode, body)
		}

		var response map[string]interface{}
		if err := json.Unmarshal(body, &response); err != nil {
			t.Fatalf("Failed to unmarshal response: %v", err)
		}

		errorMsg, ok := response["error"].(string)
		if !ok || (!strings.Contains(errorMsg, "token has expired") && !strings.Contains(errorMsg, "invalid token")) {
			t.Errorf("Expected token expired or invalid token error, got: %v", response["error"])
		}
	})

	t.Run("InvalidToken", func(t *testing.T) {
		handler := config.Handler(false, "admin")
		app := createTestApp(handler)

		resp, body, err := makeRequest(app, td.invalidToken, testIP)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}

		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("Expected status 401, got %d. Body: %s", resp.StatusCode, body)
		}
	})

	t.Run("InvalidRole", func(t *testing.T) {
		handler := config.Handler(false, "different-role")
		app := createTestApp(handler)

		resp, body, err := makeRequest(app, td.validToken, testIP)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}

		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("Expected status 401, got %d. Body: %s", resp.StatusCode, body)
		}

		var response map[string]interface{}
		if err := json.Unmarshal(body, &response); err != nil {
			t.Fatalf("Failed to unmarshal response: %v", err)
		}

		errorMsg, ok := response["error"].(string)
		if !ok || !strings.Contains(errorMsg, "insufficient permissions") {
			t.Errorf("Expected insufficient permissions error, got: %v", response["error"])
		}
	})

	t.Run("NoRoleClaim", func(t *testing.T) {
		handler := config.Handler(false, "admin")
		app := createTestApp(handler)

		resp, body, err := makeRequest(app, td.noRoleToken, testIP)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}

		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("Expected status 401, got %d. Body: %s", resp.StatusCode, body)
		}

		var response map[string]interface{}
		if err := json.Unmarshal(body, &response); err != nil {
			t.Fatalf("Failed to unmarshal response: %v", err)
		}

		errorMsg, ok := response["error"].(string)
		if !ok || !strings.Contains(errorMsg, "invalid role claim") {
			t.Errorf("Expected invalid role claim error, got: %v", response["error"])
		}
	})
}

// TestIPValidation tests IP validation functionality
func TestIPValidation(t *testing.T) {
	os.Setenv("JWT_SECRET", testSecret)
	defer os.Unsetenv("JWT_SECRET")

	td := setupTestData()

	t.Run("IPValidationEnabled_CorrectIP", func(t *testing.T) {
		config := middleware.FiberNewJwtRoleMiddleware(true)
		handler := config.Handler(false, "admin")
		app := createTestApp(handler)

		resp, _, err := makeRequest(app, td.validToken, testIP)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}
	})

	t.Run("IPValidationEnabled_WrongIP", func(t *testing.T) {
		config := middleware.FiberNewJwtRoleMiddleware(true)
		handler := config.Handler(false, "admin")
		app := createTestApp(handler)

		resp, body, err := makeRequest(app, td.wrongIPToken, testIP)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}

		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("Expected status 401, got %d. Body: %s", resp.StatusCode, body)
		}

		var response map[string]interface{}
		if err := json.Unmarshal(body, &response); err != nil {
			t.Fatalf("Failed to unmarshal response: %v", err)
		}

		errorMsg, ok := response["error"].(string)
		if !ok || !strings.Contains(errorMsg, "token IP does not match request IP") {
			t.Errorf("Expected IP mismatch error, got: %v", response["error"])
		}
	})

	t.Run("IPValidationDisabled_WrongIP", func(t *testing.T) {
		config := middleware.FiberNewJwtRoleMiddleware(false)
		handler := config.Handler(false, "admin")
		app := createTestApp(handler)

		resp, _, err := makeRequest(app, td.wrongIPToken, testIP)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200 when IP validation disabled, got %d", resp.StatusCode)
		}
	})
}

// TestMultipleRoles tests handling of multiple roles
func TestMultipleRoles(t *testing.T) {
	os.Setenv("JWT_SECRET", testSecret)
	defer os.Unsetenv("JWT_SECRET")

	td := setupTestData()
	config := middleware.FiberNewJwtRoleMiddleware(false)

	t.Run("MultipleAllowedRoles", func(t *testing.T) {
		handler := config.Handler(false, "admin", "user", "moderator")
		app := createTestApp(handler)

		resp, _, err := makeRequest(app, td.validToken, testIP)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}
	})

	t.Run("UserWithMultipleRoles", func(t *testing.T) {
		multiRoleToken := td.generateToken(jwt.MapClaims{
			"email": "multi@example.com",
			"rol":   []interface{}{"user", "moderator", "editor"},
			"ip":    testIP,
			"exp":   time.Now().Add(time.Hour).Unix(),
		})

		handler := config.Handler(false, "editor")
		app := createTestApp(handler)

		resp, _, err := makeRequest(app, multiRoleToken, testIP)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}
	})
}

// TestLocalsPassthrough tests the pass parameter functionality
func TestLocalsPassthrough(t *testing.T) {
	os.Setenv("JWT_SECRET", testSecret)
	defer os.Unsetenv("JWT_SECRET")

	td := setupTestData()
	config := middleware.FiberNewJwtRoleMiddleware(false)

	t.Run("PassEnabled", func(t *testing.T) {
		handler := config.Handler(true, "admin")
		app := createTestApp(handler)

		resp, body, err := makeRequest(app, td.validToken, testIP)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}

		var response map[string]interface{}
		if err := json.Unmarshal(body, &response); err != nil {
			t.Fatalf("Failed to unmarshal response: %v", err)
		}

		if response["email"] != "test@example.com" {
			t.Errorf("Expected email to be passed to locals, got %v", response["email"])
		}
	})

	t.Run("PassDisabled", func(t *testing.T) {
		handler := config.Handler(false, "admin")
		app := createTestApp(handler)

		resp, body, err := makeRequest(app, td.validToken, testIP)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}

		var response map[string]interface{}
		if err := json.Unmarshal(body, &response); err != nil {
			t.Fatalf("Failed to unmarshal response: %v", err)
		}

		if response["email"] != nil {
			t.Error("Expected email to not be passed to locals when pass=false")
		}
	})
}

// TestEdgeCases tests various edge cases
func TestEdgeCases(t *testing.T) {
	os.Setenv("JWT_SECRET", testSecret)
	defer os.Unsetenv("JWT_SECRET")

	td := setupTestData()
	config := middleware.FiberNewJwtRoleMiddleware(false)

	t.Run("EmptyRolesList", func(t *testing.T) {
		handler := config.Handler(false) // No roles specified
		app := createTestApp(handler)

		// Solo superadmin debería pasar
		superadminToken := td.generateToken(jwt.MapClaims{
			"email": "superadmin@example.com",
			"rol":   []interface{}{"superadmin"},
			"ip":    testIP,
			"exp":   time.Now().Add(time.Hour).Unix(),
		})

		resp, _, err := makeRequest(app, superadminToken, testIP)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200 for superadmin with empty roles list, got %d", resp.StatusCode)
		}

		// Token normal debería fallar
		resp, _, err = makeRequest(app, td.validToken, testIP)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}

		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("Expected status 401 for normal user with empty roles list, got %d", resp.StatusCode)
		}
	})

	t.Run("MalformedJWT", func(t *testing.T) {
		handler := config.Handler(false, "admin")
		app := createTestApp(handler)

		malformedTokens := []string{
			"not.a.jwt",
			"invalid-jwt-format",
			"header.payload", // Missing signature
			"",               // Empty token
		}

		for _, token := range malformedTokens {
			resp, _, err := makeRequest(app, token, testIP)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}

			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("Expected status 401 for malformed token '%s', got %d", token, resp.StatusCode)
			}
		}
	})

	t.Run("InvalidClaimsTypes", func(t *testing.T) {
		handler := config.Handler(false, "admin")
		app := createTestApp(handler)

		// Token con claims de tipo incorrecto
		invalidClaimsToken := td.generateToken(jwt.MapClaims{
			"email": 12345,   // Should be string
			"rol":   "admin", // Should be array
			"ip":    testIP,
			"exp":   "invalid", // Should be number
		})

		resp, _, err := makeRequest(app, invalidClaimsToken, testIP)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}

		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("Expected status 401 for invalid claims types, got %d", resp.StatusCode)
		}
	})
}

// Benchmark tests
func BenchmarkMiddlewareValidRequest(b *testing.B) {
	os.Setenv("JWT_SECRET", testSecret)
	defer os.Unsetenv("JWT_SECRET")

	td := setupTestData()
	config := middleware.FiberNewJwtRoleMiddleware(false)
	handler := config.Handler(true, "admin")
	app := createTestApp(handler)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			resp, _, err := makeRequest(app, td.validToken, testIP)
			if err != nil {
				b.Fatalf("Request failed: %v", err)
			}
			if resp.StatusCode != http.StatusOK {
				b.Fatalf("Expected status 200, got %d", resp.StatusCode)
			}
		}
	})
}

func BenchmarkMiddlewareInvalidRequest(b *testing.B) {
	os.Setenv("JWT_SECRET", testSecret)
	defer os.Unsetenv("JWT_SECRET")

	td := setupTestData()
	config := middleware.FiberNewJwtRoleMiddleware(false)
	handler := config.Handler(false, "admin")
	app := createTestApp(handler)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			resp, _, err := makeRequest(app, td.expiredToken, testIP)
			if err != nil {
				b.Fatalf("Request failed: %v", err)
			}
			if resp.StatusCode != http.StatusUnauthorized {
				b.Fatalf("Expected status 401, got %d", resp.StatusCode)
			}
		}
	})
}
