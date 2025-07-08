package middleware_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Eracles-Development/fiber-eracles/v1/middleware"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
)

const (
	testSecret = "test-secret-key"
	testIP     = "0.0.0.0" // Fiber devuelve 0.0.0.0 en tests
)

type testClaims struct {
	Cedula string `json:"cedula"`
	Rol    string `json:"rol"`
	IP     string `json:"ip"`
	Verif  bool   `json:"verif"`
	jwt.RegisteredClaims
}

// generateTestJWT creates a JWT token for testing purposes
func generateTestJWT(cedula, rol, ip string, verif bool, expTime time.Time) (string, error) {
	claims := testClaims{
		Cedula: cedula,
		Rol:    rol,
		IP:     ip,
		Verif:  verif,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expTime),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(testSecret))
}

// createTestApp creates a Fiber app for testing
func createTestApp(middlewareHandler fiber.Handler) *fiber.App {
	app := fiber.New()
	app.Use(middlewareHandler)
	app.Get("/test", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"message": "success",
			"cedula":  c.Locals("cedula"),
			"rol":     c.Locals("rol"),
		})
	})
	return app
}

// createTestRequest creates an HTTP request for testing
func createTestRequest(method, path, authHeader string) *http.Request {
	req := httptest.NewRequest(method, path, nil)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	req.Header.Set("X-Forwarded-For", testIP)
	return req
}

// Helper functions for assertions
func assertEqual(t *testing.T, expected, actual interface{}, msg ...string) {
	t.Helper()
	if expected != actual {
		message := fmt.Sprintf("Expected %v, got %v", expected, actual)
		if len(msg) > 0 {
			message = fmt.Sprintf("%s: %s", msg[0], message)
		}
		t.Fatalf("%s", message)
	}
}

func assertNoError(t *testing.T, err error, msg ...string) {
	t.Helper()
	if err != nil {
		message := fmt.Sprintf("Expected no error, got %v", err)
		if len(msg) > 0 {
			message = fmt.Sprintf("%s: %s", msg[0], message)
		}
		t.Fatalf("%s", message)
	}
}

func assertContains(t *testing.T, str, substr string, msg ...string) {
	t.Helper()
	if !strings.Contains(str, substr) {
		message := fmt.Sprintf("Expected string to contain '%s', got '%s'", substr, str)
		if len(msg) > 0 {
			message = fmt.Sprintf("%s: %s", msg[0], message)
		}
		t.Fatalf("%s", message)
	}
}

// TestJwtRoleMiddleware_Success tests successful authentication scenarios
func TestJwtRoleMiddleware_Success(t *testing.T) {
	tests := []struct {
		name         string
		pass         bool
		devops       bool
		roles        []string
		userRole     string
		userCedula   string
		userVerif    bool
		expectedCode int
	}{
		{
			name:         "Valid token with allowed role",
			pass:         false,
			devops:       false,
			roles:        []string{"admin"},
			userRole:     "admin",
			userCedula:   "12345678",
			userVerif:    true,
			expectedCode: 200,
		},
		{
			name:         "Superadmin always allowed",
			pass:         false,
			devops:       false,
			roles:        []string{"user"},
			userRole:     "superadmin",
			userCedula:   "87654321",
			userVerif:    true,
			expectedCode: 200,
		},
		{
			name:         "Owner_driver role with conductor",
			pass:         false,
			devops:       false,
			roles:        []string{"conductor"},
			userRole:     "owner_driver",
			userCedula:   "11111111",
			userVerif:    true,
			expectedCode: 200,
		},
		{
			name:         "Owner_driver role with dueño",
			pass:         false,
			devops:       false,
			roles:        []string{"dueño"},
			userRole:     "owner_driver",
			userCedula:   "22222222",
			userVerif:    true,
			expectedCode: 200,
		},
		{
			name:         "Pass mode skips locals setting",
			pass:         true,
			devops:       false,
			roles:        []string{"user"},
			userRole:     "user",
			userCedula:   "33333333",
			userVerif:    true,
			expectedCode: 200,
		},
		{
			name:         "Devops mode allows unverified user",
			pass:         false,
			devops:       true,
			roles:        []string{"admin"},
			userRole:     "admin",
			userCedula:   "44444444",
			userVerif:    false,
			expectedCode: 200,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			token, err := generateTestJWT(tt.userCedula, tt.userRole, testIP, tt.userVerif, time.Now().Add(time.Hour))
			assertNoError(t, err)

			config := middleware.NewJwtRoleMiddleware(tt.devops, testSecret)
			middlewareHandler := config.Handler(tt.pass, tt.roles...)
			app := createTestApp(middlewareHandler)

			// Act
			req := createTestRequest("GET", "/test", "Bearer "+token)
			resp, err := app.Test(req)

			// Assert
			assertNoError(t, err)
			assertEqual(t, tt.expectedCode, resp.StatusCode)

			if tt.expectedCode == 200 {
				body, err := io.ReadAll(resp.Body)
				assertNoError(t, err)
				responseBody := string(body)
				assertContains(t, responseBody, "success")

				if !tt.pass {
					assertContains(t, responseBody, tt.userCedula)
					assertContains(t, responseBody, tt.userRole)
				}
			}
		})
	}
}

// TestJwtRoleMiddleware_AuthenticationErrors tests authentication error scenarios
func TestJwtRoleMiddleware_AuthenticationErrors(t *testing.T) {
	tests := []struct {
		name         string
		setupToken   func() string
		expectedCode int
		expectedMsg  string
	}{
		{
			name: "Missing Authorization header",
			setupToken: func() string {
				return ""
			},
			expectedCode: 401,
			expectedMsg:  "unauthorized - missing or invalid authorization header",
		},
		{
			name: "Invalid Bearer prefix",
			setupToken: func() string {
				return "InvalidPrefix token"
			},
			expectedCode: 401,
			expectedMsg:  "unauthorized - missing or invalid authorization header",
		},
		{
			name: "Invalid token format",
			setupToken: func() string {
				return "Bearer invalid.token.format"
			},
			expectedCode: 401,
			expectedMsg:  "unauthorized - invalid token",
		},
		{
			name: "Expired token",
			setupToken: func() string {
				token, _ := generateTestJWT("12345678", "admin", testIP, true, time.Now().Add(-time.Hour))
				return "Bearer " + token
			},
			expectedCode: 401,
			expectedMsg:  "unauthorized - invalid token", // El JWT library detecta expired tokens como invalid
		},
		{
			name: "Invalid IP",
			setupToken: func() string {
				token, _ := generateTestJWT("12345678", "admin", "127.0.0.1", true, time.Now().Add(time.Hour))
				return "Bearer " + token
			},
			expectedCode: 401,
			expectedMsg:  "unauthorized - invalid ip",
		},
		{
			name: "Unverified user (non-devops)",
			setupToken: func() string {
				token, _ := generateTestJWT("12345678", "admin", testIP, false, time.Now().Add(time.Hour))
				return "Bearer " + token
			},
			expectedCode: 401,
			expectedMsg:  "unauthorized - user not verified",
		},
		{
			name: "Invalid role",
			setupToken: func() string {
				token, _ := generateTestJWT("12345678", "unauthorized_role", testIP, true, time.Now().Add(time.Hour))
				return "Bearer " + token
			},
			expectedCode: 401,
			expectedMsg:  "unauthorized - invalid role",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			config := middleware.NewJwtRoleMiddleware(false, testSecret)
			middlewareHandler := config.Handler(false, "admin")
			app := createTestApp(middlewareHandler)

			// Act
			authHeader := tt.setupToken()
			req := createTestRequest("GET", "/test", authHeader)
			resp, err := app.Test(req)

			// Assert
			assertNoError(t, err)
			assertEqual(t, tt.expectedCode, resp.StatusCode)

			body, err := io.ReadAll(resp.Body)
			assertNoError(t, err)
			responseBody := string(body)
			assertContains(t, responseBody, tt.expectedMsg)
		})
	}
}

// TestJwtRoleMiddleware_RoleVerification tests role verification logic
func TestJwtRoleMiddleware_RoleVerification(t *testing.T) {
	tests := []struct {
		name           string
		allowedRoles   []string
		userRole       string
		expectedStatus int
		description    string
	}{
		{
			name:           "Single allowed role matches",
			allowedRoles:   []string{"admin"},
			userRole:       "admin",
			expectedStatus: 200,
			description:    "User with admin role should be allowed",
		},
		{
			name:           "Multiple allowed roles - first matches",
			allowedRoles:   []string{"admin", "user", "moderator"},
			userRole:       "admin",
			expectedStatus: 200,
			description:    "User with admin role should be allowed from multiple roles",
		},
		{
			name:           "Multiple allowed roles - middle matches",
			allowedRoles:   []string{"admin", "user", "moderator"},
			userRole:       "user",
			expectedStatus: 200,
			description:    "User with user role should be allowed from multiple roles",
		},
		{
			name:           "Role not in allowed list",
			allowedRoles:   []string{"admin", "moderator"},
			userRole:       "guest",
			expectedStatus: 401,
			description:    "User with guest role should not be allowed",
		},
		{
			name:           "Superadmin always allowed regardless of role list",
			allowedRoles:   []string{"user"},
			userRole:       "superadmin",
			expectedStatus: 200,
			description:    "Superadmin should always be allowed",
		},
		{
			name:           "Empty role list still allows superadmin",
			allowedRoles:   []string{},
			userRole:       "superadmin",
			expectedStatus: 200,
			description:    "Superadmin should be allowed even with empty role list",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			token, err := generateTestJWT("12345678", tt.userRole, testIP, true, time.Now().Add(time.Hour))
			assertNoError(t, err, tt.description)

			config := middleware.NewJwtRoleMiddleware(false, testSecret)
			middlewareHandler := config.Handler(false, tt.allowedRoles...)
			app := createTestApp(middlewareHandler)

			// Act
			req := createTestRequest("GET", "/test", "Bearer "+token)
			resp, err := app.Test(req)

			// Assert
			assertNoError(t, err, tt.description)
			assertEqual(t, tt.expectedStatus, resp.StatusCode, tt.description)
		})
	}
}

// TestJwtRoleMiddleware_LocalsHandling tests how locals are handled
func TestJwtRoleMiddleware_LocalsHandling(t *testing.T) {
	t.Run("Should set locals when pass is false", func(t *testing.T) {
		// Arrange
		cedula := "12345678"
		role := "admin"
		token, err := generateTestJWT(cedula, role, testIP, true, time.Now().Add(time.Hour))
		assertNoError(t, err)

		config := middleware.NewJwtRoleMiddleware(false, testSecret)
		middlewareHandler := config.Handler(false, "admin")
		app := createTestApp(middlewareHandler)

		// Act
		req := createTestRequest("GET", "/test", "Bearer "+token)
		resp, err := app.Test(req)

		// Assert
		assertNoError(t, err)
		assertEqual(t, 200, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		assertNoError(t, err)
		responseBody := string(body)
		assertContains(t, responseBody, cedula)
		assertContains(t, responseBody, role)
	})

	t.Run("Should not set locals when pass is true", func(t *testing.T) {
		// Arrange
		cedula := "12345678"
		role := "admin"
		token, err := generateTestJWT(cedula, role, testIP, true, time.Now().Add(time.Hour))
		assertNoError(t, err)

		config := middleware.NewJwtRoleMiddleware(false, testSecret)
		middlewareHandler := config.Handler(true, "admin")
		app := createTestApp(middlewareHandler)

		// Act
		req := createTestRequest("GET", "/test", "Bearer "+token)
		resp, err := app.Test(req)

		// Assert
		assertNoError(t, err)
		assertEqual(t, 200, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		assertNoError(t, err)
		responseBody := string(body)
		assertContains(t, responseBody, "null") // locals should be null when pass=true
	})
}

// TestJwtRoleMiddleware_EdgeCases tests edge cases and error scenarios
func TestJwtRoleMiddleware_EdgeCases(t *testing.T) {
	t.Run("Token with wrong signing method", func(t *testing.T) {
		// Arrange
		claims := testClaims{
			Cedula: "12345678",
			Rol:    "admin",
			IP:     testIP,
			Verif:  true,
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			},
		}

		// Use RS256 instead of HS256 - this will create a malformed token
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tokenString, err := token.SignedString([]byte(testSecret))
		// This will fail, so we use a malformed token instead
		if err != nil {
			tokenString = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.invalid.signature"
		}

		config := middleware.NewJwtRoleMiddleware(false, testSecret)
		middlewareHandler := config.Handler(false, "admin")
		app := createTestApp(middlewareHandler)

		// Act
		req := createTestRequest("GET", "/test", "Bearer "+tokenString)
		resp, err := app.Test(req)

		// Assert
		assertNoError(t, err)
		assertEqual(t, 401, resp.StatusCode)
	})

	t.Run("Token without required claims", func(t *testing.T) {
		// Arrange
		claims := jwt.MapClaims{
			"exp": time.Now().Add(time.Hour).Unix(),
			// Missing rol, ip, verif, cedula claims
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString([]byte(testSecret))
		assertNoError(t, err)

		config := middleware.NewJwtRoleMiddleware(false, testSecret)
		middlewareHandler := config.Handler(false, "admin")
		app := createTestApp(middlewareHandler)

		// Act
		req := createTestRequest("GET", "/test", "Bearer "+tokenString)
		resp, err := app.Test(req)

		// Assert
		assertNoError(t, err)
		assertEqual(t, 401, resp.StatusCode)
	})
}

// BenchmarkJwtRoleMiddleware_ValidToken benchmarks the middleware with valid tokens
func BenchmarkJwtRoleMiddleware_ValidToken(b *testing.B) {
	token, err := generateTestJWT("12345678", "admin", testIP, true, time.Now().Add(time.Hour))
	if err != nil {
		b.Fatalf("Failed to generate test token: %v", err)
	}

	config := middleware.NewJwtRoleMiddleware(false, testSecret)
	middlewareHandler := config.Handler(false, "admin")
	app := createTestApp(middlewareHandler)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := createTestRequest("GET", "/test", "Bearer "+token)
		resp, err := app.Test(req)
		if err != nil {
			b.Fatalf("Test failed: %v", err)
		}
		if resp.StatusCode != 200 {
			b.Fatalf("Expected status 200, got %d", resp.StatusCode)
		}
	}
}

// =============================================================================
// NEW API TESTS
// =============================================================================

// TestJwtRoleMiddleware_Configuration tests the middleware configuration API
func TestJwtRoleMiddleware_Configuration(t *testing.T) {
	t.Run("Should create middleware with devops=false and secret", func(t *testing.T) {
		// Arrange
		devops := false
		secret := "my-secret-key"
		config := middleware.NewJwtRoleMiddleware(devops, secret)

		// Act
		handler := config.Handler(false, "admin")

		// Assert
		if handler == nil {
			t.Fatal("Expected handler to be created, got nil")
		}
	})

	t.Run("Should create middleware with devops=true and secret", func(t *testing.T) {
		// Arrange
		devops := true
		secret := "my-secret-key"
		config := middleware.NewJwtRoleMiddleware(devops, secret)

		// Act
		handler := config.Handler(false, "admin")

		// Assert
		if handler == nil {
			t.Fatal("Expected handler to be created, got nil")
		}
	})
}

// TestJwtRoleMiddleware_Usage tests the middleware usage pattern
func TestJwtRoleMiddleware_Usage(t *testing.T) {
	t.Run("Should work with devops=false configuration", func(t *testing.T) {
		// Arrange
		config := middleware.NewJwtRoleMiddleware(false, testSecret)
		token, err := generateTestJWT("12345678", "admin", testIP, true, time.Now().Add(time.Hour))
		assertNoError(t, err)

		// Create handler with pass=false and admin role
		handler := config.Handler(false, "admin")
		app := createTestApp(handler)

		// Act
		req := createTestRequest("GET", "/test", "Bearer "+token)
		resp, err := app.Test(req)

		// Assert
		assertNoError(t, err)
		assertEqual(t, 200, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		assertNoError(t, err)
		responseBody := string(body)
		assertContains(t, responseBody, "success")
		assertContains(t, responseBody, "12345678")
		assertContains(t, responseBody, "admin")
	})

	t.Run("Should work with devops=true configuration for unverified user", func(t *testing.T) {
		// Arrange
		config := middleware.NewJwtRoleMiddleware(true, testSecret)
		token, err := generateTestJWT("12345678", "admin", testIP, false, time.Now().Add(time.Hour))
		assertNoError(t, err)

		// Create handler with pass=false and admin role
		handler := config.Handler(false, "admin")
		app := createTestApp(handler)

		// Act
		req := createTestRequest("GET", "/test", "Bearer "+token)
		resp, err := app.Test(req)

		// Assert
		assertNoError(t, err)
		assertEqual(t, 200, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		assertNoError(t, err)
		responseBody := string(body)
		assertContains(t, responseBody, "success")
	})
}

// TestJwtRoleMiddleware_Reusability tests middleware reusability
func TestJwtRoleMiddleware_Reusability(t *testing.T) {
	t.Run("Should reuse same config for multiple handlers", func(t *testing.T) {
		// Arrange
		config := middleware.NewJwtRoleMiddleware(false, testSecret)
		token, err := generateTestJWT("12345678", "admin", testIP, true, time.Now().Add(time.Hour))
		assertNoError(t, err)

		// Create multiple handlers with different configurations
		adminHandler := config.Handler(false, "admin")
		userHandler := config.Handler(false, "user", "moderator")
		passHandler := config.Handler(true, "admin")

		// Test admin handler
		app1 := createTestApp(adminHandler)
		req1 := createTestRequest("GET", "/test", "Bearer "+token)
		resp1, err := app1.Test(req1)
		assertNoError(t, err)
		assertEqual(t, 200, resp1.StatusCode)

		// Test user handler (should fail as token has admin role)
		app2 := createTestApp(userHandler)
		req2 := createTestRequest("GET", "/test", "Bearer "+token)
		resp2, err := app2.Test(req2)
		assertNoError(t, err)
		assertEqual(t, 401, resp2.StatusCode)

		// Test pass handler (should succeed and not set locals)
		app3 := createTestApp(passHandler)
		req3 := createTestRequest("GET", "/test", "Bearer "+token)
		resp3, err := app3.Test(req3)
		assertNoError(t, err)
		assertEqual(t, 200, resp3.StatusCode)

		body, err := io.ReadAll(resp3.Body)
		assertNoError(t, err)
		responseBody := string(body)
		assertContains(t, responseBody, "null") // pass=true should not set locals
	})
}

// TestJwtRoleMiddleware_DifferentSecrets tests middleware with different secrets
func TestJwtRoleMiddleware_DifferentSecrets(t *testing.T) {
	t.Run("Should fail with wrong secret", func(t *testing.T) {
		// Arrange
		config := middleware.NewJwtRoleMiddleware(false, "wrong-secret")
		token, err := generateTestJWT("12345678", "admin", testIP, true, time.Now().Add(time.Hour))
		assertNoError(t, err)

		handler := config.Handler(false, "admin")
		app := createTestApp(handler)

		// Act
		req := createTestRequest("GET", "/test", "Bearer "+token)
		resp, err := app.Test(req)

		// Assert
		assertNoError(t, err)
		assertEqual(t, 401, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		assertNoError(t, err)
		responseBody := string(body)
		assertContains(t, responseBody, "invalid token")
	})
}

// BenchmarkJwtRoleMiddleware_ValidToken benchmarks the middleware API
// (Esta función ya está definida antes, así que eliminamos esta duplicada)
