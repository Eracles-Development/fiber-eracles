package middleware_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/Eracles-Development/fiber-eracles/v2/middleware"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
)

const (
	integrationTestSecret = "test-secret-key-for-testing"
	integrationTestIP     = "192.168.1.1"
)

// TestIntegrationScenarios tests real-world scenarios
func TestIntegrationScenarios(t *testing.T) {
	originalSecret := os.Getenv("JWT_SECRET")
	defer os.Setenv("JWT_SECRET", originalSecret)

	os.Setenv("JWT_SECRET", integrationTestSecret)

	// Setup test data
	hash := sha256.Sum256([]byte(integrationTestSecret))
	privateKey := ed25519.NewKeyFromSeed(hash[:])

	generateTestToken := func(claims jwt.MapClaims) string {
		token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
		tokenString, err := token.SignedString(privateKey)
		if err != nil {
			t.Fatalf("Error generating test token: %v", err)
		}
		return tokenString
	}

	t.Run("CompleteUserJourney", func(t *testing.T) {
		// Crear una aplicación completa con múltiples endpoints y roles
		app := fiber.New()

		// Endpoint público (sin autenticación)
		app.Get("/public", func(c *fiber.Ctx) error {
			return c.JSON(fiber.Map{"message": "public access"})
		})

		// Endpoint para usuarios autenticados (sin IP validation)
		configNoIP := middleware.FiberNewJwtRoleMiddleware(false)
		app.Get("/user", configNoIP.Handler(true, "user"), func(c *fiber.Ctx) error {
			email := c.Locals("email")
			return c.JSON(fiber.Map{
				"message": "user access",
				"email":   email,
			})
		})

		// Endpoint para administradores (sin IP validation)
		app.Get("/admin", configNoIP.Handler(true, "admin"), func(c *fiber.Ctx) error {
			email := c.Locals("email")
			return c.JSON(fiber.Map{
				"message": "admin access",
				"email":   email,
			})
		})

		// Endpoint para superadmin (sin IP validation)
		app.Get("/superadmin", configNoIP.Handler(true, "superadmin"), func(c *fiber.Ctx) error {
			email := c.Locals("email")
			return c.JSON(fiber.Map{
				"message": "superadmin access",
				"email":   email,
			})
		})

		// Endpoint que requiere múltiples roles (sin IP validation)
		app.Get("/moderator-admin", configNoIP.Handler(true, "moderator", "admin"), func(c *fiber.Ctx) error {
			return c.JSON(fiber.Map{"message": "moderator or admin access"})
		})

		// Tokens de prueba
		userToken := generateTestToken(jwt.MapClaims{
			"email": "user@example.com",
			"rol":   []interface{}{"user"},
			"ip":    integrationTestIP,
			"exp":   time.Now().Add(time.Hour).Unix(),
		})

		adminToken := generateTestToken(jwt.MapClaims{
			"email": "admin@example.com",
			"rol":   []interface{}{"admin", "user"},
			"ip":    integrationTestIP,
			"exp":   time.Now().Add(time.Hour).Unix(),
		})

		superadminToken := generateTestToken(jwt.MapClaims{
			"email": "superadmin@example.com",
			"rol":   []interface{}{"superadmin"},
			"ip":    integrationTestIP,
			"exp":   time.Now().Add(time.Hour).Unix(),
		})

		moderatorToken := generateTestToken(jwt.MapClaims{
			"email": "moderator@example.com",
			"rol":   []interface{}{"moderator"},
			"ip":    integrationTestIP,
			"exp":   time.Now().Add(time.Hour).Unix(),
		})

		// Test cases
		testCases := []struct {
			endpoint       string
			token          string
			expectedStatus int
			description    string
		}{
			// Acceso público
			{"/public", "", http.StatusOK, "Public access without token"},
			{"/public", userToken, http.StatusOK, "Public access with token"},

			// Acceso de usuario
			{"/user", "", http.StatusUnauthorized, "User endpoint without token"},
			{"/user", userToken, http.StatusOK, "User endpoint with user token"},
			{"/user", adminToken, http.StatusOK, "User endpoint with admin token"},
			{"/user", superadminToken, http.StatusOK, "User endpoint with superadmin token"},

			// Acceso de admin
			{"/admin", "", http.StatusUnauthorized, "Admin endpoint without token"},
			{"/admin", userToken, http.StatusUnauthorized, "Admin endpoint with user token"},
			{"/admin", adminToken, http.StatusOK, "Admin endpoint with admin token"},
			{"/admin", superadminToken, http.StatusOK, "Admin endpoint with superadmin token"},

			// Acceso de superadmin
			{"/superadmin", "", http.StatusUnauthorized, "Superadmin endpoint without token"},
			{"/superadmin", userToken, http.StatusUnauthorized, "Superadmin endpoint with user token"},
			{"/superadmin", adminToken, http.StatusUnauthorized, "Superadmin endpoint with admin token"},
			{"/superadmin", superadminToken, http.StatusOK, "Superadmin endpoint with superadmin token"},

			// Acceso múltiple rol
			{"/moderator-admin", "", http.StatusUnauthorized, "Multi-role endpoint without token"},
			{"/moderator-admin", userToken, http.StatusUnauthorized, "Multi-role endpoint with user token"},
			{"/moderator-admin", adminToken, http.StatusOK, "Multi-role endpoint with admin token"},
			{"/moderator-admin", moderatorToken, http.StatusOK, "Multi-role endpoint with moderator token"},
			{"/moderator-admin", superadminToken, http.StatusOK, "Multi-role endpoint with superadmin token"},
		}

		for _, tc := range testCases {
			t.Run(tc.description, func(t *testing.T) {
				req, _ := http.NewRequest("GET", tc.endpoint, nil)
				if tc.token != "" {
					req.Header.Set("Authorization", "Bearer "+tc.token)
				}
				req.Header.Set("X-Forwarded-For", integrationTestIP)

				resp, err := app.Test(req)
				if err != nil {
					t.Fatalf("Request failed: %v", err)
				}

				if resp.StatusCode != tc.expectedStatus {
					t.Errorf("Expected status %d, got %d for %s", tc.expectedStatus, resp.StatusCode, tc.description)
				}

				resp.Body.Close()
			})
		}
	})

	t.Run("HighLoadScenario", func(t *testing.T) {
		configLoad := middleware.FiberNewJwtRoleMiddleware(false)
		handler := configLoad.Handler(false, "user")

		app := fiber.New()
		app.Use(handler)
		app.Get("/test", func(c *fiber.Ctx) error {
			return c.JSON(fiber.Map{"status": "ok"})
		})

		validToken := generateTestToken(jwt.MapClaims{
			"email": "load-test@example.com",
			"rol":   []interface{}{"user"},
			"ip":    integrationTestIP,
			"exp":   time.Now().Add(time.Hour).Unix(),
		})

		// Simular carga alta
		const numRequests = 100
		resultChan := make(chan error, numRequests)

		for i := 0; i < numRequests; i++ {
			go func() {
				req, _ := http.NewRequest("GET", "/test", nil)
				req.Header.Set("Authorization", "Bearer "+validToken)

				resp, err := app.Test(req)
				if err != nil {
					resultChan <- err
					return
				}

				if resp.StatusCode != http.StatusOK {
					resultChan <- fmt.Errorf("expected status 200, got %d", resp.StatusCode)
					return
				}

				resp.Body.Close()
				resultChan <- nil
			}()
		}

		// Verificar resultados
		for i := 0; i < numRequests; i++ {
			if err := <-resultChan; err != nil {
				t.Errorf("Request %d failed: %v", i, err)
			}
		}
	})

	t.Run("SessionManagement", func(t *testing.T) {
		configSession := middleware.FiberNewJwtRoleMiddleware(false) // Disable IP validation for test
		handler := configSession.Handler(true, "user")

		app := fiber.New()
		app.Use(handler)
		app.Get("/session", func(c *fiber.Ctx) error {
			email := c.Locals("email")
			return c.JSON(fiber.Map{
				"email":     email,
				"sessionId": c.Get("X-Session-ID"),
			})
		})

		// Token válido con sesión
		sessionToken := generateTestToken(jwt.MapClaims{
			"email":     "session@example.com",
			"rol":       []interface{}{"user"},
			"ip":        integrationTestIP,
			"sessionId": "session-123",
			"exp":       time.Now().Add(time.Hour).Unix(),
		})

		req, _ := http.NewRequest("GET", "/session", nil)
		req.Header.Set("Authorization", "Bearer "+sessionToken)
		req.Header.Set("X-Session-ID", "session-123")
		req.Header.Set("X-Forwarded-For", integrationTestIP)

		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}

		var response map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&response)

		if response["email"] != "session@example.com" {
			t.Errorf("Expected email to be session@example.com, got %v", response["email"])
		}

		resp.Body.Close()
	})

	t.Run("TokenRotationScenario", func(t *testing.T) {
		configRotation := middleware.FiberNewJwtRoleMiddleware(false)
		handler := configRotation.Handler(false, "user")

		app := fiber.New()
		app.Use(handler)
		app.Get("/protected", func(c *fiber.Ctx) error {
			return c.JSON(fiber.Map{"message": "protected resource"})
		})

		// Token que expira pronto
		shortToken := generateTestToken(jwt.MapClaims{
			"email": "rotation@example.com",
			"rol":   []interface{}{"user"},
			"ip":    integrationTestIP,
			"exp":   time.Now().Add(time.Second).Unix(), // Expira en 1 segundo
		})

		// Primera request - debería funcionar
		req, _ := http.NewRequest("GET", "/protected", nil)
		req.Header.Set("Authorization", "Bearer "+shortToken)

		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("First request failed: %v", err)
		}

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200 for first request, got %d", resp.StatusCode)
		}
		resp.Body.Close()

		// Esperar a que expire
		time.Sleep(2 * time.Second)

		// Segunda request - debería fallar
		req, _ = http.NewRequest("GET", "/protected", nil)
		req.Header.Set("Authorization", "Bearer "+shortToken)

		resp, err = app.Test(req)
		if err != nil {
			t.Fatalf("Second request failed: %v", err)
		}

		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("Expected status 401 for expired token, got %d", resp.StatusCode)
		}
		resp.Body.Close()

		// Nuevo token - debería funcionar
		newToken := generateTestToken(jwt.MapClaims{
			"email": "rotation@example.com",
			"rol":   []interface{}{"user"},
			"ip":    integrationTestIP,
			"exp":   time.Now().Add(time.Hour).Unix(),
		})

		req, _ = http.NewRequest("GET", "/protected", nil)
		req.Header.Set("Authorization", "Bearer "+newToken)

		resp, err = app.Test(req)
		if err != nil {
			t.Fatalf("Third request failed: %v", err)
		}

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200 for new token, got %d", resp.StatusCode)
		}
		resp.Body.Close()
	})
}

// TestRealWorldErrorScenarios tests error scenarios that might occur in production
func TestRealWorldErrorScenarios(t *testing.T) {
	originalSecret := os.Getenv("JWT_SECRET")
	defer os.Setenv("JWT_SECRET", originalSecret)

	os.Setenv("JWT_SECRET", integrationTestSecret)

	configError := middleware.FiberNewJwtRoleMiddleware(false) // Disable IP validation for error tests
	handler := configError.Handler(false, "user")

	app := fiber.New()
	app.Use(handler)
	app.Get("/test", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok"})
	})

	t.Run("NetworkIssueSimulation", func(t *testing.T) {
		// Simular problemas de red con headers malformados
		malformedRequests := []struct {
			name    string
			headers map[string]string
		}{
			{
				name: "MissingUserAgent",
				headers: map[string]string{
					"Authorization": "Bearer invalid-token",
				},
			},
			{
				name: "DoubleAuthHeader",
				headers: map[string]string{
					"Authorization": "Bearer token1, Bearer token2",
				},
			},
			{
				name: "CaseInsensitiveBearer",
				headers: map[string]string{
					"Authorization": "bearer valid-looking-token",
				},
			},
		}

		for _, tc := range malformedRequests {
			t.Run(tc.name, func(t *testing.T) {
				req, _ := http.NewRequest("GET", "/test", nil)
				for key, value := range tc.headers {
					req.Header.Set(key, value)
				}

				resp, err := app.Test(req)
				if err != nil {
					t.Fatalf("Request failed: %v", err)
				}

				if resp.StatusCode != http.StatusUnauthorized {
					t.Errorf("Expected status 401 for %s, got %d", tc.name, resp.StatusCode)
				}
				resp.Body.Close()
			})
		}
	})

	t.Run("BruteForceSimulation", func(t *testing.T) {
		// Simular intentos de fuerza bruta con tokens inválidos
		invalidTokens := []string{
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid",
			"header.payload.signature",
			"totally-invalid-token",
			"",
		}

		for i, token := range invalidTokens {
			t.Run(fmt.Sprintf("BruteForceAttempt_%d", i), func(t *testing.T) {
				req, _ := http.NewRequest("GET", "/test", nil)
				if token != "" {
					req.Header.Set("Authorization", "Bearer "+token)
				}

				resp, err := app.Test(req)
				if err != nil {
					t.Fatalf("Request failed: %v", err)
				}

				if resp.StatusCode != http.StatusUnauthorized {
					t.Errorf("Expected status 401 for brute force attempt %d, got %d", i, resp.StatusCode)
				}
				resp.Body.Close()
			})
		}
	})
}
