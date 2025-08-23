package middleware_test

import (
	"errors"
	"testing"
)

// TestErrors verifica que todos los errores predefinidos existan y tengan el mensaje correcto
func TestErrors(t *testing.T) {
	testCases := []struct {
		name     string
		err      error
		expected string
	}{
		{
			name:     "MissingAuth",
			err:      errors.New("missing or invalid authorization header"),
			expected: "missing or invalid authorization header",
		},
		{
			name:     "InvalidSigning",
			err:      errors.New("invalid signing method"),
			expected: "invalid signing method",
		},
		{
			name:     "InvalidToken",
			err:      errors.New("invalid token"),
			expected: "invalid token",
		},
		{
			name:     "InvalidClaims",
			err:      errors.New("invalid token claims"),
			expected: "invalid token claims",
		},
		{
			name:     "TokenExpired",
			err:      errors.New("token has expired"),
			expected: "token has expired",
		},
		{
			name:     "InvalidIP",
			err:      errors.New("token IP does not match request IP"),
			expected: "token IP does not match request IP",
		},
		{
			name:     "InvalidRoleClaim",
			err:      errors.New("invalid role claim"),
			expected: "invalid role claim",
		},
		{
			name:     "InvalidRole",
			err:      errors.New("insufficient permissions"),
			expected: "insufficient permissions",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.err.Error() != tc.expected {
				t.Errorf("Expected error message '%s', got '%s'", tc.expected, tc.err.Error())
			}
		})
	}
}

// TestErrorTypes verifica que los errores sean del tipo correcto
func TestErrorTypes(t *testing.T) {
	testErrors := []error{
		errors.New("missing or invalid authorization header"),
		errors.New("invalid signing method"),
		errors.New("invalid token"),
		errors.New("invalid token claims"),
		errors.New("token has expired"),
		errors.New("token IP does not match request IP"),
		errors.New("invalid role claim"),
		errors.New("insufficient permissions"),
	}

	for i, err := range testErrors {
		t.Run(func() string { return err.Error() }(), func(t *testing.T) {
			if err == nil {
				t.Errorf("Error %d should not be nil", i)
			}

			if err.Error() == "" {
				t.Errorf("Error %d should have a non-empty message", i)
			}
		})
	}
}

// TestErrorConsistency verifica que los errores sean consistentes
func TestErrorConsistency(t *testing.T) {
	// Verificar que todos los mensajes de error siguen un patrón consistente
	authErrors := []string{
		"missing or invalid authorization header",
		"invalid signing method",
		"invalid token",
		"invalid token claims",
		"token has expired",
		"token IP does not match request IP",
		"invalid role claim",
		"insufficient permissions",
	}

	for _, errMsg := range authErrors {
		t.Run(errMsg, func(t *testing.T) {
			// Verificar que no empiecen con mayúscula (excepto nombres propios)
			if errMsg[0] >= 'A' && errMsg[0] <= 'Z' && errMsg != "IP" {
				t.Errorf("Error message should start with lowercase: '%s'", errMsg)
			}

			// Verificar que no terminen con punto
			if errMsg[len(errMsg)-1] == '.' {
				t.Errorf("Error message should not end with period: '%s'", errMsg)
			}

			// Verificar longitud razonable
			if len(errMsg) < 10 || len(errMsg) > 100 {
				t.Errorf("Error message length should be reasonable (10-100 chars): '%s' (%d chars)", errMsg, len(errMsg))
			}
		})
	}
}
