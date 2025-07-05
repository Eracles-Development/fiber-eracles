# Testing Guide - Fiber Eracles 🧪

Este directorio contiene todos los tests para el proyecto Fiber Eracles, organizados de manera estructurada y siguiendo las mejores prácticas de Go.

## 📁 Estructura de Carpetas

```
v1/test/
├── middleware/
│   └── auth_test.go        # Tests para JWT Role Middleware
└── README.md               # Esta guía
```

## 🧪 Tests Implementados

### **Middleware Tests**
- **`auth_test.go`**: Tests completos para `JwtRoleMiddleware`
  - ✅ Casos de éxito (tokens válidos, roles, superadmin)
  - ❌ Casos de error (tokens inválidos, roles no permitidos)
  - 🔧 Casos edge (métodos de firma incorrectos, claims faltantes)
  - 📊 Benchmarks de performance

## 🚀 Comandos para Ejecutar Tests

### **Comandos Básicos**

```bash
# Ejecutar todos los tests
go test ./v1/test/...

# Ejecutar tests con output detallado
go test -v ./v1/test/...

# Ejecutar tests de un paquete específico
go test -v ./v1/test/middleware/

# Ejecutar un test específico
go test -v ./v1/test/middleware/ -run TestJwtRoleMiddleware_Success
```

### **Comandos Avanzados**

```bash
# Ejecutar tests con cobertura
go test -v -cover ./v1/test/...

# Generar reporte de cobertura en HTML
go test -v -coverprofile=coverage.out ./v1/test/...
go tool cover -html=coverage.out -o coverage.html

# Ejecutar tests en paralelo
go test -v -parallel 4 ./v1/test/...

# Ejecutar tests con timeout
go test -v -timeout 30s ./v1/test/...
```

### **Benchmarks**

```bash
# Ejecutar benchmarks
go test -bench=. ./v1/test/middleware/

# Ejecutar benchmarks con estadísticas de memoria
go test -bench=. -benchmem ./v1/test/middleware/

# Ejecutar benchmarks múltiples veces para mayor precisión
go test -bench=. -count=5 ./v1/test/middleware/
```

### **Tests de Integración**

```bash
# Ejecutar tests con variables de entorno específicas
JWT_SECRET=test-secret go test -v ./v1/test/...

# Ejecutar tests con flags personalizados
go test -v ./v1/test/middleware/ -args -secret=custom-secret
```

## 📊 Interpretación de Resultados

### **Salida Normal**
```
=== RUN   TestJwtRoleMiddleware_Success
=== RUN   TestJwtRoleMiddleware_Success/Valid_token_with_allowed_role
=== RUN   TestJwtRoleMiddleware_Success/Superadmin_always_allowed
--- PASS: TestJwtRoleMiddleware_Success (0.01s)
    --- PASS: TestJwtRoleMiddleware_Success/Valid_token_with_allowed_role (0.00s)
    --- PASS: TestJwtRoleMiddleware_Success/Superadmin_always_allowed (0.00s)
```

### **Salida con Cobertura**
```
coverage: 95.2% of statements
PASS
```

### **Salida de Benchmarks**
```
BenchmarkJwtRoleMiddleware_ValidToken-8   	   50000	     25847 ns/op	    1234 B/op	      15 allocs/op
```

## 🛠️ Buenas Prácticas Implementadas

### **Organización**
- ✅ **Separación de concerns**: Tests separados del código fuente
- ✅ **Naming conventions**: Nombres descriptivos y consistentes
- ✅ **Package naming**: Uso de `package middleware_test`

### **Estructura de Tests**
- ✅ **Table-driven tests**: Para múltiples casos de prueba
- ✅ **Arrange-Act-Assert**: Patrón AAA en todos los tests
- ✅ **Helper functions**: Funciones auxiliares para assertions

### **Cobertura**
- ✅ **Happy path**: Casos de éxito completamente cubiertos
- ✅ **Error handling**: Todos los casos de error probados
- ✅ **Edge cases**: Casos límite y excepcionales
- ✅ **Performance**: Benchmarks para medir rendimiento

## 🚦 Comandos de CI/CD

### **Para Integración Continua**
```bash
# Comando completo para CI
go test -v -race -coverprofile=coverage.out ./v1/test/...

# Verificar formato de código
go fmt ./v1/test/...
go vet ./v1/test/...

# Ejecutar linter (si golangci-lint está instalado)
golangci-lint run ./v1/test/...
```

### **Para Deployment**
```bash
# Tests rápidos antes de deploy
go test -short ./v1/test/...

# Tests completos con timeout
go test -v -timeout 60s ./v1/test/...
```

## 📝 Agregando Nuevos Tests

### **Estructura Recomendada**
```go
func TestNombreFuncion_Escenario(t *testing.T) {
    // Arrange - Preparar datos de prueba
    
    // Act - Ejecutar la función
    
    // Assert - Verificar resultados
}
```

### **Ejemplo de Test**
```go
func TestMiMiddleware_ValidToken(t *testing.T) {
    // Arrange
    token := generateTestJWT("user123", "admin", testIP, true, time.Now().Add(time.Hour))
    middleware := MiMiddleware(false, false, testSecret, "admin")
    
    // Act
    result := middleware(mockContext)
    
    // Assert
    assertNoError(t, result)
    assertEqual(t, 200, mockContext.StatusCode)
}
```

## 🔧 Solución de Problemas

### **Errores Comunes**
1. **Import path incorrecto**: Verificar que el módulo esté en `go.mod`
2. **JWT secret**: Asegurar que el secret de prueba sea consistente
3. **Timeouts**: Tokens de prueba con tiempo de expiración adecuado

### **Debugging**
```bash
# Ejecutar con más detalle
go test -v -x ./v1/test/middleware/

# Ver qué tests están corriendo
go test -v -trace trace.out ./v1/test/middleware/
```

## 📈 Métricas de Calidad

- **Cobertura objetivo**: > 90%
- **Tiempo de ejecución**: < 30s para todos los tests
- **Benchmarks**: Mantener performance dentro de límites aceptables

---

**💡 Tip**: Ejecuta `go test -v ./v1/test/...` antes de cada commit para asegurar que todo funcione correctamente. 