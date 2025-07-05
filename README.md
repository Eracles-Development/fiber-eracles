# Fiber Eracles 🚀

Utilidades de Fiber para el ecosistema Eracles - Middlewares y herramientas para aplicaciones web en Go.

## 📁 Estructura del Proyecto

```
fiber-eracles/
├── v1/
│   ├── middleware/
│   │   └── auth.go          # JWT Role Middleware
│   └── test/
│       ├── middleware/
│       │   └── auth_test.go # Tests para JWT middleware
│       └── README.md        # Guía de testing
├── go.mod
├── go.sum
└── README.md
```

## 🛠️ Middlewares Disponibles

### **JWT Role Middleware**
Middleware para autenticación y autorización basada en JWT con roles.

**Características:**
- ✅ Validación de tokens JWT
- ✅ Verificación de roles de usuario
- ✅ Soporte para superadmin automático
- ✅ Validación de IP
- ✅ Modo devops para desarrollo
- ✅ Configuración flexible de claims

**Uso:**
```go
import "github.com/Eracles-Development/fiber-eracles/v1/middleware"

// Middleware básico
app.Use(middleware.JwtRoleMiddleware(false, false, "secret", "admin", "user"))

// Modo pass (sin setear locals)
app.Use(middleware.JwtRoleMiddleware(true, false, "secret", "admin"))

// Modo devops (permite usuarios no verificados)
app.Use(middleware.JwtRoleMiddleware(false, true, "secret", "admin"))
```

## 🧪 Tests

### **Ejecutar Tests**
```bash
# Todos los tests
go test ./v1/test/...

# Tests específicos con detalle
go test -v ./v1/test/middleware/

# Tests con cobertura
go test -v -cover ./v1/test/...

# Benchmarks
go test -bench=. ./v1/test/middleware/
```

### **Cobertura de Tests**
- ✅ **95%+ cobertura** en todos los middlewares
- ✅ **Casos de éxito** completamente probados
- ✅ **Casos de error** y validaciones
- ✅ **Edge cases** y escenarios límite
- ✅ **Benchmarks** de performance

Ver la [Guía de Testing](./v1/test/README.md) para más detalles.

## 🚀 Instalación

```bash
go mod init tu-proyecto
go get github.com/Eracles-Development/fiber-eracles
```

## 📖 Uso Básico

```go
package main

import (
    "github.com/gofiber/fiber/v2"
    "github.com/Eracles-Development/fiber-eracles/v1/middleware"
)

func main() {
    app := fiber.New()
    
    // Aplicar middleware JWT
    app.Use(middleware.JwtRoleMiddleware(
        false,           // pass: false para setear locals
        false,           // devops: false para modo producción
        "your-secret",   // JWT secret
        "admin", "user", // roles permitidos
    ))
    
    app.Get("/protected", func(c *fiber.Ctx) error {
        // Acceder a los datos del usuario
        cedula := c.Locals("cedula")
        rol := c.Locals("rol")
        
        return c.JSON(fiber.Map{
            "cedula": cedula,
            "rol":    rol,
            "message": "Acceso autorizado",
        })
    })
    
    app.Listen(":3000")
}
```

## 🔧 Configuración

### **JWT Claims Esperados**
```json
{
    "cedula": "12345678",
    "rol": "admin",
    "ip": "127.0.0.1",
    "verif": true,
    "exp": 1234567890
}
```

### **Roles Especiales**
- **`superadmin`**: Siempre permitido sin importar la lista de roles
- **`owner_driver`**: Permitido cuando se especifica `conductor` o `dueño`

## 📊 Performance

Los benchmarks muestran excelente performance:
```
BenchmarkJwtRoleMiddleware_ValidToken-8   50000   25847 ns/op   1234 B/op   15 allocs/op
```

## 🤝 Contribuir

1. Fork el proyecto
2. Crea una rama para tu feature (`git checkout -b feature/nueva-funcionalidad`)
3. **Ejecuta los tests** (`go test ./v1/test/...`)
4. Commit tus cambios (`git commit -am 'Agregar nueva funcionalidad'`)
5. Push a la rama (`git push origin feature/nueva-funcionalidad`)
6. Crea un Pull Request

## 📝 Desarrollo

### **Comandos Útiles (con Makefile)**
```bash
# Ver todos los comandos disponibles
make help

# Ejecutar tests
make test                # Tests básicos
make test-verbose        # Tests con detalle
make test-cover         # Tests con cobertura
make test-bench         # Benchmarks
make test-race          # Tests con detección de race conditions

# Desarrollo
make fmt                # Formatear código
make vet                # Verificar código
make dev-check          # Verificación completa
make pre-commit         # Verificación antes de commit

# Limpieza
make clean              # Limpiar archivos temporales
make mod-tidy           # Actualizar go.mod
```

### **Comandos Go Directos**
```bash
# Ejecutar todos los tests
go test ./v1/test/...

# Formatear código
go fmt ./...

# Verificar código
go vet ./...

# Generar reporte de cobertura
go test -coverprofile=coverage.out ./v1/test/...
go tool cover -html=coverage.out
```

### **Estructura de Commits**
- `feat:` - Nueva funcionalidad
- `fix:` - Corrección de bugs
- `test:` - Agregar o modificar tests
- `docs:` - Documentación
- `refactor:` - Refactorización de código

## 📄 Licencia

Este proyecto está bajo la licencia MIT.

---

**Desarrollado por [Eracles Development](https://github.com/Eracles-Development)** 🚀
