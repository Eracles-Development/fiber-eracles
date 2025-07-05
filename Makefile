# Makefile para Fiber Eracles
# Comandos útiles para desarrollo y testing

.PHONY: test test-verbose test-cover test-bench clean fmt vet lint help

# Variables
TEST_PATH = ./v1/test/...
COVERAGE_FILE = coverage.out
COVERAGE_HTML = coverage.html

# Comandos de testing
test: ## Ejecutar todos los tests
	@echo "🧪 Ejecutando tests..."
	go test $(TEST_PATH)

test-verbose: ## Ejecutar tests con output detallado
	@echo "🧪 Ejecutando tests con detalle..."
	go test -v $(TEST_PATH)

test-cover: ## Ejecutar tests con cobertura
	@echo "📊 Ejecutando tests con cobertura..."
	go test -v -cover $(TEST_PATH)

test-cover-html: ## Generar reporte HTML de cobertura
	@echo "📊 Generando reporte HTML de cobertura..."
	go test -v -coverprofile=$(COVERAGE_FILE) $(TEST_PATH)
	go tool cover -html=$(COVERAGE_FILE) -o $(COVERAGE_HTML)
	@echo "📊 Reporte generado en $(COVERAGE_HTML)"

test-bench: ## Ejecutar benchmarks
	@echo "⚡ Ejecutando benchmarks..."
	go test -bench=. -benchmem $(TEST_PATH)

test-race: ## Ejecutar tests con detección de race conditions
	@echo "🏃 Ejecutando tests con detección de race conditions..."
	go test -race $(TEST_PATH)

test-ci: ## Ejecutar tests para CI/CD
	@echo "🚀 Ejecutando tests para CI/CD..."
	go test -v -race -coverprofile=$(COVERAGE_FILE) $(TEST_PATH)

# Comandos de formato y validación
fmt: ## Formatear código
	@echo "🎨 Formateando código..."
	go fmt ./...

vet: ## Verificar código con go vet
	@echo "🔍 Verificando código..."
	go vet ./...

lint: ## Ejecutar linter (requiere golangci-lint)
	@echo "🔍 Ejecutando linter..."
	golangci-lint run ./...

# Comandos de limpieza
clean: ## Limpiar archivos temporales
	@echo "🧹 Limpiando archivos temporales..."
	rm -f $(COVERAGE_FILE) $(COVERAGE_HTML)
	go clean -testcache

# Comandos de desarrollo
dev-check: fmt vet test ## Verificación completa para desarrollo
	@echo "✅ Verificación completa completada"

pre-commit: fmt vet test-race ## Verificación antes de commit
	@echo "✅ Pre-commit verificación completada"

# Comandos de información
deps: ## Mostrar dependencias
	@echo "📦 Dependencias del proyecto:"
	go list -m all

mod-tidy: ## Limpiar y actualizar go.mod
	@echo "📦 Actualizando go.mod..."
	go mod tidy

mod-download: ## Descargar dependencias
	@echo "📦 Descargando dependencias..."
	go mod download

# Ayuda
help: ## Mostrar esta ayuda
	@echo "🚀 Fiber Eracles - Comandos disponibles:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# Comando por defecto
.DEFAULT_GOAL := help 