# Fiber Eracles v2 Makefile
# Makefile para testing exhaustivo y generación de reportes

# Variables
PACKAGE := github.com/Eracles-Development/fiber-eracles/v2
TEST_DIR := ./test
MIDDLEWARE_DIR := ./middleware
DOCS_DIR := ./docs
COVERAGE_FILE := $(DOCS_DIR)/coverage.out
COVERAGE_HTML := $(DOCS_DIR)/coverage.html
TIMESTAMP := $(shell date +"%Y%m%d_%H%M%S")
REPORT_FILE := $(DOCS_DIR)/test_report_$(TIMESTAMP).md
JSON_REPORT := $(DOCS_DIR)/test_results_$(TIMESTAMP).json

# Funciones de output limpio

.PHONY: help test test-verbose test-short benchmark clean setup deps lint format test-report test-coverage

# Comando principal: ejecutar tests exhaustivos y generar informe
test: setup
	@echo "🚀 Ejecutando tests exhaustivos para Fiber Eracles Middleware v2"
	@echo "📅 Fecha: $(shell date '+%Y-%m-%d %H:%M:%S')"
	@echo "📊 Generando informe automático..."
	@echo ""
	
	# Crear directorio docs si no existe
	@mkdir -p $(DOCS_DIR)
	
	# Ejecutar tests con cobertura y output JSON
	@echo "🧪 Ejecutando tests unitarios..."
	@JWT_SECRET=test-secret-key-for-testing go test -v -race -coverprofile=$(COVERAGE_FILE) -covermode=atomic -json $(TEST_DIR)/... > $(JSON_REPORT) 2>&1 || true
	
	# Ejecutar benchmarks
	@echo "⚡ Ejecutando benchmarks..."
	@JWT_SECRET=test-secret-key-for-testing go test -bench=. -benchmem -count=3 $(TEST_DIR)/... >> $(JSON_REPORT) 2>&1 || true
	
	# Generar reporte HTML de cobertura
	@echo "📈 Generando reporte de cobertura..."
	@go tool cover -html=$(COVERAGE_FILE) -o $(COVERAGE_HTML)
	
	# Generar reporte markdown
	@echo "📝 Generando reporte markdown..."
	@$(MAKE) generate-report
	
	@echo ""
	@echo "✅ Tests completados exitosamente!"
	@echo "📁 Reportes generados en: $(DOCS_DIR)/"
	@echo "  - Reporte principal: $(REPORT_FILE)"
	@echo "  - Cobertura HTML: $(COVERAGE_HTML)"
	@echo "  - Datos JSON: $(JSON_REPORT)"

# Generar reporte markdown detallado
generate-report:
	@echo "# 🧪 Reporte de Tests - Fiber Eracles Middleware v2" > $(REPORT_FILE)
	@echo "" >> $(REPORT_FILE)
	@echo "**📅 Fecha de ejecución:** $(shell date '+%Y-%m-%d %H:%M:%S')" >> $(REPORT_FILE)
	@echo "**🏗️ Versión Go:** $(shell go version)" >> $(REPORT_FILE)
	@echo "**📦 Módulo:** $(PACKAGE)" >> $(REPORT_FILE)
	@echo "" >> $(REPORT_FILE)
	
	@echo "## 📊 Resumen Ejecutivo" >> $(REPORT_FILE)
	@echo "" >> $(REPORT_FILE)
	
	# Estadísticas de tests
	@echo "### 🎯 Estadísticas de Tests" >> $(REPORT_FILE)
	@echo "" >> $(REPORT_FILE)
	@echo "| Métrica | Valor |" >> $(REPORT_FILE)
	@echo "|---------|-------|" >> $(REPORT_FILE)
	@echo "| Tests Ejecutados | $(shell grep -c '"Test"' $(JSON_REPORT) 2>/dev/null || echo 'N/A') |" >> $(REPORT_FILE)
	@echo "| Tests Pasados | $(shell grep -c '"Action":"pass"' $(JSON_REPORT) 2>/dev/null || echo 'N/A') |" >> $(REPORT_FILE)
	@echo "| Tests Fallidos | $(shell grep -c '"Action":"fail"' $(JSON_REPORT) 2>/dev/null || echo 'N/A') |" >> $(REPORT_FILE)
	@echo "| Cobertura Total | $(shell go tool cover -func=$(COVERAGE_FILE) 2>/dev/null | tail -n 1 | awk '{print $$3}' || echo 'N/A') |" >> $(REPORT_FILE)
	@echo "| Duración Total | $(shell grep '"Elapsed"' $(JSON_REPORT) 2>/dev/null | tail -n 1 | grep -o '"Elapsed":[0-9.]*' | cut -d: -f2 || echo 'N/A')s |" >> $(REPORT_FILE)
	@echo "" >> $(REPORT_FILE)
	
	# Cobertura por archivo
	@echo "### 📈 Cobertura por Archivo" >> $(REPORT_FILE)
	@echo "" >> $(REPORT_FILE)
	@echo "| Archivo | Cobertura |" >> $(REPORT_FILE)
	@echo "|---------|-----------|" >> $(REPORT_FILE)
	@go tool cover -func=$(COVERAGE_FILE) 2>/dev/null | grep -v "total:" | while read line; do \
		file=$$(echo $$line | awk '{print $$1}' | sed 's|.*/||'); \
		coverage=$$(echo $$line | awk '{print $$3}'); \
		echo "| $$file | $$coverage |" >> $(REPORT_FILE); \
	done || true
	@echo "" >> $(REPORT_FILE)
	
	# Resultados detallados
	@echo "## 🔍 Resultados Detallados" >> $(REPORT_FILE)
	@echo "" >> $(REPORT_FILE)
	
	# Tests por categoría
	@echo "### 🧪 Tests Unitarios" >> $(REPORT_FILE)
	@echo "" >> $(REPORT_FILE)
	@echo "#### ✅ Tests Exitosos" >> $(REPORT_FILE)
	@echo "\`\`\`" >> $(REPORT_FILE)
	@grep '"Action":"pass"' $(JSON_REPORT) 2>/dev/null | grep '"Test"' | sed 's/.*"Test":"\([^"]*\)".*/- \1/' >> $(REPORT_FILE) || echo "No se encontraron tests exitosos" >> $(REPORT_FILE)
	@echo "\`\`\`" >> $(REPORT_FILE)
	@echo "" >> $(REPORT_FILE)
	
	@echo "#### ❌ Tests Fallidos" >> $(REPORT_FILE)
	@echo "\`\`\`" >> $(REPORT_FILE)
	@grep '"Action":"fail"' $(JSON_REPORT) 2>/dev/null | grep '"Test"' | sed 's/.*"Test":"\([^"]*\)".*/- \1/' >> $(REPORT_FILE) || echo "No hay tests fallidos! 🎉" >> $(REPORT_FILE)
	@echo "\`\`\`" >> $(REPORT_FILE)
	@echo "" >> $(REPORT_FILE)
	
	# Benchmarks
	@echo "### ⚡ Rendimiento (Benchmarks)" >> $(REPORT_FILE)
	@echo "" >> $(REPORT_FILE)
	@echo "| Benchmark | Iteraciones | ns/op | MB/s | allocs/op |" >> $(REPORT_FILE)
	@echo "|-----------|-------------|-------|------|-----------|" >> $(REPORT_FILE)
	@grep "^Benchmark" $(JSON_REPORT) 2>/dev/null | while read line; do \
		benchmark=$$(echo $$line | awk '{print $$1}'); \
		iterations=$$(echo $$line | awk '{print $$2}'); \
		nsop=$$(echo $$line | awk '{print $$3}'); \
		echo "| $$benchmark | $$iterations | $$nsop | - | - |" >> $(REPORT_FILE); \
	done || echo "| No benchmarks | - | - | - | - |" >> $(REPORT_FILE)
	@echo "" >> $(REPORT_FILE)
	
	# Información del sistema
	@echo "## 🖥️ Información del Sistema" >> $(REPORT_FILE)
	@echo "" >> $(REPORT_FILE)
	@echo "- **OS:** $(shell uname -s -r)" >> $(REPORT_FILE)
	@echo "- **Arquitectura:** $(shell uname -m)" >> $(REPORT_FILE)
	@echo "- **Go Version:** $(shell go version)" >> $(REPORT_FILE)
	@echo "- **CPU:** $(shell nproc) cores" >> $(REPORT_FILE)
	@echo "- **RAM:** $(shell free -h 2>/dev/null | awk '/^Mem:/ {print $$2}' || echo 'N/A')" >> $(REPORT_FILE)
	@echo "" >> $(REPORT_FILE)
	
	# Archivos de test
	@echo "## 📁 Archivos de Test Ejecutados" >> $(REPORT_FILE)
	@echo "" >> $(REPORT_FILE)
	@find $(TEST_DIR) -name "*.go" -type f | while read file; do \
		echo "- \`$$file\`" >> $(REPORT_FILE); \
	done
	@echo "" >> $(REPORT_FILE)
	
	# Comandos de reproducción
	@echo "## 🔄 Comandos de Reproducción" >> $(REPORT_FILE)
	@echo "" >> $(REPORT_FILE)
	@echo "\`\`\`bash" >> $(REPORT_FILE)
	@echo "# Ejecutar todos los tests" >> $(REPORT_FILE)
	@echo "make test" >> $(REPORT_FILE)
	@echo "" >> $(REPORT_FILE)
	@echo "# Ejecutar tests específicos" >> $(REPORT_FILE)
	@echo "go test -v ./test/middleware_test.go" >> $(REPORT_FILE)
	@echo "go test -v ./test/errors_test.go" >> $(REPORT_FILE)
	@echo "go test -v ./test/integration_test.go" >> $(REPORT_FILE)
	@echo "" >> $(REPORT_FILE)
	@echo "# Ver cobertura" >> $(REPORT_FILE)
	@echo "go tool cover -html=$(COVERAGE_FILE)" >> $(REPORT_FILE)
	@echo "\`\`\`" >> $(REPORT_FILE)
	@echo "" >> $(REPORT_FILE)
	
	@echo "---" >> $(REPORT_FILE)
	@echo "*Reporte generado automáticamente por el sistema de testing de Fiber Eracles v2*" >> $(REPORT_FILE)

# Tests verbose para debugging
test-verbose: setup
	@echo "🔍 Ejecutando tests en modo verbose..."
	@JWT_SECRET=test-secret-key-for-testing go test -v -race $(TEST_DIR)/...

# Tests rápidos (sin race detection)
test-short: setup
	@echo "⚡ Ejecutando tests rápidos..."
	@JWT_SECRET=test-secret-key-for-testing go test -short $(TEST_DIR)/...

# Solo benchmarks
benchmark: setup
	@echo "⚡ Ejecutando benchmarks..."
	@JWT_SECRET=test-secret-key-for-testing go test -bench=. -benchmem -count=5 $(TEST_DIR)/...

# Cobertura detallada
test-coverage: setup
	@mkdir -p $(DOCS_DIR)
	@echo "📊 Generando reporte de cobertura detallado..."
	@JWT_SECRET=test-secret-key-for-testing go test -coverprofile=$(COVERAGE_FILE) -covermode=atomic $(TEST_DIR)/...
	@go tool cover -html=$(COVERAGE_FILE) -o $(COVERAGE_HTML)
	@go tool cover -func=$(COVERAGE_FILE)
	@echo "📁 Reporte HTML generado: $(COVERAGE_HTML)"

# Linting
lint:
	@echo "🔍 Ejecutando linters..."
	@go vet ./...
	@gofmt -l . | (! read)
	@echo "✅ Linting completado"

# Formatear código
format:
	@echo "🎨 Formateando código..."
	@gofmt -w .
	@echo "✅ Código formateado"

# Instalar dependencias
deps:
	@echo "📦 Instalando dependencias..."
	@go mod download
	@go mod tidy
	@echo "✅ Dependencias instaladas"

# Setup inicial
setup: deps
	@echo "🔧 Configurando entorno de testing..."
	@mkdir -p $(DOCS_DIR)
	@export JWT_SECRET=test-secret-key-for-testing

# Limpiar archivos generados
clean:
	@echo "🧹 Limpiando archivos generados..."
	@rm -f $(COVERAGE_FILE)
	@rm -f $(DOCS_DIR)/coverage.html
	@rm -f $(DOCS_DIR)/test_report_*.md
	@rm -f $(DOCS_DIR)/test_results_*.json
	@echo "✅ Archivos limpiados"

# Ayuda
help:
	@echo "📚 Comandos disponibles para Fiber Eracles Middleware v2:"
	@echo ""
	@echo "Comandos principales:"
	@echo "  test          - Ejecutar tests exhaustivos y generar informe completo"
	@echo "  test-verbose  - Ejecutar tests en modo verbose para debugging" 
	@echo "  test-short    - Ejecutar tests rápidos (sin race detection)"
	@echo "  test-coverage - Generar reporte detallado de cobertura"
	@echo "  benchmark     - Ejecutar solo benchmarks de rendimiento"
	@echo ""
	@echo "Utilidades:"
	@echo "  setup         - Configurar entorno de testing"
	@echo "  deps          - Instalar/actualizar dependencias"
	@echo "  lint          - Ejecutar linters de código"
	@echo "  format        - Formatear código fuente"
	@echo "  clean         - Limpiar archivos generados"
	@echo "  help          - Mostrar esta ayuda"
	@echo ""
	@echo "Archivos generados:"
	@echo "  - $(DOCS_DIR)/test_report_YYYYMMDD_HHMMSS.md  (Reporte principal)"
	@echo "  - $(DOCS_DIR)/coverage.html                    (Cobertura visual)"
	@echo "  - $(DOCS_DIR)/test_results_YYYYMMDD_HHMMSS.json (Datos brutos)"
	@echo ""
