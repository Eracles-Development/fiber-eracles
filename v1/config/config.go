package config

import (
	"log"
	"os"

	"github.com/ansrivas/fiberprometheus/v2"
	"github.com/gofiber/contrib/swagger"
	"github.com/gofiber/fiber/v2"
	"github.com/joho/godotenv"
)

// Carga las variables de entorno probando las posibles rutas si es nativo o docker
func LoadEnv() error {
	envPaths := []string{
		"../.env",
		"../../.env",
	}

	var err error
	for _, path := range envPaths {
		err = godotenv.Load(path)
		if err == nil {
			log.Printf("Successfully loaded .env from: %s", path)
			break
		} else {
			return err
		}
	}

	return nil
}

// ISDev revisa si la aplicación está en modo desarrollo
// Devuelve true si la variable de entorno ENV está configurada como "development"
func IsDev() bool {
	return os.Getenv("ENV") == "development"
}

// Establece los endpoints basicos de la aplicación Fiber
// Configura el middleware de salud, prometheus y swagger
// Necesita variable de entorno APP_NAME
func SetupBasicHCFiber(app *fiber.App, isDev bool) {

	log.Println(
		`

        ███████╗██████╗░░█████╗░░█████╗░██╗░░░░░███████╗░██████╗
        ██╔════╝██╔══██╗██╔══██╗██╔══██╗██║░░░░░██╔════╝██╔════╝
        █████╗░░██████╔╝███████║██║░░╚═╝██║░░░░░█████╗░░╚█████╗░
        ██╔══╝░░██╔══██╗██╔══██║██║░░██╗██║░░░░░██╔══╝░░░╚═══██╗
        ███████╗██║░░██║██║░░██║╚█████╔╝███████╗███████╗██████╔╝
        ╚══════╝╚═╝░░╚═╝╚═╝░░╚═╝░╚════╝░╚══════╝╚══════╝╚═════╝░

		Σracles Software Company

		Developed by:

		The Σracles Team
        `)

	setupLive(app)

	setupPrometheus(app)

	setupSwagger(app, isDev)

}

func setupPrometheus(app *fiber.App) {
	prometheus := fiberprometheus.New(os.Getenv("APP_NAME"))
	prometheus.RegisterAt(app, "/Oracle")
	app.Use(prometheus.Middleware)
}

func setupSwagger(app *fiber.App, isDev bool) {

	if isDev {
		swaggerDir := "/app/docs/swagger.json"
		info, err := os.Stat(swaggerDir)
		if err != nil || !info.IsDir() {
			swaggerDir = "docs/swagger.json"
		}

		SwaggerConfig := swagger.Config{
			FilePath: swaggerDir,
			Path:     "/BibliothecAlexandrina",
			Title:    os.Getenv("APP_NAME"),
		}

		app.Use(swagger.New(SwaggerConfig))

	}
}

func setupLive(app *fiber.App) {
	app.Get("/ERACLESlives", func(c *fiber.Ctx) error {
		return c.SendString("OK")
	})
}

// LiveDoc Healthcheck endpoint
// @Summary      Healthcheck
// @Description  Verifica que el servicio esté vivo
// @Tags         Health
// @Produce      plain
// @Success      200 {string} string "OK"
// @Router       /ERACLESlives [get]
func liveDoc(c *fiber.Ctx) error {
	return c.SendString("OK")
}

// MetricsDoc Prometheus metrics endpoint
// @Summary      Métricas Prometheus
// @Description  Expone métricas para Prometheus
// @Tags         Metrics
// @Produce      plain
// @Success      200 {string} string "Prometheus metrics"
// @Router       /Oracle [get]
func metricsDoc(c *fiber.Ctx) error {
	return c.SendString("Prometheus metrics")
}

// SwaggerDoc Swagger UI endpoint
// @Summary      Swagger UI
// @Description  Interfaz web para explorar la API usando Swagger
// @Tags         Documentation
// @Produce      html
// @Success      200 {string} string "Swagger UI"
// @Router       /BibliothecAlexandrina [get]
func swaggerDoc(c *fiber.Ctx) error {
	// Redirige al path donde se sirve el Swagger UI
	return c.Redirect("/BibliothecAlexandrina", fiber.StatusFound)
}
