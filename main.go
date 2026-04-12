package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"

	"github.com/gin-gonic/gin"
)

const (
	defaultPort    = 8080
	defaultHost    = "0.0.0.0"
	appName        = "sub2api"
	appVersion     = "dev"
)

// Config holds the application configuration.
type Config struct {
	Host    string
	Port    int
	Debug   bool
	Token   string // optional bearer token for protecting endpoints
}

func main() {
	cfg := parseConfig()

	if !cfg.Debug {
		gin.SetMode(gin.ReleaseMode)
	}

	router := setupRouter(cfg)

	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	log.Printf("%s %s listening on %s", appName, appVersion, addr)

	server := &http.Server{
		Addr:    addr,
		Handler: router,
	}

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
}

// parseConfig reads configuration from flags and environment variables.
// Environment variables take precedence over defaults; flags override env vars.
func parseConfig() *Config {
	cfg := &Config{}

	// Defaults from environment
	host := envOrDefault("SUB2API_HOST", defaultHost)
	port := defaultPort
	if p, err := strconv.Atoi(os.Getenv("SUB2API_PORT")); err == nil && p > 0 {
		port = p
	}
	token := os.Getenv("SUB2API_TOKEN")
	debug := os.Getenv("SUB2API_DEBUG") == "true" || os.Getenv("GIN_MODE") == "debug"

	flag.StringVar(&cfg.Host, "host", host, "host address to listen on (env: SUB2API_HOST)")
	flag.IntVar(&cfg.Port, "port", port, "port to listen on (env: SUB2API_PORT)")
	flag.StringVar(&cfg.Token, "token", token, "optional bearer token for endpoint auth (env: SUB2API_TOKEN)")
	flag.BoolVar(&cfg.Debug, "debug", debug, "enable debug/verbose logging (env: SUB2API_DEBUG)")
	flag.Parse()

	return cfg
}

// setupRouter configures and returns the Gin engine with all routes registered.
func setupRouter(cfg *Config) *gin.Engine {
	router := gin.New()
	router.Use(gin.Logger(), gin.Recovery())

	// Health / readiness probe
	router.GET("/health", handleHealth)
	router.GET("/ping", handleHealth)

	// API v1 group — optionally protected by bearer token
	v1 := router.Group("/api/v1")
	if cfg.Token != "" {
		v1.Use(bearerAuthMiddleware(cfg.Token))
	}
	{
		v1.GET("/convert", handleConvert)
	}

	return router
}

// handleHealth returns a simple liveness response.
func handleHealth(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":  "ok",
		"service": appName,
		"version": appVersion,
	})
}

// handleConvert is a placeholder for the subscription-to-API conversion logic.
// The actual implementation lives in the converter package.
func handleConvert(c *gin.Context) {
	subURL := c.Query("url")
	if subURL == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "url query parameter is required"})
		return
	}
	// TODO: delegate to converter.Convert(subURL)
	c.JSON(http.StatusNotImplemented, gin.H{"error": "converter not yet implemented", "url": subURL})
}

// bearerAuthMiddleware validates a static Bearer token.
func bearerAuthMiddleware(token string) gin.HandlerFunc {
	expected := "Bearer " + token
	return func(c *gin.Context) {
		if c.GetHeader("Authorization") != expected {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		c.Next()
	}
}

// envOrDefault returns the value of the environment variable key, or fallback
// if the variable is unset or empty.
func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
