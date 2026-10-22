package server

import (
	"fmt"
	"os"

	"github.com/gin-gonic/gin"

	"stream-proxy/internal/config"
	"stream-proxy/internal/handlers"
	"stream-proxy/internal/middleware"
	"stream-proxy/internal/providers"
)

func NewRouter(cfg *config.Config) *gin.Engine {
	if cfg.LogLevel != "debug" {
		gin.SetMode(gin.ReleaseMode)
	}

	// Load provider manifest from embedded file to populate allowlist
	var err error
	_, err = providers.LoadManifestEmbedded()
	if err != nil {
		// Fatal: manifest is required for SSRF allowlist
		fmt.Fprintf(os.Stderr, "FATAL: failed to load embedded provider manifest: %v\n", err)
		os.Exit(1)
	}

	r := gin.New()

	if cfg.LogLevel != "debug" {
		gin.SetMode(gin.ReleaseMode)
	}

	// Core middleware
	r.Use(middleware.Recovery())
	r.Use(middleware.RequestID())
	r.Use(middleware.Logger())
	r.Use(middleware.CORS(cfg.CORSAllowedOrigins))
	r.Use(middleware.SecurityHeaders())
	r.Use(middleware.RateLimit(cfg.MaxGlobalConcurrent))

	// Health & meta
	r.GET("/healthz", handlers.Health(cfg))
	r.GET("/v1/meta", handlers.Meta(cfg))

	// Source resolution (calls anivexa)
	r.GET("/v1/sources", handlers.Sources(cfg))

	// Media playback (primary endpoint: /stream/proxy)
	r.GET("/stream/proxy", handlers.Play(cfg))
	r.HEAD("/stream/proxy", handlers.Play(cfg))

	// Embed inspection (iframe-able HTML player page)
	r.GET("/v1/embed", middleware.AllowFraming(), handlers.Embed(cfg))

	// Global OPTIONS (removed wildcard to avoid conflict)
	// OPTIONS is handled by CORS middleware

	return r
}
