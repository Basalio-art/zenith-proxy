package main

import (
	"context"
	"embed"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"stream-proxy/internal/config"
	"stream-proxy/internal/providers"
	"stream-proxy/internal/server"
)

//go:embed providers/manifest.yaml
var manifestYAML embed.FS

func main() {
	// Load embedded manifest
	data, err := manifestYAML.ReadFile("providers/manifest.yaml")
	if err != nil {
		log.Fatalf("failed to read embedded manifest: %v", err)
	}
	providers.ManifestYAML = data
	cfg := config.Load()

	// Initialize router
	router := server.NewRouter(cfg)

	srv := &http.Server{
		Addr:         ":" + strconv.Itoa(cfg.ProxyPort),
		Handler:      router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 0, // streaming responses need no write timeout
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		log.Printf("stream-proxy listening on :%d (anivexa: %s)", cfg.ProxyPort, cfg.AnivexaBase)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("forced shutdown: %v", err)
	}
	log.Println("exited")
}