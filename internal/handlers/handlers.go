package handlers

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"stream-proxy/internal/config"
	"stream-proxy/internal/policy"
	"stream-proxy/internal/providers"
)

func Health(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":       "ok",
			"service":      "stream-proxy",
			"anivexa_base": cfg.AnivexaBase,
		})
	}
}

func Meta(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		m := providers.LoadedManifest
		hostCount := 0
		patternCount := 0
		if m != nil {
			for _, p := range m.Providers {
				hostCount += len(p.Hosts)
				for _, h := range p.Hosts {
					if strings.Contains(h, ".") {
						patternCount++
					}
				}
			}
		}
		c.JSON(http.StatusOK, gin.H{
			"name":              "stream-proxy",
			"version":           "0.1.0",
			"anivexa_base":      cfg.AnivexaBase,
			"providers":         []string{"mkissa", "reanime", "anikoto", "animegg", "anizone", "aniwaves", "kaa", "animedunya", "animeonsen", "senshi"},
			"allowlist_hosts":   policy.GlobalAllowlist.HostCount(),
			"allowlist_patterns": policy.GlobalAllowlist.PatternCount(),
			"manifest_loaded":   m != nil,
			"manifest_hosts":    hostCount,
			"manifest_patterns": patternCount,
		})
	}
}