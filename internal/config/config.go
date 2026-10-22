package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	ProxyPort          int
	AnivexaBase        string
	HMACSecret         []byte
	CORSAllowedOrigins string

	UpstreamDialTimeout    time.Duration
	UpstreamResponseTimeout time.Duration
	UpstreamIdleTimeout    time.Duration
	UpstreamPlaylistTimeout time.Duration

	CacheMasterTTL    time.Duration
	CacheVariantTTL   time.Duration
	CacheMediaTTL     time.Duration
	CacheMPDTTL       time.Duration
	CacheEmbedTTL     time.Duration
	CacheNegativeTTL  time.Duration

	MaxPlaylistSize int64
	MaxMPDSize      int64
	MaxEmbedSize    int64

	MaxGlobalConcurrent  int
	MaxPerHostConcurrent int

	LogLevel string
}

func Load() *Config {
	c := &Config{
		ProxyPort:              getEnvInt("PROXY_PORT", 9190),
		AnivexaBase:            getEnv("ANIVEXA_BASE", "http://localhost:9189"),
		HMACSecret:             []byte(getEnv("HMAC_SECRET", "dev-secret-change-me-32-bytes-long!!")),
		CORSAllowedOrigins:     getEnv("CORS_ALLOWED_ORIGINS", "*"),

		UpstreamDialTimeout:     getEnvDuration("UPSTREAM_DIAL_TIMEOUT", 10*time.Second),
		UpstreamResponseTimeout: getEnvDuration("UPSTREAM_RESPONSE_TIMEOUT", 15*time.Second),
		UpstreamIdleTimeout:     getEnvDuration("UPSTREAM_IDLE_TIMEOUT", 30*time.Second),
		UpstreamPlaylistTimeout: getEnvDuration("UPSTREAM_PLAYLIST_TIMEOUT", 30*time.Second),

		CacheMasterTTL:    getEnvDuration("CACHE_MASTER_TTL", 60*time.Second),
		CacheVariantTTL:   getEnvDuration("CACHE_VARIANT_TTL", 15*time.Second),
		CacheMediaTTL:     getEnvDuration("CACHE_MEDIA_TTL", 15*time.Second),
		CacheMPDTTL:       getEnvDuration("CACHE_MPD_TTL", 30*time.Second),
		CacheEmbedTTL:     getEnvDuration("CACHE_EMBED_TTL", 60*time.Second),
		CacheNegativeTTL:  getEnvDuration("CACHE_NEGATIVE_TTL", 10*time.Second),

		MaxPlaylistSize: getEnvInt64("MAX_PLAYLIST_SIZE", 2*1024*1024),
		MaxMPDSize:      getEnvInt64("MAX_MPD_SIZE", 1024*1024),
		MaxEmbedSize:    getEnvInt64("MAX_EMBED_SIZE", 4*1024*1024),

		MaxGlobalConcurrent:  getEnvInt("MAX_GLOBAL_CONCURRENT", 64),
		MaxPerHostConcurrent: getEnvInt("MAX_PER_HOST_CONCURRENT", 8),

		LogLevel: getEnv("LOG_LEVEL", "info"),
	}
	return c
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getEnvInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return def
}

func getEnvInt64(key string, def int64) int64 {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.ParseInt(v, 10, 64); err == nil {
			return i
		}
	}
	return def
}

func getEnvDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return time.Duration(i) * time.Second
		}
	}
	return def
}