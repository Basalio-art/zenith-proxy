package handlers

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"

	"stream-proxy/internal/cache"
	"stream-proxy/internal/config"
	"stream-proxy/internal/embed"
	"stream-proxy/internal/media"
	"stream-proxy/internal/policy"
	"stream-proxy/internal/providers"
	"stream-proxy/internal/resolve"
)

type SourcesResponse struct {
	AnilistID  int                        `json:"anilistId"`
	Episode    int                        `json:"episode"`
	Audio      string                     `json:"audio"`
	Provider   string                     `json:"provider"`
	Sources    []resolve.NormalizedSource `json:"sources"`
	ErrorClass string                     `json:"errorClass,omitempty"`
	Error      string                     `json:"error,omitempty"`
}

func Sources(cfg *config.Config) gin.HandlerFunc {
	anivexa := resolve.NewAnivexaClient(cfg)
	allowlist := policy.GlobalAllowlist

	return func(c *gin.Context) {
		ctx := c.Request.Context()

		anilistID := c.Query("anilist")
		provider := c.Query("provider")
		audio := c.Query("audio")
		epStr := c.Query("ep")

		if anilistID == "" || provider == "" || audio == "" || epStr == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "missing required params: anilist, provider, audio, ep"})
			return
		}

		var anilist, ep int
		fmt.Sscanf(anilistID, "%d", &anilist)
		fmt.Sscanf(epStr, "%d", &ep)

		wr, err := anivexa.GetWatch(ctx, provider, anilist, audio, ep)
		if err != nil {
			c.JSON(http.StatusBadGateway, gin.H{
				"error":    "upstream_failed",
				"provider": provider,
				"anilist":  anilist,
				"episode":  ep,
				"detail":   err.Error(),
			})
			return
		}

		sources := resolve.NormalizeSources(wr, provider)

		// Register hosts in allowlist
		for _, s := range sources {
			if u, err := url.Parse(s.URL); err == nil {
				allowlist.Register(u.Hostname())
			}
		}

		errClass := "ok"
		errMsg := ""
		if len(sources) == 1 && sources[0].ErrorClass != "" && sources[0].ErrorClass != "ok" {
			errClass = sources[0].ErrorClass
			errMsg = sources[0].RawError
			sources = []resolve.NormalizedSource{}
		}

		c.JSON(http.StatusOK, SourcesResponse{
			AnilistID:  anilist,
			Episode:    ep,
			Audio:      audio,
			Provider:   provider,
			Sources:    sources,
			ErrorClass: errClass,
			Error:      errMsg,
		})
	}
}

func Play(cfg *config.Config) gin.HandlerFunc {
	pc := cache.NewPlaylistCache(&cache.PlaylistCacheConfig{
		MasterTTL:   cfg.CacheMasterTTL,
		VariantTTL:  cfg.CacheVariantTTL,
		MediaTTL:    cfg.CacheMediaTTL,
		MPDTTL:      cfg.CacheMPDTTL,
		EmbedTTL:    cfg.CacheEmbedTTL,
		NegativeTTL: cfg.CacheNegativeTTL,
	})

	return func(c *gin.Context) {
		ctx := c.Request.Context()

		tokenStr := c.Query("token")
		var targetURL, provider, codec string
		var playlistKey []byte
		var headerSet http.Header

		if tokenStr != "" {
			// Token-based flow (new secure API)
			payload, err := policy.VerifyToken(cfg.HMACSecret, tokenStr)
			if err != nil {
				c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
				return
			}

			targetURL = payload.URL
			provider = payload.Provider
			codec = payload.Codec
			if codec == "" {
				codec = inferCodec(provider, targetURL)
			}
			playlistKey, _ = base64.StdEncoding.DecodeString(c.Query("playlist_key"))

			// Validate URL against allowlist (enforced for token flow)
			_, err = policy.ValidateURL(targetURL, policy.GlobalAllowlist, true)
			if err != nil {
				c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
				return
			}

			// Get header set for provider (from manifest or defaults)
			headerSet = getHeaderSetForProvider(provider, targetURL)
		} else {
			// Legacy proxy flow (backwards compatibility)
			targetURL = c.Query("url")
			if targetURL == "" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "url parameter required"})
				return
			}

			referer := c.Query("referer")
			origin := c.Query("origin")
			auth := c.Query("auth")

			// Validate URL against allowlist (NOT enforced for legacy flow - SSRF protection still applies)
			_, err := policy.ValidateURL(targetURL, policy.GlobalAllowlist, false)
			if err != nil {
				c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
				return
			}

			// Extract provider from URL or use default
			provider = extractProviderFromURL(targetURL)
			codec = inferCodec(provider, targetURL)

			// Build header set from provider config (includes provider-specific headers)
			headerSet = getHeaderSetForProvider(provider, targetURL)
			// Override with explicit query params if provided
			if referer != "" {
				headerSet.Set("Referer", referer)
			}
			if origin != "" {
				headerSet.Set("Origin", origin)
			}
			if auth != "" {
				headerSet.Set("Authorization", auth)
			}
		}

		// Override with token payload codec
		if codec == "" {
			codec = inferCodec(provider, targetURL)
		}

		if len(playlistKey) == 0 {
			playlistKey, _ = base64.StdEncoding.DecodeString(c.Query("playlist_key"))
		}

		// Fast kind detection from URL extension to avoid probe round-trip
		kind := detectKindFromURL(targetURL)
		if kind == media.MediaKindUnknown {
			// Only probe when URL extension is ambiguous
			probe, _ := media.ProbeMedia(ctx, targetURL, headerSet, cfg)
			if probe != nil {
				kind = probe.Kind
			}
		}

		// Check cache for playlists
		cacheKey := buildCacheKey(targetURL, provider, kind, headerSet)
		var cached *cache.Entry
		var hit bool

		switch kind {
		case media.MediaKindHLS:
			cached, hit = pc.GetMaster(cacheKey)
		case media.MediaKindDASH:
			cached, hit = pc.GetMPD(cacheKey)
		}

		if hit && cached != nil && !cached.Negative {
			serveCached(c, cached)
			return
		}

		// Stream the media
		err := media.StreamMedia(ctx, c.Writer, c.Request, targetURL, headerSet, kind, codec, playlistKey, cfg)
		if err != nil {
			// Cache negative result for errors
			if strings.Contains(err.Error(), "404") || strings.Contains(err.Error(), "403") || strings.Contains(err.Error(), "502") || strings.Contains(err.Error(), "unsupported_anti_bot") {
				pc.SetNegative(cacheKey, 0)
			}
			// Don't write JSON if response already started
			if !c.Writer.Written() {
				c.JSON(http.StatusBadGateway, gin.H{"error": "upstream_failed", "detail": err.Error()})
			}
			return
		}
	}
}

func Embed(cfg *config.Config) gin.HandlerFunc {
	// Use the new dual-mode embed player handler
	playerHandler := embed.EmbedPlayerHandler(cfg)
	return func(c *gin.Context) {
		playerHandler(c.Writer, c.Request)
	}
}

func getHeaderSetForProvider(provider, targetURL string) http.Header {
	// Use manifest if available
	m := providers.LoadedManifest
	if m != nil {
		return m.GetHeaderSet(provider, targetURL)
	}

	// Fallback defaults
	h := http.Header{
		"User-Agent": {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"},
		"Accept":     {"*/*"},
	}

	switch provider {
	case "reanime":
		h.Set("Referer", "https://flixcloud.cc/")
		h.Set("Origin", "https://flixcloud.cc")
		h.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
	case "anikoto":
		h.Set("Referer", "https://megaplay.buzz/")
	case "animegg":
		h.Set("Referer", "https://www.animegg.org/")
	case "anizone":
		// works bare
	case "aniwaves":
		h.Set("Referer", "https://play.echovideo.ru/")
	case "kaa":
		h.Set("Referer", "https://krussdomi.com/")
		h.Set("Origin", "https://krussdomi.com") // no trailing slash
	case "animedunya":
		h.Set("Referer", "https://anime-dunya.com/")
	case "animeonsen":
		h.Set("Referer", "https://www.animeonsen.xyz/")
	case "senshi":
		h.Set("Referer", "https://senshi.to/")
	case "mkissa":
		h.Set("Referer", "https://mkissa.to/")
	}

	return h
}

func inferCodec(provider, url string) string {
	if provider == "reanime" && strings.Contains(url, "flixcloud") {
		return "flixcloud-b64-xor"
	}
	return "none"
}

func extractProviderFromURL(targetURL string) string {
	// Try to determine provider from URL hostname
	u, err := url.Parse(targetURL)
	if err != nil {
		return "unknown"
	}
	host := u.Hostname()

	// Map known hosts to providers
	switch {
	case strings.Contains(host, "flixcloud") || strings.Contains(host, "vault-"):
		return "reanime"
	case strings.Contains(host, "nexabloom") || strings.Contains(host, "wolfn") || strings.Contains(host, "megaplay"):
		return "anikoto"
	case strings.Contains(host, "animegg"):
		return "animegg"
	case strings.Contains(host, "vid-cdn"):
		return "anizone"
	case strings.Contains(host, "echovideo") || strings.Contains(host, "mfw09") || strings.Contains(host, "myvidplay"):
		return "aniwaves"
	case strings.Contains(host, "krussdomi") || strings.Contains(host, "advancedairesearchlab"):
		return "kaa"
	case strings.Contains(host, "anime-dunya"):
		return "animedunya"
	case strings.Contains(host, "animeonsen"):
		return "animeonsen"
	case strings.Contains(host, "anidap") || strings.Contains(host, "senshi"):
		return "senshi"
	case strings.Contains(host, "wixmp") || strings.Contains(host, "allanime") || strings.Contains(host, "streamsb") || strings.Contains(host, "ok.ru") || strings.Contains(host, "streamlare"):
		return "mkissa"
	}
	return "unknown"
}

func buildCacheKey(targetURL, provider string, kind media.MediaKind, headers http.Header) string {
	var b strings.Builder
	b.WriteString(targetURL)
	b.WriteString("|")
	b.WriteString(provider)
	b.WriteString("|")
	b.WriteString(headers.Get("Referer"))
	b.WriteString("|")
	b.WriteString(headers.Get("Origin"))
	return b.String()
}

func serveCached(c *gin.Context, entry *cache.Entry) {
	for k, v := range entry.Headers {
		c.Header(k, v)
	}
	c.Data(entry.StatusCode, "application/octet-stream", entry.Data)
}

func extractHost(urlStr string) string {
	if strings.HasPrefix(urlStr, "http://") {
		urlStr = urlStr[7:]
	} else if strings.HasPrefix(urlStr, "https://") {
		urlStr = urlStr[8:]
	}
	if idx := strings.Index(urlStr, "/"); idx >= 0 {
		return urlStr[:idx]
	}
	return urlStr
}

// detectKindFromURL quickly classifies media type from URL path/extension
// Returns MediaKindUnknown if ambiguous (caller should probe)
func detectKindFromURL(rawURL string) media.MediaKind {
	u, err := url.Parse(rawURL)
	if err != nil {
		return media.MediaKindUnknown
	}
	path := strings.ToLower(u.Path)
	switch {
	case strings.HasSuffix(path, ".m3u8") || strings.Contains(path, "/master.m3u8") || strings.Contains(path, "/playlist.m3u8") || strings.Contains(path, "manifest.m3u8"):
		return media.MediaKindHLS
	case strings.HasSuffix(path, ".mpd") || strings.Contains(path, "manifest.mpd"):
		return media.MediaKindDASH
	case strings.HasSuffix(path, ".mp4") || strings.HasSuffix(path, ".m4v") || strings.HasSuffix(path, ".m4s") || strings.HasSuffix(path, ".mpd") || strings.Contains(path, ".mp4?") || strings.Contains(path, "/video.mp4"):
		return media.MediaKindMP4
	case strings.HasSuffix(path, ".webm") || strings.HasSuffix(path, ".mkv"):
		return media.MediaKindWebM
	case strings.HasSuffix(path, ".ts") || strings.HasSuffix(path, ".m4s") || strings.HasSuffix(path, ".m4a") || strings.Contains(path, "/segment") || strings.Contains(path, "/seg_"):
		// Could be HLS segment or DASH init/media - probe needed
		return media.MediaKindUnknown
	}
	return media.MediaKindUnknown
}
