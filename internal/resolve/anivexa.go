package resolve

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"stream-proxy/internal/config"
	"stream-proxy/internal/policy"
)

type AnivexaClient struct {
	baseURL    string
	httpClient *http.Client
}

func NewAnivexaClient(cfg *config.Config) *AnivexaClient {
	return &AnivexaClient{
		baseURL: strings.TrimSuffix(cfg.AnivexaBase, "/"),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				DialContext: (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
				TLSHandshakeTimeout: 10 * time.Second,
			},
		},
	}
}

type EpisodeSource struct {
	ID       string `json:"id"`
	Number   int    `json:"number"`
	Title    string `json:"title,omitempty"`
	Audio    string `json:"audio"`
	Duration int    `json:"duration,omitempty"`
}

type WatchResponse struct {
	AnilistID int    `json:"anilistId"`
	Episode   int    `json:"episode"`
	Audio     string `json:"audio"`
	Streams   []Stream `json:"streams"`
	Sources   []Source `json:"sources,omitempty"`
	Error     string `json:"error,omitempty"`
	RawError  string `json:"Raw-ERROR,omitempty"`
}

type Stream struct {
	URL        string            `json:"url"`
	Type       string            `json:"type"`
	Server     string            `json:"server,omitempty"`
	Referer    string            `json:"referer,omitempty"`
	EmbedURL   string            `json:"embed,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	Subtitles  []Subtitle        `json:"subtitles,omitempty"`
	Priority   float64           `json:"priority,omitempty"`
	IsActive   bool              `json:"isActive,omitempty"`
	PlaylistKey string           `json:"playlist_key,omitempty"`
	Key        string            `json:"key,omitempty"`
	ThumbnailsVTT string          `json:"thumbnails_vtt,omitempty"`
	VideoTitle string            `json:"video_title,omitempty"`
	Intro      *Chapter          `json:"intro,omitempty"`
	Outro      *Chapter          `json:"outro,omitempty"`
}

type Source struct {
	Name         string `json:"name"`
	URL          string `json:"url"`
	ExtractedURL string `json:"extractedUrl,omitempty"`
	ExtractedType string `json:"extractedType,omitempty"`
	Type         string `json:"type"`
	Headers      map[string]string `json:"headers,omitempty"`
	Priority     float64           `json:"priority,omitempty"`
	Downloads    *Download         `json:"downloads,omitempty"`
}

type Download struct {
	SourceName string `json:"sourceName"`
	DownloadURL string `json:"downloadUrl"`
}

type Subtitle struct {
	URL     string `json:"url"`
	Label   string `json:"label"`
	Srclang string `json:"srclang"`
	Format  string `json:"format,omitempty"`
	Default bool   `json:"default,omitempty"`
	Source  string `json:"source,omitempty"`
}

type Chapter struct {
	Start int    `json:"start"`
	End   int    `json:"end"`
	Title string `json:"title,omitempty"`
}

func (c *AnivexaClient) GetWatch(ctx context.Context, provider string, anilistID int, audio string, ep int) (*WatchResponse, error) {
	// Map provider to anivexa route
	route := c.buildWatchRoute(provider, anilistID, audio, ep)
	if route == "" {
		return nil, fmt.Errorf("unknown provider: %s", provider)
	}

	reqURL := c.baseURL + route
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var wr WatchResponse
	if err := json.NewDecoder(resp.Body).Decode(&wr); err != nil {
		return nil, err
	}

	// Don't error on non-200 if we got a parseable response with error info
	// Let NormalizeSources classify it (no_source vs upstream_error)
	return &wr, nil
}

func (c *AnivexaClient) buildWatchRoute(provider string, anilistID int, audio string, ep int) string {
	// Handle special cases
	switch provider {
	case "reanime":
		return fmt.Sprintf("/watch/reanime/%d/%s/reanime-%d", anilistID, audio, ep)
	case "mkissa":
		return fmt.Sprintf("/watch/mkissa/%d/%s/mkissa-%d", anilistID, audio, ep)
	}
	// Standard pattern: /watch/<provider>/<anilistID>/<audio>/<provider>-<ep>
	return fmt.Sprintf("/watch/%s/%d/%s/%s-%d", provider, anilistID, audio, provider, ep)
}

type NormalizedSource struct {
	ID          string
	Kind        string // hls, mp4, dash, embed, json
	Server      string
	URL         string
	Headers     map[string]string
	Referer     string
	Subtitles   []Subtitle
	Priority    float64
	IsActive    bool
	Expiry      time.Time
	Codec       string // flixcloud-b64-xor, none
	PlaylistKey string
	ThumbnailsVTT string
	VideoTitle    string
	Intro         *Chapter
	Outro         *Chapter
	Provider      string
	ErrorClass    string // ok, no_source, upstream_error
	RawError      string
}

func NormalizeSources(wr *WatchResponse, provider string) []NormalizedSource {
	if wr == nil {
		return nil
	}

	var out []NormalizedSource

	// Process streams
	for _, s := range wr.Streams {
		if s.URL == "" {
			continue
		}
		kind := inferKind(s.URL, s.Type)
		headers := s.Headers
		if headers == nil {
			headers = make(map[string]string)
		}
		if s.Referer != "" {
			headers["Referer"] = s.Referer
		}

		ns := NormalizedSource{
			ID:            fmt.Sprintf("%s-%s-%d", provider, s.Server, wr.Episode),
			Kind:          kind,
			Server:        s.Server,
			URL:           s.URL,
			Headers:       headers,
			Referer:       s.Referer,
			Subtitles:     s.Subtitles,
			Priority:      s.Priority,
			IsActive:      s.IsActive,
			Codec:         inferCodec(provider, s.URL),
			PlaylistKey:   s.PlaylistKey,
			ThumbnailsVTT: s.ThumbnailsVTT,
			VideoTitle:    s.VideoTitle,
			Intro:         s.Intro,
			Outro:         s.Outro,
			Provider:      provider,
			ErrorClass:    "ok",
		}
		out = append(out, ns)
	}

	// Process sources (mkissa style)
	for _, s := range wr.Sources {
		url := s.ExtractedURL
		if url == "" {
			url = s.URL
		}
		if url == "" {
			continue
		}
		kind := inferKind(url, s.ExtractedType)
		if kind == "" {
			kind = inferKind(url, s.Type)
		}
		headers := s.Headers
		if headers == nil {
			headers = make(map[string]string)
		}

		ns := NormalizedSource{
			ID:       fmt.Sprintf("%s-%s-%s", provider, s.Name, strings.ReplaceAll(s.Type, "/", "-")),
			Kind:     kind,
			Server:   s.Name,
			URL:      url,
			Headers:  headers,
			Priority: s.Priority,
			Codec:    inferCodec(provider, url),
			Provider: provider,
			ErrorClass: "ok",
		}
		out = append(out, ns)
	}

	// Handle error responses
	if wr.Error != "" && len(out) == 0 {
		errClass := "upstream_error"
		msg := strings.ToLower(wr.Error)
		if strings.Contains(msg, "match not found") || strings.Contains(msg, "not found") || strings.Contains(msg, "404") {
			errClass = "no_source"
		}
		out = append(out, NormalizedSource{
			Provider:   provider,
			ErrorClass: errClass,
			RawError:   wr.Error,
		})
	}

	return out
}

func inferKind(urlStr, explicitType string) string {
	// Infer from URL first for direct stream patterns
	u := strings.ToLower(urlStr)
	if strings.Contains(u, ".m3u8") || strings.Contains(u, "mpegurl") || strings.Contains(u, "master.m3u8") || strings.Contains(u, "playlist.m3u8") {
		return "hls"
	}
	if strings.Contains(u, ".mpd") || strings.Contains(u, "manifest.mpd") {
		return "dash"
	}
	if strings.Contains(u, ".mp4") || strings.Contains(u, "video.mp4") {
		return "mp4"
	}
	
	// Then check explicit type
	if explicitType != "" {
		switch explicitType {
		case "hls", "m3u8":
			return "hls"
		case "mp4":
			return "mp4"
		case "dash", "mpd":
			return "dash"
		case "embed", "iframe":
			return "embed"
		}
	}
	
	// Fallback URL patterns for embed
	if strings.Contains(u, "embed") || strings.Contains(u, "iframe") || strings.Contains(u, "/e/") || strings.Contains(u, "ok.ru") || strings.Contains(u, "streamlare") || strings.Contains(u, "streamsb") {
		return "embed"
	}
	return "unknown"
}

func inferCodec(provider, urlStr string) string {
	if provider == "reanime" && strings.Contains(urlStr, "flixcloud") {
		return "flixcloud-b64-xor"
	}
	return "none"
}

// ValidateRedirectFunc for upstream client
func ValidateRedirectFunc(allowlist *policy.Allowlist) func(*url.URL) error {
	return func(u *url.URL) error {
		host := u.Hostname()
		if host == "" {
			return policy.ErrInvalidURL
		}
		if !allowlist.IsAllowed(host) {
			return policy.ErrHostNotAllowed
		}
		return nil
	}
}