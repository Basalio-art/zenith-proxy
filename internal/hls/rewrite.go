package hls

import (
	"bytes"
	"encoding/base64"
	"errors"
	"net/url"
	"regexp"
	"strings"
)

var (
	// Matches URI="..." in HLS tags
	uriRegex = regexp.MustCompile(`URI="([^"]+)"`)
	// Matches plain segment/playlist lines (not tags)
	lineRegex = regexp.MustCompile(`^[^#].+`)
)

type PlaylistType int

const (
	PlaylistTypeUnknown PlaylistType = iota
	PlaylistTypeMaster
	PlaylistTypeMedia
)

func DetectPlaylistType(body []byte) PlaylistType {
	text := strings.TrimSpace(string(body))
	if !strings.HasPrefix(text, "#EXTM3U") {
		return PlaylistTypeUnknown
	}
	if strings.Contains(text, "#EXT-X-STREAM-INF") || strings.Contains(text, "#EXT-X-I-FRAME-STREAM-INF") {
		return PlaylistTypeMaster
	}
	return PlaylistTypeMedia
}

func ResolveURL(base *url.URL, ref string) (string, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "", nil
	}
	if strings.HasPrefix(strings.ToLower(ref), "data:") {
		return ref, nil
	}
	u, err := url.Parse(ref)
	if err != nil {
		return "", err
	}
	return base.ResolveReference(u).String(), nil
}

func BuildProxyURL(targetURL, referer, origin, token, playlistKey string) string {
	v := url.Values{}
	v.Set("url", targetURL)
	if referer != "" {
		v.Set("referer", referer)
	}
	if origin != "" {
		v.Set("origin", origin)
	}
	if token != "" {
		v.Set("token", token)
	}
	if playlistKey != "" {
		v.Set("playlist_key", playlistKey)
	}
	return "/stream/proxy?" + v.Encode()
}

// RewriteManifest rewrites all URIs in an HLS manifest to go through the proxy
func RewriteManifest(manifest string, baseURL *url.URL, referer, origin, token string, codec string, playlistKey []byte) string {
	lines := strings.Split(manifest, "\n")

	// Base64 encode playlist key for query param
	playlistKeyStr := ""
	if len(playlistKey) > 0 {
		playlistKeyStr = base64.StdEncoding.EncodeToString(playlistKey)
	}

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		if trimmed == "" {
			continue
		}

		// HLS tag
		if strings.HasPrefix(trimmed, "#") {
			lines[i] = rewriteTagAttributes(line, baseURL, referer, origin, token, playlistKeyStr)
			continue
		}

		// Media segment or playlist reference
		absoluteURL, err := ResolveURL(baseURL, trimmed)
		if err != nil || absoluteURL == "" {
			continue
		}

		if strings.HasPrefix(strings.ToLower(absoluteURL), "data:") {
			continue
		}

		// Apply provider-specific rewrites before proxying
		if codec == "flixcloud-b64-xor" {
			absoluteURL = rewriteFlixcloudSegment(absoluteURL)
		}

		// Build proxy URL
		proxyReferer := referer
		if proxyReferer == "" {
			proxyReferer = baseURL.Scheme + "://" + baseURL.Host + "/"
		}
		proxyURL := BuildProxyURL(absoluteURL, proxyReferer, origin, token, playlistKeyStr)

		// Preserve indentation
		prefixLen := len(line) - len(strings.TrimLeft(line, " \t"))
		lines[i] = line[:prefixLen] + proxyURL
	}

	return strings.Join(lines, "\n")
}

func rewriteTagAttributes(line string, baseURL *url.URL, referer, origin, token, playlistKey string) string {
	return uriRegex.ReplaceAllStringFunc(line, func(match string) string {
		submatches := uriRegex.FindStringSubmatch(match)
		if len(submatches) != 2 {
			return match
		}
		rawURI := submatches[1]

		absoluteURL, err := ResolveURL(baseURL, rawURI)
		if err != nil || absoluteURL == "" {
			return match
		}

		if strings.HasPrefix(strings.ToLower(absoluteURL), "data:") {
			return match
		}

		proxyReferer := referer
		if proxyReferer == "" {
			proxyReferer = baseURL.Scheme + "://" + baseURL.Host + "/"
		}
		proxyURL := BuildProxyURL(absoluteURL, proxyReferer, origin, token, playlistKey)

		return `URI="` + proxyURL + `"`
	})
}

func rewriteFlixcloudSegment(urlStr string) string {
	// Flixcloud playlists list segments as .webp or .png but they're actually .ts
	// Rewrite extension to .ts for actual MPEG-TS content
	if strings.HasSuffix(urlStr, ".webp") || strings.HasSuffix(urlStr, ".png") {
		// Replace last extension
		for _, ext := range []string{".webp", ".png"} {
			if strings.HasSuffix(urlStr, ext) {
				return urlStr[:len(urlStr)-len(ext)] + ".ts"
			}
		}
	}
	return urlStr
}

// DecodeFlixcloudPlaylist decodes the base64+XOR encoded Flixcloud playlist
func DecodeFlixcloudPlaylist(encodedBody []byte, playlistKey []byte) ([]byte, error) {
	// Body is base64 text
	b64 := bytes.TrimSpace(encodedBody)
	decoded, err := base64StdDecode(b64)
	if err != nil {
		return nil, err
	}

	// XOR with repeating playlist key
	if len(playlistKey) == 0 {
		return decoded, nil
	}

	out := make([]byte, len(decoded))
	for i := range decoded {
		out[i] = decoded[i] ^ playlistKey[i%len(playlistKey)]
	}

	// Verify it's a valid playlist
	if !bytes.HasPrefix(bytes.TrimSpace(out), []byte("#EXTM3U")) {
		return nil, ErrInvalidPlaylist
	}

	return out, nil
}

// base64StdDecode handles standard base64 (flixcloud uses standard base64)
func base64StdDecode(data []byte) ([]byte, error) {
	// Try standard base64 first (flixcloud uses standard base64)
	s := string(data)
	// Add padding if needed
	if m := len(s) % 4; m != 0 {
		s += strings.Repeat("=", 4-m)
	}
	if decoded, err := base64.StdEncoding.DecodeString(s); err == nil {
		return decoded, nil
	}
	// Fallback to URL-safe
	return base64.URLEncoding.DecodeString(s)
}
var ErrInvalidPlaylist = errors.New("decoded playlist is not valid #EXTM3U")