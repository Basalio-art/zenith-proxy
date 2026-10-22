package policy

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"strings"
	"time"
)

var (
	ErrInvalidToken       = errors.New("invalid or expired token")
	ErrTokenExpired       = errors.New("token expired")
	ErrHostNotAllowed     = errors.New("host not in allowlist")
	ErrInvalidURL         = errors.New("invalid URL")
	ErrPrivateIP          = errors.New("private/reserved IP not allowed")
	ErrBlockedHostname    = errors.New("blocked hostname")
	ErrBlockedScheme      = errors.New("blocked scheme")
	ErrBlockedPort        = errors.New("blocked port")
	ErrDNSRebinding       = errors.New("dns rebinding detected")
)

type ValidateRedirectFunc func(*url.URL) error

type HeaderSet struct {
	Referer   string `json:"referer,omitempty"`
	Origin    string `json:"origin,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
	Auth      string `json:"auth,omitempty"`
	Extra     map[string]string `json:"extra,omitempty"`
}

type TokenPayload struct {
	URL         string    `json:"u"`
	Provider    string    `json:"p"`
	HeaderSetID string    `json:"h"`
	Exp         int64     `json:"e"`
	Kind        string    `json:"k"` // hls, mp4, dash, embed
	Codec       string    `json:"c,omitempty"` // flixcloud-b64-xor, none
}

func SignToken(secret []byte, payload *TokenPayload) (string, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	b64 := base64.RawURLEncoding.EncodeToString(data)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(b64))
	sig := mac.Sum(nil)
	return "v1." + b64 + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func VerifyToken(secret []byte, token string) (*TokenPayload, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != "v1" {
		return nil, ErrInvalidToken
	}
	data, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrInvalidToken
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(parts[1]))
	expected := mac.Sum(nil)
	provided, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !hmac.Equal(expected, provided) {
		return nil, ErrInvalidToken
	}
	var payload TokenPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, ErrInvalidToken
	}
	if time.Now().Unix() > payload.Exp {
		return nil, ErrTokenExpired
	}
	return &payload, nil
}

// ValidateURL performs comprehensive SSRF checks with optional allowlist enforcement
func ValidateURL(rawURL string, allowlist *Allowlist, enforceAllowlist bool) (*url.URL, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, ErrInvalidURL
	}

	// Scheme check
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, ErrBlockedScheme
	}

	// Host check
	host := u.Hostname()
	if host == "" {
		return nil, ErrInvalidURL
	}

	// Blocked hostnames
	blockedHosts := []string{
		"localhost", "localhost.localdomain",
		"metadata.google.internal", "metadata", "169.254.169.254",
		"100.100.100.200", "metadata.azure.com",
	}
	hostLower := strings.ToLower(host)
	for _, b := range blockedHosts {
		if hostLower == b || strings.HasSuffix(hostLower, "."+b) {
			return nil, ErrBlockedHostname
		}
	}
	if strings.HasSuffix(hostLower, ".local") || strings.HasSuffix(hostLower, ".internal") || hostLower == "localhost" {
		return nil, ErrBlockedHostname
	}

	// Port check
	if u.Port() != "" {
		port := u.Port()
		if port != "80" && port != "443" {
			return nil, ErrBlockedPort
		}
	}

	// Resolve and check IP
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return nil, ErrInvalidURL
	}

	for _, ip := range ips {
		if isPrivateOrReserved(ip) {
			return nil, ErrPrivateIP
		}
		if isMetadataIP(ip) {
			return nil, ErrBlockedHostname
		}
	}

	// Allowlist check (only enforced for token-based flow)
	if enforceAllowlist && allowlist != nil && !allowlist.IsAllowed(host) {
		return nil, ErrHostNotAllowed
	}

	return u, nil
}

func isPrivateOrReserved(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 != nil {
		// 127.0.0.0/8
		if ip4[0] == 127 {
			return true
		}
		// 10.0.0.0/8
		if ip4[0] == 10 {
			return true
		}
		// 172.16.0.0/12
		if ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
			return true
		}
		// 192.168.0.0/16
		if ip4[0] == 192 && ip4[1] == 168 {
			return true
		}
		// 169.254.0.0/16
		if ip4[0] == 169 && ip4[1] == 254 {
			return true
		}
		// 100.64.0.0/10 (CGNAT)
		if ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
			return true
		}
		// 0.0.0.0/8
		if ip4[0] == 0 {
			return true
		}
		// 224.0.0.0/4 (multicast)
		if ip4[0] >= 224 {
			return true
		}
		// 255.255.255.255
		if ip4[0] == 255 && ip4[1] == 255 && ip4[2] == 255 && ip4[3] == 255 {
			return true
		}
		return false
	}

	// IPv6
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	// fc00::/7 (ULA)
	if len(ip) == 16 && (ip[0]&0xfe) == 0xfc {
		return true
	}
	// fe80::/10 (link-local)
	if len(ip) == 16 && ip[0] == 0xfe && (ip[1]&0xc0) == 0x80 {
		return true
	}
	// ::ffff:0:0/96 (IPv4-mapped)
	if len(ip) == 16 && ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] == 0 && ip[4] == 0 && ip[5] == 0 && ip[6] == 0 && ip[7] == 0 && ip[8] == 0 && ip[9] == 0 && ip[10] == 0xff && ip[11] == 0xff {
		return isPrivateOrReserved(ip[12:])
	}
	return false
}

func isMetadataIP(ip net.IP) bool {
	// 169.254.169.254
	if ip4 := ip.To4(); ip4 != nil {
		return ip4[0] == 169 && ip4[1] == 254 && ip4[2] == 169 && ip4[3] == 254
	}
	return false
}

// PinnedDialer creates a dialer that resolves once and pins the IP
func PinnedDialer(validatedURL *url.URL) func(network, address string) (net.Conn, error) {
	host := validatedURL.Hostname()
	port := validatedURL.Port()
	if port == "" {
		if validatedURL.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	ips, _ := net.LookupIP(host)
	var firstIP net.IP
	for _, ip := range ips {
		if !isPrivateOrReserved(ip) && !isMetadataIP(ip) {
			firstIP = ip
			break
		}
	}
	if firstIP == nil {
		return nil
	}

	pinnedAddr := net.JoinHostPort(firstIP.String(), port)
	return func(network, address string) (net.Conn, error) {
		return net.Dial(network, pinnedAddr)
	}
}