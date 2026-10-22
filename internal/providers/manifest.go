package providers

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"stream-proxy/internal/policy"
)

type Manifest struct {
	Providers []ProviderConfig `yaml:"providers"`
}

// ManifestYAML is the embedded manifest.yaml content (populated by go:embed in main)
var ManifestYAML []byte

// LoadManifestEmbedded loads the manifest from the embedded []byte
func LoadManifestEmbedded() (*Manifest, error) {
	if len(ManifestYAML) == 0 {
		return nil, fmt.Errorf("no embedded manifest data (go:embed missing)")
	}
	var m Manifest
	if err := yaml.Unmarshal(ManifestYAML, &m); err != nil {
		return nil, fmt.Errorf("yaml unmarshal: %w", err)
	}

	// Register all hosts in global allowlist
	for _, p := range m.Providers {
		for _, h := range p.Hosts {
			policy.GlobalAllowlist.Register(h)
			// Also register wildcard for subdomains ONLY if host has at least 3 parts (e.g., cdn.example.com -> *.example.com)
			// Skip 2-part hosts (e.g., example.com) to avoid overly broad patterns like *.com
			if strings.Count(h, ".") >= 2 {
				parts := strings.SplitN(h, ".", 2)
				if len(parts) == 2 {
					policy.GlobalAllowlist.RegisterPattern("*." + parts[1])
				}
			}
		}
	}

	// Store for later access by handlers
	LoadedManifest = &m

	return &m, nil
}

// LoadedManifest holds the loaded manifest for access by handlers
var LoadedManifest *Manifest

// LoadManifestFile loads the manifest from a file path (legacy, for tests)
func LoadManifestFile(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var m Manifest
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, err
	}

	// Register all hosts in global allowlist
	for _, p := range m.Providers {
		for _, h := range p.Hosts {
			policy.GlobalAllowlist.Register(h)
			if strings.Contains(h, ".") {
				parts := strings.SplitN(h, ".", 2)
				if len(parts) == 2 {
					policy.GlobalAllowlist.RegisterPattern("*." + parts[1])
				}
			}
		}
	}

	return &m, nil
}

type ProviderConfig struct {
	ID          string            `yaml:"id"`
	Name        string            `yaml:"name"`
	Hosts       []string          `yaml:"hosts"`
	HeaderSets  map[string]HeaderSet `yaml:"header_sets"`
	Codecs      map[string]string `yaml:"codecs"`
	Quirks      []string          `yaml:"quirks"`
	Notes       string            `yaml:"notes"`
}

type HeaderSet struct {
	Referer    string `yaml:"referer"`
	Origin     string `yaml:"origin"`
	UserAgent  string `yaml:"user_agent"`
}

func LoadManifest(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var m Manifest
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, err
	}

	// Register all hosts in global allowlist
	for _, p := range m.Providers {
		for _, h := range p.Hosts {
			policy.GlobalAllowlist.Register(h)
			// Also register wildcard for subdomains ONLY if host has at least 3 parts (e.g., cdn.example.com -> *.example.com)
			// Skip 2-part hosts (e.g., example.com) to avoid overly broad patterns like *.com
			if strings.Count(h, ".") >= 2 {
				parts := strings.SplitN(h, ".", 2)
				if len(parts) == 2 {
					policy.GlobalAllowlist.RegisterPattern("*." + parts[1])
				}
			}
		}
	}

	return &m, nil
}

func (m *Manifest) GetProvider(id string) *ProviderConfig {
	for i := range m.Providers {
		if m.Providers[i].ID == id {
			return &m.Providers[i]
		}
	}
	return nil
}

func (m *Manifest) GetHeaderSet(providerID, targetURL string) http.Header {
	p := m.GetProvider(providerID)
	if p == nil {
		return defaultHeaderSet()
	}

	// Determine which header set to use based on URL host
	for _, hsName := range []string{"flixcloud", "megaplay", "krussdomi_master", "krussdomi_segment", "echovideo", "default"} {
		if hs, ok := p.HeaderSets[hsName]; ok {
			if matchesHost(targetURL, hsName, p) {
				return hs.ToHeaders()
			}
		}
	}

	// Fallback to first header set
	for _, hs := range p.HeaderSets {
		return hs.ToHeaders()
	}

	return defaultHeaderSet()
}

func matchesHost(targetURL, hsName string, p *ProviderConfig) bool {
	u, err := url.Parse(targetURL)
	if err != nil {
		return false
	}
	host := u.Hostname()

	// Simple matching logic
	switch hsName {
	case "flixcloud":
		return strings.Contains(host, "flixcloud") || strings.Contains(host, "vault-")
	case "megaplay":
		return strings.Contains(host, "nexabloom") || strings.Contains(host, "wolfn") || strings.Contains(host, "megaplay")
	case "krussdomi_master":
		return strings.Contains(host, "krussdomi")
	case "krussdomi_segment":
		return strings.Contains(host, "advancedairesearchlab")
	case "echovideo":
		return strings.Contains(host, "echovideo") || strings.Contains(host, "mfw09") || strings.Contains(host, "myvidplay")
	default:
		for _, h := range p.Hosts {
			if strings.Contains(host, h) {
				return true
			}
		}
	}
	return false
}

func (hs HeaderSet) ToHeaders() http.Header {
	h := http.Header{
		"User-Agent": {hs.UserAgent},
		"Accept":     {"*/*"},
	}
	if hs.Referer != "" {
		h.Set("Referer", hs.Referer)
	}
	if hs.Origin != "" {
		h.Set("Origin", hs.Origin)
	}
	return h
}

func defaultHeaderSet() http.Header {
	return http.Header{
		"User-Agent": {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"},
		"Accept":     {"*/*"},
	}
}