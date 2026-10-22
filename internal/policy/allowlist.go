package policy

import (
	"strings"
	"sync"
)

type Allowlist struct {
	mu       sync.RWMutex
	hosts    map[string]bool
	patterns []string
}

func NewAllowlist() *Allowlist {
	return &Allowlist{
		hosts:    make(map[string]bool),
		patterns: []string{},
	}
}

func (a *Allowlist) Register(host string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.hosts[strings.ToLower(host)] = true
}

func (a *Allowlist) RegisterPattern(pattern string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.patterns = append(a.patterns, strings.ToLower(pattern))
}

func (a *Allowlist) IsAllowed(host string) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	hl := strings.ToLower(host)
	if a.hosts[hl] {
		return true
	}
	for _, p := range a.patterns {
		if matchPattern(hl, p) {
			return true
		}
	}
	return false
}

func (a *Allowlist) HostCount() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.hosts)
}

func (a *Allowlist) PatternCount() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.patterns)
}

func matchPattern(host, pattern string) bool {
	// Simple suffix matching for patterns like "*.flixcloud.cc"
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[2:]
		return strings.HasSuffix(host, suffix)
	}
	return host == pattern
}

// GlobalAllowlist is the singleton instance
var GlobalAllowlist = NewAllowlist()