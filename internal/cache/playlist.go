package cache

import (
	"sync"
	"time"
)

type Entry struct {
	Data       []byte
	Headers    map[string]string
	ExpiresAt  time.Time
	Negative   bool
	StatusCode int
}

type Cache struct {
	mu    sync.RWMutex
	items map[string]*Entry
	ttl   time.Duration
}

func NewCache(ttl time.Duration) *Cache {
	c := &Cache{
		items: make(map[string]*Entry),
		ttl:   ttl,
	}
	go c.janitor()
	return c
}

func (c *Cache) Set(key string, data []byte, headers map[string]string, statusCode int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items[key] = &Entry{
		Data:       data,
		Headers:    headers,
		ExpiresAt:  time.Now().Add(c.ttl),
		StatusCode: statusCode,
	}
}

func (c *Cache) SetNegative(key string, statusCode int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items[key] = &Entry{
		Negative:   true,
		StatusCode: statusCode,
		ExpiresAt:  time.Now().Add(c.ttl),
	}
}

func (c *Cache) Get(key string) (*Entry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.items[key]
	if !ok || time.Now().After(e.ExpiresAt) {
		return nil, false
	}
	return e, true
}

func (c *Cache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.items, key)
}

func (c *Cache) janitor() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		for k, e := range c.items {
			if now.After(e.ExpiresAt) {
				delete(c.items, k)
			}
		}
		c.mu.Unlock()
	}
}

// PlaylistCache is a specialized cache for HLS/DASH playlists
type PlaylistCache struct {
	masterCache   *Cache
	variantCache  *Cache
	mediaCache    *Cache
	mpdCache      *Cache
	embedCache    *Cache
	negativeCache *Cache
}

func NewPlaylistCache(cfg *PlaylistCacheConfig) *PlaylistCache {
	return &PlaylistCache{
		masterCache:   NewCache(cfg.MasterTTL),
		variantCache:  NewCache(cfg.VariantTTL),
		mediaCache:    NewCache(cfg.MediaTTL),
		mpdCache:      NewCache(cfg.MPDTTL),
		embedCache:    NewCache(cfg.EmbedTTL),
		negativeCache: NewCache(cfg.NegativeTTL),
	}
}

type PlaylistCacheConfig struct {
	MasterTTL   time.Duration
	VariantTTL  time.Duration
	MediaTTL    time.Duration
	MPDTTL      time.Duration
	EmbedTTL    time.Duration
	NegativeTTL time.Duration
}

func (pc *PlaylistCache) GetMaster(key string) (*Entry, bool)   { return pc.masterCache.Get(key) }
func (pc *PlaylistCache) SetMaster(key string, data []byte, headers map[string]string, status int) {
	pc.masterCache.Set(key, data, headers, status)
}
func (pc *PlaylistCache) GetVariant(key string) (*Entry, bool) { return pc.variantCache.Get(key) }
func (pc *PlaylistCache) SetVariant(key string, data []byte, headers map[string]string, status int) {
	pc.variantCache.Set(key, data, headers, status)
}
func (pc *PlaylistCache) GetMedia(key string) (*Entry, bool) { return pc.mediaCache.Get(key) }
func (pc *PlaylistCache) SetMedia(key string, data []byte, headers map[string]string, status int) {
	pc.mediaCache.Set(key, data, headers, status)
}
func (pc *PlaylistCache) GetMPD(key string) (*Entry, bool) { return pc.mpdCache.Get(key) }
func (pc *PlaylistCache) SetMPD(key string, data []byte, headers map[string]string, status int) {
	pc.mpdCache.Set(key, data, headers, status)
}
func (pc *PlaylistCache) GetEmbed(key string) (*Entry, bool) { return pc.embedCache.Get(key) }
func (pc *PlaylistCache) SetEmbed(key string, data []byte, headers map[string]string, status int) {
	pc.embedCache.Set(key, data, headers, status)
}
func (pc *PlaylistCache) GetNegative(key string) (*Entry, bool) { return pc.negativeCache.Get(key) }
func (pc *PlaylistCache) SetNegative(key string, status int) { pc.negativeCache.SetNegative(key, status) }

// Key builders
func MasterKey(url, headerSetID, codec string) string   { return "master:" + url + "|" + headerSetID + "|" + codec }
func VariantKey(url, headerSetID, codec string) string  { return "variant:" + url + "|" + headerSetID + "|" + codec }
func MediaKey(url, headerSetID string) string           { return "media:" + url + "|" + headerSetID }
func MPDKey(url, headerSetID string) string             { return "mpd:" + url + "|" + headerSetID }
func EmbedKey(url, headerSetID string) string           { return "embed:" + url + "|" + headerSetID }
func NegativeKey(url, headerSetID string) string        { return "neg:" + url + "|" + headerSetID }