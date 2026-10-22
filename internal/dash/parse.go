package dash

import (
	"encoding/xml"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// MPD represents the root MPD element
type MPD struct {
	XMLName                 xml.Name `xml:"MPD"`
	Profiles                string   `xml:"profiles,attr"`
	Type                    string   `xml:"type,attr"`
	MediaPresentationDuration string   `xml:"mediaPresentationDuration,attr"`
	Periods                 []Period `xml:"Period"`
	BaseURLs                []BaseURL `xml:"BaseURL"`
	Locations               []Location `xml:"Location"`
}

// MediaPresentationDurationSeconds returns the duration in seconds (parses ISO 8601)
func (m *MPD) MediaPresentationDurationSeconds() float64 {
	return parseISO8601Duration(m.MediaPresentationDuration)
}

// parseISO8601Duration parses ISO 8601 duration format (e.g., PT25M40.9S, PT1H30M, PT0.5S)
func parseISO8601Duration(duration string) float64 {
	if duration == "" {
		return 0
	}
	// Remove PT prefix
	d := strings.TrimPrefix(duration, "PT")
	
	var hours, minutes, seconds float64
	
	// Parse hours
	if idx := strings.Index(d, "H"); idx >= 0 {
		hours, _ = strconv.ParseFloat(d[:idx], 64)
		d = d[idx+1:]
	}
	
	// Parse minutes
	if idx := strings.Index(d, "M"); idx >= 0 {
		minutes, _ = strconv.ParseFloat(d[:idx], 64)
		d = d[idx+1:]
	}
	
	// Parse seconds (remove trailing S)
	if idx := strings.Index(d, "S"); idx >= 0 {
		seconds, _ = strconv.ParseFloat(d[:idx], 64)
	}
	
	return hours*3600 + minutes*60 + seconds
}

type Period struct {
	ID             string          `xml:"id,attr"`
	Start          string          `xml:"start,attr"`
	Duration       string          `xml:"duration,attr"`
	AdaptationSets []AdaptationSet `xml:"AdaptationSet"`
	BaseURLs       []BaseURL       `xml:"BaseURL"`
}

type AdaptationSet struct {
	ID             string             `xml:"id,attr"`
	Group          string             `xml:"group,attr"`
	ContentType    string             `xml:"contentType,attr"`
	Lang           string             `xml:"lang,attr"`
	MimeType       string             `xml:"mimeType,attr"`
	Codecs         string             `xml:"codecs,attr"`
	StartWithSAP   int                `xml:"startWithSAP,attr"`
	SegmentAlignment bool             `xml:"segmentAlignment,attr"`
	BitstreamSwitching bool           `xml:"bitstreamSwitching,attr"`
	Representations []Representation  `xml:"Representation"`
	BaseURLs       []BaseURL          `xml:"BaseURL"`
	SegmentTemplate *SegmentTemplate  `xml:"SegmentTemplate"`
	SegmentList    *SegmentList       `xml:"SegmentList"`
	SegmentBase    *SegmentBase       `xml:"SegmentBase"`
}

type Representation struct {
	ID           string        `xml:"id,attr"`
	Bandwidth    string        `xml:"bandwidth,attr"`
	Width        int           `xml:"width,attr"`
	Height       int           `xml:"height,attr"`
	Codecs       string        `xml:"codecs,attr"`
	MimeType     string        `xml:"mimeType,attr"`
	BaseURLs     []BaseURL     `xml:"BaseURL"`
	SegmentTemplate *SegmentTemplate `xml:"SegmentTemplate"`
	SegmentList  *SegmentList  `xml:"SegmentList"`
	SegmentBase  *SegmentBase  `xml:"SegmentBase"`
}

type BaseURL struct {
	Value string `xml:",chardata"`
	ServiceLocation string `xml:"serviceLocation,attr"`
}

type Location struct {
	Value string `xml:",chardata"`
}

type SegmentTemplate struct {
	Media          string `xml:"media,attr"`
	Initialization string `xml:"initialization,attr"`
	StartNumber    string `xml:"startNumber,attr"`
	Timescale      string `xml:"timescale,attr"`
	Duration       string `xml:"duration,attr"`
	PresentationTimeOffset string `xml:"presentationTimeOffset,attr"`
	IndexRange     string `xml:"indexRange,attr"`
	IndexRangeExact string `xml:"indexRangeExact,attr"`
	AvailabilityTimeOffset string `xml:"availabilityTimeOffset,attr"`
	AvailabilityTimeComplete string `xml:"availabilityTimeComplete,attr"`
	SegmentTimeline *SegmentTimeline `xml:"SegmentTimeline"`
}

type SegmentTimeline struct {
	S []STimeline `xml:"S"`
}

type STimeline struct {
	T string `xml:"t,attr"` // start time
	D string `xml:"d,attr"` // duration
	R string `xml:"r,attr"` // repeat count
}

type SegmentList struct {
	Timescale      string          `xml:"timescale,attr"`
	Duration       string          `xml:"duration,attr"`
	StartNumber    string          `xml:"startNumber,attr"`
	SegmentURLs    []SegmentURL    `xml:"SegmentURL"`
	Initialization *Initialization `xml:"Initialization"`
}

type SegmentURL struct {
	Media      string `xml:"media,attr"`
	MediaRange string `xml:"mediaRange,attr"`
	Index      string `xml:"index,attr"`
	IndexRange string `xml:"indexRange,attr"`
}

type Initialization struct {
	SourceURL string `xml:"sourceURL,attr"`
	Range     string `xml:"range,attr"`
}

type SegmentBase struct {
	Initialization *Initialization `xml:"Initialization"`
	IndexRange     string          `xml:"indexRange,attr"`
	IndexRangeExact string         `xml:"indexRangeExact,attr"`
	AvailabilityTimeOffset string `xml:"availabilityTimeOffset,attr"`
	AvailabilityTimeComplete string `xml:"availabilityTimeComplete,attr"`
	SourceURL      string `xml:"sourceURL,attr"`
}

func ParseMPD(data []byte) (*MPD, error) {
	var mpd MPD
	if err := xml.Unmarshal(data, &mpd); err != nil {
		return nil, err
	}
	return &mpd, nil
}

func ResolveURL(base *url.URL, ref string) string {
	if ref == "" {
		return ""
	}
	if strings.HasPrefix(strings.ToLower(ref), "data:") {
		return ref
	}
	u, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	return base.ResolveReference(u).String()
}

func BuildProxyURL(targetURL, referer, origin, token string) string {
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
	return "/stream/proxy?" + v.Encode()
}

// RewriteMPD rewrites all media/initialization URLs in MPD to go through the proxy
func RewriteMPD(mpdXML string, baseURL *url.URL, referer, origin, token string) (string, error) {
	var mpd MPD
	if err := xml.Unmarshal([]byte(mpdXML), &mpd); err != nil {
		return "", err
	}

	// Collect all BaseURLs for resolution
	baseURLs := collectBaseURLs(&mpd, baseURL)

	// Rewrite all URLs
	rewriteMPDURLs(&mpd, baseURLs, referer, origin, token)

	// Marshal back
	out, err := xml.MarshalIndent(mpd, "", "  ")
	if err != nil {
		return "", err
	}
	return xml.Header + string(out), nil
}

func collectBaseURLs(mpd *MPD, base *url.URL) []*url.URL {
	var bases []*url.URL
	bases = append(bases, base)

	for _, bu := range mpd.BaseURLs {
		if u := ResolveURL(base, bu.Value); u != "" {
			if parsed, err := url.Parse(u); err == nil {
				bases = append(bases, parsed)
			}
		}
	}
	for _, p := range mpd.Periods {
		for _, bu := range p.BaseURLs {
			if u := ResolveURL(base, bu.Value); u != "" {
				if parsed, err := url.Parse(u); err == nil {
					bases = append(bases, parsed)
				}
			}
		}
		for _, as := range p.AdaptationSets {
			for _, bu := range as.BaseURLs {
				if u := ResolveURL(base, bu.Value); u != "" {
					if parsed, err := url.Parse(u); err == nil {
						bases = append(bases, parsed)
					}
				}
			}
			for _, rep := range as.Representations {
				for _, bu := range rep.BaseURLs {
					if u := ResolveURL(base, bu.Value); u != "" {
						if parsed, err := url.Parse(u); err == nil {
							bases = append(bases, parsed)
						}
					}
				}
			}
		}
	}
	return bases
}

func resolveFromBases(bases []*url.URL, ref string) string {
	for _, b := range bases {
		resolved := ResolveURL(b, ref)
		if resolved != "" {
			return resolved
		}
	}
	return ""
}

func rewriteMPDURLs(mpd *MPD, bases []*url.URL, referer, origin, token string) {
	// Rewrite MPD BaseURLs (for subsequent resolution)
	for i := range mpd.BaseURLs {
		mpd.BaseURLs[i].Value = BuildProxyURL(ResolveURL(bases[0], mpd.BaseURLs[i].Value), referer, origin, token)
	}
	for _, loc := range mpd.Locations {
		if u := ResolveURL(bases[0], loc.Value); u != "" {
			loc.Value = u
		}
	}

	for pi := range mpd.Periods {
		p := &mpd.Periods[pi]
		for i := range p.BaseURLs {
			p.BaseURLs[i].Value = BuildProxyURL(ResolveURL(bases[0], p.BaseURLs[i].Value), referer, origin, token)
		}
		for asi := range p.AdaptationSets {
			as := &p.AdaptationSets[asi]
			for i := range as.BaseURLs {
				as.BaseURLs[i].Value = BuildProxyURL(ResolveURL(bases[0], as.BaseURLs[i].Value), referer, origin, token)
			}
			rewriteSegmentTemplate(as.SegmentTemplate, bases, referer, origin, token)
			rewriteSegmentList(as.SegmentList, bases, referer, origin, token)
			rewriteSegmentBase(as.SegmentBase, bases, referer, origin, token)

			for ri := range as.Representations {
				rep := &as.Representations[ri]
				for i := range rep.BaseURLs {
					rep.BaseURLs[i].Value = BuildProxyURL(ResolveURL(bases[0], rep.BaseURLs[i].Value), referer, origin, token)
				}
				rewriteSegmentTemplate(rep.SegmentTemplate, bases, referer, origin, token)
				rewriteSegmentList(rep.SegmentList, bases, referer, origin, token)
				rewriteSegmentBase(rep.SegmentBase, bases, referer, origin, token)
			}
		}
	}
}

func rewriteSegmentTemplate(st *SegmentTemplate, bases []*url.URL, referer, origin, token string) {
	if st == nil {
		return
	}
	if st.Media != "" {
		st.Media = BuildProxyURL(resolveFromBases(bases, st.Media), referer, origin, token)
	}
	if st.Initialization != "" {
		st.Initialization = BuildProxyURL(resolveFromBases(bases, st.Initialization), referer, origin, token)
	}
	if st.SegmentTimeline != nil {
		// SegmentTimeline doesn't have URLs, but uses $Number$/$Time$ templates
		// These are already handled by the Media/Initialization templates
	}
}

func rewriteSegmentList(sl *SegmentList, bases []*url.URL, referer, origin, token string) {
	if sl == nil {
		return
	}
	if sl.Initialization != nil && sl.Initialization.SourceURL != "" {
		sl.Initialization.SourceURL = BuildProxyURL(resolveFromBases(bases, sl.Initialization.SourceURL), referer, origin, token)
	}
	for i := range sl.SegmentURLs {
		if sl.SegmentURLs[i].Media != "" {
			sl.SegmentURLs[i].Media = BuildProxyURL(resolveFromBases(bases, sl.SegmentURLs[i].Media), referer, origin, token)
		}
	}
}

func rewriteSegmentBase(sb *SegmentBase, bases []*url.URL, referer, origin, token string) {
	if sb == nil {
		return
	}
	if sb.Initialization != nil && sb.Initialization.SourceURL != "" {
		sb.Initialization.SourceURL = BuildProxyURL(resolveFromBases(bases, sb.Initialization.SourceURL), referer, origin, token)
	}
	if sb.SourceURL != "" {
		sb.SourceURL = BuildProxyURL(resolveFromBases(bases, sb.SourceURL), referer, origin, token)
	}
}

// ExtractMediaURLs extracts all media and initialization URLs from MPD for pre-fetching/validation
func ExtractMediaURLs(mpdXML string, baseURL *url.URL) ([]string, []string) {
	var mpd MPD
	if err := xml.Unmarshal([]byte(mpdXML), &mpd); err != nil {
		return nil, nil
	}

	bases := collectBaseURLs(&mpd, baseURL)
	var mediaURLs, initURLs []string

	for _, p := range mpd.Periods {
		for _, as := range p.AdaptationSets {
			collectFromTemplate(as.SegmentTemplate, bases, &mediaURLs, &initURLs)
			collectFromSegmentList(as.SegmentList, bases, &mediaURLs, &initURLs)
			collectFromSegmentBase(as.SegmentBase, bases, &mediaURLs, &initURLs)

			for _, rep := range as.Representations {
				collectFromTemplate(rep.SegmentTemplate, bases, &mediaURLs, &initURLs)
				collectFromSegmentList(rep.SegmentList, bases, &mediaURLs, &initURLs)
				collectFromSegmentBase(rep.SegmentBase, bases, &mediaURLs, &initURLs)
			}
		}
	}
	return mediaURLs, initURLs
}

func collectFromTemplate(st *SegmentTemplate, bases []*url.URL, media, init *[]string) {
	if st == nil {
		return
	}
	if st.Media != "" {
		*media = append(*media, resolveFromBases(bases, st.Media))
	}
	if st.Initialization != "" {
		*init = append(*init, resolveFromBases(bases, st.Initialization))
	}
}

func collectFromSegmentList(sl *SegmentList, bases []*url.URL, media, init *[]string) {
	if sl == nil {
		return
	}
	if sl.Initialization != nil && sl.Initialization.SourceURL != "" {
		*init = append(*init, resolveFromBases(bases, sl.Initialization.SourceURL))
	}
	for _, su := range sl.SegmentURLs {
		if su.Media != "" {
			*media = append(*media, resolveFromBases(bases, su.Media))
		}
	}
}

func collectFromSegmentBase(sb *SegmentBase, bases []*url.URL, media, init *[]string) {
	if sb == nil {
		return
	}
	if sb.Initialization != nil && sb.Initialization.SourceURL != "" {
		*init = append(*init, resolveFromBases(bases, sb.Initialization.SourceURL))
	}
	if sb.SourceURL != "" {
		*media = append(*media, resolveFromBases(bases, sb.SourceURL))
	}
}

// Template regex for $RepresentationID$, $Number%08d$, $Bandwidth$, $Time$
var templateRe = regexp.MustCompile(`\$([A-Za-z0-9%]+)\$`)

func ExpandTemplate(tmpl string, params map[string]string) string {
	return templateRe.ReplaceAllStringFunc(tmpl, func(match string) string {
		key := match[1 : len(match)-1]
		if val, ok := params[key]; ok {
			return val
		}
		return match
	})
}