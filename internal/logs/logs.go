// Package logs provides a structured, leveled and searchable in-memory log
// buffer. It is deliberately bounded: access logs can be produced once per
// connection, so the buffer keeps only the newest entries per category.
package logs

import (
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Level string

const (
	LevelDebug Level = "DEBUG"
	LevelInfo  Level = "INFO"
	LevelWarn  Level = "WARN"
	LevelError Level = "ERROR"
)

var levelRank = map[Level]int{LevelDebug: 0, LevelInfo: 1, LevelWarn: 2, LevelError: 3}

func ParseLevel(value string) Level {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "DEBUG":
		return LevelDebug
	case "WARN", "WARNING":
		return LevelWarn
	case "ERROR":
		return LevelError
	default:
		return LevelInfo
	}
}

func (l Level) AtLeast(min Level) bool {
	return levelRank[l] >= levelRank[min]
}

// Entry is one structured record. Message must already be sanitized: never put
// credentials, tokens or raw upstream URIs in here.
type Entry struct {
	TS       string         `json:"ts"`
	Level    Level          `json:"level"`
	Category string         `json:"category"`
	Source   string         `json:"source,omitempty"`
	Message  string         `json:"message"`
	Fields   map[string]any `json:"fields,omitempty"`
}

const defaultCapacity = 2000
const maxQueryLimit = 1000

// Buffer owns two independent rings so a burst of access logs cannot evict
// refresh/verification diagnostics.
type Buffer struct {
	mu       sync.Mutex
	capacity int
	general  []Entry
	access   []Entry
	minLevel atomic.Value // stores Level
}

func New(capacity int) *Buffer {
	if capacity <= 0 {
		capacity = defaultCapacity
	}
	b := &Buffer{capacity: capacity}
	b.minLevel.Store(LevelInfo)
	return b
}

var defaultBuffer = New(defaultCapacity)

// Default returns the process-wide buffer shared by producers and the API.
func Default() *Buffer { return defaultBuffer }

func (b *Buffer) SetMinLevel(level Level) { b.minLevel.Store(level) }
func (b *Buffer) MinLevel() Level         { return b.minLevel.Load().(Level) }

// Add records an entry. Entries below the configured threshold are dropped so
// verbose per-node detail never floods the buffer by default.
func (b *Buffer) Add(e Entry) {
	if e.Level == "" {
		e.Level = LevelInfo
	}
	if !e.Level.AtLeast(b.MinLevel()) {
		return
	}
	if e.TS == "" {
		e.TS = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if e.Category == "" {
		e.Category = "general"
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if e.Category == "access" {
		b.access = appendBounded(b.access, e, b.capacity)
	} else {
		b.general = appendBounded(b.general, e, b.capacity)
	}
}

func appendBounded(ring []Entry, e Entry, capacity int) []Entry {
	if len(ring) < capacity {
		return append(ring, e)
	}
	copy(ring, ring[1:])
	ring[len(ring)-1] = e
	return ring
}

// Query returns newest-first entries filtered by minimum level, exact category
// and a case-insensitive substring over message/source/serialized fields.
func (b *Buffer) Query(minLevel Level, category, q string, limit int) []Entry {
	if minLevel == "" {
		minLevel = LevelDebug
	}
	if limit <= 0 || limit > maxQueryLimit {
		limit = 200
	}
	needle := strings.ToLower(strings.TrimSpace(q))
	b.mu.Lock()
	defer b.mu.Unlock()
	var source []Entry
	if category == "access" {
		source = b.access
	} else if category != "" && category != "all" {
		// Category filter over the general ring.
		combined := make([]Entry, 0, len(b.general))
		for _, e := range b.general {
			if e.Category == category {
				combined = append(combined, e)
			}
		}
		source = combined
	} else {
		source = append(append(make([]Entry, 0, len(b.general)+len(b.access)), b.general...), b.access...)
	}
	out := make([]Entry, 0, limit)
	for i := len(source) - 1; i >= 0 && len(out) < limit; i-- {
		e := source[i]
		if !e.Level.AtLeast(minLevel) {
			continue
		}
		if needle != "" && !entryMatches(e, needle) {
			continue
		}
		out = append(out, e)
	}
	return out
}

func entryMatches(e Entry, needle string) bool {
	if strings.Contains(strings.ToLower(e.Message), needle) ||
		strings.Contains(strings.ToLower(e.Source), needle) ||
		strings.Contains(strings.ToLower(e.Category), needle) {
		return true
	}
	for key, value := range e.Fields {
		if strings.Contains(strings.ToLower(key), needle) ||
			strings.Contains(strings.ToLower(fieldString(value)), needle) {
			return true
		}
	}
	return false
}

func fieldString(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case int:
		return strconv.Itoa(v)
	case int64:
		return strconv.FormatInt(v, 10)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(v)
	default:
		return ""
	}
}

var embeddedURL = regexp.MustCompile(`https?://[^\s"'<>]+`)

// SanitizeError removes query strings and credentials from URLs embedded in
// provider errors (e.g. "key=..." in FOFA request URLs) before logging.
func SanitizeError(message string) string {
	if message == "" {
		return ""
	}
	return embeddedURL.ReplaceAllStringFunc(message, func(raw string) string {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Host == "" {
			return raw
		}
		return parsed.Scheme + "://" + parsed.Host + parsed.Path
	})
}
