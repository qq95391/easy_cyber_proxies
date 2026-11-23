// Package quality keeps the latest full-dimension verification result per
// node. It is a bounded, best-effort cache: verification is an operator action,
// never a hot-path requirement.
package quality

import (
	"encoding/json"
	"os"
	"sort"
	"sync"

	"easy_proxies/internal/verify"
)

type Record struct {
	Key       string        `json:"key"`
	Name      string        `json:"name,omitempty"`
	Score     int           `json:"score"`
	Grade     string        `json:"grade"`
	CheckedAt string        `json:"checked_at"`
	Result    verify.Result `json:"result"`
}

type Store struct {
	mu       sync.RWMutex
	capacity int
	path     string
	records  map[string]Record
}

func New(capacity int) *Store {
	if capacity <= 0 {
		capacity = 2000
	}
	return &Store{capacity: capacity, records: make(map[string]Record)}
}

var defaultStore = New(2000)

func Default() *Store { return defaultStore }

func (s *Store) SetPath(path string) {
	s.mu.Lock()
	s.path = path
	s.mu.Unlock()
}

func (s *Store) Upsert(record Record) {
	if record.Key == "" {
		return
	}
	s.mu.Lock()
	s.records[record.Key] = record
	if len(s.records) > s.capacity {
		s.evictLocked()
	}
	s.mu.Unlock()
}

func (s *Store) evictLocked() {
	oldestKey := ""
	oldest := ""
	for key, record := range s.records {
		if oldestKey == "" || record.CheckedAt < oldest {
			oldestKey, oldest = key, record.CheckedAt
		}
	}
	if oldestKey != "" {
		delete(s.records, oldestKey)
	}
}

func (s *Store) Get(key string) (Record, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, ok := s.records[key]
	return record, ok
}

func (s *Store) All() []Record {
	s.mu.RLock()
	out := make([]Record, 0, len(s.records))
	for _, record := range s.records {
		out = append(out, record)
	}
	s.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].CheckedAt > out[j].CheckedAt })
	return out
}

func (s *Store) Load(path string) error {
	s.mu.Lock()
	s.path = path
	s.mu.Unlock()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var records []Record
	if err := json.Unmarshal(data, &records); err != nil {
		return err
	}
	s.mu.Lock()
	for _, record := range records {
		if record.Key != "" {
			s.records[record.Key] = record
		}
	}
	s.mu.Unlock()
	return nil
}

func (s *Store) Save() error {
	s.mu.RLock()
	path := s.path
	records := make([]Record, 0, len(s.records))
	for _, record := range s.records {
		records = append(records, record)
	}
	s.mu.RUnlock()
	if path == "" {
		return nil
	}
	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}
