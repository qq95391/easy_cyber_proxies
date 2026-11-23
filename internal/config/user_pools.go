package config

import (
	"strings"
	"sync/atomic"
)

// UserPoolConfig binds base usernames to an explicit node subset. The pool is
// selected by the base username (the part before the last ".session" suffix);
// users that match no pool fall back to the default pool, which is all nodes.
type UserPoolConfig struct {
	Name  string   `yaml:"name" json:"name"`
	Users []string `yaml:"users" json:"users"`
	// Nodes lists node tags. An empty list means "this pool is the full node
	// set", matching the default-pool semantics.
	Nodes []string `yaml:"nodes,omitempty" json:"nodes,omitempty"`
	// Mode optionally overrides the scheduling mode for this pool. Empty uses
	// the global pool mode.
	Mode string `yaml:"mode,omitempty" json:"mode,omitempty"`
	// Fallback controls what happens when every node in the pool is unavailable:
	// "none" (default, no fallback), "default_pool", "direct".
	Fallback string `yaml:"fallback,omitempty" json:"fallback,omitempty"`
}

// NormalizeUserPools trims and de-duplicates a user pool list so the runtime
// store and the on-disk config agree on the same canonical form.
func NormalizeUserPools(pools []UserPoolConfig) []UserPoolConfig {
	if len(pools) == 0 {
		return nil
	}
	out := make([]UserPoolConfig, 0, len(pools))
	for _, p := range pools {
		name := strings.TrimSpace(p.Name)
		users := normalizeStrings(p.Users)
		if name == "" || len(users) == 0 {
			continue
		}
		out = append(out, UserPoolConfig{
			Name:     name,
			Users:    users,
			Nodes:    normalizeStrings(p.Nodes),
			Mode:     strings.TrimSpace(p.Mode),
			Fallback: normalizeFallback(p.Fallback),
		})
	}
	return out
}

func normalizeFallback(value string) string {
	switch strings.TrimSpace(value) {
	case "default_pool", "direct":
		return strings.TrimSpace(value)
	default:
		return "none"
	}
}

func normalizeStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

var (
	userPoolStore    atomic.Pointer[[]UserPoolConfig]
	basePoolStore    atomic.Pointer[[]UserPoolConfig]
	accountPoolStore atomic.Pointer[[]UserPoolConfig]
)

// PublishUserPools records the config.yaml rules and re-publishes them together
// with the independently managed account pools. Core reloads call this, so an
// account pool can never be silently dropped by a rebuild.
func PublishUserPools(base []UserPoolConfig) {
	copy := append([]UserPoolConfig(nil), base...)
	basePoolStore.Store(&copy)
	republishPools()
}

// SetAccountPools publishes pools owned by the account system.
func SetAccountPools(pools []UserPoolConfig) {
	copy := append([]UserPoolConfig(nil), pools...)
	accountPoolStore.Store(&copy)
	republishPools()
}

func republishPools() {
	accountNames := make(map[string]bool)
	if account := accountPoolStore.Load(); account != nil {
		for _, pool := range *account {
			accountNames[pool.Name] = true
		}
	}
	var merged []UserPoolConfig
	if base := basePoolStore.Load(); base != nil {
		for _, pool := range *base {
			if !accountNames[pool.Name] {
				merged = append(merged, pool)
			}
		}
	}
	if account := accountPoolStore.Load(); account != nil {
		merged = append(merged, (*account)...)
	}
	SetUserPools(merged)
}

// SetUserPools publishes the live pool rules. Callers must also persist the
// same list to config.yaml; this store only drives routing.
func SetUserPools(pools []UserPoolConfig) {
	normalized := NormalizeUserPools(pools)
	userPoolStore.Store(&normalized)
}

// LoadUserPools returns the live pool rules.
func LoadUserPools() []UserPoolConfig {
	if p := userPoolStore.Load(); p != nil {
		return append([]UserPoolConfig(nil), (*p)...)
	}
	return nil
}

// MatchUserPool returns the node-tag allowlist for baseUser together with the
// matched pool name. A nil allowlist with matched=true means the pool is
// configured as the full node set. A false matched value means no pool matched,
// so the default (all nodes) applies.
func MatchUserPool(baseUser string) (allow map[string]bool, poolName string, matched bool) {
	baseUser = strings.TrimSpace(baseUser)
	if baseUser == "" {
		return nil, "", false
	}
	for _, p := range LoadUserPools() {
		for _, u := range p.Users {
			if u != baseUser {
				continue
			}
			if len(p.Nodes) == 0 {
				return nil, p.Name, true
			}
			allow = make(map[string]bool, len(p.Nodes))
			for _, tag := range p.Nodes {
				allow[tag] = true
			}
			return allow, p.Name, true
		}
	}
	return nil, "", false
}
