// Package accounts implements the independent proxy account system: one
// credential per user, one pool per user, hot-swappable without a core reload.
package accounts

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"easy_proxies/internal/config"
	"easy_proxies/internal/routing"

	"golang.org/x/crypto/bcrypt"
)

const maxAuditEntries = 200

var usernamePattern = regexp.MustCompile(`^[A-Za-z0-9_.+-]{1,64}$`)
var poolNamePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// UserView is the API representation. It never contains a password or hash.
type UserView struct {
	Username          string `json:"username"`
	DisplayName       string `json:"display_name,omitempty"`
	Pool              string `json:"pool,omitempty"`
	Enabled           bool   `json:"enabled"`
	ExpiresAt         string `json:"expires_at,omitempty"`
	MaxSessions       int    `json:"max_sessions,omitempty"`
	MaxConns          int    `json:"max_conns,omitempty"`
	Note              string `json:"note,omitempty"`
	CredentialVersion int    `json:"credential_version"`
	CreatedAt         string `json:"created_at"`
	UpdatedAt         string `json:"updated_at"`
}

// UserInput is accepted by create/update API calls.
type UserInput struct {
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	Password    string `json:"password"`
	Pool        string `json:"pool"`
	Enabled     *bool  `json:"enabled"`
	ExpiresAt   string `json:"expires_at"`
	MaxSessions int    `json:"max_sessions"`
	MaxConns    int    `json:"max_conns"`
	Note        string `json:"note"`
}

// PoolInput is accepted by create/update API calls.
type PoolInput struct {
	Name     string   `json:"name"`
	Nodes    []string `json:"nodes"`
	Fallback string   `json:"fallback"`
	Enabled  *bool    `json:"enabled"`
	Note     string   `json:"note"`
}

type entry struct {
	record  config.AccountRecord
	expires time.Time
}

type snapshot struct {
	users map[string]*entry
	names []string
	pools map[string]config.AccountPoolRecord
}

// Store owns the persisted data and an immutable runtime snapshot.
type Store struct {
	mu   sync.Mutex
	path string
	data config.AccountsFile
	snap atomic.Pointer[snapshot]
}

var (
	defaultMu    sync.RWMutex
	defaultStore = &Store{}
)

// Default returns the process-wide store. An empty store safely falls back to
// the legacy single listener credentials.
func Default() *Store {
	defaultMu.RLock()
	defer defaultMu.RUnlock()
	return defaultStore
}

// SetDefault installs a store and returns a restore function (used by tests).
func SetDefault(s *Store) func() {
	defaultMu.Lock()
	previous := defaultStore
	if s == nil {
		s = &Store{}
	}
	defaultStore = s
	defaultMu.Unlock()
	return func() {
		defaultMu.Lock()
		defaultStore = previous
		defaultMu.Unlock()
	}
}

// Load reads the sidecar and installs the runtime snapshot.
func Load(path string) (*Store, error) {
	file, err := config.LoadAccounts(path)
	if err != nil {
		return nil, err
	}
	return New(path, file), nil
}

// New builds a store from a parsed accounts file and publishes its pool rules.
func New(path string, file config.AccountsFile) *Store {
	s := &Store{path: path, data: normalizeFile(file)}
	s.rebuild()
	return s
}

func normalizeFile(file config.AccountsFile) config.AccountsFile {
	file.Users = append([]config.AccountRecord(nil), file.Users...)
	file.Pools = append([]config.AccountPoolRecord(nil), file.Pools...)
	file.Audit = append([]config.AuditRecord(nil), file.Audit...)
	if len(file.Audit) > maxAuditEntries {
		file.Audit = file.Audit[len(file.Audit)-maxAuditEntries:]
	}
	for i := range file.Pools {
		if file.Pools[i].Fallback == "" {
			file.Pools[i].Fallback = "none"
		}
	}
	return file
}

func cloneFile(in config.AccountsFile) config.AccountsFile {
	out := normalizeFile(in)
	for i := range out.Users {
		out.Users[i] = in.Users[i]
	}
	for i := range out.Pools {
		out.Pools[i] = in.Pools[i]
		out.Pools[i].Nodes = append([]string(nil), in.Pools[i].Nodes...)
	}
	return out
}

func (s *Store) rebuild() {
	snap := &snapshot{
		users: make(map[string]*entry, len(s.data.Users)),
		pools: make(map[string]config.AccountPoolRecord, len(s.data.Pools)),
	}
	for _, record := range s.data.Users {
		copy := record
		var expires time.Time
		if record.ExpiresAt != "" {
			if parsed, err := time.Parse(time.RFC3339, record.ExpiresAt); err == nil {
				expires = parsed
			}
		}
		snap.users[record.Username] = &entry{record: copy, expires: expires}
		snap.names = append(snap.names, record.Username)
	}
	// Longest first so "wang.name" wins over "wang" on prefixed session names.
	sort.Slice(snap.names, func(i, j int) bool { return len(snap.names[i]) > len(snap.names[j]) })
	for _, pool := range s.data.Pools {
		snap.pools[pool.Name] = pool
	}
	s.snap.Store(snap)
	config.SetAccountPools(s.userPools())
}

func (s *Store) userPools() []config.UserPoolConfig {
	pools := make([]config.UserPoolConfig, 0, len(s.data.Pools))
	for _, pool := range s.data.Pools {
		if !pool.Enabled {
			continue
		}
		users := make([]string, 0)
		for _, user := range s.data.Users {
			if user.Enabled && user.Pool == pool.Name {
				users = append(users, user.Username)
			}
		}
		if len(users) == 0 {
			continue
		}
		pools = append(pools, config.UserPoolConfig{
			Name:     pool.Name,
			Users:    users,
			Nodes:    append([]string(nil), pool.Nodes...),
			Fallback: pool.Fallback,
		})
	}
	return pools
}

// Authenticate verifies credentials against the runtime snapshot. It supports
// username.session routing and never discloses credential values in errors.
func (s *Store) Authenticate(input, password string, sessionEnabled bool) (string, bool) {
	snap := s.snap.Load()
	if snap == nil {
		return "", false
	}
	if e, ok := snap.users[input]; ok {
		return "", s.verify(e, password)
	}
	for _, name := range snap.names {
		session, ok := routing.ParseUsername(name, input)
		if !ok || (session != "" && !sessionEnabled) {
			continue
		}
		if s.verify(snap.users[name], password) {
			return session, true
		}
	}
	return "", false
}

func (s *Store) verify(e *entry, password string) bool {
	if e == nil || !e.record.Enabled || e.record.PasswordHash == "" {
		return false
	}
	if !e.expires.IsZero() && time.Now().After(e.expires) {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(e.record.PasswordHash), []byte(password)) == nil
}

// Users returns a credential-free view of all accounts.
func (s *Store) Users() []UserView {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]UserView, 0, len(s.data.Users))
	for _, record := range s.data.Users {
		out = append(out, viewOf(record))
	}
	return out
}

// Pools returns all configured pools.
func (s *Store) Pools() []config.AccountPoolRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]config.AccountPoolRecord, 0, len(s.data.Pools))
	for _, pool := range s.data.Pools {
		pool.Nodes = append([]string(nil), pool.Nodes...)
		out = append(out, pool)
	}
	return out
}

// Audit returns the bounded credential-free change log.
func (s *Store) Audit() []config.AuditRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]config.AuditRecord(nil), s.data.Audit...)
}

func viewOf(record config.AccountRecord) UserView {
	return UserView{
		Username:          record.Username,
		DisplayName:       record.DisplayName,
		Pool:              record.Pool,
		Enabled:           record.Enabled,
		ExpiresAt:         record.ExpiresAt,
		MaxSessions:       record.MaxSessions,
		MaxConns:          record.MaxConns,
		Note:              record.Note,
		CredentialVersion: record.CredentialVersion,
		CreatedAt:         record.CreatedAt,
		UpdatedAt:         record.UpdatedAt,
	}
}

func (s *Store) commit(next config.AccountsFile, action, target string) error {
	next.Audit = append(next.Audit, config.AuditRecord{
		At: time.Now().UTC().Format(time.RFC3339), Action: action, Target: target,
	})
	if len(next.Audit) > maxAuditEntries {
		next.Audit = next.Audit[len(next.Audit)-maxAuditEntries:]
	}
	if err := config.SaveAccounts(s.path, next); err != nil {
		return err
	}
	// An empty path means an in-memory store (tests, or a config with no path).
	s.data = next
	s.rebuild()
	return nil
}

func (s *Store) requireWritable() error {
	if s.path == "" {
		return errors.New("账号存储路径未知，无法持久化")
	}
	return nil
}

func validateUserInput(input UserInput, requirePassword bool) error {
	if !usernamePattern.MatchString(input.Username) {
		return errors.New("用户名需为 1-64 位字母、数字、点、下划线、加号或连字符")
	}
	if requirePassword && input.Password == "" {
		return errors.New("创建用户必须设置密码")
	}
	if len(input.Password) > 128 {
		return errors.New("密码过长")
	}
	if input.MaxSessions < 0 || input.MaxConns < 0 {
		return errors.New("配额不能为负数")
	}
	if input.ExpiresAt != "" {
		if _, err := time.Parse(time.RFC3339, input.ExpiresAt); err != nil {
			return errors.New("到期时间必须为 RFC3339 格式")
		}
	}
	return nil
}

func (s *Store) validatePoolRef(pool string, pools []config.AccountPoolRecord) error {
	if pool == "" {
		return nil
	}
	for _, candidate := range pools {
		if candidate.Name == pool {
			return nil
		}
	}
	return fmt.Errorf("分池 %q 不存在", pool)
}

func boolValue(value *bool, fallback bool) bool {
	if value == nil {
		return fallback
	}
	return *value
}

// CreateUser adds an account and immediately publishes its routing rules.
func (s *Store) CreateUser(input UserInput) (UserView, error) {
	input.Username = strings.TrimSpace(input.Username)
	if err := validateUserInput(input, true); err != nil {
		return UserView{}, err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		return UserView{}, fmt.Errorf("密码哈希失败: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.requireWritable(); err != nil {
		return UserView{}, err
	}
	for _, existing := range s.data.Users {
		if existing.Username == input.Username {
			return UserView{}, errors.New("用户名已存在")
		}
	}
	if err := s.validatePoolRef(input.Pool, s.data.Pools); err != nil {
		return UserView{}, err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	record := config.AccountRecord{
		Username: input.Username, DisplayName: strings.TrimSpace(input.DisplayName),
		PasswordHash: string(hash), Pool: input.Pool,
		Enabled: boolValue(input.Enabled, true), ExpiresAt: input.ExpiresAt,
		MaxSessions: input.MaxSessions, MaxConns: input.MaxConns,
		Note: input.Note, CredentialVersion: 1, CreatedAt: now, UpdatedAt: now,
	}
	next := cloneFile(s.data)
	next.Users = append(next.Users, record)
	if err := s.commit(next, "create_user", record.Username); err != nil {
		return UserView{}, err
	}
	return viewOf(record), nil
}

// UpdateUser changes an account. A non-empty password rotates the credential.
func (s *Store) UpdateUser(username string, input UserInput) (UserView, error) {
	input.Username = username
	if err := validateUserInput(input, false); err != nil {
		return UserView{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.requireWritable(); err != nil {
		return UserView{}, err
	}
	next := cloneFile(s.data)
	index := -1
	for i := range next.Users {
		if next.Users[i].Username == username {
			index = i
			break
		}
	}
	if index < 0 {
		return UserView{}, errors.New("用户不存在")
	}
	if err := s.validatePoolRef(input.Pool, next.Pools); err != nil {
		return UserView{}, err
	}
	record := next.Users[index]
	record.DisplayName = strings.TrimSpace(input.DisplayName)
	record.Pool = input.Pool
	record.Enabled = boolValue(input.Enabled, record.Enabled)
	record.ExpiresAt = input.ExpiresAt
	record.MaxSessions = input.MaxSessions
	record.MaxConns = input.MaxConns
	record.Note = input.Note
	record.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	if input.Password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
		if err != nil {
			return UserView{}, fmt.Errorf("密码哈希失败: %w", err)
		}
		record.PasswordHash = string(hash)
		record.CredentialVersion++
	}
	next.Users[index] = record
	if err := s.commit(next, "update_user", username); err != nil {
		return UserView{}, err
	}
	return viewOf(record), nil
}

// DeleteUser removes an account. Connections already in flight are not closed.
func (s *Store) DeleteUser(username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.requireWritable(); err != nil {
		return err
	}
	next := cloneFile(s.data)
	kept := make([]config.AccountRecord, 0, len(next.Users))
	found := false
	for _, record := range next.Users {
		if record.Username == username {
			found = true
			continue
		}
		kept = append(kept, record)
	}
	if !found {
		return errors.New("用户不存在")
	}
	next.Users = kept
	return s.commit(next, "delete_user", username)
}

// CreatePool adds a pool.
func (s *Store) CreatePool(input PoolInput) (config.AccountPoolRecord, error) {
	input.Name = strings.TrimSpace(input.Name)
	if !poolNamePattern.MatchString(input.Name) {
		return config.AccountPoolRecord{}, errors.New("分池名需为 1-64 位字母、数字、下划线或连字符")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.requireWritable(); err != nil {
		return config.AccountPoolRecord{}, err
	}
	for _, pool := range s.data.Pools {
		if pool.Name == input.Name {
			return config.AccountPoolRecord{}, errors.New("分池名已存在")
		}
	}
	now := time.Now().UTC().Format(time.RFC3339)
	record := config.AccountPoolRecord{
		Name: input.Name, Nodes: normalizeNodes(input.Nodes),
		Fallback: normalizePoolFallback(input.Fallback),
		Enabled:  boolValue(input.Enabled, true), Note: input.Note,
		CreatedAt: now, UpdatedAt: now,
	}
	next := cloneFile(s.data)
	next.Pools = append(next.Pools, record)
	if err := s.commit(next, "create_pool", record.Name); err != nil {
		return config.AccountPoolRecord{}, err
	}
	return record, nil
}

// UpdatePool changes a pool's node subset and fallback policy.
func (s *Store) UpdatePool(name string, input PoolInput) (config.AccountPoolRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.requireWritable(); err != nil {
		return config.AccountPoolRecord{}, err
	}
	next := cloneFile(s.data)
	index := -1
	for i := range next.Pools {
		if next.Pools[i].Name == name {
			index = i
			break
		}
	}
	if index < 0 {
		return config.AccountPoolRecord{}, errors.New("分池不存在")
	}
	record := next.Pools[index]
	record.Nodes = normalizeNodes(input.Nodes)
	record.Fallback = normalizePoolFallback(input.Fallback)
	record.Enabled = boolValue(input.Enabled, record.Enabled)
	record.Note = input.Note
	record.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	next.Pools[index] = record
	if err := s.commit(next, "update_pool", name); err != nil {
		return config.AccountPoolRecord{}, err
	}
	return record, nil
}

// DeletePool refuses to remove a pool that still owns users.
func (s *Store) DeletePool(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.requireWritable(); err != nil {
		return err
	}
	for _, user := range s.data.Users {
		if user.Pool == name {
			return fmt.Errorf("分池 %q 仍有用户 %q，请先迁移或删除用户", name, user.Username)
		}
	}
	next := cloneFile(s.data)
	kept := make([]config.AccountPoolRecord, 0, len(next.Pools))
	found := false
	for _, pool := range next.Pools {
		if pool.Name == name {
			found = true
			continue
		}
		kept = append(kept, pool)
	}
	if !found {
		return errors.New("分池不存在")
	}
	next.Pools = kept
	return s.commit(next, "delete_pool", name)
}

func normalizeNodes(nodes []string) []string {
	seen := make(map[string]bool, len(nodes))
	out := make([]string, 0, len(nodes))
	for _, node := range nodes {
		node = strings.TrimSpace(node)
		if node == "" || seen[node] {
			continue
		}
		seen[node] = true
		out = append(out, node)
	}
	return out
}

func normalizePoolFallback(value string) string {
	switch strings.TrimSpace(value) {
	case "default_pool", "direct":
		return strings.TrimSpace(value)
	default:
		return "none"
	}
}
