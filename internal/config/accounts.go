package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const accountsFileName = "accounts.json"
const accountsFileVersion = 1

// AccountRecord is the persisted form of one proxy account. PasswordHash is a
// bcrypt digest; the plaintext password is never written or returned by the API.
type AccountRecord struct {
	Username          string `json:"username"`
	DisplayName       string `json:"display_name,omitempty"`
	PasswordHash      string `json:"password_hash"`
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

// AccountPoolRecord is the persisted form of one user pool.
type AccountPoolRecord struct {
	Name      string   `json:"name"`
	Nodes     []string `json:"nodes,omitempty"`
	Fallback  string   `json:"fallback"`
	Enabled   bool     `json:"enabled"`
	Note      string   `json:"note,omitempty"`
	CreatedAt string   `json:"created_at"`
	UpdatedAt string   `json:"updated_at"`
}

// AuditRecord is a credential-free change log entry.
type AuditRecord struct {
	At     string `json:"at"`
	Action string `json:"action"`
	Target string `json:"target"`
}

// AccountsFile is the sidecar stored next to config.yaml.
type AccountsFile struct {
	Version int                 `json:"version"`
	Users   []AccountRecord     `json:"users"`
	Pools   []AccountPoolRecord `json:"pools"`
	Audit   []AuditRecord       `json:"audit,omitempty"`
}

// AccountsPath returns the sidecar path, or empty when the config path is unknown.
func (c *Config) AccountsPath() string {
	if c == nil || c.filePath == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(c.filePath), accountsFileName)
}

// NodeQualityPath returns the strict-verification sidecar path, or empty when
// the config path is unknown.
func (c *Config) NodeQualityPath() string {
	if c == nil || c.filePath == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(c.filePath), "node_quality.json")
}

// LoadAccounts reads the sidecar. A missing file is an empty, valid store.
func LoadAccounts(path string) (AccountsFile, error) {
	empty := AccountsFile{Version: accountsFileVersion}
	if path == "" {
		return empty, nil
	}
	data, err := readFileWithLock(path)
	if errors.Is(err, os.ErrNotExist) {
		return empty, nil
	}
	if err != nil {
		return empty, fmt.Errorf("read accounts file: %w", err)
	}
	if len(data) == 0 {
		return empty, nil
	}
	var file AccountsFile
	if err := json.Unmarshal(data, &file); err != nil {
		return empty, fmt.Errorf("decode accounts file: %w", err)
	}
	if file.Version == 0 {
		file.Version = accountsFileVersion
	}
	return file, nil
}

// SaveAccounts writes the sidecar atomically under the shared path lock.
func SaveAccounts(path string, file AccountsFile) error {
	if path == "" {
		return errors.New("accounts file path is unknown")
	}
	file.Version = accountsFileVersion
	encoded, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return fmt.Errorf("encode accounts file: %w", err)
	}
	encoded = append(encoded, '\n')
	return writeFileWithLock(path, encoded, 0600)
}
