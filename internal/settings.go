package internal

import (
	"fmt"
	"strings"

	"github.com/Muxcore-Media/core/pkg/contracts"
	"github.com/Muxcore-Media/secrets-file/internal/vault"
)

func (m *Module) Settings() []contracts.SettingDef {
	return m.settingsDefs()
}

func (m *Module) UpdateSetting(key, value string) error {
	return m.updateSetting(key, value)
}

func (m *Module) settingsDefs() []contracts.SettingDef {
	m.cfgMu.RLock()
	defer m.cfgMu.RUnlock()
	return []contracts.SettingDef{
		{
			Key:         "store_path",
			Label:       "Secrets Store Path",
			Type:        contracts.SettingTypeString,
			Value:       m.store,
			Default:     "secrets.json",
			Description: "Encrypted JSON store path (SECRETS_STORE)",
			Group:       "Storage",
		},
		{
			Key:         "key_file",
			Label:       "Master Key File",
			Type:        contracts.SettingTypeString,
			Value:       m.keyFile,
			Description: "Path to hex-encoded 32-byte master key file (SECRETS_KEY_FILE); ignored when SECRETS_MASTER_KEY is set",
			Group:       "Storage",
		},
	}
}

func (m *Module) updateSetting(key, value string) error {
	value = strings.TrimSpace(value)
	switch key {
	case "store_path", "SECRETS_STORE":
		if value == "" {
			return fmt.Errorf("store_path must not be empty")
		}
		return m.setPaths(value, nil)
	case "key_file", "SECRETS_KEY_FILE":
		return m.setPaths("", &value)
	default:
		return fmt.Errorf("unknown setting %q", key)
	}
}

// setPaths updates store and/or key file and reopens the vault when live.
// Empty store keeps current; nil keyFile keeps current.
func (m *Module) setPaths(store string, keyFile *string) error {
	m.cfgMu.Lock()
	defer m.cfgMu.Unlock()

	newStore := m.store
	newKey := m.keyFile
	if store != "" {
		newStore = store
	}
	if keyFile != nil {
		newKey = *keyFile
	}
	if newStore == m.store && newKey == m.keyFile {
		return nil
	}

	if m.srv == nil {
		m.store = newStore
		m.keyFile = newKey
		return nil
	}

	masterKey, err := loadMasterKey(newKey)
	if err != nil {
		return fmt.Errorf("load master key: %w", err)
	}
	v, err := vault.New(newStore, masterKey)
	if err != nil {
		return fmt.Errorf("open vault: %w", err)
	}
	old := m.srv.ReplaceVault(v)
	m.vault = v
	m.store = newStore
	m.keyFile = newKey
	if old != nil {
		_ = old.Flush()
		old.Close()
	}
	return nil
}
