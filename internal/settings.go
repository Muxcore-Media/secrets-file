package internal

import (
	"context"
	"fmt"
	"os"
	"strconv"
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

	count := 0
	if m.vault != nil {
		count = m.vault.Count()
	}

	return []contracts.SettingDef{
		{
			Key:         "store_path",
			Label:       "Secrets Store Path",
			Type:        contracts.SettingTypeString,
			Value:       m.store,
			Default:     "secrets.json",
			Description: "Encrypted JSON store path (SECRETS_STORE); must stay under SECRETS_ALLOWED_ROOT",
			Group:       "Storage",
		},
		{
			Key:         "key_file",
			Label:       "Master Key File",
			Type:        contracts.SettingTypeString,
			Value:       m.keyFile,
			Description: "Path to hex-encoded 32-byte master key file (SECRETS_KEY_FILE); must already exist; ignored when SECRETS_MASTER_KEY is set",
			Group:       "Storage",
		},
		{
			Key:         "rotate_master_key",
			Label:       "Rotate Master Key",
			Type:        contracts.SettingTypeBool,
			Value:       "false",
			Description: "Set to true to generate a new master key, re-encrypt all secrets, and overwrite key_file (0600)",
			Group:       "Storage",
		},
		{
			Key:         "secret_count",
			Label:       "Secret Count",
			Type:        contracts.SettingTypeInt,
			Value:       strconv.Itoa(count),
			Description: "Read-only count of stored secrets",
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
		if value == "" {
			return fmt.Errorf("key_file must not be empty")
		}
		return m.setPaths("", &value)
	case "rotate_master_key":
		if value != "true" && value != "1" {
			return nil
		}
		return m.rotateMasterKey()
	case "secret_count":
		return fmt.Errorf("secret_count is read-only")
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

	if err := validateStoragePath(m.allowedRoot, newStore); err != nil {
		return fmt.Errorf("store path: %w", err)
	}
	if newKey != "" {
		if err := validateStoragePath(m.allowedRoot, newKey); err != nil {
			return fmt.Errorf("key file path: %w", err)
		}
	}

	if m.srv == nil {
		m.store = newStore
		m.keyFile = newKey
		return nil
	}

	if keyFile != nil {
		if _, err := os.Stat(newKey); err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("key file %q does not exist", newKey)
			}
			return fmt.Errorf("stat key file: %w", err)
		}
	}

	masterKey, err := loadMasterKey(newKey, false)
	if err != nil {
		return fmt.Errorf("load master key: %w", err)
	}

	oldVault := m.vault
	oldStore := m.store
	copySecrets := store != "" && newStore != oldStore && oldVault != nil && oldVault.Count() > 0

	v, err := vault.New(newStore, masterKey)
	if err != nil {
		return fmt.Errorf("open vault: %w", err)
	}

	if copySecrets {
		if err := oldVault.CopyEntries(context.Background(), v); err != nil {
			v.Close()
			return fmt.Errorf("copy secrets to new store: %w", err)
		}
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
