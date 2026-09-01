package internal

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func resolveAllowedRoot(store, keyFile string) string {
	var root string
	if v := strings.TrimSpace(os.Getenv("SECRETS_ALLOWED_ROOT")); v != "" {
		root = absPath(v)
	} else {
		var dirs []string
		if store != "" {
			dirs = append(dirs, absPath(filepath.Dir(store)))
		}
		if keyFile != "" {
			dirs = append(dirs, absPath(filepath.Dir(keyFile)))
		}
		switch len(dirs) {
		case 0:
			root = filepath.Clean(".")
		case 1:
			root = dirs[0]
		case 2:
			if dirs[0] == dirs[1] {
				root = dirs[0]
			} else {
				root = commonPathPrefix(dirs[0], dirs[1])
			}
		default:
			root = dirs[0]
			for _, d := range dirs[1:] {
				root = commonPathPrefix(root, d)
			}
		}
	}
	if abs, err := filepath.Abs(root); err == nil {
		return abs
	}
	return filepath.Clean(root)
}

func commonPathPrefix(a, b string) string {
	a = filepath.Clean(a)
	b = filepath.Clean(b)
	i := 0
	for i < len(a) && i < len(b) && a[i] == b[i] {
		i++
	}
	if i == 0 {
		return "."
	}
	for i > 0 && a[i-1] != filepath.Separator {
		i--
	}
	if i <= 1 {
		if filepath.IsAbs(a) || filepath.IsAbs(b) {
			return string(filepath.Separator)
		}
		return "."
	}
	return a[:i-1]
}

func validateStoragePath(root, path string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("path must not be empty")
	}
	clean := filepath.Clean(path)
	if clean == "." {
		return fmt.Errorf("path must not be %q", clean)
	}
	if strings.Contains(clean, "..") {
		return fmt.Errorf("path must not contain parent segments")
	}

	absRoot, err := filepath.Abs(root)
	if err != nil {
		return fmt.Errorf("resolve allowed root: %w", err)
	}
	absPath, err := filepath.Abs(clean)
	if err != nil {
		return fmt.Errorf("resolve path: %w", err)
	}
	rel, err := filepath.Rel(absRoot, absPath)
	if err != nil {
		return fmt.Errorf("path outside allowed root: %w", err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("path %q outside allowed root %q", clean, absRoot)
	}
	return nil
}
