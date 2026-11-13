package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"
)

const configurationLimit = 16 * 1024

// This is installed authority, not a user-supplied command line or environment.
type configuration struct {
	Schema           int      `json:"schema"`
	DataDir          string   `json:"data_dir"`
	LauncherPath     string   `json:"launcher_path"`
	LauncherSHA256   string   `json:"launcher_sha256"`
	LauncherArgs     []string `json:"launcher_args"`
	WorkingDirectory string   `json:"working_directory"`
}

func decodeConfiguration(raw []byte) (configuration, error) {
	var c configuration
	if len(raw) == 0 || len(raw) > configurationLimit || !utf8.Valid(raw) {
		return c, errors.New("configuration size or encoding is invalid")
	}
	// DisallowUnknownFields alone does not reject duplicate JSON keys.
	d := json.NewDecoder(bytes.NewReader(raw))
	first, err := d.Token()
	if err != nil || first != json.Delim('{') {
		return c, errors.New("configuration must be an object")
	}
	seen := map[string]bool{}
	allowed := map[string]bool{"schema": true, "data_dir": true, "launcher_path": true, "launcher_sha256": true, "launcher_args": true, "working_directory": true}
	for d.More() {
		token, err := d.Token()
		name, ok := token.(string)
		if err != nil || !ok || seen[name] || !allowed[name] {
			return c, errors.New("configuration has duplicate or invalid fields")
		}
		seen[name] = true
		var value json.RawMessage
		if err := d.Decode(&value); err != nil {
			return c, errors.New("configuration field is malformed")
		}
	}
	if _, err := d.Token(); err != nil {
		return c, errors.New("configuration is incomplete")
	}
	if _, err := d.Token(); err != io.EOF {
		return c, errors.New("configuration has trailing data")
	}
	if len(seen) != 6 {
		return c, errors.New("configuration fields are incomplete")
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return c, errors.New("configuration schema is invalid")
	}
	if c.Schema != 2 {
		return c, errors.New("configuration version is unsupported")
	}
	for _, p := range []string{c.DataDir, c.LauncherPath, c.WorkingDirectory} {
		if !localAbsolutePath(p) {
			return c, errors.New("configuration requires canonical local absolute paths")
		}
	}
	if !strings.EqualFold(filepath.Base(c.LauncherPath), "Angerona.exe") ||
		!strings.EqualFold(filepath.Dir(c.LauncherPath), c.WorkingDirectory) {
		return c, errors.New("configuration does not name the fixed Angerona launcher")
	}
	if len(c.LauncherSHA256) != 64 || strings.Trim(c.LauncherSHA256, "0123456789abcdef") != "" {
		return c, errors.New("configuration launcher pin is invalid")
	}
	if len(c.LauncherArgs) != 1 || c.LauncherArgs[0] != "--engine-service" {
		return c, errors.New("configuration must name the fixed installed service entry")
	}
	return c, nil
}

func localAbsolutePath(p string) bool {
	if p == "" || len(p) > 2048 || strings.ContainsAny(p, "\x00\r\n\t") ||
		strings.HasPrefix(p, `\\`) || strings.HasPrefix(p, "//") ||
		!filepath.IsAbs(p) || filepath.Clean(p) != p {
		return false
	}
	for _, part := range strings.FieldsFunc(p, func(r rune) bool { return r == '/' || r == '\\' }) {
		if part == "." || part == ".." {
			return false
		}
		if part == filepath.VolumeName(p) {
			continue
		}
		if strings.ContainsAny(part, `<>:"|?*`) || strings.TrimRight(part, " .") != part ||
			strings.IndexFunc(part, unicode.IsControl) >= 0 {
			return false
		}
		base := strings.ToUpper(strings.SplitN(part, ".", 2)[0])
		if base == "CON" || base == "PRN" || base == "AUX" || base == "NUL" || base == "CLOCK$" ||
			(len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && base[3] >= '1' && base[3] <= '9') {
			return false
		}
	}
	return true
}
