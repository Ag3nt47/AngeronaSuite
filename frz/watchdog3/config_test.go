package main

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func fixtureConfiguration(t *testing.T) configuration {
	t.Helper()
	root := t.TempDir()
	return configuration{2, filepath.Join(root, "data"), filepath.Join(root, "Angerona.exe"), strings.Repeat("a", 64), []string{"--engine-service"}, root}
}

func TestConfigurationOnlyAcceptsFixedPinnedNativeLauncher(t *testing.T) {
	c := fixtureConfiguration(t)
	raw, _ := json.Marshal(c)
	if _, err := decodeConfiguration(raw); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*configuration){
		"missing pin":      func(c *configuration) { c.LauncherSHA256 = "" },
		"learn pin":        func(c *configuration) { c.LauncherSHA256 = "learn" },
		"shell":            func(c *configuration) { c.LauncherPath = filepath.Join(c.WorkingDirectory, "cmd.exe") },
		"relative":         func(c *configuration) { c.DataDir = "data" },
		"network":          func(c *configuration) { c.DataDir = `\\server\share` },
		"extra argument":   func(c *configuration) { c.LauncherArgs = []string{"--chill", "--setup"} },
		"missing argument": func(c *configuration) { c.LauncherArgs = nil },
		"other cwd":        func(c *configuration) { c.WorkingDirectory = filepath.Join(c.WorkingDirectory, "other") },
		"other version":    func(c *configuration) { c.Schema = 1 },
		"alternate stream": func(c *configuration) { c.DataDir = filepath.Join(c.DataDir, "cache:stream") },
		"trailing dot":     func(c *configuration) { c.DataDir = filepath.Join(c.DataDir, "cache.") },
		"control":          func(c *configuration) { c.DataDir = filepath.Join(c.DataDir, "cache\x01") },
		"device name":      func(c *configuration) { c.DataDir = filepath.Join(c.DataDir, "CON") },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := c
			mutate(&candidate)
			raw, _ := json.Marshal(candidate)
			if _, err := decodeConfiguration(raw); err == nil {
				t.Fatal("unapproved configuration accepted")
			}
		})
	}
}

func TestConfigurationRejectsDuplicateUnknownAndTrailingJSON(t *testing.T) {
	c := fixtureConfiguration(t)
	raw, _ := json.Marshal(c)
	for _, bad := range [][]byte{
		[]byte(strings.Replace(string(raw), `"schema":`, `"Schema":`, 1)),
		append([]byte(`{"schema":1,`), raw[1:]...),
		append([]byte(`{"environment":{},`), raw[1:]...),
		append(append([]byte{}, raw...), []byte(` {}`)...),
		[]byte(`null`), []byte(`[]`), []byte(`{"schema":true}`),
		[]byte(strings.Repeat(" ", configurationLimit+1)),
	} {
		if _, err := decodeConfiguration(bad); err == nil {
			t.Fatal("malformed configuration accepted")
		}
	}
}
