//go:build windows

package main

import (
	"reflect"
	"strings"
	"testing"
)

func TestChillCoreCommand(t *testing.T) {
	cases := []struct {
		name string
		argv []string
		want []string
	}{
		{"nil", nil, nil},
		{"empty", []string{}, nil},
		{"executableOnly", []string{"pythonw"}, []string{"pythonw", "--chill"}},
		{"absent", []string{"pythonw", "-m", "angerona", "--headless"}, []string{"pythonw", "-m", "angerona", "--headless", "--chill"}},
		{"existing", []string{"pythonw", "--chill", "--headless"}, []string{"pythonw", "--headless", "--chill"}},
		{"duplicates", []string{"pythonw", "--chill", "--headless", "--chill", "--chill"}, []string{"pythonw", "--headless", "--chill"}},
		{"exactOnly", []string{"pythonw", "--CHILL", "--chill=true", "path with spaces", ""}, []string{"pythonw", "--CHILL", "--chill=true", "path with spaces", "", "--chill"}},
		{"executablePreserved", []string{"--chill", "-m", "angerona"}, []string{"--chill", "-m", "angerona", "--chill"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			backing := append(append([]string{}, tc.argv...), "sentinel", "spare")
			before := append([]string{}, backing...)
			got := chillCoreCommand(backing[:len(tc.argv)])
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %#v, want %#v", got, tc.want)
			}
			if !reflect.DeepEqual(chillCoreCommand(got), got) {
				t.Fatal("normalization is not idempotent")
			}
			if len(got) > 0 {
				got[0] = "changed result"
			}
			if !reflect.DeepEqual(backing, before) {
				t.Fatalf("input backing array changed: %#v", backing)
			}
		})
	}
}

func TestChillCoreCommandRetainsFieldsParsing(t *testing.T) {
	// ANGERONA_CORE_CMD already uses strings.Fields; quote handling is unchanged.
	got := chillCoreCommand(strings.Fields("  pythonw\t-m angerona  --headless \"two words\" --chill  "))
	want := []string{"pythonw", "-m", "angerona", "--headless", "\"two", "words\"", "--chill"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("existing Fields parsing changed: got %#v, want %#v", got, want)
	}
	if err := detachedRun(chillCoreCommand(strings.Fields(" \t\n"))); err == nil || err.Error() != "empty command" {
		t.Fatalf("empty command must remain rejected: %v", err)
	}
}
