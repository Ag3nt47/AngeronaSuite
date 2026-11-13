package main

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

func TestRestartLedgerAuthenticationAndBounds(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	now := time.Unix(1700000000, 0)
	saved := supervisorSnapshot{Schema: 1, Stops: []int64{now.Add(-time.Hour).UnixNano(), now.Add(-time.Minute).UnixNano()}, Attempts: 5, RetryAfterNS: now.Add(time.Minute).UnixNano()}
	raw, err := encodeLedger(key, saved)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := decodeLedger(key, raw)
	if err != nil || restored.Attempts != 5 || len(restored.Stops) != 2 {
		t.Fatalf("ledger lost data: %+v %v", restored, err)
	}
	for _, input := range [][]byte{append(raw, []byte("{}")...), bytes.Replace(raw, []byte(`"attempts":5`), []byte(`"attempts":1`), 1), []byte(`{"body":{},"mac":"forged"}`), bytes.Repeat([]byte{'x'}, maximumLedgerBytes+1)} {
		if _, err := decodeLedger(key, input); err == nil {
			t.Fatal("untrusted ledger accepted")
		}
	}
	if _, err := decodeLedger(bytes.Repeat([]byte{2}, 32), raw); err == nil {
		t.Fatal("wrong ledger authority accepted")
	}
	saved.Stops = make([]int64, maximumPressureEvents)
	for index := range saved.Stops {
		saved.Stops[index] = int64(index + 1)
	}
	raw, err = encodeLedger(key, saved)
	if err != nil {
		t.Fatal(err)
	}
	if decoded, err := decodeLedger(key, raw); err != nil || len(decoded.Stops) != maximumPressureEvents {
		t.Fatal("maximum valid bounded ledger not readable", err)
	}
	for _, value := range []any{true, json.Number("1.0"), json.Number("-1")} {
		if _, err := boundedUnsigned(value, 32); err == nil {
			t.Fatal("invalid integer accepted")
		}
	}
}
