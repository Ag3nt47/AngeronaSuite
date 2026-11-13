package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
)

const maximumLedgerBytes = 16 * 1024

func ledgerKey(authority []byte) ([]byte, error) {
	if len(authority) != 32 {
		return nil, errors.New("restart ledger authority unavailable")
	}
	mac := hmac.New(sha256.New, authority)
	mac.Write([]byte("angerona-watchdog3-restart-ledger-v1\x00"))
	return mac.Sum(nil), nil
}

func ledgerBody(saved supervisorSnapshot) (map[string]any, error) {
	if saved.Schema != 1 || len(saved.Stops) > maximumPressureEvents || saved.RetryAfterNS < 0 {
		return nil, errors.New("invalid restart ledger")
	}
	stops := make([]any, 0, len(saved.Stops))
	last := int64(0)
	for _, stamp := range saved.Stops {
		if stamp <= 0 || stamp < last {
			return nil, errors.New("invalid restart ledger")
		}
		last = stamp
		stops = append(stops, stamp)
	}
	return map[string]any{"schema": 1, "stops": stops, "attempts": saved.Attempts, "retry_after_ns": saved.RetryAfterNS}, nil
}

func encodeLedger(authority []byte, saved supervisorSnapshot) ([]byte, error) {
	key, err := ledgerKey(authority)
	if err != nil {
		return nil, err
	}
	body, err := ledgerBody(saved)
	if err != nil {
		return nil, err
	}
	canonical, err := canonicalJSON(body)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(canonical)
	raw, err := canonicalJSON(map[string]any{"body": body, "mac": hex.EncodeToString(mac.Sum(nil))})
	if err != nil || len(raw) > maximumLedgerBytes {
		return nil, errors.New("restart ledger exceeds bound")
	}
	return raw, nil
}

func boundedUnsigned(value any, bits int) (uint64, error) {
	number, ok := value.(json.Number)
	if !ok || strings.ContainsAny(string(number), ".eE-") {
		return 0, errors.New("invalid restart ledger integer")
	}
	result, err := strconv.ParseUint(string(number), 10, bits)
	if err != nil {
		return 0, errors.New("invalid restart ledger integer")
	}
	return result, nil
}

func decodeLedger(authority, raw []byte) (supervisorSnapshot, error) {
	var saved supervisorSnapshot
	key, err := ledgerKey(authority)
	if err != nil {
		return saved, err
	}
	envelope, err := readJSON(raw, maximumLedgerBytes)
	if err != nil {
		return saved, err
	}
	if !exactFields(envelope, "body", "mac") {
		return saved, errors.New("invalid restart ledger envelope")
	}
	body, ok := envelope["body"].(map[string]any)
	if !ok || !exactFields(body, "schema", "stops", "attempts", "retry_after_ns") {
		return saved, errors.New("invalid restart ledger body")
	}
	tag, ok := envelope["mac"].(string)
	if !ok || !lowerHex(tag, 64) {
		return saved, errors.New("invalid restart ledger authentication")
	}
	canonical, err := canonicalJSON(body)
	if err != nil {
		return saved, err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(canonical)
	supplied, _ := hex.DecodeString(tag)
	if !hmac.Equal(mac.Sum(nil), supplied) {
		return saved, errors.New("restart ledger authentication failed")
	}
	schema, err := boundedUnsigned(body["schema"], 32)
	if err != nil || schema != 1 {
		return saved, errors.New("invalid restart ledger schema")
	}
	attempts, err := boundedUnsigned(body["attempts"], 32)
	if err != nil {
		return saved, err
	}
	retry, err := boundedUnsigned(body["retry_after_ns"], 63)
	if err != nil {
		return saved, err
	}
	stops, ok := body["stops"].([]any)
	if !ok || len(stops) > maximumPressureEvents {
		return saved, errors.New("invalid restart ledger stops")
	}
	saved = supervisorSnapshot{Schema: 1, Stops: make([]int64, 0, len(stops)), Attempts: uint32(attempts), RetryAfterNS: int64(retry)}
	last := int64(0)
	for _, value := range stops {
		stamp, err := boundedUnsigned(value, 63)
		if err != nil || stamp == 0 || int64(stamp) < last {
			return supervisorSnapshot{}, errors.New("invalid restart ledger stop")
		}
		last = int64(stamp)
		saved.Stops = append(saved.Stops, last)
	}
	return saved, nil
}
