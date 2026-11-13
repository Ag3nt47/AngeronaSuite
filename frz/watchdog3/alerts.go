package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	alertGenesis = "0000000000000000000000000000000000000000000000000000000000000000"
	maxAlertLine = 4096
	maxAlertFile = 256 * 1024
)

func alertKey(authority []byte) ([]byte, error) {
	if len(authority) != 32 {
		return nil, errors.New("invalid alert authority")
	}
	mac := hmac.New(sha256.New, authority)
	mac.Write([]byte("angerona-peer-alert-outbox-v1\x00"))
	return mac.Sum(nil), nil
}

func alertMAC(key []byte, record map[string]any) (string, error) {
	body := map[string]any{}
	for _, field := range []string{"id", "ts", "source", "level", "msg", "details", "prev"} {
		value, ok := record[field]
		if !ok {
			return "", errors.New("invalid alert fields")
		}
		body[field] = value
	}
	raw, err := canonicalJSON(body)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(raw)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// No file IO occurs here. The one-writer runtime holds private file custody,
// rotates at maxAlertFile, and recomputes the first rotated line at genesis.
// Callers provide fixed messages and observed state/count details, not input
// file names, exception messages, command text or other attacker-controlled data.
func makeAlert(authority []byte, previous, level, msg string, details map[string]any, now time.Time, id string) ([]byte, string, error) {
	key, err := alertKey(authority)
	if err != nil {
		return nil, "", err
	}
	if !lowerHex(previous, 64) || !lowerHex(id, 16) || (level != "MEDIUM" && level != "HIGH" && level != "CRITICAL") || !printable(msg, 512) {
		return nil, "", errors.New("invalid alert metadata")
	}
	if len(details) > 24 {
		return nil, "", errors.New("too many alert details")
	}
	safe := map[string]any{}
	for name, value := range details {
		if !printable(name, 64) {
			return nil, "", errors.New("invalid alert detail name")
		}
		switch typed := value.(type) {
		case nil, bool, int, int64, uint64, uint32:
			safe[name] = value
		case json.Number:
			if _, err := pythonNumber(typed); err != nil {
				return nil, "", err
			}
			safe[name] = value
		case float64:
			if math.IsNaN(typed) || math.IsInf(typed, 0) {
				return nil, "", errors.New("invalid alert numeric detail")
			}
			safe[name] = typed
		case string:
			if !utf8.ValidString(typed) || utf8.RuneCountInString(typed) > 256 {
				return nil, "", errors.New("invalid alert string detail")
			}
			for _, c := range typed {
				if c < 32 {
					return nil, "", errors.New("invalid alert string detail")
				}
			}
			safe[name] = typed
		default:
			return nil, "", errors.New("invalid alert detail type")
		}
	}
	seconds := float64(now.Unix()) + float64(now.Nanosecond())/1e9
	stamp := strconv.FormatFloat(math.RoundToEven(seconds*1000)/1000, 'f', 3, 64)
	stamp = strings.TrimRight(stamp, "0")
	if strings.HasSuffix(stamp, ".") {
		stamp += "0"
	}
	record := map[string]any{"id": id, "ts": json.Number(stamp), "source": "watchdog3", "level": level, "msg": msg, "details": safe, "prev": previous}
	mac, err := alertMAC(key, record)
	if err != nil {
		return nil, "", err
	}
	record["mac"] = mac
	line, err := canonicalJSON(record)
	if err != nil {
		return nil, "", err
	}
	if len(line)+1 > maxAlertLine {
		record["details"] = map[string]any{"truncated": true}
		mac, err = alertMAC(key, record)
		if err != nil {
			return nil, "", err
		}
		record["mac"] = mac
		line, err = canonicalJSON(record)
	}
	if err != nil || len(line)+1 > maxAlertLine {
		return nil, "", errors.New("alert line exceeds bound")
	}
	return append(line, '\n'), mac, nil
}

// Unlike silently resetting a corrupt tail, refusal preserves tamper evidence.
// A rotation is a new chain and must be explicitly made by the runtime.
func recoverAlertTail(authority []byte, raw []byte) (string, error) {
	key, err := alertKey(authority)
	if err != nil {
		return "", err
	}
	if len(raw) > maxAlertFile {
		return "", errors.New("alert file exceeds bound")
	}
	if len(raw) == 0 {
		return alertGenesis, nil
	}
	if raw[len(raw)-1] != '\n' {
		return "", errors.New("incomplete alert line")
	}
	previous := alertGenesis
	for _, line := range bytes.Split(raw, []byte{'\n'}) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		if len(line)+1 > maxAlertLine {
			return "", errors.New("alert line exceeds bound")
		}
		record, err := readJSON(line, maxAlertLine)
		if err != nil {
			return "", err
		}
		if !exactFields(record, "id", "ts", "source", "level", "msg", "details", "prev", "mac") {
			return "", errors.New("invalid alert fields")
		}
		id, idOK := record["id"].(string)
		source, sourceOK := record["source"].(string)
		level, levelOK := record["level"].(string)
		msg, msgOK := record["msg"].(string)
		prev, prevOK := record["prev"].(string)
		mac, macOK := record["mac"].(string)
		_, stampOK := finiteNumber(record["ts"])
		details, detailsOK := record["details"].(map[string]any)
		if !idOK || !lowerHex(id, 16) || !sourceOK || source != "watchdog3" || !levelOK || (level != "MEDIUM" && level != "HIGH" && level != "CRITICAL") || !msgOK || !printable(msg, 512) || !prevOK || prev != previous || !macOK || !lowerHex(mac, 64) || !stampOK || !detailsOK || len(details) > 24 {
			return "", errors.New("invalid alert metadata or chain")
		}
		expected, err := alertMAC(key, record)
		if err != nil || !hmac.Equal([]byte(mac), []byte(expected)) {
			return "", errors.New("alert authentication failed")
		}
		previous = mac
	}
	return previous, nil
}
