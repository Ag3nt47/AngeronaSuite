package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

const maxControlFile = 4096

// Secure, bounded file acquisition is separate: CustodyValid means that the
// runtime retained and checked the authority's files and parent directories.
// AdminPresent refers to the control directory, including incomplete installs.
type stopInputs struct {
	AdminPresent                                         bool
	CustodyValid                                         bool
	AdminPublic, AdminEpoch, AdminCommand, LegacyCommand []byte
}

type stopDecision struct {
	Active       bool
	Source, Kind string
	Epoch        uint64
}

// readJSON rejects duplicate members, trailing values, excess nesting and bad
// UTF-8 before a signed body is interpreted. Decoder's UseNumber retains the
// distinction between integer and floating-point values in Python's wire form.
func readJSON(raw []byte, limit int) (map[string]any, error) {
	if len(raw) == 0 || len(raw) > limit || !utf8.Valid(raw) {
		return nil, errors.New("invalid JSON size or encoding")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value func(int) (any, error)
	value = func(depth int) (any, error) {
		if depth > 8 {
			return nil, errors.New("JSON nesting exceeds bound")
		}
		token, err := decoder.Token()
		if err != nil {
			return nil, errors.New("malformed JSON")
		}
		if delim, ok := token.(json.Delim); ok {
			switch delim {
			case '{':
				object := map[string]any{}
				for decoder.More() {
					member, err := decoder.Token()
					if err != nil {
						return nil, errors.New("malformed JSON member")
					}
					name, ok := member.(string)
					if !ok || len(name) > 128 {
						return nil, errors.New("invalid JSON member")
					}
					if _, exists := object[name]; exists {
						return nil, errors.New("duplicate JSON member")
					}
					child, err := value(depth + 1)
					if err != nil {
						return nil, err
					}
					object[name] = child
					if len(object) > 32 {
						return nil, errors.New("too many JSON members")
					}
				}
				end, err := decoder.Token()
				if err != nil || end != json.Delim('}') {
					return nil, errors.New("malformed JSON object")
				}
				return object, nil
			case '[':
				array := []any{}
				for decoder.More() {
					child, err := value(depth + 1)
					if err != nil {
						return nil, err
					}
					array = append(array, child)
					if len(array) > 64 {
						return nil, errors.New("JSON array exceeds bound")
					}
				}
				end, err := decoder.Token()
				if err != nil || end != json.Delim(']') {
					return nil, errors.New("malformed JSON array")
				}
				return array, nil
			default:
				return nil, errors.New("unexpected JSON delimiter")
			}
		}
		return token, nil
	}
	result, err := value(0)
	if err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, errors.New("trailing JSON data")
	}
	object, ok := result.(map[string]any)
	if !ok {
		return nil, errors.New("JSON object required")
	}
	return object, nil
}

func pythonQuoted(value string) string {
	var out strings.Builder
	out.WriteByte('"')
	for _, r := range value {
		switch r {
		case '"', '\\':
			out.WriteByte('\\')
			out.WriteRune(r)
		case '\b':
			out.WriteString("\\b")
		case '\f':
			out.WriteString("\\f")
		case '\n':
			out.WriteString("\\n")
		case '\r':
			out.WriteString("\\r")
		case '\t':
			out.WriteString("\\t")
		default:
			if r >= 0x20 && r < 0x7f {
				out.WriteRune(r)
			} else if r <= 0xffff {
				out.WriteString("\\u")
				out.WriteString(hex4(uint16(r)))
			} else {
				hi, lo := utf16.EncodeRune(r)
				out.WriteString("\\u")
				out.WriteString(hex4(uint16(hi)))
				out.WriteString("\\u")
				out.WriteString(hex4(uint16(lo)))
			}
		}
	}
	out.WriteByte('"')
	return out.String()
}

func hex4(value uint16) string {
	const digits = "0123456789abcdef"
	return string([]byte{digits[value>>12], digits[(value>>8)&15], digits[(value>>4)&15], digits[value&15]})
}

func pythonNumber(number json.Number) (string, error) {
	text := string(number)
	if !strings.ContainsAny(text, ".eE") {
		integer, ok := new(big.Int).SetString(text, 10)
		if !ok {
			return "", errors.New("invalid integer")
		}
		return integer.String(), nil
	}
	f, err := strconv.ParseFloat(text, 64)
	if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
		return "", errors.New("invalid finite number")
	}
	abs := math.Abs(f)
	if abs == 0 || (abs >= 1e-4 && abs < 1e16) {
		text = strconv.FormatFloat(f, 'f', -1, 64)
		if !strings.Contains(text, ".") {
			text += ".0"
		}
		return text, nil
	}
	return strconv.FormatFloat(f, 'e', -1, 64), nil
}

// Match Python json.dumps(sort_keys=True,separators=(",",":"),ensure_ascii=True).
func canonicalJSON(value any) ([]byte, error) {
	var encode func(any) (string, error)
	encode = func(value any) (string, error) {
		switch typed := value.(type) {
		case nil:
			return "null", nil
		case bool:
			if typed {
				return "true", nil
			}
			return "false", nil
		case string:
			if !utf8.ValidString(typed) {
				return "", errors.New("invalid string encoding")
			}
			return pythonQuoted(typed), nil
		case json.Number:
			return pythonNumber(typed)
		case int:
			return strconv.Itoa(typed), nil
		case int64:
			return strconv.FormatInt(typed, 10), nil
		case uint64:
			return strconv.FormatUint(typed, 10), nil
		case uint32:
			return strconv.FormatUint(uint64(typed), 10), nil
		case float64:
			text := strconv.FormatFloat(typed, 'g', -1, 64)
			if !strings.ContainsAny(text, ".eE") {
				text += ".0"
			}
			return pythonNumber(json.Number(text))
		case map[string]any:
			keys := make([]string, 0, len(typed))
			for key := range typed {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			parts := make([]string, 0, len(keys))
			for _, key := range keys {
				child, err := encode(typed[key])
				if err != nil {
					return "", err
				}
				parts = append(parts, pythonQuoted(key)+":"+child)
			}
			return "{" + strings.Join(parts, ",") + "}", nil
		case []any:
			parts := make([]string, 0, len(typed))
			for _, child := range typed {
				encoded, err := encode(child)
				if err != nil {
					return "", err
				}
				parts = append(parts, encoded)
			}
			return "[" + strings.Join(parts, ",") + "]", nil
		default:
			return "", errors.New("unsupported canonical value")
		}
	}
	encoded, err := encode(value)
	return []byte(encoded), err
}

func exactFields(document map[string]any, names ...string) bool {
	if len(document) != len(names) {
		return false
	}
	for _, name := range names {
		if _, ok := document[name]; !ok {
			return false
		}
	}
	return true
}
func positiveInteger(value any) (uint64, bool) {
	number, ok := value.(json.Number)
	if !ok || strings.ContainsAny(string(number), ".eE-") {
		return 0, false
	}
	n, err := strconv.ParseUint(string(number), 10, 63)
	return n, err == nil && n > 0
}
func finiteNumber(value any) (float64, bool) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseFloat(string(number), 64)
	return n, err == nil && !math.IsNaN(n) && !math.IsInf(n, 0)
}
func lowerHex(value string, count int) bool {
	if len(value) != count {
		return false
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func printable(value string, limit int) bool {
	if !utf8.ValidString(value) || utf8.RuneCountInString(value) == 0 || utf8.RuneCountInString(value) > limit {
		return false
	}
	for _, c := range value {
		if c < 32 {
			return false
		}
	}
	return true
}

func signedControl(raw []byte, public ed25519.PublicKey) (map[string]any, error) {
	document, err := readJSON(raw, maxControlFile)
	if err != nil {
		return nil, err
	}
	signatureText, ok := document["sig"].(string)
	if !ok || !lowerHex(signatureText, 128) {
		return nil, errors.New("invalid control signature")
	}
	signature, _ := hex.DecodeString(signatureText)
	delete(document, "sig")
	canonical, err := canonicalJSON(document)
	if err != nil || !ed25519.Verify(public, canonical, signature) {
		return nil, errors.New("control authentication failed")
	}
	schema, ok := positiveInteger(document["schema"])
	if !ok || schema != 1 {
		return nil, errors.New("unsupported control schema")
	}
	return document, nil
}

func verifyStop(input stopInputs, authority []byte, now time.Time) (stopDecision, error) {
	clear := stopDecision{Source: "legacy"}
	if len(authority) != 32 || !input.CustodyValid {
		return clear, errors.New("STOP authority custody unavailable")
	}
	if input.AdminPresent {
		clear.Source = "admin"
		if len(input.AdminPublic) > 128 {
			return clear, errors.New("invalid admin public key")
		}
		for _, b := range input.AdminPublic {
			if b > 127 {
				return clear, errors.New("invalid admin public key encoding")
			}
		}
		encoded := strings.TrimSpace(string(input.AdminPublic))
		public, err := hex.DecodeString(encoded)
		if err != nil || len(public) != ed25519.PublicKeySize {
			return clear, errors.New("invalid admin public key")
		}
		epoch, err := signedControl(input.AdminEpoch, public)
		if err != nil {
			return clear, err
		}
		if !exactFields(epoch, "schema", "kind", "epoch", "ts") || epoch["kind"] != "epoch" {
			return clear, errors.New("invalid admin epoch")
		}
		epochNumber, ok := positiveInteger(epoch["epoch"])
		stamp, stampOK := finiteNumber(epoch["ts"])
		if !ok || !stampOK || stamp <= 0 {
			return clear, errors.New("invalid admin epoch")
		}
		clear.Epoch = epochNumber
		if input.AdminCommand == nil {
			return clear, nil
		}
		command, err := signedControl(input.AdminCommand, public)
		if err != nil {
			return clear, err
		}
		kind, ok := command["kind"].(string)
		if !ok || (kind != "operator-stop" && kind != "maintenance") {
			return clear, errors.New("invalid admin STOP kind")
		}
		names := []string{"schema", "kind", "nonce", "ts", "reason", "epoch"}
		if kind == "maintenance" {
			names = append(names, "expires")
		}
		if !exactFields(command, names...) {
			return clear, errors.New("invalid admin STOP fields")
		}
		commandEpoch, ok := positiveInteger(command["epoch"])
		ts, tsOK := finiteNumber(command["ts"])
		nonce, nonceOK := command["nonce"].(string)
		reason, reasonOK := command["reason"].(string)
		if !ok || !tsOK || ts <= 0 || !nonceOK || !lowerHex(nonce, 32) || !reasonOK || !printable(reason, 256) {
			return clear, errors.New("invalid admin STOP fields")
		}
		nowSeconds := float64(now.Unix()) + float64(now.Nanosecond())/1e9
		if commandEpoch != epochNumber || ts-nowSeconds > 30 {
			return clear, nil
		}
		if kind == "maintenance" {
			expires, ok := finiteNumber(command["expires"])
			if !ok {
				return clear, errors.New("invalid maintenance expiry")
			}
			if !(nowSeconds < expires && expires <= ts+3600) {
				return clear, nil
			}
		}
		clear.Active, clear.Kind = true, kind
		return clear, nil
	}
	if input.LegacyCommand == nil {
		return clear, nil
	}
	command, err := readJSON(input.LegacyCommand, maxControlFile)
	if err != nil {
		return clear, err
	}
	if !exactFields(command, "nonce", "ts", "reason", "sig") {
		return clear, errors.New("invalid legacy STOP fields")
	}
	nonce, nonceOK := command["nonce"].(string)
	reason, reasonOK := command["reason"].(string)
	sig, sigOK := command["sig"].(string)
	ts, tsOK := finiteNumber(command["ts"])
	if !nonceOK || !lowerHex(nonce, 32) || !reasonOK || !printable(reason, 256) || !sigOK || !lowerHex(sig, 64) || !tsOK || ts <= 0 || ts >= float64(math.MaxInt64) {
		return clear, errors.New("invalid legacy STOP fields")
	}
	payload := nonce + "\x00" + strconv.FormatInt(int64(ts), 10) + "\x00" + reason
	mac := hmac.New(sha256.New, authority)
	mac.Write([]byte(payload))
	signature, _ := hex.DecodeString(sig)
	if !hmac.Equal(mac.Sum(nil), signature) {
		return clear, errors.New("legacy STOP authentication failed")
	}
	nowSeconds := float64(now.Unix()) + float64(now.Nanosecond())/1e9
	age := nowSeconds - ts
	persistent := strings.HasPrefix(reason, "operator-stop: ")
	if age < -30 || (!persistent && age > 3600) {
		return clear, nil
	}
	clear.Active = true
	clear.Kind = "maintenance"
	if persistent {
		clear.Kind = "operator-stop"
	}
	return clear, nil
}
