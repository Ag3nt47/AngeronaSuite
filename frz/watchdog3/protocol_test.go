package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

type protocolVectors struct {
	TestMaterialOnly bool    `json:"test_material_only"`
	AuthorityHex     string  `json:"authority_hex"`
	SeedHex          string  `json:"ed25519_seed_hex"`
	PublicHex        string  `json:"admin_public_hex"`
	Now              float64 `json:"now"`
	Heartbeats       []struct {
		Name        string `json:"name"`
		TimestampNS uint64 `json:"timestamp_ns"`
		PID         uint32 `json:"pid"`
		Counter     uint32 `json:"counter"`
		Flags       uint32 `json:"flags"`
		Hex         string `json:"hex"`
	} `json:"heartbeats"`
	Stop           map[string]string `json:"stop"`
	Alerts         map[string]string `json:"alerts"`
	CanonicalCases []struct {
		Input    json.RawMessage `json:"input"`
		Expected string          `json:"expected"`
	} `json:"canonical_cases"`
}

func loadProtocolVectors(t *testing.T) protocolVectors {
	t.Helper()
	raw, err := os.ReadFile("testdata/protocol_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture protocolVectors
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if !fixture.TestMaterialOnly {
		t.Fatal("protocol authority must be test material")
	}
	return fixture
}

func testAuthority(t *testing.T, fixture protocolVectors) []byte {
	t.Helper()
	key, err := hex.DecodeString(fixture.AuthorityHex)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
func vectorTime(fixture protocolVectors) time.Time { return time.Unix(int64(fixture.Now), 125000000) }

func TestPythonHeartbeatVectors(t *testing.T) {
	fixture := loadProtocolVectors(t)
	key := testAuthority(t, fixture)
	for _, vector := range fixture.Heartbeats {
		t.Run(vector.Name, func(t *testing.T) {
			raw, err := hex.DecodeString(vector.Hex)
			if err != nil {
				t.Fatal(err)
			}
			expected := heartbeatRecord{vector.TimestampNS, vector.PID, vector.Counter, vector.Flags}
			actual, err := decodeHeartbeat(key, vector.Name, raw)
			if err != nil || actual != expected {
				t.Fatalf("Python frame not decoded: %v", err)
			}
			encoded, err := encodeHeartbeat(key, vector.Name, expected)
			if err != nil || !bytes.Equal(encoded, raw) {
				t.Fatalf("Go frame differs from Python: %v", err)
			}
			for index := range raw {
				tampered := append([]byte(nil), raw...)
				tampered[index] ^= 1
				if _, err := decodeHeartbeat(key, vector.Name, tampered); err == nil {
					t.Fatalf("tampered byte %d accepted", index)
				}
			}
			if _, err := decodeHeartbeat(key, vector.Name+"-wrong-component", raw); err == nil {
				t.Fatal("wrong component accepted")
			}
			wrong := bytes.Repeat([]byte{0xab}, 32)
			if _, err := decodeHeartbeat(wrong, vector.Name, raw); err == nil {
				t.Fatal("wrong authority accepted")
			}
			if _, err := decodeHeartbeat(key, vector.Name, raw[:31]); err == nil {
				t.Fatal("truncated frame accepted")
			}
			if _, err := decodeHeartbeat(key, vector.Name, append(raw, 0)); err == nil {
				t.Fatal("oversized frame accepted")
			}
		})
	}
}

func TestHeartbeatReplayAndCounterWrap(t *testing.T) {
	first := heartbeatRecord{1000, 1234, 100, heartbeatV2 | heartbeatRunning}
	var state heartbeatReplay
	for _, frame := range []heartbeatRecord{first, first, {1000, 1234, 101, heartbeatV2 | heartbeatRunning}, {1001, 1234, 102, heartbeatV2 | heartbeatRunning}} {
		if err := state.accept(frame); err != nil {
			t.Fatal(err)
		}
	}
	for _, frame := range []heartbeatRecord{{1000, 1234, 103, heartbeatV2 | heartbeatRunning}, {1001, 1234, 101, heartbeatV2 | heartbeatRunning}, {1001, 5678, 1, heartbeatV2 | heartbeatRunning}} {
		if err := state.accept(frame); err == nil {
			t.Fatal("replayed frame accepted")
		}
	}
	if err := state.accept(heartbeatRecord{1002, 5678, 1, heartbeatV2 | heartbeatRunning}); err != nil {
		t.Fatal("new generation cannot restart counter")
	}
	state = heartbeatReplay{}
	if err := state.accept(heartbeatRecord{2000, 1234, 0xffffffff, heartbeatV2 | heartbeatRunning}); err != nil {
		t.Fatal(err)
	}
	if err := state.accept(heartbeatRecord{2001, 1234, 0, heartbeatV2 | heartbeatRunning}); err != nil {
		t.Fatal("legitimate counter wrap refused")
	}
}

func TestPythonCanonicalControlVectors(t *testing.T) {
	for _, vector := range loadProtocolVectors(t).CanonicalCases {
		document, err := readJSON(vector.Input, maxControlFile)
		if err != nil {
			t.Fatal(err)
		}
		canonical, err := canonicalJSON(document)
		if err != nil || string(canonical) != vector.Expected {
			t.Fatalf("Python canonical mismatch: %q != %q (%v)", canonical, vector.Expected, err)
		}
	}
	for _, raw := range []string{`{"schema":1,"schema":2}`, `{"a":1} {"b":2}`, `[]`, `{"nested":[[[[[[[[[0]]]]]]]]]}`} {
		if _, err := readJSON([]byte(raw), maxControlFile); err == nil {
			t.Fatal("ambiguous or unbounded JSON accepted")
		}
	}
}

func TestPythonAdminSTOPVectors(t *testing.T) {
	fixture := loadProtocolVectors(t)
	key := testAuthority(t, fixture)
	for _, test := range []struct {
		name   string
		active bool
	}{{"operator", true}, {"maintenance", true}, {"expired", false}, {"stale_epoch", false}, {"future", false}} {
		t.Run(test.name, func(t *testing.T) {
			input := stopInputs{AdminPresent: true, CustodyValid: true, AdminPublic: []byte(fixture.PublicHex), AdminEpoch: []byte(fixture.Stop["epoch"]), AdminCommand: []byte(fixture.Stop[test.name]), LegacyCommand: []byte(fixture.Stop["legacy_operator"])}
			decision, err := verifyStop(input, key, vectorTime(fixture))
			if err != nil || decision.Active != test.active || decision.Source != "admin" || decision.Epoch != 7 {
				t.Fatalf("admin STOP mismatch: %+v %v", decision, err)
			}
		})
	}
	input := stopInputs{AdminPresent: true, CustodyValid: true, AdminPublic: []byte(fixture.PublicHex), AdminEpoch: []byte(fixture.Stop["epoch"]), LegacyCommand: []byte(fixture.Stop["legacy_operator"])}
	if decision, err := verifyStop(input, key, vectorTime(fixture)); err != nil || decision.Active {
		t.Fatal("legacy command bypassed provisioned admin authority")
	}
	input.AdminPublic = nil
	if decision, err := verifyStop(input, key, vectorTime(fixture)); err == nil || decision.Active {
		t.Fatal("incomplete admin directory became clear/legacy STOP")
	}
	input.AdminPublic = []byte(fixture.PublicHex)
	input.AdminCommand = []byte{}
	if decision, err := verifyStop(input, key, vectorTime(fixture)); err == nil || decision.Active {
		t.Fatal("existing empty admin command became absent/clear")
	}
}

func signTestControl(t *testing.T, fixture protocolVectors, document map[string]any) []byte {
	t.Helper()
	seed, err := hex.DecodeString(fixture.SeedHex)
	if err != nil {
		t.Fatal(err)
	}
	private := ed25519.NewKeyFromSeed(seed)
	delete(document, "sig")
	canonical, err := canonicalJSON(document)
	if err != nil {
		t.Fatal(err)
	}
	document["sig"] = hex.EncodeToString(ed25519.Sign(private, canonical))
	raw, err := canonicalJSON(document)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestAdminSTOPRejectsTamperAndClosedSchemaViolations(t *testing.T) {
	fixture := loadProtocolVectors(t)
	key := testAuthority(t, fixture)
	base := func() stopInputs {
		return stopInputs{AdminPresent: true, CustodyValid: true, AdminPublic: []byte(fixture.PublicHex), AdminEpoch: []byte(fixture.Stop["epoch"]), AdminCommand: []byte(fixture.Stop["operator"])}
	}
	for _, mutate := range []func(*stopInputs){
		func(i *stopInputs) { i.CustodyValid = false }, func(i *stopInputs) { i.AdminEpoch = i.AdminEpoch[:10] },
		func(i *stopInputs) {
			i.AdminCommand = []byte(strings.Replace(string(i.AdminCommand), "Operator", "Tampered", 1))
		},
		func(i *stopInputs) { i.AdminCommand = bytes.Repeat([]byte{' '}, maxControlFile+1) },
		func(i *stopInputs) { i.AdminPublic = []byte(strings.Repeat("0", 64)) },
	} {
		input := base()
		mutate(&input)
		if decision, err := verifyStop(input, key, vectorTime(fixture)); err == nil || decision.Active {
			t.Fatal("invalid admin input accepted")
		}
	}
	for _, test := range []struct {
		name  string
		value any
	}{{"epoch", true}, {"epoch", json.Number("7.0")}, {"schema", json.Number("2")}, {"nonce", "wrong"}, {"reason", ""}, {"reason", "bad\nreason"}, {"extra", true}} {
		document, err := readJSON([]byte(fixture.Stop["operator"]), maxControlFile)
		if err != nil {
			t.Fatal(err)
		}
		document[test.name] = test.value
		input := base()
		input.AdminCommand = signTestControl(t, fixture, document)
		if decision, err := verifyStop(input, key, vectorTime(fixture)); err == nil || decision.Active {
			t.Fatalf("closed control schema violation accepted: %s", test.name)
		}
	}
	epoch, err := readJSON([]byte(fixture.Stop["epoch"]), maxControlFile)
	if err != nil {
		t.Fatal(err)
	}
	epoch["epoch"] = true
	input := base()
	input.AdminEpoch = signTestControl(t, fixture, epoch)
	if decision, err := verifyStop(input, key, vectorTime(fixture)); err == nil || decision.Active {
		t.Fatal("boolean epoch accepted")
	}
}

func TestPythonLegacySTOPVectors(t *testing.T) {
	fixture := loadProtocolVectors(t)
	key := testAuthority(t, fixture)
	for _, test := range []struct {
		name   string
		active bool
	}{{"legacy_operator", true}, {"legacy_maintenance", true}, {"legacy_expired", false}} {
		input := stopInputs{CustodyValid: true, LegacyCommand: []byte(fixture.Stop[test.name])}
		decision, err := verifyStop(input, key, vectorTime(fixture))
		if err != nil || decision.Active != test.active {
			t.Fatalf("legacy mismatch %s: %+v %v", test.name, decision, err)
		}
		input.LegacyCommand = []byte(strings.Replace(string(input.LegacyCommand), "maintenance", "tampered", 1))
		if test.name != "legacy_operator" {
			if _, err := verifyStop(input, key, vectorTime(fixture)); err == nil {
				t.Fatal("tampered legacy accepted")
			}
		}
	}
	for _, raw := range []string{`{}`, `{"nonce":true}`, fixture.Stop["legacy_operator"] + `{}`, strings.Replace(fixture.Stop["legacy_operator"], `"nonce":`, `"nonce":"duplicate","nonce":`, 1)} {
		if decision, err := verifyStop(stopInputs{CustodyValid: true, LegacyCommand: []byte(raw)}, key, vectorTime(fixture)); err == nil || decision.Active {
			t.Fatal("malformed legacy accepted")
		}
	}
	if decision, err := verifyStop(stopInputs{CustodyValid: true, LegacyCommand: []byte{}}, key, vectorTime(fixture)); err == nil || decision.Active {
		t.Fatal("existing empty legacy command became absent/clear")
	}
}

func TestPythonAlertChainAndGoEncoding(t *testing.T) {
	fixture := loadProtocolVectors(t)
	key := testAuthority(t, fixture)
	first, err := readJSON([]byte(strings.TrimSpace(fixture.Alerts["first"])), maxAlertLine)
	if err != nil {
		t.Fatal(err)
	}
	line, mac, err := makeAlert(key, alertGenesis, "HIGH", "Native watchdog peer state changed", first["details"].(map[string]any), vectorTime(fixture), "0123456789abcdef")
	if err != nil || string(line) != fixture.Alerts["first"] {
		t.Fatalf("Go alert differs from Python: %v\n%s", err, line)
	}
	second, next, err := makeAlert(key, mac, "CRITICAL", "Native watchdog peer state changed", first["details"].(map[string]any), vectorTime(fixture), "abcdef0123456789")
	if err != nil || string(second) != fixture.Alerts["second"] {
		t.Fatalf("Go chained alert differs from Python: %v", err)
	}
	if tail, err := recoverAlertTail(key, append(line, second...)); err != nil || tail != next {
		t.Fatalf("Python alert chain invalid: %s %v", tail, err)
	}
	for _, raw := range [][]byte{
		[]byte(strings.Replace(fixture.Alerts["first"], "state changed", "state forged", 1)),
		[]byte(fixture.Alerts["second"] + fixture.Alerts["first"]),
		append(append([]byte(nil), line...), []byte("{\"forged\":true}\n")...), line[:len(line)-1],
		bytes.Repeat([]byte{'x'}, maxAlertFile+1),
	} {
		if _, err := recoverAlertTail(key, raw); err == nil {
			t.Fatal("edited, reordered or incomplete alert chain accepted")
		}
	}
	if tail, err := recoverAlertTail(key, nil); err != nil || tail != alertGenesis {
		t.Fatal("new chain does not begin at genesis")
	}
}

func TestAlertBoundsReauthenticateTruncatedDetails(t *testing.T) {
	fixture := loadProtocolVectors(t)
	details := map[string]any{}
	for index := 0; index < 24; index++ {
		details[fmt.Sprint(index)] = strings.Repeat("x", 256)
	}
	line, mac, err := makeAlert(testAuthority(t, fixture), alertGenesis, "HIGH", "Native watchdog peer state changed", details, vectorTime(fixture), "0123456789abcdef")
	if err != nil || len(line) > maxAlertLine {
		t.Fatal("bounded alert not emitted", err)
	}
	if !bytes.Contains(line, []byte(`"truncated":true`)) {
		t.Fatal("oversized details not marked")
	}
	if tail, err := recoverAlertTail(testAuthority(t, fixture), line); err != nil || tail != mac {
		t.Fatal("truncated details not authenticated")
	}
}

func TestPythonAlertIntegralAndMillisecondTimestamps(t *testing.T) {
	fixture := loadProtocolVectors(t)
	key := testAuthority(t, fixture)
	first, err := readJSON([]byte(strings.TrimSpace(fixture.Alerts["first"])), maxAlertLine)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name  string
		nanos int64
	}{{"integral", 0}, {"millisecond", 1000000}} {
		line, _, err := makeAlert(key, alertGenesis, "HIGH", "Native watchdog peer state changed", first["details"].(map[string]any), time.Unix(1700000000, test.nanos), "0123456789abcdef")
		if err != nil || string(line) != fixture.Alerts[test.name] {
			t.Fatalf("timestamp canonicalization differs from Python: %s %v", test.name, err)
		}
	}
}

// A test-only export gives pytest an actual Go-produced frame and alert line.
// It never runs from the production executable and contains fixed public keys.
func TestExportPythonInterop(t *testing.T) {
	if os.Getenv("ANGERONA_WATCHDOG3_INTEROP_EXPORT") != "1" {
		t.Skip("explicit cross-language fixture export only")
	}
	fixture := loadProtocolVectors(t)
	key := testAuthority(t, fixture)
	vector := fixture.Heartbeats[0]
	heartbeat, err := encodeHeartbeat(key, "core", heartbeatRecord{vector.TimestampNS, vector.PID, vector.Counter, vector.Flags})
	if err != nil {
		t.Fatal(err)
	}
	first, err := readJSON([]byte(strings.TrimSpace(fixture.Alerts["first"])), maxAlertLine)
	if err != nil {
		t.Fatal(err)
	}
	line, _, err := makeAlert(key, alertGenesis, "HIGH", "Native watchdog peer state changed", first["details"].(map[string]any), vectorTime(fixture), "0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(map[string]string{"heartbeat_hex": hex.EncodeToString(heartbeat), "alert_line_base64": base64.StdEncoding.EncodeToString(line)})
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("WATCHDOG3_INTEROP %s\n", base64.StdEncoding.EncodeToString(raw))
}
