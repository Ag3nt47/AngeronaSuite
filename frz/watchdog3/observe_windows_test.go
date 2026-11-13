//go:build windows

package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func observeTestBootstrap() observeBootstrap {
	return observeBootstrap{Schema: 1, Nonce: strings.Repeat("a", 64), MACKey: strings.Repeat("b", 64),
		CorePID: 42, CoreBirth: "134387267728789675", CoreImage: `C:\Angerona\pythonw.exe`,
		CoreHeartbeat: `C:\Angerona\core.hb`, CoreHeartbeatKey: strings.Repeat("c", 64)}
}

func TestObserveBootstrapClosedScope(t *testing.T) {
	good := observeTestBootstrap()
	raw, _ := json.Marshal(good)
	if _, err := parseObserveBootstrap(raw); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []func(*observeBootstrap){
		func(v *observeBootstrap) { v.Schema = 2 }, func(v *observeBootstrap) { v.CorePID = 0 },
		func(v *observeBootstrap) { v.CoreBirth = "01" }, func(v *observeBootstrap) { v.Nonce = "00" },
		func(v *observeBootstrap) { v.CoreImage = `\\server\target.exe` },
		func(v *observeBootstrap) { v.CoreHeartbeat = `C:\Angerona\..\foreign.hb` },
	} {
		value := good
		mutation(&value)
		raw, _ := json.Marshal(value)
		if _, err := parseObserveBootstrap(raw); err == nil {
			t.Fatal("invalid scope admitted")
		}
	}
	for _, raw := range [][]byte{append(raw, []byte("{}")...), []byte(strings.Repeat(" ", observeMaxInput+1)), []byte(`{"schema":1,"authority":true}`)} {
		if _, err := parseObserveBootstrap(raw); err == nil {
			t.Fatal("open schema admitted")
		}
	}
}

func observeTestHeartbeat(key []byte, now time.Time) []byte {
	raw := make([]byte, 32)
	binary.LittleEndian.PutUint32(raw, 0x41574447)
	binary.LittleEndian.PutUint64(raw[4:], uint64(now.UnixNano()))
	binary.LittleEndian.PutUint32(raw[12:], 42)
	binary.LittleEndian.PutUint32(raw[24:], 7)
	binary.LittleEndian.PutUint32(raw[28:], 0x80000001)
	var body bytes.Buffer
	binary.Write(&body, binary.LittleEndian, uint16(4))
	body.WriteString("core")
	body.Write(raw[4:16])
	body.Write(raw[24:32])
	mac := hmac.New(sha256.New, key)
	mac.Write(body.Bytes())
	copy(raw[16:24], mac.Sum(nil)[:8])
	return raw
}

func TestObserveHeartbeatAuthenticatesExactCoreAndFreshness(t *testing.T) {
	now := time.Unix(1700000000, 0)
	key := bytes.Repeat([]byte{9}, 32)
	good := observeTestHeartbeat(key, now)
	if count, err := observeCoreHeartbeat(good, key, 42, now); err != nil || count != 7 {
		t.Fatal(count, err)
	}
	for _, index := range []int{0, 4, 12, 16, 24, 28} {
		bad := append([]byte(nil), good...)
		bad[index] ^= 1
		if _, err := observeCoreHeartbeat(bad, key, 42, now); err == nil {
			t.Fatal("tampered heartbeat admitted", index)
		}
	}
	if _, err := observeCoreHeartbeat(good, key, 43, now); err == nil {
		t.Fatal("other PID admitted")
	}
	if _, err := observeCoreHeartbeat(good, key, 42, now.Add(11*time.Second)); err == nil {
		t.Fatal("stale admitted")
	}
	if _, err := observeCoreHeartbeat(good, key, 42, now.Add(-time.Second)); err == nil {
		t.Fatal("future admitted")
	}
}

func TestObserveProgressIsNonceBoundWithoutResponseAuthority(t *testing.T) {
	key := bytes.Repeat([]byte{6}, 32)
	value := observeProgress{Schema: 1, Nonce: strings.Repeat("a", 64), PID: 42, Birth: "123", Counter: 1}
	var output bytes.Buffer
	if err := writeObserveProgress(&output, value, key); err != nil {
		t.Fatal(err)
	}
	var frame struct {
		Payload string `json:"payload"`
		MAC     string `json:"mac"`
	}
	if err := json.Unmarshal(output.Bytes(), &frame); err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("angerona-watchdog3-observe-v1\x00"))
	mac.Write([]byte(frame.Payload))
	if hex.EncodeToString(mac.Sum(nil)) != frame.MAC {
		t.Fatal("progress MAC differs")
	}
	var decoded observeProgress
	if err := json.Unmarshal([]byte(frame.Payload), &decoded); err != nil || decoded.RecoveryAvailable || decoded.Nonce != value.Nonce {
		t.Fatal("scope changed", err)
	}
}

func TestObserveRejectsArgumentsBeforeAnyRuntimeAdmission(t *testing.T) {
	var output bytes.Buffer
	if code := runObserveCommand([]string{"--service"}, &output, &output); code != 2 {
		t.Fatal(code)
	}
}
