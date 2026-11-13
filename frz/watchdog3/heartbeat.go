package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"unicode/utf8"
)

const (
	heartbeatSize           = 32
	heartbeatMagic   uint32 = 0x41574447
	heartbeatRunning uint32 = 1
	heartbeatV2      uint32 = 0x80000000
)

// This codec deliberately contains no process lookup or liveness judgement.
// A verified frame is evidence from one component, never stand-down authority.
type heartbeatRecord struct {
	TimestampNS uint64
	PID         uint32
	Counter     uint32
	Flags       uint32
}

func heartbeatProof(authority []byte, name string, record heartbeatRecord) ([]byte, error) {
	if len(authority) != 32 || len(name) == 0 || len(name) > 65535 || !utf8.ValidString(name) {
		return nil, errors.New("invalid heartbeat authority or component")
	}
	derive := hmac.New(sha256.New, authority)
	derive.Write([]byte("angerona-resilience-heartbeat-v2\x00"))
	derive.Write([]byte(name))
	mac := hmac.New(sha256.New, derive.Sum(nil))
	payload := make([]byte, 2+len(name)+20)
	binary.LittleEndian.PutUint16(payload[:2], uint16(len(name)))
	copy(payload[2:], name)
	offset := 2 + len(name)
	binary.LittleEndian.PutUint64(payload[offset:], record.TimestampNS)
	binary.LittleEndian.PutUint32(payload[offset+8:], record.PID)
	binary.LittleEndian.PutUint32(payload[offset+12:], record.Counter)
	binary.LittleEndian.PutUint32(payload[offset+16:], record.Flags)
	mac.Write(payload)
	return mac.Sum(nil)[:8], nil
}

func encodeHeartbeat(authority []byte, name string, record heartbeatRecord) ([]byte, error) {
	if record.PID == 0 || record.TimestampNS == 0 || record.Flags&heartbeatV2 == 0 || record.Flags&^(heartbeatRunning|heartbeatV2) != 0 {
		return nil, errors.New("invalid heartbeat fields")
	}
	proof, err := heartbeatProof(authority, name, record)
	if err != nil {
		return nil, err
	}
	raw := make([]byte, heartbeatSize)
	binary.LittleEndian.PutUint32(raw, heartbeatMagic)
	binary.LittleEndian.PutUint64(raw[4:], record.TimestampNS)
	binary.LittleEndian.PutUint32(raw[12:], record.PID)
	copy(raw[16:24], proof)
	binary.LittleEndian.PutUint32(raw[24:], record.Counter)
	binary.LittleEndian.PutUint32(raw[28:], record.Flags)
	return raw, nil
}

func decodeHeartbeat(authority []byte, name string, raw []byte) (heartbeatRecord, error) {
	var record heartbeatRecord
	if len(raw) != heartbeatSize || binary.LittleEndian.Uint32(raw) != heartbeatMagic {
		return record, errors.New("invalid heartbeat frame")
	}
	record = heartbeatRecord{binary.LittleEndian.Uint64(raw[4:]), binary.LittleEndian.Uint32(raw[12:]), binary.LittleEndian.Uint32(raw[24:]), binary.LittleEndian.Uint32(raw[28:])}
	if record.PID == 0 || record.TimestampNS == 0 || record.Flags&heartbeatV2 == 0 || record.Flags&^(heartbeatRunning|heartbeatV2) != 0 {
		return heartbeatRecord{}, errors.New("invalid heartbeat fields")
	}
	expected, err := heartbeatProof(authority, name, record)
	if err != nil || !hmac.Equal(expected, raw[16:24]) {
		return heartbeatRecord{}, errors.New("heartbeat authentication failed")
	}
	return record, nil
}

// Process creation identity and monotonic freshness are owned by the supervisor.
// The replay state must not be reset merely because a PID was re-used.
type heartbeatReplay struct {
	initialized bool
	last        heartbeatRecord
	birth       uint64
}

func (state *heartbeatReplay) accept(record heartbeatRecord) error {
	if state.initialized {
		last := state.last
		if record.TimestampNS < last.TimestampNS || (record.TimestampNS == last.TimestampNS && record.PID != last.PID) {
			return errors.New("heartbeat timestamp replay")
		}
		if record.PID == last.PID && record.Counter < last.Counter && !(last.Counter > 0xffff0000 && record.Counter < 0x0000ffff) {
			return errors.New("heartbeat counter replay")
		}
	}
	state.initialized, state.last = true, record
	return nil
}

// Only a caller holding the new native process generation after proving the old
// handle exited may use this. A new counter does not reset timestamp history.
func (state *heartbeatReplay) acceptBound(record heartbeatRecord, birth, birthNS uint64) error {
	if birth == 0 || record.TimestampNS < birthNS {
		return errors.New("heartbeat predates process generation")
	}
	if state.initialized && state.birth != 0 && birth != state.birth && record.PID == state.last.PID {
		if birth <= state.birth || record.TimestampNS <= state.last.TimestampNS {
			return errors.New("heartbeat generation replay")
		}
		state.last, state.birth = record, birth
		return nil
	}
	if err := state.accept(record); err != nil {
		return err
	}
	state.birth = birth
	return nil
}
