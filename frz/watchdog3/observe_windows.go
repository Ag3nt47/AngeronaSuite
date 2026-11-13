//go:build windows

package main

// Ordinary-user observation is separate from installed supervision. It accepts
// no authority or paths on its command line and performs no recovery actions.
import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const observeMaxInput = 8192
const observeDeadline = 10 * time.Second

type observeBootstrap struct {
	Schema           int    `json:"schema"`
	Nonce            string `json:"nonce"`
	MACKey           string `json:"mac_key"`
	CorePID          uint32 `json:"core_pid"`
	CoreBirth        string `json:"core_birth_ticks"`
	CoreImage        string `json:"core_image"`
	CoreHeartbeat    string `json:"core_heartbeat"`
	CoreHeartbeatKey string `json:"core_heartbeat_key"`
}

type observeProgress struct {
	Schema            int               `json:"schema"`
	Nonce             string            `json:"nonce"`
	PID               uint32            `json:"pid"`
	Birth             string            `json:"birth_ticks"`
	Image             string            `json:"executable_path"`
	Counter           uint64            `json:"counter"`
	CorePID           uint32            `json:"core_pid"`
	CoreBirth         string            `json:"core_birth_ticks"`
	CoreCounter       uint32            `json:"core_counter"`
	CoreState         string            `json:"core_state"`
	Signature         signingInspection `json:"signature"`
	RecoveryAvailable bool              `json:"recovery_available"`
}

func parseObserveBootstrap(raw []byte) (observeBootstrap, error) {
	var value observeBootstrap
	if len(raw) == 0 || len(raw) > observeMaxInput {
		return value, errors.New("observe bootstrap bound")
	}
	// Reject duplicate top-level fields rather than accepting last-value wins.
	closed := json.NewDecoder(bytes.NewReader(raw))
	token, err := closed.Token()
	if err != nil || token != json.Delim('{') {
		return value, errors.New("observe bootstrap object required")
	}
	seen := make(map[string]bool)
	for closed.More() {
		token, err := closed.Token()
		name, ok := token.(string)
		if err != nil || !ok || seen[name] {
			return value, errors.New("observe bootstrap repeats a field")
		}
		seen[name] = true
		var ignored json.RawMessage
		if err := closed.Decode(&ignored); err != nil {
			return value, errors.New("observe bootstrap value invalid")
		}
	}
	if token, err := closed.Token(); err != nil || token != json.Delim('}') {
		return value, errors.New("observe bootstrap object incomplete")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return value, errors.New("observe bootstrap malformed")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return value, errors.New("observe bootstrap has trailing data")
	}
	if value.Schema != 1 || value.CorePID == 0 || value.CorePID == uint32(os.Getpid()) {
		return value, errors.New("observe scope invalid")
	}
	for _, item := range []string{value.Nonce, value.MACKey, value.CoreHeartbeatKey} {
		decoded, err := hex.DecodeString(item)
		if err != nil || len(decoded) != 32 || strings.ToLower(item) != item {
			return value, errors.New("observe nonce or key invalid")
		}
	}
	birth, err := strconv.ParseUint(value.CoreBirth, 10, 64)
	if err != nil || birth == 0 || strconv.FormatUint(birth, 10) != value.CoreBirth {
		return value, errors.New("observe core birth invalid")
	}
	for _, path := range []string{value.CoreImage, value.CoreHeartbeat} {
		if _, err := localPath(path); err != nil {
			return value, errors.New("observe path invalid")
		}
	}
	return value, nil
}

// Unlike IsElevated's bool, this query never hides a failed token lookup.
func observeTokenIdentity(token windows.Token) (string, error) {
	var elevated uint32
	var size uint32
	if err := windows.GetTokenInformation(token, windows.TokenElevation, (*byte)(unsafe.Pointer(&elevated)), 4, &size); err != nil || size != 4 || elevated != 0 {
		return "", errors.New("observe requires a verified ordinary-user token")
	}
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return "", errors.New("observe token user unavailable")
	}
	sid := user.User.Sid.String()
	if sid == "" || sid == "S-1-5-18" || sid == "S-1-5-19" || sid == "S-1-5-20" {
		return "", errors.New("observe refuses service identities")
	}
	return sid, nil
}

func observeOrdinaryUser() (string, uint32, error) {
	if err := custodyReady(); err != nil {
		return "", 0, err
	}
	var impersonation windows.Token
	err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &impersonation)
	if err == nil {
		return "", 0, errors.Join(errors.New("observe refuses impersonation"), retireNative(windows.Handle(impersonation)))
	}
	if !errors.Is(err, windows.ERROR_NO_TOKEN) {
		return "", 0, errors.New("observe thread token unavailable")
	}
	sid, err := observeTokenIdentity(windows.GetCurrentProcessToken())
	if err != nil {
		return "", 0, err
	}
	var session uint32
	if err := windows.ProcessIdToSessionId(uint32(os.Getpid()), &session); err != nil || session == 0 {
		return "", 0, errors.New("observe requires an interactive user session")
	}
	return sid, session, nil
}

func observeImage(peer *peerHandle) (string, error) {
	buffer := make([]uint16, 32768)
	count := uint32(len(buffer))
	if err := windows.QueryFullProcessImageName(peer.handle, 0, &buffer[0], &count); err != nil || count == 0 || count >= uint32(len(buffer)) {
		return "", errors.New("observe process image unavailable")
	}
	path := windows.UTF16ToString(buffer[:count])
	return localPath(path)
}

func observeCoreScope(peer *peerHandle, request observeBootstrap, sid string, session uint32) error {
	birth, _ := strconv.ParseUint(request.CoreBirth, 10, 64)
	image, err := observeImage(peer)
	if err != nil || peer.BirthTicks != birth || !strings.EqualFold(image, request.CoreImage) {
		return errors.New("observe core generation or image mismatch")
	}
	var coreSession uint32
	if err := windows.ProcessIdToSessionId(peer.PID, &coreSession); err != nil || coreSession != session {
		return errors.New("observe core is outside this session")
	}
	var token windows.Token
	if err := windows.OpenProcessToken(peer.handle, windows.TOKEN_QUERY, &token); err != nil {
		return errors.New("observe core token unavailable")
	}
	actual, queryErr := observeTokenIdentity(token)
	closeErr := retireNative(windows.Handle(token))
	if queryErr != nil || actual != sid || closeErr != nil {
		return errors.Join(errors.New("observe core token differs or cleanup is held"), queryErr, closeErr)
	}
	return nil
}

func observeCoreHeartbeat(raw, key []byte, pid uint32, now time.Time) (uint32, error) {
	if len(raw) != 32 || len(key) != 32 || binary.LittleEndian.Uint32(raw[:4]) != 0x41574447 || binary.LittleEndian.Uint32(raw[12:16]) != pid {
		return 0, errors.New("observe core heartbeat invalid")
	}
	ts := binary.LittleEndian.Uint64(raw[4:12])
	counter := binary.LittleEndian.Uint32(raw[24:28])
	flags := binary.LittleEndian.Uint32(raw[28:32])
	if counter == 0 || flags&0x80000001 != 0x80000001 || flags & ^uint32(0x80000001) != 0 {
		return 0, errors.New("observe core heartbeat stopped or unsupported")
	}
	if ts > uint64(now.UnixNano()) || uint64(now.UnixNano())-ts > uint64(observeDeadline) {
		return 0, errors.New("observe core heartbeat is stale")
	}
	var body bytes.Buffer
	binary.Write(&body, binary.LittleEndian, uint16(4))
	body.WriteString("core")
	binary.Write(&body, binary.LittleEndian, ts)
	binary.Write(&body, binary.LittleEndian, pid)
	binary.Write(&body, binary.LittleEndian, counter)
	binary.Write(&body, binary.LittleEndian, flags)
	mac := hmac.New(sha256.New, key)
	mac.Write(body.Bytes())
	if !hmac.Equal(mac.Sum(nil)[:8], raw[16:24]) {
		return 0, errors.New("observe core heartbeat authentication failed")
	}
	return counter, nil
}

func writeObserveProgress(output io.Writer, value observeProgress, key []byte) error {
	payload, err := json.Marshal(value)
	if err != nil || len(payload) > observeMaxInput {
		return errors.New("observe progress bound")
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("angerona-watchdog3-observe-v1\x00"))
	mac.Write(payload)
	frame, err := json.Marshal(struct {
		Payload string `json:"payload"`
		MAC     string `json:"mac"`
	}{string(payload), hex.EncodeToString(mac.Sum(nil))})
	if err != nil {
		return err
	}
	frame = append(frame, '\n')
	written, err := output.Write(frame)
	if err != nil || written != len(frame) {
		return errors.New("observe progress pipe unavailable")
	}
	return nil
}

func runObserveCommand(arguments []string, stdout, stderr io.Writer) int {
	if len(arguments) != 0 {
		fmt.Fprintln(stderr, "observe accepts no command-line scope or authority")
		return 2
	}
	sid, session, err := observeOrdinaryUser()
	if err != nil {
		fmt.Fprintln(stderr, "ordinary-user observation is unavailable")
		return 1
	}
	reader := bufio.NewReaderSize(os.Stdin, observeMaxInput+1)
	line, err := reader.ReadSlice('\n')
	if err != nil {
		fmt.Fprintln(stderr, "observe bootstrap pipe unavailable")
		return 1
	}
	request, err := parseObserveBootstrap(line)
	if err != nil {
		fmt.Fprintln(stderr, "observe bootstrap rejected")
		return 1
	}
	core, err := openPeer(request.CorePID)
	if err != nil {
		fmt.Fprintln(stderr, "observe core unavailable")
		return 1
	}
	if err = observeCoreScope(core, request, sid, session); err != nil {
		_ = core.Close()
		return 1
	}
	self, err := openPeer(uint32(os.Getpid()))
	if err != nil {
		_ = core.Close()
		return 1
	}
	image, imageErr := observeImage(self)
	birth := self.BirthTicks
	closeErr := self.Close()
	if imageErr != nil || closeErr != nil {
		_ = core.Close()
		return 1
	}
	inspection, inspectErr := nativeInspectSigning(image)
	if inspectErr != nil {
		inspection.SignatureValid = false
	}
	macKey, _ := hex.DecodeString(request.MACKey)
	heartbeatKey, _ := hex.DecodeString(request.CoreHeartbeatKey)
	defer func() {
		for i := range macKey {
			macKey[i] = 0
		}
		for i := range heartbeatKey {
			heartbeatKey[i] = 0
		}
	}()
	progress := observeProgress{Schema: 1, Nonce: request.Nonce, PID: uint32(os.Getpid()), Birth: strconv.FormatUint(birth, 10), Image: image, CorePID: request.CorePID, CoreBirth: request.CoreBirth, Signature: inspection}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var previous uint32
	var lastAdvance time.Time
	result := 0
	for {
		present, presentErr := core.Present()
		progress.CoreState = "unavailable"
		if presentErr != nil {
			result = 1
			break
		}
		if !present {
			progress.CoreState = "exited"
		} else {
			raw, readErr := readCustodyFile(request.CoreHeartbeat, 32, false, false)
			if readErr == nil {
				counter, heartbeatErr := observeCoreHeartbeat(raw, heartbeatKey, request.CorePID, time.Now())
				if heartbeatErr == nil {
					if previous != 0 && counter > previous {
						lastAdvance = time.Now()
					}
					if counter < previous {
						result = 1
						break
					}
					previous = counter
					progress.CoreCounter = counter
					progress.CoreState = "pending"
					if !lastAdvance.IsZero() && time.Since(lastAdvance) <= observeDeadline {
						progress.CoreState = "verified"
					}
					if !lastAdvance.IsZero() && time.Since(lastAdvance) > observeDeadline {
						progress.CoreState = "stale"
					}
				}
			}
		}
		progress.Counter++
		if err := writeObserveProgress(stdout, progress, macKey); err != nil {
			result = 1
			break
		}
		if !present {
			break
		}
		<-ticker.C
	}
	if err := core.Close(); err != nil {
		return 1
	}
	if err := custodyReady(); err != nil {
		return 1
	}
	return result
}
