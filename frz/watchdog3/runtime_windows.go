//go:build windows

package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const maximumOutputBytes = 256 * 1024

var errAlreadyRunning = errors.New("watchdog instance already exists")
var errSpawnBusy = errors.New("peer spawn claim is busy")

// A close failure leaves custody unknown. Keep one bounded, sticky hold rather
// than retrying a possibly reused numeric handle or allocating on each tick.
var custodyMu sync.Mutex
var custodyHold error
var nativeClose = windows.CloseHandle
var fileClose = func(file *os.File) error { return file.Close() }

func custodyReady() error { custodyMu.Lock(); defer custodyMu.Unlock(); return custodyHold }
func holdCustody(err error) error {
	if err == nil {
		return nil
	}
	custodyMu.Lock()
	defer custodyMu.Unlock()
	if custodyHold == nil {
		custodyHold = errors.New("native resource retirement is unverified")
	}
	return errors.Join(err, custodyHold)
}
func retireNative(handle windows.Handle) error { return holdCustody(nativeClose(handle)) }
func retireFile(file *os.File) error           { return holdCustody(fileClose(file)) }
func retireParents(handles []windows.Handle) error {
	var result error
	for i := len(handles) - 1; i >= 0; i-- {
		result = errors.Join(result, retireNative(handles[i]))
	}
	return result
}

func programDataDirectory() (string, error) {
	return windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
}

func localPath(path string) (string, error) {
	if len(path) == 0 || len(path) > 32760 || !filepath.IsAbs(path) || strings.HasPrefix(path, `\\`) || strings.ContainsAny(path, "\x00*?\r\n") {
		return "", errors.New("path is not explicit local data")
	}
	volume := filepath.VolumeName(path)
	if len(volume) != 2 || volume[1] != ':' || ((volume[0] < 'A' || volume[0] > 'Z') && (volume[0] < 'a' || volume[0] > 'z')) {
		return "", errors.New("path is not on a local drive")
	}
	if filepath.Clean(path) != path {
		return "", errors.New("path is not canonical")
	}
	for _, part := range strings.Split(path[len(volume)+1:], `\`) {
		if part == "" {
			continue
		}
		if part == "." || part == ".." || strings.Contains(part, ":") || strings.HasSuffix(part, ".") || strings.HasSuffix(part, " ") {
			return "", errors.New("path contains an ambiguous component")
		}
		for _, ch := range part {
			if ch < 32 {
				return "", errors.New("path contains a control character")
			}
		}
		stem := strings.ToUpper(strings.SplitN(part, ".", 2)[0])
		if stem == "CON" || stem == "PRN" || stem == "AUX" || stem == "NUL" || (len(stem) == 4 && (strings.HasPrefix(stem, "COM") || strings.HasPrefix(stem, "LPT")) && stem[3] >= '1' && stem[3] <= '9') {
			return "", errors.New("path contains a device name")
		}
	}
	return path, nil
}

func currentSID() (string, error) {
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil {
		return "", err
	}
	return user.User.Sid.String(), nil
}

func privateAttributes() (*windows.SecurityAttributes, error) {
	sid, err := currentSID()
	if err != nil {
		return nil, err
	}
	sd, err := windows.SecurityDescriptorFromString("O:" + sid + "D:P(A;OICI;FA;;;" + sid + ")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		return nil, err
	}
	return &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}, nil
}

func checkCustody(handle windows.Handle, adminOnly, secret bool) error {
	sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return errors.New("file owner unavailable")
	}
	user, err := currentSID()
	if err != nil {
		return err
	}
	trusted := func(sid string) bool {
		return sid == "S-1-5-18" || sid == "S-1-5-32-544" || sid == "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464" || (!adminOnly && sid == user)
	}
	if !trusted(owner.String()) {
		return errors.New("file owner is outside custody")
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil || dacl.AceCount == 0 || dacl.AceCount > 64 {
		return errors.New("file ACL unavailable or unbounded")
	}
	const writeMask = uint32(0x0002 | 0x0004 | 0x0010 | 0x0040 | 0x0100 | 0x10000 | 0x40000 | 0x80000 | 0x10000000 | 0x40000000 | 0x02000000)
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil || ace == nil {
			return errors.New("file ACL entry unavailable")
		}
		if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return errors.New("file ACL entry type unsupported")
		}
		if ace.Header.AceSize < 20 {
			return errors.New("file ACL entry malformed")
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.IsValid() {
			return errors.New("file ACL identity malformed")
		}
		if !trusted(sid.String()) && (secret || uint32(ace.Mask)&writeMask != 0) {
			return errors.New("file ACL grants outside authority")
		}
	}
	return nil
}

type pathHold struct {
	file    *os.File
	parents []windows.Handle
	info    windows.ByHandleFileInformation
}

func (h *pathHold) Close() error {
	var result error
	if h.file != nil {
		file := h.file
		h.file = nil
		result = retireFile(file)
	}
	parents := h.parents
	h.parents = nil
	return errors.Join(result, retireParents(parents))
}

func fileInformation(handle windows.Handle, directory bool) (windows.ByHandleFileInformation, error) {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return info, err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return info, errors.New("redirected file object")
	}
	if (info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != directory {
		return info, errors.New("file object has wrong kind")
	}
	if !directory && info.NumberOfLinks != 1 {
		return info, errors.New("file object is not single-link data")
	}
	return info, nil
}

func openPlain(path string, access, sharing, disposition uint32, directory bool, attrs *windows.SecurityAttributes) (windows.Handle, error) {
	if err := custodyReady(); err != nil {
		return windows.InvalidHandle, err
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return windows.InvalidHandle, err
	}
	flags := uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT)
	if directory {
		flags |= windows.FILE_FLAG_BACKUP_SEMANTICS
	} else {
		flags |= windows.FILE_ATTRIBUTE_NORMAL
	}
	h, err := windows.CreateFile(p, access, sharing, attrs, disposition, flags, 0)
	if err != nil {
		return windows.InvalidHandle, err
	}
	if _, err := fileInformation(h, directory); err != nil {
		return windows.InvalidHandle, errors.Join(err, retireNative(h))
	}
	return h, nil
}

func holdParents(path string) ([]windows.Handle, error) {
	if _, err := localPath(path); err != nil {
		return nil, err
	}
	parent := filepath.Dir(path)
	parts := []string{}
	for {
		parts = append(parts, parent)
		next := filepath.Dir(parent)
		if next == parent {
			break
		}
		parent = next
	}
	held := []windows.Handle{}
	for i := len(parts) - 1; i >= 0; i-- {
		h, err := openPlain(parts[i], windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ, windows.OPEN_EXISTING, true, nil)
		if err != nil {
			return nil, errors.Join(err, retireParents(held))
		}
		held = append(held, h)
	}
	return held, nil
}

func openHeld(path string, access, sharing uint32, directory bool, adminOnly, secret bool) (*pathHold, error) {
	parents, err := holdParents(path)
	if err != nil {
		return nil, err
	}
	hold := &pathHold{parents: parents}
	h, err := openPlain(path, access|windows.READ_CONTROL, sharing, windows.OPEN_EXISTING, directory, nil)
	if err != nil {
		return nil, errors.Join(err, hold.Close())
	}
	hold.file = os.NewFile(uintptr(h), path)
	if err = checkCustody(h, adminOnly, secret); err != nil {
		return nil, errors.Join(err, hold.Close())
	}
	hold.info, err = fileInformation(h, directory)
	if err != nil {
		return nil, errors.Join(err, hold.Close())
	}
	return hold, nil
}

func readCustodyFile(path string, max int, adminOnly, secret bool) (result []byte, resultErr error) {
	if max <= 0 || max > maximumOutputBytes {
		return nil, errors.New("read bound is invalid")
	}
	hold, err := openHeld(path, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, false, adminOnly, secret)
	if err != nil {
		return nil, err
	}
	defer func() {
		resultErr = errors.Join(resultErr, hold.Close())
		if resultErr != nil {
			result = nil
		}
	}()
	size := uint64(hold.info.FileSizeHigh)<<32 | uint64(hold.info.FileSizeLow)
	if size > uint64(max) {
		return nil, errors.New("file exceeds byte bound")
	}
	raw, err := io.ReadAll(io.LimitReader(hold.file, int64(max)+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > max || uint64(len(raw)) != size {
		return nil, errors.New("file read is incomplete")
	}
	after, err := fileInformation(windows.Handle(hold.file.Fd()), false)
	if err != nil {
		return nil, err
	}
	if after.VolumeSerialNumber != hold.info.VolumeSerialNumber || after.FileIndexHigh != hold.info.FileIndexHigh || after.FileIndexLow != hold.info.FileIndexLow || after.FileSizeHigh != hold.info.FileSizeHigh || after.FileSizeLow != hold.info.FileSizeLow {
		return nil, errors.New("file identity changed")
	}
	if err := checkCustody(windows.Handle(hold.file.Fd()), adminOnly, secret); err != nil {
		return nil, err
	}
	return raw, nil
}
func readPrivateFile(path string, max int) ([]byte, error) {
	return readCustodyFile(path, max, false, true)
}
func readAdminFile(path string, max int) ([]byte, error) {
	return readCustodyFile(path, max, true, false)
}

func checkAdminDirectory(path string) error {
	h, err := openHeld(path, windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ, true, true, false)
	if err != nil {
		return err
	}
	return h.Close()
}
func checkPrivateDirectory(path string) error {
	h, err := openHeld(path, windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ, true, false, true)
	if err != nil {
		return err
	}
	return h.Close()
}

// These supported OS policies reduce optional DLL injection paths; they do not
// prevent the owner or administrator from closing or terminating the watchdog.
func hardenSelf() error {
	setter := windows.NewLazySystemDLL("kernel32.dll").NewProc("SetProcessMitigationPolicy")
	if err := setter.Find(); err != nil {
		return err
	}
	value := uint32(1)
	var result error
	for _, policy := range []uintptr{6, 8} {
		ok, _, callErr := setter.Call(policy, uintptr(unsafe.Pointer(&value)), unsafe.Sizeof(value))
		if ok == 0 {
			result = errors.Join(result, callErr)
		}
	}
	return result
}

func ensurePrivateDirectory(path string) (resultErr error) {
	parents, err := holdParents(path)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, retireParents(parents)) }()
	attrs, err := privateAttributes()
	if err != nil {
		return err
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	if err = windows.CreateDirectory(p, attrs); err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return err
	}
	h, err := openPlain(path, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, windows.OPEN_EXISTING, true, nil)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, retireNative(h)) }()
	return checkCustody(h, false, true)
}

func checkPrivateParent(path string) error {
	h, err := openHeld(filepath.Dir(path), windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, true, false, true)
	if err != nil {
		return err
	}
	return h.Close()
}

func checkHeldPrivateParent(parents []windows.Handle) error {
	if len(parents) == 0 {
		return errors.New("private parent custody unavailable")
	}
	return checkCustody(parents[len(parents)-1], false, true)
}

func renameHeld(handle windows.Handle, path string, replace bool) error {
	name, err := windows.UTF16FromString(path)
	if err != nil {
		return err
	}
	name = name[:len(name)-1]
	// FILE_RENAME_INFO: BOOLEAN/flags32, aligned HANDLE, DWORD byte length,
	// UTF16 name. The retained source object is renamed without reopening it.
	offset := int(unsafe.Sizeof(uintptr(0)))
	if offset == 8 {
		offset = 8
	} else {
		offset = 4
	}
	lengthOffset := offset + int(unsafe.Sizeof(uintptr(0)))
	nameOffset := lengthOffset + 4
	buffer := make([]byte, nameOffset+2*len(name))
	if replace {
		binary.LittleEndian.PutUint32(buffer, 1)
	}
	binary.LittleEndian.PutUint32(buffer[lengthOffset:], uint32(2*len(name)))
	for i, ch := range name {
		binary.LittleEndian.PutUint16(buffer[nameOffset+i*2:], ch)
	}
	return windows.SetFileInformationByHandle(handle, windows.FileRenameInfo, &buffer[0], uint32(len(buffer)))
}

func deleteHeld(handle windows.Handle) error {
	value := byte(1)
	return windows.SetFileInformationByHandle(handle, windows.FileDispositionInfo, &value, 1)
}

func writePrivateFile(path string, raw []byte) (resultErr error) {
	if len(raw) > maximumOutputBytes {
		return errors.New("output exceeds byte bound")
	}
	if err := checkPrivateParent(path); err != nil {
		return err
	}
	parents, err := holdParents(path)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, retireParents(parents)) }()
	if err := checkHeldPrivateParent(parents); err != nil {
		return err
	}
	if old, err := openHeld(path, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, false, false, true); err == nil {
		if err := old.Close(); err != nil {
			return err
		}
	} else if !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	temporary := filepath.Join(filepath.Dir(path), ".watchdog3-"+hex.EncodeToString(nonce[:])+".tmp")
	attrs, err := privateAttributes()
	if err != nil {
		return err
	}
	h, err := openPlain(temporary, windows.GENERIC_WRITE|windows.READ_CONTROL|windows.DELETE, windows.FILE_SHARE_READ, windows.CREATE_NEW, false, attrs)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(h), temporary)
	published := false
	defer func() {
		if !published {
			resultErr = errors.Join(resultErr, holdCustody(deleteHeld(h)))
		}
		resultErr = errors.Join(resultErr, retireFile(f))
	}()
	if err := checkCustody(h, false, true); err != nil {
		return err
	}
	if _, err := f.Write(raw); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := renameHeld(h, path, true); err != nil {
		return err
	}
	published = true
	return nil
}

func appendPrivateFile(path string, raw []byte, max int) (resultErr error) {
	if max <= 0 || max > maximumOutputBytes || len(raw) > 4096 {
		return errors.New("append bound is invalid")
	}
	if err := checkPrivateParent(path); err != nil {
		return err
	}
	parents, err := holdParents(path)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, retireParents(parents)) }()
	if err := checkHeldPrivateParent(parents); err != nil {
		return err
	}
	attrs, err := privateAttributes()
	if err != nil {
		return err
	}
	h, err := openPlain(path, windows.GENERIC_READ|windows.GENERIC_WRITE|windows.READ_CONTROL, windows.FILE_SHARE_READ, windows.OPEN_ALWAYS, false, attrs)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(h), path)
	defer func() { resultErr = errors.Join(resultErr, retireFile(f)) }()
	if err := checkCustody(h, false, true); err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if info.Size()+int64(len(raw)) > int64(max) {
		return errors.New("append file is full")
	}
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		return err
	}
	if _, err := f.Write(raw); err != nil {
		return err
	}
	return f.Sync()
}

type peerHandle struct {
	handle     windows.Handle
	thread     windows.Handle
	PID        uint32
	BirthTicks uint64
}

func openPeer(pid uint32) (*peerHandle, error) {
	if err := custodyReady(); err != nil {
		return nil, err
	}
	if pid == 0 {
		return nil, errors.New("peer PID is invalid")
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, pid)
	if errors.Is(err, windows.ERROR_INVALID_PARAMETER) || errors.Is(err, windows.ERROR_NOT_FOUND) {
		return nil, os.ErrNotExist
	}
	if err != nil {
		return nil, err
	}
	var birth, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &birth, &exit, &kernel, &user); err != nil {
		return nil, errors.Join(err, retireNative(h))
	}
	p := &peerHandle{handle: h, PID: pid, BirthTicks: uint64(birth.HighDateTime)<<32 | uint64(birth.LowDateTime)}
	if present, err := p.Present(); err != nil || !present {
		closeErr := p.Close()
		if closeErr != nil {
			return nil, errors.Join(err, closeErr)
		}
		if err != nil {
			return nil, err
		}
		return nil, os.ErrNotExist
	}
	return p, nil
}
func (p *peerHandle) Present() (bool, error) {
	if p == nil || p.handle == 0 {
		return false, errors.New("peer handle is unavailable")
	}
	state, err := windows.WaitForSingleObject(p.handle, 0)
	if err != nil {
		return false, err
	}
	if state == uint32(windows.WAIT_TIMEOUT) {
		return true, nil
	}
	if state == windows.WAIT_OBJECT_0 {
		return false, nil
	}
	return false, errors.New("peer wait result is unknown")
}
func (p *peerHandle) Close() error {
	if p == nil || p.handle == 0 {
		return nil
	}
	h := p.handle
	p.handle = 0
	thread := p.thread
	p.thread = 0
	var threadErr error
	if thread != 0 {
		threadErr = retireNative(thread)
	}
	return errors.Join(threadErr, retireNative(h))
}

type closeGroup struct {
	handles     []windows.Handle
	files       []*os.File
	deleteFiles bool
	once        sync.Once
	err         error
}

func (g *closeGroup) Close() error {
	g.once.Do(func() {
		for i := len(g.files) - 1; i >= 0; i-- {
			if g.deleteFiles {
				g.err = errors.Join(g.err, holdCustody(deleteHeld(windows.Handle(g.files[i].Fd()))))
			}
			g.err = errors.Join(g.err, retireFile(g.files[i]))
		}
		g.err = errors.Join(g.err, retireParents(g.handles))
		g.files = nil
		g.handles = nil
	})
	return g.err
}
func (g *closeGroup) failed(err error) (io.Closer, error) { return nil, errors.Join(err, g.Close()) }
func acquireInstance(dataRoot string) (io.Closer, error) {
	if err := custodyReady(); err != nil {
		return nil, err
	}
	if _, err := localPath(dataRoot); err != nil {
		return nil, err
	}
	attrs, err := privateAttributes()
	if err != nil {
		return nil, err
	}
	sid, err := currentSID()
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(strings.ToLower(dataRoot) + "\x00" + sid))
	name, _ := windows.UTF16PtrFromString(`Local\Angerona.Watchdog3.` + hex.EncodeToString(digest[:16]))
	mutex, err := windows.CreateMutex(attrs, false, name)
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		if mutex != 0 {
			if closeErr := retireNative(mutex); closeErr != nil {
				return nil, closeErr
			}
		}
		return nil, errAlreadyRunning
	}
	if err != nil {
		return nil, err
	}
	group := &closeGroup{handles: []windows.Handle{mutex}}
	path := filepath.Join(dataRoot, "ipc", "watchdog3.lock")
	parents, err := holdParents(path)
	if err != nil {
		return group.failed(err)
	}
	group.handles = append(group.handles, parents...)
	if err := checkHeldPrivateParent(parents); err != nil {
		return group.failed(err)
	}
	h, err := openPlain(path, windows.GENERIC_READ|windows.GENERIC_WRITE|windows.READ_CONTROL, 0, windows.OPEN_ALWAYS, false, attrs)
	if err != nil {
		if errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
			return group.failed(errAlreadyRunning)
		}
		return group.failed(err)
	}
	f := os.NewFile(uintptr(h), path)
	group.files = append(group.files, f)
	if err := checkCustody(h, false, true); err != nil {
		return group.failed(err)
	}
	return group, nil
}

func staleSpawnClaim(path string) (resultErr error) {
	hold, err := openHeld(path, windows.GENERIC_READ|windows.DELETE, windows.FILE_SHARE_READ, false, false, true)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, hold.Close()) }()
	info, err := hold.file.Stat()
	if err != nil {
		return err
	}
	if time.Since(info.ModTime()) < 15*time.Second {
		return errSpawnBusy
	}
	raw, err := io.ReadAll(io.LimitReader(hold.file, 129))
	if err != nil || len(raw) > 128 {
		return errSpawnBusy
	}
	parts := strings.Fields(string(raw))
	if len(parts) != 2 {
		return errSpawnBusy
	}
	pid, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil || pid == 0 {
		return errSpawnBusy
	}
	stamp, err := strconv.ParseFloat(parts[1], 64)
	if err != nil || math.IsNaN(stamp) || math.IsInf(stamp, 0) || stamp <= 0 || float64(time.Now().UnixNano())/1e9-stamp < 15 {
		return errSpawnBusy
	}
	process, err := openPeer(uint32(pid))
	if err == nil {
		defer func() { resultErr = errors.Join(resultErr, process.Close()) }()
		present, presenceErr := process.Present()
		if presenceErr != nil {
			return errSpawnBusy
		}
		created := uint64(hold.info.CreationTime.HighDateTime)<<32 | uint64(hold.info.CreationTime.LowDateTime)
		if present && process.BirthTicks <= created {
			return errSpawnBusy
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.Join(errSpawnBusy, err)
	}
	// Retained DELETE custody retires this exact stale object, not a raced name.
	return deleteHeld(windows.Handle(hold.file.Fd()))
}
func claimSpawnLocks(dataRoot string) (io.Closer, error) {
	return claimNamedSpawnLocks(dataRoot, []string{"core", "watchdog"})
}

func claimServiceSpawnLock(dataRoot string) (io.Closer, error) {
	return claimNamedSpawnLocks(dataRoot, []string{"service"})
}

func claimNamedSpawnLocks(dataRoot string, names []string) (io.Closer, error) {
	if err := custodyReady(); err != nil {
		return nil, err
	}
	group := &closeGroup{deleteFiles: true}
	attrs, err := privateAttributes()
	if err != nil {
		return nil, err
	}
	for _, name := range names {
		path := filepath.Join(dataRoot, "ipc", name+".spawnlock")
		if err := checkPrivateParent(path); err != nil {
			return group.failed(err)
		}
		parents, err := holdParents(path)
		if err != nil {
			return group.failed(err)
		}
		group.handles = append(group.handles, parents...)
		if err := checkHeldPrivateParent(parents); err != nil {
			return group.failed(err)
		}
		h, err := openPlain(path, windows.GENERIC_READ|windows.GENERIC_WRITE|windows.READ_CONTROL|windows.DELETE, windows.FILE_SHARE_READ, windows.CREATE_NEW, false, attrs)
		if errors.Is(err, windows.ERROR_FILE_EXISTS) || errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			if staleErr := staleSpawnClaim(path); staleErr != nil {
				return group.failed(errors.Join(errSpawnBusy, staleErr))
			}
			h, err = openPlain(path, windows.GENERIC_READ|windows.GENERIC_WRITE|windows.READ_CONTROL|windows.DELETE, windows.FILE_SHARE_READ, windows.CREATE_NEW, false, attrs)
		}
		if err != nil {
			return group.failed(errors.Join(errSpawnBusy, err))
		}
		f := os.NewFile(uintptr(h), path)
		group.files = append(group.files, f)
		if err := checkCustody(h, false, true); err != nil {
			return group.failed(err)
		}
		if _, err := fmt.Fprintf(f, "%d %.9f", os.Getpid(), float64(time.Now().UnixNano())/1e9); err != nil {
			return group.failed(err)
		}
		if err := f.Sync(); err != nil {
			return group.failed(err)
		}
	}
	return group, nil
}

func sanitizedLaunchEnvironment(dataRoot, pressure string) ([]string, error) {
	if _, err := localPath(dataRoot); err != nil {
		return nil, err
	}
	root, err := windows.GetWindowsDirectory()
	if err != nil {
		return nil, err
	}
	temporary := filepath.Join(dataRoot, "tmp")
	if err := ensurePrivateDirectory(temporary); err != nil {
		return nil, err
	}
	values := map[string]string{"SystemRoot": root, "WINDIR": root, "PATH": filepath.Join(root, "System32"), "TEMP": temporary, "TMP": temporary, "ANGERONA_DATA": dataRoot, "ANGERONA_SUPERVISED_RECOVERY": "1"}
	for key, folder := range map[string]*windows.KNOWNFOLDERID{"USERPROFILE": windows.FOLDERID_Profile, "APPDATA": windows.FOLDERID_RoamingAppData, "LOCALAPPDATA": windows.FOLDERID_LocalAppData} {
		value, err := windows.KnownFolderPath(folder, 0)
		if err != nil {
			return nil, err
		}
		values[key] = value
	}
	if pressure != "" {
		if pressure != "elevated" && pressure != "attack" {
			return nil, errors.New("restart pressure is outside closed values")
		}
		values["ANGERONA_RECOVERY_PRESSURE"] = pressure
	}
	env := make([]string, 0, len(values))
	for key, value := range values {
		if strings.ContainsRune(value, 0) {
			return nil, errors.New("native environment value is invalid")
		}
		env = append(env, key+"="+value)
	}
	sort.Slice(env, func(i, j int) bool { return strings.ToUpper(env[i]) < strings.ToUpper(env[j]) })
	return env, nil
}

func launchPinned(path, digest string, args []string, dataRoot, cwd, pressure string, finalGate func() error) (uint32, error) {
	p, err := launchPinnedRetained(path, digest, args, dataRoot, cwd, pressure, finalGate)
	if p == nil {
		return 0, err
	}
	pid := p.PID
	return pid, errors.Join(err, p.Close())
}

func launchPinnedRetained(path, digest string, args []string, dataRoot, cwd, pressure string, finalGate func() error) (result *peerHandle, resultErr error) {
	if _, err := localPath(path); err != nil {
		return nil, err
	}
	if !strings.EqualFold(filepath.Ext(path), ".exe") || filepath.Dir(path) != cwd {
		return nil, errors.New("launcher is not a fixed native image")
	}
	if len(args) != 1 || args[0] != "--chill" {
		return nil, errors.New("launcher arguments are not fixed recovery mode")
	}
	expected, err := hex.DecodeString(digest)
	if err != nil || len(expected) != 32 || strings.ToLower(digest) != digest {
		return nil, errors.New("launcher digest is malformed")
	}
	hold, err := openHeld(path, windows.GENERIC_READ, windows.FILE_SHARE_READ, false, true, false)
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, hold.Close()) }()
	return startPinnedImage(hold, digest, args, dataRoot, cwd, pressure, finalGate)
}

// startPinnedImage consumes already-proven file custody. The production entry
// above always supplies an administrator-controlled image; inert native tests
// can exercise the same launch machinery using their private fixture image.
func startPinnedImage(hold *pathHold, digest string, args []string, dataRoot, cwd, pressure string, finalGate func() error) (*peerHandle, error) {
	if err := validateHeldImage(hold, digest, args, cwd); err != nil {
		return nil, err
	}
	path := hold.file.Name()
	return createPinnedProcess(path, args, dataRoot, cwd, pressure, finalGate)
}

func validatePinnedLauncher(path, digest string, args []string, cwd string) (resultErr error) {
	if _, err := localPath(path); err != nil {
		return err
	}
	if !strings.EqualFold(filepath.Ext(path), ".exe") {
		return errors.New("launcher is not a native image")
	}
	hold, err := openHeld(path, windows.GENERIC_READ, windows.FILE_SHARE_READ, false, true, false)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, hold.Close()) }()
	return validateHeldImage(hold, digest, args, cwd)
}

func validateHeldImage(hold *pathHold, digest string, args []string, cwd string) error {
	if len(args) != 1 || args[0] != "--chill" {
		return errors.New("launcher contract changed")
	}
	return validateHeldExecutable(hold, digest, cwd)
}

func validateHeldExecutable(hold *pathHold, digest, cwd string) error {
	if hold == nil || hold.file == nil {
		return errors.New("image custody unavailable")
	}
	path := hold.file.Name()
	if filepath.Dir(path) != cwd {
		return errors.New("launcher contract changed")
	}
	expected, err := hex.DecodeString(digest)
	if err != nil || len(expected) != 32 || strings.ToLower(digest) != digest {
		return errors.New("launcher digest is malformed")
	}
	size := uint64(hold.info.FileSizeHigh)<<32 | uint64(hold.info.FileSizeLow)
	if size < 2 || size > 1<<30 {
		return errors.New("launcher size exceeds its bound")
	}
	if _, err := hold.file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	head := make([]byte, 2)
	if _, err := io.ReadFull(hold.file, head); err != nil || string(head) != "MZ" {
		return errors.New("launcher is not a PE image")
	}
	if _, err := hold.file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	hasher := sha256.New()
	n, err := io.CopyBuffer(hasher, io.LimitReader(hold.file, 1<<30+1), make([]byte, 1<<20))
	if err != nil || uint64(n) != size || subtle.ConstantTimeCompare(hasher.Sum(nil), expected) != 1 {
		return errors.New("launcher digest does not match install pin")
	}
	if _, err := fileInformation(windows.Handle(hold.file.Fd()), false); err != nil {
		return err
	}
	return nil
}

func createPinnedProcess(path string, args []string, dataRoot, cwd, pressure string, finalGate func() error) (*peerHandle, error) {
	environment, err := sanitizedLaunchEnvironment(dataRoot, pressure)
	if err != nil {
		return nil, err
	}
	// Build the closed environment block directly; no inherited entries cross.
	encoded := []uint16{}
	for _, entry := range environment {
		part, e := windows.UTF16FromString(entry)
		if e != nil {
			return nil, e
		}
		encoded = append(encoded, part...)
	}
	encoded = append(encoded, 0)
	application, _ := windows.UTF16PtrFromString(path)
	command, _ := windows.UTF16FromString(windows.ComposeCommandLine(append([]string{path}, args...)))
	directory, err := windows.UTF16PtrFromString(cwd)
	if err != nil {
		return nil, err
	}
	startup := windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfo{}))}
	var process windows.ProcessInformation
	if finalGate == nil {
		return nil, errors.New("final STOP and peer gate unavailable")
	}
	if err := finalGate(); err != nil {
		return nil, err
	}
	if err := custodyReady(); err != nil {
		return nil, err
	}
	if err := windows.CreateProcess(application, &command[0], nil, nil, false, windows.CREATE_UNICODE_ENVIRONMENT|windows.CREATE_NEW_PROCESS_GROUP|windows.CREATE_NO_WINDOW, &encoded[0], directory, &startup, &process); err != nil {
		return nil, err
	}
	// Transfer the actual created process generation, never reopen its PID.
	// Retention observes only; no termination right is used by this supervisor.
	retained := &peerHandle{handle: process.Process, thread: process.Thread, PID: process.ProcessId}
	var birth, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(process.Process, &birth, &exit, &kernel, &user); err != nil {
		return retained, err
	}
	retained.BirthTicks = uint64(birth.HighDateTime)<<32 | uint64(birth.LowDateTime)
	return retained, nil
}
