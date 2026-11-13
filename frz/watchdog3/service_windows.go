//go:build windows

package main

import (
	"errors"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const protectionServiceName = "AngeronaProtection"
const protectionServiceAccount = `NT SERVICE\AngeronaProtection`
const maximumServiceConfig = 32 * 1024

type serviceRegistration struct {
	Command, Account string
	Type, SIDType    uint32
}
type serviceStatus struct{ State, PID, Type, Win32ExitCode, ServiceExitCode uint32 }
type serviceProcess interface {
	ID() uint32
	Birth() uint64
	Present() (bool, error)
	Close() error
}

// The injection boundary supplies native SCM operations in production and inert
// records/handles in tests. There is no CLI-selected name, account or service.
type scmOperations struct {
	OpenManager  func() (windows.Handle, error)
	OpenService  func(windows.Handle, uint32) (windows.Handle, error)
	Registration func(windows.Handle) (serviceRegistration, error)
	Status       func(windows.Handle) (serviceStatus, error)
	Custody      func(windows.Handle) error
	Start        func(windows.Handle) error
	Close        func(windows.Handle) error
	Pin          func(configuration) (io.Closer, error)
	Process      func(uint32) (serviceProcess, error)
	Image        func(serviceProcess) (string, error)
	Now          func() time.Time
}

func (p *peerHandle) ID() uint32    { return p.PID }
func (p *peerHandle) Birth() uint64 { return p.BirthTicks }

func nativeSCMOperations() scmOperations {
	return scmOperations{
		OpenManager: func() (windows.Handle, error) { return windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT) },
		OpenService: func(manager windows.Handle, access uint32) (windows.Handle, error) {
			name, _ := windows.UTF16PtrFromString(protectionServiceName)
			return windows.OpenService(manager, name, access)
		},
		Registration: nativeServiceRegistration, Status: nativeServiceStatus, Custody: checkServiceCustody,
		Start: func(service windows.Handle) error { return windows.StartService(service, 0, nil) },
		Close: windows.CloseServiceHandle, Pin: pinServiceImage,
		Process: func(pid uint32) (serviceProcess, error) { return openPeer(pid) },
		Image: func(process serviceProcess) (string, error) {
			peer, ok := process.(*peerHandle)
			if !ok || peer.handle == 0 {
				return "", errors.New("native service process custody unavailable")
			}
			buffer := make([]uint16, 32768)
			size := uint32(len(buffer))
			if err := windows.QueryFullProcessImageName(peer.handle, 0, &buffer[0], &size); err != nil {
				return "", err
			}
			if size == 0 || size >= uint32(len(buffer)) {
				return "", errors.New("native service image path unavailable")
			}
			return windows.UTF16ToString(buffer[:size]), nil
		},
		Now: time.Now,
	}
}

func serviceStateName(state uint32) string {
	switch state {
	case windows.SERVICE_STOPPED:
		return "stopped"
	case windows.SERVICE_START_PENDING:
		return "start_pending"
	case windows.SERVICE_STOP_PENDING:
		return "stop_pending"
	case windows.SERVICE_RUNNING:
		return "running"
	case windows.SERVICE_CONTINUE_PENDING:
		return "continue_pending"
	case windows.SERVICE_PAUSE_PENDING:
		return "pause_pending"
	case windows.SERVICE_PAUSED:
		return "paused"
	}
	return "unknown"
}

func boundedServiceString(pointer *uint16, buffer []byte) (string, error) {
	if pointer == nil || len(buffer) < 2 {
		return "", errors.New("service string unavailable")
	}
	base := uintptr(unsafe.Pointer(&buffer[0]))
	address := uintptr(unsafe.Pointer(pointer))
	end := base + uintptr(len(buffer))
	if address < base || address >= end || address%2 != 0 {
		return "", errors.New("service string lies outside response")
	}
	count := int((end - address) / 2)
	chars := unsafe.Slice(pointer, count)
	for i, value := range chars {
		if value == 0 {
			return windows.UTF16ToString(chars[:i]), nil
		}
	}
	return "", errors.New("service string exceeds response bound")
}

func nativeServiceRegistration(service windows.Handle) (serviceRegistration, error) {
	var result serviceRegistration
	var needed uint32
	err := windows.QueryServiceConfig(service, nil, 0, &needed)
	if !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) || needed < uint32(unsafe.Sizeof(windows.QUERY_SERVICE_CONFIG{})) || needed > maximumServiceConfig {
		return result, errors.New("service configuration bound unavailable")
	}
	buffer := make([]byte, needed)
	config := (*windows.QUERY_SERVICE_CONFIG)(unsafe.Pointer(&buffer[0]))
	if err := windows.QueryServiceConfig(service, config, uint32(len(buffer)), &needed); err != nil {
		return result, err
	}
	if needed > uint32(len(buffer)) {
		return result, errors.New("service configuration changed size")
	}
	command, err := boundedServiceString(config.BinaryPathName, buffer)
	if err != nil {
		return result, err
	}
	account, err := boundedServiceString(config.ServiceStartName, buffer)
	if err != nil {
		return result, err
	}
	var sidType uint32
	if err := windows.QueryServiceConfig2(service, windows.SERVICE_CONFIG_SERVICE_SID_INFO, (*byte)(unsafe.Pointer(&sidType)), uint32(unsafe.Sizeof(sidType)), &needed); err != nil {
		return result, err
	}
	if needed > uint32(unsafe.Sizeof(sidType)) {
		return result, errors.New("service SID response exceeds bound")
	}
	return serviceRegistration{Command: command, Account: account, Type: config.ServiceType, SIDType: sidType}, nil
}

func nativeServiceStatus(service windows.Handle) (serviceStatus, error) {
	var status windows.SERVICE_STATUS_PROCESS
	var needed uint32
	if err := windows.QueryServiceStatusEx(service, windows.SC_STATUS_PROCESS_INFO, (*byte)(unsafe.Pointer(&status)), uint32(unsafe.Sizeof(status)), &needed); err != nil {
		return serviceStatus{}, err
	}
	if needed > uint32(unsafe.Sizeof(status)) {
		return serviceStatus{}, errors.New("service status exceeds bound")
	}
	return serviceStatus{State: status.CurrentState, PID: status.ProcessId, Type: status.ServiceType, Win32ExitCode: status.Win32ExitCode, ServiceExitCode: status.ServiceSpecificExitCode}, nil
}

func checkServiceCustody(service windows.Handle) error {
	sd, err := windows.GetSecurityInfo(service, windows.SE_SERVICE, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return errors.New("service owner unavailable")
	}
	trusted := func(sid string) bool {
		return sid == "S-1-5-18" || sid == "S-1-5-32-544" || sid == "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
	}
	if !trusted(owner.String()) {
		return errors.New("service owner lies outside installed authority")
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil || dacl.AceCount == 0 || dacl.AceCount > 64 {
		return errors.New("service DACL unavailable")
	}
	const outsideAllowed = uint32(0x8012008d)
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil || ace == nil {
			return errors.New("service DACL entry unavailable")
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 || ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceSize < 20 {
			return errors.New("service DACL entry unsupported")
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.IsValid() {
			return errors.New("service DACL identity malformed")
		}
		if !trusted(sid.String()) && uint32(ace.Mask)&^outsideAllowed != 0 {
			return errors.New("service grants authority outside installed writers")
		}
	}
	return nil
}

func serviceConfigurationContract(config configuration) error {
	if config.Schema != 2 || len(config.LauncherArgs) != 1 || config.LauncherArgs[0] != "--engine-service" || !strings.EqualFold(filepath.Base(config.LauncherPath), "Angerona.exe") || !strings.EqualFold(filepath.Dir(config.LauncherPath), config.WorkingDirectory) {
		return errors.New("installed service contract is not closed")
	}
	for _, path := range []string{config.DataDir, config.LauncherPath, config.WorkingDirectory} {
		if _, err := localPath(path); err != nil {
			return err
		}
	}
	if len(config.LauncherSHA256) != 64 || strings.Trim(config.LauncherSHA256, "0123456789abcdef") != "" {
		return errors.New("installed service pin is malformed")
	}
	return nil
}

func pinServiceImage(config configuration) (io.Closer, error) {
	hold, err := openHeld(config.LauncherPath, windows.GENERIC_READ, windows.FILE_SHARE_READ, false, true, false)
	if err != nil {
		return nil, err
	}
	if err := validateHeldExecutable(hold, config.LauncherSHA256, config.WorkingDirectory); err != nil {
		return nil, errors.Join(err, hold.Close())
	}
	return hold, nil
}

type serviceRef struct {
	config           configuration
	ops              scmOperations
	manager, service windows.Handle
	process          serviceProcess
	pendingUntil     time.Time
	observedActive   bool
	closed           bool
	closeOnce        sync.Once
	closeErr         error
}

func openServiceRef(config configuration, ops scmOperations, start bool) (*serviceRef, error) {
	if err := custodyReady(); err != nil {
		return nil, err
	}
	if err := serviceConfigurationContract(config); err != nil {
		return nil, err
	}
	if ops.OpenManager == nil || ops.OpenService == nil || ops.Registration == nil || ops.Status == nil || ops.Custody == nil || ops.Start == nil || ops.Close == nil || ops.Pin == nil || ops.Process == nil || ops.Image == nil || ops.Now == nil {
		return nil, errors.New("native SCM dependencies unavailable")
	}
	manager, err := ops.OpenManager()
	if err != nil {
		return nil, err
	}
	ref := &serviceRef{config: config, ops: ops, manager: manager}
	access := uint32(windows.SERVICE_QUERY_CONFIG | windows.SERVICE_QUERY_STATUS | windows.READ_CONTROL)
	if start {
		access |= windows.SERVICE_START
	}
	ref.service, err = ops.OpenService(manager, access)
	if err != nil {
		return nil, errors.Join(err, ref.Close())
	}
	if err := ref.registration(); err != nil {
		return nil, errors.Join(err, ref.Close())
	}
	return ref, nil
}

func (s *serviceRef) registration() error {
	if s.closed {
		return errors.New("service reference is retired")
	}
	if err := s.ops.Custody(s.service); err != nil {
		return err
	}
	registration, err := s.ops.Registration(s.service)
	if err != nil {
		return err
	}
	if registration.Type != windows.SERVICE_WIN32_OWN_PROCESS || registration.SIDType != windows.SERVICE_SID_TYPE_RESTRICTED || !strings.EqualFold(registration.Account, protectionServiceAccount) {
		return errors.New("service type, virtual account or restricted SID policy differs")
	}
	if len(registration.Command) == 0 || len(registration.Command) > maximumServiceConfig || strings.ContainsAny(registration.Command, "\x00\r\n") {
		return errors.New("service command exceeds closed bounds")
	}
	arguments, err := windows.DecomposeCommandLine(registration.Command)
	if err != nil || len(arguments) != 2 || !strings.EqualFold(arguments[0], s.config.LauncherPath) || arguments[1] != "--engine-service" {
		return errors.New("service command does not match installed image and fixed entry")
	}
	if _, err := localPath(arguments[0]); err != nil {
		return err
	}
	return nil
}

func (s *serviceRef) snapshot() (serviceObservation, error) {
	result := serviceObservation{State: "unknown"}
	if err := s.registration(); err != nil {
		return result, err
	}
	status, err := s.ops.Status(s.service)
	if err != nil {
		return result, err
	}
	result.State = serviceStateName(status.State)
	result.Win32ExitCode = status.Win32ExitCode
	result.ServiceExitCode = status.ServiceExitCode
	if status.Type != windows.SERVICE_WIN32_OWN_PROCESS || result.State == "unknown" {
		result.IdentityUnknown = true
		return result, errors.New("service status type or state is unknown")
	}
	if s.process != nil {
		present, err := s.process.Present()
		if err != nil {
			result.IdentityUnknown = true
			return result, err
		}
		if !present {
			process := s.process
			s.process = nil
			if err := process.Close(); err != nil {
				result.IdentityUnknown = true
				return result, holdCustody(err)
			}
		}
	}
	if status.State == windows.SERVICE_STOPPED {
		// SCM does not promise a usable PID in STOPPED. Preserve a nonzero
		// value as non-launchable ambiguity; never open that numeric PID.
		result.PID = status.PID
		if s.process != nil {
			result.PID = s.process.ID()
			result.BirthTicks = s.process.Birth()
			result.ProcessPresent = true
		}
		return result, nil
	}
	s.observedActive = true
	if status.PID == 0 {
		return result, nil
	} // SCM itself retains the pending claim.
	if s.process != nil && s.process.ID() != status.PID {
		result.IdentityUnknown = true
		result.ProcessPresent = true
		return result, errors.New("live retained service generation differs from SCM PID")
	}
	if s.process == nil {
		process, err := s.ops.Process(status.PID)
		if err != nil || process == nil {
			result.IdentityUnknown = true
			return result, errors.New("service process generation unavailable")
		}
		s.process = process
	}
	result.PID = s.process.ID()
	result.BirthTicks = s.process.Birth()
	if result.PID != status.PID || result.BirthTicks == 0 {
		result.IdentityUnknown = true
		return result, errors.New("service process identity unavailable")
	}
	image, err := s.ops.Image(s.process)
	if err != nil || !strings.EqualFold(image, s.config.LauncherPath) {
		result.IdentityUnknown = true
		return result, errors.New("service process image differs from installed pin target")
	}
	if _, err := localPath(image); err != nil {
		result.IdentityUnknown = true
		return result, err
	}
	confirmed, err := s.ops.Status(s.service)
	if err != nil || confirmed.PID != status.PID || confirmed.Type != status.Type || confirmed.State == windows.SERVICE_STOPPED || serviceStateName(confirmed.State) == "unknown" {
		result.IdentityUnknown = true
		return result, errors.New("SCM process membership changed during observation")
	}
	present, err := s.process.Present()
	if err != nil || !present {
		result.IdentityUnknown = true
		return result, errors.New("retained service process retired during observation")
	}
	result.State = serviceStateName(confirmed.State)
	result.Win32ExitCode = confirmed.Win32ExitCode
	result.ServiceExitCode = confirmed.ServiceExitCode
	result.ProcessPresent = true
	return result, nil
}

func (s *serviceRef) ID() uint32 {
	if s.process != nil {
		return s.process.ID()
	}
	return 0
}
func (s *serviceRef) Birth() uint64 {
	if s.process != nil {
		return s.process.Birth()
	}
	return 0
}
func (s *serviceRef) Present() (bool, error) {
	if err := custodyReady(); err != nil {
		return false, err
	}
	observation, err := s.snapshot()
	if err != nil {
		return false, err
	}
	if observation.ProcessPresent || observation.State != "stopped" {
		return true, nil
	}
	if !s.observedActive && !s.pendingUntil.IsZero() && s.ops.Now().Before(s.pendingUntil) {
		return true, nil
	}
	return false, nil
}
func (s *serviceRef) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		s.closed = true
		if s.process != nil {
			process := s.process
			s.process = nil
			s.closeErr = errors.Join(s.closeErr, holdCustody(process.Close()))
		}
		service, manager := s.service, s.manager
		s.service = 0
		s.manager = 0
		if service != 0 {
			s.closeErr = errors.Join(s.closeErr, holdCustody(s.ops.Close(service)))
		}
		if manager != 0 {
			s.closeErr = errors.Join(s.closeErr, holdCustody(s.ops.Close(manager)))
		}
	})
	return s.closeErr
}

func queryPinnedService(config configuration) (serviceObservation, error) {
	return queryServiceUsing(config, nativeSCMOperations())
}
func queryServiceUsing(config configuration, ops scmOperations) (result serviceObservation, resultErr error) {
	ref, err := openServiceRef(config, ops, false)
	if err != nil {
		return serviceObservation{State: "unknown", IdentityUnknown: true}, err
	}
	defer func() {
		resultErr = errors.Join(resultErr, ref.Close())
		if resultErr != nil {
			result.IdentityUnknown = true
		}
	}()
	return ref.snapshot()
}

func validatePinnedService(config configuration) error {
	return validateServiceUsing(config, nativeSCMOperations())
}
func validateServiceUsing(config configuration, ops scmOperations) (resultErr error) {
	ref, err := openServiceRef(config, ops, false)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, ref.Close()) }()
	image, err := ops.Pin(config)
	if err != nil {
		return err
	}
	if image == nil {
		return errors.New("service image custody unavailable")
	}
	defer func() { resultErr = errors.Join(resultErr, holdCustody(image.Close())) }()
	_, err = ref.snapshot()
	return err
}

func startPinnedServiceRetained(config configuration, finalGate func() error) (*serviceRef, error) {
	return startServiceUsing(config, finalGate, nativeSCMOperations())
}
func startServiceUsing(config configuration, finalGate func() error, ops scmOperations) (result *serviceRef, resultErr error) {
	if finalGate == nil {
		return nil, errors.New("final signed STOP and SCM gate unavailable")
	}
	ref, err := openServiceRef(config, ops, true)
	if err != nil {
		return nil, err
	}
	defer func() {
		if result == nil {
			resultErr = errors.Join(resultErr, ref.Close())
		}
	}()
	observation, err := ref.snapshot()
	if err != nil {
		return nil, err
	}
	recoverable := func(observation serviceObservation) bool {
		return observation.State == "stopped" && observation.PID == 0 && !observation.ProcessPresent && !observation.IdentityUnknown && observation.Win32ExitCode != 0
	}
	if !recoverable(observation) {
		return nil, errors.New("SCM state does not authorize failure recovery")
	}
	image, err := ops.Pin(config)
	if err != nil {
		return nil, err
	}
	if image == nil {
		return nil, errors.New("service image custody unavailable")
	}
	defer func() { resultErr = errors.Join(resultErr, holdCustody(image.Close())) }()
	if err := finalGate(); err != nil {
		return nil, err
	}
	observation, err = ref.snapshot()
	if err != nil {
		return nil, err
	}
	if !recoverable(observation) {
		if observation.State != "stopped" || observation.ProcessPresent {
			return ref, errors.New("service already owns an active or pending generation")
		}
		return nil, errors.New("SCM state no longer authorizes failure recovery")
	}
	if err := finalGate(); err != nil {
		return nil, err
	}
	if err := custodyReady(); err != nil {
		return nil, err
	}
	err = ops.Start(ref.service)
	if err != nil {
		// Definitive admission failures cannot have dispatched our service.
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) || errors.Is(err, windows.ERROR_SERVICE_DISABLED) || errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) || errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) || errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
			return nil, err
		}
		// A timeout/RPC failure can arrive after dispatch. Retain the exact SCM
		// claim through a bounded startup grace, even before a PID is visible.
		ref.pendingUntil = ops.Now().Add(startupGrace)
		return ref, err
	}
	ref.pendingUntil = ops.Now().Add(startupGrace)
	return ref, nil
}
