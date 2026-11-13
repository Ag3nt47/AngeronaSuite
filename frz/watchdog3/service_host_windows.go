//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

const watchdogHostServiceName = "AngeronaWatchdog3"

// SCM Running means only that this native dispatcher is responsive. Admission
// still precedes all supervisor work; neither Running nor this DTO attests to
// the protection engine's sensors, publisher signature, or operating health.
type watchdogHostIdentity struct {
	PID, ServicePID, ServiceState, ServiceType, SIDType, Session uint32
	BirthTicks                                                   uint64
	Image, ModuleImage, User, Account, Command                   string
}

func verifyWatchdogHostIdentity(value watchdogHostIdentity) error {
	if value.PID == 0 || value.PID != value.ServicePID || value.BirthTicks <= 116444736000000000 || value.ServiceState != windows.SERVICE_RUNNING || value.ServiceType != windows.SERVICE_WIN32_OWN_PROCESS || value.SIDType != windows.SERVICE_SID_TYPE_NONE || value.User != "S-1-5-18" || value.Session != 0 {
		return errors.New("watchdog SCM process, token or service profile is not admitted")
	}
	if !strings.EqualFold(value.Account, "LocalSystem") && !strings.EqualFold(value.Account, `NT AUTHORITY\SYSTEM`) {
		return errors.New("watchdog SCM account is not LocalSystem")
	}
	if _, err := localPath(value.Image); err != nil {
		return err
	}
	if !strings.EqualFold(value.Image, value.ModuleImage) || !strings.EqualFold(filepath.Base(value.Image), "watchdog3.exe") {
		return errors.New("watchdog actual native image differs from its module")
	}
	if len(value.Command) == 0 || len(value.Command) > maximumServiceConfig || strings.ContainsAny(value.Command, "\x00\r\n") {
		return errors.New("watchdog service command is malformed")
	}
	arguments, err := windows.DecomposeCommandLine(value.Command)
	if err != nil || len(arguments) != 2 || !strings.EqualFold(arguments[0], value.Image) || arguments[1] != "--service" {
		return errors.New("watchdog SCM command is not its fixed native service entry")
	}
	return nil
}

// This query-only admission does not register a service, enable an account,
// manufacture a digest/signature, repair an ACL, or open an engine key.
func admitNativeWatchdogHost(ctx context.Context) (result io.Closer, resultErr error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := custodyReady(); err != nil {
		return nil, err
	}
	defer func() {
		if resultErr != nil && result != nil {
			resultErr = errors.Join(resultErr, result.Close())
			result = nil
		}
	}()
	peer, err := openPeer(uint32(os.Getpid()))
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, peer.Close()) }()
	var token windows.Token
	if err := windows.OpenProcessToken(peer.handle, windows.TOKEN_QUERY, &token); err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, retireNative(windows.Handle(token))) }()
	user, err := token.GetTokenUser()
	if err != nil {
		return nil, err
	}
	var session, needed uint32
	if err := windows.GetTokenInformation(token, windows.TokenSessionId, (*byte)(unsafe.Pointer(&session)), uint32(unsafe.Sizeof(session)), &needed); err != nil {
		return nil, err
	}
	if needed > uint32(unsafe.Sizeof(session)) || user.User.Sid.String() != "S-1-5-18" || session != 0 {
		return nil, errors.New("native watchdog service requires SYSTEM Session 0")
	}
	buffer := make([]uint16, 32768)
	size := uint32(len(buffer))
	if err := windows.QueryFullProcessImageName(peer.handle, 0, &buffer[0], &size); err != nil {
		return nil, err
	}
	if size == 0 || size >= uint32(len(buffer)) {
		return nil, errors.New("watchdog native image path unavailable")
	}
	image := windows.UTF16ToString(buffer[:size])
	module, err := os.Executable()
	if err != nil {
		return nil, err
	}
	manager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, holdCustody(windows.CloseServiceHandle(manager))) }()
	name, _ := windows.UTF16PtrFromString(watchdogHostServiceName)
	service, err := windows.OpenService(manager, name, windows.SERVICE_QUERY_CONFIG|windows.SERVICE_QUERY_STATUS|windows.READ_CONTROL)
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, holdCustody(windows.CloseServiceHandle(service))) }()
	if err := checkServiceCustody(service); err != nil {
		return nil, err
	}
	registration, err := nativeServiceRegistration(service)
	if err != nil {
		return nil, err
	}
	readback, cancelReadback := context.WithTimeout(ctx, 2*time.Second)
	defer cancelReadback()
	poll := time.NewTicker(10 * time.Millisecond)
	defer poll.Stop()
	status, err := awaitWatchdogHostPID(readback, peer.PID, func() (serviceStatus, error) { return nativeServiceStatus(service) }, func(ctx context.Context) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-poll.C:
			return nil
		}
	})
	if err != nil {
		return nil, err
	}
	identity := watchdogHostIdentity{PID: peer.PID, BirthTicks: peer.BirthTicks, ServicePID: status.PID, ServiceState: status.State, ServiceType: registration.Type, SIDType: registration.SIDType, Session: session, Image: image, ModuleImage: module, User: user.User.Sid.String(), Account: registration.Account, Command: registration.Command}
	if err := verifyWatchdogHostIdentity(identity); err != nil {
		return nil, err
	}
	if status.Type != windows.SERVICE_WIN32_OWN_PROCESS {
		return nil, errors.New("watchdog SCM status type differs")
	}
	hold, err := openHeld(image, windows.GENERIC_READ, windows.FILE_SHARE_READ, false, true, false)
	if err != nil {
		return nil, err
	}
	result = hold
	header := make([]byte, 2)
	if _, err := io.ReadFull(hold.file, header); err != nil || string(header) != "MZ" {
		return result, errors.New("watchdog own image is not a native PE")
	}
	// Recheck SCM PID membership while the exact native process and protected
	// image remain held. Mandatory self-signing admission separately holds the
	// exact enrolled final image and verified machine-context publisher identity.
	confirmed, err := nativeServiceStatus(service)
	if err != nil || confirmed.State != windows.SERVICE_RUNNING || confirmed.PID != peer.PID || confirmed.Type != windows.SERVICE_WIN32_OWN_PROCESS {
		return result, errors.New("watchdog SCM generation changed during admission")
	}
	if present, err := peer.Present(); err != nil || !present {
		return result, errors.New("watchdog native generation retired during admission")
	}
	return result, nil
}

func awaitWatchdogHostPID(ctx context.Context, pid uint32, read func() (serviceStatus, error), pause func(context.Context) error) (serviceStatus, error) {
	for observations := 0; observations < 256; observations++ {
		if err := ctx.Err(); err != nil {
			return serviceStatus{}, err
		}
		status, err := read()
		if err != nil {
			return serviceStatus{}, err
		}
		if status.Type != windows.SERVICE_WIN32_OWN_PROCESS {
			return serviceStatus{}, errors.New("watchdog SCM status is not an own-process host")
		}
		if status.State == windows.SERVICE_RUNNING {
			if status.PID != pid || pid == 0 {
				return serviceStatus{}, errors.New("watchdog SCM PID differs from the native host")
			}
			return status, nil
		}
		if status.State != windows.SERVICE_START_PENDING || (status.PID != 0 && status.PID != pid) {
			return serviceStatus{}, errors.New("watchdog SCM state cannot admit this native host")
		}
		if err := pause(ctx); err != nil {
			return serviceStatus{}, err
		}
	}
	return serviceStatus{}, errors.New("watchdog SCM PID readback exceeded its observation bound")
}

type watchdogServiceHandler struct {
	parent             context.Context
	admit              func(context.Context) (io.Closer, error)
	run                func(context.Context) int
	checkpointInterval time.Duration
	completed          chan struct{}
	started            atomic.Bool
	exitCode           atomic.Uint32
}

func (h *watchdogServiceHandler) Execute(arguments []string, requests <-chan svc.ChangeRequest, statuses chan<- svc.Status) (specific bool, exit uint32) {
	h.started.Store(true)
	defer func() { h.exitCode.Store(exit); close(h.completed) }()
	if h.parent.Err() != nil || len(arguments) != 1 || !strings.EqualFold(arguments[0], watchdogHostServiceName) || h.admit == nil || h.run == nil {
		return true, 4
	}
	publish := func(status svc.Status) bool {
		select {
		case statuses <- status:
			return true
		case <-h.parent.Done():
			return false
		}
	}
	if !publish(svc.Status{State: svc.StartPending, WaitHint: 10000, CheckPoint: 1}) {
		return true, 1
	}
	// START_PENDING has no guaranteed usable SCM PID. Running here describes
	// dispatcher liveness only; no engine/supervisor work has started yet.
	if !publish(svc.Status{State: svc.Running}) {
		return true, 1
	}
	custody, err := h.admit(h.parent)
	if err != nil || custody == nil {
		if custody != nil {
			if custody.Close() != nil {
				return true, 1
			}
		}
		return true, 4
	}
	defer func() {
		if custody.Close() != nil {
			specific = true
			exit = 1
		}
	}()
	ctx, cancel := context.WithCancel(h.parent)
	defer cancel()
	if h.parent.Err() != nil {
		return true, 1
	}
	current := svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	if !publish(current) {
		return true, 1
	}
	done := make(chan int, 1)
	go func() { done <- h.run(ctx) }()
	interval := h.checkpointInterval
	if interval <= 0 {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	stopping := false
	beginStop := func() {
		if !stopping {
			stopping = true
			cancel()
			current = svc.Status{State: svc.StopPending, WaitHint: 5000, CheckPoint: 1}
			publish(current)
		}
	}
	for {
		select {
		case code := <-done:
			if code < 0 || code > 255 {
				code = 1
			}
			return code != 0, uint32(code)
		case request, open := <-requests:
			if !open {
				beginStop()
				requests = nil
				continue
			}
			switch request.Cmd {
			case svc.Stop, svc.Shutdown:
				beginStop()
			case svc.Interrogate:
				publish(current)
			}
		case <-h.parent.Done():
			beginStop()
			// The dispatcher can disappear after a failed status update. Still
			// wait for the exact worker return; never report a successful stop
			// or abandon its resource owner while supervision is still running.
			code := <-done
			if code == 0 {
				code = 1
			}
			if code < 0 || code > 255 {
				code = 1
			}
			return true, uint32(code)
		case <-ticker.C:
			if stopping {
				if current.CheckPoint < ^uint32(0) {
					current.CheckPoint++
				}
				publish(current)
			}
		}
	}
}

type watchdogDispatcher func(string, svc.Handler) error

func runWatchdogService(dispatch watchdogDispatcher, admit func(context.Context) (io.Closer, error), run func(context.Context) int) (int, error) {
	if dispatch == nil {
		return 1, errors.New("native SCM dispatcher unavailable")
	}
	ctx, cancel := context.WithCancel(context.Background())
	handler := &watchdogServiceHandler{parent: ctx, admit: admit, run: run, completed: make(chan struct{})}
	err := dispatch(watchdogHostServiceName, handler)
	cancel()
	if handler.started.Load() {
		<-handler.completed
	} else if err == nil {
		err = errors.New("SCM dispatcher returned without admitting its service")
	}
	code := int(handler.exitCode.Load())
	if err != nil && code == 0 {
		code = 1
	}
	return code, err
}

func nativeWatchdogService() (exitCode int) {
	activation, activationErr := nativeSelfActivation()
	if activationErr != nil {
		fmt.Fprintln(os.Stderr, "Watchdog3 service inactive: explicit signing enrollment is required.")
		return inactiveSigningExit
	}
	defer closeCommandActivation(activation, os.Stderr, &exitCode)
	code, err := runWatchdogService(svc.Run, admitNativeWatchdogHost, func(ctx context.Context) int {
		host := nativeCommandHost()
		host.Run = func(config configuration, controlRoot string, key []byte, ops runnerIO) error {
			runner, err := newNativeRunner(config, controlRoot, key, ops.Now(), ops)
			if err != nil {
				return err
			}
			return runSupervision(ctx, runner)
		}
		return runCommand(nil, io.Discard, io.Discard, host)
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "Watchdog3 service refused: native SCM admission or dispatcher unavailable.")
	}
	return code
}

func dispatchWatchdogCommand(arguments []string, stdout, stderr io.Writer, host commandHost, service func() int) (exitCode int) {
	if len(arguments) > 0 {
		switch arguments[0] {
		case "--observe":
			return runObserveCommand(arguments[1:], stdout, stderr)
		case "--inspect-signing":
			return runSigningDiagnostic(arguments[1:], false, stdout, stderr, nativeSigningInspectionHost())
		case "--signing-status":
			return runSigningDiagnostic(arguments[1:], true, stdout, stderr, nativeSigningInspectionHost())
		}
	}
	for _, argument := range arguments {
		if argument == "--service" {
			if len(arguments) != 1 || service == nil {
				fmt.Fprintln(stderr, "The fixed service entry cannot be combined with other arguments.")
				return 2
			}
			activation, err := openCommandActivation(host)
			if err != nil {
				fmt.Fprintln(stderr, "Watchdog3 service inactive: explicit end-user signing and enrollment are required.")
				return inactiveSigningExit
			}
			defer closeCommandActivation(activation, stderr, &exitCode)
			return service()
		}
	}
	return runCommand(arguments, stdout, stderr, host)
}
