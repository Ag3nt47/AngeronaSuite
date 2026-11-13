//go:build windows

package main

import (
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

type scmFakeProcess struct {
	id     uint32
	birth  uint64
	alive  *bool
	closed bool
	closes *int
}

func (p *scmFakeProcess) ID() uint32    { return p.id }
func (p *scmFakeProcess) Birth() uint64 { return p.birth }
func (p *scmFakeProcess) Present() (bool, error) {
	if p.closed {
		return false, errors.New("inert process handle retired")
	}
	return *p.alive, nil
}
func (p *scmFakeProcess) Close() error {
	if !p.closed {
		p.closed = true
		*p.closes++
	}
	return nil
}

type scmFakePin struct {
	closes *int
	err    error
}

func (p *scmFakePin) Close() error { *p.closes++; return p.err }

type scmFixture struct {
	config                                                                           configuration
	registration                                                                     serviceRegistration
	status                                                                           serviceStatus
	now                                                                              time.Time
	starts, managerOpens, serviceOpens, pins, pinCloses, processOpens, processCloses int
	access                                                                           uint32
	closed                                                                           []windows.Handle
	serviceAlive                                                                     bool
	startErr, custodyErr, pinErr, pinCloseErr, closeErr                              error
	image                                                                            string
	startHook                                                                        func()
}

func newSCMFixture() *scmFixture {
	c := configuration{Schema: 2, DataDir: `C:\ProgramData\Angerona\Watchdog3Runtime`, LauncherPath: `C:\Program Files\Angerona\Angerona.exe`, LauncherSHA256: strings.Repeat("a", 64), LauncherArgs: []string{"--engine-service"}, WorkingDirectory: `C:\Program Files\Angerona`}
	return &scmFixture{config: c, registration: serviceRegistration{Command: windows.ComposeCommandLine([]string{c.LauncherPath, "--engine-service"}), Account: protectionServiceAccount, Type: windows.SERVICE_WIN32_OWN_PROCESS, SIDType: windows.SERVICE_SID_TYPE_RESTRICTED}, status: serviceStatus{State: windows.SERVICE_STOPPED, Type: windows.SERVICE_WIN32_OWN_PROCESS, Win32ExitCode: 1067}, now: time.Unix(1750000000, 0), serviceAlive: true, image: c.LauncherPath}
}
func (f *scmFixture) ops() scmOperations {
	return scmOperations{
		OpenManager: func() (windows.Handle, error) { f.managerOpens++; return 1, nil },
		OpenService: func(manager windows.Handle, access uint32) (windows.Handle, error) {
			if manager != 1 {
				return 0, errors.New("unexpected manager")
			}
			f.serviceOpens++
			f.access = access
			return 2, nil
		},
		Registration: func(windows.Handle) (serviceRegistration, error) { return f.registration, nil },
		Status:       func(windows.Handle) (serviceStatus, error) { return f.status, nil },
		Custody:      func(windows.Handle) error { return f.custodyErr },
		Start: func(windows.Handle) error {
			f.starts++
			if f.startHook != nil {
				f.startHook()
			}
			return f.startErr
		},
		Close: func(handle windows.Handle) error { f.closed = append(f.closed, handle); return f.closeErr },
		Pin: func(configuration) (io.Closer, error) {
			f.pins++
			if f.pinErr != nil {
				return nil, f.pinErr
			}
			return &scmFakePin{closes: &f.pinCloses, err: f.pinCloseErr}, nil
		},
		Process: func(pid uint32) (serviceProcess, error) {
			f.processOpens++
			return &scmFakeProcess{id: pid, birth: 116444736000000000 + uint64(f.now.Add(-time.Minute).UnixNano()/100), alive: &f.serviceAlive, closes: &f.processCloses}, nil
		},
		Image: func(serviceProcess) (string, error) { return f.image, nil },
		Now:   func() time.Time { return f.now },
	}
}

func TestSCMQueriesAreReadOnlyAndDoNotHashEveryPoll(t *testing.T) {
	f := newSCMFixture()
	f.status.State = windows.SERVICE_RUNNING
	f.status.PID = 44
	for i := 0; i < 3; i++ {
		observation, err := queryServiceUsing(f.config, f.ops())
		if err != nil {
			t.Fatal(err)
		}
		if observation.State != "running" || !observation.ProcessPresent || observation.PID != 44 || observation.BirthTicks == 0 {
			t.Fatal(observation)
		}
	}
	if f.starts != 0 || f.pins != 0 || f.processOpens != 3 || f.processCloses != 3 || len(f.closed) != 6 {
		t.Fatal("poll acquired mutation/hash authority or leaked custody", f)
	}
	if f.access != windows.SERVICE_QUERY_CONFIG|windows.SERVICE_QUERY_STATUS|windows.READ_CONTROL {
		t.Fatal("poll requested excess rights", f.access)
	}
}

func TestSCMValidatePinsWithoutStartingOrChangingService(t *testing.T) {
	f := newSCMFixture()
	if err := validateServiceUsing(f.config, f.ops()); err != nil {
		t.Fatal(err)
	}
	if f.starts != 0 || f.pins != 1 || f.pinCloses != 1 || len(f.closed) != 2 {
		t.Fatal("validation mutated or leaked service custody", f)
	}
	if f.access&windows.SERVICE_START != 0 {
		t.Fatal("validation requested start authority")
	}
}

func TestSCMNormalStopsAndAllActiveStatesNeverAutoStart(t *testing.T) {
	for _, state := range []uint32{windows.SERVICE_STOPPED, windows.SERVICE_START_PENDING, windows.SERVICE_STOP_PENDING, windows.SERVICE_RUNNING, windows.SERVICE_CONTINUE_PENDING, windows.SERVICE_PAUSE_PENDING, windows.SERVICE_PAUSED, 99} {
		t.Run(serviceStateName(state), func(t *testing.T) {
			f := newSCMFixture()
			f.status.State = state
			f.status.Win32ExitCode = 0
			f.status.ServiceExitCode = 0
			if state == windows.SERVICE_STOPPED {
				f.status.ServiceExitCode = 99
			} // stale specifics never override a normal Win32 stop.
			ref, err := startServiceUsing(f.config, func() error { return nil }, f.ops())
			if ref != nil {
				ref.Close()
			}
			if err == nil || f.starts != 0 || f.pins != 0 {
				t.Fatal("normal/active/unknown state authorized start", state, err)
			}
		})
	}
}

func TestSCMRegistrationAndPinDriftRefuseDispatch(t *testing.T) {
	for _, kind := range []string{"wrong-image", "wrong-entry", "extra-args", "shared-process", "wrong-account", "unrestricted-sid", "service-acl", "image-pin", "schema1"} {
		t.Run(kind, func(t *testing.T) {
			f := newSCMFixture()
			switch kind {
			case "wrong-image":
				f.registration.Command = `"C:\different.exe" --engine-service`
			case "wrong-entry":
				f.registration.Command = windows.ComposeCommandLine([]string{f.config.LauncherPath, "--chill"})
			case "extra-args":
				f.registration.Command += " --another"
			case "shared-process":
				f.registration.Type = windows.SERVICE_WIN32_SHARE_PROCESS
			case "wrong-account":
				f.registration.Account = "LocalSystem"
			case "unrestricted-sid":
				f.registration.SIDType = windows.SERVICE_SID_TYPE_UNRESTRICTED
			case "service-acl":
				f.custodyErr = errors.New("inert nonadmin grant")
			case "image-pin":
				f.pinErr = errors.New("inert digest mismatch")
			case "schema1":
				f.config.Schema = 1
			}
			ref, err := startServiceUsing(f.config, func() error { return nil }, f.ops())
			if ref != nil {
				ref.Close()
			}
			if err == nil || f.starts != 0 {
				t.Fatal("drift reached StartService", kind, err)
			}
		})
	}
}

func TestSCMFinalSignedStopAndFreshStateGatePrecedeStart(t *testing.T) {
	for _, kind := range []string{"stop", "registration-changed", "normal-stop", "normal-stop-stale-specific", "stopped-stale-pid", "concurrent-start"} {
		t.Run(kind, func(t *testing.T) {
			f := newSCMFixture()
			gates := 0
			ref, err := startServiceUsing(f.config, func() error {
				gates++
				if kind == "stop" {
					return errors.New("inert verified STOP")
				}
				if gates == 1 {
					switch kind {
					case "registration-changed":
						f.registration.Account = "LocalSystem"
					case "normal-stop":
						f.status.Win32ExitCode = 0
					case "normal-stop-stale-specific":
						f.status.Win32ExitCode = 0
						f.status.ServiceExitCode = 99
					case "stopped-stale-pid":
						f.status.PID = 99
					case "concurrent-start":
						f.status.State = windows.SERVICE_START_PENDING
					}
				}
				return nil
			}, f.ops())
			if ref != nil {
				if kind != "concurrent-start" {
					t.Error("unexpected retained work")
				}
				ref.Close()
			}
			if err == nil || f.starts != 0 || gates == 0 {
				t.Fatal("fresh gate bypassed", kind, err)
			}
		})
	}
}

func TestSCMFailureRecoveryRetainsPendingClaimThenExactGeneration(t *testing.T) {
	f := newSCMFixture()
	f.startHook = func() { f.status.State = windows.SERVICE_START_PENDING }
	gates := 0
	ref, err := startServiceUsing(f.config, func() error { gates++; return nil }, f.ops())
	if err != nil || ref == nil {
		t.Fatal(ref, err)
	}
	defer ref.Close()
	if f.starts != 1 || gates != 2 || f.pinCloses != 1 || len(f.closed) != 0 {
		t.Fatal("start did not retain exact SCM ownership", f)
	}
	if f.access != windows.SERVICE_QUERY_CONFIG|windows.SERVICE_QUERY_STATUS|windows.READ_CONTROL|windows.SERVICE_START {
		t.Fatal("start requested excess service rights", f.access)
	}
	if ref.ID() != 0 || ref.Birth() != 0 {
		t.Fatal("pending claim invented a PID")
	}
	if present, err := ref.Present(); err != nil || !present {
		t.Fatal("pending claim was released", present, err)
	}
	f.status.State = windows.SERVICE_RUNNING
	f.status.PID = 55
	if present, err := ref.Present(); err != nil || !present || ref.ID() != 55 || ref.Birth() == 0 {
		t.Fatal("service generation not retained", present, err)
	}
	f.serviceAlive = false
	f.status.State = windows.SERVICE_STOPPED
	f.status.PID = 0
	if present, err := ref.Present(); err != nil || present {
		t.Fatal("retired generation remained present", present, err)
	}
	if err := ref.Close(); err != nil {
		t.Fatal(err)
	}
	if len(f.closed) != 2 || f.processCloses != 1 {
		t.Fatal("native ownership did not retire once", f)
	}
	if err := ref.Close(); err != nil || len(f.closed) != 2 {
		t.Fatal("retired raw handles were retried")
	}
}

func TestSCMAmbiguousTimeoutRetainsBoundedClaimWithoutPID(t *testing.T) {
	f := newSCMFixture()
	f.startErr = windows.ERROR_SERVICE_REQUEST_TIMEOUT
	ref, err := startServiceUsing(f.config, func() error { return nil }, f.ops())
	if ref == nil || !errors.Is(err, windows.ERROR_SERVICE_REQUEST_TIMEOUT) {
		t.Fatal(ref, err)
	}
	defer ref.Close()
	if present, err := ref.Present(); err != nil || !present {
		t.Fatal("ambiguous dispatch lost pending claim", present, err)
	}
	f.now = f.now.Add(startupGrace + time.Second)
	if present, err := ref.Present(); err != nil || present {
		t.Fatal("proven-stopped expired pending claim did not retire", present, err)
	}
	if f.starts != 1 {
		t.Fatal("pending claim restarted service")
	}
}

func TestSCMWrongProcessImageNeverClaimsMembership(t *testing.T) {
	f := newSCMFixture()
	f.status.State = windows.SERVICE_RUNNING
	f.status.PID = 88
	f.image = `C:\different.exe`
	observation, err := queryServiceUsing(f.config, f.ops())
	if err == nil || !observation.IdentityUnknown || f.starts != 0 || f.processCloses != 1 {
		t.Fatal("different process became service authority", observation, err)
	}
}

func TestSCMCleanupErrorAfterDispatchPreservesPendingReference(t *testing.T) {
	f := newSCMFixture()
	injected := errors.New("inert pin close uncertainty")
	f.pinCloseErr = injected
	t.Cleanup(func() { custodyMu.Lock(); custodyHold = nil; custodyMu.Unlock() })
	ref, err := startServiceUsing(f.config, func() error { return nil }, f.ops())
	if ref == nil || !errors.Is(err, injected) || f.starts != 1 || custodyReady() == nil {
		t.Fatal("post-dispatch custody error lost claim", ref, err)
	}
	if err := ref.Close(); err != nil {
		t.Fatal(err)
	}
	before := f.managerOpens
	if _, err := queryServiceUsing(f.config, f.ops()); err == nil || f.managerOpens != before {
		t.Fatal("unproven cleanup permitted another allocation")
	}
}

func TestSCMQueryCleanupErrorCannotReturnTrustedObservation(t *testing.T) {
	f := newSCMFixture()
	injected := errors.New("inert SCM close uncertainty")
	f.closeErr = injected
	t.Cleanup(func() { custodyMu.Lock(); custodyHold = nil; custodyMu.Unlock() })
	observation, err := queryServiceUsing(f.config, f.ops())
	if !errors.Is(err, injected) || !observation.IdentityUnknown || len(f.closed) != 2 || custodyReady() == nil {
		t.Fatal("SCM cleanup error was ignored", observation, err)
	}
}
