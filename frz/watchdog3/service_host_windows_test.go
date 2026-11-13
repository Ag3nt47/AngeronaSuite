//go:build windows

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

type hostTestCloser struct {
	calls atomic.Int32
	err   error
}

func (c *hostTestCloser) Close() error { c.calls.Add(1); return c.err }

func admittedHostIdentity() watchdogHostIdentity {
	image := `C:\Program Files\Angerona\watchdog3.exe`
	return watchdogHostIdentity{PID: 71, ServicePID: 71, ServiceState: windows.SERVICE_RUNNING, ServiceType: windows.SERVICE_WIN32_OWN_PROCESS, SIDType: windows.SERVICE_SID_TYPE_NONE, Session: 0, BirthTicks: 116444736000000000 + 17500000000000000, Image: image, ModuleImage: image, User: "S-1-5-18", Account: "LocalSystem", Command: windows.ComposeCommandLine([]string{image, "--service"})}
}

func TestWatchdogHostIdentityRequiresExactSCMSYSTEMProfile(t *testing.T) {
	valid := admittedHostIdentity()
	if err := verifyWatchdogHostIdentity(valid); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"other-pid", "missing-birth", "pending", "shared-process", "restricted-sid", "interactive-session", "ordinary-user", "other-account", "other-image", "other-module", "other-entry", "extra-entry", "unc-image"} {
		t.Run(kind, func(t *testing.T) {
			value := valid
			switch kind {
			case "other-pid":
				value.ServicePID++
			case "missing-birth":
				value.BirthTicks = 0
			case "pending":
				value.ServiceState = windows.SERVICE_START_PENDING
			case "shared-process":
				value.ServiceType = windows.SERVICE_WIN32_SHARE_PROCESS
			case "restricted-sid":
				value.SIDType = windows.SERVICE_SID_TYPE_RESTRICTED
			case "interactive-session":
				value.Session = 1
			case "ordinary-user":
				value.User = "S-1-5-21-1-2-3-4"
			case "other-account":
				value.Account = `NT SERVICE\AngeronaProtection`
			case "other-image":
				value.Image = `C:\different.exe`
			case "other-module":
				value.ModuleImage = `C:\different.exe`
			case "other-entry":
				value.Command = windows.ComposeCommandLine([]string{value.Image, "--engine-service"})
			case "extra-entry":
				value.Command += " --version"
			case "unc-image":
				value.Image = `\\server\share\watchdog3.exe`
				value.ModuleImage = value.Image
				value.Command = windows.ComposeCommandLine([]string{value.Image, "--service"})
			}
			if err := verifyWatchdogHostIdentity(value); err == nil {
				t.Fatal("invalid native host profile admitted", kind)
			}
		})
	}
}

func TestWatchdogHostPIDReadbackWaitsOnlyForBoundedPendingTransition(t *testing.T) {
	reads, pauses := 0, 0
	status, err := awaitWatchdogHostPID(context.Background(), 71, func() (serviceStatus, error) {
		reads++
		if reads == 1 {
			return serviceStatus{State: windows.SERVICE_START_PENDING, Type: windows.SERVICE_WIN32_OWN_PROCESS}, nil
		}
		return serviceStatus{State: windows.SERVICE_RUNNING, Type: windows.SERVICE_WIN32_OWN_PROCESS, PID: 71}, nil
	}, func(context.Context) error { pauses++; return nil })
	if err != nil || status.State != windows.SERVICE_RUNNING || status.PID != 71 || reads != 2 || pauses != 1 {
		t.Fatal("pending handshake was rejected or treated as identity", status, err, reads, pauses)
	}
	for _, kind := range []string{"never-running", "cancelled", "different-running-pid", "stopped", "read-error"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			reads := 0
			injected := errors.New("inert native query failure")
			_, err := awaitWatchdogHostPID(ctx, 71, func() (serviceStatus, error) {
				reads++
				switch kind {
				case "different-running-pid":
					return serviceStatus{State: windows.SERVICE_RUNNING, Type: windows.SERVICE_WIN32_OWN_PROCESS, PID: 72}, nil
				case "stopped":
					return serviceStatus{State: windows.SERVICE_STOPPED, Type: windows.SERVICE_WIN32_OWN_PROCESS}, nil
				case "read-error":
					return serviceStatus{}, injected
				}
				return serviceStatus{State: windows.SERVICE_START_PENDING, Type: windows.SERVICE_WIN32_OWN_PROCESS}, nil
			}, func(context.Context) error {
				if kind == "cancelled" {
					cancel()
				}
				return nil
			})
			if err == nil || reads == 0 || reads > 256 {
				t.Fatal("unbounded or invalid admission", kind, err, reads)
			}
			if kind == "never-running" && reads != 256 {
				t.Fatal("pending observation bound changed", reads)
			}
			if kind == "cancelled" && (!errors.Is(err, context.Canceled) || reads != 1) {
				t.Fatal("readback did not stop on cancellation", err, reads)
			}
			if kind == "read-error" && (!errors.Is(err, injected) || reads != 1) {
				t.Fatal("native query error was retried", err, reads)
			}
		})
	}
}

func TestWatchdogServiceEntryIsExclusiveAndConsoleVersionUnchanged(t *testing.T) {
	calls := 0
	service := func() int { calls++; return 7 }
	var out, errs bytes.Buffer
	if code := dispatchWatchdogCommand([]string{"--service"}, &out, &errs, commandHost{}, service); code != 7 || calls != 1 {
		t.Fatal("fixed service dispatch changed", code, calls)
	}
	for _, arguments := range [][]string{{"--service", "--version"}, {"--version", "--service"}, {"--service", "--config", `C:\x`}, {"--service", "--service"}, {"--service=true"}} {
		before := calls
		if code := dispatchWatchdogCommand(arguments, &out, &errs, commandHost{}, service); code != 2 || calls != before {
			t.Fatal("combined service options were admitted", arguments, code)
		}
	}
	out.Reset()
	if code := dispatchWatchdogCommand([]string{"--version"}, &out, &errs, commandHost{}, service); code != 0 || calls != 1 || out.Len() == 0 {
		t.Fatal("ordinary console version changed", code, calls)
	}
}

func TestWatchdogHostRefusesUnadmittedOrWrongServiceBeforeWorker(t *testing.T) {
	for _, kind := range []string{"wrong-name", "extra-service-args", "admission-failed", "no-custody"} {
		t.Run(kind, func(t *testing.T) {
			calls := 0
			closer := &hostTestCloser{}
			h := &watchdogServiceHandler{parent: context.Background(), completed: make(chan struct{}), admit: func(context.Context) (io.Closer, error) {
				if kind == "admission-failed" {
					return closer, errors.New("inert native profile mismatch")
				}
				if kind == "no-custody" {
					return nil, nil
				}
				return closer, nil
			}, run: func(context.Context) int { calls++; return 0 }}
			arguments := []string{watchdogHostServiceName}
			if kind == "wrong-name" {
				arguments[0] = "DifferentService"
			}
			if kind == "extra-service-args" {
				arguments = append(arguments, "unapproved")
			}
			specific, code := h.Execute(arguments, make(chan svc.ChangeRequest), make(chan svc.Status, 8))
			if !specific || code == 0 || calls != 0 {
				t.Fatal("service proof failed open", kind, code, calls)
			}
			if kind == "admission-failed" && closer.calls.Load() != 1 {
				t.Fatal("rejected admission custody leaked")
			}
			select {
			case <-h.completed:
			default:
				t.Fatal("exact handler completion missing")
			}
		})
	}
}

type hostExecutionResult struct {
	specific bool
	code     uint32
}

func awaitHostStatus(t *testing.T, statuses <-chan svc.Status, predicate func(svc.Status) bool) svc.Status {
	t.Helper()
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	for {
		select {
		case status := <-statuses:
			if predicate(status) {
				return status
			}
		case <-timer.C:
			t.Fatal("bounded inert host status did not arrive")
			return svc.Status{}
		}
	}
}

func TestWatchdogHostStopAndShutdownWaitForExactSupervisorReturn(t *testing.T) {
	for _, control := range []svc.Cmd{svc.Stop, svc.Shutdown} {
		t.Run(map[svc.Cmd]string{svc.Stop: "stop", svc.Shutdown: "shutdown"}[control], func(t *testing.T) {
			parent, cancelParent := context.WithCancel(context.Background())
			defer cancelParent()
			entered, cancelled, returned := make(chan struct{}), make(chan struct{}), make(chan struct{})
			release := make(chan struct{})
			var releaseOnce sync.Once
			releaseWorker := func() { releaseOnce.Do(func() { close(release) }) }
			t.Cleanup(func() { cancelParent(); releaseWorker() })
			closer := &hostTestCloser{}
			h := &watchdogServiceHandler{parent: parent, completed: make(chan struct{}), checkpointInterval: 5 * time.Millisecond, admit: func(context.Context) (io.Closer, error) { return closer, nil }, run: func(ctx context.Context) int {
				close(entered)
				<-ctx.Done()
				close(cancelled)
				<-release
				close(returned)
				return 0
			}}
			requests := make(chan svc.ChangeRequest, 4)
			statuses := make(chan svc.Status, 64)
			done := make(chan hostExecutionResult, 1)
			go func() {
				specific, code := h.Execute([]string{watchdogHostServiceName}, requests, statuses)
				done <- hostExecutionResult{specific, code}
			}()
			awaitHostStatus(t, statuses, func(s svc.Status) bool { return s.State == svc.Running && s.Accepts&svc.AcceptStop != 0 })
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("inert worker not admitted")
			}
			requests <- svc.ChangeRequest{Cmd: control}
			select {
			case <-cancelled:
			case <-time.After(3 * time.Second):
				t.Fatal("SCM cancellation not delivered")
			}
			pending := awaitHostStatus(t, statuses, func(s svc.Status) bool { return s.State == svc.StopPending })
			if pending.WaitHint == 0 || pending.WaitHint > 10000 {
				t.Fatal("shutdown wait hint is unbounded")
			}
			select {
			case result := <-done:
				t.Fatal("host claimed stopped before exact worker returned", result)
			default:
			}
			awaitHostStatus(t, statuses, func(s svc.Status) bool { return s.State == svc.StopPending && s.CheckPoint > pending.CheckPoint })
			requests <- svc.ChangeRequest{Cmd: svc.Interrogate}
			awaitHostStatus(t, statuses, func(s svc.Status) bool { return s.State == svc.StopPending })
			releaseWorker()
			select {
			case result := <-done:
				if result.specific || result.code != 0 {
					t.Fatal(result)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("host did not complete after exact worker return")
			}
			select {
			case <-returned:
			default:
				t.Fatal("success lacks worker-return proof")
			}
			if closer.calls.Load() != 1 {
				t.Fatal("native admission custody not retired once")
			}
		})
	}
}

func TestWatchdogHostClosesCustodyAndReportsWorkerOrCleanupFailure(t *testing.T) {
	for _, kind := range []string{"worker-failed", "close-failed"} {
		t.Run(kind, func(t *testing.T) {
			closer := &hostTestCloser{}
			if kind == "close-failed" {
				closer.err = errors.New("inert cleanup uncertainty")
			}
			h := &watchdogServiceHandler{parent: context.Background(), completed: make(chan struct{}), admit: func(context.Context) (io.Closer, error) { return closer, nil }, run: func(context.Context) int {
				if kind == "worker-failed" {
					return 7
				}
				return 0
			}}
			specific, code := h.Execute([]string{watchdogHostServiceName}, make(chan svc.ChangeRequest), make(chan svc.Status, 8))
			if !specific || code == 0 || closer.calls.Load() != 1 || h.exitCode.Load() != code {
				t.Fatal("worker/cleanup failure reported as successful stop", kind, specific, code)
			}
		})
	}
}

func TestWatchdogDispatcherFailureDoesNotFallBackToConsoleOrWorker(t *testing.T) {
	admissions, runs := 0, 0
	injected := errors.New("inert not launched by SCM")
	code, err := runWatchdogService(func(name string, handler svc.Handler) error {
		if name != watchdogHostServiceName {
			t.Fatal("alternate service name")
		}
		return injected
	}, func(context.Context) (io.Closer, error) { admissions++; return &hostTestCloser{}, nil }, func(context.Context) int { runs++; return 0 })
	if code == 0 || !errors.Is(err, injected) || admissions != 0 || runs != 0 {
		t.Fatal("dispatcher failure fell back", code, err, admissions, runs)
	}
}

func TestWatchdogDispatcherDropCancelsAndRetiresExactWorker(t *testing.T) {
	entered, returned := make(chan struct{}), make(chan struct{})
	closer := &hostTestCloser{}
	injected := errors.New("inert dispatcher status channel retired")
	code, err := runWatchdogService(func(name string, handler svc.Handler) error {
		requests := make(chan svc.ChangeRequest)
		statuses := make(chan svc.Status, 16)
		go handler.Execute([]string{name}, requests, statuses)
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			return errors.New("inert worker was not admitted")
		}
		return injected
	}, func(context.Context) (io.Closer, error) { return closer, nil }, func(ctx context.Context) int { close(entered); <-ctx.Done(); close(returned); return 0 })
	if code == 0 || !errors.Is(err, injected) || closer.calls.Load() != 1 {
		t.Fatal("dispatcher drop did not propagate", code, err)
	}
	select {
	case <-returned:
	default:
		t.Fatal("dispatcher returned before exact worker retirement")
	}
}
