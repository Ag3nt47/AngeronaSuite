//go:build windows

package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"
)

var watchdogVersion = "1.0.0"

type retainedNativeProcess struct{ process *peerHandle }

func (p *retainedNativeProcess) ID() uint32             { return p.process.PID }
func (p *retainedNativeProcess) Birth() uint64          { return p.process.BirthTicks }
func (p *retainedNativeProcess) Present() (bool, error) { return p.process.Present() }
func (p *retainedNativeProcess) Close() error           { return p.process.Close() }

type commandHost struct {
	ProgramData            func() (string, error)
	ReadAdmin              func(string, int) ([]byte, error)
	ReadPrivate            func(string, int) ([]byte, error)
	CheckAdminDirectory    func(string) error
	CheckPrivateDirectory  func(string) error
	EnsurePrivateDirectory func(string) error
	ValidateService        func(configuration) error
	Harden                 func() error
	AcquireInstance        func(string) (io.Closer, error)
	Run                    func(configuration, string, []byte, runnerIO) error
	IO                     func(string, []byte) runnerIO
}

func nativeCommandHost() commandHost {
	host := commandHost{ProgramData: programDataDirectory, ReadAdmin: readAdminFile, ReadPrivate: readPrivateFile, CheckAdminDirectory: checkAdminDirectory, CheckPrivateDirectory: checkPrivateDirectory, EnsurePrivateDirectory: ensurePrivateDirectory, ValidateService: validatePinnedService, Harden: hardenSelf, AcquireInstance: acquireInstance}
	host.IO = func(configPath string, initial []byte) runnerIO {
		digest := sha256.Sum256(initial)
		return runnerIO{
			ReadPrivate: readPrivateFile, ReadAdmin: readAdminFile, WritePrivate: writePrivateFile, AppendPrivate: appendPrivateFile, CheckPrivateDirectory: checkPrivateDirectory, CheckAdminDirectory: checkAdminDirectory,
			Exists: func(path string) (bool, error) {
				_, err := os.Lstat(path)
				if errors.Is(err, os.ErrNotExist) {
					return false, nil
				}
				return err == nil, err
			},
			ClaimLocks:     claimServiceSpawnLock,
			ObserveService: queryPinnedService,
			OpenPeer: func(pid uint32) (processRef, error) {
				process, err := openPeer(pid)
				if process == nil {
					return nil, err
				}
				return &retainedNativeProcess{process}, err
			},
			Launch: func(config configuration, pressure string, gate func() error) (processRef, error) {
				process, err := startPinnedServiceRetained(config, gate)
				if process == nil {
					return nil, err
				}
				return process, err
			},
			CheckConfiguration: func() error {
				if err := checkAdminDirectory(filepath.Dir(filepath.Dir(configPath))); err != nil {
					return err
				}
				if err := checkAdminDirectory(filepath.Dir(configPath)); err != nil {
					return err
				}
				raw, err := readAdminFile(configPath, configurationLimit)
				if err != nil {
					return err
				}
				current := sha256.Sum256(raw)
				if current != digest {
					return errors.New("installed configuration changed")
				}
				return nil
			}, Now: time.Now, OwnPID: uint32(os.Getpid()),
		}
	}
	host.Run = func(config configuration, controlRoot string, key []byte, ops runnerIO) error {
		runner, err := newNativeRunner(config, controlRoot, key, ops.Now(), ops)
		if err != nil {
			return err
		}
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
		defer cancel()
		return runSupervision(ctx, runner)
	}
	return host
}

func runCommand(arguments []string, stdout, stderr io.Writer, host commandHost) (exitCode int) {
	flags := flag.NewFlagSet("angerona_watchdog3", flag.ContinueOnError)
	flags.SetOutput(stderr)
	version := flags.Bool("version", false, "show the native watchdog version")
	configFlag := flags.String("config", "", "fixed installed ProgramData configuration path")
	validateOnly := flags.Bool("validate-only", false, "validate existing installed configuration and authority without writes or launches")
	if err := flags.Parse(arguments); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "Unexpected watchdog arguments.")
		return 2
	}
	if *version {
		if *configFlag != "" || *validateOnly {
			fmt.Fprintln(stderr, "Version cannot be combined with configuration options.")
			return 2
		}
		fmt.Fprintln(stdout, "Angerona watchdog3 "+watchdogVersion+" (native Go)")
		return 0
	}
	programData, err := host.ProgramData()
	if err != nil {
		fmt.Fprintln(stderr, "Watchdog3 held: native ProgramData is unavailable.")
		return 3
	}
	installedRoot := filepath.Join(programData, "Angerona")
	configurationPath := filepath.Join(installedRoot, "watchdog3", "config.json")
	if *configFlag != "" && (!localAbsolutePath(*configFlag) || !strings.EqualFold(*configFlag, configurationPath)) {
		fmt.Fprintln(stderr, "Watchdog3 held: configuration must be the fixed installed path.")
		return 3
	}
	for _, directory := range []string{installedRoot, filepath.Dir(configurationPath)} {
		if host.CheckAdminDirectory(directory) != nil {
			fmt.Fprintln(stderr, "Watchdog3 held: installed configuration custody is unavailable.")
			return 3
		}
	}
	raw, err := host.ReadAdmin(configurationPath, configurationLimit)
	if err != nil {
		fmt.Fprintln(stderr, "Watchdog3 held: installed configuration is unavailable.")
		return 3
	}
	config, err := decodeConfiguration(raw)
	if err != nil {
		fmt.Fprintln(stderr, "Watchdog3 held: installed configuration is invalid.")
		return 3
	}
	if host.CheckPrivateDirectory(config.DataDir) != nil {
		fmt.Fprintln(stderr, "Watchdog3 held: existing data custody is unavailable.")
		return 4
	}
	keyRaw, err := host.ReadPrivate(filepath.Join(config.DataDir, "shutdown.key"), 128)
	if err != nil {
		fmt.Fprintln(stderr, "Watchdog3 held: existing install authority is unavailable.")
		return 4
	}
	key, err := parseInstallAuthority(keyRaw)
	if err != nil {
		fmt.Fprintln(stderr, "Watchdog3 held: existing install authority is invalid.")
		return 4
	}
	controlRoot := filepath.Join(installedRoot, "control")
	ops := host.IO(configurationPath, raw)
	preflight := &nativeRunner{config: config, controlRoot: controlRoot, authority: key, ops: ops}
	stop, err := preflight.readStop(ops.Now())
	if err != nil {
		fmt.Fprintln(stderr, "Watchdog3 held: STOP authority cannot be verified.")
		return 4
	}
	if *validateOnly {
		if host.ValidateService(config) != nil {
			fmt.Fprintln(stderr, "Watchdog3 held: installed launcher pin or custody is invalid.")
			return 4
		}
		if stop.Active {
			fmt.Fprintln(stdout, "Watchdog3 configuration and authority verified; STOP is active. No supervision started.")
		} else {
			fmt.Fprintln(stdout, "Watchdog3 configuration, authority and launcher pin verified. No supervision started.")
		}
		return 0
	}
	if host.Harden() != nil {
		fmt.Fprintln(stderr, "Watchdog3 held: native process mitigation setup failed.")
		return 4
	}
	for _, name := range []string{"heartbeats", "ipc", "diagnostics"} {
		if host.EnsurePrivateDirectory(filepath.Join(config.DataDir, name)) != nil {
			fmt.Fprintln(stderr, "Watchdog3 held: private runtime directory unavailable.")
			return 4
		}
	}
	instance, err := host.AcquireInstance(config.DataDir)
	if errors.Is(err, errAlreadyRunning) {
		fmt.Fprintln(stdout, "Watchdog3 is already running for this installation.")
		return 0
	}
	if err != nil || instance == nil {
		fmt.Fprintln(stderr, "Watchdog3 held: single-instance custody unavailable.")
		return 4
	}
	defer func() {
		if instance.Close() != nil {
			fmt.Fprintln(stderr, "Watchdog3 stopped: instance handle cleanup could not be verified.")
			if exitCode == 0 {
				exitCode = 1
			}
		}
	}()
	if err := host.Run(config, controlRoot, key, ops); err != nil {
		fmt.Fprintln(stderr, "Watchdog3 stopped: native supervision could not complete.")
		return 1
	}
	return 0
}

func main() { os.Exit(runCommand(os.Args[1:], os.Stdout, os.Stderr, nativeCommandHost())) }
