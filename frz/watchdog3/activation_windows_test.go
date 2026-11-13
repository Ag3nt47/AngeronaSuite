//go:build windows

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type activationTestCloser struct {
	closed int
	err    error
}

func (closer *activationTestCloser) Close() error { closer.closed++; return closer.err }

type activationTestImage struct {
	activationTestCloser
	values []string
	err    error
	reads  int
}

func (image *activationTestImage) Digest() (string, error) {
	image.reads++
	if image.err != nil {
		return "", image.err
	}
	if len(image.values) == 0 {
		return strings.Repeat("a", 64), nil
	}
	value := image.values[0]
	if len(image.values) > 1 {
		image.values = image.values[1:]
	}
	return value, nil
}

func testActivationEnrollment() activationEnrollment {
	return activationEnrollment{Schema: 1, Enabled: true, WatchdogSHA256: strings.Repeat("a", 64), CertificateSHA256: strings.Repeat("b", 64), Publisher: "CN=Explicit End User,O=Example"}
}
func testActivationSigner() activationSigner {
	return activationSigner{CertificateSHA256: strings.Repeat("b", 64), Publisher: "CN=Explicit End User,O=Example", NotAfter: "2099-01-01T00:00:00Z"}
}
func isolateActivationCustody(t *testing.T) {
	t.Helper()
	custodyMu.Lock()
	previous := custodyHold
	previousTrust := retainedActivationTrustState
	custodyHold = nil
	retainedActivationTrustState = nil
	custodyMu.Unlock()
	t.Cleanup(func() {
		custodyMu.Lock()
		custodyHold = previous
		retainedActivationTrustState = previousTrust
		custodyMu.Unlock()
	})
}

func TestActivationEnrollmentRequiresExplicitClosedFinalPins(t *testing.T) {
	good, _ := json.Marshal(testActivationEnrollment())
	if _, err := decodeActivation(good); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"disabled", "old-schema", "empty", "oversized", "missing-field", "duplicate-field", "unknown-field", "case-alias", "trailing", "wrong-bool", "uppercase-hash", "zero-hash", "bad-cert", "empty-publisher", "publisher-control", "publisher-padding"} {
		t.Run(kind, func(t *testing.T) {
			raw := append([]byte(nil), good...)
			value := testActivationEnrollment()
			switch kind {
			case "empty":
				raw = nil
			case "oversized":
				raw = bytes.Repeat([]byte(" "), activationLimit+1)
			case "missing-field":
				raw = bytes.Replace(raw, []byte(`"schema":1,`), nil, 1)
			case "duplicate-field":
				raw = append([]byte(`{"schema":1,`), raw[1:]...)
			case "unknown-field":
				raw = append([]byte(`{"extra":true,`), raw[1:]...)
			case "case-alias":
				raw = bytes.Replace(raw, []byte(`"schema"`), []byte(`"Schema"`), 1)
			case "trailing":
				raw = append(raw, []byte("{}")...)
			case "wrong-bool":
				raw = bytes.Replace(raw, []byte(`"enabled":true`), []byte(`"enabled":"true"`), 1)
			default:
				switch kind {
				case "disabled":
					value.Enabled = false
				case "old-schema":
					value.Schema = 2
				case "uppercase-hash":
					value.WatchdogSHA256 = strings.Repeat("A", 64)
				case "zero-hash":
					value.WatchdogSHA256 = strings.Repeat("0", 64)
				case "bad-cert":
					value.CertificateSHA256 = "not-enrolled"
				case "empty-publisher":
					value.Publisher = ""
				case "publisher-control":
					value.Publisher = "CN=operator\n"
				case "publisher-padding":
					value.Publisher = " CN=operator"
				}
				raw, _ = json.Marshal(value)
			}
			if _, err := decodeActivation(raw); err == nil {
				t.Fatal("invalid signing enrollment admitted", kind)
			}
		})
	}
}

func TestActivationBindingRequiresFinalDigestAndExactLeafIdentity(t *testing.T) {
	for _, kind := range []string{"good", "other-image", "other-cert", "other-publisher", "no-cert", "no-publisher", "disabled", "old-schema"} {
		t.Run(kind, func(t *testing.T) {
			record, signer, digest := testActivationEnrollment(), testActivationSigner(), strings.Repeat("a", 64)
			switch kind {
			case "other-image":
				digest = strings.Repeat("c", 64)
			case "other-cert":
				signer.CertificateSHA256 = strings.Repeat("d", 64)
			case "other-publisher":
				signer.Publisher = "CN=Different"
			case "no-cert":
				signer.CertificateSHA256 = ""
			case "no-publisher":
				signer.Publisher = ""
			case "disabled":
				record.Enabled = false
			case "old-schema":
				record.Schema = 2
			}
			err := checkActivationBinding(record, digest, signer)
			if (err == nil) != (kind == "good") {
				t.Fatal("wrong activation binding result", kind, err)
			}
		})
	}
}

func TestActivationAdmissionRefusesMissingDependenciesBeforeReads(t *testing.T) {
	for _, missing := range []string{"load", "image", "verify"} {
		t.Run(missing, func(t *testing.T) {
			isolateActivationCustody(t)
			calls := 0
			ops := activationIO{
				Load: func() (activationEnrollment, io.Closer, error) {
					calls++
					return testActivationEnrollment(), &activationTestCloser{}, nil
				},
				OpenImage: func() (activationImage, error) { calls++; return &activationTestImage{}, nil },
				Verify:    func(activationImage) (activationSigner, error) { calls++; return testActivationSigner(), nil },
			}
			switch missing {
			case "load":
				ops.Load = nil
			case "image":
				ops.OpenImage = nil
			case "verify":
				ops.Verify = nil
			}
			if lease, err := admitSelfActivation(ops); err == nil || lease != nil || calls != 0 {
				t.Fatal("missing signing dependency performed work", missing, err, calls)
			}
		})
	}
}

func TestActivationAdmissionFailurePreservesNoOperationalCapability(t *testing.T) {
	for _, kind := range []string{"missing-enrollment", "nil-enrollment-lease", "image-open", "nil-image", "digest-read", "wrong-digest", "unsigned", "wrong-leaf", "changed-after-signature", "success"} {
		t.Run(kind, func(t *testing.T) {
			isolateActivationCustody(t)
			record := &activationTestCloser{}
			image := &activationTestImage{}
			opened, verified := 0, 0
			ops := activationIO{
				Load: func() (activationEnrollment, io.Closer, error) {
					if kind == "missing-enrollment" {
						return activationEnrollment{}, record, errors.New("private enrollment bytes")
					}
					if kind == "nil-enrollment-lease" {
						return testActivationEnrollment(), nil, nil
					}
					return testActivationEnrollment(), record, nil
				},
				OpenImage: func() (activationImage, error) {
					opened++
					if kind == "image-open" {
						return image, errors.New("private image detail")
					}
					if kind == "nil-image" {
						return nil, nil
					}
					if kind == "digest-read" {
						image.err = errors.New("read failure")
					}
					if kind == "wrong-digest" {
						image.values = []string{strings.Repeat("c", 64)}
					}
					if kind == "changed-after-signature" {
						image.values = []string{strings.Repeat("a", 64), strings.Repeat("c", 64)}
					}
					return image, nil
				},
				Verify: func(activationImage) (activationSigner, error) {
					verified++
					if kind == "unsigned" {
						return activationSigner{}, errors.New("signature unavailable")
					}
					signer := testActivationSigner()
					if kind == "wrong-leaf" {
						signer.CertificateSHA256 = strings.Repeat("d", 64)
					}
					return signer, nil
				},
			}
			lease, err := admitSelfActivation(ops)
			if kind == "success" {
				if err != nil || lease == nil || record.closed != 0 || image.closed != 0 || image.reads != 2 {
					t.Fatal("signed image lease not retained", err)
				}
				if err := lease.Close(); err != nil {
					t.Fatal(err)
				}
				if err := lease.Close(); err != nil {
					t.Fatal(err)
				}
				if record.closed != 1 || image.closed != 1 {
					t.Fatal("activation resources not retired exactly once")
				}
				return
			}
			if err == nil || lease != nil {
				t.Fatal("failed signing produced an activation capability", kind)
			}
			if kind != "nil-enrollment-lease" && record.closed != 1 {
				t.Fatal("enrollment resource lost", kind, record.closed)
			}
			if opened != 0 && kind != "nil-image" && image.closed != 1 {
				t.Fatal("image resource lost", kind, image.closed)
			}
			if (kind == "missing-enrollment" || kind == "nil-enrollment-lease") && (opened != 0 || verified != 0) {
				t.Fatal("missing enrollment reached image/verification")
			}
			if (kind == "wrong-digest" || kind == "digest-read") && verified != 0 {
				t.Fatal("unenrolled bytes reached native signer", kind)
			}
		})
	}
}

func TestActivationUnknownRetirementIsStickyAndNeverRetried(t *testing.T) {
	isolateActivationCustody(t)
	resource := &activationTestCloser{err: errors.New("unknown native close")}
	lease := &activationLease{resources: []io.Closer{resource}}
	if lease.Close() == nil || lease.Close() == nil || resource.closed != 1 || custodyReady() == nil {
		t.Fatal("uncertain native retirement reopened or retried")
	}
	calls := 0
	ops := activationIO{
		Load: func() (activationEnrollment, io.Closer, error) {
			calls++
			return testActivationEnrollment(), &activationTestCloser{}, nil
		},
		OpenImage: func() (activationImage, error) { calls++; return &activationTestImage{}, nil },
		Verify:    func(activationImage) (activationSigner, error) { calls++; return testActivationSigner(), nil },
	}
	if result, err := admitSelfActivation(ops); err == nil || result != nil || calls != 0 {
		t.Fatal("unknown custody allowed future admission")
	}
}

func TestNativeSigningGatePrecedesEveryOperationalCommand(t *testing.T) {
	for _, args := range [][]string{nil, {"--validate-only"}, {"--config", `C:\ProgramData\Angerona\watchdog3\config.json`}, {"--service"}} {
		for _, kind := range []string{"missing-gate", "refused", "nil-lease"} {
			t.Run(strings.Join(args, "_")+kind, func(t *testing.T) {
				effects, serviceCalls, gateCalls := 0, 0, 0
				closer := &activationTestCloser{}
				host := commandHost{
					ProgramData:            func() (string, error) { effects++; return "", errors.New("must not read") },
					ReadAdmin:              func(string, int) ([]byte, error) { effects++; return nil, nil },
					ReadPrivate:            func(string, int) ([]byte, error) { effects++; return nil, nil },
					Harden:                 func() error { effects++; return nil },
					EnsurePrivateDirectory: func(string) error { effects++; return nil },
					AcquireInstance:        func(string) (io.Closer, error) { effects++; return nil, nil },
					Run:                    func(configuration, string, []byte, runnerIO) error { effects++; return nil },
				}
				if kind != "missing-gate" {
					host.AdmitSelf = func() (io.Closer, error) {
						gateCalls++
						if kind == "nil-lease" {
							return nil, nil
						}
						return closer, errors.New("private signing failure")
					}
				}
				var out, errs bytes.Buffer
				code := dispatchWatchdogCommand(args, &out, &errs, host, func() int { serviceCalls++; return 0 })
				if code != inactiveSigningExit || effects != 0 || serviceCalls != 0 {
					t.Fatal("unsigned code reached authority/runtime/SCM", args, kind, code, effects, serviceCalls)
				}
				if kind == "refused" && closer.closed != 1 {
					t.Fatal("refused admission leaked lease")
				}
				if strings.Contains(errs.String(), "private signing failure") {
					t.Fatal("private signing error escaped")
				}
				if kind == "missing-gate" && gateCalls != 0 {
					t.Fatal("missing gate called")
				}
			})
		}
	}
}

func TestSignedServiceDispatchRetainsAndRetiresGateLease(t *testing.T) {
	for _, closeFails := range []bool{false, true} {
		isolateActivationCustody(t)
		closer := &activationTestCloser{}
		if closeFails {
			closer.err = errors.New("private close detail")
		}
		host := commandHost{AdmitSelf: func() (io.Closer, error) { return closer, nil }}
		var out, errs bytes.Buffer
		called := 0
		code := dispatchWatchdogCommand([]string{"--service"}, &out, &errs, host, func() int {
			called++
			if closer.closed != 0 {
				t.Fatal("signing lease released before dispatcher")
			}
			return 0
		})
		if called != 1 || closer.closed != 1 || (code == 0) == closeFails {
			t.Fatal("wrong signing lease lifecycle", code, called, closer.closed)
		}
		if strings.Contains(errs.String(), "private close detail") {
			t.Fatal("raw cleanup error escaped")
		}
	}
}

func TestSigningDiagnosticsNeverEnterOperationalAdmission(t *testing.T) {
	for _, self := range []bool{false, true} {
		path := `C:\Program Files\Angerona\watchdog3.exe`
		inspected := 0
		host := signingInspectionHost{
			Executable: func() (string, error) { return path, nil },
			Inspect: func(actual string) (signingInspection, error) {
				inspected++
				if actual != path {
					t.Fatal("wrong selected path")
				}
				return signingInspection{SignatureValid: true, WatchdogSHA256: strings.Repeat("a", 64), CertificateSHA256: strings.Repeat("b", 64), Publisher: "CN=Explicit End User", NotAfter: "2099-01-01T00:00:00Z", Reason: "verified-machine-code-signing-chain", ActivationEligible: true, ModeState: "should-not-escape", ActivationStatus: "should-not-escape"}, nil
			},
		}
		var out, errs bytes.Buffer
		args := []string{path}
		if self {
			args = nil
		}
		if code := runSigningDiagnostic(args, self, &out, &errs, host); code != 0 || inspected != 1 {
			t.Fatal("read-only inspector failed", code, inspected)
		}
		var value map[string]any
		if err := json.Unmarshal(out.Bytes(), &value); err != nil {
			t.Fatal(err)
		}
		if len(value) != 10 || value["signature_valid"] != true || value["activation_eligible"] != false || value["mode_state"] != "diagnostic" || value["activation_status"] != "not-assessed-by-diagnostic" {
			t.Fatal("diagnostic became activation authority", value)
		}
	}
}

func TestSigningInspectionRejectsPathsAndMixedOptionsBeforeNativeWork(t *testing.T) {
	for _, args := range [][]string{nil, {"--service"}, {`\\host\share\watchdog3.exe`}, {`C:\x\..\watchdog3.exe`}, {`C:\x.ps1`}, {`C:\x.exe`, "--service"}} {
		calls := 0
		host := signingInspectionHost{Inspect: func(string) (signingInspection, error) { calls++; return signingInspection{}, nil }}
		var out, errs bytes.Buffer
		code := runSigningDiagnostic(args, false, &out, &errs, host)
		if calls != 0 {
			t.Fatal("invalid path/options reached native signing", args)
		}
		if len(args) != 1 && code != 2 {
			t.Fatal("mixed inspection arguments accepted", args, code)
		}
	}
}

func TestActivationNTPathRejectsNetworkSubstitutionAndAmbiguity(t *testing.T) {
	path := `C:\Program Files\Angerona\watchdog3.exe`
	got, err := activationNTPath(path, `\Device\HarddiskVolume12`)
	if err != nil || got != `\Device\HarddiskVolume12\Program Files\Angerona\watchdog3.exe` {
		t.Fatal(got, err)
	}
	for _, device := range []string{`\Device\Mup\server`, `\??\C:\shadow`, `\Device\HarddiskVolume`, `\Device\HarddiskVolumeShadowCopy12`, `\Device\HarddiskVolume12\escape`} {
		if _, err := activationNTPath(path, device); err == nil {
			t.Fatal("non-fixed device accepted", device)
		}
	}
	for _, path := range []string{`C:\x\..\watchdog3.exe`, `\\server\share\watchdog3.exe`, `C:\x.exe:stream`, `C:watchdog3.exe`} {
		if _, err := activationNTPath(path, `\Device\HarddiskVolume12`); err == nil {
			t.Fatal("ambiguous path accepted", path)
		}
	}
}
func TestSigningDiagnosticRejectsInvalidOrUnavailableProof(t *testing.T) {
	for _, kind := range []string{"nil-inspector", "inspector-error", "expired", "bad-expiry", "wrong-image-digest", "wrong-cert-digest", "publisher-control", "publisher-too-long", "reason-too-long", "unsigned-clears-identity"} {
		t.Run(kind, func(t *testing.T) {
			proof := signingInspection{SignatureValid: true, WatchdogSHA256: strings.Repeat("a", 64), CertificateSHA256: strings.Repeat("b", 64), Publisher: "CN=Explicit End User", NotAfter: "2099-01-01T00:00:00Z", Reason: "verified-machine-code-signing-chain"}
			switch kind {
			case "expired":
				proof.NotAfter = "2000-01-01T00:00:00Z"
			case "bad-expiry":
				proof.NotAfter = "unknown"
			case "wrong-image-digest":
				proof.WatchdogSHA256 = "not-a-digest"
			case "wrong-cert-digest":
				proof.CertificateSHA256 = strings.Repeat("B", 64)
			case "publisher-control":
				proof.Publisher = "CN=operator\n"
			case "publisher-too-long":
				proof.Publisher = strings.Repeat("x", 2049)
			case "reason-too-long":
				proof.Reason = strings.Repeat("x", 97)
			case "unsigned-clears-identity":
				proof.SignatureValid = false
			}
			host := signingInspectionHost{Inspect: func(string) (signingInspection, error) {
				if kind == "inspector-error" {
					return proof, errors.New("private provider failure")
				}
				return proof, nil
			}}
			if kind == "nil-inspector" {
				host.Inspect = nil
			}
			var out, errs bytes.Buffer
			if code := runSigningDiagnostic([]string{`C:\Selected\watchdog3.exe`}, false, &out, &errs, host); code != 0 {
				t.Fatal("unavailable diagnostic did not return closed metadata", code)
			}
			var result signingInspection
			if err := json.Unmarshal(out.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if result.SignatureValid || result.CertificateSHA256 != "" || result.Publisher != "" || result.NotAfter != "" || result.ActivationEligible {
				t.Fatal("unavailable proof became verified signer", kind, result)
			}
			if strings.Contains(out.String(), "private provider failure") {
				t.Fatal("provider error escaped")
			}
		})
	}
}

func TestSigningDiagnosticsVersionAndHelpNeedNoActivation(t *testing.T) {
	for _, args := range [][]string{{"--version"}, {"--help"}} {
		calls := 0
		host := commandHost{AdmitSelf: func() (io.Closer, error) { calls++; return nil, errors.New("must stay inert") }}
		var out, errs bytes.Buffer
		if code := dispatchWatchdogCommand(args, &out, &errs, host, func() int { t.Fatal("diagnostic reached SCM"); return 0 }); code != 0 || calls != 0 {
			t.Fatal("version/help requested activation", args, code, calls)
		}
	}
}

func TestUncertainWinTrustRetainsImageWithoutRetryingClose(t *testing.T) {
	isolateActivationCustody(t)
	hold := &pathHold{}
	image := &nativeActivationImage{hold: hold, retirementHeld: true}
	if image.Close() == nil || image.Close() == nil || image.hold != hold || custodyReady() == nil {
		t.Fatal("uncertain provider owner was not quarantined")
	}
}

// Exercise the real local-file/NtCreateFile path, not a substituted trust host.
// The only selected image is an unsigned copy of this Go test executable in
// testing's private temporary directory. It is inspected as data, never run.
func TestNativeSigningInspectionReadsUnsignedCopy(t *testing.T) {
	if err := custodyReady(); err != nil {
		t.Fatalf("native signing custody was already held: %v", err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 || len(raw) > activationImageLimit {
		t.Fatal("test executable exceeds the bounded signing fixture")
	}
	directory := t.TempDir()
	selected := filepath.Join(directory, "unsigned-inspection.exe")
	if err := os.WriteFile(selected, raw, 0600); err != nil {
		t.Fatal(err)
	}
	expected := sha256.Sum256(raw)
	result, inspectErr := nativeInspectSigning(selected)
	if inspectErr != nil {
		t.Fatalf("real unsigned inspection failed before metadata: reason=%q hash=%q error=%T: %v",
			result.Reason, result.WatchdogSHA256, inspectErr, inspectErr)
	}
	if result.WatchdogSHA256 != hex.EncodeToString(expected[:]) {
		t.Fatalf("real unsigned inspection lost its retained-byte digest: reason=%q hash=%q",
			result.Reason, result.WatchdogSHA256)
	}
	if result.SignatureValid || result.ActivationEligible || result.CertificateSHA256 != "" || result.Publisher != "" || result.NotAfter != "" {
		t.Fatal("unsigned file inspection manufactured signing or activation authority")
	}
	if result.Schema != 1 || result.ModeState != "diagnostic" || result.ActivationStatus != "not-assessed-by-diagnostic" {
		t.Fatal("read-only inspection lost its diagnostic boundary")
	}
	if err := custodyReady(); err != nil {
		t.Fatalf("read-only inspection retained uncertain native custody: %v", err)
	}
	// A still-retained FILE_SHARE_READ lease denies this Windows rename. Verify
	// exact inspection leases retired before testing removes its own directory.
	if err := os.Rename(selected, filepath.Join(directory, "retired-inspection.exe")); err != nil {
		t.Fatalf("read-only inspection did not release its selected file: %v", err)
	}
}
