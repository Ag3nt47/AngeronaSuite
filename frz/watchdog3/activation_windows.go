//go:build windows

package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
	"unsafe"

	"golang.org/x/sys/windows"
)

const activationLimit = 8 * 1024
const activationImageLimit = 64 * 1024 * 1024
const inactiveSigningExit = 5

// This record is separate from the six-field engine configuration. It can only
// be provisioned through independently governed administrator enrollment after
// the final watchdog bytes have been signed. It is never learned from a bundle.
type activationEnrollment struct {
	Schema            int    `json:"schema"`
	Enabled           bool   `json:"enabled"`
	WatchdogSHA256    string `json:"watchdog_sha256"`
	CertificateSHA256 string `json:"certificate_sha256"`
	Publisher         string `json:"publisher"`
}

type activationSigner struct {
	CertificateSHA256 string
	Publisher         string
	NotAfter          string
}

func exactActivationDigest(value string) bool {
	return len(value) == 64 && strings.Trim(value, "0123456789abcdef") == "" &&
		value != strings.Repeat("0", 64)
}

func decodeActivation(raw []byte) (activationEnrollment, error) {
	var value activationEnrollment
	if len(raw) == 0 || len(raw) > activationLimit || !utf8.Valid(raw) {
		return value, errors.New("signing enrollment size or encoding is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return value, errors.New("signing enrollment is not an object")
	}
	allowed := map[string]bool{"schema": true, "enabled": true, "watchdog_sha256": true, "certificate_sha256": true, "publisher": true}
	seen := map[string]bool{}
	for decoder.More() {
		key, err := decoder.Token()
		name, ok := key.(string)
		if err != nil || !ok || !allowed[name] || seen[name] {
			return value, errors.New("signing enrollment has duplicate or unknown fields")
		}
		seen[name] = true
		var field json.RawMessage
		if decoder.Decode(&field) != nil {
			return value, errors.New("signing enrollment field is malformed")
		}
	}
	if _, err := decoder.Token(); err != nil {
		return value, errors.New("signing enrollment is incomplete")
	}
	if _, err := decoder.Token(); err != io.EOF || len(seen) != len(allowed) {
		return value, errors.New("signing enrollment is incomplete or has trailing data")
	}
	decoder = json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil || value.Schema != 1 || !value.Enabled {
		return value, errors.New("watchdog signing is not explicitly enabled")
	}
	if !exactActivationDigest(value.WatchdogSHA256) || !exactActivationDigest(value.CertificateSHA256) {
		return value, errors.New("signing enrollment pins are invalid")
	}
	if len(value.Publisher) == 0 || len(value.Publisher) > 2048 ||
		strings.TrimSpace(value.Publisher) != value.Publisher ||
		strings.IndexFunc(value.Publisher, unicode.IsControl) >= 0 {
		return value, errors.New("signing enrollment publisher is invalid")
	}
	return value, nil
}

// A successful signature result without the independently enrolled final digest
// and exact leaf identity is never activation authority.
func checkActivationBinding(enrollment activationEnrollment, digest string, signer activationSigner) error {
	if !enrollment.Enabled || enrollment.Schema != 1 ||
		!exactActivationDigest(digest) ||
		digest != enrollment.WatchdogSHA256 ||
		!exactActivationDigest(signer.CertificateSHA256) ||
		signer.CertificateSHA256 != enrollment.CertificateSHA256 ||
		signer.Publisher == "" || signer.Publisher != enrollment.Publisher {
		return errors.New("signed watchdog does not match explicit enrollment")
	}
	return nil
}

type activationImage interface {
	io.Closer
	Digest() (string, error)
}

type activationIO struct {
	Load      func() (activationEnrollment, io.Closer, error)
	OpenImage func() (activationImage, error)
	Verify    func(activationImage) (activationSigner, error)
}

type activationLease struct {
	once      sync.Once
	resources []io.Closer
	err       error
}

func (lease *activationLease) Close() error {
	lease.once.Do(func() {
		for index := len(lease.resources) - 1; index >= 0; index-- {
			lease.err = errors.Join(lease.err, lease.resources[index].Close())
		}
		lease.resources = nil
		lease.err = holdCustody(lease.err)
	})
	return lease.err
}

func admitSelfActivation(ops activationIO) (result io.Closer, resultErr error) {
	if ops.Load == nil || ops.OpenImage == nil || ops.Verify == nil {
		return nil, errors.New("native signing admission dependency unavailable")
	}
	if err := custodyReady(); err != nil {
		return nil, err
	}
	lease := &activationLease{}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, lease.Close())
			result = nil
		}
	}()
	enrollment, record, err := ops.Load()
	if record != nil {
		lease.resources = append(lease.resources, record)
	}
	if err != nil || record == nil {
		return nil, errors.Join(err, errors.New("explicit signing enrollment unavailable"))
	}
	image, err := ops.OpenImage()
	if image != nil {
		lease.resources = append(lease.resources, image)
	}
	if err != nil || image == nil {
		return nil, errors.Join(err, errors.New("own image custody unavailable"))
	}
	digest, err := image.Digest()
	if err != nil || digest != enrollment.WatchdogSHA256 {
		return nil, errors.Join(err, errors.New("final signed watchdog digest not enrolled"))
	}
	signer, err := ops.Verify(image)
	if err != nil {
		return nil, errors.New("own native Authenticode admission failed")
	}
	if err := checkActivationBinding(enrollment, digest, signer); err != nil {
		return nil, err
	}
	// Rehash through the same retained file. No pathname reopen supplies proof.
	after, err := image.Digest()
	if err != nil || after != digest {
		return nil, errors.Join(err, errors.New("own image changed during signing admission"))
	}
	return lease, nil
}

func openCommandActivation(host commandHost) (io.Closer, error) {
	if host.AdmitSelf == nil {
		return nil, errors.New("watchdog signing admission is unavailable")
	}
	lease, err := host.AdmitSelf()
	if err != nil || lease == nil {
		if lease != nil {
			err = errors.Join(err, holdCustody(lease.Close()))
		}
		return nil, errors.Join(err, errors.New("watchdog signing is not enrolled"))
	}
	return lease, nil
}

func closeCommandActivation(lease io.Closer, stderr io.Writer, code *int) {
	if err := lease.Close(); err != nil {
		holdCustody(err)
		io.WriteString(stderr, "Watchdog3 inactive: signing admission cleanup is unverified.\n")
		if *code == 0 {
			*code = 1
		}
	}
}

type nativeActivationImage struct {
	hold           *pathHold
	path           string
	adminOnly      bool
	retirementHeld bool
}

func (image *nativeActivationImage) Close() error {
	if image == nil || image.hold == nil {
		return nil
	}
	if image.retirementHeld {
		// Provider state may still reference this exact handle. Quarantine it
		// with its input owners until process exit; never reuse or retry it.
		return holdCustody(errors.New("native signature image retirement is held"))
	}
	return image.hold.Close()
}
func (image *nativeActivationImage) Digest() (string, error) {
	if image == nil || image.hold == nil || image.hold.file == nil {
		return "", errors.New("own image is not retained")
	}
	info, err := fileInformation(windows.Handle(image.hold.file.Fd()), false)
	if err != nil {
		return "", err
	}
	before := image.hold.info
	if info.VolumeSerialNumber != before.VolumeSerialNumber || info.FileIndexHigh != before.FileIndexHigh ||
		info.FileIndexLow != before.FileIndexLow || info.FileSizeHigh != before.FileSizeHigh ||
		info.FileSizeLow != before.FileSizeLow || info.FileSizeHigh != 0 ||
		info.FileSizeLow == 0 || info.FileSizeLow > activationImageLimit {
		return "", errors.New("own image identity or bound changed")
	}
	if err := checkCustody(windows.Handle(image.hold.file.Fd()), image.adminOnly, false); err != nil {
		return "", err
	}
	if _, err := image.hold.file.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	digest := sha256.New()
	count, err := io.Copy(digest, io.LimitReader(image.hold.file, activationImageLimit+1))
	if err != nil || count != int64(info.FileSizeLow) {
		return "", errors.New("own image digest is incomplete")
	}
	if _, err := image.hold.file.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func loadNativeActivation() (value activationEnrollment, result io.Closer, resultErr error) {
	if err := custodyReady(); err != nil {
		return value, nil, err
	}
	base, err := programDataDirectory()
	if err != nil {
		return value, nil, err
	}
	for _, directory := range []string{filepath.Join(base, "Angerona"), filepath.Join(base, "Angerona", "watchdog3")} {
		hold, err := openActivationHeld(directory, true, true)
		if err != nil {
			return value, nil, err
		}
		if err := hold.Close(); err != nil {
			return value, nil, err
		}
	}
	path := filepath.Join(base, "Angerona", "watchdog3", "activation.json")
	record, err := openActivationHeld(path, false, true)
	if err != nil {
		return value, nil, err
	}
	result = record
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, record.Close())
			result = nil
		}
	}()
	if record.info.FileSizeHigh != 0 || record.info.FileSizeLow > activationLimit {
		return value, result, errors.New("signing enrollment exceeds its byte bound")
	}
	raw, err := io.ReadAll(io.LimitReader(record.file, activationLimit+1))
	if err != nil || len(raw) > activationLimit || len(raw) != int(record.info.FileSizeLow) {
		return value, result, errors.New("signing enrollment read is incomplete")
	}
	after, err := fileInformation(windows.Handle(record.file.Fd()), false)
	if err != nil || after.VolumeSerialNumber != record.info.VolumeSerialNumber ||
		after.FileIndexHigh != record.info.FileIndexHigh || after.FileIndexLow != record.info.FileIndexLow ||
		after.FileSizeHigh != record.info.FileSizeHigh || after.FileSizeLow != record.info.FileSizeLow {
		return value, result, errors.New("signing enrollment identity changed during read")
	}
	if err := checkCustody(windows.Handle(record.file.Fd()), true, false); err != nil {
		return value, result, err
	}
	value, err = decodeActivation(raw)
	if err != nil {
		return value, result, err
	}
	return value, result, nil
}

func openNativeActivationImage() (activationImage, error) {
	path, err := os.Executable()
	if err != nil || !strings.EqualFold(filepath.Base(path), "watchdog3.exe") {
		return nil, errors.New("own image path is unavailable or not the final watchdog")
	}
	if _, err := localPath(path); err != nil {
		return nil, err
	}
	hold, err := openActivationHeld(path, false, true)
	if err != nil {
		return nil, err
	}
	return &nativeActivationImage{hold: hold, path: hold.file.Name(), adminOnly: true}, nil
}

func nativeSelfActivation() (io.Closer, error) {
	return admitSelfActivation(activationIO{Load: loadNativeActivation, OpenImage: openNativeActivationImage, Verify: verifyNativeActivationImage})
}

// These are opaque trust-provider records. The certificate accessor, rather
// than pointer arithmetic across a provider array, retrieves the first leaf.
type providerSignerPrefix struct {
	Size             uint32
	VerifyAsOf       windows.Filetime
	CertificateCount uint32
	CertificateChain uintptr
	SignerType       uint32
	SignerInfo       uintptr
	Error            uint32
}

// WinTrust returns pointers into its stable foreign allocation, owned by
// StateData until CLOSE. Bit-copy that native address; it is never a derived
// Go-heap uintptr and cannot outlive the retained provider state.
func foreignProviderPointer(address uintptr) unsafe.Pointer {
	return *(*unsafe.Pointer)(unsafe.Pointer(&address))
}

type providerCertificatePrefix struct {
	Size uint32
	Cert *windows.CertContext
}

var activationTrustDLL = windows.NewLazySystemDLL("wintrust.dll")
var activationProviderData = activationTrustDLL.NewProc("WTHelperProvDataFromStateData")
var activationProviderSigner = activationTrustDLL.NewProc("WTHelperGetProvSignerFromChain")
var activationProviderCert = activationTrustDLL.NewProc("WTHelperGetProvCertFromChain")

// If a provider's CLOSE result is unknown, preserve its Go input owners and
// globally hold all later native allocations. Never retry that state handle.
var retainedActivationTrustState *activationTrustInputs
var activationTrustMu sync.Mutex

type activationTrustInputs struct {
	HeldImage *nativeActivationImage
	Path      *uint16
	FileInfo  windows.WinTrustFileInfo
	Settings  windows.WinTrustSignatureSettings
	Data      windows.WinTrustData
}

func verifyNativeActivationImage(image activationImage) (identity activationSigner, resultErr error) {
	native, ok := image.(*nativeActivationImage)
	if !ok || native == nil || native.hold == nil || native.hold.file == nil {
		return identity, errors.New("native signature requires the retained own image")
	}
	// Serialize the provider owner so at most one uncertain state can be
	// quarantined; a sticky hold refuses every subsequent verification.
	activationTrustMu.Lock()
	defer activationTrustMu.Unlock()
	if err := custodyReady(); err != nil {
		return identity, err
	}
	path, err := windows.UTF16PtrFromString(native.path)
	if err != nil {
		return identity, err
	}
	input := &activationTrustInputs{Path: path, HeldImage: native}
	input.FileInfo = windows.WinTrustFileInfo{Size: uint32(unsafe.Sizeof(windows.WinTrustFileInfo{})), FilePath: path, File: windows.Handle(native.hold.file.Fd())}
	input.Settings.Size = uint32(unsafe.Sizeof(input.Settings))
	input.Settings.Index = 0
	input.Settings.Flags = 1 // WSS_VERIFY_SPECIFIC; bind provider signer zero.
	input.Data = windows.WinTrustData{
		Size:     uint32(unsafe.Sizeof(windows.WinTrustData{})),
		UIChoice: windows.WTD_UI_NONE, RevocationChecks: windows.WTD_REVOKE_WHOLECHAIN,
		UnionChoice: windows.WTD_CHOICE_FILE, FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(&input.FileInfo),
		StateAction: windows.WTD_STATEACTION_VERIFY,
		ProvFlags: windows.WTD_CACHE_ONLY_URL_RETRIEVAL | windows.WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT |
			windows.WTD_DISABLE_MD2_MD4 | windows.WTD_LIFETIME_SIGNING_FLAG,
		SignatureSettings: &input.Settings,
	}
	defer func() {
		input.Data.StateAction = windows.WTD_STATEACTION_CLOSE
		if err := windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, &input.Data); err != nil {
			custodyMu.Lock()
			native.retirementHeld = true
			if retainedActivationTrustState == nil {
				retainedActivationTrustState = input
			}
			custodyMu.Unlock()
			resultErr = errors.Join(resultErr, holdCustody(errors.New("native signature state cleanup is unverified")))
		}
		runtime.KeepAlive(input)
		if resultErr != nil {
			identity = activationSigner{}
		}
	}()
	if err := windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, &input.Data); err != nil ||
		input.Data.StateData == 0 || input.Settings.VerifiedSigIndex != 0 {
		return identity, errors.New("native own-image signature is unavailable or invalid")
	}
	for _, proc := range []*windows.LazyProc{activationProviderData, activationProviderSigner, activationProviderCert} {
		if err := proc.Find(); err != nil {
			return identity, errors.New("native verified signer accessor unavailable")
		}
	}
	provider, _, _ := activationProviderData.Call(uintptr(input.Data.StateData))
	if provider == 0 {
		return identity, errors.New("native signature state has no provider")
	}
	signer, _, _ := activationProviderSigner.Call(provider, 0, 0, 0)
	if signer == 0 {
		return identity, errors.New("native signature state has no verified signer")
	}
	signerInfo := (*providerSignerPrefix)(foreignProviderPointer(signer))
	if signerInfo.Size < uint32(unsafe.Sizeof(*signerInfo)) || signerInfo.CertificateCount == 0 || signerInfo.CertificateCount > 32 || signerInfo.CertificateChain == 0 || signerInfo.Error != 0 {
		return identity, errors.New("native verified signer chain is unavailable")
	}
	certificate, _, _ := activationProviderCert.Call(signer, 0)
	if certificate == 0 {
		return identity, errors.New("native signature state has no signer certificate")
	}
	prefix := (*providerCertificatePrefix)(foreignProviderPointer(certificate))
	if prefix.Size < uint32(unsafe.Sizeof(*prefix)) || prefix.Cert == nil {
		return identity, errors.New("native signer certificate shape is invalid")
	}
	leaf := prefix.Cert
	if leaf.EncodedCert == nil || leaf.Length == 0 || leaf.Length > 64*1024 {
		return identity, errors.New("native signer certificate is unavailable or oversized")
	}
	der := append([]byte(nil), unsafe.Slice(leaf.EncodedCert, int(leaf.Length))...)
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return identity, errors.New("native signer certificate cannot be parsed")
	}
	if err := verifyActivationMachineChain(leaf); err != nil {
		return identity, err
	}
	digest := sha256.Sum256(der)
	return activationSigner{CertificateSHA256: hex.EncodeToString(digest[:]), Publisher: parsed.Subject.String(), NotAfter: parsed.NotAfter.UTC().Format(time.RFC3339)}, nil
}

func verifyActivationMachineChain(leaf *windows.CertContext) error {
	// HCCE_LOCAL_MACHINE (1) excludes current-user roots. All additional
	// certificates supply intermediates only; they do not grant root trust.
	const machineChainEngine = windows.Handle(1)
	const cacheOnlyChain = uint32(0x4)
	const disableAuthRootUpdate = uint32(0x100)
	const disableAIA = uint32(0x2000)
	const revocationChainExcludeRoot = uint32(0x40000000)
	const revocationCacheOnly = uint32(0x80000000)
	usageOID := []byte("1.3.6.1.5.5.7.3.3\x00")
	usagePointer := &usageOID[0]
	para := windows.CertChainPara{
		Size:           uint32(unsafe.Sizeof(windows.CertChainPara{})),
		RequestedUsage: windows.CertUsageMatch{Type: 0, Usage: windows.CertEnhKeyUsage{Length: 1, UsageIdentifiers: &usagePointer}},
	}
	var chain *windows.CertChainContext
	err := windows.CertGetCertificateChain(machineChainEngine, leaf, nil, leaf.Store, &para,
		cacheOnlyChain|disableAuthRootUpdate|disableAIA|revocationChainExcludeRoot|revocationCacheOnly, 0, &chain)
	runtime.KeepAlive(usageOID)
	runtime.KeepAlive(usagePointer)
	if chain != nil {
		defer windows.CertFreeCertificateChain(chain)
	}
	if err != nil || chain == nil || chain.Size < uint32(unsafe.Sizeof(*chain)) ||
		chain.ChainCount == 0 || chain.ChainCount > 64 || chain.TrustStatus.ErrorStatus != 0 {
		return errors.New("signer does not have a valid machine-context code-signing chain")
	}
	policy := windows.CertChainPolicyPara{Size: uint32(unsafe.Sizeof(windows.CertChainPolicyPara{}))}
	status := windows.CertChainPolicyStatus{Size: uint32(unsafe.Sizeof(windows.CertChainPolicyStatus{}))}
	if err := windows.CertVerifyCertificateChainPolicy(windows.CERT_CHAIN_POLICY_AUTHENTICODE, chain, &policy, &status); err != nil || status.Error != 0 {
		return errors.New("machine-context Authenticode policy did not approve the signer")
	}
	return nil
}

// The selected-file inspector accepts only fixed local NT volumes. It does not
// execute the selected image or follow DOS-device substitutions/reparse points.
func activationNTPath(path, device string) (string, error) {
	if _, err := localPath(path); err != nil {
		return "", err
	}
	const prefix = `\Device\HarddiskVolume`
	number := strings.TrimPrefix(device, prefix)
	if number == device || number == "" || strings.Trim(number, "0123456789") != "" {
		return "", errors.New("signing path is not a fixed local NT volume")
	}
	volume := filepath.VolumeName(path)
	return device + path[len(volume):], nil
}

func nativeActivationNTPath(path string) (string, error) {
	if _, err := localPath(path); err != nil {
		return "", err
	}
	volume := filepath.VolumeName(path)
	root, err := windows.UTF16PtrFromString(volume + `\`)
	if err != nil || windows.GetDriveType(root) != windows.DRIVE_FIXED {
		return "", errors.New("signing path is not on a fixed local drive")
	}
	name, err := windows.UTF16PtrFromString(volume)
	if err != nil {
		return "", err
	}
	target := make([]uint16, 32768)
	length, err := windows.QueryDosDevice(name, &target[0], uint32(len(target)))
	if err != nil || length == 0 || length > uint32(len(target)) {
		return "", errors.New("signing path device mapping is unavailable")
	}
	return activationNTPath(path, windows.UTF16ToString(target[:length]))
}

func activationNTObject(name string, directory bool) (windows.Handle, error) {
	if err := custodyReady(); err != nil {
		return windows.InvalidHandle, err
	}
	encoded, err := windows.UTF16FromString(name)
	if err != nil || len(encoded) > 32760 {
		return windows.InvalidHandle, errors.New("native signing path is malformed")
	}
	nativeName := windows.NTUnicodeString{Length: uint16((len(encoded) - 1) * 2), MaximumLength: uint16(len(encoded) * 2), Buffer: &encoded[0]}
	attributes := windows.OBJECT_ATTRIBUTES{Length: uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})), ObjectName: &nativeName, Attributes: windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE}
	access := uint32(windows.READ_CONTROL | windows.FILE_READ_ATTRIBUTES | windows.SYNCHRONIZE)
	options := uint32(windows.FILE_OPEN_REPARSE_POINT | windows.FILE_SYNCHRONOUS_IO_NONALERT)
	if directory {
		options |= windows.FILE_DIRECTORY_FILE
	} else {
		access |= windows.FILE_READ_DATA
		options |= windows.FILE_NON_DIRECTORY_FILE
	}
	var handle windows.Handle
	var status windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(&handle, access, &attributes, &status, nil, 0, windows.FILE_SHARE_READ, windows.FILE_OPEN, options, 0, 0)
	runtime.KeepAlive(encoded)
	runtime.KeepAlive(nativeName)
	runtime.KeepAlive(attributes)
	if err != nil {
		if handle != 0 && handle != windows.InvalidHandle {
			err = errors.Join(err, retireNative(handle))
		}
		return windows.InvalidHandle, err
	}
	if handle == 0 || handle == windows.InvalidHandle {
		return windows.InvalidHandle, errors.New("native signing open returned no object")
	}
	if _, err := fileInformation(handle, directory); err != nil {
		return windows.InvalidHandle, errors.Join(err, retireNative(handle))
	}
	return handle, nil
}

func openActivationHeld(path string, directory, adminOnly bool) (*pathHold, error) {
	nativePath, err := nativeActivationNTPath(path)
	if err != nil {
		return nil, err
	}
	if depth := strings.Count(nativePath, `\`); depth > 66 {
		return nil, errors.New("signing ancestry exceeds its bounded scope")
	}
	hold := &pathHold{}
	// Keep the already-resolved local ancestors while signing inspects its file
	// handle. Every open independently refuses any intervening reparse point.
	for index := len(`\Device\`); index < len(nativePath); index++ {
		if nativePath[index] != '\\' {
			continue
		}
		parent := nativePath[:index]
		if strings.Count(parent, `\`) < 2 {
			continue
		}
		parent += `\`
		handle, err := activationNTObject(parent, true)
		if err != nil {
			return nil, errors.Join(err, hold.Close())
		}
		hold.parents = append(hold.parents, handle)
	}
	handle, err := activationNTObject(nativePath, directory)
	if err != nil {
		return nil, errors.Join(err, hold.Close())
	}
	hold.file = os.NewFile(uintptr(handle), `\\?\GLOBALROOT`+nativePath)
	if hold.file == nil {
		return nil, errors.Join(errors.New("native signing file owner unavailable"), retireNative(handle), hold.Close())
	}
	if err := checkCustody(handle, adminOnly, false); err != nil {
		return nil, errors.Join(err, hold.Close())
	}
	hold.info, err = fileInformation(handle, directory)
	if err != nil {
		return nil, errors.Join(err, hold.Close())
	}
	return hold, nil
}

type signingInspection struct {
	Schema             int    `json:"schema"`
	SignatureValid     bool   `json:"signature_valid"`
	WatchdogSHA256     string `json:"watchdog_sha256"`
	CertificateSHA256  string `json:"certificate_sha256"`
	Publisher          string `json:"publisher"`
	NotAfter           string `json:"not_after"`
	Reason             string `json:"reason"`
	ActivationEligible bool   `json:"activation_eligible"`
	ModeState          string `json:"mode_state"`
	ActivationStatus   string `json:"activation_status"`
}

func unavailableSigningInspection(reason string) signingInspection {
	return signingInspection{Schema: 1, Reason: reason, ModeState: "diagnostic", ActivationStatus: "not-assessed-by-diagnostic"}
}

// This metadata has no activation authority. The observer binds its own cached
// copy separately to its actual process/session and admitted bundle digest.
func nativeInspectSigning(path string) (result signingInspection, resultErr error) {
	result = unavailableSigningInspection("image-custody-unavailable")
	if !strings.EqualFold(filepath.Ext(path), ".exe") {
		return result, errors.New("signing inspection requires a local executable")
	}
	hold, err := openActivationHeld(path, false, false)
	if err != nil {
		return result, err
	}
	image := &nativeActivationImage{hold: hold, path: hold.file.Name(), adminOnly: false}
	defer func() {
		if err := image.Close(); err != nil {
			result = unavailableSigningInspection("resource-retirement-unverified")
			resultErr = err
		}
	}()
	digest, err := image.Digest()
	if err != nil {
		return result, err
	}
	result.WatchdogSHA256 = digest
	result.Reason = "signature-unavailable-or-invalid"
	signer, err := verifyNativeActivationImage(image)
	if err != nil {
		return result, nil
	}
	after, err := image.Digest()
	if err != nil || after != digest {
		result.Reason = "image-changed-during-inspection"
		return result, errors.New("signing inspection image changed")
	}
	expiry, expiryErr := time.Parse(time.RFC3339, signer.NotAfter)
	if !exactActivationDigest(signer.CertificateSHA256) || len(signer.Publisher) == 0 || len(signer.Publisher) > 2048 ||
		strings.IndexFunc(signer.Publisher, unicode.IsControl) >= 0 || expiryErr != nil || !expiry.After(time.Now()) {
		return result, errors.New("signer inspection metadata is unavailable")
	}
	result.SignatureValid = true
	result.CertificateSHA256 = signer.CertificateSHA256
	result.Publisher = signer.Publisher
	result.NotAfter = signer.NotAfter
	result.Reason = "verified-machine-code-signing-chain"
	return result, nil
}

type signingInspectionHost struct {
	Inspect    func(string) (signingInspection, error)
	Executable func() (string, error)
}

func nativeSigningInspectionHost() signingInspectionHost {
	return signingInspectionHost{Inspect: nativeInspectSigning, Executable: os.Executable}
}

func runSigningDiagnostic(arguments []string, self bool, stdout, stderr io.Writer, host signingInspectionHost) int {
	path := ""
	if self {
		if len(arguments) != 0 || host.Executable == nil {
			io.WriteString(stderr, "Signing status accepts no additional arguments.\n")
			return 2
		}
		var err error
		path, err = host.Executable()
		if err != nil {
			path = ""
		}
	} else {
		if len(arguments) != 1 {
			io.WriteString(stderr, "Signing inspection requires one selected executable path.\n")
			return 2
		}
		path = arguments[0]
	}
	result := unavailableSigningInspection("inspection-unavailable")
	if _, err := localPath(path); err == nil && strings.EqualFold(filepath.Ext(path), ".exe") && host.Inspect != nil {
		snapshot, err := host.Inspect(path)
		if err == nil {
			result = snapshot
		}
	}
	if result.SignatureValid {
		expiry, err := time.Parse(time.RFC3339, result.NotAfter)
		if !exactActivationDigest(result.WatchdogSHA256) || !exactActivationDigest(result.CertificateSHA256) ||
			len(result.Publisher) == 0 || strings.IndexFunc(result.Publisher, unicode.IsControl) >= 0 || err != nil || !expiry.After(time.Now()) {
			result = unavailableSigningInspection("inspection-unavailable")
		}
	} else {
		result.CertificateSHA256, result.Publisher, result.NotAfter = "", "", ""
	}
	// The diagnostic is incapable of granting enrollment or operational state.
	result.Schema = 1
	result.ActivationEligible = false
	result.ModeState = "diagnostic"
	result.ActivationStatus = "not-assessed-by-diagnostic"
	if len(result.Publisher) > 2048 || len(result.Reason) > 96 || len(result.NotAfter) > 32 ||
		(result.WatchdogSHA256 != "" && !exactActivationDigest(result.WatchdogSHA256)) ||
		(result.CertificateSHA256 != "" && !exactActivationDigest(result.CertificateSHA256)) {
		result = unavailableSigningInspection("inspection-unavailable")
	}
	raw, err := json.Marshal(result)
	if err != nil || len(raw) > 4096 {
		return 1
	}
	if _, err := stdout.Write(append(raw, '\n')); err != nil {
		return 1
	}
	return 0
}
