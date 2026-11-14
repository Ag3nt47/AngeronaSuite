"""Optional macOS support pack: pinned download, installation and launch gate.

The support pack is a separate repository of macOS-specific modules and
operational scripts.  It is never fetched without the user's explicit consent,
and Angerona works without it.

Trust model
-----------
``release/macos-support-pack.json`` in this reviewed source tree pins one commit
of the support repository and the SHA-256 of its ``pack-manifest.json``.  That
manifest lists every installable file with its own size and SHA-256, so the one
reviewed digest binds every byte.  Files are fetched individually over HTTPS
from the pinned commit, redirects are refused, and nothing is written into the
live installation until every byte has verified.  No archive is extracted and
no downloaded code runs during installation.

The pack's modules are unsigned.  They can therefore load only through the
existing unsigned-development override, which this module enables at launch
solely when the module folder contains exactly the pinned pack's modules, and
always with a visible reduced-security notice.  Any other drop-in file, or a
changed support module, keeps the override off.

Standard library only: this file is also used by ``tools/macos_support_pack.py``
before the application starts.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping, MutableMapping, TextIO

CANONICAL_REPOSITORY = "Ag3nt47/Angerona-macOS-Support"
PIN_RELATIVE_PATH = "release/macos-support-pack.json"
PIN_SCHEMA = "angerona.macos-support-pin/v1"
MANIFEST_SCHEMA = "angerona.macos-support-pack/v1"
RECEIPT_SCHEMA = "angerona.macos-support-receipt/v1"
MODULE_TRUST = "unsigned-hash-pinned"
RAW_HOST = "raw.githubusercontent.com"

MAX_PIN_BYTES = 64 * 1024
MAX_MANIFEST_BYTES = 256 * 1024
MAX_FILE_BYTES = 1024 * 1024
MAX_TOTAL_BYTES = 16 * 1024 * 1024
MAX_FILES = 256
NETWORK_TIMEOUT_SECONDS = 30.0

REDUCED_SECURITY_NOTICE = (
    "Angerona: the optional macOS support modules are enabled. They are unsigned "
    "(verified by SHA-256 pin only), so this start uses the reduced-security "
    "development override, which also allows in-app source editing. "
    "Disable with: tools/macos_support_pack.py disable"
)

_COMMIT = re.compile(r"[0-9a-f]{40}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_VERSION = re.compile(r"\d{1,4}\.\d{1,4}\.\d{1,4}")
_PACK_PATH = re.compile(
    r"(?:(?:modules|scripts|docs)/[A-Za-z0-9][A-Za-z0-9._-]{0,120}|README\.md|LICENSE)"
)
_MODULE_NAME = re.compile(r"macos_[a-z0-9_]{1,80}\.(?:py|angerona\.json)")
_TRUE = frozenset({"1", "true", "yes", "on"})
_FALSE = frozenset({"0", "false", "no", "off", "never"})

Fetcher = Callable[[str, int], bytes]


class SupportPackError(RuntimeError):
    """The support pack could not be proven safe; nothing was enabled."""


@dataclass(frozen=True)
class Pin:
    repository: str
    commit: str
    version: str
    manifest_sha256: str
    manifest_size: int


@dataclass(frozen=True)
class PackFile:
    path: str
    sha256: str
    size: int
    executable: bool


# ── Reviewed pin and manifest ───────────────────────────────────────────────
def _strict_object(raw: bytes, what: str) -> dict:
    def reject_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise SupportPackError(f"{what} repeats the field {key!r}")
            result[key] = value
        return result

    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, ValueError) as exc:
        raise SupportPackError(f"{what} is not valid JSON") from exc
    if not isinstance(data, dict):
        raise SupportPackError(f"{what} must be a JSON object")
    return data


def load_pin(root: Path) -> Pin:
    """Read the reviewed pin shipped in this source tree."""
    path = Path(root) / PIN_RELATIVE_PATH
    try:
        if path.is_symlink() or path.stat().st_size > MAX_PIN_BYTES:
            raise SupportPackError("the support pack pin is not a bounded regular file")
        data = _strict_object(path.read_bytes(), "the support pack pin")
    except OSError as exc:
        raise SupportPackError("this Angerona revision has no support pack pin") from exc
    expected = {"schema", "repository", "commit", "version", "manifest_sha256",
                "manifest_size", "module_trust"}
    if set(data) != expected or data["schema"] != PIN_SCHEMA:
        raise SupportPackError("the support pack pin has an unsupported schema")
    if data["repository"] != CANONICAL_REPOSITORY:
        raise SupportPackError("the support pack pin names an unexpected repository")
    if data["module_trust"] != MODULE_TRUST:
        raise SupportPackError("the support pack pin declares an unknown trust mode")
    commit, digest, version = data["commit"], data["manifest_sha256"], data["version"]
    size = data["manifest_size"]
    if (
        not isinstance(commit, str) or not _COMMIT.fullmatch(commit)
        or not isinstance(digest, str) or not _SHA256.fullmatch(digest)
        or not isinstance(version, str) or not _VERSION.fullmatch(version)
        or type(size) is not int or not 0 < size <= MAX_MANIFEST_BYTES
    ):
        raise SupportPackError("the support pack pin contains an invalid value")
    return Pin(CANONICAL_REPOSITORY, commit, version, digest, size)


def parse_manifest(raw: bytes, pin: Pin) -> tuple[PackFile, ...]:
    """Validate the pinned pack manifest and return its file list."""
    if len(raw) != pin.manifest_size or hashlib.sha256(raw).hexdigest() != pin.manifest_sha256:
        raise SupportPackError(
            "the downloaded support pack manifest does not match the reviewed pin"
        )
    data = _strict_object(raw, "the support pack manifest")
    if (
        data.get("schema") != MANIFEST_SCHEMA or data.get("platform") != "macos"
        or data.get("version") != pin.version or data.get("module_trust") != MODULE_TRUST
    ):
        raise SupportPackError("the support pack manifest is not the reviewed macOS pack")
    rows = data.get("files")
    if not isinstance(rows, list) or not 0 < len(rows) <= MAX_FILES:
        raise SupportPackError("the support pack manifest has an invalid file list")
    files: list[PackFile] = []
    seen: set[str] = set()
    total = 0
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"path", "sha256", "size", "mode"}:
            raise SupportPackError("the support pack manifest has a malformed file entry")
        path, digest, size, mode = row["path"], row["sha256"], row["size"], row["mode"]
        if (
            not isinstance(path, str) or not _PACK_PATH.fullmatch(path)
            or ".." in path or path.casefold() in seen
            or not isinstance(digest, str) or not _SHA256.fullmatch(digest)
            or type(size) is not int or not 0 <= size <= MAX_FILE_BYTES
            or mode not in ("644", "755")
        ):
            raise SupportPackError("the support pack manifest has an unsafe file entry")
        if path.startswith("modules/") and not _MODULE_NAME.fullmatch(path[len("modules/"):]):
            raise SupportPackError("the support pack contains an unexpected module name")
        seen.add(path.casefold())
        total += size
        files.append(PackFile(path, digest, size, mode == "755"))
    if total > MAX_TOTAL_BYTES:
        raise SupportPackError("the support pack exceeds its size limit")
    return tuple(files)


# ── Fetching ────────────────────────────────────────────────────────────────
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        raise urllib.error.HTTPError(req.full_url, code, "redirect refused", headers, fp)


def _curl_fetch(url: str, relative: str, maximum: int) -> bytes:
    """Fallback for Python builds without CA certificates (python.org installers).

    ``/usr/bin/curl`` ships with every macOS and uses the system trust store.
    HTTPS only, no redirects, bounded size and time.
    """
    import subprocess

    curl = "/usr/bin/curl"
    if not os.path.isfile(curl):
        raise SupportPackError(f"could not download {relative}: no trusted HTTPS client")
    try:
        proc = subprocess.run(
            [curl, "--silent", "--show-error", "--fail", "--proto", "=https",
             "--max-redirs", "0", "--max-time", str(int(NETWORK_TIMEOUT_SECONDS)),
             "--max-filesize", str(maximum + 1), "--", url],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=NETWORK_TIMEOUT_SECONDS + 10, check=False,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SupportPackError(f"could not download {relative} ({type(exc).__name__})") from exc
    if proc.returncode != 0:
        raise SupportPackError(f"could not download {relative} from GitHub (curl {proc.returncode})")
    return proc.stdout


def github_fetcher(pin: Pin) -> Fetcher:
    """Fetch individual files of the pinned commit over HTTPS, no redirects."""
    import ssl

    opener = urllib.request.build_opener(_NoRedirect())

    def fetch(relative: str, maximum: int) -> bytes:
        url = f"https://{RAW_HOST}/{pin.repository}/{pin.commit}/{relative}"
        request = urllib.request.Request(
            url, headers={"User-Agent": "angerona-macos-support/1", "Accept": "*/*"},
        )
        try:
            with opener.open(request, timeout=NETWORK_TIMEOUT_SECONDS) as response:
                if response.status != 200:
                    raise SupportPackError(f"GitHub answered {response.status} for {relative}")
                body = response.read(maximum + 1)
        except SupportPackError:
            raise
        except urllib.error.URLError as exc:
            if isinstance(getattr(exc, "reason", None), ssl.SSLError):
                body = _curl_fetch(url, relative, maximum)
            else:
                raise SupportPackError(
                    f"could not download {relative} from GitHub ({type(exc).__name__})"
                ) from exc
        except (OSError, ValueError) as exc:
            raise SupportPackError(
                f"could not download {relative} from GitHub ({type(exc).__name__})"
            ) from exc
        if len(body) > maximum:
            raise SupportPackError(f"{relative} is larger than its reviewed size")
        return body

    return fetch


def directory_fetcher(source: Path) -> Fetcher:
    """Read a local copy of the pack (offline install); still hash-verified."""
    base = Path(source).resolve(strict=True)

    def fetch(relative: str, maximum: int) -> bytes:
        path = base / relative
        try:
            resolved = path.resolve(strict=True)
        except OSError as exc:
            raise SupportPackError(f"{relative} is missing from the source folder") from exc
        if path.is_symlink() or base not in resolved.parents or not resolved.is_file():
            raise SupportPackError(f"{relative} is not a plain file inside the source folder")
        with open(resolved, "rb") as stream:
            body = stream.read(maximum + 1)
        if len(body) > maximum:
            raise SupportPackError(f"{relative} is larger than its reviewed size")
        return body

    return fetch


# ── Filesystem layout ───────────────────────────────────────────────────────
def default_data_dir(environ: Mapping[str, str] = os.environ) -> Path:
    """The per-user data folder the macOS source installer uses."""
    override = environ.get("ANGERONA_DATA", "").strip()
    if override:
        return Path(override).expanduser()
    return Path.home() / "Library" / "Application Support" / "Angerona"


def _support_dir(data: Path) -> Path:
    return Path(data) / "macos-support"


def _modules_dir(data: Path) -> Path:
    return Path(data) / "modules"


def _private_dir(path: Path) -> Path:
    if path.is_symlink():
        raise SupportPackError(f"refusing a symbolic link in the data folder: {path.name}")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not path.is_dir():
        raise SupportPackError(f"{path.name} is not a directory")
    return path


def _atomic_write(path: Path, content: bytes, mode: int) -> None:
    fd, name = tempfile.mkstemp(prefix=".angerona-", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.chmod(mode)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def read_receipt(data: Path) -> dict | None:
    """Return the installation receipt, or ``None`` when absent or malformed."""
    path = _support_dir(data) / "installed.json"
    try:
        if path.is_symlink() or path.stat().st_size > MAX_PIN_BYTES:
            return None
        receipt = _strict_object(path.read_bytes(), "the support pack receipt")
    except (OSError, SupportPackError):
        return None
    modules = receipt.get("modules")
    if (
        receipt.get("schema") != RECEIPT_SCHEMA
        or not isinstance(receipt.get("manifest_sha256"), str)
        or not _SHA256.fullmatch(receipt["manifest_sha256"])
        or not isinstance(receipt.get("version"), str)
        or not isinstance(modules, dict) or not modules
        or any(
            not isinstance(name, str) or not _MODULE_NAME.fullmatch(name)
            or not isinstance(digest, str) or not _SHA256.fullmatch(digest)
            for name, digest in modules.items()
        )
    ):
        return None
    return receipt


# ── Install / uninstall ─────────────────────────────────────────────────────
def _validate_module_pairs(contents: Mapping[str, bytes]) -> dict[str, str]:
    """Every module must carry an unsigned manifest bound to its exact bytes."""
    modules = {
        path[len("modules/"):]: body
        for path, body in contents.items() if path.startswith("modules/")
    }
    sources = sorted(name for name in modules if name.endswith(".py"))
    manifests = sorted(name for name in modules if name.endswith(".angerona.json"))
    if not sources or [name[:-3] + ".angerona.json" for name in sources] != manifests:
        raise SupportPackError("the support pack modules and manifests do not pair up")
    for name in sources:
        manifest = _strict_object(modules[name[:-3] + ".angerona.json"], "a module manifest")
        permissions = manifest.get("permissions")
        if (
            manifest.get("entrypoint") != name
            or manifest.get("sha256") != hashlib.sha256(modules[name]).hexdigest()
            or manifest.get("publisher") != "" or manifest.get("signature") != ""
            or not isinstance(permissions, list) or "network.connect" in permissions
            or (manifest.get("privacy") or {}).get("egress") != "none"
        ):
            raise SupportPackError(f"the manifest for {name} is not the reviewed local-only form")
    return {name: hashlib.sha256(body).hexdigest() for name, body in modules.items()}


def install(
    root: Path, data: Path, *, fetch: Fetcher | None = None,
    platform: str = sys.platform, clock: Callable[[], float] = time.time,
) -> dict:
    """Download, verify and install the pinned pack. Raises on any mismatch."""
    if platform != "darwin":
        raise SupportPackError("the macOS support pack installs only on macOS")
    pin = load_pin(root)
    fetch = fetch or github_fetcher(pin)
    files = parse_manifest(fetch("pack-manifest.json", pin.manifest_size), pin)

    contents: dict[str, bytes] = {}
    for item in files:
        body = fetch(item.path, item.size)
        if len(body) != item.size or hashlib.sha256(body).hexdigest() != item.sha256:
            raise SupportPackError(
                f"{item.path} does not match the reviewed support pack; nothing was installed"
            )
        contents[item.path] = body
    module_digests = _validate_module_pairs(contents)

    data = Path(data)
    _private_dir(data)
    support = _private_dir(_support_dir(data))
    packs = _private_dir(support / "packs")
    modules_dir = _private_dir(_modules_dir(data))
    previous = read_receipt(data) or {}
    previous_modules = set(previous.get("modules") or ())
    for name in module_digests:
        target = modules_dir / name
        if (target.exists() or target.is_symlink()) and name not in previous_modules:
            raise SupportPackError(
                f"a different drop-in module named {name} already exists; it was not replaced"
            )

    staging = Path(tempfile.mkdtemp(prefix=".staging-", dir=support))
    final = packs / f"{pin.version}-{pin.manifest_sha256[:12]}"
    try:
        for item in files:
            target = staging / item.path
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            _atomic_write(target, contents[item.path], 0o755 if item.executable else 0o644)
        if final.exists():
            shutil.rmtree(final)
        os.rename(staging, final)
    finally:
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)

    for name in sorted(module_digests):
        _atomic_write(modules_dir / name, contents["modules/" + name], 0o600)
    for name in sorted(previous_modules - set(module_digests)):
        (modules_dir / name).unlink(missing_ok=True)
    for stale in packs.iterdir():
        if stale != final and stale.is_dir() and not stale.is_symlink():
            shutil.rmtree(stale, ignore_errors=True)

    link = support / "current"
    temporary_link = support / ".current-new"
    temporary_link.unlink(missing_ok=True)
    os.symlink(os.path.join("packs", final.name), temporary_link)
    os.replace(temporary_link, link)

    receipt = {
        "schema": RECEIPT_SCHEMA,
        "repository": pin.repository,
        "commit": pin.commit,
        "version": pin.version,
        "manifest_sha256": pin.manifest_sha256,
        "module_trust": MODULE_TRUST,
        "installed_at": int(clock()),
        "pack_directory": final.name,
        "modules": dict(sorted(module_digests.items())),
    }
    _atomic_write(
        support / "installed.json",
        (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode("utf-8"), 0o600,
    )
    _atomic_write(support / "enabled", b"enabled by explicit user consent\n", 0o600)
    (support / "declined").unlink(missing_ok=True)
    return receipt


def uninstall(data: Path) -> bool:
    """Remove the pack's modules, scripts and switches. Returns True if present."""
    data = Path(data)
    support = _support_dir(data)
    if support.is_symlink() or not support.is_dir():
        return False
    receipt = read_receipt(data)
    modules_dir = _modules_dir(data)
    if receipt and modules_dir.is_dir() and not modules_dir.is_symlink():
        for name in receipt["modules"]:
            target = modules_dir / name
            if target.is_file() or target.is_symlink():
                target.unlink()
    present = bool(receipt) or (support / "packs").exists()
    for name in ("enabled", "installed.json", "current", ".current-new"):
        (support / name).unlink(missing_ok=True)
    packs = support / "packs"
    if packs.is_dir() and not packs.is_symlink():
        shutil.rmtree(packs, ignore_errors=True)
    return present


def set_enabled(data: Path, enabled: bool) -> None:
    support = _support_dir(Path(data))
    if enabled:
        if read_receipt(data) is None:
            raise SupportPackError("the support pack is not installed")
        _atomic_write(support / "enabled", b"enabled by explicit user consent\n", 0o600)
    else:
        (support / "enabled").unlink(missing_ok=True)


def decline(data: Path) -> None:
    """Remember that the user does not want to be asked again."""
    support = _private_dir(_support_dir(_private_dir(Path(data))))
    _atomic_write(support / "declined", b"declined by the user\n", 0o600)


# ── Verification and launch gate ────────────────────────────────────────────
def verify_installed(root: Path, data: Path) -> tuple[bool, str]:
    """Prove the module folder holds exactly the pinned pack's modules."""
    receipt = read_receipt(data)
    if receipt is None:
        return False, "the support pack receipt is missing or malformed"
    try:
        pin = load_pin(root)
    except SupportPackError as exc:
        return False, str(exc)
    if receipt["manifest_sha256"] != pin.manifest_sha256:
        return False, (
            "the installed support pack is not the revision this Angerona reviewed; "
            "run tools/macos_support_pack.py install"
        )
    modules_dir = _modules_dir(data)
    if modules_dir.is_symlink() or not modules_dir.is_dir():
        return False, "the module folder is missing or is a symbolic link"
    expected: dict[str, str] = receipt["modules"]
    try:
        present = sorted(
            entry.name for entry in os.scandir(modules_dir)
            if entry.name.endswith((".py", ".json")) and not entry.name.startswith("_")
        )
    except OSError:
        return False, "the module folder could not be read"
    extra = [name for name in present if name not in expected]
    if extra:
        return False, (
            "the module folder contains drop-ins that are not part of the support pack "
            f"({', '.join(extra[:3])}); the unsigned override was not enabled for them"
        )
    for name, digest in expected.items():
        path = modules_dir / name
        try:
            if path.is_symlink() or path.stat().st_size > MAX_FILE_BYTES:
                raise OSError
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError:
            return False, f"support module file {name} is missing or unreadable"
        if actual != digest:
            return False, f"support module file {name} changed after installation"
    return True, f"support pack {receipt['version']} verified"


def apply_environment(
    root: Path | None = None, data: Path | None = None, *,
    environ: MutableMapping[str, str] = os.environ,
    stream: TextIO | None = None, platform: str = sys.platform,
) -> str:
    """Enable the pack's unsigned modules for this start, with a notice.

    Returns one of ``not-macos``, ``disabled``, ``held``, ``rejected`` or
    ``enabled``.  It never raises: a failure leaves the modules off.
    """
    if platform != "darwin":
        return "not-macos"
    stream = stream if stream is not None else sys.stderr
    try:
        if data is None or root is None:
            from angerona.core.data_paths import data_dir, project_root

            data = data if data is not None else data_dir(create=False)
            root = root if root is not None else project_root()
        if not (_support_dir(Path(data)) / "enabled").is_file():
            return "disabled"
        if environ.get("ANGERONA_MACOS_SUPPORT", "").strip().casefold() in _FALSE:
            return "disabled"
        if environ.get("ANGERONA_ENFORCE_KEY_ACL", "").strip().casefold() in _TRUE:
            print("[Angerona] macOS support modules stay off in protected launch mode.",
                  file=stream, flush=True)
            return "held"
        verified, reason = verify_installed(Path(root), Path(data))
        if not verified:
            print(f"[Angerona] macOS support modules were not enabled: {reason}.",
                  file=stream, flush=True)
            return "rejected"
        environ["ANGERONA_EXTERNAL_MODULES"] = "1"
        environ["ANGERONA_ALLOW_UNSIGNED_EXTERNAL_MODULES"] = "1"
        environ["ANGERONA_DEVELOPMENT_MODE"] = "1"
        print(REDUCED_SECURITY_NOTICE, file=stream, flush=True)
        return "enabled"
    except Exception as exc:  # the optional pack must never block startup
        print(f"[Angerona] macOS support modules were not enabled: {type(exc).__name__}.",
              file=stream, flush=True)
        return "rejected"


def status(root: Path, data: Path, *, platform: str = sys.platform) -> dict:
    """Describe the pack state for the CLI and the setup prompt."""
    data = Path(data)
    support = _support_dir(data)
    receipt = read_receipt(data)
    try:
        pin: Pin | None = load_pin(root)
        pin_problem = ""
    except SupportPackError as exc:
        pin, pin_problem = None, str(exc)
    verified, reason = (verify_installed(root, data) if receipt else (False, "not installed"))
    current = bool(receipt and pin and receipt["manifest_sha256"] == pin.manifest_sha256)
    declined = (support / "declined").is_file()
    return {
        "platform_supported": platform == "darwin",
        "pinned_version": pin.version if pin else "",
        "pin_problem": pin_problem,
        "installed": receipt is not None,
        "installed_version": receipt["version"] if receipt else "",
        "current": current,
        "verified": verified,
        "detail": reason,
        "enabled": (support / "enabled").is_file(),
        "declined": declined,
        # Offer it when this Mac has no current pack and the user has not said no.
        "should_ask": platform == "darwin" and pin is not None and not current and not declined,
    }
