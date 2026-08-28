"""Verify that GitHub serves the exact public images referenced by README.md."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path, PurePosixPath
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen

if __package__ in {None, ""}:  # Allow direct execution from the repository.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.validate_documentation_drift import (  # noqa: E402
    MAX_PUBLIC_IMAGE_BYTES,
    local_readme_image_targets,
    validate_png_payload,
)


REPOSITORY_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
REF_RE = re.compile(r"[A-Za-z0-9._/-]{1,160}")


class PublishedAssetError(RuntimeError):
    """Raised when a public README asset cannot be proven byte-identical."""


def _validate_coordinates(repository: str, ref: str) -> None:
    if not REPOSITORY_RE.fullmatch(repository):
        raise PublishedAssetError("GitHub repository must use exact owner/name form")
    if (
        not REF_RE.fullmatch(ref)
        or ref.startswith("/")
        or ref.endswith("/")
        or ".." in ref
        or "//" in ref
    ):
        raise PublishedAssetError("GitHub ref is not a canonical branch or commit")


def _download_exact(url: str, *, timeout: float) -> tuple[bytes, str]:
    request = Request(
        url,
        headers={
            "Accept": "image/*",
            "Cache-Control": "no-cache",
            "User-Agent": "Angerona-publication-verifier/1.0",
        },
    )
    try:
        with urlopen(request, timeout=timeout) as response:  # noqa: S310
            status = getattr(response, "status", 200)
            if status != 200:
                raise PublishedAssetError(f"GitHub returned HTTP {status}")
            final = urlsplit(response.geturl())
            if final.scheme != "https" or final.hostname != "raw.githubusercontent.com":
                raise PublishedAssetError(
                    "GitHub image request redirected off the raw host"
                )
            content_type = response.headers.get("Content-Type", "").split(";", 1)[0]
            if content_type.lower() != "image/png":
                raise PublishedAssetError(
                    f"GitHub returned unexpected content type {content_type!r}"
                )
            payload = response.read(MAX_PUBLIC_IMAGE_BYTES + 1)
    except URLError as exc:
        reason = exc.reason
        if os.name != "nt" or not isinstance(reason, OSError):
            raise
        payload, content_type = _download_exact_with_windows_powershell(
            url, timeout=timeout
        )
    if len(payload) > MAX_PUBLIC_IMAGE_BYTES:
        raise PublishedAssetError("GitHub image exceeds the public size bound")
    return payload, content_type


def _download_exact_with_windows_powershell(
    url: str,
    *,
    timeout: float,
) -> tuple[bytes, str]:
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    powershell = (
        Path(system_root)
        / "System32"
        / "WindowsPowerShell"
        / "v1.0"
        / "powershell.exe"
    )
    if not powershell.is_file():
        raise PublishedAssetError("fixed Windows PowerShell client is unavailable")
    descriptor, temporary_name = tempfile.mkstemp(prefix="angerona-public-image-")
    os.close(descriptor)
    temporary = Path(temporary_name)
    environment = os.environ.copy()
    environment["ANGERONA_PUBLIC_IMAGE_URL"] = url
    environment["ANGERONA_PUBLIC_IMAGE_PATH"] = str(temporary)
    environment["ANGERONA_PUBLIC_IMAGE_TIMEOUT"] = str(max(1, int(timeout + 0.999)))
    command = (
        "$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';"
        "$r=Invoke-WebRequest -Uri $env:ANGERONA_PUBLIC_IMAGE_URL "
        "-OutFile $env:ANGERONA_PUBLIC_IMAGE_PATH -PassThru -UseBasicParsing "
        "-MaximumRedirection 3 -TimeoutSec $env:ANGERONA_PUBLIC_IMAGE_TIMEOUT;"
        "if([int]$r.StatusCode -ne 200){exit 21};"
        "$u=[Uri]$r.BaseResponse.ResponseUri;"
        "if($u.Scheme -cne 'https' -or "
        "$u.Host -cne 'raw.githubusercontent.com'){exit 22};"
        "$t=[string]$r.Headers['Content-Type'];[Console]::Out.Write($t)"
    )
    try:
        result = subprocess.run(
            [
                str(powershell),
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                command,
            ],
            capture_output=True,
            text=True,
            env=environment,
            check=False,
        )
        if result.returncode != 0:
            detail = result.stderr.strip() or f"exit {result.returncode}"
            raise PublishedAssetError(f"PowerShell GitHub download failed: {detail}")
        content_type = result.stdout.strip().split(";", 1)[0]
        if content_type.lower() != "image/png":
            raise PublishedAssetError(
                f"GitHub returned unexpected content type {content_type!r}"
            )
        if temporary.stat().st_size > MAX_PUBLIC_IMAGE_BYTES:
            raise PublishedAssetError("GitHub image exceeds the public size bound")
        payload = temporary.read_bytes()
    finally:
        temporary.unlink(missing_ok=True)
    return payload, content_type


def verify_published_assets(
    root: Path,
    *,
    repository: str,
    ref: str,
    attempts: int = 3,
    timeout: float = 20.0,
) -> list[str]:
    """Download and compare every repository-relative README image."""

    _validate_coordinates(repository, ref)
    if not 1 <= attempts <= 5:
        raise PublishedAssetError("attempt count must be between one and five")
    if not 1.0 <= timeout <= 60.0:
        raise PublishedAssetError("timeout must be between one and 60 seconds")

    readme = (root / "README.md").read_text(encoding="utf-8")
    targets, parse_errors = local_readme_image_targets(readme)
    if parse_errors:
        raise PublishedAssetError("; ".join(parse_errors))
    if not targets:
        raise PublishedAssetError("README.md has no local public images")

    verified: list[str] = []
    encoded_ref = quote(ref, safe="")
    resolved_root = root.resolve()
    for relative in targets:
        try:
            local = root.joinpath(*PurePosixPath(relative).parts).resolve(strict=True)
        except OSError as exc:
            raise PublishedAssetError(f"local image is unavailable: {relative}") from exc
        if not local.is_relative_to(resolved_root) or not local.is_file():
            raise PublishedAssetError(f"local image escapes repository: {relative}")
        if local.stat().st_size > MAX_PUBLIC_IMAGE_BYTES:
            raise PublishedAssetError(f"local image exceeds size bound: {relative}")
        expected = local.read_bytes()
        try:
            validate_png_payload(expected)
        except ValueError as exc:
            raise PublishedAssetError(
                f"local image is not a valid PNG: {relative}"
            ) from exc

        expected_digest = hashlib.sha256(expected).hexdigest()
        encoded_path = quote(relative, safe="/")
        url = (
            f"https://raw.githubusercontent.com/{repository}/"
            f"{encoded_ref}/{encoded_path}"
        )
        last_error: Exception | None = None
        for attempt in range(attempts):
            try:
                payload, _content_type = _download_exact(url, timeout=timeout)
                try:
                    validate_png_payload(payload)
                except ValueError as exc:
                    raise PublishedAssetError(
                        "published response is not a valid PNG"
                    ) from exc
                actual_digest = hashlib.sha256(payload).hexdigest()
                if len(payload) != len(expected) or actual_digest != expected_digest:
                    raise PublishedAssetError(
                        "published bytes differ from the checked-out file"
                    )
                verified.append(relative)
                last_error = None
                break
            except (HTTPError, URLError, OSError, PublishedAssetError) as exc:
                last_error = exc
                if attempt + 1 < attempts:
                    time.sleep(min(0.5 * (2**attempt), 2.0))
        if last_error is not None:
            raise PublishedAssetError(f"{relative}: {last_error}") from last_error
    return verified


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True, help="Exact GitHub owner/name")
    parser.add_argument("--ref", required=True, help="Published branch or commit")
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="Repository root",
    )
    parser.add_argument("--attempts", type=int, default=3)
    parser.add_argument("--timeout", type=float, default=20.0)
    args = parser.parse_args()
    try:
        verified = verify_published_assets(
            args.root.resolve(),
            repository=args.repository,
            ref=args.ref,
            attempts=args.attempts,
            timeout=args.timeout,
        )
    except (OSError, PublishedAssetError) as exc:
        print(f"published README assets: FAIL: {exc}", file=sys.stderr)
        return 1
    print(f"published README assets: PASS ({len(verified)} exact images)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
