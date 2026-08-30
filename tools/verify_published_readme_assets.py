"""Verify that GitHub serves the exact public images referenced by README.md."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import ssl
import sys
import time
from pathlib import Path, PurePosixPath
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener

if __package__ in {None, ""}:  # Allow direct execution from the repository.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.validate_documentation_drift import (  # noqa: E402
    MAX_PUBLIC_IMAGE_BYTES,
    local_readme_image_targets,
    validate_png_payload,
)
from tools.publication_transport import (  # noqa: E402
    PublicationTransportError,
    TrustedGitBoundary,
    bounded_error,
    resolve_trusted_git_boundary,
)


REPOSITORY_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
REF_RE = re.compile(r"[A-Za-z0-9._/-]{1,160}")
OBJECT_ID_RE = re.compile(r"[0-9a-f]{40,64}")
MAX_TRACKED_README_BYTES = 2 * 1024 * 1024
_HTTPS_AUTHORITY_ENVIRONMENT = frozenset({
    "all_proxy",
    "curl_ca_bundle",
    "http_proxy",
    "https_proxy",
    "no_proxy",
    "openssl_conf",
    "pythonhttpsverify",
    "requests_ca_bundle",
    "ssl_cert_dir",
    "ssl_cert_file",
    "sslkeylogfile",
})


class PublishedAssetError(RuntimeError):
    """Raised when a public README asset cannot be proven byte-identical."""


def _validate_raw_github_url(url: str, *, label: str) -> None:
    parsed = urlsplit(url)
    try:
        port = parsed.port
    except ValueError as exc:
        raise PublishedAssetError(f"{label} GitHub URL is invalid") from exc
    if (
        parsed.scheme != "https"
        or parsed.hostname != "raw.githubusercontent.com"
        or port is not None
        or parsed.username is not None
        or parsed.password is not None
        or bool(parsed.query)
        or bool(parsed.fragment)
        or not parsed.path.startswith("/")
    ):
        raise PublishedAssetError(f"{label} GitHub URL is not canonical raw HTTPS")


def _git_bytes(
    root: Path,
    *arguments: str,
    boundary: TrustedGitBoundary | None = None,
) -> bytes:
    active = boundary or resolve_trusted_git_boundary()
    owned = boundary is None
    try:
        result = active.run(root, arguments, text=False, timeout=30.0)
    except PublicationTransportError as exc:
        if owned:
            try:
                active.close()
            except PublicationTransportError:
                pass
        raise PublishedAssetError(str(exc)) from exc
    if owned:
        try:
            active.close()
        except PublicationTransportError as exc:
            raise PublishedAssetError(str(exc)) from exc
    if result.returncode != 0:
        raise PublishedAssetError(bounded_error(result) or "Git object query failed")
    if not isinstance(result.stdout, bytes):
        raise PublishedAssetError("Git object query returned the wrong output type")
    return result.stdout


def _resolve_immutable_commit(
    root: Path,
    commit: str | None,
    boundary: TrustedGitBoundary,
) -> str:
    candidate = commit or _git_bytes(
        root,
        "rev-parse",
        "--verify",
        "HEAD^{commit}",
        boundary=boundary,
    ).decode("ascii", errors="strict").strip().lower()
    if not OBJECT_ID_RE.fullmatch(candidate):
        raise PublishedAssetError("local publication commit is not an exact object ID")
    resolved = _git_bytes(
        root,
        "rev-parse",
        "--verify",
        f"{candidate}^{{commit}}",
        boundary=boundary,
    ).decode("ascii", errors="strict").strip().lower()
    if resolved != candidate:
        raise PublishedAssetError("local publication commit did not resolve exactly")
    return candidate


def _git_blob(
    root: Path,
    commit: str,
    relative: str,
    *,
    limit: int,
    boundary: TrustedGitBoundary,
) -> bytes:
    path = PurePosixPath(relative)
    if (
        path.is_absolute()
        or not path.parts
        or any(part in {"", ".", ".."} for part in path.parts)
        or "\\" in relative
    ):
        raise PublishedAssetError(f"unsafe tracked path: {relative}")
    object_name = f"{commit}:{path.as_posix()}"
    raw_size = _git_bytes(
        root,
        "cat-file",
        "-s",
        object_name,
        boundary=boundary,
    )
    try:
        size = int(raw_size.decode("ascii", errors="strict").strip())
    except (UnicodeError, ValueError) as exc:
        raise PublishedAssetError(f"tracked blob size is invalid: {relative}") from exc
    if size < 0 or size > limit:
        raise PublishedAssetError(f"tracked blob exceeds size bound: {relative}")
    payload = _git_bytes(
        root,
        "cat-file",
        "blob",
        object_name,
        boundary=boundary,
    )
    if len(payload) != size:
        raise PublishedAssetError(f"tracked blob size changed: {relative}")
    return payload


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


def _reject_ambient_https_authority() -> None:
    forbidden = sorted(
        name
        for name, value in os.environ.items()
        if value and name.casefold() in _HTTPS_AUTHORITY_ENVIRONMENT
    )
    if forbidden:
        raise PublishedAssetError(
            "ambient HTTPS transport authority is forbidden: "
            + ", ".join(forbidden)
        )


def _system_trust_context() -> ssl.SSLContext:
    """Create strict TLS using system trust, never caller CA environment."""

    _reject_ambient_https_authority()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    if hasattr(ssl, "TLSVersion"):
        context.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        if sys.platform == "win32":
            # Python loads the Windows CA/ROOT certificate stores here.  The
            # environment CA selectors were rejected before context creation.
            context.load_default_certs(ssl.Purpose.SERVER_AUTH)
        else:
            paths = ssl.get_default_verify_paths()
            cafile = paths.openssl_cafile
            capath = paths.openssl_capath
            if not (cafile and Path(cafile).is_file()) and not (
                capath and Path(capath).is_dir()
            ):
                raise PublishedAssetError("compiled system TLS trust is unavailable")
            context.load_verify_locations(
                cafile=cafile if cafile and Path(cafile).is_file() else None,
                capath=capath if capath and Path(capath).is_dir() else None,
            )
    except (OSError, ssl.SSLError) as exc:
        raise PublishedAssetError("system TLS trust could not be loaded") from exc
    return context


def _private_https_opener():
    """Return a request-local HTTPS opener with proxy discovery disabled."""

    context = _system_trust_context()
    return build_opener(
        ProxyHandler({}),
        HTTPSHandler(context=context),
    )


def _download_exact(
    url: str,
    *,
    timeout: float,
    allowed_content_types: frozenset[str] = frozenset({"image/png"}),
    max_bytes: int = MAX_PUBLIC_IMAGE_BYTES,
) -> tuple[bytes, str]:
    _validate_raw_github_url(url, label="requested")
    request = Request(
        url,
        headers={
            "Accept": "image/*",
            "Cache-Control": "no-cache",
            "User-Agent": "Angerona-publication-verifier/1.0",
        },
    )
    try:
        opener = _private_https_opener()
        with opener.open(request, timeout=timeout) as response:  # noqa: S310
            status = getattr(response, "status", 200)
            if status != 200:
                raise PublishedAssetError(f"GitHub returned HTTP {status}")
            _validate_raw_github_url(response.geturl(), label="final")
            content_type = response.headers.get("Content-Type", "").split(";", 1)[0]
            if content_type.lower() not in allowed_content_types:
                raise PublishedAssetError(
                    f"GitHub returned unexpected content type {content_type!r}"
                )
            payload = response.read(max_bytes + 1)
    except (HTTPError, URLError, OSError, ssl.SSLError) as exc:
        detail = str(exc).strip().replace("\r", " ").replace("\n", " ")[:240]
        raise PublishedAssetError(
            "bounded direct HTTPS request failed"
            + (f": {detail}" if detail else "")
        ) from exc
    if len(payload) > max_bytes:
        raise PublishedAssetError("GitHub response exceeds the public size bound")
    return payload, content_type


def _verify_published_assets_with_boundary(
    root: Path,
    *,
    repository: str,
    ref: str,
    expected_commit: str | None = None,
    attempts: int = 3,
    timeout: float = 20.0,
    git_boundary: TrustedGitBoundary,
) -> list[str]:
    """Compare public assets with immutable blobs from one captured commit."""

    _validate_coordinates(repository, ref)
    if not 1 <= attempts <= 5:
        raise PublishedAssetError("attempt count must be between one and five")
    if not 1.0 <= timeout <= 60.0:
        raise PublishedAssetError("timeout must be between one and 60 seconds")

    root = root.resolve()
    commit = _resolve_immutable_commit(root, expected_commit, git_boundary)
    readme_payload = _git_blob(
        root,
        commit,
        "README.md",
        limit=MAX_TRACKED_README_BYTES,
        boundary=git_boundary,
    )
    try:
        readme = readme_payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise PublishedAssetError("tracked README.md is not strict UTF-8") from exc
    targets, parse_errors = local_readme_image_targets(readme)
    if parse_errors:
        raise PublishedAssetError("; ".join(parse_errors))
    if not targets:
        raise PublishedAssetError("README.md has no local public images")

    verified: list[str] = []
    encoded_ref = quote(ref, safe="")
    public_readme_url = (
        f"https://raw.githubusercontent.com/{repository}/"
        f"{encoded_ref}/README.md"
    )
    readme_error: Exception | None = None
    for attempt in range(attempts):
        try:
            public_readme, _content_type = _download_exact(
                public_readme_url,
                timeout=timeout,
                allowed_content_types=frozenset({
                    "application/octet-stream",
                    "text/markdown",
                    "text/plain",
                }),
                max_bytes=MAX_TRACKED_README_BYTES,
            )
            if public_readme != readme_payload:
                raise PublishedAssetError(
                    "published README differs from the captured commit"
                )
            readme_error = None
            break
        except (HTTPError, URLError, OSError, PublishedAssetError) as exc:
            readme_error = exc
            if attempt + 1 < attempts:
                time.sleep(min(0.5 * (2**attempt), 2.0))
    if readme_error is not None:
        raise PublishedAssetError(
            f"README.md: {readme_error}"
        ) from readme_error

    for relative in targets:
        expected = _git_blob(
            root,
            commit,
            relative,
            limit=MAX_PUBLIC_IMAGE_BYTES,
            boundary=git_boundary,
        )
        try:
            validate_png_payload(expected)
        except ValueError as exc:
            raise PublishedAssetError(
                f"captured image is not a valid PNG: {relative}"
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
                        "published bytes differ from the captured commit"
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


def verify_published_assets(
    root: Path,
    *,
    repository: str,
    ref: str,
    expected_commit: str | None = None,
    attempts: int = 3,
    timeout: float = 20.0,
    git_boundary: TrustedGitBoundary | None = None,
) -> list[str]:
    """Compare public assets using one caller-owned or privately owned Git seal."""

    _validate_coordinates(repository, ref)
    if not 1 <= attempts <= 5:
        raise PublishedAssetError("attempt count must be between one and five")
    if not 1.0 <= timeout <= 60.0:
        raise PublishedAssetError("timeout must be between one and 60 seconds")
    owned = git_boundary is None
    try:
        active = git_boundary or resolve_trusted_git_boundary()
    except PublicationTransportError as exc:
        raise PublishedAssetError(str(exc)) from exc
    try:
        return _verify_published_assets_with_boundary(
            root,
            repository=repository,
            ref=ref,
            expected_commit=expected_commit,
            attempts=attempts,
            timeout=timeout,
            git_boundary=active,
        )
    finally:
        if owned:
            try:
                active.close()
            except PublicationTransportError as exc:
                raise PublishedAssetError(str(exc)) from exc


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
