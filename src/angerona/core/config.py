"""Configuration + canonical filesystem paths.

All runtime state lives under a dedicated data directory so the app folder
itself stays clean and read-only-friendly. Credentials use the current-user OS
store (Windows DPAPI, macOS Keychain, or Linux Secret Service); legacy
plaintext imports require an explicit action.
"""
from __future__ import annotations

import json
import ipaddress
import os
import re
import secrets
from urllib.parse import urlsplit
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict


_ARIA_PUSH_URL_KEY = "ANGERONA_ARIA_PUSH_URL"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_SIGNAL_IDENTITY = re.compile(r"\+[1-9][0-9]{7,14}\Z")


def _atomic_write_text(path: Path, text: str) -> None:
    """Durably stage UTF-8 text and atomically replace one settings file."""
    from angerona.core.atomic_io import replace_with_retry

    path.parent.mkdir(parents=True, exist_ok=True)
    candidate = path.with_name(f".{path.name}.{secrets.token_hex(12)}.tmp")
    descriptor: int | None = None
    try:
        descriptor = os.open(
            candidate,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
            0o600,
        )
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            descriptor = None
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        replace_with_retry(candidate, path)
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        try:
            candidate.unlink(missing_ok=True)
        except OSError:
            pass


def _bounded_setting(value: object, default: str, limit: int) -> str:
    try:
        text = str(value if value is not None else "").strip()
    except Exception:
        return default
    if len(text) > limit or any(ord(character) < 32 for character in text):
        return default
    return text


def _port_setting(value: object, default: int) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError, OverflowError):
        return default
    return port if 1 <= port <= 65535 else default


def _https_feed_setting(value: object) -> str:
    text = _bounded_setting(value, "", 2048)
    if not text:
        return ""
    try:
        parsed = urlsplit(text)
    except ValueError:
        return ""
    if (
        parsed.scheme.casefold() != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        return ""
    return text


def _bool_setting(data: dict, key: str, default: bool) -> bool:
    """Load a JSON boolean without truth-coercing strings or numbers.

    Security/privacy switches must fail to their declared default when a hand-
    edited or corrupted settings file contains ``"false"``, ``1``, or another
    non-boolean value. Python's normal ``bool("false")`` result is True, which
    can otherwise enable egress or the Teams development auth bypass.
    """
    value = data.get(key, default)
    return value if type(value) is bool else bool(default)


def _data_dir() -> Path:
    from angerona.core.data_paths import data_dir
    p = data_dir()
    (p / "logs").mkdir(parents=True, exist_ok=True)
    return p


def write_env_keys(updates: dict) -> Path:
    """Persist credentials in the current-user OS store and publish them live.

    The historical function name remains for UI compatibility, but this no
    longer creates a plaintext ``.env`` in the elevated application checkout.
    """
    from angerona.core.secure_store import write_secret_map
    return write_secret_map(updates, _data_dir())


@dataclass
class Config:
    data_dir: Path = field(default_factory=_data_dir)
    ollama_host: str = "http://localhost:11434"
    ollama_model: str = "llama3"
    github_repo: str = "your-user/Angerona"   # set to your repo for auto-update
    theme: str = "cyber"                       # gui theme key (see gui/theme.py)
    accent: str = ""                           # optional custom accent hex tint
    module_states: Dict[str, bool] = field(default_factory=dict)
    autostart_enabled: bool = True              # platform-native per-user logon startup
    eco_mode: bool = True                        # start in network-first Chill Mode for all-day low-impact protection
    blackbox_enabled: bool = True                # auto-launch the decoupled Black Box diagnostic recorder at startup
    # Decoys stay inside Angerona's D-drive data root unless the operator
    # explicitly opts into personal-folder/registry placement.
    deception_user_folders: bool = False
    # ── Mobile Response Bridge (Signal / signal-cli) — opt-in, default off ──
    mobile_enabled: bool = False
    mobile_signal_cli: str = ""                   # path to the signal-cli binary
    mobile_signal_cli_sha256: str = ""            # exact executable digest pin
    mobile_signal_cli_publisher: str = ""         # exact Authenticode subject pin
    mobile_host_number: str = ""                  # this machine's registered Signal number
    mobile_dest_number: str = ""                  # operator's destination phone number
    # ── Linux eBPF kernel sensor — optional privileged supplement ──────────
    ebpf_enabled: bool = False
    # ── Online AI consult priority order (first with a key wins) ──
    ai_provider_order: list = field(default_factory=lambda: [
        "anthropic", "gemini", "groq", "openai", "openrouter", "ollama"
    ])
    # ── MCP server (local loopback — opt-in, default off) ──────────────────
    mcp_enabled: bool = False                   # start engines/mcp_server.py at boot
    mcp_port:    int  = 47923                   # loopback port for the MCP SSE endpoint
    # Separate authenticated JARVIS adapter. MCP stays read-only; this channel
    # accepts only a fixed catalog of confirmation-gated defensive scans.
    jarvis_control_enabled: bool = False
    jarvis_control_port: int = 47925
    # Local self-hosted fleet service. Loopback-only until an external mTLS
    # termination and deployment threat model are separately approved.
    fleet_service_enabled: bool = False
    fleet_service_port: int = 47930
    fleet_tenant_id: str = "local"

    # ── Audited interoperability (off until a destination is configured) ──
    siem_host: str = ""
    siem_port: int = 6514
    siem_protocol: str = "tls"               # tls | tcp | udp
    siem_min_severity: str = "MEDIUM"
    siem_allow_plaintext: bool = False
    siem_ca_file: str = ""
    siem_include_raw: bool = False
    remote_bridge_mode: str = ""              # "" | SENDER | RECEIVER
    remote_bridge_peer: str = ""
    remote_bridge_bind: str = "127.0.0.1"
    remote_bridge_port: int = 47924
    remote_bridge_node_id: str = ""
    remote_bridge_allow_nonloopback: bool = False
    ioc_feed_url: str = ""
    ioc_feed_sha256: str = ""

    # ── ARIA assistant layer (v1.8.0) — local, gated, defensive-only ───────
    aria_enabled: bool = False                  # master opt-in: HUD + local assistant
    perf_governor_enabled: bool = False         # ARIA Overdrive adaptive UI-path governor
    aria_persona: str = "aria"                 # aria | friday | ultron (presentation only)
    aria_voice_enabled: bool = False            # spoken threat narration (local TTS)
    aria_conversation_awareness: bool = False   # transient rolling room/follow-up context
    aria_always_listen: bool = False             # accept speech without a wake word
    aria_follow_up_seconds: int = 12             # no-wake follow-up window after a reply
    aria_hand_controls: bool = False             # local camera gesture navigation
    aria_camera_index: int = 0                   # explicit camera used by hand controls
    aria_voice_cloud_tts: bool = False          # allow ElevenLabs cloud TTS (opt-in egress)
    aria_cloud_fallback: bool = False           # send a sanitized question to a configured cloud AI if local AI is offline
    alert_analysis_cloud_fallback: bool = False # send privacy-sanitized alert evidence only after a separate explicit opt-in
    # Microphone source for listening: "" / "default" = the computer's built-in
    # mic (default); otherwise the sounddevice input-device index (as a string)
    # of an added/external mic chosen in Settings.
    aria_mic_device: str = ""
    aria_push_enabled: bool = False             # auto-brief a channel on criticals
    aria_push_kind: str = "slack"               # slack | teams | ntfy | webhook
    aria_push_url: str = ""                      # channel webhook URL (blank = disabled)
    aria_inbox_enabled: bool = False            # inbox phishing triage (background IMAP poller)
    aria_imap_host: str = ""                     # IMAP server, e.g. imap.gmail.com
    aria_imap_user: str = ""                     # mailbox address; password stays in the OS credential store
    aria_inbox_interval_min: int = 5             # how often to scan the mailbox (minutes)
    aria_research_egress: bool = False          # allow headless research fetches (else browser-surface)
    # ── Microsoft Teams bot (two-way ARIA over Teams) — opt-in, default off ──
    teams_bot_enabled: bool = False
    teams_app_id: str = ""                       # Azure Bot App ID; secret stays in the OS credential store
    teams_allowed_users: str = ""                # comma/semicolon-separated immutable Teams user IDs
    teams_bot_port: int = 3978                   # local Bot Framework messaging-endpoint port
    teams_bot_skip_auth: bool = False            # runtime-only dev switch; never persisted
    # ── ARIA model tuning ──
    ollama_keep_alive: str = "30m"               # Full mode lease; Chill overrides this to immediate release

    # ── UI scale (responsive buttons/text) ─────────────────────────────────
    # "auto"  = scale the whole UI with the window size (default; clamped to a
    #           readable band in gui/theme.clamp_scale).
    # "fixed" = pin the UI at ui_scale_fixed regardless of window size — useful
    #           on very large or very high-DPI monitors where auto feels off.
    ui_scale_mode: str = "auto"                  # "auto" | "fixed"
    ui_scale_fixed: float = 1.0                  # honored only when mode == "fixed"
    ui_motion_enabled: bool = True                # polished panel reveals; OS reduced-motion still wins
    dashboard_mode: str = "classic"              # "classic" | "flow" (Local SOC workspace)
    holographic_orb_enabled: bool = True          # minimized-window token + radial service controls
    # Global center; the pair (-1, -1) selects the active-screen corner. A
    # single negative coordinate is valid for monitors left/above primary.
    holographic_orb_x: int = -1
    holographic_orb_y: int = -1
    # Offline normal-process learning is opt-in and suggestion-only. It never
    # changes threat posture until the operator approves a mature candidate.
    process_baseline_enabled: bool = False

    # ── Adversary Combat standing authority ────────────────────────────────
    # Maximum mode is deliberately availability-aggressive: detections are
    # acted on without a per-incident approval prompt. Every reversible action
    # is recorded so the operator can undo it from Settings.
    adversary_combat_enabled: bool = True
    adversary_combat_mode: str = "maximum"        # contain | aggressive | maximum
    adversary_combat_min_severity: str = "LOW"    # LOW | MEDIUM | HIGH | CRITICAL
    adversary_combat_block_network: bool = True
    adversary_combat_quarantine_files: bool = True
    adversary_combat_process_action: str = "terminate"  # suspend | terminate
    adversary_combat_isolate_host: bool = True
    adversary_combat_activate_honeypots: bool = True
    adversary_combat_isolation_threshold: int = 3

    # ── Self-hardening input integrity ─────────────────────────────────────
    # When True, After-Action Reports that aren't HMAC-authenticated (unsigned
    # or unverifiable) are REFUSED by the self-hardening loop, not just flagged
    # (see core/report_attest.py). Published to ANGERONA_REQUIRE_SIGNED_AAR so
    # the stdlib attestation layer honours it without a config handle.
    require_signed_aar: bool = True
    # Experimental: offload ransomware entropy scanning to worker processes so
    # the CPU-bound hashing runs off the main interpreter's GIL. Default off —
    # see core/entropy_pool.py. Published to ANGERONA_ENTROPY_POOL.
    entropy_pool_enabled: bool = False

    # ── Derived paths ───────────────────────────────────────────────────────
    @property
    def db_path(self) -> Path:
        return self.data_dir / "flight-recorder.db"

    @property
    def settings_path(self) -> Path:
        return self.data_dir / "settings.json"

    @property
    def external_modules_dir(self) -> Path:
        d = self.data_dir / "modules"
        d.mkdir(parents=True, exist_ok=True)
        return d

    def validate_integration_settings(self) -> None:
        """Validate non-secret interoperability settings before persistence/use."""

        def bounded(name: str, value: object, limit: int) -> str:
            text = _bounded_setting(value, "", limit)
            if text != str(value if value is not None else "").strip():
                raise ValueError(f"{name} contains invalid or excessive text")
            return text

        self.validate_mobile_settings()

        self.siem_host = bounded("SIEM host", self.siem_host, 253)
        if self.siem_host and (
            any(character.isspace() for character in self.siem_host)
            or any(character in self.siem_host for character in "/\\@")
        ):
            raise ValueError("SIEM host must be a hostname or IP address")
        self.siem_port = _port_setting(self.siem_port, 0)
        if not self.siem_port:
            raise ValueError("SIEM port must be between 1 and 65535")
        self.siem_protocol = bounded(
            "SIEM protocol", self.siem_protocol, 8
        ).casefold()
        if self.siem_protocol not in {"tls", "tcp", "udp"}:
            raise ValueError("SIEM protocol must be TLS, TCP, or UDP")
        self.siem_min_severity = bounded(
            "SIEM severity", self.siem_min_severity, 16
        ).upper()
        if self.siem_min_severity not in {
            "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"
        }:
            raise ValueError("SIEM severity is invalid")
        if self.siem_protocol != "tls" and not self.siem_allow_plaintext:
            raise ValueError(
                "TCP/UDP SIEM export requires explicit plaintext approval"
            )
        self.siem_ca_file = bounded("SIEM CA file", self.siem_ca_file, 1024)
        if self.siem_ca_file:
            ca_path = Path(self.siem_ca_file).expanduser()
            if not ca_path.is_absolute() or not ca_path.is_file():
                raise ValueError("SIEM CA file must be an existing absolute file")
            self.siem_ca_file = str(ca_path.resolve())

        self.remote_bridge_mode = bounded(
            "Remote Bridge mode", self.remote_bridge_mode, 16
        ).upper()
        if self.remote_bridge_mode not in {"", "SENDER", "RECEIVER"}:
            raise ValueError("Remote Bridge mode must be Off, Sender, or Receiver")
        self.remote_bridge_peer = bounded(
            "Remote Bridge peer", self.remote_bridge_peer, 320
        )
        if self.remote_bridge_mode == "SENDER":
            host, separator, port_text = self.remote_bridge_peer.rpartition(":")
            if not separator or not host or _port_setting(port_text, 0) == 0:
                raise ValueError("Remote Bridge sender requires peer host:port")
        self.remote_bridge_bind = bounded(
            "Remote Bridge bind", self.remote_bridge_bind, 253
        ) or "127.0.0.1"
        try:
            bind_address = ipaddress.ip_address(self.remote_bridge_bind)
        except ValueError as exc:
            raise ValueError("Remote Bridge bind must be a literal IP address") from exc
        if (
            self.remote_bridge_mode == "RECEIVER"
            and not bind_address.is_loopback
            and not self.remote_bridge_allow_nonloopback
        ):
            raise ValueError(
                "Non-loopback Remote Bridge receive requires explicit approval"
            )
        self.remote_bridge_port = _port_setting(self.remote_bridge_port, 0)
        if not self.remote_bridge_port:
            raise ValueError("Remote Bridge port must be between 1 and 65535")
        self.remote_bridge_node_id = bounded(
            "Remote Bridge node ID", self.remote_bridge_node_id, 64
        )

        raw_feed = bounded("IOC feed URL", self.ioc_feed_url, 2048)
        self.ioc_feed_url = _https_feed_setting(raw_feed)
        if raw_feed and not self.ioc_feed_url:
            raise ValueError("IOC feed must be a public HTTPS URL without credentials")
        self.ioc_feed_sha256 = bounded(
            "IOC feed SHA-256", self.ioc_feed_sha256, 64
        ).casefold()
        if self.ioc_feed_sha256 and not _SHA256.fullmatch(self.ioc_feed_sha256):
            raise ValueError("IOC feed SHA-256 must be exactly 64 hexadecimal characters")
        if self.ioc_feed_sha256 and not self.ioc_feed_url:
            raise ValueError("IOC feed pin requires an IOC feed URL")

    def validate_mobile_settings(self) -> None:
        """Fail closed on incomplete or ambiguous Mobile Bridge authority."""

        def bounded(name: str, value: object, limit: int) -> str:
            text = _bounded_setting(value, "", limit)
            if text != str(value if value is not None else "").strip():
                raise ValueError(f"{name} contains invalid or excessive text")
            return text

        self.mobile_signal_cli = bounded(
            "signal-cli path", self.mobile_signal_cli, 32767
        )
        self.mobile_signal_cli_sha256 = bounded(
            "signal-cli SHA-256", self.mobile_signal_cli_sha256, 64
        ).casefold()
        self.mobile_signal_cli_publisher = bounded(
            "signal-cli publisher", self.mobile_signal_cli_publisher, 512
        )
        self.mobile_host_number = bounded(
            "Signal host number", self.mobile_host_number, 32
        )
        self.mobile_dest_number = bounded(
            "Signal destination number", self.mobile_dest_number, 32
        )
        if self.mobile_signal_cli_sha256 and not _SHA256.fullmatch(
            self.mobile_signal_cli_sha256
        ):
            raise ValueError(
                "signal-cli SHA-256 must contain exactly 64 hexadecimal characters"
            )
        for label, number in (
            ("host", self.mobile_host_number),
            ("destination", self.mobile_dest_number),
        ):
            if number and not _SIGNAL_IDENTITY.fullmatch(number):
                raise ValueError(
                    f"Signal {label} number must use canonical E.164 form (for example +13035550100)"
                )
        if self.mobile_host_number and self.mobile_host_number == self.mobile_dest_number:
            raise ValueError("Signal host and destination numbers must be different")
        if self.mobile_enabled:
            missing = [
                label
                for label, value in (
                    ("absolute signal-cli path", self.mobile_signal_cli),
                    ("signal-cli SHA-256 pin", self.mobile_signal_cli_sha256),
                    ("exact Authenticode publisher", self.mobile_signal_cli_publisher),
                    ("Signal host number", self.mobile_host_number),
                    ("Signal destination number", self.mobile_dest_number),
                )
                if not value
            ]
            if missing:
                raise ValueError(
                    "Mobile Response Bridge cannot be enabled until these fields are set: "
                    + ", ".join(missing)
                )
            if not _SHA256.fullmatch(self.mobile_signal_cli_sha256):
                raise ValueError("Mobile Response Bridge requires an exact signal-cli SHA-256 pin")

    def publish_integration_environment(self) -> None:
        """Publish validated, non-secret connector settings to legacy modules."""
        self.validate_integration_settings()
        values = {
            "ANGERONA_SIEM_HOST": self.siem_host,
            "ANGERONA_SIEM_PORT": str(self.siem_port),
            "ANGERONA_SIEM_PROTO": self.siem_protocol,
            "ANGERONA_SIEM_MINSEV": self.siem_min_severity,
            "ANGERONA_SIEM_CA_FILE": self.siem_ca_file,
            "ANGERONA_BRIDGE_MODE": self.remote_bridge_mode,
            "ANGERONA_BRIDGE_PEER": self.remote_bridge_peer,
            "ANGERONA_BRIDGE_BIND": self.remote_bridge_bind,
            "ANGERONA_BRIDGE_PORT": str(self.remote_bridge_port),
            "ANGERONA_BRIDGE_NODE_ID": self.remote_bridge_node_id,
            "ANGERONA_IOC_FEED": self.ioc_feed_url,
            "ANGERONA_IOC_FEED_SHA256": self.ioc_feed_sha256,
        }
        for name, value in values.items():
            if value:
                os.environ[name] = value
            else:
                os.environ.pop(name, None)
        for name, enabled in {
            "ANGERONA_SIEM_ALLOW_PLAINTEXT": self.siem_allow_plaintext,
            "ANGERONA_SIEM_INCLUDE_RAW": self.siem_include_raw,
            "ANGERONA_BRIDGE_ALLOW_NONLOOPBACK": (
                self.remote_bridge_allow_nonloopback
            ),
        }.items():
            if enabled:
                os.environ[name] = "1"
            else:
                os.environ.pop(name, None)

    # ── Persistence ─────────────────────────────────────────────────────────
    @classmethod
    def load(cls) -> "Config":
        cfg = cls()
        cls._load_dotenv(cfg)
        if cfg.settings_path.exists():
            try:
                data = json.loads(cfg.settings_path.read_text(encoding="utf-8"))
                cfg.ollama_host = data.get("ollama_host", cfg.ollama_host)
                cfg.ollama_model = data.get("ollama_model", cfg.ollama_model)
                cfg.github_repo = data.get("github_repo", cfg.github_repo)
                cfg.theme = data.get("theme", cfg.theme)
                cfg.accent = data.get("accent", cfg.accent)
                cfg.module_states = data.get("module_states", {})
                cfg.autostart_enabled = _bool_setting(
                    data, "autostart_enabled", cfg.autostart_enabled)
                cfg.eco_mode = _bool_setting(data, "eco_mode", cfg.eco_mode)
                cfg.blackbox_enabled = _bool_setting(
                    data, "blackbox_enabled", cfg.blackbox_enabled)
                cfg.deception_user_folders = _bool_setting(
                    data, "deception_user_folders", cfg.deception_user_folders)
                cfg.mobile_enabled = _bool_setting(
                    data, "mobile_enabled", cfg.mobile_enabled)
                cfg.mobile_signal_cli = _bounded_setting(
                    data.get("mobile_signal_cli"), "", 32767
                )
                requested_mobile_digest = _bounded_setting(
                    data.get("mobile_signal_cli_sha256"), "", 64
                ).casefold()
                cfg.mobile_signal_cli_sha256 = (
                    requested_mobile_digest
                    if _SHA256.fullmatch(requested_mobile_digest)
                    else ""
                )
                cfg.mobile_signal_cli_publisher = _bounded_setting(
                    data.get("mobile_signal_cli_publisher"), "", 512
                )
                cfg.mobile_host_number = _bounded_setting(
                    data.get("mobile_host_number"), "", 32
                )
                cfg.mobile_dest_number = _bounded_setting(
                    data.get("mobile_dest_number"), "", 32
                )
                cfg.ebpf_enabled = _bool_setting(
                    data, "ebpf_enabled", cfg.ebpf_enabled)
                cfg.ai_provider_order = data.get("ai_provider_order", cfg.ai_provider_order)
                cfg.mcp_enabled = _bool_setting(
                    data, "mcp_enabled", cfg.mcp_enabled)
                cfg.mcp_port    = int(data.get("mcp_port", cfg.mcp_port))
                cfg.jarvis_control_enabled = _bool_setting(
                    data, "jarvis_control_enabled", cfg.jarvis_control_enabled)
                try:
                    cfg.jarvis_control_port = int(
                        data.get("jarvis_control_port", cfg.jarvis_control_port)
                    )
                except (TypeError, ValueError):
                    pass
                cfg.fleet_service_enabled = _bool_setting(
                    data, "fleet_service_enabled", cfg.fleet_service_enabled)
                try:
                    cfg.fleet_service_port = int(
                        data.get("fleet_service_port", cfg.fleet_service_port)
                    )
                except (TypeError, ValueError):
                    pass
                cfg.fleet_tenant_id = str(
                    data.get("fleet_tenant_id", cfg.fleet_tenant_id)
                )
                cfg.siem_host = _bounded_setting(
                    data.get("siem_host"), cfg.siem_host, 253
                )
                cfg.siem_port = _port_setting(
                    data.get("siem_port"), cfg.siem_port
                )
                requested_siem_protocol = _bounded_setting(
                    data.get("siem_protocol"), cfg.siem_protocol, 8
                ).casefold()
                cfg.siem_protocol = (
                    requested_siem_protocol
                    if requested_siem_protocol in {"tls", "tcp", "udp"}
                    else "tls"
                )
                requested_siem_severity = _bounded_setting(
                    data.get("siem_min_severity"), cfg.siem_min_severity, 16
                ).upper()
                cfg.siem_min_severity = (
                    requested_siem_severity
                    if requested_siem_severity
                    in {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
                    else "MEDIUM"
                )
                cfg.siem_allow_plaintext = _bool_setting(
                    data, "siem_allow_plaintext", cfg.siem_allow_plaintext
                )
                cfg.siem_ca_file = _bounded_setting(
                    data.get("siem_ca_file"), cfg.siem_ca_file, 1024
                )
                cfg.siem_include_raw = _bool_setting(
                    data, "siem_include_raw", cfg.siem_include_raw
                )
                requested_bridge_mode = _bounded_setting(
                    data.get("remote_bridge_mode"), "", 16
                ).upper()
                cfg.remote_bridge_mode = (
                    requested_bridge_mode
                    if requested_bridge_mode in {"", "SENDER", "RECEIVER"}
                    else ""
                )
                cfg.remote_bridge_peer = _bounded_setting(
                    data.get("remote_bridge_peer"), "", 320
                )
                cfg.remote_bridge_bind = _bounded_setting(
                    data.get("remote_bridge_bind"), "127.0.0.1", 253
                )
                cfg.remote_bridge_port = _port_setting(
                    data.get("remote_bridge_port"), cfg.remote_bridge_port
                )
                cfg.remote_bridge_node_id = _bounded_setting(
                    data.get("remote_bridge_node_id"), "", 64
                )
                cfg.remote_bridge_allow_nonloopback = _bool_setting(
                    data,
                    "remote_bridge_allow_nonloopback",
                    cfg.remote_bridge_allow_nonloopback,
                )
                cfg.ioc_feed_url = _https_feed_setting(data.get("ioc_feed_url"))
                requested_ioc_pin = _bounded_setting(
                    data.get("ioc_feed_sha256"), "", 64
                ).casefold()
                cfg.ioc_feed_sha256 = (
                    requested_ioc_pin if _SHA256.fullmatch(requested_ioc_pin) else ""
                )
                cfg.aria_enabled = _bool_setting(
                    data, "aria_enabled", cfg.aria_enabled)
                cfg.perf_governor_enabled = _bool_setting(
                    data, "perf_governor_enabled", cfg.perf_governor_enabled)
                requested_persona = str(
                    data.get("aria_persona", cfg.aria_persona)
                ).strip().lower()
                cfg.aria_persona = (
                    requested_persona
                    if requested_persona in {"aria", "friday", "ultron"}
                    else "aria"
                )
                cfg.aria_voice_enabled = _bool_setting(
                    data, "aria_voice_enabled", cfg.aria_voice_enabled)
                cfg.aria_conversation_awareness = _bool_setting(
                    data,
                    "aria_conversation_awareness",
                    cfg.aria_conversation_awareness,
                )
                cfg.aria_always_listen = _bool_setting(
                    data, "aria_always_listen", cfg.aria_always_listen)
                try:
                    cfg.aria_follow_up_seconds = max(
                        0,
                        min(60, int(data.get(
                            "aria_follow_up_seconds", cfg.aria_follow_up_seconds
                        ))),
                    )
                except (TypeError, ValueError, OverflowError):
                    pass
                cfg.aria_hand_controls = _bool_setting(
                    data, "aria_hand_controls", cfg.aria_hand_controls)
                try:
                    cfg.aria_camera_index = max(
                        0,
                        min(16, int(data.get(
                            "aria_camera_index", cfg.aria_camera_index
                        ))),
                    )
                except (TypeError, ValueError, OverflowError):
                    pass
                cfg.aria_voice_cloud_tts = _bool_setting(
                    data, "aria_voice_cloud_tts", cfg.aria_voice_cloud_tts)
                cfg.aria_cloud_fallback = _bool_setting(
                    data, "aria_cloud_fallback", cfg.aria_cloud_fallback)
                cfg.alert_analysis_cloud_fallback = _bool_setting(
                    data,
                    "alert_analysis_cloud_fallback",
                    cfg.alert_analysis_cloud_fallback,
                )
                cfg.aria_mic_device       = str(data.get("aria_mic_device", cfg.aria_mic_device))
                cfg.aria_push_enabled = _bool_setting(
                    data, "aria_push_enabled", cfg.aria_push_enabled)
                cfg.aria_push_kind        = data.get("aria_push_kind", cfg.aria_push_kind)
                # Webhook URLs contain bearer-like channel credentials. Prefer
                # the OS credential store and read the settings value only as a legacy
                # in-memory fallback that the next successful save migrates.
                cfg.aria_push_url = os.environ.get(
                    _ARIA_PUSH_URL_KEY,
                    data.get("aria_push_url", cfg.aria_push_url),
                )
                cfg.aria_inbox_enabled = _bool_setting(
                    data, "aria_inbox_enabled", cfg.aria_inbox_enabled)
                cfg.aria_imap_host        = data.get("aria_imap_host", cfg.aria_imap_host)
                cfg.aria_imap_user        = data.get("aria_imap_user", cfg.aria_imap_user)
                cfg.aria_inbox_interval_min = int(data.get("aria_inbox_interval_min", cfg.aria_inbox_interval_min))
                cfg.aria_research_egress = _bool_setting(
                    data, "aria_research_egress", cfg.aria_research_egress)
                cfg.teams_bot_enabled = _bool_setting(
                    data, "teams_bot_enabled", cfg.teams_bot_enabled)
                cfg.teams_app_id          = data.get("teams_app_id", cfg.teams_app_id)
                cfg.teams_allowed_users   = data.get("teams_allowed_users", cfg.teams_allowed_users)
                cfg.teams_bot_port        = int(data.get("teams_bot_port", cfg.teams_bot_port))
                # Authentication bypasses are never restored from disk.
                cfg.teams_bot_skip_auth = False
                cfg.ollama_keep_alive     = data.get("ollama_keep_alive", cfg.ollama_keep_alive)
                cfg.ui_scale_mode         = str(data.get("ui_scale_mode", cfg.ui_scale_mode))
                try:
                    cfg.ui_scale_fixed    = float(data.get("ui_scale_fixed", cfg.ui_scale_fixed))
                except (TypeError, ValueError):
                    pass
                cfg.ui_motion_enabled = _bool_setting(
                    data, "ui_motion_enabled", cfg.ui_motion_enabled)
                requested_dashboard = str(
                    data.get("dashboard_mode", cfg.dashboard_mode)
                ).strip().lower()
                cfg.dashboard_mode = (
                    requested_dashboard
                    if requested_dashboard in {"classic", "flow"}
                    else "classic"
                )
                cfg.holographic_orb_enabled = _bool_setting(
                    data,
                    "holographic_orb_enabled",
                    cfg.holographic_orb_enabled,
                )
                cfg.process_baseline_enabled = _bool_setting(
                    data,
                    "process_baseline_enabled",
                    cfg.process_baseline_enabled,
                )
                cfg.adversary_combat_enabled = _bool_setting(
                    data, "adversary_combat_enabled", cfg.adversary_combat_enabled)
                requested_combat_mode = str(data.get(
                    "adversary_combat_mode", cfg.adversary_combat_mode
                )).strip().lower()
                cfg.adversary_combat_mode = (
                    requested_combat_mode
                    if requested_combat_mode in {"contain", "aggressive", "maximum"}
                    else "maximum"
                )
                requested_combat_severity = str(data.get(
                    "adversary_combat_min_severity",
                    cfg.adversary_combat_min_severity,
                )).strip().upper()
                cfg.adversary_combat_min_severity = (
                    requested_combat_severity
                    if requested_combat_severity in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
                    else "LOW"
                )
                cfg.adversary_combat_block_network = _bool_setting(
                    data,
                    "adversary_combat_block_network",
                    cfg.adversary_combat_block_network,
                )
                cfg.adversary_combat_quarantine_files = _bool_setting(
                    data,
                    "adversary_combat_quarantine_files",
                    cfg.adversary_combat_quarantine_files,
                )
                requested_process_action = str(data.get(
                    "adversary_combat_process_action",
                    cfg.adversary_combat_process_action,
                )).strip().lower()
                cfg.adversary_combat_process_action = (
                    requested_process_action
                    if requested_process_action in {"suspend", "terminate"}
                    else "terminate"
                )
                cfg.adversary_combat_isolate_host = _bool_setting(
                    data,
                    "adversary_combat_isolate_host",
                    cfg.adversary_combat_isolate_host,
                )
                cfg.adversary_combat_activate_honeypots = _bool_setting(
                    data,
                    "adversary_combat_activate_honeypots",
                    cfg.adversary_combat_activate_honeypots,
                )
                try:
                    cfg.adversary_combat_isolation_threshold = max(
                        1,
                        min(100, int(data.get(
                            "adversary_combat_isolation_threshold",
                            cfg.adversary_combat_isolation_threshold,
                        ))),
                    )
                except (TypeError, ValueError, OverflowError):
                    cfg.adversary_combat_isolation_threshold = 3
                try:
                    cfg.holographic_orb_x = int(
                        data.get("holographic_orb_x", cfg.holographic_orb_x)
                    )
                    cfg.holographic_orb_y = int(
                        data.get("holographic_orb_y", cfg.holographic_orb_y)
                    )
                except (TypeError, ValueError, OverflowError):
                    cfg.holographic_orb_x = -1
                    cfg.holographic_orb_y = -1
                cfg.require_signed_aar = _bool_setting(
                    data, "require_signed_aar", cfg.require_signed_aar)
                cfg.entropy_pool_enabled = _bool_setting(
                    data, "entropy_pool_enabled", cfg.entropy_pool_enabled)
            except Exception:
                pass
        # OLLAMA_HOST env var (set by the D-drive Ollama install) wins.
        cfg.ollama_host = os.environ.get("OLLAMA_HOST", cfg.ollama_host)
        # Publish the AI consult order to the environment so engines/ai_consult.py
        # (stdlib, no config handle) honours the operator's chosen priority.
        try:
            if cfg.ai_provider_order:
                os.environ["ANGERONA_AI_ORDER"] = ",".join(cfg.ai_provider_order)
        except Exception:
            pass
        # Publish integrity/perf toggles to the environment for the stdlib layers
        # that read them (report_attest, entropy_pool). Only publish when enabled
        # so a manually-set env var isn't clobbered off by a default-false config.
        try:
            if cfg.require_signed_aar:
                os.environ["ANGERONA_REQUIRE_SIGNED_AAR"] = "1"
            if cfg.entropy_pool_enabled:
                os.environ["ANGERONA_ENTROPY_POOL"] = "1"
            if cfg.deception_user_folders:
                os.environ["ANGERONA_USER_FOLDER_DECEPTION"] = "1"
            else:
                os.environ.pop("ANGERONA_USER_FOLDER_DECEPTION", None)
            if cfg.adversary_combat_enabled:
                os.environ["ANGERONA_ADVERSARY_COMBAT_ENABLED"] = "1"
                os.environ["ANGERONA_ADVERSARY_COMBAT_MODE"] = (
                    cfg.adversary_combat_mode
                )
            else:
                os.environ.pop("ANGERONA_ADVERSARY_COMBAT_ENABLED", None)
                os.environ.pop("ANGERONA_ADVERSARY_COMBAT_MODE", None)
        except Exception:
            pass
        # The ARIA master switch is a real authority/sensor boundary. Legacy or
        # hand-edited settings cannot leave subordinate listeners/connectors
        # active while the master is off.
        if not cfg.aria_enabled:
            cfg.perf_governor_enabled = False
            cfg.aria_voice_enabled = False
            cfg.aria_voice_cloud_tts = False
            cfg.aria_conversation_awareness = False
            cfg.aria_always_listen = False
            cfg.aria_hand_controls = False
            cfg.aria_cloud_fallback = False
            cfg.aria_push_enabled = False
            cfg.aria_inbox_enabled = False
            cfg.aria_research_egress = False
            cfg.teams_bot_enabled = False
        try:
            cfg.validate_mobile_settings()
        except ValueError:
            # Older settings could enable the bridge without executable pins.
            # Preserve well-formed values for operator repair, but remove all
            # remote authority. Malformed values fall back to empty defaults.
            cfg.mobile_enabled = False
            try:
                cfg.validate_mobile_settings()
            except ValueError:
                defaults = cls(data_dir=cfg.data_dir)
                for name in (
                    "mobile_signal_cli",
                    "mobile_signal_cli_sha256",
                    "mobile_signal_cli_publisher",
                    "mobile_host_number",
                    "mobile_dest_number",
                ):
                    setattr(cfg, name, getattr(defaults, name))
        try:
            cfg.publish_integration_environment()
        except ValueError:
            # A hand-edited invalid integration block is never inherited as
            # network authority. Reset only that block and publish safe defaults.
            defaults = cls(data_dir=cfg.data_dir)
            for name in (
                "siem_host", "siem_port", "siem_protocol", "siem_min_severity",
                "siem_allow_plaintext", "siem_ca_file", "siem_include_raw",
                "remote_bridge_mode", "remote_bridge_peer", "remote_bridge_bind",
                "remote_bridge_port", "remote_bridge_node_id",
                "remote_bridge_allow_nonloopback", "ioc_feed_url",
                "ioc_feed_sha256",
            ):
                setattr(cfg, name, getattr(defaults, name))
            cfg.publish_integration_environment()
        return cfg

    def save(self) -> None:
        self.validate_integration_settings()
        # Persist the push webhook before replacing settings.json. If the OS store is
        # unavailable, fail the save rather than falling back to a plaintext
        # credential in the general settings file.
        previous_push: str | None = None
        push_touched = bool(self.aria_push_url or os.environ.get(_ARIA_PUSH_URL_KEY))
        if push_touched:
            from angerona.core.secure_store import read_secret_values, write_secret_map

            previous_push = read_secret_values(
                (_ARIA_PUSH_URL_KEY,), self.data_dir, strict=True
            ).get(_ARIA_PUSH_URL_KEY)
            write_secret_map({_ARIA_PUSH_URL_KEY: self.aria_push_url}, self.data_dir)
        encoded = json.dumps(
                {
                    "ollama_host": self.ollama_host,
                    "ollama_model": self.ollama_model,
                    "github_repo": self.github_repo,
                    "theme": self.theme,
                    "accent": self.accent,
                    "module_states":     self.module_states,
                    "autostart_enabled": self.autostart_enabled,
                    "eco_mode":          self.eco_mode,
                    "blackbox_enabled":  self.blackbox_enabled,
                    "deception_user_folders": self.deception_user_folders,
                    "mobile_enabled":     self.mobile_enabled,
                    "mobile_signal_cli":  self.mobile_signal_cli,
                    "mobile_signal_cli_sha256": self.mobile_signal_cli_sha256,
                    "mobile_signal_cli_publisher": self.mobile_signal_cli_publisher,
                    "mobile_host_number": self.mobile_host_number,
                    "mobile_dest_number": self.mobile_dest_number,
                    "ebpf_enabled":       self.ebpf_enabled,
                    "ai_provider_order":  self.ai_provider_order,
                    "mcp_enabled":       self.mcp_enabled,
                    "mcp_port":          self.mcp_port,
                    "jarvis_control_enabled": self.jarvis_control_enabled,
                    "jarvis_control_port": self.jarvis_control_port,
                    "fleet_service_enabled": self.fleet_service_enabled,
                    "fleet_service_port": self.fleet_service_port,
                    "fleet_tenant_id": self.fleet_tenant_id,
                    "siem_host": self.siem_host,
                    "siem_port": self.siem_port,
                    "siem_protocol": self.siem_protocol,
                    "siem_min_severity": self.siem_min_severity,
                    "siem_allow_plaintext": self.siem_allow_plaintext,
                    "siem_ca_file": self.siem_ca_file,
                    "siem_include_raw": self.siem_include_raw,
                    "remote_bridge_mode": self.remote_bridge_mode,
                    "remote_bridge_peer": self.remote_bridge_peer,
                    "remote_bridge_bind": self.remote_bridge_bind,
                    "remote_bridge_port": self.remote_bridge_port,
                    "remote_bridge_node_id": self.remote_bridge_node_id,
                    "remote_bridge_allow_nonloopback": (
                        self.remote_bridge_allow_nonloopback
                    ),
                    "ioc_feed_url": self.ioc_feed_url,
                    "ioc_feed_sha256": self.ioc_feed_sha256,
                    "aria_enabled":          self.aria_enabled,
                    "perf_governor_enabled": self.perf_governor_enabled,
                    "aria_persona":          self.aria_persona,
                    "aria_voice_enabled":    self.aria_voice_enabled,
                    "aria_conversation_awareness": self.aria_conversation_awareness,
                    "aria_always_listen":    self.aria_always_listen,
                    "aria_follow_up_seconds": self.aria_follow_up_seconds,
                    "aria_hand_controls":    self.aria_hand_controls,
                    "aria_camera_index":     self.aria_camera_index,
                    "aria_voice_cloud_tts":  self.aria_voice_cloud_tts,
                    "aria_cloud_fallback":   self.aria_cloud_fallback,
                    "alert_analysis_cloud_fallback": self.alert_analysis_cloud_fallback,
                    "aria_mic_device":       self.aria_mic_device,
                    "aria_push_enabled":     self.aria_push_enabled,
                    "aria_push_kind":        self.aria_push_kind,
                    "aria_inbox_enabled":    self.aria_inbox_enabled,
                    "aria_imap_host":        self.aria_imap_host,
                    "aria_imap_user":        self.aria_imap_user,
                    "aria_inbox_interval_min": self.aria_inbox_interval_min,
                    "aria_research_egress":  self.aria_research_egress,
                    "teams_bot_enabled":     self.teams_bot_enabled,
                    "teams_app_id":          self.teams_app_id,
                    "teams_allowed_users":   self.teams_allowed_users,
                    "teams_bot_port":        self.teams_bot_port,
                    "ollama_keep_alive":     self.ollama_keep_alive,
                    "ui_scale_mode":         self.ui_scale_mode,
                    "ui_scale_fixed":        self.ui_scale_fixed,
                    "ui_motion_enabled":     self.ui_motion_enabled,
                    "dashboard_mode":        self.dashboard_mode,
                    "holographic_orb_enabled": self.holographic_orb_enabled,
                    "holographic_orb_x":     self.holographic_orb_x,
                    "holographic_orb_y":     self.holographic_orb_y,
                    "process_baseline_enabled": self.process_baseline_enabled,
                    "adversary_combat_enabled": self.adversary_combat_enabled,
                    "adversary_combat_mode": self.adversary_combat_mode,
                    "adversary_combat_min_severity": self.adversary_combat_min_severity,
                    "adversary_combat_block_network": self.adversary_combat_block_network,
                    "adversary_combat_quarantine_files": self.adversary_combat_quarantine_files,
                    "adversary_combat_process_action": self.adversary_combat_process_action,
                    "adversary_combat_isolate_host": self.adversary_combat_isolate_host,
                    "adversary_combat_activate_honeypots": self.adversary_combat_activate_honeypots,
                    "adversary_combat_isolation_threshold": self.adversary_combat_isolation_threshold,
                    "require_signed_aar":    self.require_signed_aar,
                    "entropy_pool_enabled":  self.entropy_pool_enabled,
                },
                indent=2,
            )
        try:
            _atomic_write_text(self.settings_path, encoded)
        except Exception as save_exc:
            if push_touched:
                try:
                    from angerona.core.secure_store import write_secret_map

                    write_secret_map(
                        {_ARIA_PUSH_URL_KEY: previous_push or ""}, self.data_dir
                    )
                except Exception as rollback_exc:
                    raise RuntimeError(
                        "settings save failed and protected push credential rollback failed: "
                        f"save={save_exc}; rollback={rollback_exc}"
                    ) from save_exc
            raise
        self.publish_integration_environment()

    @staticmethod
    def _load_dotenv(cfg: "Config") -> None:
        """Load only the protected canonical credential store.

        The process working directory is intentionally never trusted as a
        credential source: Angerona commonly runs elevated and a writable
        checkout-level .env would become a privilege-boundary injection point.
        Legacy import is an explicit operator/installer action.
        """
        from angerona.core.secure_store import load_into_environment
        load_into_environment(cfg.data_dir)
