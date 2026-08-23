"""Comprehensive, platform-aware Angerona end-user setup program.

The wizard exposes every supported end-user configuration area in one bounded
flow. Ordinary values are staged until Finish, credentials are written only to
the operating-system protected store, and network/cloud features remain opt-in.
The data model and validators are usable without Qt for cross-platform tests.
"""
from __future__ import annotations

import os
import re
import shutil
import sys
from dataclasses import dataclass
from typing import Any, Mapping
from urllib.parse import urlsplit


CONFIG_KINDS = frozenset({
    "check", "text", "secret_config", "combo", "mic", "spin", "double",
})
SECRET_KINDS = frozenset({"password_env", "provider_secret"})


@dataclass(frozen=True)
class Field:
    kind: str
    key: str
    label: str
    placeholder: str = ""
    options: tuple = ()
    note: str = ""
    minimum: float = 0
    maximum: float = 65535
    platforms: tuple[str, ...] = ()


@dataclass(frozen=True)
class Step:
    title: str
    intro: str
    fields: tuple[Field, ...] = ()


SETUP_PROFILES: dict[str, dict[str, object]] = {
    "Recommended local protection": {
        "eco_mode": True,
        "aria_enabled": True,
        "perf_governor_enabled": True,
        "process_baseline_enabled": True,
        "require_signed_aar": True,
        "entropy_pool_enabled": False,
        "aria_cloud_fallback": False,
        "alert_analysis_cloud_fallback": False,
        "aria_voice_cloud_tts": False,
        "aria_research_egress": False,
        "aria_push_enabled": False,
        "aria_inbox_enabled": False,
        "teams_bot_enabled": False,
        "mobile_enabled": False,
        "mcp_enabled": False,
        "jarvis_control_enabled": False,
        "fleet_service_enabled": False,
    },
    "Maximum local coverage": {
        "eco_mode": False,
        "aria_enabled": True,
        "perf_governor_enabled": True,
        "process_baseline_enabled": True,
        "require_signed_aar": True,
        "entropy_pool_enabled": True,
        "aria_cloud_fallback": False,
        "alert_analysis_cloud_fallback": False,
        "aria_voice_cloud_tts": False,
        "aria_research_egress": False,
        "aria_push_enabled": False,
        "aria_inbox_enabled": False,
        "teams_bot_enabled": False,
        "mobile_enabled": False,
        "mcp_enabled": False,
        "jarvis_control_enabled": False,
        "fleet_service_enabled": False,
    },
    "Low-resource local": {
        "eco_mode": True,
        "aria_enabled": True,
        "perf_governor_enabled": False,
        "process_baseline_enabled": False,
        "require_signed_aar": True,
        "entropy_pool_enabled": False,
        "aria_cloud_fallback": False,
        "alert_analysis_cloud_fallback": False,
        "aria_voice_cloud_tts": False,
        "aria_research_egress": False,
        "aria_push_enabled": False,
        "aria_inbox_enabled": False,
        "teams_bot_enabled": False,
        "mobile_enabled": False,
        "mcp_enabled": False,
        "jarvis_control_enabled": False,
        "fleet_service_enabled": False,
    },
}


STEPS: tuple[Step, ...] = (
    Step(
        "Welcome to Angerona Full Setup",
        "Configure the complete supported product in one pass. Nothing is sent "
        "off this device unless you explicitly enable an option marked as network "
        "or cloud. Changes are reviewed and saved only when you press Finish.",
        (
            Field("profile", "_profile", "Starting profile", options=tuple(SETUP_PROFILES)),
            Field("action", "apply_profile", "Apply selected profile"),
            Field("action", "run_preflight", "Run local setup preflight"),
        ),
    ),
    Step(
        "Appearance and accessibility",
        "Choose the dashboard presentation and motion level.",
        (
            Field("combo", "theme", "Theme", options=("cyber", "crt", "slate")),
            Field(
                "combo", "dashboard_mode", "Startup dashboard",
                options=("classic", "flow"),
                note="Flow opens the Local SOC workspace; Classic remains available.",
            ),
            Field("text", "accent", "Accent colour", "#1f9cff"),
            Field("combo", "ui_scale_mode", "UI scaling", options=("auto", "fixed")),
            Field("double", "ui_scale_fixed", "Fixed UI scale", minimum=0.75, maximum=1.50),
            Field("check", "ui_motion_enabled", "Enable interface motion and panel reveals"),
            Field("check", "holographic_orb_enabled", "Enable the minimized holographic globe"),
            Field("action", "reset_orb", "Reset globe position to the active-screen corner"),
        ),
    ),
    Step(
        "Local AI and ARIA",
        "Configure the local Ollama service. Local AI is the recommended default.",
        (
            Field("check", "aria_enabled", "Enable the ARIA local security assistant"),
            Field("text", "ollama_host", "Ollama address", "http://127.0.0.1:11434"),
            Field("text", "ollama_model", "Local model", "llama3"),
            Field("text", "ollama_keep_alive", "Model keep-alive", "30m"),
            Field("text", "ai_provider_order", "AI priority", "anthropic,gemini,groq,openai,openrouter,ollama",
                  note="Comma-separated. Ollama remains available without a cloud key."),
            Field("action", "check_ollama", "Check local Ollama availability"),
        ),
    ),
    Step(
        "Optional AI provider credentials",
        "Leave fields blank to keep existing protected credentials. Cloud providers "
        "are never contacted unless a separate cloud fallback is enabled.",
        (
            Field("provider_secret", "anthropic", "Anthropic API key"),
            Field("provider_secret", "gemini", "Gemini API key or rotation pool"),
            Field("provider_secret", "groq", "Groq API key"),
            Field("provider_secret", "openai", "OpenAI API key"),
            Field("provider_secret", "openrouter", "OpenRouter API key"),
        ),
    ),
    Step(
        "Voice and microphone",
        "Configure local speech and the microphone used for push-to-talk.",
        (
            Field("check", "aria_voice_enabled", "Enable local spoken replies"),
            Field("mic", "aria_mic_device", "Microphone"),
            Field("check", "aria_voice_cloud_tts", "Allow cloud text-to-speech",
                  note="Opt-in network egress; local speech remains available without it."),
        ),
    ),
    Step(
        "Privacy and research",
        "Every switch on this page can create outbound traffic and is off by default.",
        (
            Field("check", "aria_cloud_fallback", "Allow sanitized ARIA questions to use cloud AI"),
            Field("check", "alert_analysis_cloud_fallback", "Allow separately sanitized alert evidence to use cloud AI"),
            Field("check", "aria_research_egress", "Allow background threat-research web requests"),
        ),
    ),
    Step(
        "Critical-alert destination",
        "Optional outbound notification channel. The destination is stored as a credential.",
        (
            Field("check", "aria_push_enabled", "Send critical-alert briefings"),
            Field("combo", "aria_push_kind", "Destination type", options=("slack", "teams", "ntfy", "webhook")),
            Field("secret_config", "aria_push_url", "Destination URL", "Leave blank to keep the configured URL"),
        ),
    ),
    Step(
        "Mailbox phishing triage",
        "Optional read-only IMAP polling. The mailbox password stays in the OS credential store.",
        (
            Field("check", "aria_inbox_enabled", "Enable mailbox phishing triage"),
            Field("text", "aria_imap_host", "IMAP host", "imap.example.com"),
            Field("text", "aria_imap_user", "Mailbox account", "security@example.com"),
            Field("spin", "aria_inbox_interval_min", "Polling interval (minutes)", minimum=1, maximum=1440),
            Field("password_env", "ARIA_IMAP_PASS", "Mailbox password"),
        ),
    ),
    Step(
        "Microsoft Teams bot",
        "Optional two-way ARIA connector. An immutable user allowlist is required.",
        (
            Field("check", "teams_bot_enabled", "Enable the Teams bot"),
            Field("text", "teams_app_id", "Azure application ID"),
            Field("password_env", "ANGERONA_TEAMS_APP_PASSWORD", "Application secret"),
            Field("text", "teams_allowed_users", "Allowed immutable AAD object IDs"),
            Field("spin", "teams_bot_port", "Loopback port", minimum=1024, maximum=65535),
        ),
    ),
    Step(
        "Signal mobile bridge",
        "Optional Signal-based operator chat and response channel.",
        (
            Field("check", "mobile_enabled", "Enable the Signal mobile bridge"),
            Field("text", "mobile_signal_cli", "signal-cli executable path"),
            Field("text", "mobile_host_number", "This device's registered Signal number"),
            Field("text", "mobile_dest_number", "Approved operator Signal number"),
            Field("password_env", "ANGERONA_MOBILE_PIN", "Four-digit response PIN",
                  note="Stored only in the operating-system protected credential store."),
        ),
    ),
    Step(
        "Local integrations",
        "These services bind to loopback only. Keep them disabled unless a local integration needs them.",
        (
            Field("check", "mcp_enabled", "Enable the read-only local MCP service"),
            Field("spin", "mcp_port", "MCP loopback port", minimum=1024, maximum=65535),
            Field(
                "check",
                "jarvis_control_enabled",
                "Enable authenticated local JARVIS defensive controls",
            ),
            Field(
                "password_env",
                "ANGERONA_JARVIS_CONTROL_TOKEN",
                "JARVIS control token",
                "Leave blank to keep the protected token",
                note=(
                    "At least 32 bytes. Stored only in the operating-system "
                    "credential store and never accepted from the launch environment."
                ),
            ),
            Field(
                "action",
                "regenerate_jarvis_token",
                "Generate a new protected JARVIS token",
                note="The generated token is masked and is saved only when setup finishes.",
            ),
            Field(
                "spin",
                "jarvis_control_port",
                "JARVIS loopback port",
                minimum=1024,
                maximum=65535,
            ),
            Field("check", "fleet_service_enabled", "Enable the authenticated local fleet service"),
            Field("spin", "fleet_service_port", "Fleet loopback port", minimum=1024, maximum=65535),
            Field("text", "fleet_tenant_id", "Fleet tenant identifier", "local"),
        ),
    ),
    Step(
        "Platform sensors and resilience",
        "Only capabilities supported by this operating system can be enabled.",
        (
            Field("check", "blackbox_enabled", "Run the Windows Black Box sidecar", platforms=("win32",)),
            Field("check", "ebpf_enabled", "Enable the optional privileged Linux BCC/eBPF sensor", platforms=("linux",),
                  note="Do not run the desktop GUI as root; deploy the sensor separately."),
            Field("check", "process_baseline_enabled", "Learn normal signed processes for operator-reviewed trust suggestions"),
            Field("check", "require_signed_aar", "Require authenticated After-Action Reports"),
            Field(
                "check",
                "deception_user_folders",
                "Place inert deception markers in personal folders",
                note=(
                    "Advanced opt-in. Off keeps Angerona-created decoys under the configured "
                    "data directory; existing files are never overwritten."
                ),
            ),
            Field("action", "reset_modules", "Restore supported module defaults"),
        ),
    ),
    Step(
        "Performance and startup",
        "Choose the resource profile and sign-in behavior.",
        (
            Field("check", "autostart_enabled", "Start Angerona when I sign in"),
            Field("check", "eco_mode", "Start in network-first Chill Mode"),
            Field("check", "perf_governor_enabled", "Enable adaptive performance governance"),
            Field("check", "entropy_pool_enabled", "Use worker processes for entropy scanning"),
        ),
    ),
    Step(
        "Updates and storage",
        "Review where evidence is retained and configure the public release source.",
        (
            Field("text", "github_repo", "GitHub release repository", "owner/AngeronaSuite"),
            Field("info", "data_dir", "Evidence and settings location"),
        ),
    ),
    Step(
        "Trusted applications",
        "Trust is always an explicit operator decision. Automatic learning only creates suggestions.",
        (Field("action", "trust_running", "Trust current non-system applications by exact path",
               note="Angerona and Windows system processes are excluded. You must confirm this bulk action."),),
    ),
    Step(
        "Review and apply",
        "Review the summary below. Finish validates every enabled integration, writes "
        "ordinary settings to the protected data directory, writes credentials to the "
        "OS store, and applies platform-native startup registration.",
        (Field("review", "_review", "Pending configuration summary"),),
    ),
)


def platform_family(platform: str | None = None) -> str:
    value = sys.platform if platform is None else str(platform)
    if value.startswith("linux"):
        return "linux"
    if value == "darwin":
        return "darwin"
    if value.startswith("win"):
        return "win32"
    return value


def field_supported(field: Field, platform: str | None = None) -> bool:
    return not field.platforms or platform_family(platform) in field.platforms


def collect(step: Step, values: dict[str, object]) -> dict[str, Any]:
    """Return only ordinary Config assignments from one setup step."""
    return {
        field.key: values[field.key]
        for field in step.fields
        if field.kind in CONFIG_KINDS and field.key in values
    }


def normalize_setup_values(values: dict[str, object]) -> dict[str, object]:
    normalized = dict(values)
    order = normalized.get("ai_provider_order")
    if isinstance(order, str):
        normalized["ai_provider_order"] = [
            item.strip().casefold() for item in order.split(",") if item.strip()
        ]
    for key in ("ollama_host", "ollama_model", "ollama_keep_alive", "accent",
                "aria_imap_host", "aria_imap_user", "teams_app_id",
                "teams_allowed_users", "mobile_signal_cli", "mobile_host_number",
                "mobile_dest_number", "fleet_tenant_id", "github_repo"):
        if key in normalized:
            normalized[key] = str(normalized[key]).strip()
    return normalized


def validate_setup(values: dict[str, object]) -> list[str]:
    """Validate the complete staged setup without touching disk or the network."""
    values = normalize_setup_values(values)
    errors: list[str] = []
    accent = str(values.get("accent", ""))
    if accent and not re.fullmatch(r"#[0-9A-Fa-f]{6}", accent):
        errors.append("Accent colour must be a six-digit value such as #1f9cff.")

    ollama = str(values.get("ollama_host", ""))
    parsed = urlsplit(ollama)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        errors.append("Ollama address must be a complete http:// or https:// URL.")

    known_providers = {"anthropic", "gemini", "groq", "openai", "openrouter", "ollama"}
    order = values.get("ai_provider_order", [])
    if not isinstance(order, list) or not order or any(item not in known_providers for item in order):
        errors.append("AI priority contains an unknown provider or is empty.")

    for key, label in (
        ("mcp_port", "MCP"), ("jarvis_control_port", "JARVIS"),
        ("fleet_service_port", "Fleet"),
        ("teams_bot_port", "Teams"),
    ):
        try:
            port = int(values.get(key, 0))
            if not 1024 <= port <= 65535:
                raise ValueError
        except (TypeError, ValueError):
            errors.append(f"{label} port must be between 1024 and 65535.")

    try:
        interval = int(values.get("aria_inbox_interval_min", 0))
        if not 1 <= interval <= 1440:
            raise ValueError
    except (TypeError, ValueError):
        errors.append("Mailbox polling interval must be between 1 and 1440 minutes.")

    if values.get("aria_push_enabled") and not str(values.get("aria_push_url", "")).strip():
        if not os.environ.get("ANGERONA_ARIA_PUSH_URL"):
            errors.append("Critical-alert push requires a destination URL.")
    if values.get("aria_inbox_enabled") and not (
        str(values.get("aria_imap_host", "")).strip()
        and str(values.get("aria_imap_user", "")).strip()
    ):
        errors.append("Mailbox triage requires both an IMAP host and account.")
    if values.get("teams_bot_enabled") and not str(values.get("teams_allowed_users", "")).strip():
        errors.append("The Teams bot requires at least one immutable AAD object ID.")
    if values.get("mobile_enabled") and not (
        str(values.get("mobile_signal_cli", "")).strip()
        and str(values.get("mobile_host_number", "")).strip()
        and str(values.get("mobile_dest_number", "")).strip()
    ):
        errors.append("The Signal bridge requires signal-cli and both approved phone numbers.")
    tenant = str(values.get("fleet_tenant_id", ""))
    if values.get("fleet_service_enabled") and not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._:-]{2,127}", tenant
    ):
        errors.append("Fleet tenant must be 3-128 safe identifier characters.")
    repo = str(values.get("github_repo", ""))
    if repo and not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
        errors.append("GitHub repository must use the owner/repository form.")
    return errors


def validate_secret_requirements(
    values: dict[str, object],
    secret_updates: dict[str, str],
    environment: Mapping[str, str] = os.environ,
    protected_secrets: Mapping[str, str] | None = None,
) -> list[str]:
    """Require credentials for enabled connectors without exposing their values."""
    errors: list[str] = []
    protected = protected_secrets or {}
    available = lambda key: bool(secret_updates.get(key) or environment.get(key))
    if values.get("aria_inbox_enabled") and not available("ARIA_IMAP_PASS"):
        errors.append("Mailbox triage requires a protected mailbox password.")
    if values.get("teams_bot_enabled") and not available("ANGERONA_TEAMS_APP_PASSWORD"):
        errors.append("The Teams bot requires a protected application secret.")
    if values.get("mobile_enabled") and not (
        available("ANGERONA_MOBILE_PIN")
        or available("ANGERONA_MOBILE_PIN_DPAPI")
    ):
        errors.append("The Signal bridge requires a protected four-digit response PIN.")
    if values.get("jarvis_control_enabled"):
        # Do not consult ``environment`` for this authority: setup and runtime
        # deliberately reject inherited elevation-environment control tokens.
        token = str(
            secret_updates.get("ANGERONA_JARVIS_CONTROL_TOKEN")
            or protected.get("ANGERONA_JARVIS_CONTROL_TOKEN")
            or ""
        ).strip()
        if len(token.encode("utf-8")) < 32:
            errors.append(
                "JARVIS controls require a protected token of at least 32 bytes. "
                "Use Generate a new protected JARVIS token."
            )
    return errors


def local_preflight() -> tuple[tuple[str, bool, str], ...]:
    """Return privacy-safe local readiness checks; performs no network access."""
    family = platform_family()
    credential_backend = {
        "win32": "Windows DPAPI", "darwin": "macOS Keychain", "linux": "Secret Service",
    }.get(family, "unsupported credential backend")
    ollama = shutil.which("ollama")
    secret_tool = shutil.which("secret-tool")
    return (
        ("Operating system", family in {"win32", "darwin", "linux"}, family),
        ("Credential custody", family in {"win32", "darwin", "linux"}, credential_backend),
        ("Local AI command", ollama is not None, "Ollama command found" if ollama else "optional Ollama command not found"),
        ("Linux credential helper", family != "linux" or secret_tool is not None,
         "secret-tool available" if secret_tool else "install libsecret-tools to save credentials"),
    )


def self_test() -> tuple[bool, str]:
    try:
        from angerona.core.config import Config

        cfg = Config()
        for step in STEPS:
            for field in step.fields:
                if field.kind in CONFIG_KINDS:
                    assert hasattr(cfg, field.key), f"Config has {field.key}"
        appearance = next(step for step in STEPS if step.title.startswith("Appearance"))
        assert collect(appearance, {"theme": "slate", "accent": "#123456"}) == {
            "theme": "slate", "accent": "#123456"
        }
        valid = {field.key: getattr(cfg, field.key) for step in STEPS for field in step.fields
                 if field.kind in CONFIG_KINDS}
        assert not validate_setup(valid), validate_setup(valid)
        linux_only = Field("check", "ebpf_enabled", "eBPF", platforms=("linux",))
        assert field_supported(linux_only, "linux")
        assert not field_supported(linux_only, "win32")
        return True, f"{len(STEPS)} steps; complete Config mapping, platform gates and validation passed"
    except AssertionError as exc:
        return False, f"FAIL — {exc}"
    except Exception as exc:  # pragma: no cover
        return False, f"ERROR — {type(exc).__name__}: {exc}"


try:
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import (
        QCheckBox, QComboBox, QDialog, QDoubleSpinBox, QFormLayout, QHBoxLayout,
        QLabel, QLineEdit, QMessageBox, QPushButton, QScrollArea, QSpinBox,
        QStackedWidget, QVBoxLayout, QWidget,
    )
    _HAVE_QT = True
except Exception:  # pragma: no cover
    _HAVE_QT = False


if _HAVE_QT:

    class SetupWizard(QDialog):
        """Full product setup with review-before-apply semantics."""

        def __init__(self, config, apply_theme_fn=None, trust_running_fn=None, parent=None):
            super().__init__(parent)
            self._cfg = config
            self._apply_theme = apply_theme_fn
            self._trust_running = trust_running_fn
            self._widgets: list[dict[object, object]] = []
            self._review_label: QLabel | None = None
            self.launch_tour = False
            self._reset_modules = False
            self._reset_orb = False

            self.setWindowTitle("Angerona — Full Setup")
            self.setMinimumSize(660, 560)
            self.resize(760, 720)
            self.setModal(True)
            root = QVBoxLayout(self)
            self._stack = QStackedWidget()
            root.addWidget(self._stack, 1)
            for step in STEPS:
                self._stack.addWidget(self._build_page(step))

            self._progress = QLabel("")
            self._progress.setStyleSheet("color:#94a3b8; font-size:11px;")
            root.addWidget(self._progress)
            row = QHBoxLayout()
            self._back = QPushButton("← Back")
            self._skip = QPushButton("Skip")
            self._next = QPushButton("Next →")
            self._back.clicked.connect(lambda: self._go(-1))
            self._skip.clicked.connect(lambda: self._go(+1))
            self._next.clicked.connect(lambda: self._go(+1))
            row.addWidget(self._back)
            row.addStretch()
            row.addWidget(self._skip)
            row.addWidget(self._next)
            root.addLayout(row)
            self._sync()

        def _build_page(self, step: Step) -> QWidget:
            outer = QScrollArea()
            outer.setWidgetResizable(True)
            page = QWidget()
            layout = QVBoxLayout(page)
            title = QLabel(step.title)
            title.setStyleSheet("font-size:19px; font-weight:800;")
            layout.addWidget(title)
            intro = QLabel(step.intro)
            intro.setWordWrap(True)
            intro.setStyleSheet("color:#cbd5e1;")
            layout.addWidget(intro)
            form = QFormLayout()
            form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
            widget_map: dict[object, object] = {}
            for field in step.fields:
                widget = self._make_field(field)
                if widget is None:
                    continue
                supported = field_supported(field)
                widget.setEnabled(supported)
                if not supported:
                    widget.setToolTip("This option is unavailable on this operating system.")
                if field.kind in {"check", "action", "review"}:
                    form.addRow(widget)
                else:
                    form.addRow(field.label, widget)
                if field.kind == "password_env":
                    widget_map[("ENV", field.key)] = widget
                elif field.kind == "provider_secret":
                    widget_map[("PROVIDER", field.key)] = widget
                elif field.kind not in {"action", "info", "review", "profile"}:
                    widget_map[field.key] = widget
                if field.note:
                    note = QLabel(field.note)
                    note.setWordWrap(True)
                    note.setStyleSheet("color:#94a3b8; font-size:11px;")
                    form.addRow("", note)
            layout.addLayout(form)
            layout.addStretch()
            self._widgets.append(widget_map)
            outer.setWidget(page)
            return outer

        def _make_field(self, field: Field):
            if field.kind == "check":
                widget = QCheckBox(field.label)
                widget.setChecked(bool(getattr(self._cfg, field.key, False)))
                return widget
            if field.kind in {"combo", "profile"}:
                widget = QComboBox()
                widget.addItems([str(item) for item in field.options])
                current = str(getattr(self._cfg, field.key, "")) if field.kind == "combo" else str(field.options[0])
                found = widget.findText(current)
                if found >= 0:
                    widget.setCurrentIndex(found)
                if field.kind == "profile":
                    self._profile_combo = widget
                return widget
            if field.kind == "mic":
                widget = QComboBox()
                widget.addItem("Computer microphone (default)", "")
                try:
                    from angerona.connectors.voice import Voice
                    for index, name in Voice.list_input_devices():
                        widget.addItem(f"Microphone — {name}", str(index))
                except Exception:
                    pass
                current = str(getattr(self._cfg, field.key, "") or "")
                found = widget.findData(current)
                widget.setCurrentIndex(found if found >= 0 else 0)
                widget.setProperty("useData", True)
                return widget
            if field.kind == "spin":
                widget = QSpinBox()
                widget.setRange(int(field.minimum), int(field.maximum))
                widget.setValue(int(getattr(self._cfg, field.key, field.minimum)))
                return widget
            if field.kind == "double":
                widget = QDoubleSpinBox()
                widget.setDecimals(2)
                widget.setSingleStep(0.05)
                widget.setRange(float(field.minimum), float(field.maximum))
                widget.setValue(float(getattr(self._cfg, field.key, field.minimum)))
                return widget
            if field.kind in {"text", "secret_config", "password_env", "provider_secret"}:
                current = "" if field.kind in SECRET_KINDS or field.kind == "secret_config" else getattr(self._cfg, field.key, "")
                if field.key == "ai_provider_order" and isinstance(current, list):
                    current = ",".join(current)
                widget = QLineEdit(str(current))
                widget.setPlaceholderText(field.placeholder or "Leave blank to keep the protected value")
                if field.kind in SECRET_KINDS or field.kind == "secret_config":
                    widget.setEchoMode(QLineEdit.Password)
                return widget
            if field.kind == "info":
                value = QLabel(str(getattr(self._cfg, field.key, "")))
                value.setTextInteractionFlags(Qt.TextSelectableByMouse)
                value.setWordWrap(True)
                return value
            if field.kind == "review":
                self._review_label = QLabel("Review will appear on the final step.")
                self._review_label.setWordWrap(True)
                self._review_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
                return self._review_label
            if field.kind == "action":
                button = QPushButton(field.label)
                button.clicked.connect(lambda _checked=False, action=field.key: self._do_action(action))
                return button
            return None

        @staticmethod
        def _widget_value(widget):
            if isinstance(widget, QCheckBox):
                return widget.isChecked()
            if isinstance(widget, QComboBox):
                return str(widget.currentData() or "") if widget.property("useData") else widget.currentText()
            if isinstance(widget, (QSpinBox, QDoubleSpinBox)):
                return widget.value()
            if isinstance(widget, QLineEdit):
                return widget.text().strip()
            return None

        def _staged(self) -> tuple[dict[str, object], dict[str, str], dict[str, str]]:
            values: dict[str, object] = {}
            secrets: dict[str, str] = {}
            providers: dict[str, str] = {}
            for mapping in self._widgets:
                for key, widget in mapping.items():
                    value = self._widget_value(widget)
                    if isinstance(key, tuple) and key[0] == "ENV":
                        if value:
                            secrets[key[1]] = str(value)
                    elif isinstance(key, tuple) and key[0] == "PROVIDER":
                        if value:
                            providers[key[1]] = str(value)
                    elif key == "aria_push_url" and not value:
                        values[key] = getattr(self._cfg, key, "")
                    else:
                        values[str(key)] = value
            return normalize_setup_values(values), secrets, providers

        def _set_widget(self, key: str, value: object) -> None:
            for mapping in self._widgets:
                widget = mapping.get(key)
                if widget is None:
                    continue
                if isinstance(widget, QCheckBox):
                    widget.setChecked(bool(value))
                elif isinstance(widget, QComboBox):
                    found = widget.findText(str(value))
                    if found >= 0:
                        widget.setCurrentIndex(found)
                elif isinstance(widget, (QSpinBox, QDoubleSpinBox)):
                    widget.setValue(value)
                elif isinstance(widget, QLineEdit):
                    widget.setText(str(value))

        def _set_secret_widget(self, key: str, value: str) -> bool:
            for mapping in self._widgets:
                widget = mapping.get(("ENV", key))
                if isinstance(widget, QLineEdit):
                    widget.setText(value)
                    return True
            return False

        def _do_action(self, action: str) -> None:
            if action == "apply_profile":
                name = self._profile_combo.currentText()
                for key, value in SETUP_PROFILES.get(name, {}).items():
                    self._set_widget(key, value)
                self._progress.setText(f"Applied profile: {name}. Cloud and network connectors remain off.")
            elif action == "run_preflight":
                lines = [f"{'PASS' if ok else 'CHECK'} — {name}: {detail}" for name, ok, detail in local_preflight()]
                QMessageBox.information(self, "Local setup preflight", "\n".join(lines))
            elif action == "check_ollama":
                found = shutil.which("ollama")
                QMessageBox.information(self, "Ollama", "Ollama is installed and available." if found else "Ollama was not found. ARIA can use its deterministic local fallback until Ollama is installed.")
            elif action == "reset_orb":
                self._reset_orb = True
                self._progress.setText("Globe position will reset when setup is applied.")
            elif action == "reset_modules":
                self._reset_modules = True
                self._progress.setText("Supported module defaults will be restored on Finish.")
            elif action == "regenerate_jarvis_token":
                import secrets

                token = secrets.token_urlsafe(48)
                if self._set_secret_widget("ANGERONA_JARVIS_CONTROL_TOKEN", token):
                    self._progress.setText(
                        "A new JARVIS token is staged. Finish setup to protect it."
                    )
            elif action == "trust_running" and callable(self._trust_running):
                if QMessageBox.question(
                    self,
                    "Confirm trusted applications",
                    "Trust every currently running non-system application that has an "
                    "exact executable path? This can suppress future behavior and memory "
                    "alerts for those files. Review or remove entries later in Settings.",
                    QMessageBox.Yes | QMessageBox.No,
                    QMessageBox.No,
                ) != QMessageBox.Yes:
                    return
                try:
                    result = self._trust_running()
                    self._progress.setText(str(result or "Trusted applications updated."))
                except Exception as exc:
                    self._progress.setText(f"Trust review could not open: {type(exc).__name__}")

        def _summary(self) -> str:
            values, secrets, providers = self._staged()
            enabled_cloud = [key.replace("_", " ") for key in (
                "aria_cloud_fallback", "alert_analysis_cloud_fallback",
                "aria_voice_cloud_tts", "aria_research_egress", "aria_push_enabled",
                "aria_inbox_enabled", "teams_bot_enabled", "mobile_enabled",
            ) if values.get(key)]
            return (
                f"Platform: {platform_family()}\n"
                f"Profile: {self._profile_combo.currentText()}\n"
                f"Startup: {'enabled' if values.get('autostart_enabled') else 'disabled'}; "
                f"Chill Mode: {'on' if values.get('eco_mode') else 'off'}\n"
                f"Local AI: {values.get('ollama_model')} at {values.get('ollama_host')}\n"
                f"Optional outbound features: {', '.join(enabled_cloud) if enabled_cloud else 'none'}\n"
                f"Protected credentials being updated: {len(secrets) + len(providers)}\n"
                f"Module defaults: {'restore' if self._reset_modules else 'keep current overrides'}\n"
                f"Evidence directory: {self._cfg.data_dir}"
            )

        def _go(self, delta: int) -> None:
            current = self._stack.currentIndex()
            target = current + delta
            if target >= len(STEPS):
                self._finish()
                return
            if target < 0:
                return
            self._stack.setCurrentIndex(target)
            self._sync()

        def _sync(self) -> None:
            index = self._stack.currentIndex()
            if index == len(STEPS) - 1 and self._review_label is not None:
                self._review_label.setText(self._summary())
            self._progress.setText(f"Step {index + 1} of {len(STEPS)}")
            self._back.setEnabled(index > 0)
            self._next.setText("Finish and verify ✓" if index == len(STEPS) - 1 else "Next →")
            self._skip.setVisible(index not in (0, len(STEPS) - 1))

        def _finish(self) -> None:
            values, secret_updates, providers = self._staged()
            errors = validate_setup(values)
            protected_secrets: Mapping[str, str] = {}
            if values.get("jarvis_control_enabled"):
                try:
                    from angerona.core.secure_store import read_secret_map

                    protected_secrets = read_secret_map(
                        self._cfg.data_dir,
                        strict=True,
                    )
                except Exception as exc:
                    QMessageBox.warning(
                        self,
                        "Protected credentials unavailable",
                        "Angerona could not verify the operating-system credential "
                        "store, so JARVIS controls remain unchanged.\n\n"
                        f"{type(exc).__name__}",
                    )
                    return
            errors.extend(
                validate_secret_requirements(
                    values,
                    secret_updates,
                    protected_secrets=protected_secrets,
                )
            )
            if errors:
                QMessageBox.warning(self, "Setup needs attention", "\n\n".join(errors))
                return
            outbound = any(bool(values.get(key)) for key in (
                "aria_cloud_fallback", "alert_analysis_cloud_fallback",
                "aria_voice_cloud_tts", "aria_research_egress", "aria_push_enabled",
                "aria_inbox_enabled", "teams_bot_enabled", "mobile_enabled",
            ))
            if outbound and QMessageBox.question(
                self, "Confirm optional network features",
                "One or more optional network/cloud features are enabled. Angerona will "
                "only send the data described by those controls. Continue?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
            ) != QMessageBox.Yes:
                return

            snapshot = {key: getattr(self._cfg, key) for key in values if hasattr(self._cfg, key)}
            snapshot_module_states = dict(self._cfg.module_states)
            snapshot_orb = (
                self._cfg.holographic_orb_x,
                self._cfg.holographic_orb_y,
            )
            snapshot_autostart = bool(self._cfg.autostart_enabled)
            warnings: list[str] = []
            try:
                for key, value in values.items():
                    if hasattr(self._cfg, key):
                        setattr(self._cfg, key, value)
                if self._reset_modules:
                    self._cfg.module_states = {}
                if self._reset_orb:
                    self._cfg.holographic_orb_x = -1
                    self._cfg.holographic_orb_y = -1
                if self._cfg.fleet_service_enabled and not os.environ.get("ANGERONA_FLEET_SERVICE_KEY"):
                    import secrets
                    secret_updates["ANGERONA_FLEET_SERVICE_KEY"] = secrets.token_urlsafe(48)

                from angerona.core.autostart import disable_autostart, enable_autostart, is_enabled
                wanted = bool(self._cfg.autostart_enabled)
                changed = enable_autostart() if wanted else disable_autostart()
                actual = bool(is_enabled())
                if not changed or actual != wanted:
                    self._cfg.autostart_enabled = actual
                    warnings.append("Startup registration could not be changed; the saved setting matches the detected state.")

                self._cfg.save()
                if secret_updates:
                    from angerona.core.config import write_env_keys
                    write_env_keys(secret_updates)
                if providers:
                    from angerona.core.provider_credentials import save_provider_credentials
                    save_provider_credentials(providers)
                if self._cfg.require_signed_aar:
                    os.environ["ANGERONA_REQUIRE_SIGNED_AAR"] = "1"
                else:
                    os.environ.pop("ANGERONA_REQUIRE_SIGNED_AAR", None)
                if self._cfg.entropy_pool_enabled:
                    os.environ["ANGERONA_ENTROPY_POOL"] = "1"
                else:
                    os.environ.pop("ANGERONA_ENTROPY_POOL", None)
                os.environ["ANGERONA_AI_ORDER"] = ",".join(self._cfg.ai_provider_order)
            except Exception as exc:
                for key, value in snapshot.items():
                    setattr(self._cfg, key, value)
                self._cfg.module_states = snapshot_module_states
                (
                    self._cfg.holographic_orb_x,
                    self._cfg.holographic_orb_y,
                ) = snapshot_orb
                try:
                    from angerona.core.autostart import disable_autostart, enable_autostart
                    enable_autostart() if snapshot_autostart else disable_autostart()
                except Exception:
                    pass
                try:
                    self._cfg.save()
                except Exception:
                    pass
                QMessageBox.warning(self, "Setup was not applied", f"The protected setup transaction failed closed.\n\n{type(exc).__name__}: {exc}")
                return

            try:
                if self._apply_theme:
                    self._apply_theme(self._cfg.theme)
            except Exception:
                warnings.append("The new theme will appear after restart.")
            message = "Full setup completed. Restart Angerona to activate services that are currently stopped."
            if warnings:
                message += "\n\n" + "\n".join(warnings)
            QMessageBox.information(self, "Angerona setup complete", message)
            self.accept()


if __name__ == "__main__":
    ok, detail = self_test()
    print(f"[setup_wizard] self_test: {'PASS' if ok else 'FAIL'} — {detail}")
    raise SystemExit(0 if ok else 1)
