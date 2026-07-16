"""Configuration + canonical filesystem paths.

All runtime state lives under a per-user data directory so the app folder
itself stays clean and read-only-friendly (important for a Program Files or
release install). Secrets come only from a git-ignored .env.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict


def _data_dir() -> Path:
    from angerona.core.data_paths import data_dir
    p = data_dir()
    (p / "logs").mkdir(parents=True, exist_ok=True)
    return p


def write_env_keys(updates: dict) -> Path:
    """Upsert KEY=VALUE pairs into ./.env (persisted) and os.environ (live now,
    so modules re-reading env pick them up without a restart). Blank values skip."""
    path = Path.cwd() / ".env"
    lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    for key, val in updates.items():
        if not val:
            continue
        os.environ[key] = val
        newline = f"{key}={val}"
        replaced = False
        for i, ln in enumerate(lines):
            if "=" in ln and not ln.strip().startswith("#") and ln.split("=", 1)[0].strip() == key:
                lines[i] = newline
                replaced = True
                break
        if not replaced:
            lines.append(newline)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


@dataclass
class Config:
    data_dir: Path = field(default_factory=_data_dir)
    ollama_host: str = "http://localhost:11434"
    ollama_model: str = "llama3"
    github_repo: str = "your-user/Angerona"   # set to your repo for auto-update
    theme: str = "cyber"                       # gui theme key (see gui/theme.py)
    accent: str = ""                           # optional custom accent hex tint
    module_states: Dict[str, bool] = field(default_factory=dict)
    autostart_enabled: bool = True              # launch at Windows logon (core/autostart.py)
    eco_mode: bool = True                        # start in Eco Mode (heavy scanners paused) for a fast, responsive launch
    blackbox_enabled: bool = True                # auto-launch the decoupled Black Box diagnostic recorder at startup
    # ── Mobile Response Bridge (Signal / signal-cli) — opt-in, default off ──
    mobile_enabled: bool = False
    mobile_signal_cli: str = ""                   # path to the signal-cli binary
    mobile_host_number: str = ""                  # this machine's registered Signal number
    mobile_dest_number: str = ""                  # operator's destination phone number
    # ── Linux eBPF sensor node (headless Linux only) — opt-in, default off ──
    ebpf_enabled: bool = False
    # ── Online AI consult priority order (first with a key wins) ──
    ai_provider_order: list = field(default_factory=lambda: ["anthropic", "gemini", "openai", "openrouter", "ollama"])
    # ── MCP server (local loopback — opt-in, default off) ──────────────────
    mcp_enabled: bool = False                   # start engines/mcp_server.py at boot
    mcp_port:    int  = 47923                   # loopback port for the MCP SSE endpoint

    # ── ARIA assistant layer (v1.8.0) — local, gated, defensive-only ───────
    aria_enabled: bool = True                   # show the ARIA HUD tab + local assistant
    perf_governor_enabled: bool = False         # ARIA Overdrive adaptive UI-path governor
    aria_voice_enabled: bool = False            # spoken threat narration (local TTS)
    aria_voice_cloud_tts: bool = False          # allow ElevenLabs cloud TTS (opt-in egress)
    aria_push_enabled: bool = False             # auto-brief a channel on criticals
    aria_push_kind: str = "slack"               # slack | teams | ntfy | webhook
    aria_push_url: str = ""                      # channel webhook URL (blank = disabled)
    aria_inbox_enabled: bool = False            # inbox phishing triage (background IMAP poller)
    aria_imap_host: str = ""                     # IMAP server, e.g. imap.gmail.com
    aria_imap_user: str = ""                     # mailbox address (password lives in .env: ARIA_IMAP_PASS)
    aria_inbox_interval_min: int = 5             # how often to scan the mailbox (minutes)
    aria_research_egress: bool = False          # allow headless research fetches (else browser-surface)
    # ── Microsoft Teams bot (two-way ARIA over Teams) — opt-in, default off ──
    teams_bot_enabled: bool = False
    teams_app_id: str = ""                       # Azure Bot App (client) ID; secret in .env
    teams_allowed_users: str = ""                # comma/semicolon-separated Teams user id(s)/name(s)
    teams_bot_port: int = 3978                   # local Bot Framework messaging-endpoint port
    teams_bot_skip_auth: bool = False            # DEV ONLY: skip inbound JWT verification
    # ── ARIA model tuning ──
    ollama_keep_alive: str = "30m"               # keep the local model warm for fast replies

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
                cfg.autostart_enabled = data.get("autostart_enabled", cfg.autostart_enabled)
                cfg.eco_mode = data.get("eco_mode", cfg.eco_mode)
                cfg.blackbox_enabled = data.get("blackbox_enabled", cfg.blackbox_enabled)
                cfg.mobile_enabled = data.get("mobile_enabled", cfg.mobile_enabled)
                cfg.mobile_signal_cli = data.get("mobile_signal_cli", cfg.mobile_signal_cli)
                cfg.mobile_host_number = data.get("mobile_host_number", cfg.mobile_host_number)
                cfg.mobile_dest_number = data.get("mobile_dest_number", cfg.mobile_dest_number)
                cfg.ebpf_enabled = data.get("ebpf_enabled", cfg.ebpf_enabled)
                cfg.ai_provider_order = data.get("ai_provider_order", cfg.ai_provider_order)
                cfg.mcp_enabled = data.get("mcp_enabled", cfg.mcp_enabled)
                cfg.mcp_port    = int(data.get("mcp_port", cfg.mcp_port))
                cfg.aria_enabled          = data.get("aria_enabled", cfg.aria_enabled)
                cfg.perf_governor_enabled = data.get("perf_governor_enabled", cfg.perf_governor_enabled)
                cfg.aria_voice_enabled    = data.get("aria_voice_enabled", cfg.aria_voice_enabled)
                cfg.aria_voice_cloud_tts  = data.get("aria_voice_cloud_tts", cfg.aria_voice_cloud_tts)
                cfg.aria_push_enabled     = data.get("aria_push_enabled", cfg.aria_push_enabled)
                cfg.aria_push_kind        = data.get("aria_push_kind", cfg.aria_push_kind)
                cfg.aria_push_url         = data.get("aria_push_url", cfg.aria_push_url)
                cfg.aria_inbox_enabled    = data.get("aria_inbox_enabled", cfg.aria_inbox_enabled)
                cfg.aria_imap_host        = data.get("aria_imap_host", cfg.aria_imap_host)
                cfg.aria_imap_user        = data.get("aria_imap_user", cfg.aria_imap_user)
                cfg.aria_inbox_interval_min = int(data.get("aria_inbox_interval_min", cfg.aria_inbox_interval_min))
                cfg.aria_research_egress  = data.get("aria_research_egress", cfg.aria_research_egress)
                cfg.teams_bot_enabled     = data.get("teams_bot_enabled", cfg.teams_bot_enabled)
                cfg.teams_app_id          = data.get("teams_app_id", cfg.teams_app_id)
                cfg.teams_allowed_users   = data.get("teams_allowed_users", cfg.teams_allowed_users)
                cfg.teams_bot_port        = int(data.get("teams_bot_port", cfg.teams_bot_port))
                cfg.teams_bot_skip_auth   = data.get("teams_bot_skip_auth", cfg.teams_bot_skip_auth)
                cfg.ollama_keep_alive     = data.get("ollama_keep_alive", cfg.ollama_keep_alive)
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
        return cfg

    def save(self) -> None:
        self.settings_path.write_text(
            json.dumps(
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
                    "mobile_enabled":     self.mobile_enabled,
                    "mobile_signal_cli":  self.mobile_signal_cli,
                    "mobile_host_number": self.mobile_host_number,
                    "mobile_dest_number": self.mobile_dest_number,
                    "ebpf_enabled":       self.ebpf_enabled,
                    "ai_provider_order":  self.ai_provider_order,
                    "mcp_enabled":       self.mcp_enabled,
                    "mcp_port":          self.mcp_port,
                    "aria_enabled":          self.aria_enabled,
                    "perf_governor_enabled": self.perf_governor_enabled,
                    "aria_voice_enabled":    self.aria_voice_enabled,
                    "aria_voice_cloud_tts":  self.aria_voice_cloud_tts,
                    "aria_push_enabled":     self.aria_push_enabled,
                    "aria_push_kind":        self.aria_push_kind,
                    "aria_push_url":         self.aria_push_url,
                    "aria_inbox_enabled":    self.aria_inbox_enabled,
                    "aria_imap_host":        self.aria_imap_host,
                    "aria_imap_user":        self.aria_imap_user,
                    "aria_inbox_interval_min": self.aria_inbox_interval_min,
                    "aria_research_egress":  self.aria_research_egress,
                    "teams_bot_enabled":     self.teams_bot_enabled,
                    "teams_app_id":          self.teams_app_id,
                    "teams_allowed_users":   self.teams_allowed_users,
                    "teams_bot_port":        self.teams_bot_port,
                    "teams_bot_skip_auth":   self.teams_bot_skip_auth,
                    "ollama_keep_alive":     self.ollama_keep_alive,
                },
                indent=2,
            ),
            encoding="utf-8",
        )

    @staticmethod
    def _load_dotenv(cfg: "Config") -> None:
        """Load a local .env next to the app, if present (keys never committed)."""
        for candidate in (Path.cwd() / ".env", cfg.data_dir / ".env"):
            if candidate.exists():
                for line in candidate.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, v = line.split("=", 1)
                    os.environ.setdefault(k.strip(), v.strip())
