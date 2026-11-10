# Configuration reference

This index enumerates the stored Config schema and its code defaults. It never opens a user's settings or secret store. Defaults are not current saved values; platform validation and separate policy gates may change effective behavior.

Use Settings or Full Setup for supported edits. Credentials belong in their protected stores. Editing a sandbox copy does not activate it or bypass privileged consent.

Declared fields: **164**.

| Setting | Type | Code default | Source note |
| --- | --- | --- | --- |
| [`data_dir`](../../src/angerona/core/config.py#L259) | `Path` | `field(default_factory=_data_dir)` |  |
| [`ollama_host`](../../src/angerona/core/config.py#L260) | `str` | `'http://localhost:11434'` |  |
| [`ollama_model`](../../src/angerona/core/config.py#L261) | `str` | `'llama3'` |  |
| [`github_repo`](../../src/angerona/core/config.py#L262) | `str` | `'Ag3nt47/AngeronaSuite'` | canonical update source |
| [`github_daily_check_enabled`](../../src/angerona/core/config.py#L263) | `bool` | `False` | opt-in public GitHub metadata; never auto-installs |
| [`startup_recovery_enabled`](../../src/angerona/core/config.py#L264) | `bool` | `True` | user-authorized verified source recovery after failed startup |
| [`startup_recovery_github_enabled`](../../src/angerona/core/config.py#L265) | `bool` | `True` | public canonical source downloads; never host uploads |
| [`github_tools_enabled`](../../src/angerona/core/config.py#L266) | `bool` | `True` |  |
| [`github_tools_auto_prepare`](../../src/angerona/core/config.py#L267) | `bool` | `True` |  |
| [`github_tools_allow_download`](../../src/angerona/core/config.py#L268) | `bool` | `True` |  |
| [`community_rules_enabled`](../../src/angerona/core/config.py#L269) | `bool` | `False` | separately reviewed/activated data rules only |
| [`community_playbooks_enabled`](../../src/angerona/core/config.py#L270) | `bool` | `False` | existing policy-gated runner only |
| [`github_tools_job_limit_mib`](../../src/angerona/core/config.py#L271) | `int` | `256` |  |
| [`github_tools_report_limit_mib`](../../src/angerona/core/config.py#L272) | `int` | `64` |  |
| [`github_tools_report_count`](../../src/angerona/core/config.py#L273) | `int \| str` | `SCANNER_REPORT_COUNT_UNLIMITED` |  |
| [`github_tools_timeout_seconds`](../../src/angerona/core/config.py#L274) | `int` | `300` |  |
| [`spyware_scan_timeout_seconds`](../../src/angerona/core/config.py#L275) | `int` | `3600` |  |
| [`theme`](../../src/angerona/core/config.py#L276) | `str` | `'cyber'` | gui theme key (see gui/theme.py) |
| [`accent`](../../src/angerona/core/config.py#L277) | `str` | `''` | optional custom accent hex tint |
| [`module_states`](../../src/angerona/core/config.py#L278) | `Dict[str, bool]` | `field(default_factory=dict)` |  |
| [`selftest_timeout_seconds`](../../src/angerona/core/config.py#L279) | `int` | `30` |  |
| [`selftest_auto_recover_modules`](../../src/angerona/core/config.py#L280) | `list[str]` | `field(default_factory=list)` |  |
| [`autostart_enabled`](../../src/angerona/core/config.py#L281) | `bool` | `True` | platform-native per-user logon startup |
| [`eco_mode`](../../src/angerona/core/config.py#L282) | `bool` | `True` | start in network-first Chill Mode for all-day low-impact protection |
| [`blackbox_enabled`](../../src/angerona/core/config.py#L283) | `bool` | `True` | auto-launch the decoupled Black Box diagnostic recorder at startup |
| [`live_debug_enabled`](../../src/angerona/core/config.py#L284) | `bool` | `False` | opt-in same-user, outbound-only diagnostic pipe |
| [`identity_session_collection_enabled`](../../src/angerona/core/config.py#L285) | `bool` | `False` | read-only Windows Security channel |
| [`browser_extension_inventory_enabled`](../../src/angerona/core/config.py#L286) | `bool` | `False` | manifest metadata only; no browser contents |
| [`alert_retention_enabled`](../../src/angerona/core/config.py#L287) | `bool` | `True` | disposable runtime-alert archives only |
| [`alert_retention_days`](../../src/angerona/core/config.py#L288) | `int` | `30` |  |
| [`alert_retention_max_mib`](../../src/angerona/core/config.py#L289) | `int` | `256` |  |
| [`normal_log_max_mib`](../../src/angerona/core/config.py#L290) | `int` | `8` | per crash-log target and per-process append allowance |
| [`normal_log_message_kib`](../../src/angerona/core/config.py#L291) | `int` | `64` | complete Python/Qt message, including header |
| [`normal_log_paused`](../../src/angerona/core/config.py#L292) | `bool` | `False` | preserves logs; native fault output remains separate |
| [`telemetry_storage_blocked`](../../src/angerona/core/config.py#L293) | `bool` | `False` | telemetry only; remediation shares the database |
| [`telemetry_db_target_mib`](../../src/angerona/core/config.py#L294) | `int` | `256` |  |
| [`telemetry_wal_target_mib`](../../src/angerona/core/config.py#L295) | `int` | `64` |  |
| [`telemetry_min_free_mib`](../../src/angerona/core/config.py#L296) | `int` | `2048` |  |
| [`shadow_cache_enabled`](../../src/angerona/core/config.py#L297) | `bool` | `True` | bounded ransomware recovery copies |
| [`shadow_cache_max_mib`](../../src/angerona/core/config.py#L298) | `int` | `2048` |  |
| [`shadow_min_free_mib`](../../src/angerona/core/config.py#L299) | `int` | `2048` |  |
| [`shadow_vss_enabled`](../../src/angerona/core/config.py#L300) | `bool` | `False` | Windows shadow storage needs explicit opt-in |
| [`deception_user_folders`](../../src/angerona/core/config.py#L303) | `bool` | `False` |  |
| [`mobile_enabled`](../../src/angerona/core/config.py#L305) | `bool` | `False` |  |
| [`mobile_signal_cli`](../../src/angerona/core/config.py#L306) | `str` | `''` | path to the signal-cli binary |
| [`mobile_signal_cli_sha256`](../../src/angerona/core/config.py#L307) | `str` | `''` | exact executable digest pin |
| [`mobile_signal_cli_publisher`](../../src/angerona/core/config.py#L308) | `str` | `''` | exact Authenticode subject pin |
| [`mobile_host_number`](../../src/angerona/core/config.py#L309) | `str` | `''` | this machine's registered Signal number |
| [`mobile_dest_number`](../../src/angerona/core/config.py#L310) | `str` | `''` | operator's destination phone number |
| [`ebpf_enabled`](../../src/angerona/core/config.py#L312) | `bool` | `False` |  |
| [`ai_provider_order`](../../src/angerona/core/config.py#L314) | `list` | `field(default_factory=lambda: ['anthropic', 'gemini', 'groq', 'openai', 'openrouter', 'ollama'])` |  |
| [`mcp_enabled`](../../src/angerona/core/config.py#L318) | `bool` | `False` | start engines/mcp_server.py at boot |
| [`mcp_port`](../../src/angerona/core/config.py#L319) | `int` | `47923` | loopback port for the MCP SSE endpoint |
| [`jarvis_control_enabled`](../../src/angerona/core/config.py#L322) | `bool` | `False` |  |
| [`jarvis_control_port`](../../src/angerona/core/config.py#L323) | `int` | `47925` |  |
| [`fleet_service_enabled`](../../src/angerona/core/config.py#L326) | `bool` | `False` |  |
| [`fleet_service_port`](../../src/angerona/core/config.py#L327) | `int` | `47930` |  |
| [`fleet_tenant_id`](../../src/angerona/core/config.py#L328) | `str` | `'local'` |  |
| [`siem_host`](../../src/angerona/core/config.py#L331) | `str` | `''` |  |
| [`siem_port`](../../src/angerona/core/config.py#L332) | `int` | `6514` |  |
| [`siem_protocol`](../../src/angerona/core/config.py#L333) | `str` | `'tls'` | tls \| tcp \| udp |
| [`siem_min_severity`](../../src/angerona/core/config.py#L334) | `str` | `'MEDIUM'` |  |
| [`siem_allow_plaintext`](../../src/angerona/core/config.py#L335) | `bool` | `False` |  |
| [`siem_ca_file`](../../src/angerona/core/config.py#L336) | `str` | `''` |  |
| [`siem_include_raw`](../../src/angerona/core/config.py#L337) | `bool` | `False` |  |
| [`remote_bridge_mode`](../../src/angerona/core/config.py#L338) | `str` | `''` | "" \| SENDER \| RECEIVER |
| [`remote_bridge_peer`](../../src/angerona/core/config.py#L339) | `str` | `''` |  |
| [`remote_bridge_bind`](../../src/angerona/core/config.py#L340) | `str` | `'127.0.0.1'` |  |
| [`remote_bridge_port`](../../src/angerona/core/config.py#L341) | `int` | `47924` |  |
| [`remote_bridge_node_id`](../../src/angerona/core/config.py#L342) | `str` | `''` |  |
| [`remote_bridge_allow_nonloopback`](../../src/angerona/core/config.py#L343) | `bool` | `False` |  |
| [`ioc_feed_url`](../../src/angerona/core/config.py#L344) | `str` | `''` |  |
| [`ioc_feed_sha256`](../../src/angerona/core/config.py#L345) | `str` | `''` |  |
| [`aria_enabled`](../../src/angerona/core/config.py#L348) | `bool` | `False` | master opt-in: HUD + local assistant |
| [`perf_governor_enabled`](../../src/angerona/core/config.py#L349) | `bool` | `False` | ARIA Overdrive adaptive UI-path governor |
| [`aria_persona`](../../src/angerona/core/config.py#L350) | `str` | `'aria'` | aria \| friday \| ultron (presentation only) |
| [`aria_voice_enabled`](../../src/angerona/core/config.py#L351) | `bool` | `False` | spoken threat narration (local TTS) |
| [`aria_conversation_awareness`](../../src/angerona/core/config.py#L352) | `bool` | `False` | transient rolling room/follow-up context |
| [`aria_always_listen`](../../src/angerona/core/config.py#L353) | `bool` | `False` | accept speech without a wake word |
| [`aria_follow_up_seconds`](../../src/angerona/core/config.py#L354) | `int` | `12` | no-wake follow-up window after a reply |
| [`aria_hand_controls`](../../src/angerona/core/config.py#L355) | `bool` | `False` | local camera gesture navigation |
| [`aria_camera_index`](../../src/angerona/core/config.py#L356) | `int` | `0` | explicit camera used by hand controls |
| [`aria_voice_cloud_tts`](../../src/angerona/core/config.py#L357) | `bool` | `False` | allow ElevenLabs cloud TTS (opt-in egress) |
| [`aria_cloud_fallback`](../../src/angerona/core/config.py#L358) | `bool` | `False` | send a sanitized question to a configured cloud AI if local AI is offline |
| [`alert_analysis_cloud_fallback`](../../src/angerona/core/config.py#L359) | `bool` | `False` | send privacy-sanitized alert evidence only after a separate explicit opt-in |
| [`aria_mic_device`](../../src/angerona/core/config.py#L363) | `str` | `''` |  |
| [`aria_push_enabled`](../../src/angerona/core/config.py#L364) | `bool` | `False` | auto-brief a channel on criticals |
| [`aria_push_kind`](../../src/angerona/core/config.py#L365) | `str` | `'slack'` | slack \| teams \| ntfy \| webhook |
| [`aria_push_url`](../../src/angerona/core/config.py#L366) | `str` | `''` | channel webhook URL (blank = disabled) |
| [`aria_inbox_enabled`](../../src/angerona/core/config.py#L367) | `bool` | `False` | inbox phishing triage (background IMAP poller) |
| [`aria_imap_host`](../../src/angerona/core/config.py#L368) | `str` | `''` | IMAP server, e.g. imap.gmail.com |
| [`aria_imap_user`](../../src/angerona/core/config.py#L369) | `str` | `''` | mailbox address; password stays in the OS credential store |
| [`aria_inbox_interval_min`](../../src/angerona/core/config.py#L370) | `int` | `5` | how often to scan the mailbox (minutes) |
| [`aria_research_egress`](../../src/angerona/core/config.py#L371) | `bool` | `False` | allow headless research fetches (else browser-surface) |
| [`teams_bot_enabled`](../../src/angerona/core/config.py#L373) | `bool` | `False` |  |
| [`teams_app_id`](../../src/angerona/core/config.py#L374) | `str` | `''` | Azure Bot App ID; secret stays in the OS credential store |
| [`teams_allowed_users`](../../src/angerona/core/config.py#L375) | `str` | `''` | comma/semicolon-separated immutable Teams user IDs |
| [`teams_bot_port`](../../src/angerona/core/config.py#L376) | `int` | `3978` | local Bot Framework messaging-endpoint port |
| [`teams_bot_skip_auth`](../../src/angerona/core/config.py#L377) | `bool` | `False` | runtime-only dev switch; never persisted |
| [`ollama_keep_alive`](../../src/angerona/core/config.py#L379) | `str` | `'30m'` | Full mode lease; Chill overrides this to immediate release |
| [`ui_scale_mode`](../../src/angerona/core/config.py#L386) | `str` | `'auto'` | "auto" \| "fixed" |
| [`ui_scale_fixed`](../../src/angerona/core/config.py#L387) | `float` | `1.0` | honored only when mode == "fixed" |
| [`ui_motion_enabled`](../../src/angerona/core/config.py#L388) | `bool` | `True` | polished panel reveals; OS reduced-motion still wins |
| [`adaptive_scan_pacing_enabled`](../../src/angerona/core/config.py#L389) | `bool` | `True` | pace routine scans when dashboard/host is busy |
| [`dashboard_display`](../../src/angerona/core/config.py#L390) | `str` | `'standard'` | "standard" \| "orbital" (optional visual overview) |
| [`dashboard_mode`](../../src/angerona/core/config.py#L391) | `str` | `'classic'` | "classic" \| "flow" (Local SOC workspace) |
| [`holographic_orb_enabled`](../../src/angerona/core/config.py#L392) | `bool` | `True` | minimized-window token + radial service controls |
| [`holographic_orb_x`](../../src/angerona/core/config.py#L395) | `int` | `-1` |  |
| [`holographic_orb_y`](../../src/angerona/core/config.py#L396) | `int` | `-1` |  |
| [`process_baseline_enabled`](../../src/angerona/core/config.py#L399) | `bool` | `False` |  |
| [`spyware_auto_contain`](../../src/angerona/core/config.py#L402) | `bool` | `True` |  |
| [`spyware_scan_native_enabled`](../../src/angerona/core/config.py#L403) | `bool` | `True` |  |
| [`spyware_scan_zero_breach_enabled`](../../src/angerona/core/config.py#L404) | `bool` | `True` |  |
| [`spyware_scan_auto_enabled`](../../src/angerona/core/config.py#L405) | `bool` | `True` |  |
| [`spyware_scan_auto_scope`](../../src/angerona/core/config.py#L406) | `str` | `'full'` |  |
| [`spyware_scan_priority`](../../src/angerona/core/config.py#L407) | `str` | `'above-normal'` |  |
| [`spyware_scan_cpu_percent`](../../src/angerona/core/config.py#L408) | `int` | `70` |  |
| [`spyware_scan_memory_mib`](../../src/angerona/core/config.py#L409) | `int` | `512` |  |
| [`spyware_scan_background_percent`](../../src/angerona/core/config.py#L410) | `int` | `10` |  |
| [`spyware_scan_verify_admin`](../../src/angerona/core/config.py#L411) | `bool` | `True` |  |
| [`breach_auto_isolate_enabled`](../../src/angerona/core/config.py#L412) | `bool` | `True` |  |
| [`breach_lifted_cases`](../../src/angerona/core/config.py#L413) | `list[str]` | `field(default_factory=list)` |  |
| [`spyware_network_enabled`](../../src/angerona/core/config.py#L414) | `bool` | `False` |  |
| [`spyware_memory_enabled`](../../src/angerona/core/config.py#L415) | `bool` | `False` |  |
| [`spyware_beacon_enabled`](../../src/angerona/core/config.py#L416) | `bool` | `False` |  |
| [`spyware_beacon_channel`](../../src/angerona/core/config.py#L417) | `bool` | `True` |  |
| [`spyware_beacon_signal`](../../src/angerona/core/config.py#L418) | `bool` | `False` |  |
| [`spyware_research_urls`](../../src/angerona/core/config.py#L419) | `list[str]` | `field(default_factory=list)` |  |
| [`ugcap_enabled`](../../src/angerona/core/config.py#L420) | `bool` | `False` |  |
| [`ugcap_cadence_hours`](../../src/angerona/core/config.py#L421) | `int` | `168` |  |
| [`ugcap_vault_path`](../../src/angerona/core/config.py#L422) | `str` | `''` |  |
| [`ugcap_key_name`](../../src/angerona/core/config.py#L423) | `str` | `'Angerona.UGCAP.v1'` |  |
| [`ugcap_lockdown`](../../src/angerona/core/config.py#L424) | `bool` | `True` |  |
| [`ugcap_witness_enabled`](../../src/angerona/core/config.py#L425) | `bool` | `False` |  |
| [`ugcap_witness_endpoint`](../../src/angerona/core/config.py#L426) | `str` | `''` |  |
| [`ugcap_witness_certificate_sha256`](../../src/angerona/core/config.py#L427) | `str` | `''` |  |
| [`ugcap_witness_authority_public_key`](../../src/angerona/core/config.py#L428) | `str` | `''` |  |
| [`ugcap_witness_installation_id`](../../src/angerona/core/config.py#L429) | `str` | `''` |  |
| [`ugcap_witness_client_id`](../../src/angerona/core/config.py#L430) | `str` | `''` |  |
| [`ugcap_witness_client_certificate_path`](../../src/angerona/core/config.py#L431) | `str` | `''` |  |
| [`ugcap_witness_client_key_path`](../../src/angerona/core/config.py#L432) | `str` | `''` |  |
| [`ugcap_witness_ca_bundle_path`](../../src/angerona/core/config.py#L433) | `str` | `''` |  |
| [`recorder_witness_enabled`](../../src/angerona/core/config.py#L436) | `bool` | `False` |  |
| [`recorder_witness_independent_host`](../../src/angerona/core/config.py#L437) | `bool` | `False` |  |
| [`recorder_witness_endpoint`](../../src/angerona/core/config.py#L438) | `str` | `''` |  |
| [`recorder_witness_certificate_sha256`](../../src/angerona/core/config.py#L439) | `str` | `''` |  |
| [`recorder_witness_authority_public_key`](../../src/angerona/core/config.py#L440) | `str` | `''` |  |
| [`recorder_witness_installation_id`](../../src/angerona/core/config.py#L441) | `str` | `''` |  |
| [`recorder_witness_client_id`](../../src/angerona/core/config.py#L442) | `str` | `''` |  |
| [`recorder_witness_client_certificate_path`](../../src/angerona/core/config.py#L443) | `str` | `''` |  |
| [`recorder_witness_client_key_path`](../../src/angerona/core/config.py#L444) | `str` | `''` |  |
| [`recorder_witness_ca_bundle_path`](../../src/angerona/core/config.py#L445) | `str` | `''` |  |
| [`recorder_witness_archive_mib`](../../src/angerona/core/config.py#L446) | `int` | `16` |  |
| [`adversary_combat_enabled`](../../src/angerona/core/config.py#L452) | `bool` | `True` |  |
| [`adversary_combat_mode`](../../src/angerona/core/config.py#L453) | `str` | `'maximum'` | contain \| aggressive \| maximum |
| [`adversary_combat_min_severity`](../../src/angerona/core/config.py#L454) | `str` | `'LOW'` | LOW \| MEDIUM \| HIGH \| CRITICAL |
| [`adversary_combat_block_network`](../../src/angerona/core/config.py#L455) | `bool` | `True` |  |
| [`adversary_combat_quarantine_files`](../../src/angerona/core/config.py#L456) | `bool` | `True` |  |
| [`adversary_combat_process_action`](../../src/angerona/core/config.py#L457) | `str` | `'terminate'` | suspend \| terminate |
| [`adversary_combat_isolate_host`](../../src/angerona/core/config.py#L458) | `bool` | `True` |  |
| [`adversary_combat_activate_honeypots`](../../src/angerona/core/config.py#L459) | `bool` | `True` |  |
| [`adversary_combat_isolation_threshold`](../../src/angerona/core/config.py#L460) | `int` | `3` |  |
| [`require_signed_aar`](../../src/angerona/core/config.py#L467) | `bool` | `True` |  |
| [`entropy_pool_enabled`](../../src/angerona/core/config.py#L471) | `bool` | `False` |  |
