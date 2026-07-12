"""Legacy Angerona engines, brought across verbatim from the original project.

These are the original capability implementations (memory/forensics scanning,
packet sniffer, cloud escalation, flight-recorder, etc.). They are kept here as
the source of truth while each is wrapped into a clean ``BaseModule`` under
``angerona.modules``. They are NOT auto-loaded (the ModuleManager only scans
``angerona.modules`` and the user drop-in folder), so importing this package has
no side effects.

Port status (wrapped as first-class modules):
    ✔ file integrity        -> modules/file_integrity.py
    ✔ process lineage       -> modules/process_monitor.py
    ✔ network monitor       -> modules/network_monitor.py
    ✔ YARA scanning         -> modules/yara_scanner.py
    ✔ AI triage (Ollama)    -> modules/ai_triage.py
    ✔ active deception      -> modules/deception.py
    ✔ memory/forensics      -> modules/forensics.py
    ✔ packet sniffer        -> modules/packet_sniffer.py
    ✔ cloud escalation      -> modules/cloud_escalation.py

Infrastructure (now provided by the core, NOT wrapped as modules):
    persistence.py, edr_logger.py     -> superseded by core/storage.py
    unified_edr.py, unified_defense_engine.py, core_engine.py
                                       -> superseded by core + EventBus orchestration
    rag.py, ai_telemetry.py, reporter.py -> support libs, kept for reference

Deliberately NOT ported:
    self_compiler.py  -> self-modifying / runtime-recompilation code. This is an
                         anti-pattern in a security product (tamper surface,
                         looks like persistence/obfuscation) and is intentionally
                         left out of the new app.
    watchdog.py       -> the old respawn-the-monolith watchdog is obsolete; the
                         ModuleManager already supervises modules and marks any
                         that crash as 'error'.
"""
