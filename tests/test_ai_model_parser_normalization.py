"""Real-byte regressions for the model parser's typed failure contract.

Every model, baseline and key belongs to a private temporary fixture. Product
imports are delayed until data/model paths are held. No provider calls, native
workers, real installation keys, replicated signers or successful-attestation
stubs are used.
"""
from __future__ import annotations

import hashlib
import importlib
import json
import re
import secrets
import sys
from types import SimpleNamespace

import pytest


_APIS = ["direct", "inventory"]
_BAD_BASELINES = ["deep-json", "integer-limit", "approved-at-overflow"]
_FIXTURE_BYTE_CAP = 64 * 1024
_PARSER_SHAPE_CAP = 8192


@pytest.fixture
def private_model(tmp_path, monkeypatch):
    data = tmp_path / "data"
    models = tmp_path / "models-\u00e9"
    data.mkdir()
    models.mkdir()
    temp = data / "tmp"
    temp.mkdir()
    for name, value in {
        "ANGERONA_DATA": data,
        "ANGERONA_DIAG_DIR": data / "diagnostics",
        "TEMP": temp,
        "TMP": temp,
        "ANGERONA_OLLAMA_MODELS": models,
        "OLLAMA_MODELS": models,
        "ANGERONA_MODEL": "fixture:latest",
        "OLLAMA_MODEL": "fixture:latest",
        "OLLAMA_HOST": "http://127.0.0.1:11434",
        "ANGERONA_BLACKBOX_ENABLED": "0",
    }.items():
        monkeypatch.setenv(name, str(value))
    monkeypatch.delenv("ANGERONA_CHILL_ACTIVE", raising=False)
    monkeypatch.delenv("ANGERONA_CHILL_AI_BLOCKED", raising=False)

    # No product module is imported by this file during collection. Hold the
    # shared resolver too, so a previously cached default cannot select host data.
    data_paths = importlib.import_module("angerona.core.data_paths")
    monkeypatch.setattr(data_paths, "data_dir", lambda *_args, **_kwargs: data)
    integrity = importlib.import_module("angerona.modules.ai_model_integrity")
    monkeypatch.setattr(integrity, "_repo_root", lambda: data)
    monkeypatch.setattr(integrity, "_ATTESTATION_CACHE", {})
    guard_class = integrity.AIModelIntegrityGuardModule
    real_init = guard_class.__init__
    fixture_key = secrets.token_bytes(32)
    baseline_path = data / "fixture-baseline.json"

    def private_init(self):
        real_init(self)
        self._baseline_path = baseline_path
        self._baseline_key_override = fixture_key

    # All fresh guards, including readiness/cache consumers, get only this key.
    monkeypatch.setattr(guard_class, "__init__", private_init)
    guard = guard_class()
    blob_hex = hashlib.sha256(b"").hexdigest()
    blob = models / "blobs" / ("sha256-" + blob_hex)
    blob.parent.mkdir()
    blob.write_bytes(b"")
    manifest = models / "manifests" / "registry.ollama.ai" / "library" / "fixture" / "latest"
    manifest.parent.mkdir(parents=True)
    raw = json.dumps({
        "config": {"digest": "sha256:" + blob_hex, "size": 0},
        "layers": [],
    }, sort_keys=True, separators=(",", ":")).encode("utf-8")
    manifest.write_bytes(raw)
    return SimpleNamespace(
        integrity=integrity, guard=guard, models=models, data=data,
        blob=blob, blob_hex=blob_hex, manifest=manifest, raw=raw,
        baseline=baseline_path, fixture_key=fixture_key,
    )


def _extension(raw, value):
    assert raw.endswith(b"}")
    return raw[:-1] + b',"ignored":' + value + b"}"


def _deep_value(record_property):
    limit = sys.getrecursionlimit()
    depth = limit + 64
    record_property("interpreter_recursion_limit", limit)
    if depth > _PARSER_SHAPE_CAP:
        pytest.skip("interpreter recursion limit exceeds bounded deep-JSON fixture (8192)")
    attempts = 0
    while True:
        attempts += 1
        value = b"[" * depth + b"0" + b"]" * depth
        assert 0 < len(value) <= _FIXTURE_BYTE_CAP
        try:
            json.loads(value.decode("ascii"))
        except RecursionError:
            record_property("fixture_json_depth", depth)
            record_property("fixture_json_probe_attempts", attempts)
            return value
        if depth == _PARSER_SHAPE_CAP:
            record_property("fixture_json_depth", depth)
            record_property("fixture_json_probe_attempts", attempts)
            pytest.fail("bounded deep-JSON fixture did not reach an actual parser RecursionError (8192)", pytrace=False)
        depth = min(depth * 2, _PARSER_SHAPE_CAP)


def _integer_token(record_property):
    getter = getattr(sys, "get_int_max_str_digits", None)
    if getter is None:
        pytest.skip("interpreter integer-string conversion limit API unavailable")
    limit = getter()
    record_property("interpreter_integer_string_limit", limit)
    if limit <= 0:
        pytest.skip("interpreter integer-string conversion limit is disabled")
    if limit >= _PARSER_SHAPE_CAP:
        pytest.skip("interpreter integer-string limit exceeds bounded digit fixture (8192)")
    record_property("fixture_integer_digits", limit + 1)
    return b"9" * (limit + 1)


def _invoke_manifest(harness, api, raw):
    assert 0 < len(raw) <= _FIXTURE_BYTE_CAP
    harness.manifest.write_bytes(raw)
    if api == "direct":
        return harness.integrity.verify_ollama_model_files(
            "fixture:latest", "sha256:" + hashlib.sha256(raw).hexdigest(),
            models_root=harness.models,
        )
    assert api == "inventory"
    return harness.guard._snapshot_inventory()


def _assert_unapproved_manifest_evidence(harness, raw):
    assert harness.manifest.read_bytes() == raw
    assert harness.blob.read_bytes() == b""
    assert not harness.baseline.exists()
    assert harness.integrity._ATTESTATION_CACHE == {}


def _approve(harness):
    assert harness.guard.rebaseline(approved=True) == 2
    original = harness.baseline.read_bytes()
    assert 0 < len(original) <= _FIXTURE_BYTE_CAP
    assert harness.guard._load_baseline() is True
    return original


def _malformed_baseline(harness, kind, record_property):
    original = harness.baseline.read_bytes()
    original_mac = json.loads(original)["hmac_sha256"]
    if kind == "deep-json":
        token = _deep_value(record_property)
    elif kind == "integer-limit":
        token = _integer_token(record_property)
    else:
        assert kind == "approved-at-overflow"
        token = b"9" * 400
    pattern = rb'("approved_at"\s*:\s*)([^,}\s]+)'
    matches = list(re.finditer(pattern, original))
    assert len(matches) == 1
    match = matches[0]
    bad = original[:match.start(2)] + token + original[match.end(2):]
    assert 0 < len(bad) <= _FIXTURE_BYTE_CAP
    assert json.dumps(original_mac).encode("ascii") in bad
    if kind == "deep-json":
        with pytest.raises(RecursionError):
            json.loads(bad.decode("utf-8"))
    elif kind == "integer-limit":
        with pytest.raises(ValueError) as error:
            json.loads(bad.decode("utf-8"))
        assert type(error.value) is ValueError
    else:
        document = json.loads(bad.decode("utf-8"))
        assert document["hmac_sha256"] == original_mac
        with pytest.raises(OverflowError):
            float(document["approved_at"])
    harness.baseline.write_bytes(bad)
    record_property("malformed_baseline_bytes", len(bad))
    return bad


def _assert_invalid_evidence(harness, raw):
    assert harness.guard._load_baseline() is False
    assert harness.guard._baseline_status == "invalid"
    assert harness.guard.last_error
    with pytest.raises(harness.integrity.ModelIntegrityError, match="refusing to overwrite"):
        harness.guard.rebaseline(approved=True)
    assert harness.baseline.read_bytes() == raw


@pytest.mark.parametrize("api", _APIS)
def test_deep_manifest_normalizes_actual_parser_recursion(private_model, api, record_property):
    raw = _extension(private_model.raw, _deep_value(record_property))
    with pytest.raises(private_model.integrity.ModelIntegrityError) as error:
        _invoke_manifest(private_model, api, raw)
    assert isinstance(error.value.__cause__, RecursionError)
    _assert_unapproved_manifest_evidence(private_model, raw)


@pytest.mark.parametrize("api", _APIS)
def test_integer_manifest_normalizes_active_conversion_limit(private_model, api, record_property):
    raw = _extension(private_model.raw, _integer_token(record_property))
    with pytest.raises(private_model.integrity.ModelIntegrityError) as error:
        _invoke_manifest(private_model, api, raw)
    assert type(error.value.__cause__) is ValueError
    _assert_unapproved_manifest_evidence(private_model, raw)


@pytest.mark.parametrize("kind", _BAD_BASELINES)
def test_malformed_baseline_is_invalid_preserved_and_not_reenrolled(
    private_model, kind, record_property,
):
    _approve(private_model)
    raw = _malformed_baseline(private_model, kind, record_property)
    _assert_invalid_evidence(private_model, raw)


@pytest.mark.parametrize("api", _APIS)
@pytest.mark.parametrize("variant", ["root", "nested", "escape-equivalent"])
def test_duplicate_manifest_keys_keep_specific_typed_error(private_model, api, variant):
    if variant == "root":
        raw = private_model.raw[:-1] + b',"layers":[]}'
    elif variant == "nested":
        raw = private_model.raw.replace(b'"size":0', b'"size":0,"size":0', 1)
    else:
        raw = private_model.raw.replace(b'"size":0', b'"size":0,"si\\u007ae":0', 1)
    with pytest.raises(
        private_model.integrity.ModelIntegrityError, match="duplicate Ollama manifest field",
    ) as error:
        _invoke_manifest(private_model, api, raw)
    assert error.value.__cause__ is None
    _assert_unapproved_manifest_evidence(private_model, raw)


@pytest.mark.parametrize("api", _APIS)
def test_invalid_manifest_utf8_keeps_typed_failure(private_model, api):
    raw = _extension(private_model.raw, b'"\xff"')
    with pytest.raises(private_model.integrity.ModelIntegrityError) as error:
        _invoke_manifest(private_model, api, raw)
    assert isinstance(error.value.__cause__, UnicodeDecodeError)
    _assert_unapproved_manifest_evidence(private_model, raw)


@pytest.mark.parametrize("api", _APIS)
@pytest.mark.parametrize(
    "token",
    [b"true", b"false", b"0.0", b'"0"', b"-1", b"1125899906842625",
     b"NaN", b"Infinity", b"-Infinity"],
    ids=["true", "false", "float", "string", "negative", "over-bound",
         "nan", "infinity", "negative-infinity"],
)
def test_manifest_security_sizes_stay_strict(private_model, api, token):
    raw = private_model.raw.replace(b'"size":0', b'"size":' + token, 1)
    with pytest.raises(private_model.integrity.ModelIntegrityError, match="identity is invalid"):
        _invoke_manifest(private_model, api, raw)
    _assert_unapproved_manifest_evidence(private_model, raw)


@pytest.mark.parametrize("api", _APIS)
@pytest.mark.parametrize(
    "metadata", [b"null", b"NaN", b"Infinity", b"-Infinity", b'"\\ud800"', b'{"purpose":"fixture"}'],
    ids=["null", "nan", "infinity", "negative-infinity", "escaped-surrogate", "ordinary"],
)
def test_zero_size_and_ignored_metadata_compatibility(private_model, api, metadata):
    raw = _extension(private_model.raw, metadata)
    result = _invoke_manifest(private_model, api, raw)
    if api == "direct":
        assert result.bytes_verified == 0 and result.blob_count == 1
        assert result.manifest_digest == "sha256:" + hashlib.sha256(raw).hexdigest()
    else:
        hashes, identity = result
        relative = private_model.manifest.relative_to(private_model.models).as_posix()
        assert hashes[relative] == hashlib.sha256(raw).hexdigest()
        assert hashes["blobs/sha256-" + private_model.blob_hex] == private_model.blob_hex
        assert identity["resolved"] == str(private_model.models.resolve())
    _assert_unapproved_manifest_evidence(private_model, raw)


@pytest.mark.parametrize(
    "representation", ["whitespace", "key-order", "literal-unicode", "equivalent-escape"],
)
def test_equivalent_baseline_objects_authenticate_but_raw_sha_changes(private_model, representation):
    original = _approve(private_model)
    prior = private_model.integrity.require_fresh_model_attestation("fixture:latest")
    document = json.loads(original)
    if representation == "whitespace":
        equivalent = json.dumps(document, indent=2).encode("utf-8")
    elif representation == "key-order":
        equivalent = json.dumps(dict(reversed(list(document.items())))).encode("utf-8")
    elif representation == "literal-unicode":
        equivalent = json.dumps(document, ensure_ascii=False).encode("utf-8")
    else:
        assert b"\\u00e9" in original
        equivalent = original.replace(b"\\u00e9", b"\\u00E9")
    assert equivalent != original and json.loads(equivalent) == document
    private_model.baseline.write_bytes(equivalent)
    assert private_model.guard._load_baseline() is True
    assert private_model.guard._baseline_sha256 == hashlib.sha256(equivalent).hexdigest()
    assert private_model.guard._baseline_sha256 != prior.baseline_sha256
    current = private_model.integrity.require_fresh_model_attestation("fixture:latest")
    assert current is not prior
    assert current.baseline_sha256 == private_model.guard._baseline_sha256
    assert private_model.baseline.read_bytes() == equivalent


@pytest.mark.parametrize(
    "mutation",
    ["approved-at-bool", "approved-at-number", "approved-at-nan", "approved-at-infinity",
     "authority", "schema-value", "schema-float", "root-resolved", "root-device-value",
     "root-device-bool", "root-inode-value", "root-inode-bool", "file-digest", "file-name"],
)
def test_baseline_security_mutations_do_not_authenticate(private_model, mutation):
    original = _approve(private_model)
    document = json.loads(original)
    original_mac = document["hmac_sha256"]
    if mutation == "approved-at-bool":
        document["approved_at"] = True
    elif mutation == "approved-at-number":
        document["approved_at"] = -1
    elif mutation == "approved-at-nan":
        document["approved_at"] = float("nan")
    elif mutation == "approved-at-infinity":
        document["approved_at"] = float("inf")
    elif mutation == "authority":
        document["authority"] = "fixture-unapproved"
    elif mutation == "schema-value":
        document["schema"] = 3
    elif mutation == "schema-float":
        document["schema"] = 2.0
    elif mutation == "root-resolved":
        document["root"]["resolved"] += "-changed"
    elif mutation == "root-device-value":
        document["root"]["device"] += 1
    elif mutation == "root-device-bool":
        document["root"]["device"] = True
    elif mutation == "root-inode-value":
        document["root"]["inode"] += 1
    elif mutation == "root-inode-bool":
        document["root"]["inode"] = True
    elif mutation == "file-digest":
        document["files"][next(iter(document["files"]))] = "0" * 64
    else:
        assert mutation == "file-name"
        document["files"]["../outside"] = document["files"].pop(next(iter(document["files"])))
    assert document["hmac_sha256"] == original_mac
    raw = json.dumps(document).encode("utf-8")
    private_model.baseline.write_bytes(raw)
    _assert_invalid_evidence(private_model, raw)


@pytest.mark.parametrize("variant", ["root", "nested", "escape-equivalent"])
def test_duplicate_baseline_keys_remain_invalid(private_model, variant):
    original = _approve(private_model)
    if variant == "root":
        raw = original[:-1] + b',"schema":2}'
    elif variant == "nested":
        assert original.count(b'"root":{') == 1
        raw = original.replace(b'"root":{', b'"root":{"device":0,', 1)
    else:
        raw = original[:-1] + b',"sch\\u0065ma":2}'
    private_model.baseline.write_bytes(raw)
    _assert_invalid_evidence(private_model, raw)
    assert "duplicate Ollama manifest field" in private_model.guard.last_error


def test_non_ascii_baseline_mac_is_invalid_without_comparison_escape(private_model):
    original = _approve(private_model)
    document = json.loads(original)
    document["hmac_sha256"] = "\u00e9" * 64
    raw = json.dumps(document).encode("utf-8")
    private_model.baseline.write_bytes(raw)
    _assert_invalid_evidence(private_model, raw)


@pytest.mark.parametrize("kind", _BAD_BASELINES)
def test_malformed_baseline_blocks_cached_receipt_and_readiness(private_model, kind, record_property):
    _approve(private_model)
    prior = private_model.integrity.require_fresh_model_attestation("fixture:latest")
    raw = _malformed_baseline(private_model, kind, record_property)
    for operation in [private_model.integrity.check_model_readiness,
                      private_model.integrity.require_fresh_model_attestation]:
        with pytest.raises(private_model.integrity.ModelIntegrityError, match="invalid"):
            operation("fixture:latest")
    # A retained old object in the implementation cache grants no successful call.
    assert private_model.integrity._ATTESTATION_CACHE["fixture:latest"] is prior
    _assert_invalid_evidence(private_model, raw)


@pytest.mark.parametrize("kind", _BAD_BASELINES)
def test_actual_bad_baseline_blocks_triage_transport_and_clears_receipt(
    private_model, monkeypatch, kind, record_property,
):
    _approve(private_model)
    prior = private_model.integrity.require_fresh_model_attestation("fixture:latest")
    raw = _malformed_baseline(private_model, kind, record_property)
    triage = importlib.import_module("angerona.modules.ai_triage")
    calls = []

    def forbidden_transport(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("malformed-fixture attestation reached provider transport")

    monkeypatch.setattr(triage, "safe_urlopen", forbidden_transport)
    instance = triage.AITriageModule()
    instance._attestation_receipt = prior
    monkeypatch.setattr(instance, "emit", lambda *_args, **_kwargs: None)
    assert instance._ask("inert fixture event") is None
    assert calls == [] and instance._attestation_receipt is None
    assert "invalid" in instance._attestation_error
    assert private_model.baseline.read_bytes() == raw


@pytest.mark.parametrize("kind", _BAD_BASELINES)
def test_actual_bad_baseline_keeps_speculative_prewarm_unwarmed(
    private_model, monkeypatch, kind, record_property,
):
    _approve(private_model)
    raw = _malformed_baseline(private_model, kind, record_property)
    speculative = importlib.import_module("angerona.modules.speculative_triage")
    monkeypatch.setattr(speculative, "_MODEL", "fixture:latest")
    calls = []

    def forbidden_provider(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("malformed-fixture attestation reached speculative provider")

    monkeypatch.setattr(speculative.ollama_client, "analyze_telemetry", forbidden_provider)
    instance = speculative.SpeculativeTriageModule()
    monkeypatch.setattr(instance, "emit", lambda *_args, **_kwargs: None)
    instance._prewarm({"pid": 301, "message": "inert marker", "details": {}})
    assert calls == [] and instance.successful_prewarms == 0
    assert instance._primed[301]["warmed"] is False
    assert "invalid" in instance.last_error
    assert private_model.baseline.read_bytes() == raw


@pytest.mark.parametrize("kind", ["deep-json", "integer-limit"])
def test_one_cycle_guard_contains_real_malformed_manifest_without_escaping(
    private_model, monkeypatch, kind, record_property,
):
    original = _approve(private_model)
    token = _deep_value(record_property) if kind == "deep-json" else _integer_token(record_property)
    raw = _extension(private_model.raw, token)
    private_model.manifest.write_bytes(raw)
    events = []
    boundaries = []
    stop = private_model.guard.generation_stop_event()
    monkeypatch.setattr(private_model.guard, "emit", lambda *args, **kwargs: events.append((args, kwargs)))

    def finish_generation(captured_stop):
        assert captured_stop is stop
        boundaries.append(True)
        captured_stop.set()

    monkeypatch.setattr(private_model.guard, "_wait_for_next_scan", finish_generation)
    private_model.guard.run()  # Synchronous one-cycle unit seam: no native/thread wrapper.
    assert boundaries == [True] and stop.is_set()
    assert private_model.guard._baseline_status == "approved"
    assert private_model.guard.health == 0 and private_model.guard._verified == 0
    assert "not a valid Ollama manifest" in private_model.guard.last_error
    assert any("structurally invalid" in str(args) for args, _kwargs in events)
    assert private_model.baseline.read_bytes() == original
    assert private_model.manifest.read_bytes() == raw


@pytest.mark.parametrize("kind", _BAD_BASELINES)
def test_one_cycle_guard_reports_invalid_baseline_through_existing_unavailable_branch(
    private_model, monkeypatch, kind, record_property,
):
    _approve(private_model)
    raw = _malformed_baseline(private_model, kind, record_property)
    events = []
    boundaries = []
    stop = private_model.guard.generation_stop_event()
    monkeypatch.setattr(private_model.guard, "emit", lambda *args, **kwargs: events.append((args, kwargs)))

    def finish_generation(captured_stop):
        assert captured_stop is stop
        boundaries.append(True)
        captured_stop.set()

    monkeypatch.setattr(private_model.guard, "_wait_for_next_scan", finish_generation)
    private_model.guard.run()
    assert boundaries == [True] and stop.is_set()
    assert private_model.guard._baseline_status == "invalid"
    assert private_model.guard.health == 25 and private_model.guard._verified == 0
    assert any("attestation unavailable" in str(args) for args, _kwargs in events)
    assert private_model.baseline.read_bytes() == raw


@pytest.mark.parametrize("kind", ["deep-json", "integer-limit"])
def test_model_pack_activation_stops_at_actual_parser_before_mutation(
    private_model, monkeypatch, kind, record_property,
):
    token = _deep_value(record_property) if kind == "deep-json" else _integer_token(record_property)
    raw = _extension(private_model.raw, token)
    private_model.manifest.write_bytes(raw)
    digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    packs = importlib.import_module("angerona.core.model_pack_manager")
    # Minimal in-memory admission/state seams; the local verifier and activate()
    # are real. No production manager constructor, catalog mutation or API call.
    manager = object.__new__(packs.ModelPackManager)
    manager._key = private_model.fixture_key
    pack = SimpleNamespace(
        id="fixture-pack", model=SimpleNamespace(
            managed_name="fixture:latest", manifest_digest=digest, model_bytes=1,
        ),
    )
    manager._pack = lambda _pack_id: pack
    manager.state = lambda: {"installed": {pack.id: {"managed_model": "fixture:latest"}}}
    manager._model_digest = lambda _model: digest
    manager._model_verifier = lambda model, expected: private_model.integrity.verify_ollama_model_files(
        model, expected, models_root=private_model.models,
    )
    mutations = []
    manager._config_update = lambda *_args: mutations.append("config")
    manager._write_state = lambda *_args: mutations.append("state")
    manager._receipt = lambda *_args, **_kwargs: mutations.append("receipt")
    with pytest.raises(packs.ModelPackError, match="local model verification failed") as error:
        manager.activate(pack.id)
    assert isinstance(error.value.__cause__, private_model.integrity.ModelIntegrityError)
    assert isinstance(error.value.__cause__.__cause__, RecursionError if kind == "deep-json" else ValueError)
    assert mutations == []
    _assert_unapproved_manifest_evidence(private_model, raw)
