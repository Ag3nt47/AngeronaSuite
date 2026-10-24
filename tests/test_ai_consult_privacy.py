"""Inert manual-consult privacy tests: captured bodies, no network or model."""
from __future__ import annotations

import json
import threading
import time
from types import SimpleNamespace

import pytest
import shiboken6
from PySide6.QtCore import QCoreApplication, QEvent, QThread, Qt
from PySide6.QtWidgets import QApplication, QWidget

from angerona.core import privacy
from angerona.engines import ai_consult
from angerona.gui import ai_consult_dialog


_PRIVATE = (
    "INERT_JSON_BEARER_SECRET", "INERT_PASSWORD_VALUE", "INERT_PRIVATE_HOST",
    "INERT_PRIVATE_VPN", "INERT_PRIVATE_OPERATOR", "INERT_PRIVATE_DEVICE",
    "Private Cases", "private-payload.exe", "private-posix-file",
    "203.0.113.44", "2001:db8::42", "00:11:22:33:44:55",
    "alice@example.test", "https://private.example.test/path",
    "ghp_0123456789abcdefghijklmnopqrstuv", "INERT_SYSTEM_SECRET",
)
_RAW_PROMPT = (
    'Research this alert. Module: SpywareGuard. Severity: High.\n'
    'Details: {"authorization": "Bearer INERT_JSON_BEARER_SECRET", '
    '"password": "INERT_PASSWORD_VALUE"}\n'
    'host=INERT_PRIVATE_HOST | vpn_tunnels=INERT_PRIVATE_VPN\n'
    'Operator INERT_PRIVATE_OPERATOR at INERT_PRIVATE_DEVICE\n'
    'opened C:\\Users\\Alice\\Private Cases\\private-payload.exe\n'
    'opened /home/alice/private-posix-file\n'
    'peer 203.0.113.44 2001:db8::42 00:11:22:33:44:55\n'
    'contact alice@example.test https://private.example.test/path\n'
    'ghp_0123456789abcdefghijklmnopqrstuv\n'
    'Explain which evidence is unavailable and propose review steps.'
)
_RAW_SYSTEM = 'Be concise. {"secret": "INERT_SYSTEM_SECRET"}'


class _Response:
    headers = {}

    def __init__(self, answer: str):
        self._data = json.dumps({
            "content": [{"text": answer}],
            "choices": [{"message": {"content": answer}}],
            "candidates": [{"content": {"parts": [{"text": answer}]}}],
            "message": {"content": answer},
        }).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, maximum):
        return self._data[:maximum]


@pytest.fixture
def captured_transport(monkeypatch):
    state = SimpleNamespace(requests=[], answer="Inert advisory answer.",
                            configured={"anthropic"}, keys={})
    monkeypatch.setattr(ai_consult, "configured_provider_ids",
                        lambda: sorted(state.configured))
    monkeypatch.setattr(ai_consult, "credential_value",
                        lambda name: state.keys.get(name, "INERT_PROVIDER_CREDENTIAL") if name in state.configured else "")
    monkeypatch.setenv("ANGERONA_AI_ORDER", "")
    monkeypatch.setenv("USERNAME", "INERT_PRIVATE_OPERATOR")
    monkeypatch.setenv("COMPUTERNAME", "INERT_PRIVATE_DEVICE")
    monkeypatch.setattr(privacy.socket, "gethostname", lambda: "INERT_PRIVATE_DEVICE")
    monkeypatch.setattr(ai_consult, "OLLAMA_HOST", "http://localhost:11434")
    # Capture the existing local URL helper's pinning contract without any DNS.
    monkeypatch.setattr(ai_consult, "local_service_url",
                        lambda _base, path: "http://127.0.0.1:11434" + path)
    monkeypatch.setattr(ai_consult_dialog, "begin_loading", lambda *_a, **_k: None)
    monkeypatch.setattr(ai_consult_dialog, "finish_loading", lambda *_a, **_k: None)

    def capture(request, *, policy, timeout):
        state.requests.append((request, policy, timeout))
        return _Response(state.answer)

    monkeypatch.setattr(ai_consult, "safe_urlopen", capture)
    # Even an accidental alternate urllib transport cannot make a real request.
    monkeypatch.setattr(ai_consult.urllib.request, "urlopen", lambda *_a, **_k:
                        (_ for _ in ()).throw(AssertionError("real HTTP forbidden")))
    return state


def _assert_private_absent(value: object):
    text = json.dumps(value, ensure_ascii=False).casefold()
    for private in _PRIVATE:
        assert private.casefold() not in text


def _payload(request):
    return json.loads(request.data.decode("utf-8"))


def _content(payload):
    if "system_instruction" in payload:
        return (payload["contents"][0]["parts"][0]["text"],
                payload["system_instruction"]["parts"][0]["text"])
    if "system" in payload:
        return payload["messages"][0]["content"], payload["system"]
    return payload["messages"][1]["content"], payload["messages"][0]["content"]


@pytest.mark.parametrize("provider", [
    "anthropic", "gemini", "groq", "openai", "openrouter", "ollama",
])
def test_direct_consult_sanitizes_both_contents_before_each_adapter(captured_transport, monkeypatch, provider):
    captured_transport.configured = {provider}
    fn = dict(ai_consult._PROVIDERS)[provider]
    monkeypatch.setattr(ai_consult, "_PROVIDERS", [(provider, fn)])
    original = (_RAW_PROMPT, _RAW_SYSTEM)
    result = ai_consult.consult_ai(_RAW_PROMPT, _RAW_SYSTEM)
    assert result["provider"] == provider
    assert result["text"] == "Inert advisory answer."
    assert len(captured_transport.requests) == 1
    request, policy, _timeout = captured_transport.requests[0]
    body = _payload(request)
    _assert_private_absent(body)
    assert _content(body) == privacy.prepare_consultation_text(*original)
    assert "SpywareGuard" in _content(body)[0]
    assert "redacted" in _content(body)[0]
    assert (_RAW_PROMPT, _RAW_SYSTEM) == original
    if provider == "ollama":
        assert request.full_url == "http://127.0.0.1:11434/api/chat"
        assert policy is ai_consult.OLLAMA_SERVICE_POLICY


def test_provider_order_and_fallback_are_preserved_after_sanitization(monkeypatch):
    calls = []

    def first(prompt, system):
        calls.append(("first", prompt, system))
        return ""

    def second(prompt, system):
        calls.append(("second", prompt, system))
        return "answer"

    monkeypatch.setattr(ai_consult, "_PROVIDERS", [("first", first), ("second", second)])
    monkeypatch.setenv("ANGERONA_AI_ORDER", "second,first")
    result = ai_consult.consult_ai('password="INERT_PASSWORD_VALUE"', allow_local_fallback=False)
    assert result["provider"] == "second"
    assert [row[0] for row in calls] == ["second"]
    _assert_private_absent(calls)


def test_preparation_failure_holds_every_provider(captured_transport, monkeypatch):
    def fail(*_args, **_kwargs):
        raise ValueError("INERT_PASSWORD_VALUE must not be echoed")

    monkeypatch.setattr(ai_consult, "prepare_consultation_text", fail)
    result = ai_consult.consult_ai(_RAW_PROMPT, _RAW_SYSTEM)
    assert result["provider"] is None
    assert "held" in result["error"]
    assert "INERT_PASSWORD_VALUE" not in result["error"]
    assert captured_transport.requests == []


def test_non_text_input_does_not_invoke_stringification_or_transport(captured_transport):
    class Hostile:
        def __str__(self):
            raise AssertionError("must not stringify arbitrary prompt objects")

    result = ai_consult.consult_ai(Hostile())
    assert result["provider"] is None
    assert "held" in result["error"]
    assert captured_transport.requests == []


def test_bounds_apply_before_regex_and_serialization(captured_transport):
    raw = ("/tmp/private-posix-file " * 10_000) + "INERT_PASSWORD_VALUE"
    result = ai_consult.consult_ai(raw, "\x01" * 40_000, allow_local_fallback=False)
    assert result["provider"] == "anthropic"
    request = captured_transport.requests[0][0]
    prompt, system = _content(_payload(request))
    assert len(prompt) <= privacy.CONSULT_MAX_PROMPT_CHARS
    assert len(system) <= privacy.CONSULT_MAX_SYSTEM_CHARS
    assert len(request.data) < 64_000
    assert "context-size-limit" in prompt
    assert "context-size-limit" in system
    assert "private-posix-file" not in prompt


def test_multiline_private_key_is_not_in_outbound_body(captured_transport):
    marker = "INERT_PRIVATE_KEY_MATERIAL"
    key = "-----BEGIN PRIVATE KEY-----\n" + marker + "\n-----END PRIVATE KEY-----"
    result = ai_consult.consult_ai("Review: " + key, allow_local_fallback=False)
    assert result["provider"] == "anthropic"
    assert marker not in captured_transport.requests[0][0].data.decode("utf-8")


def test_preview_has_no_transport_and_binds_exact_content(captured_transport):
    captured_transport.configured = {"openai", "anthropic"}
    preview = ai_consult.prepare_consultation(_RAW_PROMPT, _RAW_SYSTEM, False)
    assert captured_transport.requests == []
    assert [route.provider_id for route in preview.destinations] == ["anthropic", "openai"]
    assert all("INERT_PROVIDER_CREDENTIAL" not in route.endpoint for route in preview.destinations)
    assert json.loads(preview.payload_json()) == {"prompt": preview.prompt, "system": preview.system}
    result = ai_consult.consult_ai(_RAW_PROMPT, _RAW_SYSTEM, False, approved_preview=preview)
    assert result["provider"] == "anthropic"
    assert _content(_payload(captured_transport.requests[0][0])) == (preview.prompt, preview.system)


@pytest.mark.parametrize("change", ["prompt", "system", "configured", "order", "model", "local"])
def test_review_mismatch_holds_before_transport(captured_transport, monkeypatch, change):
    captured_transport.configured = {"anthropic", "openai"}
    preview = ai_consult.prepare_consultation(_RAW_PROMPT, _RAW_SYSTEM, True)
    prompt, system, local = _RAW_PROMPT, _RAW_SYSTEM, True
    if change == "prompt":
        prompt = "A different selected question"
    elif change == "system":
        system = "Different role framing"
    elif change == "configured":
        captured_transport.configured.add("gemini")
    elif change == "order":
        monkeypatch.setenv("ANGERONA_AI_ORDER", "openai,anthropic")
    elif change == "model":
        monkeypatch.setattr(ai_consult, "ANTHROPIC_MODEL", "changed-model")
    else:
        local = False
    result = ai_consult.consult_ai(prompt, system, local, approved_preview=preview)
    assert result["provider"] is None
    assert "held" in result["error"]
    assert captured_transport.requests == []


def test_cancelled_request_does_not_begin_a_provider(captured_transport):
    result = ai_consult.consult_ai(_RAW_PROMPT, cancelled=lambda: True)
    assert result["error"] == "Consultation cancelled."
    assert captured_transport.requests == []


def test_shared_analysis_sanitizer_keeps_compatibility_defaults():
    from angerona.core.analysis_worker import _CloudPromptSanitizer, _build_cloud_prompt

    assert _CloudPromptSanitizer is privacy.CloudPromptSanitizer
    prompt = _build_cloud_prompt({"details": {"authorization": "INERT_JSON_BEARER_SECRET"}})
    assert "INERT_JSON_BEARER_SECRET" not in prompt
    assert "<redacted:sensitive-field>" in prompt
    benign_text = ("routine scan status " * 300)[:5_000]
    assert _CloudPromptSanitizer().text(benign_text) == benign_text[:privacy.CLOUD_MAX_STRING_CHARS]
    # Hash/encoded-looking input must retain the baseline secret redaction.
    assert _CloudPromptSanitizer().text("a" * 5_000) == "[REDACTED]"


@pytest.fixture
def app():
    instance = QApplication.instance() or QApplication([])
    yield instance
    instance.processEvents()


def _until(app, predicate, seconds=5.0):
    deadline = time.monotonic() + seconds
    while not predicate():
        assert time.monotonic() < deadline, "owned inert worker did not retire"
        app.processEvents()
        time.sleep(0.002)
    app.processEvents()


def test_dialog_open_and_retry_only_preview_then_explicit_send(app, captured_transport):
    dialog = ai_consult_dialog.AIConsultDialog("Inert privacy review", _RAW_PROMPT,
                                             system=_RAW_SYSTEM, allow_local_fallback=False)
    try:
        app.processEvents()
        assert captured_transport.requests == []
        assert dialog._worker is None
        assert dialog._active_worker is None
        _assert_private_absent(json.loads(dialog._payload_preview.toPlainText()))
        assert "api.anthropic.com" in dialog._destinations.text()
        assert "Nothing sent" in dialog._status.text()
        dialog._btn_retry.click()
        assert captured_transport.requests == []
        reviewed = json.loads(dialog._payload_preview.toPlainText())
        dialog._btn_send_reviewed.click()
        _until(app, lambda: dialog._active_worker is None)
        assert len(captured_transport.requests) == 1
        assert _content(_payload(captured_transport.requests[0][0])) == (reviewed["prompt"], reviewed["system"])
        assert dialog._worker is None
        assert dialog._fu_worker is None
        assert not dialog._btn_send_reviewed.isEnabled()
        assert "advisory" in dialog._output.toPlainText().lower()
    finally:
        dialog.close()


def test_edited_preview_needs_new_review_and_another_explicit_send(app, captured_transport):
    dialog = ai_consult_dialog.AIConsultDialog("Inert edits", _RAW_PROMPT,
                                             allow_local_fallback=False)
    try:
        dialog._payload_preview.setPlainText(json.dumps({
            "prompt": 'Selected question only. password="INERT_PASSWORD_VALUE"',
            "system": 'Keep concise. secret="INERT_SYSTEM_SECRET"',
        }))
        assert dialog._preview_dirty
        assert not dialog._btn_send_reviewed.isEnabled()
        dialog._send_reviewed()
        assert captured_transport.requests == []
        dialog._btn_review.click()
        assert captured_transport.requests == []
        reviewed = json.loads(dialog._payload_preview.toPlainText())
        _assert_private_absent(reviewed)
        assert "Selected question only" in reviewed["prompt"]
        assert "SpywareGuard" not in reviewed["prompt"]
        dialog._btn_send_reviewed.click()
        _until(app, lambda: dialog._active_worker is None)
        assert len(captured_transport.requests) == 1
        assert _content(_payload(captured_transport.requests[0][0])) == (reviewed["prompt"], reviewed["system"])
    finally:
        dialog.close()


def test_followup_including_model_text_is_sanitized_and_reviewed_again(app, captured_transport):
    captured_transport.answer = 'Advisory. {"authorization":"INERT_JSON_BEARER_SECRET"}'
    dialog = ai_consult_dialog.AIConsultDialog("Inert follow-up", _RAW_PROMPT,
                                             allow_local_fallback=False)
    try:
        dialog._btn_send_reviewed.click()
        _until(app, lambda: dialog._active_worker is None)
        assert len(captured_transport.requests) == 1
        dialog._prompt_input.setText('Next question: password="INERT_PASSWORD_VALUE"')
        dialog._send_btn.click()
        app.processEvents()
        assert len(captured_transport.requests) == 1
        assert dialog._active_worker is None
        reviewed = json.loads(dialog._payload_preview.toPlainText())
        _assert_private_absent(reviewed)
        assert "Next question" in reviewed["prompt"]
        dialog._btn_send_reviewed.click()
        _until(app, lambda: dialog._active_worker is None)
        assert len(captured_transport.requests) == 2
        assert _content(_payload(captured_transport.requests[1][0])) == (reviewed["prompt"], reviewed["system"])
        _assert_private_absent(_payload(captured_transport.requests[1][0]))
    finally:
        dialog.close()


def test_dialog_holds_routing_change_without_constructing_worker(app, captured_transport, monkeypatch):
    dialog = ai_consult_dialog.AIConsultDialog("Inert route change", _RAW_PROMPT,
                                             allow_local_fallback=False)
    try:
        monkeypatch.setattr(ai_consult, "ANTHROPIC_MODEL", "changed-model")
        dialog._btn_send_reviewed.click()
        app.processEvents()
        assert captured_transport.requests == []
        assert dialog._active_worker is None
        assert "held" in dialog._status.text()
        assert not dialog._btn_send_reviewed.isEnabled()
    finally:
        dialog.close()


def test_dialog_preparation_error_cannot_enable_send(app, captured_transport, monkeypatch):
    def fail(*_args, **_kwargs):
        raise RuntimeError("INERT_PASSWORD_VALUE")

    monkeypatch.setattr(ai_consult_dialog, "prepare_consultation", fail)
    dialog = ai_consult_dialog.AIConsultDialog("Inert failure", _RAW_PROMPT)
    try:
        app.processEvents()
        assert captured_transport.requests == []
        assert dialog._worker is None
        assert not dialog._btn_send_reviewed.isEnabled()
        assert "INERT_PASSWORD_VALUE" not in dialog._status.text()
    finally:
        dialog.close()


def test_close_retains_owned_worker_and_stops_further_fallbacks(app, captured_transport, monkeypatch):
    entered, release = threading.Event(), threading.Event()
    captured_transport.configured = {"anthropic", "openai"}
    original_capture = ai_consult.safe_urlopen

    def blocked_capture(request, **kwargs):
        response = original_capture(request, **kwargs)
        entered.set()
        assert release.wait(5.0), "inert close fixture not released"
        response._data = json.dumps({"content": []}).encode("utf-8")
        return response

    monkeypatch.setattr(ai_consult, "safe_urlopen", blocked_capture)
    dialog = ai_consult_dialog.AIConsultDialog("Inert close", _RAW_PROMPT,
                                             allow_local_fallback=False)
    dialog.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose, True)
    worker = None
    native_waits = []
    destroyed = []
    dialog.destroyed.connect(lambda *_args: destroyed.append(True))
    dialog_id = id(dialog)
    try:
        dialog.show()
        dialog._btn_send_reviewed.click()
        worker = dialog._active_worker
        native_wait = worker.wait

        def observed_wait(milliseconds):
            outcome = native_wait(milliseconds)
            native_waits.append((milliseconds, outcome))
            return outcome

        monkeypatch.setattr(worker, "wait", observed_wait)
        _until(app, entered.is_set)
        started = time.monotonic()
        dialog.close()
        assert time.monotonic() - started < 0.25
        assert not dialog.isVisible()
        assert worker.isRunning()
        assert worker.isInterruptionRequested()
        release.set()
        _until(app, lambda: bool(destroyed))
        assert any(milliseconds == 0 and outcome for milliseconds, outcome in native_waits)
        assert dialog_id not in ai_consult_dialog._RETAINED_CONSULTS
        assert len(captured_transport.requests) == 1
    finally:
        release.set()
        if worker is not None and shiboken6.isValid(worker):
            assert worker.wait(5_000)
        QCoreApplication.processEvents()


@pytest.mark.parametrize("text", [
    'environment={"A":"INERT_FIRST_VALUE","B":"INERT_SECOND_VALUE"}',
    'environment={\n"A":"INERT_FIRST_VALUE",\n"B":"INERT_SECOND_VALUE"}',
    'environment=["INERT_FIRST_VALUE", {"nested":"INERT_SECOND_VALUE"}]',
    'environment={"A":"INERT_FIRST_VALUE","B":"INERT_SECOND_VALUE"',
    json.dumps({"message": json.dumps({"environment": {"A": "INERT_FIRST_VALUE", "B": "INERT_SECOND_VALUE"}})}),
    'Authorization: Basic\n INERT_FIRST_VALUE\n INERT_SECOND_VALUE',
    'Cookie: sid=INERT_FIRST_VALUE; custom=INERT_SECOND_VALUE',
    'Authorization: Digest username="INERT_FIRST_VALUE", nonce="INERT_SECOND_VALUE"',
    'Proxy-Authorization: Basic INERT_FIRST_VALUE\n INERT_SECOND_VALUE',
    'UserSid=INERT_FIRST_VALUE | RemoteAddress=INERT_SECOND_VALUE',
    'key=INERT_FIRST_VALUE | user_name=INERT_SECOND_VALUE',
    'host_name=INERT_FIRST_VALUE | computer_name=INERT_SECOND_VALUE',
    'ImagePath="INERT_FIRST_VALUE" | CommandLine="INERT_SECOND_VALUE"',
    'postgresql://alice:INERT_FIRST_VALUE@database/INERT_SECOND_VALUE',
    'ssh://alice:INERT_FIRST_VALUE@server/INERT_SECOND_VALUE',
    'a://alice:INERT_FIRST_VALUE@singlehost/INERT_SECOND_VALUE',
])
def test_private_values_are_removed_as_whole_containers_and_header_context(captured_transport, text):
    preview = ai_consult.prepare_consultation(text, text, False)
    for private in ("INERT_FIRST_VALUE", "INERT_SECOND_VALUE"):
        assert private not in preview.prompt
        assert private not in preview.system
    assert "redacted" in preview.prompt.lower() or "[URL]" in preview.prompt
    assert privacy.prepare_consultation_text(preview.prompt, preview.system) == (preview.prompt, preview.system)
    result = ai_consult.consult_ai(text, text, False, approved_preview=preview)
    assert result["provider"] == "anthropic"
    assert _content(_payload(captured_transport.requests[0][0])) == (preview.prompt, preview.system)


@pytest.mark.parametrize("base", [
    "http://localhost.evil.test:11434", "http://203.0.113.8:11434",
    "http://user:INERT_PASSWORD_VALUE@localhost:11434",
    "http://localhost:11434?token=INERT_PASSWORD_VALUE", "http://localhost:11434/#secret",
    "http://localhost:11434/other", "http://localhost:0", "http://localhost:65536",
    "http://localhost:11434\n", "file://localhost:11434",
])
def test_invalid_local_destination_is_held_before_dns_or_request(captured_transport, monkeypatch, base):
    captured_transport.configured = set()
    monkeypatch.setattr(ai_consult, "OLLAMA_HOST", base)
    monkeypatch.setattr(ai_consult, "local_service_url", lambda *_a, **_k:
                        (_ for _ in ()).throw(AssertionError("must not resolve during preview")))
    monkeypatch.setattr(privacy.socket, "getaddrinfo", lambda *_a, **_k:
                        (_ for _ in ()).throw(AssertionError("preview must not perform DNS")))
    with pytest.raises(ValueError):
        ai_consult.prepare_consultation("Selected question")
    assert captured_transport.requests == []


@pytest.mark.parametrize("model", ["bad?token=INERT_PASSWORD_VALUE", "bad\nheader", "../other", "x" * 201])
def test_invalid_provider_model_cannot_enter_preview(captured_transport, monkeypatch, model):
    monkeypatch.setattr(ai_consult, "ANTHROPIC_MODEL", model)
    with pytest.raises(ValueError):
        ai_consult.prepare_consultation("Question", allow_local_fallback=False)
    assert captured_transport.requests == []


def test_preview_contains_only_private_one_way_credential_binding(captured_transport):
    preview = ai_consult.prepare_consultation("Selected question", allow_local_fallback=False)
    route = preview.destinations[0]
    assert len(route.credential_binding) == 32
    assert "INERT_PROVIDER_CREDENTIAL" not in repr(preview)
    assert "INERT_PROVIDER_CREDENTIAL" not in preview.payload_json()
    assert "credential_binding" not in preview.payload_json()
    captured_transport.keys["anthropic"] = "INERT_ROTATED_PROVIDER_CREDENTIAL"
    result = ai_consult.consult_ai("Selected question", allow_local_fallback=False,
                                   approved_preview=preview)
    assert result["provider"] is None
    assert "held" in result["error"]
    assert captured_transport.requests == []


@pytest.mark.parametrize("change", ["model", "key", "order"])
def test_configuration_change_during_first_request_holds_later_fallback(captured_transport, monkeypatch, change):
    captured_transport.configured = {"anthropic", "openai"}
    preview = ai_consult.prepare_consultation("Question", allow_local_fallback=False)
    original_capture = ai_consult.safe_urlopen

    def capture_and_change(request, **kwargs):
        response = original_capture(request, **kwargs)
        if change == "model":
            monkeypatch.setattr(ai_consult, "OPENAI_MODEL", "changed-model")
        elif change == "key":
            captured_transport.keys["openai"] = "INERT_ROTATED_KEY"
        else:
            monkeypatch.setenv("ANGERONA_AI_ORDER", "openai,anthropic")
        response._data = json.dumps({"content": []}).encode("utf-8")
        return response

    monkeypatch.setattr(ai_consult, "safe_urlopen", capture_and_change)
    result = ai_consult.consult_ai("Question", allow_local_fallback=False, approved_preview=preview)
    assert result["provider"] is None
    assert "held" in result["error"]
    assert len(captured_transport.requests) == 1


def test_adapter_uses_reviewed_route_even_if_model_global_changes_at_dispatch(captured_transport, monkeypatch):
    preview = ai_consult.prepare_consultation("Question", allow_local_fallback=False)
    route = preview.destinations[0]
    monkeypatch.setattr(ai_consult, "ANTHROPIC_MODEL", "changed-model")
    assert ai_consult._anthropic(preview.prompt, preview.system, route=route)
    assert _payload(captured_transport.requests[0][0])["model"] == route.model


def test_adapter_compares_exact_credential_used_in_header(captured_transport):
    preview = ai_consult.prepare_consultation("Question", allow_local_fallback=False)
    captured_transport.keys["anthropic"] = "INERT_ROTATED_KEY"
    with pytest.raises(ValueError):
        ai_consult._anthropic(preview.prompt, preview.system, route=preview.destinations[0])
    assert captured_transport.requests == []


def test_provider_exception_text_cannot_echo_credentials(captured_transport, monkeypatch):
    def fail(*_args, **_kwargs):
        raise RuntimeError("INERT_PASSWORD_VALUE INERT_PROVIDER_CREDENTIAL")

    monkeypatch.setattr(ai_consult, "safe_urlopen", fail)
    result = ai_consult.consult_ai("Question", allow_local_fallback=False)
    assert result["provider"] is None
    assert "RuntimeError" in result["error"]
    assert "INERT_PASSWORD_VALUE" not in result["error"]
    assert "INERT_PROVIDER_CREDENTIAL" not in result["error"]


def test_reject_revokes_unsent_preview_even_if_dialog_is_shown_again(app, captured_transport):
    dialog = ai_consult_dialog.AIConsultDialog("Inert reject", "Question", allow_local_fallback=False)
    try:
        assert dialog._pending_preview is not None
        dialog.reject()
        assert dialog._pending_preview is None
        assert dialog._closing
        dialog.show()
        dialog._send_reviewed()
        assert dialog._active_worker is None
        assert captured_transport.requests == []
    finally:
        dialog.close()


def test_followup_preserves_operator_removed_system_content(app, captured_transport):
    marker = "NONPATTERN_PRIVATE_SYSTEM_SENTINEL"
    dialog = ai_consult_dialog.AIConsultDialog("Inert system choice", "Question",
                                             system="Be concise. " + marker,
                                             allow_local_fallback=False)
    try:
        dialog._payload_preview.setPlainText(json.dumps({"prompt": "Question", "system": "Be concise."}))
        dialog._btn_review.click()
        dialog._btn_send_reviewed.click()
        _until(app, lambda: dialog._active_worker is None)
        dialog._prompt_input.setText("Follow up")
        dialog._send_btn.click()
        assert marker not in dialog._payload_preview.toPlainText()
        assert len(captured_transport.requests) == 1
        dialog._btn_send_reviewed.click()
        _until(app, lambda: dialog._active_worker is None)
        assert marker not in json.dumps(_payload(captured_transport.requests[1][0]))
    finally:
        dialog.close()


def test_done_is_gui_queued_and_cannot_reopen_admission_before_native_retirement(app, captured_transport, monkeypatch):
    released = threading.Event()
    completed = threading.Event()
    callback_threads = []
    original_worker = ai_consult_dialog.AIConsultWorker

    class HeldWorker(original_worker):
        def run(self):
            super().run()  # emits done inside this actual QThread
            completed.set()
            assert released.wait(5.0)

    class ObservedDialog(ai_consult_dialog.AIConsultDialog):
        def _on_done(self, *args):
            callback_threads.append(QThread.currentThread() is self.thread())
            super()._on_done(*args)

        def _retire_worker(self, worker):
            callback_threads.append(QThread.currentThread() is self.thread())
            super()._retire_worker(worker)

    monkeypatch.setattr(ai_consult_dialog, "AIConsultWorker", HeldWorker)
    dialog = ObservedDialog("Inert native retirement", "Question", allow_local_fallback=False)
    worker = None
    try:
        dialog._btn_send_reviewed.click()
        worker = dialog._active_worker
        _until(app, lambda: completed.is_set() and bool(callback_threads))
        assert worker.isRunning()
        assert not worker.wait(0)
        assert dialog._active_worker is worker
        assert not dialog._btn_send_reviewed.isEnabled()
        assert not dialog._btn_retry.isEnabled()
        released.set()
        _until(app, lambda: dialog._active_worker is None)
        assert len(callback_threads) >= 2 and all(callback_threads)
    finally:
        released.set()
        if worker is not None and shiboken6.isValid(worker):
            assert worker.wait(5_000)
        dialog.close()


def test_parent_destruction_cannot_destroy_inflight_consult(app, captured_transport, monkeypatch):
    entered, release = threading.Event(), threading.Event()
    original_capture = ai_consult.safe_urlopen

    def blocked(request, **kwargs):
        response = original_capture(request, **kwargs)
        entered.set()
        assert release.wait(5.0)
        return response

    monkeypatch.setattr(ai_consult, "safe_urlopen", blocked)
    parent = QWidget()
    dialog = ai_consult_dialog.AIConsultDialog("Inert parent lifetime", "Question", parent=parent,
                                             allow_local_fallback=False)
    worker = None
    try:
        dialog.show()
        dialog._btn_send_reviewed.click()
        worker = dialog._active_worker
        _until(app, entered.is_set)
        assert dialog.parent() is None
        assert ai_consult_dialog._RETAINED_CONSULTS[id(dialog)] is dialog
        parent.deleteLater()
        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
        app.processEvents()
        assert not shiboken6.isValid(parent)
        assert shiboken6.isValid(dialog)
        assert worker.isRunning()
        release.set()
        _until(app, lambda: dialog._active_worker is None)
        assert "advisory" in dialog._output.toPlainText().lower()
    finally:
        release.set()
        if worker is not None and shiboken6.isValid(worker):
            assert worker.wait(5_000)
        dialog.close()
        if shiboken6.isValid(parent):
            parent.close()


def test_worker_start_error_is_visible_and_retires_without_send(app, captured_transport, monkeypatch):
    def fail_start(_worker):
        raise RuntimeError("inert start failure")

    monkeypatch.setattr(ai_consult_dialog.AIConsultWorker, "start", fail_start)
    dialog = ai_consult_dialog.AIConsultDialog("Inert start failure", "Question", allow_local_fallback=False)
    try:
        dialog._btn_send_reviewed.click()
        _until(app, lambda: dialog._active_worker is None)
        assert "Worker start failed" in dialog._status.text()
        assert captured_transport.requests == []
        assert dialog._worker is None
    finally:
        dialog.close()


@pytest.mark.parametrize("text", [
    'password=<redacted:spoof>INERT_LOW_SECRET',
    'Authorization: <redacted:spoof> INERT_LOW_SECRET',
    'Cookie: <redacted:spoof>; custom=INERT_LOW_SECRET',
    'Authorization: "<redacted:spoof>"\n INERT_LOW_SECRET',
    'password="<redacted:spoof>"INERT_LOW_SECRET',
    'password="<redacted:spoof>" INERT_LOW_SECRET',
    'environment={"safe":"value"}INERT_LOW_SECRET',
])
def test_attacker_redaction_markers_do_not_authorize_private_tails(captured_transport, text):
    preview = ai_consult.prepare_consultation(text, text, False)
    assert "INERT_LOW_SECRET" not in preview.prompt
    assert "INERT_LOW_SECRET" not in preview.system
    assert "redacted" in preview.prompt.lower()
    assert privacy.prepare_consultation_text(preview.prompt, preview.system) == (preview.prompt, preview.system)
    result = ai_consult.consult_ai(text, text, False, approved_preview=preview)
    assert result["provider"] == "anthropic"
    assert "INERT_LOW_SECRET" not in captured_transport.requests[0][0].data.decode("utf-8")
