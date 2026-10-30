"""Owned enrollment worker with inert secure-store functions only."""
from __future__ import annotations

from dataclasses import FrozenInstanceError
from pathlib import Path
import threading

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from angerona.core import recorder_enrollment as enrollment
from angerona.core import recorder_integrity


@pytest.fixture
def public_key():
    return Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")


@pytest.fixture(autouse=True)
def no_operator_store(monkeypatch):
    def forbidden(_root):
        raise AssertionError("Unexpected operator secure-store access")
    monkeypatch.setattr(recorder_integrity, "provision_host_identity", forbidden)
    # All owners in these replaced registries are test fixtures with exact
    # cleanup in each case; no real runtime/store object is cleared.
    monkeypatch.setattr(enrollment, "_LIVE_OWNERS", [])
    monkeypatch.setattr(enrollment, "_RETIREMENT_HOLDS", [])


def join_body(owner):
    assert owner._retired.wait(3)
    owner._thread.join(3)
    assert not owner._thread.is_alive()


def test_constructor_and_immutable_status_never_read_store(tmp_path):
    owner = enrollment.RecorderEnrollmentOwner(tmp_path)
    status = owner.latest_status()
    assert status == enrollment.RecorderEnrollmentStatus()
    assert owner._thread is None and not list(tmp_path.iterdir())
    with pytest.raises(FrozenInstanceError):
        status.state = "ready"
    assert owner.stop() and owner.latest_status().state == "stopped"


def test_explicit_non_daemon_worker_returns_only_public_identity_and_reuses_key(monkeypatch, tmp_path, public_key):
    calls = []
    def provision(root):
        calls.append((root, threading.current_thread(), threading.current_thread().daemon))
        return public_key
    monkeypatch.setattr(recorder_integrity, "provision_host_identity", provision)
    owner = enrollment.RecorderEnrollmentOwner(tmp_path)
    assert owner.request()
    join_body(owner)
    status = owner.latest_status()
    assert status.state == "ready" and status.public_key == public_key and status.error == "" and status.revision >= 2
    assert calls[0][0] == Path(tmp_path) and calls[0][1] is owner._thread and calls[0][2] is False
    assert calls[0][1] is not threading.current_thread()
    thread = owner._thread
    assert owner.request() and owner._thread is thread and len(calls) == 1
    assert owner.stop() and owner.latest_status().public_key == public_key


def test_no_duplicate_worker_while_provisioning_is_blocked(monkeypatch, tmp_path, public_key):
    entered, finish = threading.Event(), threading.Event()
    calls = []
    def provision(_root):
        calls.append(1)
        entered.set()
        assert finish.wait(3)
        return public_key
    monkeypatch.setattr(recorder_integrity, "provision_host_identity", provision)
    owner = enrollment.RecorderEnrollmentOwner(tmp_path)
    try:
        assert owner.request() and entered.wait(2)
        thread = owner._thread
        assert not owner.request() and owner._thread is thread
        assert owner.latest_status().state == "running" and calls == [1]
    finally:
        finish.set()
        assert owner.stop(3)


def test_failed_worker_can_retry_only_after_exact_retirement(monkeypatch, tmp_path, public_key):
    calls = []
    def provision(_root):
        calls.append(1)
        if len(calls) == 1:
            raise OSError("PRIVATE-SECRET should never be in public status")
        return public_key  # model get-or-create returning the same stored identity
    monkeypatch.setattr(recorder_integrity, "provision_host_identity", provision)
    owner = enrollment.RecorderEnrollmentOwner(tmp_path)
    assert owner.request()
    join_body(owner)
    prior = owner._thread
    status = owner.latest_status()
    assert status.state == "unavailable" and "PRIVATE-SECRET" not in status.error and not status.public_key
    assert owner.request()
    join_body(owner)
    assert owner._thread is not prior and owner.latest_status().public_key == public_key and len(calls) == 2
    assert owner.stop()


@pytest.mark.parametrize("bad", ["private-pem", "oversized", "arbitrary", "non-ascii", "object"])
def test_unexpected_or_private_results_are_never_published(monkeypatch, tmp_path, bad):
    private = Ed25519PrivateKey.generate().private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode("ascii")
    value = private if bad == "private-pem" else "x" * 2049 if bad == "oversized" else "untrusted result" if bad == "arbitrary" else "\N{SNOWMAN}" if bad == "non-ascii" else object()
    monkeypatch.setattr(recorder_integrity, "provision_host_identity", lambda _root: value)
    owner = enrollment.RecorderEnrollmentOwner(tmp_path)
    assert owner.request()
    join_body(owner)
    status = owner.latest_status()
    assert status.state == "unavailable" and status.public_key == "" and len(status.error) <= 2048
    assert "PRIVATE KEY" not in status.error and "untrusted result" not in status.error
    assert owner.stop()


def test_stop_before_request_fences_all_future_work(tmp_path):
    owner = enrollment.RecorderEnrollmentOwner(tmp_path)
    owner.request_stop()
    assert not owner.request() and owner._thread is None
    assert owner.stop() and owner.latest_status().state == "stopped"


def test_queued_native_worker_observes_stop_before_store_admission(monkeypatch, tmp_path, public_key):
    real_thread = threading.Thread
    entered, finish = threading.Event(), threading.Event()
    calls = []
    def factory(*, target, **kwargs):
        def queued():
            entered.set()
            assert finish.wait(3)
            target()
        return real_thread(target=queued, **kwargs)
    monkeypatch.setattr(enrollment.threading, "Thread", factory)
    monkeypatch.setattr(recorder_integrity, "provision_host_identity", lambda _root: calls.append(1) or public_key)
    owner = enrollment.RecorderEnrollmentOwner(tmp_path)
    try:
        assert owner.request() and entered.wait(2)
        owner.request_stop()
    finally:
        finish.set()
        assert owner.stop(3)
    assert calls == [] and owner.latest_status().state == "stopped"


def test_admitted_store_call_drains_and_timeout_retains_exact_owner(monkeypatch, tmp_path, public_key):
    entered, finish = threading.Event(), threading.Event()
    def provision(_root):
        entered.set()
        assert finish.wait(3)
        return public_key
    monkeypatch.setattr(recorder_integrity, "provision_host_identity", provision)
    owner = enrollment.RecorderEnrollmentOwner(tmp_path)
    try:
        assert owner.request() and entered.wait(2)
        assert not owner.stop(0)
        assert owner.latest_status().state == "retirement-held"
        assert enrollment._LIVE_OWNERS == enrollment._RETIREMENT_HOLDS == [owner]
        other = enrollment.RecorderEnrollmentOwner(tmp_path)
        assert not other.request() and other._thread is None
        assert not owner.request()
    finally:
        finish.set()
        assert owner.stop(3)
    assert owner.latest_status().state == "stopped" and owner.latest_status().public_key == public_key
    assert not enrollment._LIVE_OWNERS and not enrollment._RETIREMENT_HOLDS
    assert not owner.request()


def test_uncertain_start_with_late_bootstrap_is_sticky_even_ident_none(monkeypatch, tmp_path, public_key):
    real_thread = threading.Thread
    entered, finish = threading.Event(), threading.Event()
    calls = []
    class UnpublishedThread:
        ident = None
        def __init__(self, *, target, **kwargs):
            def late():
                entered.set()
                assert finish.wait(3)
                target()
            self.actual = real_thread(target=late, **kwargs)
        def start(self):
            self.actual.start()
            assert entered.wait(2)
            raise RuntimeError("simulated unpublished native admission")
        def is_alive(self):
            return False  # intentionally untrustworthy until ident is published
        def join(self, _timeout):
            raise AssertionError("No join proof exists for unpublished bootstrap")
    monkeypatch.setattr(enrollment.threading, "Thread", UnpublishedThread)
    monkeypatch.setattr(recorder_integrity, "provision_host_identity", lambda _root: calls.append(1) or public_key)
    owner = enrollment.RecorderEnrollmentOwner(tmp_path)
    try:
        assert not owner.request() and entered.wait(2)
        assert owner._thread.ident is None and not owner._thread.is_alive()
        assert not owner.stop(0)
        assert enrollment._RETIREMENT_HOLDS == [owner]
        assert not enrollment.RecorderEnrollmentOwner(tmp_path).request()
    finally:
        finish.set()
        owner._thread.actual.join(3)
        assert not owner._thread.actual.is_alive()
    assert calls == [] and owner._retired.is_set()
    assert not owner.stop(3) and not owner.request()
    assert owner.latest_status().state == "retirement-held" and enrollment._LIVE_OWNERS == [owner]


def test_join_failure_never_becomes_clean_from_dead_thread_snapshot(monkeypatch, tmp_path, public_key):
    monkeypatch.setattr(recorder_integrity, "provision_host_identity", lambda _root: public_key)
    owner = enrollment.RecorderEnrollmentOwner(tmp_path)
    assert owner.request()
    join_body(owner)
    def uncertain_join(_timeout):
        raise RuntimeError("simulated join uncertainty with secret text")
    monkeypatch.setattr(owner._thread, "join", uncertain_join)
    assert not owner.stop() and not owner.stop()
    assert owner.latest_status().state == "retirement-held" and "secret text" not in owner.latest_status().error
    assert enrollment._RETIREMENT_HOLDS == [owner] and not owner.request()


def test_worker_construction_failure_is_retryable_without_native_admission(monkeypatch, tmp_path, public_key):
    real_thread = threading.Thread
    def failed(**_kwargs):
        raise RuntimeError("simulated memory-only worker allocation failure")
    monkeypatch.setattr(enrollment.threading, "Thread", failed)
    monkeypatch.setattr(recorder_integrity, "provision_host_identity", lambda _root: public_key)
    owner = enrollment.RecorderEnrollmentOwner(tmp_path)
    assert not owner.request() and owner.latest_status().state == "unavailable"
    assert owner._thread is None and not enrollment._LIVE_OWNERS and not enrollment._RETIREMENT_HOLDS
    monkeypatch.setattr(enrollment.threading, "Thread", real_thread)
    assert owner.request()
    join_body(owner)
    assert owner.stop()


def test_completed_status_remains_snapshot_when_stop_changes_owner(monkeypatch, tmp_path, public_key):
    monkeypatch.setattr(recorder_integrity, "provision_host_identity", lambda _root: public_key)
    owner = enrollment.RecorderEnrollmentOwner(tmp_path)
    assert owner.request()
    join_body(owner)
    ready = owner.latest_status()
    assert owner.stop()
    stopped = owner.latest_status()
    assert ready.state == "ready" and stopped.state == "stopped" and stopped.revision > ready.revision
