"""Tool mentions stay visible without waking Chill or authorizing response."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from angerona.core.chill_mode import ChillPolicy
from angerona.core.eventbus import Event, EventBus, Severity
from angerona.core.threat import active_threat_events, event_disposition, threat_level
from angerona.modules import lsass_guard, shadowcopy_guard
from angerona.modules.adversary_combat import AdversaryCombat


def _detector_event(monkeypatch, tmp_path, detector, *, exact=False, birth=1234.5):
    if detector == 'lsass':
        provider, module = lsass_guard, lsass_guard.LsassGuardModule()
        name = 'procdump64.exe' if exact else 'python.exe'
        argv = ([name, '-ma', 'lsass.exe', 'out.dmp'] if exact else
                [name, '-c', "print('mimikatz lsass.dmp')"])
    else:
        provider, module = shadowcopy_guard, shadowcopy_guard.ShadowCopyGuardModule()
        name = 'vssadmin.exe' if exact else 'cmd.exe'
        argv = ([name, 'delete', 'shadows', '/all'] if exact else
                [name, '/c', 'echo vssadmin delete shadows /all'])
        # The native signature/path boundary is fixture-controlled; the real
        # destructive-argv parser and complete detector loop still execute.
        monkeypatch.setattr(provider, '_trusted_system_utility', lambda proc_name, _exe: (
            'vssadmin.exe' if proc_name == 'vssadmin.exe' else None
        ))
    process = SimpleNamespace(info={
        'pid': 54321, 'name': name, 'exe': str(tmp_path / name),
        'cmdline': argv, 'create_time': birth,
    })
    monkeypatch.setattr(provider, 'psutil', SimpleNamespace(
        process_iter=lambda _attrs: [process],
        Process=lambda _pid: SimpleNamespace(ppid=lambda: 43210),
    ))
    bus = EventBus()
    module.bind(bus)
    monkeypatch.setattr(module, 'sleep', lambda _seconds: module.stop())
    module.run()
    events = [event for event in bus.recent(10) if event.severity == Severity.CRITICAL]
    assert len(events) == 1
    return module, events[0]


def _chill_transition(event):
    policy = ChillPolicy()
    policy.enable()
    transition = policy.observe_active(active_threat_events([event]))
    return policy, transition


@pytest.mark.parametrize('detector', ['lsass', 'shadowcopy'])
def test_tool_text_is_visible_observation_without_chill_wake_or_response(monkeypatch, tmp_path, detector):
    module, event = _detector_event(monkeypatch, tmp_path, detector)
    assert event.severity == Severity.CRITICAL
    assert event.details['cmdline']
    assert 'credential' in event.message or 'RANSOMWARE PRECURSOR' in event.message
    assert event.details['detector_policy'] == 'semantic-indicator-alert-only'
    assert event.details['active_attack'] is False
    assert event.details['response_authorized'] is False
    assert 'response_contract' not in event.details
    assert event_disposition(event) == 'observation'
    assert threat_level([event]) == Severity.INFO
    policy, transition = _chill_transition(event)
    assert transition is None
    assert not policy.escalated and policy.awake_until == 0
    assert AdversaryCombat._response_actions(event) is None
    assert module._last_coverage['readable'] == 1
    assert module._detections == 1


@pytest.mark.parametrize('detector', ['lsass', 'shadowcopy'])
def test_exact_dangerous_command_retains_threat_wake_and_typed_response(monkeypatch, tmp_path, detector):
    _module, event = _detector_event(monkeypatch, tmp_path, detector, exact=True)
    assert event.severity == Severity.CRITICAL
    assert event.details['active_attack'] is True
    assert event.details['response_authorized'] is True
    assert event_disposition(event) == 'active'
    assert threat_level([event]) == Severity.CRITICAL
    policy, transition = _chill_transition(event)
    assert transition.action == 'escalate'
    assert policy.escalated
    actions = AdversaryCombat._response_actions(event)
    assert {'suspend_process', 'terminate_process', 'activate_honeypots'} <= actions
    assert ('isolate_host' in actions) is (detector == 'shadowcopy')
    targets = event.details['response_contract']['targets']
    assert targets['pid'] == 54321 and targets['process_create_time'] == 1234.5


@pytest.mark.parametrize('detector', ['lsass', 'shadowcopy'])
def test_exact_command_missing_process_birth_stays_active_without_response(monkeypatch, tmp_path, detector):
    module, event = _detector_event(monkeypatch, tmp_path, detector, exact=True, birth=None)
    assert event.details['active_attack'] is True
    assert event.details['detector_policy'].startswith('exact-')
    assert event.details['response_authorized'] is False
    assert 'response_contract' not in event.details
    assert event_disposition(event) == 'active'
    policy, transition = _chill_transition(event)
    assert transition.action == 'escalate' and policy.escalated
    assert AdversaryCombat._response_actions(event) is None
    assert module.health == 70
    assert module._last_coverage['identity_incomplete'] == 1


@pytest.mark.parametrize('module', [lsass_guard.LsassGuardModule.name, shadowcopy_guard.ShadowCopyGuardModule.name])
def test_old_semantic_indicator_history_does_not_keep_chill_awake(module):
    event = Event(module, 'Historical textual indicator retained', Severity.CRITICAL, details={
        'active_attack': True, 'detector_policy': 'semantic-indicator-alert-only',
        'pid': 54321, 'process_create_time': 1234.5,
    })
    assert event_disposition(event) == 'observation'
    assert event.severity == Severity.CRITICAL
    assert event.details['active_attack'] is True  # Evidence itself is untouched.
    policy, transition = _chill_transition(event)
    assert transition is None and not policy.escalated


@pytest.mark.parametrize('changes', [
    {'active_exploitation': True},
    {'threat_intel_corroborated': True},
    {'entropy_corroborated': True},
    {'response_authorized': True},
    {'response_contract': {}},
    {'detector_policy': 'exact-tool-lsass-dump'},
    {'detector_policy': 'semantic-indicator-alert-only-new-policy'},
    {'process_create_time': None},
    {'process_create_time': float('nan')},
    {'process_create_time': '1234.5'},
    {'pid': True},
])
def test_legacy_rule_does_not_demote_independent_or_other_policy_evidence(changes):
    event = Event(lsass_guard.LsassGuardModule.name, 'Independent evidence', Severity.CRITICAL, details={
        'active_attack': True, 'detector_policy': 'semantic-indicator-alert-only',
        'pid': 54321, 'process_create_time': 1234.5, **changes,
    })
    assert event_disposition(event) == 'active'


@pytest.mark.parametrize('module', ['Other Detector', 'LSASS Credential-Access Guard copy'])
def test_other_producers_without_response_authority_are_not_globally_demoted(module):
    event = Event(module, 'Independent finding', Severity.CRITICAL, details={
        'response_authorized': False, 'detector_policy': 'semantic-indicator-alert-only',
    })
    assert event_disposition(event) == 'active'


@pytest.fixture(autouse=True)
def _shared_process_evidence(monkeypatch):
    # Existing detector-policy fixtures control process rows. Exercise the
    # detector through its shared-snapshot seam; sensor collection has its own
    # concurrency, loss and PID-reuse tests.
    from angerona.telemetry.sensors import ProcessSnapshot
    from angerona.modules import lsass_guard, shadowcopy_guard

    for provider in (lsass_guard, shadowcopy_guard,):
        def snapshot(*_args, _provider=provider, **_kwargs):
            rows = tuple(item.info for item in _provider.psutil.process_iter([]))
            return ProcessSnapshot(rows, 1.0, True, len(rows), 0)
        monkeypatch.setattr(provider, "process_snapshot", snapshot)
