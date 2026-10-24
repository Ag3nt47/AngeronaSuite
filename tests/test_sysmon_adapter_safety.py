from types import SimpleNamespace
import sys

import pytest

from angerona.core.eventbus import Severity
from angerona.modules.sysmon_listener import SysmonListenerModule, _SYSMON_CHANNEL


def _module(tmp_path, monkeypatch):
    module = SysmonListenerModule(data_root=tmp_path, cursor_key=b'x' * 32)
    emitted = []
    monkeypatch.setattr(module, 'emit', lambda message, severity, **details:
                        emitted.append((message, severity, details)))
    return module, emitted


def _record(payload=None, provider='Microsoft-Windows-Sysmon', eid=10):
    return SimpleNamespace(RecordNumber=1, SourceName=provider, EventID=eid,
                           StringInserts=None if payload is None else [payload])


def _backend(monkeypatch, *, provider='Microsoft-Windows-Sysmon', native_error=None,
             classic_error=None, count=1):
    calls = []
    handle = object()
    class Probe:
        def Close(self):
            calls.append('probe-close')
    def query(channel, flags, expression):
        calls.append(('query', channel, flags, expression))
        if native_error:
            raise native_error
        return Probe()
    def open_log(server, channel):
        calls.append(('classic-open', server, channel))
        if classic_error:
            raise classic_error
        return handle
    backend = SimpleNamespace(
        EvtQuery=query, EvtQueryChannelPath=1, EvtQueryForwardDirection=256,
        OpenEventLog=open_log, CloseEventLog=lambda h: calls.append(('classic-close', h)),
        GetNumberOfEventLogRecords=lambda h: count,
        GetOldestEventLogRecord=lambda h: 1,
        ReadEventLog=lambda h, flags, offset, size: [_record(provider=provider)],
    )
    monkeypatch.setitem(sys.modules, 'win32evtlog', backend)
    return backend, calls, handle


def _assert_coverage(emitted, error_class, observed=None):
    message, severity, details = emitted[-1]
    assert severity == Severity.MEDIUM
    assert details['disposition'] == 'health'
    assert details['active_attack'] is False
    assert details['response_authorized'] is False
    assert details['response_authority'] == 'observe-only'
    assert details['coverage_state'] == 'unavailable'
    assert details['error_type'] == error_class
    assert 'response_contract' not in details
    assert 'ProcessAccess' not in message
    if observed:
        assert details['eid'] == 10 and details['observed_severity'] == observed


def test_missing_native_channel_never_opens_classic_application_fallback(tmp_path, monkeypatch):
    module, emitted = _module(tmp_path, monkeypatch)
    _backend(monkeypatch, native_error=OSError(15007, 'untrusted native text'))
    assert module._try_open_sysmon() is False
    assert module._evtlog_handle is None and module._using_fallback
    _assert_coverage(emitted, 'NativeChannelUnavailable')
    assert 'untrusted native text' not in repr(emitted)
    assert not module._cursor_path.exists()


def test_native_channel_probe_does_not_authorize_foreign_classic_records(tmp_path, monkeypatch):
    module, emitted = _module(tmp_path, monkeypatch)
    _api, calls, handle = _backend(monkeypatch, provider='Microsoft-Windows-AppModel-State')
    assert module._try_open_sysmon() is False
    assert 'probe-close' in calls and ('classic-close', handle) in calls
    assert module._evtlog_handle is None
    _assert_coverage(emitted, 'ProviderMismatch')
    assert not module._cursor_path.exists()


def test_native_probe_is_closed_when_classic_open_fails(tmp_path, monkeypatch):
    module, emitted = _module(tmp_path, monkeypatch)
    _api, calls, _handle = _backend(monkeypatch, classic_error=PermissionError('raw payload'))
    assert module._try_open_sysmon() is False
    assert calls.count('probe-close') == 1
    _assert_coverage(emitted, 'ClassicChannelUnavailable')
    assert 'raw payload' not in repr(emitted)


def test_verified_native_channel_and_classic_provider_allow_continuity_setup(tmp_path, monkeypatch):
    module, emitted = _module(tmp_path, monkeypatch)
    _api, calls, handle = _backend(monkeypatch)
    assert module._try_open_sysmon() is True
    assert module._evtlog_handle is handle and module._using_fallback is False
    assert calls[0] == ('query', _SYSMON_CHANNEL, 257, '*')
    assert emitted[-1][1] == Severity.INFO
    module._close_sysmon()
    assert module._evtlog_handle is None and ('classic-close', handle) in calls


def test_foreign_provider_is_rejected_before_reading_event_id(tmp_path, monkeypatch):
    module, emitted = _module(tmp_path, monkeypatch)
    class Foreign:
        SourceName = 'Microsoft-Windows-AppModel-State'
        @property
        def EventID(self):
            pytest.fail('foreign event was given Sysmon semantics')
    module._process_record(Foreign())
    _assert_coverage(emitted, 'ProviderMismatch')
    assert module._parse_rejection_count == 1
    assert 'eid' not in emitted[-1][2]


@pytest.mark.parametrize('provider', [None, '', 'Sysmon', 'Microsoft-Windows-Sysmon-extra', 42])
def test_missing_or_ambiguous_provider_cannot_become_critical(tmp_path, monkeypatch, provider):
    module, emitted = _module(tmp_path, monkeypatch)
    module._process_record(_record('untrusted non-XML data', provider=provider))
    _assert_coverage(emitted, 'ProviderMismatch')


@pytest.mark.parametrize('payload,error_class', [
    ('non XML native insertion string', 'XmlParseError'),
    (None, 'XmlMissing'), ('', 'XmlMissing'), (4, 'XmlMissing'),
    ('x' * (1024 * 1024 + 1), 'XmlOversized'),
    ('<!DOCTYPE Event [<!ENTITY probe SYSTEM "file:///inert-must-not-open">]><Event>&probe;</Event>', 'XmlUnsafe'),
], ids=['malformed', 'missing', 'empty', 'non-string', 'oversized', 'external-entity'])
def test_unparsed_genuine_sysmon_critical_is_explicit_unavailable_coverage(tmp_path, monkeypatch, payload, error_class):
    module, emitted = _module(tmp_path, monkeypatch)
    module._process_record(_record(payload))
    _assert_coverage(emitted, error_class, 'CRITICAL')
    assert module._parse_rejection_count == 1
    assert 'untrusted' not in repr(emitted) and 'file:///' not in repr(emitted)
    assert not module._cursor_path.exists()


def test_valid_parsed_sysmon_keeps_severity_and_exact_observation_fields(tmp_path, monkeypatch):
    module, emitted = _module(tmp_path, monkeypatch)
    xml = ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><EventData>'
           '<Data Name="SourceImage">C:\\inert\\source.exe</Data>'
           '<Data Name="SourceProcessId">123</Data>'
           '<Data Name="TargetImage">C:\\inert\\target.exe</Data>'
           '<Data Name="TargetProcessId">456</Data>'
           '<Data Name="GrantedAccess">0x10</Data></EventData></Event>')
    module._process_record(_record(xml))
    message, severity, details = emitted[-1]
    assert severity == Severity.CRITICAL and message.startswith('ProcessAccess:')
    assert details['source_pid'] == '123' and details['target_pid'] == '456'
    assert details['granted_access'] == '0x10'
    assert details['response_authorized'] is False and details['raw_sensor_evidence'] is True
    assert 'response_contract' not in details and module._parse_rejection_count == 0


def test_reopen_failure_uses_verified_opener_and_truthful_fallback(tmp_path, monkeypatch):
    module, emitted = _module(tmp_path, monkeypatch)
    _backend(monkeypatch)
    calls = []
    def failed_read(_backend):
        raise OSError('inert read failure')
    monkeypatch.setattr(module, '_reseek_and_drain', failed_read)
    monkeypatch.setattr(module, '_try_open_sysmon', lambda: calls.append('verified-open') or False)
    monkeypatch.setattr(module, '_run_fallback_loop', lambda: calls.append('fallback'))
    module._run_sysmon_loop()
    assert calls == ['verified-open', 'fallback']


def test_run_retires_owned_native_handle_even_when_loop_raises(tmp_path, monkeypatch):
    module, emitted = _module(tmp_path, monkeypatch)
    _api, calls, handle = _backend(monkeypatch)
    def fail():
        raise RuntimeError('inert worker failure')
    monkeypatch.setattr(module, '_run_sysmon_loop', fail)
    with pytest.raises(RuntimeError, match='inert worker failure'):
        module.run()
    assert module._evtlog_handle is None and calls.count(('classic-close', handle)) == 1
