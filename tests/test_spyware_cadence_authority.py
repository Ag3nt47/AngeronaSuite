from types import SimpleNamespace
import pytest
from angerona.core.eventbus import BusAuthority,Event,EventBus,Severity
from angerona.core.response_contract import process_and_remote_response
from angerona.core.threat import event_disposition,is_active_threat
from angerona.modules.adversary_combat import AdversaryCombat
from angerona.modules.spyware_guard import SpywareGuardModule
from angerona.telemetry.sensors import ProcessSnapshot,ConnectionSnapshot

NOW=1800000000.0
def module_bus():
    module=SpywareGuardModule(clock=lambda:NOW,
        persistence_collector=lambda **kw:{'findings':[],'coverage':{}},
        process_observer=lambda:ProcessSnapshot((),NOW,True,0,0),
        connection_observer=lambda:ConnectionSnapshot((),NOW,True,0,0))
    bus=EventBus();bus.arm(BusAuthority(b'c'*32));module.bind(bus)
    return module,bus

@pytest.mark.parametrize('birth',[NOW-10,None])
@pytest.mark.parametrize('policy',[None,'cadence-indicator-alert-only','unknown-policy'])
def test_cadence_cannot_gain_process_peer_or_host_response(birth,policy):
    module,bus=module_bus()
    source=Event('C2 Beacon Detector','regular connection timing',Severity.MEDIUM,NOW,{
        'pid':45001,'process_create_time':birth,'remote':'8.8.8.8',
        'detector_policy':policy,'threat_intel_corroborated':False,
        'active_attack':False,'disposition':'observation'})
    bus.publish(source)
    source=bus.recent(1)[0]
    module._consume_events()
    event,=[e for e in bus.recent(10) if e.module==module.name]
    assert bus.verify(event) and event.details['evidence']['source_event_digest']==source.hmac_sig
    assert event_disposition(event)=='exposure' and not is_active_threat(event)
    assert event.details['response_authorized'] is False
    assert event.details['response_eligible'] is False
    assert 'response_contract' not in event.details
    assert AdversaryCombat._response_actions(event) is None
    assert not event.details.get('single_rule_host_fallback')
    assert module.dashboard_snapshot()['hits'][0]['response_requested'] is False

def test_conflicting_response_hints_cannot_override_alert_only_producer_policy():
    module,bus=module_bus()
    source=Event('C2 Beacon Detector','regular connection timing',Severity.HIGH,NOW,{
        'pid':45001,'process_create_time':NOW-10,'remote':'8.8.8.8',
        'detector_policy':'cadence-indicator-alert-only','threat_intel_corroborated':False,
        'active_attack':True,'single_rule_host_fallback':True,
        **process_and_remote_response(45001,NOW-10,'8.8.8.8')})
    bus.publish(source)
    source=bus.recent(1)[0]
    module._consume_events()
    event,=[e for e in bus.recent(10) if e.module==module.name]
    assert event_disposition(event)=='exposure'
    assert event.details['response_authorized'] is False
    assert 'response_contract' not in event.details
    assert not event.details.get('single_rule_host_fallback')
    assert not module.dashboard_snapshot()['hits'][0]['response_requested']

def test_corroborated_existing_upstream_response_remains_automatic_single_owner():
    module,bus=module_bus()
    source=Event('C2 Beacon Detector','corroborated timing and IOC',Severity.HIGH,NOW,{
        'pid':45001,'process_create_time':NOW-10,'remote':'8.8.8.8',
        'remote_ip':'8.8.8.8',
        'detector_policy':'cadence-plus-threat-intel','threat_intel_corroborated':True,
        'active_attack':True,'disposition':'active',
        **process_and_remote_response(45001,NOW-10,'8.8.8.8')})
    bus.publish(source)
    source=bus.recent(1)[0]
    module._consume_events()
    assert bus.verify(source) and AdversaryCombat._response_actions(source) is not None
    event,=[e for e in bus.recent(10) if e.module==module.name]
    assert event.details['response_authorized'] is False
    assert 'response_contract' not in event.details
    assert module.dashboard_snapshot()['hits'][0]['status']=='upstream-response-requested'

def test_corroborated_legacy_peer_adapter_retains_automatic_response():
    module,bus=module_bus()
    bus.publish(Event('C2 Beacon Detector','corroborated timing and IOC',Severity.HIGH,NOW,{
        'pid':45001,'process_create_time':NOW-10,'remote':'8.8.8.8',
        'detector_policy':'cadence-plus-threat-intel','threat_intel_corroborated':True,
        'active_attack':True,'disposition':'active',
        **process_and_remote_response(45001,NOW-10,'8.8.8.8')}))
    module._consume_events()
    event,=[e for e in bus.recent(10) if e.module==module.name]
    assert bus.verify(event) and AdversaryCombat._response_actions(event) is not None
    assert event.details['response_authorized'] is True
    assert 'terminate_process' in event.details['response_contract']['actions']

def test_direct_cadence_finding_cannot_acquire_host_fallback_or_peer_authority():
    module,_=module_bus()
    finding={'kind':'sensor_c2_beacon_detector','detector_policy':'cadence-indicator-alert-only',
        'threat_intel_corroborated':False,'response_eligible':True,
        'pid':45001,'process_create_time':NOW-10,'remote_ip':'8.8.8.8',
        'single_rule_host_fallback':True}
    assert module._response(finding,True)=={}
    finding.pop('pid');finding.pop('process_create_time');finding.pop('remote_ip')
    assert module._response(finding,True)=={}
