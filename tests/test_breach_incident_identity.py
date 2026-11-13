"""Inert mesh-only incident identity regressions; no response actions execute."""
import pytest
from angerona.core import breach_state as breach
from angerona.core.response_contract import authorize_response
from test_breach_state import native_graph, emit


def host_incident(graph, **changes):
    return emit(graph, finding_code=None, event_type="ugcap_divergence", pid=None,
                process_create_time=None, response_contract=authorize_response(
                    ["isolate_host"], local_host=True)["response_contract"], **changes)


def test_ugcap_report_identity_survives_repeats_but_next_report_is_new_case(tmp_path):
    with native_graph(tmp_path) as graph:
        first = breach.verified_breach(host_incident(graph, report_id="a" * 32), graph.bus, graph.manager.modules)
        repeated = breach.verified_breach(host_incident(graph, report_id="a" * 32, message="reworded"), graph.bus, graph.manager.modules)
        next_case = breach.verified_breach(host_incident(graph, report_id="b" * 32), graph.bus, graph.manager.modules)
        assert first is not None and repeated is not None and next_case is not None
        assert first.case_id == repeated.case_id
        assert first.case_id != next_case.case_id
        graph.config.breach_lifted_cases = [first.case_id]
        assert graph.combat._breach_is_lifted(first.case_id)
        assert not graph.combat._breach_is_lifted(next_case.case_id)


@pytest.mark.parametrize("report_id", [None, "", 7, "x" * 129, "bad\nidentifier"])
def test_host_only_breach_without_valid_incident_identity_is_held(tmp_path, report_id):
    with native_graph(tmp_path) as graph:
        event = host_incident(graph, report_id=report_id)
        assert breach.verified_breach(event, graph.bus, graph.manager.modules) is None


def test_existing_exact_process_identity_still_has_stable_case_without_report(tmp_path):
    with native_graph(tmp_path) as graph:
        first = breach.verified_breach(emit(graph), graph.bus, graph.manager.modules)
        repeat = breach.verified_breach(emit(graph, message="repeat"), graph.bus, graph.manager.modules)
        assert first is not None and repeat is not None
        assert first.case_id == repeat.case_id
