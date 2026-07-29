import pytest

from angerona.core.ai_security_broker import (
    AIMode, AIRequest, AISecurityBroker, EgressDecision, ModelProvenance,
)


LOCAL = ModelProvenance("ollama", "local-model", "1", local=True)


def request(mode=AIMode.EXPLAIN):
    return AIRequest("r1", mode, "Explain this alert", ("ev-1",), LOCAL)


def valid_output(**extra):
    value = {
        "confidence": 80, "abstained": False, "abstention_reason": "",
        "conclusions": [{"text": "Suspicious behavior", "evidence_ids": ["ev-1"]}],
    }
    value.update(extra)
    return value


def test_cloud_requires_explicit_egress_decision():
    cloud = ModelProvenance("vendor", "model", "2026", local=False)
    with pytest.raises(ValueError, match="egress"):
        AIRequest("r", AIMode.EXPLAIN, "x", (), cloud)
    allowed = AIRequest(
        "r", AIMode.EXPLAIN, "x", (), cloud,
        EgressDecision(True, True, "operator chose cloud analysis"),
    )
    assert not allowed.provenance.local


def test_conclusions_require_known_evidence_and_confidence_contract():
    broker = AISecurityBroker()
    response = broker.validate(request(), valid_output())
    assert response.confidence == 80
    with pytest.raises(ValueError, match="unknown evidence"):
        broker.validate(request(), valid_output(conclusions=[
            {"text": "claim", "evidence_ids": ["invented"]}
        ]))
    with pytest.raises(ValueError, match="confidence"):
        broker.validate(request(), valid_output(confidence=0.8))


def test_abstention_requires_reason_and_allows_no_conclusion():
    broker = AISecurityBroker()
    result = broker.validate(request(), {
        "confidence": 20, "abstained": True,
        "abstention_reason": "insufficient evidence", "conclusions": [],
    })
    assert result.abstained
    with pytest.raises(ValueError, match="reason"):
        broker.validate(request(), {
            "confidence": 20, "abstained": True,
            "abstention_reason": "", "conclusions": [],
        })


def test_execute_only_registered_typed_tools_and_is_disabled_by_default():
    broker = AISecurityBroker()
    broker.register_tool(
        "isolate_target", validators={"target": lambda value: str(value)},
        handler=lambda target: {"isolated": target},
    )
    response = broker.validate(request(AIMode.EXECUTE), valid_output(
        tool_name="isolate_target", tool_arguments={"target": "host-1"}
    ))
    with pytest.raises(PermissionError, match="disabled"):
        broker.execute(response)
    with pytest.raises(ValueError, match="registered"):
        broker.validate(request(AIMode.EXECUTE), valid_output(
            tool_name="raw_shell", tool_arguments={"command": "whoami"}
        ))
    with pytest.raises(ValueError, match="forbidden"):
        broker.register_tool(
            "powershell_runner", validators={"x": str}, handler=lambda x: x
        )


def test_enabled_execution_and_canonical_receipt():
    broker = AISecurityBroker(execution_enabled=True)
    broker.register_tool(
        "collect_fact", validators={"pid": lambda value: int(value)},
        handler=lambda pid: {"pid": pid},
    )
    req = request(AIMode.EXECUTE)
    response = broker.validate(req, valid_output(
        tool_name="collect_fact", tool_arguments={"pid": "42"}
    ))
    executed = broker.execute(response)
    assert executed.tool_executed
    assert executed.tool_result == {"pid": 42}
    one = broker.receipt(req, executed, now=10)
    two = broker.receipt(req, executed, now=10)
    assert one == two
    assert len(one.receipt_hash) == 64


def test_tools_rejected_outside_execute_mode_and_output_bounded():
    broker = AISecurityBroker()
    with pytest.raises(ValueError, match="only in execute"):
        broker.validate(request(), valid_output(
            tool_name="anything", tool_arguments={"x": 1}
        ))
    with pytest.raises(ValueError, match="exceeds"):
        broker.validate(request(), {"blob": "x" * 65000})
