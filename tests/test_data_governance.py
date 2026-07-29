import pytest

from angerona.core.data_governance import (
    DEFAULT_RETENTION,
    DataClass,
    EgressPolicy,
)


def test_external_egress_is_denied_and_payload_is_minimized():
    preview = EgressPolicy().preview(
        {
            "module": "Process Sensor",
            "username": "Agent",
            "password": "never-export",
            "nested": {"destination_ip": "203.0.113.9"},
        },
        purpose="operator-requested research",
        destination="cloud-provider",
        salt=b"s" * 32,
        external=True,
    )
    assert not preview.permitted
    assert preview.reasons == ("external egress is disabled",)
    assert "password" not in preview.minimized_payload
    assert preview.minimized_payload["username"].startswith("tok_")
    assert preview.minimized_payload["nested"]["destination_ip"].startswith("tok_")
    actions = {item.path: item.action for item in preview.fields}
    assert actions["password"] == "removed"
    assert actions["username"] == "tokenized"


def test_explicit_external_policy_still_removes_restricted_fields():
    preview = EgressPolicy(
        maximum_class=DataClass.SENSITIVE,
        allow_external=True,
    ).preview(
        {"message": "ok", "token": "secret", "path": r"D:\sample.txt"},
        purpose="approved export",
        destination="case-system",
        salt=b"x" * 32,
        external=True,
    )
    assert preview.permitted
    assert preview.minimized_payload == {
        "message": "ok", "path": r"D:\sample.txt",
    }


def test_field_depth_count_and_size_are_bounded():
    policy = EgressPolicy()
    with pytest.raises(ValueError, match="field budget"):
        policy.preview(
            {f"k{i}": i for i in range(300)},
            purpose="test", destination="local", salt=b"x" * 32,
            external=False,
        )
    preview = EgressPolicy(max_payload_bytes=1024).preview(
        {"message": "a" * 2000},
        purpose="test", destination="local", salt=b"x" * 32,
        external=False,
    )
    assert not preview.permitted
    assert "byte budget" in preview.reasons[0]


def test_retention_is_shorter_for_more_sensitive_data():
    assert DEFAULT_RETENTION.retain_days(DataClass.RESTRICTED) == 7
    assert (
        DEFAULT_RETENTION.retain_days(DataClass.RESTRICTED)
        < DEFAULT_RETENTION.retain_days(DataClass.SENSITIVE)
        < DEFAULT_RETENTION.retain_days(DataClass.INTERNAL)
    )
