"""Inert Teams boundary tests: no HTTP listener, OAuth, Microsoft or AI calls."""
from types import SimpleNamespace
import sys
import pytest
from angerona.connectors import teams_bot as teams

SERVICE = "https://smba.trafficmanager.net/amer/"
TOKEN = "header.payload.signature"


def auth_fixture(monkeypatch, claims=None, header=None):
    calls = []
    jwt = SimpleNamespace(
        get_unverified_header=lambda _token: header or {"alg": "RS256", "kid": "key-1"},
        PyJWK=SimpleNamespace(from_dict=lambda _record: SimpleNamespace(key="inert-public-key")),
        decode=lambda *_args, **kwargs: claims if claims is not None else {"serviceurl": SERVICE})
    monkeypatch.setitem(sys.modules, "jwt", jwt)
    monkeypatch.setattr(teams, "_have", lambda _name: True)
    class Response:
        def __init__(self, payload):
            self.payload = payload
        def __enter__(self):
            return self
        def __exit__(self, *_args):
            return False
    def open_fake(url, **_kwargs):
        calls.append(url)
        return Response({"issuer": "https://api.botframework.com", "jwks_uri": "https://login.botframework.com/keys"}
                        if url == teams._OPENID_URL else {"keys": [{"kid": "key-1", "kty": "RSA", "use": "sig"}]})
    monkeypatch.setattr(teams, "safe_urlopen", open_fake)
    monkeypatch.setattr(teams, "validate_url", lambda value, _policy: value)
    monkeypatch.setattr(teams, "read_bounded", lambda response, _maximum: __import__("json").dumps(response.payload).encode())
    return teams.TeamsBot(app_id="inert-app"), calls, jwt


@pytest.mark.parametrize("claimed", [SERVICE, SERVICE.rstrip("/")])
def test_verified_connector_claim_must_bind_the_activity_service_url(monkeypatch, claimed):
    bot, calls, _jwt = auth_fixture(monkeypatch, {"serviceurl": claimed})
    assert bot._verify_auth("Bearer " + TOKEN, service_url=SERVICE)
    assert len(calls) == 2
    assert not bot._verify_auth("Bearer " + TOKEN, service_url="https://smba.trafficmanager.net/other/")
    assert len(calls) == 2


@pytest.mark.parametrize("claims", [{}, {"serviceurl": "https://tenant.trafficmanager.net/steal"},
    {"serviceurl": SERVICE, "serviceUrl": "https://smba.trafficmanager.net/other"}])
def test_missing_spoofed_or_conflicting_service_claims_are_refused(monkeypatch, claims):
    bot, _calls, _jwt = auth_fixture(monkeypatch, claims)
    assert not bot._verify_auth("Bearer " + TOKEN, service_url=SERVICE)


@pytest.mark.parametrize("header", [{"kid": "key-1", "alg": "none"}, {"alg": "RS256"},
                                   {"kid": "x" * 129, "alg": "RS256"}])
def test_bad_jwt_header_is_rejected_before_metadata_network_work(monkeypatch, header):
    bot, calls, _jwt = auth_fixture(monkeypatch, header=header)
    assert not bot._verify_auth("Bearer " + TOKEN, service_url=SERVICE)
    assert calls == []


def test_key_cache_avoids_repeated_metadata_for_unknown_kid(monkeypatch):
    bot, calls, jwt = auth_fixture(monkeypatch)
    assert bot._verify_auth("Bearer " + TOKEN, service_url=SERVICE)
    jwt.get_unverified_header = lambda _token: {"kid": "unknown", "alg": "RS256"}
    for _ in range(20):
        assert not bot._verify_auth("Bearer " + TOKEN, service_url=SERVICE)
    assert len(calls) == 2


def activity(**changes):
    result = {"type": "message", "channelId": "msteams", "id": "act-1", "text": "status",
        "from": {"aadObjectId": "operator"}, "recipient": {"id": "bot"},
        "conversation": {"id": "conversation"}, "serviceUrl": SERVICE}
    result.update(changes)
    return result


def chat_bot():
    work = []
    bot = teams.TeamsBot(allowed_users=["operator"], handler=lambda text: work.append(text) or "reply",
        token_fn=lambda *_args: "INERT", reply_fn=lambda *_args: 200)
    return bot, work


@pytest.mark.parametrize("url", ["https://tenant.trafficmanager.net/", "https://smba.trafficmanager.net:444/",
    "https://smba.trafficmanager.net/?redirect=elsewhere", "https://smba.trafficmanager.net/#fragment",
    "https://user@smba.trafficmanager.net/", "https://smba.trafficmanager.net/\\path"])
def test_untrusted_reply_url_never_reaches_handler_or_token_provider(url):
    bot, work = chat_bot()
    assert bot.handle_activity(activity(serviceUrl=url)) is None
    assert work == []


def test_only_msteams_aad_operator_is_admitted_and_activity_replay_is_bounded():
    bot, work = chat_bot()
    assert bot.handle_activity(activity(channelId="directline")) is None
    assert bot.handle_activity(activity(**{"from": {"id": "operator"}})) is None
    assert work == []
    assert bot.handle_activity(activity()) is not None
    assert bot.handle_activity(activity()) is None
    assert work == ["status"]
    assert bot.handle_activity(activity(id="act-2")) is not None
    assert work == ["status", "status"]


def test_teams_inert_builtin_selftest_still_passes():
    ok, message = teams.TeamsBot().self_test()
    assert ok, message


def test_conversation_identifier_is_one_encoded_path_segment():
    sent = []
    bot = teams.TeamsBot(allowed_users=["operator"], handler=lambda _text: "reply",
        token_fn=lambda *_args: "INERT", reply_fn=lambda url, *_args: sent.append(url) or 200)
    assert bot.handle_activity(activity(conversation={"id": "../other/path?x=1"})) is not None
    assert sent == [SERVICE.rstrip("/") + "/v3/conversations/..%2Fother%2Fpath%3Fx%3D1/activities"]
