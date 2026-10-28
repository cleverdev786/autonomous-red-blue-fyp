"""T10: bounded ZAP API adapter, offline/injected transport verification."""

from pathlib import Path
import socket

import pytest
from pydantic import ValidationError

from orchestrator.policy_engine import StandardRedPolicy
from schemas.red_team import RedPolicyUsage
from services.target_registry import TargetRegistry
from services.zap_adapter import ZapAdapter, ZapAdapterDenied, ZapBudget


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def policy_and_auth():
    registry = TargetRegistry.from_directories(
        targets_dir=ROOT / "config/targets",
        security_tests_dir=ROOT / "config/security_tests",
    )
    policy = StandardRedPolicy(registry=registry, budget_file=ROOT / "config/red_standard.json")
    auth = policy.freeze(assessment_id="assessment-1", approval_id="review-1",
                         target_id="vulnerable-store")
    return policy, auth


@pytest.fixture
def budget():
    return ZapBudget(max_urls=4, max_depth=2, duration_seconds=10)


def test_discover_uses_fixed_passive_view_and_only_registered_origin(policy_and_auth, budget):
    policy, auth = policy_and_auth
    calls = []

    def transport(path, params, timeout):
        calls.append((path, params, timeout))
        return {"urls": [
            "http://vulnerable-store:8000/scenarios/xss/search?q=ignored-secret",
            "http://vulnerable-store:8000/health",
            "http://vulnerable-store:8000/scenarios/xss/search?q=another-secret",
        ]}

    adapter = ZapAdapter(policy=policy, request_json=transport)
    result = adapter.discover(auth, target_id="vulnerable-store",
                              endpoint_id="scenario-xss-search",
                              budget=budget, usage=RedPolicyUsage())
    assert result == ("/scenarios/xss/search", "/health")
    assert calls == [(
        "/JSON/core/view/urls/",
        {"baseurl": "http://vulnerable-store:8000"},
        10,
    )]


def test_seed_only_registered_get_no_redirects(policy_and_auth, budget):
    policy, auth = policy_and_auth
    calls = []

    def transport(path, params, timeout):
        calls.append((path, params, timeout))
        return {"accessUrl": "HTTP/1.1 200 OK"}

    adapter = ZapAdapter(policy=policy, request_json=transport)
    assert adapter.seed(auth, target_id="vulnerable-store",
                        endpoint_id="scenario-xss-search",
                        budget=budget, usage=RedPolicyUsage())
    assert calls == [(
        "/JSON/core/action/accessUrl/",
        {"url": "http://vulnerable-store:8000/scenarios/xss/search",
         "followRedirects": "false"},
        10,
    )]


@pytest.mark.parametrize("url", [
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1:8000/health",
    "http://evil.test:8000/health",
    "http://vulnerable-store.evil.test:8000/health",
    "http://vulnerable-store:8001/health",
    "https://vulnerable-store:8000/health",
    "http://user@vulnerable-store:8000/health",
    "http://vulnerable-store:8000/../admin",
    "http://vulnerable-store:8000/%2e%2e/admin",
    "http://vulnerable-store:8000/health#fragment",
    "http://vulnerable-store:8000//evil.test",
])
def test_discovery_rejects_all_untrusted_url_forms(policy_and_auth, budget, url):
    policy, auth = policy_and_auth
    adapter = ZapAdapter(policy=policy, request_json=lambda *_: {"urls": [url]})
    with pytest.raises(ZapAdapterDenied, match="out_of_scope"):
        adapter.discover(auth, target_id="vulnerable-store",
                         endpoint_id="scenario-xss-search",
                         budget=budget, usage=RedPolicyUsage())


@pytest.mark.parametrize("response", [
    {}, {"urls": "not-list"}, {"urls": [42]}, {"urls": [{"url": "http://vulnerable-store:8000/health"}]},
    {"urls": ["http://vulnerable-store:8000/health"] * 100},
    {"error": "unknown_api"},
])
def test_malformed_or_oversized_response_is_denied(policy_and_auth, budget, response):
    policy, auth = policy_and_auth
    adapter = ZapAdapter(policy=policy, request_json=lambda *_: response)
    with pytest.raises(ZapAdapterDenied, match="malformed_response"):
        adapter.discover(auth, target_id="vulnerable-store",
                         endpoint_id="scenario-xss-search",
                         budget=budget, usage=RedPolicyUsage())


@pytest.mark.parametrize("reply", [
    {"accessUrl": "HTTP/1.1 301 Moved Permanently\nLocation: http://evil.test"},
    {"accessUrl": "HTTP/1.1 302 Found"},
    {"accessUrl": "HTTP/1.1 307 Temporary Redirect"},
    {"accessUrl": "HTTP/1.1 200 OK\nLocation: http://evil.test"},
    {"accessUrl": "not a HTTP response"},
    {},
    {"error": "bad_auth"},
])
def test_access_response_rejects_redirects_and_errors(policy_and_auth, budget, reply):
    policy, auth = policy_and_auth
    adapter = ZapAdapter(policy=policy, request_json=lambda *_: reply)
    with pytest.raises(ZapAdapterDenied, match="malformed_response|redirect"):
        adapter.seed(auth, target_id="vulnerable-store", endpoint_id="scenario-xss-search",
                     budget=budget, usage=RedPolicyUsage())


@pytest.mark.parametrize("error", [TimeoutError("slow"), socket.timeout("slow")])
def test_timeout_is_structured_not_raw_exception(policy_and_auth, budget, error):
    policy, auth = policy_and_auth

    def transport(*_):
        raise error

    adapter = ZapAdapter(policy=policy, request_json=transport)
    with pytest.raises(ZapAdapterDenied, match="timeout"):
        adapter.discover(auth, target_id="vulnerable-store",
                         endpoint_id="scenario-xss-search",
                         budget=budget, usage=RedPolicyUsage())


@pytest.mark.parametrize("changes", [
    {"target_id": "external"},
    {"endpoint_id": "unregistered"},
])
def test_unregistered_inputs_rejected_before_any_api_call(policy_and_auth, budget, changes):
    policy, auth = policy_and_auth

    def forbidden(*_):
        pytest.fail("ZAP API call must not occur")

    adapter = ZapAdapter(policy=policy, request_json=forbidden)
    kwargs = {"target_id": "vulnerable-store", "endpoint_id": "scenario-xss-search",
              "budget": budget, "usage": RedPolicyUsage()}
    kwargs.update(changes)
    with pytest.raises(ZapAdapterDenied, match="denied"):
        adapter.discover(auth, **kwargs)


@pytest.mark.parametrize("usage", [
    RedPolicyUsage(http_requests=24),
    RedPolicyUsage(crawl_requests=12),
    RedPolicyUsage(elapsed_seconds=180),
    RedPolicyUsage(active_operations=1),
])
def test_standard_usage_bounds_reject_before_api(policy_and_auth, budget, usage):
    policy, auth = policy_and_auth
    adapter = ZapAdapter(policy=policy, request_json=lambda *_: pytest.fail("should not call API"))
    with pytest.raises(ZapAdapterDenied, match="budget_denied"):
        adapter.discover(auth, target_id="vulnerable-store",
                         endpoint_id="scenario-xss-search", budget=budget, usage=usage)


def test_forged_authorization_and_scope_rejected(policy_and_auth, budget):
    policy, auth = policy_and_auth
    forged = auth.model_copy(update={"hostname": "external"})
    adapter = ZapAdapter(policy=policy, request_json=lambda *_: pytest.fail("should not call API"))
    with pytest.raises(ZapAdapterDenied, match="budget_denied"):
        adapter.discover(forged, target_id="vulnerable-store",
                         endpoint_id="scenario-xss-search", budget=budget, usage=RedPolicyUsage())


def test_no_generic_commands_raw_url_or_shell_arguments(policy_and_auth, budget):
    policy, auth = policy_and_auth
    adapter = ZapAdapter(policy=policy, request_json=lambda *_: {})
    with pytest.raises(TypeError):
        adapter.discover(auth, target_id="vulnerable-store", endpoint_id="scenario-xss-search",
                         budget=budget, usage=RedPolicyUsage(), shell="bash")
    with pytest.raises(ValidationError):
        ZapBudget(max_urls=0, max_depth=0, duration_seconds=0)
    with pytest.raises(ValidationError):
        ZapBudget(max_urls=200, max_depth=20, duration_seconds=500)

def test_zap_tmpfs_home_is_writable_as_nonroot():
    import yaml
    overlay = yaml.safe_load((ROOT / "compose.zap.yaml").read_text())
    zap = overlay["services"]["zap"]
    home = next(value for value in zap["tmpfs"] if value.startswith("/home/zap/.ZAP:"))
    assert "uid=1000" in home
    assert "gid=1000" in home
    assert "mode=0700" in home
    assert "size=160m" in home



def test_real_zap_2170_access_url_serialized_exchange_is_supported(policy_and_auth, budget):
    policy, auth = policy_and_auth
    # ZAP 2.17.0 returns a stringified list of exchange dictionaries.
    # No raw response-body data must enter the result.
    value = repr([{
        "note": "", "rtt": "93", "responseBody": "sensitive-body-must-not-leak",
        "responseHeader": "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n",
        "requestHeader": "GET /health HTTP/1.1",
    }])
    adapter = ZapAdapter(policy=policy, request_json=lambda *_: {"accessUrl": value})
    assert adapter.seed(auth, target_id="vulnerable-store", endpoint_id="health",
                        budget=budget, usage=RedPolicyUsage())


@pytest.mark.parametrize("header", [
    "HTTP/1.1 301 Moved Permanently\r\nLocation: http://evil.test",
    "HTTP/1.1 302 Found\r\n",
    "HTTP/1.1 200 OK\r\nLocation: http://evil.test",
    "HTTP/1.1 500 Error\r\n",
    "not a response",
])
def test_real_zap_serialized_exchange_rejects_redirects_and_malformed(policy_and_auth, budget, header):
    policy, auth = policy_and_auth
    value = repr([{"responseHeader": header, "responseBody": "secret"}])
    adapter = ZapAdapter(policy=policy, request_json=lambda *_: {"accessUrl": value})
    with pytest.raises(ZapAdapterDenied, match="redirect|malformed_response"):
        adapter.seed(auth, target_id="vulnerable-store", endpoint_id="health",
                     budget=budget, usage=RedPolicyUsage())


@pytest.mark.parametrize("value", [
    repr([]), repr([{"responseBody": "fake"}]), repr([{"responseHeader": 200}]),
    "{'responseHeader': 'HTTP/1.1 200 OK'}", "(__import__('os').system('echo x'))",
])
def test_noncanonical_zap_exchange_data_is_denied(policy_and_auth, budget, value):
    policy, auth = policy_and_auth
    adapter = ZapAdapter(policy=policy, request_json=lambda *_: {"accessUrl": value})
    with pytest.raises(ZapAdapterDenied, match="malformed_response"):
        adapter.seed(auth, target_id="vulnerable-store", endpoint_id="health",
                     budget=budget, usage=RedPolicyUsage())

def test_bounded_large_zap_exchange_may_be_parsed_without_exposing_body(policy_and_auth, budget):
    policy, auth = policy_and_auth
    # Official ZAP accessUrl exchange includes metadata and body, unlike a status line.
    payload = repr([{
        "responseHeader": "HTTP/1.1 200 OK\r\n",
        "responseBody": "x" * 5000,
    }])
    adapter = ZapAdapter(policy=policy, request_json=lambda *_: {"accessUrl": payload})
    assert adapter.seed(auth, target_id="vulnerable-store", endpoint_id="health",
                        budget=budget, usage=RedPolicyUsage())



def test_bounded_64k_zap_exchange_can_be_parsed_without_exposing_body(policy_and_auth, budget):
    policy, auth = policy_and_auth
    exchange = repr([{"responseHeader": "HTTP/1.1 200 OK\r\n",
                      "responseBody": "x" * 25000}])
    adapter = ZapAdapter(policy=policy, request_json=lambda *_: {"accessUrl": exchange})
    assert adapter.seed(auth, target_id="vulnerable-store", endpoint_id="health",
                        budget=budget, usage=RedPolicyUsage())


def test_over_64k_exchange_rejected(policy_and_auth, budget):
    policy, auth = policy_and_auth
    payload = repr([{"responseHeader": "HTTP/1.1 200 OK",
                     "responseBody": "x" * 70000}])
    adapter = ZapAdapter(policy=policy, request_json=lambda *_: {"accessUrl": payload})
    with pytest.raises(ZapAdapterDenied, match="malformed_response"):
        adapter.seed(auth, target_id="vulnerable-store", endpoint_id="health",
                     budget=budget, usage=RedPolicyUsage())



def test_live_zap_access_url_list_of_exchange_dicts(policy_and_auth, budget):
    policy, auth = policy_and_auth
    zap = ZapAdapter(policy=policy, request_json=lambda *_: {
        "accessUrl": [{"responseHeader": "HTTP/1.1 200 OK\r\n",
                       "responseBody": "secret-not-exposed"}]
    })
    assert zap.seed(auth, target_id="vulnerable-store", endpoint_id="health",
                    budget=budget, usage=RedPolicyUsage())


@pytest.mark.parametrize("response", [
    [{"responseHeader": "HTTP/1.1 302 Found\r\nLocation: http://evil.test"}],
    [{"responseHeader": "HTTP/1.1 200 OK\r\nLocation: http://evil.test"}],
    [{"responseHeader": "HTTP/1.1 200 OK"}, {"responseHeader": "HTTP/1.1 200 OK"}],
    {"responseHeader": "HTTP/1.1 200 OK"}, [42], [],
])
def test_live_zap_structured_exchange_denied_on_redirect_or_malformed(policy_and_auth, budget, response):
    policy, auth = policy_and_auth
    zap = ZapAdapter(policy=policy, request_json=lambda *_: {"accessUrl": response})
    with pytest.raises(ZapAdapterDenied, match="malformed_response|redirect"):
        zap.seed(auth, target_id="vulnerable-store", endpoint_id="health",
                 budget=budget, usage=RedPolicyUsage())
