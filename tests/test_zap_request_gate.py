"""Static and handler-level guards for the target-side ZAP request cap."""

from pathlib import Path

from infrastructure import zap_request_gate


def test_gate_has_one_fixed_endpoint_and_two_request_origin_cap() -> None:
    assert zap_request_gate.LIMIT == 2
    assert zap_request_gate.ORIGIN == "http://vulnerable-store-origin:8000"
    assert zap_request_gate.PATH == "/scenarios/xss/search"
    source = Path(zap_request_gate.__file__).read_text(encoding="utf-8")
    assert "_forwarded >= LIMIT" in source
    assert "outside registered endpoint" in source
    assert "_opener.open(request, timeout=5)" in source


def test_gate_never_forwards_more_than_two_registered_requests(monkeypatch) -> None:
    forwarded = []

    class Response:
        status = 200

        class headers:
            @staticmethod
            def get_content_type():
                return "text/html"

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        @staticmethod
        def read(_limit):
            return b"ok"

    def urlopen(request, timeout):
        forwarded.append((request.full_url, timeout))
        return Response()

    monkeypatch.setattr(zap_request_gate._opener, "open", urlopen)
    monkeypatch.setattr(zap_request_gate, "_forwarded", 0)
    statuses = []
    handler = object.__new__(zap_request_gate.Handler)
    handler._send = lambda status, _body, _content_type: statuses.append(status)
    for value in ("one", "two", "three"):
        handler.path = f"/scenarios/xss/search?q={value}"
        handler.do_GET()

    assert len(forwarded) == 2
    assert statuses == [200, 200, 429]


def test_gate_does_not_follow_upstream_redirects() -> None:
    assert any(
        isinstance(handler, zap_request_gate._NoRedirect)
        for handler in zap_request_gate._opener.handlers
    )
