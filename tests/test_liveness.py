import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import liffy


class FakeResponse:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


def test_ping_checks_full_http_url_with_port(monkeypatch):
    requested = {}

    def fake_head(url, allow_redirects, timeout):
        requested["url"] = url
        return FakeResponse()

    monkeypatch.setattr(liffy.requests, "head", fake_head)

    assert liffy.ping("http://154.57.164.76:30189/?view=") is True
    assert requested["url"] == "http://154.57.164.76:30189/?view="


def test_ping_falls_back_to_get_when_head_fails(monkeypatch):
    response = FakeResponse()

    def fake_head(url, allow_redirects, timeout):
        raise liffy.requests.RequestException("HEAD blocked")

    def fake_get(url, stream, timeout):
        return response

    monkeypatch.setattr(liffy.requests, "head", fake_head)
    monkeypatch.setattr(liffy.requests, "get", fake_get)

    assert liffy.ping("http://example.com:8080/?view=") is True
    assert response.closed is True


def test_ping_returns_false_when_http_is_unreachable(monkeypatch):
    def fake_head(url, allow_redirects, timeout):
        raise liffy.requests.RequestException("unreachable")

    def fake_get(url, stream, timeout):
        raise liffy.requests.RequestException("unreachable")

    monkeypatch.setattr(liffy.requests, "head", fake_head)
    monkeypatch.setattr(liffy.requests, "get", fake_get)

    assert liffy.ping("http://example.com:8080/?view=") is False
