from types import SimpleNamespace

import liffy
from core.BlindScan import BlindScan
from core.OOBScan import OOBScan


class FakeElapsed:
    def __init__(self, seconds):
        self.seconds = seconds

    def total_seconds(self):
        return self.seconds


class FakeResponse:
    headers = {}

    def __init__(self, text="", status_code=200, seconds=0.1):
        self.text = text
        self.status_code = status_code
        self.elapsed = FakeElapsed(seconds)


def make_args(**overrides):
    defaults = {
        "url": "http://target.local/page.php?file=",
        "cookies": None,
        "method": "GET",
        "headers": None,
        "post_data": None,
        "oob_url": None,
        "auto": False,
        "detection": False,
        "directorytraverse": False,
        "wrappers": False,
        "blind": False,
        "oob": False,
        "data": False,
        "input": False,
        "expect": False,
        "proc": False,
        "access": False,
        "ssh": False,
        "filter": False,
        "null_byte": False,
        "zip": False,
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def test_oob_scan_skips_without_callback_url():
    scan = OOBScan(make_args())

    assert scan.execute_oob_scan() == []


def test_oob_scan_sends_callback_payloads(monkeypatch):
    sent = []

    def fake_attack(target, payload, **kwargs):
        sent.append((target, payload, kwargs))
        return FakeResponse(status_code=204)

    monkeypatch.setattr("core.OOBScan.attack", fake_attack)
    scan = OOBScan(make_args(oob_url="https://abc.oast.site/"))

    results = scan.execute_oob_scan()

    assert len(results) == 4
    assert sent[0][1] == "https://abc.oast.site"
    assert any("liffy-oob" in payload for _, payload, _ in sent)
    assert all(result["note"].startswith("Check your OOB listener") for result in results)


def test_blind_scan_uses_default_pairs_without_list():
    scan = BlindScan(make_args())

    assert scan._load_probe_pairs() == BlindScan.PROBE_PAIRS


def test_blind_scan_loads_custom_probe_list(tmp_path):
    blind_list = tmp_path / "blind.txt"
    blind_list.write_text(
        "# ignored\n"
        "linux-passwd=/etc/passwd\n"
        ".env\n"
    )
    scan = BlindScan(make_args(blind_list=str(blind_list)))

    assert scan._load_probe_pairs() == [
        ("linux-passwd", "/etc/passwd"),
        ("custom-3", ".env"),
    ]


def test_blind_scan_scores_status_length_and_timing_differences():
    existing = {"status": 200, "length": 1000, "time": 2.5}
    missing = {"status": 404, "length": 10, "time": 0.1}

    score, reasons = BlindScan._score(existing, missing)

    assert score == 90
    assert "status differs" in reasons
    assert any(reason.startswith("content length differs") for reason in reasons)
    assert any(reason.startswith("response time differs") for reason in reasons)


def test_blind_scan_reports_response_difference(monkeypatch):
    responses = iter(
        [
            FakeResponse("A" * 1000, status_code=200, seconds=0.1),
            FakeResponse("missing", status_code=404, seconds=0.1),
        ]
    )
    scan = BlindScan(make_args())
    scan.PROBE_PAIRS = [("linux-passwd", "/etc/passwd")]
    monkeypatch.setattr(scan, "_request", lambda payload: next(responses))

    findings = scan.execute_blind_scan()

    assert findings[0]["probe"] == "linux-passwd"
    assert findings[0]["confidence"] >= 40
    assert "status differs" in findings[0]["evidence"]


def test_auto_enables_safe_scan_plan_without_oob_url():
    args = make_args(auto=True)

    liffy.apply_auto_scan(args)

    assert args.detection is True
    assert args.directorytraverse is True
    assert args.wrappers is True
    assert args.blind is True
    assert args.oob is False


def test_auto_includes_oob_when_callback_url_is_set():
    args = make_args(auto=True, oob_url="https://abc.oast.site")

    liffy.apply_auto_scan(args)

    assert args.oob is True
