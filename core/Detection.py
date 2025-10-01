from .utils import attack
from .rich_output import colors, print_error, print_success, print_info
from .Encoding import EncodingBypass


class Detection:
    def __init__(self, attack_instance):
        self.attack_instance = attack_instance

    def detect(self):
        print(
            colors(
                f"[~] Detection mode enabled for {self.attack_instance.__class__.__name__}",
                93,
            )
        )

        # Check if encoding bypass is enabled
        use_encoding = (
            hasattr(self.attack_instance, "use_encoding")
            and self.attack_instance.use_encoding
        )

        with open(
            "payload_wordlists/directory_traversal_list.txt", "r"
        ) as payload_file:
            payloads = payload_file.readlines()

            for payload in payloads:
                payload = payload.strip()
                test_payloads = [payload]

                # Generate encoding variants if enabled
                if use_encoding:
                    test_payloads.extend(EncodingBypass.generate_all_variants(payload))
                    print(
                        colors(
                            f"[~] Testing {len(test_payloads)} encoding variants for payload",
                            94,
                        )
                    )

                for test_payload in test_payloads:
                    try:
                        response = self.attack_instance.attack(test_payload)
                        if response and self.is_vulnerable(response.text):
                            print(
                                colors(
                                    f"[+] LFI vulnerability detected with payload: {test_payload}",
                                    92,
                                )
                            )
                            return
                    except Exception as e:
                        continue  # Skip failed requests

        print(colors("[-] LFI vulnerability not detected.", 91))

    def is_vulnerable(self, text):
        vulnerable_indicators = [
            "root:",
            "toor:",
            "bin/bash",
            "/etc/passwd",
            "[boot loader]",
            "[fonts]",
            "for 16-bit app support",  # Windows indicators
            "daemon:",
            "sys:",
            "www-data:",  # More Linux user indicators
            "<?php",
            "<?=",  # PHP source code exposure
            "mysql:",
            "postgres:",
            "redis:",  # Database configs
        ]
        for indicator in vulnerable_indicators:
            if indicator.lower() in text.lower():
                return True
        return False
