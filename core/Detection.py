from .utils import attack, colors

from .utils import attack, colors

class Detection:
    def __init__(self, attack_instance):
        self.attack_instance = attack_instance

    def detect(self):
        print(colors(f"[~] Detection mode enabled for {self.attack_instance.__class__.__name__}", 93))
        with open('payload_wordlists/directory_traversal_list.txt', 'r') as payload_file:
            payloads = payload_file.readlines()
            for payload in payloads:
                response = self.attack_instance.attack(payload[:-1])
                if response and self.is_vulnerable(response.text):
                    print(colors(f"[+] LFI vulnerability detected with payload: {payload}", 92))
                    return
        print(colors("[-] LFI vulnerability not detected.", 91))

    def is_vulnerable(self, text):
        vulnerable_indicators = ["root:", "toor:", "bin/bash", "etc/passwd"]
        for indicator in vulnerable_indicators:
            if indicator in text:
                return True
        return False