from .Detection import Detection
from .utils import attack, colors, cook

class NullByte:
    def __init__(self, args):
        self.target = args.url
        self.cookies = args.cookies
        self.detection = args.detection

    def attack(self, payload):
        payload = f"{payload}%00"
        if self.cookies:
            cookies = cook(self.cookies)
            response = attack(self.target, payload, cookies=cookies, detection_mode=self.detection)
        else:
            response = attack(self.target, payload, detection_mode=self.detection)
        return response

    def execute_null_byte(self):
        if self.detection:
            detector = Detection(self)
            detector.detect()
            return

        print(colors("[~] Testing for Null Byte Poisoning", 93))
        with open('payload_wordlists/directory_traversal_list.txt', 'r') as payloadfile:
            payloads = payloadfile.readlines()
            for payload in payloads:
                self.attack(payload[:-1])
