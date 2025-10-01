from .utils import attack, colors

from .Detection import Detection

class dirTraversal:
    def __init__(self, args, dt):
        self.target = args.url
        self.dt = dt
        self.detection = args.detection

    def attack(self, payload):
        response = attack(self.target, payload, dt=self.dt)
        return response

    def execute_dirTraversal(self):
        if self.detection:
            detector = Detection(self)
            detector.detect()
            return

        print(colors("[~] Testing for Directory Traversal", 93))
        with open('payload_wordlists/directory_traversal_list.txt', 'r') as payloadfile:
            payloads = payloadfile.readlines()
            for payload in payloads:
                attack(self.target, payload[:-1], dt=self.dt)