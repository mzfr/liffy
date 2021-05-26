from .utils import attack, colors

class dirTraversal:
    def __init__(self, target, file, dt):
        self.target = target
        self.file = file
        self.dt = dt

    def execute_dirTraversal(self):
        if self.file:
            print(colors("[~] Testing for Directory Traversal", 93))
            with open(self.file, 'r') as payloadfile:
                payloads = payloadfile.readlines()
                for payload in payloads:
                    attack(self.target, payload[:-1], dt=self.dt)