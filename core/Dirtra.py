from .utils import attack, colors

class dirtra:
    def __init__(self, target, file, dt):
        self.target = target
        self.file = file
        self.dt = dt

    def execute_dirtra(self):
        if self.file:
            with open(self.file, 'r') as payloadfile:
                payloads = payloadfile.readlines()
                for payload in payloads:
                    ret = attack(self.target, payload[:-1], dt=self.dt)
                    if ret == 1:
                        print(colors("[+] Vulnerable: "+self.target+payload[:-1], 92))