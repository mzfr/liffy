#!/usr/bin/python

import argparse
import os
import signal
import sys
import urllib.parse

from pyfiglet import figlet_format

from core import Expect, Filter, Input, accesslog, data, proc, sshlog, DirTraversal
from core.utils import colors


def ping(hostname):
    """Ping the host to check if it's up or down

    Arguments:
        hostname {str} -- hostname to ping

    Returns:
        bool -- Tell if host is up or not
    """
    resp = os.system("ping -c 1 -W2 "+hostname+" > /dev/null 2>&1")

    if resp == 0:
        return True
    else:
        return False


def signal_handler(signal, frame):
    print(colors('\n\nYou pressed Ctrl+C!', 91))
    sys.exit(0)


def main():
    if not len(sys.argv):
        print("[!] Not Enough Arguments!")
        # TODO: Add usage
        sys.exit(0)

    parser = argparse.ArgumentParser()
    parser.add_argument("url", help="URL to test for LFI")
    parser.add_argument("-d", "--data", help="Use data:// technique", action="store_true")
    parser.add_argument("-i", "--input", help="Use input:// technique", action="store_true")
    parser.add_argument("-e", "--expect", help="Use expect:// technique", action="store_true")
    parser.add_argument("-f", "--filter", help="Use filter:// technique", action="store_true")
    parser.add_argument("-p", "--proc", help="Use /proc/self/environ technique", action="store_true")
    parser.add_argument("-a", "--access", help="Apache access logs technique", action="store_true")
    parser.add_argument("-ns", "--nostager", help="execute payload directly, do not use stager", action="store_true")
    parser.add_argument("-r", "--relative", help="use path traversal sequences for attack", action="store_true")
    parser.add_argument("--ssh", help="SSH auth log poisoning", action="store_true")
    parser.add_argument("-l", "--location", help="path to target file (access log, auth log, etc.)")
    parser.add_argument("--cookies", help="session cookies for authentication")
    parser.add_argument('-dt', "--directorytraverse", help="Test for Directory Traversal", action="store_true")

    args = parser.parse_args()

    url = args.url
    nostager = args.nostager
    relative = args.relative
    cookies = args.cookies

    parsed = urllib.parse.urlsplit(url)

    print(colors("[~] Checking Target: {0}".format(parsed.netloc), 93))

    # if ping(parsed.netloc):
    #     print(colors("[+] Target looks alive ", 92))
    # else:
    #     print(colors("[!] Target irresponsive ", 91))
    #     sys.exit(1)

    if not parsed.query:
        print(colors("[!] No GET parameter Provided ", 91))

    # TODO: Find a better way to do these checks
    if args.data:
        print(colors("[~] Testing with data:// ", 93))
        d = data.Data(url, nostager, cookies)
        d.execute_data()
    elif args.input:
        print(colors("[~] Testing with input:// ", 93))
        i = Input.Input(url, nostager, cookies)
        i.execute_input()
    elif args.expect:
        print(colors("[~] Testing with expect:// ", 93))
        e = Expect.Expect(url, nostager, cookies)
        e.execute_expect()
    elif args.proc:
        print(colors("[~] /proc/self/environ Technique Selected!", 93))
        i = proc.Environ(url, nostager, relative, cookies)
        i.execute_environ()
    elif args.access:
        print(colors("[~] Testing for Apache access.log poisoning", 93))
        if not args.location:
            print(colors("[~] Log Location Not Provided! Using Default", 93))
            l = '/var/log/apache2/access.log'
        else:
            l = args.location
        a = accesslog(url, l, nostager, relative, cookies)
        a.execute_logs()
    elif args.ssh:
        print(colors("[~] Testing for SSH log poisoning ", 93))
        if not args.location:
            print(colors("[~] Log Location Not Provided! Using Default", 93))
            l = '/var/log/auth.log'
        else:
            l = args.location
        a = sshlog.SSHLogs(url, l, relative, cookies)
        a.execute_ssh()
    elif args.filter:
        print(colors("[~] Testing with expect://", 93))
        f = Filter.Filter(url, cookies)
        f.execute_filter()
    elif args.directorytraverse:
        print(colors("[~] Testing for directory traversal", 93))
        filename = input(colors("[*] Please give a payload file for testing Directory Traversl: ", 91))
        dt = DirTraversal.dirTraversal(url, filename, True)
        dt.execute_dirTraversal()
    else:
        print(colors("[!] Please select atleast one technique to test", 91))
        sys.exit(0)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    print(colors(figlet_format('Liffy v2.0', font='big'), 92))
    print("\n")
    main()
