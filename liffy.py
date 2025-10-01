#!/usr/bin/python

import argparse
import os
import signal
import sys
import concurrent.futures
import urllib.parse

from pyfiglet import figlet_format

from core import Expect, Filter, Input, accesslog, data, proc, sshlog, DirTraversal
from core.utils import colors
from tests.test_liffy import (
    test_data,
    test_input,
    test_expect,
    test_proc,
    test_access,
    test_ssh,
    test_filter,
    test_directory_traversal,
    test_null_byte,
)


def ping(hostname):
    """Ping the host to check if it's up or down

    Arguments:
        hostname {str} -- hostname to ping

    Returns:
        bool -- Tell if host is up or not
    """
    resp = os.system("ping -c 1 -W2 " + hostname + " > /dev/null 2>&1")

    if resp == 0:
        return True
    else:
        return False


def signal_handler(signal, frame):
    print(colors("\n\nYou pressed Ctrl+C!", 91))
    sys.exit(0)


def main():
    if not len(sys.argv):
        print("[!] Not Enough Arguments!")
        # TODO: Add usage
        sys.exit(0)

    parser = argparse.ArgumentParser()
    parser.add_argument("url", help="URL to test for LFI")
    parser.add_argument(
        "-d", "--data", help="Use data:// technique", action="store_true"
    )
    parser.add_argument(
        "-i", "--input", help="Use input:// technique", action="store_true"
    )
    parser.add_argument(
        "-e", "--expect", help="Use expect:// technique", action="store_true"
    )
    parser.add_argument(
        "-f", "--filter", help="Use filter:// technique", action="store_true"
    )
    parser.add_argument(
        "-p", "--proc", help="Use /proc/self/environ technique", action="store_true"
    )
    parser.add_argument(
        "-a", "--access", help="Apache access logs technique", action="store_true"
    )
    parser.add_argument(
        "-ns",
        "--nostager",
        help="execute payload directly, do not use stager",
        action="store_true",
    )
    parser.add_argument(
        "-r",
        "--relative",
        help="use path traversal sequences for attack",
        action="store_true",
    )
    parser.add_argument("--ssh", help="SSH auth log poisoning", action="store_true")
    parser.add_argument(
        "-l", "--location", help="path to target file (access log, auth log, etc.)"
    )
    parser.add_argument("--cookies", help="session cookies for authentication")
    parser.add_argument(
        "-dt",
        "--directorytraverse",
        help="Test for Directory Traversal",
        action="store_true",
    )
    parser.add_argument(
        "-t",
        "--threads",
        help="number of threads to use",
        default=5,
        type=int
    )
    parser.add_argument(
        "--detection",
        help="Only perform LFI detection, without attempting to get a shell",
        action="store_true",
    )
    parser.add_argument(
        "--null-byte",
        help="Test for Null Byte Poisoning",
        action="store_true",
    )

    args = parser.parse_args()

    parsed = urllib.parse.urlsplit(args.url)
    if not parsed.query:
        print(colors("[!] No GET parameter Provided ", 91))

    pre_run_tasks = {
        ping: "Checking Target: {0}".format(parsed.netloc),
    }
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=len(pre_run_tasks)
    ) as executor:
        future_to_task = {
            executor.submit(task, parsed.netloc): task for task in pre_run_tasks
        }
        for future in concurrent.futures.as_completed(future_to_task):
            task = future_to_task[future]
            try:
                result = future.result()
                if not result:
                    print(colors("[!] Target irresponsive ", 91))
                    sys.exit(1)
                else:
                    print(colors("[+] Target looks alive ", 92))
            except Exception as exc:
                print(f"{pre_run_tasks[task]} generated an exception: {exc}")

    tasks = []
    if args.data:
        tasks.append(test_data)
    if args.input:
        tasks.append(test_input)
    if args.expect:
        tasks.append(test_expect)
    if args.proc:
        tasks.append(test_proc)
    if args.access:
        tasks.append(test_access)
    if args.ssh:
        tasks.append(test_ssh)
    if args.filter:
        tasks.append(test_filter)
    if args.directorytraverse:
        tasks.append(test_directory_traversal)
    if args.null_byte:
        tasks.append(test_null_byte)

    if not tasks:
        print(colors("[!] Please select at least one technique to test", 91))
        sys.exit(0)

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        for task in tasks:
            executor.submit(task, args)



if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    print(colors(figlet_format("Liffy v2.0", font="big"), 92))
    print("\n")
    main()
