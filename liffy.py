#!/usr/bin/python

import argparse
import os
import signal
import sys
import concurrent.futures
import urllib.parse

from core import Expect, Filter, Input, accesslog, data, proc, sshlog, DirTraversal
from core.rich_output import (
    print_banner,
    configure_output,
    load_config,
    create_default_config,
    rich_print,
    print_error,
    print_success,
)
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
    test_zip_wrapper,
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
    print_error("\n\nYou pressed Ctrl+C!")
    sys.exit(0)


def main():
    if not len(sys.argv):
        print("[!] Not Enough Arguments!")
        # TODO: Add usage
        sys.exit(0)

    # Parse args first to check for banner/color settings
    parser = argparse.ArgumentParser()
    parser.add_argument("url", help="URL to test for LFI", nargs="?")
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
        "-t", "--threads", help="number of threads to use", default=5, type=int
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
    parser.add_argument(
        "--zip",
        help="Test for ZIP wrapper exploitation",
        action="store_true",
    )
    parser.add_argument(
        "--encoding",
        help="Use advanced encoding/bypass techniques",
        action="store_true",
    )
    parser.add_argument(
        "--method",
        help="HTTP method to use (GET/POST)",
        default="GET",
        choices=["GET", "POST"],
    )
    parser.add_argument(
        "--post-data",
        help="POST data (format: key=value&key2=value2)",
    )
    parser.add_argument(
        "--headers",
        help="Custom headers (format: Header1:Value1,Header2:Value2)",
    )
    parser.add_argument(
        "--no-color",
        help="Disable colored output",
        action="store_true",
    )
    parser.add_argument(
        "--no-banner",
        help="Disable banner display",
        action="store_true",
    )
    parser.add_argument(
        "--config",
        help="Create default YAML configuration file",
        action="store_true",
    )

    args = parser.parse_args()

    # Handle config creation
    if args.config:
        if create_default_config():
            print_success(
                "Default configuration file 'liffy_config.yaml' created successfully!"
            )
        else:
            print_error(
                "Configuration file already exists! Delete 'liffy_config.yaml' first or edit it directly."
            )
        sys.exit(0)

    # Load configuration and apply CLI overrides
    load_config()
    configure_output(disable_colors=args.no_color, disable_banner=args.no_banner)

    # Show banner after configuration is loaded
    print_banner()

    if not args.url:
        print_error("URL is required")
        sys.exit(1)

    parsed = urllib.parse.urlsplit(args.url)
    if not parsed.query:
        print_error("No GET parameter Provided")

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
                    print_error("Target irresponsive")
                    sys.exit(1)
                else:
                    print_success("Target looks alive")
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
    if args.zip:
        tasks.append(test_zip_wrapper)

    if not tasks:
        print_error("Please select at least one technique to test")
        sys.exit(0)

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        for task in tasks:
            executor.submit(task, args)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    main()
