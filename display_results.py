#!/usr/bin/env python3

import argparse
import ipaddress
import json
import sys
import textwrap

try:
    from colorama import Fore, Style
except ImportError as exception:
    print(
        f"[-] Please install required modules, e.g. pip3 install -r requirements.txt: {exception}",
        file=sys.stderr,
    )

NAME = "display_results"
VERSION = "0.0.1"


def parse_arguments(banner):
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent(
            banner
            + """\
 - displays scan results nicely

Copyright (C) 2020  Peter Mosmans [Go Forward]
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version."""
        ),
    )
    parser.add_argument(
        "inputfile",
        nargs="?",
        action="store",
        type=str,
        help="A JSON file containing scan results",
    )
    parser.add_argument(
        "--info",
        action="store_true",
        help="Show also informational items",
        default=False,
    )
    parser.add_argument("--version", action="store_true", help="Show version and exit")
    args = parser.parse_args()
    if args.version:
        print(banner)
        sys.exit(0)
    if not args.inputfile:
        parser.error("Specify a JSON input file")
    return vars(parser.parse_args())


def sorted_hosts(unsorted):
    """Return a list of hosts sorted on IP address."""
    return map(str, sorted([ipaddress.ip_address(x) for x in unsorted]))


def display_json(filename, info=False, empty=False):
    """Display filename sorted on IP address."""
    try:
        with open(filename, mode="r", encoding="utf-8") as json_file:
            results = json.load(json_file)
        print(
            f"Scan of {results['arguments']['target']} was started at {Style.BRIGHT}{results['date_start']}{Style.NORMAL}"
        )
        hosts = results["results"]
        targets = sorted_hosts(hosts)
        for target in targets:
            heading = f"{Style.BRIGHT}{target}{Style.NORMAL}"
            if empty:
                heading = display_heading(heading)
            if "info" in hosts[target] and info:
                heading = display_heading(heading)
                for port in hosts[target]["info"]:
                    for item in hosts[target]["info"][port]:
                        print(f" {Fore.MAGENTA}{port:>5}{Fore.RESET} {item}")
            if "alerts" in hosts[target]:
                heading = display_heading(heading)
                for port in hosts[target]["alerts"]:
                    for alert in hosts[target]["alerts"][port]:
                        print(
                            f" {Fore.MAGENTA}{port:>5} {Fore.GREEN}{alert}{Fore.RESET}"
                        )
    except FileNotFoundError as exception:
        print(f"File {filename} could not be found: Exception {exception}")
    except KeyError as exception:
        print(f"File {filename} not in expected format: Exception {exception}")


def display_heading(heading):
    """Displays heading and resets heading."""
    return print(heading)


def main():
    """Main program loop."""
    banner = "{0} version {1}".format(NAME, VERSION)
    options = parse_arguments(banner)
    display_json(options["inputfile"], info=options["info"])
    sys.exit(0)


if __name__ == "__main__":
    main()
