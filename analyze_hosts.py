#!/usr/bin/env python

"""
analyze_hosts -scans one or more hosts for security misconfigurations

Copyright (C) 2015 Peter Mosmans [Go Forward]
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

from __future__ import absolute_import
from __future__ import print_function

import argparse
import subprocess
import sys
import textwrap


import nmap

UNKNOWN = -1


def print_exit(text, result):
    """
    Prints error message and exits if result is not 0.
    """
    print('[-] ' + text, file=sys.stderr)
    sys.stdout.flush()
    sys.stderr.flush()
    if result:
        sys.exit(result)


def print_status(text):
    """
    Prints status message.
    """
    print('[*] ' + text)
    sys.stdout.flush()
    sys.stderr.flush()


def preflight_checks(options):
    """
    Checks if all tools are there, and disables tools automatically
    """
    if options.nmap:
        tool = 'nmap'
        print('[*] Checking {0}... '.format(tool), end='')
        if not execute_command([tool, 'version']):
            print_exit('FAILED: Could not execute {0}, disabling option'.format(tool), 0)
            options.nmap = False
        else:
            print('OK')


def execute_command(cmd):
    """
    Executes command.
    Returns True if command succeeded
    """
    stdout = ''
    stderr = ''
    result = False
    try:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        result = not process.returncode
    except OSError as exception:
        print('could not execute {0}'.format(cmd))
        print('[-] {0}'.format(exception.strerror), file=sys.stderr)
    if not result:
        print('FAILED')
#        print(stdout, stderr)
    return result


def perform_recon(host, options, output_file):
    """
    Performs all recon actions on @host when specified in @options.
    Writes output to @output_file.
    """
    if options.whois:
        do_whois(host, options, host_data)
# show output


def do_portscan(host, options, output_file):
    """
    Performs a portscan.


    Returns:
        A list of open ports.

    Arguments:
        host: target host in string
        options: dictionary with options
        output_file: raw output file
    """
    if not options.nmap:
        return [UNKNOWN]
    open_ports = []
    scanner = nmap.PortScanner()
    arguments = '-A -oN ' + output_file
    print_status('starting nmap scan')
    scanner.scan(hosts=host, arguments=arguments)
    print_status('Finished succesfully')
    for ip in scanner.all_hosts():
        if scanner[ip] and scanner[ip].state() == 'up':
            for protocol in scanner[ip].all_protocols():
                for port in scanner[ip][protocol].keys():
                    if scanner[ip][protocol][port]['state'] == "open":
                        open_ports.append(port)
    return open_ports


def reverse_lookup(ip):
    """
    Resolves an IP address to a hostname
    """
    return socket.gethostbyaddr(ip)


def do_nikto(host, port, options, output_file):
    """Performs a nikto scan.

    Arguments:
        host:
        options:
        output_file:
    """
    if not options.nikto:
        return
    command = ['nikto', '-display', 'P', '-u', '{0}:{1}'.format(host, port)]
    if port == 443:
        command.append('-ssl')
    print(command)


def interrogate_DNS(ip):
    """Performs deeper DNS inspection.

    Arguments:
        ip: ip address
    """
    reverse = dns.reversename.from_address(ip)
    print(reverse)

def prepare_queue(options):
    """Prepares a queue file which holds all hosts to scan.
    """
    return

def remove_from_queue(host, queue):
    """
    Removes a host from the queue file.
    """
    queuefile = 'analyze_hosts.queue'
    
    return 'analyze'

def port_open(port, open_ports):
    """
    Checks whether a port has been flagged as open
    Returns True if the port was open, or hasn't been scanned.

    Arguments:
    - `port`: the port to look up
    - `open_ports`: a list of open ports, or -1 if it hasn't been scanned.
    """
    return (UNKNOWN in open_ports) or (port in open_ports)

def loop_hosts(options, queue):
    """
    """
    for host in queue:
        output_file = '{0}.analyze_hosts'.format(host)
        perform_recon(host, options, output_file)
        open_ports = do_portscan(host, options, output_file)
        print_status('Found open ports ' + open_ports)
        for port in [80, 443, 8080]:
            if port_open(port, open_ports):
                do_nikto(host, port, options, output_file)
#                if options.trace:
#                    check_for_trace(host, port)
#                if options.secure_redirect:
#                    check_for_secure_redirect(host, port, output_file)
#                if port == 443:
#                    if testssl:
#                        do_testssl(host, port, output_file)
#                    if cipherscan:
#                        do_cipherscan(host, port, output_file)
#        if port_open(53, open_ports):
#            recursive_dig(host, options, host_data, output_file)
        remove_from_queue(host, queue)


def parse_arguments():
    """
    Parses command line arguments.
    """
    parser = argparse.ArgumentParser(
            formatter_class=argparse.RawDescriptionHelpFormatter,
            description=textwrap.dedent('''\
analyze_hosts

Copyright (C) 2015 Peter Mosmans [Go Forward]
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.'''))
    parser.add_argument('target', nargs='?', type=str,
                        help='[TARGET] can be a single (IP) address, an IP range, eg. 127.0.0.1-255, or multiple comma-separated addressess')
    parser.add_argument('-i', '--inputfile', action='store',
                        help='a file containing multiple targets, one per line')
    parser.add_argument('-f', '--force', action='store_true',
                        help='don\'t perform preflight checks, go ahead anyway')
    parser.add_argument('--nikto', action='store_true',
                        help='run a nikto scan')
    parser.add_argument('-n', '--nmap', action='store_true',
                        help='run a nmap scan')
    parser.add_argument('-w', '--whois', action='store_true',
                        help='perform a whois lookup')
    args = parser.parse_args()
    if not (args.inputfile or args.target):
        parser.error('Specify either a target or input file')
    return parser.parse_args()


def main():
    """
    Main program loop.
    """
    options = parse_arguments()
    queue = []
    print(options)
    if not options.force:
        preflight_checks(options)
    if not options.inputfile:
        queue.append(options.target)
    loop_hosts(options, queue)


if __name__ == "__main__":
    main()

