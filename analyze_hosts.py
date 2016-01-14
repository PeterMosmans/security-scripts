#!/usr/bin/env python

"""
analyze_hosts - scans one or more hosts for security misconfigurations

Copyright (C) 2015-2016 Peter Mosmans [Go Forward]
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

from __future__ import absolute_import
from __future__ import print_function

import argparse
import os
import signal
import ssl
import subprocess
import sys
import tempfile
import textwrap


import nmap


UNKNOWN = -1


def exit_gracefully(signum, frame):
    """
    Handle interrupts gracefully.
    """
    global child
    signal.signal(signal.SIGINT, original_sigint)
    try:
        if len(child):
            if raw_input('\nKill running process {0} ? (y/n) '.format(child[1])).lower().startswith('y'):
                os.kill(child[0], signal.SIGHUP)
        if raw_input("\nQuit analyze_hosts ? (y/n) ").lower().startswith('y'):
            print_error('Quitting...', [], -1)
    except KeyboardInterrupt:
        print_error('Quitting...', -1)
    signal.signal(signal.SIGINT, [], exit_gracefully)


def print_error(text, options, result=False):
    """
    Prints error message and exits with result code result if not 0.
    """
    if not len(options) or not options['quiet']:
        print('[-] ' + text, file=sys.stderr)
        sys.stdout.flush()
        sys.stderr.flush()
    if result:
        sys.exit(result)


def print_status(text, options):
    """
    Prints status message.
    """
    if not options['quiet']:
        print('[*] ' + text)
        sys.stdout.flush()
        sys.stderr.flush()


def preflight_checks(options):
    """
    Checks if all tools are there, and disables tools automatically
    """
    if options['resume']:
        if not os.path.isfile(options['queuefile']) or not os.stat(options['queuefile']).st_size:
            print_error('Cannot resume - queuefile {0} is empty'.format(options['queuefile']), options, True)
    else:
        if os.path.isfile(options['queuefile']) and os.stat(options['queuefile']).st_size:
            print_error('WARNING: Queuefile {0} already exists.\nUse --resume to resume with previous targets, or delete file manually'.format(options['queuefile']), options, True)
    for basic in ['nmap', 'timeout']:
        options[basic] = True
    for tool in ['curl', 'nmap', 'nikto', 'testssl.sh', 'timeout']:
        if options[tool]:
            print_status('Checking whether {0} is present... '.format(tool), options)
            result, _stdout, _stderr = execute_command([tool, '--version'], options)
            if not result:
                print_error('FAILED: Could not execute {0}, disabling checks'.format(tool), options, False)
                options[tool] = False



def execute_command(cmd, options):
    """
    Executes command.
    Returns True if command succeeded
    """
    stdout = ''
    stderr = ''
    result = False
    global child
    child = []
    if options['dryrun']:
        print_status(' '.join(cmd), options)
        return True, stdout, stderr
    try:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        child.append(process.pid)
        child.append(cmd[0])
        stdout, stderr = process.communicate()
        result = not process.returncode
    except OSError as exception:
        pass
    child = []
    return result, stdout, stderr


def perform_recon(host, options):
    """
    Performs all recon actions on @host when specified in @options.
    """
    if options['whois']:
        do_whois(host, options, host_data)


def download_cert(host, port, options):
    """
    Downloads and outputs a SSL certificate.
    """
    cert = ssl.get_server_certificate((host, port))
    append_logs(options, cert)


def do_portscan(host, options):
    """
    Performs a portscan.


    Returns:
        A list of open ports.

    Arguments:
        host: target host in string
        options: dictionary with options
    """
    arguments = '-sS -sS -v --script=dns-nsid,dns-recursion,http-title,http-trace,ntp-info,ntp-monlist,nbstat,smb-os-discovery,smtp-open-relay,ssh2-enum-algos'
    if options['port']:
        arguments += ' -p' + options['port']
    if options['allports']:
        arguments += ' -p1-65535'
    if not options['nmap'] or options['noportscan']:
        return [UNKNOWN]
    open_ports = []
#    if options['trace']:
#        arguments += ' --script=http-trace'

#    if options['smtp']:
#        arguments += ' --script=smtp-open-relay'
# output matches:
#    bind.version: [secured]
#    dns-recursion: Recursion appears to be enabled
#    smtp-open-relay: Server is an open relay (x/y tests)
#    http-trace: TRACE is enabled
    if options['dryrun']:
        print_status('nmap {0} {1}'.format(arguments, host), options)
        return [UNKNOWN]
    print_status('Starting nmap scan', options)
    try:
        temp_file = tempfile.NamedTemporaryFile()
        arguments = '{0} -oN {1}'.format(arguments, temp_file.name)
        scanner = nmap.PortScanner()
        scanner.scan(hosts=host, arguments=arguments)
        for ip in scanner.all_hosts():
            if scanner[ip] and scanner[ip].state() == 'up':
                for port in scanner[ip].all_tcp():
                    if scanner[ip]['tcp'][port]['state'] == 'open':
                        open_ports.append(port)
        if len(open_ports):
            print_status('Found open ports {0}'.format(open_ports), options)
        else:
            print_status('Did not detect any open ports', options)
        append_file(options, temp_file.name)
    except nmap.PortScannerError as exception:
        print_error('issue while running nmap ({0})'.format(exception), options)
        open_ports = [UNKNOWN]
    finally:
        temp_file.close()
    return open_ports


def append_logs(options, stdout, stderr=None):
    try:
        if stdout:
            with open(options['output_file'], 'a+') as open_file:
                open_file.write(stdout)
        if stderr:
            with open(options['output_file'], 'a+') as open_file:
                open_file.write(stderr)
    except IOError:
        print_error('FAILED: Could not write to {0}'.
                    format(options['output_file']), options, -1)


def append_file(options, input_file):
    try:
        if os.path.isfile(input_file) and os.stat(input_file).st_size:
            with open(input_file, 'r') as read_file:
                result = read_file.read()
            append_logs(options, result)
    except IOError as exception:
        print_error('FAILED: Could not read {0} ({1}'.
                    format(input_file, exception), options, -1)


def reverse_lookup(ip):
    """
    Resolves an IP address to a hostname
    """
    return socket.gethostbyaddr(ip)


# tool-specific commands

def do_curl(host, port, options):
    """
    Checks for HTTP TRACE method.
    """
    if options['trace']:
        command = ['curl', '-qsIA', "'{0}'".format(options['header']), '--connect-timeout', str(options['timeout']), '-X', 'TRACE', '{0}:{1}'.format(host, port)]
        result, stdout, stderr = execute_command(command, options)
        append_logs(options, stdout, stderr)


def do_nikto(host, port, options):
    """
    Performs a nikto scan.
    """
    command = ['nikto', '-vhost', '{0}'.format(host), '-maxtime',
               '{0}s'.format(options['maxtime']), '-host',
               '{0}:{1}'.format(host, port)]
    if port == 443:
        command.append('-ssl')
    result, stdout, stderr = execute_command(command, options)
    append_logs(options, stdout, stderr)


def do_testssl(host, port, options):
    """
    Checks SSL/TLS configuration and vulnerabilities.
    """
    timeout = 100 # hardcoded for now
    command = ['testssl.sh', '--quiet', '--warnings', 'off', '--color', '0',
               '-p', '-f', '-U', '-S']
#    if options['timeout']:
#        command = ['timeout', str(timeout)] + command
    if port == 25:
        command += ['--starttls', 'smtp']
    result, stdout, stderr = execute_command(command +
            ['{0}:{1}'.format(host, port)], options)
    append_logs(options, stdout, stderr)


def interrogate_DNS(ip):
    """
    Performs deeper DNS inspection.
    """
    reverse = dns.reversename.from_address(ip)
    print(reverse)


def prepare_queue(options):
    """
    Prepares a queue file which holds all hosts to scan.
    """
    if options['target'] in ['/', '-', ',']:
        if not options['nmap']:
            print_error('nmap is necessary for IP ranges', options, True)
        arguments = '-nsL'
        scanner = nmap.PortScanner()
        scanner.scan(hosts='{0}'.format(options['target']), arguments=arguments)
        hosts = scanner.all_hosts()
    else:
        hosts = [options['target']]
    with open(options['queuefile'], 'a') as queuefile:
        for host in hosts:
            queuefile.write(host + '\n')
    return queuefile


def remove_from_queue(host, options):
    """
    Removes a host from the queue file.
    """
    with open(options['queuefile'], 'r+') as f:
        hosts = f.read().splitlines()
        f.seek(0)
        for i in hosts:
            if i != host:
                f.write(i + '\n')
        f.truncate()
    if not os.stat(options['queuefile']).st_size:
        os.remove(options['queuefile'])


def port_open(port, open_ports):
    """
    Checks whether a port has been flagged as open
    Returns True if the port was open, or hasn't been scanned.

    Arguments:
    - `port`: the port to look up
    - `open_ports`: a list of open ports, or -1 if it hasn't been scanned.
    """
    return (UNKNOWN in open_ports) or (port in open_ports)


def use_tool(tool, host, port, options):
    """
    Wrapper to see if tool is available, and to tart correct tool.
    """
    if not options[tool]:
        return
    print_status('starting {0} scan on {1}:{2}'.format(tool, host, port), options)
    if tool == 'nikto':
        do_nikto(host, port, options)
    if tool == 'curl':
        do_curl(host, port, options)
    if tool == 'testssl.sh':
        do_testssl(host, port, options)


def loop_hosts(options, queue):
    """
    Main loop, iterates all hosts in queue.
    """
    counter = 1
    for host in queue:
        status = 'Working on {0} ({1} of {2})'.format(host, counter, len(queue))
        print_status(status, options)
        append_logs(options, status + '\n')
        perform_recon(host, options)
        open_ports = do_portscan(host, options)
        for port in [80, 443, 8080]:
            if port_open(port, open_ports):
                for tool in ['curl', 'nikto']:
                    use_tool(tool, host, port, options)
                if port in [25, 443, 465, 993, 995]:
                    for tool in ['testssl.sh']:
                        use_tool(tool, host, port, options)
                    download_cert(host, port, options)
        remove_from_queue(host, options)
        counter += 1
    print_status('Output saved to {0}'.format(options['output_file']), options)


def read_queue(filename):
    """
    Returns a list of targets.
    """
    queue = []
    try:
        with open(filename, 'r') as queuefile:
            queue = queuefile.read().splitlines()
    except IOError:
        print('[-] could not read {0}'.format(filename))
    return queue


def parse_arguments():
    """
    Parses command line arguments.
    """
    parser = argparse.ArgumentParser(
            formatter_class=argparse.RawDescriptionHelpFormatter,
            description=textwrap.dedent('''\
analyze_hosts - scans one or more hosts for security misconfigurations

Please note that this is NOT a stealthy scan tool: By default, a TCP and UDP
portscan will be launched, using some of nmap's interrogation scripts.

Copyright (C) 2015-2016  Peter Mosmans [Go Forward]
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.'''))
    parser.add_argument('target', nargs='?', type=str,
                        help='[TARGET] can be a single (IP) address, an IP range, eg. 127.0.0.1-255, or multiple comma-separated addressess')
    parser.add_argument('--dryrun', action='store_true',
                        help='only show commands, don\'t actually run anything')
    parser.add_argument('-i', '--inputfile', action='store', type=str,
                        help='a file containing multiple targets, one per line')
    parser.add_argument('-o', '--output_file', action='store', type=str,
                        default = 'analyze_hosts.output',
                        help='output file containing all scanresults (default analyze_hosts.output')
    parser.add_argument('-f', '--force', action='store_true',
                        help='don\'t perform preflight checks, go ahead anyway')
    parser.add_argument('--nikto', action='store_true',
                        help='run a nikto scan')
    parser.add_argument('-n', '--noportscan', action='store_true',
                        help='do NOT run a nmap portscan')
    parser.add_argument('-p', '--port', action='store',
                        help='specific port(s) to scan')
    parser.add_argument('--queuefile', action='store',
                        default='analyze_hosts.queue', help='the queuefile')
    parser.add_argument('--resume', action='store_true',
                        help='resume working on the queue')
    parser.add_argument('--ssl', action='store_true',
                        help='run a ssl scan')
    parser.add_argument('--sslcert', action='store_true',
                        help='download SSL certificate')
    parser.add_argument('--allports', action='store_true',
                        help='run a full-blown nmap scan on all ports')
#    parser.add_argument('--smtp', action='store_true',
#                        help='check mailserver for open relay')
    parser.add_argument('-t', '--trace', action='store_true',
                        help='check webserver for HTTP TRACE method')
    parser.add_argument('-w', '--whois', action='store_true',
                        help='perform a whois lookup')
    parser.add_argument('--header', action='store', default='analyze_hosts',
                        help='custom header to use for scantools (default analyze_hosts)')
    parser.add_argument('--maxtime', action='store', default='600', type=int,
                        help='timeout for scans in seconds (default 600)')
    parser.add_argument('--timeout', action='store', default='10', type=int,
                        help='timeout for requests in seconds (default 10)')
    parser.add_argument('--quiet', action='store_true',
                        help='Don\'t output status messages')
    args = parser.parse_args()
    if not (args.inputfile or args.target or args.resume):
        parser.error('Specify either a target or input file')
    options = vars(parser.parse_args())
    options['testssl.sh'] = args.ssl
    options['curl'] = args.trace
    return options


def main():
    """
    Main program loop.
    """
    options = parse_arguments()
    if not options['force']:
        preflight_checks(options)
    if not options['inputfile']:
        if options['resume']:
            options['inputfile'] = options['queuefile']
        else:
            options['inputfile'] = prepare_queue(options)
    queue = read_queue(options['queuefile'])
    loop_hosts(options, queue)


if __name__ == "__main__":
    original_sigint = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, exit_gracefully)
    main()

