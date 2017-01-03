#!/usr/bin/env python

"""
analyze_hosts - scans one or more hosts for security misconfigurations

Copyright (C) 2015-2016 Peter Mosmans [Go Forward]
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""


from __future__ import print_function
from __future__ import unicode_literals

import argparse
import logging
import os
import Queue
import re
import signal
import ssl
import subprocess
import sys
import tempfile
import threading
import textwrap
import time

try:
    import nmap
except ImportError:
    print('[-] Please install python-nmap, e.g. pip install python-nmap',
          file=sys.stderr)
    sys.exit(-1)
try:
    import requests
    import Wappalyzer
except ImportError:
    print('[-] Please install the requests and Wappalyzer modules, e.g. '
          'pip install -r requirements.txt', file=sys.stderr)
    sys.stderr.flush()


VERSION = '0.33.0'
ALLPORTS = [25, 80, 443, 465, 993, 995, 8080]
SCRIPTS = """banner,dns-nsid,dns-recursion,http-cisco-anyconnect,\
http-php-version,http-title,http-trace,ntp-info,ntp-monlist,nbstat,\
rdp-enum-encryption,rpcinfo,sip-methods,smb-os-discovery,smb-security-mode,\
smtp-open-relay,ssh2-enum-algos,vnc-info,xmlrpc-methods,xmpp-info"""
UNKNOWN = -1
# The program has the following loglevels:
# logging.DEBUG = 10    debug messages (module constant)
# logging.INFO  = 20    verbose status messages (module constant)
COMMAND         = 23  # tool command line        pylint:disable=bad-whitespace
STATUS          = 25  # generic status messages  pylint:disable=bad-whitespace
# ERROR         = 40    recoverable error messages (module constant)
# CRITICAL      = 50    abort program (module constant)

# The following levels are used for the actual scanning output:
LOGS            = 30  # scan output / logfiles   pylint:disable=bad-whitespace
ALERT           = 35  # vulnerabilities found    pylint:disable=bad-whitespace


class LogFormatter(logging.Formatter):
    """
    Class to format log messages based on their type.
    """
    FORMATS = {logging.DEBUG :"[d] %(message)s",
               logging.INFO : "[*] %(message)s",
               COMMAND : "%% %(message)s",
               STATUS : "[+] %(message)s",
               LOGS : "%(message)s",
               ALERT : "[!] %(message)s",
               logging.ERROR : "[-] %(message)s",
               logging.CRITICAL : "[-] FATAL: %(message)s",
               'DEFAULT' : "%(message)s"}

    def format(self, record):
        self._fmt = self.FORMATS.get(record.levelno, self.FORMATS['DEFAULT'])
        return logging.Formatter.format(self, record)


class LogFilter(object):
    """
    Class to remove certain log levels.
    """
    def __init__(self, level):
        self.__level = level

    def filter(self, logRecord):
        return logRecord.levelno != self.__level


def abort_program(text, error_code=-1):
    """
    Log critical error @text and exit program with @error_code.
    """
    logging.critical(text)
    sys.exit(error_code)


def analyze_url(url, options, logfile):
    """
    Analyze an URL using wappalyzer and execute corresponding scans.
    """
    wappalyzer = Wappalyzer.Wappalyzer.latest()
    page = requests_get(url, options)
    if not page:
        return
    if page.status_code == 200:
        webpage = Wappalyzer.WebPage(url, page.text, page.headers)
        analysis = wappalyzer.analyze(webpage)
        logging.log(LOGS, '%s Analysis: %s', url, analysis)
        if 'Drupal' in analysis:
            do_droopescan(url, 'drupal', options, logfile)
        if 'Joomla' in analysis:
            do_droopescan(url, 'joomla', options, logfile)
        if 'WordPress' in analysis:
            do_wpscan(url, options, logfile)
    else:
        logging.debug('%s Got result %s - cannot analyze that', url,
                      page.status_code)


def requests_get(url, options, headers=None, allow_redirects=True):
    """
    Generic wrapper around requests object.
    """
    # Don't try this at home, kids! Disabling SSL verification
    verify = False
    if not headers:
        headers = {'User-Agent': options['user_agent']}
    if not verify:
        requests.packages.urllib3.disable_warnings(
            requests.packages.urllib3.exceptions.InsecureRequestWarning)
    proxies = None
    if options['proxy']:
        proxies = {'http': 'http://' + options['proxy'],
                   'https': 'https://' + options['proxy']}
    try:
        request = requests.get(url, headers=headers, proxies=proxies,
                               verify=verify, allow_redirects=allow_redirects)
    except (requests.exceptions.ConnectionError, requests.exceptions.RequestException) as exception:
        logging.error('%s Could not connect: %s', url, exception)
        request = None
    return request


def http_checks(host, port, options, logfile):
    """
    Perform various HTTP checks.
    """
    # TODO: this check is shoddy, as it relies on port number and not on protocol
    ssl_proto = (port == 443)
    if ssl_proto:
        url = 'https://{0}:{1}'.format(host, port)
    else:
        url = 'http://{0}:{1}'.format(host, port)
    for tool in ['curl', 'nikto']:
        use_tool(tool, host, port, options, logfile)
    if options['dry_run']:
        return
    if options['framework']:
        analyze_url(url, options, logfile)
    if options['http']:
        check_redirect(url, options)
        check_headers(url, options, ssl_proto=ssl_proto)
        check_compression(url, options, ssl_proto=ssl_proto)


def tls_checks(host, port, options, logfile):
    """
    Perform various SSL/TLS checks.
    """
    if options['ssl']:
        use_tool('testssl.sh', host, port, options, logfile)
    if options['sslcert']:
        download_cert(host, port, options, logfile)


def check_redirect(url, options):
    """
    Check for insecure open redirect.
    """
    request = requests_get(url, options,
                           headers={'Host': 'EVIL-INSERTED-HOST',
                                    'User-Agent': options['user_agent']},
                           allow_redirects=False)
    if request and request.status_code == 302:
        if 'Location' in request.headers:
            if 'EVIL-INSERTED-HOST' in request.headers['Location']:
                logging.log(ALERT, '%s vulnerable to open insecure redirect: %s',
                            url, request.headers['Location'])


def check_headers(url, options, ssl_proto=False):
    """
    Check HTTP headers for omissions / insecure settings.
    """
    request = requests_get(url, options, headers={'User-Agent': options['user_agent']},
                           allow_redirects=False)
    if not request:
        return
    logging.debug("%s Received status %s and the following headers: %s", url,
                  request.status_code, request.headers)
    security_headers = ['X-Content-Type-Options', 'X-XSS-Protection']
    if ssl_proto:
        security_headers.append('Strict-Transport-Security')
    if request.status_code == 200:
        if 'X-Frame-Options' not in request.headers:
            logging.log(ALERT, '%s lacks a X-Frame-Options header', url)
        elif '*' in request.headers['X-Frame-Options']:
            logging.log(ALERT, '%s has an insecure X-Frame-Options header: %s',
                        url, request.headers['X-Frame-Options'])
        for header in security_headers:
            if header not in request.headers:
                logging.log(ALERT, '%s lacks a %s header', url, header)


def check_compression(url, options, ssl_proto=False):
    """
    Check which compression methods are supported.
    """
    request = requests_get(url, options, allow_redirects=True)
    if not request:
        return
    if request.history:
        # check if protocol was changed: if so, abort checks
        if (not ssl_proto and 'https' in request.url) or \
           (ssl_proto and 'https' not in request.url):
            logging.debug('%s protocol has changed while testing to %s - aborting compression test',
                          url, request.url)
            return
        url = request.url
    for compression in ['br', 'bzip2', 'compress', 'deflate', 'exi', 'gzip',
                        'identity', 'lzma', 'pack200-gzip', 'peerdist', 'sdch',
                        'xpress', 'xz']:
        request = requests_get(url, options, headers={'User-Agent': options['user_agent'],
                                                      'Accept-Encoding': compression},
                               allow_redirects=False)
        if request and request.status_code == 200:
            if 'Content-Encoding' in request.headers:
                if compression in request.headers['Content-Encoding']:
                    logging.log(ALERT, '%s supports %s compression', url, compression)


def is_admin():
    """
    Check whether script is executed using root privileges.
    """
    if os.name == 'nt':
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin()
        except ImportError:
            return False
    else:
        return os.geteuid() == 0  # pylint: disable=no-member


def preflight_checks(options):
    """
    Check if all tools are there, and disable tools automatically.
    """
    try:
        if options['resume']:
            if not os.path.isfile(options['queuefile']) or \
               not os.stat(options['queuefile']).st_size:
                abort_program('Queuefile {0} is empty'.format(options['queuefile']))
        else:
            if os.path.isfile(options['queuefile']) and \
               os.stat(options['queuefile']).st_size:
                if options['force']:
                    os.remove(options['queuefile'])
                else:
                    abort_program('Queuefile {0} already exists.\n'.
                                  format(options['queuefile']) +
                                  '    Use --resume to resume with previous targets, ' +
                                  'or use --force to overwrite the queuefile')
    except (IOError, OSError) as exception:
        logging.error('FAILED: Could not read %s (%s)', options['queuefile'], exception)
    for basic in ['nmap']:
        options[basic] = True
    if options['udp'] and not is_admin() and not options['dry_run']:
        logging.error('UDP portscan needs root permissions')
    if options['framework']:
        try:
            import requests
            import Wappalyzer
            options['droopescan'] = True
            options['wpscan'] = True
        except ImportError:
            logging.error('Disabling --framework due to missing Python libraries')
            options['framework'] = False
    if options['wpscan'] and not is_admin():
        logging.error('Disabling --wpscan as this option needs root permissions')
        options['wpscan'] = False
    options['timeout'] = options['testssl.sh']
    for tool in ['nmap', 'curl', 'droopescan', 'nikto', 'testssl.sh',
                 'timeout', 'wpscan']:
        if options[tool]:
            logging.debug('Checking whether %s is present... ', tool)
            version = '--version'
            if tool == 'nikto':
                version = '-Version'
            result, stdout, stderr = execute_command([get_binary(tool), version], options)
            if not result:
                if tool == 'nmap':
                    if not options['dry_run'] and not options['no_portscan']:
                        abort_program('Could not execute nmap, which is necessary')
                logging.error('Could not execute %s, disabling checks (%s)',
                              tool, stderr)
                options[tool] = False
            else:
                logging.debug(stdout)


def execute_command(cmd, options, logfile=False):
    """
    Execute command.

    If logfile is provided, will add the command as well as stdout and stderr to
    the logfile.

    Returns result, stdout, stderr.
    """
    stdout = ''
    stderr = ''
    result = False
    logging.debug(' '.join(cmd))
    if options['dry_run']:
        return True, stdout, stderr
    try:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        result = not process.returncode
    except OSError:
        pass
    stdout = unicode.replace(stdout.decode('utf-8'), '\r\n', '\n')
    stderr = unicode.replace(stderr.decode('utf-8'), '\r\n', '\n')
    if logfile:
        append_logs(logfile, options, ' '.join(cmd))
        append_logs(logfile, options, stdout, stderr)
    return result, stdout, stderr


def download_cert(host, port, options, logfile):
    """
    Download an SSL certificate and append it to the logfile.
    """
    try:
        cert = ssl.get_server_certificate((host, port))
        append_logs(logfile, options, cert)
    except ssl.SSLError:
        pass


def append_logs(logfile, options, stdout, stderr=None):
    """
    Append text strings to logfile.
    """
    if options['dry_run']:
        return
    try:
        if stdout and len(stdout):
            with open(logfile, 'a+') as open_file:
                open_file.write(compact_strings(stdout, options).encode('utf-8'))
        if stderr and len(stderr):
            with open(logfile, 'a+') as open_file:
                open_file.write(compact_strings(stderr, options))
    except IOError:
        logging.error('Could not write to %s', logfile)


def append_file(logfile, options, input_file):
    """
    Append file to logfile, and delete @input_file.
    """
    if options['dry_run']:
        return
    try:
        if os.path.isfile(input_file) and os.stat(input_file).st_size:
            with open(input_file, 'r') as read_file:
                append_logs(logfile, options, read_file.read())
        os.remove(input_file)
    except (IOError, OSError) as exception:
        logging.error('FAILED: Could not read %s (%s)', input_file, exception)


def compact_strings(strings, options):
    """
    Remove as much unnecessary strings as possible.
    """
    if not options['compact']:
        return strings
    return '\n'.join([x for x in strings.splitlines() if x and
                      not x.startswith('#')]) + '\n'


def do_curl(host, port, options, logfile):
    """
    Check for HTTP TRACE method.
    """
    if options['trace']:
        command = [get_binary('curl'), '-qsIA', "'{0}'".format(options['user_agent']),
                   '--connect-timeout', str(options['timeout']), '-X', 'TRACE',
                   '{0}:{1}'.format(host, port)]
        _result, _stdout, _stderr = execute_command(command, options, logfile)  # pylint: disable=unused-variable


def do_droopescan(url, cms, options, logfile):
    """
    Perform a droopescan of type @cmd
    """
    if options['droopescan']:
        logging.debug('Performing %s droopescan on %s', cms, url)
        command = [get_binary('droopescan'), 'scan', cms, '--quiet', '--url', url]
        _result, stdout, stderr = execute_command(command, options, logfile)  # pylint: disable=unused-variable


def do_nikto(host, port, options, logfile):
    """
    Perform a nikto scan.
    """
    command = [get_binary('nikto'), '-vhost', '{0}'.format(host), '-maxtime',
               '{0}s'.format(options['maxtime']), '-host',
               '{0}:{1}'.format(host, port)]
    if port == 443:
        command.append('-ssl')
        if options['proxy']:
            command += ['-useproxy', 'https://' + options['proxy']]
    else:
        if options['proxy']:
            command += ['-useproxy', 'http://' + options['proxy']]
    if options['username'] and options['password']:
        command += ['-id', options['username'] + ':' + options['password']]
    _result, _stdout, _stderr = execute_command(command, options, logfile)  # pylint: disable=unused-variable


def do_portscan(host, options, logfile, stop_event):
    """
    Perform a portscan.

    Args:
        host:       Target host.
        options:    Dictionary object containing options.
        logfile:    Filename where logfile will be written to.
        stop_event: Event handler for stop event

    Returns:
        A list of open ports.
    """
    open_ports = []
    if options['no_portscan'] and options['port']:
        return [int(port) for port in options['port'].split(',') if port.isdigit()]
    if not options['nmap'] or (options['no_portscan'] and not options['port']):
        return ALLPORTS
    arguments = '--open'
    if is_admin():
        arguments += ' -sS'
        if options['udp']:
            arguments += ' -sU'
    else:
        arguments += ' -sT'
    if options['port']:
        arguments += ' -p' + options['port']
    if options['no_portscan']:
        arguments = '-sn'
    if options['no_portscan'] or options['up']:
        arguments += ' -Pn'
    arguments += ' -sV --script=' + SCRIPTS
    if options['whois']:
        arguments += ',asn-query,fcrdns,whois-ip'
        if re.match('.*[a-z].*', host):
            arguments += ',whois-domain'
    if options['allports']:
        arguments += ' -p1-65535'
    if options['dry_run']:
        return ALLPORTS
    logging.info('%s Starting nmap', host)
    try:
        temp_file = 'nmap-{0}-{1}'.format(host, next(tempfile._get_candidate_names()))  # pylint: disable=protected-access
        arguments = '{0} -oN {1}'.format(arguments, temp_file)
        scanner = nmap.PortScanner()
        logging.debug('nmap %s %s', arguments, host)
        scanner.scan(hosts=host, arguments=arguments)
        for ip_address in [x for x in scanner.all_hosts() if scanner[x] and
                           scanner[x].state() == 'up']:
            open_ports = [port for port in scanner[ip_address].all_tcp() if
                          scanner[ip_address]['tcp'][port]['state'] == 'open']
        append_logs(logfile, options, arguments)
        if options['no_portscan'] or len(open_ports):
            append_file(logfile, options, temp_file)
            if len(open_ports):
                logging.info('%s Found open ports %s', host, open_ports)
    except (AssertionError, nmap.PortScannerError) as exception:
        if stop_event.isSet():
            logging.debug('%s nmap interrupted', host)
        else:
            logging.error('%s Issue with nmap %s: %s', host, arguments, exception)
        open_ports = [UNKNOWN]
    finally:
        if os.path.isfile(temp_file):
            os.remove(temp_file)
    return open_ports


def get_binary(tool):
    """
    Convert tool to environment variable, if it is set.
    """
    if tool.split('.')[0].upper() in os.environ:
        tool = os.environ[tool.split('.')[0].upper()]
    return tool


def do_testssl(host, port, options, logfile):
    """
    Check SSL/TLS configuration and vulnerabilities.
    """
    command = [get_binary('testssl.sh'), '--quiet', '--warnings', 'off', '--color', '0',
               '-p', '-f', '-U', '-S']
    if options['timeout']:
        command = [get_binary('timeout'), str(options['maxtime'])] + command
    if port == 25:
        command += ['--starttls', 'smtp']
    logging.info('%s Starting testssl.sh on port %s', host, port)
    _result, stdout, _stderr = execute_command(command +  # pylint: disable=unused-variable
                                               ['{0}:{1}'.format(host, port)],
                                               options, logfile)
    for line in stdout.splitlines():
        if 'NOT ok' in line:
            logging.log(ALERT, '%s:%s %s', host, port, line)


def do_wpscan(url, options, logfile):
    """
    Run WPscan/
    """
    if options['wpscan']:
        logging.info('Starting WPscan on ' + url)
        command = [get_binary('wpscan'), '--batch', '--no-color', '--url', url]
        _result, _stdout, _stderr = execute_command(command, options, logfile)  # pylint: disable=unused-variable


def prepare_queue(options):
    """
    Prepare a queue file which holds all hosts to scan.
    """
    expanded = False
    try:
        if not options['inputfile']:
            expanded = next(tempfile._get_candidate_names())  # pylint: disable=protected-access
            with open(expanded, 'a') as inputfile:
                inputfile.write(options['target'])
                options['inputfile'] = expanded
        with open(options['inputfile'], 'r') as inputfile:
            targets = []
            for host in [line for line in inputfile.read().splitlines() if line.strip()]:
                if options['dry_run'] or not re.match(r'.*\.[0-9]+[-/][0-9]+', host):
                    targets.append(host)
                else:
                    arguments = '-nsL'
                    scanner = nmap.PortScanner()
                    scanner.scan(hosts='{0}'.format(host), arguments=arguments)
                    targets += sorted(scanner.all_hosts(),
                                      key=lambda x: tuple(map(int, x.split('.'))))
            with open(options['queuefile'], 'a') as queuefile:
                for target in targets:
                    queuefile.write(target + '\n')
        if expanded:
            os.remove(expanded)
    except IOError as exception:
        abort_program('Could not read/write file: {0}'.format(exception))


def remove_from_queue(finished_queue, stop_event, options):
    """
    Remove a host from the queue file synchronously
    """
    while not stop_event.wait(1) or not finished_queue.empty():
        try:
            host = finished_queue.get(block=False)
            with open(options['queuefile'], 'r+') as queuefile:
                hosts = queuefile.read().splitlines()
                queuefile.seek(0)
                for i in hosts:
                    if i != host:
                        queuefile.write(i + '\n')
                queuefile.truncate()
            if not os.stat(options['queuefile']).st_size:
                os.remove(options['queuefile'])
            finished_queue.task_done()
            logging.debug('%s Removed from queue', host)
        except Queue.Empty:
            pass
    logging.debug('Exiting remove_from_queue thread')


def port_open(port, open_ports):
    """
    Check whether a port has been flagged as open.
    Returns True if the port was open, or hasn't been scanned.

    Arguments:
    - `port`: the port to look up
    - `open_ports`: a list of open ports, or -1 if it hasn't been scanned.
    """
    return (UNKNOWN in open_ports) or (port in open_ports)


def use_tool(tool, host, port, options, logfile):
    """
    Wrapper to see if tool is available, and to start correct tool.
    """
    if not options[tool]:
        return
    if tool == 'nikto':
        do_nikto(host, port, options, logfile)
    if tool == 'curl':
        do_curl(host, port, options, logfile)
    if tool == 'testssl.sh':
        do_testssl(host, port, options, logfile)


def process_host(options, host_queue, output_queue, finished_queue, stop_event):
    """
    Worker thread: Process each host atomic, add output files to output_queue,
    and finished hosts to finished_queue.
    """
    while host_queue.qsize() and not stop_event.wait(.01):
        try:
            host = host_queue.get()
            host_logfile = host + '-' + next(tempfile._get_candidate_names())  # pylint: disable=protected-access
            logging.debug('%s Processing (%s in queue)', host, host_queue.qsize())
            open_ports = do_portscan(host, options, host_logfile, stop_event)
            if len(open_ports):
                if UNKNOWN in open_ports:
                    logging.info('%s Scan interrupted ?', host)
                else:
                    for port in open_ports:
                        if stop_event.isSet():
                            logging.info('%s Scan interrupted ?', host)
                            break
                        if port in [80, 443, 8080]:
                            http_checks(host, port, options, host_logfile)
                        if port in [25, 443, 465, 993, 995]:
                            tls_checks(host, port, options, host_logfile)
            else:
                logging.info('%s Nothing to report', host)
            if os.path.isfile(host_logfile) and os.stat(host_logfile).st_size:
                with open(host_logfile, 'r') as read_file:
                    output_queue.put(read_file.read())
                os.remove(host_logfile)
            host_queue.task_done()
            finished_queue.put(host)
        except Queue.Empty:
            break
    logging.debug('Exiting process_host thread')


def process_output(output_queue, stop_event):
    """
    Process logfiles synchronously.
    """
    while not stop_event.wait(1) or not output_queue.empty():
        try:
            item = output_queue.get(block=False)
            logging.log(LOGS, item.encode('ascii', 'ignore'))
            output_queue.task_done()
        except Queue.Empty:
            pass
    logging.debug('Exiting process_output thread')


def loop_hosts(options, queue):
    """
    Main loop, iterate all hosts in queue and perform requested actions.
    """
    stop_event = threading.Event()
    work_queue = Queue.Queue()
    output_queue = Queue.Queue()
    finished_queue = Queue.Queue()

    def stop_gracefully(signum, frame):  # pylint: disable=unused-argument
        """
        Handle interrupt (gracefully).
        """
        logging.error('Caught Ctrl-C - exiting gracefully (please be patient)')
        stop_event.set()

    signal.signal(signal.SIGINT, stop_gracefully)
    for host in queue:
        work_queue.put(host)
    threads = [threading.Thread(target=process_host, args=(options, work_queue,
                                                           output_queue,
                                                           finished_queue,
                                                           stop_event))
               for _ in range(min(options['threads'], work_queue.qsize()))]
    threads.append(threading.Thread(target=process_output, args=(output_queue,
                                                                 stop_event)))
    threads.append(threading.Thread(target=remove_from_queue, args=(finished_queue,
                                                                    stop_event,
                                                                    options)))
    logging.debug('Starting %s threads', len(threads))
    for thread in threads:
        thread.start()
    while work_queue.qsize() and not stop_event.wait(1):
        try:
            time.sleep(0.0001)
        except IOError:
            pass
    if not stop_event.isSet():
        work_queue.join()  # block until the queue is empty
        stop_event.set()  # signal that the work_queue is empty
    logging.debug('Waiting for threads to finish')
    while threads:
        threads.pop().join()
    if output_queue.qsize():
        process_output(output_queue, stop_event)
    output_queue.join()  # always make sure that the output is properly processed


def read_queue(filename):
    """
    Return a list of targets.
    """
    queue = []
    try:
        with open(filename, 'r') as queuefile:
            queue = [line for line in queuefile.read().splitlines() if line.strip()]
    except IOError:
        logging.error('Could not read %s', filename)
    return queue


def parse_arguments(banner):
    """
    Parse command line arguments.
    """
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent(banner + '''\
 - scans one or more hosts for security misconfigurations

Please note that this is NOT a stealthy scan tool: By default, a TCP and UDP
portscan will be launched, using some of nmap's interrogation scripts.

Copyright (C) 2015-2016  Peter Mosmans [Go Forward]
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.'''))
    parser.add_argument('target', nargs='?', type=str,
                        help="""[TARGET] can be a single (IP) address, an IP
                        range, or multiple comma-separated addressess""")
    parser.add_argument('--dry-run', action='store_true',
                        help='Only show commands, don\'t actually do anything')
    parser.add_argument('-i', '--inputfile', action='store', type=str,
                        help='A file containing targets, one per line')
    parser.add_argument('-o', '--output-file', action='store', type=str,
                        default='analyze_hosts.output',
                        help="""output file containing all scanresults
                        (default analyze_hosts.output""")
    parser.add_argument('--compact', action='store_true',
                        help='Only log raw logfiles and alerts to file')
    parser.add_argument('--queuefile', action='store',
                        default='analyze_hosts.queue', help='the queuefile')
    parser.add_argument('--resume', action='store_true',
                        help='Resume working on the queue')
    parser.add_argument('--force', action='store_true',
                        help='Ignore / overwrite the queuefile')
    parser.add_argument('--debug', action='store_true',
                        help='Show debug information')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Be more verbose')
    parser.add_argument('-q', '--quiet', action='store_true',
                        help='Do not show scan outputs on the console')
    parser.add_argument('--allports', action='store_true',
                        help='Run a full-blown nmap scan on all ports')
    parser.add_argument('-n', '--no-portscan', action='store_true',
                        help='Do NOT run a nmap portscan')
    parser.add_argument('-p', '--port', action='store',
                        help='Specific port(s) to scan')
    parser.add_argument('--up', action='store_true',
                        help='Assume host is up (do not rely on ping probe)')
    parser.add_argument('--udp', action='store_true',
                        help='Check for open UDP ports as well')
    parser.add_argument('--framework', action='store_true',
                        help='Analyze the website and run webscans')
    parser.add_argument('--http', action='store_true',
                        help='Check for various HTTP vulnerabilities')
    parser.add_argument('--ssl', action='store_true',
                        help='Check for various SSL/TLS vulnerabilities')
    parser.add_argument('--nikto', action='store_true',
                        help='Run a nikto scan')
    parser.add_argument('--sslcert', action='store_true',
                        help='Download SSL certificate')
    parser.add_argument('-t', '--trace', action='store_true',
                        help='Check webserver for HTTP TRACE method')
    parser.add_argument('-w', '--whois', action='store_true',
                        help='Perform a whois lookup')
    parser.add_argument('--proxy', action='store',
                        help='Use proxy server (host:port)')
    parser.add_argument('--timeout', action='store', default='10', type=int,
                        help='Timeout for requests in seconds (default 10)')
    parser.add_argument('--threads', action='store', type=int, default=5,
                        help='Maximum number of threads (default 5)')
    parser.add_argument('--user-agent', action='store', default='analyze_hosts',
                        help='Custom User-Agent to use (default analyze_hosts)')
    parser.add_argument('--password', action='store',
                        help='Password for HTTP basic host authentication')
    parser.add_argument('--username', action='store',
                        help='Username for HTTP basic host authentication')
    parser.add_argument('--maxtime', action='store', default='1200', type=int,
                        help='Timeout for scans in seconds (default 1200)')
    args = parser.parse_args()
    if not (args.inputfile or args.target or args.resume):
        parser.error('Specify either a target or input file')
    options = vars(parser.parse_args())
    options['testssl.sh'] = args.ssl
    options['curl'] = args.trace
    options['wpscan'] = args.framework
    options['droopescan'] = args.framework
    return options


def setup_logging(options):
    """
    Set up loghandlers according to options.
    """
    logger = logging.getLogger()
    logger.setLevel(0)
    logfile = logging.FileHandler(options['output_file'])
    logfile.setFormatter(logging.Formatter('%(message)s'))
    logfile.setLevel(COMMAND)
    logger.addHandler(logfile)
    console = logging.StreamHandler(stream=sys.stdout)
    console.setFormatter(LogFormatter())
    if options['debug']:
        console.setLevel(logging.DEBUG)
    elif options['verbose']:
        console.setLevel(logging.INFO)
    elif options['dry_run']:
        console.setLevel(COMMAND)
    else:
        console.setLevel(STATUS)
    logger.addHandler(console)
    if options['compact']:
        logfile.setLevel(LOGS)
    if options['quiet']:
        console.addFilter(LogFilter(LOGS))
    # make sure requests library is, erm, less verbose
    logging.getLogger('requests.packages.urllib3.connectionpool').setLevel(logging.ERROR)


def main():
    """
    Main program loop.
    """
    banner = 'analyze_hosts.py version {0}'.format(VERSION)
    options = parse_arguments(banner)
    setup_logging(options)
    logging.info(banner + ' starting')
    preflight_checks(options)
    logging.debug(options)
    if not options['resume']:
        prepare_queue(options)
    queue = read_queue(options['queuefile'])
    loop_hosts(options, queue)
    if not options['dry_run']:
        logging.log(STATUS, 'Output saved to %s', options['output_file'])
    sys.exit(0)


if __name__ == "__main__":
    main()
