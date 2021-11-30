#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""analyze_hosts - scans one or more hosts for security misconfigurations

Copyright (C) 2015-2021 Peter Mosmans [Go Forward]
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

import argparse
import io
import datetime
import json
import logging
import os
import queue
import re
import signal
import ssl
import subprocess
import sys
import tempfile
import threading
import time


try:
    import nmap
except ImportError:
    print(
        "[-] Please install python-nmap, e.g. pip3 install python-nmap", file=sys.stderr
    )
    sys.exit(-1)
try:
    import requests
    import yaml
    import Wappalyzer
except ImportError as exception:
    print(
        f"[-] Please install required modules, e.g. pip3 install -r requirements.txt: {exception}",
        file=sys.stderr,
    )
    sys.stderr.flush()

NAME = "analyze_hosts"
__version__ = "1.11.0"
ALLPORTS = [
    (22, "ssh"),
    (25, "smtp"),
    (80, "http"),
    (443, "https"),
    (465, "smtps"),
    (993, "imaps"),
    (995, "pop3s"),
    (8080, "http-proxy"),
]
SSL_PORTS = [25, 443, 465, 993, 995]
# Default list of allowed open ports, different ports will generate an alert
ALLOWED_OPEN_PORTS = [
    80,
    443,
]
NIKTO_ALERTS = [
    "+ OSVDB-",
    "Entry '/index.php/user/register/' in robots.txt returned a non-forbidden or redirect HTTP code",
]
NMAP_ALERTS = [
    "3des-cbc",
    "arcfour",
    "blowfish-cbc",
    "cast128-cbc",
    "diffie-hellman-group-exchange-sha1",
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
    "ecdh-sha2-nistp",
    "ecdsa",
    "hmac-md5",
    "hmac-sha1",
    "message_signing: disabled",
    "mountd ",
    "msrpc",
    "netbios-ssn ",
    "ssh-dss",
    "umac-64",
]
# All these keywords will be suffixed with ': '
NMAP_INFO = [
    "Computer name",
    "Domain name",
    "NetBIOS computer name",
    "authentication_level",
    "banner",
    "challenge_response",
    "http-server-header",
    "http-title",
    "message_signing",
    "nbstat" "smb-security-mode",
    "smtp-open-relay",
]
NMAP_ARGUMENTS = ["-sV", "--open"]  # A list of default arguments to pass to nmap
NMAP_SCRIPTS = [
    "banner",
    "dns-nsid",
    "dns-recursion",
    "http-cisco-anyconnect",
    "http-php-version",
    "http-title",
    "http-trace",
    "ntp-info",
    "ntp-monlist",
    "nbstat",
    "rdp-enum-encryption",
    "rpcinfo",
    "sip-methods",
    "smb-os-discovery",
    "smb-security-mode",
    "smtp-open-relay",
    "ssh2-enum-algos",
    "vnc-info",
    "xmlrpc-methods",
    "xmpp-info",
]
TESTSSL_ALERTS = [
    "(deprecated)",
    "DES-CBC3",
    "NOT ok",
    "TLS1: ",
    "VULNERABLE",
]
TESTSSL_UNTRUSTED = [
    "NOT ok (self signed CA in chain)",
    "NOT ok -- neither CRL nor OCSP URI provided",
]

# A regular expression of prepend characters to remove in a line
REMOVE_PREPEND_LINE = r"^[| _+]*"
UNKNOWN = -1
# The program has the following loglevels:
# logging.DEBUG = 10    debug messages (module constant)
# logging.INFO  = 20    verbose status messages (module constant)
COMMAND = 23  # tool command line        pylint:disable=bad-whitespace
STATUS = 25  # generic status messages  pylint:disable=bad-whitespace
# ERROR         = 40    recoverable error messages (module constant)
# CRITICAL      = 50    abort program (module constant)

# The following levels are used for the actual scanning output:
LOGS = 30  # scan output / logfiles   pylint:disable=bad-whitespace
ALERT = 35  # vulnerabilities found    pylint:disable=bad-whitespace


class LogFormatter(logging.Formatter):
    """Class to format log messages based on their type."""

    # pylint: disable=protected-access
    FORMATS = {
        logging.DEBUG: logging._STYLES["{"][0]("[d] {message}"),
        logging.INFO: logging._STYLES["{"][0]("[*] {message}"),
        "STATUS": logging._STYLES["{"][0]("[+] {message}"),
        "ALERT": logging._STYLES["{"][0]("[!] {message}"),
        logging.ERROR: logging._STYLES["{"][0]("[-] {message}"),
        logging.CRITICAL: logging._STYLES["{"][0]("[-] FATAL: {message}"),
        "DEFAULT": logging._STYLES["{"][0]("{message}"),
    }

    def format(self, record):
        self._style = self.FORMATS.get(record.levelno, self.FORMATS["DEFAULT"])
        return logging.Formatter.format(self, record)


class LogFilter:  # pylint: disable=too-few-public-methods
    """Class to remove certain log levels."""

    def __init__(self, filterlist):
        self.__filterlist = filterlist

    def filter(self, logRecord):  # pylint: disable=invalid-name
        """Remove logRecord if it is part of filterlist."""
        return logRecord.levelno not in self.__filterlist


def abort_program(text, error_code=-1):
    """Log critical error @text and exit program with @error_code."""
    logging.critical(text)
    sys.exit(error_code)


def analyze_url(url, port, options, logfile, host_results):
    """Analyze a URL using wappalyzer and execute corresponding scans."""
    wappalyzer = Wappalyzer.Wappalyzer.latest()
    page = requests_get(url, options)
    if page.status_code == 400 and "http://" in url:
        # Retry with a different proticol, as the site might also be securely accessible
        url = url.replace("http://", "https://")
        page = requests_get(url, options)
    if page.status_code == 200:
        webpage = Wappalyzer.WebPage(url, page.text, page.headers)
        analysis = wappalyzer.analyze(webpage)
        # Format logmessage as info message, so that it ends up in logfile
        logging.log(LOGS, "[*] %s Analysis: %s", url, analysis)
        if "Drupal" in analysis:
            do_droopescan(url, port, "drupal", options, logfile, host_results)
        if "Joomla" in analysis:
            do_droopescan(url, port, "joomla", options, logfile, host_results)
        if "WordPress" in analysis:
            do_wpscan(url, port, options, logfile)
    else:
        logging.debug("%s Got result %s - cannot analyze that", url, page.status_code)


def requests_get(url, options, headers=None, allow_redirects=True):
    """Generic wrapper around requests object."""
    # Don't try this at home, kids! Disabling SSL verification
    verify = False
    if not headers:
        headers = {"User-Agent": options["user_agent"]}
    if not verify:
        # pylint: disable=E1101
        requests.packages.urllib3.disable_warnings(
            requests.packages.urllib3.exceptions.InsecureRequestWarning
        )
    proxies = None
    if options["proxy"]:
        proxies = {
            "http": f"http://{options['proxy']}",
            "https": f"https://{options['proxy']}",
        }
    try:
        request = requests.get(
            url,
            headers=headers,
            proxies=proxies,
            verify=verify,
            allow_redirects=allow_redirects,
        )
    except (
        requests.exceptions.ConnectionError,
        requests.exceptions.RequestException,
    ) as exception:
        logging.log(STATUS, "%s Could not connect: %s", url, exception)
        request = None
    return request


def http_checks(host, port, protocol, options, logfile, host_results):
    """Perform various HTTP checks."""
    ssl = False
    if "ssl" in protocol or "https" in protocol:
        ssl = True
        url = f"https://{host}:{port}"
    else:
        url = f"http://{host}:{port}"
    if options["nikto"]:
        do_nikto(host, port, options, logfile, host_results)
    if options["framework"]:
        analyze_url(url, port, options, logfile, host_results)
    if options["http"] or options["compression"]:
        check_compression(url, port, options, host_results, use_ssl=ssl)
    if options["http"] or options["headers"]:
        check_headers(url, port, options, host_results, use_ssl=ssl)
    if options["http"] or options["redirect"]:
        check_redirect(url, port, options, host_results)
    if options["http"] or options["trace"]:
        check_trace(host, port, options, logfile, host_results)


def tls_checks(host, port, protocol, options, logfile, host_results):
    """Perform various SSL/TLS checks."""
    if options["ssl"]:
        do_testssl(host, port, protocol, options, logfile, host_results)
    if options["sslcert"]:
        download_cert(host, port, options, logfile)


def check_redirect(url, port, options, host_results):
    """Check for insecure open redirect."""
    request = requests_get(
        url,
        options,
        headers={"Host": "EVIL-INSERTED-HOST", "User-Agent": options["user_agent"]},
        allow_redirects=False,
    )
    if (
        request
        and request.status_code == 302
        and "Location" in request.headers
        and "EVIL-INSERTED-HOST" in request.headers["Location"]
    ):
        add_item(
            host_results,
            url,
            port,
            options,
            f"{url} vulnerable to open insecure redirect: {request.headers['Location']}",
            ALERT,
        )


def check_headers(url, port, options, host_results, use_ssl=False):
    """Check HTTP headers for omissions / insecure settings."""
    request = requests_get(
        url,
        options,
        headers={"User-Agent": options["user_agent"]},
        allow_redirects=False,
    )
    if not request:
        return
    logging.debug(
        "%s Received status %s and the following headers: %s",
        url,
        request.status_code,
        request.headers,
    )
    security_headers = ["X-Content-Type-Options", "X-XSS-Protection"]
    if use_ssl:
        security_headers.append("Strict-Transport-Security")
    if request.status_code == 200:
        if "X-Frame-Options" not in request.headers:
            add_item(
                host_results,
                url,
                port,
                options,
                f"{url} lacks an X-Frame-Options header",
                ALERT,
            )
        elif "*" in request.headers["X-Frame-Options"]:
            add_item(
                host_results,
                url,
                port,
                options,
                f"{url} has an insecure X-Frame-Options header: {request.headers['X-Frame-Options']}",
                ALERT,
            )
        for header in security_headers:
            if header not in request.headers:
                add_item(
                    host_results,
                    url,
                    port,
                    options,
                    f"{url} lacks a {header} header",
                    ALERT,
                )


def check_compression(url, port, options, host_results, use_ssl=False):
    """Check which compression methods are supported."""
    request = requests_get(url, options, allow_redirects=True)
    if not request:
        return
    if request.history:
        # check if protocol was changed: if so, abort checks
        if (not use_ssl and "https" in request.url) or (
            use_ssl and "https" not in request.url
        ):
            logging.debug(
                "%s protocol has changed while testing to %s - aborting compression test",
                url,
                request.url,
            )
            return
        url = request.url
    for compression in [
        "br",
        "bzip2",
        "compress",
        "deflate",
        "exi",
        "gzip",
        "identity",
        "lzma",
        "pack200-gzip",
        "peerdist",
        "sdch",
        "xpress",
        "xz",
    ]:
        request = requests_get(
            url,
            options,
            headers={
                "User-Agent": options["user_agent"],
                "Accept-Encoding": compression,
            },
            allow_redirects=False,
        )
        if request and request.status_code == 200:
            if "Content-Encoding" in request.headers:
                if compression in request.headers["Content-Encoding"]:
                    add_item(
                        host_results,
                        url,
                        port,
                        options,
                        f"{url} supports {compression} compression",
                        ALERT,
                    )


def is_admin():
    """Check whether script is executed using root privileges."""
    if os.name == "nt":
        try:
            import ctypes

            return ctypes.windll.shell32.IsUserAnAdmin()
        except ImportError:
            return False
    else:
        return os.geteuid() == 0  # pylint: disable=no-member


def preflight_checks(options):
    """Check if all tools are there, and disable tools automatically."""
    try:
        if options["resume"]:
            if (
                not os.path.isfile(options["queuefile"])
                or not os.stat(options["queuefile"]).st_size
            ):
                abort_program("Queuefile {0} is empty".format(options["queuefile"]))
        else:
            if (
                os.path.isfile(options["queuefile"])
                and os.stat(options["queuefile"]).st_size
            ):
                if options["force"]:
                    os.remove(options["queuefile"])
                else:
                    abort_program(
                        "Queuefile {0} already exists.\n".format(options["queuefile"])
                        + "    Use --resume to resume with previous targets, "
                        + "or use --force to overwrite the queuefile"
                    )
    except (IOError, OSError) as exception:
        logging.error("FAILED: Could not read %s (%s)", options["queuefile"], exception)
    for basic in ["nmap"]:
        options[basic] = True
    if options["udp"] and not is_admin() and not options["dry_run"]:
        logging.error("UDP portscan needs root permissions")
    if options["framework"]:
        try:
            import requests
            import Wappalyzer

            options["droopescan"] = True
            options["wpscan"] = True
        except ImportError:
            logging.error("Disabling --framework due to missing Python libraries")
            options["framework"] = False
    if options["wpscan"] and not is_admin():
        logging.error("Disabling --wpscan as this option needs root permissions")
        options["wpscan"] = False
    options["timeout"] = options["testssl.sh"]
    for tool in [
        "nmap",
        "curl",
        "droopescan",
        "nikto",
        "testssl.sh",
        "timeout",
        "wpscan",
    ]:
        if options[tool]:
            logging.debug("Checking whether %s is present... ", tool)
            version = "--version"
            if tool == "nikto":
                version = "-Version"
            elif tool == "droopescan":
                version = "stats"
            result, stdout, stderr = execute_command(
                [get_binary(tool), version], options, keep_endings=False
            )
            options[f"version_{tool}"] = stdout
            if not result:
                if tool == "nmap":
                    if not options["dry_run"] and not options["no_portscan"]:
                        abort_program("Could not execute nmap, which is necessary")
                logging.error(
                    "Could not execute %s, disabling checks (%s)", tool, stderr
                )
                options[tool] = False
            else:
                logging.debug(stdout)


def prepare_nmap_arguments(options):
    """Prepare nmap command line arguments."""
    arguments = NMAP_ARGUMENTS
    scripts = NMAP_SCRIPTS
    if is_admin():
        arguments.append("-sS")
        if options["udp"]:
            arguments.append("-sU")
    elif options["no_portscan"]:
        arguments.append("-sn")
    else:
        arguments.append("-sT")
    if options["allports"]:
        arguments.append("-p1-65535")
    elif options["port"]:
        arguments.append("-p" + options["port"])
    if options["no_portscan"] or options["up"]:
        arguments.append("-Pn")
    if options["whois"]:
        scripts += "asn-query", "fcrdns,whois-ip", "whois-domain"
    if scripts:
        arguments.append("--script=" + ",".join(scripts))
    options["nmap_arguments"] = " ".join(arguments)


def execute_command(cmd, options, logfile=False, keep_endings=True):
    """Execute system command.

    If logfile is provided, will add the command as well as stdout and stderr
    to the logfile.

    Args:
        cmd (str): Command to execute
        options (dictionary): Options
        logfile (str): Name of logfile

    Returns:
        Result value, stdout, stderr (tuple)
    """
    stdout = ""
    stderr = ""
    result = False
    logging.debug(" ".join(cmd))
    if options["dry_run"]:
        return True, stdout, stderr
    try:
        process = subprocess.run(cmd, encoding="utf-8", text=True, capture_output=True)
        # For easier processing, split string into lines
        stdout = process.stdout.splitlines(keep_endings)
        stderr = process.stderr.splitlines(keep_endings)
        result = not process.returncode
    except OSError as exception:
        logging.error("Error while executing %s: %s", cmd, exception)
    except Exception as exception:
        logging.error("Exception while executing %s: %s", cmd, exception)
    if logfile:
        append_logs(logfile, options, " ".join(cmd), "")
        append_logs(logfile, options, stdout, stderr)
    return result, stdout, stderr


def download_cert(host, port, options, logfile):
    """Download an SSL certificate and append it to the logfile."""
    try:
        cert = ssl.get_server_certificate((host, port))
        append_logs(logfile, options, cert, "")
    except ssl.SSLError:
        pass


def append_logs(logfile, options, stdout, stderr):
    """Append unicode text strings to unicode type logfile."""
    if options["dry_run"]:
        return
    try:
        if stdout:
            with io.open(logfile, encoding="utf-8", mode="a+") as open_file:
                open_file.write(compact_strings(stdout, options))
        if stderr:
            with io.open(logfile, encoding="utf-8", mode="a+") as open_file:
                open_file.write(compact_strings(stderr, options))
    except IOError:
        logging.error("Could not write to %s", logfile)


def append_file(logfile, options, input_file):
    """Append content from input_file to logfile, and delete input_file."""
    if options["dry_run"]:
        return
    try:
        if os.path.isfile(input_file) and os.stat(input_file).st_size:
            with open(input_file, "r") as read_file:
                logging.debug("Appending input_file to logfile")
                append_logs(logfile, options, read_file.read().splitlines(True), [])
        os.remove(input_file)
    except (IOError, OSError) as exception:
        logging.error("FAILED: Could not read %s (%s)", input_file, exception)


def compact_strings(lines, options):
    """Remove empty and remarked lines."""
    if options["compact"]:
        return "".join([x for x in lines if not (x == "\n") and not x.startswith("#")])
    return "".join(lines)


def check_trace(host, port, options, logfile, host_results):
    """Check for HTTP TRACE method."""
    if options["trace"]:
        command = [
            get_binary("curl"),
            "-sIA",
            "'{0}'".format(options["user_agent"]),
            "--connect-timeout",
            str(options["timeout"]),
            "-X",
            "TRACE",
            f"{host}:{port}",
        ]
        _result, _stdout, _stderr = execute_command(
            command, options, logfile
        )  # pylint: disable=unused-variable


def do_droopescan(url, port, cms, options, logfile, host_results):
    """Perform a droopescan of type cms."""
    if options["droopescan"]:
        logging.debug("Performing %s droopescan on %s", cms, url)
        command = [get_binary("droopescan"), "scan", cms, "--quiet", "--url", url]
        _result, _stdout, _stderr = execute_command(
            command, options, logfile
        )  # pylint: disable=unused-variable


def do_nikto(host, port, options, logfile, host_results):
    """Perform a nikto scan."""
    command = [
        get_binary("nikto"),
        "-ask",
        "no",
        "-host",
        f"{host}:{port}",
        "-maxtime",
        f'{options["maxtime"]}s',
        "-nointeractive",
        "-vhost",
        f"{host}",
    ]
    if port == 443:
        command.append("-ssl")
        if options["proxy"]:
            command += ["-useproxy", f'https://{options["proxy"]}']
    elif options["proxy"]:
        command += ["-useproxy", f'http://{options["proxy"]}']
    if options["username"] and options["password"]:
        command += ["-id", f'{options["username"]}:{options["password"]}']
    parameters = read_parameters(options["settings"], host, port)
    if "nikto_output" in parameters:
        command += "-output", parameters["nikto_output"]
    if "nikto_plugins" in parameters:
        command += "-Plugins", parameters["nikto_plugins"]
    if "nikto_tuning" in parameters:
        command += "-Tuning", parameters["nikto_tuning"]
    if options["timeout"]:
        command = [get_binary("timeout"), str(options["maxtime"])] + command
    logging.info("%s Starting nikto on port %s", host, port)
    _result, stdout, _stderr = execute_command(
        command, options, logfile
    )  # pylint: disable=unused-variable
    check_strings_for_alerts(stdout, NIKTO_ALERTS, host_results, host, port, options)


def read_parameters(settings, host, port):
    """Read tuning dictionary per host-port combination from the settings dictionary."""
    parameters = {}
    if (
        "targets" in settings
        and host in settings["targets"]
        and "ports" in settings["targets"][host]
    ):
        parameters = next(
            (
                item
                for item in settings["targets"][host]["ports"]
                if item["port"] == port
            ),
            {},
        )
    return parameters


def do_portscan(host, options, logfile, stop_event, host_results):
    """Perform a portscan.

    Args:
        host:         Target host.
        options:      Dictionary object containing options.
        logfile:      Filename where logfile will be written to.
        stop_event:   Event handler for stop event
        host_results: Host results dictionary

    Returns:
        A list with tuples of open ports and the protocol.
    """
    ports = []
    open_ports = []
    if not options["nmap"]:
        if options["port"]:
            ports = [int(port) for port in options["port"].split(",") if port.isdigit()]
            return zip(ports, ["unknown"] * len(ports))
        return ALLPORTS
    if ":" in host:
        options["nmap_arguments"] += " -6"
    logging.info("%s Starting nmap", host)
    logging.log(COMMAND, "nmap %s %s", options["nmap_arguments"], host)
    if options["dry_run"]:
        return ALLPORTS
    try:
        temp_file = "nmap-{0}-{1}".format(
            host, next(tempfile._get_candidate_names())
        )  # pylint: disable=protected-access
        scanner = nmap.PortScanner()
        scanner.scan(
            hosts=host,
            arguments="{0} -oN {1}".format(options["nmap_arguments"], temp_file),
        )
        for ip_address in [
            x for x in scanner.all_hosts() if scanner[x] and scanner[x].state() == "up"
        ]:
            ports = [
                port
                for port in scanner[ip_address].all_tcp()
                if scanner[ip_address]["tcp"][port]["state"] == "open"
            ]
            for port in ports:
                open_ports.append([port, scanner[ip_address]["tcp"][port]["name"]])
        check_nmap_log_for_alerts(temp_file, host_results, host, options)
        append_file(logfile, options, temp_file)
        if open_ports:
            logging.info("%s Found open TCP ports %s", host, open_ports)
        else:
            # Format logmessage as info message, so that it ends up in logfile
            logging.log(LOGS, "[*] %s No open ports found", host)
    except (AssertionError, nmap.PortScannerError) as exception:
        if stop_event.is_set():
            logging.debug("%s nmap interrupted", host)
        else:
            logging.log(
                STATUS,
                "%s Issue with nmap %s: %s",
                host,
                options["nmap_arguments"],
                exception,
            )
        open_ports = [UNKNOWN]
    finally:
        if os.path.isfile(temp_file):
            os.remove(temp_file)
    host_results["ports"] = ports
    return open_ports


def check_nmap_log_for_alerts(logfile, host_results, host, options):
    """Check for keywords in logfile and log them as alert."""
    try:
        if os.path.isfile(logfile) and os.stat(logfile).st_size:
            with open(logfile, "r") as read_file:
                log = read_file.read().splitlines()
            port = 0
            for line in log:  # Highly inefficient 'brute-force' check
                # Grab the last open port number to use that for the alert
                if (
                    " open " in line
                    and "/" in line[:7]
                    and line[: (line.index("/"))].isdecimal()
                ):
                    port = int(line[: (line.index("/"))])
                for keyword in NMAP_INFO:
                    if f"{keyword}: " in line:
                        add_item(host_results, host, port, options, line, logging.INFO)
                for keyword in NMAP_ALERTS:
                    if keyword in line:
                        add_item(host_results, host, port, options, line, ALERT)
    except (IOError, OSError) as exception:
        logging.error("FAILED: Could not read %s (%s)", logfile, exception)


def check_strings_for_alerts(
    strings, keywords, host_results, host, port, options, negate=[]
):
    """Check for keywords in strings and log them as alerts."""
    for line in strings:  # Highly inefficient 'brute-force' check
        for keyword in keywords:
            if keyword in line:
                if not len(negate):
                    add_item(host_results, host, port, options, line, ALERT)
                else:
                    for item in negate:
                        if item in line:
                            line = ""
                    if line:
                        add_item(host_results, host, port, options, line, ALERT)


def add_item(host_results, host, port, options, line, logging_type):
    """Log item, and add line to the corresponding key in host_results.
    Set options["exit"] code when alerts are found.

    logging_type can be INFO or ALERT.
    """
    filtered_line = re.sub(REMOVE_PREPEND_LINE, "", line).strip()
    if logging_type == logging.INFO:
        key = "info"
    else:
        key = "alerts"
        if options["exit_code"]:
            options["exit"] = 1
    if key not in host_results:
        host_results[key] = {}
    if port not in host_results[key]:
        host_results[key][port] = [filtered_line]
    else:
        host_results[key][port].append(filtered_line)
    logging.log(logging_type, f"{host}:{port} {filtered_line}")


def get_binary(tool):
    """Convert tool command to its environment variable, if it is set."""
    if tool.split(".")[0].upper() in os.environ:
        tool = os.environ[tool.split(".")[0].upper()]
    return tool


def do_testssl(host, port, protocol, options, logfile, host_results):
    """Check SSL/TLS configuration and vulnerabilities."""
    # --color 0            Don't use color escape codes
    # --warnings off       Skip connection warnings
    # --quiet              Don't output the banner
    #
    # The following settings are default, and can be overwritten using the 'testssl' parameter
    # --each-cipher        Checks each local cipher remotely
    # --fs                 Check (perfect) forward secrecy settings
    # --protocols          Check TLS/SSL protocols
    # --server-defaults    Display the server's default picks and certificate info
    # --starttls protocol  Use starttls protocol
    # --vulnerable         Test for all vulnerabilities
    if not options["testssl.sh"]:
        return
    command = [
        get_binary("testssl.sh"),
        "--color",
        "0",
        "--quiet",
        "--warnings",
        "off",
    ]
    parameters = read_parameters(options["settings"], host, port)
    if "testssl" in parameters:
        for parameter in parameters["testssl"]:
            command.append(parameter)
    else:
        command += [
            "--each-cipher",
            "--fs",
            "--protocols",
            "--server-defaults",
            "--vulnerable",
        ]
    if options["timeout"]:
        command = [get_binary("timeout"), str(options["maxtime"])] + command
    if "smtp" in protocol:
        command += ["--starttls", "smtp"]
    logging.info("%s Starting testssl.sh on port %s", host, port)
    _result, stdout, _stderr = execute_command(
        command + [f"{host}:{port}"],  # pylint: disable=unused-variable
        options,
        logfile,
    )
    negate = []
    if "testssl_untrusted" in parameters and bool(parameters["testssl_untrusted"]):
        negate = TESTSSL_UNTRUSTED
    check_strings_for_alerts(
        stdout, TESTSSL_ALERTS, host_results, host, port, options, negate
    )


def do_wpscan(url, port, options, logfile):
    """Run WPscan."""
    if options["wpscan"]:
        logging.info("Starting WPscan on " + url)
        command = [
            get_binary("wpscan"),
            "--format",
            "cli-no-color",
            "--no-banner",
            "--update",
            "--ignore-main-redirect",
            "--url",
            url,
        ]
        _result, _stdout, _stderr = execute_command(
            command, options, logfile
        )  # pylint: disable=unused-variable


def prepare_queue(options):
    """Prepare a file which holds all hosts (targets) to scan."""
    expanded = False
    try:
        if not options["inputfile"]:
            expanded = next(
                tempfile._get_candidate_names()
            )  # pylint: disable=protected-access
            with open(expanded, "a") as inputfile:
                inputfile.write(options["target"])
                options["inputfile"] = expanded
        with open(options["inputfile"], "r") as inputfile:
            targets = []
            for host in [
                line for line in inputfile.read().splitlines() if line.strip()
            ]:
                if options["dry_run"] or not re.match(r".*[\.:].*[-/][0-9]+", host):
                    targets.append(host)
                else:
                    arguments = "-nsL"
                    scanner = nmap.PortScanner()
                    scanner.scan(hosts="{0}".format(host), arguments=arguments)
                    if "." in scanner.all_hosts():
                        targets += sorted(
                            scanner.all_hosts(),
                            key=lambda x: tuple(map(int, x.split("."))),
                        )
                    else:
                        targets += scanner.all_hosts()
            with open(options["queuefile"], "a") as queuefile:
                for target in targets:
                    queuefile.write(target + "\n")
        if expanded:
            os.remove(expanded)
    except IOError as exception:
        abort_program("Could not read/write file: {0}".format(exception))


def remove_from_queue(finished_queue, options, stop_event):
    """Remove a host from the queue file."""
    while not stop_event.is_set() or finished_queue.qsize():
        try:
            host = finished_queue.get(block=False)
            with open(options["queuefile"], "r+") as queuefile:
                hosts = queuefile.read().splitlines()
                queuefile.seek(0)
                for i in hosts:
                    if i != host:
                        queuefile.write(i + "\n")
                queuefile.truncate()
            if not os.stat(options["queuefile"]).st_size:
                os.remove(options["queuefile"])
            finished_queue.task_done()
            logging.debug("%s Removed from queue", host)
        except queue.Empty:
            time.sleep(1)
    logging.debug("Exiting remove_from_queue thread")


def process_host(
    options, host_queue, output_queue, finished_queue, stop_event, results
):
    """
    Worker thread: Process each host atomic, add output files to output_queue,
    and finished hosts to finished_queue.
    """
    while host_queue.qsize() and not stop_event.wait(0.01):
        try:
            host = host_queue.get()
            host_logfile = (
                host + "-" + next(tempfile._get_candidate_names())
            )  # pylint: disable=protected-access
            logging.debug(
                "%s Processing (%s items left in host queue)", host, host_queue.qsize()
            )
            host_results = {}
            open_ports = do_portscan(
                host, options, host_logfile, stop_event, host_results
            )
            expected_ports = ALLOWED_OPEN_PORTS
            if (
                "targets" in options["settings"]
                and host in options["settings"]["targets"]
                and "allowed_ports" in options["settings"]["targets"][host]
            ):
                expected_ports = options["settings"]["targets"][host]["allowed_ports"]
            if open_ports:
                if UNKNOWN in open_ports:
                    logging.info("%s Scan interrupted ?", host)
                else:
                    for port, protocol in open_ports:
                        if stop_event.is_set():
                            logging.info("%s Scan interrupted ?", host)
                            break
                        # Sometimes nmap detects webserver as 'ssl/ssl'
                        if port not in expected_ports:
                            add_item(
                                host_results,
                                host,
                                port,
                                options,
                                "Unexpected open port found",
                                ALERT,
                            )
                        if "http" in protocol or "ssl" in protocol:
                            http_checks(
                                host,
                                port,
                                protocol,
                                options,
                                host_logfile,
                                host_results,
                            )
                        if (
                            "ssl" in protocol
                            or port in SSL_PORTS
                            or options["force_ssl"]
                        ):
                            tls_checks(
                                host,
                                port,
                                protocol,
                                options,
                                host_logfile,
                                host_results,
                            )
            if os.path.isfile(host_logfile):
                if os.stat(host_logfile).st_size:
                    with open(host_logfile, "r") as read_file:
                        output_queue.put(read_file.read())
                os.remove(host_logfile)
            if not stop_event.is_set():  # Do not flag host as being done
                results["results"][host] = host_results
                finished_queue.put(host)
            host_queue.task_done()
        except queue.Empty:
            break
    logging.debug(
        "Exiting process_host thread, queue contains %s items", host_queue.qsize()
    )


def process_output(output_queue, stop_event):
    """Convert logged items in output_queue atomically to log items."""
    while not stop_event.is_set() or output_queue.qsize():
        try:
            item = output_queue.get(block=False)
            logging.debug("Processing output item")
            logging.log(LOGS, item)
            output_queue.task_done()
        except queue.Empty:
            time.sleep(1)
        except UnicodeDecodeError as exception:
            logging.error("Having issues decoding %s: %s", item, exception)
            # Flag the issue ready, regardless
            output_queue.task_done()
    logging.debug(
        "Exiting process_output thread, queue contains %s items", output_queue.qsize()
    )


def loop_hosts(options, target_list, results):
    """Iterate all hosts in target_list and perform requested actions."""
    stop_event = threading.Event()
    work_queue = queue.Queue()
    output_queue = queue.Queue()
    finished_queue = queue.Queue()

    def stop_gracefully(signum, frame):  # pylint: disable=unused-argument
        """Handle interrupt (gracefully)."""
        logging.error("Caught Ctrl-C - exiting gracefully (please be patient)")
        stop_event.set()

    signal.signal(signal.SIGINT, stop_gracefully)
    for target in target_list:
        work_queue.put(target)
    threads = [
        threading.Thread(
            target=process_host,
            args=(
                options,
                work_queue,
                output_queue,
                finished_queue,
                stop_event,
                results,
            ),
        )
        for _ in range(min(options["threads"], work_queue.qsize()))
    ]
    threads.append(
        threading.Thread(
            target=remove_from_queue, args=(finished_queue, options, stop_event)
        )
    )
    threads[-1].daemon = True
    threads.append(
        threading.Thread(target=process_output, args=(output_queue, stop_event))
    )
    threads[-1].daemon = True
    logging.debug("Starting %s threads", len(threads))
    for thread in threads:
        thread.start()
    while work_queue.qsize() and not stop_event.wait(1):
        try:
            time.sleep(0.0001)
        except IOError:
            pass
    if not stop_event.is_set():
        work_queue.join()  # block until the queue is empty
    logging.debug("Work queue is empty - waiting for threads to finish")
    while not stop_event.is_set() and (
        not output_queue.empty() or not finished_queue.empty()
    ):
        logging.debug(
            "%s threads running. %s items in output and %s items in finished queue",
            threading.activeCount(),
            output_queue.qsize(),
            finished_queue.qsize(),
        )
        time.sleep(1)


def read_settings(filename):
    """Return a list of settings parsed as an object."""
    settings = {}
    if os.path.isfile(filename):
        try:
            with open(filename) as yamlfile:
                settings = yaml.safe_load(yamlfile)
        except yaml.scanner.ScannerError as exception:
            logging.error(f"Could not parse settings file {filename}: {exception}")
    return settings


def read_targets(filename):
    """Return a list of targets."""
    target_list = []
    try:
        with open(filename, "r") as queuefile:
            target_list = [
                line for line in queuefile.read().splitlines() if line.strip()
            ]
    except IOError:
        logging.error("Could not read %s", filename)
    return target_list


def parse_arguments(banner):
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        fromfile_prefix_chars="@",
    )
    parser.add_argument(
        "target",
        nargs="?",
        type=str,
        help="""[TARGET] can be a single (IP) address, an IP
                        range, or multiple comma-separated addressess""",
    )
    parser.add_argument("--version", action="store_true", help="Show version and exit")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Only show commands, don't actually do anything",
    )
    parser.add_argument(
        "-i",
        "--inputfile",
        action="store",
        type=str,
        help="A file containing targets, one per line",
    )
    parser.add_argument(
        "-o",
        "--output-file",
        action="store",
        type=str,
        default="analyze_hosts.output",
        help="""output file containing all scanresults
                        (default %(default)s)""",
    )
    parser.add_argument(
        "--compact",
        action="store_true",
        help="Only log raw logfiles and alerts to file",
    )
    parser.add_argument(
        "--queuefile",
        action="store",
        default="analyze_hosts.queue",
        help="the queuefile",
    )
    parser.add_argument(
        "--resume", action="store_true", help="Resume working on the queue"
    )
    parser.add_argument(
        "--settings",
        action="store",
        default="analyze_hosts.yml",
        help="Name of settings file to use (default %(default)s)",
    )
    parser.add_argument(
        "--exit-code",
        action="store_true",
        help="When supplied, return exit code 1 when alerts are discovered",
    )
    parser.add_argument(
        "--force", action="store_true", help="Ignore / overwrite the queuefile"
    )
    parser.add_argument("--debug", action="store_true", help="Show debug information")
    parser.add_argument("-v", "--verbose", action="store_true", help="Be more verbose")
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Do not show scan outputs on the console",
    )
    parser.add_argument(
        "--allports",
        action="store_true",
        help="Run a full-blown nmap scan on all ports",
    )
    parser.add_argument(
        "-n", "--no-portscan", action="store_true", help="Do NOT run a nmap portscan"
    )
    parser.add_argument("-p", "--port", action="store", help="Specific port(s) to scan")
    parser.add_argument(
        "--up",
        action="store_true",
        help="Assume host is up (do not rely on ping probe)",
    )
    parser.add_argument(
        "--udp", action="store_true", help="Check for open UDP ports as well"
    )

    parser.add_argument(
        "--framework", action="store_true", help="Analyze the website and run webscans"
    )
    parser.add_argument(
        "--http",
        action="store_true",
        help="""Check for various HTTP vulnerabilities (compression,
headers, trace)""",
    )
    parser.add_argument(
        "--compression", action="store_true", help="Check for webserver compression"
    )
    parser.add_argument(
        "--headers", action="store_true", help="Check for various HTTP headers"
    )
    parser.add_argument(
        "--trace", action="store_true", help="Check webserver for HTTP TRACE method"
    )
    parser.add_argument(
        "--redirect", action="store_true", help="Check for insecure redirect"
    )
    parser.add_argument(
        "--force-ssl",
        action="store_true",
        help="Enforce SSL/TLS check on all open ports",
    )
    parser.add_argument(
        "--json", action="store", type=str, help="Save output in JSON file"
    )
    parser.add_argument(
        "--ssl", action="store_true", help="Check for various SSL/TLS vulnerabilities"
    )
    parser.add_argument("--nikto", action="store_true", help="Run a nikto scan")
    parser.add_argument(
        "--sslcert", action="store_true", help="Download SSL certificate"
    )

    parser.add_argument(
        "-w", "--whois", action="store_true", help="Perform a whois lookup"
    )
    parser.add_argument("--proxy", action="store", help="Use proxy server (host:port)")
    parser.add_argument(
        "--timeout",
        action="store",
        default="10",
        type=int,
        help="Timeout for requests in seconds (default %(default)s)",
    )
    parser.add_argument(
        "--threads",
        action="store",
        type=int,
        default=5,
        help="Maximum number of threads (default %(default)s)",
    )
    parser.add_argument(
        "--user-agent",
        action="store",
        default="analyze_hosts",
        help="Custom User-Agent to use (default %(default)s)",
    )
    parser.add_argument(
        "--password", action="store", help="Password for HTTP basic host authentication"
    )
    parser.add_argument(
        "--username", action="store", help="Username for HTTP basic host authentication"
    )
    parser.add_argument(
        "--maxtime",
        action="store",
        default="600",
        type=int,
        help="Timeout for scans in seconds (default %(default)s)",
    )
    args = parser.parse_args()
    if args.version:
        print(banner)
        sys.exit(0)
    if not (args.inputfile or args.target or args.resume):
        parser.error("Specify either a target or input file")
    options = vars(parser.parse_args())
    options["testssl.sh"] = args.ssl
    options["curl"] = args.trace
    options["wpscan"] = args.framework
    options["droopescan"] = args.framework
    return options


def setup_logging(options):
    """Set up loghandlers according to options."""
    logger = logging.getLogger()
    logger.setLevel(0)
    try:
        logfile = logging.FileHandler(options["output_file"], encoding="utf-8")
    except IOError:
        print(f"[-] Could not log to {options['output_file']}, exiting")
        sys.exit(-1)
    logfile.setFormatter(LogFormatter())
    logfile.setLevel(COMMAND)
    logger.addHandler(logfile)
    # Don't log the asynchronous commands in the logfile
    logfile.addFilter(LogFilter([COMMAND, STATUS]))
    console = logging.StreamHandler(stream=sys.stdout)
    console.setFormatter(LogFormatter())
    # Set up a stderr loghandler which only shows error message
    errors = logging.StreamHandler(stream=sys.stderr)
    errors.setFormatter(LogFormatter())
    errors.setLevel(logging.ERROR)
    console.addFilter(LogFilter([logging.ERROR]))
    console.addFilter(LogFilter([logging.CRITICAL]))
    if options["debug"]:
        console.setLevel(logging.DEBUG)
    elif options["verbose"]:
        console.setLevel(logging.INFO)
    elif options["dry_run"]:
        console.setLevel(COMMAND)
    else:
        console.setLevel(STATUS)
    logger.addHandler(console)
    logger.addHandler(errors)
    if options["compact"]:
        logfile.setLevel(LOGS)
    if options["quiet"]:
        console.addFilter(LogFilter([COMMAND, LOGS]))
    # make sure requests library is, erm, less verbose
    # pylint: disable=E1101
    logging.getLogger("requests.packages.urllib3.connectionpool").setLevel(
        logging.ERROR
    )


def init_results(options):
    """Initialize the results object with basic scan information."""
    # For now, no support for resumed scans
    results = {}
    results["arguments"] = options
    results["date_start"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    results["results"] = {}
    return results


def write_json(results, options):
    """Write results to JSON file."""
    if options["json"]:
        results["date_finish"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        json_results = json.dumps(results)
        # Truncating the file, no check yet on whether it exists
        with io.open(options["json"], encoding="utf-8", mode="w+") as open_file:
            open_file.write(json_results)
        logging.log(STATUS, "JSON results saved to %s", options["json"])


def main():
    """Main program loop."""
    banner = "{0} version {1}".format(NAME, __version__)
    options = parse_arguments(banner)
    options["exit"] = 0
    setup_logging(options)
    logging.log(STATUS, "%s starting", banner)
    preflight_checks(options)
    prepare_nmap_arguments(options)
    if not options["resume"]:
        prepare_queue(options)
    options["settings"] = read_settings(options["settings"])
    logging.debug(options)
    results = init_results(options)
    loop_hosts(options, read_targets(options["queuefile"]), results)
    write_json(results, options)
    if not options["dry_run"]:
        logging.log(STATUS, "Output saved to %s", options["output_file"])
    sys.exit(options["exit"])


if __name__ == "__main__":
    main()
