# security-scripts

A collection of security related Python and Bash shell scripts, mainly revolving
around testing hosts for security vulnerabilities. For the shell scripts no
fancy programming framework is required, all that is needed is a Bash shell.

Note that it is highly recommended to use `analyze_hosts.py` as it is the most
recent version. No new features will be added to the Bash version
`analyze_hosts.sh`.

`analyze_hosts` is also available as Docker image, including the open source
scanners `droopescan`, `nmap`, `Nikto` and `testssl.sh`. Build it yourself using
the supplied Dockerfile, or grab the image from Docker Hub

```
docker run --rm gofwd/analyze_hosts
```

You can also run the included tools that way; just override the entrypoint. As
an example, run `testssl.sh`:

```
docker run --rm --entrypoint 'testssl.sh' gofwd/analyze_hosts
```

## analyze_hosts.py

Build status for master branch:
[![Build
Status](https://travis-ci.org/PeterMosmans/security-scripts.svg?branch=master)](https://travis-ci.org/PeterMosmans/security-scripts)

A simple wrapper script around several open source security tools to simplify
scanning of hosts for network vulnerabilities. The script lets you analyze one
or several hosts for common misconfiguration vulnerabilities and weaknesses.

The main objectives for the script is to make it as easy as possible to perform
generic security tests, without any heavy prerequisites, make the output as
informative as possible, and use open source tools. It can easily be used as
scheduled task, or be implemented in Continuous Integration environments.

The only requirements are ``nmap`` and ``Python3``.

As the scan output can be written to a JSON file it can be used to generate
deltas (differences) between scans, or to use the output for further inspection.

### Installation

Note that you can also run `analyze_hosts` straight from a Docker image:

```
docker run --rm gofwd/analyze_hosts
```

One-time installation steps without virtualenv (all required Python libraries
are specified in the `requirements.txt` file):

```
git clone https://github.com/PeterMosmans/security-scripts && \
cd security-script && \
pip3 install -r requirements.txt
```

### Usage

```
usage: analyze_hosts.py [-h] [--version] [--dry-run] [-i INPUTFILE]
                        [-o OUTPUT_FILE] [--compact] [--queuefile QUEUEFILE]
                        [--resume] [--settings SETTINGS] [--exit-code]
                        [--force] [--debug] [-v] [-q] [--allports] [-n]
                        [-p PORT] [--up] [--udp] [--framework] [--http]
                        [--compression] [--headers] [--trace] [--redirect]
                        [--force-ssl] [--json JSON] [--ssl] [--nikto]
                        [--sslcert] [-w] [--proxy PROXY] [--timeout TIMEOUT]
                        [--threads THREADS] [--user-agent USER_AGENT]
                        [--password PASSWORD] [--username USERNAME]
                        [--maxtime MAXTIME]
                        [target]

analyze_hosts - scans one or more hosts for security misconfigurations

Copyright (C) 2015-2021 Peter Mosmans [Go Forward]
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

positional arguments:
  target                [TARGET] can be a single (IP) address, an IP range, or
                        multiple comma-separated addressess

optional arguments:
  -h, --help            show this help message and exit
  --version             Show version and exit
  --dry-run             Only show commands, don't actually do anything
  -i INPUTFILE, --inputfile INPUTFILE
                        A file containing targets, one per line
  -o OUTPUT_FILE, --output-file OUTPUT_FILE
                        output file containing all scanresults (default
                        analyze_hosts.output)

  --compact             Only log raw logfiles and alerts to file
  --queuefile QUEUEFILE
                        the queuefile
  --resume              Resume working on the queue
  --settings SETTINGS   Name of settings file to use (default
                        analyze_hosts.yml)
  --exit-code           When supplied, return exit code 1 when alerts are
                        discovered
  --force               Ignore / overwrite the queuefile
  --debug               Show debug information
  -v, --verbose         Be more verbose
  -q, --quiet           Do not show scan outputs on the console
  --allports            Run a full-blown nmap scan on all ports
  -n, --no-portscan     Do NOT run a nmap portscan
  -p PORT, --port PORT  Specific port(s) to scan
  --up                  Assume host is up (do not rely on ping probe)
  --udp                 Check for open UDP ports as well
  --framework           Analyze the website and run webscans
  --http                Check for various HTTP vulnerabilities (compression,
                        headers, trace)
  --compression         Check for webserver compression
  --headers             Check for various HTTP headers
  --trace               Check webserver for HTTP TRACE method
  --redirect            Check for insecure redirect
  --force-ssl           Enforce SSL/TLS check on all open ports
  --json JSON           Save output in JSON file
  --ssl                 Check for various SSL/TLS vulnerabilities
  --nikto               Run a nikto scan
  --sslcert             Download SSL certificate
  -w, --whois           Perform a whois lookup
  --proxy PROXY         Use proxy server (host:port)
  --timeout TIMEOUT     Timeout for requests in seconds (default 10)
  --threads THREADS     Maximum number of threads (default 5)
  --user-agent USER_AGENT
                        Custom User-Agent to use (default analyze_hosts)
  --password PASSWORD   Password for HTTP basic host authentication
  --username USERNAME   Username for HTTP basic host authentication
  --maxtime MAXTIME     Timeout for scans in seconds (default 600)


```

The script `analyze_hosts` automatically execute other scans (based on their
fingerprint or open ports):

```
droopescan
nikto
testssl.sh
WPscan
```

You can use the following environment variables (all uppercase) to specify the
tools if they cannot be found in the standard paths:

CURL, DROOPESCAN, NIKTO, OPENSSL, TESTSSL, WPSCAN

### Suppressing false positives

A settings file can be used (`--settings`) to configure or tweak scan parameters
per host / port combination. This allows you to suppress false positives in scan
results. Currently the Nikto `Plugins`, `Tuning` and `output` parameters are
supported, as well as a list of allowed / expected open ports, and testssl
parameters:

Example settings file:

```
targets:
  127.0.0.1:
    allowed_ports: [22, 80, 443]
    ports:
      - port: 80
        nikto_plugins: "@@ALL"
        nikto_tuning: "x1"
        nikto_output: "report.html"
      - port: 443
        testssl_untrusted: true
        testssl:
          - "--ccs-injection"
          - "--ticketbleed"
          - "--robot"

```

This will supply the `-Plugins '@@ALL' -Tuning 'x1' -output 'report.html'
parameters to Nikto, when port 80 is scanned.

Furthermore, it will not generate an alert when an open port other than port 22,
80 or 443 is found. By default, an alert will be generated if an open port other
than 80 or 443 is found.

There will no alert be generated if the SSL/TLS endpoint on port 443 contains an
untrusted (self-signed) certificate. And instead of all default tests, only
three SSL/TLS tests will be performed.

### JSON format

```
{
  "arguments": {
    "target": "1.2.3.1/30",
    "version": false,
    "dry_run": false,
    "inputfile": "0frnfb4e",
    "output_file": "output.txt,
    "compact": true,
    "queuefile": "analyze_hosts.queue",
    "resume": false,
    "force": false,
    "debug": false,
    "verbose": false,
    "quiet": false,
    "allports": false,
    "no_portscan": false,
    "port": null,
    "up": false,
    "udp": false,
    "framework": false,
    "http": true,
    "json": "results.json",
    "ssl": true,
    "nikto": true,
    "sslcert": false,
    "trace": false,
    "whois": false,
    "proxy": null,
    "timeout": true,
    "threads": 5,
    "user_agent": "analyze_hosts",
    "password": null,
    "username": null,
    "maxtime": 1200,
    "testssl.sh": true,
    "curl": false,
    "wpscan": true,
    "droopescan": true,
    "nmap": true,
    "nmap_arguments": "-sV --open -sS --script=banner,dns-nsid,dns-recursion,http-cisco-anyconnect,http-php-version,http-title,http-trace,ntp-info,ntp-monlist,nbstat,rdp-enum-encryption,rpcinfo,sip-methods,smb-os-discovery,smb-security-mode,smtp-open-relay,ssh2-enum-algos,vnc-info,xmlrpc-methods,xmpp-info"
  },
  "date_start": "2020-05-26 31:33:06"
  "results": {
    "1.2.3.1": {
      "ports": [
        53
      ]
    },
    "1.2.3.2": {
      "ports": []
    },
    "1.2.3.3": {
      "ports": [
        80,
        443
      ],
      "alerts": [
        ":443  LUCKY13 (CVE-2013-0169), experimental     potentially VULNERABLE, uses cipher block chaining (CBC) ciphers with TLS. Check patches"
      ]
    },
    "1.2.3.4": {
      "ports": [
        80,
        443
      ],
      "alerts": [
        ":443 + OSVDB-3092: /download/: This might be interesting...",
        ":443 + OSVDB-3092: /status/: This might be interesting...",
        ":443 + OSVDB-4231: /DHrPp.xml: Coccoon from Apache-XML project reveals file system path in error messages.",
        ":443 + OSVDB-3092: /upgrade.php: upgrade.php was found."
      ]
    }
  },
  "date_finish": "2020-05-26 31:33:07"
}
```

## display_results.py

A little helper script that formats the scan results nicely, so that scan
results can easily be reviewed.

```
usage: display_results.py [-h] [--info] [--version] [inputfile]

display_results version 0.0.1 - displays scan results nicely

positional arguments:
  inputfile   A JSON file containing scan results

optional arguments:
  -h, --help  show this help message and exit
  --info      Show also informational items
  --version   Show version and exit

```

## analyze-hosts.sh

A simple wrapper script around several open source security tools to simplify
scanning of hosts for network vulnerabilities. The script lets you analyze one
or several hosts for common misconfiguration vulnerabilities and weaknesses. The
main objectives for the script is to make it as easy as possible to perform
generic security tests, without any heavy prerequisites, make the output as
informative as possible, and use open source tools....

- [cipherscan](https://github.com/jvehent/cipherscan)
- curl
- nmap
- [openssl-1.0.2-chacha](https://github.com/PeterMosmans/openssl/tree/1.0.2-chacha/)
- [whatweb](https://github.com/urbanadventurer/WhatWeb)

* whois

### Examples

#### SSL certificates

```
./analyze_hosts.sh --sslcert www.google.com
```

Shows details of a certificate, like the issuer and subject. It warns when
certificate is expired or when the certificate is a certificate authority.

Example output:

```
trying to retrieve SSL x.509 certificate on www.google.com:443... received
issuer=
    countryName               = US
    organizationName          = Google Inc
    commonName                = Google Internet Authority G2
subject=
    countryName               = US
    stateOrProvinceName       = California
    localityName              = Mountain View
    organizationName          = Google Inc
    commonName                = www.google.com
OK: certificate is valid between 16-07-2014 and 14-10-2014
```

#### SSL/TLS ciphers

```
./analyze_hosts.sh --ssl --sslports 443 -v www.microsoft.com
```

Checks which ciphers are allowed. It warns when insecure ciphers are being used.
By default the ports 443, 465, 993, 995 and 3389 and are checked. You can
specify the ports by using --sslports The -v flag outputs all results, regardles
of the message type.

Example output:

```
prio  ciphersuite   protocols    pfs_keysize
1     RC4-MD5       SSLv3,TLSv1
2     RC4-SHA       SSLv3,TLSv1
3     DES-CBC3-SHA  SSLv3,TLSv1
4     AES256-SHA    TLSv1
5     AES128-SHA    TLSv1

Certificate: UNTRUSTED, 2048 bit, sha1WithRSAEncryption signature
trying to retrieve SSL x.509 certificate on www.microsoft.com:443... received
issuer=
    domainComponent           = com
    domainComponent           = microsoft
    domainComponent           = corp
    domainComponent           = redmond
    commonName                = MSIT Machine Auth CA 2
subject=
    countryName               = US
    stateOrProvinceName       = WA
    localityName              = Redmond
    organizationName          = Microsoft Corporation
    organizationalUnitName    = MSCOM
    commonName                = www.microsoft.com
OK: certificate is valid between 12-01-2013 and 12-01-2015

performing nmap sslscan on www.microsoft.com ports 443...
Nmap scan report for www.microsoft.com (134.170.184.133)
Host is up (0.15s latency).
PORT    STATE SERVICE
443/tcp open  https
| ssl-enum-ciphers:
|   SSLv3:
|     ciphers:
|       TLS_RSA_WITH_3DES_EDE_CBC_SHA - strong
|       TLS_RSA_WITH_RC4_128_MD5 - strong
|       TLS_RSA_WITH_RC4_128_SHA - strong
|     compressors:
|       NULL
|   TLSv1.0:
|     ciphers:
|       TLS_RSA_WITH_3DES_EDE_CBC_SHA - strong
|       TLS_RSA_WITH_AES_128_CBC_SHA - strong
|       TLS_RSA_WITH_AES_256_CBC_SHA - strong
|       TLS_RSA_WITH_RC4_128_MD5 - strong
|       TLS_RSA_WITH_RC4_128_SHA - strong
|     compressors:
|       NULL
|_  least strength: strong
```

### usage

```
./analyze_hosts.sh [OPTION]... [HOST]

Scanning options:
 -a, --all               perform all basic scans
     --max               perform all advanced scans (more thorough)
 -b, --basic             perform basic scans (fingerprint, ssl, trace)
                         results of HOST matches regexp FILTER
     --dns               test for recursive query and version string
 -f                      perform web fingerprinting (all webports)
     --fingerprint       perform all web fingerprinting methods
 -h, --header            show webserver headers (all webports)
 -n, --nikto             nikto webscan (all webports)
 -p                      nmap portscan (top 1000 TCP ports)
     --ports             nmap portscan (all ports, TCP and UDP)
     --redirect          test for open secure redirect
 -s                      check SSL configuration
     --ssl               perform all SSL configuration checks
     --sslcert           show details of SSL certificate
     --timeout=SECONDS   change timeout for tools (default 60)
     --ssh               perform SSH configuration checks
 -t                      check webserver for HTTP TRACE method
     --trace             perform all HTTP TRACE method checks
 -w, --whois             perform WHOIS lookup for (hostname and) IP address
 -W                      confirm WHOIS results before continuing scan
     --filter=FILTER     only proceed with scan of HOST if WHOIS
     --wordlist=filename scan webserver for existence of files in filename

Port selection (comma separated list):
     --webports=PORTS    use PORTS for web scans (default 80,443,8080)
     --sslports=PORTS    use PORTS for ssl scans (default 443,465,993,995,3389)

Logging and input file:
 -d, --directory=DIR     location of temporary files (default /tmp)
 -i, --inputfile=FILE    use a file containing hostnames
 -l, --log               log each scan in a separate logfile
     --nocolor           don't use fancy colors in screen output
 -o, --output=FILE       concatenate all OK and WARNING messages into FILE
 -q, --quiet             quiet
 -v, --verbose           show server responses

Default programs:
     --cipherscan=FILE   location of cipherscan (default cipherscan)
     --openssl=FILE      location of openssl (default openssl)

 -u                      update this script (if it's a cloned repository)
     --update            force update (overwrite all local modifications)
     --version           print version information and exit

                         BLUE: INFO, status messages
                         GREEN: OK, secure settings
                         RED: WARNING, possible vulnerabilities

 [HOST] can be a single (IP) address, an IP range, eg. 127.0.0.1-255
 or multiple comma-separated addressess
```

### history

- since 0.88: preliminary support for starttls xmpp

## test_ssl_handhake.sh

A script to test TLS/SSL handshakes with. Several bugtests are included:

- 128 cipherlimit when using tls1_2 protocol
- aRSA cipher order
- version intolerant server

\$ ./test_ssl_handshake.sh

```
      (c) 2014 Peter Mosmans [Go Forward]
      Licensed under the GPL 3.0

tests SSL/TLS handshakes (for known bugs)

usage: ./test_ssl_handshake.sh target[:port] [start]

     [start]            number of ciphers to start with (default 125)
     --ciphers=FILE     a file containing a list which ciphers to use
     --cipherstring=CIPHERSTRING
                        cipherstring (default )
     -f | --force       continue even though the error has been detected
     --iterate          iterate through all the ciphers instead of adding
     --openssl=FILE     location of openssl (default )
     -v | --verbose     be more verbose, please

 tests:
     --128              test for 128 cipherlimit
     --intolerant       test for version intolerant server
     --rsa              test for RSA order sensitivity

     by default, all tests will be performed
```
