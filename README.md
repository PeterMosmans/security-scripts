security-scripts
================

A collection of security related Bash shell scripts.
No fancy programming framework required, all that is needed is a Bash shell.


analyze-hosts.sh
----------------
A simple wrapper script around several open source security tools to simplify scanning of hosts for network vulnerabilities. The script lets you analyze one or several hosts for common misconfiguration vulnerabilities and weaknesses.
The main objectives for the script is to make it as easy as possible to perform generic security tests, without any heavy prerequisites, make the output as informative as possible, and use open source tools....

* [cipherscan](https://github.com/jvehent/cipherscan)
* curl
* nmap
* [openssl](https://github.com/PeterMosmans/openssl/tree/1.0.2-chacha/)
* [whatweb](https://github.com/urbanadventurer/WhatWeb)


```
 usage: ./analyze_hosts.sh [OPTION]... [HOST]

Scanning options:
 -a, --all               perform all basic scans
     --max               perform all advanced scans (more thorough)
 -b, --basic             perform basic scans (fingerprint, ssl, trace)
                         results of HOST matches regexp FILTER
     --dns               test for recursive query
 -f                      perform web fingerprinting (all webports)
     --fingerprint       perform all web fingerprinting methods
 -h, --header            show webserver headers (all webports)
 -n, --nikto             nikto webscan (all webports)
 -p                      nmap portscan (top 1000 ports)
     --ports             nmap portscan (all ports)
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
 -o, --output=FILE       concatenate all results into FILE
 -q, --quiet             quiet
 -v, --verbose           show server responses

Default programs:
     --cipherscan=FILE   location of cipherscan (default /usr/local/bin/cipherscan/cipherscan)
     --openssl=FILE      location of openssl (default /usr/bin/openssl)

 -u                      update this script (if it's a cloned repository)
     --update            force update (overwrite all local modifications)
     --version           print version information and exit

                         BLUE: status messages
                         GREEN: secure settings
                         RED: possible vulnerabilities

 [HOST] can be a single (IP) address, an IP range, eg. 127.0.0.1-255
 or multiple comma-separated addressess

example: ./analyze_hosts.sh -sslcert www.google.com

```