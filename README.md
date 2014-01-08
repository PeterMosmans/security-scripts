security-scripts
================

A collection of security related Bash shell scripts.
No fancy programming framework required, all that is needed is a Bash shell.

analyze-hosts.sh
----------------
Acts as a wrapper around several other open source tools. Can be used to verify the security of hosts
Performs webscans, portscans, web fingerprinting, checks webserver and SSL/TLS configuration

Uses curl for TRACE checks, nikto for webscans, nmap for portscans and several other checks, sslscan for SSL/TLS configuration checks and whatweb for fingerprinting. 

```
 usage: analyze_hosts.sh [OPTION]... [HOST]

Scanning options:
 -a, --all               perform all basic scans
     --max               perform all advanced scans (more thorough)
 -b, --basic             perform basic scans (fingerprint, ssl, trace)
     --filter=FILTER     only proceed with scan of HOST if WHOIS
                         results of HOST matches regexp FILTER
 -f, --fingerprint       perform web fingerprinting
 -n                      nikto webscan
     --nikto             nikto webscan (port 80 and port 443)
 -p, --ports             nmap portscan
     --allports          nmap portscan (all ports)
 -s                      check SSL configuration
     --ssl               alternative check of SSL configuration
 -t                      check webserver for HTTP TRACE method
     --trace             extra check for HTTP TRACE method
 -w, --whois             perform WHOIS lookup
 -W                      confirm WHOIS results before continuing scan

Logging and input file:
 -d, --directory=DIR     location of temporary files (default /tmp)
 -i, --inputfile=FILE    use a file containing hostnames
 -l, --log               log each scan in a separate logfile
 -o, --output=FILE       concatenate all results into FILE
 -q, --quiet             quiet
 -v, --verbose           show server responses

     --version           print version information and exit

                         BLUE: status messages
                         GREEN: secure settings
                         RED: possible vulnerabilities

 [HOST] can be a single (IP) address or an IP range, eg. 127.0.0.1-255

example: analyze_hosts.sh -a --filter Amazon www.google.com
```