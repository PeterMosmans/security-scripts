# security-scripts

A collection of security related Bash shell scripts.
No fancy programming framework required, all that is needed is a Bash shell.


## analyze-hosts.sh
A simple wrapper script around several open source security tools to simplify scanning of hosts for network vulnerabilities. The script lets you analyze one or several hosts for common misconfiguration vulnerabilities and weaknesses.
The main objectives for the script is to make it as easy as possible to perform generic security tests, without any heavy prerequisites, make the output as informative as possible, and use open source tools....

* [cipherscan](https://github.com/jvehent/cipherscan)
* curl
* nmap
* [openssl](https://github.com/PeterMosmans/openssl/tree/1.0.2-chacha/)
* [whatweb](https://github.com/urbanadventurer/WhatWeb)


### Examples
#### SSL certificates
```
./analyze_hosts.sh --sslcert www.google.com
```

Shows details of a certificate, like the issuer and subject. It warns when certificate is expired or when the certificate is a certificate authority.

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
By default the ports 443, 465, 993, 995 and 3389 and are checked. You can specify the ports by using --sslports
The -v flag outputs all results, regardles of the message type.

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

```

### history
* since 0.88: preliminary support for starttls xmpp

## test_ssl_handhake.sh
A script to test TLS/SSL handshakes with. Several bugtests are included:
- 128 cipherlimit when using tls1_2 protocol
- aRSA cipher order
- version intolerant server

$ ./test_ssl_handshake.sh
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
