#!/bin/bash

# analyze_hosts - Scans one or more hosts on security vulnerabilities
#
# Copyright (C) 2012-2014 Peter Mosmans
#                         <support AT go-forward.net>
#
# This source code (shell script) is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# TODO: - preflight check on hostname 
#       - add option to only list commands, don't execute them
#       - add no-color option
#       - remove color from sslscan output
#       - make webports configurable

NAME="analyze_hosts"
VERSION="0.47 (09-01-2014)"

# statuses
declare -c ERROR=-1
declare -c UNKNOWN=0
declare -c OPEN=1
declare -c UP=1
declare -c NONEWLINE=1
declare -c BASIC=1
declare -c ADVANCED=2
declare -c ALTERNATIVE=4

# logging and verboseness
declare -c QUIET=1
declare -c STDOUT=2
declare -c VERBOSE=4
declare -c LOGFILE=8
declare -c RAWLOGS=16
declare -c SEPARATELOGS=32

# scantypes, defaults
declare -i fingerprint=$UNKNOWN
declare -i nikto=$UNKNOWN
declare -i portscan=$UNKNOWN
declare -i sslscan=$UNKNOWN
declare -i trace=$UNKNOWN
declare -i whois=$UNKNOWN
declare -i hoststatus=$UNKNOWN
declare -i loglevel=$STDOUT
declare -i portstatus=$UNKNOWN
declare -c WEBPORTS=80,443

datestring=$(date +%Y-%m-%d)
workdir=/tmp

# temporary files
umask 177
portselection=$(mktemp -q $NAME.XXXXXXX --tmpdir=/tmp)
tmpfile=$(mktemp -q $NAME.XXXXXXX --tmpdir=/tmp)

# colours
declare -c BLUE='\E[1;49;96m'
declare -c LIGHTBLUE='\E[2;49;96m'
declare -c RED='\E[1;49;31m'
declare -c LIGHTRED='\E[2;49;31m'
declare -c GREEN='\E[1;49;32m'
declare -c LIGHTGREEN='\E[2;49;32m'

trap abortscan INT
trap cleanup QUIT

# define functions
prettyprint() {
    if (($loglevel&$QUIET)); then return; fi
    echo -ne $2
    if [[ "$3" == "$NONEWLINE" ]]; then
        echo -n "$1"
    else
        echo "$1"
    fi
    tput sgr0
}

usage() {
    prettyprint "$NAME version $VERSION" $BLUE
    prettyprint "      (c) 2012-2014 Peter Mosmans [Go Forward]" $LIGHTBLUE
    prettyprint "      Licensed under the Mozilla Public License 2.0" $LIGHTBLUE
    echo ""
    echo " usage: $0 [OPTION]... [HOST]"
    echo ""
    echo "Scanning options:"
    echo " -a, --all               perform all basic scans" 
    echo "     --max               perform all advanced scans (more thorough)" 
    echo " -b, --basic             perform basic scans (fingerprint, ssl, trace)" 
    echo "     --filter=FILTER     only proceed with scan of HOST if WHOIS"
    echo "                         results of HOST matches regexp FILTER"
    echo " -f                      perform web fingerprinting (all webports)"
    echo "     -- fingerprint      advanced web fingerprinting"
    echo " -h, --header            show webserver headers (all webports)"
    echo " -n, --nikto             nikto webscan (all webports)"
    echo " -p, --ports             nmap portscan"
    echo "     --allports          nmap portscan (all ports)"
    echo " -s                      check SSL configuration"
    echo "     --ssl               alternative check of SSL configuration"
    echo " -t                      check webserver for HTTP TRACE method"
    echo "     --trace             extra check for HTTP TRACE method"
    echo " -w, --whois             perform WHOIS lookup"
    echo " -W                      confirm WHOIS results before continuing scan"
    echo ""
    echo "Logging and input file:"
    echo " -d, --directory=DIR     location of temporary files (default /tmp)"
    echo " -i, --inputfile=FILE    use a file containing hostnames"
    echo " -l, --log               log each scan in a separate logfile"
    echo " -o, --output=FILE       concatenate all results into FILE"
    echo " -q, --quiet             quiet"
    echo " -v, --verbose           show server responses"
    echo ""
    echo "     --version           print version information and exit"
    echo ""
    prettyprint "                         BLUE: status messages" $BLUE
    prettyprint "                         GREEN: secure settings" $GREEN
    prettyprint "                         RED: possible vulnerabilities" $RED
    echo ""
    echo " [HOST] can be a single (IP) address or an IP range, eg. 127.0.0.1-255"
    echo ""
    echo "example: $0 -a --filter Amazon www.google.com"
    echo ""
}

# setlogfilename (name)
# sets the GLOBAL variable logfile and tool
setlogfilename() {
    logfile=${target}_$1_${datestring}.txt
    if type $1 >/dev/null 2>&1; then
        tool=$1
    else
        prettyprint "ERROR: The program $1 could not be found - aborting test" $RED
        tool=$ERROR
    fi
}

# purgelogs logfile [VERBOSE]
purgelogs() {
    if [[ -f "$logfile" ]]; then
        if (($loglevel&$VERBOSE)) || [[ $LOGFILE=="$1" ]]; then
            if [[ -s "$logfile" ]]; then 
                showstatus "$(cat $logfile)"
                showstatus ""
            fi
        fi
        if (($loglevel&$RAWLOGS)); then
            grep -v '^[#%]' $logfile >> $outputfile
        fi
        if !(($loglevel&$SEPARATELOGS)); then rm $logfile 1>/dev/null 2>&1; fi
    fi
    tool=$ERROR
}

# showstatus message [COLOR|NONEWLINE|LOGFILE]
showstatus() {
#    if [[ -z "$1" ]]; then return; fi
    if [[ ! -z "$2" ]]; then
        case "$2" in
            $LOGFILE)
                if (($loglevel&$LOGFILE)); then echo "$1" >> $outputfile; fi;;
            $NONEWLINE)
                if !(($loglevel&$QUIET)); then echo -n "$1"; fi
                if (($loglevel&$LOGFILE)); then echo -n "$1" >> $outputfile; fi;;
            (*) 
                prettyprint "$1" $2 $3
                if (($loglevel&$LOGFILE)); then echo "$1" >> $outputfile; fi;;
        esac
    else
        if !(($loglevel&$QUIET)); then echo "$1"; fi
        if (($loglevel&$LOGFILE)); then echo "$1" >> $outputfile; fi
    fi
}

startup() {
    flag=$OPEN
    trap cleanup EXIT
    showstatus "$NAME version $VERSION starting on $(date +%d-%m-%Y' at '%R)"
    if (($loglevel&$LOGFILE)); then
        if [[ -n $appendfile ]]; then
            showstatus "appending to existing file $outputfile"
        else
            showstatus "logging to $outputfile"
        fi
    fi
    showstatus "scanparameters: ${fulloptions//-- /}" $LOGFILE
    if [[ -n "$workdir" ]]; then pushd $workdir 1>/dev/null; fi
}

version() {
    curl --version
    echo ""
    nikto -Version
    echo ""
    nmap -V
    echo ""
    sslscan --version
    echo ""
    prettyprint "$NAME version $VERSION" $BLUE
    prettyprint "      (c) 2013-2014 Peter Mosmans [Go Forward]" $LIGHTBLUE
    prettyprint "      Licensed under the Mozilla Public License 2.0" $LIGHTBLUE
    echo ""
}

checkifportopen() {
    portstatus=$UNKNOWN
    if [[ -s "$portselection" ]]; then
        portstatus=$ERROR
        grep -q " $1/open/" $portselection && portstatus=$OPEN
    fi
}

do_sslscan() {
    checkifportopen 443
    if (($portstatus==$ERROR)); then
        showstatus "port 443 closed" $BLUE
        return
    fi

    setlogfilename "sslscan"
    if (($sslscan==$BASIC)) && (($tool!=$ERROR)); then
       showstatus "performing sslscan..."
       sslscan --no-failed $target:443 > $logfile
       grep -qe "ERROR: Could not open a connection to host $target on port 443" $logfile||portstatus=$ERROR
       if (($portstatus==$ERROR)) ; then
           showstatus "could not connect to port 443" $BLUE
       else
           showstatus "$(awk '/(Accepted).*(SSLv2|EXP|MD5|NULL| 40| 56)/{print $2,$3,$4,$5}' $logfile)" $RED
       fi
       purgelogs
    fi

    if (($sslscan>=$ADVANCED)); then
        showstatus "performing nmap sslscan..."
        setlogfilename "nmap"
        nmap -p 443,8080 --script ssl-enum-ciphers --open -oN $logfile $target 1>/dev/null 2>&1 </dev/null
        if [[ -s $logfile ]] ; then
            showstatus "$(awk '/( - )(broken|weak|unknown)/{print $2}' $logfile)" $RED
        else
            showstatus "could not connect to port 443" $BLUE
        fi
        purgelogs
    fi
}

do_fingerprint() {
    if (($fingerprint==$BASIC)) || (($fingerprint==$ADVANCED)); then
        setlogfilename "whatweb"
        if (($tool!=$ERROR)); then
            for port in ${WEBPORTS//,/ }; do
                setlogfilename "whatweb"
                showstatus "performing whatweb fingerprinting on port $port... "
                if (($port!=443)); then
                    whatweb -a3 --color never http://$target:$port --log-brief $logfile 1>/dev/null 2>&1
                else
                    whatweb -a3 --color never https://$target:$port --log-brief $logfile 1>/dev/null 2>&1
                fi
                purgelogs $VERBOSE
            done
        fi
    fi

    if (($fingerprint==$ADVANCED)) || (($fingerprint==$ALTERNATIVE)); then
        setlogfilename "curl"
        if (($tool!=$ERROR)); then
            for port in ${WEBPORTS//,/ }; do
                setlogfilename "curl"
                checkifportopen $port
                if (($portstatus==$ERROR)); then
                    showstatus "port $port closed" $GREEN
                else
                    showstatus "retrieving headers from port $port... " $NONEWLINE
                    if (($port!=443)); then
                        curl -q --insecure -m 10 --dump-header $logfile http://$target:$port 1>/dev/null 2>&1 || prettyprint "could not connect to port $port" $BLUE $NONEWLINE
                    else
                        curl -q --insecure -m 10 --dump-header $logfile https://$target:$port 1>/dev/null 2>&1 || prettyprint "could not connect to port $port" $BLUE $NONEWLINE
                    fi
                    showstatus ""
                    purgelogs $VERBOSE
                fi
            done
        fi
    fi
}

do_nikto() {
    setlogfilename "nikto"
    if (($tool!=$ERROR)); then
        if [[ $target =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
            showstatus "FQDN preferred over IP address"
        fi
        for port in ${WEBPORTS//,/ }; do
            setlogfilename "nikto"
            checkifportopen $port
            if (($portstatus==$ERROR)); then
                showstatus "port $port closed" $GREEN
            else
                showstatus "performing nikto webscan on port $port... "
                nikto -host $target:$port -Format txt -output $logfile 1>/dev/null 2>&1 </dev/null
            fi
            purgelogs $VERBOSE
        done
    fi
}

do_portscan() {
    setlogfilename "nmap"
    hoststatus=$UNKNOWN
    if (($portscan>=$ADVANCED)); then
        showstatus "performing advanced nmap portscan (all ports)... " $NONEWLINE
        nmap --open -p- -sV -sC -oN $logfile -oG $portselection $target 1>/dev/null 2>&1 </dev/null
    else
        showstatus "performing nmap portscan... " $NONEWLINE
        nmap --open -sV -sC -oN $logfile -oG $portselection $target 1>/dev/null 2>&1 </dev/null
    fi
    grep -q "0 hosts up" $portselection || hoststatus=$UP
    if (($hoststatus<$UP)); then
        showstatus "host down" $BLUE
    else
        showstatus "host is up" $BLUE
    fi
    # show logfiles regardless of verbose level
    previousloglevel=$loglevel
    let "loglevel=loglevel|$VERBOSE"
    purgelogs
    loglevel=$previousloglevel
}

do_trace() {
    setlogfilename "curl"
    if (($tool!=$ERROR)); then
        for port in ${WEBPORTS//,/ }; do
            setlogfilename "curl"
            checkifportopen $port
            if (($portstatus==$ERROR)); then
                showstatus "port $port closed" $GREEN
            else
                showstatus "trying TRACE method on port $port... " $NONEWLINE
                curl -q --insecure -i -m 30 -X TRACE -o $logfile http://$target/ 1>/dev/null 2>&1
                if [[ -s $logfile ]]; then
                    status=$(awk 'NR==1 {print $2}' $logfile)
                    if [[ $status -le 302 ]]; then
                        showstatus "TRACE enabled on port $port" $RED
                    else
                        showstatus "disabled (HTTP statuscode $status)" $GREEN
                    fi
                else
                    showstatus "could not connect to port $port" $GREEN
                fi
            fi
            purgelogs
        done
    fi

    if (($trace>=$ADVANCED)); then
        setlogfilename "nmap"
        showstatus "trying nmap TRACE method on ports $WEBPORTS... " $NONEWLINE
        nmap -p$WEBPORTS --open --script http-trace -oN $logfile $target 1>/dev/null 2>&1 </dev/null
	if [[ -s $logfile ]]; then
            status="$(awk '{FS="/";a[++i]=$1}/TRACE is enabled/{print "TRACE enabled on port "a[NR-1]}' $logfile)"
            if [[ -z "$status" ]]; then
                showstatus "disabled"  $GREEN
            else
                showstatus "$status" $RED
            fi
        fi
        purgelogs
    fi
}

execute_all() {
    if (($whois>=$BASIC)); then
        local nomatch=
        local ip=
        setlogfilename whois
        if [[ $target =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
            ip=$target
            local reverse=$(host $target|awk '{print $5}')
            if [[ "$reverse" == "3(NXDOMAIN)" ]]; then
                showstatus "$target does not resolve to a PTR record" 
            else
                showstatus "$target resolves to " $NONEWLINE
                showstatus $reverse $BLUE
            fi
        else
            ip=$(host -c IN $target|awk '/address/{print $4}')
            if [[ ! -n "$ip" ]]; then
                showstatus "$target does not resolve to an IP address - aborting scans" $RED
                purgelogs
                return
            else
                showstatus "$target resolves to $ip" 
            fi
        fi
        whois -H $ip > $logfile
        showstatus "$(grep -iE '^(inetnum|netrange|netname|nettype|descr|orgname|orgid|originas|country|origin):(.*)[^ ]$' $logfile)"
        if [[ -n "$filter" ]]; then
            if grep -qiE "^(inetnum|netrange|netname|nettype|descr|orgname|orgid|originas|country|origin):.*($filter)" $logfile; then
                showstatus "WHOIS info matches $filter - continuing scans" $GREEN
            else
                showstatus "WHOIS info doesn't match $filter - aborting scans on $target" $RED
                purgelogs
                return
            fi
        fi

        if (($whois&$ADVANCED)); then
            read -p "press any key to continue: " failsafe < stdin
        fi
        purgelogs
    fi

    if (($portscan>=$BASIC)); then do_portscan; fi
    if (($fingerprint>=$BASIC)); then do_fingerprint; fi
    if (($nikto>=$BASIC)); then do_nikto; fi
    if (($sslscan>=$BASIC)); then do_sslscan; fi
    if (($trace>=$BASIC)); then do_trace; fi
    if [[ ! -n "$portselection" ]]; then rm $portselection 1>/dev/null 2>&1; fi
}

looptargets() {
    if [[ -s "$inputfile" ]]; then
        total=$(wc -l < $inputfile)
        counter=1
        while read target; do
            showstatus ""
            showstatus "working on " $NONEWLINE
            showstatus "$target" $BLUE $NONEWLINE
            showstatus " ($counter of $total)"
            execute_all
            let counter=$counter+1
        done < "$inputfile"
    else
        showstatus ""
        showstatus "working on " $NONEWLINE
        showstatus "$target" $BLUE
        execute_all
    fi
}

abortscan() {
    flag=$ERROR
     if (($tool!=$ERROR)); then
         showstatus ""
         prettyprint "$tool interrupted..." $RED
         purgelogs
         prettyprint "press Ctrl-C again to abort scan, or wait 10 seconds to resume" $BLUE
         sleep 10 && flag=$OPEN
     fi
     if ((flag==$ERROR)); then exit 1; fi
}

cleanup() {
    trap '' EXIT INT QUIT
    if [[ ! -z $tool ]] && (($ERROR!=$tool)); then 
        prettyprint "$tool interrupted..." $RED
        purgelogs
    fi
    showstatus "cleaning up temporary files..."
    if [[ -e "$portselection" ]]; then rm "$portselection" ; fi
    if [[ -e "$tmpfile" ]]; then rm "$tmpfile" ; fi
    if [[ -n "$workdir" ]]; then popd 1>/dev/null ; fi
    showstatus "ended on $(date +%d-%m-%Y' at '%R)"
    exit
}

if ! options=$(getopt -o ad:fhi:lno:pqstvwWy -l allports,directory:,filter:,fingerprint,header,inputfile:,log,max,nikto,output:,ports,quiet,ssl,trace,version,whois -- "$@") ; then
    usage
    exit 1
fi 

eval set -- $options
if [[ "$#" -le 1 ]]; then
    usage
    exit 1
fi

fulloptions=$@

while [[ $# -gt 0 ]]; do
    case $1 in
        -a|--all) 
            fingerprint=$BASIC
            nikto=$BASIC
            portscan=$BASIC
            sslscan=$BASIC
            trace=$BASIC
            whois=$BASIC;;
        --allports) portscan=$ADVANCED;;
        -f) fingerprint=$BASIC;;
        --fingerprint) fingerprint=$ADVANCED;;
        -h|--header) fingerprint=$ALTERNATIVE;;
        -d|--directory) workdir=$2
                        if [[ -n "$workdir" ]]; then 
                            [[ -d $workdir ]] && mkdir $workdir 1>/dev/null
                        fi
                        shift ;;
        --filter) filter="$2"
                  whois=$ADVANCED
                  shift ;;
        -i|--inputfile) inputfile="$2"
                        if [[ ! -s "$inputfile" ]]; then
                            echo "error: cannot find $inputfile" 
                            exit 1
                        fi           
                        shift ;;
        -l) log="TRUE";;
        --max)             
            fingerprint=$ADVANCED
            nikto=$ADVANCED
            portscan=$ADVANCED
            sslscan=$ADVANCED
            trace=$ADVANCED
            whois=$ADVANCED;; 
        -n) nikto=$BASIC;;
        --nikto) nikto=$ADVANCED;;
        -o|--output)
            let "loglevel=loglevel|$LOGFILE"
            outputfile=$2
            if [[ ! $outputfile =~ ^/ ]]; then 	        
                outputfile=$(pwd)/$outputfile
            fi
            [[ -s $outputfile ]] && appendfile=1
            shift ;;
        -p|--ports) portscan=$BASIC;;
        -q|--quiet) let "loglevel=loglevel|$QUIET";;
        -s) sslscan=$BASIC;;
        --ssl) sslscan=$ADVANCED;;
        -t) trace=$BASIC;;
        --trace) trace=$ADVANCED;;
        -v) let "loglevel=loglevel|$VERBOSE";;
        --version) version;
                   exit 0;;
        -w|--whois) whois=$BASIC;;
        -W) let "whois=whois|$ADVANCED";;
        (--) shift; 
             break;;
        (-*) echo "$0: unrecognized option $1" 1>&2; exit 1;;
        (*) break;;
    esac
    shift
done

if ! type nmap >/dev/null 2>&1; then
    prettyprint "ERROR: the program nmap is needed but could not be found" $RED
    exit
fi

if [[ ! -s "$inputfile" ]]; then
    if [[ ! -n "$1" ]]; then
        echo "Nothing to do... no target specified"
        exit
    fi
    if [[ $1 =~ -.*[0-9]$ ]]; then
        nmap -nsL $1 2>/dev/null|awk '/scan report/{print $5}' >$tmpfile
        inputfile=$tmpfile
    fi
    target=$1
fi

startup
looptargets
