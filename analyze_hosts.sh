#!/bin/bash

# analyze_hosts - Scans one or more hosts on security vulnerabilities
#
# Copyright (C) 2012-2014 Peter Mosmans
#                         <support AT go-forward.net>
#
# This source code (shell script) is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# TODO: - add: option to only list commands, don't execute them
#       - add: make logging of output default
#       - add: grep on errors of ssh script output
#       - add: check installation (whether all tools are present)


NAME="analyze_hosts"
VERSION="0.78 (28-01-2014)"

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
declare -c NOLOGFILE=-1
declare -c QUIET=1
declare -c STDOUT=2
declare -c VERBOSE=4
declare -c LOGFILE=8
declare -c RAWLOGS=16
declare -c SEPARATELOGS=32

# scantypes, defaults
declare -i fingerprint=$UNKNOWN
declare -i dnstest=$UNKNOWN
declare -i nikto=$UNKNOWN
declare -i portscan=$UNKNOWN
declare -i sshscan=$UNKNOWN
declare -i sslscan=$UNKNOWN
declare -i trace=$UNKNOWN
declare -i whois=$UNKNOWN
declare -i webscan=$UNKNOWN
declare -i hoststatus=$UNKNOWN
declare -i loglevel=$STDOUT
declare -i portstatus=$UNKNOWN
declare -i timeout=30
declare webports=80,443
declare sslports=443,993,995
datestring=$(date +%Y-%m-%d)
workdir=/tmp

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
    (($loglevel&$QUIET)) && return
    [[ -z $nocolor ]] && echo -ne $2
    if [[ "$3" == "$NONEWLINE" ]]; then
        echo -n "$1"
    else
        echo "$1"
    fi
    [[ -z $nocolor ]] && tput sgr0
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
    echo "                         results of HOST matches regexp FILTER"
    echo "     --dns               test for recursive query"
    echo " -f                      perform web fingerprinting (all webports)"
    echo "     --fingerprint       perform all web fingerprinting methods"
    echo " -h, --header            show webserver headers (all webports)"
    echo " -n, --nikto             nikto webscan (all webports)"
    echo " -p                      nmap portscan (top 1000 ports)"
    echo "     --ports             nmap portscan (all ports)"
    echo " -s                      check SSL configuration"
    echo "     --ssl               perform all SSL configuration checks"
    echo "     --timeout=SECONDS   change timeout for sslscan (default=$timeout)"
    echo "     --ssh               perform SSH configuration checks"
    echo " -t                      check webserver for HTTP TRACE method"
    echo "     --trace             perform all HTTP TRACE method checks"
    echo " -w, --whois             perform WHOIS lookup for (hostname and) IP address"
    echo " -W                      confirm WHOIS results before continuing scan"
    echo "     --filter=FILTER     only proceed with scan of HOST if WHOIS"
    echo "     --wordlist=filename scan webserver for existence of files in filename"
    echo ""
    echo "Port selection (comma separated list):"
    echo "     --webports=PORTS    use PORTS for web scans (default $webports)"
    echo "     --sslports=PORTS    use PORTS for ssl scans (default $sslports)"
    echo ""
    echo "Logging and input file:"
    echo " -d, --directory=DIR     location of temporary files (default /tmp)"
    echo " -i, --inputfile=FILE    use a file containing hostnames"
    echo " -l, --log               log each scan in a separate logfile"
    echo "     --nocolor           don't use fancy colors in screen output" 
    echo " -o, --output=FILE       concatenate all results into FILE"
    echo " -q, --quiet             quiet"
    echo " -v, --verbose           show server responses"
    echo ""
    echo " -u                      update this script (if it's a cloned repository)"
    echo "     --update            force update (overwrite all local modifications)"
    echo "     --version           print version information and exit"
    echo ""
    prettyprint "                         BLUE: status messages" $BLUE
    prettyprint "                         GREEN: secure settings" $GREEN
    prettyprint "                         RED: possible vulnerabilities" $RED
    echo ""
    echo " [HOST] can be a single (IP) address, an IP range, eg. 127.0.0.1-255"
    echo " or multiple comma-separated addressess"
    echo ""
    echo "example: $0 -a --filter Amazon www.google.com"
    echo ""
}

# setlogfilename (name)
# sets the GLOBAL variable logfile and tool
setlogfilename() {
    logfile=$workdir/${target}_$1_${datestring}.txt
    if type $1 >/dev/null 2>&1; then
        tool=$1
    else
        showstatus "ERROR: The program $1 could not be found" $RED
        tool=$ERROR
    fi
}

# purgelogs logfile [LOGLEVEL]
# purges the current logfile
# if LOGLEVEL = VERBOSE then show log on screen
purgelogs() {
    local currentloglevel=$loglevel
    if [[ ! -z $1 ]]; then let "loglevel=loglevel|$1"; fi
    if [[ ! -z "$$logfile" ]] && [[ -f "$logfile" ]]; then
        if (($loglevel&$VERBOSE)); then
            if [[ -s "$logfile" ]]; then 
                showstatus "$(grep -v '^#' $logfile)"
                showstatus ""
            fi
        fi
        if (($loglevel&$RAWLOGS)); then
            grep -v '^[#%]' $logfile >> $outputfile
        fi
        if !(($loglevel&$SEPARATELOGS)); then rm $logfile 1>/dev/null 2>&1; fi
    fi
    tool=$ERROR
    loglevel=$currentloglevel
}

# showstatus message [COLOR] [LOGFILE|NOLOGFILE|NONEWLINE]
#                    COLOR: color of message
#                    LOGFILE: only write contents to logfile
#                    NOLOGFILE: don't log contents to logfile
#                    NONEWLINE: don't echo new line character

showstatus() {
    if [[ ! -z "$2" ]]; then
        case "$2" in
            $LOGFILE)
                (($loglevel&$LOGFILE)) && echo "$1" >> $outputfile;;
            $NOLOGFILE)
                !(($loglevel&$QUIET)) && echo "$1";;
            $NONEWLINE)
                !(($loglevel&$QUIET)) && echo -n "$1"
                (($loglevel&$LOGFILE)) && echo -n "$1" >> $outputfile;;
            (*) 
                prettyprint "$1" $2 $3
                (($loglevel&$LOGFILE)) && echo "$1" >> $outputfile;;
        esac
    else
        !(($loglevel&$QUIET)) && echo "$1"
        (($loglevel&$LOGFILE)) && echo "$1" >> $outputfile
    fi
}

do_update() {
    local realpath=$(dirname $(readlink -f $0))
    if [[ -d $realpath/.git ]]; then
        setlogfilename "git"
        if (($tool!=$ERROR)); then
            local status=$UNKNOWN
            showstatus "current version: $VERSION"
            pushd $realpath 1>/dev/null 2>&1
            if [[ ! -z "$1" ]]; then
                showstatus "forcing update, overwriting local changes"
                git fetch origin master 1>$logfile 2>&1
                git reset --hard FETCH_HEAD 1>>$logfile 2>&1
            else
                git pull 1>$logfile 2>&1
            fi
            grep -Eq "error: |Permission denied" $logfile && status=$ERROR
            grep -q "Already up-to-date." $logfile && status=$OPEN
            popd 1>/dev/null 2>&1
        else
            status=$ERROR
        fi
        case $status in
            $ERROR) showstatus "error updating $0" $RED;;
            $UNKNOWN) showstatus "succesfully updated to $(awk '{FS="\""}/^VERSION=/{print $2}' $0)" $GREEN;;
            $OPEN) showstatus "already running latest version" $BLUE;;
        esac
        purgelogs
        exit 0
    else
        showstatus "Sorry, this doesn't seem to be a git archive"
        showstatus "Please clone the repository using the following command: "
        showstatus "git clone https://github.com/PeterMosmans/security-scripts.git"
    fi;
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
    showstatus "scanparameters: $options" $LOGFILE
    [[ -n "$workdir" ]] && pushd $workdir 1>/dev/null 2>&1
}

version() {
    curl --version
    echo ""
    nikto -Version
    echo ""
    nmap -V
    echo ""
    sslscan --version|sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[m|K]//g"
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

do_dnstest() {
    setlogfilename "dig"
    if (($tool!=$ERROR)); then
        local status=$UNKNOWN
        local ports=53
        showstatus "trying recursive dig... " $NONEWLINE
        dig google.com @$target 1>$logfile 2>&1 </dev/null
        grep -q "ANSWER SECTION" $logfile && status=$OPEN
        if (($status==$OPEN)); then
            showstatus "recursion allowed" $RED
        else
            showstatus "no recursion or answer detected" $GREEN
        fi
        purgelogs
    fi
}

do_fingerprint() {
    if (($fingerprint==$BASIC)) || (($fingerprint==$ADVANCED)); then
        setlogfilename "whatweb"
        if (($tool!=$ERROR)); then
            for port in ${webports//,/ }; do
                setlogfilename "whatweb"
                showstatus "performing whatweb fingerprinting on $target port $port... "
                if [[ ! $sslports =~ $port ]]; then
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
            for port in ${webports//,/ }; do
                setlogfilename "curl"
                checkifportopen $port
                if (($portstatus==$ERROR)); then
                    showstatus "$target port $port closed" $BLUE
                else
                    showstatus "retrieving headers from $target port $port... " $NONEWLINE
                    if [[ ! $sslports =~ $port ]]; then
                        curl -A "$NAME" -q --insecure -m 10 --dump-header $logfile http://$target:$port 1>/dev/null 2>&1 || showstatus "could not connect to $target port $port" $BLUE $NONEWLINE
                    else
                        curl -A "$NAME" -q --insecure -m 10 --dump-header $logfile https://$target:$port 1>/dev/null 2>&1 || showstatus "could not connect to $target port $port" $BLUE $NONEWLINE
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
        [[ $target =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] && showstatus "FQDN preferred over IP address"
        for port in ${webports//,/ }; do
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
    purgelogs $VERBOSE
}

do_sshscan() {
    if (($sshscan>=$BASIC)); then
        setlogfilename "nmap"
        local portstatus=$UNKNOWN
        local ports=22
        showstatus "trying nmap SSH scan on $target port $ports... " $NONEWLINE
        nmap -Pn -p $ports --open --script banner.nse,sshv1.nse,ssh-hostkey.nse,ssh2-enum-algos.nse -oN $logfile $target 1>/dev/null 2>&1 </dev/null
        grep -q " open " $logfile && portstatus=$OPEN
        if (($portstatus<$OPEN)); then
            showstatus "port closed" $BLUE
            purgelogs
        else
            showstatus "port open" $BLUE
            purgelogs $VERBOSE
        fi
    fi
}

do_sslscan() {
    setlogfilename "sslscan"
    if (($sslscan>=$BASIC)) && (($tool!=$ERROR)); then
       for port in ${sslports//,/ }; do
           checkifportopen $port
           if (($portstatus==$ERROR)); then
               showstatus "port $port closed" $BLUE
               return
           fi
           showstatus "performing sslscan on $target port $port..." $NONEWLINE
           timeout $timeout sslscan --no-failed $target:$port|sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[m|K]//g" > $logfile || portstatus=$ERROR
           if [[ -s $logfile ]] ; then
               grep -qe "ERROR: Could not open a connection to host" $logfile&&portstatus=$ERROR
           else
               portstatus=$ERROR
           fi
           if (($portstatus==$ERROR)) ; then
               showstatus "could not connect" $BLUE
           else
               showstatus ""
               showstatus "$(awk '/(Accepted).*(SSLv2|EXP|MD5|NULL| 40| 56)/{print $2,$3,$4,$5}' $logfile)" $RED
           fi
           purgelogs
       done
    fi

    if (($sslscan>=$ADVANCED)); then
        showstatus "performing nmap sslscan on $target ports $sslports..."
        setlogfilename "nmap"
        nmap -p $sslports --script ssl-enum-ciphers --open -oN $logfile $target 1>/dev/null 2>&1 </dev/null
        if [[ -s $logfile ]] ; then
            showstatus "$(awk '/( - )(broken|weak|unknown)/{print $2}' $logfile)" $RED
        else
            showstatus "could not connect to $target ports $sslports" $BLUE
        fi
        purgelogs
    fi
}

do_trace() {
    setlogfilename "curl"
    if (($tool!=$ERROR)); then
        for port in ${webports//,/ }; do
            setlogfilename "curl"
            checkifportopen $port
            showstatus "trying TRACE method on $target port $port... " $NONEWLINE
            if (($portstatus==$ERROR)); then
                showstatus "$target port $port closed" $GREEN
            else
                local prefix="http://"
                [[ ! $sslports =~ $port ]] && prefix="--insecure https://"
                curl -q -s -A "$NAME" -i -m 30 -X TRACE -o $logfile $prefix$target:$port/ 1>/dev/null 2>&1
                if [[ -s $logfile ]]; then
                    status=$(awk 'NR==1 {print $2}' $logfile)
                    if (($status==200)); then
                        showstatus "TRACE enabled on port $port" $RED
                    else
                        showstatus "disabled (HTTP $status)" $GREEN
                    fi
                else
                    showstatus "could not connect" $BLUE
                fi
            fi
            purgelogs
        done
    fi

    if (($trace>=$ADVANCED)); then
        setlogfilename "nmap"
        showstatus "trying nmap TRACE method on ports $webports... " $NONEWLINE
        nmap -p$webports --open --script http-trace -oN $logfile $target 1>/dev/null 2>&1 </dev/null
	if [[ -s $logfile ]]; then
            status="$(awk '{FS="/";a[++i]=$1}/TRACE is enabled/{print "TRACE enabled on port "a[NR-1]}' $logfile)"
            if [[ -z "$status" ]]; then
                grep -q " open " $logfile && status=$OPEN
                if [[ $OPEN -eq $status ]]; then
                    showstatus "disabled"  $GREEN
                else
                    showstatus "could not connect" $BLUE
                fi
            else
                showstatus "$status" $RED
            fi
        fi
        purgelogs
    fi
}

do_webscan() {
    setlogfilename "curl"
    if (($tool!=$ERROR)); then
        for port in ${webports//,/ }; do
            showstatus "trying list $wordlist on $target port $port... "
            local prefix="http://"
            [[ ! $sslports =~ $port ]] && prefix="--insecure https://"
            if [[ -s "$wordlist" ]]; then
                total=$(grep -c . $wordlist)
                counter=1
                while read word; do
                    setlogfilename "curl"
                    curl -q -s -A "$NAME" -I -m 10 -o $logfile $prefix$target/$word </dev/null
                    if [[ -s $logfile ]]; then
                        status=$(awk 'NR==1 {print $2}' $logfile)
                        (($status==200)) && showstatus "$target:$port/$word exists" $RED
                    fi
                    purgelogs
                done < "$wordlist"
            else
                showstatus "could not open $wordlist" $RED
            fi
        done
    fi
}

execute_all() {
    portselection=$(mktemp -q $NAME.XXXXXXX --tmpdir=$workdir)
    if (($whois>=$BASIC)); then
        local nomatch=
        local ip=
        setlogfilename "whois"
        if [[ $target =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
            ip=$target
            local reverse=$(host $target|awk '{print $5}'|sed s'/[.]$//')
            if [[ "$reverse" == "3(NXDOMAIN)" ]] ; then
                showstatus "$target does not resolve to a PTR record" 
            else
                showstatus "$target resolves to " $NONEWLINE
                showstatus $reverse $BLUE
            fi
        else
            whois ${target#*.} > $logfile
            grep -q "No match for" $logfile && whois ${target%%*.} > $logfile
            # not all whois servers use the same formatting
            showstatus "$(grep -iE '^(registra|date|admin |tech|name server)(.*):(.*)[^ ]$' $logfile)"
            showstatus "$(awk '/Registrar( Technical Contacts)*:[ ]*$|(Domain )*[Nn]ameservers:[ ]*$|Technical:[ ]*$/{s=1}s; /^$/{s=0}' $logfile)"
            ip=$(host -c IN $target|awk '/address/{print $4}'|head -1)
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

        (($whois&$ADVANCED)) && read -p "press any key to continue: " failsafe < stdin
        purgelogs
    fi

    (($portscan>=$BASIC)) && do_portscan
    (($dnstest>=$BASIC)) && do_dnstest
    (($fingerprint>=$BASIC)) && do_fingerprint
    (($nikto>=$BASIC)) && do_nikto
    (($sshscan>=$BASIC)) && do_sshscan
    (($sslscan>=$BASIC)) && do_sslscan
    (($trace>=$BASIC)) && do_trace
    (($webscan>=$BASIC)) && do_webscan
    [[ -e "$portselection" ]] && rm $portselection 1>/dev/null 2>&1
}

looptargets() {
    if [[ -s "$inputfile" ]]; then
        total=$(grep -c . $inputfile)
        counter=1
        while read target; do
            if [[ ! -z "$target" ]]; then
               showstatus ""
               showstatus "working on " $NONEWLINE
               showstatus "$target" $BLUE $NONEWLINE
               showstatus " ($counter of $total)"
               let counter=$counter+1
               execute_all
            fi
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
         showstatus "interrupted $tool while working on $target..." $RED
         purgelogs
         prettyprint "press Ctrl-C again to abort scan, or wait 10 seconds to resume" $BLUE
         sleep 10 && flag=$OPEN
     fi
     ((flag==$ERROR)) && exit 1
}

cleanup() {
    trap '' EXIT INT QUIT
    if [[ ! -z $tool ]] && (($ERROR!=$tool)); then 
        showstatus "$tool interrupted..." $RED
        purgelogs
    fi
    showstatus "cleaning up temporary files..."
    [[ -e "$portselection" ]] && rm "$portselection"
    [[ -e "$tmpfile" ]] && rm "$tmpfile"
    [[ -n "$workdir" ]] && popd 1>/dev/null
    (($loglevel&$LOGFILE)) && showstatus "logged to $outputfile" $NOLOGFILE
    showstatus "ended on $(date +%d-%m-%Y' at '%R)"
    exit
}

if ! options=$(getopt -o ad:fhi:lno:pqstuvwWy -l dns,directory:,filter:,fingerprint,header,inputfile:,log,max,nikto,nocolor,output:,ports,quiet,ssh,ssl,sslports:,timeout:,trace,update,version,webports:,whois,wordlist: -- "$@") ; then
    usage
    exit 1
fi 

eval set -- $options
if [[ "$#" -le 1 ]]; then
    usage
    exit 1
fi

while [[ $# -gt 0 ]]; do
    case $1 in
        -a|--all) 
            dnstest=$BASIC
            fingerprint=$BASIC
            nikto=$BASIC
            portscan=$BASIC
            sshscan=$BASIC
            sslscan=$BASIC
            trace=$BASIC
            whois=$BASIC;;
        --allports) portscan=$ADVANCED;;
        --dns) dnstest=$ADVANCED;;
        -f) fingerprint=$BASIC;;
        --fingerprint) fingerprint=$ADVANCED;;
        -h|--header) fingerprint=$ALTERNATIVE;;
        -d|--directory) workdir=$2
            shift ;;
        --filter) filter="$2"
            whois=$ADVANCED
            shift ;;
        -i|--inputfile) inputfile="$2"
            [[ ! $inputfile =~ ^/ ]] && inputfile=$(pwd)/$inputfile
            if [[ ! -s "$inputfile" ]]; then
                echo "error: cannot find $inputfile" 
                exit 1
            fi           
            shift ;;
        -l) log="TRUE";;
        --max)             
            dnstest=$ADVANCED
            fingerprint=$ADVANCED
            nikto=$ADVANCED
            portscan=$ADVANCED
            sshscan=$ADVANCED
            sslscan=$ADVANCED
            trace=$ADVANCED
            whois=$ADVANCED;; 
        -n) nikto=$BASIC;;
        --nikto) nikto=$ADVANCED;;
        --nocolor) nocolor=TRUE;;
        -o|--output)
            let "loglevel=loglevel|$LOGFILE"
            outputfile=$2
            [[ ! $outputfile =~ ^/ ]] && outputfile=$(pwd)/$outputfile
            [[ -s $outputfile ]] && appendfile=1
            shift ;;
        -p) portscan=$BASIC;;
        --ports) portscan=$ADVANCED;;
        --webports) webports=$2
            shift ;;
        --sslports) sslports=$2
            shift ;;
        -q|--quiet) let "loglevel=loglevel|$QUIET";;
        -s) sslscan=$BASIC;;
        --ssh) sshscan=$BASIC;;
        --ssl) sslscan=$ADVANCED;;
        -t) trace=$BASIC;;
        --timeout) timeout=$2
            shift ;;
        --trace) trace=$ADVANCED;;
        -u) do_update && exit 0;;
        --update) do_update 1 && exit 0;;
        -v) let "loglevel=loglevel|$VERBOSE";;
        --version) version;
                   exit 0;;
        -w|--whois) whois=$BASIC;;
        -W) let "whois=whois|$ADVANCED";;
        --wordlist) let "webscan=webscan|$BASIC"
            wordlist=$2
            [[ ! $wordlist =~ ^/ ]] && wordlist=$(pwd)/$wordlist
            shift ;;
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
    umask 177
    if [[ -n "$workdir" ]]; then 
        [[ -d $workdir ]] || mkdir $workdir 1>/dev/null 2>&1
    fi
    tmpfile=$(mktemp -q $NAME.XXXXXXX --tmpdir=$workdir)
    if [[ $1 =~ -.*[0-9]$ ]]; then
        nmap -nsL $1 2>/dev/null|awk '/scan report/{print $5}' >$tmpfile
        inputfile=$tmpfile
    fi
    if [[ $1 =~ , ]]; then
        for targets in ${1//,/ }; do
            echo $targets >> $tmpfile
        done
        inputfile=$tmpfile
    fi
fi

target=$1
startup
looptargets
