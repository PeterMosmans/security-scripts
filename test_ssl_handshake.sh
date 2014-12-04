#!/usr/bin/env bash

# test_ssl_handshake - Tests SSL/TLS handshakes
#
# Copyright (C) 2014 Peter Mosmans <support@go-forward.net>
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

NAME="test_ssl_handshake"


BUGSTRING='(ssl handshake failure|sslv3 alert unexpected message|sslv3 alert illegal parameter)'

#statuses
declare SUCCESS=0
declare ERR_PREREQUISITES=100
declare ERR_NOTDETECTED=101
declare NONEWLINE=1

# logging and verboseness (v1.0)
declare NOLOGFILE=-1
declare QUIET=1
declare STDOUT=2
declare VERBOSE=4
declare LOGFILE=8
declare RAWLOGS=16
declare SEPARATELOGS=32

#defaults
DEFAULTSTART=125
DEFAULTSTRING="ALL:!PSK:!SRP"
DEFAULTPROTOCOL="-ssl2 -ssl3 -tls1"
EXTRAPARMS="-quiet -verify 0 -connect"

# colours (v1.0)
declare BLUE='\E[1;49;96m' LIGHTBLUE='\E[2;49;96m'
declare RED='\E[1;49;31m' LIGHTRED='\E[2;49;31m'
declare GREEN='\E[1;49;32m' LIGHTGREEN='\E[2;49;32m'
declare RESETSCREEN='\E[0m'

# temporary file - just in case it's needed for debugging purposes
STATUSREPORT=${TMP}/status

# global variables
cipherfile=
cipherlist=
defaultoption=true
faultyciphers=
force=false
iterate=false
loglevel=0
start=0
total=0

# bug tests
bug128=false
bugrsa=false
bugintolerant=false

# define functions: first the bug tests

# Handshake fails when the tls1_2 protocol and 128 or more ciphers are specified,
# but is successful with tls1_2 and 127 or less ciphers
bug_128_cipherlimit() {
    load_ciphers "-tls1" ""
    prettyprint "testing for 128 cipherlimit" $BLUE
    local bug=128
    local protocol="-tls1_2"
    local start=126
    local try=10
    let end=$(echo ${cipherlist} | tr ':' ' ' | wc -w)
    [[ ${end} -gt $((start+try)) ]] && let end=$((start+try))
    if [[ ${end} -le ${bug} ]]; then
        prettyprint "FAILED TEST: need at least ${bug} ciphersuites to test" $GREEN
        return ${ERR_PREREQUISITES}
    fi
    add_ciphers ${start} ${cipherlist} ${protocol} ${end}
    successful=$?
    if [[ ${successful} -ne ${bug} ]]; then
        prettyprint "FAILED TEST: tried ${successful} ciphers" $GREEN
        return ${ERR_NOTDETECTED}
    fi
    echo "shuffling order of ciphers"
    cipherlist=$(echo ${cipherlist} | tr ':' '\n'| shuf | tr '\n' ':'| sed -e 's/:$//' 1>/dev/stdout)
    add_ciphers ${start} ${cipherlist} ${protocol} ${end}
    successful=$?
    if [[ ${successful} -ne ${bug} ]]; then
        prettyprint "FAILED TEST: tried ${successful} ciphers" $GREEN
        return ${ERR_NOTDETECTED}
    fi
    prettyprint "SUCCESS: 128 cipherlimit detected" $RED
}

# Handshake fails when aRSA ciphers are specified first,
# but is successful with the default ordering
bug_rsa_order() {
    load_ciphers "" 'ALL'
    local protocol="-ssl3"
    local tests=3
    prettyprint "testing for RSA order sensitivity" $BLUE
    echo  "test 1 of ${tests} - using cipherstring ALL"
    echo Q | $openssl s_client ${protocol} -cipher ${cipherlist} ${EXTRAPARMS} ${host} 1>/dev/null 2>${STATUSREPORT}
    parse_status ${STATUSREPORT}
    if [[ $? -ne ${SUCCESS} ]]; then
        prettyprint "FAILED TEST: handshake failed" $GREEN
        return ${ERR_NOTDETECTED}
    fi
    load_ciphers "" 'ALL:+aRSA'
    echo  "test 2 of ${tests} - using cipherstring ALL:+aRSA"
    echo Q | $openssl s_client ${protocol} -cipher ${cipherlist} ${EXTRAPARMS} ${host} 1>/dev/null 2>${STATUSREPORT}
    parse_status ${STATUSREPORT}
    if [[ $? -eq ${SUCCESS} ]]; then
        prettyprint "FAILED TEST: handshake successful" $GREEN
        return ${ERR_NOTDETECTED}
    fi
    load_ciphers "" 'ALL:aRSA'
    echo  "test 3 of ${tests} - using cipherstring ALL:aRSA"
    echo Q | $openssl s_client ${protocol} -cipher ${cipherlist} ${EXTRAPARMS} ${host} 1>/dev/null 2>${STATUSREPORT}
    parse_status ${STATUSREPORT}
    if [[ $? -ne ${SUCCESS} ]]; then
        prettyprint 'FAILED TEST: handshake failed when testing cipherstring ALL:aRSA' $GREEN
        return ${ERR_NOTDETECTED}
    fi
    prettyprint "SUCCESS: RSA order sensitivity detected" $RED
    return 0
}

# Handshake fails without connecting without specifying TLS protocol,
# but is successful when a TLS protocol is specified
bug_intolerant() {
    local protocols="-tls1_2 -tls1_1 -tls1 -ssl3 -ssl2"
    local succeeded=""
    local counter=1
    local tests=$(($(echo ${protocols}|wc -w)+1))
    prettyprint "testing for version intolerant server (using previously loaded cipherstring)" $BLUE
    echo -n "test ${counter} of ${tests} - connect without a protocol specified "
    # check if default connection fails
    echo Q | $openssl s_client ${protocol} -cipher ${cipherlist} ${EXTRAPARMS} ${host} 1>/dev/null 2>${STATUSREPORT}
    _=$(parse_status ${STATUSREPORT})
    if [[ $? -eq ${SUCCESS} ]]; then
        echo ""
        prettyprint "FAILED TEST: handshake successful" $GREEN
        return ${ERR_NOTDETECTED}
    fi
    echo "handshake failed"
    # check if connection is successful with one of the protocols
    for protocol in ${protocols}; do
        let counter=${counter}+1
        echo -n "test ${counter} of ${tests} - connect with ${protocol} "
        echo Q | $openssl s_client ${protocol} -cipher ${cipherlist} ${EXTRAPARMS} ${host} 1>/dev/null 2>${STATUSREPORT}
        _=$(parse_status ${STATUSREPORT})
        if [[ $? -eq ${SUCCESS} ]]; then
            succeeded=${protocol}
            prettyprint "SUCCESS: handshake successful" $RED
        else
            echo "handshake failed"
        fi
    done
    if [ -z ${succeeded} ]; then
        prettyprint "FAILED TEST: could not connect with any of the protocols ${protocols}" $GREEN
        return ${ERR_NOTDETECTED}
    fi
    prettyprint "SUCCESS: version intolerant server detected" $RED
}

# ...then the general functions
cleanup() {
    rm -f ${STATUSREPORT} 1>/dev/null
    if [[ ! -z ${faultyciphers} ]]; then
        echo "faulty cipherlist: "
        echo ${faultyciphers}
    fi
}

# returns number of successful ciphers
add_ciphers() {
    local start=$1
    local cipherlist=$2
    local protocol=$3
    local finish=${4:-$(echo ${cipherlist} | tr ':' ' ' | wc -w)}

    echo "Adding ${start} to ${finish} ciphersuites"
    for ((c=${start}; c<=${finish}; c++ )); do
        [[ $c -gt $start ]] && echo "total number of ciphers ${c} - cipher added: $(echo ${cipherlist} | cut --delimiter=":" -f$c)"
        (($loglevel&$VERBOSE)) && echo "${openssl} s_client -cipher $(echo ${cipherlist} | cut --delimiter=":" -f1-$c) ${protocol} ${EXTRAPARMS} ${host}"
        echo Q | $openssl s_client -cipher $(echo ${cipherlist} | cut --delimiter=":" -f1-$c) ${protocol} ${EXTRAPARMS} ${host} 1>/dev/null 2>${STATUSREPORT}
        parse_status ${STATUSREPORT}
        [[ $? -ne 0 ]] && return $c
    done
    return $((c-1))
}

# returns number of successful ciphers
iterate_ciphers() {

    local start=$1
    local cipherlist=$2
    local total=$(echo ${cipherlist} | tr ':' ' ' | wc -w)
    echo "${start} ${cipherlist} ${total}"
    for ((c=${start}; c<=${total}; c++ )); do
        local cipher=$(echo ${cipherlist} | cut --delimiter=":" -f$c)
        echo -n "testing cipher ${c} - ${cipher} "
        rm -f ${STATUSREPORT} 1>/dev/null
        (($loglevel&$VERBOSE)) && echo "$openssl s_client -cipher ${cipher} ${EXTRAPARMS} ${host}"
        echo Q | $openssl s_client -cipher ${cipher} ${EXTRAPARMS} ${host} 1>/dev/null 2>${STATUSREPORT}
        parse_status ${STATUSREPORT}
        if [[ $? -ne ${SUCCESS} ]]; then
            [[ ${counter} == ${bug} ]] && return ${counter}
            [[ ! ${force} ]] && return ${counter}
            prettyprint "handshake failed" $RED $NONEWLINE
            echo ", adding ${cipher} to the list of faulty ciphers"
            [[ ! -z ${faultyciphers} ]] && faultyciphers="${faultyciphers}:"
            faultyciphers="${faultyciphers}${cipher}"
        else
            prettyprint "handshake successful" $GREEN
        fi
    done
    return $((c-1))
}

load_ciphers() {
    local protocol={$1:-$DEFAULTPROTOCOL}
    local cipherstring=${2:-$DEFAULTSTRING}
    if [[ ! -z $2 ]]; then
        (($loglevel&$VERBOSE)) && echo "loading custom cipherstring ${2}"
    fi
    if [[ ! -z ${cipherfile} ]] && [[ -f ${cipherfile} ]]; then
        # cipherstring expects : as delimiters, check if they're present..
        if grep -vq ":" ${cipherfile}; then
            # is it a multiple-column file ? if so, only use first column
            if grep -q "=" ${cipherfile}; then
                cipherlist=$(awk '{print $1}' ${cipherfile} | tr '\n' ':' | sed -e 's/:$//' 1>/dev/stdout)
            else
                # replace newline characters with :
                cipherlist=$(tr '\n' ':' < ${cipherfile} | sed -e 's/:$//')
            fi
        else
            cipherlist=$(cat ${cipherfile})
        fi
    else
        (($loglevel&$VERBOSE)) && echo "reading cipherlist from ${openssl} and cipherstring ${cipherstring}"
        cipherlist=$(${openssl} ciphers ${protocol} -l ${cipherstring})
    fi
    totalciphers=$(echo ${cipherlist} | tr ':' ' ' | wc -w)
    (($loglevel&$VERBOSE)) && echo "loaded ${totalciphers} ciphers"
}

main() {
    startup "$@"
    load_ciphers "${protocol}" "${cipherstring}"
    test_connection ${cipherlist} ${protocol}
    ${bugintolerant} && bug_intolerant
    ${bug128} && bug_128_cipherlimit
    ${bugrsa} && bug_rsa_order
    if ${iterate}; then
        iterate_ciphers "${start}" "${cipherlist}"
        echo ${faultyciphers}
    fi
#        else
#            add_ciphers
#        fi
}

parse_status() {
    (($loglevel&$VERBOSE)) && show_statusreport $1
    if grep -qiE "no ciphers available" $1; then
        echo "cipher not supported by server"
        return 0
    fi
    if grep -qiE "no cipher match" $1; then
        echo "cipher locally not supported by ${openssl}"
        return 0
    fi
    if grep -qiE "ssl handshake failure" $1; then
        echo "SSL handshake error detected"
        (($loglevel&$VERBOSE)) && show_statusreport $1
        return 1
    fi
    if grep -qiE "${BUGSTRING}" $1; then
        echo "SSL error detected"
        show_statusreport $1
        return 1
    fi
}

# prettyprint (v1.0)
prettyprint() {
    (($loglevel&$QUIET)) && return
    [[ -z $nocolor ]] && echo -ne $2
    if [[ "$3" == "$NONEWLINE" ]]; then
        echo -n "$1"
    else
        echo "$1"
    fi
    [[ -z $nocolor ]] && echo -ne ${RESETSCREEN}
}

show_statusreport() {
    echo "status report from server:"
    grep -iv "loading" $1|awk 'FS=":"{print $6}'
    grep -iv "loading" $1
}

startup() {
    prettyprint "$NAME starting on $(date +%d-%m-%Y' at '%R)" $BLUE
    prettyprint "BETA VERSION - bugs are present and not all features are correctly implemented" $RED
    trap cleanup EXIT QUIT
    if ! options=$(getopt -o :fv -l 128,ciphers:,cipherstring:,force,intolerant,iterate,openssl:,rsa,start:,verbose -- "$@") ; then
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
            --128)
                bug128=true
                defaultoption=false;;
            --ciphers)
                cipherfile=$2
                shift;;
            --cipherstring)
                cipherstring=$2
                shift;;
            -f|--force)
                force=true;;
            --intolerant)
                bugintolerant=true
                defaultoption=false;;
            --iterate)
                iterate=true
                defaultoption=false;;
            --openssl)
                openssl=$2
                shift;;
            --rsa)
                bugrsa=true
                defaultoption=false;;
            --start)
                start=$2
                shift;;
            -v|--verbose)
                let "loglevel=loglevel|$VERBOSE";;
            (--) shift; 
                 break;;
            (-*) echo "$0: unrecognized option $1" 1>&2; exit 1;;
            (*) break;;
        esac
        shift
    done
    openssl=${openssl:-$(which openssl)}
    if ! [[ -f ${openssl} ]]; then
        echo "could not find ${openssl}... exiting"
        exit 1
    fi

    if [ -z $1 ]; then
        usage
        exit 0
    fi

    # add default port number ?
    if [[ $1 =~ .*:[0-9]+$ ]]; then
        host=$1
    else
        host=$1:443
    fi

    if ${defaultoption}; then
        bug128=true
        bugrsa=true
        bugintolerant=true
    fi
}

test_connection() {
    local cipherlist=$1
    local protocol=$2
    echo "first trying to connect to ${host} using ${totalciphers} ciphers..."
    echo Q | ${openssl} s_client -cipher ${cipherlist} ${protocol} ${EXTRAPARMS} ${host} 1>/dev/null 2>${STATUSREPORT}
    if grep -qiE "(connect:errno|ssl handhake failure|no cipher match)" ${STATUSREPORT}; then
        echo "could not connect to ${host} with all ciphers... exiting"
        exit 1
    fi
    parse_status ${STATUSREPORT}
    if [[ $? -eq 0 ]]; then
        echo "no issues detected"
    fi
}

usage() {
    local realpath=$(dirname $(readlink -f $0))
    if [[ -d $realpath/.git ]]; then
        pushd $realpath 1>/dev/null 2>&1
        local branch=$(git rev-parse --abbrev-ref HEAD)
        local commit=$(git log|head -1|awk '{print $2}'|cut -c -10)
        popd 1>/dev/null
        prettyprint "$NAME (git)" $BLUE $NONEWLINE
        echo " from ${branch} branch commit ${commit}"
    else
        prettyprint "$NAME version $VERSION" $BLUE
    fi
    prettyprint "      (c) 2014 Peter Mosmans [Go Forward]" $LIGHTBLUE
    prettyprint "      Licensed under the GPL 3.0" $LIGHTBLUE
    echo ""
    echo "tests SSL/TLS handshakes (for known bugs)"
    echo ""
    echo "usage: $0 target[:port]"
    echo ""
    echo "     --start=NUMBER     number of ciphers to start with"
    echo "     --ciphers=FILE     a file containing a list which ciphers to use"
    echo "     --cipherstring=CIPHERSTRING"
    echo "                        cipherstring (default ${cipherstring})"
    echo "     -f | --force       continue even though the error has been detected"
    echo "     --total=NUMBER     number of ciphers to test"
    echo "     --iterate          iterate through all the ciphers instead of adding"
    echo "     --openssl=FILE     location of openssl (default ${openssl})"
    echo "     -v | --verbose     be more verbose, please"
    echo ""
    echo " tests:"
    echo "     --128              test for 128 cipherlimit"
    echo "     --intolerant       test for version intolerant server"
    echo "     --rsa              test for RSA order sensitivity"
    echo ""
    echo "     by default, all tests will be performed"
    echo ""
    echo "BETA VERSION - bugs are present and not all features are correctly implemented"
}

main "$@"
