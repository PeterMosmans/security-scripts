#!/usr/bin/env bash

# test_ssl_handshake - Tests SSL/TLS handshake
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


# bug presents itself with 128 or more ciphers
BUG=128
BUGSTRING='(ssl handshake failure|sslv3 alert)'
#NOBUGSTRING='(certificate verify failed|no ciphers available|verify error)'
DEFAULTSTART=125
# verify error:num=20:unable to get local issuer certificate
# 2348672:error:14090086:SSL routines:SSL3_GET_SERVER_CERTIFICATE:certificate verify failed:s3_clnt.c:1180:
#2348672:error:140830B5:SSL routines:SSL3_CLIENT_HELLO:no ciphers available:s3_clnt.c:755:
# use all ciphers, except preshared keys or secure remote password
cipherstring="ALL:!PSK:!SRP"
PARMS="-ssl3 -quiet -verify 0 -connect"
# temporary files
ALLCIPHERS=${TMP}/allciphers
STATUSREPORT=${TMP}//status
faultyciphers=""
force=false
iterate=false
verbose=false


# define functions
cleanup() {
#    rm -f ${STATUSREPORT} 1>/dev/null
    rm -f ${ALLCIPHERS} 1>/dev/null
    if [[ ! -z ${faultyciphers} ]]; then
        echo "faulty cipherlist: "
        echo ${faultyciphers}
    fi
}

add_ciphers() {
    echo "Adding from ${start} to ${finish} ciphersuites"
    for ((c=${start}; c<=${finish}; c++ )); do
        touch 
        [[ $c -gt $start ]] && echo "total number of ciphers ${c} - cipher added: $(cut --delimiter=":" -f$c ${ALLCIPHERS})"
        ${verbose} && echo "$openssl s_client -cipher $(cut --delimiter=":" -f1-$c ${ALLCIPHERS}) ${PARMS} ${host}"
        echo Q | $openssl s_client -cipher $(cut --delimiter=":" -f1-$c ${ALLCIPHERS}) ${PARMS} ${host} 1>/dev/null 2>${STATUSREPORT}
        parse_status ${STATUSREPORT}
    done
}

iterate_ciphers() {
    echo "starting..."
    for ((c=${start}; c<=${finish}; c++ )); do
        local cipher=$(cut --delimiter=":" -f${c} ${ALLCIPHERS})
        [[ $c -gt $start ]] && echo "testing cipher ${c} - ${cipher}"
        rm -f ${STATUSREPORT} 1>/dev/null
        ${verbose} && echo "$openssl s_client -cipher ${cipher} ${PARMS} ${host}"
        echo Q | $openssl s_client -cipher ${cipher} ${PARMS} ${host} 1>/dev/null 2>${STATUSREPORT}
        parse_status ${STATUSREPORT}
        if [[ $? -ne 0 ]]; then
            echo "adding ${cipher} to the list of faulty ciphers"
            faultyciphers="${faultyciphers} ${cipher}"
        fi
    done
}

load_ciphers() {
    ${openssl} ciphers -l ${cipherstring} > ${ALLCIPHERS}
    totalciphers=$(cat ${ALLCIPHERS} | tr ':' ' ' | wc -w)
    echo "Loaded ${totalciphers} ciphers using ${openssl} and cipherstring ${cipherstring}"
    finish=${totalciphers}
    if [[ ${totalciphers} -lt ${finish} ]] || [[ ${totalciphers} -lt ${start} ]]; then
        echo "not enough ciphersuites to test from ${start}... exiting"
        exit 1
    fi
}

main() {
    startup "$@"
    load_ciphers
    test_connection
    if [ ${iterate} ]; then
        iterate_ciphers
    else
        add_ciphers
    fi
    echo "BUG not detected... ${totalciphers} ciphers are supported"
}

parse_status() {
    ${verbose} && show_statusreport $1
    if grep -qiE "no ciphers available" $1; then
        echo "cipher not supported by server"
        return 0
    fi
    if grep -qiE "ssl handshake failure" $1; then
        echo "SSL handshake error detected"
        show_statusreport $1
        return 1
    fi
    if grep -qiE "${BUGSTRING}" $1; then
        echo "SSL error detected"
        show_statusreport $1
        return 1
    fi
}

show_statusreport() {
    echo "status report from server:"
    grep -iv "loading" $1|awk '{FS=":";print $6}'
    grep -iv "loading" $1
}

startup() {
    trap cleanup EXIT QUIT
    if ! options=$(getopt -o :c:fv -l cipherstring:,force,iterate,openssl:,verbose -- "$@") ; then
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
            -c|--cipherstring)
                cipherstring=$2
                shift;;
            -f|--force)
                force=true;;
            --iterate)
                iterate=true;;
            --openssl)
                openssl=$2
                shift;;
            -v|--verbose)
                verbose=true
                ;;            
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
    start=${2:-$DEFAULTSTART}
}

test_connection() {
    echo "first trying to connect to ${host} using ${totalciphers} ciphers..."
    echo Q | ${openssl} s_client -cipher $(cat ${ALLCIPHERS}) ${PARMS} ${host} 1>/dev/null 2>${STATUSREPORT}
    if grep -qiE "(connect:errno|ssl handhake failure)" ${STATUSREPORT}; then
        echo "could not connect to ${host}... exiting"
        exit 1
    fi
    parse_status ${STATUSREPORT}
    if [[ $? -ne 0 ]]; then
        echo "no issues detected..."
        ${force} || exit 0
    fi
}

bug_big_cipherlist() {
}

usage() {
    echo "      (c) 2014 Peter Mosmans [Go Forward]" $LIGHTBLUE
    echo "      Licensed under the GPL 3.0" $LIGHTBLUE
    echo ""
    echo "tests whether SSL handshake bug is present, when proposing ${BUG} ciphers"
    echo ""
    echo "usage: $0 target[:port] [start]"
    echo ""
    echo "     [start]         the number of ciphers to start with (default ${DEFAULTSTART})"
    echo "     -c | --cipherstring=CIPHERSTRING"
    echo "                     cipherstring (default ${cipherstring})"
    echo "     -f | --force    continue even though the error has been detected"
    echo "     --iterate       iterate through all the ciphers instead of adding"
    echo "     --openssl=FILE  location of openssl (default ${openssl})"
    echo "     -v | --verbose  be more verbose, please"
}

main "$@"
