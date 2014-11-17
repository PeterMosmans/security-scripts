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
DEFAULTSTART=125

# use all ciphers, except preshared keys or secure remote password
CIPHERSTRING="ALL:!PSK:!SRP"
PARMS="-tls1_2 -quiet -verify 0 -connect"
# temporary files
ALLCIPHERS=${TMP}/allciphers
STATUSREPORT=${TMP}//status


# define functions
cleanup() {
    rm -f ${STATUSREPORT} 1>/dev/null
    rm -f ${ALLCIPHERS} 1>/dev/null
}

cycle_ciphers() {
    echo ""
    echo "starting with ${start} ciphers (plus TLS_EMPTY_RENEGOTIATION_INFO_SCSV)..."
    for ((c=${start}; c<=${finish}; c++ )); do
        [[ $c -gt $start ]] && echo "total number of ciphers ${c} - cipher added: $(cut --delimiter=":" -f$c ${ALLCIPHERS})"
        echo Q | $openssl s_client -cipher $(cut --delimiter=":" -f1-$c ${ALLCIPHERS}) ${PARMS} ${host} 1>/dev/null 2>${STATUSREPORT}
        if grep -qi "sslv3 alert" ${STATUSREPORT}; then
            echo "Server returned error while trying $c ciphers..."
            [[ $c -ge ${BUG} ]] && echo "BUG PRESENT - Cipherlimit of ${BUG} detected"
            echo ""
            echo "status report from server:"
            grep -iv "loading" ${STATUSREPORT}
            exit 0
        fi
    done
}

load_ciphers() {
    ${openssl} ciphers -tls1 -l ${CIPHERSTRING} > ${ALLCIPHERS}
    totalciphers=$(cat ${ALLCIPHERS} | tr ':' ' ' | wc -w)
    echo "Loaded ${totalciphers} ciphers using ${openssl} and cipherstring ${CIPHERSTRING}"
    finish=${totalciphers}
    if [[ ${totalciphers} -lt ${finish} ]] || [[ ${totalciphers} -lt ${start} ]]; then
        echo "not enough ciphersuites to test from ${start}... exiting"
        exit 1
    fi
    echo "trying to test from ${start} to ${finish} ciphersuites"
}

main() {
    startup "$@"
    load_ciphers
    test_connection
    cycle_ciphers
    echo "BUG not detected... ${totalciphers} ciphers are supported"
}

startup() {
    trap cleanup EXIT QUIT
    if ! options=$(getopt -o : -l openssl: -- "$@") ; then
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
            --openssl)
                openssl=$2
                shift;;
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
    if grep -qi "sslv3 alert" ${STATUSREPORT}; then
        echo "SSL error occurred while trying all ciphers - bug is probably present"
    else
        echo "no issues detected... exiting"
        exit 0
    fi
}


usage() {
    echo "      (c) 2014 Peter Mosmans [Go Forward]" $LIGHTBLUE
    echo "      Licensed under the GPL 3.0" $LIGHTBLUE
    echo ""
    echo "tests whether SSL handshake bug is present, when proposing ${BUG} ciphers"
    echo ""
    echo "usage: $0 target[:port] [start]"
    echo ""
    echo "     [start] the number of ciphers to start with (default ${DEFAULTSTART})"
    echo "     --openssl=FILE      location of openssl (default ${openssl})"
}

main "$@"
