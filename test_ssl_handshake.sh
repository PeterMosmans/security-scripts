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



BUGSTRING='(ssl handshake failure|sslv3 alert unexpected message:sslv3 alert illegal parameter)'
#NOBUGSTRING='(certificate verify failed|no ciphers available|verify error)'
DEFAULTSTART=125
# verify error:num=20:unable to get local issuer certificate
# 2348672:error:14090086:SSL routines:SSL3_GET_SERVER_CERTIFICATE:certificate verify failed:s3_clnt.c:1180:
#2348672:error:140830B5:SSL routines:SSL3_CLIENT_HELLO:no ciphers available:s3_clnt.c:755:
# use all ciphers, except preshared keys or secure remote password
cipherfile=
cipherlist=
cipherstring="ALL:!PSK:!SRP"
EXTRAPARMS="-quiet -verify 0 -connect"
# temporary files
ALLCIPHERS=${TMP}/allciphers
STATUSREPORT=${TMP}//status
faultyciphers=
force=false
iterate=false
cipherlist=
defaultoption=true
verbose=false

ERR_PREREQUISITES=100
ERR_NOTDETECTED=101


# define functions

# first the bugs...
# Cisco: bug presents itself with 128 or more ciphers
bug_128_cipherlimit() {
    local ciphers=$1
    echo "testing for 128 cipherlimit"
    local bug=128
    local protocol="-tls1_2"
    local start=126
    local try=10
    let end=$(echo ${cipherlist} | tr ':' ' ' | wc -w)
    [[ ${end} -gt $((start+try)) ]] && let end=$((start+try))
    if [[ ${end} -le ${bug} ]]; then
        echo "sorry... need at least ${bug} ciphersuites to test"
        return ${ERR_PREREQUISITES}
    fi
    add_ciphers ${start} ${cipherlist} ${protocol} ${end}
    if [[ $? -ne ${bug} ]]; then
        echo "bug not present"
        return ${ERR_NOTDETECTED}
    fi
    # swap order
    echo "swapping order of ciphers"
    add_ciphers ${start} ${cipherlist} ${protocol} ${end}
    if [[ $? -ne ${bug} ]]; then
        echo "bug not present"
        return ${ERR_NOTDETECTED}
    fi
    return 0
}


# ...then the general functions
cleanup() {
#    rm -f ${STATUSREPORT} 1>/dev/null
    rm -f ${ALLCIPHERS} 1>/dev/null
    if [[ ! -z ${faultyciphers} ]]; then
        echo "faulty cipherlist: "
        echo ${faultyciphers}
    fi
}

# returns number of succesful ciphers
add_ciphers() {
    local start=$1
    local cipherlist=$2
    local protocol=$3
    local finish=${4:-$(echo ${cipherlist} | tr ':' ' ' | wc -w)}

    echo "Adding ${start} to ${finish} ciphersuites"
    for ((c=${start}; c<=${finish}; c++ )); do
        [[ $c -gt $start ]] && echo "total number of ciphers ${c} - cipher added: $(echo ${cipherlist} | cut --delimiter=":" -f$c)"
        ${verbose} && echo "${openssl} s_client -cipher $(echo ${cipherlist} | cut --delimiter=":" -f1-$c) ${protocol} ${EXTRAPARMS} ${host}"
        echo Q | $openssl s_client -cipher $(echo ${cipherlist} | cut --delimiter=":" -f1-$c) ${protocol} ${EXTRAPARMS} ${host} 1>/dev/null 2>${STATUSREPORT}
        parse_status ${STATUSREPORT}
        [[ $? -ne 0 ]] && return $c
    done
    return $((c-1))
}

# returns number of succesful ciphers
iterate_ciphers() {
    local start=$1
    local cipherlist=$2
    for ((c=${start}; c<=${finish}; c++ )); do
        local cipher=$(cut --delimiter=":" -f${c} ${cipherlist})
        [[ $c -gt $start ]] && echo "testing cipher ${c} - ${cipher}"
        rm -f ${STATUSREPORT} 1>/dev/null
        ${verbose} && echo "$openssl s_client -cipher ${cipher} ${PARMS} ${host}"
        echo Q | $openssl s_client -cipher ${cipher} ${PARMS} ${host} 1>/dev/null 2>${STATUSREPORT}
        parse_status ${STATUSREPORT}
        if [[ $? -ne 0 ]]; then
            [[ ${counter} == ${bug} ]] && return ${counter}
            [[ ! ${force} ]] && return ${counter}
            echo "adding ${cipher} to the list of faulty ciphers"
            [[ ! -z ${faultyciphers} ]] && faultyciphers="${faultyciphers}:"
            faultyciphers="${faultyciphers}${cipher}"
        fi
        return ${counter}
    done
}

load_ciphers() {
    if [[ ! -z ${cipherfile} ]] && [[ -f ${cipherfile} ]]; then
        # ALLCIPHERS expects : as delimiters, check if they're present..
        if grep -vq ":" ${cipherfile}; then
            # is it a full list ? if so, only use first column
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
        echo "reading cipherlist from ${openssl} and cipherstring ${cipherstring}"
        cipherlist=$(${openssl} ciphers -l ${cipherstring})
    fi
    totalciphers=$(echo ${cipherlist} | tr ':' ' ' | wc -w)
    echo "Loaded ${totalciphers} ciphers"
}

main() {
    startup "$@"
    load_ciphers
    test_connection ${cipherlist} ${protocol}
    if ${defaultoption}; then
        bug_128_cipherlimit
        [[ $? -eq 0 ]] && echo "128 cipherlimit detected"
    else
        if [ ${iterate} ]; then
            iterate_ciphers
        else
            add_ciphers
        fi
    fi
}

parse_status() {
    ${verbose} && show_statusreport $1
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
        ${verbose} && show_statusreport $1
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
    if ! options=$(getopt -o :fv -l ciphers:,cipherstring:,force,iterate,openssl:,verbose -- "$@") ; then
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
            --ciphers)
                cipherfile=$2
                shift;;
            --cipherstring)
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
    ${iterate} && defaultoption=false
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
    echo "      (c) 2014 Peter Mosmans [Go Forward]" $LIGHTBLUE
    echo "      Licensed under the GPL 3.0" $LIGHTBLUE
    echo ""
    echo "tests SSL/TLS handshakes (for known bugs)"
    echo ""
    echo "usage: $0 target[:port] [start]"
    echo ""
    echo "     [start]            number of ciphers to start with (default ${DEFAULTSTART})"
    echo "     --ciphers=FILE     a file containing a list which ciphers to use"
    echo "     --cipherstring=CIPHERSTRING"
    echo "                        cipherstring (default ${cipherstring})"
    echo "     -f | --force       continue even though the error has been detected"
    echo "     --iterate          iterate through all the ciphers instead of adding"
    echo "     --openssl=FILE     location of openssl (default ${openssl})"
    echo "     -v | --verbose     be more verbose, please"
    echo ""
    echo "     by default, all tests will be performed"
}

main "$@"
