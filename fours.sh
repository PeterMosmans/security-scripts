#!/usr/bin/env bash

# Fours - Snap Shot Security Scanner
# Perform a security scan given a set of parameters, and report in HTML

# Copyright (C) 2023, Peter Mosmans
# SPDX-License-Identifier: GPL-3.0-only

IMAGE=gofwd/analyze_hosts
TIMEZONE=Europe/Amsterdam
TARGETS=targets.txt
SCANLOG=scan-results.txt
SCANRESULTS=scan-results.json
HTMLRESULTS=scan-results.html

if ! which docker &>/dev/null; then
    echo "Docker not found or not installed - exiting prematurely"
    exit 1
fi

if [[ ! -f $TARGETS ]]; then
    echo "Target file $TARGETS not found - exiting prematurely"
    exit 1
fi

echo "Fours v0.1 - Snap Shot Security Scanner - (c) 2023 Peter Mosmans"
if [[ -f analyze_hosts.queue ]]; then
    echo -n "It looks like a scan is still active: "
    state=$(docker ps --format '{{.Image}} Created {{.RunningFor}} - {{.Status}}' | grep $IMAGE)
    echo "$state"
    if [[ -z "$state" ]]; then
        echo "Hmm... it seems $IMAGE is not running (anymore)"
        echo "You might want to manually remove analyze_hosts.queue and restart the script"
    fi
    echo "Exiting prematurely"
    exit 0
fi

echo "Starting scan of $(wc -l $TARGETS) target(s)"
if [[ ! -f $SCANLOG ]]; then
    echo "Appending scan log to $SCANLOG"
fi

docker run --rm --volume "$PWD":/workdir -e TZ=$TIMEZONE $IMAGE \
--compact \
--http \
--nikto \
--quiet \
--settings analyze_hosts.yml \
--ssl \
--threads 10 \
-i $TARGETS \
-o $SCANLOG \
--json $SCANRESULTS

if [[ ! -f $SCANRESULTS ]]; then
    echo "$SCANRESULTS not created - exiting prematurely"
    exit 1
fi

echo "Converting scan results into HTML file $HTMLRESULTS"
docker run --rm --volume "$PWD":/workdir --entrypoint '' gofwd/analyze_hosts \
results_to_html.py $SCANRESULTS > $HTMLRESULTS
