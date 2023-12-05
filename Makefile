# Generic Makefile for Docker images

# Copyright (C) 2018-2023 Peter Mosmans [Go Forward]
# SPDX-License-Identifier: GPL-3.0-or-later

# TAG	!= git tag|tail -1
TAG     = "latest"
NAME	:= analyze_hosts
DOCKER_IMG := gofwd/$(NAME):$(TAG)
DOCKER_CMD := docker run --rm -i --entrypoint '' --volume $$PWD:/workdir:ro ${DOCKER_IMG}

# Enforce Bash as shell, as that makes it easier to script
SHELL := /bin/bash

# Recipes that aren't filenames: This ensures that they always will be executed
.PHONY: image imagetest test

# Build image
image:
	@echo "Building $(DOCKER_IMG)..." && \
	DOCKER_BUILDKIT=1 docker build . -t $(DOCKER_IMG)

# Test an image: make is required for this phase
imagetest:
	echo running ${DOCKER_CMD}
	@${DOCKER_CMD} /bin/bash -c "make test"

test:
	./analyze_hosts.py --version && \
	./results_to_html.py --help && \
	curl --version && \
	nikto.pl -Version && \
	nmap --version && \
	testssl.sh --version
