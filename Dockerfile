# Use a base image to build (and download) the tools on
FROM python:slim-buster as build

LABEL maintainer="support@go-forward.net"
LABEL vendor="Go Forward"

# Create virtual environment
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install necessary binaries
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    unzip \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install package manually
RUN python3 -m pip install -e "git+https://github.com/KhasMek/python-Wappalyzer@python3#egg=python-wappalyzer"

# Install (rest of the) packages as specified in the requirements.txt file
COPY requirements.txt .
RUN pip3 install -r requirements.txt

# Clone nikto.pl
RUN git clone --depth=1 https://github.com/sullo/nikto /tmp/nikto && \
    rm -rf /tmp/nikto/program/.git && \
    mv /tmp/nikto/program /usr/lib/nikto

# Clone testssl.sh
RUN git clone --depth=1 https://github.com/drwetter/testssl.sh /tmp/testssl && \
    mkdir /usr/lib/testssl && \
    mv /tmp/testssl/bin/openssl.Linux.x86_64 /usr/lib/testssl/openssl && \
    chmod ugo+x /usr/lib/testssl/openssl && \
    mv /tmp/testssl/etc/ /usr/lib/testssl/etc/ && \
    mv /tmp/testssl/testssl.sh /usr/lib/testssl/testssl.sh && \
    chmod ugo+x /usr/lib/testssl/testssl.sh

FROM python:slim-buster as release
COPY --from=build /opt/venv /opt/venv
COPY --from=build /usr/lib/nikto/ /usr/lib/nikto/
COPY --from=build /usr/lib/testssl/ /usr/lib/testssl/
COPY analyze_hosts.py /usr/local/bin/analyze_hosts.py
RUN ln -s /usr/lib/nikto/nikto.pl /usr/local/bin/nikto.pl
RUN ln -s /usr/lib/nikto/nikto.pl /usr/local/bin/nikto
RUN ln -s /usr/local/bin/analyze_hosts.py /usr/local/bin/analyze_hosts
RUN ln -s /usr/lib/testssl/testssl.sh /usr/local/bin/testssl.sh

# Install necessary binaries
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    bsdmainutils \
    curl \
    dnsutils \
    git \
    libnet-ssleay-perl \
    nmap \
    procps \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

ENV PATH="/opt/venv/bin:$PATH"
ENV LC_ALL=C.UTF-8

USER root
WORKDIR /tmp
ENTRYPOINT ["/usr/local/bin/analyze_hosts"]
CMD ["--help"]