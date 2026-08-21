FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    nodejs npm python3 python3-pip \
    strace ltrace tcpdump net-tools procps \
    inotify-tools curl jq \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash analyst

WORKDIR /analysis

COPY --chown=analyst:samples /analysis/samples/ /analysis/samples/
COPY --chown=analyst:analyst /analysis/mock-rpc.js /analysis/mock-c2.js /analysis/
COPY --chown=analyst:analyst /analysis/monitor.sh /analysis/

RUN chmod +x /analysis/monitor.sh

USER analyst

ENTRYPOINT ["/bin/bash"]
