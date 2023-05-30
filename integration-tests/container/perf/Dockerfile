FROM quay.io/centos/centos:stream9 AS base

RUN yum groupinstall -y 'Development Tools'
RUN dnf install -y bash bc bison flex elfutils-devel make openssl-devel diffutils kernel-devel
# RUN dnf install -y curl  # conflicts with curl-minimal which is already installed

COPY tools /tools
COPY scripts /scripts

WORKDIR /root

#
# Init image for downloading and installing kernel headers
#
FROM base AS init

WORKDIR /
CMD ["/scripts/init.sh"]

#
# BCC image that contains bcc-tools
# see: https://github.com/iovisor/bcc
#
FROM base AS bcc

RUN dnf install -y bcc-tools && \
    ln -s /usr/bin/python3 /usr/bin/python

ENV PATH=/bin:/usr/bin:/usr/share/bcc/tools:/tools
ENTRYPOINT ["/scripts/run-tool.sh"]

#
# Perf image that just contains the perf tool
#
FROM base AS perf

RUN dnf install -y perf

ENTRYPOINT ["/scripts/run-tool.sh", "perf"]
