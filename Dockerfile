FROM ubuntu:focal AS gitserver

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -y && \
    apt-get install --no-install-recommends -y \
        curl ca-certificates xz-utils openjdk-14-jre-headless && \
    /usr/sbin/update-ca-certificates && \
    apt-get autoremove -y && \
    apt-get clean

RUN curl -sL https://github.com/omegaup/libinteractive/releases/download/v2.0.27/libinteractive.jar \
        -o /usr/share/java/libinteractive.jar && \
    useradd --create-home --shell=/bin/bash ubuntu && \
    mkdir -p /etc/omegaup/gitserver /var/log/omegaup /var/lib/omegaup/problems.git && \
    chown -R ubuntu /var/log/omegaup /var/lib/omegaup

ARG RELEASE
ENV RELEASE=$RELEASE
RUN curl -sL https://github.com/omegaup/gitserver/releases/download/${RELEASE}/omegaup-gitserver.tar.xz | \
        tar xJ -C /

USER ubuntu
WORKDIR /var/lib/omegaup
