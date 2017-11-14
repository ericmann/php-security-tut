FROM ubuntu:14.04

MAINTAINER kirk@tozny.com
ENV DEBIAN_FRONTEND noninteractive

RUN apt-get -y update && \
    apt-get -y install build-essential
RUN mkdir /tozny-sdk-php

COPY *.php /tozny-sdk-php/
COPY packaging /tozny-sdk-php/packaging/

WORKDIR /tozny-sdk-php
ENTRYPOINT ["./packaging/debian/create_package.sh", "target/"]
