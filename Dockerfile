FROM debian:stretch

ENV LIBEVENT_VERSION 2.1.8

RUN apt-get update -y && apt-get upgrade -y

RUN apt-get install -y git-core build-essential wget

RUN set -x \
    &&  apt-get install -y \
     --no-install-recommends \
      make automake autoconf libssl-dev \
    && apt-get autoclean -y \
    && wget \
    https://github.com/libevent/libevent/releases/download/release-$LIBEVENT_VERSION-stable/libevent-$LIBEVENT_VERSION-stable.tar.gz \
    && tar xzvf libevent-$LIBEVENT_VERSION-stable.tar.gz && cd libevent-$LIBEVENT_VERSION-stable \
    && ./configure && make && make install \
    && cd .. && rm -rf libevent-$LIBEVENT_VERSION-stable.tar.gz libevent-$LIBEVENT_VERSION-stable

WORKDIR /app

ADD . /app

COPY . /app

RUN ./autogen.sh && ./configure --with-openssl=/usr/local --with-libevent=/usr/local && make install

EXPOSE 1080 1080

CMD $COMMAND
