FROM debian:stretch

ENV LIBEVENT_VERSION 2.1.8

ENV OPENSSL_VERSION 1_1_0-stable

RUN apt-get update -y && apt-get upgrade -y

RUN apt-get install -y git-core build-essential wget

RUN set -x \
    &&  apt-get install -y \
     --no-install-recommends \
      make automake autoconf \
    && apt-get autoclean -y \
    && wget \
    https://github.com/libevent/libevent/releases/download/release-$LIBEVENT_VERSION-stable/libevent-$LIBEVENT_VERSION-stable.tar.gz \
    https://github.com/openssl/openssl/archive/OpenSSL_$OPENSSL_VERSION.tar.gz \
    && tar xzvf libevent-$LIBEVENT_VERSION-stable.tar.gz && cd libevent-$LIBEVENT_VERSION-stable \
    && ./configure && make && make install \
    && cd ../ && tar xvf OpenSSL_$OPENSSL_VERSION.tar.gz && cd ./openssl-OpenSSL_$OPENSSL_VERSION && ./config --prefix=/usr/local && make install_sw

WORKDIR /app

ADD . /app

COPY . /app

RUN ./autogen.sh && ./configure --with-openssl=/usr/local --with-libevent=/usr/local && make install

EXPOSE 1080 1081

CMD $COMMAND
