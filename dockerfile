FROM debian:stretch

ENV LIBEVENT_VERSION 2.1.8

RUN apt update -y && apt upgrade -y

RUN apt install -y git-core build-essential wget

RUN set -x \
    &&  apt install -y \
     --no-install-recommends \
      make automake autoconf libssl-dev \
    && apt autoclean -y \
    && wget \
    https://github.com/libevent/libevent/releases/download/release-$LIBEVENT_VERSION-stable/libevent-$LIBEVENT_VERSION-stable.tar.gz \
    https://github.com/libevent/libevent/releases/download/release-$LIBEVENT_VERSION-stable/libevent-$LIBEVENT_VERSION-stable.tar.gz.asc \
    # Might fail here depending on your network policies...
    && gpg --keyserver pgp.mit.edu --recv 8EF8686D \
    && gpg --verify ./libevent-$LIBEVENT_VERSION-stable.tar.gz.asc \
    && tar xzvf libevent-$LIBEVENT_VERSION-stable.tar.gz && cd libevent-$LIBEVENT_VERSION-stable \
    && ./configure && make && make install && ldconfig

WORKDIR /app

ADD . /app

COPY . /app

RUN automake && autoconf && ./configure --enable-debug && make

EXPOSE 1080

CMD ./esocks -o /app/resolv.conf