FROM debian:stretch

ENV LIBEVENT_VERSION 2.1.12

RUN apt-get update -y && apt-get upgrade -y

RUN apt-get install -y git-core build-essential wget

RUN set -x \
    &&  apt-get install \
    -y --no-install-recommends make automake autoconf libssl1.1 libssl-dev \
    && apt-get autoclean -y \
    && wget https://github.com/libevent/libevent/releases/download/release-$LIBEVENT_VERSION-stable/libevent-$LIBEVENT_VERSION-stable.tar.gz \
    && tar xzvf libevent-$LIBEVENT_VERSION-stable.tar.gz && cd libevent-$LIBEVENT_VERSION-stable \
    && ./configure --prefix=/usr/local && make -j4 && make install \
    && cd .. && rm -rf libevent-$LIBEVENT_VERSION-stable.tar.gz libevent-$LIBEVENT_VERSION-stable

RUN mkdir -p /opt/esocks

COPY . /opt/esocks

RUN cd /opt/esocks \
    && ./autogen.sh \
    && ./configure --with-libevent=/usr/local \
    && make install

EXPOSE 1080

ENTRYPOINT [ "esocks" ]

CMD [ "-h" ]
