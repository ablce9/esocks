## NAME
  esocks

## SYNOPSIS

```console
  % ./esocks -p2000 -k this-is-my-password,yo -s <your_server_ip>
  % ./esocks -j2000 -k this-is-my-password,yo -s <your_server_ip>
  % ss -4np state listening
Netid  Recv-Q Send-Q                           Local Address:Port    Peer Address:Port
tcp    0      128                                             *:2000               *:*          users:(("esocks",pid=28724,fd=3))
tcp    0      128                                             *:1080               *:*          users:(("esocks",pid=28723,fd=3))
  % curl --socks5 0.0.0.0:1080 google.com -v
```

## NOTES
 ### project status
 It's pretty much a WIP.

## BUILD
```console
./autogen.sh && ./configure && make
```

## DEPENDENCIES
 - [libevent(release-2.1.8-stable)](http://libevent.org)
 - [OpenSSL(OpenSSL_1_0_2-stable)](https://www.openssl.org)
 - autotools(whatever version. I didn't pay attention to the version... newer is better.)

## TODO
 - Make valgrind stop complaining about memory leak stuff. There seems nasty leaks around lru cache.
 - ~~Need a breakthrough in crpyto.c. Cannot figure out how to handle successive buffer.~~ Use stream ciphers instead of block ciphers.
 - key and intial vector for EVP_CIPHER_CTX is hard-coded now, so let's come up with some idea not do so.

## What the heck is this?
 I'm inspired by Tor project. You launch two servers on your local computer and a server somewhere safe. Two servers establish a _safe_ tunnel and you can access stuff without being afraid of eavesdroppers.<br/>
The app uses libevent as backend. Thus, a sevrer is supposed to run in single thread(think of apps written in nodejs). There will be no threads but event driven network application. I started this project for purely learning purposes.
