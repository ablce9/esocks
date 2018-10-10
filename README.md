## NAME
  Esocks

## SYNOPSIS

```console
  % ./esocks -p2000 -s 192.168.0.153 -k this-is-my-password,yo
  % ./esocks -j2000 -u 192.168.0.153 -s 127.0.0.1 -k this-is-my-password,yo
  % ss -4np state listening
Netid  Recv-Q Send-Q                           Local Address:Port    Peer Address:Port
tcp    0      128                              192.168.0.153:2000               *:*          users:(("esocks",pid=28724,fd=3))
tcp    0      128                                  127.0.0.1:1080               *:*          users:(("esocks",pid=28723,fd=3))
  % curl --socks5 0.0.0.0:1080 google.com -v
```

## DESCRIPTION
 Esocks is a proxy server or possibly VPN(close enough to VPN) that lets you bypass annoying network rules. Esocks depends on two libraries: Libevent and OpenSSL. The power of Libevent helps to create robust I/O architecture and the power of OpenSSL provides AES encryption.

## NOTES
 ### project status
 It's pretty much a WIP.

## BUILD
```console
./autogen.sh && ./configure && make
```

## DEPENDENCIES
 - [libevent(release-2.1.8-stable)](http://libevent.org)
 - [OpenSSL(OpenSSL_1_1_0-stable)](https://www.openssl.org)
 - autotools(whatever version. I didn't pay attention to the version... newer is better.)

## TODO
 - Make valgrind stop complaining about memory leak stuff. There seems nasty leaks around lru cache.
 - ~~Need a breakthrough in crpyto.c. Cannot figure out how to handle successive buffer.~~ Use stream ciphers instead of block ciphers.
 - key and initial vector for EVP_CIPHER_CTX is hard-coded now, so let's come up with some idea not to do so.

## What the heck is this?
 I'm inspired by Tor project. You launch two servers on your local computer and a server somewhere safe. Two servers establish a _safe_ tunnel and you can access stuff without being afraid of eavesdroppers.<br/>
The app uses libevent as backend. Thus, a server is supposed to run in single thread(think of apps written in nodejs). There will be no threads but event driven network application. I started this project for purely learning purposes.

## See also
 - http://blog.zorinaq.com/my-experience-with-the-great-firewall-of-china/
