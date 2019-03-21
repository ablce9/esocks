## NAME
  Esocks

## SYNOPSIS

```console
 $ esocks
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
 - Support socks authentications
 - Write log file
 - key and initial vector for EVP_CIPHER_CTX is hard-coded now, so let's come up with some idea not to do so.

## What the heck is this?
 I'm inspired by Tor project. You launch two servers on your local computer and a server somewhere safe. Two servers establish a _safe_ tunnel and you can access stuff without being afraid of eavesdroppers.<br/>
The app uses libevent as backend. Thus, a server is supposed to run in single thread(think of apps written in nodejs). There will be no threads but event driven network application. I started this project for purely learning purposes.

## See also
 - http://blog.zorinaq.com/my-experience-with-the-great-firewall-of-china/

## License

This project is released under the [GPLv2](COPYING).
