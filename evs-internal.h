/*
 * internal.h
 *
 * Use of this source code is governed by a
 * license that can be found in the LICENSE file.
 *
 *
*/


#ifndef INTERNAL_H
#define INTERNAL_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <openssl/evp.h>

#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/event.h>
#include <event2/util.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>

# define u64 ev_uint64_t
# define u32 ev_uint32_t
# define u16 ev_uint16_t
# define u8   ev_uint8_t

/* simple debug mode */
#ifndef  DEBUG
# define  DEBUG 0
#endif

#if defined DEBUG
# define ASSERT(exp) assert(exp)
#else
# define ASSERT(exp) // pass
#endif

/* socks version  */
# define SOCKS_VERSION 5

# define SOCKSNOAUTH       0
# define GSSAPI            1
# define SOCKSAUTHPASSWORD 2
# define IANASSIGNED       3 /* curl requests this */

#define SOCKS_MAX_BUFFER_SIZE 4096

struct settings {
  struct socksaddr_in  *proxy;
  int                  timeout;
  const char           *srv_addr;
  short                srv_port;
  const char           *server_addr;
  short                server_port;
  const char           *worker;
  _Bool                relay_mode;
  const char           *nameserver;
  const char           *resolv_conf;
  int                  rate_rlimit;
  int                  rate_wlimit;
  const char           *cipher_name;
  const EVP_MD         *dgst;
  const EVP_CIPHER     *cipher;
  const u8             *iv;
  const u8             *key;
  u8                   *passphrase;
  int                  plen;
  long                 dns_cache_tval;
};

extern struct settings settings;

typedef enum {
  SUCCESSED = 0,
  GENERAL_FAILURE,
  METHOD_NOT_ALLOWED,
  NETWORK_UNREACHABLE,
  HOST_UNREACHABLE,
  CONNECTION_REFUSED,
  TTL_EXPIRED,
  METHOD_NOT_SUPPORTED,
  ADDRESS_TYPE_NOT_SUPPORTED,
  UNASSIGNED
} socks_reply_e;  /* server replies */

/* address type */
# define IPV4        1
# define DOMAINN     3
# define IPV6        4

# define SOCKS_INET_ADDRSTRLEN  (sizeof("255.255.255.255") - 1)
# define SOCKS_INET6_ADDRSTRLEN \
  (sizeof("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255") - 1)

#endif
