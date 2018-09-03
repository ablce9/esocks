#ifndef HELPER_H
#define HELPER_H

#ifndef SOCKS_HAVE_INET6 // TODO: configure if system has AF_INET6
#define SOCKS_HAVE_INET6 1
#endif

#include "evs-internal.h"
#include "evs_lru.h"

#include <sys/socket.h>


typedef struct {
  struct sockaddr *sockaddr;
  socklen_t       socklen;
  int             naddrs;
} socks_addr_t;

typedef struct socks_name_s {
  u8                 hlen;
  u16                port;
  int                family;
  char               domain[256];
  socks_addr_t       *addrs;
  struct sockaddr    *sa;
} socks_name_t;

#ifdef HAVE_GETADDRINFO
int resolve_host(socks_name_t *);
#endif

char * ev_copy(char *dst, char *src, size_t s);
void *ev_xmalloc(size_t);

#endif
