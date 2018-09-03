#include "evs-internal.h"

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "evs_helper.h"
#include "evs_log.h"

static char * ev_copy_(char *dst, char *src, size_t s);


#ifdef HAVE_GETADDRINFO
/*
 * resolve_domain is a helper function using getaddrinfo as backend.
 * This blocks your program. :)
 */
int
resolve_domain(socks_name_t *n)
{
  struct addrinfo hints, *res, *p;
  struct sockaddr_in *sin;
  char *domain;
  int i;

  domain = malloc(n->hlen + 1);
  assert(!domain);

  (void) ev_copy(domain, n->domain, n->hlen);

  log_d(DEBUG, "resolve: %s", domain);

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  if (getaddrinfo((char *)domain, NULL, &hints, &res) != 0) {
    log_e("domain not found");
    free(domain);
    return -1;
  }

  free(domain);

  for (i =0, p =res; p != NULL; p = p->ai_next) {
    switch(p->ai_family) {
    case AF_INET:
    case AF_INET6:
      break;
    default:
      continue;
    }
    i++;
  }

  if (i == 0) { /* no results */
    log_e("domain not found");
    goto failed;
  }

  n->addrs = malloc(i * sizeof(socks_addr_t));
  assert(n->addrs != NULL);

  n->addrs->naddrs = i;
  i = 0;

  for (p =res; p !=NULL; p =p->ai_next) {

    // #define have_netinet_in6_h
    if (p->ai_family != AF_INET)
      continue;

    sin = malloc(sizeof(struct sockaddr_in));
    assert(!sin != NULL);

    memcpy(sin, p->ai_addr, p->ai_addrlen);

    sin->sin_port = n->port;

    n->addrs[i].sockaddr = (struct sockaddr*)sin;
    n->addrs[i].socklen = p->ai_addrlen;

    i++;
    break;
  }

  freeaddrinfo(res);
  return 0;

 failed:
  freeaddrinfo(res);
  return -1;
}

#endif

/*
 * ev_copy does copy src buffer to dst buffer that is null-terminated.
 */
char * ev_copy(char *dst, char *src, size_t s)
{
  return ev_copy_(dst, src, s);
}

static char *
ev_copy_(char *dst, char *src, size_t s)
{

  while(s--)
    {

      *dst = *src;

      if (*dst == '\0') return dst;

      dst ++; src ++;

    }

  *dst = '\0';

  return dst;
}
