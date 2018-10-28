#ifndef esocks_helper_h
#define esocks_helper_h

#ifndef SOCKS_HAVE_INET6 // TODO: configure if system has AF_INET6
#define SOCKS_HAVE_INET6 1
#endif

#include <sys/socket.h>

#include "def.h"
#include "lru.h"

struct socks_addr {
  struct sockaddr *sockaddr;
  socklen_t        socklen;
};

typedef struct {
  struct socks_addr *addrs;
  int                naddrs;
} socks_addr_t;

typedef struct socks_name_s {
  u8                 hlen;
  u16                port;
  int                family;
  char               domain[256];
  socks_addr_t *addrs;
  struct sockaddr *sa;
} socks_name_t;

char *e_copy(char *dst, char *src, size_t s);
void e_parse_line(char * const start);
int e_read_file(const char *filename, char **out, int *out_len);
int e_parse_conf_file(struct settings *st, const char *filename);

#endif
