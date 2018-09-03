#ifndef SERVER_H
#define SERVER_H

#include "evs_helper.h"

struct dns_cache_config {
  struct lru_node_s  *cache;
  long               timeout;
};

typedef enum {
  /* socks context flags */
  ev_read = 1,
  ev_write,
  ev_wait,
  ev_hang,
  ev_destroy,
  ev_finished,
  ev_connected,
  ev_dns_wip,
  ev_dns_ok,
  ev_init,
  ev_freed, // 11
  ev_error,
  ev_eof,
  ev_left,
} socks_status_e;

struct ev_context_s {
  struct bufferevent      *bev;
  struct bufferevent      *partner;
  struct sockaddr_in      *sin;
  struct sockaddr_in6     *sin6;
  bufferevent_data_cb     *event_handler;
  socks_addr_t            *socks_addr;
  short                   port;
  char                    domain[256];
  socks_status_e          st;
  short                   what;
  _Bool                   reversed;
};

void run_srv(void);
void resolve(struct ev_context_s *s);
void err_writecb(struct bufferevent *bev, void *ctx);
void close_on_finished_writecb(struct bufferevent *bev, void *ctx);
void destroycb(struct bufferevent *bev, struct ev_context_s *ctx);
void resolvecb(int errcode, struct evutil_addrinfo *ai, void *ptr);
void fast_streamcb(struct bufferevent *bev, void *ctx);
void handle_streamcb(struct bufferevent *bev, void *ctx);
void evs_setcb_for_local(struct bufferevent *bev, void *context);
void eventcb(struct bufferevent *bev, short what, void *ctx);
void clean_dns_cache_func(evutil_socket_t sig_flag, short what, void *ctx);
int encrypt_(u8 *in, int ilen, u8 *out);
int decrypt_(u8 *in, int ilen, u8 *out);

#endif
