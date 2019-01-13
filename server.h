#ifndef esocks_server_h
#define esocks_server_h

#include "helper.h"

struct dns_cache_config {
    struct lru_node_s *cache;
    long              timeout;
};

typedef enum {
    e_read = 1,
    e_write,
    e_wait,
    e_hang,
    e_destroy,
    e_finished,
    e_connected,
    e_dns_wip,
    e_dns_ok,
    e_init,
    e_freed,
    e_error,
    e_eof,
    e_left,
} socks_status_e;

struct e_context_s {
    struct bufferevent  *bev;
    struct bufferevent  *partner;
    struct sockaddr_in  *sin;
    struct sockaddr_in6 *sin6;
    bufferevent_data_cb *event_handler;
    socks_addr_t        *socks_addr;
    short               port;
    char                domain[256];
    socks_status_e      st;
    short               what;
    _Bool               reversed;
    EVP_CIPHER_CTX      *evp_cipher_ctx;
    EVP_CIPHER_CTX      *evp_decipher_ctx;
};

void e_start_server(void);
void resolve(struct e_context_s *s);
void err_writecb(struct bufferevent *bev, void *ctx);
void close_on_finished_writecb(struct bufferevent *bev, void *ctx);
void resolvecb(int errcode, struct evutil_addrinfo *ai, void *ptr);
void fast_streamcb(struct bufferevent *bev, void *ctx);
void handle_streamcb(struct bufferevent *bev, void *ctx);
void evs_setcb_for_local(struct bufferevent *bev, void *context);
void eventcb(struct bufferevent *bev, short what, void *ctx);
void clean_dns_cache_func(evutil_socket_t sig_flag, short what, void *ctx);
int daemonize(int nochdir, int noclose);

#endif
