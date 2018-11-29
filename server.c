/*
 * Use of this source code is governed by a
 * license that can be found in the LICENSE file.
 *
 */

#define MAX_OUTPUT (4096*512)
#define BACKLOG 1024

#include "config.h"
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <signal.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <event2/dns.h>

#ifdef HAVE_GETOPT
#include <getopt.h>
#endif

#include "def.h"
#include "log.h"
#include "lru.h"
#include "server.h"
#include "helper.h"
#include "crypto.h"

/* Global settings */
struct settings settings;
static struct event_base *e_base;
static struct evdns_base *dns_base;

/* Lru node for dns cache */
static struct lru_node_s *node;

static void signalcb(evutil_socket_t sig_flag, short what, void *ctx);
static void sigpipecb(evutil_socket_t sig_flag, short what, void *ctx);
static void listencb(evutil_socket_t, short, void*);
static void acceptcb(evutil_socket_t, short, void*);
static void initcb(struct bufferevent *bev, void *ctx);
static void parse_headercb(struct bufferevent *bev, void *ctx);
static void next_readcb(struct bufferevent *bev, void *ctx);
static void event_log(short what, struct e_context_s *ctx);
static void close_writecb(struct bufferevent *bev, void *ctx);
static void libevent_dns_logfn(int is_warn, const char *msg);
static void libevent_logfn(int severity, const char *msg);
static struct e_context_s *e_new_context(void);
static void e_free_context(struct e_context_s *ctx);
const char *_getprogname(void) { return "esocks"; }

void e_start_server(void)
{
  struct event *signal_event;
  struct event *sigpipe_event;
  struct event *listen_event;
  struct event *handle_dns_cache;
  struct dns_cache_config cache_config;
  struct sockaddr_in sin;
  struct sockaddr_in proxy_sin;
  struct timeval dns_cache_tval = {settings.dns_cache_tval, 0};
  void *proxy = NULL;
  int fd;
  int signal_flags = 0;
  int socktype = SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC;

  memset(&sin, 0, sizeof(sin));
  sin.sin_family = AF_INET;

  if (settings.relay_mode) {
    sin.sin_port = htons(settings.listen_port);
    if (!(evutil_inet_pton(AF_INET, settings.listen_addr,
			   (struct sockaddr *)&sin.sin_addr)))
      log_ex(1, "%s: evutil_inet_pton()", __func__);

    memset(&proxy_sin, 0, sizeof(proxy_sin));
    proxy_sin.sin_family = AF_INET;
    proxy_sin.sin_port = htons(settings.server_port);

    if (!(evutil_inet_pton(AF_INET, settings.server_addr,
			   (struct sockaddr *)&proxy_sin.sin_addr)))
      log_ex(1, "%s: evutil_inet_pton()", __func__);

    proxy = &proxy_sin;
    settings.proxy = proxy;
  } else {
    sin.sin_port = htons(settings.listen_port);
    if (!(evutil_inet_pton(AF_INET, settings.listen_addr,
			   (struct sockaddr *)&sin.sin_addr)))
      log_ex(1, "%s: evutil_inet_pton()", __func__);
  }

  fd = socket(AF_INET, socktype, 0);
  if (fd == -1)
    goto err;

  if (DEBUG) {
    event_set_log_callback(libevent_logfn);
    evdns_set_log_fn(libevent_dns_logfn);
  }

#if defined(HAVE_TCP_FASTOPEN) && defined(HAVE_TCP_NODELAY)
  int optval = 5;

  log_i("%s: set tcp_fastopen and tcp_nodelay", __func__);

  if (setsockopt(fd, SOL_TCP, TCP_FASTOPEN, (void *)&optval, sizeof(optval)) < 0)
    log_ex(1, "%s: setsockopt, level=TCP, opt=TCP_FASTOPEN", __func__);

  if (setsockopt(fd, SOL_TCP, TCP_NODELAY, (void *)&optval, sizeof(optval)) < 0)
    log_ex(1, "%s: setsockopt, level=TCP, opt=TCP_NODELAY", __func__);
#endif

  if (evutil_make_socket_nonblocking(fd) < 0)
    goto err;
  if (evutil_make_listen_socket_reuseable(fd) < 0)
    goto err;
  if (evutil_make_listen_socket_reuseable_port(fd) < 0)
    goto err;
  if (evutil_make_tcp_listen_socket_deferred(fd) < 0)
    goto err;
  if (bind(fd, (struct sockaddr *)&sin, sizeof(sin)) < 0)
    goto err;
  if (listen(fd, BACKLOG) < 0)
    goto err;

#if defined(LIBEVENT_VERSION_NUMBER) && LIBEVENT_VERSION_NUMBER >= 0x02000100
  log_d(DEBUG, "setting LIBEVENT_BASE_FLAG_USE_EPOLL_CHANGELIST");
  /* Let's use a cool feature from libevent:
     Setting this flag can make your code run faster, but it may trigger a Linux bug:
     it is not safe to use this flag if you have any fds cloned by dup() or its variants.
     Doing so will produce strange and hard-to-diagnose bugs. */
  struct event_config *e_conf;

  e_conf = event_config_new();
  event_config_set_flag(e_conf, EVENT_BASE_FLAG_EPOLL_USE_CHANGELIST);
  e_base = event_base_new_with_config(e_conf);
  event_config_free(e_conf);
#else
  e_base = event_base_new();
#endif

  signal_event = event_new(e_base, SIGTERM|SIGKILL|SIGINT,
			   EV_SIGNAL|EV_PERSIST, signalcb, (void *)e_base);
  event_add(signal_event, NULL);

  /* SIGPIPE happens when connection is reset by peer. */
  signal_flags |= SIGPIPE;
  sigpipe_event = event_new(e_base, signal_flags,
			    EV_SIGNAL|EV_PERSIST, sigpipecb, (void *)e_base);
  event_add(sigpipe_event, NULL);

  listen_event = event_new(e_base, fd,
			   EV_READ|EV_PERSIST, listencb, NULL);
  event_add(listen_event, NULL);

  if (!settings.proxy) {
    memset(&cache_config, 0, sizeof(struct dns_cache_config));

    log_i("%s: start DNS service", __func__);

    dns_base = evdns_base_new(e_base, EVDNS_BASE_DISABLE_WHEN_INACTIVE);
    if (dns_base == NULL)
      log_ex(1, "%s: evdns_base_new", __func__);

    if (settings.nameserver)
      log_ex(1, "%s: failed to add nameserver(s)", __func__);

    if (evdns_base_resolv_conf_parse(dns_base,
				     DNS_OPTION_NAMESERVERS, settings.resolv_conf) < 0)
      log_ex(1, "%s: evdns_base_resolv_conf_parse()", __func__);

    node = lru_init();
    ASSERT(node != NULL);

    cache_config.cache = node;
    cache_config.timeout = (long) dns_cache_tval.tv_sec;

    handle_dns_cache = event_new(e_base, -1,
				 EV_TIMEOUT|EV_PERSIST, clean_dns_cache_func,
				 (void *)&cache_config);

    event_add(handle_dns_cache, &dns_cache_tval);
  }

  event_base_dispatch(e_base);
  event_free(signal_event);
  event_free(sigpipe_event);
  event_free(listen_event);
  event_base_free(e_base);
  if (!settings.proxy) {
    evdns_base_free(dns_base, 0);
    lru_purge_all(&node);
  }
  crypto_shutdown();
  return;

 err:
  evutil_closesocket(fd);
  log_ex(1, "%s: A fatal error occurred", __func__);
}

static void listencb(evutil_socket_t fd, short what, void *ctx)
{
  int new_fd;
  socklen_t addrlen;
  u8 cli_addr[128];

  while (1) {
    struct sockaddr_storage ss;
    addrlen = sizeof(ss);

#if (HAVE_ACCEPT4)
    new_fd = accept4(fd, (struct sockaddr *)&ss, &addrlen, SOCK_NONBLOCK);
#else
    new_fd = accept(fd, (struct sockaddr *)&ss, &addrlen);
#endif
    if (new_fd < 0)
      break;

    if (addrlen == 0) {
      /* This can happen with some older linux kernels in
       * response to nmap. */
      evutil_closesocket(new_fd);
      continue;
    }

    evutil_inet_ntop(ss.ss_family, e_get_sockaddr_storage(&ss), (char *)cli_addr, addrlen);
    log_i("connection from %s", cli_addr);

    if (evutil_make_socket_closeonexec(fd) < 0)
      log_warn("%s: evutil_make_socket_closeonexec()", __func__);
    if (evutil_make_socket_nonblocking(fd) < 0)
      log_warn("%s: evutil_make_socket_nonblocking()", __func__);

    acceptcb(new_fd, what, ctx);
  }

  if (fd == EAGAIN || fd == EWOULDBLOCK || fd == ECONNABORTED || fd == EINTR) {
    log_warn("%s: fd error code=%d", __func__, fd);
    evutil_closesocket(new_fd);
  }
}

static struct e_context_s* e_new_context(void)
{
  struct e_context_s *ctx;

  ctx = calloc(1, sizeof(struct e_context_s));

  if (ctx != NULL) {
    ctx->bev = NULL;
    ctx->partner = NULL;
    ctx->sin = NULL;
    ctx->sin6 = NULL;
    ctx->socks_addr = NULL;
    ctx->st = 0;
    ctx->reversed = false;
    ctx->event_handler = NULL;
    ctx->evp_cipher_ctx = EVP_CIPHER_CTX_new();
    ctx->evp_decipher_ctx = EVP_CIPHER_CTX_new();

    if (!EVP_CipherInit_ex(ctx->evp_cipher_ctx, settings.cipher, NULL,
			   settings.key, settings.iv, 1))
      return NULL;
    if (!EVP_CipherInit_ex(ctx->evp_decipher_ctx, settings.cipher, NULL,
			   settings.key, settings.iv, 0))
      return NULL;
  }

  return ctx;
}

static void e_free_context(struct e_context_s *ctx)
{
  if (ctx != NULL && ctx->st == e_destroy) {

    log_d(DEBUG, "freeing context key=%s", ctx->domain == NULL ? "raw addr" :
	  ctx->domain);

    ctx->reversed ?
      bufferevent_free(ctx->partner) :
      bufferevent_free(ctx->bev);

    ctx->st = 0;
    ctx->partner = NULL;
    ctx->bev = NULL;

    if (ctx->evp_cipher_ctx && ctx->evp_decipher_ctx) {

      EVP_CIPHER_CTX_cleanup(ctx->evp_cipher_ctx);
      EVP_CIPHER_CTX_free(ctx->evp_cipher_ctx);

      EVP_CIPHER_CTX_cleanup(ctx->evp_decipher_ctx);
      EVP_CIPHER_CTX_free(ctx->evp_decipher_ctx);
    }
    /* To avoid double free, make sure a ctx becomes NULL. */
    ctx = NULL;
    free(ctx);
  }
}

static void acceptcb(evutil_socket_t fd, short what, void *ctx)
{
  struct bufferevent *bev;
  struct bufferevent *partner;
  struct e_context_s *context;
  struct timeval tval = {settings.connection_timeout, 0};
  u8 addr[128];

  bev = bufferevent_socket_new(e_base, fd,
			       BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);

  partner = bufferevent_socket_new(e_base, -1,
				   BEV_OPT_CLOSE_ON_FREE|
				   BEV_OPT_DEFER_CALLBACKS);

  context = e_new_context();

  ASSERT(bev && partner && context);

  context->partner = partner;
  context->bev = bev;
  context->what = what;

  // Set timeout and we can avoid CLOSE-WAIT state.
  bufferevent_set_timeouts(bev, &tval, &tval);
  bufferevent_set_timeouts(partner, &tval, &tval);

  if (settings.proxy) {
    // Set up proxy
    // TODO: use sockaddr_storage instead here!
    struct sockaddr_in *sin = (struct sockaddr_in *)settings.proxy;

    context->st = e_init;
    context->event_handler = (bufferevent_data_cb *)fast_streamcb;

    evutil_inet_ntop(AF_INET, (struct sockaddr *)&sin->sin_addr, (char *)addr, sizeof(addr));
    log_i("%s: connect to %s", __func__, addr);

    if (bufferevent_socket_connect(context->partner, (struct sockaddr *)sin,
				   sizeof(struct sockaddr_in)) != 0) {
      u8 reply[2] = {5, NETWORK_UNREACHABLE};

      log_e("bufferevent_socket_connect(): failed to connect");
      bufferevent_write(bev, reply, 2);
      context->st = e_destroy;
      e_free_context(context);
    }

    if (context->st == e_init) {
      // local server directly goes to streamcb.
      context->st = e_connected;
      evs_setcb_for_local(bev, context);
      bufferevent_enable(bev, EV_READ|EV_WRITE);
    }

  } else {
    context->event_handler = (bufferevent_data_cb *)handle_streamcb;
    bufferevent_setcb(bev, initcb, NULL, eventcb, context);
    bufferevent_enable(bev, EV_READ|EV_WRITE);
  }
}

void eventcb(struct bufferevent *bev, short what, void *ctx)
{
  struct e_context_s *context = ctx;
  struct bufferevent *partner;

  partner = context->reversed ? context->bev : context->partner;

  event_log(what, context);

  if (what & (BEV_EVENT_EOF|BEV_EVENT_ERROR|BEV_EVENT_TIMEOUT)) {
    if (partner != NULL) {
      /* Flush leftover */
      (*(bufferevent_data_cb)context->event_handler)(bev, ctx);

      if (evbuffer_get_length(bufferevent_get_output(partner))) {
	log_d(DEBUG, "set to close_on_finished_writecb");
	context->st = e_destroy;
	bufferevent_setcb(partner, NULL,
			  close_on_finished_writecb, eventcb, context);
	bufferevent_disable(partner, EV_READ);
      } else {
	/* We have nothing left to say to the other
	 * side; close it! */
	log_d(DEBUG, "nothing to write and let partner go");
	bufferevent_free(partner);
	context->st = e_destroy;
      }
    }

    e_free_context(context);
  }
}

static void initcb(struct bufferevent *bev, void *ctx)
{
  struct evbuffer *src = bufferevent_get_input(bev);
  struct e_context_s *context = ctx;
  size_t buf_size = evbuffer_get_length(src);
  u8 buf[buf_size];
  u8 enc_buf[SOCKS_MAX_BUFFER_SIZE];
  u8 dec_buf[SOCKS_MAX_BUFFER_SIZE];
  int outl;

  // dec
  evbuffer_copyout(src, buf, buf_size);
  evbuffer_drain(src, buf_size);
  e_decrypt(context->evp_decipher_ctx, buf, buf_size, dec_buf);

  log_i("%s: getting client and have %ld bytes", __func__, buf_size);

  // TODO: check NMETHODS
  if (dec_buf[0] == SOCKS_VERSION && dec_buf[2] == NO_AUTHENTICATION) {
    // enc
    u8 p[2] = {SOCKS_VERSION, SUCCEEDED};

    outl = e_encrypt(context->evp_cipher_ctx, p, sizeof(p), enc_buf);
    bufferevent_write(bev, enc_buf, outl);
    context->st = e_init;
    bufferevent_setcb(bev, parse_headercb, NULL, eventcb, context);
    bufferevent_enable(bev, EV_READ|EV_WRITE);
  } else {
    log_e("%s: wrong version=%d", __func__, dec_buf[0]);
    context->st = e_destroy;
    e_free_context(context);
  }

}

enum {
  connect_cmd = 1,
  bind_cmd,
  udpassoc_cmd,
} socks_cmd_e;

static void parse_headercb(struct bufferevent *bev, void *ctx)
{
  struct sockaddr_in sin;
  struct evbuffer *src = bufferevent_get_input(bev);
  struct e_context_s *context = ctx;
  struct bufferevent *partner = context->partner;
  lru_node_t *cached;
  int res;
  int try;
  int buf_len;
  u16 port;
  char tmpl4[SOCKS_INET_ADDRSTRLEN];
  static const char fmt4[] = "%d.%d.%d.%d";
  size_t buf_size = evbuffer_get_length(src);
  size_t dlen;
  size_t buflen;
  u8 buf[buf_size];
  u8 portbuf[2];
  u8 buf4[4];
  u8 domain[256];
  u8 socks_reply[10] = {SOCKS_VERSION, SUCCEEDED, 0, 1, 0, 0, 0, 0, 0, 0};
  u8 dec_buf[SOCKS_MAX_BUFFER_SIZE];
  u8 enc_buf[SOCKS_MAX_BUFFER_SIZE];
  u8 server_addr[128];

  // dec
  evbuffer_copyout(src, buf, buf_size);
  evbuffer_drain(src, buf_size);

  e_decrypt(context->evp_decipher_ctx, buf, buf_size, dec_buf);

  if (context->st == e_init && dec_buf[0] == SOCKS_VERSION) {
    switch (dec_buf[1]) {
    case connect_cmd:
    case bind_cmd:
      break;
    case udpassoc_cmd:
      log_warn("%s: udp associate is not supported", __func__);
      context->st = e_destroy;
      break;
    default:
      log_warn("%s: unkonw command: %d", __func__, dec_buf[1]);
      // enc
      socks_reply[1] = GENERAL_FAILURE;
      buf_len = e_encrypt(context->evp_cipher_ctx, socks_reply,
			  sizeof(socks_reply), enc_buf);
      bufferevent_write(bev, enc_buf, buf_len);
      bufferevent_disable(bev, EV_WRITE);
      context->st = e_destroy;
      break;
    }
  }

  if (context->st != e_init) {
    e_free_context(context);
    return;
  }

  // Connect to the server
  switch (dec_buf[3]) {
  case IPV4:
    log_i("%s: IPv4, connect immediate", __func__);
    memcpy(buf4, dec_buf + 4, sizeof(buf4));
    evutil_snprintf(tmpl4, sizeof(tmpl4), fmt4, buf4[0], buf4[1], buf4[2], buf4[3]);
    memset(&sin, 0, sizeof(sin));
    res = evutil_inet_pton(AF_INET, (char *)tmpl4, &sin.sin_addr);
    if (res <= 0) {
      log_e("%s: inet_pton() failed to resolve addr", __func__);
      socks_reply[1] = HOST_UNREACHABLE;
      bufferevent_write(bev, socks_reply, 10);
      break;
    }

    memcpy(portbuf, dec_buf + 8, 2);
    port = portbuf[0] << 8 | portbuf[1];
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);

    evutil_inet_ntop(AF_INET, (struct sockaddr *)&sin.sin_addr,
		     (char *)server_addr, sizeof(server_addr));
    log_i("%s: connecting to %s", __func__, server_addr);

    if (bufferevent_socket_connect(partner, (struct sockaddr *)&sin,
				   sizeof(struct sockaddr_in)) != 0) {
      log_e("%s: connect() failed to connect", __func__);
      socks_reply[1] = CONNECTION_REFUSED;
      buf_len = e_encrypt(context->evp_cipher_ctx, socks_reply,
			  sizeof(socks_reply), enc_buf);
      bufferevent_write(bev, enc_buf, buf_len);
      context->st = e_destroy;
    } else
      context->st = e_connected;
    break;
  case IPV6:
    log_e("%s: IPv6 is not supported yet", __func__);
    socks_reply[1] = ADDRESS_TYPE_NOT_SUPPORTED;
    // enc
    bufferevent_write(bev, socks_reply, 10);
    context->st = e_destroy;
    break;
  case DOMAINN:
    dlen = (u8)dec_buf[4];
    buflen = (int)dlen + 5;

    // Get port info first
    memcpy(portbuf, dec_buf + buflen, 2);
    port = portbuf[0]<<8 | portbuf[1];

    // Get a name bytes sequence
    memset(domain, 0, dlen);
    memcpy(domain, dec_buf + 5, dlen);

    e_copy(context->domain, (char *)&domain, dlen);

    context->port = htons(port);
    context->st = e_dns_wip;

    cached = lru_get_node(&node, context->domain, (lru_cmp_func *)strcmp);
    if (cached) {
      log_d(DEBUG, "%s: cached: \"%s\"", __func__, context->domain);

      socks_addr_t *addrinfo = (socks_addr_t *)cached->payload_ptr;

      // Start to connect to a server.
      for (try = 0; try < addrinfo->naddrs; try++) {
	struct sockaddr_in ssin;

	memset(&ssin, 0, sizeof(ssin));
	memcpy(&ssin, addrinfo->addrs[try].sockaddr, addrinfo->addrs[try].socklen);
	ssin.sin_family = AF_INET;
	ssin.sin_port = context->port;

	if (bufferevent_socket_connect(context->partner, (struct sockaddr *)&ssin,
				       sizeof(struct sockaddr_in)) == 0) {
	  log_i("%s: got connected to %s index=%d",
		__func__, context->domain, try);
	  context->st = e_connected;
	  break;
	}
      }
    } else
      resolve(context);

    break;
  default:
    log_warn("strange command=%d", buf[3]);
    context->st = e_destroy;
  }

  if (context->st == e_connected) {
    int outl = e_encrypt(context->evp_cipher_ctx, socks_reply,
			 sizeof(socks_reply), enc_buf);
    bufferevent_write(bev, enc_buf, outl);
    bufferevent_setcb(bev, next_readcb, NULL, eventcb, context);
    bufferevent_enable(bev, EV_READ|EV_WRITE);
  }
  if (context->st == e_destroy)
    e_free_context(context);
}

static void close_writecb(struct bufferevent *bev, void *ctx)
{
  struct e_context_s *context = ctx;
  struct bufferevent *partner = context->partner;

  /* We were choking the other side until we drained our outbuf a bit.
   * Now it seems drained. */
  bufferevent_setcb(bev, handle_streamcb, NULL, eventcb, context);
  bufferevent_setwatermark(bev, EV_WRITE, 0, 0);

  if (partner)
    bufferevent_enable(partner, EV_READ);
}

static void next_readcb(struct bufferevent *bev, void *ctx)
{
  struct e_context_s *context = ctx;
  struct bufferevent *partner = context->partner;
  struct evbuffer *src = bufferevent_get_input(bev);
  size_t buf_size = evbuffer_get_length(src);
  u8 buf[buf_size];
  u8 dec_buf[SOCKS_MAX_BUFFER_SIZE];

  if (context->st == e_connected && buf_size) {
    evbuffer_copyout(src, buf, buf_size);
    evbuffer_drain(src, buf_size);

    // dec
    int outl = e_decrypt(context->evp_decipher_ctx, buf, buf_size, dec_buf);

    if (bufferevent_write(partner, dec_buf, outl) < 0) {
      log_e("%s: bufferevent_write", __func__);
      context->st = e_destroy;
    } else {
      context->reversed = true;
      context->st = e_connected;
      bufferevent_setcb(partner, handle_streamcb, NULL, eventcb, context);
      bufferevent_enable(partner, EV_WRITE|EV_READ);
    }
  }
}

void handle_streamcb(struct bufferevent *bev, void *ctx)
{
  struct e_context_s *context = ctx;
  struct bufferevent *partner = context->bev;
  struct evbuffer *src = bufferevent_get_input(bev);
  struct evbuffer *dst;
  int outl;
  size_t buf_size = evbuffer_get_length(src);
  u8 buf[buf_size];
  u8 enc_buf[SOCKS_MAX_BUFFER_SIZE];

  if (!partner || !buf_size) {
    evbuffer_drain(src, buf_size);
    return;
  }

  if (context->st == e_connected && buf_size && context->partner) {
    // enc
    evbuffer_copyout(src, buf, buf_size);
    evbuffer_drain(src, buf_size);
    outl = e_encrypt(context->evp_cipher_ctx, buf, buf_size, enc_buf);

    if (bufferevent_write(partner, enc_buf, outl) != 0) {
      log_e("%s: failed to write", __func__);
      context->st = e_destroy;
    } else {
      // Keep doing proxy until there is no data
      bufferevent_setcb(bev, handle_streamcb, NULL, eventcb, context);
      bufferevent_enable(bev, EV_READ|EV_WRITE);

      dst = bufferevent_get_output(partner);

      if (evbuffer_get_length(dst) >= MAX_OUTPUT) {
	log_d(DEBUG, "%s: setting watermark bufsize=%ld",
	      __func__, evbuffer_get_length(dst));
	bufferevent_setcb(partner, handle_streamcb, close_writecb, eventcb,
			  context);
	bufferevent_setwatermark(partner, EV_WRITE, MAX_OUTPUT/2, MAX_OUTPUT);
	bufferevent_disable(bev, EV_READ);
      }
    }
  }
}

void resolve(struct e_context_s *context)
{
  struct evutil_addrinfo hints;

  if (!context->bev)
    return;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = PF_INET; // Let's prefer IPV4 for now
  hints.ai_protocol = IPPROTO_UDP;
  hints.ai_flags = EVUTIL_AI_CANONNAME;

  if (!evdns_getaddrinfo(dns_base, context->domain, NULL, &hints, resolvecb, context))
    context->st = e_destroy;
}

void resolvecb(int errcode, struct evutil_addrinfo *ai, void *ptr)
{
  struct sockaddr_in *sin_p;
  struct e_context_s *context = ptr;
  struct evutil_addrinfo *ai_p;
  socks_addr_t *socks_addr;
  int i;
  int try;
  // Send out 10 bytes to reply OK!
  u8 resp[10] = {5, 0, 0, 1, 0, 0, 0, 0, 0, 0};
  u8 enc_buf[SOCKS_MAX_BUFFER_SIZE];

  if (errcode != 0 || ai == NULL) {
    log_e("%s: %s:%s", __func__, context->domain, evutil_gai_strerror(errcode));
    context->st = e_destroy;
    return;
  }

  if (context->st == e_dns_wip) {
    for (i = 0, ai_p = ai; ai_p != NULL; ai_p = ai_p->ai_next) {
      switch (ai_p->ai_family) {
      case AF_INET:
      case AF_INET6:
	break;
      default:
	continue;
      }
      i++;
    }

    if (i == 0)
      goto failed;

    socks_addr = calloc(1, sizeof(socks_addr_t));
    if (!socks_addr)
      log_warn("%s: calloc", __func__);

    socks_addr->addrs = malloc(i * sizeof(struct socks_addr));
    if (!socks_addr->addrs)
      log_warn("%s: malloc", __func__);

    socks_addr->naddrs = i;

    for (i = 0, ai_p = ai; ai_p != NULL; ai_p = ai_p->ai_next) {
      if (ai_p->ai_family != AF_INET)
	continue;

      sin_p = malloc(sizeof(struct sockaddr_in));
      if (!sin_p)
	log_warn("%s: malloc", __func__);

      memcpy(sin_p, ai_p->ai_addr, ai_p->ai_addrlen);

      sin_p->sin_port = context->port;
      sin_p->sin_family = AF_INET;

      socks_addr->addrs[i].sockaddr = (struct sockaddr *)sin_p;
      socks_addr->addrs[i].socklen = ai_p->ai_addrlen;

      i++;
    }

    log_i("%s: connect to %s", context->domain, __func__);

    context->socks_addr = socks_addr;

    // Start to connect to a server.
    for (try = 0; try < i; try++) {
      struct sockaddr_in sin;

      memset(&sin, 0, sizeof(sin));
      memcpy(&sin, context->socks_addr->addrs[try].sockaddr,
	     context->socks_addr->addrs[try].socklen);

      sin.sin_family = AF_INET;
      sin.sin_port = context->port;

      if (bufferevent_socket_connect(context->partner, (struct sockaddr *)&sin,
				     sizeof(struct sockaddr_in)) == 0) {
	log_i("%s: changing status to e_dns_ok", __func__);
	context->st = e_dns_ok;
	break;
      }
    }

    if (node != NULL)
      lru_insert_left(&node, (const char *)context->domain,
		      context->socks_addr, sizeof(context->socks_addr));
  }

  if (context->st == e_dns_ok) {
    context->st = e_connected;

    if (context->bev != NULL) {
      int outl = e_encrypt(context->evp_cipher_ctx, resp, sizeof(resp), enc_buf);

      bufferevent_write(context->bev, enc_buf, outl);
      bufferevent_setcb(context->bev, next_readcb, NULL, eventcb, context);
      bufferevent_enable(context->bev, EV_READ|EV_WRITE);
    }
  } else {
    context->st = e_destroy;
    log_i("%s: can\'nt establish connection to %s", context->domain, __func__);
  }

  if (ai)
    evutil_freeaddrinfo(ai);

  return;

 failed:
  context->st = e_destroy;

  if (ai)
    evutil_freeaddrinfo(ai);
}

void close_on_finished_writecb(struct bufferevent *bev, void *ctx)
{
  struct evbuffer *evb = bufferevent_get_output(bev);

  if (evbuffer_get_length(evb) == 0) {
    log_d(DEBUG, "close_on_finished_writecb");
    e_free_context(ctx);
  }
}

static void sigpipecb(evutil_socket_t sig_flag, short what, void *ctx)
{
  log_warn("connection reset by peer");
}

static void signalcb(evutil_socket_t sig_flag, short what, void *ctx)
{
  struct event_base *base = ctx;
#define SIGNAL_DELAY 2
  struct timeval delay = {SIGNAL_DELAY, 0};
  int sec = SIGNAL_DELAY;

  log_i("Caught an interupt signal; exiting cleanly in %d second(s)", sec);
  event_base_loopexit(base, &delay);
}

void clean_dns_cache_func(evutil_socket_t sig_flag, short what, void *ctx)
{
  struct dns_cache_config *config = ctx;
  socks_addr_t *addrinfo;
  int i;

  if (what & EV_TIMEOUT) {
    while ((addrinfo = (socks_addr_t *)lru_get_oldest_payload(&config->cache,
							      config->timeout))) {
      if (addrinfo) {
	for (i = 0; i < addrinfo->naddrs; i++) {
	  free(addrinfo->addrs[i].sockaddr);
	  addrinfo->addrs[i].sockaddr = NULL;
	}

	free(addrinfo->addrs);
	free(addrinfo);
	addrinfo = NULL;
	log_d(DEBUG, "%s: sweeping dns cache", __func__);
      }
    }
  }
}

static void libevent_dns_logfn(int is_warn, const char *msg) {
  is_warn ? log_warn("%s", msg) : log_i("%s", msg);
}

static void libevent_logfn(int severity, const char *msg)
{
  switch (severity) {
  case EVENT_LOG_DEBUG:
    log_i(msg);
    break;
  case EVENT_LOG_MSG:
    log_i(msg);
    break;
  case EVENT_LOG_WARN:
    log_warn(msg);
    break;
  case EVENT_LOG_ERR:
    log_e(msg);
    break;
  default:
    break;
  }
}

static void event_log(short what, struct e_context_s *ctx)
{
  log_d(DEBUG, "reversed=%s status=%d domain=%s event=%s %s %s %s %s %s",
	ctx->reversed ? "true" : "false",
	ctx->st,
	ctx->domain == NULL ? "raw addr" : ctx->domain,
	(what & BEV_EVENT_READING) ? "e_reading" : "",
	(what & BEV_EVENT_WRITING) ? "e_writing" : "",
	(what & BEV_EVENT_EOF) ? "e_eof" : "",
	(what & BEV_EVENT_ERROR) ? "e_error" : "",
	(what & BEV_EVENT_TIMEOUT) ? "e_timeout" : "",
	(what & BEV_EVENT_CONNECTED) ? "e_connected" : "");
}

int e_encrypt(EVP_CIPHER_CTX *ctx, u8 *in, int ilen, u8 *out)
{
  return openssl_encrypt(ctx, out, in, ilen);
}

int e_decrypt(EVP_CIPHER_CTX *ctx, u8 *in, int ilen, u8 *out)
{
  return openssl_decrypt(ctx, out, in, ilen);
}
