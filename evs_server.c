/*
 * Use of this source code is governed by a
 * license that can be found in the LICENSE file.
 *
 */

#define MAX_OUTPUT 1024 * 512
#define BACKLOG 1024

#include "evs-internal.h"

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

#include "evs_log.h"
#include "evs_lru.h"
#include "evs_server.h"
#include "evs_helper.h"
#include "crypto.h"

struct settings settings;
static struct event_base *base = NULL;
static struct evdns_base *dns_base = NULL;
static struct lru_node_s *node = NULL;

static void signal_func(evutil_socket_t sig_flag, short what, void *ctx);
static void pass_through_func(evutil_socket_t sig_flag, short what, void *ctx);
static void listen_func(evutil_socket_t, short, void*);
static void accept_func(evutil_socket_t, short, void*);
static void socks_initcb(struct bufferevent *bev, void *ctx);
static void parse_header_cb(struct bufferevent *bev, void *ctx);
static void next_readcb(struct bufferevent *bev, void *ctx);
static void print_address(struct sockaddr *, int type, const char *ctx);
static void event_logger(short what, struct ev_context_s *ctx);
static void unchoke_writecb(struct bufferevent *bev, void *ctx);
static void dns_logfn(int is_warn, const char *msg);
static struct ev_context_s *ev_new_context(void);
const char * _getprogname(void) { return "esocks"; }

void
run_srv(void)
{
  struct event *signal_event, *sigpipe_event, *listen_event;
  struct dns_cache_config cache_config;
  struct sockaddr_in sin, proxy_sin;
  struct timeval dns_cache_tval = {300, 0}; // 5 minutes

  int fd;
  void *proxy = NULL;
  int socktype = SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC;

  // Init OpenSSL
  // TODO: free all loaded memory
  crypto_init();

  memset(&sin, 0, sizeof(sin));
  sin.sin_family = AF_INET;

  if (settings.relay_mode)
    {
      sin.sin_port = htons(settings.srv_port);
      if (!(evutil_inet_pton(AF_INET, settings.srv_addr,
			     (struct sockaddr*)&sin.sin_addr)))
	log_ex(1, "evutil_inet_pton");

      memset(&proxy_sin, 0, sizeof(proxy_sin));
      proxy_sin.sin_family = AF_INET;
      proxy_sin.sin_port = htons(settings.server_port);

      if (!(evutil_inet_pton(AF_INET, settings.server_addr,
			     (struct sockaddr*)&proxy_sin.sin_addr)))
	log_ex(1, "evutil_inet_pton");

      proxy = &proxy_sin;
    }
  else
    {
      sin.sin_port = htons(settings.srv_port);
      if (!(evutil_inet_pton(AF_INET, settings.srv_addr,
			     (struct sockaddr*)&sin.sin_addr)))
	log_ex(1, "evutil_inet_pton");
    }

  settings.proxy = proxy;

  fd = socket(AF_INET, socktype, 0);
  if (fd == -1)
    goto err;

#if defined(HAVE_TCP_FASTOPEN) && defined(HAVE_TCP_NODELAY)

  int optval = 5;

  log_i("set tcp_fastopen and tcp_nodelay");

  if (setsockopt(fd, SOL_TCP, TCP_FASTOPEN, (void*)&optval, sizeof(optval)) < 0)
    log_ex(1, "setsockopt, level=TCP, opt=TCP_FASTOPEN");

  if (setsockopt(fd, SOL_TCP, TCP_NODELAY, (void*)&optval, sizeof(optval)) < 0)
    log_ex(1, "setsockopt, level=TCP, opt=TCP_NODELAY");
#endif

  int flags;
  if ((flags = fcntl(fd, F_GETFL, NULL)) < 0)
    goto err;
  if (!(flags & O_NONBLOCK))
    goto err;

  if (evutil_make_listen_socket_reuseable(fd) < 0)
    goto err;
  if (evutil_make_listen_socket_reuseable_port(fd) < 0)
    goto err;
  if (evutil_make_tcp_listen_socket_deferred(fd) < 0)
    goto err;
  if (bind(fd, (struct sockaddr*)&sin, sizeof(sin)) < 0)
    goto err;
  if (listen(fd, BACKLOG) < 0)
    goto err;

  base = event_base_new();
  signal_event = event_new(base, SIGTERM,
			   EV_SIGNAL|EV_PERSIST, signal_func, (void*)base);
  event_add(signal_event, NULL);

  // SIGPIPE happens when connections are reset by peers
  sigpipe_event = event_new(base, SIGPIPE,
			    EV_SIGNAL|EV_PERSIST, pass_through_func, (void*)base);
  event_add(sigpipe_event, NULL);

  // Set Listener callback
  listen_event = event_new(base, fd,
			   EV_READ|EV_PERSIST, listen_func, NULL);
  event_add(listen_event, NULL);

  if (!settings.proxy)
    {

      struct event *handle_dns_cache;

      memset(&cache_config, 0, sizeof(struct dns_cache_config));

      log_i("start DNS service");

      // Start asynchronous dns services
      dns_base = evdns_base_new(base, EVDNS_BASE_DISABLE_WHEN_INACTIVE);
      if (dns_base == NULL)
	log_ex(1, "end_base_new");

      if (DEBUG)
	evdns_set_log_fn(dns_logfn);

      // Configure nameservers
      if (settings.nameserver)
	log_ex(1, "failed to add nameserver(s)");

      if (evdns_base_resolv_conf_parse(dns_base,
				       DNS_OPTION_NAMESERVERS, settings.resolv_conf) < 0)
	log_ex(1, "evdns_base_resolv_conf_parse");

      node = init_lru();
      ASSERT(node != NULL);

      cache_config.cache = node;
      cache_config.timeout = (long) dns_cache_tval.tv_sec;

      // Clean dns cache with timeout
      handle_dns_cache = event_new(base, -1,
				   EV_TIMEOUT|EV_PERSIST, clean_dns_cache_func,
				   (void*)&cache_config);

      event_add(handle_dns_cache, &dns_cache_tval);
    }

  event_base_dispatch(base);

  event_free(signal_event);
  event_free(sigpipe_event);
  event_free(listen_event);
  event_base_free(base);
  evdns_base_free(dns_base, 0);
  lru_purge_all(&node);
  crypto_shutdown();

  exit(0);

 err:
  evutil_closesocket(fd);
  log_ex(1, "A fatal error occurred");
}

static void
listen_func(evutil_socket_t fd, short what, void *ctx)
{
  int new_fd;
  socklen_t addrlen;

  while (1)
    {
      struct sockaddr_storage ss;
      addrlen = sizeof(ss);
      new_fd = accept(fd, (struct sockaddr*)&ss, &addrlen);

      if (new_fd < 0)
	break;

      if (addrlen == 0)
	{
	  /* This can happen with some older linux kernels in
	   * response to nmap. */
	  evutil_closesocket(new_fd);
	  continue;
	}

      if (fcntl(new_fd, F_SETFD, FD_CLOEXEC) == -1) {
	evutil_closesocket(new_fd);
	log_warn("fcntl, F_SETFD");
      }

      if (evutil_make_socket_nonblocking(fd) < 0)
	log_warn("socket_nonblocking");

      accept_func(new_fd, what, ctx);
    }

  if (fd == EAGAIN || fd == EWOULDBLOCK || fd == ECONNABORTED || fd == EINTR)
    log_warn("fd error code=%d", fd);
}

static struct ev_context_s *
ev_new_context(void)
{
  struct ev_context_s *s;

  s = calloc(1, sizeof(struct ev_context_s));

  if (s != NULL)
    {
      s->bev = NULL;
      s->partner = NULL;
      s->sin = NULL;
      s->sin6 = NULL;
      s->socks_addr = NULL;
      s->socks_addr->naddrs = 0;
      s->st = 0;
      s->reversed = false;
      s->event_handler = NULL;
    }

  return s;
}

static void
accept_func(evutil_socket_t fd, short what, void *ctx)
{
  struct bufferevent *bev, *partner;
  struct ev_context_s *context;
  struct timeval tval = {settings.timeout, 0};

  bev = bufferevent_socket_new(base, fd,
			       BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);

  partner = bufferevent_socket_new(base, -1,
				   BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);

  context = ev_new_context();

  ASSERT(bev && partner && context);

  context->partner = partner;
  context->bev = bev;
  context->what = what;

  // Set timeout and we can avoid CLOSE-WAIT state.
  bufferevent_set_timeouts(bev, &tval, &tval);
  bufferevent_set_timeouts(partner, &tval, &tval);

  if (settings.proxy) {
    // Set up proxy...
    struct sockaddr_in *sin = (struct sockaddr_in*)settings.proxy;

    context->st = ev_init;
    context->event_handler = (bufferevent_data_cb*)fast_streamcb;

    print_address((struct sockaddr*)&sin->sin_addr, AF_INET, "connect to");

    if (bufferevent_socket_connect(context->partner, (struct sockaddr*)sin,
				   sizeof(struct sockaddr_in)) != 0)
      {
	DEBUG ? log_ex(1, "connect: failed to connect")
	  : log_e("failed to connect");

	context->st = ev_destroy;
	bufferevent_setcb(bev, NULL, err_writecb, eventcb, context);
      }

    if (context->st == ev_init)
      {
	// local server directly goes to streamcb.
	// We want local server to run as fast as it can, so let's this as sharp as
	// can be!
	context->st = ev_connected;
	evs_setcb_for_local(bev, context);
	bufferevent_enable(bev, EV_READ|EV_WRITE);

      }

  } else
    {
      context->event_handler = (bufferevent_data_cb*)handle_streamcb;
      bufferevent_setcb(bev, socks_initcb, NULL, eventcb, context);
      bufferevent_enable(bev, EV_READ|EV_WRITE);
    }

}

void
eventcb(struct bufferevent *bev, short what, void *ctx)
{
  struct ev_context_s *context = ctx;
  struct bufferevent *partner = context->reversed ? context->bev : context->partner;

  // Simple analyzer to log events
  event_logger(what, context);

  if (what & (BEV_EVENT_EOF|BEV_EVENT_ERROR|BEV_EVENT_TIMEOUT))
    {
      if (partner != NULL)
	{
	  /* Flush leftover */
	  (*(bufferevent_data_cb)context->event_handler)(bev, ctx);

	  if (evbuffer_get_length(bufferevent_get_output(partner)))
	    {
	      log_d(DEBUG, "set to close_on_finished_writecb");
	      context->st = ev_freed;
	      bufferevent_setcb(partner, NULL,
				close_on_finished_writecb, eventcb, context);
	      bufferevent_disable(partner, EV_READ);
	    }
	  else
	    {
	      /* We have nothing left to say to the other
	       * spide; close it! */
	      log_d(DEBUG, "nothing to write and let partner go");
	      bufferevent_free(partner);
	      context->st = ev_freed;
	    }

	}

      if (context != NULL)
	{
	  log_d(DEBUG, "free context %s", context->domain);
	  log_d(DEBUG, "context->st %d", context->st);

	  if (context->st != 0 && context->st != ev_freed)
	    context->reversed ?
	      bufferevent_free(context->partner):
	      bufferevent_free(context->bev);

	  context->st = 0;
	  context->partner = NULL;
	  context->bev = NULL;
	  // To avoid double free, make sure a context becomes NULL.
	  context = NULL;
	  free(context);
	}
    }
}

static void
event_logger(short what, struct ev_context_s *ctx)
{
  log_d(DEBUG, "reversed=%s status=%d domain=%s event=%s %s %s %s %s %s",
	ctx->reversed ? "true" : "false",
	ctx->st,
	ctx->domain,
	(what & BEV_EVENT_READING  ) ? "ev_reading": "",
	(what & BEV_EVENT_WRITING  ) ? "ev_writing": "",
	(what & BEV_EVENT_EOF      ) ? "ev_eof": "",
	(what & BEV_EVENT_ERROR    ) ? "ev_error": "",
	(what & BEV_EVENT_TIMEOUT  ) ? "ev_timeout": "",
	(what & BEV_EVENT_CONNECTED) ? "ev_connected": "");
}

static void
socks_initcb(struct bufferevent *bev, void *ctx)
{
  struct evbuffer *src = bufferevent_get_input(bev);
  struct ev_context_s *context = ctx;
  size_t buf_size = evbuffer_get_length(src);
  u8 buf[buf_size], dec_buf[SOCKS_MAX_BUFFER_SIZE], enc_buf[SOCKS_MAX_BUFFER_SIZE];
  int outl;

  // dec
  evbuffer_copyout(src, buf, buf_size);
  evbuffer_drain(src, buf_size);

  decrypt_(buf, buf_size, dec_buf);

  if (dec_buf[0] == 5)
    {
      // Frist negotiation
      // enc
      u8 p[2] = {5, 0};

      outl = encrypt_(p, 2, enc_buf);

      if (bufferevent_write(bev, enc_buf, outl) != 0)
	{
	  log_e("bufferevent_write");
	  destroycb(bev, context);
	  return;
	}

      context->st = ev_init;

      bufferevent_setcb(bev, parse_header_cb, NULL, eventcb, context);
      bufferevent_enable(bev, EV_READ|EV_WRITE);

    } else
    destroycb(bev, context);
}

enum {
  c_connect = 1,
  c_bind,
  udpassoc
} socks_cmd_e;

static void
parse_header_cb(struct bufferevent *bev, void *ctx)
{
  struct sockaddr_in sin;
  struct evbuffer *src = bufferevent_get_input(bev);
  struct ev_context_s *context = ctx;
  struct bufferevent *partner = context->partner;
  size_t buf_size = evbuffer_get_length(src), dlen, buflen;
  int res, try;
  u8 buf[buf_size], portbuf[2], buf4[4],
    domain[256], resp[10] = {5, 0, 0, 1, 0, 0, 0, 0, 0, 0},
    dec_buf[SOCKS_MAX_BUFFER_SIZE];
  u16 port;
  char tmp4[SOCKS_INET_ADDRSTRLEN];
  lru_node_t *cached;

  // Todo: Support IPv6
  static const char fmt4[] = "%d.%d.%d.%d";
  u8 msg[2] = {5, 1};

  // dec
  evbuffer_copyout(src, buf, buf_size);
  evbuffer_drain(src, buf_size);

  decrypt_(buf, buf_size, dec_buf);

  /* Check if version is correct and status is equal to INIT */
  if (context->st == ev_init && dec_buf[0] == SOCKS_VERSION)
    {
      /* Parse socks header */
      switch (dec_buf[1]) {
      case c_connect:
      case c_bind:
	break;
      case udpassoc:
	log_warn("udp associate is not supported");
	context->st = ev_destroy;
	break;
      default:
	log_warn("unkonw command=%d", dec_buf[1]);
	context->st = ev_destroy;
	// bufferevent_setcb(bev, NULL, err_writecb, eventcb, context);
	// enc
	bufferevent_write(bev, msg, 2);
	bufferevent_disable(bev, EV_WRITE);
      }
    }

  if (context->st != ev_init) return;

  // Connect to the server
  switch(dec_buf[3])
    {

    case IPV4:
      memcpy(buf4, dec_buf + 4, sizeof(buf4));
      evutil_snprintf(tmp4, sizeof(tmp4), fmt4, buf4[0], buf4[1], buf4[2], buf4[3]);

      memset(&sin, 0, sizeof(sin));
      res = evutil_inet_pton(AF_INET, (char*)tmp4, &sin.sin_addr);

      if (res != 1)
	{
	  log_e("failed to resolve addr");
	  destroycb(bev, context);
	  return;
	}

      memcpy(portbuf, dec_buf + 8, 2);
      port = portbuf[0] << 8 | portbuf[1];
      sin.sin_family = AF_INET;
      sin.sin_port = htons(port);

      print_address((struct sockaddr*)&sin.sin_addr, AF_INET, NULL);

      if (bufferevent_socket_connect(partner, (struct sockaddr*)&sin,
				     sizeof(struct sockaddr_in)) != 0)
	{
	  log_e("connect: failed to connect");
	  resp[1] = 4;

	  // enc
	  if (bufferevent_write(bev, resp, 10) != 0)
	    {
	      destroycb(bev, context);
	      return;
	    }
	}

      context->st = ev_connected;

      log_i("IPv4: connect immediate");
      break;
    case IPV6:
      log_e("IPv6 is not supported yet");
      resp[1] = 4;
      // enc
      if (bufferevent_write(bev, resp, 10) != 0)
	{
	  destroycb(bev, context);
	  return;
	}
      break;
    case DOMAINN:
      dlen = (u8) dec_buf[4];
      buflen = (int) dlen + 5;

      // Get port info first
      memcpy(portbuf, dec_buf + buflen, 2);
      port = portbuf[0]<<8 | portbuf[1];

      // Get a name bytes sequence
      memset(domain, 0, dlen);
      memcpy(domain, dec_buf + 5, dlen);

      ev_copy(context->domain, (char*)&domain, dlen);

      context->port = htons(port);
      context->st = ev_dns_wip;

      cached = lru_get_node(&node, context->domain, (lru_cmp_func*)strcmp);
      if (cached)
	{
	  log_d(DEBUG, "cached: \"%s\"", context->domain);

	  socks_addr_t* addrinfo = (socks_addr_t*)cached->payload_ptr;

	  // Start to connect to a server.
	  for (try = 0; try < addrinfo->naddrs; try++) {
	    struct sockaddr_in ssin;
	    memset(&ssin, 0, sizeof(ssin));
	    memcpy(&ssin, addrinfo->addrs[try].sockaddr, addrinfo->addrs[try].socklen);
	    ssin.sin_family = AF_INET;
	    ssin.sin_port = context->port;

	    if (bufferevent_socket_connect(context->partner, (struct sockaddr*)&ssin,
					   sizeof(struct sockaddr_in)) != 0)
	      ; // Pass and try next address

	    else {
	      context->st = ev_connected;
	      break;
	    }

	  }

	}
      else
	resolve(context);

      break;
    default:
      log_warn("strange command=%d", buf[3]);
      context->st = ev_destroy;
    }

  if (context->st == ev_connected)
    {
      u8 enc_buf[SOCKS_MAX_BUFFER_SIZE];
      int outl = encrypt_(resp, 10, enc_buf);

      if (bufferevent_write(bev, enc_buf, outl) < 0)
	{
	  destroycb(bev, context);
	  return;
	}

      bufferevent_setcb(bev, next_readcb, NULL, eventcb, context);
      bufferevent_enable(bev, EV_READ|EV_WRITE);
    }

}

static void
unchoke_writecb(struct bufferevent *bev, void *ctx)
{
  struct ev_context_s *context = ctx;
  struct bufferevent *partner = context->partner;

  /* We were choking the other side until we drained our outbuf a bit.
   * Now it seems drained. */
  bufferevent_setcb(bev, handle_streamcb, NULL, eventcb, context);
  bufferevent_setwatermark(bev, EV_WRITE, 0, 0);

  if (partner)
    bufferevent_enable(partner, EV_READ);

}

static void
next_readcb(struct bufferevent *bev, void *ctx)
{
  struct ev_context_s *context = ctx;
  struct bufferevent *partner = context->partner;
  struct evbuffer *src = bufferevent_get_input(bev);
  size_t buf_size = evbuffer_get_length(src);
  u8 buf[buf_size], dec_buf[SOCKS_MAX_BUFFER_SIZE];
  int outl;

  if (context->st == ev_connected && buf_size)
    {
      evbuffer_copyout(src, buf, buf_size);
      evbuffer_drain(src, buf_size);

      outl = decrypt_(buf, buf_size, dec_buf);

      // dec
      if (bufferevent_write(partner, dec_buf, outl) < 0)
	{
	  log_e("bufferevent_write");
	  destroycb(bev, context);
	  return;
	}

      context->reversed = true;
      context->st = ev_connected;

      /* set callbacks and wait for server response */
      bufferevent_setcb(partner, handle_streamcb, NULL, eventcb, context);
      bufferevent_enable(partner, EV_WRITE|EV_READ);
    }
}

void
handle_streamcb(struct bufferevent *bev, void *ctx)
{
  struct ev_context_s *context = ctx;
  struct bufferevent *partner = context->bev;
  struct evbuffer *src = bufferevent_get_input(bev), *dst;
  size_t buf_size = evbuffer_get_length(src);
  u8 buf[buf_size], dec_or_enc_buf[SOCKS_MAX_BUFFER_SIZE];
  int outl;

  if (!partner || !buf_size)
    {
      evbuffer_drain(src, buf_size);
      return;
    }

  // dec or enc
  evbuffer_copyout(src, buf, buf_size);
  evbuffer_drain(src, buf_size);

  if (settings.proxy)
    outl = decrypt_(buf, buf_size, dec_or_enc_buf);

  else
    outl = encrypt_(buf, buf_size, dec_or_enc_buf);

  if (context->st == ev_connected && buf_size && context->partner)
    {
      if (bufferevent_write(partner, dec_or_enc_buf, outl) != 0)
	{
	  log_e("failed to write");
	  destroycb(partner, context);
	  return;
	}

      // Keep doing proxy until there is no data
      bufferevent_setcb(bev, handle_streamcb, NULL, eventcb, context);
      bufferevent_enable(bev, EV_READ|EV_WRITE);

      dst = bufferevent_get_output(partner);

      if (evbuffer_get_length(dst) >= MAX_OUTPUT)
	{
	  log_d(DEBUG, "Setting watermark bufsize=%ld", evbuffer_get_length(dst));
	  bufferevent_setcb(partner, handle_streamcb, unchoke_writecb, eventcb, context);
	  bufferevent_setwatermark(partner, EV_WRITE, MAX_OUTPUT/2, MAX_OUTPUT);
	  bufferevent_disable(bev, EV_READ);
	}
    }
}

void
resolve(struct ev_context_s *context)
{
  struct evutil_addrinfo hints;

  if (!context->bev)
    return;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = PF_INET; // Let's prefer IPV4 for now
  hints.ai_protocol = IPPROTO_UDP;
  hints.ai_flags = EVUTIL_AI_CANONNAME;

  if (!evdns_getaddrinfo(dns_base, context->domain, NULL, &hints, resolvecb, context))
    context->st = ev_destroy;
}

void
resolvecb(int errcode, struct evutil_addrinfo *ai, void *ptr)
{
  struct sockaddr_in *sin_p;
  struct ev_context_s *context = ptr;
  struct evutil_addrinfo *ai_p;
  socks_addr_t *socks_addr;
  int i, try;
  // Send out 10 bytes to reply OK!
  u8 resp[10] = {5, 0, 0, 1, 0, 0, 0, 0, 0, 0};

  if (errcode != 0 || ai == NULL)
    {
      log_e("%s:%s", context->domain, evutil_gai_strerror(errcode));
      goto failed;
    }

  if (context->st == ev_dns_wip)
    {

      for (i = 0, ai_p = ai; ai_p != NULL; ai_p = ai_p->ai_next) {
	switch(ai_p->ai_family) {
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
	log_warn("calloc");

      socks_addr->addrs = malloc(i * sizeof(socks_addr_t));
      if (!socks_addr->addrs)
	log_warn("malloc");

      socks_addr->naddrs = i;

      for (i = 0, ai_p = ai; ai_p != NULL; ai_p = ai_p->ai_next) {
	if (ai_p->ai_family != AF_INET)
	  continue;

	sin_p = malloc(sizeof(struct sockaddr_in));
	if (!sin_p)
	  log_warn("malloc");

	memcpy(sin_p, ai_p->ai_addr, ai_p->ai_addrlen);

	sin_p->sin_port = context->port;
	sin_p->sin_family = AF_INET;

	socks_addr->addrs[i].sockaddr = (struct sockaddr*)sin_p;
	socks_addr->addrs[i].socklen = ai_p->ai_addrlen;

	i++;
      }

      log_i("connect to %s", context->domain);

      context->st = ev_dns_ok;
      context->socks_addr = socks_addr;

      // Start to connect to a server.
      for (try = 0; try < i; try++) {
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	memcpy(&sin, context->socks_addr->addrs[try].sockaddr,
	       context->socks_addr->addrs[try].socklen);

	sin.sin_family = AF_INET;
	sin.sin_port = context->port;

	if (bufferevent_socket_connect(context->partner, (struct sockaddr*)&sin,
				       sizeof(struct sockaddr_in)) != 0)
	  ; // Pass til have a conn

	else
	  break;
      }

      if (node != NULL)
	lru_insert_left(&node, (const char*)context->domain,
			context->socks_addr, sizeof(context->socks_addr));

    }

  if (context->st == ev_dns_ok)
    {

      context->st = ev_connected;

      if (context->bev != NULL)
	{
	  bufferevent_write(context->bev, resp, 10);
	  bufferevent_setcb(context->bev, next_readcb, NULL, eventcb, context);
	  bufferevent_enable(context->bev, EV_READ|EV_WRITE);
	}

    }

  if (ai)
    evutil_freeaddrinfo(ai);

  return;

 failed:
  context->st = ev_destroy;

  if (ai)
    evutil_freeaddrinfo(ai);
}

void
destroycb(struct bufferevent *bev, struct ev_context_s *ctx)
{
  bufferevent_free(bev);
  ctx = NULL;
  free(ctx);
}

void
close_on_finished_writecb(struct bufferevent *bev, void *ctx)
{
  struct evbuffer *evb = bufferevent_get_output(bev);
  struct ev_context_s *context = ctx;

  if (evbuffer_get_length(evb) == 0)
    {
      bufferevent_free(bev);
      context->st = ev_freed;
      context->partner = NULL;
      context->bev = NULL;
      // To avoid double free, make sure a context becomes NULL.
      context = NULL;
      free(context);
      log_d(DEBUG, "close_on_finished_writecb");
    }
}

void
err_writecb(struct bufferevent *bev, void *ctx)
{
  u8 msg[2] = {5, 1};

  if (bufferevent_write(bev, msg, 2) != 0)
    log_e("failed to write an error message");

}

static void
pass_through_func(evutil_socket_t sig_flag, short what, void *ctx)
{
  log_warn("connection reset by peer");
}

static void
signal_func(evutil_socket_t sig_flag, short what, void *ctx)
{
  struct event_base *base = ctx;
  struct timeval delay = {1, 0};
  int sec = 1;

  log_i("Caught an interupt signal; exiting cleanly in %d second(s)", sec);
  event_base_loopexit(base, &delay);
}

void
clean_dns_cache_func(evutil_socket_t sig_flag, short what, void *ctx)
{
  struct dns_cache_config *config = ctx;
  socks_addr_t *addrinfo;
  int i;

  if (what & EV_TIMEOUT)
    {
      log_d(DEBUG, "timeout: clean_dns_cache_func %ld sec elapsed", config->timeout);

      while (1)
	{
	  addrinfo = (socks_addr_t*)lru_get_oldest_payload(&config->cache,
							   config->timeout);

	  if (addrinfo)
	    {
	      for (i = 0; i < addrinfo->naddrs; i++) {
		free(addrinfo->addrs[i].sockaddr);
		addrinfo->addrs[i].sockaddr = NULL;
	      }

	      free(addrinfo->addrs);
	      free(addrinfo);
	      addrinfo = NULL;
	      log_d(DEBUG, "sweeping dns cache");
	    }
	  else
	    break;

	}
    }
}

static void
dns_logfn(int is_warn, const char *msg) {
  fprintf(stderr, "%s: %s\n", is_warn ? "WARN" : "INFO", msg);
}

static void
print_address(struct sockaddr *buf, int type, const char *ctx)
{
  u8 out[128];

  switch (type) {
  case AF_INET:
    if (evutil_inet_ntop(type, buf, (char*)out, sizeof(out)) == NULL)
      goto err;
    break;
  case AF_INET6:
    if (evutil_inet_ntop(type, (struct sockaddr*)buf, (void*)out, sizeof(out)) == NULL)
      goto err;
    break;
  default:
    log_warn("wrong type %d", type);
    goto err;
  }

  ctx == NULL ? log_i("address=%s", out) : log_i("%s address=%s", ctx, out);
  return;

 err:
  log_warn("no address found");
}

int
encrypt_(u8 *in, int ilen, u8 *out)
{
  return evs_encrypt(settings.cipher, settings.dgst, out, in, ilen,
		     (u8*)settings.passphrase, settings.plen, settings.key, settings.iv);
}

int
decrypt_(u8 *in, int ilen, u8 *out)
{
  return evs_decrypt(settings.cipher, settings.dgst, out, in, ilen,
		     (u8*)settings.passphrase, settings.plen, settings.key, settings.iv);

}
