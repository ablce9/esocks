#include <event2/dns.h>

#include "./evs-internal.h"
#include "./evs_server.h"
#include "./evs_lru.h"
#include "./evs_helper.h"
#include "./crypto.h"

static void
test_setting_init(void)
{
  settings.passphrase = "my password";
  settings.plen = strlen(settings.passphrase);
  settings.cipher_name = "aes-256-cfb";
  settings.cipher = EVP_get_cipherbyname(settings.cipher_name);
  settings.dgst = EVP_md5();

  memcpy(settings.key, "01234567890123456789012345678901", 32);
  memcpy(settings.iv, "0123456789012345", 16);
}

static void
announce(int ok_or_fail, const char *msg, va_list ap)
{
  char buf[1024];
  char *status = ok_or_fail == 0 ? "ok" : "failed";

  evutil_vsnprintf(buf, sizeof(buf), msg, ap);

  (void)fprintf(stderr, "[%s] %s\n", status, buf);
}

static void
test_ok(const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  va_end(ap);

  announce(0, fmt, ap);
}

static void
test_failed(const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  va_end(ap);

  announce(1, fmt, ap);
  exit(1);
}

static void
test_lru__payload(void)
{
  lru_node_t *node, *current;
  struct payload_s x, y, z;
  node = init_lru();
  assert(node != NULL);

  x.key = "key";
  x.val = "val";

  lru_insert_left(&node, "zero", &x, sizeof(x));

  assert(strcmp(lru_get_tail(&node)->key, (const char*)"zero") == 0);

  current = lru_get_node(&node, "does_not_exist", (lru_cmp_func*)strcmp);
  assert(current == NULL);

  y.key = "key1";
  y.val = "val1";

  lru_insert_left(&node, "first", &y, sizeof(y));

  z.key = "key2";
  z.val = "val2";
  lru_insert_left(&node, "second", &z, sizeof(z));

  current = lru_get_node(&node, "second", (lru_cmp_func*)strcmp);
  assert(current);
  assert(strcmp(current->key, (const char*)"second") == 0);

  current = lru_get_node(&node, "first", (lru_cmp_func*)strcmp);
  assert(current);
  assert(current->key == (const char*)"first");
  assert(strcmp(((payload_t*)current->payload_ptr)->key, (const char*)"key1") == 0);
  assert(strcmp(((payload_t*)current->payload_ptr)->val, (const char*)"val1") == 0);

  current = lru_get_node(&node, "zero", (lru_cmp_func*)strcmp);
  assert(current);

  assert(strcmp(((payload_t*)current->payload_ptr)->key, (const char*)"key") == 0);
  assert(lru_get_tail(&node) != NULL);

  lru_purge_all(&node);
}

void
test_lru_validate_tail(void)
{
  lru_node_t *node;
  struct payload_s x;
  node = init_lru();
  assert(node);

  x.key = "xkey";
  x.val = "xval";

  lru_insert_left(&node, "foo", &x, sizeof(x));

  // tail should be the first, which was inserted right before this one called.
  assert(strcmp((lru_get_tail(&node))->key, (const char*)"foo") == 0);
  assert(strcmp((lru_get_node(&node, "foo", (lru_cmp_func*)strcmp))->key, (const char*)"foo") == 0);

  // Let's create a place where ptr->next && ptr->prev are fully loaded.
  // And retrieve a middle of the node.
  lru_insert_left(&node, "doo", &x, sizeof(x));
  lru_insert_left(&node, "buz", &x, sizeof(x));

  // Middle of the node
  assert(strcmp((lru_get_node(&node, "doo", (lru_cmp_func*)strcmp))->key, (const char*)"doo") == 0);
  // Tail of the node
  assert(strcmp((lru_get_tail(&node))->key, (const char*)"foo") == 0);
  // Head of the node
  assert(strcmp(node->key, (const char*)"doo") == 0);
  // Don't forget buz :)
  assert(strcmp(node->prev->key, (const char*)"buz") == 0);

  lru_purge_all(&node);
}

void
test_lru_remove_node(void)
{
  lru_node_t *node;
  struct payload_s x;
  node = init_lru();
  assert(node);

  x.key = "xkey";
  x.val = "xval";
  lru_insert_left(&node, "foo", &x, sizeof(x));
  lru_insert_left(&node, "doo", &x, sizeof(x));

  usleep(1100000);
  // Pop key=first
  lru_remove_oldest(&node, 1);

  assert(lru_get_tail(&node)->key == (const char*)"doo");

  lru_purge_all(&node);
}

static void
test_lru_timeout_handler(void)
{
  struct event_base *base = NULL;
  struct lru_node_s *node = NULL;
  struct event *handler;
  struct timeval tval = {1, 0};
  struct evutil_addrinfo hints, *res, *p;
  struct sockaddr_in *sin;
  struct dns_cache_config config;

  socks_addr_t *sock_addr; // Put addrinfo here
  int err, i;
  char *hostname = "client-event-reporter.twitch.tv";
  char *port = "443";
  base = event_base_new();
  node = init_lru();

  memset(&config, 0, sizeof(config));
  config.cache = node;
  config.timeout = 1;

  assert(node && base);

  handler = event_new(base, -1,
		      EV_TIMEOUT, clean_dns_cache_func, (void*)&config);
  event_add(handler, &tval);

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_flags = EVUTIL_AI_CANONNAME;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;

  err = evutil_getaddrinfo(hostname, port, &hints, &res);
  if (err != 0)
    test_failed("evutil_getaddrinfo");

  for (i = 0, p = res; p != NULL; p = p->ai_next) {
      switch(p->ai_family) {
      case AF_INET:
      case AF_INET6:
	break;
      default:
	continue;
      }
      i++;
  }

  if (i == 0)
    test_failed("evutil_getaddrinfo");

  sock_addr = calloc(1, sizeof(socks_addr_t));
  assert(sock_addr != NULL);

  sock_addr->addrs = malloc(i * sizeof(socks_addr_t));
  assert(sock_addr->addrs != NULL);

  for (i = 0, p = res; p != NULL; p = p->ai_next) {
    if (p->ai_family != AF_INET)
      continue;

    sin = malloc(sizeof(struct sockaddr_in));
    assert(sin != NULL);

    memcpy(sin, p->ai_addr, p->ai_addrlen);

    sin->sin_family = AF_INET;

    sock_addr->addrs[i].sockaddr = (struct sockaddr*)sin;
    sock_addr->addrs[i].socklen = p->ai_addrlen;

    i++;
  }

  // Total resolved address number
  sock_addr->naddrs = i;

  // Insert target data here
  lru_insert_left(&config.cache, hostname, sock_addr, sizeof(sock_addr));
  usleep(1100000);

  event_base_dispatch(base);

  // Try to free allocated mems
  evutil_freeaddrinfo(res);
  event_free(handler);
  event_base_free(base);
  lru_purge_all(&config.cache);
}

static void
logfn(int is_warn, const char *msg) {
  fprintf(stderr, "%s: %s\n", is_warn ? "WARN" : "INFO", msg);
}

static void
test_resolve_cb(void)
{
  int err;
  struct event_base *base;
  struct evutil_addrinfo hints, *res;
  struct ev_context_s *ctx;
  struct bufferevent *partner;

  base = event_base_new();
  assert(base);

  char *hostname = "www.google.com";
  char *port = "80";
  int i;

  evdns_set_log_fn(logfn);

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_flags = EVUTIL_AI_CANONNAME;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;

  ctx = calloc(1, sizeof(struct ev_context_s));
  assert(ctx);

  ctx->st = ev_dns_wip;
  ctx->port = 80;
  ev_copy(ctx->domain, hostname, strlen(hostname));
  partner = bufferevent_socket_new(base, -1,
				   BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
  ctx->partner = partner;

  err = evutil_getaddrinfo(hostname, port, &hints, &res);

  resolvecb(err, res, ctx);

  assert(ctx->socks_addr->naddrs > 0);
  assert(ctx->st == ev_connected);

  bufferevent_free(ctx->partner);

  // -1 because IPv6 is not malloced.
  for (i = 0; i < ctx->socks_addr->naddrs-1; i++)
    free(ctx->socks_addr->addrs[i].sockaddr);

  free(ctx->socks_addr->addrs);
  free(ctx->socks_addr);
  free(ctx);
  event_base_dispatch(base);
  event_base_free(base);
}

static void
test_event_cb(void)
{
  struct event_base *base;
  struct bufferevent *bev0, *partner0, *bev1, *partner1;
  struct ev_context_s ctx0, ctx1;
  short what = 0x00;

  base = event_base_new();
  assert(base);

  bev0 = bufferevent_socket_new(base, -1, 0);
  partner0 = bufferevent_socket_new(base, -1, 0);

  bev1 = bufferevent_socket_new(base, -1, 0);
  partner1 = bufferevent_socket_new(base, -1, 0);

  memset(&ctx0, 0, sizeof(struct ev_context_s));
  memset(&ctx1, 0, sizeof(struct ev_context_s));
  what |= BEV_EVENT_EOF;

  assert(bev0 && partner0 && bev0 && partner0);

  ctx0.partner = partner0;
  ctx0.bev = bev0;
  ctx0.event_handler = (bufferevent_data_cb*)handle_streamcb;

  ctx1.partner = partner1;
  ctx1.bev = bev1;
  ctx1.event_handler = (bufferevent_data_cb*)handle_streamcb;

  // Checks for non-reversed bufferevent
  ctx0.reversed = false;
  memcpy(&ctx0.domain, "foooo", 5);
  eventcb(bev0, what, (void*)&ctx0);

  assert(ctx0.st == 0);
  assert(ctx0.bev == NULL);
  assert(ctx0.partner == NULL);

  // Checks for reversed bufferevent
  ctx1.reversed = true;
  memcpy(&ctx1.domain, "doooo", 5);
  eventcb(bev1, what, (void*)&ctx1);

  assert(ctx1.st == 0);
  assert(ctx1.bev == NULL);
  assert(ctx1.partner == NULL);

  event_base_dispatch(base);
  event_base_free(base);
}

static
void test_crypto(void)
{
  const EVP_CIPHER *cipher; // , *decipher;
  u8 ciphertext[SOCKS_MAX_BUFFER_SIZE],
    plaintext[64] =
    "0123456789012345678901234567890123456789012345678901234567890123",
    *plaintext_copy;
  int ciphertext_len;

  plaintext_copy = (unsigned char*)strndup((char*)plaintext, 64);

  cipher = EVP_get_cipherbyname(settings.cipher_name);

  ciphertext_len = evs_encrypt(cipher, settings.dgst, ciphertext, plaintext, 64,
			       (u8*)settings.passphrase, settings.plen, settings.key, settings.iv);

  test_ok("ciphertext_len=%d", ciphertext_len);

  u8 decrypted_text[ciphertext_len];

  evs_decrypt(cipher, settings.dgst, decrypted_text, ciphertext, ciphertext_len,
	      (u8*)settings.passphrase, settings.plen, settings.key, settings.iv);

  if (!strcmp((const char*)plaintext_copy,
	      (const char*)decrypted_text))
    test_ok("decrypted=%s",&decrypted_text);
  else
    test_failed("doesn't match");

  free(plaintext_copy);
}

static
void test_wrapped_crypto(void)
{
  u8 plaintext[64] = "0123456789012345678901234567890123456789012345678901234567890123",
    enc_buf[SOCKS_MAX_BUFFER_SIZE],
    dec_buf[SOCKS_MAX_BUFFER_SIZE],
    *plaintext_copy;
  int outl;

  plaintext_copy = (u8*)strndup((char*)plaintext, 64);
  outl = encrypt_(plaintext, 64, enc_buf);

  decrypt_(enc_buf, outl, dec_buf);

  if (!strcmp((const char*)plaintext_copy,
	      (const char*)dec_buf))
    test_ok("decrypted=%s",&dec_buf);
  else
    test_failed("doesn't match outl=\"%s\"", &dec_buf);

  free(plaintext_copy);
}

typedef void(*test_function)(void);

struct testcase {
  const char *description;
  test_function function;
};

struct testcase testcases[] = {
  {"test_lru_lrupayload", test_lru__payload},
  {"test_lru_validate_tail", test_lru_validate_tail},
  {"test_lru_remove_node",test_lru_remove_node},
  {"test_lru_timeout_handler", test_lru_timeout_handler},
  {"test_event_cb", test_event_cb},
  {"test_resolve_cb", test_resolve_cb},
  {"test_crypto", test_crypto},
  {"test_wrapped_crypto", test_wrapped_crypto},
};

int
main(int argc, char **argv)
{
  int total_tests, current;

  crypto_init();
  test_setting_init();

  total_tests = (int)sizeof(testcases)/sizeof(testcases[0]);
  for (current = 0; current < total_tests; current++)
    {
      testcases[current].function();
    }

  crypto_shutdown();
  return 0;
}
