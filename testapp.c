#include <event2/dns.h>

#include <openssl/evp.h>
#include <openssl/err.h>

#include "./evs-internal.h"
#include "./evs_server.h"
#include "./evs_lru.h"
#include "./evs_helper.h"
#include "./crypto.h"

static void announce(int ok_or_fail, const char *msg, va_list ap)
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

  socks_addr_t *addrs; // Put addrinfo here
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

  addrs = malloc(i * sizeof(socks_addr_t));
  assert(addrs != NULL);

  for (i = 0, p = res; p != NULL; p = p->ai_next) {
    if (p->ai_family != AF_INET)
      continue;

    sin = malloc(sizeof(struct sockaddr_in));
    assert(sin != NULL);

    memcpy(sin, p->ai_addr, p->ai_addrlen);

    sin->sin_family = AF_INET;

    addrs[i].sockaddr = (struct sockaddr*)sin;
    addrs[i].socklen = p->ai_addrlen;

    i++;
  }

  // Total resolved address number
  addrs->naddrs = i;

  // Insert target data here
  lru_insert_left(&config.cache, hostname, addrs, sizeof(addrs));
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

  assert(ctx->addrs->naddrs > 0);
  assert(ctx->st == ev_connected);

  bufferevent_free(ctx->partner);

  for (i = 0; i < ctx->addrs->naddrs-1; i++)
    free(ctx->addrs[i].sockaddr);

  free(ctx->addrs);
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
  const EVP_CIPHER *cipher, *decipher;
  u8 key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH],
    ciphertext[SOCKS_MAX_BUFFER_SIZE],
    plaintext[64] =
    "0123456789012345678901234567890123456789012345678901234567890123",
    *plaintext_copy;

  int ciphertext_len;

  crypto_init();

  memcpy(key, "012345678901234567890123456789012345678901234567", 48);
  memcpy(iv, "0123456789012345678901234567890123456789012345678901234567890123", 64);
  plaintext_copy = (unsigned char*)strndup((char*)plaintext, 64);

  cipher = EVP_get_cipherbyname("aes-256-cfb");
  decipher = EVP_get_cipherbyname("aes-256-cfb");
  assert(cipher && decipher);

  ciphertext_len = evs_encrypt(cipher, plaintext, 64, key, iv, ciphertext);

  test_ok("ciphertext_len=%d", ciphertext_len);

  u8 decrypted_text[ciphertext_len];

  evs_decrypt(decipher, ciphertext, ciphertext_len, key, iv, decrypted_text);

  if (!strcmp((const char*)plaintext_copy,
	      (const char*)decrypted_text))
    test_ok("decrypted=%s",&decrypted_text);
  else
    test_failed("doesn't match");

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
};

int
main(int argc, char **argv)
{
  int total_tests, current;

  total_tests = (int)sizeof(testcases)/sizeof(testcases[0]);
  for (current = 0; current < total_tests; current++)
    {
      testcases[current].function();
    }
  return 0;
}
