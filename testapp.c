#include <fcntl.h>

#include <event2/dns.h>

#include "./def.h"
#include "./server.h"
#include "./lru.h"
#include "./helper.h"
#include "./crypto.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(e) (sizeof(e)/sizeof(e[0]))
#endif

#define MEMCMP(a, b, s)					\
    do { if (!memcmp(a, b, s))				\
	    test_ok("matched: %s", __func__);		\
	else						\
	    test_failed("doesn't match: %s", __func__);	\
    } while (0);

#define CIPHER_INIT(ctx, cipher, key, iv, opt)				\
    do { if (!EVP_CipherInit_ex(ctx, cipher, NULL, key, iv, opt))	\
	    test_failed("failed to init cipher");			\
    } while (0);

static void test_setting_init(void)
{
    const u8 iv16[16] = {
	0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
	0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12
    };
    const u8 key32[32] = {
	0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
	0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12,
	0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34,
	0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56
    };

    settings.passphrase = (u8 *)"this is my password!";
    settings.plen = strlen((char *)settings.passphrase);
    settings.cipher_name = "aes-256-cfb";
    settings.cipher = EVP_get_cipherbyname(settings.cipher_name);
    settings.dgst = EVP_md5();
    settings.key = iv16;
    settings.iv = key32;
}

static void announce(int ok_or_fail, const char *msg, va_list ap)
{
    char buf[1024];
    char *status = ok_or_fail == 0 ? "\033[00;36mok\033[00;00m"
	: "\033[00;31mfailed\033[00;00m";

    evutil_vsnprintf(buf, sizeof(buf), msg, ap);

    (void)fprintf(stderr, "[%s] %s\n", status, buf);
}

static void test_ok(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    va_end(ap);

    announce(0, fmt, ap);
}

static void test_failed(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    va_end(ap);

    announce(1, fmt, ap);
    exit(1);
}

static void test_lru_payload(void)
{
    lru_node_t *node;
    lru_node_t *current;
    struct payload_s x, y, z;

    node = lru_init();
    assert(node != NULL);

    x.key = "key";
    x.val = "val";

    lru_insert_left(&node, "zero", &x, sizeof(x));

    assert(strcmp(lru_get_tail()->key, (const char *)"zero") == 0);

    current = lru_get_node(&node, "does_not_exist", (lru_cmp_func *)strcmp);
    assert(current == NULL);

    y.key = "key1";
    y.val = "val1";

    lru_insert_left(&node, "first", &y, sizeof(y));

    z.key = "key2";
    z.val = "val2";
    lru_insert_left(&node, "second", &z, sizeof(z));

    current = lru_get_node(&node, "second", (lru_cmp_func *)strcmp);
    assert(current);
    assert(strcmp(current->key, (const char *)"second") == 0);

    current = lru_get_node(&node, "first", (lru_cmp_func *)strcmp);
    assert(current);
    assert(current->key == (const char *)"first");
    assert(strcmp(((payload_t *)current->payload_ptr)->key, (const char *)"key1") == 0);
    assert(strcmp(((payload_t *)current->payload_ptr)->val, (const char *)"val1") == 0);

    current = lru_get_node(&node, "zero", (lru_cmp_func *)strcmp);
    assert(current);

    assert(strcmp(((payload_t *)current->payload_ptr)->key, (const char *)"key") == 0);
    assert(lru_get_tail() != NULL);

    lru_purge_all(&node);
    test_ok("%s", __func__);
}

void test_lru_validate_tail(void)
{
    lru_node_t *node;
    struct payload_s x;

    node = lru_init();
    assert(node);

    x.key = "xkey";
    x.val = "xval";

    lru_insert_left(&node, "foo", &x, sizeof(x));

    // tail should be the first, which was inserted right before this one called.
    assert(strcmp((lru_get_tail())->key, (const char *)"foo") == 0);
    assert(strcmp((lru_get_node(&node, "foo", (lru_cmp_func *)strcmp))->key,
		  (const char *)"foo") == 0);

    // Let's create a place where ptr->next && ptr->prev are fully loaded.
    // And retrieve a middle of the node.
    lru_insert_left(&node, "doo", &x, sizeof(x));
    lru_insert_left(&node, "buz", &x, sizeof(x));

    // Middle of the node
    assert(strcmp((lru_get_node(&node, "doo", (lru_cmp_func *)strcmp))->key,
		  (const char *)"doo") == 0);
    // Tail of the node
    assert(strcmp((lru_get_tail())->key, (const char *)"foo") == 0);
    // Head of the node
    assert(strcmp(node->key, (const char *)"doo") == 0);
    // Don't forget buz :)
    assert(strcmp(node->prev->key, (const char *)"buz") == 0);

    lru_purge_all(&node);
    test_ok("%s", __func__);
}

void test_lru_remove_node(void)
{
    lru_node_t *node;
    struct payload_s x;

    node = lru_init();
    assert(node);

    x.key = "xkey";
    x.val = "xval";
    lru_insert_left(&node, "foo", &x, sizeof(x));
    lru_insert_left(&node, "doo", &x, sizeof(x));

    usleep(1100000);
    // Pop key=first
    lru_remove_oldest(&node, 1);

    assert(lru_get_tail()->key == (const char *)"doo");

    lru_purge_all(&node);
    test_ok("%s", __func__);
}

static void test_lru_timeout_handler(void)
{
    struct event_base *base = NULL;
    struct lru_node_s *node = NULL;
    struct event *handler;
    struct timeval tval = {1, 0};
    struct evutil_addrinfo hints;
    struct evutil_addrinfo *res;
    struct evutil_addrinfo *p;
    struct sockaddr_in *sin;
    struct dns_cache_config config;
    socks_addr_t *sock_addr;
    int err;
    int i;
    char *hostname = "google.com";
    char *port = "443";
    short what = 0;

    what |= EV_TIMEOUT;

    base = event_base_new();
    node = lru_init();

    memset(&config, 0, sizeof(config));
    config.cache = node;
    config.timeout = 0;

    assert(node && base);

    handler = event_new(base, -1,
			EV_TIMEOUT, clean_dns_cache_func, (void *)&config);
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
	switch (p->ai_family) {
	case AF_INET:
	case AF_INET6:
	    break;
	default:
	    continue;
	}
	i++;
    }

    assert(i != 0);

    sock_addr = calloc(1, sizeof(*sock_addr));
    assert(sock_addr != NULL);

    sock_addr->addrs = malloc(i * sizeof(*sock_addr->addrs));
    assert(sock_addr->addrs != NULL);

    for (i = 0, p = res; p != NULL; p = p->ai_next) {
	if (p->ai_family != AF_INET)
	    continue;

	sin = malloc(sizeof(*sin));
	assert(sin != NULL);

	memcpy(sin, p->ai_addr, p->ai_addrlen);

	sin->sin_family = AF_INET;

	sock_addr->addrs[i].sockaddr = (struct sockaddr *)sin;
	sock_addr->addrs[i].socklen = p->ai_addrlen;

	i++;
    }

    // Total resolved address number
    sock_addr->naddrs = i;

    // Insert target data here
    lru_insert_left(&config.cache, hostname, sock_addr, sizeof(sock_addr));
    usleep(1100000);

    clean_dns_cache_func(0, what, (void *)&config);

    event_base_dispatch(base);

    // Try to free allocated mems
    evutil_freeaddrinfo(res);
    event_free(handler);
    event_base_free(base);
    lru_purge_all(&config.cache);
    test_ok("%s", __func__);
}

static void logfn(int is_warn, const char *msg) {
    fprintf(stderr, "%s: %s\n", is_warn ? "WARN" : "INFO", msg);
}

static void test_resolve_dns_cb(void)
{
    struct event_base *base;
    struct evutil_addrinfo hints;
    struct evutil_addrinfo *res;
    struct e_context_s *ctx;
    struct bufferevent *partner;
    int i;
    int err;
    char *hostname = "www.google.com";
    char *port = "80";

    base = event_base_new();
    assert(base);

    evdns_set_log_fn(logfn);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = EVUTIL_AI_CANONNAME;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    ctx = calloc(1, sizeof(*ctx));
    assert(ctx);

    ctx->st = e_dns_wip;
    ctx->port = 80;
    e_copy(ctx->domain, hostname, strlen(hostname));
    partner = bufferevent_socket_new(base, -1,
				     BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
    ctx->partner = partner;

    err = evutil_getaddrinfo(hostname, port, &hints, &res);

    resolve_dnscb(err, res, ctx);

    assert(ctx->socks_addr->naddrs > 0);
    assert(ctx->st == e_connected);

    bufferevent_free(ctx->partner);

    for (i = 0; i < ctx->socks_addr->naddrs-1; i++)
	free(ctx->socks_addr->addrs[i].sockaddr);

    free(ctx->socks_addr->addrs);
    free(ctx->socks_addr);
    free(ctx);
    event_base_dispatch(base);
    event_base_free(base);
    test_ok("%s", __func__);
}

static void test_event_cb(void)
{
    struct event_base *base;
    struct bufferevent *bev0;
    struct bufferevent *partner0;
    struct bufferevent *bev1;
    struct bufferevent *partner1;
    struct e_context_s ctx0;
    struct e_context_s ctx1;
    short what = 0;

    base = event_base_new();
    assert(base);

    bev0 = bufferevent_socket_new(base, -1, 0);
    partner0 = bufferevent_socket_new(base, -1, 0);

    bev1 = bufferevent_socket_new(base, -1, 0);
    partner1 = bufferevent_socket_new(base, -1, 0);

    memset(&ctx0, 0, sizeof(struct e_context_s));
    memset(&ctx1, 0, sizeof(struct e_context_s));
    what |= BEV_EVENT_EOF;

    assert(bev0 && partner0 && bev1 && partner1);

    ctx0.partner = partner0;
    ctx0.bev = bev0;
    ctx0.event_handler = (bufferevent_data_cb *)handle_streamcb;

    ctx1.partner = partner1;
    ctx1.bev = bev1;
    ctx1.event_handler = (bufferevent_data_cb *)handle_streamcb;

    // Checks for non-reversed bufferevent
    ctx0.reversed = false;
    memcpy(&ctx0.domain, "foooo", 5);
    eventcb(bev0, what, (void *)&ctx0);

    assert(ctx0.st == 0);
    assert(ctx0.bev == NULL);
    assert(ctx0.partner == NULL);

    // Checks for reversed bufferevent
    ctx1.reversed = true;
    memcpy(&ctx1.domain, "doooo", 5);
    eventcb(bev1, what, (void *)&ctx1);

    assert(ctx1.st == 0);
    assert(ctx1.bev == NULL);
    assert(ctx1.partner == NULL);

    event_base_dispatch(base);
    event_base_free(base);
    test_ok("%s", __func__);
}

static void test_close_on_finished_writecb(void)
{
    static evutil_socket_t pair[2] = {0, 1};
    struct event_base *base;
    struct bufferevent *bev;
    struct bufferevent *partner;
    struct e_context_s ctx;
    struct timeval tv;
    short what = 0;
    u8 buffer[1024];
    int i;
    int fd;

    what |= BEV_EVENT_EOF;
    for (i = 0; i < (int)sizeof(buffer); i++)
	buffer[i] = i;

    fd = open("/dev/null", O_RDWR);
    if (fd == -1)
	test_failed("open()");

    pair[1] = fd;

    base = event_base_new();
    bev = bufferevent_socket_new(base, pair[0], 0);
    partner = bufferevent_socket_new(base, pair[1], 0);
    memset(&ctx, 0, sizeof(ctx));

    assert(bev && partner  && base);

    ctx.partner = partner;
    ctx.bev = bev;
    ctx.event_handler = (bufferevent_data_cb *)handle_streamcb;

    bufferevent_setcb(bev, NULL, NULL, eventcb, &ctx);
    bufferevent_enable(partner, EV_WRITE|EV_READ);
    bufferevent_write(partner, buffer, sizeof(buffer));
    bufferevent_trigger_event(bev, what, 0);

    tv.tv_sec = 0;
    tv.tv_usec = 300000;

    event_base_loopexit(base, &tv);
    event_base_dispatch(base);
    event_base_free(base);

    assert(ctx.st == 0);
    assert(ctx.bev == NULL);
    assert(ctx.partner == NULL);

    test_ok("%s", __func__);
}

static void test_crypto(void)
{
    EVP_CIPHER_CTX *c1;
    EVP_CIPHER_CTX *c2;
    u8 out[SOCKS_MAX_BUFFER_SIZE];
    u8 in[32] = {
	0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xf,
	0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xf,
    };
    int outl;

    c1 = EVP_CIPHER_CTX_new();
    c2 = EVP_CIPHER_CTX_new();

    CIPHER_INIT(c1, settings.cipher, settings.key, settings.iv, 1);
    CIPHER_INIT(c2, settings.cipher, settings.key, settings.iv, 0);

    outl = openssl_encrypt(c1, out, in, sizeof(in));
    u8 dec_buf[outl];

    outl = openssl_decrypt(c2, dec_buf, out, outl);

    MEMCMP(in, dec_buf, outl);
    EVP_CIPHER_CTX_free(c1);
    EVP_CIPHER_CTX_free(c2);
}

static void test_wrapped_crypto(void)
{
    static const int buf_size = 100;
    u8 enc_buf[SOCKS_MAX_BUFFER_SIZE];
    int outl;
    int index;
    int i;

    for (i = 0; i < 1000; i++) {
	// Create random bytes.
	u8 in[buf_size];
	EVP_CIPHER_CTX *c1;
	EVP_CIPHER_CTX *c2;

	for (index = 0; index < buf_size; index++)
	    in[index] = rand();

	c1 = EVP_CIPHER_CTX_new();
	c2 = EVP_CIPHER_CTX_new();

	CIPHER_INIT(c1, settings.cipher, settings.key, settings.iv, 1);
	CIPHER_INIT(c2, settings.cipher, settings.key, settings.iv, 0);

	outl = openssl_encrypt(c1, enc_buf, in, sizeof(in));
	u8 dec_buf[outl];

	outl = openssl_decrypt(c2,  dec_buf, enc_buf, outl);

	assert(memcmp(in, dec_buf, outl) == 0);
	EVP_CIPHER_CTX_free(c1);
	EVP_CIPHER_CTX_free(c2);
    }
    test_ok("%s", __func__);
}

static void test_stream_encryption(void)
{
    EVP_CIPHER_CTX *c1;
    EVP_CIPHER_CTX *c2;
    int i;
    static const int buf_size = 2049;
    u8 enc_buf[SOCKS_MAX_BUFFER_SIZE];
    u8 dec_buf[SOCKS_MAX_BUFFER_SIZE];
    u8 in[buf_size];
    u8 buf[buf_size];

    c1 = EVP_CIPHER_CTX_new();
    c2 = EVP_CIPHER_CTX_new();

    CIPHER_INIT(c1, settings.cipher, settings.key, settings.iv, 1);
    CIPHER_INIT(c2, settings.cipher, settings.key, settings.iv, 0);

    for (i = 0; i < buf_size; i++)
	buf[i] = i;

    i = 0;
    do {
	int dec_total = 0;

	i += 517;
	memcpy(in, buf, i);
	openssl_encrypt(c1, enc_buf, in, i);
	dec_total += openssl_decrypt(c2,  dec_buf, enc_buf, i);
	assert(memcmp(in, dec_buf, dec_total) == 0);
    } while (i < buf_size);

    test_ok("%s", __func__);
    EVP_CIPHER_CTX_free(c1);
    EVP_CIPHER_CTX_free(c2);
}

static void test_can_read_conf_file()
{
    const char *filename = "./sample_esocks.conf";
    struct settings st;

    memset(&st, 0, sizeof(struct settings));
    if (e_parse_conf_file(&st, filename) != 0)
	test_failed("e_parse_conf_file()");

    assert(strcmp(st.cipher_name, "aes-256-cfb") == 0);
    assert(st.dns_cache_tval == 6500);
    assert(!st.daemon_mode);
    assert(strcmp((const char *)st.passphrase, "thisIsMyPassword") == 0);
    assert(strcmp((const char *)st.listen_addr, "127.0.0.1") == 0);
    assert(st.listen_port == 3080);
    assert(strcmp((const char *)st.resolv_conf, "/etc/resolv.conf.dev") == 0);
    assert(strcmp((const char *)st.server_addr, "1.2.3.4") == 0);
    assert(st.server_port == 3081);
    assert(st.workers == 2);
    test_ok("%s", __func__);
}

typedef void(*test_function)(void);

struct testcase {
    const char *description;
    test_function function;
};

struct testcase testcases[] = {
    {"test_lru_lrupayload", test_lru_payload},
    {"test_lru_validate_tail", test_lru_validate_tail},
    {"test_lru_remove_node", test_lru_remove_node},
    {"test_event_cb", test_event_cb},
    {"test_close_on_finished_writecb", test_close_on_finished_writecb},
    {"test_resolve_dns_cb", test_resolve_dns_cb},
    {"test_lru_timeout_handler", test_lru_timeout_handler},
    {"test_crypto", test_crypto},
    {"test_wrapped_crypto", test_wrapped_crypto},
    {"test_stream_encryption", test_stream_encryption},
    {"test_can_read_config_file", test_can_read_conf_file},
};

int main(int argc, char **argv)
{
    int total_tests, current;

    crypto_init();
    test_setting_init();
    EVP_BytesToKey(settings.cipher, settings.dgst, NULL,
		   settings.passphrase, settings.plen, 1, (u8 *)settings.key,
		   (u8 *)settings.iv);
    total_tests = (int)ARRAY_SIZE(testcases);

    for (current = 0; current < total_tests; current++)
	testcases[current].function();

    crypto_shutdown();
    exit(0);
}
