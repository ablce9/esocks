#include "def.h"
#include "helper.h"
#include "server.h"
#include "crypto.h"
#include "log.h"

struct settings settings;
static void  relay_streamcb(struct bufferevent *bev, void *ctx);

void evs_setcb_for_local(struct bufferevent *bev, void *context)
{
  bufferevent_setcb(bev, fast_streamcb, NULL, eventcb, context);
}

void fast_streamcb(struct bufferevent *bev, void *ctx)
{
  struct e_context_s *context = ctx;
  struct bufferevent *partner = context->partner;
  struct evbuffer *src = bufferevent_get_input(bev);
  size_t buf_size = evbuffer_get_length(src);
  u8 buf[buf_size];
  u8 enc_buf[SOCKS_MAX_BUFFER_SIZE];
  int buflen;

  if (!partner || !buf_size) {
    evbuffer_drain(src, buf_size);
    return;
  }

  evbuffer_copyout(src, buf, buf_size);
  evbuffer_drain(src, buf_size);

  if (context->st == e_connected && context->partner) {
    // enc
    buflen = openssl_encrypt(context->evp_cipher_ctx, enc_buf, buf, buf_size);
    if (bufferevent_write(partner, enc_buf, buflen) != 0) {
      log_e("failed to write");
      context->st = e_destroy;
    } else {
      context->reversed = true;

      // Keep doing proxy until there is no data
      bufferevent_setcb(partner, relay_streamcb, NULL, eventcb, context);
      bufferevent_enable(partner, EV_READ|EV_WRITE);
    }
  }
}

static void relay_streamcb(struct bufferevent *bev, void *ctx)
{
  struct e_context_s *context = ctx;
  struct bufferevent *partner = context->bev;
  struct evbuffer *src = bufferevent_get_input(bev);
  int buflen;
  size_t buf_size = evbuffer_get_length(src);
  u8 buf[buf_size];
  u8 dec_buf[SOCKS_MAX_BUFFER_SIZE];

  if (!partner || !buf_size) {
    evbuffer_drain(src, buf_size);
    return;
  }

  if (context->st == e_connected && buf_size && context->partner) {
    // dec
    evbuffer_copyout(src, buf, buf_size);
    evbuffer_drain(src, buf_size);

    buflen = openssl_decrypt(context->evp_decipher_ctx, dec_buf, buf, buf_size);
    if (bufferevent_write(partner, dec_buf, buflen) != 0) {
      log_e("failed to write");
      context->st = e_destroy;
    } else {
      // Keep doing proxy until there is no data
      bufferevent_setcb(bev, relay_streamcb, NULL, eventcb, context);
      bufferevent_enable(bev, EV_READ|EV_WRITE);
    }
  }
}
