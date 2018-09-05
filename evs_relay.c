#include "evs-internal.h"
#include "evs_helper.h"
#include "evs_server.h"
#include "crypto.h"
#include "evs_log.h"

struct settings settings;
static void  streamcb(struct bufferevent *bev, void *ctx);

void
evs_setcb_for_local(struct bufferevent *bev, void *context)
{
  bufferevent_setcb(bev, fast_streamcb, NULL, eventcb, context);
}


void
fast_streamcb(struct bufferevent *bev, void *ctx)
{
  struct ev_context_s *context = ctx;
  struct bufferevent *partner = context->partner;
  struct evbuffer *src = bufferevent_get_input(bev);
  size_t buf_size = evbuffer_get_length(src);
  u8 buf[buf_size], enc_buf[SOCKS_MAX_BUFFER_SIZE];
  int outl;

  if (!partner || !buf_size)
    {
      evbuffer_drain(src, buf_size);
      return;
    }

  evbuffer_copyout(src, buf, buf_size);
  evbuffer_drain(src, buf_size);

  if (context->st == ev_connected && context->partner)
    {
      // enc
      outl = encrypt_(context->evp_cipher_ctx, false, buf, buf_size, enc_buf);
      if (bufferevent_write(partner, enc_buf, outl) != 0)
	{
	  log_e("failed to write");
	  context->st = ev_destroy;
	}
      // TODO:
      //   set up some cbs
      // bufferevent_setcb(bev, NULL, err_writecb, __eventcb, failed);

      else
	{
	  context->reversed = true;
	  context->successive = false;
	  // Keep doing proxy until there is no data
	  bufferevent_setcb(partner, streamcb, NULL, eventcb, context);
	  bufferevent_enable(partner, EV_READ|EV_WRITE);
	}
    }
}

static void
streamcb(struct bufferevent *bev, void *ctx)
{
  struct ev_context_s *context = ctx;
  struct bufferevent *partner = context->bev;
  struct evbuffer *src = bufferevent_get_input(bev);
  size_t buf_size = evbuffer_get_length(src);
  u8 buf[buf_size], dec_buf[SOCKS_MAX_BUFFER_SIZE];
  int outl;

  if (!partner || !buf_size)
    {
      evbuffer_drain(src, buf_size);
      return;
    }

  if (context->st == ev_connected && buf_size && context->partner)
    {
      // dec
      evbuffer_copyout(src, buf, buf_size);
      evbuffer_drain(src, buf_size);

      outl = decrypt_(context->evp_cipher_ctx, context->successive, buf, buf_size, dec_buf);
      if (bufferevent_write(partner, dec_buf, outl) != 0)
	{
	  log_e("failed to write");
	  destroycb(partner, context);
	  return;
	}

      context->successive = true;
      // Keep doing proxy until there is no data
      bufferevent_setcb(bev, streamcb, NULL, eventcb, context);
      bufferevent_enable(bev, EV_READ|EV_WRITE);
    }
}
