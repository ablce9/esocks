#include "evs-internal.h"
#include "evs_helper.h"
#include "evs_server.h"
#include "crypto.h"
#include "evs_log.h"

struct settings settings;

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

  if (context->st == ev_connected && buf_size && context->partner)
    {
      // enc
      evbuffer_copyout(src, buf, buf_size);
      evbuffer_drain(src, buf_size);

      outl = encrypt_(buf, buf_size, enc_buf);

      if (bufferevent_write(partner, enc_buf, outl) != 0)
	log_e("failed to write");
      // TODO:
      //   set up some cbs
      // bufferevent_setcb(bev, NULL, err_writecb, __eventcb, failed);

      else
	{
	  context->reversed = true;
	  context->st = ev_connected;

	  // Keep doing proxy until there is no data
	  bufferevent_setcb(partner, handle_streamcb, NULL, eventcb, context);
	  bufferevent_enable(partner, EV_READ|EV_WRITE);
	}
    }
}
