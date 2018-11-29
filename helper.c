#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <event2/util.h>

#include "def.h"
#include "helper.h"
#include "log.h"

static void e_parse_conf_line(struct settings *st, char * const start);

char* e_copy(char *dst, char *src, size_t s)
{

  while (s--) {
    *dst = *src;
    if (*dst == '\0')
      return dst;
    dst++; src++;
  }

  *dst = '\0';

  return dst;
}

void e_parse_line(char * const start)
{
  char *strtok_state;
  static const char *delims = " \t";
#define NEXT_TOKEN strtok_r(NULL, delims, &strtok_state)

  char *const first_token = strtok_r(start, delims, &strtok_state);

  if (!first_token)
    return;
}

/*
  ev_read_file returns 0 on success, returns -1 if file cannot be
  opened and -2 for other reasons.

  Taken from libevent/evutil.c evutil_read_file_
*/
int e_read_file(const char *filename, char **out, int *out_len)
{
  struct stat st;
  int fd;
  int r;
  int flags = 0;
  int read_so_far = 0;
  int mode = O_RDONLY;
  char *mem;

  fd = open(filename, flags, mode);
  if (fd < 0) {
    log_e("ev_read_file(): failed to open()");
    return -1;
  }

  if (evutil_make_socket_closeonexec(fd) < 0) {
    close(fd);
    log_e("evutil_make_socket_closeonexec()");
    return -2;
  }

  if (fstat(fd, &st) || st.st_size < 0) {
    close(fd);
    log_e("fstat()");
    return -2;
  }

  mem = malloc((size_t)st.st_size + 1);
  if (!mem) {
    log_e("malloc()");
    return -2;
  }

  read_so_far = 0;
#define N_TO_READ(x) (((x) > INT_MAX) ? INT_MAX : ((int)(x)))
  while ((r = read(fd, mem+read_so_far, N_TO_READ(st.st_size - read_so_far))) > 0) {
    read_so_far += r;
    if (read_so_far >= (int)st.st_size)
      break;
    assert(read_so_far < (int)st.st_size);
  }
  close(fd);
  if (r < 0) {
    free(mem);
    return -2;
  }

  mem[read_so_far] = '\0';
  *out_len = read_so_far;
  *out = mem;

  return 0;
}

int e_parse_conf_file(struct settings *st, const char *filename)
{
  char *out;
  char *start;
  int err;
  int out_len;

  err = e_read_file(filename, &out, &out_len);

  if (err < 0) {
    if (err == -1)
      log_e("%s: file doesn't exist", __func__);
    if (err == -2)
      log_e("%s: fatal error", __func__);
    return 1;
  }

  start = out;
  for ( ;; ) {
    char * const newline = strchr(start, '\n');

    if (!newline) {
      e_parse_conf_line(st, start);
      break;
    } else {
      *newline = '\0';
      e_parse_conf_line(st, start);
      start = newline + 1;
    }
  }
  return 0;
}

static void e_parse_conf_line(struct settings *st, char * const start)
{
  char *first_token;
  char *token_val;
  char * const delims = " \t";
  int zero_or_one;

  first_token = strtok_r(start, delims, &token_val);
  if (!first_token)
    return;

  if (!strcmp("CipherName", first_token))
    st->cipher_name = (char *)token_val;

  if (!strcmp("ConnectionTimeout", first_token))
    st->connection_timeout = atoi(token_val);

  if (!strcmp("DNSCacheTimeout", first_token))
    st->dns_cache_tval = atol(token_val);

  if (!strcmp("DaemonMode", first_token)) {
    zero_or_one = atoi(token_val);
    if (zero_or_one)
      st->daemon_mode = true;
  }

  if (!strcmp("Password", first_token))
    st->passphrase = (u8 *)token_val;

  if (!strcmp("ListenAddress", first_token))
    st->listen_addr = (const char *)token_val;

  if (!strcmp("ListenPort", first_token))
    st->listen_port = atoi(token_val);

  if (!strcmp("ResolvConf", first_token))
    st->resolv_conf = (const char *)token_val;

  if (!strcmp("ServerAddress", first_token)) {
    st->server_addr = (const char *)token_val;
    st->relay_mode = true;
  }

  if (!strcmp("ServerPort", first_token)) {
    st->server_port = atoi(token_val);
    st->relay_mode = true;
  }

  if (!strcmp("Workers", first_token))
    st->workers = atoi(token_val);
}
