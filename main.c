/*
 * Watch out - this is a work in progress!
 *
 * Use of this source code is governed by a
 * license that can be found in the LICENSE file.
 *
 * Simple proxy server with Libevent & OpenSSL
 *
 */

#include "evs-internal.h"
#include "crypto.h"
#include "evs_log.h"
#include "evs_server.h"

struct settings settings;

static void settings_init(void);
static void usage(void);
static void fatal_error_cb(int err);

static void fatal_error_cb(int err) {
  log_e("fata_error_cb got=%d\n", err);
}

static void
settings_init(void)
{
  settings.srv_addr = "0.0.0.0";
  settings.srv_port = 1080;
  settings.server_addr = "0.0.0.0";
  settings.server_port = 1080;
  settings.passphrase = "too lame to set password";
  // Timeout for connections made between clients and a server.
  settings.timeout = 300;
  settings.relay_mode = false;
  settings.resolv_conf = "/etc/resolv.conf";
  settings.nameserver = NULL;
  // TOODO: Let users set up rate limit.
  settings.rate_wlimit = 20000;
  settings.rate_rlimit = 20000;
  settings.proxy = NULL;

  // TODO: refactor
  memcpy(settings.key, "012345678901234567890123456789012345678901234567", 48);
  memcpy(settings.iv, "0123456789012345", 15);
  settings.cipher_name = "aes-256-cfb";
}

static
void usage() {
  printf("Usage: esocks [OPTIONS...]\n"
	 "\n"
	 "options:\n"
	 "  -s  bind to this address, default 0.0.0.0\n"
	 "  -p  bind to this port, default 1080\n"
	 "  -u  server address\n"
	 "  -j  server port\n"
	 "  -k  password\n"
	 "  -c  cipher name, defualt aes-256-cfb\n"
	 "  -n  workers\n"
	 "  -t  timeout for connections, default 300 seconds\n"
	 "  -g  nameserver\n"
	 "  -o  path to resolver conf file, defualt /etc/resolv.conf\n"
	 "  -r  limit reading rate in bytes, default none\n"
	 "  -w  limit writing rate in bytes, default none\n"
	 );
  exit(1);
}

int
main(int argc, char **argv)
{
  int cc = 0;
  int port;

  // Init OpenSSL
  // TODO: free all loaded memory
  crypto_init();

  settings_init();

  while (cc != -1) {
    cc = getopt(argc, argv, "lhs:p:u:j:k:w:r:g:t:n:o:r:e:c:");

    switch(cc) {
    case 's':
      settings.srv_addr = optarg;
      break;
    case 'p':
      port = atoi(optarg);
      if (port < 1 || port > 65535)
	usage();
      settings.srv_port = port;
      break;
    case 'u':
      settings.server_addr = optarg;
      settings.relay_mode = true;
      break;
    case 'j':
      port = atoi(optarg);
      if (port < 1 || port > 65535)
	usage();
      settings.server_port = port;
      settings.relay_mode = true;
      break;
    case 'k':
      settings.passphrase = optarg;
      break;
    case 'n':
      settings.worker = optarg;
      break;
    case 'g':
      settings.nameserver = optarg;
      break;
    case 't':
      settings.timeout = atol(optarg);
      break;
    case 'o':
      settings.resolv_conf = optarg;
      break;
    case 'h':
      usage();
      break;
      // TODO rate limit
    case 'r':
      settings.rate_rlimit = atoi(optarg);
      break;
    case 'e':
      settings.rate_wlimit = atoi(optarg);
      break;
    case 'c':
      settings.cipher_name = optarg;
      break;
    }
  }

  settings.plen = strlen(settings.passphrase);
  settings.cipher = EVP_get_cipherbyname(settings.cipher_name);
  settings.dgst = EVP_md5();

  if (settings.cipher == NULL)
    log_ex(1, "Setting cipher %s", settings.cipher_name);

  DEBUG ? NULL : event_set_fatal_callback(fatal_error_cb);

  if (settings.relay_mode)
    log_i("%s:%d and connect to %s:%d",
	  settings.srv_addr, settings.srv_port, settings.server_addr, settings.server_port);
  else
    {
      log_i("%s:%d", settings.srv_addr, settings.srv_port);
      log_d(DEBUG, "running in debug mode, timeout=%d seconds", settings.timeout);
    }

  (void)run_srv();

  return 0;
}
