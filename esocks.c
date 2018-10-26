/*
 * Watch out - this is a work in progress!
 *
 * Use of this source code is governed by a
 * license that can be found in the LICENSE file.
 *
 */

#include <sys/wait.h>
#include <signal.h>

#include "def.h"
#include "crypto.h"
#include "log.h"
#include "server.h"
#include "version.h"
#include "helper.h"

struct settings settings;

static void settings_init(void);
static void usage(void);
static void fatal_error_cb(int err);
static void ev_do_fork(int workers);
static void save_pid(const char* pid_file);
static void remove_pid(const char* pid_file);

static void fatal_error_cb(int err) {
  log_e("fata_error_cb got=%d\n", err);
}

static void
settings_init(void)
{
#define DEFAULT_SERVER_PORT 1080
  settings.listen_addr = "0.0.0.0";
  settings.listen_port = DEFAULT_SERVER_PORT;
  settings.server_addr = "0.0.0.0";
  settings.server_port = DEFAULT_SERVER_PORT;
  settings.passphrase = (u8*)"too lame to set password";
  // Timeout for connections made between clients and a server.
#define DEFAULT_CONNECTION_TIMEOUT 300
  settings.connection_timeout = DEFAULT_CONNECTION_TIMEOUT;
  settings.relay_mode = false;
  settings.resolv_conf = "/etc/resolv.conf";
  settings.nameserver = NULL;
  // TOODO: Let users set up rate limit.
#define DEFAULT_RATE_LIMIT 20000
  settings.rate_wlimit = DEFAULT_RATE_LIMIT;
  settings.rate_rlimit = DEFAULT_RATE_LIMIT;
  settings.proxy = NULL;
  // TODO: dns ttl
#define DEFAULT_DNS_CACHE_TVAL 6500;
  settings.dns_cache_tval = DEFAULT_DNS_CACHE_TVAL;
#define DEFAULT_WORKER_NUMBER 0
  settings.workers = DEFAULT_WORKER_NUMBER;
  settings.daemon_mode = false;
  settings.pid_file = "/var/run/esocks.pid";

  // TODO: refactor, this ain't good for security!
  const u8 key16[16] = {
    0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
    0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12
  };
  const u8 ckey32[32] = {
    0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
    0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12,
    0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34,
    0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56
  };

  settings.key = ckey32;
  settings.iv = key16;
  settings.cipher_name = "aes-256-cfb";
}

static
void usage() {
  printf("Esocks " ESOCKS_VERSION ", a socks5 proxy server\n"
	 "Usage: esocks [OPTIONS...]\n"
	 "\n"
	 "OPTIONS:\n"
	 "  -c  cipher name (default aes-256-cfb)\n"
	 "  -C  path to config file\n"
	 "  -d  dns cache timeout (default 6500 seconds)\n"
	 "  -D  enable daemon mode (default false)\n"
	 "  -j  connect to this port\n"
	 "  -k  password for AES enc/dec\n"
	 "  -n  worker number\n"
	 "  -o  path to resolver conf file (default /etc/resolv.conf)\n"
	 "  -p  bind to this port (default 1080)\n"
	 "  -P  write PID file (default /var/run/esocks.pid\n"
	 "  -s  bind to this address (default 0.0.0.0)\n"
	 "  -u  connect to this server address\n"
	 "  -t  timeout for connections (default 300 seconds)\n"
	 "  -g  nameserver\n"
	 "  -V  show version number\n"
	 );
  exit(1);
}

static void
ev_do_fork(int workers)
{
 int j;
 pid_t pid;
 int workers_ = workers-1;
 pid_t pids[workers_];

 log_i("fork(): parent pid=%ld", (long)getpid());
 for (j = 0; j < workers_; j++) {
   if ((pid = fork()) == 0) {
     // child process
     log_i("fork(): child pid=%ld", (long)getpid());
     e_start_server();
     exit(0);
   }
   else
     pids[j] = pid;
 }

 e_start_server();
 log_i("event_loopexit(): parent's loop just exited.");

  for (j = 0; j < workers_; j++) {
    int status;
    kill(pids[j], SIGTERM);
    if ((waitpid(pids[j], &status, 0)) == -1)
      log_e("waitpid()");

    if (WIFEXITED(status))
      log_i("WIFEXITED(): child excited");
    if (WIFSIGNALED(status))
      log_i("WIFSIGNALED(): child killed by signal");
  }
}

static void
save_pid(const char* pid_file)
{
  FILE* fp;

  if ((fp = fopen(pid_file, "r")) != NULL)
    {
      char buf[1024];
      if (fgets(buf, sizeof(buf), fp) != NULL) {
	char* endptr;
	pid_t pid;
	if ((pid = strtoul(buf, &endptr, 10)) && kill((pid_t)pid, SIGTERM) == 0)
	  log_warn("The pid file contained pid: %u", pid);
      }
      fclose(fp);
    }
  if ((fp = fopen(pid_file, "w")) != NULL) {
    fprintf(fp, "%ld\n", (long)getpid());
    fclose(fp);
  }
  else
    log_ex(1, "fopen(%ld, w)", (long)getpid());
}

static void
remove_pid(const char* pid_file)
{
  if (pid_file == NULL)
    return;

  if (unlink(pid_file) != 0)
    log_ex(1, "unlink(%s)", pid_file);
}

int
main(int argc, char** argv)
{
  int port;
  int cc = 0;
  int daemon_nochdir = 0;
  int daemon_noclose = 0;
  _Bool load_config = false;

  crypto_init();
  settings_init();

  char* shortopts =
    "C:" /* TODO: support config file */
    "c:" /* cipher name */
    "d:" /* dns cache timeout */
    "D"  /* TODO: support daemon mode */
    // "g:" /* TODO: make it comma-separate; nameservers */
    "j:" /* Connect to this port */
    "k:" /* password for AES enc/dec */
    "n:" /* TODO: support worker number */
    "o:" /* Path to resolver conf */
    "p:" /* Bind to this port */
    "P:" /* TODO: Save PID file */
    // "r:" /* TODO: read rate limit */
    "s:" /* Bind to this address */
    "t:" /* Timeout for connections */
    "u:" /* Connect to this address */
    // "v"  /* TODO: verbose */
    "Vh"  /* Show version number */
    // "w:" /* TODO: write rate limit */
    ;
  while (cc != -1) {
    cc = getopt(argc, argv, shortopts);

    switch(cc) {
    case 'c':
      settings.cipher_name = optarg;
      break;
    case 'C':
      load_config = true;
      settings.config_file = optarg;
      break;
    case 'd':
      settings.dns_cache_tval = atol(optarg);
      break;
    case 'D':
      settings.daemon_mode = true;
      break;
    case 'j':
      port = atoi(optarg);
      if (port < 1 || port > 65535)
	usage();
      settings.server_port = port;
      settings.relay_mode = true;
      break;
    case 'k':
      settings.passphrase = (u8*)optarg;
      break;
    case 'n':
      settings.workers = atoi(optarg);
      break;
    case 'o':
      settings.resolv_conf = optarg;
      break;
    case 'p':
      port = atoi(optarg);
      if (port < 1 || port > 65535)
	usage();
      settings.listen_port = port;
      break;
    case 'P':
      settings.pid_file = optarg;
      break;
    case 's':
      settings.listen_addr = optarg;
      break;
    case 't':
      settings.connection_timeout = atol(optarg);
      break;
    case 'u':
      settings.server_addr = optarg;
      settings.relay_mode = true;
      break;
    case 'V':
      printf("esocks %s\n", ESOCKS_VERSION);
      exit(0);
    case 'h':
      usage();
      break;
    case '?':
      usage();
    }
  }

  if (load_config)
    if (e_parse_conf_file(&settings, settings.config_file) != 0)
      log_ex(1, "cannot find config file: %s", settings.config_file);

  settings.plen = strlen((char*)settings.passphrase);

  settings.cipher = EVP_get_cipherbyname(settings.cipher_name);
  if (settings.cipher == NULL)
    log_ex(1, "failed to set cipher: %s", settings.cipher_name);

  settings.dgst = EVP_md5();

  EVP_BytesToKey(settings.cipher, settings.dgst, NULL,
		 settings.passphrase, settings.plen, 1, (u8*)settings.key,
		 (u8*)settings.iv);

  DEBUG ? NULL : event_set_fatal_callback(fatal_error_cb);

  save_pid(settings.pid_file);

  if (settings.daemon_mode)
    daemonize(daemon_nochdir, daemon_noclose);

  if (settings.relay_mode)
    log_i("listening on %s:%d and connect to %s:%d",
	  settings.listen_addr, settings.listen_port, settings.server_addr,
	  settings.server_port);
  else
      log_i("listening on %s:%d", settings.listen_addr, settings.listen_port);

  log_d(DEBUG, "running in debug mode, timeout=%d mode=%s",
	settings.connection_timeout, settings.cipher_name);

  if (settings.workers)
    ev_do_fork(settings.workers);
  else
    (void)e_start_server();

  remove_pid(settings.pid_file);
  exit(0);
}
