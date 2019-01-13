#include <errno.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#include <event2/util.h>

#include "log.h"

static void socks_log(int serverity, const char *msg);

void log_ex(int eval, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    log_output(SOCKS_LOG_ERROR, NULL, fmt, ap);
    va_end(ap);
    exit(eval);
}

void log_e(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    log_output(SOCKS_LOG_ERROR, strerror(errno), fmt, ap);
    va_end(ap);
}

void log_warn(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    log_output(SOCKS_LOG_WARN, strerror(errno), fmt, ap);
    va_end(ap);
}

void log_d(int v, const char *fmt, ...)
{
    va_list ap;

    if (v > 0) {
	va_start(ap, fmt);
	log_output(SOCKS_LOG_DEBUG, NULL, fmt, ap);
	va_end(ap);
    }
}

void log_i(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    log_output(SOCKS_LOG_INFO, NULL, fmt, ap);
    va_end(ap);
}

void log_output(int serverity, const char *errstr, const char *fmt, va_list ap)
{
    char buf[512];
    size_t len;

    if (fmt != NULL)
	evutil_vsnprintf(buf, sizeof(buf), fmt, ap);
    else
	// null-terminated
	buf[0] = '\0';

    if (errstr) {
	len = strlen(buf);
	if (len < sizeof(buf) - 3) {
	    evutil_snprintf(buf + len, sizeof(buf) - len, ": %s", errstr);
	}
    }

    socks_log(serverity, buf);
}

static void socks_log(int serverity, const char *msg)
{
    time_t t;
    struct timeval now;
    struct tm tm;
    int ms;
    const char *serverity_str = NULL;
    char timebuf[64];
    size_t n;

    evutil_gettimeofday(&now, NULL);
    t = (time_t)now.tv_sec;
    ms = (int)now.tv_usec / 1000;
    n = strftime(timebuf, sizeof(timebuf), "%b %d %H:%M:%S",
		 localtime_r(&t, &tm));
    evutil_snprintf(timebuf+n, sizeof(timebuf)-n, ".%.3i", ms);

    switch (serverity) {
    case SOCKS_LOG_DEBUG:
	serverity_str = "debug";
	break;
    case SOCKS_LOG_INFO:
	serverity_str = "info";
	break;
    case SOCKS_LOG_WARN:
	serverity_str = "warn";
	break;
    case SOCKS_LOG_ERROR:
	serverity_str = "error";
	break;
    }
    (void)fprintf(stderr, "%s [%s] %s\n", timebuf, serverity_str, msg);
}
