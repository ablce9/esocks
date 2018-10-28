#ifndef esocks_log_h
#define esocks_log_h

#include <stdarg.h>

#ifdef __GNUC__
#define S_CHECK_FMT(a, b) __attribute__((format(printf, a, b)))
#define S_NO_RETURN __attribute__((noreturn))
#else
#define S_CHECK_FMT(a, b)
#define S_NO_RETURN
#endif

#define SOCKS_LOG_DEBUG  1
#define SOCKS_LOG_INFO   2
#define SOCKS_LOG_WARN   3
#define SOCKS_LOG_ERROR  4

void log_ex(int eval, const char* fmt, ...)S_NO_RETURN;
void log_e(const char* fmt, ...) S_CHECK_FMT(1, 2);
void log_warn(const char* fmt, ...) S_CHECK_FMT(1, 2);
void log_d(int v, const char* fmt, ...) S_CHECK_FMT(2, 3);
void log_i(const char* fmt, ...) S_CHECK_FMT(1, 2);
void log_output(int serverity, const char* errstr, const char* fmt, va_list ap) S_CHECK_FMT(3, 0);

#endif
