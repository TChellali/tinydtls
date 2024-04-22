/*******************************************************************************
 *
 * Copyright (c) 2011, 2012, 2013, 2014, 2015 Olaf Bergmann (TZI) and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v. 1.0 which accompanies this distribution.
 *
 * The Eclipse Public License is available at http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at 
 * http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * Contributors:
 *    Olaf Bergmann  - initial API and implementation
 *    Hauke Mehrtens - memory optimization, ECC integration
 *
 *******************************************************************************/

#include "tinydtls.h"

#include "iowa_logger.h"

#if defined(HAVE_ASSERT_H) && !defined(assert)
#include <assert.h>
#endif

#include <stdarg.h>
#include <stdio.h>

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef HAVE_TIME_H
#include <time.h>
#endif

#include "global.h"
#include "dtls_debug.h"
#include "dtls_time.h"

#ifndef min
#define min(a,b) ((a) < (b) ? (a) : (b))
#endif

static int maxlog = DTLS_LOG_WARN;	/* default maximum log level */

const char *dtls_package_name() {
  return PACKAGE_NAME;
}

const char *dtls_package_version() {
  return PACKAGE_VERSION;
}

log_t 
dtls_get_log_level() {
  return (log_t)maxlog;
}

void
dtls_set_log_level(log_t level) {
#ifdef NDEBUG
  maxlog = min(level, DTLS_LOG_INFO);
#else /* !NDEBUG */
  maxlog = level;
#endif /* NDEBUG */
}

/* this array has the same order as the type log_t */
static char *loglevels[] = {
  "EMRG", "ALRT", "CRIT", "WARN", "NOTE", "INFO", "DEBG" 
};

#ifdef HAVE_TIME_H

static inline size_t
print_timestamp(char *s, size_t len, time_t t) {
  struct tm *tmp;
  tmp = localtime(&t);
  return strftime(s, len, "%b %d %H:%M:%S", tmp);
}

#else /* alternative implementation: just print the timestamp */

static inline size_t
print_timestamp(char *s, size_t len, clock_time_t t) {
#ifdef HAVE_SNPRINTF
  return snprintf(s, len, "%u.%03u", 
		  (unsigned int)(t / CLOCK_SECOND), 
		  (unsigned int)(t % CLOCK_SECOND));
#else /* HAVE_SNPRINTF */
  /* @todo do manual conversion of timestamp */
  return 0;
#endif /* HAVE_SNPRINTF */
}

#endif /* HAVE_TIME_H */

#ifndef NDEBUG

#ifdef HAVE_ARPA_INET_H
/** 
 * A length-safe strlen() fake. 
 * 
 * @param s      The string to count characters != 0.
 * @param maxlen The maximum length of @p s.
 * 
 * @return The length of @p s.
 */
static inline size_t
dtls_strnlen(const char *s, size_t maxlen) {
  size_t n = 0;
  while(*s++ && n < maxlen)
    ++n;
  return n;
}
#endif

static size_t
dsrv_print_addr(const session_t *addr, char *buf, size_t len) {
#ifdef HAVE_ARPA_INET_H
  const void *addrptr = NULL;
  in_port_t port;
  char *p = buf;

  switch (addr->addr.sa.sa_family) {
  case AF_INET: 
    if (len < INET_ADDRSTRLEN)
      return 0;
  
    addrptr = &addr->addr.sin.sin_addr;
    port = ntohs(addr->addr.sin.sin_port);
    break;
  case AF_INET6:
    if (len < INET6_ADDRSTRLEN + 2)
      return 0;

    *p++ = '[';

    addrptr = &addr->addr.sin6.sin6_addr;
    port = ntohs(addr->addr.sin6.sin6_port);

    break;
  default:
    memcpy(buf, "(unknown address type)", min(22, len));
    return min(22, len);
  }

  if (inet_ntop(addr->addr.sa.sa_family, addrptr, p, len) == 0) {
    perror("dsrv_print_addr");
    return 0;
  }

  p += dtls_strnlen(p, len);

  if (addr->addr.sa.sa_family == AF_INET6) {
    if (p < buf + len) {
      *p++ = ']';
    } else 
      return 0;
  }

  p += snprintf(p, buf + len - p + 1, ":%d", port);

  return p - buf;
#else /* HAVE_ARPA_INET_H */
# if WITH_CONTIKI
  char *p = buf;
#  if NETSTACK_CONF_WITH_IPV6
  uint8_t i;
  const char hex[] = "0123456789ABCDEF";

  if (len < 41)
    return 0;

  *p++ = '[';

  for (i=0; i < 16; i += 2) {
    if (i) {
      *p++ = ':';
    }
    *p++ = hex[(addr->addr.u8[i] & 0xf0) >> 4];
    *p++ = hex[(addr->addr.u8[i] & 0x0f)];
    *p++ = hex[(addr->addr.u8[i+1] & 0xf0) >> 4];
    *p++ = hex[(addr->addr.u8[i+1] & 0x0f)];
  }
  *p++ = ']';
#  else /* NETSTACK_CONF_IPV6 */
  if (len < 21)
    return 0;

  p += sprintf(p, "%u.%u.%u.%u",
               addr->addr.u8[0], addr->addr.u8[1],
               addr->addr.u8[2], addr->addr.u8[3]);
#  endif /* NETSTACK_CONF_IPV6 */
  if (buf + len - p < 6)
    return 0;

  p += sprintf(p, ":%d", uip_htons(addr->port));

  return p - buf;
# endif /* WITH_CONTIKI */
  return 0;
#endif
}

#endif /* NDEBUG */

void 
dsrv_log(log_t level, const char *functionName, unsigned int line, char *format, ...) {
    char str[DEBUG_BUF_SIZE];
    va_list ap;
    size_t size;

    size = 0;
    va_start(ap, format);
    size = vsnprintf(str, DEBUG_BUF_SIZE, format, ap);
    va_end(ap);

    if (size >= 0 && size < DEBUG_BUF_SIZE)
    {
        if (str[size - 1] == '\n')
        {
            str[size - 1] = '\0';
        }
    }

    switch (level)
    {
    case DTLS_LOG_EMERG:
    case DTLS_LOG_ALERT:
    case DTLS_LOG_CRIT:
        iowa_log(IOWA_PART_SECURITY, IOWA_LOG_LEVEL_ERROR, functionName, line, str);
        break;

    case DTLS_LOG_WARN:
        iowa_log(IOWA_PART_SECURITY, IOWA_LOG_LEVEL_WARNING, functionName, line, str);
        break;

    case DTLS_LOG_NOTICE:
    case DTLS_LOG_INFO:
        iowa_log(IOWA_PART_SECURITY, IOWA_LOG_LEVEL_INFO, functionName, line, str);
        break;

    default:
        iowa_log(IOWA_PART_SECURITY, IOWA_LOG_LEVEL_TRACE, functionName, line, str);
    }
}

#ifndef NDEBUG
/** dumps packets in usual hexdump format */
void hexdump(const unsigned char *packet, int length) {
  int n = 0;

  while (length--) { 
    if (n % 16 == 0)
      printf("%08X ",n);

    printf("%02X ", *packet++);
    
    n++;
    if (n % 8 == 0) {
      if (n % 16 == 0)
	printf("\n");
      else
	printf(" ");
    }
  }
}

/** dump as narrow string of hex digits */
void dump(unsigned char *buf, size_t len) {
  while (len--) 
    printf("%02x", *buf++);
}

void dtls_dsrv_log_addr(log_t level, const char *name, const session_t *addr)
{
  char addrbuf[73];
  int len;

  len = dsrv_print_addr(addr, addrbuf, sizeof(addrbuf));
  if (!len)
    return;
  dsrv_log(level, __func__, __LINE__, "%s: %s\n", name, addrbuf);
}

#ifndef WITH_CONTIKI
void 
dtls_dsrv_hexdump_log(log_t level, const char *name, const unsigned char *buf, size_t length, int extend) {
  static char timebuf[32];

  if (maxlog < (int)level)
    return;
// #define dtls_debug_hexdump(name, buf, length) dtls_dsrv_hexdump_log(DTLS_LOG_DEBUG, name, buf, length, 1)

  iowa_log_buffer(IOWA_PART_SECURITY, IOWA_LOG_LEVEL_TRACE, name, 0x0, name, buf, length);
// #ifdef HAVE_TIME_H
//   if (print_timestamp(timebuf, sizeof(timebuf), time(NULL)))
// #else
//   if (print_timestamp(timebuf,sizeof(timebuf), iowa_system_gettime()))
// #endif
}
#else /* WITH_CONTIKI */
void 
dtls_dsrv_hexdump_log(log_t level, const char *name, const unsigned char *buf, size_t length, int extend) {
  static char timebuf[32];
  int n = 0;

  if (maxlog < level)
    return;

  if (print_timestamp(timebuf,sizeof(timebuf), clock_time()))
    PRINTF("%s ", timebuf);

  if (level >= 0 && level <= DTLS_LOG_DEBUG) 
    PRINTF("%s ", loglevels[level]);

  if (extend) {
    PRINTF("%s: (%zu bytes):\n", name, length);

    while (length--) {
      if (n % 16 == 0)
	PRINTF("%08X ", n);

      PRINTF("%02X ", *buf++);

      n++;
      if (n % 8 == 0) {
	if (n % 16 == 0)
	  PRINTF("\n");
	else
	  PRINTF(" ");
      }
    }
  } else {
    PRINTF("%s: (%zu bytes): ", name, length);
    while (length--) 
      PRINTF("%02X", *buf++);
  }
  PRINTF("\n");
}
#endif /* WITH_CONTIKI */

#endif /* NDEBUG */
