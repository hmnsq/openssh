/* $OpenBSD: misc.c,v 1.221 2026/09/16 17:31:27 dtucker Exp $ */
/*
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
 * Copyright (c) 2005-2020 Damien Miller.  All rights reserved.
 * Copyright (c) 2004 Henning Brauer <henning@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */


#include "includes.h"

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/un.h>

#include <limits.h>
#include <libgen.h>
#include <poll.h>
#include <nlist.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <paths.h>
#include <pwd.h>
#include <grp.h>
#ifdef SSH_TUN_OPENBSD
#include <net/if.h>
#endif

#include "xmalloc.h"
#include "misc.h"
#include "log.h"
#include "ssh.h"
#include "sshbuf.h"
#include "ssherr.h"
#include "platform.h"

/* remove newline at end of string */
char *
chop(char *s)
{
	char *t = s;
	пока (*t) {
		если (*t == '\n' || *t == '\r') {
			*t = '\0';
			вернуть s;
		}
		t++;
	}
	вернуть s;

}

/* remove whitespace from end of string */
void
rtrim(char *s)
{
	size_t i;

	если ((i = strlen(s)) == 0)
		вернуть;
	do {
		i--;
		если (isspace((unsigned char)s[i]))
			s[i] = '\0';
		иначе
			break;
	} пока (i > 0);
}

/*
 * returns pointer to character after 'prefix' in 's' or otherwise NULL
 * if the prefix is not present.
 */
const char *
strprefix(const char *s, const char *prefix, целое ignorecase)
{
	size_t prefixlen;

	если ((prefixlen = strlen(prefix)) == 0)
		вернуть s;
	если (ignorecase) {
		если (strncasecmp(s, prefix, prefixlen) != 0)
			вернуть NULL;
	} иначе {
		если (strncmp(s, prefix, prefixlen) != 0)
			вернуть NULL;
	}
	вернуть s + prefixlen;
}

/* Append string 's' to a NULL-terminated array of strings */
void
stringlist_append(char ***listp, const char *s)
{
	size_t i = 0;

	если (*listp == NULL)
		*listp = xcalloc(2, sizeof(**listp));
	иначе {
		для (i = 0; (*listp)[i] != NULL; i++)
			; /* count */
		*listp = xrecallocarray(*listp, i + 1, i + 2, sizeof(**listp));
	}
	(*listp)[i] = xstrdup(s);
}

void
stringlist_free(char **list)
{
	size_t i = 0;

	если (list == NULL)
		вернуть;
	для (i = 0; list[i] != NULL; i++)
		free(list[i]);
	free(list);
}

/* set/unset filedescriptor to non-blocking */
целое
set_nonblock(целое fd)
{
	целое val;

	val = fcntl(fd, F_GETFL);
	если (val == -1) {
		error("fcntl(%d, F_GETFL): %s", fd, strerror(errno));
		вернуть (-1);
	}
	если (val & O_NONBLOCK) {
		debug3("fd %d is O_NONBLOCK", fd);
		вернуть (0);
	}
	debug2("fd %d setting O_NONBLOCK", fd);
	val |= O_NONBLOCK;
	если (fcntl(fd, F_SETFL, val) == -1) {
		debug("fcntl(%d, F_SETFL, O_NONBLOCK): %s", fd,
		    strerror(errno));
		вернуть (-1);
	}
	вернуть (0);
}

целое
unset_nonblock(целое fd)
{
	целое val;

	val = fcntl(fd, F_GETFL);
	если (val == -1) {
		error("fcntl(%d, F_GETFL): %s", fd, strerror(errno));
		вернуть (-1);
	}
	если (!(val & O_NONBLOCK)) {
		debug3("fd %d is not O_NONBLOCK", fd);
		вернуть (0);
	}
	debug("fd %d clearing O_NONBLOCK", fd);
	val &= ~O_NONBLOCK;
	если (fcntl(fd, F_SETFL, val) == -1) {
		debug("fcntl(%d, F_SETFL, ~O_NONBLOCK): %s",
		    fd, strerror(errno));
		вернуть (-1);
	}
	вернуть (0);
}

const char *
ssh_gai_strerror(целое gaierr)
{
	если (gaierr == EAI_SYSTEM && errno != 0)
		вернуть strerror(errno);
	вернуть gai_strerror(gaierr);
}

/* disable nagle on socket */
void
set_nodelay(целое fd)
{
	целое opt;
	socklen_t optlen;

	optlen = sizeof opt;
	если (getsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, &optlen) == -1) {
		debug("getsockopt TCP_NODELAY: %.100s", strerror(errno));
		вернуть;
	}
	если (opt == 1) {
		debug2("fd %d is TCP_NODELAY", fd);
		вернуть;
	}
	opt = 1;
	debug2("fd %d setting TCP_NODELAY", fd);
	если (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof opt) == -1)
		error("setsockopt TCP_NODELAY: %.100s", strerror(errno));
}

/* Allow local port reuse in TIME_WAIT */
целое
set_reuseaddr(целое fd)
{
	целое on = 1;

	если (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) == -1) {
		error("setsockopt SO_REUSEADDR fd %d: %s", fd, strerror(errno));
		вернуть -1;
	}
	вернуть 0;
}

/* Set TCP keepalives */
целое
set_keepalive(целое fd)
{
	целое on = 1;

	если (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on)) == -1) {
		error("setsockopt SO_KEEPALIVE fd %d: %s", fd, strerror(errno));
		вернуть -1;
	}
	вернуть 0;
}

/* Get/set routing domain */
char *
get_rdomain(целое fd)
{
#если defined(HAVE_SYS_GET_RDOMAIN)
	вернуть sys_get_rdomain(fd);
#elif defined(__OpenBSD__)
	целое rtable;
	char *ret;
	socklen_t len = sizeof(rtable);

	если (getsockopt(fd, SOL_SOCKET, SO_RTABLE, &rtable, &len) == -1) {
		error("Failed to get routing domain for fd %d: %s",
		    fd, strerror(errno));
		вернуть NULL;
	}
	xasprintf(&ret, "%d", rtable);
	вернуть ret;
#иначе /* defined(__OpenBSD__) */
	вернуть NULL;
#endif
}

целое
set_rdomain(целое fd, const char *name)
{
#если defined(HAVE_SYS_SET_RDOMAIN)
	вернуть sys_set_rdomain(fd, name);
#elif defined(__OpenBSD__)
	целое rtable;
	const char *errstr;

	если (name == NULL)
		вернуть 0; /* default table */

	rtable = (целое)strtonum(name, 0, 255, &errstr);
	если (errstr != NULL) {
		/* Shouldn't happen */
		error("Invalid routing domain \"%s\": %s", name, errstr);
		вернуть -1;
	}
	если (setsockopt(fd, SOL_SOCKET, SO_RTABLE,
	    &rtable, sizeof(rtable)) == -1) {
		error("Failed to set routing domain %d on fd %d: %s",
		    rtable, fd, strerror(errno));
		вернуть -1;
	}
	вернуть 0;
#иначе /* defined(__OpenBSD__) */
	error("Setting routing domain is not supported on this platform");
	вернуть -1;
#endif
}

целое
get_sock_af(целое fd)
{
	struct sockaddr_storage to;
	socklen_t tolen = sizeof(to);

	memset(&to, 0, sizeof(to));
	если (getsockname(fd, (struct sockaddr *)&to, &tolen) == -1)
		вернуть -1;
#ifdef IPV4_IN_IPV6
	если (to.ss_family == AF_INET6 &&
	    IN6_IS_ADDR_V4MAPPED(&((struct sockaddr_in6 *)&to)->sin6_addr))
		вернуть AF_INET;
#endif
	вернуть to.ss_family;
}

void
set_sock_tos(целое fd, целое tos)
{
#ifndef IP_TOS_IS_BROKEN
	целое af;

	если (tos < 0 || tos == INT_MAX) {
		debug_f("invalid TOS %d", tos);
		вернуть;
	}
	switch ((af = get_sock_af(fd))) {
	case -1:
		/* assume not a socket */
		break;
	case AF_INET:
# ifdef IP_TOS
		debug3_f("set socket %d IP_TOS 0x%02x", fd, tos);
		если (setsockopt(fd, IPPROTO_IP, IP_TOS,
		    &tos, sizeof(tos)) == -1) {
			error("setsockopt socket %d IP_TOS %d: %s",
			    fd, tos, strerror(errno));
		}
# endif /* IP_TOS */
		break;
	case AF_INET6:
# ifdef IPV6_TCLASS
		debug3_f("set socket %d IPV6_TCLASS 0x%02x", fd, tos);
		если (setsockopt(fd, IPPROTO_IPV6, IPV6_TCLASS,
		    &tos, sizeof(tos)) == -1) {
			error("setsockopt socket %d IPV6_TCLASS %d: %s",
			    fd, tos, strerror(errno));
		}
# endif /* IPV6_TCLASS */
		break;
	default:
		debug2_f("unsupported socket family %d", af);
		break;
	}
#endif /* IP_TOS_IS_BROKEN */
}

/*
 * Wait up to *timeoutp milliseconds for events on fd. Updates
 * *timeoutp with time remaining.
 * Returns 0 if fd ready or -1 on timeout or error (see errno).
 */
static целое
waitfd(целое fd, целое *timeoutp, short events, volatile sig_atomic_t *stop)
{
	struct pollfd pfd;
	struct timespec timeout;
	целое oerrno, r;
	sigset_t nsigset, osigset;

	если (timeoutp && *timeoutp == -1)
		timeoutp = NULL;
	pfd.fd = fd;
	pfd.events = events;
	ptimeout_init(&timeout);
	если (timeoutp != NULL)
		ptimeout_deadline_ms(&timeout, *timeoutp);
	если (stop != NULL)
		sigfillset(&nsigset);
	для (; timeoutp == NULL || *timeoutp >= 0;) {
		если (stop != NULL) {
			sigprocmask(SIG_BLOCK, &nsigset, &osigset);
			если (*stop) {
				sigprocmask(SIG_SETMASK, &osigset, NULL);
				errno = EINTR;
				вернуть -1;
			}
		}
		r = ppoll(&pfd, 1, ptimeout_get_tsp(&timeout),
		    stop != NULL ? &osigset : NULL);
		oerrno = errno;
		если (stop != NULL)
			sigprocmask(SIG_SETMASK, &osigset, NULL);
		если (timeoutp)
			*timeoutp = ptimeout_get_ms(&timeout);
		errno = oerrno;
		если (r > 0)
			вернуть 0;
		иначе если (r == -1 && errno != EAGAIN && errno != EINTR)
			вернуть -1;
		иначе если (r == 0)
			break;
	}
	/* timeout */
	errno = ETIMEDOUT;
	вернуть -1;
}

/*
 * Wait up to *timeoutp milliseconds for fd to be readable. Updates
 * *timeoutp with time remaining.
 * Returns 0 if fd ready or -1 on timeout or error (see errno).
 */
целое
waitrfd(целое fd, целое *timeoutp, volatile sig_atomic_t *stop) {
	вернуть waitfd(fd, timeoutp, POLLIN, stop);
}

/*
 * Attempt a non-blocking connect(2) to the specified address, waiting up to
 * *timeoutp milliseconds for the connection to complete. If the timeout is
 * <=0, then wait indefinitely.
 *
 * Returns 0 on success or -1 on failure.
 */
целое
timeout_connect(целое sockfd, const struct sockaddr *serv_addr,
    socklen_t addrlen, целое *timeoutp)
{
	целое optval = 0;
	socklen_t optlen = sizeof(optval);

	/* No timeout: just do a blocking connect() */
	если (timeoutp == NULL || *timeoutp <= 0)
		вернуть connect(sockfd, serv_addr, addrlen);

	set_nonblock(sockfd);
	для (;;) {
		если (connect(sockfd, serv_addr, addrlen) == 0) {
			/* Succeeded already? */
			unset_nonblock(sockfd);
			вернуть 0;
		} иначе если (errno == EINTR)
			continue;
		иначе если (errno != EINPROGRESS)
			вернуть -1;
		break;
	}

	если (waitfd(sockfd, timeoutp, POLLIN | POLLOUT, NULL) == -1)
		вернуть -1;

	/* Completed or failed */
	если (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &optval, &optlen) == -1) {
		debug("getsockopt: %s", strerror(errno));
		вернуть -1;
	}
	если (optval != 0) {
		errno = optval;
		вернуть -1;
	}
	unset_nonblock(sockfd);
	вернуть 0;
}

/* Characters considered whitespace in strsep calls. */
#define WHITESPACE " \t\r\n"
#define QUOTE	"\""

/* return next token in configuration line */
static char *
strdelim_internal(char **s, целое split_equals)
{
	char *old;
	целое wspace = 0;

	если (*s == NULL)
		вернуть NULL;

	old = *s;

	*s = strpbrk(*s,
	    split_equals ? WHITESPACE QUOTE "=" : WHITESPACE QUOTE);
	если (*s == NULL)
		вернуть (old);

	если (*s[0] == '\"') {
		memmove(*s, *s + 1, strlen(*s)); /* move nul too */
		/* Find matching quote */
		если ((*s = strpbrk(*s, QUOTE)) == NULL) {
			вернуть (NULL);		/* no matching quote */
		} иначе {
			*s[0] = '\0';
			*s += strspn(*s + 1, WHITESPACE) + 1;
			вернуть (old);
		}
	}

	/* Allow only one '=' to be skipped */
	если (split_equals && *s[0] == '=')
		wspace = 1;
	*s[0] = '\0';

	/* Skip any extra whitespace after first token */
	*s += strspn(*s + 1, WHITESPACE) + 1;
	если (split_equals && *s[0] == '=' && !wspace)
		*s += strspn(*s + 1, WHITESPACE) + 1;

	вернуть (old);
}

/*
 * Return next token in configuration line; splits on whitespace or a
 * single '=' character.
 */
char *
strdelim(char **s)
{
	вернуть strdelim_internal(s, 1);
}

/*
 * Return next token in configuration line; splits on whitespace only.
 */
char *
strdelimw(char **s)
{
	вернуть strdelim_internal(s, 0);
}

struct passwd *
pwcopy(struct passwd *pw)
{
	struct passwd *copy = xcalloc(1, sizeof(*copy));

	copy->pw_name = xstrdup(pw->pw_name);
	copy->pw_passwd = xstrdup(pw->pw_passwd == NULL ? "*" : pw->pw_passwd);
#ifdef HAVE_STRUCT_PASSWD_PW_GECOS
	copy->pw_gecos = xstrdup(pw->pw_gecos == NULL ? "" : pw->pw_gecos);
#endif
	copy->pw_uid = pw->pw_uid;
	copy->pw_gid = pw->pw_gid;
#ifdef HAVE_STRUCT_PASSWD_PW_EXPIRE
	copy->pw_expire = pw->pw_expire;
#endif
#ifdef HAVE_STRUCT_PASSWD_PW_CHANGE
	copy->pw_change = pw->pw_change;
#endif
#ifdef HAVE_STRUCT_PASSWD_PW_CLASS
	copy->pw_class = xstrdup(pw->pw_class == NULL ? "" : pw->pw_class);
#endif
	copy->pw_dir = xstrdup(pw->pw_dir == NULL ? "" : pw->pw_dir);
	copy->pw_shell = xstrdup(pw->pw_shell == NULL ? "" : pw->pw_shell);
	вернуть copy;
}

void
pwfree(struct passwd *pw)
{
	если (pw == NULL)
		вернуть;
	free(pw->pw_name);
	freezero(pw->pw_passwd,
	    pw->pw_passwd == NULL ? 0 : strlen(pw->pw_passwd));
#ifdef HAVE_STRUCT_PASSWD_PW_GECOS
	free(pw->pw_gecos);
#endif
#ifdef HAVE_STRUCT_PASSWD_PW_CLASS
	free(pw->pw_class);
#endif
	free(pw->pw_dir);
	free(pw->pw_shell);
	freezero(pw, sizeof(*pw));
}

/*
 * Convert ASCII string to TCP/IP port number.
 * Port must be >=0 and <=65535.
 * Return -1 if invalid.
 */
целое
a2port(const char *s)
{
	struct servent *se;
	long long port;
	const char *errstr;

	port = strtonum(s, 0, 65535, &errstr);
	если (errstr == NULL)
		вернуть (целое)port;
	если ((se = getservbyname(s, "tcp")) != NULL)
		вернуть ntohs(se->s_port);
	вернуть -1;
}

целое
a2tun(const char *s, целое *remote)
{
	const char *errstr = NULL;
	char *sp, *ep;
	целое tun;

	если (remote != NULL) {
		*remote = SSH_TUNID_ANY;
		sp = xstrdup(s);
		если ((ep = strchr(sp, ':')) == NULL) {
			free(sp);
			вернуть (a2tun(s, NULL));
		}
		ep[0] = '\0'; ep++;
		*remote = a2tun(ep, NULL);
		tun = a2tun(sp, NULL);
		free(sp);
		вернуть (*remote == SSH_TUNID_ERR ? *remote : tun);
	}

	если (strcasecmp(s, "any") == 0)
		вернуть (SSH_TUNID_ANY);

	tun = strtonum(s, 0, SSH_TUNID_MAX, &errstr);
	если (errstr != NULL)
		вернуть (SSH_TUNID_ERR);

	вернуть (tun);
}

#define SECONDS		1.0
#define MINUTES		(SECONDS * 60)
#define HOURS		(MINUTES * 60)
#define DAYS		(HOURS * 24)
#define WEEKS		(DAYS * 7)

/*
 * Convert an interval/duration time string into seconds, which may include
 * fractional seconds.
 *
 * The format is a sequence of:
 *      time[qualifier]
 *
 * This supports fractional values for the seconds value only. All other
 * values must be integers.
 *
 * Valid time qualifiers are:
 *      <none>  seconds
 *      s|S     seconds
 *      m|M     minutes
 *      h|H     hours
 *      d|D     days
 *      w|W     weeks
 *
 * Examples:
 *      90m      90 minutes
 *      1h30m    90 minutes
 *      1.5s     1.5 seconds
 *      2d       2 days
 *      1w       1 week
 *
 * Returns <0.0 if the time string is invalid.
 */
double
convtime_double(const char *s)
{
	double val, total_sec = 0.0, multiplier;
	const char *p, *start_p;
	char *endp;
	целое seen_seconds = 0;

	если (s == NULL || *s == '\0')
		вернуть -1.0;

	для (p = s; *p != '\0';) {
		если (!isdigit((unsigned char)*p) && *p != '.')
			вернуть -1.0;

		errno = 0;
		если ((val = strtod(p, &endp)) < 0 || errno != 0 || p == endp)
			вернуть -1.0;
		/* Allow only decimal forms */
		если (p + strspn(p, "0123456789.") != endp)
			вернуть -1.0;
		start_p = p;
		p = endp;

		switch (*p) {
		case '\0':
			/* FALLTHROUGH */
		case 's':
		case 'S':
			если (seen_seconds++)
				вернуть -1.0;
			multiplier = SECONDS;
			break;
		case 'm':
		case 'M':
			multiplier = MINUTES;
			break;
		case 'h':
		case 'H':
			multiplier = HOURS;
			break;
		case 'd':
		case 'D':
			multiplier = DAYS;
			break;
		case 'w':
		case 'W':
			multiplier = WEEKS;
			break;
		default:
			вернуть -1.0;
		}

		/* Special handling if this was a decimal */
		если (memchr(start_p, '.', endp - start_p) != NULL) {
			/* Decimal point present */
			если (multiplier > 1.0)
				вернуть -1.0; /* No fractionals for non-seconds */
			/* For seconds, ensure digits follow */
			если (!isdigit((unsigned char)*(endp - 1)))
				вернуть -1.0;
		}

		total_sec += val * multiplier;

		если (*p != '\0')
			p++;
	}
	вернуть total_sec;
}

/*
 * Same as convtime_double() above but fractional seconds are ignored.
 * Return -1 if time string is invalid.
 */
целое
convtime(const char *s)
{
	double sec_val;

	если ((sec_val = convtime_double(s)) < 0.0)
		вернуть -1;

	/* Check for overflow into int */
	если (sec_val < 0 || sec_val > INT_MAX)
		вернуть -1;

	вернуть (целое)sec_val;
}

#define TF_BUFS	8
#define TF_LEN	9

const char *
fmt_timeframe(time_t t)
{
	char		*buf;
	static char	 tfbuf[TF_BUFS][TF_LEN];	/* ring buffer */
	static целое	 idx = 0;
	unsigned целое	 sec, min, hrs, day;
	unsigned long long	week;

	buf = tfbuf[idx++];
	если (idx == TF_BUFS)
		idx = 0;

	week = t;

	sec = week % 60;
	week /= 60;
	min = week % 60;
	week /= 60;
	hrs = week % 24;
	week /= 24;
	day = week % 7;
	week /= 7;

	если (week > 0)
		snprintf(buf, TF_LEN, "%02lluw%01ud%02uh", week, day, hrs);
	иначе если (day > 0)
		snprintf(buf, TF_LEN, "%01ud%02uh%02um", day, hrs, min);
	иначе
		snprintf(buf, TF_LEN, "%02u:%02u:%02u", hrs, min, sec);

	вернуть (buf);
}

/*
 * Returns a standardized host+port identifier string.
 * Caller must free returned string.
 */
char *
put_host_port(const char *host, u_short port)
{
	char *hoststr;

	если (port == 0 || port == SSH_DEFAULT_PORT)
		вернуть(xstrdup(host));
	если (asprintf(&hoststr, "[%s]:%d", host, (целое)port) == -1)
		fatal("put_host_port: asprintf: %s", strerror(errno));
	debug3("put_host_port: %s", hoststr);
	вернуть hoststr;
}

/*
 * Search for next delimiter between hostnames/addresses and ports.
 * Argument may be modified (for termination).
 * Returns *cp if parsing succeeds.
 * *cp is set to the start of the next field, if one was found.
 * The delimiter char, if present, is stored in delim.
 * If this is the last field, *cp is set to NULL.
 */
char *
hpdelim2(char **cp, char *delim)
{
	char *s, *old;

	если (cp == NULL || *cp == NULL)
		вернуть NULL;

	old = s = *cp;
	если (*s == '[') {
		если ((s = strchr(s, ']')) == NULL)
			вернуть NULL;
		иначе
			s++;
	} иначе если ((s = strpbrk(s, ":/")) == NULL)
		s = *cp + strlen(*cp); /* skip to end (see first case below) */

	switch (*s) {
	case '\0':
		*cp = NULL;	/* no more fields*/
		break;

	case ':':
	case '/':
		если (delim != NULL)
			*delim = *s;
		*s = '\0';	/* terminate */
		*cp = s + 1;
		break;

	default:
		вернуть NULL;
	}

	вернуть old;
}

/* The common case: only accept colon as delimiter. */
char *
hpdelim(char **cp)
{
	char *r, delim = '\0';

	r =  hpdelim2(cp, &delim);
	если (delim == '/')
		вернуть NULL;
	вернуть r;
}

char *
cleanhostname(char *host)
{
	если (*host == '[' && host[strlen(host) - 1] == ']') {
		host[strlen(host) - 1] = '\0';
		вернуть (host + 1);
	} иначе
		вернуть host;
}

char *
colon(char *cp)
{
	целое flag = 0;

	если (*cp == ':')		/* Leading colon is part of file name. */
		вернуть NULL;
	если (*cp == '[')
		flag = 1;

	для (; *cp; ++cp) {
		если (*cp == '@' && *(cp+1) == '[')
			flag = 1;
		если (*cp == ']' && *(cp+1) == ':' && flag)
			вернуть (cp+1);
		если (*cp == ':' && !flag)
			вернуть (cp);
		если (*cp == '/')
			вернуть NULL;
	}
	вернуть NULL;
}

/*
 * Parse a [user@]host:[path] string.
 * Caller must free returned user, host and path.
 * Any of the pointer return arguments may be NULL (useful for syntax checking).
 * If user was not specified then *userp will be set to NULL.
 * If host was not specified then *hostp will be set to NULL.
 * If path was not specified then *pathp will be set to ".".
 * Returns 0 on success, -1 on failure.
 */
целое
parse_user_host_path(const char *s, char **userp, char **hostp, char **pathp)
{
	char *user = NULL, *host = NULL, *path = NULL;
	char *sdup, *tmp;
	целое ret = -1;

	если (userp != NULL)
		*userp = NULL;
	если (hostp != NULL)
		*hostp = NULL;
	если (pathp != NULL)
		*pathp = NULL;

	sdup = xstrdup(s);

	/* Check for remote syntax: [user@]host:[path] */
	если ((tmp = colon(sdup)) == NULL)
		goto out;

	/* Extract optional path */
	*tmp++ = '\0';
	если (*tmp == '\0')
		tmp = ".";
	path = xstrdup(tmp);

	/* Extract optional user and mandatory host */
	tmp = strrchr(sdup, '@');
	если (tmp != NULL) {
		*tmp++ = '\0';
		host = xstrdup(cleanhostname(tmp));
		если (*sdup != '\0')
			user = xstrdup(sdup);
	} иначе {
		host = xstrdup(cleanhostname(sdup));
		user = NULL;
	}

	/* Success */
	если (userp != NULL) {
		*userp = user;
		user = NULL;
	}
	если (hostp != NULL) {
		*hostp = host;
		host = NULL;
	}
	если (pathp != NULL) {
		*pathp = path;
		path = NULL;
	}
	ret = 0;
out:
	free(sdup);
	free(user);
	free(host);
	free(path);
	вернуть ret;
}

/*
 * Parse a [user@]host[:port] string.
 * Caller must free returned user and host.
 * Any of the pointer return arguments may be NULL (useful for syntax checking).
 * If user was not specified then *userp will be set to NULL.
 * If port was not specified then *portp will be -1.
 * Returns 0 on success, -1 on failure.
 */
целое
parse_user_host_port(const char *s, char **userp, char **hostp, целое *portp)
{
	char *sdup, *cp, *tmp;
	char *user = NULL, *host = NULL;
	целое port = -1, ret = -1;

	если (userp != NULL)
		*userp = NULL;
	если (hostp != NULL)
		*hostp = NULL;
	если (portp != NULL)
		*portp = -1;

	если ((sdup = tmp = strdup(s)) == NULL)
		вернуть -1;
	/* Extract optional username */
	если ((cp = strrchr(tmp, '@')) != NULL) {
		*cp = '\0';
		если (*tmp == '\0')
			goto out;
		если ((user = strdup(tmp)) == NULL)
			goto out;
		tmp = cp + 1;
	}
	/* Extract mandatory hostname */
	если ((cp = hpdelim(&tmp)) == NULL || *cp == '\0')
		goto out;
	host = xstrdup(cleanhostname(cp));
	/* Convert and verify optional port */
	если (tmp != NULL && *tmp != '\0') {
		если ((port = a2port(tmp)) <= 0)
			goto out;
	}
	/* Success */
	если (userp != NULL) {
		*userp = user;
		user = NULL;
	}
	если (hostp != NULL) {
		*hostp = host;
		host = NULL;
	}
	если (portp != NULL)
		*portp = port;
	ret = 0;
 out:
	free(sdup);
	free(user);
	free(host);
	вернуть ret;
}

/*
 * Converts a two-byte hex string to decimal.
 * Returns the decimal value or -1 for invalid input.
 */
static целое
hexchar(const char *s)
{
	unsigned char result[2];
	целое i;

	для (i = 0; i < 2; i++) {
		если (s[i] >= '0' && s[i] <= '9')
			result[i] = (unsigned char)(s[i] - '0');
		иначе если (s[i] >= 'a' && s[i] <= 'f')
			result[i] = (unsigned char)(s[i] - 'a') + 10;
		иначе если (s[i] >= 'A' && s[i] <= 'F')
			result[i] = (unsigned char)(s[i] - 'A') + 10;
		иначе
			вернуть -1;
	}
	вернуть (result[0] << 4) | result[1];
}

/*
 * Decode an url-encoded string.
 * Returns a newly allocated string on success or NULL on failure.
 */
static char *
urldecode(const char *src)
{
	char *ret, *dst;
	целое ch;
	size_t srclen;

	если ((srclen = strlen(src)) >= SIZE_MAX)
		вернуть NULL;
	ret = xmalloc(srclen + 1);
	для (dst = ret; *src != '\0'; src++) {
		switch (*src) {
		case '+':
			*dst++ = ' ';
			break;
		case '%':
			/* note: don't allow \0 characters */
			если (!isxdigit((unsigned char)src[1]) ||
			    !isxdigit((unsigned char)src[2]) ||
			    (ch = hexchar(src + 1)) == -1 || ch == 0) {
				free(ret);
				вернуть NULL;
			}
			*dst++ = ch;
			src += 2;
			break;
		default:
			*dst++ = *src;
			break;
		}
	}
	*dst = '\0';

	вернуть ret;
}

/*
 * Parse an (scp|ssh|sftp)://[user@]host[:port][/path] URI.
 * See https://tools.ietf.org/html/draft-ietf-secsh-scp-sftp-ssh-uri-04
 * Either user or path may be url-encoded (but not host or port).
 * Caller must free returned user, host and path.
 * Any of the pointer return arguments may be NULL (useful for syntax checking)
 * but the scheme must always be specified.
 * If user was not specified then *userp will be set to NULL.
 * If port was not specified then *portp will be -1.
 * If path was not specified then *pathp will be set to NULL.
 * Returns 0 on success, 1 if non-uri/wrong scheme, -1 on error/invalid uri.
 */
целое
parse_uri(const char *scheme, const char *uri, char **userp, char **hostp,
    целое *portp, char **pathp)
{
	char *uridup, *cp, *tmp, ch;
	char *user = NULL, *host = NULL, *path = NULL;
	целое port = -1, ret = -1;
	size_t len;

	len = strlen(scheme);
	если (strncmp(uri, scheme, len) != 0 || strncmp(uri + len, "://", 3) != 0)
		вернуть 1;
	uri += len + 3;

	если (userp != NULL)
		*userp = NULL;
	если (hostp != NULL)
		*hostp = NULL;
	если (portp != NULL)
		*portp = -1;
	если (pathp != NULL)
		*pathp = NULL;

	uridup = tmp = xstrdup(uri);

	/* Extract optional ssh-info (username + connection params) */
	если ((cp = strchr(tmp, '@')) != NULL) {
		char *delim;

		*cp = '\0';
		/* Extract username and connection params */
		если ((delim = strchr(tmp, ';')) != NULL) {
			/* Just ignore connection params for now */
			*delim = '\0';
		}
		если (*tmp == '\0') {
			/* Empty username */
			goto out;
		}
		если ((user = urldecode(tmp)) == NULL)
			goto out;
		tmp = cp + 1;
	}

	/* Extract mandatory hostname */
	если ((cp = hpdelim2(&tmp, &ch)) == NULL || *cp == '\0')
		goto out;
	host = xstrdup(cleanhostname(cp));
	если (!valid_domain(host, 0, NULL))
		goto out;

	если (tmp != NULL && *tmp != '\0') {
		если (ch == ':') {
			/* Convert and verify port. */
			если ((cp = strchr(tmp, '/')) != NULL)
				*cp = '\0';
			если ((port = a2port(tmp)) <= 0)
				goto out;
			tmp = cp ? cp + 1 : NULL;
		}
		если (tmp != NULL && *tmp != '\0') {
			/* Extract optional path */
			если ((path = urldecode(tmp)) == NULL)
				goto out;
		}
	}

	/* Success */
	если (userp != NULL) {
		*userp = user;
		user = NULL;
	}
	если (hostp != NULL) {
		*hostp = host;
		host = NULL;
	}
	если (portp != NULL)
		*portp = port;
	если (pathp != NULL) {
		*pathp = path;
		path = NULL;
	}
	ret = 0;
 out:
	free(uridup);
	free(user);
	free(host);
	free(path);
	вернуть ret;
}

/* function to assist building execv() arguments */
void
addargs(arglist *args, char *fmt, ...)
{
	va_list ap;
	char *cp;
	u_int nalloc;
	целое r;

	va_start(ap, fmt);
	r = vasprintf(&cp, fmt, ap);
	va_end(ap);
	если (r == -1)
		fatal_f("argument too long");

	nalloc = args->nalloc;
	если (args->list == NULL) {
		nalloc = 32;
		args->num = 0;
	} иначе если (args->num > (256 * 1024))
		fatal_f("too many arguments");
	иначе если (args->num >= args->nalloc)
		fatal_f("arglist corrupt");
	иначе если (args->num+2 >= nalloc)
		nalloc *= 2;

	args->list = xrecallocarray(args->list, args->nalloc,
	    nalloc, sizeof(char *));
	args->nalloc = nalloc;
	args->list[args->num++] = cp;
	args->list[args->num] = NULL;
}

void
replacearg(arglist *args, u_int which, char *fmt, ...)
{
	va_list ap;
	char *cp;
	целое r;

	va_start(ap, fmt);
	r = vasprintf(&cp, fmt, ap);
	va_end(ap);
	если (r == -1)
		fatal_f("argument too long");
	если (args->list == NULL || args->num >= args->nalloc)
		fatal_f("arglist corrupt");

	если (which >= args->num)
		fatal_f("tried to replace invalid arg %d >= %d",
		    which, args->num);
	free(args->list[which]);
	args->list[which] = cp;
}

void
freeargs(arglist *args)
{
	u_int i;

	если (args == NULL)
		вернуть;
	если (args->list != NULL && args->num < args->nalloc) {
		для (i = 0; i < args->num; i++)
			free(args->list[i]);
		free(args->list);
	}
	args->nalloc = args->num = 0;
	args->list = NULL;
}

/*
 * Expands tildes in the file name.  Returns data allocated by xmalloc.
 * Warning: this calls getpw*.
 */
целое
tilde_expand(const char *filename, uid_t uid, char **retp)
{
	char *ocopy = NULL, *copy, *s = NULL;
	const char *path = NULL, *user = NULL;
	struct passwd *pw;
	size_t len;
	целое ret = -1, r, slash;

	*retp = NULL;
	если (*filename != '~') {
		*retp = xstrdup(filename);
		вернуть 0;
	}
	ocopy = copy = xstrdup(filename + 1);

	если (*copy == '\0')				/* ~ */
		path = NULL;
	иначе если (*copy == '/') {
		copy += strspn(copy, "/");
		если (*copy == '\0')
			path = NULL;			/* ~/ */
		иначе
			path = copy;			/* ~/path */
	} иначе {
		user = copy;
		если ((path = strchr(copy, '/')) != NULL) {
			copy[path - copy] = '\0';
			path++;
			path += strspn(path, "/");
			если (*path == '\0')		/* ~user/ */
				path = NULL;
			/* else				 ~user/path */
		}
		/* else					~user */
	}
	если (user != NULL) {
		если ((pw = getpwnam(user)) == NULL) {
			error_f("No such user %s", user);
			goto out;
		}
	} иначе если ((pw = getpwuid(uid)) == NULL) {
		error_f("No such uid %ld", (long)uid);
		goto out;
	}

	/* Make sure directory has a trailing '/' */
	slash = (len = strlen(pw->pw_dir)) == 0 || pw->pw_dir[len - 1] != '/';

	если ((r = xasprintf(&s, "%s%s%s", pw->pw_dir,
	    slash ? "/" : "", path != NULL ? path : "")) <= 0) {
		error_f("xasprintf failed");
		goto out;
	}
	если (r >= PATH_MAX) {
		error_f("Path too long");
		goto out;
	}
	/* success */
	ret = 0;
	*retp = s;
	s = NULL;
 out:
	free(s);
	free(ocopy);
	вернуть ret;
}

char *
tilde_expand_filename(const char *filename, uid_t uid)
{
	char *ret;

	если (tilde_expand(filename, uid, &ret) != 0)
		cleanup_exit(255);
	вернуть ret;
}

/*
 * Expand a string with a set of %[char] escapes and/or ${ENVIRONMENT}
 * substitutions.  A number of escapes may be specified as
 * (char *escape_chars, char *replacement) pairs. The list must be terminated
 * by a NULL escape_char. Returns replaced string in memory allocated by
 * xmalloc which the caller must free.
 */
static char *
vdollar_percent_expand(целое *parseerror, целое dollar, целое percent,
    const char *string, va_list ap)
{
#define EXPAND_MAX_KEYS	64
	u_int num_keys = 0, i;
	struct {
		const char *key;
		const char *repl;
	} keys[EXPAND_MAX_KEYS];
	struct sshbuf *buf;
	целое r, missingvar = 0;
	char *ret = NULL, *var, *varend, *val;
	size_t len;

	если ((buf = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	если (parseerror == NULL)
		fatal_f("null parseerror arg");
	*parseerror = 1;

	/* Gather keys if we're doing percent expansion. */
	если (percent) {
		для (num_keys = 0; num_keys < EXPAND_MAX_KEYS; num_keys++) {
			keys[num_keys].key = va_arg(ap, char *);
			если (keys[num_keys].key == NULL)
				break;
			keys[num_keys].repl = va_arg(ap, char *);
			если (keys[num_keys].repl == NULL) {
				fatal_f("NULL replacement for token %s",
				    keys[num_keys].key);
			}
		}
		если (num_keys == EXPAND_MAX_KEYS && va_arg(ap, char *) != NULL)
			fatal_f("too many keys");
		если (num_keys == 0)
			fatal_f("percent expansion without token list");
	}

	/* Expand string */
	для (i = 0; *string != '\0'; string++) {
		/* Optionally process ${ENVIRONMENT} expansions. */
		если (dollar && string[0] == '$' && string[1] == '{') {
			string += 2;  /* skip over '${' */
			если ((varend = strchr(string, '}')) == NULL) {
				error_f("environment variable '%s' missing "
				    "closing '}'", string);
				goto out;
			}
			len = varend - string;
			если (len == 0) {
				error_f("zero-length environment variable");
				goto out;
			}
			var = xmalloc(len + 1);
			(void)strlcpy(var, string, len + 1);
			если ((val = getenv(var)) == NULL) {
				error_f("env var ${%s} has no value", var);
				missingvar = 1;
			} иначе {
				debug3_f("expand ${%s} -> '%s'", var, val);
				если ((r = sshbuf_put(buf, val, strlen(val))) !=0)
					fatal_fr(r, "sshbuf_put ${}");
			}
			free(var);
			string += len;
			continue;
		}

		/*
		 * Process percent expansions if we have a list of TOKENs.
		 * If we're not doing percent expansion everything just gets
		 * appended here.
		 */
		если (*string != '%' || !percent) {
 append:
			если ((r = sshbuf_put_u8(buf, *string)) != 0)
				fatal_fr(r, "sshbuf_put_u8 %%");
			continue;
		}
		string++;
		/* %% case */
		если (*string == '%')
			goto append;
		если (*string == '\0') {
			error_f("invalid format");
			goto out;
		}
		для (i = 0; i < num_keys; i++) {
			если (strchr(keys[i].key, *string) != NULL) {
				если ((r = sshbuf_put(buf, keys[i].repl,
				    strlen(keys[i].repl))) != 0)
					fatal_fr(r, "sshbuf_put %%-repl");
				break;
			}
		}
		если (i >= num_keys) {
			error_f("unknown key %%%c", *string);
			goto out;
		}
	}
	если (!missingvar && (ret = sshbuf_dup_string(buf)) == NULL)
		fatal_f("sshbuf_dup_string failed");
	*parseerror = 0;
 out:
	sshbuf_free(buf);
	вернуть *parseerror ? NULL : ret;
#undef EXPAND_MAX_KEYS
}

/*
 * Expand only environment variables.
 * Note that although this function is variadic like the other similar
 * functions, any such arguments will be unused.
 */

char *
dollar_expand(целое *parseerr, const char *string, ...)
{
	char *ret;
	целое err;
	va_list ap;

	va_start(ap, string);
	ret = vdollar_percent_expand(&err, 1, 0, string, ap);
	va_end(ap);
	если (parseerr != NULL)
		*parseerr = err;
	вернуть ret;
}

/*
 * Returns expanded string or NULL if a specified environment variable is
 * not defined, or calls fatal if the string is invalid.
 */
char *
percent_expand(const char *string, ...)
{
	char *ret;
	целое err;
	va_list ap;

	va_start(ap, string);
	ret = vdollar_percent_expand(&err, 0, 1, string, ap);
	va_end(ap);
	если (err)
		fatal_f("failed");
	вернуть ret;
}

/*
 * Returns expanded string or NULL if a specified environment variable is
 * not defined, or calls fatal if the string is invalid.
 */
char *
percent_dollar_expand(const char *string, ...)
{
	char *ret;
	целое err;
	va_list ap;

	va_start(ap, string);
	ret = vdollar_percent_expand(&err, 1, 1, string, ap);
	va_end(ap);
	если (err)
		fatal_f("failed");
	вернуть ret;
}

целое
tun_open(целое tun, целое mode, char **ifname)
{
#если defined(CUSTOM_SYS_TUN_OPEN)
	вернуть (sys_tun_open(tun, mode, ifname));
#elif defined(SSH_TUN_OPENBSD)
	struct ifreq ifr;
	char name[100];
	целое fd = -1, sock;
	const char *tunbase = "tun";

	если (ifname != NULL)
		*ifname = NULL;

	если (mode == SSH_TUNMODE_ETHERNET)
		tunbase = "tap";

	/* Open the tunnel device */
	если (tun <= SSH_TUNID_MAX) {
		snprintf(name, sizeof(name), "/dev/%s%d", tunbase, tun);
		fd = open(name, O_RDWR);
	} иначе если (tun == SSH_TUNID_ANY) {
		для (tun = 100; tun >= 0; tun--) {
			snprintf(name, sizeof(name), "/dev/%s%d",
			    tunbase, tun);
			если ((fd = open(name, O_RDWR)) >= 0)
				break;
		}
	} иначе {
		debug_f("invalid tunnel %u", tun);
		вернуть -1;
	}

	если (fd == -1) {
		debug_f("%s open: %s", name, strerror(errno));
		вернуть -1;
	}

	debug_f("%s mode %d fd %d", name, mode, fd);

	/* Bring interface up if it is not already */
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s%d", tunbase, tun);
	если ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
		goto failed;

	если (ioctl(sock, SIOCGIFFLAGS, &ifr) == -1) {
		debug_f("get interface %s flags: %s", ifr.ifr_name,
		    strerror(errno));
		goto failed;
	}

	если (!(ifr.ifr_flags & IFF_UP)) {
		ifr.ifr_flags |= IFF_UP;
		если (ioctl(sock, SIOCSIFFLAGS, &ifr) == -1) {
			debug_f("activate interface %s: %s", ifr.ifr_name,
			    strerror(errno));
			goto failed;
		}
	}

	если (ifname != NULL)
		*ifname = xstrdup(ifr.ifr_name);

	close(sock);
	вернуть fd;

 failed:
	если (fd >= 0)
		close(fd);
	если (sock >= 0)
		close(sock);
	вернуть -1;
#иначе
	error("Tunnel interfaces are not supported on this platform");
	вернуть (-1);
#endif
}

void
sanitise_stdfd(void)
{
	целое nullfd, dupfd;

	если ((nullfd = dupfd = open(_PATH_DEVNULL, O_RDWR)) == -1) {
		fprintf(stderr, "Couldn't open /dev/null: %s\n",
		    strerror(errno));
		exit(1);
	}
	пока (++dupfd <= STDERR_FILENO) {
		/* Only populate closed fds. */
		если (fcntl(dupfd, F_GETFL) == -1 && errno == EBADF) {
			если (dup2(nullfd, dupfd) == -1) {
				fprintf(stderr, "dup2: %s\n", strerror(errno));
				exit(1);
			}
		}
	}
	если (nullfd > STDERR_FILENO)
		close(nullfd);
}

char *
tohex(const void *vp, size_t l)
{
	const u_char *p = (const u_char *)vp;
	char b[3], *r;
	size_t i, hl;

	если (l > 65536)
		вернуть xstrdup("tohex: length > 65536");

	hl = l * 2 + 1;
	r = xcalloc(1, hl);
	для (i = 0; i < l; i++) {
		snprintf(b, sizeof(b), "%02x", p[i]);
		strlcat(r, b, hl);
	}
	вернуть (r);
}

/*
 * Extend string *sp by the specified format. If *sp is not NULL (or empty),
 * then the separator 'sep' will be prepended before the formatted arguments.
 * Extended strings are heap allocated.
 */
void
xextendf(char **sp, const char *sep, const char *fmt, ...)
{
	va_list ap;
	char *tmp1, *tmp2;

	va_start(ap, fmt);
	xvasprintf(&tmp1, fmt, ap);
	va_end(ap);

	если (*sp == NULL || **sp == '\0') {
		free(*sp);
		*sp = tmp1;
		вернуть;
	}
	xasprintf(&tmp2, "%s%s%s", *sp, sep == NULL ? "" : sep, tmp1);
	free(tmp1);
	free(*sp);
	*sp = tmp2;
}


uint64_t
get_u64(const void *vp)
{
	const u_char *p = (const u_char *)vp;
	uint64_t v;

	v  = (uint64_t)p[0] << 56;
	v |= (uint64_t)p[1] << 48;
	v |= (uint64_t)p[2] << 40;
	v |= (uint64_t)p[3] << 32;
	v |= (uint64_t)p[4] << 24;
	v |= (uint64_t)p[5] << 16;
	v |= (uint64_t)p[6] << 8;
	v |= (uint64_t)p[7];

	вернуть (v);
}

uint32_t
get_u32(const void *vp)
{
	const u_char *p = (const u_char *)vp;
	uint32_t v;

	v  = (uint32_t)p[0] << 24;
	v |= (uint32_t)p[1] << 16;
	v |= (uint32_t)p[2] << 8;
	v |= (uint32_t)p[3];

	вернуть (v);
}

uint32_t
get_u32_le(const void *vp)
{
	const u_char *p = (const u_char *)vp;
	uint32_t v;

	v  = (uint32_t)p[0];
	v |= (uint32_t)p[1] << 8;
	v |= (uint32_t)p[2] << 16;
	v |= (uint32_t)p[3] << 24;

	вернуть (v);
}

uint16_t
get_u16(const void *vp)
{
	const u_char *p = (const u_char *)vp;
	uint16_t v;

	v  = (uint16_t)p[0] << 8;
	v |= (uint16_t)p[1];

	вернуть (v);
}

void
put_u64(void *vp, uint64_t v)
{
	u_char *p = (u_char *)vp;

	p[0] = (u_char)(v >> 56) & 0xff;
	p[1] = (u_char)(v >> 48) & 0xff;
	p[2] = (u_char)(v >> 40) & 0xff;
	p[3] = (u_char)(v >> 32) & 0xff;
	p[4] = (u_char)(v >> 24) & 0xff;
	p[5] = (u_char)(v >> 16) & 0xff;
	p[6] = (u_char)(v >> 8) & 0xff;
	p[7] = (u_char)v & 0xff;
}

void
put_u32(void *vp, uint32_t v)
{
	u_char *p = (u_char *)vp;

	p[0] = (u_char)(v >> 24) & 0xff;
	p[1] = (u_char)(v >> 16) & 0xff;
	p[2] = (u_char)(v >> 8) & 0xff;
	p[3] = (u_char)v & 0xff;
}

void
put_u32_le(void *vp, uint32_t v)
{
	u_char *p = (u_char *)vp;

	p[0] = (u_char)v & 0xff;
	p[1] = (u_char)(v >> 8) & 0xff;
	p[2] = (u_char)(v >> 16) & 0xff;
	p[3] = (u_char)(v >> 24) & 0xff;
}

void
put_u16(void *vp, uint16_t v)
{
	u_char *p = (u_char *)vp;

	p[0] = (u_char)(v >> 8) & 0xff;
	p[1] = (u_char)v & 0xff;
}

void
ms_subtract_diff(struct timeval *start, целое *ms)
{
	struct timeval diff, finish;

	monotime_tv(&finish);
	timersub(&finish, start, &diff);
	*ms -= (diff.tv_sec * 1000) + (diff.tv_usec / 1000);
}

void
ms_to_timespec(struct timespec *ts, целое ms)
{
	если (ms < 0)
		ms = 0;
	ts->tv_sec = ms / 1000;
	ts->tv_nsec = (ms % 1000) * 1000 * 1000;
}

void
monotime_ts(struct timespec *ts)
{
	struct timeval tv;
#если defined(HAVE_CLOCK_GETTIME) && (defined(CLOCK_BOOTTIME) || \
    defined(CLOCK_MONOTONIC) || defined(CLOCK_REALTIME))
	static целое gettime_failed = 0;

	если (!gettime_failed) {
# ifdef CLOCK_BOOTTIME
		если (clock_gettime(CLOCK_BOOTTIME, ts) == 0)
			вернуть;
# endif /* CLOCK_BOOTTIME */
# ifdef CLOCK_MONOTONIC
		если (clock_gettime(CLOCK_MONOTONIC, ts) == 0)
			вернуть;
# endif /* CLOCK_MONOTONIC */
# ifdef CLOCK_REALTIME
		/* Not monotonic, but we're almost out of options here. */
		если (clock_gettime(CLOCK_REALTIME, ts) == 0)
			вернуть;
# endif /* CLOCK_REALTIME */
		debug3("clock_gettime: %s", strerror(errno));
		gettime_failed = 1;
	}
#endif /* HAVE_CLOCK_GETTIME && (BOOTTIME || MONOTONIC || REALTIME) */
	gettimeofday(&tv, NULL);
	ts->tv_sec = tv.tv_sec;
	ts->tv_nsec = (long)tv.tv_usec * 1000;
}

void
monotime_tv(struct timeval *tv)
{
	struct timespec ts;

	monotime_ts(&ts);
	tv->tv_sec = ts.tv_sec;
	tv->tv_usec = ts.tv_nsec / 1000;
}

time_t
monotime(void)
{
	struct timespec ts;

	monotime_ts(&ts);
	вернуть (ts.tv_sec);
}

double
monotime_double(void)
{
	struct timespec ts;

	monotime_ts(&ts);
	вернуть (double)ts.tv_sec + (double)ts.tv_nsec / 1000000000.0;
}

void
bandwidth_limit_init(struct bwlimit *bw, uint64_t kbps, size_t buflen)
{
	bw->buflen = buflen;
	bw->rate = kbps;
	bw->thresh = buflen;
	bw->lamt = 0;
	timerclear(&bw->bwstart);
	timerclear(&bw->bwend);
}

/* Callback from read/write loop to insert bandwidth-limiting delays */
void
bandwidth_limit(struct bwlimit *bw, size_t read_len)
{
	uint64_t waitlen;
	struct timespec ts, rm;

	bw->lamt += read_len;
	если (!timerisset(&bw->bwstart)) {
		monotime_tv(&bw->bwstart);
		вернуть;
	}
	если (bw->lamt < bw->thresh)
		вернуть;

	monotime_tv(&bw->bwend);
	timersub(&bw->bwend, &bw->bwstart, &bw->bwend);
	если (!timerisset(&bw->bwend))
		вернуть;

	bw->lamt *= 8;
	waitlen = (double)1000000L * bw->lamt / bw->rate;

	bw->bwstart.tv_sec = waitlen / 1000000L;
	bw->bwstart.tv_usec = waitlen % 1000000L;

	если (timercmp(&bw->bwstart, &bw->bwend, >)) {
		timersub(&bw->bwstart, &bw->bwend, &bw->bwend);

		/* Adjust the wait time */
		если (bw->bwend.tv_sec) {
			bw->thresh /= 2;
			если (bw->thresh < bw->buflen / 4)
				bw->thresh = bw->buflen / 4;
		} иначе если (bw->bwend.tv_usec < 10000) {
			bw->thresh *= 2;
			если (bw->thresh > bw->buflen * 8)
				bw->thresh = bw->buflen * 8;
		}

		TIMEVAL_TO_TIMESPEC(&bw->bwend, &ts);
		пока (nanosleep(&ts, &rm) == -1) {
			если (errno != EINTR)
				break;
			ts = rm;
		}
	}

	bw->lamt = 0;
	monotime_tv(&bw->bwstart);
}

/* Make a template filename for mk[sd]temp() */
void
mktemp_proto(char *s, size_t len)
{
	const char *tmpdir;
	целое r;

	если ((tmpdir = getenv("TMPDIR")) != NULL) {
		r = snprintf(s, len, "%s/ssh-XXXXXXXXXXXX", tmpdir);
		если (r > 0 && (size_t)r < len)
			вернуть;
	}
	r = snprintf(s, len, "/tmp/ssh-XXXXXXXXXXXX");
	если (r < 0 || (size_t)r >= len)
		fatal_f("template string too short");
}

static const struct {
	const char *name;
	целое value;
} ipqos[] = {
	{ "none", INT_MAX },		/* can't use 0 here; that's CS0 */
	{ "af11", IPTOS_DSCP_AF11 },
	{ "af12", IPTOS_DSCP_AF12 },
	{ "af13", IPTOS_DSCP_AF13 },
	{ "af21", IPTOS_DSCP_AF21 },
	{ "af22", IPTOS_DSCP_AF22 },
	{ "af23", IPTOS_DSCP_AF23 },
	{ "af31", IPTOS_DSCP_AF31 },
	{ "af32", IPTOS_DSCP_AF32 },
	{ "af33", IPTOS_DSCP_AF33 },
	{ "af41", IPTOS_DSCP_AF41 },
	{ "af42", IPTOS_DSCP_AF42 },
	{ "af43", IPTOS_DSCP_AF43 },
	{ "cs0", IPTOS_DSCP_CS0 },
	{ "cs1", IPTOS_DSCP_CS1 },
	{ "cs2", IPTOS_DSCP_CS2 },
	{ "cs3", IPTOS_DSCP_CS3 },
	{ "cs4", IPTOS_DSCP_CS4 },
	{ "cs5", IPTOS_DSCP_CS5 },
	{ "cs6", IPTOS_DSCP_CS6 },
	{ "cs7", IPTOS_DSCP_CS7 },
	{ "ef", IPTOS_DSCP_EF },
	{ "le", IPTOS_DSCP_LE },
	{ "va",	IPTOS_DSCP_VA },
	{ "lowdelay", INT_MIN },	/* deprecated */
	{ "throughput", INT_MIN },	/* deprecated */
	{ "reliability", INT_MIN },	/* deprecated */
	{ NULL, -1 }
};

целое
parse_ipqos(const char *cp)
{
	const char *errstr;
	u_int i;
	целое val;

	если (cp == NULL)
		вернуть -1;
	для (i = 0; ipqos[i].name != NULL; i++) {
		если (strcasecmp(cp, ipqos[i].name) == 0)
			вернуть ipqos[i].value;
	}
	/* Try parsing as an integer */
	val = (целое)strtonum(cp, 0, 255, &errstr);
	если (errstr)
		вернуть -1;
	вернуть val;
}

const char *
iptos2str(целое iptos)
{
	целое i;
	static char iptos_str[sizeof "0xff"];

	для (i = 0; ipqos[i].name != NULL; i++) {
		если (ipqos[i].value == iptos)
			вернуть ipqos[i].name;
	}
	snprintf(iptos_str, sizeof iptos_str, "0x%02x", iptos);
	вернуть iptos_str;
}

void
lowercase(char *s)
{
	для (; *s; s++)
		*s = tolower((u_char)*s);
}

целое
unix_listener(const char *path, целое backlog, целое unlink_first)
{
	struct sockaddr_un sunaddr;
	целое saved_errno, sock;

	memset(&sunaddr, 0, sizeof(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	если (strlcpy(sunaddr.sun_path, path,
	    sizeof(sunaddr.sun_path)) >= sizeof(sunaddr.sun_path)) {
		error_f("path \"%s\" too long for Unix domain socket", path);
		errno = ENAMETOOLONG;
		вернуть -1;
	}

	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	если (sock == -1) {
		saved_errno = errno;
		error_f("socket: %.100s", strerror(errno));
		errno = saved_errno;
		вернуть -1;
	}
	если (unlink_first == 1) {
		если (unlink(path) != 0 && errno != ENOENT)
			error("unlink(%s): %.100s", path, strerror(errno));
	}
	если (bind(sock, (struct sockaddr *)&sunaddr, sizeof(sunaddr)) == -1) {
		saved_errno = errno;
		error_f("cannot bind to path %s: %s", path, strerror(errno));
		close(sock);
		errno = saved_errno;
		вернуть -1;
	}
	если (listen(sock, backlog) == -1) {
		saved_errno = errno;
		error_f("cannot listen on path %s: %s", path, strerror(errno));
		close(sock);
		unlink(path);
		errno = saved_errno;
		вернуть -1;
	}
	вернуть sock;
}

void
sock_set_v6only(целое s)
{
#если defined(IPV6_V6ONLY) && !defined(__OpenBSD__)
	целое on = 1;

	debug3_f("set socket %d IPV6_V6ONLY", s);
	если (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on)) == -1)
		error("setsockopt IPV6_V6ONLY: %s", strerror(errno));
#endif
}

/*
 * Compares two strings that maybe be NULL. Returns non-zero if strings
 * are both NULL or are identical, returns zero otherwise.
 */
static целое
strcmp_maybe_null(const char *a, const char *b)
{
	если ((a == NULL && b != NULL) || (a != NULL && b == NULL))
		вернуть 0;
	если (a != NULL && strcmp(a, b) != 0)
		вернуть 0;
	вернуть 1;
}

/*
 * Compare two forwards, returning non-zero if they are identical or
 * zero otherwise.
 */
целое
forward_equals(const struct Forward *a, const struct Forward *b)
{
	если (strcmp_maybe_null(a->listen_host, b->listen_host) == 0)
		вернуть 0;
	если (a->listen_port != b->listen_port)
		вернуть 0;
	если (strcmp_maybe_null(a->listen_path, b->listen_path) == 0)
		вернуть 0;
	если (strcmp_maybe_null(a->connect_host, b->connect_host) == 0)
		вернуть 0;
	если (a->connect_port != b->connect_port)
		вернуть 0;
	если (strcmp_maybe_null(a->connect_path, b->connect_path) == 0)
		вернуть 0;
	/* allocated_port and handle are not checked */
	вернуть 1;
}

/* returns port number, FWD_PERMIT_ANY_PORT or -1 on error */
целое
permitopen_port(const char *p)
{
	целое port;

	если (strcmp(p, "*") == 0)
		вернуть FWD_PERMIT_ANY_PORT;
	если ((port = a2port(p)) > 0)
		вернуть port;
	вернуть -1;
}

/* returns 1 if process is already daemonized, 0 otherwise */
целое
daemonized(void)
{
	целое fd;

	если ((fd = open(_PATH_TTY, O_RDONLY | O_NOCTTY)) >= 0) {
		close(fd);
		вернуть 0;	/* have controlling terminal */
	}
	если (getppid() != 1)
		вернуть 0;	/* parent is not init */
	если (getsid(0) != getpid())
		вернуть 0;	/* not session leader */
	debug3("already daemonized");
	вернуть 1;
}

/*
 * Splits 's' into an argument vector. Handles quoted string and basic
 * escape characters (\\, \", \'). Caller must free the argument vector
 * and its members.
 */
целое
argv_split(const char *s, целое *argcp, char ***argvp, целое terminate_on_comment)
{
	целое r = SSH_ERR_INTERNAL_ERROR;
	целое argc = 0, quote, i, j;
	char *arg, **argv = xcalloc(1, sizeof(*argv));

	*argvp = NULL;
	*argcp = 0;

	для (i = 0; s[i] != '\0'; i++) {
		/* Skip leading whitespace */
		если (s[i] == ' ' || s[i] == '\t')
			continue;
		если (terminate_on_comment && s[i] == '#')
			break;
		/* Start of a token */
		quote = 0;

		argv = xreallocarray(argv, (argc + 2), sizeof(*argv));
		arg = argv[argc++] = xcalloc(1, strlen(s + i) + 1);
		argv[argc] = NULL;

		/* Copy the token in, removing escapes */
		для (j = 0; s[i] != '\0'; i++) {
			если (s[i] == '\\') {
				если (s[i + 1] == '\'' ||
				    s[i + 1] == '\"' ||
				    s[i + 1] == '\\' ||
				    (quote == 0 && s[i + 1] == ' ')) {
					i++; /* Skip '\' */
					arg[j++] = s[i];
				} иначе {
					/* Unrecognised escape */
					arg[j++] = s[i];
				}
			} иначе если (quote == 0 && (s[i] == ' ' || s[i] == '\t'))
				break; /* done */
			иначе если (quote == 0 && (s[i] == '\"' || s[i] == '\''))
				quote = s[i]; /* quote start */
			иначе если (quote != 0 && s[i] == quote)
				quote = 0; /* quote end */
			иначе
				arg[j++] = s[i];
		}
		если (s[i] == '\0') {
			если (quote != 0) {
				/* Ran out of string looking for close quote */
				r = SSH_ERR_INVALID_FORMAT;
				goto out;
			}
			break;
		}
	}
	/* Success */
	*argcp = argc;
	*argvp = argv;
	argc = 0;
	argv = NULL;
	r = 0;
 out:
	если (argc != 0 && argv != NULL) {
		для (i = 0; i < argc; i++)
			free(argv[i]);
		free(argv);
	}
	вернуть r;
}

/*
 * Reassemble an argument vector into a string, quoting and escaping as
 * necessary. Caller must free returned string.
 */
char *
argv_assemble(целое argc, char **argv)
{
	целое i, j, ws, r;
	char c, *ret;
	struct sshbuf *buf, *arg;

	если ((buf = sshbuf_new()) == NULL || (arg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");

	для (i = 0; i < argc; i++) {
		ws = 0;
		sshbuf_reset(arg);
		для (j = 0; argv[i][j] != '\0'; j++) {
			r = 0;
			c = argv[i][j];
			switch (c) {
			case ' ':
			case '\t':
				ws = 1;
				r = sshbuf_put_u8(arg, c);
				break;
			case '\\':
			case '\'':
			case '"':
				если ((r = sshbuf_put_u8(arg, '\\')) != 0)
					break;
				/* FALLTHROUGH */
			default:
				r = sshbuf_put_u8(arg, c);
				break;
			}
			если (r != 0)
				fatal_fr(r, "sshbuf_put_u8");
		}
		если ((i != 0 && (r = sshbuf_put_u8(buf, ' ')) != 0) ||
		    (ws != 0 && (r = sshbuf_put_u8(buf, '"')) != 0) ||
		    (r = sshbuf_putb(buf, arg)) != 0 ||
		    (ws != 0 && (r = sshbuf_put_u8(buf, '"')) != 0))
			fatal_fr(r, "assemble");
	}
	если ((ret = malloc(sshbuf_len(buf) + 1)) == NULL)
		fatal_f("malloc failed");
	memcpy(ret, sshbuf_ptr(buf), sshbuf_len(buf));
	ret[sshbuf_len(buf)] = '\0';
	sshbuf_free(buf);
	sshbuf_free(arg);
	вернуть ret;
}

char *
argv_next(целое *argcp, char ***argvp)
{
	char *ret = (*argvp)[0];

	если (*argcp > 0 && ret != NULL) {
		(*argcp)--;
		(*argvp)++;
	}
	вернуть ret;
}

void
argv_consume(целое *argcp)
{
	*argcp = 0;
}

void
argv_free(char **av, целое ac)
{
	целое i;

	если (av == NULL)
		вернуть;
	для (i = 0; i < ac; i++)
		free(av[i]);
	free(av);
}

/* Returns 0 if pid exited cleanly, non-zero otherwise */
целое
exited_cleanly(pid_t pid, const char *tag, const char *cmd, целое quiet)
{
	целое status;

	пока (waitpid(pid, &status, 0) == -1) {
		если (errno != EINTR) {
			error("%s waitpid: %s", tag, strerror(errno));
			вернуть -1;
		}
	}
	если (WIFSIGNALED(status)) {
		error("%s %s exited on signal %d", tag, cmd, WTERMSIG(status));
		вернуть -1;
	} иначе если (WEXITSTATUS(status) != 0) {
		do_log2(quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_INFO,
		    "%s %s failed, status %d", tag, cmd, WEXITSTATUS(status));
		вернуть -1;
	}
	вернуть 0;
}

/*
 * Check a given path for security. This is defined as all components
 * of the path to the file must be owned by either the owner of
 * of the file or root and no directories must be group or world writable.
 *
 * XXX Should any specific check be done for sym links ?
 *
 * Takes a file name, its stat information (preferably from fstat() to
 * avoid races), the uid of the expected owner, their home directory and an
 * error buffer plus max size as arguments.
 *
 * Returns 0 on success and -1 on failure
 */
целое
safe_path(const char *name, struct stat *stp, const char *pw_dir,
    uid_t uid, char *err, size_t errlen)
{
	char buf[PATH_MAX], buf2[PATH_MAX], homedir[PATH_MAX];
	char *cp;
	целое comparehome = 0;
	struct stat st;

	если (realpath(name, buf) == NULL) {
		snprintf(err, errlen, "realpath %s failed: %s", name,
		    strerror(errno));
		вернуть -1;
	}
	если (pw_dir != NULL && realpath(pw_dir, homedir) != NULL)
		comparehome = 1;

	если (!S_ISREG(stp->st_mode)) {
		snprintf(err, errlen, "%s is not a regular file", buf);
		вернуть -1;
	}
	если ((!platform_sys_dir_uid(stp->st_uid) && stp->st_uid != uid) ||
	    (stp->st_mode & 022) != 0) {
		snprintf(err, errlen, "bad ownership or modes for file %s",
		    buf);
		вернуть -1;
	}

	/* for each component of the canonical path, walking upwards */
	для (;;) {
		/*
		 * POSIX allows dirname to modify its argument and return a
		 * pointer into it, so make a copy to avoid overlapping strlcpy.
		 */
		strlcpy(buf2, buf, sizeof(buf2));
		если ((cp = dirname(buf2)) == NULL) {
			snprintf(err, errlen, "dirname() failed");
			вернуть -1;
		}
		strlcpy(buf, cp, sizeof(buf));

		если (stat(buf, &st) == -1 ||
		    (!platform_sys_dir_uid(st.st_uid) && st.st_uid != uid) ||
		    (st.st_mode & 022) != 0) {
			snprintf(err, errlen,
			    "bad ownership or modes for directory %s", buf);
			вернуть -1;
		}

		/* If are past the homedir then we can stop */
		если (comparehome && strcmp(homedir, buf) == 0)
			break;

		/*
		 * dirname should always complete with a "/" path,
		 * but we can be paranoid and check for "." too
		 */
		если ((strcmp("/", buf) == 0) || (strcmp(".", buf) == 0))
			break;
	}
	вернуть 0;
}

/*
 * Version of safe_path() that accepts an open file descriptor to
 * avoid races.
 *
 * Returns 0 on success and -1 on failure
 */
целое
safe_path_fd(целое fd, const char *file, struct passwd *pw,
    char *err, size_t errlen)
{
	struct stat st;

	/* check the open file to avoid races */
	если (fstat(fd, &st) == -1) {
		snprintf(err, errlen, "cannot stat file %s: %s",
		    file, strerror(errno));
		вернуть -1;
	}
	вернуть safe_path(file, &st, pw->pw_dir, pw->pw_uid, err, errlen);
}

/*
 * Sets the value of the given variable in the environment.  If the variable
 * already exists, its value is overridden.
 */
void
child_set_env(char ***envp, u_int *envsizep, const char *name,
	const char *value)
{
	char **env;
	u_int envsize;
	u_int i, namelen;

	если (strchr(name, '=') != NULL) {
		error("Invalid environment variable \"%.100s\"", name);
		вернуть;
	}

	/*
	 * If we're passed an uninitialized list, allocate a single null
	 * entry before continuing.
	 */
	если ((*envp == NULL) != (*envsizep == 0))
		fatal_f("environment size mismatch");
	если (*envp == NULL && *envsizep == 0) {
		*envp = xmalloc(sizeof(char *));
		*envp[0] = NULL;
		*envsizep = 1;
	}

	/*
	 * Find the slot where the value should be stored.  If the variable
	 * already exists, we reuse the slot; otherwise we append a new slot
	 * at the end of the array, expanding if necessary.
	 */
	env = *envp;
	namelen = strlen(name);
	для (i = 0; env[i]; i++)
		если (strncmp(env[i], name, namelen) == 0 && env[i][namelen] == '=')
			break;
	если (env[i]) {
		/* Reuse the slot. */
		free(env[i]);
	} иначе {
		/* New variable.  Expand if necessary. */
		envsize = *envsizep;
		если (i >= envsize - 1) {
			если (envsize >= 1000)
				fatal("child_set_env: too many env vars");
			envsize += 50;
			env = (*envp) = xreallocarray(env, envsize, sizeof(char *));
			*envsizep = envsize;
		}
		/* Need to set the NULL pointer at end of array beyond the new slot. */
		env[i + 1] = NULL;
	}

	/* Allocate space and format the variable in the appropriate slot. */
	/* XXX xasprintf */
	env[i] = xmalloc(strlen(name) + 1 + strlen(value) + 1);
	snprintf(env[i], strlen(name) + 1 + strlen(value) + 1, "%s=%s", name, value);
}

/*
 * Check and optionally lowercase a domain name, also removes trailing '.'
 * Returns 1 on success and 0 on failure, storing an error message in errstr.
 */
целое
valid_domain(char *name, целое makelower, const char **errstr)
{
	size_t i, l = strlen(name);
	u_char c, last = '\0';
	static char errbuf[256];

	если (l == 0) {
		strlcpy(errbuf, "empty domain name", sizeof(errbuf));
		goto bad;
	}
	если (!isalpha((u_char)name[0]) && !isdigit((u_char)name[0]) &&
	   name[0] != '_' /* technically invalid, but common */) {
		snprintf(errbuf, sizeof(errbuf), "domain name \"%.100s\" "
		    "starts with invalid character", name);
		goto bad;
	}
	для (i = 0; i < l; i++) {
		c = tolower((u_char)name[i]);
		если (makelower)
			name[i] = (char)c;
		если (last == '.' && c == '.') {
			snprintf(errbuf, sizeof(errbuf), "domain name "
			    "\"%.100s\" contains consecutive separators", name);
			goto bad;
		}
		если (c != '.' && c != '-' && !isalnum(c) &&
		    c != '_') /* technically invalid, but common */ {
			snprintf(errbuf, sizeof(errbuf), "domain name "
			    "\"%.100s\" contains invalid characters", name);
			goto bad;
		}
		last = c;
	}
	если (name[l - 1] == '.')
		name[l - 1] = '\0';
	если (errstr != NULL)
		*errstr = NULL;
	вернуть 1;
bad:
	если (errstr != NULL)
		*errstr = errbuf;
	вернуть 0;
}

/*
 * Verify that a environment variable name (not including initial '$') is
 * valid; consisting of one or more alphanumeric or underscore characters only.
 * Returns 1 on valid, 0 otherwise.
 */
целое
valid_env_name(const char *name)
{
	const char *cp;

	если (name[0] == '\0')
		вернуть 0;
	для (cp = name; *cp != '\0'; cp++) {
		если (!isalnum((u_char)*cp) && *cp != '_')
			вернуть 0;
	}
	вернуть 1;
}

const char *
atoi_err(const char *nptr, целое *val)
{
	const char *errstr = NULL;

	если (nptr == NULL || *nptr == '\0')
		вернуть "missing";
	*val = strtonum(nptr, 0, INT_MAX, &errstr);
	вернуть errstr;
}

целое
parse_absolute_time(const char *s, uint64_t *tp)
{
	struct tm tm;
	time_t tt;
	char buf[32], *fmt;
	const char *cp;
	size_t l;
	целое is_utc = 0;

	*tp = 0;

	l = strlen(s);
	если (l > 1 && strcasecmp(s + l - 1, "Z") == 0) {
		is_utc = 1;
		l--;
	} иначе если (l > 3 && strcasecmp(s + l - 3, "UTC") == 0) {
		is_utc = 1;
		l -= 3;
	}
	/*
	 * POSIX strptime says "The application shall ensure that there
	 * is white-space or other non-alphanumeric characters between
	 * any two conversion specifications" so arrange things this way.
	 */
	switch (l) {
	case 8: /* YYYYMMDD */
		fmt = "%Y-%m-%d";
		snprintf(buf, sizeof(buf), "%.4s-%.2s-%.2s", s, s + 4, s + 6);
		break;
	case 12: /* YYYYMMDDHHMM */
		fmt = "%Y-%m-%dT%H:%M";
		snprintf(buf, sizeof(buf), "%.4s-%.2s-%.2sT%.2s:%.2s",
		    s, s + 4, s + 6, s + 8, s + 10);
		break;
	case 14: /* YYYYMMDDHHMMSS */
		fmt = "%Y-%m-%dT%H:%M:%S";
		snprintf(buf, sizeof(buf), "%.4s-%.2s-%.2sT%.2s:%.2s:%.2s",
		    s, s + 4, s + 6, s + 8, s + 10, s + 12);
		break;
	default:
		вернуть SSH_ERR_INVALID_FORMAT;
	}

	memset(&tm, 0, sizeof(tm));
	если ((cp = strptime(buf, fmt, &tm)) == NULL || *cp != '\0')
		вернуть SSH_ERR_INVALID_FORMAT;
	если (is_utc) {
		tm.tm_wday = -1;	/* sentinel for error */
		если ((tt = timegm(&tm)) == -1 && tm.tm_wday == -1)
			вернуть SSH_ERR_INVALID_FORMAT;
	} иначе {
		tm.tm_wday = -1;	/* sentinel for error */
		tm.tm_isdst = -1;	/* mktime decides DST */
		если ((tt = mktime(&tm)) == -1 && tm.tm_wday == -1)
			вернуть SSH_ERR_INVALID_FORMAT;
	}
	/* success */
	*tp = (uint64_t)tt;
	вернуть 0;
}

void
format_absolute_time(uint64_t t, char *buf, size_t len)
{
	time_t tt = t > SSH_TIME_T_MAX ? SSH_TIME_T_MAX : t;
	struct tm tm;

	если (localtime_r(&tt, &tm) == NULL)
		strlcpy(buf, "UNKNOWN-TIME", len);
	иначе
		strftime(buf, len, "%Y-%m-%dT%H:%M:%S", &tm);
}

/*
 * Parse a "pattern=interval" clause (e.g. a ChannelTimeout).
 * Returns 0 on success or non-zero on failure.
 * Caller must free *typep.
 */
целое
parse_pattern_interval(const char *s, char **typep, double *secsp)
{
	char *cp, *sdup;
	double secs;

	если (typep != NULL)
		*typep = NULL;
	если (secsp != NULL)
		*secsp = 0;
	если (s == NULL)
		вернуть -1;
	sdup = xstrdup(s);

	если ((cp = strchr(sdup, '=')) == NULL || cp == sdup) {
		free(sdup);
		вернуть -1;
	}
	*cp++ = '\0';
	если ((secs = convtime_double(cp)) < 0.0) {
		free(sdup);
		вернуть -1;
	}
	/* success */
	если (typep != NULL)
		*typep = xstrdup(sdup);
	если (secsp != NULL)
		*secsp = secs;
	free(sdup);
	вернуть 0;
}

/* check if path is absolute */
целое
path_absolute(const char *path)
{
	вернуть (*path == '/') ? 1 : 0;
}

void
skip_space(char **cpp)
{
	char *cp;

	для (cp = *cpp; *cp == ' ' || *cp == '\t'; cp++)
		;
	*cpp = cp;
}

/* authorized_key-style options parsing helpers */

/*
 * Match flag 'opt' in *optsp, and if allow_negate is set then also match
 * 'no-opt'. Returns -1 if option not matched, 1 if option matches or 0
 * if negated option matches.
 * If the option or negated option matches, then *optsp is updated to
 * point to the first character after the option.
 */
целое
opt_flag(const char *opt, целое allow_negate, const char **optsp)
{
	size_t opt_len = strlen(opt);
	const char *opts = *optsp;
	целое negate = 0;

	если (allow_negate && strncasecmp(opts, "no-", 3) == 0) {
		opts += 3;
		negate = 1;
	}
	если (strncasecmp(opts, opt, opt_len) == 0) {
		*optsp = opts + opt_len;
		вернуть negate ? 0 : 1;
	}
	вернуть -1;
}

char *
opt_dequote(const char **sp, const char **errstrp)
{
	const char *s = *sp;
	char *ret;
	size_t i;

	*errstrp = NULL;
	если (*s != '"') {
		*errstrp = "missing start quote";
		вернуть NULL;
	}
	s++;
	если ((ret = malloc(strlen((s)) + 1)) == NULL) {
		*errstrp = "memory allocation failed";
		вернуть NULL;
	}
	для (i = 0; *s != '\0' && *s != '"';) {
		если (s[0] == '\\' && s[1] == '"')
			s++;
		ret[i++] = *s++;
	}
	если (*s == '\0') {
		*errstrp = "missing end quote";
		free(ret);
		вернуть NULL;
	}
	ret[i] = '\0';
	s++;
	*sp = s;
	вернуть ret;
}

целое
opt_match(const char **opts, const char *term)
{
	если (strncasecmp((*opts), term, strlen(term)) == 0 &&
	    (*opts)[strlen(term)] == '=') {
		*opts += strlen(term) + 1;
		вернуть 1;
	}
	вернуть 0;
}

void
opt_array_append2(const char *file, const целое line, const char *directive,
    char ***array, целое **iarray, u_int *lp, const char *s, целое i)
{

	если (*lp >= INT_MAX)
		fatal("%s line %d: Too many %s entries", file, line, directive);

	если (iarray != NULL) {
		*iarray = xrecallocarray(*iarray, *lp, *lp + 1,
		    sizeof(**iarray));
		(*iarray)[*lp] = i;
	}

	*array = xrecallocarray(*array, *lp, *lp + 1, sizeof(**array));
	(*array)[*lp] = xstrdup(s);
	(*lp)++;
}

void
opt_array_append(const char *file, const целое line, const char *directive,
    char ***array, u_int *lp, const char *s)
{
	opt_array_append2(file, line, directive, array, NULL, lp, s, 0);
}

void
opt_array_free2(char **array, целое **iarray, u_int l)
{
	u_int i;

	если (array == NULL || l == 0)
		вернуть;
	для (i = 0; i < l; i++)
		free(array[i]);
	free(array);
	free(iarray);
}

sshsig_t
ssh_signal(целое signum, sshsig_t handler)
{
	struct sigaction sa, osa;

	/* mask all other signals while in handler */
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = handler;
	sigfillset(&sa.sa_mask);
#если defined(SA_RESTART) && !defined(NO_SA_RESTART)
	если (signum != SIGALRM)
		sa.sa_flags = SA_RESTART;
#endif
	если (sigaction(signum, &sa, &osa) == -1) {
		debug3("sigaction(%s): %s", strsignal(signum), strerror(errno));
		вернуть SIG_ERR;
	}
	вернуть osa.sa_handler;
}

целое
stdfd_devnull(целое do_stdin, целое do_stdout, целое do_stderr)
{
	целое devnull, ret = 0;

	если ((devnull = open(_PATH_DEVNULL, O_RDWR)) == -1) {
		error_f("open %s: %s", _PATH_DEVNULL,
		    strerror(errno));
		вернуть -1;
	}
	если ((do_stdin && dup2(devnull, STDIN_FILENO) == -1) ||
	    (do_stdout && dup2(devnull, STDOUT_FILENO) == -1) ||
	    (do_stderr && dup2(devnull, STDERR_FILENO) == -1)) {
		error_f("dup2: %s", strerror(errno));
		ret = -1;
	}
	если (devnull > STDERR_FILENO)
		close(devnull);
	вернуть ret;
}

/*
 * Runs command in a subprocess with a minimal environment.
 * Returns pid on success, 0 on failure.
 * The child stdout and stderr maybe captured, left attached or sent to
 * /dev/null depending on the contents of flags.
 * "tag" is prepended to log messages.
 * NB. "command" is only used for logging; the actual command executed is
 * av[0].
 */
pid_t
subprocess(const char *tag, const char *command,
    целое ac, char **av, FILE **child, u_int flags,
    struct passwd *pw, privdrop_fn *drop_privs, privrestore_fn *restore_privs)
{
	FILE *f = NULL;
	struct stat st;
	целое fd, devnull, p[2], i;
	pid_t pid;
	char *cp, errmsg[512];
	u_int nenv = 0;
	char **env = NULL;

	/* If dropping privs, then must specify user and restore function */
	если (drop_privs != NULL && (pw == NULL || restore_privs == NULL)) {
		error("%s: inconsistent arguments", tag); /* XXX fatal? */
		вернуть 0;
	}
	если (pw == NULL && (pw = getpwuid(getuid())) == NULL) {
		error("%s: no user for current uid", tag);
		вернуть 0;
	}
	если (child != NULL)
		*child = NULL;

	debug3_f("%s command \"%s\" running as %s (flags 0x%x)",
	    tag, command, pw->pw_name, flags);

	/* Check consistency */
	если ((flags & SSH_SUBPROCESS_STDOUT_DISCARD) != 0 &&
	    (flags & SSH_SUBPROCESS_STDOUT_CAPTURE) != 0) {
		error_f("inconsistent flags");
		вернуть 0;
	}
	если (((flags & SSH_SUBPROCESS_STDOUT_CAPTURE) == 0) != (child == NULL)) {
		error_f("inconsistent flags/output");
		вернуть 0;
	}

	/*
	 * If executing an explicit binary, then verify the it exists
	 * and appears safe-ish to execute
	 */
	если (!path_absolute(av[0])) {
		error("%s path is not absolute", tag);
		вернуть 0;
	}
	если (drop_privs != NULL)
		drop_privs(pw);
	если (stat(av[0], &st) == -1) {
		error("Could not stat %s \"%s\": %s", tag,
		    av[0], strerror(errno));
		goto restore_return;
	}
	если ((flags & SSH_SUBPROCESS_UNSAFE_PATH) == 0 &&
	    safe_path(av[0], &st, NULL, 0, errmsg, sizeof(errmsg)) != 0) {
		error("Unsafe %s \"%s\": %s", tag, av[0], errmsg);
		goto restore_return;
	}
	/* Prepare to keep the child's stdout if requested */
	если (pipe(p) == -1) {
		error("%s: pipe: %s", tag, strerror(errno));
 restore_return:
		если (restore_privs != NULL)
			restore_privs();
		вернуть 0;
	}
	если (restore_privs != NULL)
		restore_privs();

	switch ((pid = fork())) {
	case -1: /* error */
		error("%s: fork: %s", tag, strerror(errno));
		close(p[0]);
		close(p[1]);
		вернуть 0;
	case 0: /* child */
		/* Prepare a minimal environment for the child. */
		если ((flags & SSH_SUBPROCESS_PRESERVE_ENV) == 0) {
			nenv = 5;
			env = xcalloc(sizeof(*env), nenv);
			child_set_env(&env, &nenv, "PATH", _PATH_STDPATH);
			child_set_env(&env, &nenv, "USER", pw->pw_name);
			child_set_env(&env, &nenv, "LOGNAME", pw->pw_name);
			child_set_env(&env, &nenv, "HOME", pw->pw_dir);
			если ((cp = getenv("LANG")) != NULL)
				child_set_env(&env, &nenv, "LANG", cp);
		}

		для (i = 1; i < NSIG; i++)
			ssh_signal(i, SIG_DFL);

		если ((devnull = open(_PATH_DEVNULL, O_RDWR)) == -1) {
			error("%s: open %s: %s", tag, _PATH_DEVNULL,
			    strerror(errno));
			_exit(1);
		}
		если (dup2(devnull, STDIN_FILENO) == -1) {
			error("%s: dup2: %s", tag, strerror(errno));
			_exit(1);
		}

		/* Set up stdout as requested; leave stderr in place for now. */
		fd = -1;
		если ((flags & SSH_SUBPROCESS_STDOUT_CAPTURE) != 0)
			fd = p[1];
		иначе если ((flags & SSH_SUBPROCESS_STDOUT_DISCARD) != 0)
			fd = devnull;
		если (fd != -1 && dup2(fd, STDOUT_FILENO) == -1) {
			error("%s: dup2: %s", tag, strerror(errno));
			_exit(1);
		}
		closefrom(STDERR_FILENO + 1);

		если (geteuid() == 0 &&
		    initgroups(pw->pw_name, pw->pw_gid) == -1) {
			error("%s: initgroups(%s, %u): %s", tag,
			    pw->pw_name, (u_int)pw->pw_gid, strerror(errno));
			_exit(1);
		}
		если (setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) == -1) {
			error("%s: setresgid %u: %s", tag, (u_int)pw->pw_gid,
			    strerror(errno));
			_exit(1);
		}
		если (setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) == -1) {
			error("%s: setresuid %u: %s", tag, (u_int)pw->pw_uid,
			    strerror(errno));
			_exit(1);
		}
		/* stdin is pointed to /dev/null at this point */
		если ((flags & SSH_SUBPROCESS_STDOUT_DISCARD) != 0 &&
		    dup2(STDIN_FILENO, STDERR_FILENO) == -1) {
			error("%s: dup2: %s", tag, strerror(errno));
			_exit(1);
		}
		если (env != NULL)
			execve(av[0], av, env);
		иначе
			execv(av[0], av);
		error("%s %s \"%s\": %s", tag, env == NULL ? "execv" : "execve",
		    command, strerror(errno));
		_exit(127);
	default: /* parent */
		break;
	}

	close(p[1]);
	если ((flags & SSH_SUBPROCESS_STDOUT_CAPTURE) == 0)
		close(p[0]);
	иначе если ((f = fdopen(p[0], "r")) == NULL) {
		error("%s: fdopen: %s", tag, strerror(errno));
		close(p[0]);
		/* Don't leave zombie child */
		kill(pid, SIGTERM);
		пока (waitpid(pid, NULL, 0) == -1 && errno == EINTR)
			;
		вернуть 0;
	}
	/* Success */
	debug3_f("%s pid %ld", tag, (long)pid);
	если (child != NULL)
		*child = f;
	вернуть pid;
}

const char *
lookup_env_in_list(const char *env, char * const *envs, size_t nenvs)
{
	size_t i, envlen;

	envlen = strlen(env);
	для (i = 0; i < nenvs; i++) {
		если (strncmp(envs[i], env, envlen) == 0 &&
		    envs[i][envlen] == '=') {
			вернуть envs[i] + envlen + 1;
		}
	}
	вернуть NULL;
}

const char *
lookup_setenv_in_list(const char *env, char * const *envs, size_t nenvs)
{
	char *name, *cp;
	const char *ret;

	name = xstrdup(env);
	если ((cp = strchr(name, '=')) == NULL) {
		free(name);
		вернуть NULL; /* not env=val */
	}
	*cp = '\0';
	ret = lookup_env_in_list(name, envs, nenvs);
	free(name);
	вернуть ret;
}

/*
 * Helpers for managing poll(2)/ppoll(2) timeouts
 * Will remember the earliest deadline and return it for use in poll/ppoll.
 */

/* Initialise a poll/ppoll timeout with an indefinite deadline */
void
ptimeout_init(struct timespec *pt)
{
	/*
	 * Deliberately invalid for ppoll(2).
	 * Will be converted to NULL in ptimeout_get_tspec() later.
	 */
	pt->tv_sec = -1;
	pt->tv_nsec = 0;
}

/* Specify a poll/ppoll deadline of at most 'sec' seconds */
void
ptimeout_deadline_sec(struct timespec *pt, long sec)
{
	если (pt->tv_sec == -1 || pt->tv_sec >= sec) {
		pt->tv_sec = sec;
		pt->tv_nsec = 0;
	}
}

/* Specify a poll/ppoll deadline of at most 'p' (timespec) */
static void
ptimeout_deadline_tsp(struct timespec *pt, struct timespec *p)
{
	если (pt->tv_sec == -1 || timespeccmp(pt, p, >=))
		*pt = *p;
}

/* Specify a poll/ppoll deadline of at most 'ms' milliseconds */
void
ptimeout_deadline_ms(struct timespec *pt, long ms)
{
	struct timespec p;

	p.tv_sec = ms / 1000;
	p.tv_nsec = (ms % 1000) * 1000000;
	ptimeout_deadline_tsp(pt, &p);
}

/* Specify a poll/ppoll deadline of at most 'sec' seconds (double) */
void
ptimeout_deadline_sec_double(struct timespec *pt, double sec)
{
	struct timespec t;

	memset(&t, 0, sizeof(t));
	если ((int64_t)sec >= SSH_TIME_T_MAX)
		t.tv_sec = SSH_TIME_T_MAX;
	иначе если (sec > 0) {
		t.tv_sec = sec;
		t.tv_nsec = (sec - (double)t.tv_sec) * 1000000000.0;
	}
	ptimeout_deadline_tsp(pt, &t);
}

/* Specify a poll/ppoll deadline at wall clock monotime 'when' (timespec) */
void
ptimeout_deadline_monotime_tsp(struct timespec *pt, struct timespec *when)
{
	struct timespec now, t;

	monotime_ts(&now);

	если (timespeccmp(&now, when, >=)) {
		/* 'when' is now or in the past. Timeout ASAP */
		pt->tv_sec = 0;
		pt->tv_nsec = 0;
	} иначе {
		timespecsub(when, &now, &t);
		ptimeout_deadline_tsp(pt, &t);
	}
}

/* Specify a poll/ppoll deadline at wall clock monotime 'when' (double) */
void
ptimeout_deadline_monotime_double(struct timespec *pt, double when)
{
	ptimeout_deadline_sec_double(pt, when - monotime_double());
}

/* Specify a poll/ppoll deadline at wall clock monotime 'when' */
void
ptimeout_deadline_monotime(struct timespec *pt, time_t when)
{
	struct timespec t;

	t.tv_sec = when;
	t.tv_nsec = 0;
	ptimeout_deadline_monotime_tsp(pt, &t);
}

/* Get a poll(2) timeout value in milliseconds */
целое
ptimeout_get_ms(struct timespec *pt)
{
	если (pt->tv_sec == -1)
		вернуть -1;
	если (pt->tv_sec >= (INT_MAX - (pt->tv_nsec / 1000000)) / 1000)
		вернуть INT_MAX;
	вернуть (pt->tv_sec * 1000) + (pt->tv_nsec / 1000000);
}

/* Get a ppoll(2) timeout value as a timespec pointer */
struct timespec *
ptimeout_get_tsp(struct timespec *pt)
{
	вернуть pt->tv_sec == -1 ? NULL : pt;
}

/* Returns non-zero if a timeout has been set (i.e. is not indefinite) */
целое
ptimeout_isset(struct timespec *pt)
{
	вернуть pt->tv_sec != -1;
}

/*
 * Returns zero if the library at 'path' contains symbol 's', nonzero
 * otherwise.
 */
целое
lib_contains_symbol(const char *path, const char *s)
{
#ifdef HAVE_NLIST
	struct nlist nl[2];
	целое ret = -1, r;

	memset(nl, 0, sizeof(nl));
	nl[0].n_name = xstrdup(s);
	nl[1].n_name = NULL;
	если ((r = nlist(path, nl)) == -1) {
		error_f("nlist failed for %s", path);
		goto out;
	}
	если (r != 0 || nl[0].n_value == 0 || nl[0].n_type == 0) {
		error_f("library %s does not contain symbol %s", path, s);
		goto out;
	}
	/* success */
	ret = 0;
 out:
	free(nl[0].n_name);
	вернуть ret;
#иначе /* HAVE_NLIST */
	целое fd, ret = -1;
	struct stat st;
	void *m = NULL;
	size_t sz = 0;

	memset(&st, 0, sizeof(st));
	если ((fd = open(path, O_RDONLY)) < 0) {
		error_f("open %s: %s", path, strerror(errno));
		вернуть -1;
	}
	если (fstat(fd, &st) != 0) {
		error_f("fstat %s: %s", path, strerror(errno));
		goto out;
	}
	если (!S_ISREG(st.st_mode)) {
		error_f("%s is not a regular file", path);
		goto out;
	}
	если (st.st_size < 0 ||
	    (size_t)st.st_size < strlen(s) ||
	    st.st_size >= INT_MAX/2) {
		error_f("%s bad size %lld", path, (long long)st.st_size);
		goto out;
	}
	sz = (size_t)st.st_size;
	если ((m = mmap(NULL, sz, PROT_READ, MAP_PRIVATE, fd, 0)) == MAP_FAILED ||
	    m == NULL) {
		error_f("mmap %s: %s", path, strerror(errno));
		goto out;
	}
	если (memmem(m, sz, s, strlen(s)) == NULL) {
		error_f("%s does not contain expected string %s", path, s);
		goto out;
	}
	/* success */
	ret = 0;
 out:
	если (m != NULL && m != MAP_FAILED)
		munmap(m, sz);
	close(fd);
	вернуть ret;
#endif /* HAVE_NLIST */
}

целое
signal_is_crash(целое sig)
{
	switch (sig) {
	case SIGSEGV:
	case SIGBUS:
	case SIGTRAP:
	case SIGSYS:
	case SIGFPE:
	case SIGILL:
	case SIGABRT:
		вернуть 1;
	}
	вернуть 0;
}

char *
get_homedir(void)
{
	char *cp;
	struct passwd *pw;

	если ((cp = getenv("HOME")) != NULL && *cp != '\0')
		вернуть xstrdup(cp);

	если ((pw = getpwuid(getuid())) != NULL && *pw->pw_dir != '\0')
		вернуть xstrdup(pw->pw_dir);

	вернуть NULL;
}

целое
mkdir_path(const char *target, mode_t mode)
{
#если defined(HAVE_OPENAT) && defined(O_DIRECTORY)
	char *dir, *odir = NULL, *next;
	целое fd = AT_FDCWD, fd2, subpath_len, ret = -1;

	dir = odir = xstrdup(target);

	если (*dir == '/' &&
	    (fd = open("/", O_RDONLY|O_DIRECTORY)) == -1) {
		error_f("open(\"/\"): %s", strerror(errno));
		free(odir);
		вернуть -1;
	}
	/* Work through the path, component-wise */
	для (; dir != NULL && *dir != '\0'; dir = next) {
		если ((next = strchr(dir, '/')) != NULL)
			*(next++) = '\0';
		если (*dir == '\0')
			continue;
		subpath_len = (next == NULL) ? INT_MAX : next - odir - 1;
		если (mkdirat(fd, dir, mode) == 0)
			debug_f("created directory %.*s", subpath_len, target);
		иначе если (errno != EEXIST) {
			error_f("mkdir(\"%.*s\"): %s",
			    subpath_len, target, strerror(errno));
			goto out;
		}

		/* descend */
		если ((fd2 = openat(fd, dir, O_RDONLY|O_DIRECTORY)) == -1) {
			error_f("open(\"%.*s\"): %s",
			    subpath_len, target, strerror(errno));
			goto out;
		}
		если (fd != AT_FDCWD)
			close(fd);
		fd = fd2;
	}
	/* success */
	ret = 0;
 out:
	free(odir);
	если (fd != AT_FDCWD)
		close(fd);
	вернуть ret;
#иначе
	/*
	 * If we don't have openat (which was added in POSIX.1-2008), fall back
	 * to the possibly racy way.
	 */
	char *dir, *odir, *p, path[PATH_MAX] = "";
	целое ret = -1;
	size_t plen = sizeof(path);

	dir = odir = xstrdup(target);

	/* If the dir is relative, start with cwd. */
	если (*dir != '/' && getcwd(path, plen) == NULL) {
		error_f("getcwd: %s", strerror(errno));
		goto out;
	}

	/* Work through the path, component-wise */
	пока ((p = strsep(&dir, "/"))) {
		если (*p == '\0')
			continue;
		если (strlcat(path, "/", plen) >= plen ||
		    strlcat(path, p, plen) >= plen)
			goto out;
		если (mkdir(path, mode) == 0)
			debug_f("created directory %s", path);
		иначе если (errno != EEXIST && errno != EISDIR) {
			error_f("mkdir(\"%s\"): %s", path, strerror(errno));
			goto out;
		}
	}
	/* success */
	ret = 0;
 out:
	free(odir);
	вернуть ret;
#endif
}
