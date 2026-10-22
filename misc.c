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
	поки (*t) {
		якщо (*t == '\n' || *t == '\r') {
			*t = '\0';
			повернути s;
		}
		t++;
	}
	повернути s;

}

/* remove whitespace from end of string */
void
rtrim(char *s)
{
	size_t i;

	якщо ((i = strlen(s)) == 0)
		повернути;
	do {
		i--;
		якщо (isspace((unsigned char)s[i]))
			s[i] = '\0';
		інакше
			break;
	} поки (i > 0);
}

/*
 * returns pointer to character after 'prefix' in 's' or otherwise NULL
 * if the prefix is not present.
 */
const char *
strprefix(const char *s, const char *prefix, ціле ignorecase)
{
	size_t prefixlen;

	якщо ((prefixlen = strlen(prefix)) == 0)
		повернути s;
	якщо (ignorecase) {
		якщо (strncasecmp(s, prefix, prefixlen) != 0)
			повернути NULL;
	} інакше {
		якщо (strncmp(s, prefix, prefixlen) != 0)
			повернути NULL;
	}
	повернути s + prefixlen;
}

/* Append string 's' to a NULL-terminated array of strings */
void
stringlist_append(char ***listp, const char *s)
{
	size_t i = 0;

	якщо (*listp == NULL)
		*listp = xcalloc(2, sizeof(**listp));
	інакше {
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

	якщо (list == NULL)
		повернути;
	для (i = 0; list[i] != NULL; i++)
		free(list[i]);
	free(list);
}

/* set/unset filedescriptor to non-blocking */
ціле
set_nonblock(ціле fd)
{
	ціле val;

	val = fcntl(fd, F_GETFL);
	якщо (val == -1) {
		error("fcntl(%d, F_GETFL): %s", fd, strerror(errno));
		повернути (-1);
	}
	якщо (val & O_NONBLOCK) {
		debug3("fd %d is O_NONBLOCK", fd);
		повернути (0);
	}
	debug2("fd %d setting O_NONBLOCK", fd);
	val |= O_NONBLOCK;
	якщо (fcntl(fd, F_SETFL, val) == -1) {
		debug("fcntl(%d, F_SETFL, O_NONBLOCK): %s", fd,
		    strerror(errno));
		повернути (-1);
	}
	повернути (0);
}

ціле
unset_nonblock(ціле fd)
{
	ціле val;

	val = fcntl(fd, F_GETFL);
	якщо (val == -1) {
		error("fcntl(%d, F_GETFL): %s", fd, strerror(errno));
		повернути (-1);
	}
	якщо (!(val & O_NONBLOCK)) {
		debug3("fd %d is not O_NONBLOCK", fd);
		повернути (0);
	}
	debug("fd %d clearing O_NONBLOCK", fd);
	val &= ~O_NONBLOCK;
	якщо (fcntl(fd, F_SETFL, val) == -1) {
		debug("fcntl(%d, F_SETFL, ~O_NONBLOCK): %s",
		    fd, strerror(errno));
		повернути (-1);
	}
	повернути (0);
}

const char *
ssh_gai_strerror(ціле gaierr)
{
	якщо (gaierr == EAI_SYSTEM && errno != 0)
		повернути strerror(errno);
	повернути gai_strerror(gaierr);
}

/* disable nagle on socket */
void
set_nodelay(ціле fd)
{
	ціле opt;
	socklen_t optlen;

	optlen = sizeof opt;
	якщо (getsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, &optlen) == -1) {
		debug("getsockopt TCP_NODELAY: %.100s", strerror(errno));
		повернути;
	}
	якщо (opt == 1) {
		debug2("fd %d is TCP_NODELAY", fd);
		повернути;
	}
	opt = 1;
	debug2("fd %d setting TCP_NODELAY", fd);
	якщо (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof opt) == -1)
		error("setsockopt TCP_NODELAY: %.100s", strerror(errno));
}

/* Allow local port reuse in TIME_WAIT */
ціле
set_reuseaddr(ціле fd)
{
	ціле on = 1;

	якщо (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) == -1) {
		error("setsockopt SO_REUSEADDR fd %d: %s", fd, strerror(errno));
		повернути -1;
	}
	повернути 0;
}

/* Set TCP keepalives */
ціле
set_keepalive(ціле fd)
{
	ціле on = 1;

	якщо (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on)) == -1) {
		error("setsockopt SO_KEEPALIVE fd %d: %s", fd, strerror(errno));
		повернути -1;
	}
	повернути 0;
}

/* Get/set routing domain */
char *
get_rdomain(ціле fd)
{
#якщо defined(HAVE_SYS_GET_RDOMAIN)
	повернути sys_get_rdomain(fd);
#elif defined(__OpenBSD__)
	ціле rtable;
	char *ret;
	socklen_t len = sizeof(rtable);

	якщо (getsockopt(fd, SOL_SOCKET, SO_RTABLE, &rtable, &len) == -1) {
		error("Failed to get routing domain for fd %d: %s",
		    fd, strerror(errno));
		повернути NULL;
	}
	xasprintf(&ret, "%d", rtable);
	повернути ret;
#інакше /* defined(__OpenBSD__) */
	повернути NULL;
#endif
}

ціле
set_rdomain(ціле fd, const char *name)
{
#якщо defined(HAVE_SYS_SET_RDOMAIN)
	повернути sys_set_rdomain(fd, name);
#elif defined(__OpenBSD__)
	ціле rtable;
	const char *errstr;

	якщо (name == NULL)
		повернути 0; /* default table */

	rtable = (ціле)strtonum(name, 0, 255, &errstr);
	якщо (errstr != NULL) {
		/* Shouldn't happen */
		error("Invalid routing domain \"%s\": %s", name, errstr);
		повернути -1;
	}
	якщо (setsockopt(fd, SOL_SOCKET, SO_RTABLE,
	    &rtable, sizeof(rtable)) == -1) {
		error("Failed to set routing domain %d on fd %d: %s",
		    rtable, fd, strerror(errno));
		повернути -1;
	}
	повернути 0;
#інакше /* defined(__OpenBSD__) */
	error("Setting routing domain is not supported on this platform");
	повернути -1;
#endif
}

ціле
get_sock_af(ціле fd)
{
	struct sockaddr_storage to;
	socklen_t tolen = sizeof(to);

	memset(&to, 0, sizeof(to));
	якщо (getsockname(fd, (struct sockaddr *)&to, &tolen) == -1)
		повернути -1;
#ifdef IPV4_IN_IPV6
	якщо (to.ss_family == AF_INET6 &&
	    IN6_IS_ADDR_V4MAPPED(&((struct sockaddr_in6 *)&to)->sin6_addr))
		повернути AF_INET;
#endif
	повернути to.ss_family;
}

void
set_sock_tos(ціле fd, ціле tos)
{
#ifndef IP_TOS_IS_BROKEN
	ціле af;

	якщо (tos < 0 || tos == INT_MAX) {
		debug_f("invalid TOS %d", tos);
		повернути;
	}
	switch ((af = get_sock_af(fd))) {
	case -1:
		/* assume not a socket */
		break;
	case AF_INET:
# ifdef IP_TOS
		debug3_f("set socket %d IP_TOS 0x%02x", fd, tos);
		якщо (setsockopt(fd, IPPROTO_IP, IP_TOS,
		    &tos, sizeof(tos)) == -1) {
			error("setsockopt socket %d IP_TOS %d: %s",
			    fd, tos, strerror(errno));
		}
# endif /* IP_TOS */
		break;
	case AF_INET6:
# ifdef IPV6_TCLASS
		debug3_f("set socket %d IPV6_TCLASS 0x%02x", fd, tos);
		якщо (setsockopt(fd, IPPROTO_IPV6, IPV6_TCLASS,
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
static ціле
waitfd(ціле fd, ціле *timeoutp, short events, volatile sig_atomic_t *stop)
{
	struct pollfd pfd;
	struct timespec timeout;
	ціле oerrno, r;
	sigset_t nsigset, osigset;

	якщо (timeoutp && *timeoutp == -1)
		timeoutp = NULL;
	pfd.fd = fd;
	pfd.events = events;
	ptimeout_init(&timeout);
	якщо (timeoutp != NULL)
		ptimeout_deadline_ms(&timeout, *timeoutp);
	якщо (stop != NULL)
		sigfillset(&nsigset);
	для (; timeoutp == NULL || *timeoutp >= 0;) {
		якщо (stop != NULL) {
			sigprocmask(SIG_BLOCK, &nsigset, &osigset);
			якщо (*stop) {
				sigprocmask(SIG_SETMASK, &osigset, NULL);
				errno = EINTR;
				повернути -1;
			}
		}
		r = ppoll(&pfd, 1, ptimeout_get_tsp(&timeout),
		    stop != NULL ? &osigset : NULL);
		oerrno = errno;
		якщо (stop != NULL)
			sigprocmask(SIG_SETMASK, &osigset, NULL);
		якщо (timeoutp)
			*timeoutp = ptimeout_get_ms(&timeout);
		errno = oerrno;
		якщо (r > 0)
			повернути 0;
		інакше якщо (r == -1 && errno != EAGAIN && errno != EINTR)
			повернути -1;
		інакше якщо (r == 0)
			break;
	}
	/* timeout */
	errno = ETIMEDOUT;
	повернути -1;
}

/*
 * Wait up to *timeoutp milliseconds for fd to be readable. Updates
 * *timeoutp with time remaining.
 * Returns 0 if fd ready or -1 on timeout or error (see errno).
 */
ціле
waitrfd(ціле fd, ціле *timeoutp, volatile sig_atomic_t *stop) {
	повернути waitfd(fd, timeoutp, POLLIN, stop);
}

/*
 * Attempt a non-blocking connect(2) to the specified address, waiting up to
 * *timeoutp milliseconds for the connection to complete. If the timeout is
 * <=0, then wait indefinitely.
 *
 * Returns 0 on success or -1 on failure.
 */
ціле
timeout_connect(ціле sockfd, const struct sockaddr *serv_addr,
    socklen_t addrlen, ціле *timeoutp)
{
	ціле optval = 0;
	socklen_t optlen = sizeof(optval);

	/* No timeout: just do a blocking connect() */
	якщо (timeoutp == NULL || *timeoutp <= 0)
		повернути connect(sockfd, serv_addr, addrlen);

	set_nonblock(sockfd);
	для (;;) {
		якщо (connect(sockfd, serv_addr, addrlen) == 0) {
			/* Succeeded already? */
			unset_nonblock(sockfd);
			повернути 0;
		} інакше якщо (errno == EINTR)
			continue;
		інакше якщо (errno != EINPROGRESS)
			повернути -1;
		break;
	}

	якщо (waitfd(sockfd, timeoutp, POLLIN | POLLOUT, NULL) == -1)
		повернути -1;

	/* Completed or failed */
	якщо (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &optval, &optlen) == -1) {
		debug("getsockopt: %s", strerror(errno));
		повернути -1;
	}
	якщо (optval != 0) {
		errno = optval;
		повернути -1;
	}
	unset_nonblock(sockfd);
	повернути 0;
}

/* Characters considered whitespace in strsep calls. */
#define WHITESPACE " \t\r\n"
#define QUOTE	"\""

/* return next token in configuration line */
static char *
strdelim_internal(char **s, ціле split_equals)
{
	char *old;
	ціле wspace = 0;

	якщо (*s == NULL)
		повернути NULL;

	old = *s;

	*s = strpbrk(*s,
	    split_equals ? WHITESPACE QUOTE "=" : WHITESPACE QUOTE);
	якщо (*s == NULL)
		повернути (old);

	якщо (*s[0] == '\"') {
		memmove(*s, *s + 1, strlen(*s)); /* move nul too */
		/* Find matching quote */
		якщо ((*s = strpbrk(*s, QUOTE)) == NULL) {
			повернути (NULL);		/* no matching quote */
		} інакше {
			*s[0] = '\0';
			*s += strspn(*s + 1, WHITESPACE) + 1;
			повернути (old);
		}
	}

	/* Allow only one '=' to be skipped */
	якщо (split_equals && *s[0] == '=')
		wspace = 1;
	*s[0] = '\0';

	/* Skip any extra whitespace after first token */
	*s += strspn(*s + 1, WHITESPACE) + 1;
	якщо (split_equals && *s[0] == '=' && !wspace)
		*s += strspn(*s + 1, WHITESPACE) + 1;

	повернути (old);
}

/*
 * Return next token in configuration line; splits on whitespace or a
 * single '=' character.
 */
char *
strdelim(char **s)
{
	повернути strdelim_internal(s, 1);
}

/*
 * Return next token in configuration line; splits on whitespace only.
 */
char *
strdelimw(char **s)
{
	повернути strdelim_internal(s, 0);
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
	повернути copy;
}

void
pwfree(struct passwd *pw)
{
	якщо (pw == NULL)
		повернути;
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
ціле
a2port(const char *s)
{
	struct servent *se;
	long long port;
	const char *errstr;

	port = strtonum(s, 0, 65535, &errstr);
	якщо (errstr == NULL)
		повернути (ціле)port;
	якщо ((se = getservbyname(s, "tcp")) != NULL)
		повернути ntohs(se->s_port);
	повернути -1;
}

ціле
a2tun(const char *s, ціле *remote)
{
	const char *errstr = NULL;
	char *sp, *ep;
	ціле tun;

	якщо (remote != NULL) {
		*remote = SSH_TUNID_ANY;
		sp = xstrdup(s);
		якщо ((ep = strchr(sp, ':')) == NULL) {
			free(sp);
			повернути (a2tun(s, NULL));
		}
		ep[0] = '\0'; ep++;
		*remote = a2tun(ep, NULL);
		tun = a2tun(sp, NULL);
		free(sp);
		повернути (*remote == SSH_TUNID_ERR ? *remote : tun);
	}

	якщо (strcasecmp(s, "any") == 0)
		повернути (SSH_TUNID_ANY);

	tun = strtonum(s, 0, SSH_TUNID_MAX, &errstr);
	якщо (errstr != NULL)
		повернути (SSH_TUNID_ERR);

	повернути (tun);
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
	ціле seen_seconds = 0;

	якщо (s == NULL || *s == '\0')
		повернути -1.0;

	для (p = s; *p != '\0';) {
		якщо (!isdigit((unsigned char)*p) && *p != '.')
			повернути -1.0;

		errno = 0;
		якщо ((val = strtod(p, &endp)) < 0 || errno != 0 || p == endp)
			повернути -1.0;
		/* Allow only decimal forms */
		якщо (p + strspn(p, "0123456789.") != endp)
			повернути -1.0;
		start_p = p;
		p = endp;

		switch (*p) {
		case '\0':
			/* FALLTHROUGH */
		case 's':
		case 'S':
			якщо (seen_seconds++)
				повернути -1.0;
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
			повернути -1.0;
		}

		/* Special handling if this was a decimal */
		якщо (memchr(start_p, '.', endp - start_p) != NULL) {
			/* Decimal point present */
			якщо (multiplier > 1.0)
				повернути -1.0; /* No fractionals for non-seconds */
			/* For seconds, ensure digits follow */
			якщо (!isdigit((unsigned char)*(endp - 1)))
				повернути -1.0;
		}

		total_sec += val * multiplier;

		якщо (*p != '\0')
			p++;
	}
	повернути total_sec;
}

/*
 * Same as convtime_double() above but fractional seconds are ignored.
 * Return -1 if time string is invalid.
 */
ціле
convtime(const char *s)
{
	double sec_val;

	якщо ((sec_val = convtime_double(s)) < 0.0)
		повернути -1;

	/* Check for overflow into int */
	якщо (sec_val < 0 || sec_val > INT_MAX)
		повернути -1;

	повернути (ціле)sec_val;
}

#define TF_BUFS	8
#define TF_LEN	9

const char *
fmt_timeframe(time_t t)
{
	char		*buf;
	static char	 tfbuf[TF_BUFS][TF_LEN];	/* ring buffer */
	static ціле	 idx = 0;
	unsigned ціле	 sec, min, hrs, day;
	unsigned long long	week;

	buf = tfbuf[idx++];
	якщо (idx == TF_BUFS)
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

	якщо (week > 0)
		snprintf(buf, TF_LEN, "%02lluw%01ud%02uh", week, day, hrs);
	інакше якщо (day > 0)
		snprintf(buf, TF_LEN, "%01ud%02uh%02um", day, hrs, min);
	інакше
		snprintf(buf, TF_LEN, "%02u:%02u:%02u", hrs, min, sec);

	повернути (buf);
}

/*
 * Returns a standardized host+port identifier string.
 * Caller must free returned string.
 */
char *
put_host_port(const char *host, u_short port)
{
	char *hoststr;

	якщо (port == 0 || port == SSH_DEFAULT_PORT)
		повернути(xstrdup(host));
	якщо (asprintf(&hoststr, "[%s]:%d", host, (ціле)port) == -1)
		fatal("put_host_port: asprintf: %s", strerror(errno));
	debug3("put_host_port: %s", hoststr);
	повернути hoststr;
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

	якщо (cp == NULL || *cp == NULL)
		повернути NULL;

	old = s = *cp;
	якщо (*s == '[') {
		якщо ((s = strchr(s, ']')) == NULL)
			повернути NULL;
		інакше
			s++;
	} інакше якщо ((s = strpbrk(s, ":/")) == NULL)
		s = *cp + strlen(*cp); /* skip to end (see first case below) */

	switch (*s) {
	case '\0':
		*cp = NULL;	/* no more fields*/
		break;

	case ':':
	case '/':
		якщо (delim != NULL)
			*delim = *s;
		*s = '\0';	/* terminate */
		*cp = s + 1;
		break;

	default:
		повернути NULL;
	}

	повернути old;
}

/* The common case: only accept colon as delimiter. */
char *
hpdelim(char **cp)
{
	char *r, delim = '\0';

	r =  hpdelim2(cp, &delim);
	якщо (delim == '/')
		повернути NULL;
	повернути r;
}

char *
cleanhostname(char *host)
{
	якщо (*host == '[' && host[strlen(host) - 1] == ']') {
		host[strlen(host) - 1] = '\0';
		повернути (host + 1);
	} інакше
		повернути host;
}

char *
colon(char *cp)
{
	ціле flag = 0;

	якщо (*cp == ':')		/* Leading colon is part of file name. */
		повернути NULL;
	якщо (*cp == '[')
		flag = 1;

	для (; *cp; ++cp) {
		якщо (*cp == '@' && *(cp+1) == '[')
			flag = 1;
		якщо (*cp == ']' && *(cp+1) == ':' && flag)
			повернути (cp+1);
		якщо (*cp == ':' && !flag)
			повернути (cp);
		якщо (*cp == '/')
			повернути NULL;
	}
	повернути NULL;
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
ціле
parse_user_host_path(const char *s, char **userp, char **hostp, char **pathp)
{
	char *user = NULL, *host = NULL, *path = NULL;
	char *sdup, *tmp;
	ціле ret = -1;

	якщо (userp != NULL)
		*userp = NULL;
	якщо (hostp != NULL)
		*hostp = NULL;
	якщо (pathp != NULL)
		*pathp = NULL;

	sdup = xstrdup(s);

	/* Check for remote syntax: [user@]host:[path] */
	якщо ((tmp = colon(sdup)) == NULL)
		goto out;

	/* Extract optional path */
	*tmp++ = '\0';
	якщо (*tmp == '\0')
		tmp = ".";
	path = xstrdup(tmp);

	/* Extract optional user and mandatory host */
	tmp = strrchr(sdup, '@');
	якщо (tmp != NULL) {
		*tmp++ = '\0';
		host = xstrdup(cleanhostname(tmp));
		якщо (*sdup != '\0')
			user = xstrdup(sdup);
	} інакше {
		host = xstrdup(cleanhostname(sdup));
		user = NULL;
	}

	/* Success */
	якщо (userp != NULL) {
		*userp = user;
		user = NULL;
	}
	якщо (hostp != NULL) {
		*hostp = host;
		host = NULL;
	}
	якщо (pathp != NULL) {
		*pathp = path;
		path = NULL;
	}
	ret = 0;
out:
	free(sdup);
	free(user);
	free(host);
	free(path);
	повернути ret;
}

/*
 * Parse a [user@]host[:port] string.
 * Caller must free returned user and host.
 * Any of the pointer return arguments may be NULL (useful for syntax checking).
 * If user was not specified then *userp will be set to NULL.
 * If port was not specified then *portp will be -1.
 * Returns 0 on success, -1 on failure.
 */
ціле
parse_user_host_port(const char *s, char **userp, char **hostp, ціле *portp)
{
	char *sdup, *cp, *tmp;
	char *user = NULL, *host = NULL;
	ціле port = -1, ret = -1;

	якщо (userp != NULL)
		*userp = NULL;
	якщо (hostp != NULL)
		*hostp = NULL;
	якщо (portp != NULL)
		*portp = -1;

	якщо ((sdup = tmp = strdup(s)) == NULL)
		повернути -1;
	/* Extract optional username */
	якщо ((cp = strrchr(tmp, '@')) != NULL) {
		*cp = '\0';
		якщо (*tmp == '\0')
			goto out;
		якщо ((user = strdup(tmp)) == NULL)
			goto out;
		tmp = cp + 1;
	}
	/* Extract mandatory hostname */
	якщо ((cp = hpdelim(&tmp)) == NULL || *cp == '\0')
		goto out;
	host = xstrdup(cleanhostname(cp));
	/* Convert and verify optional port */
	якщо (tmp != NULL && *tmp != '\0') {
		якщо ((port = a2port(tmp)) <= 0)
			goto out;
	}
	/* Success */
	якщо (userp != NULL) {
		*userp = user;
		user = NULL;
	}
	якщо (hostp != NULL) {
		*hostp = host;
		host = NULL;
	}
	якщо (portp != NULL)
		*portp = port;
	ret = 0;
 out:
	free(sdup);
	free(user);
	free(host);
	повернути ret;
}

/*
 * Converts a two-byte hex string to decimal.
 * Returns the decimal value or -1 for invalid input.
 */
static ціле
hexchar(const char *s)
{
	unsigned char result[2];
	ціле i;

	для (i = 0; i < 2; i++) {
		якщо (s[i] >= '0' && s[i] <= '9')
			result[i] = (unsigned char)(s[i] - '0');
		інакше якщо (s[i] >= 'a' && s[i] <= 'f')
			result[i] = (unsigned char)(s[i] - 'a') + 10;
		інакше якщо (s[i] >= 'A' && s[i] <= 'F')
			result[i] = (unsigned char)(s[i] - 'A') + 10;
		інакше
			повернути -1;
	}
	повернути (result[0] << 4) | result[1];
}

/*
 * Decode an url-encoded string.
 * Returns a newly allocated string on success or NULL on failure.
 */
static char *
urldecode(const char *src)
{
	char *ret, *dst;
	ціле ch;
	size_t srclen;

	якщо ((srclen = strlen(src)) >= SIZE_MAX)
		повернути NULL;
	ret = xmalloc(srclen + 1);
	для (dst = ret; *src != '\0'; src++) {
		switch (*src) {
		case '+':
			*dst++ = ' ';
			break;
		case '%':
			/* note: don't allow \0 characters */
			якщо (!isxdigit((unsigned char)src[1]) ||
			    !isxdigit((unsigned char)src[2]) ||
			    (ch = hexchar(src + 1)) == -1 || ch == 0) {
				free(ret);
				повернути NULL;
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

	повернути ret;
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
ціле
parse_uri(const char *scheme, const char *uri, char **userp, char **hostp,
    ціле *portp, char **pathp)
{
	char *uridup, *cp, *tmp, ch;
	char *user = NULL, *host = NULL, *path = NULL;
	ціле port = -1, ret = -1;
	size_t len;

	len = strlen(scheme);
	якщо (strncmp(uri, scheme, len) != 0 || strncmp(uri + len, "://", 3) != 0)
		повернути 1;
	uri += len + 3;

	якщо (userp != NULL)
		*userp = NULL;
	якщо (hostp != NULL)
		*hostp = NULL;
	якщо (portp != NULL)
		*portp = -1;
	якщо (pathp != NULL)
		*pathp = NULL;

	uridup = tmp = xstrdup(uri);

	/* Extract optional ssh-info (username + connection params) */
	якщо ((cp = strchr(tmp, '@')) != NULL) {
		char *delim;

		*cp = '\0';
		/* Extract username and connection params */
		якщо ((delim = strchr(tmp, ';')) != NULL) {
			/* Just ignore connection params for now */
			*delim = '\0';
		}
		якщо (*tmp == '\0') {
			/* Empty username */
			goto out;
		}
		якщо ((user = urldecode(tmp)) == NULL)
			goto out;
		tmp = cp + 1;
	}

	/* Extract mandatory hostname */
	якщо ((cp = hpdelim2(&tmp, &ch)) == NULL || *cp == '\0')
		goto out;
	host = xstrdup(cleanhostname(cp));
	якщо (!valid_domain(host, 0, NULL))
		goto out;

	якщо (tmp != NULL && *tmp != '\0') {
		якщо (ch == ':') {
			/* Convert and verify port. */
			якщо ((cp = strchr(tmp, '/')) != NULL)
				*cp = '\0';
			якщо ((port = a2port(tmp)) <= 0)
				goto out;
			tmp = cp ? cp + 1 : NULL;
		}
		якщо (tmp != NULL && *tmp != '\0') {
			/* Extract optional path */
			якщо ((path = urldecode(tmp)) == NULL)
				goto out;
		}
	}

	/* Success */
	якщо (userp != NULL) {
		*userp = user;
		user = NULL;
	}
	якщо (hostp != NULL) {
		*hostp = host;
		host = NULL;
	}
	якщо (portp != NULL)
		*portp = port;
	якщо (pathp != NULL) {
		*pathp = path;
		path = NULL;
	}
	ret = 0;
 out:
	free(uridup);
	free(user);
	free(host);
	free(path);
	повернути ret;
}

/* function to assist building execv() arguments */
void
addargs(arglist *args, char *fmt, ...)
{
	va_list ap;
	char *cp;
	u_int nalloc;
	ціле r;

	va_start(ap, fmt);
	r = vasprintf(&cp, fmt, ap);
	va_end(ap);
	якщо (r == -1)
		fatal_f("argument too long");

	nalloc = args->nalloc;
	якщо (args->list == NULL) {
		nalloc = 32;
		args->num = 0;
	} інакше якщо (args->num > (256 * 1024))
		fatal_f("too many arguments");
	інакше якщо (args->num >= args->nalloc)
		fatal_f("arglist corrupt");
	інакше якщо (args->num+2 >= nalloc)
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
	ціле r;

	va_start(ap, fmt);
	r = vasprintf(&cp, fmt, ap);
	va_end(ap);
	якщо (r == -1)
		fatal_f("argument too long");
	якщо (args->list == NULL || args->num >= args->nalloc)
		fatal_f("arglist corrupt");

	якщо (which >= args->num)
		fatal_f("tried to replace invalid arg %d >= %d",
		    which, args->num);
	free(args->list[which]);
	args->list[which] = cp;
}

void
freeargs(arglist *args)
{
	u_int i;

	якщо (args == NULL)
		повернути;
	якщо (args->list != NULL && args->num < args->nalloc) {
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
ціле
tilde_expand(const char *filename, uid_t uid, char **retp)
{
	char *ocopy = NULL, *copy, *s = NULL;
	const char *path = NULL, *user = NULL;
	struct passwd *pw;
	size_t len;
	ціле ret = -1, r, slash;

	*retp = NULL;
	якщо (*filename != '~') {
		*retp = xstrdup(filename);
		повернути 0;
	}
	ocopy = copy = xstrdup(filename + 1);

	якщо (*copy == '\0')				/* ~ */
		path = NULL;
	інакше якщо (*copy == '/') {
		copy += strspn(copy, "/");
		якщо (*copy == '\0')
			path = NULL;			/* ~/ */
		інакше
			path = copy;			/* ~/path */
	} інакше {
		user = copy;
		якщо ((path = strchr(copy, '/')) != NULL) {
			copy[path - copy] = '\0';
			path++;
			path += strspn(path, "/");
			якщо (*path == '\0')		/* ~user/ */
				path = NULL;
			/* else				 ~user/path */
		}
		/* else					~user */
	}
	якщо (user != NULL) {
		якщо ((pw = getpwnam(user)) == NULL) {
			error_f("No such user %s", user);
			goto out;
		}
	} інакше якщо ((pw = getpwuid(uid)) == NULL) {
		error_f("No such uid %ld", (long)uid);
		goto out;
	}

	/* Make sure directory has a trailing '/' */
	slash = (len = strlen(pw->pw_dir)) == 0 || pw->pw_dir[len - 1] != '/';

	якщо ((r = xasprintf(&s, "%s%s%s", pw->pw_dir,
	    slash ? "/" : "", path != NULL ? path : "")) <= 0) {
		error_f("xasprintf failed");
		goto out;
	}
	якщо (r >= PATH_MAX) {
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
	повернути ret;
}

char *
tilde_expand_filename(const char *filename, uid_t uid)
{
	char *ret;

	якщо (tilde_expand(filename, uid, &ret) != 0)
		cleanup_exit(255);
	повернути ret;
}

/*
 * Expand a string with a set of %[char] escapes and/or ${ENVIRONMENT}
 * substitutions.  A number of escapes may be specified as
 * (char *escape_chars, char *replacement) pairs. The list must be terminated
 * by a NULL escape_char. Returns replaced string in memory allocated by
 * xmalloc which the caller must free.
 */
static char *
vdollar_percent_expand(ціле *parseerror, ціле dollar, ціле percent,
    const char *string, va_list ap)
{
#define EXPAND_MAX_KEYS	64
	u_int num_keys = 0, i;
	struct {
		const char *key;
		const char *repl;
	} keys[EXPAND_MAX_KEYS];
	struct sshbuf *buf;
	ціле r, missingvar = 0;
	char *ret = NULL, *var, *varend, *val;
	size_t len;

	якщо ((buf = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	якщо (parseerror == NULL)
		fatal_f("null parseerror arg");
	*parseerror = 1;

	/* Gather keys if we're doing percent expansion. */
	якщо (percent) {
		для (num_keys = 0; num_keys < EXPAND_MAX_KEYS; num_keys++) {
			keys[num_keys].key = va_arg(ap, char *);
			якщо (keys[num_keys].key == NULL)
				break;
			keys[num_keys].repl = va_arg(ap, char *);
			якщо (keys[num_keys].repl == NULL) {
				fatal_f("NULL replacement for token %s",
				    keys[num_keys].key);
			}
		}
		якщо (num_keys == EXPAND_MAX_KEYS && va_arg(ap, char *) != NULL)
			fatal_f("too many keys");
		якщо (num_keys == 0)
			fatal_f("percent expansion without token list");
	}

	/* Expand string */
	для (i = 0; *string != '\0'; string++) {
		/* Optionally process ${ENVIRONMENT} expansions. */
		якщо (dollar && string[0] == '$' && string[1] == '{') {
			string += 2;  /* skip over '${' */
			якщо ((varend = strchr(string, '}')) == NULL) {
				error_f("environment variable '%s' missing "
				    "closing '}'", string);
				goto out;
			}
			len = varend - string;
			якщо (len == 0) {
				error_f("zero-length environment variable");
				goto out;
			}
			var = xmalloc(len + 1);
			(void)strlcpy(var, string, len + 1);
			якщо ((val = getenv(var)) == NULL) {
				error_f("env var ${%s} has no value", var);
				missingvar = 1;
			} інакше {
				debug3_f("expand ${%s} -> '%s'", var, val);
				якщо ((r = sshbuf_put(buf, val, strlen(val))) !=0)
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
		якщо (*string != '%' || !percent) {
 append:
			якщо ((r = sshbuf_put_u8(buf, *string)) != 0)
				fatal_fr(r, "sshbuf_put_u8 %%");
			continue;
		}
		string++;
		/* %% case */
		якщо (*string == '%')
			goto append;
		якщо (*string == '\0') {
			error_f("invalid format");
			goto out;
		}
		для (i = 0; i < num_keys; i++) {
			якщо (strchr(keys[i].key, *string) != NULL) {
				якщо ((r = sshbuf_put(buf, keys[i].repl,
				    strlen(keys[i].repl))) != 0)
					fatal_fr(r, "sshbuf_put %%-repl");
				break;
			}
		}
		якщо (i >= num_keys) {
			error_f("unknown key %%%c", *string);
			goto out;
		}
	}
	якщо (!missingvar && (ret = sshbuf_dup_string(buf)) == NULL)
		fatal_f("sshbuf_dup_string failed");
	*parseerror = 0;
 out:
	sshbuf_free(buf);
	повернути *parseerror ? NULL : ret;
#undef EXPAND_MAX_KEYS
}

/*
 * Expand only environment variables.
 * Note that although this function is variadic like the other similar
 * functions, any such arguments will be unused.
 */

char *
dollar_expand(ціле *parseerr, const char *string, ...)
{
	char *ret;
	ціле err;
	va_list ap;

	va_start(ap, string);
	ret = vdollar_percent_expand(&err, 1, 0, string, ap);
	va_end(ap);
	якщо (parseerr != NULL)
		*parseerr = err;
	повернути ret;
}

/*
 * Returns expanded string or NULL if a specified environment variable is
 * not defined, or calls fatal if the string is invalid.
 */
char *
percent_expand(const char *string, ...)
{
	char *ret;
	ціле err;
	va_list ap;

	va_start(ap, string);
	ret = vdollar_percent_expand(&err, 0, 1, string, ap);
	va_end(ap);
	якщо (err)
		fatal_f("failed");
	повернути ret;
}

/*
 * Returns expanded string or NULL if a specified environment variable is
 * not defined, or calls fatal if the string is invalid.
 */
char *
percent_dollar_expand(const char *string, ...)
{
	char *ret;
	ціле err;
	va_list ap;

	va_start(ap, string);
	ret = vdollar_percent_expand(&err, 1, 1, string, ap);
	va_end(ap);
	якщо (err)
		fatal_f("failed");
	повернути ret;
}

ціле
tun_open(ціле tun, ціле mode, char **ifname)
{
#якщо defined(CUSTOM_SYS_TUN_OPEN)
	повернути (sys_tun_open(tun, mode, ifname));
#elif defined(SSH_TUN_OPENBSD)
	struct ifreq ifr;
	char name[100];
	ціле fd = -1, sock;
	const char *tunbase = "tun";

	якщо (ifname != NULL)
		*ifname = NULL;

	якщо (mode == SSH_TUNMODE_ETHERNET)
		tunbase = "tap";

	/* Open the tunnel device */
	якщо (tun <= SSH_TUNID_MAX) {
		snprintf(name, sizeof(name), "/dev/%s%d", tunbase, tun);
		fd = open(name, O_RDWR);
	} інакше якщо (tun == SSH_TUNID_ANY) {
		для (tun = 100; tun >= 0; tun--) {
			snprintf(name, sizeof(name), "/dev/%s%d",
			    tunbase, tun);
			якщо ((fd = open(name, O_RDWR)) >= 0)
				break;
		}
	} інакше {
		debug_f("invalid tunnel %u", tun);
		повернути -1;
	}

	якщо (fd == -1) {
		debug_f("%s open: %s", name, strerror(errno));
		повернути -1;
	}

	debug_f("%s mode %d fd %d", name, mode, fd);

	/* Bring interface up if it is not already */
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s%d", tunbase, tun);
	якщо ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
		goto failed;

	якщо (ioctl(sock, SIOCGIFFLAGS, &ifr) == -1) {
		debug_f("get interface %s flags: %s", ifr.ifr_name,
		    strerror(errno));
		goto failed;
	}

	якщо (!(ifr.ifr_flags & IFF_UP)) {
		ifr.ifr_flags |= IFF_UP;
		якщо (ioctl(sock, SIOCSIFFLAGS, &ifr) == -1) {
			debug_f("activate interface %s: %s", ifr.ifr_name,
			    strerror(errno));
			goto failed;
		}
	}

	якщо (ifname != NULL)
		*ifname = xstrdup(ifr.ifr_name);

	close(sock);
	повернути fd;

 failed:
	якщо (fd >= 0)
		close(fd);
	якщо (sock >= 0)
		close(sock);
	повернути -1;
#інакше
	error("Tunnel interfaces are not supported on this platform");
	повернути (-1);
#endif
}

void
sanitise_stdfd(void)
{
	ціле nullfd, dupfd;

	якщо ((nullfd = dupfd = open(_PATH_DEVNULL, O_RDWR)) == -1) {
		fprintf(stderr, "Couldn't open /dev/null: %s\n",
		    strerror(errno));
		exit(1);
	}
	поки (++dupfd <= STDERR_FILENO) {
		/* Only populate closed fds. */
		якщо (fcntl(dupfd, F_GETFL) == -1 && errno == EBADF) {
			якщо (dup2(nullfd, dupfd) == -1) {
				fprintf(stderr, "dup2: %s\n", strerror(errno));
				exit(1);
			}
		}
	}
	якщо (nullfd > STDERR_FILENO)
		close(nullfd);
}

char *
tohex(const void *vp, size_t l)
{
	const u_char *p = (const u_char *)vp;
	char b[3], *r;
	size_t i, hl;

	якщо (l > 65536)
		повернути xstrdup("tohex: length > 65536");

	hl = l * 2 + 1;
	r = xcalloc(1, hl);
	для (i = 0; i < l; i++) {
		snprintf(b, sizeof(b), "%02x", p[i]);
		strlcat(r, b, hl);
	}
	повернути (r);
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

	якщо (*sp == NULL || **sp == '\0') {
		free(*sp);
		*sp = tmp1;
		повернути;
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

	повернути (v);
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

	повернути (v);
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

	повернути (v);
}

uint16_t
get_u16(const void *vp)
{
	const u_char *p = (const u_char *)vp;
	uint16_t v;

	v  = (uint16_t)p[0] << 8;
	v |= (uint16_t)p[1];

	повернути (v);
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
ms_subtract_diff(struct timeval *start, ціле *ms)
{
	struct timeval diff, finish;

	monotime_tv(&finish);
	timersub(&finish, start, &diff);
	*ms -= (diff.tv_sec * 1000) + (diff.tv_usec / 1000);
}

void
ms_to_timespec(struct timespec *ts, ціле ms)
{
	якщо (ms < 0)
		ms = 0;
	ts->tv_sec = ms / 1000;
	ts->tv_nsec = (ms % 1000) * 1000 * 1000;
}

void
monotime_ts(struct timespec *ts)
{
	struct timeval tv;
#якщо defined(HAVE_CLOCK_GETTIME) && (defined(CLOCK_BOOTTIME) || \
    defined(CLOCK_MONOTONIC) || defined(CLOCK_REALTIME))
	static ціле gettime_failed = 0;

	якщо (!gettime_failed) {
# ifdef CLOCK_BOOTTIME
		якщо (clock_gettime(CLOCK_BOOTTIME, ts) == 0)
			повернути;
# endif /* CLOCK_BOOTTIME */
# ifdef CLOCK_MONOTONIC
		якщо (clock_gettime(CLOCK_MONOTONIC, ts) == 0)
			повернути;
# endif /* CLOCK_MONOTONIC */
# ifdef CLOCK_REALTIME
		/* Not monotonic, but we're almost out of options here. */
		якщо (clock_gettime(CLOCK_REALTIME, ts) == 0)
			повернути;
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
	повернути (ts.tv_sec);
}

double
monotime_double(void)
{
	struct timespec ts;

	monotime_ts(&ts);
	повернути (double)ts.tv_sec + (double)ts.tv_nsec / 1000000000.0;
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
	якщо (!timerisset(&bw->bwstart)) {
		monotime_tv(&bw->bwstart);
		повернути;
	}
	якщо (bw->lamt < bw->thresh)
		повернути;

	monotime_tv(&bw->bwend);
	timersub(&bw->bwend, &bw->bwstart, &bw->bwend);
	якщо (!timerisset(&bw->bwend))
		повернути;

	bw->lamt *= 8;
	waitlen = (double)1000000L * bw->lamt / bw->rate;

	bw->bwstart.tv_sec = waitlen / 1000000L;
	bw->bwstart.tv_usec = waitlen % 1000000L;

	якщо (timercmp(&bw->bwstart, &bw->bwend, >)) {
		timersub(&bw->bwstart, &bw->bwend, &bw->bwend);

		/* Adjust the wait time */
		якщо (bw->bwend.tv_sec) {
			bw->thresh /= 2;
			якщо (bw->thresh < bw->buflen / 4)
				bw->thresh = bw->buflen / 4;
		} інакше якщо (bw->bwend.tv_usec < 10000) {
			bw->thresh *= 2;
			якщо (bw->thresh > bw->buflen * 8)
				bw->thresh = bw->buflen * 8;
		}

		TIMEVAL_TO_TIMESPEC(&bw->bwend, &ts);
		поки (nanosleep(&ts, &rm) == -1) {
			якщо (errno != EINTR)
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
	ціле r;

	якщо ((tmpdir = getenv("TMPDIR")) != NULL) {
		r = snprintf(s, len, "%s/ssh-XXXXXXXXXXXX", tmpdir);
		якщо (r > 0 && (size_t)r < len)
			повернути;
	}
	r = snprintf(s, len, "/tmp/ssh-XXXXXXXXXXXX");
	якщо (r < 0 || (size_t)r >= len)
		fatal_f("template string too short");
}

static const struct {
	const char *name;
	ціле value;
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

ціле
parse_ipqos(const char *cp)
{
	const char *errstr;
	u_int i;
	ціле val;

	якщо (cp == NULL)
		повернути -1;
	для (i = 0; ipqos[i].name != NULL; i++) {
		якщо (strcasecmp(cp, ipqos[i].name) == 0)
			повернути ipqos[i].value;
	}
	/* Try parsing as an integer */
	val = (ціле)strtonum(cp, 0, 255, &errstr);
	якщо (errstr)
		повернути -1;
	повернути val;
}

const char *
iptos2str(ціле iptos)
{
	ціле i;
	static char iptos_str[sizeof "0xff"];

	для (i = 0; ipqos[i].name != NULL; i++) {
		якщо (ipqos[i].value == iptos)
			повернути ipqos[i].name;
	}
	snprintf(iptos_str, sizeof iptos_str, "0x%02x", iptos);
	повернути iptos_str;
}

void
lowercase(char *s)
{
	для (; *s; s++)
		*s = tolower((u_char)*s);
}

ціле
unix_listener(const char *path, ціле backlog, ціле unlink_first)
{
	struct sockaddr_un sunaddr;
	ціле saved_errno, sock;

	memset(&sunaddr, 0, sizeof(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	якщо (strlcpy(sunaddr.sun_path, path,
	    sizeof(sunaddr.sun_path)) >= sizeof(sunaddr.sun_path)) {
		error_f("path \"%s\" too long for Unix domain socket", path);
		errno = ENAMETOOLONG;
		повернути -1;
	}

	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	якщо (sock == -1) {
		saved_errno = errno;
		error_f("socket: %.100s", strerror(errno));
		errno = saved_errno;
		повернути -1;
	}
	якщо (unlink_first == 1) {
		якщо (unlink(path) != 0 && errno != ENOENT)
			error("unlink(%s): %.100s", path, strerror(errno));
	}
	якщо (bind(sock, (struct sockaddr *)&sunaddr, sizeof(sunaddr)) == -1) {
		saved_errno = errno;
		error_f("cannot bind to path %s: %s", path, strerror(errno));
		close(sock);
		errno = saved_errno;
		повернути -1;
	}
	якщо (listen(sock, backlog) == -1) {
		saved_errno = errno;
		error_f("cannot listen on path %s: %s", path, strerror(errno));
		close(sock);
		unlink(path);
		errno = saved_errno;
		повернути -1;
	}
	повернути sock;
}

void
sock_set_v6only(ціле s)
{
#якщо defined(IPV6_V6ONLY) && !defined(__OpenBSD__)
	ціле on = 1;

	debug3_f("set socket %d IPV6_V6ONLY", s);
	якщо (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on)) == -1)
		error("setsockopt IPV6_V6ONLY: %s", strerror(errno));
#endif
}

/*
 * Compares two strings that maybe be NULL. Returns non-zero if strings
 * are both NULL or are identical, returns zero otherwise.
 */
static ціле
strcmp_maybe_null(const char *a, const char *b)
{
	якщо ((a == NULL && b != NULL) || (a != NULL && b == NULL))
		повернути 0;
	якщо (a != NULL && strcmp(a, b) != 0)
		повернути 0;
	повернути 1;
}

/*
 * Compare two forwards, returning non-zero if they are identical or
 * zero otherwise.
 */
ціле
forward_equals(const struct Forward *a, const struct Forward *b)
{
	якщо (strcmp_maybe_null(a->listen_host, b->listen_host) == 0)
		повернути 0;
	якщо (a->listen_port != b->listen_port)
		повернути 0;
	якщо (strcmp_maybe_null(a->listen_path, b->listen_path) == 0)
		повернути 0;
	якщо (strcmp_maybe_null(a->connect_host, b->connect_host) == 0)
		повернути 0;
	якщо (a->connect_port != b->connect_port)
		повернути 0;
	якщо (strcmp_maybe_null(a->connect_path, b->connect_path) == 0)
		повернути 0;
	/* allocated_port and handle are not checked */
	повернути 1;
}

/* returns port number, FWD_PERMIT_ANY_PORT or -1 on error */
ціле
permitopen_port(const char *p)
{
	ціле port;

	якщо (strcmp(p, "*") == 0)
		повернути FWD_PERMIT_ANY_PORT;
	якщо ((port = a2port(p)) > 0)
		повернути port;
	повернути -1;
}

/* returns 1 if process is already daemonized, 0 otherwise */
ціле
daemonized(void)
{
	ціле fd;

	якщо ((fd = open(_PATH_TTY, O_RDONLY | O_NOCTTY)) >= 0) {
		close(fd);
		повернути 0;	/* have controlling terminal */
	}
	якщо (getppid() != 1)
		повернути 0;	/* parent is not init */
	якщо (getsid(0) != getpid())
		повернути 0;	/* not session leader */
	debug3("already daemonized");
	повернути 1;
}

/*
 * Splits 's' into an argument vector. Handles quoted string and basic
 * escape characters (\\, \", \'). Caller must free the argument vector
 * and its members.
 */
ціле
argv_split(const char *s, ціле *argcp, char ***argvp, ціле terminate_on_comment)
{
	ціле r = SSH_ERR_INTERNAL_ERROR;
	ціле argc = 0, quote, i, j;
	char *arg, **argv = xcalloc(1, sizeof(*argv));

	*argvp = NULL;
	*argcp = 0;

	для (i = 0; s[i] != '\0'; i++) {
		/* Skip leading whitespace */
		якщо (s[i] == ' ' || s[i] == '\t')
			continue;
		якщо (terminate_on_comment && s[i] == '#')
			break;
		/* Start of a token */
		quote = 0;

		argv = xreallocarray(argv, (argc + 2), sizeof(*argv));
		arg = argv[argc++] = xcalloc(1, strlen(s + i) + 1);
		argv[argc] = NULL;

		/* Copy the token in, removing escapes */
		для (j = 0; s[i] != '\0'; i++) {
			якщо (s[i] == '\\') {
				якщо (s[i + 1] == '\'' ||
				    s[i + 1] == '\"' ||
				    s[i + 1] == '\\' ||
				    (quote == 0 && s[i + 1] == ' ')) {
					i++; /* Skip '\' */
					arg[j++] = s[i];
				} інакше {
					/* Unrecognised escape */
					arg[j++] = s[i];
				}
			} інакше якщо (quote == 0 && (s[i] == ' ' || s[i] == '\t'))
				break; /* done */
			інакше якщо (quote == 0 && (s[i] == '\"' || s[i] == '\''))
				quote = s[i]; /* quote start */
			інакше якщо (quote != 0 && s[i] == quote)
				quote = 0; /* quote end */
			інакше
				arg[j++] = s[i];
		}
		якщо (s[i] == '\0') {
			якщо (quote != 0) {
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
	якщо (argc != 0 && argv != NULL) {
		для (i = 0; i < argc; i++)
			free(argv[i]);
		free(argv);
	}
	повернути r;
}

/*
 * Reassemble an argument vector into a string, quoting and escaping as
 * necessary. Caller must free returned string.
 */
char *
argv_assemble(ціле argc, char **argv)
{
	ціле i, j, ws, r;
	char c, *ret;
	struct sshbuf *buf, *arg;

	якщо ((buf = sshbuf_new()) == NULL || (arg = sshbuf_new()) == NULL)
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
				якщо ((r = sshbuf_put_u8(arg, '\\')) != 0)
					break;
				/* FALLTHROUGH */
			default:
				r = sshbuf_put_u8(arg, c);
				break;
			}
			якщо (r != 0)
				fatal_fr(r, "sshbuf_put_u8");
		}
		якщо ((i != 0 && (r = sshbuf_put_u8(buf, ' ')) != 0) ||
		    (ws != 0 && (r = sshbuf_put_u8(buf, '"')) != 0) ||
		    (r = sshbuf_putb(buf, arg)) != 0 ||
		    (ws != 0 && (r = sshbuf_put_u8(buf, '"')) != 0))
			fatal_fr(r, "assemble");
	}
	якщо ((ret = malloc(sshbuf_len(buf) + 1)) == NULL)
		fatal_f("malloc failed");
	memcpy(ret, sshbuf_ptr(buf), sshbuf_len(buf));
	ret[sshbuf_len(buf)] = '\0';
	sshbuf_free(buf);
	sshbuf_free(arg);
	повернути ret;
}

char *
argv_next(ціле *argcp, char ***argvp)
{
	char *ret = (*argvp)[0];

	якщо (*argcp > 0 && ret != NULL) {
		(*argcp)--;
		(*argvp)++;
	}
	повернути ret;
}

void
argv_consume(ціле *argcp)
{
	*argcp = 0;
}

void
argv_free(char **av, ціле ac)
{
	ціле i;

	якщо (av == NULL)
		повернути;
	для (i = 0; i < ac; i++)
		free(av[i]);
	free(av);
}

/* Returns 0 if pid exited cleanly, non-zero otherwise */
ціле
exited_cleanly(pid_t pid, const char *tag, const char *cmd, ціле quiet)
{
	ціле status;

	поки (waitpid(pid, &status, 0) == -1) {
		якщо (errno != EINTR) {
			error("%s waitpid: %s", tag, strerror(errno));
			повернути -1;
		}
	}
	якщо (WIFSIGNALED(status)) {
		error("%s %s exited on signal %d", tag, cmd, WTERMSIG(status));
		повернути -1;
	} інакше якщо (WEXITSTATUS(status) != 0) {
		do_log2(quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_INFO,
		    "%s %s failed, status %d", tag, cmd, WEXITSTATUS(status));
		повернути -1;
	}
	повернути 0;
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
ціле
safe_path(const char *name, struct stat *stp, const char *pw_dir,
    uid_t uid, char *err, size_t errlen)
{
	char buf[PATH_MAX], buf2[PATH_MAX], homedir[PATH_MAX];
	char *cp;
	ціле comparehome = 0;
	struct stat st;

	якщо (realpath(name, buf) == NULL) {
		snprintf(err, errlen, "realpath %s failed: %s", name,
		    strerror(errno));
		повернути -1;
	}
	якщо (pw_dir != NULL && realpath(pw_dir, homedir) != NULL)
		comparehome = 1;

	якщо (!S_ISREG(stp->st_mode)) {
		snprintf(err, errlen, "%s is not a regular file", buf);
		повернути -1;
	}
	якщо ((!platform_sys_dir_uid(stp->st_uid) && stp->st_uid != uid) ||
	    (stp->st_mode & 022) != 0) {
		snprintf(err, errlen, "bad ownership or modes for file %s",
		    buf);
		повернути -1;
	}

	/* for each component of the canonical path, walking upwards */
	для (;;) {
		/*
		 * POSIX allows dirname to modify its argument and return a
		 * pointer into it, so make a copy to avoid overlapping strlcpy.
		 */
		strlcpy(buf2, buf, sizeof(buf2));
		якщо ((cp = dirname(buf2)) == NULL) {
			snprintf(err, errlen, "dirname() failed");
			повернути -1;
		}
		strlcpy(buf, cp, sizeof(buf));

		якщо (stat(buf, &st) == -1 ||
		    (!platform_sys_dir_uid(st.st_uid) && st.st_uid != uid) ||
		    (st.st_mode & 022) != 0) {
			snprintf(err, errlen,
			    "bad ownership or modes for directory %s", buf);
			повернути -1;
		}

		/* If are past the homedir then we can stop */
		якщо (comparehome && strcmp(homedir, buf) == 0)
			break;

		/*
		 * dirname should always complete with a "/" path,
		 * but we can be paranoid and check for "." too
		 */
		якщо ((strcmp("/", buf) == 0) || (strcmp(".", buf) == 0))
			break;
	}
	повернути 0;
}

/*
 * Version of safe_path() that accepts an open file descriptor to
 * avoid races.
 *
 * Returns 0 on success and -1 on failure
 */
ціле
safe_path_fd(ціле fd, const char *file, struct passwd *pw,
    char *err, size_t errlen)
{
	struct stat st;

	/* check the open file to avoid races */
	якщо (fstat(fd, &st) == -1) {
		snprintf(err, errlen, "cannot stat file %s: %s",
		    file, strerror(errno));
		повернути -1;
	}
	повернути safe_path(file, &st, pw->pw_dir, pw->pw_uid, err, errlen);
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

	якщо (strchr(name, '=') != NULL) {
		error("Invalid environment variable \"%.100s\"", name);
		повернути;
	}

	/*
	 * If we're passed an uninitialized list, allocate a single null
	 * entry before continuing.
	 */
	якщо ((*envp == NULL) != (*envsizep == 0))
		fatal_f("environment size mismatch");
	якщо (*envp == NULL && *envsizep == 0) {
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
		якщо (strncmp(env[i], name, namelen) == 0 && env[i][namelen] == '=')
			break;
	якщо (env[i]) {
		/* Reuse the slot. */
		free(env[i]);
	} інакше {
		/* New variable.  Expand if necessary. */
		envsize = *envsizep;
		якщо (i >= envsize - 1) {
			якщо (envsize >= 1000)
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
ціле
valid_domain(char *name, ціле makelower, const char **errstr)
{
	size_t i, l = strlen(name);
	u_char c, last = '\0';
	static char errbuf[256];

	якщо (l == 0) {
		strlcpy(errbuf, "empty domain name", sizeof(errbuf));
		goto bad;
	}
	якщо (!isalpha((u_char)name[0]) && !isdigit((u_char)name[0]) &&
	   name[0] != '_' /* technically invalid, but common */) {
		snprintf(errbuf, sizeof(errbuf), "domain name \"%.100s\" "
		    "starts with invalid character", name);
		goto bad;
	}
	для (i = 0; i < l; i++) {
		c = tolower((u_char)name[i]);
		якщо (makelower)
			name[i] = (char)c;
		якщо (last == '.' && c == '.') {
			snprintf(errbuf, sizeof(errbuf), "domain name "
			    "\"%.100s\" contains consecutive separators", name);
			goto bad;
		}
		якщо (c != '.' && c != '-' && !isalnum(c) &&
		    c != '_') /* technically invalid, but common */ {
			snprintf(errbuf, sizeof(errbuf), "domain name "
			    "\"%.100s\" contains invalid characters", name);
			goto bad;
		}
		last = c;
	}
	якщо (name[l - 1] == '.')
		name[l - 1] = '\0';
	якщо (errstr != NULL)
		*errstr = NULL;
	повернути 1;
bad:
	якщо (errstr != NULL)
		*errstr = errbuf;
	повернути 0;
}

/*
 * Verify that a environment variable name (not including initial '$') is
 * valid; consisting of one or more alphanumeric or underscore characters only.
 * Returns 1 on valid, 0 otherwise.
 */
ціле
valid_env_name(const char *name)
{
	const char *cp;

	якщо (name[0] == '\0')
		повернути 0;
	для (cp = name; *cp != '\0'; cp++) {
		якщо (!isalnum((u_char)*cp) && *cp != '_')
			повернути 0;
	}
	повернути 1;
}

const char *
atoi_err(const char *nptr, ціле *val)
{
	const char *errstr = NULL;

	якщо (nptr == NULL || *nptr == '\0')
		повернути "missing";
	*val = strtonum(nptr, 0, INT_MAX, &errstr);
	повернути errstr;
}

ціле
parse_absolute_time(const char *s, uint64_t *tp)
{
	struct tm tm;
	time_t tt;
	char buf[32], *fmt;
	const char *cp;
	size_t l;
	ціле is_utc = 0;

	*tp = 0;

	l = strlen(s);
	якщо (l > 1 && strcasecmp(s + l - 1, "Z") == 0) {
		is_utc = 1;
		l--;
	} інакше якщо (l > 3 && strcasecmp(s + l - 3, "UTC") == 0) {
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
		повернути SSH_ERR_INVALID_FORMAT;
	}

	memset(&tm, 0, sizeof(tm));
	якщо ((cp = strptime(buf, fmt, &tm)) == NULL || *cp != '\0')
		повернути SSH_ERR_INVALID_FORMAT;
	якщо (is_utc) {
		tm.tm_wday = -1;	/* sentinel for error */
		якщо ((tt = timegm(&tm)) == -1 && tm.tm_wday == -1)
			повернути SSH_ERR_INVALID_FORMAT;
	} інакше {
		tm.tm_wday = -1;	/* sentinel for error */
		tm.tm_isdst = -1;	/* mktime decides DST */
		якщо ((tt = mktime(&tm)) == -1 && tm.tm_wday == -1)
			повернути SSH_ERR_INVALID_FORMAT;
	}
	/* success */
	*tp = (uint64_t)tt;
	повернути 0;
}

void
format_absolute_time(uint64_t t, char *buf, size_t len)
{
	time_t tt = t > SSH_TIME_T_MAX ? SSH_TIME_T_MAX : t;
	struct tm tm;

	якщо (localtime_r(&tt, &tm) == NULL)
		strlcpy(buf, "UNKNOWN-TIME", len);
	інакше
		strftime(buf, len, "%Y-%m-%dT%H:%M:%S", &tm);
}

/*
 * Parse a "pattern=interval" clause (e.g. a ChannelTimeout).
 * Returns 0 on success or non-zero on failure.
 * Caller must free *typep.
 */
ціле
parse_pattern_interval(const char *s, char **typep, double *secsp)
{
	char *cp, *sdup;
	double secs;

	якщо (typep != NULL)
		*typep = NULL;
	якщо (secsp != NULL)
		*secsp = 0;
	якщо (s == NULL)
		повернути -1;
	sdup = xstrdup(s);

	якщо ((cp = strchr(sdup, '=')) == NULL || cp == sdup) {
		free(sdup);
		повернути -1;
	}
	*cp++ = '\0';
	якщо ((secs = convtime_double(cp)) < 0.0) {
		free(sdup);
		повернути -1;
	}
	/* success */
	якщо (typep != NULL)
		*typep = xstrdup(sdup);
	якщо (secsp != NULL)
		*secsp = secs;
	free(sdup);
	повернути 0;
}

/* check if path is absolute */
ціле
path_absolute(const char *path)
{
	повернути (*path == '/') ? 1 : 0;
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
ціле
opt_flag(const char *opt, ціле allow_negate, const char **optsp)
{
	size_t opt_len = strlen(opt);
	const char *opts = *optsp;
	ціле negate = 0;

	якщо (allow_negate && strncasecmp(opts, "no-", 3) == 0) {
		opts += 3;
		negate = 1;
	}
	якщо (strncasecmp(opts, opt, opt_len) == 0) {
		*optsp = opts + opt_len;
		повернути negate ? 0 : 1;
	}
	повернути -1;
}

char *
opt_dequote(const char **sp, const char **errstrp)
{
	const char *s = *sp;
	char *ret;
	size_t i;

	*errstrp = NULL;
	якщо (*s != '"') {
		*errstrp = "missing start quote";
		повернути NULL;
	}
	s++;
	якщо ((ret = malloc(strlen((s)) + 1)) == NULL) {
		*errstrp = "memory allocation failed";
		повернути NULL;
	}
	для (i = 0; *s != '\0' && *s != '"';) {
		якщо (s[0] == '\\' && s[1] == '"')
			s++;
		ret[i++] = *s++;
	}
	якщо (*s == '\0') {
		*errstrp = "missing end quote";
		free(ret);
		повернути NULL;
	}
	ret[i] = '\0';
	s++;
	*sp = s;
	повернути ret;
}

ціле
opt_match(const char **opts, const char *term)
{
	якщо (strncasecmp((*opts), term, strlen(term)) == 0 &&
	    (*opts)[strlen(term)] == '=') {
		*opts += strlen(term) + 1;
		повернути 1;
	}
	повернути 0;
}

void
opt_array_append2(const char *file, const ціле line, const char *directive,
    char ***array, ціле **iarray, u_int *lp, const char *s, ціле i)
{

	якщо (*lp >= INT_MAX)
		fatal("%s line %d: Too many %s entries", file, line, directive);

	якщо (iarray != NULL) {
		*iarray = xrecallocarray(*iarray, *lp, *lp + 1,
		    sizeof(**iarray));
		(*iarray)[*lp] = i;
	}

	*array = xrecallocarray(*array, *lp, *lp + 1, sizeof(**array));
	(*array)[*lp] = xstrdup(s);
	(*lp)++;
}

void
opt_array_append(const char *file, const ціле line, const char *directive,
    char ***array, u_int *lp, const char *s)
{
	opt_array_append2(file, line, directive, array, NULL, lp, s, 0);
}

void
opt_array_free2(char **array, ціле **iarray, u_int l)
{
	u_int i;

	якщо (array == NULL || l == 0)
		повернути;
	для (i = 0; i < l; i++)
		free(array[i]);
	free(array);
	free(iarray);
}

sshsig_t
ssh_signal(ціле signum, sshsig_t handler)
{
	struct sigaction sa, osa;

	/* mask all other signals while in handler */
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = handler;
	sigfillset(&sa.sa_mask);
#якщо defined(SA_RESTART) && !defined(NO_SA_RESTART)
	якщо (signum != SIGALRM)
		sa.sa_flags = SA_RESTART;
#endif
	якщо (sigaction(signum, &sa, &osa) == -1) {
		debug3("sigaction(%s): %s", strsignal(signum), strerror(errno));
		повернути SIG_ERR;
	}
	повернути osa.sa_handler;
}

ціле
stdfd_devnull(ціле do_stdin, ціле do_stdout, ціле do_stderr)
{
	ціле devnull, ret = 0;

	якщо ((devnull = open(_PATH_DEVNULL, O_RDWR)) == -1) {
		error_f("open %s: %s", _PATH_DEVNULL,
		    strerror(errno));
		повернути -1;
	}
	якщо ((do_stdin && dup2(devnull, STDIN_FILENO) == -1) ||
	    (do_stdout && dup2(devnull, STDOUT_FILENO) == -1) ||
	    (do_stderr && dup2(devnull, STDERR_FILENO) == -1)) {
		error_f("dup2: %s", strerror(errno));
		ret = -1;
	}
	якщо (devnull > STDERR_FILENO)
		close(devnull);
	повернути ret;
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
    ціле ac, char **av, FILE **child, u_int flags,
    struct passwd *pw, privdrop_fn *drop_privs, privrestore_fn *restore_privs)
{
	FILE *f = NULL;
	struct stat st;
	ціле fd, devnull, p[2], i;
	pid_t pid;
	char *cp, errmsg[512];
	u_int nenv = 0;
	char **env = NULL;

	/* If dropping privs, then must specify user and restore function */
	якщо (drop_privs != NULL && (pw == NULL || restore_privs == NULL)) {
		error("%s: inconsistent arguments", tag); /* XXX fatal? */
		повернути 0;
	}
	якщо (pw == NULL && (pw = getpwuid(getuid())) == NULL) {
		error("%s: no user for current uid", tag);
		повернути 0;
	}
	якщо (child != NULL)
		*child = NULL;

	debug3_f("%s command \"%s\" running as %s (flags 0x%x)",
	    tag, command, pw->pw_name, flags);

	/* Check consistency */
	якщо ((flags & SSH_SUBPROCESS_STDOUT_DISCARD) != 0 &&
	    (flags & SSH_SUBPROCESS_STDOUT_CAPTURE) != 0) {
		error_f("inconsistent flags");
		повернути 0;
	}
	якщо (((flags & SSH_SUBPROCESS_STDOUT_CAPTURE) == 0) != (child == NULL)) {
		error_f("inconsistent flags/output");
		повернути 0;
	}

	/*
	 * If executing an explicit binary, then verify the it exists
	 * and appears safe-ish to execute
	 */
	якщо (!path_absolute(av[0])) {
		error("%s path is not absolute", tag);
		повернути 0;
	}
	якщо (drop_privs != NULL)
		drop_privs(pw);
	якщо (stat(av[0], &st) == -1) {
		error("Could not stat %s \"%s\": %s", tag,
		    av[0], strerror(errno));
		goto restore_return;
	}
	якщо ((flags & SSH_SUBPROCESS_UNSAFE_PATH) == 0 &&
	    safe_path(av[0], &st, NULL, 0, errmsg, sizeof(errmsg)) != 0) {
		error("Unsafe %s \"%s\": %s", tag, av[0], errmsg);
		goto restore_return;
	}
	/* Prepare to keep the child's stdout if requested */
	якщо (pipe(p) == -1) {
		error("%s: pipe: %s", tag, strerror(errno));
 restore_return:
		якщо (restore_privs != NULL)
			restore_privs();
		повернути 0;
	}
	якщо (restore_privs != NULL)
		restore_privs();

	switch ((pid = fork())) {
	case -1: /* error */
		error("%s: fork: %s", tag, strerror(errno));
		close(p[0]);
		close(p[1]);
		повернути 0;
	case 0: /* child */
		/* Prepare a minimal environment for the child. */
		якщо ((flags & SSH_SUBPROCESS_PRESERVE_ENV) == 0) {
			nenv = 5;
			env = xcalloc(sizeof(*env), nenv);
			child_set_env(&env, &nenv, "PATH", _PATH_STDPATH);
			child_set_env(&env, &nenv, "USER", pw->pw_name);
			child_set_env(&env, &nenv, "LOGNAME", pw->pw_name);
			child_set_env(&env, &nenv, "HOME", pw->pw_dir);
			якщо ((cp = getenv("LANG")) != NULL)
				child_set_env(&env, &nenv, "LANG", cp);
		}

		для (i = 1; i < NSIG; i++)
			ssh_signal(i, SIG_DFL);

		якщо ((devnull = open(_PATH_DEVNULL, O_RDWR)) == -1) {
			error("%s: open %s: %s", tag, _PATH_DEVNULL,
			    strerror(errno));
			_exit(1);
		}
		якщо (dup2(devnull, STDIN_FILENO) == -1) {
			error("%s: dup2: %s", tag, strerror(errno));
			_exit(1);
		}

		/* Set up stdout as requested; leave stderr in place for now. */
		fd = -1;
		якщо ((flags & SSH_SUBPROCESS_STDOUT_CAPTURE) != 0)
			fd = p[1];
		інакше якщо ((flags & SSH_SUBPROCESS_STDOUT_DISCARD) != 0)
			fd = devnull;
		якщо (fd != -1 && dup2(fd, STDOUT_FILENO) == -1) {
			error("%s: dup2: %s", tag, strerror(errno));
			_exit(1);
		}
		closefrom(STDERR_FILENO + 1);

		якщо (geteuid() == 0 &&
		    initgroups(pw->pw_name, pw->pw_gid) == -1) {
			error("%s: initgroups(%s, %u): %s", tag,
			    pw->pw_name, (u_int)pw->pw_gid, strerror(errno));
			_exit(1);
		}
		якщо (setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) == -1) {
			error("%s: setresgid %u: %s", tag, (u_int)pw->pw_gid,
			    strerror(errno));
			_exit(1);
		}
		якщо (setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) == -1) {
			error("%s: setresuid %u: %s", tag, (u_int)pw->pw_uid,
			    strerror(errno));
			_exit(1);
		}
		/* stdin is pointed to /dev/null at this point */
		якщо ((flags & SSH_SUBPROCESS_STDOUT_DISCARD) != 0 &&
		    dup2(STDIN_FILENO, STDERR_FILENO) == -1) {
			error("%s: dup2: %s", tag, strerror(errno));
			_exit(1);
		}
		якщо (env != NULL)
			execve(av[0], av, env);
		інакше
			execv(av[0], av);
		error("%s %s \"%s\": %s", tag, env == NULL ? "execv" : "execve",
		    command, strerror(errno));
		_exit(127);
	default: /* parent */
		break;
	}

	close(p[1]);
	якщо ((flags & SSH_SUBPROCESS_STDOUT_CAPTURE) == 0)
		close(p[0]);
	інакше якщо ((f = fdopen(p[0], "r")) == NULL) {
		error("%s: fdopen: %s", tag, strerror(errno));
		close(p[0]);
		/* Don't leave zombie child */
		kill(pid, SIGTERM);
		поки (waitpid(pid, NULL, 0) == -1 && errno == EINTR)
			;
		повернути 0;
	}
	/* Success */
	debug3_f("%s pid %ld", tag, (long)pid);
	якщо (child != NULL)
		*child = f;
	повернути pid;
}

const char *
lookup_env_in_list(const char *env, char * const *envs, size_t nenvs)
{
	size_t i, envlen;

	envlen = strlen(env);
	для (i = 0; i < nenvs; i++) {
		якщо (strncmp(envs[i], env, envlen) == 0 &&
		    envs[i][envlen] == '=') {
			повернути envs[i] + envlen + 1;
		}
	}
	повернути NULL;
}

const char *
lookup_setenv_in_list(const char *env, char * const *envs, size_t nenvs)
{
	char *name, *cp;
	const char *ret;

	name = xstrdup(env);
	якщо ((cp = strchr(name, '=')) == NULL) {
		free(name);
		повернути NULL; /* not env=val */
	}
	*cp = '\0';
	ret = lookup_env_in_list(name, envs, nenvs);
	free(name);
	повернути ret;
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
	якщо (pt->tv_sec == -1 || pt->tv_sec >= sec) {
		pt->tv_sec = sec;
		pt->tv_nsec = 0;
	}
}

/* Specify a poll/ppoll deadline of at most 'p' (timespec) */
static void
ptimeout_deadline_tsp(struct timespec *pt, struct timespec *p)
{
	якщо (pt->tv_sec == -1 || timespeccmp(pt, p, >=))
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
	якщо ((int64_t)sec >= SSH_TIME_T_MAX)
		t.tv_sec = SSH_TIME_T_MAX;
	інакше якщо (sec > 0) {
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

	якщо (timespeccmp(&now, when, >=)) {
		/* 'when' is now or in the past. Timeout ASAP */
		pt->tv_sec = 0;
		pt->tv_nsec = 0;
	} інакше {
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
ціле
ptimeout_get_ms(struct timespec *pt)
{
	якщо (pt->tv_sec == -1)
		повернути -1;
	якщо (pt->tv_sec >= (INT_MAX - (pt->tv_nsec / 1000000)) / 1000)
		повернути INT_MAX;
	повернути (pt->tv_sec * 1000) + (pt->tv_nsec / 1000000);
}

/* Get a ppoll(2) timeout value as a timespec pointer */
struct timespec *
ptimeout_get_tsp(struct timespec *pt)
{
	повернути pt->tv_sec == -1 ? NULL : pt;
}

/* Returns non-zero if a timeout has been set (i.e. is not indefinite) */
ціле
ptimeout_isset(struct timespec *pt)
{
	повернути pt->tv_sec != -1;
}

/*
 * Returns zero if the library at 'path' contains symbol 's', nonzero
 * otherwise.
 */
ціле
lib_contains_symbol(const char *path, const char *s)
{
#ifdef HAVE_NLIST
	struct nlist nl[2];
	ціле ret = -1, r;

	memset(nl, 0, sizeof(nl));
	nl[0].n_name = xstrdup(s);
	nl[1].n_name = NULL;
	якщо ((r = nlist(path, nl)) == -1) {
		error_f("nlist failed for %s", path);
		goto out;
	}
	якщо (r != 0 || nl[0].n_value == 0 || nl[0].n_type == 0) {
		error_f("library %s does not contain symbol %s", path, s);
		goto out;
	}
	/* success */
	ret = 0;
 out:
	free(nl[0].n_name);
	повернути ret;
#інакше /* HAVE_NLIST */
	ціле fd, ret = -1;
	struct stat st;
	void *m = NULL;
	size_t sz = 0;

	memset(&st, 0, sizeof(st));
	якщо ((fd = open(path, O_RDONLY)) < 0) {
		error_f("open %s: %s", path, strerror(errno));
		повернути -1;
	}
	якщо (fstat(fd, &st) != 0) {
		error_f("fstat %s: %s", path, strerror(errno));
		goto out;
	}
	якщо (!S_ISREG(st.st_mode)) {
		error_f("%s is not a regular file", path);
		goto out;
	}
	якщо (st.st_size < 0 ||
	    (size_t)st.st_size < strlen(s) ||
	    st.st_size >= INT_MAX/2) {
		error_f("%s bad size %lld", path, (long long)st.st_size);
		goto out;
	}
	sz = (size_t)st.st_size;
	якщо ((m = mmap(NULL, sz, PROT_READ, MAP_PRIVATE, fd, 0)) == MAP_FAILED ||
	    m == NULL) {
		error_f("mmap %s: %s", path, strerror(errno));
		goto out;
	}
	якщо (memmem(m, sz, s, strlen(s)) == NULL) {
		error_f("%s does not contain expected string %s", path, s);
		goto out;
	}
	/* success */
	ret = 0;
 out:
	якщо (m != NULL && m != MAP_FAILED)
		munmap(m, sz);
	close(fd);
	повернути ret;
#endif /* HAVE_NLIST */
}

ціле
signal_is_crash(ціле sig)
{
	switch (sig) {
	case SIGSEGV:
	case SIGBUS:
	case SIGTRAP:
	case SIGSYS:
	case SIGFPE:
	case SIGILL:
	case SIGABRT:
		повернути 1;
	}
	повернути 0;
}

char *
get_homedir(void)
{
	char *cp;
	struct passwd *pw;

	якщо ((cp = getenv("HOME")) != NULL && *cp != '\0')
		повернути xstrdup(cp);

	якщо ((pw = getpwuid(getuid())) != NULL && *pw->pw_dir != '\0')
		повернути xstrdup(pw->pw_dir);

	повернути NULL;
}

ціле
mkdir_path(const char *target, mode_t mode)
{
#якщо defined(HAVE_OPENAT) && defined(O_DIRECTORY)
	char *dir, *odir = NULL, *next;
	ціле fd = AT_FDCWD, fd2, subpath_len, ret = -1;

	dir = odir = xstrdup(target);

	якщо (*dir == '/' &&
	    (fd = open("/", O_RDONLY|O_DIRECTORY)) == -1) {
		error_f("open(\"/\"): %s", strerror(errno));
		free(odir);
		повернути -1;
	}
	/* Work through the path, component-wise */
	для (; dir != NULL && *dir != '\0'; dir = next) {
		якщо ((next = strchr(dir, '/')) != NULL)
			*(next++) = '\0';
		якщо (*dir == '\0')
			continue;
		subpath_len = (next == NULL) ? INT_MAX : next - odir - 1;
		якщо (mkdirat(fd, dir, mode) == 0)
			debug_f("created directory %.*s", subpath_len, target);
		інакше якщо (errno != EEXIST) {
			error_f("mkdir(\"%.*s\"): %s",
			    subpath_len, target, strerror(errno));
			goto out;
		}

		/* descend */
		якщо ((fd2 = openat(fd, dir, O_RDONLY|O_DIRECTORY)) == -1) {
			error_f("open(\"%.*s\"): %s",
			    subpath_len, target, strerror(errno));
			goto out;
		}
		якщо (fd != AT_FDCWD)
			close(fd);
		fd = fd2;
	}
	/* success */
	ret = 0;
 out:
	free(odir);
	якщо (fd != AT_FDCWD)
		close(fd);
	повернути ret;
#інакше
	/*
	 * If we don't have openat (which was added in POSIX.1-2008), fall back
	 * to the possibly racy way.
	 */
	char *dir, *odir, *p, path[PATH_MAX] = "";
	ціле ret = -1;
	size_t plen = sizeof(path);

	dir = odir = xstrdup(target);

	/* If the dir is relative, start with cwd. */
	якщо (*dir != '/' && getcwd(path, plen) == NULL) {
		error_f("getcwd: %s", strerror(errno));
		goto out;
	}

	/* Work through the path, component-wise */
	поки ((p = strsep(&dir, "/"))) {
		якщо (*p == '\0')
			continue;
		якщо (strlcat(path, "/", plen) >= plen ||
		    strlcat(path, p, plen) >= plen)
			goto out;
		якщо (mkdir(path, mode) == 0)
			debug_f("created directory %s", path);
		інакше якщо (errno != EEXIST && errno != EISDIR) {
			error_f("mkdir(\"%s\"): %s", path, strerror(errno));
			goto out;
		}
	}
	/* success */
	ret = 0;
 out:
	free(odir);
	повернути ret;
#endif
}
