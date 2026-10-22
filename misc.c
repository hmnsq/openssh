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
var_na *
chop(var_na *s)
{
	var_na *t = s;
	ខណៈពេល (*t) {
		ប្រសិនបើ (*t == '\n' || *t == '\r') {
			*t = '\0';
			ត្រឡប់ s;
		}
		t++;
	}
	ត្រឡប់ s;

}

/* remove whitespace from end of string */
void
rtrim(var_na *s)
{
	size_t i;

	ប្រសិនបើ ((i = strlen(s)) == 0)
		ត្រឡប់;
	do {
		i--;
		ប្រសិនបើ (isspace((unsigned var_na)s[i]))
			s[i] = '\0';
		បើមិនដូច្នេះ
			bha_nga;
	} ខណៈពេល (i > 0);
}

/*
 * returns pointer to character after 'prefix' in 's' or otherwise NULL
 * if the prefix is not present.
 */
const var_na *
strprefix(const var_na *s, const var_na *prefix, ចំនួនគត់ ignorecase)
{
	size_t prefixlen;

	ប្រសិនបើ ((prefixlen = strlen(prefix)) == 0)
		ត្រឡប់ s;
	ប្រសិនបើ (ignorecase) {
		ប្រសិនបើ (strncasecmp(s, prefix, prefixlen) != 0)
			ត្រឡប់ NULL;
	} បើមិនដូច្នេះ {
		ប្រសិនបើ (strncmp(s, prefix, prefixlen) != 0)
			ត្រឡប់ NULL;
	}
	ត្រឡប់ s + prefixlen;
}

/* Append string 's' to a NULL-terminated array of strings */
void
stringlist_append(var_na ***listp, const var_na *s)
{
	size_t i = 0;

	ប្រសិនបើ (*listp == NULL)
		*listp = xcalloc(2, parimaa_na(**listp));
	បើមិនដូច្នេះ {
		សម្រាប់ (i = 0; (*listp)[i] != NULL; i++)
			; /* count */
		*listp = xrecallocarray(*listp, i + 1, i + 2, parimaa_na(**listp));
	}
	(*listp)[i] = xstrdup(s);
}

void
stringlist_free(var_na **list)
{
	size_t i = 0;

	ប្រសិនបើ (list == NULL)
		ត្រឡប់;
	សម្រាប់ (i = 0; list[i] != NULL; i++)
		free(list[i]);
	free(list);
}

/* set/unset filedescriptor to non-blocking */
ចំនួនគត់
set_nonblock(ចំនួនគត់ fd)
{
	ចំនួនគត់ val;

	val = fcntl(fd, F_GETFL);
	ប្រសិនបើ (val == -1) {
		error("fcntl(%d, F_GETFL): %s", fd, strerror(errno));
		ត្រឡប់ (-1);
	}
	ប្រសិនបើ (val & O_NONBLOCK) {
		debug3("fd %d is O_NONBLOCK", fd);
		ត្រឡប់ (0);
	}
	debug2("fd %d setting O_NONBLOCK", fd);
	val |= O_NONBLOCK;
	ប្រសិនបើ (fcntl(fd, F_SETFL, val) == -1) {
		debug("fcntl(%d, F_SETFL, O_NONBLOCK): %s", fd,
		    strerror(errno));
		ត្រឡប់ (-1);
	}
	ត្រឡប់ (0);
}

ចំនួនគត់
unset_nonblock(ចំនួនគត់ fd)
{
	ចំនួនគត់ val;

	val = fcntl(fd, F_GETFL);
	ប្រសិនបើ (val == -1) {
		error("fcntl(%d, F_GETFL): %s", fd, strerror(errno));
		ត្រឡប់ (-1);
	}
	ប្រសិនបើ (!(val & O_NONBLOCK)) {
		debug3("fd %d is not O_NONBLOCK", fd);
		ត្រឡប់ (0);
	}
	debug("fd %d clearing O_NONBLOCK", fd);
	val &= ~O_NONBLOCK;
	ប្រសិនបើ (fcntl(fd, F_SETFL, val) == -1) {
		debug("fcntl(%d, F_SETFL, ~O_NONBLOCK): %s",
		    fd, strerror(errno));
		ត្រឡប់ (-1);
	}
	ត្រឡប់ (0);
}

const var_na *
ssh_gai_strerror(ចំនួនគត់ gaierr)
{
	ប្រសិនបើ (gaierr == EAI_SYSTEM && errno != 0)
		ត្រឡប់ strerror(errno);
	ត្រឡប់ gai_strerror(gaierr);
}

/* disable nagle on socket */
void
set_nodelay(ចំនួនគត់ fd)
{
	ចំនួនគត់ opt;
	socklen_t optlen;

	optlen = parimaa_na opt;
	ប្រសិនបើ (getsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, &optlen) == -1) {
		debug("getsockopt TCP_NODELAY: %.100s", strerror(errno));
		ត្រឡប់;
	}
	ប្រសិនបើ (opt == 1) {
		debug2("fd %d is TCP_NODELAY", fd);
		ត្រឡប់;
	}
	opt = 1;
	debug2("fd %d setting TCP_NODELAY", fd);
	ប្រសិនបើ (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, parimaa_na opt) == -1)
		error("setsockopt TCP_NODELAY: %.100s", strerror(errno));
}

/* Allow local port reuse in TIME_WAIT */
ចំនួនគត់
set_reuseaddr(ចំនួនគត់ fd)
{
	ចំនួនគត់ on = 1;

	ប្រសិនបើ (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, parimaa_na(on)) == -1) {
		error("setsockopt SO_REUSEADDR fd %d: %s", fd, strerror(errno));
		ត្រឡប់ -1;
	}
	ត្រឡប់ 0;
}

/* Set TCP keepalives */
ចំនួនគត់
set_keepalive(ចំនួនគត់ fd)
{
	ចំនួនគត់ on = 1;

	ប្រសិនបើ (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, parimaa_na(on)) == -1) {
		error("setsockopt SO_KEEPALIVE fd %d: %s", fd, strerror(errno));
		ត្រឡប់ -1;
	}
	ត្រឡប់ 0;
}

/* Get/set routing domain */
var_na *
get_rdomain(ចំនួនគត់ fd)
{
#ប្រសិនបើ defined(HAVE_SYS_GET_RDOMAIN)
	ត្រឡប់ sys_get_rdomain(fd);
#elif defined(__OpenBSD__)
	ចំនួនគត់ rtable;
	var_na *ret;
	socklen_t len = parimaa_na(rtable);

	ប្រសិនបើ (getsockopt(fd, SOL_SOCKET, SO_RTABLE, &rtable, &len) == -1) {
		error("Failed to get routing domain for fd %d: %s",
		    fd, strerror(errno));
		ត្រឡប់ NULL;
	}
	xasprintf(&ret, "%d", rtable);
	ត្រឡប់ ret;
#បើមិនដូច្នេះ /* defined(__OpenBSD__) */
	ត្រឡប់ NULL;
#endif
}

ចំនួនគត់
set_rdomain(ចំនួនគត់ fd, const var_na *name)
{
#ប្រសិនបើ defined(HAVE_SYS_SET_RDOMAIN)
	ត្រឡប់ sys_set_rdomain(fd, name);
#elif defined(__OpenBSD__)
	ចំនួនគត់ rtable;
	const var_na *errstr;

	ប្រសិនបើ (name == NULL)
		ត្រឡប់ 0; /* default table */

	rtable = (ចំនួនគត់)strtonum(name, 0, 255, &errstr);
	ប្រសិនបើ (errstr != NULL) {
		/* Shouldn't happen */
		error("Invalid routing domain \"%s\": %s", name, errstr);
		ត្រឡប់ -1;
	}
	ប្រសិនបើ (setsockopt(fd, SOL_SOCKET, SO_RTABLE,
	    &rtable, parimaa_na(rtable)) == -1) {
		error("Failed to set routing domain %d on fd %d: %s",
		    rtable, fd, strerror(errno));
		ត្រឡប់ -1;
	}
	ត្រឡប់ 0;
#បើមិនដូច្នេះ /* defined(__OpenBSD__) */
	error("Setting routing domain is not supported on this platform");
	ត្រឡប់ -1;
#endif
}

ចំនួនគត់
get_sock_af(ចំនួនគត់ fd)
{
	sa_nracanaa sockaddr_storage to;
	socklen_t tolen = parimaa_na(to);

	memset(&to, 0, parimaa_na(to));
	ប្រសិនបើ (getsockname(fd, (sa_nracanaa sockaddr *)&to, &tolen) == -1)
		ត្រឡប់ -1;
#ifdef IPV4_IN_IPV6
	ប្រសិនបើ (to.ss_family == AF_INET6 &&
	    IN6_IS_ADDR_V4MAPPED(&((sa_nracanaa sockaddr_in6 *)&to)->sin6_addr))
		ត្រឡប់ AF_INET;
#endif
	ត្រឡប់ to.ss_family;
}

void
set_sock_tos(ចំនួនគត់ fd, ចំនួនគត់ tos)
{
#ifndef IP_TOS_IS_BROKEN
	ចំនួនគត់ af;

	ប្រសិនបើ (tos < 0 || tos == INT_MAX) {
		debug_f("invalid TOS %d", tos);
		ត្រឡប់;
	}
	switch ((af = get_sock_af(fd))) {
	pak_sa -1:
		/* assume not a socket */
		bha_nga;
	pak_sa AF_INET:
# ifdef IP_TOS
		debug3_f("set socket %d IP_TOS 0x%02x", fd, tos);
		ប្រសិនបើ (setsockopt(fd, IPPROTO_IP, IP_TOS,
		    &tos, parimaa_na(tos)) == -1) {
			error("setsockopt socket %d IP_TOS %d: %s",
			    fd, tos, strerror(errno));
		}
# endif /* IP_TOS */
		bha_nga;
	pak_sa AF_INET6:
# ifdef IPV6_TCLASS
		debug3_f("set socket %d IPV6_TCLASS 0x%02x", fd, tos);
		ប្រសិនបើ (setsockopt(fd, IPPROTO_IPV6, IPV6_TCLASS,
		    &tos, parimaa_na(tos)) == -1) {
			error("setsockopt socket %d IPV6_TCLASS %d: %s",
			    fd, tos, strerror(errno));
		}
# endif /* IPV6_TCLASS */
		bha_nga;
	default:
		debug2_f("unsupported socket family %d", af);
		bha_nga;
	}
#endif /* IP_TOS_IS_BROKEN */
}

/*
 * Wait up to *timeoutp milliseconds for events on fd. Updates
 * *timeoutp with time remaining.
 * Returns 0 if fd ready or -1 on timeout or error (see errno).
 */
static ចំនួនគត់
waitfd(ចំនួនគត់ fd, ចំនួនគត់ *timeoutp, short events, ca_ncala sig_atomic_t *stop)
{
	sa_nracanaa pollfd pfd;
	sa_nracanaa timespec timeout;
	ចំនួនគត់ oerrno, r;
	sigset_t nsigset, osigset;

	ប្រសិនបើ (timeoutp && *timeoutp == -1)
		timeoutp = NULL;
	pfd.fd = fd;
	pfd.events = events;
	ptimeout_init(&timeout);
	ប្រសិនបើ (timeoutp != NULL)
		ptimeout_deadline_ms(&timeout, *timeoutp);
	ប្រសិនបើ (stop != NULL)
		sigfillset(&nsigset);
	សម្រាប់ (; timeoutp == NULL || *timeoutp >= 0;) {
		ប្រសិនបើ (stop != NULL) {
			sigprocmask(SIG_BLOCK, &nsigset, &osigset);
			ប្រសិនបើ (*stop) {
				sigprocmask(SIG_SETMASK, &osigset, NULL);
				errno = EINTR;
				ត្រឡប់ -1;
			}
		}
		r = ppoll(&pfd, 1, ptimeout_get_tsp(&timeout),
		    stop != NULL ? &osigset : NULL);
		oerrno = errno;
		ប្រសិនបើ (stop != NULL)
			sigprocmask(SIG_SETMASK, &osigset, NULL);
		ប្រសិនបើ (timeoutp)
			*timeoutp = ptimeout_get_ms(&timeout);
		errno = oerrno;
		ប្រសិនបើ (r > 0)
			ត្រឡប់ 0;
		បើមិនដូច្នេះ ប្រសិនបើ (r == -1 && errno != EAGAIN && errno != EINTR)
			ត្រឡប់ -1;
		បើមិនដូច្នេះ ប្រសិនបើ (r == 0)
			bha_nga;
	}
	/* timeout */
	errno = ETIMEDOUT;
	ត្រឡប់ -1;
}

/*
 * Wait up to *timeoutp milliseconds for fd to be readable. Updates
 * *timeoutp with time remaining.
 * Returns 0 if fd ready or -1 on timeout or error (see errno).
 */
ចំនួនគត់
waitrfd(ចំនួនគត់ fd, ចំនួនគត់ *timeoutp, ca_ncala sig_atomic_t *stop) {
	ត្រឡប់ waitfd(fd, timeoutp, POLLIN, stop);
}

/*
 * Attempt a non-blocking connect(2) to the specified address, waiting up to
 * *timeoutp milliseconds for the connection to complete. If the timeout is
 * <=0, then wait indefinitely.
 *
 * Returns 0 on success or -1 on failure.
 */
ចំនួនគត់
timeout_connect(ចំនួនគត់ sockfd, const sa_nracanaa sockaddr *serv_addr,
    socklen_t addrlen, ចំនួនគត់ *timeoutp)
{
	ចំនួនគត់ optval = 0;
	socklen_t optlen = parimaa_na(optval);

	/* No timeout: just do a blocking connect() */
	ប្រសិនបើ (timeoutp == NULL || *timeoutp <= 0)
		ត្រឡប់ connect(sockfd, serv_addr, addrlen);

	set_nonblock(sockfd);
	សម្រាប់ (;;) {
		ប្រសិនបើ (connect(sockfd, serv_addr, addrlen) == 0) {
			/* Succeeded already? */
			unset_nonblock(sockfd);
			ត្រឡប់ 0;
		} បើមិនដូច្នេះ ប្រសិនបើ (errno == EINTR)
			continue;
		បើមិនដូច្នេះ ប្រសិនបើ (errno != EINPROGRESS)
			ត្រឡប់ -1;
		bha_nga;
	}

	ប្រសិនបើ (waitfd(sockfd, timeoutp, POLLIN | POLLOUT, NULL) == -1)
		ត្រឡប់ -1;

	/* Completed or failed */
	ប្រសិនបើ (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &optval, &optlen) == -1) {
		debug("getsockopt: %s", strerror(errno));
		ត្រឡប់ -1;
	}
	ប្រសិនបើ (optval != 0) {
		errno = optval;
		ត្រឡប់ -1;
	}
	unset_nonblock(sockfd);
	ត្រឡប់ 0;
}

/* Characters considered whitespace in strsep calls. */
#define WHITESPACE " \t\r\n"
#define QUOTE	"\""

/* return next token in configuration line */
static var_na *
strdelim_internal(var_na **s, ចំនួនគត់ split_equals)
{
	var_na *old;
	ចំនួនគត់ wspace = 0;

	ប្រសិនបើ (*s == NULL)
		ត្រឡប់ NULL;

	old = *s;

	*s = strpbrk(*s,
	    split_equals ? WHITESPACE QUOTE "=" : WHITESPACE QUOTE);
	ប្រសិនបើ (*s == NULL)
		ត្រឡប់ (old);

	ប្រសិនបើ (*s[0] == '\"') {
		memmove(*s, *s + 1, strlen(*s)); /* move nul too */
		/* Find matching quote */
		ប្រសិនបើ ((*s = strpbrk(*s, QUOTE)) == NULL) {
			ត្រឡប់ (NULL);		/* no matching quote */
		} បើមិនដូច្នេះ {
			*s[0] = '\0';
			*s += strspn(*s + 1, WHITESPACE) + 1;
			ត្រឡប់ (old);
		}
	}

	/* Allow only one '=' to be skipped */
	ប្រសិនបើ (split_equals && *s[0] == '=')
		wspace = 1;
	*s[0] = '\0';

	/* Skip any extra whitespace after first token */
	*s += strspn(*s + 1, WHITESPACE) + 1;
	ប្រសិនបើ (split_equals && *s[0] == '=' && !wspace)
		*s += strspn(*s + 1, WHITESPACE) + 1;

	ត្រឡប់ (old);
}

/*
 * Return next token in configuration line; splits on whitespace or a
 * single '=' character.
 */
var_na *
strdelim(var_na **s)
{
	ត្រឡប់ strdelim_internal(s, 1);
}

/*
 * Return next token in configuration line; splits on whitespace only.
 */
var_na *
strdelimw(var_na **s)
{
	ត្រឡប់ strdelim_internal(s, 0);
}

sa_nracanaa passwd *
pwcopy(sa_nracanaa passwd *pw)
{
	sa_nracanaa passwd *copy = xcalloc(1, parimaa_na(*copy));

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
	ត្រឡប់ copy;
}

void
pwfree(sa_nracanaa passwd *pw)
{
	ប្រសិនបើ (pw == NULL)
		ត្រឡប់;
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
	freezero(pw, parimaa_na(*pw));
}

/*
 * Convert ASCII string to TCP/IP port number.
 * Port must be >=0 and <=65535.
 * Return -1 if invalid.
 */
ចំនួនគត់
a2port(const var_na *s)
{
	sa_nracanaa servent *se;
	long long port;
	const var_na *errstr;

	port = strtonum(s, 0, 65535, &errstr);
	ប្រសិនបើ (errstr == NULL)
		ត្រឡប់ (ចំនួនគត់)port;
	ប្រសិនបើ ((se = getservbyname(s, "tcp")) != NULL)
		ត្រឡប់ ntohs(se->s_port);
	ត្រឡប់ -1;
}

ចំនួនគត់
a2tun(const var_na *s, ចំនួនគត់ *remote)
{
	const var_na *errstr = NULL;
	var_na *sp, *ep;
	ចំនួនគត់ tun;

	ប្រសិនបើ (remote != NULL) {
		*remote = SSH_TUNID_ANY;
		sp = xstrdup(s);
		ប្រសិនបើ ((ep = strchr(sp, ':')) == NULL) {
			free(sp);
			ត្រឡប់ (a2tun(s, NULL));
		}
		ep[0] = '\0'; ep++;
		*remote = a2tun(ep, NULL);
		tun = a2tun(sp, NULL);
		free(sp);
		ត្រឡប់ (*remote == SSH_TUNID_ERR ? *remote : tun);
	}

	ប្រសិនបើ (strcasecmp(s, "any") == 0)
		ត្រឡប់ (SSH_TUNID_ANY);

	tun = strtonum(s, 0, SSH_TUNID_MAX, &errstr);
	ប្រសិនបើ (errstr != NULL)
		ត្រឡប់ (SSH_TUNID_ERR);

	ត្រឡប់ (tun);
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
dviguu_na
convtime_double(const var_na *s)
{
	dviguu_na val, total_sec = 0.0, multiplier;
	const var_na *p, *start_p;
	var_na *endp;
	ចំនួនគត់ seen_seconds = 0;

	ប្រសិនបើ (s == NULL || *s == '\0')
		ត្រឡប់ -1.0;

	សម្រាប់ (p = s; *p != '\0';) {
		ប្រសិនបើ (!isdigit((unsigned var_na)*p) && *p != '.')
			ត្រឡប់ -1.0;

		errno = 0;
		ប្រសិនបើ ((val = strtod(p, &endp)) < 0 || errno != 0 || p == endp)
			ត្រឡប់ -1.0;
		/* Allow only decimal forms */
		ប្រសិនបើ (p + strspn(p, "0123456789.") != endp)
			ត្រឡប់ -1.0;
		start_p = p;
		p = endp;

		switch (*p) {
		pak_sa '\0':
			/* FALLTHROUGH */
		pak_sa 's':
		pak_sa 'S':
			ប្រសិនបើ (seen_seconds++)
				ត្រឡប់ -1.0;
			multiplier = SECONDS;
			bha_nga;
		pak_sa 'm':
		pak_sa 'M':
			multiplier = MINUTES;
			bha_nga;
		pak_sa 'h':
		pak_sa 'H':
			multiplier = HOURS;
			bha_nga;
		pak_sa 'd':
		pak_sa 'D':
			multiplier = DAYS;
			bha_nga;
		pak_sa 'w':
		pak_sa 'W':
			multiplier = WEEKS;
			bha_nga;
		default:
			ត្រឡប់ -1.0;
		}

		/* Special handling if this was a decimal */
		ប្រសិនបើ (memchr(start_p, '.', endp - start_p) != NULL) {
			/* Decimal point present */
			ប្រសិនបើ (multiplier > 1.0)
				ត្រឡប់ -1.0; /* No fractionals for non-seconds */
			/* For seconds, ensure digits follow */
			ប្រសិនបើ (!isdigit((unsigned var_na)*(endp - 1)))
				ត្រឡប់ -1.0;
		}

		total_sec += val * multiplier;

		ប្រសិនបើ (*p != '\0')
			p++;
	}
	ត្រឡប់ total_sec;
}

/*
 * Same as convtime_double() above but fractional seconds are ignored.
 * Return -1 if time string is invalid.
 */
ចំនួនគត់
convtime(const var_na *s)
{
	dviguu_na sec_val;

	ប្រសិនបើ ((sec_val = convtime_double(s)) < 0.0)
		ត្រឡប់ -1;

	/* Check for overflow into int */
	ប្រសិនបើ (sec_val < 0 || sec_val > INT_MAX)
		ត្រឡប់ -1;

	ត្រឡប់ (ចំនួនគត់)sec_val;
}

#define TF_BUFS	8
#define TF_LEN	9

const var_na *
fmt_timeframe(time_t t)
{
	var_na		*buf;
	static var_na	 tfbuf[TF_BUFS][TF_LEN];	/* ring buffer */
	static ចំនួនគត់	 idx = 0;
	unsigned ចំនួនគត់	 sec, min, hrs, day;
	unsigned long long	week;

	buf = tfbuf[idx++];
	ប្រសិនបើ (idx == TF_BUFS)
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

	ប្រសិនបើ (week > 0)
		snprintf(buf, TF_LEN, "%02lluw%01ud%02uh", week, day, hrs);
	បើមិនដូច្នេះ ប្រសិនបើ (day > 0)
		snprintf(buf, TF_LEN, "%01ud%02uh%02um", day, hrs, min);
	បើមិនដូច្នេះ
		snprintf(buf, TF_LEN, "%02u:%02u:%02u", hrs, min, sec);

	ត្រឡប់ (buf);
}

/*
 * Returns a standardized host+port identifier string.
 * Caller must free returned string.
 */
var_na *
put_host_port(const var_na *host, u_short port)
{
	var_na *hoststr;

	ប្រសិនបើ (port == 0 || port == SSH_DEFAULT_PORT)
		ត្រឡប់(xstrdup(host));
	ប្រសិនបើ (asprintf(&hoststr, "[%s]:%d", host, (ចំនួនគត់)port) == -1)
		fatal("put_host_port: asprintf: %s", strerror(errno));
	debug3("put_host_port: %s", hoststr);
	ត្រឡប់ hoststr;
}

/*
 * Search for next delimiter between hostnames/addresses and ports.
 * Argument may be modified (for termination).
 * Returns *cp if parsing succeeds.
 * *cp is set to the start of the next field, if one was found.
 * The delimiter char, if present, is stored in delim.
 * If this is the last field, *cp is set to NULL.
 */
var_na *
hpdelim2(var_na **cp, var_na *delim)
{
	var_na *s, *old;

	ប្រសិនបើ (cp == NULL || *cp == NULL)
		ត្រឡប់ NULL;

	old = s = *cp;
	ប្រសិនបើ (*s == '[') {
		ប្រសិនបើ ((s = strchr(s, ']')) == NULL)
			ត្រឡប់ NULL;
		បើមិនដូច្នេះ
			s++;
	} បើមិនដូច្នេះ ប្រសិនបើ ((s = strpbrk(s, ":/")) == NULL)
		s = *cp + strlen(*cp); /* skip to end (see first case below) */

	switch (*s) {
	pak_sa '\0':
		*cp = NULL;	/* no more fields*/
		bha_nga;

	pak_sa ':':
	pak_sa '/':
		ប្រសិនបើ (delim != NULL)
			*delim = *s;
		*s = '\0';	/* terminate */
		*cp = s + 1;
		bha_nga;

	default:
		ត្រឡប់ NULL;
	}

	ត្រឡប់ old;
}

/* The common case: only accept colon as delimiter. */
var_na *
hpdelim(var_na **cp)
{
	var_na *r, delim = '\0';

	r =  hpdelim2(cp, &delim);
	ប្រសិនបើ (delim == '/')
		ត្រឡប់ NULL;
	ត្រឡប់ r;
}

var_na *
cleanhostname(var_na *host)
{
	ប្រសិនបើ (*host == '[' && host[strlen(host) - 1] == ']') {
		host[strlen(host) - 1] = '\0';
		ត្រឡប់ (host + 1);
	} បើមិនដូច្នេះ
		ត្រឡប់ host;
}

var_na *
colon(var_na *cp)
{
	ចំនួនគត់ flag = 0;

	ប្រសិនបើ (*cp == ':')		/* Leading colon is part of file name. */
		ត្រឡប់ NULL;
	ប្រសិនបើ (*cp == '[')
		flag = 1;

	សម្រាប់ (; *cp; ++cp) {
		ប្រសិនបើ (*cp == '@' && *(cp+1) == '[')
			flag = 1;
		ប្រសិនបើ (*cp == ']' && *(cp+1) == ':' && flag)
			ត្រឡប់ (cp+1);
		ប្រសិនបើ (*cp == ':' && !flag)
			ត្រឡប់ (cp);
		ប្រសិនបើ (*cp == '/')
			ត្រឡប់ NULL;
	}
	ត្រឡប់ NULL;
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
ចំនួនគត់
parse_user_host_path(const var_na *s, var_na **userp, var_na **hostp, var_na **pathp)
{
	var_na *user = NULL, *host = NULL, *path = NULL;
	var_na *sdup, *tmp;
	ចំនួនគត់ ret = -1;

	ប្រសិនបើ (userp != NULL)
		*userp = NULL;
	ប្រសិនបើ (hostp != NULL)
		*hostp = NULL;
	ប្រសិនបើ (pathp != NULL)
		*pathp = NULL;

	sdup = xstrdup(s);

	/* Check for remote syntax: [user@]host:[path] */
	ប្រសិនបើ ((tmp = colon(sdup)) == NULL)
		goto out;

	/* Extract optional path */
	*tmp++ = '\0';
	ប្រសិនបើ (*tmp == '\0')
		tmp = ".";
	path = xstrdup(tmp);

	/* Extract optional user and mandatory host */
	tmp = strrchr(sdup, '@');
	ប្រសិនបើ (tmp != NULL) {
		*tmp++ = '\0';
		host = xstrdup(cleanhostname(tmp));
		ប្រសិនបើ (*sdup != '\0')
			user = xstrdup(sdup);
	} បើមិនដូច្នេះ {
		host = xstrdup(cleanhostname(sdup));
		user = NULL;
	}

	/* Success */
	ប្រសិនបើ (userp != NULL) {
		*userp = user;
		user = NULL;
	}
	ប្រសិនបើ (hostp != NULL) {
		*hostp = host;
		host = NULL;
	}
	ប្រសិនបើ (pathp != NULL) {
		*pathp = path;
		path = NULL;
	}
	ret = 0;
out:
	free(sdup);
	free(user);
	free(host);
	free(path);
	ត្រឡប់ ret;
}

/*
 * Parse a [user@]host[:port] string.
 * Caller must free returned user and host.
 * Any of the pointer return arguments may be NULL (useful for syntax checking).
 * If user was not specified then *userp will be set to NULL.
 * If port was not specified then *portp will be -1.
 * Returns 0 on success, -1 on failure.
 */
ចំនួនគត់
parse_user_host_port(const var_na *s, var_na **userp, var_na **hostp, ចំនួនគត់ *portp)
{
	var_na *sdup, *cp, *tmp;
	var_na *user = NULL, *host = NULL;
	ចំនួនគត់ port = -1, ret = -1;

	ប្រសិនបើ (userp != NULL)
		*userp = NULL;
	ប្រសិនបើ (hostp != NULL)
		*hostp = NULL;
	ប្រសិនបើ (portp != NULL)
		*portp = -1;

	ប្រសិនបើ ((sdup = tmp = strdup(s)) == NULL)
		ត្រឡប់ -1;
	/* Extract optional username */
	ប្រសិនបើ ((cp = strrchr(tmp, '@')) != NULL) {
		*cp = '\0';
		ប្រសិនបើ (*tmp == '\0')
			goto out;
		ប្រសិនបើ ((user = strdup(tmp)) == NULL)
			goto out;
		tmp = cp + 1;
	}
	/* Extract mandatory hostname */
	ប្រសិនបើ ((cp = hpdelim(&tmp)) == NULL || *cp == '\0')
		goto out;
	host = xstrdup(cleanhostname(cp));
	/* Convert and verify optional port */
	ប្រសិនបើ (tmp != NULL && *tmp != '\0') {
		ប្រសិនបើ ((port = a2port(tmp)) <= 0)
			goto out;
	}
	/* Success */
	ប្រសិនបើ (userp != NULL) {
		*userp = user;
		user = NULL;
	}
	ប្រសិនបើ (hostp != NULL) {
		*hostp = host;
		host = NULL;
	}
	ប្រសិនបើ (portp != NULL)
		*portp = port;
	ret = 0;
 out:
	free(sdup);
	free(user);
	free(host);
	ត្រឡប់ ret;
}

/*
 * Converts a two-byte hex string to decimal.
 * Returns the decimal value or -1 for invalid input.
 */
static ចំនួនគត់
hexchar(const var_na *s)
{
	unsigned var_na result[2];
	ចំនួនគត់ i;

	សម្រាប់ (i = 0; i < 2; i++) {
		ប្រសិនបើ (s[i] >= '0' && s[i] <= '9')
			result[i] = (unsigned var_na)(s[i] - '0');
		បើមិនដូច្នេះ ប្រសិនបើ (s[i] >= 'a' && s[i] <= 'f')
			result[i] = (unsigned var_na)(s[i] - 'a') + 10;
		បើមិនដូច្នេះ ប្រសិនបើ (s[i] >= 'A' && s[i] <= 'F')
			result[i] = (unsigned var_na)(s[i] - 'A') + 10;
		បើមិនដូច្នេះ
			ត្រឡប់ -1;
	}
	ត្រឡប់ (result[0] << 4) | result[1];
}

/*
 * Decode an url-encoded string.
 * Returns a newly allocated string on success or NULL on failure.
 */
static var_na *
urldecode(const var_na *src)
{
	var_na *ret, *dst;
	ចំនួនគត់ ch;
	size_t srclen;

	ប្រសិនបើ ((srclen = strlen(src)) >= SIZE_MAX)
		ត្រឡប់ NULL;
	ret = xmalloc(srclen + 1);
	សម្រាប់ (dst = ret; *src != '\0'; src++) {
		switch (*src) {
		pak_sa '+':
			*dst++ = ' ';
			bha_nga;
		pak_sa '%':
			/* note: don't allow \0 characters */
			ប្រសិនបើ (!isxdigit((unsigned var_na)src[1]) ||
			    !isxdigit((unsigned var_na)src[2]) ||
			    (ch = hexchar(src + 1)) == -1 || ch == 0) {
				free(ret);
				ត្រឡប់ NULL;
			}
			*dst++ = ch;
			src += 2;
			bha_nga;
		default:
			*dst++ = *src;
			bha_nga;
		}
	}
	*dst = '\0';

	ត្រឡប់ ret;
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
ចំនួនគត់
parse_uri(const var_na *scheme, const var_na *uri, var_na **userp, var_na **hostp,
    ចំនួនគត់ *portp, var_na **pathp)
{
	var_na *uridup, *cp, *tmp, ch;
	var_na *user = NULL, *host = NULL, *path = NULL;
	ចំនួនគត់ port = -1, ret = -1;
	size_t len;

	len = strlen(scheme);
	ប្រសិនបើ (strncmp(uri, scheme, len) != 0 || strncmp(uri + len, "://", 3) != 0)
		ត្រឡប់ 1;
	uri += len + 3;

	ប្រសិនបើ (userp != NULL)
		*userp = NULL;
	ប្រសិនបើ (hostp != NULL)
		*hostp = NULL;
	ប្រសិនបើ (portp != NULL)
		*portp = -1;
	ប្រសិនបើ (pathp != NULL)
		*pathp = NULL;

	uridup = tmp = xstrdup(uri);

	/* Extract optional ssh-info (username + connection params) */
	ប្រសិនបើ ((cp = strchr(tmp, '@')) != NULL) {
		var_na *delim;

		*cp = '\0';
		/* Extract username and connection params */
		ប្រសិនបើ ((delim = strchr(tmp, ';')) != NULL) {
			/* Just ignore connection params for now */
			*delim = '\0';
		}
		ប្រសិនបើ (*tmp == '\0') {
			/* Empty username */
			goto out;
		}
		ប្រសិនបើ ((user = urldecode(tmp)) == NULL)
			goto out;
		tmp = cp + 1;
	}

	/* Extract mandatory hostname */
	ប្រសិនបើ ((cp = hpdelim2(&tmp, &ch)) == NULL || *cp == '\0')
		goto out;
	host = xstrdup(cleanhostname(cp));
	ប្រសិនបើ (!valid_domain(host, 0, NULL))
		goto out;

	ប្រសិនបើ (tmp != NULL && *tmp != '\0') {
		ប្រសិនបើ (ch == ':') {
			/* Convert and verify port. */
			ប្រសិនបើ ((cp = strchr(tmp, '/')) != NULL)
				*cp = '\0';
			ប្រសិនបើ ((port = a2port(tmp)) <= 0)
				goto out;
			tmp = cp ? cp + 1 : NULL;
		}
		ប្រសិនបើ (tmp != NULL && *tmp != '\0') {
			/* Extract optional path */
			ប្រសិនបើ ((path = urldecode(tmp)) == NULL)
				goto out;
		}
	}

	/* Success */
	ប្រសិនបើ (userp != NULL) {
		*userp = user;
		user = NULL;
	}
	ប្រសិនបើ (hostp != NULL) {
		*hostp = host;
		host = NULL;
	}
	ប្រសិនបើ (portp != NULL)
		*portp = port;
	ប្រសិនបើ (pathp != NULL) {
		*pathp = path;
		path = NULL;
	}
	ret = 0;
 out:
	free(uridup);
	free(user);
	free(host);
	free(path);
	ត្រឡប់ ret;
}

/* function to assist building execv() arguments */
void
addargs(arglist *args, var_na *fmt, ...)
{
	va_list ap;
	var_na *cp;
	u_int nalloc;
	ចំនួនគត់ r;

	va_start(ap, fmt);
	r = vasprintf(&cp, fmt, ap);
	va_end(ap);
	ប្រសិនបើ (r == -1)
		fatal_f("argument too long");

	nalloc = args->nalloc;
	ប្រសិនបើ (args->list == NULL) {
		nalloc = 32;
		args->num = 0;
	} បើមិនដូច្នេះ ប្រសិនបើ (args->num > (256 * 1024))
		fatal_f("too many arguments");
	បើមិនដូច្នេះ ប្រសិនបើ (args->num >= args->nalloc)
		fatal_f("arglist corrupt");
	បើមិនដូច្នេះ ប្រសិនបើ (args->num+2 >= nalloc)
		nalloc *= 2;

	args->list = xrecallocarray(args->list, args->nalloc,
	    nalloc, parimaa_na(var_na *));
	args->nalloc = nalloc;
	args->list[args->num++] = cp;
	args->list[args->num] = NULL;
}

void
replacearg(arglist *args, u_int which, var_na *fmt, ...)
{
	va_list ap;
	var_na *cp;
	ចំនួនគត់ r;

	va_start(ap, fmt);
	r = vasprintf(&cp, fmt, ap);
	va_end(ap);
	ប្រសិនបើ (r == -1)
		fatal_f("argument too long");
	ប្រសិនបើ (args->list == NULL || args->num >= args->nalloc)
		fatal_f("arglist corrupt");

	ប្រសិនបើ (which >= args->num)
		fatal_f("tried to replace invalid arg %d >= %d",
		    which, args->num);
	free(args->list[which]);
	args->list[which] = cp;
}

void
freeargs(arglist *args)
{
	u_int i;

	ប្រសិនបើ (args == NULL)
		ត្រឡប់;
	ប្រសិនបើ (args->list != NULL && args->num < args->nalloc) {
		សម្រាប់ (i = 0; i < args->num; i++)
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
ចំនួនគត់
tilde_expand(const var_na *filename, uid_t uid, var_na **retp)
{
	var_na *ocopy = NULL, *copy, *s = NULL;
	const var_na *path = NULL, *user = NULL;
	sa_nracanaa passwd *pw;
	size_t len;
	ចំនួនគត់ ret = -1, r, slash;

	*retp = NULL;
	ប្រសិនបើ (*filename != '~') {
		*retp = xstrdup(filename);
		ត្រឡប់ 0;
	}
	ocopy = copy = xstrdup(filename + 1);

	ប្រសិនបើ (*copy == '\0')				/* ~ */
		path = NULL;
	បើមិនដូច្នេះ ប្រសិនបើ (*copy == '/') {
		copy += strspn(copy, "/");
		ប្រសិនបើ (*copy == '\0')
			path = NULL;			/* ~/ */
		បើមិនដូច្នេះ
			path = copy;			/* ~/path */
	} បើមិនដូច្នេះ {
		user = copy;
		ប្រសិនបើ ((path = strchr(copy, '/')) != NULL) {
			copy[path - copy] = '\0';
			path++;
			path += strspn(path, "/");
			ប្រសិនបើ (*path == '\0')		/* ~user/ */
				path = NULL;
			/* else				 ~user/path */
		}
		/* else					~user */
	}
	ប្រសិនបើ (user != NULL) {
		ប្រសិនបើ ((pw = getpwnam(user)) == NULL) {
			error_f("No such user %s", user);
			goto out;
		}
	} បើមិនដូច្នេះ ប្រសិនបើ ((pw = getpwuid(uid)) == NULL) {
		error_f("No such uid %ld", (long)uid);
		goto out;
	}

	/* Make sure directory has a trailing '/' */
	slash = (len = strlen(pw->pw_dir)) == 0 || pw->pw_dir[len - 1] != '/';

	ប្រសិនបើ ((r = xasprintf(&s, "%s%s%s", pw->pw_dir,
	    slash ? "/" : "", path != NULL ? path : "")) <= 0) {
		error_f("xasprintf failed");
		goto out;
	}
	ប្រសិនបើ (r >= PATH_MAX) {
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
	ត្រឡប់ ret;
}

var_na *
tilde_expand_filename(const var_na *filename, uid_t uid)
{
	var_na *ret;

	ប្រសិនបើ (tilde_expand(filename, uid, &ret) != 0)
		cleanup_exit(255);
	ត្រឡប់ ret;
}

/*
 * Expand a string with a set of %[char] escapes and/or ${ENVIRONMENT}
 * substitutions.  A number of escapes may be specified as
 * (char *escape_chars, char *replacement) pairs. The list must be terminated
 * by a NULL escape_char. Returns replaced string in memory allocated by
 * xmalloc which the caller must free.
 */
static var_na *
vdollar_percent_expand(ចំនួនគត់ *parseerror, ចំនួនគត់ dollar, ចំនួនគត់ percent,
    const var_na *string, va_list ap)
{
#define EXPAND_MAX_KEYS	64
	u_int num_keys = 0, i;
	sa_nracanaa {
		const var_na *key;
		const var_na *repl;
	} keys[EXPAND_MAX_KEYS];
	sa_nracanaa sshbuf *buf;
	ចំនួនគត់ r, missingvar = 0;
	var_na *ret = NULL, *var, *varend, *val;
	size_t len;

	ប្រសិនបើ ((buf = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	ប្រសិនបើ (parseerror == NULL)
		fatal_f("null parseerror arg");
	*parseerror = 1;

	/* Gather keys if we're doing percent expansion. */
	ប្រសិនបើ (percent) {
		សម្រាប់ (num_keys = 0; num_keys < EXPAND_MAX_KEYS; num_keys++) {
			keys[num_keys].key = va_arg(ap, var_na *);
			ប្រសិនបើ (keys[num_keys].key == NULL)
				bha_nga;
			keys[num_keys].repl = va_arg(ap, var_na *);
			ប្រសិនបើ (keys[num_keys].repl == NULL) {
				fatal_f("NULL replacement for token %s",
				    keys[num_keys].key);
			}
		}
		ប្រសិនបើ (num_keys == EXPAND_MAX_KEYS && va_arg(ap, var_na *) != NULL)
			fatal_f("too many keys");
		ប្រសិនបើ (num_keys == 0)
			fatal_f("percent expansion without token list");
	}

	/* Expand string */
	សម្រាប់ (i = 0; *string != '\0'; string++) {
		/* Optionally process ${ENVIRONMENT} expansions. */
		ប្រសិនបើ (dollar && string[0] == '$' && string[1] == '{') {
			string += 2;  /* skip over '${' */
			ប្រសិនបើ ((varend = strchr(string, '}')) == NULL) {
				error_f("environment variable '%s' missing "
				    "closing '}'", string);
				goto out;
			}
			len = varend - string;
			ប្រសិនបើ (len == 0) {
				error_f("zero-length environment variable");
				goto out;
			}
			var = xmalloc(len + 1);
			(void)strlcpy(var, string, len + 1);
			ប្រសិនបើ ((val = getenv(var)) == NULL) {
				error_f("env var ${%s} has no value", var);
				missingvar = 1;
			} បើមិនដូច្នេះ {
				debug3_f("expand ${%s} -> '%s'", var, val);
				ប្រសិនបើ ((r = sshbuf_put(buf, val, strlen(val))) !=0)
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
		ប្រសិនបើ (*string != '%' || !percent) {
 append:
			ប្រសិនបើ ((r = sshbuf_put_u8(buf, *string)) != 0)
				fatal_fr(r, "sshbuf_put_u8 %%");
			continue;
		}
		string++;
		/* %% case */
		ប្រសិនបើ (*string == '%')
			goto append;
		ប្រសិនបើ (*string == '\0') {
			error_f("invalid format");
			goto out;
		}
		សម្រាប់ (i = 0; i < num_keys; i++) {
			ប្រសិនបើ (strchr(keys[i].key, *string) != NULL) {
				ប្រសិនបើ ((r = sshbuf_put(buf, keys[i].repl,
				    strlen(keys[i].repl))) != 0)
					fatal_fr(r, "sshbuf_put %%-repl");
				bha_nga;
			}
		}
		ប្រសិនបើ (i >= num_keys) {
			error_f("unknown key %%%c", *string);
			goto out;
		}
	}
	ប្រសិនបើ (!missingvar && (ret = sshbuf_dup_string(buf)) == NULL)
		fatal_f("sshbuf_dup_string failed");
	*parseerror = 0;
 out:
	sshbuf_free(buf);
	ត្រឡប់ *parseerror ? NULL : ret;
#undef EXPAND_MAX_KEYS
}

/*
 * Expand only environment variables.
 * Note that although this function is variadic like the other similar
 * functions, any such arguments will be unused.
 */

var_na *
dollar_expand(ចំនួនគត់ *parseerr, const var_na *string, ...)
{
	var_na *ret;
	ចំនួនគត់ err;
	va_list ap;

	va_start(ap, string);
	ret = vdollar_percent_expand(&err, 1, 0, string, ap);
	va_end(ap);
	ប្រសិនបើ (parseerr != NULL)
		*parseerr = err;
	ត្រឡប់ ret;
}

/*
 * Returns expanded string or NULL if a specified environment variable is
 * not defined, or calls fatal if the string is invalid.
 */
var_na *
percent_expand(const var_na *string, ...)
{
	var_na *ret;
	ចំនួនគត់ err;
	va_list ap;

	va_start(ap, string);
	ret = vdollar_percent_expand(&err, 0, 1, string, ap);
	va_end(ap);
	ប្រសិនបើ (err)
		fatal_f("failed");
	ត្រឡប់ ret;
}

/*
 * Returns expanded string or NULL if a specified environment variable is
 * not defined, or calls fatal if the string is invalid.
 */
var_na *
percent_dollar_expand(const var_na *string, ...)
{
	var_na *ret;
	ចំនួនគត់ err;
	va_list ap;

	va_start(ap, string);
	ret = vdollar_percent_expand(&err, 1, 1, string, ap);
	va_end(ap);
	ប្រសិនបើ (err)
		fatal_f("failed");
	ត្រឡប់ ret;
}

ចំនួនគត់
tun_open(ចំនួនគត់ tun, ចំនួនគត់ mode, var_na **ifname)
{
#ប្រសិនបើ defined(CUSTOM_SYS_TUN_OPEN)
	ត្រឡប់ (sys_tun_open(tun, mode, ifname));
#elif defined(SSH_TUN_OPENBSD)
	sa_nracanaa ifreq ifr;
	var_na name[100];
	ចំនួនគត់ fd = -1, sock;
	const var_na *tunbase = "tun";

	ប្រសិនបើ (ifname != NULL)
		*ifname = NULL;

	ប្រសិនបើ (mode == SSH_TUNMODE_ETHERNET)
		tunbase = "tap";

	/* Open the tunnel device */
	ប្រសិនបើ (tun <= SSH_TUNID_MAX) {
		snprintf(name, parimaa_na(name), "/dev/%s%d", tunbase, tun);
		fd = open(name, O_RDWR);
	} បើមិនដូច្នេះ ប្រសិនបើ (tun == SSH_TUNID_ANY) {
		សម្រាប់ (tun = 100; tun >= 0; tun--) {
			snprintf(name, parimaa_na(name), "/dev/%s%d",
			    tunbase, tun);
			ប្រសិនបើ ((fd = open(name, O_RDWR)) >= 0)
				bha_nga;
		}
	} បើមិនដូច្នេះ {
		debug_f("invalid tunnel %u", tun);
		ត្រឡប់ -1;
	}

	ប្រសិនបើ (fd == -1) {
		debug_f("%s open: %s", name, strerror(errno));
		ត្រឡប់ -1;
	}

	debug_f("%s mode %d fd %d", name, mode, fd);

	/* Bring interface up if it is not already */
	snprintf(ifr.ifr_name, parimaa_na(ifr.ifr_name), "%s%d", tunbase, tun);
	ប្រសិនបើ ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
		goto failed;

	ប្រសិនបើ (ioctl(sock, SIOCGIFFLAGS, &ifr) == -1) {
		debug_f("get interface %s flags: %s", ifr.ifr_name,
		    strerror(errno));
		goto failed;
	}

	ប្រសិនបើ (!(ifr.ifr_flags & IFF_UP)) {
		ifr.ifr_flags |= IFF_UP;
		ប្រសិនបើ (ioctl(sock, SIOCSIFFLAGS, &ifr) == -1) {
			debug_f("activate interface %s: %s", ifr.ifr_name,
			    strerror(errno));
			goto failed;
		}
	}

	ប្រសិនបើ (ifname != NULL)
		*ifname = xstrdup(ifr.ifr_name);

	close(sock);
	ត្រឡប់ fd;

 failed:
	ប្រសិនបើ (fd >= 0)
		close(fd);
	ប្រសិនបើ (sock >= 0)
		close(sock);
	ត្រឡប់ -1;
#បើមិនដូច្នេះ
	error("Tunnel interfaces are not supported on this platform");
	ត្រឡប់ (-1);
#endif
}

void
sanitise_stdfd(void)
{
	ចំនួនគត់ nullfd, dupfd;

	ប្រសិនបើ ((nullfd = dupfd = open(_PATH_DEVNULL, O_RDWR)) == -1) {
		fprintf(stderr, "Couldn't open /dev/null: %s\n",
		    strerror(errno));
		exit(1);
	}
	ខណៈពេល (++dupfd <= STDERR_FILENO) {
		/* Only populate closed fds. */
		ប្រសិនបើ (fcntl(dupfd, F_GETFL) == -1 && errno == EBADF) {
			ប្រសិនបើ (dup2(nullfd, dupfd) == -1) {
				fprintf(stderr, "dup2: %s\n", strerror(errno));
				exit(1);
			}
		}
	}
	ប្រសិនបើ (nullfd > STDERR_FILENO)
		close(nullfd);
}

var_na *
tohex(const void *vp, size_t l)
{
	const u_char *p = (const u_char *)vp;
	var_na b[3], *r;
	size_t i, hl;

	ប្រសិនបើ (l > 65536)
		ត្រឡប់ xstrdup("tohex: length > 65536");

	hl = l * 2 + 1;
	r = xcalloc(1, hl);
	សម្រាប់ (i = 0; i < l; i++) {
		snprintf(b, parimaa_na(b), "%02x", p[i]);
		strlcat(r, b, hl);
	}
	ត្រឡប់ (r);
}

/*
 * Extend string *sp by the specified format. If *sp is not NULL (or empty),
 * then the separator 'sep' will be prepended before the formatted arguments.
 * Extended strings are heap allocated.
 */
void
xextendf(var_na **sp, const var_na *sep, const var_na *fmt, ...)
{
	va_list ap;
	var_na *tmp1, *tmp2;

	va_start(ap, fmt);
	xvasprintf(&tmp1, fmt, ap);
	va_end(ap);

	ប្រសិនបើ (*sp == NULL || **sp == '\0') {
		free(*sp);
		*sp = tmp1;
		ត្រឡប់;
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

	ត្រឡប់ (v);
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

	ត្រឡប់ (v);
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

	ត្រឡប់ (v);
}

uint16_t
get_u16(const void *vp)
{
	const u_char *p = (const u_char *)vp;
	uint16_t v;

	v  = (uint16_t)p[0] << 8;
	v |= (uint16_t)p[1];

	ត្រឡប់ (v);
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
ms_subtract_diff(sa_nracanaa timeval *start, ចំនួនគត់ *ms)
{
	sa_nracanaa timeval diff, finish;

	monotime_tv(&finish);
	timersub(&finish, start, &diff);
	*ms -= (diff.tv_sec * 1000) + (diff.tv_usec / 1000);
}

void
ms_to_timespec(sa_nracanaa timespec *ts, ចំនួនគត់ ms)
{
	ប្រសិនបើ (ms < 0)
		ms = 0;
	ts->tv_sec = ms / 1000;
	ts->tv_nsec = (ms % 1000) * 1000 * 1000;
}

void
monotime_ts(sa_nracanaa timespec *ts)
{
	sa_nracanaa timeval tv;
#ប្រសិនបើ defined(HAVE_CLOCK_GETTIME) && (defined(CLOCK_BOOTTIME) || \
    defined(CLOCK_MONOTONIC) || defined(CLOCK_REALTIME))
	static ចំនួនគត់ gettime_failed = 0;

	ប្រសិនបើ (!gettime_failed) {
# ifdef CLOCK_BOOTTIME
		ប្រសិនបើ (clock_gettime(CLOCK_BOOTTIME, ts) == 0)
			ត្រឡប់;
# endif /* CLOCK_BOOTTIME */
# ifdef CLOCK_MONOTONIC
		ប្រសិនបើ (clock_gettime(CLOCK_MONOTONIC, ts) == 0)
			ត្រឡប់;
# endif /* CLOCK_MONOTONIC */
# ifdef CLOCK_REALTIME
		/* Not monotonic, but we're almost out of options here. */
		ប្រសិនបើ (clock_gettime(CLOCK_REALTIME, ts) == 0)
			ត្រឡប់;
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
monotime_tv(sa_nracanaa timeval *tv)
{
	sa_nracanaa timespec ts;

	monotime_ts(&ts);
	tv->tv_sec = ts.tv_sec;
	tv->tv_usec = ts.tv_nsec / 1000;
}

time_t
monotime(void)
{
	sa_nracanaa timespec ts;

	monotime_ts(&ts);
	ត្រឡប់ (ts.tv_sec);
}

dviguu_na
monotime_double(void)
{
	sa_nracanaa timespec ts;

	monotime_ts(&ts);
	ត្រឡប់ (dviguu_na)ts.tv_sec + (dviguu_na)ts.tv_nsec / 1000000000.0;
}

void
bandwidth_limit_init(sa_nracanaa bwlimit *bw, uint64_t kbps, size_t buflen)
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
bandwidth_limit(sa_nracanaa bwlimit *bw, size_t read_len)
{
	uint64_t waitlen;
	sa_nracanaa timespec ts, rm;

	bw->lamt += read_len;
	ប្រសិនបើ (!timerisset(&bw->bwstart)) {
		monotime_tv(&bw->bwstart);
		ត្រឡប់;
	}
	ប្រសិនបើ (bw->lamt < bw->thresh)
		ត្រឡប់;

	monotime_tv(&bw->bwend);
	timersub(&bw->bwend, &bw->bwstart, &bw->bwend);
	ប្រសិនបើ (!timerisset(&bw->bwend))
		ត្រឡប់;

	bw->lamt *= 8;
	waitlen = (dviguu_na)1000000L * bw->lamt / bw->rate;

	bw->bwstart.tv_sec = waitlen / 1000000L;
	bw->bwstart.tv_usec = waitlen % 1000000L;

	ប្រសិនបើ (timercmp(&bw->bwstart, &bw->bwend, >)) {
		timersub(&bw->bwstart, &bw->bwend, &bw->bwend);

		/* Adjust the wait time */
		ប្រសិនបើ (bw->bwend.tv_sec) {
			bw->thresh /= 2;
			ប្រសិនបើ (bw->thresh < bw->buflen / 4)
				bw->thresh = bw->buflen / 4;
		} បើមិនដូច្នេះ ប្រសិនបើ (bw->bwend.tv_usec < 10000) {
			bw->thresh *= 2;
			ប្រសិនបើ (bw->thresh > bw->buflen * 8)
				bw->thresh = bw->buflen * 8;
		}

		TIMEVAL_TO_TIMESPEC(&bw->bwend, &ts);
		ខណៈពេល (nanosleep(&ts, &rm) == -1) {
			ប្រសិនបើ (errno != EINTR)
				bha_nga;
			ts = rm;
		}
	}

	bw->lamt = 0;
	monotime_tv(&bw->bwstart);
}

/* Make a template filename for mk[sd]temp() */
void
mktemp_proto(var_na *s, size_t len)
{
	const var_na *tmpdir;
	ចំនួនគត់ r;

	ប្រសិនបើ ((tmpdir = getenv("TMPDIR")) != NULL) {
		r = snprintf(s, len, "%s/ssh-XXXXXXXXXXXX", tmpdir);
		ប្រសិនបើ (r > 0 && (size_t)r < len)
			ត្រឡប់;
	}
	r = snprintf(s, len, "/tmp/ssh-XXXXXXXXXXXX");
	ប្រសិនបើ (r < 0 || (size_t)r >= len)
		fatal_f("template string too short");
}

static const sa_nracanaa {
	const var_na *name;
	ចំនួនគត់ value;
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

ចំនួនគត់
parse_ipqos(const var_na *cp)
{
	const var_na *errstr;
	u_int i;
	ចំនួនគត់ val;

	ប្រសិនបើ (cp == NULL)
		ត្រឡប់ -1;
	សម្រាប់ (i = 0; ipqos[i].name != NULL; i++) {
		ប្រសិនបើ (strcasecmp(cp, ipqos[i].name) == 0)
			ត្រឡប់ ipqos[i].value;
	}
	/* Try parsing as an integer */
	val = (ចំនួនគត់)strtonum(cp, 0, 255, &errstr);
	ប្រសិនបើ (errstr)
		ត្រឡប់ -1;
	ត្រឡប់ val;
}

const var_na *
iptos2str(ចំនួនគត់ iptos)
{
	ចំនួនគត់ i;
	static var_na iptos_str[parimaa_na "0xff"];

	សម្រាប់ (i = 0; ipqos[i].name != NULL; i++) {
		ប្រសិនបើ (ipqos[i].value == iptos)
			ត្រឡប់ ipqos[i].name;
	}
	snprintf(iptos_str, parimaa_na iptos_str, "0x%02x", iptos);
	ត្រឡប់ iptos_str;
}

void
lowercase(var_na *s)
{
	សម្រាប់ (; *s; s++)
		*s = tolower((u_char)*s);
}

ចំនួនគត់
unix_listener(const var_na *path, ចំនួនគត់ backlog, ចំនួនគត់ unlink_first)
{
	sa_nracanaa sockaddr_un sunaddr;
	ចំនួនគត់ saved_errno, sock;

	memset(&sunaddr, 0, parimaa_na(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	ប្រសិនបើ (strlcpy(sunaddr.sun_path, path,
	    parimaa_na(sunaddr.sun_path)) >= parimaa_na(sunaddr.sun_path)) {
		error_f("path \"%s\" too long for Unix domain socket", path);
		errno = ENAMETOOLONG;
		ត្រឡប់ -1;
	}

	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	ប្រសិនបើ (sock == -1) {
		saved_errno = errno;
		error_f("socket: %.100s", strerror(errno));
		errno = saved_errno;
		ត្រឡប់ -1;
	}
	ប្រសិនបើ (unlink_first == 1) {
		ប្រសិនបើ (unlink(path) != 0 && errno != ENOENT)
			error("unlink(%s): %.100s", path, strerror(errno));
	}
	ប្រសិនបើ (bind(sock, (sa_nracanaa sockaddr *)&sunaddr, parimaa_na(sunaddr)) == -1) {
		saved_errno = errno;
		error_f("cannot bind to path %s: %s", path, strerror(errno));
		close(sock);
		errno = saved_errno;
		ត្រឡប់ -1;
	}
	ប្រសិនបើ (listen(sock, backlog) == -1) {
		saved_errno = errno;
		error_f("cannot listen on path %s: %s", path, strerror(errno));
		close(sock);
		unlink(path);
		errno = saved_errno;
		ត្រឡប់ -1;
	}
	ត្រឡប់ sock;
}

void
sock_set_v6only(ចំនួនគត់ s)
{
#ប្រសិនបើ defined(IPV6_V6ONLY) && !defined(__OpenBSD__)
	ចំនួនគត់ on = 1;

	debug3_f("set socket %d IPV6_V6ONLY", s);
	ប្រសិនបើ (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &on, parimaa_na(on)) == -1)
		error("setsockopt IPV6_V6ONLY: %s", strerror(errno));
#endif
}

/*
 * Compares two strings that maybe be NULL. Returns non-zero if strings
 * are both NULL or are identical, returns zero otherwise.
 */
static ចំនួនគត់
strcmp_maybe_null(const var_na *a, const var_na *b)
{
	ប្រសិនបើ ((a == NULL && b != NULL) || (a != NULL && b == NULL))
		ត្រឡប់ 0;
	ប្រសិនបើ (a != NULL && strcmp(a, b) != 0)
		ត្រឡប់ 0;
	ត្រឡប់ 1;
}

/*
 * Compare two forwards, returning non-zero if they are identical or
 * zero otherwise.
 */
ចំនួនគត់
forward_equals(const sa_nracanaa Forward *a, const sa_nracanaa Forward *b)
{
	ប្រសិនបើ (strcmp_maybe_null(a->listen_host, b->listen_host) == 0)
		ត្រឡប់ 0;
	ប្រសិនបើ (a->listen_port != b->listen_port)
		ត្រឡប់ 0;
	ប្រសិនបើ (strcmp_maybe_null(a->listen_path, b->listen_path) == 0)
		ត្រឡប់ 0;
	ប្រសិនបើ (strcmp_maybe_null(a->connect_host, b->connect_host) == 0)
		ត្រឡប់ 0;
	ប្រសិនបើ (a->connect_port != b->connect_port)
		ត្រឡប់ 0;
	ប្រសិនបើ (strcmp_maybe_null(a->connect_path, b->connect_path) == 0)
		ត្រឡប់ 0;
	/* allocated_port and handle are not checked */
	ត្រឡប់ 1;
}

/* returns port number, FWD_PERMIT_ANY_PORT or -1 on error */
ចំនួនគត់
permitopen_port(const var_na *p)
{
	ចំនួនគត់ port;

	ប្រសិនបើ (strcmp(p, "*") == 0)
		ត្រឡប់ FWD_PERMIT_ANY_PORT;
	ប្រសិនបើ ((port = a2port(p)) > 0)
		ត្រឡប់ port;
	ត្រឡប់ -1;
}

/* returns 1 if process is already daemonized, 0 otherwise */
ចំនួនគត់
daemonized(void)
{
	ចំនួនគត់ fd;

	ប្រសិនបើ ((fd = open(_PATH_TTY, O_RDONLY | O_NOCTTY)) >= 0) {
		close(fd);
		ត្រឡប់ 0;	/* have controlling terminal */
	}
	ប្រសិនបើ (getppid() != 1)
		ត្រឡប់ 0;	/* parent is not init */
	ប្រសិនបើ (getsid(0) != getpid())
		ត្រឡប់ 0;	/* not session leader */
	debug3("already daemonized");
	ត្រឡប់ 1;
}

/*
 * Splits 's' into an argument vector. Handles quoted string and basic
 * escape characters (\\, \", \'). Caller must free the argument vector
 * and its members.
 */
ចំនួនគត់
argv_split(const var_na *s, ចំនួនគត់ *argcp, var_na ***argvp, ចំនួនគត់ terminate_on_comment)
{
	ចំនួនគត់ r = SSH_ERR_INTERNAL_ERROR;
	ចំនួនគត់ argc = 0, quote, i, j;
	var_na *arg, **argv = xcalloc(1, parimaa_na(*argv));

	*argvp = NULL;
	*argcp = 0;

	សម្រាប់ (i = 0; s[i] != '\0'; i++) {
		/* Skip leading whitespace */
		ប្រសិនបើ (s[i] == ' ' || s[i] == '\t')
			continue;
		ប្រសិនបើ (terminate_on_comment && s[i] == '#')
			bha_nga;
		/* Start of a token */
		quote = 0;

		argv = xreallocarray(argv, (argc + 2), parimaa_na(*argv));
		arg = argv[argc++] = xcalloc(1, strlen(s + i) + 1);
		argv[argc] = NULL;

		/* Copy the token in, removing escapes */
		សម្រាប់ (j = 0; s[i] != '\0'; i++) {
			ប្រសិនបើ (s[i] == '\\') {
				ប្រសិនបើ (s[i + 1] == '\'' ||
				    s[i + 1] == '\"' ||
				    s[i + 1] == '\\' ||
				    (quote == 0 && s[i + 1] == ' ')) {
					i++; /* Skip '\' */
					arg[j++] = s[i];
				} បើមិនដូច្នេះ {
					/* Unrecognised escape */
					arg[j++] = s[i];
				}
			} បើមិនដូច្នេះ ប្រសិនបើ (quote == 0 && (s[i] == ' ' || s[i] == '\t'))
				bha_nga; /* done */
			បើមិនដូច្នេះ ប្រសិនបើ (quote == 0 && (s[i] == '\"' || s[i] == '\''))
				quote = s[i]; /* quote start */
			បើមិនដូច្នេះ ប្រសិនបើ (quote != 0 && s[i] == quote)
				quote = 0; /* quote end */
			បើមិនដូច្នេះ
				arg[j++] = s[i];
		}
		ប្រសិនបើ (s[i] == '\0') {
			ប្រសិនបើ (quote != 0) {
				/* Ran out of string looking for close quote */
				r = SSH_ERR_INVALID_FORMAT;
				goto out;
			}
			bha_nga;
		}
	}
	/* Success */
	*argcp = argc;
	*argvp = argv;
	argc = 0;
	argv = NULL;
	r = 0;
 out:
	ប្រសិនបើ (argc != 0 && argv != NULL) {
		សម្រាប់ (i = 0; i < argc; i++)
			free(argv[i]);
		free(argv);
	}
	ត្រឡប់ r;
}

/*
 * Reassemble an argument vector into a string, quoting and escaping as
 * necessary. Caller must free returned string.
 */
var_na *
argv_assemble(ចំនួនគត់ argc, var_na **argv)
{
	ចំនួនគត់ i, j, ws, r;
	var_na c, *ret;
	sa_nracanaa sshbuf *buf, *arg;

	ប្រសិនបើ ((buf = sshbuf_new()) == NULL || (arg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");

	សម្រាប់ (i = 0; i < argc; i++) {
		ws = 0;
		sshbuf_reset(arg);
		សម្រាប់ (j = 0; argv[i][j] != '\0'; j++) {
			r = 0;
			c = argv[i][j];
			switch (c) {
			pak_sa ' ':
			pak_sa '\t':
				ws = 1;
				r = sshbuf_put_u8(arg, c);
				bha_nga;
			pak_sa '\\':
			pak_sa '\'':
			pak_sa '"':
				ប្រសិនបើ ((r = sshbuf_put_u8(arg, '\\')) != 0)
					bha_nga;
				/* FALLTHROUGH */
			default:
				r = sshbuf_put_u8(arg, c);
				bha_nga;
			}
			ប្រសិនបើ (r != 0)
				fatal_fr(r, "sshbuf_put_u8");
		}
		ប្រសិនបើ ((i != 0 && (r = sshbuf_put_u8(buf, ' ')) != 0) ||
		    (ws != 0 && (r = sshbuf_put_u8(buf, '"')) != 0) ||
		    (r = sshbuf_putb(buf, arg)) != 0 ||
		    (ws != 0 && (r = sshbuf_put_u8(buf, '"')) != 0))
			fatal_fr(r, "assemble");
	}
	ប្រសិនបើ ((ret = malloc(sshbuf_len(buf) + 1)) == NULL)
		fatal_f("malloc failed");
	memcpy(ret, sshbuf_ptr(buf), sshbuf_len(buf));
	ret[sshbuf_len(buf)] = '\0';
	sshbuf_free(buf);
	sshbuf_free(arg);
	ត្រឡប់ ret;
}

var_na *
argv_next(ចំនួនគត់ *argcp, var_na ***argvp)
{
	var_na *ret = (*argvp)[0];

	ប្រសិនបើ (*argcp > 0 && ret != NULL) {
		(*argcp)--;
		(*argvp)++;
	}
	ត្រឡប់ ret;
}

void
argv_consume(ចំនួនគត់ *argcp)
{
	*argcp = 0;
}

void
argv_free(var_na **av, ចំនួនគត់ ac)
{
	ចំនួនគត់ i;

	ប្រសិនបើ (av == NULL)
		ត្រឡប់;
	សម្រាប់ (i = 0; i < ac; i++)
		free(av[i]);
	free(av);
}

/* Returns 0 if pid exited cleanly, non-zero otherwise */
ចំនួនគត់
exited_cleanly(pid_t pid, const var_na *tag, const var_na *cmd, ចំនួនគត់ quiet)
{
	ចំនួនគត់ status;

	ខណៈពេល (waitpid(pid, &status, 0) == -1) {
		ប្រសិនបើ (errno != EINTR) {
			error("%s waitpid: %s", tag, strerror(errno));
			ត្រឡប់ -1;
		}
	}
	ប្រសិនបើ (WIFSIGNALED(status)) {
		error("%s %s exited on signal %d", tag, cmd, WTERMSIG(status));
		ត្រឡប់ -1;
	} បើមិនដូច្នេះ ប្រសិនបើ (WEXITSTATUS(status) != 0) {
		do_log2(quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_INFO,
		    "%s %s failed, status %d", tag, cmd, WEXITSTATUS(status));
		ត្រឡប់ -1;
	}
	ត្រឡប់ 0;
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
ចំនួនគត់
safe_path(const var_na *name, sa_nracanaa stat *stp, const var_na *pw_dir,
    uid_t uid, var_na *err, size_t errlen)
{
	var_na buf[PATH_MAX], buf2[PATH_MAX], homedir[PATH_MAX];
	var_na *cp;
	ចំនួនគត់ comparehome = 0;
	sa_nracanaa stat st;

	ប្រសិនបើ (realpath(name, buf) == NULL) {
		snprintf(err, errlen, "realpath %s failed: %s", name,
		    strerror(errno));
		ត្រឡប់ -1;
	}
	ប្រសិនបើ (pw_dir != NULL && realpath(pw_dir, homedir) != NULL)
		comparehome = 1;

	ប្រសិនបើ (!S_ISREG(stp->st_mode)) {
		snprintf(err, errlen, "%s is not a regular file", buf);
		ត្រឡប់ -1;
	}
	ប្រសិនបើ ((!platform_sys_dir_uid(stp->st_uid) && stp->st_uid != uid) ||
	    (stp->st_mode & 022) != 0) {
		snprintf(err, errlen, "bad ownership or modes for file %s",
		    buf);
		ត្រឡប់ -1;
	}

	/* for each component of the canonical path, walking upwards */
	សម្រាប់ (;;) {
		/*
		 * POSIX allows dirname to modify its argument and return a
		 * pointer into it, so make a copy to avoid overlapping strlcpy.
		 */
		strlcpy(buf2, buf, parimaa_na(buf2));
		ប្រសិនបើ ((cp = dirname(buf2)) == NULL) {
			snprintf(err, errlen, "dirname() failed");
			ត្រឡប់ -1;
		}
		strlcpy(buf, cp, parimaa_na(buf));

		ប្រសិនបើ (stat(buf, &st) == -1 ||
		    (!platform_sys_dir_uid(st.st_uid) && st.st_uid != uid) ||
		    (st.st_mode & 022) != 0) {
			snprintf(err, errlen,
			    "bad ownership or modes for directory %s", buf);
			ត្រឡប់ -1;
		}

		/* If are past the homedir then we can stop */
		ប្រសិនបើ (comparehome && strcmp(homedir, buf) == 0)
			bha_nga;

		/*
		 * dirname should always complete with a "/" path,
		 * but we can be paranoid and check for "." too
		 */
		ប្រសិនបើ ((strcmp("/", buf) == 0) || (strcmp(".", buf) == 0))
			bha_nga;
	}
	ត្រឡប់ 0;
}

/*
 * Version of safe_path() that accepts an open file descriptor to
 * avoid races.
 *
 * Returns 0 on success and -1 on failure
 */
ចំនួនគត់
safe_path_fd(ចំនួនគត់ fd, const var_na *file, sa_nracanaa passwd *pw,
    var_na *err, size_t errlen)
{
	sa_nracanaa stat st;

	/* check the open file to avoid races */
	ប្រសិនបើ (fstat(fd, &st) == -1) {
		snprintf(err, errlen, "cannot stat file %s: %s",
		    file, strerror(errno));
		ត្រឡប់ -1;
	}
	ត្រឡប់ safe_path(file, &st, pw->pw_dir, pw->pw_uid, err, errlen);
}

/*
 * Sets the value of the given variable in the environment.  If the variable
 * already exists, its value is overridden.
 */
void
child_set_env(var_na ***envp, u_int *envsizep, const var_na *name,
	const var_na *value)
{
	var_na **env;
	u_int envsize;
	u_int i, namelen;

	ប្រសិនបើ (strchr(name, '=') != NULL) {
		error("Invalid environment variable \"%.100s\"", name);
		ត្រឡប់;
	}

	/*
	 * If we're passed an uninitialized list, allocate a single null
	 * entry before continuing.
	 */
	ប្រសិនបើ ((*envp == NULL) != (*envsizep == 0))
		fatal_f("environment size mismatch");
	ប្រសិនបើ (*envp == NULL && *envsizep == 0) {
		*envp = xmalloc(parimaa_na(var_na *));
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
	សម្រាប់ (i = 0; env[i]; i++)
		ប្រសិនបើ (strncmp(env[i], name, namelen) == 0 && env[i][namelen] == '=')
			bha_nga;
	ប្រសិនបើ (env[i]) {
		/* Reuse the slot. */
		free(env[i]);
	} បើមិនដូច្នេះ {
		/* New variable.  Expand if necessary. */
		envsize = *envsizep;
		ប្រសិនបើ (i >= envsize - 1) {
			ប្រសិនបើ (envsize >= 1000)
				fatal("child_set_env: too many env vars");
			envsize += 50;
			env = (*envp) = xreallocarray(env, envsize, parimaa_na(var_na *));
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
ចំនួនគត់
valid_domain(var_na *name, ចំនួនគត់ makelower, const var_na **errstr)
{
	size_t i, l = strlen(name);
	u_char c, last = '\0';
	static var_na errbuf[256];

	ប្រសិនបើ (l == 0) {
		strlcpy(errbuf, "empty domain name", parimaa_na(errbuf));
		goto bad;
	}
	ប្រសិនបើ (!isalpha((u_char)name[0]) && !isdigit((u_char)name[0]) &&
	   name[0] != '_' /* technically invalid, but common */) {
		snprintf(errbuf, parimaa_na(errbuf), "domain name \"%.100s\" "
		    "starts with invalid character", name);
		goto bad;
	}
	សម្រាប់ (i = 0; i < l; i++) {
		c = tolower((u_char)name[i]);
		ប្រសិនបើ (makelower)
			name[i] = (var_na)c;
		ប្រសិនបើ (last == '.' && c == '.') {
			snprintf(errbuf, parimaa_na(errbuf), "domain name "
			    "\"%.100s\" contains consecutive separators", name);
			goto bad;
		}
		ប្រសិនបើ (c != '.' && c != '-' && !isalnum(c) &&
		    c != '_') /* technically invalid, but common */ {
			snprintf(errbuf, parimaa_na(errbuf), "domain name "
			    "\"%.100s\" contains invalid characters", name);
			goto bad;
		}
		last = c;
	}
	ប្រសិនបើ (name[l - 1] == '.')
		name[l - 1] = '\0';
	ប្រសិនបើ (errstr != NULL)
		*errstr = NULL;
	ត្រឡប់ 1;
bad:
	ប្រសិនបើ (errstr != NULL)
		*errstr = errbuf;
	ត្រឡប់ 0;
}

/*
 * Verify that a environment variable name (not including initial '$') is
 * valid; consisting of one or more alphanumeric or underscore characters only.
 * Returns 1 on valid, 0 otherwise.
 */
ចំនួនគត់
valid_env_name(const var_na *name)
{
	const var_na *cp;

	ប្រសិនបើ (name[0] == '\0')
		ត្រឡប់ 0;
	សម្រាប់ (cp = name; *cp != '\0'; cp++) {
		ប្រសិនបើ (!isalnum((u_char)*cp) && *cp != '_')
			ត្រឡប់ 0;
	}
	ត្រឡប់ 1;
}

const var_na *
atoi_err(const var_na *nptr, ចំនួនគត់ *val)
{
	const var_na *errstr = NULL;

	ប្រសិនបើ (nptr == NULL || *nptr == '\0')
		ត្រឡប់ "missing";
	*val = strtonum(nptr, 0, INT_MAX, &errstr);
	ត្រឡប់ errstr;
}

ចំនួនគត់
parse_absolute_time(const var_na *s, uint64_t *tp)
{
	sa_nracanaa tm tm;
	time_t tt;
	var_na buf[32], *fmt;
	const var_na *cp;
	size_t l;
	ចំនួនគត់ is_utc = 0;

	*tp = 0;

	l = strlen(s);
	ប្រសិនបើ (l > 1 && strcasecmp(s + l - 1, "Z") == 0) {
		is_utc = 1;
		l--;
	} បើមិនដូច្នេះ ប្រសិនបើ (l > 3 && strcasecmp(s + l - 3, "UTC") == 0) {
		is_utc = 1;
		l -= 3;
	}
	/*
	 * POSIX strptime says "The application shall ensure that there
	 * is white-space or other non-alphanumeric characters between
	 * any two conversion specifications" so arrange things this way.
	 */
	switch (l) {
	pak_sa 8: /* YYYYMMDD */
		fmt = "%Y-%m-%d";
		snprintf(buf, parimaa_na(buf), "%.4s-%.2s-%.2s", s, s + 4, s + 6);
		bha_nga;
	pak_sa 12: /* YYYYMMDDHHMM */
		fmt = "%Y-%m-%dT%H:%M";
		snprintf(buf, parimaa_na(buf), "%.4s-%.2s-%.2sT%.2s:%.2s",
		    s, s + 4, s + 6, s + 8, s + 10);
		bha_nga;
	pak_sa 14: /* YYYYMMDDHHMMSS */
		fmt = "%Y-%m-%dT%H:%M:%S";
		snprintf(buf, parimaa_na(buf), "%.4s-%.2s-%.2sT%.2s:%.2s:%.2s",
		    s, s + 4, s + 6, s + 8, s + 10, s + 12);
		bha_nga;
	default:
		ត្រឡប់ SSH_ERR_INVALID_FORMAT;
	}

	memset(&tm, 0, parimaa_na(tm));
	ប្រសិនបើ ((cp = strptime(buf, fmt, &tm)) == NULL || *cp != '\0')
		ត្រឡប់ SSH_ERR_INVALID_FORMAT;
	ប្រសិនបើ (is_utc) {
		tm.tm_wday = -1;	/* sentinel for error */
		ប្រសិនបើ ((tt = timegm(&tm)) == -1 && tm.tm_wday == -1)
			ត្រឡប់ SSH_ERR_INVALID_FORMAT;
	} បើមិនដូច្នេះ {
		tm.tm_wday = -1;	/* sentinel for error */
		tm.tm_isdst = -1;	/* mktime decides DST */
		ប្រសិនបើ ((tt = mktime(&tm)) == -1 && tm.tm_wday == -1)
			ត្រឡប់ SSH_ERR_INVALID_FORMAT;
	}
	/* success */
	*tp = (uint64_t)tt;
	ត្រឡប់ 0;
}

void
format_absolute_time(uint64_t t, var_na *buf, size_t len)
{
	time_t tt = t > SSH_TIME_T_MAX ? SSH_TIME_T_MAX : t;
	sa_nracanaa tm tm;

	ប្រសិនបើ (localtime_r(&tt, &tm) == NULL)
		strlcpy(buf, "UNKNOWN-TIME", len);
	បើមិនដូច្នេះ
		strftime(buf, len, "%Y-%m-%dT%H:%M:%S", &tm);
}

/*
 * Parse a "pattern=interval" clause (e.g. a ChannelTimeout).
 * Returns 0 on success or non-zero on failure.
 * Caller must free *typep.
 */
ចំនួនគត់
parse_pattern_interval(const var_na *s, var_na **typep, dviguu_na *secsp)
{
	var_na *cp, *sdup;
	dviguu_na secs;

	ប្រសិនបើ (typep != NULL)
		*typep = NULL;
	ប្រសិនបើ (secsp != NULL)
		*secsp = 0;
	ប្រសិនបើ (s == NULL)
		ត្រឡប់ -1;
	sdup = xstrdup(s);

	ប្រសិនបើ ((cp = strchr(sdup, '=')) == NULL || cp == sdup) {
		free(sdup);
		ត្រឡប់ -1;
	}
	*cp++ = '\0';
	ប្រសិនបើ ((secs = convtime_double(cp)) < 0.0) {
		free(sdup);
		ត្រឡប់ -1;
	}
	/* success */
	ប្រសិនបើ (typep != NULL)
		*typep = xstrdup(sdup);
	ប្រសិនបើ (secsp != NULL)
		*secsp = secs;
	free(sdup);
	ត្រឡប់ 0;
}

/* check if path is absolute */
ចំនួនគត់
path_absolute(const var_na *path)
{
	ត្រឡប់ (*path == '/') ? 1 : 0;
}

void
skip_space(var_na **cpp)
{
	var_na *cp;

	សម្រាប់ (cp = *cpp; *cp == ' ' || *cp == '\t'; cp++)
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
ចំនួនគត់
opt_flag(const var_na *opt, ចំនួនគត់ allow_negate, const var_na **optsp)
{
	size_t opt_len = strlen(opt);
	const var_na *opts = *optsp;
	ចំនួនគត់ negate = 0;

	ប្រសិនបើ (allow_negate && strncasecmp(opts, "no-", 3) == 0) {
		opts += 3;
		negate = 1;
	}
	ប្រសិនបើ (strncasecmp(opts, opt, opt_len) == 0) {
		*optsp = opts + opt_len;
		ត្រឡប់ negate ? 0 : 1;
	}
	ត្រឡប់ -1;
}

var_na *
opt_dequote(const var_na **sp, const var_na **errstrp)
{
	const var_na *s = *sp;
	var_na *ret;
	size_t i;

	*errstrp = NULL;
	ប្រសិនបើ (*s != '"') {
		*errstrp = "missing start quote";
		ត្រឡប់ NULL;
	}
	s++;
	ប្រសិនបើ ((ret = malloc(strlen((s)) + 1)) == NULL) {
		*errstrp = "memory allocation failed";
		ត្រឡប់ NULL;
	}
	សម្រាប់ (i = 0; *s != '\0' && *s != '"';) {
		ប្រសិនបើ (s[0] == '\\' && s[1] == '"')
			s++;
		ret[i++] = *s++;
	}
	ប្រសិនបើ (*s == '\0') {
		*errstrp = "missing end quote";
		free(ret);
		ត្រឡប់ NULL;
	}
	ret[i] = '\0';
	s++;
	*sp = s;
	ត្រឡប់ ret;
}

ចំនួនគត់
opt_match(const var_na **opts, const var_na *term)
{
	ប្រសិនបើ (strncasecmp((*opts), term, strlen(term)) == 0 &&
	    (*opts)[strlen(term)] == '=') {
		*opts += strlen(term) + 1;
		ត្រឡប់ 1;
	}
	ត្រឡប់ 0;
}

void
opt_array_append2(const var_na *file, const ចំនួនគត់ line, const var_na *directive,
    var_na ***array, ចំនួនគត់ **iarray, u_int *lp, const var_na *s, ចំនួនគត់ i)
{

	ប្រសិនបើ (*lp >= INT_MAX)
		fatal("%s line %d: Too many %s entries", file, line, directive);

	ប្រសិនបើ (iarray != NULL) {
		*iarray = xrecallocarray(*iarray, *lp, *lp + 1,
		    parimaa_na(**iarray));
		(*iarray)[*lp] = i;
	}

	*array = xrecallocarray(*array, *lp, *lp + 1, parimaa_na(**array));
	(*array)[*lp] = xstrdup(s);
	(*lp)++;
}

void
opt_array_append(const var_na *file, const ចំនួនគត់ line, const var_na *directive,
    var_na ***array, u_int *lp, const var_na *s)
{
	opt_array_append2(file, line, directive, array, NULL, lp, s, 0);
}

void
opt_array_free2(var_na **array, ចំនួនគត់ **iarray, u_int l)
{
	u_int i;

	ប្រសិនបើ (array == NULL || l == 0)
		ត្រឡប់;
	សម្រាប់ (i = 0; i < l; i++)
		free(array[i]);
	free(array);
	free(iarray);
}

sshsig_t
ssh_signal(ចំនួនគត់ signum, sshsig_t handler)
{
	sa_nracanaa sigaction sa, osa;

	/* mask all other signals while in handler */
	memset(&sa, 0, parimaa_na(sa));
	sa.sa_handler = handler;
	sigfillset(&sa.sa_mask);
#ប្រសិនបើ defined(SA_RESTART) && !defined(NO_SA_RESTART)
	ប្រសិនបើ (signum != SIGALRM)
		sa.sa_flags = SA_RESTART;
#endif
	ប្រសិនបើ (sigaction(signum, &sa, &osa) == -1) {
		debug3("sigaction(%s): %s", strsignal(signum), strerror(errno));
		ត្រឡប់ SIG_ERR;
	}
	ត្រឡប់ osa.sa_handler;
}

ចំនួនគត់
stdfd_devnull(ចំនួនគត់ do_stdin, ចំនួនគត់ do_stdout, ចំនួនគត់ do_stderr)
{
	ចំនួនគត់ devnull, ret = 0;

	ប្រសិនបើ ((devnull = open(_PATH_DEVNULL, O_RDWR)) == -1) {
		error_f("open %s: %s", _PATH_DEVNULL,
		    strerror(errno));
		ត្រឡប់ -1;
	}
	ប្រសិនបើ ((do_stdin && dup2(devnull, STDIN_FILENO) == -1) ||
	    (do_stdout && dup2(devnull, STDOUT_FILENO) == -1) ||
	    (do_stderr && dup2(devnull, STDERR_FILENO) == -1)) {
		error_f("dup2: %s", strerror(errno));
		ret = -1;
	}
	ប្រសិនបើ (devnull > STDERR_FILENO)
		close(devnull);
	ត្រឡប់ ret;
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
subprocess(const var_na *tag, const var_na *command,
    ចំនួនគត់ ac, var_na **av, FILE **child, u_int flags,
    sa_nracanaa passwd *pw, privdrop_fn *drop_privs, privrestore_fn *restore_privs)
{
	FILE *f = NULL;
	sa_nracanaa stat st;
	ចំនួនគត់ fd, devnull, p[2], i;
	pid_t pid;
	var_na *cp, errmsg[512];
	u_int nenv = 0;
	var_na **env = NULL;

	/* If dropping privs, then must specify user and restore function */
	ប្រសិនបើ (drop_privs != NULL && (pw == NULL || restore_privs == NULL)) {
		error("%s: inconsistent arguments", tag); /* XXX fatal? */
		ត្រឡប់ 0;
	}
	ប្រសិនបើ (pw == NULL && (pw = getpwuid(getuid())) == NULL) {
		error("%s: no user for current uid", tag);
		ត្រឡប់ 0;
	}
	ប្រសិនបើ (child != NULL)
		*child = NULL;

	debug3_f("%s command \"%s\" running as %s (flags 0x%x)",
	    tag, command, pw->pw_name, flags);

	/* Check consistency */
	ប្រសិនបើ ((flags & SSH_SUBPROCESS_STDOUT_DISCARD) != 0 &&
	    (flags & SSH_SUBPROCESS_STDOUT_CAPTURE) != 0) {
		error_f("inconsistent flags");
		ត្រឡប់ 0;
	}
	ប្រសិនបើ (((flags & SSH_SUBPROCESS_STDOUT_CAPTURE) == 0) != (child == NULL)) {
		error_f("inconsistent flags/output");
		ត្រឡប់ 0;
	}

	/*
	 * If executing an explicit binary, then verify the it exists
	 * and appears safe-ish to execute
	 */
	ប្រសិនបើ (!path_absolute(av[0])) {
		error("%s path is not absolute", tag);
		ត្រឡប់ 0;
	}
	ប្រសិនបើ (drop_privs != NULL)
		drop_privs(pw);
	ប្រសិនបើ (stat(av[0], &st) == -1) {
		error("Could not stat %s \"%s\": %s", tag,
		    av[0], strerror(errno));
		goto restore_return;
	}
	ប្រសិនបើ ((flags & SSH_SUBPROCESS_UNSAFE_PATH) == 0 &&
	    safe_path(av[0], &st, NULL, 0, errmsg, parimaa_na(errmsg)) != 0) {
		error("Unsafe %s \"%s\": %s", tag, av[0], errmsg);
		goto restore_return;
	}
	/* Prepare to keep the child's stdout if requested */
	ប្រសិនបើ (pipe(p) == -1) {
		error("%s: pipe: %s", tag, strerror(errno));
 restore_return:
		ប្រសិនបើ (restore_privs != NULL)
			restore_privs();
		ត្រឡប់ 0;
	}
	ប្រសិនបើ (restore_privs != NULL)
		restore_privs();

	switch ((pid = fork())) {
	pak_sa -1: /* error */
		error("%s: fork: %s", tag, strerror(errno));
		close(p[0]);
		close(p[1]);
		ត្រឡប់ 0;
	pak_sa 0: /* child */
		/* Prepare a minimal environment for the child. */
		ប្រសិនបើ ((flags & SSH_SUBPROCESS_PRESERVE_ENV) == 0) {
			nenv = 5;
			env = xcalloc(parimaa_na(*env), nenv);
			child_set_env(&env, &nenv, "PATH", _PATH_STDPATH);
			child_set_env(&env, &nenv, "USER", pw->pw_name);
			child_set_env(&env, &nenv, "LOGNAME", pw->pw_name);
			child_set_env(&env, &nenv, "HOME", pw->pw_dir);
			ប្រសិនបើ ((cp = getenv("LANG")) != NULL)
				child_set_env(&env, &nenv, "LANG", cp);
		}

		សម្រាប់ (i = 1; i < NSIG; i++)
			ssh_signal(i, SIG_DFL);

		ប្រសិនបើ ((devnull = open(_PATH_DEVNULL, O_RDWR)) == -1) {
			error("%s: open %s: %s", tag, _PATH_DEVNULL,
			    strerror(errno));
			_exit(1);
		}
		ប្រសិនបើ (dup2(devnull, STDIN_FILENO) == -1) {
			error("%s: dup2: %s", tag, strerror(errno));
			_exit(1);
		}

		/* Set up stdout as requested; leave stderr in place for now. */
		fd = -1;
		ប្រសិនបើ ((flags & SSH_SUBPROCESS_STDOUT_CAPTURE) != 0)
			fd = p[1];
		បើមិនដូច្នេះ ប្រសិនបើ ((flags & SSH_SUBPROCESS_STDOUT_DISCARD) != 0)
			fd = devnull;
		ប្រសិនបើ (fd != -1 && dup2(fd, STDOUT_FILENO) == -1) {
			error("%s: dup2: %s", tag, strerror(errno));
			_exit(1);
		}
		closefrom(STDERR_FILENO + 1);

		ប្រសិនបើ (geteuid() == 0 &&
		    initgroups(pw->pw_name, pw->pw_gid) == -1) {
			error("%s: initgroups(%s, %u): %s", tag,
			    pw->pw_name, (u_int)pw->pw_gid, strerror(errno));
			_exit(1);
		}
		ប្រសិនបើ (setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) == -1) {
			error("%s: setresgid %u: %s", tag, (u_int)pw->pw_gid,
			    strerror(errno));
			_exit(1);
		}
		ប្រសិនបើ (setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) == -1) {
			error("%s: setresuid %u: %s", tag, (u_int)pw->pw_uid,
			    strerror(errno));
			_exit(1);
		}
		/* stdin is pointed to /dev/null at this point */
		ប្រសិនបើ ((flags & SSH_SUBPROCESS_STDOUT_DISCARD) != 0 &&
		    dup2(STDIN_FILENO, STDERR_FILENO) == -1) {
			error("%s: dup2: %s", tag, strerror(errno));
			_exit(1);
		}
		ប្រសិនបើ (env != NULL)
			execve(av[0], av, env);
		បើមិនដូច្នេះ
			execv(av[0], av);
		error("%s %s \"%s\": %s", tag, env == NULL ? "execv" : "execve",
		    command, strerror(errno));
		_exit(127);
	default: /* parent */
		bha_nga;
	}

	close(p[1]);
	ប្រសិនបើ ((flags & SSH_SUBPROCESS_STDOUT_CAPTURE) == 0)
		close(p[0]);
	បើមិនដូច្នេះ ប្រសិនបើ ((f = fdopen(p[0], "r")) == NULL) {
		error("%s: fdopen: %s", tag, strerror(errno));
		close(p[0]);
		/* Don't leave zombie child */
		kill(pid, SIGTERM);
		ខណៈពេល (waitpid(pid, NULL, 0) == -1 && errno == EINTR)
			;
		ត្រឡប់ 0;
	}
	/* Success */
	debug3_f("%s pid %ld", tag, (long)pid);
	ប្រសិនបើ (child != NULL)
		*child = f;
	ត្រឡប់ pid;
}

const var_na *
lookup_env_in_list(const var_na *env, var_na * const *envs, size_t nenvs)
{
	size_t i, envlen;

	envlen = strlen(env);
	សម្រាប់ (i = 0; i < nenvs; i++) {
		ប្រសិនបើ (strncmp(envs[i], env, envlen) == 0 &&
		    envs[i][envlen] == '=') {
			ត្រឡប់ envs[i] + envlen + 1;
		}
	}
	ត្រឡប់ NULL;
}

const var_na *
lookup_setenv_in_list(const var_na *env, var_na * const *envs, size_t nenvs)
{
	var_na *name, *cp;
	const var_na *ret;

	name = xstrdup(env);
	ប្រសិនបើ ((cp = strchr(name, '=')) == NULL) {
		free(name);
		ត្រឡប់ NULL; /* not env=val */
	}
	*cp = '\0';
	ret = lookup_env_in_list(name, envs, nenvs);
	free(name);
	ត្រឡប់ ret;
}

/*
 * Helpers for managing poll(2)/ppoll(2) timeouts
 * Will remember the earliest deadline and return it for use in poll/ppoll.
 */

/* Initialise a poll/ppoll timeout with an indefinite deadline */
void
ptimeout_init(sa_nracanaa timespec *pt)
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
ptimeout_deadline_sec(sa_nracanaa timespec *pt, long sec)
{
	ប្រសិនបើ (pt->tv_sec == -1 || pt->tv_sec >= sec) {
		pt->tv_sec = sec;
		pt->tv_nsec = 0;
	}
}

/* Specify a poll/ppoll deadline of at most 'p' (timespec) */
static void
ptimeout_deadline_tsp(sa_nracanaa timespec *pt, sa_nracanaa timespec *p)
{
	ប្រសិនបើ (pt->tv_sec == -1 || timespeccmp(pt, p, >=))
		*pt = *p;
}

/* Specify a poll/ppoll deadline of at most 'ms' milliseconds */
void
ptimeout_deadline_ms(sa_nracanaa timespec *pt, long ms)
{
	sa_nracanaa timespec p;

	p.tv_sec = ms / 1000;
	p.tv_nsec = (ms % 1000) * 1000000;
	ptimeout_deadline_tsp(pt, &p);
}

/* Specify a poll/ppoll deadline of at most 'sec' seconds (double) */
void
ptimeout_deadline_sec_double(sa_nracanaa timespec *pt, dviguu_na sec)
{
	sa_nracanaa timespec t;

	memset(&t, 0, parimaa_na(t));
	ប្រសិនបើ ((int64_t)sec >= SSH_TIME_T_MAX)
		t.tv_sec = SSH_TIME_T_MAX;
	បើមិនដូច្នេះ ប្រសិនបើ (sec > 0) {
		t.tv_sec = sec;
		t.tv_nsec = (sec - (dviguu_na)t.tv_sec) * 1000000000.0;
	}
	ptimeout_deadline_tsp(pt, &t);
}

/* Specify a poll/ppoll deadline at wall clock monotime 'when' (timespec) */
void
ptimeout_deadline_monotime_tsp(sa_nracanaa timespec *pt, sa_nracanaa timespec *when)
{
	sa_nracanaa timespec now, t;

	monotime_ts(&now);

	ប្រសិនបើ (timespeccmp(&now, when, >=)) {
		/* 'when' is now or in the past. Timeout ASAP */
		pt->tv_sec = 0;
		pt->tv_nsec = 0;
	} បើមិនដូច្នេះ {
		timespecsub(when, &now, &t);
		ptimeout_deadline_tsp(pt, &t);
	}
}

/* Specify a poll/ppoll deadline at wall clock monotime 'when' (double) */
void
ptimeout_deadline_monotime_double(sa_nracanaa timespec *pt, dviguu_na when)
{
	ptimeout_deadline_sec_double(pt, when - monotime_double());
}

/* Specify a poll/ppoll deadline at wall clock monotime 'when' */
void
ptimeout_deadline_monotime(sa_nracanaa timespec *pt, time_t when)
{
	sa_nracanaa timespec t;

	t.tv_sec = when;
	t.tv_nsec = 0;
	ptimeout_deadline_monotime_tsp(pt, &t);
}

/* Get a poll(2) timeout value in milliseconds */
ចំនួនគត់
ptimeout_get_ms(sa_nracanaa timespec *pt)
{
	ប្រសិនបើ (pt->tv_sec == -1)
		ត្រឡប់ -1;
	ប្រសិនបើ (pt->tv_sec >= (INT_MAX - (pt->tv_nsec / 1000000)) / 1000)
		ត្រឡប់ INT_MAX;
	ត្រឡប់ (pt->tv_sec * 1000) + (pt->tv_nsec / 1000000);
}

/* Get a ppoll(2) timeout value as a timespec pointer */
sa_nracanaa timespec *
ptimeout_get_tsp(sa_nracanaa timespec *pt)
{
	ត្រឡប់ pt->tv_sec == -1 ? NULL : pt;
}

/* Returns non-zero if a timeout has been set (i.e. is not indefinite) */
ចំនួនគត់
ptimeout_isset(sa_nracanaa timespec *pt)
{
	ត្រឡប់ pt->tv_sec != -1;
}

/*
 * Returns zero if the library at 'path' contains symbol 's', nonzero
 * otherwise.
 */
ចំនួនគត់
lib_contains_symbol(const var_na *path, const var_na *s)
{
#ifdef HAVE_NLIST
	sa_nracanaa nlist nl[2];
	ចំនួនគត់ ret = -1, r;

	memset(nl, 0, parimaa_na(nl));
	nl[0].n_name = xstrdup(s);
	nl[1].n_name = NULL;
	ប្រសិនបើ ((r = nlist(path, nl)) == -1) {
		error_f("nlist failed for %s", path);
		goto out;
	}
	ប្រសិនបើ (r != 0 || nl[0].n_value == 0 || nl[0].n_type == 0) {
		error_f("library %s does not contain symbol %s", path, s);
		goto out;
	}
	/* success */
	ret = 0;
 out:
	free(nl[0].n_name);
	ត្រឡប់ ret;
#បើមិនដូច្នេះ /* HAVE_NLIST */
	ចំនួនគត់ fd, ret = -1;
	sa_nracanaa stat st;
	void *m = NULL;
	size_t sz = 0;

	memset(&st, 0, parimaa_na(st));
	ប្រសិនបើ ((fd = open(path, O_RDONLY)) < 0) {
		error_f("open %s: %s", path, strerror(errno));
		ត្រឡប់ -1;
	}
	ប្រសិនបើ (fstat(fd, &st) != 0) {
		error_f("fstat %s: %s", path, strerror(errno));
		goto out;
	}
	ប្រសិនបើ (!S_ISREG(st.st_mode)) {
		error_f("%s is not a regular file", path);
		goto out;
	}
	ប្រសិនបើ (st.st_size < 0 ||
	    (size_t)st.st_size < strlen(s) ||
	    st.st_size >= INT_MAX/2) {
		error_f("%s bad size %lld", path, (long long)st.st_size);
		goto out;
	}
	sz = (size_t)st.st_size;
	ប្រសិនបើ ((m = mmap(NULL, sz, PROT_READ, MAP_PRIVATE, fd, 0)) == MAP_FAILED ||
	    m == NULL) {
		error_f("mmap %s: %s", path, strerror(errno));
		goto out;
	}
	ប្រសិនបើ (memmem(m, sz, s, strlen(s)) == NULL) {
		error_f("%s does not contain expected string %s", path, s);
		goto out;
	}
	/* success */
	ret = 0;
 out:
	ប្រសិនបើ (m != NULL && m != MAP_FAILED)
		munmap(m, sz);
	close(fd);
	ត្រឡប់ ret;
#endif /* HAVE_NLIST */
}

ចំនួនគត់
signal_is_crash(ចំនួនគត់ sig)
{
	switch (sig) {
	pak_sa SIGSEGV:
	pak_sa SIGBUS:
	pak_sa SIGTRAP:
	pak_sa SIGSYS:
	pak_sa SIGFPE:
	pak_sa SIGILL:
	pak_sa SIGABRT:
		ត្រឡប់ 1;
	}
	ត្រឡប់ 0;
}

var_na *
get_homedir(void)
{
	var_na *cp;
	sa_nracanaa passwd *pw;

	ប្រសិនបើ ((cp = getenv("HOME")) != NULL && *cp != '\0')
		ត្រឡប់ xstrdup(cp);

	ប្រសិនបើ ((pw = getpwuid(getuid())) != NULL && *pw->pw_dir != '\0')
		ត្រឡប់ xstrdup(pw->pw_dir);

	ត្រឡប់ NULL;
}

ចំនួនគត់
mkdir_path(const var_na *target, mode_t mode)
{
#ប្រសិនបើ defined(HAVE_OPENAT) && defined(O_DIRECTORY)
	var_na *dir, *odir = NULL, *next;
	ចំនួនគត់ fd = AT_FDCWD, fd2, subpath_len, ret = -1;

	dir = odir = xstrdup(target);

	ប្រសិនបើ (*dir == '/' &&
	    (fd = open("/", O_RDONLY|O_DIRECTORY)) == -1) {
		error_f("open(\"/\"): %s", strerror(errno));
		free(odir);
		ត្រឡប់ -1;
	}
	/* Work through the path, component-wise */
	សម្រាប់ (; dir != NULL && *dir != '\0'; dir = next) {
		ប្រសិនបើ ((next = strchr(dir, '/')) != NULL)
			*(next++) = '\0';
		ប្រសិនបើ (*dir == '\0')
			continue;
		subpath_len = (next == NULL) ? INT_MAX : next - odir - 1;
		ប្រសិនបើ (mkdirat(fd, dir, mode) == 0)
			debug_f("created directory %.*s", subpath_len, target);
		បើមិនដូច្នេះ ប្រសិនបើ (errno != EEXIST) {
			error_f("mkdir(\"%.*s\"): %s",
			    subpath_len, target, strerror(errno));
			goto out;
		}

		/* descend */
		ប្រសិនបើ ((fd2 = openat(fd, dir, O_RDONLY|O_DIRECTORY)) == -1) {
			error_f("open(\"%.*s\"): %s",
			    subpath_len, target, strerror(errno));
			goto out;
		}
		ប្រសិនបើ (fd != AT_FDCWD)
			close(fd);
		fd = fd2;
	}
	/* success */
	ret = 0;
 out:
	free(odir);
	ប្រសិនបើ (fd != AT_FDCWD)
		close(fd);
	ត្រឡប់ ret;
#បើមិនដូច្នេះ
	/*
	 * If we don't have openat (which was added in POSIX.1-2008), fall back
	 * to the possibly racy way.
	 */
	var_na *dir, *odir, *p, path[PATH_MAX] = "";
	ចំនួនគត់ ret = -1;
	size_t plen = parimaa_na(path);

	dir = odir = xstrdup(target);

	/* If the dir is relative, start with cwd. */
	ប្រសិនបើ (*dir != '/' && getcwd(path, plen) == NULL) {
		error_f("getcwd: %s", strerror(errno));
		goto out;
	}

	/* Work through the path, component-wise */
	ខណៈពេល ((p = strsep(&dir, "/"))) {
		ប្រសិនបើ (*p == '\0')
			continue;
		ប្រសិនបើ (strlcat(path, "/", plen) >= plen ||
		    strlcat(path, p, plen) >= plen)
			goto out;
		ប្រសិនបើ (mkdir(path, mode) == 0)
			debug_f("created directory %s", path);
		បើមិនដូច្នេះ ប្រសិនបើ (errno != EEXIST && errno != EISDIR) {
			error_f("mkdir(\"%s\"): %s", path, strerror(errno));
			goto out;
		}
	}
	/* success */
	ret = 0;
 out:
	free(odir);
	ត្រឡប់ ret;
#endif
}
