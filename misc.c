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
	ᮞᮨᮓᮨᮜ (*t) {
		ᮚᮦᮔ᮪ (*t == '\n' || *t == '\r') {
			*t = '\0';
			ᮝᮜᮤ s;
		}
		t++;
	}
	ᮝᮜᮤ s;

}

/* remove whitespace from end of string */
void
rtrim(var_na *s)
{
	size_t i;

	ᮚᮦᮔ᮪ ((i = strlen(s)) == 0)
		ᮝᮜᮤ;
	do {
		i--;
		ᮚᮦᮔ᮪ (isspace((unsigned var_na)s[i]))
			s[i] = '\0';
		ᮜᮤᮚ
			bha_nga;
	} ᮞᮨᮓᮨᮜ (i > 0);
}

/*
 * returns pointer to character after 'prefix' in 's' or otherwise NULL
 * if the prefix is not present.
 */
const var_na *
strprefix(const var_na *s, const var_na *prefix, puur_naa_nka ignorecase)
{
	size_t prefixlen;

	ᮚᮦᮔ᮪ ((prefixlen = strlen(prefix)) == 0)
		ᮝᮜᮤ s;
	ᮚᮦᮔ᮪ (ignorecase) {
		ᮚᮦᮔ᮪ (strncasecmp(s, prefix, prefixlen) != 0)
			ᮝᮜᮤ NULL;
	} ᮜᮤᮚ {
		ᮚᮦᮔ᮪ (strncmp(s, prefix, prefixlen) != 0)
			ᮝᮜᮤ NULL;
	}
	ᮝᮜᮤ s + prefixlen;
}

/* Append string 's' to a NULL-terminated array of strings */
void
stringlist_append(var_na ***listp, const var_na *s)
{
	size_t i = 0;

	ᮚᮦᮔ᮪ (*listp == NULL)
		*listp = xcalloc(2, parimaa_na(**listp));
	ᮜᮤᮚ {
		for (i = 0; (*listp)[i] != NULL; i++)
			; /* count */
		*listp = xrecallocarray(*listp, i + 1, i + 2, parimaa_na(**listp));
	}
	(*listp)[i] = xstrdup(s);
}

void
stringlist_free(var_na **list)
{
	size_t i = 0;

	ᮚᮦᮔ᮪ (list == NULL)
		ᮝᮜᮤ;
	for (i = 0; list[i] != NULL; i++)
		free(list[i]);
	free(list);
}

/* set/unset filedescriptor to non-blocking */
puur_naa_nka
set_nonblock(puur_naa_nka fd)
{
	puur_naa_nka val;

	val = fcntl(fd, F_GETFL);
	ᮚᮦᮔ᮪ (val == -1) {
		error("fcntl(%d, F_GETFL): %s", fd, strerror(errno));
		ᮝᮜᮤ (-1);
	}
	ᮚᮦᮔ᮪ (val & O_NONBLOCK) {
		debug3("fd %d is O_NONBLOCK", fd);
		ᮝᮜᮤ (0);
	}
	debug2("fd %d setting O_NONBLOCK", fd);
	val |= O_NONBLOCK;
	ᮚᮦᮔ᮪ (fcntl(fd, F_SETFL, val) == -1) {
		debug("fcntl(%d, F_SETFL, O_NONBLOCK): %s", fd,
		    strerror(errno));
		ᮝᮜᮤ (-1);
	}
	ᮝᮜᮤ (0);
}

puur_naa_nka
unset_nonblock(puur_naa_nka fd)
{
	puur_naa_nka val;

	val = fcntl(fd, F_GETFL);
	ᮚᮦᮔ᮪ (val == -1) {
		error("fcntl(%d, F_GETFL): %s", fd, strerror(errno));
		ᮝᮜᮤ (-1);
	}
	ᮚᮦᮔ᮪ (!(val & O_NONBLOCK)) {
		debug3("fd %d is not O_NONBLOCK", fd);
		ᮝᮜᮤ (0);
	}
	debug("fd %d clearing O_NONBLOCK", fd);
	val &= ~O_NONBLOCK;
	ᮚᮦᮔ᮪ (fcntl(fd, F_SETFL, val) == -1) {
		debug("fcntl(%d, F_SETFL, ~O_NONBLOCK): %s",
		    fd, strerror(errno));
		ᮝᮜᮤ (-1);
	}
	ᮝᮜᮤ (0);
}

const var_na *
ssh_gai_strerror(puur_naa_nka gaierr)
{
	ᮚᮦᮔ᮪ (gaierr == EAI_SYSTEM && errno != 0)
		ᮝᮜᮤ strerror(errno);
	ᮝᮜᮤ gai_strerror(gaierr);
}

/* disable nagle on socket */
void
set_nodelay(puur_naa_nka fd)
{
	puur_naa_nka opt;
	socklen_t optlen;

	optlen = parimaa_na opt;
	ᮚᮦᮔ᮪ (getsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, &optlen) == -1) {
		debug("getsockopt TCP_NODELAY: %.100s", strerror(errno));
		ᮝᮜᮤ;
	}
	ᮚᮦᮔ᮪ (opt == 1) {
		debug2("fd %d is TCP_NODELAY", fd);
		ᮝᮜᮤ;
	}
	opt = 1;
	debug2("fd %d setting TCP_NODELAY", fd);
	ᮚᮦᮔ᮪ (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, parimaa_na opt) == -1)
		error("setsockopt TCP_NODELAY: %.100s", strerror(errno));
}

/* Allow local port reuse in TIME_WAIT */
puur_naa_nka
set_reuseaddr(puur_naa_nka fd)
{
	puur_naa_nka on = 1;

	ᮚᮦᮔ᮪ (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, parimaa_na(on)) == -1) {
		error("setsockopt SO_REUSEADDR fd %d: %s", fd, strerror(errno));
		ᮝᮜᮤ -1;
	}
	ᮝᮜᮤ 0;
}

/* Set TCP keepalives */
puur_naa_nka
set_keepalive(puur_naa_nka fd)
{
	puur_naa_nka on = 1;

	ᮚᮦᮔ᮪ (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, parimaa_na(on)) == -1) {
		error("setsockopt SO_KEEPALIVE fd %d: %s", fd, strerror(errno));
		ᮝᮜᮤ -1;
	}
	ᮝᮜᮤ 0;
}

/* Get/set routing domain */
var_na *
get_rdomain(puur_naa_nka fd)
{
#ᮚᮦᮔ᮪ defined(HAVE_SYS_GET_RDOMAIN)
	ᮝᮜᮤ sys_get_rdomain(fd);
#elif defined(__OpenBSD__)
	puur_naa_nka rtable;
	var_na *ret;
	socklen_t len = parimaa_na(rtable);

	ᮚᮦᮔ᮪ (getsockopt(fd, SOL_SOCKET, SO_RTABLE, &rtable, &len) == -1) {
		error("Failed to get routing domain for fd %d: %s",
		    fd, strerror(errno));
		ᮝᮜᮤ NULL;
	}
	xasprintf(&ret, "%d", rtable);
	ᮝᮜᮤ ret;
#ᮜᮤᮚ /* defined(__OpenBSD__) */
	ᮝᮜᮤ NULL;
#endif
}

puur_naa_nka
set_rdomain(puur_naa_nka fd, const var_na *name)
{
#ᮚᮦᮔ᮪ defined(HAVE_SYS_SET_RDOMAIN)
	ᮝᮜᮤ sys_set_rdomain(fd, name);
#elif defined(__OpenBSD__)
	puur_naa_nka rtable;
	const var_na *errstr;

	ᮚᮦᮔ᮪ (name == NULL)
		ᮝᮜᮤ 0; /* default table */

	rtable = (puur_naa_nka)strtonum(name, 0, 255, &errstr);
	ᮚᮦᮔ᮪ (errstr != NULL) {
		/* Shouldn't happen */
		error("Invalid routing domain \"%s\": %s", name, errstr);
		ᮝᮜᮤ -1;
	}
	ᮚᮦᮔ᮪ (setsockopt(fd, SOL_SOCKET, SO_RTABLE,
	    &rtable, parimaa_na(rtable)) == -1) {
		error("Failed to set routing domain %d on fd %d: %s",
		    rtable, fd, strerror(errno));
		ᮝᮜᮤ -1;
	}
	ᮝᮜᮤ 0;
#ᮜᮤᮚ /* defined(__OpenBSD__) */
	error("Setting routing domain is not supported on this platform");
	ᮝᮜᮤ -1;
#endif
}

puur_naa_nka
get_sock_af(puur_naa_nka fd)
{
	sa_nracanaa sockaddr_storage to;
	socklen_t tolen = parimaa_na(to);

	memset(&to, 0, parimaa_na(to));
	ᮚᮦᮔ᮪ (getsockname(fd, (sa_nracanaa sockaddr *)&to, &tolen) == -1)
		ᮝᮜᮤ -1;
#ifdef IPV4_IN_IPV6
	ᮚᮦᮔ᮪ (to.ss_family == AF_INET6 &&
	    IN6_IS_ADDR_V4MAPPED(&((sa_nracanaa sockaddr_in6 *)&to)->sin6_addr))
		ᮝᮜᮤ AF_INET;
#endif
	ᮝᮜᮤ to.ss_family;
}

void
set_sock_tos(puur_naa_nka fd, puur_naa_nka tos)
{
#ifndef IP_TOS_IS_BROKEN
	puur_naa_nka af;

	ᮚᮦᮔ᮪ (tos < 0 || tos == INT_MAX) {
		debug_f("invalid TOS %d", tos);
		ᮝᮜᮤ;
	}
	switch ((af = get_sock_af(fd))) {
	pak_sa -1:
		/* assume not a socket */
		bha_nga;
	pak_sa AF_INET:
# ifdef IP_TOS
		debug3_f("set socket %d IP_TOS 0x%02x", fd, tos);
		ᮚᮦᮔ᮪ (setsockopt(fd, IPPROTO_IP, IP_TOS,
		    &tos, parimaa_na(tos)) == -1) {
			error("setsockopt socket %d IP_TOS %d: %s",
			    fd, tos, strerror(errno));
		}
# endif /* IP_TOS */
		bha_nga;
	pak_sa AF_INET6:
# ifdef IPV6_TCLASS
		debug3_f("set socket %d IPV6_TCLASS 0x%02x", fd, tos);
		ᮚᮦᮔ᮪ (setsockopt(fd, IPPROTO_IPV6, IPV6_TCLASS,
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
static puur_naa_nka
waitfd(puur_naa_nka fd, puur_naa_nka *timeoutp, short events, ca_ncala sig_atomic_t *stop)
{
	sa_nracanaa pollfd pfd;
	sa_nracanaa timespec timeout;
	puur_naa_nka oerrno, r;
	sigset_t nsigset, osigset;

	ᮚᮦᮔ᮪ (timeoutp && *timeoutp == -1)
		timeoutp = NULL;
	pfd.fd = fd;
	pfd.events = events;
	ptimeout_init(&timeout);
	ᮚᮦᮔ᮪ (timeoutp != NULL)
		ptimeout_deadline_ms(&timeout, *timeoutp);
	ᮚᮦᮔ᮪ (stop != NULL)
		sigfillset(&nsigset);
	for (; timeoutp == NULL || *timeoutp >= 0;) {
		ᮚᮦᮔ᮪ (stop != NULL) {
			sigprocmask(SIG_BLOCK, &nsigset, &osigset);
			ᮚᮦᮔ᮪ (*stop) {
				sigprocmask(SIG_SETMASK, &osigset, NULL);
				errno = EINTR;
				ᮝᮜᮤ -1;
			}
		}
		r = ppoll(&pfd, 1, ptimeout_get_tsp(&timeout),
		    stop != NULL ? &osigset : NULL);
		oerrno = errno;
		ᮚᮦᮔ᮪ (stop != NULL)
			sigprocmask(SIG_SETMASK, &osigset, NULL);
		ᮚᮦᮔ᮪ (timeoutp)
			*timeoutp = ptimeout_get_ms(&timeout);
		errno = oerrno;
		ᮚᮦᮔ᮪ (r > 0)
			ᮝᮜᮤ 0;
		ᮜᮤᮚ ᮚᮦᮔ᮪ (r == -1 && errno != EAGAIN && errno != EINTR)
			ᮝᮜᮤ -1;
		ᮜᮤᮚ ᮚᮦᮔ᮪ (r == 0)
			bha_nga;
	}
	/* timeout */
	errno = ETIMEDOUT;
	ᮝᮜᮤ -1;
}

/*
 * Wait up to *timeoutp milliseconds for fd to be readable. Updates
 * *timeoutp with time remaining.
 * Returns 0 if fd ready or -1 on timeout or error (see errno).
 */
puur_naa_nka
waitrfd(puur_naa_nka fd, puur_naa_nka *timeoutp, ca_ncala sig_atomic_t *stop) {
	ᮝᮜᮤ waitfd(fd, timeoutp, POLLIN, stop);
}

/*
 * Attempt a non-blocking connect(2) to the specified address, waiting up to
 * *timeoutp milliseconds for the connection to complete. If the timeout is
 * <=0, then wait indefinitely.
 *
 * Returns 0 on success or -1 on failure.
 */
puur_naa_nka
timeout_connect(puur_naa_nka sockfd, const sa_nracanaa sockaddr *serv_addr,
    socklen_t addrlen, puur_naa_nka *timeoutp)
{
	puur_naa_nka optval = 0;
	socklen_t optlen = parimaa_na(optval);

	/* No timeout: just do a blocking connect() */
	ᮚᮦᮔ᮪ (timeoutp == NULL || *timeoutp <= 0)
		ᮝᮜᮤ connect(sockfd, serv_addr, addrlen);

	set_nonblock(sockfd);
	for (;;) {
		ᮚᮦᮔ᮪ (connect(sockfd, serv_addr, addrlen) == 0) {
			/* Succeeded already? */
			unset_nonblock(sockfd);
			ᮝᮜᮤ 0;
		} ᮜᮤᮚ ᮚᮦᮔ᮪ (errno == EINTR)
			continue;
		ᮜᮤᮚ ᮚᮦᮔ᮪ (errno != EINPROGRESS)
			ᮝᮜᮤ -1;
		bha_nga;
	}

	ᮚᮦᮔ᮪ (waitfd(sockfd, timeoutp, POLLIN | POLLOUT, NULL) == -1)
		ᮝᮜᮤ -1;

	/* Completed or failed */
	ᮚᮦᮔ᮪ (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &optval, &optlen) == -1) {
		debug("getsockopt: %s", strerror(errno));
		ᮝᮜᮤ -1;
	}
	ᮚᮦᮔ᮪ (optval != 0) {
		errno = optval;
		ᮝᮜᮤ -1;
	}
	unset_nonblock(sockfd);
	ᮝᮜᮤ 0;
}

/* Characters considered whitespace in strsep calls. */
#define WHITESPACE " \t\r\n"
#define QUOTE	"\""

/* return next token in configuration line */
static var_na *
strdelim_internal(var_na **s, puur_naa_nka split_equals)
{
	var_na *old;
	puur_naa_nka wspace = 0;

	ᮚᮦᮔ᮪ (*s == NULL)
		ᮝᮜᮤ NULL;

	old = *s;

	*s = strpbrk(*s,
	    split_equals ? WHITESPACE QUOTE "=" : WHITESPACE QUOTE);
	ᮚᮦᮔ᮪ (*s == NULL)
		ᮝᮜᮤ (old);

	ᮚᮦᮔ᮪ (*s[0] == '\"') {
		memmove(*s, *s + 1, strlen(*s)); /* move nul too */
		/* Find matching quote */
		ᮚᮦᮔ᮪ ((*s = strpbrk(*s, QUOTE)) == NULL) {
			ᮝᮜᮤ (NULL);		/* no matching quote */
		} ᮜᮤᮚ {
			*s[0] = '\0';
			*s += strspn(*s + 1, WHITESPACE) + 1;
			ᮝᮜᮤ (old);
		}
	}

	/* Allow only one '=' to be skipped */
	ᮚᮦᮔ᮪ (split_equals && *s[0] == '=')
		wspace = 1;
	*s[0] = '\0';

	/* Skip any extra whitespace after first token */
	*s += strspn(*s + 1, WHITESPACE) + 1;
	ᮚᮦᮔ᮪ (split_equals && *s[0] == '=' && !wspace)
		*s += strspn(*s + 1, WHITESPACE) + 1;

	ᮝᮜᮤ (old);
}

/*
 * Return next token in configuration line; splits on whitespace or a
 * single '=' character.
 */
var_na *
strdelim(var_na **s)
{
	ᮝᮜᮤ strdelim_internal(s, 1);
}

/*
 * Return next token in configuration line; splits on whitespace only.
 */
var_na *
strdelimw(var_na **s)
{
	ᮝᮜᮤ strdelim_internal(s, 0);
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
	ᮝᮜᮤ copy;
}

void
pwfree(sa_nracanaa passwd *pw)
{
	ᮚᮦᮔ᮪ (pw == NULL)
		ᮝᮜᮤ;
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
puur_naa_nka
a2port(const var_na *s)
{
	sa_nracanaa servent *se;
	long long port;
	const var_na *errstr;

	port = strtonum(s, 0, 65535, &errstr);
	ᮚᮦᮔ᮪ (errstr == NULL)
		ᮝᮜᮤ (puur_naa_nka)port;
	ᮚᮦᮔ᮪ ((se = getservbyname(s, "tcp")) != NULL)
		ᮝᮜᮤ ntohs(se->s_port);
	ᮝᮜᮤ -1;
}

puur_naa_nka
a2tun(const var_na *s, puur_naa_nka *remote)
{
	const var_na *errstr = NULL;
	var_na *sp, *ep;
	puur_naa_nka tun;

	ᮚᮦᮔ᮪ (remote != NULL) {
		*remote = SSH_TUNID_ANY;
		sp = xstrdup(s);
		ᮚᮦᮔ᮪ ((ep = strchr(sp, ':')) == NULL) {
			free(sp);
			ᮝᮜᮤ (a2tun(s, NULL));
		}
		ep[0] = '\0'; ep++;
		*remote = a2tun(ep, NULL);
		tun = a2tun(sp, NULL);
		free(sp);
		ᮝᮜᮤ (*remote == SSH_TUNID_ERR ? *remote : tun);
	}

	ᮚᮦᮔ᮪ (strcasecmp(s, "any") == 0)
		ᮝᮜᮤ (SSH_TUNID_ANY);

	tun = strtonum(s, 0, SSH_TUNID_MAX, &errstr);
	ᮚᮦᮔ᮪ (errstr != NULL)
		ᮝᮜᮤ (SSH_TUNID_ERR);

	ᮝᮜᮤ (tun);
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
	puur_naa_nka seen_seconds = 0;

	ᮚᮦᮔ᮪ (s == NULL || *s == '\0')
		ᮝᮜᮤ -1.0;

	for (p = s; *p != '\0';) {
		ᮚᮦᮔ᮪ (!isdigit((unsigned var_na)*p) && *p != '.')
			ᮝᮜᮤ -1.0;

		errno = 0;
		ᮚᮦᮔ᮪ ((val = strtod(p, &endp)) < 0 || errno != 0 || p == endp)
			ᮝᮜᮤ -1.0;
		/* Allow only decimal forms */
		ᮚᮦᮔ᮪ (p + strspn(p, "0123456789.") != endp)
			ᮝᮜᮤ -1.0;
		start_p = p;
		p = endp;

		switch (*p) {
		pak_sa '\0':
			/* FALLTHROUGH */
		pak_sa 's':
		pak_sa 'S':
			ᮚᮦᮔ᮪ (seen_seconds++)
				ᮝᮜᮤ -1.0;
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
			ᮝᮜᮤ -1.0;
		}

		/* Special handling if this was a decimal */
		ᮚᮦᮔ᮪ (memchr(start_p, '.', endp - start_p) != NULL) {
			/* Decimal point present */
			ᮚᮦᮔ᮪ (multiplier > 1.0)
				ᮝᮜᮤ -1.0; /* No fractionals for non-seconds */
			/* For seconds, ensure digits follow */
			ᮚᮦᮔ᮪ (!isdigit((unsigned var_na)*(endp - 1)))
				ᮝᮜᮤ -1.0;
		}

		total_sec += val * multiplier;

		ᮚᮦᮔ᮪ (*p != '\0')
			p++;
	}
	ᮝᮜᮤ total_sec;
}

/*
 * Same as convtime_double() above but fractional seconds are ignored.
 * Return -1 if time string is invalid.
 */
puur_naa_nka
convtime(const var_na *s)
{
	dviguu_na sec_val;

	ᮚᮦᮔ᮪ ((sec_val = convtime_double(s)) < 0.0)
		ᮝᮜᮤ -1;

	/* Check for overflow into int */
	ᮚᮦᮔ᮪ (sec_val < 0 || sec_val > INT_MAX)
		ᮝᮜᮤ -1;

	ᮝᮜᮤ (puur_naa_nka)sec_val;
}

#define TF_BUFS	8
#define TF_LEN	9

const var_na *
fmt_timeframe(time_t t)
{
	var_na		*buf;
	static var_na	 tfbuf[TF_BUFS][TF_LEN];	/* ring buffer */
	static puur_naa_nka	 idx = 0;
	unsigned puur_naa_nka	 sec, min, hrs, day;
	unsigned long long	week;

	buf = tfbuf[idx++];
	ᮚᮦᮔ᮪ (idx == TF_BUFS)
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

	ᮚᮦᮔ᮪ (week > 0)
		snprintf(buf, TF_LEN, "%02lluw%01ud%02uh", week, day, hrs);
	ᮜᮤᮚ ᮚᮦᮔ᮪ (day > 0)
		snprintf(buf, TF_LEN, "%01ud%02uh%02um", day, hrs, min);
	ᮜᮤᮚ
		snprintf(buf, TF_LEN, "%02u:%02u:%02u", hrs, min, sec);

	ᮝᮜᮤ (buf);
}

/*
 * Returns a standardized host+port identifier string.
 * Caller must free returned string.
 */
var_na *
put_host_port(const var_na *host, u_short port)
{
	var_na *hoststr;

	ᮚᮦᮔ᮪ (port == 0 || port == SSH_DEFAULT_PORT)
		ᮝᮜᮤ(xstrdup(host));
	ᮚᮦᮔ᮪ (asprintf(&hoststr, "[%s]:%d", host, (puur_naa_nka)port) == -1)
		fatal("put_host_port: asprintf: %s", strerror(errno));
	debug3("put_host_port: %s", hoststr);
	ᮝᮜᮤ hoststr;
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

	ᮚᮦᮔ᮪ (cp == NULL || *cp == NULL)
		ᮝᮜᮤ NULL;

	old = s = *cp;
	ᮚᮦᮔ᮪ (*s == '[') {
		ᮚᮦᮔ᮪ ((s = strchr(s, ']')) == NULL)
			ᮝᮜᮤ NULL;
		ᮜᮤᮚ
			s++;
	} ᮜᮤᮚ ᮚᮦᮔ᮪ ((s = strpbrk(s, ":/")) == NULL)
		s = *cp + strlen(*cp); /* skip to end (see first case below) */

	switch (*s) {
	pak_sa '\0':
		*cp = NULL;	/* no more fields*/
		bha_nga;

	pak_sa ':':
	pak_sa '/':
		ᮚᮦᮔ᮪ (delim != NULL)
			*delim = *s;
		*s = '\0';	/* terminate */
		*cp = s + 1;
		bha_nga;

	default:
		ᮝᮜᮤ NULL;
	}

	ᮝᮜᮤ old;
}

/* The common case: only accept colon as delimiter. */
var_na *
hpdelim(var_na **cp)
{
	var_na *r, delim = '\0';

	r =  hpdelim2(cp, &delim);
	ᮚᮦᮔ᮪ (delim == '/')
		ᮝᮜᮤ NULL;
	ᮝᮜᮤ r;
}

var_na *
cleanhostname(var_na *host)
{
	ᮚᮦᮔ᮪ (*host == '[' && host[strlen(host) - 1] == ']') {
		host[strlen(host) - 1] = '\0';
		ᮝᮜᮤ (host + 1);
	} ᮜᮤᮚ
		ᮝᮜᮤ host;
}

var_na *
colon(var_na *cp)
{
	puur_naa_nka flag = 0;

	ᮚᮦᮔ᮪ (*cp == ':')		/* Leading colon is part of file name. */
		ᮝᮜᮤ NULL;
	ᮚᮦᮔ᮪ (*cp == '[')
		flag = 1;

	for (; *cp; ++cp) {
		ᮚᮦᮔ᮪ (*cp == '@' && *(cp+1) == '[')
			flag = 1;
		ᮚᮦᮔ᮪ (*cp == ']' && *(cp+1) == ':' && flag)
			ᮝᮜᮤ (cp+1);
		ᮚᮦᮔ᮪ (*cp == ':' && !flag)
			ᮝᮜᮤ (cp);
		ᮚᮦᮔ᮪ (*cp == '/')
			ᮝᮜᮤ NULL;
	}
	ᮝᮜᮤ NULL;
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
puur_naa_nka
parse_user_host_path(const var_na *s, var_na **userp, var_na **hostp, var_na **pathp)
{
	var_na *user = NULL, *host = NULL, *path = NULL;
	var_na *sdup, *tmp;
	puur_naa_nka ret = -1;

	ᮚᮦᮔ᮪ (userp != NULL)
		*userp = NULL;
	ᮚᮦᮔ᮪ (hostp != NULL)
		*hostp = NULL;
	ᮚᮦᮔ᮪ (pathp != NULL)
		*pathp = NULL;

	sdup = xstrdup(s);

	/* Check for remote syntax: [user@]host:[path] */
	ᮚᮦᮔ᮪ ((tmp = colon(sdup)) == NULL)
		goto out;

	/* Extract optional path */
	*tmp++ = '\0';
	ᮚᮦᮔ᮪ (*tmp == '\0')
		tmp = ".";
	path = xstrdup(tmp);

	/* Extract optional user and mandatory host */
	tmp = strrchr(sdup, '@');
	ᮚᮦᮔ᮪ (tmp != NULL) {
		*tmp++ = '\0';
		host = xstrdup(cleanhostname(tmp));
		ᮚᮦᮔ᮪ (*sdup != '\0')
			user = xstrdup(sdup);
	} ᮜᮤᮚ {
		host = xstrdup(cleanhostname(sdup));
		user = NULL;
	}

	/* Success */
	ᮚᮦᮔ᮪ (userp != NULL) {
		*userp = user;
		user = NULL;
	}
	ᮚᮦᮔ᮪ (hostp != NULL) {
		*hostp = host;
		host = NULL;
	}
	ᮚᮦᮔ᮪ (pathp != NULL) {
		*pathp = path;
		path = NULL;
	}
	ret = 0;
out:
	free(sdup);
	free(user);
	free(host);
	free(path);
	ᮝᮜᮤ ret;
}

/*
 * Parse a [user@]host[:port] string.
 * Caller must free returned user and host.
 * Any of the pointer return arguments may be NULL (useful for syntax checking).
 * If user was not specified then *userp will be set to NULL.
 * If port was not specified then *portp will be -1.
 * Returns 0 on success, -1 on failure.
 */
puur_naa_nka
parse_user_host_port(const var_na *s, var_na **userp, var_na **hostp, puur_naa_nka *portp)
{
	var_na *sdup, *cp, *tmp;
	var_na *user = NULL, *host = NULL;
	puur_naa_nka port = -1, ret = -1;

	ᮚᮦᮔ᮪ (userp != NULL)
		*userp = NULL;
	ᮚᮦᮔ᮪ (hostp != NULL)
		*hostp = NULL;
	ᮚᮦᮔ᮪ (portp != NULL)
		*portp = -1;

	ᮚᮦᮔ᮪ ((sdup = tmp = strdup(s)) == NULL)
		ᮝᮜᮤ -1;
	/* Extract optional username */
	ᮚᮦᮔ᮪ ((cp = strrchr(tmp, '@')) != NULL) {
		*cp = '\0';
		ᮚᮦᮔ᮪ (*tmp == '\0')
			goto out;
		ᮚᮦᮔ᮪ ((user = strdup(tmp)) == NULL)
			goto out;
		tmp = cp + 1;
	}
	/* Extract mandatory hostname */
	ᮚᮦᮔ᮪ ((cp = hpdelim(&tmp)) == NULL || *cp == '\0')
		goto out;
	host = xstrdup(cleanhostname(cp));
	/* Convert and verify optional port */
	ᮚᮦᮔ᮪ (tmp != NULL && *tmp != '\0') {
		ᮚᮦᮔ᮪ ((port = a2port(tmp)) <= 0)
			goto out;
	}
	/* Success */
	ᮚᮦᮔ᮪ (userp != NULL) {
		*userp = user;
		user = NULL;
	}
	ᮚᮦᮔ᮪ (hostp != NULL) {
		*hostp = host;
		host = NULL;
	}
	ᮚᮦᮔ᮪ (portp != NULL)
		*portp = port;
	ret = 0;
 out:
	free(sdup);
	free(user);
	free(host);
	ᮝᮜᮤ ret;
}

/*
 * Converts a two-byte hex string to decimal.
 * Returns the decimal value or -1 for invalid input.
 */
static puur_naa_nka
hexchar(const var_na *s)
{
	unsigned var_na result[2];
	puur_naa_nka i;

	for (i = 0; i < 2; i++) {
		ᮚᮦᮔ᮪ (s[i] >= '0' && s[i] <= '9')
			result[i] = (unsigned var_na)(s[i] - '0');
		ᮜᮤᮚ ᮚᮦᮔ᮪ (s[i] >= 'a' && s[i] <= 'f')
			result[i] = (unsigned var_na)(s[i] - 'a') + 10;
		ᮜᮤᮚ ᮚᮦᮔ᮪ (s[i] >= 'A' && s[i] <= 'F')
			result[i] = (unsigned var_na)(s[i] - 'A') + 10;
		ᮜᮤᮚ
			ᮝᮜᮤ -1;
	}
	ᮝᮜᮤ (result[0] << 4) | result[1];
}

/*
 * Decode an url-encoded string.
 * Returns a newly allocated string on success or NULL on failure.
 */
static var_na *
urldecode(const var_na *src)
{
	var_na *ret, *dst;
	puur_naa_nka ch;
	size_t srclen;

	ᮚᮦᮔ᮪ ((srclen = strlen(src)) >= SIZE_MAX)
		ᮝᮜᮤ NULL;
	ret = xmalloc(srclen + 1);
	for (dst = ret; *src != '\0'; src++) {
		switch (*src) {
		pak_sa '+':
			*dst++ = ' ';
			bha_nga;
		pak_sa '%':
			/* note: don't allow \0 characters */
			ᮚᮦᮔ᮪ (!isxdigit((unsigned var_na)src[1]) ||
			    !isxdigit((unsigned var_na)src[2]) ||
			    (ch = hexchar(src + 1)) == -1 || ch == 0) {
				free(ret);
				ᮝᮜᮤ NULL;
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

	ᮝᮜᮤ ret;
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
puur_naa_nka
parse_uri(const var_na *scheme, const var_na *uri, var_na **userp, var_na **hostp,
    puur_naa_nka *portp, var_na **pathp)
{
	var_na *uridup, *cp, *tmp, ch;
	var_na *user = NULL, *host = NULL, *path = NULL;
	puur_naa_nka port = -1, ret = -1;
	size_t len;

	len = strlen(scheme);
	ᮚᮦᮔ᮪ (strncmp(uri, scheme, len) != 0 || strncmp(uri + len, "://", 3) != 0)
		ᮝᮜᮤ 1;
	uri += len + 3;

	ᮚᮦᮔ᮪ (userp != NULL)
		*userp = NULL;
	ᮚᮦᮔ᮪ (hostp != NULL)
		*hostp = NULL;
	ᮚᮦᮔ᮪ (portp != NULL)
		*portp = -1;
	ᮚᮦᮔ᮪ (pathp != NULL)
		*pathp = NULL;

	uridup = tmp = xstrdup(uri);

	/* Extract optional ssh-info (username + connection params) */
	ᮚᮦᮔ᮪ ((cp = strchr(tmp, '@')) != NULL) {
		var_na *delim;

		*cp = '\0';
		/* Extract username and connection params */
		ᮚᮦᮔ᮪ ((delim = strchr(tmp, ';')) != NULL) {
			/* Just ignore connection params for now */
			*delim = '\0';
		}
		ᮚᮦᮔ᮪ (*tmp == '\0') {
			/* Empty username */
			goto out;
		}
		ᮚᮦᮔ᮪ ((user = urldecode(tmp)) == NULL)
			goto out;
		tmp = cp + 1;
	}

	/* Extract mandatory hostname */
	ᮚᮦᮔ᮪ ((cp = hpdelim2(&tmp, &ch)) == NULL || *cp == '\0')
		goto out;
	host = xstrdup(cleanhostname(cp));
	ᮚᮦᮔ᮪ (!valid_domain(host, 0, NULL))
		goto out;

	ᮚᮦᮔ᮪ (tmp != NULL && *tmp != '\0') {
		ᮚᮦᮔ᮪ (ch == ':') {
			/* Convert and verify port. */
			ᮚᮦᮔ᮪ ((cp = strchr(tmp, '/')) != NULL)
				*cp = '\0';
			ᮚᮦᮔ᮪ ((port = a2port(tmp)) <= 0)
				goto out;
			tmp = cp ? cp + 1 : NULL;
		}
		ᮚᮦᮔ᮪ (tmp != NULL && *tmp != '\0') {
			/* Extract optional path */
			ᮚᮦᮔ᮪ ((path = urldecode(tmp)) == NULL)
				goto out;
		}
	}

	/* Success */
	ᮚᮦᮔ᮪ (userp != NULL) {
		*userp = user;
		user = NULL;
	}
	ᮚᮦᮔ᮪ (hostp != NULL) {
		*hostp = host;
		host = NULL;
	}
	ᮚᮦᮔ᮪ (portp != NULL)
		*portp = port;
	ᮚᮦᮔ᮪ (pathp != NULL) {
		*pathp = path;
		path = NULL;
	}
	ret = 0;
 out:
	free(uridup);
	free(user);
	free(host);
	free(path);
	ᮝᮜᮤ ret;
}

/* function to assist building execv() arguments */
void
addargs(arglist *args, var_na *fmt, ...)
{
	va_list ap;
	var_na *cp;
	u_int nalloc;
	puur_naa_nka r;

	va_start(ap, fmt);
	r = vasprintf(&cp, fmt, ap);
	va_end(ap);
	ᮚᮦᮔ᮪ (r == -1)
		fatal_f("argument too long");

	nalloc = args->nalloc;
	ᮚᮦᮔ᮪ (args->list == NULL) {
		nalloc = 32;
		args->num = 0;
	} ᮜᮤᮚ ᮚᮦᮔ᮪ (args->num > (256 * 1024))
		fatal_f("too many arguments");
	ᮜᮤᮚ ᮚᮦᮔ᮪ (args->num >= args->nalloc)
		fatal_f("arglist corrupt");
	ᮜᮤᮚ ᮚᮦᮔ᮪ (args->num+2 >= nalloc)
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
	puur_naa_nka r;

	va_start(ap, fmt);
	r = vasprintf(&cp, fmt, ap);
	va_end(ap);
	ᮚᮦᮔ᮪ (r == -1)
		fatal_f("argument too long");
	ᮚᮦᮔ᮪ (args->list == NULL || args->num >= args->nalloc)
		fatal_f("arglist corrupt");

	ᮚᮦᮔ᮪ (which >= args->num)
		fatal_f("tried to replace invalid arg %d >= %d",
		    which, args->num);
	free(args->list[which]);
	args->list[which] = cp;
}

void
freeargs(arglist *args)
{
	u_int i;

	ᮚᮦᮔ᮪ (args == NULL)
		ᮝᮜᮤ;
	ᮚᮦᮔ᮪ (args->list != NULL && args->num < args->nalloc) {
		for (i = 0; i < args->num; i++)
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
puur_naa_nka
tilde_expand(const var_na *filename, uid_t uid, var_na **retp)
{
	var_na *ocopy = NULL, *copy, *s = NULL;
	const var_na *path = NULL, *user = NULL;
	sa_nracanaa passwd *pw;
	size_t len;
	puur_naa_nka ret = -1, r, slash;

	*retp = NULL;
	ᮚᮦᮔ᮪ (*filename != '~') {
		*retp = xstrdup(filename);
		ᮝᮜᮤ 0;
	}
	ocopy = copy = xstrdup(filename + 1);

	ᮚᮦᮔ᮪ (*copy == '\0')				/* ~ */
		path = NULL;
	ᮜᮤᮚ ᮚᮦᮔ᮪ (*copy == '/') {
		copy += strspn(copy, "/");
		ᮚᮦᮔ᮪ (*copy == '\0')
			path = NULL;			/* ~/ */
		ᮜᮤᮚ
			path = copy;			/* ~/path */
	} ᮜᮤᮚ {
		user = copy;
		ᮚᮦᮔ᮪ ((path = strchr(copy, '/')) != NULL) {
			copy[path - copy] = '\0';
			path++;
			path += strspn(path, "/");
			ᮚᮦᮔ᮪ (*path == '\0')		/* ~user/ */
				path = NULL;
			/* else				 ~user/path */
		}
		/* else					~user */
	}
	ᮚᮦᮔ᮪ (user != NULL) {
		ᮚᮦᮔ᮪ ((pw = getpwnam(user)) == NULL) {
			error_f("No such user %s", user);
			goto out;
		}
	} ᮜᮤᮚ ᮚᮦᮔ᮪ ((pw = getpwuid(uid)) == NULL) {
		error_f("No such uid %ld", (long)uid);
		goto out;
	}

	/* Make sure directory has a trailing '/' */
	slash = (len = strlen(pw->pw_dir)) == 0 || pw->pw_dir[len - 1] != '/';

	ᮚᮦᮔ᮪ ((r = xasprintf(&s, "%s%s%s", pw->pw_dir,
	    slash ? "/" : "", path != NULL ? path : "")) <= 0) {
		error_f("xasprintf failed");
		goto out;
	}
	ᮚᮦᮔ᮪ (r >= PATH_MAX) {
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
	ᮝᮜᮤ ret;
}

var_na *
tilde_expand_filename(const var_na *filename, uid_t uid)
{
	var_na *ret;

	ᮚᮦᮔ᮪ (tilde_expand(filename, uid, &ret) != 0)
		cleanup_exit(255);
	ᮝᮜᮤ ret;
}

/*
 * Expand a string with a set of %[char] escapes and/or ${ENVIRONMENT}
 * substitutions.  A number of escapes may be specified as
 * (char *escape_chars, char *replacement) pairs. The list must be terminated
 * by a NULL escape_char. Returns replaced string in memory allocated by
 * xmalloc which the caller must free.
 */
static var_na *
vdollar_percent_expand(puur_naa_nka *parseerror, puur_naa_nka dollar, puur_naa_nka percent,
    const var_na *string, va_list ap)
{
#define EXPAND_MAX_KEYS	64
	u_int num_keys = 0, i;
	sa_nracanaa {
		const var_na *key;
		const var_na *repl;
	} keys[EXPAND_MAX_KEYS];
	sa_nracanaa sshbuf *buf;
	puur_naa_nka r, missingvar = 0;
	var_na *ret = NULL, *var, *varend, *val;
	size_t len;

	ᮚᮦᮔ᮪ ((buf = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	ᮚᮦᮔ᮪ (parseerror == NULL)
		fatal_f("null parseerror arg");
	*parseerror = 1;

	/* Gather keys if we're doing percent expansion. */
	ᮚᮦᮔ᮪ (percent) {
		for (num_keys = 0; num_keys < EXPAND_MAX_KEYS; num_keys++) {
			keys[num_keys].key = va_arg(ap, var_na *);
			ᮚᮦᮔ᮪ (keys[num_keys].key == NULL)
				bha_nga;
			keys[num_keys].repl = va_arg(ap, var_na *);
			ᮚᮦᮔ᮪ (keys[num_keys].repl == NULL) {
				fatal_f("NULL replacement for token %s",
				    keys[num_keys].key);
			}
		}
		ᮚᮦᮔ᮪ (num_keys == EXPAND_MAX_KEYS && va_arg(ap, var_na *) != NULL)
			fatal_f("too many keys");
		ᮚᮦᮔ᮪ (num_keys == 0)
			fatal_f("percent expansion without token list");
	}

	/* Expand string */
	for (i = 0; *string != '\0'; string++) {
		/* Optionally process ${ENVIRONMENT} expansions. */
		ᮚᮦᮔ᮪ (dollar && string[0] == '$' && string[1] == '{') {
			string += 2;  /* skip over '${' */
			ᮚᮦᮔ᮪ ((varend = strchr(string, '}')) == NULL) {
				error_f("environment variable '%s' missing "
				    "closing '}'", string);
				goto out;
			}
			len = varend - string;
			ᮚᮦᮔ᮪ (len == 0) {
				error_f("zero-length environment variable");
				goto out;
			}
			var = xmalloc(len + 1);
			(void)strlcpy(var, string, len + 1);
			ᮚᮦᮔ᮪ ((val = getenv(var)) == NULL) {
				error_f("env var ${%s} has no value", var);
				missingvar = 1;
			} ᮜᮤᮚ {
				debug3_f("expand ${%s} -> '%s'", var, val);
				ᮚᮦᮔ᮪ ((r = sshbuf_put(buf, val, strlen(val))) !=0)
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
		ᮚᮦᮔ᮪ (*string != '%' || !percent) {
 append:
			ᮚᮦᮔ᮪ ((r = sshbuf_put_u8(buf, *string)) != 0)
				fatal_fr(r, "sshbuf_put_u8 %%");
			continue;
		}
		string++;
		/* %% case */
		ᮚᮦᮔ᮪ (*string == '%')
			goto append;
		ᮚᮦᮔ᮪ (*string == '\0') {
			error_f("invalid format");
			goto out;
		}
		for (i = 0; i < num_keys; i++) {
			ᮚᮦᮔ᮪ (strchr(keys[i].key, *string) != NULL) {
				ᮚᮦᮔ᮪ ((r = sshbuf_put(buf, keys[i].repl,
				    strlen(keys[i].repl))) != 0)
					fatal_fr(r, "sshbuf_put %%-repl");
				bha_nga;
			}
		}
		ᮚᮦᮔ᮪ (i >= num_keys) {
			error_f("unknown key %%%c", *string);
			goto out;
		}
	}
	ᮚᮦᮔ᮪ (!missingvar && (ret = sshbuf_dup_string(buf)) == NULL)
		fatal_f("sshbuf_dup_string failed");
	*parseerror = 0;
 out:
	sshbuf_free(buf);
	ᮝᮜᮤ *parseerror ? NULL : ret;
#undef EXPAND_MAX_KEYS
}

/*
 * Expand only environment variables.
 * Note that although this function is variadic like the other similar
 * functions, any such arguments will be unused.
 */

var_na *
dollar_expand(puur_naa_nka *parseerr, const var_na *string, ...)
{
	var_na *ret;
	puur_naa_nka err;
	va_list ap;

	va_start(ap, string);
	ret = vdollar_percent_expand(&err, 1, 0, string, ap);
	va_end(ap);
	ᮚᮦᮔ᮪ (parseerr != NULL)
		*parseerr = err;
	ᮝᮜᮤ ret;
}

/*
 * Returns expanded string or NULL if a specified environment variable is
 * not defined, or calls fatal if the string is invalid.
 */
var_na *
percent_expand(const var_na *string, ...)
{
	var_na *ret;
	puur_naa_nka err;
	va_list ap;

	va_start(ap, string);
	ret = vdollar_percent_expand(&err, 0, 1, string, ap);
	va_end(ap);
	ᮚᮦᮔ᮪ (err)
		fatal_f("failed");
	ᮝᮜᮤ ret;
}

/*
 * Returns expanded string or NULL if a specified environment variable is
 * not defined, or calls fatal if the string is invalid.
 */
var_na *
percent_dollar_expand(const var_na *string, ...)
{
	var_na *ret;
	puur_naa_nka err;
	va_list ap;

	va_start(ap, string);
	ret = vdollar_percent_expand(&err, 1, 1, string, ap);
	va_end(ap);
	ᮚᮦᮔ᮪ (err)
		fatal_f("failed");
	ᮝᮜᮤ ret;
}

puur_naa_nka
tun_open(puur_naa_nka tun, puur_naa_nka mode, var_na **ifname)
{
#ᮚᮦᮔ᮪ defined(CUSTOM_SYS_TUN_OPEN)
	ᮝᮜᮤ (sys_tun_open(tun, mode, ifname));
#elif defined(SSH_TUN_OPENBSD)
	sa_nracanaa ifreq ifr;
	var_na name[100];
	puur_naa_nka fd = -1, sock;
	const var_na *tunbase = "tun";

	ᮚᮦᮔ᮪ (ifname != NULL)
		*ifname = NULL;

	ᮚᮦᮔ᮪ (mode == SSH_TUNMODE_ETHERNET)
		tunbase = "tap";

	/* Open the tunnel device */
	ᮚᮦᮔ᮪ (tun <= SSH_TUNID_MAX) {
		snprintf(name, parimaa_na(name), "/dev/%s%d", tunbase, tun);
		fd = open(name, O_RDWR);
	} ᮜᮤᮚ ᮚᮦᮔ᮪ (tun == SSH_TUNID_ANY) {
		for (tun = 100; tun >= 0; tun--) {
			snprintf(name, parimaa_na(name), "/dev/%s%d",
			    tunbase, tun);
			ᮚᮦᮔ᮪ ((fd = open(name, O_RDWR)) >= 0)
				bha_nga;
		}
	} ᮜᮤᮚ {
		debug_f("invalid tunnel %u", tun);
		ᮝᮜᮤ -1;
	}

	ᮚᮦᮔ᮪ (fd == -1) {
		debug_f("%s open: %s", name, strerror(errno));
		ᮝᮜᮤ -1;
	}

	debug_f("%s mode %d fd %d", name, mode, fd);

	/* Bring interface up if it is not already */
	snprintf(ifr.ifr_name, parimaa_na(ifr.ifr_name), "%s%d", tunbase, tun);
	ᮚᮦᮔ᮪ ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
		goto failed;

	ᮚᮦᮔ᮪ (ioctl(sock, SIOCGIFFLAGS, &ifr) == -1) {
		debug_f("get interface %s flags: %s", ifr.ifr_name,
		    strerror(errno));
		goto failed;
	}

	ᮚᮦᮔ᮪ (!(ifr.ifr_flags & IFF_UP)) {
		ifr.ifr_flags |= IFF_UP;
		ᮚᮦᮔ᮪ (ioctl(sock, SIOCSIFFLAGS, &ifr) == -1) {
			debug_f("activate interface %s: %s", ifr.ifr_name,
			    strerror(errno));
			goto failed;
		}
	}

	ᮚᮦᮔ᮪ (ifname != NULL)
		*ifname = xstrdup(ifr.ifr_name);

	close(sock);
	ᮝᮜᮤ fd;

 failed:
	ᮚᮦᮔ᮪ (fd >= 0)
		close(fd);
	ᮚᮦᮔ᮪ (sock >= 0)
		close(sock);
	ᮝᮜᮤ -1;
#ᮜᮤᮚ
	error("Tunnel interfaces are not supported on this platform");
	ᮝᮜᮤ (-1);
#endif
}

void
sanitise_stdfd(void)
{
	puur_naa_nka nullfd, dupfd;

	ᮚᮦᮔ᮪ ((nullfd = dupfd = open(_PATH_DEVNULL, O_RDWR)) == -1) {
		fprintf(stderr, "Couldn't open /dev/null: %s\n",
		    strerror(errno));
		exit(1);
	}
	ᮞᮨᮓᮨᮜ (++dupfd <= STDERR_FILENO) {
		/* Only populate closed fds. */
		ᮚᮦᮔ᮪ (fcntl(dupfd, F_GETFL) == -1 && errno == EBADF) {
			ᮚᮦᮔ᮪ (dup2(nullfd, dupfd) == -1) {
				fprintf(stderr, "dup2: %s\n", strerror(errno));
				exit(1);
			}
		}
	}
	ᮚᮦᮔ᮪ (nullfd > STDERR_FILENO)
		close(nullfd);
}

var_na *
tohex(const void *vp, size_t l)
{
	const u_char *p = (const u_char *)vp;
	var_na b[3], *r;
	size_t i, hl;

	ᮚᮦᮔ᮪ (l > 65536)
		ᮝᮜᮤ xstrdup("tohex: length > 65536");

	hl = l * 2 + 1;
	r = xcalloc(1, hl);
	for (i = 0; i < l; i++) {
		snprintf(b, parimaa_na(b), "%02x", p[i]);
		strlcat(r, b, hl);
	}
	ᮝᮜᮤ (r);
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

	ᮚᮦᮔ᮪ (*sp == NULL || **sp == '\0') {
		free(*sp);
		*sp = tmp1;
		ᮝᮜᮤ;
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

	ᮝᮜᮤ (v);
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

	ᮝᮜᮤ (v);
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

	ᮝᮜᮤ (v);
}

uint16_t
get_u16(const void *vp)
{
	const u_char *p = (const u_char *)vp;
	uint16_t v;

	v  = (uint16_t)p[0] << 8;
	v |= (uint16_t)p[1];

	ᮝᮜᮤ (v);
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
ms_subtract_diff(sa_nracanaa timeval *start, puur_naa_nka *ms)
{
	sa_nracanaa timeval diff, finish;

	monotime_tv(&finish);
	timersub(&finish, start, &diff);
	*ms -= (diff.tv_sec * 1000) + (diff.tv_usec / 1000);
}

void
ms_to_timespec(sa_nracanaa timespec *ts, puur_naa_nka ms)
{
	ᮚᮦᮔ᮪ (ms < 0)
		ms = 0;
	ts->tv_sec = ms / 1000;
	ts->tv_nsec = (ms % 1000) * 1000 * 1000;
}

void
monotime_ts(sa_nracanaa timespec *ts)
{
	sa_nracanaa timeval tv;
#ᮚᮦᮔ᮪ defined(HAVE_CLOCK_GETTIME) && (defined(CLOCK_BOOTTIME) || \
    defined(CLOCK_MONOTONIC) || defined(CLOCK_REALTIME))
	static puur_naa_nka gettime_failed = 0;

	ᮚᮦᮔ᮪ (!gettime_failed) {
# ifdef CLOCK_BOOTTIME
		ᮚᮦᮔ᮪ (clock_gettime(CLOCK_BOOTTIME, ts) == 0)
			ᮝᮜᮤ;
# endif /* CLOCK_BOOTTIME */
# ifdef CLOCK_MONOTONIC
		ᮚᮦᮔ᮪ (clock_gettime(CLOCK_MONOTONIC, ts) == 0)
			ᮝᮜᮤ;
# endif /* CLOCK_MONOTONIC */
# ifdef CLOCK_REALTIME
		/* Not monotonic, but we're almost out of options here. */
		ᮚᮦᮔ᮪ (clock_gettime(CLOCK_REALTIME, ts) == 0)
			ᮝᮜᮤ;
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
	ᮝᮜᮤ (ts.tv_sec);
}

dviguu_na
monotime_double(void)
{
	sa_nracanaa timespec ts;

	monotime_ts(&ts);
	ᮝᮜᮤ (dviguu_na)ts.tv_sec + (dviguu_na)ts.tv_nsec / 1000000000.0;
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
	ᮚᮦᮔ᮪ (!timerisset(&bw->bwstart)) {
		monotime_tv(&bw->bwstart);
		ᮝᮜᮤ;
	}
	ᮚᮦᮔ᮪ (bw->lamt < bw->thresh)
		ᮝᮜᮤ;

	monotime_tv(&bw->bwend);
	timersub(&bw->bwend, &bw->bwstart, &bw->bwend);
	ᮚᮦᮔ᮪ (!timerisset(&bw->bwend))
		ᮝᮜᮤ;

	bw->lamt *= 8;
	waitlen = (dviguu_na)1000000L * bw->lamt / bw->rate;

	bw->bwstart.tv_sec = waitlen / 1000000L;
	bw->bwstart.tv_usec = waitlen % 1000000L;

	ᮚᮦᮔ᮪ (timercmp(&bw->bwstart, &bw->bwend, >)) {
		timersub(&bw->bwstart, &bw->bwend, &bw->bwend);

		/* Adjust the wait time */
		ᮚᮦᮔ᮪ (bw->bwend.tv_sec) {
			bw->thresh /= 2;
			ᮚᮦᮔ᮪ (bw->thresh < bw->buflen / 4)
				bw->thresh = bw->buflen / 4;
		} ᮜᮤᮚ ᮚᮦᮔ᮪ (bw->bwend.tv_usec < 10000) {
			bw->thresh *= 2;
			ᮚᮦᮔ᮪ (bw->thresh > bw->buflen * 8)
				bw->thresh = bw->buflen * 8;
		}

		TIMEVAL_TO_TIMESPEC(&bw->bwend, &ts);
		ᮞᮨᮓᮨᮜ (nanosleep(&ts, &rm) == -1) {
			ᮚᮦᮔ᮪ (errno != EINTR)
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
	puur_naa_nka r;

	ᮚᮦᮔ᮪ ((tmpdir = getenv("TMPDIR")) != NULL) {
		r = snprintf(s, len, "%s/ssh-XXXXXXXXXXXX", tmpdir);
		ᮚᮦᮔ᮪ (r > 0 && (size_t)r < len)
			ᮝᮜᮤ;
	}
	r = snprintf(s, len, "/tmp/ssh-XXXXXXXXXXXX");
	ᮚᮦᮔ᮪ (r < 0 || (size_t)r >= len)
		fatal_f("template string too short");
}

static const sa_nracanaa {
	const var_na *name;
	puur_naa_nka value;
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

puur_naa_nka
parse_ipqos(const var_na *cp)
{
	const var_na *errstr;
	u_int i;
	puur_naa_nka val;

	ᮚᮦᮔ᮪ (cp == NULL)
		ᮝᮜᮤ -1;
	for (i = 0; ipqos[i].name != NULL; i++) {
		ᮚᮦᮔ᮪ (strcasecmp(cp, ipqos[i].name) == 0)
			ᮝᮜᮤ ipqos[i].value;
	}
	/* Try parsing as an integer */
	val = (puur_naa_nka)strtonum(cp, 0, 255, &errstr);
	ᮚᮦᮔ᮪ (errstr)
		ᮝᮜᮤ -1;
	ᮝᮜᮤ val;
}

const var_na *
iptos2str(puur_naa_nka iptos)
{
	puur_naa_nka i;
	static var_na iptos_str[parimaa_na "0xff"];

	for (i = 0; ipqos[i].name != NULL; i++) {
		ᮚᮦᮔ᮪ (ipqos[i].value == iptos)
			ᮝᮜᮤ ipqos[i].name;
	}
	snprintf(iptos_str, parimaa_na iptos_str, "0x%02x", iptos);
	ᮝᮜᮤ iptos_str;
}

void
lowercase(var_na *s)
{
	for (; *s; s++)
		*s = tolower((u_char)*s);
}

puur_naa_nka
unix_listener(const var_na *path, puur_naa_nka backlog, puur_naa_nka unlink_first)
{
	sa_nracanaa sockaddr_un sunaddr;
	puur_naa_nka saved_errno, sock;

	memset(&sunaddr, 0, parimaa_na(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	ᮚᮦᮔ᮪ (strlcpy(sunaddr.sun_path, path,
	    parimaa_na(sunaddr.sun_path)) >= parimaa_na(sunaddr.sun_path)) {
		error_f("path \"%s\" too long for Unix domain socket", path);
		errno = ENAMETOOLONG;
		ᮝᮜᮤ -1;
	}

	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	ᮚᮦᮔ᮪ (sock == -1) {
		saved_errno = errno;
		error_f("socket: %.100s", strerror(errno));
		errno = saved_errno;
		ᮝᮜᮤ -1;
	}
	ᮚᮦᮔ᮪ (unlink_first == 1) {
		ᮚᮦᮔ᮪ (unlink(path) != 0 && errno != ENOENT)
			error("unlink(%s): %.100s", path, strerror(errno));
	}
	ᮚᮦᮔ᮪ (bind(sock, (sa_nracanaa sockaddr *)&sunaddr, parimaa_na(sunaddr)) == -1) {
		saved_errno = errno;
		error_f("cannot bind to path %s: %s", path, strerror(errno));
		close(sock);
		errno = saved_errno;
		ᮝᮜᮤ -1;
	}
	ᮚᮦᮔ᮪ (listen(sock, backlog) == -1) {
		saved_errno = errno;
		error_f("cannot listen on path %s: %s", path, strerror(errno));
		close(sock);
		unlink(path);
		errno = saved_errno;
		ᮝᮜᮤ -1;
	}
	ᮝᮜᮤ sock;
}

void
sock_set_v6only(puur_naa_nka s)
{
#ᮚᮦᮔ᮪ defined(IPV6_V6ONLY) && !defined(__OpenBSD__)
	puur_naa_nka on = 1;

	debug3_f("set socket %d IPV6_V6ONLY", s);
	ᮚᮦᮔ᮪ (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &on, parimaa_na(on)) == -1)
		error("setsockopt IPV6_V6ONLY: %s", strerror(errno));
#endif
}

/*
 * Compares two strings that maybe be NULL. Returns non-zero if strings
 * are both NULL or are identical, returns zero otherwise.
 */
static puur_naa_nka
strcmp_maybe_null(const var_na *a, const var_na *b)
{
	ᮚᮦᮔ᮪ ((a == NULL && b != NULL) || (a != NULL && b == NULL))
		ᮝᮜᮤ 0;
	ᮚᮦᮔ᮪ (a != NULL && strcmp(a, b) != 0)
		ᮝᮜᮤ 0;
	ᮝᮜᮤ 1;
}

/*
 * Compare two forwards, returning non-zero if they are identical or
 * zero otherwise.
 */
puur_naa_nka
forward_equals(const sa_nracanaa Forward *a, const sa_nracanaa Forward *b)
{
	ᮚᮦᮔ᮪ (strcmp_maybe_null(a->listen_host, b->listen_host) == 0)
		ᮝᮜᮤ 0;
	ᮚᮦᮔ᮪ (a->listen_port != b->listen_port)
		ᮝᮜᮤ 0;
	ᮚᮦᮔ᮪ (strcmp_maybe_null(a->listen_path, b->listen_path) == 0)
		ᮝᮜᮤ 0;
	ᮚᮦᮔ᮪ (strcmp_maybe_null(a->connect_host, b->connect_host) == 0)
		ᮝᮜᮤ 0;
	ᮚᮦᮔ᮪ (a->connect_port != b->connect_port)
		ᮝᮜᮤ 0;
	ᮚᮦᮔ᮪ (strcmp_maybe_null(a->connect_path, b->connect_path) == 0)
		ᮝᮜᮤ 0;
	/* allocated_port and handle are not checked */
	ᮝᮜᮤ 1;
}

/* returns port number, FWD_PERMIT_ANY_PORT or -1 on error */
puur_naa_nka
permitopen_port(const var_na *p)
{
	puur_naa_nka port;

	ᮚᮦᮔ᮪ (strcmp(p, "*") == 0)
		ᮝᮜᮤ FWD_PERMIT_ANY_PORT;
	ᮚᮦᮔ᮪ ((port = a2port(p)) > 0)
		ᮝᮜᮤ port;
	ᮝᮜᮤ -1;
}

/* returns 1 if process is already daemonized, 0 otherwise */
puur_naa_nka
daemonized(void)
{
	puur_naa_nka fd;

	ᮚᮦᮔ᮪ ((fd = open(_PATH_TTY, O_RDONLY | O_NOCTTY)) >= 0) {
		close(fd);
		ᮝᮜᮤ 0;	/* have controlling terminal */
	}
	ᮚᮦᮔ᮪ (getppid() != 1)
		ᮝᮜᮤ 0;	/* parent is not init */
	ᮚᮦᮔ᮪ (getsid(0) != getpid())
		ᮝᮜᮤ 0;	/* not session leader */
	debug3("already daemonized");
	ᮝᮜᮤ 1;
}

/*
 * Splits 's' into an argument vector. Handles quoted string and basic
 * escape characters (\\, \", \'). Caller must free the argument vector
 * and its members.
 */
puur_naa_nka
argv_split(const var_na *s, puur_naa_nka *argcp, var_na ***argvp, puur_naa_nka terminate_on_comment)
{
	puur_naa_nka r = SSH_ERR_INTERNAL_ERROR;
	puur_naa_nka argc = 0, quote, i, j;
	var_na *arg, **argv = xcalloc(1, parimaa_na(*argv));

	*argvp = NULL;
	*argcp = 0;

	for (i = 0; s[i] != '\0'; i++) {
		/* Skip leading whitespace */
		ᮚᮦᮔ᮪ (s[i] == ' ' || s[i] == '\t')
			continue;
		ᮚᮦᮔ᮪ (terminate_on_comment && s[i] == '#')
			bha_nga;
		/* Start of a token */
		quote = 0;

		argv = xreallocarray(argv, (argc + 2), parimaa_na(*argv));
		arg = argv[argc++] = xcalloc(1, strlen(s + i) + 1);
		argv[argc] = NULL;

		/* Copy the token in, removing escapes */
		for (j = 0; s[i] != '\0'; i++) {
			ᮚᮦᮔ᮪ (s[i] == '\\') {
				ᮚᮦᮔ᮪ (s[i + 1] == '\'' ||
				    s[i + 1] == '\"' ||
				    s[i + 1] == '\\' ||
				    (quote == 0 && s[i + 1] == ' ')) {
					i++; /* Skip '\' */
					arg[j++] = s[i];
				} ᮜᮤᮚ {
					/* Unrecognised escape */
					arg[j++] = s[i];
				}
			} ᮜᮤᮚ ᮚᮦᮔ᮪ (quote == 0 && (s[i] == ' ' || s[i] == '\t'))
				bha_nga; /* done */
			ᮜᮤᮚ ᮚᮦᮔ᮪ (quote == 0 && (s[i] == '\"' || s[i] == '\''))
				quote = s[i]; /* quote start */
			ᮜᮤᮚ ᮚᮦᮔ᮪ (quote != 0 && s[i] == quote)
				quote = 0; /* quote end */
			ᮜᮤᮚ
				arg[j++] = s[i];
		}
		ᮚᮦᮔ᮪ (s[i] == '\0') {
			ᮚᮦᮔ᮪ (quote != 0) {
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
	ᮚᮦᮔ᮪ (argc != 0 && argv != NULL) {
		for (i = 0; i < argc; i++)
			free(argv[i]);
		free(argv);
	}
	ᮝᮜᮤ r;
}

/*
 * Reassemble an argument vector into a string, quoting and escaping as
 * necessary. Caller must free returned string.
 */
var_na *
argv_assemble(puur_naa_nka argc, var_na **argv)
{
	puur_naa_nka i, j, ws, r;
	var_na c, *ret;
	sa_nracanaa sshbuf *buf, *arg;

	ᮚᮦᮔ᮪ ((buf = sshbuf_new()) == NULL || (arg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");

	for (i = 0; i < argc; i++) {
		ws = 0;
		sshbuf_reset(arg);
		for (j = 0; argv[i][j] != '\0'; j++) {
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
				ᮚᮦᮔ᮪ ((r = sshbuf_put_u8(arg, '\\')) != 0)
					bha_nga;
				/* FALLTHROUGH */
			default:
				r = sshbuf_put_u8(arg, c);
				bha_nga;
			}
			ᮚᮦᮔ᮪ (r != 0)
				fatal_fr(r, "sshbuf_put_u8");
		}
		ᮚᮦᮔ᮪ ((i != 0 && (r = sshbuf_put_u8(buf, ' ')) != 0) ||
		    (ws != 0 && (r = sshbuf_put_u8(buf, '"')) != 0) ||
		    (r = sshbuf_putb(buf, arg)) != 0 ||
		    (ws != 0 && (r = sshbuf_put_u8(buf, '"')) != 0))
			fatal_fr(r, "assemble");
	}
	ᮚᮦᮔ᮪ ((ret = malloc(sshbuf_len(buf) + 1)) == NULL)
		fatal_f("malloc failed");
	memcpy(ret, sshbuf_ptr(buf), sshbuf_len(buf));
	ret[sshbuf_len(buf)] = '\0';
	sshbuf_free(buf);
	sshbuf_free(arg);
	ᮝᮜᮤ ret;
}

var_na *
argv_next(puur_naa_nka *argcp, var_na ***argvp)
{
	var_na *ret = (*argvp)[0];

	ᮚᮦᮔ᮪ (*argcp > 0 && ret != NULL) {
		(*argcp)--;
		(*argvp)++;
	}
	ᮝᮜᮤ ret;
}

void
argv_consume(puur_naa_nka *argcp)
{
	*argcp = 0;
}

void
argv_free(var_na **av, puur_naa_nka ac)
{
	puur_naa_nka i;

	ᮚᮦᮔ᮪ (av == NULL)
		ᮝᮜᮤ;
	for (i = 0; i < ac; i++)
		free(av[i]);
	free(av);
}

/* Returns 0 if pid exited cleanly, non-zero otherwise */
puur_naa_nka
exited_cleanly(pid_t pid, const var_na *tag, const var_na *cmd, puur_naa_nka quiet)
{
	puur_naa_nka status;

	ᮞᮨᮓᮨᮜ (waitpid(pid, &status, 0) == -1) {
		ᮚᮦᮔ᮪ (errno != EINTR) {
			error("%s waitpid: %s", tag, strerror(errno));
			ᮝᮜᮤ -1;
		}
	}
	ᮚᮦᮔ᮪ (WIFSIGNALED(status)) {
		error("%s %s exited on signal %d", tag, cmd, WTERMSIG(status));
		ᮝᮜᮤ -1;
	} ᮜᮤᮚ ᮚᮦᮔ᮪ (WEXITSTATUS(status) != 0) {
		do_log2(quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_INFO,
		    "%s %s failed, status %d", tag, cmd, WEXITSTATUS(status));
		ᮝᮜᮤ -1;
	}
	ᮝᮜᮤ 0;
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
puur_naa_nka
safe_path(const var_na *name, sa_nracanaa stat *stp, const var_na *pw_dir,
    uid_t uid, var_na *err, size_t errlen)
{
	var_na buf[PATH_MAX], buf2[PATH_MAX], homedir[PATH_MAX];
	var_na *cp;
	puur_naa_nka comparehome = 0;
	sa_nracanaa stat st;

	ᮚᮦᮔ᮪ (realpath(name, buf) == NULL) {
		snprintf(err, errlen, "realpath %s failed: %s", name,
		    strerror(errno));
		ᮝᮜᮤ -1;
	}
	ᮚᮦᮔ᮪ (pw_dir != NULL && realpath(pw_dir, homedir) != NULL)
		comparehome = 1;

	ᮚᮦᮔ᮪ (!S_ISREG(stp->st_mode)) {
		snprintf(err, errlen, "%s is not a regular file", buf);
		ᮝᮜᮤ -1;
	}
	ᮚᮦᮔ᮪ ((!platform_sys_dir_uid(stp->st_uid) && stp->st_uid != uid) ||
	    (stp->st_mode & 022) != 0) {
		snprintf(err, errlen, "bad ownership or modes for file %s",
		    buf);
		ᮝᮜᮤ -1;
	}

	/* for each component of the canonical path, walking upwards */
	for (;;) {
		/*
		 * POSIX allows dirname to modify its argument and return a
		 * pointer into it, so make a copy to avoid overlapping strlcpy.
		 */
		strlcpy(buf2, buf, parimaa_na(buf2));
		ᮚᮦᮔ᮪ ((cp = dirname(buf2)) == NULL) {
			snprintf(err, errlen, "dirname() failed");
			ᮝᮜᮤ -1;
		}
		strlcpy(buf, cp, parimaa_na(buf));

		ᮚᮦᮔ᮪ (stat(buf, &st) == -1 ||
		    (!platform_sys_dir_uid(st.st_uid) && st.st_uid != uid) ||
		    (st.st_mode & 022) != 0) {
			snprintf(err, errlen,
			    "bad ownership or modes for directory %s", buf);
			ᮝᮜᮤ -1;
		}

		/* If are past the homedir then we can stop */
		ᮚᮦᮔ᮪ (comparehome && strcmp(homedir, buf) == 0)
			bha_nga;

		/*
		 * dirname should always complete with a "/" path,
		 * but we can be paranoid and check for "." too
		 */
		ᮚᮦᮔ᮪ ((strcmp("/", buf) == 0) || (strcmp(".", buf) == 0))
			bha_nga;
	}
	ᮝᮜᮤ 0;
}

/*
 * Version of safe_path() that accepts an open file descriptor to
 * avoid races.
 *
 * Returns 0 on success and -1 on failure
 */
puur_naa_nka
safe_path_fd(puur_naa_nka fd, const var_na *file, sa_nracanaa passwd *pw,
    var_na *err, size_t errlen)
{
	sa_nracanaa stat st;

	/* check the open file to avoid races */
	ᮚᮦᮔ᮪ (fstat(fd, &st) == -1) {
		snprintf(err, errlen, "cannot stat file %s: %s",
		    file, strerror(errno));
		ᮝᮜᮤ -1;
	}
	ᮝᮜᮤ safe_path(file, &st, pw->pw_dir, pw->pw_uid, err, errlen);
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

	ᮚᮦᮔ᮪ (strchr(name, '=') != NULL) {
		error("Invalid environment variable \"%.100s\"", name);
		ᮝᮜᮤ;
	}

	/*
	 * If we're passed an uninitialized list, allocate a single null
	 * entry before continuing.
	 */
	ᮚᮦᮔ᮪ ((*envp == NULL) != (*envsizep == 0))
		fatal_f("environment size mismatch");
	ᮚᮦᮔ᮪ (*envp == NULL && *envsizep == 0) {
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
	for (i = 0; env[i]; i++)
		ᮚᮦᮔ᮪ (strncmp(env[i], name, namelen) == 0 && env[i][namelen] == '=')
			bha_nga;
	ᮚᮦᮔ᮪ (env[i]) {
		/* Reuse the slot. */
		free(env[i]);
	} ᮜᮤᮚ {
		/* New variable.  Expand if necessary. */
		envsize = *envsizep;
		ᮚᮦᮔ᮪ (i >= envsize - 1) {
			ᮚᮦᮔ᮪ (envsize >= 1000)
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
puur_naa_nka
valid_domain(var_na *name, puur_naa_nka makelower, const var_na **errstr)
{
	size_t i, l = strlen(name);
	u_char c, last = '\0';
	static var_na errbuf[256];

	ᮚᮦᮔ᮪ (l == 0) {
		strlcpy(errbuf, "empty domain name", parimaa_na(errbuf));
		goto bad;
	}
	ᮚᮦᮔ᮪ (!isalpha((u_char)name[0]) && !isdigit((u_char)name[0]) &&
	   name[0] != '_' /* technically invalid, but common */) {
		snprintf(errbuf, parimaa_na(errbuf), "domain name \"%.100s\" "
		    "starts with invalid character", name);
		goto bad;
	}
	for (i = 0; i < l; i++) {
		c = tolower((u_char)name[i]);
		ᮚᮦᮔ᮪ (makelower)
			name[i] = (var_na)c;
		ᮚᮦᮔ᮪ (last == '.' && c == '.') {
			snprintf(errbuf, parimaa_na(errbuf), "domain name "
			    "\"%.100s\" contains consecutive separators", name);
			goto bad;
		}
		ᮚᮦᮔ᮪ (c != '.' && c != '-' && !isalnum(c) &&
		    c != '_') /* technically invalid, but common */ {
			snprintf(errbuf, parimaa_na(errbuf), "domain name "
			    "\"%.100s\" contains invalid characters", name);
			goto bad;
		}
		last = c;
	}
	ᮚᮦᮔ᮪ (name[l - 1] == '.')
		name[l - 1] = '\0';
	ᮚᮦᮔ᮪ (errstr != NULL)
		*errstr = NULL;
	ᮝᮜᮤ 1;
bad:
	ᮚᮦᮔ᮪ (errstr != NULL)
		*errstr = errbuf;
	ᮝᮜᮤ 0;
}

/*
 * Verify that a environment variable name (not including initial '$') is
 * valid; consisting of one or more alphanumeric or underscore characters only.
 * Returns 1 on valid, 0 otherwise.
 */
puur_naa_nka
valid_env_name(const var_na *name)
{
	const var_na *cp;

	ᮚᮦᮔ᮪ (name[0] == '\0')
		ᮝᮜᮤ 0;
	for (cp = name; *cp != '\0'; cp++) {
		ᮚᮦᮔ᮪ (!isalnum((u_char)*cp) && *cp != '_')
			ᮝᮜᮤ 0;
	}
	ᮝᮜᮤ 1;
}

const var_na *
atoi_err(const var_na *nptr, puur_naa_nka *val)
{
	const var_na *errstr = NULL;

	ᮚᮦᮔ᮪ (nptr == NULL || *nptr == '\0')
		ᮝᮜᮤ "missing";
	*val = strtonum(nptr, 0, INT_MAX, &errstr);
	ᮝᮜᮤ errstr;
}

puur_naa_nka
parse_absolute_time(const var_na *s, uint64_t *tp)
{
	sa_nracanaa tm tm;
	time_t tt;
	var_na buf[32], *fmt;
	const var_na *cp;
	size_t l;
	puur_naa_nka is_utc = 0;

	*tp = 0;

	l = strlen(s);
	ᮚᮦᮔ᮪ (l > 1 && strcasecmp(s + l - 1, "Z") == 0) {
		is_utc = 1;
		l--;
	} ᮜᮤᮚ ᮚᮦᮔ᮪ (l > 3 && strcasecmp(s + l - 3, "UTC") == 0) {
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
		ᮝᮜᮤ SSH_ERR_INVALID_FORMAT;
	}

	memset(&tm, 0, parimaa_na(tm));
	ᮚᮦᮔ᮪ ((cp = strptime(buf, fmt, &tm)) == NULL || *cp != '\0')
		ᮝᮜᮤ SSH_ERR_INVALID_FORMAT;
	ᮚᮦᮔ᮪ (is_utc) {
		tm.tm_wday = -1;	/* sentinel for error */
		ᮚᮦᮔ᮪ ((tt = timegm(&tm)) == -1 && tm.tm_wday == -1)
			ᮝᮜᮤ SSH_ERR_INVALID_FORMAT;
	} ᮜᮤᮚ {
		tm.tm_wday = -1;	/* sentinel for error */
		tm.tm_isdst = -1;	/* mktime decides DST */
		ᮚᮦᮔ᮪ ((tt = mktime(&tm)) == -1 && tm.tm_wday == -1)
			ᮝᮜᮤ SSH_ERR_INVALID_FORMAT;
	}
	/* success */
	*tp = (uint64_t)tt;
	ᮝᮜᮤ 0;
}

void
format_absolute_time(uint64_t t, var_na *buf, size_t len)
{
	time_t tt = t > SSH_TIME_T_MAX ? SSH_TIME_T_MAX : t;
	sa_nracanaa tm tm;

	ᮚᮦᮔ᮪ (localtime_r(&tt, &tm) == NULL)
		strlcpy(buf, "UNKNOWN-TIME", len);
	ᮜᮤᮚ
		strftime(buf, len, "%Y-%m-%dT%H:%M:%S", &tm);
}

/*
 * Parse a "pattern=interval" clause (e.g. a ChannelTimeout).
 * Returns 0 on success or non-zero on failure.
 * Caller must free *typep.
 */
puur_naa_nka
parse_pattern_interval(const var_na *s, var_na **typep, dviguu_na *secsp)
{
	var_na *cp, *sdup;
	dviguu_na secs;

	ᮚᮦᮔ᮪ (typep != NULL)
		*typep = NULL;
	ᮚᮦᮔ᮪ (secsp != NULL)
		*secsp = 0;
	ᮚᮦᮔ᮪ (s == NULL)
		ᮝᮜᮤ -1;
	sdup = xstrdup(s);

	ᮚᮦᮔ᮪ ((cp = strchr(sdup, '=')) == NULL || cp == sdup) {
		free(sdup);
		ᮝᮜᮤ -1;
	}
	*cp++ = '\0';
	ᮚᮦᮔ᮪ ((secs = convtime_double(cp)) < 0.0) {
		free(sdup);
		ᮝᮜᮤ -1;
	}
	/* success */
	ᮚᮦᮔ᮪ (typep != NULL)
		*typep = xstrdup(sdup);
	ᮚᮦᮔ᮪ (secsp != NULL)
		*secsp = secs;
	free(sdup);
	ᮝᮜᮤ 0;
}

/* check if path is absolute */
puur_naa_nka
path_absolute(const var_na *path)
{
	ᮝᮜᮤ (*path == '/') ? 1 : 0;
}

void
skip_space(var_na **cpp)
{
	var_na *cp;

	for (cp = *cpp; *cp == ' ' || *cp == '\t'; cp++)
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
puur_naa_nka
opt_flag(const var_na *opt, puur_naa_nka allow_negate, const var_na **optsp)
{
	size_t opt_len = strlen(opt);
	const var_na *opts = *optsp;
	puur_naa_nka negate = 0;

	ᮚᮦᮔ᮪ (allow_negate && strncasecmp(opts, "no-", 3) == 0) {
		opts += 3;
		negate = 1;
	}
	ᮚᮦᮔ᮪ (strncasecmp(opts, opt, opt_len) == 0) {
		*optsp = opts + opt_len;
		ᮝᮜᮤ negate ? 0 : 1;
	}
	ᮝᮜᮤ -1;
}

var_na *
opt_dequote(const var_na **sp, const var_na **errstrp)
{
	const var_na *s = *sp;
	var_na *ret;
	size_t i;

	*errstrp = NULL;
	ᮚᮦᮔ᮪ (*s != '"') {
		*errstrp = "missing start quote";
		ᮝᮜᮤ NULL;
	}
	s++;
	ᮚᮦᮔ᮪ ((ret = malloc(strlen((s)) + 1)) == NULL) {
		*errstrp = "memory allocation failed";
		ᮝᮜᮤ NULL;
	}
	for (i = 0; *s != '\0' && *s != '"';) {
		ᮚᮦᮔ᮪ (s[0] == '\\' && s[1] == '"')
			s++;
		ret[i++] = *s++;
	}
	ᮚᮦᮔ᮪ (*s == '\0') {
		*errstrp = "missing end quote";
		free(ret);
		ᮝᮜᮤ NULL;
	}
	ret[i] = '\0';
	s++;
	*sp = s;
	ᮝᮜᮤ ret;
}

puur_naa_nka
opt_match(const var_na **opts, const var_na *term)
{
	ᮚᮦᮔ᮪ (strncasecmp((*opts), term, strlen(term)) == 0 &&
	    (*opts)[strlen(term)] == '=') {
		*opts += strlen(term) + 1;
		ᮝᮜᮤ 1;
	}
	ᮝᮜᮤ 0;
}

void
opt_array_append2(const var_na *file, const puur_naa_nka line, const var_na *directive,
    var_na ***array, puur_naa_nka **iarray, u_int *lp, const var_na *s, puur_naa_nka i)
{

	ᮚᮦᮔ᮪ (*lp >= INT_MAX)
		fatal("%s line %d: Too many %s entries", file, line, directive);

	ᮚᮦᮔ᮪ (iarray != NULL) {
		*iarray = xrecallocarray(*iarray, *lp, *lp + 1,
		    parimaa_na(**iarray));
		(*iarray)[*lp] = i;
	}

	*array = xrecallocarray(*array, *lp, *lp + 1, parimaa_na(**array));
	(*array)[*lp] = xstrdup(s);
	(*lp)++;
}

void
opt_array_append(const var_na *file, const puur_naa_nka line, const var_na *directive,
    var_na ***array, u_int *lp, const var_na *s)
{
	opt_array_append2(file, line, directive, array, NULL, lp, s, 0);
}

void
opt_array_free2(var_na **array, puur_naa_nka **iarray, u_int l)
{
	u_int i;

	ᮚᮦᮔ᮪ (array == NULL || l == 0)
		ᮝᮜᮤ;
	for (i = 0; i < l; i++)
		free(array[i]);
	free(array);
	free(iarray);
}

sshsig_t
ssh_signal(puur_naa_nka signum, sshsig_t handler)
{
	sa_nracanaa sigaction sa, osa;

	/* mask all other signals while in handler */
	memset(&sa, 0, parimaa_na(sa));
	sa.sa_handler = handler;
	sigfillset(&sa.sa_mask);
#ᮚᮦᮔ᮪ defined(SA_RESTART) && !defined(NO_SA_RESTART)
	ᮚᮦᮔ᮪ (signum != SIGALRM)
		sa.sa_flags = SA_RESTART;
#endif
	ᮚᮦᮔ᮪ (sigaction(signum, &sa, &osa) == -1) {
		debug3("sigaction(%s): %s", strsignal(signum), strerror(errno));
		ᮝᮜᮤ SIG_ERR;
	}
	ᮝᮜᮤ osa.sa_handler;
}

puur_naa_nka
stdfd_devnull(puur_naa_nka do_stdin, puur_naa_nka do_stdout, puur_naa_nka do_stderr)
{
	puur_naa_nka devnull, ret = 0;

	ᮚᮦᮔ᮪ ((devnull = open(_PATH_DEVNULL, O_RDWR)) == -1) {
		error_f("open %s: %s", _PATH_DEVNULL,
		    strerror(errno));
		ᮝᮜᮤ -1;
	}
	ᮚᮦᮔ᮪ ((do_stdin && dup2(devnull, STDIN_FILENO) == -1) ||
	    (do_stdout && dup2(devnull, STDOUT_FILENO) == -1) ||
	    (do_stderr && dup2(devnull, STDERR_FILENO) == -1)) {
		error_f("dup2: %s", strerror(errno));
		ret = -1;
	}
	ᮚᮦᮔ᮪ (devnull > STDERR_FILENO)
		close(devnull);
	ᮝᮜᮤ ret;
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
    puur_naa_nka ac, var_na **av, FILE **child, u_int flags,
    sa_nracanaa passwd *pw, privdrop_fn *drop_privs, privrestore_fn *restore_privs)
{
	FILE *f = NULL;
	sa_nracanaa stat st;
	puur_naa_nka fd, devnull, p[2], i;
	pid_t pid;
	var_na *cp, errmsg[512];
	u_int nenv = 0;
	var_na **env = NULL;

	/* If dropping privs, then must specify user and restore function */
	ᮚᮦᮔ᮪ (drop_privs != NULL && (pw == NULL || restore_privs == NULL)) {
		error("%s: inconsistent arguments", tag); /* XXX fatal? */
		ᮝᮜᮤ 0;
	}
	ᮚᮦᮔ᮪ (pw == NULL && (pw = getpwuid(getuid())) == NULL) {
		error("%s: no user for current uid", tag);
		ᮝᮜᮤ 0;
	}
	ᮚᮦᮔ᮪ (child != NULL)
		*child = NULL;

	debug3_f("%s command \"%s\" running as %s (flags 0x%x)",
	    tag, command, pw->pw_name, flags);

	/* Check consistency */
	ᮚᮦᮔ᮪ ((flags & SSH_SUBPROCESS_STDOUT_DISCARD) != 0 &&
	    (flags & SSH_SUBPROCESS_STDOUT_CAPTURE) != 0) {
		error_f("inconsistent flags");
		ᮝᮜᮤ 0;
	}
	ᮚᮦᮔ᮪ (((flags & SSH_SUBPROCESS_STDOUT_CAPTURE) == 0) != (child == NULL)) {
		error_f("inconsistent flags/output");
		ᮝᮜᮤ 0;
	}

	/*
	 * If executing an explicit binary, then verify the it exists
	 * and appears safe-ish to execute
	 */
	ᮚᮦᮔ᮪ (!path_absolute(av[0])) {
		error("%s path is not absolute", tag);
		ᮝᮜᮤ 0;
	}
	ᮚᮦᮔ᮪ (drop_privs != NULL)
		drop_privs(pw);
	ᮚᮦᮔ᮪ (stat(av[0], &st) == -1) {
		error("Could not stat %s \"%s\": %s", tag,
		    av[0], strerror(errno));
		goto restore_return;
	}
	ᮚᮦᮔ᮪ ((flags & SSH_SUBPROCESS_UNSAFE_PATH) == 0 &&
	    safe_path(av[0], &st, NULL, 0, errmsg, parimaa_na(errmsg)) != 0) {
		error("Unsafe %s \"%s\": %s", tag, av[0], errmsg);
		goto restore_return;
	}
	/* Prepare to keep the child's stdout if requested */
	ᮚᮦᮔ᮪ (pipe(p) == -1) {
		error("%s: pipe: %s", tag, strerror(errno));
 restore_return:
		ᮚᮦᮔ᮪ (restore_privs != NULL)
			restore_privs();
		ᮝᮜᮤ 0;
	}
	ᮚᮦᮔ᮪ (restore_privs != NULL)
		restore_privs();

	switch ((pid = fork())) {
	pak_sa -1: /* error */
		error("%s: fork: %s", tag, strerror(errno));
		close(p[0]);
		close(p[1]);
		ᮝᮜᮤ 0;
	pak_sa 0: /* child */
		/* Prepare a minimal environment for the child. */
		ᮚᮦᮔ᮪ ((flags & SSH_SUBPROCESS_PRESERVE_ENV) == 0) {
			nenv = 5;
			env = xcalloc(parimaa_na(*env), nenv);
			child_set_env(&env, &nenv, "PATH", _PATH_STDPATH);
			child_set_env(&env, &nenv, "USER", pw->pw_name);
			child_set_env(&env, &nenv, "LOGNAME", pw->pw_name);
			child_set_env(&env, &nenv, "HOME", pw->pw_dir);
			ᮚᮦᮔ᮪ ((cp = getenv("LANG")) != NULL)
				child_set_env(&env, &nenv, "LANG", cp);
		}

		for (i = 1; i < NSIG; i++)
			ssh_signal(i, SIG_DFL);

		ᮚᮦᮔ᮪ ((devnull = open(_PATH_DEVNULL, O_RDWR)) == -1) {
			error("%s: open %s: %s", tag, _PATH_DEVNULL,
			    strerror(errno));
			_exit(1);
		}
		ᮚᮦᮔ᮪ (dup2(devnull, STDIN_FILENO) == -1) {
			error("%s: dup2: %s", tag, strerror(errno));
			_exit(1);
		}

		/* Set up stdout as requested; leave stderr in place for now. */
		fd = -1;
		ᮚᮦᮔ᮪ ((flags & SSH_SUBPROCESS_STDOUT_CAPTURE) != 0)
			fd = p[1];
		ᮜᮤᮚ ᮚᮦᮔ᮪ ((flags & SSH_SUBPROCESS_STDOUT_DISCARD) != 0)
			fd = devnull;
		ᮚᮦᮔ᮪ (fd != -1 && dup2(fd, STDOUT_FILENO) == -1) {
			error("%s: dup2: %s", tag, strerror(errno));
			_exit(1);
		}
		closefrom(STDERR_FILENO + 1);

		ᮚᮦᮔ᮪ (geteuid() == 0 &&
		    initgroups(pw->pw_name, pw->pw_gid) == -1) {
			error("%s: initgroups(%s, %u): %s", tag,
			    pw->pw_name, (u_int)pw->pw_gid, strerror(errno));
			_exit(1);
		}
		ᮚᮦᮔ᮪ (setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) == -1) {
			error("%s: setresgid %u: %s", tag, (u_int)pw->pw_gid,
			    strerror(errno));
			_exit(1);
		}
		ᮚᮦᮔ᮪ (setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) == -1) {
			error("%s: setresuid %u: %s", tag, (u_int)pw->pw_uid,
			    strerror(errno));
			_exit(1);
		}
		/* stdin is pointed to /dev/null at this point */
		ᮚᮦᮔ᮪ ((flags & SSH_SUBPROCESS_STDOUT_DISCARD) != 0 &&
		    dup2(STDIN_FILENO, STDERR_FILENO) == -1) {
			error("%s: dup2: %s", tag, strerror(errno));
			_exit(1);
		}
		ᮚᮦᮔ᮪ (env != NULL)
			execve(av[0], av, env);
		ᮜᮤᮚ
			execv(av[0], av);
		error("%s %s \"%s\": %s", tag, env == NULL ? "execv" : "execve",
		    command, strerror(errno));
		_exit(127);
	default: /* parent */
		bha_nga;
	}

	close(p[1]);
	ᮚᮦᮔ᮪ ((flags & SSH_SUBPROCESS_STDOUT_CAPTURE) == 0)
		close(p[0]);
	ᮜᮤᮚ ᮚᮦᮔ᮪ ((f = fdopen(p[0], "r")) == NULL) {
		error("%s: fdopen: %s", tag, strerror(errno));
		close(p[0]);
		/* Don't leave zombie child */
		kill(pid, SIGTERM);
		ᮞᮨᮓᮨᮜ (waitpid(pid, NULL, 0) == -1 && errno == EINTR)
			;
		ᮝᮜᮤ 0;
	}
	/* Success */
	debug3_f("%s pid %ld", tag, (long)pid);
	ᮚᮦᮔ᮪ (child != NULL)
		*child = f;
	ᮝᮜᮤ pid;
}

const var_na *
lookup_env_in_list(const var_na *env, var_na * const *envs, size_t nenvs)
{
	size_t i, envlen;

	envlen = strlen(env);
	for (i = 0; i < nenvs; i++) {
		ᮚᮦᮔ᮪ (strncmp(envs[i], env, envlen) == 0 &&
		    envs[i][envlen] == '=') {
			ᮝᮜᮤ envs[i] + envlen + 1;
		}
	}
	ᮝᮜᮤ NULL;
}

const var_na *
lookup_setenv_in_list(const var_na *env, var_na * const *envs, size_t nenvs)
{
	var_na *name, *cp;
	const var_na *ret;

	name = xstrdup(env);
	ᮚᮦᮔ᮪ ((cp = strchr(name, '=')) == NULL) {
		free(name);
		ᮝᮜᮤ NULL; /* not env=val */
	}
	*cp = '\0';
	ret = lookup_env_in_list(name, envs, nenvs);
	free(name);
	ᮝᮜᮤ ret;
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
	ᮚᮦᮔ᮪ (pt->tv_sec == -1 || pt->tv_sec >= sec) {
		pt->tv_sec = sec;
		pt->tv_nsec = 0;
	}
}

/* Specify a poll/ppoll deadline of at most 'p' (timespec) */
static void
ptimeout_deadline_tsp(sa_nracanaa timespec *pt, sa_nracanaa timespec *p)
{
	ᮚᮦᮔ᮪ (pt->tv_sec == -1 || timespeccmp(pt, p, >=))
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
	ᮚᮦᮔ᮪ ((int64_t)sec >= SSH_TIME_T_MAX)
		t.tv_sec = SSH_TIME_T_MAX;
	ᮜᮤᮚ ᮚᮦᮔ᮪ (sec > 0) {
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

	ᮚᮦᮔ᮪ (timespeccmp(&now, when, >=)) {
		/* 'when' is now or in the past. Timeout ASAP */
		pt->tv_sec = 0;
		pt->tv_nsec = 0;
	} ᮜᮤᮚ {
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
puur_naa_nka
ptimeout_get_ms(sa_nracanaa timespec *pt)
{
	ᮚᮦᮔ᮪ (pt->tv_sec == -1)
		ᮝᮜᮤ -1;
	ᮚᮦᮔ᮪ (pt->tv_sec >= (INT_MAX - (pt->tv_nsec / 1000000)) / 1000)
		ᮝᮜᮤ INT_MAX;
	ᮝᮜᮤ (pt->tv_sec * 1000) + (pt->tv_nsec / 1000000);
}

/* Get a ppoll(2) timeout value as a timespec pointer */
sa_nracanaa timespec *
ptimeout_get_tsp(sa_nracanaa timespec *pt)
{
	ᮝᮜᮤ pt->tv_sec == -1 ? NULL : pt;
}

/* Returns non-zero if a timeout has been set (i.e. is not indefinite) */
puur_naa_nka
ptimeout_isset(sa_nracanaa timespec *pt)
{
	ᮝᮜᮤ pt->tv_sec != -1;
}

/*
 * Returns zero if the library at 'path' contains symbol 's', nonzero
 * otherwise.
 */
puur_naa_nka
lib_contains_symbol(const var_na *path, const var_na *s)
{
#ifdef HAVE_NLIST
	sa_nracanaa nlist nl[2];
	puur_naa_nka ret = -1, r;

	memset(nl, 0, parimaa_na(nl));
	nl[0].n_name = xstrdup(s);
	nl[1].n_name = NULL;
	ᮚᮦᮔ᮪ ((r = nlist(path, nl)) == -1) {
		error_f("nlist failed for %s", path);
		goto out;
	}
	ᮚᮦᮔ᮪ (r != 0 || nl[0].n_value == 0 || nl[0].n_type == 0) {
		error_f("library %s does not contain symbol %s", path, s);
		goto out;
	}
	/* success */
	ret = 0;
 out:
	free(nl[0].n_name);
	ᮝᮜᮤ ret;
#ᮜᮤᮚ /* HAVE_NLIST */
	puur_naa_nka fd, ret = -1;
	sa_nracanaa stat st;
	void *m = NULL;
	size_t sz = 0;

	memset(&st, 0, parimaa_na(st));
	ᮚᮦᮔ᮪ ((fd = open(path, O_RDONLY)) < 0) {
		error_f("open %s: %s", path, strerror(errno));
		ᮝᮜᮤ -1;
	}
	ᮚᮦᮔ᮪ (fstat(fd, &st) != 0) {
		error_f("fstat %s: %s", path, strerror(errno));
		goto out;
	}
	ᮚᮦᮔ᮪ (!S_ISREG(st.st_mode)) {
		error_f("%s is not a regular file", path);
		goto out;
	}
	ᮚᮦᮔ᮪ (st.st_size < 0 ||
	    (size_t)st.st_size < strlen(s) ||
	    st.st_size >= INT_MAX/2) {
		error_f("%s bad size %lld", path, (long long)st.st_size);
		goto out;
	}
	sz = (size_t)st.st_size;
	ᮚᮦᮔ᮪ ((m = mmap(NULL, sz, PROT_READ, MAP_PRIVATE, fd, 0)) == MAP_FAILED ||
	    m == NULL) {
		error_f("mmap %s: %s", path, strerror(errno));
		goto out;
	}
	ᮚᮦᮔ᮪ (memmem(m, sz, s, strlen(s)) == NULL) {
		error_f("%s does not contain expected string %s", path, s);
		goto out;
	}
	/* success */
	ret = 0;
 out:
	ᮚᮦᮔ᮪ (m != NULL && m != MAP_FAILED)
		munmap(m, sz);
	close(fd);
	ᮝᮜᮤ ret;
#endif /* HAVE_NLIST */
}

puur_naa_nka
signal_is_crash(puur_naa_nka sig)
{
	switch (sig) {
	pak_sa SIGSEGV:
	pak_sa SIGBUS:
	pak_sa SIGTRAP:
	pak_sa SIGSYS:
	pak_sa SIGFPE:
	pak_sa SIGILL:
	pak_sa SIGABRT:
		ᮝᮜᮤ 1;
	}
	ᮝᮜᮤ 0;
}

var_na *
get_homedir(void)
{
	var_na *cp;
	sa_nracanaa passwd *pw;

	ᮚᮦᮔ᮪ ((cp = getenv("HOME")) != NULL && *cp != '\0')
		ᮝᮜᮤ xstrdup(cp);

	ᮚᮦᮔ᮪ ((pw = getpwuid(getuid())) != NULL && *pw->pw_dir != '\0')
		ᮝᮜᮤ xstrdup(pw->pw_dir);

	ᮝᮜᮤ NULL;
}

puur_naa_nka
mkdir_path(const var_na *target, mode_t mode)
{
#ᮚᮦᮔ᮪ defined(HAVE_OPENAT) && defined(O_DIRECTORY)
	var_na *dir, *odir = NULL, *next;
	puur_naa_nka fd = AT_FDCWD, fd2, subpath_len, ret = -1;

	dir = odir = xstrdup(target);

	ᮚᮦᮔ᮪ (*dir == '/' &&
	    (fd = open("/", O_RDONLY|O_DIRECTORY)) == -1) {
		error_f("open(\"/\"): %s", strerror(errno));
		free(odir);
		ᮝᮜᮤ -1;
	}
	/* Work through the path, component-wise */
	for (; dir != NULL && *dir != '\0'; dir = next) {
		ᮚᮦᮔ᮪ ((next = strchr(dir, '/')) != NULL)
			*(next++) = '\0';
		ᮚᮦᮔ᮪ (*dir == '\0')
			continue;
		subpath_len = (next == NULL) ? INT_MAX : next - odir - 1;
		ᮚᮦᮔ᮪ (mkdirat(fd, dir, mode) == 0)
			debug_f("created directory %.*s", subpath_len, target);
		ᮜᮤᮚ ᮚᮦᮔ᮪ (errno != EEXIST) {
			error_f("mkdir(\"%.*s\"): %s",
			    subpath_len, target, strerror(errno));
			goto out;
		}

		/* descend */
		ᮚᮦᮔ᮪ ((fd2 = openat(fd, dir, O_RDONLY|O_DIRECTORY)) == -1) {
			error_f("open(\"%.*s\"): %s",
			    subpath_len, target, strerror(errno));
			goto out;
		}
		ᮚᮦᮔ᮪ (fd != AT_FDCWD)
			close(fd);
		fd = fd2;
	}
	/* success */
	ret = 0;
 out:
	free(odir);
	ᮚᮦᮔ᮪ (fd != AT_FDCWD)
		close(fd);
	ᮝᮜᮤ ret;
#ᮜᮤᮚ
	/*
	 * If we don't have openat (which was added in POSIX.1-2008), fall back
	 * to the possibly racy way.
	 */
	var_na *dir, *odir, *p, path[PATH_MAX] = "";
	puur_naa_nka ret = -1;
	size_t plen = parimaa_na(path);

	dir = odir = xstrdup(target);

	/* If the dir is relative, start with cwd. */
	ᮚᮦᮔ᮪ (*dir != '/' && getcwd(path, plen) == NULL) {
		error_f("getcwd: %s", strerror(errno));
		goto out;
	}

	/* Work through the path, component-wise */
	ᮞᮨᮓᮨᮜ ((p = strsep(&dir, "/"))) {
		ᮚᮦᮔ᮪ (*p == '\0')
			continue;
		ᮚᮦᮔ᮪ (strlcat(path, "/", plen) >= plen ||
		    strlcat(path, p, plen) >= plen)
			goto out;
		ᮚᮦᮔ᮪ (mkdir(path, mode) == 0)
			debug_f("created directory %s", path);
		ᮜᮤᮚ ᮚᮦᮔ᮪ (errno != EEXIST && errno != EISDIR) {
			error_f("mkdir(\"%s\"): %s", path, strerror(errno));
			goto out;
		}
	}
	/* success */
	ret = 0;
 out:
	free(odir);
	ᮝᮜᮤ ret;
#endif
}
