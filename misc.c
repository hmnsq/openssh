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


#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/ioctl.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/mman.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/socket.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/stat.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/time.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/wait.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/un.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <limits.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <libgen.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <poll.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <nlist.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <signal.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <time.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <netinet/in.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <netinet/ip.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <netinet/tcp.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <arpa/inet.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <ctype.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <fcntl.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <netdb.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <paths.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <pwd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <grp.h>
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ SSH_TUN_OPENBSD
#ਅਨ੍ਤਰ੍ਭਾਵ <net/if.h>
#ਜੇ_ਅੰਤ

#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "platform.h"

/* remove newline at end of string */
ਅੱਖਰ *
chop(ਅੱਖਰ *s)
{
	ਅੱਖਰ *t = s;
	ਜਦੋਂ (*t) {
		ਜੇ (*t == '\n' || *t == '\r') {
			*t = '\0';
			ਵਾਪਸ s;
		}
		t++;
	}
	ਵਾਪਸ s;

}

/* remove whitespace from end of string */
ਖਾਲੀ
rtrim(ਅੱਖਰ *s)
{
	ਮਾਪ_t i;

	ਜੇ ((i = ਲੜੀ_ਲੰਬਾਈ(s)) == 0)
		ਵਾਪਸ;
	ਕਰੋ {
		i--;
		ਜੇ (ਖਾਲੀ_ਥਾਂ_ਹੈ((ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ)s[i]))
			s[i] = '\0';
		ਨਹੀਂਤਾਂ
			ਰੋਕੋ;
	} ਜਦੋਂ (i > 0);
}

/*
 * returns pointer to character after 'prefix' in 's' or otherwise NULL
 * if the prefix is not present.
 */
ਅਚਲ ਅੱਖਰ *
strprefix(ਅਚਲ ਅੱਖਰ *s, ਅਚਲ ਅੱਖਰ *ਅਗੇਤਰ, ਪੂਰਨ ignorecase)
{
	ਮਾਪ_t prefixlen;

	ਜੇ ((prefixlen = ਲੜੀ_ਲੰਬਾਈ(ਅਗੇਤਰ)) == 0)
		ਵਾਪਸ s;
	ਜੇ (ignorecase) {
		ਜੇ (strncasecmp(s, ਅਗੇਤਰ, prefixlen) != 0)
			ਵਾਪਸ ਨਿਰਾ;
	} ਨਹੀਂਤਾਂ {
		ਜੇ (ਲੜੀ_ਤੁਲਨਾ(s, ਅਗੇਤਰ, prefixlen) != 0)
			ਵਾਪਸ ਨਿਰਾ;
	}
	ਵਾਪਸ s + prefixlen;
}

/* Append string 's' to a NULL-terminated array of strings */
ਖਾਲੀ
stringlist_append(ਅੱਖਰ ***listp, ਅਚਲ ਅੱਖਰ *s)
{
	ਮਾਪ_t i = 0;

	ਜੇ (*listp == ਨਿਰਾ)
		*listp = xcalloc(2, ਆਕਾਰ(**listp));
	ਨਹੀਂਤਾਂ {
		ਲਈ (i = 0; (*listp)[i] != ਨਿਰਾ; i++)
			; /* count */
		*listp = xrecallocarray(*listp, i + 1, i + 2, ਆਕਾਰ(**listp));
	}
	(*listp)[i] = xstrdup(s);
}

ਖਾਲੀ
stringlist_free(ਅੱਖਰ **list)
{
	ਮਾਪ_t i = 0;

	ਜੇ (list == ਨਿਰਾ)
		ਵਾਪਸ;
	ਲਈ (i = 0; list[i] != ਨਿਰਾ; i++)
		ਮੁਕਤ(list[i]);
	ਮੁਕਤ(list);
}

/* set/unset filedescriptor to non-blocking */
ਪੂਰਨ
ਸੈੱਟ_nonblock(ਪੂਰਨ fd)
{
	ਪੂਰਨ val;

	val = fcntl(fd, F_GETFL);
	ਜੇ (val == -1) {
		error("fcntl(%d, F_GETFL): %s", fd, strerror(errno));
		ਵਾਪਸ (-1);
	}
	ਜੇ (val & O_NONBLOCK) {
		debug3("fd %d is O_NONBLOCK", fd);
		ਵਾਪਸ (0);
	}
	debug2("fd %d setting O_NONBLOCK", fd);
	val |= O_NONBLOCK;
	ਜੇ (fcntl(fd, F_SETFL, val) == -1) {
		debug("fcntl(%d, F_SETFL, O_NONBLOCK): %s", fd,
		    strerror(errno));
		ਵਾਪਸ (-1);
	}
	ਵਾਪਸ (0);
}

ਪੂਰਨ
unset_nonblock(ਪੂਰਨ fd)
{
	ਪੂਰਨ val;

	val = fcntl(fd, F_GETFL);
	ਜੇ (val == -1) {
		error("fcntl(%d, F_GETFL): %s", fd, strerror(errno));
		ਵਾਪਸ (-1);
	}
	ਜੇ (!(val & O_NONBLOCK)) {
		debug3("fd %d is not O_NONBLOCK", fd);
		ਵਾਪਸ (0);
	}
	debug("fd %d clearing O_NONBLOCK", fd);
	val &= ~O_NONBLOCK;
	ਜੇ (fcntl(fd, F_SETFL, val) == -1) {
		debug("fcntl(%d, F_SETFL, ~O_NONBLOCK): %s",
		    fd, strerror(errno));
		ਵਾਪਸ (-1);
	}
	ਵਾਪਸ (0);
}

ਅਚਲ ਅੱਖਰ *
ssh_gai_strerror(ਪੂਰਨ gaierr)
{
	ਜੇ (gaierr == EAI_SYSTEM && errno != 0)
		ਵਾਪਸ strerror(errno);
	ਵਾਪਸ gai_strerror(gaierr);
}

/* disable nagle on socket */
ਖਾਲੀ
ਸੈੱਟ_nodelay(ਪੂਰਨ fd)
{
	ਪੂਰਨ opt;
	socklen_t optlen;

	optlen = ਆਕਾਰ opt;
	ਜੇ (getsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, &optlen) == -1) {
		debug("getsockopt TCP_NODELAY: %.100s", strerror(errno));
		ਵਾਪਸ;
	}
	ਜੇ (opt == 1) {
		debug2("fd %d is TCP_NODELAY", fd);
		ਵਾਪਸ;
	}
	opt = 1;
	debug2("fd %d setting TCP_NODELAY", fd);
	ਜੇ (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, ਆਕਾਰ opt) == -1)
		error("setsockopt TCP_NODELAY: %.100s", strerror(errno));
}

/* Allow local port reuse in TIME_WAIT */
ਪੂਰਨ
ਸੈੱਟ_reuseaddr(ਪੂਰਨ fd)
{
	ਪੂਰਨ on = 1;

	ਜੇ (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, ਆਕਾਰ(on)) == -1) {
		error("setsockopt SO_REUSEADDR fd %d: %s", fd, strerror(errno));
		ਵਾਪਸ -1;
	}
	ਵਾਪਸ 0;
}

/* Set TCP keepalives */
ਪੂਰਨ
ਸੈੱਟ_keepalive(ਪੂਰਨ fd)
{
	ਪੂਰਨ on = 1;

	ਜੇ (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, ਆਕਾਰ(on)) == -1) {
		error("setsockopt SO_KEEPALIVE fd %d: %s", fd, strerror(errno));
		ਵਾਪਸ -1;
	}
	ਵਾਪਸ 0;
}

/* Get/set routing domain */
ਅੱਖਰ *
get_rdomain(ਪੂਰਨ fd)
{
#ਜੇ defined(HAVE_SYS_GET_RDOMAIN)
	ਵਾਪਸ sys_get_rdomain(fd);
#ਜਾਂਜੇ defined(__OpenBSD__)
	ਪੂਰਨ rtable;
	ਅੱਖਰ *ret;
	socklen_t len = ਆਕਾਰ(rtable);

	ਜੇ (getsockopt(fd, SOL_SOCKET, SO_RTABLE, &rtable, &len) == -1) {
		error("Failed to get routing domain for fd %d: %s",
		    fd, strerror(errno));
		ਵਾਪਸ ਨਿਰਾ;
	}
	xasprintf(&ret, "%d", rtable);
	ਵਾਪਸ ret;
#ਨਹੀਂਤਾਂ /* defined(__OpenBSD__) */
	ਵਾਪਸ ਨਿਰਾ;
#ਜੇ_ਅੰਤ
}

ਪੂਰਨ
ਸੈੱਟ_rdomain(ਪੂਰਨ fd, ਅਚਲ ਅੱਖਰ *name)
{
#ਜੇ defined(HAVE_SYS_ਸੈੱਟ_RDOMAIN)
	ਵਾਪਸ sys_ਸੈੱਟ_rdomain(fd, name);
#ਜਾਂਜੇ defined(__OpenBSD__)
	ਪੂਰਨ rtable;
	ਅਚਲ ਅੱਖਰ *errstr;

	ਜੇ (name == ਨਿਰਾ)
		ਵਾਪਸ 0; /* default table */

	rtable = (ਪੂਰਨ)strtonum(name, 0, 255, &errstr);
	ਜੇ (errstr != ਨਿਰਾ) {
		/* Shouldn't happen */
		error("Invalid routing domain \"%s\": %s", name, errstr);
		ਵਾਪਸ -1;
	}
	ਜੇ (setsockopt(fd, SOL_SOCKET, SO_RTABLE,
	    &rtable, ਆਕਾਰ(rtable)) == -1) {
		error("Failed to set routing domain %d on fd %d: %s",
		    rtable, fd, strerror(errno));
		ਵਾਪਸ -1;
	}
	ਵਾਪਸ 0;
#ਨਹੀਂਤਾਂ /* defined(__OpenBSD__) */
	error("Setting routing domain is not supported on this platform");
	ਵਾਪਸ -1;
#ਜੇ_ਅੰਤ
}

ਪੂਰਨ
get_sock_af(ਪੂਰਨ fd)
{
	ਬਣਤਰ sockaddr_storage ਮੰਜ਼ਿਲ;
	socklen_t tolen = ਆਕਾਰ(ਮੰਜ਼ਿਲ);

	memset(&ਮੰਜ਼ਿਲ, 0, ਆਕਾਰ(ਮੰਜ਼ਿਲ));
	ਜੇ (getsockname(fd, (ਬਣਤਰ sockaddr *)&ਮੰਜ਼ਿਲ, &tolen) == -1)
		ਵਾਪਸ -1;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ IPV4_ਵਿੱਚ_IPV6
	ਜੇ (ਮੰਜ਼ਿਲ.ss_family == AF_INET6 &&
	    IN6_IS_ADDR_V4MAPPED(&((ਬਣਤਰ sockaddr_in6 *)&ਮੰਜ਼ਿਲ)->sin6_addr))
		ਵਾਪਸ AF_INET;
#ਜੇ_ਅੰਤ
	ਵਾਪਸ ਮੰਜ਼ਿਲ.ss_family;
}

ਖਾਲੀ
ਸੈੱਟ_sock_tos(ਪੂਰਨ fd, ਪੂਰਨ tos)
{
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ IP_TOS_IS_BROKEN
	ਪੂਰਨ af;

	ਜੇ (tos < 0 || tos == ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ) {
		debug_f("invalid TOS %d", tos);
		ਵਾਪਸ;
	}
	ਚੋਣ ((af = get_sock_af(fd))) {
	ਹਾਲਤ -1:
		/* assume not a socket */
		ਰੋਕੋ;
	ਹਾਲਤ AF_INET:
# ifdef IP_TOS
		debug3_f("set socket %d IP_TOS 0x%02x", fd, tos);
		ਜੇ (setsockopt(fd, IPPROTO_IP, IP_TOS,
		    &tos, ਆਕਾਰ(tos)) == -1) {
			error("setsockopt socket %d IP_TOS %d: %s",
			    fd, tos, strerror(errno));
		}
# endif /* IP_TOS */
		ਰੋਕੋ;
	ਹਾਲਤ AF_INET6:
# ifdef IPV6_TCLASS
		debug3_f("set socket %d IPV6_TCLASS 0x%02x", fd, tos);
		ਜੇ (setsockopt(fd, IPPROTO_IPV6, IPV6_TCLASS,
		    &tos, ਆਕਾਰ(tos)) == -1) {
			error("setsockopt socket %d IPV6_TCLASS %d: %s",
			    fd, tos, strerror(errno));
		}
# endif /* IPV6_TCLASS */
		ਰੋਕੋ;
	ਮੂਲ:
		debug2_f("unsupported socket family %d", af);
		ਰੋਕੋ;
	}
#ਜੇ_ਅੰਤ /* IP_TOS_IS_BROKEN */
}

/*
 * Wait up to *timeoutp milliseconds for events on fd. Updates
 * *timeoutp with time remaining.
 * Returns 0 if fd ready or -1 on timeout or error (see errno).
 */
ਸਥਿਰ ਪੂਰਨ
waitfd(ਪੂਰਨ fd, ਪੂਰਨ *timeoutp, ਛੋਟਾ events, ਅਸਥਿਰ sig_atomic_t *stop)
{
	ਬਣਤਰ pollfd pfd;
	ਬਣਤਰ timespec timeout;
	ਪੂਰਨ oerrno, r;
	sigset_t nsigset, osigset;

	ਜੇ (timeoutp && *timeoutp == -1)
		timeoutp = ਨਿਰਾ;
	pfd.fd = fd;
	pfd.events = events;
	ptimeout_init(&timeout);
	ਜੇ (timeoutp != ਨਿਰਾ)
		ptimeout_deadline_ms(&timeout, *timeoutp);
	ਜੇ (stop != ਨਿਰਾ)
		sigfillset(&nsigset);
	ਲਈ (; timeoutp == ਨਿਰਾ || *timeoutp >= 0;) {
		ਜੇ (stop != ਨਿਰਾ) {
			sigprocmask(SIG_BLOCK, &nsigset, &osigset);
			ਜੇ (*stop) {
				sigprocmask(SIG_SETMASK, &osigset, ਨਿਰਾ);
				errno = EINTR;
				ਵਾਪਸ -1;
			}
		}
		r = ppoll(&pfd, 1, ptimeout_get_tsp(&timeout),
		    stop != ਨਿਰਾ ? &osigset : ਨਿਰਾ);
		oerrno = errno;
		ਜੇ (stop != ਨਿਰਾ)
			sigprocmask(SIG_SETMASK, &osigset, ਨਿਰਾ);
		ਜੇ (timeoutp)
			*timeoutp = ptimeout_get_ms(&timeout);
		errno = oerrno;
		ਜੇ (r > 0)
			ਵਾਪਸ 0;
		ਨਹੀਂਤਾਂ ਜੇ (r == -1 && errno != EAGAIN && errno != EINTR)
			ਵਾਪਸ -1;
		ਨਹੀਂਤਾਂ ਜੇ (r == 0)
			ਰੋਕੋ;
	}
	/* timeout */
	errno = ETIMEDOUT;
	ਵਾਪਸ -1;
}

/*
 * Wait up to *timeoutp milliseconds for fd to be readable. Updates
 * *timeoutp with time remaining.
 * Returns 0 if fd ready or -1 on timeout or error (see errno).
 */
ਪੂਰਨ
waitrfd(ਪੂਰਨ fd, ਪੂਰਨ *timeoutp, ਅਸਥਿਰ sig_atomic_t *stop) {
	ਵਾਪਸ waitfd(fd, timeoutp, POLLIN, stop);
}

/*
 * Attempt a non-blocking connect(2) to the specified address, waiting up to
 * *timeoutp milliseconds for the connection to complete. If the timeout is
 * <=0, then wait indefinitely.
 *
 * Returns 0 on success or -1 on failure.
 */
ਪੂਰਨ
timeout_connect(ਪੂਰਨ sockfd, ਅਚਲ ਬਣਤਰ sockaddr *serv_addr,
    socklen_t addrlen, ਪੂਰਨ *timeoutp)
{
	ਪੂਰਨ optval = 0;
	socklen_t optlen = ਆਕਾਰ(optval);

	/* No timeout: just do a blocking connect() */
	ਜੇ (timeoutp == ਨਿਰਾ || *timeoutp <= 0)
		ਵਾਪਸ connect(sockfd, serv_addr, addrlen);

	ਸੈੱਟ_nonblock(sockfd);
	ਲਈ (;;) {
		ਜੇ (connect(sockfd, serv_addr, addrlen) == 0) {
			/* Succeeded already? */
			unset_nonblock(sockfd);
			ਵਾਪਸ 0;
		} ਨਹੀਂਤਾਂ ਜੇ (errno == EINTR)
			ਜਾਰੀ;
		ਨਹੀਂਤਾਂ ਜੇ (errno != EINPROGRESS)
			ਵਾਪਸ -1;
		ਰੋਕੋ;
	}

	ਜੇ (waitfd(sockfd, timeoutp, POLLIN | POLLOUT, ਨਿਰਾ) == -1)
		ਵਾਪਸ -1;

	/* Completed or failed */
	ਜੇ (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &optval, &optlen) == -1) {
		debug("getsockopt: %s", strerror(errno));
		ਵਾਪਸ -1;
	}
	ਜੇ (optval != 0) {
		errno = optval;
		ਵਾਪਸ -1;
	}
	unset_nonblock(sockfd);
	ਵਾਪਸ 0;
}

/* Characters considered whitespace in strsep calls. */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ WHITESPACE " \t\r\n"
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ QUOTE	"\""

/* return next token in configuration line */
ਸਥਿਰ ਅੱਖਰ *
strdelim_ਅੰਦਰੂਨੀ(ਅੱਖਰ **s, ਪੂਰਨ ਵੰਡੋ_equals)
{
	ਅੱਖਰ *old;
	ਪੂਰਨ wspace = 0;

	ਜੇ (*s == ਨਿਰਾ)
		ਵਾਪਸ ਨਿਰਾ;

	old = *s;

	*s = strpbrk(*s,
	    ਵੰਡੋ_equals ? WHITESPACE QUOTE "=" : WHITESPACE QUOTE);
	ਜੇ (*s == ਨਿਰਾ)
		ਵਾਪਸ (old);

	ਜੇ (*s[0] == '\"') {
		memmove(*s, *s + 1, ਲੜੀ_ਲੰਬਾਈ(*s)); /* move nul too */
		/* Find matching quote */
		ਜੇ ((*s = strpbrk(*s, QUOTE)) == ਨਿਰਾ) {
			ਵਾਪਸ (ਨਿਰਾ);		/* no matching quote */
		} ਨਹੀਂਤਾਂ {
			*s[0] = '\0';
			*s += strspn(*s + 1, WHITESPACE) + 1;
			ਵਾਪਸ (old);
		}
	}

	/* Allow only one '=' to be skipped */
	ਜੇ (ਵੰਡੋ_equals && *s[0] == '=')
		wspace = 1;
	*s[0] = '\0';

	/* Skip any extra whitespace after first token */
	*s += strspn(*s + 1, WHITESPACE) + 1;
	ਜੇ (ਵੰਡੋ_equals && *s[0] == '=' && !wspace)
		*s += strspn(*s + 1, WHITESPACE) + 1;

	ਵਾਪਸ (old);
}

/*
 * Return next token in configuration line; splits on whitespace or a
 * single '=' character.
 */
ਅੱਖਰ *
strdelim(ਅੱਖਰ **s)
{
	ਵਾਪਸ strdelim_ਅੰਦਰੂਨੀ(s, 1);
}

/*
 * Return next token in configuration line; splits on whitespace only.
 */
ਅੱਖਰ *
strdelimw(ਅੱਖਰ **s)
{
	ਵਾਪਸ strdelim_ਅੰਦਰੂਨੀ(s, 0);
}

ਬਣਤਰ passwd *
pwcopy(ਬਣਤਰ passwd *pw)
{
	ਬਣਤਰ passwd *copy = xcalloc(1, ਆਕਾਰ(*copy));

	copy->pw_name = xstrdup(pw->pw_name);
	copy->pw_passwd = xstrdup(pw->pw_passwd == ਨਿਰਾ ? "*" : pw->pw_passwd);
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_STRUCT_PASSWD_PW_GECOS
	copy->pw_gecos = xstrdup(pw->pw_gecos == ਨਿਰਾ ? "" : pw->pw_gecos);
#ਜੇ_ਅੰਤ
	copy->pw_uid = pw->pw_uid;
	copy->pw_gid = pw->pw_gid;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_STRUCT_PASSWD_PW_EXPIRE
	copy->pw_expire = pw->pw_expire;
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_STRUCT_PASSWD_PW_CHANGE
	copy->pw_change = pw->pw_change;
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_STRUCT_PASSWD_PW_CLASS
	copy->pw_class = xstrdup(pw->pw_class == ਨਿਰਾ ? "" : pw->pw_class);
#ਜੇ_ਅੰਤ
	copy->pw_dir = xstrdup(pw->pw_dir == ਨਿਰਾ ? "" : pw->pw_dir);
	copy->pw_shell = xstrdup(pw->pw_shell == ਨਿਰਾ ? "" : pw->pw_shell);
	ਵਾਪਸ copy;
}

ਖਾਲੀ
pwfree(ਬਣਤਰ passwd *pw)
{
	ਜੇ (pw == ਨਿਰਾ)
		ਵਾਪਸ;
	ਮੁਕਤ(pw->pw_name);
	freezero(pw->pw_passwd,
	    pw->pw_passwd == ਨਿਰਾ ? 0 : ਲੜੀ_ਲੰਬਾਈ(pw->pw_passwd));
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_STRUCT_PASSWD_PW_GECOS
	ਮੁਕਤ(pw->pw_gecos);
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_STRUCT_PASSWD_PW_CLASS
	ਮੁਕਤ(pw->pw_class);
#ਜੇ_ਅੰਤ
	ਮੁਕਤ(pw->pw_dir);
	ਮੁਕਤ(pw->pw_shell);
	freezero(pw, ਆਕਾਰ(*pw));
}

/*
 * Convert ASCII string to TCP/IP port number.
 * Port must be >=0 and <=65535.
 * Return -1 if invalid.
 */
ਪੂਰਨ
a2port(ਅਚਲ ਅੱਖਰ *s)
{
	ਬਣਤਰ servent *se;
	ਲੰਮਾ ਲੰਮਾ ਪੋਰਟ;
	ਅਚਲ ਅੱਖਰ *errstr;

	ਪੋਰਟ = strtonum(s, 0, 65535, &errstr);
	ਜੇ (errstr == ਨਿਰਾ)
		ਵਾਪਸ (ਪੂਰਨ)ਪੋਰਟ;
	ਜੇ ((se = getservbyname(s, "tcp")) != ਨਿਰਾ)
		ਵਾਪਸ ntohs(se->s_port);
	ਵਾਪਸ -1;
}

ਪੂਰਨ
a2tun(ਅਚਲ ਅੱਖਰ *s, ਪੂਰਨ *remote)
{
	ਅਚਲ ਅੱਖਰ *errstr = ਨਿਰਾ;
	ਅੱਖਰ *sp, *ep;
	ਪੂਰਨ tun;

	ਜੇ (remote != ਨਿਰਾ) {
		*remote = SSH_TUNID_ANY;
		sp = xstrdup(s);
		ਜੇ ((ep = strchr(sp, ':')) == ਨਿਰਾ) {
			ਮੁਕਤ(sp);
			ਵਾਪਸ (a2tun(s, ਨਿਰਾ));
		}
		ep[0] = '\0'; ep++;
		*remote = a2tun(ep, ਨਿਰਾ);
		tun = a2tun(sp, ਨਿਰਾ);
		ਮੁਕਤ(sp);
		ਵਾਪਸ (*remote == SSH_TUNID_ERR ? *remote : tun);
	}

	ਜੇ (strcasecmp(s, "any") == 0)
		ਵਾਪਸ (SSH_TUNID_ANY);

	tun = strtonum(s, 0, SSH_TUNID_MAX, &errstr);
	ਜੇ (errstr != ਨਿਰਾ)
		ਵਾਪਸ (SSH_TUNID_ERR);

	ਵਾਪਸ (tun);
}

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SECONDS		1.0
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MINUTES		(SECONDS * 60)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ HOURS		(MINUTES * 60)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ DAYS		(HOURS * 24)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ WEEKS		(DAYS * 7)

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
ਦੁੱਗਣਾ
convtime_double(ਅਚਲ ਅੱਖਰ *s)
{
	ਦੁੱਗਣਾ val, ਕੁੱਲ_sec = 0.0, multiplier;
	ਅਚਲ ਅੱਖਰ *p, *ਸ਼ੁਰੂ_p;
	ਅੱਖਰ *endp;
	ਪੂਰਨ ਵੇਖਿਆ_seconds = 0;

	ਜੇ (s == ਨਿਰਾ || *s == '\0')
		ਵਾਪਸ -1.0;

	ਲਈ (p = s; *p != '\0';) {
		ਜੇ (!ਅੰਕ_ਹੈ((ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ)*p) && *p != '.')
			ਵਾਪਸ -1.0;

		errno = 0;
		ਜੇ ((val = strtod(p, &endp)) < 0 || errno != 0 || p == endp)
			ਵਾਪਸ -1.0;
		/* Allow only decimal forms */
		ਜੇ (p + strspn(p, "0123456789.") != endp)
			ਵਾਪਸ -1.0;
		ਸ਼ੁਰੂ_p = p;
		p = endp;

		ਚੋਣ (*p) {
		ਹਾਲਤ '\0':
			/* FALLTHROUGH */
		ਹਾਲਤ 's':
		ਹਾਲਤ 'S':
			ਜੇ (ਵੇਖਿਆ_seconds++)
				ਵਾਪਸ -1.0;
			multiplier = SECONDS;
			ਰੋਕੋ;
		ਹਾਲਤ 'm':
		ਹਾਲਤ 'M':
			multiplier = MINUTES;
			ਰੋਕੋ;
		ਹਾਲਤ 'h':
		ਹਾਲਤ 'H':
			multiplier = HOURS;
			ਰੋਕੋ;
		ਹਾਲਤ 'd':
		ਹਾਲਤ 'D':
			multiplier = DAYS;
			ਰੋਕੋ;
		ਹਾਲਤ 'w':
		ਹਾਲਤ 'W':
			multiplier = WEEKS;
			ਰੋਕੋ;
		ਮੂਲ:
			ਵਾਪਸ -1.0;
		}

		/* Special handling if this was a decimal */
		ਜੇ (memchr(ਸ਼ੁਰੂ_p, '.', endp - ਸ਼ੁਰੂ_p) != ਨਿਰਾ) {
			/* Decimal point present */
			ਜੇ (multiplier > 1.0)
				ਵਾਪਸ -1.0; /* No fractionals for non-seconds */
			/* For seconds, ensure digits follow */
			ਜੇ (!ਅੰਕ_ਹੈ((ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ)*(endp - 1)))
				ਵਾਪਸ -1.0;
		}

		ਕੁੱਲ_sec += val * multiplier;

		ਜੇ (*p != '\0')
			p++;
	}
	ਵਾਪਸ ਕੁੱਲ_sec;
}

/*
 * Same as convtime_double() above but fractional seconds are ignored.
 * Return -1 if time string is invalid.
 */
ਪੂਰਨ
convtime(ਅਚਲ ਅੱਖਰ *s)
{
	ਦੁੱਗਣਾ sec_val;

	ਜੇ ((sec_val = convtime_double(s)) < 0.0)
		ਵਾਪਸ -1;

	/* Check for overflow into int */
	ਜੇ (sec_val < 0 || sec_val > ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ)
		ਵਾਪਸ -1;

	ਵਾਪਸ (ਪੂਰਨ)sec_val;
}

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ TF_BUFS	8
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ TF_LEN	9

ਅਚਲ ਅੱਖਰ *
fmt_timeframe(time_t t)
{
	ਅੱਖਰ		*buf;
	ਸਥਿਰ ਅੱਖਰ	 tfbuf[TF_BUFS][TF_LEN];	/* ring buffer */
	ਸਥਿਰ ਪੂਰਨ	 idx = 0;
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ	 sec, min, hrs, day;
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ	week;

	buf = tfbuf[idx++];
	ਜੇ (idx == TF_BUFS)
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

	ਜੇ (week > 0)
		snprintf(buf, TF_LEN, "%02lluw%01ud%02uh", week, day, hrs);
	ਨਹੀਂਤਾਂ ਜੇ (day > 0)
		snprintf(buf, TF_LEN, "%01ud%02uh%02um", day, hrs, min);
	ਨਹੀਂਤਾਂ
		snprintf(buf, TF_LEN, "%02u:%02u:%02u", hrs, min, sec);

	ਵਾਪਸ (buf);
}

/*
 * Returns a standardized host+port identifier string.
 * Caller must free returned string.
 */
ਅੱਖਰ *
put_host_ਪੋਰਟ(ਅਚਲ ਅੱਖਰ *host, u_short ਪੋਰਟ)
{
	ਅੱਖਰ *hoststr;

	ਜੇ (ਪੋਰਟ == 0 || ਪੋਰਟ == SSH_DEFAULT_ਪੋਰਟ)
		ਵਾਪਸ(xstrdup(host));
	ਜੇ (asprintf(&hoststr, "[%s]:%d", host, (ਪੂਰਨ)ਪੋਰਟ) == -1)
		fatal("put_host_port: asprintf: %s", strerror(errno));
	debug3("put_host_port: %s", hoststr);
	ਵਾਪਸ hoststr;
}

/*
 * Search for next delimiter between hostnames/addresses and ports.
 * Argument may be modified (for termination).
 * Returns *cp if parsing succeeds.
 * *cp is set to the start of the next field, if one was found.
 * The delimiter char, if present, is stored in delim.
 * If this is the last field, *cp is set to NULL.
 */
ਅੱਖਰ *
hpdelim2(ਅੱਖਰ **cp, ਅੱਖਰ *delim)
{
	ਅੱਖਰ *s, *old;

	ਜੇ (cp == ਨਿਰਾ || *cp == ਨਿਰਾ)
		ਵਾਪਸ ਨਿਰਾ;

	old = s = *cp;
	ਜੇ (*s == '[') {
		ਜੇ ((s = strchr(s, ']')) == ਨਿਰਾ)
			ਵਾਪਸ ਨਿਰਾ;
		ਨਹੀਂਤਾਂ
			s++;
	} ਨਹੀਂਤਾਂ ਜੇ ((s = strpbrk(s, ":/")) == ਨਿਰਾ)
		s = *cp + ਲੜੀ_ਲੰਬਾਈ(*cp); /* skip to end (see first case below) */

	ਚੋਣ (*s) {
	ਹਾਲਤ '\0':
		*cp = ਨਿਰਾ;	/* no more fields*/
		ਰੋਕੋ;

	ਹਾਲਤ ':':
	ਹਾਲਤ '/':
		ਜੇ (delim != ਨਿਰਾ)
			*delim = *s;
		*s = '\0';	/* terminate */
		*cp = s + 1;
		ਰੋਕੋ;

	ਮੂਲ:
		ਵਾਪਸ ਨਿਰਾ;
	}

	ਵਾਪਸ old;
}

/* The common case: only accept colon as delimiter. */
ਅੱਖਰ *
hpdelim(ਅੱਖਰ **cp)
{
	ਅੱਖਰ *r, delim = '\0';

	r =  hpdelim2(cp, &delim);
	ਜੇ (delim == '/')
		ਵਾਪਸ ਨਿਰਾ;
	ਵਾਪਸ r;
}

ਅੱਖਰ *
cleanhostname(ਅੱਖਰ *host)
{
	ਜੇ (*host == '[' && host[ਲੜੀ_ਲੰਬਾਈ(host) - 1] == ']') {
		host[ਲੜੀ_ਲੰਬਾਈ(host) - 1] = '\0';
		ਵਾਪਸ (host + 1);
	} ਨਹੀਂਤਾਂ
		ਵਾਪਸ host;
}

ਅੱਖਰ *
colon(ਅੱਖਰ *cp)
{
	ਪੂਰਨ flag = 0;

	ਜੇ (*cp == ':')		/* Leading colon is part of file name. */
		ਵਾਪਸ ਨਿਰਾ;
	ਜੇ (*cp == '[')
		flag = 1;

	ਲਈ (; *cp; ++cp) {
		ਜੇ (*cp == '@' && *(cp+1) == '[')
			flag = 1;
		ਜੇ (*cp == ']' && *(cp+1) == ':' && flag)
			ਵਾਪਸ (cp+1);
		ਜੇ (*cp == ':' && !flag)
			ਵਾਪਸ (cp);
		ਜੇ (*cp == '/')
			ਵਾਪਸ ਨਿਰਾ;
	}
	ਵਾਪਸ ਨਿਰਾ;
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
ਪੂਰਨ
parse_user_host_ਰਸਤਾ(ਅਚਲ ਅੱਖਰ *s, ਅੱਖਰ **userp, ਅੱਖਰ **hostp, ਅੱਖਰ **pathp)
{
	ਅੱਖਰ *user = ਨਿਰਾ, *host = ਨਿਰਾ, *ਰਸਤਾ = ਨਿਰਾ;
	ਅੱਖਰ *sdup, *tmp;
	ਪੂਰਨ ret = -1;

	ਜੇ (userp != ਨਿਰਾ)
		*userp = ਨਿਰਾ;
	ਜੇ (hostp != ਨਿਰਾ)
		*hostp = ਨਿਰਾ;
	ਜੇ (pathp != ਨਿਰਾ)
		*pathp = ਨਿਰਾ;

	sdup = xstrdup(s);

	/* Check for remote syntax: [user@]host:[path] */
	ਜੇ ((tmp = colon(sdup)) == ਨਿਰਾ)
		ਜਾਓ ਬਾਹਰਲਾ;

	/* Extract optional path */
	*tmp++ = '\0';
	ਜੇ (*tmp == '\0')
		tmp = ".";
	ਰਸਤਾ = xstrdup(tmp);

	/* Extract optional user and mandatory host */
	tmp = strrchr(sdup, '@');
	ਜੇ (tmp != ਨਿਰਾ) {
		*tmp++ = '\0';
		host = xstrdup(cleanhostname(tmp));
		ਜੇ (*sdup != '\0')
			user = xstrdup(sdup);
	} ਨਹੀਂਤਾਂ {
		host = xstrdup(cleanhostname(sdup));
		user = ਨਿਰਾ;
	}

	/* Success */
	ਜੇ (userp != ਨਿਰਾ) {
		*userp = user;
		user = ਨਿਰਾ;
	}
	ਜੇ (hostp != ਨਿਰਾ) {
		*hostp = host;
		host = ਨਿਰਾ;
	}
	ਜੇ (pathp != ਨਿਰਾ) {
		*pathp = ਰਸਤਾ;
		ਰਸਤਾ = ਨਿਰਾ;
	}
	ret = 0;
ਬਾਹਰਲਾ:
	ਮੁਕਤ(sdup);
	ਮੁਕਤ(user);
	ਮੁਕਤ(host);
	ਮੁਕਤ(ਰਸਤਾ);
	ਵਾਪਸ ret;
}

/*
 * Parse a [user@]host[:port] string.
 * Caller must free returned user and host.
 * Any of the pointer return arguments may be NULL (useful for syntax checking).
 * If user was not specified then *userp will be set to NULL.
 * If port was not specified then *portp will be -1.
 * Returns 0 on success, -1 on failure.
 */
ਪੂਰਨ
parse_user_host_ਪੋਰਟ(ਅਚਲ ਅੱਖਰ *s, ਅੱਖਰ **userp, ਅੱਖਰ **hostp, ਪੂਰਨ *portp)
{
	ਅੱਖਰ *sdup, *cp, *tmp;
	ਅੱਖਰ *user = ਨਿਰਾ, *host = ਨਿਰਾ;
	ਪੂਰਨ ਪੋਰਟ = -1, ret = -1;

	ਜੇ (userp != ਨਿਰਾ)
		*userp = ਨਿਰਾ;
	ਜੇ (hostp != ਨਿਰਾ)
		*hostp = ਨਿਰਾ;
	ਜੇ (portp != ਨਿਰਾ)
		*portp = -1;

	ਜੇ ((sdup = tmp = strdup(s)) == ਨਿਰਾ)
		ਵਾਪਸ -1;
	/* Extract optional username */
	ਜੇ ((cp = strrchr(tmp, '@')) != ਨਿਰਾ) {
		*cp = '\0';
		ਜੇ (*tmp == '\0')
			ਜਾਓ ਬਾਹਰਲਾ;
		ਜੇ ((user = strdup(tmp)) == ਨਿਰਾ)
			ਜਾਓ ਬਾਹਰਲਾ;
		tmp = cp + 1;
	}
	/* Extract mandatory hostname */
	ਜੇ ((cp = hpdelim(&tmp)) == ਨਿਰਾ || *cp == '\0')
		ਜਾਓ ਬਾਹਰਲਾ;
	host = xstrdup(cleanhostname(cp));
	/* Convert and verify optional port */
	ਜੇ (tmp != ਨਿਰਾ && *tmp != '\0') {
		ਜੇ ((ਪੋਰਟ = a2port(tmp)) <= 0)
			ਜਾਓ ਬਾਹਰਲਾ;
	}
	/* Success */
	ਜੇ (userp != ਨਿਰਾ) {
		*userp = user;
		user = ਨਿਰਾ;
	}
	ਜੇ (hostp != ਨਿਰਾ) {
		*hostp = host;
		host = ਨਿਰਾ;
	}
	ਜੇ (portp != ਨਿਰਾ)
		*portp = ਪੋਰਟ;
	ret = 0;
 ਬਾਹਰਲਾ:
	ਮੁਕਤ(sdup);
	ਮੁਕਤ(user);
	ਮੁਕਤ(host);
	ਵਾਪਸ ret;
}

/*
 * Converts a two-byte hex string to decimal.
 * Returns the decimal value or -1 for invalid input.
 */
ਸਥਿਰ ਪੂਰਨ
hexchar(ਅਚਲ ਅੱਖਰ *s)
{
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ ਨਤੀਜਾ[2];
	ਪੂਰਨ i;

	ਲਈ (i = 0; i < 2; i++) {
		ਜੇ (s[i] >= '0' && s[i] <= '9')
			ਨਤੀਜਾ[i] = (ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ)(s[i] - '0');
		ਨਹੀਂਤਾਂ ਜੇ (s[i] >= 'a' && s[i] <= 'f')
			ਨਤੀਜਾ[i] = (ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ)(s[i] - 'a') + 10;
		ਨਹੀਂਤਾਂ ਜੇ (s[i] >= 'A' && s[i] <= 'F')
			ਨਤੀਜਾ[i] = (ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ)(s[i] - 'A') + 10;
		ਨਹੀਂਤਾਂ
			ਵਾਪਸ -1;
	}
	ਵਾਪਸ (ਨਤੀਜਾ[0] << 4) | ਨਤੀਜਾ[1];
}

/*
 * Decode an url-encoded string.
 * Returns a newly allocated string on success or NULL on failure.
 */
ਸਥਿਰ ਅੱਖਰ *
urldecode(ਅਚਲ ਅੱਖਰ *src)
{
	ਅੱਖਰ *ret, *dst;
	ਪੂਰਨ ch;
	ਮਾਪ_t srclen;

	ਜੇ ((srclen = ਲੜੀ_ਲੰਬਾਈ(src)) >= SIZE_MAX)
		ਵਾਪਸ ਨਿਰਾ;
	ret = xmalloc(srclen + 1);
	ਲਈ (dst = ret; *src != '\0'; src++) {
		ਚੋਣ (*src) {
		ਹਾਲਤ '+':
			*dst++ = ' ';
			ਰੋਕੋ;
		ਹਾਲਤ '%':
			/* note: don't allow \0 characters */
			ਜੇ (!isxdigit((ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ)src[1]) ||
			    !isxdigit((ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ)src[2]) ||
			    (ch = hexchar(src + 1)) == -1 || ch == 0) {
				ਮੁਕਤ(ret);
				ਵਾਪਸ ਨਿਰਾ;
			}
			*dst++ = ch;
			src += 2;
			ਰੋਕੋ;
		ਮੂਲ:
			*dst++ = *src;
			ਰੋਕੋ;
		}
	}
	*dst = '\0';

	ਵਾਪਸ ret;
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
ਪੂਰਨ
parse_uri(ਅਚਲ ਅੱਖਰ *scheme, ਅਚਲ ਅੱਖਰ *uri, ਅੱਖਰ **userp, ਅੱਖਰ **hostp,
    ਪੂਰਨ *portp, ਅੱਖਰ **pathp)
{
	ਅੱਖਰ *uridup, *cp, *tmp, ch;
	ਅੱਖਰ *user = ਨਿਰਾ, *host = ਨਿਰਾ, *ਰਸਤਾ = ਨਿਰਾ;
	ਪੂਰਨ ਪੋਰਟ = -1, ret = -1;
	ਮਾਪ_t len;

	len = ਲੜੀ_ਲੰਬਾਈ(scheme);
	ਜੇ (ਲੜੀ_ਤੁਲਨਾ(uri, scheme, len) != 0 || ਲੜੀ_ਤੁਲਨਾ(uri + len, "://", 3) != 0)
		ਵਾਪਸ 1;
	uri += len + 3;

	ਜੇ (userp != ਨਿਰਾ)
		*userp = ਨਿਰਾ;
	ਜੇ (hostp != ਨਿਰਾ)
		*hostp = ਨਿਰਾ;
	ਜੇ (portp != ਨਿਰਾ)
		*portp = -1;
	ਜੇ (pathp != ਨਿਰਾ)
		*pathp = ਨਿਰਾ;

	uridup = tmp = xstrdup(uri);

	/* Extract optional ssh-info (username + connection params) */
	ਜੇ ((cp = strchr(tmp, '@')) != ਨਿਰਾ) {
		ਅੱਖਰ *delim;

		*cp = '\0';
		/* Extract username and connection params */
		ਜੇ ((delim = strchr(tmp, ';')) != ਨਿਰਾ) {
			/* Just ignore connection params for now */
			*delim = '\0';
		}
		ਜੇ (*tmp == '\0') {
			/* Empty username */
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ ((user = urldecode(tmp)) == ਨਿਰਾ)
			ਜਾਓ ਬਾਹਰਲਾ;
		tmp = cp + 1;
	}

	/* Extract mandatory hostname */
	ਜੇ ((cp = hpdelim2(&tmp, &ch)) == ਨਿਰਾ || *cp == '\0')
		ਜਾਓ ਬਾਹਰਲਾ;
	host = xstrdup(cleanhostname(cp));
	ਜੇ (!valid_domain(host, 0, ਨਿਰਾ))
		ਜਾਓ ਬਾਹਰਲਾ;

	ਜੇ (tmp != ਨਿਰਾ && *tmp != '\0') {
		ਜੇ (ch == ':') {
			/* Convert and verify port. */
			ਜੇ ((cp = strchr(tmp, '/')) != ਨਿਰਾ)
				*cp = '\0';
			ਜੇ ((ਪੋਰਟ = a2port(tmp)) <= 0)
				ਜਾਓ ਬਾਹਰਲਾ;
			tmp = cp ? cp + 1 : ਨਿਰਾ;
		}
		ਜੇ (tmp != ਨਿਰਾ && *tmp != '\0') {
			/* Extract optional path */
			ਜੇ ((ਰਸਤਾ = urldecode(tmp)) == ਨਿਰਾ)
				ਜਾਓ ਬਾਹਰਲਾ;
		}
	}

	/* Success */
	ਜੇ (userp != ਨਿਰਾ) {
		*userp = user;
		user = ਨਿਰਾ;
	}
	ਜੇ (hostp != ਨਿਰਾ) {
		*hostp = host;
		host = ਨਿਰਾ;
	}
	ਜੇ (portp != ਨਿਰਾ)
		*portp = ਪੋਰਟ;
	ਜੇ (pathp != ਨਿਰਾ) {
		*pathp = ਰਸਤਾ;
		ਰਸਤਾ = ਨਿਰਾ;
	}
	ret = 0;
 ਬਾਹਰਲਾ:
	ਮੁਕਤ(uridup);
	ਮੁਕਤ(user);
	ਮੁਕਤ(host);
	ਮੁਕਤ(ਰਸਤਾ);
	ਵਾਪਸ ret;
}

/* function to assist building execv() arguments */
ਖਾਲੀ
addargs(arglist *ਦਲੀਲਾਂ, ਅੱਖਰ *fmt, ...)
{
	va_list ap;
	ਅੱਖਰ *cp;
	u_int nalloc;
	ਪੂਰਨ r;

	va_start(ap, fmt);
	r = vasprintf(&cp, fmt, ap);
	va_end(ap);
	ਜੇ (r == -1)
		fatal_f("argument too long");

	nalloc = ਦਲੀਲਾਂ->nalloc;
	ਜੇ (ਦਲੀਲਾਂ->list == ਨਿਰਾ) {
		nalloc = 32;
		ਦਲੀਲਾਂ->ਅੰਕ = 0;
	} ਨਹੀਂਤਾਂ ਜੇ (ਦਲੀਲਾਂ->ਅੰਕ > (256 * 1024))
		fatal_f("too many arguments");
	ਨਹੀਂਤਾਂ ਜੇ (ਦਲੀਲਾਂ->ਅੰਕ >= ਦਲੀਲਾਂ->nalloc)
		fatal_f("arglist corrupt");
	ਨਹੀਂਤਾਂ ਜੇ (ਦਲੀਲਾਂ->ਅੰਕ+2 >= nalloc)
		nalloc *= 2;

	ਦਲੀਲਾਂ->list = xrecallocarray(ਦਲੀਲਾਂ->list, ਦਲੀਲਾਂ->nalloc,
	    nalloc, ਆਕਾਰ(ਅੱਖਰ *));
	ਦਲੀਲਾਂ->nalloc = nalloc;
	ਦਲੀਲਾਂ->list[ਦਲੀਲਾਂ->ਅੰਕ++] = cp;
	ਦਲੀਲਾਂ->list[ਦਲੀਲਾਂ->ਅੰਕ] = ਨਿਰਾ;
}

ਖਾਲੀ
replacearg(arglist *ਦਲੀਲਾਂ, u_int which, ਅੱਖਰ *fmt, ...)
{
	va_list ap;
	ਅੱਖਰ *cp;
	ਪੂਰਨ r;

	va_start(ap, fmt);
	r = vasprintf(&cp, fmt, ap);
	va_end(ap);
	ਜੇ (r == -1)
		fatal_f("argument too long");
	ਜੇ (ਦਲੀਲਾਂ->list == ਨਿਰਾ || ਦਲੀਲਾਂ->ਅੰਕ >= ਦਲੀਲਾਂ->nalloc)
		fatal_f("arglist corrupt");

	ਜੇ (which >= ਦਲੀਲਾਂ->ਅੰਕ)
		fatal_f("tried to replace invalid arg %d >= %d",
		    which, ਦਲੀਲਾਂ->ਅੰਕ);
	ਮੁਕਤ(ਦਲੀਲਾਂ->list[which]);
	ਦਲੀਲਾਂ->list[which] = cp;
}

ਖਾਲੀ
freeargs(arglist *ਦਲੀਲਾਂ)
{
	u_int i;

	ਜੇ (ਦਲੀਲਾਂ == ਨਿਰਾ)
		ਵਾਪਸ;
	ਜੇ (ਦਲੀਲਾਂ->list != ਨਿਰਾ && ਦਲੀਲਾਂ->ਅੰਕ < ਦਲੀਲਾਂ->nalloc) {
		ਲਈ (i = 0; i < ਦਲੀਲਾਂ->ਅੰਕ; i++)
			ਮੁਕਤ(ਦਲੀਲਾਂ->list[i]);
		ਮੁਕਤ(ਦਲੀਲਾਂ->list);
	}
	ਦਲੀਲਾਂ->nalloc = ਦਲੀਲਾਂ->ਅੰਕ = 0;
	ਦਲੀਲਾਂ->list = ਨਿਰਾ;
}

/*
 * Expands tildes in the file name.  Returns data allocated by xmalloc.
 * Warning: this calls getpw*.
 */
ਪੂਰਨ
tilde_expand(ਅਚਲ ਅੱਖਰ *filename, uid_t uid, ਅੱਖਰ **retp)
{
	ਅੱਖਰ *ocopy = ਨਿਰਾ, *copy, *s = ਨਿਰਾ;
	ਅਚਲ ਅੱਖਰ *ਰਸਤਾ = ਨਿਰਾ, *user = ਨਿਰਾ;
	ਬਣਤਰ passwd *pw;
	ਮਾਪ_t len;
	ਪੂਰਨ ret = -1, r, slash;

	*retp = ਨਿਰਾ;
	ਜੇ (*filename != '~') {
		*retp = xstrdup(filename);
		ਵਾਪਸ 0;
	}
	ocopy = copy = xstrdup(filename + 1);

	ਜੇ (*copy == '\0')				/* ~ */
		ਰਸਤਾ = ਨਿਰਾ;
	ਨਹੀਂਤਾਂ ਜੇ (*copy == '/') {
		copy += strspn(copy, "/");
		ਜੇ (*copy == '\0')
			ਰਸਤਾ = ਨਿਰਾ;			/* ~/ */
		ਨਹੀਂਤਾਂ
			ਰਸਤਾ = copy;			/* ~/path */
	} ਨਹੀਂਤਾਂ {
		user = copy;
		ਜੇ ((ਰਸਤਾ = strchr(copy, '/')) != ਨਿਰਾ) {
			copy[ਰਸਤਾ - copy] = '\0';
			ਰਸਤਾ++;
			ਰਸਤਾ += strspn(ਰਸਤਾ, "/");
			ਜੇ (*ਰਸਤਾ == '\0')		/* ~user/ */
				ਰਸਤਾ = ਨਿਰਾ;
			/* else				 ~user/path */
		}
		/* else					~user */
	}
	ਜੇ (user != ਨਿਰਾ) {
		ਜੇ ((pw = getpwnam(user)) == ਨਿਰਾ) {
			error_f("No such user %s", user);
			ਜਾਓ ਬਾਹਰਲਾ;
		}
	} ਨਹੀਂਤਾਂ ਜੇ ((pw = getpwuid(uid)) == ਨਿਰਾ) {
		error_f("No such uid %ld", (ਲੰਮਾ)uid);
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	/* Make sure directory has a trailing '/' */
	slash = (len = ਲੜੀ_ਲੰਬਾਈ(pw->pw_dir)) == 0 || pw->pw_dir[len - 1] != '/';

	ਜੇ ((r = xasprintf(&s, "%s%s%s", pw->pw_dir,
	    slash ? "/" : "", ਰਸਤਾ != ਨਿਰਾ ? ਰਸਤਾ : "")) <= 0) {
		error_f("xasprintf failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (r >= PATH_MAX) {
		error_f("Path too long");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/* success */
	ret = 0;
	*retp = s;
	s = ਨਿਰਾ;
 ਬਾਹਰਲਾ:
	ਮੁਕਤ(s);
	ਮੁਕਤ(ocopy);
	ਵਾਪਸ ret;
}

ਅੱਖਰ *
tilde_expand_filename(ਅਚਲ ਅੱਖਰ *filename, uid_t uid)
{
	ਅੱਖਰ *ret;

	ਜੇ (tilde_expand(filename, uid, &ret) != 0)
		cleanup_exit(255);
	ਵਾਪਸ ret;
}

/*
 * Expand a string with a set of %[char] escapes and/or ${ENVIRONMENT}
 * substitutions.  A number of escapes may be specified as
 * (char *escape_chars, char *replacement) pairs. The list must be terminated
 * by a NULL escape_char. Returns replaced string in memory allocated by
 * xmalloc which the caller must free.
 */
ਸਥਿਰ ਅੱਖਰ *
vdollar_percent_expand(ਪੂਰਨ *parseerror, ਪੂਰਨ dollar, ਪੂਰਨ percent,
    ਅਚਲ ਅੱਖਰ *string, va_list ap)
{
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ EXPAND_MAX_ਕੁੰਜੀਆਂ	64
	u_int ਅੰਕ_ਕੁੰਜੀਆਂ = 0, i;
	ਬਣਤਰ {
		ਅਚਲ ਅੱਖਰ *ਕੁੰਜੀ;
		ਅਚਲ ਅੱਖਰ *repl;
	} ਕੁੰਜੀਆਂ[EXPAND_MAX_ਕੁੰਜੀਆਂ];
	ਬਣਤਰ sshbuf *buf;
	ਪੂਰਨ r, missingvar = 0;
	ਅੱਖਰ *ret = ਨਿਰਾ, *var, *varend, *val;
	ਮਾਪ_t len;

	ਜੇ ((buf = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	ਜੇ (parseerror == ਨਿਰਾ)
		fatal_f("null parseerror arg");
	*parseerror = 1;

	/* Gather keys if we're doing percent expansion. */
	ਜੇ (percent) {
		ਲਈ (ਅੰਕ_ਕੁੰਜੀਆਂ = 0; ਅੰਕ_ਕੁੰਜੀਆਂ < EXPAND_MAX_ਕੁੰਜੀਆਂ; ਅੰਕ_ਕੁੰਜੀਆਂ++) {
			ਕੁੰਜੀਆਂ[ਅੰਕ_ਕੁੰਜੀਆਂ].ਕੁੰਜੀ = va_arg(ap, ਅੱਖਰ *);
			ਜੇ (ਕੁੰਜੀਆਂ[ਅੰਕ_ਕੁੰਜੀਆਂ].ਕੁੰਜੀ == ਨਿਰਾ)
				ਰੋਕੋ;
			ਕੁੰਜੀਆਂ[ਅੰਕ_ਕੁੰਜੀਆਂ].repl = va_arg(ap, ਅੱਖਰ *);
			ਜੇ (ਕੁੰਜੀਆਂ[ਅੰਕ_ਕੁੰਜੀਆਂ].repl == ਨਿਰਾ) {
				fatal_f("NULL replacement for token %s",
				    ਕੁੰਜੀਆਂ[ਅੰਕ_ਕੁੰਜੀਆਂ].ਕੁੰਜੀ);
			}
		}
		ਜੇ (ਅੰਕ_ਕੁੰਜੀਆਂ == EXPAND_MAX_ਕੁੰਜੀਆਂ && va_arg(ap, ਅੱਖਰ *) != ਨਿਰਾ)
			fatal_f("too many keys");
		ਜੇ (ਅੰਕ_ਕੁੰਜੀਆਂ == 0)
			fatal_f("percent expansion without token list");
	}

	/* Expand string */
	ਲਈ (i = 0; *string != '\0'; string++) {
		/* Optionally process ${ENVIRONMENT} expansions. */
		ਜੇ (dollar && string[0] == '$' && string[1] == '{') {
			string += 2;  /* skip over '${' */
			ਜੇ ((varend = strchr(string, '}')) == ਨਿਰਾ) {
				error_f("environment variable '%s' missing "
				    "closing '}'", string);
				ਜਾਓ ਬਾਹਰਲਾ;
			}
			len = varend - string;
			ਜੇ (len == 0) {
				error_f("zero-length environment variable");
				ਜਾਓ ਬਾਹਰਲਾ;
			}
			var = xmalloc(len + 1);
			(ਖਾਲੀ)strlcpy(var, string, len + 1);
			ਜੇ ((val = getenv(var)) == ਨਿਰਾ) {
				error_f("env var ${%s} has no value", var);
				missingvar = 1;
			} ਨਹੀਂਤਾਂ {
				debug3_f("expand ${%s} -> '%s'", var, val);
				ਜੇ ((r = sshbuf_put(buf, val, ਲੜੀ_ਲੰਬਾਈ(val))) !=0)
					fatal_fr(r, "sshbuf_put ${}");
			}
			ਮੁਕਤ(var);
			string += len;
			ਜਾਰੀ;
		}

		/*
		 * Process percent expansions if we have a list of TOKENs.
		 * If we're not doing percent expansion everything just gets
		 * appended here.
		 */
		ਜੇ (*string != '%' || !percent) {
 append:
			ਜੇ ((r = sshbuf_put_u8(buf, *string)) != 0)
				fatal_fr(r, "sshbuf_put_u8 %%");
			ਜਾਰੀ;
		}
		string++;
		/* %% case */
		ਜੇ (*string == '%')
			ਜਾਓ append;
		ਜੇ (*string == '\0') {
			error_f("invalid format");
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਲਈ (i = 0; i < ਅੰਕ_ਕੁੰਜੀਆਂ; i++) {
			ਜੇ (strchr(ਕੁੰਜੀਆਂ[i].ਕੁੰਜੀ, *string) != ਨਿਰਾ) {
				ਜੇ ((r = sshbuf_put(buf, ਕੁੰਜੀਆਂ[i].repl,
				    ਲੜੀ_ਲੰਬਾਈ(ਕੁੰਜੀਆਂ[i].repl))) != 0)
					fatal_fr(r, "sshbuf_put %%-repl");
				ਰੋਕੋ;
			}
		}
		ਜੇ (i >= ਅੰਕ_ਕੁੰਜੀਆਂ) {
			error_f("unknown key %%%c", *string);
			ਜਾਓ ਬਾਹਰਲਾ;
		}
	}
	ਜੇ (!missingvar && (ret = sshbuf_dup_string(buf)) == ਨਿਰਾ)
		fatal_f("sshbuf_dup_string failed");
	*parseerror = 0;
 ਬਾਹਰਲਾ:
	sshbuf_free(buf);
	ਵਾਪਸ *parseerror ? ਨਿਰਾ : ret;
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ EXPAND_MAX_ਕੁੰਜੀਆਂ
}

/*
 * Expand only environment variables.
 * Note that although this function is variadic like the other similar
 * functions, any such arguments will be unused.
 */

ਅੱਖਰ *
dollar_expand(ਪੂਰਨ *parseerr, ਅਚਲ ਅੱਖਰ *string, ...)
{
	ਅੱਖਰ *ret;
	ਪੂਰਨ err;
	va_list ap;

	va_start(ap, string);
	ret = vdollar_percent_expand(&err, 1, 0, string, ap);
	va_end(ap);
	ਜੇ (parseerr != ਨਿਰਾ)
		*parseerr = err;
	ਵਾਪਸ ret;
}

/*
 * Returns expanded string or NULL if a specified environment variable is
 * not defined, or calls fatal if the string is invalid.
 */
ਅੱਖਰ *
percent_expand(ਅਚਲ ਅੱਖਰ *string, ...)
{
	ਅੱਖਰ *ret;
	ਪੂਰਨ err;
	va_list ap;

	va_start(ap, string);
	ret = vdollar_percent_expand(&err, 0, 1, string, ap);
	va_end(ap);
	ਜੇ (err)
		fatal_f("failed");
	ਵਾਪਸ ret;
}

/*
 * Returns expanded string or NULL if a specified environment variable is
 * not defined, or calls fatal if the string is invalid.
 */
ਅੱਖਰ *
percent_dollar_expand(ਅਚਲ ਅੱਖਰ *string, ...)
{
	ਅੱਖਰ *ret;
	ਪੂਰਨ err;
	va_list ap;

	va_start(ap, string);
	ret = vdollar_percent_expand(&err, 1, 1, string, ap);
	va_end(ap);
	ਜੇ (err)
		fatal_f("failed");
	ਵਾਪਸ ret;
}

ਪੂਰਨ
tun_open(ਪੂਰਨ tun, ਪੂਰਨ ਬਹੁਲਕ, ਅੱਖਰ **ifname)
{
#ਜੇ defined(CUSTOM_SYS_TUN_OPEN)
	ਵਾਪਸ (sys_tun_open(tun, ਬਹੁਲਕ, ifname));
#ਜਾਂਜੇ defined(SSH_TUN_OPENBSD)
	ਬਣਤਰ ifreq ifr;
	ਅੱਖਰ name[100];
	ਪੂਰਨ fd = -1, sock;
	ਅਚਲ ਅੱਖਰ *tunbase = "tun";

	ਜੇ (ifname != ਨਿਰਾ)
		*ifname = ਨਿਰਾ;

	ਜੇ (ਬਹੁਲਕ == SSH_TUNMODE_ETHERNET)
		tunbase = "tap";

	/* Open the tunnel device */
	ਜੇ (tun <= SSH_TUNID_MAX) {
		snprintf(name, ਆਕਾਰ(name), "/dev/%s%d", tunbase, tun);
		fd = open(name, O_RDWR);
	} ਨਹੀਂਤਾਂ ਜੇ (tun == SSH_TUNID_ANY) {
		ਲਈ (tun = 100; tun >= 0; tun--) {
			snprintf(name, ਆਕਾਰ(name), "/dev/%s%d",
			    tunbase, tun);
			ਜੇ ((fd = open(name, O_RDWR)) >= 0)
				ਰੋਕੋ;
		}
	} ਨਹੀਂਤਾਂ {
		debug_f("invalid tunnel %u", tun);
		ਵਾਪਸ -1;
	}

	ਜੇ (fd == -1) {
		debug_f("%s open: %s", name, strerror(errno));
		ਵਾਪਸ -1;
	}

	debug_f("%s mode %d fd %d", name, ਬਹੁਲਕ, fd);

	/* Bring interface up if it is not already */
	snprintf(ifr.ifr_name, ਆਕਾਰ(ifr.ifr_name), "%s%d", tunbase, tun);
	ਜੇ ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
		ਜਾਓ failed;

	ਜੇ (ioctl(sock, SIOCGIFFLAGS, &ifr) == -1) {
		debug_f("get interface %s flags: %s", ifr.ifr_name,
		    strerror(errno));
		ਜਾਓ failed;
	}

	ਜੇ (!(ifr.ifr_flags & IFF_UP)) {
		ifr.ifr_flags |= IFF_UP;
		ਜੇ (ioctl(sock, SIOCSIFFLAGS, &ifr) == -1) {
			debug_f("activate interface %s: %s", ifr.ifr_name,
			    strerror(errno));
			ਜਾਓ failed;
		}
	}

	ਜੇ (ifname != ਨਿਰਾ)
		*ifname = xstrdup(ifr.ifr_name);

	close(sock);
	ਵਾਪਸ fd;

 failed:
	ਜੇ (fd >= 0)
		close(fd);
	ਜੇ (sock >= 0)
		close(sock);
	ਵਾਪਸ -1;
#ਨਹੀਂਤਾਂ
	error("Tunnel interfaces are not supported on this platform");
	ਵਾਪਸ (-1);
#ਜੇ_ਅੰਤ
}

ਖਾਲੀ
sanitise_stdfd(ਖਾਲੀ)
{
	ਪੂਰਨ nullfd, dupfd;

	ਜੇ ((nullfd = dupfd = open(_PATH_DEVNULL, O_RDWR)) == -1) {
		fprintf(stderr, "Couldn't open /dev/null: %s\n",
		    strerror(errno));
		ਬਾਹਰ_ਨਿਕਲੋ(1);
	}
	ਜਦੋਂ (++dupfd <= STDERR_FILENO) {
		/* Only populate closed fds. */
		ਜੇ (fcntl(dupfd, F_GETFL) == -1 && errno == EBADF) {
			ਜੇ (dup2(nullfd, dupfd) == -1) {
				fprintf(stderr, "dup2: %s\n", strerror(errno));
				ਬਾਹਰ_ਨਿਕਲੋ(1);
			}
		}
	}
	ਜੇ (nullfd > STDERR_FILENO)
		close(nullfd);
}

ਅੱਖਰ *
tohex(ਅਚਲ ਖਾਲੀ *vp, ਮਾਪ_t l)
{
	ਅਚਲ u_char *p = (ਅਚਲ u_char *)vp;
	ਅੱਖਰ b[3], *r;
	ਮਾਪ_t i, hl;

	ਜੇ (l > 65536)
		ਵਾਪਸ xstrdup("tohex: length > 65536");

	hl = l * 2 + 1;
	r = xcalloc(1, hl);
	ਲਈ (i = 0; i < l; i++) {
		snprintf(b, ਆਕਾਰ(b), "%02x", p[i]);
		strlcat(r, b, hl);
	}
	ਵਾਪਸ (r);
}

/*
 * Extend string *sp by the specified format. If *sp is not NULL (or empty),
 * then the separator 'sep' will be prepended before the formatted arguments.
 * Extended strings are heap allocated.
 */
ਖਾਲੀ
xextendf(ਅੱਖਰ **sp, ਅਚਲ ਅੱਖਰ *sep, ਅਚਲ ਅੱਖਰ *fmt, ...)
{
	va_list ap;
	ਅੱਖਰ *tmp1, *tmp2;

	va_start(ap, fmt);
	xvasprintf(&tmp1, fmt, ap);
	va_end(ap);

	ਜੇ (*sp == ਨਿਰਾ || **sp == '\0') {
		ਮੁਕਤ(*sp);
		*sp = tmp1;
		ਵਾਪਸ;
	}
	xasprintf(&tmp2, "%s%s%s", *sp, sep == ਨਿਰਾ ? "" : sep, tmp1);
	ਮੁਕਤ(tmp1);
	ਮੁਕਤ(*sp);
	*sp = tmp2;
}


uint64_t
get_u64(ਅਚਲ ਖਾਲੀ *vp)
{
	ਅਚਲ u_char *p = (ਅਚਲ u_char *)vp;
	uint64_t v;

	v  = (uint64_t)p[0] << 56;
	v |= (uint64_t)p[1] << 48;
	v |= (uint64_t)p[2] << 40;
	v |= (uint64_t)p[3] << 32;
	v |= (uint64_t)p[4] << 24;
	v |= (uint64_t)p[5] << 16;
	v |= (uint64_t)p[6] << 8;
	v |= (uint64_t)p[7];

	ਵਾਪਸ (v);
}

uint32_t
get_u32(ਅਚਲ ਖਾਲੀ *vp)
{
	ਅਚਲ u_char *p = (ਅਚਲ u_char *)vp;
	uint32_t v;

	v  = (uint32_t)p[0] << 24;
	v |= (uint32_t)p[1] << 16;
	v |= (uint32_t)p[2] << 8;
	v |= (uint32_t)p[3];

	ਵਾਪਸ (v);
}

uint32_t
get_u32_le(ਅਚਲ ਖਾਲੀ *vp)
{
	ਅਚਲ u_char *p = (ਅਚਲ u_char *)vp;
	uint32_t v;

	v  = (uint32_t)p[0];
	v |= (uint32_t)p[1] << 8;
	v |= (uint32_t)p[2] << 16;
	v |= (uint32_t)p[3] << 24;

	ਵਾਪਸ (v);
}

uint16_t
get_u16(ਅਚਲ ਖਾਲੀ *vp)
{
	ਅਚਲ u_char *p = (ਅਚਲ u_char *)vp;
	uint16_t v;

	v  = (uint16_t)p[0] << 8;
	v |= (uint16_t)p[1];

	ਵਾਪਸ (v);
}

ਖਾਲੀ
put_u64(ਖਾਲੀ *vp, uint64_t v)
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

ਖਾਲੀ
put_u32(ਖਾਲੀ *vp, uint32_t v)
{
	u_char *p = (u_char *)vp;

	p[0] = (u_char)(v >> 24) & 0xff;
	p[1] = (u_char)(v >> 16) & 0xff;
	p[2] = (u_char)(v >> 8) & 0xff;
	p[3] = (u_char)v & 0xff;
}

ਖਾਲੀ
put_u32_le(ਖਾਲੀ *vp, uint32_t v)
{
	u_char *p = (u_char *)vp;

	p[0] = (u_char)v & 0xff;
	p[1] = (u_char)(v >> 8) & 0xff;
	p[2] = (u_char)(v >> 16) & 0xff;
	p[3] = (u_char)(v >> 24) & 0xff;
}

ਖਾਲੀ
put_u16(ਖਾਲੀ *vp, uint16_t v)
{
	u_char *p = (u_char *)vp;

	p[0] = (u_char)(v >> 8) & 0xff;
	p[1] = (u_char)v & 0xff;
}

ਖਾਲੀ
ms_ਘਟਾਓ_diff(ਬਣਤਰ timeval *ਸ਼ੁਰੂ, ਪੂਰਨ *ms)
{
	ਬਣਤਰ timeval diff, ਅੰਤ;

	monotime_tv(&ਅੰਤ);
	timersub(&ਅੰਤ, ਸ਼ੁਰੂ, &diff);
	*ms -= (diff.tv_sec * 1000) + (diff.tv_usec / 1000);
}

ਖਾਲੀ
ms_ਮੰਜ਼ਿਲ_timespec(ਬਣਤਰ timespec *ts, ਪੂਰਨ ms)
{
	ਜੇ (ms < 0)
		ms = 0;
	ts->tv_sec = ms / 1000;
	ts->tv_nsec = (ms % 1000) * 1000 * 1000;
}

ਖਾਲੀ
monotime_ts(ਬਣਤਰ timespec *ts)
{
	ਬਣਤਰ timeval tv;
#ਜੇ defined(HAVE_CLOCK_GETTIME) && (defined(CLOCK_BOOTTIME) || \
    defined(CLOCK_MONOTONIC) || defined(CLOCK_REALTIME))
	ਸਥਿਰ ਪੂਰਨ gettime_failed = 0;

	ਜੇ (!gettime_failed) {
# ifdef CLOCK_BOOTTIME
		ਜੇ (clock_gettime(CLOCK_BOOTTIME, ts) == 0)
			ਵਾਪਸ;
# endif /* CLOCK_BOOTTIME */
# ifdef CLOCK_MONOTONIC
		ਜੇ (clock_gettime(CLOCK_MONOTONIC, ts) == 0)
			ਵਾਪਸ;
# endif /* CLOCK_MONOTONIC */
# ifdef CLOCK_REALTIME
		/* Not monotonic, but we're almost out of options here. */
		ਜੇ (clock_gettime(CLOCK_REALTIME, ts) == 0)
			ਵਾਪਸ;
# endif /* CLOCK_REALTIME */
		debug3("clock_gettime: %s", strerror(errno));
		gettime_failed = 1;
	}
#ਜੇ_ਅੰਤ /* HAVE_CLOCK_GETTIME && (BOOTTIME || MONOTONIC || REALTIME) */
	gettimeofday(&tv, ਨਿਰਾ);
	ts->tv_sec = tv.tv_sec;
	ts->tv_nsec = (ਲੰਮਾ)tv.tv_usec * 1000;
}

ਖਾਲੀ
monotime_tv(ਬਣਤਰ timeval *tv)
{
	ਬਣਤਰ timespec ts;

	monotime_ts(&ts);
	tv->tv_sec = ts.tv_sec;
	tv->tv_usec = ts.tv_nsec / 1000;
}

time_t
monotime(ਖਾਲੀ)
{
	ਬਣਤਰ timespec ts;

	monotime_ts(&ts);
	ਵਾਪਸ (ts.tv_sec);
}

ਦੁੱਗਣਾ
monotime_double(ਖਾਲੀ)
{
	ਬਣਤਰ timespec ts;

	monotime_ts(&ts);
	ਵਾਪਸ (ਦੁੱਗਣਾ)ts.tv_sec + (ਦੁੱਗਣਾ)ts.tv_nsec / 1000000000.0;
}

ਖਾਲੀ
bandwidth_ਹੱਦਬੰਦੀ_init(ਬਣਤਰ bwlimit *bw, uint64_t kbps, ਮਾਪ_t buflen)
{
	bw->buflen = buflen;
	bw->ਦਰ = kbps;
	bw->thresh = buflen;
	bw->lamt = 0;
	timerclear(&bw->bwstart);
	timerclear(&bw->bwend);
}

/* Callback from read/write loop to insert bandwidth-limiting delays */
ਖਾਲੀ
bandwidth_ਹੱਦਬੰਦੀ(ਬਣਤਰ bwlimit *bw, ਮਾਪ_t read_len)
{
	uint64_t waitlen;
	ਬਣਤਰ timespec ts, rm;

	bw->lamt += read_len;
	ਜੇ (!timerisset(&bw->bwstart)) {
		monotime_tv(&bw->bwstart);
		ਵਾਪਸ;
	}
	ਜੇ (bw->lamt < bw->thresh)
		ਵਾਪਸ;

	monotime_tv(&bw->bwend);
	timersub(&bw->bwend, &bw->bwstart, &bw->bwend);
	ਜੇ (!timerisset(&bw->bwend))
		ਵਾਪਸ;

	bw->lamt *= 8;
	waitlen = (ਦੁੱਗਣਾ)1000000L * bw->lamt / bw->ਦਰ;

	bw->bwstart.tv_sec = waitlen / 1000000L;
	bw->bwstart.tv_usec = waitlen % 1000000L;

	ਜੇ (timercmp(&bw->bwstart, &bw->bwend, >)) {
		timersub(&bw->bwstart, &bw->bwend, &bw->bwend);

		/* Adjust the wait time */
		ਜੇ (bw->bwend.tv_sec) {
			bw->thresh /= 2;
			ਜੇ (bw->thresh < bw->buflen / 4)
				bw->thresh = bw->buflen / 4;
		} ਨਹੀਂਤਾਂ ਜੇ (bw->bwend.tv_usec < 10000) {
			bw->thresh *= 2;
			ਜੇ (bw->thresh > bw->buflen * 8)
				bw->thresh = bw->buflen * 8;
		}

		TIMEVAL_ਮੰਜ਼ਿਲ_TIMESPEC(&bw->bwend, &ts);
		ਜਦੋਂ (nanosleep(&ts, &rm) == -1) {
			ਜੇ (errno != EINTR)
				ਰੋਕੋ;
			ts = rm;
		}
	}

	bw->lamt = 0;
	monotime_tv(&bw->bwstart);
}

/* Make a template filename for mk[sd]temp() */
ਖਾਲੀ
mktemp_proto(ਅੱਖਰ *s, ਮਾਪ_t len)
{
	ਅਚਲ ਅੱਖਰ *tmpdir;
	ਪੂਰਨ r;

	ਜੇ ((tmpdir = getenv("TMPDIR")) != ਨਿਰਾ) {
		r = snprintf(s, len, "%s/ssh-XXXXXXXXXXXX", tmpdir);
		ਜੇ (r > 0 && (ਮਾਪ_t)r < len)
			ਵਾਪਸ;
	}
	r = snprintf(s, len, "/tmp/ssh-XXXXXXXXXXXX");
	ਜੇ (r < 0 || (ਮਾਪ_t)r >= len)
		fatal_f("template string too short");
}

ਸਥਿਰ ਅਚਲ ਬਣਤਰ {
	ਅਚਲ ਅੱਖਰ *name;
	ਪੂਰਨ ਮੁੱਲ;
} ipqos[] = {
	{ "none", ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ },		/* can't use 0 here; that's CS0 */
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
	{ ਨਿਰਾ, -1 }
};

ਪੂਰਨ
parse_ipqos(ਅਚਲ ਅੱਖਰ *cp)
{
	ਅਚਲ ਅੱਖਰ *errstr;
	u_int i;
	ਪੂਰਨ val;

	ਜੇ (cp == ਨਿਰਾ)
		ਵਾਪਸ -1;
	ਲਈ (i = 0; ipqos[i].name != ਨਿਰਾ; i++) {
		ਜੇ (strcasecmp(cp, ipqos[i].name) == 0)
			ਵਾਪਸ ipqos[i].ਮੁੱਲ;
	}
	/* Try parsing as an integer */
	val = (ਪੂਰਨ)strtonum(cp, 0, 255, &errstr);
	ਜੇ (errstr)
		ਵਾਪਸ -1;
	ਵਾਪਸ val;
}

ਅਚਲ ਅੱਖਰ *
iptos2str(ਪੂਰਨ iptos)
{
	ਪੂਰਨ i;
	ਸਥਿਰ ਅੱਖਰ iptos_str[ਆਕਾਰ "0xff"];

	ਲਈ (i = 0; ipqos[i].name != ਨਿਰਾ; i++) {
		ਜੇ (ipqos[i].ਮੁੱਲ == iptos)
			ਵਾਪਸ ipqos[i].name;
	}
	snprintf(iptos_str, ਆਕਾਰ iptos_str, "0x%02x", iptos);
	ਵਾਪਸ iptos_str;
}

ਖਾਲੀ
lowercase(ਅੱਖਰ *s)
{
	ਲਈ (; *s; s++)
		*s = tolower((u_char)*s);
}

ਪੂਰਨ
unix_listener(ਅਚਲ ਅੱਖਰ *ਰਸਤਾ, ਪੂਰਨ backlog, ਪੂਰਨ unlink_ਪਹਿਲਾ)
{
	ਬਣਤਰ sockaddr_un sunaddr;
	ਪੂਰਨ saved_errno, sock;

	memset(&sunaddr, 0, ਆਕਾਰ(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	ਜੇ (strlcpy(sunaddr.sun_ਰਸਤਾ, ਰਸਤਾ,
	    ਆਕਾਰ(sunaddr.sun_ਰਸਤਾ)) >= ਆਕਾਰ(sunaddr.sun_ਰਸਤਾ)) {
		error_f("path \"%s\" too long for Unix domain socket", ਰਸਤਾ);
		errno = ENAMETOOLONG;
		ਵਾਪਸ -1;
	}

	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	ਜੇ (sock == -1) {
		saved_errno = errno;
		error_f("socket: %.100s", strerror(errno));
		errno = saved_errno;
		ਵਾਪਸ -1;
	}
	ਜੇ (unlink_ਪਹਿਲਾ == 1) {
		ਜੇ (unlink(ਰਸਤਾ) != 0 && errno != ENOENT)
			error("unlink(%s): %.100s", ਰਸਤਾ, strerror(errno));
	}
	ਜੇ (bind(sock, (ਬਣਤਰ sockaddr *)&sunaddr, ਆਕਾਰ(sunaddr)) == -1) {
		saved_errno = errno;
		error_f("cannot bind to path %s: %s", ਰਸਤਾ, strerror(errno));
		close(sock);
		errno = saved_errno;
		ਵਾਪਸ -1;
	}
	ਜੇ (listen(sock, backlog) == -1) {
		saved_errno = errno;
		error_f("cannot listen on path %s: %s", ਰਸਤਾ, strerror(errno));
		close(sock);
		unlink(ਰਸਤਾ);
		errno = saved_errno;
		ਵਾਪਸ -1;
	}
	ਵਾਪਸ sock;
}

ਖਾਲੀ
sock_ਸੈੱਟ_v6only(ਪੂਰਨ s)
{
#ਜੇ defined(IPV6_V6ONLY) && !defined(__OpenBSD__)
	ਪੂਰਨ on = 1;

	debug3_f("set socket %d IPV6_V6ONLY", s);
	ਜੇ (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &on, ਆਕਾਰ(on)) == -1)
		error("setsockopt IPV6_V6ONLY: %s", strerror(errno));
#ਜੇ_ਅੰਤ
}

/*
 * Compares two strings that maybe be NULL. Returns non-zero if strings
 * are both NULL or are identical, returns zero otherwise.
 */
ਸਥਿਰ ਪੂਰਨ
strcmp_maybe_null(ਅਚਲ ਅੱਖਰ *a, ਅਚਲ ਅੱਖਰ *b)
{
	ਜੇ ((a == ਨਿਰਾ && b != ਨਿਰਾ) || (a != ਨਿਰਾ && b == ਨਿਰਾ))
		ਵਾਪਸ 0;
	ਜੇ (a != ਨਿਰਾ && strcmp(a, b) != 0)
		ਵਾਪਸ 0;
	ਵਾਪਸ 1;
}

/*
 * Compare two forwards, returning non-zero if they are identical or
 * zero otherwise.
 */
ਪੂਰਨ
forward_equals(ਅਚਲ ਬਣਤਰ Forward *a, ਅਚਲ ਬਣਤਰ Forward *b)
{
	ਜੇ (strcmp_maybe_null(a->listen_host, b->listen_host) == 0)
		ਵਾਪਸ 0;
	ਜੇ (a->listen_ਪੋਰਟ != b->listen_ਪੋਰਟ)
		ਵਾਪਸ 0;
	ਜੇ (strcmp_maybe_null(a->listen_ਰਸਤਾ, b->listen_ਰਸਤਾ) == 0)
		ਵਾਪਸ 0;
	ਜੇ (strcmp_maybe_null(a->connect_host, b->connect_host) == 0)
		ਵਾਪਸ 0;
	ਜੇ (a->connect_ਪੋਰਟ != b->connect_ਪੋਰਟ)
		ਵਾਪਸ 0;
	ਜੇ (strcmp_maybe_null(a->connect_ਰਸਤਾ, b->connect_ਰਸਤਾ) == 0)
		ਵਾਪਸ 0;
	/* allocated_port and handle are not checked */
	ਵਾਪਸ 1;
}

/* returns port number, FWD_PERMIT_ANY_PORT or -1 on error */
ਪੂਰਨ
permitopen_ਪੋਰਟ(ਅਚਲ ਅੱਖਰ *p)
{
	ਪੂਰਨ ਪੋਰਟ;

	ਜੇ (strcmp(p, "*") == 0)
		ਵਾਪਸ FWD_PERMIT_ANY_ਪੋਰਟ;
	ਜੇ ((ਪੋਰਟ = a2port(p)) > 0)
		ਵਾਪਸ ਪੋਰਟ;
	ਵਾਪਸ -1;
}

/* returns 1 if process is already daemonized, 0 otherwise */
ਪੂਰਨ
daemonized(ਖਾਲੀ)
{
	ਪੂਰਨ fd;

	ਜੇ ((fd = open(_PATH_TTY, O_RDONLY | O_NOCTTY)) >= 0) {
		close(fd);
		ਵਾਪਸ 0;	/* have controlling terminal */
	}
	ਜੇ (getppid() != 1)
		ਵਾਪਸ 0;	/* parent is not init */
	ਜੇ (getsid(0) != getpid())
		ਵਾਪਸ 0;	/* not session leader */
	debug3("already daemonized");
	ਵਾਪਸ 1;
}

/*
 * Splits 's' into an argument vector. Handles quoted string and basic
 * escape characters (\\, \", \'). Caller must free the argument vector
 * and its members.
 */
ਪੂਰਨ
argv_ਵੰਡੋ(ਅਚਲ ਅੱਖਰ *s, ਪੂਰਨ *argcp, ਅੱਖਰ ***argvp, ਪੂਰਨ terminate_on_comment)
{
	ਪੂਰਨ r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	ਪੂਰਨ argc = 0, quote, i, j;
	ਅੱਖਰ *arg, **argv = xcalloc(1, ਆਕਾਰ(*argv));

	*argvp = ਨਿਰਾ;
	*argcp = 0;

	ਲਈ (i = 0; s[i] != '\0'; i++) {
		/* Skip leading whitespace */
		ਜੇ (s[i] == ' ' || s[i] == '\t')
			ਜਾਰੀ;
		ਜੇ (terminate_on_comment && s[i] == '#')
			ਰੋਕੋ;
		/* Start of a token */
		quote = 0;

		argv = xreallocarray(argv, (argc + 2), ਆਕਾਰ(*argv));
		arg = argv[argc++] = xcalloc(1, ਲੜੀ_ਲੰਬਾਈ(s + i) + 1);
		argv[argc] = ਨਿਰਾ;

		/* Copy the token in, removing escapes */
		ਲਈ (j = 0; s[i] != '\0'; i++) {
			ਜੇ (s[i] == '\\') {
				ਜੇ (s[i + 1] == '\'' ||
				    s[i + 1] == '\"' ||
				    s[i + 1] == '\\' ||
				    (quote == 0 && s[i + 1] == ' ')) {
					i++; /* Skip '\' */
					arg[j++] = s[i];
				} ਨਹੀਂਤਾਂ {
					/* Unrecognised escape */
					arg[j++] = s[i];
				}
			} ਨਹੀਂਤਾਂ ਜੇ (quote == 0 && (s[i] == ' ' || s[i] == '\t'))
				ਰੋਕੋ; /*ਪੂਰਾ*/
			ਨਹੀਂਤਾਂ ਜੇ (quote == 0 && (s[i] == '\"' || s[i] == '\''))
				quote = s[i]; /* quote start */
			ਨਹੀਂਤਾਂ ਜੇ (quote != 0 && s[i] == quote)
				quote = 0; /* quote end */
			ਨਹੀਂਤਾਂ
				arg[j++] = s[i];
		}
		ਜੇ (s[i] == '\0') {
			ਜੇ (quote != 0) {
				/* Ran out of string looking for close quote */
				r = SSH_ERR_INVALID_FORMAT;
				ਜਾਓ ਬਾਹਰਲਾ;
			}
			ਰੋਕੋ;
		}
	}
	/* Success */
	*argcp = argc;
	*argvp = argv;
	argc = 0;
	argv = ਨਿਰਾ;
	r = 0;
 ਬਾਹਰਲਾ:
	ਜੇ (argc != 0 && argv != ਨਿਰਾ) {
		ਲਈ (i = 0; i < argc; i++)
			ਮੁਕਤ(argv[i]);
		ਮੁਕਤ(argv);
	}
	ਵਾਪਸ r;
}

/*
 * Reassemble an argument vector into a string, quoting and escaping as
 * necessary. Caller must free returned string.
 */
ਅੱਖਰ *
argv_assemble(ਪੂਰਨ argc, ਅੱਖਰ **argv)
{
	ਪੂਰਨ i, j, ws, r;
	ਅੱਖਰ c, *ret;
	ਬਣਤਰ sshbuf *buf, *arg;

	ਜੇ ((buf = sshbuf_new()) == ਨਿਰਾ || (arg = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");

	ਲਈ (i = 0; i < argc; i++) {
		ws = 0;
		sshbuf_reset(arg);
		ਲਈ (j = 0; argv[i][j] != '\0'; j++) {
			r = 0;
			c = argv[i][j];
			ਚੋਣ (c) {
			ਹਾਲਤ ' ':
			ਹਾਲਤ '\t':
				ws = 1;
				r = sshbuf_put_u8(arg, c);
				ਰੋਕੋ;
			ਹਾਲਤ '\\':
			ਹਾਲਤ '\'':
			ਹਾਲਤ '"':
				ਜੇ ((r = sshbuf_put_u8(arg, '\\')) != 0)
					ਰੋਕੋ;
				/* FALLTHROUGH */
			ਮੂਲ:
				r = sshbuf_put_u8(arg, c);
				ਰੋਕੋ;
			}
			ਜੇ (r != 0)
				fatal_fr(r, "sshbuf_put_u8");
		}
		ਜੇ ((i != 0 && (r = sshbuf_put_u8(buf, ' ')) != 0) ||
		    (ws != 0 && (r = sshbuf_put_u8(buf, '"')) != 0) ||
		    (r = sshbuf_putb(buf, arg)) != 0 ||
		    (ws != 0 && (r = sshbuf_put_u8(buf, '"')) != 0))
			fatal_fr(r, "assemble");
	}
	ਜੇ ((ret = ਸਮ੍ਰਿਤੀ_ਦਿਓ(sshbuf_len(buf) + 1)) == ਨਿਰਾ)
		fatal_f("malloc failed");
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(ret, sshbuf_ptr(buf), sshbuf_len(buf));
	ret[sshbuf_len(buf)] = '\0';
	sshbuf_free(buf);
	sshbuf_free(arg);
	ਵਾਪਸ ret;
}

ਅੱਖਰ *
argv_ਅਗਲਾ(ਪੂਰਨ *argcp, ਅੱਖਰ ***argvp)
{
	ਅੱਖਰ *ret = (*argvp)[0];

	ਜੇ (*argcp > 0 && ret != ਨਿਰਾ) {
		(*argcp)--;
		(*argvp)++;
	}
	ਵਾਪਸ ret;
}

ਖਾਲੀ
argv_consume(ਪੂਰਨ *argcp)
{
	*argcp = 0;
}

ਖਾਲੀ
argv_free(ਅੱਖਰ **av, ਪੂਰਨ ac)
{
	ਪੂਰਨ i;

	ਜੇ (av == ਨਿਰਾ)
		ਵਾਪਸ;
	ਲਈ (i = 0; i < ac; i++)
		ਮੁਕਤ(av[i]);
	ਮੁਕਤ(av);
}

/* Returns 0 if pid exited cleanly, non-zero otherwise */
ਪੂਰਨ
exited_cleanly(pid_t pid, ਅਚਲ ਅੱਖਰ *ਟੈਗ, ਅਚਲ ਅੱਖਰ *cmd, ਪੂਰਨ quiet)
{
	ਪੂਰਨ ਸਥਿਤੀ;

	ਜਦੋਂ (waitpid(pid, &ਸਥਿਤੀ, 0) == -1) {
		ਜੇ (errno != EINTR) {
			error("%s waitpid: %s", ਟੈਗ, strerror(errno));
			ਵਾਪਸ -1;
		}
	}
	ਜੇ (WIFSIGNALED(ਸਥਿਤੀ)) {
		error("%s %s exited on signal %d", ਟੈਗ, cmd, WTERMSIG(ਸਥਿਤੀ));
		ਵਾਪਸ -1;
	} ਨਹੀਂਤਾਂ ਜੇ (WEXITSTATUS(ਸਥਿਤੀ) != 0) {
		do_log2(quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_INFO,
		    "%s %s failed, status %d", ਟੈਗ, cmd, WEXITSTATUS(ਸਥਿਤੀ));
		ਵਾਪਸ -1;
	}
	ਵਾਪਸ 0;
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
ਪੂਰਨ
ਸੁਰੱਖਿਅਤ_ਰਸਤਾ(ਅਚਲ ਅੱਖਰ *name, ਬਣਤਰ stat *stp, ਅਚਲ ਅੱਖਰ *pw_dir,
    uid_t uid, ਅੱਖਰ *err, ਮਾਪ_t errlen)
{
	ਅੱਖਰ buf[PATH_MAX], buf2[PATH_MAX], homedir[PATH_MAX];
	ਅੱਖਰ *cp;
	ਪੂਰਨ comparehome = 0;
	ਬਣਤਰ stat st;

	ਜੇ (realpath(name, buf) == ਨਿਰਾ) {
		snprintf(err, errlen, "realpath %s failed: %s", name,
		    strerror(errno));
		ਵਾਪਸ -1;
	}
	ਜੇ (pw_dir != ਨਿਰਾ && realpath(pw_dir, homedir) != ਨਿਰਾ)
		comparehome = 1;

	ਜੇ (!S_ISREG(stp->st_mode)) {
		snprintf(err, errlen, "%s is not a regular file", buf);
		ਵਾਪਸ -1;
	}
	ਜੇ ((!platform_sys_dir_uid(stp->st_uid) && stp->st_uid != uid) ||
	    (stp->st_mode & 022) != 0) {
		snprintf(err, errlen, "bad ownership or modes for file %s",
		    buf);
		ਵਾਪਸ -1;
	}

	/* for each component of the canonical path, walking upwards */
	ਲਈ (;;) {
		/*
		 * POSIX allows dirname to modify its argument and return a
		 * pointer into it, so make a copy to avoid overlapping strlcpy.
		 */
		strlcpy(buf2, buf, ਆਕਾਰ(buf2));
		ਜੇ ((cp = dirname(buf2)) == ਨਿਰਾ) {
			snprintf(err, errlen, "dirname() failed");
			ਵਾਪਸ -1;
		}
		strlcpy(buf, cp, ਆਕਾਰ(buf));

		ਜੇ (stat(buf, &st) == -1 ||
		    (!platform_sys_dir_uid(st.st_uid) && st.st_uid != uid) ||
		    (st.st_mode & 022) != 0) {
			snprintf(err, errlen,
			    "bad ownership or modes for directory %s", buf);
			ਵਾਪਸ -1;
		}

		/* If are past the homedir then we can stop */
		ਜੇ (comparehome && strcmp(homedir, buf) == 0)
			ਰੋਕੋ;

		/*
		 * dirname should always complete with a "/" path,
		 * but we can be paranoid and check for "." too
		 */
		ਜੇ ((strcmp("/", buf) == 0) || (strcmp(".", buf) == 0))
			ਰੋਕੋ;
	}
	ਵਾਪਸ 0;
}

/*
 * Version of safe_path() that accepts an open file descriptor to
 * avoid races.
 *
 * Returns 0 on success and -1 on failure
 */
ਪੂਰਨ
ਸੁਰੱਖਿਅਤ_ਰਸਤਾ_fd(ਪੂਰਨ fd, ਅਚਲ ਅੱਖਰ *file, ਬਣਤਰ passwd *pw,
    ਅੱਖਰ *err, ਮਾਪ_t errlen)
{
	ਬਣਤਰ stat st;

	/* check the open file to avoid races */
	ਜੇ (fstat(fd, &st) == -1) {
		snprintf(err, errlen, "cannot stat file %s: %s",
		    file, strerror(errno));
		ਵਾਪਸ -1;
	}
	ਵਾਪਸ ਸੁਰੱਖਿਅਤ_ਰਸਤਾ(file, &st, pw->pw_dir, pw->pw_uid, err, errlen);
}

/*
 * Sets the value of the given variable in the environment.  If the variable
 * already exists, its value is overridden.
 */
ਖਾਲੀ
ਬੱਚਾ_ਸੈੱਟ_env(ਅੱਖਰ ***envp, u_int *envsizep, ਅਚਲ ਅੱਖਰ *name,
	ਅਚਲ ਅੱਖਰ *ਮੁੱਲ)
{
	ਅੱਖਰ **env;
	u_int envsize;
	u_int i, namelen;

	ਜੇ (strchr(name, '=') != ਨਿਰਾ) {
		error("Invalid environment variable \"%.100s\"", name);
		ਵਾਪਸ;
	}

	/*
	 * If we're passed an uninitialized list, allocate a single null
	 * entry before continuing.
	 */
	ਜੇ ((*envp == ਨਿਰਾ) != (*envsizep == 0))
		fatal_f("environment size mismatch");
	ਜੇ (*envp == ਨਿਰਾ && *envsizep == 0) {
		*envp = xmalloc(ਆਕਾਰ(ਅੱਖਰ *));
		*envp[0] = ਨਿਰਾ;
		*envsizep = 1;
	}

	/*
	 * Find the slot where the value should be stored.  If the variable
	 * already exists, we reuse the slot; otherwise we append a new slot
	 * at the end of the array, expanding if necessary.
	 */
	env = *envp;
	namelen = ਲੜੀ_ਲੰਬਾਈ(name);
	ਲਈ (i = 0; env[i]; i++)
		ਜੇ (ਲੜੀ_ਤੁਲਨਾ(env[i], name, namelen) == 0 && env[i][namelen] == '=')
			ਰੋਕੋ;
	ਜੇ (env[i]) {
		/* Reuse the slot. */
		ਮੁਕਤ(env[i]);
	} ਨਹੀਂਤਾਂ {
		/* New variable.  Expand if necessary. */
		envsize = *envsizep;
		ਜੇ (i >= envsize - 1) {
			ਜੇ (envsize >= 1000)
				fatal("child_set_env: too many env vars");
			envsize += 50;
			env = (*envp) = xreallocarray(env, envsize, ਆਕਾਰ(ਅੱਖਰ *));
			*envsizep = envsize;
		}
		/* Need to set the NULL pointer at end of array beyond the new slot. */
		env[i + 1] = ਨਿਰਾ;
	}

	/* Allocate space and format the variable in the appropriate slot. */
	/* XXX xasprintf */
	env[i] = xmalloc(ਲੜੀ_ਲੰਬਾਈ(name) + 1 + ਲੜੀ_ਲੰਬਾਈ(ਮੁੱਲ) + 1);
	snprintf(env[i], ਲੜੀ_ਲੰਬਾਈ(name) + 1 + ਲੜੀ_ਲੰਬਾਈ(ਮੁੱਲ) + 1, "%s=%s", name, ਮੁੱਲ);
}

/*
 * Check and optionally lowercase a domain name, also removes trailing '.'
 * Returns 1 on success and 0 on failure, storing an error message in errstr.
 */
ਪੂਰਨ
valid_domain(ਅੱਖਰ *name, ਪੂਰਨ makelower, ਅਚਲ ਅੱਖਰ **errstr)
{
	ਮਾਪ_t i, l = ਲੜੀ_ਲੰਬਾਈ(name);
	u_char c, ਆਖਰੀ = '\0';
	ਸਥਿਰ ਅੱਖਰ errbuf[256];

	ਜੇ (l == 0) {
		strlcpy(errbuf, "empty domain name", ਆਕਾਰ(errbuf));
		ਜਾਓ bad;
	}
	ਜੇ (!ਅੱਖਰ_ਹੈ((u_char)name[0]) && !ਅੰਕ_ਹੈ((u_char)name[0]) &&
	   name[0] != '_' /* technically invalid, but common */) {
		snprintf(errbuf, ਆਕਾਰ(errbuf), "domain name \"%.100s\" "
		    "starts with invalid character", name);
		ਜਾਓ bad;
	}
	ਲਈ (i = 0; i < l; i++) {
		c = tolower((u_char)name[i]);
		ਜੇ (makelower)
			name[i] = (ਅੱਖਰ)c;
		ਜੇ (ਆਖਰੀ == '.' && c == '.') {
			snprintf(errbuf, ਆਕਾਰ(errbuf), "domain name "
			    "\"%.100s\" contains consecutive separators", name);
			ਜਾਓ bad;
		}
		ਜੇ (c != '.' && c != '-' && !ਅੱਖਰ_ਜਾਂ_ਅੰਕ(c) &&
		    c != '_') /* technically invalid, but common */ {
			snprintf(errbuf, ਆਕਾਰ(errbuf), "domain name "
			    "\"%.100s\" contains invalid characters", name);
			ਜਾਓ bad;
		}
		ਆਖਰੀ = c;
	}
	ਜੇ (name[l - 1] == '.')
		name[l - 1] = '\0';
	ਜੇ (errstr != ਨਿਰਾ)
		*errstr = ਨਿਰਾ;
	ਵਾਪਸ 1;
bad:
	ਜੇ (errstr != ਨਿਰਾ)
		*errstr = errbuf;
	ਵਾਪਸ 0;
}

/*
 * Verify that a environment variable name (not including initial '$') is
 * valid; consisting of one or more alphanumeric or underscore characters only.
 * Returns 1 on valid, 0 otherwise.
 */
ਪੂਰਨ
valid_env_name(ਅਚਲ ਅੱਖਰ *name)
{
	ਅਚਲ ਅੱਖਰ *cp;

	ਜੇ (name[0] == '\0')
		ਵਾਪਸ 0;
	ਲਈ (cp = name; *cp != '\0'; cp++) {
		ਜੇ (!ਅੱਖਰ_ਜਾਂ_ਅੰਕ((u_char)*cp) && *cp != '_')
			ਵਾਪਸ 0;
	}
	ਵਾਪਸ 1;
}

ਅਚਲ ਅੱਖਰ *
atoi_err(ਅਚਲ ਅੱਖਰ *nptr, ਪੂਰਨ *val)
{
	ਅਚਲ ਅੱਖਰ *errstr = ਨਿਰਾ;

	ਜੇ (nptr == ਨਿਰਾ || *nptr == '\0')
		ਵਾਪਸ "missing";
	*val = strtonum(nptr, 0, ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ, &errstr);
	ਵਾਪਸ errstr;
}

ਪੂਰਨ
parse_absolute_ਸਮਾਂ(ਅਚਲ ਅੱਖਰ *s, uint64_t *tp)
{
	ਬਣਤਰ tm tm;
	time_t tt;
	ਅੱਖਰ buf[32], *fmt;
	ਅਚਲ ਅੱਖਰ *cp;
	ਮਾਪ_t l;
	ਪੂਰਨ is_utc = 0;

	*tp = 0;

	l = ਲੜੀ_ਲੰਬਾਈ(s);
	ਜੇ (l > 1 && strcasecmp(s + l - 1, "Z") == 0) {
		is_utc = 1;
		l--;
	} ਨਹੀਂਤਾਂ ਜੇ (l > 3 && strcasecmp(s + l - 3, "UTC") == 0) {
		is_utc = 1;
		l -= 3;
	}
	/*
	 * POSIX strptime says "The application shall ensure that there
	 * is white-space or other non-alphanumeric characters between
	 * any two conversion specifications" so arrange things this way.
	 */
	ਚੋਣ (l) {
	ਹਾਲਤ 8: /* YYYYMMDD */
		fmt = "%Y-%m-%d";
		snprintf(buf, ਆਕਾਰ(buf), "%.4s-%.2s-%.2s", s, s + 4, s + 6);
		ਰੋਕੋ;
	ਹਾਲਤ 12: /* YYYYMMDDHHMM */
		fmt = "%Y-%m-%dT%H:%M";
		snprintf(buf, ਆਕਾਰ(buf), "%.4s-%.2s-%.2sT%.2s:%.2s",
		    s, s + 4, s + 6, s + 8, s + 10);
		ਰੋਕੋ;
	ਹਾਲਤ 14: /* YYYYMMDDHHMMSS */
		fmt = "%Y-%m-%dT%H:%M:%S";
		snprintf(buf, ਆਕਾਰ(buf), "%.4s-%.2s-%.2sT%.2s:%.2s:%.2s",
		    s, s + 4, s + 6, s + 8, s + 10, s + 12);
		ਰੋਕੋ;
	ਮੂਲ:
		ਵਾਪਸ SSH_ERR_INVALID_FORMAT;
	}

	memset(&tm, 0, ਆਕਾਰ(tm));
	ਜੇ ((cp = strptime(buf, fmt, &tm)) == ਨਿਰਾ || *cp != '\0')
		ਵਾਪਸ SSH_ERR_INVALID_FORMAT;
	ਜੇ (is_utc) {
		tm.tm_wday = -1;	/* sentinel for error */
		ਜੇ ((tt = timegm(&tm)) == -1 && tm.tm_wday == -1)
			ਵਾਪਸ SSH_ERR_INVALID_FORMAT;
	} ਨਹੀਂਤਾਂ {
		tm.tm_wday = -1;	/* sentinel for error */
		tm.tm_isdst = -1;	/* mktime decides DST */
		ਜੇ ((tt = mktime(&tm)) == -1 && tm.tm_wday == -1)
			ਵਾਪਸ SSH_ERR_INVALID_FORMAT;
	}
	/* success */
	*tp = (uint64_t)tt;
	ਵਾਪਸ 0;
}

ਖਾਲੀ
format_absolute_ਸਮਾਂ(uint64_t t, ਅੱਖਰ *buf, ਮਾਪ_t len)
{
	time_t tt = t > SSH_ਸਮਾਂ_T_MAX ? SSH_ਸਮਾਂ_T_MAX : t;
	ਬਣਤਰ tm tm;

	ਜੇ (localtime_r(&tt, &tm) == ਨਿਰਾ)
		strlcpy(buf, "UNKNOWN-TIME", len);
	ਨਹੀਂਤਾਂ
		strftime(buf, len, "%Y-%m-%dT%H:%M:%S", &tm);
}

/*
 * Parse a "pattern=interval" clause (e.g. a ChannelTimeout).
 * Returns 0 on success or non-zero on failure.
 * Caller must free *typep.
 */
ਪੂਰਨ
parse_ਨਮੂਨਾ_interval(ਅਚਲ ਅੱਖਰ *s, ਅੱਖਰ **typep, ਦੁੱਗਣਾ *secsp)
{
	ਅੱਖਰ *cp, *sdup;
	ਦੁੱਗਣਾ secs;

	ਜੇ (typep != ਨਿਰਾ)
		*typep = ਨਿਰਾ;
	ਜੇ (secsp != ਨਿਰਾ)
		*secsp = 0;
	ਜੇ (s == ਨਿਰਾ)
		ਵਾਪਸ -1;
	sdup = xstrdup(s);

	ਜੇ ((cp = strchr(sdup, '=')) == ਨਿਰਾ || cp == sdup) {
		ਮੁਕਤ(sdup);
		ਵਾਪਸ -1;
	}
	*cp++ = '\0';
	ਜੇ ((secs = convtime_double(cp)) < 0.0) {
		ਮੁਕਤ(sdup);
		ਵਾਪਸ -1;
	}
	/* success */
	ਜੇ (typep != ਨਿਰਾ)
		*typep = xstrdup(sdup);
	ਜੇ (secsp != ਨਿਰਾ)
		*secsp = secs;
	ਮੁਕਤ(sdup);
	ਵਾਪਸ 0;
}

/* check if path is absolute */
ਪੂਰਨ
ਰਸਤਾ_absolute(ਅਚਲ ਅੱਖਰ *ਰਸਤਾ)
{
	ਵਾਪਸ (*ਰਸਤਾ == '/') ? 1 : 0;
}

ਖਾਲੀ
skip_space(ਅੱਖਰ **cpp)
{
	ਅੱਖਰ *cp;

	ਲਈ (cp = *cpp; *cp == ' ' || *cp == '\t'; cp++)
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
ਪੂਰਨ
opt_flag(ਅਚਲ ਅੱਖਰ *opt, ਪੂਰਨ allow_negate, ਅਚਲ ਅੱਖਰ **optsp)
{
	ਮਾਪ_t opt_len = ਲੜੀ_ਲੰਬਾਈ(opt);
	ਅਚਲ ਅੱਖਰ *opts = *optsp;
	ਪੂਰਨ negate = 0;

	ਜੇ (allow_negate && strncasecmp(opts, "no-", 3) == 0) {
		opts += 3;
		negate = 1;
	}
	ਜੇ (strncasecmp(opts, opt, opt_len) == 0) {
		*optsp = opts + opt_len;
		ਵਾਪਸ negate ? 0 : 1;
	}
	ਵਾਪਸ -1;
}

ਅੱਖਰ *
opt_dequote(ਅਚਲ ਅੱਖਰ **sp, ਅਚਲ ਅੱਖਰ **errstrp)
{
	ਅਚਲ ਅੱਖਰ *s = *sp;
	ਅੱਖਰ *ret;
	ਮਾਪ_t i;

	*errstrp = ਨਿਰਾ;
	ਜੇ (*s != '"') {
		*errstrp = "missing start quote";
		ਵਾਪਸ ਨਿਰਾ;
	}
	s++;
	ਜੇ ((ret = ਸਮ੍ਰਿਤੀ_ਦਿਓ(ਲੜੀ_ਲੰਬਾਈ((s)) + 1)) == ਨਿਰਾ) {
		*errstrp = "memory allocation failed";
		ਵਾਪਸ ਨਿਰਾ;
	}
	ਲਈ (i = 0; *s != '\0' && *s != '"';) {
		ਜੇ (s[0] == '\\' && s[1] == '"')
			s++;
		ret[i++] = *s++;
	}
	ਜੇ (*s == '\0') {
		*errstrp = "missing end quote";
		ਮੁਕਤ(ret);
		ਵਾਪਸ ਨਿਰਾ;
	}
	ret[i] = '\0';
	s++;
	*sp = s;
	ਵਾਪਸ ret;
}

ਪੂਰਨ
opt_ਮੇਲ(ਅਚਲ ਅੱਖਰ **opts, ਅਚਲ ਅੱਖਰ *ਪਦ)
{
	ਜੇ (strncasecmp((*opts), ਪਦ, ਲੜੀ_ਲੰਬਾਈ(ਪਦ)) == 0 &&
	    (*opts)[ਲੜੀ_ਲੰਬਾਈ(ਪਦ)] == '=') {
		*opts += ਲੜੀ_ਲੰਬਾਈ(ਪਦ) + 1;
		ਵਾਪਸ 1;
	}
	ਵਾਪਸ 0;
}

ਖਾਲੀ
opt_array_append2(ਅਚਲ ਅੱਖਰ *file, ਅਚਲ ਪੂਰਨ ਸਤਰ, ਅਚਲ ਅੱਖਰ *directive,
    ਅੱਖਰ ***array, ਪੂਰਨ **iarray, u_int *lp, ਅਚਲ ਅੱਖਰ *s, ਪੂਰਨ i)
{

	ਜੇ (*lp >= ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ)
		fatal("%s line %d: Too many %s entries", file, ਸਤਰ, directive);

	ਜੇ (iarray != ਨਿਰਾ) {
		*iarray = xrecallocarray(*iarray, *lp, *lp + 1,
		    ਆਕਾਰ(**iarray));
		(*iarray)[*lp] = i;
	}

	*array = xrecallocarray(*array, *lp, *lp + 1, ਆਕਾਰ(**array));
	(*array)[*lp] = xstrdup(s);
	(*lp)++;
}

ਖਾਲੀ
opt_array_append(ਅਚਲ ਅੱਖਰ *file, ਅਚਲ ਪੂਰਨ ਸਤਰ, ਅਚਲ ਅੱਖਰ *directive,
    ਅੱਖਰ ***array, u_int *lp, ਅਚਲ ਅੱਖਰ *s)
{
	opt_array_append2(file, ਸਤਰ, directive, array, ਨਿਰਾ, lp, s, 0);
}

ਖਾਲੀ
opt_array_free2(ਅੱਖਰ **array, ਪੂਰਨ **iarray, u_int l)
{
	u_int i;

	ਜੇ (array == ਨਿਰਾ || l == 0)
		ਵਾਪਸ;
	ਲਈ (i = 0; i < l; i++)
		ਮੁਕਤ(array[i]);
	ਮੁਕਤ(array);
	ਮੁਕਤ(iarray);
}

sshsig_t
ssh_signal(ਪੂਰਨ signum, sshsig_t handler)
{
	ਬਣਤਰ sigaction sa, osa;

	/* mask all other signals while in handler */
	memset(&sa, 0, ਆਕਾਰ(sa));
	sa.sa_handler = handler;
	sigfillset(&sa.sa_mask);
#ਜੇ defined(SA_RESTART) && !defined(NO_SA_RESTART)
	ਜੇ (signum != SIGALRM)
		sa.sa_flags = SA_RESTART;
#ਜੇ_ਅੰਤ
	ਜੇ (sigaction(signum, &sa, &osa) == -1) {
		debug3("sigaction(%s): %s", strsignal(signum), strerror(errno));
		ਵਾਪਸ SIG_ERR;
	}
	ਵਾਪਸ osa.sa_handler;
}

ਪੂਰਨ
stdfd_devnull(ਪੂਰਨ do_stdin, ਪੂਰਨ do_stdout, ਪੂਰਨ do_stderr)
{
	ਪੂਰਨ devnull, ret = 0;

	ਜੇ ((devnull = open(_PATH_DEVNULL, O_RDWR)) == -1) {
		error_f("open %s: %s", _PATH_DEVNULL,
		    strerror(errno));
		ਵਾਪਸ -1;
	}
	ਜੇ ((do_stdin && dup2(devnull, STDIN_FILENO) == -1) ||
	    (do_stdout && dup2(devnull, STDOUT_FILENO) == -1) ||
	    (do_stderr && dup2(devnull, STDERR_FILENO) == -1)) {
		error_f("dup2: %s", strerror(errno));
		ret = -1;
	}
	ਜੇ (devnull > STDERR_FILENO)
		close(devnull);
	ਵਾਪਸ ret;
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
subprocess(ਅਚਲ ਅੱਖਰ *ਟੈਗ, ਅਚਲ ਅੱਖਰ *command,
    ਪੂਰਨ ac, ਅੱਖਰ **av, FILE **ਬੱਚਾ, u_int flags,
    ਬਣਤਰ passwd *pw, privdrop_fn *drop_privs, privrestore_fn *restore_privs)
{
	FILE *f = ਨਿਰਾ;
	ਬਣਤਰ stat st;
	ਪੂਰਨ fd, devnull, p[2], i;
	pid_t pid;
	ਅੱਖਰ *cp, errmsg[512];
	u_int nenv = 0;
	ਅੱਖਰ **env = ਨਿਰਾ;

	/* If dropping privs, then must specify user and restore function */
	ਜੇ (drop_privs != ਨਿਰਾ && (pw == ਨਿਰਾ || restore_privs == ਨਿਰਾ)) {
		error("%s: inconsistent arguments", ਟੈਗ); /* XXX fatal? */
		ਵਾਪਸ 0;
	}
	ਜੇ (pw == ਨਿਰਾ && (pw = getpwuid(getuid())) == ਨਿਰਾ) {
		error("%s: no user for current uid", ਟੈਗ);
		ਵਾਪਸ 0;
	}
	ਜੇ (ਬੱਚਾ != ਨਿਰਾ)
		*ਬੱਚਾ = ਨਿਰਾ;

	debug3_f("%s command \"%s\" running as %s (flags 0x%x)",
	    ਟੈਗ, command, pw->pw_name, flags);

	/* Check consistency */
	ਜੇ ((flags & SSH_SUBPROCESS_STDOUT_DISCARD) != 0 &&
	    (flags & SSH_SUBPROCESS_STDOUT_CAPTURE) != 0) {
		error_f("inconsistent flags");
		ਵਾਪਸ 0;
	}
	ਜੇ (((flags & SSH_SUBPROCESS_STDOUT_CAPTURE) == 0) != (ਬੱਚਾ == ਨਿਰਾ)) {
		error_f("inconsistent flags/output");
		ਵਾਪਸ 0;
	}

	/*
	 * If executing an explicit binary, then verify the it exists
	 * and appears safe-ish to execute
	 */
	ਜੇ (!ਰਸਤਾ_absolute(av[0])) {
		error("%s path is not absolute", ਟੈਗ);
		ਵਾਪਸ 0;
	}
	ਜੇ (drop_privs != ਨਿਰਾ)
		drop_privs(pw);
	ਜੇ (stat(av[0], &st) == -1) {
		error("Could not stat %s \"%s\": %s", ਟੈਗ,
		    av[0], strerror(errno));
		ਜਾਓ restore_return;
	}
	ਜੇ ((flags & SSH_SUBPROCESS_UNSAFE_ਰਸਤਾ) == 0 &&
	    ਸੁਰੱਖਿਅਤ_ਰਸਤਾ(av[0], &st, ਨਿਰਾ, 0, errmsg, ਆਕਾਰ(errmsg)) != 0) {
		error("Unsafe %s \"%s\": %s", ਟੈਗ, av[0], errmsg);
		ਜਾਓ restore_return;
	}
	/* Prepare to keep the child's stdout if requested */
	ਜੇ (pipe(p) == -1) {
		error("%s: pipe: %s", ਟੈਗ, strerror(errno));
 restore_return:
		ਜੇ (restore_privs != ਨਿਰਾ)
			restore_privs();
		ਵਾਪਸ 0;
	}
	ਜੇ (restore_privs != ਨਿਰਾ)
		restore_privs();

	ਚੋਣ ((pid = fork())) {
	ਹਾਲਤ -1: /* error */
		error("%s: fork: %s", ਟੈਗ, strerror(errno));
		close(p[0]);
		close(p[1]);
		ਵਾਪਸ 0;
	ਹਾਲਤ 0: /*ਬੱਚਾ*/
		/* Prepare a minimal environment for the child. */
		ਜੇ ((flags & SSH_SUBPROCESS_PRESERVE_ENV) == 0) {
			nenv = 5;
			env = xcalloc(ਆਕਾਰ(*env), nenv);
			ਬੱਚਾ_ਸੈੱਟ_env(&env, &nenv, "PATH", _PATH_STDPATH);
			ਬੱਚਾ_ਸੈੱਟ_env(&env, &nenv, "USER", pw->pw_name);
			ਬੱਚਾ_ਸੈੱਟ_env(&env, &nenv, "LOGNAME", pw->pw_name);
			ਬੱਚਾ_ਸੈੱਟ_env(&env, &nenv, "HOME", pw->pw_dir);
			ਜੇ ((cp = getenv("LANG")) != ਨਿਰਾ)
				ਬੱਚਾ_ਸੈੱਟ_env(&env, &nenv, "LANG", cp);
		}

		ਲਈ (i = 1; i < NSIG; i++)
			ssh_signal(i, SIG_DFL);

		ਜੇ ((devnull = open(_PATH_DEVNULL, O_RDWR)) == -1) {
			error("%s: open %s: %s", ਟੈਗ, _PATH_DEVNULL,
			    strerror(errno));
			_exit(1);
		}
		ਜੇ (dup2(devnull, STDIN_FILENO) == -1) {
			error("%s: dup2: %s", ਟੈਗ, strerror(errno));
			_exit(1);
		}

		/* Set up stdout as requested; leave stderr in place for now. */
		fd = -1;
		ਜੇ ((flags & SSH_SUBPROCESS_STDOUT_CAPTURE) != 0)
			fd = p[1];
		ਨਹੀਂਤਾਂ ਜੇ ((flags & SSH_SUBPROCESS_STDOUT_DISCARD) != 0)
			fd = devnull;
		ਜੇ (fd != -1 && dup2(fd, STDOUT_FILENO) == -1) {
			error("%s: dup2: %s", ਟੈਗ, strerror(errno));
			_exit(1);
		}
		closefrom(STDERR_FILENO + 1);

		ਜੇ (geteuid() == 0 &&
		    initgroups(pw->pw_name, pw->pw_gid) == -1) {
			error("%s: initgroups(%s, %u): %s", ਟੈਗ,
			    pw->pw_name, (u_int)pw->pw_gid, strerror(errno));
			_exit(1);
		}
		ਜੇ (setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) == -1) {
			error("%s: setresgid %u: %s", ਟੈਗ, (u_int)pw->pw_gid,
			    strerror(errno));
			_exit(1);
		}
		ਜੇ (setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) == -1) {
			error("%s: setresuid %u: %s", ਟੈਗ, (u_int)pw->pw_uid,
			    strerror(errno));
			_exit(1);
		}
		/* stdin is pointed to /dev/null at this point */
		ਜੇ ((flags & SSH_SUBPROCESS_STDOUT_DISCARD) != 0 &&
		    dup2(STDIN_FILENO, STDERR_FILENO) == -1) {
			error("%s: dup2: %s", ਟੈਗ, strerror(errno));
			_exit(1);
		}
		ਜੇ (env != ਨਿਰਾ)
			execve(av[0], av, env);
		ਨਹੀਂਤਾਂ
			execv(av[0], av);
		error("%s %s \"%s\": %s", ਟੈਗ, env == ਨਿਰਾ ? "execv" : "execve",
		    command, strerror(errno));
		_exit(127);
	ਮੂਲ: /*ਮਾਪਾ*/
		ਰੋਕੋ;
	}

	close(p[1]);
	ਜੇ ((flags & SSH_SUBPROCESS_STDOUT_CAPTURE) == 0)
		close(p[0]);
	ਨਹੀਂਤਾਂ ਜੇ ((f = fdopen(p[0], "r")) == ਨਿਰਾ) {
		error("%s: fdopen: %s", ਟੈਗ, strerror(errno));
		close(p[0]);
		/* Don't leave zombie child */
		kill(pid, SIGTERM);
		ਜਦੋਂ (waitpid(pid, ਨਿਰਾ, 0) == -1 && errno == EINTR)
			;
		ਵਾਪਸ 0;
	}
	/* Success */
	debug3_f("%s pid %ld", ਟੈਗ, (ਲੰਮਾ)pid);
	ਜੇ (ਬੱਚਾ != ਨਿਰਾ)
		*ਬੱਚਾ = f;
	ਵਾਪਸ pid;
}

ਅਚਲ ਅੱਖਰ *
lookup_env_ਵਿੱਚ_list(ਅਚਲ ਅੱਖਰ *env, ਅੱਖਰ * ਅਚਲ *envs, ਮਾਪ_t nenvs)
{
	ਮਾਪ_t i, envlen;

	envlen = ਲੜੀ_ਲੰਬਾਈ(env);
	ਲਈ (i = 0; i < nenvs; i++) {
		ਜੇ (ਲੜੀ_ਤੁਲਨਾ(envs[i], env, envlen) == 0 &&
		    envs[i][envlen] == '=') {
			ਵਾਪਸ envs[i] + envlen + 1;
		}
	}
	ਵਾਪਸ ਨਿਰਾ;
}

ਅਚਲ ਅੱਖਰ *
lookup_setenv_ਵਿੱਚ_list(ਅਚਲ ਅੱਖਰ *env, ਅੱਖਰ * ਅਚਲ *envs, ਮਾਪ_t nenvs)
{
	ਅੱਖਰ *name, *cp;
	ਅਚਲ ਅੱਖਰ *ret;

	name = xstrdup(env);
	ਜੇ ((cp = strchr(name, '=')) == ਨਿਰਾ) {
		ਮੁਕਤ(name);
		ਵਾਪਸ ਨਿਰਾ; /* not env=val */
	}
	*cp = '\0';
	ret = lookup_env_ਵਿੱਚ_list(name, envs, nenvs);
	ਮੁਕਤ(name);
	ਵਾਪਸ ret;
}

/*
 * Helpers for managing poll(2)/ppoll(2) timeouts
 * Will remember the earliest deadline and return it for use in poll/ppoll.
 */

/* Initialise a poll/ppoll timeout with an indefinite deadline */
ਖਾਲੀ
ptimeout_init(ਬਣਤਰ timespec *pt)
{
	/*
	 * Deliberately invalid for ppoll(2).
	 * Will be converted to NULL in ptimeout_get_tspec() later.
	 */
	pt->tv_sec = -1;
	pt->tv_nsec = 0;
}

/* Specify a poll/ppoll deadline of at most 'sec' seconds */
ਖਾਲੀ
ptimeout_deadline_sec(ਬਣਤਰ timespec *pt, ਲੰਮਾ sec)
{
	ਜੇ (pt->tv_sec == -1 || pt->tv_sec >= sec) {
		pt->tv_sec = sec;
		pt->tv_nsec = 0;
	}
}

/* Specify a poll/ppoll deadline of at most 'p' (timespec) */
ਸਥਿਰ ਖਾਲੀ
ptimeout_deadline_tsp(ਬਣਤਰ timespec *pt, ਬਣਤਰ timespec *p)
{
	ਜੇ (pt->tv_sec == -1 || timespeccmp(pt, p, >=))
		*pt = *p;
}

/* Specify a poll/ppoll deadline of at most 'ms' milliseconds */
ਖਾਲੀ
ptimeout_deadline_ms(ਬਣਤਰ timespec *pt, ਲੰਮਾ ms)
{
	ਬਣਤਰ timespec p;

	p.tv_sec = ms / 1000;
	p.tv_nsec = (ms % 1000) * 1000000;
	ptimeout_deadline_tsp(pt, &p);
}

/* Specify a poll/ppoll deadline of at most 'sec' seconds (double) */
ਖਾਲੀ
ptimeout_deadline_sec_double(ਬਣਤਰ timespec *pt, ਦੁੱਗਣਾ sec)
{
	ਬਣਤਰ timespec t;

	memset(&t, 0, ਆਕਾਰ(t));
	ਜੇ ((int64_t)sec >= SSH_ਸਮਾਂ_T_MAX)
		t.tv_sec = SSH_ਸਮਾਂ_T_MAX;
	ਨਹੀਂਤਾਂ ਜੇ (sec > 0) {
		t.tv_sec = sec;
		t.tv_nsec = (sec - (ਦੁੱਗਣਾ)t.tv_sec) * 1000000000.0;
	}
	ptimeout_deadline_tsp(pt, &t);
}

/* Specify a poll/ppoll deadline at wall clock monotime 'when' (timespec) */
ਖਾਲੀ
ptimeout_deadline_monotime_tsp(ਬਣਤਰ timespec *pt, ਬਣਤਰ timespec *when)
{
	ਬਣਤਰ timespec now, t;

	monotime_ts(&now);

	ਜੇ (timespeccmp(&now, when, >=)) {
		/* 'when' is now or in the past. Timeout ASAP */
		pt->tv_sec = 0;
		pt->tv_nsec = 0;
	} ਨਹੀਂਤਾਂ {
		timespecsub(when, &now, &t);
		ptimeout_deadline_tsp(pt, &t);
	}
}

/* Specify a poll/ppoll deadline at wall clock monotime 'when' (double) */
ਖਾਲੀ
ptimeout_deadline_monotime_double(ਬਣਤਰ timespec *pt, ਦੁੱਗਣਾ when)
{
	ptimeout_deadline_sec_double(pt, when - monotime_double());
}

/* Specify a poll/ppoll deadline at wall clock monotime 'when' */
ਖਾਲੀ
ptimeout_deadline_monotime(ਬਣਤਰ timespec *pt, time_t when)
{
	ਬਣਤਰ timespec t;

	t.tv_sec = when;
	t.tv_nsec = 0;
	ptimeout_deadline_monotime_tsp(pt, &t);
}

/* Get a poll(2) timeout value in milliseconds */
ਪੂਰਨ
ptimeout_get_ms(ਬਣਤਰ timespec *pt)
{
	ਜੇ (pt->tv_sec == -1)
		ਵਾਪਸ -1;
	ਜੇ (pt->tv_sec >= (ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ - (pt->tv_nsec / 1000000)) / 1000)
		ਵਾਪਸ ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ;
	ਵਾਪਸ (pt->tv_sec * 1000) + (pt->tv_nsec / 1000000);
}

/* Get a ppoll(2) timeout value as a timespec pointer */
ਬਣਤਰ timespec *
ptimeout_get_tsp(ਬਣਤਰ timespec *pt)
{
	ਵਾਪਸ pt->tv_sec == -1 ? ਨਿਰਾ : pt;
}

/* Returns non-zero if a timeout has been set (i.e. is not indefinite) */
ਪੂਰਨ
ptimeout_isset(ਬਣਤਰ timespec *pt)
{
	ਵਾਪਸ pt->tv_sec != -1;
}

/*
 * Returns zero if the library at 'path' contains symbol 's', nonzero
 * otherwise.
 */
ਪੂਰਨ
lib_ਸ਼ਾਮਲ_ਹੈ_ਚਿੰਨ੍ਹ(ਅਚਲ ਅੱਖਰ *ਰਸਤਾ, ਅਚਲ ਅੱਖਰ *s)
{
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_NLIST
	ਬਣਤਰ nlist nl[2];
	ਪੂਰਨ ret = -1, r;

	memset(nl, 0, ਆਕਾਰ(nl));
	nl[0].n_name = xstrdup(s);
	nl[1].n_name = ਨਿਰਾ;
	ਜੇ ((r = nlist(ਰਸਤਾ, nl)) == -1) {
		error_f("nlist failed for %s", ਰਸਤਾ);
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (r != 0 || nl[0].n_ਮੁੱਲ == 0 || nl[0].n_type == 0) {
		error_f("library %s does not contain symbol %s", ਰਸਤਾ, s);
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/* success */
	ret = 0;
 ਬਾਹਰਲਾ:
	ਮੁਕਤ(nl[0].n_name);
	ਵਾਪਸ ret;
#ਨਹੀਂਤਾਂ /* HAVE_NLIST */
	ਪੂਰਨ fd, ret = -1;
	ਬਣਤਰ stat st;
	ਖਾਲੀ *m = ਨਿਰਾ;
	ਮਾਪ_t sz = 0;

	memset(&st, 0, ਆਕਾਰ(st));
	ਜੇ ((fd = open(ਰਸਤਾ, O_RDONLY)) < 0) {
		error_f("open %s: %s", ਰਸਤਾ, strerror(errno));
		ਵਾਪਸ -1;
	}
	ਜੇ (fstat(fd, &st) != 0) {
		error_f("fstat %s: %s", ਰਸਤਾ, strerror(errno));
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (!S_ISREG(st.st_mode)) {
		error_f("%s is not a regular file", ਰਸਤਾ);
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (st.st_size < 0 ||
	    (ਮਾਪ_t)st.st_size < ਲੜੀ_ਲੰਬਾਈ(s) ||
	    st.st_size >= ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ/2) {
		error_f("%s bad size %lld", ਰਸਤਾ, (ਲੰਮਾ ਲੰਮਾ)st.st_size);
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	sz = (ਮਾਪ_t)st.st_size;
	ਜੇ ((m = mmap(ਨਿਰਾ, sz, PROT_READ, MAP_PRIVATE, fd, 0)) == MAP_FAILED ||
	    m == ਨਿਰਾ) {
		error_f("mmap %s: %s", ਰਸਤਾ, strerror(errno));
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (memmem(m, sz, s, ਲੜੀ_ਲੰਬਾਈ(s)) == ਨਿਰਾ) {
		error_f("%s does not contain expected string %s", ਰਸਤਾ, s);
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/* success */
	ret = 0;
 ਬਾਹਰਲਾ:
	ਜੇ (m != ਨਿਰਾ && m != MAP_FAILED)
		munmap(m, sz);
	close(fd);
	ਵਾਪਸ ret;
#ਜੇ_ਅੰਤ /* HAVE_NLIST */
}

ਪੂਰਨ
signal_is_crash(ਪੂਰਨ sig)
{
	ਚੋਣ (sig) {
	ਹਾਲਤ SIGSEGV:
	ਹਾਲਤ SIGBUS:
	ਹਾਲਤ SIGTRAP:
	ਹਾਲਤ SIGSYS:
	ਹਾਲਤ SIGFPE:
	ਹਾਲਤ SIGILL:
	ਹਾਲਤ SIGABRT:
		ਵਾਪਸ 1;
	}
	ਵਾਪਸ 0;
}

ਅੱਖਰ *
get_homedir(ਖਾਲੀ)
{
	ਅੱਖਰ *cp;
	ਬਣਤਰ passwd *pw;

	ਜੇ ((cp = getenv("HOME")) != ਨਿਰਾ && *cp != '\0')
		ਵਾਪਸ xstrdup(cp);

	ਜੇ ((pw = getpwuid(getuid())) != ਨਿਰਾ && *pw->pw_dir != '\0')
		ਵਾਪਸ xstrdup(pw->pw_dir);

	ਵਾਪਸ ਨਿਰਾ;
}

ਪੂਰਨ
mkdir_ਰਸਤਾ(ਅਚਲ ਅੱਖਰ *ਨਿਸ਼ਾਨਾ, ਬਹੁਲਕ_t ਬਹੁਲਕ)
{
#ਜੇ defined(HAVE_OPENAT) && defined(O_DIRECTORY)
	ਅੱਖਰ *dir, *odir = ਨਿਰਾ, *ਅਗਲਾ;
	ਪੂਰਨ fd = AT_FDCWD, fd2, subpath_len, ret = -1;

	dir = odir = xstrdup(ਨਿਸ਼ਾਨਾ);

	ਜੇ (*dir == '/' &&
	    (fd = open("/", O_RDONLY|O_DIRECTORY)) == -1) {
		error_f("open(\"/\"): %s", strerror(errno));
		ਮੁਕਤ(odir);
		ਵਾਪਸ -1;
	}
	/* Work through the path, component-wise */
	ਲਈ (; dir != ਨਿਰਾ && *dir != '\0'; dir = ਅਗਲਾ) {
		ਜੇ ((ਅਗਲਾ = strchr(dir, '/')) != ਨਿਰਾ)
			*(ਅਗਲਾ++) = '\0';
		ਜੇ (*dir == '\0')
			ਜਾਰੀ;
		subpath_len = (ਅਗਲਾ == ਨਿਰਾ) ? ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ : ਅਗਲਾ - odir - 1;
		ਜੇ (mkdirat(fd, dir, ਬਹੁਲਕ) == 0)
			debug_f("created directory %.*s", subpath_len, ਨਿਸ਼ਾਨਾ);
		ਨਹੀਂਤਾਂ ਜੇ (errno != EEXIST) {
			error_f("mkdir(\"%.*s\"): %s",
			    subpath_len, ਨਿਸ਼ਾਨਾ, strerror(errno));
			ਜਾਓ ਬਾਹਰਲਾ;
		}

		/* descend */
		ਜੇ ((fd2 = openat(fd, dir, O_RDONLY|O_DIRECTORY)) == -1) {
			error_f("open(\"%.*s\"): %s",
			    subpath_len, ਨਿਸ਼ਾਨਾ, strerror(errno));
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ (fd != AT_FDCWD)
			close(fd);
		fd = fd2;
	}
	/* success */
	ret = 0;
 ਬਾਹਰਲਾ:
	ਮੁਕਤ(odir);
	ਜੇ (fd != AT_FDCWD)
		close(fd);
	ਵਾਪਸ ret;
#ਨਹੀਂਤਾਂ
	/*
	 * If we don't have openat (which was added in POSIX.1-2008), fall back
	 * to the possibly racy way.
	 */
	ਅੱਖਰ *dir, *odir, *p, ਰਸਤਾ[PATH_MAX] = "";
	ਪੂਰਨ ret = -1;
	ਮਾਪ_t plen = ਆਕਾਰ(ਰਸਤਾ);

	dir = odir = xstrdup(ਨਿਸ਼ਾਨਾ);

	/* If the dir is relative, start with cwd. */
	ਜੇ (*dir != '/' && getcwd(ਰਸਤਾ, plen) == ਨਿਰਾ) {
		error_f("getcwd: %s", strerror(errno));
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	/* Work through the path, component-wise */
	ਜਦੋਂ ((p = strsep(&dir, "/"))) {
		ਜੇ (*p == '\0')
			ਜਾਰੀ;
		ਜੇ (strlcat(ਰਸਤਾ, "/", plen) >= plen ||
		    strlcat(ਰਸਤਾ, p, plen) >= plen)
			ਜਾਓ ਬਾਹਰਲਾ;
		ਜੇ (mkdir(ਰਸਤਾ, ਬਹੁਲਕ) == 0)
			debug_f("created directory %s", ਰਸਤਾ);
		ਨਹੀਂਤਾਂ ਜੇ (errno != EEXIST && errno != EISDIR) {
			error_f("mkdir(\"%s\"): %s", ਰਸਤਾ, strerror(errno));
			ਜਾਓ ਬਾਹਰਲਾ;
		}
	}
	/* success */
	ret = 0;
 ਬਾਹਰਲਾ:
	ਮੁਕਤ(odir);
	ਵਾਪਸ ret;
#ਜੇ_ਅੰਤ
}
