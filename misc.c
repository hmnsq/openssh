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


#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/ioctl.h>
#ಅನ್ತರ್ಭಾವ <sys/mman.h>
#ಅನ್ತರ್ಭಾವ <sys/socket.h>
#ಅನ್ತರ್ಭಾವ <sys/stat.h>
#ಅನ್ತರ್ಭಾವ <sys/time.h>
#ಅನ್ತರ್ಭಾವ <sys/wait.h>
#ಅನ್ತರ್ಭಾವ <sys/un.h>

#ಅನ್ತರ್ಭಾವ <limits.h>
#ಅನ್ತರ್ಭಾವ <libgen.h>
#ಅನ್ತರ್ಭಾವ <poll.h>
#ಅನ್ತರ್ಭಾವ <nlist.h>
#ಅನ್ತರ್ಭಾವ <signal.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <time.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>

#ಅನ್ತರ್ಭಾವ <netinet/in.h>
#ಅನ್ತರ್ಭಾವ <netinet/ip.h>
#ಅನ್ತರ್ಭಾವ <netinet/tcp.h>
#ಅನ್ತರ್ಭಾವ <arpa/inet.h>

#ಅನ್ತರ್ಭಾವ <ctype.h>
#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <fcntl.h>
#ಅನ್ತರ್ಭಾವ <netdb.h>
#ಅನ್ತರ್ಭಾವ <paths.h>
#ಅನ್ತರ್ಭಾವ <pwd.h>
#ಅನ್ತರ್ಭಾವ <grp.h>
#ifdef SSH_TUN_OPENBSD
#ಅನ್ತರ್ಭಾವ <net/if.h>
#endif

#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "ssh.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "platform.h"

/* remove newline at end of string */
ವರ್ಣ *
chop(ವರ್ಣ *s)
{
	ವರ್ಣ *t = s;
	ಯಾವತ್ (*t) {
		ಯದಿ (*t == '\n' || *t == '\r') {
			*t = '\0';
			ಪ್ರತ್ಯಾಗಮ s;
		}
		t++;
	}
	ಪ್ರತ್ಯಾಗಮ s;

}

/* remove whitespace from end of string */
ಶೂನ್ಯ
rtrim(ವರ್ಣ *s)
{
	size_t i;

	ಯದಿ ((i = strlen(s)) == 0)
		ಪ್ರತ್ಯಾಗಮ;
	ಕುರು {
		i--;
		ಯದಿ (isspace((unsigned ವರ್ಣ)s[i]))
			s[i] = '\0';
		ಅನ್ಯಥಾ
			ಭಙ್ಗ;
	} ಯಾವತ್ (i > 0);
}

/*
 * returns pointer to character after 'prefix' in 's' or otherwise NULL
 * if the prefix is not present.
 */
ಧ್ರುವ ವರ್ಣ *
strprefix(ಧ್ರುವ ವರ್ಣ *s, ಧ್ರುವ ವರ್ಣ *prefix, ಪೂರ್ಣಾಙ್ಕ ignorecase)
{
	size_t prefixlen;

	ಯದಿ ((prefixlen = strlen(prefix)) == 0)
		ಪ್ರತ್ಯಾಗಮ s;
	ಯದಿ (ignorecase) {
		ಯದಿ (strncasecmp(s, prefix, prefixlen) != 0)
			ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	} ಅನ್ಯಥಾ {
		ಯದಿ (strncmp(s, prefix, prefixlen) != 0)
			ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}
	ಪ್ರತ್ಯಾಗಮ s + prefixlen;
}

/* Append string 's' to a NULL-terminated array of strings */
ಶೂನ್ಯ
stringlist_append(ವರ್ಣ ***listp, ಧ್ರುವ ವರ್ಣ *s)
{
	size_t i = 0;

	ಯದಿ (*listp == ರಿಕ್ತ)
		*listp = xcalloc(2, ಪರಿಮಾಣ(**listp));
	ಅನ್ಯಥಾ {
		ಪ್ರತಿ (i = 0; (*listp)[i] != ರಿಕ್ತ; i++)
			; /* count */
		*listp = xrecallocarray(*listp, i + 1, i + 2, ಪರಿಮಾಣ(**listp));
	}
	(*listp)[i] = xstrdup(s);
}

ಶೂನ್ಯ
stringlist_free(ವರ್ಣ **list)
{
	size_t i = 0;

	ಯದಿ (list == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;
	ಪ್ರತಿ (i = 0; list[i] != ರಿಕ್ತ; i++)
		ಮುಕ್ತ(list[i]);
	ಮುಕ್ತ(list);
}

/* set/unset filedescriptor to non-blocking */
ಪೂರ್ಣಾಙ್ಕ
set_nonblock(ಪೂರ್ಣಾಙ್ಕ fd)
{
	ಪೂರ್ಣಾಙ್ಕ val;

	val = fcntl(fd, F_GETFL);
	ಯದಿ (val == -1) {
		error("fcntl(%d, F_GETFL): %s", fd, strerror(errno));
		ಪ್ರತ್ಯಾಗಮ (-1);
	}
	ಯದಿ (val & O_NONBLOCK) {
		debug3("fd %d is O_NONBLOCK", fd);
		ಪ್ರತ್ಯಾಗಮ (0);
	}
	debug2("fd %d setting O_NONBLOCK", fd);
	val |= O_NONBLOCK;
	ಯದಿ (fcntl(fd, F_SETFL, val) == -1) {
		debug("fcntl(%d, F_SETFL, O_NONBLOCK): %s", fd,
		    strerror(errno));
		ಪ್ರತ್ಯಾಗಮ (-1);
	}
	ಪ್ರತ್ಯಾಗಮ (0);
}

ಪೂರ್ಣಾಙ್ಕ
unset_nonblock(ಪೂರ್ಣಾಙ್ಕ fd)
{
	ಪೂರ್ಣಾಙ್ಕ val;

	val = fcntl(fd, F_GETFL);
	ಯದಿ (val == -1) {
		error("fcntl(%d, F_GETFL): %s", fd, strerror(errno));
		ಪ್ರತ್ಯಾಗಮ (-1);
	}
	ಯದಿ (!(val & O_NONBLOCK)) {
		debug3("fd %d is not O_NONBLOCK", fd);
		ಪ್ರತ್ಯಾಗಮ (0);
	}
	debug("fd %d clearing O_NONBLOCK", fd);
	val &= ~O_NONBLOCK;
	ಯದಿ (fcntl(fd, F_SETFL, val) == -1) {
		debug("fcntl(%d, F_SETFL, ~O_NONBLOCK): %s",
		    fd, strerror(errno));
		ಪ್ರತ್ಯಾಗಮ (-1);
	}
	ಪ್ರತ್ಯಾಗಮ (0);
}

ಧ್ರುವ ವರ್ಣ *
ssh_gai_strerror(ಪೂರ್ಣಾಙ್ಕ gaierr)
{
	ಯದಿ (gaierr == EAI_SYSTEM && errno != 0)
		ಪ್ರತ್ಯಾಗಮ strerror(errno);
	ಪ್ರತ್ಯಾಗಮ gai_strerror(gaierr);
}

/* disable nagle on socket */
ಶೂನ್ಯ
set_nodelay(ಪೂರ್ಣಾಙ್ಕ fd)
{
	ಪೂರ್ಣಾಙ್ಕ opt;
	socklen_t optlen;

	optlen = ಪರಿಮಾಣ opt;
	ಯದಿ (getsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, &optlen) == -1) {
		debug("getsockopt TCP_NODELAY: %.100s", strerror(errno));
		ಪ್ರತ್ಯಾಗಮ;
	}
	ಯದಿ (opt == 1) {
		debug2("fd %d is TCP_NODELAY", fd);
		ಪ್ರತ್ಯಾಗಮ;
	}
	opt = 1;
	debug2("fd %d setting TCP_NODELAY", fd);
	ಯದಿ (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, ಪರಿಮಾಣ opt) == -1)
		error("setsockopt TCP_NODELAY: %.100s", strerror(errno));
}

/* Allow local port reuse in TIME_WAIT */
ಪೂರ್ಣಾಙ್ಕ
set_reuseaddr(ಪೂರ್ಣಾಙ್ಕ fd)
{
	ಪೂರ್ಣಾಙ್ಕ on = 1;

	ಯದಿ (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, ಪರಿಮಾಣ(on)) == -1) {
		error("setsockopt SO_REUSEADDR fd %d: %s", fd, strerror(errno));
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

/* Set TCP keepalives */
ಪೂರ್ಣಾಙ್ಕ
set_keepalive(ಪೂರ್ಣಾಙ್ಕ fd)
{
	ಪೂರ್ಣಾಙ್ಕ on = 1;

	ಯದಿ (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, ಪರಿಮಾಣ(on)) == -1) {
		error("setsockopt SO_KEEPALIVE fd %d: %s", fd, strerror(errno));
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

/* Get/set routing domain */
ವರ್ಣ *
get_rdomain(ಪೂರ್ಣಾಙ್ಕ fd)
{
#ಯದಿ defined(HAVE_SYS_GET_RDOMAIN)
	ಪ್ರತ್ಯಾಗಮ sys_get_rdomain(fd);
#ನೋಚೇದ್ಯದಿ defined(__OpenBSD__)
	ಪೂರ್ಣಾಙ್ಕ rtable;
	ವರ್ಣ *ret;
	socklen_t len = ಪರಿಮಾಣ(rtable);

	ಯದಿ (getsockopt(fd, SOL_SOCKET, SO_RTABLE, &rtable, &len) == -1) {
		error("Failed to get routing domain for fd %d: %s",
		    fd, strerror(errno));
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}
	xasprintf(&ret, "%d", rtable);
	ಪ್ರತ್ಯಾಗಮ ret;
#ಅನ್ಯಥಾ /* defined(__OpenBSD__) */
	ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
#endif
}

ಪೂರ್ಣಾಙ್ಕ
set_rdomain(ಪೂರ್ಣಾಙ್ಕ fd, ಧ್ರುವ ವರ್ಣ *name)
{
#ಯದಿ defined(HAVE_SYS_SET_RDOMAIN)
	ಪ್ರತ್ಯಾಗಮ sys_set_rdomain(fd, name);
#ನೋಚೇದ್ಯದಿ defined(__OpenBSD__)
	ಪೂರ್ಣಾಙ್ಕ rtable;
	ಧ್ರುವ ವರ್ಣ *errstr;

	ಯದಿ (name == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ 0; /* default table */

	rtable = (ಪೂರ್ಣಾಙ್ಕ)strtonum(name, 0, 255, &errstr);
	ಯದಿ (errstr != ರಿಕ್ತ) {
		/* Shouldn't happen */
		error("Invalid routing domain \"%s\": %s", name, errstr);
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	ಯದಿ (setsockopt(fd, SOL_SOCKET, SO_RTABLE,
	    &rtable, ಪರಿಮಾಣ(rtable)) == -1) {
		error("Failed to set routing domain %d on fd %d: %s",
		    rtable, fd, strerror(errno));
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
#ಅನ್ಯಥಾ /* defined(__OpenBSD__) */
	error("Setting routing domain is not supported on this platform");
	ಪ್ರತ್ಯಾಗಮ -1;
#endif
}

ಪೂರ್ಣಾಙ್ಕ
get_sock_af(ಪೂರ್ಣಾಙ್ಕ fd)
{
	ಸಂರಚನಾ sockaddr_storage to;
	socklen_t tolen = ಪರಿಮಾಣ(to);

	memset(&to, 0, ಪರಿಮಾಣ(to));
	ಯದಿ (getsockname(fd, (ಸಂರಚನಾ sockaddr *)&to, &tolen) == -1)
		ಪ್ರತ್ಯಾಗಮ -1;
#ifdef IPV4_IN_IPV6
	ಯದಿ (to.ss_family == AF_INET6 &&
	    IN6_IS_ADDR_V4MAPPED(&((ಸಂರಚನಾ sockaddr_in6 *)&to)->sin6_addr))
		ಪ್ರತ್ಯಾಗಮ AF_INET;
#endif
	ಪ್ರತ್ಯಾಗಮ to.ss_family;
}

ಶೂನ್ಯ
set_sock_tos(ಪೂರ್ಣಾಙ್ಕ fd, ಪೂರ್ಣಾಙ್ಕ tos)
{
#ifndef IP_TOS_IS_BROKEN
	ಪೂರ್ಣಾಙ್ಕ af;

	ಯದಿ (tos < 0 || tos == INT_MAX) {
		debug_f("invalid TOS %d", tos);
		ಪ್ರತ್ಯಾಗಮ;
	}
	ವಿಕಲ್ಪ ((af = get_sock_af(fd))) {
	ಪಕ್ಷ -1:
		/* assume not a socket */
		ಭಙ್ಗ;
	ಪಕ್ಷ AF_INET:
# ifdef IP_TOS
		debug3_f("set socket %d IP_TOS 0x%02x", fd, tos);
		ಯದಿ (setsockopt(fd, IPPROTO_IP, IP_TOS,
		    &tos, ಪರಿಮಾಣ(tos)) == -1) {
			error("setsockopt socket %d IP_TOS %d: %s",
			    fd, tos, strerror(errno));
		}
# endif /* IP_TOS */
		ಭಙ್ಗ;
	ಪಕ್ಷ AF_INET6:
# ifdef IPV6_TCLASS
		debug3_f("set socket %d IPV6_TCLASS 0x%02x", fd, tos);
		ಯದಿ (setsockopt(fd, IPPROTO_IPV6, IPV6_TCLASS,
		    &tos, ಪರಿಮಾಣ(tos)) == -1) {
			error("setsockopt socket %d IPV6_TCLASS %d: %s",
			    fd, tos, strerror(errno));
		}
# endif /* IPV6_TCLASS */
		ಭಙ್ಗ;
	ಸ್ವಭಾವ:
		debug2_f("unsupported socket family %d", af);
		ಭಙ್ಗ;
	}
#endif /* IP_TOS_IS_BROKEN */
}

/*
 * Wait up to *timeoutp milliseconds for events on fd. Updates
 * *timeoutp with time remaining.
 * Returns 0 if fd ready or -1 on timeout or error (see errno).
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
waitfd(ಪೂರ್ಣಾಙ್ಕ fd, ಪೂರ್ಣಾಙ್ಕ *timeoutp, short events, ಚಞ್ಚಲ sig_atomic_t *stop)
{
	ಸಂರಚನಾ pollfd pfd;
	ಸಂರಚನಾ timespec timeout;
	ಪೂರ್ಣಾಙ್ಕ oerrno, r;
	sigset_t nsigset, osigset;

	ಯದಿ (timeoutp && *timeoutp == -1)
		timeoutp = ರಿಕ್ತ;
	pfd.fd = fd;
	pfd.events = events;
	ptimeout_init(&timeout);
	ಯದಿ (timeoutp != ರಿಕ್ತ)
		ptimeout_deadline_ms(&timeout, *timeoutp);
	ಯದಿ (stop != ರಿಕ್ತ)
		sigfillset(&nsigset);
	ಪ್ರತಿ (; timeoutp == ರಿಕ್ತ || *timeoutp >= 0;) {
		ಯದಿ (stop != ರಿಕ್ತ) {
			sigprocmask(SIG_BLOCK, &nsigset, &osigset);
			ಯದಿ (*stop) {
				sigprocmask(SIG_SETMASK, &osigset, ರಿಕ್ತ);
				errno = EINTR;
				ಪ್ರತ್ಯಾಗಮ -1;
			}
		}
		r = ppoll(&pfd, 1, ptimeout_get_tsp(&timeout),
		    stop != ರಿಕ್ತ ? &osigset : ರಿಕ್ತ);
		oerrno = errno;
		ಯದಿ (stop != ರಿಕ್ತ)
			sigprocmask(SIG_SETMASK, &osigset, ರಿಕ್ತ);
		ಯದಿ (timeoutp)
			*timeoutp = ptimeout_get_ms(&timeout);
		errno = oerrno;
		ಯದಿ (r > 0)
			ಪ್ರತ್ಯಾಗಮ 0;
		ಅನ್ಯಥಾ ಯದಿ (r == -1 && errno != EAGAIN && errno != EINTR)
			ಪ್ರತ್ಯಾಗಮ -1;
		ಅನ್ಯಥಾ ಯದಿ (r == 0)
			ಭಙ್ಗ;
	}
	/* timeout */
	errno = ETIMEDOUT;
	ಪ್ರತ್ಯಾಗಮ -1;
}

/*
 * Wait up to *timeoutp milliseconds for fd to be readable. Updates
 * *timeoutp with time remaining.
 * Returns 0 if fd ready or -1 on timeout or error (see errno).
 */
ಪೂರ್ಣಾಙ್ಕ
waitrfd(ಪೂರ್ಣಾಙ್ಕ fd, ಪೂರ್ಣಾಙ್ಕ *timeoutp, ಚಞ್ಚಲ sig_atomic_t *stop) {
	ಪ್ರತ್ಯಾಗಮ waitfd(fd, timeoutp, POLLIN, stop);
}

/*
 * Attempt a non-blocking connect(2) to the specified address, waiting up to
 * *timeoutp milliseconds for the connection to complete. If the timeout is
 * <=0, then wait indefinitely.
 *
 * Returns 0 on success or -1 on failure.
 */
ಪೂರ್ಣಾಙ್ಕ
timeout_connect(ಪೂರ್ಣಾಙ್ಕ sockfd, ಧ್ರುವ ಸಂರಚನಾ sockaddr *serv_addr,
    socklen_t addrlen, ಪೂರ್ಣಾಙ್ಕ *timeoutp)
{
	ಪೂರ್ಣಾಙ್ಕ optval = 0;
	socklen_t optlen = ಪರಿಮಾಣ(optval);

	/* No timeout: just do a blocking connect() */
	ಯದಿ (timeoutp == ರಿಕ್ತ || *timeoutp <= 0)
		ಪ್ರತ್ಯಾಗಮ connect(sockfd, serv_addr, addrlen);

	set_nonblock(sockfd);
	ಪ್ರತಿ (;;) {
		ಯದಿ (connect(sockfd, serv_addr, addrlen) == 0) {
			/* Succeeded already? */
			unset_nonblock(sockfd);
			ಪ್ರತ್ಯಾಗಮ 0;
		} ಅನ್ಯಥಾ ಯದಿ (errno == EINTR)
			ಅನುವರ್ತ;
		ಅನ್ಯಥಾ ಯದಿ (errno != EINPROGRESS)
			ಪ್ರತ್ಯಾಗಮ -1;
		ಭಙ್ಗ;
	}

	ಯದಿ (waitfd(sockfd, timeoutp, POLLIN | POLLOUT, ರಿಕ್ತ) == -1)
		ಪ್ರತ್ಯಾಗಮ -1;

	/* Completed or failed */
	ಯದಿ (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &optval, &optlen) == -1) {
		debug("getsockopt: %s", strerror(errno));
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	ಯದಿ (optval != 0) {
		errno = optval;
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	unset_nonblock(sockfd);
	ಪ್ರತ್ಯಾಗಮ 0;
}

/* Characters considered whitespace in strsep calls. */
#define WHITESPACE " \t\r\n"
#define QUOTE	"\""

/* return next token in configuration line */
ಸ್ಥಿರ ವರ್ಣ *
strdelim_internal(ವರ್ಣ **s, ಪೂರ್ಣಾಙ್ಕ split_equals)
{
	ವರ್ಣ *old;
	ಪೂರ್ಣಾಙ್ಕ wspace = 0;

	ಯದಿ (*s == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;

	old = *s;

	*s = strpbrk(*s,
	    split_equals ? WHITESPACE QUOTE "=" : WHITESPACE QUOTE);
	ಯದಿ (*s == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ (old);

	ಯದಿ (*s[0] == '\"') {
		memmove(*s, *s + 1, strlen(*s)); /* move nul too */
		/* Find matching quote */
		ಯದಿ ((*s = strpbrk(*s, QUOTE)) == ರಿಕ್ತ) {
			ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);		/* no matching quote */
		} ಅನ್ಯಥಾ {
			*s[0] = '\0';
			*s += strspn(*s + 1, WHITESPACE) + 1;
			ಪ್ರತ್ಯಾಗಮ (old);
		}
	}

	/* Allow only one '=' to be skipped */
	ಯದಿ (split_equals && *s[0] == '=')
		wspace = 1;
	*s[0] = '\0';

	/* Skip any extra whitespace after first token */
	*s += strspn(*s + 1, WHITESPACE) + 1;
	ಯದಿ (split_equals && *s[0] == '=' && !wspace)
		*s += strspn(*s + 1, WHITESPACE) + 1;

	ಪ್ರತ್ಯಾಗಮ (old);
}

/*
 * Return next token in configuration line; splits on whitespace or a
 * single '=' character.
 */
ವರ್ಣ *
strdelim(ವರ್ಣ **s)
{
	ಪ್ರತ್ಯಾಗಮ strdelim_internal(s, 1);
}

/*
 * Return next token in configuration line; splits on whitespace only.
 */
ವರ್ಣ *
strdelimw(ವರ್ಣ **s)
{
	ಪ್ರತ್ಯಾಗಮ strdelim_internal(s, 0);
}

ಸಂರಚನಾ passwd *
pwcopy(ಸಂರಚನಾ passwd *pw)
{
	ಸಂರಚನಾ passwd *copy = xcalloc(1, ಪರಿಮಾಣ(*copy));

	copy->pw_name = xstrdup(pw->pw_name);
	copy->pw_passwd = xstrdup(pw->pw_passwd == ರಿಕ್ತ ? "*" : pw->pw_passwd);
#ifdef HAVE_STRUCT_PASSWD_PW_GECOS
	copy->pw_gecos = xstrdup(pw->pw_gecos == ರಿಕ್ತ ? "" : pw->pw_gecos);
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
	copy->pw_class = xstrdup(pw->pw_class == ರಿಕ್ತ ? "" : pw->pw_class);
#endif
	copy->pw_dir = xstrdup(pw->pw_dir == ರಿಕ್ತ ? "" : pw->pw_dir);
	copy->pw_shell = xstrdup(pw->pw_shell == ರಿಕ್ತ ? "" : pw->pw_shell);
	ಪ್ರತ್ಯಾಗಮ copy;
}

ಶೂನ್ಯ
pwfree(ಸಂರಚನಾ passwd *pw)
{
	ಯದಿ (pw == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;
	ಮುಕ್ತ(pw->pw_name);
	freezero(pw->pw_passwd,
	    pw->pw_passwd == ರಿಕ್ತ ? 0 : strlen(pw->pw_passwd));
#ifdef HAVE_STRUCT_PASSWD_PW_GECOS
	ಮುಕ್ತ(pw->pw_gecos);
#endif
#ifdef HAVE_STRUCT_PASSWD_PW_CLASS
	ಮುಕ್ತ(pw->pw_class);
#endif
	ಮುಕ್ತ(pw->pw_dir);
	ಮುಕ್ತ(pw->pw_shell);
	freezero(pw, ಪರಿಮಾಣ(*pw));
}

/*
 * Convert ASCII string to TCP/IP port number.
 * Port must be >=0 and <=65535.
 * Return -1 if invalid.
 */
ಪೂರ್ಣಾಙ್ಕ
a2port(ಧ್ರುವ ವರ್ಣ *s)
{
	ಸಂರಚನಾ servent *se;
	long long port;
	ಧ್ರುವ ವರ್ಣ *errstr;

	port = strtonum(s, 0, 65535, &errstr);
	ಯದಿ (errstr == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ (ಪೂರ್ಣಾಙ್ಕ)port;
	ಯದಿ ((se = getservbyname(s, "tcp")) != ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ ntohs(se->s_port);
	ಪ್ರತ್ಯಾಗಮ -1;
}

ಪೂರ್ಣಾಙ್ಕ
a2tun(ಧ್ರುವ ವರ್ಣ *s, ಪೂರ್ಣಾಙ್ಕ *remote)
{
	ಧ್ರುವ ವರ್ಣ *errstr = ರಿಕ್ತ;
	ವರ್ಣ *sp, *ep;
	ಪೂರ್ಣಾಙ್ಕ tun;

	ಯದಿ (remote != ರಿಕ್ತ) {
		*remote = SSH_TUNID_ANY;
		sp = xstrdup(s);
		ಯದಿ ((ep = strchr(sp, ':')) == ರಿಕ್ತ) {
			ಮುಕ್ತ(sp);
			ಪ್ರತ್ಯಾಗಮ (a2tun(s, ರಿಕ್ತ));
		}
		ep[0] = '\0'; ep++;
		*remote = a2tun(ep, ರಿಕ್ತ);
		tun = a2tun(sp, ರಿಕ್ತ);
		ಮುಕ್ತ(sp);
		ಪ್ರತ್ಯಾಗಮ (*remote == SSH_TUNID_ERR ? *remote : tun);
	}

	ಯದಿ (strcasecmp(s, "any") == 0)
		ಪ್ರತ್ಯಾಗಮ (SSH_TUNID_ANY);

	tun = strtonum(s, 0, SSH_TUNID_MAX, &errstr);
	ಯದಿ (errstr != ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ (SSH_TUNID_ERR);

	ಪ್ರತ್ಯಾಗಮ (tun);
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
ದ್ವಿಗುಣ
convtime_double(ಧ್ರುವ ವರ್ಣ *s)
{
	ದ್ವಿಗುಣ val, total_sec = 0.0, multiplier;
	ಧ್ರುವ ವರ್ಣ *p, *start_p;
	ವರ್ಣ *endp;
	ಪೂರ್ಣಾಙ್ಕ seen_seconds = 0;

	ಯದಿ (s == ರಿಕ್ತ || *s == '\0')
		ಪ್ರತ್ಯಾಗಮ -1.0;

	ಪ್ರತಿ (p = s; *p != '\0';) {
		ಯದಿ (!isdigit((unsigned ವರ್ಣ)*p) && *p != '.')
			ಪ್ರತ್ಯಾಗಮ -1.0;

		errno = 0;
		ಯದಿ ((val = strtod(p, &endp)) < 0 || errno != 0 || p == endp)
			ಪ್ರತ್ಯಾಗಮ -1.0;
		/* Allow only decimal forms */
		ಯದಿ (p + strspn(p, "0123456789.") != endp)
			ಪ್ರತ್ಯಾಗಮ -1.0;
		start_p = p;
		p = endp;

		ವಿಕಲ್ಪ (*p) {
		ಪಕ್ಷ '\0':
			/* FALLTHROUGH */
		ಪಕ್ಷ 's':
		ಪಕ್ಷ 'S':
			ಯದಿ (seen_seconds++)
				ಪ್ರತ್ಯಾಗಮ -1.0;
			multiplier = SECONDS;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'm':
		ಪಕ್ಷ 'M':
			multiplier = MINUTES;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'h':
		ಪಕ್ಷ 'H':
			multiplier = HOURS;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'd':
		ಪಕ್ಷ 'D':
			multiplier = DAYS;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'w':
		ಪಕ್ಷ 'W':
			multiplier = WEEKS;
			ಭಙ್ಗ;
		ಸ್ವಭಾವ:
			ಪ್ರತ್ಯಾಗಮ -1.0;
		}

		/* Special handling if this was a decimal */
		ಯದಿ (memchr(start_p, '.', endp - start_p) != ರಿಕ್ತ) {
			/* Decimal point present */
			ಯದಿ (multiplier > 1.0)
				ಪ್ರತ್ಯಾಗಮ -1.0; /* No fractionals for non-seconds */
			/* For seconds, ensure digits follow */
			ಯದಿ (!isdigit((unsigned ವರ್ಣ)*(endp - 1)))
				ಪ್ರತ್ಯಾಗಮ -1.0;
		}

		total_sec += val * multiplier;

		ಯದಿ (*p != '\0')
			p++;
	}
	ಪ್ರತ್ಯಾಗಮ total_sec;
}

/*
 * Same as convtime_double() above but fractional seconds are ignored.
 * Return -1 if time string is invalid.
 */
ಪೂರ್ಣಾಙ್ಕ
convtime(ಧ್ರುವ ವರ್ಣ *s)
{
	ದ್ವಿಗುಣ sec_val;

	ಯದಿ ((sec_val = convtime_double(s)) < 0.0)
		ಪ್ರತ್ಯಾಗಮ -1;

	/* Check for overflow into int */
	ಯದಿ (sec_val < 0 || sec_val > INT_MAX)
		ಪ್ರತ್ಯಾಗಮ -1;

	ಪ್ರತ್ಯಾಗಮ (ಪೂರ್ಣಾಙ್ಕ)sec_val;
}

#define TF_BUFS	8
#define TF_LEN	9

ಧ್ರುವ ವರ್ಣ *
fmt_timeframe(time_t t)
{
	ವರ್ಣ		*buf;
	ಸ್ಥಿರ ವರ್ಣ	 tfbuf[TF_BUFS][TF_LEN];	/* ring buffer */
	ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ	 idx = 0;
	unsigned ಪೂರ್ಣಾಙ್ಕ	 sec, min, hrs, day;
	unsigned long long	week;

	buf = tfbuf[idx++];
	ಯದಿ (idx == TF_BUFS)
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

	ಯದಿ (week > 0)
		snprintf(buf, TF_LEN, "%02lluw%01ud%02uh", week, day, hrs);
	ಅನ್ಯಥಾ ಯದಿ (day > 0)
		snprintf(buf, TF_LEN, "%01ud%02uh%02um", day, hrs, min);
	ಅನ್ಯಥಾ
		snprintf(buf, TF_LEN, "%02u:%02u:%02u", hrs, min, sec);

	ಪ್ರತ್ಯಾಗಮ (buf);
}

/*
 * Returns a standardized host+port identifier string.
 * Caller must free returned string.
 */
ವರ್ಣ *
put_host_port(ಧ್ರುವ ವರ್ಣ *host, u_short port)
{
	ವರ್ಣ *hoststr;

	ಯದಿ (port == 0 || port == SSH_DEFAULT_PORT)
		ಪ್ರತ್ಯಾಗಮ(xstrdup(host));
	ಯದಿ (asprintf(&hoststr, "[%s]:%d", host, (ಪೂರ್ಣಾಙ್ಕ)port) == -1)
		fatal("put_host_port: asprintf: %s", strerror(errno));
	debug3("put_host_port: %s", hoststr);
	ಪ್ರತ್ಯಾಗಮ hoststr;
}

/*
 * Search for next delimiter between hostnames/addresses and ports.
 * Argument may be modified (for termination).
 * Returns *cp if parsing succeeds.
 * *cp is set to the start of the next field, if one was found.
 * The delimiter char, if present, is stored in delim.
 * If this is the last field, *cp is set to NULL.
 */
ವರ್ಣ *
hpdelim2(ವರ್ಣ **cp, ವರ್ಣ *delim)
{
	ವರ್ಣ *s, *old;

	ಯದಿ (cp == ರಿಕ್ತ || *cp == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;

	old = s = *cp;
	ಯದಿ (*s == '[') {
		ಯದಿ ((s = strchr(s, ']')) == ರಿಕ್ತ)
			ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
		ಅನ್ಯಥಾ
			s++;
	} ಅನ್ಯಥಾ ಯದಿ ((s = strpbrk(s, ":/")) == ರಿಕ್ತ)
		s = *cp + strlen(*cp); /* skip to end (see first case below) */

	ವಿಕಲ್ಪ (*s) {
	ಪಕ್ಷ '\0':
		*cp = ರಿಕ್ತ;	/* no more fields*/
		ಭಙ್ಗ;

	ಪಕ್ಷ ':':
	ಪಕ್ಷ '/':
		ಯದಿ (delim != ರಿಕ್ತ)
			*delim = *s;
		*s = '\0';	/* terminate */
		*cp = s + 1;
		ಭಙ್ಗ;

	ಸ್ವಭಾವ:
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}

	ಪ್ರತ್ಯಾಗಮ old;
}

/* The common case: only accept colon as delimiter. */
ವರ್ಣ *
hpdelim(ವರ್ಣ **cp)
{
	ವರ್ಣ *r, delim = '\0';

	r =  hpdelim2(cp, &delim);
	ಯದಿ (delim == '/')
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	ಪ್ರತ್ಯಾಗಮ r;
}

ವರ್ಣ *
cleanhostname(ವರ್ಣ *host)
{
	ಯದಿ (*host == '[' && host[strlen(host) - 1] == ']') {
		host[strlen(host) - 1] = '\0';
		ಪ್ರತ್ಯಾಗಮ (host + 1);
	} ಅನ್ಯಥಾ
		ಪ್ರತ್ಯಾಗಮ host;
}

ವರ್ಣ *
colon(ವರ್ಣ *cp)
{
	ಪೂರ್ಣಾಙ್ಕ flag = 0;

	ಯದಿ (*cp == ':')		/* Leading colon is part of file name. */
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	ಯದಿ (*cp == '[')
		flag = 1;

	ಪ್ರತಿ (; *cp; ++cp) {
		ಯದಿ (*cp == '@' && *(cp+1) == '[')
			flag = 1;
		ಯದಿ (*cp == ']' && *(cp+1) == ':' && flag)
			ಪ್ರತ್ಯಾಗಮ (cp+1);
		ಯದಿ (*cp == ':' && !flag)
			ಪ್ರತ್ಯಾಗಮ (cp);
		ಯದಿ (*cp == '/')
			ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}
	ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
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
ಪೂರ್ಣಾಙ್ಕ
parse_user_host_path(ಧ್ರುವ ವರ್ಣ *s, ವರ್ಣ **userp, ವರ್ಣ **hostp, ವರ್ಣ **pathp)
{
	ವರ್ಣ *user = ರಿಕ್ತ, *host = ರಿಕ್ತ, *path = ರಿಕ್ತ;
	ವರ್ಣ *sdup, *tmp;
	ಪೂರ್ಣಾಙ್ಕ ret = -1;

	ಯದಿ (userp != ರಿಕ್ತ)
		*userp = ರಿಕ್ತ;
	ಯದಿ (hostp != ರಿಕ್ತ)
		*hostp = ರಿಕ್ತ;
	ಯದಿ (pathp != ರಿಕ್ತ)
		*pathp = ರಿಕ್ತ;

	sdup = xstrdup(s);

	/* Check for remote syntax: [user@]host:[path] */
	ಯದಿ ((tmp = colon(sdup)) == ರಿಕ್ತ)
		ಗಚ್ಛ out;

	/* Extract optional path */
	*tmp++ = '\0';
	ಯದಿ (*tmp == '\0')
		tmp = ".";
	path = xstrdup(tmp);

	/* Extract optional user and mandatory host */
	tmp = strrchr(sdup, '@');
	ಯದಿ (tmp != ರಿಕ್ತ) {
		*tmp++ = '\0';
		host = xstrdup(cleanhostname(tmp));
		ಯದಿ (*sdup != '\0')
			user = xstrdup(sdup);
	} ಅನ್ಯಥಾ {
		host = xstrdup(cleanhostname(sdup));
		user = ರಿಕ್ತ;
	}

	/* Success */
	ಯದಿ (userp != ರಿಕ್ತ) {
		*userp = user;
		user = ರಿಕ್ತ;
	}
	ಯದಿ (hostp != ರಿಕ್ತ) {
		*hostp = host;
		host = ರಿಕ್ತ;
	}
	ಯದಿ (pathp != ರಿಕ್ತ) {
		*pathp = path;
		path = ರಿಕ್ತ;
	}
	ret = 0;
out:
	ಮುಕ್ತ(sdup);
	ಮುಕ್ತ(user);
	ಮುಕ್ತ(host);
	ಮುಕ್ತ(path);
	ಪ್ರತ್ಯಾಗಮ ret;
}

/*
 * Parse a [user@]host[:port] string.
 * Caller must free returned user and host.
 * Any of the pointer return arguments may be NULL (useful for syntax checking).
 * If user was not specified then *userp will be set to NULL.
 * If port was not specified then *portp will be -1.
 * Returns 0 on success, -1 on failure.
 */
ಪೂರ್ಣಾಙ್ಕ
parse_user_host_port(ಧ್ರುವ ವರ್ಣ *s, ವರ್ಣ **userp, ವರ್ಣ **hostp, ಪೂರ್ಣಾಙ್ಕ *portp)
{
	ವರ್ಣ *sdup, *cp, *tmp;
	ವರ್ಣ *user = ರಿಕ್ತ, *host = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ port = -1, ret = -1;

	ಯದಿ (userp != ರಿಕ್ತ)
		*userp = ರಿಕ್ತ;
	ಯದಿ (hostp != ರಿಕ್ತ)
		*hostp = ರಿಕ್ತ;
	ಯದಿ (portp != ರಿಕ್ತ)
		*portp = -1;

	ಯದಿ ((sdup = tmp = strdup(s)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ -1;
	/* Extract optional username */
	ಯದಿ ((cp = strrchr(tmp, '@')) != ರಿಕ್ತ) {
		*cp = '\0';
		ಯದಿ (*tmp == '\0')
			ಗಚ್ಛ out;
		ಯದಿ ((user = strdup(tmp)) == ರಿಕ್ತ)
			ಗಚ್ಛ out;
		tmp = cp + 1;
	}
	/* Extract mandatory hostname */
	ಯದಿ ((cp = hpdelim(&tmp)) == ರಿಕ್ತ || *cp == '\0')
		ಗಚ್ಛ out;
	host = xstrdup(cleanhostname(cp));
	/* Convert and verify optional port */
	ಯದಿ (tmp != ರಿಕ್ತ && *tmp != '\0') {
		ಯದಿ ((port = a2port(tmp)) <= 0)
			ಗಚ್ಛ out;
	}
	/* Success */
	ಯದಿ (userp != ರಿಕ್ತ) {
		*userp = user;
		user = ರಿಕ್ತ;
	}
	ಯದಿ (hostp != ರಿಕ್ತ) {
		*hostp = host;
		host = ರಿಕ್ತ;
	}
	ಯದಿ (portp != ರಿಕ್ತ)
		*portp = port;
	ret = 0;
 out:
	ಮುಕ್ತ(sdup);
	ಮುಕ್ತ(user);
	ಮುಕ್ತ(host);
	ಪ್ರತ್ಯಾಗಮ ret;
}

/*
 * Converts a two-byte hex string to decimal.
 * Returns the decimal value or -1 for invalid input.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
hexchar(ಧ್ರುವ ವರ್ಣ *s)
{
	unsigned ವರ್ಣ result[2];
	ಪೂರ್ಣಾಙ್ಕ i;

	ಪ್ರತಿ (i = 0; i < 2; i++) {
		ಯದಿ (s[i] >= '0' && s[i] <= '9')
			result[i] = (unsigned ವರ್ಣ)(s[i] - '0');
		ಅನ್ಯಥಾ ಯದಿ (s[i] >= 'a' && s[i] <= 'f')
			result[i] = (unsigned ವರ್ಣ)(s[i] - 'a') + 10;
		ಅನ್ಯಥಾ ಯದಿ (s[i] >= 'A' && s[i] <= 'F')
			result[i] = (unsigned ವರ್ಣ)(s[i] - 'A') + 10;
		ಅನ್ಯಥಾ
			ಪ್ರತ್ಯಾಗಮ -1;
	}
	ಪ್ರತ್ಯಾಗಮ (result[0] << 4) | result[1];
}

/*
 * Decode an url-encoded string.
 * Returns a newly allocated string on success or NULL on failure.
 */
ಸ್ಥಿರ ವರ್ಣ *
urldecode(ಧ್ರುವ ವರ್ಣ *src)
{
	ವರ್ಣ *ret, *dst;
	ಪೂರ್ಣಾಙ್ಕ ch;
	size_t srclen;

	ಯದಿ ((srclen = strlen(src)) >= SIZE_MAX)
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	ret = xmalloc(srclen + 1);
	ಪ್ರತಿ (dst = ret; *src != '\0'; src++) {
		ವಿಕಲ್ಪ (*src) {
		ಪಕ್ಷ '+':
			*dst++ = ' ';
			ಭಙ್ಗ;
		ಪಕ್ಷ '%':
			/* note: don't allow \0 characters */
			ಯದಿ (!isxdigit((unsigned ವರ್ಣ)src[1]) ||
			    !isxdigit((unsigned ವರ್ಣ)src[2]) ||
			    (ch = hexchar(src + 1)) == -1 || ch == 0) {
				ಮುಕ್ತ(ret);
				ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
			}
			*dst++ = ch;
			src += 2;
			ಭಙ್ಗ;
		ಸ್ವಭಾವ:
			*dst++ = *src;
			ಭಙ್ಗ;
		}
	}
	*dst = '\0';

	ಪ್ರತ್ಯಾಗಮ ret;
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
ಪೂರ್ಣಾಙ್ಕ
parse_uri(ಧ್ರುವ ವರ್ಣ *scheme, ಧ್ರುವ ವರ್ಣ *uri, ವರ್ಣ **userp, ವರ್ಣ **hostp,
    ಪೂರ್ಣಾಙ್ಕ *portp, ವರ್ಣ **pathp)
{
	ವರ್ಣ *uridup, *cp, *tmp, ch;
	ವರ್ಣ *user = ರಿಕ್ತ, *host = ರಿಕ್ತ, *path = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ port = -1, ret = -1;
	size_t len;

	len = strlen(scheme);
	ಯದಿ (strncmp(uri, scheme, len) != 0 || strncmp(uri + len, "://", 3) != 0)
		ಪ್ರತ್ಯಾಗಮ 1;
	uri += len + 3;

	ಯದಿ (userp != ರಿಕ್ತ)
		*userp = ರಿಕ್ತ;
	ಯದಿ (hostp != ರಿಕ್ತ)
		*hostp = ರಿಕ್ತ;
	ಯದಿ (portp != ರಿಕ್ತ)
		*portp = -1;
	ಯದಿ (pathp != ರಿಕ್ತ)
		*pathp = ರಿಕ್ತ;

	uridup = tmp = xstrdup(uri);

	/* Extract optional ssh-info (username + connection params) */
	ಯದಿ ((cp = strchr(tmp, '@')) != ರಿಕ್ತ) {
		ವರ್ಣ *delim;

		*cp = '\0';
		/* Extract username and connection params */
		ಯದಿ ((delim = strchr(tmp, ';')) != ರಿಕ್ತ) {
			/* Just ignore connection params for now */
			*delim = '\0';
		}
		ಯದಿ (*tmp == '\0') {
			/* Empty username */
			ಗಚ್ಛ out;
		}
		ಯದಿ ((user = urldecode(tmp)) == ರಿಕ್ತ)
			ಗಚ್ಛ out;
		tmp = cp + 1;
	}

	/* Extract mandatory hostname */
	ಯದಿ ((cp = hpdelim2(&tmp, &ch)) == ರಿಕ್ತ || *cp == '\0')
		ಗಚ್ಛ out;
	host = xstrdup(cleanhostname(cp));
	ಯದಿ (!valid_domain(host, 0, ರಿಕ್ತ))
		ಗಚ್ಛ out;

	ಯದಿ (tmp != ರಿಕ್ತ && *tmp != '\0') {
		ಯದಿ (ch == ':') {
			/* Convert and verify port. */
			ಯದಿ ((cp = strchr(tmp, '/')) != ರಿಕ್ತ)
				*cp = '\0';
			ಯದಿ ((port = a2port(tmp)) <= 0)
				ಗಚ್ಛ out;
			tmp = cp ? cp + 1 : ರಿಕ್ತ;
		}
		ಯದಿ (tmp != ರಿಕ್ತ && *tmp != '\0') {
			/* Extract optional path */
			ಯದಿ ((path = urldecode(tmp)) == ರಿಕ್ತ)
				ಗಚ್ಛ out;
		}
	}

	/* Success */
	ಯದಿ (userp != ರಿಕ್ತ) {
		*userp = user;
		user = ರಿಕ್ತ;
	}
	ಯದಿ (hostp != ರಿಕ್ತ) {
		*hostp = host;
		host = ರಿಕ್ತ;
	}
	ಯದಿ (portp != ರಿಕ್ತ)
		*portp = port;
	ಯದಿ (pathp != ರಿಕ್ತ) {
		*pathp = path;
		path = ರಿಕ್ತ;
	}
	ret = 0;
 out:
	ಮುಕ್ತ(uridup);
	ಮುಕ್ತ(user);
	ಮುಕ್ತ(host);
	ಮುಕ್ತ(path);
	ಪ್ರತ್ಯಾಗಮ ret;
}

/* function to assist building execv() arguments */
ಶೂನ್ಯ
addargs(arglist *args, ವರ್ಣ *fmt, ...)
{
	va_list ap;
	ವರ್ಣ *cp;
	u_int nalloc;
	ಪೂರ್ಣಾಙ್ಕ r;

	va_start(ap, fmt);
	r = vasprintf(&cp, fmt, ap);
	va_end(ap);
	ಯದಿ (r == -1)
		fatal_f("argument too long");

	nalloc = args->nalloc;
	ಯದಿ (args->list == ರಿಕ್ತ) {
		nalloc = 32;
		args->ಅಂಕೆ = 0;
	} ಅನ್ಯಥಾ ಯದಿ (args->ಅಂಕೆ > (256 * 1024))
		fatal_f("too many arguments");
	ಅನ್ಯಥಾ ಯದಿ (args->ಅಂಕೆ >= args->nalloc)
		fatal_f("arglist corrupt");
	ಅನ್ಯಥಾ ಯದಿ (args->ಅಂಕೆ+2 >= nalloc)
		nalloc *= 2;

	args->list = xrecallocarray(args->list, args->nalloc,
	    nalloc, ಪರಿಮಾಣ(ವರ್ಣ *));
	args->nalloc = nalloc;
	args->list[args->ಅಂಕೆ++] = cp;
	args->list[args->ಅಂಕೆ] = ರಿಕ್ತ;
}

ಶೂನ್ಯ
replacearg(arglist *args, u_int which, ವರ್ಣ *fmt, ...)
{
	va_list ap;
	ವರ್ಣ *cp;
	ಪೂರ್ಣಾಙ್ಕ r;

	va_start(ap, fmt);
	r = vasprintf(&cp, fmt, ap);
	va_end(ap);
	ಯದಿ (r == -1)
		fatal_f("argument too long");
	ಯದಿ (args->list == ರಿಕ್ತ || args->ಅಂಕೆ >= args->nalloc)
		fatal_f("arglist corrupt");

	ಯದಿ (which >= args->ಅಂಕೆ)
		fatal_f("tried to replace invalid arg %d >= %d",
		    which, args->ಅಂಕೆ);
	ಮುಕ್ತ(args->list[which]);
	args->list[which] = cp;
}

ಶೂನ್ಯ
freeargs(arglist *args)
{
	u_int i;

	ಯದಿ (args == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;
	ಯದಿ (args->list != ರಿಕ್ತ && args->ಅಂಕೆ < args->nalloc) {
		ಪ್ರತಿ (i = 0; i < args->ಅಂಕೆ; i++)
			ಮುಕ್ತ(args->list[i]);
		ಮುಕ್ತ(args->list);
	}
	args->nalloc = args->ಅಂಕೆ = 0;
	args->list = ರಿಕ್ತ;
}

/*
 * Expands tildes in the file name.  Returns data allocated by xmalloc.
 * Warning: this calls getpw*.
 */
ಪೂರ್ಣಾಙ್ಕ
tilde_expand(ಧ್ರುವ ವರ್ಣ *filename, uid_t uid, ವರ್ಣ **retp)
{
	ವರ್ಣ *ocopy = ರಿಕ್ತ, *copy, *s = ರಿಕ್ತ;
	ಧ್ರುವ ವರ್ಣ *path = ರಿಕ್ತ, *user = ರಿಕ್ತ;
	ಸಂರಚನಾ passwd *pw;
	size_t len;
	ಪೂರ್ಣಾಙ್ಕ ret = -1, r, slash;

	*retp = ರಿಕ್ತ;
	ಯದಿ (*filename != '~') {
		*retp = xstrdup(filename);
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	ocopy = copy = xstrdup(filename + 1);

	ಯದಿ (*copy == '\0')				/* ~ */
		path = ರಿಕ್ತ;
	ಅನ್ಯಥಾ ಯದಿ (*copy == '/') {
		copy += strspn(copy, "/");
		ಯದಿ (*copy == '\0')
			path = ರಿಕ್ತ;			/* ~/ */
		ಅನ್ಯಥಾ
			path = copy;			/* ~/path */
	} ಅನ್ಯಥಾ {
		user = copy;
		ಯದಿ ((path = strchr(copy, '/')) != ರಿಕ್ತ) {
			copy[path - copy] = '\0';
			path++;
			path += strspn(path, "/");
			ಯದಿ (*path == '\0')		/* ~user/ */
				path = ರಿಕ್ತ;
			/* else				 ~user/path */
		}
		/* else					~user */
	}
	ಯದಿ (user != ರಿಕ್ತ) {
		ಯದಿ ((pw = getpwnam(user)) == ರಿಕ್ತ) {
			error_f("No such user %s", user);
			ಗಚ್ಛ out;
		}
	} ಅನ್ಯಥಾ ಯದಿ ((pw = getpwuid(uid)) == ರಿಕ್ತ) {
		error_f("No such uid %ld", (long)uid);
		ಗಚ್ಛ out;
	}

	/* Make sure directory has a trailing '/' */
	slash = (len = strlen(pw->pw_dir)) == 0 || pw->pw_dir[len - 1] != '/';

	ಯದಿ ((r = xasprintf(&s, "%s%s%s", pw->pw_dir,
	    slash ? "/" : "", path != ರಿಕ್ತ ? path : "")) <= 0) {
		error_f("xasprintf failed");
		ಗಚ್ಛ out;
	}
	ಯದಿ (r >= PATH_MAX) {
		error_f("Path too long");
		ಗಚ್ಛ out;
	}
	/* success */
	ret = 0;
	*retp = s;
	s = ರಿಕ್ತ;
 out:
	ಮುಕ್ತ(s);
	ಮುಕ್ತ(ocopy);
	ಪ್ರತ್ಯಾಗಮ ret;
}

ವರ್ಣ *
tilde_expand_filename(ಧ್ರುವ ವರ್ಣ *filename, uid_t uid)
{
	ವರ್ಣ *ret;

	ಯದಿ (tilde_expand(filename, uid, &ret) != 0)
		cleanup_exit(255);
	ಪ್ರತ್ಯಾಗಮ ret;
}

/*
 * Expand a string with a set of %[char] escapes and/or ${ENVIRONMENT}
 * substitutions.  A number of escapes may be specified as
 * (char *escape_chars, char *replacement) pairs. The list must be terminated
 * by a NULL escape_char. Returns replaced string in memory allocated by
 * xmalloc which the caller must free.
 */
ಸ್ಥಿರ ವರ್ಣ *
vdollar_percent_expand(ಪೂರ್ಣಾಙ್ಕ *parseerror, ಪೂರ್ಣಾಙ್ಕ dollar, ಪೂರ್ಣಾಙ್ಕ percent,
    ಧ್ರುವ ವರ್ಣ *string, va_list ap)
{
#define EXPAND_MAX_ಕೀಲಿಗಳು	64
	u_int ಅಂಕೆ_ಕೀಲಿಗಳು = 0, i;
	ಸಂರಚನಾ {
		ಧ್ರುವ ವರ್ಣ *ಕೀಲಿ;
		ಧ್ರುವ ವರ್ಣ *repl;
	} ಕೀಲಿಗಳು[EXPAND_MAX_ಕೀಲಿಗಳು];
	ಸಂರಚನಾ sshbuf *buf;
	ಪೂರ್ಣಾಙ್ಕ r, missingvar = 0;
	ವರ್ಣ *ret = ರಿಕ್ತ, *var, *varend, *val;
	size_t len;

	ಯದಿ ((buf = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	ಯದಿ (parseerror == ರಿಕ್ತ)
		fatal_f("null parseerror arg");
	*parseerror = 1;

	/* Gather keys if we're doing percent expansion. */
	ಯದಿ (percent) {
		ಪ್ರತಿ (ಅಂಕೆ_ಕೀಲಿಗಳು = 0; ಅಂಕೆ_ಕೀಲಿಗಳು < EXPAND_MAX_ಕೀಲಿಗಳು; ಅಂಕೆ_ಕೀಲಿಗಳು++) {
			ಕೀಲಿಗಳು[ಅಂಕೆ_ಕೀಲಿಗಳು].ಕೀಲಿ = va_arg(ap, ವರ್ಣ *);
			ಯದಿ (ಕೀಲಿಗಳು[ಅಂಕೆ_ಕೀಲಿಗಳು].ಕೀಲಿ == ರಿಕ್ತ)
				ಭಙ್ಗ;
			ಕೀಲಿಗಳು[ಅಂಕೆ_ಕೀಲಿಗಳು].repl = va_arg(ap, ವರ್ಣ *);
			ಯದಿ (ಕೀಲಿಗಳು[ಅಂಕೆ_ಕೀಲಿಗಳು].repl == ರಿಕ್ತ) {
				fatal_f("NULL replacement for token %s",
				    ಕೀಲಿಗಳು[ಅಂಕೆ_ಕೀಲಿಗಳು].ಕೀಲಿ);
			}
		}
		ಯದಿ (ಅಂಕೆ_ಕೀಲಿಗಳು == EXPAND_MAX_ಕೀಲಿಗಳು && va_arg(ap, ವರ್ಣ *) != ರಿಕ್ತ)
			fatal_f("too many keys");
		ಯದಿ (ಅಂಕೆ_ಕೀಲಿಗಳು == 0)
			fatal_f("percent expansion without token list");
	}

	/* Expand string */
	ಪ್ರತಿ (i = 0; *string != '\0'; string++) {
		/* Optionally process ${ENVIRONMENT} expansions. */
		ಯದಿ (dollar && string[0] == '$' && string[1] == '{') {
			string += 2;  /* skip over '${' */
			ಯದಿ ((varend = strchr(string, '}')) == ರಿಕ್ತ) {
				error_f("environment variable '%s' missing "
				    "closing '}'", string);
				ಗಚ್ಛ out;
			}
			len = varend - string;
			ಯದಿ (len == 0) {
				error_f("zero-length environment variable");
				ಗಚ್ಛ out;
			}
			var = xmalloc(len + 1);
			(ಶೂನ್ಯ)strlcpy(var, string, len + 1);
			ಯದಿ ((val = getenv(var)) == ರಿಕ್ತ) {
				error_f("env var ${%s} has no value", var);
				missingvar = 1;
			} ಅನ್ಯಥಾ {
				debug3_f("expand ${%s} -> '%s'", var, val);
				ಯದಿ ((r = sshbuf_put(buf, val, strlen(val))) !=0)
					fatal_fr(r, "sshbuf_put ${}");
			}
			ಮುಕ್ತ(var);
			string += len;
			ಅನುವರ್ತ;
		}

		/*
		 * Process percent expansions if we have a list of TOKENs.
		 * If we're not doing percent expansion everything just gets
		 * appended here.
		 */
		ಯದಿ (*string != '%' || !percent) {
 append:
			ಯದಿ ((r = sshbuf_put_u8(buf, *string)) != 0)
				fatal_fr(r, "sshbuf_put_u8 %%");
			ಅನುವರ್ತ;
		}
		string++;
		/* %% case */
		ಯದಿ (*string == '%')
			ಗಚ್ಛ append;
		ಯದಿ (*string == '\0') {
			error_f("invalid format");
			ಗಚ್ಛ out;
		}
		ಪ್ರತಿ (i = 0; i < ಅಂಕೆ_ಕೀಲಿಗಳು; i++) {
			ಯದಿ (strchr(ಕೀಲಿಗಳು[i].ಕೀಲಿ, *string) != ರಿಕ್ತ) {
				ಯದಿ ((r = sshbuf_put(buf, ಕೀಲಿಗಳು[i].repl,
				    strlen(ಕೀಲಿಗಳು[i].repl))) != 0)
					fatal_fr(r, "sshbuf_put %%-repl");
				ಭಙ್ಗ;
			}
		}
		ಯದಿ (i >= ಅಂಕೆ_ಕೀಲಿಗಳು) {
			error_f("unknown key %%%c", *string);
			ಗಚ್ಛ out;
		}
	}
	ಯದಿ (!missingvar && (ret = sshbuf_dup_string(buf)) == ರಿಕ್ತ)
		fatal_f("sshbuf_dup_string failed");
	*parseerror = 0;
 out:
	sshbuf_free(buf);
	ಪ್ರತ್ಯಾಗಮ *parseerror ? ರಿಕ್ತ : ret;
#undef EXPAND_MAX_ಕೀಲಿಗಳು
}

/*
 * Expand only environment variables.
 * Note that although this function is variadic like the other similar
 * functions, any such arguments will be unused.
 */

ವರ್ಣ *
dollar_expand(ಪೂರ್ಣಾಙ್ಕ *parseerr, ಧ್ರುವ ವರ್ಣ *string, ...)
{
	ವರ್ಣ *ret;
	ಪೂರ್ಣಾಙ್ಕ err;
	va_list ap;

	va_start(ap, string);
	ret = vdollar_percent_expand(&err, 1, 0, string, ap);
	va_end(ap);
	ಯದಿ (parseerr != ರಿಕ್ತ)
		*parseerr = err;
	ಪ್ರತ್ಯಾಗಮ ret;
}

/*
 * Returns expanded string or NULL if a specified environment variable is
 * not defined, or calls fatal if the string is invalid.
 */
ವರ್ಣ *
percent_expand(ಧ್ರುವ ವರ್ಣ *string, ...)
{
	ವರ್ಣ *ret;
	ಪೂರ್ಣಾಙ್ಕ err;
	va_list ap;

	va_start(ap, string);
	ret = vdollar_percent_expand(&err, 0, 1, string, ap);
	va_end(ap);
	ಯದಿ (err)
		fatal_f("failed");
	ಪ್ರತ್ಯಾಗಮ ret;
}

/*
 * Returns expanded string or NULL if a specified environment variable is
 * not defined, or calls fatal if the string is invalid.
 */
ವರ್ಣ *
percent_dollar_expand(ಧ್ರುವ ವರ್ಣ *string, ...)
{
	ವರ್ಣ *ret;
	ಪೂರ್ಣಾಙ್ಕ err;
	va_list ap;

	va_start(ap, string);
	ret = vdollar_percent_expand(&err, 1, 1, string, ap);
	va_end(ap);
	ಯದಿ (err)
		fatal_f("failed");
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಪೂರ್ಣಾಙ್ಕ
tun_open(ಪೂರ್ಣಾಙ್ಕ tun, ಪೂರ್ಣಾಙ್ಕ mode, ವರ್ಣ **ifname)
{
#ಯದಿ defined(CUSTOM_SYS_TUN_OPEN)
	ಪ್ರತ್ಯಾಗಮ (sys_tun_open(tun, mode, ifname));
#ನೋಚೇದ್ಯದಿ defined(SSH_TUN_OPENBSD)
	ಸಂರಚನಾ ifreq ifr;
	ವರ್ಣ name[100];
	ಪೂರ್ಣಾಙ್ಕ fd = -1, sock;
	ಧ್ರುವ ವರ್ಣ *tunbase = "tun";

	ಯದಿ (ifname != ರಿಕ್ತ)
		*ifname = ರಿಕ್ತ;

	ಯದಿ (mode == SSH_TUNMODE_ETHERNET)
		tunbase = "tap";

	/* Open the tunnel device */
	ಯದಿ (tun <= SSH_TUNID_MAX) {
		snprintf(name, ಪರಿಮಾಣ(name), "/dev/%s%d", tunbase, tun);
		fd = open(name, O_RDWR);
	} ಅನ್ಯಥಾ ಯದಿ (tun == SSH_TUNID_ANY) {
		ಪ್ರತಿ (tun = 100; tun >= 0; tun--) {
			snprintf(name, ಪರಿಮಾಣ(name), "/dev/%s%d",
			    tunbase, tun);
			ಯದಿ ((fd = open(name, O_RDWR)) >= 0)
				ಭಙ್ಗ;
		}
	} ಅನ್ಯಥಾ {
		debug_f("invalid tunnel %u", tun);
		ಪ್ರತ್ಯಾಗಮ -1;
	}

	ಯದಿ (fd == -1) {
		debug_f("%s open: %s", name, strerror(errno));
		ಪ್ರತ್ಯಾಗಮ -1;
	}

	debug_f("%s mode %d fd %d", name, mode, fd);

	/* Bring interface up if it is not already */
	snprintf(ifr.ifr_name, ಪರಿಮಾಣ(ifr.ifr_name), "%s%d", tunbase, tun);
	ಯದಿ ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
		ಗಚ್ಛ failed;

	ಯದಿ (ioctl(sock, SIOCGIFFLAGS, &ifr) == -1) {
		debug_f("get interface %s flags: %s", ifr.ifr_name,
		    strerror(errno));
		ಗಚ್ಛ failed;
	}

	ಯದಿ (!(ifr.ifr_flags & IFF_UP)) {
		ifr.ifr_flags |= IFF_UP;
		ಯದಿ (ioctl(sock, SIOCSIFFLAGS, &ifr) == -1) {
			debug_f("activate interface %s: %s", ifr.ifr_name,
			    strerror(errno));
			ಗಚ್ಛ failed;
		}
	}

	ಯದಿ (ifname != ರಿಕ್ತ)
		*ifname = xstrdup(ifr.ifr_name);

	close(sock);
	ಪ್ರತ್ಯಾಗಮ fd;

 failed:
	ಯದಿ (fd >= 0)
		close(fd);
	ಯದಿ (sock >= 0)
		close(sock);
	ಪ್ರತ್ಯಾಗಮ -1;
#ಅನ್ಯಥಾ
	error("Tunnel interfaces are not supported on this platform");
	ಪ್ರತ್ಯಾಗಮ (-1);
#endif
}

ಶೂನ್ಯ
sanitise_stdfd(ಶೂನ್ಯ)
{
	ಪೂರ್ಣಾಙ್ಕ nullfd, dupfd;

	ಯದಿ ((nullfd = dupfd = open(_PATH_DEVNULL, O_RDWR)) == -1) {
		fprintf(stderr, "Couldn't open /dev/null: %s\n",
		    strerror(errno));
		exit(1);
	}
	ಯಾವತ್ (++dupfd <= STDERR_FILENO) {
		/* Only populate closed fds. */
		ಯದಿ (fcntl(dupfd, F_GETFL) == -1 && errno == EBADF) {
			ಯದಿ (dup2(nullfd, dupfd) == -1) {
				fprintf(stderr, "dup2: %s\n", strerror(errno));
				exit(1);
			}
		}
	}
	ಯದಿ (nullfd > STDERR_FILENO)
		close(nullfd);
}

ವರ್ಣ *
tohex(ಧ್ರುವ ಶೂನ್ಯ *vp, size_t l)
{
	ಧ್ರುವ u_char *p = (ಧ್ರುವ u_char *)vp;
	ವರ್ಣ b[3], *r;
	size_t i, hl;

	ಯದಿ (l > 65536)
		ಪ್ರತ್ಯಾಗಮ xstrdup("tohex: length > 65536");

	hl = l * 2 + 1;
	r = xcalloc(1, hl);
	ಪ್ರತಿ (i = 0; i < l; i++) {
		snprintf(b, ಪರಿಮಾಣ(b), "%02x", p[i]);
		strlcat(r, b, hl);
	}
	ಪ್ರತ್ಯಾಗಮ (r);
}

/*
 * Extend string *sp by the specified format. If *sp is not NULL (or empty),
 * then the separator 'sep' will be prepended before the formatted arguments.
 * Extended strings are heap allocated.
 */
ಶೂನ್ಯ
xextendf(ವರ್ಣ **sp, ಧ್ರುವ ವರ್ಣ *sep, ಧ್ರುವ ವರ್ಣ *fmt, ...)
{
	va_list ap;
	ವರ್ಣ *tmp1, *tmp2;

	va_start(ap, fmt);
	xvasprintf(&tmp1, fmt, ap);
	va_end(ap);

	ಯದಿ (*sp == ರಿಕ್ತ || **sp == '\0') {
		ಮುಕ್ತ(*sp);
		*sp = tmp1;
		ಪ್ರತ್ಯಾಗಮ;
	}
	xasprintf(&tmp2, "%s%s%s", *sp, sep == ರಿಕ್ತ ? "" : sep, tmp1);
	ಮುಕ್ತ(tmp1);
	ಮುಕ್ತ(*sp);
	*sp = tmp2;
}


uint64_t
get_u64(ಧ್ರುವ ಶೂನ್ಯ *vp)
{
	ಧ್ರುವ u_char *p = (ಧ್ರುವ u_char *)vp;
	uint64_t v;

	v  = (uint64_t)p[0] << 56;
	v |= (uint64_t)p[1] << 48;
	v |= (uint64_t)p[2] << 40;
	v |= (uint64_t)p[3] << 32;
	v |= (uint64_t)p[4] << 24;
	v |= (uint64_t)p[5] << 16;
	v |= (uint64_t)p[6] << 8;
	v |= (uint64_t)p[7];

	ಪ್ರತ್ಯಾಗಮ (v);
}

uint32_t
get_u32(ಧ್ರುವ ಶೂನ್ಯ *vp)
{
	ಧ್ರುವ u_char *p = (ಧ್ರುವ u_char *)vp;
	uint32_t v;

	v  = (uint32_t)p[0] << 24;
	v |= (uint32_t)p[1] << 16;
	v |= (uint32_t)p[2] << 8;
	v |= (uint32_t)p[3];

	ಪ್ರತ್ಯಾಗಮ (v);
}

uint32_t
get_u32_le(ಧ್ರುವ ಶೂನ್ಯ *vp)
{
	ಧ್ರುವ u_char *p = (ಧ್ರುವ u_char *)vp;
	uint32_t v;

	v  = (uint32_t)p[0];
	v |= (uint32_t)p[1] << 8;
	v |= (uint32_t)p[2] << 16;
	v |= (uint32_t)p[3] << 24;

	ಪ್ರತ್ಯಾಗಮ (v);
}

uint16_t
get_u16(ಧ್ರುವ ಶೂನ್ಯ *vp)
{
	ಧ್ರುವ u_char *p = (ಧ್ರುವ u_char *)vp;
	uint16_t v;

	v  = (uint16_t)p[0] << 8;
	v |= (uint16_t)p[1];

	ಪ್ರತ್ಯಾಗಮ (v);
}

ಶೂನ್ಯ
put_u64(ಶೂನ್ಯ *vp, uint64_t v)
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

ಶೂನ್ಯ
put_u32(ಶೂನ್ಯ *vp, uint32_t v)
{
	u_char *p = (u_char *)vp;

	p[0] = (u_char)(v >> 24) & 0xff;
	p[1] = (u_char)(v >> 16) & 0xff;
	p[2] = (u_char)(v >> 8) & 0xff;
	p[3] = (u_char)v & 0xff;
}

ಶೂನ್ಯ
put_u32_le(ಶೂನ್ಯ *vp, uint32_t v)
{
	u_char *p = (u_char *)vp;

	p[0] = (u_char)v & 0xff;
	p[1] = (u_char)(v >> 8) & 0xff;
	p[2] = (u_char)(v >> 16) & 0xff;
	p[3] = (u_char)(v >> 24) & 0xff;
}

ಶೂನ್ಯ
put_u16(ಶೂನ್ಯ *vp, uint16_t v)
{
	u_char *p = (u_char *)vp;

	p[0] = (u_char)(v >> 8) & 0xff;
	p[1] = (u_char)v & 0xff;
}

ಶೂನ್ಯ
ms_subtract_diff(ಸಂರಚನಾ timeval *start, ಪೂರ್ಣಾಙ್ಕ *ms)
{
	ಸಂರಚನಾ timeval diff, finish;

	monotime_tv(&finish);
	timersub(&finish, start, &diff);
	*ms -= (diff.tv_sec * 1000) + (diff.tv_usec / 1000);
}

ಶೂನ್ಯ
ms_to_timespec(ಸಂರಚನಾ timespec *ts, ಪೂರ್ಣಾಙ್ಕ ms)
{
	ಯದಿ (ms < 0)
		ms = 0;
	ts->tv_sec = ms / 1000;
	ts->tv_nsec = (ms % 1000) * 1000 * 1000;
}

ಶೂನ್ಯ
monotime_ts(ಸಂರಚನಾ timespec *ts)
{
	ಸಂರಚನಾ timeval tv;
#ಯದಿ defined(HAVE_CLOCK_GETTIME) && (defined(CLOCK_BOOTTIME) || \
    defined(CLOCK_MONOTONIC) || defined(CLOCK_REALTIME))
	ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ gettime_failed = 0;

	ಯದಿ (!gettime_failed) {
# ifdef CLOCK_BOOTTIME
		ಯದಿ (clock_gettime(CLOCK_BOOTTIME, ts) == 0)
			ಪ್ರತ್ಯಾಗಮ;
# endif /* CLOCK_BOOTTIME */
# ifdef CLOCK_MONOTONIC
		ಯದಿ (clock_gettime(CLOCK_MONOTONIC, ts) == 0)
			ಪ್ರತ್ಯಾಗಮ;
# endif /* CLOCK_MONOTONIC */
# ifdef CLOCK_REALTIME
		/* Not monotonic, but we're almost out of options here. */
		ಯದಿ (clock_gettime(CLOCK_REALTIME, ts) == 0)
			ಪ್ರತ್ಯಾಗಮ;
# endif /* CLOCK_REALTIME */
		debug3("clock_gettime: %s", strerror(errno));
		gettime_failed = 1;
	}
#endif /* HAVE_CLOCK_GETTIME && (BOOTTIME || MONOTONIC || REALTIME) */
	gettimeofday(&tv, ರಿಕ್ತ);
	ts->tv_sec = tv.tv_sec;
	ts->tv_nsec = (long)tv.tv_usec * 1000;
}

ಶೂನ್ಯ
monotime_tv(ಸಂರಚನಾ timeval *tv)
{
	ಸಂರಚನಾ timespec ts;

	monotime_ts(&ts);
	tv->tv_sec = ts.tv_sec;
	tv->tv_usec = ts.tv_nsec / 1000;
}

time_t
monotime(ಶೂನ್ಯ)
{
	ಸಂರಚನಾ timespec ts;

	monotime_ts(&ts);
	ಪ್ರತ್ಯಾಗಮ (ts.tv_sec);
}

ದ್ವಿಗುಣ
monotime_double(ಶೂನ್ಯ)
{
	ಸಂರಚನಾ timespec ts;

	monotime_ts(&ts);
	ಪ್ರತ್ಯಾಗಮ (ದ್ವಿಗುಣ)ts.tv_sec + (ದ್ವಿಗುಣ)ts.tv_nsec / 1000000000.0;
}

ಶೂನ್ಯ
bandwidth_limit_init(ಸಂರಚನಾ bwlimit *bw, uint64_t kbps, size_t buflen)
{
	bw->buflen = buflen;
	bw->rate = kbps;
	bw->thresh = buflen;
	bw->lamt = 0;
	timerclear(&bw->bwstart);
	timerclear(&bw->bwend);
}

/* Callback from read/write loop to insert bandwidth-limiting delays */
ಶೂನ್ಯ
bandwidth_limit(ಸಂರಚನಾ bwlimit *bw, size_t read_len)
{
	uint64_t waitlen;
	ಸಂರಚನಾ timespec ts, rm;

	bw->lamt += read_len;
	ಯದಿ (!timerisset(&bw->bwstart)) {
		monotime_tv(&bw->bwstart);
		ಪ್ರತ್ಯಾಗಮ;
	}
	ಯದಿ (bw->lamt < bw->thresh)
		ಪ್ರತ್ಯಾಗಮ;

	monotime_tv(&bw->bwend);
	timersub(&bw->bwend, &bw->bwstart, &bw->bwend);
	ಯದಿ (!timerisset(&bw->bwend))
		ಪ್ರತ್ಯಾಗಮ;

	bw->lamt *= 8;
	waitlen = (ದ್ವಿಗುಣ)1000000L * bw->lamt / bw->rate;

	bw->bwstart.tv_sec = waitlen / 1000000L;
	bw->bwstart.tv_usec = waitlen % 1000000L;

	ಯದಿ (timercmp(&bw->bwstart, &bw->bwend, >)) {
		timersub(&bw->bwstart, &bw->bwend, &bw->bwend);

		/* Adjust the wait time */
		ಯದಿ (bw->bwend.tv_sec) {
			bw->thresh /= 2;
			ಯದಿ (bw->thresh < bw->buflen / 4)
				bw->thresh = bw->buflen / 4;
		} ಅನ್ಯಥಾ ಯದಿ (bw->bwend.tv_usec < 10000) {
			bw->thresh *= 2;
			ಯದಿ (bw->thresh > bw->buflen * 8)
				bw->thresh = bw->buflen * 8;
		}

		TIMEVAL_TO_TIMESPEC(&bw->bwend, &ts);
		ಯಾವತ್ (nanosleep(&ts, &rm) == -1) {
			ಯದಿ (errno != EINTR)
				ಭಙ್ಗ;
			ts = rm;
		}
	}

	bw->lamt = 0;
	monotime_tv(&bw->bwstart);
}

/* Make a template filename for mk[sd]temp() */
ಶೂನ್ಯ
mktemp_proto(ವರ್ಣ *s, size_t len)
{
	ಧ್ರುವ ವರ್ಣ *tmpdir;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((tmpdir = getenv("TMPDIR")) != ರಿಕ್ತ) {
		r = snprintf(s, len, "%s/ssh-XXXXXXXXXXXX", tmpdir);
		ಯದಿ (r > 0 && (size_t)r < len)
			ಪ್ರತ್ಯಾಗಮ;
	}
	r = snprintf(s, len, "/tmp/ssh-XXXXXXXXXXXX");
	ಯದಿ (r < 0 || (size_t)r >= len)
		fatal_f("template string too short");
}

ಸ್ಥಿರ ಧ್ರುವ ಸಂರಚನಾ {
	ಧ್ರುವ ವರ್ಣ *name;
	ಪೂರ್ಣಾಙ್ಕ ಮೌಲ್ಯ;
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
	{ ರಿಕ್ತ, -1 }
};

ಪೂರ್ಣಾಙ್ಕ
parse_ipqos(ಧ್ರುವ ವರ್ಣ *cp)
{
	ಧ್ರುವ ವರ್ಣ *errstr;
	u_int i;
	ಪೂರ್ಣಾಙ್ಕ val;

	ಯದಿ (cp == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ -1;
	ಪ್ರತಿ (i = 0; ipqos[i].name != ರಿಕ್ತ; i++) {
		ಯದಿ (strcasecmp(cp, ipqos[i].name) == 0)
			ಪ್ರತ್ಯಾಗಮ ipqos[i].ಮೌಲ್ಯ;
	}
	/* Try parsing as an integer */
	val = (ಪೂರ್ಣಾಙ್ಕ)strtonum(cp, 0, 255, &errstr);
	ಯದಿ (errstr)
		ಪ್ರತ್ಯಾಗಮ -1;
	ಪ್ರತ್ಯಾಗಮ val;
}

ಧ್ರುವ ವರ್ಣ *
iptos2str(ಪೂರ್ಣಾಙ್ಕ iptos)
{
	ಪೂರ್ಣಾಙ್ಕ i;
	ಸ್ಥಿರ ವರ್ಣ iptos_str[ಪರಿಮಾಣ "0xff"];

	ಪ್ರತಿ (i = 0; ipqos[i].name != ರಿಕ್ತ; i++) {
		ಯದಿ (ipqos[i].ಮೌಲ್ಯ == iptos)
			ಪ್ರತ್ಯಾಗಮ ipqos[i].name;
	}
	snprintf(iptos_str, ಪರಿಮಾಣ iptos_str, "0x%02x", iptos);
	ಪ್ರತ್ಯಾಗಮ iptos_str;
}

ಶೂನ್ಯ
lowercase(ವರ್ಣ *s)
{
	ಪ್ರತಿ (; *s; s++)
		*s = tolower((u_char)*s);
}

ಪೂರ್ಣಾಙ್ಕ
unix_listener(ಧ್ರುವ ವರ್ಣ *path, ಪೂರ್ಣಾಙ್ಕ backlog, ಪೂರ್ಣಾಙ್ಕ unlink_first)
{
	ಸಂರಚನಾ sockaddr_un sunaddr;
	ಪೂರ್ಣಾಙ್ಕ saved_errno, sock;

	memset(&sunaddr, 0, ಪರಿಮಾಣ(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	ಯದಿ (strlcpy(sunaddr.sun_path, path,
	    ಪರಿಮಾಣ(sunaddr.sun_path)) >= ಪರಿಮಾಣ(sunaddr.sun_path)) {
		error_f("path \"%s\" too long for Unix domain socket", path);
		errno = ENAMETOOLONG;
		ಪ್ರತ್ಯಾಗಮ -1;
	}

	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	ಯದಿ (sock == -1) {
		saved_errno = errno;
		error_f("socket: %.100s", strerror(errno));
		errno = saved_errno;
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	ಯದಿ (unlink_first == 1) {
		ಯದಿ (unlink(path) != 0 && errno != ENOENT)
			error("unlink(%s): %.100s", path, strerror(errno));
	}
	ಯದಿ (bind(sock, (ಸಂರಚನಾ sockaddr *)&sunaddr, ಪರಿಮಾಣ(sunaddr)) == -1) {
		saved_errno = errno;
		error_f("cannot bind to path %s: %s", path, strerror(errno));
		close(sock);
		errno = saved_errno;
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	ಯದಿ (listen(sock, backlog) == -1) {
		saved_errno = errno;
		error_f("cannot listen on path %s: %s", path, strerror(errno));
		close(sock);
		unlink(path);
		errno = saved_errno;
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	ಪ್ರತ್ಯಾಗಮ sock;
}

ಶೂನ್ಯ
sock_set_v6only(ಪೂರ್ಣಾಙ್ಕ s)
{
#ಯದಿ defined(IPV6_V6ONLY) && !defined(__OpenBSD__)
	ಪೂರ್ಣಾಙ್ಕ on = 1;

	debug3_f("set socket %d IPV6_V6ONLY", s);
	ಯದಿ (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &on, ಪರಿಮಾಣ(on)) == -1)
		error("setsockopt IPV6_V6ONLY: %s", strerror(errno));
#endif
}

/*
 * Compares two strings that maybe be NULL. Returns non-zero if strings
 * are both NULL or are identical, returns zero otherwise.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
strcmp_maybe_null(ಧ್ರುವ ವರ್ಣ *a, ಧ್ರುವ ವರ್ಣ *b)
{
	ಯದಿ ((a == ರಿಕ್ತ && b != ರಿಕ್ತ) || (a != ರಿಕ್ತ && b == ರಿಕ್ತ))
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ (a != ರಿಕ್ತ && strcmp(a, b) != 0)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಪ್ರತ್ಯಾಗಮ 1;
}

/*
 * Compare two forwards, returning non-zero if they are identical or
 * zero otherwise.
 */
ಪೂರ್ಣಾಙ್ಕ
forward_equals(ಧ್ರುವ ಸಂರಚನಾ Forward *a, ಧ್ರುವ ಸಂರಚನಾ Forward *b)
{
	ಯದಿ (strcmp_maybe_null(a->listen_host, b->listen_host) == 0)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ (a->listen_port != b->listen_port)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ (strcmp_maybe_null(a->listen_path, b->listen_path) == 0)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ (strcmp_maybe_null(a->connect_host, b->connect_host) == 0)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ (a->connect_port != b->connect_port)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ (strcmp_maybe_null(a->connect_path, b->connect_path) == 0)
		ಪ್ರತ್ಯಾಗಮ 0;
	/* allocated_port and handle are not checked */
	ಪ್ರತ್ಯಾಗಮ 1;
}

/* returns port number, FWD_PERMIT_ANY_PORT or -1 on error */
ಪೂರ್ಣಾಙ್ಕ
permitopen_port(ಧ್ರುವ ವರ್ಣ *p)
{
	ಪೂರ್ಣಾಙ್ಕ port;

	ಯದಿ (strcmp(p, "*") == 0)
		ಪ್ರತ್ಯಾಗಮ FWD_PERMIT_ANY_PORT;
	ಯದಿ ((port = a2port(p)) > 0)
		ಪ್ರತ್ಯಾಗಮ port;
	ಪ್ರತ್ಯಾಗಮ -1;
}

/* returns 1 if process is already daemonized, 0 otherwise */
ಪೂರ್ಣಾಙ್ಕ
daemonized(ಶೂನ್ಯ)
{
	ಪೂರ್ಣಾಙ್ಕ fd;

	ಯದಿ ((fd = open(_PATH_TTY, O_RDONLY | O_NOCTTY)) >= 0) {
		close(fd);
		ಪ್ರತ್ಯಾಗಮ 0;	/* have controlling terminal */
	}
	ಯದಿ (getppid() != 1)
		ಪ್ರತ್ಯಾಗಮ 0;	/* parent is not init */
	ಯದಿ (getsid(0) != getpid())
		ಪ್ರತ್ಯಾಗಮ 0;	/* not session leader */
	debug3("already daemonized");
	ಪ್ರತ್ಯಾಗಮ 1;
}

/*
 * Splits 's' into an argument vector. Handles quoted string and basic
 * escape characters (\\, \", \'). Caller must free the argument vector
 * and its members.
 */
ಪೂರ್ಣಾಙ್ಕ
argv_split(ಧ್ರುವ ವರ್ಣ *s, ಪೂರ್ಣಾಙ್ಕ *argcp, ವರ್ಣ ***argvp, ಪೂರ್ಣಾಙ್ಕ terminate_on_comment)
{
	ಪೂರ್ಣಾಙ್ಕ r = SSH_ERR_INTERNAL_ERROR;
	ಪೂರ್ಣಾಙ್ಕ argc = 0, quote, i, j;
	ವರ್ಣ *arg, **argv = xcalloc(1, ಪರಿಮಾಣ(*argv));

	*argvp = ರಿಕ್ತ;
	*argcp = 0;

	ಪ್ರತಿ (i = 0; s[i] != '\0'; i++) {
		/* Skip leading whitespace */
		ಯದಿ (s[i] == ' ' || s[i] == '\t')
			ಅನುವರ್ತ;
		ಯದಿ (terminate_on_comment && s[i] == '#')
			ಭಙ್ಗ;
		/* Start of a token */
		quote = 0;

		argv = xreallocarray(argv, (argc + 2), ಪರಿಮಾಣ(*argv));
		arg = argv[argc++] = xcalloc(1, strlen(s + i) + 1);
		argv[argc] = ರಿಕ್ತ;

		/* Copy the token in, removing escapes */
		ಪ್ರತಿ (j = 0; s[i] != '\0'; i++) {
			ಯದಿ (s[i] == '\\') {
				ಯದಿ (s[i + 1] == '\'' ||
				    s[i + 1] == '\"' ||
				    s[i + 1] == '\\' ||
				    (quote == 0 && s[i + 1] == ' ')) {
					i++; /* Skip '\' */
					arg[j++] = s[i];
				} ಅನ್ಯಥಾ {
					/* Unrecognised escape */
					arg[j++] = s[i];
				}
			} ಅನ್ಯಥಾ ಯದಿ (quote == 0 && (s[i] == ' ' || s[i] == '\t'))
				ಭಙ್ಗ; /* done */
			ಅನ್ಯಥಾ ಯದಿ (quote == 0 && (s[i] == '\"' || s[i] == '\''))
				quote = s[i]; /* quote start */
			ಅನ್ಯಥಾ ಯದಿ (quote != 0 && s[i] == quote)
				quote = 0; /* quote end */
			ಅನ್ಯಥಾ
				arg[j++] = s[i];
		}
		ಯದಿ (s[i] == '\0') {
			ಯದಿ (quote != 0) {
				/* Ran out of string looking for close quote */
				r = SSH_ERR_INVALID_FORMAT;
				ಗಚ್ಛ out;
			}
			ಭಙ್ಗ;
		}
	}
	/* Success */
	*argcp = argc;
	*argvp = argv;
	argc = 0;
	argv = ರಿಕ್ತ;
	r = 0;
 out:
	ಯದಿ (argc != 0 && argv != ರಿಕ್ತ) {
		ಪ್ರತಿ (i = 0; i < argc; i++)
			ಮುಕ್ತ(argv[i]);
		ಮುಕ್ತ(argv);
	}
	ಪ್ರತ್ಯಾಗಮ r;
}

/*
 * Reassemble an argument vector into a string, quoting and escaping as
 * necessary. Caller must free returned string.
 */
ವರ್ಣ *
argv_assemble(ಪೂರ್ಣಾಙ್ಕ argc, ವರ್ಣ **argv)
{
	ಪೂರ್ಣಾಙ್ಕ i, j, ws, r;
	ವರ್ಣ c, *ret;
	ಸಂರಚನಾ sshbuf *buf, *arg;

	ಯದಿ ((buf = sshbuf_new()) == ರಿಕ್ತ || (arg = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");

	ಪ್ರತಿ (i = 0; i < argc; i++) {
		ws = 0;
		sshbuf_reset(arg);
		ಪ್ರತಿ (j = 0; argv[i][j] != '\0'; j++) {
			r = 0;
			c = argv[i][j];
			ವಿಕಲ್ಪ (c) {
			ಪಕ್ಷ ' ':
			ಪಕ್ಷ '\t':
				ws = 1;
				r = sshbuf_put_u8(arg, c);
				ಭಙ್ಗ;
			ಪಕ್ಷ '\\':
			ಪಕ್ಷ '\'':
			ಪಕ್ಷ '"':
				ಯದಿ ((r = sshbuf_put_u8(arg, '\\')) != 0)
					ಭಙ್ಗ;
				/* FALLTHROUGH */
			ಸ್ವಭಾವ:
				r = sshbuf_put_u8(arg, c);
				ಭಙ್ಗ;
			}
			ಯದಿ (r != 0)
				fatal_fr(r, "sshbuf_put_u8");
		}
		ಯದಿ ((i != 0 && (r = sshbuf_put_u8(buf, ' ')) != 0) ||
		    (ws != 0 && (r = sshbuf_put_u8(buf, '"')) != 0) ||
		    (r = sshbuf_putb(buf, arg)) != 0 ||
		    (ws != 0 && (r = sshbuf_put_u8(buf, '"')) != 0))
			fatal_fr(r, "assemble");
	}
	ಯದಿ ((ret = malloc(sshbuf_len(buf) + 1)) == ರಿಕ್ತ)
		fatal_f("malloc failed");
	memcpy(ret, sshbuf_ptr(buf), sshbuf_len(buf));
	ret[sshbuf_len(buf)] = '\0';
	sshbuf_free(buf);
	sshbuf_free(arg);
	ಪ್ರತ್ಯಾಗಮ ret;
}

ವರ್ಣ *
argv_next(ಪೂರ್ಣಾಙ್ಕ *argcp, ವರ್ಣ ***argvp)
{
	ವರ್ಣ *ret = (*argvp)[0];

	ಯದಿ (*argcp > 0 && ret != ರಿಕ್ತ) {
		(*argcp)--;
		(*argvp)++;
	}
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಶೂನ್ಯ
argv_consume(ಪೂರ್ಣಾಙ್ಕ *argcp)
{
	*argcp = 0;
}

ಶೂನ್ಯ
argv_free(ವರ್ಣ **av, ಪೂರ್ಣಾಙ್ಕ ac)
{
	ಪೂರ್ಣಾಙ್ಕ i;

	ಯದಿ (av == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;
	ಪ್ರತಿ (i = 0; i < ac; i++)
		ಮುಕ್ತ(av[i]);
	ಮುಕ್ತ(av);
}

/* Returns 0 if pid exited cleanly, non-zero otherwise */
ಪೂರ್ಣಾಙ್ಕ
exited_cleanly(pid_t pid, ಧ್ರುವ ವರ್ಣ *tag, ಧ್ರುವ ವರ್ಣ *cmd, ಪೂರ್ಣಾಙ್ಕ quiet)
{
	ಪೂರ್ಣಾಙ್ಕ status;

	ಯಾವತ್ (waitpid(pid, &status, 0) == -1) {
		ಯದಿ (errno != EINTR) {
			error("%s waitpid: %s", tag, strerror(errno));
			ಪ್ರತ್ಯಾಗಮ -1;
		}
	}
	ಯದಿ (WIFSIGNALED(status)) {
		error("%s %s exited on signal %d", tag, cmd, WTERMSIG(status));
		ಪ್ರತ್ಯಾಗಮ -1;
	} ಅನ್ಯಥಾ ಯದಿ (WEXITSTATUS(status) != 0) {
		do_log2(quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_INFO,
		    "%s %s failed, status %d", tag, cmd, WEXITSTATUS(status));
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
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
ಪೂರ್ಣಾಙ್ಕ
safe_path(ಧ್ರುವ ವರ್ಣ *name, ಸಂರಚನಾ stat *stp, ಧ್ರುವ ವರ್ಣ *pw_dir,
    uid_t uid, ವರ್ಣ *err, size_t errlen)
{
	ವರ್ಣ buf[PATH_MAX], buf2[PATH_MAX], homedir[PATH_MAX];
	ವರ್ಣ *cp;
	ಪೂರ್ಣಾಙ್ಕ comparehome = 0;
	ಸಂರಚನಾ stat st;

	ಯದಿ (realpath(name, buf) == ರಿಕ್ತ) {
		snprintf(err, errlen, "realpath %s failed: %s", name,
		    strerror(errno));
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	ಯದಿ (pw_dir != ರಿಕ್ತ && realpath(pw_dir, homedir) != ರಿಕ್ತ)
		comparehome = 1;

	ಯದಿ (!S_ISREG(stp->st_mode)) {
		snprintf(err, errlen, "%s is not a regular file", buf);
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	ಯದಿ ((!platform_sys_dir_uid(stp->st_uid) && stp->st_uid != uid) ||
	    (stp->st_mode & 022) != 0) {
		snprintf(err, errlen, "bad ownership or modes for file %s",
		    buf);
		ಪ್ರತ್ಯಾಗಮ -1;
	}

	/* for each component of the canonical path, walking upwards */
	ಪ್ರತಿ (;;) {
		/*
		 * POSIX allows dirname to modify its argument and return a
		 * pointer into it, so make a copy to avoid overlapping strlcpy.
		 */
		strlcpy(buf2, buf, ಪರಿಮಾಣ(buf2));
		ಯದಿ ((cp = dirname(buf2)) == ರಿಕ್ತ) {
			snprintf(err, errlen, "dirname() failed");
			ಪ್ರತ್ಯಾಗಮ -1;
		}
		strlcpy(buf, cp, ಪರಿಮಾಣ(buf));

		ಯದಿ (stat(buf, &st) == -1 ||
		    (!platform_sys_dir_uid(st.st_uid) && st.st_uid != uid) ||
		    (st.st_mode & 022) != 0) {
			snprintf(err, errlen,
			    "bad ownership or modes for directory %s", buf);
			ಪ್ರತ್ಯಾಗಮ -1;
		}

		/* If are past the homedir then we can stop */
		ಯದಿ (comparehome && strcmp(homedir, buf) == 0)
			ಭಙ್ಗ;

		/*
		 * dirname should always complete with a "/" path,
		 * but we can be paranoid and check for "." too
		 */
		ಯದಿ ((strcmp("/", buf) == 0) || (strcmp(".", buf) == 0))
			ಭಙ್ಗ;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

/*
 * Version of safe_path() that accepts an open file descriptor to
 * avoid races.
 *
 * Returns 0 on success and -1 on failure
 */
ಪೂರ್ಣಾಙ್ಕ
safe_path_fd(ಪೂರ್ಣಾಙ್ಕ fd, ಧ್ರುವ ವರ್ಣ *file, ಸಂರಚನಾ passwd *pw,
    ವರ್ಣ *err, size_t errlen)
{
	ಸಂರಚನಾ stat st;

	/* check the open file to avoid races */
	ಯದಿ (fstat(fd, &st) == -1) {
		snprintf(err, errlen, "cannot stat file %s: %s",
		    file, strerror(errno));
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	ಪ್ರತ್ಯಾಗಮ safe_path(file, &st, pw->pw_dir, pw->pw_uid, err, errlen);
}

/*
 * Sets the value of the given variable in the environment.  If the variable
 * already exists, its value is overridden.
 */
ಶೂನ್ಯ
child_set_env(ವರ್ಣ ***envp, u_int *envsizep, ಧ್ರುವ ವರ್ಣ *name,
	ಧ್ರುವ ವರ್ಣ *ಮೌಲ್ಯ)
{
	ವರ್ಣ **env;
	u_int envsize;
	u_int i, namelen;

	ಯದಿ (strchr(name, '=') != ರಿಕ್ತ) {
		error("Invalid environment variable \"%.100s\"", name);
		ಪ್ರತ್ಯಾಗಮ;
	}

	/*
	 * If we're passed an uninitialized list, allocate a single null
	 * entry before continuing.
	 */
	ಯದಿ ((*envp == ರಿಕ್ತ) != (*envsizep == 0))
		fatal_f("environment size mismatch");
	ಯದಿ (*envp == ರಿಕ್ತ && *envsizep == 0) {
		*envp = xmalloc(ಪರಿಮಾಣ(ವರ್ಣ *));
		*envp[0] = ರಿಕ್ತ;
		*envsizep = 1;
	}

	/*
	 * Find the slot where the value should be stored.  If the variable
	 * already exists, we reuse the slot; otherwise we append a new slot
	 * at the end of the array, expanding if necessary.
	 */
	env = *envp;
	namelen = strlen(name);
	ಪ್ರತಿ (i = 0; env[i]; i++)
		ಯದಿ (strncmp(env[i], name, namelen) == 0 && env[i][namelen] == '=')
			ಭಙ್ಗ;
	ಯದಿ (env[i]) {
		/* Reuse the slot. */
		ಮುಕ್ತ(env[i]);
	} ಅನ್ಯಥಾ {
		/* New variable.  Expand if necessary. */
		envsize = *envsizep;
		ಯದಿ (i >= envsize - 1) {
			ಯದಿ (envsize >= 1000)
				fatal("child_set_env: too many env vars");
			envsize += 50;
			env = (*envp) = xreallocarray(env, envsize, ಪರಿಮಾಣ(ವರ್ಣ *));
			*envsizep = envsize;
		}
		/* Need to set the NULL pointer at end of array beyond the new slot. */
		env[i + 1] = ರಿಕ್ತ;
	}

	/* Allocate space and format the variable in the appropriate slot. */
	/* XXX xasprintf */
	env[i] = xmalloc(strlen(name) + 1 + strlen(ಮೌಲ್ಯ) + 1);
	snprintf(env[i], strlen(name) + 1 + strlen(ಮೌಲ್ಯ) + 1, "%s=%s", name, ಮೌಲ್ಯ);
}

/*
 * Check and optionally lowercase a domain name, also removes trailing '.'
 * Returns 1 on success and 0 on failure, storing an error message in errstr.
 */
ಪೂರ್ಣಾಙ್ಕ
valid_domain(ವರ್ಣ *name, ಪೂರ್ಣಾಙ್ಕ makelower, ಧ್ರುವ ವರ್ಣ **errstr)
{
	size_t i, l = strlen(name);
	u_char c, last = '\0';
	ಸ್ಥಿರ ವರ್ಣ errbuf[256];

	ಯದಿ (l == 0) {
		strlcpy(errbuf, "empty domain name", ಪರಿಮಾಣ(errbuf));
		ಗಚ್ಛ bad;
	}
	ಯದಿ (!isalpha((u_char)name[0]) && !isdigit((u_char)name[0]) &&
	   name[0] != '_' /* technically invalid, but common */) {
		snprintf(errbuf, ಪರಿಮಾಣ(errbuf), "domain name \"%.100s\" "
		    "starts with invalid character", name);
		ಗಚ್ಛ bad;
	}
	ಪ್ರತಿ (i = 0; i < l; i++) {
		c = tolower((u_char)name[i]);
		ಯದಿ (makelower)
			name[i] = (ವರ್ಣ)c;
		ಯದಿ (last == '.' && c == '.') {
			snprintf(errbuf, ಪರಿಮಾಣ(errbuf), "domain name "
			    "\"%.100s\" contains consecutive separators", name);
			ಗಚ್ಛ bad;
		}
		ಯದಿ (c != '.' && c != '-' && !isalnum(c) &&
		    c != '_') /* technically invalid, but common */ {
			snprintf(errbuf, ಪರಿಮಾಣ(errbuf), "domain name "
			    "\"%.100s\" contains invalid characters", name);
			ಗಚ್ಛ bad;
		}
		last = c;
	}
	ಯದಿ (name[l - 1] == '.')
		name[l - 1] = '\0';
	ಯದಿ (errstr != ರಿಕ್ತ)
		*errstr = ರಿಕ್ತ;
	ಪ್ರತ್ಯಾಗಮ 1;
bad:
	ಯದಿ (errstr != ರಿಕ್ತ)
		*errstr = errbuf;
	ಪ್ರತ್ಯಾಗಮ 0;
}

/*
 * Verify that a environment variable name (not including initial '$') is
 * valid; consisting of one or more alphanumeric or underscore characters only.
 * Returns 1 on valid, 0 otherwise.
 */
ಪೂರ್ಣಾಙ್ಕ
valid_env_name(ಧ್ರುವ ವರ್ಣ *name)
{
	ಧ್ರುವ ವರ್ಣ *cp;

	ಯದಿ (name[0] == '\0')
		ಪ್ರತ್ಯಾಗಮ 0;
	ಪ್ರತಿ (cp = name; *cp != '\0'; cp++) {
		ಯದಿ (!isalnum((u_char)*cp) && *cp != '_')
			ಪ್ರತ್ಯಾಗಮ 0;
	}
	ಪ್ರತ್ಯಾಗಮ 1;
}

ಧ್ರುವ ವರ್ಣ *
atoi_err(ಧ್ರುವ ವರ್ಣ *nptr, ಪೂರ್ಣಾಙ್ಕ *val)
{
	ಧ್ರುವ ವರ್ಣ *errstr = ರಿಕ್ತ;

	ಯದಿ (nptr == ರಿಕ್ತ || *nptr == '\0')
		ಪ್ರತ್ಯಾಗಮ "missing";
	*val = strtonum(nptr, 0, INT_MAX, &errstr);
	ಪ್ರತ್ಯಾಗಮ errstr;
}

ಪೂರ್ಣಾಙ್ಕ
parse_absolute_time(ಧ್ರುವ ವರ್ಣ *s, uint64_t *tp)
{
	ಸಂರಚನಾ tm tm;
	time_t tt;
	ವರ್ಣ buf[32], *fmt;
	ಧ್ರುವ ವರ್ಣ *cp;
	size_t l;
	ಪೂರ್ಣಾಙ್ಕ is_utc = 0;

	*tp = 0;

	l = strlen(s);
	ಯದಿ (l > 1 && strcasecmp(s + l - 1, "Z") == 0) {
		is_utc = 1;
		l--;
	} ಅನ್ಯಥಾ ಯದಿ (l > 3 && strcasecmp(s + l - 3, "UTC") == 0) {
		is_utc = 1;
		l -= 3;
	}
	/*
	 * POSIX strptime says "The application shall ensure that there
	 * is white-space or other non-alphanumeric characters between
	 * any two conversion specifications" so arrange things this way.
	 */
	ವಿಕಲ್ಪ (l) {
	ಪಕ್ಷ 8: /* YYYYMMDD */
		fmt = "%Y-%m-%d";
		snprintf(buf, ಪರಿಮಾಣ(buf), "%.4s-%.2s-%.2s", s, s + 4, s + 6);
		ಭಙ್ಗ;
	ಪಕ್ಷ 12: /* YYYYMMDDHHMM */
		fmt = "%Y-%m-%dT%H:%M";
		snprintf(buf, ಪರಿಮಾಣ(buf), "%.4s-%.2s-%.2sT%.2s:%.2s",
		    s, s + 4, s + 6, s + 8, s + 10);
		ಭಙ್ಗ;
	ಪಕ್ಷ 14: /* YYYYMMDDHHMMSS */
		fmt = "%Y-%m-%dT%H:%M:%S";
		snprintf(buf, ಪರಿಮಾಣ(buf), "%.4s-%.2s-%.2sT%.2s:%.2s:%.2s",
		    s, s + 4, s + 6, s + 8, s + 10, s + 12);
		ಭಙ್ಗ;
	ಸ್ವಭಾವ:
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_FORMAT;
	}

	memset(&tm, 0, ಪರಿಮಾಣ(tm));
	ಯದಿ ((cp = strptime(buf, fmt, &tm)) == ರಿಕ್ತ || *cp != '\0')
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_FORMAT;
	ಯದಿ (is_utc) {
		tm.tm_wday = -1;	/* sentinel for error */
		ಯದಿ ((tt = timegm(&tm)) == -1 && tm.tm_wday == -1)
			ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_FORMAT;
	} ಅನ್ಯಥಾ {
		tm.tm_wday = -1;	/* sentinel for error */
		tm.tm_isdst = -1;	/* mktime decides DST */
		ಯದಿ ((tt = mktime(&tm)) == -1 && tm.tm_wday == -1)
			ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_FORMAT;
	}
	/* success */
	*tp = (uint64_t)tt;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಶೂನ್ಯ
format_absolute_time(uint64_t t, ವರ್ಣ *buf, size_t len)
{
	time_t tt = t > SSH_TIME_T_MAX ? SSH_TIME_T_MAX : t;
	ಸಂರಚನಾ tm tm;

	ಯದಿ (localtime_r(&tt, &tm) == ರಿಕ್ತ)
		strlcpy(buf, "UNKNOWN-TIME", len);
	ಅನ್ಯಥಾ
		strftime(buf, len, "%Y-%m-%dT%H:%M:%S", &tm);
}

/*
 * Parse a "pattern=interval" clause (e.g. a ChannelTimeout).
 * Returns 0 on success or non-zero on failure.
 * Caller must free *typep.
 */
ಪೂರ್ಣಾಙ್ಕ
parse_pattern_interval(ಧ್ರುವ ವರ್ಣ *s, ವರ್ಣ **typep, ದ್ವಿಗುಣ *secsp)
{
	ವರ್ಣ *cp, *sdup;
	ದ್ವಿಗುಣ secs;

	ಯದಿ (typep != ರಿಕ್ತ)
		*typep = ರಿಕ್ತ;
	ಯದಿ (secsp != ರಿಕ್ತ)
		*secsp = 0;
	ಯದಿ (s == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ -1;
	sdup = xstrdup(s);

	ಯದಿ ((cp = strchr(sdup, '=')) == ರಿಕ್ತ || cp == sdup) {
		ಮುಕ್ತ(sdup);
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	*cp++ = '\0';
	ಯದಿ ((secs = convtime_double(cp)) < 0.0) {
		ಮುಕ್ತ(sdup);
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	/* success */
	ಯದಿ (typep != ರಿಕ್ತ)
		*typep = xstrdup(sdup);
	ಯದಿ (secsp != ರಿಕ್ತ)
		*secsp = secs;
	ಮುಕ್ತ(sdup);
	ಪ್ರತ್ಯಾಗಮ 0;
}

/* check if path is absolute */
ಪೂರ್ಣಾಙ್ಕ
path_absolute(ಧ್ರುವ ವರ್ಣ *path)
{
	ಪ್ರತ್ಯಾಗಮ (*path == '/') ? 1 : 0;
}

ಶೂನ್ಯ
skip_space(ವರ್ಣ **cpp)
{
	ವರ್ಣ *cp;

	ಪ್ರತಿ (cp = *cpp; *cp == ' ' || *cp == '\t'; cp++)
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
ಪೂರ್ಣಾಙ್ಕ
opt_flag(ಧ್ರುವ ವರ್ಣ *opt, ಪೂರ್ಣಾಙ್ಕ allow_negate, ಧ್ರುವ ವರ್ಣ **optsp)
{
	size_t opt_len = strlen(opt);
	ಧ್ರುವ ವರ್ಣ *opts = *optsp;
	ಪೂರ್ಣಾಙ್ಕ negate = 0;

	ಯದಿ (allow_negate && strncasecmp(opts, "no-", 3) == 0) {
		opts += 3;
		negate = 1;
	}
	ಯದಿ (strncasecmp(opts, opt, opt_len) == 0) {
		*optsp = opts + opt_len;
		ಪ್ರತ್ಯಾಗಮ negate ? 0 : 1;
	}
	ಪ್ರತ್ಯಾಗಮ -1;
}

ವರ್ಣ *
opt_dequote(ಧ್ರುವ ವರ್ಣ **sp, ಧ್ರುವ ವರ್ಣ **errstrp)
{
	ಧ್ರುವ ವರ್ಣ *s = *sp;
	ವರ್ಣ *ret;
	size_t i;

	*errstrp = ರಿಕ್ತ;
	ಯದಿ (*s != '"') {
		*errstrp = "missing start quote";
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}
	s++;
	ಯದಿ ((ret = malloc(strlen((s)) + 1)) == ರಿಕ್ತ) {
		*errstrp = "memory allocation failed";
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}
	ಪ್ರತಿ (i = 0; *s != '\0' && *s != '"';) {
		ಯದಿ (s[0] == '\\' && s[1] == '"')
			s++;
		ret[i++] = *s++;
	}
	ಯದಿ (*s == '\0') {
		*errstrp = "missing end quote";
		ಮುಕ್ತ(ret);
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}
	ret[i] = '\0';
	s++;
	*sp = s;
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಪೂರ್ಣಾಙ್ಕ
opt_match(ಧ್ರುವ ವರ್ಣ **opts, ಧ್ರುವ ವರ್ಣ *term)
{
	ಯದಿ (strncasecmp((*opts), term, strlen(term)) == 0 &&
	    (*opts)[strlen(term)] == '=') {
		*opts += strlen(term) + 1;
		ಪ್ರತ್ಯಾಗಮ 1;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಶೂನ್ಯ
opt_array_append2(ಧ್ರುವ ವರ್ಣ *file, ಧ್ರುವ ಪೂರ್ಣಾಙ್ಕ ಸಾಲು, ಧ್ರುವ ವರ್ಣ *directive,
    ವರ್ಣ ***array, ಪೂರ್ಣಾಙ್ಕ **iarray, u_int *lp, ಧ್ರುವ ವರ್ಣ *s, ಪೂರ್ಣಾಙ್ಕ i)
{

	ಯದಿ (*lp >= INT_MAX)
		fatal("%s line %d: Too many %s entries", file, ಸಾಲು, directive);

	ಯದಿ (iarray != ರಿಕ್ತ) {
		*iarray = xrecallocarray(*iarray, *lp, *lp + 1,
		    ಪರಿಮಾಣ(**iarray));
		(*iarray)[*lp] = i;
	}

	*array = xrecallocarray(*array, *lp, *lp + 1, ಪರಿಮಾಣ(**array));
	(*array)[*lp] = xstrdup(s);
	(*lp)++;
}

ಶೂನ್ಯ
opt_array_append(ಧ್ರುವ ವರ್ಣ *file, ಧ್ರುವ ಪೂರ್ಣಾಙ್ಕ ಸಾಲು, ಧ್ರುವ ವರ್ಣ *directive,
    ವರ್ಣ ***array, u_int *lp, ಧ್ರುವ ವರ್ಣ *s)
{
	opt_array_append2(file, ಸಾಲು, directive, array, ರಿಕ್ತ, lp, s, 0);
}

ಶೂನ್ಯ
opt_array_free2(ವರ್ಣ **array, ಪೂರ್ಣಾಙ್ಕ **iarray, u_int l)
{
	u_int i;

	ಯದಿ (array == ರಿಕ್ತ || l == 0)
		ಪ್ರತ್ಯಾಗಮ;
	ಪ್ರತಿ (i = 0; i < l; i++)
		ಮುಕ್ತ(array[i]);
	ಮುಕ್ತ(array);
	ಮುಕ್ತ(iarray);
}

sshsig_t
ssh_signal(ಪೂರ್ಣಾಙ್ಕ signum, sshsig_t handler)
{
	ಸಂರಚನಾ sigaction sa, osa;

	/* mask all other signals while in handler */
	memset(&sa, 0, ಪರಿಮಾಣ(sa));
	sa.sa_handler = handler;
	sigfillset(&sa.sa_mask);
#ಯದಿ defined(SA_RESTART) && !defined(NO_SA_RESTART)
	ಯದಿ (signum != SIGALRM)
		sa.sa_flags = SA_RESTART;
#endif
	ಯದಿ (sigaction(signum, &sa, &osa) == -1) {
		debug3("sigaction(%s): %s", strsignal(signum), strerror(errno));
		ಪ್ರತ್ಯಾಗಮ SIG_ERR;
	}
	ಪ್ರತ್ಯಾಗಮ osa.sa_handler;
}

ಪೂರ್ಣಾಙ್ಕ
stdfd_devnull(ಪೂರ್ಣಾಙ್ಕ do_stdin, ಪೂರ್ಣಾಙ್ಕ do_stdout, ಪೂರ್ಣಾಙ್ಕ do_stderr)
{
	ಪೂರ್ಣಾಙ್ಕ devnull, ret = 0;

	ಯದಿ ((devnull = open(_PATH_DEVNULL, O_RDWR)) == -1) {
		error_f("open %s: %s", _PATH_DEVNULL,
		    strerror(errno));
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	ಯದಿ ((do_stdin && dup2(devnull, STDIN_FILENO) == -1) ||
	    (do_stdout && dup2(devnull, STDOUT_FILENO) == -1) ||
	    (do_stderr && dup2(devnull, STDERR_FILENO) == -1)) {
		error_f("dup2: %s", strerror(errno));
		ret = -1;
	}
	ಯದಿ (devnull > STDERR_FILENO)
		close(devnull);
	ಪ್ರತ್ಯಾಗಮ ret;
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
subprocess(ಧ್ರುವ ವರ್ಣ *tag, ಧ್ರುವ ವರ್ಣ *command,
    ಪೂರ್ಣಾಙ್ಕ ac, ವರ್ಣ **av, FILE **child, u_int flags,
    ಸಂರಚನಾ passwd *pw, privdrop_fn *drop_privs, privrestore_fn *restore_privs)
{
	FILE *f = ರಿಕ್ತ;
	ಸಂರಚನಾ stat st;
	ಪೂರ್ಣಾಙ್ಕ fd, devnull, p[2], i;
	pid_t pid;
	ವರ್ಣ *cp, errmsg[512];
	u_int nenv = 0;
	ವರ್ಣ **env = ರಿಕ್ತ;

	/* If dropping privs, then must specify user and restore function */
	ಯದಿ (drop_privs != ರಿಕ್ತ && (pw == ರಿಕ್ತ || restore_privs == ರಿಕ್ತ)) {
		error("%s: inconsistent arguments", tag); /* XXX fatal? */
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	ಯದಿ (pw == ರಿಕ್ತ && (pw = getpwuid(getuid())) == ರಿಕ್ತ) {
		error("%s: no user for current uid", tag);
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	ಯದಿ (child != ರಿಕ್ತ)
		*child = ರಿಕ್ತ;

	debug3_f("%s command \"%s\" running as %s (flags 0x%x)",
	    tag, command, pw->pw_name, flags);

	/* Check consistency */
	ಯದಿ ((flags & SSH_SUBPROCESS_STDOUT_DISCARD) != 0 &&
	    (flags & SSH_SUBPROCESS_STDOUT_CAPTURE) != 0) {
		error_f("inconsistent flags");
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	ಯದಿ (((flags & SSH_SUBPROCESS_STDOUT_CAPTURE) == 0) != (child == ರಿಕ್ತ)) {
		error_f("inconsistent flags/output");
		ಪ್ರತ್ಯಾಗಮ 0;
	}

	/*
	 * If executing an explicit binary, then verify the it exists
	 * and appears safe-ish to execute
	 */
	ಯದಿ (!path_absolute(av[0])) {
		error("%s path is not absolute", tag);
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	ಯದಿ (drop_privs != ರಿಕ್ತ)
		drop_privs(pw);
	ಯದಿ (stat(av[0], &st) == -1) {
		error("Could not stat %s \"%s\": %s", tag,
		    av[0], strerror(errno));
		ಗಚ್ಛ restore_return;
	}
	ಯದಿ ((flags & SSH_SUBPROCESS_UNSAFE_PATH) == 0 &&
	    safe_path(av[0], &st, ರಿಕ್ತ, 0, errmsg, ಪರಿಮಾಣ(errmsg)) != 0) {
		error("Unsafe %s \"%s\": %s", tag, av[0], errmsg);
		ಗಚ್ಛ restore_return;
	}
	/* Prepare to keep the child's stdout if requested */
	ಯದಿ (pipe(p) == -1) {
		error("%s: pipe: %s", tag, strerror(errno));
 restore_return:
		ಯದಿ (restore_privs != ರಿಕ್ತ)
			restore_privs();
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	ಯದಿ (restore_privs != ರಿಕ್ತ)
		restore_privs();

	ವಿಕಲ್ಪ ((pid = fork())) {
	ಪಕ್ಷ -1: /* error */
		error("%s: fork: %s", tag, strerror(errno));
		close(p[0]);
		close(p[1]);
		ಪ್ರತ್ಯಾಗಮ 0;
	ಪಕ್ಷ 0: /* child */
		/* Prepare a minimal environment for the child. */
		ಯದಿ ((flags & SSH_SUBPROCESS_PRESERVE_ENV) == 0) {
			nenv = 5;
			env = xcalloc(ಪರಿಮಾಣ(*env), nenv);
			child_set_env(&env, &nenv, "PATH", _PATH_STDPATH);
			child_set_env(&env, &nenv, "USER", pw->pw_name);
			child_set_env(&env, &nenv, "LOGNAME", pw->pw_name);
			child_set_env(&env, &nenv, "HOME", pw->pw_dir);
			ಯದಿ ((cp = getenv("LANG")) != ರಿಕ್ತ)
				child_set_env(&env, &nenv, "LANG", cp);
		}

		ಪ್ರತಿ (i = 1; i < NSIG; i++)
			ssh_signal(i, SIG_DFL);

		ಯದಿ ((devnull = open(_PATH_DEVNULL, O_RDWR)) == -1) {
			error("%s: open %s: %s", tag, _PATH_DEVNULL,
			    strerror(errno));
			_exit(1);
		}
		ಯದಿ (dup2(devnull, STDIN_FILENO) == -1) {
			error("%s: dup2: %s", tag, strerror(errno));
			_exit(1);
		}

		/* Set up stdout as requested; leave stderr in place for now. */
		fd = -1;
		ಯದಿ ((flags & SSH_SUBPROCESS_STDOUT_CAPTURE) != 0)
			fd = p[1];
		ಅನ್ಯಥಾ ಯದಿ ((flags & SSH_SUBPROCESS_STDOUT_DISCARD) != 0)
			fd = devnull;
		ಯದಿ (fd != -1 && dup2(fd, STDOUT_FILENO) == -1) {
			error("%s: dup2: %s", tag, strerror(errno));
			_exit(1);
		}
		closefrom(STDERR_FILENO + 1);

		ಯದಿ (geteuid() == 0 &&
		    initgroups(pw->pw_name, pw->pw_gid) == -1) {
			error("%s: initgroups(%s, %u): %s", tag,
			    pw->pw_name, (u_int)pw->pw_gid, strerror(errno));
			_exit(1);
		}
		ಯದಿ (setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) == -1) {
			error("%s: setresgid %u: %s", tag, (u_int)pw->pw_gid,
			    strerror(errno));
			_exit(1);
		}
		ಯದಿ (setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) == -1) {
			error("%s: setresuid %u: %s", tag, (u_int)pw->pw_uid,
			    strerror(errno));
			_exit(1);
		}
		/* stdin is pointed to /dev/null at this point */
		ಯದಿ ((flags & SSH_SUBPROCESS_STDOUT_DISCARD) != 0 &&
		    dup2(STDIN_FILENO, STDERR_FILENO) == -1) {
			error("%s: dup2: %s", tag, strerror(errno));
			_exit(1);
		}
		ಯದಿ (env != ರಿಕ್ತ)
			execve(av[0], av, env);
		ಅನ್ಯಥಾ
			execv(av[0], av);
		error("%s %s \"%s\": %s", tag, env == ರಿಕ್ತ ? "execv" : "execve",
		    command, strerror(errno));
		_exit(127);
	ಸ್ವಭಾವ: /* parent */
		ಭಙ್ಗ;
	}

	close(p[1]);
	ಯದಿ ((flags & SSH_SUBPROCESS_STDOUT_CAPTURE) == 0)
		close(p[0]);
	ಅನ್ಯಥಾ ಯದಿ ((f = fdopen(p[0], "r")) == ರಿಕ್ತ) {
		error("%s: fdopen: %s", tag, strerror(errno));
		close(p[0]);
		/* Don't leave zombie child */
		kill(pid, SIGTERM);
		ಯಾವತ್ (waitpid(pid, ರಿಕ್ತ, 0) == -1 && errno == EINTR)
			;
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	/* Success */
	debug3_f("%s pid %ld", tag, (long)pid);
	ಯದಿ (child != ರಿಕ್ತ)
		*child = f;
	ಪ್ರತ್ಯಾಗಮ pid;
}

ಧ್ರುವ ವರ್ಣ *
lookup_env_in_list(ಧ್ರುವ ವರ್ಣ *env, ವರ್ಣ * ಧ್ರುವ *envs, size_t nenvs)
{
	size_t i, envlen;

	envlen = strlen(env);
	ಪ್ರತಿ (i = 0; i < nenvs; i++) {
		ಯದಿ (strncmp(envs[i], env, envlen) == 0 &&
		    envs[i][envlen] == '=') {
			ಪ್ರತ್ಯಾಗಮ envs[i] + envlen + 1;
		}
	}
	ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
}

ಧ್ರುವ ವರ್ಣ *
lookup_setenv_in_list(ಧ್ರುವ ವರ್ಣ *env, ವರ್ಣ * ಧ್ರುವ *envs, size_t nenvs)
{
	ವರ್ಣ *name, *cp;
	ಧ್ರುವ ವರ್ಣ *ret;

	name = xstrdup(env);
	ಯದಿ ((cp = strchr(name, '=')) == ರಿಕ್ತ) {
		ಮುಕ್ತ(name);
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ; /* not env=val */
	}
	*cp = '\0';
	ret = lookup_env_in_list(name, envs, nenvs);
	ಮುಕ್ತ(name);
	ಪ್ರತ್ಯಾಗಮ ret;
}

/*
 * Helpers for managing poll(2)/ppoll(2) timeouts
 * Will remember the earliest deadline and return it for use in poll/ppoll.
 */

/* Initialise a poll/ppoll timeout with an indefinite deadline */
ಶೂನ್ಯ
ptimeout_init(ಸಂರಚನಾ timespec *pt)
{
	/*
	 * Deliberately invalid for ppoll(2).
	 * Will be converted to NULL in ptimeout_get_tspec() later.
	 */
	pt->tv_sec = -1;
	pt->tv_nsec = 0;
}

/* Specify a poll/ppoll deadline of at most 'sec' seconds */
ಶೂನ್ಯ
ptimeout_deadline_sec(ಸಂರಚನಾ timespec *pt, long sec)
{
	ಯದಿ (pt->tv_sec == -1 || pt->tv_sec >= sec) {
		pt->tv_sec = sec;
		pt->tv_nsec = 0;
	}
}

/* Specify a poll/ppoll deadline of at most 'p' (timespec) */
ಸ್ಥಿರ ಶೂನ್ಯ
ptimeout_deadline_tsp(ಸಂರಚನಾ timespec *pt, ಸಂರಚನಾ timespec *p)
{
	ಯದಿ (pt->tv_sec == -1 || timespeccmp(pt, p, >=))
		*pt = *p;
}

/* Specify a poll/ppoll deadline of at most 'ms' milliseconds */
ಶೂನ್ಯ
ptimeout_deadline_ms(ಸಂರಚನಾ timespec *pt, long ms)
{
	ಸಂರಚನಾ timespec p;

	p.tv_sec = ms / 1000;
	p.tv_nsec = (ms % 1000) * 1000000;
	ptimeout_deadline_tsp(pt, &p);
}

/* Specify a poll/ppoll deadline of at most 'sec' seconds (double) */
ಶೂನ್ಯ
ptimeout_deadline_sec_double(ಸಂರಚನಾ timespec *pt, ದ್ವಿಗುಣ sec)
{
	ಸಂರಚನಾ timespec t;

	memset(&t, 0, ಪರಿಮಾಣ(t));
	ಯದಿ ((int64_t)sec >= SSH_TIME_T_MAX)
		t.tv_sec = SSH_TIME_T_MAX;
	ಅನ್ಯಥಾ ಯದಿ (sec > 0) {
		t.tv_sec = sec;
		t.tv_nsec = (sec - (ದ್ವಿಗುಣ)t.tv_sec) * 1000000000.0;
	}
	ptimeout_deadline_tsp(pt, &t);
}

/* Specify a poll/ppoll deadline at wall clock monotime 'when' (timespec) */
ಶೂನ್ಯ
ptimeout_deadline_monotime_tsp(ಸಂರಚನಾ timespec *pt, ಸಂರಚನಾ timespec *when)
{
	ಸಂರಚನಾ timespec now, t;

	monotime_ts(&now);

	ಯದಿ (timespeccmp(&now, when, >=)) {
		/* 'when' is now or in the past. Timeout ASAP */
		pt->tv_sec = 0;
		pt->tv_nsec = 0;
	} ಅನ್ಯಥಾ {
		timespecsub(when, &now, &t);
		ptimeout_deadline_tsp(pt, &t);
	}
}

/* Specify a poll/ppoll deadline at wall clock monotime 'when' (double) */
ಶೂನ್ಯ
ptimeout_deadline_monotime_double(ಸಂರಚನಾ timespec *pt, ದ್ವಿಗುಣ when)
{
	ptimeout_deadline_sec_double(pt, when - monotime_double());
}

/* Specify a poll/ppoll deadline at wall clock monotime 'when' */
ಶೂನ್ಯ
ptimeout_deadline_monotime(ಸಂರಚನಾ timespec *pt, time_t when)
{
	ಸಂರಚನಾ timespec t;

	t.tv_sec = when;
	t.tv_nsec = 0;
	ptimeout_deadline_monotime_tsp(pt, &t);
}

/* Get a poll(2) timeout value in milliseconds */
ಪೂರ್ಣಾಙ್ಕ
ptimeout_get_ms(ಸಂರಚನಾ timespec *pt)
{
	ಯದಿ (pt->tv_sec == -1)
		ಪ್ರತ್ಯಾಗಮ -1;
	ಯದಿ (pt->tv_sec >= (INT_MAX - (pt->tv_nsec / 1000000)) / 1000)
		ಪ್ರತ್ಯಾಗಮ INT_MAX;
	ಪ್ರತ್ಯಾಗಮ (pt->tv_sec * 1000) + (pt->tv_nsec / 1000000);
}

/* Get a ppoll(2) timeout value as a timespec pointer */
ಸಂರಚನಾ timespec *
ptimeout_get_tsp(ಸಂರಚನಾ timespec *pt)
{
	ಪ್ರತ್ಯಾಗಮ pt->tv_sec == -1 ? ರಿಕ್ತ : pt;
}

/* Returns non-zero if a timeout has been set (i.e. is not indefinite) */
ಪೂರ್ಣಾಙ್ಕ
ptimeout_isset(ಸಂರಚನಾ timespec *pt)
{
	ಪ್ರತ್ಯಾಗಮ pt->tv_sec != -1;
}

/*
 * Returns zero if the library at 'path' contains symbol 's', nonzero
 * otherwise.
 */
ಪೂರ್ಣಾಙ್ಕ
lib_contains_ಚಿಹ್ನೆ(ಧ್ರುವ ವರ್ಣ *path, ಧ್ರುವ ವರ್ಣ *s)
{
#ifdef HAVE_NLIST
	ಸಂರಚನಾ nlist nl[2];
	ಪೂರ್ಣಾಙ್ಕ ret = -1, r;

	memset(nl, 0, ಪರಿಮಾಣ(nl));
	nl[0].n_name = xstrdup(s);
	nl[1].n_name = ರಿಕ್ತ;
	ಯದಿ ((r = nlist(path, nl)) == -1) {
		error_f("nlist failed for %s", path);
		ಗಚ್ಛ out;
	}
	ಯದಿ (r != 0 || nl[0].n_ಮೌಲ್ಯ == 0 || nl[0].n_type == 0) {
		error_f("library %s does not contain symbol %s", path, s);
		ಗಚ್ಛ out;
	}
	/* success */
	ret = 0;
 out:
	ಮುಕ್ತ(nl[0].n_name);
	ಪ್ರತ್ಯಾಗಮ ret;
#ಅನ್ಯಥಾ /* HAVE_NLIST */
	ಪೂರ್ಣಾಙ್ಕ fd, ret = -1;
	ಸಂರಚನಾ stat st;
	ಶೂನ್ಯ *m = ರಿಕ್ತ;
	size_t sz = 0;

	memset(&st, 0, ಪರಿಮಾಣ(st));
	ಯದಿ ((fd = open(path, O_RDONLY)) < 0) {
		error_f("open %s: %s", path, strerror(errno));
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	ಯದಿ (fstat(fd, &st) != 0) {
		error_f("fstat %s: %s", path, strerror(errno));
		ಗಚ್ಛ out;
	}
	ಯದಿ (!S_ISREG(st.st_mode)) {
		error_f("%s is not a regular file", path);
		ಗಚ್ಛ out;
	}
	ಯದಿ (st.st_size < 0 ||
	    (size_t)st.st_size < strlen(s) ||
	    st.st_size >= INT_MAX/2) {
		error_f("%s bad size %lld", path, (long long)st.st_size);
		ಗಚ್ಛ out;
	}
	sz = (size_t)st.st_size;
	ಯದಿ ((m = mmap(ರಿಕ್ತ, sz, PROT_READ, MAP_PRIVATE, fd, 0)) == MAP_FAILED ||
	    m == ರಿಕ್ತ) {
		error_f("mmap %s: %s", path, strerror(errno));
		ಗಚ್ಛ out;
	}
	ಯದಿ (memmem(m, sz, s, strlen(s)) == ರಿಕ್ತ) {
		error_f("%s does not contain expected string %s", path, s);
		ಗಚ್ಛ out;
	}
	/* success */
	ret = 0;
 out:
	ಯದಿ (m != ರಿಕ್ತ && m != MAP_FAILED)
		munmap(m, sz);
	close(fd);
	ಪ್ರತ್ಯಾಗಮ ret;
#endif /* HAVE_NLIST */
}

ಪೂರ್ಣಾಙ್ಕ
signal_is_crash(ಪೂರ್ಣಾಙ್ಕ sig)
{
	ವಿಕಲ್ಪ (sig) {
	ಪಕ್ಷ SIGSEGV:
	ಪಕ್ಷ SIGBUS:
	ಪಕ್ಷ SIGTRAP:
	ಪಕ್ಷ SIGSYS:
	ಪಕ್ಷ SIGFPE:
	ಪಕ್ಷ SIGILL:
	ಪಕ್ಷ SIGABRT:
		ಪ್ರತ್ಯಾಗಮ 1;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

ವರ್ಣ *
get_homedir(ಶೂನ್ಯ)
{
	ವರ್ಣ *cp;
	ಸಂರಚನಾ passwd *pw;

	ಯದಿ ((cp = getenv("HOME")) != ರಿಕ್ತ && *cp != '\0')
		ಪ್ರತ್ಯಾಗಮ xstrdup(cp);

	ಯದಿ ((pw = getpwuid(getuid())) != ರಿಕ್ತ && *pw->pw_dir != '\0')
		ಪ್ರತ್ಯಾಗಮ xstrdup(pw->pw_dir);

	ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
}

ಪೂರ್ಣಾಙ್ಕ
mkdir_path(ಧ್ರುವ ವರ್ಣ *target, mode_t mode)
{
#ಯದಿ defined(HAVE_OPENAT) && defined(O_DIRECTORY)
	ವರ್ಣ *dir, *odir = ರಿಕ್ತ, *next;
	ಪೂರ್ಣಾಙ್ಕ fd = AT_FDCWD, fd2, subpath_len, ret = -1;

	dir = odir = xstrdup(target);

	ಯದಿ (*dir == '/' &&
	    (fd = open("/", O_RDONLY|O_DIRECTORY)) == -1) {
		error_f("open(\"/\"): %s", strerror(errno));
		ಮುಕ್ತ(odir);
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	/* Work through the path, component-wise */
	ಪ್ರತಿ (; dir != ರಿಕ್ತ && *dir != '\0'; dir = next) {
		ಯದಿ ((next = strchr(dir, '/')) != ರಿಕ್ತ)
			*(next++) = '\0';
		ಯದಿ (*dir == '\0')
			ಅನುವರ್ತ;
		subpath_len = (next == ರಿಕ್ತ) ? INT_MAX : next - odir - 1;
		ಯದಿ (mkdirat(fd, dir, mode) == 0)
			debug_f("created directory %.*s", subpath_len, target);
		ಅನ್ಯಥಾ ಯದಿ (errno != EEXIST) {
			error_f("mkdir(\"%.*s\"): %s",
			    subpath_len, target, strerror(errno));
			ಗಚ್ಛ out;
		}

		/* descend */
		ಯದಿ ((fd2 = openat(fd, dir, O_RDONLY|O_DIRECTORY)) == -1) {
			error_f("open(\"%.*s\"): %s",
			    subpath_len, target, strerror(errno));
			ಗಚ್ಛ out;
		}
		ಯದಿ (fd != AT_FDCWD)
			close(fd);
		fd = fd2;
	}
	/* success */
	ret = 0;
 out:
	ಮುಕ್ತ(odir);
	ಯದಿ (fd != AT_FDCWD)
		close(fd);
	ಪ್ರತ್ಯಾಗಮ ret;
#ಅನ್ಯಥಾ
	/*
	 * If we don't have openat (which was added in POSIX.1-2008), fall back
	 * to the possibly racy way.
	 */
	ವರ್ಣ *dir, *odir, *p, path[PATH_MAX] = "";
	ಪೂರ್ಣಾಙ್ಕ ret = -1;
	size_t plen = ಪರಿಮಾಣ(path);

	dir = odir = xstrdup(target);

	/* If the dir is relative, start with cwd. */
	ಯದಿ (*dir != '/' && getcwd(path, plen) == ರಿಕ್ತ) {
		error_f("getcwd: %s", strerror(errno));
		ಗಚ್ಛ out;
	}

	/* Work through the path, component-wise */
	ಯಾವತ್ ((p = strsep(&dir, "/"))) {
		ಯದಿ (*p == '\0')
			ಅನುವರ್ತ;
		ಯದಿ (strlcat(path, "/", plen) >= plen ||
		    strlcat(path, p, plen) >= plen)
			ಗಚ್ಛ out;
		ಯದಿ (mkdir(path, mode) == 0)
			debug_f("created directory %s", path);
		ಅನ್ಯಥಾ ಯದಿ (errno != EEXIST && errno != EISDIR) {
			error_f("mkdir(\"%s\"): %s", path, strerror(errno));
			ಗಚ್ಛ out;
		}
	}
	/* success */
	ret = 0;
 out:
	ಮುಕ್ತ(odir);
	ಪ್ರತ್ಯಾಗಮ ret;
#endif
}
