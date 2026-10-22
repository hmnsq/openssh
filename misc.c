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
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ SSH_TUN_OPENBSD
#ಅನ್ತರ್ಭಾವ <net/if.h>
#ಆದರೆ_ಅಂತ್ಯ

#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "ssh.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "platform.h"

/* remove newline at end of string */
ಅಕ್ಷರ *
chop(ಅಕ್ಷರ *s)
{
	ಅಕ್ಷರ *t = s;
	ಆಗ (*t) {
		ಆದರೆ (*t == '\n' || *t == '\r') {
			*t = '\0';
			ಹಿಂತಿರುಗಿ s;
		}
		t++;
	}
	ಹಿಂತಿರುಗಿ s;

}

/* remove whitespace from end of string */
ಶೂನ್ಯ
rtrim(ಅಕ್ಷರ *s)
{
	ಗಾತ್ರ_t i;

	ಆದರೆ ((i = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(s)) == 0)
		ಹಿಂತಿರುಗಿ;
	ಮಾಡು {
		i--;
		ಆದರೆ (ಖಾಲಿಯೇ((ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ)s[i]))
			s[i] = '\0';
		ಇಲ್ಲದಿದ್ದರೆ
			ನಿಲ್ಲಿಸು;
	} ಆಗ (i > 0);
}

/*
 * returns pointer to character after 'prefix' in 's' or otherwise NULL
 * if the prefix is not present.
 */
ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *
strprefix(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *s, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಪೂರ್ವಪ್ರತ್ಯಯ, ಪೂರ್ಣಾಂಕ ignorecase)
{
	ಗಾತ್ರ_t prefixlen;

	ಆದರೆ ((prefixlen = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(ಪೂರ್ವಪ್ರತ್ಯಯ)) == 0)
		ಹಿಂತಿರುಗಿ s;
	ಆದರೆ (ignorecase) {
		ಆದರೆ (strncasecmp(s, ಪೂರ್ವಪ್ರತ್ಯಯ, prefixlen) != 0)
			ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	} ಇಲ್ಲದಿದ್ದರೆ {
		ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಹೋಲಿಕೆ(s, ಪೂರ್ವಪ್ರತ್ಯಯ, prefixlen) != 0)
			ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	ಹಿಂತಿರುಗಿ s + prefixlen;
}

/* Append string 's' to a NULL-terminated array of strings */
ಶೂನ್ಯ
stringlist_append(ಅಕ್ಷರ ***listp, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *s)
{
	ಗಾತ್ರ_t i = 0;

	ಆದರೆ (*listp == ಖಾಲಿ)
		*listp = xcalloc(2, ಗಾತ್ರ(**listp));
	ಇಲ್ಲದಿದ್ದರೆ {
		ಗಾಗಿ (i = 0; (*listp)[i] != ಖಾಲಿ; i++)
			; /* count */
		*listp = xrecallocarray(*listp, i + 1, i + 2, ಗಾತ್ರ(**listp));
	}
	(*listp)[i] = xstrdup(s);
}

ಶೂನ್ಯ
stringlist_free(ಅಕ್ಷರ **list)
{
	ಗಾತ್ರ_t i = 0;

	ಆದರೆ (list == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;
	ಗಾಗಿ (i = 0; list[i] != ಖಾಲಿ; i++)
		ಬಿಡುಗಡೆ(list[i]);
	ಬಿಡುಗಡೆ(list);
}

/* set/unset filedescriptor to non-blocking */
ಪೂರ್ಣಾಂಕ
ಗಣ_nonblock(ಪೂರ್ಣಾಂಕ fd)
{
	ಪೂರ್ಣಾಂಕ val;

	val = fcntl(fd, F_GETFL);
	ಆದರೆ (val == -1) {
		error("fcntl(%d, F_GETFL): %s", fd, strerror(errno));
		ಹಿಂತಿರುಗಿ (-1);
	}
	ಆದರೆ (val & O_NONBLOCK) {
		debug3("fd %d is O_NONBLOCK", fd);
		ಹಿಂತಿರುಗಿ (0);
	}
	debug2("fd %d setting O_NONBLOCK", fd);
	val |= O_NONBLOCK;
	ಆದರೆ (fcntl(fd, F_SETFL, val) == -1) {
		debug("fcntl(%d, F_SETFL, O_NONBLOCK): %s", fd,
		    strerror(errno));
		ಹಿಂತಿರುಗಿ (-1);
	}
	ಹಿಂತಿರುಗಿ (0);
}

ಪೂರ್ಣಾಂಕ
unset_nonblock(ಪೂರ್ಣಾಂಕ fd)
{
	ಪೂರ್ಣಾಂಕ val;

	val = fcntl(fd, F_GETFL);
	ಆದರೆ (val == -1) {
		error("fcntl(%d, F_GETFL): %s", fd, strerror(errno));
		ಹಿಂತಿರುಗಿ (-1);
	}
	ಆದರೆ (!(val & O_NONBLOCK)) {
		debug3("fd %d is not O_NONBLOCK", fd);
		ಹಿಂತಿರುಗಿ (0);
	}
	debug("fd %d clearing O_NONBLOCK", fd);
	val &= ~O_NONBLOCK;
	ಆದರೆ (fcntl(fd, F_SETFL, val) == -1) {
		debug("fcntl(%d, F_SETFL, ~O_NONBLOCK): %s",
		    fd, strerror(errno));
		ಹಿಂತಿರುಗಿ (-1);
	}
	ಹಿಂತಿರುಗಿ (0);
}

ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *
ssh_gai_strerror(ಪೂರ್ಣಾಂಕ gaierr)
{
	ಆದರೆ (gaierr == EAI_SYSTEM && errno != 0)
		ಹಿಂತಿರುಗಿ strerror(errno);
	ಹಿಂತಿರುಗಿ gai_strerror(gaierr);
}

/* disable nagle on socket */
ಶೂನ್ಯ
ಗಣ_nodelay(ಪೂರ್ಣಾಂಕ fd)
{
	ಪೂರ್ಣಾಂಕ opt;
	socklen_t optlen;

	optlen = ಗಾತ್ರ opt;
	ಆದರೆ (getsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, &optlen) == -1) {
		debug("getsockopt TCP_NODELAY: %.100s", strerror(errno));
		ಹಿಂತಿರುಗಿ;
	}
	ಆದರೆ (opt == 1) {
		debug2("fd %d is TCP_NODELAY", fd);
		ಹಿಂತಿರುಗಿ;
	}
	opt = 1;
	debug2("fd %d setting TCP_NODELAY", fd);
	ಆದರೆ (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, ಗಾತ್ರ opt) == -1)
		error("setsockopt TCP_NODELAY: %.100s", strerror(errno));
}

/* Allow local port reuse in TIME_WAIT */
ಪೂರ್ಣಾಂಕ
ಗಣ_reuseaddr(ಪೂರ್ಣಾಂಕ fd)
{
	ಪೂರ್ಣಾಂಕ on = 1;

	ಆದರೆ (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, ಗಾತ್ರ(on)) == -1) {
		error("setsockopt SO_REUSEADDR fd %d: %s", fd, strerror(errno));
		ಹಿಂತಿರುಗಿ -1;
	}
	ಹಿಂತಿರುಗಿ 0;
}

/* Set TCP keepalives */
ಪೂರ್ಣಾಂಕ
ಗಣ_keepalive(ಪೂರ್ಣಾಂಕ fd)
{
	ಪೂರ್ಣಾಂಕ on = 1;

	ಆದರೆ (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, ಗಾತ್ರ(on)) == -1) {
		error("setsockopt SO_KEEPALIVE fd %d: %s", fd, strerror(errno));
		ಹಿಂತಿರುಗಿ -1;
	}
	ಹಿಂತಿರುಗಿ 0;
}

/* Get/set routing domain */
ಅಕ್ಷರ *
get_rdomain(ಪೂರ್ಣಾಂಕ fd)
{
#ಆದರೆ defined(HAVE_SYS_GET_RDOMAIN)
	ಹಿಂತಿರುಗಿ sys_get_rdomain(fd);
#ಅಥವಾಆದರೆ defined(__OpenBSD__)
	ಪೂರ್ಣಾಂಕ rtable;
	ಅಕ್ಷರ *ret;
	socklen_t len = ಗಾತ್ರ(rtable);

	ಆದರೆ (getsockopt(fd, SOL_SOCKET, SO_RTABLE, &rtable, &len) == -1) {
		error("Failed to get routing domain for fd %d: %s",
		    fd, strerror(errno));
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	xasprintf(&ret, "%d", rtable);
	ಹಿಂತಿರುಗಿ ret;
#ಇಲ್ಲದಿದ್ದರೆ /* defined(__OpenBSD__) */
	ಹಿಂತಿರುಗಿ ಖಾಲಿ;
#ಆದರೆ_ಅಂತ್ಯ
}

ಪೂರ್ಣಾಂಕ
ಗಣ_rdomain(ಪೂರ್ಣಾಂಕ fd, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name)
{
#ಆದರೆ defined(HAVE_SYS_ಗಣ_RDOMAIN)
	ಹಿಂತಿರುಗಿ sys_ಗಣ_rdomain(fd, name);
#ಅಥವಾಆದರೆ defined(__OpenBSD__)
	ಪೂರ್ಣಾಂಕ rtable;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *errstr;

	ಆದರೆ (name == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 0; /* default table */

	rtable = (ಪೂರ್ಣಾಂಕ)strtonum(name, 0, 255, &errstr);
	ಆದರೆ (errstr != ಖಾಲಿ) {
		/* Shouldn't happen */
		error("Invalid routing domain \"%s\": %s", name, errstr);
		ಹಿಂತಿರುಗಿ -1;
	}
	ಆದರೆ (setsockopt(fd, SOL_SOCKET, SO_RTABLE,
	    &rtable, ಗಾತ್ರ(rtable)) == -1) {
		error("Failed to set routing domain %d on fd %d: %s",
		    rtable, fd, strerror(errno));
		ಹಿಂತಿರುಗಿ -1;
	}
	ಹಿಂತಿರುಗಿ 0;
#ಇಲ್ಲದಿದ್ದರೆ /* defined(__OpenBSD__) */
	error("Setting routing domain is not supported on this platform");
	ಹಿಂತಿರುಗಿ -1;
#ಆದರೆ_ಅಂತ್ಯ
}

ಪೂರ್ಣಾಂಕ
get_sock_af(ಪೂರ್ಣಾಂಕ fd)
{
	ರಚನೆ sockaddr_storage ಗಮ್ಯ;
	socklen_t tolen = ಗಾತ್ರ(ಗಮ್ಯ);

	memset(&ಗಮ್ಯ, 0, ಗಾತ್ರ(ಗಮ್ಯ));
	ಆದರೆ (getsockname(fd, (ರಚನೆ sockaddr *)&ಗಮ್ಯ, &tolen) == -1)
		ಹಿಂತಿರುಗಿ -1;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ IPV4_ಒಳ_IPV6
	ಆದರೆ (ಗಮ್ಯ.ss_family == AF_INET6 &&
	    IN6_IS_ADDR_V4MAPPED(&((ರಚನೆ sockaddr_in6 *)&ಗಮ್ಯ)->sin6_addr))
		ಹಿಂತಿರುಗಿ AF_INET;
#ಆದರೆ_ಅಂತ್ಯ
	ಹಿಂತಿರುಗಿ ಗಮ್ಯ.ss_family;
}

ಶೂನ್ಯ
ಗಣ_sock_tos(ಪೂರ್ಣಾಂಕ fd, ಪೂರ್ಣಾಂಕ tos)
{
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ IP_TOS_IS_BROKEN
	ಪೂರ್ಣಾಂಕ af;

	ಆದರೆ (tos < 0 || tos == ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ) {
		debug_f("invalid TOS %d", tos);
		ಹಿಂತಿರುಗಿ;
	}
	ಆಯ್ಕೆ ((af = get_sock_af(fd))) {
	ಸ್ಥಿತಿ -1:
		/* assume not a socket */
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ AF_INET:
# ifdef IP_TOS
		debug3_f("set socket %d IP_TOS 0x%02x", fd, tos);
		ಆದರೆ (setsockopt(fd, IPPROTO_IP, IP_TOS,
		    &tos, ಗಾತ್ರ(tos)) == -1) {
			error("setsockopt socket %d IP_TOS %d: %s",
			    fd, tos, strerror(errno));
		}
# endif /* IP_TOS */
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ AF_INET6:
# ifdef IPV6_TCLASS
		debug3_f("set socket %d IPV6_TCLASS 0x%02x", fd, tos);
		ಆದರೆ (setsockopt(fd, IPPROTO_IPV6, IPV6_TCLASS,
		    &tos, ಗಾತ್ರ(tos)) == -1) {
			error("setsockopt socket %d IPV6_TCLASS %d: %s",
			    fd, tos, strerror(errno));
		}
# endif /* IPV6_TCLASS */
		ನಿಲ್ಲಿಸು;
	ಪೂರ್ವನಿಯೋಜಿತ:
		debug2_f("unsupported socket family %d", af);
		ನಿಲ್ಲಿಸು;
	}
#ಆದರೆ_ಅಂತ್ಯ /* IP_TOS_IS_BROKEN */
}

/*
 * Wait up to *timeoutp milliseconds for events on fd. Updates
 * *timeoutp with time remaining.
 * Returns 0 if fd ready or -1 on timeout or error (see errno).
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
waitfd(ಪೂರ್ಣಾಂಕ fd, ಪೂರ್ಣಾಂಕ *timeoutp, ಗಿಡ್ಡ events, ಅಸ್ಥಿರ sig_atomic_t *stop)
{
	ರಚನೆ pollfd pfd;
	ರಚನೆ timespec timeout;
	ಪೂರ್ಣಾಂಕ oerrno, r;
	sigset_t nsigset, osigset;

	ಆದರೆ (timeoutp && *timeoutp == -1)
		timeoutp = ಖಾಲಿ;
	pfd.fd = fd;
	pfd.events = events;
	ptimeout_init(&timeout);
	ಆದರೆ (timeoutp != ಖಾಲಿ)
		ptimeout_deadline_ms(&timeout, *timeoutp);
	ಆದರೆ (stop != ಖಾಲಿ)
		sigfillset(&nsigset);
	ಗಾಗಿ (; timeoutp == ಖಾಲಿ || *timeoutp >= 0;) {
		ಆದರೆ (stop != ಖಾಲಿ) {
			sigprocmask(SIG_BLOCK, &nsigset, &osigset);
			ಆದರೆ (*stop) {
				sigprocmask(SIG_SETMASK, &osigset, ಖಾಲಿ);
				errno = EINTR;
				ಹಿಂತಿರುಗಿ -1;
			}
		}
		r = ppoll(&pfd, 1, ptimeout_get_tsp(&timeout),
		    stop != ಖಾಲಿ ? &osigset : ಖಾಲಿ);
		oerrno = errno;
		ಆದರೆ (stop != ಖಾಲಿ)
			sigprocmask(SIG_SETMASK, &osigset, ಖಾಲಿ);
		ಆದರೆ (timeoutp)
			*timeoutp = ptimeout_get_ms(&timeout);
		errno = oerrno;
		ಆದರೆ (r > 0)
			ಹಿಂತಿರುಗಿ 0;
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (r == -1 && errno != EAGAIN && errno != EINTR)
			ಹಿಂತಿರುಗಿ -1;
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (r == 0)
			ನಿಲ್ಲಿಸು;
	}
	/* timeout */
	errno = ETIMEDOUT;
	ಹಿಂತಿರುಗಿ -1;
}

/*
 * Wait up to *timeoutp milliseconds for fd to be readable. Updates
 * *timeoutp with time remaining.
 * Returns 0 if fd ready or -1 on timeout or error (see errno).
 */
ಪೂರ್ಣಾಂಕ
waitrfd(ಪೂರ್ಣಾಂಕ fd, ಪೂರ್ಣಾಂಕ *timeoutp, ಅಸ್ಥಿರ sig_atomic_t *stop) {
	ಹಿಂತಿರುಗಿ waitfd(fd, timeoutp, POLLIN, stop);
}

/*
 * Attempt a non-blocking connect(2) to the specified address, waiting up to
 * *timeoutp milliseconds for the connection to complete. If the timeout is
 * <=0, then wait indefinitely.
 *
 * Returns 0 on success or -1 on failure.
 */
ಪೂರ್ಣಾಂಕ
timeout_connect(ಪೂರ್ಣಾಂಕ sockfd, ಸ್ಥಿರಾಂಕ ರಚನೆ sockaddr *serv_addr,
    socklen_t addrlen, ಪೂರ್ಣಾಂಕ *timeoutp)
{
	ಪೂರ್ಣಾಂಕ optval = 0;
	socklen_t optlen = ಗಾತ್ರ(optval);

	/* No timeout: just do a blocking connect() */
	ಆದರೆ (timeoutp == ಖಾಲಿ || *timeoutp <= 0)
		ಹಿಂತಿರುಗಿ connect(sockfd, serv_addr, addrlen);

	ಗಣ_nonblock(sockfd);
	ಗಾಗಿ (;;) {
		ಆದರೆ (connect(sockfd, serv_addr, addrlen) == 0) {
			/* Succeeded already? */
			unset_nonblock(sockfd);
			ಹಿಂತಿರುಗಿ 0;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (errno == EINTR)
			ಮುಂದುವರಿ;
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (errno != EINPROGRESS)
			ಹಿಂತಿರುಗಿ -1;
		ನಿಲ್ಲಿಸು;
	}

	ಆದರೆ (waitfd(sockfd, timeoutp, POLLIN | POLLOUT, ಖಾಲಿ) == -1)
		ಹಿಂತಿರುಗಿ -1;

	/* Completed or failed */
	ಆದರೆ (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &optval, &optlen) == -1) {
		debug("getsockopt: %s", strerror(errno));
		ಹಿಂತಿರುಗಿ -1;
	}
	ಆದರೆ (optval != 0) {
		errno = optval;
		ಹಿಂತಿರುಗಿ -1;
	}
	unset_nonblock(sockfd);
	ಹಿಂತಿರುಗಿ 0;
}

/* Characters considered whitespace in strsep calls. */
#ವ್ಯಾಖ್ಯಾನಿಸು WHITESPACE " \t\r\n"
#ವ್ಯಾಖ್ಯಾನಿಸು QUOTE	"\""

/* return next token in configuration line */
ಸ್ಥಿರ ಅಕ್ಷರ *
strdelim_ಆಂತರಿಕ(ಅಕ್ಷರ **s, ಪೂರ್ಣಾಂಕ ವಿಭಜಿಸು_equals)
{
	ಅಕ್ಷರ *old;
	ಪೂರ್ಣಾಂಕ wspace = 0;

	ಆದರೆ (*s == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;

	old = *s;

	*s = strpbrk(*s,
	    ವಿಭಜಿಸು_equals ? WHITESPACE QUOTE "=" : WHITESPACE QUOTE);
	ಆದರೆ (*s == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ (old);

	ಆದರೆ (*s[0] == '\"') {
		memmove(*s, *s + 1, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(*s)); /* move nul too */
		/* Find matching quote */
		ಆದರೆ ((*s = strpbrk(*s, QUOTE)) == ಖಾಲಿ) {
			ಹಿಂತಿರುಗಿ (ಖಾಲಿ);		/* no matching quote */
		} ಇಲ್ಲದಿದ್ದರೆ {
			*s[0] = '\0';
			*s += strspn(*s + 1, WHITESPACE) + 1;
			ಹಿಂತಿರುಗಿ (old);
		}
	}

	/* Allow only one '=' to be skipped */
	ಆದರೆ (ವಿಭಜಿಸು_equals && *s[0] == '=')
		wspace = 1;
	*s[0] = '\0';

	/* Skip any extra whitespace after first token */
	*s += strspn(*s + 1, WHITESPACE) + 1;
	ಆದರೆ (ವಿಭಜಿಸು_equals && *s[0] == '=' && !wspace)
		*s += strspn(*s + 1, WHITESPACE) + 1;

	ಹಿಂತಿರುಗಿ (old);
}

/*
 * Return next token in configuration line; splits on whitespace or a
 * single '=' character.
 */
ಅಕ್ಷರ *
strdelim(ಅಕ್ಷರ **s)
{
	ಹಿಂತಿರುಗಿ strdelim_ಆಂತರಿಕ(s, 1);
}

/*
 * Return next token in configuration line; splits on whitespace only.
 */
ಅಕ್ಷರ *
strdelimw(ಅಕ್ಷರ **s)
{
	ಹಿಂತಿರುಗಿ strdelim_ಆಂತರಿಕ(s, 0);
}

ರಚನೆ passwd *
pwcopy(ರಚನೆ passwd *pw)
{
	ರಚನೆ passwd *copy = xcalloc(1, ಗಾತ್ರ(*copy));

	copy->pw_name = xstrdup(pw->pw_name);
	copy->pw_passwd = xstrdup(pw->pw_passwd == ಖಾಲಿ ? "*" : pw->pw_passwd);
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_STRUCT_PASSWD_PW_GECOS
	copy->pw_gecos = xstrdup(pw->pw_gecos == ಖಾಲಿ ? "" : pw->pw_gecos);
#ಆದರೆ_ಅಂತ್ಯ
	copy->pw_uid = pw->pw_uid;
	copy->pw_gid = pw->pw_gid;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_STRUCT_PASSWD_PW_EXPIRE
	copy->pw_expire = pw->pw_expire;
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_STRUCT_PASSWD_PW_CHANGE
	copy->pw_change = pw->pw_change;
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_STRUCT_PASSWD_PW_CLASS
	copy->pw_class = xstrdup(pw->pw_class == ಖಾಲಿ ? "" : pw->pw_class);
#ಆದರೆ_ಅಂತ್ಯ
	copy->pw_dir = xstrdup(pw->pw_dir == ಖಾಲಿ ? "" : pw->pw_dir);
	copy->pw_shell = xstrdup(pw->pw_shell == ಖಾಲಿ ? "" : pw->pw_shell);
	ಹಿಂತಿರುಗಿ copy;
}

ಶೂನ್ಯ
pwfree(ರಚನೆ passwd *pw)
{
	ಆದರೆ (pw == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;
	ಬಿಡುಗಡೆ(pw->pw_name);
	freezero(pw->pw_passwd,
	    pw->pw_passwd == ಖಾಲಿ ? 0 : ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(pw->pw_passwd));
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_STRUCT_PASSWD_PW_GECOS
	ಬಿಡುಗಡೆ(pw->pw_gecos);
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_STRUCT_PASSWD_PW_CLASS
	ಬಿಡುಗಡೆ(pw->pw_class);
#ಆದರೆ_ಅಂತ್ಯ
	ಬಿಡುಗಡೆ(pw->pw_dir);
	ಬಿಡುಗಡೆ(pw->pw_shell);
	freezero(pw, ಗಾತ್ರ(*pw));
}

/*
 * Convert ASCII string to TCP/IP port number.
 * Port must be >=0 and <=65535.
 * Return -1 if invalid.
 */
ಪೂರ್ಣಾಂಕ
a2port(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *s)
{
	ರಚನೆ servent *se;
	ದೀರ್ಘ ದೀರ್ಘ ಪೋರ್ಟ್;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *errstr;

	ಪೋರ್ಟ್ = strtonum(s, 0, 65535, &errstr);
	ಆದರೆ (errstr == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ (ಪೂರ್ಣಾಂಕ)ಪೋರ್ಟ್;
	ಆದರೆ ((se = getservbyname(s, "tcp")) != ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ ntohs(se->s_port);
	ಹಿಂತಿರುಗಿ -1;
}

ಪೂರ್ಣಾಂಕ
a2tun(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *s, ಪೂರ್ಣಾಂಕ *remote)
{
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *errstr = ಖಾಲಿ;
	ಅಕ್ಷರ *sp, *ep;
	ಪೂರ್ಣಾಂಕ tun;

	ಆದರೆ (remote != ಖಾಲಿ) {
		*remote = SSH_TUNID_ANY;
		sp = xstrdup(s);
		ಆದರೆ ((ep = strchr(sp, ':')) == ಖಾಲಿ) {
			ಬಿಡುಗಡೆ(sp);
			ಹಿಂತಿರುಗಿ (a2tun(s, ಖಾಲಿ));
		}
		ep[0] = '\0'; ep++;
		*remote = a2tun(ep, ಖಾಲಿ);
		tun = a2tun(sp, ಖಾಲಿ);
		ಬಿಡುಗಡೆ(sp);
		ಹಿಂತಿರುಗಿ (*remote == SSH_TUNID_ERR ? *remote : tun);
	}

	ಆದರೆ (strcasecmp(s, "any") == 0)
		ಹಿಂತಿರುಗಿ (SSH_TUNID_ANY);

	tun = strtonum(s, 0, SSH_TUNID_MAX, &errstr);
	ಆದರೆ (errstr != ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ (SSH_TUNID_ERR);

	ಹಿಂತಿರುಗಿ (tun);
}

#ವ್ಯಾಖ್ಯಾನಿಸು SECONDS		1.0
#ವ್ಯಾಖ್ಯಾನಿಸು MINUTES		(SECONDS * 60)
#ವ್ಯಾಖ್ಯಾನಿಸು HOURS		(MINUTES * 60)
#ವ್ಯಾಖ್ಯಾನಿಸು DAYS		(HOURS * 24)
#ವ್ಯಾಖ್ಯಾನಿಸು WEEKS		(DAYS * 7)

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
convtime_double(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *s)
{
	ದ್ವಿಗುಣ val, ಒಟ್ಟು_sec = 0.0, multiplier;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *p, *ಆರಂಭ_p;
	ಅಕ್ಷರ *endp;
	ಪೂರ್ಣಾಂಕ ನೋಡಿದ_seconds = 0;

	ಆದರೆ (s == ಖಾಲಿ || *s == '\0')
		ಹಿಂತಿರುಗಿ -1.0;

	ಗಾಗಿ (p = s; *p != '\0';) {
		ಆದರೆ (!ಅಂಕಿಯೇ((ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ)*p) && *p != '.')
			ಹಿಂತಿರುಗಿ -1.0;

		errno = 0;
		ಆದರೆ ((val = strtod(p, &endp)) < 0 || errno != 0 || p == endp)
			ಹಿಂತಿರುಗಿ -1.0;
		/* Allow only decimal forms */
		ಆದರೆ (p + strspn(p, "0123456789.") != endp)
			ಹಿಂತಿರುಗಿ -1.0;
		ಆರಂಭ_p = p;
		p = endp;

		ಆಯ್ಕೆ (*p) {
		ಸ್ಥಿತಿ '\0':
			/* FALLTHROUGH */
		ಸ್ಥಿತಿ 's':
		ಸ್ಥಿತಿ 'S':
			ಆದರೆ (ನೋಡಿದ_seconds++)
				ಹಿಂತಿರುಗಿ -1.0;
			multiplier = SECONDS;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'm':
		ಸ್ಥಿತಿ 'M':
			multiplier = MINUTES;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'h':
		ಸ್ಥಿತಿ 'H':
			multiplier = HOURS;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'd':
		ಸ್ಥಿತಿ 'D':
			multiplier = DAYS;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'w':
		ಸ್ಥಿತಿ 'W':
			multiplier = WEEKS;
			ನಿಲ್ಲಿಸು;
		ಪೂರ್ವನಿಯೋಜಿತ:
			ಹಿಂತಿರುಗಿ -1.0;
		}

		/* Special handling if this was a decimal */
		ಆದರೆ (memchr(ಆರಂಭ_p, '.', endp - ಆರಂಭ_p) != ಖಾಲಿ) {
			/* Decimal point present */
			ಆದರೆ (multiplier > 1.0)
				ಹಿಂತಿರುಗಿ -1.0; /* No fractionals for non-seconds */
			/* For seconds, ensure digits follow */
			ಆದರೆ (!ಅಂಕಿಯೇ((ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ)*(endp - 1)))
				ಹಿಂತಿರುಗಿ -1.0;
		}

		ಒಟ್ಟು_sec += val * multiplier;

		ಆದರೆ (*p != '\0')
			p++;
	}
	ಹಿಂತಿರುಗಿ ಒಟ್ಟು_sec;
}

/*
 * Same as convtime_double() above but fractional seconds are ignored.
 * Return -1 if time string is invalid.
 */
ಪೂರ್ಣಾಂಕ
convtime(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *s)
{
	ದ್ವಿಗುಣ sec_val;

	ಆದರೆ ((sec_val = convtime_double(s)) < 0.0)
		ಹಿಂತಿರುಗಿ -1;

	/* Check for overflow into int */
	ಆದರೆ (sec_val < 0 || sec_val > ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ)
		ಹಿಂತಿರುಗಿ -1;

	ಹಿಂತಿರುಗಿ (ಪೂರ್ಣಾಂಕ)sec_val;
}

#ವ್ಯಾಖ್ಯಾನಿಸು TF_BUFS	8
#ವ್ಯಾಖ್ಯಾನಿಸು TF_LEN	9

ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *
fmt_timeframe(time_t t)
{
	ಅಕ್ಷರ		*buf;
	ಸ್ಥಿರ ಅಕ್ಷರ	 tfbuf[TF_BUFS][TF_LEN];	/* ring buffer */
	ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ	 idx = 0;
	ಚಿಹ್ನೆರಹಿತ ಪೂರ್ಣಾಂಕ	 sec, min, hrs, day;
	ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ	week;

	buf = tfbuf[idx++];
	ಆದರೆ (idx == TF_BUFS)
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

	ಆದರೆ (week > 0)
		snprintf(buf, TF_LEN, "%02lluw%01ud%02uh", week, day, hrs);
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (day > 0)
		snprintf(buf, TF_LEN, "%01ud%02uh%02um", day, hrs, min);
	ಇಲ್ಲದಿದ್ದರೆ
		snprintf(buf, TF_LEN, "%02u:%02u:%02u", hrs, min, sec);

	ಹಿಂತಿರುಗಿ (buf);
}

/*
 * Returns a standardized host+port identifier string.
 * Caller must free returned string.
 */
ಅಕ್ಷರ *
put_host_ಪೋರ್ಟ್(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host, u_short ಪೋರ್ಟ್)
{
	ಅಕ್ಷರ *hoststr;

	ಆದರೆ (ಪೋರ್ಟ್ == 0 || ಪೋರ್ಟ್ == SSH_DEFAULT_ಪೋರ್ಟ್)
		ಹಿಂತಿರುಗಿ(xstrdup(host));
	ಆದರೆ (asprintf(&hoststr, "[%s]:%d", host, (ಪೂರ್ಣಾಂಕ)ಪೋರ್ಟ್) == -1)
		fatal("put_host_port: asprintf: %s", strerror(errno));
	debug3("put_host_port: %s", hoststr);
	ಹಿಂತಿರುಗಿ hoststr;
}

/*
 * Search for next delimiter between hostnames/addresses and ports.
 * Argument may be modified (for termination).
 * Returns *cp if parsing succeeds.
 * *cp is set to the start of the next field, if one was found.
 * The delimiter char, if present, is stored in delim.
 * If this is the last field, *cp is set to NULL.
 */
ಅಕ್ಷರ *
hpdelim2(ಅಕ್ಷರ **cp, ಅಕ್ಷರ *delim)
{
	ಅಕ್ಷರ *s, *old;

	ಆದರೆ (cp == ಖಾಲಿ || *cp == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;

	old = s = *cp;
	ಆದರೆ (*s == '[') {
		ಆದರೆ ((s = strchr(s, ']')) == ಖಾಲಿ)
			ಹಿಂತಿರುಗಿ ಖಾಲಿ;
		ಇಲ್ಲದಿದ್ದರೆ
			s++;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((s = strpbrk(s, ":/")) == ಖಾಲಿ)
		s = *cp + ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(*cp); /* skip to end (see first case below) */

	ಆಯ್ಕೆ (*s) {
	ಸ್ಥಿತಿ '\0':
		*cp = ಖಾಲಿ;	/* no more fields*/
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ ':':
	ಸ್ಥಿತಿ '/':
		ಆದರೆ (delim != ಖಾಲಿ)
			*delim = *s;
		*s = '\0';	/* terminate */
		*cp = s + 1;
		ನಿಲ್ಲಿಸು;

	ಪೂರ್ವನಿಯೋಜಿತ:
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}

	ಹಿಂತಿರುಗಿ old;
}

/* The common case: only accept colon as delimiter. */
ಅಕ್ಷರ *
hpdelim(ಅಕ್ಷರ **cp)
{
	ಅಕ್ಷರ *r, delim = '\0';

	r =  hpdelim2(cp, &delim);
	ಆದರೆ (delim == '/')
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	ಹಿಂತಿರುಗಿ r;
}

ಅಕ್ಷರ *
cleanhostname(ಅಕ್ಷರ *host)
{
	ಆದರೆ (*host == '[' && host[ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(host) - 1] == ']') {
		host[ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(host) - 1] = '\0';
		ಹಿಂತಿರುಗಿ (host + 1);
	} ಇಲ್ಲದಿದ್ದರೆ
		ಹಿಂತಿರುಗಿ host;
}

ಅಕ್ಷರ *
colon(ಅಕ್ಷರ *cp)
{
	ಪೂರ್ಣಾಂಕ flag = 0;

	ಆದರೆ (*cp == ':')		/* Leading colon is part of file name. */
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	ಆದರೆ (*cp == '[')
		flag = 1;

	ಗಾಗಿ (; *cp; ++cp) {
		ಆದರೆ (*cp == '@' && *(cp+1) == '[')
			flag = 1;
		ಆದರೆ (*cp == ']' && *(cp+1) == ':' && flag)
			ಹಿಂತಿರುಗಿ (cp+1);
		ಆದರೆ (*cp == ':' && !flag)
			ಹಿಂತಿರುಗಿ (cp);
		ಆದರೆ (*cp == '/')
			ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	ಹಿಂತಿರುಗಿ ಖಾಲಿ;
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
ಪೂರ್ಣಾಂಕ
parse_user_host_ಮಾರ್ಗ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *s, ಅಕ್ಷರ **userp, ಅಕ್ಷರ **hostp, ಅಕ್ಷರ **pathp)
{
	ಅಕ್ಷರ *user = ಖಾಲಿ, *host = ಖಾಲಿ, *ಮಾರ್ಗ = ಖಾಲಿ;
	ಅಕ್ಷರ *sdup, *tmp;
	ಪೂರ್ಣಾಂಕ ret = -1;

	ಆದರೆ (userp != ಖಾಲಿ)
		*userp = ಖಾಲಿ;
	ಆದರೆ (hostp != ಖಾಲಿ)
		*hostp = ಖಾಲಿ;
	ಆದರೆ (pathp != ಖಾಲಿ)
		*pathp = ಖಾಲಿ;

	sdup = xstrdup(s);

	/* Check for remote syntax: [user@]host:[path] */
	ಆದರೆ ((tmp = colon(sdup)) == ಖಾಲಿ)
		ಹೋಗು ಹೊರಹೋಗು;

	/* Extract optional path */
	*tmp++ = '\0';
	ಆದರೆ (*tmp == '\0')
		tmp = ".";
	ಮಾರ್ಗ = xstrdup(tmp);

	/* Extract optional user and mandatory host */
	tmp = strrchr(sdup, '@');
	ಆದರೆ (tmp != ಖಾಲಿ) {
		*tmp++ = '\0';
		host = xstrdup(cleanhostname(tmp));
		ಆದರೆ (*sdup != '\0')
			user = xstrdup(sdup);
	} ಇಲ್ಲದಿದ್ದರೆ {
		host = xstrdup(cleanhostname(sdup));
		user = ಖಾಲಿ;
	}

	/* Success */
	ಆದರೆ (userp != ಖಾಲಿ) {
		*userp = user;
		user = ಖಾಲಿ;
	}
	ಆದರೆ (hostp != ಖಾಲಿ) {
		*hostp = host;
		host = ಖಾಲಿ;
	}
	ಆದರೆ (pathp != ಖಾಲಿ) {
		*pathp = ಮಾರ್ಗ;
		ಮಾರ್ಗ = ಖಾಲಿ;
	}
	ret = 0;
ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(sdup);
	ಬಿಡುಗಡೆ(user);
	ಬಿಡುಗಡೆ(host);
	ಬಿಡುಗಡೆ(ಮಾರ್ಗ);
	ಹಿಂತಿರುಗಿ ret;
}

/*
 * Parse a [user@]host[:port] string.
 * Caller must free returned user and host.
 * Any of the pointer return arguments may be NULL (useful for syntax checking).
 * If user was not specified then *userp will be set to NULL.
 * If port was not specified then *portp will be -1.
 * Returns 0 on success, -1 on failure.
 */
ಪೂರ್ಣಾಂಕ
parse_user_host_ಪೋರ್ಟ್(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *s, ಅಕ್ಷರ **userp, ಅಕ್ಷರ **hostp, ಪೂರ್ಣಾಂಕ *portp)
{
	ಅಕ್ಷರ *sdup, *cp, *tmp;
	ಅಕ್ಷರ *user = ಖಾಲಿ, *host = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ ಪೋರ್ಟ್ = -1, ret = -1;

	ಆದರೆ (userp != ಖಾಲಿ)
		*userp = ಖಾಲಿ;
	ಆದರೆ (hostp != ಖಾಲಿ)
		*hostp = ಖಾಲಿ;
	ಆದರೆ (portp != ಖಾಲಿ)
		*portp = -1;

	ಆದರೆ ((sdup = tmp = strdup(s)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ -1;
	/* Extract optional username */
	ಆದರೆ ((cp = strrchr(tmp, '@')) != ಖಾಲಿ) {
		*cp = '\0';
		ಆದರೆ (*tmp == '\0')
			ಹೋಗು ಹೊರಹೋಗು;
		ಆದರೆ ((user = strdup(tmp)) == ಖಾಲಿ)
			ಹೋಗು ಹೊರಹೋಗು;
		tmp = cp + 1;
	}
	/* Extract mandatory hostname */
	ಆದರೆ ((cp = hpdelim(&tmp)) == ಖಾಲಿ || *cp == '\0')
		ಹೋಗು ಹೊರಹೋಗು;
	host = xstrdup(cleanhostname(cp));
	/* Convert and verify optional port */
	ಆದರೆ (tmp != ಖಾಲಿ && *tmp != '\0') {
		ಆದರೆ ((ಪೋರ್ಟ್ = a2port(tmp)) <= 0)
			ಹೋಗು ಹೊರಹೋಗು;
	}
	/* Success */
	ಆದರೆ (userp != ಖಾಲಿ) {
		*userp = user;
		user = ಖಾಲಿ;
	}
	ಆದರೆ (hostp != ಖಾಲಿ) {
		*hostp = host;
		host = ಖಾಲಿ;
	}
	ಆದರೆ (portp != ಖಾಲಿ)
		*portp = ಪೋರ್ಟ್;
	ret = 0;
 ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(sdup);
	ಬಿಡುಗಡೆ(user);
	ಬಿಡುಗಡೆ(host);
	ಹಿಂತಿರುಗಿ ret;
}

/*
 * Converts a two-byte hex string to decimal.
 * Returns the decimal value or -1 for invalid input.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
hexchar(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *s)
{
	ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ ಫಲಿತಾಂಶ[2];
	ಪೂರ್ಣಾಂಕ i;

	ಗಾಗಿ (i = 0; i < 2; i++) {
		ಆದರೆ (s[i] >= '0' && s[i] <= '9')
			ಫಲಿತಾಂಶ[i] = (ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ)(s[i] - '0');
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (s[i] >= 'a' && s[i] <= 'f')
			ಫಲಿತಾಂಶ[i] = (ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ)(s[i] - 'a') + 10;
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (s[i] >= 'A' && s[i] <= 'F')
			ಫಲಿತಾಂಶ[i] = (ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ)(s[i] - 'A') + 10;
		ಇಲ್ಲದಿದ್ದರೆ
			ಹಿಂತಿರುಗಿ -1;
	}
	ಹಿಂತಿರುಗಿ (ಫಲಿತಾಂಶ[0] << 4) | ಫಲಿತಾಂಶ[1];
}

/*
 * Decode an url-encoded string.
 * Returns a newly allocated string on success or NULL on failure.
 */
ಸ್ಥಿರ ಅಕ್ಷರ *
urldecode(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *src)
{
	ಅಕ್ಷರ *ret, *dst;
	ಪೂರ್ಣಾಂಕ ch;
	ಗಾತ್ರ_t srclen;

	ಆದರೆ ((srclen = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(src)) >= SIZE_MAX)
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	ret = xmalloc(srclen + 1);
	ಗಾಗಿ (dst = ret; *src != '\0'; src++) {
		ಆಯ್ಕೆ (*src) {
		ಸ್ಥಿತಿ '+':
			*dst++ = ' ';
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ '%':
			/* note: don't allow \0 characters */
			ಆದರೆ (!isxdigit((ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ)src[1]) ||
			    !isxdigit((ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ)src[2]) ||
			    (ch = hexchar(src + 1)) == -1 || ch == 0) {
				ಬಿಡುಗಡೆ(ret);
				ಹಿಂತಿರುಗಿ ಖಾಲಿ;
			}
			*dst++ = ch;
			src += 2;
			ನಿಲ್ಲಿಸು;
		ಪೂರ್ವನಿಯೋಜಿತ:
			*dst++ = *src;
			ನಿಲ್ಲಿಸು;
		}
	}
	*dst = '\0';

	ಹಿಂತಿರುಗಿ ret;
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
ಪೂರ್ಣಾಂಕ
parse_uri(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *scheme, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *uri, ಅಕ್ಷರ **userp, ಅಕ್ಷರ **hostp,
    ಪೂರ್ಣಾಂಕ *portp, ಅಕ್ಷರ **pathp)
{
	ಅಕ್ಷರ *uridup, *cp, *tmp, ch;
	ಅಕ್ಷರ *user = ಖಾಲಿ, *host = ಖಾಲಿ, *ಮಾರ್ಗ = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ ಪೋರ್ಟ್ = -1, ret = -1;
	ಗಾತ್ರ_t len;

	len = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(scheme);
	ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಹೋಲಿಕೆ(uri, scheme, len) != 0 || ಅಕ್ಷರಸರಣಿ_ಹೋಲಿಕೆ(uri + len, "://", 3) != 0)
		ಹಿಂತಿರುಗಿ 1;
	uri += len + 3;

	ಆದರೆ (userp != ಖಾಲಿ)
		*userp = ಖಾಲಿ;
	ಆದರೆ (hostp != ಖಾಲಿ)
		*hostp = ಖಾಲಿ;
	ಆದರೆ (portp != ಖಾಲಿ)
		*portp = -1;
	ಆದರೆ (pathp != ಖಾಲಿ)
		*pathp = ಖಾಲಿ;

	uridup = tmp = xstrdup(uri);

	/* Extract optional ssh-info (username + connection params) */
	ಆದರೆ ((cp = strchr(tmp, '@')) != ಖಾಲಿ) {
		ಅಕ್ಷರ *delim;

		*cp = '\0';
		/* Extract username and connection params */
		ಆದರೆ ((delim = strchr(tmp, ';')) != ಖಾಲಿ) {
			/* Just ignore connection params for now */
			*delim = '\0';
		}
		ಆದರೆ (*tmp == '\0') {
			/* Empty username */
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ ((user = urldecode(tmp)) == ಖಾಲಿ)
			ಹೋಗು ಹೊರಹೋಗು;
		tmp = cp + 1;
	}

	/* Extract mandatory hostname */
	ಆದರೆ ((cp = hpdelim2(&tmp, &ch)) == ಖಾಲಿ || *cp == '\0')
		ಹೋಗು ಹೊರಹೋಗು;
	host = xstrdup(cleanhostname(cp));
	ಆದರೆ (!valid_domain(host, 0, ಖಾಲಿ))
		ಹೋಗು ಹೊರಹೋಗು;

	ಆದರೆ (tmp != ಖಾಲಿ && *tmp != '\0') {
		ಆದರೆ (ch == ':') {
			/* Convert and verify port. */
			ಆದರೆ ((cp = strchr(tmp, '/')) != ಖಾಲಿ)
				*cp = '\0';
			ಆದರೆ ((ಪೋರ್ಟ್ = a2port(tmp)) <= 0)
				ಹೋಗು ಹೊರಹೋಗು;
			tmp = cp ? cp + 1 : ಖಾಲಿ;
		}
		ಆದರೆ (tmp != ಖಾಲಿ && *tmp != '\0') {
			/* Extract optional path */
			ಆದರೆ ((ಮಾರ್ಗ = urldecode(tmp)) == ಖಾಲಿ)
				ಹೋಗು ಹೊರಹೋಗು;
		}
	}

	/* Success */
	ಆದರೆ (userp != ಖಾಲಿ) {
		*userp = user;
		user = ಖಾಲಿ;
	}
	ಆದರೆ (hostp != ಖಾಲಿ) {
		*hostp = host;
		host = ಖಾಲಿ;
	}
	ಆದರೆ (portp != ಖಾಲಿ)
		*portp = ಪೋರ್ಟ್;
	ಆದರೆ (pathp != ಖಾಲಿ) {
		*pathp = ಮಾರ್ಗ;
		ಮಾರ್ಗ = ಖಾಲಿ;
	}
	ret = 0;
 ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(uridup);
	ಬಿಡುಗಡೆ(user);
	ಬಿಡುಗಡೆ(host);
	ಬಿಡುಗಡೆ(ಮಾರ್ಗ);
	ಹಿಂತಿರುಗಿ ret;
}

/* function to assist building execv() arguments */
ಶೂನ್ಯ
addargs(arglist *ವಾದಗಳು, ಅಕ್ಷರ *fmt, ...)
{
	va_list ap;
	ಅಕ್ಷರ *cp;
	u_int nalloc;
	ಪೂರ್ಣಾಂಕ r;

	va_start(ap, fmt);
	r = vasprintf(&cp, fmt, ap);
	va_end(ap);
	ಆದರೆ (r == -1)
		fatal_f("argument too long");

	nalloc = ವಾದಗಳು->nalloc;
	ಆದರೆ (ವಾದಗಳು->list == ಖಾಲಿ) {
		nalloc = 32;
		ವಾದಗಳು->ಅಂಕೆ = 0;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ವಾದಗಳು->ಅಂಕೆ > (256 * 1024))
		fatal_f("too many arguments");
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ವಾದಗಳು->ಅಂಕೆ >= ವಾದಗಳು->nalloc)
		fatal_f("arglist corrupt");
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ವಾದಗಳು->ಅಂಕೆ+2 >= nalloc)
		nalloc *= 2;

	ವಾದಗಳು->list = xrecallocarray(ವಾದಗಳು->list, ವಾದಗಳು->nalloc,
	    nalloc, ಗಾತ್ರ(ಅಕ್ಷರ *));
	ವಾದಗಳು->nalloc = nalloc;
	ವಾದಗಳು->list[ವಾದಗಳು->ಅಂಕೆ++] = cp;
	ವಾದಗಳು->list[ವಾದಗಳು->ಅಂಕೆ] = ಖಾಲಿ;
}

ಶೂನ್ಯ
replacearg(arglist *ವಾದಗಳು, u_int which, ಅಕ್ಷರ *fmt, ...)
{
	va_list ap;
	ಅಕ್ಷರ *cp;
	ಪೂರ್ಣಾಂಕ r;

	va_start(ap, fmt);
	r = vasprintf(&cp, fmt, ap);
	va_end(ap);
	ಆದರೆ (r == -1)
		fatal_f("argument too long");
	ಆದರೆ (ವಾದಗಳು->list == ಖಾಲಿ || ವಾದಗಳು->ಅಂಕೆ >= ವಾದಗಳು->nalloc)
		fatal_f("arglist corrupt");

	ಆದರೆ (which >= ವಾದಗಳು->ಅಂಕೆ)
		fatal_f("tried to replace invalid arg %d >= %d",
		    which, ವಾದಗಳು->ಅಂಕೆ);
	ಬಿಡುಗಡೆ(ವಾದಗಳು->list[which]);
	ವಾದಗಳು->list[which] = cp;
}

ಶೂನ್ಯ
freeargs(arglist *ವಾದಗಳು)
{
	u_int i;

	ಆದರೆ (ವಾದಗಳು == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;
	ಆದರೆ (ವಾದಗಳು->list != ಖಾಲಿ && ವಾದಗಳು->ಅಂಕೆ < ವಾದಗಳು->nalloc) {
		ಗಾಗಿ (i = 0; i < ವಾದಗಳು->ಅಂಕೆ; i++)
			ಬಿಡುಗಡೆ(ವಾದಗಳು->list[i]);
		ಬಿಡುಗಡೆ(ವಾದಗಳು->list);
	}
	ವಾದಗಳು->nalloc = ವಾದಗಳು->ಅಂಕೆ = 0;
	ವಾದಗಳು->list = ಖಾಲಿ;
}

/*
 * Expands tildes in the file name.  Returns data allocated by xmalloc.
 * Warning: this calls getpw*.
 */
ಪೂರ್ಣಾಂಕ
tilde_expand(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *filename, uid_t uid, ಅಕ್ಷರ **retp)
{
	ಅಕ್ಷರ *ocopy = ಖಾಲಿ, *copy, *s = ಖಾಲಿ;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ = ಖಾಲಿ, *user = ಖಾಲಿ;
	ರಚನೆ passwd *pw;
	ಗಾತ್ರ_t len;
	ಪೂರ್ಣಾಂಕ ret = -1, r, slash;

	*retp = ಖಾಲಿ;
	ಆದರೆ (*filename != '~') {
		*retp = xstrdup(filename);
		ಹಿಂತಿರುಗಿ 0;
	}
	ocopy = copy = xstrdup(filename + 1);

	ಆದರೆ (*copy == '\0')				/* ~ */
		ಮಾರ್ಗ = ಖಾಲಿ;
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (*copy == '/') {
		copy += strspn(copy, "/");
		ಆದರೆ (*copy == '\0')
			ಮಾರ್ಗ = ಖಾಲಿ;			/* ~/ */
		ಇಲ್ಲದಿದ್ದರೆ
			ಮಾರ್ಗ = copy;			/* ~/path */
	} ಇಲ್ಲದಿದ್ದರೆ {
		user = copy;
		ಆದರೆ ((ಮಾರ್ಗ = strchr(copy, '/')) != ಖಾಲಿ) {
			copy[ಮಾರ್ಗ - copy] = '\0';
			ಮಾರ್ಗ++;
			ಮಾರ್ಗ += strspn(ಮಾರ್ಗ, "/");
			ಆದರೆ (*ಮಾರ್ಗ == '\0')		/* ~user/ */
				ಮಾರ್ಗ = ಖಾಲಿ;
			/* else				 ~user/path */
		}
		/* else					~user */
	}
	ಆದರೆ (user != ಖಾಲಿ) {
		ಆದರೆ ((pw = getpwnam(user)) == ಖಾಲಿ) {
			error_f("No such user %s", user);
			ಹೋಗು ಹೊರಹೋಗು;
		}
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((pw = getpwuid(uid)) == ಖಾಲಿ) {
		error_f("No such uid %ld", (ದೀರ್ಘ)uid);
		ಹೋಗು ಹೊರಹೋಗು;
	}

	/* Make sure directory has a trailing '/' */
	slash = (len = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(pw->pw_dir)) == 0 || pw->pw_dir[len - 1] != '/';

	ಆದರೆ ((r = xasprintf(&s, "%s%s%s", pw->pw_dir,
	    slash ? "/" : "", ಮಾರ್ಗ != ಖಾಲಿ ? ಮಾರ್ಗ : "")) <= 0) {
		error_f("xasprintf failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (r >= PATH_MAX) {
		error_f("Path too long");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/* success */
	ret = 0;
	*retp = s;
	s = ಖಾಲಿ;
 ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(s);
	ಬಿಡುಗಡೆ(ocopy);
	ಹಿಂತಿರುಗಿ ret;
}

ಅಕ್ಷರ *
tilde_expand_filename(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *filename, uid_t uid)
{
	ಅಕ್ಷರ *ret;

	ಆದರೆ (tilde_expand(filename, uid, &ret) != 0)
		cleanup_exit(255);
	ಹಿಂತಿರುಗಿ ret;
}

/*
 * Expand a string with a set of %[char] escapes and/or ${ENVIRONMENT}
 * substitutions.  A number of escapes may be specified as
 * (char *escape_chars, char *replacement) pairs. The list must be terminated
 * by a NULL escape_char. Returns replaced string in memory allocated by
 * xmalloc which the caller must free.
 */
ಸ್ಥಿರ ಅಕ್ಷರ *
vdollar_percent_expand(ಪೂರ್ಣಾಂಕ *parseerror, ಪೂರ್ಣಾಂಕ dollar, ಪೂರ್ಣಾಂಕ percent,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *string, va_list ap)
{
#ವ್ಯಾಖ್ಯಾನಿಸು EXPAND_MAX_ಕೀಲಿಗಳು	64
	u_int ಅಂಕೆ_ಕೀಲಿಗಳು = 0, i;
	ರಚನೆ {
		ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಕೀಲಿ;
		ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *repl;
	} ಕೀಲಿಗಳು[EXPAND_MAX_ಕೀಲಿಗಳು];
	ರಚನೆ sshbuf *buf;
	ಪೂರ್ಣಾಂಕ r, missingvar = 0;
	ಅಕ್ಷರ *ret = ಖಾಲಿ, *var, *varend, *val;
	ಗಾತ್ರ_t len;

	ಆದರೆ ((buf = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	ಆದರೆ (parseerror == ಖಾಲಿ)
		fatal_f("null parseerror arg");
	*parseerror = 1;

	/* Gather keys if we're doing percent expansion. */
	ಆದರೆ (percent) {
		ಗಾಗಿ (ಅಂಕೆ_ಕೀಲಿಗಳು = 0; ಅಂಕೆ_ಕೀಲಿಗಳು < EXPAND_MAX_ಕೀಲಿಗಳು; ಅಂಕೆ_ಕೀಲಿಗಳು++) {
			ಕೀಲಿಗಳು[ಅಂಕೆ_ಕೀಲಿಗಳು].ಕೀಲಿ = va_arg(ap, ಅಕ್ಷರ *);
			ಆದರೆ (ಕೀಲಿಗಳು[ಅಂಕೆ_ಕೀಲಿಗಳು].ಕೀಲಿ == ಖಾಲಿ)
				ನಿಲ್ಲಿಸು;
			ಕೀಲಿಗಳು[ಅಂಕೆ_ಕೀಲಿಗಳು].repl = va_arg(ap, ಅಕ್ಷರ *);
			ಆದರೆ (ಕೀಲಿಗಳು[ಅಂಕೆ_ಕೀಲಿಗಳು].repl == ಖಾಲಿ) {
				fatal_f("NULL replacement for token %s",
				    ಕೀಲಿಗಳು[ಅಂಕೆ_ಕೀಲಿಗಳು].ಕೀಲಿ);
			}
		}
		ಆದರೆ (ಅಂಕೆ_ಕೀಲಿಗಳು == EXPAND_MAX_ಕೀಲಿಗಳು && va_arg(ap, ಅಕ್ಷರ *) != ಖಾಲಿ)
			fatal_f("too many keys");
		ಆದರೆ (ಅಂಕೆ_ಕೀಲಿಗಳು == 0)
			fatal_f("percent expansion without token list");
	}

	/* Expand string */
	ಗಾಗಿ (i = 0; *string != '\0'; string++) {
		/* Optionally process ${ENVIRONMENT} expansions. */
		ಆದರೆ (dollar && string[0] == '$' && string[1] == '{') {
			string += 2;  /* skip over '${' */
			ಆದರೆ ((varend = strchr(string, '}')) == ಖಾಲಿ) {
				error_f("environment variable '%s' missing "
				    "closing '}'", string);
				ಹೋಗು ಹೊರಹೋಗು;
			}
			len = varend - string;
			ಆದರೆ (len == 0) {
				error_f("zero-length environment variable");
				ಹೋಗು ಹೊರಹೋಗು;
			}
			var = xmalloc(len + 1);
			(ಶೂನ್ಯ)strlcpy(var, string, len + 1);
			ಆದರೆ ((val = getenv(var)) == ಖಾಲಿ) {
				error_f("env var ${%s} has no value", var);
				missingvar = 1;
			} ಇಲ್ಲದಿದ್ದರೆ {
				debug3_f("expand ${%s} -> '%s'", var, val);
				ಆದರೆ ((r = sshbuf_put(buf, val, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(val))) !=0)
					fatal_fr(r, "sshbuf_put ${}");
			}
			ಬಿಡುಗಡೆ(var);
			string += len;
			ಮುಂದುವರಿ;
		}

		/*
		 * Process percent expansions if we have a list of TOKENs.
		 * If we're not doing percent expansion everything just gets
		 * appended here.
		 */
		ಆದರೆ (*string != '%' || !percent) {
 append:
			ಆದರೆ ((r = sshbuf_put_u8(buf, *string)) != 0)
				fatal_fr(r, "sshbuf_put_u8 %%");
			ಮುಂದುವರಿ;
		}
		string++;
		/* %% case */
		ಆದರೆ (*string == '%')
			ಹೋಗು append;
		ಆದರೆ (*string == '\0') {
			error_f("invalid format");
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಗಾಗಿ (i = 0; i < ಅಂಕೆ_ಕೀಲಿಗಳು; i++) {
			ಆದರೆ (strchr(ಕೀಲಿಗಳು[i].ಕೀಲಿ, *string) != ಖಾಲಿ) {
				ಆದರೆ ((r = sshbuf_put(buf, ಕೀಲಿಗಳು[i].repl,
				    ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(ಕೀಲಿಗಳು[i].repl))) != 0)
					fatal_fr(r, "sshbuf_put %%-repl");
				ನಿಲ್ಲಿಸು;
			}
		}
		ಆದರೆ (i >= ಅಂಕೆ_ಕೀಲಿಗಳು) {
			error_f("unknown key %%%c", *string);
			ಹೋಗು ಹೊರಹೋಗು;
		}
	}
	ಆದರೆ (!missingvar && (ret = sshbuf_dup_string(buf)) == ಖಾಲಿ)
		fatal_f("sshbuf_dup_string failed");
	*parseerror = 0;
 ಹೊರಹೋಗು:
	sshbuf_free(buf);
	ಹಿಂತಿರುಗಿ *parseerror ? ಖಾಲಿ : ret;
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು EXPAND_MAX_ಕೀಲಿಗಳು
}

/*
 * Expand only environment variables.
 * Note that although this function is variadic like the other similar
 * functions, any such arguments will be unused.
 */

ಅಕ್ಷರ *
dollar_expand(ಪೂರ್ಣಾಂಕ *parseerr, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *string, ...)
{
	ಅಕ್ಷರ *ret;
	ಪೂರ್ಣಾಂಕ err;
	va_list ap;

	va_start(ap, string);
	ret = vdollar_percent_expand(&err, 1, 0, string, ap);
	va_end(ap);
	ಆದರೆ (parseerr != ಖಾಲಿ)
		*parseerr = err;
	ಹಿಂತಿರುಗಿ ret;
}

/*
 * Returns expanded string or NULL if a specified environment variable is
 * not defined, or calls fatal if the string is invalid.
 */
ಅಕ್ಷರ *
percent_expand(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *string, ...)
{
	ಅಕ್ಷರ *ret;
	ಪೂರ್ಣಾಂಕ err;
	va_list ap;

	va_start(ap, string);
	ret = vdollar_percent_expand(&err, 0, 1, string, ap);
	va_end(ap);
	ಆದರೆ (err)
		fatal_f("failed");
	ಹಿಂತಿರುಗಿ ret;
}

/*
 * Returns expanded string or NULL if a specified environment variable is
 * not defined, or calls fatal if the string is invalid.
 */
ಅಕ್ಷರ *
percent_dollar_expand(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *string, ...)
{
	ಅಕ್ಷರ *ret;
	ಪೂರ್ಣಾಂಕ err;
	va_list ap;

	va_start(ap, string);
	ret = vdollar_percent_expand(&err, 1, 1, string, ap);
	va_end(ap);
	ಆದರೆ (err)
		fatal_f("failed");
	ಹಿಂತಿರುಗಿ ret;
}

ಪೂರ್ಣಾಂಕ
tun_open(ಪೂರ್ಣಾಂಕ tun, ಪೂರ್ಣಾಂಕ ಬಹುಲಕ, ಅಕ್ಷರ **ifname)
{
#ಆದರೆ defined(CUSTOM_SYS_TUN_OPEN)
	ಹಿಂತಿರುಗಿ (sys_tun_open(tun, ಬಹುಲಕ, ifname));
#ಅಥವಾಆದರೆ defined(SSH_TUN_OPENBSD)
	ರಚನೆ ifreq ifr;
	ಅಕ್ಷರ name[100];
	ಪೂರ್ಣಾಂಕ fd = -1, sock;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *tunbase = "tun";

	ಆದರೆ (ifname != ಖಾಲಿ)
		*ifname = ಖಾಲಿ;

	ಆದರೆ (ಬಹುಲಕ == SSH_TUNMODE_ETHERNET)
		tunbase = "tap";

	/* Open the tunnel device */
	ಆದರೆ (tun <= SSH_TUNID_MAX) {
		snprintf(name, ಗಾತ್ರ(name), "/dev/%s%d", tunbase, tun);
		fd = open(name, O_RDWR);
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (tun == SSH_TUNID_ANY) {
		ಗಾಗಿ (tun = 100; tun >= 0; tun--) {
			snprintf(name, ಗಾತ್ರ(name), "/dev/%s%d",
			    tunbase, tun);
			ಆದರೆ ((fd = open(name, O_RDWR)) >= 0)
				ನಿಲ್ಲಿಸು;
		}
	} ಇಲ್ಲದಿದ್ದರೆ {
		debug_f("invalid tunnel %u", tun);
		ಹಿಂತಿರುಗಿ -1;
	}

	ಆದರೆ (fd == -1) {
		debug_f("%s open: %s", name, strerror(errno));
		ಹಿಂತಿರುಗಿ -1;
	}

	debug_f("%s mode %d fd %d", name, ಬಹುಲಕ, fd);

	/* Bring interface up if it is not already */
	snprintf(ifr.ifr_name, ಗಾತ್ರ(ifr.ifr_name), "%s%d", tunbase, tun);
	ಆದರೆ ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
		ಹೋಗು failed;

	ಆದರೆ (ioctl(sock, SIOCGIFFLAGS, &ifr) == -1) {
		debug_f("get interface %s flags: %s", ifr.ifr_name,
		    strerror(errno));
		ಹೋಗು failed;
	}

	ಆದರೆ (!(ifr.ifr_flags & IFF_UP)) {
		ifr.ifr_flags |= IFF_UP;
		ಆದರೆ (ioctl(sock, SIOCSIFFLAGS, &ifr) == -1) {
			debug_f("activate interface %s: %s", ifr.ifr_name,
			    strerror(errno));
			ಹೋಗು failed;
		}
	}

	ಆದರೆ (ifname != ಖಾಲಿ)
		*ifname = xstrdup(ifr.ifr_name);

	close(sock);
	ಹಿಂತಿರುಗಿ fd;

 failed:
	ಆದರೆ (fd >= 0)
		close(fd);
	ಆದರೆ (sock >= 0)
		close(sock);
	ಹಿಂತಿರುಗಿ -1;
#ಇಲ್ಲದಿದ್ದರೆ
	error("Tunnel interfaces are not supported on this platform");
	ಹಿಂತಿರುಗಿ (-1);
#ಆದರೆ_ಅಂತ್ಯ
}

ಶೂನ್ಯ
sanitise_stdfd(ಶೂನ್ಯ)
{
	ಪೂರ್ಣಾಂಕ nullfd, dupfd;

	ಆದರೆ ((nullfd = dupfd = open(_PATH_DEVNULL, O_RDWR)) == -1) {
		fprintf(stderr, "Couldn't open /dev/null: %s\n",
		    strerror(errno));
		ನಿರ್ಗಮಿಸು(1);
	}
	ಆಗ (++dupfd <= STDERR_FILENO) {
		/* Only populate closed fds. */
		ಆದರೆ (fcntl(dupfd, F_GETFL) == -1 && errno == EBADF) {
			ಆದರೆ (dup2(nullfd, dupfd) == -1) {
				fprintf(stderr, "dup2: %s\n", strerror(errno));
				ನಿರ್ಗಮಿಸು(1);
			}
		}
	}
	ಆದರೆ (nullfd > STDERR_FILENO)
		close(nullfd);
}

ಅಕ್ಷರ *
tohex(ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *vp, ಗಾತ್ರ_t l)
{
	ಸ್ಥಿರಾಂಕ u_char *p = (ಸ್ಥಿರಾಂಕ u_char *)vp;
	ಅಕ್ಷರ b[3], *r;
	ಗಾತ್ರ_t i, hl;

	ಆದರೆ (l > 65536)
		ಹಿಂತಿರುಗಿ xstrdup("tohex: length > 65536");

	hl = l * 2 + 1;
	r = xcalloc(1, hl);
	ಗಾಗಿ (i = 0; i < l; i++) {
		snprintf(b, ಗಾತ್ರ(b), "%02x", p[i]);
		strlcat(r, b, hl);
	}
	ಹಿಂತಿರುಗಿ (r);
}

/*
 * Extend string *sp by the specified format. If *sp is not NULL (or empty),
 * then the separator 'sep' will be prepended before the formatted arguments.
 * Extended strings are heap allocated.
 */
ಶೂನ್ಯ
xextendf(ಅಕ್ಷರ **sp, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sep, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *fmt, ...)
{
	va_list ap;
	ಅಕ್ಷರ *tmp1, *tmp2;

	va_start(ap, fmt);
	xvasprintf(&tmp1, fmt, ap);
	va_end(ap);

	ಆದರೆ (*sp == ಖಾಲಿ || **sp == '\0') {
		ಬಿಡುಗಡೆ(*sp);
		*sp = tmp1;
		ಹಿಂತಿರುಗಿ;
	}
	xasprintf(&tmp2, "%s%s%s", *sp, sep == ಖಾಲಿ ? "" : sep, tmp1);
	ಬಿಡುಗಡೆ(tmp1);
	ಬಿಡುಗಡೆ(*sp);
	*sp = tmp2;
}


uint64_t
get_u64(ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *vp)
{
	ಸ್ಥಿರಾಂಕ u_char *p = (ಸ್ಥಿರಾಂಕ u_char *)vp;
	uint64_t v;

	v  = (uint64_t)p[0] << 56;
	v |= (uint64_t)p[1] << 48;
	v |= (uint64_t)p[2] << 40;
	v |= (uint64_t)p[3] << 32;
	v |= (uint64_t)p[4] << 24;
	v |= (uint64_t)p[5] << 16;
	v |= (uint64_t)p[6] << 8;
	v |= (uint64_t)p[7];

	ಹಿಂತಿರುಗಿ (v);
}

uint32_t
get_u32(ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *vp)
{
	ಸ್ಥಿರಾಂಕ u_char *p = (ಸ್ಥಿರಾಂಕ u_char *)vp;
	uint32_t v;

	v  = (uint32_t)p[0] << 24;
	v |= (uint32_t)p[1] << 16;
	v |= (uint32_t)p[2] << 8;
	v |= (uint32_t)p[3];

	ಹಿಂತಿರುಗಿ (v);
}

uint32_t
get_u32_le(ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *vp)
{
	ಸ್ಥಿರಾಂಕ u_char *p = (ಸ್ಥಿರಾಂಕ u_char *)vp;
	uint32_t v;

	v  = (uint32_t)p[0];
	v |= (uint32_t)p[1] << 8;
	v |= (uint32_t)p[2] << 16;
	v |= (uint32_t)p[3] << 24;

	ಹಿಂತಿರುಗಿ (v);
}

uint16_t
get_u16(ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *vp)
{
	ಸ್ಥಿರಾಂಕ u_char *p = (ಸ್ಥಿರಾಂಕ u_char *)vp;
	uint16_t v;

	v  = (uint16_t)p[0] << 8;
	v |= (uint16_t)p[1];

	ಹಿಂತಿರುಗಿ (v);
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
ms_ಕಳೆ_diff(ರಚನೆ timeval *ಆರಂಭ, ಪೂರ್ಣಾಂಕ *ms)
{
	ರಚನೆ timeval diff, ಮುಕ್ತಾಯ;

	monotime_tv(&ಮುಕ್ತಾಯ);
	timersub(&ಮುಕ್ತಾಯ, ಆರಂಭ, &diff);
	*ms -= (diff.tv_sec * 1000) + (diff.tv_usec / 1000);
}

ಶೂನ್ಯ
ms_ಗಮ್ಯ_timespec(ರಚನೆ timespec *ts, ಪೂರ್ಣಾಂಕ ms)
{
	ಆದರೆ (ms < 0)
		ms = 0;
	ts->tv_sec = ms / 1000;
	ts->tv_nsec = (ms % 1000) * 1000 * 1000;
}

ಶೂನ್ಯ
monotime_ts(ರಚನೆ timespec *ts)
{
	ರಚನೆ timeval tv;
#ಆದರೆ defined(HAVE_CLOCK_GETTIME) && (defined(CLOCK_BOOTTIME) || \
    defined(CLOCK_MONOTONIC) || defined(CLOCK_REALTIME))
	ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ gettime_failed = 0;

	ಆದರೆ (!gettime_failed) {
# ifdef CLOCK_BOOTTIME
		ಆದರೆ (clock_gettime(CLOCK_BOOTTIME, ts) == 0)
			ಹಿಂತಿರುಗಿ;
# endif /* CLOCK_BOOTTIME */
# ifdef CLOCK_MONOTONIC
		ಆದರೆ (clock_gettime(CLOCK_MONOTONIC, ts) == 0)
			ಹಿಂತಿರುಗಿ;
# endif /* CLOCK_MONOTONIC */
# ifdef CLOCK_REALTIME
		/* Not monotonic, but we're almost out of options here. */
		ಆದರೆ (clock_gettime(CLOCK_REALTIME, ts) == 0)
			ಹಿಂತಿರುಗಿ;
# endif /* CLOCK_REALTIME */
		debug3("clock_gettime: %s", strerror(errno));
		gettime_failed = 1;
	}
#ಆದರೆ_ಅಂತ್ಯ /* HAVE_CLOCK_GETTIME && (BOOTTIME || MONOTONIC || REALTIME) */
	gettimeofday(&tv, ಖಾಲಿ);
	ts->tv_sec = tv.tv_sec;
	ts->tv_nsec = (ದೀರ್ಘ)tv.tv_usec * 1000;
}

ಶೂನ್ಯ
monotime_tv(ರಚನೆ timeval *tv)
{
	ರಚನೆ timespec ts;

	monotime_ts(&ts);
	tv->tv_sec = ts.tv_sec;
	tv->tv_usec = ts.tv_nsec / 1000;
}

time_t
monotime(ಶೂನ್ಯ)
{
	ರಚನೆ timespec ts;

	monotime_ts(&ts);
	ಹಿಂತಿರುಗಿ (ts.tv_sec);
}

ದ್ವಿಗುಣ
monotime_double(ಶೂನ್ಯ)
{
	ರಚನೆ timespec ts;

	monotime_ts(&ts);
	ಹಿಂತಿರುಗಿ (ದ್ವಿಗುಣ)ts.tv_sec + (ದ್ವಿಗುಣ)ts.tv_nsec / 1000000000.0;
}

ಶೂನ್ಯ
bandwidth_ಎಲ್ಲೆ_init(ರಚನೆ bwlimit *bw, uint64_t kbps, ಗಾತ್ರ_t buflen)
{
	bw->buflen = buflen;
	bw->ದರ = kbps;
	bw->thresh = buflen;
	bw->lamt = 0;
	timerclear(&bw->bwstart);
	timerclear(&bw->bwend);
}

/* Callback from read/write loop to insert bandwidth-limiting delays */
ಶೂನ್ಯ
bandwidth_ಎಲ್ಲೆ(ರಚನೆ bwlimit *bw, ಗಾತ್ರ_t read_len)
{
	uint64_t waitlen;
	ರಚನೆ timespec ts, rm;

	bw->lamt += read_len;
	ಆದರೆ (!timerisset(&bw->bwstart)) {
		monotime_tv(&bw->bwstart);
		ಹಿಂತಿರುಗಿ;
	}
	ಆದರೆ (bw->lamt < bw->thresh)
		ಹಿಂತಿರುಗಿ;

	monotime_tv(&bw->bwend);
	timersub(&bw->bwend, &bw->bwstart, &bw->bwend);
	ಆದರೆ (!timerisset(&bw->bwend))
		ಹಿಂತಿರುಗಿ;

	bw->lamt *= 8;
	waitlen = (ದ್ವಿಗುಣ)1000000L * bw->lamt / bw->ದರ;

	bw->bwstart.tv_sec = waitlen / 1000000L;
	bw->bwstart.tv_usec = waitlen % 1000000L;

	ಆದರೆ (timercmp(&bw->bwstart, &bw->bwend, >)) {
		timersub(&bw->bwstart, &bw->bwend, &bw->bwend);

		/* Adjust the wait time */
		ಆದರೆ (bw->bwend.tv_sec) {
			bw->thresh /= 2;
			ಆದರೆ (bw->thresh < bw->buflen / 4)
				bw->thresh = bw->buflen / 4;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (bw->bwend.tv_usec < 10000) {
			bw->thresh *= 2;
			ಆದರೆ (bw->thresh > bw->buflen * 8)
				bw->thresh = bw->buflen * 8;
		}

		TIMEVAL_ಗಮ್ಯ_TIMESPEC(&bw->bwend, &ts);
		ಆಗ (nanosleep(&ts, &rm) == -1) {
			ಆದರೆ (errno != EINTR)
				ನಿಲ್ಲಿಸು;
			ts = rm;
		}
	}

	bw->lamt = 0;
	monotime_tv(&bw->bwstart);
}

/* Make a template filename for mk[sd]temp() */
ಶೂನ್ಯ
mktemp_proto(ಅಕ್ಷರ *s, ಗಾತ್ರ_t len)
{
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *tmpdir;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((tmpdir = getenv("TMPDIR")) != ಖಾಲಿ) {
		r = snprintf(s, len, "%s/ssh-XXXXXXXXXXXX", tmpdir);
		ಆದರೆ (r > 0 && (ಗಾತ್ರ_t)r < len)
			ಹಿಂತಿರುಗಿ;
	}
	r = snprintf(s, len, "/tmp/ssh-XXXXXXXXXXXX");
	ಆದರೆ (r < 0 || (ಗಾತ್ರ_t)r >= len)
		fatal_f("template string too short");
}

ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ರಚನೆ {
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name;
	ಪೂರ್ಣಾಂಕ ಮೌಲ್ಯ;
} ipqos[] = {
	{ "none", ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ },		/* can't use 0 here; that's CS0 */
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
	{ ಖಾಲಿ, -1 }
};

ಪೂರ್ಣಾಂಕ
parse_ipqos(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *cp)
{
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *errstr;
	u_int i;
	ಪೂರ್ಣಾಂಕ val;

	ಆದರೆ (cp == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ -1;
	ಗಾಗಿ (i = 0; ipqos[i].name != ಖಾಲಿ; i++) {
		ಆದರೆ (strcasecmp(cp, ipqos[i].name) == 0)
			ಹಿಂತಿರುಗಿ ipqos[i].ಮೌಲ್ಯ;
	}
	/* Try parsing as an integer */
	val = (ಪೂರ್ಣಾಂಕ)strtonum(cp, 0, 255, &errstr);
	ಆದರೆ (errstr)
		ಹಿಂತಿರುಗಿ -1;
	ಹಿಂತಿರುಗಿ val;
}

ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *
iptos2str(ಪೂರ್ಣಾಂಕ iptos)
{
	ಪೂರ್ಣಾಂಕ i;
	ಸ್ಥಿರ ಅಕ್ಷರ iptos_str[ಗಾತ್ರ "0xff"];

	ಗಾಗಿ (i = 0; ipqos[i].name != ಖಾಲಿ; i++) {
		ಆದರೆ (ipqos[i].ಮೌಲ್ಯ == iptos)
			ಹಿಂತಿರುಗಿ ipqos[i].name;
	}
	snprintf(iptos_str, ಗಾತ್ರ iptos_str, "0x%02x", iptos);
	ಹಿಂತಿರುಗಿ iptos_str;
}

ಶೂನ್ಯ
lowercase(ಅಕ್ಷರ *s)
{
	ಗಾಗಿ (; *s; s++)
		*s = tolower((u_char)*s);
}

ಪೂರ್ಣಾಂಕ
unix_listener(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ, ಪೂರ್ಣಾಂಕ backlog, ಪೂರ್ಣಾಂಕ unlink_ಮೊದಲ)
{
	ರಚನೆ sockaddr_un sunaddr;
	ಪೂರ್ಣಾಂಕ saved_errno, sock;

	memset(&sunaddr, 0, ಗಾತ್ರ(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	ಆದರೆ (strlcpy(sunaddr.sun_ಮಾರ್ಗ, ಮಾರ್ಗ,
	    ಗಾತ್ರ(sunaddr.sun_ಮಾರ್ಗ)) >= ಗಾತ್ರ(sunaddr.sun_ಮಾರ್ಗ)) {
		error_f("path \"%s\" too long for Unix domain socket", ಮಾರ್ಗ);
		errno = ENAMETOOLONG;
		ಹಿಂತಿರುಗಿ -1;
	}

	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	ಆದರೆ (sock == -1) {
		saved_errno = errno;
		error_f("socket: %.100s", strerror(errno));
		errno = saved_errno;
		ಹಿಂತಿರುಗಿ -1;
	}
	ಆದರೆ (unlink_ಮೊದಲ == 1) {
		ಆದರೆ (unlink(ಮಾರ್ಗ) != 0 && errno != ENOENT)
			error("unlink(%s): %.100s", ಮಾರ್ಗ, strerror(errno));
	}
	ಆದರೆ (bind(sock, (ರಚನೆ sockaddr *)&sunaddr, ಗಾತ್ರ(sunaddr)) == -1) {
		saved_errno = errno;
		error_f("cannot bind to path %s: %s", ಮಾರ್ಗ, strerror(errno));
		close(sock);
		errno = saved_errno;
		ಹಿಂತಿರುಗಿ -1;
	}
	ಆದರೆ (listen(sock, backlog) == -1) {
		saved_errno = errno;
		error_f("cannot listen on path %s: %s", ಮಾರ್ಗ, strerror(errno));
		close(sock);
		unlink(ಮಾರ್ಗ);
		errno = saved_errno;
		ಹಿಂತಿರುಗಿ -1;
	}
	ಹಿಂತಿರುಗಿ sock;
}

ಶೂನ್ಯ
sock_ಗಣ_v6only(ಪೂರ್ಣಾಂಕ s)
{
#ಆದರೆ defined(IPV6_V6ONLY) && !defined(__OpenBSD__)
	ಪೂರ್ಣಾಂಕ on = 1;

	debug3_f("set socket %d IPV6_V6ONLY", s);
	ಆದರೆ (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &on, ಗಾತ್ರ(on)) == -1)
		error("setsockopt IPV6_V6ONLY: %s", strerror(errno));
#ಆದರೆ_ಅಂತ್ಯ
}

/*
 * Compares two strings that maybe be NULL. Returns non-zero if strings
 * are both NULL or are identical, returns zero otherwise.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
strcmp_maybe_null(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *a, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *b)
{
	ಆದರೆ ((a == ಖಾಲಿ && b != ಖಾಲಿ) || (a != ಖಾಲಿ && b == ಖಾಲಿ))
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ (a != ಖಾಲಿ && strcmp(a, b) != 0)
		ಹಿಂತಿರುಗಿ 0;
	ಹಿಂತಿರುಗಿ 1;
}

/*
 * Compare two forwards, returning non-zero if they are identical or
 * zero otherwise.
 */
ಪೂರ್ಣಾಂಕ
forward_equals(ಸ್ಥಿರಾಂಕ ರಚನೆ Forward *a, ಸ್ಥಿರಾಂಕ ರಚನೆ Forward *b)
{
	ಆದರೆ (strcmp_maybe_null(a->listen_host, b->listen_host) == 0)
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ (a->listen_ಪೋರ್ಟ್ != b->listen_ಪೋರ್ಟ್)
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ (strcmp_maybe_null(a->listen_ಮಾರ್ಗ, b->listen_ಮಾರ್ಗ) == 0)
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ (strcmp_maybe_null(a->connect_host, b->connect_host) == 0)
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ (a->connect_ಪೋರ್ಟ್ != b->connect_ಪೋರ್ಟ್)
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ (strcmp_maybe_null(a->connect_ಮಾರ್ಗ, b->connect_ಮಾರ್ಗ) == 0)
		ಹಿಂತಿರುಗಿ 0;
	/* allocated_port and handle are not checked */
	ಹಿಂತಿರುಗಿ 1;
}

/* returns port number, FWD_PERMIT_ANY_PORT or -1 on error */
ಪೂರ್ಣಾಂಕ
permitopen_ಪೋರ್ಟ್(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *p)
{
	ಪೂರ್ಣಾಂಕ ಪೋರ್ಟ್;

	ಆದರೆ (strcmp(p, "*") == 0)
		ಹಿಂತಿರುಗಿ FWD_PERMIT_ANY_ಪೋರ್ಟ್;
	ಆದರೆ ((ಪೋರ್ಟ್ = a2port(p)) > 0)
		ಹಿಂತಿರುಗಿ ಪೋರ್ಟ್;
	ಹಿಂತಿರುಗಿ -1;
}

/* returns 1 if process is already daemonized, 0 otherwise */
ಪೂರ್ಣಾಂಕ
daemonized(ಶೂನ್ಯ)
{
	ಪೂರ್ಣಾಂಕ fd;

	ಆದರೆ ((fd = open(_PATH_TTY, O_RDONLY | O_NOCTTY)) >= 0) {
		close(fd);
		ಹಿಂತಿರುಗಿ 0;	/* have controlling terminal */
	}
	ಆದರೆ (getppid() != 1)
		ಹಿಂತಿರುಗಿ 0;	/* parent is not init */
	ಆದರೆ (getsid(0) != getpid())
		ಹಿಂತಿರುಗಿ 0;	/* not session leader */
	debug3("already daemonized");
	ಹಿಂತಿರುಗಿ 1;
}

/*
 * Splits 's' into an argument vector. Handles quoted string and basic
 * escape characters (\\, \", \'). Caller must free the argument vector
 * and its members.
 */
ಪೂರ್ಣಾಂಕ
argv_ವಿಭಜಿಸು(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *s, ಪೂರ್ಣಾಂಕ *argcp, ಅಕ್ಷರ ***argvp, ಪೂರ್ಣಾಂಕ terminate_on_comment)
{
	ಪೂರ್ಣಾಂಕ r = SSH_ERR_ಆಂತರಿಕ_ERROR;
	ಪೂರ್ಣಾಂಕ argc = 0, quote, i, j;
	ಅಕ್ಷರ *arg, **argv = xcalloc(1, ಗಾತ್ರ(*argv));

	*argvp = ಖಾಲಿ;
	*argcp = 0;

	ಗಾಗಿ (i = 0; s[i] != '\0'; i++) {
		/* Skip leading whitespace */
		ಆದರೆ (s[i] == ' ' || s[i] == '\t')
			ಮುಂದುವರಿ;
		ಆದರೆ (terminate_on_comment && s[i] == '#')
			ನಿಲ್ಲಿಸು;
		/* Start of a token */
		quote = 0;

		argv = xreallocarray(argv, (argc + 2), ಗಾತ್ರ(*argv));
		arg = argv[argc++] = xcalloc(1, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(s + i) + 1);
		argv[argc] = ಖಾಲಿ;

		/* Copy the token in, removing escapes */
		ಗಾಗಿ (j = 0; s[i] != '\0'; i++) {
			ಆದರೆ (s[i] == '\\') {
				ಆದರೆ (s[i + 1] == '\'' ||
				    s[i + 1] == '\"' ||
				    s[i + 1] == '\\' ||
				    (quote == 0 && s[i + 1] == ' ')) {
					i++; /* Skip '\' */
					arg[j++] = s[i];
				} ಇಲ್ಲದಿದ್ದರೆ {
					/* Unrecognised escape */
					arg[j++] = s[i];
				}
			} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (quote == 0 && (s[i] == ' ' || s[i] == '\t'))
				ನಿಲ್ಲಿಸು; /*ಮುಗಿದ*/
			ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (quote == 0 && (s[i] == '\"' || s[i] == '\''))
				quote = s[i]; /* quote start */
			ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (quote != 0 && s[i] == quote)
				quote = 0; /* quote end */
			ಇಲ್ಲದಿದ್ದರೆ
				arg[j++] = s[i];
		}
		ಆದರೆ (s[i] == '\0') {
			ಆದರೆ (quote != 0) {
				/* Ran out of string looking for close quote */
				r = SSH_ERR_INVALID_FORMAT;
				ಹೋಗು ಹೊರಹೋಗು;
			}
			ನಿಲ್ಲಿಸು;
		}
	}
	/* Success */
	*argcp = argc;
	*argvp = argv;
	argc = 0;
	argv = ಖಾಲಿ;
	r = 0;
 ಹೊರಹೋಗು:
	ಆದರೆ (argc != 0 && argv != ಖಾಲಿ) {
		ಗಾಗಿ (i = 0; i < argc; i++)
			ಬಿಡುಗಡೆ(argv[i]);
		ಬಿಡುಗಡೆ(argv);
	}
	ಹಿಂತಿರುಗಿ r;
}

/*
 * Reassemble an argument vector into a string, quoting and escaping as
 * necessary. Caller must free returned string.
 */
ಅಕ್ಷರ *
argv_assemble(ಪೂರ್ಣಾಂಕ argc, ಅಕ್ಷರ **argv)
{
	ಪೂರ್ಣಾಂಕ i, j, ws, r;
	ಅಕ್ಷರ c, *ret;
	ರಚನೆ sshbuf *buf, *arg;

	ಆದರೆ ((buf = sshbuf_new()) == ಖಾಲಿ || (arg = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");

	ಗಾಗಿ (i = 0; i < argc; i++) {
		ws = 0;
		sshbuf_reset(arg);
		ಗಾಗಿ (j = 0; argv[i][j] != '\0'; j++) {
			r = 0;
			c = argv[i][j];
			ಆಯ್ಕೆ (c) {
			ಸ್ಥಿತಿ ' ':
			ಸ್ಥಿತಿ '\t':
				ws = 1;
				r = sshbuf_put_u8(arg, c);
				ನಿಲ್ಲಿಸು;
			ಸ್ಥಿತಿ '\\':
			ಸ್ಥಿತಿ '\'':
			ಸ್ಥಿತಿ '"':
				ಆದರೆ ((r = sshbuf_put_u8(arg, '\\')) != 0)
					ನಿಲ್ಲಿಸು;
				/* FALLTHROUGH */
			ಪೂರ್ವನಿಯೋಜಿತ:
				r = sshbuf_put_u8(arg, c);
				ನಿಲ್ಲಿಸು;
			}
			ಆದರೆ (r != 0)
				fatal_fr(r, "sshbuf_put_u8");
		}
		ಆದರೆ ((i != 0 && (r = sshbuf_put_u8(buf, ' ')) != 0) ||
		    (ws != 0 && (r = sshbuf_put_u8(buf, '"')) != 0) ||
		    (r = sshbuf_putb(buf, arg)) != 0 ||
		    (ws != 0 && (r = sshbuf_put_u8(buf, '"')) != 0))
			fatal_fr(r, "assemble");
	}
	ಆದರೆ ((ret = ಸ್ಮರಣೆ_ಕೊಡು(sshbuf_len(buf) + 1)) == ಖಾಲಿ)
		fatal_f("malloc failed");
	ಸ್ಮರಣೆ_ನಕಲು(ret, sshbuf_ptr(buf), sshbuf_len(buf));
	ret[sshbuf_len(buf)] = '\0';
	sshbuf_free(buf);
	sshbuf_free(arg);
	ಹಿಂತಿರುಗಿ ret;
}

ಅಕ್ಷರ *
argv_ಮುಂದಿನ(ಪೂರ್ಣಾಂಕ *argcp, ಅಕ್ಷರ ***argvp)
{
	ಅಕ್ಷರ *ret = (*argvp)[0];

	ಆದರೆ (*argcp > 0 && ret != ಖಾಲಿ) {
		(*argcp)--;
		(*argvp)++;
	}
	ಹಿಂತಿರುಗಿ ret;
}

ಶೂನ್ಯ
argv_consume(ಪೂರ್ಣಾಂಕ *argcp)
{
	*argcp = 0;
}

ಶೂನ್ಯ
argv_free(ಅಕ್ಷರ **av, ಪೂರ್ಣಾಂಕ ac)
{
	ಪೂರ್ಣಾಂಕ i;

	ಆದರೆ (av == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;
	ಗಾಗಿ (i = 0; i < ac; i++)
		ಬಿಡುಗಡೆ(av[i]);
	ಬಿಡುಗಡೆ(av);
}

/* Returns 0 if pid exited cleanly, non-zero otherwise */
ಪೂರ್ಣಾಂಕ
exited_cleanly(pid_t pid, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಟ್ಯಾಗ್, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *cmd, ಪೂರ್ಣಾಂಕ quiet)
{
	ಪೂರ್ಣಾಂಕ ಸ್ಥಿತಿ_2;

	ಆಗ (waitpid(pid, &ಸ್ಥಿತಿ_2, 0) == -1) {
		ಆದರೆ (errno != EINTR) {
			error("%s waitpid: %s", ಟ್ಯಾಗ್, strerror(errno));
			ಹಿಂತಿರುಗಿ -1;
		}
	}
	ಆದರೆ (WIFSIGNALED(ಸ್ಥಿತಿ_2)) {
		error("%s %s exited on signal %d", ಟ್ಯಾಗ್, cmd, WTERMSIG(ಸ್ಥಿತಿ_2));
		ಹಿಂತಿರುಗಿ -1;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (WEXITSTATUS(ಸ್ಥಿತಿ_2) != 0) {
		do_log2(quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_INFO,
		    "%s %s failed, status %d", ಟ್ಯಾಗ್, cmd, WEXITSTATUS(ಸ್ಥಿತಿ_2));
		ಹಿಂತಿರುಗಿ -1;
	}
	ಹಿಂತಿರುಗಿ 0;
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
ಪೂರ್ಣಾಂಕ
ಸುರಕ್ಷಿತ_ಮಾರ್ಗ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name, ರಚನೆ stat *stp, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *pw_dir,
    uid_t uid, ಅಕ್ಷರ *err, ಗಾತ್ರ_t errlen)
{
	ಅಕ್ಷರ buf[PATH_MAX], buf2[PATH_MAX], homedir[PATH_MAX];
	ಅಕ್ಷರ *cp;
	ಪೂರ್ಣಾಂಕ comparehome = 0;
	ರಚನೆ stat st;

	ಆದರೆ (realpath(name, buf) == ಖಾಲಿ) {
		snprintf(err, errlen, "realpath %s failed: %s", name,
		    strerror(errno));
		ಹಿಂತಿರುಗಿ -1;
	}
	ಆದರೆ (pw_dir != ಖಾಲಿ && realpath(pw_dir, homedir) != ಖಾಲಿ)
		comparehome = 1;

	ಆದರೆ (!S_ISREG(stp->st_mode)) {
		snprintf(err, errlen, "%s is not a regular file", buf);
		ಹಿಂತಿರುಗಿ -1;
	}
	ಆದರೆ ((!platform_sys_dir_uid(stp->st_uid) && stp->st_uid != uid) ||
	    (stp->st_mode & 022) != 0) {
		snprintf(err, errlen, "bad ownership or modes for file %s",
		    buf);
		ಹಿಂತಿರುಗಿ -1;
	}

	/* for each component of the canonical path, walking upwards */
	ಗಾಗಿ (;;) {
		/*
		 * POSIX allows dirname to modify its argument and return a
		 * pointer into it, so make a copy to avoid overlapping strlcpy.
		 */
		strlcpy(buf2, buf, ಗಾತ್ರ(buf2));
		ಆದರೆ ((cp = dirname(buf2)) == ಖಾಲಿ) {
			snprintf(err, errlen, "dirname() failed");
			ಹಿಂತಿರುಗಿ -1;
		}
		strlcpy(buf, cp, ಗಾತ್ರ(buf));

		ಆದರೆ (stat(buf, &st) == -1 ||
		    (!platform_sys_dir_uid(st.st_uid) && st.st_uid != uid) ||
		    (st.st_mode & 022) != 0) {
			snprintf(err, errlen,
			    "bad ownership or modes for directory %s", buf);
			ಹಿಂತಿರುಗಿ -1;
		}

		/* If are past the homedir then we can stop */
		ಆದರೆ (comparehome && strcmp(homedir, buf) == 0)
			ನಿಲ್ಲಿಸು;

		/*
		 * dirname should always complete with a "/" path,
		 * but we can be paranoid and check for "." too
		 */
		ಆದರೆ ((strcmp("/", buf) == 0) || (strcmp(".", buf) == 0))
			ನಿಲ್ಲಿಸು;
	}
	ಹಿಂತಿರುಗಿ 0;
}

/*
 * Version of safe_path() that accepts an open file descriptor to
 * avoid races.
 *
 * Returns 0 on success and -1 on failure
 */
ಪೂರ್ಣಾಂಕ
ಸುರಕ್ಷಿತ_ಮಾರ್ಗ_fd(ಪೂರ್ಣಾಂಕ fd, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *file, ರಚನೆ passwd *pw,
    ಅಕ್ಷರ *err, ಗಾತ್ರ_t errlen)
{
	ರಚನೆ stat st;

	/* check the open file to avoid races */
	ಆದರೆ (fstat(fd, &st) == -1) {
		snprintf(err, errlen, "cannot stat file %s: %s",
		    file, strerror(errno));
		ಹಿಂತಿರುಗಿ -1;
	}
	ಹಿಂತಿರುಗಿ ಸುರಕ್ಷಿತ_ಮಾರ್ಗ(file, &st, pw->pw_dir, pw->pw_uid, err, errlen);
}

/*
 * Sets the value of the given variable in the environment.  If the variable
 * already exists, its value is overridden.
 */
ಶೂನ್ಯ
ಮಗು_ಗಣ_env(ಅಕ್ಷರ ***envp, u_int *envsizep, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name,
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮೌಲ್ಯ)
{
	ಅಕ್ಷರ **env;
	u_int envsize;
	u_int i, namelen;

	ಆದರೆ (strchr(name, '=') != ಖಾಲಿ) {
		error("Invalid environment variable \"%.100s\"", name);
		ಹಿಂತಿರುಗಿ;
	}

	/*
	 * If we're passed an uninitialized list, allocate a single null
	 * entry before continuing.
	 */
	ಆದರೆ ((*envp == ಖಾಲಿ) != (*envsizep == 0))
		fatal_f("environment size mismatch");
	ಆದರೆ (*envp == ಖಾಲಿ && *envsizep == 0) {
		*envp = xmalloc(ಗಾತ್ರ(ಅಕ್ಷರ *));
		*envp[0] = ಖಾಲಿ;
		*envsizep = 1;
	}

	/*
	 * Find the slot where the value should be stored.  If the variable
	 * already exists, we reuse the slot; otherwise we append a new slot
	 * at the end of the array, expanding if necessary.
	 */
	env = *envp;
	namelen = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(name);
	ಗಾಗಿ (i = 0; env[i]; i++)
		ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಹೋಲಿಕೆ(env[i], name, namelen) == 0 && env[i][namelen] == '=')
			ನಿಲ್ಲಿಸು;
	ಆದರೆ (env[i]) {
		/* Reuse the slot. */
		ಬಿಡುಗಡೆ(env[i]);
	} ಇಲ್ಲದಿದ್ದರೆ {
		/* New variable.  Expand if necessary. */
		envsize = *envsizep;
		ಆದರೆ (i >= envsize - 1) {
			ಆದರೆ (envsize >= 1000)
				fatal("child_set_env: too many env vars");
			envsize += 50;
			env = (*envp) = xreallocarray(env, envsize, ಗಾತ್ರ(ಅಕ್ಷರ *));
			*envsizep = envsize;
		}
		/* Need to set the NULL pointer at end of array beyond the new slot. */
		env[i + 1] = ಖಾಲಿ;
	}

	/* Allocate space and format the variable in the appropriate slot. */
	/* XXX xasprintf */
	env[i] = xmalloc(ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(name) + 1 + ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(ಮೌಲ್ಯ) + 1);
	snprintf(env[i], ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(name) + 1 + ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(ಮೌಲ್ಯ) + 1, "%s=%s", name, ಮೌಲ್ಯ);
}

/*
 * Check and optionally lowercase a domain name, also removes trailing '.'
 * Returns 1 on success and 0 on failure, storing an error message in errstr.
 */
ಪೂರ್ಣಾಂಕ
valid_domain(ಅಕ್ಷರ *name, ಪೂರ್ಣಾಂಕ makelower, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ **errstr)
{
	ಗಾತ್ರ_t i, l = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(name);
	u_char c, ಕೊನೆಯ = '\0';
	ಸ್ಥಿರ ಅಕ್ಷರ errbuf[256];

	ಆದರೆ (l == 0) {
		strlcpy(errbuf, "empty domain name", ಗಾತ್ರ(errbuf));
		ಹೋಗು bad;
	}
	ಆದರೆ (!ಅಕ್ಷರವೇ((u_char)name[0]) && !ಅಂಕಿಯೇ((u_char)name[0]) &&
	   name[0] != '_' /* technically invalid, but common */) {
		snprintf(errbuf, ಗಾತ್ರ(errbuf), "domain name \"%.100s\" "
		    "starts with invalid character", name);
		ಹೋಗು bad;
	}
	ಗಾಗಿ (i = 0; i < l; i++) {
		c = tolower((u_char)name[i]);
		ಆದರೆ (makelower)
			name[i] = (ಅಕ್ಷರ)c;
		ಆದರೆ (ಕೊನೆಯ == '.' && c == '.') {
			snprintf(errbuf, ಗಾತ್ರ(errbuf), "domain name "
			    "\"%.100s\" contains consecutive separators", name);
			ಹೋಗು bad;
		}
		ಆದರೆ (c != '.' && c != '-' && !ಅಕ್ಷರವೇ_ಅಂಕಿಯೇ(c) &&
		    c != '_') /* technically invalid, but common */ {
			snprintf(errbuf, ಗಾತ್ರ(errbuf), "domain name "
			    "\"%.100s\" contains invalid characters", name);
			ಹೋಗು bad;
		}
		ಕೊನೆಯ = c;
	}
	ಆದರೆ (name[l - 1] == '.')
		name[l - 1] = '\0';
	ಆದರೆ (errstr != ಖಾಲಿ)
		*errstr = ಖಾಲಿ;
	ಹಿಂತಿರುಗಿ 1;
bad:
	ಆದರೆ (errstr != ಖಾಲಿ)
		*errstr = errbuf;
	ಹಿಂತಿರುಗಿ 0;
}

/*
 * Verify that a environment variable name (not including initial '$') is
 * valid; consisting of one or more alphanumeric or underscore characters only.
 * Returns 1 on valid, 0 otherwise.
 */
ಪೂರ್ಣಾಂಕ
valid_env_name(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name)
{
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *cp;

	ಆದರೆ (name[0] == '\0')
		ಹಿಂತಿರುಗಿ 0;
	ಗಾಗಿ (cp = name; *cp != '\0'; cp++) {
		ಆದರೆ (!ಅಕ್ಷರವೇ_ಅಂಕಿಯೇ((u_char)*cp) && *cp != '_')
			ಹಿಂತಿರುಗಿ 0;
	}
	ಹಿಂತಿರುಗಿ 1;
}

ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *
atoi_err(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *nptr, ಪೂರ್ಣಾಂಕ *val)
{
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *errstr = ಖಾಲಿ;

	ಆದರೆ (nptr == ಖಾಲಿ || *nptr == '\0')
		ಹಿಂತಿರುಗಿ "missing";
	*val = strtonum(nptr, 0, ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ, &errstr);
	ಹಿಂತಿರುಗಿ errstr;
}

ಪೂರ್ಣಾಂಕ
parse_absolute_ಸಮಯ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *s, uint64_t *tp)
{
	ರಚನೆ tm tm;
	time_t tt;
	ಅಕ್ಷರ buf[32], *fmt;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *cp;
	ಗಾತ್ರ_t l;
	ಪೂರ್ಣಾಂಕ is_utc = 0;

	*tp = 0;

	l = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(s);
	ಆದರೆ (l > 1 && strcasecmp(s + l - 1, "Z") == 0) {
		is_utc = 1;
		l--;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (l > 3 && strcasecmp(s + l - 3, "UTC") == 0) {
		is_utc = 1;
		l -= 3;
	}
	/*
	 * POSIX strptime says "The application shall ensure that there
	 * is white-space or other non-alphanumeric characters between
	 * any two conversion specifications" so arrange things this way.
	 */
	ಆಯ್ಕೆ (l) {
	ಸ್ಥಿತಿ 8: /* YYYYMMDD */
		fmt = "%Y-%m-%d";
		snprintf(buf, ಗಾತ್ರ(buf), "%.4s-%.2s-%.2s", s, s + 4, s + 6);
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ 12: /* YYYYMMDDHHMM */
		fmt = "%Y-%m-%dT%H:%M";
		snprintf(buf, ಗಾತ್ರ(buf), "%.4s-%.2s-%.2sT%.2s:%.2s",
		    s, s + 4, s + 6, s + 8, s + 10);
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ 14: /* YYYYMMDDHHMMSS */
		fmt = "%Y-%m-%dT%H:%M:%S";
		snprintf(buf, ಗಾತ್ರ(buf), "%.4s-%.2s-%.2sT%.2s:%.2s:%.2s",
		    s, s + 4, s + 6, s + 8, s + 10, s + 12);
		ನಿಲ್ಲಿಸು;
	ಪೂರ್ವನಿಯೋಜಿತ:
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_FORMAT;
	}

	memset(&tm, 0, ಗಾತ್ರ(tm));
	ಆದರೆ ((cp = strptime(buf, fmt, &tm)) == ಖಾಲಿ || *cp != '\0')
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_FORMAT;
	ಆದರೆ (is_utc) {
		tm.tm_wday = -1;	/* sentinel for error */
		ಆದರೆ ((tt = timegm(&tm)) == -1 && tm.tm_wday == -1)
			ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_FORMAT;
	} ಇಲ್ಲದಿದ್ದರೆ {
		tm.tm_wday = -1;	/* sentinel for error */
		tm.tm_isdst = -1;	/* mktime decides DST */
		ಆದರೆ ((tt = mktime(&tm)) == -1 && tm.tm_wday == -1)
			ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_FORMAT;
	}
	/* success */
	*tp = (uint64_t)tt;
	ಹಿಂತಿರುಗಿ 0;
}

ಶೂನ್ಯ
format_absolute_ಸಮಯ(uint64_t t, ಅಕ್ಷರ *buf, ಗಾತ್ರ_t len)
{
	time_t tt = t > SSH_ಸಮಯ_T_MAX ? SSH_ಸಮಯ_T_MAX : t;
	ರಚನೆ tm tm;

	ಆದರೆ (localtime_r(&tt, &tm) == ಖಾಲಿ)
		strlcpy(buf, "UNKNOWN-TIME", len);
	ಇಲ್ಲದಿದ್ದರೆ
		strftime(buf, len, "%Y-%m-%dT%H:%M:%S", &tm);
}

/*
 * Parse a "pattern=interval" clause (e.g. a ChannelTimeout).
 * Returns 0 on success or non-zero on failure.
 * Caller must free *typep.
 */
ಪೂರ್ಣಾಂಕ
parse_ನಮೂನೆ_interval(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *s, ಅಕ್ಷರ **typep, ದ್ವಿಗುಣ *secsp)
{
	ಅಕ್ಷರ *cp, *sdup;
	ದ್ವಿಗುಣ secs;

	ಆದರೆ (typep != ಖಾಲಿ)
		*typep = ಖಾಲಿ;
	ಆದರೆ (secsp != ಖಾಲಿ)
		*secsp = 0;
	ಆದರೆ (s == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ -1;
	sdup = xstrdup(s);

	ಆದರೆ ((cp = strchr(sdup, '=')) == ಖಾಲಿ || cp == sdup) {
		ಬಿಡುಗಡೆ(sdup);
		ಹಿಂತಿರುಗಿ -1;
	}
	*cp++ = '\0';
	ಆದರೆ ((secs = convtime_double(cp)) < 0.0) {
		ಬಿಡುಗಡೆ(sdup);
		ಹಿಂತಿರುಗಿ -1;
	}
	/* success */
	ಆದರೆ (typep != ಖಾಲಿ)
		*typep = xstrdup(sdup);
	ಆದರೆ (secsp != ಖಾಲಿ)
		*secsp = secs;
	ಬಿಡುಗಡೆ(sdup);
	ಹಿಂತಿರುಗಿ 0;
}

/* check if path is absolute */
ಪೂರ್ಣಾಂಕ
ಮಾರ್ಗ_absolute(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ)
{
	ಹಿಂತಿರುಗಿ (*ಮಾರ್ಗ == '/') ? 1 : 0;
}

ಶೂನ್ಯ
skip_space(ಅಕ್ಷರ **cpp)
{
	ಅಕ್ಷರ *cp;

	ಗಾಗಿ (cp = *cpp; *cp == ' ' || *cp == '\t'; cp++)
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
ಪೂರ್ಣಾಂಕ
opt_flag(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *opt, ಪೂರ್ಣಾಂಕ allow_negate, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ **optsp)
{
	ಗಾತ್ರ_t opt_len = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(opt);
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *opts = *optsp;
	ಪೂರ್ಣಾಂಕ negate = 0;

	ಆದರೆ (allow_negate && strncasecmp(opts, "no-", 3) == 0) {
		opts += 3;
		negate = 1;
	}
	ಆದರೆ (strncasecmp(opts, opt, opt_len) == 0) {
		*optsp = opts + opt_len;
		ಹಿಂತಿರುಗಿ negate ? 0 : 1;
	}
	ಹಿಂತಿರುಗಿ -1;
}

ಅಕ್ಷರ *
opt_dequote(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ **sp, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ **errstrp)
{
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *s = *sp;
	ಅಕ್ಷರ *ret;
	ಗಾತ್ರ_t i;

	*errstrp = ಖಾಲಿ;
	ಆದರೆ (*s != '"') {
		*errstrp = "missing start quote";
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	s++;
	ಆದರೆ ((ret = ಸ್ಮರಣೆ_ಕೊಡು(ಅಕ್ಷರಸರಣಿ_ಉದ್ದ((s)) + 1)) == ಖಾಲಿ) {
		*errstrp = "memory allocation failed";
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	ಗಾಗಿ (i = 0; *s != '\0' && *s != '"';) {
		ಆದರೆ (s[0] == '\\' && s[1] == '"')
			s++;
		ret[i++] = *s++;
	}
	ಆದರೆ (*s == '\0') {
		*errstrp = "missing end quote";
		ಬಿಡುಗಡೆ(ret);
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	ret[i] = '\0';
	s++;
	*sp = s;
	ಹಿಂತಿರುಗಿ ret;
}

ಪೂರ್ಣಾಂಕ
opt_ಹೊಂದಿಕೆ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ **opts, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಪದ)
{
	ಆದರೆ (strncasecmp((*opts), ಪದ, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(ಪದ)) == 0 &&
	    (*opts)[ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(ಪದ)] == '=') {
		*opts += ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(ಪದ) + 1;
		ಹಿಂತಿರುಗಿ 1;
	}
	ಹಿಂತಿರುಗಿ 0;
}

ಶೂನ್ಯ
opt_array_append2(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *file, ಸ್ಥಿರಾಂಕ ಪೂರ್ಣಾಂಕ ಸಾಲು, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *directive,
    ಅಕ್ಷರ ***array, ಪೂರ್ಣಾಂಕ **iarray, u_int *lp, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *s, ಪೂರ್ಣಾಂಕ i)
{

	ಆದರೆ (*lp >= ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ)
		fatal("%s line %d: Too many %s entries", file, ಸಾಲು, directive);

	ಆದರೆ (iarray != ಖಾಲಿ) {
		*iarray = xrecallocarray(*iarray, *lp, *lp + 1,
		    ಗಾತ್ರ(**iarray));
		(*iarray)[*lp] = i;
	}

	*array = xrecallocarray(*array, *lp, *lp + 1, ಗಾತ್ರ(**array));
	(*array)[*lp] = xstrdup(s);
	(*lp)++;
}

ಶೂನ್ಯ
opt_array_append(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *file, ಸ್ಥಿರಾಂಕ ಪೂರ್ಣಾಂಕ ಸಾಲು, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *directive,
    ಅಕ್ಷರ ***array, u_int *lp, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *s)
{
	opt_array_append2(file, ಸಾಲು, directive, array, ಖಾಲಿ, lp, s, 0);
}

ಶೂನ್ಯ
opt_array_free2(ಅಕ್ಷರ **array, ಪೂರ್ಣಾಂಕ **iarray, u_int l)
{
	u_int i;

	ಆದರೆ (array == ಖಾಲಿ || l == 0)
		ಹಿಂತಿರುಗಿ;
	ಗಾಗಿ (i = 0; i < l; i++)
		ಬಿಡುಗಡೆ(array[i]);
	ಬಿಡುಗಡೆ(array);
	ಬಿಡುಗಡೆ(iarray);
}

sshsig_t
ssh_signal(ಪೂರ್ಣಾಂಕ signum, sshsig_t handler)
{
	ರಚನೆ sigaction sa, osa;

	/* mask all other signals while in handler */
	memset(&sa, 0, ಗಾತ್ರ(sa));
	sa.sa_handler = handler;
	sigfillset(&sa.sa_mask);
#ಆದರೆ defined(SA_RESTART) && !defined(NO_SA_RESTART)
	ಆದರೆ (signum != SIGALRM)
		sa.sa_flags = SA_RESTART;
#ಆದರೆ_ಅಂತ್ಯ
	ಆದರೆ (sigaction(signum, &sa, &osa) == -1) {
		debug3("sigaction(%s): %s", strsignal(signum), strerror(errno));
		ಹಿಂತಿರುಗಿ SIG_ERR;
	}
	ಹಿಂತಿರುಗಿ osa.sa_handler;
}

ಪೂರ್ಣಾಂಕ
stdfd_devnull(ಪೂರ್ಣಾಂಕ do_stdin, ಪೂರ್ಣಾಂಕ do_stdout, ಪೂರ್ಣಾಂಕ do_stderr)
{
	ಪೂರ್ಣಾಂಕ devnull, ret = 0;

	ಆದರೆ ((devnull = open(_PATH_DEVNULL, O_RDWR)) == -1) {
		error_f("open %s: %s", _PATH_DEVNULL,
		    strerror(errno));
		ಹಿಂತಿರುಗಿ -1;
	}
	ಆದರೆ ((do_stdin && dup2(devnull, STDIN_FILENO) == -1) ||
	    (do_stdout && dup2(devnull, STDOUT_FILENO) == -1) ||
	    (do_stderr && dup2(devnull, STDERR_FILENO) == -1)) {
		error_f("dup2: %s", strerror(errno));
		ret = -1;
	}
	ಆದರೆ (devnull > STDERR_FILENO)
		close(devnull);
	ಹಿಂತಿರುಗಿ ret;
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
subprocess(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಟ್ಯಾಗ್, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *command,
    ಪೂರ್ಣಾಂಕ ac, ಅಕ್ಷರ **av, FILE **ಮಗು, u_int flags,
    ರಚನೆ passwd *pw, privdrop_fn *drop_privs, privrestore_fn *restore_privs)
{
	FILE *f = ಖಾಲಿ;
	ರಚನೆ stat st;
	ಪೂರ್ಣಾಂಕ fd, devnull, p[2], i;
	pid_t pid;
	ಅಕ್ಷರ *cp, errmsg[512];
	u_int nenv = 0;
	ಅಕ್ಷರ **env = ಖಾಲಿ;

	/* If dropping privs, then must specify user and restore function */
	ಆದರೆ (drop_privs != ಖಾಲಿ && (pw == ಖಾಲಿ || restore_privs == ಖಾಲಿ)) {
		error("%s: inconsistent arguments", ಟ್ಯಾಗ್); /* XXX fatal? */
		ಹಿಂತಿರುಗಿ 0;
	}
	ಆದರೆ (pw == ಖಾಲಿ && (pw = getpwuid(getuid())) == ಖಾಲಿ) {
		error("%s: no user for current uid", ಟ್ಯಾಗ್);
		ಹಿಂತಿರುಗಿ 0;
	}
	ಆದರೆ (ಮಗು != ಖಾಲಿ)
		*ಮಗು = ಖಾಲಿ;

	debug3_f("%s command \"%s\" running as %s (flags 0x%x)",
	    ಟ್ಯಾಗ್, command, pw->pw_name, flags);

	/* Check consistency */
	ಆದರೆ ((flags & SSH_SUBPROCESS_STDOUT_DISCARD) != 0 &&
	    (flags & SSH_SUBPROCESS_STDOUT_CAPTURE) != 0) {
		error_f("inconsistent flags");
		ಹಿಂತಿರುಗಿ 0;
	}
	ಆದರೆ (((flags & SSH_SUBPROCESS_STDOUT_CAPTURE) == 0) != (ಮಗು == ಖಾಲಿ)) {
		error_f("inconsistent flags/output");
		ಹಿಂತಿರುಗಿ 0;
	}

	/*
	 * If executing an explicit binary, then verify the it exists
	 * and appears safe-ish to execute
	 */
	ಆದರೆ (!ಮಾರ್ಗ_absolute(av[0])) {
		error("%s path is not absolute", ಟ್ಯಾಗ್);
		ಹಿಂತಿರುಗಿ 0;
	}
	ಆದರೆ (drop_privs != ಖಾಲಿ)
		drop_privs(pw);
	ಆದರೆ (stat(av[0], &st) == -1) {
		error("Could not stat %s \"%s\": %s", ಟ್ಯಾಗ್,
		    av[0], strerror(errno));
		ಹೋಗು restore_return;
	}
	ಆದರೆ ((flags & SSH_SUBPROCESS_UNSAFE_ಮಾರ್ಗ) == 0 &&
	    ಸುರಕ್ಷಿತ_ಮಾರ್ಗ(av[0], &st, ಖಾಲಿ, 0, errmsg, ಗಾತ್ರ(errmsg)) != 0) {
		error("Unsafe %s \"%s\": %s", ಟ್ಯಾಗ್, av[0], errmsg);
		ಹೋಗು restore_return;
	}
	/* Prepare to keep the child's stdout if requested */
	ಆದರೆ (pipe(p) == -1) {
		error("%s: pipe: %s", ಟ್ಯಾಗ್, strerror(errno));
 restore_return:
		ಆದರೆ (restore_privs != ಖಾಲಿ)
			restore_privs();
		ಹಿಂತಿರುಗಿ 0;
	}
	ಆದರೆ (restore_privs != ಖಾಲಿ)
		restore_privs();

	ಆಯ್ಕೆ ((pid = fork())) {
	ಸ್ಥಿತಿ -1: /* error */
		error("%s: fork: %s", ಟ್ಯಾಗ್, strerror(errno));
		close(p[0]);
		close(p[1]);
		ಹಿಂತಿರುಗಿ 0;
	ಸ್ಥಿತಿ 0: /*ಮಗು*/
		/* Prepare a minimal environment for the child. */
		ಆದರೆ ((flags & SSH_SUBPROCESS_PRESERVE_ENV) == 0) {
			nenv = 5;
			env = xcalloc(ಗಾತ್ರ(*env), nenv);
			ಮಗು_ಗಣ_env(&env, &nenv, "PATH", _PATH_STDPATH);
			ಮಗು_ಗಣ_env(&env, &nenv, "USER", pw->pw_name);
			ಮಗು_ಗಣ_env(&env, &nenv, "LOGNAME", pw->pw_name);
			ಮಗು_ಗಣ_env(&env, &nenv, "HOME", pw->pw_dir);
			ಆದರೆ ((cp = getenv("LANG")) != ಖಾಲಿ)
				ಮಗು_ಗಣ_env(&env, &nenv, "LANG", cp);
		}

		ಗಾಗಿ (i = 1; i < NSIG; i++)
			ssh_signal(i, SIG_DFL);

		ಆದರೆ ((devnull = open(_PATH_DEVNULL, O_RDWR)) == -1) {
			error("%s: open %s: %s", ಟ್ಯಾಗ್, _PATH_DEVNULL,
			    strerror(errno));
			_exit(1);
		}
		ಆದರೆ (dup2(devnull, STDIN_FILENO) == -1) {
			error("%s: dup2: %s", ಟ್ಯಾಗ್, strerror(errno));
			_exit(1);
		}

		/* Set up stdout as requested; leave stderr in place for now. */
		fd = -1;
		ಆದರೆ ((flags & SSH_SUBPROCESS_STDOUT_CAPTURE) != 0)
			fd = p[1];
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((flags & SSH_SUBPROCESS_STDOUT_DISCARD) != 0)
			fd = devnull;
		ಆದರೆ (fd != -1 && dup2(fd, STDOUT_FILENO) == -1) {
			error("%s: dup2: %s", ಟ್ಯಾಗ್, strerror(errno));
			_exit(1);
		}
		closefrom(STDERR_FILENO + 1);

		ಆದರೆ (geteuid() == 0 &&
		    initgroups(pw->pw_name, pw->pw_gid) == -1) {
			error("%s: initgroups(%s, %u): %s", ಟ್ಯಾಗ್,
			    pw->pw_name, (u_int)pw->pw_gid, strerror(errno));
			_exit(1);
		}
		ಆದರೆ (setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) == -1) {
			error("%s: setresgid %u: %s", ಟ್ಯಾಗ್, (u_int)pw->pw_gid,
			    strerror(errno));
			_exit(1);
		}
		ಆದರೆ (setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) == -1) {
			error("%s: setresuid %u: %s", ಟ್ಯಾಗ್, (u_int)pw->pw_uid,
			    strerror(errno));
			_exit(1);
		}
		/* stdin is pointed to /dev/null at this point */
		ಆದರೆ ((flags & SSH_SUBPROCESS_STDOUT_DISCARD) != 0 &&
		    dup2(STDIN_FILENO, STDERR_FILENO) == -1) {
			error("%s: dup2: %s", ಟ್ಯಾಗ್, strerror(errno));
			_exit(1);
		}
		ಆದರೆ (env != ಖಾಲಿ)
			execve(av[0], av, env);
		ಇಲ್ಲದಿದ್ದರೆ
			execv(av[0], av);
		error("%s %s \"%s\": %s", ಟ್ಯಾಗ್, env == ಖಾಲಿ ? "execv" : "execve",
		    command, strerror(errno));
		_exit(127);
	ಪೂರ್ವನಿಯೋಜಿತ: /*ಪೋಷಕ*/
		ನಿಲ್ಲಿಸು;
	}

	close(p[1]);
	ಆದರೆ ((flags & SSH_SUBPROCESS_STDOUT_CAPTURE) == 0)
		close(p[0]);
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((f = fdopen(p[0], "r")) == ಖಾಲಿ) {
		error("%s: fdopen: %s", ಟ್ಯಾಗ್, strerror(errno));
		close(p[0]);
		/* Don't leave zombie child */
		kill(pid, SIGTERM);
		ಆಗ (waitpid(pid, ಖಾಲಿ, 0) == -1 && errno == EINTR)
			;
		ಹಿಂತಿರುಗಿ 0;
	}
	/* Success */
	debug3_f("%s pid %ld", ಟ್ಯಾಗ್, (ದೀರ್ಘ)pid);
	ಆದರೆ (ಮಗು != ಖಾಲಿ)
		*ಮಗು = f;
	ಹಿಂತಿರುಗಿ pid;
}

ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *
lookup_env_ಒಳ_list(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *env, ಅಕ್ಷರ * ಸ್ಥಿರಾಂಕ *envs, ಗಾತ್ರ_t nenvs)
{
	ಗಾತ್ರ_t i, envlen;

	envlen = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(env);
	ಗಾಗಿ (i = 0; i < nenvs; i++) {
		ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಹೋಲಿಕೆ(envs[i], env, envlen) == 0 &&
		    envs[i][envlen] == '=') {
			ಹಿಂತಿರುಗಿ envs[i] + envlen + 1;
		}
	}
	ಹಿಂತಿರುಗಿ ಖಾಲಿ;
}

ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *
lookup_setenv_ಒಳ_list(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *env, ಅಕ್ಷರ * ಸ್ಥಿರಾಂಕ *envs, ಗಾತ್ರ_t nenvs)
{
	ಅಕ್ಷರ *name, *cp;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ret;

	name = xstrdup(env);
	ಆದರೆ ((cp = strchr(name, '=')) == ಖಾಲಿ) {
		ಬಿಡುಗಡೆ(name);
		ಹಿಂತಿರುಗಿ ಖಾಲಿ; /* not env=val */
	}
	*cp = '\0';
	ret = lookup_env_ಒಳ_list(name, envs, nenvs);
	ಬಿಡುಗಡೆ(name);
	ಹಿಂತಿರುಗಿ ret;
}

/*
 * Helpers for managing poll(2)/ppoll(2) timeouts
 * Will remember the earliest deadline and return it for use in poll/ppoll.
 */

/* Initialise a poll/ppoll timeout with an indefinite deadline */
ಶೂನ್ಯ
ptimeout_init(ರಚನೆ timespec *pt)
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
ptimeout_deadline_sec(ರಚನೆ timespec *pt, ದೀರ್ಘ sec)
{
	ಆದರೆ (pt->tv_sec == -1 || pt->tv_sec >= sec) {
		pt->tv_sec = sec;
		pt->tv_nsec = 0;
	}
}

/* Specify a poll/ppoll deadline of at most 'p' (timespec) */
ಸ್ಥಿರ ಶೂನ್ಯ
ptimeout_deadline_tsp(ರಚನೆ timespec *pt, ರಚನೆ timespec *p)
{
	ಆದರೆ (pt->tv_sec == -1 || timespeccmp(pt, p, >=))
		*pt = *p;
}

/* Specify a poll/ppoll deadline of at most 'ms' milliseconds */
ಶೂನ್ಯ
ptimeout_deadline_ms(ರಚನೆ timespec *pt, ದೀರ್ಘ ms)
{
	ರಚನೆ timespec p;

	p.tv_sec = ms / 1000;
	p.tv_nsec = (ms % 1000) * 1000000;
	ptimeout_deadline_tsp(pt, &p);
}

/* Specify a poll/ppoll deadline of at most 'sec' seconds (double) */
ಶೂನ್ಯ
ptimeout_deadline_sec_double(ರಚನೆ timespec *pt, ದ್ವಿಗುಣ sec)
{
	ರಚನೆ timespec t;

	memset(&t, 0, ಗಾತ್ರ(t));
	ಆದರೆ ((int64_t)sec >= SSH_ಸಮಯ_T_MAX)
		t.tv_sec = SSH_ಸಮಯ_T_MAX;
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (sec > 0) {
		t.tv_sec = sec;
		t.tv_nsec = (sec - (ದ್ವಿಗುಣ)t.tv_sec) * 1000000000.0;
	}
	ptimeout_deadline_tsp(pt, &t);
}

/* Specify a poll/ppoll deadline at wall clock monotime 'when' (timespec) */
ಶೂನ್ಯ
ptimeout_deadline_monotime_tsp(ರಚನೆ timespec *pt, ರಚನೆ timespec *when)
{
	ರಚನೆ timespec now, t;

	monotime_ts(&now);

	ಆದರೆ (timespeccmp(&now, when, >=)) {
		/* 'when' is now or in the past. Timeout ASAP */
		pt->tv_sec = 0;
		pt->tv_nsec = 0;
	} ಇಲ್ಲದಿದ್ದರೆ {
		timespecsub(when, &now, &t);
		ptimeout_deadline_tsp(pt, &t);
	}
}

/* Specify a poll/ppoll deadline at wall clock monotime 'when' (double) */
ಶೂನ್ಯ
ptimeout_deadline_monotime_double(ರಚನೆ timespec *pt, ದ್ವಿಗುಣ when)
{
	ptimeout_deadline_sec_double(pt, when - monotime_double());
}

/* Specify a poll/ppoll deadline at wall clock monotime 'when' */
ಶೂನ್ಯ
ptimeout_deadline_monotime(ರಚನೆ timespec *pt, time_t when)
{
	ರಚನೆ timespec t;

	t.tv_sec = when;
	t.tv_nsec = 0;
	ptimeout_deadline_monotime_tsp(pt, &t);
}

/* Get a poll(2) timeout value in milliseconds */
ಪೂರ್ಣಾಂಕ
ptimeout_get_ms(ರಚನೆ timespec *pt)
{
	ಆದರೆ (pt->tv_sec == -1)
		ಹಿಂತಿರುಗಿ -1;
	ಆದರೆ (pt->tv_sec >= (ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ - (pt->tv_nsec / 1000000)) / 1000)
		ಹಿಂತಿರುಗಿ ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ;
	ಹಿಂತಿರುಗಿ (pt->tv_sec * 1000) + (pt->tv_nsec / 1000000);
}

/* Get a ppoll(2) timeout value as a timespec pointer */
ರಚನೆ timespec *
ptimeout_get_tsp(ರಚನೆ timespec *pt)
{
	ಹಿಂತಿರುಗಿ pt->tv_sec == -1 ? ಖಾಲಿ : pt;
}

/* Returns non-zero if a timeout has been set (i.e. is not indefinite) */
ಪೂರ್ಣಾಂಕ
ptimeout_isset(ರಚನೆ timespec *pt)
{
	ಹಿಂತಿರುಗಿ pt->tv_sec != -1;
}

/*
 * Returns zero if the library at 'path' contains symbol 's', nonzero
 * otherwise.
 */
ಪೂರ್ಣಾಂಕ
lib_ಒಳಗೊಂಡಿದೆ_ಚಿಹ್ನೆ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *s)
{
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_NLIST
	ರಚನೆ nlist nl[2];
	ಪೂರ್ಣಾಂಕ ret = -1, r;

	memset(nl, 0, ಗಾತ್ರ(nl));
	nl[0].n_name = xstrdup(s);
	nl[1].n_name = ಖಾಲಿ;
	ಆದರೆ ((r = nlist(ಮಾರ್ಗ, nl)) == -1) {
		error_f("nlist failed for %s", ಮಾರ್ಗ);
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (r != 0 || nl[0].n_ಮೌಲ್ಯ == 0 || nl[0].n_type == 0) {
		error_f("library %s does not contain symbol %s", ಮಾರ್ಗ, s);
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/* success */
	ret = 0;
 ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(nl[0].n_name);
	ಹಿಂತಿರುಗಿ ret;
#ಇಲ್ಲದಿದ್ದರೆ /* HAVE_NLIST */
	ಪೂರ್ಣಾಂಕ fd, ret = -1;
	ರಚನೆ stat st;
	ಶೂನ್ಯ *m = ಖಾಲಿ;
	ಗಾತ್ರ_t sz = 0;

	memset(&st, 0, ಗಾತ್ರ(st));
	ಆದರೆ ((fd = open(ಮಾರ್ಗ, O_RDONLY)) < 0) {
		error_f("open %s: %s", ಮಾರ್ಗ, strerror(errno));
		ಹಿಂತಿರುಗಿ -1;
	}
	ಆದರೆ (fstat(fd, &st) != 0) {
		error_f("fstat %s: %s", ಮಾರ್ಗ, strerror(errno));
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (!S_ISREG(st.st_mode)) {
		error_f("%s is not a regular file", ಮಾರ್ಗ);
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (st.st_size < 0 ||
	    (ಗಾತ್ರ_t)st.st_size < ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(s) ||
	    st.st_size >= ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ/2) {
		error_f("%s bad size %lld", ಮಾರ್ಗ, (ದೀರ್ಘ ದೀರ್ಘ)st.st_size);
		ಹೋಗು ಹೊರಹೋಗು;
	}
	sz = (ಗಾತ್ರ_t)st.st_size;
	ಆದರೆ ((m = mmap(ಖಾಲಿ, sz, PROT_READ, MAP_PRIVATE, fd, 0)) == MAP_FAILED ||
	    m == ಖಾಲಿ) {
		error_f("mmap %s: %s", ಮಾರ್ಗ, strerror(errno));
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (memmem(m, sz, s, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(s)) == ಖಾಲಿ) {
		error_f("%s does not contain expected string %s", ಮಾರ್ಗ, s);
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/* success */
	ret = 0;
 ಹೊರಹೋಗು:
	ಆದರೆ (m != ಖಾಲಿ && m != MAP_FAILED)
		munmap(m, sz);
	close(fd);
	ಹಿಂತಿರುಗಿ ret;
#ಆದರೆ_ಅಂತ್ಯ /* HAVE_NLIST */
}

ಪೂರ್ಣಾಂಕ
signal_is_crash(ಪೂರ್ಣಾಂಕ sig)
{
	ಆಯ್ಕೆ (sig) {
	ಸ್ಥಿತಿ SIGSEGV:
	ಸ್ಥಿತಿ SIGBUS:
	ಸ್ಥಿತಿ SIGTRAP:
	ಸ್ಥಿತಿ SIGSYS:
	ಸ್ಥಿತಿ SIGFPE:
	ಸ್ಥಿತಿ SIGILL:
	ಸ್ಥಿತಿ SIGABRT:
		ಹಿಂತಿರುಗಿ 1;
	}
	ಹಿಂತಿರುಗಿ 0;
}

ಅಕ್ಷರ *
get_homedir(ಶೂನ್ಯ)
{
	ಅಕ್ಷರ *cp;
	ರಚನೆ passwd *pw;

	ಆದರೆ ((cp = getenv("HOME")) != ಖಾಲಿ && *cp != '\0')
		ಹಿಂತಿರುಗಿ xstrdup(cp);

	ಆದರೆ ((pw = getpwuid(getuid())) != ಖಾಲಿ && *pw->pw_dir != '\0')
		ಹಿಂತಿರುಗಿ xstrdup(pw->pw_dir);

	ಹಿಂತಿರುಗಿ ಖಾಲಿ;
}

ಪೂರ್ಣಾಂಕ
mkdir_ಮಾರ್ಗ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಗುರಿ, ಬಹುಲಕ_t ಬಹುಲಕ)
{
#ಆದರೆ defined(HAVE_OPENAT) && defined(O_DIRECTORY)
	ಅಕ್ಷರ *dir, *odir = ಖಾಲಿ, *ಮುಂದಿನ;
	ಪೂರ್ಣಾಂಕ fd = AT_FDCWD, fd2, subpath_len, ret = -1;

	dir = odir = xstrdup(ಗುರಿ);

	ಆದರೆ (*dir == '/' &&
	    (fd = open("/", O_RDONLY|O_DIRECTORY)) == -1) {
		error_f("open(\"/\"): %s", strerror(errno));
		ಬಿಡುಗಡೆ(odir);
		ಹಿಂತಿರುಗಿ -1;
	}
	/* Work through the path, component-wise */
	ಗಾಗಿ (; dir != ಖಾಲಿ && *dir != '\0'; dir = ಮುಂದಿನ) {
		ಆದರೆ ((ಮುಂದಿನ = strchr(dir, '/')) != ಖಾಲಿ)
			*(ಮುಂದಿನ++) = '\0';
		ಆದರೆ (*dir == '\0')
			ಮುಂದುವರಿ;
		subpath_len = (ಮುಂದಿನ == ಖಾಲಿ) ? ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ : ಮುಂದಿನ - odir - 1;
		ಆದರೆ (mkdirat(fd, dir, ಬಹುಲಕ) == 0)
			debug_f("created directory %.*s", subpath_len, ಗುರಿ);
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (errno != EEXIST) {
			error_f("mkdir(\"%.*s\"): %s",
			    subpath_len, ಗುರಿ, strerror(errno));
			ಹೋಗು ಹೊರಹೋಗು;
		}

		/* descend */
		ಆದರೆ ((fd2 = openat(fd, dir, O_RDONLY|O_DIRECTORY)) == -1) {
			error_f("open(\"%.*s\"): %s",
			    subpath_len, ಗುರಿ, strerror(errno));
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ (fd != AT_FDCWD)
			close(fd);
		fd = fd2;
	}
	/* success */
	ret = 0;
 ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(odir);
	ಆದರೆ (fd != AT_FDCWD)
		close(fd);
	ಹಿಂತಿರುಗಿ ret;
#ಇಲ್ಲದಿದ್ದರೆ
	/*
	 * If we don't have openat (which was added in POSIX.1-2008), fall back
	 * to the possibly racy way.
	 */
	ಅಕ್ಷರ *dir, *odir, *p, ಮಾರ್ಗ[PATH_MAX] = "";
	ಪೂರ್ಣಾಂಕ ret = -1;
	ಗಾತ್ರ_t plen = ಗಾತ್ರ(ಮಾರ್ಗ);

	dir = odir = xstrdup(ಗುರಿ);

	/* If the dir is relative, start with cwd. */
	ಆದರೆ (*dir != '/' && getcwd(ಮಾರ್ಗ, plen) == ಖಾಲಿ) {
		error_f("getcwd: %s", strerror(errno));
		ಹೋಗು ಹೊರಹೋಗು;
	}

	/* Work through the path, component-wise */
	ಆಗ ((p = strsep(&dir, "/"))) {
		ಆದರೆ (*p == '\0')
			ಮುಂದುವರಿ;
		ಆದರೆ (strlcat(ಮಾರ್ಗ, "/", plen) >= plen ||
		    strlcat(ಮಾರ್ಗ, p, plen) >= plen)
			ಹೋಗು ಹೊರಹೋಗು;
		ಆದರೆ (mkdir(ಮಾರ್ಗ, ಬಹುಲಕ) == 0)
			debug_f("created directory %s", ಮಾರ್ಗ);
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (errno != EEXIST && errno != EISDIR) {
			error_f("mkdir(\"%s\"): %s", ಮಾರ್ಗ, strerror(errno));
			ಹೋಗು ಹೊರಹೋಗು;
		}
	}
	/* success */
	ret = 0;
 ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(odir);
	ಹಿಂತಿರುಗಿ ret;
#ಆದರೆ_ಅಂತ್ಯ
}
