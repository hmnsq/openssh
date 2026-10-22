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


#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/ioctl.h>
#ଅନ୍ତର୍ଭାଵ <sys/mman.h>
#ଅନ୍ତର୍ଭାଵ <sys/socket.h>
#ଅନ୍ତର୍ଭାଵ <sys/stat.h>
#ଅନ୍ତର୍ଭାଵ <sys/time.h>
#ଅନ୍ତର୍ଭାଵ <sys/wait.h>
#ଅନ୍ତର୍ଭାଵ <sys/un.h>

#ଅନ୍ତର୍ଭାଵ <limits.h>
#ଅନ୍ତର୍ଭାଵ <libgen.h>
#ଅନ୍ତର୍ଭାଵ <poll.h>
#ଅନ୍ତର୍ଭାଵ <nlist.h>
#ଅନ୍ତର୍ଭାଵ <signal.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdint.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <time.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>

#ଅନ୍ତର୍ଭାଵ <netinet/in.h>
#ଅନ୍ତର୍ଭାଵ <netinet/ip.h>
#ଅନ୍ତର୍ଭାଵ <netinet/tcp.h>
#ଅନ୍ତର୍ଭାଵ <arpa/inet.h>

#ଅନ୍ତର୍ଭାଵ <ctype.h>
#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <fcntl.h>
#ଅନ୍ତର୍ଭାଵ <netdb.h>
#ଅନ୍ତର୍ଭାଵ <paths.h>
#ଅନ୍ତର୍ଭାଵ <pwd.h>
#ଅନ୍ତର୍ଭାଵ <grp.h>
#ifdef SSH_TUN_OPENBSD
#ଅନ୍ତର୍ଭାଵ <net/if.h>
#endif

#ଅନ୍ତର୍ଭାଵ "xmalloc.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"
#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "ssh.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#ଅନ୍ତର୍ଭାଵ "platform.h"

/* remove newline at end of string */
ଅକ୍ଷର *
chop(ଅକ୍ଷର *s)
{
	ଅକ୍ଷର *t = s;
	ଯେତେବେଳେ (*t) {
		ଯଦି (*t == '\n' || *t == '\r') {
			*t = '\0';
			ଫେରନ୍ତୁ s;
		}
		t++;
	}
	ଫେରନ୍ତୁ s;

}

/* remove whitespace from end of string */
ଶୂନ୍ୟ
rtrim(ଅକ୍ଷର *s)
{
	size_t i;

	ଯଦି ((i = strlen(s)) == 0)
		ଫେରନ୍ତୁ;
	କର {
		i--;
		ଯଦି (isspace((unsigned ଅକ୍ଷର)s[i]))
			s[i] = '\0';
		ଅନ୍ୟଥା
			ଭାଙ୍ଗ;
	} ଯେତେବେଳେ (i > 0);
}

/*
 * returns pointer to character after 'prefix' in 's' or otherwise NULL
 * if the prefix is not present.
 */
ଅଚଳ ଅକ୍ଷର *
strprefix(ଅଚଳ ଅକ୍ଷର *s, ଅଚଳ ଅକ୍ଷର *prefix, ପୂର୍ଣ୍ଣସଂଖ୍ୟା ignorecase)
{
	size_t prefixlen;

	ଯଦି ((prefixlen = strlen(prefix)) == 0)
		ଫେରନ୍ତୁ s;
	ଯଦି (ignorecase) {
		ଯଦି (strncasecmp(s, prefix, prefixlen) != 0)
			ଫେରନ୍ତୁ ଖାଲି;
	} ଅନ୍ୟଥା {
		ଯଦି (strncmp(s, prefix, prefixlen) != 0)
			ଫେରନ୍ତୁ ଖାଲି;
	}
	ଫେରନ୍ତୁ s + prefixlen;
}

/* Append string 's' to a NULL-terminated array of strings */
ଶୂନ୍ୟ
stringlist_append(ଅକ୍ଷର ***listp, ଅଚଳ ଅକ୍ଷର *s)
{
	size_t i = 0;

	ଯଦି (*listp == ଖାଲି)
		*listp = xcalloc(2, ଆକାର(**listp));
	ଅନ୍ୟଥା {
		ପାଇଁ (i = 0; (*listp)[i] != ଖାଲି; i++)
			; /* count */
		*listp = xrecallocarray(*listp, i + 1, i + 2, ଆକାର(**listp));
	}
	(*listp)[i] = xstrdup(s);
}

ଶୂନ୍ୟ
stringlist_free(ଅକ୍ଷର **list)
{
	size_t i = 0;

	ଯଦି (list == ଖାଲି)
		ଫେରନ୍ତୁ;
	ପାଇଁ (i = 0; list[i] != ଖାଲି; i++)
		ମୁକ୍ତ(list[i]);
	ମୁକ୍ତ(list);
}

/* set/unset filedescriptor to non-blocking */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
set_nonblock(ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା val;

	val = fcntl(fd, F_GETFL);
	ଯଦି (val == -1) {
		error("fcntl(%d, F_GETFL): %s", fd, strerror(errno));
		ଫେରନ୍ତୁ (-1);
	}
	ଯଦି (val & O_NONBLOCK) {
		debug3("fd %d is O_NONBLOCK", fd);
		ଫେରନ୍ତୁ (0);
	}
	debug2("fd %d setting O_NONBLOCK", fd);
	val |= O_NONBLOCK;
	ଯଦି (fcntl(fd, F_SETFL, val) == -1) {
		debug("fcntl(%d, F_SETFL, O_NONBLOCK): %s", fd,
		    strerror(errno));
		ଫେରନ୍ତୁ (-1);
	}
	ଫେରନ୍ତୁ (0);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
unset_nonblock(ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା val;

	val = fcntl(fd, F_GETFL);
	ଯଦି (val == -1) {
		error("fcntl(%d, F_GETFL): %s", fd, strerror(errno));
		ଫେରନ୍ତୁ (-1);
	}
	ଯଦି (!(val & O_NONBLOCK)) {
		debug3("fd %d is not O_NONBLOCK", fd);
		ଫେରନ୍ତୁ (0);
	}
	debug("fd %d clearing O_NONBLOCK", fd);
	val &= ~O_NONBLOCK;
	ଯଦି (fcntl(fd, F_SETFL, val) == -1) {
		debug("fcntl(%d, F_SETFL, ~O_NONBLOCK): %s",
		    fd, strerror(errno));
		ଫେରନ୍ତୁ (-1);
	}
	ଫେରନ୍ତୁ (0);
}

ଅଚଳ ଅକ୍ଷର *
ssh_gai_strerror(ପୂର୍ଣ୍ଣସଂଖ୍ୟା gaierr)
{
	ଯଦି (gaierr == EAI_SYSTEM && errno != 0)
		ଫେରନ୍ତୁ strerror(errno);
	ଫେରନ୍ତୁ gai_strerror(gaierr);
}

/* disable nagle on socket */
ଶୂନ୍ୟ
set_nodelay(ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା opt;
	socklen_t optlen;

	optlen = ଆକାର opt;
	ଯଦି (getsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, &optlen) == -1) {
		debug("getsockopt TCP_NODELAY: %.100s", strerror(errno));
		ଫେରନ୍ତୁ;
	}
	ଯଦି (opt == 1) {
		debug2("fd %d is TCP_NODELAY", fd);
		ଫେରନ୍ତୁ;
	}
	opt = 1;
	debug2("fd %d setting TCP_NODELAY", fd);
	ଯଦି (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, ଆକାର opt) == -1)
		error("setsockopt TCP_NODELAY: %.100s", strerror(errno));
}

/* Allow local port reuse in TIME_WAIT */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
set_reuseaddr(ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା on = 1;

	ଯଦି (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, ଆକାର(on)) == -1) {
		error("setsockopt SO_REUSEADDR fd %d: %s", fd, strerror(errno));
		ଫେରନ୍ତୁ -1;
	}
	ଫେରନ୍ତୁ 0;
}

/* Set TCP keepalives */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
set_keepalive(ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା on = 1;

	ଯଦି (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, ଆକାର(on)) == -1) {
		error("setsockopt SO_KEEPALIVE fd %d: %s", fd, strerror(errno));
		ଫେରନ୍ତୁ -1;
	}
	ଫେରନ୍ତୁ 0;
}

/* Get/set routing domain */
ଅକ୍ଷର *
get_rdomain(ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd)
{
#ଯଦି defined(HAVE_SYS_GET_RDOMAIN)
	ଫେରନ୍ତୁ sys_get_rdomain(fd);
#ନଚେତଯଦି defined(__OpenBSD__)
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା rtable;
	ଅକ୍ଷର *ret;
	socklen_t len = ଆକାର(rtable);

	ଯଦି (getsockopt(fd, SOL_SOCKET, SO_RTABLE, &rtable, &len) == -1) {
		error("Failed to get routing domain for fd %d: %s",
		    fd, strerror(errno));
		ଫେରନ୍ତୁ ଖାଲି;
	}
	xasprintf(&ret, "%d", rtable);
	ଫେରନ୍ତୁ ret;
#ଅନ୍ୟଥା /* defined(__OpenBSD__) */
	ଫେରନ୍ତୁ ଖାଲି;
#endif
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
set_rdomain(ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd, ଅଚଳ ଅକ୍ଷର *name)
{
#ଯଦି defined(HAVE_SYS_SET_RDOMAIN)
	ଫେରନ୍ତୁ sys_set_rdomain(fd, name);
#ନଚେତଯଦି defined(__OpenBSD__)
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା rtable;
	ଅଚଳ ଅକ୍ଷର *errstr;

	ଯଦି (name == ଖାଲି)
		ଫେରନ୍ତୁ 0; /* default table */

	rtable = (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)strtonum(name, 0, 255, &errstr);
	ଯଦି (errstr != ଖାଲି) {
		/* Shouldn't happen */
		error("Invalid routing domain \"%s\": %s", name, errstr);
		ଫେରନ୍ତୁ -1;
	}
	ଯଦି (setsockopt(fd, SOL_SOCKET, SO_RTABLE,
	    &rtable, ଆକାର(rtable)) == -1) {
		error("Failed to set routing domain %d on fd %d: %s",
		    rtable, fd, strerror(errno));
		ଫେରନ୍ତୁ -1;
	}
	ଫେରନ୍ତୁ 0;
#ଅନ୍ୟଥା /* defined(__OpenBSD__) */
	error("Setting routing domain is not supported on this platform");
	ଫେରନ୍ତୁ -1;
#endif
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
get_sock_af(ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd)
{
	ସଂରଚନା sockaddr_storage to;
	socklen_t tolen = ଆକାର(to);

	memset(&to, 0, ଆକାର(to));
	ଯଦି (getsockname(fd, (ସଂରଚନା sockaddr *)&to, &tolen) == -1)
		ଫେରନ୍ତୁ -1;
#ifdef IPV4_IN_IPV6
	ଯଦି (to.ss_family == AF_INET6 &&
	    IN6_IS_ADDR_V4MAPPED(&((ସଂରଚନା sockaddr_in6 *)&to)->sin6_addr))
		ଫେରନ୍ତୁ AF_INET;
#endif
	ଫେରନ୍ତୁ to.ss_family;
}

ଶୂନ୍ୟ
set_sock_tos(ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd, ପୂର୍ଣ୍ଣସଂଖ୍ୟା tos)
{
#ifndef IP_TOS_IS_BROKEN
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା af;

	ଯଦି (tos < 0 || tos == INT_MAX) {
		debug_f("invalid TOS %d", tos);
		ଫେରନ୍ତୁ;
	}
	ବାଛ ((af = get_sock_af(fd))) {
	ସ୍ଥିତି -1:
		/* assume not a socket */
		ଭାଙ୍ଗ;
	ସ୍ଥିତି AF_INET:
# ifdef IP_TOS
		debug3_f("set socket %d IP_TOS 0x%02x", fd, tos);
		ଯଦି (setsockopt(fd, IPPROTO_IP, IP_TOS,
		    &tos, ଆକାର(tos)) == -1) {
			error("setsockopt socket %d IP_TOS %d: %s",
			    fd, tos, strerror(errno));
		}
# endif /* IP_TOS */
		ଭାଙ୍ଗ;
	ସ୍ଥିତି AF_INET6:
# ifdef IPV6_TCLASS
		debug3_f("set socket %d IPV6_TCLASS 0x%02x", fd, tos);
		ଯଦି (setsockopt(fd, IPPROTO_IPV6, IPV6_TCLASS,
		    &tos, ଆକାର(tos)) == -1) {
			error("setsockopt socket %d IPV6_TCLASS %d: %s",
			    fd, tos, strerror(errno));
		}
# endif /* IPV6_TCLASS */
		ଭାଙ୍ଗ;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		debug2_f("unsupported socket family %d", af);
		ଭାଙ୍ଗ;
	}
#endif /* IP_TOS_IS_BROKEN */
}

/*
 * Wait up to *timeoutp milliseconds for events on fd. Updates
 * *timeoutp with time remaining.
 * Returns 0 if fd ready or -1 on timeout or error (see errno).
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
waitfd(ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *timeoutp, short events, ଅସ୍ଥିର sig_atomic_t *stop)
{
	ସଂରଚନା pollfd pfd;
	ସଂରଚନା timespec timeout;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା oerrno, r;
	sigset_t nsigset, osigset;

	ଯଦି (timeoutp && *timeoutp == -1)
		timeoutp = ଖାଲି;
	pfd.fd = fd;
	pfd.events = events;
	ptimeout_init(&timeout);
	ଯଦି (timeoutp != ଖାଲି)
		ptimeout_deadline_ms(&timeout, *timeoutp);
	ଯଦି (stop != ଖାଲି)
		sigfillset(&nsigset);
	ପାଇଁ (; timeoutp == ଖାଲି || *timeoutp >= 0;) {
		ଯଦି (stop != ଖାଲି) {
			sigprocmask(SIG_BLOCK, &nsigset, &osigset);
			ଯଦି (*stop) {
				sigprocmask(SIG_SETMASK, &osigset, ଖାଲି);
				errno = EINTR;
				ଫେରନ୍ତୁ -1;
			}
		}
		r = ppoll(&pfd, 1, ptimeout_get_tsp(&timeout),
		    stop != ଖାଲି ? &osigset : ଖାଲି);
		oerrno = errno;
		ଯଦି (stop != ଖାଲି)
			sigprocmask(SIG_SETMASK, &osigset, ଖାଲି);
		ଯଦି (timeoutp)
			*timeoutp = ptimeout_get_ms(&timeout);
		errno = oerrno;
		ଯଦି (r > 0)
			ଫେରନ୍ତୁ 0;
		ଅନ୍ୟଥା ଯଦି (r == -1 && errno != EAGAIN && errno != EINTR)
			ଫେରନ୍ତୁ -1;
		ଅନ୍ୟଥା ଯଦି (r == 0)
			ଭାଙ୍ଗ;
	}
	/* timeout */
	errno = ETIMEDOUT;
	ଫେରନ୍ତୁ -1;
}

/*
 * Wait up to *timeoutp milliseconds for fd to be readable. Updates
 * *timeoutp with time remaining.
 * Returns 0 if fd ready or -1 on timeout or error (see errno).
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
waitrfd(ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *timeoutp, ଅସ୍ଥିର sig_atomic_t *stop) {
	ଫେରନ୍ତୁ waitfd(fd, timeoutp, POLLIN, stop);
}

/*
 * Attempt a non-blocking connect(2) to the specified address, waiting up to
 * *timeoutp milliseconds for the connection to complete. If the timeout is
 * <=0, then wait indefinitely.
 *
 * Returns 0 on success or -1 on failure.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
timeout_connect(ପୂର୍ଣ୍ଣସଂଖ୍ୟା sockfd, ଅଚଳ ସଂରଚନା sockaddr *serv_addr,
    socklen_t addrlen, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *timeoutp)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା optval = 0;
	socklen_t optlen = ଆକାର(optval);

	/* No timeout: just do a blocking connect() */
	ଯଦି (timeoutp == ଖାଲି || *timeoutp <= 0)
		ଫେରନ୍ତୁ connect(sockfd, serv_addr, addrlen);

	set_nonblock(sockfd);
	ପାଇଁ (;;) {
		ଯଦି (connect(sockfd, serv_addr, addrlen) == 0) {
			/* Succeeded already? */
			unset_nonblock(sockfd);
			ଫେରନ୍ତୁ 0;
		} ଅନ୍ୟଥା ଯଦି (errno == EINTR)
			ଜାରି;
		ଅନ୍ୟଥା ଯଦି (errno != EINPROGRESS)
			ଫେରନ୍ତୁ -1;
		ଭାଙ୍ଗ;
	}

	ଯଦି (waitfd(sockfd, timeoutp, POLLIN | POLLOUT, ଖାଲି) == -1)
		ଫେରନ୍ତୁ -1;

	/* Completed or failed */
	ଯଦି (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &optval, &optlen) == -1) {
		debug("getsockopt: %s", strerror(errno));
		ଫେରନ୍ତୁ -1;
	}
	ଯଦି (optval != 0) {
		errno = optval;
		ଫେରନ୍ତୁ -1;
	}
	unset_nonblock(sockfd);
	ଫେରନ୍ତୁ 0;
}

/* Characters considered whitespace in strsep calls. */
#define WHITESPACE " \t\r\n"
#define QUOTE	"\""

/* return next token in configuration line */
ସ୍ଥିର ଅକ୍ଷର *
strdelim_internal(ଅକ୍ଷର **s, ପୂର୍ଣ୍ଣସଂଖ୍ୟା split_equals)
{
	ଅକ୍ଷର *old;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା wspace = 0;

	ଯଦି (*s == ଖାଲି)
		ଫେରନ୍ତୁ ଖାଲି;

	old = *s;

	*s = strpbrk(*s,
	    split_equals ? WHITESPACE QUOTE "=" : WHITESPACE QUOTE);
	ଯଦି (*s == ଖାଲି)
		ଫେରନ୍ତୁ (old);

	ଯଦି (*s[0] == '\"') {
		memmove(*s, *s + 1, strlen(*s)); /* move nul too */
		/* Find matching quote */
		ଯଦି ((*s = strpbrk(*s, QUOTE)) == ଖାଲି) {
			ଫେରନ୍ତୁ (ଖାଲି);		/* no matching quote */
		} ଅନ୍ୟଥା {
			*s[0] = '\0';
			*s += strspn(*s + 1, WHITESPACE) + 1;
			ଫେରନ୍ତୁ (old);
		}
	}

	/* Allow only one '=' to be skipped */
	ଯଦି (split_equals && *s[0] == '=')
		wspace = 1;
	*s[0] = '\0';

	/* Skip any extra whitespace after first token */
	*s += strspn(*s + 1, WHITESPACE) + 1;
	ଯଦି (split_equals && *s[0] == '=' && !wspace)
		*s += strspn(*s + 1, WHITESPACE) + 1;

	ଫେରନ୍ତୁ (old);
}

/*
 * Return next token in configuration line; splits on whitespace or a
 * single '=' character.
 */
ଅକ୍ଷର *
strdelim(ଅକ୍ଷର **s)
{
	ଫେରନ୍ତୁ strdelim_internal(s, 1);
}

/*
 * Return next token in configuration line; splits on whitespace only.
 */
ଅକ୍ଷର *
strdelimw(ଅକ୍ଷର **s)
{
	ଫେରନ୍ତୁ strdelim_internal(s, 0);
}

ସଂରଚନା passwd *
pwcopy(ସଂରଚନା passwd *pw)
{
	ସଂରଚନା passwd *copy = xcalloc(1, ଆକାର(*copy));

	copy->pw_name = xstrdup(pw->pw_name);
	copy->pw_passwd = xstrdup(pw->pw_passwd == ଖାଲି ? "*" : pw->pw_passwd);
#ifdef HAVE_STRUCT_PASSWD_PW_GECOS
	copy->pw_gecos = xstrdup(pw->pw_gecos == ଖାଲି ? "" : pw->pw_gecos);
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
	copy->pw_class = xstrdup(pw->pw_class == ଖାଲି ? "" : pw->pw_class);
#endif
	copy->pw_dir = xstrdup(pw->pw_dir == ଖାଲି ? "" : pw->pw_dir);
	copy->pw_shell = xstrdup(pw->pw_shell == ଖାଲି ? "" : pw->pw_shell);
	ଫେରନ୍ତୁ copy;
}

ଶୂନ୍ୟ
pwfree(ସଂରଚନା passwd *pw)
{
	ଯଦି (pw == ଖାଲି)
		ଫେରନ୍ତୁ;
	ମୁକ୍ତ(pw->pw_name);
	freezero(pw->pw_passwd,
	    pw->pw_passwd == ଖାଲି ? 0 : strlen(pw->pw_passwd));
#ifdef HAVE_STRUCT_PASSWD_PW_GECOS
	ମୁକ୍ତ(pw->pw_gecos);
#endif
#ifdef HAVE_STRUCT_PASSWD_PW_CLASS
	ମୁକ୍ତ(pw->pw_class);
#endif
	ମୁକ୍ତ(pw->pw_dir);
	ମୁକ୍ତ(pw->pw_shell);
	freezero(pw, ଆକାର(*pw));
}

/*
 * Convert ASCII string to TCP/IP port number.
 * Port must be >=0 and <=65535.
 * Return -1 if invalid.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
a2port(ଅଚଳ ଅକ୍ଷର *s)
{
	ସଂରଚନା servent *se;
	long long port;
	ଅଚଳ ଅକ୍ଷର *errstr;

	port = strtonum(s, 0, 65535, &errstr);
	ଯଦି (errstr == ଖାଲି)
		ଫେରନ୍ତୁ (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)port;
	ଯଦି ((se = getservbyname(s, "tcp")) != ଖାଲି)
		ଫେରନ୍ତୁ ntohs(se->s_port);
	ଫେରନ୍ତୁ -1;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
a2tun(ଅଚଳ ଅକ୍ଷର *s, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *remote)
{
	ଅଚଳ ଅକ୍ଷର *errstr = ଖାଲି;
	ଅକ୍ଷର *sp, *ep;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା tun;

	ଯଦି (remote != ଖାଲି) {
		*remote = SSH_TUNID_ANY;
		sp = xstrdup(s);
		ଯଦି ((ep = strchr(sp, ':')) == ଖାଲି) {
			ମୁକ୍ତ(sp);
			ଫେରନ୍ତୁ (a2tun(s, ଖାଲି));
		}
		ep[0] = '\0'; ep++;
		*remote = a2tun(ep, ଖାଲି);
		tun = a2tun(sp, ଖାଲି);
		ମୁକ୍ତ(sp);
		ଫେରନ୍ତୁ (*remote == SSH_TUNID_ERR ? *remote : tun);
	}

	ଯଦି (strcasecmp(s, "any") == 0)
		ଫେରନ୍ତୁ (SSH_TUNID_ANY);

	tun = strtonum(s, 0, SSH_TUNID_MAX, &errstr);
	ଯଦି (errstr != ଖାଲି)
		ଫେରନ୍ତୁ (SSH_TUNID_ERR);

	ଫେରନ୍ତୁ (tun);
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
ଦ୍ୱିଗୁଣ
convtime_double(ଅଚଳ ଅକ୍ଷର *s)
{
	ଦ୍ୱିଗୁଣ val, total_sec = 0.0, multiplier;
	ଅଚଳ ଅକ୍ଷର *p, *start_p;
	ଅକ୍ଷର *endp;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା seen_seconds = 0;

	ଯଦି (s == ଖାଲି || *s == '\0')
		ଫେରନ୍ତୁ -1.0;

	ପାଇଁ (p = s; *p != '\0';) {
		ଯଦି (!isdigit((unsigned ଅକ୍ଷର)*p) && *p != '.')
			ଫେରନ୍ତୁ -1.0;

		errno = 0;
		ଯଦି ((val = strtod(p, &endp)) < 0 || errno != 0 || p == endp)
			ଫେରନ୍ତୁ -1.0;
		/* Allow only decimal forms */
		ଯଦି (p + strspn(p, "0123456789.") != endp)
			ଫେରନ୍ତୁ -1.0;
		start_p = p;
		p = endp;

		ବାଛ (*p) {
		ସ୍ଥିତି '\0':
			/* FALLTHROUGH */
		ସ୍ଥିତି 's':
		ସ୍ଥିତି 'S':
			ଯଦି (seen_seconds++)
				ଫେରନ୍ତୁ -1.0;
			multiplier = SECONDS;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'm':
		ସ୍ଥିତି 'M':
			multiplier = MINUTES;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'h':
		ସ୍ଥିତି 'H':
			multiplier = HOURS;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'd':
		ସ୍ଥିତି 'D':
			multiplier = DAYS;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'w':
		ସ୍ଥିତି 'W':
			multiplier = WEEKS;
			ଭାଙ୍ଗ;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			ଫେରନ୍ତୁ -1.0;
		}

		/* Special handling if this was a decimal */
		ଯଦି (memchr(start_p, '.', endp - start_p) != ଖାଲି) {
			/* Decimal point present */
			ଯଦି (multiplier > 1.0)
				ଫେରନ୍ତୁ -1.0; /* No fractionals for non-seconds */
			/* For seconds, ensure digits follow */
			ଯଦି (!isdigit((unsigned ଅକ୍ଷର)*(endp - 1)))
				ଫେରନ୍ତୁ -1.0;
		}

		total_sec += val * multiplier;

		ଯଦି (*p != '\0')
			p++;
	}
	ଫେରନ୍ତୁ total_sec;
}

/*
 * Same as convtime_double() above but fractional seconds are ignored.
 * Return -1 if time string is invalid.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
convtime(ଅଚଳ ଅକ୍ଷର *s)
{
	ଦ୍ୱିଗୁଣ sec_val;

	ଯଦି ((sec_val = convtime_double(s)) < 0.0)
		ଫେରନ୍ତୁ -1;

	/* Check for overflow into int */
	ଯଦି (sec_val < 0 || sec_val > INT_MAX)
		ଫେରନ୍ତୁ -1;

	ଫେରନ୍ତୁ (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)sec_val;
}

#define TF_BUFS	8
#define TF_LEN	9

ଅଚଳ ଅକ୍ଷର *
fmt_timeframe(time_t t)
{
	ଅକ୍ଷର		*buf;
	ସ୍ଥିର ଅକ୍ଷର	 tfbuf[TF_BUFS][TF_LEN];	/* ring buffer */
	ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 idx = 0;
	unsigned ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 sec, min, hrs, day;
	unsigned long long	week;

	buf = tfbuf[idx++];
	ଯଦି (idx == TF_BUFS)
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

	ଯଦି (week > 0)
		snprintf(buf, TF_LEN, "%02lluw%01ud%02uh", week, day, hrs);
	ଅନ୍ୟଥା ଯଦି (day > 0)
		snprintf(buf, TF_LEN, "%01ud%02uh%02um", day, hrs, min);
	ଅନ୍ୟଥା
		snprintf(buf, TF_LEN, "%02u:%02u:%02u", hrs, min, sec);

	ଫେରନ୍ତୁ (buf);
}

/*
 * Returns a standardized host+port identifier string.
 * Caller must free returned string.
 */
ଅକ୍ଷର *
put_host_port(ଅଚଳ ଅକ୍ଷର *host, u_short port)
{
	ଅକ୍ଷର *hoststr;

	ଯଦି (port == 0 || port == SSH_DEFAULT_PORT)
		ଫେରନ୍ତୁ(xstrdup(host));
	ଯଦି (asprintf(&hoststr, "[%s]:%d", host, (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)port) == -1)
		fatal("put_host_port: asprintf: %s", strerror(errno));
	debug3("put_host_port: %s", hoststr);
	ଫେରନ୍ତୁ hoststr;
}

/*
 * Search for next delimiter between hostnames/addresses and ports.
 * Argument may be modified (for termination).
 * Returns *cp if parsing succeeds.
 * *cp is set to the start of the next field, if one was found.
 * The delimiter char, if present, is stored in delim.
 * If this is the last field, *cp is set to NULL.
 */
ଅକ୍ଷର *
hpdelim2(ଅକ୍ଷର **cp, ଅକ୍ଷର *delim)
{
	ଅକ୍ଷର *s, *old;

	ଯଦି (cp == ଖାଲି || *cp == ଖାଲି)
		ଫେରନ୍ତୁ ଖାଲି;

	old = s = *cp;
	ଯଦି (*s == '[') {
		ଯଦି ((s = strchr(s, ']')) == ଖାଲି)
			ଫେରନ୍ତୁ ଖାଲି;
		ଅନ୍ୟଥା
			s++;
	} ଅନ୍ୟଥା ଯଦି ((s = strpbrk(s, ":/")) == ଖାଲି)
		s = *cp + strlen(*cp); /* skip to end (see first case below) */

	ବାଛ (*s) {
	ସ୍ଥିତି '\0':
		*cp = ଖାଲି;	/* no more fields*/
		ଭାଙ୍ଗ;

	ସ୍ଥିତି ':':
	ସ୍ଥିତି '/':
		ଯଦି (delim != ଖାଲି)
			*delim = *s;
		*s = '\0';	/* terminate */
		*cp = s + 1;
		ଭାଙ୍ଗ;

	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		ଫେରନ୍ତୁ ଖାଲି;
	}

	ଫେରନ୍ତୁ old;
}

/* The common case: only accept colon as delimiter. */
ଅକ୍ଷର *
hpdelim(ଅକ୍ଷର **cp)
{
	ଅକ୍ଷର *r, delim = '\0';

	r =  hpdelim2(cp, &delim);
	ଯଦି (delim == '/')
		ଫେରନ୍ତୁ ଖାଲି;
	ଫେରନ୍ତୁ r;
}

ଅକ୍ଷର *
cleanhostname(ଅକ୍ଷର *host)
{
	ଯଦି (*host == '[' && host[strlen(host) - 1] == ']') {
		host[strlen(host) - 1] = '\0';
		ଫେରନ୍ତୁ (host + 1);
	} ଅନ୍ୟଥା
		ଫେରନ୍ତୁ host;
}

ଅକ୍ଷର *
colon(ଅକ୍ଷର *cp)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା flag = 0;

	ଯଦି (*cp == ':')		/* Leading colon is part of file name. */
		ଫେରନ୍ତୁ ଖାଲି;
	ଯଦି (*cp == '[')
		flag = 1;

	ପାଇଁ (; *cp; ++cp) {
		ଯଦି (*cp == '@' && *(cp+1) == '[')
			flag = 1;
		ଯଦି (*cp == ']' && *(cp+1) == ':' && flag)
			ଫେରନ୍ତୁ (cp+1);
		ଯଦି (*cp == ':' && !flag)
			ଫେରନ୍ତୁ (cp);
		ଯଦି (*cp == '/')
			ଫେରନ୍ତୁ ଖାଲି;
	}
	ଫେରନ୍ତୁ ଖାଲି;
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
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
parse_user_host_path(ଅଚଳ ଅକ୍ଷର *s, ଅକ୍ଷର **userp, ଅକ୍ଷର **hostp, ଅକ୍ଷର **pathp)
{
	ଅକ୍ଷର *user = ଖାଲି, *host = ଖାଲି, *path = ଖାଲି;
	ଅକ୍ଷର *sdup, *tmp;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret = -1;

	ଯଦି (userp != ଖାଲି)
		*userp = ଖାଲି;
	ଯଦି (hostp != ଖାଲି)
		*hostp = ଖାଲି;
	ଯଦି (pathp != ଖାଲି)
		*pathp = ଖାଲି;

	sdup = xstrdup(s);

	/* Check for remote syntax: [user@]host:[path] */
	ଯଦି ((tmp = colon(sdup)) == ଖାଲି)
		ଯାଅ out;

	/* Extract optional path */
	*tmp++ = '\0';
	ଯଦି (*tmp == '\0')
		tmp = ".";
	path = xstrdup(tmp);

	/* Extract optional user and mandatory host */
	tmp = strrchr(sdup, '@');
	ଯଦି (tmp != ଖାଲି) {
		*tmp++ = '\0';
		host = xstrdup(cleanhostname(tmp));
		ଯଦି (*sdup != '\0')
			user = xstrdup(sdup);
	} ଅନ୍ୟଥା {
		host = xstrdup(cleanhostname(sdup));
		user = ଖାଲି;
	}

	/* Success */
	ଯଦି (userp != ଖାଲି) {
		*userp = user;
		user = ଖାଲି;
	}
	ଯଦି (hostp != ଖାଲି) {
		*hostp = host;
		host = ଖାଲି;
	}
	ଯଦି (pathp != ଖାଲି) {
		*pathp = path;
		path = ଖାଲି;
	}
	ret = 0;
out:
	ମୁକ୍ତ(sdup);
	ମୁକ୍ତ(user);
	ମୁକ୍ତ(host);
	ମୁକ୍ତ(path);
	ଫେରନ୍ତୁ ret;
}

/*
 * Parse a [user@]host[:port] string.
 * Caller must free returned user and host.
 * Any of the pointer return arguments may be NULL (useful for syntax checking).
 * If user was not specified then *userp will be set to NULL.
 * If port was not specified then *portp will be -1.
 * Returns 0 on success, -1 on failure.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
parse_user_host_port(ଅଚଳ ଅକ୍ଷର *s, ଅକ୍ଷର **userp, ଅକ୍ଷର **hostp, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *portp)
{
	ଅକ୍ଷର *sdup, *cp, *tmp;
	ଅକ୍ଷର *user = ଖାଲି, *host = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା port = -1, ret = -1;

	ଯଦି (userp != ଖାଲି)
		*userp = ଖାଲି;
	ଯଦି (hostp != ଖାଲି)
		*hostp = ଖାଲି;
	ଯଦି (portp != ଖାଲି)
		*portp = -1;

	ଯଦି ((sdup = tmp = strdup(s)) == ଖାଲି)
		ଫେରନ୍ତୁ -1;
	/* Extract optional username */
	ଯଦି ((cp = strrchr(tmp, '@')) != ଖାଲି) {
		*cp = '\0';
		ଯଦି (*tmp == '\0')
			ଯାଅ out;
		ଯଦି ((user = strdup(tmp)) == ଖାଲି)
			ଯାଅ out;
		tmp = cp + 1;
	}
	/* Extract mandatory hostname */
	ଯଦି ((cp = hpdelim(&tmp)) == ଖାଲି || *cp == '\0')
		ଯାଅ out;
	host = xstrdup(cleanhostname(cp));
	/* Convert and verify optional port */
	ଯଦି (tmp != ଖାଲି && *tmp != '\0') {
		ଯଦି ((port = a2port(tmp)) <= 0)
			ଯାଅ out;
	}
	/* Success */
	ଯଦି (userp != ଖାଲି) {
		*userp = user;
		user = ଖାଲି;
	}
	ଯଦି (hostp != ଖାଲି) {
		*hostp = host;
		host = ଖାଲି;
	}
	ଯଦି (portp != ଖାଲି)
		*portp = port;
	ret = 0;
 out:
	ମୁକ୍ତ(sdup);
	ମୁକ୍ତ(user);
	ମୁକ୍ତ(host);
	ଫେରନ୍ତୁ ret;
}

/*
 * Converts a two-byte hex string to decimal.
 * Returns the decimal value or -1 for invalid input.
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
hexchar(ଅଚଳ ଅକ୍ଷର *s)
{
	unsigned ଅକ୍ଷର result[2];
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;

	ପାଇଁ (i = 0; i < 2; i++) {
		ଯଦି (s[i] >= '0' && s[i] <= '9')
			result[i] = (unsigned ଅକ୍ଷର)(s[i] - '0');
		ଅନ୍ୟଥା ଯଦି (s[i] >= 'a' && s[i] <= 'f')
			result[i] = (unsigned ଅକ୍ଷର)(s[i] - 'a') + 10;
		ଅନ୍ୟଥା ଯଦି (s[i] >= 'A' && s[i] <= 'F')
			result[i] = (unsigned ଅକ୍ଷର)(s[i] - 'A') + 10;
		ଅନ୍ୟଥା
			ଫେରନ୍ତୁ -1;
	}
	ଫେରନ୍ତୁ (result[0] << 4) | result[1];
}

/*
 * Decode an url-encoded string.
 * Returns a newly allocated string on success or NULL on failure.
 */
ସ୍ଥିର ଅକ୍ଷର *
urldecode(ଅଚଳ ଅକ୍ଷର *src)
{
	ଅକ୍ଷର *ret, *dst;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ch;
	size_t srclen;

	ଯଦି ((srclen = strlen(src)) >= SIZE_MAX)
		ଫେରନ୍ତୁ ଖାଲି;
	ret = xmalloc(srclen + 1);
	ପାଇଁ (dst = ret; *src != '\0'; src++) {
		ବାଛ (*src) {
		ସ୍ଥିତି '+':
			*dst++ = ' ';
			ଭାଙ୍ଗ;
		ସ୍ଥିତି '%':
			/* note: don't allow \0 characters */
			ଯଦି (!isxdigit((unsigned ଅକ୍ଷର)src[1]) ||
			    !isxdigit((unsigned ଅକ୍ଷର)src[2]) ||
			    (ch = hexchar(src + 1)) == -1 || ch == 0) {
				ମୁକ୍ତ(ret);
				ଫେରନ୍ତୁ ଖାଲି;
			}
			*dst++ = ch;
			src += 2;
			ଭାଙ୍ଗ;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			*dst++ = *src;
			ଭାଙ୍ଗ;
		}
	}
	*dst = '\0';

	ଫେରନ୍ତୁ ret;
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
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
parse_uri(ଅଚଳ ଅକ୍ଷର *scheme, ଅଚଳ ଅକ୍ଷର *uri, ଅକ୍ଷର **userp, ଅକ୍ଷର **hostp,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା *portp, ଅକ୍ଷର **pathp)
{
	ଅକ୍ଷର *uridup, *cp, *tmp, ch;
	ଅକ୍ଷର *user = ଖାଲି, *host = ଖାଲି, *path = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା port = -1, ret = -1;
	size_t len;

	len = strlen(scheme);
	ଯଦି (strncmp(uri, scheme, len) != 0 || strncmp(uri + len, "://", 3) != 0)
		ଫେରନ୍ତୁ 1;
	uri += len + 3;

	ଯଦି (userp != ଖାଲି)
		*userp = ଖାଲି;
	ଯଦି (hostp != ଖାଲି)
		*hostp = ଖାଲି;
	ଯଦି (portp != ଖାଲି)
		*portp = -1;
	ଯଦି (pathp != ଖାଲି)
		*pathp = ଖାଲି;

	uridup = tmp = xstrdup(uri);

	/* Extract optional ssh-info (username + connection params) */
	ଯଦି ((cp = strchr(tmp, '@')) != ଖାଲି) {
		ଅକ୍ଷର *delim;

		*cp = '\0';
		/* Extract username and connection params */
		ଯଦି ((delim = strchr(tmp, ';')) != ଖାଲି) {
			/* Just ignore connection params for now */
			*delim = '\0';
		}
		ଯଦି (*tmp == '\0') {
			/* Empty username */
			ଯାଅ out;
		}
		ଯଦି ((user = urldecode(tmp)) == ଖାଲି)
			ଯାଅ out;
		tmp = cp + 1;
	}

	/* Extract mandatory hostname */
	ଯଦି ((cp = hpdelim2(&tmp, &ch)) == ଖାଲି || *cp == '\0')
		ଯାଅ out;
	host = xstrdup(cleanhostname(cp));
	ଯଦି (!valid_domain(host, 0, ଖାଲି))
		ଯାଅ out;

	ଯଦି (tmp != ଖାଲି && *tmp != '\0') {
		ଯଦି (ch == ':') {
			/* Convert and verify port. */
			ଯଦି ((cp = strchr(tmp, '/')) != ଖାଲି)
				*cp = '\0';
			ଯଦି ((port = a2port(tmp)) <= 0)
				ଯାଅ out;
			tmp = cp ? cp + 1 : ଖାଲି;
		}
		ଯଦି (tmp != ଖାଲି && *tmp != '\0') {
			/* Extract optional path */
			ଯଦି ((path = urldecode(tmp)) == ଖାଲି)
				ଯାଅ out;
		}
	}

	/* Success */
	ଯଦି (userp != ଖାଲି) {
		*userp = user;
		user = ଖାଲି;
	}
	ଯଦି (hostp != ଖାଲି) {
		*hostp = host;
		host = ଖାଲି;
	}
	ଯଦି (portp != ଖାଲି)
		*portp = port;
	ଯଦି (pathp != ଖାଲି) {
		*pathp = path;
		path = ଖାଲି;
	}
	ret = 0;
 out:
	ମୁକ୍ତ(uridup);
	ମୁକ୍ତ(user);
	ମୁକ୍ତ(host);
	ମୁକ୍ତ(path);
	ଫେରନ୍ତୁ ret;
}

/* function to assist building execv() arguments */
ଶୂନ୍ୟ
addargs(arglist *args, ଅକ୍ଷର *fmt, ...)
{
	va_list ap;
	ଅକ୍ଷର *cp;
	u_int nalloc;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	va_start(ap, fmt);
	r = vasprintf(&cp, fmt, ap);
	va_end(ap);
	ଯଦି (r == -1)
		fatal_f("argument too long");

	nalloc = args->nalloc;
	ଯଦି (args->list == ଖାଲି) {
		nalloc = 32;
		args->ଅଙ୍କ = 0;
	} ଅନ୍ୟଥା ଯଦି (args->ଅଙ୍କ > (256 * 1024))
		fatal_f("too many arguments");
	ଅନ୍ୟଥା ଯଦି (args->ଅଙ୍କ >= args->nalloc)
		fatal_f("arglist corrupt");
	ଅନ୍ୟଥା ଯଦି (args->ଅଙ୍କ+2 >= nalloc)
		nalloc *= 2;

	args->list = xrecallocarray(args->list, args->nalloc,
	    nalloc, ଆକାର(ଅକ୍ଷର *));
	args->nalloc = nalloc;
	args->list[args->ଅଙ୍କ++] = cp;
	args->list[args->ଅଙ୍କ] = ଖାଲି;
}

ଶୂନ୍ୟ
replacearg(arglist *args, u_int which, ଅକ୍ଷର *fmt, ...)
{
	va_list ap;
	ଅକ୍ଷର *cp;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	va_start(ap, fmt);
	r = vasprintf(&cp, fmt, ap);
	va_end(ap);
	ଯଦି (r == -1)
		fatal_f("argument too long");
	ଯଦି (args->list == ଖାଲି || args->ଅଙ୍କ >= args->nalloc)
		fatal_f("arglist corrupt");

	ଯଦି (which >= args->ଅଙ୍କ)
		fatal_f("tried to replace invalid arg %d >= %d",
		    which, args->ଅଙ୍କ);
	ମୁକ୍ତ(args->list[which]);
	args->list[which] = cp;
}

ଶୂନ୍ୟ
freeargs(arglist *args)
{
	u_int i;

	ଯଦି (args == ଖାଲି)
		ଫେରନ୍ତୁ;
	ଯଦି (args->list != ଖାଲି && args->ଅଙ୍କ < args->nalloc) {
		ପାଇଁ (i = 0; i < args->ଅଙ୍କ; i++)
			ମୁକ୍ତ(args->list[i]);
		ମୁକ୍ତ(args->list);
	}
	args->nalloc = args->ଅଙ୍କ = 0;
	args->list = ଖାଲି;
}

/*
 * Expands tildes in the file name.  Returns data allocated by xmalloc.
 * Warning: this calls getpw*.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
tilde_expand(ଅଚଳ ଅକ୍ଷର *filename, uid_t uid, ଅକ୍ଷର **retp)
{
	ଅକ୍ଷର *ocopy = ଖାଲି, *copy, *s = ଖାଲି;
	ଅଚଳ ଅକ୍ଷର *path = ଖାଲି, *user = ଖାଲି;
	ସଂରଚନା passwd *pw;
	size_t len;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret = -1, r, slash;

	*retp = ଖାଲି;
	ଯଦି (*filename != '~') {
		*retp = xstrdup(filename);
		ଫେରନ୍ତୁ 0;
	}
	ocopy = copy = xstrdup(filename + 1);

	ଯଦି (*copy == '\0')				/* ~ */
		path = ଖାଲି;
	ଅନ୍ୟଥା ଯଦି (*copy == '/') {
		copy += strspn(copy, "/");
		ଯଦି (*copy == '\0')
			path = ଖାଲି;			/* ~/ */
		ଅନ୍ୟଥା
			path = copy;			/* ~/path */
	} ଅନ୍ୟଥା {
		user = copy;
		ଯଦି ((path = strchr(copy, '/')) != ଖାଲି) {
			copy[path - copy] = '\0';
			path++;
			path += strspn(path, "/");
			ଯଦି (*path == '\0')		/* ~user/ */
				path = ଖାଲି;
			/* else				 ~user/path */
		}
		/* else					~user */
	}
	ଯଦି (user != ଖାଲି) {
		ଯଦି ((pw = getpwnam(user)) == ଖାଲି) {
			error_f("No such user %s", user);
			ଯାଅ out;
		}
	} ଅନ୍ୟଥା ଯଦି ((pw = getpwuid(uid)) == ଖାଲି) {
		error_f("No such uid %ld", (long)uid);
		ଯାଅ out;
	}

	/* Make sure directory has a trailing '/' */
	slash = (len = strlen(pw->pw_dir)) == 0 || pw->pw_dir[len - 1] != '/';

	ଯଦି ((r = xasprintf(&s, "%s%s%s", pw->pw_dir,
	    slash ? "/" : "", path != ଖାଲି ? path : "")) <= 0) {
		error_f("xasprintf failed");
		ଯାଅ out;
	}
	ଯଦି (r >= PATH_MAX) {
		error_f("Path too long");
		ଯାଅ out;
	}
	/* success */
	ret = 0;
	*retp = s;
	s = ଖାଲି;
 out:
	ମୁକ୍ତ(s);
	ମୁକ୍ତ(ocopy);
	ଫେରନ୍ତୁ ret;
}

ଅକ୍ଷର *
tilde_expand_filename(ଅଚଳ ଅକ୍ଷର *filename, uid_t uid)
{
	ଅକ୍ଷର *ret;

	ଯଦି (tilde_expand(filename, uid, &ret) != 0)
		cleanup_exit(255);
	ଫେରନ୍ତୁ ret;
}

/*
 * Expand a string with a set of %[char] escapes and/or ${ENVIRONMENT}
 * substitutions.  A number of escapes may be specified as
 * (char *escape_chars, char *replacement) pairs. The list must be terminated
 * by a NULL escape_char. Returns replaced string in memory allocated by
 * xmalloc which the caller must free.
 */
ସ୍ଥିର ଅକ୍ଷର *
vdollar_percent_expand(ପୂର୍ଣ୍ଣସଂଖ୍ୟା *parseerror, ପୂର୍ଣ୍ଣସଂଖ୍ୟା dollar, ପୂର୍ଣ୍ଣସଂଖ୍ୟା percent,
    ଅଚଳ ଅକ୍ଷର *string, va_list ap)
{
#define EXPAND_MAX_ଚାବିଗୁଡ଼ିକ	64
	u_int ଅଙ୍କ_ଚାବିଗୁଡ଼ିକ = 0, i;
	ସଂରଚନା {
		ଅଚଳ ଅକ୍ଷର *ଚାବି;
		ଅଚଳ ଅକ୍ଷର *repl;
	} ଚାବିଗୁଡ଼ିକ[EXPAND_MAX_ଚାବିଗୁଡ଼ିକ];
	ସଂରଚନା sshbuf *buf;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, missingvar = 0;
	ଅକ୍ଷର *ret = ଖାଲି, *var, *varend, *val;
	size_t len;

	ଯଦି ((buf = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	ଯଦି (parseerror == ଖାଲି)
		fatal_f("null parseerror arg");
	*parseerror = 1;

	/* Gather keys if we're doing percent expansion. */
	ଯଦି (percent) {
		ପାଇଁ (ଅଙ୍କ_ଚାବିଗୁଡ଼ିକ = 0; ଅଙ୍କ_ଚାବିଗୁଡ଼ିକ < EXPAND_MAX_ଚାବିଗୁଡ଼ିକ; ଅଙ୍କ_ଚାବିଗୁଡ଼ିକ++) {
			ଚାବିଗୁଡ଼ିକ[ଅଙ୍କ_ଚାବିଗୁଡ଼ିକ].ଚାବି = va_arg(ap, ଅକ୍ଷର *);
			ଯଦି (ଚାବିଗୁଡ଼ିକ[ଅଙ୍କ_ଚାବିଗୁଡ଼ିକ].ଚାବି == ଖାଲି)
				ଭାଙ୍ଗ;
			ଚାବିଗୁଡ଼ିକ[ଅଙ୍କ_ଚାବିଗୁଡ଼ିକ].repl = va_arg(ap, ଅକ୍ଷର *);
			ଯଦି (ଚାବିଗୁଡ଼ିକ[ଅଙ୍କ_ଚାବିଗୁଡ଼ିକ].repl == ଖାଲି) {
				fatal_f("NULL replacement for token %s",
				    ଚାବିଗୁଡ଼ିକ[ଅଙ୍କ_ଚାବିଗୁଡ଼ିକ].ଚାବି);
			}
		}
		ଯଦି (ଅଙ୍କ_ଚାବିଗୁଡ଼ିକ == EXPAND_MAX_ଚାବିଗୁଡ଼ିକ && va_arg(ap, ଅକ୍ଷର *) != ଖାଲି)
			fatal_f("too many keys");
		ଯଦି (ଅଙ୍କ_ଚାବିଗୁଡ଼ିକ == 0)
			fatal_f("percent expansion without token list");
	}

	/* Expand string */
	ପାଇଁ (i = 0; *string != '\0'; string++) {
		/* Optionally process ${ENVIRONMENT} expansions. */
		ଯଦି (dollar && string[0] == '$' && string[1] == '{') {
			string += 2;  /* skip over '${' */
			ଯଦି ((varend = strchr(string, '}')) == ଖାଲି) {
				error_f("environment variable '%s' missing "
				    "closing '}'", string);
				ଯାଅ out;
			}
			len = varend - string;
			ଯଦି (len == 0) {
				error_f("zero-length environment variable");
				ଯାଅ out;
			}
			var = xmalloc(len + 1);
			(ଶୂନ୍ୟ)strlcpy(var, string, len + 1);
			ଯଦି ((val = getenv(var)) == ଖାଲି) {
				error_f("env var ${%s} has no value", var);
				missingvar = 1;
			} ଅନ୍ୟଥା {
				debug3_f("expand ${%s} -> '%s'", var, val);
				ଯଦି ((r = sshbuf_put(buf, val, strlen(val))) !=0)
					fatal_fr(r, "sshbuf_put ${}");
			}
			ମୁକ୍ତ(var);
			string += len;
			ଜାରି;
		}

		/*
		 * Process percent expansions if we have a list of TOKENs.
		 * If we're not doing percent expansion everything just gets
		 * appended here.
		 */
		ଯଦି (*string != '%' || !percent) {
 append:
			ଯଦି ((r = sshbuf_put_u8(buf, *string)) != 0)
				fatal_fr(r, "sshbuf_put_u8 %%");
			ଜାରି;
		}
		string++;
		/* %% case */
		ଯଦି (*string == '%')
			ଯାଅ append;
		ଯଦି (*string == '\0') {
			error_f("invalid format");
			ଯାଅ out;
		}
		ପାଇଁ (i = 0; i < ଅଙ୍କ_ଚାବିଗୁଡ଼ିକ; i++) {
			ଯଦି (strchr(ଚାବିଗୁଡ଼ିକ[i].ଚାବି, *string) != ଖାଲି) {
				ଯଦି ((r = sshbuf_put(buf, ଚାବିଗୁଡ଼ିକ[i].repl,
				    strlen(ଚାବିଗୁଡ଼ିକ[i].repl))) != 0)
					fatal_fr(r, "sshbuf_put %%-repl");
				ଭାଙ୍ଗ;
			}
		}
		ଯଦି (i >= ଅଙ୍କ_ଚାବିଗୁଡ଼ିକ) {
			error_f("unknown key %%%c", *string);
			ଯାଅ out;
		}
	}
	ଯଦି (!missingvar && (ret = sshbuf_dup_string(buf)) == ଖାଲି)
		fatal_f("sshbuf_dup_string failed");
	*parseerror = 0;
 out:
	sshbuf_free(buf);
	ଫେରନ୍ତୁ *parseerror ? ଖାଲି : ret;
#undef EXPAND_MAX_ଚାବିଗୁଡ଼ିକ
}

/*
 * Expand only environment variables.
 * Note that although this function is variadic like the other similar
 * functions, any such arguments will be unused.
 */

ଅକ୍ଷର *
dollar_expand(ପୂର୍ଣ୍ଣସଂଖ୍ୟା *parseerr, ଅଚଳ ଅକ୍ଷର *string, ...)
{
	ଅକ୍ଷର *ret;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା err;
	va_list ap;

	va_start(ap, string);
	ret = vdollar_percent_expand(&err, 1, 0, string, ap);
	va_end(ap);
	ଯଦି (parseerr != ଖାଲି)
		*parseerr = err;
	ଫେରନ୍ତୁ ret;
}

/*
 * Returns expanded string or NULL if a specified environment variable is
 * not defined, or calls fatal if the string is invalid.
 */
ଅକ୍ଷର *
percent_expand(ଅଚଳ ଅକ୍ଷର *string, ...)
{
	ଅକ୍ଷର *ret;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା err;
	va_list ap;

	va_start(ap, string);
	ret = vdollar_percent_expand(&err, 0, 1, string, ap);
	va_end(ap);
	ଯଦି (err)
		fatal_f("failed");
	ଫେରନ୍ତୁ ret;
}

/*
 * Returns expanded string or NULL if a specified environment variable is
 * not defined, or calls fatal if the string is invalid.
 */
ଅକ୍ଷର *
percent_dollar_expand(ଅଚଳ ଅକ୍ଷର *string, ...)
{
	ଅକ୍ଷର *ret;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା err;
	va_list ap;

	va_start(ap, string);
	ret = vdollar_percent_expand(&err, 1, 1, string, ap);
	va_end(ap);
	ଯଦି (err)
		fatal_f("failed");
	ଫେରନ୍ତୁ ret;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
tun_open(ପୂର୍ଣ୍ଣସଂଖ୍ୟା tun, ପୂର୍ଣ୍ଣସଂଖ୍ୟା mode, ଅକ୍ଷର **ifname)
{
#ଯଦି defined(CUSTOM_SYS_TUN_OPEN)
	ଫେରନ୍ତୁ (sys_tun_open(tun, mode, ifname));
#ନଚେତଯଦି defined(SSH_TUN_OPENBSD)
	ସଂରଚନା ifreq ifr;
	ଅକ୍ଷର name[100];
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd = -1, sock;
	ଅଚଳ ଅକ୍ଷର *tunbase = "tun";

	ଯଦି (ifname != ଖାଲି)
		*ifname = ଖାଲି;

	ଯଦି (mode == SSH_TUNMODE_ETHERNET)
		tunbase = "tap";

	/* Open the tunnel device */
	ଯଦି (tun <= SSH_TUNID_MAX) {
		snprintf(name, ଆକାର(name), "/dev/%s%d", tunbase, tun);
		fd = open(name, O_RDWR);
	} ଅନ୍ୟଥା ଯଦି (tun == SSH_TUNID_ANY) {
		ପାଇଁ (tun = 100; tun >= 0; tun--) {
			snprintf(name, ଆକାର(name), "/dev/%s%d",
			    tunbase, tun);
			ଯଦି ((fd = open(name, O_RDWR)) >= 0)
				ଭାଙ୍ଗ;
		}
	} ଅନ୍ୟଥା {
		debug_f("invalid tunnel %u", tun);
		ଫେରନ୍ତୁ -1;
	}

	ଯଦି (fd == -1) {
		debug_f("%s open: %s", name, strerror(errno));
		ଫେରନ୍ତୁ -1;
	}

	debug_f("%s mode %d fd %d", name, mode, fd);

	/* Bring interface up if it is not already */
	snprintf(ifr.ifr_name, ଆକାର(ifr.ifr_name), "%s%d", tunbase, tun);
	ଯଦି ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
		ଯାଅ failed;

	ଯଦି (ioctl(sock, SIOCGIFFLAGS, &ifr) == -1) {
		debug_f("get interface %s flags: %s", ifr.ifr_name,
		    strerror(errno));
		ଯାଅ failed;
	}

	ଯଦି (!(ifr.ifr_flags & IFF_UP)) {
		ifr.ifr_flags |= IFF_UP;
		ଯଦି (ioctl(sock, SIOCSIFFLAGS, &ifr) == -1) {
			debug_f("activate interface %s: %s", ifr.ifr_name,
			    strerror(errno));
			ଯାଅ failed;
		}
	}

	ଯଦି (ifname != ଖାଲି)
		*ifname = xstrdup(ifr.ifr_name);

	close(sock);
	ଫେରନ୍ତୁ fd;

 failed:
	ଯଦି (fd >= 0)
		close(fd);
	ଯଦି (sock >= 0)
		close(sock);
	ଫେରନ୍ତୁ -1;
#ଅନ୍ୟଥା
	error("Tunnel interfaces are not supported on this platform");
	ଫେରନ୍ତୁ (-1);
#endif
}

ଶୂନ୍ୟ
sanitise_stdfd(ଶୂନ୍ୟ)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା nullfd, dupfd;

	ଯଦି ((nullfd = dupfd = open(_PATH_DEVNULL, O_RDWR)) == -1) {
		fprintf(stderr, "Couldn't open /dev/null: %s\n",
		    strerror(errno));
		exit(1);
	}
	ଯେତେବେଳେ (++dupfd <= STDERR_FILENO) {
		/* Only populate closed fds. */
		ଯଦି (fcntl(dupfd, F_GETFL) == -1 && errno == EBADF) {
			ଯଦି (dup2(nullfd, dupfd) == -1) {
				fprintf(stderr, "dup2: %s\n", strerror(errno));
				exit(1);
			}
		}
	}
	ଯଦି (nullfd > STDERR_FILENO)
		close(nullfd);
}

ଅକ୍ଷର *
tohex(ଅଚଳ ଶୂନ୍ୟ *vp, size_t l)
{
	ଅଚଳ u_char *p = (ଅଚଳ u_char *)vp;
	ଅକ୍ଷର b[3], *r;
	size_t i, hl;

	ଯଦି (l > 65536)
		ଫେରନ୍ତୁ xstrdup("tohex: length > 65536");

	hl = l * 2 + 1;
	r = xcalloc(1, hl);
	ପାଇଁ (i = 0; i < l; i++) {
		snprintf(b, ଆକାର(b), "%02x", p[i]);
		strlcat(r, b, hl);
	}
	ଫେରନ୍ତୁ (r);
}

/*
 * Extend string *sp by the specified format. If *sp is not NULL (or empty),
 * then the separator 'sep' will be prepended before the formatted arguments.
 * Extended strings are heap allocated.
 */
ଶୂନ୍ୟ
xextendf(ଅକ୍ଷର **sp, ଅଚଳ ଅକ୍ଷର *sep, ଅଚଳ ଅକ୍ଷର *fmt, ...)
{
	va_list ap;
	ଅକ୍ଷର *tmp1, *tmp2;

	va_start(ap, fmt);
	xvasprintf(&tmp1, fmt, ap);
	va_end(ap);

	ଯଦି (*sp == ଖାଲି || **sp == '\0') {
		ମୁକ୍ତ(*sp);
		*sp = tmp1;
		ଫେରନ୍ତୁ;
	}
	xasprintf(&tmp2, "%s%s%s", *sp, sep == ଖାଲି ? "" : sep, tmp1);
	ମୁକ୍ତ(tmp1);
	ମୁକ୍ତ(*sp);
	*sp = tmp2;
}


uint64_t
get_u64(ଅଚଳ ଶୂନ୍ୟ *vp)
{
	ଅଚଳ u_char *p = (ଅଚଳ u_char *)vp;
	uint64_t v;

	v  = (uint64_t)p[0] << 56;
	v |= (uint64_t)p[1] << 48;
	v |= (uint64_t)p[2] << 40;
	v |= (uint64_t)p[3] << 32;
	v |= (uint64_t)p[4] << 24;
	v |= (uint64_t)p[5] << 16;
	v |= (uint64_t)p[6] << 8;
	v |= (uint64_t)p[7];

	ଫେରନ୍ତୁ (v);
}

uint32_t
get_u32(ଅଚଳ ଶୂନ୍ୟ *vp)
{
	ଅଚଳ u_char *p = (ଅଚଳ u_char *)vp;
	uint32_t v;

	v  = (uint32_t)p[0] << 24;
	v |= (uint32_t)p[1] << 16;
	v |= (uint32_t)p[2] << 8;
	v |= (uint32_t)p[3];

	ଫେରନ୍ତୁ (v);
}

uint32_t
get_u32_le(ଅଚଳ ଶୂନ୍ୟ *vp)
{
	ଅଚଳ u_char *p = (ଅଚଳ u_char *)vp;
	uint32_t v;

	v  = (uint32_t)p[0];
	v |= (uint32_t)p[1] << 8;
	v |= (uint32_t)p[2] << 16;
	v |= (uint32_t)p[3] << 24;

	ଫେରନ୍ତୁ (v);
}

uint16_t
get_u16(ଅଚଳ ଶୂନ୍ୟ *vp)
{
	ଅଚଳ u_char *p = (ଅଚଳ u_char *)vp;
	uint16_t v;

	v  = (uint16_t)p[0] << 8;
	v |= (uint16_t)p[1];

	ଫେରନ୍ତୁ (v);
}

ଶୂନ୍ୟ
put_u64(ଶୂନ୍ୟ *vp, uint64_t v)
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

ଶୂନ୍ୟ
put_u32(ଶୂନ୍ୟ *vp, uint32_t v)
{
	u_char *p = (u_char *)vp;

	p[0] = (u_char)(v >> 24) & 0xff;
	p[1] = (u_char)(v >> 16) & 0xff;
	p[2] = (u_char)(v >> 8) & 0xff;
	p[3] = (u_char)v & 0xff;
}

ଶୂନ୍ୟ
put_u32_le(ଶୂନ୍ୟ *vp, uint32_t v)
{
	u_char *p = (u_char *)vp;

	p[0] = (u_char)v & 0xff;
	p[1] = (u_char)(v >> 8) & 0xff;
	p[2] = (u_char)(v >> 16) & 0xff;
	p[3] = (u_char)(v >> 24) & 0xff;
}

ଶୂନ୍ୟ
put_u16(ଶୂନ୍ୟ *vp, uint16_t v)
{
	u_char *p = (u_char *)vp;

	p[0] = (u_char)(v >> 8) & 0xff;
	p[1] = (u_char)v & 0xff;
}

ଶୂନ୍ୟ
ms_subtract_diff(ସଂରଚନା timeval *start, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *ms)
{
	ସଂରଚନା timeval diff, finish;

	monotime_tv(&finish);
	timersub(&finish, start, &diff);
	*ms -= (diff.tv_sec * 1000) + (diff.tv_usec / 1000);
}

ଶୂନ୍ୟ
ms_to_timespec(ସଂରଚନା timespec *ts, ପୂର୍ଣ୍ଣସଂଖ୍ୟା ms)
{
	ଯଦି (ms < 0)
		ms = 0;
	ts->tv_sec = ms / 1000;
	ts->tv_nsec = (ms % 1000) * 1000 * 1000;
}

ଶୂନ୍ୟ
monotime_ts(ସଂରଚନା timespec *ts)
{
	ସଂରଚନା timeval tv;
#ଯଦି defined(HAVE_CLOCK_GETTIME) && (defined(CLOCK_BOOTTIME) || \
    defined(CLOCK_MONOTONIC) || defined(CLOCK_REALTIME))
	ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା gettime_failed = 0;

	ଯଦି (!gettime_failed) {
# ifdef CLOCK_BOOTTIME
		ଯଦି (clock_gettime(CLOCK_BOOTTIME, ts) == 0)
			ଫେରନ୍ତୁ;
# endif /* CLOCK_BOOTTIME */
# ifdef CLOCK_MONOTONIC
		ଯଦି (clock_gettime(CLOCK_MONOTONIC, ts) == 0)
			ଫେରନ୍ତୁ;
# endif /* CLOCK_MONOTONIC */
# ifdef CLOCK_REALTIME
		/* Not monotonic, but we're almost out of options here. */
		ଯଦି (clock_gettime(CLOCK_REALTIME, ts) == 0)
			ଫେରନ୍ତୁ;
# endif /* CLOCK_REALTIME */
		debug3("clock_gettime: %s", strerror(errno));
		gettime_failed = 1;
	}
#endif /* HAVE_CLOCK_GETTIME && (BOOTTIME || MONOTONIC || REALTIME) */
	gettimeofday(&tv, ଖାଲି);
	ts->tv_sec = tv.tv_sec;
	ts->tv_nsec = (long)tv.tv_usec * 1000;
}

ଶୂନ୍ୟ
monotime_tv(ସଂରଚନା timeval *tv)
{
	ସଂରଚନା timespec ts;

	monotime_ts(&ts);
	tv->tv_sec = ts.tv_sec;
	tv->tv_usec = ts.tv_nsec / 1000;
}

time_t
monotime(ଶୂନ୍ୟ)
{
	ସଂରଚନା timespec ts;

	monotime_ts(&ts);
	ଫେରନ୍ତୁ (ts.tv_sec);
}

ଦ୍ୱିଗୁଣ
monotime_double(ଶୂନ୍ୟ)
{
	ସଂରଚନା timespec ts;

	monotime_ts(&ts);
	ଫେରନ୍ତୁ (ଦ୍ୱିଗୁଣ)ts.tv_sec + (ଦ୍ୱିଗୁଣ)ts.tv_nsec / 1000000000.0;
}

ଶୂନ୍ୟ
bandwidth_limit_init(ସଂରଚନା bwlimit *bw, uint64_t kbps, size_t buflen)
{
	bw->buflen = buflen;
	bw->rate = kbps;
	bw->thresh = buflen;
	bw->lamt = 0;
	timerclear(&bw->bwstart);
	timerclear(&bw->bwend);
}

/* Callback from read/write loop to insert bandwidth-limiting delays */
ଶୂନ୍ୟ
bandwidth_limit(ସଂରଚନା bwlimit *bw, size_t read_len)
{
	uint64_t waitlen;
	ସଂରଚନା timespec ts, rm;

	bw->lamt += read_len;
	ଯଦି (!timerisset(&bw->bwstart)) {
		monotime_tv(&bw->bwstart);
		ଫେରନ୍ତୁ;
	}
	ଯଦି (bw->lamt < bw->thresh)
		ଫେରନ୍ତୁ;

	monotime_tv(&bw->bwend);
	timersub(&bw->bwend, &bw->bwstart, &bw->bwend);
	ଯଦି (!timerisset(&bw->bwend))
		ଫେରନ୍ତୁ;

	bw->lamt *= 8;
	waitlen = (ଦ୍ୱିଗୁଣ)1000000L * bw->lamt / bw->rate;

	bw->bwstart.tv_sec = waitlen / 1000000L;
	bw->bwstart.tv_usec = waitlen % 1000000L;

	ଯଦି (timercmp(&bw->bwstart, &bw->bwend, >)) {
		timersub(&bw->bwstart, &bw->bwend, &bw->bwend);

		/* Adjust the wait time */
		ଯଦି (bw->bwend.tv_sec) {
			bw->thresh /= 2;
			ଯଦି (bw->thresh < bw->buflen / 4)
				bw->thresh = bw->buflen / 4;
		} ଅନ୍ୟଥା ଯଦି (bw->bwend.tv_usec < 10000) {
			bw->thresh *= 2;
			ଯଦି (bw->thresh > bw->buflen * 8)
				bw->thresh = bw->buflen * 8;
		}

		TIMEVAL_TO_TIMESPEC(&bw->bwend, &ts);
		ଯେତେବେଳେ (nanosleep(&ts, &rm) == -1) {
			ଯଦି (errno != EINTR)
				ଭାଙ୍ଗ;
			ts = rm;
		}
	}

	bw->lamt = 0;
	monotime_tv(&bw->bwstart);
}

/* Make a template filename for mk[sd]temp() */
ଶୂନ୍ୟ
mktemp_proto(ଅକ୍ଷର *s, size_t len)
{
	ଅଚଳ ଅକ୍ଷର *tmpdir;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((tmpdir = getenv("TMPDIR")) != ଖାଲି) {
		r = snprintf(s, len, "%s/ssh-XXXXXXXXXXXX", tmpdir);
		ଯଦି (r > 0 && (size_t)r < len)
			ଫେରନ୍ତୁ;
	}
	r = snprintf(s, len, "/tmp/ssh-XXXXXXXXXXXX");
	ଯଦି (r < 0 || (size_t)r >= len)
		fatal_f("template string too short");
}

ସ୍ଥିର ଅଚଳ ସଂରଚନା {
	ଅଚଳ ଅକ୍ଷର *name;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ମୂଲ୍ୟ;
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
	{ ଖାଲି, -1 }
};

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
parse_ipqos(ଅଚଳ ଅକ୍ଷର *cp)
{
	ଅଚଳ ଅକ୍ଷର *errstr;
	u_int i;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା val;

	ଯଦି (cp == ଖାଲି)
		ଫେରନ୍ତୁ -1;
	ପାଇଁ (i = 0; ipqos[i].name != ଖାଲି; i++) {
		ଯଦି (strcasecmp(cp, ipqos[i].name) == 0)
			ଫେରନ୍ତୁ ipqos[i].ମୂଲ୍ୟ;
	}
	/* Try parsing as an integer */
	val = (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)strtonum(cp, 0, 255, &errstr);
	ଯଦି (errstr)
		ଫେରନ୍ତୁ -1;
	ଫେରନ୍ତୁ val;
}

ଅଚଳ ଅକ୍ଷର *
iptos2str(ପୂର୍ଣ୍ଣସଂଖ୍ୟା iptos)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;
	ସ୍ଥିର ଅକ୍ଷର iptos_str[ଆକାର "0xff"];

	ପାଇଁ (i = 0; ipqos[i].name != ଖାଲି; i++) {
		ଯଦି (ipqos[i].ମୂଲ୍ୟ == iptos)
			ଫେରନ୍ତୁ ipqos[i].name;
	}
	snprintf(iptos_str, ଆକାର iptos_str, "0x%02x", iptos);
	ଫେରନ୍ତୁ iptos_str;
}

ଶୂନ୍ୟ
lowercase(ଅକ୍ଷର *s)
{
	ପାଇଁ (; *s; s++)
		*s = tolower((u_char)*s);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
unix_listener(ଅଚଳ ଅକ୍ଷର *path, ପୂର୍ଣ୍ଣସଂଖ୍ୟା backlog, ପୂର୍ଣ୍ଣସଂଖ୍ୟା unlink_first)
{
	ସଂରଚନା sockaddr_un sunaddr;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା saved_errno, sock;

	memset(&sunaddr, 0, ଆକାର(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	ଯଦି (strlcpy(sunaddr.sun_path, path,
	    ଆକାର(sunaddr.sun_path)) >= ଆକାର(sunaddr.sun_path)) {
		error_f("path \"%s\" too long for Unix domain socket", path);
		errno = ENAMETOOLONG;
		ଫେରନ୍ତୁ -1;
	}

	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	ଯଦି (sock == -1) {
		saved_errno = errno;
		error_f("socket: %.100s", strerror(errno));
		errno = saved_errno;
		ଫେରନ୍ତୁ -1;
	}
	ଯଦି (unlink_first == 1) {
		ଯଦି (unlink(path) != 0 && errno != ENOENT)
			error("unlink(%s): %.100s", path, strerror(errno));
	}
	ଯଦି (bind(sock, (ସଂରଚନା sockaddr *)&sunaddr, ଆକାର(sunaddr)) == -1) {
		saved_errno = errno;
		error_f("cannot bind to path %s: %s", path, strerror(errno));
		close(sock);
		errno = saved_errno;
		ଫେରନ୍ତୁ -1;
	}
	ଯଦି (listen(sock, backlog) == -1) {
		saved_errno = errno;
		error_f("cannot listen on path %s: %s", path, strerror(errno));
		close(sock);
		unlink(path);
		errno = saved_errno;
		ଫେରନ୍ତୁ -1;
	}
	ଫେରନ୍ତୁ sock;
}

ଶୂନ୍ୟ
sock_set_v6only(ପୂର୍ଣ୍ଣସଂଖ୍ୟା s)
{
#ଯଦି defined(IPV6_V6ONLY) && !defined(__OpenBSD__)
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା on = 1;

	debug3_f("set socket %d IPV6_V6ONLY", s);
	ଯଦି (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &on, ଆକାର(on)) == -1)
		error("setsockopt IPV6_V6ONLY: %s", strerror(errno));
#endif
}

/*
 * Compares two strings that maybe be NULL. Returns non-zero if strings
 * are both NULL or are identical, returns zero otherwise.
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
strcmp_maybe_null(ଅଚଳ ଅକ୍ଷର *a, ଅଚଳ ଅକ୍ଷର *b)
{
	ଯଦି ((a == ଖାଲି && b != ଖାଲି) || (a != ଖାଲି && b == ଖାଲି))
		ଫେରନ୍ତୁ 0;
	ଯଦି (a != ଖାଲି && strcmp(a, b) != 0)
		ଫେରନ୍ତୁ 0;
	ଫେରନ୍ତୁ 1;
}

/*
 * Compare two forwards, returning non-zero if they are identical or
 * zero otherwise.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
forward_equals(ଅଚଳ ସଂରଚନା Forward *a, ଅଚଳ ସଂରଚନା Forward *b)
{
	ଯଦି (strcmp_maybe_null(a->listen_host, b->listen_host) == 0)
		ଫେରନ୍ତୁ 0;
	ଯଦି (a->listen_port != b->listen_port)
		ଫେରନ୍ତୁ 0;
	ଯଦି (strcmp_maybe_null(a->listen_path, b->listen_path) == 0)
		ଫେରନ୍ତୁ 0;
	ଯଦି (strcmp_maybe_null(a->connect_host, b->connect_host) == 0)
		ଫେରନ୍ତୁ 0;
	ଯଦି (a->connect_port != b->connect_port)
		ଫେରନ୍ତୁ 0;
	ଯଦି (strcmp_maybe_null(a->connect_path, b->connect_path) == 0)
		ଫେରନ୍ତୁ 0;
	/* allocated_port and handle are not checked */
	ଫେରନ୍ତୁ 1;
}

/* returns port number, FWD_PERMIT_ANY_PORT or -1 on error */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
permitopen_port(ଅଚଳ ଅକ୍ଷର *p)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା port;

	ଯଦି (strcmp(p, "*") == 0)
		ଫେରନ୍ତୁ FWD_PERMIT_ANY_PORT;
	ଯଦି ((port = a2port(p)) > 0)
		ଫେରନ୍ତୁ port;
	ଫେରନ୍ତୁ -1;
}

/* returns 1 if process is already daemonized, 0 otherwise */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
daemonized(ଶୂନ୍ୟ)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd;

	ଯଦି ((fd = open(_PATH_TTY, O_RDONLY | O_NOCTTY)) >= 0) {
		close(fd);
		ଫେରନ୍ତୁ 0;	/* have controlling terminal */
	}
	ଯଦି (getppid() != 1)
		ଫେରନ୍ତୁ 0;	/* parent is not init */
	ଯଦି (getsid(0) != getpid())
		ଫେରନ୍ତୁ 0;	/* not session leader */
	debug3("already daemonized");
	ଫେରନ୍ତୁ 1;
}

/*
 * Splits 's' into an argument vector. Handles quoted string and basic
 * escape characters (\\, \", \'). Caller must free the argument vector
 * and its members.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
argv_split(ଅଚଳ ଅକ୍ଷର *s, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *argcp, ଅକ୍ଷର ***argvp, ପୂର୍ଣ୍ଣସଂଖ୍ୟା terminate_on_comment)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = SSH_ERR_INTERNAL_ERROR;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା argc = 0, quote, i, j;
	ଅକ୍ଷର *arg, **argv = xcalloc(1, ଆକାର(*argv));

	*argvp = ଖାଲି;
	*argcp = 0;

	ପାଇଁ (i = 0; s[i] != '\0'; i++) {
		/* Skip leading whitespace */
		ଯଦି (s[i] == ' ' || s[i] == '\t')
			ଜାରି;
		ଯଦି (terminate_on_comment && s[i] == '#')
			ଭାଙ୍ଗ;
		/* Start of a token */
		quote = 0;

		argv = xreallocarray(argv, (argc + 2), ଆକାର(*argv));
		arg = argv[argc++] = xcalloc(1, strlen(s + i) + 1);
		argv[argc] = ଖାଲି;

		/* Copy the token in, removing escapes */
		ପାଇଁ (j = 0; s[i] != '\0'; i++) {
			ଯଦି (s[i] == '\\') {
				ଯଦି (s[i + 1] == '\'' ||
				    s[i + 1] == '\"' ||
				    s[i + 1] == '\\' ||
				    (quote == 0 && s[i + 1] == ' ')) {
					i++; /* Skip '\' */
					arg[j++] = s[i];
				} ଅନ୍ୟଥା {
					/* Unrecognised escape */
					arg[j++] = s[i];
				}
			} ଅନ୍ୟଥା ଯଦି (quote == 0 && (s[i] == ' ' || s[i] == '\t'))
				ଭାଙ୍ଗ; /* done */
			ଅନ୍ୟଥା ଯଦି (quote == 0 && (s[i] == '\"' || s[i] == '\''))
				quote = s[i]; /* quote start */
			ଅନ୍ୟଥା ଯଦି (quote != 0 && s[i] == quote)
				quote = 0; /* quote end */
			ଅନ୍ୟଥା
				arg[j++] = s[i];
		}
		ଯଦି (s[i] == '\0') {
			ଯଦି (quote != 0) {
				/* Ran out of string looking for close quote */
				r = SSH_ERR_INVALID_FORMAT;
				ଯାଅ out;
			}
			ଭାଙ୍ଗ;
		}
	}
	/* Success */
	*argcp = argc;
	*argvp = argv;
	argc = 0;
	argv = ଖାଲି;
	r = 0;
 out:
	ଯଦି (argc != 0 && argv != ଖାଲି) {
		ପାଇଁ (i = 0; i < argc; i++)
			ମୁକ୍ତ(argv[i]);
		ମୁକ୍ତ(argv);
	}
	ଫେରନ୍ତୁ r;
}

/*
 * Reassemble an argument vector into a string, quoting and escaping as
 * necessary. Caller must free returned string.
 */
ଅକ୍ଷର *
argv_assemble(ପୂର୍ଣ୍ଣସଂଖ୍ୟା argc, ଅକ୍ଷର **argv)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i, j, ws, r;
	ଅକ୍ଷର c, *ret;
	ସଂରଚନା sshbuf *buf, *arg;

	ଯଦି ((buf = sshbuf_new()) == ଖାଲି || (arg = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");

	ପାଇଁ (i = 0; i < argc; i++) {
		ws = 0;
		sshbuf_reset(arg);
		ପାଇଁ (j = 0; argv[i][j] != '\0'; j++) {
			r = 0;
			c = argv[i][j];
			ବାଛ (c) {
			ସ୍ଥିତି ' ':
			ସ୍ଥିତି '\t':
				ws = 1;
				r = sshbuf_put_u8(arg, c);
				ଭାଙ୍ଗ;
			ସ୍ଥିତି '\\':
			ସ୍ଥିତି '\'':
			ସ୍ଥିତି '"':
				ଯଦି ((r = sshbuf_put_u8(arg, '\\')) != 0)
					ଭାଙ୍ଗ;
				/* FALLTHROUGH */
			ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
				r = sshbuf_put_u8(arg, c);
				ଭାଙ୍ଗ;
			}
			ଯଦି (r != 0)
				fatal_fr(r, "sshbuf_put_u8");
		}
		ଯଦି ((i != 0 && (r = sshbuf_put_u8(buf, ' ')) != 0) ||
		    (ws != 0 && (r = sshbuf_put_u8(buf, '"')) != 0) ||
		    (r = sshbuf_putb(buf, arg)) != 0 ||
		    (ws != 0 && (r = sshbuf_put_u8(buf, '"')) != 0))
			fatal_fr(r, "assemble");
	}
	ଯଦି ((ret = malloc(sshbuf_len(buf) + 1)) == ଖାଲି)
		fatal_f("malloc failed");
	memcpy(ret, sshbuf_ptr(buf), sshbuf_len(buf));
	ret[sshbuf_len(buf)] = '\0';
	sshbuf_free(buf);
	sshbuf_free(arg);
	ଫେରନ୍ତୁ ret;
}

ଅକ୍ଷର *
argv_next(ପୂର୍ଣ୍ଣସଂଖ୍ୟା *argcp, ଅକ୍ଷର ***argvp)
{
	ଅକ୍ଷର *ret = (*argvp)[0];

	ଯଦି (*argcp > 0 && ret != ଖାଲି) {
		(*argcp)--;
		(*argvp)++;
	}
	ଫେରନ୍ତୁ ret;
}

ଶୂନ୍ୟ
argv_consume(ପୂର୍ଣ୍ଣସଂଖ୍ୟା *argcp)
{
	*argcp = 0;
}

ଶୂନ୍ୟ
argv_free(ଅକ୍ଷର **av, ପୂର୍ଣ୍ଣସଂଖ୍ୟା ac)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;

	ଯଦି (av == ଖାଲି)
		ଫେରନ୍ତୁ;
	ପାଇଁ (i = 0; i < ac; i++)
		ମୁକ୍ତ(av[i]);
	ମୁକ୍ତ(av);
}

/* Returns 0 if pid exited cleanly, non-zero otherwise */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
exited_cleanly(pid_t pid, ଅଚଳ ଅକ୍ଷର *tag, ଅଚଳ ଅକ୍ଷର *cmd, ପୂର୍ଣ୍ଣସଂଖ୍ୟା quiet)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା status;

	ଯେତେବେଳେ (waitpid(pid, &status, 0) == -1) {
		ଯଦି (errno != EINTR) {
			error("%s waitpid: %s", tag, strerror(errno));
			ଫେରନ୍ତୁ -1;
		}
	}
	ଯଦି (WIFSIGNALED(status)) {
		error("%s %s exited on signal %d", tag, cmd, WTERMSIG(status));
		ଫେରନ୍ତୁ -1;
	} ଅନ୍ୟଥା ଯଦି (WEXITSTATUS(status) != 0) {
		do_log2(quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_INFO,
		    "%s %s failed, status %d", tag, cmd, WEXITSTATUS(status));
		ଫେରନ୍ତୁ -1;
	}
	ଫେରନ୍ତୁ 0;
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
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
safe_path(ଅଚଳ ଅକ୍ଷର *name, ସଂରଚନା stat *stp, ଅଚଳ ଅକ୍ଷର *pw_dir,
    uid_t uid, ଅକ୍ଷର *err, size_t errlen)
{
	ଅକ୍ଷର buf[PATH_MAX], buf2[PATH_MAX], homedir[PATH_MAX];
	ଅକ୍ଷର *cp;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା comparehome = 0;
	ସଂରଚନା stat st;

	ଯଦି (realpath(name, buf) == ଖାଲି) {
		snprintf(err, errlen, "realpath %s failed: %s", name,
		    strerror(errno));
		ଫେରନ୍ତୁ -1;
	}
	ଯଦି (pw_dir != ଖାଲି && realpath(pw_dir, homedir) != ଖାଲି)
		comparehome = 1;

	ଯଦି (!S_ISREG(stp->st_mode)) {
		snprintf(err, errlen, "%s is not a regular file", buf);
		ଫେରନ୍ତୁ -1;
	}
	ଯଦି ((!platform_sys_dir_uid(stp->st_uid) && stp->st_uid != uid) ||
	    (stp->st_mode & 022) != 0) {
		snprintf(err, errlen, "bad ownership or modes for file %s",
		    buf);
		ଫେରନ୍ତୁ -1;
	}

	/* for each component of the canonical path, walking upwards */
	ପାଇଁ (;;) {
		/*
		 * POSIX allows dirname to modify its argument and return a
		 * pointer into it, so make a copy to avoid overlapping strlcpy.
		 */
		strlcpy(buf2, buf, ଆକାର(buf2));
		ଯଦି ((cp = dirname(buf2)) == ଖାଲି) {
			snprintf(err, errlen, "dirname() failed");
			ଫେରନ୍ତୁ -1;
		}
		strlcpy(buf, cp, ଆକାର(buf));

		ଯଦି (stat(buf, &st) == -1 ||
		    (!platform_sys_dir_uid(st.st_uid) && st.st_uid != uid) ||
		    (st.st_mode & 022) != 0) {
			snprintf(err, errlen,
			    "bad ownership or modes for directory %s", buf);
			ଫେରନ୍ତୁ -1;
		}

		/* If are past the homedir then we can stop */
		ଯଦି (comparehome && strcmp(homedir, buf) == 0)
			ଭାଙ୍ଗ;

		/*
		 * dirname should always complete with a "/" path,
		 * but we can be paranoid and check for "." too
		 */
		ଯଦି ((strcmp("/", buf) == 0) || (strcmp(".", buf) == 0))
			ଭାଙ୍ଗ;
	}
	ଫେରନ୍ତୁ 0;
}

/*
 * Version of safe_path() that accepts an open file descriptor to
 * avoid races.
 *
 * Returns 0 on success and -1 on failure
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
safe_path_fd(ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd, ଅଚଳ ଅକ୍ଷର *file, ସଂରଚନା passwd *pw,
    ଅକ୍ଷର *err, size_t errlen)
{
	ସଂରଚନା stat st;

	/* check the open file to avoid races */
	ଯଦି (fstat(fd, &st) == -1) {
		snprintf(err, errlen, "cannot stat file %s: %s",
		    file, strerror(errno));
		ଫେରନ୍ତୁ -1;
	}
	ଫେରନ୍ତୁ safe_path(file, &st, pw->pw_dir, pw->pw_uid, err, errlen);
}

/*
 * Sets the value of the given variable in the environment.  If the variable
 * already exists, its value is overridden.
 */
ଶୂନ୍ୟ
child_set_env(ଅକ୍ଷର ***envp, u_int *envsizep, ଅଚଳ ଅକ୍ଷର *name,
	ଅଚଳ ଅକ୍ଷର *ମୂଲ୍ୟ)
{
	ଅକ୍ଷର **env;
	u_int envsize;
	u_int i, namelen;

	ଯଦି (strchr(name, '=') != ଖାଲି) {
		error("Invalid environment variable \"%.100s\"", name);
		ଫେରନ୍ତୁ;
	}

	/*
	 * If we're passed an uninitialized list, allocate a single null
	 * entry before continuing.
	 */
	ଯଦି ((*envp == ଖାଲି) != (*envsizep == 0))
		fatal_f("environment size mismatch");
	ଯଦି (*envp == ଖାଲି && *envsizep == 0) {
		*envp = xmalloc(ଆକାର(ଅକ୍ଷର *));
		*envp[0] = ଖାଲି;
		*envsizep = 1;
	}

	/*
	 * Find the slot where the value should be stored.  If the variable
	 * already exists, we reuse the slot; otherwise we append a new slot
	 * at the end of the array, expanding if necessary.
	 */
	env = *envp;
	namelen = strlen(name);
	ପାଇଁ (i = 0; env[i]; i++)
		ଯଦି (strncmp(env[i], name, namelen) == 0 && env[i][namelen] == '=')
			ଭାଙ୍ଗ;
	ଯଦି (env[i]) {
		/* Reuse the slot. */
		ମୁକ୍ତ(env[i]);
	} ଅନ୍ୟଥା {
		/* New variable.  Expand if necessary. */
		envsize = *envsizep;
		ଯଦି (i >= envsize - 1) {
			ଯଦି (envsize >= 1000)
				fatal("child_set_env: too many env vars");
			envsize += 50;
			env = (*envp) = xreallocarray(env, envsize, ଆକାର(ଅକ୍ଷର *));
			*envsizep = envsize;
		}
		/* Need to set the NULL pointer at end of array beyond the new slot. */
		env[i + 1] = ଖାଲି;
	}

	/* Allocate space and format the variable in the appropriate slot. */
	/* XXX xasprintf */
	env[i] = xmalloc(strlen(name) + 1 + strlen(ମୂଲ୍ୟ) + 1);
	snprintf(env[i], strlen(name) + 1 + strlen(ମୂଲ୍ୟ) + 1, "%s=%s", name, ମୂଲ୍ୟ);
}

/*
 * Check and optionally lowercase a domain name, also removes trailing '.'
 * Returns 1 on success and 0 on failure, storing an error message in errstr.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
valid_domain(ଅକ୍ଷର *name, ପୂର୍ଣ୍ଣସଂଖ୍ୟା makelower, ଅଚଳ ଅକ୍ଷର **errstr)
{
	size_t i, l = strlen(name);
	u_char c, last = '\0';
	ସ୍ଥିର ଅକ୍ଷର errbuf[256];

	ଯଦି (l == 0) {
		strlcpy(errbuf, "empty domain name", ଆକାର(errbuf));
		ଯାଅ bad;
	}
	ଯଦି (!isalpha((u_char)name[0]) && !isdigit((u_char)name[0]) &&
	   name[0] != '_' /* technically invalid, but common */) {
		snprintf(errbuf, ଆକାର(errbuf), "domain name \"%.100s\" "
		    "starts with invalid character", name);
		ଯାଅ bad;
	}
	ପାଇଁ (i = 0; i < l; i++) {
		c = tolower((u_char)name[i]);
		ଯଦି (makelower)
			name[i] = (ଅକ୍ଷର)c;
		ଯଦି (last == '.' && c == '.') {
			snprintf(errbuf, ଆକାର(errbuf), "domain name "
			    "\"%.100s\" contains consecutive separators", name);
			ଯାଅ bad;
		}
		ଯଦି (c != '.' && c != '-' && !isalnum(c) &&
		    c != '_') /* technically invalid, but common */ {
			snprintf(errbuf, ଆକାର(errbuf), "domain name "
			    "\"%.100s\" contains invalid characters", name);
			ଯାଅ bad;
		}
		last = c;
	}
	ଯଦି (name[l - 1] == '.')
		name[l - 1] = '\0';
	ଯଦି (errstr != ଖାଲି)
		*errstr = ଖାଲି;
	ଫେରନ୍ତୁ 1;
bad:
	ଯଦି (errstr != ଖାଲି)
		*errstr = errbuf;
	ଫେରନ୍ତୁ 0;
}

/*
 * Verify that a environment variable name (not including initial '$') is
 * valid; consisting of one or more alphanumeric or underscore characters only.
 * Returns 1 on valid, 0 otherwise.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
valid_env_name(ଅଚଳ ଅକ୍ଷର *name)
{
	ଅଚଳ ଅକ୍ଷର *cp;

	ଯଦି (name[0] == '\0')
		ଫେରନ୍ତୁ 0;
	ପାଇଁ (cp = name; *cp != '\0'; cp++) {
		ଯଦି (!isalnum((u_char)*cp) && *cp != '_')
			ଫେରନ୍ତୁ 0;
	}
	ଫେରନ୍ତୁ 1;
}

ଅଚଳ ଅକ୍ଷର *
atoi_err(ଅଚଳ ଅକ୍ଷର *nptr, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *val)
{
	ଅଚଳ ଅକ୍ଷର *errstr = ଖାଲି;

	ଯଦି (nptr == ଖାଲି || *nptr == '\0')
		ଫେରନ୍ତୁ "missing";
	*val = strtonum(nptr, 0, INT_MAX, &errstr);
	ଫେରନ୍ତୁ errstr;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
parse_absolute_time(ଅଚଳ ଅକ୍ଷର *s, uint64_t *tp)
{
	ସଂରଚନା tm tm;
	time_t tt;
	ଅକ୍ଷର buf[32], *fmt;
	ଅଚଳ ଅକ୍ଷର *cp;
	size_t l;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା is_utc = 0;

	*tp = 0;

	l = strlen(s);
	ଯଦି (l > 1 && strcasecmp(s + l - 1, "Z") == 0) {
		is_utc = 1;
		l--;
	} ଅନ୍ୟଥା ଯଦି (l > 3 && strcasecmp(s + l - 3, "UTC") == 0) {
		is_utc = 1;
		l -= 3;
	}
	/*
	 * POSIX strptime says "The application shall ensure that there
	 * is white-space or other non-alphanumeric characters between
	 * any two conversion specifications" so arrange things this way.
	 */
	ବାଛ (l) {
	ସ୍ଥିତି 8: /* YYYYMMDD */
		fmt = "%Y-%m-%d";
		snprintf(buf, ଆକାର(buf), "%.4s-%.2s-%.2s", s, s + 4, s + 6);
		ଭାଙ୍ଗ;
	ସ୍ଥିତି 12: /* YYYYMMDDHHMM */
		fmt = "%Y-%m-%dT%H:%M";
		snprintf(buf, ଆକାର(buf), "%.4s-%.2s-%.2sT%.2s:%.2s",
		    s, s + 4, s + 6, s + 8, s + 10);
		ଭାଙ୍ଗ;
	ସ୍ଥିତି 14: /* YYYYMMDDHHMMSS */
		fmt = "%Y-%m-%dT%H:%M:%S";
		snprintf(buf, ଆକାର(buf), "%.4s-%.2s-%.2sT%.2s:%.2s:%.2s",
		    s, s + 4, s + 6, s + 8, s + 10, s + 12);
		ଭାଙ୍ଗ;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		ଫେରନ୍ତୁ SSH_ERR_INVALID_FORMAT;
	}

	memset(&tm, 0, ଆକାର(tm));
	ଯଦି ((cp = strptime(buf, fmt, &tm)) == ଖାଲି || *cp != '\0')
		ଫେରନ୍ତୁ SSH_ERR_INVALID_FORMAT;
	ଯଦି (is_utc) {
		tm.tm_wday = -1;	/* sentinel for error */
		ଯଦି ((tt = timegm(&tm)) == -1 && tm.tm_wday == -1)
			ଫେରନ୍ତୁ SSH_ERR_INVALID_FORMAT;
	} ଅନ୍ୟଥା {
		tm.tm_wday = -1;	/* sentinel for error */
		tm.tm_isdst = -1;	/* mktime decides DST */
		ଯଦି ((tt = mktime(&tm)) == -1 && tm.tm_wday == -1)
			ଫେରନ୍ତୁ SSH_ERR_INVALID_FORMAT;
	}
	/* success */
	*tp = (uint64_t)tt;
	ଫେରନ୍ତୁ 0;
}

ଶୂନ୍ୟ
format_absolute_time(uint64_t t, ଅକ୍ଷର *buf, size_t len)
{
	time_t tt = t > SSH_TIME_T_MAX ? SSH_TIME_T_MAX : t;
	ସଂରଚନା tm tm;

	ଯଦି (localtime_r(&tt, &tm) == ଖାଲି)
		strlcpy(buf, "UNKNOWN-TIME", len);
	ଅନ୍ୟଥା
		strftime(buf, len, "%Y-%m-%dT%H:%M:%S", &tm);
}

/*
 * Parse a "pattern=interval" clause (e.g. a ChannelTimeout).
 * Returns 0 on success or non-zero on failure.
 * Caller must free *typep.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
parse_pattern_interval(ଅଚଳ ଅକ୍ଷର *s, ଅକ୍ଷର **typep, ଦ୍ୱିଗୁଣ *secsp)
{
	ଅକ୍ଷର *cp, *sdup;
	ଦ୍ୱିଗୁଣ secs;

	ଯଦି (typep != ଖାଲି)
		*typep = ଖାଲି;
	ଯଦି (secsp != ଖାଲି)
		*secsp = 0;
	ଯଦି (s == ଖାଲି)
		ଫେରନ୍ତୁ -1;
	sdup = xstrdup(s);

	ଯଦି ((cp = strchr(sdup, '=')) == ଖାଲି || cp == sdup) {
		ମୁକ୍ତ(sdup);
		ଫେରନ୍ତୁ -1;
	}
	*cp++ = '\0';
	ଯଦି ((secs = convtime_double(cp)) < 0.0) {
		ମୁକ୍ତ(sdup);
		ଫେରନ୍ତୁ -1;
	}
	/* success */
	ଯଦି (typep != ଖାଲି)
		*typep = xstrdup(sdup);
	ଯଦି (secsp != ଖାଲି)
		*secsp = secs;
	ମୁକ୍ତ(sdup);
	ଫେରନ୍ତୁ 0;
}

/* check if path is absolute */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
path_absolute(ଅଚଳ ଅକ୍ଷର *path)
{
	ଫେରନ୍ତୁ (*path == '/') ? 1 : 0;
}

ଶୂନ୍ୟ
skip_space(ଅକ୍ଷର **cpp)
{
	ଅକ୍ଷର *cp;

	ପାଇଁ (cp = *cpp; *cp == ' ' || *cp == '\t'; cp++)
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
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
opt_flag(ଅଚଳ ଅକ୍ଷର *opt, ପୂର୍ଣ୍ଣସଂଖ୍ୟା allow_negate, ଅଚଳ ଅକ୍ଷର **optsp)
{
	size_t opt_len = strlen(opt);
	ଅଚଳ ଅକ୍ଷର *opts = *optsp;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା negate = 0;

	ଯଦି (allow_negate && strncasecmp(opts, "no-", 3) == 0) {
		opts += 3;
		negate = 1;
	}
	ଯଦି (strncasecmp(opts, opt, opt_len) == 0) {
		*optsp = opts + opt_len;
		ଫେରନ୍ତୁ negate ? 0 : 1;
	}
	ଫେରନ୍ତୁ -1;
}

ଅକ୍ଷର *
opt_dequote(ଅଚଳ ଅକ୍ଷର **sp, ଅଚଳ ଅକ୍ଷର **errstrp)
{
	ଅଚଳ ଅକ୍ଷର *s = *sp;
	ଅକ୍ଷର *ret;
	size_t i;

	*errstrp = ଖାଲି;
	ଯଦି (*s != '"') {
		*errstrp = "missing start quote";
		ଫେରନ୍ତୁ ଖାଲି;
	}
	s++;
	ଯଦି ((ret = malloc(strlen((s)) + 1)) == ଖାଲି) {
		*errstrp = "memory allocation failed";
		ଫେରନ୍ତୁ ଖାଲି;
	}
	ପାଇଁ (i = 0; *s != '\0' && *s != '"';) {
		ଯଦି (s[0] == '\\' && s[1] == '"')
			s++;
		ret[i++] = *s++;
	}
	ଯଦି (*s == '\0') {
		*errstrp = "missing end quote";
		ମୁକ୍ତ(ret);
		ଫେରନ୍ତୁ ଖାଲି;
	}
	ret[i] = '\0';
	s++;
	*sp = s;
	ଫେରନ୍ତୁ ret;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
opt_match(ଅଚଳ ଅକ୍ଷର **opts, ଅଚଳ ଅକ୍ଷର *term)
{
	ଯଦି (strncasecmp((*opts), term, strlen(term)) == 0 &&
	    (*opts)[strlen(term)] == '=') {
		*opts += strlen(term) + 1;
		ଫେରନ୍ତୁ 1;
	}
	ଫେରନ୍ତୁ 0;
}

ଶୂନ୍ୟ
opt_array_append2(ଅଚଳ ଅକ୍ଷର *file, ଅଚଳ ପୂର୍ଣ୍ଣସଂଖ୍ୟା ଧାଡ଼ି, ଅଚଳ ଅକ୍ଷର *directive,
    ଅକ୍ଷର ***array, ପୂର୍ଣ୍ଣସଂଖ୍ୟା **iarray, u_int *lp, ଅଚଳ ଅକ୍ଷର *s, ପୂର୍ଣ୍ଣସଂଖ୍ୟା i)
{

	ଯଦି (*lp >= INT_MAX)
		fatal("%s line %d: Too many %s entries", file, ଧାଡ଼ି, directive);

	ଯଦି (iarray != ଖାଲି) {
		*iarray = xrecallocarray(*iarray, *lp, *lp + 1,
		    ଆକାର(**iarray));
		(*iarray)[*lp] = i;
	}

	*array = xrecallocarray(*array, *lp, *lp + 1, ଆକାର(**array));
	(*array)[*lp] = xstrdup(s);
	(*lp)++;
}

ଶୂନ୍ୟ
opt_array_append(ଅଚଳ ଅକ୍ଷର *file, ଅଚଳ ପୂର୍ଣ୍ଣସଂଖ୍ୟା ଧାଡ଼ି, ଅଚଳ ଅକ୍ଷର *directive,
    ଅକ୍ଷର ***array, u_int *lp, ଅଚଳ ଅକ୍ଷର *s)
{
	opt_array_append2(file, ଧାଡ଼ି, directive, array, ଖାଲି, lp, s, 0);
}

ଶୂନ୍ୟ
opt_array_free2(ଅକ୍ଷର **array, ପୂର୍ଣ୍ଣସଂଖ୍ୟା **iarray, u_int l)
{
	u_int i;

	ଯଦି (array == ଖାଲି || l == 0)
		ଫେରନ୍ତୁ;
	ପାଇଁ (i = 0; i < l; i++)
		ମୁକ୍ତ(array[i]);
	ମୁକ୍ତ(array);
	ମୁକ୍ତ(iarray);
}

sshsig_t
ssh_signal(ପୂର୍ଣ୍ଣସଂଖ୍ୟା signum, sshsig_t handler)
{
	ସଂରଚନା sigaction sa, osa;

	/* mask all other signals while in handler */
	memset(&sa, 0, ଆକାର(sa));
	sa.sa_handler = handler;
	sigfillset(&sa.sa_mask);
#ଯଦି defined(SA_RESTART) && !defined(NO_SA_RESTART)
	ଯଦି (signum != SIGALRM)
		sa.sa_flags = SA_RESTART;
#endif
	ଯଦି (sigaction(signum, &sa, &osa) == -1) {
		debug3("sigaction(%s): %s", strsignal(signum), strerror(errno));
		ଫେରନ୍ତୁ SIG_ERR;
	}
	ଫେରନ୍ତୁ osa.sa_handler;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
stdfd_devnull(ପୂର୍ଣ୍ଣସଂଖ୍ୟା do_stdin, ପୂର୍ଣ୍ଣସଂଖ୍ୟା do_stdout, ପୂର୍ଣ୍ଣସଂଖ୍ୟା do_stderr)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା devnull, ret = 0;

	ଯଦି ((devnull = open(_PATH_DEVNULL, O_RDWR)) == -1) {
		error_f("open %s: %s", _PATH_DEVNULL,
		    strerror(errno));
		ଫେରନ୍ତୁ -1;
	}
	ଯଦି ((do_stdin && dup2(devnull, STDIN_FILENO) == -1) ||
	    (do_stdout && dup2(devnull, STDOUT_FILENO) == -1) ||
	    (do_stderr && dup2(devnull, STDERR_FILENO) == -1)) {
		error_f("dup2: %s", strerror(errno));
		ret = -1;
	}
	ଯଦି (devnull > STDERR_FILENO)
		close(devnull);
	ଫେରନ୍ତୁ ret;
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
subprocess(ଅଚଳ ଅକ୍ଷର *tag, ଅଚଳ ଅକ୍ଷର *command,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା ac, ଅକ୍ଷର **av, FILE **child, u_int flags,
    ସଂରଚନା passwd *pw, privdrop_fn *drop_privs, privrestore_fn *restore_privs)
{
	FILE *f = ଖାଲି;
	ସଂରଚନା stat st;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd, devnull, p[2], i;
	pid_t pid;
	ଅକ୍ଷର *cp, errmsg[512];
	u_int nenv = 0;
	ଅକ୍ଷର **env = ଖାଲି;

	/* If dropping privs, then must specify user and restore function */
	ଯଦି (drop_privs != ଖାଲି && (pw == ଖାଲି || restore_privs == ଖାଲି)) {
		error("%s: inconsistent arguments", tag); /* XXX fatal? */
		ଫେରନ୍ତୁ 0;
	}
	ଯଦି (pw == ଖାଲି && (pw = getpwuid(getuid())) == ଖାଲି) {
		error("%s: no user for current uid", tag);
		ଫେରନ୍ତୁ 0;
	}
	ଯଦି (child != ଖାଲି)
		*child = ଖାଲି;

	debug3_f("%s command \"%s\" running as %s (flags 0x%x)",
	    tag, command, pw->pw_name, flags);

	/* Check consistency */
	ଯଦି ((flags & SSH_SUBPROCESS_STDOUT_DISCARD) != 0 &&
	    (flags & SSH_SUBPROCESS_STDOUT_CAPTURE) != 0) {
		error_f("inconsistent flags");
		ଫେରନ୍ତୁ 0;
	}
	ଯଦି (((flags & SSH_SUBPROCESS_STDOUT_CAPTURE) == 0) != (child == ଖାଲି)) {
		error_f("inconsistent flags/output");
		ଫେରନ୍ତୁ 0;
	}

	/*
	 * If executing an explicit binary, then verify the it exists
	 * and appears safe-ish to execute
	 */
	ଯଦି (!path_absolute(av[0])) {
		error("%s path is not absolute", tag);
		ଫେରନ୍ତୁ 0;
	}
	ଯଦି (drop_privs != ଖାଲି)
		drop_privs(pw);
	ଯଦି (stat(av[0], &st) == -1) {
		error("Could not stat %s \"%s\": %s", tag,
		    av[0], strerror(errno));
		ଯାଅ restore_return;
	}
	ଯଦି ((flags & SSH_SUBPROCESS_UNSAFE_PATH) == 0 &&
	    safe_path(av[0], &st, ଖାଲି, 0, errmsg, ଆକାର(errmsg)) != 0) {
		error("Unsafe %s \"%s\": %s", tag, av[0], errmsg);
		ଯାଅ restore_return;
	}
	/* Prepare to keep the child's stdout if requested */
	ଯଦି (pipe(p) == -1) {
		error("%s: pipe: %s", tag, strerror(errno));
 restore_return:
		ଯଦି (restore_privs != ଖାଲି)
			restore_privs();
		ଫେରନ୍ତୁ 0;
	}
	ଯଦି (restore_privs != ଖାଲି)
		restore_privs();

	ବାଛ ((pid = fork())) {
	ସ୍ଥିତି -1: /* error */
		error("%s: fork: %s", tag, strerror(errno));
		close(p[0]);
		close(p[1]);
		ଫେରନ୍ତୁ 0;
	ସ୍ଥିତି 0: /* child */
		/* Prepare a minimal environment for the child. */
		ଯଦି ((flags & SSH_SUBPROCESS_PRESERVE_ENV) == 0) {
			nenv = 5;
			env = xcalloc(ଆକାର(*env), nenv);
			child_set_env(&env, &nenv, "PATH", _PATH_STDPATH);
			child_set_env(&env, &nenv, "USER", pw->pw_name);
			child_set_env(&env, &nenv, "LOGNAME", pw->pw_name);
			child_set_env(&env, &nenv, "HOME", pw->pw_dir);
			ଯଦି ((cp = getenv("LANG")) != ଖାଲି)
				child_set_env(&env, &nenv, "LANG", cp);
		}

		ପାଇଁ (i = 1; i < NSIG; i++)
			ssh_signal(i, SIG_DFL);

		ଯଦି ((devnull = open(_PATH_DEVNULL, O_RDWR)) == -1) {
			error("%s: open %s: %s", tag, _PATH_DEVNULL,
			    strerror(errno));
			_exit(1);
		}
		ଯଦି (dup2(devnull, STDIN_FILENO) == -1) {
			error("%s: dup2: %s", tag, strerror(errno));
			_exit(1);
		}

		/* Set up stdout as requested; leave stderr in place for now. */
		fd = -1;
		ଯଦି ((flags & SSH_SUBPROCESS_STDOUT_CAPTURE) != 0)
			fd = p[1];
		ଅନ୍ୟଥା ଯଦି ((flags & SSH_SUBPROCESS_STDOUT_DISCARD) != 0)
			fd = devnull;
		ଯଦି (fd != -1 && dup2(fd, STDOUT_FILENO) == -1) {
			error("%s: dup2: %s", tag, strerror(errno));
			_exit(1);
		}
		closefrom(STDERR_FILENO + 1);

		ଯଦି (geteuid() == 0 &&
		    initgroups(pw->pw_name, pw->pw_gid) == -1) {
			error("%s: initgroups(%s, %u): %s", tag,
			    pw->pw_name, (u_int)pw->pw_gid, strerror(errno));
			_exit(1);
		}
		ଯଦି (setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) == -1) {
			error("%s: setresgid %u: %s", tag, (u_int)pw->pw_gid,
			    strerror(errno));
			_exit(1);
		}
		ଯଦି (setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) == -1) {
			error("%s: setresuid %u: %s", tag, (u_int)pw->pw_uid,
			    strerror(errno));
			_exit(1);
		}
		/* stdin is pointed to /dev/null at this point */
		ଯଦି ((flags & SSH_SUBPROCESS_STDOUT_DISCARD) != 0 &&
		    dup2(STDIN_FILENO, STDERR_FILENO) == -1) {
			error("%s: dup2: %s", tag, strerror(errno));
			_exit(1);
		}
		ଯଦି (env != ଖାଲି)
			execve(av[0], av, env);
		ଅନ୍ୟଥା
			execv(av[0], av);
		error("%s %s \"%s\": %s", tag, env == ଖାଲି ? "execv" : "execve",
		    command, strerror(errno));
		_exit(127);
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ: /* parent */
		ଭାଙ୍ଗ;
	}

	close(p[1]);
	ଯଦି ((flags & SSH_SUBPROCESS_STDOUT_CAPTURE) == 0)
		close(p[0]);
	ଅନ୍ୟଥା ଯଦି ((f = fdopen(p[0], "r")) == ଖାଲି) {
		error("%s: fdopen: %s", tag, strerror(errno));
		close(p[0]);
		/* Don't leave zombie child */
		kill(pid, SIGTERM);
		ଯେତେବେଳେ (waitpid(pid, ଖାଲି, 0) == -1 && errno == EINTR)
			;
		ଫେରନ୍ତୁ 0;
	}
	/* Success */
	debug3_f("%s pid %ld", tag, (long)pid);
	ଯଦି (child != ଖାଲି)
		*child = f;
	ଫେରନ୍ତୁ pid;
}

ଅଚଳ ଅକ୍ଷର *
lookup_env_in_list(ଅଚଳ ଅକ୍ଷର *env, ଅକ୍ଷର * ଅଚଳ *envs, size_t nenvs)
{
	size_t i, envlen;

	envlen = strlen(env);
	ପାଇଁ (i = 0; i < nenvs; i++) {
		ଯଦି (strncmp(envs[i], env, envlen) == 0 &&
		    envs[i][envlen] == '=') {
			ଫେରନ୍ତୁ envs[i] + envlen + 1;
		}
	}
	ଫେରନ୍ତୁ ଖାଲି;
}

ଅଚଳ ଅକ୍ଷର *
lookup_setenv_in_list(ଅଚଳ ଅକ୍ଷର *env, ଅକ୍ଷର * ଅଚଳ *envs, size_t nenvs)
{
	ଅକ୍ଷର *name, *cp;
	ଅଚଳ ଅକ୍ଷର *ret;

	name = xstrdup(env);
	ଯଦି ((cp = strchr(name, '=')) == ଖାଲି) {
		ମୁକ୍ତ(name);
		ଫେରନ୍ତୁ ଖାଲି; /* not env=val */
	}
	*cp = '\0';
	ret = lookup_env_in_list(name, envs, nenvs);
	ମୁକ୍ତ(name);
	ଫେରନ୍ତୁ ret;
}

/*
 * Helpers for managing poll(2)/ppoll(2) timeouts
 * Will remember the earliest deadline and return it for use in poll/ppoll.
 */

/* Initialise a poll/ppoll timeout with an indefinite deadline */
ଶୂନ୍ୟ
ptimeout_init(ସଂରଚନା timespec *pt)
{
	/*
	 * Deliberately invalid for ppoll(2).
	 * Will be converted to NULL in ptimeout_get_tspec() later.
	 */
	pt->tv_sec = -1;
	pt->tv_nsec = 0;
}

/* Specify a poll/ppoll deadline of at most 'sec' seconds */
ଶୂନ୍ୟ
ptimeout_deadline_sec(ସଂରଚନା timespec *pt, long sec)
{
	ଯଦି (pt->tv_sec == -1 || pt->tv_sec >= sec) {
		pt->tv_sec = sec;
		pt->tv_nsec = 0;
	}
}

/* Specify a poll/ppoll deadline of at most 'p' (timespec) */
ସ୍ଥିର ଶୂନ୍ୟ
ptimeout_deadline_tsp(ସଂରଚନା timespec *pt, ସଂରଚନା timespec *p)
{
	ଯଦି (pt->tv_sec == -1 || timespeccmp(pt, p, >=))
		*pt = *p;
}

/* Specify a poll/ppoll deadline of at most 'ms' milliseconds */
ଶୂନ୍ୟ
ptimeout_deadline_ms(ସଂରଚନା timespec *pt, long ms)
{
	ସଂରଚନା timespec p;

	p.tv_sec = ms / 1000;
	p.tv_nsec = (ms % 1000) * 1000000;
	ptimeout_deadline_tsp(pt, &p);
}

/* Specify a poll/ppoll deadline of at most 'sec' seconds (double) */
ଶୂନ୍ୟ
ptimeout_deadline_sec_double(ସଂରଚନା timespec *pt, ଦ୍ୱିଗୁଣ sec)
{
	ସଂରଚନା timespec t;

	memset(&t, 0, ଆକାର(t));
	ଯଦି ((int64_t)sec >= SSH_TIME_T_MAX)
		t.tv_sec = SSH_TIME_T_MAX;
	ଅନ୍ୟଥା ଯଦି (sec > 0) {
		t.tv_sec = sec;
		t.tv_nsec = (sec - (ଦ୍ୱିଗୁଣ)t.tv_sec) * 1000000000.0;
	}
	ptimeout_deadline_tsp(pt, &t);
}

/* Specify a poll/ppoll deadline at wall clock monotime 'when' (timespec) */
ଶୂନ୍ୟ
ptimeout_deadline_monotime_tsp(ସଂରଚନା timespec *pt, ସଂରଚନା timespec *when)
{
	ସଂରଚନା timespec now, t;

	monotime_ts(&now);

	ଯଦି (timespeccmp(&now, when, >=)) {
		/* 'when' is now or in the past. Timeout ASAP */
		pt->tv_sec = 0;
		pt->tv_nsec = 0;
	} ଅନ୍ୟଥା {
		timespecsub(when, &now, &t);
		ptimeout_deadline_tsp(pt, &t);
	}
}

/* Specify a poll/ppoll deadline at wall clock monotime 'when' (double) */
ଶୂନ୍ୟ
ptimeout_deadline_monotime_double(ସଂରଚନା timespec *pt, ଦ୍ୱିଗୁଣ when)
{
	ptimeout_deadline_sec_double(pt, when - monotime_double());
}

/* Specify a poll/ppoll deadline at wall clock monotime 'when' */
ଶୂନ୍ୟ
ptimeout_deadline_monotime(ସଂରଚନା timespec *pt, time_t when)
{
	ସଂରଚନା timespec t;

	t.tv_sec = when;
	t.tv_nsec = 0;
	ptimeout_deadline_monotime_tsp(pt, &t);
}

/* Get a poll(2) timeout value in milliseconds */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ptimeout_get_ms(ସଂରଚନା timespec *pt)
{
	ଯଦି (pt->tv_sec == -1)
		ଫେରନ୍ତୁ -1;
	ଯଦି (pt->tv_sec >= (INT_MAX - (pt->tv_nsec / 1000000)) / 1000)
		ଫେରନ୍ତୁ INT_MAX;
	ଫେରନ୍ତୁ (pt->tv_sec * 1000) + (pt->tv_nsec / 1000000);
}

/* Get a ppoll(2) timeout value as a timespec pointer */
ସଂରଚନା timespec *
ptimeout_get_tsp(ସଂରଚନା timespec *pt)
{
	ଫେରନ୍ତୁ pt->tv_sec == -1 ? ଖାଲି : pt;
}

/* Returns non-zero if a timeout has been set (i.e. is not indefinite) */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ptimeout_isset(ସଂରଚନା timespec *pt)
{
	ଫେରନ୍ତୁ pt->tv_sec != -1;
}

/*
 * Returns zero if the library at 'path' contains symbol 's', nonzero
 * otherwise.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
lib_contains_ପ୍ରତୀକ(ଅଚଳ ଅକ୍ଷର *path, ଅଚଳ ଅକ୍ଷର *s)
{
#ifdef HAVE_NLIST
	ସଂରଚନା nlist nl[2];
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret = -1, r;

	memset(nl, 0, ଆକାର(nl));
	nl[0].n_name = xstrdup(s);
	nl[1].n_name = ଖାଲି;
	ଯଦି ((r = nlist(path, nl)) == -1) {
		error_f("nlist failed for %s", path);
		ଯାଅ out;
	}
	ଯଦି (r != 0 || nl[0].n_ମୂଲ୍ୟ == 0 || nl[0].n_type == 0) {
		error_f("library %s does not contain symbol %s", path, s);
		ଯାଅ out;
	}
	/* success */
	ret = 0;
 out:
	ମୁକ୍ତ(nl[0].n_name);
	ଫେରନ୍ତୁ ret;
#ଅନ୍ୟଥା /* HAVE_NLIST */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd, ret = -1;
	ସଂରଚନା stat st;
	ଶୂନ୍ୟ *m = ଖାଲି;
	size_t sz = 0;

	memset(&st, 0, ଆକାର(st));
	ଯଦି ((fd = open(path, O_RDONLY)) < 0) {
		error_f("open %s: %s", path, strerror(errno));
		ଫେରନ୍ତୁ -1;
	}
	ଯଦି (fstat(fd, &st) != 0) {
		error_f("fstat %s: %s", path, strerror(errno));
		ଯାଅ out;
	}
	ଯଦି (!S_ISREG(st.st_mode)) {
		error_f("%s is not a regular file", path);
		ଯାଅ out;
	}
	ଯଦି (st.st_size < 0 ||
	    (size_t)st.st_size < strlen(s) ||
	    st.st_size >= INT_MAX/2) {
		error_f("%s bad size %lld", path, (long long)st.st_size);
		ଯାଅ out;
	}
	sz = (size_t)st.st_size;
	ଯଦି ((m = mmap(ଖାଲି, sz, PROT_READ, MAP_PRIVATE, fd, 0)) == MAP_FAILED ||
	    m == ଖାଲି) {
		error_f("mmap %s: %s", path, strerror(errno));
		ଯାଅ out;
	}
	ଯଦି (memmem(m, sz, s, strlen(s)) == ଖାଲି) {
		error_f("%s does not contain expected string %s", path, s);
		ଯାଅ out;
	}
	/* success */
	ret = 0;
 out:
	ଯଦି (m != ଖାଲି && m != MAP_FAILED)
		munmap(m, sz);
	close(fd);
	ଫେରନ୍ତୁ ret;
#endif /* HAVE_NLIST */
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
signal_is_crash(ପୂର୍ଣ୍ଣସଂଖ୍ୟା sig)
{
	ବାଛ (sig) {
	ସ୍ଥିତି SIGSEGV:
	ସ୍ଥିତି SIGBUS:
	ସ୍ଥିତି SIGTRAP:
	ସ୍ଥିତି SIGSYS:
	ସ୍ଥିତି SIGFPE:
	ସ୍ଥିତି SIGILL:
	ସ୍ଥିତି SIGABRT:
		ଫେରନ୍ତୁ 1;
	}
	ଫେରନ୍ତୁ 0;
}

ଅକ୍ଷର *
get_homedir(ଶୂନ୍ୟ)
{
	ଅକ୍ଷର *cp;
	ସଂରଚନା passwd *pw;

	ଯଦି ((cp = getenv("HOME")) != ଖାଲି && *cp != '\0')
		ଫେରନ୍ତୁ xstrdup(cp);

	ଯଦି ((pw = getpwuid(getuid())) != ଖାଲି && *pw->pw_dir != '\0')
		ଫେରନ୍ତୁ xstrdup(pw->pw_dir);

	ଫେରନ୍ତୁ ଖାଲି;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mkdir_path(ଅଚଳ ଅକ୍ଷର *target, mode_t mode)
{
#ଯଦି defined(HAVE_OPENAT) && defined(O_DIRECTORY)
	ଅକ୍ଷର *dir, *odir = ଖାଲି, *next;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd = AT_FDCWD, fd2, subpath_len, ret = -1;

	dir = odir = xstrdup(target);

	ଯଦି (*dir == '/' &&
	    (fd = open("/", O_RDONLY|O_DIRECTORY)) == -1) {
		error_f("open(\"/\"): %s", strerror(errno));
		ମୁକ୍ତ(odir);
		ଫେରନ୍ତୁ -1;
	}
	/* Work through the path, component-wise */
	ପାଇଁ (; dir != ଖାଲି && *dir != '\0'; dir = next) {
		ଯଦି ((next = strchr(dir, '/')) != ଖାଲି)
			*(next++) = '\0';
		ଯଦି (*dir == '\0')
			ଜାରି;
		subpath_len = (next == ଖାଲି) ? INT_MAX : next - odir - 1;
		ଯଦି (mkdirat(fd, dir, mode) == 0)
			debug_f("created directory %.*s", subpath_len, target);
		ଅନ୍ୟଥା ଯଦି (errno != EEXIST) {
			error_f("mkdir(\"%.*s\"): %s",
			    subpath_len, target, strerror(errno));
			ଯାଅ out;
		}

		/* descend */
		ଯଦି ((fd2 = openat(fd, dir, O_RDONLY|O_DIRECTORY)) == -1) {
			error_f("open(\"%.*s\"): %s",
			    subpath_len, target, strerror(errno));
			ଯାଅ out;
		}
		ଯଦି (fd != AT_FDCWD)
			close(fd);
		fd = fd2;
	}
	/* success */
	ret = 0;
 out:
	ମୁକ୍ତ(odir);
	ଯଦି (fd != AT_FDCWD)
		close(fd);
	ଫେରନ୍ତୁ ret;
#ଅନ୍ୟଥା
	/*
	 * If we don't have openat (which was added in POSIX.1-2008), fall back
	 * to the possibly racy way.
	 */
	ଅକ୍ଷର *dir, *odir, *p, path[PATH_MAX] = "";
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret = -1;
	size_t plen = ଆକାର(path);

	dir = odir = xstrdup(target);

	/* If the dir is relative, start with cwd. */
	ଯଦି (*dir != '/' && getcwd(path, plen) == ଖାଲି) {
		error_f("getcwd: %s", strerror(errno));
		ଯାଅ out;
	}

	/* Work through the path, component-wise */
	ଯେତେବେଳେ ((p = strsep(&dir, "/"))) {
		ଯଦି (*p == '\0')
			ଜାରି;
		ଯଦି (strlcat(path, "/", plen) >= plen ||
		    strlcat(path, p, plen) >= plen)
			ଯାଅ out;
		ଯଦି (mkdir(path, mode) == 0)
			debug_f("created directory %s", path);
		ଅନ୍ୟଥା ଯଦି (errno != EEXIST && errno != EISDIR) {
			error_f("mkdir(\"%s\"): %s", path, strerror(errno));
			ଯାଅ out;
		}
	}
	/* success */
	ret = 0;
 out:
	ମୁକ୍ତ(odir);
	ଫେରନ୍ତୁ ret;
#endif
}
