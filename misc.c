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


#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <sys/ioctl.h>
#অন্তর্ভাব <sys/mman.h>
#অন্তর্ভাব <sys/socket.h>
#অন্তর্ভাব <sys/stat.h>
#অন্তর্ভাব <sys/time.h>
#অন্তর্ভাব <sys/wait.h>
#অন্তর্ভাব <sys/un.h>

#অন্তর্ভাব <limits.h>
#অন্তর্ভাব <libgen.h>
#অন্তর্ভাব <poll.h>
#অন্তর্ভাব <nlist.h>
#অন্তর্ভাব <signal.h>
#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdint.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <time.h>
#অন্তর্ভাব <unistd.h>

#অন্তর্ভাব <netinet/in.h>
#অন্তর্ভাব <netinet/ip.h>
#অন্তর্ভাব <netinet/tcp.h>
#অন্তর্ভাব <arpa/inet.h>

#অন্তর্ভাব <ctype.h>
#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <fcntl.h>
#অন্তর্ভাব <netdb.h>
#অন্তর্ভাব <paths.h>
#অন্তর্ভাব <pwd.h>
#অন্তর্ভাব <grp.h>
#ifdef SSH_TUN_OPENBSD
#অন্তর্ভাব <net/if.h>
#endif

#অন্তর্ভাব "xmalloc.h"
#অন্তর্ভাব "misc.h"
#অন্তর্ভাব "log.h"
#অন্তর্ভাব "ssh.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "platform.h"

/* remove newline at end of string */
বর্ণ *
chop(বর্ণ *s)
{
	বর্ণ *t = s;
	যাবত্ (*t) {
		যদি (*t == '\n' || *t == '\r') {
			*t = '\0';
			প্রত্যাগম s;
		}
		t++;
	}
	প্রত্যাগম s;

}

/* remove whitespace from end of string */
শূন্য
rtrim(বর্ণ *s)
{
	size_t i;

	যদি ((i = strlen(s)) == 0)
		প্রত্যাগম;
	কুরু {
		i--;
		যদি (isspace((unsigned বর্ণ)s[i]))
			s[i] = '\0';
		অন্যথা
			ভঙ্গ;
	} যাবত্ (i > 0);
}

/*
 * returns pointer to character after 'prefix' in 's' or otherwise NULL
 * if the prefix is not present.
 */
ধ্রুব বর্ণ *
strprefix(ধ্রুব বর্ণ *s, ধ্রুব বর্ণ *prefix, পূর্ণাঙ্ক ignorecase)
{
	size_t prefixlen;

	যদি ((prefixlen = strlen(prefix)) == 0)
		প্রত্যাগম s;
	যদি (ignorecase) {
		যদি (strncasecmp(s, prefix, prefixlen) != 0)
			প্রত্যাগম রিক্ত;
	} অন্যথা {
		যদি (strncmp(s, prefix, prefixlen) != 0)
			প্রত্যাগম রিক্ত;
	}
	প্রত্যাগম s + prefixlen;
}

/* Append string 's' to a NULL-terminated array of strings */
শূন্য
stringlist_append(বর্ণ ***listp, ধ্রুব বর্ণ *s)
{
	size_t i = 0;

	যদি (*listp == রিক্ত)
		*listp = xcalloc(2, পরিমাণ(**listp));
	অন্যথা {
		প্রতি (i = 0; (*listp)[i] != রিক্ত; i++)
			; /* count */
		*listp = xrecallocarray(*listp, i + 1, i + 2, পরিমাণ(**listp));
	}
	(*listp)[i] = xstrdup(s);
}

শূন্য
stringlist_free(বর্ণ **list)
{
	size_t i = 0;

	যদি (list == রিক্ত)
		প্রত্যাগম;
	প্রতি (i = 0; list[i] != রিক্ত; i++)
		মুক্ত(list[i]);
	মুক্ত(list);
}

/* set/unset filedescriptor to non-blocking */
পূর্ণাঙ্ক
set_nonblock(পূর্ণাঙ্ক fd)
{
	পূর্ণাঙ্ক val;

	val = fcntl(fd, F_GETFL);
	যদি (val == -1) {
		error("fcntl(%d, F_GETFL): %s", fd, strerror(errno));
		প্রত্যাগম (-1);
	}
	যদি (val & O_NONBLOCK) {
		debug3("fd %d is O_NONBLOCK", fd);
		প্রত্যাগম (0);
	}
	debug2("fd %d setting O_NONBLOCK", fd);
	val |= O_NONBLOCK;
	যদি (fcntl(fd, F_SETFL, val) == -1) {
		debug("fcntl(%d, F_SETFL, O_NONBLOCK): %s", fd,
		    strerror(errno));
		প্রত্যাগম (-1);
	}
	প্রত্যাগম (0);
}

পূর্ণাঙ্ক
unset_nonblock(পূর্ণাঙ্ক fd)
{
	পূর্ণাঙ্ক val;

	val = fcntl(fd, F_GETFL);
	যদি (val == -1) {
		error("fcntl(%d, F_GETFL): %s", fd, strerror(errno));
		প্রত্যাগম (-1);
	}
	যদি (!(val & O_NONBLOCK)) {
		debug3("fd %d is not O_NONBLOCK", fd);
		প্রত্যাগম (0);
	}
	debug("fd %d clearing O_NONBLOCK", fd);
	val &= ~O_NONBLOCK;
	যদি (fcntl(fd, F_SETFL, val) == -1) {
		debug("fcntl(%d, F_SETFL, ~O_NONBLOCK): %s",
		    fd, strerror(errno));
		প্রত্যাগম (-1);
	}
	প্রত্যাগম (0);
}

ধ্রুব বর্ণ *
ssh_gai_strerror(পূর্ণাঙ্ক gaierr)
{
	যদি (gaierr == EAI_SYSTEM && errno != 0)
		প্রত্যাগম strerror(errno);
	প্রত্যাগম gai_strerror(gaierr);
}

/* disable nagle on socket */
শূন্য
set_nodelay(পূর্ণাঙ্ক fd)
{
	পূর্ণাঙ্ক opt;
	socklen_t optlen;

	optlen = পরিমাণ opt;
	যদি (getsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, &optlen) == -1) {
		debug("getsockopt TCP_NODELAY: %.100s", strerror(errno));
		প্রত্যাগম;
	}
	যদি (opt == 1) {
		debug2("fd %d is TCP_NODELAY", fd);
		প্রত্যাগম;
	}
	opt = 1;
	debug2("fd %d setting TCP_NODELAY", fd);
	যদি (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, পরিমাণ opt) == -1)
		error("setsockopt TCP_NODELAY: %.100s", strerror(errno));
}

/* Allow local port reuse in TIME_WAIT */
পূর্ণাঙ্ক
set_reuseaddr(পূর্ণাঙ্ক fd)
{
	পূর্ণাঙ্ক on = 1;

	যদি (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, পরিমাণ(on)) == -1) {
		error("setsockopt SO_REUSEADDR fd %d: %s", fd, strerror(errno));
		প্রত্যাগম -1;
	}
	প্রত্যাগম 0;
}

/* Set TCP keepalives */
পূর্ণাঙ্ক
set_keepalive(পূর্ণাঙ্ক fd)
{
	পূর্ণাঙ্ক on = 1;

	যদি (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, পরিমাণ(on)) == -1) {
		error("setsockopt SO_KEEPALIVE fd %d: %s", fd, strerror(errno));
		প্রত্যাগম -1;
	}
	প্রত্যাগম 0;
}

/* Get/set routing domain */
বর্ণ *
get_rdomain(পূর্ণাঙ্ক fd)
{
#যদি defined(HAVE_SYS_GET_RDOMAIN)
	প্রত্যাগম sys_get_rdomain(fd);
#নোচেদ্যদি defined(__OpenBSD__)
	পূর্ণাঙ্ক rtable;
	বর্ণ *ret;
	socklen_t len = পরিমাণ(rtable);

	যদি (getsockopt(fd, SOL_SOCKET, SO_RTABLE, &rtable, &len) == -1) {
		error("Failed to get routing domain for fd %d: %s",
		    fd, strerror(errno));
		প্রত্যাগম রিক্ত;
	}
	xasprintf(&ret, "%d", rtable);
	প্রত্যাগম ret;
#অন্যথা /* defined(__OpenBSD__) */
	প্রত্যাগম রিক্ত;
#endif
}

পূর্ণাঙ্ক
set_rdomain(পূর্ণাঙ্ক fd, ধ্রুব বর্ণ *name)
{
#যদি defined(HAVE_SYS_SET_RDOMAIN)
	প্রত্যাগম sys_set_rdomain(fd, name);
#নোচেদ্যদি defined(__OpenBSD__)
	পূর্ণাঙ্ক rtable;
	ধ্রুব বর্ণ *errstr;

	যদি (name == রিক্ত)
		প্রত্যাগম 0; /* default table */

	rtable = (পূর্ণাঙ্ক)strtonum(name, 0, 255, &errstr);
	যদি (errstr != রিক্ত) {
		/* Shouldn't happen */
		error("Invalid routing domain \"%s\": %s", name, errstr);
		প্রত্যাগম -1;
	}
	যদি (setsockopt(fd, SOL_SOCKET, SO_RTABLE,
	    &rtable, পরিমাণ(rtable)) == -1) {
		error("Failed to set routing domain %d on fd %d: %s",
		    rtable, fd, strerror(errno));
		প্রত্যাগম -1;
	}
	প্রত্যাগম 0;
#অন্যথা /* defined(__OpenBSD__) */
	error("Setting routing domain is not supported on this platform");
	প্রত্যাগম -1;
#endif
}

পূর্ণাঙ্ক
get_sock_af(পূর্ণাঙ্ক fd)
{
	সংরচনা sockaddr_storage to;
	socklen_t tolen = পরিমাণ(to);

	memset(&to, 0, পরিমাণ(to));
	যদি (getsockname(fd, (সংরচনা sockaddr *)&to, &tolen) == -1)
		প্রত্যাগম -1;
#ifdef IPV4_IN_IPV6
	যদি (to.ss_family == AF_INET6 &&
	    IN6_IS_ADDR_V4MAPPED(&((সংরচনা sockaddr_in6 *)&to)->sin6_addr))
		প্রত্যাগম AF_INET;
#endif
	প্রত্যাগম to.ss_family;
}

শূন্য
set_sock_tos(পূর্ণাঙ্ক fd, পূর্ণাঙ্ক tos)
{
#ifndef IP_TOS_IS_BROKEN
	পূর্ণাঙ্ক af;

	যদি (tos < 0 || tos == INT_MAX) {
		debug_f("invalid TOS %d", tos);
		প্রত্যাগম;
	}
	বিকল্প ((af = get_sock_af(fd))) {
	পক্ষ -1:
		/* assume not a socket */
		ভঙ্গ;
	পক্ষ AF_INET:
# ifdef IP_TOS
		debug3_f("set socket %d IP_TOS 0x%02x", fd, tos);
		যদি (setsockopt(fd, IPPROTO_IP, IP_TOS,
		    &tos, পরিমাণ(tos)) == -1) {
			error("setsockopt socket %d IP_TOS %d: %s",
			    fd, tos, strerror(errno));
		}
# endif /* IP_TOS */
		ভঙ্গ;
	পক্ষ AF_INET6:
# ifdef IPV6_TCLASS
		debug3_f("set socket %d IPV6_TCLASS 0x%02x", fd, tos);
		যদি (setsockopt(fd, IPPROTO_IPV6, IPV6_TCLASS,
		    &tos, পরিমাণ(tos)) == -1) {
			error("setsockopt socket %d IPV6_TCLASS %d: %s",
			    fd, tos, strerror(errno));
		}
# endif /* IPV6_TCLASS */
		ভঙ্গ;
	স্বভাব:
		debug2_f("unsupported socket family %d", af);
		ভঙ্গ;
	}
#endif /* IP_TOS_IS_BROKEN */
}

/*
 * Wait up to *timeoutp milliseconds for events on fd. Updates
 * *timeoutp with time remaining.
 * Returns 0 if fd ready or -1 on timeout or error (see errno).
 */
স্থির পূর্ণাঙ্ক
waitfd(পূর্ণাঙ্ক fd, পূর্ণাঙ্ক *timeoutp, short events, চঞ্চল sig_atomic_t *stop)
{
	সংরচনা pollfd pfd;
	সংরচনা timespec timeout;
	পূর্ণাঙ্ক oerrno, r;
	sigset_t nsigset, osigset;

	যদি (timeoutp && *timeoutp == -1)
		timeoutp = রিক্ত;
	pfd.fd = fd;
	pfd.events = events;
	ptimeout_init(&timeout);
	যদি (timeoutp != রিক্ত)
		ptimeout_deadline_ms(&timeout, *timeoutp);
	যদি (stop != রিক্ত)
		sigfillset(&nsigset);
	প্রতি (; timeoutp == রিক্ত || *timeoutp >= 0;) {
		যদি (stop != রিক্ত) {
			sigprocmask(SIG_BLOCK, &nsigset, &osigset);
			যদি (*stop) {
				sigprocmask(SIG_SETMASK, &osigset, রিক্ত);
				errno = EINTR;
				প্রত্যাগম -1;
			}
		}
		r = ppoll(&pfd, 1, ptimeout_get_tsp(&timeout),
		    stop != রিক্ত ? &osigset : রিক্ত);
		oerrno = errno;
		যদি (stop != রিক্ত)
			sigprocmask(SIG_SETMASK, &osigset, রিক্ত);
		যদি (timeoutp)
			*timeoutp = ptimeout_get_ms(&timeout);
		errno = oerrno;
		যদি (r > 0)
			প্রত্যাগম 0;
		অন্যথা যদি (r == -1 && errno != EAGAIN && errno != EINTR)
			প্রত্যাগম -1;
		অন্যথা যদি (r == 0)
			ভঙ্গ;
	}
	/* timeout */
	errno = ETIMEDOUT;
	প্রত্যাগম -1;
}

/*
 * Wait up to *timeoutp milliseconds for fd to be readable. Updates
 * *timeoutp with time remaining.
 * Returns 0 if fd ready or -1 on timeout or error (see errno).
 */
পূর্ণাঙ্ক
waitrfd(পূর্ণাঙ্ক fd, পূর্ণাঙ্ক *timeoutp, চঞ্চল sig_atomic_t *stop) {
	প্রত্যাগম waitfd(fd, timeoutp, POLLIN, stop);
}

/*
 * Attempt a non-blocking connect(2) to the specified address, waiting up to
 * *timeoutp milliseconds for the connection to complete. If the timeout is
 * <=0, then wait indefinitely.
 *
 * Returns 0 on success or -1 on failure.
 */
পূর্ণাঙ্ক
timeout_connect(পূর্ণাঙ্ক sockfd, ধ্রুব সংরচনা sockaddr *serv_addr,
    socklen_t addrlen, পূর্ণাঙ্ক *timeoutp)
{
	পূর্ণাঙ্ক optval = 0;
	socklen_t optlen = পরিমাণ(optval);

	/* No timeout: just do a blocking connect() */
	যদি (timeoutp == রিক্ত || *timeoutp <= 0)
		প্রত্যাগম connect(sockfd, serv_addr, addrlen);

	set_nonblock(sockfd);
	প্রতি (;;) {
		যদি (connect(sockfd, serv_addr, addrlen) == 0) {
			/* Succeeded already? */
			unset_nonblock(sockfd);
			প্রত্যাগম 0;
		} অন্যথা যদি (errno == EINTR)
			অনুবর্ত;
		অন্যথা যদি (errno != EINPROGRESS)
			প্রত্যাগম -1;
		ভঙ্গ;
	}

	যদি (waitfd(sockfd, timeoutp, POLLIN | POLLOUT, রিক্ত) == -1)
		প্রত্যাগম -1;

	/* Completed or failed */
	যদি (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &optval, &optlen) == -1) {
		debug("getsockopt: %s", strerror(errno));
		প্রত্যাগম -1;
	}
	যদি (optval != 0) {
		errno = optval;
		প্রত্যাগম -1;
	}
	unset_nonblock(sockfd);
	প্রত্যাগম 0;
}

/* Characters considered whitespace in strsep calls. */
#define WHITESPACE " \t\r\n"
#define QUOTE	"\""

/* return next token in configuration line */
স্থির বর্ণ *
strdelim_internal(বর্ণ **s, পূর্ণাঙ্ক split_equals)
{
	বর্ণ *old;
	পূর্ণাঙ্ক wspace = 0;

	যদি (*s == রিক্ত)
		প্রত্যাগম রিক্ত;

	old = *s;

	*s = strpbrk(*s,
	    split_equals ? WHITESPACE QUOTE "=" : WHITESPACE QUOTE);
	যদি (*s == রিক্ত)
		প্রত্যাগম (old);

	যদি (*s[0] == '\"') {
		memmove(*s, *s + 1, strlen(*s)); /* move nul too */
		/* Find matching quote */
		যদি ((*s = strpbrk(*s, QUOTE)) == রিক্ত) {
			প্রত্যাগম (রিক্ত);		/* no matching quote */
		} অন্যথা {
			*s[0] = '\0';
			*s += strspn(*s + 1, WHITESPACE) + 1;
			প্রত্যাগম (old);
		}
	}

	/* Allow only one '=' to be skipped */
	যদি (split_equals && *s[0] == '=')
		wspace = 1;
	*s[0] = '\0';

	/* Skip any extra whitespace after first token */
	*s += strspn(*s + 1, WHITESPACE) + 1;
	যদি (split_equals && *s[0] == '=' && !wspace)
		*s += strspn(*s + 1, WHITESPACE) + 1;

	প্রত্যাগম (old);
}

/*
 * Return next token in configuration line; splits on whitespace or a
 * single '=' character.
 */
বর্ণ *
strdelim(বর্ণ **s)
{
	প্রত্যাগম strdelim_internal(s, 1);
}

/*
 * Return next token in configuration line; splits on whitespace only.
 */
বর্ণ *
strdelimw(বর্ণ **s)
{
	প্রত্যাগম strdelim_internal(s, 0);
}

সংরচনা passwd *
pwcopy(সংরচনা passwd *pw)
{
	সংরচনা passwd *copy = xcalloc(1, পরিমাণ(*copy));

	copy->pw_name = xstrdup(pw->pw_name);
	copy->pw_passwd = xstrdup(pw->pw_passwd == রিক্ত ? "*" : pw->pw_passwd);
#ifdef HAVE_STRUCT_PASSWD_PW_GECOS
	copy->pw_gecos = xstrdup(pw->pw_gecos == রিক্ত ? "" : pw->pw_gecos);
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
	copy->pw_class = xstrdup(pw->pw_class == রিক্ত ? "" : pw->pw_class);
#endif
	copy->pw_dir = xstrdup(pw->pw_dir == রিক্ত ? "" : pw->pw_dir);
	copy->pw_shell = xstrdup(pw->pw_shell == রিক্ত ? "" : pw->pw_shell);
	প্রত্যাগম copy;
}

শূন্য
pwfree(সংরচনা passwd *pw)
{
	যদি (pw == রিক্ত)
		প্রত্যাগম;
	মুক্ত(pw->pw_name);
	freezero(pw->pw_passwd,
	    pw->pw_passwd == রিক্ত ? 0 : strlen(pw->pw_passwd));
#ifdef HAVE_STRUCT_PASSWD_PW_GECOS
	মুক্ত(pw->pw_gecos);
#endif
#ifdef HAVE_STRUCT_PASSWD_PW_CLASS
	মুক্ত(pw->pw_class);
#endif
	মুক্ত(pw->pw_dir);
	মুক্ত(pw->pw_shell);
	freezero(pw, পরিমাণ(*pw));
}

/*
 * Convert ASCII string to TCP/IP port number.
 * Port must be >=0 and <=65535.
 * Return -1 if invalid.
 */
পূর্ণাঙ্ক
a2port(ধ্রুব বর্ণ *s)
{
	সংরচনা servent *se;
	long long port;
	ধ্রুব বর্ণ *errstr;

	port = strtonum(s, 0, 65535, &errstr);
	যদি (errstr == রিক্ত)
		প্রত্যাগম (পূর্ণাঙ্ক)port;
	যদি ((se = getservbyname(s, "tcp")) != রিক্ত)
		প্রত্যাগম ntohs(se->s_port);
	প্রত্যাগম -1;
}

পূর্ণাঙ্ক
a2tun(ধ্রুব বর্ণ *s, পূর্ণাঙ্ক *remote)
{
	ধ্রুব বর্ণ *errstr = রিক্ত;
	বর্ণ *sp, *ep;
	পূর্ণাঙ্ক tun;

	যদি (remote != রিক্ত) {
		*remote = SSH_TUNID_ANY;
		sp = xstrdup(s);
		যদি ((ep = strchr(sp, ':')) == রিক্ত) {
			মুক্ত(sp);
			প্রত্যাগম (a2tun(s, রিক্ত));
		}
		ep[0] = '\0'; ep++;
		*remote = a2tun(ep, রিক্ত);
		tun = a2tun(sp, রিক্ত);
		মুক্ত(sp);
		প্রত্যাগম (*remote == SSH_TUNID_ERR ? *remote : tun);
	}

	যদি (strcasecmp(s, "any") == 0)
		প্রত্যাগম (SSH_TUNID_ANY);

	tun = strtonum(s, 0, SSH_TUNID_MAX, &errstr);
	যদি (errstr != রিক্ত)
		প্রত্যাগম (SSH_TUNID_ERR);

	প্রত্যাগম (tun);
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
দ্বিগুণ
convtime_double(ধ্রুব বর্ণ *s)
{
	দ্বিগুণ val, total_sec = 0.0, multiplier;
	ধ্রুব বর্ণ *p, *start_p;
	বর্ণ *endp;
	পূর্ণাঙ্ক seen_seconds = 0;

	যদি (s == রিক্ত || *s == '\0')
		প্রত্যাগম -1.0;

	প্রতি (p = s; *p != '\0';) {
		যদি (!isdigit((unsigned বর্ণ)*p) && *p != '.')
			প্রত্যাগম -1.0;

		errno = 0;
		যদি ((val = strtod(p, &endp)) < 0 || errno != 0 || p == endp)
			প্রত্যাগম -1.0;
		/* Allow only decimal forms */
		যদি (p + strspn(p, "0123456789.") != endp)
			প্রত্যাগম -1.0;
		start_p = p;
		p = endp;

		বিকল্প (*p) {
		পক্ষ '\0':
			/* FALLTHROUGH */
		পক্ষ 's':
		পক্ষ 'S':
			যদি (seen_seconds++)
				প্রত্যাগম -1.0;
			multiplier = SECONDS;
			ভঙ্গ;
		পক্ষ 'm':
		পক্ষ 'M':
			multiplier = MINUTES;
			ভঙ্গ;
		পক্ষ 'h':
		পক্ষ 'H':
			multiplier = HOURS;
			ভঙ্গ;
		পক্ষ 'd':
		পক্ষ 'D':
			multiplier = DAYS;
			ভঙ্গ;
		পক্ষ 'w':
		পক্ষ 'W':
			multiplier = WEEKS;
			ভঙ্গ;
		স্বভাব:
			প্রত্যাগম -1.0;
		}

		/* Special handling if this was a decimal */
		যদি (memchr(start_p, '.', endp - start_p) != রিক্ত) {
			/* Decimal point present */
			যদি (multiplier > 1.0)
				প্রত্যাগম -1.0; /* No fractionals for non-seconds */
			/* For seconds, ensure digits follow */
			যদি (!isdigit((unsigned বর্ণ)*(endp - 1)))
				প্রত্যাগম -1.0;
		}

		total_sec += val * multiplier;

		যদি (*p != '\0')
			p++;
	}
	প্রত্যাগম total_sec;
}

/*
 * Same as convtime_double() above but fractional seconds are ignored.
 * Return -1 if time string is invalid.
 */
পূর্ণাঙ্ক
convtime(ধ্রুব বর্ণ *s)
{
	দ্বিগুণ sec_val;

	যদি ((sec_val = convtime_double(s)) < 0.0)
		প্রত্যাগম -1;

	/* Check for overflow into int */
	যদি (sec_val < 0 || sec_val > INT_MAX)
		প্রত্যাগম -1;

	প্রত্যাগম (পূর্ণাঙ্ক)sec_val;
}

#define TF_BUFS	8
#define TF_LEN	9

ধ্রুব বর্ণ *
fmt_timeframe(time_t t)
{
	বর্ণ		*buf;
	স্থির বর্ণ	 tfbuf[TF_BUFS][TF_LEN];	/* ring buffer */
	স্থির পূর্ণাঙ্ক	 idx = 0;
	unsigned পূর্ণাঙ্ক	 sec, min, hrs, day;
	unsigned long long	week;

	buf = tfbuf[idx++];
	যদি (idx == TF_BUFS)
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

	যদি (week > 0)
		snprintf(buf, TF_LEN, "%02lluw%01ud%02uh", week, day, hrs);
	অন্যথা যদি (day > 0)
		snprintf(buf, TF_LEN, "%01ud%02uh%02um", day, hrs, min);
	অন্যথা
		snprintf(buf, TF_LEN, "%02u:%02u:%02u", hrs, min, sec);

	প্রত্যাগম (buf);
}

/*
 * Returns a standardized host+port identifier string.
 * Caller must free returned string.
 */
বর্ণ *
put_host_port(ধ্রুব বর্ণ *host, u_short port)
{
	বর্ণ *hoststr;

	যদি (port == 0 || port == SSH_DEFAULT_PORT)
		প্রত্যাগম(xstrdup(host));
	যদি (asprintf(&hoststr, "[%s]:%d", host, (পূর্ণাঙ্ক)port) == -1)
		fatal("put_host_port: asprintf: %s", strerror(errno));
	debug3("put_host_port: %s", hoststr);
	প্রত্যাগম hoststr;
}

/*
 * Search for next delimiter between hostnames/addresses and ports.
 * Argument may be modified (for termination).
 * Returns *cp if parsing succeeds.
 * *cp is set to the start of the next field, if one was found.
 * The delimiter char, if present, is stored in delim.
 * If this is the last field, *cp is set to NULL.
 */
বর্ণ *
hpdelim2(বর্ণ **cp, বর্ণ *delim)
{
	বর্ণ *s, *old;

	যদি (cp == রিক্ত || *cp == রিক্ত)
		প্রত্যাগম রিক্ত;

	old = s = *cp;
	যদি (*s == '[') {
		যদি ((s = strchr(s, ']')) == রিক্ত)
			প্রত্যাগম রিক্ত;
		অন্যথা
			s++;
	} অন্যথা যদি ((s = strpbrk(s, ":/")) == রিক্ত)
		s = *cp + strlen(*cp); /* skip to end (see first case below) */

	বিকল্প (*s) {
	পক্ষ '\0':
		*cp = রিক্ত;	/* no more fields*/
		ভঙ্গ;

	পক্ষ ':':
	পক্ষ '/':
		যদি (delim != রিক্ত)
			*delim = *s;
		*s = '\0';	/* terminate */
		*cp = s + 1;
		ভঙ্গ;

	স্বভাব:
		প্রত্যাগম রিক্ত;
	}

	প্রত্যাগম old;
}

/* The common case: only accept colon as delimiter. */
বর্ণ *
hpdelim(বর্ণ **cp)
{
	বর্ণ *r, delim = '\0';

	r =  hpdelim2(cp, &delim);
	যদি (delim == '/')
		প্রত্যাগম রিক্ত;
	প্রত্যাগম r;
}

বর্ণ *
cleanhostname(বর্ণ *host)
{
	যদি (*host == '[' && host[strlen(host) - 1] == ']') {
		host[strlen(host) - 1] = '\0';
		প্রত্যাগম (host + 1);
	} অন্যথা
		প্রত্যাগম host;
}

বর্ণ *
colon(বর্ণ *cp)
{
	পূর্ণাঙ্ক flag = 0;

	যদি (*cp == ':')		/* Leading colon is part of file name. */
		প্রত্যাগম রিক্ত;
	যদি (*cp == '[')
		flag = 1;

	প্রতি (; *cp; ++cp) {
		যদি (*cp == '@' && *(cp+1) == '[')
			flag = 1;
		যদি (*cp == ']' && *(cp+1) == ':' && flag)
			প্রত্যাগম (cp+1);
		যদি (*cp == ':' && !flag)
			প্রত্যাগম (cp);
		যদি (*cp == '/')
			প্রত্যাগম রিক্ত;
	}
	প্রত্যাগম রিক্ত;
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
পূর্ণাঙ্ক
parse_user_host_path(ধ্রুব বর্ণ *s, বর্ণ **userp, বর্ণ **hostp, বর্ণ **pathp)
{
	বর্ণ *user = রিক্ত, *host = রিক্ত, *path = রিক্ত;
	বর্ণ *sdup, *tmp;
	পূর্ণাঙ্ক ret = -1;

	যদি (userp != রিক্ত)
		*userp = রিক্ত;
	যদি (hostp != রিক্ত)
		*hostp = রিক্ত;
	যদি (pathp != রিক্ত)
		*pathp = রিক্ত;

	sdup = xstrdup(s);

	/* Check for remote syntax: [user@]host:[path] */
	যদি ((tmp = colon(sdup)) == রিক্ত)
		গচ্ছ out;

	/* Extract optional path */
	*tmp++ = '\0';
	যদি (*tmp == '\0')
		tmp = ".";
	path = xstrdup(tmp);

	/* Extract optional user and mandatory host */
	tmp = strrchr(sdup, '@');
	যদি (tmp != রিক্ত) {
		*tmp++ = '\0';
		host = xstrdup(cleanhostname(tmp));
		যদি (*sdup != '\0')
			user = xstrdup(sdup);
	} অন্যথা {
		host = xstrdup(cleanhostname(sdup));
		user = রিক্ত;
	}

	/* Success */
	যদি (userp != রিক্ত) {
		*userp = user;
		user = রিক্ত;
	}
	যদি (hostp != রিক্ত) {
		*hostp = host;
		host = রিক্ত;
	}
	যদি (pathp != রিক্ত) {
		*pathp = path;
		path = রিক্ত;
	}
	ret = 0;
out:
	মুক্ত(sdup);
	মুক্ত(user);
	মুক্ত(host);
	মুক্ত(path);
	প্রত্যাগম ret;
}

/*
 * Parse a [user@]host[:port] string.
 * Caller must free returned user and host.
 * Any of the pointer return arguments may be NULL (useful for syntax checking).
 * If user was not specified then *userp will be set to NULL.
 * If port was not specified then *portp will be -1.
 * Returns 0 on success, -1 on failure.
 */
পূর্ণাঙ্ক
parse_user_host_port(ধ্রুব বর্ণ *s, বর্ণ **userp, বর্ণ **hostp, পূর্ণাঙ্ক *portp)
{
	বর্ণ *sdup, *cp, *tmp;
	বর্ণ *user = রিক্ত, *host = রিক্ত;
	পূর্ণাঙ্ক port = -1, ret = -1;

	যদি (userp != রিক্ত)
		*userp = রিক্ত;
	যদি (hostp != রিক্ত)
		*hostp = রিক্ত;
	যদি (portp != রিক্ত)
		*portp = -1;

	যদি ((sdup = tmp = strdup(s)) == রিক্ত)
		প্রত্যাগম -1;
	/* Extract optional username */
	যদি ((cp = strrchr(tmp, '@')) != রিক্ত) {
		*cp = '\0';
		যদি (*tmp == '\0')
			গচ্ছ out;
		যদি ((user = strdup(tmp)) == রিক্ত)
			গচ্ছ out;
		tmp = cp + 1;
	}
	/* Extract mandatory hostname */
	যদি ((cp = hpdelim(&tmp)) == রিক্ত || *cp == '\0')
		গচ্ছ out;
	host = xstrdup(cleanhostname(cp));
	/* Convert and verify optional port */
	যদি (tmp != রিক্ত && *tmp != '\0') {
		যদি ((port = a2port(tmp)) <= 0)
			গচ্ছ out;
	}
	/* Success */
	যদি (userp != রিক্ত) {
		*userp = user;
		user = রিক্ত;
	}
	যদি (hostp != রিক্ত) {
		*hostp = host;
		host = রিক্ত;
	}
	যদি (portp != রিক্ত)
		*portp = port;
	ret = 0;
 out:
	মুক্ত(sdup);
	মুক্ত(user);
	মুক্ত(host);
	প্রত্যাগম ret;
}

/*
 * Converts a two-byte hex string to decimal.
 * Returns the decimal value or -1 for invalid input.
 */
স্থির পূর্ণাঙ্ক
hexchar(ধ্রুব বর্ণ *s)
{
	unsigned বর্ণ result[2];
	পূর্ণাঙ্ক i;

	প্রতি (i = 0; i < 2; i++) {
		যদি (s[i] >= '0' && s[i] <= '9')
			result[i] = (unsigned বর্ণ)(s[i] - '0');
		অন্যথা যদি (s[i] >= 'a' && s[i] <= 'f')
			result[i] = (unsigned বর্ণ)(s[i] - 'a') + 10;
		অন্যথা যদি (s[i] >= 'A' && s[i] <= 'F')
			result[i] = (unsigned বর্ণ)(s[i] - 'A') + 10;
		অন্যথা
			প্রত্যাগম -1;
	}
	প্রত্যাগম (result[0] << 4) | result[1];
}

/*
 * Decode an url-encoded string.
 * Returns a newly allocated string on success or NULL on failure.
 */
স্থির বর্ণ *
urldecode(ধ্রুব বর্ণ *src)
{
	বর্ণ *ret, *dst;
	পূর্ণাঙ্ক ch;
	size_t srclen;

	যদি ((srclen = strlen(src)) >= SIZE_MAX)
		প্রত্যাগম রিক্ত;
	ret = xmalloc(srclen + 1);
	প্রতি (dst = ret; *src != '\0'; src++) {
		বিকল্প (*src) {
		পক্ষ '+':
			*dst++ = ' ';
			ভঙ্গ;
		পক্ষ '%':
			/* note: don't allow \0 characters */
			যদি (!isxdigit((unsigned বর্ণ)src[1]) ||
			    !isxdigit((unsigned বর্ণ)src[2]) ||
			    (ch = hexchar(src + 1)) == -1 || ch == 0) {
				মুক্ত(ret);
				প্রত্যাগম রিক্ত;
			}
			*dst++ = ch;
			src += 2;
			ভঙ্গ;
		স্বভাব:
			*dst++ = *src;
			ভঙ্গ;
		}
	}
	*dst = '\0';

	প্রত্যাগম ret;
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
পূর্ণাঙ্ক
parse_uri(ধ্রুব বর্ণ *scheme, ধ্রুব বর্ণ *uri, বর্ণ **userp, বর্ণ **hostp,
    পূর্ণাঙ্ক *portp, বর্ণ **pathp)
{
	বর্ণ *uridup, *cp, *tmp, ch;
	বর্ণ *user = রিক্ত, *host = রিক্ত, *path = রিক্ত;
	পূর্ণাঙ্ক port = -1, ret = -1;
	size_t len;

	len = strlen(scheme);
	যদি (strncmp(uri, scheme, len) != 0 || strncmp(uri + len, "://", 3) != 0)
		প্রত্যাগম 1;
	uri += len + 3;

	যদি (userp != রিক্ত)
		*userp = রিক্ত;
	যদি (hostp != রিক্ত)
		*hostp = রিক্ত;
	যদি (portp != রিক্ত)
		*portp = -1;
	যদি (pathp != রিক্ত)
		*pathp = রিক্ত;

	uridup = tmp = xstrdup(uri);

	/* Extract optional ssh-info (username + connection params) */
	যদি ((cp = strchr(tmp, '@')) != রিক্ত) {
		বর্ণ *delim;

		*cp = '\0';
		/* Extract username and connection params */
		যদি ((delim = strchr(tmp, ';')) != রিক্ত) {
			/* Just ignore connection params for now */
			*delim = '\0';
		}
		যদি (*tmp == '\0') {
			/* Empty username */
			গচ্ছ out;
		}
		যদি ((user = urldecode(tmp)) == রিক্ত)
			গচ্ছ out;
		tmp = cp + 1;
	}

	/* Extract mandatory hostname */
	যদি ((cp = hpdelim2(&tmp, &ch)) == রিক্ত || *cp == '\0')
		গচ্ছ out;
	host = xstrdup(cleanhostname(cp));
	যদি (!valid_domain(host, 0, রিক্ত))
		গচ্ছ out;

	যদি (tmp != রিক্ত && *tmp != '\0') {
		যদি (ch == ':') {
			/* Convert and verify port. */
			যদি ((cp = strchr(tmp, '/')) != রিক্ত)
				*cp = '\0';
			যদি ((port = a2port(tmp)) <= 0)
				গচ্ছ out;
			tmp = cp ? cp + 1 : রিক্ত;
		}
		যদি (tmp != রিক্ত && *tmp != '\0') {
			/* Extract optional path */
			যদি ((path = urldecode(tmp)) == রিক্ত)
				গচ্ছ out;
		}
	}

	/* Success */
	যদি (userp != রিক্ত) {
		*userp = user;
		user = রিক্ত;
	}
	যদি (hostp != রিক্ত) {
		*hostp = host;
		host = রিক্ত;
	}
	যদি (portp != রিক্ত)
		*portp = port;
	যদি (pathp != রিক্ত) {
		*pathp = path;
		path = রিক্ত;
	}
	ret = 0;
 out:
	মুক্ত(uridup);
	মুক্ত(user);
	মুক্ত(host);
	মুক্ত(path);
	প্রত্যাগম ret;
}

/* function to assist building execv() arguments */
শূন্য
addargs(arglist *args, বর্ণ *fmt, ...)
{
	va_list ap;
	বর্ণ *cp;
	u_int nalloc;
	পূর্ণাঙ্ক r;

	va_start(ap, fmt);
	r = vasprintf(&cp, fmt, ap);
	va_end(ap);
	যদি (r == -1)
		fatal_f("argument too long");

	nalloc = args->nalloc;
	যদি (args->list == রিক্ত) {
		nalloc = 32;
		args->অঙ্ক = 0;
	} অন্যথা যদি (args->অঙ্ক > (256 * 1024))
		fatal_f("too many arguments");
	অন্যথা যদি (args->অঙ্ক >= args->nalloc)
		fatal_f("arglist corrupt");
	অন্যথা যদি (args->অঙ্ক+2 >= nalloc)
		nalloc *= 2;

	args->list = xrecallocarray(args->list, args->nalloc,
	    nalloc, পরিমাণ(বর্ণ *));
	args->nalloc = nalloc;
	args->list[args->অঙ্ক++] = cp;
	args->list[args->অঙ্ক] = রিক্ত;
}

শূন্য
replacearg(arglist *args, u_int which, বর্ণ *fmt, ...)
{
	va_list ap;
	বর্ণ *cp;
	পূর্ণাঙ্ক r;

	va_start(ap, fmt);
	r = vasprintf(&cp, fmt, ap);
	va_end(ap);
	যদি (r == -1)
		fatal_f("argument too long");
	যদি (args->list == রিক্ত || args->অঙ্ক >= args->nalloc)
		fatal_f("arglist corrupt");

	যদি (which >= args->অঙ্ক)
		fatal_f("tried to replace invalid arg %d >= %d",
		    which, args->অঙ্ক);
	মুক্ত(args->list[which]);
	args->list[which] = cp;
}

শূন্য
freeargs(arglist *args)
{
	u_int i;

	যদি (args == রিক্ত)
		প্রত্যাগম;
	যদি (args->list != রিক্ত && args->অঙ্ক < args->nalloc) {
		প্রতি (i = 0; i < args->অঙ্ক; i++)
			মুক্ত(args->list[i]);
		মুক্ত(args->list);
	}
	args->nalloc = args->অঙ্ক = 0;
	args->list = রিক্ত;
}

/*
 * Expands tildes in the file name.  Returns data allocated by xmalloc.
 * Warning: this calls getpw*.
 */
পূর্ণাঙ্ক
tilde_expand(ধ্রুব বর্ণ *filename, uid_t uid, বর্ণ **retp)
{
	বর্ণ *ocopy = রিক্ত, *copy, *s = রিক্ত;
	ধ্রুব বর্ণ *path = রিক্ত, *user = রিক্ত;
	সংরচনা passwd *pw;
	size_t len;
	পূর্ণাঙ্ক ret = -1, r, slash;

	*retp = রিক্ত;
	যদি (*filename != '~') {
		*retp = xstrdup(filename);
		প্রত্যাগম 0;
	}
	ocopy = copy = xstrdup(filename + 1);

	যদি (*copy == '\0')				/* ~ */
		path = রিক্ত;
	অন্যথা যদি (*copy == '/') {
		copy += strspn(copy, "/");
		যদি (*copy == '\0')
			path = রিক্ত;			/* ~/ */
		অন্যথা
			path = copy;			/* ~/path */
	} অন্যথা {
		user = copy;
		যদি ((path = strchr(copy, '/')) != রিক্ত) {
			copy[path - copy] = '\0';
			path++;
			path += strspn(path, "/");
			যদি (*path == '\0')		/* ~user/ */
				path = রিক্ত;
			/* else				 ~user/path */
		}
		/* else					~user */
	}
	যদি (user != রিক্ত) {
		যদি ((pw = getpwnam(user)) == রিক্ত) {
			error_f("No such user %s", user);
			গচ্ছ out;
		}
	} অন্যথা যদি ((pw = getpwuid(uid)) == রিক্ত) {
		error_f("No such uid %ld", (long)uid);
		গচ্ছ out;
	}

	/* Make sure directory has a trailing '/' */
	slash = (len = strlen(pw->pw_dir)) == 0 || pw->pw_dir[len - 1] != '/';

	যদি ((r = xasprintf(&s, "%s%s%s", pw->pw_dir,
	    slash ? "/" : "", path != রিক্ত ? path : "")) <= 0) {
		error_f("xasprintf failed");
		গচ্ছ out;
	}
	যদি (r >= PATH_MAX) {
		error_f("Path too long");
		গচ্ছ out;
	}
	/* success */
	ret = 0;
	*retp = s;
	s = রিক্ত;
 out:
	মুক্ত(s);
	মুক্ত(ocopy);
	প্রত্যাগম ret;
}

বর্ণ *
tilde_expand_filename(ধ্রুব বর্ণ *filename, uid_t uid)
{
	বর্ণ *ret;

	যদি (tilde_expand(filename, uid, &ret) != 0)
		cleanup_exit(255);
	প্রত্যাগম ret;
}

/*
 * Expand a string with a set of %[char] escapes and/or ${ENVIRONMENT}
 * substitutions.  A number of escapes may be specified as
 * (char *escape_chars, char *replacement) pairs. The list must be terminated
 * by a NULL escape_char. Returns replaced string in memory allocated by
 * xmalloc which the caller must free.
 */
স্থির বর্ণ *
vdollar_percent_expand(পূর্ণাঙ্ক *parseerror, পূর্ণাঙ্ক dollar, পূর্ণাঙ্ক percent,
    ধ্রুব বর্ণ *string, va_list ap)
{
#define EXPAND_MAX_চাবিগুলি	64
	u_int অঙ্ক_চাবিগুলি = 0, i;
	সংরচনা {
		ধ্রুব বর্ণ *চাবি;
		ধ্রুব বর্ণ *repl;
	} চাবিগুলি[EXPAND_MAX_চাবিগুলি];
	সংরচনা sshbuf *buf;
	পূর্ণাঙ্ক r, missingvar = 0;
	বর্ণ *ret = রিক্ত, *var, *varend, *val;
	size_t len;

	যদি ((buf = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new failed");
	যদি (parseerror == রিক্ত)
		fatal_f("null parseerror arg");
	*parseerror = 1;

	/* Gather keys if we're doing percent expansion. */
	যদি (percent) {
		প্রতি (অঙ্ক_চাবিগুলি = 0; অঙ্ক_চাবিগুলি < EXPAND_MAX_চাবিগুলি; অঙ্ক_চাবিগুলি++) {
			চাবিগুলি[অঙ্ক_চাবিগুলি].চাবি = va_arg(ap, বর্ণ *);
			যদি (চাবিগুলি[অঙ্ক_চাবিগুলি].চাবি == রিক্ত)
				ভঙ্গ;
			চাবিগুলি[অঙ্ক_চাবিগুলি].repl = va_arg(ap, বর্ণ *);
			যদি (চাবিগুলি[অঙ্ক_চাবিগুলি].repl == রিক্ত) {
				fatal_f("NULL replacement for token %s",
				    চাবিগুলি[অঙ্ক_চাবিগুলি].চাবি);
			}
		}
		যদি (অঙ্ক_চাবিগুলি == EXPAND_MAX_চাবিগুলি && va_arg(ap, বর্ণ *) != রিক্ত)
			fatal_f("too many keys");
		যদি (অঙ্ক_চাবিগুলি == 0)
			fatal_f("percent expansion without token list");
	}

	/* Expand string */
	প্রতি (i = 0; *string != '\0'; string++) {
		/* Optionally process ${ENVIRONMENT} expansions. */
		যদি (dollar && string[0] == '$' && string[1] == '{') {
			string += 2;  /* skip over '${' */
			যদি ((varend = strchr(string, '}')) == রিক্ত) {
				error_f("environment variable '%s' missing "
				    "closing '}'", string);
				গচ্ছ out;
			}
			len = varend - string;
			যদি (len == 0) {
				error_f("zero-length environment variable");
				গচ্ছ out;
			}
			var = xmalloc(len + 1);
			(শূন্য)strlcpy(var, string, len + 1);
			যদি ((val = getenv(var)) == রিক্ত) {
				error_f("env var ${%s} has no value", var);
				missingvar = 1;
			} অন্যথা {
				debug3_f("expand ${%s} -> '%s'", var, val);
				যদি ((r = sshbuf_put(buf, val, strlen(val))) !=0)
					fatal_fr(r, "sshbuf_put ${}");
			}
			মুক্ত(var);
			string += len;
			অনুবর্ত;
		}

		/*
		 * Process percent expansions if we have a list of TOKENs.
		 * If we're not doing percent expansion everything just gets
		 * appended here.
		 */
		যদি (*string != '%' || !percent) {
 append:
			যদি ((r = sshbuf_put_u8(buf, *string)) != 0)
				fatal_fr(r, "sshbuf_put_u8 %%");
			অনুবর্ত;
		}
		string++;
		/* %% case */
		যদি (*string == '%')
			গচ্ছ append;
		যদি (*string == '\0') {
			error_f("invalid format");
			গচ্ছ out;
		}
		প্রতি (i = 0; i < অঙ্ক_চাবিগুলি; i++) {
			যদি (strchr(চাবিগুলি[i].চাবি, *string) != রিক্ত) {
				যদি ((r = sshbuf_put(buf, চাবিগুলি[i].repl,
				    strlen(চাবিগুলি[i].repl))) != 0)
					fatal_fr(r, "sshbuf_put %%-repl");
				ভঙ্গ;
			}
		}
		যদি (i >= অঙ্ক_চাবিগুলি) {
			error_f("unknown key %%%c", *string);
			গচ্ছ out;
		}
	}
	যদি (!missingvar && (ret = sshbuf_dup_string(buf)) == রিক্ত)
		fatal_f("sshbuf_dup_string failed");
	*parseerror = 0;
 out:
	sshbuf_free(buf);
	প্রত্যাগম *parseerror ? রিক্ত : ret;
#undef EXPAND_MAX_চাবিগুলি
}

/*
 * Expand only environment variables.
 * Note that although this function is variadic like the other similar
 * functions, any such arguments will be unused.
 */

বর্ণ *
dollar_expand(পূর্ণাঙ্ক *parseerr, ধ্রুব বর্ণ *string, ...)
{
	বর্ণ *ret;
	পূর্ণাঙ্ক err;
	va_list ap;

	va_start(ap, string);
	ret = vdollar_percent_expand(&err, 1, 0, string, ap);
	va_end(ap);
	যদি (parseerr != রিক্ত)
		*parseerr = err;
	প্রত্যাগম ret;
}

/*
 * Returns expanded string or NULL if a specified environment variable is
 * not defined, or calls fatal if the string is invalid.
 */
বর্ণ *
percent_expand(ধ্রুব বর্ণ *string, ...)
{
	বর্ণ *ret;
	পূর্ণাঙ্ক err;
	va_list ap;

	va_start(ap, string);
	ret = vdollar_percent_expand(&err, 0, 1, string, ap);
	va_end(ap);
	যদি (err)
		fatal_f("failed");
	প্রত্যাগম ret;
}

/*
 * Returns expanded string or NULL if a specified environment variable is
 * not defined, or calls fatal if the string is invalid.
 */
বর্ণ *
percent_dollar_expand(ধ্রুব বর্ণ *string, ...)
{
	বর্ণ *ret;
	পূর্ণাঙ্ক err;
	va_list ap;

	va_start(ap, string);
	ret = vdollar_percent_expand(&err, 1, 1, string, ap);
	va_end(ap);
	যদি (err)
		fatal_f("failed");
	প্রত্যাগম ret;
}

পূর্ণাঙ্ক
tun_open(পূর্ণাঙ্ক tun, পূর্ণাঙ্ক mode, বর্ণ **ifname)
{
#যদি defined(CUSTOM_SYS_TUN_OPEN)
	প্রত্যাগম (sys_tun_open(tun, mode, ifname));
#নোচেদ্যদি defined(SSH_TUN_OPENBSD)
	সংরচনা ifreq ifr;
	বর্ণ name[100];
	পূর্ণাঙ্ক fd = -1, sock;
	ধ্রুব বর্ণ *tunbase = "tun";

	যদি (ifname != রিক্ত)
		*ifname = রিক্ত;

	যদি (mode == SSH_TUNMODE_ETHERNET)
		tunbase = "tap";

	/* Open the tunnel device */
	যদি (tun <= SSH_TUNID_MAX) {
		snprintf(name, পরিমাণ(name), "/dev/%s%d", tunbase, tun);
		fd = open(name, O_RDWR);
	} অন্যথা যদি (tun == SSH_TUNID_ANY) {
		প্রতি (tun = 100; tun >= 0; tun--) {
			snprintf(name, পরিমাণ(name), "/dev/%s%d",
			    tunbase, tun);
			যদি ((fd = open(name, O_RDWR)) >= 0)
				ভঙ্গ;
		}
	} অন্যথা {
		debug_f("invalid tunnel %u", tun);
		প্রত্যাগম -1;
	}

	যদি (fd == -1) {
		debug_f("%s open: %s", name, strerror(errno));
		প্রত্যাগম -1;
	}

	debug_f("%s mode %d fd %d", name, mode, fd);

	/* Bring interface up if it is not already */
	snprintf(ifr.ifr_name, পরিমাণ(ifr.ifr_name), "%s%d", tunbase, tun);
	যদি ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
		গচ্ছ failed;

	যদি (ioctl(sock, SIOCGIFFLAGS, &ifr) == -1) {
		debug_f("get interface %s flags: %s", ifr.ifr_name,
		    strerror(errno));
		গচ্ছ failed;
	}

	যদি (!(ifr.ifr_flags & IFF_UP)) {
		ifr.ifr_flags |= IFF_UP;
		যদি (ioctl(sock, SIOCSIFFLAGS, &ifr) == -1) {
			debug_f("activate interface %s: %s", ifr.ifr_name,
			    strerror(errno));
			গচ্ছ failed;
		}
	}

	যদি (ifname != রিক্ত)
		*ifname = xstrdup(ifr.ifr_name);

	close(sock);
	প্রত্যাগম fd;

 failed:
	যদি (fd >= 0)
		close(fd);
	যদি (sock >= 0)
		close(sock);
	প্রত্যাগম -1;
#অন্যথা
	error("Tunnel interfaces are not supported on this platform");
	প্রত্যাগম (-1);
#endif
}

শূন্য
sanitise_stdfd(শূন্য)
{
	পূর্ণাঙ্ক nullfd, dupfd;

	যদি ((nullfd = dupfd = open(_PATH_DEVNULL, O_RDWR)) == -1) {
		fprintf(stderr, "Couldn't open /dev/null: %s\n",
		    strerror(errno));
		exit(1);
	}
	যাবত্ (++dupfd <= STDERR_FILENO) {
		/* Only populate closed fds. */
		যদি (fcntl(dupfd, F_GETFL) == -1 && errno == EBADF) {
			যদি (dup2(nullfd, dupfd) == -1) {
				fprintf(stderr, "dup2: %s\n", strerror(errno));
				exit(1);
			}
		}
	}
	যদি (nullfd > STDERR_FILENO)
		close(nullfd);
}

বর্ণ *
tohex(ধ্রুব শূন্য *vp, size_t l)
{
	ধ্রুব u_char *p = (ধ্রুব u_char *)vp;
	বর্ণ b[3], *r;
	size_t i, hl;

	যদি (l > 65536)
		প্রত্যাগম xstrdup("tohex: length > 65536");

	hl = l * 2 + 1;
	r = xcalloc(1, hl);
	প্রতি (i = 0; i < l; i++) {
		snprintf(b, পরিমাণ(b), "%02x", p[i]);
		strlcat(r, b, hl);
	}
	প্রত্যাগম (r);
}

/*
 * Extend string *sp by the specified format. If *sp is not NULL (or empty),
 * then the separator 'sep' will be prepended before the formatted arguments.
 * Extended strings are heap allocated.
 */
শূন্য
xextendf(বর্ণ **sp, ধ্রুব বর্ণ *sep, ধ্রুব বর্ণ *fmt, ...)
{
	va_list ap;
	বর্ণ *tmp1, *tmp2;

	va_start(ap, fmt);
	xvasprintf(&tmp1, fmt, ap);
	va_end(ap);

	যদি (*sp == রিক্ত || **sp == '\0') {
		মুক্ত(*sp);
		*sp = tmp1;
		প্রত্যাগম;
	}
	xasprintf(&tmp2, "%s%s%s", *sp, sep == রিক্ত ? "" : sep, tmp1);
	মুক্ত(tmp1);
	মুক্ত(*sp);
	*sp = tmp2;
}


uint64_t
get_u64(ধ্রুব শূন্য *vp)
{
	ধ্রুব u_char *p = (ধ্রুব u_char *)vp;
	uint64_t v;

	v  = (uint64_t)p[0] << 56;
	v |= (uint64_t)p[1] << 48;
	v |= (uint64_t)p[2] << 40;
	v |= (uint64_t)p[3] << 32;
	v |= (uint64_t)p[4] << 24;
	v |= (uint64_t)p[5] << 16;
	v |= (uint64_t)p[6] << 8;
	v |= (uint64_t)p[7];

	প্রত্যাগম (v);
}

uint32_t
get_u32(ধ্রুব শূন্য *vp)
{
	ধ্রুব u_char *p = (ধ্রুব u_char *)vp;
	uint32_t v;

	v  = (uint32_t)p[0] << 24;
	v |= (uint32_t)p[1] << 16;
	v |= (uint32_t)p[2] << 8;
	v |= (uint32_t)p[3];

	প্রত্যাগম (v);
}

uint32_t
get_u32_le(ধ্রুব শূন্য *vp)
{
	ধ্রুব u_char *p = (ধ্রুব u_char *)vp;
	uint32_t v;

	v  = (uint32_t)p[0];
	v |= (uint32_t)p[1] << 8;
	v |= (uint32_t)p[2] << 16;
	v |= (uint32_t)p[3] << 24;

	প্রত্যাগম (v);
}

uint16_t
get_u16(ধ্রুব শূন্য *vp)
{
	ধ্রুব u_char *p = (ধ্রুব u_char *)vp;
	uint16_t v;

	v  = (uint16_t)p[0] << 8;
	v |= (uint16_t)p[1];

	প্রত্যাগম (v);
}

শূন্য
put_u64(শূন্য *vp, uint64_t v)
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

শূন্য
put_u32(শূন্য *vp, uint32_t v)
{
	u_char *p = (u_char *)vp;

	p[0] = (u_char)(v >> 24) & 0xff;
	p[1] = (u_char)(v >> 16) & 0xff;
	p[2] = (u_char)(v >> 8) & 0xff;
	p[3] = (u_char)v & 0xff;
}

শূন্য
put_u32_le(শূন্য *vp, uint32_t v)
{
	u_char *p = (u_char *)vp;

	p[0] = (u_char)v & 0xff;
	p[1] = (u_char)(v >> 8) & 0xff;
	p[2] = (u_char)(v >> 16) & 0xff;
	p[3] = (u_char)(v >> 24) & 0xff;
}

শূন্য
put_u16(শূন্য *vp, uint16_t v)
{
	u_char *p = (u_char *)vp;

	p[0] = (u_char)(v >> 8) & 0xff;
	p[1] = (u_char)v & 0xff;
}

শূন্য
ms_subtract_diff(সংরচনা timeval *start, পূর্ণাঙ্ক *ms)
{
	সংরচনা timeval diff, finish;

	monotime_tv(&finish);
	timersub(&finish, start, &diff);
	*ms -= (diff.tv_sec * 1000) + (diff.tv_usec / 1000);
}

শূন্য
ms_to_timespec(সংরচনা timespec *ts, পূর্ণাঙ্ক ms)
{
	যদি (ms < 0)
		ms = 0;
	ts->tv_sec = ms / 1000;
	ts->tv_nsec = (ms % 1000) * 1000 * 1000;
}

শূন্য
monotime_ts(সংরচনা timespec *ts)
{
	সংরচনা timeval tv;
#যদি defined(HAVE_CLOCK_GETTIME) && (defined(CLOCK_BOOTTIME) || \
    defined(CLOCK_MONOTONIC) || defined(CLOCK_REALTIME))
	স্থির পূর্ণাঙ্ক gettime_failed = 0;

	যদি (!gettime_failed) {
# ifdef CLOCK_BOOTTIME
		যদি (clock_gettime(CLOCK_BOOTTIME, ts) == 0)
			প্রত্যাগম;
# endif /* CLOCK_BOOTTIME */
# ifdef CLOCK_MONOTONIC
		যদি (clock_gettime(CLOCK_MONOTONIC, ts) == 0)
			প্রত্যাগম;
# endif /* CLOCK_MONOTONIC */
# ifdef CLOCK_REALTIME
		/* Not monotonic, but we're almost out of options here. */
		যদি (clock_gettime(CLOCK_REALTIME, ts) == 0)
			প্রত্যাগম;
# endif /* CLOCK_REALTIME */
		debug3("clock_gettime: %s", strerror(errno));
		gettime_failed = 1;
	}
#endif /* HAVE_CLOCK_GETTIME && (BOOTTIME || MONOTONIC || REALTIME) */
	gettimeofday(&tv, রিক্ত);
	ts->tv_sec = tv.tv_sec;
	ts->tv_nsec = (long)tv.tv_usec * 1000;
}

শূন্য
monotime_tv(সংরচনা timeval *tv)
{
	সংরচনা timespec ts;

	monotime_ts(&ts);
	tv->tv_sec = ts.tv_sec;
	tv->tv_usec = ts.tv_nsec / 1000;
}

time_t
monotime(শূন্য)
{
	সংরচনা timespec ts;

	monotime_ts(&ts);
	প্রত্যাগম (ts.tv_sec);
}

দ্বিগুণ
monotime_double(শূন্য)
{
	সংরচনা timespec ts;

	monotime_ts(&ts);
	প্রত্যাগম (দ্বিগুণ)ts.tv_sec + (দ্বিগুণ)ts.tv_nsec / 1000000000.0;
}

শূন্য
bandwidth_limit_init(সংরচনা bwlimit *bw, uint64_t kbps, size_t buflen)
{
	bw->buflen = buflen;
	bw->rate = kbps;
	bw->thresh = buflen;
	bw->lamt = 0;
	timerclear(&bw->bwstart);
	timerclear(&bw->bwend);
}

/* Callback from read/write loop to insert bandwidth-limiting delays */
শূন্য
bandwidth_limit(সংরচনা bwlimit *bw, size_t read_len)
{
	uint64_t waitlen;
	সংরচনা timespec ts, rm;

	bw->lamt += read_len;
	যদি (!timerisset(&bw->bwstart)) {
		monotime_tv(&bw->bwstart);
		প্রত্যাগম;
	}
	যদি (bw->lamt < bw->thresh)
		প্রত্যাগম;

	monotime_tv(&bw->bwend);
	timersub(&bw->bwend, &bw->bwstart, &bw->bwend);
	যদি (!timerisset(&bw->bwend))
		প্রত্যাগম;

	bw->lamt *= 8;
	waitlen = (দ্বিগুণ)1000000L * bw->lamt / bw->rate;

	bw->bwstart.tv_sec = waitlen / 1000000L;
	bw->bwstart.tv_usec = waitlen % 1000000L;

	যদি (timercmp(&bw->bwstart, &bw->bwend, >)) {
		timersub(&bw->bwstart, &bw->bwend, &bw->bwend);

		/* Adjust the wait time */
		যদি (bw->bwend.tv_sec) {
			bw->thresh /= 2;
			যদি (bw->thresh < bw->buflen / 4)
				bw->thresh = bw->buflen / 4;
		} অন্যথা যদি (bw->bwend.tv_usec < 10000) {
			bw->thresh *= 2;
			যদি (bw->thresh > bw->buflen * 8)
				bw->thresh = bw->buflen * 8;
		}

		TIMEVAL_TO_TIMESPEC(&bw->bwend, &ts);
		যাবত্ (nanosleep(&ts, &rm) == -1) {
			যদি (errno != EINTR)
				ভঙ্গ;
			ts = rm;
		}
	}

	bw->lamt = 0;
	monotime_tv(&bw->bwstart);
}

/* Make a template filename for mk[sd]temp() */
শূন্য
mktemp_proto(বর্ণ *s, size_t len)
{
	ধ্রুব বর্ণ *tmpdir;
	পূর্ণাঙ্ক r;

	যদি ((tmpdir = getenv("TMPDIR")) != রিক্ত) {
		r = snprintf(s, len, "%s/ssh-XXXXXXXXXXXX", tmpdir);
		যদি (r > 0 && (size_t)r < len)
			প্রত্যাগম;
	}
	r = snprintf(s, len, "/tmp/ssh-XXXXXXXXXXXX");
	যদি (r < 0 || (size_t)r >= len)
		fatal_f("template string too short");
}

স্থির ধ্রুব সংরচনা {
	ধ্রুব বর্ণ *name;
	পূর্ণাঙ্ক মান;
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
	{ রিক্ত, -1 }
};

পূর্ণাঙ্ক
parse_ipqos(ধ্রুব বর্ণ *cp)
{
	ধ্রুব বর্ণ *errstr;
	u_int i;
	পূর্ণাঙ্ক val;

	যদি (cp == রিক্ত)
		প্রত্যাগম -1;
	প্রতি (i = 0; ipqos[i].name != রিক্ত; i++) {
		যদি (strcasecmp(cp, ipqos[i].name) == 0)
			প্রত্যাগম ipqos[i].মান;
	}
	/* Try parsing as an integer */
	val = (পূর্ণাঙ্ক)strtonum(cp, 0, 255, &errstr);
	যদি (errstr)
		প্রত্যাগম -1;
	প্রত্যাগম val;
}

ধ্রুব বর্ণ *
iptos2str(পূর্ণাঙ্ক iptos)
{
	পূর্ণাঙ্ক i;
	স্থির বর্ণ iptos_str[পরিমাণ "0xff"];

	প্রতি (i = 0; ipqos[i].name != রিক্ত; i++) {
		যদি (ipqos[i].মান == iptos)
			প্রত্যাগম ipqos[i].name;
	}
	snprintf(iptos_str, পরিমাণ iptos_str, "0x%02x", iptos);
	প্রত্যাগম iptos_str;
}

শূন্য
lowercase(বর্ণ *s)
{
	প্রতি (; *s; s++)
		*s = tolower((u_char)*s);
}

পূর্ণাঙ্ক
unix_listener(ধ্রুব বর্ণ *path, পূর্ণাঙ্ক backlog, পূর্ণাঙ্ক unlink_first)
{
	সংরচনা sockaddr_un sunaddr;
	পূর্ণাঙ্ক saved_errno, sock;

	memset(&sunaddr, 0, পরিমাণ(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	যদি (strlcpy(sunaddr.sun_path, path,
	    পরিমাণ(sunaddr.sun_path)) >= পরিমাণ(sunaddr.sun_path)) {
		error_f("path \"%s\" too long for Unix domain socket", path);
		errno = ENAMETOOLONG;
		প্রত্যাগম -1;
	}

	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	যদি (sock == -1) {
		saved_errno = errno;
		error_f("socket: %.100s", strerror(errno));
		errno = saved_errno;
		প্রত্যাগম -1;
	}
	যদি (unlink_first == 1) {
		যদি (unlink(path) != 0 && errno != ENOENT)
			error("unlink(%s): %.100s", path, strerror(errno));
	}
	যদি (bind(sock, (সংরচনা sockaddr *)&sunaddr, পরিমাণ(sunaddr)) == -1) {
		saved_errno = errno;
		error_f("cannot bind to path %s: %s", path, strerror(errno));
		close(sock);
		errno = saved_errno;
		প্রত্যাগম -1;
	}
	যদি (listen(sock, backlog) == -1) {
		saved_errno = errno;
		error_f("cannot listen on path %s: %s", path, strerror(errno));
		close(sock);
		unlink(path);
		errno = saved_errno;
		প্রত্যাগম -1;
	}
	প্রত্যাগম sock;
}

শূন্য
sock_set_v6only(পূর্ণাঙ্ক s)
{
#যদি defined(IPV6_V6ONLY) && !defined(__OpenBSD__)
	পূর্ণাঙ্ক on = 1;

	debug3_f("set socket %d IPV6_V6ONLY", s);
	যদি (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &on, পরিমাণ(on)) == -1)
		error("setsockopt IPV6_V6ONLY: %s", strerror(errno));
#endif
}

/*
 * Compares two strings that maybe be NULL. Returns non-zero if strings
 * are both NULL or are identical, returns zero otherwise.
 */
স্থির পূর্ণাঙ্ক
strcmp_maybe_null(ধ্রুব বর্ণ *a, ধ্রুব বর্ণ *b)
{
	যদি ((a == রিক্ত && b != রিক্ত) || (a != রিক্ত && b == রিক্ত))
		প্রত্যাগম 0;
	যদি (a != রিক্ত && strcmp(a, b) != 0)
		প্রত্যাগম 0;
	প্রত্যাগম 1;
}

/*
 * Compare two forwards, returning non-zero if they are identical or
 * zero otherwise.
 */
পূর্ণাঙ্ক
forward_equals(ধ্রুব সংরচনা Forward *a, ধ্রুব সংরচনা Forward *b)
{
	যদি (strcmp_maybe_null(a->listen_host, b->listen_host) == 0)
		প্রত্যাগম 0;
	যদি (a->listen_port != b->listen_port)
		প্রত্যাগম 0;
	যদি (strcmp_maybe_null(a->listen_path, b->listen_path) == 0)
		প্রত্যাগম 0;
	যদি (strcmp_maybe_null(a->connect_host, b->connect_host) == 0)
		প্রত্যাগম 0;
	যদি (a->connect_port != b->connect_port)
		প্রত্যাগম 0;
	যদি (strcmp_maybe_null(a->connect_path, b->connect_path) == 0)
		প্রত্যাগম 0;
	/* allocated_port and handle are not checked */
	প্রত্যাগম 1;
}

/* returns port number, FWD_PERMIT_ANY_PORT or -1 on error */
পূর্ণাঙ্ক
permitopen_port(ধ্রুব বর্ণ *p)
{
	পূর্ণাঙ্ক port;

	যদি (strcmp(p, "*") == 0)
		প্রত্যাগম FWD_PERMIT_ANY_PORT;
	যদি ((port = a2port(p)) > 0)
		প্রত্যাগম port;
	প্রত্যাগম -1;
}

/* returns 1 if process is already daemonized, 0 otherwise */
পূর্ণাঙ্ক
daemonized(শূন্য)
{
	পূর্ণাঙ্ক fd;

	যদি ((fd = open(_PATH_TTY, O_RDONLY | O_NOCTTY)) >= 0) {
		close(fd);
		প্রত্যাগম 0;	/* have controlling terminal */
	}
	যদি (getppid() != 1)
		প্রত্যাগম 0;	/* parent is not init */
	যদি (getsid(0) != getpid())
		প্রত্যাগম 0;	/* not session leader */
	debug3("already daemonized");
	প্রত্যাগম 1;
}

/*
 * Splits 's' into an argument vector. Handles quoted string and basic
 * escape characters (\\, \", \'). Caller must free the argument vector
 * and its members.
 */
পূর্ণাঙ্ক
argv_split(ধ্রুব বর্ণ *s, পূর্ণাঙ্ক *argcp, বর্ণ ***argvp, পূর্ণাঙ্ক terminate_on_comment)
{
	পূর্ণাঙ্ক r = SSH_ERR_INTERNAL_ERROR;
	পূর্ণাঙ্ক argc = 0, quote, i, j;
	বর্ণ *arg, **argv = xcalloc(1, পরিমাণ(*argv));

	*argvp = রিক্ত;
	*argcp = 0;

	প্রতি (i = 0; s[i] != '\0'; i++) {
		/* Skip leading whitespace */
		যদি (s[i] == ' ' || s[i] == '\t')
			অনুবর্ত;
		যদি (terminate_on_comment && s[i] == '#')
			ভঙ্গ;
		/* Start of a token */
		quote = 0;

		argv = xreallocarray(argv, (argc + 2), পরিমাণ(*argv));
		arg = argv[argc++] = xcalloc(1, strlen(s + i) + 1);
		argv[argc] = রিক্ত;

		/* Copy the token in, removing escapes */
		প্রতি (j = 0; s[i] != '\0'; i++) {
			যদি (s[i] == '\\') {
				যদি (s[i + 1] == '\'' ||
				    s[i + 1] == '\"' ||
				    s[i + 1] == '\\' ||
				    (quote == 0 && s[i + 1] == ' ')) {
					i++; /* Skip '\' */
					arg[j++] = s[i];
				} অন্যথা {
					/* Unrecognised escape */
					arg[j++] = s[i];
				}
			} অন্যথা যদি (quote == 0 && (s[i] == ' ' || s[i] == '\t'))
				ভঙ্গ; /* done */
			অন্যথা যদি (quote == 0 && (s[i] == '\"' || s[i] == '\''))
				quote = s[i]; /* quote start */
			অন্যথা যদি (quote != 0 && s[i] == quote)
				quote = 0; /* quote end */
			অন্যথা
				arg[j++] = s[i];
		}
		যদি (s[i] == '\0') {
			যদি (quote != 0) {
				/* Ran out of string looking for close quote */
				r = SSH_ERR_INVALID_FORMAT;
				গচ্ছ out;
			}
			ভঙ্গ;
		}
	}
	/* Success */
	*argcp = argc;
	*argvp = argv;
	argc = 0;
	argv = রিক্ত;
	r = 0;
 out:
	যদি (argc != 0 && argv != রিক্ত) {
		প্রতি (i = 0; i < argc; i++)
			মুক্ত(argv[i]);
		মুক্ত(argv);
	}
	প্রত্যাগম r;
}

/*
 * Reassemble an argument vector into a string, quoting and escaping as
 * necessary. Caller must free returned string.
 */
বর্ণ *
argv_assemble(পূর্ণাঙ্ক argc, বর্ণ **argv)
{
	পূর্ণাঙ্ক i, j, ws, r;
	বর্ণ c, *ret;
	সংরচনা sshbuf *buf, *arg;

	যদি ((buf = sshbuf_new()) == রিক্ত || (arg = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new failed");

	প্রতি (i = 0; i < argc; i++) {
		ws = 0;
		sshbuf_reset(arg);
		প্রতি (j = 0; argv[i][j] != '\0'; j++) {
			r = 0;
			c = argv[i][j];
			বিকল্প (c) {
			পক্ষ ' ':
			পক্ষ '\t':
				ws = 1;
				r = sshbuf_put_u8(arg, c);
				ভঙ্গ;
			পক্ষ '\\':
			পক্ষ '\'':
			পক্ষ '"':
				যদি ((r = sshbuf_put_u8(arg, '\\')) != 0)
					ভঙ্গ;
				/* FALLTHROUGH */
			স্বভাব:
				r = sshbuf_put_u8(arg, c);
				ভঙ্গ;
			}
			যদি (r != 0)
				fatal_fr(r, "sshbuf_put_u8");
		}
		যদি ((i != 0 && (r = sshbuf_put_u8(buf, ' ')) != 0) ||
		    (ws != 0 && (r = sshbuf_put_u8(buf, '"')) != 0) ||
		    (r = sshbuf_putb(buf, arg)) != 0 ||
		    (ws != 0 && (r = sshbuf_put_u8(buf, '"')) != 0))
			fatal_fr(r, "assemble");
	}
	যদি ((ret = malloc(sshbuf_len(buf) + 1)) == রিক্ত)
		fatal_f("malloc failed");
	memcpy(ret, sshbuf_ptr(buf), sshbuf_len(buf));
	ret[sshbuf_len(buf)] = '\0';
	sshbuf_free(buf);
	sshbuf_free(arg);
	প্রত্যাগম ret;
}

বর্ণ *
argv_next(পূর্ণাঙ্ক *argcp, বর্ণ ***argvp)
{
	বর্ণ *ret = (*argvp)[0];

	যদি (*argcp > 0 && ret != রিক্ত) {
		(*argcp)--;
		(*argvp)++;
	}
	প্রত্যাগম ret;
}

শূন্য
argv_consume(পূর্ণাঙ্ক *argcp)
{
	*argcp = 0;
}

শূন্য
argv_free(বর্ণ **av, পূর্ণাঙ্ক ac)
{
	পূর্ণাঙ্ক i;

	যদি (av == রিক্ত)
		প্রত্যাগম;
	প্রতি (i = 0; i < ac; i++)
		মুক্ত(av[i]);
	মুক্ত(av);
}

/* Returns 0 if pid exited cleanly, non-zero otherwise */
পূর্ণাঙ্ক
exited_cleanly(pid_t pid, ধ্রুব বর্ণ *tag, ধ্রুব বর্ণ *cmd, পূর্ণাঙ্ক quiet)
{
	পূর্ণাঙ্ক status;

	যাবত্ (waitpid(pid, &status, 0) == -1) {
		যদি (errno != EINTR) {
			error("%s waitpid: %s", tag, strerror(errno));
			প্রত্যাগম -1;
		}
	}
	যদি (WIFSIGNALED(status)) {
		error("%s %s exited on signal %d", tag, cmd, WTERMSIG(status));
		প্রত্যাগম -1;
	} অন্যথা যদি (WEXITSTATUS(status) != 0) {
		do_log2(quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_INFO,
		    "%s %s failed, status %d", tag, cmd, WEXITSTATUS(status));
		প্রত্যাগম -1;
	}
	প্রত্যাগম 0;
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
পূর্ণাঙ্ক
safe_path(ধ্রুব বর্ণ *name, সংরচনা stat *stp, ধ্রুব বর্ণ *pw_dir,
    uid_t uid, বর্ণ *err, size_t errlen)
{
	বর্ণ buf[PATH_MAX], buf2[PATH_MAX], homedir[PATH_MAX];
	বর্ণ *cp;
	পূর্ণাঙ্ক comparehome = 0;
	সংরচনা stat st;

	যদি (realpath(name, buf) == রিক্ত) {
		snprintf(err, errlen, "realpath %s failed: %s", name,
		    strerror(errno));
		প্রত্যাগম -1;
	}
	যদি (pw_dir != রিক্ত && realpath(pw_dir, homedir) != রিক্ত)
		comparehome = 1;

	যদি (!S_ISREG(stp->st_mode)) {
		snprintf(err, errlen, "%s is not a regular file", buf);
		প্রত্যাগম -1;
	}
	যদি ((!platform_sys_dir_uid(stp->st_uid) && stp->st_uid != uid) ||
	    (stp->st_mode & 022) != 0) {
		snprintf(err, errlen, "bad ownership or modes for file %s",
		    buf);
		প্রত্যাগম -1;
	}

	/* for each component of the canonical path, walking upwards */
	প্রতি (;;) {
		/*
		 * POSIX allows dirname to modify its argument and return a
		 * pointer into it, so make a copy to avoid overlapping strlcpy.
		 */
		strlcpy(buf2, buf, পরিমাণ(buf2));
		যদি ((cp = dirname(buf2)) == রিক্ত) {
			snprintf(err, errlen, "dirname() failed");
			প্রত্যাগম -1;
		}
		strlcpy(buf, cp, পরিমাণ(buf));

		যদি (stat(buf, &st) == -1 ||
		    (!platform_sys_dir_uid(st.st_uid) && st.st_uid != uid) ||
		    (st.st_mode & 022) != 0) {
			snprintf(err, errlen,
			    "bad ownership or modes for directory %s", buf);
			প্রত্যাগম -1;
		}

		/* If are past the homedir then we can stop */
		যদি (comparehome && strcmp(homedir, buf) == 0)
			ভঙ্গ;

		/*
		 * dirname should always complete with a "/" path,
		 * but we can be paranoid and check for "." too
		 */
		যদি ((strcmp("/", buf) == 0) || (strcmp(".", buf) == 0))
			ভঙ্গ;
	}
	প্রত্যাগম 0;
}

/*
 * Version of safe_path() that accepts an open file descriptor to
 * avoid races.
 *
 * Returns 0 on success and -1 on failure
 */
পূর্ণাঙ্ক
safe_path_fd(পূর্ণাঙ্ক fd, ধ্রুব বর্ণ *file, সংরচনা passwd *pw,
    বর্ণ *err, size_t errlen)
{
	সংরচনা stat st;

	/* check the open file to avoid races */
	যদি (fstat(fd, &st) == -1) {
		snprintf(err, errlen, "cannot stat file %s: %s",
		    file, strerror(errno));
		প্রত্যাগম -1;
	}
	প্রত্যাগম safe_path(file, &st, pw->pw_dir, pw->pw_uid, err, errlen);
}

/*
 * Sets the value of the given variable in the environment.  If the variable
 * already exists, its value is overridden.
 */
শূন্য
child_set_env(বর্ণ ***envp, u_int *envsizep, ধ্রুব বর্ণ *name,
	ধ্রুব বর্ণ *মান)
{
	বর্ণ **env;
	u_int envsize;
	u_int i, namelen;

	যদি (strchr(name, '=') != রিক্ত) {
		error("Invalid environment variable \"%.100s\"", name);
		প্রত্যাগম;
	}

	/*
	 * If we're passed an uninitialized list, allocate a single null
	 * entry before continuing.
	 */
	যদি ((*envp == রিক্ত) != (*envsizep == 0))
		fatal_f("environment size mismatch");
	যদি (*envp == রিক্ত && *envsizep == 0) {
		*envp = xmalloc(পরিমাণ(বর্ণ *));
		*envp[0] = রিক্ত;
		*envsizep = 1;
	}

	/*
	 * Find the slot where the value should be stored.  If the variable
	 * already exists, we reuse the slot; otherwise we append a new slot
	 * at the end of the array, expanding if necessary.
	 */
	env = *envp;
	namelen = strlen(name);
	প্রতি (i = 0; env[i]; i++)
		যদি (strncmp(env[i], name, namelen) == 0 && env[i][namelen] == '=')
			ভঙ্গ;
	যদি (env[i]) {
		/* Reuse the slot. */
		মুক্ত(env[i]);
	} অন্যথা {
		/* New variable.  Expand if necessary. */
		envsize = *envsizep;
		যদি (i >= envsize - 1) {
			যদি (envsize >= 1000)
				fatal("child_set_env: too many env vars");
			envsize += 50;
			env = (*envp) = xreallocarray(env, envsize, পরিমাণ(বর্ণ *));
			*envsizep = envsize;
		}
		/* Need to set the NULL pointer at end of array beyond the new slot. */
		env[i + 1] = রিক্ত;
	}

	/* Allocate space and format the variable in the appropriate slot. */
	/* XXX xasprintf */
	env[i] = xmalloc(strlen(name) + 1 + strlen(মান) + 1);
	snprintf(env[i], strlen(name) + 1 + strlen(মান) + 1, "%s=%s", name, মান);
}

/*
 * Check and optionally lowercase a domain name, also removes trailing '.'
 * Returns 1 on success and 0 on failure, storing an error message in errstr.
 */
পূর্ণাঙ্ক
valid_domain(বর্ণ *name, পূর্ণাঙ্ক makelower, ধ্রুব বর্ণ **errstr)
{
	size_t i, l = strlen(name);
	u_char c, last = '\0';
	স্থির বর্ণ errbuf[256];

	যদি (l == 0) {
		strlcpy(errbuf, "empty domain name", পরিমাণ(errbuf));
		গচ্ছ bad;
	}
	যদি (!isalpha((u_char)name[0]) && !isdigit((u_char)name[0]) &&
	   name[0] != '_' /* technically invalid, but common */) {
		snprintf(errbuf, পরিমাণ(errbuf), "domain name \"%.100s\" "
		    "starts with invalid character", name);
		গচ্ছ bad;
	}
	প্রতি (i = 0; i < l; i++) {
		c = tolower((u_char)name[i]);
		যদি (makelower)
			name[i] = (বর্ণ)c;
		যদি (last == '.' && c == '.') {
			snprintf(errbuf, পরিমাণ(errbuf), "domain name "
			    "\"%.100s\" contains consecutive separators", name);
			গচ্ছ bad;
		}
		যদি (c != '.' && c != '-' && !isalnum(c) &&
		    c != '_') /* technically invalid, but common */ {
			snprintf(errbuf, পরিমাণ(errbuf), "domain name "
			    "\"%.100s\" contains invalid characters", name);
			গচ্ছ bad;
		}
		last = c;
	}
	যদি (name[l - 1] == '.')
		name[l - 1] = '\0';
	যদি (errstr != রিক্ত)
		*errstr = রিক্ত;
	প্রত্যাগম 1;
bad:
	যদি (errstr != রিক্ত)
		*errstr = errbuf;
	প্রত্যাগম 0;
}

/*
 * Verify that a environment variable name (not including initial '$') is
 * valid; consisting of one or more alphanumeric or underscore characters only.
 * Returns 1 on valid, 0 otherwise.
 */
পূর্ণাঙ্ক
valid_env_name(ধ্রুব বর্ণ *name)
{
	ধ্রুব বর্ণ *cp;

	যদি (name[0] == '\0')
		প্রত্যাগম 0;
	প্রতি (cp = name; *cp != '\0'; cp++) {
		যদি (!isalnum((u_char)*cp) && *cp != '_')
			প্রত্যাগম 0;
	}
	প্রত্যাগম 1;
}

ধ্রুব বর্ণ *
atoi_err(ধ্রুব বর্ণ *nptr, পূর্ণাঙ্ক *val)
{
	ধ্রুব বর্ণ *errstr = রিক্ত;

	যদি (nptr == রিক্ত || *nptr == '\0')
		প্রত্যাগম "missing";
	*val = strtonum(nptr, 0, INT_MAX, &errstr);
	প্রত্যাগম errstr;
}

পূর্ণাঙ্ক
parse_absolute_time(ধ্রুব বর্ণ *s, uint64_t *tp)
{
	সংরচনা tm tm;
	time_t tt;
	বর্ণ buf[32], *fmt;
	ধ্রুব বর্ণ *cp;
	size_t l;
	পূর্ণাঙ্ক is_utc = 0;

	*tp = 0;

	l = strlen(s);
	যদি (l > 1 && strcasecmp(s + l - 1, "Z") == 0) {
		is_utc = 1;
		l--;
	} অন্যথা যদি (l > 3 && strcasecmp(s + l - 3, "UTC") == 0) {
		is_utc = 1;
		l -= 3;
	}
	/*
	 * POSIX strptime says "The application shall ensure that there
	 * is white-space or other non-alphanumeric characters between
	 * any two conversion specifications" so arrange things this way.
	 */
	বিকল্প (l) {
	পক্ষ 8: /* YYYYMMDD */
		fmt = "%Y-%m-%d";
		snprintf(buf, পরিমাণ(buf), "%.4s-%.2s-%.2s", s, s + 4, s + 6);
		ভঙ্গ;
	পক্ষ 12: /* YYYYMMDDHHMM */
		fmt = "%Y-%m-%dT%H:%M";
		snprintf(buf, পরিমাণ(buf), "%.4s-%.2s-%.2sT%.2s:%.2s",
		    s, s + 4, s + 6, s + 8, s + 10);
		ভঙ্গ;
	পক্ষ 14: /* YYYYMMDDHHMMSS */
		fmt = "%Y-%m-%dT%H:%M:%S";
		snprintf(buf, পরিমাণ(buf), "%.4s-%.2s-%.2sT%.2s:%.2s:%.2s",
		    s, s + 4, s + 6, s + 8, s + 10, s + 12);
		ভঙ্গ;
	স্বভাব:
		প্রত্যাগম SSH_ERR_INVALID_FORMAT;
	}

	memset(&tm, 0, পরিমাণ(tm));
	যদি ((cp = strptime(buf, fmt, &tm)) == রিক্ত || *cp != '\0')
		প্রত্যাগম SSH_ERR_INVALID_FORMAT;
	যদি (is_utc) {
		tm.tm_wday = -1;	/* sentinel for error */
		যদি ((tt = timegm(&tm)) == -1 && tm.tm_wday == -1)
			প্রত্যাগম SSH_ERR_INVALID_FORMAT;
	} অন্যথা {
		tm.tm_wday = -1;	/* sentinel for error */
		tm.tm_isdst = -1;	/* mktime decides DST */
		যদি ((tt = mktime(&tm)) == -1 && tm.tm_wday == -1)
			প্রত্যাগম SSH_ERR_INVALID_FORMAT;
	}
	/* success */
	*tp = (uint64_t)tt;
	প্রত্যাগম 0;
}

শূন্য
format_absolute_time(uint64_t t, বর্ণ *buf, size_t len)
{
	time_t tt = t > SSH_TIME_T_MAX ? SSH_TIME_T_MAX : t;
	সংরচনা tm tm;

	যদি (localtime_r(&tt, &tm) == রিক্ত)
		strlcpy(buf, "UNKNOWN-TIME", len);
	অন্যথা
		strftime(buf, len, "%Y-%m-%dT%H:%M:%S", &tm);
}

/*
 * Parse a "pattern=interval" clause (e.g. a ChannelTimeout).
 * Returns 0 on success or non-zero on failure.
 * Caller must free *typep.
 */
পূর্ণাঙ্ক
parse_pattern_interval(ধ্রুব বর্ণ *s, বর্ণ **typep, দ্বিগুণ *secsp)
{
	বর্ণ *cp, *sdup;
	দ্বিগুণ secs;

	যদি (typep != রিক্ত)
		*typep = রিক্ত;
	যদি (secsp != রিক্ত)
		*secsp = 0;
	যদি (s == রিক্ত)
		প্রত্যাগম -1;
	sdup = xstrdup(s);

	যদি ((cp = strchr(sdup, '=')) == রিক্ত || cp == sdup) {
		মুক্ত(sdup);
		প্রত্যাগম -1;
	}
	*cp++ = '\0';
	যদি ((secs = convtime_double(cp)) < 0.0) {
		মুক্ত(sdup);
		প্রত্যাগম -1;
	}
	/* success */
	যদি (typep != রিক্ত)
		*typep = xstrdup(sdup);
	যদি (secsp != রিক্ত)
		*secsp = secs;
	মুক্ত(sdup);
	প্রত্যাগম 0;
}

/* check if path is absolute */
পূর্ণাঙ্ক
path_absolute(ধ্রুব বর্ণ *path)
{
	প্রত্যাগম (*path == '/') ? 1 : 0;
}

শূন্য
skip_space(বর্ণ **cpp)
{
	বর্ণ *cp;

	প্রতি (cp = *cpp; *cp == ' ' || *cp == '\t'; cp++)
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
পূর্ণাঙ্ক
opt_flag(ধ্রুব বর্ণ *opt, পূর্ণাঙ্ক allow_negate, ধ্রুব বর্ণ **optsp)
{
	size_t opt_len = strlen(opt);
	ধ্রুব বর্ণ *opts = *optsp;
	পূর্ণাঙ্ক negate = 0;

	যদি (allow_negate && strncasecmp(opts, "no-", 3) == 0) {
		opts += 3;
		negate = 1;
	}
	যদি (strncasecmp(opts, opt, opt_len) == 0) {
		*optsp = opts + opt_len;
		প্রত্যাগম negate ? 0 : 1;
	}
	প্রত্যাগম -1;
}

বর্ণ *
opt_dequote(ধ্রুব বর্ণ **sp, ধ্রুব বর্ণ **errstrp)
{
	ধ্রুব বর্ণ *s = *sp;
	বর্ণ *ret;
	size_t i;

	*errstrp = রিক্ত;
	যদি (*s != '"') {
		*errstrp = "missing start quote";
		প্রত্যাগম রিক্ত;
	}
	s++;
	যদি ((ret = malloc(strlen((s)) + 1)) == রিক্ত) {
		*errstrp = "memory allocation failed";
		প্রত্যাগম রিক্ত;
	}
	প্রতি (i = 0; *s != '\0' && *s != '"';) {
		যদি (s[0] == '\\' && s[1] == '"')
			s++;
		ret[i++] = *s++;
	}
	যদি (*s == '\0') {
		*errstrp = "missing end quote";
		মুক্ত(ret);
		প্রত্যাগম রিক্ত;
	}
	ret[i] = '\0';
	s++;
	*sp = s;
	প্রত্যাগম ret;
}

পূর্ণাঙ্ক
opt_match(ধ্রুব বর্ণ **opts, ধ্রুব বর্ণ *term)
{
	যদি (strncasecmp((*opts), term, strlen(term)) == 0 &&
	    (*opts)[strlen(term)] == '=') {
		*opts += strlen(term) + 1;
		প্রত্যাগম 1;
	}
	প্রত্যাগম 0;
}

শূন্য
opt_array_append2(ধ্রুব বর্ণ *file, ধ্রুব পূর্ণাঙ্ক সারি, ধ্রুব বর্ণ *directive,
    বর্ণ ***array, পূর্ণাঙ্ক **iarray, u_int *lp, ধ্রুব বর্ণ *s, পূর্ণাঙ্ক i)
{

	যদি (*lp >= INT_MAX)
		fatal("%s line %d: Too many %s entries", file, সারি, directive);

	যদি (iarray != রিক্ত) {
		*iarray = xrecallocarray(*iarray, *lp, *lp + 1,
		    পরিমাণ(**iarray));
		(*iarray)[*lp] = i;
	}

	*array = xrecallocarray(*array, *lp, *lp + 1, পরিমাণ(**array));
	(*array)[*lp] = xstrdup(s);
	(*lp)++;
}

শূন্য
opt_array_append(ধ্রুব বর্ণ *file, ধ্রুব পূর্ণাঙ্ক সারি, ধ্রুব বর্ণ *directive,
    বর্ণ ***array, u_int *lp, ধ্রুব বর্ণ *s)
{
	opt_array_append2(file, সারি, directive, array, রিক্ত, lp, s, 0);
}

শূন্য
opt_array_free2(বর্ণ **array, পূর্ণাঙ্ক **iarray, u_int l)
{
	u_int i;

	যদি (array == রিক্ত || l == 0)
		প্রত্যাগম;
	প্রতি (i = 0; i < l; i++)
		মুক্ত(array[i]);
	মুক্ত(array);
	মুক্ত(iarray);
}

sshsig_t
ssh_signal(পূর্ণাঙ্ক signum, sshsig_t handler)
{
	সংরচনা sigaction sa, osa;

	/* mask all other signals while in handler */
	memset(&sa, 0, পরিমাণ(sa));
	sa.sa_handler = handler;
	sigfillset(&sa.sa_mask);
#যদি defined(SA_RESTART) && !defined(NO_SA_RESTART)
	যদি (signum != SIGALRM)
		sa.sa_flags = SA_RESTART;
#endif
	যদি (sigaction(signum, &sa, &osa) == -1) {
		debug3("sigaction(%s): %s", strsignal(signum), strerror(errno));
		প্রত্যাগম SIG_ERR;
	}
	প্রত্যাগম osa.sa_handler;
}

পূর্ণাঙ্ক
stdfd_devnull(পূর্ণাঙ্ক do_stdin, পূর্ণাঙ্ক do_stdout, পূর্ণাঙ্ক do_stderr)
{
	পূর্ণাঙ্ক devnull, ret = 0;

	যদি ((devnull = open(_PATH_DEVNULL, O_RDWR)) == -1) {
		error_f("open %s: %s", _PATH_DEVNULL,
		    strerror(errno));
		প্রত্যাগম -1;
	}
	যদি ((do_stdin && dup2(devnull, STDIN_FILENO) == -1) ||
	    (do_stdout && dup2(devnull, STDOUT_FILENO) == -1) ||
	    (do_stderr && dup2(devnull, STDERR_FILENO) == -1)) {
		error_f("dup2: %s", strerror(errno));
		ret = -1;
	}
	যদি (devnull > STDERR_FILENO)
		close(devnull);
	প্রত্যাগম ret;
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
subprocess(ধ্রুব বর্ণ *tag, ধ্রুব বর্ণ *command,
    পূর্ণাঙ্ক ac, বর্ণ **av, FILE **child, u_int flags,
    সংরচনা passwd *pw, privdrop_fn *drop_privs, privrestore_fn *restore_privs)
{
	FILE *f = রিক্ত;
	সংরচনা stat st;
	পূর্ণাঙ্ক fd, devnull, p[2], i;
	pid_t pid;
	বর্ণ *cp, errmsg[512];
	u_int nenv = 0;
	বর্ণ **env = রিক্ত;

	/* If dropping privs, then must specify user and restore function */
	যদি (drop_privs != রিক্ত && (pw == রিক্ত || restore_privs == রিক্ত)) {
		error("%s: inconsistent arguments", tag); /* XXX fatal? */
		প্রত্যাগম 0;
	}
	যদি (pw == রিক্ত && (pw = getpwuid(getuid())) == রিক্ত) {
		error("%s: no user for current uid", tag);
		প্রত্যাগম 0;
	}
	যদি (child != রিক্ত)
		*child = রিক্ত;

	debug3_f("%s command \"%s\" running as %s (flags 0x%x)",
	    tag, command, pw->pw_name, flags);

	/* Check consistency */
	যদি ((flags & SSH_SUBPROCESS_STDOUT_DISCARD) != 0 &&
	    (flags & SSH_SUBPROCESS_STDOUT_CAPTURE) != 0) {
		error_f("inconsistent flags");
		প্রত্যাগম 0;
	}
	যদি (((flags & SSH_SUBPROCESS_STDOUT_CAPTURE) == 0) != (child == রিক্ত)) {
		error_f("inconsistent flags/output");
		প্রত্যাগম 0;
	}

	/*
	 * If executing an explicit binary, then verify the it exists
	 * and appears safe-ish to execute
	 */
	যদি (!path_absolute(av[0])) {
		error("%s path is not absolute", tag);
		প্রত্যাগম 0;
	}
	যদি (drop_privs != রিক্ত)
		drop_privs(pw);
	যদি (stat(av[0], &st) == -1) {
		error("Could not stat %s \"%s\": %s", tag,
		    av[0], strerror(errno));
		গচ্ছ restore_return;
	}
	যদি ((flags & SSH_SUBPROCESS_UNSAFE_PATH) == 0 &&
	    safe_path(av[0], &st, রিক্ত, 0, errmsg, পরিমাণ(errmsg)) != 0) {
		error("Unsafe %s \"%s\": %s", tag, av[0], errmsg);
		গচ্ছ restore_return;
	}
	/* Prepare to keep the child's stdout if requested */
	যদি (pipe(p) == -1) {
		error("%s: pipe: %s", tag, strerror(errno));
 restore_return:
		যদি (restore_privs != রিক্ত)
			restore_privs();
		প্রত্যাগম 0;
	}
	যদি (restore_privs != রিক্ত)
		restore_privs();

	বিকল্প ((pid = fork())) {
	পক্ষ -1: /* error */
		error("%s: fork: %s", tag, strerror(errno));
		close(p[0]);
		close(p[1]);
		প্রত্যাগম 0;
	পক্ষ 0: /* child */
		/* Prepare a minimal environment for the child. */
		যদি ((flags & SSH_SUBPROCESS_PRESERVE_ENV) == 0) {
			nenv = 5;
			env = xcalloc(পরিমাণ(*env), nenv);
			child_set_env(&env, &nenv, "PATH", _PATH_STDPATH);
			child_set_env(&env, &nenv, "USER", pw->pw_name);
			child_set_env(&env, &nenv, "LOGNAME", pw->pw_name);
			child_set_env(&env, &nenv, "HOME", pw->pw_dir);
			যদি ((cp = getenv("LANG")) != রিক্ত)
				child_set_env(&env, &nenv, "LANG", cp);
		}

		প্রতি (i = 1; i < NSIG; i++)
			ssh_signal(i, SIG_DFL);

		যদি ((devnull = open(_PATH_DEVNULL, O_RDWR)) == -1) {
			error("%s: open %s: %s", tag, _PATH_DEVNULL,
			    strerror(errno));
			_exit(1);
		}
		যদি (dup2(devnull, STDIN_FILENO) == -1) {
			error("%s: dup2: %s", tag, strerror(errno));
			_exit(1);
		}

		/* Set up stdout as requested; leave stderr in place for now. */
		fd = -1;
		যদি ((flags & SSH_SUBPROCESS_STDOUT_CAPTURE) != 0)
			fd = p[1];
		অন্যথা যদি ((flags & SSH_SUBPROCESS_STDOUT_DISCARD) != 0)
			fd = devnull;
		যদি (fd != -1 && dup2(fd, STDOUT_FILENO) == -1) {
			error("%s: dup2: %s", tag, strerror(errno));
			_exit(1);
		}
		closefrom(STDERR_FILENO + 1);

		যদি (geteuid() == 0 &&
		    initgroups(pw->pw_name, pw->pw_gid) == -1) {
			error("%s: initgroups(%s, %u): %s", tag,
			    pw->pw_name, (u_int)pw->pw_gid, strerror(errno));
			_exit(1);
		}
		যদি (setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) == -1) {
			error("%s: setresgid %u: %s", tag, (u_int)pw->pw_gid,
			    strerror(errno));
			_exit(1);
		}
		যদি (setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) == -1) {
			error("%s: setresuid %u: %s", tag, (u_int)pw->pw_uid,
			    strerror(errno));
			_exit(1);
		}
		/* stdin is pointed to /dev/null at this point */
		যদি ((flags & SSH_SUBPROCESS_STDOUT_DISCARD) != 0 &&
		    dup2(STDIN_FILENO, STDERR_FILENO) == -1) {
			error("%s: dup2: %s", tag, strerror(errno));
			_exit(1);
		}
		যদি (env != রিক্ত)
			execve(av[0], av, env);
		অন্যথা
			execv(av[0], av);
		error("%s %s \"%s\": %s", tag, env == রিক্ত ? "execv" : "execve",
		    command, strerror(errno));
		_exit(127);
	স্বভাব: /* parent */
		ভঙ্গ;
	}

	close(p[1]);
	যদি ((flags & SSH_SUBPROCESS_STDOUT_CAPTURE) == 0)
		close(p[0]);
	অন্যথা যদি ((f = fdopen(p[0], "r")) == রিক্ত) {
		error("%s: fdopen: %s", tag, strerror(errno));
		close(p[0]);
		/* Don't leave zombie child */
		kill(pid, SIGTERM);
		যাবত্ (waitpid(pid, রিক্ত, 0) == -1 && errno == EINTR)
			;
		প্রত্যাগম 0;
	}
	/* Success */
	debug3_f("%s pid %ld", tag, (long)pid);
	যদি (child != রিক্ত)
		*child = f;
	প্রত্যাগম pid;
}

ধ্রুব বর্ণ *
lookup_env_in_list(ধ্রুব বর্ণ *env, বর্ণ * ধ্রুব *envs, size_t nenvs)
{
	size_t i, envlen;

	envlen = strlen(env);
	প্রতি (i = 0; i < nenvs; i++) {
		যদি (strncmp(envs[i], env, envlen) == 0 &&
		    envs[i][envlen] == '=') {
			প্রত্যাগম envs[i] + envlen + 1;
		}
	}
	প্রত্যাগম রিক্ত;
}

ধ্রুব বর্ণ *
lookup_setenv_in_list(ধ্রুব বর্ণ *env, বর্ণ * ধ্রুব *envs, size_t nenvs)
{
	বর্ণ *name, *cp;
	ধ্রুব বর্ণ *ret;

	name = xstrdup(env);
	যদি ((cp = strchr(name, '=')) == রিক্ত) {
		মুক্ত(name);
		প্রত্যাগম রিক্ত; /* not env=val */
	}
	*cp = '\0';
	ret = lookup_env_in_list(name, envs, nenvs);
	মুক্ত(name);
	প্রত্যাগম ret;
}

/*
 * Helpers for managing poll(2)/ppoll(2) timeouts
 * Will remember the earliest deadline and return it for use in poll/ppoll.
 */

/* Initialise a poll/ppoll timeout with an indefinite deadline */
শূন্য
ptimeout_init(সংরচনা timespec *pt)
{
	/*
	 * Deliberately invalid for ppoll(2).
	 * Will be converted to NULL in ptimeout_get_tspec() later.
	 */
	pt->tv_sec = -1;
	pt->tv_nsec = 0;
}

/* Specify a poll/ppoll deadline of at most 'sec' seconds */
শূন্য
ptimeout_deadline_sec(সংরচনা timespec *pt, long sec)
{
	যদি (pt->tv_sec == -1 || pt->tv_sec >= sec) {
		pt->tv_sec = sec;
		pt->tv_nsec = 0;
	}
}

/* Specify a poll/ppoll deadline of at most 'p' (timespec) */
স্থির শূন্য
ptimeout_deadline_tsp(সংরচনা timespec *pt, সংরচনা timespec *p)
{
	যদি (pt->tv_sec == -1 || timespeccmp(pt, p, >=))
		*pt = *p;
}

/* Specify a poll/ppoll deadline of at most 'ms' milliseconds */
শূন্য
ptimeout_deadline_ms(সংরচনা timespec *pt, long ms)
{
	সংরচনা timespec p;

	p.tv_sec = ms / 1000;
	p.tv_nsec = (ms % 1000) * 1000000;
	ptimeout_deadline_tsp(pt, &p);
}

/* Specify a poll/ppoll deadline of at most 'sec' seconds (double) */
শূন্য
ptimeout_deadline_sec_double(সংরচনা timespec *pt, দ্বিগুণ sec)
{
	সংরচনা timespec t;

	memset(&t, 0, পরিমাণ(t));
	যদি ((int64_t)sec >= SSH_TIME_T_MAX)
		t.tv_sec = SSH_TIME_T_MAX;
	অন্যথা যদি (sec > 0) {
		t.tv_sec = sec;
		t.tv_nsec = (sec - (দ্বিগুণ)t.tv_sec) * 1000000000.0;
	}
	ptimeout_deadline_tsp(pt, &t);
}

/* Specify a poll/ppoll deadline at wall clock monotime 'when' (timespec) */
শূন্য
ptimeout_deadline_monotime_tsp(সংরচনা timespec *pt, সংরচনা timespec *when)
{
	সংরচনা timespec now, t;

	monotime_ts(&now);

	যদি (timespeccmp(&now, when, >=)) {
		/* 'when' is now or in the past. Timeout ASAP */
		pt->tv_sec = 0;
		pt->tv_nsec = 0;
	} অন্যথা {
		timespecsub(when, &now, &t);
		ptimeout_deadline_tsp(pt, &t);
	}
}

/* Specify a poll/ppoll deadline at wall clock monotime 'when' (double) */
শূন্য
ptimeout_deadline_monotime_double(সংরচনা timespec *pt, দ্বিগুণ when)
{
	ptimeout_deadline_sec_double(pt, when - monotime_double());
}

/* Specify a poll/ppoll deadline at wall clock monotime 'when' */
শূন্য
ptimeout_deadline_monotime(সংরচনা timespec *pt, time_t when)
{
	সংরচনা timespec t;

	t.tv_sec = when;
	t.tv_nsec = 0;
	ptimeout_deadline_monotime_tsp(pt, &t);
}

/* Get a poll(2) timeout value in milliseconds */
পূর্ণাঙ্ক
ptimeout_get_ms(সংরচনা timespec *pt)
{
	যদি (pt->tv_sec == -1)
		প্রত্যাগম -1;
	যদি (pt->tv_sec >= (INT_MAX - (pt->tv_nsec / 1000000)) / 1000)
		প্রত্যাগম INT_MAX;
	প্রত্যাগম (pt->tv_sec * 1000) + (pt->tv_nsec / 1000000);
}

/* Get a ppoll(2) timeout value as a timespec pointer */
সংরচনা timespec *
ptimeout_get_tsp(সংরচনা timespec *pt)
{
	প্রত্যাগম pt->tv_sec == -1 ? রিক্ত : pt;
}

/* Returns non-zero if a timeout has been set (i.e. is not indefinite) */
পূর্ণাঙ্ক
ptimeout_isset(সংরচনা timespec *pt)
{
	প্রত্যাগম pt->tv_sec != -1;
}

/*
 * Returns zero if the library at 'path' contains symbol 's', nonzero
 * otherwise.
 */
পূর্ণাঙ্ক
lib_contains_প্রতীক(ধ্রুব বর্ণ *path, ধ্রুব বর্ণ *s)
{
#ifdef HAVE_NLIST
	সংরচনা nlist nl[2];
	পূর্ণাঙ্ক ret = -1, r;

	memset(nl, 0, পরিমাণ(nl));
	nl[0].n_name = xstrdup(s);
	nl[1].n_name = রিক্ত;
	যদি ((r = nlist(path, nl)) == -1) {
		error_f("nlist failed for %s", path);
		গচ্ছ out;
	}
	যদি (r != 0 || nl[0].n_মান == 0 || nl[0].n_type == 0) {
		error_f("library %s does not contain symbol %s", path, s);
		গচ্ছ out;
	}
	/* success */
	ret = 0;
 out:
	মুক্ত(nl[0].n_name);
	প্রত্যাগম ret;
#অন্যথা /* HAVE_NLIST */
	পূর্ণাঙ্ক fd, ret = -1;
	সংরচনা stat st;
	শূন্য *m = রিক্ত;
	size_t sz = 0;

	memset(&st, 0, পরিমাণ(st));
	যদি ((fd = open(path, O_RDONLY)) < 0) {
		error_f("open %s: %s", path, strerror(errno));
		প্রত্যাগম -1;
	}
	যদি (fstat(fd, &st) != 0) {
		error_f("fstat %s: %s", path, strerror(errno));
		গচ্ছ out;
	}
	যদি (!S_ISREG(st.st_mode)) {
		error_f("%s is not a regular file", path);
		গচ্ছ out;
	}
	যদি (st.st_size < 0 ||
	    (size_t)st.st_size < strlen(s) ||
	    st.st_size >= INT_MAX/2) {
		error_f("%s bad size %lld", path, (long long)st.st_size);
		গচ্ছ out;
	}
	sz = (size_t)st.st_size;
	যদি ((m = mmap(রিক্ত, sz, PROT_READ, MAP_PRIVATE, fd, 0)) == MAP_FAILED ||
	    m == রিক্ত) {
		error_f("mmap %s: %s", path, strerror(errno));
		গচ্ছ out;
	}
	যদি (memmem(m, sz, s, strlen(s)) == রিক্ত) {
		error_f("%s does not contain expected string %s", path, s);
		গচ্ছ out;
	}
	/* success */
	ret = 0;
 out:
	যদি (m != রিক্ত && m != MAP_FAILED)
		munmap(m, sz);
	close(fd);
	প্রত্যাগম ret;
#endif /* HAVE_NLIST */
}

পূর্ণাঙ্ক
signal_is_crash(পূর্ণাঙ্ক sig)
{
	বিকল্প (sig) {
	পক্ষ SIGSEGV:
	পক্ষ SIGBUS:
	পক্ষ SIGTRAP:
	পক্ষ SIGSYS:
	পক্ষ SIGFPE:
	পক্ষ SIGILL:
	পক্ষ SIGABRT:
		প্রত্যাগম 1;
	}
	প্রত্যাগম 0;
}

বর্ণ *
get_homedir(শূন্য)
{
	বর্ণ *cp;
	সংরচনা passwd *pw;

	যদি ((cp = getenv("HOME")) != রিক্ত && *cp != '\0')
		প্রত্যাগম xstrdup(cp);

	যদি ((pw = getpwuid(getuid())) != রিক্ত && *pw->pw_dir != '\0')
		প্রত্যাগম xstrdup(pw->pw_dir);

	প্রত্যাগম রিক্ত;
}

পূর্ণাঙ্ক
mkdir_path(ধ্রুব বর্ণ *target, mode_t mode)
{
#যদি defined(HAVE_OPENAT) && defined(O_DIRECTORY)
	বর্ণ *dir, *odir = রিক্ত, *next;
	পূর্ণাঙ্ক fd = AT_FDCWD, fd2, subpath_len, ret = -1;

	dir = odir = xstrdup(target);

	যদি (*dir == '/' &&
	    (fd = open("/", O_RDONLY|O_DIRECTORY)) == -1) {
		error_f("open(\"/\"): %s", strerror(errno));
		মুক্ত(odir);
		প্রত্যাগম -1;
	}
	/* Work through the path, component-wise */
	প্রতি (; dir != রিক্ত && *dir != '\0'; dir = next) {
		যদি ((next = strchr(dir, '/')) != রিক্ত)
			*(next++) = '\0';
		যদি (*dir == '\0')
			অনুবর্ত;
		subpath_len = (next == রিক্ত) ? INT_MAX : next - odir - 1;
		যদি (mkdirat(fd, dir, mode) == 0)
			debug_f("created directory %.*s", subpath_len, target);
		অন্যথা যদি (errno != EEXIST) {
			error_f("mkdir(\"%.*s\"): %s",
			    subpath_len, target, strerror(errno));
			গচ্ছ out;
		}

		/* descend */
		যদি ((fd2 = openat(fd, dir, O_RDONLY|O_DIRECTORY)) == -1) {
			error_f("open(\"%.*s\"): %s",
			    subpath_len, target, strerror(errno));
			গচ্ছ out;
		}
		যদি (fd != AT_FDCWD)
			close(fd);
		fd = fd2;
	}
	/* success */
	ret = 0;
 out:
	মুক্ত(odir);
	যদি (fd != AT_FDCWD)
		close(fd);
	প্রত্যাগম ret;
#অন্যথা
	/*
	 * If we don't have openat (which was added in POSIX.1-2008), fall back
	 * to the possibly racy way.
	 */
	বর্ণ *dir, *odir, *p, path[PATH_MAX] = "";
	পূর্ণাঙ্ক ret = -1;
	size_t plen = পরিমাণ(path);

	dir = odir = xstrdup(target);

	/* If the dir is relative, start with cwd. */
	যদি (*dir != '/' && getcwd(path, plen) == রিক্ত) {
		error_f("getcwd: %s", strerror(errno));
		গচ্ছ out;
	}

	/* Work through the path, component-wise */
	যাবত্ ((p = strsep(&dir, "/"))) {
		যদি (*p == '\0')
			অনুবর্ত;
		যদি (strlcat(path, "/", plen) >= plen ||
		    strlcat(path, p, plen) >= plen)
			গচ্ছ out;
		যদি (mkdir(path, mode) == 0)
			debug_f("created directory %s", path);
		অন্যথা যদি (errno != EEXIST && errno != EISDIR) {
			error_f("mkdir(\"%s\"): %s", path, strerror(errno));
			গচ্ছ out;
		}
	}
	/* success */
	ret = 0;
 out:
	মুক্ত(odir);
	প্রত্যাগম ret;
#endif
}
