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
অক্ষর *
chop(অক্ষর *s)
{
	অক্ষর *t = s;
	যখন (*t) {
		যদি (*t == '\n' || *t == '\r') {
			*t = '\0';
			ফেরত s;
		}
		t++;
	}
	ফেরত s;

}

/* remove whitespace from end of string */
শূন্য
rtrim(অক্ষর *s)
{
	আকার_t i;

	যদি ((i = strlen(s)) == 0)
		ফেরত;
	করো {
		i--;
		যদি (isspace((unsigned অক্ষর)s[i]))
			s[i] = '\0';
		অন্যথা
			বিরতি;
	} যখন (i > 0);
}

/*
 * returns pointer to character after 'prefix' in 's' or otherwise NULL
 * if the prefix is not present.
 */
ধ্রুবক অক্ষর *
strprefix(ধ্রুবক অক্ষর *s, ধ্রুবক অক্ষর *prefix, পূর্ণসংখ্যা ignorecase)
{
	আকার_t prefixlen;

	যদি ((prefixlen = strlen(prefix)) == 0)
		ফেরত s;
	যদি (ignorecase) {
		যদি (strncasecmp(s, prefix, prefixlen) != 0)
			ফেরত ফাঁকা;
	} অন্যথা {
		যদি (strncmp(s, prefix, prefixlen) != 0)
			ফেরত ফাঁকা;
	}
	ফেরত s + prefixlen;
}

/* Append string 's' to a NULL-terminated array of strings */
শূন্য
stringlist_append(অক্ষর ***listp, ধ্রুবক অক্ষর *s)
{
	আকার_t i = 0;

	যদি (*listp == ফাঁকা)
		*listp = xcalloc(2, আকার(**listp));
	অন্যথা {
		জন্য (i = 0; (*listp)[i] != ফাঁকা; i++)
			; /* count */
		*listp = xrecallocarray(*listp, i + 1, i + 2, আকার(**listp));
	}
	(*listp)[i] = xstrdup(s);
}

শূন্য
stringlist_free(অক্ষর **list)
{
	আকার_t i = 0;

	যদি (list == ফাঁকা)
		ফেরত;
	জন্য (i = 0; list[i] != ফাঁকা; i++)
		মুক্ত(list[i]);
	মুক্ত(list);
}

/* set/unset filedescriptor to non-blocking */
পূর্ণসংখ্যা
set_nonblock(পূর্ণসংখ্যা fd)
{
	পূর্ণসংখ্যা val;

	val = fcntl(fd, F_GETFL);
	যদি (val == -1) {
		error("fcntl(%d, F_GETFL): %s", fd, strerror(errno));
		ফেরত (-1);
	}
	যদি (val & O_NONBLOCK) {
		debug3("fd %d is O_NONBLOCK", fd);
		ফেরত (0);
	}
	debug2("fd %d setting O_NONBLOCK", fd);
	val |= O_NONBLOCK;
	যদি (fcntl(fd, F_SETFL, val) == -1) {
		debug("fcntl(%d, F_SETFL, O_NONBLOCK): %s", fd,
		    strerror(errno));
		ফেরত (-1);
	}
	ফেরত (0);
}

পূর্ণসংখ্যা
unset_nonblock(পূর্ণসংখ্যা fd)
{
	পূর্ণসংখ্যা val;

	val = fcntl(fd, F_GETFL);
	যদি (val == -1) {
		error("fcntl(%d, F_GETFL): %s", fd, strerror(errno));
		ফেরত (-1);
	}
	যদি (!(val & O_NONBLOCK)) {
		debug3("fd %d is not O_NONBLOCK", fd);
		ফেরত (0);
	}
	debug("fd %d clearing O_NONBLOCK", fd);
	val &= ~O_NONBLOCK;
	যদি (fcntl(fd, F_SETFL, val) == -1) {
		debug("fcntl(%d, F_SETFL, ~O_NONBLOCK): %s",
		    fd, strerror(errno));
		ফেরত (-1);
	}
	ফেরত (0);
}

ধ্রুবক অক্ষর *
ssh_gai_strerror(পূর্ণসংখ্যা gaierr)
{
	যদি (gaierr == EAI_SYSTEM && errno != 0)
		ফেরত strerror(errno);
	ফেরত gai_strerror(gaierr);
}

/* disable nagle on socket */
শূন্য
set_nodelay(পূর্ণসংখ্যা fd)
{
	পূর্ণসংখ্যা opt;
	socklen_t optlen;

	optlen = আকার opt;
	যদি (getsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, &optlen) == -1) {
		debug("getsockopt TCP_NODELAY: %.100s", strerror(errno));
		ফেরত;
	}
	যদি (opt == 1) {
		debug2("fd %d is TCP_NODELAY", fd);
		ফেরত;
	}
	opt = 1;
	debug2("fd %d setting TCP_NODELAY", fd);
	যদি (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, আকার opt) == -1)
		error("setsockopt TCP_NODELAY: %.100s", strerror(errno));
}

/* Allow local port reuse in TIME_WAIT */
পূর্ণসংখ্যা
set_reuseaddr(পূর্ণসংখ্যা fd)
{
	পূর্ণসংখ্যা on = 1;

	যদি (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, আকার(on)) == -1) {
		error("setsockopt SO_REUSEADDR fd %d: %s", fd, strerror(errno));
		ফেরত -1;
	}
	ফেরত 0;
}

/* Set TCP keepalives */
পূর্ণসংখ্যা
set_keepalive(পূর্ণসংখ্যা fd)
{
	পূর্ণসংখ্যা on = 1;

	যদি (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, আকার(on)) == -1) {
		error("setsockopt SO_KEEPALIVE fd %d: %s", fd, strerror(errno));
		ফেরত -1;
	}
	ফেরত 0;
}

/* Get/set routing domain */
অক্ষর *
get_rdomain(পূর্ণসংখ্যা fd)
{
#যদি defined(HAVE_SYS_GET_RDOMAIN)
	ফেরত sys_get_rdomain(fd);
#নতুবা_যদি defined(__OpenBSD__)
	পূর্ণসংখ্যা rtable;
	অক্ষর *ret;
	socklen_t len = আকার(rtable);

	যদি (getsockopt(fd, SOL_SOCKET, SO_RTABLE, &rtable, &len) == -1) {
		error("Failed to get routing domain for fd %d: %s",
		    fd, strerror(errno));
		ফেরত ফাঁকা;
	}
	xasprintf(&ret, "%d", rtable);
	ফেরত ret;
#অন্যথা /* defined(__OpenBSD__) */
	ফেরত ফাঁকা;
#endif
}

পূর্ণসংখ্যা
set_rdomain(পূর্ণসংখ্যা fd, ধ্রুবক অক্ষর *name)
{
#যদি defined(HAVE_SYS_SET_RDOMAIN)
	ফেরত sys_set_rdomain(fd, name);
#নতুবা_যদি defined(__OpenBSD__)
	পূর্ণসংখ্যা rtable;
	ধ্রুবক অক্ষর *errstr;

	যদি (name == ফাঁকা)
		ফেরত 0; /* default table */

	rtable = (পূর্ণসংখ্যা)strtonum(name, 0, 255, &errstr);
	যদি (errstr != ফাঁকা) {
		/* Shouldn't happen */
		error("Invalid routing domain \"%s\": %s", name, errstr);
		ফেরত -1;
	}
	যদি (setsockopt(fd, SOL_SOCKET, SO_RTABLE,
	    &rtable, আকার(rtable)) == -1) {
		error("Failed to set routing domain %d on fd %d: %s",
		    rtable, fd, strerror(errno));
		ফেরত -1;
	}
	ফেরত 0;
#অন্যথা /* defined(__OpenBSD__) */
	error("Setting routing domain is not supported on this platform");
	ফেরত -1;
#endif
}

পূর্ণসংখ্যা
get_sock_af(পূর্ণসংখ্যা fd)
{
	কাঠামো sockaddr_storage to;
	socklen_t tolen = আকার(to);

	memset(&to, 0, আকার(to));
	যদি (getsockname(fd, (কাঠামো sockaddr *)&to, &tolen) == -1)
		ফেরত -1;
#ifdef IPV4_IN_IPV6
	যদি (to.ss_family == AF_INET6 &&
	    IN6_IS_ADDR_V4MAPPED(&((কাঠামো sockaddr_in6 *)&to)->sin6_addr))
		ফেরত AF_INET;
#endif
	ফেরত to.ss_family;
}

শূন্য
set_sock_tos(পূর্ণসংখ্যা fd, পূর্ণসংখ্যা tos)
{
#ifndef IP_TOS_IS_BROKEN
	পূর্ণসংখ্যা af;

	যদি (tos < 0 || tos == INT_MAX) {
		debug_f("invalid TOS %d", tos);
		ফেরত;
	}
	নির্বাচন ((af = get_sock_af(fd))) {
	ক্ষেত্র -1:
		/* assume not a socket */
		বিরতি;
	ক্ষেত্র AF_INET:
# ifdef IP_TOS
		debug3_f("set socket %d IP_TOS 0x%02x", fd, tos);
		যদি (setsockopt(fd, IPPROTO_IP, IP_TOS,
		    &tos, আকার(tos)) == -1) {
			error("setsockopt socket %d IP_TOS %d: %s",
			    fd, tos, strerror(errno));
		}
# endif /* IP_TOS */
		বিরতি;
	ক্ষেত্র AF_INET6:
# ifdef IPV6_TCLASS
		debug3_f("set socket %d IPV6_TCLASS 0x%02x", fd, tos);
		যদি (setsockopt(fd, IPPROTO_IPV6, IPV6_TCLASS,
		    &tos, আকার(tos)) == -1) {
			error("setsockopt socket %d IPV6_TCLASS %d: %s",
			    fd, tos, strerror(errno));
		}
# endif /* IPV6_TCLASS */
		বিরতি;
	পূর্বনির্ধারিত:
		debug2_f("unsupported socket family %d", af);
		বিরতি;
	}
#endif /* IP_TOS_IS_BROKEN */
}

/*
 * Wait up to *timeoutp milliseconds for events on fd. Updates
 * *timeoutp with time remaining.
 * Returns 0 if fd ready or -1 on timeout or error (see errno).
 */
স্থির পূর্ণসংখ্যা
waitfd(পূর্ণসংখ্যা fd, পূর্ণসংখ্যা *timeoutp, short events, অস্থির sig_atomic_t *stop)
{
	কাঠামো pollfd pfd;
	কাঠামো timespec timeout;
	পূর্ণসংখ্যা oerrno, r;
	sigset_t nsigset, osigset;

	যদি (timeoutp && *timeoutp == -1)
		timeoutp = ফাঁকা;
	pfd.fd = fd;
	pfd.events = events;
	ptimeout_init(&timeout);
	যদি (timeoutp != ফাঁকা)
		ptimeout_deadline_ms(&timeout, *timeoutp);
	যদি (stop != ফাঁকা)
		sigfillset(&nsigset);
	জন্য (; timeoutp == ফাঁকা || *timeoutp >= 0;) {
		যদি (stop != ফাঁকা) {
			sigprocmask(SIG_BLOCK, &nsigset, &osigset);
			যদি (*stop) {
				sigprocmask(SIG_SETMASK, &osigset, ফাঁকা);
				errno = EINTR;
				ফেরত -1;
			}
		}
		r = ppoll(&pfd, 1, ptimeout_get_tsp(&timeout),
		    stop != ফাঁকা ? &osigset : ফাঁকা);
		oerrno = errno;
		যদি (stop != ফাঁকা)
			sigprocmask(SIG_SETMASK, &osigset, ফাঁকা);
		যদি (timeoutp)
			*timeoutp = ptimeout_get_ms(&timeout);
		errno = oerrno;
		যদি (r > 0)
			ফেরত 0;
		অন্যথা যদি (r == -1 && errno != EAGAIN && errno != EINTR)
			ফেরত -1;
		অন্যথা যদি (r == 0)
			বিরতি;
	}
	/* timeout */
	errno = ETIMEDOUT;
	ফেরত -1;
}

/*
 * Wait up to *timeoutp milliseconds for fd to be readable. Updates
 * *timeoutp with time remaining.
 * Returns 0 if fd ready or -1 on timeout or error (see errno).
 */
পূর্ণসংখ্যা
waitrfd(পূর্ণসংখ্যা fd, পূর্ণসংখ্যা *timeoutp, অস্থির sig_atomic_t *stop) {
	ফেরত waitfd(fd, timeoutp, POLLIN, stop);
}

/*
 * Attempt a non-blocking connect(2) to the specified address, waiting up to
 * *timeoutp milliseconds for the connection to complete. If the timeout is
 * <=0, then wait indefinitely.
 *
 * Returns 0 on success or -1 on failure.
 */
পূর্ণসংখ্যা
timeout_connect(পূর্ণসংখ্যা sockfd, ধ্রুবক কাঠামো sockaddr *serv_addr,
    socklen_t addrlen, পূর্ণসংখ্যা *timeoutp)
{
	পূর্ণসংখ্যা optval = 0;
	socklen_t optlen = আকার(optval);

	/* No timeout: just do a blocking connect() */
	যদি (timeoutp == ফাঁকা || *timeoutp <= 0)
		ফেরত connect(sockfd, serv_addr, addrlen);

	set_nonblock(sockfd);
	জন্য (;;) {
		যদি (connect(sockfd, serv_addr, addrlen) == 0) {
			/* Succeeded already? */
			unset_nonblock(sockfd);
			ফেরত 0;
		} অন্যথা যদি (errno == EINTR)
			চালু;
		অন্যথা যদি (errno != EINPROGRESS)
			ফেরত -1;
		বিরতি;
	}

	যদি (waitfd(sockfd, timeoutp, POLLIN | POLLOUT, ফাঁকা) == -1)
		ফেরত -1;

	/* Completed or failed */
	যদি (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &optval, &optlen) == -1) {
		debug("getsockopt: %s", strerror(errno));
		ফেরত -1;
	}
	যদি (optval != 0) {
		errno = optval;
		ফেরত -1;
	}
	unset_nonblock(sockfd);
	ফেরত 0;
}

/* Characters considered whitespace in strsep calls. */
#define WHITESPACE " \t\r\n"
#define QUOTE	"\""

/* return next token in configuration line */
স্থির অক্ষর *
strdelim_internal(অক্ষর **s, পূর্ণসংখ্যা split_equals)
{
	অক্ষর *old;
	পূর্ণসংখ্যা wspace = 0;

	যদি (*s == ফাঁকা)
		ফেরত ফাঁকা;

	old = *s;

	*s = strpbrk(*s,
	    split_equals ? WHITESPACE QUOTE "=" : WHITESPACE QUOTE);
	যদি (*s == ফাঁকা)
		ফেরত (old);

	যদি (*s[0] == '\"') {
		memmove(*s, *s + 1, strlen(*s)); /* move nul too */
		/* Find matching quote */
		যদি ((*s = strpbrk(*s, QUOTE)) == ফাঁকা) {
			ফেরত (ফাঁকা);		/* no matching quote */
		} অন্যথা {
			*s[0] = '\0';
			*s += strspn(*s + 1, WHITESPACE) + 1;
			ফেরত (old);
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

	ফেরত (old);
}

/*
 * Return next token in configuration line; splits on whitespace or a
 * single '=' character.
 */
অক্ষর *
strdelim(অক্ষর **s)
{
	ফেরত strdelim_internal(s, 1);
}

/*
 * Return next token in configuration line; splits on whitespace only.
 */
অক্ষর *
strdelimw(অক্ষর **s)
{
	ফেরত strdelim_internal(s, 0);
}

কাঠামো passwd *
pwcopy(কাঠামো passwd *pw)
{
	কাঠামো passwd *copy = xcalloc(1, আকার(*copy));

	copy->pw_name = xstrdup(pw->pw_name);
	copy->pw_passwd = xstrdup(pw->pw_passwd == ফাঁকা ? "*" : pw->pw_passwd);
#ifdef HAVE_STRUCT_PASSWD_PW_GECOS
	copy->pw_gecos = xstrdup(pw->pw_gecos == ফাঁকা ? "" : pw->pw_gecos);
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
	copy->pw_class = xstrdup(pw->pw_class == ফাঁকা ? "" : pw->pw_class);
#endif
	copy->pw_dir = xstrdup(pw->pw_dir == ফাঁকা ? "" : pw->pw_dir);
	copy->pw_shell = xstrdup(pw->pw_shell == ফাঁকা ? "" : pw->pw_shell);
	ফেরত copy;
}

শূন্য
pwfree(কাঠামো passwd *pw)
{
	যদি (pw == ফাঁকা)
		ফেরত;
	মুক্ত(pw->pw_name);
	freezero(pw->pw_passwd,
	    pw->pw_passwd == ফাঁকা ? 0 : strlen(pw->pw_passwd));
#ifdef HAVE_STRUCT_PASSWD_PW_GECOS
	মুক্ত(pw->pw_gecos);
#endif
#ifdef HAVE_STRUCT_PASSWD_PW_CLASS
	মুক্ত(pw->pw_class);
#endif
	মুক্ত(pw->pw_dir);
	মুক্ত(pw->pw_shell);
	freezero(pw, আকার(*pw));
}

/*
 * Convert ASCII string to TCP/IP port number.
 * Port must be >=0 and <=65535.
 * Return -1 if invalid.
 */
পূর্ণসংখ্যা
a2port(ধ্রুবক অক্ষর *s)
{
	কাঠামো servent *se;
	long long port;
	ধ্রুবক অক্ষর *errstr;

	port = strtonum(s, 0, 65535, &errstr);
	যদি (errstr == ফাঁকা)
		ফেরত (পূর্ণসংখ্যা)port;
	যদি ((se = getservbyname(s, "tcp")) != ফাঁকা)
		ফেরত ntohs(se->s_port);
	ফেরত -1;
}

পূর্ণসংখ্যা
a2tun(ধ্রুবক অক্ষর *s, পূর্ণসংখ্যা *remote)
{
	ধ্রুবক অক্ষর *errstr = ফাঁকা;
	অক্ষর *sp, *ep;
	পূর্ণসংখ্যা tun;

	যদি (remote != ফাঁকা) {
		*remote = SSH_TUNID_ANY;
		sp = xstrdup(s);
		যদি ((ep = strchr(sp, ':')) == ফাঁকা) {
			মুক্ত(sp);
			ফেরত (a2tun(s, ফাঁকা));
		}
		ep[0] = '\0'; ep++;
		*remote = a2tun(ep, ফাঁকা);
		tun = a2tun(sp, ফাঁকা);
		মুক্ত(sp);
		ফেরত (*remote == SSH_TUNID_ERR ? *remote : tun);
	}

	যদি (strcasecmp(s, "any") == 0)
		ফেরত (SSH_TUNID_ANY);

	tun = strtonum(s, 0, SSH_TUNID_MAX, &errstr);
	যদি (errstr != ফাঁকা)
		ফেরত (SSH_TUNID_ERR);

	ফেরত (tun);
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
convtime_double(ধ্রুবক অক্ষর *s)
{
	দ্বিগুণ val, যোগ_sec = 0.0, multiplier;
	ধ্রুবক অক্ষর *p, *start_p;
	অক্ষর *endp;
	পূর্ণসংখ্যা seen_seconds = 0;

	যদি (s == ফাঁকা || *s == '\0')
		ফেরত -1.0;

	জন্য (p = s; *p != '\0';) {
		যদি (!isdigit((unsigned অক্ষর)*p) && *p != '.')
			ফেরত -1.0;

		errno = 0;
		যদি ((val = strtod(p, &endp)) < 0 || errno != 0 || p == endp)
			ফেরত -1.0;
		/* Allow only decimal forms */
		যদি (p + strspn(p, "0123456789.") != endp)
			ফেরত -1.0;
		start_p = p;
		p = endp;

		নির্বাচন (*p) {
		ক্ষেত্র '\0':
			/* FALLTHROUGH */
		ক্ষেত্র 's':
		ক্ষেত্র 'S':
			যদি (seen_seconds++)
				ফেরত -1.0;
			multiplier = SECONDS;
			বিরতি;
		ক্ষেত্র 'm':
		ক্ষেত্র 'M':
			multiplier = MINUTES;
			বিরতি;
		ক্ষেত্র 'h':
		ক্ষেত্র 'H':
			multiplier = HOURS;
			বিরতি;
		ক্ষেত্র 'd':
		ক্ষেত্র 'D':
			multiplier = DAYS;
			বিরতি;
		ক্ষেত্র 'w':
		ক্ষেত্র 'W':
			multiplier = WEEKS;
			বিরতি;
		পূর্বনির্ধারিত:
			ফেরত -1.0;
		}

		/* Special handling if this was a decimal */
		যদি (memchr(start_p, '.', endp - start_p) != ফাঁকা) {
			/* Decimal point present */
			যদি (multiplier > 1.0)
				ফেরত -1.0; /* No fractionals for non-seconds */
			/* For seconds, ensure digits follow */
			যদি (!isdigit((unsigned অক্ষর)*(endp - 1)))
				ফেরত -1.0;
		}

		যোগ_sec += val * multiplier;

		যদি (*p != '\0')
			p++;
	}
	ফেরত যোগ_sec;
}

/*
 * Same as convtime_double() above but fractional seconds are ignored.
 * Return -1 if time string is invalid.
 */
পূর্ণসংখ্যা
convtime(ধ্রুবক অক্ষর *s)
{
	দ্বিগুণ sec_val;

	যদি ((sec_val = convtime_double(s)) < 0.0)
		ফেরত -1;

	/* Check for overflow into int */
	যদি (sec_val < 0 || sec_val > INT_MAX)
		ফেরত -1;

	ফেরত (পূর্ণসংখ্যা)sec_val;
}

#define TF_BUFS	8
#define TF_LEN	9

ধ্রুবক অক্ষর *
fmt_timeframe(time_t t)
{
	অক্ষর		*buf;
	স্থির অক্ষর	 tfbuf[TF_BUFS][TF_LEN];	/* ring buffer */
	স্থির পূর্ণসংখ্যা	 idx = 0;
	unsigned পূর্ণসংখ্যা	 sec, min, hrs, day;
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

	ফেরত (buf);
}

/*
 * Returns a standardized host+port identifier string.
 * Caller must free returned string.
 */
অক্ষর *
put_host_port(ধ্রুবক অক্ষর *host, u_short port)
{
	অক্ষর *hoststr;

	যদি (port == 0 || port == SSH_DEFAULT_PORT)
		ফেরত(xstrdup(host));
	যদি (asprintf(&hoststr, "[%s]:%d", host, (পূর্ণসংখ্যা)port) == -1)
		fatal("put_host_port: asprintf: %s", strerror(errno));
	debug3("put_host_port: %s", hoststr);
	ফেরত hoststr;
}

/*
 * Search for next delimiter between hostnames/addresses and ports.
 * Argument may be modified (for termination).
 * Returns *cp if parsing succeeds.
 * *cp is set to the start of the next field, if one was found.
 * The delimiter char, if present, is stored in delim.
 * If this is the last field, *cp is set to NULL.
 */
অক্ষর *
hpdelim2(অক্ষর **cp, অক্ষর *delim)
{
	অক্ষর *s, *old;

	যদি (cp == ফাঁকা || *cp == ফাঁকা)
		ফেরত ফাঁকা;

	old = s = *cp;
	যদি (*s == '[') {
		যদি ((s = strchr(s, ']')) == ফাঁকা)
			ফেরত ফাঁকা;
		অন্যথা
			s++;
	} অন্যথা যদি ((s = strpbrk(s, ":/")) == ফাঁকা)
		s = *cp + strlen(*cp); /* skip to end (see first case below) */

	নির্বাচন (*s) {
	ক্ষেত্র '\0':
		*cp = ফাঁকা;	/* no more fields*/
		বিরতি;

	ক্ষেত্র ':':
	ক্ষেত্র '/':
		যদি (delim != ফাঁকা)
			*delim = *s;
		*s = '\0';	/* terminate */
		*cp = s + 1;
		বিরতি;

	পূর্বনির্ধারিত:
		ফেরত ফাঁকা;
	}

	ফেরত old;
}

/* The common case: only accept colon as delimiter. */
অক্ষর *
hpdelim(অক্ষর **cp)
{
	অক্ষর *r, delim = '\0';

	r =  hpdelim2(cp, &delim);
	যদি (delim == '/')
		ফেরত ফাঁকা;
	ফেরত r;
}

অক্ষর *
cleanhostname(অক্ষর *host)
{
	যদি (*host == '[' && host[strlen(host) - 1] == ']') {
		host[strlen(host) - 1] = '\0';
		ফেরত (host + 1);
	} অন্যথা
		ফেরত host;
}

অক্ষর *
colon(অক্ষর *cp)
{
	পূর্ণসংখ্যা flag = 0;

	যদি (*cp == ':')		/* Leading colon is part of file name. */
		ফেরত ফাঁকা;
	যদি (*cp == '[')
		flag = 1;

	জন্য (; *cp; ++cp) {
		যদি (*cp == '@' && *(cp+1) == '[')
			flag = 1;
		যদি (*cp == ']' && *(cp+1) == ':' && flag)
			ফেরত (cp+1);
		যদি (*cp == ':' && !flag)
			ফেরত (cp);
		যদি (*cp == '/')
			ফেরত ফাঁকা;
	}
	ফেরত ফাঁকা;
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
পূর্ণসংখ্যা
parse_user_host_path(ধ্রুবক অক্ষর *s, অক্ষর **userp, অক্ষর **hostp, অক্ষর **pathp)
{
	অক্ষর *user = ফাঁকা, *host = ফাঁকা, *path = ফাঁকা;
	অক্ষর *sdup, *tmp;
	পূর্ণসংখ্যা ret = -1;

	যদি (userp != ফাঁকা)
		*userp = ফাঁকা;
	যদি (hostp != ফাঁকা)
		*hostp = ফাঁকা;
	যদি (pathp != ফাঁকা)
		*pathp = ফাঁকা;

	sdup = xstrdup(s);

	/* Check for remote syntax: [user@]host:[path] */
	যদি ((tmp = colon(sdup)) == ফাঁকা)
		যাও out;

	/* Extract optional path */
	*tmp++ = '\0';
	যদি (*tmp == '\0')
		tmp = ".";
	path = xstrdup(tmp);

	/* Extract optional user and mandatory host */
	tmp = strrchr(sdup, '@');
	যদি (tmp != ফাঁকা) {
		*tmp++ = '\0';
		host = xstrdup(cleanhostname(tmp));
		যদি (*sdup != '\0')
			user = xstrdup(sdup);
	} অন্যথা {
		host = xstrdup(cleanhostname(sdup));
		user = ফাঁকা;
	}

	/* Success */
	যদি (userp != ফাঁকা) {
		*userp = user;
		user = ফাঁকা;
	}
	যদি (hostp != ফাঁকা) {
		*hostp = host;
		host = ফাঁকা;
	}
	যদি (pathp != ফাঁকা) {
		*pathp = path;
		path = ফাঁকা;
	}
	ret = 0;
out:
	মুক্ত(sdup);
	মুক্ত(user);
	মুক্ত(host);
	মুক্ত(path);
	ফেরত ret;
}

/*
 * Parse a [user@]host[:port] string.
 * Caller must free returned user and host.
 * Any of the pointer return arguments may be NULL (useful for syntax checking).
 * If user was not specified then *userp will be set to NULL.
 * If port was not specified then *portp will be -1.
 * Returns 0 on success, -1 on failure.
 */
পূর্ণসংখ্যা
parse_user_host_port(ধ্রুবক অক্ষর *s, অক্ষর **userp, অক্ষর **hostp, পূর্ণসংখ্যা *portp)
{
	অক্ষর *sdup, *cp, *tmp;
	অক্ষর *user = ফাঁকা, *host = ফাঁকা;
	পূর্ণসংখ্যা port = -1, ret = -1;

	যদি (userp != ফাঁকা)
		*userp = ফাঁকা;
	যদি (hostp != ফাঁকা)
		*hostp = ফাঁকা;
	যদি (portp != ফাঁকা)
		*portp = -1;

	যদি ((sdup = tmp = strdup(s)) == ফাঁকা)
		ফেরত -1;
	/* Extract optional username */
	যদি ((cp = strrchr(tmp, '@')) != ফাঁকা) {
		*cp = '\0';
		যদি (*tmp == '\0')
			যাও out;
		যদি ((user = strdup(tmp)) == ফাঁকা)
			যাও out;
		tmp = cp + 1;
	}
	/* Extract mandatory hostname */
	যদি ((cp = hpdelim(&tmp)) == ফাঁকা || *cp == '\0')
		যাও out;
	host = xstrdup(cleanhostname(cp));
	/* Convert and verify optional port */
	যদি (tmp != ফাঁকা && *tmp != '\0') {
		যদি ((port = a2port(tmp)) <= 0)
			যাও out;
	}
	/* Success */
	যদি (userp != ফাঁকা) {
		*userp = user;
		user = ফাঁকা;
	}
	যদি (hostp != ফাঁকা) {
		*hostp = host;
		host = ফাঁকা;
	}
	যদি (portp != ফাঁকা)
		*portp = port;
	ret = 0;
 out:
	মুক্ত(sdup);
	মুক্ত(user);
	মুক্ত(host);
	ফেরত ret;
}

/*
 * Converts a two-byte hex string to decimal.
 * Returns the decimal value or -1 for invalid input.
 */
স্থির পূর্ণসংখ্যা
hexchar(ধ্রুবক অক্ষর *s)
{
	unsigned অক্ষর ফলাফল[2];
	পূর্ণসংখ্যা i;

	জন্য (i = 0; i < 2; i++) {
		যদি (s[i] >= '0' && s[i] <= '9')
			ফলাফল[i] = (unsigned অক্ষর)(s[i] - '0');
		অন্যথা যদি (s[i] >= 'a' && s[i] <= 'f')
			ফলাফল[i] = (unsigned অক্ষর)(s[i] - 'a') + 10;
		অন্যথা যদি (s[i] >= 'A' && s[i] <= 'F')
			ফলাফল[i] = (unsigned অক্ষর)(s[i] - 'A') + 10;
		অন্যথা
			ফেরত -1;
	}
	ফেরত (ফলাফল[0] << 4) | ফলাফল[1];
}

/*
 * Decode an url-encoded string.
 * Returns a newly allocated string on success or NULL on failure.
 */
স্থির অক্ষর *
urldecode(ধ্রুবক অক্ষর *src)
{
	অক্ষর *ret, *dst;
	পূর্ণসংখ্যা ch;
	আকার_t srclen;

	যদি ((srclen = strlen(src)) >= SIZE_MAX)
		ফেরত ফাঁকা;
	ret = xmalloc(srclen + 1);
	জন্য (dst = ret; *src != '\0'; src++) {
		নির্বাচন (*src) {
		ক্ষেত্র '+':
			*dst++ = ' ';
			বিরতি;
		ক্ষেত্র '%':
			/* note: don't allow \0 characters */
			যদি (!isxdigit((unsigned অক্ষর)src[1]) ||
			    !isxdigit((unsigned অক্ষর)src[2]) ||
			    (ch = hexchar(src + 1)) == -1 || ch == 0) {
				মুক্ত(ret);
				ফেরত ফাঁকা;
			}
			*dst++ = ch;
			src += 2;
			বিরতি;
		পূর্বনির্ধারিত:
			*dst++ = *src;
			বিরতি;
		}
	}
	*dst = '\0';

	ফেরত ret;
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
পূর্ণসংখ্যা
parse_uri(ধ্রুবক অক্ষর *scheme, ধ্রুবক অক্ষর *uri, অক্ষর **userp, অক্ষর **hostp,
    পূর্ণসংখ্যা *portp, অক্ষর **pathp)
{
	অক্ষর *uridup, *cp, *tmp, ch;
	অক্ষর *user = ফাঁকা, *host = ফাঁকা, *path = ফাঁকা;
	পূর্ণসংখ্যা port = -1, ret = -1;
	আকার_t len;

	len = strlen(scheme);
	যদি (strncmp(uri, scheme, len) != 0 || strncmp(uri + len, "://", 3) != 0)
		ফেরত 1;
	uri += len + 3;

	যদি (userp != ফাঁকা)
		*userp = ফাঁকা;
	যদি (hostp != ফাঁকা)
		*hostp = ফাঁকা;
	যদি (portp != ফাঁকা)
		*portp = -1;
	যদি (pathp != ফাঁকা)
		*pathp = ফাঁকা;

	uridup = tmp = xstrdup(uri);

	/* Extract optional ssh-info (username + connection params) */
	যদি ((cp = strchr(tmp, '@')) != ফাঁকা) {
		অক্ষর *delim;

		*cp = '\0';
		/* Extract username and connection params */
		যদি ((delim = strchr(tmp, ';')) != ফাঁকা) {
			/* Just ignore connection params for now */
			*delim = '\0';
		}
		যদি (*tmp == '\0') {
			/* Empty username */
			যাও out;
		}
		যদি ((user = urldecode(tmp)) == ফাঁকা)
			যাও out;
		tmp = cp + 1;
	}

	/* Extract mandatory hostname */
	যদি ((cp = hpdelim2(&tmp, &ch)) == ফাঁকা || *cp == '\0')
		যাও out;
	host = xstrdup(cleanhostname(cp));
	যদি (!valid_domain(host, 0, ফাঁকা))
		যাও out;

	যদি (tmp != ফাঁকা && *tmp != '\0') {
		যদি (ch == ':') {
			/* Convert and verify port. */
			যদি ((cp = strchr(tmp, '/')) != ফাঁকা)
				*cp = '\0';
			যদি ((port = a2port(tmp)) <= 0)
				যাও out;
			tmp = cp ? cp + 1 : ফাঁকা;
		}
		যদি (tmp != ফাঁকা && *tmp != '\0') {
			/* Extract optional path */
			যদি ((path = urldecode(tmp)) == ফাঁকা)
				যাও out;
		}
	}

	/* Success */
	যদি (userp != ফাঁকা) {
		*userp = user;
		user = ফাঁকা;
	}
	যদি (hostp != ফাঁকা) {
		*hostp = host;
		host = ফাঁকা;
	}
	যদি (portp != ফাঁকা)
		*portp = port;
	যদি (pathp != ফাঁকা) {
		*pathp = path;
		path = ফাঁকা;
	}
	ret = 0;
 out:
	মুক্ত(uridup);
	মুক্ত(user);
	মুক্ত(host);
	মুক্ত(path);
	ফেরত ret;
}

/* function to assist building execv() arguments */
শূন্য
addargs(arglist *args, অক্ষর *fmt, ...)
{
	va_list ap;
	অক্ষর *cp;
	u_int nalloc;
	পূর্ণসংখ্যা r;

	va_start(ap, fmt);
	r = vasprintf(&cp, fmt, ap);
	va_end(ap);
	যদি (r == -1)
		fatal_f("argument too long");

	nalloc = args->nalloc;
	যদি (args->list == ফাঁকা) {
		nalloc = 32;
		args->অঙ্ক = 0;
	} অন্যথা যদি (args->অঙ্ক > (256 * 1024))
		fatal_f("too many arguments");
	অন্যথা যদি (args->অঙ্ক >= args->nalloc)
		fatal_f("arglist corrupt");
	অন্যথা যদি (args->অঙ্ক+2 >= nalloc)
		nalloc *= 2;

	args->list = xrecallocarray(args->list, args->nalloc,
	    nalloc, আকার(অক্ষর *));
	args->nalloc = nalloc;
	args->list[args->অঙ্ক++] = cp;
	args->list[args->অঙ্ক] = ফাঁকা;
}

শূন্য
replacearg(arglist *args, u_int which, অক্ষর *fmt, ...)
{
	va_list ap;
	অক্ষর *cp;
	পূর্ণসংখ্যা r;

	va_start(ap, fmt);
	r = vasprintf(&cp, fmt, ap);
	va_end(ap);
	যদি (r == -1)
		fatal_f("argument too long");
	যদি (args->list == ফাঁকা || args->অঙ্ক >= args->nalloc)
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

	যদি (args == ফাঁকা)
		ফেরত;
	যদি (args->list != ফাঁকা && args->অঙ্ক < args->nalloc) {
		জন্য (i = 0; i < args->অঙ্ক; i++)
			মুক্ত(args->list[i]);
		মুক্ত(args->list);
	}
	args->nalloc = args->অঙ্ক = 0;
	args->list = ফাঁকা;
}

/*
 * Expands tildes in the file name.  Returns data allocated by xmalloc.
 * Warning: this calls getpw*.
 */
পূর্ণসংখ্যা
tilde_expand(ধ্রুবক অক্ষর *filename, uid_t uid, অক্ষর **retp)
{
	অক্ষর *ocopy = ফাঁকা, *copy, *s = ফাঁকা;
	ধ্রুবক অক্ষর *path = ফাঁকা, *user = ফাঁকা;
	কাঠামো passwd *pw;
	আকার_t len;
	পূর্ণসংখ্যা ret = -1, r, slash;

	*retp = ফাঁকা;
	যদি (*filename != '~') {
		*retp = xstrdup(filename);
		ফেরত 0;
	}
	ocopy = copy = xstrdup(filename + 1);

	যদি (*copy == '\0')				/* ~ */
		path = ফাঁকা;
	অন্যথা যদি (*copy == '/') {
		copy += strspn(copy, "/");
		যদি (*copy == '\0')
			path = ফাঁকা;			/* ~/ */
		অন্যথা
			path = copy;			/* ~/path */
	} অন্যথা {
		user = copy;
		যদি ((path = strchr(copy, '/')) != ফাঁকা) {
			copy[path - copy] = '\0';
			path++;
			path += strspn(path, "/");
			যদি (*path == '\0')		/* ~user/ */
				path = ফাঁকা;
			/* else				 ~user/path */
		}
		/* else					~user */
	}
	যদি (user != ফাঁকা) {
		যদি ((pw = getpwnam(user)) == ফাঁকা) {
			error_f("No such user %s", user);
			যাও out;
		}
	} অন্যথা যদি ((pw = getpwuid(uid)) == ফাঁকা) {
		error_f("No such uid %ld", (long)uid);
		যাও out;
	}

	/* Make sure directory has a trailing '/' */
	slash = (len = strlen(pw->pw_dir)) == 0 || pw->pw_dir[len - 1] != '/';

	যদি ((r = xasprintf(&s, "%s%s%s", pw->pw_dir,
	    slash ? "/" : "", path != ফাঁকা ? path : "")) <= 0) {
		error_f("xasprintf failed");
		যাও out;
	}
	যদি (r >= PATH_MAX) {
		error_f("Path too long");
		যাও out;
	}
	/* success */
	ret = 0;
	*retp = s;
	s = ফাঁকা;
 out:
	মুক্ত(s);
	মুক্ত(ocopy);
	ফেরত ret;
}

অক্ষর *
tilde_expand_filename(ধ্রুবক অক্ষর *filename, uid_t uid)
{
	অক্ষর *ret;

	যদি (tilde_expand(filename, uid, &ret) != 0)
		cleanup_exit(255);
	ফেরত ret;
}

/*
 * Expand a string with a set of %[char] escapes and/or ${ENVIRONMENT}
 * substitutions.  A number of escapes may be specified as
 * (char *escape_chars, char *replacement) pairs. The list must be terminated
 * by a NULL escape_char. Returns replaced string in memory allocated by
 * xmalloc which the caller must free.
 */
স্থির অক্ষর *
vdollar_percent_expand(পূর্ণসংখ্যা *parseerror, পূর্ণসংখ্যা dollar, পূর্ণসংখ্যা percent,
    ধ্রুবক অক্ষর *string, va_list ap)
{
#define EXPAND_MAX_চাবিগুলি	64
	u_int অঙ্ক_চাবিগুলি = 0, i;
	কাঠামো {
		ধ্রুবক অক্ষর *চাবি;
		ধ্রুবক অক্ষর *repl;
	} চাবিগুলি[EXPAND_MAX_চাবিগুলি];
	কাঠামো sshbuf *buf;
	পূর্ণসংখ্যা r, missingvar = 0;
	অক্ষর *ret = ফাঁকা, *var, *varend, *val;
	আকার_t len;

	যদি ((buf = sshbuf_new()) == ফাঁকা)
		fatal_f("sshbuf_new failed");
	যদি (parseerror == ফাঁকা)
		fatal_f("null parseerror arg");
	*parseerror = 1;

	/* Gather keys if we're doing percent expansion. */
	যদি (percent) {
		জন্য (অঙ্ক_চাবিগুলি = 0; অঙ্ক_চাবিগুলি < EXPAND_MAX_চাবিগুলি; অঙ্ক_চাবিগুলি++) {
			চাবিগুলি[অঙ্ক_চাবিগুলি].চাবি = va_arg(ap, অক্ষর *);
			যদি (চাবিগুলি[অঙ্ক_চাবিগুলি].চাবি == ফাঁকা)
				বিরতি;
			চাবিগুলি[অঙ্ক_চাবিগুলি].repl = va_arg(ap, অক্ষর *);
			যদি (চাবিগুলি[অঙ্ক_চাবিগুলি].repl == ফাঁকা) {
				fatal_f("NULL replacement for token %s",
				    চাবিগুলি[অঙ্ক_চাবিগুলি].চাবি);
			}
		}
		যদি (অঙ্ক_চাবিগুলি == EXPAND_MAX_চাবিগুলি && va_arg(ap, অক্ষর *) != ফাঁকা)
			fatal_f("too many keys");
		যদি (অঙ্ক_চাবিগুলি == 0)
			fatal_f("percent expansion without token list");
	}

	/* Expand string */
	জন্য (i = 0; *string != '\0'; string++) {
		/* Optionally process ${ENVIRONMENT} expansions. */
		যদি (dollar && string[0] == '$' && string[1] == '{') {
			string += 2;  /* skip over '${' */
			যদি ((varend = strchr(string, '}')) == ফাঁকা) {
				error_f("environment variable '%s' missing "
				    "closing '}'", string);
				যাও out;
			}
			len = varend - string;
			যদি (len == 0) {
				error_f("zero-length environment variable");
				যাও out;
			}
			var = xmalloc(len + 1);
			(শূন্য)strlcpy(var, string, len + 1);
			যদি ((val = getenv(var)) == ফাঁকা) {
				error_f("env var ${%s} has no value", var);
				missingvar = 1;
			} অন্যথা {
				debug3_f("expand ${%s} -> '%s'", var, val);
				যদি ((r = sshbuf_put(buf, val, strlen(val))) !=0)
					fatal_fr(r, "sshbuf_put ${}");
			}
			মুক্ত(var);
			string += len;
			চালু;
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
			চালু;
		}
		string++;
		/* %% case */
		যদি (*string == '%')
			যাও append;
		যদি (*string == '\0') {
			error_f("invalid format");
			যাও out;
		}
		জন্য (i = 0; i < অঙ্ক_চাবিগুলি; i++) {
			যদি (strchr(চাবিগুলি[i].চাবি, *string) != ফাঁকা) {
				যদি ((r = sshbuf_put(buf, চাবিগুলি[i].repl,
				    strlen(চাবিগুলি[i].repl))) != 0)
					fatal_fr(r, "sshbuf_put %%-repl");
				বিরতি;
			}
		}
		যদি (i >= অঙ্ক_চাবিগুলি) {
			error_f("unknown key %%%c", *string);
			যাও out;
		}
	}
	যদি (!missingvar && (ret = sshbuf_dup_string(buf)) == ফাঁকা)
		fatal_f("sshbuf_dup_string failed");
	*parseerror = 0;
 out:
	sshbuf_free(buf);
	ফেরত *parseerror ? ফাঁকা : ret;
#undef EXPAND_MAX_চাবিগুলি
}

/*
 * Expand only environment variables.
 * Note that although this function is variadic like the other similar
 * functions, any such arguments will be unused.
 */

অক্ষর *
dollar_expand(পূর্ণসংখ্যা *parseerr, ধ্রুবক অক্ষর *string, ...)
{
	অক্ষর *ret;
	পূর্ণসংখ্যা err;
	va_list ap;

	va_start(ap, string);
	ret = vdollar_percent_expand(&err, 1, 0, string, ap);
	va_end(ap);
	যদি (parseerr != ফাঁকা)
		*parseerr = err;
	ফেরত ret;
}

/*
 * Returns expanded string or NULL if a specified environment variable is
 * not defined, or calls fatal if the string is invalid.
 */
অক্ষর *
percent_expand(ধ্রুবক অক্ষর *string, ...)
{
	অক্ষর *ret;
	পূর্ণসংখ্যা err;
	va_list ap;

	va_start(ap, string);
	ret = vdollar_percent_expand(&err, 0, 1, string, ap);
	va_end(ap);
	যদি (err)
		fatal_f("failed");
	ফেরত ret;
}

/*
 * Returns expanded string or NULL if a specified environment variable is
 * not defined, or calls fatal if the string is invalid.
 */
অক্ষর *
percent_dollar_expand(ধ্রুবক অক্ষর *string, ...)
{
	অক্ষর *ret;
	পূর্ণসংখ্যা err;
	va_list ap;

	va_start(ap, string);
	ret = vdollar_percent_expand(&err, 1, 1, string, ap);
	va_end(ap);
	যদি (err)
		fatal_f("failed");
	ফেরত ret;
}

পূর্ণসংখ্যা
tun_open(পূর্ণসংখ্যা tun, পূর্ণসংখ্যা mode, অক্ষর **ifname)
{
#যদি defined(CUSTOM_SYS_TUN_OPEN)
	ফেরত (sys_tun_open(tun, mode, ifname));
#নতুবা_যদি defined(SSH_TUN_OPENBSD)
	কাঠামো ifreq ifr;
	অক্ষর name[100];
	পূর্ণসংখ্যা fd = -1, sock;
	ধ্রুবক অক্ষর *tunbase = "tun";

	যদি (ifname != ফাঁকা)
		*ifname = ফাঁকা;

	যদি (mode == SSH_TUNMODE_ETHERNET)
		tunbase = "tap";

	/* Open the tunnel device */
	যদি (tun <= SSH_TUNID_MAX) {
		snprintf(name, আকার(name), "/dev/%s%d", tunbase, tun);
		fd = open(name, O_RDWR);
	} অন্যথা যদি (tun == SSH_TUNID_ANY) {
		জন্য (tun = 100; tun >= 0; tun--) {
			snprintf(name, আকার(name), "/dev/%s%d",
			    tunbase, tun);
			যদি ((fd = open(name, O_RDWR)) >= 0)
				বিরতি;
		}
	} অন্যথা {
		debug_f("invalid tunnel %u", tun);
		ফেরত -1;
	}

	যদি (fd == -1) {
		debug_f("%s open: %s", name, strerror(errno));
		ফেরত -1;
	}

	debug_f("%s mode %d fd %d", name, mode, fd);

	/* Bring interface up if it is not already */
	snprintf(ifr.ifr_name, আকার(ifr.ifr_name), "%s%d", tunbase, tun);
	যদি ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
		যাও failed;

	যদি (ioctl(sock, SIOCGIFFLAGS, &ifr) == -1) {
		debug_f("get interface %s flags: %s", ifr.ifr_name,
		    strerror(errno));
		যাও failed;
	}

	যদি (!(ifr.ifr_flags & IFF_UP)) {
		ifr.ifr_flags |= IFF_UP;
		যদি (ioctl(sock, SIOCSIFFLAGS, &ifr) == -1) {
			debug_f("activate interface %s: %s", ifr.ifr_name,
			    strerror(errno));
			যাও failed;
		}
	}

	যদি (ifname != ফাঁকা)
		*ifname = xstrdup(ifr.ifr_name);

	close(sock);
	ফেরত fd;

 failed:
	যদি (fd >= 0)
		close(fd);
	যদি (sock >= 0)
		close(sock);
	ফেরত -1;
#অন্যথা
	error("Tunnel interfaces are not supported on this platform");
	ফেরত (-1);
#endif
}

শূন্য
sanitise_stdfd(শূন্য)
{
	পূর্ণসংখ্যা nullfd, dupfd;

	যদি ((nullfd = dupfd = open(_PATH_DEVNULL, O_RDWR)) == -1) {
		fprintf(stderr, "Couldn't open /dev/null: %s\n",
		    strerror(errno));
		exit(1);
	}
	যখন (++dupfd <= STDERR_FILENO) {
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

অক্ষর *
tohex(ধ্রুবক শূন্য *vp, আকার_t l)
{
	ধ্রুবক u_char *p = (ধ্রুবক u_char *)vp;
	অক্ষর b[3], *r;
	আকার_t i, hl;

	যদি (l > 65536)
		ফেরত xstrdup("tohex: length > 65536");

	hl = l * 2 + 1;
	r = xcalloc(1, hl);
	জন্য (i = 0; i < l; i++) {
		snprintf(b, আকার(b), "%02x", p[i]);
		strlcat(r, b, hl);
	}
	ফেরত (r);
}

/*
 * Extend string *sp by the specified format. If *sp is not NULL (or empty),
 * then the separator 'sep' will be prepended before the formatted arguments.
 * Extended strings are heap allocated.
 */
শূন্য
xextendf(অক্ষর **sp, ধ্রুবক অক্ষর *sep, ধ্রুবক অক্ষর *fmt, ...)
{
	va_list ap;
	অক্ষর *tmp1, *tmp2;

	va_start(ap, fmt);
	xvasprintf(&tmp1, fmt, ap);
	va_end(ap);

	যদি (*sp == ফাঁকা || **sp == '\0') {
		মুক্ত(*sp);
		*sp = tmp1;
		ফেরত;
	}
	xasprintf(&tmp2, "%s%s%s", *sp, sep == ফাঁকা ? "" : sep, tmp1);
	মুক্ত(tmp1);
	মুক্ত(*sp);
	*sp = tmp2;
}


uint64_t
get_u64(ধ্রুবক শূন্য *vp)
{
	ধ্রুবক u_char *p = (ধ্রুবক u_char *)vp;
	uint64_t v;

	v  = (uint64_t)p[0] << 56;
	v |= (uint64_t)p[1] << 48;
	v |= (uint64_t)p[2] << 40;
	v |= (uint64_t)p[3] << 32;
	v |= (uint64_t)p[4] << 24;
	v |= (uint64_t)p[5] << 16;
	v |= (uint64_t)p[6] << 8;
	v |= (uint64_t)p[7];

	ফেরত (v);
}

uint32_t
get_u32(ধ্রুবক শূন্য *vp)
{
	ধ্রুবক u_char *p = (ধ্রুবক u_char *)vp;
	uint32_t v;

	v  = (uint32_t)p[0] << 24;
	v |= (uint32_t)p[1] << 16;
	v |= (uint32_t)p[2] << 8;
	v |= (uint32_t)p[3];

	ফেরত (v);
}

uint32_t
get_u32_le(ধ্রুবক শূন্য *vp)
{
	ধ্রুবক u_char *p = (ধ্রুবক u_char *)vp;
	uint32_t v;

	v  = (uint32_t)p[0];
	v |= (uint32_t)p[1] << 8;
	v |= (uint32_t)p[2] << 16;
	v |= (uint32_t)p[3] << 24;

	ফেরত (v);
}

uint16_t
get_u16(ধ্রুবক শূন্য *vp)
{
	ধ্রুবক u_char *p = (ধ্রুবক u_char *)vp;
	uint16_t v;

	v  = (uint16_t)p[0] << 8;
	v |= (uint16_t)p[1];

	ফেরত (v);
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
ms_subtract_diff(কাঠামো timeval *start, পূর্ণসংখ্যা *ms)
{
	কাঠামো timeval diff, finish;

	monotime_tv(&finish);
	timersub(&finish, start, &diff);
	*ms -= (diff.tv_sec * 1000) + (diff.tv_usec / 1000);
}

শূন্য
ms_to_timespec(কাঠামো timespec *ts, পূর্ণসংখ্যা ms)
{
	যদি (ms < 0)
		ms = 0;
	ts->tv_sec = ms / 1000;
	ts->tv_nsec = (ms % 1000) * 1000 * 1000;
}

শূন্য
monotime_ts(কাঠামো timespec *ts)
{
	কাঠামো timeval tv;
#যদি defined(HAVE_CLOCK_GETTIME) && (defined(CLOCK_BOOTTIME) || \
    defined(CLOCK_MONOTONIC) || defined(CLOCK_REALTIME))
	স্থির পূর্ণসংখ্যা gettime_failed = 0;

	যদি (!gettime_failed) {
# ifdef CLOCK_BOOTTIME
		যদি (clock_gettime(CLOCK_BOOTTIME, ts) == 0)
			ফেরত;
# endif /* CLOCK_BOOTTIME */
# ifdef CLOCK_MONOTONIC
		যদি (clock_gettime(CLOCK_MONOTONIC, ts) == 0)
			ফেরত;
# endif /* CLOCK_MONOTONIC */
# ifdef CLOCK_REALTIME
		/* Not monotonic, but we're almost out of options here. */
		যদি (clock_gettime(CLOCK_REALTIME, ts) == 0)
			ফেরত;
# endif /* CLOCK_REALTIME */
		debug3("clock_gettime: %s", strerror(errno));
		gettime_failed = 1;
	}
#endif /* HAVE_CLOCK_GETTIME && (BOOTTIME || MONOTONIC || REALTIME) */
	gettimeofday(&tv, ফাঁকা);
	ts->tv_sec = tv.tv_sec;
	ts->tv_nsec = (long)tv.tv_usec * 1000;
}

শূন্য
monotime_tv(কাঠামো timeval *tv)
{
	কাঠামো timespec ts;

	monotime_ts(&ts);
	tv->tv_sec = ts.tv_sec;
	tv->tv_usec = ts.tv_nsec / 1000;
}

time_t
monotime(শূন্য)
{
	কাঠামো timespec ts;

	monotime_ts(&ts);
	ফেরত (ts.tv_sec);
}

দ্বিগুণ
monotime_double(শূন্য)
{
	কাঠামো timespec ts;

	monotime_ts(&ts);
	ফেরত (দ্বিগুণ)ts.tv_sec + (দ্বিগুণ)ts.tv_nsec / 1000000000.0;
}

শূন্য
bandwidth_limit_init(কাঠামো bwlimit *bw, uint64_t kbps, আকার_t buflen)
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
bandwidth_limit(কাঠামো bwlimit *bw, আকার_t read_len)
{
	uint64_t waitlen;
	কাঠামো timespec ts, rm;

	bw->lamt += read_len;
	যদি (!timerisset(&bw->bwstart)) {
		monotime_tv(&bw->bwstart);
		ফেরত;
	}
	যদি (bw->lamt < bw->thresh)
		ফেরত;

	monotime_tv(&bw->bwend);
	timersub(&bw->bwend, &bw->bwstart, &bw->bwend);
	যদি (!timerisset(&bw->bwend))
		ফেরত;

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
		যখন (nanosleep(&ts, &rm) == -1) {
			যদি (errno != EINTR)
				বিরতি;
			ts = rm;
		}
	}

	bw->lamt = 0;
	monotime_tv(&bw->bwstart);
}

/* Make a template filename for mk[sd]temp() */
শূন্য
mktemp_proto(অক্ষর *s, আকার_t len)
{
	ধ্রুবক অক্ষর *tmpdir;
	পূর্ণসংখ্যা r;

	যদি ((tmpdir = getenv("TMPDIR")) != ফাঁকা) {
		r = snprintf(s, len, "%s/ssh-XXXXXXXXXXXX", tmpdir);
		যদি (r > 0 && (আকার_t)r < len)
			ফেরত;
	}
	r = snprintf(s, len, "/tmp/ssh-XXXXXXXXXXXX");
	যদি (r < 0 || (আকার_t)r >= len)
		fatal_f("template string too short");
}

স্থির ধ্রুবক কাঠামো {
	ধ্রুবক অক্ষর *name;
	পূর্ণসংখ্যা মান;
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
	{ ফাঁকা, -1 }
};

পূর্ণসংখ্যা
parse_ipqos(ধ্রুবক অক্ষর *cp)
{
	ধ্রুবক অক্ষর *errstr;
	u_int i;
	পূর্ণসংখ্যা val;

	যদি (cp == ফাঁকা)
		ফেরত -1;
	জন্য (i = 0; ipqos[i].name != ফাঁকা; i++) {
		যদি (strcasecmp(cp, ipqos[i].name) == 0)
			ফেরত ipqos[i].মান;
	}
	/* Try parsing as an integer */
	val = (পূর্ণসংখ্যা)strtonum(cp, 0, 255, &errstr);
	যদি (errstr)
		ফেরত -1;
	ফেরত val;
}

ধ্রুবক অক্ষর *
iptos2str(পূর্ণসংখ্যা iptos)
{
	পূর্ণসংখ্যা i;
	স্থির অক্ষর iptos_str[আকার "0xff"];

	জন্য (i = 0; ipqos[i].name != ফাঁকা; i++) {
		যদি (ipqos[i].মান == iptos)
			ফেরত ipqos[i].name;
	}
	snprintf(iptos_str, আকার iptos_str, "0x%02x", iptos);
	ফেরত iptos_str;
}

শূন্য
lowercase(অক্ষর *s)
{
	জন্য (; *s; s++)
		*s = tolower((u_char)*s);
}

পূর্ণসংখ্যা
unix_listener(ধ্রুবক অক্ষর *path, পূর্ণসংখ্যা backlog, পূর্ণসংখ্যা unlink_first)
{
	কাঠামো sockaddr_un sunaddr;
	পূর্ণসংখ্যা saved_errno, sock;

	memset(&sunaddr, 0, আকার(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	যদি (strlcpy(sunaddr.sun_path, path,
	    আকার(sunaddr.sun_path)) >= আকার(sunaddr.sun_path)) {
		error_f("path \"%s\" too long for Unix domain socket", path);
		errno = ENAMETOOLONG;
		ফেরত -1;
	}

	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	যদি (sock == -1) {
		saved_errno = errno;
		error_f("socket: %.100s", strerror(errno));
		errno = saved_errno;
		ফেরত -1;
	}
	যদি (unlink_first == 1) {
		যদি (unlink(path) != 0 && errno != ENOENT)
			error("unlink(%s): %.100s", path, strerror(errno));
	}
	যদি (bind(sock, (কাঠামো sockaddr *)&sunaddr, আকার(sunaddr)) == -1) {
		saved_errno = errno;
		error_f("cannot bind to path %s: %s", path, strerror(errno));
		close(sock);
		errno = saved_errno;
		ফেরত -1;
	}
	যদি (listen(sock, backlog) == -1) {
		saved_errno = errno;
		error_f("cannot listen on path %s: %s", path, strerror(errno));
		close(sock);
		unlink(path);
		errno = saved_errno;
		ফেরত -1;
	}
	ফেরত sock;
}

শূন্য
sock_set_v6only(পূর্ণসংখ্যা s)
{
#যদি defined(IPV6_V6ONLY) && !defined(__OpenBSD__)
	পূর্ণসংখ্যা on = 1;

	debug3_f("set socket %d IPV6_V6ONLY", s);
	যদি (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &on, আকার(on)) == -1)
		error("setsockopt IPV6_V6ONLY: %s", strerror(errno));
#endif
}

/*
 * Compares two strings that maybe be NULL. Returns non-zero if strings
 * are both NULL or are identical, returns zero otherwise.
 */
স্থির পূর্ণসংখ্যা
strcmp_maybe_null(ধ্রুবক অক্ষর *a, ধ্রুবক অক্ষর *b)
{
	যদি ((a == ফাঁকা && b != ফাঁকা) || (a != ফাঁকা && b == ফাঁকা))
		ফেরত 0;
	যদি (a != ফাঁকা && strcmp(a, b) != 0)
		ফেরত 0;
	ফেরত 1;
}

/*
 * Compare two forwards, returning non-zero if they are identical or
 * zero otherwise.
 */
পূর্ণসংখ্যা
forward_equals(ধ্রুবক কাঠামো Forward *a, ধ্রুবক কাঠামো Forward *b)
{
	যদি (strcmp_maybe_null(a->listen_host, b->listen_host) == 0)
		ফেরত 0;
	যদি (a->listen_port != b->listen_port)
		ফেরত 0;
	যদি (strcmp_maybe_null(a->listen_path, b->listen_path) == 0)
		ফেরত 0;
	যদি (strcmp_maybe_null(a->connect_host, b->connect_host) == 0)
		ফেরত 0;
	যদি (a->connect_port != b->connect_port)
		ফেরত 0;
	যদি (strcmp_maybe_null(a->connect_path, b->connect_path) == 0)
		ফেরত 0;
	/* allocated_port and handle are not checked */
	ফেরত 1;
}

/* returns port number, FWD_PERMIT_ANY_PORT or -1 on error */
পূর্ণসংখ্যা
permitopen_port(ধ্রুবক অক্ষর *p)
{
	পূর্ণসংখ্যা port;

	যদি (strcmp(p, "*") == 0)
		ফেরত FWD_PERMIT_ANY_PORT;
	যদি ((port = a2port(p)) > 0)
		ফেরত port;
	ফেরত -1;
}

/* returns 1 if process is already daemonized, 0 otherwise */
পূর্ণসংখ্যা
daemonized(শূন্য)
{
	পূর্ণসংখ্যা fd;

	যদি ((fd = open(_PATH_TTY, O_RDONLY | O_NOCTTY)) >= 0) {
		close(fd);
		ফেরত 0;	/* have controlling terminal */
	}
	যদি (getppid() != 1)
		ফেরত 0;	/* parent is not init */
	যদি (getsid(0) != getpid())
		ফেরত 0;	/* not session leader */
	debug3("already daemonized");
	ফেরত 1;
}

/*
 * Splits 's' into an argument vector. Handles quoted string and basic
 * escape characters (\\, \", \'). Caller must free the argument vector
 * and its members.
 */
পূর্ণসংখ্যা
argv_split(ধ্রুবক অক্ষর *s, পূর্ণসংখ্যা *argcp, অক্ষর ***argvp, পূর্ণসংখ্যা terminate_on_comment)
{
	পূর্ণসংখ্যা r = SSH_ERR_INTERNAL_ERROR;
	পূর্ণসংখ্যা argc = 0, quote, i, j;
	অক্ষর *arg, **argv = xcalloc(1, আকার(*argv));

	*argvp = ফাঁকা;
	*argcp = 0;

	জন্য (i = 0; s[i] != '\0'; i++) {
		/* Skip leading whitespace */
		যদি (s[i] == ' ' || s[i] == '\t')
			চালু;
		যদি (terminate_on_comment && s[i] == '#')
			বিরতি;
		/* Start of a token */
		quote = 0;

		argv = xreallocarray(argv, (argc + 2), আকার(*argv));
		arg = argv[argc++] = xcalloc(1, strlen(s + i) + 1);
		argv[argc] = ফাঁকা;

		/* Copy the token in, removing escapes */
		জন্য (j = 0; s[i] != '\0'; i++) {
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
				বিরতি; /* done */
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
				যাও out;
			}
			বিরতি;
		}
	}
	/* Success */
	*argcp = argc;
	*argvp = argv;
	argc = 0;
	argv = ফাঁকা;
	r = 0;
 out:
	যদি (argc != 0 && argv != ফাঁকা) {
		জন্য (i = 0; i < argc; i++)
			মুক্ত(argv[i]);
		মুক্ত(argv);
	}
	ফেরত r;
}

/*
 * Reassemble an argument vector into a string, quoting and escaping as
 * necessary. Caller must free returned string.
 */
অক্ষর *
argv_assemble(পূর্ণসংখ্যা argc, অক্ষর **argv)
{
	পূর্ণসংখ্যা i, j, ws, r;
	অক্ষর c, *ret;
	কাঠামো sshbuf *buf, *arg;

	যদি ((buf = sshbuf_new()) == ফাঁকা || (arg = sshbuf_new()) == ফাঁকা)
		fatal_f("sshbuf_new failed");

	জন্য (i = 0; i < argc; i++) {
		ws = 0;
		sshbuf_reset(arg);
		জন্য (j = 0; argv[i][j] != '\0'; j++) {
			r = 0;
			c = argv[i][j];
			নির্বাচন (c) {
			ক্ষেত্র ' ':
			ক্ষেত্র '\t':
				ws = 1;
				r = sshbuf_put_u8(arg, c);
				বিরতি;
			ক্ষেত্র '\\':
			ক্ষেত্র '\'':
			ক্ষেত্র '"':
				যদি ((r = sshbuf_put_u8(arg, '\\')) != 0)
					বিরতি;
				/* FALLTHROUGH */
			পূর্বনির্ধারিত:
				r = sshbuf_put_u8(arg, c);
				বিরতি;
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
	যদি ((ret = malloc(sshbuf_len(buf) + 1)) == ফাঁকা)
		fatal_f("malloc failed");
	memcpy(ret, sshbuf_ptr(buf), sshbuf_len(buf));
	ret[sshbuf_len(buf)] = '\0';
	sshbuf_free(buf);
	sshbuf_free(arg);
	ফেরত ret;
}

অক্ষর *
argv_পরবর্তী(পূর্ণসংখ্যা *argcp, অক্ষর ***argvp)
{
	অক্ষর *ret = (*argvp)[0];

	যদি (*argcp > 0 && ret != ফাঁকা) {
		(*argcp)--;
		(*argvp)++;
	}
	ফেরত ret;
}

শূন্য
argv_consume(পূর্ণসংখ্যা *argcp)
{
	*argcp = 0;
}

শূন্য
argv_free(অক্ষর **av, পূর্ণসংখ্যা ac)
{
	পূর্ণসংখ্যা i;

	যদি (av == ফাঁকা)
		ফেরত;
	জন্য (i = 0; i < ac; i++)
		মুক্ত(av[i]);
	মুক্ত(av);
}

/* Returns 0 if pid exited cleanly, non-zero otherwise */
পূর্ণসংখ্যা
exited_cleanly(pid_t pid, ধ্রুবক অক্ষর *tag, ধ্রুবক অক্ষর *cmd, পূর্ণসংখ্যা quiet)
{
	পূর্ণসংখ্যা status;

	যখন (waitpid(pid, &status, 0) == -1) {
		যদি (errno != EINTR) {
			error("%s waitpid: %s", tag, strerror(errno));
			ফেরত -1;
		}
	}
	যদি (WIFSIGNALED(status)) {
		error("%s %s exited on signal %d", tag, cmd, WTERMSIG(status));
		ফেরত -1;
	} অন্যথা যদি (WEXITSTATUS(status) != 0) {
		do_log2(quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_INFO,
		    "%s %s failed, status %d", tag, cmd, WEXITSTATUS(status));
		ফেরত -1;
	}
	ফেরত 0;
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
পূর্ণসংখ্যা
safe_path(ধ্রুবক অক্ষর *name, কাঠামো stat *stp, ধ্রুবক অক্ষর *pw_dir,
    uid_t uid, অক্ষর *err, আকার_t errlen)
{
	অক্ষর buf[PATH_MAX], buf2[PATH_MAX], homedir[PATH_MAX];
	অক্ষর *cp;
	পূর্ণসংখ্যা comparehome = 0;
	কাঠামো stat st;

	যদি (realpath(name, buf) == ফাঁকা) {
		snprintf(err, errlen, "realpath %s failed: %s", name,
		    strerror(errno));
		ফেরত -1;
	}
	যদি (pw_dir != ফাঁকা && realpath(pw_dir, homedir) != ফাঁকা)
		comparehome = 1;

	যদি (!S_ISREG(stp->st_mode)) {
		snprintf(err, errlen, "%s is not a regular file", buf);
		ফেরত -1;
	}
	যদি ((!platform_sys_dir_uid(stp->st_uid) && stp->st_uid != uid) ||
	    (stp->st_mode & 022) != 0) {
		snprintf(err, errlen, "bad ownership or modes for file %s",
		    buf);
		ফেরত -1;
	}

	/* for each component of the canonical path, walking upwards */
	জন্য (;;) {
		/*
		 * POSIX allows dirname to modify its argument and return a
		 * pointer into it, so make a copy to avoid overlapping strlcpy.
		 */
		strlcpy(buf2, buf, আকার(buf2));
		যদি ((cp = dirname(buf2)) == ফাঁকা) {
			snprintf(err, errlen, "dirname() failed");
			ফেরত -1;
		}
		strlcpy(buf, cp, আকার(buf));

		যদি (stat(buf, &st) == -1 ||
		    (!platform_sys_dir_uid(st.st_uid) && st.st_uid != uid) ||
		    (st.st_mode & 022) != 0) {
			snprintf(err, errlen,
			    "bad ownership or modes for directory %s", buf);
			ফেরত -1;
		}

		/* If are past the homedir then we can stop */
		যদি (comparehome && strcmp(homedir, buf) == 0)
			বিরতি;

		/*
		 * dirname should always complete with a "/" path,
		 * but we can be paranoid and check for "." too
		 */
		যদি ((strcmp("/", buf) == 0) || (strcmp(".", buf) == 0))
			বিরতি;
	}
	ফেরত 0;
}

/*
 * Version of safe_path() that accepts an open file descriptor to
 * avoid races.
 *
 * Returns 0 on success and -1 on failure
 */
পূর্ণসংখ্যা
safe_path_fd(পূর্ণসংখ্যা fd, ধ্রুবক অক্ষর *file, কাঠামো passwd *pw,
    অক্ষর *err, আকার_t errlen)
{
	কাঠামো stat st;

	/* check the open file to avoid races */
	যদি (fstat(fd, &st) == -1) {
		snprintf(err, errlen, "cannot stat file %s: %s",
		    file, strerror(errno));
		ফেরত -1;
	}
	ফেরত safe_path(file, &st, pw->pw_dir, pw->pw_uid, err, errlen);
}

/*
 * Sets the value of the given variable in the environment.  If the variable
 * already exists, its value is overridden.
 */
শূন্য
child_set_env(অক্ষর ***envp, u_int *envsizep, ধ্রুবক অক্ষর *name,
	ধ্রুবক অক্ষর *মান)
{
	অক্ষর **env;
	u_int envsize;
	u_int i, namelen;

	যদি (strchr(name, '=') != ফাঁকা) {
		error("Invalid environment variable \"%.100s\"", name);
		ফেরত;
	}

	/*
	 * If we're passed an uninitialized list, allocate a single null
	 * entry before continuing.
	 */
	যদি ((*envp == ফাঁকা) != (*envsizep == 0))
		fatal_f("environment size mismatch");
	যদি (*envp == ফাঁকা && *envsizep == 0) {
		*envp = xmalloc(আকার(অক্ষর *));
		*envp[0] = ফাঁকা;
		*envsizep = 1;
	}

	/*
	 * Find the slot where the value should be stored.  If the variable
	 * already exists, we reuse the slot; otherwise we append a new slot
	 * at the end of the array, expanding if necessary.
	 */
	env = *envp;
	namelen = strlen(name);
	জন্য (i = 0; env[i]; i++)
		যদি (strncmp(env[i], name, namelen) == 0 && env[i][namelen] == '=')
			বিরতি;
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
			env = (*envp) = xreallocarray(env, envsize, আকার(অক্ষর *));
			*envsizep = envsize;
		}
		/* Need to set the NULL pointer at end of array beyond the new slot. */
		env[i + 1] = ফাঁকা;
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
পূর্ণসংখ্যা
valid_domain(অক্ষর *name, পূর্ণসংখ্যা makelower, ধ্রুবক অক্ষর **errstr)
{
	আকার_t i, l = strlen(name);
	u_char c, last = '\0';
	স্থির অক্ষর errbuf[256];

	যদি (l == 0) {
		strlcpy(errbuf, "empty domain name", আকার(errbuf));
		যাও bad;
	}
	যদি (!isalpha((u_char)name[0]) && !isdigit((u_char)name[0]) &&
	   name[0] != '_' /* technically invalid, but common */) {
		snprintf(errbuf, আকার(errbuf), "domain name \"%.100s\" "
		    "starts with invalid character", name);
		যাও bad;
	}
	জন্য (i = 0; i < l; i++) {
		c = tolower((u_char)name[i]);
		যদি (makelower)
			name[i] = (অক্ষর)c;
		যদি (last == '.' && c == '.') {
			snprintf(errbuf, আকার(errbuf), "domain name "
			    "\"%.100s\" contains consecutive separators", name);
			যাও bad;
		}
		যদি (c != '.' && c != '-' && !isalnum(c) &&
		    c != '_') /* technically invalid, but common */ {
			snprintf(errbuf, আকার(errbuf), "domain name "
			    "\"%.100s\" contains invalid characters", name);
			যাও bad;
		}
		last = c;
	}
	যদি (name[l - 1] == '.')
		name[l - 1] = '\0';
	যদি (errstr != ফাঁকা)
		*errstr = ফাঁকা;
	ফেরত 1;
bad:
	যদি (errstr != ফাঁকা)
		*errstr = errbuf;
	ফেরত 0;
}

/*
 * Verify that a environment variable name (not including initial '$') is
 * valid; consisting of one or more alphanumeric or underscore characters only.
 * Returns 1 on valid, 0 otherwise.
 */
পূর্ণসংখ্যা
valid_env_name(ধ্রুবক অক্ষর *name)
{
	ধ্রুবক অক্ষর *cp;

	যদি (name[0] == '\0')
		ফেরত 0;
	জন্য (cp = name; *cp != '\0'; cp++) {
		যদি (!isalnum((u_char)*cp) && *cp != '_')
			ফেরত 0;
	}
	ফেরত 1;
}

ধ্রুবক অক্ষর *
atoi_err(ধ্রুবক অক্ষর *nptr, পূর্ণসংখ্যা *val)
{
	ধ্রুবক অক্ষর *errstr = ফাঁকা;

	যদি (nptr == ফাঁকা || *nptr == '\0')
		ফেরত "missing";
	*val = strtonum(nptr, 0, INT_MAX, &errstr);
	ফেরত errstr;
}

পূর্ণসংখ্যা
parse_absolute_time(ধ্রুবক অক্ষর *s, uint64_t *tp)
{
	কাঠামো tm tm;
	time_t tt;
	অক্ষর buf[32], *fmt;
	ধ্রুবক অক্ষর *cp;
	আকার_t l;
	পূর্ণসংখ্যা is_utc = 0;

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
	নির্বাচন (l) {
	ক্ষেত্র 8: /* YYYYMMDD */
		fmt = "%Y-%m-%d";
		snprintf(buf, আকার(buf), "%.4s-%.2s-%.2s", s, s + 4, s + 6);
		বিরতি;
	ক্ষেত্র 12: /* YYYYMMDDHHMM */
		fmt = "%Y-%m-%dT%H:%M";
		snprintf(buf, আকার(buf), "%.4s-%.2s-%.2sT%.2s:%.2s",
		    s, s + 4, s + 6, s + 8, s + 10);
		বিরতি;
	ক্ষেত্র 14: /* YYYYMMDDHHMMSS */
		fmt = "%Y-%m-%dT%H:%M:%S";
		snprintf(buf, আকার(buf), "%.4s-%.2s-%.2sT%.2s:%.2s:%.2s",
		    s, s + 4, s + 6, s + 8, s + 10, s + 12);
		বিরতি;
	পূর্বনির্ধারিত:
		ফেরত SSH_ERR_INVALID_FORMAT;
	}

	memset(&tm, 0, আকার(tm));
	যদি ((cp = strptime(buf, fmt, &tm)) == ফাঁকা || *cp != '\0')
		ফেরত SSH_ERR_INVALID_FORMAT;
	যদি (is_utc) {
		tm.tm_wday = -1;	/* sentinel for error */
		যদি ((tt = timegm(&tm)) == -1 && tm.tm_wday == -1)
			ফেরত SSH_ERR_INVALID_FORMAT;
	} অন্যথা {
		tm.tm_wday = -1;	/* sentinel for error */
		tm.tm_isdst = -1;	/* mktime decides DST */
		যদি ((tt = mktime(&tm)) == -1 && tm.tm_wday == -1)
			ফেরত SSH_ERR_INVALID_FORMAT;
	}
	/* success */
	*tp = (uint64_t)tt;
	ফেরত 0;
}

শূন্য
format_absolute_time(uint64_t t, অক্ষর *buf, আকার_t len)
{
	time_t tt = t > SSH_TIME_T_MAX ? SSH_TIME_T_MAX : t;
	কাঠামো tm tm;

	যদি (localtime_r(&tt, &tm) == ফাঁকা)
		strlcpy(buf, "UNKNOWN-TIME", len);
	অন্যথা
		strftime(buf, len, "%Y-%m-%dT%H:%M:%S", &tm);
}

/*
 * Parse a "pattern=interval" clause (e.g. a ChannelTimeout).
 * Returns 0 on success or non-zero on failure.
 * Caller must free *typep.
 */
পূর্ণসংখ্যা
parse_pattern_interval(ধ্রুবক অক্ষর *s, অক্ষর **typep, দ্বিগুণ *secsp)
{
	অক্ষর *cp, *sdup;
	দ্বিগুণ secs;

	যদি (typep != ফাঁকা)
		*typep = ফাঁকা;
	যদি (secsp != ফাঁকা)
		*secsp = 0;
	যদি (s == ফাঁকা)
		ফেরত -1;
	sdup = xstrdup(s);

	যদি ((cp = strchr(sdup, '=')) == ফাঁকা || cp == sdup) {
		মুক্ত(sdup);
		ফেরত -1;
	}
	*cp++ = '\0';
	যদি ((secs = convtime_double(cp)) < 0.0) {
		মুক্ত(sdup);
		ফেরত -1;
	}
	/* success */
	যদি (typep != ফাঁকা)
		*typep = xstrdup(sdup);
	যদি (secsp != ফাঁকা)
		*secsp = secs;
	মুক্ত(sdup);
	ফেরত 0;
}

/* check if path is absolute */
পূর্ণসংখ্যা
path_absolute(ধ্রুবক অক্ষর *path)
{
	ফেরত (*path == '/') ? 1 : 0;
}

শূন্য
skip_space(অক্ষর **cpp)
{
	অক্ষর *cp;

	জন্য (cp = *cpp; *cp == ' ' || *cp == '\t'; cp++)
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
পূর্ণসংখ্যা
opt_flag(ধ্রুবক অক্ষর *opt, পূর্ণসংখ্যা allow_negate, ধ্রুবক অক্ষর **optsp)
{
	আকার_t opt_len = strlen(opt);
	ধ্রুবক অক্ষর *opts = *optsp;
	পূর্ণসংখ্যা negate = 0;

	যদি (allow_negate && strncasecmp(opts, "no-", 3) == 0) {
		opts += 3;
		negate = 1;
	}
	যদি (strncasecmp(opts, opt, opt_len) == 0) {
		*optsp = opts + opt_len;
		ফেরত negate ? 0 : 1;
	}
	ফেরত -1;
}

অক্ষর *
opt_dequote(ধ্রুবক অক্ষর **sp, ধ্রুবক অক্ষর **errstrp)
{
	ধ্রুবক অক্ষর *s = *sp;
	অক্ষর *ret;
	আকার_t i;

	*errstrp = ফাঁকা;
	যদি (*s != '"') {
		*errstrp = "missing start quote";
		ফেরত ফাঁকা;
	}
	s++;
	যদি ((ret = malloc(strlen((s)) + 1)) == ফাঁকা) {
		*errstrp = "memory allocation failed";
		ফেরত ফাঁকা;
	}
	জন্য (i = 0; *s != '\0' && *s != '"';) {
		যদি (s[0] == '\\' && s[1] == '"')
			s++;
		ret[i++] = *s++;
	}
	যদি (*s == '\0') {
		*errstrp = "missing end quote";
		মুক্ত(ret);
		ফেরত ফাঁকা;
	}
	ret[i] = '\0';
	s++;
	*sp = s;
	ফেরত ret;
}

পূর্ণসংখ্যা
opt_match(ধ্রুবক অক্ষর **opts, ধ্রুবক অক্ষর *term)
{
	যদি (strncasecmp((*opts), term, strlen(term)) == 0 &&
	    (*opts)[strlen(term)] == '=') {
		*opts += strlen(term) + 1;
		ফেরত 1;
	}
	ফেরত 0;
}

শূন্য
opt_array_append2(ধ্রুবক অক্ষর *file, ধ্রুবক পূর্ণসংখ্যা সারি, ধ্রুবক অক্ষর *directive,
    অক্ষর ***array, পূর্ণসংখ্যা **iarray, u_int *lp, ধ্রুবক অক্ষর *s, পূর্ণসংখ্যা i)
{

	যদি (*lp >= INT_MAX)
		fatal("%s line %d: Too many %s entries", file, সারি, directive);

	যদি (iarray != ফাঁকা) {
		*iarray = xrecallocarray(*iarray, *lp, *lp + 1,
		    আকার(**iarray));
		(*iarray)[*lp] = i;
	}

	*array = xrecallocarray(*array, *lp, *lp + 1, আকার(**array));
	(*array)[*lp] = xstrdup(s);
	(*lp)++;
}

শূন্য
opt_array_append(ধ্রুবক অক্ষর *file, ধ্রুবক পূর্ণসংখ্যা সারি, ধ্রুবক অক্ষর *directive,
    অক্ষর ***array, u_int *lp, ধ্রুবক অক্ষর *s)
{
	opt_array_append2(file, সারি, directive, array, ফাঁকা, lp, s, 0);
}

শূন্য
opt_array_free2(অক্ষর **array, পূর্ণসংখ্যা **iarray, u_int l)
{
	u_int i;

	যদি (array == ফাঁকা || l == 0)
		ফেরত;
	জন্য (i = 0; i < l; i++)
		মুক্ত(array[i]);
	মুক্ত(array);
	মুক্ত(iarray);
}

sshsig_t
ssh_signal(পূর্ণসংখ্যা signum, sshsig_t handler)
{
	কাঠামো sigaction sa, osa;

	/* mask all other signals while in handler */
	memset(&sa, 0, আকার(sa));
	sa.sa_handler = handler;
	sigfillset(&sa.sa_mask);
#যদি defined(SA_RESTART) && !defined(NO_SA_RESTART)
	যদি (signum != SIGALRM)
		sa.sa_flags = SA_RESTART;
#endif
	যদি (sigaction(signum, &sa, &osa) == -1) {
		debug3("sigaction(%s): %s", strsignal(signum), strerror(errno));
		ফেরত SIG_ERR;
	}
	ফেরত osa.sa_handler;
}

পূর্ণসংখ্যা
stdfd_devnull(পূর্ণসংখ্যা do_stdin, পূর্ণসংখ্যা do_stdout, পূর্ণসংখ্যা do_stderr)
{
	পূর্ণসংখ্যা devnull, ret = 0;

	যদি ((devnull = open(_PATH_DEVNULL, O_RDWR)) == -1) {
		error_f("open %s: %s", _PATH_DEVNULL,
		    strerror(errno));
		ফেরত -1;
	}
	যদি ((do_stdin && dup2(devnull, STDIN_FILENO) == -1) ||
	    (do_stdout && dup2(devnull, STDOUT_FILENO) == -1) ||
	    (do_stderr && dup2(devnull, STDERR_FILENO) == -1)) {
		error_f("dup2: %s", strerror(errno));
		ret = -1;
	}
	যদি (devnull > STDERR_FILENO)
		close(devnull);
	ফেরত ret;
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
subprocess(ধ্রুবক অক্ষর *tag, ধ্রুবক অক্ষর *command,
    পূর্ণসংখ্যা ac, অক্ষর **av, FILE **child, u_int flags,
    কাঠামো passwd *pw, privdrop_fn *drop_privs, privrestore_fn *restore_privs)
{
	FILE *f = ফাঁকা;
	কাঠামো stat st;
	পূর্ণসংখ্যা fd, devnull, p[2], i;
	pid_t pid;
	অক্ষর *cp, errmsg[512];
	u_int nenv = 0;
	অক্ষর **env = ফাঁকা;

	/* If dropping privs, then must specify user and restore function */
	যদি (drop_privs != ফাঁকা && (pw == ফাঁকা || restore_privs == ফাঁকা)) {
		error("%s: inconsistent arguments", tag); /* XXX fatal? */
		ফেরত 0;
	}
	যদি (pw == ফাঁকা && (pw = getpwuid(getuid())) == ফাঁকা) {
		error("%s: no user for current uid", tag);
		ফেরত 0;
	}
	যদি (child != ফাঁকা)
		*child = ফাঁকা;

	debug3_f("%s command \"%s\" running as %s (flags 0x%x)",
	    tag, command, pw->pw_name, flags);

	/* Check consistency */
	যদি ((flags & SSH_SUBPROCESS_STDOUT_DISCARD) != 0 &&
	    (flags & SSH_SUBPROCESS_STDOUT_CAPTURE) != 0) {
		error_f("inconsistent flags");
		ফেরত 0;
	}
	যদি (((flags & SSH_SUBPROCESS_STDOUT_CAPTURE) == 0) != (child == ফাঁকা)) {
		error_f("inconsistent flags/output");
		ফেরত 0;
	}

	/*
	 * If executing an explicit binary, then verify the it exists
	 * and appears safe-ish to execute
	 */
	যদি (!path_absolute(av[0])) {
		error("%s path is not absolute", tag);
		ফেরত 0;
	}
	যদি (drop_privs != ফাঁকা)
		drop_privs(pw);
	যদি (stat(av[0], &st) == -1) {
		error("Could not stat %s \"%s\": %s", tag,
		    av[0], strerror(errno));
		যাও restore_return;
	}
	যদি ((flags & SSH_SUBPROCESS_UNSAFE_PATH) == 0 &&
	    safe_path(av[0], &st, ফাঁকা, 0, errmsg, আকার(errmsg)) != 0) {
		error("Unsafe %s \"%s\": %s", tag, av[0], errmsg);
		যাও restore_return;
	}
	/* Prepare to keep the child's stdout if requested */
	যদি (pipe(p) == -1) {
		error("%s: pipe: %s", tag, strerror(errno));
 restore_return:
		যদি (restore_privs != ফাঁকা)
			restore_privs();
		ফেরত 0;
	}
	যদি (restore_privs != ফাঁকা)
		restore_privs();

	নির্বাচন ((pid = fork())) {
	ক্ষেত্র -1: /* error */
		error("%s: fork: %s", tag, strerror(errno));
		close(p[0]);
		close(p[1]);
		ফেরত 0;
	ক্ষেত্র 0: /* child */
		/* Prepare a minimal environment for the child. */
		যদি ((flags & SSH_SUBPROCESS_PRESERVE_ENV) == 0) {
			nenv = 5;
			env = xcalloc(আকার(*env), nenv);
			child_set_env(&env, &nenv, "PATH", _PATH_STDPATH);
			child_set_env(&env, &nenv, "USER", pw->pw_name);
			child_set_env(&env, &nenv, "LOGNAME", pw->pw_name);
			child_set_env(&env, &nenv, "HOME", pw->pw_dir);
			যদি ((cp = getenv("LANG")) != ফাঁকা)
				child_set_env(&env, &nenv, "LANG", cp);
		}

		জন্য (i = 1; i < NSIG; i++)
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
		যদি (env != ফাঁকা)
			execve(av[0], av, env);
		অন্যথা
			execv(av[0], av);
		error("%s %s \"%s\": %s", tag, env == ফাঁকা ? "execv" : "execve",
		    command, strerror(errno));
		_exit(127);
	পূর্বনির্ধারিত: /* parent */
		বিরতি;
	}

	close(p[1]);
	যদি ((flags & SSH_SUBPROCESS_STDOUT_CAPTURE) == 0)
		close(p[0]);
	অন্যথা যদি ((f = fdopen(p[0], "r")) == ফাঁকা) {
		error("%s: fdopen: %s", tag, strerror(errno));
		close(p[0]);
		/* Don't leave zombie child */
		kill(pid, SIGTERM);
		যখন (waitpid(pid, ফাঁকা, 0) == -1 && errno == EINTR)
			;
		ফেরত 0;
	}
	/* Success */
	debug3_f("%s pid %ld", tag, (long)pid);
	যদি (child != ফাঁকা)
		*child = f;
	ফেরত pid;
}

ধ্রুবক অক্ষর *
lookup_env_in_list(ধ্রুবক অক্ষর *env, অক্ষর * ধ্রুবক *envs, আকার_t nenvs)
{
	আকার_t i, envlen;

	envlen = strlen(env);
	জন্য (i = 0; i < nenvs; i++) {
		যদি (strncmp(envs[i], env, envlen) == 0 &&
		    envs[i][envlen] == '=') {
			ফেরত envs[i] + envlen + 1;
		}
	}
	ফেরত ফাঁকা;
}

ধ্রুবক অক্ষর *
lookup_setenv_in_list(ধ্রুবক অক্ষর *env, অক্ষর * ধ্রুবক *envs, আকার_t nenvs)
{
	অক্ষর *name, *cp;
	ধ্রুবক অক্ষর *ret;

	name = xstrdup(env);
	যদি ((cp = strchr(name, '=')) == ফাঁকা) {
		মুক্ত(name);
		ফেরত ফাঁকা; /* not env=val */
	}
	*cp = '\0';
	ret = lookup_env_in_list(name, envs, nenvs);
	মুক্ত(name);
	ফেরত ret;
}

/*
 * Helpers for managing poll(2)/ppoll(2) timeouts
 * Will remember the earliest deadline and return it for use in poll/ppoll.
 */

/* Initialise a poll/ppoll timeout with an indefinite deadline */
শূন্য
ptimeout_init(কাঠামো timespec *pt)
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
ptimeout_deadline_sec(কাঠামো timespec *pt, long sec)
{
	যদি (pt->tv_sec == -1 || pt->tv_sec >= sec) {
		pt->tv_sec = sec;
		pt->tv_nsec = 0;
	}
}

/* Specify a poll/ppoll deadline of at most 'p' (timespec) */
স্থির শূন্য
ptimeout_deadline_tsp(কাঠামো timespec *pt, কাঠামো timespec *p)
{
	যদি (pt->tv_sec == -1 || timespeccmp(pt, p, >=))
		*pt = *p;
}

/* Specify a poll/ppoll deadline of at most 'ms' milliseconds */
শূন্য
ptimeout_deadline_ms(কাঠামো timespec *pt, long ms)
{
	কাঠামো timespec p;

	p.tv_sec = ms / 1000;
	p.tv_nsec = (ms % 1000) * 1000000;
	ptimeout_deadline_tsp(pt, &p);
}

/* Specify a poll/ppoll deadline of at most 'sec' seconds (double) */
শূন্য
ptimeout_deadline_sec_double(কাঠামো timespec *pt, দ্বিগুণ sec)
{
	কাঠামো timespec t;

	memset(&t, 0, আকার(t));
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
ptimeout_deadline_monotime_tsp(কাঠামো timespec *pt, কাঠামো timespec *when)
{
	কাঠামো timespec now, t;

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
ptimeout_deadline_monotime_double(কাঠামো timespec *pt, দ্বিগুণ when)
{
	ptimeout_deadline_sec_double(pt, when - monotime_double());
}

/* Specify a poll/ppoll deadline at wall clock monotime 'when' */
শূন্য
ptimeout_deadline_monotime(কাঠামো timespec *pt, time_t when)
{
	কাঠামো timespec t;

	t.tv_sec = when;
	t.tv_nsec = 0;
	ptimeout_deadline_monotime_tsp(pt, &t);
}

/* Get a poll(2) timeout value in milliseconds */
পূর্ণসংখ্যা
ptimeout_get_ms(কাঠামো timespec *pt)
{
	যদি (pt->tv_sec == -1)
		ফেরত -1;
	যদি (pt->tv_sec >= (INT_MAX - (pt->tv_nsec / 1000000)) / 1000)
		ফেরত INT_MAX;
	ফেরত (pt->tv_sec * 1000) + (pt->tv_nsec / 1000000);
}

/* Get a ppoll(2) timeout value as a timespec pointer */
কাঠামো timespec *
ptimeout_get_tsp(কাঠামো timespec *pt)
{
	ফেরত pt->tv_sec == -1 ? ফাঁকা : pt;
}

/* Returns non-zero if a timeout has been set (i.e. is not indefinite) */
পূর্ণসংখ্যা
ptimeout_isset(কাঠামো timespec *pt)
{
	ফেরত pt->tv_sec != -1;
}

/*
 * Returns zero if the library at 'path' contains symbol 's', nonzero
 * otherwise.
 */
পূর্ণসংখ্যা
lib_contains_প্রতীক(ধ্রুবক অক্ষর *path, ধ্রুবক অক্ষর *s)
{
#ifdef HAVE_NLIST
	কাঠামো nlist nl[2];
	পূর্ণসংখ্যা ret = -1, r;

	memset(nl, 0, আকার(nl));
	nl[0].n_name = xstrdup(s);
	nl[1].n_name = ফাঁকা;
	যদি ((r = nlist(path, nl)) == -1) {
		error_f("nlist failed for %s", path);
		যাও out;
	}
	যদি (r != 0 || nl[0].n_মান == 0 || nl[0].n_type == 0) {
		error_f("library %s does not contain symbol %s", path, s);
		যাও out;
	}
	/* success */
	ret = 0;
 out:
	মুক্ত(nl[0].n_name);
	ফেরত ret;
#অন্যথা /* HAVE_NLIST */
	পূর্ণসংখ্যা fd, ret = -1;
	কাঠামো stat st;
	শূন্য *m = ফাঁকা;
	আকার_t sz = 0;

	memset(&st, 0, আকার(st));
	যদি ((fd = open(path, O_RDONLY)) < 0) {
		error_f("open %s: %s", path, strerror(errno));
		ফেরত -1;
	}
	যদি (fstat(fd, &st) != 0) {
		error_f("fstat %s: %s", path, strerror(errno));
		যাও out;
	}
	যদি (!S_ISREG(st.st_mode)) {
		error_f("%s is not a regular file", path);
		যাও out;
	}
	যদি (st.st_size < 0 ||
	    (আকার_t)st.st_size < strlen(s) ||
	    st.st_size >= INT_MAX/2) {
		error_f("%s bad size %lld", path, (long long)st.st_size);
		যাও out;
	}
	sz = (আকার_t)st.st_size;
	যদি ((m = mmap(ফাঁকা, sz, PROT_READ, MAP_PRIVATE, fd, 0)) == MAP_FAILED ||
	    m == ফাঁকা) {
		error_f("mmap %s: %s", path, strerror(errno));
		যাও out;
	}
	যদি (memmem(m, sz, s, strlen(s)) == ফাঁকা) {
		error_f("%s does not contain expected string %s", path, s);
		যাও out;
	}
	/* success */
	ret = 0;
 out:
	যদি (m != ফাঁকা && m != MAP_FAILED)
		munmap(m, sz);
	close(fd);
	ফেরত ret;
#endif /* HAVE_NLIST */
}

পূর্ণসংখ্যা
signal_is_crash(পূর্ণসংখ্যা sig)
{
	নির্বাচন (sig) {
	ক্ষেত্র SIGSEGV:
	ক্ষেত্র SIGBUS:
	ক্ষেত্র SIGTRAP:
	ক্ষেত্র SIGSYS:
	ক্ষেত্র SIGFPE:
	ক্ষেত্র SIGILL:
	ক্ষেত্র SIGABRT:
		ফেরত 1;
	}
	ফেরত 0;
}

অক্ষর *
get_homedir(শূন্য)
{
	অক্ষর *cp;
	কাঠামো passwd *pw;

	যদি ((cp = getenv("HOME")) != ফাঁকা && *cp != '\0')
		ফেরত xstrdup(cp);

	যদি ((pw = getpwuid(getuid())) != ফাঁকা && *pw->pw_dir != '\0')
		ফেরত xstrdup(pw->pw_dir);

	ফেরত ফাঁকা;
}

পূর্ণসংখ্যা
mkdir_path(ধ্রুবক অক্ষর *target, mode_t mode)
{
#যদি defined(HAVE_OPENAT) && defined(O_DIRECTORY)
	অক্ষর *dir, *odir = ফাঁকা, *পরবর্তী;
	পূর্ণসংখ্যা fd = AT_FDCWD, fd2, subpath_len, ret = -1;

	dir = odir = xstrdup(target);

	যদি (*dir == '/' &&
	    (fd = open("/", O_RDONLY|O_DIRECTORY)) == -1) {
		error_f("open(\"/\"): %s", strerror(errno));
		মুক্ত(odir);
		ফেরত -1;
	}
	/* Work through the path, component-wise */
	জন্য (; dir != ফাঁকা && *dir != '\0'; dir = পরবর্তী) {
		যদি ((পরবর্তী = strchr(dir, '/')) != ফাঁকা)
			*(পরবর্তী++) = '\0';
		যদি (*dir == '\0')
			চালু;
		subpath_len = (পরবর্তী == ফাঁকা) ? INT_MAX : পরবর্তী - odir - 1;
		যদি (mkdirat(fd, dir, mode) == 0)
			debug_f("created directory %.*s", subpath_len, target);
		অন্যথা যদি (errno != EEXIST) {
			error_f("mkdir(\"%.*s\"): %s",
			    subpath_len, target, strerror(errno));
			যাও out;
		}

		/* descend */
		যদি ((fd2 = openat(fd, dir, O_RDONLY|O_DIRECTORY)) == -1) {
			error_f("open(\"%.*s\"): %s",
			    subpath_len, target, strerror(errno));
			যাও out;
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
	ফেরত ret;
#অন্যথা
	/*
	 * If we don't have openat (which was added in POSIX.1-2008), fall back
	 * to the possibly racy way.
	 */
	অক্ষর *dir, *odir, *p, path[PATH_MAX] = "";
	পূর্ণসংখ্যা ret = -1;
	আকার_t plen = আকার(path);

	dir = odir = xstrdup(target);

	/* If the dir is relative, start with cwd. */
	যদি (*dir != '/' && getcwd(path, plen) == ফাঁকা) {
		error_f("getcwd: %s", strerror(errno));
		যাও out;
	}

	/* Work through the path, component-wise */
	যখন ((p = strsep(&dir, "/"))) {
		যদি (*p == '\0')
			চালু;
		যদি (strlcat(path, "/", plen) >= plen ||
		    strlcat(path, p, plen) >= plen)
			যাও out;
		যদি (mkdir(path, mode) == 0)
			debug_f("created directory %s", path);
		অন্যথা যদি (errno != EEXIST && errno != EISDIR) {
			error_f("mkdir(\"%s\"): %s", path, strerror(errno));
			যাও out;
		}
	}
	/* success */
	ret = 0;
 out:
	মুক্ত(odir);
	ফেরত ret;
#endif
}
