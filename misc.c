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


#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <sys/ioctl.h>
#ضمن <sys/mman.h>
#ضمن <sys/socket.h>
#ضمن <sys/stat.h>
#ضمن <sys/time.h>
#ضمن <sys/wait.h>
#ضمن <sys/un.h>

#ضمن <limits.h>
#ضمن <libgen.h>
#ضمن <poll.h>
#ضمن <nlist.h>
#ضمن <signal.h>
#ضمن <stdarg.h>
#ضمن <stdio.h>
#ضمن <stdint.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <time.h>
#ضمن <unistd.h>

#ضمن <netinet/in.h>
#ضمن <netinet/ip.h>
#ضمن <netinet/tcp.h>
#ضمن <arpa/inet.h>

#ضمن <ctype.h>
#ضمن <errno.h>
#ضمن <fcntl.h>
#ضمن <netdb.h>
#ضمن <paths.h>
#ضمن <pwd.h>
#ضمن <grp.h>
#ifdef SSH_TUN_OPENBSD
#ضمن <net/if.h>
#endif

#ضمن "xmalloc.h"
#ضمن "misc.h"
#ضمن "log.h"
#ضمن "ssh.h"
#ضمن "sshbuf.h"
#ضمن "ssherr.h"
#ضمن "platform.h"

/* remove newline at end of string */
حرف *
chop(حرف *s)
{
	حرف *t = s;
	طالما (*t) {
		𐡄𐡍 (*t == '\n' || *t == '\r') {
			*t = '\0';
			أرجع s;
		}
		t++;
	}
	أرجع s;

}

/* remove whitespace from end of string */
فراغ
rtrim(حرف *s)
{
	size_t i;

	𐡄𐡍 ((i = strlen(s)) == 0)
		أرجع;
	𐡏𐡁𐡃 {
		i--;
		𐡄𐡍 (isspace((unsigned حرف)s[i]))
			s[i] = '\0';
		وإلا
			اكسر;
	} طالما (i > 0);
}

/*
 * returns pointer to character after 'prefix' in 's' or otherwise NULL
 * if the prefix is not present.
 */
ثابت حرف *
strprefix(ثابت حرف *s, ثابت حرف *prefix, صحيح ignorecase)
{
	size_t prefixlen;

	𐡄𐡍 ((prefixlen = strlen(prefix)) == 0)
		أرجع s;
	𐡄𐡍 (ignorecase) {
		𐡄𐡍 (strncasecmp(s, prefix, prefixlen) != 0)
			أرجع عدم;
	} وإلا {
		𐡄𐡍 (strncmp(s, prefix, prefixlen) != 0)
			أرجع عدم;
	}
	أرجع s + prefixlen;
}

/* Append string 's' to a NULL-terminated array of strings */
فراغ
stringlist_append(حرف ***listp, ثابت حرف *s)
{
	size_t i = 0;

	𐡄𐡍 (*listp == عدم)
		*listp = xcalloc(2, حجم(**listp));
	وإلا {
		لكل (i = 0; (*listp)[i] != عدم; i++)
			; /* count */
		*listp = xrecallocarray(*listp, i + 1, i + 2, حجم(**listp));
	}
	(*listp)[i] = xstrdup(s);
}

فراغ
stringlist_free(حرف **list)
{
	size_t i = 0;

	𐡄𐡍 (list == عدم)
		أرجع;
	لكل (i = 0; list[i] != عدم; i++)
		حرر(list[i]);
	حرر(list);
}

/* set/unset filedescriptor to non-blocking */
صحيح
set_nonblock(صحيح fd)
{
	صحيح val;

	val = fcntl(fd, F_GETFL);
	𐡄𐡍 (val == -1) {
		error("fcntl(%d, F_GETFL): %s", fd, strerror(errno));
		أرجع (-1);
	}
	𐡄𐡍 (val & O_NONBLOCK) {
		debug3("fd %d is O_NONBLOCK", fd);
		أرجع (0);
	}
	debug2("fd %d setting O_NONBLOCK", fd);
	val |= O_NONBLOCK;
	𐡄𐡍 (fcntl(fd, F_SETFL, val) == -1) {
		debug("fcntl(%d, F_SETFL, O_NONBLOCK): %s", fd,
		    strerror(errno));
		أرجع (-1);
	}
	أرجع (0);
}

صحيح
unset_nonblock(صحيح fd)
{
	صحيح val;

	val = fcntl(fd, F_GETFL);
	𐡄𐡍 (val == -1) {
		error("fcntl(%d, F_GETFL): %s", fd, strerror(errno));
		أرجع (-1);
	}
	𐡄𐡍 (!(val & O_NONBLOCK)) {
		debug3("fd %d is not O_NONBLOCK", fd);
		أرجع (0);
	}
	debug("fd %d clearing O_NONBLOCK", fd);
	val &= ~O_NONBLOCK;
	𐡄𐡍 (fcntl(fd, F_SETFL, val) == -1) {
		debug("fcntl(%d, F_SETFL, ~O_NONBLOCK): %s",
		    fd, strerror(errno));
		أرجع (-1);
	}
	أرجع (0);
}

ثابت حرف *
ssh_gai_strerror(صحيح gaierr)
{
	𐡄𐡍 (gaierr == EAI_SYSTEM && errno != 0)
		أرجع strerror(errno);
	أرجع gai_strerror(gaierr);
}

/* disable nagle on socket */
فراغ
set_nodelay(صحيح fd)
{
	صحيح opt;
	socklen_t optlen;

	optlen = حجم opt;
	𐡄𐡍 (getsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, &optlen) == -1) {
		debug("getsockopt TCP_NODELAY: %.100s", strerror(errno));
		أرجع;
	}
	𐡄𐡍 (opt == 1) {
		debug2("fd %d is TCP_NODELAY", fd);
		أرجع;
	}
	opt = 1;
	debug2("fd %d setting TCP_NODELAY", fd);
	𐡄𐡍 (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, حجم opt) == -1)
		error("setsockopt TCP_NODELAY: %.100s", strerror(errno));
}

/* Allow local port reuse in TIME_WAIT */
صحيح
set_reuseaddr(صحيح fd)
{
	صحيح on = 1;

	𐡄𐡍 (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, حجم(on)) == -1) {
		error("setsockopt SO_REUSEADDR fd %d: %s", fd, strerror(errno));
		أرجع -1;
	}
	أرجع 0;
}

/* Set TCP keepalives */
صحيح
set_keepalive(صحيح fd)
{
	صحيح on = 1;

	𐡄𐡍 (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, حجم(on)) == -1) {
		error("setsockopt SO_KEEPALIVE fd %d: %s", fd, strerror(errno));
		أرجع -1;
	}
	أرجع 0;
}

/* Get/set routing domain */
حرف *
get_rdomain(صحيح fd)
{
#𐡄𐡍 defined(HAVE_SYS_GET_RDOMAIN)
	أرجع sys_get_rdomain(fd);
#وإلاإذا defined(__OpenBSD__)
	صحيح rtable;
	حرف *ret;
	socklen_t len = حجم(rtable);

	𐡄𐡍 (getsockopt(fd, SOL_SOCKET, SO_RTABLE, &rtable, &len) == -1) {
		error("Failed to get routing domain for fd %d: %s",
		    fd, strerror(errno));
		أرجع عدم;
	}
	xasprintf(&ret, "%d", rtable);
	أرجع ret;
#وإلا /* defined(__OpenBSD__) */
	أرجع عدم;
#endif
}

صحيح
set_rdomain(صحيح fd, ثابت حرف *name)
{
#𐡄𐡍 defined(HAVE_SYS_SET_RDOMAIN)
	أرجع sys_set_rdomain(fd, name);
#وإلاإذا defined(__OpenBSD__)
	صحيح rtable;
	ثابت حرف *errstr;

	𐡄𐡍 (name == عدم)
		أرجع 0; /* default table */

	rtable = (صحيح)strtonum(name, 0, 255, &errstr);
	𐡄𐡍 (errstr != عدم) {
		/* Shouldn't happen */
		error("Invalid routing domain \"%s\": %s", name, errstr);
		أرجع -1;
	}
	𐡄𐡍 (setsockopt(fd, SOL_SOCKET, SO_RTABLE,
	    &rtable, حجم(rtable)) == -1) {
		error("Failed to set routing domain %d on fd %d: %s",
		    rtable, fd, strerror(errno));
		أرجع -1;
	}
	أرجع 0;
#وإلا /* defined(__OpenBSD__) */
	error("Setting routing domain is not supported on this platform");
	أرجع -1;
#endif
}

صحيح
get_sock_af(صحيح fd)
{
	بنية sockaddr_storage to;
	socklen_t tolen = حجم(to);

	memset(&to, 0, حجم(to));
	𐡄𐡍 (getsockname(fd, (بنية sockaddr *)&to, &tolen) == -1)
		أرجع -1;
#ifdef IPV4_IN_IPV6
	𐡄𐡍 (to.ss_family == AF_INET6 &&
	    IN6_IS_ADDR_V4MAPPED(&((بنية sockaddr_in6 *)&to)->sin6_addr))
		أرجع AF_INET;
#endif
	أرجع to.ss_family;
}

فراغ
set_sock_tos(صحيح fd, صحيح tos)
{
#ifndef IP_TOS_IS_BROKEN
	صحيح af;

	𐡄𐡍 (tos < 0 || tos == INT_MAX) {
		debug_f("invalid TOS %d", tos);
		أرجع;
	}
	بدل ((af = get_sock_af(fd))) {
	حالة -1:
		/* assume not a socket */
		اكسر;
	حالة AF_INET:
# ifdef IP_TOS
		debug3_f("set socket %d IP_TOS 0x%02x", fd, tos);
		𐡄𐡍 (setsockopt(fd, IPPROTO_IP, IP_TOS,
		    &tos, حجم(tos)) == -1) {
			error("setsockopt socket %d IP_TOS %d: %s",
			    fd, tos, strerror(errno));
		}
# endif /* IP_TOS */
		اكسر;
	حالة AF_INET6:
# ifdef IPV6_TCLASS
		debug3_f("set socket %d IPV6_TCLASS 0x%02x", fd, tos);
		𐡄𐡍 (setsockopt(fd, IPPROTO_IPV6, IPV6_TCLASS,
		    &tos, حجم(tos)) == -1) {
			error("setsockopt socket %d IPV6_TCLASS %d: %s",
			    fd, tos, strerror(errno));
		}
# endif /* IPV6_TCLASS */
		اكسر;
	افتراضي:
		debug2_f("unsupported socket family %d", af);
		اكسر;
	}
#endif /* IP_TOS_IS_BROKEN */
}

/*
 * Wait up to *timeoutp milliseconds for events on fd. Updates
 * *timeoutp with time remaining.
 * Returns 0 if fd ready or -1 on timeout or error (see errno).
 */
ساكن صحيح
waitfd(صحيح fd, صحيح *timeoutp, short events, متطاير sig_atomic_t *stop)
{
	بنية pollfd pfd;
	بنية timespec timeout;
	صحيح oerrno, r;
	sigset_t nsigset, osigset;

	𐡄𐡍 (timeoutp && *timeoutp == -1)
		timeoutp = عدم;
	pfd.fd = fd;
	pfd.events = events;
	ptimeout_init(&timeout);
	𐡄𐡍 (timeoutp != عدم)
		ptimeout_deadline_ms(&timeout, *timeoutp);
	𐡄𐡍 (stop != عدم)
		sigfillset(&nsigset);
	لكل (; timeoutp == عدم || *timeoutp >= 0;) {
		𐡄𐡍 (stop != عدم) {
			sigprocmask(SIG_BLOCK, &nsigset, &osigset);
			𐡄𐡍 (*stop) {
				sigprocmask(SIG_SETMASK, &osigset, عدم);
				errno = EINTR;
				أرجع -1;
			}
		}
		r = ppoll(&pfd, 1, ptimeout_get_tsp(&timeout),
		    stop != عدم ? &osigset : عدم);
		oerrno = errno;
		𐡄𐡍 (stop != عدم)
			sigprocmask(SIG_SETMASK, &osigset, عدم);
		𐡄𐡍 (timeoutp)
			*timeoutp = ptimeout_get_ms(&timeout);
		errno = oerrno;
		𐡄𐡍 (r > 0)
			أرجع 0;
		وإلا 𐡄𐡍 (r == -1 && errno != EAGAIN && errno != EINTR)
			أرجع -1;
		وإلا 𐡄𐡍 (r == 0)
			اكسر;
	}
	/* timeout */
	errno = ETIMEDOUT;
	أرجع -1;
}

/*
 * Wait up to *timeoutp milliseconds for fd to be readable. Updates
 * *timeoutp with time remaining.
 * Returns 0 if fd ready or -1 on timeout or error (see errno).
 */
صحيح
waitrfd(صحيح fd, صحيح *timeoutp, متطاير sig_atomic_t *stop) {
	أرجع waitfd(fd, timeoutp, POLLIN, stop);
}

/*
 * Attempt a non-blocking connect(2) to the specified address, waiting up to
 * *timeoutp milliseconds for the connection to complete. If the timeout is
 * <=0, then wait indefinitely.
 *
 * Returns 0 on success or -1 on failure.
 */
صحيح
timeout_connect(صحيح sockfd, ثابت بنية sockaddr *serv_addr,
    socklen_t addrlen, صحيح *timeoutp)
{
	صحيح optval = 0;
	socklen_t optlen = حجم(optval);

	/* No timeout: just do a blocking connect() */
	𐡄𐡍 (timeoutp == عدم || *timeoutp <= 0)
		أرجع connect(sockfd, serv_addr, addrlen);

	set_nonblock(sockfd);
	لكل (;;) {
		𐡄𐡍 (connect(sockfd, serv_addr, addrlen) == 0) {
			/* Succeeded already? */
			unset_nonblock(sockfd);
			أرجع 0;
		} وإلا 𐡄𐡍 (errno == EINTR)
			استمر;
		وإلا 𐡄𐡍 (errno != EINPROGRESS)
			أرجع -1;
		اكسر;
	}

	𐡄𐡍 (waitfd(sockfd, timeoutp, POLLIN | POLLOUT, عدم) == -1)
		أرجع -1;

	/* Completed or failed */
	𐡄𐡍 (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &optval, &optlen) == -1) {
		debug("getsockopt: %s", strerror(errno));
		أرجع -1;
	}
	𐡄𐡍 (optval != 0) {
		errno = optval;
		أرجع -1;
	}
	unset_nonblock(sockfd);
	أرجع 0;
}

/* Characters considered whitespace in strsep calls. */
#define WHITESPACE " \t\r\n"
#define QUOTE	"\""

/* return next token in configuration line */
ساكن حرف *
strdelim_internal(حرف **s, صحيح split_equals)
{
	حرف *old;
	صحيح wspace = 0;

	𐡄𐡍 (*s == عدم)
		أرجع عدم;

	old = *s;

	*s = strpbrk(*s,
	    split_equals ? WHITESPACE QUOTE "=" : WHITESPACE QUOTE);
	𐡄𐡍 (*s == عدم)
		أرجع (old);

	𐡄𐡍 (*s[0] == '\"') {
		memmove(*s, *s + 1, strlen(*s)); /* move nul too */
		/* Find matching quote */
		𐡄𐡍 ((*s = strpbrk(*s, QUOTE)) == عدم) {
			أرجع (عدم);		/* no matching quote */
		} وإلا {
			*s[0] = '\0';
			*s += strspn(*s + 1, WHITESPACE) + 1;
			أرجع (old);
		}
	}

	/* Allow only one '=' to be skipped */
	𐡄𐡍 (split_equals && *s[0] == '=')
		wspace = 1;
	*s[0] = '\0';

	/* Skip any extra whitespace after first token */
	*s += strspn(*s + 1, WHITESPACE) + 1;
	𐡄𐡍 (split_equals && *s[0] == '=' && !wspace)
		*s += strspn(*s + 1, WHITESPACE) + 1;

	أرجع (old);
}

/*
 * Return next token in configuration line; splits on whitespace or a
 * single '=' character.
 */
حرف *
strdelim(حرف **s)
{
	أرجع strdelim_internal(s, 1);
}

/*
 * Return next token in configuration line; splits on whitespace only.
 */
حرف *
strdelimw(حرف **s)
{
	أرجع strdelim_internal(s, 0);
}

بنية passwd *
pwcopy(بنية passwd *pw)
{
	بنية passwd *copy = xcalloc(1, حجم(*copy));

	copy->pw_name = xstrdup(pw->pw_name);
	copy->pw_passwd = xstrdup(pw->pw_passwd == عدم ? "*" : pw->pw_passwd);
#ifdef HAVE_STRUCT_PASSWD_PW_GECOS
	copy->pw_gecos = xstrdup(pw->pw_gecos == عدم ? "" : pw->pw_gecos);
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
	copy->pw_class = xstrdup(pw->pw_class == عدم ? "" : pw->pw_class);
#endif
	copy->pw_dir = xstrdup(pw->pw_dir == عدم ? "" : pw->pw_dir);
	copy->pw_shell = xstrdup(pw->pw_shell == عدم ? "" : pw->pw_shell);
	أرجع copy;
}

فراغ
pwfree(بنية passwd *pw)
{
	𐡄𐡍 (pw == عدم)
		أرجع;
	حرر(pw->pw_name);
	freezero(pw->pw_passwd,
	    pw->pw_passwd == عدم ? 0 : strlen(pw->pw_passwd));
#ifdef HAVE_STRUCT_PASSWD_PW_GECOS
	حرر(pw->pw_gecos);
#endif
#ifdef HAVE_STRUCT_PASSWD_PW_CLASS
	حرر(pw->pw_class);
#endif
	حرر(pw->pw_dir);
	حرر(pw->pw_shell);
	freezero(pw, حجم(*pw));
}

/*
 * Convert ASCII string to TCP/IP port number.
 * Port must be >=0 and <=65535.
 * Return -1 if invalid.
 */
صحيح
a2port(ثابت حرف *s)
{
	بنية servent *se;
	long long port;
	ثابت حرف *errstr;

	port = strtonum(s, 0, 65535, &errstr);
	𐡄𐡍 (errstr == عدم)
		أرجع (صحيح)port;
	𐡄𐡍 ((se = getservbyname(s, "tcp")) != عدم)
		أرجع ntohs(se->s_port);
	أرجع -1;
}

صحيح
a2tun(ثابت حرف *s, صحيح *remote)
{
	ثابت حرف *errstr = عدم;
	حرف *sp, *ep;
	صحيح tun;

	𐡄𐡍 (remote != عدم) {
		*remote = SSH_TUNID_ANY;
		sp = xstrdup(s);
		𐡄𐡍 ((ep = strchr(sp, ':')) == عدم) {
			حرر(sp);
			أرجع (a2tun(s, عدم));
		}
		ep[0] = '\0'; ep++;
		*remote = a2tun(ep, عدم);
		tun = a2tun(sp, عدم);
		حرر(sp);
		أرجع (*remote == SSH_TUNID_ERR ? *remote : tun);
	}

	𐡄𐡍 (strcasecmp(s, "any") == 0)
		أرجع (SSH_TUNID_ANY);

	tun = strtonum(s, 0, SSH_TUNID_MAX, &errstr);
	𐡄𐡍 (errstr != عدم)
		أرجع (SSH_TUNID_ERR);

	أرجع (tun);
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
مزدوج
convtime_double(ثابت حرف *s)
{
	مزدوج val, total_sec = 0.0, multiplier;
	ثابت حرف *p, *start_p;
	حرف *endp;
	صحيح seen_seconds = 0;

	𐡄𐡍 (s == عدم || *s == '\0')
		أرجع -1.0;

	لكل (p = s; *p != '\0';) {
		𐡄𐡍 (!isdigit((unsigned حرف)*p) && *p != '.')
			أرجع -1.0;

		errno = 0;
		𐡄𐡍 ((val = strtod(p, &endp)) < 0 || errno != 0 || p == endp)
			أرجع -1.0;
		/* Allow only decimal forms */
		𐡄𐡍 (p + strspn(p, "0123456789.") != endp)
			أرجع -1.0;
		start_p = p;
		p = endp;

		بدل (*p) {
		حالة '\0':
			/* FALLTHROUGH */
		حالة 's':
		حالة 'S':
			𐡄𐡍 (seen_seconds++)
				أرجع -1.0;
			multiplier = SECONDS;
			اكسر;
		حالة 'm':
		حالة 'M':
			multiplier = MINUTES;
			اكسر;
		حالة 'h':
		حالة 'H':
			multiplier = HOURS;
			اكسر;
		حالة 'd':
		حالة 'D':
			multiplier = DAYS;
			اكسر;
		حالة 'w':
		حالة 'W':
			multiplier = WEEKS;
			اكسر;
		افتراضي:
			أرجع -1.0;
		}

		/* Special handling if this was a decimal */
		𐡄𐡍 (memchr(start_p, '.', endp - start_p) != عدم) {
			/* Decimal point present */
			𐡄𐡍 (multiplier > 1.0)
				أرجع -1.0; /* No fractionals for non-seconds */
			/* For seconds, ensure digits follow */
			𐡄𐡍 (!isdigit((unsigned حرف)*(endp - 1)))
				أرجع -1.0;
		}

		total_sec += val * multiplier;

		𐡄𐡍 (*p != '\0')
			p++;
	}
	أرجع total_sec;
}

/*
 * Same as convtime_double() above but fractional seconds are ignored.
 * Return -1 if time string is invalid.
 */
صحيح
convtime(ثابت حرف *s)
{
	مزدوج sec_val;

	𐡄𐡍 ((sec_val = convtime_double(s)) < 0.0)
		أرجع -1;

	/* Check for overflow into int */
	𐡄𐡍 (sec_val < 0 || sec_val > INT_MAX)
		أرجع -1;

	أرجع (صحيح)sec_val;
}

#define TF_BUFS	8
#define TF_LEN	9

ثابت حرف *
fmt_timeframe(time_t t)
{
	حرف		*buf;
	ساكن حرف	 tfbuf[TF_BUFS][TF_LEN];	/* ring buffer */
	ساكن صحيح	 idx = 0;
	unsigned صحيح	 sec, min, hrs, day;
	unsigned long long	week;

	buf = tfbuf[idx++];
	𐡄𐡍 (idx == TF_BUFS)
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

	𐡄𐡍 (week > 0)
		snprintf(buf, TF_LEN, "%02lluw%01ud%02uh", week, day, hrs);
	وإلا 𐡄𐡍 (day > 0)
		snprintf(buf, TF_LEN, "%01ud%02uh%02um", day, hrs, min);
	وإلا
		snprintf(buf, TF_LEN, "%02u:%02u:%02u", hrs, min, sec);

	أرجع (buf);
}

/*
 * Returns a standardized host+port identifier string.
 * Caller must free returned string.
 */
حرف *
put_host_port(ثابت حرف *host, u_short port)
{
	حرف *hoststr;

	𐡄𐡍 (port == 0 || port == SSH_DEFAULT_PORT)
		أرجع(xstrdup(host));
	𐡄𐡍 (asprintf(&hoststr, "[%s]:%d", host, (صحيح)port) == -1)
		fatal("put_host_port: asprintf: %s", strerror(errno));
	debug3("put_host_port: %s", hoststr);
	أرجع hoststr;
}

/*
 * Search for next delimiter between hostnames/addresses and ports.
 * Argument may be modified (for termination).
 * Returns *cp if parsing succeeds.
 * *cp is set to the start of the next field, if one was found.
 * The delimiter char, if present, is stored in delim.
 * If this is the last field, *cp is set to NULL.
 */
حرف *
hpdelim2(حرف **cp, حرف *delim)
{
	حرف *s, *old;

	𐡄𐡍 (cp == عدم || *cp == عدم)
		أرجع عدم;

	old = s = *cp;
	𐡄𐡍 (*s == '[') {
		𐡄𐡍 ((s = strchr(s, ']')) == عدم)
			أرجع عدم;
		وإلا
			s++;
	} وإلا 𐡄𐡍 ((s = strpbrk(s, ":/")) == عدم)
		s = *cp + strlen(*cp); /* skip to end (see first case below) */

	بدل (*s) {
	حالة '\0':
		*cp = عدم;	/* no more fields*/
		اكسر;

	حالة ':':
	حالة '/':
		𐡄𐡍 (delim != عدم)
			*delim = *s;
		*s = '\0';	/* terminate */
		*cp = s + 1;
		اكسر;

	افتراضي:
		أرجع عدم;
	}

	أرجع old;
}

/* The common case: only accept colon as delimiter. */
حرف *
hpdelim(حرف **cp)
{
	حرف *r, delim = '\0';

	r =  hpdelim2(cp, &delim);
	𐡄𐡍 (delim == '/')
		أرجع عدم;
	أرجع r;
}

حرف *
cleanhostname(حرف *host)
{
	𐡄𐡍 (*host == '[' && host[strlen(host) - 1] == ']') {
		host[strlen(host) - 1] = '\0';
		أرجع (host + 1);
	} وإلا
		أرجع host;
}

حرف *
colon(حرف *cp)
{
	صحيح flag = 0;

	𐡄𐡍 (*cp == ':')		/* Leading colon is part of file name. */
		أرجع عدم;
	𐡄𐡍 (*cp == '[')
		flag = 1;

	لكل (; *cp; ++cp) {
		𐡄𐡍 (*cp == '@' && *(cp+1) == '[')
			flag = 1;
		𐡄𐡍 (*cp == ']' && *(cp+1) == ':' && flag)
			أرجع (cp+1);
		𐡄𐡍 (*cp == ':' && !flag)
			أرجع (cp);
		𐡄𐡍 (*cp == '/')
			أرجع عدم;
	}
	أرجع عدم;
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
صحيح
parse_user_host_path(ثابت حرف *s, حرف **userp, حرف **hostp, حرف **pathp)
{
	حرف *user = عدم, *host = عدم, *path = عدم;
	حرف *sdup, *tmp;
	صحيح ret = -1;

	𐡄𐡍 (userp != عدم)
		*userp = عدم;
	𐡄𐡍 (hostp != عدم)
		*hostp = عدم;
	𐡄𐡍 (pathp != عدم)
		*pathp = عدم;

	sdup = xstrdup(s);

	/* Check for remote syntax: [user@]host:[path] */
	𐡄𐡍 ((tmp = colon(sdup)) == عدم)
		اذهب out;

	/* Extract optional path */
	*tmp++ = '\0';
	𐡄𐡍 (*tmp == '\0')
		tmp = ".";
	path = xstrdup(tmp);

	/* Extract optional user and mandatory host */
	tmp = strrchr(sdup, '@');
	𐡄𐡍 (tmp != عدم) {
		*tmp++ = '\0';
		host = xstrdup(cleanhostname(tmp));
		𐡄𐡍 (*sdup != '\0')
			user = xstrdup(sdup);
	} وإلا {
		host = xstrdup(cleanhostname(sdup));
		user = عدم;
	}

	/* Success */
	𐡄𐡍 (userp != عدم) {
		*userp = user;
		user = عدم;
	}
	𐡄𐡍 (hostp != عدم) {
		*hostp = host;
		host = عدم;
	}
	𐡄𐡍 (pathp != عدم) {
		*pathp = path;
		path = عدم;
	}
	ret = 0;
out:
	حرر(sdup);
	حرر(user);
	حرر(host);
	حرر(path);
	أرجع ret;
}

/*
 * Parse a [user@]host[:port] string.
 * Caller must free returned user and host.
 * Any of the pointer return arguments may be NULL (useful for syntax checking).
 * If user was not specified then *userp will be set to NULL.
 * If port was not specified then *portp will be -1.
 * Returns 0 on success, -1 on failure.
 */
صحيح
parse_user_host_port(ثابت حرف *s, حرف **userp, حرف **hostp, صحيح *portp)
{
	حرف *sdup, *cp, *tmp;
	حرف *user = عدم, *host = عدم;
	صحيح port = -1, ret = -1;

	𐡄𐡍 (userp != عدم)
		*userp = عدم;
	𐡄𐡍 (hostp != عدم)
		*hostp = عدم;
	𐡄𐡍 (portp != عدم)
		*portp = -1;

	𐡄𐡍 ((sdup = tmp = strdup(s)) == عدم)
		أرجع -1;
	/* Extract optional username */
	𐡄𐡍 ((cp = strrchr(tmp, '@')) != عدم) {
		*cp = '\0';
		𐡄𐡍 (*tmp == '\0')
			اذهب out;
		𐡄𐡍 ((user = strdup(tmp)) == عدم)
			اذهب out;
		tmp = cp + 1;
	}
	/* Extract mandatory hostname */
	𐡄𐡍 ((cp = hpdelim(&tmp)) == عدم || *cp == '\0')
		اذهب out;
	host = xstrdup(cleanhostname(cp));
	/* Convert and verify optional port */
	𐡄𐡍 (tmp != عدم && *tmp != '\0') {
		𐡄𐡍 ((port = a2port(tmp)) <= 0)
			اذهب out;
	}
	/* Success */
	𐡄𐡍 (userp != عدم) {
		*userp = user;
		user = عدم;
	}
	𐡄𐡍 (hostp != عدم) {
		*hostp = host;
		host = عدم;
	}
	𐡄𐡍 (portp != عدم)
		*portp = port;
	ret = 0;
 out:
	حرر(sdup);
	حرر(user);
	حرر(host);
	أرجع ret;
}

/*
 * Converts a two-byte hex string to decimal.
 * Returns the decimal value or -1 for invalid input.
 */
ساكن صحيح
hexchar(ثابت حرف *s)
{
	unsigned حرف result[2];
	صحيح i;

	لكل (i = 0; i < 2; i++) {
		𐡄𐡍 (s[i] >= '0' && s[i] <= '9')
			result[i] = (unsigned حرف)(s[i] - '0');
		وإلا 𐡄𐡍 (s[i] >= 'a' && s[i] <= 'f')
			result[i] = (unsigned حرف)(s[i] - 'a') + 10;
		وإلا 𐡄𐡍 (s[i] >= 'A' && s[i] <= 'F')
			result[i] = (unsigned حرف)(s[i] - 'A') + 10;
		وإلا
			أرجع -1;
	}
	أرجع (result[0] << 4) | result[1];
}

/*
 * Decode an url-encoded string.
 * Returns a newly allocated string on success or NULL on failure.
 */
ساكن حرف *
urldecode(ثابت حرف *src)
{
	حرف *ret, *dst;
	صحيح ch;
	size_t srclen;

	𐡄𐡍 ((srclen = strlen(src)) >= SIZE_MAX)
		أرجع عدم;
	ret = xmalloc(srclen + 1);
	لكل (dst = ret; *src != '\0'; src++) {
		بدل (*src) {
		حالة '+':
			*dst++ = ' ';
			اكسر;
		حالة '%':
			/* note: don't allow \0 characters */
			𐡄𐡍 (!isxdigit((unsigned حرف)src[1]) ||
			    !isxdigit((unsigned حرف)src[2]) ||
			    (ch = hexchar(src + 1)) == -1 || ch == 0) {
				حرر(ret);
				أرجع عدم;
			}
			*dst++ = ch;
			src += 2;
			اكسر;
		افتراضي:
			*dst++ = *src;
			اكسر;
		}
	}
	*dst = '\0';

	أرجع ret;
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
صحيح
parse_uri(ثابت حرف *scheme, ثابت حرف *uri, حرف **userp, حرف **hostp,
    صحيح *portp, حرف **pathp)
{
	حرف *uridup, *cp, *tmp, ch;
	حرف *user = عدم, *host = عدم, *path = عدم;
	صحيح port = -1, ret = -1;
	size_t len;

	len = strlen(scheme);
	𐡄𐡍 (strncmp(uri, scheme, len) != 0 || strncmp(uri + len, "://", 3) != 0)
		أرجع 1;
	uri += len + 3;

	𐡄𐡍 (userp != عدم)
		*userp = عدم;
	𐡄𐡍 (hostp != عدم)
		*hostp = عدم;
	𐡄𐡍 (portp != عدم)
		*portp = -1;
	𐡄𐡍 (pathp != عدم)
		*pathp = عدم;

	uridup = tmp = xstrdup(uri);

	/* Extract optional ssh-info (username + connection params) */
	𐡄𐡍 ((cp = strchr(tmp, '@')) != عدم) {
		حرف *delim;

		*cp = '\0';
		/* Extract username and connection params */
		𐡄𐡍 ((delim = strchr(tmp, ';')) != عدم) {
			/* Just ignore connection params for now */
			*delim = '\0';
		}
		𐡄𐡍 (*tmp == '\0') {
			/* Empty username */
			اذهب out;
		}
		𐡄𐡍 ((user = urldecode(tmp)) == عدم)
			اذهب out;
		tmp = cp + 1;
	}

	/* Extract mandatory hostname */
	𐡄𐡍 ((cp = hpdelim2(&tmp, &ch)) == عدم || *cp == '\0')
		اذهب out;
	host = xstrdup(cleanhostname(cp));
	𐡄𐡍 (!valid_domain(host, 0, عدم))
		اذهب out;

	𐡄𐡍 (tmp != عدم && *tmp != '\0') {
		𐡄𐡍 (ch == ':') {
			/* Convert and verify port. */
			𐡄𐡍 ((cp = strchr(tmp, '/')) != عدم)
				*cp = '\0';
			𐡄𐡍 ((port = a2port(tmp)) <= 0)
				اذهب out;
			tmp = cp ? cp + 1 : عدم;
		}
		𐡄𐡍 (tmp != عدم && *tmp != '\0') {
			/* Extract optional path */
			𐡄𐡍 ((path = urldecode(tmp)) == عدم)
				اذهب out;
		}
	}

	/* Success */
	𐡄𐡍 (userp != عدم) {
		*userp = user;
		user = عدم;
	}
	𐡄𐡍 (hostp != عدم) {
		*hostp = host;
		host = عدم;
	}
	𐡄𐡍 (portp != عدم)
		*portp = port;
	𐡄𐡍 (pathp != عدم) {
		*pathp = path;
		path = عدم;
	}
	ret = 0;
 out:
	حرر(uridup);
	حرر(user);
	حرر(host);
	حرر(path);
	أرجع ret;
}

/* function to assist building execv() arguments */
فراغ
addargs(arglist *args, حرف *fmt, ...)
{
	va_list ap;
	حرف *cp;
	u_int nalloc;
	صحيح r;

	va_start(ap, fmt);
	r = vasprintf(&cp, fmt, ap);
	va_end(ap);
	𐡄𐡍 (r == -1)
		fatal_f("argument too long");

	nalloc = args->nalloc;
	𐡄𐡍 (args->list == عدم) {
		nalloc = 32;
		args->num = 0;
	} وإلا 𐡄𐡍 (args->num > (256 * 1024))
		fatal_f("too many arguments");
	وإلا 𐡄𐡍 (args->num >= args->nalloc)
		fatal_f("arglist corrupt");
	وإلا 𐡄𐡍 (args->num+2 >= nalloc)
		nalloc *= 2;

	args->list = xrecallocarray(args->list, args->nalloc,
	    nalloc, حجم(حرف *));
	args->nalloc = nalloc;
	args->list[args->num++] = cp;
	args->list[args->num] = عدم;
}

فراغ
replacearg(arglist *args, u_int which, حرف *fmt, ...)
{
	va_list ap;
	حرف *cp;
	صحيح r;

	va_start(ap, fmt);
	r = vasprintf(&cp, fmt, ap);
	va_end(ap);
	𐡄𐡍 (r == -1)
		fatal_f("argument too long");
	𐡄𐡍 (args->list == عدم || args->num >= args->nalloc)
		fatal_f("arglist corrupt");

	𐡄𐡍 (which >= args->num)
		fatal_f("tried to replace invalid arg %d >= %d",
		    which, args->num);
	حرر(args->list[which]);
	args->list[which] = cp;
}

فراغ
freeargs(arglist *args)
{
	u_int i;

	𐡄𐡍 (args == عدم)
		أرجع;
	𐡄𐡍 (args->list != عدم && args->num < args->nalloc) {
		لكل (i = 0; i < args->num; i++)
			حرر(args->list[i]);
		حرر(args->list);
	}
	args->nalloc = args->num = 0;
	args->list = عدم;
}

/*
 * Expands tildes in the file name.  Returns data allocated by xmalloc.
 * Warning: this calls getpw*.
 */
صحيح
tilde_expand(ثابت حرف *filename, uid_t uid, حرف **retp)
{
	حرف *ocopy = عدم, *copy, *s = عدم;
	ثابت حرف *path = عدم, *user = عدم;
	بنية passwd *pw;
	size_t len;
	صحيح ret = -1, r, slash;

	*retp = عدم;
	𐡄𐡍 (*filename != '~') {
		*retp = xstrdup(filename);
		أرجع 0;
	}
	ocopy = copy = xstrdup(filename + 1);

	𐡄𐡍 (*copy == '\0')				/* ~ */
		path = عدم;
	وإلا 𐡄𐡍 (*copy == '/') {
		copy += strspn(copy, "/");
		𐡄𐡍 (*copy == '\0')
			path = عدم;			/* ~/ */
		وإلا
			path = copy;			/* ~/path */
	} وإلا {
		user = copy;
		𐡄𐡍 ((path = strchr(copy, '/')) != عدم) {
			copy[path - copy] = '\0';
			path++;
			path += strspn(path, "/");
			𐡄𐡍 (*path == '\0')		/* ~user/ */
				path = عدم;
			/* else				 ~user/path */
		}
		/* else					~user */
	}
	𐡄𐡍 (user != عدم) {
		𐡄𐡍 ((pw = getpwnam(user)) == عدم) {
			error_f("No such user %s", user);
			اذهب out;
		}
	} وإلا 𐡄𐡍 ((pw = getpwuid(uid)) == عدم) {
		error_f("No such uid %ld", (long)uid);
		اذهب out;
	}

	/* Make sure directory has a trailing '/' */
	slash = (len = strlen(pw->pw_dir)) == 0 || pw->pw_dir[len - 1] != '/';

	𐡄𐡍 ((r = xasprintf(&s, "%s%s%s", pw->pw_dir,
	    slash ? "/" : "", path != عدم ? path : "")) <= 0) {
		error_f("xasprintf failed");
		اذهب out;
	}
	𐡄𐡍 (r >= PATH_MAX) {
		error_f("Path too long");
		اذهب out;
	}
	/* success */
	ret = 0;
	*retp = s;
	s = عدم;
 out:
	حرر(s);
	حرر(ocopy);
	أرجع ret;
}

حرف *
tilde_expand_filename(ثابت حرف *filename, uid_t uid)
{
	حرف *ret;

	𐡄𐡍 (tilde_expand(filename, uid, &ret) != 0)
		cleanup_exit(255);
	أرجع ret;
}

/*
 * Expand a string with a set of %[char] escapes and/or ${ENVIRONMENT}
 * substitutions.  A number of escapes may be specified as
 * (char *escape_chars, char *replacement) pairs. The list must be terminated
 * by a NULL escape_char. Returns replaced string in memory allocated by
 * xmalloc which the caller must free.
 */
ساكن حرف *
vdollar_percent_expand(صحيح *parseerror, صحيح dollar, صحيح percent,
    ثابت حرف *string, va_list ap)
{
#define EXPAND_MAX_KEYS	64
	u_int num_keys = 0, i;
	بنية {
		ثابت حرف *key;
		ثابت حرف *repl;
	} keys[EXPAND_MAX_KEYS];
	بنية sshbuf *buf;
	صحيح r, missingvar = 0;
	حرف *ret = عدم, *var, *varend, *val;
	size_t len;

	𐡄𐡍 ((buf = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	𐡄𐡍 (parseerror == عدم)
		fatal_f("null parseerror arg");
	*parseerror = 1;

	/* Gather keys if we're doing percent expansion. */
	𐡄𐡍 (percent) {
		لكل (num_keys = 0; num_keys < EXPAND_MAX_KEYS; num_keys++) {
			keys[num_keys].key = va_arg(ap, حرف *);
			𐡄𐡍 (keys[num_keys].key == عدم)
				اكسر;
			keys[num_keys].repl = va_arg(ap, حرف *);
			𐡄𐡍 (keys[num_keys].repl == عدم) {
				fatal_f("NULL replacement for token %s",
				    keys[num_keys].key);
			}
		}
		𐡄𐡍 (num_keys == EXPAND_MAX_KEYS && va_arg(ap, حرف *) != عدم)
			fatal_f("too many keys");
		𐡄𐡍 (num_keys == 0)
			fatal_f("percent expansion without token list");
	}

	/* Expand string */
	لكل (i = 0; *string != '\0'; string++) {
		/* Optionally process ${ENVIRONMENT} expansions. */
		𐡄𐡍 (dollar && string[0] == '$' && string[1] == '{') {
			string += 2;  /* skip over '${' */
			𐡄𐡍 ((varend = strchr(string, '}')) == عدم) {
				error_f("environment variable '%s' missing "
				    "closing '}'", string);
				اذهب out;
			}
			len = varend - string;
			𐡄𐡍 (len == 0) {
				error_f("zero-length environment variable");
				اذهب out;
			}
			var = xmalloc(len + 1);
			(فراغ)strlcpy(var, string, len + 1);
			𐡄𐡍 ((val = getenv(var)) == عدم) {
				error_f("env var ${%s} has no value", var);
				missingvar = 1;
			} وإلا {
				debug3_f("expand ${%s} -> '%s'", var, val);
				𐡄𐡍 ((r = sshbuf_put(buf, val, strlen(val))) !=0)
					fatal_fr(r, "sshbuf_put ${}");
			}
			حرر(var);
			string += len;
			استمر;
		}

		/*
		 * Process percent expansions if we have a list of TOKENs.
		 * If we're not doing percent expansion everything just gets
		 * appended here.
		 */
		𐡄𐡍 (*string != '%' || !percent) {
 append:
			𐡄𐡍 ((r = sshbuf_put_u8(buf, *string)) != 0)
				fatal_fr(r, "sshbuf_put_u8 %%");
			استمر;
		}
		string++;
		/* %% case */
		𐡄𐡍 (*string == '%')
			اذهب append;
		𐡄𐡍 (*string == '\0') {
			error_f("invalid format");
			اذهب out;
		}
		لكل (i = 0; i < num_keys; i++) {
			𐡄𐡍 (strchr(keys[i].key, *string) != عدم) {
				𐡄𐡍 ((r = sshbuf_put(buf, keys[i].repl,
				    strlen(keys[i].repl))) != 0)
					fatal_fr(r, "sshbuf_put %%-repl");
				اكسر;
			}
		}
		𐡄𐡍 (i >= num_keys) {
			error_f("unknown key %%%c", *string);
			اذهب out;
		}
	}
	𐡄𐡍 (!missingvar && (ret = sshbuf_dup_string(buf)) == عدم)
		fatal_f("sshbuf_dup_string failed");
	*parseerror = 0;
 out:
	sshbuf_free(buf);
	أرجع *parseerror ? عدم : ret;
#undef EXPAND_MAX_KEYS
}

/*
 * Expand only environment variables.
 * Note that although this function is variadic like the other similar
 * functions, any such arguments will be unused.
 */

حرف *
dollar_expand(صحيح *parseerr, ثابت حرف *string, ...)
{
	حرف *ret;
	صحيح err;
	va_list ap;

	va_start(ap, string);
	ret = vdollar_percent_expand(&err, 1, 0, string, ap);
	va_end(ap);
	𐡄𐡍 (parseerr != عدم)
		*parseerr = err;
	أرجع ret;
}

/*
 * Returns expanded string or NULL if a specified environment variable is
 * not defined, or calls fatal if the string is invalid.
 */
حرف *
percent_expand(ثابت حرف *string, ...)
{
	حرف *ret;
	صحيح err;
	va_list ap;

	va_start(ap, string);
	ret = vdollar_percent_expand(&err, 0, 1, string, ap);
	va_end(ap);
	𐡄𐡍 (err)
		fatal_f("failed");
	أرجع ret;
}

/*
 * Returns expanded string or NULL if a specified environment variable is
 * not defined, or calls fatal if the string is invalid.
 */
حرف *
percent_dollar_expand(ثابت حرف *string, ...)
{
	حرف *ret;
	صحيح err;
	va_list ap;

	va_start(ap, string);
	ret = vdollar_percent_expand(&err, 1, 1, string, ap);
	va_end(ap);
	𐡄𐡍 (err)
		fatal_f("failed");
	أرجع ret;
}

صحيح
tun_open(صحيح tun, صحيح mode, حرف **ifname)
{
#𐡄𐡍 defined(CUSTOM_SYS_TUN_OPEN)
	أرجع (sys_tun_open(tun, mode, ifname));
#وإلاإذا defined(SSH_TUN_OPENBSD)
	بنية ifreq ifr;
	حرف name[100];
	صحيح fd = -1, sock;
	ثابت حرف *tunbase = "tun";

	𐡄𐡍 (ifname != عدم)
		*ifname = عدم;

	𐡄𐡍 (mode == SSH_TUNMODE_ETHERNET)
		tunbase = "tap";

	/* Open the tunnel device */
	𐡄𐡍 (tun <= SSH_TUNID_MAX) {
		snprintf(name, حجم(name), "/dev/%s%d", tunbase, tun);
		fd = open(name, O_RDWR);
	} وإلا 𐡄𐡍 (tun == SSH_TUNID_ANY) {
		لكل (tun = 100; tun >= 0; tun--) {
			snprintf(name, حجم(name), "/dev/%s%d",
			    tunbase, tun);
			𐡄𐡍 ((fd = open(name, O_RDWR)) >= 0)
				اكسر;
		}
	} وإلا {
		debug_f("invalid tunnel %u", tun);
		أرجع -1;
	}

	𐡄𐡍 (fd == -1) {
		debug_f("%s open: %s", name, strerror(errno));
		أرجع -1;
	}

	debug_f("%s mode %d fd %d", name, mode, fd);

	/* Bring interface up if it is not already */
	snprintf(ifr.ifr_name, حجم(ifr.ifr_name), "%s%d", tunbase, tun);
	𐡄𐡍 ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
		اذهب failed;

	𐡄𐡍 (ioctl(sock, SIOCGIFFLAGS, &ifr) == -1) {
		debug_f("get interface %s flags: %s", ifr.ifr_name,
		    strerror(errno));
		اذهب failed;
	}

	𐡄𐡍 (!(ifr.ifr_flags & IFF_UP)) {
		ifr.ifr_flags |= IFF_UP;
		𐡄𐡍 (ioctl(sock, SIOCSIFFLAGS, &ifr) == -1) {
			debug_f("activate interface %s: %s", ifr.ifr_name,
			    strerror(errno));
			اذهب failed;
		}
	}

	𐡄𐡍 (ifname != عدم)
		*ifname = xstrdup(ifr.ifr_name);

	close(sock);
	أرجع fd;

 failed:
	𐡄𐡍 (fd >= 0)
		close(fd);
	𐡄𐡍 (sock >= 0)
		close(sock);
	أرجع -1;
#وإلا
	error("Tunnel interfaces are not supported on this platform");
	أرجع (-1);
#endif
}

فراغ
sanitise_stdfd(فراغ)
{
	صحيح nullfd, dupfd;

	𐡄𐡍 ((nullfd = dupfd = open(_PATH_DEVNULL, O_RDWR)) == -1) {
		fprintf(stderr, "Couldn't open /dev/null: %s\n",
		    strerror(errno));
		exit(1);
	}
	طالما (++dupfd <= STDERR_FILENO) {
		/* Only populate closed fds. */
		𐡄𐡍 (fcntl(dupfd, F_GETFL) == -1 && errno == EBADF) {
			𐡄𐡍 (dup2(nullfd, dupfd) == -1) {
				fprintf(stderr, "dup2: %s\n", strerror(errno));
				exit(1);
			}
		}
	}
	𐡄𐡍 (nullfd > STDERR_FILENO)
		close(nullfd);
}

حرف *
tohex(ثابت فراغ *vp, size_t l)
{
	ثابت u_char *p = (ثابت u_char *)vp;
	حرف b[3], *r;
	size_t i, hl;

	𐡄𐡍 (l > 65536)
		أرجع xstrdup("tohex: length > 65536");

	hl = l * 2 + 1;
	r = xcalloc(1, hl);
	لكل (i = 0; i < l; i++) {
		snprintf(b, حجم(b), "%02x", p[i]);
		strlcat(r, b, hl);
	}
	أرجع (r);
}

/*
 * Extend string *sp by the specified format. If *sp is not NULL (or empty),
 * then the separator 'sep' will be prepended before the formatted arguments.
 * Extended strings are heap allocated.
 */
فراغ
xextendf(حرف **sp, ثابت حرف *sep, ثابت حرف *fmt, ...)
{
	va_list ap;
	حرف *tmp1, *tmp2;

	va_start(ap, fmt);
	xvasprintf(&tmp1, fmt, ap);
	va_end(ap);

	𐡄𐡍 (*sp == عدم || **sp == '\0') {
		حرر(*sp);
		*sp = tmp1;
		أرجع;
	}
	xasprintf(&tmp2, "%s%s%s", *sp, sep == عدم ? "" : sep, tmp1);
	حرر(tmp1);
	حرر(*sp);
	*sp = tmp2;
}


uint64_t
get_u64(ثابت فراغ *vp)
{
	ثابت u_char *p = (ثابت u_char *)vp;
	uint64_t v;

	v  = (uint64_t)p[0] << 56;
	v |= (uint64_t)p[1] << 48;
	v |= (uint64_t)p[2] << 40;
	v |= (uint64_t)p[3] << 32;
	v |= (uint64_t)p[4] << 24;
	v |= (uint64_t)p[5] << 16;
	v |= (uint64_t)p[6] << 8;
	v |= (uint64_t)p[7];

	أرجع (v);
}

uint32_t
get_u32(ثابت فراغ *vp)
{
	ثابت u_char *p = (ثابت u_char *)vp;
	uint32_t v;

	v  = (uint32_t)p[0] << 24;
	v |= (uint32_t)p[1] << 16;
	v |= (uint32_t)p[2] << 8;
	v |= (uint32_t)p[3];

	أرجع (v);
}

uint32_t
get_u32_le(ثابت فراغ *vp)
{
	ثابت u_char *p = (ثابت u_char *)vp;
	uint32_t v;

	v  = (uint32_t)p[0];
	v |= (uint32_t)p[1] << 8;
	v |= (uint32_t)p[2] << 16;
	v |= (uint32_t)p[3] << 24;

	أرجع (v);
}

uint16_t
get_u16(ثابت فراغ *vp)
{
	ثابت u_char *p = (ثابت u_char *)vp;
	uint16_t v;

	v  = (uint16_t)p[0] << 8;
	v |= (uint16_t)p[1];

	أرجع (v);
}

فراغ
put_u64(فراغ *vp, uint64_t v)
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

فراغ
put_u32(فراغ *vp, uint32_t v)
{
	u_char *p = (u_char *)vp;

	p[0] = (u_char)(v >> 24) & 0xff;
	p[1] = (u_char)(v >> 16) & 0xff;
	p[2] = (u_char)(v >> 8) & 0xff;
	p[3] = (u_char)v & 0xff;
}

فراغ
put_u32_le(فراغ *vp, uint32_t v)
{
	u_char *p = (u_char *)vp;

	p[0] = (u_char)v & 0xff;
	p[1] = (u_char)(v >> 8) & 0xff;
	p[2] = (u_char)(v >> 16) & 0xff;
	p[3] = (u_char)(v >> 24) & 0xff;
}

فراغ
put_u16(فراغ *vp, uint16_t v)
{
	u_char *p = (u_char *)vp;

	p[0] = (u_char)(v >> 8) & 0xff;
	p[1] = (u_char)v & 0xff;
}

فراغ
ms_subtract_diff(بنية timeval *start, صحيح *ms)
{
	بنية timeval diff, finish;

	monotime_tv(&finish);
	timersub(&finish, start, &diff);
	*ms -= (diff.tv_sec * 1000) + (diff.tv_usec / 1000);
}

فراغ
ms_to_timespec(بنية timespec *ts, صحيح ms)
{
	𐡄𐡍 (ms < 0)
		ms = 0;
	ts->tv_sec = ms / 1000;
	ts->tv_nsec = (ms % 1000) * 1000 * 1000;
}

فراغ
monotime_ts(بنية timespec *ts)
{
	بنية timeval tv;
#𐡄𐡍 defined(HAVE_CLOCK_GETTIME) && (defined(CLOCK_BOOTTIME) || \
    defined(CLOCK_MONOTONIC) || defined(CLOCK_REALTIME))
	ساكن صحيح gettime_failed = 0;

	𐡄𐡍 (!gettime_failed) {
# ifdef CLOCK_BOOTTIME
		𐡄𐡍 (clock_gettime(CLOCK_BOOTTIME, ts) == 0)
			أرجع;
# endif /* CLOCK_BOOTTIME */
# ifdef CLOCK_MONOTONIC
		𐡄𐡍 (clock_gettime(CLOCK_MONOTONIC, ts) == 0)
			أرجع;
# endif /* CLOCK_MONOTONIC */
# ifdef CLOCK_REALTIME
		/* Not monotonic, but we're almost out of options here. */
		𐡄𐡍 (clock_gettime(CLOCK_REALTIME, ts) == 0)
			أرجع;
# endif /* CLOCK_REALTIME */
		debug3("clock_gettime: %s", strerror(errno));
		gettime_failed = 1;
	}
#endif /* HAVE_CLOCK_GETTIME && (BOOTTIME || MONOTONIC || REALTIME) */
	gettimeofday(&tv, عدم);
	ts->tv_sec = tv.tv_sec;
	ts->tv_nsec = (long)tv.tv_usec * 1000;
}

فراغ
monotime_tv(بنية timeval *tv)
{
	بنية timespec ts;

	monotime_ts(&ts);
	tv->tv_sec = ts.tv_sec;
	tv->tv_usec = ts.tv_nsec / 1000;
}

time_t
monotime(فراغ)
{
	بنية timespec ts;

	monotime_ts(&ts);
	أرجع (ts.tv_sec);
}

مزدوج
monotime_double(فراغ)
{
	بنية timespec ts;

	monotime_ts(&ts);
	أرجع (مزدوج)ts.tv_sec + (مزدوج)ts.tv_nsec / 1000000000.0;
}

فراغ
bandwidth_limit_init(بنية bwlimit *bw, uint64_t kbps, size_t buflen)
{
	bw->buflen = buflen;
	bw->rate = kbps;
	bw->thresh = buflen;
	bw->lamt = 0;
	timerclear(&bw->bwstart);
	timerclear(&bw->bwend);
}

/* Callback from read/write loop to insert bandwidth-limiting delays */
فراغ
bandwidth_limit(بنية bwlimit *bw, size_t read_len)
{
	uint64_t waitlen;
	بنية timespec ts, rm;

	bw->lamt += read_len;
	𐡄𐡍 (!timerisset(&bw->bwstart)) {
		monotime_tv(&bw->bwstart);
		أرجع;
	}
	𐡄𐡍 (bw->lamt < bw->thresh)
		أرجع;

	monotime_tv(&bw->bwend);
	timersub(&bw->bwend, &bw->bwstart, &bw->bwend);
	𐡄𐡍 (!timerisset(&bw->bwend))
		أرجع;

	bw->lamt *= 8;
	waitlen = (مزدوج)1000000L * bw->lamt / bw->rate;

	bw->bwstart.tv_sec = waitlen / 1000000L;
	bw->bwstart.tv_usec = waitlen % 1000000L;

	𐡄𐡍 (timercmp(&bw->bwstart, &bw->bwend, >)) {
		timersub(&bw->bwstart, &bw->bwend, &bw->bwend);

		/* Adjust the wait time */
		𐡄𐡍 (bw->bwend.tv_sec) {
			bw->thresh /= 2;
			𐡄𐡍 (bw->thresh < bw->buflen / 4)
				bw->thresh = bw->buflen / 4;
		} وإلا 𐡄𐡍 (bw->bwend.tv_usec < 10000) {
			bw->thresh *= 2;
			𐡄𐡍 (bw->thresh > bw->buflen * 8)
				bw->thresh = bw->buflen * 8;
		}

		TIMEVAL_TO_TIMESPEC(&bw->bwend, &ts);
		طالما (nanosleep(&ts, &rm) == -1) {
			𐡄𐡍 (errno != EINTR)
				اكسر;
			ts = rm;
		}
	}

	bw->lamt = 0;
	monotime_tv(&bw->bwstart);
}

/* Make a template filename for mk[sd]temp() */
فراغ
mktemp_proto(حرف *s, size_t len)
{
	ثابت حرف *tmpdir;
	صحيح r;

	𐡄𐡍 ((tmpdir = getenv("TMPDIR")) != عدم) {
		r = snprintf(s, len, "%s/ssh-XXXXXXXXXXXX", tmpdir);
		𐡄𐡍 (r > 0 && (size_t)r < len)
			أرجع;
	}
	r = snprintf(s, len, "/tmp/ssh-XXXXXXXXXXXX");
	𐡄𐡍 (r < 0 || (size_t)r >= len)
		fatal_f("template string too short");
}

ساكن ثابت بنية {
	ثابت حرف *name;
	صحيح value;
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
	{ عدم, -1 }
};

صحيح
parse_ipqos(ثابت حرف *cp)
{
	ثابت حرف *errstr;
	u_int i;
	صحيح val;

	𐡄𐡍 (cp == عدم)
		أرجع -1;
	لكل (i = 0; ipqos[i].name != عدم; i++) {
		𐡄𐡍 (strcasecmp(cp, ipqos[i].name) == 0)
			أرجع ipqos[i].value;
	}
	/* Try parsing as an integer */
	val = (صحيح)strtonum(cp, 0, 255, &errstr);
	𐡄𐡍 (errstr)
		أرجع -1;
	أرجع val;
}

ثابت حرف *
iptos2str(صحيح iptos)
{
	صحيح i;
	ساكن حرف iptos_str[حجم "0xff"];

	لكل (i = 0; ipqos[i].name != عدم; i++) {
		𐡄𐡍 (ipqos[i].value == iptos)
			أرجع ipqos[i].name;
	}
	snprintf(iptos_str, حجم iptos_str, "0x%02x", iptos);
	أرجع iptos_str;
}

فراغ
lowercase(حرف *s)
{
	لكل (; *s; s++)
		*s = tolower((u_char)*s);
}

صحيح
unix_listener(ثابت حرف *path, صحيح backlog, صحيح unlink_first)
{
	بنية sockaddr_un sunaddr;
	صحيح saved_errno, sock;

	memset(&sunaddr, 0, حجم(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	𐡄𐡍 (strlcpy(sunaddr.sun_path, path,
	    حجم(sunaddr.sun_path)) >= حجم(sunaddr.sun_path)) {
		error_f("path \"%s\" too long for Unix domain socket", path);
		errno = ENAMETOOLONG;
		أرجع -1;
	}

	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	𐡄𐡍 (sock == -1) {
		saved_errno = errno;
		error_f("socket: %.100s", strerror(errno));
		errno = saved_errno;
		أرجع -1;
	}
	𐡄𐡍 (unlink_first == 1) {
		𐡄𐡍 (unlink(path) != 0 && errno != ENOENT)
			error("unlink(%s): %.100s", path, strerror(errno));
	}
	𐡄𐡍 (bind(sock, (بنية sockaddr *)&sunaddr, حجم(sunaddr)) == -1) {
		saved_errno = errno;
		error_f("cannot bind to path %s: %s", path, strerror(errno));
		close(sock);
		errno = saved_errno;
		أرجع -1;
	}
	𐡄𐡍 (listen(sock, backlog) == -1) {
		saved_errno = errno;
		error_f("cannot listen on path %s: %s", path, strerror(errno));
		close(sock);
		unlink(path);
		errno = saved_errno;
		أرجع -1;
	}
	أرجع sock;
}

فراغ
sock_set_v6only(صحيح s)
{
#𐡄𐡍 defined(IPV6_V6ONLY) && !defined(__OpenBSD__)
	صحيح on = 1;

	debug3_f("set socket %d IPV6_V6ONLY", s);
	𐡄𐡍 (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &on, حجم(on)) == -1)
		error("setsockopt IPV6_V6ONLY: %s", strerror(errno));
#endif
}

/*
 * Compares two strings that maybe be NULL. Returns non-zero if strings
 * are both NULL or are identical, returns zero otherwise.
 */
ساكن صحيح
strcmp_maybe_null(ثابت حرف *a, ثابت حرف *b)
{
	𐡄𐡍 ((a == عدم && b != عدم) || (a != عدم && b == عدم))
		أرجع 0;
	𐡄𐡍 (a != عدم && strcmp(a, b) != 0)
		أرجع 0;
	أرجع 1;
}

/*
 * Compare two forwards, returning non-zero if they are identical or
 * zero otherwise.
 */
صحيح
forward_equals(ثابت بنية Forward *a, ثابت بنية Forward *b)
{
	𐡄𐡍 (strcmp_maybe_null(a->listen_host, b->listen_host) == 0)
		أرجع 0;
	𐡄𐡍 (a->listen_port != b->listen_port)
		أرجع 0;
	𐡄𐡍 (strcmp_maybe_null(a->listen_path, b->listen_path) == 0)
		أرجع 0;
	𐡄𐡍 (strcmp_maybe_null(a->connect_host, b->connect_host) == 0)
		أرجع 0;
	𐡄𐡍 (a->connect_port != b->connect_port)
		أرجع 0;
	𐡄𐡍 (strcmp_maybe_null(a->connect_path, b->connect_path) == 0)
		أرجع 0;
	/* allocated_port and handle are not checked */
	أرجع 1;
}

/* returns port number, FWD_PERMIT_ANY_PORT or -1 on error */
صحيح
permitopen_port(ثابت حرف *p)
{
	صحيح port;

	𐡄𐡍 (strcmp(p, "*") == 0)
		أرجع FWD_PERMIT_ANY_PORT;
	𐡄𐡍 ((port = a2port(p)) > 0)
		أرجع port;
	أرجع -1;
}

/* returns 1 if process is already daemonized, 0 otherwise */
صحيح
daemonized(فراغ)
{
	صحيح fd;

	𐡄𐡍 ((fd = open(_PATH_TTY, O_RDONLY | O_NOCTTY)) >= 0) {
		close(fd);
		أرجع 0;	/* have controlling terminal */
	}
	𐡄𐡍 (getppid() != 1)
		أرجع 0;	/* parent is not init */
	𐡄𐡍 (getsid(0) != getpid())
		أرجع 0;	/* not session leader */
	debug3("already daemonized");
	أرجع 1;
}

/*
 * Splits 's' into an argument vector. Handles quoted string and basic
 * escape characters (\\, \", \'). Caller must free the argument vector
 * and its members.
 */
صحيح
argv_split(ثابت حرف *s, صحيح *argcp, حرف ***argvp, صحيح terminate_on_comment)
{
	صحيح r = SSH_ERR_INTERNAL_ERROR;
	صحيح argc = 0, quote, i, j;
	حرف *arg, **argv = xcalloc(1, حجم(*argv));

	*argvp = عدم;
	*argcp = 0;

	لكل (i = 0; s[i] != '\0'; i++) {
		/* Skip leading whitespace */
		𐡄𐡍 (s[i] == ' ' || s[i] == '\t')
			استمر;
		𐡄𐡍 (terminate_on_comment && s[i] == '#')
			اكسر;
		/* Start of a token */
		quote = 0;

		argv = xreallocarray(argv, (argc + 2), حجم(*argv));
		arg = argv[argc++] = xcalloc(1, strlen(s + i) + 1);
		argv[argc] = عدم;

		/* Copy the token in, removing escapes */
		لكل (j = 0; s[i] != '\0'; i++) {
			𐡄𐡍 (s[i] == '\\') {
				𐡄𐡍 (s[i + 1] == '\'' ||
				    s[i + 1] == '\"' ||
				    s[i + 1] == '\\' ||
				    (quote == 0 && s[i + 1] == ' ')) {
					i++; /* Skip '\' */
					arg[j++] = s[i];
				} وإلا {
					/* Unrecognised escape */
					arg[j++] = s[i];
				}
			} وإلا 𐡄𐡍 (quote == 0 && (s[i] == ' ' || s[i] == '\t'))
				اكسر; /* done */
			وإلا 𐡄𐡍 (quote == 0 && (s[i] == '\"' || s[i] == '\''))
				quote = s[i]; /* quote start */
			وإلا 𐡄𐡍 (quote != 0 && s[i] == quote)
				quote = 0; /* quote end */
			وإلا
				arg[j++] = s[i];
		}
		𐡄𐡍 (s[i] == '\0') {
			𐡄𐡍 (quote != 0) {
				/* Ran out of string looking for close quote */
				r = SSH_ERR_INVALID_FORMAT;
				اذهب out;
			}
			اكسر;
		}
	}
	/* Success */
	*argcp = argc;
	*argvp = argv;
	argc = 0;
	argv = عدم;
	r = 0;
 out:
	𐡄𐡍 (argc != 0 && argv != عدم) {
		لكل (i = 0; i < argc; i++)
			حرر(argv[i]);
		حرر(argv);
	}
	أرجع r;
}

/*
 * Reassemble an argument vector into a string, quoting and escaping as
 * necessary. Caller must free returned string.
 */
حرف *
argv_assemble(صحيح argc, حرف **argv)
{
	صحيح i, j, ws, r;
	حرف c, *ret;
	بنية sshbuf *buf, *arg;

	𐡄𐡍 ((buf = sshbuf_new()) == عدم || (arg = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");

	لكل (i = 0; i < argc; i++) {
		ws = 0;
		sshbuf_reset(arg);
		لكل (j = 0; argv[i][j] != '\0'; j++) {
			r = 0;
			c = argv[i][j];
			بدل (c) {
			حالة ' ':
			حالة '\t':
				ws = 1;
				r = sshbuf_put_u8(arg, c);
				اكسر;
			حالة '\\':
			حالة '\'':
			حالة '"':
				𐡄𐡍 ((r = sshbuf_put_u8(arg, '\\')) != 0)
					اكسر;
				/* FALLTHROUGH */
			افتراضي:
				r = sshbuf_put_u8(arg, c);
				اكسر;
			}
			𐡄𐡍 (r != 0)
				fatal_fr(r, "sshbuf_put_u8");
		}
		𐡄𐡍 ((i != 0 && (r = sshbuf_put_u8(buf, ' ')) != 0) ||
		    (ws != 0 && (r = sshbuf_put_u8(buf, '"')) != 0) ||
		    (r = sshbuf_putb(buf, arg)) != 0 ||
		    (ws != 0 && (r = sshbuf_put_u8(buf, '"')) != 0))
			fatal_fr(r, "assemble");
	}
	𐡄𐡍 ((ret = malloc(sshbuf_len(buf) + 1)) == عدم)
		fatal_f("malloc failed");
	memcpy(ret, sshbuf_ptr(buf), sshbuf_len(buf));
	ret[sshbuf_len(buf)] = '\0';
	sshbuf_free(buf);
	sshbuf_free(arg);
	أرجع ret;
}

حرف *
argv_next(صحيح *argcp, حرف ***argvp)
{
	حرف *ret = (*argvp)[0];

	𐡄𐡍 (*argcp > 0 && ret != عدم) {
		(*argcp)--;
		(*argvp)++;
	}
	أرجع ret;
}

فراغ
argv_consume(صحيح *argcp)
{
	*argcp = 0;
}

فراغ
argv_free(حرف **av, صحيح ac)
{
	صحيح i;

	𐡄𐡍 (av == عدم)
		أرجع;
	لكل (i = 0; i < ac; i++)
		حرر(av[i]);
	حرر(av);
}

/* Returns 0 if pid exited cleanly, non-zero otherwise */
صحيح
exited_cleanly(pid_t pid, ثابت حرف *tag, ثابت حرف *cmd, صحيح quiet)
{
	صحيح status;

	طالما (waitpid(pid, &status, 0) == -1) {
		𐡄𐡍 (errno != EINTR) {
			error("%s waitpid: %s", tag, strerror(errno));
			أرجع -1;
		}
	}
	𐡄𐡍 (WIFSIGNALED(status)) {
		error("%s %s exited on signal %d", tag, cmd, WTERMSIG(status));
		أرجع -1;
	} وإلا 𐡄𐡍 (WEXITSTATUS(status) != 0) {
		do_log2(quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_INFO,
		    "%s %s failed, status %d", tag, cmd, WEXITSTATUS(status));
		أرجع -1;
	}
	أرجع 0;
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
صحيح
safe_path(ثابت حرف *name, بنية stat *stp, ثابت حرف *pw_dir,
    uid_t uid, حرف *err, size_t errlen)
{
	حرف buf[PATH_MAX], buf2[PATH_MAX], homedir[PATH_MAX];
	حرف *cp;
	صحيح comparehome = 0;
	بنية stat st;

	𐡄𐡍 (realpath(name, buf) == عدم) {
		snprintf(err, errlen, "realpath %s failed: %s", name,
		    strerror(errno));
		أرجع -1;
	}
	𐡄𐡍 (pw_dir != عدم && realpath(pw_dir, homedir) != عدم)
		comparehome = 1;

	𐡄𐡍 (!S_ISREG(stp->st_mode)) {
		snprintf(err, errlen, "%s is not a regular file", buf);
		أرجع -1;
	}
	𐡄𐡍 ((!platform_sys_dir_uid(stp->st_uid) && stp->st_uid != uid) ||
	    (stp->st_mode & 022) != 0) {
		snprintf(err, errlen, "bad ownership or modes for file %s",
		    buf);
		أرجع -1;
	}

	/* for each component of the canonical path, walking upwards */
	لكل (;;) {
		/*
		 * POSIX allows dirname to modify its argument and return a
		 * pointer into it, so make a copy to avoid overlapping strlcpy.
		 */
		strlcpy(buf2, buf, حجم(buf2));
		𐡄𐡍 ((cp = dirname(buf2)) == عدم) {
			snprintf(err, errlen, "dirname() failed");
			أرجع -1;
		}
		strlcpy(buf, cp, حجم(buf));

		𐡄𐡍 (stat(buf, &st) == -1 ||
		    (!platform_sys_dir_uid(st.st_uid) && st.st_uid != uid) ||
		    (st.st_mode & 022) != 0) {
			snprintf(err, errlen,
			    "bad ownership or modes for directory %s", buf);
			أرجع -1;
		}

		/* If are past the homedir then we can stop */
		𐡄𐡍 (comparehome && strcmp(homedir, buf) == 0)
			اكسر;

		/*
		 * dirname should always complete with a "/" path,
		 * but we can be paranoid and check for "." too
		 */
		𐡄𐡍 ((strcmp("/", buf) == 0) || (strcmp(".", buf) == 0))
			اكسر;
	}
	أرجع 0;
}

/*
 * Version of safe_path() that accepts an open file descriptor to
 * avoid races.
 *
 * Returns 0 on success and -1 on failure
 */
صحيح
safe_path_fd(صحيح fd, ثابت حرف *file, بنية passwd *pw,
    حرف *err, size_t errlen)
{
	بنية stat st;

	/* check the open file to avoid races */
	𐡄𐡍 (fstat(fd, &st) == -1) {
		snprintf(err, errlen, "cannot stat file %s: %s",
		    file, strerror(errno));
		أرجع -1;
	}
	أرجع safe_path(file, &st, pw->pw_dir, pw->pw_uid, err, errlen);
}

/*
 * Sets the value of the given variable in the environment.  If the variable
 * already exists, its value is overridden.
 */
فراغ
child_set_env(حرف ***envp, u_int *envsizep, ثابت حرف *name,
	ثابت حرف *value)
{
	حرف **env;
	u_int envsize;
	u_int i, namelen;

	𐡄𐡍 (strchr(name, '=') != عدم) {
		error("Invalid environment variable \"%.100s\"", name);
		أرجع;
	}

	/*
	 * If we're passed an uninitialized list, allocate a single null
	 * entry before continuing.
	 */
	𐡄𐡍 ((*envp == عدم) != (*envsizep == 0))
		fatal_f("environment size mismatch");
	𐡄𐡍 (*envp == عدم && *envsizep == 0) {
		*envp = xmalloc(حجم(حرف *));
		*envp[0] = عدم;
		*envsizep = 1;
	}

	/*
	 * Find the slot where the value should be stored.  If the variable
	 * already exists, we reuse the slot; otherwise we append a new slot
	 * at the end of the array, expanding if necessary.
	 */
	env = *envp;
	namelen = strlen(name);
	لكل (i = 0; env[i]; i++)
		𐡄𐡍 (strncmp(env[i], name, namelen) == 0 && env[i][namelen] == '=')
			اكسر;
	𐡄𐡍 (env[i]) {
		/* Reuse the slot. */
		حرر(env[i]);
	} وإلا {
		/* New variable.  Expand if necessary. */
		envsize = *envsizep;
		𐡄𐡍 (i >= envsize - 1) {
			𐡄𐡍 (envsize >= 1000)
				fatal("child_set_env: too many env vars");
			envsize += 50;
			env = (*envp) = xreallocarray(env, envsize, حجم(حرف *));
			*envsizep = envsize;
		}
		/* Need to set the NULL pointer at end of array beyond the new slot. */
		env[i + 1] = عدم;
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
صحيح
valid_domain(حرف *name, صحيح makelower, ثابت حرف **errstr)
{
	size_t i, l = strlen(name);
	u_char c, last = '\0';
	ساكن حرف errbuf[256];

	𐡄𐡍 (l == 0) {
		strlcpy(errbuf, "empty domain name", حجم(errbuf));
		اذهب bad;
	}
	𐡄𐡍 (!isalpha((u_char)name[0]) && !isdigit((u_char)name[0]) &&
	   name[0] != '_' /* technically invalid, but common */) {
		snprintf(errbuf, حجم(errbuf), "domain name \"%.100s\" "
		    "starts with invalid character", name);
		اذهب bad;
	}
	لكل (i = 0; i < l; i++) {
		c = tolower((u_char)name[i]);
		𐡄𐡍 (makelower)
			name[i] = (حرف)c;
		𐡄𐡍 (last == '.' && c == '.') {
			snprintf(errbuf, حجم(errbuf), "domain name "
			    "\"%.100s\" contains consecutive separators", name);
			اذهب bad;
		}
		𐡄𐡍 (c != '.' && c != '-' && !isalnum(c) &&
		    c != '_') /* technically invalid, but common */ {
			snprintf(errbuf, حجم(errbuf), "domain name "
			    "\"%.100s\" contains invalid characters", name);
			اذهب bad;
		}
		last = c;
	}
	𐡄𐡍 (name[l - 1] == '.')
		name[l - 1] = '\0';
	𐡄𐡍 (errstr != عدم)
		*errstr = عدم;
	أرجع 1;
bad:
	𐡄𐡍 (errstr != عدم)
		*errstr = errbuf;
	أرجع 0;
}

/*
 * Verify that a environment variable name (not including initial '$') is
 * valid; consisting of one or more alphanumeric or underscore characters only.
 * Returns 1 on valid, 0 otherwise.
 */
صحيح
valid_env_name(ثابت حرف *name)
{
	ثابت حرف *cp;

	𐡄𐡍 (name[0] == '\0')
		أرجع 0;
	لكل (cp = name; *cp != '\0'; cp++) {
		𐡄𐡍 (!isalnum((u_char)*cp) && *cp != '_')
			أرجع 0;
	}
	أرجع 1;
}

ثابت حرف *
atoi_err(ثابت حرف *nptr, صحيح *val)
{
	ثابت حرف *errstr = عدم;

	𐡄𐡍 (nptr == عدم || *nptr == '\0')
		أرجع "missing";
	*val = strtonum(nptr, 0, INT_MAX, &errstr);
	أرجع errstr;
}

صحيح
parse_absolute_time(ثابت حرف *s, uint64_t *tp)
{
	بنية tm tm;
	time_t tt;
	حرف buf[32], *fmt;
	ثابت حرف *cp;
	size_t l;
	صحيح is_utc = 0;

	*tp = 0;

	l = strlen(s);
	𐡄𐡍 (l > 1 && strcasecmp(s + l - 1, "Z") == 0) {
		is_utc = 1;
		l--;
	} وإلا 𐡄𐡍 (l > 3 && strcasecmp(s + l - 3, "UTC") == 0) {
		is_utc = 1;
		l -= 3;
	}
	/*
	 * POSIX strptime says "The application shall ensure that there
	 * is white-space or other non-alphanumeric characters between
	 * any two conversion specifications" so arrange things this way.
	 */
	بدل (l) {
	حالة 8: /* YYYYMMDD */
		fmt = "%Y-%m-%d";
		snprintf(buf, حجم(buf), "%.4s-%.2s-%.2s", s, s + 4, s + 6);
		اكسر;
	حالة 12: /* YYYYMMDDHHMM */
		fmt = "%Y-%m-%dT%H:%M";
		snprintf(buf, حجم(buf), "%.4s-%.2s-%.2sT%.2s:%.2s",
		    s, s + 4, s + 6, s + 8, s + 10);
		اكسر;
	حالة 14: /* YYYYMMDDHHMMSS */
		fmt = "%Y-%m-%dT%H:%M:%S";
		snprintf(buf, حجم(buf), "%.4s-%.2s-%.2sT%.2s:%.2s:%.2s",
		    s, s + 4, s + 6, s + 8, s + 10, s + 12);
		اكسر;
	افتراضي:
		أرجع SSH_ERR_INVALID_FORMAT;
	}

	memset(&tm, 0, حجم(tm));
	𐡄𐡍 ((cp = strptime(buf, fmt, &tm)) == عدم || *cp != '\0')
		أرجع SSH_ERR_INVALID_FORMAT;
	𐡄𐡍 (is_utc) {
		tm.tm_wday = -1;	/* sentinel for error */
		𐡄𐡍 ((tt = timegm(&tm)) == -1 && tm.tm_wday == -1)
			أرجع SSH_ERR_INVALID_FORMAT;
	} وإلا {
		tm.tm_wday = -1;	/* sentinel for error */
		tm.tm_isdst = -1;	/* mktime decides DST */
		𐡄𐡍 ((tt = mktime(&tm)) == -1 && tm.tm_wday == -1)
			أرجع SSH_ERR_INVALID_FORMAT;
	}
	/* success */
	*tp = (uint64_t)tt;
	أرجع 0;
}

فراغ
format_absolute_time(uint64_t t, حرف *buf, size_t len)
{
	time_t tt = t > SSH_TIME_T_MAX ? SSH_TIME_T_MAX : t;
	بنية tm tm;

	𐡄𐡍 (localtime_r(&tt, &tm) == عدم)
		strlcpy(buf, "UNKNOWN-TIME", len);
	وإلا
		strftime(buf, len, "%Y-%m-%dT%H:%M:%S", &tm);
}

/*
 * Parse a "pattern=interval" clause (e.g. a ChannelTimeout).
 * Returns 0 on success or non-zero on failure.
 * Caller must free *typep.
 */
صحيح
parse_pattern_interval(ثابت حرف *s, حرف **typep, مزدوج *secsp)
{
	حرف *cp, *sdup;
	مزدوج secs;

	𐡄𐡍 (typep != عدم)
		*typep = عدم;
	𐡄𐡍 (secsp != عدم)
		*secsp = 0;
	𐡄𐡍 (s == عدم)
		أرجع -1;
	sdup = xstrdup(s);

	𐡄𐡍 ((cp = strchr(sdup, '=')) == عدم || cp == sdup) {
		حرر(sdup);
		أرجع -1;
	}
	*cp++ = '\0';
	𐡄𐡍 ((secs = convtime_double(cp)) < 0.0) {
		حرر(sdup);
		أرجع -1;
	}
	/* success */
	𐡄𐡍 (typep != عدم)
		*typep = xstrdup(sdup);
	𐡄𐡍 (secsp != عدم)
		*secsp = secs;
	حرر(sdup);
	أرجع 0;
}

/* check if path is absolute */
صحيح
path_absolute(ثابت حرف *path)
{
	أرجع (*path == '/') ? 1 : 0;
}

فراغ
skip_space(حرف **cpp)
{
	حرف *cp;

	لكل (cp = *cpp; *cp == ' ' || *cp == '\t'; cp++)
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
صحيح
opt_flag(ثابت حرف *opt, صحيح allow_negate, ثابت حرف **optsp)
{
	size_t opt_len = strlen(opt);
	ثابت حرف *opts = *optsp;
	صحيح negate = 0;

	𐡄𐡍 (allow_negate && strncasecmp(opts, "no-", 3) == 0) {
		opts += 3;
		negate = 1;
	}
	𐡄𐡍 (strncasecmp(opts, opt, opt_len) == 0) {
		*optsp = opts + opt_len;
		أرجع negate ? 0 : 1;
	}
	أرجع -1;
}

حرف *
opt_dequote(ثابت حرف **sp, ثابت حرف **errstrp)
{
	ثابت حرف *s = *sp;
	حرف *ret;
	size_t i;

	*errstrp = عدم;
	𐡄𐡍 (*s != '"') {
		*errstrp = "missing start quote";
		أرجع عدم;
	}
	s++;
	𐡄𐡍 ((ret = malloc(strlen((s)) + 1)) == عدم) {
		*errstrp = "memory allocation failed";
		أرجع عدم;
	}
	لكل (i = 0; *s != '\0' && *s != '"';) {
		𐡄𐡍 (s[0] == '\\' && s[1] == '"')
			s++;
		ret[i++] = *s++;
	}
	𐡄𐡍 (*s == '\0') {
		*errstrp = "missing end quote";
		حرر(ret);
		أرجع عدم;
	}
	ret[i] = '\0';
	s++;
	*sp = s;
	أرجع ret;
}

صحيح
opt_match(ثابت حرف **opts, ثابت حرف *term)
{
	𐡄𐡍 (strncasecmp((*opts), term, strlen(term)) == 0 &&
	    (*opts)[strlen(term)] == '=') {
		*opts += strlen(term) + 1;
		أرجع 1;
	}
	أرجع 0;
}

فراغ
opt_array_append2(ثابت حرف *file, ثابت صحيح line, ثابت حرف *directive,
    حرف ***array, صحيح **iarray, u_int *lp, ثابت حرف *s, صحيح i)
{

	𐡄𐡍 (*lp >= INT_MAX)
		fatal("%s line %d: Too many %s entries", file, line, directive);

	𐡄𐡍 (iarray != عدم) {
		*iarray = xrecallocarray(*iarray, *lp, *lp + 1,
		    حجم(**iarray));
		(*iarray)[*lp] = i;
	}

	*array = xrecallocarray(*array, *lp, *lp + 1, حجم(**array));
	(*array)[*lp] = xstrdup(s);
	(*lp)++;
}

فراغ
opt_array_append(ثابت حرف *file, ثابت صحيح line, ثابت حرف *directive,
    حرف ***array, u_int *lp, ثابت حرف *s)
{
	opt_array_append2(file, line, directive, array, عدم, lp, s, 0);
}

فراغ
opt_array_free2(حرف **array, صحيح **iarray, u_int l)
{
	u_int i;

	𐡄𐡍 (array == عدم || l == 0)
		أرجع;
	لكل (i = 0; i < l; i++)
		حرر(array[i]);
	حرر(array);
	حرر(iarray);
}

sshsig_t
ssh_signal(صحيح signum, sshsig_t handler)
{
	بنية sigaction sa, osa;

	/* mask all other signals while in handler */
	memset(&sa, 0, حجم(sa));
	sa.sa_handler = handler;
	sigfillset(&sa.sa_mask);
#𐡄𐡍 defined(SA_RESTART) && !defined(NO_SA_RESTART)
	𐡄𐡍 (signum != SIGALRM)
		sa.sa_flags = SA_RESTART;
#endif
	𐡄𐡍 (sigaction(signum, &sa, &osa) == -1) {
		debug3("sigaction(%s): %s", strsignal(signum), strerror(errno));
		أرجع SIG_ERR;
	}
	أرجع osa.sa_handler;
}

صحيح
stdfd_devnull(صحيح do_stdin, صحيح do_stdout, صحيح do_stderr)
{
	صحيح devnull, ret = 0;

	𐡄𐡍 ((devnull = open(_PATH_DEVNULL, O_RDWR)) == -1) {
		error_f("open %s: %s", _PATH_DEVNULL,
		    strerror(errno));
		أرجع -1;
	}
	𐡄𐡍 ((do_stdin && dup2(devnull, STDIN_FILENO) == -1) ||
	    (do_stdout && dup2(devnull, STDOUT_FILENO) == -1) ||
	    (do_stderr && dup2(devnull, STDERR_FILENO) == -1)) {
		error_f("dup2: %s", strerror(errno));
		ret = -1;
	}
	𐡄𐡍 (devnull > STDERR_FILENO)
		close(devnull);
	أرجع ret;
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
subprocess(ثابت حرف *tag, ثابت حرف *command,
    صحيح ac, حرف **av, FILE **child, u_int flags,
    بنية passwd *pw, privdrop_fn *drop_privs, privrestore_fn *restore_privs)
{
	FILE *f = عدم;
	بنية stat st;
	صحيح fd, devnull, p[2], i;
	pid_t pid;
	حرف *cp, errmsg[512];
	u_int nenv = 0;
	حرف **env = عدم;

	/* If dropping privs, then must specify user and restore function */
	𐡄𐡍 (drop_privs != عدم && (pw == عدم || restore_privs == عدم)) {
		error("%s: inconsistent arguments", tag); /* XXX fatal? */
		أرجع 0;
	}
	𐡄𐡍 (pw == عدم && (pw = getpwuid(getuid())) == عدم) {
		error("%s: no user for current uid", tag);
		أرجع 0;
	}
	𐡄𐡍 (child != عدم)
		*child = عدم;

	debug3_f("%s command \"%s\" running as %s (flags 0x%x)",
	    tag, command, pw->pw_name, flags);

	/* Check consistency */
	𐡄𐡍 ((flags & SSH_SUBPROCESS_STDOUT_DISCARD) != 0 &&
	    (flags & SSH_SUBPROCESS_STDOUT_CAPTURE) != 0) {
		error_f("inconsistent flags");
		أرجع 0;
	}
	𐡄𐡍 (((flags & SSH_SUBPROCESS_STDOUT_CAPTURE) == 0) != (child == عدم)) {
		error_f("inconsistent flags/output");
		أرجع 0;
	}

	/*
	 * If executing an explicit binary, then verify the it exists
	 * and appears safe-ish to execute
	 */
	𐡄𐡍 (!path_absolute(av[0])) {
		error("%s path is not absolute", tag);
		أرجع 0;
	}
	𐡄𐡍 (drop_privs != عدم)
		drop_privs(pw);
	𐡄𐡍 (stat(av[0], &st) == -1) {
		error("Could not stat %s \"%s\": %s", tag,
		    av[0], strerror(errno));
		اذهب restore_return;
	}
	𐡄𐡍 ((flags & SSH_SUBPROCESS_UNSAFE_PATH) == 0 &&
	    safe_path(av[0], &st, عدم, 0, errmsg, حجم(errmsg)) != 0) {
		error("Unsafe %s \"%s\": %s", tag, av[0], errmsg);
		اذهب restore_return;
	}
	/* Prepare to keep the child's stdout if requested */
	𐡄𐡍 (pipe(p) == -1) {
		error("%s: pipe: %s", tag, strerror(errno));
 restore_return:
		𐡄𐡍 (restore_privs != عدم)
			restore_privs();
		أرجع 0;
	}
	𐡄𐡍 (restore_privs != عدم)
		restore_privs();

	بدل ((pid = fork())) {
	حالة -1: /* error */
		error("%s: fork: %s", tag, strerror(errno));
		close(p[0]);
		close(p[1]);
		أرجع 0;
	حالة 0: /* child */
		/* Prepare a minimal environment for the child. */
		𐡄𐡍 ((flags & SSH_SUBPROCESS_PRESERVE_ENV) == 0) {
			nenv = 5;
			env = xcalloc(حجم(*env), nenv);
			child_set_env(&env, &nenv, "PATH", _PATH_STDPATH);
			child_set_env(&env, &nenv, "USER", pw->pw_name);
			child_set_env(&env, &nenv, "LOGNAME", pw->pw_name);
			child_set_env(&env, &nenv, "HOME", pw->pw_dir);
			𐡄𐡍 ((cp = getenv("LANG")) != عدم)
				child_set_env(&env, &nenv, "LANG", cp);
		}

		لكل (i = 1; i < NSIG; i++)
			ssh_signal(i, SIG_DFL);

		𐡄𐡍 ((devnull = open(_PATH_DEVNULL, O_RDWR)) == -1) {
			error("%s: open %s: %s", tag, _PATH_DEVNULL,
			    strerror(errno));
			_exit(1);
		}
		𐡄𐡍 (dup2(devnull, STDIN_FILENO) == -1) {
			error("%s: dup2: %s", tag, strerror(errno));
			_exit(1);
		}

		/* Set up stdout as requested; leave stderr in place for now. */
		fd = -1;
		𐡄𐡍 ((flags & SSH_SUBPROCESS_STDOUT_CAPTURE) != 0)
			fd = p[1];
		وإلا 𐡄𐡍 ((flags & SSH_SUBPROCESS_STDOUT_DISCARD) != 0)
			fd = devnull;
		𐡄𐡍 (fd != -1 && dup2(fd, STDOUT_FILENO) == -1) {
			error("%s: dup2: %s", tag, strerror(errno));
			_exit(1);
		}
		closefrom(STDERR_FILENO + 1);

		𐡄𐡍 (geteuid() == 0 &&
		    initgroups(pw->pw_name, pw->pw_gid) == -1) {
			error("%s: initgroups(%s, %u): %s", tag,
			    pw->pw_name, (u_int)pw->pw_gid, strerror(errno));
			_exit(1);
		}
		𐡄𐡍 (setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) == -1) {
			error("%s: setresgid %u: %s", tag, (u_int)pw->pw_gid,
			    strerror(errno));
			_exit(1);
		}
		𐡄𐡍 (setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) == -1) {
			error("%s: setresuid %u: %s", tag, (u_int)pw->pw_uid,
			    strerror(errno));
			_exit(1);
		}
		/* stdin is pointed to /dev/null at this point */
		𐡄𐡍 ((flags & SSH_SUBPROCESS_STDOUT_DISCARD) != 0 &&
		    dup2(STDIN_FILENO, STDERR_FILENO) == -1) {
			error("%s: dup2: %s", tag, strerror(errno));
			_exit(1);
		}
		𐡄𐡍 (env != عدم)
			execve(av[0], av, env);
		وإلا
			execv(av[0], av);
		error("%s %s \"%s\": %s", tag, env == عدم ? "execv" : "execve",
		    command, strerror(errno));
		_exit(127);
	افتراضي: /* parent */
		اكسر;
	}

	close(p[1]);
	𐡄𐡍 ((flags & SSH_SUBPROCESS_STDOUT_CAPTURE) == 0)
		close(p[0]);
	وإلا 𐡄𐡍 ((f = fdopen(p[0], "r")) == عدم) {
		error("%s: fdopen: %s", tag, strerror(errno));
		close(p[0]);
		/* Don't leave zombie child */
		kill(pid, SIGTERM);
		طالما (waitpid(pid, عدم, 0) == -1 && errno == EINTR)
			;
		أرجع 0;
	}
	/* Success */
	debug3_f("%s pid %ld", tag, (long)pid);
	𐡄𐡍 (child != عدم)
		*child = f;
	أرجع pid;
}

ثابت حرف *
lookup_env_in_list(ثابت حرف *env, حرف * ثابت *envs, size_t nenvs)
{
	size_t i, envlen;

	envlen = strlen(env);
	لكل (i = 0; i < nenvs; i++) {
		𐡄𐡍 (strncmp(envs[i], env, envlen) == 0 &&
		    envs[i][envlen] == '=') {
			أرجع envs[i] + envlen + 1;
		}
	}
	أرجع عدم;
}

ثابت حرف *
lookup_setenv_in_list(ثابت حرف *env, حرف * ثابت *envs, size_t nenvs)
{
	حرف *name, *cp;
	ثابت حرف *ret;

	name = xstrdup(env);
	𐡄𐡍 ((cp = strchr(name, '=')) == عدم) {
		حرر(name);
		أرجع عدم; /* not env=val */
	}
	*cp = '\0';
	ret = lookup_env_in_list(name, envs, nenvs);
	حرر(name);
	أرجع ret;
}

/*
 * Helpers for managing poll(2)/ppoll(2) timeouts
 * Will remember the earliest deadline and return it for use in poll/ppoll.
 */

/* Initialise a poll/ppoll timeout with an indefinite deadline */
فراغ
ptimeout_init(بنية timespec *pt)
{
	/*
	 * Deliberately invalid for ppoll(2).
	 * Will be converted to NULL in ptimeout_get_tspec() later.
	 */
	pt->tv_sec = -1;
	pt->tv_nsec = 0;
}

/* Specify a poll/ppoll deadline of at most 'sec' seconds */
فراغ
ptimeout_deadline_sec(بنية timespec *pt, long sec)
{
	𐡄𐡍 (pt->tv_sec == -1 || pt->tv_sec >= sec) {
		pt->tv_sec = sec;
		pt->tv_nsec = 0;
	}
}

/* Specify a poll/ppoll deadline of at most 'p' (timespec) */
ساكن فراغ
ptimeout_deadline_tsp(بنية timespec *pt, بنية timespec *p)
{
	𐡄𐡍 (pt->tv_sec == -1 || timespeccmp(pt, p, >=))
		*pt = *p;
}

/* Specify a poll/ppoll deadline of at most 'ms' milliseconds */
فراغ
ptimeout_deadline_ms(بنية timespec *pt, long ms)
{
	بنية timespec p;

	p.tv_sec = ms / 1000;
	p.tv_nsec = (ms % 1000) * 1000000;
	ptimeout_deadline_tsp(pt, &p);
}

/* Specify a poll/ppoll deadline of at most 'sec' seconds (double) */
فراغ
ptimeout_deadline_sec_double(بنية timespec *pt, مزدوج sec)
{
	بنية timespec t;

	memset(&t, 0, حجم(t));
	𐡄𐡍 ((int64_t)sec >= SSH_TIME_T_MAX)
		t.tv_sec = SSH_TIME_T_MAX;
	وإلا 𐡄𐡍 (sec > 0) {
		t.tv_sec = sec;
		t.tv_nsec = (sec - (مزدوج)t.tv_sec) * 1000000000.0;
	}
	ptimeout_deadline_tsp(pt, &t);
}

/* Specify a poll/ppoll deadline at wall clock monotime 'when' (timespec) */
فراغ
ptimeout_deadline_monotime_tsp(بنية timespec *pt, بنية timespec *when)
{
	بنية timespec now, t;

	monotime_ts(&now);

	𐡄𐡍 (timespeccmp(&now, when, >=)) {
		/* 'when' is now or in the past. Timeout ASAP */
		pt->tv_sec = 0;
		pt->tv_nsec = 0;
	} وإلا {
		timespecsub(when, &now, &t);
		ptimeout_deadline_tsp(pt, &t);
	}
}

/* Specify a poll/ppoll deadline at wall clock monotime 'when' (double) */
فراغ
ptimeout_deadline_monotime_double(بنية timespec *pt, مزدوج when)
{
	ptimeout_deadline_sec_double(pt, when - monotime_double());
}

/* Specify a poll/ppoll deadline at wall clock monotime 'when' */
فراغ
ptimeout_deadline_monotime(بنية timespec *pt, time_t when)
{
	بنية timespec t;

	t.tv_sec = when;
	t.tv_nsec = 0;
	ptimeout_deadline_monotime_tsp(pt, &t);
}

/* Get a poll(2) timeout value in milliseconds */
صحيح
ptimeout_get_ms(بنية timespec *pt)
{
	𐡄𐡍 (pt->tv_sec == -1)
		أرجع -1;
	𐡄𐡍 (pt->tv_sec >= (INT_MAX - (pt->tv_nsec / 1000000)) / 1000)
		أرجع INT_MAX;
	أرجع (pt->tv_sec * 1000) + (pt->tv_nsec / 1000000);
}

/* Get a ppoll(2) timeout value as a timespec pointer */
بنية timespec *
ptimeout_get_tsp(بنية timespec *pt)
{
	أرجع pt->tv_sec == -1 ? عدم : pt;
}

/* Returns non-zero if a timeout has been set (i.e. is not indefinite) */
صحيح
ptimeout_isset(بنية timespec *pt)
{
	أرجع pt->tv_sec != -1;
}

/*
 * Returns zero if the library at 'path' contains symbol 's', nonzero
 * otherwise.
 */
صحيح
lib_contains_symbol(ثابت حرف *path, ثابت حرف *s)
{
#ifdef HAVE_NLIST
	بنية nlist nl[2];
	صحيح ret = -1, r;

	memset(nl, 0, حجم(nl));
	nl[0].n_name = xstrdup(s);
	nl[1].n_name = عدم;
	𐡄𐡍 ((r = nlist(path, nl)) == -1) {
		error_f("nlist failed for %s", path);
		اذهب out;
	}
	𐡄𐡍 (r != 0 || nl[0].n_value == 0 || nl[0].n_type == 0) {
		error_f("library %s does not contain symbol %s", path, s);
		اذهب out;
	}
	/* success */
	ret = 0;
 out:
	حرر(nl[0].n_name);
	أرجع ret;
#وإلا /* HAVE_NLIST */
	صحيح fd, ret = -1;
	بنية stat st;
	فراغ *m = عدم;
	size_t sz = 0;

	memset(&st, 0, حجم(st));
	𐡄𐡍 ((fd = open(path, O_RDONLY)) < 0) {
		error_f("open %s: %s", path, strerror(errno));
		أرجع -1;
	}
	𐡄𐡍 (fstat(fd, &st) != 0) {
		error_f("fstat %s: %s", path, strerror(errno));
		اذهب out;
	}
	𐡄𐡍 (!S_ISREG(st.st_mode)) {
		error_f("%s is not a regular file", path);
		اذهب out;
	}
	𐡄𐡍 (st.st_size < 0 ||
	    (size_t)st.st_size < strlen(s) ||
	    st.st_size >= INT_MAX/2) {
		error_f("%s bad size %lld", path, (long long)st.st_size);
		اذهب out;
	}
	sz = (size_t)st.st_size;
	𐡄𐡍 ((m = mmap(عدم, sz, PROT_READ, MAP_PRIVATE, fd, 0)) == MAP_FAILED ||
	    m == عدم) {
		error_f("mmap %s: %s", path, strerror(errno));
		اذهب out;
	}
	𐡄𐡍 (memmem(m, sz, s, strlen(s)) == عدم) {
		error_f("%s does not contain expected string %s", path, s);
		اذهب out;
	}
	/* success */
	ret = 0;
 out:
	𐡄𐡍 (m != عدم && m != MAP_FAILED)
		munmap(m, sz);
	close(fd);
	أرجع ret;
#endif /* HAVE_NLIST */
}

صحيح
signal_is_crash(صحيح sig)
{
	بدل (sig) {
	حالة SIGSEGV:
	حالة SIGBUS:
	حالة SIGTRAP:
	حالة SIGSYS:
	حالة SIGFPE:
	حالة SIGILL:
	حالة SIGABRT:
		أرجع 1;
	}
	أرجع 0;
}

حرف *
get_homedir(فراغ)
{
	حرف *cp;
	بنية passwd *pw;

	𐡄𐡍 ((cp = getenv("HOME")) != عدم && *cp != '\0')
		أرجع xstrdup(cp);

	𐡄𐡍 ((pw = getpwuid(getuid())) != عدم && *pw->pw_dir != '\0')
		أرجع xstrdup(pw->pw_dir);

	أرجع عدم;
}

صحيح
mkdir_path(ثابت حرف *target, mode_t mode)
{
#𐡄𐡍 defined(HAVE_OPENAT) && defined(O_DIRECTORY)
	حرف *dir, *odir = عدم, *next;
	صحيح fd = AT_FDCWD, fd2, subpath_len, ret = -1;

	dir = odir = xstrdup(target);

	𐡄𐡍 (*dir == '/' &&
	    (fd = open("/", O_RDONLY|O_DIRECTORY)) == -1) {
		error_f("open(\"/\"): %s", strerror(errno));
		حرر(odir);
		أرجع -1;
	}
	/* Work through the path, component-wise */
	لكل (; dir != عدم && *dir != '\0'; dir = next) {
		𐡄𐡍 ((next = strchr(dir, '/')) != عدم)
			*(next++) = '\0';
		𐡄𐡍 (*dir == '\0')
			استمر;
		subpath_len = (next == عدم) ? INT_MAX : next - odir - 1;
		𐡄𐡍 (mkdirat(fd, dir, mode) == 0)
			debug_f("created directory %.*s", subpath_len, target);
		وإلا 𐡄𐡍 (errno != EEXIST) {
			error_f("mkdir(\"%.*s\"): %s",
			    subpath_len, target, strerror(errno));
			اذهب out;
		}

		/* descend */
		𐡄𐡍 ((fd2 = openat(fd, dir, O_RDONLY|O_DIRECTORY)) == -1) {
			error_f("open(\"%.*s\"): %s",
			    subpath_len, target, strerror(errno));
			اذهب out;
		}
		𐡄𐡍 (fd != AT_FDCWD)
			close(fd);
		fd = fd2;
	}
	/* success */
	ret = 0;
 out:
	حرر(odir);
	𐡄𐡍 (fd != AT_FDCWD)
		close(fd);
	أرجع ret;
#وإلا
	/*
	 * If we don't have openat (which was added in POSIX.1-2008), fall back
	 * to the possibly racy way.
	 */
	حرف *dir, *odir, *p, path[PATH_MAX] = "";
	صحيح ret = -1;
	size_t plen = حجم(path);

	dir = odir = xstrdup(target);

	/* If the dir is relative, start with cwd. */
	𐡄𐡍 (*dir != '/' && getcwd(path, plen) == عدم) {
		error_f("getcwd: %s", strerror(errno));
		اذهب out;
	}

	/* Work through the path, component-wise */
	طالما ((p = strsep(&dir, "/"))) {
		𐡄𐡍 (*p == '\0')
			استمر;
		𐡄𐡍 (strlcat(path, "/", plen) >= plen ||
		    strlcat(path, p, plen) >= plen)
			اذهب out;
		𐡄𐡍 (mkdir(path, mode) == 0)
			debug_f("created directory %s", path);
		وإلا 𐡄𐡍 (errno != EEXIST && errno != EISDIR) {
			error_f("mkdir(\"%s\"): %s", path, strerror(errno));
			اذهب out;
		}
	}
	/* success */
	ret = 0;
 out:
	حرر(odir);
	أرجع ret;
#endif
}
