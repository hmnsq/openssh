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
#که_تعریف_شوی SSH_TUN_OPENBSD
#ضمن <net/if.h>
#د_که_پای

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
		إذا (*t == '\n' || *t == '\r') {
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
	اندازه_t i;

	إذا ((i = مزي_اوږدوالی(s)) == 0)
		أرجع;
	افعل {
		i--;
		إذا (که_تشه((بینښه حرف)s[i]))
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
strprefix(ثابت حرف *s, ثابت حرف *مختاړی, صحيح ignorecase)
{
	اندازه_t prefixlen;

	إذا ((prefixlen = مزي_اوږدوالی(مختاړی)) == 0)
		أرجع s;
	إذا (ignorecase) {
		إذا (strncasecmp(s, مختاړی, prefixlen) != 0)
			أرجع عدم;
	} وإلا {
		إذا (مزي_پرتله(s, مختاړی, prefixlen) != 0)
			أرجع عدم;
	}
	أرجع s + prefixlen;
}

/* Append string 's' to a NULL-terminated array of strings */
فراغ
stringlist_append(حرف ***listp, ثابت حرف *s)
{
	اندازه_t i = 0;

	إذا (*listp == عدم)
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
	اندازه_t i = 0;

	إذا (list == عدم)
		أرجع;
	لكل (i = 0; list[i] != عدم; i++)
		حرر(list[i]);
	حرر(list);
}

/* set/unset filedescriptor to non-blocking */
صحيح
سېټ_nonblock(صحيح fd)
{
	صحيح val;

	val = fcntl(fd, F_GETFL);
	إذا (val == -1) {
		error("fcntl(%d, F_GETFL): %s", fd, strerror(errno));
		أرجع (-1);
	}
	إذا (val & O_NONBLOCK) {
		debug3("fd %d is O_NONBLOCK", fd);
		أرجع (0);
	}
	debug2("fd %d setting O_NONBLOCK", fd);
	val |= O_NONBLOCK;
	إذا (fcntl(fd, F_SETFL, val) == -1) {
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
	إذا (val == -1) {
		error("fcntl(%d, F_GETFL): %s", fd, strerror(errno));
		أرجع (-1);
	}
	إذا (!(val & O_NONBLOCK)) {
		debug3("fd %d is not O_NONBLOCK", fd);
		أرجع (0);
	}
	debug("fd %d clearing O_NONBLOCK", fd);
	val &= ~O_NONBLOCK;
	إذا (fcntl(fd, F_SETFL, val) == -1) {
		debug("fcntl(%d, F_SETFL, ~O_NONBLOCK): %s",
		    fd, strerror(errno));
		أرجع (-1);
	}
	أرجع (0);
}

ثابت حرف *
ssh_gai_strerror(صحيح gaierr)
{
	إذا (gaierr == EAI_SYSTEM && errno != 0)
		أرجع strerror(errno);
	أرجع gai_strerror(gaierr);
}

/* disable nagle on socket */
فراغ
سېټ_nodelay(صحيح fd)
{
	صحيح opt;
	socklen_t optlen;

	optlen = حجم opt;
	إذا (getsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, &optlen) == -1) {
		debug("getsockopt TCP_NODELAY: %.100s", strerror(errno));
		أرجع;
	}
	إذا (opt == 1) {
		debug2("fd %d is TCP_NODELAY", fd);
		أرجع;
	}
	opt = 1;
	debug2("fd %d setting TCP_NODELAY", fd);
	إذا (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, حجم opt) == -1)
		error("setsockopt TCP_NODELAY: %.100s", strerror(errno));
}

/* Allow local port reuse in TIME_WAIT */
صحيح
سېټ_reuseaddr(صحيح fd)
{
	صحيح on = 1;

	إذا (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, حجم(on)) == -1) {
		error("setsockopt SO_REUSEADDR fd %d: %s", fd, strerror(errno));
		أرجع -1;
	}
	أرجع 0;
}

/* Set TCP keepalives */
صحيح
سېټ_keepalive(صحيح fd)
{
	صحيح on = 1;

	إذا (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, حجم(on)) == -1) {
		error("setsockopt SO_KEEPALIVE fd %d: %s", fd, strerror(errno));
		أرجع -1;
	}
	أرجع 0;
}

/* Get/set routing domain */
حرف *
get_rdomain(صحيح fd)
{
#إذا defined(HAVE_SYS_GET_RDOMAIN)
	أرجع sys_get_rdomain(fd);
#وإلاإذا defined(__OpenBSD__)
	صحيح rtable;
	حرف *ret;
	socklen_t len = حجم(rtable);

	إذا (getsockopt(fd, SOL_SOCKET, SO_RTABLE, &rtable, &len) == -1) {
		error("Failed to get routing domain for fd %d: %s",
		    fd, strerror(errno));
		أرجع عدم;
	}
	xasprintf(&ret, "%d", rtable);
	أرجع ret;
#وإلا /* defined(__OpenBSD__) */
	أرجع عدم;
#د_که_پای
}

صحيح
سېټ_rdomain(صحيح fd, ثابت حرف *name)
{
#إذا defined(HAVE_SYS_سېټ_RDOMAIN)
	أرجع sys_سېټ_rdomain(fd, name);
#وإلاإذا defined(__OpenBSD__)
	صحيح rtable;
	ثابت حرف *errstr;

	إذا (name == عدم)
		أرجع 0; /* default table */

	rtable = (صحيح)strtonum(name, 0, 255, &errstr);
	إذا (errstr != عدم) {
		/* Shouldn't happen */
		error("Invalid routing domain \"%s\": %s", name, errstr);
		أرجع -1;
	}
	إذا (setsockopt(fd, SOL_SOCKET, SO_RTABLE,
	    &rtable, حجم(rtable)) == -1) {
		error("Failed to set routing domain %d on fd %d: %s",
		    rtable, fd, strerror(errno));
		أرجع -1;
	}
	أرجع 0;
#وإلا /* defined(__OpenBSD__) */
	error("Setting routing domain is not supported on this platform");
	أرجع -1;
#د_که_پای
}

صحيح
get_sock_af(صحيح fd)
{
	بنية sockaddr_storage منزل;
	socklen_t tolen = حجم(منزل);

	memset(&منزل, 0, حجم(منزل));
	إذا (getsockname(fd, (بنية sockaddr *)&منزل, &tolen) == -1)
		أرجع -1;
#که_تعریف_شوی IPV4_دننه_IPV6
	إذا (منزل.ss_family == AF_INET6 &&
	    IN6_IS_ADDR_V4MAPPED(&((بنية sockaddr_in6 *)&منزل)->sin6_addr))
		أرجع AF_INET;
#د_که_پای
	أرجع منزل.ss_family;
}

فراغ
سېټ_sock_tos(صحيح fd, صحيح tos)
{
#که_نه_تعریف_شوی IP_TOS_IS_BROKEN
	صحيح af;

	إذا (tos < 0 || tos == لوی_عدد) {
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
		إذا (setsockopt(fd, IPPROTO_IP, IP_TOS,
		    &tos, حجم(tos)) == -1) {
			error("setsockopt socket %d IP_TOS %d: %s",
			    fd, tos, strerror(errno));
		}
# endif /* IP_TOS */
		اكسر;
	حالة AF_INET6:
# ifdef IPV6_TCLASS
		debug3_f("set socket %d IPV6_TCLASS 0x%02x", fd, tos);
		إذا (setsockopt(fd, IPPROTO_IPV6, IPV6_TCLASS,
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
#د_که_پای /* IP_TOS_IS_BROKEN */
}

/*
 * Wait up to *timeoutp milliseconds for events on fd. Updates
 * *timeoutp with time remaining.
 * Returns 0 if fd ready or -1 on timeout or error (see errno).
 */
ساكن صحيح
waitfd(صحيح fd, صحيح *timeoutp, لنډ events, متطاير sig_atomic_t *stop)
{
	بنية pollfd pfd;
	بنية timespec timeout;
	صحيح oerrno, r;
	sigset_t nsigset, osigset;

	إذا (timeoutp && *timeoutp == -1)
		timeoutp = عدم;
	pfd.fd = fd;
	pfd.events = events;
	ptimeout_init(&timeout);
	إذا (timeoutp != عدم)
		ptimeout_deadline_ms(&timeout, *timeoutp);
	إذا (stop != عدم)
		sigfillset(&nsigset);
	لكل (; timeoutp == عدم || *timeoutp >= 0;) {
		إذا (stop != عدم) {
			sigprocmask(SIG_BLOCK, &nsigset, &osigset);
			إذا (*stop) {
				sigprocmask(SIG_SETMASK, &osigset, عدم);
				errno = EINTR;
				أرجع -1;
			}
		}
		r = ppoll(&pfd, 1, ptimeout_get_tsp(&timeout),
		    stop != عدم ? &osigset : عدم);
		oerrno = errno;
		إذا (stop != عدم)
			sigprocmask(SIG_SETMASK, &osigset, عدم);
		إذا (timeoutp)
			*timeoutp = ptimeout_get_ms(&timeout);
		errno = oerrno;
		إذا (r > 0)
			أرجع 0;
		وإلا إذا (r == -1 && errno != EAGAIN && errno != EINTR)
			أرجع -1;
		وإلا إذا (r == 0)
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
	إذا (timeoutp == عدم || *timeoutp <= 0)
		أرجع connect(sockfd, serv_addr, addrlen);

	سېټ_nonblock(sockfd);
	لكل (;;) {
		إذا (connect(sockfd, serv_addr, addrlen) == 0) {
			/* Succeeded already? */
			unset_nonblock(sockfd);
			أرجع 0;
		} وإلا إذا (errno == EINTR)
			استمر;
		وإلا إذا (errno != EINPROGRESS)
			أرجع -1;
		اكسر;
	}

	إذا (waitfd(sockfd, timeoutp, POLLIN | POLLOUT, عدم) == -1)
		أرجع -1;

	/* Completed or failed */
	إذا (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &optval, &optlen) == -1) {
		debug("getsockopt: %s", strerror(errno));
		أرجع -1;
	}
	إذا (optval != 0) {
		errno = optval;
		أرجع -1;
	}
	unset_nonblock(sockfd);
	أرجع 0;
}

/* Characters considered whitespace in strsep calls. */
#تعریف_کړه WHITESPACE " \t\r\n"
#تعریف_کړه QUOTE	"\""

/* return next token in configuration line */
ساكن حرف *
strdelim_دننی(حرف **s, صحيح وېشل_equals)
{
	حرف *old;
	صحيح wspace = 0;

	إذا (*s == عدم)
		أرجع عدم;

	old = *s;

	*s = strpbrk(*s,
	    وېشل_equals ? WHITESPACE QUOTE "=" : WHITESPACE QUOTE);
	إذا (*s == عدم)
		أرجع (old);

	إذا (*s[0] == '\"') {
		memmove(*s, *s + 1, مزي_اوږدوالی(*s)); /* move nul too */
		/* Find matching quote */
		إذا ((*s = strpbrk(*s, QUOTE)) == عدم) {
			أرجع (عدم);		/* no matching quote */
		} وإلا {
			*s[0] = '\0';
			*s += strspn(*s + 1, WHITESPACE) + 1;
			أرجع (old);
		}
	}

	/* Allow only one '=' to be skipped */
	إذا (وېشل_equals && *s[0] == '=')
		wspace = 1;
	*s[0] = '\0';

	/* Skip any extra whitespace after first token */
	*s += strspn(*s + 1, WHITESPACE) + 1;
	إذا (وېشل_equals && *s[0] == '=' && !wspace)
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
	أرجع strdelim_دننی(s, 1);
}

/*
 * Return next token in configuration line; splits on whitespace only.
 */
حرف *
strdelimw(حرف **s)
{
	أرجع strdelim_دننی(s, 0);
}

بنية passwd *
pwcopy(بنية passwd *pw)
{
	بنية passwd *copy = xcalloc(1, حجم(*copy));

	copy->pw_name = xstrdup(pw->pw_name);
	copy->pw_passwd = xstrdup(pw->pw_passwd == عدم ? "*" : pw->pw_passwd);
#که_تعریف_شوی HAVE_STRUCT_PASSWD_PW_GECOS
	copy->pw_gecos = xstrdup(pw->pw_gecos == عدم ? "" : pw->pw_gecos);
#د_که_پای
	copy->pw_uid = pw->pw_uid;
	copy->pw_gid = pw->pw_gid;
#که_تعریف_شوی HAVE_STRUCT_PASSWD_PW_EXPIRE
	copy->pw_expire = pw->pw_expire;
#د_که_پای
#که_تعریف_شوی HAVE_STRUCT_PASSWD_PW_CHANGE
	copy->pw_change = pw->pw_change;
#د_که_پای
#که_تعریف_شوی HAVE_STRUCT_PASSWD_PW_CLASS
	copy->pw_class = xstrdup(pw->pw_class == عدم ? "" : pw->pw_class);
#د_که_پای
	copy->pw_dir = xstrdup(pw->pw_dir == عدم ? "" : pw->pw_dir);
	copy->pw_shell = xstrdup(pw->pw_shell == عدم ? "" : pw->pw_shell);
	أرجع copy;
}

فراغ
pwfree(بنية passwd *pw)
{
	إذا (pw == عدم)
		أرجع;
	حرر(pw->pw_name);
	freezero(pw->pw_passwd,
	    pw->pw_passwd == عدم ? 0 : مزي_اوږدوالی(pw->pw_passwd));
#که_تعریف_شوی HAVE_STRUCT_PASSWD_PW_GECOS
	حرر(pw->pw_gecos);
#د_که_پای
#که_تعریف_شوی HAVE_STRUCT_PASSWD_PW_CLASS
	حرر(pw->pw_class);
#د_که_پای
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
	اوږد اوږد پورټ;
	ثابت حرف *errstr;

	پورټ = strtonum(s, 0, 65535, &errstr);
	إذا (errstr == عدم)
		أرجع (صحيح)پورټ;
	إذا ((se = getservbyname(s, "tcp")) != عدم)
		أرجع ntohs(se->s_port);
	أرجع -1;
}

صحيح
a2tun(ثابت حرف *s, صحيح *remote)
{
	ثابت حرف *errstr = عدم;
	حرف *sp, *ep;
	صحيح tun;

	إذا (remote != عدم) {
		*remote = SSH_TUNID_ANY;
		sp = xstrdup(s);
		إذا ((ep = strchr(sp, ':')) == عدم) {
			حرر(sp);
			أرجع (a2tun(s, عدم));
		}
		ep[0] = '\0'; ep++;
		*remote = a2tun(ep, عدم);
		tun = a2tun(sp, عدم);
		حرر(sp);
		أرجع (*remote == SSH_TUNID_ERR ? *remote : tun);
	}

	إذا (strcasecmp(s, "any") == 0)
		أرجع (SSH_TUNID_ANY);

	tun = strtonum(s, 0, SSH_TUNID_MAX, &errstr);
	إذا (errstr != عدم)
		أرجع (SSH_TUNID_ERR);

	أرجع (tun);
}

#تعریف_کړه SECONDS		1.0
#تعریف_کړه MINUTES		(SECONDS * 60)
#تعریف_کړه HOURS		(MINUTES * 60)
#تعریف_کړه DAYS		(HOURS * 24)
#تعریف_کړه WEEKS		(DAYS * 7)

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
	مزدوج val, ټول_sec = 0.0, multiplier;
	ثابت حرف *p, *پیل_p;
	حرف *endp;
	صحيح کتل_شوی_seconds = 0;

	إذا (s == عدم || *s == '\0')
		أرجع -1.0;

	لكل (p = s; *p != '\0';) {
		إذا (!که_عدد((بینښه حرف)*p) && *p != '.')
			أرجع -1.0;

		errno = 0;
		إذا ((val = strtod(p, &endp)) < 0 || errno != 0 || p == endp)
			أرجع -1.0;
		/* Allow only decimal forms */
		إذا (p + strspn(p, "0123456789.") != endp)
			أرجع -1.0;
		پیل_p = p;
		p = endp;

		بدل (*p) {
		حالة '\0':
			/* FALLTHROUGH */
		حالة 's':
		حالة 'S':
			إذا (کتل_شوی_seconds++)
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
		إذا (memchr(پیل_p, '.', endp - پیل_p) != عدم) {
			/* Decimal point present */
			إذا (multiplier > 1.0)
				أرجع -1.0; /* No fractionals for non-seconds */
			/* For seconds, ensure digits follow */
			إذا (!که_عدد((بینښه حرف)*(endp - 1)))
				أرجع -1.0;
		}

		ټول_sec += val * multiplier;

		إذا (*p != '\0')
			p++;
	}
	أرجع ټول_sec;
}

/*
 * Same as convtime_double() above but fractional seconds are ignored.
 * Return -1 if time string is invalid.
 */
صحيح
convtime(ثابت حرف *s)
{
	مزدوج sec_val;

	إذا ((sec_val = convtime_double(s)) < 0.0)
		أرجع -1;

	/* Check for overflow into int */
	إذا (sec_val < 0 || sec_val > لوی_عدد)
		أرجع -1;

	أرجع (صحيح)sec_val;
}

#تعریف_کړه TF_BUFS	8
#تعریف_کړه TF_LEN	9

ثابت حرف *
fmt_timeframe(time_t t)
{
	حرف		*buf;
	ساكن حرف	 tfbuf[TF_BUFS][TF_LEN];	/* ring buffer */
	ساكن صحيح	 idx = 0;
	بینښه صحيح	 sec, min, hrs, day;
	بینښه اوږد اوږد	week;

	buf = tfbuf[idx++];
	إذا (idx == TF_BUFS)
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

	إذا (week > 0)
		snprintf(buf, TF_LEN, "%02lluw%01ud%02uh", week, day, hrs);
	وإلا إذا (day > 0)
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
put_host_پورټ(ثابت حرف *host, u_short پورټ)
{
	حرف *hoststr;

	إذا (پورټ == 0 || پورټ == SSH_DEFAULT_پورټ)
		أرجع(xstrdup(host));
	إذا (asprintf(&hoststr, "[%s]:%d", host, (صحيح)پورټ) == -1)
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

	إذا (cp == عدم || *cp == عدم)
		أرجع عدم;

	old = s = *cp;
	إذا (*s == '[') {
		إذا ((s = strchr(s, ']')) == عدم)
			أرجع عدم;
		وإلا
			s++;
	} وإلا إذا ((s = strpbrk(s, ":/")) == عدم)
		s = *cp + مزي_اوږدوالی(*cp); /* skip to end (see first case below) */

	بدل (*s) {
	حالة '\0':
		*cp = عدم;	/* no more fields*/
		اكسر;

	حالة ':':
	حالة '/':
		إذا (delim != عدم)
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
	إذا (delim == '/')
		أرجع عدم;
	أرجع r;
}

حرف *
cleanhostname(حرف *host)
{
	إذا (*host == '[' && host[مزي_اوږدوالی(host) - 1] == ']') {
		host[مزي_اوږدوالی(host) - 1] = '\0';
		أرجع (host + 1);
	} وإلا
		أرجع host;
}

حرف *
colon(حرف *cp)
{
	صحيح flag = 0;

	إذا (*cp == ':')		/* Leading colon is part of file name. */
		أرجع عدم;
	إذا (*cp == '[')
		flag = 1;

	لكل (; *cp; ++cp) {
		إذا (*cp == '@' && *(cp+1) == '[')
			flag = 1;
		إذا (*cp == ']' && *(cp+1) == ':' && flag)
			أرجع (cp+1);
		إذا (*cp == ':' && !flag)
			أرجع (cp);
		إذا (*cp == '/')
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
parse_user_host_لار(ثابت حرف *s, حرف **userp, حرف **hostp, حرف **pathp)
{
	حرف *user = عدم, *host = عدم, *لار = عدم;
	حرف *sdup, *tmp;
	صحيح ret = -1;

	إذا (userp != عدم)
		*userp = عدم;
	إذا (hostp != عدم)
		*hostp = عدم;
	إذا (pathp != عدم)
		*pathp = عدم;

	sdup = xstrdup(s);

	/* Check for remote syntax: [user@]host:[path] */
	إذا ((tmp = colon(sdup)) == عدم)
		اذهب بهر;

	/* Extract optional path */
	*tmp++ = '\0';
	إذا (*tmp == '\0')
		tmp = ".";
	لار = xstrdup(tmp);

	/* Extract optional user and mandatory host */
	tmp = strrchr(sdup, '@');
	إذا (tmp != عدم) {
		*tmp++ = '\0';
		host = xstrdup(cleanhostname(tmp));
		إذا (*sdup != '\0')
			user = xstrdup(sdup);
	} وإلا {
		host = xstrdup(cleanhostname(sdup));
		user = عدم;
	}

	/* Success */
	إذا (userp != عدم) {
		*userp = user;
		user = عدم;
	}
	إذا (hostp != عدم) {
		*hostp = host;
		host = عدم;
	}
	إذا (pathp != عدم) {
		*pathp = لار;
		لار = عدم;
	}
	ret = 0;
بهر:
	حرر(sdup);
	حرر(user);
	حرر(host);
	حرر(لار);
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
parse_user_host_پورټ(ثابت حرف *s, حرف **userp, حرف **hostp, صحيح *portp)
{
	حرف *sdup, *cp, *tmp;
	حرف *user = عدم, *host = عدم;
	صحيح پورټ = -1, ret = -1;

	إذا (userp != عدم)
		*userp = عدم;
	إذا (hostp != عدم)
		*hostp = عدم;
	إذا (portp != عدم)
		*portp = -1;

	إذا ((sdup = tmp = strdup(s)) == عدم)
		أرجع -1;
	/* Extract optional username */
	إذا ((cp = strrchr(tmp, '@')) != عدم) {
		*cp = '\0';
		إذا (*tmp == '\0')
			اذهب بهر;
		إذا ((user = strdup(tmp)) == عدم)
			اذهب بهر;
		tmp = cp + 1;
	}
	/* Extract mandatory hostname */
	إذا ((cp = hpdelim(&tmp)) == عدم || *cp == '\0')
		اذهب بهر;
	host = xstrdup(cleanhostname(cp));
	/* Convert and verify optional port */
	إذا (tmp != عدم && *tmp != '\0') {
		إذا ((پورټ = a2port(tmp)) <= 0)
			اذهب بهر;
	}
	/* Success */
	إذا (userp != عدم) {
		*userp = user;
		user = عدم;
	}
	إذا (hostp != عدم) {
		*hostp = host;
		host = عدم;
	}
	إذا (portp != عدم)
		*portp = پورټ;
	ret = 0;
 بهر:
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
	بینښه حرف پایله[2];
	صحيح i;

	لكل (i = 0; i < 2; i++) {
		إذا (s[i] >= '0' && s[i] <= '9')
			پایله[i] = (بینښه حرف)(s[i] - '0');
		وإلا إذا (s[i] >= 'a' && s[i] <= 'f')
			پایله[i] = (بینښه حرف)(s[i] - 'a') + 10;
		وإلا إذا (s[i] >= 'A' && s[i] <= 'F')
			پایله[i] = (بینښه حرف)(s[i] - 'A') + 10;
		وإلا
			أرجع -1;
	}
	أرجع (پایله[0] << 4) | پایله[1];
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
	اندازه_t srclen;

	إذا ((srclen = مزي_اوږدوالی(src)) >= SIZE_MAX)
		أرجع عدم;
	ret = xmalloc(srclen + 1);
	لكل (dst = ret; *src != '\0'; src++) {
		بدل (*src) {
		حالة '+':
			*dst++ = ' ';
			اكسر;
		حالة '%':
			/* note: don't allow \0 characters */
			إذا (!isxdigit((بینښه حرف)src[1]) ||
			    !isxdigit((بینښه حرف)src[2]) ||
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
	حرف *user = عدم, *host = عدم, *لار = عدم;
	صحيح پورټ = -1, ret = -1;
	اندازه_t len;

	len = مزي_اوږدوالی(scheme);
	إذا (مزي_پرتله(uri, scheme, len) != 0 || مزي_پرتله(uri + len, "://", 3) != 0)
		أرجع 1;
	uri += len + 3;

	إذا (userp != عدم)
		*userp = عدم;
	إذا (hostp != عدم)
		*hostp = عدم;
	إذا (portp != عدم)
		*portp = -1;
	إذا (pathp != عدم)
		*pathp = عدم;

	uridup = tmp = xstrdup(uri);

	/* Extract optional ssh-info (username + connection params) */
	إذا ((cp = strchr(tmp, '@')) != عدم) {
		حرف *delim;

		*cp = '\0';
		/* Extract username and connection params */
		إذا ((delim = strchr(tmp, ';')) != عدم) {
			/* Just ignore connection params for now */
			*delim = '\0';
		}
		إذا (*tmp == '\0') {
			/* Empty username */
			اذهب بهر;
		}
		إذا ((user = urldecode(tmp)) == عدم)
			اذهب بهر;
		tmp = cp + 1;
	}

	/* Extract mandatory hostname */
	إذا ((cp = hpdelim2(&tmp, &ch)) == عدم || *cp == '\0')
		اذهب بهر;
	host = xstrdup(cleanhostname(cp));
	إذا (!valid_domain(host, 0, عدم))
		اذهب بهر;

	إذا (tmp != عدم && *tmp != '\0') {
		إذا (ch == ':') {
			/* Convert and verify port. */
			إذا ((cp = strchr(tmp, '/')) != عدم)
				*cp = '\0';
			إذا ((پورټ = a2port(tmp)) <= 0)
				اذهب بهر;
			tmp = cp ? cp + 1 : عدم;
		}
		إذا (tmp != عدم && *tmp != '\0') {
			/* Extract optional path */
			إذا ((لار = urldecode(tmp)) == عدم)
				اذهب بهر;
		}
	}

	/* Success */
	إذا (userp != عدم) {
		*userp = user;
		user = عدم;
	}
	إذا (hostp != عدم) {
		*hostp = host;
		host = عدم;
	}
	إذا (portp != عدم)
		*portp = پورټ;
	إذا (pathp != عدم) {
		*pathp = لار;
		لار = عدم;
	}
	ret = 0;
 بهر:
	حرر(uridup);
	حرر(user);
	حرر(host);
	حرر(لار);
	أرجع ret;
}

/* function to assist building execv() arguments */
فراغ
addargs(arglist *دلیلونه, حرف *fmt, ...)
{
	va_list ap;
	حرف *cp;
	u_int nalloc;
	صحيح r;

	va_start(ap, fmt);
	r = vasprintf(&cp, fmt, ap);
	va_end(ap);
	إذا (r == -1)
		fatal_f("argument too long");

	nalloc = دلیلونه->nalloc;
	إذا (دلیلونه->list == عدم) {
		nalloc = 32;
		دلیلونه->عدد = 0;
	} وإلا إذا (دلیلونه->عدد > (256 * 1024))
		fatal_f("too many arguments");
	وإلا إذا (دلیلونه->عدد >= دلیلونه->nalloc)
		fatal_f("arglist corrupt");
	وإلا إذا (دلیلونه->عدد+2 >= nalloc)
		nalloc *= 2;

	دلیلونه->list = xrecallocarray(دلیلونه->list, دلیلونه->nalloc,
	    nalloc, حجم(حرف *));
	دلیلونه->nalloc = nalloc;
	دلیلونه->list[دلیلونه->عدد++] = cp;
	دلیلونه->list[دلیلونه->عدد] = عدم;
}

فراغ
replacearg(arglist *دلیلونه, u_int which, حرف *fmt, ...)
{
	va_list ap;
	حرف *cp;
	صحيح r;

	va_start(ap, fmt);
	r = vasprintf(&cp, fmt, ap);
	va_end(ap);
	إذا (r == -1)
		fatal_f("argument too long");
	إذا (دلیلونه->list == عدم || دلیلونه->عدد >= دلیلونه->nalloc)
		fatal_f("arglist corrupt");

	إذا (which >= دلیلونه->عدد)
		fatal_f("tried to replace invalid arg %d >= %d",
		    which, دلیلونه->عدد);
	حرر(دلیلونه->list[which]);
	دلیلونه->list[which] = cp;
}

فراغ
freeargs(arglist *دلیلونه)
{
	u_int i;

	إذا (دلیلونه == عدم)
		أرجع;
	إذا (دلیلونه->list != عدم && دلیلونه->عدد < دلیلونه->nalloc) {
		لكل (i = 0; i < دلیلونه->عدد; i++)
			حرر(دلیلونه->list[i]);
		حرر(دلیلونه->list);
	}
	دلیلونه->nalloc = دلیلونه->عدد = 0;
	دلیلونه->list = عدم;
}

/*
 * Expands tildes in the file name.  Returns data allocated by xmalloc.
 * Warning: this calls getpw*.
 */
صحيح
tilde_expand(ثابت حرف *filename, uid_t uid, حرف **retp)
{
	حرف *ocopy = عدم, *copy, *s = عدم;
	ثابت حرف *لار = عدم, *user = عدم;
	بنية passwd *pw;
	اندازه_t len;
	صحيح ret = -1, r, slash;

	*retp = عدم;
	إذا (*filename != '~') {
		*retp = xstrdup(filename);
		أرجع 0;
	}
	ocopy = copy = xstrdup(filename + 1);

	إذا (*copy == '\0')				/* ~ */
		لار = عدم;
	وإلا إذا (*copy == '/') {
		copy += strspn(copy, "/");
		إذا (*copy == '\0')
			لار = عدم;			/* ~/ */
		وإلا
			لار = copy;			/* ~/path */
	} وإلا {
		user = copy;
		إذا ((لار = strchr(copy, '/')) != عدم) {
			copy[لار - copy] = '\0';
			لار++;
			لار += strspn(لار, "/");
			إذا (*لار == '\0')		/* ~user/ */
				لار = عدم;
			/* else				 ~user/path */
		}
		/* else					~user */
	}
	إذا (user != عدم) {
		إذا ((pw = getpwnam(user)) == عدم) {
			error_f("No such user %s", user);
			اذهب بهر;
		}
	} وإلا إذا ((pw = getpwuid(uid)) == عدم) {
		error_f("No such uid %ld", (اوږد)uid);
		اذهب بهر;
	}

	/* Make sure directory has a trailing '/' */
	slash = (len = مزي_اوږدوالی(pw->pw_dir)) == 0 || pw->pw_dir[len - 1] != '/';

	إذا ((r = xasprintf(&s, "%s%s%s", pw->pw_dir,
	    slash ? "/" : "", لار != عدم ? لار : "")) <= 0) {
		error_f("xasprintf failed");
		اذهب بهر;
	}
	إذا (r >= PATH_MAX) {
		error_f("Path too long");
		اذهب بهر;
	}
	/* success */
	ret = 0;
	*retp = s;
	s = عدم;
 بهر:
	حرر(s);
	حرر(ocopy);
	أرجع ret;
}

حرف *
tilde_expand_filename(ثابت حرف *filename, uid_t uid)
{
	حرف *ret;

	إذا (tilde_expand(filename, uid, &ret) != 0)
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
#تعریف_کړه EXPAND_MAX_کلیګانې	64
	u_int عدد_کلیګانې = 0, i;
	بنية {
		ثابت حرف *کلی;
		ثابت حرف *repl;
	} کلیګانې[EXPAND_MAX_کلیګانې];
	بنية sshbuf *buf;
	صحيح r, missingvar = 0;
	حرف *ret = عدم, *var, *varend, *val;
	اندازه_t len;

	إذا ((buf = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	إذا (parseerror == عدم)
		fatal_f("null parseerror arg");
	*parseerror = 1;

	/* Gather keys if we're doing percent expansion. */
	إذا (percent) {
		لكل (عدد_کلیګانې = 0; عدد_کلیګانې < EXPAND_MAX_کلیګانې; عدد_کلیګانې++) {
			کلیګانې[عدد_کلیګانې].کلی = va_arg(ap, حرف *);
			إذا (کلیګانې[عدد_کلیګانې].کلی == عدم)
				اكسر;
			کلیګانې[عدد_کلیګانې].repl = va_arg(ap, حرف *);
			إذا (کلیګانې[عدد_کلیګانې].repl == عدم) {
				fatal_f("NULL replacement for token %s",
				    کلیګانې[عدد_کلیګانې].کلی);
			}
		}
		إذا (عدد_کلیګانې == EXPAND_MAX_کلیګانې && va_arg(ap, حرف *) != عدم)
			fatal_f("too many keys");
		إذا (عدد_کلیګانې == 0)
			fatal_f("percent expansion without token list");
	}

	/* Expand string */
	لكل (i = 0; *string != '\0'; string++) {
		/* Optionally process ${ENVIRONMENT} expansions. */
		إذا (dollar && string[0] == '$' && string[1] == '{') {
			string += 2;  /* skip over '${' */
			إذا ((varend = strchr(string, '}')) == عدم) {
				error_f("environment variable '%s' missing "
				    "closing '}'", string);
				اذهب بهر;
			}
			len = varend - string;
			إذا (len == 0) {
				error_f("zero-length environment variable");
				اذهب بهر;
			}
			var = xmalloc(len + 1);
			(فراغ)strlcpy(var, string, len + 1);
			إذا ((val = getenv(var)) == عدم) {
				error_f("env var ${%s} has no value", var);
				missingvar = 1;
			} وإلا {
				debug3_f("expand ${%s} -> '%s'", var, val);
				إذا ((r = sshbuf_put(buf, val, مزي_اوږدوالی(val))) !=0)
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
		إذا (*string != '%' || !percent) {
 append:
			إذا ((r = sshbuf_put_u8(buf, *string)) != 0)
				fatal_fr(r, "sshbuf_put_u8 %%");
			استمر;
		}
		string++;
		/* %% case */
		إذا (*string == '%')
			اذهب append;
		إذا (*string == '\0') {
			error_f("invalid format");
			اذهب بهر;
		}
		لكل (i = 0; i < عدد_کلیګانې; i++) {
			إذا (strchr(کلیګانې[i].کلی, *string) != عدم) {
				إذا ((r = sshbuf_put(buf, کلیګانې[i].repl,
				    مزي_اوږدوالی(کلیګانې[i].repl))) != 0)
					fatal_fr(r, "sshbuf_put %%-repl");
				اكسر;
			}
		}
		إذا (i >= عدد_کلیګانې) {
			error_f("unknown key %%%c", *string);
			اذهب بهر;
		}
	}
	إذا (!missingvar && (ret = sshbuf_dup_string(buf)) == عدم)
		fatal_f("sshbuf_dup_string failed");
	*parseerror = 0;
 بهر:
	sshbuf_free(buf);
	أرجع *parseerror ? عدم : ret;
#تعریف_لغوه EXPAND_MAX_کلیګانې
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
	إذا (parseerr != عدم)
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
	إذا (err)
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
	إذا (err)
		fatal_f("failed");
	أرجع ret;
}

صحيح
tun_open(صحيح tun, صحيح ډېرپېښ, حرف **ifname)
{
#إذا defined(CUSTOM_SYS_TUN_OPEN)
	أرجع (sys_tun_open(tun, ډېرپېښ, ifname));
#وإلاإذا defined(SSH_TUN_OPENBSD)
	بنية ifreq ifr;
	حرف name[100];
	صحيح fd = -1, sock;
	ثابت حرف *tunbase = "tun";

	إذا (ifname != عدم)
		*ifname = عدم;

	إذا (ډېرپېښ == SSH_TUNMODE_ETHERNET)
		tunbase = "tap";

	/* Open the tunnel device */
	إذا (tun <= SSH_TUNID_MAX) {
		snprintf(name, حجم(name), "/dev/%s%d", tunbase, tun);
		fd = open(name, O_RDWR);
	} وإلا إذا (tun == SSH_TUNID_ANY) {
		لكل (tun = 100; tun >= 0; tun--) {
			snprintf(name, حجم(name), "/dev/%s%d",
			    tunbase, tun);
			إذا ((fd = open(name, O_RDWR)) >= 0)
				اكسر;
		}
	} وإلا {
		debug_f("invalid tunnel %u", tun);
		أرجع -1;
	}

	إذا (fd == -1) {
		debug_f("%s open: %s", name, strerror(errno));
		أرجع -1;
	}

	debug_f("%s mode %d fd %d", name, ډېرپېښ, fd);

	/* Bring interface up if it is not already */
	snprintf(ifr.ifr_name, حجم(ifr.ifr_name), "%s%d", tunbase, tun);
	إذا ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
		اذهب failed;

	إذا (ioctl(sock, SIOCGIFFLAGS, &ifr) == -1) {
		debug_f("get interface %s flags: %s", ifr.ifr_name,
		    strerror(errno));
		اذهب failed;
	}

	إذا (!(ifr.ifr_flags & IFF_UP)) {
		ifr.ifr_flags |= IFF_UP;
		إذا (ioctl(sock, SIOCSIFFLAGS, &ifr) == -1) {
			debug_f("activate interface %s: %s", ifr.ifr_name,
			    strerror(errno));
			اذهب failed;
		}
	}

	إذا (ifname != عدم)
		*ifname = xstrdup(ifr.ifr_name);

	close(sock);
	أرجع fd;

 failed:
	إذا (fd >= 0)
		close(fd);
	إذا (sock >= 0)
		close(sock);
	أرجع -1;
#وإلا
	error("Tunnel interfaces are not supported on this platform");
	أرجع (-1);
#د_که_پای
}

فراغ
sanitise_stdfd(فراغ)
{
	صحيح nullfd, dupfd;

	إذا ((nullfd = dupfd = open(_PATH_DEVNULL, O_RDWR)) == -1) {
		fprintf(stderr, "Couldn't open /dev/null: %s\n",
		    strerror(errno));
		وتل(1);
	}
	طالما (++dupfd <= STDERR_FILENO) {
		/* Only populate closed fds. */
		إذا (fcntl(dupfd, F_GETFL) == -1 && errno == EBADF) {
			إذا (dup2(nullfd, dupfd) == -1) {
				fprintf(stderr, "dup2: %s\n", strerror(errno));
				وتل(1);
			}
		}
	}
	إذا (nullfd > STDERR_FILENO)
		close(nullfd);
}

حرف *
tohex(ثابت فراغ *vp, اندازه_t l)
{
	ثابت u_char *p = (ثابت u_char *)vp;
	حرف b[3], *r;
	اندازه_t i, hl;

	إذا (l > 65536)
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

	إذا (*sp == عدم || **sp == '\0') {
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
ms_کمول_diff(بنية timeval *پیل, صحيح *ms)
{
	بنية timeval diff, پای;

	monotime_tv(&پای);
	timersub(&پای, پیل, &diff);
	*ms -= (diff.tv_sec * 1000) + (diff.tv_usec / 1000);
}

فراغ
ms_منزل_timespec(بنية timespec *ts, صحيح ms)
{
	إذا (ms < 0)
		ms = 0;
	ts->tv_sec = ms / 1000;
	ts->tv_nsec = (ms % 1000) * 1000 * 1000;
}

فراغ
monotime_ts(بنية timespec *ts)
{
	بنية timeval tv;
#إذا defined(HAVE_CLOCK_GETTIME) && (defined(CLOCK_BOOTTIME) || \
    defined(CLOCK_MONOTONIC) || defined(CLOCK_REALTIME))
	ساكن صحيح gettime_failed = 0;

	إذا (!gettime_failed) {
# ifdef CLOCK_BOOTTIME
		إذا (clock_gettime(CLOCK_BOOTTIME, ts) == 0)
			أرجع;
# endif /* CLOCK_BOOTTIME */
# ifdef CLOCK_MONOTONIC
		إذا (clock_gettime(CLOCK_MONOTONIC, ts) == 0)
			أرجع;
# endif /* CLOCK_MONOTONIC */
# ifdef CLOCK_REALTIME
		/* Not monotonic, but we're almost out of options here. */
		إذا (clock_gettime(CLOCK_REALTIME, ts) == 0)
			أرجع;
# endif /* CLOCK_REALTIME */
		debug3("clock_gettime: %s", strerror(errno));
		gettime_failed = 1;
	}
#د_که_پای /* HAVE_CLOCK_GETTIME && (BOOTTIME || MONOTONIC || REALTIME) */
	gettimeofday(&tv, عدم);
	ts->tv_sec = tv.tv_sec;
	ts->tv_nsec = (اوږد)tv.tv_usec * 1000;
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
bandwidth_حد_init(بنية bwlimit *bw, uint64_t kbps, اندازه_t buflen)
{
	bw->buflen = buflen;
	bw->شرح = kbps;
	bw->thresh = buflen;
	bw->lamt = 0;
	timerclear(&bw->bwstart);
	timerclear(&bw->bwend);
}

/* Callback from read/write loop to insert bandwidth-limiting delays */
فراغ
bandwidth_حد(بنية bwlimit *bw, اندازه_t read_len)
{
	uint64_t waitlen;
	بنية timespec ts, rm;

	bw->lamt += read_len;
	إذا (!timerisset(&bw->bwstart)) {
		monotime_tv(&bw->bwstart);
		أرجع;
	}
	إذا (bw->lamt < bw->thresh)
		أرجع;

	monotime_tv(&bw->bwend);
	timersub(&bw->bwend, &bw->bwstart, &bw->bwend);
	إذا (!timerisset(&bw->bwend))
		أرجع;

	bw->lamt *= 8;
	waitlen = (مزدوج)1000000L * bw->lamt / bw->شرح;

	bw->bwstart.tv_sec = waitlen / 1000000L;
	bw->bwstart.tv_usec = waitlen % 1000000L;

	إذا (timercmp(&bw->bwstart, &bw->bwend, >)) {
		timersub(&bw->bwstart, &bw->bwend, &bw->bwend);

		/* Adjust the wait time */
		إذا (bw->bwend.tv_sec) {
			bw->thresh /= 2;
			إذا (bw->thresh < bw->buflen / 4)
				bw->thresh = bw->buflen / 4;
		} وإلا إذا (bw->bwend.tv_usec < 10000) {
			bw->thresh *= 2;
			إذا (bw->thresh > bw->buflen * 8)
				bw->thresh = bw->buflen * 8;
		}

		TIMEVAL_منزل_TIMESPEC(&bw->bwend, &ts);
		طالما (nanosleep(&ts, &rm) == -1) {
			إذا (errno != EINTR)
				اكسر;
			ts = rm;
		}
	}

	bw->lamt = 0;
	monotime_tv(&bw->bwstart);
}

/* Make a template filename for mk[sd]temp() */
فراغ
mktemp_proto(حرف *s, اندازه_t len)
{
	ثابت حرف *tmpdir;
	صحيح r;

	إذا ((tmpdir = getenv("TMPDIR")) != عدم) {
		r = snprintf(s, len, "%s/ssh-XXXXXXXXXXXX", tmpdir);
		إذا (r > 0 && (اندازه_t)r < len)
			أرجع;
	}
	r = snprintf(s, len, "/tmp/ssh-XXXXXXXXXXXX");
	إذا (r < 0 || (اندازه_t)r >= len)
		fatal_f("template string too short");
}

ساكن ثابت بنية {
	ثابت حرف *name;
	صحيح ارزښت;
} ipqos[] = {
	{ "none", لوی_عدد },		/* can't use 0 here; that's CS0 */
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

	إذا (cp == عدم)
		أرجع -1;
	لكل (i = 0; ipqos[i].name != عدم; i++) {
		إذا (strcasecmp(cp, ipqos[i].name) == 0)
			أرجع ipqos[i].ارزښت;
	}
	/* Try parsing as an integer */
	val = (صحيح)strtonum(cp, 0, 255, &errstr);
	إذا (errstr)
		أرجع -1;
	أرجع val;
}

ثابت حرف *
iptos2str(صحيح iptos)
{
	صحيح i;
	ساكن حرف iptos_str[حجم "0xff"];

	لكل (i = 0; ipqos[i].name != عدم; i++) {
		إذا (ipqos[i].ارزښت == iptos)
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
unix_listener(ثابت حرف *لار, صحيح backlog, صحيح unlink_لومړی)
{
	بنية sockaddr_un sunaddr;
	صحيح saved_errno, sock;

	memset(&sunaddr, 0, حجم(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	إذا (strlcpy(sunaddr.sun_لار, لار,
	    حجم(sunaddr.sun_لار)) >= حجم(sunaddr.sun_لار)) {
		error_f("path \"%s\" too long for Unix domain socket", لار);
		errno = ENAMETOOLONG;
		أرجع -1;
	}

	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	إذا (sock == -1) {
		saved_errno = errno;
		error_f("socket: %.100s", strerror(errno));
		errno = saved_errno;
		أرجع -1;
	}
	إذا (unlink_لومړی == 1) {
		إذا (unlink(لار) != 0 && errno != ENOENT)
			error("unlink(%s): %.100s", لار, strerror(errno));
	}
	إذا (bind(sock, (بنية sockaddr *)&sunaddr, حجم(sunaddr)) == -1) {
		saved_errno = errno;
		error_f("cannot bind to path %s: %s", لار, strerror(errno));
		close(sock);
		errno = saved_errno;
		أرجع -1;
	}
	إذا (listen(sock, backlog) == -1) {
		saved_errno = errno;
		error_f("cannot listen on path %s: %s", لار, strerror(errno));
		close(sock);
		unlink(لار);
		errno = saved_errno;
		أرجع -1;
	}
	أرجع sock;
}

فراغ
sock_سېټ_v6only(صحيح s)
{
#إذا defined(IPV6_V6ONLY) && !defined(__OpenBSD__)
	صحيح on = 1;

	debug3_f("set socket %d IPV6_V6ONLY", s);
	إذا (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &on, حجم(on)) == -1)
		error("setsockopt IPV6_V6ONLY: %s", strerror(errno));
#د_که_پای
}

/*
 * Compares two strings that maybe be NULL. Returns non-zero if strings
 * are both NULL or are identical, returns zero otherwise.
 */
ساكن صحيح
strcmp_maybe_null(ثابت حرف *a, ثابت حرف *b)
{
	إذا ((a == عدم && b != عدم) || (a != عدم && b == عدم))
		أرجع 0;
	إذا (a != عدم && strcmp(a, b) != 0)
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
	إذا (strcmp_maybe_null(a->listen_host, b->listen_host) == 0)
		أرجع 0;
	إذا (a->listen_پورټ != b->listen_پورټ)
		أرجع 0;
	إذا (strcmp_maybe_null(a->listen_لار, b->listen_لار) == 0)
		أرجع 0;
	إذا (strcmp_maybe_null(a->connect_host, b->connect_host) == 0)
		أرجع 0;
	إذا (a->connect_پورټ != b->connect_پورټ)
		أرجع 0;
	إذا (strcmp_maybe_null(a->connect_لار, b->connect_لار) == 0)
		أرجع 0;
	/* allocated_port and handle are not checked */
	أرجع 1;
}

/* returns port number, FWD_PERMIT_ANY_PORT or -1 on error */
صحيح
permitopen_پورټ(ثابت حرف *p)
{
	صحيح پورټ;

	إذا (strcmp(p, "*") == 0)
		أرجع FWD_PERMIT_ANY_پورټ;
	إذا ((پورټ = a2port(p)) > 0)
		أرجع پورټ;
	أرجع -1;
}

/* returns 1 if process is already daemonized, 0 otherwise */
صحيح
daemonized(فراغ)
{
	صحيح fd;

	إذا ((fd = open(_PATH_TTY, O_RDONLY | O_NOCTTY)) >= 0) {
		close(fd);
		أرجع 0;	/* have controlling terminal */
	}
	إذا (getppid() != 1)
		أرجع 0;	/* parent is not init */
	إذا (getsid(0) != getpid())
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
argv_وېشل(ثابت حرف *s, صحيح *argcp, حرف ***argvp, صحيح terminate_on_comment)
{
	صحيح r = SSH_ERR_دننی_ERROR;
	صحيح argc = 0, quote, i, j;
	حرف *arg, **argv = xcalloc(1, حجم(*argv));

	*argvp = عدم;
	*argcp = 0;

	لكل (i = 0; s[i] != '\0'; i++) {
		/* Skip leading whitespace */
		إذا (s[i] == ' ' || s[i] == '\t')
			استمر;
		إذا (terminate_on_comment && s[i] == '#')
			اكسر;
		/* Start of a token */
		quote = 0;

		argv = xreallocarray(argv, (argc + 2), حجم(*argv));
		arg = argv[argc++] = xcalloc(1, مزي_اوږدوالی(s + i) + 1);
		argv[argc] = عدم;

		/* Copy the token in, removing escapes */
		لكل (j = 0; s[i] != '\0'; i++) {
			إذا (s[i] == '\\') {
				إذا (s[i + 1] == '\'' ||
				    s[i + 1] == '\"' ||
				    s[i + 1] == '\\' ||
				    (quote == 0 && s[i + 1] == ' ')) {
					i++; /* Skip '\' */
					arg[j++] = s[i];
				} وإلا {
					/* Unrecognised escape */
					arg[j++] = s[i];
				}
			} وإلا إذا (quote == 0 && (s[i] == ' ' || s[i] == '\t'))
				اكسر; /*بشپړ*/
			وإلا إذا (quote == 0 && (s[i] == '\"' || s[i] == '\''))
				quote = s[i]; /* quote start */
			وإلا إذا (quote != 0 && s[i] == quote)
				quote = 0; /* quote end */
			وإلا
				arg[j++] = s[i];
		}
		إذا (s[i] == '\0') {
			إذا (quote != 0) {
				/* Ran out of string looking for close quote */
				r = SSH_ERR_INVALID_FORMAT;
				اذهب بهر;
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
 بهر:
	إذا (argc != 0 && argv != عدم) {
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

	إذا ((buf = sshbuf_new()) == عدم || (arg = sshbuf_new()) == عدم)
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
				إذا ((r = sshbuf_put_u8(arg, '\\')) != 0)
					اكسر;
				/* FALLTHROUGH */
			افتراضي:
				r = sshbuf_put_u8(arg, c);
				اكسر;
			}
			إذا (r != 0)
				fatal_fr(r, "sshbuf_put_u8");
		}
		إذا ((i != 0 && (r = sshbuf_put_u8(buf, ' ')) != 0) ||
		    (ws != 0 && (r = sshbuf_put_u8(buf, '"')) != 0) ||
		    (r = sshbuf_putb(buf, arg)) != 0 ||
		    (ws != 0 && (r = sshbuf_put_u8(buf, '"')) != 0))
			fatal_fr(r, "assemble");
	}
	إذا ((ret = حافظه_ورکړه(sshbuf_len(buf) + 1)) == عدم)
		fatal_f("malloc failed");
	حافظه_نقل(ret, sshbuf_ptr(buf), sshbuf_len(buf));
	ret[sshbuf_len(buf)] = '\0';
	sshbuf_free(buf);
	sshbuf_free(arg);
	أرجع ret;
}

حرف *
argv_بل(صحيح *argcp, حرف ***argvp)
{
	حرف *ret = (*argvp)[0];

	إذا (*argcp > 0 && ret != عدم) {
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

	إذا (av == عدم)
		أرجع;
	لكل (i = 0; i < ac; i++)
		حرر(av[i]);
	حرر(av);
}

/* Returns 0 if pid exited cleanly, non-zero otherwise */
صحيح
exited_cleanly(pid_t pid, ثابت حرف *نښان, ثابت حرف *cmd, صحيح quiet)
{
	صحيح حالت;

	طالما (waitpid(pid, &حالت, 0) == -1) {
		إذا (errno != EINTR) {
			error("%s waitpid: %s", نښان, strerror(errno));
			أرجع -1;
		}
	}
	إذا (WIFSIGNALED(حالت)) {
		error("%s %s exited on signal %d", نښان, cmd, WTERMSIG(حالت));
		أرجع -1;
	} وإلا إذا (WEXITSTATUS(حالت) != 0) {
		do_log2(quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_INFO,
		    "%s %s failed, status %d", نښان, cmd, WEXITSTATUS(حالت));
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
خوندي_لار(ثابت حرف *name, بنية stat *stp, ثابت حرف *pw_dir,
    uid_t uid, حرف *err, اندازه_t errlen)
{
	حرف buf[PATH_MAX], buf2[PATH_MAX], homedir[PATH_MAX];
	حرف *cp;
	صحيح comparehome = 0;
	بنية stat st;

	إذا (realpath(name, buf) == عدم) {
		snprintf(err, errlen, "realpath %s failed: %s", name,
		    strerror(errno));
		أرجع -1;
	}
	إذا (pw_dir != عدم && realpath(pw_dir, homedir) != عدم)
		comparehome = 1;

	إذا (!S_ISREG(stp->st_mode)) {
		snprintf(err, errlen, "%s is not a regular file", buf);
		أرجع -1;
	}
	إذا ((!platform_sys_dir_uid(stp->st_uid) && stp->st_uid != uid) ||
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
		إذا ((cp = dirname(buf2)) == عدم) {
			snprintf(err, errlen, "dirname() failed");
			أرجع -1;
		}
		strlcpy(buf, cp, حجم(buf));

		إذا (stat(buf, &st) == -1 ||
		    (!platform_sys_dir_uid(st.st_uid) && st.st_uid != uid) ||
		    (st.st_mode & 022) != 0) {
			snprintf(err, errlen,
			    "bad ownership or modes for directory %s", buf);
			أرجع -1;
		}

		/* If are past the homedir then we can stop */
		إذا (comparehome && strcmp(homedir, buf) == 0)
			اكسر;

		/*
		 * dirname should always complete with a "/" path,
		 * but we can be paranoid and check for "." too
		 */
		إذا ((strcmp("/", buf) == 0) || (strcmp(".", buf) == 0))
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
خوندي_لار_fd(صحيح fd, ثابت حرف *file, بنية passwd *pw,
    حرف *err, اندازه_t errlen)
{
	بنية stat st;

	/* check the open file to avoid races */
	إذا (fstat(fd, &st) == -1) {
		snprintf(err, errlen, "cannot stat file %s: %s",
		    file, strerror(errno));
		أرجع -1;
	}
	أرجع خوندي_لار(file, &st, pw->pw_dir, pw->pw_uid, err, errlen);
}

/*
 * Sets the value of the given variable in the environment.  If the variable
 * already exists, its value is overridden.
 */
فراغ
ماشوم_سېټ_env(حرف ***envp, u_int *envsizep, ثابت حرف *name,
	ثابت حرف *ارزښت)
{
	حرف **env;
	u_int envsize;
	u_int i, namelen;

	إذا (strchr(name, '=') != عدم) {
		error("Invalid environment variable \"%.100s\"", name);
		أرجع;
	}

	/*
	 * If we're passed an uninitialized list, allocate a single null
	 * entry before continuing.
	 */
	إذا ((*envp == عدم) != (*envsizep == 0))
		fatal_f("environment size mismatch");
	إذا (*envp == عدم && *envsizep == 0) {
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
	namelen = مزي_اوږدوالی(name);
	لكل (i = 0; env[i]; i++)
		إذا (مزي_پرتله(env[i], name, namelen) == 0 && env[i][namelen] == '=')
			اكسر;
	إذا (env[i]) {
		/* Reuse the slot. */
		حرر(env[i]);
	} وإلا {
		/* New variable.  Expand if necessary. */
		envsize = *envsizep;
		إذا (i >= envsize - 1) {
			إذا (envsize >= 1000)
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
	env[i] = xmalloc(مزي_اوږدوالی(name) + 1 + مزي_اوږدوالی(ارزښت) + 1);
	snprintf(env[i], مزي_اوږدوالی(name) + 1 + مزي_اوږدوالی(ارزښت) + 1, "%s=%s", name, ارزښت);
}

/*
 * Check and optionally lowercase a domain name, also removes trailing '.'
 * Returns 1 on success and 0 on failure, storing an error message in errstr.
 */
صحيح
valid_domain(حرف *name, صحيح makelower, ثابت حرف **errstr)
{
	اندازه_t i, l = مزي_اوږدوالی(name);
	u_char c, وروستی = '\0';
	ساكن حرف errbuf[256];

	إذا (l == 0) {
		strlcpy(errbuf, "empty domain name", حجم(errbuf));
		اذهب bad;
	}
	إذا (!که_توری((u_char)name[0]) && !که_عدد((u_char)name[0]) &&
	   name[0] != '_' /* technically invalid, but common */) {
		snprintf(errbuf, حجم(errbuf), "domain name \"%.100s\" "
		    "starts with invalid character", name);
		اذهب bad;
	}
	لكل (i = 0; i < l; i++) {
		c = tolower((u_char)name[i]);
		إذا (makelower)
			name[i] = (حرف)c;
		إذا (وروستی == '.' && c == '.') {
			snprintf(errbuf, حجم(errbuf), "domain name "
			    "\"%.100s\" contains consecutive separators", name);
			اذهب bad;
		}
		إذا (c != '.' && c != '-' && !که_توری_یا_عدد(c) &&
		    c != '_') /* technically invalid, but common */ {
			snprintf(errbuf, حجم(errbuf), "domain name "
			    "\"%.100s\" contains invalid characters", name);
			اذهب bad;
		}
		وروستی = c;
	}
	إذا (name[l - 1] == '.')
		name[l - 1] = '\0';
	إذا (errstr != عدم)
		*errstr = عدم;
	أرجع 1;
bad:
	إذا (errstr != عدم)
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

	إذا (name[0] == '\0')
		أرجع 0;
	لكل (cp = name; *cp != '\0'; cp++) {
		إذا (!که_توری_یا_عدد((u_char)*cp) && *cp != '_')
			أرجع 0;
	}
	أرجع 1;
}

ثابت حرف *
atoi_err(ثابت حرف *nptr, صحيح *val)
{
	ثابت حرف *errstr = عدم;

	إذا (nptr == عدم || *nptr == '\0')
		أرجع "missing";
	*val = strtonum(nptr, 0, لوی_عدد, &errstr);
	أرجع errstr;
}

صحيح
parse_absolute_وخت(ثابت حرف *s, uint64_t *tp)
{
	بنية tm tm;
	time_t tt;
	حرف buf[32], *fmt;
	ثابت حرف *cp;
	اندازه_t l;
	صحيح is_utc = 0;

	*tp = 0;

	l = مزي_اوږدوالی(s);
	إذا (l > 1 && strcasecmp(s + l - 1, "Z") == 0) {
		is_utc = 1;
		l--;
	} وإلا إذا (l > 3 && strcasecmp(s + l - 3, "UTC") == 0) {
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
	إذا ((cp = strptime(buf, fmt, &tm)) == عدم || *cp != '\0')
		أرجع SSH_ERR_INVALID_FORMAT;
	إذا (is_utc) {
		tm.tm_wday = -1;	/* sentinel for error */
		إذا ((tt = timegm(&tm)) == -1 && tm.tm_wday == -1)
			أرجع SSH_ERR_INVALID_FORMAT;
	} وإلا {
		tm.tm_wday = -1;	/* sentinel for error */
		tm.tm_isdst = -1;	/* mktime decides DST */
		إذا ((tt = mktime(&tm)) == -1 && tm.tm_wday == -1)
			أرجع SSH_ERR_INVALID_FORMAT;
	}
	/* success */
	*tp = (uint64_t)tt;
	أرجع 0;
}

فراغ
format_absolute_وخت(uint64_t t, حرف *buf, اندازه_t len)
{
	time_t tt = t > SSH_وخت_T_MAX ? SSH_وخت_T_MAX : t;
	بنية tm tm;

	إذا (localtime_r(&tt, &tm) == عدم)
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
parse_نمونه_interval(ثابت حرف *s, حرف **typep, مزدوج *secsp)
{
	حرف *cp, *sdup;
	مزدوج secs;

	إذا (typep != عدم)
		*typep = عدم;
	إذا (secsp != عدم)
		*secsp = 0;
	إذا (s == عدم)
		أرجع -1;
	sdup = xstrdup(s);

	إذا ((cp = strchr(sdup, '=')) == عدم || cp == sdup) {
		حرر(sdup);
		أرجع -1;
	}
	*cp++ = '\0';
	إذا ((secs = convtime_double(cp)) < 0.0) {
		حرر(sdup);
		أرجع -1;
	}
	/* success */
	إذا (typep != عدم)
		*typep = xstrdup(sdup);
	إذا (secsp != عدم)
		*secsp = secs;
	حرر(sdup);
	أرجع 0;
}

/* check if path is absolute */
صحيح
لار_absolute(ثابت حرف *لار)
{
	أرجع (*لار == '/') ? 1 : 0;
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
	اندازه_t opt_len = مزي_اوږدوالی(opt);
	ثابت حرف *opts = *optsp;
	صحيح negate = 0;

	إذا (allow_negate && strncasecmp(opts, "no-", 3) == 0) {
		opts += 3;
		negate = 1;
	}
	إذا (strncasecmp(opts, opt, opt_len) == 0) {
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
	اندازه_t i;

	*errstrp = عدم;
	إذا (*s != '"') {
		*errstrp = "missing start quote";
		أرجع عدم;
	}
	s++;
	إذا ((ret = حافظه_ورکړه(مزي_اوږدوالی((s)) + 1)) == عدم) {
		*errstrp = "memory allocation failed";
		أرجع عدم;
	}
	لكل (i = 0; *s != '\0' && *s != '"';) {
		إذا (s[0] == '\\' && s[1] == '"')
			s++;
		ret[i++] = *s++;
	}
	إذا (*s == '\0') {
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
opt_سمون(ثابت حرف **opts, ثابت حرف *غړی)
{
	إذا (strncasecmp((*opts), غړی, مزي_اوږدوالی(غړی)) == 0 &&
	    (*opts)[مزي_اوږدوالی(غړی)] == '=') {
		*opts += مزي_اوږدوالی(غړی) + 1;
		أرجع 1;
	}
	أرجع 0;
}

فراغ
opt_array_append2(ثابت حرف *file, ثابت صحيح کرښه, ثابت حرف *directive,
    حرف ***array, صحيح **iarray, u_int *lp, ثابت حرف *s, صحيح i)
{

	إذا (*lp >= لوی_عدد)
		fatal("%s line %d: Too many %s entries", file, کرښه, directive);

	إذا (iarray != عدم) {
		*iarray = xrecallocarray(*iarray, *lp, *lp + 1,
		    حجم(**iarray));
		(*iarray)[*lp] = i;
	}

	*array = xrecallocarray(*array, *lp, *lp + 1, حجم(**array));
	(*array)[*lp] = xstrdup(s);
	(*lp)++;
}

فراغ
opt_array_append(ثابت حرف *file, ثابت صحيح کرښه, ثابت حرف *directive,
    حرف ***array, u_int *lp, ثابت حرف *s)
{
	opt_array_append2(file, کرښه, directive, array, عدم, lp, s, 0);
}

فراغ
opt_array_free2(حرف **array, صحيح **iarray, u_int l)
{
	u_int i;

	إذا (array == عدم || l == 0)
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
#إذا defined(SA_RESTART) && !defined(NO_SA_RESTART)
	إذا (signum != SIGALRM)
		sa.sa_flags = SA_RESTART;
#د_که_پای
	إذا (sigaction(signum, &sa, &osa) == -1) {
		debug3("sigaction(%s): %s", strsignal(signum), strerror(errno));
		أرجع SIG_ERR;
	}
	أرجع osa.sa_handler;
}

صحيح
stdfd_devnull(صحيح do_stdin, صحيح do_stdout, صحيح do_stderr)
{
	صحيح devnull, ret = 0;

	إذا ((devnull = open(_PATH_DEVNULL, O_RDWR)) == -1) {
		error_f("open %s: %s", _PATH_DEVNULL,
		    strerror(errno));
		أرجع -1;
	}
	إذا ((do_stdin && dup2(devnull, STDIN_FILENO) == -1) ||
	    (do_stdout && dup2(devnull, STDOUT_FILENO) == -1) ||
	    (do_stderr && dup2(devnull, STDERR_FILENO) == -1)) {
		error_f("dup2: %s", strerror(errno));
		ret = -1;
	}
	إذا (devnull > STDERR_FILENO)
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
subprocess(ثابت حرف *نښان, ثابت حرف *command,
    صحيح ac, حرف **av, FILE **ماشوم, u_int flags,
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
	إذا (drop_privs != عدم && (pw == عدم || restore_privs == عدم)) {
		error("%s: inconsistent arguments", نښان); /* XXX fatal? */
		أرجع 0;
	}
	إذا (pw == عدم && (pw = getpwuid(getuid())) == عدم) {
		error("%s: no user for current uid", نښان);
		أرجع 0;
	}
	إذا (ماشوم != عدم)
		*ماشوم = عدم;

	debug3_f("%s command \"%s\" running as %s (flags 0x%x)",
	    نښان, command, pw->pw_name, flags);

	/* Check consistency */
	إذا ((flags & SSH_SUBPROCESS_STDOUT_DISCARD) != 0 &&
	    (flags & SSH_SUBPROCESS_STDOUT_CAPTURE) != 0) {
		error_f("inconsistent flags");
		أرجع 0;
	}
	إذا (((flags & SSH_SUBPROCESS_STDOUT_CAPTURE) == 0) != (ماشوم == عدم)) {
		error_f("inconsistent flags/output");
		أرجع 0;
	}

	/*
	 * If executing an explicit binary, then verify the it exists
	 * and appears safe-ish to execute
	 */
	إذا (!لار_absolute(av[0])) {
		error("%s path is not absolute", نښان);
		أرجع 0;
	}
	إذا (drop_privs != عدم)
		drop_privs(pw);
	إذا (stat(av[0], &st) == -1) {
		error("Could not stat %s \"%s\": %s", نښان,
		    av[0], strerror(errno));
		اذهب restore_return;
	}
	إذا ((flags & SSH_SUBPROCESS_UNSAFE_لار) == 0 &&
	    خوندي_لار(av[0], &st, عدم, 0, errmsg, حجم(errmsg)) != 0) {
		error("Unsafe %s \"%s\": %s", نښان, av[0], errmsg);
		اذهب restore_return;
	}
	/* Prepare to keep the child's stdout if requested */
	إذا (pipe(p) == -1) {
		error("%s: pipe: %s", نښان, strerror(errno));
 restore_return:
		إذا (restore_privs != عدم)
			restore_privs();
		أرجع 0;
	}
	إذا (restore_privs != عدم)
		restore_privs();

	بدل ((pid = fork())) {
	حالة -1: /* error */
		error("%s: fork: %s", نښان, strerror(errno));
		close(p[0]);
		close(p[1]);
		أرجع 0;
	حالة 0: /*ماشوم*/
		/* Prepare a minimal environment for the child. */
		إذا ((flags & SSH_SUBPROCESS_PRESERVE_ENV) == 0) {
			nenv = 5;
			env = xcalloc(حجم(*env), nenv);
			ماشوم_سېټ_env(&env, &nenv, "PATH", _PATH_STDPATH);
			ماشوم_سېټ_env(&env, &nenv, "USER", pw->pw_name);
			ماشوم_سېټ_env(&env, &nenv, "LOGNAME", pw->pw_name);
			ماشوم_سېټ_env(&env, &nenv, "HOME", pw->pw_dir);
			إذا ((cp = getenv("LANG")) != عدم)
				ماشوم_سېټ_env(&env, &nenv, "LANG", cp);
		}

		لكل (i = 1; i < NSIG; i++)
			ssh_signal(i, SIG_DFL);

		إذا ((devnull = open(_PATH_DEVNULL, O_RDWR)) == -1) {
			error("%s: open %s: %s", نښان, _PATH_DEVNULL,
			    strerror(errno));
			_exit(1);
		}
		إذا (dup2(devnull, STDIN_FILENO) == -1) {
			error("%s: dup2: %s", نښان, strerror(errno));
			_exit(1);
		}

		/* Set up stdout as requested; leave stderr in place for now. */
		fd = -1;
		إذا ((flags & SSH_SUBPROCESS_STDOUT_CAPTURE) != 0)
			fd = p[1];
		وإلا إذا ((flags & SSH_SUBPROCESS_STDOUT_DISCARD) != 0)
			fd = devnull;
		إذا (fd != -1 && dup2(fd, STDOUT_FILENO) == -1) {
			error("%s: dup2: %s", نښان, strerror(errno));
			_exit(1);
		}
		closefrom(STDERR_FILENO + 1);

		إذا (geteuid() == 0 &&
		    initgroups(pw->pw_name, pw->pw_gid) == -1) {
			error("%s: initgroups(%s, %u): %s", نښان,
			    pw->pw_name, (u_int)pw->pw_gid, strerror(errno));
			_exit(1);
		}
		إذا (setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) == -1) {
			error("%s: setresgid %u: %s", نښان, (u_int)pw->pw_gid,
			    strerror(errno));
			_exit(1);
		}
		إذا (setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) == -1) {
			error("%s: setresuid %u: %s", نښان, (u_int)pw->pw_uid,
			    strerror(errno));
			_exit(1);
		}
		/* stdin is pointed to /dev/null at this point */
		إذا ((flags & SSH_SUBPROCESS_STDOUT_DISCARD) != 0 &&
		    dup2(STDIN_FILENO, STDERR_FILENO) == -1) {
			error("%s: dup2: %s", نښان, strerror(errno));
			_exit(1);
		}
		إذا (env != عدم)
			execve(av[0], av, env);
		وإلا
			execv(av[0], av);
		error("%s %s \"%s\": %s", نښان, env == عدم ? "execv" : "execve",
		    command, strerror(errno));
		_exit(127);
	افتراضي: /*پلار*/
		اكسر;
	}

	close(p[1]);
	إذا ((flags & SSH_SUBPROCESS_STDOUT_CAPTURE) == 0)
		close(p[0]);
	وإلا إذا ((f = fdopen(p[0], "r")) == عدم) {
		error("%s: fdopen: %s", نښان, strerror(errno));
		close(p[0]);
		/* Don't leave zombie child */
		kill(pid, SIGTERM);
		طالما (waitpid(pid, عدم, 0) == -1 && errno == EINTR)
			;
		أرجع 0;
	}
	/* Success */
	debug3_f("%s pid %ld", نښان, (اوږد)pid);
	إذا (ماشوم != عدم)
		*ماشوم = f;
	أرجع pid;
}

ثابت حرف *
lookup_env_دننه_list(ثابت حرف *env, حرف * ثابت *envs, اندازه_t nenvs)
{
	اندازه_t i, envlen;

	envlen = مزي_اوږدوالی(env);
	لكل (i = 0; i < nenvs; i++) {
		إذا (مزي_پرتله(envs[i], env, envlen) == 0 &&
		    envs[i][envlen] == '=') {
			أرجع envs[i] + envlen + 1;
		}
	}
	أرجع عدم;
}

ثابت حرف *
lookup_setenv_دننه_list(ثابت حرف *env, حرف * ثابت *envs, اندازه_t nenvs)
{
	حرف *name, *cp;
	ثابت حرف *ret;

	name = xstrdup(env);
	إذا ((cp = strchr(name, '=')) == عدم) {
		حرر(name);
		أرجع عدم; /* not env=val */
	}
	*cp = '\0';
	ret = lookup_env_دننه_list(name, envs, nenvs);
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
ptimeout_deadline_sec(بنية timespec *pt, اوږد sec)
{
	إذا (pt->tv_sec == -1 || pt->tv_sec >= sec) {
		pt->tv_sec = sec;
		pt->tv_nsec = 0;
	}
}

/* Specify a poll/ppoll deadline of at most 'p' (timespec) */
ساكن فراغ
ptimeout_deadline_tsp(بنية timespec *pt, بنية timespec *p)
{
	إذا (pt->tv_sec == -1 || timespeccmp(pt, p, >=))
		*pt = *p;
}

/* Specify a poll/ppoll deadline of at most 'ms' milliseconds */
فراغ
ptimeout_deadline_ms(بنية timespec *pt, اوږد ms)
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
	إذا ((int64_t)sec >= SSH_وخت_T_MAX)
		t.tv_sec = SSH_وخت_T_MAX;
	وإلا إذا (sec > 0) {
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

	إذا (timespeccmp(&now, when, >=)) {
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
	إذا (pt->tv_sec == -1)
		أرجع -1;
	إذا (pt->tv_sec >= (لوی_عدد - (pt->tv_nsec / 1000000)) / 1000)
		أرجع لوی_عدد;
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
lib_لري_نښه(ثابت حرف *لار, ثابت حرف *s)
{
#که_تعریف_شوی HAVE_NLIST
	بنية nlist nl[2];
	صحيح ret = -1, r;

	memset(nl, 0, حجم(nl));
	nl[0].n_name = xstrdup(s);
	nl[1].n_name = عدم;
	إذا ((r = nlist(لار, nl)) == -1) {
		error_f("nlist failed for %s", لار);
		اذهب بهر;
	}
	إذا (r != 0 || nl[0].n_ارزښت == 0 || nl[0].n_type == 0) {
		error_f("library %s does not contain symbol %s", لار, s);
		اذهب بهر;
	}
	/* success */
	ret = 0;
 بهر:
	حرر(nl[0].n_name);
	أرجع ret;
#وإلا /* HAVE_NLIST */
	صحيح fd, ret = -1;
	بنية stat st;
	فراغ *m = عدم;
	اندازه_t sz = 0;

	memset(&st, 0, حجم(st));
	إذا ((fd = open(لار, O_RDONLY)) < 0) {
		error_f("open %s: %s", لار, strerror(errno));
		أرجع -1;
	}
	إذا (fstat(fd, &st) != 0) {
		error_f("fstat %s: %s", لار, strerror(errno));
		اذهب بهر;
	}
	إذا (!S_ISREG(st.st_mode)) {
		error_f("%s is not a regular file", لار);
		اذهب بهر;
	}
	إذا (st.st_size < 0 ||
	    (اندازه_t)st.st_size < مزي_اوږدوالی(s) ||
	    st.st_size >= لوی_عدد/2) {
		error_f("%s bad size %lld", لار, (اوږد اوږد)st.st_size);
		اذهب بهر;
	}
	sz = (اندازه_t)st.st_size;
	إذا ((m = mmap(عدم, sz, PROT_READ, MAP_PRIVATE, fd, 0)) == MAP_FAILED ||
	    m == عدم) {
		error_f("mmap %s: %s", لار, strerror(errno));
		اذهب بهر;
	}
	إذا (memmem(m, sz, s, مزي_اوږدوالی(s)) == عدم) {
		error_f("%s does not contain expected string %s", لار, s);
		اذهب بهر;
	}
	/* success */
	ret = 0;
 بهر:
	إذا (m != عدم && m != MAP_FAILED)
		munmap(m, sz);
	close(fd);
	أرجع ret;
#د_که_پای /* HAVE_NLIST */
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

	إذا ((cp = getenv("HOME")) != عدم && *cp != '\0')
		أرجع xstrdup(cp);

	إذا ((pw = getpwuid(getuid())) != عدم && *pw->pw_dir != '\0')
		أرجع xstrdup(pw->pw_dir);

	أرجع عدم;
}

صحيح
mkdir_لار(ثابت حرف *موخه, ډېرپېښ_t ډېرپېښ)
{
#إذا defined(HAVE_OPENAT) && defined(O_DIRECTORY)
	حرف *dir, *odir = عدم, *بل;
	صحيح fd = AT_FDCWD, fd2, subpath_len, ret = -1;

	dir = odir = xstrdup(موخه);

	إذا (*dir == '/' &&
	    (fd = open("/", O_RDONLY|O_DIRECTORY)) == -1) {
		error_f("open(\"/\"): %s", strerror(errno));
		حرر(odir);
		أرجع -1;
	}
	/* Work through the path, component-wise */
	لكل (; dir != عدم && *dir != '\0'; dir = بل) {
		إذا ((بل = strchr(dir, '/')) != عدم)
			*(بل++) = '\0';
		إذا (*dir == '\0')
			استمر;
		subpath_len = (بل == عدم) ? لوی_عدد : بل - odir - 1;
		إذا (mkdirat(fd, dir, ډېرپېښ) == 0)
			debug_f("created directory %.*s", subpath_len, موخه);
		وإلا إذا (errno != EEXIST) {
			error_f("mkdir(\"%.*s\"): %s",
			    subpath_len, موخه, strerror(errno));
			اذهب بهر;
		}

		/* descend */
		إذا ((fd2 = openat(fd, dir, O_RDONLY|O_DIRECTORY)) == -1) {
			error_f("open(\"%.*s\"): %s",
			    subpath_len, موخه, strerror(errno));
			اذهب بهر;
		}
		إذا (fd != AT_FDCWD)
			close(fd);
		fd = fd2;
	}
	/* success */
	ret = 0;
 بهر:
	حرر(odir);
	إذا (fd != AT_FDCWD)
		close(fd);
	أرجع ret;
#وإلا
	/*
	 * If we don't have openat (which was added in POSIX.1-2008), fall back
	 * to the possibly racy way.
	 */
	حرف *dir, *odir, *p, لار[PATH_MAX] = "";
	صحيح ret = -1;
	اندازه_t plen = حجم(لار);

	dir = odir = xstrdup(موخه);

	/* If the dir is relative, start with cwd. */
	إذا (*dir != '/' && getcwd(لار, plen) == عدم) {
		error_f("getcwd: %s", strerror(errno));
		اذهب بهر;
	}

	/* Work through the path, component-wise */
	طالما ((p = strsep(&dir, "/"))) {
		إذا (*p == '\0')
			استمر;
		إذا (strlcat(لار, "/", plen) >= plen ||
		    strlcat(لار, p, plen) >= plen)
			اذهب بهر;
		إذا (mkdir(لار, ډېرپېښ) == 0)
			debug_f("created directory %s", لار);
		وإلا إذا (errno != EEXIST && errno != EISDIR) {
			error_f("mkdir(\"%s\"): %s", لار, strerror(errno));
			اذهب بهر;
		}
	}
	/* success */
	ret = 0;
 بهر:
	حرر(odir);
	أرجع ret;
#د_که_پای
}
