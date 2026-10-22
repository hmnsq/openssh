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


#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/ioctl.h>
#شامل <sys/mman.h>
#شامل <sys/socket.h>
#شامل <sys/stat.h>
#شامل <sys/time.h>
#شامل <sys/wait.h>
#شامل <sys/un.h>

#شامل <limits.h>
#شامل <libgen.h>
#شامل <poll.h>
#شامل <nlist.h>
#شامل <signal.h>
#شامل <stdarg.h>
#شامل <stdio.h>
#شامل <stdint.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <time.h>
#شامل <unistd.h>

#شامل <netinet/in.h>
#شامل <netinet/ip.h>
#شامل <netinet/tcp.h>
#شامل <arpa/inet.h>

#شامل <ctype.h>
#شامل <errno.h>
#شامل <fcntl.h>
#شامل <netdb.h>
#شامل <paths.h>
#شامل <pwd.h>
#شامل <grp.h>
#اگر_تعریف_شدہ SSH_TUN_OPENBSD
#شامل <net/if.h>
#اگر_ختم

#شامل "xmalloc.h"
#شامل "misc.h"
#شامل "log.h"
#شامل "ssh.h"
#شامل "sshbuf.h"
#شامل "ssherr.h"
#شامل "platform.h"

/* remove newline at end of string */
حرف *
chop(حرف *s)
{
	حرف *t = s;
	جب (*t) {
		اگر (*t == '\n' || *t == '\r') {
			*t = '\0';
			واپس s;
		}
		t++;
	}
	واپس s;

}

/* remove whitespace from end of string */
خالی
rtrim(حرف *s)
{
	سائز_t i;

	اگر ((i = لڑی_لمبائی(s)) == 0)
		واپس;
	کرو {
		i--;
		اگر (خلا_ہے((غیرعلامتی حرف)s[i]))
			s[i] = '\0';
		ورنہ
			توڑو;
	} جب (i > 0);
}

/*
 * returns pointer to character after 'prefix' in 's' or otherwise NULL
 * if the prefix is not present.
 */
ثابت حرف *
strprefix(ثابت حرف *s, ثابت حرف *سابقہ, صحیح ignorecase)
{
	سائز_t prefixlen;

	اگر ((prefixlen = لڑی_لمبائی(سابقہ)) == 0)
		واپس s;
	اگر (ignorecase) {
		اگر (strncasecmp(s, سابقہ, prefixlen) != 0)
			واپس تہی;
	} ورنہ {
		اگر (لڑی_موازنہ(s, سابقہ, prefixlen) != 0)
			واپس تہی;
	}
	واپس s + prefixlen;
}

/* Append string 's' to a NULL-terminated array of strings */
خالی
stringlist_append(حرف ***listp, ثابت حرف *s)
{
	سائز_t i = 0;

	اگر (*listp == تہی)
		*listp = xcalloc(2, حجم(**listp));
	ورنہ {
		برائے (i = 0; (*listp)[i] != تہی; i++)
			; /* count */
		*listp = xrecallocarray(*listp, i + 1, i + 2, حجم(**listp));
	}
	(*listp)[i] = xstrdup(s);
}

خالی
stringlist_free(حرف **list)
{
	سائز_t i = 0;

	اگر (list == تہی)
		واپس;
	برائے (i = 0; list[i] != تہی; i++)
		آزاد(list[i]);
	آزاد(list);
}

/* set/unset filedescriptor to non-blocking */
صحیح
سیٹ_nonblock(صحیح fd)
{
	صحیح val;

	val = fcntl(fd, F_GETFL);
	اگر (val == -1) {
		error("fcntl(%d, F_GETFL): %s", fd, strerror(errno));
		واپس (-1);
	}
	اگر (val & O_NONBLOCK) {
		debug3("fd %d is O_NONBLOCK", fd);
		واپس (0);
	}
	debug2("fd %d setting O_NONBLOCK", fd);
	val |= O_NONBLOCK;
	اگر (fcntl(fd, F_SETFL, val) == -1) {
		debug("fcntl(%d, F_SETFL, O_NONBLOCK): %s", fd,
		    strerror(errno));
		واپس (-1);
	}
	واپس (0);
}

صحیح
unset_nonblock(صحیح fd)
{
	صحیح val;

	val = fcntl(fd, F_GETFL);
	اگر (val == -1) {
		error("fcntl(%d, F_GETFL): %s", fd, strerror(errno));
		واپس (-1);
	}
	اگر (!(val & O_NONBLOCK)) {
		debug3("fd %d is not O_NONBLOCK", fd);
		واپس (0);
	}
	debug("fd %d clearing O_NONBLOCK", fd);
	val &= ~O_NONBLOCK;
	اگر (fcntl(fd, F_SETFL, val) == -1) {
		debug("fcntl(%d, F_SETFL, ~O_NONBLOCK): %s",
		    fd, strerror(errno));
		واپس (-1);
	}
	واپس (0);
}

ثابت حرف *
ssh_gai_strerror(صحیح gaierr)
{
	اگر (gaierr == EAI_SYSTEM && errno != 0)
		واپس strerror(errno);
	واپس gai_strerror(gaierr);
}

/* disable nagle on socket */
خالی
سیٹ_nodelay(صحیح fd)
{
	صحیح opt;
	socklen_t optlen;

	optlen = حجم opt;
	اگر (getsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, &optlen) == -1) {
		debug("getsockopt TCP_NODELAY: %.100s", strerror(errno));
		واپس;
	}
	اگر (opt == 1) {
		debug2("fd %d is TCP_NODELAY", fd);
		واپس;
	}
	opt = 1;
	debug2("fd %d setting TCP_NODELAY", fd);
	اگر (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, حجم opt) == -1)
		error("setsockopt TCP_NODELAY: %.100s", strerror(errno));
}

/* Allow local port reuse in TIME_WAIT */
صحیح
سیٹ_reuseaddr(صحیح fd)
{
	صحیح on = 1;

	اگر (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, حجم(on)) == -1) {
		error("setsockopt SO_REUSEADDR fd %d: %s", fd, strerror(errno));
		واپس -1;
	}
	واپس 0;
}

/* Set TCP keepalives */
صحیح
سیٹ_keepalive(صحیح fd)
{
	صحیح on = 1;

	اگر (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, حجم(on)) == -1) {
		error("setsockopt SO_KEEPALIVE fd %d: %s", fd, strerror(errno));
		واپس -1;
	}
	واپس 0;
}

/* Get/set routing domain */
حرف *
get_rdomain(صحیح fd)
{
#اگر defined(HAVE_SYS_GET_RDOMAIN)
	واپس sys_get_rdomain(fd);
#وگرنہ_اگر defined(__OpenBSD__)
	صحیح rtable;
	حرف *ret;
	socklen_t len = حجم(rtable);

	اگر (getsockopt(fd, SOL_SOCKET, SO_RTABLE, &rtable, &len) == -1) {
		error("Failed to get routing domain for fd %d: %s",
		    fd, strerror(errno));
		واپس تہی;
	}
	xasprintf(&ret, "%d", rtable);
	واپس ret;
#ورنہ /* defined(__OpenBSD__) */
	واپس تہی;
#اگر_ختم
}

صحیح
سیٹ_rdomain(صحیح fd, ثابت حرف *name)
{
#اگر defined(HAVE_SYS_سیٹ_RDOMAIN)
	واپس sys_سیٹ_rdomain(fd, name);
#وگرنہ_اگر defined(__OpenBSD__)
	صحیح rtable;
	ثابت حرف *errstr;

	اگر (name == تہی)
		واپس 0; /* default table */

	rtable = (صحیح)strtonum(name, 0, 255, &errstr);
	اگر (errstr != تہی) {
		/* Shouldn't happen */
		error("Invalid routing domain \"%s\": %s", name, errstr);
		واپس -1;
	}
	اگر (setsockopt(fd, SOL_SOCKET, SO_RTABLE,
	    &rtable, حجم(rtable)) == -1) {
		error("Failed to set routing domain %d on fd %d: %s",
		    rtable, fd, strerror(errno));
		واپس -1;
	}
	واپس 0;
#ورنہ /* defined(__OpenBSD__) */
	error("Setting routing domain is not supported on this platform");
	واپس -1;
#اگر_ختم
}

صحیح
get_sock_af(صحیح fd)
{
	ساخت sockaddr_storage مقصد;
	socklen_t tolen = حجم(مقصد);

	memset(&مقصد, 0, حجم(مقصد));
	اگر (getsockname(fd, (ساخت sockaddr *)&مقصد, &tolen) == -1)
		واپس -1;
#اگر_تعریف_شدہ IPV4_اندر_IPV6
	اگر (مقصد.ss_family == AF_INET6 &&
	    IN6_IS_ADDR_V4MAPPED(&((ساخت sockaddr_in6 *)&مقصد)->sin6_addr))
		واپس AF_INET;
#اگر_ختم
	واپس مقصد.ss_family;
}

خالی
سیٹ_sock_tos(صحیح fd, صحیح tos)
{
#اگر_غیر_تعریف_شدہ IP_TOS_IS_BROKEN
	صحیح af;

	اگر (tos < 0 || tos == زیادہ_سے_زیادہ_عدد) {
		debug_f("invalid TOS %d", tos);
		واپس;
	}
	انتخاب ((af = get_sock_af(fd))) {
	حالت -1:
		/* assume not a socket */
		توڑو;
	حالت AF_INET:
# ifdef IP_TOS
		debug3_f("set socket %d IP_TOS 0x%02x", fd, tos);
		اگر (setsockopt(fd, IPPROTO_IP, IP_TOS,
		    &tos, حجم(tos)) == -1) {
			error("setsockopt socket %d IP_TOS %d: %s",
			    fd, tos, strerror(errno));
		}
# endif /* IP_TOS */
		توڑو;
	حالت AF_INET6:
# ifdef IPV6_TCLASS
		debug3_f("set socket %d IPV6_TCLASS 0x%02x", fd, tos);
		اگر (setsockopt(fd, IPPROTO_IPV6, IPV6_TCLASS,
		    &tos, حجم(tos)) == -1) {
			error("setsockopt socket %d IPV6_TCLASS %d: %s",
			    fd, tos, strerror(errno));
		}
# endif /* IPV6_TCLASS */
		توڑو;
	طےشدہ:
		debug2_f("unsupported socket family %d", af);
		توڑو;
	}
#اگر_ختم /* IP_TOS_IS_BROKEN */
}

/*
 * Wait up to *timeoutp milliseconds for events on fd. Updates
 * *timeoutp with time remaining.
 * Returns 0 if fd ready or -1 on timeout or error (see errno).
 */
ساکن صحیح
waitfd(صحیح fd, صحیح *timeoutp, مختصر events, متلون sig_atomic_t *stop)
{
	ساخت pollfd pfd;
	ساخت timespec timeout;
	صحیح oerrno, r;
	sigset_t nsigset, osigset;

	اگر (timeoutp && *timeoutp == -1)
		timeoutp = تہی;
	pfd.fd = fd;
	pfd.events = events;
	ptimeout_init(&timeout);
	اگر (timeoutp != تہی)
		ptimeout_deadline_ms(&timeout, *timeoutp);
	اگر (stop != تہی)
		sigfillset(&nsigset);
	برائے (; timeoutp == تہی || *timeoutp >= 0;) {
		اگر (stop != تہی) {
			sigprocmask(SIG_BLOCK, &nsigset, &osigset);
			اگر (*stop) {
				sigprocmask(SIG_SETMASK, &osigset, تہی);
				errno = EINTR;
				واپس -1;
			}
		}
		r = ppoll(&pfd, 1, ptimeout_get_tsp(&timeout),
		    stop != تہی ? &osigset : تہی);
		oerrno = errno;
		اگر (stop != تہی)
			sigprocmask(SIG_SETMASK, &osigset, تہی);
		اگر (timeoutp)
			*timeoutp = ptimeout_get_ms(&timeout);
		errno = oerrno;
		اگر (r > 0)
			واپس 0;
		ورنہ اگر (r == -1 && errno != EAGAIN && errno != EINTR)
			واپس -1;
		ورنہ اگر (r == 0)
			توڑو;
	}
	/* timeout */
	errno = ETIMEDOUT;
	واپس -1;
}

/*
 * Wait up to *timeoutp milliseconds for fd to be readable. Updates
 * *timeoutp with time remaining.
 * Returns 0 if fd ready or -1 on timeout or error (see errno).
 */
صحیح
waitrfd(صحیح fd, صحیح *timeoutp, متلون sig_atomic_t *stop) {
	واپس waitfd(fd, timeoutp, POLLIN, stop);
}

/*
 * Attempt a non-blocking connect(2) to the specified address, waiting up to
 * *timeoutp milliseconds for the connection to complete. If the timeout is
 * <=0, then wait indefinitely.
 *
 * Returns 0 on success or -1 on failure.
 */
صحیح
timeout_connect(صحیح sockfd, ثابت ساخت sockaddr *serv_addr,
    socklen_t addrlen, صحیح *timeoutp)
{
	صحیح optval = 0;
	socklen_t optlen = حجم(optval);

	/* No timeout: just do a blocking connect() */
	اگر (timeoutp == تہی || *timeoutp <= 0)
		واپس connect(sockfd, serv_addr, addrlen);

	سیٹ_nonblock(sockfd);
	برائے (;;) {
		اگر (connect(sockfd, serv_addr, addrlen) == 0) {
			/* Succeeded already? */
			unset_nonblock(sockfd);
			واپس 0;
		} ورنہ اگر (errno == EINTR)
			جاری;
		ورنہ اگر (errno != EINPROGRESS)
			واپس -1;
		توڑو;
	}

	اگر (waitfd(sockfd, timeoutp, POLLIN | POLLOUT, تہی) == -1)
		واپس -1;

	/* Completed or failed */
	اگر (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &optval, &optlen) == -1) {
		debug("getsockopt: %s", strerror(errno));
		واپس -1;
	}
	اگر (optval != 0) {
		errno = optval;
		واپس -1;
	}
	unset_nonblock(sockfd);
	واپس 0;
}

/* Characters considered whitespace in strsep calls. */
#تعریف_کرو WHITESPACE " \t\r\n"
#تعریف_کرو QUOTE	"\""

/* return next token in configuration line */
ساکن حرف *
strdelim_اندرونی(حرف **s, صحیح بانٹو_equals)
{
	حرف *old;
	صحیح wspace = 0;

	اگر (*s == تہی)
		واپس تہی;

	old = *s;

	*s = strpbrk(*s,
	    بانٹو_equals ? WHITESPACE QUOTE "=" : WHITESPACE QUOTE);
	اگر (*s == تہی)
		واپس (old);

	اگر (*s[0] == '\"') {
		memmove(*s, *s + 1, لڑی_لمبائی(*s)); /* move nul too */
		/* Find matching quote */
		اگر ((*s = strpbrk(*s, QUOTE)) == تہی) {
			واپس (تہی);		/* no matching quote */
		} ورنہ {
			*s[0] = '\0';
			*s += strspn(*s + 1, WHITESPACE) + 1;
			واپس (old);
		}
	}

	/* Allow only one '=' to be skipped */
	اگر (بانٹو_equals && *s[0] == '=')
		wspace = 1;
	*s[0] = '\0';

	/* Skip any extra whitespace after first token */
	*s += strspn(*s + 1, WHITESPACE) + 1;
	اگر (بانٹو_equals && *s[0] == '=' && !wspace)
		*s += strspn(*s + 1, WHITESPACE) + 1;

	واپس (old);
}

/*
 * Return next token in configuration line; splits on whitespace or a
 * single '=' character.
 */
حرف *
strdelim(حرف **s)
{
	واپس strdelim_اندرونی(s, 1);
}

/*
 * Return next token in configuration line; splits on whitespace only.
 */
حرف *
strdelimw(حرف **s)
{
	واپس strdelim_اندرونی(s, 0);
}

ساخت passwd *
pwcopy(ساخت passwd *pw)
{
	ساخت passwd *copy = xcalloc(1, حجم(*copy));

	copy->pw_name = xstrdup(pw->pw_name);
	copy->pw_passwd = xstrdup(pw->pw_passwd == تہی ? "*" : pw->pw_passwd);
#اگر_تعریف_شدہ HAVE_STRUCT_PASSWD_PW_GECOS
	copy->pw_gecos = xstrdup(pw->pw_gecos == تہی ? "" : pw->pw_gecos);
#اگر_ختم
	copy->pw_uid = pw->pw_uid;
	copy->pw_gid = pw->pw_gid;
#اگر_تعریف_شدہ HAVE_STRUCT_PASSWD_PW_EXPIRE
	copy->pw_expire = pw->pw_expire;
#اگر_ختم
#اگر_تعریف_شدہ HAVE_STRUCT_PASSWD_PW_CHANGE
	copy->pw_change = pw->pw_change;
#اگر_ختم
#اگر_تعریف_شدہ HAVE_STRUCT_PASSWD_PW_CLASS
	copy->pw_class = xstrdup(pw->pw_class == تہی ? "" : pw->pw_class);
#اگر_ختم
	copy->pw_dir = xstrdup(pw->pw_dir == تہی ? "" : pw->pw_dir);
	copy->pw_shell = xstrdup(pw->pw_shell == تہی ? "" : pw->pw_shell);
	واپس copy;
}

خالی
pwfree(ساخت passwd *pw)
{
	اگر (pw == تہی)
		واپس;
	آزاد(pw->pw_name);
	freezero(pw->pw_passwd,
	    pw->pw_passwd == تہی ? 0 : لڑی_لمبائی(pw->pw_passwd));
#اگر_تعریف_شدہ HAVE_STRUCT_PASSWD_PW_GECOS
	آزاد(pw->pw_gecos);
#اگر_ختم
#اگر_تعریف_شدہ HAVE_STRUCT_PASSWD_PW_CLASS
	آزاد(pw->pw_class);
#اگر_ختم
	آزاد(pw->pw_dir);
	آزاد(pw->pw_shell);
	freezero(pw, حجم(*pw));
}

/*
 * Convert ASCII string to TCP/IP port number.
 * Port must be >=0 and <=65535.
 * Return -1 if invalid.
 */
صحیح
a2port(ثابت حرف *s)
{
	ساخت servent *se;
	طویل طویل پورٹ;
	ثابت حرف *errstr;

	پورٹ = strtonum(s, 0, 65535, &errstr);
	اگر (errstr == تہی)
		واپس (صحیح)پورٹ;
	اگر ((se = getservbyname(s, "tcp")) != تہی)
		واپس ntohs(se->s_port);
	واپس -1;
}

صحیح
a2tun(ثابت حرف *s, صحیح *remote)
{
	ثابت حرف *errstr = تہی;
	حرف *sp, *ep;
	صحیح tun;

	اگر (remote != تہی) {
		*remote = SSH_TUNID_ANY;
		sp = xstrdup(s);
		اگر ((ep = strchr(sp, ':')) == تہی) {
			آزاد(sp);
			واپس (a2tun(s, تہی));
		}
		ep[0] = '\0'; ep++;
		*remote = a2tun(ep, تہی);
		tun = a2tun(sp, تہی);
		آزاد(sp);
		واپس (*remote == SSH_TUNID_ERR ? *remote : tun);
	}

	اگر (strcasecmp(s, "any") == 0)
		واپس (SSH_TUNID_ANY);

	tun = strtonum(s, 0, SSH_TUNID_MAX, &errstr);
	اگر (errstr != تہی)
		واپس (SSH_TUNID_ERR);

	واپس (tun);
}

#تعریف_کرو SECONDS		1.0
#تعریف_کرو MINUTES		(SECONDS * 60)
#تعریف_کرو HOURS		(MINUTES * 60)
#تعریف_کرو DAYS		(HOURS * 24)
#تعریف_کرو WEEKS		(DAYS * 7)

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
دوہرا
convtime_double(ثابت حرف *s)
{
	دوہرا val, کل_sec = 0.0, multiplier;
	ثابت حرف *p, *آغاز_p;
	حرف *endp;
	صحیح نظر_آیا_seconds = 0;

	اگر (s == تہی || *s == '\0')
		واپس -1.0;

	برائے (p = s; *p != '\0';) {
		اگر (!ہندسہ_ہے((غیرعلامتی حرف)*p) && *p != '.')
			واپس -1.0;

		errno = 0;
		اگر ((val = strtod(p, &endp)) < 0 || errno != 0 || p == endp)
			واپس -1.0;
		/* Allow only decimal forms */
		اگر (p + strspn(p, "0123456789.") != endp)
			واپس -1.0;
		آغاز_p = p;
		p = endp;

		انتخاب (*p) {
		حالت '\0':
			/* FALLTHROUGH */
		حالت 's':
		حالت 'S':
			اگر (نظر_آیا_seconds++)
				واپس -1.0;
			multiplier = SECONDS;
			توڑو;
		حالت 'm':
		حالت 'M':
			multiplier = MINUTES;
			توڑو;
		حالت 'h':
		حالت 'H':
			multiplier = HOURS;
			توڑو;
		حالت 'd':
		حالت 'D':
			multiplier = DAYS;
			توڑو;
		حالت 'w':
		حالت 'W':
			multiplier = WEEKS;
			توڑو;
		طےشدہ:
			واپس -1.0;
		}

		/* Special handling if this was a decimal */
		اگر (memchr(آغاز_p, '.', endp - آغاز_p) != تہی) {
			/* Decimal point present */
			اگر (multiplier > 1.0)
				واپس -1.0; /* No fractionals for non-seconds */
			/* For seconds, ensure digits follow */
			اگر (!ہندسہ_ہے((غیرعلامتی حرف)*(endp - 1)))
				واپس -1.0;
		}

		کل_sec += val * multiplier;

		اگر (*p != '\0')
			p++;
	}
	واپس کل_sec;
}

/*
 * Same as convtime_double() above but fractional seconds are ignored.
 * Return -1 if time string is invalid.
 */
صحیح
convtime(ثابت حرف *s)
{
	دوہرا sec_val;

	اگر ((sec_val = convtime_double(s)) < 0.0)
		واپس -1;

	/* Check for overflow into int */
	اگر (sec_val < 0 || sec_val > زیادہ_سے_زیادہ_عدد)
		واپس -1;

	واپس (صحیح)sec_val;
}

#تعریف_کرو TF_BUFS	8
#تعریف_کرو TF_LEN	9

ثابت حرف *
fmt_timeframe(time_t t)
{
	حرف		*buf;
	ساکن حرف	 tfbuf[TF_BUFS][TF_LEN];	/* ring buffer */
	ساکن صحیح	 idx = 0;
	غیرعلامتی صحیح	 sec, min, hrs, day;
	غیرعلامتی طویل طویل	week;

	buf = tfbuf[idx++];
	اگر (idx == TF_BUFS)
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

	اگر (week > 0)
		snprintf(buf, TF_LEN, "%02lluw%01ud%02uh", week, day, hrs);
	ورنہ اگر (day > 0)
		snprintf(buf, TF_LEN, "%01ud%02uh%02um", day, hrs, min);
	ورنہ
		snprintf(buf, TF_LEN, "%02u:%02u:%02u", hrs, min, sec);

	واپس (buf);
}

/*
 * Returns a standardized host+port identifier string.
 * Caller must free returned string.
 */
حرف *
put_host_پورٹ(ثابت حرف *host, u_short پورٹ)
{
	حرف *hoststr;

	اگر (پورٹ == 0 || پورٹ == SSH_DEFAULT_پورٹ)
		واپس(xstrdup(host));
	اگر (asprintf(&hoststr, "[%s]:%d", host, (صحیح)پورٹ) == -1)
		fatal("put_host_port: asprintf: %s", strerror(errno));
	debug3("put_host_port: %s", hoststr);
	واپس hoststr;
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

	اگر (cp == تہی || *cp == تہی)
		واپس تہی;

	old = s = *cp;
	اگر (*s == '[') {
		اگر ((s = strchr(s, ']')) == تہی)
			واپس تہی;
		ورنہ
			s++;
	} ورنہ اگر ((s = strpbrk(s, ":/")) == تہی)
		s = *cp + لڑی_لمبائی(*cp); /* skip to end (see first case below) */

	انتخاب (*s) {
	حالت '\0':
		*cp = تہی;	/* no more fields*/
		توڑو;

	حالت ':':
	حالت '/':
		اگر (delim != تہی)
			*delim = *s;
		*s = '\0';	/* terminate */
		*cp = s + 1;
		توڑو;

	طےشدہ:
		واپس تہی;
	}

	واپس old;
}

/* The common case: only accept colon as delimiter. */
حرف *
hpdelim(حرف **cp)
{
	حرف *r, delim = '\0';

	r =  hpdelim2(cp, &delim);
	اگر (delim == '/')
		واپس تہی;
	واپس r;
}

حرف *
cleanhostname(حرف *host)
{
	اگر (*host == '[' && host[لڑی_لمبائی(host) - 1] == ']') {
		host[لڑی_لمبائی(host) - 1] = '\0';
		واپس (host + 1);
	} ورنہ
		واپس host;
}

حرف *
colon(حرف *cp)
{
	صحیح flag = 0;

	اگر (*cp == ':')		/* Leading colon is part of file name. */
		واپس تہی;
	اگر (*cp == '[')
		flag = 1;

	برائے (; *cp; ++cp) {
		اگر (*cp == '@' && *(cp+1) == '[')
			flag = 1;
		اگر (*cp == ']' && *(cp+1) == ':' && flag)
			واپس (cp+1);
		اگر (*cp == ':' && !flag)
			واپس (cp);
		اگر (*cp == '/')
			واپس تہی;
	}
	واپس تہی;
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
صحیح
parse_user_host_راستہ(ثابت حرف *s, حرف **userp, حرف **hostp, حرف **pathp)
{
	حرف *user = تہی, *host = تہی, *راستہ = تہی;
	حرف *sdup, *tmp;
	صحیح ret = -1;

	اگر (userp != تہی)
		*userp = تہی;
	اگر (hostp != تہی)
		*hostp = تہی;
	اگر (pathp != تہی)
		*pathp = تہی;

	sdup = xstrdup(s);

	/* Check for remote syntax: [user@]host:[path] */
	اگر ((tmp = colon(sdup)) == تہی)
		جاؤ برآمد;

	/* Extract optional path */
	*tmp++ = '\0';
	اگر (*tmp == '\0')
		tmp = ".";
	راستہ = xstrdup(tmp);

	/* Extract optional user and mandatory host */
	tmp = strrchr(sdup, '@');
	اگر (tmp != تہی) {
		*tmp++ = '\0';
		host = xstrdup(cleanhostname(tmp));
		اگر (*sdup != '\0')
			user = xstrdup(sdup);
	} ورنہ {
		host = xstrdup(cleanhostname(sdup));
		user = تہی;
	}

	/* Success */
	اگر (userp != تہی) {
		*userp = user;
		user = تہی;
	}
	اگر (hostp != تہی) {
		*hostp = host;
		host = تہی;
	}
	اگر (pathp != تہی) {
		*pathp = راستہ;
		راستہ = تہی;
	}
	ret = 0;
برآمد:
	آزاد(sdup);
	آزاد(user);
	آزاد(host);
	آزاد(راستہ);
	واپس ret;
}

/*
 * Parse a [user@]host[:port] string.
 * Caller must free returned user and host.
 * Any of the pointer return arguments may be NULL (useful for syntax checking).
 * If user was not specified then *userp will be set to NULL.
 * If port was not specified then *portp will be -1.
 * Returns 0 on success, -1 on failure.
 */
صحیح
parse_user_host_پورٹ(ثابت حرف *s, حرف **userp, حرف **hostp, صحیح *portp)
{
	حرف *sdup, *cp, *tmp;
	حرف *user = تہی, *host = تہی;
	صحیح پورٹ = -1, ret = -1;

	اگر (userp != تہی)
		*userp = تہی;
	اگر (hostp != تہی)
		*hostp = تہی;
	اگر (portp != تہی)
		*portp = -1;

	اگر ((sdup = tmp = strdup(s)) == تہی)
		واپس -1;
	/* Extract optional username */
	اگر ((cp = strrchr(tmp, '@')) != تہی) {
		*cp = '\0';
		اگر (*tmp == '\0')
			جاؤ برآمد;
		اگر ((user = strdup(tmp)) == تہی)
			جاؤ برآمد;
		tmp = cp + 1;
	}
	/* Extract mandatory hostname */
	اگر ((cp = hpdelim(&tmp)) == تہی || *cp == '\0')
		جاؤ برآمد;
	host = xstrdup(cleanhostname(cp));
	/* Convert and verify optional port */
	اگر (tmp != تہی && *tmp != '\0') {
		اگر ((پورٹ = a2port(tmp)) <= 0)
			جاؤ برآمد;
	}
	/* Success */
	اگر (userp != تہی) {
		*userp = user;
		user = تہی;
	}
	اگر (hostp != تہی) {
		*hostp = host;
		host = تہی;
	}
	اگر (portp != تہی)
		*portp = پورٹ;
	ret = 0;
 برآمد:
	آزاد(sdup);
	آزاد(user);
	آزاد(host);
	واپس ret;
}

/*
 * Converts a two-byte hex string to decimal.
 * Returns the decimal value or -1 for invalid input.
 */
ساکن صحیح
hexchar(ثابت حرف *s)
{
	غیرعلامتی حرف نتیجہ[2];
	صحیح i;

	برائے (i = 0; i < 2; i++) {
		اگر (s[i] >= '0' && s[i] <= '9')
			نتیجہ[i] = (غیرعلامتی حرف)(s[i] - '0');
		ورنہ اگر (s[i] >= 'a' && s[i] <= 'f')
			نتیجہ[i] = (غیرعلامتی حرف)(s[i] - 'a') + 10;
		ورنہ اگر (s[i] >= 'A' && s[i] <= 'F')
			نتیجہ[i] = (غیرعلامتی حرف)(s[i] - 'A') + 10;
		ورنہ
			واپس -1;
	}
	واپس (نتیجہ[0] << 4) | نتیجہ[1];
}

/*
 * Decode an url-encoded string.
 * Returns a newly allocated string on success or NULL on failure.
 */
ساکن حرف *
urldecode(ثابت حرف *src)
{
	حرف *ret, *dst;
	صحیح ch;
	سائز_t srclen;

	اگر ((srclen = لڑی_لمبائی(src)) >= SIZE_MAX)
		واپس تہی;
	ret = xmalloc(srclen + 1);
	برائے (dst = ret; *src != '\0'; src++) {
		انتخاب (*src) {
		حالت '+':
			*dst++ = ' ';
			توڑو;
		حالت '%':
			/* note: don't allow \0 characters */
			اگر (!isxdigit((غیرعلامتی حرف)src[1]) ||
			    !isxdigit((غیرعلامتی حرف)src[2]) ||
			    (ch = hexchar(src + 1)) == -1 || ch == 0) {
				آزاد(ret);
				واپس تہی;
			}
			*dst++ = ch;
			src += 2;
			توڑو;
		طےشدہ:
			*dst++ = *src;
			توڑو;
		}
	}
	*dst = '\0';

	واپس ret;
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
صحیح
parse_uri(ثابت حرف *scheme, ثابت حرف *uri, حرف **userp, حرف **hostp,
    صحیح *portp, حرف **pathp)
{
	حرف *uridup, *cp, *tmp, ch;
	حرف *user = تہی, *host = تہی, *راستہ = تہی;
	صحیح پورٹ = -1, ret = -1;
	سائز_t len;

	len = لڑی_لمبائی(scheme);
	اگر (لڑی_موازنہ(uri, scheme, len) != 0 || لڑی_موازنہ(uri + len, "://", 3) != 0)
		واپس 1;
	uri += len + 3;

	اگر (userp != تہی)
		*userp = تہی;
	اگر (hostp != تہی)
		*hostp = تہی;
	اگر (portp != تہی)
		*portp = -1;
	اگر (pathp != تہی)
		*pathp = تہی;

	uridup = tmp = xstrdup(uri);

	/* Extract optional ssh-info (username + connection params) */
	اگر ((cp = strchr(tmp, '@')) != تہی) {
		حرف *delim;

		*cp = '\0';
		/* Extract username and connection params */
		اگر ((delim = strchr(tmp, ';')) != تہی) {
			/* Just ignore connection params for now */
			*delim = '\0';
		}
		اگر (*tmp == '\0') {
			/* Empty username */
			جاؤ برآمد;
		}
		اگر ((user = urldecode(tmp)) == تہی)
			جاؤ برآمد;
		tmp = cp + 1;
	}

	/* Extract mandatory hostname */
	اگر ((cp = hpdelim2(&tmp, &ch)) == تہی || *cp == '\0')
		جاؤ برآمد;
	host = xstrdup(cleanhostname(cp));
	اگر (!valid_domain(host, 0, تہی))
		جاؤ برآمد;

	اگر (tmp != تہی && *tmp != '\0') {
		اگر (ch == ':') {
			/* Convert and verify port. */
			اگر ((cp = strchr(tmp, '/')) != تہی)
				*cp = '\0';
			اگر ((پورٹ = a2port(tmp)) <= 0)
				جاؤ برآمد;
			tmp = cp ? cp + 1 : تہی;
		}
		اگر (tmp != تہی && *tmp != '\0') {
			/* Extract optional path */
			اگر ((راستہ = urldecode(tmp)) == تہی)
				جاؤ برآمد;
		}
	}

	/* Success */
	اگر (userp != تہی) {
		*userp = user;
		user = تہی;
	}
	اگر (hostp != تہی) {
		*hostp = host;
		host = تہی;
	}
	اگر (portp != تہی)
		*portp = پورٹ;
	اگر (pathp != تہی) {
		*pathp = راستہ;
		راستہ = تہی;
	}
	ret = 0;
 برآمد:
	آزاد(uridup);
	آزاد(user);
	آزاد(host);
	آزاد(راستہ);
	واپس ret;
}

/* function to assist building execv() arguments */
خالی
addargs(arglist *دلائل, حرف *fmt, ...)
{
	va_list ap;
	حرف *cp;
	u_int nalloc;
	صحیح r;

	va_start(ap, fmt);
	r = vasprintf(&cp, fmt, ap);
	va_end(ap);
	اگر (r == -1)
		fatal_f("argument too long");

	nalloc = دلائل->nalloc;
	اگر (دلائل->list == تہی) {
		nalloc = 32;
		دلائل->عدد = 0;
	} ورنہ اگر (دلائل->عدد > (256 * 1024))
		fatal_f("too many arguments");
	ورنہ اگر (دلائل->عدد >= دلائل->nalloc)
		fatal_f("arglist corrupt");
	ورنہ اگر (دلائل->عدد+2 >= nalloc)
		nalloc *= 2;

	دلائل->list = xrecallocarray(دلائل->list, دلائل->nalloc,
	    nalloc, حجم(حرف *));
	دلائل->nalloc = nalloc;
	دلائل->list[دلائل->عدد++] = cp;
	دلائل->list[دلائل->عدد] = تہی;
}

خالی
replacearg(arglist *دلائل, u_int which, حرف *fmt, ...)
{
	va_list ap;
	حرف *cp;
	صحیح r;

	va_start(ap, fmt);
	r = vasprintf(&cp, fmt, ap);
	va_end(ap);
	اگر (r == -1)
		fatal_f("argument too long");
	اگر (دلائل->list == تہی || دلائل->عدد >= دلائل->nalloc)
		fatal_f("arglist corrupt");

	اگر (which >= دلائل->عدد)
		fatal_f("tried to replace invalid arg %d >= %d",
		    which, دلائل->عدد);
	آزاد(دلائل->list[which]);
	دلائل->list[which] = cp;
}

خالی
freeargs(arglist *دلائل)
{
	u_int i;

	اگر (دلائل == تہی)
		واپس;
	اگر (دلائل->list != تہی && دلائل->عدد < دلائل->nalloc) {
		برائے (i = 0; i < دلائل->عدد; i++)
			آزاد(دلائل->list[i]);
		آزاد(دلائل->list);
	}
	دلائل->nalloc = دلائل->عدد = 0;
	دلائل->list = تہی;
}

/*
 * Expands tildes in the file name.  Returns data allocated by xmalloc.
 * Warning: this calls getpw*.
 */
صحیح
tilde_expand(ثابت حرف *filename, uid_t uid, حرف **retp)
{
	حرف *ocopy = تہی, *copy, *s = تہی;
	ثابت حرف *راستہ = تہی, *user = تہی;
	ساخت passwd *pw;
	سائز_t len;
	صحیح ret = -1, r, slash;

	*retp = تہی;
	اگر (*filename != '~') {
		*retp = xstrdup(filename);
		واپس 0;
	}
	ocopy = copy = xstrdup(filename + 1);

	اگر (*copy == '\0')				/* ~ */
		راستہ = تہی;
	ورنہ اگر (*copy == '/') {
		copy += strspn(copy, "/");
		اگر (*copy == '\0')
			راستہ = تہی;			/* ~/ */
		ورنہ
			راستہ = copy;			/* ~/path */
	} ورنہ {
		user = copy;
		اگر ((راستہ = strchr(copy, '/')) != تہی) {
			copy[راستہ - copy] = '\0';
			راستہ++;
			راستہ += strspn(راستہ, "/");
			اگر (*راستہ == '\0')		/* ~user/ */
				راستہ = تہی;
			/* else				 ~user/path */
		}
		/* else					~user */
	}
	اگر (user != تہی) {
		اگر ((pw = getpwnam(user)) == تہی) {
			error_f("No such user %s", user);
			جاؤ برآمد;
		}
	} ورنہ اگر ((pw = getpwuid(uid)) == تہی) {
		error_f("No such uid %ld", (طویل)uid);
		جاؤ برآمد;
	}

	/* Make sure directory has a trailing '/' */
	slash = (len = لڑی_لمبائی(pw->pw_dir)) == 0 || pw->pw_dir[len - 1] != '/';

	اگر ((r = xasprintf(&s, "%s%s%s", pw->pw_dir,
	    slash ? "/" : "", راستہ != تہی ? راستہ : "")) <= 0) {
		error_f("xasprintf failed");
		جاؤ برآمد;
	}
	اگر (r >= PATH_MAX) {
		error_f("Path too long");
		جاؤ برآمد;
	}
	/* success */
	ret = 0;
	*retp = s;
	s = تہی;
 برآمد:
	آزاد(s);
	آزاد(ocopy);
	واپس ret;
}

حرف *
tilde_expand_filename(ثابت حرف *filename, uid_t uid)
{
	حرف *ret;

	اگر (tilde_expand(filename, uid, &ret) != 0)
		cleanup_exit(255);
	واپس ret;
}

/*
 * Expand a string with a set of %[char] escapes and/or ${ENVIRONMENT}
 * substitutions.  A number of escapes may be specified as
 * (char *escape_chars, char *replacement) pairs. The list must be terminated
 * by a NULL escape_char. Returns replaced string in memory allocated by
 * xmalloc which the caller must free.
 */
ساکن حرف *
vdollar_percent_expand(صحیح *parseerror, صحیح dollar, صحیح percent,
    ثابت حرف *string, va_list ap)
{
#تعریف_کرو EXPAND_MAX_کلیدیں	64
	u_int عدد_کلیدیں = 0, i;
	ساخت {
		ثابت حرف *کلید;
		ثابت حرف *repl;
	} کلیدیں[EXPAND_MAX_کلیدیں];
	ساخت sshbuf *buf;
	صحیح r, missingvar = 0;
	حرف *ret = تہی, *var, *varend, *val;
	سائز_t len;

	اگر ((buf = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	اگر (parseerror == تہی)
		fatal_f("null parseerror arg");
	*parseerror = 1;

	/* Gather keys if we're doing percent expansion. */
	اگر (percent) {
		برائے (عدد_کلیدیں = 0; عدد_کلیدیں < EXPAND_MAX_کلیدیں; عدد_کلیدیں++) {
			کلیدیں[عدد_کلیدیں].کلید = va_arg(ap, حرف *);
			اگر (کلیدیں[عدد_کلیدیں].کلید == تہی)
				توڑو;
			کلیدیں[عدد_کلیدیں].repl = va_arg(ap, حرف *);
			اگر (کلیدیں[عدد_کلیدیں].repl == تہی) {
				fatal_f("NULL replacement for token %s",
				    کلیدیں[عدد_کلیدیں].کلید);
			}
		}
		اگر (عدد_کلیدیں == EXPAND_MAX_کلیدیں && va_arg(ap, حرف *) != تہی)
			fatal_f("too many keys");
		اگر (عدد_کلیدیں == 0)
			fatal_f("percent expansion without token list");
	}

	/* Expand string */
	برائے (i = 0; *string != '\0'; string++) {
		/* Optionally process ${ENVIRONMENT} expansions. */
		اگر (dollar && string[0] == '$' && string[1] == '{') {
			string += 2;  /* skip over '${' */
			اگر ((varend = strchr(string, '}')) == تہی) {
				error_f("environment variable '%s' missing "
				    "closing '}'", string);
				جاؤ برآمد;
			}
			len = varend - string;
			اگر (len == 0) {
				error_f("zero-length environment variable");
				جاؤ برآمد;
			}
			var = xmalloc(len + 1);
			(خالی)strlcpy(var, string, len + 1);
			اگر ((val = getenv(var)) == تہی) {
				error_f("env var ${%s} has no value", var);
				missingvar = 1;
			} ورنہ {
				debug3_f("expand ${%s} -> '%s'", var, val);
				اگر ((r = sshbuf_put(buf, val, لڑی_لمبائی(val))) !=0)
					fatal_fr(r, "sshbuf_put ${}");
			}
			آزاد(var);
			string += len;
			جاری;
		}

		/*
		 * Process percent expansions if we have a list of TOKENs.
		 * If we're not doing percent expansion everything just gets
		 * appended here.
		 */
		اگر (*string != '%' || !percent) {
 append:
			اگر ((r = sshbuf_put_u8(buf, *string)) != 0)
				fatal_fr(r, "sshbuf_put_u8 %%");
			جاری;
		}
		string++;
		/* %% case */
		اگر (*string == '%')
			جاؤ append;
		اگر (*string == '\0') {
			error_f("invalid format");
			جاؤ برآمد;
		}
		برائے (i = 0; i < عدد_کلیدیں; i++) {
			اگر (strchr(کلیدیں[i].کلید, *string) != تہی) {
				اگر ((r = sshbuf_put(buf, کلیدیں[i].repl,
				    لڑی_لمبائی(کلیدیں[i].repl))) != 0)
					fatal_fr(r, "sshbuf_put %%-repl");
				توڑو;
			}
		}
		اگر (i >= عدد_کلیدیں) {
			error_f("unknown key %%%c", *string);
			جاؤ برآمد;
		}
	}
	اگر (!missingvar && (ret = sshbuf_dup_string(buf)) == تہی)
		fatal_f("sshbuf_dup_string failed");
	*parseerror = 0;
 برآمد:
	sshbuf_free(buf);
	واپس *parseerror ? تہی : ret;
#تعریف_منسوخ EXPAND_MAX_کلیدیں
}

/*
 * Expand only environment variables.
 * Note that although this function is variadic like the other similar
 * functions, any such arguments will be unused.
 */

حرف *
dollar_expand(صحیح *parseerr, ثابت حرف *string, ...)
{
	حرف *ret;
	صحیح err;
	va_list ap;

	va_start(ap, string);
	ret = vdollar_percent_expand(&err, 1, 0, string, ap);
	va_end(ap);
	اگر (parseerr != تہی)
		*parseerr = err;
	واپس ret;
}

/*
 * Returns expanded string or NULL if a specified environment variable is
 * not defined, or calls fatal if the string is invalid.
 */
حرف *
percent_expand(ثابت حرف *string, ...)
{
	حرف *ret;
	صحیح err;
	va_list ap;

	va_start(ap, string);
	ret = vdollar_percent_expand(&err, 0, 1, string, ap);
	va_end(ap);
	اگر (err)
		fatal_f("failed");
	واپس ret;
}

/*
 * Returns expanded string or NULL if a specified environment variable is
 * not defined, or calls fatal if the string is invalid.
 */
حرف *
percent_dollar_expand(ثابت حرف *string, ...)
{
	حرف *ret;
	صحیح err;
	va_list ap;

	va_start(ap, string);
	ret = vdollar_percent_expand(&err, 1, 1, string, ap);
	va_end(ap);
	اگر (err)
		fatal_f("failed");
	واپس ret;
}

صحیح
tun_open(صحیح tun, صحیح منوال, حرف **ifname)
{
#اگر defined(CUSTOM_SYS_TUN_OPEN)
	واپس (sys_tun_open(tun, منوال, ifname));
#وگرنہ_اگر defined(SSH_TUN_OPENBSD)
	ساخت ifreq ifr;
	حرف name[100];
	صحیح fd = -1, sock;
	ثابت حرف *tunbase = "tun";

	اگر (ifname != تہی)
		*ifname = تہی;

	اگر (منوال == SSH_TUNMODE_ETHERNET)
		tunbase = "tap";

	/* Open the tunnel device */
	اگر (tun <= SSH_TUNID_MAX) {
		snprintf(name, حجم(name), "/dev/%s%d", tunbase, tun);
		fd = open(name, O_RDWR);
	} ورنہ اگر (tun == SSH_TUNID_ANY) {
		برائے (tun = 100; tun >= 0; tun--) {
			snprintf(name, حجم(name), "/dev/%s%d",
			    tunbase, tun);
			اگر ((fd = open(name, O_RDWR)) >= 0)
				توڑو;
		}
	} ورنہ {
		debug_f("invalid tunnel %u", tun);
		واپس -1;
	}

	اگر (fd == -1) {
		debug_f("%s open: %s", name, strerror(errno));
		واپس -1;
	}

	debug_f("%s mode %d fd %d", name, منوال, fd);

	/* Bring interface up if it is not already */
	snprintf(ifr.ifr_name, حجم(ifr.ifr_name), "%s%d", tunbase, tun);
	اگر ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
		جاؤ failed;

	اگر (ioctl(sock, SIOCGIFFLAGS, &ifr) == -1) {
		debug_f("get interface %s flags: %s", ifr.ifr_name,
		    strerror(errno));
		جاؤ failed;
	}

	اگر (!(ifr.ifr_flags & IFF_UP)) {
		ifr.ifr_flags |= IFF_UP;
		اگر (ioctl(sock, SIOCSIFFLAGS, &ifr) == -1) {
			debug_f("activate interface %s: %s", ifr.ifr_name,
			    strerror(errno));
			جاؤ failed;
		}
	}

	اگر (ifname != تہی)
		*ifname = xstrdup(ifr.ifr_name);

	close(sock);
	واپس fd;

 failed:
	اگر (fd >= 0)
		close(fd);
	اگر (sock >= 0)
		close(sock);
	واپس -1;
#ورنہ
	error("Tunnel interfaces are not supported on this platform");
	واپس (-1);
#اگر_ختم
}

خالی
sanitise_stdfd(خالی)
{
	صحیح nullfd, dupfd;

	اگر ((nullfd = dupfd = open(_PATH_DEVNULL, O_RDWR)) == -1) {
		fprintf(stderr, "Couldn't open /dev/null: %s\n",
		    strerror(errno));
		باہر_نکلو(1);
	}
	جب (++dupfd <= STDERR_FILENO) {
		/* Only populate closed fds. */
		اگر (fcntl(dupfd, F_GETFL) == -1 && errno == EBADF) {
			اگر (dup2(nullfd, dupfd) == -1) {
				fprintf(stderr, "dup2: %s\n", strerror(errno));
				باہر_نکلو(1);
			}
		}
	}
	اگر (nullfd > STDERR_FILENO)
		close(nullfd);
}

حرف *
tohex(ثابت خالی *vp, سائز_t l)
{
	ثابت u_char *p = (ثابت u_char *)vp;
	حرف b[3], *r;
	سائز_t i, hl;

	اگر (l > 65536)
		واپس xstrdup("tohex: length > 65536");

	hl = l * 2 + 1;
	r = xcalloc(1, hl);
	برائے (i = 0; i < l; i++) {
		snprintf(b, حجم(b), "%02x", p[i]);
		strlcat(r, b, hl);
	}
	واپس (r);
}

/*
 * Extend string *sp by the specified format. If *sp is not NULL (or empty),
 * then the separator 'sep' will be prepended before the formatted arguments.
 * Extended strings are heap allocated.
 */
خالی
xextendf(حرف **sp, ثابت حرف *sep, ثابت حرف *fmt, ...)
{
	va_list ap;
	حرف *tmp1, *tmp2;

	va_start(ap, fmt);
	xvasprintf(&tmp1, fmt, ap);
	va_end(ap);

	اگر (*sp == تہی || **sp == '\0') {
		آزاد(*sp);
		*sp = tmp1;
		واپس;
	}
	xasprintf(&tmp2, "%s%s%s", *sp, sep == تہی ? "" : sep, tmp1);
	آزاد(tmp1);
	آزاد(*sp);
	*sp = tmp2;
}


uint64_t
get_u64(ثابت خالی *vp)
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

	واپس (v);
}

uint32_t
get_u32(ثابت خالی *vp)
{
	ثابت u_char *p = (ثابت u_char *)vp;
	uint32_t v;

	v  = (uint32_t)p[0] << 24;
	v |= (uint32_t)p[1] << 16;
	v |= (uint32_t)p[2] << 8;
	v |= (uint32_t)p[3];

	واپس (v);
}

uint32_t
get_u32_le(ثابت خالی *vp)
{
	ثابت u_char *p = (ثابت u_char *)vp;
	uint32_t v;

	v  = (uint32_t)p[0];
	v |= (uint32_t)p[1] << 8;
	v |= (uint32_t)p[2] << 16;
	v |= (uint32_t)p[3] << 24;

	واپس (v);
}

uint16_t
get_u16(ثابت خالی *vp)
{
	ثابت u_char *p = (ثابت u_char *)vp;
	uint16_t v;

	v  = (uint16_t)p[0] << 8;
	v |= (uint16_t)p[1];

	واپس (v);
}

خالی
put_u64(خالی *vp, uint64_t v)
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

خالی
put_u32(خالی *vp, uint32_t v)
{
	u_char *p = (u_char *)vp;

	p[0] = (u_char)(v >> 24) & 0xff;
	p[1] = (u_char)(v >> 16) & 0xff;
	p[2] = (u_char)(v >> 8) & 0xff;
	p[3] = (u_char)v & 0xff;
}

خالی
put_u32_le(خالی *vp, uint32_t v)
{
	u_char *p = (u_char *)vp;

	p[0] = (u_char)v & 0xff;
	p[1] = (u_char)(v >> 8) & 0xff;
	p[2] = (u_char)(v >> 16) & 0xff;
	p[3] = (u_char)(v >> 24) & 0xff;
}

خالی
put_u16(خالی *vp, uint16_t v)
{
	u_char *p = (u_char *)vp;

	p[0] = (u_char)(v >> 8) & 0xff;
	p[1] = (u_char)v & 0xff;
}

خالی
ms_تفریق_diff(ساخت timeval *آغاز, صحیح *ms)
{
	ساخت timeval diff, اختتام;

	monotime_tv(&اختتام);
	timersub(&اختتام, آغاز, &diff);
	*ms -= (diff.tv_sec * 1000) + (diff.tv_usec / 1000);
}

خالی
ms_مقصد_timespec(ساخت timespec *ts, صحیح ms)
{
	اگر (ms < 0)
		ms = 0;
	ts->tv_sec = ms / 1000;
	ts->tv_nsec = (ms % 1000) * 1000 * 1000;
}

خالی
monotime_ts(ساخت timespec *ts)
{
	ساخت timeval tv;
#اگر defined(HAVE_CLOCK_GETTIME) && (defined(CLOCK_BOOTTIME) || \
    defined(CLOCK_MONOTONIC) || defined(CLOCK_REALTIME))
	ساکن صحیح gettime_failed = 0;

	اگر (!gettime_failed) {
# ifdef CLOCK_BOOTTIME
		اگر (clock_gettime(CLOCK_BOOTTIME, ts) == 0)
			واپس;
# endif /* CLOCK_BOOTTIME */
# ifdef CLOCK_MONOTONIC
		اگر (clock_gettime(CLOCK_MONOTONIC, ts) == 0)
			واپس;
# endif /* CLOCK_MONOTONIC */
# ifdef CLOCK_REALTIME
		/* Not monotonic, but we're almost out of options here. */
		اگر (clock_gettime(CLOCK_REALTIME, ts) == 0)
			واپس;
# endif /* CLOCK_REALTIME */
		debug3("clock_gettime: %s", strerror(errno));
		gettime_failed = 1;
	}
#اگر_ختم /* HAVE_CLOCK_GETTIME && (BOOTTIME || MONOTONIC || REALTIME) */
	gettimeofday(&tv, تہی);
	ts->tv_sec = tv.tv_sec;
	ts->tv_nsec = (طویل)tv.tv_usec * 1000;
}

خالی
monotime_tv(ساخت timeval *tv)
{
	ساخت timespec ts;

	monotime_ts(&ts);
	tv->tv_sec = ts.tv_sec;
	tv->tv_usec = ts.tv_nsec / 1000;
}

time_t
monotime(خالی)
{
	ساخت timespec ts;

	monotime_ts(&ts);
	واپس (ts.tv_sec);
}

دوہرا
monotime_double(خالی)
{
	ساخت timespec ts;

	monotime_ts(&ts);
	واپس (دوہرا)ts.tv_sec + (دوہرا)ts.tv_nsec / 1000000000.0;
}

خالی
bandwidth_حد_بندی_init(ساخت bwlimit *bw, uint64_t kbps, سائز_t buflen)
{
	bw->buflen = buflen;
	bw->شرح = kbps;
	bw->thresh = buflen;
	bw->lamt = 0;
	timerclear(&bw->bwstart);
	timerclear(&bw->bwend);
}

/* Callback from read/write loop to insert bandwidth-limiting delays */
خالی
bandwidth_حد_بندی(ساخت bwlimit *bw, سائز_t read_len)
{
	uint64_t waitlen;
	ساخت timespec ts, rm;

	bw->lamt += read_len;
	اگر (!timerisset(&bw->bwstart)) {
		monotime_tv(&bw->bwstart);
		واپس;
	}
	اگر (bw->lamt < bw->thresh)
		واپس;

	monotime_tv(&bw->bwend);
	timersub(&bw->bwend, &bw->bwstart, &bw->bwend);
	اگر (!timerisset(&bw->bwend))
		واپس;

	bw->lamt *= 8;
	waitlen = (دوہرا)1000000L * bw->lamt / bw->شرح;

	bw->bwstart.tv_sec = waitlen / 1000000L;
	bw->bwstart.tv_usec = waitlen % 1000000L;

	اگر (timercmp(&bw->bwstart, &bw->bwend, >)) {
		timersub(&bw->bwstart, &bw->bwend, &bw->bwend);

		/* Adjust the wait time */
		اگر (bw->bwend.tv_sec) {
			bw->thresh /= 2;
			اگر (bw->thresh < bw->buflen / 4)
				bw->thresh = bw->buflen / 4;
		} ورنہ اگر (bw->bwend.tv_usec < 10000) {
			bw->thresh *= 2;
			اگر (bw->thresh > bw->buflen * 8)
				bw->thresh = bw->buflen * 8;
		}

		TIMEVAL_مقصد_TIMESPEC(&bw->bwend, &ts);
		جب (nanosleep(&ts, &rm) == -1) {
			اگر (errno != EINTR)
				توڑو;
			ts = rm;
		}
	}

	bw->lamt = 0;
	monotime_tv(&bw->bwstart);
}

/* Make a template filename for mk[sd]temp() */
خالی
mktemp_proto(حرف *s, سائز_t len)
{
	ثابت حرف *tmpdir;
	صحیح r;

	اگر ((tmpdir = getenv("TMPDIR")) != تہی) {
		r = snprintf(s, len, "%s/ssh-XXXXXXXXXXXX", tmpdir);
		اگر (r > 0 && (سائز_t)r < len)
			واپس;
	}
	r = snprintf(s, len, "/tmp/ssh-XXXXXXXXXXXX");
	اگر (r < 0 || (سائز_t)r >= len)
		fatal_f("template string too short");
}

ساکن ثابت ساخت {
	ثابت حرف *name;
	صحیح قدر;
} ipqos[] = {
	{ "none", زیادہ_سے_زیادہ_عدد },		/* can't use 0 here; that's CS0 */
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
	{ تہی, -1 }
};

صحیح
parse_ipqos(ثابت حرف *cp)
{
	ثابت حرف *errstr;
	u_int i;
	صحیح val;

	اگر (cp == تہی)
		واپس -1;
	برائے (i = 0; ipqos[i].name != تہی; i++) {
		اگر (strcasecmp(cp, ipqos[i].name) == 0)
			واپس ipqos[i].قدر;
	}
	/* Try parsing as an integer */
	val = (صحیح)strtonum(cp, 0, 255, &errstr);
	اگر (errstr)
		واپس -1;
	واپس val;
}

ثابت حرف *
iptos2str(صحیح iptos)
{
	صحیح i;
	ساکن حرف iptos_str[حجم "0xff"];

	برائے (i = 0; ipqos[i].name != تہی; i++) {
		اگر (ipqos[i].قدر == iptos)
			واپس ipqos[i].name;
	}
	snprintf(iptos_str, حجم iptos_str, "0x%02x", iptos);
	واپس iptos_str;
}

خالی
lowercase(حرف *s)
{
	برائے (; *s; s++)
		*s = tolower((u_char)*s);
}

صحیح
unix_listener(ثابت حرف *راستہ, صحیح backlog, صحیح unlink_پہلا)
{
	ساخت sockaddr_un sunaddr;
	صحیح saved_errno, sock;

	memset(&sunaddr, 0, حجم(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	اگر (strlcpy(sunaddr.sun_راستہ, راستہ,
	    حجم(sunaddr.sun_راستہ)) >= حجم(sunaddr.sun_راستہ)) {
		error_f("path \"%s\" too long for Unix domain socket", راستہ);
		errno = ENAMETOOLONG;
		واپس -1;
	}

	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	اگر (sock == -1) {
		saved_errno = errno;
		error_f("socket: %.100s", strerror(errno));
		errno = saved_errno;
		واپس -1;
	}
	اگر (unlink_پہلا == 1) {
		اگر (unlink(راستہ) != 0 && errno != ENOENT)
			error("unlink(%s): %.100s", راستہ, strerror(errno));
	}
	اگر (bind(sock, (ساخت sockaddr *)&sunaddr, حجم(sunaddr)) == -1) {
		saved_errno = errno;
		error_f("cannot bind to path %s: %s", راستہ, strerror(errno));
		close(sock);
		errno = saved_errno;
		واپس -1;
	}
	اگر (listen(sock, backlog) == -1) {
		saved_errno = errno;
		error_f("cannot listen on path %s: %s", راستہ, strerror(errno));
		close(sock);
		unlink(راستہ);
		errno = saved_errno;
		واپس -1;
	}
	واپس sock;
}

خالی
sock_سیٹ_v6only(صحیح s)
{
#اگر defined(IPV6_V6ONLY) && !defined(__OpenBSD__)
	صحیح on = 1;

	debug3_f("set socket %d IPV6_V6ONLY", s);
	اگر (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &on, حجم(on)) == -1)
		error("setsockopt IPV6_V6ONLY: %s", strerror(errno));
#اگر_ختم
}

/*
 * Compares two strings that maybe be NULL. Returns non-zero if strings
 * are both NULL or are identical, returns zero otherwise.
 */
ساکن صحیح
strcmp_maybe_null(ثابت حرف *a, ثابت حرف *b)
{
	اگر ((a == تہی && b != تہی) || (a != تہی && b == تہی))
		واپس 0;
	اگر (a != تہی && strcmp(a, b) != 0)
		واپس 0;
	واپس 1;
}

/*
 * Compare two forwards, returning non-zero if they are identical or
 * zero otherwise.
 */
صحیح
forward_equals(ثابت ساخت Forward *a, ثابت ساخت Forward *b)
{
	اگر (strcmp_maybe_null(a->listen_host, b->listen_host) == 0)
		واپس 0;
	اگر (a->listen_پورٹ != b->listen_پورٹ)
		واپس 0;
	اگر (strcmp_maybe_null(a->listen_راستہ, b->listen_راستہ) == 0)
		واپس 0;
	اگر (strcmp_maybe_null(a->connect_host, b->connect_host) == 0)
		واپس 0;
	اگر (a->connect_پورٹ != b->connect_پورٹ)
		واپس 0;
	اگر (strcmp_maybe_null(a->connect_راستہ, b->connect_راستہ) == 0)
		واپس 0;
	/* allocated_port and handle are not checked */
	واپس 1;
}

/* returns port number, FWD_PERMIT_ANY_PORT or -1 on error */
صحیح
permitopen_پورٹ(ثابت حرف *p)
{
	صحیح پورٹ;

	اگر (strcmp(p, "*") == 0)
		واپس FWD_PERMIT_ANY_پورٹ;
	اگر ((پورٹ = a2port(p)) > 0)
		واپس پورٹ;
	واپس -1;
}

/* returns 1 if process is already daemonized, 0 otherwise */
صحیح
daemonized(خالی)
{
	صحیح fd;

	اگر ((fd = open(_PATH_TTY, O_RDONLY | O_NOCTTY)) >= 0) {
		close(fd);
		واپس 0;	/* have controlling terminal */
	}
	اگر (getppid() != 1)
		واپس 0;	/* parent is not init */
	اگر (getsid(0) != getpid())
		واپس 0;	/* not session leader */
	debug3("already daemonized");
	واپس 1;
}

/*
 * Splits 's' into an argument vector. Handles quoted string and basic
 * escape characters (\\, \", \'). Caller must free the argument vector
 * and its members.
 */
صحیح
argv_بانٹو(ثابت حرف *s, صحیح *argcp, حرف ***argvp, صحیح terminate_on_comment)
{
	صحیح r = SSH_ERR_اندرونی_ERROR;
	صحیح argc = 0, quote, i, j;
	حرف *arg, **argv = xcalloc(1, حجم(*argv));

	*argvp = تہی;
	*argcp = 0;

	برائے (i = 0; s[i] != '\0'; i++) {
		/* Skip leading whitespace */
		اگر (s[i] == ' ' || s[i] == '\t')
			جاری;
		اگر (terminate_on_comment && s[i] == '#')
			توڑو;
		/* Start of a token */
		quote = 0;

		argv = xreallocarray(argv, (argc + 2), حجم(*argv));
		arg = argv[argc++] = xcalloc(1, لڑی_لمبائی(s + i) + 1);
		argv[argc] = تہی;

		/* Copy the token in, removing escapes */
		برائے (j = 0; s[i] != '\0'; i++) {
			اگر (s[i] == '\\') {
				اگر (s[i + 1] == '\'' ||
				    s[i + 1] == '\"' ||
				    s[i + 1] == '\\' ||
				    (quote == 0 && s[i + 1] == ' ')) {
					i++; /* Skip '\' */
					arg[j++] = s[i];
				} ورنہ {
					/* Unrecognised escape */
					arg[j++] = s[i];
				}
			} ورنہ اگر (quote == 0 && (s[i] == ' ' || s[i] == '\t'))
				توڑو; /*مکمل*/
			ورنہ اگر (quote == 0 && (s[i] == '\"' || s[i] == '\''))
				quote = s[i]; /* quote start */
			ورنہ اگر (quote != 0 && s[i] == quote)
				quote = 0; /* quote end */
			ورنہ
				arg[j++] = s[i];
		}
		اگر (s[i] == '\0') {
			اگر (quote != 0) {
				/* Ran out of string looking for close quote */
				r = SSH_ERR_INVALID_FORMAT;
				جاؤ برآمد;
			}
			توڑو;
		}
	}
	/* Success */
	*argcp = argc;
	*argvp = argv;
	argc = 0;
	argv = تہی;
	r = 0;
 برآمد:
	اگر (argc != 0 && argv != تہی) {
		برائے (i = 0; i < argc; i++)
			آزاد(argv[i]);
		آزاد(argv);
	}
	واپس r;
}

/*
 * Reassemble an argument vector into a string, quoting and escaping as
 * necessary. Caller must free returned string.
 */
حرف *
argv_assemble(صحیح argc, حرف **argv)
{
	صحیح i, j, ws, r;
	حرف c, *ret;
	ساخت sshbuf *buf, *arg;

	اگر ((buf = sshbuf_new()) == تہی || (arg = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");

	برائے (i = 0; i < argc; i++) {
		ws = 0;
		sshbuf_reset(arg);
		برائے (j = 0; argv[i][j] != '\0'; j++) {
			r = 0;
			c = argv[i][j];
			انتخاب (c) {
			حالت ' ':
			حالت '\t':
				ws = 1;
				r = sshbuf_put_u8(arg, c);
				توڑو;
			حالت '\\':
			حالت '\'':
			حالت '"':
				اگر ((r = sshbuf_put_u8(arg, '\\')) != 0)
					توڑو;
				/* FALLTHROUGH */
			طےشدہ:
				r = sshbuf_put_u8(arg, c);
				توڑو;
			}
			اگر (r != 0)
				fatal_fr(r, "sshbuf_put_u8");
		}
		اگر ((i != 0 && (r = sshbuf_put_u8(buf, ' ')) != 0) ||
		    (ws != 0 && (r = sshbuf_put_u8(buf, '"')) != 0) ||
		    (r = sshbuf_putb(buf, arg)) != 0 ||
		    (ws != 0 && (r = sshbuf_put_u8(buf, '"')) != 0))
			fatal_fr(r, "assemble");
	}
	اگر ((ret = حافظہ_دو(sshbuf_len(buf) + 1)) == تہی)
		fatal_f("malloc failed");
	حافظہ_نقل(ret, sshbuf_ptr(buf), sshbuf_len(buf));
	ret[sshbuf_len(buf)] = '\0';
	sshbuf_free(buf);
	sshbuf_free(arg);
	واپس ret;
}

حرف *
argv_اگلا(صحیح *argcp, حرف ***argvp)
{
	حرف *ret = (*argvp)[0];

	اگر (*argcp > 0 && ret != تہی) {
		(*argcp)--;
		(*argvp)++;
	}
	واپس ret;
}

خالی
argv_consume(صحیح *argcp)
{
	*argcp = 0;
}

خالی
argv_free(حرف **av, صحیح ac)
{
	صحیح i;

	اگر (av == تہی)
		واپس;
	برائے (i = 0; i < ac; i++)
		آزاد(av[i]);
	آزاد(av);
}

/* Returns 0 if pid exited cleanly, non-zero otherwise */
صحیح
exited_cleanly(pid_t pid, ثابت حرف *لیبل, ثابت حرف *cmd, صحیح quiet)
{
	صحیح حالت_2;

	جب (waitpid(pid, &حالت_2, 0) == -1) {
		اگر (errno != EINTR) {
			error("%s waitpid: %s", لیبل, strerror(errno));
			واپس -1;
		}
	}
	اگر (WIFSIGNALED(حالت_2)) {
		error("%s %s exited on signal %d", لیبل, cmd, WTERMSIG(حالت_2));
		واپس -1;
	} ورنہ اگر (WEXITSTATUS(حالت_2) != 0) {
		do_log2(quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_INFO,
		    "%s %s failed, status %d", لیبل, cmd, WEXITSTATUS(حالت_2));
		واپس -1;
	}
	واپس 0;
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
صحیح
محفوظ_راستہ(ثابت حرف *name, ساخت stat *stp, ثابت حرف *pw_dir,
    uid_t uid, حرف *err, سائز_t errlen)
{
	حرف buf[PATH_MAX], buf2[PATH_MAX], homedir[PATH_MAX];
	حرف *cp;
	صحیح comparehome = 0;
	ساخت stat st;

	اگر (realpath(name, buf) == تہی) {
		snprintf(err, errlen, "realpath %s failed: %s", name,
		    strerror(errno));
		واپس -1;
	}
	اگر (pw_dir != تہی && realpath(pw_dir, homedir) != تہی)
		comparehome = 1;

	اگر (!S_ISREG(stp->st_mode)) {
		snprintf(err, errlen, "%s is not a regular file", buf);
		واپس -1;
	}
	اگر ((!platform_sys_dir_uid(stp->st_uid) && stp->st_uid != uid) ||
	    (stp->st_mode & 022) != 0) {
		snprintf(err, errlen, "bad ownership or modes for file %s",
		    buf);
		واپس -1;
	}

	/* for each component of the canonical path, walking upwards */
	برائے (;;) {
		/*
		 * POSIX allows dirname to modify its argument and return a
		 * pointer into it, so make a copy to avoid overlapping strlcpy.
		 */
		strlcpy(buf2, buf, حجم(buf2));
		اگر ((cp = dirname(buf2)) == تہی) {
			snprintf(err, errlen, "dirname() failed");
			واپس -1;
		}
		strlcpy(buf, cp, حجم(buf));

		اگر (stat(buf, &st) == -1 ||
		    (!platform_sys_dir_uid(st.st_uid) && st.st_uid != uid) ||
		    (st.st_mode & 022) != 0) {
			snprintf(err, errlen,
			    "bad ownership or modes for directory %s", buf);
			واپس -1;
		}

		/* If are past the homedir then we can stop */
		اگر (comparehome && strcmp(homedir, buf) == 0)
			توڑو;

		/*
		 * dirname should always complete with a "/" path,
		 * but we can be paranoid and check for "." too
		 */
		اگر ((strcmp("/", buf) == 0) || (strcmp(".", buf) == 0))
			توڑو;
	}
	واپس 0;
}

/*
 * Version of safe_path() that accepts an open file descriptor to
 * avoid races.
 *
 * Returns 0 on success and -1 on failure
 */
صحیح
محفوظ_راستہ_fd(صحیح fd, ثابت حرف *file, ساخت passwd *pw,
    حرف *err, سائز_t errlen)
{
	ساخت stat st;

	/* check the open file to avoid races */
	اگر (fstat(fd, &st) == -1) {
		snprintf(err, errlen, "cannot stat file %s: %s",
		    file, strerror(errno));
		واپس -1;
	}
	واپس محفوظ_راستہ(file, &st, pw->pw_dir, pw->pw_uid, err, errlen);
}

/*
 * Sets the value of the given variable in the environment.  If the variable
 * already exists, its value is overridden.
 */
خالی
بچہ_سیٹ_env(حرف ***envp, u_int *envsizep, ثابت حرف *name,
	ثابت حرف *قدر)
{
	حرف **env;
	u_int envsize;
	u_int i, namelen;

	اگر (strchr(name, '=') != تہی) {
		error("Invalid environment variable \"%.100s\"", name);
		واپس;
	}

	/*
	 * If we're passed an uninitialized list, allocate a single null
	 * entry before continuing.
	 */
	اگر ((*envp == تہی) != (*envsizep == 0))
		fatal_f("environment size mismatch");
	اگر (*envp == تہی && *envsizep == 0) {
		*envp = xmalloc(حجم(حرف *));
		*envp[0] = تہی;
		*envsizep = 1;
	}

	/*
	 * Find the slot where the value should be stored.  If the variable
	 * already exists, we reuse the slot; otherwise we append a new slot
	 * at the end of the array, expanding if necessary.
	 */
	env = *envp;
	namelen = لڑی_لمبائی(name);
	برائے (i = 0; env[i]; i++)
		اگر (لڑی_موازنہ(env[i], name, namelen) == 0 && env[i][namelen] == '=')
			توڑو;
	اگر (env[i]) {
		/* Reuse the slot. */
		آزاد(env[i]);
	} ورنہ {
		/* New variable.  Expand if necessary. */
		envsize = *envsizep;
		اگر (i >= envsize - 1) {
			اگر (envsize >= 1000)
				fatal("child_set_env: too many env vars");
			envsize += 50;
			env = (*envp) = xreallocarray(env, envsize, حجم(حرف *));
			*envsizep = envsize;
		}
		/* Need to set the NULL pointer at end of array beyond the new slot. */
		env[i + 1] = تہی;
	}

	/* Allocate space and format the variable in the appropriate slot. */
	/* XXX xasprintf */
	env[i] = xmalloc(لڑی_لمبائی(name) + 1 + لڑی_لمبائی(قدر) + 1);
	snprintf(env[i], لڑی_لمبائی(name) + 1 + لڑی_لمبائی(قدر) + 1, "%s=%s", name, قدر);
}

/*
 * Check and optionally lowercase a domain name, also removes trailing '.'
 * Returns 1 on success and 0 on failure, storing an error message in errstr.
 */
صحیح
valid_domain(حرف *name, صحیح makelower, ثابت حرف **errstr)
{
	سائز_t i, l = لڑی_لمبائی(name);
	u_char c, آخری = '\0';
	ساکن حرف errbuf[256];

	اگر (l == 0) {
		strlcpy(errbuf, "empty domain name", حجم(errbuf));
		جاؤ bad;
	}
	اگر (!حرف_ہے((u_char)name[0]) && !ہندسہ_ہے((u_char)name[0]) &&
	   name[0] != '_' /* technically invalid, but common */) {
		snprintf(errbuf, حجم(errbuf), "domain name \"%.100s\" "
		    "starts with invalid character", name);
		جاؤ bad;
	}
	برائے (i = 0; i < l; i++) {
		c = tolower((u_char)name[i]);
		اگر (makelower)
			name[i] = (حرف)c;
		اگر (آخری == '.' && c == '.') {
			snprintf(errbuf, حجم(errbuf), "domain name "
			    "\"%.100s\" contains consecutive separators", name);
			جاؤ bad;
		}
		اگر (c != '.' && c != '-' && !حرف_یا_ہندسہ(c) &&
		    c != '_') /* technically invalid, but common */ {
			snprintf(errbuf, حجم(errbuf), "domain name "
			    "\"%.100s\" contains invalid characters", name);
			جاؤ bad;
		}
		آخری = c;
	}
	اگر (name[l - 1] == '.')
		name[l - 1] = '\0';
	اگر (errstr != تہی)
		*errstr = تہی;
	واپس 1;
bad:
	اگر (errstr != تہی)
		*errstr = errbuf;
	واپس 0;
}

/*
 * Verify that a environment variable name (not including initial '$') is
 * valid; consisting of one or more alphanumeric or underscore characters only.
 * Returns 1 on valid, 0 otherwise.
 */
صحیح
valid_env_name(ثابت حرف *name)
{
	ثابت حرف *cp;

	اگر (name[0] == '\0')
		واپس 0;
	برائے (cp = name; *cp != '\0'; cp++) {
		اگر (!حرف_یا_ہندسہ((u_char)*cp) && *cp != '_')
			واپس 0;
	}
	واپس 1;
}

ثابت حرف *
atoi_err(ثابت حرف *nptr, صحیح *val)
{
	ثابت حرف *errstr = تہی;

	اگر (nptr == تہی || *nptr == '\0')
		واپس "missing";
	*val = strtonum(nptr, 0, زیادہ_سے_زیادہ_عدد, &errstr);
	واپس errstr;
}

صحیح
parse_absolute_وقت(ثابت حرف *s, uint64_t *tp)
{
	ساخت tm tm;
	time_t tt;
	حرف buf[32], *fmt;
	ثابت حرف *cp;
	سائز_t l;
	صحیح is_utc = 0;

	*tp = 0;

	l = لڑی_لمبائی(s);
	اگر (l > 1 && strcasecmp(s + l - 1, "Z") == 0) {
		is_utc = 1;
		l--;
	} ورنہ اگر (l > 3 && strcasecmp(s + l - 3, "UTC") == 0) {
		is_utc = 1;
		l -= 3;
	}
	/*
	 * POSIX strptime says "The application shall ensure that there
	 * is white-space or other non-alphanumeric characters between
	 * any two conversion specifications" so arrange things this way.
	 */
	انتخاب (l) {
	حالت 8: /* YYYYMMDD */
		fmt = "%Y-%m-%d";
		snprintf(buf, حجم(buf), "%.4s-%.2s-%.2s", s, s + 4, s + 6);
		توڑو;
	حالت 12: /* YYYYMMDDHHMM */
		fmt = "%Y-%m-%dT%H:%M";
		snprintf(buf, حجم(buf), "%.4s-%.2s-%.2sT%.2s:%.2s",
		    s, s + 4, s + 6, s + 8, s + 10);
		توڑو;
	حالت 14: /* YYYYMMDDHHMMSS */
		fmt = "%Y-%m-%dT%H:%M:%S";
		snprintf(buf, حجم(buf), "%.4s-%.2s-%.2sT%.2s:%.2s:%.2s",
		    s, s + 4, s + 6, s + 8, s + 10, s + 12);
		توڑو;
	طےشدہ:
		واپس SSH_ERR_INVALID_FORMAT;
	}

	memset(&tm, 0, حجم(tm));
	اگر ((cp = strptime(buf, fmt, &tm)) == تہی || *cp != '\0')
		واپس SSH_ERR_INVALID_FORMAT;
	اگر (is_utc) {
		tm.tm_wday = -1;	/* sentinel for error */
		اگر ((tt = timegm(&tm)) == -1 && tm.tm_wday == -1)
			واپس SSH_ERR_INVALID_FORMAT;
	} ورنہ {
		tm.tm_wday = -1;	/* sentinel for error */
		tm.tm_isdst = -1;	/* mktime decides DST */
		اگر ((tt = mktime(&tm)) == -1 && tm.tm_wday == -1)
			واپس SSH_ERR_INVALID_FORMAT;
	}
	/* success */
	*tp = (uint64_t)tt;
	واپس 0;
}

خالی
format_absolute_وقت(uint64_t t, حرف *buf, سائز_t len)
{
	time_t tt = t > SSH_وقت_T_MAX ? SSH_وقت_T_MAX : t;
	ساخت tm tm;

	اگر (localtime_r(&tt, &tm) == تہی)
		strlcpy(buf, "UNKNOWN-TIME", len);
	ورنہ
		strftime(buf, len, "%Y-%m-%dT%H:%M:%S", &tm);
}

/*
 * Parse a "pattern=interval" clause (e.g. a ChannelTimeout).
 * Returns 0 on success or non-zero on failure.
 * Caller must free *typep.
 */
صحیح
parse_نمونہ_interval(ثابت حرف *s, حرف **typep, دوہرا *secsp)
{
	حرف *cp, *sdup;
	دوہرا secs;

	اگر (typep != تہی)
		*typep = تہی;
	اگر (secsp != تہی)
		*secsp = 0;
	اگر (s == تہی)
		واپس -1;
	sdup = xstrdup(s);

	اگر ((cp = strchr(sdup, '=')) == تہی || cp == sdup) {
		آزاد(sdup);
		واپس -1;
	}
	*cp++ = '\0';
	اگر ((secs = convtime_double(cp)) < 0.0) {
		آزاد(sdup);
		واپس -1;
	}
	/* success */
	اگر (typep != تہی)
		*typep = xstrdup(sdup);
	اگر (secsp != تہی)
		*secsp = secs;
	آزاد(sdup);
	واپس 0;
}

/* check if path is absolute */
صحیح
راستہ_absolute(ثابت حرف *راستہ)
{
	واپس (*راستہ == '/') ? 1 : 0;
}

خالی
skip_space(حرف **cpp)
{
	حرف *cp;

	برائے (cp = *cpp; *cp == ' ' || *cp == '\t'; cp++)
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
صحیح
opt_flag(ثابت حرف *opt, صحیح allow_negate, ثابت حرف **optsp)
{
	سائز_t opt_len = لڑی_لمبائی(opt);
	ثابت حرف *opts = *optsp;
	صحیح negate = 0;

	اگر (allow_negate && strncasecmp(opts, "no-", 3) == 0) {
		opts += 3;
		negate = 1;
	}
	اگر (strncasecmp(opts, opt, opt_len) == 0) {
		*optsp = opts + opt_len;
		واپس negate ? 0 : 1;
	}
	واپس -1;
}

حرف *
opt_dequote(ثابت حرف **sp, ثابت حرف **errstrp)
{
	ثابت حرف *s = *sp;
	حرف *ret;
	سائز_t i;

	*errstrp = تہی;
	اگر (*s != '"') {
		*errstrp = "missing start quote";
		واپس تہی;
	}
	s++;
	اگر ((ret = حافظہ_دو(لڑی_لمبائی((s)) + 1)) == تہی) {
		*errstrp = "memory allocation failed";
		واپس تہی;
	}
	برائے (i = 0; *s != '\0' && *s != '"';) {
		اگر (s[0] == '\\' && s[1] == '"')
			s++;
		ret[i++] = *s++;
	}
	اگر (*s == '\0') {
		*errstrp = "missing end quote";
		آزاد(ret);
		واپس تہی;
	}
	ret[i] = '\0';
	s++;
	*sp = s;
	واپس ret;
}

صحیح
opt_مطابقت(ثابت حرف **opts, ثابت حرف *رکن)
{
	اگر (strncasecmp((*opts), رکن, لڑی_لمبائی(رکن)) == 0 &&
	    (*opts)[لڑی_لمبائی(رکن)] == '=') {
		*opts += لڑی_لمبائی(رکن) + 1;
		واپس 1;
	}
	واپس 0;
}

خالی
opt_array_append2(ثابت حرف *file, ثابت صحیح سطر, ثابت حرف *directive,
    حرف ***array, صحیح **iarray, u_int *lp, ثابت حرف *s, صحیح i)
{

	اگر (*lp >= زیادہ_سے_زیادہ_عدد)
		fatal("%s line %d: Too many %s entries", file, سطر, directive);

	اگر (iarray != تہی) {
		*iarray = xrecallocarray(*iarray, *lp, *lp + 1,
		    حجم(**iarray));
		(*iarray)[*lp] = i;
	}

	*array = xrecallocarray(*array, *lp, *lp + 1, حجم(**array));
	(*array)[*lp] = xstrdup(s);
	(*lp)++;
}

خالی
opt_array_append(ثابت حرف *file, ثابت صحیح سطر, ثابت حرف *directive,
    حرف ***array, u_int *lp, ثابت حرف *s)
{
	opt_array_append2(file, سطر, directive, array, تہی, lp, s, 0);
}

خالی
opt_array_free2(حرف **array, صحیح **iarray, u_int l)
{
	u_int i;

	اگر (array == تہی || l == 0)
		واپس;
	برائے (i = 0; i < l; i++)
		آزاد(array[i]);
	آزاد(array);
	آزاد(iarray);
}

sshsig_t
ssh_signal(صحیح signum, sshsig_t handler)
{
	ساخت sigaction sa, osa;

	/* mask all other signals while in handler */
	memset(&sa, 0, حجم(sa));
	sa.sa_handler = handler;
	sigfillset(&sa.sa_mask);
#اگر defined(SA_RESTART) && !defined(NO_SA_RESTART)
	اگر (signum != SIGALRM)
		sa.sa_flags = SA_RESTART;
#اگر_ختم
	اگر (sigaction(signum, &sa, &osa) == -1) {
		debug3("sigaction(%s): %s", strsignal(signum), strerror(errno));
		واپس SIG_ERR;
	}
	واپس osa.sa_handler;
}

صحیح
stdfd_devnull(صحیح do_stdin, صحیح do_stdout, صحیح do_stderr)
{
	صحیح devnull, ret = 0;

	اگر ((devnull = open(_PATH_DEVNULL, O_RDWR)) == -1) {
		error_f("open %s: %s", _PATH_DEVNULL,
		    strerror(errno));
		واپس -1;
	}
	اگر ((do_stdin && dup2(devnull, STDIN_FILENO) == -1) ||
	    (do_stdout && dup2(devnull, STDOUT_FILENO) == -1) ||
	    (do_stderr && dup2(devnull, STDERR_FILENO) == -1)) {
		error_f("dup2: %s", strerror(errno));
		ret = -1;
	}
	اگر (devnull > STDERR_FILENO)
		close(devnull);
	واپس ret;
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
subprocess(ثابت حرف *لیبل, ثابت حرف *command,
    صحیح ac, حرف **av, FILE **بچہ, u_int flags,
    ساخت passwd *pw, privdrop_fn *drop_privs, privrestore_fn *restore_privs)
{
	FILE *f = تہی;
	ساخت stat st;
	صحیح fd, devnull, p[2], i;
	pid_t pid;
	حرف *cp, errmsg[512];
	u_int nenv = 0;
	حرف **env = تہی;

	/* If dropping privs, then must specify user and restore function */
	اگر (drop_privs != تہی && (pw == تہی || restore_privs == تہی)) {
		error("%s: inconsistent arguments", لیبل); /* XXX fatal? */
		واپس 0;
	}
	اگر (pw == تہی && (pw = getpwuid(getuid())) == تہی) {
		error("%s: no user for current uid", لیبل);
		واپس 0;
	}
	اگر (بچہ != تہی)
		*بچہ = تہی;

	debug3_f("%s command \"%s\" running as %s (flags 0x%x)",
	    لیبل, command, pw->pw_name, flags);

	/* Check consistency */
	اگر ((flags & SSH_SUBPROCESS_STDOUT_DISCARD) != 0 &&
	    (flags & SSH_SUBPROCESS_STDOUT_CAPTURE) != 0) {
		error_f("inconsistent flags");
		واپس 0;
	}
	اگر (((flags & SSH_SUBPROCESS_STDOUT_CAPTURE) == 0) != (بچہ == تہی)) {
		error_f("inconsistent flags/output");
		واپس 0;
	}

	/*
	 * If executing an explicit binary, then verify the it exists
	 * and appears safe-ish to execute
	 */
	اگر (!راستہ_absolute(av[0])) {
		error("%s path is not absolute", لیبل);
		واپس 0;
	}
	اگر (drop_privs != تہی)
		drop_privs(pw);
	اگر (stat(av[0], &st) == -1) {
		error("Could not stat %s \"%s\": %s", لیبل,
		    av[0], strerror(errno));
		جاؤ restore_return;
	}
	اگر ((flags & SSH_SUBPROCESS_UNSAFE_راستہ) == 0 &&
	    محفوظ_راستہ(av[0], &st, تہی, 0, errmsg, حجم(errmsg)) != 0) {
		error("Unsafe %s \"%s\": %s", لیبل, av[0], errmsg);
		جاؤ restore_return;
	}
	/* Prepare to keep the child's stdout if requested */
	اگر (pipe(p) == -1) {
		error("%s: pipe: %s", لیبل, strerror(errno));
 restore_return:
		اگر (restore_privs != تہی)
			restore_privs();
		واپس 0;
	}
	اگر (restore_privs != تہی)
		restore_privs();

	انتخاب ((pid = fork())) {
	حالت -1: /* error */
		error("%s: fork: %s", لیبل, strerror(errno));
		close(p[0]);
		close(p[1]);
		واپس 0;
	حالت 0: /*بچہ*/
		/* Prepare a minimal environment for the child. */
		اگر ((flags & SSH_SUBPROCESS_PRESERVE_ENV) == 0) {
			nenv = 5;
			env = xcalloc(حجم(*env), nenv);
			بچہ_سیٹ_env(&env, &nenv, "PATH", _PATH_STDPATH);
			بچہ_سیٹ_env(&env, &nenv, "USER", pw->pw_name);
			بچہ_سیٹ_env(&env, &nenv, "LOGNAME", pw->pw_name);
			بچہ_سیٹ_env(&env, &nenv, "HOME", pw->pw_dir);
			اگر ((cp = getenv("LANG")) != تہی)
				بچہ_سیٹ_env(&env, &nenv, "LANG", cp);
		}

		برائے (i = 1; i < NSIG; i++)
			ssh_signal(i, SIG_DFL);

		اگر ((devnull = open(_PATH_DEVNULL, O_RDWR)) == -1) {
			error("%s: open %s: %s", لیبل, _PATH_DEVNULL,
			    strerror(errno));
			_exit(1);
		}
		اگر (dup2(devnull, STDIN_FILENO) == -1) {
			error("%s: dup2: %s", لیبل, strerror(errno));
			_exit(1);
		}

		/* Set up stdout as requested; leave stderr in place for now. */
		fd = -1;
		اگر ((flags & SSH_SUBPROCESS_STDOUT_CAPTURE) != 0)
			fd = p[1];
		ورنہ اگر ((flags & SSH_SUBPROCESS_STDOUT_DISCARD) != 0)
			fd = devnull;
		اگر (fd != -1 && dup2(fd, STDOUT_FILENO) == -1) {
			error("%s: dup2: %s", لیبل, strerror(errno));
			_exit(1);
		}
		closefrom(STDERR_FILENO + 1);

		اگر (geteuid() == 0 &&
		    initgroups(pw->pw_name, pw->pw_gid) == -1) {
			error("%s: initgroups(%s, %u): %s", لیبل,
			    pw->pw_name, (u_int)pw->pw_gid, strerror(errno));
			_exit(1);
		}
		اگر (setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) == -1) {
			error("%s: setresgid %u: %s", لیبل, (u_int)pw->pw_gid,
			    strerror(errno));
			_exit(1);
		}
		اگر (setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) == -1) {
			error("%s: setresuid %u: %s", لیبل, (u_int)pw->pw_uid,
			    strerror(errno));
			_exit(1);
		}
		/* stdin is pointed to /dev/null at this point */
		اگر ((flags & SSH_SUBPROCESS_STDOUT_DISCARD) != 0 &&
		    dup2(STDIN_FILENO, STDERR_FILENO) == -1) {
			error("%s: dup2: %s", لیبل, strerror(errno));
			_exit(1);
		}
		اگر (env != تہی)
			execve(av[0], av, env);
		ورنہ
			execv(av[0], av);
		error("%s %s \"%s\": %s", لیبل, env == تہی ? "execv" : "execve",
		    command, strerror(errno));
		_exit(127);
	طےشدہ: /*والد*/
		توڑو;
	}

	close(p[1]);
	اگر ((flags & SSH_SUBPROCESS_STDOUT_CAPTURE) == 0)
		close(p[0]);
	ورنہ اگر ((f = fdopen(p[0], "r")) == تہی) {
		error("%s: fdopen: %s", لیبل, strerror(errno));
		close(p[0]);
		/* Don't leave zombie child */
		kill(pid, SIGTERM);
		جب (waitpid(pid, تہی, 0) == -1 && errno == EINTR)
			;
		واپس 0;
	}
	/* Success */
	debug3_f("%s pid %ld", لیبل, (طویل)pid);
	اگر (بچہ != تہی)
		*بچہ = f;
	واپس pid;
}

ثابت حرف *
lookup_env_اندر_list(ثابت حرف *env, حرف * ثابت *envs, سائز_t nenvs)
{
	سائز_t i, envlen;

	envlen = لڑی_لمبائی(env);
	برائے (i = 0; i < nenvs; i++) {
		اگر (لڑی_موازنہ(envs[i], env, envlen) == 0 &&
		    envs[i][envlen] == '=') {
			واپس envs[i] + envlen + 1;
		}
	}
	واپس تہی;
}

ثابت حرف *
lookup_setenv_اندر_list(ثابت حرف *env, حرف * ثابت *envs, سائز_t nenvs)
{
	حرف *name, *cp;
	ثابت حرف *ret;

	name = xstrdup(env);
	اگر ((cp = strchr(name, '=')) == تہی) {
		آزاد(name);
		واپس تہی; /* not env=val */
	}
	*cp = '\0';
	ret = lookup_env_اندر_list(name, envs, nenvs);
	آزاد(name);
	واپس ret;
}

/*
 * Helpers for managing poll(2)/ppoll(2) timeouts
 * Will remember the earliest deadline and return it for use in poll/ppoll.
 */

/* Initialise a poll/ppoll timeout with an indefinite deadline */
خالی
ptimeout_init(ساخت timespec *pt)
{
	/*
	 * Deliberately invalid for ppoll(2).
	 * Will be converted to NULL in ptimeout_get_tspec() later.
	 */
	pt->tv_sec = -1;
	pt->tv_nsec = 0;
}

/* Specify a poll/ppoll deadline of at most 'sec' seconds */
خالی
ptimeout_deadline_sec(ساخت timespec *pt, طویل sec)
{
	اگر (pt->tv_sec == -1 || pt->tv_sec >= sec) {
		pt->tv_sec = sec;
		pt->tv_nsec = 0;
	}
}

/* Specify a poll/ppoll deadline of at most 'p' (timespec) */
ساکن خالی
ptimeout_deadline_tsp(ساخت timespec *pt, ساخت timespec *p)
{
	اگر (pt->tv_sec == -1 || timespeccmp(pt, p, >=))
		*pt = *p;
}

/* Specify a poll/ppoll deadline of at most 'ms' milliseconds */
خالی
ptimeout_deadline_ms(ساخت timespec *pt, طویل ms)
{
	ساخت timespec p;

	p.tv_sec = ms / 1000;
	p.tv_nsec = (ms % 1000) * 1000000;
	ptimeout_deadline_tsp(pt, &p);
}

/* Specify a poll/ppoll deadline of at most 'sec' seconds (double) */
خالی
ptimeout_deadline_sec_double(ساخت timespec *pt, دوہرا sec)
{
	ساخت timespec t;

	memset(&t, 0, حجم(t));
	اگر ((int64_t)sec >= SSH_وقت_T_MAX)
		t.tv_sec = SSH_وقت_T_MAX;
	ورنہ اگر (sec > 0) {
		t.tv_sec = sec;
		t.tv_nsec = (sec - (دوہرا)t.tv_sec) * 1000000000.0;
	}
	ptimeout_deadline_tsp(pt, &t);
}

/* Specify a poll/ppoll deadline at wall clock monotime 'when' (timespec) */
خالی
ptimeout_deadline_monotime_tsp(ساخت timespec *pt, ساخت timespec *when)
{
	ساخت timespec now, t;

	monotime_ts(&now);

	اگر (timespeccmp(&now, when, >=)) {
		/* 'when' is now or in the past. Timeout ASAP */
		pt->tv_sec = 0;
		pt->tv_nsec = 0;
	} ورنہ {
		timespecsub(when, &now, &t);
		ptimeout_deadline_tsp(pt, &t);
	}
}

/* Specify a poll/ppoll deadline at wall clock monotime 'when' (double) */
خالی
ptimeout_deadline_monotime_double(ساخت timespec *pt, دوہرا when)
{
	ptimeout_deadline_sec_double(pt, when - monotime_double());
}

/* Specify a poll/ppoll deadline at wall clock monotime 'when' */
خالی
ptimeout_deadline_monotime(ساخت timespec *pt, time_t when)
{
	ساخت timespec t;

	t.tv_sec = when;
	t.tv_nsec = 0;
	ptimeout_deadline_monotime_tsp(pt, &t);
}

/* Get a poll(2) timeout value in milliseconds */
صحیح
ptimeout_get_ms(ساخت timespec *pt)
{
	اگر (pt->tv_sec == -1)
		واپس -1;
	اگر (pt->tv_sec >= (زیادہ_سے_زیادہ_عدد - (pt->tv_nsec / 1000000)) / 1000)
		واپس زیادہ_سے_زیادہ_عدد;
	واپس (pt->tv_sec * 1000) + (pt->tv_nsec / 1000000);
}

/* Get a ppoll(2) timeout value as a timespec pointer */
ساخت timespec *
ptimeout_get_tsp(ساخت timespec *pt)
{
	واپس pt->tv_sec == -1 ? تہی : pt;
}

/* Returns non-zero if a timeout has been set (i.e. is not indefinite) */
صحیح
ptimeout_isset(ساخت timespec *pt)
{
	واپس pt->tv_sec != -1;
}

/*
 * Returns zero if the library at 'path' contains symbol 's', nonzero
 * otherwise.
 */
صحیح
lib_شامل_ہے_علامت(ثابت حرف *راستہ, ثابت حرف *s)
{
#اگر_تعریف_شدہ HAVE_NLIST
	ساخت nlist nl[2];
	صحیح ret = -1, r;

	memset(nl, 0, حجم(nl));
	nl[0].n_name = xstrdup(s);
	nl[1].n_name = تہی;
	اگر ((r = nlist(راستہ, nl)) == -1) {
		error_f("nlist failed for %s", راستہ);
		جاؤ برآمد;
	}
	اگر (r != 0 || nl[0].n_قدر == 0 || nl[0].n_type == 0) {
		error_f("library %s does not contain symbol %s", راستہ, s);
		جاؤ برآمد;
	}
	/* success */
	ret = 0;
 برآمد:
	آزاد(nl[0].n_name);
	واپس ret;
#ورنہ /* HAVE_NLIST */
	صحیح fd, ret = -1;
	ساخت stat st;
	خالی *m = تہی;
	سائز_t sz = 0;

	memset(&st, 0, حجم(st));
	اگر ((fd = open(راستہ, O_RDONLY)) < 0) {
		error_f("open %s: %s", راستہ, strerror(errno));
		واپس -1;
	}
	اگر (fstat(fd, &st) != 0) {
		error_f("fstat %s: %s", راستہ, strerror(errno));
		جاؤ برآمد;
	}
	اگر (!S_ISREG(st.st_mode)) {
		error_f("%s is not a regular file", راستہ);
		جاؤ برآمد;
	}
	اگر (st.st_size < 0 ||
	    (سائز_t)st.st_size < لڑی_لمبائی(s) ||
	    st.st_size >= زیادہ_سے_زیادہ_عدد/2) {
		error_f("%s bad size %lld", راستہ, (طویل طویل)st.st_size);
		جاؤ برآمد;
	}
	sz = (سائز_t)st.st_size;
	اگر ((m = mmap(تہی, sz, PROT_READ, MAP_PRIVATE, fd, 0)) == MAP_FAILED ||
	    m == تہی) {
		error_f("mmap %s: %s", راستہ, strerror(errno));
		جاؤ برآمد;
	}
	اگر (memmem(m, sz, s, لڑی_لمبائی(s)) == تہی) {
		error_f("%s does not contain expected string %s", راستہ, s);
		جاؤ برآمد;
	}
	/* success */
	ret = 0;
 برآمد:
	اگر (m != تہی && m != MAP_FAILED)
		munmap(m, sz);
	close(fd);
	واپس ret;
#اگر_ختم /* HAVE_NLIST */
}

صحیح
signal_is_crash(صحیح sig)
{
	انتخاب (sig) {
	حالت SIGSEGV:
	حالت SIGBUS:
	حالت SIGTRAP:
	حالت SIGSYS:
	حالت SIGFPE:
	حالت SIGILL:
	حالت SIGABRT:
		واپس 1;
	}
	واپس 0;
}

حرف *
get_homedir(خالی)
{
	حرف *cp;
	ساخت passwd *pw;

	اگر ((cp = getenv("HOME")) != تہی && *cp != '\0')
		واپس xstrdup(cp);

	اگر ((pw = getpwuid(getuid())) != تہی && *pw->pw_dir != '\0')
		واپس xstrdup(pw->pw_dir);

	واپس تہی;
}

صحیح
mkdir_راستہ(ثابت حرف *ہدف, منوال_t منوال)
{
#اگر defined(HAVE_OPENAT) && defined(O_DIRECTORY)
	حرف *dir, *odir = تہی, *اگلا;
	صحیح fd = AT_FDCWD, fd2, subpath_len, ret = -1;

	dir = odir = xstrdup(ہدف);

	اگر (*dir == '/' &&
	    (fd = open("/", O_RDONLY|O_DIRECTORY)) == -1) {
		error_f("open(\"/\"): %s", strerror(errno));
		آزاد(odir);
		واپس -1;
	}
	/* Work through the path, component-wise */
	برائے (; dir != تہی && *dir != '\0'; dir = اگلا) {
		اگر ((اگلا = strchr(dir, '/')) != تہی)
			*(اگلا++) = '\0';
		اگر (*dir == '\0')
			جاری;
		subpath_len = (اگلا == تہی) ? زیادہ_سے_زیادہ_عدد : اگلا - odir - 1;
		اگر (mkdirat(fd, dir, منوال) == 0)
			debug_f("created directory %.*s", subpath_len, ہدف);
		ورنہ اگر (errno != EEXIST) {
			error_f("mkdir(\"%.*s\"): %s",
			    subpath_len, ہدف, strerror(errno));
			جاؤ برآمد;
		}

		/* descend */
		اگر ((fd2 = openat(fd, dir, O_RDONLY|O_DIRECTORY)) == -1) {
			error_f("open(\"%.*s\"): %s",
			    subpath_len, ہدف, strerror(errno));
			جاؤ برآمد;
		}
		اگر (fd != AT_FDCWD)
			close(fd);
		fd = fd2;
	}
	/* success */
	ret = 0;
 برآمد:
	آزاد(odir);
	اگر (fd != AT_FDCWD)
		close(fd);
	واپس ret;
#ورنہ
	/*
	 * If we don't have openat (which was added in POSIX.1-2008), fall back
	 * to the possibly racy way.
	 */
	حرف *dir, *odir, *p, راستہ[PATH_MAX] = "";
	صحیح ret = -1;
	سائز_t plen = حجم(راستہ);

	dir = odir = xstrdup(ہدف);

	/* If the dir is relative, start with cwd. */
	اگر (*dir != '/' && getcwd(راستہ, plen) == تہی) {
		error_f("getcwd: %s", strerror(errno));
		جاؤ برآمد;
	}

	/* Work through the path, component-wise */
	جب ((p = strsep(&dir, "/"))) {
		اگر (*p == '\0')
			جاری;
		اگر (strlcat(راستہ, "/", plen) >= plen ||
		    strlcat(راستہ, p, plen) >= plen)
			جاؤ برآمد;
		اگر (mkdir(راستہ, منوال) == 0)
			debug_f("created directory %s", راستہ);
		ورنہ اگر (errno != EEXIST && errno != EISDIR) {
			error_f("mkdir(\"%s\"): %s", راستہ, strerror(errno));
			جاؤ برآمد;
		}
	}
	/* success */
	ret = 0;
 برآمد:
	آزاد(odir);
	واپس ret;
#اگر_ختم
}
