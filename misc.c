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
#ifdef SSH_TUN_OPENBSD
#شامل <net/if.h>
#endif

#شامل "xmalloc.h"
#شامل "misc.h"
#شامل "log.h"
#شامل "ssh.h"
#شامل "sshbuf.h"
#شامل "ssherr.h"
#شامل "platform.h"

/* remove newline at end of string */
نویسه *
chop(نویسه *s)
{
	نویسه *t = s;
	وقتی (*t) {
		اگر (*t == '\n' || *t == '\r') {
			*t = '\0';
			بازگشت s;
		}
		t++;
	}
	بازگشت s;

}

/* remove whitespace from end of string */
تهی
rtrim(نویسه *s)
{
	size_t i;

	اگر ((i = strlen(s)) == 0)
		بازگشت;
	انجامبده {
		i--;
		اگر (isspace((unsigned نویسه)s[i]))
			s[i] = '\0';
		وگرنه
			بشکن;
	} وقتی (i > 0);
}

/*
 * returns pointer to character after 'prefix' in 's' or otherwise NULL
 * if the prefix is not present.
 */
ثابت نویسه *
strprefix(ثابت نویسه *s, ثابت نویسه *prefix, صحیح ignorecase)
{
	size_t prefixlen;

	اگر ((prefixlen = strlen(prefix)) == 0)
		بازگشت s;
	اگر (ignorecase) {
		اگر (strncasecmp(s, prefix, prefixlen) != 0)
			بازگشت پوچ;
	} وگرنه {
		اگر (strncmp(s, prefix, prefixlen) != 0)
			بازگشت پوچ;
	}
	بازگشت s + prefixlen;
}

/* Append string 's' to a NULL-terminated array of strings */
تهی
stringlist_append(نویسه ***listp, ثابت نویسه *s)
{
	size_t i = 0;

	اگر (*listp == پوچ)
		*listp = xcalloc(2, اندازه(**listp));
	وگرنه {
		برای (i = 0; (*listp)[i] != پوچ; i++)
			; /* count */
		*listp = xrecallocarray(*listp, i + 1, i + 2, اندازه(**listp));
	}
	(*listp)[i] = xstrdup(s);
}

تهی
stringlist_free(نویسه **list)
{
	size_t i = 0;

	اگر (list == پوچ)
		بازگشت;
	برای (i = 0; list[i] != پوچ; i++)
		آزاد(list[i]);
	آزاد(list);
}

/* set/unset filedescriptor to non-blocking */
صحیح
set_nonblock(صحیح fd)
{
	صحیح val;

	val = fcntl(fd, F_GETFL);
	اگر (val == -1) {
		error("fcntl(%d, F_GETFL): %s", fd, strerror(errno));
		بازگشت (-1);
	}
	اگر (val & O_NONBLOCK) {
		debug3("fd %d is O_NONBLOCK", fd);
		بازگشت (0);
	}
	debug2("fd %d setting O_NONBLOCK", fd);
	val |= O_NONBLOCK;
	اگر (fcntl(fd, F_SETFL, val) == -1) {
		debug("fcntl(%d, F_SETFL, O_NONBLOCK): %s", fd,
		    strerror(errno));
		بازگشت (-1);
	}
	بازگشت (0);
}

صحیح
unset_nonblock(صحیح fd)
{
	صحیح val;

	val = fcntl(fd, F_GETFL);
	اگر (val == -1) {
		error("fcntl(%d, F_GETFL): %s", fd, strerror(errno));
		بازگشت (-1);
	}
	اگر (!(val & O_NONBLOCK)) {
		debug3("fd %d is not O_NONBLOCK", fd);
		بازگشت (0);
	}
	debug("fd %d clearing O_NONBLOCK", fd);
	val &= ~O_NONBLOCK;
	اگر (fcntl(fd, F_SETFL, val) == -1) {
		debug("fcntl(%d, F_SETFL, ~O_NONBLOCK): %s",
		    fd, strerror(errno));
		بازگشت (-1);
	}
	بازگشت (0);
}

ثابت نویسه *
ssh_gai_strerror(صحیح gaierr)
{
	اگر (gaierr == EAI_SYSTEM && errno != 0)
		بازگشت strerror(errno);
	بازگشت gai_strerror(gaierr);
}

/* disable nagle on socket */
تهی
set_nodelay(صحیح fd)
{
	صحیح opt;
	socklen_t optlen;

	optlen = اندازه opt;
	اگر (getsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, &optlen) == -1) {
		debug("getsockopt TCP_NODELAY: %.100s", strerror(errno));
		بازگشت;
	}
	اگر (opt == 1) {
		debug2("fd %d is TCP_NODELAY", fd);
		بازگشت;
	}
	opt = 1;
	debug2("fd %d setting TCP_NODELAY", fd);
	اگر (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, اندازه opt) == -1)
		error("setsockopt TCP_NODELAY: %.100s", strerror(errno));
}

/* Allow local port reuse in TIME_WAIT */
صحیح
set_reuseaddr(صحیح fd)
{
	صحیح on = 1;

	اگر (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, اندازه(on)) == -1) {
		error("setsockopt SO_REUSEADDR fd %d: %s", fd, strerror(errno));
		بازگشت -1;
	}
	بازگشت 0;
}

/* Set TCP keepalives */
صحیح
set_keepalive(صحیح fd)
{
	صحیح on = 1;

	اگر (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, اندازه(on)) == -1) {
		error("setsockopt SO_KEEPALIVE fd %d: %s", fd, strerror(errno));
		بازگشت -1;
	}
	بازگشت 0;
}

/* Get/set routing domain */
نویسه *
get_rdomain(صحیح fd)
{
#اگر defined(HAVE_SYS_GET_RDOMAIN)
	بازگشت sys_get_rdomain(fd);
#وگرنهاگر defined(__OpenBSD__)
	صحیح rtable;
	نویسه *ret;
	socklen_t len = اندازه(rtable);

	اگر (getsockopt(fd, SOL_SOCKET, SO_RTABLE, &rtable, &len) == -1) {
		error("Failed to get routing domain for fd %d: %s",
		    fd, strerror(errno));
		بازگشت پوچ;
	}
	xasprintf(&ret, "%d", rtable);
	بازگشت ret;
#وگرنه /* defined(__OpenBSD__) */
	بازگشت پوچ;
#endif
}

صحیح
set_rdomain(صحیح fd, ثابت نویسه *name)
{
#اگر defined(HAVE_SYS_SET_RDOMAIN)
	بازگشت sys_set_rdomain(fd, name);
#وگرنهاگر defined(__OpenBSD__)
	صحیح rtable;
	ثابت نویسه *errstr;

	اگر (name == پوچ)
		بازگشت 0; /* default table */

	rtable = (صحیح)strtonum(name, 0, 255, &errstr);
	اگر (errstr != پوچ) {
		/* Shouldn't happen */
		error("Invalid routing domain \"%s\": %s", name, errstr);
		بازگشت -1;
	}
	اگر (setsockopt(fd, SOL_SOCKET, SO_RTABLE,
	    &rtable, اندازه(rtable)) == -1) {
		error("Failed to set routing domain %d on fd %d: %s",
		    rtable, fd, strerror(errno));
		بازگشت -1;
	}
	بازگشت 0;
#وگرنه /* defined(__OpenBSD__) */
	error("Setting routing domain is not supported on this platform");
	بازگشت -1;
#endif
}

صحیح
get_sock_af(صحیح fd)
{
	ساختار sockaddr_storage to;
	socklen_t tolen = اندازه(to);

	memset(&to, 0, اندازه(to));
	اگر (getsockname(fd, (ساختار sockaddr *)&to, &tolen) == -1)
		بازگشت -1;
#ifdef IPV4_IN_IPV6
	اگر (to.ss_family == AF_INET6 &&
	    IN6_IS_ADDR_V4MAPPED(&((ساختار sockaddr_in6 *)&to)->sin6_addr))
		بازگشت AF_INET;
#endif
	بازگشت to.ss_family;
}

تهی
set_sock_tos(صحیح fd, صحیح tos)
{
#ifndef IP_TOS_IS_BROKEN
	صحیح af;

	اگر (tos < 0 || tos == INT_MAX) {
		debug_f("invalid TOS %d", tos);
		بازگشت;
	}
	انتخاب ((af = get_sock_af(fd))) {
	حالت -1:
		/* assume not a socket */
		بشکن;
	حالت AF_INET:
# ifdef IP_TOS
		debug3_f("set socket %d IP_TOS 0x%02x", fd, tos);
		اگر (setsockopt(fd, IPPROTO_IP, IP_TOS,
		    &tos, اندازه(tos)) == -1) {
			error("setsockopt socket %d IP_TOS %d: %s",
			    fd, tos, strerror(errno));
		}
# endif /* IP_TOS */
		بشکن;
	حالت AF_INET6:
# ifdef IPV6_TCLASS
		debug3_f("set socket %d IPV6_TCLASS 0x%02x", fd, tos);
		اگر (setsockopt(fd, IPPROTO_IPV6, IPV6_TCLASS,
		    &tos, اندازه(tos)) == -1) {
			error("setsockopt socket %d IPV6_TCLASS %d: %s",
			    fd, tos, strerror(errno));
		}
# endif /* IPV6_TCLASS */
		بشکن;
	پیشفرض:
		debug2_f("unsupported socket family %d", af);
		بشکن;
	}
#endif /* IP_TOS_IS_BROKEN */
}

/*
 * Wait up to *timeoutp milliseconds for events on fd. Updates
 * *timeoutp with time remaining.
 * Returns 0 if fd ready or -1 on timeout or error (see errno).
 */
ایستا صحیح
waitfd(صحیح fd, صحیح *timeoutp, short events, فرار sig_atomic_t *stop)
{
	ساختار pollfd pfd;
	ساختار timespec timeout;
	صحیح oerrno, r;
	sigset_t nsigset, osigset;

	اگر (timeoutp && *timeoutp == -1)
		timeoutp = پوچ;
	pfd.fd = fd;
	pfd.events = events;
	ptimeout_init(&timeout);
	اگر (timeoutp != پوچ)
		ptimeout_deadline_ms(&timeout, *timeoutp);
	اگر (stop != پوچ)
		sigfillset(&nsigset);
	برای (; timeoutp == پوچ || *timeoutp >= 0;) {
		اگر (stop != پوچ) {
			sigprocmask(SIG_BLOCK, &nsigset, &osigset);
			اگر (*stop) {
				sigprocmask(SIG_SETMASK, &osigset, پوچ);
				errno = EINTR;
				بازگشت -1;
			}
		}
		r = ppoll(&pfd, 1, ptimeout_get_tsp(&timeout),
		    stop != پوچ ? &osigset : پوچ);
		oerrno = errno;
		اگر (stop != پوچ)
			sigprocmask(SIG_SETMASK, &osigset, پوچ);
		اگر (timeoutp)
			*timeoutp = ptimeout_get_ms(&timeout);
		errno = oerrno;
		اگر (r > 0)
			بازگشت 0;
		وگرنه اگر (r == -1 && errno != EAGAIN && errno != EINTR)
			بازگشت -1;
		وگرنه اگر (r == 0)
			بشکن;
	}
	/* timeout */
	errno = ETIMEDOUT;
	بازگشت -1;
}

/*
 * Wait up to *timeoutp milliseconds for fd to be readable. Updates
 * *timeoutp with time remaining.
 * Returns 0 if fd ready or -1 on timeout or error (see errno).
 */
صحیح
waitrfd(صحیح fd, صحیح *timeoutp, فرار sig_atomic_t *stop) {
	بازگشت waitfd(fd, timeoutp, POLLIN, stop);
}

/*
 * Attempt a non-blocking connect(2) to the specified address, waiting up to
 * *timeoutp milliseconds for the connection to complete. If the timeout is
 * <=0, then wait indefinitely.
 *
 * Returns 0 on success or -1 on failure.
 */
صحیح
timeout_connect(صحیح sockfd, ثابت ساختار sockaddr *serv_addr,
    socklen_t addrlen, صحیح *timeoutp)
{
	صحیح optval = 0;
	socklen_t optlen = اندازه(optval);

	/* No timeout: just do a blocking connect() */
	اگر (timeoutp == پوچ || *timeoutp <= 0)
		بازگشت connect(sockfd, serv_addr, addrlen);

	set_nonblock(sockfd);
	برای (;;) {
		اگر (connect(sockfd, serv_addr, addrlen) == 0) {
			/* Succeeded already? */
			unset_nonblock(sockfd);
			بازگشت 0;
		} وگرنه اگر (errno == EINTR)
			ادامه;
		وگرنه اگر (errno != EINPROGRESS)
			بازگشت -1;
		بشکن;
	}

	اگر (waitfd(sockfd, timeoutp, POLLIN | POLLOUT, پوچ) == -1)
		بازگشت -1;

	/* Completed or failed */
	اگر (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &optval, &optlen) == -1) {
		debug("getsockopt: %s", strerror(errno));
		بازگشت -1;
	}
	اگر (optval != 0) {
		errno = optval;
		بازگشت -1;
	}
	unset_nonblock(sockfd);
	بازگشت 0;
}

/* Characters considered whitespace in strsep calls. */
#define WHITESPACE " \t\r\n"
#define QUOTE	"\""

/* return next token in configuration line */
ایستا نویسه *
strdelim_internal(نویسه **s, صحیح split_equals)
{
	نویسه *old;
	صحیح wspace = 0;

	اگر (*s == پوچ)
		بازگشت پوچ;

	old = *s;

	*s = strpbrk(*s,
	    split_equals ? WHITESPACE QUOTE "=" : WHITESPACE QUOTE);
	اگر (*s == پوچ)
		بازگشت (old);

	اگر (*s[0] == '\"') {
		memmove(*s, *s + 1, strlen(*s)); /* move nul too */
		/* Find matching quote */
		اگر ((*s = strpbrk(*s, QUOTE)) == پوچ) {
			بازگشت (پوچ);		/* no matching quote */
		} وگرنه {
			*s[0] = '\0';
			*s += strspn(*s + 1, WHITESPACE) + 1;
			بازگشت (old);
		}
	}

	/* Allow only one '=' to be skipped */
	اگر (split_equals && *s[0] == '=')
		wspace = 1;
	*s[0] = '\0';

	/* Skip any extra whitespace after first token */
	*s += strspn(*s + 1, WHITESPACE) + 1;
	اگر (split_equals && *s[0] == '=' && !wspace)
		*s += strspn(*s + 1, WHITESPACE) + 1;

	بازگشت (old);
}

/*
 * Return next token in configuration line; splits on whitespace or a
 * single '=' character.
 */
نویسه *
strdelim(نویسه **s)
{
	بازگشت strdelim_internal(s, 1);
}

/*
 * Return next token in configuration line; splits on whitespace only.
 */
نویسه *
strdelimw(نویسه **s)
{
	بازگشت strdelim_internal(s, 0);
}

ساختار passwd *
pwcopy(ساختار passwd *pw)
{
	ساختار passwd *copy = xcalloc(1, اندازه(*copy));

	copy->pw_name = xstrdup(pw->pw_name);
	copy->pw_passwd = xstrdup(pw->pw_passwd == پوچ ? "*" : pw->pw_passwd);
#ifdef HAVE_STRUCT_PASSWD_PW_GECOS
	copy->pw_gecos = xstrdup(pw->pw_gecos == پوچ ? "" : pw->pw_gecos);
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
	copy->pw_class = xstrdup(pw->pw_class == پوچ ? "" : pw->pw_class);
#endif
	copy->pw_dir = xstrdup(pw->pw_dir == پوچ ? "" : pw->pw_dir);
	copy->pw_shell = xstrdup(pw->pw_shell == پوچ ? "" : pw->pw_shell);
	بازگشت copy;
}

تهی
pwfree(ساختار passwd *pw)
{
	اگر (pw == پوچ)
		بازگشت;
	آزاد(pw->pw_name);
	freezero(pw->pw_passwd,
	    pw->pw_passwd == پوچ ? 0 : strlen(pw->pw_passwd));
#ifdef HAVE_STRUCT_PASSWD_PW_GECOS
	آزاد(pw->pw_gecos);
#endif
#ifdef HAVE_STRUCT_PASSWD_PW_CLASS
	آزاد(pw->pw_class);
#endif
	آزاد(pw->pw_dir);
	آزاد(pw->pw_shell);
	freezero(pw, اندازه(*pw));
}

/*
 * Convert ASCII string to TCP/IP port number.
 * Port must be >=0 and <=65535.
 * Return -1 if invalid.
 */
صحیح
a2port(ثابت نویسه *s)
{
	ساختار servent *se;
	long long port;
	ثابت نویسه *errstr;

	port = strtonum(s, 0, 65535, &errstr);
	اگر (errstr == پوچ)
		بازگشت (صحیح)port;
	اگر ((se = getservbyname(s, "tcp")) != پوچ)
		بازگشت ntohs(se->s_port);
	بازگشت -1;
}

صحیح
a2tun(ثابت نویسه *s, صحیح *remote)
{
	ثابت نویسه *errstr = پوچ;
	نویسه *sp, *ep;
	صحیح tun;

	اگر (remote != پوچ) {
		*remote = SSH_TUNID_ANY;
		sp = xstrdup(s);
		اگر ((ep = strchr(sp, ':')) == پوچ) {
			آزاد(sp);
			بازگشت (a2tun(s, پوچ));
		}
		ep[0] = '\0'; ep++;
		*remote = a2tun(ep, پوچ);
		tun = a2tun(sp, پوچ);
		آزاد(sp);
		بازگشت (*remote == SSH_TUNID_ERR ? *remote : tun);
	}

	اگر (strcasecmp(s, "any") == 0)
		بازگشت (SSH_TUNID_ANY);

	tun = strtonum(s, 0, SSH_TUNID_MAX, &errstr);
	اگر (errstr != پوچ)
		بازگشت (SSH_TUNID_ERR);

	بازگشت (tun);
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
دوگانه
convtime_double(ثابت نویسه *s)
{
	دوگانه val, total_sec = 0.0, multiplier;
	ثابت نویسه *p, *start_p;
	نویسه *endp;
	صحیح seen_seconds = 0;

	اگر (s == پوچ || *s == '\0')
		بازگشت -1.0;

	برای (p = s; *p != '\0';) {
		اگر (!isdigit((unsigned نویسه)*p) && *p != '.')
			بازگشت -1.0;

		errno = 0;
		اگر ((val = strtod(p, &endp)) < 0 || errno != 0 || p == endp)
			بازگشت -1.0;
		/* Allow only decimal forms */
		اگر (p + strspn(p, "0123456789.") != endp)
			بازگشت -1.0;
		start_p = p;
		p = endp;

		انتخاب (*p) {
		حالت '\0':
			/* FALLTHROUGH */
		حالت 's':
		حالت 'S':
			اگر (seen_seconds++)
				بازگشت -1.0;
			multiplier = SECONDS;
			بشکن;
		حالت 'm':
		حالت 'M':
			multiplier = MINUTES;
			بشکن;
		حالت 'h':
		حالت 'H':
			multiplier = HOURS;
			بشکن;
		حالت 'd':
		حالت 'D':
			multiplier = DAYS;
			بشکن;
		حالت 'w':
		حالت 'W':
			multiplier = WEEKS;
			بشکن;
		پیشفرض:
			بازگشت -1.0;
		}

		/* Special handling if this was a decimal */
		اگر (memchr(start_p, '.', endp - start_p) != پوچ) {
			/* Decimal point present */
			اگر (multiplier > 1.0)
				بازگشت -1.0; /* No fractionals for non-seconds */
			/* For seconds, ensure digits follow */
			اگر (!isdigit((unsigned نویسه)*(endp - 1)))
				بازگشت -1.0;
		}

		total_sec += val * multiplier;

		اگر (*p != '\0')
			p++;
	}
	بازگشت total_sec;
}

/*
 * Same as convtime_double() above but fractional seconds are ignored.
 * Return -1 if time string is invalid.
 */
صحیح
convtime(ثابت نویسه *s)
{
	دوگانه sec_val;

	اگر ((sec_val = convtime_double(s)) < 0.0)
		بازگشت -1;

	/* Check for overflow into int */
	اگر (sec_val < 0 || sec_val > INT_MAX)
		بازگشت -1;

	بازگشت (صحیح)sec_val;
}

#define TF_BUFS	8
#define TF_LEN	9

ثابت نویسه *
fmt_timeframe(time_t t)
{
	نویسه		*buf;
	ایستا نویسه	 tfbuf[TF_BUFS][TF_LEN];	/* ring buffer */
	ایستا صحیح	 idx = 0;
	unsigned صحیح	 sec, min, hrs, day;
	unsigned long long	week;

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
	وگرنه اگر (day > 0)
		snprintf(buf, TF_LEN, "%01ud%02uh%02um", day, hrs, min);
	وگرنه
		snprintf(buf, TF_LEN, "%02u:%02u:%02u", hrs, min, sec);

	بازگشت (buf);
}

/*
 * Returns a standardized host+port identifier string.
 * Caller must free returned string.
 */
نویسه *
put_host_port(ثابت نویسه *host, u_short port)
{
	نویسه *hoststr;

	اگر (port == 0 || port == SSH_DEFAULT_PORT)
		بازگشت(xstrdup(host));
	اگر (asprintf(&hoststr, "[%s]:%d", host, (صحیح)port) == -1)
		fatal("put_host_port: asprintf: %s", strerror(errno));
	debug3("put_host_port: %s", hoststr);
	بازگشت hoststr;
}

/*
 * Search for next delimiter between hostnames/addresses and ports.
 * Argument may be modified (for termination).
 * Returns *cp if parsing succeeds.
 * *cp is set to the start of the next field, if one was found.
 * The delimiter char, if present, is stored in delim.
 * If this is the last field, *cp is set to NULL.
 */
نویسه *
hpdelim2(نویسه **cp, نویسه *delim)
{
	نویسه *s, *old;

	اگر (cp == پوچ || *cp == پوچ)
		بازگشت پوچ;

	old = s = *cp;
	اگر (*s == '[') {
		اگر ((s = strchr(s, ']')) == پوچ)
			بازگشت پوچ;
		وگرنه
			s++;
	} وگرنه اگر ((s = strpbrk(s, ":/")) == پوچ)
		s = *cp + strlen(*cp); /* skip to end (see first case below) */

	انتخاب (*s) {
	حالت '\0':
		*cp = پوچ;	/* no more fields*/
		بشکن;

	حالت ':':
	حالت '/':
		اگر (delim != پوچ)
			*delim = *s;
		*s = '\0';	/* terminate */
		*cp = s + 1;
		بشکن;

	پیشفرض:
		بازگشت پوچ;
	}

	بازگشت old;
}

/* The common case: only accept colon as delimiter. */
نویسه *
hpdelim(نویسه **cp)
{
	نویسه *r, delim = '\0';

	r =  hpdelim2(cp, &delim);
	اگر (delim == '/')
		بازگشت پوچ;
	بازگشت r;
}

نویسه *
cleanhostname(نویسه *host)
{
	اگر (*host == '[' && host[strlen(host) - 1] == ']') {
		host[strlen(host) - 1] = '\0';
		بازگشت (host + 1);
	} وگرنه
		بازگشت host;
}

نویسه *
colon(نویسه *cp)
{
	صحیح flag = 0;

	اگر (*cp == ':')		/* Leading colon is part of file name. */
		بازگشت پوچ;
	اگر (*cp == '[')
		flag = 1;

	برای (; *cp; ++cp) {
		اگر (*cp == '@' && *(cp+1) == '[')
			flag = 1;
		اگر (*cp == ']' && *(cp+1) == ':' && flag)
			بازگشت (cp+1);
		اگر (*cp == ':' && !flag)
			بازگشت (cp);
		اگر (*cp == '/')
			بازگشت پوچ;
	}
	بازگشت پوچ;
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
parse_user_host_path(ثابت نویسه *s, نویسه **userp, نویسه **hostp, نویسه **pathp)
{
	نویسه *user = پوچ, *host = پوچ, *path = پوچ;
	نویسه *sdup, *tmp;
	صحیح ret = -1;

	اگر (userp != پوچ)
		*userp = پوچ;
	اگر (hostp != پوچ)
		*hostp = پوچ;
	اگر (pathp != پوچ)
		*pathp = پوچ;

	sdup = xstrdup(s);

	/* Check for remote syntax: [user@]host:[path] */
	اگر ((tmp = colon(sdup)) == پوچ)
		برو out;

	/* Extract optional path */
	*tmp++ = '\0';
	اگر (*tmp == '\0')
		tmp = ".";
	path = xstrdup(tmp);

	/* Extract optional user and mandatory host */
	tmp = strrchr(sdup, '@');
	اگر (tmp != پوچ) {
		*tmp++ = '\0';
		host = xstrdup(cleanhostname(tmp));
		اگر (*sdup != '\0')
			user = xstrdup(sdup);
	} وگرنه {
		host = xstrdup(cleanhostname(sdup));
		user = پوچ;
	}

	/* Success */
	اگر (userp != پوچ) {
		*userp = user;
		user = پوچ;
	}
	اگر (hostp != پوچ) {
		*hostp = host;
		host = پوچ;
	}
	اگر (pathp != پوچ) {
		*pathp = path;
		path = پوچ;
	}
	ret = 0;
out:
	آزاد(sdup);
	آزاد(user);
	آزاد(host);
	آزاد(path);
	بازگشت ret;
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
parse_user_host_port(ثابت نویسه *s, نویسه **userp, نویسه **hostp, صحیح *portp)
{
	نویسه *sdup, *cp, *tmp;
	نویسه *user = پوچ, *host = پوچ;
	صحیح port = -1, ret = -1;

	اگر (userp != پوچ)
		*userp = پوچ;
	اگر (hostp != پوچ)
		*hostp = پوچ;
	اگر (portp != پوچ)
		*portp = -1;

	اگر ((sdup = tmp = strdup(s)) == پوچ)
		بازگشت -1;
	/* Extract optional username */
	اگر ((cp = strrchr(tmp, '@')) != پوچ) {
		*cp = '\0';
		اگر (*tmp == '\0')
			برو out;
		اگر ((user = strdup(tmp)) == پوچ)
			برو out;
		tmp = cp + 1;
	}
	/* Extract mandatory hostname */
	اگر ((cp = hpdelim(&tmp)) == پوچ || *cp == '\0')
		برو out;
	host = xstrdup(cleanhostname(cp));
	/* Convert and verify optional port */
	اگر (tmp != پوچ && *tmp != '\0') {
		اگر ((port = a2port(tmp)) <= 0)
			برو out;
	}
	/* Success */
	اگر (userp != پوچ) {
		*userp = user;
		user = پوچ;
	}
	اگر (hostp != پوچ) {
		*hostp = host;
		host = پوچ;
	}
	اگر (portp != پوچ)
		*portp = port;
	ret = 0;
 out:
	آزاد(sdup);
	آزاد(user);
	آزاد(host);
	بازگشت ret;
}

/*
 * Converts a two-byte hex string to decimal.
 * Returns the decimal value or -1 for invalid input.
 */
ایستا صحیح
hexchar(ثابت نویسه *s)
{
	unsigned نویسه result[2];
	صحیح i;

	برای (i = 0; i < 2; i++) {
		اگر (s[i] >= '0' && s[i] <= '9')
			result[i] = (unsigned نویسه)(s[i] - '0');
		وگرنه اگر (s[i] >= 'a' && s[i] <= 'f')
			result[i] = (unsigned نویسه)(s[i] - 'a') + 10;
		وگرنه اگر (s[i] >= 'A' && s[i] <= 'F')
			result[i] = (unsigned نویسه)(s[i] - 'A') + 10;
		وگرنه
			بازگشت -1;
	}
	بازگشت (result[0] << 4) | result[1];
}

/*
 * Decode an url-encoded string.
 * Returns a newly allocated string on success or NULL on failure.
 */
ایستا نویسه *
urldecode(ثابت نویسه *src)
{
	نویسه *ret, *dst;
	صحیح ch;
	size_t srclen;

	اگر ((srclen = strlen(src)) >= SIZE_MAX)
		بازگشت پوچ;
	ret = xmalloc(srclen + 1);
	برای (dst = ret; *src != '\0'; src++) {
		انتخاب (*src) {
		حالت '+':
			*dst++ = ' ';
			بشکن;
		حالت '%':
			/* note: don't allow \0 characters */
			اگر (!isxdigit((unsigned نویسه)src[1]) ||
			    !isxdigit((unsigned نویسه)src[2]) ||
			    (ch = hexchar(src + 1)) == -1 || ch == 0) {
				آزاد(ret);
				بازگشت پوچ;
			}
			*dst++ = ch;
			src += 2;
			بشکن;
		پیشفرض:
			*dst++ = *src;
			بشکن;
		}
	}
	*dst = '\0';

	بازگشت ret;
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
parse_uri(ثابت نویسه *scheme, ثابت نویسه *uri, نویسه **userp, نویسه **hostp,
    صحیح *portp, نویسه **pathp)
{
	نویسه *uridup, *cp, *tmp, ch;
	نویسه *user = پوچ, *host = پوچ, *path = پوچ;
	صحیح port = -1, ret = -1;
	size_t len;

	len = strlen(scheme);
	اگر (strncmp(uri, scheme, len) != 0 || strncmp(uri + len, "://", 3) != 0)
		بازگشت 1;
	uri += len + 3;

	اگر (userp != پوچ)
		*userp = پوچ;
	اگر (hostp != پوچ)
		*hostp = پوچ;
	اگر (portp != پوچ)
		*portp = -1;
	اگر (pathp != پوچ)
		*pathp = پوچ;

	uridup = tmp = xstrdup(uri);

	/* Extract optional ssh-info (username + connection params) */
	اگر ((cp = strchr(tmp, '@')) != پوچ) {
		نویسه *delim;

		*cp = '\0';
		/* Extract username and connection params */
		اگر ((delim = strchr(tmp, ';')) != پوچ) {
			/* Just ignore connection params for now */
			*delim = '\0';
		}
		اگر (*tmp == '\0') {
			/* Empty username */
			برو out;
		}
		اگر ((user = urldecode(tmp)) == پوچ)
			برو out;
		tmp = cp + 1;
	}

	/* Extract mandatory hostname */
	اگر ((cp = hpdelim2(&tmp, &ch)) == پوچ || *cp == '\0')
		برو out;
	host = xstrdup(cleanhostname(cp));
	اگر (!valid_domain(host, 0, پوچ))
		برو out;

	اگر (tmp != پوچ && *tmp != '\0') {
		اگر (ch == ':') {
			/* Convert and verify port. */
			اگر ((cp = strchr(tmp, '/')) != پوچ)
				*cp = '\0';
			اگر ((port = a2port(tmp)) <= 0)
				برو out;
			tmp = cp ? cp + 1 : پوچ;
		}
		اگر (tmp != پوچ && *tmp != '\0') {
			/* Extract optional path */
			اگر ((path = urldecode(tmp)) == پوچ)
				برو out;
		}
	}

	/* Success */
	اگر (userp != پوچ) {
		*userp = user;
		user = پوچ;
	}
	اگر (hostp != پوچ) {
		*hostp = host;
		host = پوچ;
	}
	اگر (portp != پوچ)
		*portp = port;
	اگر (pathp != پوچ) {
		*pathp = path;
		path = پوچ;
	}
	ret = 0;
 out:
	آزاد(uridup);
	آزاد(user);
	آزاد(host);
	آزاد(path);
	بازگشت ret;
}

/* function to assist building execv() arguments */
تهی
addargs(arglist *args, نویسه *fmt, ...)
{
	va_list ap;
	نویسه *cp;
	u_int nalloc;
	صحیح r;

	va_start(ap, fmt);
	r = vasprintf(&cp, fmt, ap);
	va_end(ap);
	اگر (r == -1)
		fatal_f("argument too long");

	nalloc = args->nalloc;
	اگر (args->list == پوچ) {
		nalloc = 32;
		args->رقم = 0;
	} وگرنه اگر (args->رقم > (256 * 1024))
		fatal_f("too many arguments");
	وگرنه اگر (args->رقم >= args->nalloc)
		fatal_f("arglist corrupt");
	وگرنه اگر (args->رقم+2 >= nalloc)
		nalloc *= 2;

	args->list = xrecallocarray(args->list, args->nalloc,
	    nalloc, اندازه(نویسه *));
	args->nalloc = nalloc;
	args->list[args->رقم++] = cp;
	args->list[args->رقم] = پوچ;
}

تهی
replacearg(arglist *args, u_int which, نویسه *fmt, ...)
{
	va_list ap;
	نویسه *cp;
	صحیح r;

	va_start(ap, fmt);
	r = vasprintf(&cp, fmt, ap);
	va_end(ap);
	اگر (r == -1)
		fatal_f("argument too long");
	اگر (args->list == پوچ || args->رقم >= args->nalloc)
		fatal_f("arglist corrupt");

	اگر (which >= args->رقم)
		fatal_f("tried to replace invalid arg %d >= %d",
		    which, args->رقم);
	آزاد(args->list[which]);
	args->list[which] = cp;
}

تهی
freeargs(arglist *args)
{
	u_int i;

	اگر (args == پوچ)
		بازگشت;
	اگر (args->list != پوچ && args->رقم < args->nalloc) {
		برای (i = 0; i < args->رقم; i++)
			آزاد(args->list[i]);
		آزاد(args->list);
	}
	args->nalloc = args->رقم = 0;
	args->list = پوچ;
}

/*
 * Expands tildes in the file name.  Returns data allocated by xmalloc.
 * Warning: this calls getpw*.
 */
صحیح
tilde_expand(ثابت نویسه *filename, uid_t uid, نویسه **retp)
{
	نویسه *ocopy = پوچ, *copy, *s = پوچ;
	ثابت نویسه *path = پوچ, *user = پوچ;
	ساختار passwd *pw;
	size_t len;
	صحیح ret = -1, r, slash;

	*retp = پوچ;
	اگر (*filename != '~') {
		*retp = xstrdup(filename);
		بازگشت 0;
	}
	ocopy = copy = xstrdup(filename + 1);

	اگر (*copy == '\0')				/* ~ */
		path = پوچ;
	وگرنه اگر (*copy == '/') {
		copy += strspn(copy, "/");
		اگر (*copy == '\0')
			path = پوچ;			/* ~/ */
		وگرنه
			path = copy;			/* ~/path */
	} وگرنه {
		user = copy;
		اگر ((path = strchr(copy, '/')) != پوچ) {
			copy[path - copy] = '\0';
			path++;
			path += strspn(path, "/");
			اگر (*path == '\0')		/* ~user/ */
				path = پوچ;
			/* else				 ~user/path */
		}
		/* else					~user */
	}
	اگر (user != پوچ) {
		اگر ((pw = getpwnam(user)) == پوچ) {
			error_f("No such user %s", user);
			برو out;
		}
	} وگرنه اگر ((pw = getpwuid(uid)) == پوچ) {
		error_f("No such uid %ld", (long)uid);
		برو out;
	}

	/* Make sure directory has a trailing '/' */
	slash = (len = strlen(pw->pw_dir)) == 0 || pw->pw_dir[len - 1] != '/';

	اگر ((r = xasprintf(&s, "%s%s%s", pw->pw_dir,
	    slash ? "/" : "", path != پوچ ? path : "")) <= 0) {
		error_f("xasprintf failed");
		برو out;
	}
	اگر (r >= PATH_MAX) {
		error_f("Path too long");
		برو out;
	}
	/* success */
	ret = 0;
	*retp = s;
	s = پوچ;
 out:
	آزاد(s);
	آزاد(ocopy);
	بازگشت ret;
}

نویسه *
tilde_expand_filename(ثابت نویسه *filename, uid_t uid)
{
	نویسه *ret;

	اگر (tilde_expand(filename, uid, &ret) != 0)
		cleanup_exit(255);
	بازگشت ret;
}

/*
 * Expand a string with a set of %[char] escapes and/or ${ENVIRONMENT}
 * substitutions.  A number of escapes may be specified as
 * (char *escape_chars, char *replacement) pairs. The list must be terminated
 * by a NULL escape_char. Returns replaced string in memory allocated by
 * xmalloc which the caller must free.
 */
ایستا نویسه *
vdollar_percent_expand(صحیح *parseerror, صحیح dollar, صحیح percent,
    ثابت نویسه *string, va_list ap)
{
#define EXPAND_MAX_کلیدها	64
	u_int رقم_کلیدها = 0, i;
	ساختار {
		ثابت نویسه *کلید;
		ثابت نویسه *repl;
	} کلیدها[EXPAND_MAX_کلیدها];
	ساختار sshbuf *buf;
	صحیح r, missingvar = 0;
	نویسه *ret = پوچ, *var, *varend, *val;
	size_t len;

	اگر ((buf = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	اگر (parseerror == پوچ)
		fatal_f("null parseerror arg");
	*parseerror = 1;

	/* Gather keys if we're doing percent expansion. */
	اگر (percent) {
		برای (رقم_کلیدها = 0; رقم_کلیدها < EXPAND_MAX_کلیدها; رقم_کلیدها++) {
			کلیدها[رقم_کلیدها].کلید = va_arg(ap, نویسه *);
			اگر (کلیدها[رقم_کلیدها].کلید == پوچ)
				بشکن;
			کلیدها[رقم_کلیدها].repl = va_arg(ap, نویسه *);
			اگر (کلیدها[رقم_کلیدها].repl == پوچ) {
				fatal_f("NULL replacement for token %s",
				    کلیدها[رقم_کلیدها].کلید);
			}
		}
		اگر (رقم_کلیدها == EXPAND_MAX_کلیدها && va_arg(ap, نویسه *) != پوچ)
			fatal_f("too many keys");
		اگر (رقم_کلیدها == 0)
			fatal_f("percent expansion without token list");
	}

	/* Expand string */
	برای (i = 0; *string != '\0'; string++) {
		/* Optionally process ${ENVIRONMENT} expansions. */
		اگر (dollar && string[0] == '$' && string[1] == '{') {
			string += 2;  /* skip over '${' */
			اگر ((varend = strchr(string, '}')) == پوچ) {
				error_f("environment variable '%s' missing "
				    "closing '}'", string);
				برو out;
			}
			len = varend - string;
			اگر (len == 0) {
				error_f("zero-length environment variable");
				برو out;
			}
			var = xmalloc(len + 1);
			(تهی)strlcpy(var, string, len + 1);
			اگر ((val = getenv(var)) == پوچ) {
				error_f("env var ${%s} has no value", var);
				missingvar = 1;
			} وگرنه {
				debug3_f("expand ${%s} -> '%s'", var, val);
				اگر ((r = sshbuf_put(buf, val, strlen(val))) !=0)
					fatal_fr(r, "sshbuf_put ${}");
			}
			آزاد(var);
			string += len;
			ادامه;
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
			ادامه;
		}
		string++;
		/* %% case */
		اگر (*string == '%')
			برو append;
		اگر (*string == '\0') {
			error_f("invalid format");
			برو out;
		}
		برای (i = 0; i < رقم_کلیدها; i++) {
			اگر (strchr(کلیدها[i].کلید, *string) != پوچ) {
				اگر ((r = sshbuf_put(buf, کلیدها[i].repl,
				    strlen(کلیدها[i].repl))) != 0)
					fatal_fr(r, "sshbuf_put %%-repl");
				بشکن;
			}
		}
		اگر (i >= رقم_کلیدها) {
			error_f("unknown key %%%c", *string);
			برو out;
		}
	}
	اگر (!missingvar && (ret = sshbuf_dup_string(buf)) == پوچ)
		fatal_f("sshbuf_dup_string failed");
	*parseerror = 0;
 out:
	sshbuf_free(buf);
	بازگشت *parseerror ? پوچ : ret;
#undef EXPAND_MAX_کلیدها
}

/*
 * Expand only environment variables.
 * Note that although this function is variadic like the other similar
 * functions, any such arguments will be unused.
 */

نویسه *
dollar_expand(صحیح *parseerr, ثابت نویسه *string, ...)
{
	نویسه *ret;
	صحیح err;
	va_list ap;

	va_start(ap, string);
	ret = vdollar_percent_expand(&err, 1, 0, string, ap);
	va_end(ap);
	اگر (parseerr != پوچ)
		*parseerr = err;
	بازگشت ret;
}

/*
 * Returns expanded string or NULL if a specified environment variable is
 * not defined, or calls fatal if the string is invalid.
 */
نویسه *
percent_expand(ثابت نویسه *string, ...)
{
	نویسه *ret;
	صحیح err;
	va_list ap;

	va_start(ap, string);
	ret = vdollar_percent_expand(&err, 0, 1, string, ap);
	va_end(ap);
	اگر (err)
		fatal_f("failed");
	بازگشت ret;
}

/*
 * Returns expanded string or NULL if a specified environment variable is
 * not defined, or calls fatal if the string is invalid.
 */
نویسه *
percent_dollar_expand(ثابت نویسه *string, ...)
{
	نویسه *ret;
	صحیح err;
	va_list ap;

	va_start(ap, string);
	ret = vdollar_percent_expand(&err, 1, 1, string, ap);
	va_end(ap);
	اگر (err)
		fatal_f("failed");
	بازگشت ret;
}

صحیح
tun_open(صحیح tun, صحیح mode, نویسه **ifname)
{
#اگر defined(CUSTOM_SYS_TUN_OPEN)
	بازگشت (sys_tun_open(tun, mode, ifname));
#وگرنهاگر defined(SSH_TUN_OPENBSD)
	ساختار ifreq ifr;
	نویسه name[100];
	صحیح fd = -1, sock;
	ثابت نویسه *tunbase = "tun";

	اگر (ifname != پوچ)
		*ifname = پوچ;

	اگر (mode == SSH_TUNMODE_ETHERNET)
		tunbase = "tap";

	/* Open the tunnel device */
	اگر (tun <= SSH_TUNID_MAX) {
		snprintf(name, اندازه(name), "/dev/%s%d", tunbase, tun);
		fd = open(name, O_RDWR);
	} وگرنه اگر (tun == SSH_TUNID_ANY) {
		برای (tun = 100; tun >= 0; tun--) {
			snprintf(name, اندازه(name), "/dev/%s%d",
			    tunbase, tun);
			اگر ((fd = open(name, O_RDWR)) >= 0)
				بشکن;
		}
	} وگرنه {
		debug_f("invalid tunnel %u", tun);
		بازگشت -1;
	}

	اگر (fd == -1) {
		debug_f("%s open: %s", name, strerror(errno));
		بازگشت -1;
	}

	debug_f("%s mode %d fd %d", name, mode, fd);

	/* Bring interface up if it is not already */
	snprintf(ifr.ifr_name, اندازه(ifr.ifr_name), "%s%d", tunbase, tun);
	اگر ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
		برو failed;

	اگر (ioctl(sock, SIOCGIFFLAGS, &ifr) == -1) {
		debug_f("get interface %s flags: %s", ifr.ifr_name,
		    strerror(errno));
		برو failed;
	}

	اگر (!(ifr.ifr_flags & IFF_UP)) {
		ifr.ifr_flags |= IFF_UP;
		اگر (ioctl(sock, SIOCSIFFLAGS, &ifr) == -1) {
			debug_f("activate interface %s: %s", ifr.ifr_name,
			    strerror(errno));
			برو failed;
		}
	}

	اگر (ifname != پوچ)
		*ifname = xstrdup(ifr.ifr_name);

	close(sock);
	بازگشت fd;

 failed:
	اگر (fd >= 0)
		close(fd);
	اگر (sock >= 0)
		close(sock);
	بازگشت -1;
#وگرنه
	error("Tunnel interfaces are not supported on this platform");
	بازگشت (-1);
#endif
}

تهی
sanitise_stdfd(تهی)
{
	صحیح nullfd, dupfd;

	اگر ((nullfd = dupfd = open(_PATH_DEVNULL, O_RDWR)) == -1) {
		fprintf(stderr, "Couldn't open /dev/null: %s\n",
		    strerror(errno));
		exit(1);
	}
	وقتی (++dupfd <= STDERR_FILENO) {
		/* Only populate closed fds. */
		اگر (fcntl(dupfd, F_GETFL) == -1 && errno == EBADF) {
			اگر (dup2(nullfd, dupfd) == -1) {
				fprintf(stderr, "dup2: %s\n", strerror(errno));
				exit(1);
			}
		}
	}
	اگر (nullfd > STDERR_FILENO)
		close(nullfd);
}

نویسه *
tohex(ثابت تهی *vp, size_t l)
{
	ثابت u_char *p = (ثابت u_char *)vp;
	نویسه b[3], *r;
	size_t i, hl;

	اگر (l > 65536)
		بازگشت xstrdup("tohex: length > 65536");

	hl = l * 2 + 1;
	r = xcalloc(1, hl);
	برای (i = 0; i < l; i++) {
		snprintf(b, اندازه(b), "%02x", p[i]);
		strlcat(r, b, hl);
	}
	بازگشت (r);
}

/*
 * Extend string *sp by the specified format. If *sp is not NULL (or empty),
 * then the separator 'sep' will be prepended before the formatted arguments.
 * Extended strings are heap allocated.
 */
تهی
xextendf(نویسه **sp, ثابت نویسه *sep, ثابت نویسه *fmt, ...)
{
	va_list ap;
	نویسه *tmp1, *tmp2;

	va_start(ap, fmt);
	xvasprintf(&tmp1, fmt, ap);
	va_end(ap);

	اگر (*sp == پوچ || **sp == '\0') {
		آزاد(*sp);
		*sp = tmp1;
		بازگشت;
	}
	xasprintf(&tmp2, "%s%s%s", *sp, sep == پوچ ? "" : sep, tmp1);
	آزاد(tmp1);
	آزاد(*sp);
	*sp = tmp2;
}


uint64_t
get_u64(ثابت تهی *vp)
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

	بازگشت (v);
}

uint32_t
get_u32(ثابت تهی *vp)
{
	ثابت u_char *p = (ثابت u_char *)vp;
	uint32_t v;

	v  = (uint32_t)p[0] << 24;
	v |= (uint32_t)p[1] << 16;
	v |= (uint32_t)p[2] << 8;
	v |= (uint32_t)p[3];

	بازگشت (v);
}

uint32_t
get_u32_le(ثابت تهی *vp)
{
	ثابت u_char *p = (ثابت u_char *)vp;
	uint32_t v;

	v  = (uint32_t)p[0];
	v |= (uint32_t)p[1] << 8;
	v |= (uint32_t)p[2] << 16;
	v |= (uint32_t)p[3] << 24;

	بازگشت (v);
}

uint16_t
get_u16(ثابت تهی *vp)
{
	ثابت u_char *p = (ثابت u_char *)vp;
	uint16_t v;

	v  = (uint16_t)p[0] << 8;
	v |= (uint16_t)p[1];

	بازگشت (v);
}

تهی
put_u64(تهی *vp, uint64_t v)
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

تهی
put_u32(تهی *vp, uint32_t v)
{
	u_char *p = (u_char *)vp;

	p[0] = (u_char)(v >> 24) & 0xff;
	p[1] = (u_char)(v >> 16) & 0xff;
	p[2] = (u_char)(v >> 8) & 0xff;
	p[3] = (u_char)v & 0xff;
}

تهی
put_u32_le(تهی *vp, uint32_t v)
{
	u_char *p = (u_char *)vp;

	p[0] = (u_char)v & 0xff;
	p[1] = (u_char)(v >> 8) & 0xff;
	p[2] = (u_char)(v >> 16) & 0xff;
	p[3] = (u_char)(v >> 24) & 0xff;
}

تهی
put_u16(تهی *vp, uint16_t v)
{
	u_char *p = (u_char *)vp;

	p[0] = (u_char)(v >> 8) & 0xff;
	p[1] = (u_char)v & 0xff;
}

تهی
ms_subtract_diff(ساختار timeval *start, صحیح *ms)
{
	ساختار timeval diff, finish;

	monotime_tv(&finish);
	timersub(&finish, start, &diff);
	*ms -= (diff.tv_sec * 1000) + (diff.tv_usec / 1000);
}

تهی
ms_to_timespec(ساختار timespec *ts, صحیح ms)
{
	اگر (ms < 0)
		ms = 0;
	ts->tv_sec = ms / 1000;
	ts->tv_nsec = (ms % 1000) * 1000 * 1000;
}

تهی
monotime_ts(ساختار timespec *ts)
{
	ساختار timeval tv;
#اگر defined(HAVE_CLOCK_GETTIME) && (defined(CLOCK_BOOTTIME) || \
    defined(CLOCK_MONOTONIC) || defined(CLOCK_REALTIME))
	ایستا صحیح gettime_failed = 0;

	اگر (!gettime_failed) {
# ifdef CLOCK_BOOTTIME
		اگر (clock_gettime(CLOCK_BOOTTIME, ts) == 0)
			بازگشت;
# endif /* CLOCK_BOOTTIME */
# ifdef CLOCK_MONOTONIC
		اگر (clock_gettime(CLOCK_MONOTONIC, ts) == 0)
			بازگشت;
# endif /* CLOCK_MONOTONIC */
# ifdef CLOCK_REALTIME
		/* Not monotonic, but we're almost out of options here. */
		اگر (clock_gettime(CLOCK_REALTIME, ts) == 0)
			بازگشت;
# endif /* CLOCK_REALTIME */
		debug3("clock_gettime: %s", strerror(errno));
		gettime_failed = 1;
	}
#endif /* HAVE_CLOCK_GETTIME && (BOOTTIME || MONOTONIC || REALTIME) */
	gettimeofday(&tv, پوچ);
	ts->tv_sec = tv.tv_sec;
	ts->tv_nsec = (long)tv.tv_usec * 1000;
}

تهی
monotime_tv(ساختار timeval *tv)
{
	ساختار timespec ts;

	monotime_ts(&ts);
	tv->tv_sec = ts.tv_sec;
	tv->tv_usec = ts.tv_nsec / 1000;
}

time_t
monotime(تهی)
{
	ساختار timespec ts;

	monotime_ts(&ts);
	بازگشت (ts.tv_sec);
}

دوگانه
monotime_double(تهی)
{
	ساختار timespec ts;

	monotime_ts(&ts);
	بازگشت (دوگانه)ts.tv_sec + (دوگانه)ts.tv_nsec / 1000000000.0;
}

تهی
bandwidth_limit_init(ساختار bwlimit *bw, uint64_t kbps, size_t buflen)
{
	bw->buflen = buflen;
	bw->rate = kbps;
	bw->thresh = buflen;
	bw->lamt = 0;
	timerclear(&bw->bwstart);
	timerclear(&bw->bwend);
}

/* Callback from read/write loop to insert bandwidth-limiting delays */
تهی
bandwidth_limit(ساختار bwlimit *bw, size_t read_len)
{
	uint64_t waitlen;
	ساختار timespec ts, rm;

	bw->lamt += read_len;
	اگر (!timerisset(&bw->bwstart)) {
		monotime_tv(&bw->bwstart);
		بازگشت;
	}
	اگر (bw->lamt < bw->thresh)
		بازگشت;

	monotime_tv(&bw->bwend);
	timersub(&bw->bwend, &bw->bwstart, &bw->bwend);
	اگر (!timerisset(&bw->bwend))
		بازگشت;

	bw->lamt *= 8;
	waitlen = (دوگانه)1000000L * bw->lamt / bw->rate;

	bw->bwstart.tv_sec = waitlen / 1000000L;
	bw->bwstart.tv_usec = waitlen % 1000000L;

	اگر (timercmp(&bw->bwstart, &bw->bwend, >)) {
		timersub(&bw->bwstart, &bw->bwend, &bw->bwend);

		/* Adjust the wait time */
		اگر (bw->bwend.tv_sec) {
			bw->thresh /= 2;
			اگر (bw->thresh < bw->buflen / 4)
				bw->thresh = bw->buflen / 4;
		} وگرنه اگر (bw->bwend.tv_usec < 10000) {
			bw->thresh *= 2;
			اگر (bw->thresh > bw->buflen * 8)
				bw->thresh = bw->buflen * 8;
		}

		TIMEVAL_TO_TIMESPEC(&bw->bwend, &ts);
		وقتی (nanosleep(&ts, &rm) == -1) {
			اگر (errno != EINTR)
				بشکن;
			ts = rm;
		}
	}

	bw->lamt = 0;
	monotime_tv(&bw->bwstart);
}

/* Make a template filename for mk[sd]temp() */
تهی
mktemp_proto(نویسه *s, size_t len)
{
	ثابت نویسه *tmpdir;
	صحیح r;

	اگر ((tmpdir = getenv("TMPDIR")) != پوچ) {
		r = snprintf(s, len, "%s/ssh-XXXXXXXXXXXX", tmpdir);
		اگر (r > 0 && (size_t)r < len)
			بازگشت;
	}
	r = snprintf(s, len, "/tmp/ssh-XXXXXXXXXXXX");
	اگر (r < 0 || (size_t)r >= len)
		fatal_f("template string too short");
}

ایستا ثابت ساختار {
	ثابت نویسه *name;
	صحیح مقدار;
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
	{ پوچ, -1 }
};

صحیح
parse_ipqos(ثابت نویسه *cp)
{
	ثابت نویسه *errstr;
	u_int i;
	صحیح val;

	اگر (cp == پوچ)
		بازگشت -1;
	برای (i = 0; ipqos[i].name != پوچ; i++) {
		اگر (strcasecmp(cp, ipqos[i].name) == 0)
			بازگشت ipqos[i].مقدار;
	}
	/* Try parsing as an integer */
	val = (صحیح)strtonum(cp, 0, 255, &errstr);
	اگر (errstr)
		بازگشت -1;
	بازگشت val;
}

ثابت نویسه *
iptos2str(صحیح iptos)
{
	صحیح i;
	ایستا نویسه iptos_str[اندازه "0xff"];

	برای (i = 0; ipqos[i].name != پوچ; i++) {
		اگر (ipqos[i].مقدار == iptos)
			بازگشت ipqos[i].name;
	}
	snprintf(iptos_str, اندازه iptos_str, "0x%02x", iptos);
	بازگشت iptos_str;
}

تهی
lowercase(نویسه *s)
{
	برای (; *s; s++)
		*s = tolower((u_char)*s);
}

صحیح
unix_listener(ثابت نویسه *path, صحیح backlog, صحیح unlink_first)
{
	ساختار sockaddr_un sunaddr;
	صحیح saved_errno, sock;

	memset(&sunaddr, 0, اندازه(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	اگر (strlcpy(sunaddr.sun_path, path,
	    اندازه(sunaddr.sun_path)) >= اندازه(sunaddr.sun_path)) {
		error_f("path \"%s\" too long for Unix domain socket", path);
		errno = ENAMETOOLONG;
		بازگشت -1;
	}

	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	اگر (sock == -1) {
		saved_errno = errno;
		error_f("socket: %.100s", strerror(errno));
		errno = saved_errno;
		بازگشت -1;
	}
	اگر (unlink_first == 1) {
		اگر (unlink(path) != 0 && errno != ENOENT)
			error("unlink(%s): %.100s", path, strerror(errno));
	}
	اگر (bind(sock, (ساختار sockaddr *)&sunaddr, اندازه(sunaddr)) == -1) {
		saved_errno = errno;
		error_f("cannot bind to path %s: %s", path, strerror(errno));
		close(sock);
		errno = saved_errno;
		بازگشت -1;
	}
	اگر (listen(sock, backlog) == -1) {
		saved_errno = errno;
		error_f("cannot listen on path %s: %s", path, strerror(errno));
		close(sock);
		unlink(path);
		errno = saved_errno;
		بازگشت -1;
	}
	بازگشت sock;
}

تهی
sock_set_v6only(صحیح s)
{
#اگر defined(IPV6_V6ONLY) && !defined(__OpenBSD__)
	صحیح on = 1;

	debug3_f("set socket %d IPV6_V6ONLY", s);
	اگر (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &on, اندازه(on)) == -1)
		error("setsockopt IPV6_V6ONLY: %s", strerror(errno));
#endif
}

/*
 * Compares two strings that maybe be NULL. Returns non-zero if strings
 * are both NULL or are identical, returns zero otherwise.
 */
ایستا صحیح
strcmp_maybe_null(ثابت نویسه *a, ثابت نویسه *b)
{
	اگر ((a == پوچ && b != پوچ) || (a != پوچ && b == پوچ))
		بازگشت 0;
	اگر (a != پوچ && strcmp(a, b) != 0)
		بازگشت 0;
	بازگشت 1;
}

/*
 * Compare two forwards, returning non-zero if they are identical or
 * zero otherwise.
 */
صحیح
forward_equals(ثابت ساختار Forward *a, ثابت ساختار Forward *b)
{
	اگر (strcmp_maybe_null(a->listen_host, b->listen_host) == 0)
		بازگشت 0;
	اگر (a->listen_port != b->listen_port)
		بازگشت 0;
	اگر (strcmp_maybe_null(a->listen_path, b->listen_path) == 0)
		بازگشت 0;
	اگر (strcmp_maybe_null(a->connect_host, b->connect_host) == 0)
		بازگشت 0;
	اگر (a->connect_port != b->connect_port)
		بازگشت 0;
	اگر (strcmp_maybe_null(a->connect_path, b->connect_path) == 0)
		بازگشت 0;
	/* allocated_port and handle are not checked */
	بازگشت 1;
}

/* returns port number, FWD_PERMIT_ANY_PORT or -1 on error */
صحیح
permitopen_port(ثابت نویسه *p)
{
	صحیح port;

	اگر (strcmp(p, "*") == 0)
		بازگشت FWD_PERMIT_ANY_PORT;
	اگر ((port = a2port(p)) > 0)
		بازگشت port;
	بازگشت -1;
}

/* returns 1 if process is already daemonized, 0 otherwise */
صحیح
daemonized(تهی)
{
	صحیح fd;

	اگر ((fd = open(_PATH_TTY, O_RDONLY | O_NOCTTY)) >= 0) {
		close(fd);
		بازگشت 0;	/* have controlling terminal */
	}
	اگر (getppid() != 1)
		بازگشت 0;	/* parent is not init */
	اگر (getsid(0) != getpid())
		بازگشت 0;	/* not session leader */
	debug3("already daemonized");
	بازگشت 1;
}

/*
 * Splits 's' into an argument vector. Handles quoted string and basic
 * escape characters (\\, \", \'). Caller must free the argument vector
 * and its members.
 */
صحیح
argv_split(ثابت نویسه *s, صحیح *argcp, نویسه ***argvp, صحیح terminate_on_comment)
{
	صحیح r = SSH_ERR_INTERNAL_ERROR;
	صحیح argc = 0, quote, i, j;
	نویسه *arg, **argv = xcalloc(1, اندازه(*argv));

	*argvp = پوچ;
	*argcp = 0;

	برای (i = 0; s[i] != '\0'; i++) {
		/* Skip leading whitespace */
		اگر (s[i] == ' ' || s[i] == '\t')
			ادامه;
		اگر (terminate_on_comment && s[i] == '#')
			بشکن;
		/* Start of a token */
		quote = 0;

		argv = xreallocarray(argv, (argc + 2), اندازه(*argv));
		arg = argv[argc++] = xcalloc(1, strlen(s + i) + 1);
		argv[argc] = پوچ;

		/* Copy the token in, removing escapes */
		برای (j = 0; s[i] != '\0'; i++) {
			اگر (s[i] == '\\') {
				اگر (s[i + 1] == '\'' ||
				    s[i + 1] == '\"' ||
				    s[i + 1] == '\\' ||
				    (quote == 0 && s[i + 1] == ' ')) {
					i++; /* Skip '\' */
					arg[j++] = s[i];
				} وگرنه {
					/* Unrecognised escape */
					arg[j++] = s[i];
				}
			} وگرنه اگر (quote == 0 && (s[i] == ' ' || s[i] == '\t'))
				بشکن; /* done */
			وگرنه اگر (quote == 0 && (s[i] == '\"' || s[i] == '\''))
				quote = s[i]; /* quote start */
			وگرنه اگر (quote != 0 && s[i] == quote)
				quote = 0; /* quote end */
			وگرنه
				arg[j++] = s[i];
		}
		اگر (s[i] == '\0') {
			اگر (quote != 0) {
				/* Ran out of string looking for close quote */
				r = SSH_ERR_INVALID_FORMAT;
				برو out;
			}
			بشکن;
		}
	}
	/* Success */
	*argcp = argc;
	*argvp = argv;
	argc = 0;
	argv = پوچ;
	r = 0;
 out:
	اگر (argc != 0 && argv != پوچ) {
		برای (i = 0; i < argc; i++)
			آزاد(argv[i]);
		آزاد(argv);
	}
	بازگشت r;
}

/*
 * Reassemble an argument vector into a string, quoting and escaping as
 * necessary. Caller must free returned string.
 */
نویسه *
argv_assemble(صحیح argc, نویسه **argv)
{
	صحیح i, j, ws, r;
	نویسه c, *ret;
	ساختار sshbuf *buf, *arg;

	اگر ((buf = sshbuf_new()) == پوچ || (arg = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");

	برای (i = 0; i < argc; i++) {
		ws = 0;
		sshbuf_reset(arg);
		برای (j = 0; argv[i][j] != '\0'; j++) {
			r = 0;
			c = argv[i][j];
			انتخاب (c) {
			حالت ' ':
			حالت '\t':
				ws = 1;
				r = sshbuf_put_u8(arg, c);
				بشکن;
			حالت '\\':
			حالت '\'':
			حالت '"':
				اگر ((r = sshbuf_put_u8(arg, '\\')) != 0)
					بشکن;
				/* FALLTHROUGH */
			پیشفرض:
				r = sshbuf_put_u8(arg, c);
				بشکن;
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
	اگر ((ret = malloc(sshbuf_len(buf) + 1)) == پوچ)
		fatal_f("malloc failed");
	memcpy(ret, sshbuf_ptr(buf), sshbuf_len(buf));
	ret[sshbuf_len(buf)] = '\0';
	sshbuf_free(buf);
	sshbuf_free(arg);
	بازگشت ret;
}

نویسه *
argv_next(صحیح *argcp, نویسه ***argvp)
{
	نویسه *ret = (*argvp)[0];

	اگر (*argcp > 0 && ret != پوچ) {
		(*argcp)--;
		(*argvp)++;
	}
	بازگشت ret;
}

تهی
argv_consume(صحیح *argcp)
{
	*argcp = 0;
}

تهی
argv_free(نویسه **av, صحیح ac)
{
	صحیح i;

	اگر (av == پوچ)
		بازگشت;
	برای (i = 0; i < ac; i++)
		آزاد(av[i]);
	آزاد(av);
}

/* Returns 0 if pid exited cleanly, non-zero otherwise */
صحیح
exited_cleanly(pid_t pid, ثابت نویسه *tag, ثابت نویسه *cmd, صحیح quiet)
{
	صحیح status;

	وقتی (waitpid(pid, &status, 0) == -1) {
		اگر (errno != EINTR) {
			error("%s waitpid: %s", tag, strerror(errno));
			بازگشت -1;
		}
	}
	اگر (WIFSIGNALED(status)) {
		error("%s %s exited on signal %d", tag, cmd, WTERMSIG(status));
		بازگشت -1;
	} وگرنه اگر (WEXITSTATUS(status) != 0) {
		do_log2(quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_INFO,
		    "%s %s failed, status %d", tag, cmd, WEXITSTATUS(status));
		بازگشت -1;
	}
	بازگشت 0;
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
safe_path(ثابت نویسه *name, ساختار stat *stp, ثابت نویسه *pw_dir,
    uid_t uid, نویسه *err, size_t errlen)
{
	نویسه buf[PATH_MAX], buf2[PATH_MAX], homedir[PATH_MAX];
	نویسه *cp;
	صحیح comparehome = 0;
	ساختار stat st;

	اگر (realpath(name, buf) == پوچ) {
		snprintf(err, errlen, "realpath %s failed: %s", name,
		    strerror(errno));
		بازگشت -1;
	}
	اگر (pw_dir != پوچ && realpath(pw_dir, homedir) != پوچ)
		comparehome = 1;

	اگر (!S_ISREG(stp->st_mode)) {
		snprintf(err, errlen, "%s is not a regular file", buf);
		بازگشت -1;
	}
	اگر ((!platform_sys_dir_uid(stp->st_uid) && stp->st_uid != uid) ||
	    (stp->st_mode & 022) != 0) {
		snprintf(err, errlen, "bad ownership or modes for file %s",
		    buf);
		بازگشت -1;
	}

	/* for each component of the canonical path, walking upwards */
	برای (;;) {
		/*
		 * POSIX allows dirname to modify its argument and return a
		 * pointer into it, so make a copy to avoid overlapping strlcpy.
		 */
		strlcpy(buf2, buf, اندازه(buf2));
		اگر ((cp = dirname(buf2)) == پوچ) {
			snprintf(err, errlen, "dirname() failed");
			بازگشت -1;
		}
		strlcpy(buf, cp, اندازه(buf));

		اگر (stat(buf, &st) == -1 ||
		    (!platform_sys_dir_uid(st.st_uid) && st.st_uid != uid) ||
		    (st.st_mode & 022) != 0) {
			snprintf(err, errlen,
			    "bad ownership or modes for directory %s", buf);
			بازگشت -1;
		}

		/* If are past the homedir then we can stop */
		اگر (comparehome && strcmp(homedir, buf) == 0)
			بشکن;

		/*
		 * dirname should always complete with a "/" path,
		 * but we can be paranoid and check for "." too
		 */
		اگر ((strcmp("/", buf) == 0) || (strcmp(".", buf) == 0))
			بشکن;
	}
	بازگشت 0;
}

/*
 * Version of safe_path() that accepts an open file descriptor to
 * avoid races.
 *
 * Returns 0 on success and -1 on failure
 */
صحیح
safe_path_fd(صحیح fd, ثابت نویسه *file, ساختار passwd *pw,
    نویسه *err, size_t errlen)
{
	ساختار stat st;

	/* check the open file to avoid races */
	اگر (fstat(fd, &st) == -1) {
		snprintf(err, errlen, "cannot stat file %s: %s",
		    file, strerror(errno));
		بازگشت -1;
	}
	بازگشت safe_path(file, &st, pw->pw_dir, pw->pw_uid, err, errlen);
}

/*
 * Sets the value of the given variable in the environment.  If the variable
 * already exists, its value is overridden.
 */
تهی
child_set_env(نویسه ***envp, u_int *envsizep, ثابت نویسه *name,
	ثابت نویسه *مقدار)
{
	نویسه **env;
	u_int envsize;
	u_int i, namelen;

	اگر (strchr(name, '=') != پوچ) {
		error("Invalid environment variable \"%.100s\"", name);
		بازگشت;
	}

	/*
	 * If we're passed an uninitialized list, allocate a single null
	 * entry before continuing.
	 */
	اگر ((*envp == پوچ) != (*envsizep == 0))
		fatal_f("environment size mismatch");
	اگر (*envp == پوچ && *envsizep == 0) {
		*envp = xmalloc(اندازه(نویسه *));
		*envp[0] = پوچ;
		*envsizep = 1;
	}

	/*
	 * Find the slot where the value should be stored.  If the variable
	 * already exists, we reuse the slot; otherwise we append a new slot
	 * at the end of the array, expanding if necessary.
	 */
	env = *envp;
	namelen = strlen(name);
	برای (i = 0; env[i]; i++)
		اگر (strncmp(env[i], name, namelen) == 0 && env[i][namelen] == '=')
			بشکن;
	اگر (env[i]) {
		/* Reuse the slot. */
		آزاد(env[i]);
	} وگرنه {
		/* New variable.  Expand if necessary. */
		envsize = *envsizep;
		اگر (i >= envsize - 1) {
			اگر (envsize >= 1000)
				fatal("child_set_env: too many env vars");
			envsize += 50;
			env = (*envp) = xreallocarray(env, envsize, اندازه(نویسه *));
			*envsizep = envsize;
		}
		/* Need to set the NULL pointer at end of array beyond the new slot. */
		env[i + 1] = پوچ;
	}

	/* Allocate space and format the variable in the appropriate slot. */
	/* XXX xasprintf */
	env[i] = xmalloc(strlen(name) + 1 + strlen(مقدار) + 1);
	snprintf(env[i], strlen(name) + 1 + strlen(مقدار) + 1, "%s=%s", name, مقدار);
}

/*
 * Check and optionally lowercase a domain name, also removes trailing '.'
 * Returns 1 on success and 0 on failure, storing an error message in errstr.
 */
صحیح
valid_domain(نویسه *name, صحیح makelower, ثابت نویسه **errstr)
{
	size_t i, l = strlen(name);
	u_char c, last = '\0';
	ایستا نویسه errbuf[256];

	اگر (l == 0) {
		strlcpy(errbuf, "empty domain name", اندازه(errbuf));
		برو bad;
	}
	اگر (!isalpha((u_char)name[0]) && !isdigit((u_char)name[0]) &&
	   name[0] != '_' /* technically invalid, but common */) {
		snprintf(errbuf, اندازه(errbuf), "domain name \"%.100s\" "
		    "starts with invalid character", name);
		برو bad;
	}
	برای (i = 0; i < l; i++) {
		c = tolower((u_char)name[i]);
		اگر (makelower)
			name[i] = (نویسه)c;
		اگر (last == '.' && c == '.') {
			snprintf(errbuf, اندازه(errbuf), "domain name "
			    "\"%.100s\" contains consecutive separators", name);
			برو bad;
		}
		اگر (c != '.' && c != '-' && !isalnum(c) &&
		    c != '_') /* technically invalid, but common */ {
			snprintf(errbuf, اندازه(errbuf), "domain name "
			    "\"%.100s\" contains invalid characters", name);
			برو bad;
		}
		last = c;
	}
	اگر (name[l - 1] == '.')
		name[l - 1] = '\0';
	اگر (errstr != پوچ)
		*errstr = پوچ;
	بازگشت 1;
bad:
	اگر (errstr != پوچ)
		*errstr = errbuf;
	بازگشت 0;
}

/*
 * Verify that a environment variable name (not including initial '$') is
 * valid; consisting of one or more alphanumeric or underscore characters only.
 * Returns 1 on valid, 0 otherwise.
 */
صحیح
valid_env_name(ثابت نویسه *name)
{
	ثابت نویسه *cp;

	اگر (name[0] == '\0')
		بازگشت 0;
	برای (cp = name; *cp != '\0'; cp++) {
		اگر (!isalnum((u_char)*cp) && *cp != '_')
			بازگشت 0;
	}
	بازگشت 1;
}

ثابت نویسه *
atoi_err(ثابت نویسه *nptr, صحیح *val)
{
	ثابت نویسه *errstr = پوچ;

	اگر (nptr == پوچ || *nptr == '\0')
		بازگشت "missing";
	*val = strtonum(nptr, 0, INT_MAX, &errstr);
	بازگشت errstr;
}

صحیح
parse_absolute_time(ثابت نویسه *s, uint64_t *tp)
{
	ساختار tm tm;
	time_t tt;
	نویسه buf[32], *fmt;
	ثابت نویسه *cp;
	size_t l;
	صحیح is_utc = 0;

	*tp = 0;

	l = strlen(s);
	اگر (l > 1 && strcasecmp(s + l - 1, "Z") == 0) {
		is_utc = 1;
		l--;
	} وگرنه اگر (l > 3 && strcasecmp(s + l - 3, "UTC") == 0) {
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
		snprintf(buf, اندازه(buf), "%.4s-%.2s-%.2s", s, s + 4, s + 6);
		بشکن;
	حالت 12: /* YYYYMMDDHHMM */
		fmt = "%Y-%m-%dT%H:%M";
		snprintf(buf, اندازه(buf), "%.4s-%.2s-%.2sT%.2s:%.2s",
		    s, s + 4, s + 6, s + 8, s + 10);
		بشکن;
	حالت 14: /* YYYYMMDDHHMMSS */
		fmt = "%Y-%m-%dT%H:%M:%S";
		snprintf(buf, اندازه(buf), "%.4s-%.2s-%.2sT%.2s:%.2s:%.2s",
		    s, s + 4, s + 6, s + 8, s + 10, s + 12);
		بشکن;
	پیشفرض:
		بازگشت SSH_ERR_INVALID_FORMAT;
	}

	memset(&tm, 0, اندازه(tm));
	اگر ((cp = strptime(buf, fmt, &tm)) == پوچ || *cp != '\0')
		بازگشت SSH_ERR_INVALID_FORMAT;
	اگر (is_utc) {
		tm.tm_wday = -1;	/* sentinel for error */
		اگر ((tt = timegm(&tm)) == -1 && tm.tm_wday == -1)
			بازگشت SSH_ERR_INVALID_FORMAT;
	} وگرنه {
		tm.tm_wday = -1;	/* sentinel for error */
		tm.tm_isdst = -1;	/* mktime decides DST */
		اگر ((tt = mktime(&tm)) == -1 && tm.tm_wday == -1)
			بازگشت SSH_ERR_INVALID_FORMAT;
	}
	/* success */
	*tp = (uint64_t)tt;
	بازگشت 0;
}

تهی
format_absolute_time(uint64_t t, نویسه *buf, size_t len)
{
	time_t tt = t > SSH_TIME_T_MAX ? SSH_TIME_T_MAX : t;
	ساختار tm tm;

	اگر (localtime_r(&tt, &tm) == پوچ)
		strlcpy(buf, "UNKNOWN-TIME", len);
	وگرنه
		strftime(buf, len, "%Y-%m-%dT%H:%M:%S", &tm);
}

/*
 * Parse a "pattern=interval" clause (e.g. a ChannelTimeout).
 * Returns 0 on success or non-zero on failure.
 * Caller must free *typep.
 */
صحیح
parse_pattern_interval(ثابت نویسه *s, نویسه **typep, دوگانه *secsp)
{
	نویسه *cp, *sdup;
	دوگانه secs;

	اگر (typep != پوچ)
		*typep = پوچ;
	اگر (secsp != پوچ)
		*secsp = 0;
	اگر (s == پوچ)
		بازگشت -1;
	sdup = xstrdup(s);

	اگر ((cp = strchr(sdup, '=')) == پوچ || cp == sdup) {
		آزاد(sdup);
		بازگشت -1;
	}
	*cp++ = '\0';
	اگر ((secs = convtime_double(cp)) < 0.0) {
		آزاد(sdup);
		بازگشت -1;
	}
	/* success */
	اگر (typep != پوچ)
		*typep = xstrdup(sdup);
	اگر (secsp != پوچ)
		*secsp = secs;
	آزاد(sdup);
	بازگشت 0;
}

/* check if path is absolute */
صحیح
path_absolute(ثابت نویسه *path)
{
	بازگشت (*path == '/') ? 1 : 0;
}

تهی
skip_space(نویسه **cpp)
{
	نویسه *cp;

	برای (cp = *cpp; *cp == ' ' || *cp == '\t'; cp++)
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
opt_flag(ثابت نویسه *opt, صحیح allow_negate, ثابت نویسه **optsp)
{
	size_t opt_len = strlen(opt);
	ثابت نویسه *opts = *optsp;
	صحیح negate = 0;

	اگر (allow_negate && strncasecmp(opts, "no-", 3) == 0) {
		opts += 3;
		negate = 1;
	}
	اگر (strncasecmp(opts, opt, opt_len) == 0) {
		*optsp = opts + opt_len;
		بازگشت negate ? 0 : 1;
	}
	بازگشت -1;
}

نویسه *
opt_dequote(ثابت نویسه **sp, ثابت نویسه **errstrp)
{
	ثابت نویسه *s = *sp;
	نویسه *ret;
	size_t i;

	*errstrp = پوچ;
	اگر (*s != '"') {
		*errstrp = "missing start quote";
		بازگشت پوچ;
	}
	s++;
	اگر ((ret = malloc(strlen((s)) + 1)) == پوچ) {
		*errstrp = "memory allocation failed";
		بازگشت پوچ;
	}
	برای (i = 0; *s != '\0' && *s != '"';) {
		اگر (s[0] == '\\' && s[1] == '"')
			s++;
		ret[i++] = *s++;
	}
	اگر (*s == '\0') {
		*errstrp = "missing end quote";
		آزاد(ret);
		بازگشت پوچ;
	}
	ret[i] = '\0';
	s++;
	*sp = s;
	بازگشت ret;
}

صحیح
opt_match(ثابت نویسه **opts, ثابت نویسه *term)
{
	اگر (strncasecmp((*opts), term, strlen(term)) == 0 &&
	    (*opts)[strlen(term)] == '=') {
		*opts += strlen(term) + 1;
		بازگشت 1;
	}
	بازگشت 0;
}

تهی
opt_array_append2(ثابت نویسه *file, ثابت صحیح سطر, ثابت نویسه *directive,
    نویسه ***array, صحیح **iarray, u_int *lp, ثابت نویسه *s, صحیح i)
{

	اگر (*lp >= INT_MAX)
		fatal("%s line %d: Too many %s entries", file, سطر, directive);

	اگر (iarray != پوچ) {
		*iarray = xrecallocarray(*iarray, *lp, *lp + 1,
		    اندازه(**iarray));
		(*iarray)[*lp] = i;
	}

	*array = xrecallocarray(*array, *lp, *lp + 1, اندازه(**array));
	(*array)[*lp] = xstrdup(s);
	(*lp)++;
}

تهی
opt_array_append(ثابت نویسه *file, ثابت صحیح سطر, ثابت نویسه *directive,
    نویسه ***array, u_int *lp, ثابت نویسه *s)
{
	opt_array_append2(file, سطر, directive, array, پوچ, lp, s, 0);
}

تهی
opt_array_free2(نویسه **array, صحیح **iarray, u_int l)
{
	u_int i;

	اگر (array == پوچ || l == 0)
		بازگشت;
	برای (i = 0; i < l; i++)
		آزاد(array[i]);
	آزاد(array);
	آزاد(iarray);
}

sshsig_t
ssh_signal(صحیح signum, sshsig_t handler)
{
	ساختار sigaction sa, osa;

	/* mask all other signals while in handler */
	memset(&sa, 0, اندازه(sa));
	sa.sa_handler = handler;
	sigfillset(&sa.sa_mask);
#اگر defined(SA_RESTART) && !defined(NO_SA_RESTART)
	اگر (signum != SIGALRM)
		sa.sa_flags = SA_RESTART;
#endif
	اگر (sigaction(signum, &sa, &osa) == -1) {
		debug3("sigaction(%s): %s", strsignal(signum), strerror(errno));
		بازگشت SIG_ERR;
	}
	بازگشت osa.sa_handler;
}

صحیح
stdfd_devnull(صحیح do_stdin, صحیح do_stdout, صحیح do_stderr)
{
	صحیح devnull, ret = 0;

	اگر ((devnull = open(_PATH_DEVNULL, O_RDWR)) == -1) {
		error_f("open %s: %s", _PATH_DEVNULL,
		    strerror(errno));
		بازگشت -1;
	}
	اگر ((do_stdin && dup2(devnull, STDIN_FILENO) == -1) ||
	    (do_stdout && dup2(devnull, STDOUT_FILENO) == -1) ||
	    (do_stderr && dup2(devnull, STDERR_FILENO) == -1)) {
		error_f("dup2: %s", strerror(errno));
		ret = -1;
	}
	اگر (devnull > STDERR_FILENO)
		close(devnull);
	بازگشت ret;
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
subprocess(ثابت نویسه *tag, ثابت نویسه *command,
    صحیح ac, نویسه **av, FILE **child, u_int flags,
    ساختار passwd *pw, privdrop_fn *drop_privs, privrestore_fn *restore_privs)
{
	FILE *f = پوچ;
	ساختار stat st;
	صحیح fd, devnull, p[2], i;
	pid_t pid;
	نویسه *cp, errmsg[512];
	u_int nenv = 0;
	نویسه **env = پوچ;

	/* If dropping privs, then must specify user and restore function */
	اگر (drop_privs != پوچ && (pw == پوچ || restore_privs == پوچ)) {
		error("%s: inconsistent arguments", tag); /* XXX fatal? */
		بازگشت 0;
	}
	اگر (pw == پوچ && (pw = getpwuid(getuid())) == پوچ) {
		error("%s: no user for current uid", tag);
		بازگشت 0;
	}
	اگر (child != پوچ)
		*child = پوچ;

	debug3_f("%s command \"%s\" running as %s (flags 0x%x)",
	    tag, command, pw->pw_name, flags);

	/* Check consistency */
	اگر ((flags & SSH_SUBPROCESS_STDOUT_DISCARD) != 0 &&
	    (flags & SSH_SUBPROCESS_STDOUT_CAPTURE) != 0) {
		error_f("inconsistent flags");
		بازگشت 0;
	}
	اگر (((flags & SSH_SUBPROCESS_STDOUT_CAPTURE) == 0) != (child == پوچ)) {
		error_f("inconsistent flags/output");
		بازگشت 0;
	}

	/*
	 * If executing an explicit binary, then verify the it exists
	 * and appears safe-ish to execute
	 */
	اگر (!path_absolute(av[0])) {
		error("%s path is not absolute", tag);
		بازگشت 0;
	}
	اگر (drop_privs != پوچ)
		drop_privs(pw);
	اگر (stat(av[0], &st) == -1) {
		error("Could not stat %s \"%s\": %s", tag,
		    av[0], strerror(errno));
		برو restore_return;
	}
	اگر ((flags & SSH_SUBPROCESS_UNSAFE_PATH) == 0 &&
	    safe_path(av[0], &st, پوچ, 0, errmsg, اندازه(errmsg)) != 0) {
		error("Unsafe %s \"%s\": %s", tag, av[0], errmsg);
		برو restore_return;
	}
	/* Prepare to keep the child's stdout if requested */
	اگر (pipe(p) == -1) {
		error("%s: pipe: %s", tag, strerror(errno));
 restore_return:
		اگر (restore_privs != پوچ)
			restore_privs();
		بازگشت 0;
	}
	اگر (restore_privs != پوچ)
		restore_privs();

	انتخاب ((pid = fork())) {
	حالت -1: /* error */
		error("%s: fork: %s", tag, strerror(errno));
		close(p[0]);
		close(p[1]);
		بازگشت 0;
	حالت 0: /* child */
		/* Prepare a minimal environment for the child. */
		اگر ((flags & SSH_SUBPROCESS_PRESERVE_ENV) == 0) {
			nenv = 5;
			env = xcalloc(اندازه(*env), nenv);
			child_set_env(&env, &nenv, "PATH", _PATH_STDPATH);
			child_set_env(&env, &nenv, "USER", pw->pw_name);
			child_set_env(&env, &nenv, "LOGNAME", pw->pw_name);
			child_set_env(&env, &nenv, "HOME", pw->pw_dir);
			اگر ((cp = getenv("LANG")) != پوچ)
				child_set_env(&env, &nenv, "LANG", cp);
		}

		برای (i = 1; i < NSIG; i++)
			ssh_signal(i, SIG_DFL);

		اگر ((devnull = open(_PATH_DEVNULL, O_RDWR)) == -1) {
			error("%s: open %s: %s", tag, _PATH_DEVNULL,
			    strerror(errno));
			_exit(1);
		}
		اگر (dup2(devnull, STDIN_FILENO) == -1) {
			error("%s: dup2: %s", tag, strerror(errno));
			_exit(1);
		}

		/* Set up stdout as requested; leave stderr in place for now. */
		fd = -1;
		اگر ((flags & SSH_SUBPROCESS_STDOUT_CAPTURE) != 0)
			fd = p[1];
		وگرنه اگر ((flags & SSH_SUBPROCESS_STDOUT_DISCARD) != 0)
			fd = devnull;
		اگر (fd != -1 && dup2(fd, STDOUT_FILENO) == -1) {
			error("%s: dup2: %s", tag, strerror(errno));
			_exit(1);
		}
		closefrom(STDERR_FILENO + 1);

		اگر (geteuid() == 0 &&
		    initgroups(pw->pw_name, pw->pw_gid) == -1) {
			error("%s: initgroups(%s, %u): %s", tag,
			    pw->pw_name, (u_int)pw->pw_gid, strerror(errno));
			_exit(1);
		}
		اگر (setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) == -1) {
			error("%s: setresgid %u: %s", tag, (u_int)pw->pw_gid,
			    strerror(errno));
			_exit(1);
		}
		اگر (setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) == -1) {
			error("%s: setresuid %u: %s", tag, (u_int)pw->pw_uid,
			    strerror(errno));
			_exit(1);
		}
		/* stdin is pointed to /dev/null at this point */
		اگر ((flags & SSH_SUBPROCESS_STDOUT_DISCARD) != 0 &&
		    dup2(STDIN_FILENO, STDERR_FILENO) == -1) {
			error("%s: dup2: %s", tag, strerror(errno));
			_exit(1);
		}
		اگر (env != پوچ)
			execve(av[0], av, env);
		وگرنه
			execv(av[0], av);
		error("%s %s \"%s\": %s", tag, env == پوچ ? "execv" : "execve",
		    command, strerror(errno));
		_exit(127);
	پیشفرض: /* parent */
		بشکن;
	}

	close(p[1]);
	اگر ((flags & SSH_SUBPROCESS_STDOUT_CAPTURE) == 0)
		close(p[0]);
	وگرنه اگر ((f = fdopen(p[0], "r")) == پوچ) {
		error("%s: fdopen: %s", tag, strerror(errno));
		close(p[0]);
		/* Don't leave zombie child */
		kill(pid, SIGTERM);
		وقتی (waitpid(pid, پوچ, 0) == -1 && errno == EINTR)
			;
		بازگشت 0;
	}
	/* Success */
	debug3_f("%s pid %ld", tag, (long)pid);
	اگر (child != پوچ)
		*child = f;
	بازگشت pid;
}

ثابت نویسه *
lookup_env_in_list(ثابت نویسه *env, نویسه * ثابت *envs, size_t nenvs)
{
	size_t i, envlen;

	envlen = strlen(env);
	برای (i = 0; i < nenvs; i++) {
		اگر (strncmp(envs[i], env, envlen) == 0 &&
		    envs[i][envlen] == '=') {
			بازگشت envs[i] + envlen + 1;
		}
	}
	بازگشت پوچ;
}

ثابت نویسه *
lookup_setenv_in_list(ثابت نویسه *env, نویسه * ثابت *envs, size_t nenvs)
{
	نویسه *name, *cp;
	ثابت نویسه *ret;

	name = xstrdup(env);
	اگر ((cp = strchr(name, '=')) == پوچ) {
		آزاد(name);
		بازگشت پوچ; /* not env=val */
	}
	*cp = '\0';
	ret = lookup_env_in_list(name, envs, nenvs);
	آزاد(name);
	بازگشت ret;
}

/*
 * Helpers for managing poll(2)/ppoll(2) timeouts
 * Will remember the earliest deadline and return it for use in poll/ppoll.
 */

/* Initialise a poll/ppoll timeout with an indefinite deadline */
تهی
ptimeout_init(ساختار timespec *pt)
{
	/*
	 * Deliberately invalid for ppoll(2).
	 * Will be converted to NULL in ptimeout_get_tspec() later.
	 */
	pt->tv_sec = -1;
	pt->tv_nsec = 0;
}

/* Specify a poll/ppoll deadline of at most 'sec' seconds */
تهی
ptimeout_deadline_sec(ساختار timespec *pt, long sec)
{
	اگر (pt->tv_sec == -1 || pt->tv_sec >= sec) {
		pt->tv_sec = sec;
		pt->tv_nsec = 0;
	}
}

/* Specify a poll/ppoll deadline of at most 'p' (timespec) */
ایستا تهی
ptimeout_deadline_tsp(ساختار timespec *pt, ساختار timespec *p)
{
	اگر (pt->tv_sec == -1 || timespeccmp(pt, p, >=))
		*pt = *p;
}

/* Specify a poll/ppoll deadline of at most 'ms' milliseconds */
تهی
ptimeout_deadline_ms(ساختار timespec *pt, long ms)
{
	ساختار timespec p;

	p.tv_sec = ms / 1000;
	p.tv_nsec = (ms % 1000) * 1000000;
	ptimeout_deadline_tsp(pt, &p);
}

/* Specify a poll/ppoll deadline of at most 'sec' seconds (double) */
تهی
ptimeout_deadline_sec_double(ساختار timespec *pt, دوگانه sec)
{
	ساختار timespec t;

	memset(&t, 0, اندازه(t));
	اگر ((int64_t)sec >= SSH_TIME_T_MAX)
		t.tv_sec = SSH_TIME_T_MAX;
	وگرنه اگر (sec > 0) {
		t.tv_sec = sec;
		t.tv_nsec = (sec - (دوگانه)t.tv_sec) * 1000000000.0;
	}
	ptimeout_deadline_tsp(pt, &t);
}

/* Specify a poll/ppoll deadline at wall clock monotime 'when' (timespec) */
تهی
ptimeout_deadline_monotime_tsp(ساختار timespec *pt, ساختار timespec *when)
{
	ساختار timespec now, t;

	monotime_ts(&now);

	اگر (timespeccmp(&now, when, >=)) {
		/* 'when' is now or in the past. Timeout ASAP */
		pt->tv_sec = 0;
		pt->tv_nsec = 0;
	} وگرنه {
		timespecsub(when, &now, &t);
		ptimeout_deadline_tsp(pt, &t);
	}
}

/* Specify a poll/ppoll deadline at wall clock monotime 'when' (double) */
تهی
ptimeout_deadline_monotime_double(ساختار timespec *pt, دوگانه when)
{
	ptimeout_deadline_sec_double(pt, when - monotime_double());
}

/* Specify a poll/ppoll deadline at wall clock monotime 'when' */
تهی
ptimeout_deadline_monotime(ساختار timespec *pt, time_t when)
{
	ساختار timespec t;

	t.tv_sec = when;
	t.tv_nsec = 0;
	ptimeout_deadline_monotime_tsp(pt, &t);
}

/* Get a poll(2) timeout value in milliseconds */
صحیح
ptimeout_get_ms(ساختار timespec *pt)
{
	اگر (pt->tv_sec == -1)
		بازگشت -1;
	اگر (pt->tv_sec >= (INT_MAX - (pt->tv_nsec / 1000000)) / 1000)
		بازگشت INT_MAX;
	بازگشت (pt->tv_sec * 1000) + (pt->tv_nsec / 1000000);
}

/* Get a ppoll(2) timeout value as a timespec pointer */
ساختار timespec *
ptimeout_get_tsp(ساختار timespec *pt)
{
	بازگشت pt->tv_sec == -1 ? پوچ : pt;
}

/* Returns non-zero if a timeout has been set (i.e. is not indefinite) */
صحیح
ptimeout_isset(ساختار timespec *pt)
{
	بازگشت pt->tv_sec != -1;
}

/*
 * Returns zero if the library at 'path' contains symbol 's', nonzero
 * otherwise.
 */
صحیح
lib_contains_نماد(ثابت نویسه *path, ثابت نویسه *s)
{
#ifdef HAVE_NLIST
	ساختار nlist nl[2];
	صحیح ret = -1, r;

	memset(nl, 0, اندازه(nl));
	nl[0].n_name = xstrdup(s);
	nl[1].n_name = پوچ;
	اگر ((r = nlist(path, nl)) == -1) {
		error_f("nlist failed for %s", path);
		برو out;
	}
	اگر (r != 0 || nl[0].n_مقدار == 0 || nl[0].n_type == 0) {
		error_f("library %s does not contain symbol %s", path, s);
		برو out;
	}
	/* success */
	ret = 0;
 out:
	آزاد(nl[0].n_name);
	بازگشت ret;
#وگرنه /* HAVE_NLIST */
	صحیح fd, ret = -1;
	ساختار stat st;
	تهی *m = پوچ;
	size_t sz = 0;

	memset(&st, 0, اندازه(st));
	اگر ((fd = open(path, O_RDONLY)) < 0) {
		error_f("open %s: %s", path, strerror(errno));
		بازگشت -1;
	}
	اگر (fstat(fd, &st) != 0) {
		error_f("fstat %s: %s", path, strerror(errno));
		برو out;
	}
	اگر (!S_ISREG(st.st_mode)) {
		error_f("%s is not a regular file", path);
		برو out;
	}
	اگر (st.st_size < 0 ||
	    (size_t)st.st_size < strlen(s) ||
	    st.st_size >= INT_MAX/2) {
		error_f("%s bad size %lld", path, (long long)st.st_size);
		برو out;
	}
	sz = (size_t)st.st_size;
	اگر ((m = mmap(پوچ, sz, PROT_READ, MAP_PRIVATE, fd, 0)) == MAP_FAILED ||
	    m == پوچ) {
		error_f("mmap %s: %s", path, strerror(errno));
		برو out;
	}
	اگر (memmem(m, sz, s, strlen(s)) == پوچ) {
		error_f("%s does not contain expected string %s", path, s);
		برو out;
	}
	/* success */
	ret = 0;
 out:
	اگر (m != پوچ && m != MAP_FAILED)
		munmap(m, sz);
	close(fd);
	بازگشت ret;
#endif /* HAVE_NLIST */
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
		بازگشت 1;
	}
	بازگشت 0;
}

نویسه *
get_homedir(تهی)
{
	نویسه *cp;
	ساختار passwd *pw;

	اگر ((cp = getenv("HOME")) != پوچ && *cp != '\0')
		بازگشت xstrdup(cp);

	اگر ((pw = getpwuid(getuid())) != پوچ && *pw->pw_dir != '\0')
		بازگشت xstrdup(pw->pw_dir);

	بازگشت پوچ;
}

صحیح
mkdir_path(ثابت نویسه *target, mode_t mode)
{
#اگر defined(HAVE_OPENAT) && defined(O_DIRECTORY)
	نویسه *dir, *odir = پوچ, *next;
	صحیح fd = AT_FDCWD, fd2, subpath_len, ret = -1;

	dir = odir = xstrdup(target);

	اگر (*dir == '/' &&
	    (fd = open("/", O_RDONLY|O_DIRECTORY)) == -1) {
		error_f("open(\"/\"): %s", strerror(errno));
		آزاد(odir);
		بازگشت -1;
	}
	/* Work through the path, component-wise */
	برای (; dir != پوچ && *dir != '\0'; dir = next) {
		اگر ((next = strchr(dir, '/')) != پوچ)
			*(next++) = '\0';
		اگر (*dir == '\0')
			ادامه;
		subpath_len = (next == پوچ) ? INT_MAX : next - odir - 1;
		اگر (mkdirat(fd, dir, mode) == 0)
			debug_f("created directory %.*s", subpath_len, target);
		وگرنه اگر (errno != EEXIST) {
			error_f("mkdir(\"%.*s\"): %s",
			    subpath_len, target, strerror(errno));
			برو out;
		}

		/* descend */
		اگر ((fd2 = openat(fd, dir, O_RDONLY|O_DIRECTORY)) == -1) {
			error_f("open(\"%.*s\"): %s",
			    subpath_len, target, strerror(errno));
			برو out;
		}
		اگر (fd != AT_FDCWD)
			close(fd);
		fd = fd2;
	}
	/* success */
	ret = 0;
 out:
	آزاد(odir);
	اگر (fd != AT_FDCWD)
		close(fd);
	بازگشت ret;
#وگرنه
	/*
	 * If we don't have openat (which was added in POSIX.1-2008), fall back
	 * to the possibly racy way.
	 */
	نویسه *dir, *odir, *p, path[PATH_MAX] = "";
	صحیح ret = -1;
	size_t plen = اندازه(path);

	dir = odir = xstrdup(target);

	/* If the dir is relative, start with cwd. */
	اگر (*dir != '/' && getcwd(path, plen) == پوچ) {
		error_f("getcwd: %s", strerror(errno));
		برو out;
	}

	/* Work through the path, component-wise */
	وقتی ((p = strsep(&dir, "/"))) {
		اگر (*p == '\0')
			ادامه;
		اگر (strlcat(path, "/", plen) >= plen ||
		    strlcat(path, p, plen) >= plen)
			برو out;
		اگر (mkdir(path, mode) == 0)
			debug_f("created directory %s", path);
		وگرنه اگر (errno != EEXIST && errno != EISDIR) {
			error_f("mkdir(\"%s\"): %s", path, strerror(errno));
			برو out;
		}
	}
	/* success */
	ret = 0;
 out:
	آزاد(odir);
	بازگشت ret;
#endif
}
