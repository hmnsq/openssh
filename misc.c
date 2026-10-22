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


#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/ioctl.h>
#அந்தர்பாவ <sys/mman.h>
#அந்தர்பாவ <sys/socket.h>
#அந்தர்பாவ <sys/stat.h>
#அந்தர்பாவ <sys/time.h>
#அந்தர்பாவ <sys/wait.h>
#அந்தர்பாவ <sys/un.h>

#அந்தர்பாவ <limits.h>
#அந்தர்பாவ <libgen.h>
#அந்தர்பாவ <poll.h>
#அந்தர்பாவ <nlist.h>
#அந்தர்பாவ <signal.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdint.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <time.h>
#அந்தர்பாவ <unistd.h>

#அந்தர்பாவ <netinet/in.h>
#அந்தர்பாவ <netinet/ip.h>
#அந்தர்பாவ <netinet/tcp.h>
#அந்தர்பாவ <arpa/inet.h>

#அந்தர்பாவ <ctype.h>
#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <fcntl.h>
#அந்தர்பாவ <netdb.h>
#அந்தர்பாவ <paths.h>
#அந்தர்பாவ <pwd.h>
#அந்தர்பாவ <grp.h>
#ifdef SSH_TUN_OPENBSD
#அந்தர்பாவ <net/if.h>
#endif

#அந்தர்பாவ "xmalloc.h"
#அந்தர்பாவ "misc.h"
#அந்தர்பாவ "log.h"
#அந்தர்பாவ "ssh.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "ssherr.h"
#அந்தர்பாவ "platform.h"

/* remove newline at end of string */
எழுத்து *
chop(எழுத்து *s)
{
	எழுத்து *t = s;
	போது (*t) {
		எனில் (*t == '\n' || *t == '\r') {
			*t = '\0';
			திரும்பு s;
		}
		t++;
	}
	திரும்பு s;

}

/* remove whitespace from end of string */
வெறுமை
rtrim(எழுத்து *s)
{
	size_t i;

	எனில் ((i = strlen(s)) == 0)
		திரும்பு;
	செய் {
		i--;
		எனில் (isspace((unsigned எழுத்து)s[i]))
			s[i] = '\0';
		இல்லையெனில்
			நிறுத்து;
	} போது (i > 0);
}

/*
 * returns pointer to character after 'prefix' in 's' or otherwise NULL
 * if the prefix is not present.
 */
மாறிலி எழுத்து *
strprefix(மாறிலி எழுத்து *s, மாறிலி எழுத்து *prefix, முழு ignorecase)
{
	size_t prefixlen;

	எனில் ((prefixlen = strlen(prefix)) == 0)
		திரும்பு s;
	எனில் (ignorecase) {
		எனில் (strncasecmp(s, prefix, prefixlen) != 0)
			திரும்பு வெற்று;
	} இல்லையெனில் {
		எனில் (strncmp(s, prefix, prefixlen) != 0)
			திரும்பு வெற்று;
	}
	திரும்பு s + prefixlen;
}

/* Append string 's' to a NULL-terminated array of strings */
வெறுமை
stringlist_append(எழுத்து ***listp, மாறிலி எழுத்து *s)
{
	size_t i = 0;

	எனில் (*listp == வெற்று)
		*listp = xcalloc(2, அளவு(**listp));
	இல்லையெனில் {
		க்கு (i = 0; (*listp)[i] != வெற்று; i++)
			; /* count */
		*listp = xrecallocarray(*listp, i + 1, i + 2, அளவு(**listp));
	}
	(*listp)[i] = xstrdup(s);
}

வெறுமை
stringlist_free(எழுத்து **list)
{
	size_t i = 0;

	எனில் (list == வெற்று)
		திரும்பு;
	க்கு (i = 0; list[i] != வெற்று; i++)
		விடுவி(list[i]);
	விடுவி(list);
}

/* set/unset filedescriptor to non-blocking */
முழு
set_nonblock(முழு fd)
{
	முழு val;

	val = fcntl(fd, F_GETFL);
	எனில் (val == -1) {
		error("fcntl(%d, F_GETFL): %s", fd, strerror(errno));
		திரும்பு (-1);
	}
	எனில் (val & O_NONBLOCK) {
		debug3("fd %d is O_NONBLOCK", fd);
		திரும்பு (0);
	}
	debug2("fd %d setting O_NONBLOCK", fd);
	val |= O_NONBLOCK;
	எனில் (fcntl(fd, F_SETFL, val) == -1) {
		debug("fcntl(%d, F_SETFL, O_NONBLOCK): %s", fd,
		    strerror(errno));
		திரும்பு (-1);
	}
	திரும்பு (0);
}

முழு
unset_nonblock(முழு fd)
{
	முழு val;

	val = fcntl(fd, F_GETFL);
	எனில் (val == -1) {
		error("fcntl(%d, F_GETFL): %s", fd, strerror(errno));
		திரும்பு (-1);
	}
	எனில் (!(val & O_NONBLOCK)) {
		debug3("fd %d is not O_NONBLOCK", fd);
		திரும்பு (0);
	}
	debug("fd %d clearing O_NONBLOCK", fd);
	val &= ~O_NONBLOCK;
	எனில் (fcntl(fd, F_SETFL, val) == -1) {
		debug("fcntl(%d, F_SETFL, ~O_NONBLOCK): %s",
		    fd, strerror(errno));
		திரும்பு (-1);
	}
	திரும்பு (0);
}

மாறிலி எழுத்து *
ssh_gai_strerror(முழு gaierr)
{
	எனில் (gaierr == EAI_SYSTEM && errno != 0)
		திரும்பு strerror(errno);
	திரும்பு gai_strerror(gaierr);
}

/* disable nagle on socket */
வெறுமை
set_nodelay(முழு fd)
{
	முழு opt;
	socklen_t optlen;

	optlen = அளவு opt;
	எனில் (getsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, &optlen) == -1) {
		debug("getsockopt TCP_NODELAY: %.100s", strerror(errno));
		திரும்பு;
	}
	எனில் (opt == 1) {
		debug2("fd %d is TCP_NODELAY", fd);
		திரும்பு;
	}
	opt = 1;
	debug2("fd %d setting TCP_NODELAY", fd);
	எனில் (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, அளவு opt) == -1)
		error("setsockopt TCP_NODELAY: %.100s", strerror(errno));
}

/* Allow local port reuse in TIME_WAIT */
முழு
set_reuseaddr(முழு fd)
{
	முழு on = 1;

	எனில் (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, அளவு(on)) == -1) {
		error("setsockopt SO_REUSEADDR fd %d: %s", fd, strerror(errno));
		திரும்பு -1;
	}
	திரும்பு 0;
}

/* Set TCP keepalives */
முழு
set_keepalive(முழு fd)
{
	முழு on = 1;

	எனில் (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, அளவு(on)) == -1) {
		error("setsockopt SO_KEEPALIVE fd %d: %s", fd, strerror(errno));
		திரும்பு -1;
	}
	திரும்பு 0;
}

/* Get/set routing domain */
எழுத்து *
get_rdomain(முழு fd)
{
#எனில் defined(HAVE_SYS_GET_RDOMAIN)
	திரும்பு sys_get_rdomain(fd);
#அல்லதெனில் defined(__OpenBSD__)
	முழு rtable;
	எழுத்து *ret;
	socklen_t len = அளவு(rtable);

	எனில் (getsockopt(fd, SOL_SOCKET, SO_RTABLE, &rtable, &len) == -1) {
		error("Failed to get routing domain for fd %d: %s",
		    fd, strerror(errno));
		திரும்பு வெற்று;
	}
	xasprintf(&ret, "%d", rtable);
	திரும்பு ret;
#இல்லையெனில் /* defined(__OpenBSD__) */
	திரும்பு வெற்று;
#endif
}

முழு
set_rdomain(முழு fd, மாறிலி எழுத்து *name)
{
#எனில் defined(HAVE_SYS_SET_RDOMAIN)
	திரும்பு sys_set_rdomain(fd, name);
#அல்லதெனில் defined(__OpenBSD__)
	முழு rtable;
	மாறிலி எழுத்து *errstr;

	எனில் (name == வெற்று)
		திரும்பு 0; /* default table */

	rtable = (முழு)strtonum(name, 0, 255, &errstr);
	எனில் (errstr != வெற்று) {
		/* Shouldn't happen */
		error("Invalid routing domain \"%s\": %s", name, errstr);
		திரும்பு -1;
	}
	எனில் (setsockopt(fd, SOL_SOCKET, SO_RTABLE,
	    &rtable, அளவு(rtable)) == -1) {
		error("Failed to set routing domain %d on fd %d: %s",
		    rtable, fd, strerror(errno));
		திரும்பு -1;
	}
	திரும்பு 0;
#இல்லையெனில் /* defined(__OpenBSD__) */
	error("Setting routing domain is not supported on this platform");
	திரும்பு -1;
#endif
}

முழு
get_sock_af(முழு fd)
{
	கட்டமைப்பு sockaddr_storage to;
	socklen_t tolen = அளவு(to);

	memset(&to, 0, அளவு(to));
	எனில் (getsockname(fd, (கட்டமைப்பு sockaddr *)&to, &tolen) == -1)
		திரும்பு -1;
#ifdef IPV4_IN_IPV6
	எனில் (to.ss_family == AF_INET6 &&
	    IN6_IS_ADDR_V4MAPPED(&((கட்டமைப்பு sockaddr_in6 *)&to)->sin6_addr))
		திரும்பு AF_INET;
#endif
	திரும்பு to.ss_family;
}

வெறுமை
set_sock_tos(முழு fd, முழு tos)
{
#ifndef IP_TOS_IS_BROKEN
	முழு af;

	எனில் (tos < 0 || tos == INT_MAX) {
		debug_f("invalid TOS %d", tos);
		திரும்பு;
	}
	தேர்வு ((af = get_sock_af(fd))) {
	நிலை -1:
		/* assume not a socket */
		நிறுத்து;
	நிலை AF_INET:
# ifdef IP_TOS
		debug3_f("set socket %d IP_TOS 0x%02x", fd, tos);
		எனில் (setsockopt(fd, IPPROTO_IP, IP_TOS,
		    &tos, அளவு(tos)) == -1) {
			error("setsockopt socket %d IP_TOS %d: %s",
			    fd, tos, strerror(errno));
		}
# endif /* IP_TOS */
		நிறுத்து;
	நிலை AF_INET6:
# ifdef IPV6_TCLASS
		debug3_f("set socket %d IPV6_TCLASS 0x%02x", fd, tos);
		எனில் (setsockopt(fd, IPPROTO_IPV6, IPV6_TCLASS,
		    &tos, அளவு(tos)) == -1) {
			error("setsockopt socket %d IPV6_TCLASS %d: %s",
			    fd, tos, strerror(errno));
		}
# endif /* IPV6_TCLASS */
		நிறுத்து;
	இயல்பு:
		debug2_f("unsupported socket family %d", af);
		நிறுத்து;
	}
#endif /* IP_TOS_IS_BROKEN */
}

/*
 * Wait up to *timeoutp milliseconds for events on fd. Updates
 * *timeoutp with time remaining.
 * Returns 0 if fd ready or -1 on timeout or error (see errno).
 */
நிலையான முழு
waitfd(முழு fd, முழு *timeoutp, short events, நிலையற்ற sig_atomic_t *stop)
{
	கட்டமைப்பு pollfd pfd;
	கட்டமைப்பு timespec timeout;
	முழு oerrno, r;
	sigset_t nsigset, osigset;

	எனில் (timeoutp && *timeoutp == -1)
		timeoutp = வெற்று;
	pfd.fd = fd;
	pfd.events = events;
	ptimeout_init(&timeout);
	எனில் (timeoutp != வெற்று)
		ptimeout_deadline_ms(&timeout, *timeoutp);
	எனில் (stop != வெற்று)
		sigfillset(&nsigset);
	க்கு (; timeoutp == வெற்று || *timeoutp >= 0;) {
		எனில் (stop != வெற்று) {
			sigprocmask(SIG_BLOCK, &nsigset, &osigset);
			எனில் (*stop) {
				sigprocmask(SIG_SETMASK, &osigset, வெற்று);
				errno = EINTR;
				திரும்பு -1;
			}
		}
		r = ppoll(&pfd, 1, ptimeout_get_tsp(&timeout),
		    stop != வெற்று ? &osigset : வெற்று);
		oerrno = errno;
		எனில் (stop != வெற்று)
			sigprocmask(SIG_SETMASK, &osigset, வெற்று);
		எனில் (timeoutp)
			*timeoutp = ptimeout_get_ms(&timeout);
		errno = oerrno;
		எனில் (r > 0)
			திரும்பு 0;
		இல்லையெனில் எனில் (r == -1 && errno != EAGAIN && errno != EINTR)
			திரும்பு -1;
		இல்லையெனில் எனில் (r == 0)
			நிறுத்து;
	}
	/* timeout */
	errno = ETIMEDOUT;
	திரும்பு -1;
}

/*
 * Wait up to *timeoutp milliseconds for fd to be readable. Updates
 * *timeoutp with time remaining.
 * Returns 0 if fd ready or -1 on timeout or error (see errno).
 */
முழு
waitrfd(முழு fd, முழு *timeoutp, நிலையற்ற sig_atomic_t *stop) {
	திரும்பு waitfd(fd, timeoutp, POLLIN, stop);
}

/*
 * Attempt a non-blocking connect(2) to the specified address, waiting up to
 * *timeoutp milliseconds for the connection to complete. If the timeout is
 * <=0, then wait indefinitely.
 *
 * Returns 0 on success or -1 on failure.
 */
முழு
timeout_connect(முழு sockfd, மாறிலி கட்டமைப்பு sockaddr *serv_addr,
    socklen_t addrlen, முழு *timeoutp)
{
	முழு optval = 0;
	socklen_t optlen = அளவு(optval);

	/* No timeout: just do a blocking connect() */
	எனில் (timeoutp == வெற்று || *timeoutp <= 0)
		திரும்பு connect(sockfd, serv_addr, addrlen);

	set_nonblock(sockfd);
	க்கு (;;) {
		எனில் (connect(sockfd, serv_addr, addrlen) == 0) {
			/* Succeeded already? */
			unset_nonblock(sockfd);
			திரும்பு 0;
		} இல்லையெனில் எனில் (errno == EINTR)
			தொடர்;
		இல்லையெனில் எனில் (errno != EINPROGRESS)
			திரும்பு -1;
		நிறுத்து;
	}

	எனில் (waitfd(sockfd, timeoutp, POLLIN | POLLOUT, வெற்று) == -1)
		திரும்பு -1;

	/* Completed or failed */
	எனில் (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &optval, &optlen) == -1) {
		debug("getsockopt: %s", strerror(errno));
		திரும்பு -1;
	}
	எனில் (optval != 0) {
		errno = optval;
		திரும்பு -1;
	}
	unset_nonblock(sockfd);
	திரும்பு 0;
}

/* Characters considered whitespace in strsep calls. */
#define WHITESPACE " \t\r\n"
#define QUOTE	"\""

/* return next token in configuration line */
நிலையான எழுத்து *
strdelim_internal(எழுத்து **s, முழு split_equals)
{
	எழுத்து *old;
	முழு wspace = 0;

	எனில் (*s == வெற்று)
		திரும்பு வெற்று;

	old = *s;

	*s = strpbrk(*s,
	    split_equals ? WHITESPACE QUOTE "=" : WHITESPACE QUOTE);
	எனில் (*s == வெற்று)
		திரும்பு (old);

	எனில் (*s[0] == '\"') {
		memmove(*s, *s + 1, strlen(*s)); /* move nul too */
		/* Find matching quote */
		எனில் ((*s = strpbrk(*s, QUOTE)) == வெற்று) {
			திரும்பு (வெற்று);		/* no matching quote */
		} இல்லையெனில் {
			*s[0] = '\0';
			*s += strspn(*s + 1, WHITESPACE) + 1;
			திரும்பு (old);
		}
	}

	/* Allow only one '=' to be skipped */
	எனில் (split_equals && *s[0] == '=')
		wspace = 1;
	*s[0] = '\0';

	/* Skip any extra whitespace after first token */
	*s += strspn(*s + 1, WHITESPACE) + 1;
	எனில் (split_equals && *s[0] == '=' && !wspace)
		*s += strspn(*s + 1, WHITESPACE) + 1;

	திரும்பு (old);
}

/*
 * Return next token in configuration line; splits on whitespace or a
 * single '=' character.
 */
எழுத்து *
strdelim(எழுத்து **s)
{
	திரும்பு strdelim_internal(s, 1);
}

/*
 * Return next token in configuration line; splits on whitespace only.
 */
எழுத்து *
strdelimw(எழுத்து **s)
{
	திரும்பு strdelim_internal(s, 0);
}

கட்டமைப்பு passwd *
pwcopy(கட்டமைப்பு passwd *pw)
{
	கட்டமைப்பு passwd *copy = xcalloc(1, அளவு(*copy));

	copy->pw_name = xstrdup(pw->pw_name);
	copy->pw_passwd = xstrdup(pw->pw_passwd == வெற்று ? "*" : pw->pw_passwd);
#ifdef HAVE_STRUCT_PASSWD_PW_GECOS
	copy->pw_gecos = xstrdup(pw->pw_gecos == வெற்று ? "" : pw->pw_gecos);
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
	copy->pw_class = xstrdup(pw->pw_class == வெற்று ? "" : pw->pw_class);
#endif
	copy->pw_dir = xstrdup(pw->pw_dir == வெற்று ? "" : pw->pw_dir);
	copy->pw_shell = xstrdup(pw->pw_shell == வெற்று ? "" : pw->pw_shell);
	திரும்பு copy;
}

வெறுமை
pwfree(கட்டமைப்பு passwd *pw)
{
	எனில் (pw == வெற்று)
		திரும்பு;
	விடுவி(pw->pw_name);
	freezero(pw->pw_passwd,
	    pw->pw_passwd == வெற்று ? 0 : strlen(pw->pw_passwd));
#ifdef HAVE_STRUCT_PASSWD_PW_GECOS
	விடுவி(pw->pw_gecos);
#endif
#ifdef HAVE_STRUCT_PASSWD_PW_CLASS
	விடுவி(pw->pw_class);
#endif
	விடுவி(pw->pw_dir);
	விடுவி(pw->pw_shell);
	freezero(pw, அளவு(*pw));
}

/*
 * Convert ASCII string to TCP/IP port number.
 * Port must be >=0 and <=65535.
 * Return -1 if invalid.
 */
முழு
a2port(மாறிலி எழுத்து *s)
{
	கட்டமைப்பு servent *se;
	long long port;
	மாறிலி எழுத்து *errstr;

	port = strtonum(s, 0, 65535, &errstr);
	எனில் (errstr == வெற்று)
		திரும்பு (முழு)port;
	எனில் ((se = getservbyname(s, "tcp")) != வெற்று)
		திரும்பு ntohs(se->s_port);
	திரும்பு -1;
}

முழு
a2tun(மாறிலி எழுத்து *s, முழு *remote)
{
	மாறிலி எழுத்து *errstr = வெற்று;
	எழுத்து *sp, *ep;
	முழு tun;

	எனில் (remote != வெற்று) {
		*remote = SSH_TUNID_ANY;
		sp = xstrdup(s);
		எனில் ((ep = strchr(sp, ':')) == வெற்று) {
			விடுவி(sp);
			திரும்பு (a2tun(s, வெற்று));
		}
		ep[0] = '\0'; ep++;
		*remote = a2tun(ep, வெற்று);
		tun = a2tun(sp, வெற்று);
		விடுவி(sp);
		திரும்பு (*remote == SSH_TUNID_ERR ? *remote : tun);
	}

	எனில் (strcasecmp(s, "any") == 0)
		திரும்பு (SSH_TUNID_ANY);

	tun = strtonum(s, 0, SSH_TUNID_MAX, &errstr);
	எனில் (errstr != வெற்று)
		திரும்பு (SSH_TUNID_ERR);

	திரும்பு (tun);
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
இரட்டை
convtime_double(மாறிலி எழுத்து *s)
{
	இரட்டை val, total_sec = 0.0, multiplier;
	மாறிலி எழுத்து *p, *start_p;
	எழுத்து *endp;
	முழு seen_seconds = 0;

	எனில் (s == வெற்று || *s == '\0')
		திரும்பு -1.0;

	க்கு (p = s; *p != '\0';) {
		எனில் (!isdigit((unsigned எழுத்து)*p) && *p != '.')
			திரும்பு -1.0;

		errno = 0;
		எனில் ((val = strtod(p, &endp)) < 0 || errno != 0 || p == endp)
			திரும்பு -1.0;
		/* Allow only decimal forms */
		எனில் (p + strspn(p, "0123456789.") != endp)
			திரும்பு -1.0;
		start_p = p;
		p = endp;

		தேர்வு (*p) {
		நிலை '\0':
			/* FALLTHROUGH */
		நிலை 's':
		நிலை 'S':
			எனில் (seen_seconds++)
				திரும்பு -1.0;
			multiplier = SECONDS;
			நிறுத்து;
		நிலை 'm':
		நிலை 'M':
			multiplier = MINUTES;
			நிறுத்து;
		நிலை 'h':
		நிலை 'H':
			multiplier = HOURS;
			நிறுத்து;
		நிலை 'd':
		நிலை 'D':
			multiplier = DAYS;
			நிறுத்து;
		நிலை 'w':
		நிலை 'W':
			multiplier = WEEKS;
			நிறுத்து;
		இயல்பு:
			திரும்பு -1.0;
		}

		/* Special handling if this was a decimal */
		எனில் (memchr(start_p, '.', endp - start_p) != வெற்று) {
			/* Decimal point present */
			எனில் (multiplier > 1.0)
				திரும்பு -1.0; /* No fractionals for non-seconds */
			/* For seconds, ensure digits follow */
			எனில் (!isdigit((unsigned எழுத்து)*(endp - 1)))
				திரும்பு -1.0;
		}

		total_sec += val * multiplier;

		எனில் (*p != '\0')
			p++;
	}
	திரும்பு total_sec;
}

/*
 * Same as convtime_double() above but fractional seconds are ignored.
 * Return -1 if time string is invalid.
 */
முழு
convtime(மாறிலி எழுத்து *s)
{
	இரட்டை sec_val;

	எனில் ((sec_val = convtime_double(s)) < 0.0)
		திரும்பு -1;

	/* Check for overflow into int */
	எனில் (sec_val < 0 || sec_val > INT_MAX)
		திரும்பு -1;

	திரும்பு (முழு)sec_val;
}

#define TF_BUFS	8
#define TF_LEN	9

மாறிலி எழுத்து *
fmt_timeframe(time_t t)
{
	எழுத்து		*buf;
	நிலையான எழுத்து	 tfbuf[TF_BUFS][TF_LEN];	/* ring buffer */
	நிலையான முழு	 idx = 0;
	unsigned முழு	 sec, min, hrs, day;
	unsigned long long	week;

	buf = tfbuf[idx++];
	எனில் (idx == TF_BUFS)
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

	எனில் (week > 0)
		snprintf(buf, TF_LEN, "%02lluw%01ud%02uh", week, day, hrs);
	இல்லையெனில் எனில் (day > 0)
		snprintf(buf, TF_LEN, "%01ud%02uh%02um", day, hrs, min);
	இல்லையெனில்
		snprintf(buf, TF_LEN, "%02u:%02u:%02u", hrs, min, sec);

	திரும்பு (buf);
}

/*
 * Returns a standardized host+port identifier string.
 * Caller must free returned string.
 */
எழுத்து *
put_host_port(மாறிலி எழுத்து *host, u_short port)
{
	எழுத்து *hoststr;

	எனில் (port == 0 || port == SSH_DEFAULT_PORT)
		திரும்பு(xstrdup(host));
	எனில் (asprintf(&hoststr, "[%s]:%d", host, (முழு)port) == -1)
		fatal("put_host_port: asprintf: %s", strerror(errno));
	debug3("put_host_port: %s", hoststr);
	திரும்பு hoststr;
}

/*
 * Search for next delimiter between hostnames/addresses and ports.
 * Argument may be modified (for termination).
 * Returns *cp if parsing succeeds.
 * *cp is set to the start of the next field, if one was found.
 * The delimiter char, if present, is stored in delim.
 * If this is the last field, *cp is set to NULL.
 */
எழுத்து *
hpdelim2(எழுத்து **cp, எழுத்து *delim)
{
	எழுத்து *s, *old;

	எனில் (cp == வெற்று || *cp == வெற்று)
		திரும்பு வெற்று;

	old = s = *cp;
	எனில் (*s == '[') {
		எனில் ((s = strchr(s, ']')) == வெற்று)
			திரும்பு வெற்று;
		இல்லையெனில்
			s++;
	} இல்லையெனில் எனில் ((s = strpbrk(s, ":/")) == வெற்று)
		s = *cp + strlen(*cp); /* skip to end (see first case below) */

	தேர்வு (*s) {
	நிலை '\0':
		*cp = வெற்று;	/* no more fields*/
		நிறுத்து;

	நிலை ':':
	நிலை '/':
		எனில் (delim != வெற்று)
			*delim = *s;
		*s = '\0';	/* terminate */
		*cp = s + 1;
		நிறுத்து;

	இயல்பு:
		திரும்பு வெற்று;
	}

	திரும்பு old;
}

/* The common case: only accept colon as delimiter. */
எழுத்து *
hpdelim(எழுத்து **cp)
{
	எழுத்து *r, delim = '\0';

	r =  hpdelim2(cp, &delim);
	எனில் (delim == '/')
		திரும்பு வெற்று;
	திரும்பு r;
}

எழுத்து *
cleanhostname(எழுத்து *host)
{
	எனில் (*host == '[' && host[strlen(host) - 1] == ']') {
		host[strlen(host) - 1] = '\0';
		திரும்பு (host + 1);
	} இல்லையெனில்
		திரும்பு host;
}

எழுத்து *
colon(எழுத்து *cp)
{
	முழு flag = 0;

	எனில் (*cp == ':')		/* Leading colon is part of file name. */
		திரும்பு வெற்று;
	எனில் (*cp == '[')
		flag = 1;

	க்கு (; *cp; ++cp) {
		எனில் (*cp == '@' && *(cp+1) == '[')
			flag = 1;
		எனில் (*cp == ']' && *(cp+1) == ':' && flag)
			திரும்பு (cp+1);
		எனில் (*cp == ':' && !flag)
			திரும்பு (cp);
		எனில் (*cp == '/')
			திரும்பு வெற்று;
	}
	திரும்பு வெற்று;
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
முழு
parse_user_host_path(மாறிலி எழுத்து *s, எழுத்து **userp, எழுத்து **hostp, எழுத்து **pathp)
{
	எழுத்து *user = வெற்று, *host = வெற்று, *path = வெற்று;
	எழுத்து *sdup, *tmp;
	முழு ret = -1;

	எனில் (userp != வெற்று)
		*userp = வெற்று;
	எனில் (hostp != வெற்று)
		*hostp = வெற்று;
	எனில் (pathp != வெற்று)
		*pathp = வெற்று;

	sdup = xstrdup(s);

	/* Check for remote syntax: [user@]host:[path] */
	எனில் ((tmp = colon(sdup)) == வெற்று)
		செல் out;

	/* Extract optional path */
	*tmp++ = '\0';
	எனில் (*tmp == '\0')
		tmp = ".";
	path = xstrdup(tmp);

	/* Extract optional user and mandatory host */
	tmp = strrchr(sdup, '@');
	எனில் (tmp != வெற்று) {
		*tmp++ = '\0';
		host = xstrdup(cleanhostname(tmp));
		எனில் (*sdup != '\0')
			user = xstrdup(sdup);
	} இல்லையெனில் {
		host = xstrdup(cleanhostname(sdup));
		user = வெற்று;
	}

	/* Success */
	எனில் (userp != வெற்று) {
		*userp = user;
		user = வெற்று;
	}
	எனில் (hostp != வெற்று) {
		*hostp = host;
		host = வெற்று;
	}
	எனில் (pathp != வெற்று) {
		*pathp = path;
		path = வெற்று;
	}
	ret = 0;
out:
	விடுவி(sdup);
	விடுவி(user);
	விடுவி(host);
	விடுவி(path);
	திரும்பு ret;
}

/*
 * Parse a [user@]host[:port] string.
 * Caller must free returned user and host.
 * Any of the pointer return arguments may be NULL (useful for syntax checking).
 * If user was not specified then *userp will be set to NULL.
 * If port was not specified then *portp will be -1.
 * Returns 0 on success, -1 on failure.
 */
முழு
parse_user_host_port(மாறிலி எழுத்து *s, எழுத்து **userp, எழுத்து **hostp, முழு *portp)
{
	எழுத்து *sdup, *cp, *tmp;
	எழுத்து *user = வெற்று, *host = வெற்று;
	முழு port = -1, ret = -1;

	எனில் (userp != வெற்று)
		*userp = வெற்று;
	எனில் (hostp != வெற்று)
		*hostp = வெற்று;
	எனில் (portp != வெற்று)
		*portp = -1;

	எனில் ((sdup = tmp = strdup(s)) == வெற்று)
		திரும்பு -1;
	/* Extract optional username */
	எனில் ((cp = strrchr(tmp, '@')) != வெற்று) {
		*cp = '\0';
		எனில் (*tmp == '\0')
			செல் out;
		எனில் ((user = strdup(tmp)) == வெற்று)
			செல் out;
		tmp = cp + 1;
	}
	/* Extract mandatory hostname */
	எனில் ((cp = hpdelim(&tmp)) == வெற்று || *cp == '\0')
		செல் out;
	host = xstrdup(cleanhostname(cp));
	/* Convert and verify optional port */
	எனில் (tmp != வெற்று && *tmp != '\0') {
		எனில் ((port = a2port(tmp)) <= 0)
			செல் out;
	}
	/* Success */
	எனில் (userp != வெற்று) {
		*userp = user;
		user = வெற்று;
	}
	எனில் (hostp != வெற்று) {
		*hostp = host;
		host = வெற்று;
	}
	எனில் (portp != வெற்று)
		*portp = port;
	ret = 0;
 out:
	விடுவி(sdup);
	விடுவி(user);
	விடுவி(host);
	திரும்பு ret;
}

/*
 * Converts a two-byte hex string to decimal.
 * Returns the decimal value or -1 for invalid input.
 */
நிலையான முழு
hexchar(மாறிலி எழுத்து *s)
{
	unsigned எழுத்து result[2];
	முழு i;

	க்கு (i = 0; i < 2; i++) {
		எனில் (s[i] >= '0' && s[i] <= '9')
			result[i] = (unsigned எழுத்து)(s[i] - '0');
		இல்லையெனில் எனில் (s[i] >= 'a' && s[i] <= 'f')
			result[i] = (unsigned எழுத்து)(s[i] - 'a') + 10;
		இல்லையெனில் எனில் (s[i] >= 'A' && s[i] <= 'F')
			result[i] = (unsigned எழுத்து)(s[i] - 'A') + 10;
		இல்லையெனில்
			திரும்பு -1;
	}
	திரும்பு (result[0] << 4) | result[1];
}

/*
 * Decode an url-encoded string.
 * Returns a newly allocated string on success or NULL on failure.
 */
நிலையான எழுத்து *
urldecode(மாறிலி எழுத்து *src)
{
	எழுத்து *ret, *dst;
	முழு ch;
	size_t srclen;

	எனில் ((srclen = strlen(src)) >= SIZE_MAX)
		திரும்பு வெற்று;
	ret = xmalloc(srclen + 1);
	க்கு (dst = ret; *src != '\0'; src++) {
		தேர்வு (*src) {
		நிலை '+':
			*dst++ = ' ';
			நிறுத்து;
		நிலை '%':
			/* note: don't allow \0 characters */
			எனில் (!isxdigit((unsigned எழுத்து)src[1]) ||
			    !isxdigit((unsigned எழுத்து)src[2]) ||
			    (ch = hexchar(src + 1)) == -1 || ch == 0) {
				விடுவி(ret);
				திரும்பு வெற்று;
			}
			*dst++ = ch;
			src += 2;
			நிறுத்து;
		இயல்பு:
			*dst++ = *src;
			நிறுத்து;
		}
	}
	*dst = '\0';

	திரும்பு ret;
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
முழு
parse_uri(மாறிலி எழுத்து *scheme, மாறிலி எழுத்து *uri, எழுத்து **userp, எழுத்து **hostp,
    முழு *portp, எழுத்து **pathp)
{
	எழுத்து *uridup, *cp, *tmp, ch;
	எழுத்து *user = வெற்று, *host = வெற்று, *path = வெற்று;
	முழு port = -1, ret = -1;
	size_t len;

	len = strlen(scheme);
	எனில் (strncmp(uri, scheme, len) != 0 || strncmp(uri + len, "://", 3) != 0)
		திரும்பு 1;
	uri += len + 3;

	எனில் (userp != வெற்று)
		*userp = வெற்று;
	எனில் (hostp != வெற்று)
		*hostp = வெற்று;
	எனில் (portp != வெற்று)
		*portp = -1;
	எனில் (pathp != வெற்று)
		*pathp = வெற்று;

	uridup = tmp = xstrdup(uri);

	/* Extract optional ssh-info (username + connection params) */
	எனில் ((cp = strchr(tmp, '@')) != வெற்று) {
		எழுத்து *delim;

		*cp = '\0';
		/* Extract username and connection params */
		எனில் ((delim = strchr(tmp, ';')) != வெற்று) {
			/* Just ignore connection params for now */
			*delim = '\0';
		}
		எனில் (*tmp == '\0') {
			/* Empty username */
			செல் out;
		}
		எனில் ((user = urldecode(tmp)) == வெற்று)
			செல் out;
		tmp = cp + 1;
	}

	/* Extract mandatory hostname */
	எனில் ((cp = hpdelim2(&tmp, &ch)) == வெற்று || *cp == '\0')
		செல் out;
	host = xstrdup(cleanhostname(cp));
	எனில் (!valid_domain(host, 0, வெற்று))
		செல் out;

	எனில் (tmp != வெற்று && *tmp != '\0') {
		எனில் (ch == ':') {
			/* Convert and verify port. */
			எனில் ((cp = strchr(tmp, '/')) != வெற்று)
				*cp = '\0';
			எனில் ((port = a2port(tmp)) <= 0)
				செல் out;
			tmp = cp ? cp + 1 : வெற்று;
		}
		எனில் (tmp != வெற்று && *tmp != '\0') {
			/* Extract optional path */
			எனில் ((path = urldecode(tmp)) == வெற்று)
				செல் out;
		}
	}

	/* Success */
	எனில் (userp != வெற்று) {
		*userp = user;
		user = வெற்று;
	}
	எனில் (hostp != வெற்று) {
		*hostp = host;
		host = வெற்று;
	}
	எனில் (portp != வெற்று)
		*portp = port;
	எனில் (pathp != வெற்று) {
		*pathp = path;
		path = வெற்று;
	}
	ret = 0;
 out:
	விடுவி(uridup);
	விடுவி(user);
	விடுவி(host);
	விடுவி(path);
	திரும்பு ret;
}

/* function to assist building execv() arguments */
வெறுமை
addargs(arglist *args, எழுத்து *fmt, ...)
{
	va_list ap;
	எழுத்து *cp;
	u_int nalloc;
	முழு r;

	va_start(ap, fmt);
	r = vasprintf(&cp, fmt, ap);
	va_end(ap);
	எனில் (r == -1)
		fatal_f("argument too long");

	nalloc = args->nalloc;
	எனில் (args->list == வெற்று) {
		nalloc = 32;
		args->இலக்கம் = 0;
	} இல்லையெனில் எனில் (args->இலக்கம் > (256 * 1024))
		fatal_f("too many arguments");
	இல்லையெனில் எனில் (args->இலக்கம் >= args->nalloc)
		fatal_f("arglist corrupt");
	இல்லையெனில் எனில் (args->இலக்கம்+2 >= nalloc)
		nalloc *= 2;

	args->list = xrecallocarray(args->list, args->nalloc,
	    nalloc, அளவு(எழுத்து *));
	args->nalloc = nalloc;
	args->list[args->இலக்கம்++] = cp;
	args->list[args->இலக்கம்] = வெற்று;
}

வெறுமை
replacearg(arglist *args, u_int which, எழுத்து *fmt, ...)
{
	va_list ap;
	எழுத்து *cp;
	முழு r;

	va_start(ap, fmt);
	r = vasprintf(&cp, fmt, ap);
	va_end(ap);
	எனில் (r == -1)
		fatal_f("argument too long");
	எனில் (args->list == வெற்று || args->இலக்கம் >= args->nalloc)
		fatal_f("arglist corrupt");

	எனில் (which >= args->இலக்கம்)
		fatal_f("tried to replace invalid arg %d >= %d",
		    which, args->இலக்கம்);
	விடுவி(args->list[which]);
	args->list[which] = cp;
}

வெறுமை
freeargs(arglist *args)
{
	u_int i;

	எனில் (args == வெற்று)
		திரும்பு;
	எனில் (args->list != வெற்று && args->இலக்கம் < args->nalloc) {
		க்கு (i = 0; i < args->இலக்கம்; i++)
			விடுவி(args->list[i]);
		விடுவி(args->list);
	}
	args->nalloc = args->இலக்கம் = 0;
	args->list = வெற்று;
}

/*
 * Expands tildes in the file name.  Returns data allocated by xmalloc.
 * Warning: this calls getpw*.
 */
முழு
tilde_expand(மாறிலி எழுத்து *filename, uid_t uid, எழுத்து **retp)
{
	எழுத்து *ocopy = வெற்று, *copy, *s = வெற்று;
	மாறிலி எழுத்து *path = வெற்று, *user = வெற்று;
	கட்டமைப்பு passwd *pw;
	size_t len;
	முழு ret = -1, r, slash;

	*retp = வெற்று;
	எனில் (*filename != '~') {
		*retp = xstrdup(filename);
		திரும்பு 0;
	}
	ocopy = copy = xstrdup(filename + 1);

	எனில் (*copy == '\0')				/* ~ */
		path = வெற்று;
	இல்லையெனில் எனில் (*copy == '/') {
		copy += strspn(copy, "/");
		எனில் (*copy == '\0')
			path = வெற்று;			/* ~/ */
		இல்லையெனில்
			path = copy;			/* ~/path */
	} இல்லையெனில் {
		user = copy;
		எனில் ((path = strchr(copy, '/')) != வெற்று) {
			copy[path - copy] = '\0';
			path++;
			path += strspn(path, "/");
			எனில் (*path == '\0')		/* ~user/ */
				path = வெற்று;
			/* else				 ~user/path */
		}
		/* else					~user */
	}
	எனில் (user != வெற்று) {
		எனில் ((pw = getpwnam(user)) == வெற்று) {
			error_f("No such user %s", user);
			செல் out;
		}
	} இல்லையெனில் எனில் ((pw = getpwuid(uid)) == வெற்று) {
		error_f("No such uid %ld", (long)uid);
		செல் out;
	}

	/* Make sure directory has a trailing '/' */
	slash = (len = strlen(pw->pw_dir)) == 0 || pw->pw_dir[len - 1] != '/';

	எனில் ((r = xasprintf(&s, "%s%s%s", pw->pw_dir,
	    slash ? "/" : "", path != வெற்று ? path : "")) <= 0) {
		error_f("xasprintf failed");
		செல் out;
	}
	எனில் (r >= PATH_MAX) {
		error_f("Path too long");
		செல் out;
	}
	/* success */
	ret = 0;
	*retp = s;
	s = வெற்று;
 out:
	விடுவி(s);
	விடுவி(ocopy);
	திரும்பு ret;
}

எழுத்து *
tilde_expand_filename(மாறிலி எழுத்து *filename, uid_t uid)
{
	எழுத்து *ret;

	எனில் (tilde_expand(filename, uid, &ret) != 0)
		cleanup_exit(255);
	திரும்பு ret;
}

/*
 * Expand a string with a set of %[char] escapes and/or ${ENVIRONMENT}
 * substitutions.  A number of escapes may be specified as
 * (char *escape_chars, char *replacement) pairs. The list must be terminated
 * by a NULL escape_char. Returns replaced string in memory allocated by
 * xmalloc which the caller must free.
 */
நிலையான எழுத்து *
vdollar_percent_expand(முழு *parseerror, முழு dollar, முழு percent,
    மாறிலி எழுத்து *string, va_list ap)
{
#define EXPAND_MAX_சாவிகள்	64
	u_int இலக்கம்_சாவிகள் = 0, i;
	கட்டமைப்பு {
		மாறிலி எழுத்து *சாவி;
		மாறிலி எழுத்து *repl;
	} சாவிகள்[EXPAND_MAX_சாவிகள்];
	கட்டமைப்பு sshbuf *buf;
	முழு r, missingvar = 0;
	எழுத்து *ret = வெற்று, *var, *varend, *val;
	size_t len;

	எனில் ((buf = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	எனில் (parseerror == வெற்று)
		fatal_f("null parseerror arg");
	*parseerror = 1;

	/* Gather keys if we're doing percent expansion. */
	எனில் (percent) {
		க்கு (இலக்கம்_சாவிகள் = 0; இலக்கம்_சாவிகள் < EXPAND_MAX_சாவிகள்; இலக்கம்_சாவிகள்++) {
			சாவிகள்[இலக்கம்_சாவிகள்].சாவி = va_arg(ap, எழுத்து *);
			எனில் (சாவிகள்[இலக்கம்_சாவிகள்].சாவி == வெற்று)
				நிறுத்து;
			சாவிகள்[இலக்கம்_சாவிகள்].repl = va_arg(ap, எழுத்து *);
			எனில் (சாவிகள்[இலக்கம்_சாவிகள்].repl == வெற்று) {
				fatal_f("NULL replacement for token %s",
				    சாவிகள்[இலக்கம்_சாவிகள்].சாவி);
			}
		}
		எனில் (இலக்கம்_சாவிகள் == EXPAND_MAX_சாவிகள் && va_arg(ap, எழுத்து *) != வெற்று)
			fatal_f("too many keys");
		எனில் (இலக்கம்_சாவிகள் == 0)
			fatal_f("percent expansion without token list");
	}

	/* Expand string */
	க்கு (i = 0; *string != '\0'; string++) {
		/* Optionally process ${ENVIRONMENT} expansions. */
		எனில் (dollar && string[0] == '$' && string[1] == '{') {
			string += 2;  /* skip over '${' */
			எனில் ((varend = strchr(string, '}')) == வெற்று) {
				error_f("environment variable '%s' missing "
				    "closing '}'", string);
				செல் out;
			}
			len = varend - string;
			எனில் (len == 0) {
				error_f("zero-length environment variable");
				செல் out;
			}
			var = xmalloc(len + 1);
			(வெறுமை)strlcpy(var, string, len + 1);
			எனில் ((val = getenv(var)) == வெற்று) {
				error_f("env var ${%s} has no value", var);
				missingvar = 1;
			} இல்லையெனில் {
				debug3_f("expand ${%s} -> '%s'", var, val);
				எனில் ((r = sshbuf_put(buf, val, strlen(val))) !=0)
					fatal_fr(r, "sshbuf_put ${}");
			}
			விடுவி(var);
			string += len;
			தொடர்;
		}

		/*
		 * Process percent expansions if we have a list of TOKENs.
		 * If we're not doing percent expansion everything just gets
		 * appended here.
		 */
		எனில் (*string != '%' || !percent) {
 append:
			எனில் ((r = sshbuf_put_u8(buf, *string)) != 0)
				fatal_fr(r, "sshbuf_put_u8 %%");
			தொடர்;
		}
		string++;
		/* %% case */
		எனில் (*string == '%')
			செல் append;
		எனில் (*string == '\0') {
			error_f("invalid format");
			செல் out;
		}
		க்கு (i = 0; i < இலக்கம்_சாவிகள்; i++) {
			எனில் (strchr(சாவிகள்[i].சாவி, *string) != வெற்று) {
				எனில் ((r = sshbuf_put(buf, சாவிகள்[i].repl,
				    strlen(சாவிகள்[i].repl))) != 0)
					fatal_fr(r, "sshbuf_put %%-repl");
				நிறுத்து;
			}
		}
		எனில் (i >= இலக்கம்_சாவிகள்) {
			error_f("unknown key %%%c", *string);
			செல் out;
		}
	}
	எனில் (!missingvar && (ret = sshbuf_dup_string(buf)) == வெற்று)
		fatal_f("sshbuf_dup_string failed");
	*parseerror = 0;
 out:
	sshbuf_free(buf);
	திரும்பு *parseerror ? வெற்று : ret;
#undef EXPAND_MAX_சாவிகள்
}

/*
 * Expand only environment variables.
 * Note that although this function is variadic like the other similar
 * functions, any such arguments will be unused.
 */

எழுத்து *
dollar_expand(முழு *parseerr, மாறிலி எழுத்து *string, ...)
{
	எழுத்து *ret;
	முழு err;
	va_list ap;

	va_start(ap, string);
	ret = vdollar_percent_expand(&err, 1, 0, string, ap);
	va_end(ap);
	எனில் (parseerr != வெற்று)
		*parseerr = err;
	திரும்பு ret;
}

/*
 * Returns expanded string or NULL if a specified environment variable is
 * not defined, or calls fatal if the string is invalid.
 */
எழுத்து *
percent_expand(மாறிலி எழுத்து *string, ...)
{
	எழுத்து *ret;
	முழு err;
	va_list ap;

	va_start(ap, string);
	ret = vdollar_percent_expand(&err, 0, 1, string, ap);
	va_end(ap);
	எனில் (err)
		fatal_f("failed");
	திரும்பு ret;
}

/*
 * Returns expanded string or NULL if a specified environment variable is
 * not defined, or calls fatal if the string is invalid.
 */
எழுத்து *
percent_dollar_expand(மாறிலி எழுத்து *string, ...)
{
	எழுத்து *ret;
	முழு err;
	va_list ap;

	va_start(ap, string);
	ret = vdollar_percent_expand(&err, 1, 1, string, ap);
	va_end(ap);
	எனில் (err)
		fatal_f("failed");
	திரும்பு ret;
}

முழு
tun_open(முழு tun, முழு mode, எழுத்து **ifname)
{
#எனில் defined(CUSTOM_SYS_TUN_OPEN)
	திரும்பு (sys_tun_open(tun, mode, ifname));
#அல்லதெனில் defined(SSH_TUN_OPENBSD)
	கட்டமைப்பு ifreq ifr;
	எழுத்து name[100];
	முழு fd = -1, sock;
	மாறிலி எழுத்து *tunbase = "tun";

	எனில் (ifname != வெற்று)
		*ifname = வெற்று;

	எனில் (mode == SSH_TUNMODE_ETHERNET)
		tunbase = "tap";

	/* Open the tunnel device */
	எனில் (tun <= SSH_TUNID_MAX) {
		snprintf(name, அளவு(name), "/dev/%s%d", tunbase, tun);
		fd = open(name, O_RDWR);
	} இல்லையெனில் எனில் (tun == SSH_TUNID_ANY) {
		க்கு (tun = 100; tun >= 0; tun--) {
			snprintf(name, அளவு(name), "/dev/%s%d",
			    tunbase, tun);
			எனில் ((fd = open(name, O_RDWR)) >= 0)
				நிறுத்து;
		}
	} இல்லையெனில் {
		debug_f("invalid tunnel %u", tun);
		திரும்பு -1;
	}

	எனில் (fd == -1) {
		debug_f("%s open: %s", name, strerror(errno));
		திரும்பு -1;
	}

	debug_f("%s mode %d fd %d", name, mode, fd);

	/* Bring interface up if it is not already */
	snprintf(ifr.ifr_name, அளவு(ifr.ifr_name), "%s%d", tunbase, tun);
	எனில் ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
		செல் failed;

	எனில் (ioctl(sock, SIOCGIFFLAGS, &ifr) == -1) {
		debug_f("get interface %s flags: %s", ifr.ifr_name,
		    strerror(errno));
		செல் failed;
	}

	எனில் (!(ifr.ifr_flags & IFF_UP)) {
		ifr.ifr_flags |= IFF_UP;
		எனில் (ioctl(sock, SIOCSIFFLAGS, &ifr) == -1) {
			debug_f("activate interface %s: %s", ifr.ifr_name,
			    strerror(errno));
			செல் failed;
		}
	}

	எனில் (ifname != வெற்று)
		*ifname = xstrdup(ifr.ifr_name);

	close(sock);
	திரும்பு fd;

 failed:
	எனில் (fd >= 0)
		close(fd);
	எனில் (sock >= 0)
		close(sock);
	திரும்பு -1;
#இல்லையெனில்
	error("Tunnel interfaces are not supported on this platform");
	திரும்பு (-1);
#endif
}

வெறுமை
sanitise_stdfd(வெறுமை)
{
	முழு nullfd, dupfd;

	எனில் ((nullfd = dupfd = open(_PATH_DEVNULL, O_RDWR)) == -1) {
		fprintf(stderr, "Couldn't open /dev/null: %s\n",
		    strerror(errno));
		exit(1);
	}
	போது (++dupfd <= STDERR_FILENO) {
		/* Only populate closed fds. */
		எனில் (fcntl(dupfd, F_GETFL) == -1 && errno == EBADF) {
			எனில் (dup2(nullfd, dupfd) == -1) {
				fprintf(stderr, "dup2: %s\n", strerror(errno));
				exit(1);
			}
		}
	}
	எனில் (nullfd > STDERR_FILENO)
		close(nullfd);
}

எழுத்து *
tohex(மாறிலி வெறுமை *vp, size_t l)
{
	மாறிலி u_char *p = (மாறிலி u_char *)vp;
	எழுத்து b[3], *r;
	size_t i, hl;

	எனில் (l > 65536)
		திரும்பு xstrdup("tohex: length > 65536");

	hl = l * 2 + 1;
	r = xcalloc(1, hl);
	க்கு (i = 0; i < l; i++) {
		snprintf(b, அளவு(b), "%02x", p[i]);
		strlcat(r, b, hl);
	}
	திரும்பு (r);
}

/*
 * Extend string *sp by the specified format. If *sp is not NULL (or empty),
 * then the separator 'sep' will be prepended before the formatted arguments.
 * Extended strings are heap allocated.
 */
வெறுமை
xextendf(எழுத்து **sp, மாறிலி எழுத்து *sep, மாறிலி எழுத்து *fmt, ...)
{
	va_list ap;
	எழுத்து *tmp1, *tmp2;

	va_start(ap, fmt);
	xvasprintf(&tmp1, fmt, ap);
	va_end(ap);

	எனில் (*sp == வெற்று || **sp == '\0') {
		விடுவி(*sp);
		*sp = tmp1;
		திரும்பு;
	}
	xasprintf(&tmp2, "%s%s%s", *sp, sep == வெற்று ? "" : sep, tmp1);
	விடுவி(tmp1);
	விடுவி(*sp);
	*sp = tmp2;
}


uint64_t
get_u64(மாறிலி வெறுமை *vp)
{
	மாறிலி u_char *p = (மாறிலி u_char *)vp;
	uint64_t v;

	v  = (uint64_t)p[0] << 56;
	v |= (uint64_t)p[1] << 48;
	v |= (uint64_t)p[2] << 40;
	v |= (uint64_t)p[3] << 32;
	v |= (uint64_t)p[4] << 24;
	v |= (uint64_t)p[5] << 16;
	v |= (uint64_t)p[6] << 8;
	v |= (uint64_t)p[7];

	திரும்பு (v);
}

uint32_t
get_u32(மாறிலி வெறுமை *vp)
{
	மாறிலி u_char *p = (மாறிலி u_char *)vp;
	uint32_t v;

	v  = (uint32_t)p[0] << 24;
	v |= (uint32_t)p[1] << 16;
	v |= (uint32_t)p[2] << 8;
	v |= (uint32_t)p[3];

	திரும்பு (v);
}

uint32_t
get_u32_le(மாறிலி வெறுமை *vp)
{
	மாறிலி u_char *p = (மாறிலி u_char *)vp;
	uint32_t v;

	v  = (uint32_t)p[0];
	v |= (uint32_t)p[1] << 8;
	v |= (uint32_t)p[2] << 16;
	v |= (uint32_t)p[3] << 24;

	திரும்பு (v);
}

uint16_t
get_u16(மாறிலி வெறுமை *vp)
{
	மாறிலி u_char *p = (மாறிலி u_char *)vp;
	uint16_t v;

	v  = (uint16_t)p[0] << 8;
	v |= (uint16_t)p[1];

	திரும்பு (v);
}

வெறுமை
put_u64(வெறுமை *vp, uint64_t v)
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

வெறுமை
put_u32(வெறுமை *vp, uint32_t v)
{
	u_char *p = (u_char *)vp;

	p[0] = (u_char)(v >> 24) & 0xff;
	p[1] = (u_char)(v >> 16) & 0xff;
	p[2] = (u_char)(v >> 8) & 0xff;
	p[3] = (u_char)v & 0xff;
}

வெறுமை
put_u32_le(வெறுமை *vp, uint32_t v)
{
	u_char *p = (u_char *)vp;

	p[0] = (u_char)v & 0xff;
	p[1] = (u_char)(v >> 8) & 0xff;
	p[2] = (u_char)(v >> 16) & 0xff;
	p[3] = (u_char)(v >> 24) & 0xff;
}

வெறுமை
put_u16(வெறுமை *vp, uint16_t v)
{
	u_char *p = (u_char *)vp;

	p[0] = (u_char)(v >> 8) & 0xff;
	p[1] = (u_char)v & 0xff;
}

வெறுமை
ms_subtract_diff(கட்டமைப்பு timeval *start, முழு *ms)
{
	கட்டமைப்பு timeval diff, finish;

	monotime_tv(&finish);
	timersub(&finish, start, &diff);
	*ms -= (diff.tv_sec * 1000) + (diff.tv_usec / 1000);
}

வெறுமை
ms_to_timespec(கட்டமைப்பு timespec *ts, முழு ms)
{
	எனில் (ms < 0)
		ms = 0;
	ts->tv_sec = ms / 1000;
	ts->tv_nsec = (ms % 1000) * 1000 * 1000;
}

வெறுமை
monotime_ts(கட்டமைப்பு timespec *ts)
{
	கட்டமைப்பு timeval tv;
#எனில் defined(HAVE_CLOCK_GETTIME) && (defined(CLOCK_BOOTTIME) || \
    defined(CLOCK_MONOTONIC) || defined(CLOCK_REALTIME))
	நிலையான முழு gettime_failed = 0;

	எனில் (!gettime_failed) {
# ifdef CLOCK_BOOTTIME
		எனில் (clock_gettime(CLOCK_BOOTTIME, ts) == 0)
			திரும்பு;
# endif /* CLOCK_BOOTTIME */
# ifdef CLOCK_MONOTONIC
		எனில் (clock_gettime(CLOCK_MONOTONIC, ts) == 0)
			திரும்பு;
# endif /* CLOCK_MONOTONIC */
# ifdef CLOCK_REALTIME
		/* Not monotonic, but we're almost out of options here. */
		எனில் (clock_gettime(CLOCK_REALTIME, ts) == 0)
			திரும்பு;
# endif /* CLOCK_REALTIME */
		debug3("clock_gettime: %s", strerror(errno));
		gettime_failed = 1;
	}
#endif /* HAVE_CLOCK_GETTIME && (BOOTTIME || MONOTONIC || REALTIME) */
	gettimeofday(&tv, வெற்று);
	ts->tv_sec = tv.tv_sec;
	ts->tv_nsec = (long)tv.tv_usec * 1000;
}

வெறுமை
monotime_tv(கட்டமைப்பு timeval *tv)
{
	கட்டமைப்பு timespec ts;

	monotime_ts(&ts);
	tv->tv_sec = ts.tv_sec;
	tv->tv_usec = ts.tv_nsec / 1000;
}

time_t
monotime(வெறுமை)
{
	கட்டமைப்பு timespec ts;

	monotime_ts(&ts);
	திரும்பு (ts.tv_sec);
}

இரட்டை
monotime_double(வெறுமை)
{
	கட்டமைப்பு timespec ts;

	monotime_ts(&ts);
	திரும்பு (இரட்டை)ts.tv_sec + (இரட்டை)ts.tv_nsec / 1000000000.0;
}

வெறுமை
bandwidth_limit_init(கட்டமைப்பு bwlimit *bw, uint64_t kbps, size_t buflen)
{
	bw->buflen = buflen;
	bw->rate = kbps;
	bw->thresh = buflen;
	bw->lamt = 0;
	timerclear(&bw->bwstart);
	timerclear(&bw->bwend);
}

/* Callback from read/write loop to insert bandwidth-limiting delays */
வெறுமை
bandwidth_limit(கட்டமைப்பு bwlimit *bw, size_t read_len)
{
	uint64_t waitlen;
	கட்டமைப்பு timespec ts, rm;

	bw->lamt += read_len;
	எனில் (!timerisset(&bw->bwstart)) {
		monotime_tv(&bw->bwstart);
		திரும்பு;
	}
	எனில் (bw->lamt < bw->thresh)
		திரும்பு;

	monotime_tv(&bw->bwend);
	timersub(&bw->bwend, &bw->bwstart, &bw->bwend);
	எனில் (!timerisset(&bw->bwend))
		திரும்பு;

	bw->lamt *= 8;
	waitlen = (இரட்டை)1000000L * bw->lamt / bw->rate;

	bw->bwstart.tv_sec = waitlen / 1000000L;
	bw->bwstart.tv_usec = waitlen % 1000000L;

	எனில் (timercmp(&bw->bwstart, &bw->bwend, >)) {
		timersub(&bw->bwstart, &bw->bwend, &bw->bwend);

		/* Adjust the wait time */
		எனில் (bw->bwend.tv_sec) {
			bw->thresh /= 2;
			எனில் (bw->thresh < bw->buflen / 4)
				bw->thresh = bw->buflen / 4;
		} இல்லையெனில் எனில் (bw->bwend.tv_usec < 10000) {
			bw->thresh *= 2;
			எனில் (bw->thresh > bw->buflen * 8)
				bw->thresh = bw->buflen * 8;
		}

		TIMEVAL_TO_TIMESPEC(&bw->bwend, &ts);
		போது (nanosleep(&ts, &rm) == -1) {
			எனில் (errno != EINTR)
				நிறுத்து;
			ts = rm;
		}
	}

	bw->lamt = 0;
	monotime_tv(&bw->bwstart);
}

/* Make a template filename for mk[sd]temp() */
வெறுமை
mktemp_proto(எழுத்து *s, size_t len)
{
	மாறிலி எழுத்து *tmpdir;
	முழு r;

	எனில் ((tmpdir = getenv("TMPDIR")) != வெற்று) {
		r = snprintf(s, len, "%s/ssh-XXXXXXXXXXXX", tmpdir);
		எனில் (r > 0 && (size_t)r < len)
			திரும்பு;
	}
	r = snprintf(s, len, "/tmp/ssh-XXXXXXXXXXXX");
	எனில் (r < 0 || (size_t)r >= len)
		fatal_f("template string too short");
}

நிலையான மாறிலி கட்டமைப்பு {
	மாறிலி எழுத்து *name;
	முழு மதிப்பு;
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
	{ வெற்று, -1 }
};

முழு
parse_ipqos(மாறிலி எழுத்து *cp)
{
	மாறிலி எழுத்து *errstr;
	u_int i;
	முழு val;

	எனில் (cp == வெற்று)
		திரும்பு -1;
	க்கு (i = 0; ipqos[i].name != வெற்று; i++) {
		எனில் (strcasecmp(cp, ipqos[i].name) == 0)
			திரும்பு ipqos[i].மதிப்பு;
	}
	/* Try parsing as an integer */
	val = (முழு)strtonum(cp, 0, 255, &errstr);
	எனில் (errstr)
		திரும்பு -1;
	திரும்பு val;
}

மாறிலி எழுத்து *
iptos2str(முழு iptos)
{
	முழு i;
	நிலையான எழுத்து iptos_str[அளவு "0xff"];

	க்கு (i = 0; ipqos[i].name != வெற்று; i++) {
		எனில் (ipqos[i].மதிப்பு == iptos)
			திரும்பு ipqos[i].name;
	}
	snprintf(iptos_str, அளவு iptos_str, "0x%02x", iptos);
	திரும்பு iptos_str;
}

வெறுமை
lowercase(எழுத்து *s)
{
	க்கு (; *s; s++)
		*s = tolower((u_char)*s);
}

முழு
unix_listener(மாறிலி எழுத்து *path, முழு backlog, முழு unlink_first)
{
	கட்டமைப்பு sockaddr_un sunaddr;
	முழு saved_errno, sock;

	memset(&sunaddr, 0, அளவு(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	எனில் (strlcpy(sunaddr.sun_path, path,
	    அளவு(sunaddr.sun_path)) >= அளவு(sunaddr.sun_path)) {
		error_f("path \"%s\" too long for Unix domain socket", path);
		errno = ENAMETOOLONG;
		திரும்பு -1;
	}

	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	எனில் (sock == -1) {
		saved_errno = errno;
		error_f("socket: %.100s", strerror(errno));
		errno = saved_errno;
		திரும்பு -1;
	}
	எனில் (unlink_first == 1) {
		எனில் (unlink(path) != 0 && errno != ENOENT)
			error("unlink(%s): %.100s", path, strerror(errno));
	}
	எனில் (bind(sock, (கட்டமைப்பு sockaddr *)&sunaddr, அளவு(sunaddr)) == -1) {
		saved_errno = errno;
		error_f("cannot bind to path %s: %s", path, strerror(errno));
		close(sock);
		errno = saved_errno;
		திரும்பு -1;
	}
	எனில் (listen(sock, backlog) == -1) {
		saved_errno = errno;
		error_f("cannot listen on path %s: %s", path, strerror(errno));
		close(sock);
		unlink(path);
		errno = saved_errno;
		திரும்பு -1;
	}
	திரும்பு sock;
}

வெறுமை
sock_set_v6only(முழு s)
{
#எனில் defined(IPV6_V6ONLY) && !defined(__OpenBSD__)
	முழு on = 1;

	debug3_f("set socket %d IPV6_V6ONLY", s);
	எனில் (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &on, அளவு(on)) == -1)
		error("setsockopt IPV6_V6ONLY: %s", strerror(errno));
#endif
}

/*
 * Compares two strings that maybe be NULL. Returns non-zero if strings
 * are both NULL or are identical, returns zero otherwise.
 */
நிலையான முழு
strcmp_maybe_null(மாறிலி எழுத்து *a, மாறிலி எழுத்து *b)
{
	எனில் ((a == வெற்று && b != வெற்று) || (a != வெற்று && b == வெற்று))
		திரும்பு 0;
	எனில் (a != வெற்று && strcmp(a, b) != 0)
		திரும்பு 0;
	திரும்பு 1;
}

/*
 * Compare two forwards, returning non-zero if they are identical or
 * zero otherwise.
 */
முழு
forward_equals(மாறிலி கட்டமைப்பு Forward *a, மாறிலி கட்டமைப்பு Forward *b)
{
	எனில் (strcmp_maybe_null(a->listen_host, b->listen_host) == 0)
		திரும்பு 0;
	எனில் (a->listen_port != b->listen_port)
		திரும்பு 0;
	எனில் (strcmp_maybe_null(a->listen_path, b->listen_path) == 0)
		திரும்பு 0;
	எனில் (strcmp_maybe_null(a->connect_host, b->connect_host) == 0)
		திரும்பு 0;
	எனில் (a->connect_port != b->connect_port)
		திரும்பு 0;
	எனில் (strcmp_maybe_null(a->connect_path, b->connect_path) == 0)
		திரும்பு 0;
	/* allocated_port and handle are not checked */
	திரும்பு 1;
}

/* returns port number, FWD_PERMIT_ANY_PORT or -1 on error */
முழு
permitopen_port(மாறிலி எழுத்து *p)
{
	முழு port;

	எனில் (strcmp(p, "*") == 0)
		திரும்பு FWD_PERMIT_ANY_PORT;
	எனில் ((port = a2port(p)) > 0)
		திரும்பு port;
	திரும்பு -1;
}

/* returns 1 if process is already daemonized, 0 otherwise */
முழு
daemonized(வெறுமை)
{
	முழு fd;

	எனில் ((fd = open(_PATH_TTY, O_RDONLY | O_NOCTTY)) >= 0) {
		close(fd);
		திரும்பு 0;	/* have controlling terminal */
	}
	எனில் (getppid() != 1)
		திரும்பு 0;	/* parent is not init */
	எனில் (getsid(0) != getpid())
		திரும்பு 0;	/* not session leader */
	debug3("already daemonized");
	திரும்பு 1;
}

/*
 * Splits 's' into an argument vector. Handles quoted string and basic
 * escape characters (\\, \", \'). Caller must free the argument vector
 * and its members.
 */
முழு
argv_split(மாறிலி எழுத்து *s, முழு *argcp, எழுத்து ***argvp, முழு terminate_on_comment)
{
	முழு r = SSH_ERR_INTERNAL_ERROR;
	முழு argc = 0, quote, i, j;
	எழுத்து *arg, **argv = xcalloc(1, அளவு(*argv));

	*argvp = வெற்று;
	*argcp = 0;

	க்கு (i = 0; s[i] != '\0'; i++) {
		/* Skip leading whitespace */
		எனில் (s[i] == ' ' || s[i] == '\t')
			தொடர்;
		எனில் (terminate_on_comment && s[i] == '#')
			நிறுத்து;
		/* Start of a token */
		quote = 0;

		argv = xreallocarray(argv, (argc + 2), அளவு(*argv));
		arg = argv[argc++] = xcalloc(1, strlen(s + i) + 1);
		argv[argc] = வெற்று;

		/* Copy the token in, removing escapes */
		க்கு (j = 0; s[i] != '\0'; i++) {
			எனில் (s[i] == '\\') {
				எனில் (s[i + 1] == '\'' ||
				    s[i + 1] == '\"' ||
				    s[i + 1] == '\\' ||
				    (quote == 0 && s[i + 1] == ' ')) {
					i++; /* Skip '\' */
					arg[j++] = s[i];
				} இல்லையெனில் {
					/* Unrecognised escape */
					arg[j++] = s[i];
				}
			} இல்லையெனில் எனில் (quote == 0 && (s[i] == ' ' || s[i] == '\t'))
				நிறுத்து; /* done */
			இல்லையெனில் எனில் (quote == 0 && (s[i] == '\"' || s[i] == '\''))
				quote = s[i]; /* quote start */
			இல்லையெனில் எனில் (quote != 0 && s[i] == quote)
				quote = 0; /* quote end */
			இல்லையெனில்
				arg[j++] = s[i];
		}
		எனில் (s[i] == '\0') {
			எனில் (quote != 0) {
				/* Ran out of string looking for close quote */
				r = SSH_ERR_INVALID_FORMAT;
				செல் out;
			}
			நிறுத்து;
		}
	}
	/* Success */
	*argcp = argc;
	*argvp = argv;
	argc = 0;
	argv = வெற்று;
	r = 0;
 out:
	எனில் (argc != 0 && argv != வெற்று) {
		க்கு (i = 0; i < argc; i++)
			விடுவி(argv[i]);
		விடுவி(argv);
	}
	திரும்பு r;
}

/*
 * Reassemble an argument vector into a string, quoting and escaping as
 * necessary. Caller must free returned string.
 */
எழுத்து *
argv_assemble(முழு argc, எழுத்து **argv)
{
	முழு i, j, ws, r;
	எழுத்து c, *ret;
	கட்டமைப்பு sshbuf *buf, *arg;

	எனில் ((buf = sshbuf_new()) == வெற்று || (arg = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");

	க்கு (i = 0; i < argc; i++) {
		ws = 0;
		sshbuf_reset(arg);
		க்கு (j = 0; argv[i][j] != '\0'; j++) {
			r = 0;
			c = argv[i][j];
			தேர்வு (c) {
			நிலை ' ':
			நிலை '\t':
				ws = 1;
				r = sshbuf_put_u8(arg, c);
				நிறுத்து;
			நிலை '\\':
			நிலை '\'':
			நிலை '"':
				எனில் ((r = sshbuf_put_u8(arg, '\\')) != 0)
					நிறுத்து;
				/* FALLTHROUGH */
			இயல்பு:
				r = sshbuf_put_u8(arg, c);
				நிறுத்து;
			}
			எனில் (r != 0)
				fatal_fr(r, "sshbuf_put_u8");
		}
		எனில் ((i != 0 && (r = sshbuf_put_u8(buf, ' ')) != 0) ||
		    (ws != 0 && (r = sshbuf_put_u8(buf, '"')) != 0) ||
		    (r = sshbuf_putb(buf, arg)) != 0 ||
		    (ws != 0 && (r = sshbuf_put_u8(buf, '"')) != 0))
			fatal_fr(r, "assemble");
	}
	எனில் ((ret = malloc(sshbuf_len(buf) + 1)) == வெற்று)
		fatal_f("malloc failed");
	memcpy(ret, sshbuf_ptr(buf), sshbuf_len(buf));
	ret[sshbuf_len(buf)] = '\0';
	sshbuf_free(buf);
	sshbuf_free(arg);
	திரும்பு ret;
}

எழுத்து *
argv_next(முழு *argcp, எழுத்து ***argvp)
{
	எழுத்து *ret = (*argvp)[0];

	எனில் (*argcp > 0 && ret != வெற்று) {
		(*argcp)--;
		(*argvp)++;
	}
	திரும்பு ret;
}

வெறுமை
argv_consume(முழு *argcp)
{
	*argcp = 0;
}

வெறுமை
argv_free(எழுத்து **av, முழு ac)
{
	முழு i;

	எனில் (av == வெற்று)
		திரும்பு;
	க்கு (i = 0; i < ac; i++)
		விடுவி(av[i]);
	விடுவி(av);
}

/* Returns 0 if pid exited cleanly, non-zero otherwise */
முழு
exited_cleanly(pid_t pid, மாறிலி எழுத்து *tag, மாறிலி எழுத்து *cmd, முழு quiet)
{
	முழு status;

	போது (waitpid(pid, &status, 0) == -1) {
		எனில் (errno != EINTR) {
			error("%s waitpid: %s", tag, strerror(errno));
			திரும்பு -1;
		}
	}
	எனில் (WIFSIGNALED(status)) {
		error("%s %s exited on signal %d", tag, cmd, WTERMSIG(status));
		திரும்பு -1;
	} இல்லையெனில் எனில் (WEXITSTATUS(status) != 0) {
		do_log2(quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_INFO,
		    "%s %s failed, status %d", tag, cmd, WEXITSTATUS(status));
		திரும்பு -1;
	}
	திரும்பு 0;
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
முழு
safe_path(மாறிலி எழுத்து *name, கட்டமைப்பு stat *stp, மாறிலி எழுத்து *pw_dir,
    uid_t uid, எழுத்து *err, size_t errlen)
{
	எழுத்து buf[PATH_MAX], buf2[PATH_MAX], homedir[PATH_MAX];
	எழுத்து *cp;
	முழு comparehome = 0;
	கட்டமைப்பு stat st;

	எனில் (realpath(name, buf) == வெற்று) {
		snprintf(err, errlen, "realpath %s failed: %s", name,
		    strerror(errno));
		திரும்பு -1;
	}
	எனில் (pw_dir != வெற்று && realpath(pw_dir, homedir) != வெற்று)
		comparehome = 1;

	எனில் (!S_ISREG(stp->st_mode)) {
		snprintf(err, errlen, "%s is not a regular file", buf);
		திரும்பு -1;
	}
	எனில் ((!platform_sys_dir_uid(stp->st_uid) && stp->st_uid != uid) ||
	    (stp->st_mode & 022) != 0) {
		snprintf(err, errlen, "bad ownership or modes for file %s",
		    buf);
		திரும்பு -1;
	}

	/* for each component of the canonical path, walking upwards */
	க்கு (;;) {
		/*
		 * POSIX allows dirname to modify its argument and return a
		 * pointer into it, so make a copy to avoid overlapping strlcpy.
		 */
		strlcpy(buf2, buf, அளவு(buf2));
		எனில் ((cp = dirname(buf2)) == வெற்று) {
			snprintf(err, errlen, "dirname() failed");
			திரும்பு -1;
		}
		strlcpy(buf, cp, அளவு(buf));

		எனில் (stat(buf, &st) == -1 ||
		    (!platform_sys_dir_uid(st.st_uid) && st.st_uid != uid) ||
		    (st.st_mode & 022) != 0) {
			snprintf(err, errlen,
			    "bad ownership or modes for directory %s", buf);
			திரும்பு -1;
		}

		/* If are past the homedir then we can stop */
		எனில் (comparehome && strcmp(homedir, buf) == 0)
			நிறுத்து;

		/*
		 * dirname should always complete with a "/" path,
		 * but we can be paranoid and check for "." too
		 */
		எனில் ((strcmp("/", buf) == 0) || (strcmp(".", buf) == 0))
			நிறுத்து;
	}
	திரும்பு 0;
}

/*
 * Version of safe_path() that accepts an open file descriptor to
 * avoid races.
 *
 * Returns 0 on success and -1 on failure
 */
முழு
safe_path_fd(முழு fd, மாறிலி எழுத்து *file, கட்டமைப்பு passwd *pw,
    எழுத்து *err, size_t errlen)
{
	கட்டமைப்பு stat st;

	/* check the open file to avoid races */
	எனில் (fstat(fd, &st) == -1) {
		snprintf(err, errlen, "cannot stat file %s: %s",
		    file, strerror(errno));
		திரும்பு -1;
	}
	திரும்பு safe_path(file, &st, pw->pw_dir, pw->pw_uid, err, errlen);
}

/*
 * Sets the value of the given variable in the environment.  If the variable
 * already exists, its value is overridden.
 */
வெறுமை
child_set_env(எழுத்து ***envp, u_int *envsizep, மாறிலி எழுத்து *name,
	மாறிலி எழுத்து *மதிப்பு)
{
	எழுத்து **env;
	u_int envsize;
	u_int i, namelen;

	எனில் (strchr(name, '=') != வெற்று) {
		error("Invalid environment variable \"%.100s\"", name);
		திரும்பு;
	}

	/*
	 * If we're passed an uninitialized list, allocate a single null
	 * entry before continuing.
	 */
	எனில் ((*envp == வெற்று) != (*envsizep == 0))
		fatal_f("environment size mismatch");
	எனில் (*envp == வெற்று && *envsizep == 0) {
		*envp = xmalloc(அளவு(எழுத்து *));
		*envp[0] = வெற்று;
		*envsizep = 1;
	}

	/*
	 * Find the slot where the value should be stored.  If the variable
	 * already exists, we reuse the slot; otherwise we append a new slot
	 * at the end of the array, expanding if necessary.
	 */
	env = *envp;
	namelen = strlen(name);
	க்கு (i = 0; env[i]; i++)
		எனில் (strncmp(env[i], name, namelen) == 0 && env[i][namelen] == '=')
			நிறுத்து;
	எனில் (env[i]) {
		/* Reuse the slot. */
		விடுவி(env[i]);
	} இல்லையெனில் {
		/* New variable.  Expand if necessary. */
		envsize = *envsizep;
		எனில் (i >= envsize - 1) {
			எனில் (envsize >= 1000)
				fatal("child_set_env: too many env vars");
			envsize += 50;
			env = (*envp) = xreallocarray(env, envsize, அளவு(எழுத்து *));
			*envsizep = envsize;
		}
		/* Need to set the NULL pointer at end of array beyond the new slot. */
		env[i + 1] = வெற்று;
	}

	/* Allocate space and format the variable in the appropriate slot. */
	/* XXX xasprintf */
	env[i] = xmalloc(strlen(name) + 1 + strlen(மதிப்பு) + 1);
	snprintf(env[i], strlen(name) + 1 + strlen(மதிப்பு) + 1, "%s=%s", name, மதிப்பு);
}

/*
 * Check and optionally lowercase a domain name, also removes trailing '.'
 * Returns 1 on success and 0 on failure, storing an error message in errstr.
 */
முழு
valid_domain(எழுத்து *name, முழு makelower, மாறிலி எழுத்து **errstr)
{
	size_t i, l = strlen(name);
	u_char c, last = '\0';
	நிலையான எழுத்து errbuf[256];

	எனில் (l == 0) {
		strlcpy(errbuf, "empty domain name", அளவு(errbuf));
		செல் bad;
	}
	எனில் (!isalpha((u_char)name[0]) && !isdigit((u_char)name[0]) &&
	   name[0] != '_' /* technically invalid, but common */) {
		snprintf(errbuf, அளவு(errbuf), "domain name \"%.100s\" "
		    "starts with invalid character", name);
		செல் bad;
	}
	க்கு (i = 0; i < l; i++) {
		c = tolower((u_char)name[i]);
		எனில் (makelower)
			name[i] = (எழுத்து)c;
		எனில் (last == '.' && c == '.') {
			snprintf(errbuf, அளவு(errbuf), "domain name "
			    "\"%.100s\" contains consecutive separators", name);
			செல் bad;
		}
		எனில் (c != '.' && c != '-' && !isalnum(c) &&
		    c != '_') /* technically invalid, but common */ {
			snprintf(errbuf, அளவு(errbuf), "domain name "
			    "\"%.100s\" contains invalid characters", name);
			செல் bad;
		}
		last = c;
	}
	எனில் (name[l - 1] == '.')
		name[l - 1] = '\0';
	எனில் (errstr != வெற்று)
		*errstr = வெற்று;
	திரும்பு 1;
bad:
	எனில் (errstr != வெற்று)
		*errstr = errbuf;
	திரும்பு 0;
}

/*
 * Verify that a environment variable name (not including initial '$') is
 * valid; consisting of one or more alphanumeric or underscore characters only.
 * Returns 1 on valid, 0 otherwise.
 */
முழு
valid_env_name(மாறிலி எழுத்து *name)
{
	மாறிலி எழுத்து *cp;

	எனில் (name[0] == '\0')
		திரும்பு 0;
	க்கு (cp = name; *cp != '\0'; cp++) {
		எனில் (!isalnum((u_char)*cp) && *cp != '_')
			திரும்பு 0;
	}
	திரும்பு 1;
}

மாறிலி எழுத்து *
atoi_err(மாறிலி எழுத்து *nptr, முழு *val)
{
	மாறிலி எழுத்து *errstr = வெற்று;

	எனில் (nptr == வெற்று || *nptr == '\0')
		திரும்பு "missing";
	*val = strtonum(nptr, 0, INT_MAX, &errstr);
	திரும்பு errstr;
}

முழு
parse_absolute_time(மாறிலி எழுத்து *s, uint64_t *tp)
{
	கட்டமைப்பு tm tm;
	time_t tt;
	எழுத்து buf[32], *fmt;
	மாறிலி எழுத்து *cp;
	size_t l;
	முழு is_utc = 0;

	*tp = 0;

	l = strlen(s);
	எனில் (l > 1 && strcasecmp(s + l - 1, "Z") == 0) {
		is_utc = 1;
		l--;
	} இல்லையெனில் எனில் (l > 3 && strcasecmp(s + l - 3, "UTC") == 0) {
		is_utc = 1;
		l -= 3;
	}
	/*
	 * POSIX strptime says "The application shall ensure that there
	 * is white-space or other non-alphanumeric characters between
	 * any two conversion specifications" so arrange things this way.
	 */
	தேர்வு (l) {
	நிலை 8: /* YYYYMMDD */
		fmt = "%Y-%m-%d";
		snprintf(buf, அளவு(buf), "%.4s-%.2s-%.2s", s, s + 4, s + 6);
		நிறுத்து;
	நிலை 12: /* YYYYMMDDHHMM */
		fmt = "%Y-%m-%dT%H:%M";
		snprintf(buf, அளவு(buf), "%.4s-%.2s-%.2sT%.2s:%.2s",
		    s, s + 4, s + 6, s + 8, s + 10);
		நிறுத்து;
	நிலை 14: /* YYYYMMDDHHMMSS */
		fmt = "%Y-%m-%dT%H:%M:%S";
		snprintf(buf, அளவு(buf), "%.4s-%.2s-%.2sT%.2s:%.2s:%.2s",
		    s, s + 4, s + 6, s + 8, s + 10, s + 12);
		நிறுத்து;
	இயல்பு:
		திரும்பு SSH_ERR_INVALID_FORMAT;
	}

	memset(&tm, 0, அளவு(tm));
	எனில் ((cp = strptime(buf, fmt, &tm)) == வெற்று || *cp != '\0')
		திரும்பு SSH_ERR_INVALID_FORMAT;
	எனில் (is_utc) {
		tm.tm_wday = -1;	/* sentinel for error */
		எனில் ((tt = timegm(&tm)) == -1 && tm.tm_wday == -1)
			திரும்பு SSH_ERR_INVALID_FORMAT;
	} இல்லையெனில் {
		tm.tm_wday = -1;	/* sentinel for error */
		tm.tm_isdst = -1;	/* mktime decides DST */
		எனில் ((tt = mktime(&tm)) == -1 && tm.tm_wday == -1)
			திரும்பு SSH_ERR_INVALID_FORMAT;
	}
	/* success */
	*tp = (uint64_t)tt;
	திரும்பு 0;
}

வெறுமை
format_absolute_time(uint64_t t, எழுத்து *buf, size_t len)
{
	time_t tt = t > SSH_TIME_T_MAX ? SSH_TIME_T_MAX : t;
	கட்டமைப்பு tm tm;

	எனில் (localtime_r(&tt, &tm) == வெற்று)
		strlcpy(buf, "UNKNOWN-TIME", len);
	இல்லையெனில்
		strftime(buf, len, "%Y-%m-%dT%H:%M:%S", &tm);
}

/*
 * Parse a "pattern=interval" clause (e.g. a ChannelTimeout).
 * Returns 0 on success or non-zero on failure.
 * Caller must free *typep.
 */
முழு
parse_pattern_interval(மாறிலி எழுத்து *s, எழுத்து **typep, இரட்டை *secsp)
{
	எழுத்து *cp, *sdup;
	இரட்டை secs;

	எனில் (typep != வெற்று)
		*typep = வெற்று;
	எனில் (secsp != வெற்று)
		*secsp = 0;
	எனில் (s == வெற்று)
		திரும்பு -1;
	sdup = xstrdup(s);

	எனில் ((cp = strchr(sdup, '=')) == வெற்று || cp == sdup) {
		விடுவி(sdup);
		திரும்பு -1;
	}
	*cp++ = '\0';
	எனில் ((secs = convtime_double(cp)) < 0.0) {
		விடுவி(sdup);
		திரும்பு -1;
	}
	/* success */
	எனில் (typep != வெற்று)
		*typep = xstrdup(sdup);
	எனில் (secsp != வெற்று)
		*secsp = secs;
	விடுவி(sdup);
	திரும்பு 0;
}

/* check if path is absolute */
முழு
path_absolute(மாறிலி எழுத்து *path)
{
	திரும்பு (*path == '/') ? 1 : 0;
}

வெறுமை
skip_space(எழுத்து **cpp)
{
	எழுத்து *cp;

	க்கு (cp = *cpp; *cp == ' ' || *cp == '\t'; cp++)
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
முழு
opt_flag(மாறிலி எழுத்து *opt, முழு allow_negate, மாறிலி எழுத்து **optsp)
{
	size_t opt_len = strlen(opt);
	மாறிலி எழுத்து *opts = *optsp;
	முழு negate = 0;

	எனில் (allow_negate && strncasecmp(opts, "no-", 3) == 0) {
		opts += 3;
		negate = 1;
	}
	எனில் (strncasecmp(opts, opt, opt_len) == 0) {
		*optsp = opts + opt_len;
		திரும்பு negate ? 0 : 1;
	}
	திரும்பு -1;
}

எழுத்து *
opt_dequote(மாறிலி எழுத்து **sp, மாறிலி எழுத்து **errstrp)
{
	மாறிலி எழுத்து *s = *sp;
	எழுத்து *ret;
	size_t i;

	*errstrp = வெற்று;
	எனில் (*s != '"') {
		*errstrp = "missing start quote";
		திரும்பு வெற்று;
	}
	s++;
	எனில் ((ret = malloc(strlen((s)) + 1)) == வெற்று) {
		*errstrp = "memory allocation failed";
		திரும்பு வெற்று;
	}
	க்கு (i = 0; *s != '\0' && *s != '"';) {
		எனில் (s[0] == '\\' && s[1] == '"')
			s++;
		ret[i++] = *s++;
	}
	எனில் (*s == '\0') {
		*errstrp = "missing end quote";
		விடுவி(ret);
		திரும்பு வெற்று;
	}
	ret[i] = '\0';
	s++;
	*sp = s;
	திரும்பு ret;
}

முழு
opt_match(மாறிலி எழுத்து **opts, மாறிலி எழுத்து *term)
{
	எனில் (strncasecmp((*opts), term, strlen(term)) == 0 &&
	    (*opts)[strlen(term)] == '=') {
		*opts += strlen(term) + 1;
		திரும்பு 1;
	}
	திரும்பு 0;
}

வெறுமை
opt_array_append2(மாறிலி எழுத்து *file, மாறிலி முழு வரி, மாறிலி எழுத்து *directive,
    எழுத்து ***array, முழு **iarray, u_int *lp, மாறிலி எழுத்து *s, முழு i)
{

	எனில் (*lp >= INT_MAX)
		fatal("%s line %d: Too many %s entries", file, வரி, directive);

	எனில் (iarray != வெற்று) {
		*iarray = xrecallocarray(*iarray, *lp, *lp + 1,
		    அளவு(**iarray));
		(*iarray)[*lp] = i;
	}

	*array = xrecallocarray(*array, *lp, *lp + 1, அளவு(**array));
	(*array)[*lp] = xstrdup(s);
	(*lp)++;
}

வெறுமை
opt_array_append(மாறிலி எழுத்து *file, மாறிலி முழு வரி, மாறிலி எழுத்து *directive,
    எழுத்து ***array, u_int *lp, மாறிலி எழுத்து *s)
{
	opt_array_append2(file, வரி, directive, array, வெற்று, lp, s, 0);
}

வெறுமை
opt_array_free2(எழுத்து **array, முழு **iarray, u_int l)
{
	u_int i;

	எனில் (array == வெற்று || l == 0)
		திரும்பு;
	க்கு (i = 0; i < l; i++)
		விடுவி(array[i]);
	விடுவி(array);
	விடுவி(iarray);
}

sshsig_t
ssh_signal(முழு signum, sshsig_t handler)
{
	கட்டமைப்பு sigaction sa, osa;

	/* mask all other signals while in handler */
	memset(&sa, 0, அளவு(sa));
	sa.sa_handler = handler;
	sigfillset(&sa.sa_mask);
#எனில் defined(SA_RESTART) && !defined(NO_SA_RESTART)
	எனில் (signum != SIGALRM)
		sa.sa_flags = SA_RESTART;
#endif
	எனில் (sigaction(signum, &sa, &osa) == -1) {
		debug3("sigaction(%s): %s", strsignal(signum), strerror(errno));
		திரும்பு SIG_ERR;
	}
	திரும்பு osa.sa_handler;
}

முழு
stdfd_devnull(முழு do_stdin, முழு do_stdout, முழு do_stderr)
{
	முழு devnull, ret = 0;

	எனில் ((devnull = open(_PATH_DEVNULL, O_RDWR)) == -1) {
		error_f("open %s: %s", _PATH_DEVNULL,
		    strerror(errno));
		திரும்பு -1;
	}
	எனில் ((do_stdin && dup2(devnull, STDIN_FILENO) == -1) ||
	    (do_stdout && dup2(devnull, STDOUT_FILENO) == -1) ||
	    (do_stderr && dup2(devnull, STDERR_FILENO) == -1)) {
		error_f("dup2: %s", strerror(errno));
		ret = -1;
	}
	எனில் (devnull > STDERR_FILENO)
		close(devnull);
	திரும்பு ret;
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
subprocess(மாறிலி எழுத்து *tag, மாறிலி எழுத்து *command,
    முழு ac, எழுத்து **av, FILE **child, u_int flags,
    கட்டமைப்பு passwd *pw, privdrop_fn *drop_privs, privrestore_fn *restore_privs)
{
	FILE *f = வெற்று;
	கட்டமைப்பு stat st;
	முழு fd, devnull, p[2], i;
	pid_t pid;
	எழுத்து *cp, errmsg[512];
	u_int nenv = 0;
	எழுத்து **env = வெற்று;

	/* If dropping privs, then must specify user and restore function */
	எனில் (drop_privs != வெற்று && (pw == வெற்று || restore_privs == வெற்று)) {
		error("%s: inconsistent arguments", tag); /* XXX fatal? */
		திரும்பு 0;
	}
	எனில் (pw == வெற்று && (pw = getpwuid(getuid())) == வெற்று) {
		error("%s: no user for current uid", tag);
		திரும்பு 0;
	}
	எனில் (child != வெற்று)
		*child = வெற்று;

	debug3_f("%s command \"%s\" running as %s (flags 0x%x)",
	    tag, command, pw->pw_name, flags);

	/* Check consistency */
	எனில் ((flags & SSH_SUBPROCESS_STDOUT_DISCARD) != 0 &&
	    (flags & SSH_SUBPROCESS_STDOUT_CAPTURE) != 0) {
		error_f("inconsistent flags");
		திரும்பு 0;
	}
	எனில் (((flags & SSH_SUBPROCESS_STDOUT_CAPTURE) == 0) != (child == வெற்று)) {
		error_f("inconsistent flags/output");
		திரும்பு 0;
	}

	/*
	 * If executing an explicit binary, then verify the it exists
	 * and appears safe-ish to execute
	 */
	எனில் (!path_absolute(av[0])) {
		error("%s path is not absolute", tag);
		திரும்பு 0;
	}
	எனில் (drop_privs != வெற்று)
		drop_privs(pw);
	எனில் (stat(av[0], &st) == -1) {
		error("Could not stat %s \"%s\": %s", tag,
		    av[0], strerror(errno));
		செல் restore_return;
	}
	எனில் ((flags & SSH_SUBPROCESS_UNSAFE_PATH) == 0 &&
	    safe_path(av[0], &st, வெற்று, 0, errmsg, அளவு(errmsg)) != 0) {
		error("Unsafe %s \"%s\": %s", tag, av[0], errmsg);
		செல் restore_return;
	}
	/* Prepare to keep the child's stdout if requested */
	எனில் (pipe(p) == -1) {
		error("%s: pipe: %s", tag, strerror(errno));
 restore_return:
		எனில் (restore_privs != வெற்று)
			restore_privs();
		திரும்பு 0;
	}
	எனில் (restore_privs != வெற்று)
		restore_privs();

	தேர்வு ((pid = fork())) {
	நிலை -1: /* error */
		error("%s: fork: %s", tag, strerror(errno));
		close(p[0]);
		close(p[1]);
		திரும்பு 0;
	நிலை 0: /* child */
		/* Prepare a minimal environment for the child. */
		எனில் ((flags & SSH_SUBPROCESS_PRESERVE_ENV) == 0) {
			nenv = 5;
			env = xcalloc(அளவு(*env), nenv);
			child_set_env(&env, &nenv, "PATH", _PATH_STDPATH);
			child_set_env(&env, &nenv, "USER", pw->pw_name);
			child_set_env(&env, &nenv, "LOGNAME", pw->pw_name);
			child_set_env(&env, &nenv, "HOME", pw->pw_dir);
			எனில் ((cp = getenv("LANG")) != வெற்று)
				child_set_env(&env, &nenv, "LANG", cp);
		}

		க்கு (i = 1; i < NSIG; i++)
			ssh_signal(i, SIG_DFL);

		எனில் ((devnull = open(_PATH_DEVNULL, O_RDWR)) == -1) {
			error("%s: open %s: %s", tag, _PATH_DEVNULL,
			    strerror(errno));
			_exit(1);
		}
		எனில் (dup2(devnull, STDIN_FILENO) == -1) {
			error("%s: dup2: %s", tag, strerror(errno));
			_exit(1);
		}

		/* Set up stdout as requested; leave stderr in place for now. */
		fd = -1;
		எனில் ((flags & SSH_SUBPROCESS_STDOUT_CAPTURE) != 0)
			fd = p[1];
		இல்லையெனில் எனில் ((flags & SSH_SUBPROCESS_STDOUT_DISCARD) != 0)
			fd = devnull;
		எனில் (fd != -1 && dup2(fd, STDOUT_FILENO) == -1) {
			error("%s: dup2: %s", tag, strerror(errno));
			_exit(1);
		}
		closefrom(STDERR_FILENO + 1);

		எனில் (geteuid() == 0 &&
		    initgroups(pw->pw_name, pw->pw_gid) == -1) {
			error("%s: initgroups(%s, %u): %s", tag,
			    pw->pw_name, (u_int)pw->pw_gid, strerror(errno));
			_exit(1);
		}
		எனில் (setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) == -1) {
			error("%s: setresgid %u: %s", tag, (u_int)pw->pw_gid,
			    strerror(errno));
			_exit(1);
		}
		எனில் (setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) == -1) {
			error("%s: setresuid %u: %s", tag, (u_int)pw->pw_uid,
			    strerror(errno));
			_exit(1);
		}
		/* stdin is pointed to /dev/null at this point */
		எனில் ((flags & SSH_SUBPROCESS_STDOUT_DISCARD) != 0 &&
		    dup2(STDIN_FILENO, STDERR_FILENO) == -1) {
			error("%s: dup2: %s", tag, strerror(errno));
			_exit(1);
		}
		எனில் (env != வெற்று)
			execve(av[0], av, env);
		இல்லையெனில்
			execv(av[0], av);
		error("%s %s \"%s\": %s", tag, env == வெற்று ? "execv" : "execve",
		    command, strerror(errno));
		_exit(127);
	இயல்பு: /* parent */
		நிறுத்து;
	}

	close(p[1]);
	எனில் ((flags & SSH_SUBPROCESS_STDOUT_CAPTURE) == 0)
		close(p[0]);
	இல்லையெனில் எனில் ((f = fdopen(p[0], "r")) == வெற்று) {
		error("%s: fdopen: %s", tag, strerror(errno));
		close(p[0]);
		/* Don't leave zombie child */
		kill(pid, SIGTERM);
		போது (waitpid(pid, வெற்று, 0) == -1 && errno == EINTR)
			;
		திரும்பு 0;
	}
	/* Success */
	debug3_f("%s pid %ld", tag, (long)pid);
	எனில் (child != வெற்று)
		*child = f;
	திரும்பு pid;
}

மாறிலி எழுத்து *
lookup_env_in_list(மாறிலி எழுத்து *env, எழுத்து * மாறிலி *envs, size_t nenvs)
{
	size_t i, envlen;

	envlen = strlen(env);
	க்கு (i = 0; i < nenvs; i++) {
		எனில் (strncmp(envs[i], env, envlen) == 0 &&
		    envs[i][envlen] == '=') {
			திரும்பு envs[i] + envlen + 1;
		}
	}
	திரும்பு வெற்று;
}

மாறிலி எழுத்து *
lookup_setenv_in_list(மாறிலி எழுத்து *env, எழுத்து * மாறிலி *envs, size_t nenvs)
{
	எழுத்து *name, *cp;
	மாறிலி எழுத்து *ret;

	name = xstrdup(env);
	எனில் ((cp = strchr(name, '=')) == வெற்று) {
		விடுவி(name);
		திரும்பு வெற்று; /* not env=val */
	}
	*cp = '\0';
	ret = lookup_env_in_list(name, envs, nenvs);
	விடுவி(name);
	திரும்பு ret;
}

/*
 * Helpers for managing poll(2)/ppoll(2) timeouts
 * Will remember the earliest deadline and return it for use in poll/ppoll.
 */

/* Initialise a poll/ppoll timeout with an indefinite deadline */
வெறுமை
ptimeout_init(கட்டமைப்பு timespec *pt)
{
	/*
	 * Deliberately invalid for ppoll(2).
	 * Will be converted to NULL in ptimeout_get_tspec() later.
	 */
	pt->tv_sec = -1;
	pt->tv_nsec = 0;
}

/* Specify a poll/ppoll deadline of at most 'sec' seconds */
வெறுமை
ptimeout_deadline_sec(கட்டமைப்பு timespec *pt, long sec)
{
	எனில் (pt->tv_sec == -1 || pt->tv_sec >= sec) {
		pt->tv_sec = sec;
		pt->tv_nsec = 0;
	}
}

/* Specify a poll/ppoll deadline of at most 'p' (timespec) */
நிலையான வெறுமை
ptimeout_deadline_tsp(கட்டமைப்பு timespec *pt, கட்டமைப்பு timespec *p)
{
	எனில் (pt->tv_sec == -1 || timespeccmp(pt, p, >=))
		*pt = *p;
}

/* Specify a poll/ppoll deadline of at most 'ms' milliseconds */
வெறுமை
ptimeout_deadline_ms(கட்டமைப்பு timespec *pt, long ms)
{
	கட்டமைப்பு timespec p;

	p.tv_sec = ms / 1000;
	p.tv_nsec = (ms % 1000) * 1000000;
	ptimeout_deadline_tsp(pt, &p);
}

/* Specify a poll/ppoll deadline of at most 'sec' seconds (double) */
வெறுமை
ptimeout_deadline_sec_double(கட்டமைப்பு timespec *pt, இரட்டை sec)
{
	கட்டமைப்பு timespec t;

	memset(&t, 0, அளவு(t));
	எனில் ((int64_t)sec >= SSH_TIME_T_MAX)
		t.tv_sec = SSH_TIME_T_MAX;
	இல்லையெனில் எனில் (sec > 0) {
		t.tv_sec = sec;
		t.tv_nsec = (sec - (இரட்டை)t.tv_sec) * 1000000000.0;
	}
	ptimeout_deadline_tsp(pt, &t);
}

/* Specify a poll/ppoll deadline at wall clock monotime 'when' (timespec) */
வெறுமை
ptimeout_deadline_monotime_tsp(கட்டமைப்பு timespec *pt, கட்டமைப்பு timespec *when)
{
	கட்டமைப்பு timespec now, t;

	monotime_ts(&now);

	எனில் (timespeccmp(&now, when, >=)) {
		/* 'when' is now or in the past. Timeout ASAP */
		pt->tv_sec = 0;
		pt->tv_nsec = 0;
	} இல்லையெனில் {
		timespecsub(when, &now, &t);
		ptimeout_deadline_tsp(pt, &t);
	}
}

/* Specify a poll/ppoll deadline at wall clock monotime 'when' (double) */
வெறுமை
ptimeout_deadline_monotime_double(கட்டமைப்பு timespec *pt, இரட்டை when)
{
	ptimeout_deadline_sec_double(pt, when - monotime_double());
}

/* Specify a poll/ppoll deadline at wall clock monotime 'when' */
வெறுமை
ptimeout_deadline_monotime(கட்டமைப்பு timespec *pt, time_t when)
{
	கட்டமைப்பு timespec t;

	t.tv_sec = when;
	t.tv_nsec = 0;
	ptimeout_deadline_monotime_tsp(pt, &t);
}

/* Get a poll(2) timeout value in milliseconds */
முழு
ptimeout_get_ms(கட்டமைப்பு timespec *pt)
{
	எனில் (pt->tv_sec == -1)
		திரும்பு -1;
	எனில் (pt->tv_sec >= (INT_MAX - (pt->tv_nsec / 1000000)) / 1000)
		திரும்பு INT_MAX;
	திரும்பு (pt->tv_sec * 1000) + (pt->tv_nsec / 1000000);
}

/* Get a ppoll(2) timeout value as a timespec pointer */
கட்டமைப்பு timespec *
ptimeout_get_tsp(கட்டமைப்பு timespec *pt)
{
	திரும்பு pt->tv_sec == -1 ? வெற்று : pt;
}

/* Returns non-zero if a timeout has been set (i.e. is not indefinite) */
முழு
ptimeout_isset(கட்டமைப்பு timespec *pt)
{
	திரும்பு pt->tv_sec != -1;
}

/*
 * Returns zero if the library at 'path' contains symbol 's', nonzero
 * otherwise.
 */
முழு
lib_contains_குறியீடு(மாறிலி எழுத்து *path, மாறிலி எழுத்து *s)
{
#ifdef HAVE_NLIST
	கட்டமைப்பு nlist nl[2];
	முழு ret = -1, r;

	memset(nl, 0, அளவு(nl));
	nl[0].n_name = xstrdup(s);
	nl[1].n_name = வெற்று;
	எனில் ((r = nlist(path, nl)) == -1) {
		error_f("nlist failed for %s", path);
		செல் out;
	}
	எனில் (r != 0 || nl[0].n_மதிப்பு == 0 || nl[0].n_type == 0) {
		error_f("library %s does not contain symbol %s", path, s);
		செல் out;
	}
	/* success */
	ret = 0;
 out:
	விடுவி(nl[0].n_name);
	திரும்பு ret;
#இல்லையெனில் /* HAVE_NLIST */
	முழு fd, ret = -1;
	கட்டமைப்பு stat st;
	வெறுமை *m = வெற்று;
	size_t sz = 0;

	memset(&st, 0, அளவு(st));
	எனில் ((fd = open(path, O_RDONLY)) < 0) {
		error_f("open %s: %s", path, strerror(errno));
		திரும்பு -1;
	}
	எனில் (fstat(fd, &st) != 0) {
		error_f("fstat %s: %s", path, strerror(errno));
		செல் out;
	}
	எனில் (!S_ISREG(st.st_mode)) {
		error_f("%s is not a regular file", path);
		செல் out;
	}
	எனில் (st.st_size < 0 ||
	    (size_t)st.st_size < strlen(s) ||
	    st.st_size >= INT_MAX/2) {
		error_f("%s bad size %lld", path, (long long)st.st_size);
		செல் out;
	}
	sz = (size_t)st.st_size;
	எனில் ((m = mmap(வெற்று, sz, PROT_READ, MAP_PRIVATE, fd, 0)) == MAP_FAILED ||
	    m == வெற்று) {
		error_f("mmap %s: %s", path, strerror(errno));
		செல் out;
	}
	எனில் (memmem(m, sz, s, strlen(s)) == வெற்று) {
		error_f("%s does not contain expected string %s", path, s);
		செல் out;
	}
	/* success */
	ret = 0;
 out:
	எனில் (m != வெற்று && m != MAP_FAILED)
		munmap(m, sz);
	close(fd);
	திரும்பு ret;
#endif /* HAVE_NLIST */
}

முழு
signal_is_crash(முழு sig)
{
	தேர்வு (sig) {
	நிலை SIGSEGV:
	நிலை SIGBUS:
	நிலை SIGTRAP:
	நிலை SIGSYS:
	நிலை SIGFPE:
	நிலை SIGILL:
	நிலை SIGABRT:
		திரும்பு 1;
	}
	திரும்பு 0;
}

எழுத்து *
get_homedir(வெறுமை)
{
	எழுத்து *cp;
	கட்டமைப்பு passwd *pw;

	எனில் ((cp = getenv("HOME")) != வெற்று && *cp != '\0')
		திரும்பு xstrdup(cp);

	எனில் ((pw = getpwuid(getuid())) != வெற்று && *pw->pw_dir != '\0')
		திரும்பு xstrdup(pw->pw_dir);

	திரும்பு வெற்று;
}

முழு
mkdir_path(மாறிலி எழுத்து *target, mode_t mode)
{
#எனில் defined(HAVE_OPENAT) && defined(O_DIRECTORY)
	எழுத்து *dir, *odir = வெற்று, *next;
	முழு fd = AT_FDCWD, fd2, subpath_len, ret = -1;

	dir = odir = xstrdup(target);

	எனில் (*dir == '/' &&
	    (fd = open("/", O_RDONLY|O_DIRECTORY)) == -1) {
		error_f("open(\"/\"): %s", strerror(errno));
		விடுவி(odir);
		திரும்பு -1;
	}
	/* Work through the path, component-wise */
	க்கு (; dir != வெற்று && *dir != '\0'; dir = next) {
		எனில் ((next = strchr(dir, '/')) != வெற்று)
			*(next++) = '\0';
		எனில் (*dir == '\0')
			தொடர்;
		subpath_len = (next == வெற்று) ? INT_MAX : next - odir - 1;
		எனில் (mkdirat(fd, dir, mode) == 0)
			debug_f("created directory %.*s", subpath_len, target);
		இல்லையெனில் எனில் (errno != EEXIST) {
			error_f("mkdir(\"%.*s\"): %s",
			    subpath_len, target, strerror(errno));
			செல் out;
		}

		/* descend */
		எனில் ((fd2 = openat(fd, dir, O_RDONLY|O_DIRECTORY)) == -1) {
			error_f("open(\"%.*s\"): %s",
			    subpath_len, target, strerror(errno));
			செல் out;
		}
		எனில் (fd != AT_FDCWD)
			close(fd);
		fd = fd2;
	}
	/* success */
	ret = 0;
 out:
	விடுவி(odir);
	எனில் (fd != AT_FDCWD)
		close(fd);
	திரும்பு ret;
#இல்லையெனில்
	/*
	 * If we don't have openat (which was added in POSIX.1-2008), fall back
	 * to the possibly racy way.
	 */
	எழுத்து *dir, *odir, *p, path[PATH_MAX] = "";
	முழு ret = -1;
	size_t plen = அளவு(path);

	dir = odir = xstrdup(target);

	/* If the dir is relative, start with cwd. */
	எனில் (*dir != '/' && getcwd(path, plen) == வெற்று) {
		error_f("getcwd: %s", strerror(errno));
		செல் out;
	}

	/* Work through the path, component-wise */
	போது ((p = strsep(&dir, "/"))) {
		எனில் (*p == '\0')
			தொடர்;
		எனில் (strlcat(path, "/", plen) >= plen ||
		    strlcat(path, p, plen) >= plen)
			செல் out;
		எனில் (mkdir(path, mode) == 0)
			debug_f("created directory %s", path);
		இல்லையெனில் எனில் (errno != EEXIST && errno != EISDIR) {
			error_f("mkdir(\"%s\"): %s", path, strerror(errno));
			செல் out;
		}
	}
	/* success */
	ret = 0;
 out:
	விடுவி(odir);
	திரும்பு ret;
#endif
}
