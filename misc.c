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


#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/ioctl.h>
#અન્તર્ભાવ <sys/mman.h>
#અન્તર્ભાવ <sys/socket.h>
#અન્તર્ભાવ <sys/stat.h>
#અન્તર્ભાવ <sys/time.h>
#અન્તર્ભાવ <sys/wait.h>
#અન્તર્ભાવ <sys/un.h>

#અન્તર્ભાવ <limits.h>
#અન્તર્ભાવ <libgen.h>
#અન્તર્ભાવ <poll.h>
#અન્તર્ભાવ <nlist.h>
#અન્તર્ભાવ <signal.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdint.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <time.h>
#અન્તર્ભાવ <unistd.h>

#અન્તર્ભાવ <netinet/in.h>
#અન્તર્ભાવ <netinet/ip.h>
#અન્તર્ભાવ <netinet/tcp.h>
#અન્તર્ભાવ <arpa/inet.h>

#અન્તર્ભાવ <ctype.h>
#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <fcntl.h>
#અન્તર્ભાવ <netdb.h>
#અન્તર્ભાવ <paths.h>
#અન્તર્ભાવ <pwd.h>
#અન્તર્ભાવ <grp.h>
#ifdef SSH_TUN_OPENBSD
#અન્તર્ભાવ <net/if.h>
#endif

#અન્તર્ભાવ "xmalloc.h"
#અન્તર્ભાવ "misc.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "ssh.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "platform.h"

/* remove newline at end of string */
અક્ષર *
chop(અક્ષર *s)
{
	અક્ષર *t = s;
	જ્યારે (*t) {
		જો (*t == '\n' || *t == '\r') {
			*t = '\0';
			પાછા s;
		}
		t++;
	}
	પાછા s;

}

/* remove whitespace from end of string */
શૂન્ય
rtrim(અક્ષર *s)
{
	size_t i;

	જો ((i = strlen(s)) == 0)
		પાછા;
	કરો {
		i--;
		જો (isspace((unsigned અક્ષર)s[i]))
			s[i] = '\0';
		નહીંતર
			તોડો;
	} જ્યારે (i > 0);
}

/*
 * returns pointer to character after 'prefix' in 's' or otherwise NULL
 * if the prefix is not present.
 */
અચલ અક્ષર *
strprefix(અચલ અક્ષર *s, અચલ અક્ષર *prefix, પૂર્ણાંક ignorecase)
{
	size_t prefixlen;

	જો ((prefixlen = strlen(prefix)) == 0)
		પાછા s;
	જો (ignorecase) {
		જો (strncasecmp(s, prefix, prefixlen) != 0)
			પાછા ખાલી;
	} નહીંતર {
		જો (strncmp(s, prefix, prefixlen) != 0)
			પાછા ખાલી;
	}
	પાછા s + prefixlen;
}

/* Append string 's' to a NULL-terminated array of strings */
શૂન્ય
stringlist_append(અક્ષર ***listp, અચલ અક્ષર *s)
{
	size_t i = 0;

	જો (*listp == ખાલી)
		*listp = xcalloc(2, કદ(**listp));
	નહીંતર {
		માટે (i = 0; (*listp)[i] != ખાલી; i++)
			; /* count */
		*listp = xrecallocarray(*listp, i + 1, i + 2, કદ(**listp));
	}
	(*listp)[i] = xstrdup(s);
}

શૂન્ય
stringlist_free(અક્ષર **list)
{
	size_t i = 0;

	જો (list == ખાલી)
		પાછા;
	માટે (i = 0; list[i] != ખાલી; i++)
		મુક્ત(list[i]);
	મુક્ત(list);
}

/* set/unset filedescriptor to non-blocking */
પૂર્ણાંક
set_nonblock(પૂર્ણાંક fd)
{
	પૂર્ણાંક val;

	val = fcntl(fd, F_GETFL);
	જો (val == -1) {
		error("fcntl(%d, F_GETFL): %s", fd, strerror(errno));
		પાછા (-1);
	}
	જો (val & O_NONBLOCK) {
		debug3("fd %d is O_NONBLOCK", fd);
		પાછા (0);
	}
	debug2("fd %d setting O_NONBLOCK", fd);
	val |= O_NONBLOCK;
	જો (fcntl(fd, F_SETFL, val) == -1) {
		debug("fcntl(%d, F_SETFL, O_NONBLOCK): %s", fd,
		    strerror(errno));
		પાછા (-1);
	}
	પાછા (0);
}

પૂર્ણાંક
unset_nonblock(પૂર્ણાંક fd)
{
	પૂર્ણાંક val;

	val = fcntl(fd, F_GETFL);
	જો (val == -1) {
		error("fcntl(%d, F_GETFL): %s", fd, strerror(errno));
		પાછા (-1);
	}
	જો (!(val & O_NONBLOCK)) {
		debug3("fd %d is not O_NONBLOCK", fd);
		પાછા (0);
	}
	debug("fd %d clearing O_NONBLOCK", fd);
	val &= ~O_NONBLOCK;
	જો (fcntl(fd, F_SETFL, val) == -1) {
		debug("fcntl(%d, F_SETFL, ~O_NONBLOCK): %s",
		    fd, strerror(errno));
		પાછા (-1);
	}
	પાછા (0);
}

અચલ અક્ષર *
ssh_gai_strerror(પૂર્ણાંક gaierr)
{
	જો (gaierr == EAI_SYSTEM && errno != 0)
		પાછા strerror(errno);
	પાછા gai_strerror(gaierr);
}

/* disable nagle on socket */
શૂન્ય
set_nodelay(પૂર્ણાંક fd)
{
	પૂર્ણાંક opt;
	socklen_t optlen;

	optlen = કદ opt;
	જો (getsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, &optlen) == -1) {
		debug("getsockopt TCP_NODELAY: %.100s", strerror(errno));
		પાછા;
	}
	જો (opt == 1) {
		debug2("fd %d is TCP_NODELAY", fd);
		પાછા;
	}
	opt = 1;
	debug2("fd %d setting TCP_NODELAY", fd);
	જો (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, કદ opt) == -1)
		error("setsockopt TCP_NODELAY: %.100s", strerror(errno));
}

/* Allow local port reuse in TIME_WAIT */
પૂર્ણાંક
set_reuseaddr(પૂર્ણાંક fd)
{
	પૂર્ણાંક on = 1;

	જો (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, કદ(on)) == -1) {
		error("setsockopt SO_REUSEADDR fd %d: %s", fd, strerror(errno));
		પાછા -1;
	}
	પાછા 0;
}

/* Set TCP keepalives */
પૂર્ણાંક
set_keepalive(પૂર્ણાંક fd)
{
	પૂર્ણાંક on = 1;

	જો (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, કદ(on)) == -1) {
		error("setsockopt SO_KEEPALIVE fd %d: %s", fd, strerror(errno));
		પાછા -1;
	}
	પાછા 0;
}

/* Get/set routing domain */
અક્ષર *
get_rdomain(પૂર્ણાંક fd)
{
#જો defined(HAVE_SYS_GET_RDOMAIN)
	પાછા sys_get_rdomain(fd);
#અથવાજો defined(__OpenBSD__)
	પૂર્ણાંક rtable;
	અક્ષર *ret;
	socklen_t len = કદ(rtable);

	જો (getsockopt(fd, SOL_SOCKET, SO_RTABLE, &rtable, &len) == -1) {
		error("Failed to get routing domain for fd %d: %s",
		    fd, strerror(errno));
		પાછા ખાલી;
	}
	xasprintf(&ret, "%d", rtable);
	પાછા ret;
#નહીંતર /* defined(__OpenBSD__) */
	પાછા ખાલી;
#endif
}

પૂર્ણાંક
set_rdomain(પૂર્ણાંક fd, અચલ અક્ષર *name)
{
#જો defined(HAVE_SYS_SET_RDOMAIN)
	પાછા sys_set_rdomain(fd, name);
#અથવાજો defined(__OpenBSD__)
	પૂર્ણાંક rtable;
	અચલ અક્ષર *errstr;

	જો (name == ખાલી)
		પાછા 0; /* default table */

	rtable = (પૂર્ણાંક)strtonum(name, 0, 255, &errstr);
	જો (errstr != ખાલી) {
		/* Shouldn't happen */
		error("Invalid routing domain \"%s\": %s", name, errstr);
		પાછા -1;
	}
	જો (setsockopt(fd, SOL_SOCKET, SO_RTABLE,
	    &rtable, કદ(rtable)) == -1) {
		error("Failed to set routing domain %d on fd %d: %s",
		    rtable, fd, strerror(errno));
		પાછા -1;
	}
	પાછા 0;
#નહીંતર /* defined(__OpenBSD__) */
	error("Setting routing domain is not supported on this platform");
	પાછા -1;
#endif
}

પૂર્ણાંક
get_sock_af(પૂર્ણાંક fd)
{
	સંરચના sockaddr_storage to;
	socklen_t tolen = કદ(to);

	memset(&to, 0, કદ(to));
	જો (getsockname(fd, (સંરચના sockaddr *)&to, &tolen) == -1)
		પાછા -1;
#ifdef IPV4_IN_IPV6
	જો (to.ss_family == AF_INET6 &&
	    IN6_IS_ADDR_V4MAPPED(&((સંરચના sockaddr_in6 *)&to)->sin6_addr))
		પાછા AF_INET;
#endif
	પાછા to.ss_family;
}

શૂન્ય
set_sock_tos(પૂર્ણાંક fd, પૂર્ણાંક tos)
{
#ifndef IP_TOS_IS_BROKEN
	પૂર્ણાંક af;

	જો (tos < 0 || tos == INT_MAX) {
		debug_f("invalid TOS %d", tos);
		પાછા;
	}
	પસંદગી ((af = get_sock_af(fd))) {
	સ્થિતિ -1:
		/* assume not a socket */
		તોડો;
	સ્થિતિ AF_INET:
# ifdef IP_TOS
		debug3_f("set socket %d IP_TOS 0x%02x", fd, tos);
		જો (setsockopt(fd, IPPROTO_IP, IP_TOS,
		    &tos, કદ(tos)) == -1) {
			error("setsockopt socket %d IP_TOS %d: %s",
			    fd, tos, strerror(errno));
		}
# endif /* IP_TOS */
		તોડો;
	સ્થિતિ AF_INET6:
# ifdef IPV6_TCLASS
		debug3_f("set socket %d IPV6_TCLASS 0x%02x", fd, tos);
		જો (setsockopt(fd, IPPROTO_IPV6, IPV6_TCLASS,
		    &tos, કદ(tos)) == -1) {
			error("setsockopt socket %d IPV6_TCLASS %d: %s",
			    fd, tos, strerror(errno));
		}
# endif /* IPV6_TCLASS */
		તોડો;
	મૂળભૂત:
		debug2_f("unsupported socket family %d", af);
		તોડો;
	}
#endif /* IP_TOS_IS_BROKEN */
}

/*
 * Wait up to *timeoutp milliseconds for events on fd. Updates
 * *timeoutp with time remaining.
 * Returns 0 if fd ready or -1 on timeout or error (see errno).
 */
સ્થિર પૂર્ણાંક
waitfd(પૂર્ણાંક fd, પૂર્ણાંક *timeoutp, short events, અસ્થિર sig_atomic_t *stop)
{
	સંરચના pollfd pfd;
	સંરચના timespec timeout;
	પૂર્ણાંક oerrno, r;
	sigset_t nsigset, osigset;

	જો (timeoutp && *timeoutp == -1)
		timeoutp = ખાલી;
	pfd.fd = fd;
	pfd.events = events;
	ptimeout_init(&timeout);
	જો (timeoutp != ખાલી)
		ptimeout_deadline_ms(&timeout, *timeoutp);
	જો (stop != ખાલી)
		sigfillset(&nsigset);
	માટે (; timeoutp == ખાલી || *timeoutp >= 0;) {
		જો (stop != ખાલી) {
			sigprocmask(SIG_BLOCK, &nsigset, &osigset);
			જો (*stop) {
				sigprocmask(SIG_SETMASK, &osigset, ખાલી);
				errno = EINTR;
				પાછા -1;
			}
		}
		r = ppoll(&pfd, 1, ptimeout_get_tsp(&timeout),
		    stop != ખાલી ? &osigset : ખાલી);
		oerrno = errno;
		જો (stop != ખાલી)
			sigprocmask(SIG_SETMASK, &osigset, ખાલી);
		જો (timeoutp)
			*timeoutp = ptimeout_get_ms(&timeout);
		errno = oerrno;
		જો (r > 0)
			પાછા 0;
		નહીંતર જો (r == -1 && errno != EAGAIN && errno != EINTR)
			પાછા -1;
		નહીંતર જો (r == 0)
			તોડો;
	}
	/* timeout */
	errno = ETIMEDOUT;
	પાછા -1;
}

/*
 * Wait up to *timeoutp milliseconds for fd to be readable. Updates
 * *timeoutp with time remaining.
 * Returns 0 if fd ready or -1 on timeout or error (see errno).
 */
પૂર્ણાંક
waitrfd(પૂર્ણાંક fd, પૂર્ણાંક *timeoutp, અસ્થિર sig_atomic_t *stop) {
	પાછા waitfd(fd, timeoutp, POLLIN, stop);
}

/*
 * Attempt a non-blocking connect(2) to the specified address, waiting up to
 * *timeoutp milliseconds for the connection to complete. If the timeout is
 * <=0, then wait indefinitely.
 *
 * Returns 0 on success or -1 on failure.
 */
પૂર્ણાંક
timeout_connect(પૂર્ણાંક sockfd, અચલ સંરચના sockaddr *serv_addr,
    socklen_t addrlen, પૂર્ણાંક *timeoutp)
{
	પૂર્ણાંક optval = 0;
	socklen_t optlen = કદ(optval);

	/* No timeout: just do a blocking connect() */
	જો (timeoutp == ખાલી || *timeoutp <= 0)
		પાછા connect(sockfd, serv_addr, addrlen);

	set_nonblock(sockfd);
	માટે (;;) {
		જો (connect(sockfd, serv_addr, addrlen) == 0) {
			/* Succeeded already? */
			unset_nonblock(sockfd);
			પાછા 0;
		} નહીંતર જો (errno == EINTR)
			ચાલુ;
		નહીંતર જો (errno != EINPROGRESS)
			પાછા -1;
		તોડો;
	}

	જો (waitfd(sockfd, timeoutp, POLLIN | POLLOUT, ખાલી) == -1)
		પાછા -1;

	/* Completed or failed */
	જો (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &optval, &optlen) == -1) {
		debug("getsockopt: %s", strerror(errno));
		પાછા -1;
	}
	જો (optval != 0) {
		errno = optval;
		પાછા -1;
	}
	unset_nonblock(sockfd);
	પાછા 0;
}

/* Characters considered whitespace in strsep calls. */
#define WHITESPACE " \t\r\n"
#define QUOTE	"\""

/* return next token in configuration line */
સ્થિર અક્ષર *
strdelim_internal(અક્ષર **s, પૂર્ણાંક split_equals)
{
	અક્ષર *old;
	પૂર્ણાંક wspace = 0;

	જો (*s == ખાલી)
		પાછા ખાલી;

	old = *s;

	*s = strpbrk(*s,
	    split_equals ? WHITESPACE QUOTE "=" : WHITESPACE QUOTE);
	જો (*s == ખાલી)
		પાછા (old);

	જો (*s[0] == '\"') {
		memmove(*s, *s + 1, strlen(*s)); /* move nul too */
		/* Find matching quote */
		જો ((*s = strpbrk(*s, QUOTE)) == ખાલી) {
			પાછા (ખાલી);		/* no matching quote */
		} નહીંતર {
			*s[0] = '\0';
			*s += strspn(*s + 1, WHITESPACE) + 1;
			પાછા (old);
		}
	}

	/* Allow only one '=' to be skipped */
	જો (split_equals && *s[0] == '=')
		wspace = 1;
	*s[0] = '\0';

	/* Skip any extra whitespace after first token */
	*s += strspn(*s + 1, WHITESPACE) + 1;
	જો (split_equals && *s[0] == '=' && !wspace)
		*s += strspn(*s + 1, WHITESPACE) + 1;

	પાછા (old);
}

/*
 * Return next token in configuration line; splits on whitespace or a
 * single '=' character.
 */
અક્ષર *
strdelim(અક્ષર **s)
{
	પાછા strdelim_internal(s, 1);
}

/*
 * Return next token in configuration line; splits on whitespace only.
 */
અક્ષર *
strdelimw(અક્ષર **s)
{
	પાછા strdelim_internal(s, 0);
}

સંરચના passwd *
pwcopy(સંરચના passwd *pw)
{
	સંરચના passwd *copy = xcalloc(1, કદ(*copy));

	copy->pw_name = xstrdup(pw->pw_name);
	copy->pw_passwd = xstrdup(pw->pw_passwd == ખાલી ? "*" : pw->pw_passwd);
#ifdef HAVE_STRUCT_PASSWD_PW_GECOS
	copy->pw_gecos = xstrdup(pw->pw_gecos == ખાલી ? "" : pw->pw_gecos);
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
	copy->pw_class = xstrdup(pw->pw_class == ખાલી ? "" : pw->pw_class);
#endif
	copy->pw_dir = xstrdup(pw->pw_dir == ખાલી ? "" : pw->pw_dir);
	copy->pw_shell = xstrdup(pw->pw_shell == ખાલી ? "" : pw->pw_shell);
	પાછા copy;
}

શૂન્ય
pwfree(સંરચના passwd *pw)
{
	જો (pw == ખાલી)
		પાછા;
	મુક્ત(pw->pw_name);
	freezero(pw->pw_passwd,
	    pw->pw_passwd == ખાલી ? 0 : strlen(pw->pw_passwd));
#ifdef HAVE_STRUCT_PASSWD_PW_GECOS
	મુક્ત(pw->pw_gecos);
#endif
#ifdef HAVE_STRUCT_PASSWD_PW_CLASS
	મુક્ત(pw->pw_class);
#endif
	મુક્ત(pw->pw_dir);
	મુક્ત(pw->pw_shell);
	freezero(pw, કદ(*pw));
}

/*
 * Convert ASCII string to TCP/IP port number.
 * Port must be >=0 and <=65535.
 * Return -1 if invalid.
 */
પૂર્ણાંક
a2port(અચલ અક્ષર *s)
{
	સંરચના servent *se;
	long long port;
	અચલ અક્ષર *errstr;

	port = strtonum(s, 0, 65535, &errstr);
	જો (errstr == ખાલી)
		પાછા (પૂર્ણાંક)port;
	જો ((se = getservbyname(s, "tcp")) != ખાલી)
		પાછા ntohs(se->s_port);
	પાછા -1;
}

પૂર્ણાંક
a2tun(અચલ અક્ષર *s, પૂર્ણાંક *remote)
{
	અચલ અક્ષર *errstr = ખાલી;
	અક્ષર *sp, *ep;
	પૂર્ણાંક tun;

	જો (remote != ખાલી) {
		*remote = SSH_TUNID_ANY;
		sp = xstrdup(s);
		જો ((ep = strchr(sp, ':')) == ખાલી) {
			મુક્ત(sp);
			પાછા (a2tun(s, ખાલી));
		}
		ep[0] = '\0'; ep++;
		*remote = a2tun(ep, ખાલી);
		tun = a2tun(sp, ખાલી);
		મુક્ત(sp);
		પાછા (*remote == SSH_TUNID_ERR ? *remote : tun);
	}

	જો (strcasecmp(s, "any") == 0)
		પાછા (SSH_TUNID_ANY);

	tun = strtonum(s, 0, SSH_TUNID_MAX, &errstr);
	જો (errstr != ખાલી)
		પાછા (SSH_TUNID_ERR);

	પાછા (tun);
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
દ્વિગુણ
convtime_double(અચલ અક્ષર *s)
{
	દ્વિગુણ val, total_sec = 0.0, multiplier;
	અચલ અક્ષર *p, *start_p;
	અક્ષર *endp;
	પૂર્ણાંક seen_seconds = 0;

	જો (s == ખાલી || *s == '\0')
		પાછા -1.0;

	માટે (p = s; *p != '\0';) {
		જો (!isdigit((unsigned અક્ષર)*p) && *p != '.')
			પાછા -1.0;

		errno = 0;
		જો ((val = strtod(p, &endp)) < 0 || errno != 0 || p == endp)
			પાછા -1.0;
		/* Allow only decimal forms */
		જો (p + strspn(p, "0123456789.") != endp)
			પાછા -1.0;
		start_p = p;
		p = endp;

		પસંદગી (*p) {
		સ્થિતિ '\0':
			/* FALLTHROUGH */
		સ્થિતિ 's':
		સ્થિતિ 'S':
			જો (seen_seconds++)
				પાછા -1.0;
			multiplier = SECONDS;
			તોડો;
		સ્થિતિ 'm':
		સ્થિતિ 'M':
			multiplier = MINUTES;
			તોડો;
		સ્થિતિ 'h':
		સ્થિતિ 'H':
			multiplier = HOURS;
			તોડો;
		સ્થિતિ 'd':
		સ્થિતિ 'D':
			multiplier = DAYS;
			તોડો;
		સ્થિતિ 'w':
		સ્થિતિ 'W':
			multiplier = WEEKS;
			તોડો;
		મૂળભૂત:
			પાછા -1.0;
		}

		/* Special handling if this was a decimal */
		જો (memchr(start_p, '.', endp - start_p) != ખાલી) {
			/* Decimal point present */
			જો (multiplier > 1.0)
				પાછા -1.0; /* No fractionals for non-seconds */
			/* For seconds, ensure digits follow */
			જો (!isdigit((unsigned અક્ષર)*(endp - 1)))
				પાછા -1.0;
		}

		total_sec += val * multiplier;

		જો (*p != '\0')
			p++;
	}
	પાછા total_sec;
}

/*
 * Same as convtime_double() above but fractional seconds are ignored.
 * Return -1 if time string is invalid.
 */
પૂર્ણાંક
convtime(અચલ અક્ષર *s)
{
	દ્વિગુણ sec_val;

	જો ((sec_val = convtime_double(s)) < 0.0)
		પાછા -1;

	/* Check for overflow into int */
	જો (sec_val < 0 || sec_val > INT_MAX)
		પાછા -1;

	પાછા (પૂર્ણાંક)sec_val;
}

#define TF_BUFS	8
#define TF_LEN	9

અચલ અક્ષર *
fmt_timeframe(time_t t)
{
	અક્ષર		*buf;
	સ્થિર અક્ષર	 tfbuf[TF_BUFS][TF_LEN];	/* ring buffer */
	સ્થિર પૂર્ણાંક	 idx = 0;
	unsigned પૂર્ણાંક	 sec, min, hrs, day;
	unsigned long long	week;

	buf = tfbuf[idx++];
	જો (idx == TF_BUFS)
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

	જો (week > 0)
		snprintf(buf, TF_LEN, "%02lluw%01ud%02uh", week, day, hrs);
	નહીંતર જો (day > 0)
		snprintf(buf, TF_LEN, "%01ud%02uh%02um", day, hrs, min);
	નહીંતર
		snprintf(buf, TF_LEN, "%02u:%02u:%02u", hrs, min, sec);

	પાછા (buf);
}

/*
 * Returns a standardized host+port identifier string.
 * Caller must free returned string.
 */
અક્ષર *
put_host_port(અચલ અક્ષર *host, u_short port)
{
	અક્ષર *hoststr;

	જો (port == 0 || port == SSH_DEFAULT_PORT)
		પાછા(xstrdup(host));
	જો (asprintf(&hoststr, "[%s]:%d", host, (પૂર્ણાંક)port) == -1)
		fatal("put_host_port: asprintf: %s", strerror(errno));
	debug3("put_host_port: %s", hoststr);
	પાછા hoststr;
}

/*
 * Search for next delimiter between hostnames/addresses and ports.
 * Argument may be modified (for termination).
 * Returns *cp if parsing succeeds.
 * *cp is set to the start of the next field, if one was found.
 * The delimiter char, if present, is stored in delim.
 * If this is the last field, *cp is set to NULL.
 */
અક્ષર *
hpdelim2(અક્ષર **cp, અક્ષર *delim)
{
	અક્ષર *s, *old;

	જો (cp == ખાલી || *cp == ખાલી)
		પાછા ખાલી;

	old = s = *cp;
	જો (*s == '[') {
		જો ((s = strchr(s, ']')) == ખાલી)
			પાછા ખાલી;
		નહીંતર
			s++;
	} નહીંતર જો ((s = strpbrk(s, ":/")) == ખાલી)
		s = *cp + strlen(*cp); /* skip to end (see first case below) */

	પસંદગી (*s) {
	સ્થિતિ '\0':
		*cp = ખાલી;	/* no more fields*/
		તોડો;

	સ્થિતિ ':':
	સ્થિતિ '/':
		જો (delim != ખાલી)
			*delim = *s;
		*s = '\0';	/* terminate */
		*cp = s + 1;
		તોડો;

	મૂળભૂત:
		પાછા ખાલી;
	}

	પાછા old;
}

/* The common case: only accept colon as delimiter. */
અક્ષર *
hpdelim(અક્ષર **cp)
{
	અક્ષર *r, delim = '\0';

	r =  hpdelim2(cp, &delim);
	જો (delim == '/')
		પાછા ખાલી;
	પાછા r;
}

અક્ષર *
cleanhostname(અક્ષર *host)
{
	જો (*host == '[' && host[strlen(host) - 1] == ']') {
		host[strlen(host) - 1] = '\0';
		પાછા (host + 1);
	} નહીંતર
		પાછા host;
}

અક્ષર *
colon(અક્ષર *cp)
{
	પૂર્ણાંક flag = 0;

	જો (*cp == ':')		/* Leading colon is part of file name. */
		પાછા ખાલી;
	જો (*cp == '[')
		flag = 1;

	માટે (; *cp; ++cp) {
		જો (*cp == '@' && *(cp+1) == '[')
			flag = 1;
		જો (*cp == ']' && *(cp+1) == ':' && flag)
			પાછા (cp+1);
		જો (*cp == ':' && !flag)
			પાછા (cp);
		જો (*cp == '/')
			પાછા ખાલી;
	}
	પાછા ખાલી;
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
પૂર્ણાંક
parse_user_host_path(અચલ અક્ષર *s, અક્ષર **userp, અક્ષર **hostp, અક્ષર **pathp)
{
	અક્ષર *user = ખાલી, *host = ખાલી, *path = ખાલી;
	અક્ષર *sdup, *tmp;
	પૂર્ણાંક ret = -1;

	જો (userp != ખાલી)
		*userp = ખાલી;
	જો (hostp != ખાલી)
		*hostp = ખાલી;
	જો (pathp != ખાલી)
		*pathp = ખાલી;

	sdup = xstrdup(s);

	/* Check for remote syntax: [user@]host:[path] */
	જો ((tmp = colon(sdup)) == ખાલી)
		જાઓ out;

	/* Extract optional path */
	*tmp++ = '\0';
	જો (*tmp == '\0')
		tmp = ".";
	path = xstrdup(tmp);

	/* Extract optional user and mandatory host */
	tmp = strrchr(sdup, '@');
	જો (tmp != ખાલી) {
		*tmp++ = '\0';
		host = xstrdup(cleanhostname(tmp));
		જો (*sdup != '\0')
			user = xstrdup(sdup);
	} નહીંતર {
		host = xstrdup(cleanhostname(sdup));
		user = ખાલી;
	}

	/* Success */
	જો (userp != ખાલી) {
		*userp = user;
		user = ખાલી;
	}
	જો (hostp != ખાલી) {
		*hostp = host;
		host = ખાલી;
	}
	જો (pathp != ખાલી) {
		*pathp = path;
		path = ખાલી;
	}
	ret = 0;
out:
	મુક્ત(sdup);
	મુક્ત(user);
	મુક્ત(host);
	મુક્ત(path);
	પાછા ret;
}

/*
 * Parse a [user@]host[:port] string.
 * Caller must free returned user and host.
 * Any of the pointer return arguments may be NULL (useful for syntax checking).
 * If user was not specified then *userp will be set to NULL.
 * If port was not specified then *portp will be -1.
 * Returns 0 on success, -1 on failure.
 */
પૂર્ણાંક
parse_user_host_port(અચલ અક્ષર *s, અક્ષર **userp, અક્ષર **hostp, પૂર્ણાંક *portp)
{
	અક્ષર *sdup, *cp, *tmp;
	અક્ષર *user = ખાલી, *host = ખાલી;
	પૂર્ણાંક port = -1, ret = -1;

	જો (userp != ખાલી)
		*userp = ખાલી;
	જો (hostp != ખાલી)
		*hostp = ખાલી;
	જો (portp != ખાલી)
		*portp = -1;

	જો ((sdup = tmp = strdup(s)) == ખાલી)
		પાછા -1;
	/* Extract optional username */
	જો ((cp = strrchr(tmp, '@')) != ખાલી) {
		*cp = '\0';
		જો (*tmp == '\0')
			જાઓ out;
		જો ((user = strdup(tmp)) == ખાલી)
			જાઓ out;
		tmp = cp + 1;
	}
	/* Extract mandatory hostname */
	જો ((cp = hpdelim(&tmp)) == ખાલી || *cp == '\0')
		જાઓ out;
	host = xstrdup(cleanhostname(cp));
	/* Convert and verify optional port */
	જો (tmp != ખાલી && *tmp != '\0') {
		જો ((port = a2port(tmp)) <= 0)
			જાઓ out;
	}
	/* Success */
	જો (userp != ખાલી) {
		*userp = user;
		user = ખાલી;
	}
	જો (hostp != ખાલી) {
		*hostp = host;
		host = ખાલી;
	}
	જો (portp != ખાલી)
		*portp = port;
	ret = 0;
 out:
	મુક્ત(sdup);
	મુક્ત(user);
	મુક્ત(host);
	પાછા ret;
}

/*
 * Converts a two-byte hex string to decimal.
 * Returns the decimal value or -1 for invalid input.
 */
સ્થિર પૂર્ણાંક
hexchar(અચલ અક્ષર *s)
{
	unsigned અક્ષર result[2];
	પૂર્ણાંક i;

	માટે (i = 0; i < 2; i++) {
		જો (s[i] >= '0' && s[i] <= '9')
			result[i] = (unsigned અક્ષર)(s[i] - '0');
		નહીંતર જો (s[i] >= 'a' && s[i] <= 'f')
			result[i] = (unsigned અક્ષર)(s[i] - 'a') + 10;
		નહીંતર જો (s[i] >= 'A' && s[i] <= 'F')
			result[i] = (unsigned અક્ષર)(s[i] - 'A') + 10;
		નહીંતર
			પાછા -1;
	}
	પાછા (result[0] << 4) | result[1];
}

/*
 * Decode an url-encoded string.
 * Returns a newly allocated string on success or NULL on failure.
 */
સ્થિર અક્ષર *
urldecode(અચલ અક્ષર *src)
{
	અક્ષર *ret, *dst;
	પૂર્ણાંક ch;
	size_t srclen;

	જો ((srclen = strlen(src)) >= SIZE_MAX)
		પાછા ખાલી;
	ret = xmalloc(srclen + 1);
	માટે (dst = ret; *src != '\0'; src++) {
		પસંદગી (*src) {
		સ્થિતિ '+':
			*dst++ = ' ';
			તોડો;
		સ્થિતિ '%':
			/* note: don't allow \0 characters */
			જો (!isxdigit((unsigned અક્ષર)src[1]) ||
			    !isxdigit((unsigned અક્ષર)src[2]) ||
			    (ch = hexchar(src + 1)) == -1 || ch == 0) {
				મુક્ત(ret);
				પાછા ખાલી;
			}
			*dst++ = ch;
			src += 2;
			તોડો;
		મૂળભૂત:
			*dst++ = *src;
			તોડો;
		}
	}
	*dst = '\0';

	પાછા ret;
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
પૂર્ણાંક
parse_uri(અચલ અક્ષર *scheme, અચલ અક્ષર *uri, અક્ષર **userp, અક્ષર **hostp,
    પૂર્ણાંક *portp, અક્ષર **pathp)
{
	અક્ષર *uridup, *cp, *tmp, ch;
	અક્ષર *user = ખાલી, *host = ખાલી, *path = ખાલી;
	પૂર્ણાંક port = -1, ret = -1;
	size_t len;

	len = strlen(scheme);
	જો (strncmp(uri, scheme, len) != 0 || strncmp(uri + len, "://", 3) != 0)
		પાછા 1;
	uri += len + 3;

	જો (userp != ખાલી)
		*userp = ખાલી;
	જો (hostp != ખાલી)
		*hostp = ખાલી;
	જો (portp != ખાલી)
		*portp = -1;
	જો (pathp != ખાલી)
		*pathp = ખાલી;

	uridup = tmp = xstrdup(uri);

	/* Extract optional ssh-info (username + connection params) */
	જો ((cp = strchr(tmp, '@')) != ખાલી) {
		અક્ષર *delim;

		*cp = '\0';
		/* Extract username and connection params */
		જો ((delim = strchr(tmp, ';')) != ખાલી) {
			/* Just ignore connection params for now */
			*delim = '\0';
		}
		જો (*tmp == '\0') {
			/* Empty username */
			જાઓ out;
		}
		જો ((user = urldecode(tmp)) == ખાલી)
			જાઓ out;
		tmp = cp + 1;
	}

	/* Extract mandatory hostname */
	જો ((cp = hpdelim2(&tmp, &ch)) == ખાલી || *cp == '\0')
		જાઓ out;
	host = xstrdup(cleanhostname(cp));
	જો (!valid_domain(host, 0, ખાલી))
		જાઓ out;

	જો (tmp != ખાલી && *tmp != '\0') {
		જો (ch == ':') {
			/* Convert and verify port. */
			જો ((cp = strchr(tmp, '/')) != ખાલી)
				*cp = '\0';
			જો ((port = a2port(tmp)) <= 0)
				જાઓ out;
			tmp = cp ? cp + 1 : ખાલી;
		}
		જો (tmp != ખાલી && *tmp != '\0') {
			/* Extract optional path */
			જો ((path = urldecode(tmp)) == ખાલી)
				જાઓ out;
		}
	}

	/* Success */
	જો (userp != ખાલી) {
		*userp = user;
		user = ખાલી;
	}
	જો (hostp != ખાલી) {
		*hostp = host;
		host = ખાલી;
	}
	જો (portp != ખાલી)
		*portp = port;
	જો (pathp != ખાલી) {
		*pathp = path;
		path = ખાલી;
	}
	ret = 0;
 out:
	મુક્ત(uridup);
	મુક્ત(user);
	મુક્ત(host);
	મુક્ત(path);
	પાછા ret;
}

/* function to assist building execv() arguments */
શૂન્ય
addargs(arglist *args, અક્ષર *fmt, ...)
{
	va_list ap;
	અક્ષર *cp;
	u_int nalloc;
	પૂર્ણાંક r;

	va_start(ap, fmt);
	r = vasprintf(&cp, fmt, ap);
	va_end(ap);
	જો (r == -1)
		fatal_f("argument too long");

	nalloc = args->nalloc;
	જો (args->list == ખાલી) {
		nalloc = 32;
		args->અંક = 0;
	} નહીંતર જો (args->અંક > (256 * 1024))
		fatal_f("too many arguments");
	નહીંતર જો (args->અંક >= args->nalloc)
		fatal_f("arglist corrupt");
	નહીંતર જો (args->અંક+2 >= nalloc)
		nalloc *= 2;

	args->list = xrecallocarray(args->list, args->nalloc,
	    nalloc, કદ(અક્ષર *));
	args->nalloc = nalloc;
	args->list[args->અંક++] = cp;
	args->list[args->અંક] = ખાલી;
}

શૂન્ય
replacearg(arglist *args, u_int which, અક્ષર *fmt, ...)
{
	va_list ap;
	અક્ષર *cp;
	પૂર્ણાંક r;

	va_start(ap, fmt);
	r = vasprintf(&cp, fmt, ap);
	va_end(ap);
	જો (r == -1)
		fatal_f("argument too long");
	જો (args->list == ખાલી || args->અંક >= args->nalloc)
		fatal_f("arglist corrupt");

	જો (which >= args->અંક)
		fatal_f("tried to replace invalid arg %d >= %d",
		    which, args->અંક);
	મુક્ત(args->list[which]);
	args->list[which] = cp;
}

શૂન્ય
freeargs(arglist *args)
{
	u_int i;

	જો (args == ખાલી)
		પાછા;
	જો (args->list != ખાલી && args->અંક < args->nalloc) {
		માટે (i = 0; i < args->અંક; i++)
			મુક્ત(args->list[i]);
		મુક્ત(args->list);
	}
	args->nalloc = args->અંક = 0;
	args->list = ખાલી;
}

/*
 * Expands tildes in the file name.  Returns data allocated by xmalloc.
 * Warning: this calls getpw*.
 */
પૂર્ણાંક
tilde_expand(અચલ અક્ષર *filename, uid_t uid, અક્ષર **retp)
{
	અક્ષર *ocopy = ખાલી, *copy, *s = ખાલી;
	અચલ અક્ષર *path = ખાલી, *user = ખાલી;
	સંરચના passwd *pw;
	size_t len;
	પૂર્ણાંક ret = -1, r, slash;

	*retp = ખાલી;
	જો (*filename != '~') {
		*retp = xstrdup(filename);
		પાછા 0;
	}
	ocopy = copy = xstrdup(filename + 1);

	જો (*copy == '\0')				/* ~ */
		path = ખાલી;
	નહીંતર જો (*copy == '/') {
		copy += strspn(copy, "/");
		જો (*copy == '\0')
			path = ખાલી;			/* ~/ */
		નહીંતર
			path = copy;			/* ~/path */
	} નહીંતર {
		user = copy;
		જો ((path = strchr(copy, '/')) != ખાલી) {
			copy[path - copy] = '\0';
			path++;
			path += strspn(path, "/");
			જો (*path == '\0')		/* ~user/ */
				path = ખાલી;
			/* else				 ~user/path */
		}
		/* else					~user */
	}
	જો (user != ખાલી) {
		જો ((pw = getpwnam(user)) == ખાલી) {
			error_f("No such user %s", user);
			જાઓ out;
		}
	} નહીંતર જો ((pw = getpwuid(uid)) == ખાલી) {
		error_f("No such uid %ld", (long)uid);
		જાઓ out;
	}

	/* Make sure directory has a trailing '/' */
	slash = (len = strlen(pw->pw_dir)) == 0 || pw->pw_dir[len - 1] != '/';

	જો ((r = xasprintf(&s, "%s%s%s", pw->pw_dir,
	    slash ? "/" : "", path != ખાલી ? path : "")) <= 0) {
		error_f("xasprintf failed");
		જાઓ out;
	}
	જો (r >= PATH_MAX) {
		error_f("Path too long");
		જાઓ out;
	}
	/* success */
	ret = 0;
	*retp = s;
	s = ખાલી;
 out:
	મુક્ત(s);
	મુક્ત(ocopy);
	પાછા ret;
}

અક્ષર *
tilde_expand_filename(અચલ અક્ષર *filename, uid_t uid)
{
	અક્ષર *ret;

	જો (tilde_expand(filename, uid, &ret) != 0)
		cleanup_exit(255);
	પાછા ret;
}

/*
 * Expand a string with a set of %[char] escapes and/or ${ENVIRONMENT}
 * substitutions.  A number of escapes may be specified as
 * (char *escape_chars, char *replacement) pairs. The list must be terminated
 * by a NULL escape_char. Returns replaced string in memory allocated by
 * xmalloc which the caller must free.
 */
સ્થિર અક્ષર *
vdollar_percent_expand(પૂર્ણાંક *parseerror, પૂર્ણાંક dollar, પૂર્ણાંક percent,
    અચલ અક્ષર *string, va_list ap)
{
#define EXPAND_MAX_ચાવીઓ	64
	u_int અંક_ચાવીઓ = 0, i;
	સંરચના {
		અચલ અક્ષર *ચાવી;
		અચલ અક્ષર *repl;
	} ચાવીઓ[EXPAND_MAX_ચાવીઓ];
	સંરચના sshbuf *buf;
	પૂર્ણાંક r, missingvar = 0;
	અક્ષર *ret = ખાલી, *var, *varend, *val;
	size_t len;

	જો ((buf = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	જો (parseerror == ખાલી)
		fatal_f("null parseerror arg");
	*parseerror = 1;

	/* Gather keys if we're doing percent expansion. */
	જો (percent) {
		માટે (અંક_ચાવીઓ = 0; અંક_ચાવીઓ < EXPAND_MAX_ચાવીઓ; અંક_ચાવીઓ++) {
			ચાવીઓ[અંક_ચાવીઓ].ચાવી = va_arg(ap, અક્ષર *);
			જો (ચાવીઓ[અંક_ચાવીઓ].ચાવી == ખાલી)
				તોડો;
			ચાવીઓ[અંક_ચાવીઓ].repl = va_arg(ap, અક્ષર *);
			જો (ચાવીઓ[અંક_ચાવીઓ].repl == ખાલી) {
				fatal_f("NULL replacement for token %s",
				    ચાવીઓ[અંક_ચાવીઓ].ચાવી);
			}
		}
		જો (અંક_ચાવીઓ == EXPAND_MAX_ચાવીઓ && va_arg(ap, અક્ષર *) != ખાલી)
			fatal_f("too many keys");
		જો (અંક_ચાવીઓ == 0)
			fatal_f("percent expansion without token list");
	}

	/* Expand string */
	માટે (i = 0; *string != '\0'; string++) {
		/* Optionally process ${ENVIRONMENT} expansions. */
		જો (dollar && string[0] == '$' && string[1] == '{') {
			string += 2;  /* skip over '${' */
			જો ((varend = strchr(string, '}')) == ખાલી) {
				error_f("environment variable '%s' missing "
				    "closing '}'", string);
				જાઓ out;
			}
			len = varend - string;
			જો (len == 0) {
				error_f("zero-length environment variable");
				જાઓ out;
			}
			var = xmalloc(len + 1);
			(શૂન્ય)strlcpy(var, string, len + 1);
			જો ((val = getenv(var)) == ખાલી) {
				error_f("env var ${%s} has no value", var);
				missingvar = 1;
			} નહીંતર {
				debug3_f("expand ${%s} -> '%s'", var, val);
				જો ((r = sshbuf_put(buf, val, strlen(val))) !=0)
					fatal_fr(r, "sshbuf_put ${}");
			}
			મુક્ત(var);
			string += len;
			ચાલુ;
		}

		/*
		 * Process percent expansions if we have a list of TOKENs.
		 * If we're not doing percent expansion everything just gets
		 * appended here.
		 */
		જો (*string != '%' || !percent) {
 append:
			જો ((r = sshbuf_put_u8(buf, *string)) != 0)
				fatal_fr(r, "sshbuf_put_u8 %%");
			ચાલુ;
		}
		string++;
		/* %% case */
		જો (*string == '%')
			જાઓ append;
		જો (*string == '\0') {
			error_f("invalid format");
			જાઓ out;
		}
		માટે (i = 0; i < અંક_ચાવીઓ; i++) {
			જો (strchr(ચાવીઓ[i].ચાવી, *string) != ખાલી) {
				જો ((r = sshbuf_put(buf, ચાવીઓ[i].repl,
				    strlen(ચાવીઓ[i].repl))) != 0)
					fatal_fr(r, "sshbuf_put %%-repl");
				તોડો;
			}
		}
		જો (i >= અંક_ચાવીઓ) {
			error_f("unknown key %%%c", *string);
			જાઓ out;
		}
	}
	જો (!missingvar && (ret = sshbuf_dup_string(buf)) == ખાલી)
		fatal_f("sshbuf_dup_string failed");
	*parseerror = 0;
 out:
	sshbuf_free(buf);
	પાછા *parseerror ? ખાલી : ret;
#undef EXPAND_MAX_ચાવીઓ
}

/*
 * Expand only environment variables.
 * Note that although this function is variadic like the other similar
 * functions, any such arguments will be unused.
 */

અક્ષર *
dollar_expand(પૂર્ણાંક *parseerr, અચલ અક્ષર *string, ...)
{
	અક્ષર *ret;
	પૂર્ણાંક err;
	va_list ap;

	va_start(ap, string);
	ret = vdollar_percent_expand(&err, 1, 0, string, ap);
	va_end(ap);
	જો (parseerr != ખાલી)
		*parseerr = err;
	પાછા ret;
}

/*
 * Returns expanded string or NULL if a specified environment variable is
 * not defined, or calls fatal if the string is invalid.
 */
અક્ષર *
percent_expand(અચલ અક્ષર *string, ...)
{
	અક્ષર *ret;
	પૂર્ણાંક err;
	va_list ap;

	va_start(ap, string);
	ret = vdollar_percent_expand(&err, 0, 1, string, ap);
	va_end(ap);
	જો (err)
		fatal_f("failed");
	પાછા ret;
}

/*
 * Returns expanded string or NULL if a specified environment variable is
 * not defined, or calls fatal if the string is invalid.
 */
અક્ષર *
percent_dollar_expand(અચલ અક્ષર *string, ...)
{
	અક્ષર *ret;
	પૂર્ણાંક err;
	va_list ap;

	va_start(ap, string);
	ret = vdollar_percent_expand(&err, 1, 1, string, ap);
	va_end(ap);
	જો (err)
		fatal_f("failed");
	પાછા ret;
}

પૂર્ણાંક
tun_open(પૂર્ણાંક tun, પૂર્ણાંક mode, અક્ષર **ifname)
{
#જો defined(CUSTOM_SYS_TUN_OPEN)
	પાછા (sys_tun_open(tun, mode, ifname));
#અથવાજો defined(SSH_TUN_OPENBSD)
	સંરચના ifreq ifr;
	અક્ષર name[100];
	પૂર્ણાંક fd = -1, sock;
	અચલ અક્ષર *tunbase = "tun";

	જો (ifname != ખાલી)
		*ifname = ખાલી;

	જો (mode == SSH_TUNMODE_ETHERNET)
		tunbase = "tap";

	/* Open the tunnel device */
	જો (tun <= SSH_TUNID_MAX) {
		snprintf(name, કદ(name), "/dev/%s%d", tunbase, tun);
		fd = open(name, O_RDWR);
	} નહીંતર જો (tun == SSH_TUNID_ANY) {
		માટે (tun = 100; tun >= 0; tun--) {
			snprintf(name, કદ(name), "/dev/%s%d",
			    tunbase, tun);
			જો ((fd = open(name, O_RDWR)) >= 0)
				તોડો;
		}
	} નહીંતર {
		debug_f("invalid tunnel %u", tun);
		પાછા -1;
	}

	જો (fd == -1) {
		debug_f("%s open: %s", name, strerror(errno));
		પાછા -1;
	}

	debug_f("%s mode %d fd %d", name, mode, fd);

	/* Bring interface up if it is not already */
	snprintf(ifr.ifr_name, કદ(ifr.ifr_name), "%s%d", tunbase, tun);
	જો ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
		જાઓ failed;

	જો (ioctl(sock, SIOCGIFFLAGS, &ifr) == -1) {
		debug_f("get interface %s flags: %s", ifr.ifr_name,
		    strerror(errno));
		જાઓ failed;
	}

	જો (!(ifr.ifr_flags & IFF_UP)) {
		ifr.ifr_flags |= IFF_UP;
		જો (ioctl(sock, SIOCSIFFLAGS, &ifr) == -1) {
			debug_f("activate interface %s: %s", ifr.ifr_name,
			    strerror(errno));
			જાઓ failed;
		}
	}

	જો (ifname != ખાલી)
		*ifname = xstrdup(ifr.ifr_name);

	close(sock);
	પાછા fd;

 failed:
	જો (fd >= 0)
		close(fd);
	જો (sock >= 0)
		close(sock);
	પાછા -1;
#નહીંતર
	error("Tunnel interfaces are not supported on this platform");
	પાછા (-1);
#endif
}

શૂન્ય
sanitise_stdfd(શૂન્ય)
{
	પૂર્ણાંક nullfd, dupfd;

	જો ((nullfd = dupfd = open(_PATH_DEVNULL, O_RDWR)) == -1) {
		fprintf(stderr, "Couldn't open /dev/null: %s\n",
		    strerror(errno));
		exit(1);
	}
	જ્યારે (++dupfd <= STDERR_FILENO) {
		/* Only populate closed fds. */
		જો (fcntl(dupfd, F_GETFL) == -1 && errno == EBADF) {
			જો (dup2(nullfd, dupfd) == -1) {
				fprintf(stderr, "dup2: %s\n", strerror(errno));
				exit(1);
			}
		}
	}
	જો (nullfd > STDERR_FILENO)
		close(nullfd);
}

અક્ષર *
tohex(અચલ શૂન્ય *vp, size_t l)
{
	અચલ u_char *p = (અચલ u_char *)vp;
	અક્ષર b[3], *r;
	size_t i, hl;

	જો (l > 65536)
		પાછા xstrdup("tohex: length > 65536");

	hl = l * 2 + 1;
	r = xcalloc(1, hl);
	માટે (i = 0; i < l; i++) {
		snprintf(b, કદ(b), "%02x", p[i]);
		strlcat(r, b, hl);
	}
	પાછા (r);
}

/*
 * Extend string *sp by the specified format. If *sp is not NULL (or empty),
 * then the separator 'sep' will be prepended before the formatted arguments.
 * Extended strings are heap allocated.
 */
શૂન્ય
xextendf(અક્ષર **sp, અચલ અક્ષર *sep, અચલ અક્ષર *fmt, ...)
{
	va_list ap;
	અક્ષર *tmp1, *tmp2;

	va_start(ap, fmt);
	xvasprintf(&tmp1, fmt, ap);
	va_end(ap);

	જો (*sp == ખાલી || **sp == '\0') {
		મુક્ત(*sp);
		*sp = tmp1;
		પાછા;
	}
	xasprintf(&tmp2, "%s%s%s", *sp, sep == ખાલી ? "" : sep, tmp1);
	મુક્ત(tmp1);
	મુક્ત(*sp);
	*sp = tmp2;
}


uint64_t
get_u64(અચલ શૂન્ય *vp)
{
	અચલ u_char *p = (અચલ u_char *)vp;
	uint64_t v;

	v  = (uint64_t)p[0] << 56;
	v |= (uint64_t)p[1] << 48;
	v |= (uint64_t)p[2] << 40;
	v |= (uint64_t)p[3] << 32;
	v |= (uint64_t)p[4] << 24;
	v |= (uint64_t)p[5] << 16;
	v |= (uint64_t)p[6] << 8;
	v |= (uint64_t)p[7];

	પાછા (v);
}

uint32_t
get_u32(અચલ શૂન્ય *vp)
{
	અચલ u_char *p = (અચલ u_char *)vp;
	uint32_t v;

	v  = (uint32_t)p[0] << 24;
	v |= (uint32_t)p[1] << 16;
	v |= (uint32_t)p[2] << 8;
	v |= (uint32_t)p[3];

	પાછા (v);
}

uint32_t
get_u32_le(અચલ શૂન્ય *vp)
{
	અચલ u_char *p = (અચલ u_char *)vp;
	uint32_t v;

	v  = (uint32_t)p[0];
	v |= (uint32_t)p[1] << 8;
	v |= (uint32_t)p[2] << 16;
	v |= (uint32_t)p[3] << 24;

	પાછા (v);
}

uint16_t
get_u16(અચલ શૂન્ય *vp)
{
	અચલ u_char *p = (અચલ u_char *)vp;
	uint16_t v;

	v  = (uint16_t)p[0] << 8;
	v |= (uint16_t)p[1];

	પાછા (v);
}

શૂન્ય
put_u64(શૂન્ય *vp, uint64_t v)
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

શૂન્ય
put_u32(શૂન્ય *vp, uint32_t v)
{
	u_char *p = (u_char *)vp;

	p[0] = (u_char)(v >> 24) & 0xff;
	p[1] = (u_char)(v >> 16) & 0xff;
	p[2] = (u_char)(v >> 8) & 0xff;
	p[3] = (u_char)v & 0xff;
}

શૂન્ય
put_u32_le(શૂન્ય *vp, uint32_t v)
{
	u_char *p = (u_char *)vp;

	p[0] = (u_char)v & 0xff;
	p[1] = (u_char)(v >> 8) & 0xff;
	p[2] = (u_char)(v >> 16) & 0xff;
	p[3] = (u_char)(v >> 24) & 0xff;
}

શૂન્ય
put_u16(શૂન્ય *vp, uint16_t v)
{
	u_char *p = (u_char *)vp;

	p[0] = (u_char)(v >> 8) & 0xff;
	p[1] = (u_char)v & 0xff;
}

શૂન્ય
ms_subtract_diff(સંરચના timeval *start, પૂર્ણાંક *ms)
{
	સંરચના timeval diff, finish;

	monotime_tv(&finish);
	timersub(&finish, start, &diff);
	*ms -= (diff.tv_sec * 1000) + (diff.tv_usec / 1000);
}

શૂન્ય
ms_to_timespec(સંરચના timespec *ts, પૂર્ણાંક ms)
{
	જો (ms < 0)
		ms = 0;
	ts->tv_sec = ms / 1000;
	ts->tv_nsec = (ms % 1000) * 1000 * 1000;
}

શૂન્ય
monotime_ts(સંરચના timespec *ts)
{
	સંરચના timeval tv;
#જો defined(HAVE_CLOCK_GETTIME) && (defined(CLOCK_BOOTTIME) || \
    defined(CLOCK_MONOTONIC) || defined(CLOCK_REALTIME))
	સ્થિર પૂર્ણાંક gettime_failed = 0;

	જો (!gettime_failed) {
# ifdef CLOCK_BOOTTIME
		જો (clock_gettime(CLOCK_BOOTTIME, ts) == 0)
			પાછા;
# endif /* CLOCK_BOOTTIME */
# ifdef CLOCK_MONOTONIC
		જો (clock_gettime(CLOCK_MONOTONIC, ts) == 0)
			પાછા;
# endif /* CLOCK_MONOTONIC */
# ifdef CLOCK_REALTIME
		/* Not monotonic, but we're almost out of options here. */
		જો (clock_gettime(CLOCK_REALTIME, ts) == 0)
			પાછા;
# endif /* CLOCK_REALTIME */
		debug3("clock_gettime: %s", strerror(errno));
		gettime_failed = 1;
	}
#endif /* HAVE_CLOCK_GETTIME && (BOOTTIME || MONOTONIC || REALTIME) */
	gettimeofday(&tv, ખાલી);
	ts->tv_sec = tv.tv_sec;
	ts->tv_nsec = (long)tv.tv_usec * 1000;
}

શૂન્ય
monotime_tv(સંરચના timeval *tv)
{
	સંરચના timespec ts;

	monotime_ts(&ts);
	tv->tv_sec = ts.tv_sec;
	tv->tv_usec = ts.tv_nsec / 1000;
}

time_t
monotime(શૂન્ય)
{
	સંરચના timespec ts;

	monotime_ts(&ts);
	પાછા (ts.tv_sec);
}

દ્વિગુણ
monotime_double(શૂન્ય)
{
	સંરચના timespec ts;

	monotime_ts(&ts);
	પાછા (દ્વિગુણ)ts.tv_sec + (દ્વિગુણ)ts.tv_nsec / 1000000000.0;
}

શૂન્ય
bandwidth_limit_init(સંરચના bwlimit *bw, uint64_t kbps, size_t buflen)
{
	bw->buflen = buflen;
	bw->rate = kbps;
	bw->thresh = buflen;
	bw->lamt = 0;
	timerclear(&bw->bwstart);
	timerclear(&bw->bwend);
}

/* Callback from read/write loop to insert bandwidth-limiting delays */
શૂન્ય
bandwidth_limit(સંરચના bwlimit *bw, size_t read_len)
{
	uint64_t waitlen;
	સંરચના timespec ts, rm;

	bw->lamt += read_len;
	જો (!timerisset(&bw->bwstart)) {
		monotime_tv(&bw->bwstart);
		પાછા;
	}
	જો (bw->lamt < bw->thresh)
		પાછા;

	monotime_tv(&bw->bwend);
	timersub(&bw->bwend, &bw->bwstart, &bw->bwend);
	જો (!timerisset(&bw->bwend))
		પાછા;

	bw->lamt *= 8;
	waitlen = (દ્વિગુણ)1000000L * bw->lamt / bw->rate;

	bw->bwstart.tv_sec = waitlen / 1000000L;
	bw->bwstart.tv_usec = waitlen % 1000000L;

	જો (timercmp(&bw->bwstart, &bw->bwend, >)) {
		timersub(&bw->bwstart, &bw->bwend, &bw->bwend);

		/* Adjust the wait time */
		જો (bw->bwend.tv_sec) {
			bw->thresh /= 2;
			જો (bw->thresh < bw->buflen / 4)
				bw->thresh = bw->buflen / 4;
		} નહીંતર જો (bw->bwend.tv_usec < 10000) {
			bw->thresh *= 2;
			જો (bw->thresh > bw->buflen * 8)
				bw->thresh = bw->buflen * 8;
		}

		TIMEVAL_TO_TIMESPEC(&bw->bwend, &ts);
		જ્યારે (nanosleep(&ts, &rm) == -1) {
			જો (errno != EINTR)
				તોડો;
			ts = rm;
		}
	}

	bw->lamt = 0;
	monotime_tv(&bw->bwstart);
}

/* Make a template filename for mk[sd]temp() */
શૂન્ય
mktemp_proto(અક્ષર *s, size_t len)
{
	અચલ અક્ષર *tmpdir;
	પૂર્ણાંક r;

	જો ((tmpdir = getenv("TMPDIR")) != ખાલી) {
		r = snprintf(s, len, "%s/ssh-XXXXXXXXXXXX", tmpdir);
		જો (r > 0 && (size_t)r < len)
			પાછા;
	}
	r = snprintf(s, len, "/tmp/ssh-XXXXXXXXXXXX");
	જો (r < 0 || (size_t)r >= len)
		fatal_f("template string too short");
}

સ્થિર અચલ સંરચના {
	અચલ અક્ષર *name;
	પૂર્ણાંક કિંમત;
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
	{ ખાલી, -1 }
};

પૂર્ણાંક
parse_ipqos(અચલ અક્ષર *cp)
{
	અચલ અક્ષર *errstr;
	u_int i;
	પૂર્ણાંક val;

	જો (cp == ખાલી)
		પાછા -1;
	માટે (i = 0; ipqos[i].name != ખાલી; i++) {
		જો (strcasecmp(cp, ipqos[i].name) == 0)
			પાછા ipqos[i].કિંમત;
	}
	/* Try parsing as an integer */
	val = (પૂર્ણાંક)strtonum(cp, 0, 255, &errstr);
	જો (errstr)
		પાછા -1;
	પાછા val;
}

અચલ અક્ષર *
iptos2str(પૂર્ણાંક iptos)
{
	પૂર્ણાંક i;
	સ્થિર અક્ષર iptos_str[કદ "0xff"];

	માટે (i = 0; ipqos[i].name != ખાલી; i++) {
		જો (ipqos[i].કિંમત == iptos)
			પાછા ipqos[i].name;
	}
	snprintf(iptos_str, કદ iptos_str, "0x%02x", iptos);
	પાછા iptos_str;
}

શૂન્ય
lowercase(અક્ષર *s)
{
	માટે (; *s; s++)
		*s = tolower((u_char)*s);
}

પૂર્ણાંક
unix_listener(અચલ અક્ષર *path, પૂર્ણાંક backlog, પૂર્ણાંક unlink_first)
{
	સંરચના sockaddr_un sunaddr;
	પૂર્ણાંક saved_errno, sock;

	memset(&sunaddr, 0, કદ(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	જો (strlcpy(sunaddr.sun_path, path,
	    કદ(sunaddr.sun_path)) >= કદ(sunaddr.sun_path)) {
		error_f("path \"%s\" too long for Unix domain socket", path);
		errno = ENAMETOOLONG;
		પાછા -1;
	}

	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	જો (sock == -1) {
		saved_errno = errno;
		error_f("socket: %.100s", strerror(errno));
		errno = saved_errno;
		પાછા -1;
	}
	જો (unlink_first == 1) {
		જો (unlink(path) != 0 && errno != ENOENT)
			error("unlink(%s): %.100s", path, strerror(errno));
	}
	જો (bind(sock, (સંરચના sockaddr *)&sunaddr, કદ(sunaddr)) == -1) {
		saved_errno = errno;
		error_f("cannot bind to path %s: %s", path, strerror(errno));
		close(sock);
		errno = saved_errno;
		પાછા -1;
	}
	જો (listen(sock, backlog) == -1) {
		saved_errno = errno;
		error_f("cannot listen on path %s: %s", path, strerror(errno));
		close(sock);
		unlink(path);
		errno = saved_errno;
		પાછા -1;
	}
	પાછા sock;
}

શૂન્ય
sock_set_v6only(પૂર્ણાંક s)
{
#જો defined(IPV6_V6ONLY) && !defined(__OpenBSD__)
	પૂર્ણાંક on = 1;

	debug3_f("set socket %d IPV6_V6ONLY", s);
	જો (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &on, કદ(on)) == -1)
		error("setsockopt IPV6_V6ONLY: %s", strerror(errno));
#endif
}

/*
 * Compares two strings that maybe be NULL. Returns non-zero if strings
 * are both NULL or are identical, returns zero otherwise.
 */
સ્થિર પૂર્ણાંક
strcmp_maybe_null(અચલ અક્ષર *a, અચલ અક્ષર *b)
{
	જો ((a == ખાલી && b != ખાલી) || (a != ખાલી && b == ખાલી))
		પાછા 0;
	જો (a != ખાલી && strcmp(a, b) != 0)
		પાછા 0;
	પાછા 1;
}

/*
 * Compare two forwards, returning non-zero if they are identical or
 * zero otherwise.
 */
પૂર્ણાંક
forward_equals(અચલ સંરચના Forward *a, અચલ સંરચના Forward *b)
{
	જો (strcmp_maybe_null(a->listen_host, b->listen_host) == 0)
		પાછા 0;
	જો (a->listen_port != b->listen_port)
		પાછા 0;
	જો (strcmp_maybe_null(a->listen_path, b->listen_path) == 0)
		પાછા 0;
	જો (strcmp_maybe_null(a->connect_host, b->connect_host) == 0)
		પાછા 0;
	જો (a->connect_port != b->connect_port)
		પાછા 0;
	જો (strcmp_maybe_null(a->connect_path, b->connect_path) == 0)
		પાછા 0;
	/* allocated_port and handle are not checked */
	પાછા 1;
}

/* returns port number, FWD_PERMIT_ANY_PORT or -1 on error */
પૂર્ણાંક
permitopen_port(અચલ અક્ષર *p)
{
	પૂર્ણાંક port;

	જો (strcmp(p, "*") == 0)
		પાછા FWD_PERMIT_ANY_PORT;
	જો ((port = a2port(p)) > 0)
		પાછા port;
	પાછા -1;
}

/* returns 1 if process is already daemonized, 0 otherwise */
પૂર્ણાંક
daemonized(શૂન્ય)
{
	પૂર્ણાંક fd;

	જો ((fd = open(_PATH_TTY, O_RDONLY | O_NOCTTY)) >= 0) {
		close(fd);
		પાછા 0;	/* have controlling terminal */
	}
	જો (getppid() != 1)
		પાછા 0;	/* parent is not init */
	જો (getsid(0) != getpid())
		પાછા 0;	/* not session leader */
	debug3("already daemonized");
	પાછા 1;
}

/*
 * Splits 's' into an argument vector. Handles quoted string and basic
 * escape characters (\\, \", \'). Caller must free the argument vector
 * and its members.
 */
પૂર્ણાંક
argv_split(અચલ અક્ષર *s, પૂર્ણાંક *argcp, અક્ષર ***argvp, પૂર્ણાંક terminate_on_comment)
{
	પૂર્ણાંક r = SSH_ERR_INTERNAL_ERROR;
	પૂર્ણાંક argc = 0, quote, i, j;
	અક્ષર *arg, **argv = xcalloc(1, કદ(*argv));

	*argvp = ખાલી;
	*argcp = 0;

	માટે (i = 0; s[i] != '\0'; i++) {
		/* Skip leading whitespace */
		જો (s[i] == ' ' || s[i] == '\t')
			ચાલુ;
		જો (terminate_on_comment && s[i] == '#')
			તોડો;
		/* Start of a token */
		quote = 0;

		argv = xreallocarray(argv, (argc + 2), કદ(*argv));
		arg = argv[argc++] = xcalloc(1, strlen(s + i) + 1);
		argv[argc] = ખાલી;

		/* Copy the token in, removing escapes */
		માટે (j = 0; s[i] != '\0'; i++) {
			જો (s[i] == '\\') {
				જો (s[i + 1] == '\'' ||
				    s[i + 1] == '\"' ||
				    s[i + 1] == '\\' ||
				    (quote == 0 && s[i + 1] == ' ')) {
					i++; /* Skip '\' */
					arg[j++] = s[i];
				} નહીંતર {
					/* Unrecognised escape */
					arg[j++] = s[i];
				}
			} નહીંતર જો (quote == 0 && (s[i] == ' ' || s[i] == '\t'))
				તોડો; /* done */
			નહીંતર જો (quote == 0 && (s[i] == '\"' || s[i] == '\''))
				quote = s[i]; /* quote start */
			નહીંતર જો (quote != 0 && s[i] == quote)
				quote = 0; /* quote end */
			નહીંતર
				arg[j++] = s[i];
		}
		જો (s[i] == '\0') {
			જો (quote != 0) {
				/* Ran out of string looking for close quote */
				r = SSH_ERR_INVALID_FORMAT;
				જાઓ out;
			}
			તોડો;
		}
	}
	/* Success */
	*argcp = argc;
	*argvp = argv;
	argc = 0;
	argv = ખાલી;
	r = 0;
 out:
	જો (argc != 0 && argv != ખાલી) {
		માટે (i = 0; i < argc; i++)
			મુક્ત(argv[i]);
		મુક્ત(argv);
	}
	પાછા r;
}

/*
 * Reassemble an argument vector into a string, quoting and escaping as
 * necessary. Caller must free returned string.
 */
અક્ષર *
argv_assemble(પૂર્ણાંક argc, અક્ષર **argv)
{
	પૂર્ણાંક i, j, ws, r;
	અક્ષર c, *ret;
	સંરચના sshbuf *buf, *arg;

	જો ((buf = sshbuf_new()) == ખાલી || (arg = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");

	માટે (i = 0; i < argc; i++) {
		ws = 0;
		sshbuf_reset(arg);
		માટે (j = 0; argv[i][j] != '\0'; j++) {
			r = 0;
			c = argv[i][j];
			પસંદગી (c) {
			સ્થિતિ ' ':
			સ્થિતિ '\t':
				ws = 1;
				r = sshbuf_put_u8(arg, c);
				તોડો;
			સ્થિતિ '\\':
			સ્થિતિ '\'':
			સ્થિતિ '"':
				જો ((r = sshbuf_put_u8(arg, '\\')) != 0)
					તોડો;
				/* FALLTHROUGH */
			મૂળભૂત:
				r = sshbuf_put_u8(arg, c);
				તોડો;
			}
			જો (r != 0)
				fatal_fr(r, "sshbuf_put_u8");
		}
		જો ((i != 0 && (r = sshbuf_put_u8(buf, ' ')) != 0) ||
		    (ws != 0 && (r = sshbuf_put_u8(buf, '"')) != 0) ||
		    (r = sshbuf_putb(buf, arg)) != 0 ||
		    (ws != 0 && (r = sshbuf_put_u8(buf, '"')) != 0))
			fatal_fr(r, "assemble");
	}
	જો ((ret = malloc(sshbuf_len(buf) + 1)) == ખાલી)
		fatal_f("malloc failed");
	memcpy(ret, sshbuf_ptr(buf), sshbuf_len(buf));
	ret[sshbuf_len(buf)] = '\0';
	sshbuf_free(buf);
	sshbuf_free(arg);
	પાછા ret;
}

અક્ષર *
argv_next(પૂર્ણાંક *argcp, અક્ષર ***argvp)
{
	અક્ષર *ret = (*argvp)[0];

	જો (*argcp > 0 && ret != ખાલી) {
		(*argcp)--;
		(*argvp)++;
	}
	પાછા ret;
}

શૂન્ય
argv_consume(પૂર્ણાંક *argcp)
{
	*argcp = 0;
}

શૂન્ય
argv_free(અક્ષર **av, પૂર્ણાંક ac)
{
	પૂર્ણાંક i;

	જો (av == ખાલી)
		પાછા;
	માટે (i = 0; i < ac; i++)
		મુક્ત(av[i]);
	મુક્ત(av);
}

/* Returns 0 if pid exited cleanly, non-zero otherwise */
પૂર્ણાંક
exited_cleanly(pid_t pid, અચલ અક્ષર *tag, અચલ અક્ષર *cmd, પૂર્ણાંક quiet)
{
	પૂર્ણાંક status;

	જ્યારે (waitpid(pid, &status, 0) == -1) {
		જો (errno != EINTR) {
			error("%s waitpid: %s", tag, strerror(errno));
			પાછા -1;
		}
	}
	જો (WIFSIGNALED(status)) {
		error("%s %s exited on signal %d", tag, cmd, WTERMSIG(status));
		પાછા -1;
	} નહીંતર જો (WEXITSTATUS(status) != 0) {
		do_log2(quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_INFO,
		    "%s %s failed, status %d", tag, cmd, WEXITSTATUS(status));
		પાછા -1;
	}
	પાછા 0;
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
પૂર્ણાંક
safe_path(અચલ અક્ષર *name, સંરચના stat *stp, અચલ અક્ષર *pw_dir,
    uid_t uid, અક્ષર *err, size_t errlen)
{
	અક્ષર buf[PATH_MAX], buf2[PATH_MAX], homedir[PATH_MAX];
	અક્ષર *cp;
	પૂર્ણાંક comparehome = 0;
	સંરચના stat st;

	જો (realpath(name, buf) == ખાલી) {
		snprintf(err, errlen, "realpath %s failed: %s", name,
		    strerror(errno));
		પાછા -1;
	}
	જો (pw_dir != ખાલી && realpath(pw_dir, homedir) != ખાલી)
		comparehome = 1;

	જો (!S_ISREG(stp->st_mode)) {
		snprintf(err, errlen, "%s is not a regular file", buf);
		પાછા -1;
	}
	જો ((!platform_sys_dir_uid(stp->st_uid) && stp->st_uid != uid) ||
	    (stp->st_mode & 022) != 0) {
		snprintf(err, errlen, "bad ownership or modes for file %s",
		    buf);
		પાછા -1;
	}

	/* for each component of the canonical path, walking upwards */
	માટે (;;) {
		/*
		 * POSIX allows dirname to modify its argument and return a
		 * pointer into it, so make a copy to avoid overlapping strlcpy.
		 */
		strlcpy(buf2, buf, કદ(buf2));
		જો ((cp = dirname(buf2)) == ખાલી) {
			snprintf(err, errlen, "dirname() failed");
			પાછા -1;
		}
		strlcpy(buf, cp, કદ(buf));

		જો (stat(buf, &st) == -1 ||
		    (!platform_sys_dir_uid(st.st_uid) && st.st_uid != uid) ||
		    (st.st_mode & 022) != 0) {
			snprintf(err, errlen,
			    "bad ownership or modes for directory %s", buf);
			પાછા -1;
		}

		/* If are past the homedir then we can stop */
		જો (comparehome && strcmp(homedir, buf) == 0)
			તોડો;

		/*
		 * dirname should always complete with a "/" path,
		 * but we can be paranoid and check for "." too
		 */
		જો ((strcmp("/", buf) == 0) || (strcmp(".", buf) == 0))
			તોડો;
	}
	પાછા 0;
}

/*
 * Version of safe_path() that accepts an open file descriptor to
 * avoid races.
 *
 * Returns 0 on success and -1 on failure
 */
પૂર્ણાંક
safe_path_fd(પૂર્ણાંક fd, અચલ અક્ષર *file, સંરચના passwd *pw,
    અક્ષર *err, size_t errlen)
{
	સંરચના stat st;

	/* check the open file to avoid races */
	જો (fstat(fd, &st) == -1) {
		snprintf(err, errlen, "cannot stat file %s: %s",
		    file, strerror(errno));
		પાછા -1;
	}
	પાછા safe_path(file, &st, pw->pw_dir, pw->pw_uid, err, errlen);
}

/*
 * Sets the value of the given variable in the environment.  If the variable
 * already exists, its value is overridden.
 */
શૂન્ય
child_set_env(અક્ષર ***envp, u_int *envsizep, અચલ અક્ષર *name,
	અચલ અક્ષર *કિંમત)
{
	અક્ષર **env;
	u_int envsize;
	u_int i, namelen;

	જો (strchr(name, '=') != ખાલી) {
		error("Invalid environment variable \"%.100s\"", name);
		પાછા;
	}

	/*
	 * If we're passed an uninitialized list, allocate a single null
	 * entry before continuing.
	 */
	જો ((*envp == ખાલી) != (*envsizep == 0))
		fatal_f("environment size mismatch");
	જો (*envp == ખાલી && *envsizep == 0) {
		*envp = xmalloc(કદ(અક્ષર *));
		*envp[0] = ખાલી;
		*envsizep = 1;
	}

	/*
	 * Find the slot where the value should be stored.  If the variable
	 * already exists, we reuse the slot; otherwise we append a new slot
	 * at the end of the array, expanding if necessary.
	 */
	env = *envp;
	namelen = strlen(name);
	માટે (i = 0; env[i]; i++)
		જો (strncmp(env[i], name, namelen) == 0 && env[i][namelen] == '=')
			તોડો;
	જો (env[i]) {
		/* Reuse the slot. */
		મુક્ત(env[i]);
	} નહીંતર {
		/* New variable.  Expand if necessary. */
		envsize = *envsizep;
		જો (i >= envsize - 1) {
			જો (envsize >= 1000)
				fatal("child_set_env: too many env vars");
			envsize += 50;
			env = (*envp) = xreallocarray(env, envsize, કદ(અક્ષર *));
			*envsizep = envsize;
		}
		/* Need to set the NULL pointer at end of array beyond the new slot. */
		env[i + 1] = ખાલી;
	}

	/* Allocate space and format the variable in the appropriate slot. */
	/* XXX xasprintf */
	env[i] = xmalloc(strlen(name) + 1 + strlen(કિંમત) + 1);
	snprintf(env[i], strlen(name) + 1 + strlen(કિંમત) + 1, "%s=%s", name, કિંમત);
}

/*
 * Check and optionally lowercase a domain name, also removes trailing '.'
 * Returns 1 on success and 0 on failure, storing an error message in errstr.
 */
પૂર્ણાંક
valid_domain(અક્ષર *name, પૂર્ણાંક makelower, અચલ અક્ષર **errstr)
{
	size_t i, l = strlen(name);
	u_char c, last = '\0';
	સ્થિર અક્ષર errbuf[256];

	જો (l == 0) {
		strlcpy(errbuf, "empty domain name", કદ(errbuf));
		જાઓ bad;
	}
	જો (!isalpha((u_char)name[0]) && !isdigit((u_char)name[0]) &&
	   name[0] != '_' /* technically invalid, but common */) {
		snprintf(errbuf, કદ(errbuf), "domain name \"%.100s\" "
		    "starts with invalid character", name);
		જાઓ bad;
	}
	માટે (i = 0; i < l; i++) {
		c = tolower((u_char)name[i]);
		જો (makelower)
			name[i] = (અક્ષર)c;
		જો (last == '.' && c == '.') {
			snprintf(errbuf, કદ(errbuf), "domain name "
			    "\"%.100s\" contains consecutive separators", name);
			જાઓ bad;
		}
		જો (c != '.' && c != '-' && !isalnum(c) &&
		    c != '_') /* technically invalid, but common */ {
			snprintf(errbuf, કદ(errbuf), "domain name "
			    "\"%.100s\" contains invalid characters", name);
			જાઓ bad;
		}
		last = c;
	}
	જો (name[l - 1] == '.')
		name[l - 1] = '\0';
	જો (errstr != ખાલી)
		*errstr = ખાલી;
	પાછા 1;
bad:
	જો (errstr != ખાલી)
		*errstr = errbuf;
	પાછા 0;
}

/*
 * Verify that a environment variable name (not including initial '$') is
 * valid; consisting of one or more alphanumeric or underscore characters only.
 * Returns 1 on valid, 0 otherwise.
 */
પૂર્ણાંક
valid_env_name(અચલ અક્ષર *name)
{
	અચલ અક્ષર *cp;

	જો (name[0] == '\0')
		પાછા 0;
	માટે (cp = name; *cp != '\0'; cp++) {
		જો (!isalnum((u_char)*cp) && *cp != '_')
			પાછા 0;
	}
	પાછા 1;
}

અચલ અક્ષર *
atoi_err(અચલ અક્ષર *nptr, પૂર્ણાંક *val)
{
	અચલ અક્ષર *errstr = ખાલી;

	જો (nptr == ખાલી || *nptr == '\0')
		પાછા "missing";
	*val = strtonum(nptr, 0, INT_MAX, &errstr);
	પાછા errstr;
}

પૂર્ણાંક
parse_absolute_time(અચલ અક્ષર *s, uint64_t *tp)
{
	સંરચના tm tm;
	time_t tt;
	અક્ષર buf[32], *fmt;
	અચલ અક્ષર *cp;
	size_t l;
	પૂર્ણાંક is_utc = 0;

	*tp = 0;

	l = strlen(s);
	જો (l > 1 && strcasecmp(s + l - 1, "Z") == 0) {
		is_utc = 1;
		l--;
	} નહીંતર જો (l > 3 && strcasecmp(s + l - 3, "UTC") == 0) {
		is_utc = 1;
		l -= 3;
	}
	/*
	 * POSIX strptime says "The application shall ensure that there
	 * is white-space or other non-alphanumeric characters between
	 * any two conversion specifications" so arrange things this way.
	 */
	પસંદગી (l) {
	સ્થિતિ 8: /* YYYYMMDD */
		fmt = "%Y-%m-%d";
		snprintf(buf, કદ(buf), "%.4s-%.2s-%.2s", s, s + 4, s + 6);
		તોડો;
	સ્થિતિ 12: /* YYYYMMDDHHMM */
		fmt = "%Y-%m-%dT%H:%M";
		snprintf(buf, કદ(buf), "%.4s-%.2s-%.2sT%.2s:%.2s",
		    s, s + 4, s + 6, s + 8, s + 10);
		તોડો;
	સ્થિતિ 14: /* YYYYMMDDHHMMSS */
		fmt = "%Y-%m-%dT%H:%M:%S";
		snprintf(buf, કદ(buf), "%.4s-%.2s-%.2sT%.2s:%.2s:%.2s",
		    s, s + 4, s + 6, s + 8, s + 10, s + 12);
		તોડો;
	મૂળભૂત:
		પાછા SSH_ERR_INVALID_FORMAT;
	}

	memset(&tm, 0, કદ(tm));
	જો ((cp = strptime(buf, fmt, &tm)) == ખાલી || *cp != '\0')
		પાછા SSH_ERR_INVALID_FORMAT;
	જો (is_utc) {
		tm.tm_wday = -1;	/* sentinel for error */
		જો ((tt = timegm(&tm)) == -1 && tm.tm_wday == -1)
			પાછા SSH_ERR_INVALID_FORMAT;
	} નહીંતર {
		tm.tm_wday = -1;	/* sentinel for error */
		tm.tm_isdst = -1;	/* mktime decides DST */
		જો ((tt = mktime(&tm)) == -1 && tm.tm_wday == -1)
			પાછા SSH_ERR_INVALID_FORMAT;
	}
	/* success */
	*tp = (uint64_t)tt;
	પાછા 0;
}

શૂન્ય
format_absolute_time(uint64_t t, અક્ષર *buf, size_t len)
{
	time_t tt = t > SSH_TIME_T_MAX ? SSH_TIME_T_MAX : t;
	સંરચના tm tm;

	જો (localtime_r(&tt, &tm) == ખાલી)
		strlcpy(buf, "UNKNOWN-TIME", len);
	નહીંતર
		strftime(buf, len, "%Y-%m-%dT%H:%M:%S", &tm);
}

/*
 * Parse a "pattern=interval" clause (e.g. a ChannelTimeout).
 * Returns 0 on success or non-zero on failure.
 * Caller must free *typep.
 */
પૂર્ણાંક
parse_pattern_interval(અચલ અક્ષર *s, અક્ષર **typep, દ્વિગુણ *secsp)
{
	અક્ષર *cp, *sdup;
	દ્વિગુણ secs;

	જો (typep != ખાલી)
		*typep = ખાલી;
	જો (secsp != ખાલી)
		*secsp = 0;
	જો (s == ખાલી)
		પાછા -1;
	sdup = xstrdup(s);

	જો ((cp = strchr(sdup, '=')) == ખાલી || cp == sdup) {
		મુક્ત(sdup);
		પાછા -1;
	}
	*cp++ = '\0';
	જો ((secs = convtime_double(cp)) < 0.0) {
		મુક્ત(sdup);
		પાછા -1;
	}
	/* success */
	જો (typep != ખાલી)
		*typep = xstrdup(sdup);
	જો (secsp != ખાલી)
		*secsp = secs;
	મુક્ત(sdup);
	પાછા 0;
}

/* check if path is absolute */
પૂર્ણાંક
path_absolute(અચલ અક્ષર *path)
{
	પાછા (*path == '/') ? 1 : 0;
}

શૂન્ય
skip_space(અક્ષર **cpp)
{
	અક્ષર *cp;

	માટે (cp = *cpp; *cp == ' ' || *cp == '\t'; cp++)
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
પૂર્ણાંક
opt_flag(અચલ અક્ષર *opt, પૂર્ણાંક allow_negate, અચલ અક્ષર **optsp)
{
	size_t opt_len = strlen(opt);
	અચલ અક્ષર *opts = *optsp;
	પૂર્ણાંક negate = 0;

	જો (allow_negate && strncasecmp(opts, "no-", 3) == 0) {
		opts += 3;
		negate = 1;
	}
	જો (strncasecmp(opts, opt, opt_len) == 0) {
		*optsp = opts + opt_len;
		પાછા negate ? 0 : 1;
	}
	પાછા -1;
}

અક્ષર *
opt_dequote(અચલ અક્ષર **sp, અચલ અક્ષર **errstrp)
{
	અચલ અક્ષર *s = *sp;
	અક્ષર *ret;
	size_t i;

	*errstrp = ખાલી;
	જો (*s != '"') {
		*errstrp = "missing start quote";
		પાછા ખાલી;
	}
	s++;
	જો ((ret = malloc(strlen((s)) + 1)) == ખાલી) {
		*errstrp = "memory allocation failed";
		પાછા ખાલી;
	}
	માટે (i = 0; *s != '\0' && *s != '"';) {
		જો (s[0] == '\\' && s[1] == '"')
			s++;
		ret[i++] = *s++;
	}
	જો (*s == '\0') {
		*errstrp = "missing end quote";
		મુક્ત(ret);
		પાછા ખાલી;
	}
	ret[i] = '\0';
	s++;
	*sp = s;
	પાછા ret;
}

પૂર્ણાંક
opt_match(અચલ અક્ષર **opts, અચલ અક્ષર *term)
{
	જો (strncasecmp((*opts), term, strlen(term)) == 0 &&
	    (*opts)[strlen(term)] == '=') {
		*opts += strlen(term) + 1;
		પાછા 1;
	}
	પાછા 0;
}

શૂન્ય
opt_array_append2(અચલ અક્ષર *file, અચલ પૂર્ણાંક લીટી, અચલ અક્ષર *directive,
    અક્ષર ***array, પૂર્ણાંક **iarray, u_int *lp, અચલ અક્ષર *s, પૂર્ણાંક i)
{

	જો (*lp >= INT_MAX)
		fatal("%s line %d: Too many %s entries", file, લીટી, directive);

	જો (iarray != ખાલી) {
		*iarray = xrecallocarray(*iarray, *lp, *lp + 1,
		    કદ(**iarray));
		(*iarray)[*lp] = i;
	}

	*array = xrecallocarray(*array, *lp, *lp + 1, કદ(**array));
	(*array)[*lp] = xstrdup(s);
	(*lp)++;
}

શૂન્ય
opt_array_append(અચલ અક્ષર *file, અચલ પૂર્ણાંક લીટી, અચલ અક્ષર *directive,
    અક્ષર ***array, u_int *lp, અચલ અક્ષર *s)
{
	opt_array_append2(file, લીટી, directive, array, ખાલી, lp, s, 0);
}

શૂન્ય
opt_array_free2(અક્ષર **array, પૂર્ણાંક **iarray, u_int l)
{
	u_int i;

	જો (array == ખાલી || l == 0)
		પાછા;
	માટે (i = 0; i < l; i++)
		મુક્ત(array[i]);
	મુક્ત(array);
	મુક્ત(iarray);
}

sshsig_t
ssh_signal(પૂર્ણાંક signum, sshsig_t handler)
{
	સંરચના sigaction sa, osa;

	/* mask all other signals while in handler */
	memset(&sa, 0, કદ(sa));
	sa.sa_handler = handler;
	sigfillset(&sa.sa_mask);
#જો defined(SA_RESTART) && !defined(NO_SA_RESTART)
	જો (signum != SIGALRM)
		sa.sa_flags = SA_RESTART;
#endif
	જો (sigaction(signum, &sa, &osa) == -1) {
		debug3("sigaction(%s): %s", strsignal(signum), strerror(errno));
		પાછા SIG_ERR;
	}
	પાછા osa.sa_handler;
}

પૂર્ણાંક
stdfd_devnull(પૂર્ણાંક do_stdin, પૂર્ણાંક do_stdout, પૂર્ણાંક do_stderr)
{
	પૂર્ણાંક devnull, ret = 0;

	જો ((devnull = open(_PATH_DEVNULL, O_RDWR)) == -1) {
		error_f("open %s: %s", _PATH_DEVNULL,
		    strerror(errno));
		પાછા -1;
	}
	જો ((do_stdin && dup2(devnull, STDIN_FILENO) == -1) ||
	    (do_stdout && dup2(devnull, STDOUT_FILENO) == -1) ||
	    (do_stderr && dup2(devnull, STDERR_FILENO) == -1)) {
		error_f("dup2: %s", strerror(errno));
		ret = -1;
	}
	જો (devnull > STDERR_FILENO)
		close(devnull);
	પાછા ret;
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
subprocess(અચલ અક્ષર *tag, અચલ અક્ષર *command,
    પૂર્ણાંક ac, અક્ષર **av, FILE **child, u_int flags,
    સંરચના passwd *pw, privdrop_fn *drop_privs, privrestore_fn *restore_privs)
{
	FILE *f = ખાલી;
	સંરચના stat st;
	પૂર્ણાંક fd, devnull, p[2], i;
	pid_t pid;
	અક્ષર *cp, errmsg[512];
	u_int nenv = 0;
	અક્ષર **env = ખાલી;

	/* If dropping privs, then must specify user and restore function */
	જો (drop_privs != ખાલી && (pw == ખાલી || restore_privs == ખાલી)) {
		error("%s: inconsistent arguments", tag); /* XXX fatal? */
		પાછા 0;
	}
	જો (pw == ખાલી && (pw = getpwuid(getuid())) == ખાલી) {
		error("%s: no user for current uid", tag);
		પાછા 0;
	}
	જો (child != ખાલી)
		*child = ખાલી;

	debug3_f("%s command \"%s\" running as %s (flags 0x%x)",
	    tag, command, pw->pw_name, flags);

	/* Check consistency */
	જો ((flags & SSH_SUBPROCESS_STDOUT_DISCARD) != 0 &&
	    (flags & SSH_SUBPROCESS_STDOUT_CAPTURE) != 0) {
		error_f("inconsistent flags");
		પાછા 0;
	}
	જો (((flags & SSH_SUBPROCESS_STDOUT_CAPTURE) == 0) != (child == ખાલી)) {
		error_f("inconsistent flags/output");
		પાછા 0;
	}

	/*
	 * If executing an explicit binary, then verify the it exists
	 * and appears safe-ish to execute
	 */
	જો (!path_absolute(av[0])) {
		error("%s path is not absolute", tag);
		પાછા 0;
	}
	જો (drop_privs != ખાલી)
		drop_privs(pw);
	જો (stat(av[0], &st) == -1) {
		error("Could not stat %s \"%s\": %s", tag,
		    av[0], strerror(errno));
		જાઓ restore_return;
	}
	જો ((flags & SSH_SUBPROCESS_UNSAFE_PATH) == 0 &&
	    safe_path(av[0], &st, ખાલી, 0, errmsg, કદ(errmsg)) != 0) {
		error("Unsafe %s \"%s\": %s", tag, av[0], errmsg);
		જાઓ restore_return;
	}
	/* Prepare to keep the child's stdout if requested */
	જો (pipe(p) == -1) {
		error("%s: pipe: %s", tag, strerror(errno));
 restore_return:
		જો (restore_privs != ખાલી)
			restore_privs();
		પાછા 0;
	}
	જો (restore_privs != ખાલી)
		restore_privs();

	પસંદગી ((pid = fork())) {
	સ્થિતિ -1: /* error */
		error("%s: fork: %s", tag, strerror(errno));
		close(p[0]);
		close(p[1]);
		પાછા 0;
	સ્થિતિ 0: /* child */
		/* Prepare a minimal environment for the child. */
		જો ((flags & SSH_SUBPROCESS_PRESERVE_ENV) == 0) {
			nenv = 5;
			env = xcalloc(કદ(*env), nenv);
			child_set_env(&env, &nenv, "PATH", _PATH_STDPATH);
			child_set_env(&env, &nenv, "USER", pw->pw_name);
			child_set_env(&env, &nenv, "LOGNAME", pw->pw_name);
			child_set_env(&env, &nenv, "HOME", pw->pw_dir);
			જો ((cp = getenv("LANG")) != ખાલી)
				child_set_env(&env, &nenv, "LANG", cp);
		}

		માટે (i = 1; i < NSIG; i++)
			ssh_signal(i, SIG_DFL);

		જો ((devnull = open(_PATH_DEVNULL, O_RDWR)) == -1) {
			error("%s: open %s: %s", tag, _PATH_DEVNULL,
			    strerror(errno));
			_exit(1);
		}
		જો (dup2(devnull, STDIN_FILENO) == -1) {
			error("%s: dup2: %s", tag, strerror(errno));
			_exit(1);
		}

		/* Set up stdout as requested; leave stderr in place for now. */
		fd = -1;
		જો ((flags & SSH_SUBPROCESS_STDOUT_CAPTURE) != 0)
			fd = p[1];
		નહીંતર જો ((flags & SSH_SUBPROCESS_STDOUT_DISCARD) != 0)
			fd = devnull;
		જો (fd != -1 && dup2(fd, STDOUT_FILENO) == -1) {
			error("%s: dup2: %s", tag, strerror(errno));
			_exit(1);
		}
		closefrom(STDERR_FILENO + 1);

		જો (geteuid() == 0 &&
		    initgroups(pw->pw_name, pw->pw_gid) == -1) {
			error("%s: initgroups(%s, %u): %s", tag,
			    pw->pw_name, (u_int)pw->pw_gid, strerror(errno));
			_exit(1);
		}
		જો (setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) == -1) {
			error("%s: setresgid %u: %s", tag, (u_int)pw->pw_gid,
			    strerror(errno));
			_exit(1);
		}
		જો (setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) == -1) {
			error("%s: setresuid %u: %s", tag, (u_int)pw->pw_uid,
			    strerror(errno));
			_exit(1);
		}
		/* stdin is pointed to /dev/null at this point */
		જો ((flags & SSH_SUBPROCESS_STDOUT_DISCARD) != 0 &&
		    dup2(STDIN_FILENO, STDERR_FILENO) == -1) {
			error("%s: dup2: %s", tag, strerror(errno));
			_exit(1);
		}
		જો (env != ખાલી)
			execve(av[0], av, env);
		નહીંતર
			execv(av[0], av);
		error("%s %s \"%s\": %s", tag, env == ખાલી ? "execv" : "execve",
		    command, strerror(errno));
		_exit(127);
	મૂળભૂત: /* parent */
		તોડો;
	}

	close(p[1]);
	જો ((flags & SSH_SUBPROCESS_STDOUT_CAPTURE) == 0)
		close(p[0]);
	નહીંતર જો ((f = fdopen(p[0], "r")) == ખાલી) {
		error("%s: fdopen: %s", tag, strerror(errno));
		close(p[0]);
		/* Don't leave zombie child */
		kill(pid, SIGTERM);
		જ્યારે (waitpid(pid, ખાલી, 0) == -1 && errno == EINTR)
			;
		પાછા 0;
	}
	/* Success */
	debug3_f("%s pid %ld", tag, (long)pid);
	જો (child != ખાલી)
		*child = f;
	પાછા pid;
}

અચલ અક્ષર *
lookup_env_in_list(અચલ અક્ષર *env, અક્ષર * અચલ *envs, size_t nenvs)
{
	size_t i, envlen;

	envlen = strlen(env);
	માટે (i = 0; i < nenvs; i++) {
		જો (strncmp(envs[i], env, envlen) == 0 &&
		    envs[i][envlen] == '=') {
			પાછા envs[i] + envlen + 1;
		}
	}
	પાછા ખાલી;
}

અચલ અક્ષર *
lookup_setenv_in_list(અચલ અક્ષર *env, અક્ષર * અચલ *envs, size_t nenvs)
{
	અક્ષર *name, *cp;
	અચલ અક્ષર *ret;

	name = xstrdup(env);
	જો ((cp = strchr(name, '=')) == ખાલી) {
		મુક્ત(name);
		પાછા ખાલી; /* not env=val */
	}
	*cp = '\0';
	ret = lookup_env_in_list(name, envs, nenvs);
	મુક્ત(name);
	પાછા ret;
}

/*
 * Helpers for managing poll(2)/ppoll(2) timeouts
 * Will remember the earliest deadline and return it for use in poll/ppoll.
 */

/* Initialise a poll/ppoll timeout with an indefinite deadline */
શૂન્ય
ptimeout_init(સંરચના timespec *pt)
{
	/*
	 * Deliberately invalid for ppoll(2).
	 * Will be converted to NULL in ptimeout_get_tspec() later.
	 */
	pt->tv_sec = -1;
	pt->tv_nsec = 0;
}

/* Specify a poll/ppoll deadline of at most 'sec' seconds */
શૂન્ય
ptimeout_deadline_sec(સંરચના timespec *pt, long sec)
{
	જો (pt->tv_sec == -1 || pt->tv_sec >= sec) {
		pt->tv_sec = sec;
		pt->tv_nsec = 0;
	}
}

/* Specify a poll/ppoll deadline of at most 'p' (timespec) */
સ્થિર શૂન્ય
ptimeout_deadline_tsp(સંરચના timespec *pt, સંરચના timespec *p)
{
	જો (pt->tv_sec == -1 || timespeccmp(pt, p, >=))
		*pt = *p;
}

/* Specify a poll/ppoll deadline of at most 'ms' milliseconds */
શૂન્ય
ptimeout_deadline_ms(સંરચના timespec *pt, long ms)
{
	સંરચના timespec p;

	p.tv_sec = ms / 1000;
	p.tv_nsec = (ms % 1000) * 1000000;
	ptimeout_deadline_tsp(pt, &p);
}

/* Specify a poll/ppoll deadline of at most 'sec' seconds (double) */
શૂન્ય
ptimeout_deadline_sec_double(સંરચના timespec *pt, દ્વિગુણ sec)
{
	સંરચના timespec t;

	memset(&t, 0, કદ(t));
	જો ((int64_t)sec >= SSH_TIME_T_MAX)
		t.tv_sec = SSH_TIME_T_MAX;
	નહીંતર જો (sec > 0) {
		t.tv_sec = sec;
		t.tv_nsec = (sec - (દ્વિગુણ)t.tv_sec) * 1000000000.0;
	}
	ptimeout_deadline_tsp(pt, &t);
}

/* Specify a poll/ppoll deadline at wall clock monotime 'when' (timespec) */
શૂન્ય
ptimeout_deadline_monotime_tsp(સંરચના timespec *pt, સંરચના timespec *when)
{
	સંરચના timespec now, t;

	monotime_ts(&now);

	જો (timespeccmp(&now, when, >=)) {
		/* 'when' is now or in the past. Timeout ASAP */
		pt->tv_sec = 0;
		pt->tv_nsec = 0;
	} નહીંતર {
		timespecsub(when, &now, &t);
		ptimeout_deadline_tsp(pt, &t);
	}
}

/* Specify a poll/ppoll deadline at wall clock monotime 'when' (double) */
શૂન્ય
ptimeout_deadline_monotime_double(સંરચના timespec *pt, દ્વિગુણ when)
{
	ptimeout_deadline_sec_double(pt, when - monotime_double());
}

/* Specify a poll/ppoll deadline at wall clock monotime 'when' */
શૂન્ય
ptimeout_deadline_monotime(સંરચના timespec *pt, time_t when)
{
	સંરચના timespec t;

	t.tv_sec = when;
	t.tv_nsec = 0;
	ptimeout_deadline_monotime_tsp(pt, &t);
}

/* Get a poll(2) timeout value in milliseconds */
પૂર્ણાંક
ptimeout_get_ms(સંરચના timespec *pt)
{
	જો (pt->tv_sec == -1)
		પાછા -1;
	જો (pt->tv_sec >= (INT_MAX - (pt->tv_nsec / 1000000)) / 1000)
		પાછા INT_MAX;
	પાછા (pt->tv_sec * 1000) + (pt->tv_nsec / 1000000);
}

/* Get a ppoll(2) timeout value as a timespec pointer */
સંરચના timespec *
ptimeout_get_tsp(સંરચના timespec *pt)
{
	પાછા pt->tv_sec == -1 ? ખાલી : pt;
}

/* Returns non-zero if a timeout has been set (i.e. is not indefinite) */
પૂર્ણાંક
ptimeout_isset(સંરચના timespec *pt)
{
	પાછા pt->tv_sec != -1;
}

/*
 * Returns zero if the library at 'path' contains symbol 's', nonzero
 * otherwise.
 */
પૂર્ણાંક
lib_contains_પ્રતીક(અચલ અક્ષર *path, અચલ અક્ષર *s)
{
#ifdef HAVE_NLIST
	સંરચના nlist nl[2];
	પૂર્ણાંક ret = -1, r;

	memset(nl, 0, કદ(nl));
	nl[0].n_name = xstrdup(s);
	nl[1].n_name = ખાલી;
	જો ((r = nlist(path, nl)) == -1) {
		error_f("nlist failed for %s", path);
		જાઓ out;
	}
	જો (r != 0 || nl[0].n_કિંમત == 0 || nl[0].n_type == 0) {
		error_f("library %s does not contain symbol %s", path, s);
		જાઓ out;
	}
	/* success */
	ret = 0;
 out:
	મુક્ત(nl[0].n_name);
	પાછા ret;
#નહીંતર /* HAVE_NLIST */
	પૂર્ણાંક fd, ret = -1;
	સંરચના stat st;
	શૂન્ય *m = ખાલી;
	size_t sz = 0;

	memset(&st, 0, કદ(st));
	જો ((fd = open(path, O_RDONLY)) < 0) {
		error_f("open %s: %s", path, strerror(errno));
		પાછા -1;
	}
	જો (fstat(fd, &st) != 0) {
		error_f("fstat %s: %s", path, strerror(errno));
		જાઓ out;
	}
	જો (!S_ISREG(st.st_mode)) {
		error_f("%s is not a regular file", path);
		જાઓ out;
	}
	જો (st.st_size < 0 ||
	    (size_t)st.st_size < strlen(s) ||
	    st.st_size >= INT_MAX/2) {
		error_f("%s bad size %lld", path, (long long)st.st_size);
		જાઓ out;
	}
	sz = (size_t)st.st_size;
	જો ((m = mmap(ખાલી, sz, PROT_READ, MAP_PRIVATE, fd, 0)) == MAP_FAILED ||
	    m == ખાલી) {
		error_f("mmap %s: %s", path, strerror(errno));
		જાઓ out;
	}
	જો (memmem(m, sz, s, strlen(s)) == ખાલી) {
		error_f("%s does not contain expected string %s", path, s);
		જાઓ out;
	}
	/* success */
	ret = 0;
 out:
	જો (m != ખાલી && m != MAP_FAILED)
		munmap(m, sz);
	close(fd);
	પાછા ret;
#endif /* HAVE_NLIST */
}

પૂર્ણાંક
signal_is_crash(પૂર્ણાંક sig)
{
	પસંદગી (sig) {
	સ્થિતિ SIGSEGV:
	સ્થિતિ SIGBUS:
	સ્થિતિ SIGTRAP:
	સ્થિતિ SIGSYS:
	સ્થિતિ SIGFPE:
	સ્થિતિ SIGILL:
	સ્થિતિ SIGABRT:
		પાછા 1;
	}
	પાછા 0;
}

અક્ષર *
get_homedir(શૂન્ય)
{
	અક્ષર *cp;
	સંરચના passwd *pw;

	જો ((cp = getenv("HOME")) != ખાલી && *cp != '\0')
		પાછા xstrdup(cp);

	જો ((pw = getpwuid(getuid())) != ખાલી && *pw->pw_dir != '\0')
		પાછા xstrdup(pw->pw_dir);

	પાછા ખાલી;
}

પૂર્ણાંક
mkdir_path(અચલ અક્ષર *target, mode_t mode)
{
#જો defined(HAVE_OPENAT) && defined(O_DIRECTORY)
	અક્ષર *dir, *odir = ખાલી, *next;
	પૂર્ણાંક fd = AT_FDCWD, fd2, subpath_len, ret = -1;

	dir = odir = xstrdup(target);

	જો (*dir == '/' &&
	    (fd = open("/", O_RDONLY|O_DIRECTORY)) == -1) {
		error_f("open(\"/\"): %s", strerror(errno));
		મુક્ત(odir);
		પાછા -1;
	}
	/* Work through the path, component-wise */
	માટે (; dir != ખાલી && *dir != '\0'; dir = next) {
		જો ((next = strchr(dir, '/')) != ખાલી)
			*(next++) = '\0';
		જો (*dir == '\0')
			ચાલુ;
		subpath_len = (next == ખાલી) ? INT_MAX : next - odir - 1;
		જો (mkdirat(fd, dir, mode) == 0)
			debug_f("created directory %.*s", subpath_len, target);
		નહીંતર જો (errno != EEXIST) {
			error_f("mkdir(\"%.*s\"): %s",
			    subpath_len, target, strerror(errno));
			જાઓ out;
		}

		/* descend */
		જો ((fd2 = openat(fd, dir, O_RDONLY|O_DIRECTORY)) == -1) {
			error_f("open(\"%.*s\"): %s",
			    subpath_len, target, strerror(errno));
			જાઓ out;
		}
		જો (fd != AT_FDCWD)
			close(fd);
		fd = fd2;
	}
	/* success */
	ret = 0;
 out:
	મુક્ત(odir);
	જો (fd != AT_FDCWD)
		close(fd);
	પાછા ret;
#નહીંતર
	/*
	 * If we don't have openat (which was added in POSIX.1-2008), fall back
	 * to the possibly racy way.
	 */
	અક્ષર *dir, *odir, *p, path[PATH_MAX] = "";
	પૂર્ણાંક ret = -1;
	size_t plen = કદ(path);

	dir = odir = xstrdup(target);

	/* If the dir is relative, start with cwd. */
	જો (*dir != '/' && getcwd(path, plen) == ખાલી) {
		error_f("getcwd: %s", strerror(errno));
		જાઓ out;
	}

	/* Work through the path, component-wise */
	જ્યારે ((p = strsep(&dir, "/"))) {
		જો (*p == '\0')
			ચાલુ;
		જો (strlcat(path, "/", plen) >= plen ||
		    strlcat(path, p, plen) >= plen)
			જાઓ out;
		જો (mkdir(path, mode) == 0)
			debug_f("created directory %s", path);
		નહીંતર જો (errno != EEXIST && errno != EISDIR) {
			error_f("mkdir(\"%s\"): %s", path, strerror(errno));
			જાઓ out;
		}
	}
	/* success */
	ret = 0;
 out:
	મુક્ત(odir);
	પાછા ret;
#endif
}
