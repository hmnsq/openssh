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


#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/ioctl.h>
#അന്തര്ഭാവ <sys/mman.h>
#അന്തര്ഭാവ <sys/socket.h>
#അന്തര്ഭാവ <sys/stat.h>
#അന്തര്ഭാവ <sys/time.h>
#അന്തര്ഭാവ <sys/wait.h>
#അന്തര്ഭാവ <sys/un.h>

#അന്തര്ഭാവ <limits.h>
#അന്തര്ഭാവ <libgen.h>
#അന്തര്ഭാവ <poll.h>
#അന്തര്ഭാവ <nlist.h>
#അന്തര്ഭാവ <signal.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdint.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <time.h>
#അന്തര്ഭാവ <unistd.h>

#അന്തര്ഭാവ <netinet/in.h>
#അന്തര്ഭാവ <netinet/ip.h>
#അന്തര്ഭാവ <netinet/tcp.h>
#അന്തര്ഭാവ <arpa/inet.h>

#അന്തര്ഭാവ <ctype.h>
#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <fcntl.h>
#അന്തര്ഭാവ <netdb.h>
#അന്തര്ഭാവ <paths.h>
#അന്തര്ഭാവ <pwd.h>
#അന്തര്ഭാവ <grp.h>
#ifdef SSH_TUN_OPENBSD
#അന്തര്ഭാവ <net/if.h>
#endif

#അന്തര്ഭാവ "xmalloc.h"
#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "ssh.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "platform.h"

/* remove newline at end of string */
അക്ഷരം *
chop(അക്ഷരം *s)
{
	അക്ഷരം *t = s;
	ആകുമ്പോൾ (*t) {
		എങ്കിൽ (*t == '\n' || *t == '\r') {
			*t = '\0';
			തിരികെ s;
		}
		t++;
	}
	തിരികെ s;

}

/* remove whitespace from end of string */
ശൂന്യം
rtrim(അക്ഷരം *s)
{
	size_t i;

	എങ്കിൽ ((i = strlen(s)) == 0)
		തിരികെ;
	ചെയ്യുക {
		i--;
		എങ്കിൽ (isspace((unsigned അക്ഷരം)s[i]))
			s[i] = '\0';
		അല്ലെങ്കിൽ
			നിർത്തുക;
	} ആകുമ്പോൾ (i > 0);
}

/*
 * returns pointer to character after 'prefix' in 's' or otherwise NULL
 * if the prefix is not present.
 */
സ്ഥിരം അക്ഷരം *
strprefix(സ്ഥിരം അക്ഷരം *s, സ്ഥിരം അക്ഷരം *prefix, പൂർണ്ണസംഖ്യ ignorecase)
{
	size_t prefixlen;

	എങ്കിൽ ((prefixlen = strlen(prefix)) == 0)
		തിരികെ s;
	എങ്കിൽ (ignorecase) {
		എങ്കിൽ (strncasecmp(s, prefix, prefixlen) != 0)
			തിരികെ ശൂന്യ;
	} അല്ലെങ്കിൽ {
		എങ്കിൽ (strncmp(s, prefix, prefixlen) != 0)
			തിരികെ ശൂന്യ;
	}
	തിരികെ s + prefixlen;
}

/* Append string 's' to a NULL-terminated array of strings */
ശൂന്യം
stringlist_append(അക്ഷരം ***listp, സ്ഥിരം അക്ഷരം *s)
{
	size_t i = 0;

	എങ്കിൽ (*listp == ശൂന്യ)
		*listp = xcalloc(2, വലുപ്പം(**listp));
	അല്ലെങ്കിൽ {
		വേണ്ടി (i = 0; (*listp)[i] != ശൂന്യ; i++)
			; /* count */
		*listp = xrecallocarray(*listp, i + 1, i + 2, വലുപ്പം(**listp));
	}
	(*listp)[i] = xstrdup(s);
}

ശൂന്യം
stringlist_free(അക്ഷരം **list)
{
	size_t i = 0;

	എങ്കിൽ (list == ശൂന്യ)
		തിരികെ;
	വേണ്ടി (i = 0; list[i] != ശൂന്യ; i++)
		സ്വതന്ത്രം(list[i]);
	സ്വതന്ത്രം(list);
}

/* set/unset filedescriptor to non-blocking */
പൂർണ്ണസംഖ്യ
set_nonblock(പൂർണ്ണസംഖ്യ fd)
{
	പൂർണ്ണസംഖ്യ val;

	val = fcntl(fd, F_GETFL);
	എങ്കിൽ (val == -1) {
		error("fcntl(%d, F_GETFL): %s", fd, strerror(errno));
		തിരികെ (-1);
	}
	എങ്കിൽ (val & O_NONBLOCK) {
		debug3("fd %d is O_NONBLOCK", fd);
		തിരികെ (0);
	}
	debug2("fd %d setting O_NONBLOCK", fd);
	val |= O_NONBLOCK;
	എങ്കിൽ (fcntl(fd, F_SETFL, val) == -1) {
		debug("fcntl(%d, F_SETFL, O_NONBLOCK): %s", fd,
		    strerror(errno));
		തിരികെ (-1);
	}
	തിരികെ (0);
}

പൂർണ്ണസംഖ്യ
unset_nonblock(പൂർണ്ണസംഖ്യ fd)
{
	പൂർണ്ണസംഖ്യ val;

	val = fcntl(fd, F_GETFL);
	എങ്കിൽ (val == -1) {
		error("fcntl(%d, F_GETFL): %s", fd, strerror(errno));
		തിരികെ (-1);
	}
	എങ്കിൽ (!(val & O_NONBLOCK)) {
		debug3("fd %d is not O_NONBLOCK", fd);
		തിരികെ (0);
	}
	debug("fd %d clearing O_NONBLOCK", fd);
	val &= ~O_NONBLOCK;
	എങ്കിൽ (fcntl(fd, F_SETFL, val) == -1) {
		debug("fcntl(%d, F_SETFL, ~O_NONBLOCK): %s",
		    fd, strerror(errno));
		തിരികെ (-1);
	}
	തിരികെ (0);
}

സ്ഥിരം അക്ഷരം *
ssh_gai_strerror(പൂർണ്ണസംഖ്യ gaierr)
{
	എങ്കിൽ (gaierr == EAI_SYSTEM && errno != 0)
		തിരികെ strerror(errno);
	തിരികെ gai_strerror(gaierr);
}

/* disable nagle on socket */
ശൂന്യം
set_nodelay(പൂർണ്ണസംഖ്യ fd)
{
	പൂർണ്ണസംഖ്യ opt;
	socklen_t optlen;

	optlen = വലുപ്പം opt;
	എങ്കിൽ (getsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, &optlen) == -1) {
		debug("getsockopt TCP_NODELAY: %.100s", strerror(errno));
		തിരികെ;
	}
	എങ്കിൽ (opt == 1) {
		debug2("fd %d is TCP_NODELAY", fd);
		തിരികെ;
	}
	opt = 1;
	debug2("fd %d setting TCP_NODELAY", fd);
	എങ്കിൽ (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, വലുപ്പം opt) == -1)
		error("setsockopt TCP_NODELAY: %.100s", strerror(errno));
}

/* Allow local port reuse in TIME_WAIT */
പൂർണ്ണസംഖ്യ
set_reuseaddr(പൂർണ്ണസംഖ്യ fd)
{
	പൂർണ്ണസംഖ്യ on = 1;

	എങ്കിൽ (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, വലുപ്പം(on)) == -1) {
		error("setsockopt SO_REUSEADDR fd %d: %s", fd, strerror(errno));
		തിരികെ -1;
	}
	തിരികെ 0;
}

/* Set TCP keepalives */
പൂർണ്ണസംഖ്യ
set_keepalive(പൂർണ്ണസംഖ്യ fd)
{
	പൂർണ്ണസംഖ്യ on = 1;

	എങ്കിൽ (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, വലുപ്പം(on)) == -1) {
		error("setsockopt SO_KEEPALIVE fd %d: %s", fd, strerror(errno));
		തിരികെ -1;
	}
	തിരികെ 0;
}

/* Get/set routing domain */
അക്ഷരം *
get_rdomain(പൂർണ്ണസംഖ്യ fd)
{
#എങ്കിൽ defined(HAVE_SYS_GET_RDOMAIN)
	തിരികെ sys_get_rdomain(fd);
#അല്ലെങ്കിലെങ്കിൽ defined(__OpenBSD__)
	പൂർണ്ണസംഖ്യ rtable;
	അക്ഷരം *ret;
	socklen_t len = വലുപ്പം(rtable);

	എങ്കിൽ (getsockopt(fd, SOL_SOCKET, SO_RTABLE, &rtable, &len) == -1) {
		error("Failed to get routing domain for fd %d: %s",
		    fd, strerror(errno));
		തിരികെ ശൂന്യ;
	}
	xasprintf(&ret, "%d", rtable);
	തിരികെ ret;
#അല്ലെങ്കിൽ /* defined(__OpenBSD__) */
	തിരികെ ശൂന്യ;
#endif
}

പൂർണ്ണസംഖ്യ
set_rdomain(പൂർണ്ണസംഖ്യ fd, സ്ഥിരം അക്ഷരം *name)
{
#എങ്കിൽ defined(HAVE_SYS_SET_RDOMAIN)
	തിരികെ sys_set_rdomain(fd, name);
#അല്ലെങ്കിലെങ്കിൽ defined(__OpenBSD__)
	പൂർണ്ണസംഖ്യ rtable;
	സ്ഥിരം അക്ഷരം *errstr;

	എങ്കിൽ (name == ശൂന്യ)
		തിരികെ 0; /* default table */

	rtable = (പൂർണ്ണസംഖ്യ)strtonum(name, 0, 255, &errstr);
	എങ്കിൽ (errstr != ശൂന്യ) {
		/* Shouldn't happen */
		error("Invalid routing domain \"%s\": %s", name, errstr);
		തിരികെ -1;
	}
	എങ്കിൽ (setsockopt(fd, SOL_SOCKET, SO_RTABLE,
	    &rtable, വലുപ്പം(rtable)) == -1) {
		error("Failed to set routing domain %d on fd %d: %s",
		    rtable, fd, strerror(errno));
		തിരികെ -1;
	}
	തിരികെ 0;
#അല്ലെങ്കിൽ /* defined(__OpenBSD__) */
	error("Setting routing domain is not supported on this platform");
	തിരികെ -1;
#endif
}

പൂർണ്ണസംഖ്യ
get_sock_af(പൂർണ്ണസംഖ്യ fd)
{
	ഘടന sockaddr_storage to;
	socklen_t tolen = വലുപ്പം(to);

	memset(&to, 0, വലുപ്പം(to));
	എങ്കിൽ (getsockname(fd, (ഘടന sockaddr *)&to, &tolen) == -1)
		തിരികെ -1;
#ifdef IPV4_IN_IPV6
	എങ്കിൽ (to.ss_family == AF_INET6 &&
	    IN6_IS_ADDR_V4MAPPED(&((ഘടന sockaddr_in6 *)&to)->sin6_addr))
		തിരികെ AF_INET;
#endif
	തിരികെ to.ss_family;
}

ശൂന്യം
set_sock_tos(പൂർണ്ണസംഖ്യ fd, പൂർണ്ണസംഖ്യ tos)
{
#ifndef IP_TOS_IS_BROKEN
	പൂർണ്ണസംഖ്യ af;

	എങ്കിൽ (tos < 0 || tos == INT_MAX) {
		debug_f("invalid TOS %d", tos);
		തിരികെ;
	}
	തിരഞ്ഞെടുപ്പ് ((af = get_sock_af(fd))) {
	അവസ്ഥ -1:
		/* assume not a socket */
		നിർത്തുക;
	അവസ്ഥ AF_INET:
# ifdef IP_TOS
		debug3_f("set socket %d IP_TOS 0x%02x", fd, tos);
		എങ്കിൽ (setsockopt(fd, IPPROTO_IP, IP_TOS,
		    &tos, വലുപ്പം(tos)) == -1) {
			error("setsockopt socket %d IP_TOS %d: %s",
			    fd, tos, strerror(errno));
		}
# endif /* IP_TOS */
		നിർത്തുക;
	അവസ്ഥ AF_INET6:
# ifdef IPV6_TCLASS
		debug3_f("set socket %d IPV6_TCLASS 0x%02x", fd, tos);
		എങ്കിൽ (setsockopt(fd, IPPROTO_IPV6, IPV6_TCLASS,
		    &tos, വലുപ്പം(tos)) == -1) {
			error("setsockopt socket %d IPV6_TCLASS %d: %s",
			    fd, tos, strerror(errno));
		}
# endif /* IPV6_TCLASS */
		നിർത്തുക;
	സ്ഥിരസ്ഥിതി:
		debug2_f("unsupported socket family %d", af);
		നിർത്തുക;
	}
#endif /* IP_TOS_IS_BROKEN */
}

/*
 * Wait up to *timeoutp milliseconds for events on fd. Updates
 * *timeoutp with time remaining.
 * Returns 0 if fd ready or -1 on timeout or error (see errno).
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
waitfd(പൂർണ്ണസംഖ്യ fd, പൂർണ്ണസംഖ്യ *timeoutp, short events, അസ്ഥിര sig_atomic_t *stop)
{
	ഘടന pollfd pfd;
	ഘടന timespec timeout;
	പൂർണ്ണസംഖ്യ oerrno, r;
	sigset_t nsigset, osigset;

	എങ്കിൽ (timeoutp && *timeoutp == -1)
		timeoutp = ശൂന്യ;
	pfd.fd = fd;
	pfd.events = events;
	ptimeout_init(&timeout);
	എങ്കിൽ (timeoutp != ശൂന്യ)
		ptimeout_deadline_ms(&timeout, *timeoutp);
	എങ്കിൽ (stop != ശൂന്യ)
		sigfillset(&nsigset);
	വേണ്ടി (; timeoutp == ശൂന്യ || *timeoutp >= 0;) {
		എങ്കിൽ (stop != ശൂന്യ) {
			sigprocmask(SIG_BLOCK, &nsigset, &osigset);
			എങ്കിൽ (*stop) {
				sigprocmask(SIG_SETMASK, &osigset, ശൂന്യ);
				errno = EINTR;
				തിരികെ -1;
			}
		}
		r = ppoll(&pfd, 1, ptimeout_get_tsp(&timeout),
		    stop != ശൂന്യ ? &osigset : ശൂന്യ);
		oerrno = errno;
		എങ്കിൽ (stop != ശൂന്യ)
			sigprocmask(SIG_SETMASK, &osigset, ശൂന്യ);
		എങ്കിൽ (timeoutp)
			*timeoutp = ptimeout_get_ms(&timeout);
		errno = oerrno;
		എങ്കിൽ (r > 0)
			തിരികെ 0;
		അല്ലെങ്കിൽ എങ്കിൽ (r == -1 && errno != EAGAIN && errno != EINTR)
			തിരികെ -1;
		അല്ലെങ്കിൽ എങ്കിൽ (r == 0)
			നിർത്തുക;
	}
	/* timeout */
	errno = ETIMEDOUT;
	തിരികെ -1;
}

/*
 * Wait up to *timeoutp milliseconds for fd to be readable. Updates
 * *timeoutp with time remaining.
 * Returns 0 if fd ready or -1 on timeout or error (see errno).
 */
പൂർണ്ണസംഖ്യ
waitrfd(പൂർണ്ണസംഖ്യ fd, പൂർണ്ണസംഖ്യ *timeoutp, അസ്ഥിര sig_atomic_t *stop) {
	തിരികെ waitfd(fd, timeoutp, POLLIN, stop);
}

/*
 * Attempt a non-blocking connect(2) to the specified address, waiting up to
 * *timeoutp milliseconds for the connection to complete. If the timeout is
 * <=0, then wait indefinitely.
 *
 * Returns 0 on success or -1 on failure.
 */
പൂർണ്ണസംഖ്യ
timeout_connect(പൂർണ്ണസംഖ്യ sockfd, സ്ഥിരം ഘടന sockaddr *serv_addr,
    socklen_t addrlen, പൂർണ്ണസംഖ്യ *timeoutp)
{
	പൂർണ്ണസംഖ്യ optval = 0;
	socklen_t optlen = വലുപ്പം(optval);

	/* No timeout: just do a blocking connect() */
	എങ്കിൽ (timeoutp == ശൂന്യ || *timeoutp <= 0)
		തിരികെ connect(sockfd, serv_addr, addrlen);

	set_nonblock(sockfd);
	വേണ്ടി (;;) {
		എങ്കിൽ (connect(sockfd, serv_addr, addrlen) == 0) {
			/* Succeeded already? */
			unset_nonblock(sockfd);
			തിരികെ 0;
		} അല്ലെങ്കിൽ എങ്കിൽ (errno == EINTR)
			തുടരുക;
		അല്ലെങ്കിൽ എങ്കിൽ (errno != EINPROGRESS)
			തിരികെ -1;
		നിർത്തുക;
	}

	എങ്കിൽ (waitfd(sockfd, timeoutp, POLLIN | POLLOUT, ശൂന്യ) == -1)
		തിരികെ -1;

	/* Completed or failed */
	എങ്കിൽ (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &optval, &optlen) == -1) {
		debug("getsockopt: %s", strerror(errno));
		തിരികെ -1;
	}
	എങ്കിൽ (optval != 0) {
		errno = optval;
		തിരികെ -1;
	}
	unset_nonblock(sockfd);
	തിരികെ 0;
}

/* Characters considered whitespace in strsep calls. */
#define WHITESPACE " \t\r\n"
#define QUOTE	"\""

/* return next token in configuration line */
സ്ഥിതം അക്ഷരം *
strdelim_internal(അക്ഷരം **s, പൂർണ്ണസംഖ്യ split_equals)
{
	അക്ഷരം *old;
	പൂർണ്ണസംഖ്യ wspace = 0;

	എങ്കിൽ (*s == ശൂന്യ)
		തിരികെ ശൂന്യ;

	old = *s;

	*s = strpbrk(*s,
	    split_equals ? WHITESPACE QUOTE "=" : WHITESPACE QUOTE);
	എങ്കിൽ (*s == ശൂന്യ)
		തിരികെ (old);

	എങ്കിൽ (*s[0] == '\"') {
		memmove(*s, *s + 1, strlen(*s)); /* move nul too */
		/* Find matching quote */
		എങ്കിൽ ((*s = strpbrk(*s, QUOTE)) == ശൂന്യ) {
			തിരികെ (ശൂന്യ);		/* no matching quote */
		} അല്ലെങ്കിൽ {
			*s[0] = '\0';
			*s += strspn(*s + 1, WHITESPACE) + 1;
			തിരികെ (old);
		}
	}

	/* Allow only one '=' to be skipped */
	എങ്കിൽ (split_equals && *s[0] == '=')
		wspace = 1;
	*s[0] = '\0';

	/* Skip any extra whitespace after first token */
	*s += strspn(*s + 1, WHITESPACE) + 1;
	എങ്കിൽ (split_equals && *s[0] == '=' && !wspace)
		*s += strspn(*s + 1, WHITESPACE) + 1;

	തിരികെ (old);
}

/*
 * Return next token in configuration line; splits on whitespace or a
 * single '=' character.
 */
അക്ഷരം *
strdelim(അക്ഷരം **s)
{
	തിരികെ strdelim_internal(s, 1);
}

/*
 * Return next token in configuration line; splits on whitespace only.
 */
അക്ഷരം *
strdelimw(അക്ഷരം **s)
{
	തിരികെ strdelim_internal(s, 0);
}

ഘടന passwd *
pwcopy(ഘടന passwd *pw)
{
	ഘടന passwd *copy = xcalloc(1, വലുപ്പം(*copy));

	copy->pw_name = xstrdup(pw->pw_name);
	copy->pw_passwd = xstrdup(pw->pw_passwd == ശൂന്യ ? "*" : pw->pw_passwd);
#ifdef HAVE_STRUCT_PASSWD_PW_GECOS
	copy->pw_gecos = xstrdup(pw->pw_gecos == ശൂന്യ ? "" : pw->pw_gecos);
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
	copy->pw_class = xstrdup(pw->pw_class == ശൂന്യ ? "" : pw->pw_class);
#endif
	copy->pw_dir = xstrdup(pw->pw_dir == ശൂന്യ ? "" : pw->pw_dir);
	copy->pw_shell = xstrdup(pw->pw_shell == ശൂന്യ ? "" : pw->pw_shell);
	തിരികെ copy;
}

ശൂന്യം
pwfree(ഘടന passwd *pw)
{
	എങ്കിൽ (pw == ശൂന്യ)
		തിരികെ;
	സ്വതന്ത്രം(pw->pw_name);
	freezero(pw->pw_passwd,
	    pw->pw_passwd == ശൂന്യ ? 0 : strlen(pw->pw_passwd));
#ifdef HAVE_STRUCT_PASSWD_PW_GECOS
	സ്വതന്ത്രം(pw->pw_gecos);
#endif
#ifdef HAVE_STRUCT_PASSWD_PW_CLASS
	സ്വതന്ത്രം(pw->pw_class);
#endif
	സ്വതന്ത്രം(pw->pw_dir);
	സ്വതന്ത്രം(pw->pw_shell);
	freezero(pw, വലുപ്പം(*pw));
}

/*
 * Convert ASCII string to TCP/IP port number.
 * Port must be >=0 and <=65535.
 * Return -1 if invalid.
 */
പൂർണ്ണസംഖ്യ
a2port(സ്ഥിരം അക്ഷരം *s)
{
	ഘടന servent *se;
	long long port;
	സ്ഥിരം അക്ഷരം *errstr;

	port = strtonum(s, 0, 65535, &errstr);
	എങ്കിൽ (errstr == ശൂന്യ)
		തിരികെ (പൂർണ്ണസംഖ്യ)port;
	എങ്കിൽ ((se = getservbyname(s, "tcp")) != ശൂന്യ)
		തിരികെ ntohs(se->s_port);
	തിരികെ -1;
}

പൂർണ്ണസംഖ്യ
a2tun(സ്ഥിരം അക്ഷരം *s, പൂർണ്ണസംഖ്യ *remote)
{
	സ്ഥിരം അക്ഷരം *errstr = ശൂന്യ;
	അക്ഷരം *sp, *ep;
	പൂർണ്ണസംഖ്യ tun;

	എങ്കിൽ (remote != ശൂന്യ) {
		*remote = SSH_TUNID_ANY;
		sp = xstrdup(s);
		എങ്കിൽ ((ep = strchr(sp, ':')) == ശൂന്യ) {
			സ്വതന്ത്രം(sp);
			തിരികെ (a2tun(s, ശൂന്യ));
		}
		ep[0] = '\0'; ep++;
		*remote = a2tun(ep, ശൂന്യ);
		tun = a2tun(sp, ശൂന്യ);
		സ്വതന്ത്രം(sp);
		തിരികെ (*remote == SSH_TUNID_ERR ? *remote : tun);
	}

	എങ്കിൽ (strcasecmp(s, "any") == 0)
		തിരികെ (SSH_TUNID_ANY);

	tun = strtonum(s, 0, SSH_TUNID_MAX, &errstr);
	എങ്കിൽ (errstr != ശൂന്യ)
		തിരികെ (SSH_TUNID_ERR);

	തിരികെ (tun);
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
ഇരട്ട
convtime_double(സ്ഥിരം അക്ഷരം *s)
{
	ഇരട്ട val, total_sec = 0.0, multiplier;
	സ്ഥിരം അക്ഷരം *p, *start_p;
	അക്ഷരം *endp;
	പൂർണ്ണസംഖ്യ seen_seconds = 0;

	എങ്കിൽ (s == ശൂന്യ || *s == '\0')
		തിരികെ -1.0;

	വേണ്ടി (p = s; *p != '\0';) {
		എങ്കിൽ (!isdigit((unsigned അക്ഷരം)*p) && *p != '.')
			തിരികെ -1.0;

		errno = 0;
		എങ്കിൽ ((val = strtod(p, &endp)) < 0 || errno != 0 || p == endp)
			തിരികെ -1.0;
		/* Allow only decimal forms */
		എങ്കിൽ (p + strspn(p, "0123456789.") != endp)
			തിരികെ -1.0;
		start_p = p;
		p = endp;

		തിരഞ്ഞെടുപ്പ് (*p) {
		അവസ്ഥ '\0':
			/* FALLTHROUGH */
		അവസ്ഥ 's':
		അവസ്ഥ 'S':
			എങ്കിൽ (seen_seconds++)
				തിരികെ -1.0;
			multiplier = SECONDS;
			നിർത്തുക;
		അവസ്ഥ 'm':
		അവസ്ഥ 'M':
			multiplier = MINUTES;
			നിർത്തുക;
		അവസ്ഥ 'h':
		അവസ്ഥ 'H':
			multiplier = HOURS;
			നിർത്തുക;
		അവസ്ഥ 'd':
		അവസ്ഥ 'D':
			multiplier = DAYS;
			നിർത്തുക;
		അവസ്ഥ 'w':
		അവസ്ഥ 'W':
			multiplier = WEEKS;
			നിർത്തുക;
		സ്ഥിരസ്ഥിതി:
			തിരികെ -1.0;
		}

		/* Special handling if this was a decimal */
		എങ്കിൽ (memchr(start_p, '.', endp - start_p) != ശൂന്യ) {
			/* Decimal point present */
			എങ്കിൽ (multiplier > 1.0)
				തിരികെ -1.0; /* No fractionals for non-seconds */
			/* For seconds, ensure digits follow */
			എങ്കിൽ (!isdigit((unsigned അക്ഷരം)*(endp - 1)))
				തിരികെ -1.0;
		}

		total_sec += val * multiplier;

		എങ്കിൽ (*p != '\0')
			p++;
	}
	തിരികെ total_sec;
}

/*
 * Same as convtime_double() above but fractional seconds are ignored.
 * Return -1 if time string is invalid.
 */
പൂർണ്ണസംഖ്യ
convtime(സ്ഥിരം അക്ഷരം *s)
{
	ഇരട്ട sec_val;

	എങ്കിൽ ((sec_val = convtime_double(s)) < 0.0)
		തിരികെ -1;

	/* Check for overflow into int */
	എങ്കിൽ (sec_val < 0 || sec_val > INT_MAX)
		തിരികെ -1;

	തിരികെ (പൂർണ്ണസംഖ്യ)sec_val;
}

#define TF_BUFS	8
#define TF_LEN	9

സ്ഥിരം അക്ഷരം *
fmt_timeframe(time_t t)
{
	അക്ഷരം		*buf;
	സ്ഥിതം അക്ഷരം	 tfbuf[TF_BUFS][TF_LEN];	/* ring buffer */
	സ്ഥിതം പൂർണ്ണസംഖ്യ	 idx = 0;
	unsigned പൂർണ്ണസംഖ്യ	 sec, min, hrs, day;
	unsigned long long	week;

	buf = tfbuf[idx++];
	എങ്കിൽ (idx == TF_BUFS)
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

	എങ്കിൽ (week > 0)
		snprintf(buf, TF_LEN, "%02lluw%01ud%02uh", week, day, hrs);
	അല്ലെങ്കിൽ എങ്കിൽ (day > 0)
		snprintf(buf, TF_LEN, "%01ud%02uh%02um", day, hrs, min);
	അല്ലെങ്കിൽ
		snprintf(buf, TF_LEN, "%02u:%02u:%02u", hrs, min, sec);

	തിരികെ (buf);
}

/*
 * Returns a standardized host+port identifier string.
 * Caller must free returned string.
 */
അക്ഷരം *
put_host_port(സ്ഥിരം അക്ഷരം *host, u_short port)
{
	അക്ഷരം *hoststr;

	എങ്കിൽ (port == 0 || port == SSH_DEFAULT_PORT)
		തിരികെ(xstrdup(host));
	എങ്കിൽ (asprintf(&hoststr, "[%s]:%d", host, (പൂർണ്ണസംഖ്യ)port) == -1)
		fatal("put_host_port: asprintf: %s", strerror(errno));
	debug3("put_host_port: %s", hoststr);
	തിരികെ hoststr;
}

/*
 * Search for next delimiter between hostnames/addresses and ports.
 * Argument may be modified (for termination).
 * Returns *cp if parsing succeeds.
 * *cp is set to the start of the next field, if one was found.
 * The delimiter char, if present, is stored in delim.
 * If this is the last field, *cp is set to NULL.
 */
അക്ഷരം *
hpdelim2(അക്ഷരം **cp, അക്ഷരം *delim)
{
	അക്ഷരം *s, *old;

	എങ്കിൽ (cp == ശൂന്യ || *cp == ശൂന്യ)
		തിരികെ ശൂന്യ;

	old = s = *cp;
	എങ്കിൽ (*s == '[') {
		എങ്കിൽ ((s = strchr(s, ']')) == ശൂന്യ)
			തിരികെ ശൂന്യ;
		അല്ലെങ്കിൽ
			s++;
	} അല്ലെങ്കിൽ എങ്കിൽ ((s = strpbrk(s, ":/")) == ശൂന്യ)
		s = *cp + strlen(*cp); /* skip to end (see first case below) */

	തിരഞ്ഞെടുപ്പ് (*s) {
	അവസ്ഥ '\0':
		*cp = ശൂന്യ;	/* no more fields*/
		നിർത്തുക;

	അവസ്ഥ ':':
	അവസ്ഥ '/':
		എങ്കിൽ (delim != ശൂന്യ)
			*delim = *s;
		*s = '\0';	/* terminate */
		*cp = s + 1;
		നിർത്തുക;

	സ്ഥിരസ്ഥിതി:
		തിരികെ ശൂന്യ;
	}

	തിരികെ old;
}

/* The common case: only accept colon as delimiter. */
അക്ഷരം *
hpdelim(അക്ഷരം **cp)
{
	അക്ഷരം *r, delim = '\0';

	r =  hpdelim2(cp, &delim);
	എങ്കിൽ (delim == '/')
		തിരികെ ശൂന്യ;
	തിരികെ r;
}

അക്ഷരം *
cleanhostname(അക്ഷരം *host)
{
	എങ്കിൽ (*host == '[' && host[strlen(host) - 1] == ']') {
		host[strlen(host) - 1] = '\0';
		തിരികെ (host + 1);
	} അല്ലെങ്കിൽ
		തിരികെ host;
}

അക്ഷരം *
colon(അക്ഷരം *cp)
{
	പൂർണ്ണസംഖ്യ flag = 0;

	എങ്കിൽ (*cp == ':')		/* Leading colon is part of file name. */
		തിരികെ ശൂന്യ;
	എങ്കിൽ (*cp == '[')
		flag = 1;

	വേണ്ടി (; *cp; ++cp) {
		എങ്കിൽ (*cp == '@' && *(cp+1) == '[')
			flag = 1;
		എങ്കിൽ (*cp == ']' && *(cp+1) == ':' && flag)
			തിരികെ (cp+1);
		എങ്കിൽ (*cp == ':' && !flag)
			തിരികെ (cp);
		എങ്കിൽ (*cp == '/')
			തിരികെ ശൂന്യ;
	}
	തിരികെ ശൂന്യ;
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
പൂർണ്ണസംഖ്യ
parse_user_host_path(സ്ഥിരം അക്ഷരം *s, അക്ഷരം **userp, അക്ഷരം **hostp, അക്ഷരം **pathp)
{
	അക്ഷരം *user = ശൂന്യ, *host = ശൂന്യ, *path = ശൂന്യ;
	അക്ഷരം *sdup, *tmp;
	പൂർണ്ണസംഖ്യ ret = -1;

	എങ്കിൽ (userp != ശൂന്യ)
		*userp = ശൂന്യ;
	എങ്കിൽ (hostp != ശൂന്യ)
		*hostp = ശൂന്യ;
	എങ്കിൽ (pathp != ശൂന്യ)
		*pathp = ശൂന്യ;

	sdup = xstrdup(s);

	/* Check for remote syntax: [user@]host:[path] */
	എങ്കിൽ ((tmp = colon(sdup)) == ശൂന്യ)
		പോകുക out;

	/* Extract optional path */
	*tmp++ = '\0';
	എങ്കിൽ (*tmp == '\0')
		tmp = ".";
	path = xstrdup(tmp);

	/* Extract optional user and mandatory host */
	tmp = strrchr(sdup, '@');
	എങ്കിൽ (tmp != ശൂന്യ) {
		*tmp++ = '\0';
		host = xstrdup(cleanhostname(tmp));
		എങ്കിൽ (*sdup != '\0')
			user = xstrdup(sdup);
	} അല്ലെങ്കിൽ {
		host = xstrdup(cleanhostname(sdup));
		user = ശൂന്യ;
	}

	/* Success */
	എങ്കിൽ (userp != ശൂന്യ) {
		*userp = user;
		user = ശൂന്യ;
	}
	എങ്കിൽ (hostp != ശൂന്യ) {
		*hostp = host;
		host = ശൂന്യ;
	}
	എങ്കിൽ (pathp != ശൂന്യ) {
		*pathp = path;
		path = ശൂന്യ;
	}
	ret = 0;
out:
	സ്വതന്ത്രം(sdup);
	സ്വതന്ത്രം(user);
	സ്വതന്ത്രം(host);
	സ്വതന്ത്രം(path);
	തിരികെ ret;
}

/*
 * Parse a [user@]host[:port] string.
 * Caller must free returned user and host.
 * Any of the pointer return arguments may be NULL (useful for syntax checking).
 * If user was not specified then *userp will be set to NULL.
 * If port was not specified then *portp will be -1.
 * Returns 0 on success, -1 on failure.
 */
പൂർണ്ണസംഖ്യ
parse_user_host_port(സ്ഥിരം അക്ഷരം *s, അക്ഷരം **userp, അക്ഷരം **hostp, പൂർണ്ണസംഖ്യ *portp)
{
	അക്ഷരം *sdup, *cp, *tmp;
	അക്ഷരം *user = ശൂന്യ, *host = ശൂന്യ;
	പൂർണ്ണസംഖ്യ port = -1, ret = -1;

	എങ്കിൽ (userp != ശൂന്യ)
		*userp = ശൂന്യ;
	എങ്കിൽ (hostp != ശൂന്യ)
		*hostp = ശൂന്യ;
	എങ്കിൽ (portp != ശൂന്യ)
		*portp = -1;

	എങ്കിൽ ((sdup = tmp = strdup(s)) == ശൂന്യ)
		തിരികെ -1;
	/* Extract optional username */
	എങ്കിൽ ((cp = strrchr(tmp, '@')) != ശൂന്യ) {
		*cp = '\0';
		എങ്കിൽ (*tmp == '\0')
			പോകുക out;
		എങ്കിൽ ((user = strdup(tmp)) == ശൂന്യ)
			പോകുക out;
		tmp = cp + 1;
	}
	/* Extract mandatory hostname */
	എങ്കിൽ ((cp = hpdelim(&tmp)) == ശൂന്യ || *cp == '\0')
		പോകുക out;
	host = xstrdup(cleanhostname(cp));
	/* Convert and verify optional port */
	എങ്കിൽ (tmp != ശൂന്യ && *tmp != '\0') {
		എങ്കിൽ ((port = a2port(tmp)) <= 0)
			പോകുക out;
	}
	/* Success */
	എങ്കിൽ (userp != ശൂന്യ) {
		*userp = user;
		user = ശൂന്യ;
	}
	എങ്കിൽ (hostp != ശൂന്യ) {
		*hostp = host;
		host = ശൂന്യ;
	}
	എങ്കിൽ (portp != ശൂന്യ)
		*portp = port;
	ret = 0;
 out:
	സ്വതന്ത്രം(sdup);
	സ്വതന്ത്രം(user);
	സ്വതന്ത്രം(host);
	തിരികെ ret;
}

/*
 * Converts a two-byte hex string to decimal.
 * Returns the decimal value or -1 for invalid input.
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
hexchar(സ്ഥിരം അക്ഷരം *s)
{
	unsigned അക്ഷരം result[2];
	പൂർണ്ണസംഖ്യ i;

	വേണ്ടി (i = 0; i < 2; i++) {
		എങ്കിൽ (s[i] >= '0' && s[i] <= '9')
			result[i] = (unsigned അക്ഷരം)(s[i] - '0');
		അല്ലെങ്കിൽ എങ്കിൽ (s[i] >= 'a' && s[i] <= 'f')
			result[i] = (unsigned അക്ഷരം)(s[i] - 'a') + 10;
		അല്ലെങ്കിൽ എങ്കിൽ (s[i] >= 'A' && s[i] <= 'F')
			result[i] = (unsigned അക്ഷരം)(s[i] - 'A') + 10;
		അല്ലെങ്കിൽ
			തിരികെ -1;
	}
	തിരികെ (result[0] << 4) | result[1];
}

/*
 * Decode an url-encoded string.
 * Returns a newly allocated string on success or NULL on failure.
 */
സ്ഥിതം അക്ഷരം *
urldecode(സ്ഥിരം അക്ഷരം *src)
{
	അക്ഷരം *ret, *dst;
	പൂർണ്ണസംഖ്യ ch;
	size_t srclen;

	എങ്കിൽ ((srclen = strlen(src)) >= SIZE_MAX)
		തിരികെ ശൂന്യ;
	ret = xmalloc(srclen + 1);
	വേണ്ടി (dst = ret; *src != '\0'; src++) {
		തിരഞ്ഞെടുപ്പ് (*src) {
		അവസ്ഥ '+':
			*dst++ = ' ';
			നിർത്തുക;
		അവസ്ഥ '%':
			/* note: don't allow \0 characters */
			എങ്കിൽ (!isxdigit((unsigned അക്ഷരം)src[1]) ||
			    !isxdigit((unsigned അക്ഷരം)src[2]) ||
			    (ch = hexchar(src + 1)) == -1 || ch == 0) {
				സ്വതന്ത്രം(ret);
				തിരികെ ശൂന്യ;
			}
			*dst++ = ch;
			src += 2;
			നിർത്തുക;
		സ്ഥിരസ്ഥിതി:
			*dst++ = *src;
			നിർത്തുക;
		}
	}
	*dst = '\0';

	തിരികെ ret;
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
പൂർണ്ണസംഖ്യ
parse_uri(സ്ഥിരം അക്ഷരം *scheme, സ്ഥിരം അക്ഷരം *uri, അക്ഷരം **userp, അക്ഷരം **hostp,
    പൂർണ്ണസംഖ്യ *portp, അക്ഷരം **pathp)
{
	അക്ഷരം *uridup, *cp, *tmp, ch;
	അക്ഷരം *user = ശൂന്യ, *host = ശൂന്യ, *path = ശൂന്യ;
	പൂർണ്ണസംഖ്യ port = -1, ret = -1;
	size_t len;

	len = strlen(scheme);
	എങ്കിൽ (strncmp(uri, scheme, len) != 0 || strncmp(uri + len, "://", 3) != 0)
		തിരികെ 1;
	uri += len + 3;

	എങ്കിൽ (userp != ശൂന്യ)
		*userp = ശൂന്യ;
	എങ്കിൽ (hostp != ശൂന്യ)
		*hostp = ശൂന്യ;
	എങ്കിൽ (portp != ശൂന്യ)
		*portp = -1;
	എങ്കിൽ (pathp != ശൂന്യ)
		*pathp = ശൂന്യ;

	uridup = tmp = xstrdup(uri);

	/* Extract optional ssh-info (username + connection params) */
	എങ്കിൽ ((cp = strchr(tmp, '@')) != ശൂന്യ) {
		അക്ഷരം *delim;

		*cp = '\0';
		/* Extract username and connection params */
		എങ്കിൽ ((delim = strchr(tmp, ';')) != ശൂന്യ) {
			/* Just ignore connection params for now */
			*delim = '\0';
		}
		എങ്കിൽ (*tmp == '\0') {
			/* Empty username */
			പോകുക out;
		}
		എങ്കിൽ ((user = urldecode(tmp)) == ശൂന്യ)
			പോകുക out;
		tmp = cp + 1;
	}

	/* Extract mandatory hostname */
	എങ്കിൽ ((cp = hpdelim2(&tmp, &ch)) == ശൂന്യ || *cp == '\0')
		പോകുക out;
	host = xstrdup(cleanhostname(cp));
	എങ്കിൽ (!valid_domain(host, 0, ശൂന്യ))
		പോകുക out;

	എങ്കിൽ (tmp != ശൂന്യ && *tmp != '\0') {
		എങ്കിൽ (ch == ':') {
			/* Convert and verify port. */
			എങ്കിൽ ((cp = strchr(tmp, '/')) != ശൂന്യ)
				*cp = '\0';
			എങ്കിൽ ((port = a2port(tmp)) <= 0)
				പോകുക out;
			tmp = cp ? cp + 1 : ശൂന്യ;
		}
		എങ്കിൽ (tmp != ശൂന്യ && *tmp != '\0') {
			/* Extract optional path */
			എങ്കിൽ ((path = urldecode(tmp)) == ശൂന്യ)
				പോകുക out;
		}
	}

	/* Success */
	എങ്കിൽ (userp != ശൂന്യ) {
		*userp = user;
		user = ശൂന്യ;
	}
	എങ്കിൽ (hostp != ശൂന്യ) {
		*hostp = host;
		host = ശൂന്യ;
	}
	എങ്കിൽ (portp != ശൂന്യ)
		*portp = port;
	എങ്കിൽ (pathp != ശൂന്യ) {
		*pathp = path;
		path = ശൂന്യ;
	}
	ret = 0;
 out:
	സ്വതന്ത്രം(uridup);
	സ്വതന്ത്രം(user);
	സ്വതന്ത്രം(host);
	സ്വതന്ത്രം(path);
	തിരികെ ret;
}

/* function to assist building execv() arguments */
ശൂന്യം
addargs(arglist *args, അക്ഷരം *fmt, ...)
{
	va_list ap;
	അക്ഷരം *cp;
	u_int nalloc;
	പൂർണ്ണസംഖ്യ r;

	va_start(ap, fmt);
	r = vasprintf(&cp, fmt, ap);
	va_end(ap);
	എങ്കിൽ (r == -1)
		fatal_f("argument too long");

	nalloc = args->nalloc;
	എങ്കിൽ (args->list == ശൂന്യ) {
		nalloc = 32;
		args->അക്കം = 0;
	} അല്ലെങ്കിൽ എങ്കിൽ (args->അക്കം > (256 * 1024))
		fatal_f("too many arguments");
	അല്ലെങ്കിൽ എങ്കിൽ (args->അക്കം >= args->nalloc)
		fatal_f("arglist corrupt");
	അല്ലെങ്കിൽ എങ്കിൽ (args->അക്കം+2 >= nalloc)
		nalloc *= 2;

	args->list = xrecallocarray(args->list, args->nalloc,
	    nalloc, വലുപ്പം(അക്ഷരം *));
	args->nalloc = nalloc;
	args->list[args->അക്കം++] = cp;
	args->list[args->അക്കം] = ശൂന്യ;
}

ശൂന്യം
replacearg(arglist *args, u_int which, അക്ഷരം *fmt, ...)
{
	va_list ap;
	അക്ഷരം *cp;
	പൂർണ്ണസംഖ്യ r;

	va_start(ap, fmt);
	r = vasprintf(&cp, fmt, ap);
	va_end(ap);
	എങ്കിൽ (r == -1)
		fatal_f("argument too long");
	എങ്കിൽ (args->list == ശൂന്യ || args->അക്കം >= args->nalloc)
		fatal_f("arglist corrupt");

	എങ്കിൽ (which >= args->അക്കം)
		fatal_f("tried to replace invalid arg %d >= %d",
		    which, args->അക്കം);
	സ്വതന്ത്രം(args->list[which]);
	args->list[which] = cp;
}

ശൂന്യം
freeargs(arglist *args)
{
	u_int i;

	എങ്കിൽ (args == ശൂന്യ)
		തിരികെ;
	എങ്കിൽ (args->list != ശൂന്യ && args->അക്കം < args->nalloc) {
		വേണ്ടി (i = 0; i < args->അക്കം; i++)
			സ്വതന്ത്രം(args->list[i]);
		സ്വതന്ത്രം(args->list);
	}
	args->nalloc = args->അക്കം = 0;
	args->list = ശൂന്യ;
}

/*
 * Expands tildes in the file name.  Returns data allocated by xmalloc.
 * Warning: this calls getpw*.
 */
പൂർണ്ണസംഖ്യ
tilde_expand(സ്ഥിരം അക്ഷരം *filename, uid_t uid, അക്ഷരം **retp)
{
	അക്ഷരം *ocopy = ശൂന്യ, *copy, *s = ശൂന്യ;
	സ്ഥിരം അക്ഷരം *path = ശൂന്യ, *user = ശൂന്യ;
	ഘടന passwd *pw;
	size_t len;
	പൂർണ്ണസംഖ്യ ret = -1, r, slash;

	*retp = ശൂന്യ;
	എങ്കിൽ (*filename != '~') {
		*retp = xstrdup(filename);
		തിരികെ 0;
	}
	ocopy = copy = xstrdup(filename + 1);

	എങ്കിൽ (*copy == '\0')				/* ~ */
		path = ശൂന്യ;
	അല്ലെങ്കിൽ എങ്കിൽ (*copy == '/') {
		copy += strspn(copy, "/");
		എങ്കിൽ (*copy == '\0')
			path = ശൂന്യ;			/* ~/ */
		അല്ലെങ്കിൽ
			path = copy;			/* ~/path */
	} അല്ലെങ്കിൽ {
		user = copy;
		എങ്കിൽ ((path = strchr(copy, '/')) != ശൂന്യ) {
			copy[path - copy] = '\0';
			path++;
			path += strspn(path, "/");
			എങ്കിൽ (*path == '\0')		/* ~user/ */
				path = ശൂന്യ;
			/* else				 ~user/path */
		}
		/* else					~user */
	}
	എങ്കിൽ (user != ശൂന്യ) {
		എങ്കിൽ ((pw = getpwnam(user)) == ശൂന്യ) {
			error_f("No such user %s", user);
			പോകുക out;
		}
	} അല്ലെങ്കിൽ എങ്കിൽ ((pw = getpwuid(uid)) == ശൂന്യ) {
		error_f("No such uid %ld", (long)uid);
		പോകുക out;
	}

	/* Make sure directory has a trailing '/' */
	slash = (len = strlen(pw->pw_dir)) == 0 || pw->pw_dir[len - 1] != '/';

	എങ്കിൽ ((r = xasprintf(&s, "%s%s%s", pw->pw_dir,
	    slash ? "/" : "", path != ശൂന്യ ? path : "")) <= 0) {
		error_f("xasprintf failed");
		പോകുക out;
	}
	എങ്കിൽ (r >= PATH_MAX) {
		error_f("Path too long");
		പോകുക out;
	}
	/* success */
	ret = 0;
	*retp = s;
	s = ശൂന്യ;
 out:
	സ്വതന്ത്രം(s);
	സ്വതന്ത്രം(ocopy);
	തിരികെ ret;
}

അക്ഷരം *
tilde_expand_filename(സ്ഥിരം അക്ഷരം *filename, uid_t uid)
{
	അക്ഷരം *ret;

	എങ്കിൽ (tilde_expand(filename, uid, &ret) != 0)
		cleanup_exit(255);
	തിരികെ ret;
}

/*
 * Expand a string with a set of %[char] escapes and/or ${ENVIRONMENT}
 * substitutions.  A number of escapes may be specified as
 * (char *escape_chars, char *replacement) pairs. The list must be terminated
 * by a NULL escape_char. Returns replaced string in memory allocated by
 * xmalloc which the caller must free.
 */
സ്ഥിതം അക്ഷരം *
vdollar_percent_expand(പൂർണ്ണസംഖ്യ *parseerror, പൂർണ്ണസംഖ്യ dollar, പൂർണ്ണസംഖ്യ percent,
    സ്ഥിരം അക്ഷരം *string, va_list ap)
{
#define EXPAND_MAX_താക്കോലുകൾ	64
	u_int അക്കം_താക്കോലുകൾ = 0, i;
	ഘടന {
		സ്ഥിരം അക്ഷരം *താക്കോൽ;
		സ്ഥിരം അക്ഷരം *repl;
	} താക്കോലുകൾ[EXPAND_MAX_താക്കോലുകൾ];
	ഘടന sshbuf *buf;
	പൂർണ്ണസംഖ്യ r, missingvar = 0;
	അക്ഷരം *ret = ശൂന്യ, *var, *varend, *val;
	size_t len;

	എങ്കിൽ ((buf = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	എങ്കിൽ (parseerror == ശൂന്യ)
		fatal_f("null parseerror arg");
	*parseerror = 1;

	/* Gather keys if we're doing percent expansion. */
	എങ്കിൽ (percent) {
		വേണ്ടി (അക്കം_താക്കോലുകൾ = 0; അക്കം_താക്കോലുകൾ < EXPAND_MAX_താക്കോലുകൾ; അക്കം_താക്കോലുകൾ++) {
			താക്കോലുകൾ[അക്കം_താക്കോലുകൾ].താക്കോൽ = va_arg(ap, അക്ഷരം *);
			എങ്കിൽ (താക്കോലുകൾ[അക്കം_താക്കോലുകൾ].താക്കോൽ == ശൂന്യ)
				നിർത്തുക;
			താക്കോലുകൾ[അക്കം_താക്കോലുകൾ].repl = va_arg(ap, അക്ഷരം *);
			എങ്കിൽ (താക്കോലുകൾ[അക്കം_താക്കോലുകൾ].repl == ശൂന്യ) {
				fatal_f("NULL replacement for token %s",
				    താക്കോലുകൾ[അക്കം_താക്കോലുകൾ].താക്കോൽ);
			}
		}
		എങ്കിൽ (അക്കം_താക്കോലുകൾ == EXPAND_MAX_താക്കോലുകൾ && va_arg(ap, അക്ഷരം *) != ശൂന്യ)
			fatal_f("too many keys");
		എങ്കിൽ (അക്കം_താക്കോലുകൾ == 0)
			fatal_f("percent expansion without token list");
	}

	/* Expand string */
	വേണ്ടി (i = 0; *string != '\0'; string++) {
		/* Optionally process ${ENVIRONMENT} expansions. */
		എങ്കിൽ (dollar && string[0] == '$' && string[1] == '{') {
			string += 2;  /* skip over '${' */
			എങ്കിൽ ((varend = strchr(string, '}')) == ശൂന്യ) {
				error_f("environment variable '%s' missing "
				    "closing '}'", string);
				പോകുക out;
			}
			len = varend - string;
			എങ്കിൽ (len == 0) {
				error_f("zero-length environment variable");
				പോകുക out;
			}
			var = xmalloc(len + 1);
			(ശൂന്യം)strlcpy(var, string, len + 1);
			എങ്കിൽ ((val = getenv(var)) == ശൂന്യ) {
				error_f("env var ${%s} has no value", var);
				missingvar = 1;
			} അല്ലെങ്കിൽ {
				debug3_f("expand ${%s} -> '%s'", var, val);
				എങ്കിൽ ((r = sshbuf_put(buf, val, strlen(val))) !=0)
					fatal_fr(r, "sshbuf_put ${}");
			}
			സ്വതന്ത്രം(var);
			string += len;
			തുടരുക;
		}

		/*
		 * Process percent expansions if we have a list of TOKENs.
		 * If we're not doing percent expansion everything just gets
		 * appended here.
		 */
		എങ്കിൽ (*string != '%' || !percent) {
 append:
			എങ്കിൽ ((r = sshbuf_put_u8(buf, *string)) != 0)
				fatal_fr(r, "sshbuf_put_u8 %%");
			തുടരുക;
		}
		string++;
		/* %% case */
		എങ്കിൽ (*string == '%')
			പോകുക append;
		എങ്കിൽ (*string == '\0') {
			error_f("invalid format");
			പോകുക out;
		}
		വേണ്ടി (i = 0; i < അക്കം_താക്കോലുകൾ; i++) {
			എങ്കിൽ (strchr(താക്കോലുകൾ[i].താക്കോൽ, *string) != ശൂന്യ) {
				എങ്കിൽ ((r = sshbuf_put(buf, താക്കോലുകൾ[i].repl,
				    strlen(താക്കോലുകൾ[i].repl))) != 0)
					fatal_fr(r, "sshbuf_put %%-repl");
				നിർത്തുക;
			}
		}
		എങ്കിൽ (i >= അക്കം_താക്കോലുകൾ) {
			error_f("unknown key %%%c", *string);
			പോകുക out;
		}
	}
	എങ്കിൽ (!missingvar && (ret = sshbuf_dup_string(buf)) == ശൂന്യ)
		fatal_f("sshbuf_dup_string failed");
	*parseerror = 0;
 out:
	sshbuf_free(buf);
	തിരികെ *parseerror ? ശൂന്യ : ret;
#undef EXPAND_MAX_താക്കോലുകൾ
}

/*
 * Expand only environment variables.
 * Note that although this function is variadic like the other similar
 * functions, any such arguments will be unused.
 */

അക്ഷരം *
dollar_expand(പൂർണ്ണസംഖ്യ *parseerr, സ്ഥിരം അക്ഷരം *string, ...)
{
	അക്ഷരം *ret;
	പൂർണ്ണസംഖ്യ err;
	va_list ap;

	va_start(ap, string);
	ret = vdollar_percent_expand(&err, 1, 0, string, ap);
	va_end(ap);
	എങ്കിൽ (parseerr != ശൂന്യ)
		*parseerr = err;
	തിരികെ ret;
}

/*
 * Returns expanded string or NULL if a specified environment variable is
 * not defined, or calls fatal if the string is invalid.
 */
അക്ഷരം *
percent_expand(സ്ഥിരം അക്ഷരം *string, ...)
{
	അക്ഷരം *ret;
	പൂർണ്ണസംഖ്യ err;
	va_list ap;

	va_start(ap, string);
	ret = vdollar_percent_expand(&err, 0, 1, string, ap);
	va_end(ap);
	എങ്കിൽ (err)
		fatal_f("failed");
	തിരികെ ret;
}

/*
 * Returns expanded string or NULL if a specified environment variable is
 * not defined, or calls fatal if the string is invalid.
 */
അക്ഷരം *
percent_dollar_expand(സ്ഥിരം അക്ഷരം *string, ...)
{
	അക്ഷരം *ret;
	പൂർണ്ണസംഖ്യ err;
	va_list ap;

	va_start(ap, string);
	ret = vdollar_percent_expand(&err, 1, 1, string, ap);
	va_end(ap);
	എങ്കിൽ (err)
		fatal_f("failed");
	തിരികെ ret;
}

പൂർണ്ണസംഖ്യ
tun_open(പൂർണ്ണസംഖ്യ tun, പൂർണ്ണസംഖ്യ mode, അക്ഷരം **ifname)
{
#എങ്കിൽ defined(CUSTOM_SYS_TUN_OPEN)
	തിരികെ (sys_tun_open(tun, mode, ifname));
#അല്ലെങ്കിലെങ്കിൽ defined(SSH_TUN_OPENBSD)
	ഘടന ifreq ifr;
	അക്ഷരം name[100];
	പൂർണ്ണസംഖ്യ fd = -1, sock;
	സ്ഥിരം അക്ഷരം *tunbase = "tun";

	എങ്കിൽ (ifname != ശൂന്യ)
		*ifname = ശൂന്യ;

	എങ്കിൽ (mode == SSH_TUNMODE_ETHERNET)
		tunbase = "tap";

	/* Open the tunnel device */
	എങ്കിൽ (tun <= SSH_TUNID_MAX) {
		snprintf(name, വലുപ്പം(name), "/dev/%s%d", tunbase, tun);
		fd = open(name, O_RDWR);
	} അല്ലെങ്കിൽ എങ്കിൽ (tun == SSH_TUNID_ANY) {
		വേണ്ടി (tun = 100; tun >= 0; tun--) {
			snprintf(name, വലുപ്പം(name), "/dev/%s%d",
			    tunbase, tun);
			എങ്കിൽ ((fd = open(name, O_RDWR)) >= 0)
				നിർത്തുക;
		}
	} അല്ലെങ്കിൽ {
		debug_f("invalid tunnel %u", tun);
		തിരികെ -1;
	}

	എങ്കിൽ (fd == -1) {
		debug_f("%s open: %s", name, strerror(errno));
		തിരികെ -1;
	}

	debug_f("%s mode %d fd %d", name, mode, fd);

	/* Bring interface up if it is not already */
	snprintf(ifr.ifr_name, വലുപ്പം(ifr.ifr_name), "%s%d", tunbase, tun);
	എങ്കിൽ ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
		പോകുക failed;

	എങ്കിൽ (ioctl(sock, SIOCGIFFLAGS, &ifr) == -1) {
		debug_f("get interface %s flags: %s", ifr.ifr_name,
		    strerror(errno));
		പോകുക failed;
	}

	എങ്കിൽ (!(ifr.ifr_flags & IFF_UP)) {
		ifr.ifr_flags |= IFF_UP;
		എങ്കിൽ (ioctl(sock, SIOCSIFFLAGS, &ifr) == -1) {
			debug_f("activate interface %s: %s", ifr.ifr_name,
			    strerror(errno));
			പോകുക failed;
		}
	}

	എങ്കിൽ (ifname != ശൂന്യ)
		*ifname = xstrdup(ifr.ifr_name);

	close(sock);
	തിരികെ fd;

 failed:
	എങ്കിൽ (fd >= 0)
		close(fd);
	എങ്കിൽ (sock >= 0)
		close(sock);
	തിരികെ -1;
#അല്ലെങ്കിൽ
	error("Tunnel interfaces are not supported on this platform");
	തിരികെ (-1);
#endif
}

ശൂന്യം
sanitise_stdfd(ശൂന്യം)
{
	പൂർണ്ണസംഖ്യ nullfd, dupfd;

	എങ്കിൽ ((nullfd = dupfd = open(_PATH_DEVNULL, O_RDWR)) == -1) {
		fprintf(stderr, "Couldn't open /dev/null: %s\n",
		    strerror(errno));
		exit(1);
	}
	ആകുമ്പോൾ (++dupfd <= STDERR_FILENO) {
		/* Only populate closed fds. */
		എങ്കിൽ (fcntl(dupfd, F_GETFL) == -1 && errno == EBADF) {
			എങ്കിൽ (dup2(nullfd, dupfd) == -1) {
				fprintf(stderr, "dup2: %s\n", strerror(errno));
				exit(1);
			}
		}
	}
	എങ്കിൽ (nullfd > STDERR_FILENO)
		close(nullfd);
}

അക്ഷരം *
tohex(സ്ഥിരം ശൂന്യം *vp, size_t l)
{
	സ്ഥിരം u_char *p = (സ്ഥിരം u_char *)vp;
	അക്ഷരം b[3], *r;
	size_t i, hl;

	എങ്കിൽ (l > 65536)
		തിരികെ xstrdup("tohex: length > 65536");

	hl = l * 2 + 1;
	r = xcalloc(1, hl);
	വേണ്ടി (i = 0; i < l; i++) {
		snprintf(b, വലുപ്പം(b), "%02x", p[i]);
		strlcat(r, b, hl);
	}
	തിരികെ (r);
}

/*
 * Extend string *sp by the specified format. If *sp is not NULL (or empty),
 * then the separator 'sep' will be prepended before the formatted arguments.
 * Extended strings are heap allocated.
 */
ശൂന്യം
xextendf(അക്ഷരം **sp, സ്ഥിരം അക്ഷരം *sep, സ്ഥിരം അക്ഷരം *fmt, ...)
{
	va_list ap;
	അക്ഷരം *tmp1, *tmp2;

	va_start(ap, fmt);
	xvasprintf(&tmp1, fmt, ap);
	va_end(ap);

	എങ്കിൽ (*sp == ശൂന്യ || **sp == '\0') {
		സ്വതന്ത്രം(*sp);
		*sp = tmp1;
		തിരികെ;
	}
	xasprintf(&tmp2, "%s%s%s", *sp, sep == ശൂന്യ ? "" : sep, tmp1);
	സ്വതന്ത്രം(tmp1);
	സ്വതന്ത്രം(*sp);
	*sp = tmp2;
}


uint64_t
get_u64(സ്ഥിരം ശൂന്യം *vp)
{
	സ്ഥിരം u_char *p = (സ്ഥിരം u_char *)vp;
	uint64_t v;

	v  = (uint64_t)p[0] << 56;
	v |= (uint64_t)p[1] << 48;
	v |= (uint64_t)p[2] << 40;
	v |= (uint64_t)p[3] << 32;
	v |= (uint64_t)p[4] << 24;
	v |= (uint64_t)p[5] << 16;
	v |= (uint64_t)p[6] << 8;
	v |= (uint64_t)p[7];

	തിരികെ (v);
}

uint32_t
get_u32(സ്ഥിരം ശൂന്യം *vp)
{
	സ്ഥിരം u_char *p = (സ്ഥിരം u_char *)vp;
	uint32_t v;

	v  = (uint32_t)p[0] << 24;
	v |= (uint32_t)p[1] << 16;
	v |= (uint32_t)p[2] << 8;
	v |= (uint32_t)p[3];

	തിരികെ (v);
}

uint32_t
get_u32_le(സ്ഥിരം ശൂന്യം *vp)
{
	സ്ഥിരം u_char *p = (സ്ഥിരം u_char *)vp;
	uint32_t v;

	v  = (uint32_t)p[0];
	v |= (uint32_t)p[1] << 8;
	v |= (uint32_t)p[2] << 16;
	v |= (uint32_t)p[3] << 24;

	തിരികെ (v);
}

uint16_t
get_u16(സ്ഥിരം ശൂന്യം *vp)
{
	സ്ഥിരം u_char *p = (സ്ഥിരം u_char *)vp;
	uint16_t v;

	v  = (uint16_t)p[0] << 8;
	v |= (uint16_t)p[1];

	തിരികെ (v);
}

ശൂന്യം
put_u64(ശൂന്യം *vp, uint64_t v)
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

ശൂന്യം
put_u32(ശൂന്യം *vp, uint32_t v)
{
	u_char *p = (u_char *)vp;

	p[0] = (u_char)(v >> 24) & 0xff;
	p[1] = (u_char)(v >> 16) & 0xff;
	p[2] = (u_char)(v >> 8) & 0xff;
	p[3] = (u_char)v & 0xff;
}

ശൂന്യം
put_u32_le(ശൂന്യം *vp, uint32_t v)
{
	u_char *p = (u_char *)vp;

	p[0] = (u_char)v & 0xff;
	p[1] = (u_char)(v >> 8) & 0xff;
	p[2] = (u_char)(v >> 16) & 0xff;
	p[3] = (u_char)(v >> 24) & 0xff;
}

ശൂന്യം
put_u16(ശൂന്യം *vp, uint16_t v)
{
	u_char *p = (u_char *)vp;

	p[0] = (u_char)(v >> 8) & 0xff;
	p[1] = (u_char)v & 0xff;
}

ശൂന്യം
ms_subtract_diff(ഘടന timeval *start, പൂർണ്ണസംഖ്യ *ms)
{
	ഘടന timeval diff, finish;

	monotime_tv(&finish);
	timersub(&finish, start, &diff);
	*ms -= (diff.tv_sec * 1000) + (diff.tv_usec / 1000);
}

ശൂന്യം
ms_to_timespec(ഘടന timespec *ts, പൂർണ്ണസംഖ്യ ms)
{
	എങ്കിൽ (ms < 0)
		ms = 0;
	ts->tv_sec = ms / 1000;
	ts->tv_nsec = (ms % 1000) * 1000 * 1000;
}

ശൂന്യം
monotime_ts(ഘടന timespec *ts)
{
	ഘടന timeval tv;
#എങ്കിൽ defined(HAVE_CLOCK_GETTIME) && (defined(CLOCK_BOOTTIME) || \
    defined(CLOCK_MONOTONIC) || defined(CLOCK_REALTIME))
	സ്ഥിതം പൂർണ്ണസംഖ്യ gettime_failed = 0;

	എങ്കിൽ (!gettime_failed) {
# ifdef CLOCK_BOOTTIME
		എങ്കിൽ (clock_gettime(CLOCK_BOOTTIME, ts) == 0)
			തിരികെ;
# endif /* CLOCK_BOOTTIME */
# ifdef CLOCK_MONOTONIC
		എങ്കിൽ (clock_gettime(CLOCK_MONOTONIC, ts) == 0)
			തിരികെ;
# endif /* CLOCK_MONOTONIC */
# ifdef CLOCK_REALTIME
		/* Not monotonic, but we're almost out of options here. */
		എങ്കിൽ (clock_gettime(CLOCK_REALTIME, ts) == 0)
			തിരികെ;
# endif /* CLOCK_REALTIME */
		debug3("clock_gettime: %s", strerror(errno));
		gettime_failed = 1;
	}
#endif /* HAVE_CLOCK_GETTIME && (BOOTTIME || MONOTONIC || REALTIME) */
	gettimeofday(&tv, ശൂന്യ);
	ts->tv_sec = tv.tv_sec;
	ts->tv_nsec = (long)tv.tv_usec * 1000;
}

ശൂന്യം
monotime_tv(ഘടന timeval *tv)
{
	ഘടന timespec ts;

	monotime_ts(&ts);
	tv->tv_sec = ts.tv_sec;
	tv->tv_usec = ts.tv_nsec / 1000;
}

time_t
monotime(ശൂന്യം)
{
	ഘടന timespec ts;

	monotime_ts(&ts);
	തിരികെ (ts.tv_sec);
}

ഇരട്ട
monotime_double(ശൂന്യം)
{
	ഘടന timespec ts;

	monotime_ts(&ts);
	തിരികെ (ഇരട്ട)ts.tv_sec + (ഇരട്ട)ts.tv_nsec / 1000000000.0;
}

ശൂന്യം
bandwidth_limit_init(ഘടന bwlimit *bw, uint64_t kbps, size_t buflen)
{
	bw->buflen = buflen;
	bw->rate = kbps;
	bw->thresh = buflen;
	bw->lamt = 0;
	timerclear(&bw->bwstart);
	timerclear(&bw->bwend);
}

/* Callback from read/write loop to insert bandwidth-limiting delays */
ശൂന്യം
bandwidth_limit(ഘടന bwlimit *bw, size_t read_len)
{
	uint64_t waitlen;
	ഘടന timespec ts, rm;

	bw->lamt += read_len;
	എങ്കിൽ (!timerisset(&bw->bwstart)) {
		monotime_tv(&bw->bwstart);
		തിരികെ;
	}
	എങ്കിൽ (bw->lamt < bw->thresh)
		തിരികെ;

	monotime_tv(&bw->bwend);
	timersub(&bw->bwend, &bw->bwstart, &bw->bwend);
	എങ്കിൽ (!timerisset(&bw->bwend))
		തിരികെ;

	bw->lamt *= 8;
	waitlen = (ഇരട്ട)1000000L * bw->lamt / bw->rate;

	bw->bwstart.tv_sec = waitlen / 1000000L;
	bw->bwstart.tv_usec = waitlen % 1000000L;

	എങ്കിൽ (timercmp(&bw->bwstart, &bw->bwend, >)) {
		timersub(&bw->bwstart, &bw->bwend, &bw->bwend);

		/* Adjust the wait time */
		എങ്കിൽ (bw->bwend.tv_sec) {
			bw->thresh /= 2;
			എങ്കിൽ (bw->thresh < bw->buflen / 4)
				bw->thresh = bw->buflen / 4;
		} അല്ലെങ്കിൽ എങ്കിൽ (bw->bwend.tv_usec < 10000) {
			bw->thresh *= 2;
			എങ്കിൽ (bw->thresh > bw->buflen * 8)
				bw->thresh = bw->buflen * 8;
		}

		TIMEVAL_TO_TIMESPEC(&bw->bwend, &ts);
		ആകുമ്പോൾ (nanosleep(&ts, &rm) == -1) {
			എങ്കിൽ (errno != EINTR)
				നിർത്തുക;
			ts = rm;
		}
	}

	bw->lamt = 0;
	monotime_tv(&bw->bwstart);
}

/* Make a template filename for mk[sd]temp() */
ശൂന്യം
mktemp_proto(അക്ഷരം *s, size_t len)
{
	സ്ഥിരം അക്ഷരം *tmpdir;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((tmpdir = getenv("TMPDIR")) != ശൂന്യ) {
		r = snprintf(s, len, "%s/ssh-XXXXXXXXXXXX", tmpdir);
		എങ്കിൽ (r > 0 && (size_t)r < len)
			തിരികെ;
	}
	r = snprintf(s, len, "/tmp/ssh-XXXXXXXXXXXX");
	എങ്കിൽ (r < 0 || (size_t)r >= len)
		fatal_f("template string too short");
}

സ്ഥിതം സ്ഥിരം ഘടന {
	സ്ഥിരം അക്ഷരം *name;
	പൂർണ്ണസംഖ്യ മൂല്യം;
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
	{ ശൂന്യ, -1 }
};

പൂർണ്ണസംഖ്യ
parse_ipqos(സ്ഥിരം അക്ഷരം *cp)
{
	സ്ഥിരം അക്ഷരം *errstr;
	u_int i;
	പൂർണ്ണസംഖ്യ val;

	എങ്കിൽ (cp == ശൂന്യ)
		തിരികെ -1;
	വേണ്ടി (i = 0; ipqos[i].name != ശൂന്യ; i++) {
		എങ്കിൽ (strcasecmp(cp, ipqos[i].name) == 0)
			തിരികെ ipqos[i].മൂല്യം;
	}
	/* Try parsing as an integer */
	val = (പൂർണ്ണസംഖ്യ)strtonum(cp, 0, 255, &errstr);
	എങ്കിൽ (errstr)
		തിരികെ -1;
	തിരികെ val;
}

സ്ഥിരം അക്ഷരം *
iptos2str(പൂർണ്ണസംഖ്യ iptos)
{
	പൂർണ്ണസംഖ്യ i;
	സ്ഥിതം അക്ഷരം iptos_str[വലുപ്പം "0xff"];

	വേണ്ടി (i = 0; ipqos[i].name != ശൂന്യ; i++) {
		എങ്കിൽ (ipqos[i].മൂല്യം == iptos)
			തിരികെ ipqos[i].name;
	}
	snprintf(iptos_str, വലുപ്പം iptos_str, "0x%02x", iptos);
	തിരികെ iptos_str;
}

ശൂന്യം
lowercase(അക്ഷരം *s)
{
	വേണ്ടി (; *s; s++)
		*s = tolower((u_char)*s);
}

പൂർണ്ണസംഖ്യ
unix_listener(സ്ഥിരം അക്ഷരം *path, പൂർണ്ണസംഖ്യ backlog, പൂർണ്ണസംഖ്യ unlink_first)
{
	ഘടന sockaddr_un sunaddr;
	പൂർണ്ണസംഖ്യ saved_errno, sock;

	memset(&sunaddr, 0, വലുപ്പം(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	എങ്കിൽ (strlcpy(sunaddr.sun_path, path,
	    വലുപ്പം(sunaddr.sun_path)) >= വലുപ്പം(sunaddr.sun_path)) {
		error_f("path \"%s\" too long for Unix domain socket", path);
		errno = ENAMETOOLONG;
		തിരികെ -1;
	}

	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	എങ്കിൽ (sock == -1) {
		saved_errno = errno;
		error_f("socket: %.100s", strerror(errno));
		errno = saved_errno;
		തിരികെ -1;
	}
	എങ്കിൽ (unlink_first == 1) {
		എങ്കിൽ (unlink(path) != 0 && errno != ENOENT)
			error("unlink(%s): %.100s", path, strerror(errno));
	}
	എങ്കിൽ (bind(sock, (ഘടന sockaddr *)&sunaddr, വലുപ്പം(sunaddr)) == -1) {
		saved_errno = errno;
		error_f("cannot bind to path %s: %s", path, strerror(errno));
		close(sock);
		errno = saved_errno;
		തിരികെ -1;
	}
	എങ്കിൽ (listen(sock, backlog) == -1) {
		saved_errno = errno;
		error_f("cannot listen on path %s: %s", path, strerror(errno));
		close(sock);
		unlink(path);
		errno = saved_errno;
		തിരികെ -1;
	}
	തിരികെ sock;
}

ശൂന്യം
sock_set_v6only(പൂർണ്ണസംഖ്യ s)
{
#എങ്കിൽ defined(IPV6_V6ONLY) && !defined(__OpenBSD__)
	പൂർണ്ണസംഖ്യ on = 1;

	debug3_f("set socket %d IPV6_V6ONLY", s);
	എങ്കിൽ (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &on, വലുപ്പം(on)) == -1)
		error("setsockopt IPV6_V6ONLY: %s", strerror(errno));
#endif
}

/*
 * Compares two strings that maybe be NULL. Returns non-zero if strings
 * are both NULL or are identical, returns zero otherwise.
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
strcmp_maybe_null(സ്ഥിരം അക്ഷരം *a, സ്ഥിരം അക്ഷരം *b)
{
	എങ്കിൽ ((a == ശൂന്യ && b != ശൂന്യ) || (a != ശൂന്യ && b == ശൂന്യ))
		തിരികെ 0;
	എങ്കിൽ (a != ശൂന്യ && strcmp(a, b) != 0)
		തിരികെ 0;
	തിരികെ 1;
}

/*
 * Compare two forwards, returning non-zero if they are identical or
 * zero otherwise.
 */
പൂർണ്ണസംഖ്യ
forward_equals(സ്ഥിരം ഘടന Forward *a, സ്ഥിരം ഘടന Forward *b)
{
	എങ്കിൽ (strcmp_maybe_null(a->listen_host, b->listen_host) == 0)
		തിരികെ 0;
	എങ്കിൽ (a->listen_port != b->listen_port)
		തിരികെ 0;
	എങ്കിൽ (strcmp_maybe_null(a->listen_path, b->listen_path) == 0)
		തിരികെ 0;
	എങ്കിൽ (strcmp_maybe_null(a->connect_host, b->connect_host) == 0)
		തിരികെ 0;
	എങ്കിൽ (a->connect_port != b->connect_port)
		തിരികെ 0;
	എങ്കിൽ (strcmp_maybe_null(a->connect_path, b->connect_path) == 0)
		തിരികെ 0;
	/* allocated_port and handle are not checked */
	തിരികെ 1;
}

/* returns port number, FWD_PERMIT_ANY_PORT or -1 on error */
പൂർണ്ണസംഖ്യ
permitopen_port(സ്ഥിരം അക്ഷരം *p)
{
	പൂർണ്ണസംഖ്യ port;

	എങ്കിൽ (strcmp(p, "*") == 0)
		തിരികെ FWD_PERMIT_ANY_PORT;
	എങ്കിൽ ((port = a2port(p)) > 0)
		തിരികെ port;
	തിരികെ -1;
}

/* returns 1 if process is already daemonized, 0 otherwise */
പൂർണ്ണസംഖ്യ
daemonized(ശൂന്യം)
{
	പൂർണ്ണസംഖ്യ fd;

	എങ്കിൽ ((fd = open(_PATH_TTY, O_RDONLY | O_NOCTTY)) >= 0) {
		close(fd);
		തിരികെ 0;	/* have controlling terminal */
	}
	എങ്കിൽ (getppid() != 1)
		തിരികെ 0;	/* parent is not init */
	എങ്കിൽ (getsid(0) != getpid())
		തിരികെ 0;	/* not session leader */
	debug3("already daemonized");
	തിരികെ 1;
}

/*
 * Splits 's' into an argument vector. Handles quoted string and basic
 * escape characters (\\, \", \'). Caller must free the argument vector
 * and its members.
 */
പൂർണ്ണസംഖ്യ
argv_split(സ്ഥിരം അക്ഷരം *s, പൂർണ്ണസംഖ്യ *argcp, അക്ഷരം ***argvp, പൂർണ്ണസംഖ്യ terminate_on_comment)
{
	പൂർണ്ണസംഖ്യ r = SSH_ERR_INTERNAL_ERROR;
	പൂർണ്ണസംഖ്യ argc = 0, quote, i, j;
	അക്ഷരം *arg, **argv = xcalloc(1, വലുപ്പം(*argv));

	*argvp = ശൂന്യ;
	*argcp = 0;

	വേണ്ടി (i = 0; s[i] != '\0'; i++) {
		/* Skip leading whitespace */
		എങ്കിൽ (s[i] == ' ' || s[i] == '\t')
			തുടരുക;
		എങ്കിൽ (terminate_on_comment && s[i] == '#')
			നിർത്തുക;
		/* Start of a token */
		quote = 0;

		argv = xreallocarray(argv, (argc + 2), വലുപ്പം(*argv));
		arg = argv[argc++] = xcalloc(1, strlen(s + i) + 1);
		argv[argc] = ശൂന്യ;

		/* Copy the token in, removing escapes */
		വേണ്ടി (j = 0; s[i] != '\0'; i++) {
			എങ്കിൽ (s[i] == '\\') {
				എങ്കിൽ (s[i + 1] == '\'' ||
				    s[i + 1] == '\"' ||
				    s[i + 1] == '\\' ||
				    (quote == 0 && s[i + 1] == ' ')) {
					i++; /* Skip '\' */
					arg[j++] = s[i];
				} അല്ലെങ്കിൽ {
					/* Unrecognised escape */
					arg[j++] = s[i];
				}
			} അല്ലെങ്കിൽ എങ്കിൽ (quote == 0 && (s[i] == ' ' || s[i] == '\t'))
				നിർത്തുക; /* done */
			അല്ലെങ്കിൽ എങ്കിൽ (quote == 0 && (s[i] == '\"' || s[i] == '\''))
				quote = s[i]; /* quote start */
			അല്ലെങ്കിൽ എങ്കിൽ (quote != 0 && s[i] == quote)
				quote = 0; /* quote end */
			അല്ലെങ്കിൽ
				arg[j++] = s[i];
		}
		എങ്കിൽ (s[i] == '\0') {
			എങ്കിൽ (quote != 0) {
				/* Ran out of string looking for close quote */
				r = SSH_ERR_INVALID_FORMAT;
				പോകുക out;
			}
			നിർത്തുക;
		}
	}
	/* Success */
	*argcp = argc;
	*argvp = argv;
	argc = 0;
	argv = ശൂന്യ;
	r = 0;
 out:
	എങ്കിൽ (argc != 0 && argv != ശൂന്യ) {
		വേണ്ടി (i = 0; i < argc; i++)
			സ്വതന്ത്രം(argv[i]);
		സ്വതന്ത്രം(argv);
	}
	തിരികെ r;
}

/*
 * Reassemble an argument vector into a string, quoting and escaping as
 * necessary. Caller must free returned string.
 */
അക്ഷരം *
argv_assemble(പൂർണ്ണസംഖ്യ argc, അക്ഷരം **argv)
{
	പൂർണ്ണസംഖ്യ i, j, ws, r;
	അക്ഷരം c, *ret;
	ഘടന sshbuf *buf, *arg;

	എങ്കിൽ ((buf = sshbuf_new()) == ശൂന്യ || (arg = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");

	വേണ്ടി (i = 0; i < argc; i++) {
		ws = 0;
		sshbuf_reset(arg);
		വേണ്ടി (j = 0; argv[i][j] != '\0'; j++) {
			r = 0;
			c = argv[i][j];
			തിരഞ്ഞെടുപ്പ് (c) {
			അവസ്ഥ ' ':
			അവസ്ഥ '\t':
				ws = 1;
				r = sshbuf_put_u8(arg, c);
				നിർത്തുക;
			അവസ്ഥ '\\':
			അവസ്ഥ '\'':
			അവസ്ഥ '"':
				എങ്കിൽ ((r = sshbuf_put_u8(arg, '\\')) != 0)
					നിർത്തുക;
				/* FALLTHROUGH */
			സ്ഥിരസ്ഥിതി:
				r = sshbuf_put_u8(arg, c);
				നിർത്തുക;
			}
			എങ്കിൽ (r != 0)
				fatal_fr(r, "sshbuf_put_u8");
		}
		എങ്കിൽ ((i != 0 && (r = sshbuf_put_u8(buf, ' ')) != 0) ||
		    (ws != 0 && (r = sshbuf_put_u8(buf, '"')) != 0) ||
		    (r = sshbuf_putb(buf, arg)) != 0 ||
		    (ws != 0 && (r = sshbuf_put_u8(buf, '"')) != 0))
			fatal_fr(r, "assemble");
	}
	എങ്കിൽ ((ret = malloc(sshbuf_len(buf) + 1)) == ശൂന്യ)
		fatal_f("malloc failed");
	memcpy(ret, sshbuf_ptr(buf), sshbuf_len(buf));
	ret[sshbuf_len(buf)] = '\0';
	sshbuf_free(buf);
	sshbuf_free(arg);
	തിരികെ ret;
}

അക്ഷരം *
argv_next(പൂർണ്ണസംഖ്യ *argcp, അക്ഷരം ***argvp)
{
	അക്ഷരം *ret = (*argvp)[0];

	എങ്കിൽ (*argcp > 0 && ret != ശൂന്യ) {
		(*argcp)--;
		(*argvp)++;
	}
	തിരികെ ret;
}

ശൂന്യം
argv_consume(പൂർണ്ണസംഖ്യ *argcp)
{
	*argcp = 0;
}

ശൂന്യം
argv_free(അക്ഷരം **av, പൂർണ്ണസംഖ്യ ac)
{
	പൂർണ്ണസംഖ്യ i;

	എങ്കിൽ (av == ശൂന്യ)
		തിരികെ;
	വേണ്ടി (i = 0; i < ac; i++)
		സ്വതന്ത്രം(av[i]);
	സ്വതന്ത്രം(av);
}

/* Returns 0 if pid exited cleanly, non-zero otherwise */
പൂർണ്ണസംഖ്യ
exited_cleanly(pid_t pid, സ്ഥിരം അക്ഷരം *tag, സ്ഥിരം അക്ഷരം *cmd, പൂർണ്ണസംഖ്യ quiet)
{
	പൂർണ്ണസംഖ്യ status;

	ആകുമ്പോൾ (waitpid(pid, &status, 0) == -1) {
		എങ്കിൽ (errno != EINTR) {
			error("%s waitpid: %s", tag, strerror(errno));
			തിരികെ -1;
		}
	}
	എങ്കിൽ (WIFSIGNALED(status)) {
		error("%s %s exited on signal %d", tag, cmd, WTERMSIG(status));
		തിരികെ -1;
	} അല്ലെങ്കിൽ എങ്കിൽ (WEXITSTATUS(status) != 0) {
		do_log2(quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_INFO,
		    "%s %s failed, status %d", tag, cmd, WEXITSTATUS(status));
		തിരികെ -1;
	}
	തിരികെ 0;
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
പൂർണ്ണസംഖ്യ
safe_path(സ്ഥിരം അക്ഷരം *name, ഘടന stat *stp, സ്ഥിരം അക്ഷരം *pw_dir,
    uid_t uid, അക്ഷരം *err, size_t errlen)
{
	അക്ഷരം buf[PATH_MAX], buf2[PATH_MAX], homedir[PATH_MAX];
	അക്ഷരം *cp;
	പൂർണ്ണസംഖ്യ comparehome = 0;
	ഘടന stat st;

	എങ്കിൽ (realpath(name, buf) == ശൂന്യ) {
		snprintf(err, errlen, "realpath %s failed: %s", name,
		    strerror(errno));
		തിരികെ -1;
	}
	എങ്കിൽ (pw_dir != ശൂന്യ && realpath(pw_dir, homedir) != ശൂന്യ)
		comparehome = 1;

	എങ്കിൽ (!S_ISREG(stp->st_mode)) {
		snprintf(err, errlen, "%s is not a regular file", buf);
		തിരികെ -1;
	}
	എങ്കിൽ ((!platform_sys_dir_uid(stp->st_uid) && stp->st_uid != uid) ||
	    (stp->st_mode & 022) != 0) {
		snprintf(err, errlen, "bad ownership or modes for file %s",
		    buf);
		തിരികെ -1;
	}

	/* for each component of the canonical path, walking upwards */
	വേണ്ടി (;;) {
		/*
		 * POSIX allows dirname to modify its argument and return a
		 * pointer into it, so make a copy to avoid overlapping strlcpy.
		 */
		strlcpy(buf2, buf, വലുപ്പം(buf2));
		എങ്കിൽ ((cp = dirname(buf2)) == ശൂന്യ) {
			snprintf(err, errlen, "dirname() failed");
			തിരികെ -1;
		}
		strlcpy(buf, cp, വലുപ്പം(buf));

		എങ്കിൽ (stat(buf, &st) == -1 ||
		    (!platform_sys_dir_uid(st.st_uid) && st.st_uid != uid) ||
		    (st.st_mode & 022) != 0) {
			snprintf(err, errlen,
			    "bad ownership or modes for directory %s", buf);
			തിരികെ -1;
		}

		/* If are past the homedir then we can stop */
		എങ്കിൽ (comparehome && strcmp(homedir, buf) == 0)
			നിർത്തുക;

		/*
		 * dirname should always complete with a "/" path,
		 * but we can be paranoid and check for "." too
		 */
		എങ്കിൽ ((strcmp("/", buf) == 0) || (strcmp(".", buf) == 0))
			നിർത്തുക;
	}
	തിരികെ 0;
}

/*
 * Version of safe_path() that accepts an open file descriptor to
 * avoid races.
 *
 * Returns 0 on success and -1 on failure
 */
പൂർണ്ണസംഖ്യ
safe_path_fd(പൂർണ്ണസംഖ്യ fd, സ്ഥിരം അക്ഷരം *file, ഘടന passwd *pw,
    അക്ഷരം *err, size_t errlen)
{
	ഘടന stat st;

	/* check the open file to avoid races */
	എങ്കിൽ (fstat(fd, &st) == -1) {
		snprintf(err, errlen, "cannot stat file %s: %s",
		    file, strerror(errno));
		തിരികെ -1;
	}
	തിരികെ safe_path(file, &st, pw->pw_dir, pw->pw_uid, err, errlen);
}

/*
 * Sets the value of the given variable in the environment.  If the variable
 * already exists, its value is overridden.
 */
ശൂന്യം
child_set_env(അക്ഷരം ***envp, u_int *envsizep, സ്ഥിരം അക്ഷരം *name,
	സ്ഥിരം അക്ഷരം *മൂല്യം)
{
	അക്ഷരം **env;
	u_int envsize;
	u_int i, namelen;

	എങ്കിൽ (strchr(name, '=') != ശൂന്യ) {
		error("Invalid environment variable \"%.100s\"", name);
		തിരികെ;
	}

	/*
	 * If we're passed an uninitialized list, allocate a single null
	 * entry before continuing.
	 */
	എങ്കിൽ ((*envp == ശൂന്യ) != (*envsizep == 0))
		fatal_f("environment size mismatch");
	എങ്കിൽ (*envp == ശൂന്യ && *envsizep == 0) {
		*envp = xmalloc(വലുപ്പം(അക്ഷരം *));
		*envp[0] = ശൂന്യ;
		*envsizep = 1;
	}

	/*
	 * Find the slot where the value should be stored.  If the variable
	 * already exists, we reuse the slot; otherwise we append a new slot
	 * at the end of the array, expanding if necessary.
	 */
	env = *envp;
	namelen = strlen(name);
	വേണ്ടി (i = 0; env[i]; i++)
		എങ്കിൽ (strncmp(env[i], name, namelen) == 0 && env[i][namelen] == '=')
			നിർത്തുക;
	എങ്കിൽ (env[i]) {
		/* Reuse the slot. */
		സ്വതന്ത്രം(env[i]);
	} അല്ലെങ്കിൽ {
		/* New variable.  Expand if necessary. */
		envsize = *envsizep;
		എങ്കിൽ (i >= envsize - 1) {
			എങ്കിൽ (envsize >= 1000)
				fatal("child_set_env: too many env vars");
			envsize += 50;
			env = (*envp) = xreallocarray(env, envsize, വലുപ്പം(അക്ഷരം *));
			*envsizep = envsize;
		}
		/* Need to set the NULL pointer at end of array beyond the new slot. */
		env[i + 1] = ശൂന്യ;
	}

	/* Allocate space and format the variable in the appropriate slot. */
	/* XXX xasprintf */
	env[i] = xmalloc(strlen(name) + 1 + strlen(മൂല്യം) + 1);
	snprintf(env[i], strlen(name) + 1 + strlen(മൂല്യം) + 1, "%s=%s", name, മൂല്യം);
}

/*
 * Check and optionally lowercase a domain name, also removes trailing '.'
 * Returns 1 on success and 0 on failure, storing an error message in errstr.
 */
പൂർണ്ണസംഖ്യ
valid_domain(അക്ഷരം *name, പൂർണ്ണസംഖ്യ makelower, സ്ഥിരം അക്ഷരം **errstr)
{
	size_t i, l = strlen(name);
	u_char c, last = '\0';
	സ്ഥിതം അക്ഷരം errbuf[256];

	എങ്കിൽ (l == 0) {
		strlcpy(errbuf, "empty domain name", വലുപ്പം(errbuf));
		പോകുക bad;
	}
	എങ്കിൽ (!isalpha((u_char)name[0]) && !isdigit((u_char)name[0]) &&
	   name[0] != '_' /* technically invalid, but common */) {
		snprintf(errbuf, വലുപ്പം(errbuf), "domain name \"%.100s\" "
		    "starts with invalid character", name);
		പോകുക bad;
	}
	വേണ്ടി (i = 0; i < l; i++) {
		c = tolower((u_char)name[i]);
		എങ്കിൽ (makelower)
			name[i] = (അക്ഷരം)c;
		എങ്കിൽ (last == '.' && c == '.') {
			snprintf(errbuf, വലുപ്പം(errbuf), "domain name "
			    "\"%.100s\" contains consecutive separators", name);
			പോകുക bad;
		}
		എങ്കിൽ (c != '.' && c != '-' && !isalnum(c) &&
		    c != '_') /* technically invalid, but common */ {
			snprintf(errbuf, വലുപ്പം(errbuf), "domain name "
			    "\"%.100s\" contains invalid characters", name);
			പോകുക bad;
		}
		last = c;
	}
	എങ്കിൽ (name[l - 1] == '.')
		name[l - 1] = '\0';
	എങ്കിൽ (errstr != ശൂന്യ)
		*errstr = ശൂന്യ;
	തിരികെ 1;
bad:
	എങ്കിൽ (errstr != ശൂന്യ)
		*errstr = errbuf;
	തിരികെ 0;
}

/*
 * Verify that a environment variable name (not including initial '$') is
 * valid; consisting of one or more alphanumeric or underscore characters only.
 * Returns 1 on valid, 0 otherwise.
 */
പൂർണ്ണസംഖ്യ
valid_env_name(സ്ഥിരം അക്ഷരം *name)
{
	സ്ഥിരം അക്ഷരം *cp;

	എങ്കിൽ (name[0] == '\0')
		തിരികെ 0;
	വേണ്ടി (cp = name; *cp != '\0'; cp++) {
		എങ്കിൽ (!isalnum((u_char)*cp) && *cp != '_')
			തിരികെ 0;
	}
	തിരികെ 1;
}

സ്ഥിരം അക്ഷരം *
atoi_err(സ്ഥിരം അക്ഷരം *nptr, പൂർണ്ണസംഖ്യ *val)
{
	സ്ഥിരം അക്ഷരം *errstr = ശൂന്യ;

	എങ്കിൽ (nptr == ശൂന്യ || *nptr == '\0')
		തിരികെ "missing";
	*val = strtonum(nptr, 0, INT_MAX, &errstr);
	തിരികെ errstr;
}

പൂർണ്ണസംഖ്യ
parse_absolute_time(സ്ഥിരം അക്ഷരം *s, uint64_t *tp)
{
	ഘടന tm tm;
	time_t tt;
	അക്ഷരം buf[32], *fmt;
	സ്ഥിരം അക്ഷരം *cp;
	size_t l;
	പൂർണ്ണസംഖ്യ is_utc = 0;

	*tp = 0;

	l = strlen(s);
	എങ്കിൽ (l > 1 && strcasecmp(s + l - 1, "Z") == 0) {
		is_utc = 1;
		l--;
	} അല്ലെങ്കിൽ എങ്കിൽ (l > 3 && strcasecmp(s + l - 3, "UTC") == 0) {
		is_utc = 1;
		l -= 3;
	}
	/*
	 * POSIX strptime says "The application shall ensure that there
	 * is white-space or other non-alphanumeric characters between
	 * any two conversion specifications" so arrange things this way.
	 */
	തിരഞ്ഞെടുപ്പ് (l) {
	അവസ്ഥ 8: /* YYYYMMDD */
		fmt = "%Y-%m-%d";
		snprintf(buf, വലുപ്പം(buf), "%.4s-%.2s-%.2s", s, s + 4, s + 6);
		നിർത്തുക;
	അവസ്ഥ 12: /* YYYYMMDDHHMM */
		fmt = "%Y-%m-%dT%H:%M";
		snprintf(buf, വലുപ്പം(buf), "%.4s-%.2s-%.2sT%.2s:%.2s",
		    s, s + 4, s + 6, s + 8, s + 10);
		നിർത്തുക;
	അവസ്ഥ 14: /* YYYYMMDDHHMMSS */
		fmt = "%Y-%m-%dT%H:%M:%S";
		snprintf(buf, വലുപ്പം(buf), "%.4s-%.2s-%.2sT%.2s:%.2s:%.2s",
		    s, s + 4, s + 6, s + 8, s + 10, s + 12);
		നിർത്തുക;
	സ്ഥിരസ്ഥിതി:
		തിരികെ SSH_ERR_INVALID_FORMAT;
	}

	memset(&tm, 0, വലുപ്പം(tm));
	എങ്കിൽ ((cp = strptime(buf, fmt, &tm)) == ശൂന്യ || *cp != '\0')
		തിരികെ SSH_ERR_INVALID_FORMAT;
	എങ്കിൽ (is_utc) {
		tm.tm_wday = -1;	/* sentinel for error */
		എങ്കിൽ ((tt = timegm(&tm)) == -1 && tm.tm_wday == -1)
			തിരികെ SSH_ERR_INVALID_FORMAT;
	} അല്ലെങ്കിൽ {
		tm.tm_wday = -1;	/* sentinel for error */
		tm.tm_isdst = -1;	/* mktime decides DST */
		എങ്കിൽ ((tt = mktime(&tm)) == -1 && tm.tm_wday == -1)
			തിരികെ SSH_ERR_INVALID_FORMAT;
	}
	/* success */
	*tp = (uint64_t)tt;
	തിരികെ 0;
}

ശൂന്യം
format_absolute_time(uint64_t t, അക്ഷരം *buf, size_t len)
{
	time_t tt = t > SSH_TIME_T_MAX ? SSH_TIME_T_MAX : t;
	ഘടന tm tm;

	എങ്കിൽ (localtime_r(&tt, &tm) == ശൂന്യ)
		strlcpy(buf, "UNKNOWN-TIME", len);
	അല്ലെങ്കിൽ
		strftime(buf, len, "%Y-%m-%dT%H:%M:%S", &tm);
}

/*
 * Parse a "pattern=interval" clause (e.g. a ChannelTimeout).
 * Returns 0 on success or non-zero on failure.
 * Caller must free *typep.
 */
പൂർണ്ണസംഖ്യ
parse_pattern_interval(സ്ഥിരം അക്ഷരം *s, അക്ഷരം **typep, ഇരട്ട *secsp)
{
	അക്ഷരം *cp, *sdup;
	ഇരട്ട secs;

	എങ്കിൽ (typep != ശൂന്യ)
		*typep = ശൂന്യ;
	എങ്കിൽ (secsp != ശൂന്യ)
		*secsp = 0;
	എങ്കിൽ (s == ശൂന്യ)
		തിരികെ -1;
	sdup = xstrdup(s);

	എങ്കിൽ ((cp = strchr(sdup, '=')) == ശൂന്യ || cp == sdup) {
		സ്വതന്ത്രം(sdup);
		തിരികെ -1;
	}
	*cp++ = '\0';
	എങ്കിൽ ((secs = convtime_double(cp)) < 0.0) {
		സ്വതന്ത്രം(sdup);
		തിരികെ -1;
	}
	/* success */
	എങ്കിൽ (typep != ശൂന്യ)
		*typep = xstrdup(sdup);
	എങ്കിൽ (secsp != ശൂന്യ)
		*secsp = secs;
	സ്വതന്ത്രം(sdup);
	തിരികെ 0;
}

/* check if path is absolute */
പൂർണ്ണസംഖ്യ
path_absolute(സ്ഥിരം അക്ഷരം *path)
{
	തിരികെ (*path == '/') ? 1 : 0;
}

ശൂന്യം
skip_space(അക്ഷരം **cpp)
{
	അക്ഷരം *cp;

	വേണ്ടി (cp = *cpp; *cp == ' ' || *cp == '\t'; cp++)
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
പൂർണ്ണസംഖ്യ
opt_flag(സ്ഥിരം അക്ഷരം *opt, പൂർണ്ണസംഖ്യ allow_negate, സ്ഥിരം അക്ഷരം **optsp)
{
	size_t opt_len = strlen(opt);
	സ്ഥിരം അക്ഷരം *opts = *optsp;
	പൂർണ്ണസംഖ്യ negate = 0;

	എങ്കിൽ (allow_negate && strncasecmp(opts, "no-", 3) == 0) {
		opts += 3;
		negate = 1;
	}
	എങ്കിൽ (strncasecmp(opts, opt, opt_len) == 0) {
		*optsp = opts + opt_len;
		തിരികെ negate ? 0 : 1;
	}
	തിരികെ -1;
}

അക്ഷരം *
opt_dequote(സ്ഥിരം അക്ഷരം **sp, സ്ഥിരം അക്ഷരം **errstrp)
{
	സ്ഥിരം അക്ഷരം *s = *sp;
	അക്ഷരം *ret;
	size_t i;

	*errstrp = ശൂന്യ;
	എങ്കിൽ (*s != '"') {
		*errstrp = "missing start quote";
		തിരികെ ശൂന്യ;
	}
	s++;
	എങ്കിൽ ((ret = malloc(strlen((s)) + 1)) == ശൂന്യ) {
		*errstrp = "memory allocation failed";
		തിരികെ ശൂന്യ;
	}
	വേണ്ടി (i = 0; *s != '\0' && *s != '"';) {
		എങ്കിൽ (s[0] == '\\' && s[1] == '"')
			s++;
		ret[i++] = *s++;
	}
	എങ്കിൽ (*s == '\0') {
		*errstrp = "missing end quote";
		സ്വതന്ത്രം(ret);
		തിരികെ ശൂന്യ;
	}
	ret[i] = '\0';
	s++;
	*sp = s;
	തിരികെ ret;
}

പൂർണ്ണസംഖ്യ
opt_match(സ്ഥിരം അക്ഷരം **opts, സ്ഥിരം അക്ഷരം *term)
{
	എങ്കിൽ (strncasecmp((*opts), term, strlen(term)) == 0 &&
	    (*opts)[strlen(term)] == '=') {
		*opts += strlen(term) + 1;
		തിരികെ 1;
	}
	തിരികെ 0;
}

ശൂന്യം
opt_array_append2(സ്ഥിരം അക്ഷരം *file, സ്ഥിരം പൂർണ്ണസംഖ്യ വരി, സ്ഥിരം അക്ഷരം *directive,
    അക്ഷരം ***array, പൂർണ്ണസംഖ്യ **iarray, u_int *lp, സ്ഥിരം അക്ഷരം *s, പൂർണ്ണസംഖ്യ i)
{

	എങ്കിൽ (*lp >= INT_MAX)
		fatal("%s line %d: Too many %s entries", file, വരി, directive);

	എങ്കിൽ (iarray != ശൂന്യ) {
		*iarray = xrecallocarray(*iarray, *lp, *lp + 1,
		    വലുപ്പം(**iarray));
		(*iarray)[*lp] = i;
	}

	*array = xrecallocarray(*array, *lp, *lp + 1, വലുപ്പം(**array));
	(*array)[*lp] = xstrdup(s);
	(*lp)++;
}

ശൂന്യം
opt_array_append(സ്ഥിരം അക്ഷരം *file, സ്ഥിരം പൂർണ്ണസംഖ്യ വരി, സ്ഥിരം അക്ഷരം *directive,
    അക്ഷരം ***array, u_int *lp, സ്ഥിരം അക്ഷരം *s)
{
	opt_array_append2(file, വരി, directive, array, ശൂന്യ, lp, s, 0);
}

ശൂന്യം
opt_array_free2(അക്ഷരം **array, പൂർണ്ണസംഖ്യ **iarray, u_int l)
{
	u_int i;

	എങ്കിൽ (array == ശൂന്യ || l == 0)
		തിരികെ;
	വേണ്ടി (i = 0; i < l; i++)
		സ്വതന്ത്രം(array[i]);
	സ്വതന്ത്രം(array);
	സ്വതന്ത്രം(iarray);
}

sshsig_t
ssh_signal(പൂർണ്ണസംഖ്യ signum, sshsig_t handler)
{
	ഘടന sigaction sa, osa;

	/* mask all other signals while in handler */
	memset(&sa, 0, വലുപ്പം(sa));
	sa.sa_handler = handler;
	sigfillset(&sa.sa_mask);
#എങ്കിൽ defined(SA_RESTART) && !defined(NO_SA_RESTART)
	എങ്കിൽ (signum != SIGALRM)
		sa.sa_flags = SA_RESTART;
#endif
	എങ്കിൽ (sigaction(signum, &sa, &osa) == -1) {
		debug3("sigaction(%s): %s", strsignal(signum), strerror(errno));
		തിരികെ SIG_ERR;
	}
	തിരികെ osa.sa_handler;
}

പൂർണ്ണസംഖ്യ
stdfd_devnull(പൂർണ്ണസംഖ്യ do_stdin, പൂർണ്ണസംഖ്യ do_stdout, പൂർണ്ണസംഖ്യ do_stderr)
{
	പൂർണ്ണസംഖ്യ devnull, ret = 0;

	എങ്കിൽ ((devnull = open(_PATH_DEVNULL, O_RDWR)) == -1) {
		error_f("open %s: %s", _PATH_DEVNULL,
		    strerror(errno));
		തിരികെ -1;
	}
	എങ്കിൽ ((do_stdin && dup2(devnull, STDIN_FILENO) == -1) ||
	    (do_stdout && dup2(devnull, STDOUT_FILENO) == -1) ||
	    (do_stderr && dup2(devnull, STDERR_FILENO) == -1)) {
		error_f("dup2: %s", strerror(errno));
		ret = -1;
	}
	എങ്കിൽ (devnull > STDERR_FILENO)
		close(devnull);
	തിരികെ ret;
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
subprocess(സ്ഥിരം അക്ഷരം *tag, സ്ഥിരം അക്ഷരം *command,
    പൂർണ്ണസംഖ്യ ac, അക്ഷരം **av, FILE **child, u_int flags,
    ഘടന passwd *pw, privdrop_fn *drop_privs, privrestore_fn *restore_privs)
{
	FILE *f = ശൂന്യ;
	ഘടന stat st;
	പൂർണ്ണസംഖ്യ fd, devnull, p[2], i;
	pid_t pid;
	അക്ഷരം *cp, errmsg[512];
	u_int nenv = 0;
	അക്ഷരം **env = ശൂന്യ;

	/* If dropping privs, then must specify user and restore function */
	എങ്കിൽ (drop_privs != ശൂന്യ && (pw == ശൂന്യ || restore_privs == ശൂന്യ)) {
		error("%s: inconsistent arguments", tag); /* XXX fatal? */
		തിരികെ 0;
	}
	എങ്കിൽ (pw == ശൂന്യ && (pw = getpwuid(getuid())) == ശൂന്യ) {
		error("%s: no user for current uid", tag);
		തിരികെ 0;
	}
	എങ്കിൽ (child != ശൂന്യ)
		*child = ശൂന്യ;

	debug3_f("%s command \"%s\" running as %s (flags 0x%x)",
	    tag, command, pw->pw_name, flags);

	/* Check consistency */
	എങ്കിൽ ((flags & SSH_SUBPROCESS_STDOUT_DISCARD) != 0 &&
	    (flags & SSH_SUBPROCESS_STDOUT_CAPTURE) != 0) {
		error_f("inconsistent flags");
		തിരികെ 0;
	}
	എങ്കിൽ (((flags & SSH_SUBPROCESS_STDOUT_CAPTURE) == 0) != (child == ശൂന്യ)) {
		error_f("inconsistent flags/output");
		തിരികെ 0;
	}

	/*
	 * If executing an explicit binary, then verify the it exists
	 * and appears safe-ish to execute
	 */
	എങ്കിൽ (!path_absolute(av[0])) {
		error("%s path is not absolute", tag);
		തിരികെ 0;
	}
	എങ്കിൽ (drop_privs != ശൂന്യ)
		drop_privs(pw);
	എങ്കിൽ (stat(av[0], &st) == -1) {
		error("Could not stat %s \"%s\": %s", tag,
		    av[0], strerror(errno));
		പോകുക restore_return;
	}
	എങ്കിൽ ((flags & SSH_SUBPROCESS_UNSAFE_PATH) == 0 &&
	    safe_path(av[0], &st, ശൂന്യ, 0, errmsg, വലുപ്പം(errmsg)) != 0) {
		error("Unsafe %s \"%s\": %s", tag, av[0], errmsg);
		പോകുക restore_return;
	}
	/* Prepare to keep the child's stdout if requested */
	എങ്കിൽ (pipe(p) == -1) {
		error("%s: pipe: %s", tag, strerror(errno));
 restore_return:
		എങ്കിൽ (restore_privs != ശൂന്യ)
			restore_privs();
		തിരികെ 0;
	}
	എങ്കിൽ (restore_privs != ശൂന്യ)
		restore_privs();

	തിരഞ്ഞെടുപ്പ് ((pid = fork())) {
	അവസ്ഥ -1: /* error */
		error("%s: fork: %s", tag, strerror(errno));
		close(p[0]);
		close(p[1]);
		തിരികെ 0;
	അവസ്ഥ 0: /* child */
		/* Prepare a minimal environment for the child. */
		എങ്കിൽ ((flags & SSH_SUBPROCESS_PRESERVE_ENV) == 0) {
			nenv = 5;
			env = xcalloc(വലുപ്പം(*env), nenv);
			child_set_env(&env, &nenv, "PATH", _PATH_STDPATH);
			child_set_env(&env, &nenv, "USER", pw->pw_name);
			child_set_env(&env, &nenv, "LOGNAME", pw->pw_name);
			child_set_env(&env, &nenv, "HOME", pw->pw_dir);
			എങ്കിൽ ((cp = getenv("LANG")) != ശൂന്യ)
				child_set_env(&env, &nenv, "LANG", cp);
		}

		വേണ്ടി (i = 1; i < NSIG; i++)
			ssh_signal(i, SIG_DFL);

		എങ്കിൽ ((devnull = open(_PATH_DEVNULL, O_RDWR)) == -1) {
			error("%s: open %s: %s", tag, _PATH_DEVNULL,
			    strerror(errno));
			_exit(1);
		}
		എങ്കിൽ (dup2(devnull, STDIN_FILENO) == -1) {
			error("%s: dup2: %s", tag, strerror(errno));
			_exit(1);
		}

		/* Set up stdout as requested; leave stderr in place for now. */
		fd = -1;
		എങ്കിൽ ((flags & SSH_SUBPROCESS_STDOUT_CAPTURE) != 0)
			fd = p[1];
		അല്ലെങ്കിൽ എങ്കിൽ ((flags & SSH_SUBPROCESS_STDOUT_DISCARD) != 0)
			fd = devnull;
		എങ്കിൽ (fd != -1 && dup2(fd, STDOUT_FILENO) == -1) {
			error("%s: dup2: %s", tag, strerror(errno));
			_exit(1);
		}
		closefrom(STDERR_FILENO + 1);

		എങ്കിൽ (geteuid() == 0 &&
		    initgroups(pw->pw_name, pw->pw_gid) == -1) {
			error("%s: initgroups(%s, %u): %s", tag,
			    pw->pw_name, (u_int)pw->pw_gid, strerror(errno));
			_exit(1);
		}
		എങ്കിൽ (setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) == -1) {
			error("%s: setresgid %u: %s", tag, (u_int)pw->pw_gid,
			    strerror(errno));
			_exit(1);
		}
		എങ്കിൽ (setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) == -1) {
			error("%s: setresuid %u: %s", tag, (u_int)pw->pw_uid,
			    strerror(errno));
			_exit(1);
		}
		/* stdin is pointed to /dev/null at this point */
		എങ്കിൽ ((flags & SSH_SUBPROCESS_STDOUT_DISCARD) != 0 &&
		    dup2(STDIN_FILENO, STDERR_FILENO) == -1) {
			error("%s: dup2: %s", tag, strerror(errno));
			_exit(1);
		}
		എങ്കിൽ (env != ശൂന്യ)
			execve(av[0], av, env);
		അല്ലെങ്കിൽ
			execv(av[0], av);
		error("%s %s \"%s\": %s", tag, env == ശൂന്യ ? "execv" : "execve",
		    command, strerror(errno));
		_exit(127);
	സ്ഥിരസ്ഥിതി: /* parent */
		നിർത്തുക;
	}

	close(p[1]);
	എങ്കിൽ ((flags & SSH_SUBPROCESS_STDOUT_CAPTURE) == 0)
		close(p[0]);
	അല്ലെങ്കിൽ എങ്കിൽ ((f = fdopen(p[0], "r")) == ശൂന്യ) {
		error("%s: fdopen: %s", tag, strerror(errno));
		close(p[0]);
		/* Don't leave zombie child */
		kill(pid, SIGTERM);
		ആകുമ്പോൾ (waitpid(pid, ശൂന്യ, 0) == -1 && errno == EINTR)
			;
		തിരികെ 0;
	}
	/* Success */
	debug3_f("%s pid %ld", tag, (long)pid);
	എങ്കിൽ (child != ശൂന്യ)
		*child = f;
	തിരികെ pid;
}

സ്ഥിരം അക്ഷരം *
lookup_env_in_list(സ്ഥിരം അക്ഷരം *env, അക്ഷരം * സ്ഥിരം *envs, size_t nenvs)
{
	size_t i, envlen;

	envlen = strlen(env);
	വേണ്ടി (i = 0; i < nenvs; i++) {
		എങ്കിൽ (strncmp(envs[i], env, envlen) == 0 &&
		    envs[i][envlen] == '=') {
			തിരികെ envs[i] + envlen + 1;
		}
	}
	തിരികെ ശൂന്യ;
}

സ്ഥിരം അക്ഷരം *
lookup_setenv_in_list(സ്ഥിരം അക്ഷരം *env, അക്ഷരം * സ്ഥിരം *envs, size_t nenvs)
{
	അക്ഷരം *name, *cp;
	സ്ഥിരം അക്ഷരം *ret;

	name = xstrdup(env);
	എങ്കിൽ ((cp = strchr(name, '=')) == ശൂന്യ) {
		സ്വതന്ത്രം(name);
		തിരികെ ശൂന്യ; /* not env=val */
	}
	*cp = '\0';
	ret = lookup_env_in_list(name, envs, nenvs);
	സ്വതന്ത്രം(name);
	തിരികെ ret;
}

/*
 * Helpers for managing poll(2)/ppoll(2) timeouts
 * Will remember the earliest deadline and return it for use in poll/ppoll.
 */

/* Initialise a poll/ppoll timeout with an indefinite deadline */
ശൂന്യം
ptimeout_init(ഘടന timespec *pt)
{
	/*
	 * Deliberately invalid for ppoll(2).
	 * Will be converted to NULL in ptimeout_get_tspec() later.
	 */
	pt->tv_sec = -1;
	pt->tv_nsec = 0;
}

/* Specify a poll/ppoll deadline of at most 'sec' seconds */
ശൂന്യം
ptimeout_deadline_sec(ഘടന timespec *pt, long sec)
{
	എങ്കിൽ (pt->tv_sec == -1 || pt->tv_sec >= sec) {
		pt->tv_sec = sec;
		pt->tv_nsec = 0;
	}
}

/* Specify a poll/ppoll deadline of at most 'p' (timespec) */
സ്ഥിതം ശൂന്യം
ptimeout_deadline_tsp(ഘടന timespec *pt, ഘടന timespec *p)
{
	എങ്കിൽ (pt->tv_sec == -1 || timespeccmp(pt, p, >=))
		*pt = *p;
}

/* Specify a poll/ppoll deadline of at most 'ms' milliseconds */
ശൂന്യം
ptimeout_deadline_ms(ഘടന timespec *pt, long ms)
{
	ഘടന timespec p;

	p.tv_sec = ms / 1000;
	p.tv_nsec = (ms % 1000) * 1000000;
	ptimeout_deadline_tsp(pt, &p);
}

/* Specify a poll/ppoll deadline of at most 'sec' seconds (double) */
ശൂന്യം
ptimeout_deadline_sec_double(ഘടന timespec *pt, ഇരട്ട sec)
{
	ഘടന timespec t;

	memset(&t, 0, വലുപ്പം(t));
	എങ്കിൽ ((int64_t)sec >= SSH_TIME_T_MAX)
		t.tv_sec = SSH_TIME_T_MAX;
	അല്ലെങ്കിൽ എങ്കിൽ (sec > 0) {
		t.tv_sec = sec;
		t.tv_nsec = (sec - (ഇരട്ട)t.tv_sec) * 1000000000.0;
	}
	ptimeout_deadline_tsp(pt, &t);
}

/* Specify a poll/ppoll deadline at wall clock monotime 'when' (timespec) */
ശൂന്യം
ptimeout_deadline_monotime_tsp(ഘടന timespec *pt, ഘടന timespec *when)
{
	ഘടന timespec now, t;

	monotime_ts(&now);

	എങ്കിൽ (timespeccmp(&now, when, >=)) {
		/* 'when' is now or in the past. Timeout ASAP */
		pt->tv_sec = 0;
		pt->tv_nsec = 0;
	} അല്ലെങ്കിൽ {
		timespecsub(when, &now, &t);
		ptimeout_deadline_tsp(pt, &t);
	}
}

/* Specify a poll/ppoll deadline at wall clock monotime 'when' (double) */
ശൂന്യം
ptimeout_deadline_monotime_double(ഘടന timespec *pt, ഇരട്ട when)
{
	ptimeout_deadline_sec_double(pt, when - monotime_double());
}

/* Specify a poll/ppoll deadline at wall clock monotime 'when' */
ശൂന്യം
ptimeout_deadline_monotime(ഘടന timespec *pt, time_t when)
{
	ഘടന timespec t;

	t.tv_sec = when;
	t.tv_nsec = 0;
	ptimeout_deadline_monotime_tsp(pt, &t);
}

/* Get a poll(2) timeout value in milliseconds */
പൂർണ്ണസംഖ്യ
ptimeout_get_ms(ഘടന timespec *pt)
{
	എങ്കിൽ (pt->tv_sec == -1)
		തിരികെ -1;
	എങ്കിൽ (pt->tv_sec >= (INT_MAX - (pt->tv_nsec / 1000000)) / 1000)
		തിരികെ INT_MAX;
	തിരികെ (pt->tv_sec * 1000) + (pt->tv_nsec / 1000000);
}

/* Get a ppoll(2) timeout value as a timespec pointer */
ഘടന timespec *
ptimeout_get_tsp(ഘടന timespec *pt)
{
	തിരികെ pt->tv_sec == -1 ? ശൂന്യ : pt;
}

/* Returns non-zero if a timeout has been set (i.e. is not indefinite) */
പൂർണ്ണസംഖ്യ
ptimeout_isset(ഘടന timespec *pt)
{
	തിരികെ pt->tv_sec != -1;
}

/*
 * Returns zero if the library at 'path' contains symbol 's', nonzero
 * otherwise.
 */
പൂർണ്ണസംഖ്യ
lib_contains_ചിഹ്നം(സ്ഥിരം അക്ഷരം *path, സ്ഥിരം അക്ഷരം *s)
{
#ifdef HAVE_NLIST
	ഘടന nlist nl[2];
	പൂർണ്ണസംഖ്യ ret = -1, r;

	memset(nl, 0, വലുപ്പം(nl));
	nl[0].n_name = xstrdup(s);
	nl[1].n_name = ശൂന്യ;
	എങ്കിൽ ((r = nlist(path, nl)) == -1) {
		error_f("nlist failed for %s", path);
		പോകുക out;
	}
	എങ്കിൽ (r != 0 || nl[0].n_മൂല്യം == 0 || nl[0].n_type == 0) {
		error_f("library %s does not contain symbol %s", path, s);
		പോകുക out;
	}
	/* success */
	ret = 0;
 out:
	സ്വതന്ത്രം(nl[0].n_name);
	തിരികെ ret;
#അല്ലെങ്കിൽ /* HAVE_NLIST */
	പൂർണ്ണസംഖ്യ fd, ret = -1;
	ഘടന stat st;
	ശൂന്യം *m = ശൂന്യ;
	size_t sz = 0;

	memset(&st, 0, വലുപ്പം(st));
	എങ്കിൽ ((fd = open(path, O_RDONLY)) < 0) {
		error_f("open %s: %s", path, strerror(errno));
		തിരികെ -1;
	}
	എങ്കിൽ (fstat(fd, &st) != 0) {
		error_f("fstat %s: %s", path, strerror(errno));
		പോകുക out;
	}
	എങ്കിൽ (!S_ISREG(st.st_mode)) {
		error_f("%s is not a regular file", path);
		പോകുക out;
	}
	എങ്കിൽ (st.st_size < 0 ||
	    (size_t)st.st_size < strlen(s) ||
	    st.st_size >= INT_MAX/2) {
		error_f("%s bad size %lld", path, (long long)st.st_size);
		പോകുക out;
	}
	sz = (size_t)st.st_size;
	എങ്കിൽ ((m = mmap(ശൂന്യ, sz, PROT_READ, MAP_PRIVATE, fd, 0)) == MAP_FAILED ||
	    m == ശൂന്യ) {
		error_f("mmap %s: %s", path, strerror(errno));
		പോകുക out;
	}
	എങ്കിൽ (memmem(m, sz, s, strlen(s)) == ശൂന്യ) {
		error_f("%s does not contain expected string %s", path, s);
		പോകുക out;
	}
	/* success */
	ret = 0;
 out:
	എങ്കിൽ (m != ശൂന്യ && m != MAP_FAILED)
		munmap(m, sz);
	close(fd);
	തിരികെ ret;
#endif /* HAVE_NLIST */
}

പൂർണ്ണസംഖ്യ
signal_is_crash(പൂർണ്ണസംഖ്യ sig)
{
	തിരഞ്ഞെടുപ്പ് (sig) {
	അവസ്ഥ SIGSEGV:
	അവസ്ഥ SIGBUS:
	അവസ്ഥ SIGTRAP:
	അവസ്ഥ SIGSYS:
	അവസ്ഥ SIGFPE:
	അവസ്ഥ SIGILL:
	അവസ്ഥ SIGABRT:
		തിരികെ 1;
	}
	തിരികെ 0;
}

അക്ഷരം *
get_homedir(ശൂന്യം)
{
	അക്ഷരം *cp;
	ഘടന passwd *pw;

	എങ്കിൽ ((cp = getenv("HOME")) != ശൂന്യ && *cp != '\0')
		തിരികെ xstrdup(cp);

	എങ്കിൽ ((pw = getpwuid(getuid())) != ശൂന്യ && *pw->pw_dir != '\0')
		തിരികെ xstrdup(pw->pw_dir);

	തിരികെ ശൂന്യ;
}

പൂർണ്ണസംഖ്യ
mkdir_path(സ്ഥിരം അക്ഷരം *target, mode_t mode)
{
#എങ്കിൽ defined(HAVE_OPENAT) && defined(O_DIRECTORY)
	അക്ഷരം *dir, *odir = ശൂന്യ, *next;
	പൂർണ്ണസംഖ്യ fd = AT_FDCWD, fd2, subpath_len, ret = -1;

	dir = odir = xstrdup(target);

	എങ്കിൽ (*dir == '/' &&
	    (fd = open("/", O_RDONLY|O_DIRECTORY)) == -1) {
		error_f("open(\"/\"): %s", strerror(errno));
		സ്വതന്ത്രം(odir);
		തിരികെ -1;
	}
	/* Work through the path, component-wise */
	വേണ്ടി (; dir != ശൂന്യ && *dir != '\0'; dir = next) {
		എങ്കിൽ ((next = strchr(dir, '/')) != ശൂന്യ)
			*(next++) = '\0';
		എങ്കിൽ (*dir == '\0')
			തുടരുക;
		subpath_len = (next == ശൂന്യ) ? INT_MAX : next - odir - 1;
		എങ്കിൽ (mkdirat(fd, dir, mode) == 0)
			debug_f("created directory %.*s", subpath_len, target);
		അല്ലെങ്കിൽ എങ്കിൽ (errno != EEXIST) {
			error_f("mkdir(\"%.*s\"): %s",
			    subpath_len, target, strerror(errno));
			പോകുക out;
		}

		/* descend */
		എങ്കിൽ ((fd2 = openat(fd, dir, O_RDONLY|O_DIRECTORY)) == -1) {
			error_f("open(\"%.*s\"): %s",
			    subpath_len, target, strerror(errno));
			പോകുക out;
		}
		എങ്കിൽ (fd != AT_FDCWD)
			close(fd);
		fd = fd2;
	}
	/* success */
	ret = 0;
 out:
	സ്വതന്ത്രം(odir);
	എങ്കിൽ (fd != AT_FDCWD)
		close(fd);
	തിരികെ ret;
#അല്ലെങ്കിൽ
	/*
	 * If we don't have openat (which was added in POSIX.1-2008), fall back
	 * to the possibly racy way.
	 */
	അക്ഷരം *dir, *odir, *p, path[PATH_MAX] = "";
	പൂർണ്ണസംഖ്യ ret = -1;
	size_t plen = വലുപ്പം(path);

	dir = odir = xstrdup(target);

	/* If the dir is relative, start with cwd. */
	എങ്കിൽ (*dir != '/' && getcwd(path, plen) == ശൂന്യ) {
		error_f("getcwd: %s", strerror(errno));
		പോകുക out;
	}

	/* Work through the path, component-wise */
	ആകുമ്പോൾ ((p = strsep(&dir, "/"))) {
		എങ്കിൽ (*p == '\0')
			തുടരുക;
		എങ്കിൽ (strlcat(path, "/", plen) >= plen ||
		    strlcat(path, p, plen) >= plen)
			പോകുക out;
		എങ്കിൽ (mkdir(path, mode) == 0)
			debug_f("created directory %s", path);
		അല്ലെങ്കിൽ എങ്കിൽ (errno != EEXIST && errno != EISDIR) {
			error_f("mkdir(\"%s\"): %s", path, strerror(errno));
			പോകുക out;
		}
	}
	/* success */
	ret = 0;
 out:
	സ്വതന്ത്രം(odir);
	തിരികെ ret;
#endif
}
