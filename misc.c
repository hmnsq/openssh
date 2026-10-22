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


#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/ioctl.h>
#अन्तर्भाव <sys/mman.h>
#अन्तर्भाव <sys/socket.h>
#अन्तर्भाव <sys/stat.h>
#अन्तर्भाव <sys/time.h>
#अन्तर्भाव <sys/wait.h>
#अन्तर्भाव <sys/un.h>

#अन्तर्भाव <limits.h>
#अन्तर्भाव <libgen.h>
#अन्तर्भाव <poll.h>
#अन्तर्भाव <nlist.h>
#अन्तर्भाव <signal.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdint.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <time.h>
#अन्तर्भाव <unistd.h>

#अन्तर्भाव <netinet/in.h>
#अन्तर्भाव <netinet/ip.h>
#अन्तर्भाव <netinet/tcp.h>
#अन्तर्भाव <arpa/inet.h>

#अन्तर्भाव <ctype.h>
#अन्तर्भाव <errno.h>
#अन्तर्भाव <fcntl.h>
#अन्तर्भाव <netdb.h>
#अन्तर्भाव <paths.h>
#अन्तर्भाव <pwd.h>
#अन्तर्भाव <grp.h>
#ifdef SSH_TUN_OPENBSD
#अन्तर्भाव <net/if.h>
#endif

#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "ssh.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "platform.h"

/* remove newline at end of string */
वर्ण *
chop(वर्ण *s)
{
	वर्ण *t = s;
	याव (*t) {
		सचे (*t == '\n' || *t == '\r') {
			*t = '\0';
			पटिनिवत्त s;
		}
		t++;
	}
	पटिनिवत्त s;

}

/* remove whitespace from end of string */
शून्य
rtrim(वर्ण *s)
{
	size_t i;

	सचे ((i = strlen(s)) == 0)
		पटिनिवत्त;
	करोहि {
		i--;
		सचे (isspace((unsigned वर्ण)s[i]))
			s[i] = '\0';
		अञ्ञथा
			भङ्ग;
	} याव (i > 0);
}

/*
 * returns pointer to character after 'prefix' in 's' or otherwise NULL
 * if the prefix is not present.
 */
ध्रुव वर्ण *
strprefix(ध्रुव वर्ण *s, ध्रुव वर्ण *prefix, पूर्णाङ्क ignorecase)
{
	size_t prefixlen;

	सचे ((prefixlen = strlen(prefix)) == 0)
		पटिनिवत्त s;
	सचे (ignorecase) {
		सचे (strncasecmp(s, prefix, prefixlen) != 0)
			पटिनिवत्त रिक्त;
	} अञ्ञथा {
		सचे (strncmp(s, prefix, prefixlen) != 0)
			पटिनिवत्त रिक्त;
	}
	पटिनिवत्त s + prefixlen;
}

/* Append string 's' to a NULL-terminated array of strings */
शून्य
stringlist_append(वर्ण ***listp, ध्रुव वर्ण *s)
{
	size_t i = 0;

	सचे (*listp == रिक्त)
		*listp = xcalloc(2, परिमाण(**listp));
	अञ्ञथा {
		अत्थाय (i = 0; (*listp)[i] != रिक्त; i++)
			; /* count */
		*listp = xrecallocarray(*listp, i + 1, i + 2, परिमाण(**listp));
	}
	(*listp)[i] = xstrdup(s);
}

शून्य
stringlist_free(वर्ण **list)
{
	size_t i = 0;

	सचे (list == रिक्त)
		पटिनिवत्त;
	अत्थाय (i = 0; list[i] != रिक्त; i++)
		मुक्त(list[i]);
	मुक्त(list);
}

/* set/unset filedescriptor to non-blocking */
पूर्णाङ्क
set_nonblock(पूर्णाङ्क fd)
{
	पूर्णाङ्क val;

	val = fcntl(fd, F_GETFL);
	सचे (val == -1) {
		error("fcntl(%d, F_GETFL): %s", fd, strerror(errno));
		पटिनिवत्त (-1);
	}
	सचे (val & O_NONBLOCK) {
		debug3("fd %d is O_NONBLOCK", fd);
		पटिनिवत्त (0);
	}
	debug2("fd %d setting O_NONBLOCK", fd);
	val |= O_NONBLOCK;
	सचे (fcntl(fd, F_SETFL, val) == -1) {
		debug("fcntl(%d, F_SETFL, O_NONBLOCK): %s", fd,
		    strerror(errno));
		पटिनिवत्त (-1);
	}
	पटिनिवत्त (0);
}

पूर्णाङ्क
unset_nonblock(पूर्णाङ्क fd)
{
	पूर्णाङ्क val;

	val = fcntl(fd, F_GETFL);
	सचे (val == -1) {
		error("fcntl(%d, F_GETFL): %s", fd, strerror(errno));
		पटिनिवत्त (-1);
	}
	सचे (!(val & O_NONBLOCK)) {
		debug3("fd %d is not O_NONBLOCK", fd);
		पटिनिवत्त (0);
	}
	debug("fd %d clearing O_NONBLOCK", fd);
	val &= ~O_NONBLOCK;
	सचे (fcntl(fd, F_SETFL, val) == -1) {
		debug("fcntl(%d, F_SETFL, ~O_NONBLOCK): %s",
		    fd, strerror(errno));
		पटिनिवत्त (-1);
	}
	पटिनिवत्त (0);
}

ध्रुव वर्ण *
ssh_gai_strerror(पूर्णाङ्क gaierr)
{
	सचे (gaierr == EAI_SYSTEM && errno != 0)
		पटिनिवत्त strerror(errno);
	पटिनिवत्त gai_strerror(gaierr);
}

/* disable nagle on socket */
शून्य
set_nodelay(पूर्णाङ्क fd)
{
	पूर्णाङ्क opt;
	socklen_t optlen;

	optlen = परिमाण opt;
	सचे (getsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, &optlen) == -1) {
		debug("getsockopt TCP_NODELAY: %.100s", strerror(errno));
		पटिनिवत्त;
	}
	सचे (opt == 1) {
		debug2("fd %d is TCP_NODELAY", fd);
		पटिनिवत्त;
	}
	opt = 1;
	debug2("fd %d setting TCP_NODELAY", fd);
	सचे (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, परिमाण opt) == -1)
		error("setsockopt TCP_NODELAY: %.100s", strerror(errno));
}

/* Allow local port reuse in TIME_WAIT */
पूर्णाङ्क
set_reuseaddr(पूर्णाङ्क fd)
{
	पूर्णाङ्क on = 1;

	सचे (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, परिमाण(on)) == -1) {
		error("setsockopt SO_REUSEADDR fd %d: %s", fd, strerror(errno));
		पटिनिवत्त -1;
	}
	पटिनिवत्त 0;
}

/* Set TCP keepalives */
पूर्णाङ्क
set_keepalive(पूर्णाङ्क fd)
{
	पूर्णाङ्क on = 1;

	सचे (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, परिमाण(on)) == -1) {
		error("setsockopt SO_KEEPALIVE fd %d: %s", fd, strerror(errno));
		पटिनिवत्त -1;
	}
	पटिनिवत्त 0;
}

/* Get/set routing domain */
वर्ण *
get_rdomain(पूर्णाङ्क fd)
{
#सचे defined(HAVE_SYS_GET_RDOMAIN)
	पटिनिवत्त sys_get_rdomain(fd);
#नोचेद्यदि defined(__OpenBSD__)
	पूर्णाङ्क rtable;
	वर्ण *ret;
	socklen_t len = परिमाण(rtable);

	सचे (getsockopt(fd, SOL_SOCKET, SO_RTABLE, &rtable, &len) == -1) {
		error("Failed to get routing domain for fd %d: %s",
		    fd, strerror(errno));
		पटिनिवत्त रिक्त;
	}
	xasprintf(&ret, "%d", rtable);
	पटिनिवत्त ret;
#अञ्ञथा /* defined(__OpenBSD__) */
	पटिनिवत्त रिक्त;
#endif
}

पूर्णाङ्क
set_rdomain(पूर्णाङ्क fd, ध्रुव वर्ण *name)
{
#सचे defined(HAVE_SYS_SET_RDOMAIN)
	पटिनिवत्त sys_set_rdomain(fd, name);
#नोचेद्यदि defined(__OpenBSD__)
	पूर्णाङ्क rtable;
	ध्रुव वर्ण *errstr;

	सचे (name == रिक्त)
		पटिनिवत्त 0; /* default table */

	rtable = (पूर्णाङ्क)strtonum(name, 0, 255, &errstr);
	सचे (errstr != रिक्त) {
		/* Shouldn't happen */
		error("Invalid routing domain \"%s\": %s", name, errstr);
		पटिनिवत्त -1;
	}
	सचे (setsockopt(fd, SOL_SOCKET, SO_RTABLE,
	    &rtable, परिमाण(rtable)) == -1) {
		error("Failed to set routing domain %d on fd %d: %s",
		    rtable, fd, strerror(errno));
		पटिनिवत्त -1;
	}
	पटिनिवत्त 0;
#अञ्ञथा /* defined(__OpenBSD__) */
	error("Setting routing domain is not supported on this platform");
	पटिनिवत्त -1;
#endif
}

पूर्णाङ्क
get_sock_af(पूर्णाङ्क fd)
{
	संरचना sockaddr_storage to;
	socklen_t tolen = परिमाण(to);

	memset(&to, 0, परिमाण(to));
	सचे (getsockname(fd, (संरचना sockaddr *)&to, &tolen) == -1)
		पटिनिवत्त -1;
#ifdef IPV4_IN_IPV6
	सचे (to.ss_family == AF_INET6 &&
	    IN6_IS_ADDR_V4MAPPED(&((संरचना sockaddr_in6 *)&to)->sin6_addr))
		पटिनिवत्त AF_INET;
#endif
	पटिनिवत्त to.ss_family;
}

शून्य
set_sock_tos(पूर्णाङ्क fd, पूर्णाङ्क tos)
{
#ifndef IP_TOS_IS_BROKEN
	पूर्णाङ्क af;

	सचे (tos < 0 || tos == INT_MAX) {
		debug_f("invalid TOS %d", tos);
		पटिनिवत्त;
	}
	विकल्प ((af = get_sock_af(fd))) {
	पक्ष -1:
		/* assume not a socket */
		भङ्ग;
	पक्ष AF_INET:
# ifdef IP_TOS
		debug3_f("set socket %d IP_TOS 0x%02x", fd, tos);
		सचे (setsockopt(fd, IPPROTO_IP, IP_TOS,
		    &tos, परिमाण(tos)) == -1) {
			error("setsockopt socket %d IP_TOS %d: %s",
			    fd, tos, strerror(errno));
		}
# endif /* IP_TOS */
		भङ्ग;
	पक्ष AF_INET6:
# ifdef IPV6_TCLASS
		debug3_f("set socket %d IPV6_TCLASS 0x%02x", fd, tos);
		सचे (setsockopt(fd, IPPROTO_IPV6, IPV6_TCLASS,
		    &tos, परिमाण(tos)) == -1) {
			error("setsockopt socket %d IPV6_TCLASS %d: %s",
			    fd, tos, strerror(errno));
		}
# endif /* IPV6_TCLASS */
		भङ्ग;
	स्वभाव:
		debug2_f("unsupported socket family %d", af);
		भङ्ग;
	}
#endif /* IP_TOS_IS_BROKEN */
}

/*
 * Wait up to *timeoutp milliseconds for events on fd. Updates
 * *timeoutp with time remaining.
 * Returns 0 if fd ready or -1 on timeout or error (see errno).
 */
स्थिर पूर्णाङ्क
waitfd(पूर्णाङ्क fd, पूर्णाङ्क *timeoutp, short events, चञ्चल sig_atomic_t *stop)
{
	संरचना pollfd pfd;
	संरचना timespec timeout;
	पूर्णाङ्क oerrno, r;
	sigset_t nsigset, osigset;

	सचे (timeoutp && *timeoutp == -1)
		timeoutp = रिक्त;
	pfd.fd = fd;
	pfd.events = events;
	ptimeout_init(&timeout);
	सचे (timeoutp != रिक्त)
		ptimeout_deadline_ms(&timeout, *timeoutp);
	सचे (stop != रिक्त)
		sigfillset(&nsigset);
	अत्थाय (; timeoutp == रिक्त || *timeoutp >= 0;) {
		सचे (stop != रिक्त) {
			sigprocmask(SIG_BLOCK, &nsigset, &osigset);
			सचे (*stop) {
				sigprocmask(SIG_SETMASK, &osigset, रिक्त);
				errno = EINTR;
				पटिनिवत्त -1;
			}
		}
		r = ppoll(&pfd, 1, ptimeout_get_tsp(&timeout),
		    stop != रिक्त ? &osigset : रिक्त);
		oerrno = errno;
		सचे (stop != रिक्त)
			sigprocmask(SIG_SETMASK, &osigset, रिक्त);
		सचे (timeoutp)
			*timeoutp = ptimeout_get_ms(&timeout);
		errno = oerrno;
		सचे (r > 0)
			पटिनिवत्त 0;
		अञ्ञथा सचे (r == -1 && errno != EAGAIN && errno != EINTR)
			पटिनिवत्त -1;
		अञ्ञथा सचे (r == 0)
			भङ्ग;
	}
	/* timeout */
	errno = ETIMEDOUT;
	पटिनिवत्त -1;
}

/*
 * Wait up to *timeoutp milliseconds for fd to be readable. Updates
 * *timeoutp with time remaining.
 * Returns 0 if fd ready or -1 on timeout or error (see errno).
 */
पूर्णाङ्क
waitrfd(पूर्णाङ्क fd, पूर्णाङ्क *timeoutp, चञ्चल sig_atomic_t *stop) {
	पटिनिवत्त waitfd(fd, timeoutp, POLLIN, stop);
}

/*
 * Attempt a non-blocking connect(2) to the specified address, waiting up to
 * *timeoutp milliseconds for the connection to complete. If the timeout is
 * <=0, then wait indefinitely.
 *
 * Returns 0 on success or -1 on failure.
 */
पूर्णाङ्क
timeout_connect(पूर्णाङ्क sockfd, ध्रुव संरचना sockaddr *serv_addr,
    socklen_t addrlen, पूर्णाङ्क *timeoutp)
{
	पूर्णाङ्क optval = 0;
	socklen_t optlen = परिमाण(optval);

	/* No timeout: just do a blocking connect() */
	सचे (timeoutp == रिक्त || *timeoutp <= 0)
		पटिनिवत्त connect(sockfd, serv_addr, addrlen);

	set_nonblock(sockfd);
	अत्थाय (;;) {
		सचे (connect(sockfd, serv_addr, addrlen) == 0) {
			/* Succeeded already? */
			unset_nonblock(sockfd);
			पटिनिवत्त 0;
		} अञ्ञथा सचे (errno == EINTR)
			अनुवर्त;
		अञ्ञथा सचे (errno != EINPROGRESS)
			पटिनिवत्त -1;
		भङ्ग;
	}

	सचे (waitfd(sockfd, timeoutp, POLLIN | POLLOUT, रिक्त) == -1)
		पटिनिवत्त -1;

	/* Completed or failed */
	सचे (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &optval, &optlen) == -1) {
		debug("getsockopt: %s", strerror(errno));
		पटिनिवत्त -1;
	}
	सचे (optval != 0) {
		errno = optval;
		पटिनिवत्त -1;
	}
	unset_nonblock(sockfd);
	पटिनिवत्त 0;
}

/* Characters considered whitespace in strsep calls. */
#define WHITESPACE " \t\r\n"
#define QUOTE	"\""

/* return next token in configuration line */
स्थिर वर्ण *
strdelim_internal(वर्ण **s, पूर्णाङ्क split_equals)
{
	वर्ण *old;
	पूर्णाङ्क wspace = 0;

	सचे (*s == रिक्त)
		पटिनिवत्त रिक्त;

	old = *s;

	*s = strpbrk(*s,
	    split_equals ? WHITESPACE QUOTE "=" : WHITESPACE QUOTE);
	सचे (*s == रिक्त)
		पटिनिवत्त (old);

	सचे (*s[0] == '\"') {
		memmove(*s, *s + 1, strlen(*s)); /* move nul too */
		/* Find matching quote */
		सचे ((*s = strpbrk(*s, QUOTE)) == रिक्त) {
			पटिनिवत्त (रिक्त);		/* no matching quote */
		} अञ्ञथा {
			*s[0] = '\0';
			*s += strspn(*s + 1, WHITESPACE) + 1;
			पटिनिवत्त (old);
		}
	}

	/* Allow only one '=' to be skipped */
	सचे (split_equals && *s[0] == '=')
		wspace = 1;
	*s[0] = '\0';

	/* Skip any extra whitespace after first token */
	*s += strspn(*s + 1, WHITESPACE) + 1;
	सचे (split_equals && *s[0] == '=' && !wspace)
		*s += strspn(*s + 1, WHITESPACE) + 1;

	पटिनिवत्त (old);
}

/*
 * Return next token in configuration line; splits on whitespace or a
 * single '=' character.
 */
वर्ण *
strdelim(वर्ण **s)
{
	पटिनिवत्त strdelim_internal(s, 1);
}

/*
 * Return next token in configuration line; splits on whitespace only.
 */
वर्ण *
strdelimw(वर्ण **s)
{
	पटिनिवत्त strdelim_internal(s, 0);
}

संरचना passwd *
pwcopy(संरचना passwd *pw)
{
	संरचना passwd *copy = xcalloc(1, परिमाण(*copy));

	copy->pw_name = xstrdup(pw->pw_name);
	copy->pw_passwd = xstrdup(pw->pw_passwd == रिक्त ? "*" : pw->pw_passwd);
#ifdef HAVE_STRUCT_PASSWD_PW_GECOS
	copy->pw_gecos = xstrdup(pw->pw_gecos == रिक्त ? "" : pw->pw_gecos);
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
	copy->pw_class = xstrdup(pw->pw_class == रिक्त ? "" : pw->pw_class);
#endif
	copy->pw_dir = xstrdup(pw->pw_dir == रिक्त ? "" : pw->pw_dir);
	copy->pw_shell = xstrdup(pw->pw_shell == रिक्त ? "" : pw->pw_shell);
	पटिनिवत्त copy;
}

शून्य
pwfree(संरचना passwd *pw)
{
	सचे (pw == रिक्त)
		पटिनिवत्त;
	मुक्त(pw->pw_name);
	freezero(pw->pw_passwd,
	    pw->pw_passwd == रिक्त ? 0 : strlen(pw->pw_passwd));
#ifdef HAVE_STRUCT_PASSWD_PW_GECOS
	मुक्त(pw->pw_gecos);
#endif
#ifdef HAVE_STRUCT_PASSWD_PW_CLASS
	मुक्त(pw->pw_class);
#endif
	मुक्त(pw->pw_dir);
	मुक्त(pw->pw_shell);
	freezero(pw, परिमाण(*pw));
}

/*
 * Convert ASCII string to TCP/IP port number.
 * Port must be >=0 and <=65535.
 * Return -1 if invalid.
 */
पूर्णाङ्क
a2port(ध्रुव वर्ण *s)
{
	संरचना servent *se;
	long long port;
	ध्रुव वर्ण *errstr;

	port = strtonum(s, 0, 65535, &errstr);
	सचे (errstr == रिक्त)
		पटिनिवत्त (पूर्णाङ्क)port;
	सचे ((se = getservbyname(s, "tcp")) != रिक्त)
		पटिनिवत्त ntohs(se->s_port);
	पटिनिवत्त -1;
}

पूर्णाङ्क
a2tun(ध्रुव वर्ण *s, पूर्णाङ्क *remote)
{
	ध्रुव वर्ण *errstr = रिक्त;
	वर्ण *sp, *ep;
	पूर्णाङ्क tun;

	सचे (remote != रिक्त) {
		*remote = SSH_TUNID_ANY;
		sp = xstrdup(s);
		सचे ((ep = strchr(sp, ':')) == रिक्त) {
			मुक्त(sp);
			पटिनिवत्त (a2tun(s, रिक्त));
		}
		ep[0] = '\0'; ep++;
		*remote = a2tun(ep, रिक्त);
		tun = a2tun(sp, रिक्त);
		मुक्त(sp);
		पटिनिवत्त (*remote == SSH_TUNID_ERR ? *remote : tun);
	}

	सचे (strcasecmp(s, "any") == 0)
		पटिनिवत्त (SSH_TUNID_ANY);

	tun = strtonum(s, 0, SSH_TUNID_MAX, &errstr);
	सचे (errstr != रिक्त)
		पटिनिवत्त (SSH_TUNID_ERR);

	पटिनिवत्त (tun);
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
द्विगुण
convtime_double(ध्रुव वर्ण *s)
{
	द्विगुण val, total_sec = 0.0, multiplier;
	ध्रुव वर्ण *p, *start_p;
	वर्ण *endp;
	पूर्णाङ्क seen_seconds = 0;

	सचे (s == रिक्त || *s == '\0')
		पटिनिवत्त -1.0;

	अत्थाय (p = s; *p != '\0';) {
		सचे (!isdigit((unsigned वर्ण)*p) && *p != '.')
			पटिनिवत्त -1.0;

		errno = 0;
		सचे ((val = strtod(p, &endp)) < 0 || errno != 0 || p == endp)
			पटिनिवत्त -1.0;
		/* Allow only decimal forms */
		सचे (p + strspn(p, "0123456789.") != endp)
			पटिनिवत्त -1.0;
		start_p = p;
		p = endp;

		विकल्प (*p) {
		पक्ष '\0':
			/* FALLTHROUGH */
		पक्ष 's':
		पक्ष 'S':
			सचे (seen_seconds++)
				पटिनिवत्त -1.0;
			multiplier = SECONDS;
			भङ्ग;
		पक्ष 'm':
		पक्ष 'M':
			multiplier = MINUTES;
			भङ्ग;
		पक्ष 'h':
		पक्ष 'H':
			multiplier = HOURS;
			भङ्ग;
		पक्ष 'd':
		पक्ष 'D':
			multiplier = DAYS;
			भङ्ग;
		पक्ष 'w':
		पक्ष 'W':
			multiplier = WEEKS;
			भङ्ग;
		स्वभाव:
			पटिनिवत्त -1.0;
		}

		/* Special handling if this was a decimal */
		सचे (memchr(start_p, '.', endp - start_p) != रिक्त) {
			/* Decimal point present */
			सचे (multiplier > 1.0)
				पटिनिवत्त -1.0; /* No fractionals for non-seconds */
			/* For seconds, ensure digits follow */
			सचे (!isdigit((unsigned वर्ण)*(endp - 1)))
				पटिनिवत्त -1.0;
		}

		total_sec += val * multiplier;

		सचे (*p != '\0')
			p++;
	}
	पटिनिवत्त total_sec;
}

/*
 * Same as convtime_double() above but fractional seconds are ignored.
 * Return -1 if time string is invalid.
 */
पूर्णाङ्क
convtime(ध्रुव वर्ण *s)
{
	द्विगुण sec_val;

	सचे ((sec_val = convtime_double(s)) < 0.0)
		पटिनिवत्त -1;

	/* Check for overflow into int */
	सचे (sec_val < 0 || sec_val > INT_MAX)
		पटिनिवत्त -1;

	पटिनिवत्त (पूर्णाङ्क)sec_val;
}

#define TF_BUFS	8
#define TF_LEN	9

ध्रुव वर्ण *
fmt_timeframe(time_t t)
{
	वर्ण		*buf;
	स्थिर वर्ण	 tfbuf[TF_BUFS][TF_LEN];	/* ring buffer */
	स्थिर पूर्णाङ्क	 idx = 0;
	unsigned पूर्णाङ्क	 sec, min, hrs, day;
	unsigned long long	week;

	buf = tfbuf[idx++];
	सचे (idx == TF_BUFS)
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

	सचे (week > 0)
		snprintf(buf, TF_LEN, "%02lluw%01ud%02uh", week, day, hrs);
	अञ्ञथा सचे (day > 0)
		snprintf(buf, TF_LEN, "%01ud%02uh%02um", day, hrs, min);
	अञ्ञथा
		snprintf(buf, TF_LEN, "%02u:%02u:%02u", hrs, min, sec);

	पटिनिवत्त (buf);
}

/*
 * Returns a standardized host+port identifier string.
 * Caller must free returned string.
 */
वर्ण *
put_host_port(ध्रुव वर्ण *host, u_short port)
{
	वर्ण *hoststr;

	सचे (port == 0 || port == SSH_DEFAULT_PORT)
		पटिनिवत्त(xstrdup(host));
	सचे (asprintf(&hoststr, "[%s]:%d", host, (पूर्णाङ्क)port) == -1)
		fatal("put_host_port: asprintf: %s", strerror(errno));
	debug3("put_host_port: %s", hoststr);
	पटिनिवत्त hoststr;
}

/*
 * Search for next delimiter between hostnames/addresses and ports.
 * Argument may be modified (for termination).
 * Returns *cp if parsing succeeds.
 * *cp is set to the start of the next field, if one was found.
 * The delimiter char, if present, is stored in delim.
 * If this is the last field, *cp is set to NULL.
 */
वर्ण *
hpdelim2(वर्ण **cp, वर्ण *delim)
{
	वर्ण *s, *old;

	सचे (cp == रिक्त || *cp == रिक्त)
		पटिनिवत्त रिक्त;

	old = s = *cp;
	सचे (*s == '[') {
		सचे ((s = strchr(s, ']')) == रिक्त)
			पटिनिवत्त रिक्त;
		अञ्ञथा
			s++;
	} अञ्ञथा सचे ((s = strpbrk(s, ":/")) == रिक्त)
		s = *cp + strlen(*cp); /* skip to end (see first case below) */

	विकल्प (*s) {
	पक्ष '\0':
		*cp = रिक्त;	/* no more fields*/
		भङ्ग;

	पक्ष ':':
	पक्ष '/':
		सचे (delim != रिक्त)
			*delim = *s;
		*s = '\0';	/* terminate */
		*cp = s + 1;
		भङ्ग;

	स्वभाव:
		पटिनिवत्त रिक्त;
	}

	पटिनिवत्त old;
}

/* The common case: only accept colon as delimiter. */
वर्ण *
hpdelim(वर्ण **cp)
{
	वर्ण *r, delim = '\0';

	r =  hpdelim2(cp, &delim);
	सचे (delim == '/')
		पटिनिवत्त रिक्त;
	पटिनिवत्त r;
}

वर्ण *
cleanhostname(वर्ण *host)
{
	सचे (*host == '[' && host[strlen(host) - 1] == ']') {
		host[strlen(host) - 1] = '\0';
		पटिनिवत्त (host + 1);
	} अञ्ञथा
		पटिनिवत्त host;
}

वर्ण *
colon(वर्ण *cp)
{
	पूर्णाङ्क flag = 0;

	सचे (*cp == ':')		/* Leading colon is part of file name. */
		पटिनिवत्त रिक्त;
	सचे (*cp == '[')
		flag = 1;

	अत्थाय (; *cp; ++cp) {
		सचे (*cp == '@' && *(cp+1) == '[')
			flag = 1;
		सचे (*cp == ']' && *(cp+1) == ':' && flag)
			पटिनिवत्त (cp+1);
		सचे (*cp == ':' && !flag)
			पटिनिवत्त (cp);
		सचे (*cp == '/')
			पटिनिवत्त रिक्त;
	}
	पटिनिवत्त रिक्त;
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
पूर्णाङ्क
parse_user_host_path(ध्रुव वर्ण *s, वर्ण **userp, वर्ण **hostp, वर्ण **pathp)
{
	वर्ण *user = रिक्त, *host = रिक्त, *path = रिक्त;
	वर्ण *sdup, *tmp;
	पूर्णाङ्क ret = -1;

	सचे (userp != रिक्त)
		*userp = रिक्त;
	सचे (hostp != रिक्त)
		*hostp = रिक्त;
	सचे (pathp != रिक्त)
		*pathp = रिक्त;

	sdup = xstrdup(s);

	/* Check for remote syntax: [user@]host:[path] */
	सचे ((tmp = colon(sdup)) == रिक्त)
		गच्छ out;

	/* Extract optional path */
	*tmp++ = '\0';
	सचे (*tmp == '\0')
		tmp = ".";
	path = xstrdup(tmp);

	/* Extract optional user and mandatory host */
	tmp = strrchr(sdup, '@');
	सचे (tmp != रिक्त) {
		*tmp++ = '\0';
		host = xstrdup(cleanhostname(tmp));
		सचे (*sdup != '\0')
			user = xstrdup(sdup);
	} अञ्ञथा {
		host = xstrdup(cleanhostname(sdup));
		user = रिक्त;
	}

	/* Success */
	सचे (userp != रिक्त) {
		*userp = user;
		user = रिक्त;
	}
	सचे (hostp != रिक्त) {
		*hostp = host;
		host = रिक्त;
	}
	सचे (pathp != रिक्त) {
		*pathp = path;
		path = रिक्त;
	}
	ret = 0;
out:
	मुक्त(sdup);
	मुक्त(user);
	मुक्त(host);
	मुक्त(path);
	पटिनिवत्त ret;
}

/*
 * Parse a [user@]host[:port] string.
 * Caller must free returned user and host.
 * Any of the pointer return arguments may be NULL (useful for syntax checking).
 * If user was not specified then *userp will be set to NULL.
 * If port was not specified then *portp will be -1.
 * Returns 0 on success, -1 on failure.
 */
पूर्णाङ्क
parse_user_host_port(ध्रुव वर्ण *s, वर्ण **userp, वर्ण **hostp, पूर्णाङ्क *portp)
{
	वर्ण *sdup, *cp, *tmp;
	वर्ण *user = रिक्त, *host = रिक्त;
	पूर्णाङ्क port = -1, ret = -1;

	सचे (userp != रिक्त)
		*userp = रिक्त;
	सचे (hostp != रिक्त)
		*hostp = रिक्त;
	सचे (portp != रिक्त)
		*portp = -1;

	सचे ((sdup = tmp = strdup(s)) == रिक्त)
		पटिनिवत्त -1;
	/* Extract optional username */
	सचे ((cp = strrchr(tmp, '@')) != रिक्त) {
		*cp = '\0';
		सचे (*tmp == '\0')
			गच्छ out;
		सचे ((user = strdup(tmp)) == रिक्त)
			गच्छ out;
		tmp = cp + 1;
	}
	/* Extract mandatory hostname */
	सचे ((cp = hpdelim(&tmp)) == रिक्त || *cp == '\0')
		गच्छ out;
	host = xstrdup(cleanhostname(cp));
	/* Convert and verify optional port */
	सचे (tmp != रिक्त && *tmp != '\0') {
		सचे ((port = a2port(tmp)) <= 0)
			गच्छ out;
	}
	/* Success */
	सचे (userp != रिक्त) {
		*userp = user;
		user = रिक्त;
	}
	सचे (hostp != रिक्त) {
		*hostp = host;
		host = रिक्त;
	}
	सचे (portp != रिक्त)
		*portp = port;
	ret = 0;
 out:
	मुक्त(sdup);
	मुक्त(user);
	मुक्त(host);
	पटिनिवत्त ret;
}

/*
 * Converts a two-byte hex string to decimal.
 * Returns the decimal value or -1 for invalid input.
 */
स्थिर पूर्णाङ्क
hexchar(ध्रुव वर्ण *s)
{
	unsigned वर्ण result[2];
	पूर्णाङ्क i;

	अत्थाय (i = 0; i < 2; i++) {
		सचे (s[i] >= '0' && s[i] <= '9')
			result[i] = (unsigned वर्ण)(s[i] - '0');
		अञ्ञथा सचे (s[i] >= 'a' && s[i] <= 'f')
			result[i] = (unsigned वर्ण)(s[i] - 'a') + 10;
		अञ्ञथा सचे (s[i] >= 'A' && s[i] <= 'F')
			result[i] = (unsigned वर्ण)(s[i] - 'A') + 10;
		अञ्ञथा
			पटिनिवत्त -1;
	}
	पटिनिवत्त (result[0] << 4) | result[1];
}

/*
 * Decode an url-encoded string.
 * Returns a newly allocated string on success or NULL on failure.
 */
स्थिर वर्ण *
urldecode(ध्रुव वर्ण *src)
{
	वर्ण *ret, *dst;
	पूर्णाङ्क ch;
	size_t srclen;

	सचे ((srclen = strlen(src)) >= SIZE_MAX)
		पटिनिवत्त रिक्त;
	ret = xmalloc(srclen + 1);
	अत्थाय (dst = ret; *src != '\0'; src++) {
		विकल्प (*src) {
		पक्ष '+':
			*dst++ = ' ';
			भङ्ग;
		पक्ष '%':
			/* note: don't allow \0 characters */
			सचे (!isxdigit((unsigned वर्ण)src[1]) ||
			    !isxdigit((unsigned वर्ण)src[2]) ||
			    (ch = hexchar(src + 1)) == -1 || ch == 0) {
				मुक्त(ret);
				पटिनिवत्त रिक्त;
			}
			*dst++ = ch;
			src += 2;
			भङ्ग;
		स्वभाव:
			*dst++ = *src;
			भङ्ग;
		}
	}
	*dst = '\0';

	पटिनिवत्त ret;
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
पूर्णाङ्क
parse_uri(ध्रुव वर्ण *scheme, ध्रुव वर्ण *uri, वर्ण **userp, वर्ण **hostp,
    पूर्णाङ्क *portp, वर्ण **pathp)
{
	वर्ण *uridup, *cp, *tmp, ch;
	वर्ण *user = रिक्त, *host = रिक्त, *path = रिक्त;
	पूर्णाङ्क port = -1, ret = -1;
	size_t len;

	len = strlen(scheme);
	सचे (strncmp(uri, scheme, len) != 0 || strncmp(uri + len, "://", 3) != 0)
		पटिनिवत्त 1;
	uri += len + 3;

	सचे (userp != रिक्त)
		*userp = रिक्त;
	सचे (hostp != रिक्त)
		*hostp = रिक्त;
	सचे (portp != रिक्त)
		*portp = -1;
	सचे (pathp != रिक्त)
		*pathp = रिक्त;

	uridup = tmp = xstrdup(uri);

	/* Extract optional ssh-info (username + connection params) */
	सचे ((cp = strchr(tmp, '@')) != रिक्त) {
		वर्ण *delim;

		*cp = '\0';
		/* Extract username and connection params */
		सचे ((delim = strchr(tmp, ';')) != रिक्त) {
			/* Just ignore connection params for now */
			*delim = '\0';
		}
		सचे (*tmp == '\0') {
			/* Empty username */
			गच्छ out;
		}
		सचे ((user = urldecode(tmp)) == रिक्त)
			गच्छ out;
		tmp = cp + 1;
	}

	/* Extract mandatory hostname */
	सचे ((cp = hpdelim2(&tmp, &ch)) == रिक्त || *cp == '\0')
		गच्छ out;
	host = xstrdup(cleanhostname(cp));
	सचे (!valid_domain(host, 0, रिक्त))
		गच्छ out;

	सचे (tmp != रिक्त && *tmp != '\0') {
		सचे (ch == ':') {
			/* Convert and verify port. */
			सचे ((cp = strchr(tmp, '/')) != रिक्त)
				*cp = '\0';
			सचे ((port = a2port(tmp)) <= 0)
				गच्छ out;
			tmp = cp ? cp + 1 : रिक्त;
		}
		सचे (tmp != रिक्त && *tmp != '\0') {
			/* Extract optional path */
			सचे ((path = urldecode(tmp)) == रिक्त)
				गच्छ out;
		}
	}

	/* Success */
	सचे (userp != रिक्त) {
		*userp = user;
		user = रिक्त;
	}
	सचे (hostp != रिक्त) {
		*hostp = host;
		host = रिक्त;
	}
	सचे (portp != रिक्त)
		*portp = port;
	सचे (pathp != रिक्त) {
		*pathp = path;
		path = रिक्त;
	}
	ret = 0;
 out:
	मुक्त(uridup);
	मुक्त(user);
	मुक्त(host);
	मुक्त(path);
	पटिनिवत्त ret;
}

/* function to assist building execv() arguments */
शून्य
addargs(arglist *args, वर्ण *fmt, ...)
{
	va_list ap;
	वर्ण *cp;
	u_int nalloc;
	पूर्णाङ्क r;

	va_start(ap, fmt);
	r = vasprintf(&cp, fmt, ap);
	va_end(ap);
	सचे (r == -1)
		fatal_f("argument too long");

	nalloc = args->nalloc;
	सचे (args->list == रिक्त) {
		nalloc = 32;
		args->अङ्कः = 0;
	} अञ्ञथा सचे (args->अङ्कः > (256 * 1024))
		fatal_f("too many arguments");
	अञ्ञथा सचे (args->अङ्कः >= args->nalloc)
		fatal_f("arglist corrupt");
	अञ्ञथा सचे (args->अङ्कः+2 >= nalloc)
		nalloc *= 2;

	args->list = xrecallocarray(args->list, args->nalloc,
	    nalloc, परिमाण(वर्ण *));
	args->nalloc = nalloc;
	args->list[args->अङ्कः++] = cp;
	args->list[args->अङ्कः] = रिक्त;
}

शून्य
replacearg(arglist *args, u_int which, वर्ण *fmt, ...)
{
	va_list ap;
	वर्ण *cp;
	पूर्णाङ्क r;

	va_start(ap, fmt);
	r = vasprintf(&cp, fmt, ap);
	va_end(ap);
	सचे (r == -1)
		fatal_f("argument too long");
	सचे (args->list == रिक्त || args->अङ्कः >= args->nalloc)
		fatal_f("arglist corrupt");

	सचे (which >= args->अङ्कः)
		fatal_f("tried to replace invalid arg %d >= %d",
		    which, args->अङ्कः);
	मुक्त(args->list[which]);
	args->list[which] = cp;
}

शून्य
freeargs(arglist *args)
{
	u_int i;

	सचे (args == रिक्त)
		पटिनिवत्त;
	सचे (args->list != रिक्त && args->अङ्कः < args->nalloc) {
		अत्थाय (i = 0; i < args->अङ्कः; i++)
			मुक्त(args->list[i]);
		मुक्त(args->list);
	}
	args->nalloc = args->अङ्कः = 0;
	args->list = रिक्त;
}

/*
 * Expands tildes in the file name.  Returns data allocated by xmalloc.
 * Warning: this calls getpw*.
 */
पूर्णाङ्क
tilde_expand(ध्रुव वर्ण *filename, uid_t uid, वर्ण **retp)
{
	वर्ण *ocopy = रिक्त, *copy, *s = रिक्त;
	ध्रुव वर्ण *path = रिक्त, *user = रिक्त;
	संरचना passwd *pw;
	size_t len;
	पूर्णाङ्क ret = -1, r, slash;

	*retp = रिक्त;
	सचे (*filename != '~') {
		*retp = xstrdup(filename);
		पटिनिवत्त 0;
	}
	ocopy = copy = xstrdup(filename + 1);

	सचे (*copy == '\0')				/* ~ */
		path = रिक्त;
	अञ्ञथा सचे (*copy == '/') {
		copy += strspn(copy, "/");
		सचे (*copy == '\0')
			path = रिक्त;			/* ~/ */
		अञ्ञथा
			path = copy;			/* ~/path */
	} अञ्ञथा {
		user = copy;
		सचे ((path = strchr(copy, '/')) != रिक्त) {
			copy[path - copy] = '\0';
			path++;
			path += strspn(path, "/");
			सचे (*path == '\0')		/* ~user/ */
				path = रिक्त;
			/* else				 ~user/path */
		}
		/* else					~user */
	}
	सचे (user != रिक्त) {
		सचे ((pw = getpwnam(user)) == रिक्त) {
			error_f("No such user %s", user);
			गच्छ out;
		}
	} अञ्ञथा सचे ((pw = getpwuid(uid)) == रिक्त) {
		error_f("No such uid %ld", (long)uid);
		गच्छ out;
	}

	/* Make sure directory has a trailing '/' */
	slash = (len = strlen(pw->pw_dir)) == 0 || pw->pw_dir[len - 1] != '/';

	सचे ((r = xasprintf(&s, "%s%s%s", pw->pw_dir,
	    slash ? "/" : "", path != रिक्त ? path : "")) <= 0) {
		error_f("xasprintf failed");
		गच्छ out;
	}
	सचे (r >= PATH_MAX) {
		error_f("Path too long");
		गच्छ out;
	}
	/* success */
	ret = 0;
	*retp = s;
	s = रिक्त;
 out:
	मुक्त(s);
	मुक्त(ocopy);
	पटिनिवत्त ret;
}

वर्ण *
tilde_expand_filename(ध्रुव वर्ण *filename, uid_t uid)
{
	वर्ण *ret;

	सचे (tilde_expand(filename, uid, &ret) != 0)
		cleanup_exit(255);
	पटिनिवत्त ret;
}

/*
 * Expand a string with a set of %[char] escapes and/or ${ENVIRONMENT}
 * substitutions.  A number of escapes may be specified as
 * (char *escape_chars, char *replacement) pairs. The list must be terminated
 * by a NULL escape_char. Returns replaced string in memory allocated by
 * xmalloc which the caller must free.
 */
स्थिर वर्ण *
vdollar_percent_expand(पूर्णाङ्क *parseerror, पूर्णाङ्क dollar, पूर्णाङ्क percent,
    ध्रुव वर्ण *string, va_list ap)
{
#define EXPAND_MAX_कुञ्चिकाः	64
	u_int अङ्कः_कुञ्चिकाः = 0, i;
	संरचना {
		ध्रुव वर्ण *कुञ्चिका;
		ध्रुव वर्ण *repl;
	} कुञ्चिकाः[EXPAND_MAX_कुञ्चिकाः];
	संरचना sshbuf *buf;
	पूर्णाङ्क r, missingvar = 0;
	वर्ण *ret = रिक्त, *var, *varend, *val;
	size_t len;

	सचे ((buf = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	सचे (parseerror == रिक्त)
		fatal_f("null parseerror arg");
	*parseerror = 1;

	/* Gather keys if we're doing percent expansion. */
	सचे (percent) {
		अत्थाय (अङ्कः_कुञ्चिकाः = 0; अङ्कः_कुञ्चिकाः < EXPAND_MAX_कुञ्चिकाः; अङ्कः_कुञ्चिकाः++) {
			कुञ्चिकाः[अङ्कः_कुञ्चिकाः].कुञ्चिका = va_arg(ap, वर्ण *);
			सचे (कुञ्चिकाः[अङ्कः_कुञ्चिकाः].कुञ्चिका == रिक्त)
				भङ्ग;
			कुञ्चिकाः[अङ्कः_कुञ्चिकाः].repl = va_arg(ap, वर्ण *);
			सचे (कुञ्चिकाः[अङ्कः_कुञ्चिकाः].repl == रिक्त) {
				fatal_f("NULL replacement for token %s",
				    कुञ्चिकाः[अङ्कः_कुञ्चिकाः].कुञ्चिका);
			}
		}
		सचे (अङ्कः_कुञ्चिकाः == EXPAND_MAX_कुञ्चिकाः && va_arg(ap, वर्ण *) != रिक्त)
			fatal_f("too many keys");
		सचे (अङ्कः_कुञ्चिकाः == 0)
			fatal_f("percent expansion without token list");
	}

	/* Expand string */
	अत्थाय (i = 0; *string != '\0'; string++) {
		/* Optionally process ${ENVIRONMENT} expansions. */
		सचे (dollar && string[0] == '$' && string[1] == '{') {
			string += 2;  /* skip over '${' */
			सचे ((varend = strchr(string, '}')) == रिक्त) {
				error_f("environment variable '%s' missing "
				    "closing '}'", string);
				गच्छ out;
			}
			len = varend - string;
			सचे (len == 0) {
				error_f("zero-length environment variable");
				गच्छ out;
			}
			var = xmalloc(len + 1);
			(शून्य)strlcpy(var, string, len + 1);
			सचे ((val = getenv(var)) == रिक्त) {
				error_f("env var ${%s} has no value", var);
				missingvar = 1;
			} अञ्ञथा {
				debug3_f("expand ${%s} -> '%s'", var, val);
				सचे ((r = sshbuf_put(buf, val, strlen(val))) !=0)
					fatal_fr(r, "sshbuf_put ${}");
			}
			मुक्त(var);
			string += len;
			अनुवर्त;
		}

		/*
		 * Process percent expansions if we have a list of TOKENs.
		 * If we're not doing percent expansion everything just gets
		 * appended here.
		 */
		सचे (*string != '%' || !percent) {
 append:
			सचे ((r = sshbuf_put_u8(buf, *string)) != 0)
				fatal_fr(r, "sshbuf_put_u8 %%");
			अनुवर्त;
		}
		string++;
		/* %% case */
		सचे (*string == '%')
			गच्छ append;
		सचे (*string == '\0') {
			error_f("invalid format");
			गच्छ out;
		}
		अत्थाय (i = 0; i < अङ्कः_कुञ्चिकाः; i++) {
			सचे (strchr(कुञ्चिकाः[i].कुञ्चिका, *string) != रिक्त) {
				सचे ((r = sshbuf_put(buf, कुञ्चिकाः[i].repl,
				    strlen(कुञ्चिकाः[i].repl))) != 0)
					fatal_fr(r, "sshbuf_put %%-repl");
				भङ्ग;
			}
		}
		सचे (i >= अङ्कः_कुञ्चिकाः) {
			error_f("unknown key %%%c", *string);
			गच्छ out;
		}
	}
	सचे (!missingvar && (ret = sshbuf_dup_string(buf)) == रिक्त)
		fatal_f("sshbuf_dup_string failed");
	*parseerror = 0;
 out:
	sshbuf_free(buf);
	पटिनिवत्त *parseerror ? रिक्त : ret;
#undef EXPAND_MAX_कुञ्चिकाः
}

/*
 * Expand only environment variables.
 * Note that although this function is variadic like the other similar
 * functions, any such arguments will be unused.
 */

वर्ण *
dollar_expand(पूर्णाङ्क *parseerr, ध्रुव वर्ण *string, ...)
{
	वर्ण *ret;
	पूर्णाङ्क err;
	va_list ap;

	va_start(ap, string);
	ret = vdollar_percent_expand(&err, 1, 0, string, ap);
	va_end(ap);
	सचे (parseerr != रिक्त)
		*parseerr = err;
	पटिनिवत्त ret;
}

/*
 * Returns expanded string or NULL if a specified environment variable is
 * not defined, or calls fatal if the string is invalid.
 */
वर्ण *
percent_expand(ध्रुव वर्ण *string, ...)
{
	वर्ण *ret;
	पूर्णाङ्क err;
	va_list ap;

	va_start(ap, string);
	ret = vdollar_percent_expand(&err, 0, 1, string, ap);
	va_end(ap);
	सचे (err)
		fatal_f("failed");
	पटिनिवत्त ret;
}

/*
 * Returns expanded string or NULL if a specified environment variable is
 * not defined, or calls fatal if the string is invalid.
 */
वर्ण *
percent_dollar_expand(ध्रुव वर्ण *string, ...)
{
	वर्ण *ret;
	पूर्णाङ्क err;
	va_list ap;

	va_start(ap, string);
	ret = vdollar_percent_expand(&err, 1, 1, string, ap);
	va_end(ap);
	सचे (err)
		fatal_f("failed");
	पटिनिवत्त ret;
}

पूर्णाङ्क
tun_open(पूर्णाङ्क tun, पूर्णाङ्क mode, वर्ण **ifname)
{
#सचे defined(CUSTOM_SYS_TUN_OPEN)
	पटिनिवत्त (sys_tun_open(tun, mode, ifname));
#नोचेद्यदि defined(SSH_TUN_OPENBSD)
	संरचना ifreq ifr;
	वर्ण name[100];
	पूर्णाङ्क fd = -1, sock;
	ध्रुव वर्ण *tunbase = "tun";

	सचे (ifname != रिक्त)
		*ifname = रिक्त;

	सचे (mode == SSH_TUNMODE_ETHERNET)
		tunbase = "tap";

	/* Open the tunnel device */
	सचे (tun <= SSH_TUNID_MAX) {
		snprintf(name, परिमाण(name), "/dev/%s%d", tunbase, tun);
		fd = open(name, O_RDWR);
	} अञ्ञथा सचे (tun == SSH_TUNID_ANY) {
		अत्थाय (tun = 100; tun >= 0; tun--) {
			snprintf(name, परिमाण(name), "/dev/%s%d",
			    tunbase, tun);
			सचे ((fd = open(name, O_RDWR)) >= 0)
				भङ्ग;
		}
	} अञ्ञथा {
		debug_f("invalid tunnel %u", tun);
		पटिनिवत्त -1;
	}

	सचे (fd == -1) {
		debug_f("%s open: %s", name, strerror(errno));
		पटिनिवत्त -1;
	}

	debug_f("%s mode %d fd %d", name, mode, fd);

	/* Bring interface up if it is not already */
	snprintf(ifr.ifr_name, परिमाण(ifr.ifr_name), "%s%d", tunbase, tun);
	सचे ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
		गच्छ failed;

	सचे (ioctl(sock, SIOCGIFFLAGS, &ifr) == -1) {
		debug_f("get interface %s flags: %s", ifr.ifr_name,
		    strerror(errno));
		गच्छ failed;
	}

	सचे (!(ifr.ifr_flags & IFF_UP)) {
		ifr.ifr_flags |= IFF_UP;
		सचे (ioctl(sock, SIOCSIFFLAGS, &ifr) == -1) {
			debug_f("activate interface %s: %s", ifr.ifr_name,
			    strerror(errno));
			गच्छ failed;
		}
	}

	सचे (ifname != रिक्त)
		*ifname = xstrdup(ifr.ifr_name);

	close(sock);
	पटिनिवत्त fd;

 failed:
	सचे (fd >= 0)
		close(fd);
	सचे (sock >= 0)
		close(sock);
	पटिनिवत्त -1;
#अञ्ञथा
	error("Tunnel interfaces are not supported on this platform");
	पटिनिवत्त (-1);
#endif
}

शून्य
sanitise_stdfd(शून्य)
{
	पूर्णाङ्क nullfd, dupfd;

	सचे ((nullfd = dupfd = open(_PATH_DEVNULL, O_RDWR)) == -1) {
		fprintf(stderr, "Couldn't open /dev/null: %s\n",
		    strerror(errno));
		exit(1);
	}
	याव (++dupfd <= STDERR_FILENO) {
		/* Only populate closed fds. */
		सचे (fcntl(dupfd, F_GETFL) == -1 && errno == EBADF) {
			सचे (dup2(nullfd, dupfd) == -1) {
				fprintf(stderr, "dup2: %s\n", strerror(errno));
				exit(1);
			}
		}
	}
	सचे (nullfd > STDERR_FILENO)
		close(nullfd);
}

वर्ण *
tohex(ध्रुव शून्य *vp, size_t l)
{
	ध्रुव u_char *p = (ध्रुव u_char *)vp;
	वर्ण b[3], *r;
	size_t i, hl;

	सचे (l > 65536)
		पटिनिवत्त xstrdup("tohex: length > 65536");

	hl = l * 2 + 1;
	r = xcalloc(1, hl);
	अत्थाय (i = 0; i < l; i++) {
		snprintf(b, परिमाण(b), "%02x", p[i]);
		strlcat(r, b, hl);
	}
	पटिनिवत्त (r);
}

/*
 * Extend string *sp by the specified format. If *sp is not NULL (or empty),
 * then the separator 'sep' will be prepended before the formatted arguments.
 * Extended strings are heap allocated.
 */
शून्य
xextendf(वर्ण **sp, ध्रुव वर्ण *sep, ध्रुव वर्ण *fmt, ...)
{
	va_list ap;
	वर्ण *tmp1, *tmp2;

	va_start(ap, fmt);
	xvasprintf(&tmp1, fmt, ap);
	va_end(ap);

	सचे (*sp == रिक्त || **sp == '\0') {
		मुक्त(*sp);
		*sp = tmp1;
		पटिनिवत्त;
	}
	xasprintf(&tmp2, "%s%s%s", *sp, sep == रिक्त ? "" : sep, tmp1);
	मुक्त(tmp1);
	मुक्त(*sp);
	*sp = tmp2;
}


uint64_t
get_u64(ध्रुव शून्य *vp)
{
	ध्रुव u_char *p = (ध्रुव u_char *)vp;
	uint64_t v;

	v  = (uint64_t)p[0] << 56;
	v |= (uint64_t)p[1] << 48;
	v |= (uint64_t)p[2] << 40;
	v |= (uint64_t)p[3] << 32;
	v |= (uint64_t)p[4] << 24;
	v |= (uint64_t)p[5] << 16;
	v |= (uint64_t)p[6] << 8;
	v |= (uint64_t)p[7];

	पटिनिवत्त (v);
}

uint32_t
get_u32(ध्रुव शून्य *vp)
{
	ध्रुव u_char *p = (ध्रुव u_char *)vp;
	uint32_t v;

	v  = (uint32_t)p[0] << 24;
	v |= (uint32_t)p[1] << 16;
	v |= (uint32_t)p[2] << 8;
	v |= (uint32_t)p[3];

	पटिनिवत्त (v);
}

uint32_t
get_u32_le(ध्रुव शून्य *vp)
{
	ध्रुव u_char *p = (ध्रुव u_char *)vp;
	uint32_t v;

	v  = (uint32_t)p[0];
	v |= (uint32_t)p[1] << 8;
	v |= (uint32_t)p[2] << 16;
	v |= (uint32_t)p[3] << 24;

	पटिनिवत्त (v);
}

uint16_t
get_u16(ध्रुव शून्य *vp)
{
	ध्रुव u_char *p = (ध्रुव u_char *)vp;
	uint16_t v;

	v  = (uint16_t)p[0] << 8;
	v |= (uint16_t)p[1];

	पटिनिवत्त (v);
}

शून्य
put_u64(शून्य *vp, uint64_t v)
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

शून्य
put_u32(शून्य *vp, uint32_t v)
{
	u_char *p = (u_char *)vp;

	p[0] = (u_char)(v >> 24) & 0xff;
	p[1] = (u_char)(v >> 16) & 0xff;
	p[2] = (u_char)(v >> 8) & 0xff;
	p[3] = (u_char)v & 0xff;
}

शून्य
put_u32_le(शून्य *vp, uint32_t v)
{
	u_char *p = (u_char *)vp;

	p[0] = (u_char)v & 0xff;
	p[1] = (u_char)(v >> 8) & 0xff;
	p[2] = (u_char)(v >> 16) & 0xff;
	p[3] = (u_char)(v >> 24) & 0xff;
}

शून्य
put_u16(शून्य *vp, uint16_t v)
{
	u_char *p = (u_char *)vp;

	p[0] = (u_char)(v >> 8) & 0xff;
	p[1] = (u_char)v & 0xff;
}

शून्य
ms_subtract_diff(संरचना timeval *start, पूर्णाङ्क *ms)
{
	संरचना timeval diff, finish;

	monotime_tv(&finish);
	timersub(&finish, start, &diff);
	*ms -= (diff.tv_sec * 1000) + (diff.tv_usec / 1000);
}

शून्य
ms_to_timespec(संरचना timespec *ts, पूर्णाङ्क ms)
{
	सचे (ms < 0)
		ms = 0;
	ts->tv_sec = ms / 1000;
	ts->tv_nsec = (ms % 1000) * 1000 * 1000;
}

शून्य
monotime_ts(संरचना timespec *ts)
{
	संरचना timeval tv;
#सचे defined(HAVE_CLOCK_GETTIME) && (defined(CLOCK_BOOTTIME) || \
    defined(CLOCK_MONOTONIC) || defined(CLOCK_REALTIME))
	स्थिर पूर्णाङ्क gettime_failed = 0;

	सचे (!gettime_failed) {
# ifdef CLOCK_BOOTTIME
		सचे (clock_gettime(CLOCK_BOOTTIME, ts) == 0)
			पटिनिवत्त;
# endif /* CLOCK_BOOTTIME */
# ifdef CLOCK_MONOTONIC
		सचे (clock_gettime(CLOCK_MONOTONIC, ts) == 0)
			पटिनिवत्त;
# endif /* CLOCK_MONOTONIC */
# ifdef CLOCK_REALTIME
		/* Not monotonic, but we're almost out of options here. */
		सचे (clock_gettime(CLOCK_REALTIME, ts) == 0)
			पटिनिवत्त;
# endif /* CLOCK_REALTIME */
		debug3("clock_gettime: %s", strerror(errno));
		gettime_failed = 1;
	}
#endif /* HAVE_CLOCK_GETTIME && (BOOTTIME || MONOTONIC || REALTIME) */
	gettimeofday(&tv, रिक्त);
	ts->tv_sec = tv.tv_sec;
	ts->tv_nsec = (long)tv.tv_usec * 1000;
}

शून्य
monotime_tv(संरचना timeval *tv)
{
	संरचना timespec ts;

	monotime_ts(&ts);
	tv->tv_sec = ts.tv_sec;
	tv->tv_usec = ts.tv_nsec / 1000;
}

time_t
monotime(शून्य)
{
	संरचना timespec ts;

	monotime_ts(&ts);
	पटिनिवत्त (ts.tv_sec);
}

द्विगुण
monotime_double(शून्य)
{
	संरचना timespec ts;

	monotime_ts(&ts);
	पटिनिवत्त (द्विगुण)ts.tv_sec + (द्विगुण)ts.tv_nsec / 1000000000.0;
}

शून्य
bandwidth_limit_init(संरचना bwlimit *bw, uint64_t kbps, size_t buflen)
{
	bw->buflen = buflen;
	bw->rate = kbps;
	bw->thresh = buflen;
	bw->lamt = 0;
	timerclear(&bw->bwstart);
	timerclear(&bw->bwend);
}

/* Callback from read/write loop to insert bandwidth-limiting delays */
शून्य
bandwidth_limit(संरचना bwlimit *bw, size_t read_len)
{
	uint64_t waitlen;
	संरचना timespec ts, rm;

	bw->lamt += read_len;
	सचे (!timerisset(&bw->bwstart)) {
		monotime_tv(&bw->bwstart);
		पटिनिवत्त;
	}
	सचे (bw->lamt < bw->thresh)
		पटिनिवत्त;

	monotime_tv(&bw->bwend);
	timersub(&bw->bwend, &bw->bwstart, &bw->bwend);
	सचे (!timerisset(&bw->bwend))
		पटिनिवत्त;

	bw->lamt *= 8;
	waitlen = (द्विगुण)1000000L * bw->lamt / bw->rate;

	bw->bwstart.tv_sec = waitlen / 1000000L;
	bw->bwstart.tv_usec = waitlen % 1000000L;

	सचे (timercmp(&bw->bwstart, &bw->bwend, >)) {
		timersub(&bw->bwstart, &bw->bwend, &bw->bwend);

		/* Adjust the wait time */
		सचे (bw->bwend.tv_sec) {
			bw->thresh /= 2;
			सचे (bw->thresh < bw->buflen / 4)
				bw->thresh = bw->buflen / 4;
		} अञ्ञथा सचे (bw->bwend.tv_usec < 10000) {
			bw->thresh *= 2;
			सचे (bw->thresh > bw->buflen * 8)
				bw->thresh = bw->buflen * 8;
		}

		TIMEVAL_TO_TIMESPEC(&bw->bwend, &ts);
		याव (nanosleep(&ts, &rm) == -1) {
			सचे (errno != EINTR)
				भङ्ग;
			ts = rm;
		}
	}

	bw->lamt = 0;
	monotime_tv(&bw->bwstart);
}

/* Make a template filename for mk[sd]temp() */
शून्य
mktemp_proto(वर्ण *s, size_t len)
{
	ध्रुव वर्ण *tmpdir;
	पूर्णाङ्क r;

	सचे ((tmpdir = getenv("TMPDIR")) != रिक्त) {
		r = snprintf(s, len, "%s/ssh-XXXXXXXXXXXX", tmpdir);
		सचे (r > 0 && (size_t)r < len)
			पटिनिवत्त;
	}
	r = snprintf(s, len, "/tmp/ssh-XXXXXXXXXXXX");
	सचे (r < 0 || (size_t)r >= len)
		fatal_f("template string too short");
}

स्थिर ध्रुव संरचना {
	ध्रुव वर्ण *name;
	पूर्णाङ्क मानम्;
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
	{ रिक्त, -1 }
};

पूर्णाङ्क
parse_ipqos(ध्रुव वर्ण *cp)
{
	ध्रुव वर्ण *errstr;
	u_int i;
	पूर्णाङ्क val;

	सचे (cp == रिक्त)
		पटिनिवत्त -1;
	अत्थाय (i = 0; ipqos[i].name != रिक्त; i++) {
		सचे (strcasecmp(cp, ipqos[i].name) == 0)
			पटिनिवत्त ipqos[i].मानम्;
	}
	/* Try parsing as an integer */
	val = (पूर्णाङ्क)strtonum(cp, 0, 255, &errstr);
	सचे (errstr)
		पटिनिवत्त -1;
	पटिनिवत्त val;
}

ध्रुव वर्ण *
iptos2str(पूर्णाङ्क iptos)
{
	पूर्णाङ्क i;
	स्थिर वर्ण iptos_str[परिमाण "0xff"];

	अत्थाय (i = 0; ipqos[i].name != रिक्त; i++) {
		सचे (ipqos[i].मानम् == iptos)
			पटिनिवत्त ipqos[i].name;
	}
	snprintf(iptos_str, परिमाण iptos_str, "0x%02x", iptos);
	पटिनिवत्त iptos_str;
}

शून्य
lowercase(वर्ण *s)
{
	अत्थाय (; *s; s++)
		*s = tolower((u_char)*s);
}

पूर्णाङ्क
unix_listener(ध्रुव वर्ण *path, पूर्णाङ्क backlog, पूर्णाङ्क unlink_first)
{
	संरचना sockaddr_un sunaddr;
	पूर्णाङ्क saved_errno, sock;

	memset(&sunaddr, 0, परिमाण(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	सचे (strlcpy(sunaddr.sun_path, path,
	    परिमाण(sunaddr.sun_path)) >= परिमाण(sunaddr.sun_path)) {
		error_f("path \"%s\" too long for Unix domain socket", path);
		errno = ENAMETOOLONG;
		पटिनिवत्त -1;
	}

	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	सचे (sock == -1) {
		saved_errno = errno;
		error_f("socket: %.100s", strerror(errno));
		errno = saved_errno;
		पटिनिवत्त -1;
	}
	सचे (unlink_first == 1) {
		सचे (unlink(path) != 0 && errno != ENOENT)
			error("unlink(%s): %.100s", path, strerror(errno));
	}
	सचे (bind(sock, (संरचना sockaddr *)&sunaddr, परिमाण(sunaddr)) == -1) {
		saved_errno = errno;
		error_f("cannot bind to path %s: %s", path, strerror(errno));
		close(sock);
		errno = saved_errno;
		पटिनिवत्त -1;
	}
	सचे (listen(sock, backlog) == -1) {
		saved_errno = errno;
		error_f("cannot listen on path %s: %s", path, strerror(errno));
		close(sock);
		unlink(path);
		errno = saved_errno;
		पटिनिवत्त -1;
	}
	पटिनिवत्त sock;
}

शून्य
sock_set_v6only(पूर्णाङ्क s)
{
#सचे defined(IPV6_V6ONLY) && !defined(__OpenBSD__)
	पूर्णाङ्क on = 1;

	debug3_f("set socket %d IPV6_V6ONLY", s);
	सचे (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &on, परिमाण(on)) == -1)
		error("setsockopt IPV6_V6ONLY: %s", strerror(errno));
#endif
}

/*
 * Compares two strings that maybe be NULL. Returns non-zero if strings
 * are both NULL or are identical, returns zero otherwise.
 */
स्थिर पूर्णाङ्क
strcmp_maybe_null(ध्रुव वर्ण *a, ध्रुव वर्ण *b)
{
	सचे ((a == रिक्त && b != रिक्त) || (a != रिक्त && b == रिक्त))
		पटिनिवत्त 0;
	सचे (a != रिक्त && strcmp(a, b) != 0)
		पटिनिवत्त 0;
	पटिनिवत्त 1;
}

/*
 * Compare two forwards, returning non-zero if they are identical or
 * zero otherwise.
 */
पूर्णाङ्क
forward_equals(ध्रुव संरचना Forward *a, ध्रुव संरचना Forward *b)
{
	सचे (strcmp_maybe_null(a->listen_host, b->listen_host) == 0)
		पटिनिवत्त 0;
	सचे (a->listen_port != b->listen_port)
		पटिनिवत्त 0;
	सचे (strcmp_maybe_null(a->listen_path, b->listen_path) == 0)
		पटिनिवत्त 0;
	सचे (strcmp_maybe_null(a->connect_host, b->connect_host) == 0)
		पटिनिवत्त 0;
	सचे (a->connect_port != b->connect_port)
		पटिनिवत्त 0;
	सचे (strcmp_maybe_null(a->connect_path, b->connect_path) == 0)
		पटिनिवत्त 0;
	/* allocated_port and handle are not checked */
	पटिनिवत्त 1;
}

/* returns port number, FWD_PERMIT_ANY_PORT or -1 on error */
पूर्णाङ्क
permitopen_port(ध्रुव वर्ण *p)
{
	पूर्णाङ्क port;

	सचे (strcmp(p, "*") == 0)
		पटिनिवत्त FWD_PERMIT_ANY_PORT;
	सचे ((port = a2port(p)) > 0)
		पटिनिवत्त port;
	पटिनिवत्त -1;
}

/* returns 1 if process is already daemonized, 0 otherwise */
पूर्णाङ्क
daemonized(शून्य)
{
	पूर्णाङ्क fd;

	सचे ((fd = open(_PATH_TTY, O_RDONLY | O_NOCTTY)) >= 0) {
		close(fd);
		पटिनिवत्त 0;	/* have controlling terminal */
	}
	सचे (getppid() != 1)
		पटिनिवत्त 0;	/* parent is not init */
	सचे (getsid(0) != getpid())
		पटिनिवत्त 0;	/* not session leader */
	debug3("already daemonized");
	पटिनिवत्त 1;
}

/*
 * Splits 's' into an argument vector. Handles quoted string and basic
 * escape characters (\\, \", \'). Caller must free the argument vector
 * and its members.
 */
पूर्णाङ्क
argv_split(ध्रुव वर्ण *s, पूर्णाङ्क *argcp, वर्ण ***argvp, पूर्णाङ्क terminate_on_comment)
{
	पूर्णाङ्क r = SSH_ERR_INTERNAL_ERROR;
	पूर्णाङ्क argc = 0, quote, i, j;
	वर्ण *arg, **argv = xcalloc(1, परिमाण(*argv));

	*argvp = रिक्त;
	*argcp = 0;

	अत्थाय (i = 0; s[i] != '\0'; i++) {
		/* Skip leading whitespace */
		सचे (s[i] == ' ' || s[i] == '\t')
			अनुवर्त;
		सचे (terminate_on_comment && s[i] == '#')
			भङ्ग;
		/* Start of a token */
		quote = 0;

		argv = xreallocarray(argv, (argc + 2), परिमाण(*argv));
		arg = argv[argc++] = xcalloc(1, strlen(s + i) + 1);
		argv[argc] = रिक्त;

		/* Copy the token in, removing escapes */
		अत्थाय (j = 0; s[i] != '\0'; i++) {
			सचे (s[i] == '\\') {
				सचे (s[i + 1] == '\'' ||
				    s[i + 1] == '\"' ||
				    s[i + 1] == '\\' ||
				    (quote == 0 && s[i + 1] == ' ')) {
					i++; /* Skip '\' */
					arg[j++] = s[i];
				} अञ्ञथा {
					/* Unrecognised escape */
					arg[j++] = s[i];
				}
			} अञ्ञथा सचे (quote == 0 && (s[i] == ' ' || s[i] == '\t'))
				भङ्ग; /* done */
			अञ्ञथा सचे (quote == 0 && (s[i] == '\"' || s[i] == '\''))
				quote = s[i]; /* quote start */
			अञ्ञथा सचे (quote != 0 && s[i] == quote)
				quote = 0; /* quote end */
			अञ्ञथा
				arg[j++] = s[i];
		}
		सचे (s[i] == '\0') {
			सचे (quote != 0) {
				/* Ran out of string looking for close quote */
				r = SSH_ERR_INVALID_FORMAT;
				गच्छ out;
			}
			भङ्ग;
		}
	}
	/* Success */
	*argcp = argc;
	*argvp = argv;
	argc = 0;
	argv = रिक्त;
	r = 0;
 out:
	सचे (argc != 0 && argv != रिक्त) {
		अत्थाय (i = 0; i < argc; i++)
			मुक्त(argv[i]);
		मुक्त(argv);
	}
	पटिनिवत्त r;
}

/*
 * Reassemble an argument vector into a string, quoting and escaping as
 * necessary. Caller must free returned string.
 */
वर्ण *
argv_assemble(पूर्णाङ्क argc, वर्ण **argv)
{
	पूर्णाङ्क i, j, ws, r;
	वर्ण c, *ret;
	संरचना sshbuf *buf, *arg;

	सचे ((buf = sshbuf_new()) == रिक्त || (arg = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");

	अत्थाय (i = 0; i < argc; i++) {
		ws = 0;
		sshbuf_reset(arg);
		अत्थाय (j = 0; argv[i][j] != '\0'; j++) {
			r = 0;
			c = argv[i][j];
			विकल्प (c) {
			पक्ष ' ':
			पक्ष '\t':
				ws = 1;
				r = sshbuf_put_u8(arg, c);
				भङ्ग;
			पक्ष '\\':
			पक्ष '\'':
			पक्ष '"':
				सचे ((r = sshbuf_put_u8(arg, '\\')) != 0)
					भङ्ग;
				/* FALLTHROUGH */
			स्वभाव:
				r = sshbuf_put_u8(arg, c);
				भङ्ग;
			}
			सचे (r != 0)
				fatal_fr(r, "sshbuf_put_u8");
		}
		सचे ((i != 0 && (r = sshbuf_put_u8(buf, ' ')) != 0) ||
		    (ws != 0 && (r = sshbuf_put_u8(buf, '"')) != 0) ||
		    (r = sshbuf_putb(buf, arg)) != 0 ||
		    (ws != 0 && (r = sshbuf_put_u8(buf, '"')) != 0))
			fatal_fr(r, "assemble");
	}
	सचे ((ret = malloc(sshbuf_len(buf) + 1)) == रिक्त)
		fatal_f("malloc failed");
	memcpy(ret, sshbuf_ptr(buf), sshbuf_len(buf));
	ret[sshbuf_len(buf)] = '\0';
	sshbuf_free(buf);
	sshbuf_free(arg);
	पटिनिवत्त ret;
}

वर्ण *
argv_next(पूर्णाङ्क *argcp, वर्ण ***argvp)
{
	वर्ण *ret = (*argvp)[0];

	सचे (*argcp > 0 && ret != रिक्त) {
		(*argcp)--;
		(*argvp)++;
	}
	पटिनिवत्त ret;
}

शून्य
argv_consume(पूर्णाङ्क *argcp)
{
	*argcp = 0;
}

शून्य
argv_free(वर्ण **av, पूर्णाङ्क ac)
{
	पूर्णाङ्क i;

	सचे (av == रिक्त)
		पटिनिवत्त;
	अत्थाय (i = 0; i < ac; i++)
		मुक्त(av[i]);
	मुक्त(av);
}

/* Returns 0 if pid exited cleanly, non-zero otherwise */
पूर्णाङ्क
exited_cleanly(pid_t pid, ध्रुव वर्ण *tag, ध्रुव वर्ण *cmd, पूर्णाङ्क quiet)
{
	पूर्णाङ्क status;

	याव (waitpid(pid, &status, 0) == -1) {
		सचे (errno != EINTR) {
			error("%s waitpid: %s", tag, strerror(errno));
			पटिनिवत्त -1;
		}
	}
	सचे (WIFSIGNALED(status)) {
		error("%s %s exited on signal %d", tag, cmd, WTERMSIG(status));
		पटिनिवत्त -1;
	} अञ्ञथा सचे (WEXITSTATUS(status) != 0) {
		do_log2(quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_INFO,
		    "%s %s failed, status %d", tag, cmd, WEXITSTATUS(status));
		पटिनिवत्त -1;
	}
	पटिनिवत्त 0;
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
पूर्णाङ्क
safe_path(ध्रुव वर्ण *name, संरचना stat *stp, ध्रुव वर्ण *pw_dir,
    uid_t uid, वर्ण *err, size_t errlen)
{
	वर्ण buf[PATH_MAX], buf2[PATH_MAX], homedir[PATH_MAX];
	वर्ण *cp;
	पूर्णाङ्क comparehome = 0;
	संरचना stat st;

	सचे (realpath(name, buf) == रिक्त) {
		snprintf(err, errlen, "realpath %s failed: %s", name,
		    strerror(errno));
		पटिनिवत्त -1;
	}
	सचे (pw_dir != रिक्त && realpath(pw_dir, homedir) != रिक्त)
		comparehome = 1;

	सचे (!S_ISREG(stp->st_mode)) {
		snprintf(err, errlen, "%s is not a regular file", buf);
		पटिनिवत्त -1;
	}
	सचे ((!platform_sys_dir_uid(stp->st_uid) && stp->st_uid != uid) ||
	    (stp->st_mode & 022) != 0) {
		snprintf(err, errlen, "bad ownership or modes for file %s",
		    buf);
		पटिनिवत्त -1;
	}

	/* for each component of the canonical path, walking upwards */
	अत्थाय (;;) {
		/*
		 * POSIX allows dirname to modify its argument and return a
		 * pointer into it, so make a copy to avoid overlapping strlcpy.
		 */
		strlcpy(buf2, buf, परिमाण(buf2));
		सचे ((cp = dirname(buf2)) == रिक्त) {
			snprintf(err, errlen, "dirname() failed");
			पटिनिवत्त -1;
		}
		strlcpy(buf, cp, परिमाण(buf));

		सचे (stat(buf, &st) == -1 ||
		    (!platform_sys_dir_uid(st.st_uid) && st.st_uid != uid) ||
		    (st.st_mode & 022) != 0) {
			snprintf(err, errlen,
			    "bad ownership or modes for directory %s", buf);
			पटिनिवत्त -1;
		}

		/* If are past the homedir then we can stop */
		सचे (comparehome && strcmp(homedir, buf) == 0)
			भङ्ग;

		/*
		 * dirname should always complete with a "/" path,
		 * but we can be paranoid and check for "." too
		 */
		सचे ((strcmp("/", buf) == 0) || (strcmp(".", buf) == 0))
			भङ्ग;
	}
	पटिनिवत्त 0;
}

/*
 * Version of safe_path() that accepts an open file descriptor to
 * avoid races.
 *
 * Returns 0 on success and -1 on failure
 */
पूर्णाङ्क
safe_path_fd(पूर्णाङ्क fd, ध्रुव वर्ण *file, संरचना passwd *pw,
    वर्ण *err, size_t errlen)
{
	संरचना stat st;

	/* check the open file to avoid races */
	सचे (fstat(fd, &st) == -1) {
		snprintf(err, errlen, "cannot stat file %s: %s",
		    file, strerror(errno));
		पटिनिवत्त -1;
	}
	पटिनिवत्त safe_path(file, &st, pw->pw_dir, pw->pw_uid, err, errlen);
}

/*
 * Sets the value of the given variable in the environment.  If the variable
 * already exists, its value is overridden.
 */
शून्य
child_set_env(वर्ण ***envp, u_int *envsizep, ध्रुव वर्ण *name,
	ध्रुव वर्ण *मानम्)
{
	वर्ण **env;
	u_int envsize;
	u_int i, namelen;

	सचे (strchr(name, '=') != रिक्त) {
		error("Invalid environment variable \"%.100s\"", name);
		पटिनिवत्त;
	}

	/*
	 * If we're passed an uninitialized list, allocate a single null
	 * entry before continuing.
	 */
	सचे ((*envp == रिक्त) != (*envsizep == 0))
		fatal_f("environment size mismatch");
	सचे (*envp == रिक्त && *envsizep == 0) {
		*envp = xmalloc(परिमाण(वर्ण *));
		*envp[0] = रिक्त;
		*envsizep = 1;
	}

	/*
	 * Find the slot where the value should be stored.  If the variable
	 * already exists, we reuse the slot; otherwise we append a new slot
	 * at the end of the array, expanding if necessary.
	 */
	env = *envp;
	namelen = strlen(name);
	अत्थाय (i = 0; env[i]; i++)
		सचे (strncmp(env[i], name, namelen) == 0 && env[i][namelen] == '=')
			भङ्ग;
	सचे (env[i]) {
		/* Reuse the slot. */
		मुक्त(env[i]);
	} अञ्ञथा {
		/* New variable.  Expand if necessary. */
		envsize = *envsizep;
		सचे (i >= envsize - 1) {
			सचे (envsize >= 1000)
				fatal("child_set_env: too many env vars");
			envsize += 50;
			env = (*envp) = xreallocarray(env, envsize, परिमाण(वर्ण *));
			*envsizep = envsize;
		}
		/* Need to set the NULL pointer at end of array beyond the new slot. */
		env[i + 1] = रिक्त;
	}

	/* Allocate space and format the variable in the appropriate slot. */
	/* XXX xasprintf */
	env[i] = xmalloc(strlen(name) + 1 + strlen(मानम्) + 1);
	snprintf(env[i], strlen(name) + 1 + strlen(मानम्) + 1, "%s=%s", name, मानम्);
}

/*
 * Check and optionally lowercase a domain name, also removes trailing '.'
 * Returns 1 on success and 0 on failure, storing an error message in errstr.
 */
पूर्णाङ्क
valid_domain(वर्ण *name, पूर्णाङ्क makelower, ध्रुव वर्ण **errstr)
{
	size_t i, l = strlen(name);
	u_char c, last = '\0';
	स्थिर वर्ण errbuf[256];

	सचे (l == 0) {
		strlcpy(errbuf, "empty domain name", परिमाण(errbuf));
		गच्छ bad;
	}
	सचे (!isalpha((u_char)name[0]) && !isdigit((u_char)name[0]) &&
	   name[0] != '_' /* technically invalid, but common */) {
		snprintf(errbuf, परिमाण(errbuf), "domain name \"%.100s\" "
		    "starts with invalid character", name);
		गच्छ bad;
	}
	अत्थाय (i = 0; i < l; i++) {
		c = tolower((u_char)name[i]);
		सचे (makelower)
			name[i] = (वर्ण)c;
		सचे (last == '.' && c == '.') {
			snprintf(errbuf, परिमाण(errbuf), "domain name "
			    "\"%.100s\" contains consecutive separators", name);
			गच्छ bad;
		}
		सचे (c != '.' && c != '-' && !isalnum(c) &&
		    c != '_') /* technically invalid, but common */ {
			snprintf(errbuf, परिमाण(errbuf), "domain name "
			    "\"%.100s\" contains invalid characters", name);
			गच्छ bad;
		}
		last = c;
	}
	सचे (name[l - 1] == '.')
		name[l - 1] = '\0';
	सचे (errstr != रिक्त)
		*errstr = रिक्त;
	पटिनिवत्त 1;
bad:
	सचे (errstr != रिक्त)
		*errstr = errbuf;
	पटिनिवत्त 0;
}

/*
 * Verify that a environment variable name (not including initial '$') is
 * valid; consisting of one or more alphanumeric or underscore characters only.
 * Returns 1 on valid, 0 otherwise.
 */
पूर्णाङ्क
valid_env_name(ध्रुव वर्ण *name)
{
	ध्रुव वर्ण *cp;

	सचे (name[0] == '\0')
		पटिनिवत्त 0;
	अत्थाय (cp = name; *cp != '\0'; cp++) {
		सचे (!isalnum((u_char)*cp) && *cp != '_')
			पटिनिवत्त 0;
	}
	पटिनिवत्त 1;
}

ध्रुव वर्ण *
atoi_err(ध्रुव वर्ण *nptr, पूर्णाङ्क *val)
{
	ध्रुव वर्ण *errstr = रिक्त;

	सचे (nptr == रिक्त || *nptr == '\0')
		पटिनिवत्त "missing";
	*val = strtonum(nptr, 0, INT_MAX, &errstr);
	पटिनिवत्त errstr;
}

पूर्णाङ्क
parse_absolute_time(ध्रुव वर्ण *s, uint64_t *tp)
{
	संरचना tm tm;
	time_t tt;
	वर्ण buf[32], *fmt;
	ध्रुव वर्ण *cp;
	size_t l;
	पूर्णाङ्क is_utc = 0;

	*tp = 0;

	l = strlen(s);
	सचे (l > 1 && strcasecmp(s + l - 1, "Z") == 0) {
		is_utc = 1;
		l--;
	} अञ्ञथा सचे (l > 3 && strcasecmp(s + l - 3, "UTC") == 0) {
		is_utc = 1;
		l -= 3;
	}
	/*
	 * POSIX strptime says "The application shall ensure that there
	 * is white-space or other non-alphanumeric characters between
	 * any two conversion specifications" so arrange things this way.
	 */
	विकल्प (l) {
	पक्ष 8: /* YYYYMMDD */
		fmt = "%Y-%m-%d";
		snprintf(buf, परिमाण(buf), "%.4s-%.2s-%.2s", s, s + 4, s + 6);
		भङ्ग;
	पक्ष 12: /* YYYYMMDDHHMM */
		fmt = "%Y-%m-%dT%H:%M";
		snprintf(buf, परिमाण(buf), "%.4s-%.2s-%.2sT%.2s:%.2s",
		    s, s + 4, s + 6, s + 8, s + 10);
		भङ्ग;
	पक्ष 14: /* YYYYMMDDHHMMSS */
		fmt = "%Y-%m-%dT%H:%M:%S";
		snprintf(buf, परिमाण(buf), "%.4s-%.2s-%.2sT%.2s:%.2s:%.2s",
		    s, s + 4, s + 6, s + 8, s + 10, s + 12);
		भङ्ग;
	स्वभाव:
		पटिनिवत्त SSH_ERR_INVALID_FORMAT;
	}

	memset(&tm, 0, परिमाण(tm));
	सचे ((cp = strptime(buf, fmt, &tm)) == रिक्त || *cp != '\0')
		पटिनिवत्त SSH_ERR_INVALID_FORMAT;
	सचे (is_utc) {
		tm.tm_wday = -1;	/* sentinel for error */
		सचे ((tt = timegm(&tm)) == -1 && tm.tm_wday == -1)
			पटिनिवत्त SSH_ERR_INVALID_FORMAT;
	} अञ्ञथा {
		tm.tm_wday = -1;	/* sentinel for error */
		tm.tm_isdst = -1;	/* mktime decides DST */
		सचे ((tt = mktime(&tm)) == -1 && tm.tm_wday == -1)
			पटिनिवत्त SSH_ERR_INVALID_FORMAT;
	}
	/* success */
	*tp = (uint64_t)tt;
	पटिनिवत्त 0;
}

शून्य
format_absolute_time(uint64_t t, वर्ण *buf, size_t len)
{
	time_t tt = t > SSH_TIME_T_MAX ? SSH_TIME_T_MAX : t;
	संरचना tm tm;

	सचे (localtime_r(&tt, &tm) == रिक्त)
		strlcpy(buf, "UNKNOWN-TIME", len);
	अञ्ञथा
		strftime(buf, len, "%Y-%m-%dT%H:%M:%S", &tm);
}

/*
 * Parse a "pattern=interval" clause (e.g. a ChannelTimeout).
 * Returns 0 on success or non-zero on failure.
 * Caller must free *typep.
 */
पूर्णाङ्क
parse_pattern_interval(ध्रुव वर्ण *s, वर्ण **typep, द्विगुण *secsp)
{
	वर्ण *cp, *sdup;
	द्विगुण secs;

	सचे (typep != रिक्त)
		*typep = रिक्त;
	सचे (secsp != रिक्त)
		*secsp = 0;
	सचे (s == रिक्त)
		पटिनिवत्त -1;
	sdup = xstrdup(s);

	सचे ((cp = strchr(sdup, '=')) == रिक्त || cp == sdup) {
		मुक्त(sdup);
		पटिनिवत्त -1;
	}
	*cp++ = '\0';
	सचे ((secs = convtime_double(cp)) < 0.0) {
		मुक्त(sdup);
		पटिनिवत्त -1;
	}
	/* success */
	सचे (typep != रिक्त)
		*typep = xstrdup(sdup);
	सचे (secsp != रिक्त)
		*secsp = secs;
	मुक्त(sdup);
	पटिनिवत्त 0;
}

/* check if path is absolute */
पूर्णाङ्क
path_absolute(ध्रुव वर्ण *path)
{
	पटिनिवत्त (*path == '/') ? 1 : 0;
}

शून्य
skip_space(वर्ण **cpp)
{
	वर्ण *cp;

	अत्थाय (cp = *cpp; *cp == ' ' || *cp == '\t'; cp++)
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
पूर्णाङ्क
opt_flag(ध्रुव वर्ण *opt, पूर्णाङ्क allow_negate, ध्रुव वर्ण **optsp)
{
	size_t opt_len = strlen(opt);
	ध्रुव वर्ण *opts = *optsp;
	पूर्णाङ्क negate = 0;

	सचे (allow_negate && strncasecmp(opts, "no-", 3) == 0) {
		opts += 3;
		negate = 1;
	}
	सचे (strncasecmp(opts, opt, opt_len) == 0) {
		*optsp = opts + opt_len;
		पटिनिवत्त negate ? 0 : 1;
	}
	पटिनिवत्त -1;
}

वर्ण *
opt_dequote(ध्रुव वर्ण **sp, ध्रुव वर्ण **errstrp)
{
	ध्रुव वर्ण *s = *sp;
	वर्ण *ret;
	size_t i;

	*errstrp = रिक्त;
	सचे (*s != '"') {
		*errstrp = "missing start quote";
		पटिनिवत्त रिक्त;
	}
	s++;
	सचे ((ret = malloc(strlen((s)) + 1)) == रिक्त) {
		*errstrp = "memory allocation failed";
		पटिनिवत्त रिक्त;
	}
	अत्थाय (i = 0; *s != '\0' && *s != '"';) {
		सचे (s[0] == '\\' && s[1] == '"')
			s++;
		ret[i++] = *s++;
	}
	सचे (*s == '\0') {
		*errstrp = "missing end quote";
		मुक्त(ret);
		पटिनिवत्त रिक्त;
	}
	ret[i] = '\0';
	s++;
	*sp = s;
	पटिनिवत्त ret;
}

पूर्णाङ्क
opt_match(ध्रुव वर्ण **opts, ध्रुव वर्ण *term)
{
	सचे (strncasecmp((*opts), term, strlen(term)) == 0 &&
	    (*opts)[strlen(term)] == '=') {
		*opts += strlen(term) + 1;
		पटिनिवत्त 1;
	}
	पटिनिवत्त 0;
}

शून्य
opt_array_append2(ध्रुव वर्ण *file, ध्रुव पूर्णाङ्क पङ्क्तिः, ध्रुव वर्ण *directive,
    वर्ण ***array, पूर्णाङ्क **iarray, u_int *lp, ध्रुव वर्ण *s, पूर्णाङ्क i)
{

	सचे (*lp >= INT_MAX)
		fatal("%s line %d: Too many %s entries", file, पङ्क्तिः, directive);

	सचे (iarray != रिक्त) {
		*iarray = xrecallocarray(*iarray, *lp, *lp + 1,
		    परिमाण(**iarray));
		(*iarray)[*lp] = i;
	}

	*array = xrecallocarray(*array, *lp, *lp + 1, परिमाण(**array));
	(*array)[*lp] = xstrdup(s);
	(*lp)++;
}

शून्य
opt_array_append(ध्रुव वर्ण *file, ध्रुव पूर्णाङ्क पङ्क्तिः, ध्रुव वर्ण *directive,
    वर्ण ***array, u_int *lp, ध्रुव वर्ण *s)
{
	opt_array_append2(file, पङ्क्तिः, directive, array, रिक्त, lp, s, 0);
}

शून्य
opt_array_free2(वर्ण **array, पूर्णाङ्क **iarray, u_int l)
{
	u_int i;

	सचे (array == रिक्त || l == 0)
		पटिनिवत्त;
	अत्थाय (i = 0; i < l; i++)
		मुक्त(array[i]);
	मुक्त(array);
	मुक्त(iarray);
}

sshsig_t
ssh_signal(पूर्णाङ्क signum, sshsig_t handler)
{
	संरचना sigaction sa, osa;

	/* mask all other signals while in handler */
	memset(&sa, 0, परिमाण(sa));
	sa.sa_handler = handler;
	sigfillset(&sa.sa_mask);
#सचे defined(SA_RESTART) && !defined(NO_SA_RESTART)
	सचे (signum != SIGALRM)
		sa.sa_flags = SA_RESTART;
#endif
	सचे (sigaction(signum, &sa, &osa) == -1) {
		debug3("sigaction(%s): %s", strsignal(signum), strerror(errno));
		पटिनिवत्त SIG_ERR;
	}
	पटिनिवत्त osa.sa_handler;
}

पूर्णाङ्क
stdfd_devnull(पूर्णाङ्क do_stdin, पूर्णाङ्क do_stdout, पूर्णाङ्क do_stderr)
{
	पूर्णाङ्क devnull, ret = 0;

	सचे ((devnull = open(_PATH_DEVNULL, O_RDWR)) == -1) {
		error_f("open %s: %s", _PATH_DEVNULL,
		    strerror(errno));
		पटिनिवत्त -1;
	}
	सचे ((do_stdin && dup2(devnull, STDIN_FILENO) == -1) ||
	    (do_stdout && dup2(devnull, STDOUT_FILENO) == -1) ||
	    (do_stderr && dup2(devnull, STDERR_FILENO) == -1)) {
		error_f("dup2: %s", strerror(errno));
		ret = -1;
	}
	सचे (devnull > STDERR_FILENO)
		close(devnull);
	पटिनिवत्त ret;
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
subprocess(ध्रुव वर्ण *tag, ध्रुव वर्ण *command,
    पूर्णाङ्क ac, वर्ण **av, FILE **child, u_int flags,
    संरचना passwd *pw, privdrop_fn *drop_privs, privrestore_fn *restore_privs)
{
	FILE *f = रिक्त;
	संरचना stat st;
	पूर्णाङ्क fd, devnull, p[2], i;
	pid_t pid;
	वर्ण *cp, errmsg[512];
	u_int nenv = 0;
	वर्ण **env = रिक्त;

	/* If dropping privs, then must specify user and restore function */
	सचे (drop_privs != रिक्त && (pw == रिक्त || restore_privs == रिक्त)) {
		error("%s: inconsistent arguments", tag); /* XXX fatal? */
		पटिनिवत्त 0;
	}
	सचे (pw == रिक्त && (pw = getpwuid(getuid())) == रिक्त) {
		error("%s: no user for current uid", tag);
		पटिनिवत्त 0;
	}
	सचे (child != रिक्त)
		*child = रिक्त;

	debug3_f("%s command \"%s\" running as %s (flags 0x%x)",
	    tag, command, pw->pw_name, flags);

	/* Check consistency */
	सचे ((flags & SSH_SUBPROCESS_STDOUT_DISCARD) != 0 &&
	    (flags & SSH_SUBPROCESS_STDOUT_CAPTURE) != 0) {
		error_f("inconsistent flags");
		पटिनिवत्त 0;
	}
	सचे (((flags & SSH_SUBPROCESS_STDOUT_CAPTURE) == 0) != (child == रिक्त)) {
		error_f("inconsistent flags/output");
		पटिनिवत्त 0;
	}

	/*
	 * If executing an explicit binary, then verify the it exists
	 * and appears safe-ish to execute
	 */
	सचे (!path_absolute(av[0])) {
		error("%s path is not absolute", tag);
		पटिनिवत्त 0;
	}
	सचे (drop_privs != रिक्त)
		drop_privs(pw);
	सचे (stat(av[0], &st) == -1) {
		error("Could not stat %s \"%s\": %s", tag,
		    av[0], strerror(errno));
		गच्छ restore_return;
	}
	सचे ((flags & SSH_SUBPROCESS_UNSAFE_PATH) == 0 &&
	    safe_path(av[0], &st, रिक्त, 0, errmsg, परिमाण(errmsg)) != 0) {
		error("Unsafe %s \"%s\": %s", tag, av[0], errmsg);
		गच्छ restore_return;
	}
	/* Prepare to keep the child's stdout if requested */
	सचे (pipe(p) == -1) {
		error("%s: pipe: %s", tag, strerror(errno));
 restore_return:
		सचे (restore_privs != रिक्त)
			restore_privs();
		पटिनिवत्त 0;
	}
	सचे (restore_privs != रिक्त)
		restore_privs();

	विकल्प ((pid = fork())) {
	पक्ष -1: /* error */
		error("%s: fork: %s", tag, strerror(errno));
		close(p[0]);
		close(p[1]);
		पटिनिवत्त 0;
	पक्ष 0: /* child */
		/* Prepare a minimal environment for the child. */
		सचे ((flags & SSH_SUBPROCESS_PRESERVE_ENV) == 0) {
			nenv = 5;
			env = xcalloc(परिमाण(*env), nenv);
			child_set_env(&env, &nenv, "PATH", _PATH_STDPATH);
			child_set_env(&env, &nenv, "USER", pw->pw_name);
			child_set_env(&env, &nenv, "LOGNAME", pw->pw_name);
			child_set_env(&env, &nenv, "HOME", pw->pw_dir);
			सचे ((cp = getenv("LANG")) != रिक्त)
				child_set_env(&env, &nenv, "LANG", cp);
		}

		अत्थाय (i = 1; i < NSIG; i++)
			ssh_signal(i, SIG_DFL);

		सचे ((devnull = open(_PATH_DEVNULL, O_RDWR)) == -1) {
			error("%s: open %s: %s", tag, _PATH_DEVNULL,
			    strerror(errno));
			_exit(1);
		}
		सचे (dup2(devnull, STDIN_FILENO) == -1) {
			error("%s: dup2: %s", tag, strerror(errno));
			_exit(1);
		}

		/* Set up stdout as requested; leave stderr in place for now. */
		fd = -1;
		सचे ((flags & SSH_SUBPROCESS_STDOUT_CAPTURE) != 0)
			fd = p[1];
		अञ्ञथा सचे ((flags & SSH_SUBPROCESS_STDOUT_DISCARD) != 0)
			fd = devnull;
		सचे (fd != -1 && dup2(fd, STDOUT_FILENO) == -1) {
			error("%s: dup2: %s", tag, strerror(errno));
			_exit(1);
		}
		closefrom(STDERR_FILENO + 1);

		सचे (geteuid() == 0 &&
		    initgroups(pw->pw_name, pw->pw_gid) == -1) {
			error("%s: initgroups(%s, %u): %s", tag,
			    pw->pw_name, (u_int)pw->pw_gid, strerror(errno));
			_exit(1);
		}
		सचे (setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) == -1) {
			error("%s: setresgid %u: %s", tag, (u_int)pw->pw_gid,
			    strerror(errno));
			_exit(1);
		}
		सचे (setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) == -1) {
			error("%s: setresuid %u: %s", tag, (u_int)pw->pw_uid,
			    strerror(errno));
			_exit(1);
		}
		/* stdin is pointed to /dev/null at this point */
		सचे ((flags & SSH_SUBPROCESS_STDOUT_DISCARD) != 0 &&
		    dup2(STDIN_FILENO, STDERR_FILENO) == -1) {
			error("%s: dup2: %s", tag, strerror(errno));
			_exit(1);
		}
		सचे (env != रिक्त)
			execve(av[0], av, env);
		अञ्ञथा
			execv(av[0], av);
		error("%s %s \"%s\": %s", tag, env == रिक्त ? "execv" : "execve",
		    command, strerror(errno));
		_exit(127);
	स्वभाव: /* parent */
		भङ्ग;
	}

	close(p[1]);
	सचे ((flags & SSH_SUBPROCESS_STDOUT_CAPTURE) == 0)
		close(p[0]);
	अञ्ञथा सचे ((f = fdopen(p[0], "r")) == रिक्त) {
		error("%s: fdopen: %s", tag, strerror(errno));
		close(p[0]);
		/* Don't leave zombie child */
		kill(pid, SIGTERM);
		याव (waitpid(pid, रिक्त, 0) == -1 && errno == EINTR)
			;
		पटिनिवत्त 0;
	}
	/* Success */
	debug3_f("%s pid %ld", tag, (long)pid);
	सचे (child != रिक्त)
		*child = f;
	पटिनिवत्त pid;
}

ध्रुव वर्ण *
lookup_env_in_list(ध्रुव वर्ण *env, वर्ण * ध्रुव *envs, size_t nenvs)
{
	size_t i, envlen;

	envlen = strlen(env);
	अत्थाय (i = 0; i < nenvs; i++) {
		सचे (strncmp(envs[i], env, envlen) == 0 &&
		    envs[i][envlen] == '=') {
			पटिनिवत्त envs[i] + envlen + 1;
		}
	}
	पटिनिवत्त रिक्त;
}

ध्रुव वर्ण *
lookup_setenv_in_list(ध्रुव वर्ण *env, वर्ण * ध्रुव *envs, size_t nenvs)
{
	वर्ण *name, *cp;
	ध्रुव वर्ण *ret;

	name = xstrdup(env);
	सचे ((cp = strchr(name, '=')) == रिक्त) {
		मुक्त(name);
		पटिनिवत्त रिक्त; /* not env=val */
	}
	*cp = '\0';
	ret = lookup_env_in_list(name, envs, nenvs);
	मुक्त(name);
	पटिनिवत्त ret;
}

/*
 * Helpers for managing poll(2)/ppoll(2) timeouts
 * Will remember the earliest deadline and return it for use in poll/ppoll.
 */

/* Initialise a poll/ppoll timeout with an indefinite deadline */
शून्य
ptimeout_init(संरचना timespec *pt)
{
	/*
	 * Deliberately invalid for ppoll(2).
	 * Will be converted to NULL in ptimeout_get_tspec() later.
	 */
	pt->tv_sec = -1;
	pt->tv_nsec = 0;
}

/* Specify a poll/ppoll deadline of at most 'sec' seconds */
शून्य
ptimeout_deadline_sec(संरचना timespec *pt, long sec)
{
	सचे (pt->tv_sec == -1 || pt->tv_sec >= sec) {
		pt->tv_sec = sec;
		pt->tv_nsec = 0;
	}
}

/* Specify a poll/ppoll deadline of at most 'p' (timespec) */
स्थिर शून्य
ptimeout_deadline_tsp(संरचना timespec *pt, संरचना timespec *p)
{
	सचे (pt->tv_sec == -1 || timespeccmp(pt, p, >=))
		*pt = *p;
}

/* Specify a poll/ppoll deadline of at most 'ms' milliseconds */
शून्य
ptimeout_deadline_ms(संरचना timespec *pt, long ms)
{
	संरचना timespec p;

	p.tv_sec = ms / 1000;
	p.tv_nsec = (ms % 1000) * 1000000;
	ptimeout_deadline_tsp(pt, &p);
}

/* Specify a poll/ppoll deadline of at most 'sec' seconds (double) */
शून्य
ptimeout_deadline_sec_double(संरचना timespec *pt, द्विगुण sec)
{
	संरचना timespec t;

	memset(&t, 0, परिमाण(t));
	सचे ((int64_t)sec >= SSH_TIME_T_MAX)
		t.tv_sec = SSH_TIME_T_MAX;
	अञ्ञथा सचे (sec > 0) {
		t.tv_sec = sec;
		t.tv_nsec = (sec - (द्विगुण)t.tv_sec) * 1000000000.0;
	}
	ptimeout_deadline_tsp(pt, &t);
}

/* Specify a poll/ppoll deadline at wall clock monotime 'when' (timespec) */
शून्य
ptimeout_deadline_monotime_tsp(संरचना timespec *pt, संरचना timespec *when)
{
	संरचना timespec now, t;

	monotime_ts(&now);

	सचे (timespeccmp(&now, when, >=)) {
		/* 'when' is now or in the past. Timeout ASAP */
		pt->tv_sec = 0;
		pt->tv_nsec = 0;
	} अञ्ञथा {
		timespecsub(when, &now, &t);
		ptimeout_deadline_tsp(pt, &t);
	}
}

/* Specify a poll/ppoll deadline at wall clock monotime 'when' (double) */
शून्य
ptimeout_deadline_monotime_double(संरचना timespec *pt, द्विगुण when)
{
	ptimeout_deadline_sec_double(pt, when - monotime_double());
}

/* Specify a poll/ppoll deadline at wall clock monotime 'when' */
शून्य
ptimeout_deadline_monotime(संरचना timespec *pt, time_t when)
{
	संरचना timespec t;

	t.tv_sec = when;
	t.tv_nsec = 0;
	ptimeout_deadline_monotime_tsp(pt, &t);
}

/* Get a poll(2) timeout value in milliseconds */
पूर्णाङ्क
ptimeout_get_ms(संरचना timespec *pt)
{
	सचे (pt->tv_sec == -1)
		पटिनिवत्त -1;
	सचे (pt->tv_sec >= (INT_MAX - (pt->tv_nsec / 1000000)) / 1000)
		पटिनिवत्त INT_MAX;
	पटिनिवत्त (pt->tv_sec * 1000) + (pt->tv_nsec / 1000000);
}

/* Get a ppoll(2) timeout value as a timespec pointer */
संरचना timespec *
ptimeout_get_tsp(संरचना timespec *pt)
{
	पटिनिवत्त pt->tv_sec == -1 ? रिक्त : pt;
}

/* Returns non-zero if a timeout has been set (i.e. is not indefinite) */
पूर्णाङ्क
ptimeout_isset(संरचना timespec *pt)
{
	पटिनिवत्त pt->tv_sec != -1;
}

/*
 * Returns zero if the library at 'path' contains symbol 's', nonzero
 * otherwise.
 */
पूर्णाङ्क
lib_contains_चिह्नम्(ध्रुव वर्ण *path, ध्रुव वर्ण *s)
{
#ifdef HAVE_NLIST
	संरचना nlist nl[2];
	पूर्णाङ्क ret = -1, r;

	memset(nl, 0, परिमाण(nl));
	nl[0].n_name = xstrdup(s);
	nl[1].n_name = रिक्त;
	सचे ((r = nlist(path, nl)) == -1) {
		error_f("nlist failed for %s", path);
		गच्छ out;
	}
	सचे (r != 0 || nl[0].n_मानम् == 0 || nl[0].n_type == 0) {
		error_f("library %s does not contain symbol %s", path, s);
		गच्छ out;
	}
	/* success */
	ret = 0;
 out:
	मुक्त(nl[0].n_name);
	पटिनिवत्त ret;
#अञ्ञथा /* HAVE_NLIST */
	पूर्णाङ्क fd, ret = -1;
	संरचना stat st;
	शून्य *m = रिक्त;
	size_t sz = 0;

	memset(&st, 0, परिमाण(st));
	सचे ((fd = open(path, O_RDONLY)) < 0) {
		error_f("open %s: %s", path, strerror(errno));
		पटिनिवत्त -1;
	}
	सचे (fstat(fd, &st) != 0) {
		error_f("fstat %s: %s", path, strerror(errno));
		गच्छ out;
	}
	सचे (!S_ISREG(st.st_mode)) {
		error_f("%s is not a regular file", path);
		गच्छ out;
	}
	सचे (st.st_size < 0 ||
	    (size_t)st.st_size < strlen(s) ||
	    st.st_size >= INT_MAX/2) {
		error_f("%s bad size %lld", path, (long long)st.st_size);
		गच्छ out;
	}
	sz = (size_t)st.st_size;
	सचे ((m = mmap(रिक्त, sz, PROT_READ, MAP_PRIVATE, fd, 0)) == MAP_FAILED ||
	    m == रिक्त) {
		error_f("mmap %s: %s", path, strerror(errno));
		गच्छ out;
	}
	सचे (memmem(m, sz, s, strlen(s)) == रिक्त) {
		error_f("%s does not contain expected string %s", path, s);
		गच्छ out;
	}
	/* success */
	ret = 0;
 out:
	सचे (m != रिक्त && m != MAP_FAILED)
		munmap(m, sz);
	close(fd);
	पटिनिवत्त ret;
#endif /* HAVE_NLIST */
}

पूर्णाङ्क
signal_is_crash(पूर्णाङ्क sig)
{
	विकल्प (sig) {
	पक्ष SIGSEGV:
	पक्ष SIGBUS:
	पक्ष SIGTRAP:
	पक्ष SIGSYS:
	पक्ष SIGFPE:
	पक्ष SIGILL:
	पक्ष SIGABRT:
		पटिनिवत्त 1;
	}
	पटिनिवत्त 0;
}

वर्ण *
get_homedir(शून्य)
{
	वर्ण *cp;
	संरचना passwd *pw;

	सचे ((cp = getenv("HOME")) != रिक्त && *cp != '\0')
		पटिनिवत्त xstrdup(cp);

	सचे ((pw = getpwuid(getuid())) != रिक्त && *pw->pw_dir != '\0')
		पटिनिवत्त xstrdup(pw->pw_dir);

	पटिनिवत्त रिक्त;
}

पूर्णाङ्क
mkdir_path(ध्रुव वर्ण *target, mode_t mode)
{
#सचे defined(HAVE_OPENAT) && defined(O_DIRECTORY)
	वर्ण *dir, *odir = रिक्त, *next;
	पूर्णाङ्क fd = AT_FDCWD, fd2, subpath_len, ret = -1;

	dir = odir = xstrdup(target);

	सचे (*dir == '/' &&
	    (fd = open("/", O_RDONLY|O_DIRECTORY)) == -1) {
		error_f("open(\"/\"): %s", strerror(errno));
		मुक्त(odir);
		पटिनिवत्त -1;
	}
	/* Work through the path, component-wise */
	अत्थाय (; dir != रिक्त && *dir != '\0'; dir = next) {
		सचे ((next = strchr(dir, '/')) != रिक्त)
			*(next++) = '\0';
		सचे (*dir == '\0')
			अनुवर्त;
		subpath_len = (next == रिक्त) ? INT_MAX : next - odir - 1;
		सचे (mkdirat(fd, dir, mode) == 0)
			debug_f("created directory %.*s", subpath_len, target);
		अञ्ञथा सचे (errno != EEXIST) {
			error_f("mkdir(\"%.*s\"): %s",
			    subpath_len, target, strerror(errno));
			गच्छ out;
		}

		/* descend */
		सचे ((fd2 = openat(fd, dir, O_RDONLY|O_DIRECTORY)) == -1) {
			error_f("open(\"%.*s\"): %s",
			    subpath_len, target, strerror(errno));
			गच्छ out;
		}
		सचे (fd != AT_FDCWD)
			close(fd);
		fd = fd2;
	}
	/* success */
	ret = 0;
 out:
	मुक्त(odir);
	सचे (fd != AT_FDCWD)
		close(fd);
	पटिनिवत्त ret;
#अञ्ञथा
	/*
	 * If we don't have openat (which was added in POSIX.1-2008), fall back
	 * to the possibly racy way.
	 */
	वर्ण *dir, *odir, *p, path[PATH_MAX] = "";
	पूर्णाङ्क ret = -1;
	size_t plen = परिमाण(path);

	dir = odir = xstrdup(target);

	/* If the dir is relative, start with cwd. */
	सचे (*dir != '/' && getcwd(path, plen) == रिक्त) {
		error_f("getcwd: %s", strerror(errno));
		गच्छ out;
	}

	/* Work through the path, component-wise */
	याव ((p = strsep(&dir, "/"))) {
		सचे (*p == '\0')
			अनुवर्त;
		सचे (strlcat(path, "/", plen) >= plen ||
		    strlcat(path, p, plen) >= plen)
			गच्छ out;
		सचे (mkdir(path, mode) == 0)
			debug_f("created directory %s", path);
		अञ्ञथा सचे (errno != EEXIST && errno != EISDIR) {
			error_f("mkdir(\"%s\"): %s", path, strerror(errno));
			गच्छ out;
		}
	}
	/* success */
	ret = 0;
 out:
	मुक्त(odir);
	पटिनिवत्त ret;
#endif
}
