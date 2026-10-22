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


#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/ioctl.h>
#అన్తర్భావ <sys/mman.h>
#అన్తర్భావ <sys/socket.h>
#అన్తర్భావ <sys/stat.h>
#అన్తర్భావ <sys/time.h>
#అన్తర్భావ <sys/wait.h>
#అన్తర్భావ <sys/un.h>

#అన్తర్భావ <limits.h>
#అన్తర్భావ <libgen.h>
#అన్తర్భావ <poll.h>
#అన్తర్భావ <nlist.h>
#అన్తర్భావ <signal.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdint.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <time.h>
#అన్తర్భావ <unistd.h>

#అన్తర్భావ <netinet/in.h>
#అన్తర్భావ <netinet/ip.h>
#అన్తర్భావ <netinet/tcp.h>
#అన్తర్భావ <arpa/inet.h>

#అన్తర్భావ <ctype.h>
#అన్తర్భావ <errno.h>
#అన్తర్భావ <fcntl.h>
#అన్తర్భావ <netdb.h>
#అన్తర్భావ <paths.h>
#అన్తర్భావ <pwd.h>
#అన్తర్భావ <grp.h>
#నిర్వచితమైతే SSH_TUN_OPENBSD
#అన్తర్భావ <net/if.h>
#అయితే_ముగింపు

#అన్తర్భావ "xmalloc.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "ssh.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "platform.h"

/* remove newline at end of string */
అక్షరం *
chop(అక్షరం *s)
{
	అక్షరం *t = s;
	అయితే (*t) {
		ఒకవేళ (*t == '\n' || *t == '\r') {
			*t = '\0';
			తిరిగి s;
		}
		t++;
	}
	తిరిగి s;

}

/* remove whitespace from end of string */
శూన్య
rtrim(అక్షరం *s)
{
	కొలత_t i;

	ఒకవేళ ((i = అక్షరశ్రేణి_పొడవు(s)) == 0)
		తిరిగి;
	చేయి {
		i--;
		ఒకవేళ (ఖాళీనా((గుర్తులేని అక్షరం)s[i]))
			s[i] = '\0';
		లేకపోతే
			ఆపు;
	} అయితే (i > 0);
}

/*
 * returns pointer to character after 'prefix' in 's' or otherwise NULL
 * if the prefix is not present.
 */
స్థిరరాశి అక్షరం *
strprefix(స్థిరరాశి అక్షరం *s, స్థిరరాశి అక్షరం *ఉపసర్గ, పూర్ణాంకం ignorecase)
{
	కొలత_t prefixlen;

	ఒకవేళ ((prefixlen = అక్షరశ్రేణి_పొడవు(ఉపసర్గ)) == 0)
		తిరిగి s;
	ఒకవేళ (ignorecase) {
		ఒకవేళ (strncasecmp(s, ఉపసర్గ, prefixlen) != 0)
			తిరిగి ఖాళీ;
	} లేకపోతే {
		ఒకవేళ (అక్షరశ్రేణి_పోలిక(s, ఉపసర్గ, prefixlen) != 0)
			తిరిగి ఖాళీ;
	}
	తిరిగి s + prefixlen;
}

/* Append string 's' to a NULL-terminated array of strings */
శూన్య
stringlist_append(అక్షరం ***listp, స్థిరరాశి అక్షరం *s)
{
	కొలత_t i = 0;

	ఒకవేళ (*listp == ఖాళీ)
		*listp = xcalloc(2, పరిమాణం(**listp));
	లేకపోతే {
		కొరకు (i = 0; (*listp)[i] != ఖాళీ; i++)
			; /* count */
		*listp = xrecallocarray(*listp, i + 1, i + 2, పరిమాణం(**listp));
	}
	(*listp)[i] = xstrdup(s);
}

శూన్య
stringlist_free(అక్షరం **list)
{
	కొలత_t i = 0;

	ఒకవేళ (list == ఖాళీ)
		తిరిగి;
	కొరకు (i = 0; list[i] != ఖాళీ; i++)
		విడుదల(list[i]);
	విడుదల(list);
}

/* set/unset filedescriptor to non-blocking */
పూర్ణాంకం
సమితి_nonblock(పూర్ణాంకం fd)
{
	పూర్ణాంకం val;

	val = fcntl(fd, F_GETFL);
	ఒకవేళ (val == -1) {
		error("fcntl(%d, F_GETFL): %s", fd, strerror(errno));
		తిరిగి (-1);
	}
	ఒకవేళ (val & O_NONBLOCK) {
		debug3("fd %d is O_NONBLOCK", fd);
		తిరిగి (0);
	}
	debug2("fd %d setting O_NONBLOCK", fd);
	val |= O_NONBLOCK;
	ఒకవేళ (fcntl(fd, F_SETFL, val) == -1) {
		debug("fcntl(%d, F_SETFL, O_NONBLOCK): %s", fd,
		    strerror(errno));
		తిరిగి (-1);
	}
	తిరిగి (0);
}

పూర్ణాంకం
unset_nonblock(పూర్ణాంకం fd)
{
	పూర్ణాంకం val;

	val = fcntl(fd, F_GETFL);
	ఒకవేళ (val == -1) {
		error("fcntl(%d, F_GETFL): %s", fd, strerror(errno));
		తిరిగి (-1);
	}
	ఒకవేళ (!(val & O_NONBLOCK)) {
		debug3("fd %d is not O_NONBLOCK", fd);
		తిరిగి (0);
	}
	debug("fd %d clearing O_NONBLOCK", fd);
	val &= ~O_NONBLOCK;
	ఒకవేళ (fcntl(fd, F_SETFL, val) == -1) {
		debug("fcntl(%d, F_SETFL, ~O_NONBLOCK): %s",
		    fd, strerror(errno));
		తిరిగి (-1);
	}
	తిరిగి (0);
}

స్థిరరాశి అక్షరం *
ssh_gai_strerror(పూర్ణాంకం gaierr)
{
	ఒకవేళ (gaierr == EAI_SYSTEM && errno != 0)
		తిరిగి strerror(errno);
	తిరిగి gai_strerror(gaierr);
}

/* disable nagle on socket */
శూన్య
సమితి_nodelay(పూర్ణాంకం fd)
{
	పూర్ణాంకం opt;
	socklen_t optlen;

	optlen = పరిమాణం opt;
	ఒకవేళ (getsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, &optlen) == -1) {
		debug("getsockopt TCP_NODELAY: %.100s", strerror(errno));
		తిరిగి;
	}
	ఒకవేళ (opt == 1) {
		debug2("fd %d is TCP_NODELAY", fd);
		తిరిగి;
	}
	opt = 1;
	debug2("fd %d setting TCP_NODELAY", fd);
	ఒకవేళ (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, పరిమాణం opt) == -1)
		error("setsockopt TCP_NODELAY: %.100s", strerror(errno));
}

/* Allow local port reuse in TIME_WAIT */
పూర్ణాంకం
సమితి_reuseaddr(పూర్ణాంకం fd)
{
	పూర్ణాంకం on = 1;

	ఒకవేళ (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, పరిమాణం(on)) == -1) {
		error("setsockopt SO_REUSEADDR fd %d: %s", fd, strerror(errno));
		తిరిగి -1;
	}
	తిరిగి 0;
}

/* Set TCP keepalives */
పూర్ణాంకం
సమితి_keepalive(పూర్ణాంకం fd)
{
	పూర్ణాంకం on = 1;

	ఒకవేళ (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, పరిమాణం(on)) == -1) {
		error("setsockopt SO_KEEPALIVE fd %d: %s", fd, strerror(errno));
		తిరిగి -1;
	}
	తిరిగి 0;
}

/* Get/set routing domain */
అక్షరం *
get_rdomain(పూర్ణాంకం fd)
{
#ఒకవేళ defined(HAVE_SYS_GET_RDOMAIN)
	తిరిగి sys_get_rdomain(fd);
#లేదావేళ defined(__OpenBSD__)
	పూర్ణాంకం rtable;
	అక్షరం *ret;
	socklen_t len = పరిమాణం(rtable);

	ఒకవేళ (getsockopt(fd, SOL_SOCKET, SO_RTABLE, &rtable, &len) == -1) {
		error("Failed to get routing domain for fd %d: %s",
		    fd, strerror(errno));
		తిరిగి ఖాళీ;
	}
	xasprintf(&ret, "%d", rtable);
	తిరిగి ret;
#లేకపోతే /* defined(__OpenBSD__) */
	తిరిగి ఖాళీ;
#అయితే_ముగింపు
}

పూర్ణాంకం
సమితి_rdomain(పూర్ణాంకం fd, స్థిరరాశి అక్షరం *name)
{
#ఒకవేళ defined(HAVE_SYS_సమితి_RDOMAIN)
	తిరిగి sys_సమితి_rdomain(fd, name);
#లేదావేళ defined(__OpenBSD__)
	పూర్ణాంకం rtable;
	స్థిరరాశి అక్షరం *errstr;

	ఒకవేళ (name == ఖాళీ)
		తిరిగి 0; /* default table */

	rtable = (పూర్ణాంకం)strtonum(name, 0, 255, &errstr);
	ఒకవేళ (errstr != ఖాళీ) {
		/* Shouldn't happen */
		error("Invalid routing domain \"%s\": %s", name, errstr);
		తిరిగి -1;
	}
	ఒకవేళ (setsockopt(fd, SOL_SOCKET, SO_RTABLE,
	    &rtable, పరిమాణం(rtable)) == -1) {
		error("Failed to set routing domain %d on fd %d: %s",
		    rtable, fd, strerror(errno));
		తిరిగి -1;
	}
	తిరిగి 0;
#లేకపోతే /* defined(__OpenBSD__) */
	error("Setting routing domain is not supported on this platform");
	తిరిగి -1;
#అయితే_ముగింపు
}

పూర్ణాంకం
get_sock_af(పూర్ణాంకం fd)
{
	నిర్మాణం sockaddr_storage గమ్యం;
	socklen_t tolen = పరిమాణం(గమ్యం);

	memset(&గమ్యం, 0, పరిమాణం(గమ్యం));
	ఒకవేళ (getsockname(fd, (నిర్మాణం sockaddr *)&గమ్యం, &tolen) == -1)
		తిరిగి -1;
#నిర్వచితమైతే IPV4_లోపల_IPV6
	ఒకవేళ (గమ్యం.ss_family == AF_INET6 &&
	    IN6_IS_ADDR_V4MAPPED(&((నిర్మాణం sockaddr_in6 *)&గమ్యం)->sin6_addr))
		తిరిగి AF_INET;
#అయితే_ముగింపు
	తిరిగి గమ్యం.ss_family;
}

శూన్య
సమితి_sock_tos(పూర్ణాంకం fd, పూర్ణాంకం tos)
{
#నిర్వచితం_కాకపోతే IP_TOS_IS_BROKEN
	పూర్ణాంకం af;

	ఒకవేళ (tos < 0 || tos == గరిష్ఠ_పూర్ణాంకం) {
		debug_f("invalid TOS %d", tos);
		తిరిగి;
	}
	ఎంపిక ((af = get_sock_af(fd))) {
	స్థితి -1:
		/* assume not a socket */
		ఆపు;
	స్థితి AF_INET:
# ifdef IP_TOS
		debug3_f("set socket %d IP_TOS 0x%02x", fd, tos);
		ఒకవేళ (setsockopt(fd, IPPROTO_IP, IP_TOS,
		    &tos, పరిమాణం(tos)) == -1) {
			error("setsockopt socket %d IP_TOS %d: %s",
			    fd, tos, strerror(errno));
		}
# endif /* IP_TOS */
		ఆపు;
	స్థితి AF_INET6:
# ifdef IPV6_TCLASS
		debug3_f("set socket %d IPV6_TCLASS 0x%02x", fd, tos);
		ఒకవేళ (setsockopt(fd, IPPROTO_IPV6, IPV6_TCLASS,
		    &tos, పరిమాణం(tos)) == -1) {
			error("setsockopt socket %d IPV6_TCLASS %d: %s",
			    fd, tos, strerror(errno));
		}
# endif /* IPV6_TCLASS */
		ఆపు;
	అప్రమేయ:
		debug2_f("unsupported socket family %d", af);
		ఆపు;
	}
#అయితే_ముగింపు /* IP_TOS_IS_BROKEN */
}

/*
 * Wait up to *timeoutp milliseconds for events on fd. Updates
 * *timeoutp with time remaining.
 * Returns 0 if fd ready or -1 on timeout or error (see errno).
 */
స్థిర పూర్ణాంకం
waitfd(పూర్ణాంకం fd, పూర్ణాంకం *timeoutp, పొట్టి events, అస్థిర sig_atomic_t *stop)
{
	నిర్మాణం pollfd pfd;
	నిర్మాణం timespec timeout;
	పూర్ణాంకం oerrno, r;
	sigset_t nsigset, osigset;

	ఒకవేళ (timeoutp && *timeoutp == -1)
		timeoutp = ఖాళీ;
	pfd.fd = fd;
	pfd.events = events;
	ptimeout_init(&timeout);
	ఒకవేళ (timeoutp != ఖాళీ)
		ptimeout_deadline_ms(&timeout, *timeoutp);
	ఒకవేళ (stop != ఖాళీ)
		sigfillset(&nsigset);
	కొరకు (; timeoutp == ఖాళీ || *timeoutp >= 0;) {
		ఒకవేళ (stop != ఖాళీ) {
			sigprocmask(SIG_BLOCK, &nsigset, &osigset);
			ఒకవేళ (*stop) {
				sigprocmask(SIG_SETMASK, &osigset, ఖాళీ);
				errno = EINTR;
				తిరిగి -1;
			}
		}
		r = ppoll(&pfd, 1, ptimeout_get_tsp(&timeout),
		    stop != ఖాళీ ? &osigset : ఖాళీ);
		oerrno = errno;
		ఒకవేళ (stop != ఖాళీ)
			sigprocmask(SIG_SETMASK, &osigset, ఖాళీ);
		ఒకవేళ (timeoutp)
			*timeoutp = ptimeout_get_ms(&timeout);
		errno = oerrno;
		ఒకవేళ (r > 0)
			తిరిగి 0;
		లేకపోతే ఒకవేళ (r == -1 && errno != EAGAIN && errno != EINTR)
			తిరిగి -1;
		లేకపోతే ఒకవేళ (r == 0)
			ఆపు;
	}
	/* timeout */
	errno = ETIMEDOUT;
	తిరిగి -1;
}

/*
 * Wait up to *timeoutp milliseconds for fd to be readable. Updates
 * *timeoutp with time remaining.
 * Returns 0 if fd ready or -1 on timeout or error (see errno).
 */
పూర్ణాంకం
waitrfd(పూర్ణాంకం fd, పూర్ణాంకం *timeoutp, అస్థిర sig_atomic_t *stop) {
	తిరిగి waitfd(fd, timeoutp, POLLIN, stop);
}

/*
 * Attempt a non-blocking connect(2) to the specified address, waiting up to
 * *timeoutp milliseconds for the connection to complete. If the timeout is
 * <=0, then wait indefinitely.
 *
 * Returns 0 on success or -1 on failure.
 */
పూర్ణాంకం
timeout_connect(పూర్ణాంకం sockfd, స్థిరరాశి నిర్మాణం sockaddr *serv_addr,
    socklen_t addrlen, పూర్ణాంకం *timeoutp)
{
	పూర్ణాంకం optval = 0;
	socklen_t optlen = పరిమాణం(optval);

	/* No timeout: just do a blocking connect() */
	ఒకవేళ (timeoutp == ఖాళీ || *timeoutp <= 0)
		తిరిగి connect(sockfd, serv_addr, addrlen);

	సమితి_nonblock(sockfd);
	కొరకు (;;) {
		ఒకవేళ (connect(sockfd, serv_addr, addrlen) == 0) {
			/* Succeeded already? */
			unset_nonblock(sockfd);
			తిరిగి 0;
		} లేకపోతే ఒకవేళ (errno == EINTR)
			కొనసాగు;
		లేకపోతే ఒకవేళ (errno != EINPROGRESS)
			తిరిగి -1;
		ఆపు;
	}

	ఒకవేళ (waitfd(sockfd, timeoutp, POLLIN | POLLOUT, ఖాళీ) == -1)
		తిరిగి -1;

	/* Completed or failed */
	ఒకవేళ (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &optval, &optlen) == -1) {
		debug("getsockopt: %s", strerror(errno));
		తిరిగి -1;
	}
	ఒకవేళ (optval != 0) {
		errno = optval;
		తిరిగి -1;
	}
	unset_nonblock(sockfd);
	తిరిగి 0;
}

/* Characters considered whitespace in strsep calls. */
#నిర్వచించు WHITESPACE " \t\r\n"
#నిర్వచించు QUOTE	"\""

/* return next token in configuration line */
స్థిర అక్షరం *
strdelim_అంతర్గత(అక్షరం **s, పూర్ణాంకం విభజించు_equals)
{
	అక్షరం *old;
	పూర్ణాంకం wspace = 0;

	ఒకవేళ (*s == ఖాళీ)
		తిరిగి ఖాళీ;

	old = *s;

	*s = strpbrk(*s,
	    విభజించు_equals ? WHITESPACE QUOTE "=" : WHITESPACE QUOTE);
	ఒకవేళ (*s == ఖాళీ)
		తిరిగి (old);

	ఒకవేళ (*s[0] == '\"') {
		memmove(*s, *s + 1, అక్షరశ్రేణి_పొడవు(*s)); /* move nul too */
		/* Find matching quote */
		ఒకవేళ ((*s = strpbrk(*s, QUOTE)) == ఖాళీ) {
			తిరిగి (ఖాళీ);		/* no matching quote */
		} లేకపోతే {
			*s[0] = '\0';
			*s += strspn(*s + 1, WHITESPACE) + 1;
			తిరిగి (old);
		}
	}

	/* Allow only one '=' to be skipped */
	ఒకవేళ (విభజించు_equals && *s[0] == '=')
		wspace = 1;
	*s[0] = '\0';

	/* Skip any extra whitespace after first token */
	*s += strspn(*s + 1, WHITESPACE) + 1;
	ఒకవేళ (విభజించు_equals && *s[0] == '=' && !wspace)
		*s += strspn(*s + 1, WHITESPACE) + 1;

	తిరిగి (old);
}

/*
 * Return next token in configuration line; splits on whitespace or a
 * single '=' character.
 */
అక్షరం *
strdelim(అక్షరం **s)
{
	తిరిగి strdelim_అంతర్గత(s, 1);
}

/*
 * Return next token in configuration line; splits on whitespace only.
 */
అక్షరం *
strdelimw(అక్షరం **s)
{
	తిరిగి strdelim_అంతర్గత(s, 0);
}

నిర్మాణం passwd *
pwcopy(నిర్మాణం passwd *pw)
{
	నిర్మాణం passwd *copy = xcalloc(1, పరిమాణం(*copy));

	copy->pw_name = xstrdup(pw->pw_name);
	copy->pw_passwd = xstrdup(pw->pw_passwd == ఖాళీ ? "*" : pw->pw_passwd);
#నిర్వచితమైతే HAVE_STRUCT_PASSWD_PW_GECOS
	copy->pw_gecos = xstrdup(pw->pw_gecos == ఖాళీ ? "" : pw->pw_gecos);
#అయితే_ముగింపు
	copy->pw_uid = pw->pw_uid;
	copy->pw_gid = pw->pw_gid;
#నిర్వచితమైతే HAVE_STRUCT_PASSWD_PW_EXPIRE
	copy->pw_expire = pw->pw_expire;
#అయితే_ముగింపు
#నిర్వచితమైతే HAVE_STRUCT_PASSWD_PW_CHANGE
	copy->pw_change = pw->pw_change;
#అయితే_ముగింపు
#నిర్వచితమైతే HAVE_STRUCT_PASSWD_PW_CLASS
	copy->pw_class = xstrdup(pw->pw_class == ఖాళీ ? "" : pw->pw_class);
#అయితే_ముగింపు
	copy->pw_dir = xstrdup(pw->pw_dir == ఖాళీ ? "" : pw->pw_dir);
	copy->pw_shell = xstrdup(pw->pw_shell == ఖాళీ ? "" : pw->pw_shell);
	తిరిగి copy;
}

శూన్య
pwfree(నిర్మాణం passwd *pw)
{
	ఒకవేళ (pw == ఖాళీ)
		తిరిగి;
	విడుదల(pw->pw_name);
	freezero(pw->pw_passwd,
	    pw->pw_passwd == ఖాళీ ? 0 : అక్షరశ్రేణి_పొడవు(pw->pw_passwd));
#నిర్వచితమైతే HAVE_STRUCT_PASSWD_PW_GECOS
	విడుదల(pw->pw_gecos);
#అయితే_ముగింపు
#నిర్వచితమైతే HAVE_STRUCT_PASSWD_PW_CLASS
	విడుదల(pw->pw_class);
#అయితే_ముగింపు
	విడుదల(pw->pw_dir);
	విడుదల(pw->pw_shell);
	freezero(pw, పరిమాణం(*pw));
}

/*
 * Convert ASCII string to TCP/IP port number.
 * Port must be >=0 and <=65535.
 * Return -1 if invalid.
 */
పూర్ణాంకం
a2port(స్థిరరాశి అక్షరం *s)
{
	నిర్మాణం servent *se;
	దీర్ఘ దీర్ఘ పోర్టు;
	స్థిరరాశి అక్షరం *errstr;

	పోర్టు = strtonum(s, 0, 65535, &errstr);
	ఒకవేళ (errstr == ఖాళీ)
		తిరిగి (పూర్ణాంకం)పోర్టు;
	ఒకవేళ ((se = getservbyname(s, "tcp")) != ఖాళీ)
		తిరిగి ntohs(se->s_port);
	తిరిగి -1;
}

పూర్ణాంకం
a2tun(స్థిరరాశి అక్షరం *s, పూర్ణాంకం *remote)
{
	స్థిరరాశి అక్షరం *errstr = ఖాళీ;
	అక్షరం *sp, *ep;
	పూర్ణాంకం tun;

	ఒకవేళ (remote != ఖాళీ) {
		*remote = SSH_TUNID_ANY;
		sp = xstrdup(s);
		ఒకవేళ ((ep = strchr(sp, ':')) == ఖాళీ) {
			విడుదల(sp);
			తిరిగి (a2tun(s, ఖాళీ));
		}
		ep[0] = '\0'; ep++;
		*remote = a2tun(ep, ఖాళీ);
		tun = a2tun(sp, ఖాళీ);
		విడుదల(sp);
		తిరిగి (*remote == SSH_TUNID_ERR ? *remote : tun);
	}

	ఒకవేళ (strcasecmp(s, "any") == 0)
		తిరిగి (SSH_TUNID_ANY);

	tun = strtonum(s, 0, SSH_TUNID_MAX, &errstr);
	ఒకవేళ (errstr != ఖాళీ)
		తిరిగి (SSH_TUNID_ERR);

	తిరిగి (tun);
}

#నిర్వచించు SECONDS		1.0
#నిర్వచించు MINUTES		(SECONDS * 60)
#నిర్వచించు HOURS		(MINUTES * 60)
#నిర్వచించు DAYS		(HOURS * 24)
#నిర్వచించు WEEKS		(DAYS * 7)

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
ద్విగుణ
convtime_double(స్థిరరాశి అక్షరం *s)
{
	ద్విగుణ val, మొత్తం_sec = 0.0, multiplier;
	స్థిరరాశి అక్షరం *p, *ప్రారంభం_p;
	అక్షరం *endp;
	పూర్ణాంకం చూసిన_seconds = 0;

	ఒకవేళ (s == ఖాళీ || *s == '\0')
		తిరిగి -1.0;

	కొరకు (p = s; *p != '\0';) {
		ఒకవేళ (!అంకెనా((గుర్తులేని అక్షరం)*p) && *p != '.')
			తిరిగి -1.0;

		errno = 0;
		ఒకవేళ ((val = strtod(p, &endp)) < 0 || errno != 0 || p == endp)
			తిరిగి -1.0;
		/* Allow only decimal forms */
		ఒకవేళ (p + strspn(p, "0123456789.") != endp)
			తిరిగి -1.0;
		ప్రారంభం_p = p;
		p = endp;

		ఎంపిక (*p) {
		స్థితి '\0':
			/* FALLTHROUGH */
		స్థితి 's':
		స్థితి 'S':
			ఒకవేళ (చూసిన_seconds++)
				తిరిగి -1.0;
			multiplier = SECONDS;
			ఆపు;
		స్థితి 'm':
		స్థితి 'M':
			multiplier = MINUTES;
			ఆపు;
		స్థితి 'h':
		స్థితి 'H':
			multiplier = HOURS;
			ఆపు;
		స్థితి 'd':
		స్థితి 'D':
			multiplier = DAYS;
			ఆపు;
		స్థితి 'w':
		స్థితి 'W':
			multiplier = WEEKS;
			ఆపు;
		అప్రమేయ:
			తిరిగి -1.0;
		}

		/* Special handling if this was a decimal */
		ఒకవేళ (memchr(ప్రారంభం_p, '.', endp - ప్రారంభం_p) != ఖాళీ) {
			/* Decimal point present */
			ఒకవేళ (multiplier > 1.0)
				తిరిగి -1.0; /* No fractionals for non-seconds */
			/* For seconds, ensure digits follow */
			ఒకవేళ (!అంకెనా((గుర్తులేని అక్షరం)*(endp - 1)))
				తిరిగి -1.0;
		}

		మొత్తం_sec += val * multiplier;

		ఒకవేళ (*p != '\0')
			p++;
	}
	తిరిగి మొత్తం_sec;
}

/*
 * Same as convtime_double() above but fractional seconds are ignored.
 * Return -1 if time string is invalid.
 */
పూర్ణాంకం
convtime(స్థిరరాశి అక్షరం *s)
{
	ద్విగుణ sec_val;

	ఒకవేళ ((sec_val = convtime_double(s)) < 0.0)
		తిరిగి -1;

	/* Check for overflow into int */
	ఒకవేళ (sec_val < 0 || sec_val > గరిష్ఠ_పూర్ణాంకం)
		తిరిగి -1;

	తిరిగి (పూర్ణాంకం)sec_val;
}

#నిర్వచించు TF_BUFS	8
#నిర్వచించు TF_LEN	9

స్థిరరాశి అక్షరం *
fmt_timeframe(time_t t)
{
	అక్షరం		*buf;
	స్థిర అక్షరం	 tfbuf[TF_BUFS][TF_LEN];	/* ring buffer */
	స్థిర పూర్ణాంకం	 idx = 0;
	గుర్తులేని పూర్ణాంకం	 sec, min, hrs, day;
	గుర్తులేని దీర్ఘ దీర్ఘ	week;

	buf = tfbuf[idx++];
	ఒకవేళ (idx == TF_BUFS)
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

	ఒకవేళ (week > 0)
		snprintf(buf, TF_LEN, "%02lluw%01ud%02uh", week, day, hrs);
	లేకపోతే ఒకవేళ (day > 0)
		snprintf(buf, TF_LEN, "%01ud%02uh%02um", day, hrs, min);
	లేకపోతే
		snprintf(buf, TF_LEN, "%02u:%02u:%02u", hrs, min, sec);

	తిరిగి (buf);
}

/*
 * Returns a standardized host+port identifier string.
 * Caller must free returned string.
 */
అక్షరం *
put_host_పోర్టు(స్థిరరాశి అక్షరం *host, u_short పోర్టు)
{
	అక్షరం *hoststr;

	ఒకవేళ (పోర్టు == 0 || పోర్టు == SSH_DEFAULT_పోర్టు)
		తిరిగి(xstrdup(host));
	ఒకవేళ (asprintf(&hoststr, "[%s]:%d", host, (పూర్ణాంకం)పోర్టు) == -1)
		fatal("put_host_port: asprintf: %s", strerror(errno));
	debug3("put_host_port: %s", hoststr);
	తిరిగి hoststr;
}

/*
 * Search for next delimiter between hostnames/addresses and ports.
 * Argument may be modified (for termination).
 * Returns *cp if parsing succeeds.
 * *cp is set to the start of the next field, if one was found.
 * The delimiter char, if present, is stored in delim.
 * If this is the last field, *cp is set to NULL.
 */
అక్షరం *
hpdelim2(అక్షరం **cp, అక్షరం *delim)
{
	అక్షరం *s, *old;

	ఒకవేళ (cp == ఖాళీ || *cp == ఖాళీ)
		తిరిగి ఖాళీ;

	old = s = *cp;
	ఒకవేళ (*s == '[') {
		ఒకవేళ ((s = strchr(s, ']')) == ఖాళీ)
			తిరిగి ఖాళీ;
		లేకపోతే
			s++;
	} లేకపోతే ఒకవేళ ((s = strpbrk(s, ":/")) == ఖాళీ)
		s = *cp + అక్షరశ్రేణి_పొడవు(*cp); /* skip to end (see first case below) */

	ఎంపిక (*s) {
	స్థితి '\0':
		*cp = ఖాళీ;	/* no more fields*/
		ఆపు;

	స్థితి ':':
	స్థితి '/':
		ఒకవేళ (delim != ఖాళీ)
			*delim = *s;
		*s = '\0';	/* terminate */
		*cp = s + 1;
		ఆపు;

	అప్రమేయ:
		తిరిగి ఖాళీ;
	}

	తిరిగి old;
}

/* The common case: only accept colon as delimiter. */
అక్షరం *
hpdelim(అక్షరం **cp)
{
	అక్షరం *r, delim = '\0';

	r =  hpdelim2(cp, &delim);
	ఒకవేళ (delim == '/')
		తిరిగి ఖాళీ;
	తిరిగి r;
}

అక్షరం *
cleanhostname(అక్షరం *host)
{
	ఒకవేళ (*host == '[' && host[అక్షరశ్రేణి_పొడవు(host) - 1] == ']') {
		host[అక్షరశ్రేణి_పొడవు(host) - 1] = '\0';
		తిరిగి (host + 1);
	} లేకపోతే
		తిరిగి host;
}

అక్షరం *
colon(అక్షరం *cp)
{
	పూర్ణాంకం flag = 0;

	ఒకవేళ (*cp == ':')		/* Leading colon is part of file name. */
		తిరిగి ఖాళీ;
	ఒకవేళ (*cp == '[')
		flag = 1;

	కొరకు (; *cp; ++cp) {
		ఒకవేళ (*cp == '@' && *(cp+1) == '[')
			flag = 1;
		ఒకవేళ (*cp == ']' && *(cp+1) == ':' && flag)
			తిరిగి (cp+1);
		ఒకవేళ (*cp == ':' && !flag)
			తిరిగి (cp);
		ఒకవేళ (*cp == '/')
			తిరిగి ఖాళీ;
	}
	తిరిగి ఖాళీ;
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
పూర్ణాంకం
parse_user_host_మార్గం(స్థిరరాశి అక్షరం *s, అక్షరం **userp, అక్షరం **hostp, అక్షరం **pathp)
{
	అక్షరం *user = ఖాళీ, *host = ఖాళీ, *మార్గం = ఖాళీ;
	అక్షరం *sdup, *tmp;
	పూర్ణాంకం ret = -1;

	ఒకవేళ (userp != ఖాళీ)
		*userp = ఖాళీ;
	ఒకవేళ (hostp != ఖాళీ)
		*hostp = ఖాళీ;
	ఒకవేళ (pathp != ఖాళీ)
		*pathp = ఖాళీ;

	sdup = xstrdup(s);

	/* Check for remote syntax: [user@]host:[path] */
	ఒకవేళ ((tmp = colon(sdup)) == ఖాళీ)
		వెళ్ళు బహిర్గతం;

	/* Extract optional path */
	*tmp++ = '\0';
	ఒకవేళ (*tmp == '\0')
		tmp = ".";
	మార్గం = xstrdup(tmp);

	/* Extract optional user and mandatory host */
	tmp = strrchr(sdup, '@');
	ఒకవేళ (tmp != ఖాళీ) {
		*tmp++ = '\0';
		host = xstrdup(cleanhostname(tmp));
		ఒకవేళ (*sdup != '\0')
			user = xstrdup(sdup);
	} లేకపోతే {
		host = xstrdup(cleanhostname(sdup));
		user = ఖాళీ;
	}

	/* Success */
	ఒకవేళ (userp != ఖాళీ) {
		*userp = user;
		user = ఖాళీ;
	}
	ఒకవేళ (hostp != ఖాళీ) {
		*hostp = host;
		host = ఖాళీ;
	}
	ఒకవేళ (pathp != ఖాళీ) {
		*pathp = మార్గం;
		మార్గం = ఖాళీ;
	}
	ret = 0;
బహిర్గతం:
	విడుదల(sdup);
	విడుదల(user);
	విడుదల(host);
	విడుదల(మార్గం);
	తిరిగి ret;
}

/*
 * Parse a [user@]host[:port] string.
 * Caller must free returned user and host.
 * Any of the pointer return arguments may be NULL (useful for syntax checking).
 * If user was not specified then *userp will be set to NULL.
 * If port was not specified then *portp will be -1.
 * Returns 0 on success, -1 on failure.
 */
పూర్ణాంకం
parse_user_host_పోర్టు(స్థిరరాశి అక్షరం *s, అక్షరం **userp, అక్షరం **hostp, పూర్ణాంకం *portp)
{
	అక్షరం *sdup, *cp, *tmp;
	అక్షరం *user = ఖాళీ, *host = ఖాళీ;
	పూర్ణాంకం పోర్టు = -1, ret = -1;

	ఒకవేళ (userp != ఖాళీ)
		*userp = ఖాళీ;
	ఒకవేళ (hostp != ఖాళీ)
		*hostp = ఖాళీ;
	ఒకవేళ (portp != ఖాళీ)
		*portp = -1;

	ఒకవేళ ((sdup = tmp = strdup(s)) == ఖాళీ)
		తిరిగి -1;
	/* Extract optional username */
	ఒకవేళ ((cp = strrchr(tmp, '@')) != ఖాళీ) {
		*cp = '\0';
		ఒకవేళ (*tmp == '\0')
			వెళ్ళు బహిర్గతం;
		ఒకవేళ ((user = strdup(tmp)) == ఖాళీ)
			వెళ్ళు బహిర్గతం;
		tmp = cp + 1;
	}
	/* Extract mandatory hostname */
	ఒకవేళ ((cp = hpdelim(&tmp)) == ఖాళీ || *cp == '\0')
		వెళ్ళు బహిర్గతం;
	host = xstrdup(cleanhostname(cp));
	/* Convert and verify optional port */
	ఒకవేళ (tmp != ఖాళీ && *tmp != '\0') {
		ఒకవేళ ((పోర్టు = a2port(tmp)) <= 0)
			వెళ్ళు బహిర్గతం;
	}
	/* Success */
	ఒకవేళ (userp != ఖాళీ) {
		*userp = user;
		user = ఖాళీ;
	}
	ఒకవేళ (hostp != ఖాళీ) {
		*hostp = host;
		host = ఖాళీ;
	}
	ఒకవేళ (portp != ఖాళీ)
		*portp = పోర్టు;
	ret = 0;
 బహిర్గతం:
	విడుదల(sdup);
	విడుదల(user);
	విడుదల(host);
	తిరిగి ret;
}

/*
 * Converts a two-byte hex string to decimal.
 * Returns the decimal value or -1 for invalid input.
 */
స్థిర పూర్ణాంకం
hexchar(స్థిరరాశి అక్షరం *s)
{
	గుర్తులేని అక్షరం ఫలితం[2];
	పూర్ణాంకం i;

	కొరకు (i = 0; i < 2; i++) {
		ఒకవేళ (s[i] >= '0' && s[i] <= '9')
			ఫలితం[i] = (గుర్తులేని అక్షరం)(s[i] - '0');
		లేకపోతే ఒకవేళ (s[i] >= 'a' && s[i] <= 'f')
			ఫలితం[i] = (గుర్తులేని అక్షరం)(s[i] - 'a') + 10;
		లేకపోతే ఒకవేళ (s[i] >= 'A' && s[i] <= 'F')
			ఫలితం[i] = (గుర్తులేని అక్షరం)(s[i] - 'A') + 10;
		లేకపోతే
			తిరిగి -1;
	}
	తిరిగి (ఫలితం[0] << 4) | ఫలితం[1];
}

/*
 * Decode an url-encoded string.
 * Returns a newly allocated string on success or NULL on failure.
 */
స్థిర అక్షరం *
urldecode(స్థిరరాశి అక్షరం *src)
{
	అక్షరం *ret, *dst;
	పూర్ణాంకం ch;
	కొలత_t srclen;

	ఒకవేళ ((srclen = అక్షరశ్రేణి_పొడవు(src)) >= SIZE_MAX)
		తిరిగి ఖాళీ;
	ret = xmalloc(srclen + 1);
	కొరకు (dst = ret; *src != '\0'; src++) {
		ఎంపిక (*src) {
		స్థితి '+':
			*dst++ = ' ';
			ఆపు;
		స్థితి '%':
			/* note: don't allow \0 characters */
			ఒకవేళ (!isxdigit((గుర్తులేని అక్షరం)src[1]) ||
			    !isxdigit((గుర్తులేని అక్షరం)src[2]) ||
			    (ch = hexchar(src + 1)) == -1 || ch == 0) {
				విడుదల(ret);
				తిరిగి ఖాళీ;
			}
			*dst++ = ch;
			src += 2;
			ఆపు;
		అప్రమేయ:
			*dst++ = *src;
			ఆపు;
		}
	}
	*dst = '\0';

	తిరిగి ret;
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
పూర్ణాంకం
parse_uri(స్థిరరాశి అక్షరం *scheme, స్థిరరాశి అక్షరం *uri, అక్షరం **userp, అక్షరం **hostp,
    పూర్ణాంకం *portp, అక్షరం **pathp)
{
	అక్షరం *uridup, *cp, *tmp, ch;
	అక్షరం *user = ఖాళీ, *host = ఖాళీ, *మార్గం = ఖాళీ;
	పూర్ణాంకం పోర్టు = -1, ret = -1;
	కొలత_t len;

	len = అక్షరశ్రేణి_పొడవు(scheme);
	ఒకవేళ (అక్షరశ్రేణి_పోలిక(uri, scheme, len) != 0 || అక్షరశ్రేణి_పోలిక(uri + len, "://", 3) != 0)
		తిరిగి 1;
	uri += len + 3;

	ఒకవేళ (userp != ఖాళీ)
		*userp = ఖాళీ;
	ఒకవేళ (hostp != ఖాళీ)
		*hostp = ఖాళీ;
	ఒకవేళ (portp != ఖాళీ)
		*portp = -1;
	ఒకవేళ (pathp != ఖాళీ)
		*pathp = ఖాళీ;

	uridup = tmp = xstrdup(uri);

	/* Extract optional ssh-info (username + connection params) */
	ఒకవేళ ((cp = strchr(tmp, '@')) != ఖాళీ) {
		అక్షరం *delim;

		*cp = '\0';
		/* Extract username and connection params */
		ఒకవేళ ((delim = strchr(tmp, ';')) != ఖాళీ) {
			/* Just ignore connection params for now */
			*delim = '\0';
		}
		ఒకవేళ (*tmp == '\0') {
			/* Empty username */
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ ((user = urldecode(tmp)) == ఖాళీ)
			వెళ్ళు బహిర్గతం;
		tmp = cp + 1;
	}

	/* Extract mandatory hostname */
	ఒకవేళ ((cp = hpdelim2(&tmp, &ch)) == ఖాళీ || *cp == '\0')
		వెళ్ళు బహిర్గతం;
	host = xstrdup(cleanhostname(cp));
	ఒకవేళ (!valid_domain(host, 0, ఖాళీ))
		వెళ్ళు బహిర్గతం;

	ఒకవేళ (tmp != ఖాళీ && *tmp != '\0') {
		ఒకవేళ (ch == ':') {
			/* Convert and verify port. */
			ఒకవేళ ((cp = strchr(tmp, '/')) != ఖాళీ)
				*cp = '\0';
			ఒకవేళ ((పోర్టు = a2port(tmp)) <= 0)
				వెళ్ళు బహిర్గతం;
			tmp = cp ? cp + 1 : ఖాళీ;
		}
		ఒకవేళ (tmp != ఖాళీ && *tmp != '\0') {
			/* Extract optional path */
			ఒకవేళ ((మార్గం = urldecode(tmp)) == ఖాళీ)
				వెళ్ళు బహిర్గతం;
		}
	}

	/* Success */
	ఒకవేళ (userp != ఖాళీ) {
		*userp = user;
		user = ఖాళీ;
	}
	ఒకవేళ (hostp != ఖాళీ) {
		*hostp = host;
		host = ఖాళీ;
	}
	ఒకవేళ (portp != ఖాళీ)
		*portp = పోర్టు;
	ఒకవేళ (pathp != ఖాళీ) {
		*pathp = మార్గం;
		మార్గం = ఖాళీ;
	}
	ret = 0;
 బహిర్గతం:
	విడుదల(uridup);
	విడుదల(user);
	విడుదల(host);
	విడుదల(మార్గం);
	తిరిగి ret;
}

/* function to assist building execv() arguments */
శూన్య
addargs(arglist *వాదనలు, అక్షరం *fmt, ...)
{
	va_list ap;
	అక్షరం *cp;
	u_int nalloc;
	పూర్ణాంకం r;

	va_start(ap, fmt);
	r = vasprintf(&cp, fmt, ap);
	va_end(ap);
	ఒకవేళ (r == -1)
		fatal_f("argument too long");

	nalloc = వాదనలు->nalloc;
	ఒకవేళ (వాదనలు->list == ఖాళీ) {
		nalloc = 32;
		వాదనలు->అంకె = 0;
	} లేకపోతే ఒకవేళ (వాదనలు->అంకె > (256 * 1024))
		fatal_f("too many arguments");
	లేకపోతే ఒకవేళ (వాదనలు->అంకె >= వాదనలు->nalloc)
		fatal_f("arglist corrupt");
	లేకపోతే ఒకవేళ (వాదనలు->అంకె+2 >= nalloc)
		nalloc *= 2;

	వాదనలు->list = xrecallocarray(వాదనలు->list, వాదనలు->nalloc,
	    nalloc, పరిమాణం(అక్షరం *));
	వాదనలు->nalloc = nalloc;
	వాదనలు->list[వాదనలు->అంకె++] = cp;
	వాదనలు->list[వాదనలు->అంకె] = ఖాళీ;
}

శూన్య
replacearg(arglist *వాదనలు, u_int which, అక్షరం *fmt, ...)
{
	va_list ap;
	అక్షరం *cp;
	పూర్ణాంకం r;

	va_start(ap, fmt);
	r = vasprintf(&cp, fmt, ap);
	va_end(ap);
	ఒకవేళ (r == -1)
		fatal_f("argument too long");
	ఒకవేళ (వాదనలు->list == ఖాళీ || వాదనలు->అంకె >= వాదనలు->nalloc)
		fatal_f("arglist corrupt");

	ఒకవేళ (which >= వాదనలు->అంకె)
		fatal_f("tried to replace invalid arg %d >= %d",
		    which, వాదనలు->అంకె);
	విడుదల(వాదనలు->list[which]);
	వాదనలు->list[which] = cp;
}

శూన్య
freeargs(arglist *వాదనలు)
{
	u_int i;

	ఒకవేళ (వాదనలు == ఖాళీ)
		తిరిగి;
	ఒకవేళ (వాదనలు->list != ఖాళీ && వాదనలు->అంకె < వాదనలు->nalloc) {
		కొరకు (i = 0; i < వాదనలు->అంకె; i++)
			విడుదల(వాదనలు->list[i]);
		విడుదల(వాదనలు->list);
	}
	వాదనలు->nalloc = వాదనలు->అంకె = 0;
	వాదనలు->list = ఖాళీ;
}

/*
 * Expands tildes in the file name.  Returns data allocated by xmalloc.
 * Warning: this calls getpw*.
 */
పూర్ణాంకం
tilde_expand(స్థిరరాశి అక్షరం *filename, uid_t uid, అక్షరం **retp)
{
	అక్షరం *ocopy = ఖాళీ, *copy, *s = ఖాళీ;
	స్థిరరాశి అక్షరం *మార్గం = ఖాళీ, *user = ఖాళీ;
	నిర్మాణం passwd *pw;
	కొలత_t len;
	పూర్ణాంకం ret = -1, r, slash;

	*retp = ఖాళీ;
	ఒకవేళ (*filename != '~') {
		*retp = xstrdup(filename);
		తిరిగి 0;
	}
	ocopy = copy = xstrdup(filename + 1);

	ఒకవేళ (*copy == '\0')				/* ~ */
		మార్గం = ఖాళీ;
	లేకపోతే ఒకవేళ (*copy == '/') {
		copy += strspn(copy, "/");
		ఒకవేళ (*copy == '\0')
			మార్గం = ఖాళీ;			/* ~/ */
		లేకపోతే
			మార్గం = copy;			/* ~/path */
	} లేకపోతే {
		user = copy;
		ఒకవేళ ((మార్గం = strchr(copy, '/')) != ఖాళీ) {
			copy[మార్గం - copy] = '\0';
			మార్గం++;
			మార్గం += strspn(మార్గం, "/");
			ఒకవేళ (*మార్గం == '\0')		/* ~user/ */
				మార్గం = ఖాళీ;
			/* else				 ~user/path */
		}
		/* else					~user */
	}
	ఒకవేళ (user != ఖాళీ) {
		ఒకవేళ ((pw = getpwnam(user)) == ఖాళీ) {
			error_f("No such user %s", user);
			వెళ్ళు బహిర్గతం;
		}
	} లేకపోతే ఒకవేళ ((pw = getpwuid(uid)) == ఖాళీ) {
		error_f("No such uid %ld", (దీర్ఘ)uid);
		వెళ్ళు బహిర్గతం;
	}

	/* Make sure directory has a trailing '/' */
	slash = (len = అక్షరశ్రేణి_పొడవు(pw->pw_dir)) == 0 || pw->pw_dir[len - 1] != '/';

	ఒకవేళ ((r = xasprintf(&s, "%s%s%s", pw->pw_dir,
	    slash ? "/" : "", మార్గం != ఖాళీ ? మార్గం : "")) <= 0) {
		error_f("xasprintf failed");
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (r >= PATH_MAX) {
		error_f("Path too long");
		వెళ్ళు బహిర్గతం;
	}
	/* success */
	ret = 0;
	*retp = s;
	s = ఖాళీ;
 బహిర్గతం:
	విడుదల(s);
	విడుదల(ocopy);
	తిరిగి ret;
}

అక్షరం *
tilde_expand_filename(స్థిరరాశి అక్షరం *filename, uid_t uid)
{
	అక్షరం *ret;

	ఒకవేళ (tilde_expand(filename, uid, &ret) != 0)
		cleanup_exit(255);
	తిరిగి ret;
}

/*
 * Expand a string with a set of %[char] escapes and/or ${ENVIRONMENT}
 * substitutions.  A number of escapes may be specified as
 * (char *escape_chars, char *replacement) pairs. The list must be terminated
 * by a NULL escape_char. Returns replaced string in memory allocated by
 * xmalloc which the caller must free.
 */
స్థిర అక్షరం *
vdollar_percent_expand(పూర్ణాంకం *parseerror, పూర్ణాంకం dollar, పూర్ణాంకం percent,
    స్థిరరాశి అక్షరం *string, va_list ap)
{
#నిర్వచించు EXPAND_MAX_కీలకాలు	64
	u_int అంకె_కీలకాలు = 0, i;
	నిర్మాణం {
		స్థిరరాశి అక్షరం *కీలకం;
		స్థిరరాశి అక్షరం *repl;
	} కీలకాలు[EXPAND_MAX_కీలకాలు];
	నిర్మాణం sshbuf *buf;
	పూర్ణాంకం r, missingvar = 0;
	అక్షరం *ret = ఖాళీ, *var, *varend, *val;
	కొలత_t len;

	ఒకవేళ ((buf = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	ఒకవేళ (parseerror == ఖాళీ)
		fatal_f("null parseerror arg");
	*parseerror = 1;

	/* Gather keys if we're doing percent expansion. */
	ఒకవేళ (percent) {
		కొరకు (అంకె_కీలకాలు = 0; అంకె_కీలకాలు < EXPAND_MAX_కీలకాలు; అంకె_కీలకాలు++) {
			కీలకాలు[అంకె_కీలకాలు].కీలకం = va_arg(ap, అక్షరం *);
			ఒకవేళ (కీలకాలు[అంకె_కీలకాలు].కీలకం == ఖాళీ)
				ఆపు;
			కీలకాలు[అంకె_కీలకాలు].repl = va_arg(ap, అక్షరం *);
			ఒకవేళ (కీలకాలు[అంకె_కీలకాలు].repl == ఖాళీ) {
				fatal_f("NULL replacement for token %s",
				    కీలకాలు[అంకె_కీలకాలు].కీలకం);
			}
		}
		ఒకవేళ (అంకె_కీలకాలు == EXPAND_MAX_కీలకాలు && va_arg(ap, అక్షరం *) != ఖాళీ)
			fatal_f("too many keys");
		ఒకవేళ (అంకె_కీలకాలు == 0)
			fatal_f("percent expansion without token list");
	}

	/* Expand string */
	కొరకు (i = 0; *string != '\0'; string++) {
		/* Optionally process ${ENVIRONMENT} expansions. */
		ఒకవేళ (dollar && string[0] == '$' && string[1] == '{') {
			string += 2;  /* skip over '${' */
			ఒకవేళ ((varend = strchr(string, '}')) == ఖాళీ) {
				error_f("environment variable '%s' missing "
				    "closing '}'", string);
				వెళ్ళు బహిర్గతం;
			}
			len = varend - string;
			ఒకవేళ (len == 0) {
				error_f("zero-length environment variable");
				వెళ్ళు బహిర్గతం;
			}
			var = xmalloc(len + 1);
			(శూన్య)strlcpy(var, string, len + 1);
			ఒకవేళ ((val = getenv(var)) == ఖాళీ) {
				error_f("env var ${%s} has no value", var);
				missingvar = 1;
			} లేకపోతే {
				debug3_f("expand ${%s} -> '%s'", var, val);
				ఒకవేళ ((r = sshbuf_put(buf, val, అక్షరశ్రేణి_పొడవు(val))) !=0)
					fatal_fr(r, "sshbuf_put ${}");
			}
			విడుదల(var);
			string += len;
			కొనసాగు;
		}

		/*
		 * Process percent expansions if we have a list of TOKENs.
		 * If we're not doing percent expansion everything just gets
		 * appended here.
		 */
		ఒకవేళ (*string != '%' || !percent) {
 append:
			ఒకవేళ ((r = sshbuf_put_u8(buf, *string)) != 0)
				fatal_fr(r, "sshbuf_put_u8 %%");
			కొనసాగు;
		}
		string++;
		/* %% case */
		ఒకవేళ (*string == '%')
			వెళ్ళు append;
		ఒకవేళ (*string == '\0') {
			error_f("invalid format");
			వెళ్ళు బహిర్గతం;
		}
		కొరకు (i = 0; i < అంకె_కీలకాలు; i++) {
			ఒకవేళ (strchr(కీలకాలు[i].కీలకం, *string) != ఖాళీ) {
				ఒకవేళ ((r = sshbuf_put(buf, కీలకాలు[i].repl,
				    అక్షరశ్రేణి_పొడవు(కీలకాలు[i].repl))) != 0)
					fatal_fr(r, "sshbuf_put %%-repl");
				ఆపు;
			}
		}
		ఒకవేళ (i >= అంకె_కీలకాలు) {
			error_f("unknown key %%%c", *string);
			వెళ్ళు బహిర్గతం;
		}
	}
	ఒకవేళ (!missingvar && (ret = sshbuf_dup_string(buf)) == ఖాళీ)
		fatal_f("sshbuf_dup_string failed");
	*parseerror = 0;
 బహిర్గతం:
	sshbuf_free(buf);
	తిరిగి *parseerror ? ఖాళీ : ret;
#నిర్వచనం_రద్దు EXPAND_MAX_కీలకాలు
}

/*
 * Expand only environment variables.
 * Note that although this function is variadic like the other similar
 * functions, any such arguments will be unused.
 */

అక్షరం *
dollar_expand(పూర్ణాంకం *parseerr, స్థిరరాశి అక్షరం *string, ...)
{
	అక్షరం *ret;
	పూర్ణాంకం err;
	va_list ap;

	va_start(ap, string);
	ret = vdollar_percent_expand(&err, 1, 0, string, ap);
	va_end(ap);
	ఒకవేళ (parseerr != ఖాళీ)
		*parseerr = err;
	తిరిగి ret;
}

/*
 * Returns expanded string or NULL if a specified environment variable is
 * not defined, or calls fatal if the string is invalid.
 */
అక్షరం *
percent_expand(స్థిరరాశి అక్షరం *string, ...)
{
	అక్షరం *ret;
	పూర్ణాంకం err;
	va_list ap;

	va_start(ap, string);
	ret = vdollar_percent_expand(&err, 0, 1, string, ap);
	va_end(ap);
	ఒకవేళ (err)
		fatal_f("failed");
	తిరిగి ret;
}

/*
 * Returns expanded string or NULL if a specified environment variable is
 * not defined, or calls fatal if the string is invalid.
 */
అక్షరం *
percent_dollar_expand(స్థిరరాశి అక్షరం *string, ...)
{
	అక్షరం *ret;
	పూర్ణాంకం err;
	va_list ap;

	va_start(ap, string);
	ret = vdollar_percent_expand(&err, 1, 1, string, ap);
	va_end(ap);
	ఒకవేళ (err)
		fatal_f("failed");
	తిరిగి ret;
}

పూర్ణాంకం
tun_open(పూర్ణాంకం tun, పూర్ణాంకం బహుళకం, అక్షరం **ifname)
{
#ఒకవేళ defined(CUSTOM_SYS_TUN_OPEN)
	తిరిగి (sys_tun_open(tun, బహుళకం, ifname));
#లేదావేళ defined(SSH_TUN_OPENBSD)
	నిర్మాణం ifreq ifr;
	అక్షరం name[100];
	పూర్ణాంకం fd = -1, sock;
	స్థిరరాశి అక్షరం *tunbase = "tun";

	ఒకవేళ (ifname != ఖాళీ)
		*ifname = ఖాళీ;

	ఒకవేళ (బహుళకం == SSH_TUNMODE_ETHERNET)
		tunbase = "tap";

	/* Open the tunnel device */
	ఒకవేళ (tun <= SSH_TUNID_MAX) {
		snprintf(name, పరిమాణం(name), "/dev/%s%d", tunbase, tun);
		fd = open(name, O_RDWR);
	} లేకపోతే ఒకవేళ (tun == SSH_TUNID_ANY) {
		కొరకు (tun = 100; tun >= 0; tun--) {
			snprintf(name, పరిమాణం(name), "/dev/%s%d",
			    tunbase, tun);
			ఒకవేళ ((fd = open(name, O_RDWR)) >= 0)
				ఆపు;
		}
	} లేకపోతే {
		debug_f("invalid tunnel %u", tun);
		తిరిగి -1;
	}

	ఒకవేళ (fd == -1) {
		debug_f("%s open: %s", name, strerror(errno));
		తిరిగి -1;
	}

	debug_f("%s mode %d fd %d", name, బహుళకం, fd);

	/* Bring interface up if it is not already */
	snprintf(ifr.ifr_name, పరిమాణం(ifr.ifr_name), "%s%d", tunbase, tun);
	ఒకవేళ ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
		వెళ్ళు failed;

	ఒకవేళ (ioctl(sock, SIOCGIFFLAGS, &ifr) == -1) {
		debug_f("get interface %s flags: %s", ifr.ifr_name,
		    strerror(errno));
		వెళ్ళు failed;
	}

	ఒకవేళ (!(ifr.ifr_flags & IFF_UP)) {
		ifr.ifr_flags |= IFF_UP;
		ఒకవేళ (ioctl(sock, SIOCSIFFLAGS, &ifr) == -1) {
			debug_f("activate interface %s: %s", ifr.ifr_name,
			    strerror(errno));
			వెళ్ళు failed;
		}
	}

	ఒకవేళ (ifname != ఖాళీ)
		*ifname = xstrdup(ifr.ifr_name);

	close(sock);
	తిరిగి fd;

 failed:
	ఒకవేళ (fd >= 0)
		close(fd);
	ఒకవేళ (sock >= 0)
		close(sock);
	తిరిగి -1;
#లేకపోతే
	error("Tunnel interfaces are not supported on this platform");
	తిరిగి (-1);
#అయితే_ముగింపు
}

శూన్య
sanitise_stdfd(శూన్య)
{
	పూర్ణాంకం nullfd, dupfd;

	ఒకవేళ ((nullfd = dupfd = open(_PATH_DEVNULL, O_RDWR)) == -1) {
		fprintf(stderr, "Couldn't open /dev/null: %s\n",
		    strerror(errno));
		నిష్క్రమించు(1);
	}
	అయితే (++dupfd <= STDERR_FILENO) {
		/* Only populate closed fds. */
		ఒకవేళ (fcntl(dupfd, F_GETFL) == -1 && errno == EBADF) {
			ఒకవేళ (dup2(nullfd, dupfd) == -1) {
				fprintf(stderr, "dup2: %s\n", strerror(errno));
				నిష్క్రమించు(1);
			}
		}
	}
	ఒకవేళ (nullfd > STDERR_FILENO)
		close(nullfd);
}

అక్షరం *
tohex(స్థిరరాశి శూన్య *vp, కొలత_t l)
{
	స్థిరరాశి u_char *p = (స్థిరరాశి u_char *)vp;
	అక్షరం b[3], *r;
	కొలత_t i, hl;

	ఒకవేళ (l > 65536)
		తిరిగి xstrdup("tohex: length > 65536");

	hl = l * 2 + 1;
	r = xcalloc(1, hl);
	కొరకు (i = 0; i < l; i++) {
		snprintf(b, పరిమాణం(b), "%02x", p[i]);
		strlcat(r, b, hl);
	}
	తిరిగి (r);
}

/*
 * Extend string *sp by the specified format. If *sp is not NULL (or empty),
 * then the separator 'sep' will be prepended before the formatted arguments.
 * Extended strings are heap allocated.
 */
శూన్య
xextendf(అక్షరం **sp, స్థిరరాశి అక్షరం *sep, స్థిరరాశి అక్షరం *fmt, ...)
{
	va_list ap;
	అక్షరం *tmp1, *tmp2;

	va_start(ap, fmt);
	xvasprintf(&tmp1, fmt, ap);
	va_end(ap);

	ఒకవేళ (*sp == ఖాళీ || **sp == '\0') {
		విడుదల(*sp);
		*sp = tmp1;
		తిరిగి;
	}
	xasprintf(&tmp2, "%s%s%s", *sp, sep == ఖాళీ ? "" : sep, tmp1);
	విడుదల(tmp1);
	విడుదల(*sp);
	*sp = tmp2;
}


uint64_t
get_u64(స్థిరరాశి శూన్య *vp)
{
	స్థిరరాశి u_char *p = (స్థిరరాశి u_char *)vp;
	uint64_t v;

	v  = (uint64_t)p[0] << 56;
	v |= (uint64_t)p[1] << 48;
	v |= (uint64_t)p[2] << 40;
	v |= (uint64_t)p[3] << 32;
	v |= (uint64_t)p[4] << 24;
	v |= (uint64_t)p[5] << 16;
	v |= (uint64_t)p[6] << 8;
	v |= (uint64_t)p[7];

	తిరిగి (v);
}

uint32_t
get_u32(స్థిరరాశి శూన్య *vp)
{
	స్థిరరాశి u_char *p = (స్థిరరాశి u_char *)vp;
	uint32_t v;

	v  = (uint32_t)p[0] << 24;
	v |= (uint32_t)p[1] << 16;
	v |= (uint32_t)p[2] << 8;
	v |= (uint32_t)p[3];

	తిరిగి (v);
}

uint32_t
get_u32_le(స్థిరరాశి శూన్య *vp)
{
	స్థిరరాశి u_char *p = (స్థిరరాశి u_char *)vp;
	uint32_t v;

	v  = (uint32_t)p[0];
	v |= (uint32_t)p[1] << 8;
	v |= (uint32_t)p[2] << 16;
	v |= (uint32_t)p[3] << 24;

	తిరిగి (v);
}

uint16_t
get_u16(స్థిరరాశి శూన్య *vp)
{
	స్థిరరాశి u_char *p = (స్థిరరాశి u_char *)vp;
	uint16_t v;

	v  = (uint16_t)p[0] << 8;
	v |= (uint16_t)p[1];

	తిరిగి (v);
}

శూన్య
put_u64(శూన్య *vp, uint64_t v)
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

శూన్య
put_u32(శూన్య *vp, uint32_t v)
{
	u_char *p = (u_char *)vp;

	p[0] = (u_char)(v >> 24) & 0xff;
	p[1] = (u_char)(v >> 16) & 0xff;
	p[2] = (u_char)(v >> 8) & 0xff;
	p[3] = (u_char)v & 0xff;
}

శూన్య
put_u32_le(శూన్య *vp, uint32_t v)
{
	u_char *p = (u_char *)vp;

	p[0] = (u_char)v & 0xff;
	p[1] = (u_char)(v >> 8) & 0xff;
	p[2] = (u_char)(v >> 16) & 0xff;
	p[3] = (u_char)(v >> 24) & 0xff;
}

శూన్య
put_u16(శూన్య *vp, uint16_t v)
{
	u_char *p = (u_char *)vp;

	p[0] = (u_char)(v >> 8) & 0xff;
	p[1] = (u_char)v & 0xff;
}

శూన్య
ms_వ్యవకలనం_diff(నిర్మాణం timeval *ప్రారంభం, పూర్ణాంకం *ms)
{
	నిర్మాణం timeval diff, ముగింపు;

	monotime_tv(&ముగింపు);
	timersub(&ముగింపు, ప్రారంభం, &diff);
	*ms -= (diff.tv_sec * 1000) + (diff.tv_usec / 1000);
}

శూన్య
ms_గమ్యం_timespec(నిర్మాణం timespec *ts, పూర్ణాంకం ms)
{
	ఒకవేళ (ms < 0)
		ms = 0;
	ts->tv_sec = ms / 1000;
	ts->tv_nsec = (ms % 1000) * 1000 * 1000;
}

శూన్య
monotime_ts(నిర్మాణం timespec *ts)
{
	నిర్మాణం timeval tv;
#ఒకవేళ defined(HAVE_CLOCK_GETTIME) && (defined(CLOCK_BOOTTIME) || \
    defined(CLOCK_MONOTONIC) || defined(CLOCK_REALTIME))
	స్థిర పూర్ణాంకం gettime_failed = 0;

	ఒకవేళ (!gettime_failed) {
# ifdef CLOCK_BOOTTIME
		ఒకవేళ (clock_gettime(CLOCK_BOOTTIME, ts) == 0)
			తిరిగి;
# endif /* CLOCK_BOOTTIME */
# ifdef CLOCK_MONOTONIC
		ఒకవేళ (clock_gettime(CLOCK_MONOTONIC, ts) == 0)
			తిరిగి;
# endif /* CLOCK_MONOTONIC */
# ifdef CLOCK_REALTIME
		/* Not monotonic, but we're almost out of options here. */
		ఒకవేళ (clock_gettime(CLOCK_REALTIME, ts) == 0)
			తిరిగి;
# endif /* CLOCK_REALTIME */
		debug3("clock_gettime: %s", strerror(errno));
		gettime_failed = 1;
	}
#అయితే_ముగింపు /* HAVE_CLOCK_GETTIME && (BOOTTIME || MONOTONIC || REALTIME) */
	gettimeofday(&tv, ఖాళీ);
	ts->tv_sec = tv.tv_sec;
	ts->tv_nsec = (దీర్ఘ)tv.tv_usec * 1000;
}

శూన్య
monotime_tv(నిర్మాణం timeval *tv)
{
	నిర్మాణం timespec ts;

	monotime_ts(&ts);
	tv->tv_sec = ts.tv_sec;
	tv->tv_usec = ts.tv_nsec / 1000;
}

time_t
monotime(శూన్య)
{
	నిర్మాణం timespec ts;

	monotime_ts(&ts);
	తిరిగి (ts.tv_sec);
}

ద్విగుణ
monotime_double(శూన్య)
{
	నిర్మాణం timespec ts;

	monotime_ts(&ts);
	తిరిగి (ద్విగుణ)ts.tv_sec + (ద్విగుణ)ts.tv_nsec / 1000000000.0;
}

శూన్య
bandwidth_హద్దు_init(నిర్మాణం bwlimit *bw, uint64_t kbps, కొలత_t buflen)
{
	bw->buflen = buflen;
	bw->రేటు = kbps;
	bw->thresh = buflen;
	bw->lamt = 0;
	timerclear(&bw->bwstart);
	timerclear(&bw->bwend);
}

/* Callback from read/write loop to insert bandwidth-limiting delays */
శూన్య
bandwidth_హద్దు(నిర్మాణం bwlimit *bw, కొలత_t read_len)
{
	uint64_t waitlen;
	నిర్మాణం timespec ts, rm;

	bw->lamt += read_len;
	ఒకవేళ (!timerisset(&bw->bwstart)) {
		monotime_tv(&bw->bwstart);
		తిరిగి;
	}
	ఒకవేళ (bw->lamt < bw->thresh)
		తిరిగి;

	monotime_tv(&bw->bwend);
	timersub(&bw->bwend, &bw->bwstart, &bw->bwend);
	ఒకవేళ (!timerisset(&bw->bwend))
		తిరిగి;

	bw->lamt *= 8;
	waitlen = (ద్విగుణ)1000000L * bw->lamt / bw->రేటు;

	bw->bwstart.tv_sec = waitlen / 1000000L;
	bw->bwstart.tv_usec = waitlen % 1000000L;

	ఒకవేళ (timercmp(&bw->bwstart, &bw->bwend, >)) {
		timersub(&bw->bwstart, &bw->bwend, &bw->bwend);

		/* Adjust the wait time */
		ఒకవేళ (bw->bwend.tv_sec) {
			bw->thresh /= 2;
			ఒకవేళ (bw->thresh < bw->buflen / 4)
				bw->thresh = bw->buflen / 4;
		} లేకపోతే ఒకవేళ (bw->bwend.tv_usec < 10000) {
			bw->thresh *= 2;
			ఒకవేళ (bw->thresh > bw->buflen * 8)
				bw->thresh = bw->buflen * 8;
		}

		TIMEVAL_గమ్యం_TIMESPEC(&bw->bwend, &ts);
		అయితే (nanosleep(&ts, &rm) == -1) {
			ఒకవేళ (errno != EINTR)
				ఆపు;
			ts = rm;
		}
	}

	bw->lamt = 0;
	monotime_tv(&bw->bwstart);
}

/* Make a template filename for mk[sd]temp() */
శూన్య
mktemp_proto(అక్షరం *s, కొలత_t len)
{
	స్థిరరాశి అక్షరం *tmpdir;
	పూర్ణాంకం r;

	ఒకవేళ ((tmpdir = getenv("TMPDIR")) != ఖాళీ) {
		r = snprintf(s, len, "%s/ssh-XXXXXXXXXXXX", tmpdir);
		ఒకవేళ (r > 0 && (కొలత_t)r < len)
			తిరిగి;
	}
	r = snprintf(s, len, "/tmp/ssh-XXXXXXXXXXXX");
	ఒకవేళ (r < 0 || (కొలత_t)r >= len)
		fatal_f("template string too short");
}

స్థిర స్థిరరాశి నిర్మాణం {
	స్థిరరాశి అక్షరం *name;
	పూర్ణాంకం విలువ;
} ipqos[] = {
	{ "none", గరిష్ఠ_పూర్ణాంకం },		/* can't use 0 here; that's CS0 */
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
	{ ఖాళీ, -1 }
};

పూర్ణాంకం
parse_ipqos(స్థిరరాశి అక్షరం *cp)
{
	స్థిరరాశి అక్షరం *errstr;
	u_int i;
	పూర్ణాంకం val;

	ఒకవేళ (cp == ఖాళీ)
		తిరిగి -1;
	కొరకు (i = 0; ipqos[i].name != ఖాళీ; i++) {
		ఒకవేళ (strcasecmp(cp, ipqos[i].name) == 0)
			తిరిగి ipqos[i].విలువ;
	}
	/* Try parsing as an integer */
	val = (పూర్ణాంకం)strtonum(cp, 0, 255, &errstr);
	ఒకవేళ (errstr)
		తిరిగి -1;
	తిరిగి val;
}

స్థిరరాశి అక్షరం *
iptos2str(పూర్ణాంకం iptos)
{
	పూర్ణాంకం i;
	స్థిర అక్షరం iptos_str[పరిమాణం "0xff"];

	కొరకు (i = 0; ipqos[i].name != ఖాళీ; i++) {
		ఒకవేళ (ipqos[i].విలువ == iptos)
			తిరిగి ipqos[i].name;
	}
	snprintf(iptos_str, పరిమాణం iptos_str, "0x%02x", iptos);
	తిరిగి iptos_str;
}

శూన్య
lowercase(అక్షరం *s)
{
	కొరకు (; *s; s++)
		*s = tolower((u_char)*s);
}

పూర్ణాంకం
unix_listener(స్థిరరాశి అక్షరం *మార్గం, పూర్ణాంకం backlog, పూర్ణాంకం unlink_మొదటి)
{
	నిర్మాణం sockaddr_un sunaddr;
	పూర్ణాంకం saved_errno, sock;

	memset(&sunaddr, 0, పరిమాణం(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	ఒకవేళ (strlcpy(sunaddr.sun_మార్గం, మార్గం,
	    పరిమాణం(sunaddr.sun_మార్గం)) >= పరిమాణం(sunaddr.sun_మార్గం)) {
		error_f("path \"%s\" too long for Unix domain socket", మార్గం);
		errno = ENAMETOOLONG;
		తిరిగి -1;
	}

	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	ఒకవేళ (sock == -1) {
		saved_errno = errno;
		error_f("socket: %.100s", strerror(errno));
		errno = saved_errno;
		తిరిగి -1;
	}
	ఒకవేళ (unlink_మొదటి == 1) {
		ఒకవేళ (unlink(మార్గం) != 0 && errno != ENOENT)
			error("unlink(%s): %.100s", మార్గం, strerror(errno));
	}
	ఒకవేళ (bind(sock, (నిర్మాణం sockaddr *)&sunaddr, పరిమాణం(sunaddr)) == -1) {
		saved_errno = errno;
		error_f("cannot bind to path %s: %s", మార్గం, strerror(errno));
		close(sock);
		errno = saved_errno;
		తిరిగి -1;
	}
	ఒకవేళ (listen(sock, backlog) == -1) {
		saved_errno = errno;
		error_f("cannot listen on path %s: %s", మార్గం, strerror(errno));
		close(sock);
		unlink(మార్గం);
		errno = saved_errno;
		తిరిగి -1;
	}
	తిరిగి sock;
}

శూన్య
sock_సమితి_v6only(పూర్ణాంకం s)
{
#ఒకవేళ defined(IPV6_V6ONLY) && !defined(__OpenBSD__)
	పూర్ణాంకం on = 1;

	debug3_f("set socket %d IPV6_V6ONLY", s);
	ఒకవేళ (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &on, పరిమాణం(on)) == -1)
		error("setsockopt IPV6_V6ONLY: %s", strerror(errno));
#అయితే_ముగింపు
}

/*
 * Compares two strings that maybe be NULL. Returns non-zero if strings
 * are both NULL or are identical, returns zero otherwise.
 */
స్థిర పూర్ణాంకం
strcmp_maybe_null(స్థిరరాశి అక్షరం *a, స్థిరరాశి అక్షరం *b)
{
	ఒకవేళ ((a == ఖాళీ && b != ఖాళీ) || (a != ఖాళీ && b == ఖాళీ))
		తిరిగి 0;
	ఒకవేళ (a != ఖాళీ && strcmp(a, b) != 0)
		తిరిగి 0;
	తిరిగి 1;
}

/*
 * Compare two forwards, returning non-zero if they are identical or
 * zero otherwise.
 */
పూర్ణాంకం
forward_equals(స్థిరరాశి నిర్మాణం Forward *a, స్థిరరాశి నిర్మాణం Forward *b)
{
	ఒకవేళ (strcmp_maybe_null(a->listen_host, b->listen_host) == 0)
		తిరిగి 0;
	ఒకవేళ (a->listen_పోర్టు != b->listen_పోర్టు)
		తిరిగి 0;
	ఒకవేళ (strcmp_maybe_null(a->listen_మార్గం, b->listen_మార్గం) == 0)
		తిరిగి 0;
	ఒకవేళ (strcmp_maybe_null(a->connect_host, b->connect_host) == 0)
		తిరిగి 0;
	ఒకవేళ (a->connect_పోర్టు != b->connect_పోర్టు)
		తిరిగి 0;
	ఒకవేళ (strcmp_maybe_null(a->connect_మార్గం, b->connect_మార్గం) == 0)
		తిరిగి 0;
	/* allocated_port and handle are not checked */
	తిరిగి 1;
}

/* returns port number, FWD_PERMIT_ANY_PORT or -1 on error */
పూర్ణాంకం
permitopen_పోర్టు(స్థిరరాశి అక్షరం *p)
{
	పూర్ణాంకం పోర్టు;

	ఒకవేళ (strcmp(p, "*") == 0)
		తిరిగి FWD_PERMIT_ANY_పోర్టు;
	ఒకవేళ ((పోర్టు = a2port(p)) > 0)
		తిరిగి పోర్టు;
	తిరిగి -1;
}

/* returns 1 if process is already daemonized, 0 otherwise */
పూర్ణాంకం
daemonized(శూన్య)
{
	పూర్ణాంకం fd;

	ఒకవేళ ((fd = open(_PATH_TTY, O_RDONLY | O_NOCTTY)) >= 0) {
		close(fd);
		తిరిగి 0;	/* have controlling terminal */
	}
	ఒకవేళ (getppid() != 1)
		తిరిగి 0;	/* parent is not init */
	ఒకవేళ (getsid(0) != getpid())
		తిరిగి 0;	/* not session leader */
	debug3("already daemonized");
	తిరిగి 1;
}

/*
 * Splits 's' into an argument vector. Handles quoted string and basic
 * escape characters (\\, \", \'). Caller must free the argument vector
 * and its members.
 */
పూర్ణాంకం
argv_విభజించు(స్థిరరాశి అక్షరం *s, పూర్ణాంకం *argcp, అక్షరం ***argvp, పూర్ణాంకం terminate_on_comment)
{
	పూర్ణాంకం r = SSH_ERR_అంతర్గత_ERROR;
	పూర్ణాంకం argc = 0, quote, i, j;
	అక్షరం *arg, **argv = xcalloc(1, పరిమాణం(*argv));

	*argvp = ఖాళీ;
	*argcp = 0;

	కొరకు (i = 0; s[i] != '\0'; i++) {
		/* Skip leading whitespace */
		ఒకవేళ (s[i] == ' ' || s[i] == '\t')
			కొనసాగు;
		ఒకవేళ (terminate_on_comment && s[i] == '#')
			ఆపు;
		/* Start of a token */
		quote = 0;

		argv = xreallocarray(argv, (argc + 2), పరిమాణం(*argv));
		arg = argv[argc++] = xcalloc(1, అక్షరశ్రేణి_పొడవు(s + i) + 1);
		argv[argc] = ఖాళీ;

		/* Copy the token in, removing escapes */
		కొరకు (j = 0; s[i] != '\0'; i++) {
			ఒకవేళ (s[i] == '\\') {
				ఒకవేళ (s[i + 1] == '\'' ||
				    s[i + 1] == '\"' ||
				    s[i + 1] == '\\' ||
				    (quote == 0 && s[i + 1] == ' ')) {
					i++; /* Skip '\' */
					arg[j++] = s[i];
				} లేకపోతే {
					/* Unrecognised escape */
					arg[j++] = s[i];
				}
			} లేకపోతే ఒకవేళ (quote == 0 && (s[i] == ' ' || s[i] == '\t'))
				ఆపు; /*పూర్తి*/
			లేకపోతే ఒకవేళ (quote == 0 && (s[i] == '\"' || s[i] == '\''))
				quote = s[i]; /* quote start */
			లేకపోతే ఒకవేళ (quote != 0 && s[i] == quote)
				quote = 0; /* quote end */
			లేకపోతే
				arg[j++] = s[i];
		}
		ఒకవేళ (s[i] == '\0') {
			ఒకవేళ (quote != 0) {
				/* Ran out of string looking for close quote */
				r = SSH_ERR_INVALID_FORMAT;
				వెళ్ళు బహిర్గతం;
			}
			ఆపు;
		}
	}
	/* Success */
	*argcp = argc;
	*argvp = argv;
	argc = 0;
	argv = ఖాళీ;
	r = 0;
 బహిర్గతం:
	ఒకవేళ (argc != 0 && argv != ఖాళీ) {
		కొరకు (i = 0; i < argc; i++)
			విడుదల(argv[i]);
		విడుదల(argv);
	}
	తిరిగి r;
}

/*
 * Reassemble an argument vector into a string, quoting and escaping as
 * necessary. Caller must free returned string.
 */
అక్షరం *
argv_assemble(పూర్ణాంకం argc, అక్షరం **argv)
{
	పూర్ణాంకం i, j, ws, r;
	అక్షరం c, *ret;
	నిర్మాణం sshbuf *buf, *arg;

	ఒకవేళ ((buf = sshbuf_new()) == ఖాళీ || (arg = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");

	కొరకు (i = 0; i < argc; i++) {
		ws = 0;
		sshbuf_reset(arg);
		కొరకు (j = 0; argv[i][j] != '\0'; j++) {
			r = 0;
			c = argv[i][j];
			ఎంపిక (c) {
			స్థితి ' ':
			స్థితి '\t':
				ws = 1;
				r = sshbuf_put_u8(arg, c);
				ఆపు;
			స్థితి '\\':
			స్థితి '\'':
			స్థితి '"':
				ఒకవేళ ((r = sshbuf_put_u8(arg, '\\')) != 0)
					ఆపు;
				/* FALLTHROUGH */
			అప్రమేయ:
				r = sshbuf_put_u8(arg, c);
				ఆపు;
			}
			ఒకవేళ (r != 0)
				fatal_fr(r, "sshbuf_put_u8");
		}
		ఒకవేళ ((i != 0 && (r = sshbuf_put_u8(buf, ' ')) != 0) ||
		    (ws != 0 && (r = sshbuf_put_u8(buf, '"')) != 0) ||
		    (r = sshbuf_putb(buf, arg)) != 0 ||
		    (ws != 0 && (r = sshbuf_put_u8(buf, '"')) != 0))
			fatal_fr(r, "assemble");
	}
	ఒకవేళ ((ret = జ్ఞాపకం_ఇవ్వు(sshbuf_len(buf) + 1)) == ఖాళీ)
		fatal_f("malloc failed");
	జ్ఞాపకం_నకలు(ret, sshbuf_ptr(buf), sshbuf_len(buf));
	ret[sshbuf_len(buf)] = '\0';
	sshbuf_free(buf);
	sshbuf_free(arg);
	తిరిగి ret;
}

అక్షరం *
argv_తదుపరి(పూర్ణాంకం *argcp, అక్షరం ***argvp)
{
	అక్షరం *ret = (*argvp)[0];

	ఒకవేళ (*argcp > 0 && ret != ఖాళీ) {
		(*argcp)--;
		(*argvp)++;
	}
	తిరిగి ret;
}

శూన్య
argv_consume(పూర్ణాంకం *argcp)
{
	*argcp = 0;
}

శూన్య
argv_free(అక్షరం **av, పూర్ణాంకం ac)
{
	పూర్ణాంకం i;

	ఒకవేళ (av == ఖాళీ)
		తిరిగి;
	కొరకు (i = 0; i < ac; i++)
		విడుదల(av[i]);
	విడుదల(av);
}

/* Returns 0 if pid exited cleanly, non-zero otherwise */
పూర్ణాంకం
exited_cleanly(pid_t pid, స్థిరరాశి అక్షరం *ట్యాగ్, స్థిరరాశి అక్షరం *cmd, పూర్ణాంకం quiet)
{
	పూర్ణాంకం స్థితి_2;

	అయితే (waitpid(pid, &స్థితి_2, 0) == -1) {
		ఒకవేళ (errno != EINTR) {
			error("%s waitpid: %s", ట్యాగ్, strerror(errno));
			తిరిగి -1;
		}
	}
	ఒకవేళ (WIFSIGNALED(స్థితి_2)) {
		error("%s %s exited on signal %d", ట్యాగ్, cmd, WTERMSIG(స్థితి_2));
		తిరిగి -1;
	} లేకపోతే ఒకవేళ (WEXITSTATUS(స్థితి_2) != 0) {
		do_log2(quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_INFO,
		    "%s %s failed, status %d", ట్యాగ్, cmd, WEXITSTATUS(స్థితి_2));
		తిరిగి -1;
	}
	తిరిగి 0;
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
పూర్ణాంకం
సురక్షిత_మార్గం(స్థిరరాశి అక్షరం *name, నిర్మాణం stat *stp, స్థిరరాశి అక్షరం *pw_dir,
    uid_t uid, అక్షరం *err, కొలత_t errlen)
{
	అక్షరం buf[PATH_MAX], buf2[PATH_MAX], homedir[PATH_MAX];
	అక్షరం *cp;
	పూర్ణాంకం comparehome = 0;
	నిర్మాణం stat st;

	ఒకవేళ (realpath(name, buf) == ఖాళీ) {
		snprintf(err, errlen, "realpath %s failed: %s", name,
		    strerror(errno));
		తిరిగి -1;
	}
	ఒకవేళ (pw_dir != ఖాళీ && realpath(pw_dir, homedir) != ఖాళీ)
		comparehome = 1;

	ఒకవేళ (!S_ISREG(stp->st_mode)) {
		snprintf(err, errlen, "%s is not a regular file", buf);
		తిరిగి -1;
	}
	ఒకవేళ ((!platform_sys_dir_uid(stp->st_uid) && stp->st_uid != uid) ||
	    (stp->st_mode & 022) != 0) {
		snprintf(err, errlen, "bad ownership or modes for file %s",
		    buf);
		తిరిగి -1;
	}

	/* for each component of the canonical path, walking upwards */
	కొరకు (;;) {
		/*
		 * POSIX allows dirname to modify its argument and return a
		 * pointer into it, so make a copy to avoid overlapping strlcpy.
		 */
		strlcpy(buf2, buf, పరిమాణం(buf2));
		ఒకవేళ ((cp = dirname(buf2)) == ఖాళీ) {
			snprintf(err, errlen, "dirname() failed");
			తిరిగి -1;
		}
		strlcpy(buf, cp, పరిమాణం(buf));

		ఒకవేళ (stat(buf, &st) == -1 ||
		    (!platform_sys_dir_uid(st.st_uid) && st.st_uid != uid) ||
		    (st.st_mode & 022) != 0) {
			snprintf(err, errlen,
			    "bad ownership or modes for directory %s", buf);
			తిరిగి -1;
		}

		/* If are past the homedir then we can stop */
		ఒకవేళ (comparehome && strcmp(homedir, buf) == 0)
			ఆపు;

		/*
		 * dirname should always complete with a "/" path,
		 * but we can be paranoid and check for "." too
		 */
		ఒకవేళ ((strcmp("/", buf) == 0) || (strcmp(".", buf) == 0))
			ఆపు;
	}
	తిరిగి 0;
}

/*
 * Version of safe_path() that accepts an open file descriptor to
 * avoid races.
 *
 * Returns 0 on success and -1 on failure
 */
పూర్ణాంకం
సురక్షిత_మార్గం_fd(పూర్ణాంకం fd, స్థిరరాశి అక్షరం *file, నిర్మాణం passwd *pw,
    అక్షరం *err, కొలత_t errlen)
{
	నిర్మాణం stat st;

	/* check the open file to avoid races */
	ఒకవేళ (fstat(fd, &st) == -1) {
		snprintf(err, errlen, "cannot stat file %s: %s",
		    file, strerror(errno));
		తిరిగి -1;
	}
	తిరిగి సురక్షిత_మార్గం(file, &st, pw->pw_dir, pw->pw_uid, err, errlen);
}

/*
 * Sets the value of the given variable in the environment.  If the variable
 * already exists, its value is overridden.
 */
శూన్య
బిడ్డ_సమితి_env(అక్షరం ***envp, u_int *envsizep, స్థిరరాశి అక్షరం *name,
	స్థిరరాశి అక్షరం *విలువ)
{
	అక్షరం **env;
	u_int envsize;
	u_int i, namelen;

	ఒకవేళ (strchr(name, '=') != ఖాళీ) {
		error("Invalid environment variable \"%.100s\"", name);
		తిరిగి;
	}

	/*
	 * If we're passed an uninitialized list, allocate a single null
	 * entry before continuing.
	 */
	ఒకవేళ ((*envp == ఖాళీ) != (*envsizep == 0))
		fatal_f("environment size mismatch");
	ఒకవేళ (*envp == ఖాళీ && *envsizep == 0) {
		*envp = xmalloc(పరిమాణం(అక్షరం *));
		*envp[0] = ఖాళీ;
		*envsizep = 1;
	}

	/*
	 * Find the slot where the value should be stored.  If the variable
	 * already exists, we reuse the slot; otherwise we append a new slot
	 * at the end of the array, expanding if necessary.
	 */
	env = *envp;
	namelen = అక్షరశ్రేణి_పొడవు(name);
	కొరకు (i = 0; env[i]; i++)
		ఒకవేళ (అక్షరశ్రేణి_పోలిక(env[i], name, namelen) == 0 && env[i][namelen] == '=')
			ఆపు;
	ఒకవేళ (env[i]) {
		/* Reuse the slot. */
		విడుదల(env[i]);
	} లేకపోతే {
		/* New variable.  Expand if necessary. */
		envsize = *envsizep;
		ఒకవేళ (i >= envsize - 1) {
			ఒకవేళ (envsize >= 1000)
				fatal("child_set_env: too many env vars");
			envsize += 50;
			env = (*envp) = xreallocarray(env, envsize, పరిమాణం(అక్షరం *));
			*envsizep = envsize;
		}
		/* Need to set the NULL pointer at end of array beyond the new slot. */
		env[i + 1] = ఖాళీ;
	}

	/* Allocate space and format the variable in the appropriate slot. */
	/* XXX xasprintf */
	env[i] = xmalloc(అక్షరశ్రేణి_పొడవు(name) + 1 + అక్షరశ్రేణి_పొడవు(విలువ) + 1);
	snprintf(env[i], అక్షరశ్రేణి_పొడవు(name) + 1 + అక్షరశ్రేణి_పొడవు(విలువ) + 1, "%s=%s", name, విలువ);
}

/*
 * Check and optionally lowercase a domain name, also removes trailing '.'
 * Returns 1 on success and 0 on failure, storing an error message in errstr.
 */
పూర్ణాంకం
valid_domain(అక్షరం *name, పూర్ణాంకం makelower, స్థిరరాశి అక్షరం **errstr)
{
	కొలత_t i, l = అక్షరశ్రేణి_పొడవు(name);
	u_char c, చివరి = '\0';
	స్థిర అక్షరం errbuf[256];

	ఒకవేళ (l == 0) {
		strlcpy(errbuf, "empty domain name", పరిమాణం(errbuf));
		వెళ్ళు bad;
	}
	ఒకవేళ (!అక్షరమా((u_char)name[0]) && !అంకెనా((u_char)name[0]) &&
	   name[0] != '_' /* technically invalid, but common */) {
		snprintf(errbuf, పరిమాణం(errbuf), "domain name \"%.100s\" "
		    "starts with invalid character", name);
		వెళ్ళు bad;
	}
	కొరకు (i = 0; i < l; i++) {
		c = tolower((u_char)name[i]);
		ఒకవేళ (makelower)
			name[i] = (అక్షరం)c;
		ఒకవేళ (చివరి == '.' && c == '.') {
			snprintf(errbuf, పరిమాణం(errbuf), "domain name "
			    "\"%.100s\" contains consecutive separators", name);
			వెళ్ళు bad;
		}
		ఒకవేళ (c != '.' && c != '-' && !అక్షరమా_అంకెనా(c) &&
		    c != '_') /* technically invalid, but common */ {
			snprintf(errbuf, పరిమాణం(errbuf), "domain name "
			    "\"%.100s\" contains invalid characters", name);
			వెళ్ళు bad;
		}
		చివరి = c;
	}
	ఒకవేళ (name[l - 1] == '.')
		name[l - 1] = '\0';
	ఒకవేళ (errstr != ఖాళీ)
		*errstr = ఖాళీ;
	తిరిగి 1;
bad:
	ఒకవేళ (errstr != ఖాళీ)
		*errstr = errbuf;
	తిరిగి 0;
}

/*
 * Verify that a environment variable name (not including initial '$') is
 * valid; consisting of one or more alphanumeric or underscore characters only.
 * Returns 1 on valid, 0 otherwise.
 */
పూర్ణాంకం
valid_env_name(స్థిరరాశి అక్షరం *name)
{
	స్థిరరాశి అక్షరం *cp;

	ఒకవేళ (name[0] == '\0')
		తిరిగి 0;
	కొరకు (cp = name; *cp != '\0'; cp++) {
		ఒకవేళ (!అక్షరమా_అంకెనా((u_char)*cp) && *cp != '_')
			తిరిగి 0;
	}
	తిరిగి 1;
}

స్థిరరాశి అక్షరం *
atoi_err(స్థిరరాశి అక్షరం *nptr, పూర్ణాంకం *val)
{
	స్థిరరాశి అక్షరం *errstr = ఖాళీ;

	ఒకవేళ (nptr == ఖాళీ || *nptr == '\0')
		తిరిగి "missing";
	*val = strtonum(nptr, 0, గరిష్ఠ_పూర్ణాంకం, &errstr);
	తిరిగి errstr;
}

పూర్ణాంకం
parse_absolute_సమయం(స్థిరరాశి అక్షరం *s, uint64_t *tp)
{
	నిర్మాణం tm tm;
	time_t tt;
	అక్షరం buf[32], *fmt;
	స్థిరరాశి అక్షరం *cp;
	కొలత_t l;
	పూర్ణాంకం is_utc = 0;

	*tp = 0;

	l = అక్షరశ్రేణి_పొడవు(s);
	ఒకవేళ (l > 1 && strcasecmp(s + l - 1, "Z") == 0) {
		is_utc = 1;
		l--;
	} లేకపోతే ఒకవేళ (l > 3 && strcasecmp(s + l - 3, "UTC") == 0) {
		is_utc = 1;
		l -= 3;
	}
	/*
	 * POSIX strptime says "The application shall ensure that there
	 * is white-space or other non-alphanumeric characters between
	 * any two conversion specifications" so arrange things this way.
	 */
	ఎంపిక (l) {
	స్థితి 8: /* YYYYMMDD */
		fmt = "%Y-%m-%d";
		snprintf(buf, పరిమాణం(buf), "%.4s-%.2s-%.2s", s, s + 4, s + 6);
		ఆపు;
	స్థితి 12: /* YYYYMMDDHHMM */
		fmt = "%Y-%m-%dT%H:%M";
		snprintf(buf, పరిమాణం(buf), "%.4s-%.2s-%.2sT%.2s:%.2s",
		    s, s + 4, s + 6, s + 8, s + 10);
		ఆపు;
	స్థితి 14: /* YYYYMMDDHHMMSS */
		fmt = "%Y-%m-%dT%H:%M:%S";
		snprintf(buf, పరిమాణం(buf), "%.4s-%.2s-%.2sT%.2s:%.2s:%.2s",
		    s, s + 4, s + 6, s + 8, s + 10, s + 12);
		ఆపు;
	అప్రమేయ:
		తిరిగి SSH_ERR_INVALID_FORMAT;
	}

	memset(&tm, 0, పరిమాణం(tm));
	ఒకవేళ ((cp = strptime(buf, fmt, &tm)) == ఖాళీ || *cp != '\0')
		తిరిగి SSH_ERR_INVALID_FORMAT;
	ఒకవేళ (is_utc) {
		tm.tm_wday = -1;	/* sentinel for error */
		ఒకవేళ ((tt = timegm(&tm)) == -1 && tm.tm_wday == -1)
			తిరిగి SSH_ERR_INVALID_FORMAT;
	} లేకపోతే {
		tm.tm_wday = -1;	/* sentinel for error */
		tm.tm_isdst = -1;	/* mktime decides DST */
		ఒకవేళ ((tt = mktime(&tm)) == -1 && tm.tm_wday == -1)
			తిరిగి SSH_ERR_INVALID_FORMAT;
	}
	/* success */
	*tp = (uint64_t)tt;
	తిరిగి 0;
}

శూన్య
format_absolute_సమయం(uint64_t t, అక్షరం *buf, కొలత_t len)
{
	time_t tt = t > SSH_సమయం_T_MAX ? SSH_సమయం_T_MAX : t;
	నిర్మాణం tm tm;

	ఒకవేళ (localtime_r(&tt, &tm) == ఖాళీ)
		strlcpy(buf, "UNKNOWN-TIME", len);
	లేకపోతే
		strftime(buf, len, "%Y-%m-%dT%H:%M:%S", &tm);
}

/*
 * Parse a "pattern=interval" clause (e.g. a ChannelTimeout).
 * Returns 0 on success or non-zero on failure.
 * Caller must free *typep.
 */
పూర్ణాంకం
parse_నమూనా_interval(స్థిరరాశి అక్షరం *s, అక్షరం **typep, ద్విగుణ *secsp)
{
	అక్షరం *cp, *sdup;
	ద్విగుణ secs;

	ఒకవేళ (typep != ఖాళీ)
		*typep = ఖాళీ;
	ఒకవేళ (secsp != ఖాళీ)
		*secsp = 0;
	ఒకవేళ (s == ఖాళీ)
		తిరిగి -1;
	sdup = xstrdup(s);

	ఒకవేళ ((cp = strchr(sdup, '=')) == ఖాళీ || cp == sdup) {
		విడుదల(sdup);
		తిరిగి -1;
	}
	*cp++ = '\0';
	ఒకవేళ ((secs = convtime_double(cp)) < 0.0) {
		విడుదల(sdup);
		తిరిగి -1;
	}
	/* success */
	ఒకవేళ (typep != ఖాళీ)
		*typep = xstrdup(sdup);
	ఒకవేళ (secsp != ఖాళీ)
		*secsp = secs;
	విడుదల(sdup);
	తిరిగి 0;
}

/* check if path is absolute */
పూర్ణాంకం
మార్గం_absolute(స్థిరరాశి అక్షరం *మార్గం)
{
	తిరిగి (*మార్గం == '/') ? 1 : 0;
}

శూన్య
skip_space(అక్షరం **cpp)
{
	అక్షరం *cp;

	కొరకు (cp = *cpp; *cp == ' ' || *cp == '\t'; cp++)
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
పూర్ణాంకం
opt_flag(స్థిరరాశి అక్షరం *opt, పూర్ణాంకం allow_negate, స్థిరరాశి అక్షరం **optsp)
{
	కొలత_t opt_len = అక్షరశ్రేణి_పొడవు(opt);
	స్థిరరాశి అక్షరం *opts = *optsp;
	పూర్ణాంకం negate = 0;

	ఒకవేళ (allow_negate && strncasecmp(opts, "no-", 3) == 0) {
		opts += 3;
		negate = 1;
	}
	ఒకవేళ (strncasecmp(opts, opt, opt_len) == 0) {
		*optsp = opts + opt_len;
		తిరిగి negate ? 0 : 1;
	}
	తిరిగి -1;
}

అక్షరం *
opt_dequote(స్థిరరాశి అక్షరం **sp, స్థిరరాశి అక్షరం **errstrp)
{
	స్థిరరాశి అక్షరం *s = *sp;
	అక్షరం *ret;
	కొలత_t i;

	*errstrp = ఖాళీ;
	ఒకవేళ (*s != '"') {
		*errstrp = "missing start quote";
		తిరిగి ఖాళీ;
	}
	s++;
	ఒకవేళ ((ret = జ్ఞాపకం_ఇవ్వు(అక్షరశ్రేణి_పొడవు((s)) + 1)) == ఖాళీ) {
		*errstrp = "memory allocation failed";
		తిరిగి ఖాళీ;
	}
	కొరకు (i = 0; *s != '\0' && *s != '"';) {
		ఒకవేళ (s[0] == '\\' && s[1] == '"')
			s++;
		ret[i++] = *s++;
	}
	ఒకవేళ (*s == '\0') {
		*errstrp = "missing end quote";
		విడుదల(ret);
		తిరిగి ఖాళీ;
	}
	ret[i] = '\0';
	s++;
	*sp = s;
	తిరిగి ret;
}

పూర్ణాంకం
opt_సరిపోలిక(స్థిరరాశి అక్షరం **opts, స్థిరరాశి అక్షరం *పదం)
{
	ఒకవేళ (strncasecmp((*opts), పదం, అక్షరశ్రేణి_పొడవు(పదం)) == 0 &&
	    (*opts)[అక్షరశ్రేణి_పొడవు(పదం)] == '=') {
		*opts += అక్షరశ్రేణి_పొడవు(పదం) + 1;
		తిరిగి 1;
	}
	తిరిగి 0;
}

శూన్య
opt_array_append2(స్థిరరాశి అక్షరం *file, స్థిరరాశి పూర్ణాంకం పంక్తి, స్థిరరాశి అక్షరం *directive,
    అక్షరం ***array, పూర్ణాంకం **iarray, u_int *lp, స్థిరరాశి అక్షరం *s, పూర్ణాంకం i)
{

	ఒకవేళ (*lp >= గరిష్ఠ_పూర్ణాంకం)
		fatal("%s line %d: Too many %s entries", file, పంక్తి, directive);

	ఒకవేళ (iarray != ఖాళీ) {
		*iarray = xrecallocarray(*iarray, *lp, *lp + 1,
		    పరిమాణం(**iarray));
		(*iarray)[*lp] = i;
	}

	*array = xrecallocarray(*array, *lp, *lp + 1, పరిమాణం(**array));
	(*array)[*lp] = xstrdup(s);
	(*lp)++;
}

శూన్య
opt_array_append(స్థిరరాశి అక్షరం *file, స్థిరరాశి పూర్ణాంకం పంక్తి, స్థిరరాశి అక్షరం *directive,
    అక్షరం ***array, u_int *lp, స్థిరరాశి అక్షరం *s)
{
	opt_array_append2(file, పంక్తి, directive, array, ఖాళీ, lp, s, 0);
}

శూన్య
opt_array_free2(అక్షరం **array, పూర్ణాంకం **iarray, u_int l)
{
	u_int i;

	ఒకవేళ (array == ఖాళీ || l == 0)
		తిరిగి;
	కొరకు (i = 0; i < l; i++)
		విడుదల(array[i]);
	విడుదల(array);
	విడుదల(iarray);
}

sshsig_t
ssh_signal(పూర్ణాంకం signum, sshsig_t handler)
{
	నిర్మాణం sigaction sa, osa;

	/* mask all other signals while in handler */
	memset(&sa, 0, పరిమాణం(sa));
	sa.sa_handler = handler;
	sigfillset(&sa.sa_mask);
#ఒకవేళ defined(SA_RESTART) && !defined(NO_SA_RESTART)
	ఒకవేళ (signum != SIGALRM)
		sa.sa_flags = SA_RESTART;
#అయితే_ముగింపు
	ఒకవేళ (sigaction(signum, &sa, &osa) == -1) {
		debug3("sigaction(%s): %s", strsignal(signum), strerror(errno));
		తిరిగి SIG_ERR;
	}
	తిరిగి osa.sa_handler;
}

పూర్ణాంకం
stdfd_devnull(పూర్ణాంకం do_stdin, పూర్ణాంకం do_stdout, పూర్ణాంకం do_stderr)
{
	పూర్ణాంకం devnull, ret = 0;

	ఒకవేళ ((devnull = open(_PATH_DEVNULL, O_RDWR)) == -1) {
		error_f("open %s: %s", _PATH_DEVNULL,
		    strerror(errno));
		తిరిగి -1;
	}
	ఒకవేళ ((do_stdin && dup2(devnull, STDIN_FILENO) == -1) ||
	    (do_stdout && dup2(devnull, STDOUT_FILENO) == -1) ||
	    (do_stderr && dup2(devnull, STDERR_FILENO) == -1)) {
		error_f("dup2: %s", strerror(errno));
		ret = -1;
	}
	ఒకవేళ (devnull > STDERR_FILENO)
		close(devnull);
	తిరిగి ret;
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
subprocess(స్థిరరాశి అక్షరం *ట్యాగ్, స్థిరరాశి అక్షరం *command,
    పూర్ణాంకం ac, అక్షరం **av, FILE **బిడ్డ, u_int flags,
    నిర్మాణం passwd *pw, privdrop_fn *drop_privs, privrestore_fn *restore_privs)
{
	FILE *f = ఖాళీ;
	నిర్మాణం stat st;
	పూర్ణాంకం fd, devnull, p[2], i;
	pid_t pid;
	అక్షరం *cp, errmsg[512];
	u_int nenv = 0;
	అక్షరం **env = ఖాళీ;

	/* If dropping privs, then must specify user and restore function */
	ఒకవేళ (drop_privs != ఖాళీ && (pw == ఖాళీ || restore_privs == ఖాళీ)) {
		error("%s: inconsistent arguments", ట్యాగ్); /* XXX fatal? */
		తిరిగి 0;
	}
	ఒకవేళ (pw == ఖాళీ && (pw = getpwuid(getuid())) == ఖాళీ) {
		error("%s: no user for current uid", ట్యాగ్);
		తిరిగి 0;
	}
	ఒకవేళ (బిడ్డ != ఖాళీ)
		*బిడ్డ = ఖాళీ;

	debug3_f("%s command \"%s\" running as %s (flags 0x%x)",
	    ట్యాగ్, command, pw->pw_name, flags);

	/* Check consistency */
	ఒకవేళ ((flags & SSH_SUBPROCESS_STDOUT_DISCARD) != 0 &&
	    (flags & SSH_SUBPROCESS_STDOUT_CAPTURE) != 0) {
		error_f("inconsistent flags");
		తిరిగి 0;
	}
	ఒకవేళ (((flags & SSH_SUBPROCESS_STDOUT_CAPTURE) == 0) != (బిడ్డ == ఖాళీ)) {
		error_f("inconsistent flags/output");
		తిరిగి 0;
	}

	/*
	 * If executing an explicit binary, then verify the it exists
	 * and appears safe-ish to execute
	 */
	ఒకవేళ (!మార్గం_absolute(av[0])) {
		error("%s path is not absolute", ట్యాగ్);
		తిరిగి 0;
	}
	ఒకవేళ (drop_privs != ఖాళీ)
		drop_privs(pw);
	ఒకవేళ (stat(av[0], &st) == -1) {
		error("Could not stat %s \"%s\": %s", ట్యాగ్,
		    av[0], strerror(errno));
		వెళ్ళు restore_return;
	}
	ఒకవేళ ((flags & SSH_SUBPROCESS_UNSAFE_మార్గం) == 0 &&
	    సురక్షిత_మార్గం(av[0], &st, ఖాళీ, 0, errmsg, పరిమాణం(errmsg)) != 0) {
		error("Unsafe %s \"%s\": %s", ట్యాగ్, av[0], errmsg);
		వెళ్ళు restore_return;
	}
	/* Prepare to keep the child's stdout if requested */
	ఒకవేళ (pipe(p) == -1) {
		error("%s: pipe: %s", ట్యాగ్, strerror(errno));
 restore_return:
		ఒకవేళ (restore_privs != ఖాళీ)
			restore_privs();
		తిరిగి 0;
	}
	ఒకవేళ (restore_privs != ఖాళీ)
		restore_privs();

	ఎంపిక ((pid = fork())) {
	స్థితి -1: /* error */
		error("%s: fork: %s", ట్యాగ్, strerror(errno));
		close(p[0]);
		close(p[1]);
		తిరిగి 0;
	స్థితి 0: /*బిడ్డ*/
		/* Prepare a minimal environment for the child. */
		ఒకవేళ ((flags & SSH_SUBPROCESS_PRESERVE_ENV) == 0) {
			nenv = 5;
			env = xcalloc(పరిమాణం(*env), nenv);
			బిడ్డ_సమితి_env(&env, &nenv, "PATH", _PATH_STDPATH);
			బిడ్డ_సమితి_env(&env, &nenv, "USER", pw->pw_name);
			బిడ్డ_సమితి_env(&env, &nenv, "LOGNAME", pw->pw_name);
			బిడ్డ_సమితి_env(&env, &nenv, "HOME", pw->pw_dir);
			ఒకవేళ ((cp = getenv("LANG")) != ఖాళీ)
				బిడ్డ_సమితి_env(&env, &nenv, "LANG", cp);
		}

		కొరకు (i = 1; i < NSIG; i++)
			ssh_signal(i, SIG_DFL);

		ఒకవేళ ((devnull = open(_PATH_DEVNULL, O_RDWR)) == -1) {
			error("%s: open %s: %s", ట్యాగ్, _PATH_DEVNULL,
			    strerror(errno));
			_exit(1);
		}
		ఒకవేళ (dup2(devnull, STDIN_FILENO) == -1) {
			error("%s: dup2: %s", ట్యాగ్, strerror(errno));
			_exit(1);
		}

		/* Set up stdout as requested; leave stderr in place for now. */
		fd = -1;
		ఒకవేళ ((flags & SSH_SUBPROCESS_STDOUT_CAPTURE) != 0)
			fd = p[1];
		లేకపోతే ఒకవేళ ((flags & SSH_SUBPROCESS_STDOUT_DISCARD) != 0)
			fd = devnull;
		ఒకవేళ (fd != -1 && dup2(fd, STDOUT_FILENO) == -1) {
			error("%s: dup2: %s", ట్యాగ్, strerror(errno));
			_exit(1);
		}
		closefrom(STDERR_FILENO + 1);

		ఒకవేళ (geteuid() == 0 &&
		    initgroups(pw->pw_name, pw->pw_gid) == -1) {
			error("%s: initgroups(%s, %u): %s", ట్యాగ్,
			    pw->pw_name, (u_int)pw->pw_gid, strerror(errno));
			_exit(1);
		}
		ఒకవేళ (setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) == -1) {
			error("%s: setresgid %u: %s", ట్యాగ్, (u_int)pw->pw_gid,
			    strerror(errno));
			_exit(1);
		}
		ఒకవేళ (setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) == -1) {
			error("%s: setresuid %u: %s", ట్యాగ్, (u_int)pw->pw_uid,
			    strerror(errno));
			_exit(1);
		}
		/* stdin is pointed to /dev/null at this point */
		ఒకవేళ ((flags & SSH_SUBPROCESS_STDOUT_DISCARD) != 0 &&
		    dup2(STDIN_FILENO, STDERR_FILENO) == -1) {
			error("%s: dup2: %s", ట్యాగ్, strerror(errno));
			_exit(1);
		}
		ఒకవేళ (env != ఖాళీ)
			execve(av[0], av, env);
		లేకపోతే
			execv(av[0], av);
		error("%s %s \"%s\": %s", ట్యాగ్, env == ఖాళీ ? "execv" : "execve",
		    command, strerror(errno));
		_exit(127);
	అప్రమేయ: /*మాతృ*/
		ఆపు;
	}

	close(p[1]);
	ఒకవేళ ((flags & SSH_SUBPROCESS_STDOUT_CAPTURE) == 0)
		close(p[0]);
	లేకపోతే ఒకవేళ ((f = fdopen(p[0], "r")) == ఖాళీ) {
		error("%s: fdopen: %s", ట్యాగ్, strerror(errno));
		close(p[0]);
		/* Don't leave zombie child */
		kill(pid, SIGTERM);
		అయితే (waitpid(pid, ఖాళీ, 0) == -1 && errno == EINTR)
			;
		తిరిగి 0;
	}
	/* Success */
	debug3_f("%s pid %ld", ట్యాగ్, (దీర్ఘ)pid);
	ఒకవేళ (బిడ్డ != ఖాళీ)
		*బిడ్డ = f;
	తిరిగి pid;
}

స్థిరరాశి అక్షరం *
lookup_env_లోపల_list(స్థిరరాశి అక్షరం *env, అక్షరం * స్థిరరాశి *envs, కొలత_t nenvs)
{
	కొలత_t i, envlen;

	envlen = అక్షరశ్రేణి_పొడవు(env);
	కొరకు (i = 0; i < nenvs; i++) {
		ఒకవేళ (అక్షరశ్రేణి_పోలిక(envs[i], env, envlen) == 0 &&
		    envs[i][envlen] == '=') {
			తిరిగి envs[i] + envlen + 1;
		}
	}
	తిరిగి ఖాళీ;
}

స్థిరరాశి అక్షరం *
lookup_setenv_లోపల_list(స్థిరరాశి అక్షరం *env, అక్షరం * స్థిరరాశి *envs, కొలత_t nenvs)
{
	అక్షరం *name, *cp;
	స్థిరరాశి అక్షరం *ret;

	name = xstrdup(env);
	ఒకవేళ ((cp = strchr(name, '=')) == ఖాళీ) {
		విడుదల(name);
		తిరిగి ఖాళీ; /* not env=val */
	}
	*cp = '\0';
	ret = lookup_env_లోపల_list(name, envs, nenvs);
	విడుదల(name);
	తిరిగి ret;
}

/*
 * Helpers for managing poll(2)/ppoll(2) timeouts
 * Will remember the earliest deadline and return it for use in poll/ppoll.
 */

/* Initialise a poll/ppoll timeout with an indefinite deadline */
శూన్య
ptimeout_init(నిర్మాణం timespec *pt)
{
	/*
	 * Deliberately invalid for ppoll(2).
	 * Will be converted to NULL in ptimeout_get_tspec() later.
	 */
	pt->tv_sec = -1;
	pt->tv_nsec = 0;
}

/* Specify a poll/ppoll deadline of at most 'sec' seconds */
శూన్య
ptimeout_deadline_sec(నిర్మాణం timespec *pt, దీర్ఘ sec)
{
	ఒకవేళ (pt->tv_sec == -1 || pt->tv_sec >= sec) {
		pt->tv_sec = sec;
		pt->tv_nsec = 0;
	}
}

/* Specify a poll/ppoll deadline of at most 'p' (timespec) */
స్థిర శూన్య
ptimeout_deadline_tsp(నిర్మాణం timespec *pt, నిర్మాణం timespec *p)
{
	ఒకవేళ (pt->tv_sec == -1 || timespeccmp(pt, p, >=))
		*pt = *p;
}

/* Specify a poll/ppoll deadline of at most 'ms' milliseconds */
శూన్య
ptimeout_deadline_ms(నిర్మాణం timespec *pt, దీర్ఘ ms)
{
	నిర్మాణం timespec p;

	p.tv_sec = ms / 1000;
	p.tv_nsec = (ms % 1000) * 1000000;
	ptimeout_deadline_tsp(pt, &p);
}

/* Specify a poll/ppoll deadline of at most 'sec' seconds (double) */
శూన్య
ptimeout_deadline_sec_double(నిర్మాణం timespec *pt, ద్విగుణ sec)
{
	నిర్మాణం timespec t;

	memset(&t, 0, పరిమాణం(t));
	ఒకవేళ ((int64_t)sec >= SSH_సమయం_T_MAX)
		t.tv_sec = SSH_సమయం_T_MAX;
	లేకపోతే ఒకవేళ (sec > 0) {
		t.tv_sec = sec;
		t.tv_nsec = (sec - (ద్విగుణ)t.tv_sec) * 1000000000.0;
	}
	ptimeout_deadline_tsp(pt, &t);
}

/* Specify a poll/ppoll deadline at wall clock monotime 'when' (timespec) */
శూన్య
ptimeout_deadline_monotime_tsp(నిర్మాణం timespec *pt, నిర్మాణం timespec *when)
{
	నిర్మాణం timespec now, t;

	monotime_ts(&now);

	ఒకవేళ (timespeccmp(&now, when, >=)) {
		/* 'when' is now or in the past. Timeout ASAP */
		pt->tv_sec = 0;
		pt->tv_nsec = 0;
	} లేకపోతే {
		timespecsub(when, &now, &t);
		ptimeout_deadline_tsp(pt, &t);
	}
}

/* Specify a poll/ppoll deadline at wall clock monotime 'when' (double) */
శూన్య
ptimeout_deadline_monotime_double(నిర్మాణం timespec *pt, ద్విగుణ when)
{
	ptimeout_deadline_sec_double(pt, when - monotime_double());
}

/* Specify a poll/ppoll deadline at wall clock monotime 'when' */
శూన్య
ptimeout_deadline_monotime(నిర్మాణం timespec *pt, time_t when)
{
	నిర్మాణం timespec t;

	t.tv_sec = when;
	t.tv_nsec = 0;
	ptimeout_deadline_monotime_tsp(pt, &t);
}

/* Get a poll(2) timeout value in milliseconds */
పూర్ణాంకం
ptimeout_get_ms(నిర్మాణం timespec *pt)
{
	ఒకవేళ (pt->tv_sec == -1)
		తిరిగి -1;
	ఒకవేళ (pt->tv_sec >= (గరిష్ఠ_పూర్ణాంకం - (pt->tv_nsec / 1000000)) / 1000)
		తిరిగి గరిష్ఠ_పూర్ణాంకం;
	తిరిగి (pt->tv_sec * 1000) + (pt->tv_nsec / 1000000);
}

/* Get a ppoll(2) timeout value as a timespec pointer */
నిర్మాణం timespec *
ptimeout_get_tsp(నిర్మాణం timespec *pt)
{
	తిరిగి pt->tv_sec == -1 ? ఖాళీ : pt;
}

/* Returns non-zero if a timeout has been set (i.e. is not indefinite) */
పూర్ణాంకం
ptimeout_isset(నిర్మాణం timespec *pt)
{
	తిరిగి pt->tv_sec != -1;
}

/*
 * Returns zero if the library at 'path' contains symbol 's', nonzero
 * otherwise.
 */
పూర్ణాంకం
lib_కలిగియుంది_చిహ్నం(స్థిరరాశి అక్షరం *మార్గం, స్థిరరాశి అక్షరం *s)
{
#నిర్వచితమైతే HAVE_NLIST
	నిర్మాణం nlist nl[2];
	పూర్ణాంకం ret = -1, r;

	memset(nl, 0, పరిమాణం(nl));
	nl[0].n_name = xstrdup(s);
	nl[1].n_name = ఖాళీ;
	ఒకవేళ ((r = nlist(మార్గం, nl)) == -1) {
		error_f("nlist failed for %s", మార్గం);
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (r != 0 || nl[0].n_విలువ == 0 || nl[0].n_type == 0) {
		error_f("library %s does not contain symbol %s", మార్గం, s);
		వెళ్ళు బహిర్గతం;
	}
	/* success */
	ret = 0;
 బహిర్గతం:
	విడుదల(nl[0].n_name);
	తిరిగి ret;
#లేకపోతే /* HAVE_NLIST */
	పూర్ణాంకం fd, ret = -1;
	నిర్మాణం stat st;
	శూన్య *m = ఖాళీ;
	కొలత_t sz = 0;

	memset(&st, 0, పరిమాణం(st));
	ఒకవేళ ((fd = open(మార్గం, O_RDONLY)) < 0) {
		error_f("open %s: %s", మార్గం, strerror(errno));
		తిరిగి -1;
	}
	ఒకవేళ (fstat(fd, &st) != 0) {
		error_f("fstat %s: %s", మార్గం, strerror(errno));
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (!S_ISREG(st.st_mode)) {
		error_f("%s is not a regular file", మార్గం);
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (st.st_size < 0 ||
	    (కొలత_t)st.st_size < అక్షరశ్రేణి_పొడవు(s) ||
	    st.st_size >= గరిష్ఠ_పూర్ణాంకం/2) {
		error_f("%s bad size %lld", మార్గం, (దీర్ఘ దీర్ఘ)st.st_size);
		వెళ్ళు బహిర్గతం;
	}
	sz = (కొలత_t)st.st_size;
	ఒకవేళ ((m = mmap(ఖాళీ, sz, PROT_READ, MAP_PRIVATE, fd, 0)) == MAP_FAILED ||
	    m == ఖాళీ) {
		error_f("mmap %s: %s", మార్గం, strerror(errno));
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (memmem(m, sz, s, అక్షరశ్రేణి_పొడవు(s)) == ఖాళీ) {
		error_f("%s does not contain expected string %s", మార్గం, s);
		వెళ్ళు బహిర్గతం;
	}
	/* success */
	ret = 0;
 బహిర్గతం:
	ఒకవేళ (m != ఖాళీ && m != MAP_FAILED)
		munmap(m, sz);
	close(fd);
	తిరిగి ret;
#అయితే_ముగింపు /* HAVE_NLIST */
}

పూర్ణాంకం
signal_is_crash(పూర్ణాంకం sig)
{
	ఎంపిక (sig) {
	స్థితి SIGSEGV:
	స్థితి SIGBUS:
	స్థితి SIGTRAP:
	స్థితి SIGSYS:
	స్థితి SIGFPE:
	స్థితి SIGILL:
	స్థితి SIGABRT:
		తిరిగి 1;
	}
	తిరిగి 0;
}

అక్షరం *
get_homedir(శూన్య)
{
	అక్షరం *cp;
	నిర్మాణం passwd *pw;

	ఒకవేళ ((cp = getenv("HOME")) != ఖాళీ && *cp != '\0')
		తిరిగి xstrdup(cp);

	ఒకవేళ ((pw = getpwuid(getuid())) != ఖాళీ && *pw->pw_dir != '\0')
		తిరిగి xstrdup(pw->pw_dir);

	తిరిగి ఖాళీ;
}

పూర్ణాంకం
mkdir_మార్గం(స్థిరరాశి అక్షరం *లక్ష్యం, బహుళకం_t బహుళకం)
{
#ఒకవేళ defined(HAVE_OPENAT) && defined(O_DIRECTORY)
	అక్షరం *dir, *odir = ఖాళీ, *తదుపరి;
	పూర్ణాంకం fd = AT_FDCWD, fd2, subpath_len, ret = -1;

	dir = odir = xstrdup(లక్ష్యం);

	ఒకవేళ (*dir == '/' &&
	    (fd = open("/", O_RDONLY|O_DIRECTORY)) == -1) {
		error_f("open(\"/\"): %s", strerror(errno));
		విడుదల(odir);
		తిరిగి -1;
	}
	/* Work through the path, component-wise */
	కొరకు (; dir != ఖాళీ && *dir != '\0'; dir = తదుపరి) {
		ఒకవేళ ((తదుపరి = strchr(dir, '/')) != ఖాళీ)
			*(తదుపరి++) = '\0';
		ఒకవేళ (*dir == '\0')
			కొనసాగు;
		subpath_len = (తదుపరి == ఖాళీ) ? గరిష్ఠ_పూర్ణాంకం : తదుపరి - odir - 1;
		ఒకవేళ (mkdirat(fd, dir, బహుళకం) == 0)
			debug_f("created directory %.*s", subpath_len, లక్ష్యం);
		లేకపోతే ఒకవేళ (errno != EEXIST) {
			error_f("mkdir(\"%.*s\"): %s",
			    subpath_len, లక్ష్యం, strerror(errno));
			వెళ్ళు బహిర్గతం;
		}

		/* descend */
		ఒకవేళ ((fd2 = openat(fd, dir, O_RDONLY|O_DIRECTORY)) == -1) {
			error_f("open(\"%.*s\"): %s",
			    subpath_len, లక్ష్యం, strerror(errno));
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ (fd != AT_FDCWD)
			close(fd);
		fd = fd2;
	}
	/* success */
	ret = 0;
 బహిర్గతం:
	విడుదల(odir);
	ఒకవేళ (fd != AT_FDCWD)
		close(fd);
	తిరిగి ret;
#లేకపోతే
	/*
	 * If we don't have openat (which was added in POSIX.1-2008), fall back
	 * to the possibly racy way.
	 */
	అక్షరం *dir, *odir, *p, మార్గం[PATH_MAX] = "";
	పూర్ణాంకం ret = -1;
	కొలత_t plen = పరిమాణం(మార్గం);

	dir = odir = xstrdup(లక్ష్యం);

	/* If the dir is relative, start with cwd. */
	ఒకవేళ (*dir != '/' && getcwd(మార్గం, plen) == ఖాళీ) {
		error_f("getcwd: %s", strerror(errno));
		వెళ్ళు బహిర్గతం;
	}

	/* Work through the path, component-wise */
	అయితే ((p = strsep(&dir, "/"))) {
		ఒకవేళ (*p == '\0')
			కొనసాగు;
		ఒకవేళ (strlcat(మార్గం, "/", plen) >= plen ||
		    strlcat(మార్గం, p, plen) >= plen)
			వెళ్ళు బహిర్గతం;
		ఒకవేళ (mkdir(మార్గం, బహుళకం) == 0)
			debug_f("created directory %s", మార్గం);
		లేకపోతే ఒకవేళ (errno != EEXIST && errno != EISDIR) {
			error_f("mkdir(\"%s\"): %s", మార్గం, strerror(errno));
			వెళ్ళు బహిర్గతం;
		}
	}
	/* success */
	ret = 0;
 బహిర్గతం:
	విడుదల(odir);
	తిరిగి ret;
#అయితే_ముగింపు
}
