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
अक्षर *
chop(अक्षर *s)
{
	अक्षर *t = s;
	पर्यंत (*t) {
		जर (*t == '\n' || *t == '\r') {
			*t = '\0';
			परत s;
		}
		t++;
	}
	परत s;

}

/* remove whitespace from end of string */
शून्य
rtrim(अक्षर *s)
{
	माप_प्रकार i;

	जर ((i = म_माप(s)) == 0)
		परत;
	करा {
		i--;
		जर (है_खाली((अचिन्हित अक्षर)s[i]))
			s[i] = '\0';
		अन्यथा
			थांबा;
	} पर्यंत (i > 0);
}

/*
 * returns pointer to character after 'prefix' in 's' or otherwise NULL
 * if the prefix is not present.
 */
स्थिरांक अक्षर *
strprefix(स्थिरांक अक्षर *s, स्थिरांक अक्षर *prefix, पूर्णांक ignorecase)
{
	माप_प्रकार prefixlen;

	जर ((prefixlen = म_माप(prefix)) == 0)
		परत s;
	जर (ignorecase) {
		जर (strncasecmp(s, prefix, prefixlen) != 0)
			परत रिक्त;
	} अन्यथा {
		जर (म_भेदन(s, prefix, prefixlen) != 0)
			परत रिक्त;
	}
	परत s + prefixlen;
}

/* Append string 's' to a NULL-terminated array of strings */
शून्य
stringlist_append(अक्षर ***listp, स्थिरांक अक्षर *s)
{
	माप_प्रकार i = 0;

	जर (*listp == रिक्त)
		*listp = xcalloc(2, आकार(**listp));
	अन्यथा {
		साठी (i = 0; (*listp)[i] != रिक्त; i++)
			; /* count */
		*listp = xrecallocarray(*listp, i + 1, i + 2, आकार(**listp));
	}
	(*listp)[i] = xstrdup(s);
}

शून्य
stringlist_free(अक्षर **list)
{
	माप_प्रकार i = 0;

	जर (list == रिक्त)
		परत;
	साठी (i = 0; list[i] != रिक्त; i++)
		मुक्त(list[i]);
	मुक्त(list);
}

/* set/unset filedescriptor to non-blocking */
पूर्णांक
set_nonblock(पूर्णांक fd)
{
	पूर्णांक val;

	val = fcntl(fd, F_GETFL);
	जर (val == -1) {
		error("fcntl(%d, F_GETFL): %s", fd, म_त्रुटि(त्रुटि_सं));
		परत (-1);
	}
	जर (val & O_NONBLOCK) {
		debug3("fd %d is O_NONBLOCK", fd);
		परत (0);
	}
	debug2("fd %d setting O_NONBLOCK", fd);
	val |= O_NONBLOCK;
	जर (fcntl(fd, F_SETFL, val) == -1) {
		debug("fcntl(%d, F_SETFL, O_NONBLOCK): %s", fd,
		    म_त्रुटि(त्रुटि_सं));
		परत (-1);
	}
	परत (0);
}

पूर्णांक
unset_nonblock(पूर्णांक fd)
{
	पूर्णांक val;

	val = fcntl(fd, F_GETFL);
	जर (val == -1) {
		error("fcntl(%d, F_GETFL): %s", fd, म_त्रुटि(त्रुटि_सं));
		परत (-1);
	}
	जर (!(val & O_NONBLOCK)) {
		debug3("fd %d is not O_NONBLOCK", fd);
		परत (0);
	}
	debug("fd %d clearing O_NONBLOCK", fd);
	val &= ~O_NONBLOCK;
	जर (fcntl(fd, F_SETFL, val) == -1) {
		debug("fcntl(%d, F_SETFL, ~O_NONBLOCK): %s",
		    fd, म_त्रुटि(त्रुटि_सं));
		परत (-1);
	}
	परत (0);
}

स्थिरांक अक्षर *
ssh_gai_strerror(पूर्णांक gaierr)
{
	जर (gaierr == EAI_SYSTEM && त्रुटि_सं != 0)
		परत म_त्रुटि(त्रुटि_सं);
	परत gai_strerror(gaierr);
}

/* disable nagle on socket */
शून्य
set_nodelay(पूर्णांक fd)
{
	पूर्णांक opt;
	socklen_t optlen;

	optlen = आकार opt;
	जर (getsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, &optlen) == -1) {
		debug("getsockopt TCP_NODELAY: %.100s", म_त्रुटि(त्रुटि_सं));
		परत;
	}
	जर (opt == 1) {
		debug2("fd %d is TCP_NODELAY", fd);
		परत;
	}
	opt = 1;
	debug2("fd %d setting TCP_NODELAY", fd);
	जर (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, आकार opt) == -1)
		error("setsockopt TCP_NODELAY: %.100s", म_त्रुटि(त्रुटि_सं));
}

/* Allow local port reuse in TIME_WAIT */
पूर्णांक
set_reuseaddr(पूर्णांक fd)
{
	पूर्णांक on = 1;

	जर (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, आकार(on)) == -1) {
		error("setsockopt SO_REUSEADDR fd %d: %s", fd, म_त्रुटि(त्रुटि_सं));
		परत -1;
	}
	परत 0;
}

/* Set TCP keepalives */
पूर्णांक
set_keepalive(पूर्णांक fd)
{
	पूर्णांक on = 1;

	जर (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, आकार(on)) == -1) {
		error("setsockopt SO_KEEPALIVE fd %d: %s", fd, म_त्रुटि(त्रुटि_सं));
		परत -1;
	}
	परत 0;
}

/* Get/set routing domain */
अक्षर *
get_rdomain(पूर्णांक fd)
{
#जर defined(HAVE_SYS_GET_RDOMAIN)
	परत sys_get_rdomain(fd);
#किंवाजर defined(__OpenBSD__)
	पूर्णांक rtable;
	अक्षर *ret;
	socklen_t len = आकार(rtable);

	जर (getsockopt(fd, SOL_SOCKET, SO_RTABLE, &rtable, &len) == -1) {
		error("Failed to get routing domain for fd %d: %s",
		    fd, म_त्रुटि(त्रुटि_सं));
		परत रिक्त;
	}
	xasprintf(&ret, "%d", rtable);
	परत ret;
#अन्यथा /* defined(__OpenBSD__) */
	परत रिक्त;
#endif
}

पूर्णांक
set_rdomain(पूर्णांक fd, स्थिरांक अक्षर *name)
{
#जर defined(HAVE_SYS_SET_RDOMAIN)
	परत sys_set_rdomain(fd, name);
#किंवाजर defined(__OpenBSD__)
	पूर्णांक rtable;
	स्थिरांक अक्षर *errstr;

	जर (name == रिक्त)
		परत 0; /* default table */

	rtable = (पूर्णांक)strtonum(name, 0, 255, &errstr);
	जर (errstr != रिक्त) {
		/* Shouldn't happen */
		error("Invalid routing domain \"%s\": %s", name, errstr);
		परत -1;
	}
	जर (setsockopt(fd, SOL_SOCKET, SO_RTABLE,
	    &rtable, आकार(rtable)) == -1) {
		error("Failed to set routing domain %d on fd %d: %s",
		    rtable, fd, म_त्रुटि(त्रुटि_सं));
		परत -1;
	}
	परत 0;
#अन्यथा /* defined(__OpenBSD__) */
	error("Setting routing domain is not supported on this platform");
	परत -1;
#endif
}

पूर्णांक
get_sock_af(पूर्णांक fd)
{
	संरचना sockaddr_storage to;
	socklen_t tolen = आकार(to);

	स_रखो(&to, 0, आकार(to));
	जर (getsockname(fd, (संरचना sockaddr *)&to, &tolen) == -1)
		परत -1;
#ifdef IPV4_IN_IPV6
	जर (to.ss_family == AF_INET6 &&
	    IN6_IS_ADDR_V4MAPPED(&((संरचना sockaddr_in6 *)&to)->sin6_addr))
		परत AF_INET;
#endif
	परत to.ss_family;
}

शून्य
set_sock_tos(पूर्णांक fd, पूर्णांक tos)
{
#ifndef IP_TOS_IS_BROKEN
	पूर्णांक af;

	जर (tos < 0 || tos == पूर्णांक_उच्च) {
		debug_f("invalid TOS %d", tos);
		परत;
	}
	निवड ((af = get_sock_af(fd))) {
	स्थिती -1:
		/* assume not a socket */
		थांबा;
	स्थिती AF_INET:
# ifdef IP_TOS
		debug3_f("set socket %d IP_TOS 0x%02x", fd, tos);
		जर (setsockopt(fd, IPPROTO_IP, IP_TOS,
		    &tos, आकार(tos)) == -1) {
			error("setsockopt socket %d IP_TOS %d: %s",
			    fd, tos, म_त्रुटि(त्रुटि_सं));
		}
# endif /* IP_TOS */
		थांबा;
	स्थिती AF_INET6:
# ifdef IPV6_TCLASS
		debug3_f("set socket %d IPV6_TCLASS 0x%02x", fd, tos);
		जर (setsockopt(fd, IPPROTO_IPV6, IPV6_TCLASS,
		    &tos, आकार(tos)) == -1) {
			error("setsockopt socket %d IPV6_TCLASS %d: %s",
			    fd, tos, म_त्रुटि(त्रुटि_सं));
		}
# endif /* IPV6_TCLASS */
		थांबा;
	पूर्वनिर्धारित:
		debug2_f("unsupported socket family %d", af);
		थांबा;
	}
#endif /* IP_TOS_IS_BROKEN */
}

/*
 * Wait up to *timeoutp milliseconds for events on fd. Updates
 * *timeoutp with time remaining.
 * Returns 0 if fd ready or -1 on timeout or error (see errno).
 */
स्थिर पूर्णांक
waitfd(पूर्णांक fd, पूर्णांक *timeoutp, लघु events, अस्थिर संक_पूर्ण_प्रकार *stop)
{
	संरचना pollfd pfd;
	संरचना timespec timeout;
	पूर्णांक oerrno, r;
	sigset_t nsigset, osigset;

	जर (timeoutp && *timeoutp == -1)
		timeoutp = रिक्त;
	pfd.fd = fd;
	pfd.events = events;
	ptimeout_init(&timeout);
	जर (timeoutp != रिक्त)
		ptimeout_deadline_ms(&timeout, *timeoutp);
	जर (stop != रिक्त)
		sigfillset(&nsigset);
	साठी (; timeoutp == रिक्त || *timeoutp >= 0;) {
		जर (stop != रिक्त) {
			sigprocmask(SIG_BLOCK, &nsigset, &osigset);
			जर (*stop) {
				sigprocmask(SIG_SETMASK, &osigset, रिक्त);
				त्रुटि_सं = EINTR;
				परत -1;
			}
		}
		r = ppoll(&pfd, 1, ptimeout_get_tsp(&timeout),
		    stop != रिक्त ? &osigset : रिक्त);
		oerrno = त्रुटि_सं;
		जर (stop != रिक्त)
			sigprocmask(SIG_SETMASK, &osigset, रिक्त);
		जर (timeoutp)
			*timeoutp = ptimeout_get_ms(&timeout);
		त्रुटि_सं = oerrno;
		जर (r > 0)
			परत 0;
		अन्यथा जर (r == -1 && त्रुटि_सं != EAGAIN && त्रुटि_सं != EINTR)
			परत -1;
		अन्यथा जर (r == 0)
			थांबा;
	}
	/* timeout */
	त्रुटि_सं = ETIMEDOUT;
	परत -1;
}

/*
 * Wait up to *timeoutp milliseconds for fd to be readable. Updates
 * *timeoutp with time remaining.
 * Returns 0 if fd ready or -1 on timeout or error (see errno).
 */
पूर्णांक
waitrfd(पूर्णांक fd, पूर्णांक *timeoutp, अस्थिर संक_पूर्ण_प्रकार *stop) {
	परत waitfd(fd, timeoutp, POLLIN, stop);
}

/*
 * Attempt a non-blocking connect(2) to the specified address, waiting up to
 * *timeoutp milliseconds for the connection to complete. If the timeout is
 * <=0, then wait indefinitely.
 *
 * Returns 0 on success or -1 on failure.
 */
पूर्णांक
timeout_connect(पूर्णांक sockfd, स्थिरांक संरचना sockaddr *serv_addr,
    socklen_t addrlen, पूर्णांक *timeoutp)
{
	पूर्णांक optval = 0;
	socklen_t optlen = आकार(optval);

	/* No timeout: just do a blocking connect() */
	जर (timeoutp == रिक्त || *timeoutp <= 0)
		परत connect(sockfd, serv_addr, addrlen);

	set_nonblock(sockfd);
	साठी (;;) {
		जर (connect(sockfd, serv_addr, addrlen) == 0) {
			/* Succeeded already? */
			unset_nonblock(sockfd);
			परत 0;
		} अन्यथा जर (त्रुटि_सं == EINTR)
			सुरूठेवा;
		अन्यथा जर (त्रुटि_सं != EINPROGRESS)
			परत -1;
		थांबा;
	}

	जर (waitfd(sockfd, timeoutp, POLLIN | POLLOUT, रिक्त) == -1)
		परत -1;

	/* Completed or failed */
	जर (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &optval, &optlen) == -1) {
		debug("getsockopt: %s", म_त्रुटि(त्रुटि_सं));
		परत -1;
	}
	जर (optval != 0) {
		त्रुटि_सं = optval;
		परत -1;
	}
	unset_nonblock(sockfd);
	परत 0;
}

/* Characters considered whitespace in strsep calls. */
#define WHITESPACE " \t\r\n"
#define QUOTE	"\""

/* return next token in configuration line */
स्थिर अक्षर *
strdelim_internal(अक्षर **s, पूर्णांक split_equals)
{
	अक्षर *old;
	पूर्णांक wspace = 0;

	जर (*s == रिक्त)
		परत रिक्त;

	old = *s;

	*s = strpbrk(*s,
	    split_equals ? WHITESPACE QUOTE "=" : WHITESPACE QUOTE);
	जर (*s == रिक्त)
		परत (old);

	जर (*s[0] == '\"') {
		स_हटाओ(*s, *s + 1, म_माप(*s)); /* move nul too */
		/* Find matching quote */
		जर ((*s = strpbrk(*s, QUOTE)) == रिक्त) {
			परत (रिक्त);		/* no matching quote */
		} अन्यथा {
			*s[0] = '\0';
			*s += म_अखोज(*s + 1, WHITESPACE) + 1;
			परत (old);
		}
	}

	/* Allow only one '=' to be skipped */
	जर (split_equals && *s[0] == '=')
		wspace = 1;
	*s[0] = '\0';

	/* Skip any extra whitespace after first token */
	*s += म_अखोज(*s + 1, WHITESPACE) + 1;
	जर (split_equals && *s[0] == '=' && !wspace)
		*s += म_अखोज(*s + 1, WHITESPACE) + 1;

	परत (old);
}

/*
 * Return next token in configuration line; splits on whitespace or a
 * single '=' character.
 */
अक्षर *
strdelim(अक्षर **s)
{
	परत strdelim_internal(s, 1);
}

/*
 * Return next token in configuration line; splits on whitespace only.
 */
अक्षर *
strdelimw(अक्षर **s)
{
	परत strdelim_internal(s, 0);
}

संरचना passwd *
pwcopy(संरचना passwd *pw)
{
	संरचना passwd *copy = xcalloc(1, आकार(*copy));

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
	परत copy;
}

शून्य
pwfree(संरचना passwd *pw)
{
	जर (pw == रिक्त)
		परत;
	मुक्त(pw->pw_name);
	freezero(pw->pw_passwd,
	    pw->pw_passwd == रिक्त ? 0 : म_माप(pw->pw_passwd));
#ifdef HAVE_STRUCT_PASSWD_PW_GECOS
	मुक्त(pw->pw_gecos);
#endif
#ifdef HAVE_STRUCT_PASSWD_PW_CLASS
	मुक्त(pw->pw_class);
#endif
	मुक्त(pw->pw_dir);
	मुक्त(pw->pw_shell);
	freezero(pw, आकार(*pw));
}

/*
 * Convert ASCII string to TCP/IP port number.
 * Port must be >=0 and <=65535.
 * Return -1 if invalid.
 */
पूर्णांक
a2port(स्थिरांक अक्षर *s)
{
	संरचना servent *se;
	दीर्घ दीर्घ port;
	स्थिरांक अक्षर *errstr;

	port = strtonum(s, 0, 65535, &errstr);
	जर (errstr == रिक्त)
		परत (पूर्णांक)port;
	जर ((se = getservbyname(s, "tcp")) != रिक्त)
		परत ntohs(se->s_port);
	परत -1;
}

पूर्णांक
a2tun(स्थिरांक अक्षर *s, पूर्णांक *remote)
{
	स्थिरांक अक्षर *errstr = रिक्त;
	अक्षर *sp, *ep;
	पूर्णांक tun;

	जर (remote != रिक्त) {
		*remote = SSH_TUNID_ANY;
		sp = xstrdup(s);
		जर ((ep = म_अक्षर(sp, ':')) == रिक्त) {
			मुक्त(sp);
			परत (a2tun(s, रिक्त));
		}
		ep[0] = '\0'; ep++;
		*remote = a2tun(ep, रिक्त);
		tun = a2tun(sp, रिक्त);
		मुक्त(sp);
		परत (*remote == SSH_TUNID_ERR ? *remote : tun);
	}

	जर (strcasecmp(s, "any") == 0)
		परत (SSH_TUNID_ANY);

	tun = strtonum(s, 0, SSH_TUNID_MAX, &errstr);
	जर (errstr != रिक्त)
		परत (SSH_TUNID_ERR);

	परत (tun);
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
convtime_double(स्थिरांक अक्षर *s)
{
	द्विगुण val, total_sec = 0.0, multiplier;
	स्थिरांक अक्षर *p, *start_p;
	अक्षर *endp;
	पूर्णांक seen_seconds = 0;

	जर (s == रिक्त || *s == '\0')
		परत -1.0;

	साठी (p = s; *p != '\0';) {
		जर (!है_अंक((अचिन्हित अक्षर)*p) && *p != '.')
			परत -1.0;

		त्रुटि_सं = 0;
		जर ((val = म_से_भग्न(p, &endp)) < 0 || त्रुटि_सं != 0 || p == endp)
			परत -1.0;
		/* Allow only decimal forms */
		जर (p + म_अखोज(p, "0123456789.") != endp)
			परत -1.0;
		start_p = p;
		p = endp;

		निवड (*p) {
		स्थिती '\0':
			/* FALLTHROUGH */
		स्थिती 's':
		स्थिती 'S':
			जर (seen_seconds++)
				परत -1.0;
			multiplier = SECONDS;
			थांबा;
		स्थिती 'm':
		स्थिती 'M':
			multiplier = MINUTES;
			थांबा;
		स्थिती 'h':
		स्थिती 'H':
			multiplier = HOURS;
			थांबा;
		स्थिती 'd':
		स्थिती 'D':
			multiplier = DAYS;
			थांबा;
		स्थिती 'w':
		स्थिती 'W':
			multiplier = WEEKS;
			थांबा;
		पूर्वनिर्धारित:
			परत -1.0;
		}

		/* Special handling if this was a decimal */
		जर (स_प्रथम(start_p, '.', endp - start_p) != रिक्त) {
			/* Decimal point present */
			जर (multiplier > 1.0)
				परत -1.0; /* No fractionals for non-seconds */
			/* For seconds, ensure digits follow */
			जर (!है_अंक((अचिन्हित अक्षर)*(endp - 1)))
				परत -1.0;
		}

		total_sec += val * multiplier;

		जर (*p != '\0')
			p++;
	}
	परत total_sec;
}

/*
 * Same as convtime_double() above but fractional seconds are ignored.
 * Return -1 if time string is invalid.
 */
पूर्णांक
convtime(स्थिरांक अक्षर *s)
{
	द्विगुण sec_val;

	जर ((sec_val = convtime_double(s)) < 0.0)
		परत -1;

	/* Check for overflow into int */
	जर (sec_val < 0 || sec_val > पूर्णांक_उच्च)
		परत -1;

	परत (पूर्णांक)sec_val;
}

#define TF_BUFS	8
#define TF_LEN	9

स्थिरांक अक्षर *
fmt_timeframe(समय_प्रकार t)
{
	अक्षर		*buf;
	स्थिर अक्षर	 tfbuf[TF_BUFS][TF_LEN];	/* ring buffer */
	स्थिर पूर्णांक	 idx = 0;
	अचिन्हित पूर्णांक	 sec, min, hrs, day;
	अचिन्हित दीर्घ दीर्घ	week;

	buf = tfbuf[idx++];
	जर (idx == TF_BUFS)
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

	जर (week > 0)
		snprintf(buf, TF_LEN, "%02lluw%01ud%02uh", week, day, hrs);
	अन्यथा जर (day > 0)
		snprintf(buf, TF_LEN, "%01ud%02uh%02um", day, hrs, min);
	अन्यथा
		snprintf(buf, TF_LEN, "%02u:%02u:%02u", hrs, min, sec);

	परत (buf);
}

/*
 * Returns a standardized host+port identifier string.
 * Caller must free returned string.
 */
अक्षर *
put_host_port(स्थिरांक अक्षर *host, u_short port)
{
	अक्षर *hoststr;

	जर (port == 0 || port == SSH_DEFAULT_PORT)
		परत(xstrdup(host));
	जर (asprintf(&hoststr, "[%s]:%d", host, (पूर्णांक)port) == -1)
		fatal("put_host_port: asprintf: %s", म_त्रुटि(त्रुटि_सं));
	debug3("put_host_port: %s", hoststr);
	परत hoststr;
}

/*
 * Search for next delimiter between hostnames/addresses and ports.
 * Argument may be modified (for termination).
 * Returns *cp if parsing succeeds.
 * *cp is set to the start of the next field, if one was found.
 * The delimiter char, if present, is stored in delim.
 * If this is the last field, *cp is set to NULL.
 */
अक्षर *
hpdelim2(अक्षर **cp, अक्षर *delim)
{
	अक्षर *s, *old;

	जर (cp == रिक्त || *cp == रिक्त)
		परत रिक्त;

	old = s = *cp;
	जर (*s == '[') {
		जर ((s = म_अक्षर(s, ']')) == रिक्त)
			परत रिक्त;
		अन्यथा
			s++;
	} अन्यथा जर ((s = strpbrk(s, ":/")) == रिक्त)
		s = *cp + म_माप(*cp); /* skip to end (see first case below) */

	निवड (*s) {
	स्थिती '\0':
		*cp = रिक्त;	/* no more fields*/
		थांबा;

	स्थिती ':':
	स्थिती '/':
		जर (delim != रिक्त)
			*delim = *s;
		*s = '\0';	/* terminate */
		*cp = s + 1;
		थांबा;

	पूर्वनिर्धारित:
		परत रिक्त;
	}

	परत old;
}

/* The common case: only accept colon as delimiter. */
अक्षर *
hpdelim(अक्षर **cp)
{
	अक्षर *r, delim = '\0';

	r =  hpdelim2(cp, &delim);
	जर (delim == '/')
		परत रिक्त;
	परत r;
}

अक्षर *
cleanhostname(अक्षर *host)
{
	जर (*host == '[' && host[म_माप(host) - 1] == ']') {
		host[म_माप(host) - 1] = '\0';
		परत (host + 1);
	} अन्यथा
		परत host;
}

अक्षर *
colon(अक्षर *cp)
{
	पूर्णांक flag = 0;

	जर (*cp == ':')		/* Leading colon is part of file name. */
		परत रिक्त;
	जर (*cp == '[')
		flag = 1;

	साठी (; *cp; ++cp) {
		जर (*cp == '@' && *(cp+1) == '[')
			flag = 1;
		जर (*cp == ']' && *(cp+1) == ':' && flag)
			परत (cp+1);
		जर (*cp == ':' && !flag)
			परत (cp);
		जर (*cp == '/')
			परत रिक्त;
	}
	परत रिक्त;
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
पूर्णांक
parse_user_host_path(स्थिरांक अक्षर *s, अक्षर **userp, अक्षर **hostp, अक्षर **pathp)
{
	अक्षर *user = रिक्त, *host = रिक्त, *path = रिक्त;
	अक्षर *sdup, *tmp;
	पूर्णांक ret = -1;

	जर (userp != रिक्त)
		*userp = रिक्त;
	जर (hostp != रिक्त)
		*hostp = रिक्त;
	जर (pathp != रिक्त)
		*pathp = रिक्त;

	sdup = xstrdup(s);

	/* Check for remote syntax: [user@]host:[path] */
	जर ((tmp = colon(sdup)) == रिक्त)
		जा out;

	/* Extract optional path */
	*tmp++ = '\0';
	जर (*tmp == '\0')
		tmp = ".";
	path = xstrdup(tmp);

	/* Extract optional user and mandatory host */
	tmp = म_खोजप(sdup, '@');
	जर (tmp != रिक्त) {
		*tmp++ = '\0';
		host = xstrdup(cleanhostname(tmp));
		जर (*sdup != '\0')
			user = xstrdup(sdup);
	} अन्यथा {
		host = xstrdup(cleanhostname(sdup));
		user = रिक्त;
	}

	/* Success */
	जर (userp != रिक्त) {
		*userp = user;
		user = रिक्त;
	}
	जर (hostp != रिक्त) {
		*hostp = host;
		host = रिक्त;
	}
	जर (pathp != रिक्त) {
		*pathp = path;
		path = रिक्त;
	}
	ret = 0;
out:
	मुक्त(sdup);
	मुक्त(user);
	मुक्त(host);
	मुक्त(path);
	परत ret;
}

/*
 * Parse a [user@]host[:port] string.
 * Caller must free returned user and host.
 * Any of the pointer return arguments may be NULL (useful for syntax checking).
 * If user was not specified then *userp will be set to NULL.
 * If port was not specified then *portp will be -1.
 * Returns 0 on success, -1 on failure.
 */
पूर्णांक
parse_user_host_port(स्थिरांक अक्षर *s, अक्षर **userp, अक्षर **hostp, पूर्णांक *portp)
{
	अक्षर *sdup, *cp, *tmp;
	अक्षर *user = रिक्त, *host = रिक्त;
	पूर्णांक port = -1, ret = -1;

	जर (userp != रिक्त)
		*userp = रिक्त;
	जर (hostp != रिक्त)
		*hostp = रिक्त;
	जर (portp != रिक्त)
		*portp = -1;

	जर ((sdup = tmp = strdup(s)) == रिक्त)
		परत -1;
	/* Extract optional username */
	जर ((cp = म_खोजप(tmp, '@')) != रिक्त) {
		*cp = '\0';
		जर (*tmp == '\0')
			जा out;
		जर ((user = strdup(tmp)) == रिक्त)
			जा out;
		tmp = cp + 1;
	}
	/* Extract mandatory hostname */
	जर ((cp = hpdelim(&tmp)) == रिक्त || *cp == '\0')
		जा out;
	host = xstrdup(cleanhostname(cp));
	/* Convert and verify optional port */
	जर (tmp != रिक्त && *tmp != '\0') {
		जर ((port = a2port(tmp)) <= 0)
			जा out;
	}
	/* Success */
	जर (userp != रिक्त) {
		*userp = user;
		user = रिक्त;
	}
	जर (hostp != रिक्त) {
		*hostp = host;
		host = रिक्त;
	}
	जर (portp != रिक्त)
		*portp = port;
	ret = 0;
 out:
	मुक्त(sdup);
	मुक्त(user);
	मुक्त(host);
	परत ret;
}

/*
 * Converts a two-byte hex string to decimal.
 * Returns the decimal value or -1 for invalid input.
 */
स्थिर पूर्णांक
hexchar(स्थिरांक अक्षर *s)
{
	अचिन्हित अक्षर result[2];
	पूर्णांक i;

	साठी (i = 0; i < 2; i++) {
		जर (s[i] >= '0' && s[i] <= '9')
			result[i] = (अचिन्हित अक्षर)(s[i] - '0');
		अन्यथा जर (s[i] >= 'a' && s[i] <= 'f')
			result[i] = (अचिन्हित अक्षर)(s[i] - 'a') + 10;
		अन्यथा जर (s[i] >= 'A' && s[i] <= 'F')
			result[i] = (अचिन्हित अक्षर)(s[i] - 'A') + 10;
		अन्यथा
			परत -1;
	}
	परत (result[0] << 4) | result[1];
}

/*
 * Decode an url-encoded string.
 * Returns a newly allocated string on success or NULL on failure.
 */
स्थिर अक्षर *
urldecode(स्थिरांक अक्षर *src)
{
	अक्षर *ret, *dst;
	पूर्णांक ch;
	माप_प्रकार srclen;

	जर ((srclen = म_माप(src)) >= SIZE_MAX)
		परत रिक्त;
	ret = xmalloc(srclen + 1);
	साठी (dst = ret; *src != '\0'; src++) {
		निवड (*src) {
		स्थिती '+':
			*dst++ = ' ';
			थांबा;
		स्थिती '%':
			/* note: don't allow \0 characters */
			जर (!है_षष्ठादशक((अचिन्हित अक्षर)src[1]) ||
			    !है_षष्ठादशक((अचिन्हित अक्षर)src[2]) ||
			    (ch = hexchar(src + 1)) == -1 || ch == 0) {
				मुक्त(ret);
				परत रिक्त;
			}
			*dst++ = ch;
			src += 2;
			थांबा;
		पूर्वनिर्धारित:
			*dst++ = *src;
			थांबा;
		}
	}
	*dst = '\0';

	परत ret;
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
पूर्णांक
parse_uri(स्थिरांक अक्षर *scheme, स्थिरांक अक्षर *uri, अक्षर **userp, अक्षर **hostp,
    पूर्णांक *portp, अक्षर **pathp)
{
	अक्षर *uridup, *cp, *tmp, ch;
	अक्षर *user = रिक्त, *host = रिक्त, *path = रिक्त;
	पूर्णांक port = -1, ret = -1;
	माप_प्रकार len;

	len = म_माप(scheme);
	जर (म_भेदन(uri, scheme, len) != 0 || म_भेदन(uri + len, "://", 3) != 0)
		परत 1;
	uri += len + 3;

	जर (userp != रिक्त)
		*userp = रिक्त;
	जर (hostp != रिक्त)
		*hostp = रिक्त;
	जर (portp != रिक्त)
		*portp = -1;
	जर (pathp != रिक्त)
		*pathp = रिक्त;

	uridup = tmp = xstrdup(uri);

	/* Extract optional ssh-info (username + connection params) */
	जर ((cp = म_अक्षर(tmp, '@')) != रिक्त) {
		अक्षर *delim;

		*cp = '\0';
		/* Extract username and connection params */
		जर ((delim = म_अक्षर(tmp, ';')) != रिक्त) {
			/* Just ignore connection params for now */
			*delim = '\0';
		}
		जर (*tmp == '\0') {
			/* Empty username */
			जा out;
		}
		जर ((user = urldecode(tmp)) == रिक्त)
			जा out;
		tmp = cp + 1;
	}

	/* Extract mandatory hostname */
	जर ((cp = hpdelim2(&tmp, &ch)) == रिक्त || *cp == '\0')
		जा out;
	host = xstrdup(cleanhostname(cp));
	जर (!valid_domain(host, 0, रिक्त))
		जा out;

	जर (tmp != रिक्त && *tmp != '\0') {
		जर (ch == ':') {
			/* Convert and verify port. */
			जर ((cp = म_अक्षर(tmp, '/')) != रिक्त)
				*cp = '\0';
			जर ((port = a2port(tmp)) <= 0)
				जा out;
			tmp = cp ? cp + 1 : रिक्त;
		}
		जर (tmp != रिक्त && *tmp != '\0') {
			/* Extract optional path */
			जर ((path = urldecode(tmp)) == रिक्त)
				जा out;
		}
	}

	/* Success */
	जर (userp != रिक्त) {
		*userp = user;
		user = रिक्त;
	}
	जर (hostp != रिक्त) {
		*hostp = host;
		host = रिक्त;
	}
	जर (portp != रिक्त)
		*portp = port;
	जर (pathp != रिक्त) {
		*pathp = path;
		path = रिक्त;
	}
	ret = 0;
 out:
	मुक्त(uridup);
	मुक्त(user);
	मुक्त(host);
	मुक्त(path);
	परत ret;
}

/* function to assist building execv() arguments */
शून्य
addargs(arglist *args, अक्षर *fmt, ...)
{
	बहु_सूची ap;
	अक्षर *cp;
	u_int nalloc;
	पूर्णांक r;

	बहु_शुरू(ap, fmt);
	r = vasprintf(&cp, fmt, ap);
	बहु_पूर्ण(ap);
	जर (r == -1)
		fatal_f("argument too long");

	nalloc = args->nalloc;
	जर (args->list == रिक्त) {
		nalloc = 32;
		args->अंक = 0;
	} अन्यथा जर (args->अंक > (256 * 1024))
		fatal_f("too many arguments");
	अन्यथा जर (args->अंक >= args->nalloc)
		fatal_f("arglist corrupt");
	अन्यथा जर (args->अंक+2 >= nalloc)
		nalloc *= 2;

	args->list = xrecallocarray(args->list, args->nalloc,
	    nalloc, आकार(अक्षर *));
	args->nalloc = nalloc;
	args->list[args->अंक++] = cp;
	args->list[args->अंक] = रिक्त;
}

शून्य
replacearg(arglist *args, u_int which, अक्षर *fmt, ...)
{
	बहु_सूची ap;
	अक्षर *cp;
	पूर्णांक r;

	बहु_शुरू(ap, fmt);
	r = vasprintf(&cp, fmt, ap);
	बहु_पूर्ण(ap);
	जर (r == -1)
		fatal_f("argument too long");
	जर (args->list == रिक्त || args->अंक >= args->nalloc)
		fatal_f("arglist corrupt");

	जर (which >= args->अंक)
		fatal_f("tried to replace invalid arg %d >= %d",
		    which, args->अंक);
	मुक्त(args->list[which]);
	args->list[which] = cp;
}

शून्य
freeargs(arglist *args)
{
	u_int i;

	जर (args == रिक्त)
		परत;
	जर (args->list != रिक्त && args->अंक < args->nalloc) {
		साठी (i = 0; i < args->अंक; i++)
			मुक्त(args->list[i]);
		मुक्त(args->list);
	}
	args->nalloc = args->अंक = 0;
	args->list = रिक्त;
}

/*
 * Expands tildes in the file name.  Returns data allocated by xmalloc.
 * Warning: this calls getpw*.
 */
पूर्णांक
tilde_expand(स्थिरांक अक्षर *filename, uid_t uid, अक्षर **retp)
{
	अक्षर *ocopy = रिक्त, *copy, *s = रिक्त;
	स्थिरांक अक्षर *path = रिक्त, *user = रिक्त;
	संरचना passwd *pw;
	माप_प्रकार len;
	पूर्णांक ret = -1, r, slash;

	*retp = रिक्त;
	जर (*filename != '~') {
		*retp = xstrdup(filename);
		परत 0;
	}
	ocopy = copy = xstrdup(filename + 1);

	जर (*copy == '\0')				/* ~ */
		path = रिक्त;
	अन्यथा जर (*copy == '/') {
		copy += म_अखोज(copy, "/");
		जर (*copy == '\0')
			path = रिक्त;			/* ~/ */
		अन्यथा
			path = copy;			/* ~/path */
	} अन्यथा {
		user = copy;
		जर ((path = म_अक्षर(copy, '/')) != रिक्त) {
			copy[path - copy] = '\0';
			path++;
			path += म_अखोज(path, "/");
			जर (*path == '\0')		/* ~user/ */
				path = रिक्त;
			/* else				 ~user/path */
		}
		/* else					~user */
	}
	जर (user != रिक्त) {
		जर ((pw = getpwnam(user)) == रिक्त) {
			error_f("No such user %s", user);
			जा out;
		}
	} अन्यथा जर ((pw = getpwuid(uid)) == रिक्त) {
		error_f("No such uid %ld", (दीर्घ)uid);
		जा out;
	}

	/* Make sure directory has a trailing '/' */
	slash = (len = म_माप(pw->pw_dir)) == 0 || pw->pw_dir[len - 1] != '/';

	जर ((r = xasprintf(&s, "%s%s%s", pw->pw_dir,
	    slash ? "/" : "", path != रिक्त ? path : "")) <= 0) {
		error_f("xasprintf failed");
		जा out;
	}
	जर (r >= PATH_MAX) {
		error_f("Path too long");
		जा out;
	}
	/* success */
	ret = 0;
	*retp = s;
	s = रिक्त;
 out:
	मुक्त(s);
	मुक्त(ocopy);
	परत ret;
}

अक्षर *
tilde_expand_filename(स्थिरांक अक्षर *filename, uid_t uid)
{
	अक्षर *ret;

	जर (tilde_expand(filename, uid, &ret) != 0)
		cleanup_exit(255);
	परत ret;
}

/*
 * Expand a string with a set of %[char] escapes and/or ${ENVIRONMENT}
 * substitutions.  A number of escapes may be specified as
 * (char *escape_chars, char *replacement) pairs. The list must be terminated
 * by a NULL escape_char. Returns replaced string in memory allocated by
 * xmalloc which the caller must free.
 */
स्थिर अक्षर *
vdollar_percent_expand(पूर्णांक *parseerror, पूर्णांक dollar, पूर्णांक percent,
    स्थिरांक अक्षर *string, बहु_सूची ap)
{
#define EXPAND_MAX_किल्ल्या	64
	u_int अंक_किल्ल्या = 0, i;
	संरचना {
		स्थिरांक अक्षर *किल्ली;
		स्थिरांक अक्षर *repl;
	} किल्ल्या[EXPAND_MAX_किल्ल्या];
	संरचना sshbuf *buf;
	पूर्णांक r, missingvar = 0;
	अक्षर *ret = रिक्त, *var, *varend, *val;
	माप_प्रकार len;

	जर ((buf = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	जर (parseerror == रिक्त)
		fatal_f("null parseerror arg");
	*parseerror = 1;

	/* Gather keys if we're doing percent expansion. */
	जर (percent) {
		साठी (अंक_किल्ल्या = 0; अंक_किल्ल्या < EXPAND_MAX_किल्ल्या; अंक_किल्ल्या++) {
			किल्ल्या[अंक_किल्ल्या].किल्ली = बहु_तर्क(ap, अक्षर *);
			जर (किल्ल्या[अंक_किल्ल्या].किल्ली == रिक्त)
				थांबा;
			किल्ल्या[अंक_किल्ल्या].repl = बहु_तर्क(ap, अक्षर *);
			जर (किल्ल्या[अंक_किल्ल्या].repl == रिक्त) {
				fatal_f("NULL replacement for token %s",
				    किल्ल्या[अंक_किल्ल्या].किल्ली);
			}
		}
		जर (अंक_किल्ल्या == EXPAND_MAX_किल्ल्या && बहु_तर्क(ap, अक्षर *) != रिक्त)
			fatal_f("too many keys");
		जर (अंक_किल्ल्या == 0)
			fatal_f("percent expansion without token list");
	}

	/* Expand string */
	साठी (i = 0; *string != '\0'; string++) {
		/* Optionally process ${ENVIRONMENT} expansions. */
		जर (dollar && string[0] == '$' && string[1] == '{') {
			string += 2;  /* skip over '${' */
			जर ((varend = म_अक्षर(string, '}')) == रिक्त) {
				error_f("environment variable '%s' missing "
				    "closing '}'", string);
				जा out;
			}
			len = varend - string;
			जर (len == 0) {
				error_f("zero-length environment variable");
				जा out;
			}
			var = xmalloc(len + 1);
			(शून्य)strlcpy(var, string, len + 1);
			जर ((val = दो_पर्या(var)) == रिक्त) {
				error_f("env var ${%s} has no value", var);
				missingvar = 1;
			} अन्यथा {
				debug3_f("expand ${%s} -> '%s'", var, val);
				जर ((r = sshbuf_put(buf, val, म_माप(val))) !=0)
					fatal_fr(r, "sshbuf_put ${}");
			}
			मुक्त(var);
			string += len;
			सुरूठेवा;
		}

		/*
		 * Process percent expansions if we have a list of TOKENs.
		 * If we're not doing percent expansion everything just gets
		 * appended here.
		 */
		जर (*string != '%' || !percent) {
 append:
			जर ((r = sshbuf_put_u8(buf, *string)) != 0)
				fatal_fr(r, "sshbuf_put_u8 %%");
			सुरूठेवा;
		}
		string++;
		/* %% case */
		जर (*string == '%')
			जा append;
		जर (*string == '\0') {
			error_f("invalid format");
			जा out;
		}
		साठी (i = 0; i < अंक_किल्ल्या; i++) {
			जर (म_अक्षर(किल्ल्या[i].किल्ली, *string) != रिक्त) {
				जर ((r = sshbuf_put(buf, किल्ल्या[i].repl,
				    म_माप(किल्ल्या[i].repl))) != 0)
					fatal_fr(r, "sshbuf_put %%-repl");
				थांबा;
			}
		}
		जर (i >= अंक_किल्ल्या) {
			error_f("unknown key %%%c", *string);
			जा out;
		}
	}
	जर (!missingvar && (ret = sshbuf_dup_string(buf)) == रिक्त)
		fatal_f("sshbuf_dup_string failed");
	*parseerror = 0;
 out:
	sshbuf_free(buf);
	परत *parseerror ? रिक्त : ret;
#undef EXPAND_MAX_किल्ल्या
}

/*
 * Expand only environment variables.
 * Note that although this function is variadic like the other similar
 * functions, any such arguments will be unused.
 */

अक्षर *
dollar_expand(पूर्णांक *parseerr, स्थिरांक अक्षर *string, ...)
{
	अक्षर *ret;
	पूर्णांक err;
	बहु_सूची ap;

	बहु_शुरू(ap, string);
	ret = vdollar_percent_expand(&err, 1, 0, string, ap);
	बहु_पूर्ण(ap);
	जर (parseerr != रिक्त)
		*parseerr = err;
	परत ret;
}

/*
 * Returns expanded string or NULL if a specified environment variable is
 * not defined, or calls fatal if the string is invalid.
 */
अक्षर *
percent_expand(स्थिरांक अक्षर *string, ...)
{
	अक्षर *ret;
	पूर्णांक err;
	बहु_सूची ap;

	बहु_शुरू(ap, string);
	ret = vdollar_percent_expand(&err, 0, 1, string, ap);
	बहु_पूर्ण(ap);
	जर (err)
		fatal_f("failed");
	परत ret;
}

/*
 * Returns expanded string or NULL if a specified environment variable is
 * not defined, or calls fatal if the string is invalid.
 */
अक्षर *
percent_dollar_expand(स्थिरांक अक्षर *string, ...)
{
	अक्षर *ret;
	पूर्णांक err;
	बहु_सूची ap;

	बहु_शुरू(ap, string);
	ret = vdollar_percent_expand(&err, 1, 1, string, ap);
	बहु_पूर्ण(ap);
	जर (err)
		fatal_f("failed");
	परत ret;
}

पूर्णांक
tun_open(पूर्णांक tun, पूर्णांक mode, अक्षर **ifname)
{
#जर defined(CUSTOM_SYS_TUN_OPEN)
	परत (sys_tun_open(tun, mode, ifname));
#किंवाजर defined(SSH_TUN_OPENBSD)
	संरचना ifreq ifr;
	अक्षर name[100];
	पूर्णांक fd = -1, sock;
	स्थिरांक अक्षर *tunbase = "tun";

	जर (ifname != रिक्त)
		*ifname = रिक्त;

	जर (mode == SSH_TUNMODE_ETHERNET)
		tunbase = "tap";

	/* Open the tunnel device */
	जर (tun <= SSH_TUNID_MAX) {
		snprintf(name, आकार(name), "/dev/%s%d", tunbase, tun);
		fd = खोलो(name, O_RDWR);
	} अन्यथा जर (tun == SSH_TUNID_ANY) {
		साठी (tun = 100; tun >= 0; tun--) {
			snprintf(name, आकार(name), "/dev/%s%d",
			    tunbase, tun);
			जर ((fd = खोलो(name, O_RDWR)) >= 0)
				थांबा;
		}
	} अन्यथा {
		debug_f("invalid tunnel %u", tun);
		परत -1;
	}

	जर (fd == -1) {
		debug_f("%s open: %s", name, म_त्रुटि(त्रुटि_सं));
		परत -1;
	}

	debug_f("%s mode %d fd %d", name, mode, fd);

	/* Bring interface up if it is not already */
	snprintf(ifr.ifr_name, आकार(ifr.ifr_name), "%s%d", tunbase, tun);
	जर ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
		जा failed;

	जर (ioctl(sock, SIOCGIFFLAGS, &ifr) == -1) {
		debug_f("get interface %s flags: %s", ifr.ifr_name,
		    म_त्रुटि(त्रुटि_सं));
		जा failed;
	}

	जर (!(ifr.ifr_flags & IFF_UP)) {
		ifr.ifr_flags |= IFF_UP;
		जर (ioctl(sock, SIOCSIFFLAGS, &ifr) == -1) {
			debug_f("activate interface %s: %s", ifr.ifr_name,
			    म_त्रुटि(त्रुटि_सं));
			जा failed;
		}
	}

	जर (ifname != रिक्त)
		*ifname = xstrdup(ifr.ifr_name);

	बंद(sock);
	परत fd;

 failed:
	जर (fd >= 0)
		बंद(fd);
	जर (sock >= 0)
		बंद(sock);
	परत -1;
#अन्यथा
	error("Tunnel interfaces are not supported on this platform");
	परत (-1);
#endif
}

शून्य
sanitise_stdfd(शून्य)
{
	पूर्णांक nullfd, dupfd;

	जर ((nullfd = dupfd = खोलो(_PATH_DEVNULL, O_RDWR)) == -1) {
		ख_लिखो(मानक_त्रुटि, "Couldn't open /dev/null: %s\n",
		    म_त्रुटि(त्रुटि_सं));
		निकास(1);
	}
	पर्यंत (++dupfd <= STDERR_FILENO) {
		/* Only populate closed fds. */
		जर (fcntl(dupfd, F_GETFL) == -1 && त्रुटि_सं == EBADF) {
			जर (dup2(nullfd, dupfd) == -1) {
				ख_लिखो(मानक_त्रुटि, "dup2: %s\n", म_त्रुटि(त्रुटि_सं));
				निकास(1);
			}
		}
	}
	जर (nullfd > STDERR_FILENO)
		बंद(nullfd);
}

अक्षर *
tohex(स्थिरांक शून्य *vp, माप_प्रकार l)
{
	स्थिरांक u_char *p = (स्थिरांक u_char *)vp;
	अक्षर b[3], *r;
	माप_प्रकार i, hl;

	जर (l > 65536)
		परत xstrdup("tohex: length > 65536");

	hl = l * 2 + 1;
	r = xcalloc(1, hl);
	साठी (i = 0; i < l; i++) {
		snprintf(b, आकार(b), "%02x", p[i]);
		strlcat(r, b, hl);
	}
	परत (r);
}

/*
 * Extend string *sp by the specified format. If *sp is not NULL (or empty),
 * then the separator 'sep' will be prepended before the formatted arguments.
 * Extended strings are heap allocated.
 */
शून्य
xextendf(अक्षर **sp, स्थिरांक अक्षर *sep, स्थिरांक अक्षर *fmt, ...)
{
	बहु_सूची ap;
	अक्षर *tmp1, *tmp2;

	बहु_शुरू(ap, fmt);
	xvasprintf(&tmp1, fmt, ap);
	बहु_पूर्ण(ap);

	जर (*sp == रिक्त || **sp == '\0') {
		मुक्त(*sp);
		*sp = tmp1;
		परत;
	}
	xasprintf(&tmp2, "%s%s%s", *sp, sep == रिक्त ? "" : sep, tmp1);
	मुक्त(tmp1);
	मुक्त(*sp);
	*sp = tmp2;
}


uint64_t
get_u64(स्थिरांक शून्य *vp)
{
	स्थिरांक u_char *p = (स्थिरांक u_char *)vp;
	uint64_t v;

	v  = (uint64_t)p[0] << 56;
	v |= (uint64_t)p[1] << 48;
	v |= (uint64_t)p[2] << 40;
	v |= (uint64_t)p[3] << 32;
	v |= (uint64_t)p[4] << 24;
	v |= (uint64_t)p[5] << 16;
	v |= (uint64_t)p[6] << 8;
	v |= (uint64_t)p[7];

	परत (v);
}

uint32_t
get_u32(स्थिरांक शून्य *vp)
{
	स्थिरांक u_char *p = (स्थिरांक u_char *)vp;
	uint32_t v;

	v  = (uint32_t)p[0] << 24;
	v |= (uint32_t)p[1] << 16;
	v |= (uint32_t)p[2] << 8;
	v |= (uint32_t)p[3];

	परत (v);
}

uint32_t
get_u32_le(स्थिरांक शून्य *vp)
{
	स्थिरांक u_char *p = (स्थिरांक u_char *)vp;
	uint32_t v;

	v  = (uint32_t)p[0];
	v |= (uint32_t)p[1] << 8;
	v |= (uint32_t)p[2] << 16;
	v |= (uint32_t)p[3] << 24;

	परत (v);
}

uint16_t
get_u16(स्थिरांक शून्य *vp)
{
	स्थिरांक u_char *p = (स्थिरांक u_char *)vp;
	uint16_t v;

	v  = (uint16_t)p[0] << 8;
	v |= (uint16_t)p[1];

	परत (v);
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
ms_subtract_diff(संरचना timeval *start, पूर्णांक *ms)
{
	संरचना timeval diff, finish;

	monotime_tv(&finish);
	timersub(&finish, start, &diff);
	*ms -= (diff.tv_sec * 1000) + (diff.tv_usec / 1000);
}

शून्य
ms_to_timespec(संरचना timespec *ts, पूर्णांक ms)
{
	जर (ms < 0)
		ms = 0;
	ts->tv_sec = ms / 1000;
	ts->tv_nsec = (ms % 1000) * 1000 * 1000;
}

शून्य
monotime_ts(संरचना timespec *ts)
{
	संरचना timeval tv;
#जर defined(HAVE_CLOCK_GETTIME) && (defined(CLOCK_BOOTTIME) || \
    defined(CLOCK_MONOTONIC) || defined(CLOCK_REALTIME))
	स्थिर पूर्णांक gettime_failed = 0;

	जर (!gettime_failed) {
# ifdef CLOCK_BOOTTIME
		जर (clock_gettime(CLOCK_BOOTTIME, ts) == 0)
			परत;
# endif /* CLOCK_BOOTTIME */
# ifdef CLOCK_MONOTONIC
		जर (clock_gettime(CLOCK_MONOTONIC, ts) == 0)
			परत;
# endif /* CLOCK_MONOTONIC */
# ifdef CLOCK_REALTIME
		/* Not monotonic, but we're almost out of options here. */
		जर (clock_gettime(CLOCK_REALTIME, ts) == 0)
			परत;
# endif /* CLOCK_REALTIME */
		debug3("clock_gettime: %s", म_त्रुटि(त्रुटि_सं));
		gettime_failed = 1;
	}
#endif /* HAVE_CLOCK_GETTIME && (BOOTTIME || MONOTONIC || REALTIME) */
	gettimeofday(&tv, रिक्त);
	ts->tv_sec = tv.tv_sec;
	ts->tv_nsec = (दीर्घ)tv.tv_usec * 1000;
}

शून्य
monotime_tv(संरचना timeval *tv)
{
	संरचना timespec ts;

	monotime_ts(&ts);
	tv->tv_sec = ts.tv_sec;
	tv->tv_usec = ts.tv_nsec / 1000;
}

समय_प्रकार
monotime(शून्य)
{
	संरचना timespec ts;

	monotime_ts(&ts);
	परत (ts.tv_sec);
}

द्विगुण
monotime_double(शून्य)
{
	संरचना timespec ts;

	monotime_ts(&ts);
	परत (द्विगुण)ts.tv_sec + (द्विगुण)ts.tv_nsec / 1000000000.0;
}

शून्य
bandwidth_limit_init(संरचना bwlimit *bw, uint64_t kbps, माप_प्रकार buflen)
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
bandwidth_limit(संरचना bwlimit *bw, माप_प्रकार read_len)
{
	uint64_t waitlen;
	संरचना timespec ts, rm;

	bw->lamt += read_len;
	जर (!timerisset(&bw->bwstart)) {
		monotime_tv(&bw->bwstart);
		परत;
	}
	जर (bw->lamt < bw->thresh)
		परत;

	monotime_tv(&bw->bwend);
	timersub(&bw->bwend, &bw->bwstart, &bw->bwend);
	जर (!timerisset(&bw->bwend))
		परत;

	bw->lamt *= 8;
	waitlen = (द्विगुण)1000000L * bw->lamt / bw->rate;

	bw->bwstart.tv_sec = waitlen / 1000000L;
	bw->bwstart.tv_usec = waitlen % 1000000L;

	जर (timercmp(&bw->bwstart, &bw->bwend, >)) {
		timersub(&bw->bwstart, &bw->bwend, &bw->bwend);

		/* Adjust the wait time */
		जर (bw->bwend.tv_sec) {
			bw->thresh /= 2;
			जर (bw->thresh < bw->buflen / 4)
				bw->thresh = bw->buflen / 4;
		} अन्यथा जर (bw->bwend.tv_usec < 10000) {
			bw->thresh *= 2;
			जर (bw->thresh > bw->buflen * 8)
				bw->thresh = bw->buflen * 8;
		}

		TIMEVAL_TO_TIMESPEC(&bw->bwend, &ts);
		पर्यंत (nanosleep(&ts, &rm) == -1) {
			जर (त्रुटि_सं != EINTR)
				थांबा;
			ts = rm;
		}
	}

	bw->lamt = 0;
	monotime_tv(&bw->bwstart);
}

/* Make a template filename for mk[sd]temp() */
शून्य
mktemp_proto(अक्षर *s, माप_प्रकार len)
{
	स्थिरांक अक्षर *tmpdir;
	पूर्णांक r;

	जर ((tmpdir = दो_पर्या("TMPDIR")) != रिक्त) {
		r = snprintf(s, len, "%s/ssh-XXXXXXXXXXXX", tmpdir);
		जर (r > 0 && (माप_प्रकार)r < len)
			परत;
	}
	r = snprintf(s, len, "/tmp/ssh-XXXXXXXXXXXX");
	जर (r < 0 || (माप_प्रकार)r >= len)
		fatal_f("template string too short");
}

स्थिर स्थिरांक संरचना {
	स्थिरांक अक्षर *name;
	पूर्णांक मूल्य;
} ipqos[] = {
	{ "none", पूर्णांक_उच्च },		/* can't use 0 here; that's CS0 */
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
	{ "lowdelay", पूर्णांक_न्यून },	/* deprecated */
	{ "throughput", पूर्णांक_न्यून },	/* deprecated */
	{ "reliability", पूर्णांक_न्यून },	/* deprecated */
	{ रिक्त, -1 }
};

पूर्णांक
parse_ipqos(स्थिरांक अक्षर *cp)
{
	स्थिरांक अक्षर *errstr;
	u_int i;
	पूर्णांक val;

	जर (cp == रिक्त)
		परत -1;
	साठी (i = 0; ipqos[i].name != रिक्त; i++) {
		जर (strcasecmp(cp, ipqos[i].name) == 0)
			परत ipqos[i].मूल्य;
	}
	/* Try parsing as an integer */
	val = (पूर्णांक)strtonum(cp, 0, 255, &errstr);
	जर (errstr)
		परत -1;
	परत val;
}

स्थिरांक अक्षर *
iptos2str(पूर्णांक iptos)
{
	पूर्णांक i;
	स्थिर अक्षर iptos_str[आकार "0xff"];

	साठी (i = 0; ipqos[i].name != रिक्त; i++) {
		जर (ipqos[i].मूल्य == iptos)
			परत ipqos[i].name;
	}
	snprintf(iptos_str, आकार iptos_str, "0x%02x", iptos);
	परत iptos_str;
}

शून्य
lowercase(अक्षर *s)
{
	साठी (; *s; s++)
		*s = छोटे((u_char)*s);
}

पूर्णांक
unix_listener(स्थिरांक अक्षर *path, पूर्णांक backlog, पूर्णांक unlink_first)
{
	संरचना sockaddr_un sunaddr;
	पूर्णांक saved_errno, sock;

	स_रखो(&sunaddr, 0, आकार(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	जर (strlcpy(sunaddr.sun_path, path,
	    आकार(sunaddr.sun_path)) >= आकार(sunaddr.sun_path)) {
		error_f("path \"%s\" too long for Unix domain socket", path);
		त्रुटि_सं = ENAMETOOLONG;
		परत -1;
	}

	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	जर (sock == -1) {
		saved_errno = त्रुटि_सं;
		error_f("socket: %.100s", म_त्रुटि(त्रुटि_सं));
		त्रुटि_सं = saved_errno;
		परत -1;
	}
	जर (unlink_first == 1) {
		जर (unlink(path) != 0 && त्रुटि_सं != ENOENT)
			error("unlink(%s): %.100s", path, म_त्रुटि(त्रुटि_सं));
	}
	जर (bind(sock, (संरचना sockaddr *)&sunaddr, आकार(sunaddr)) == -1) {
		saved_errno = त्रुटि_सं;
		error_f("cannot bind to path %s: %s", path, म_त्रुटि(त्रुटि_सं));
		बंद(sock);
		त्रुटि_सं = saved_errno;
		परत -1;
	}
	जर (listen(sock, backlog) == -1) {
		saved_errno = त्रुटि_सं;
		error_f("cannot listen on path %s: %s", path, म_त्रुटि(त्रुटि_सं));
		बंद(sock);
		unlink(path);
		त्रुटि_सं = saved_errno;
		परत -1;
	}
	परत sock;
}

शून्य
sock_set_v6only(पूर्णांक s)
{
#जर defined(IPV6_V6ONLY) && !defined(__OpenBSD__)
	पूर्णांक on = 1;

	debug3_f("set socket %d IPV6_V6ONLY", s);
	जर (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &on, आकार(on)) == -1)
		error("setsockopt IPV6_V6ONLY: %s", म_त्रुटि(त्रुटि_सं));
#endif
}

/*
 * Compares two strings that maybe be NULL. Returns non-zero if strings
 * are both NULL or are identical, returns zero otherwise.
 */
स्थिर पूर्णांक
strcmp_maybe_null(स्थिरांक अक्षर *a, स्थिरांक अक्षर *b)
{
	जर ((a == रिक्त && b != रिक्त) || (a != रिक्त && b == रिक्त))
		परत 0;
	जर (a != रिक्त && म_भेद(a, b) != 0)
		परत 0;
	परत 1;
}

/*
 * Compare two forwards, returning non-zero if they are identical or
 * zero otherwise.
 */
पूर्णांक
forward_equals(स्थिरांक संरचना Forward *a, स्थिरांक संरचना Forward *b)
{
	जर (strcmp_maybe_null(a->listen_host, b->listen_host) == 0)
		परत 0;
	जर (a->listen_port != b->listen_port)
		परत 0;
	जर (strcmp_maybe_null(a->listen_path, b->listen_path) == 0)
		परत 0;
	जर (strcmp_maybe_null(a->connect_host, b->connect_host) == 0)
		परत 0;
	जर (a->connect_port != b->connect_port)
		परत 0;
	जर (strcmp_maybe_null(a->connect_path, b->connect_path) == 0)
		परत 0;
	/* allocated_port and handle are not checked */
	परत 1;
}

/* returns port number, FWD_PERMIT_ANY_PORT or -1 on error */
पूर्णांक
permitopen_port(स्थिरांक अक्षर *p)
{
	पूर्णांक port;

	जर (म_भेद(p, "*") == 0)
		परत FWD_PERMIT_ANY_PORT;
	जर ((port = a2port(p)) > 0)
		परत port;
	परत -1;
}

/* returns 1 if process is already daemonized, 0 otherwise */
पूर्णांक
daemonized(शून्य)
{
	पूर्णांक fd;

	जर ((fd = खोलो(_PATH_TTY, O_RDONLY | O_NOCTTY)) >= 0) {
		बंद(fd);
		परत 0;	/* have controlling terminal */
	}
	जर (getppid() != 1)
		परत 0;	/* parent is not init */
	जर (getsid(0) != getpid())
		परत 0;	/* not session leader */
	debug3("already daemonized");
	परत 1;
}

/*
 * Splits 's' into an argument vector. Handles quoted string and basic
 * escape characters (\\, \", \'). Caller must free the argument vector
 * and its members.
 */
पूर्णांक
argv_split(स्थिरांक अक्षर *s, पूर्णांक *argcp, अक्षर ***argvp, पूर्णांक terminate_on_comment)
{
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;
	पूर्णांक argc = 0, quote, i, j;
	अक्षर *arg, **argv = xcalloc(1, आकार(*argv));

	*argvp = रिक्त;
	*argcp = 0;

	साठी (i = 0; s[i] != '\0'; i++) {
		/* Skip leading whitespace */
		जर (s[i] == ' ' || s[i] == '\t')
			सुरूठेवा;
		जर (terminate_on_comment && s[i] == '#')
			थांबा;
		/* Start of a token */
		quote = 0;

		argv = xreallocarray(argv, (argc + 2), आकार(*argv));
		arg = argv[argc++] = xcalloc(1, म_माप(s + i) + 1);
		argv[argc] = रिक्त;

		/* Copy the token in, removing escapes */
		साठी (j = 0; s[i] != '\0'; i++) {
			जर (s[i] == '\\') {
				जर (s[i + 1] == '\'' ||
				    s[i + 1] == '\"' ||
				    s[i + 1] == '\\' ||
				    (quote == 0 && s[i + 1] == ' ')) {
					i++; /* Skip '\' */
					arg[j++] = s[i];
				} अन्यथा {
					/* Unrecognised escape */
					arg[j++] = s[i];
				}
			} अन्यथा जर (quote == 0 && (s[i] == ' ' || s[i] == '\t'))
				थांबा; /* done */
			अन्यथा जर (quote == 0 && (s[i] == '\"' || s[i] == '\''))
				quote = s[i]; /* quote start */
			अन्यथा जर (quote != 0 && s[i] == quote)
				quote = 0; /* quote end */
			अन्यथा
				arg[j++] = s[i];
		}
		जर (s[i] == '\0') {
			जर (quote != 0) {
				/* Ran out of string looking for close quote */
				r = SSH_ERR_INVALID_FORMAT;
				जा out;
			}
			थांबा;
		}
	}
	/* Success */
	*argcp = argc;
	*argvp = argv;
	argc = 0;
	argv = रिक्त;
	r = 0;
 out:
	जर (argc != 0 && argv != रिक्त) {
		साठी (i = 0; i < argc; i++)
			मुक्त(argv[i]);
		मुक्त(argv);
	}
	परत r;
}

/*
 * Reassemble an argument vector into a string, quoting and escaping as
 * necessary. Caller must free returned string.
 */
अक्षर *
argv_assemble(पूर्णांक argc, अक्षर **argv)
{
	पूर्णांक i, j, ws, r;
	अक्षर c, *ret;
	संरचना sshbuf *buf, *arg;

	जर ((buf = sshbuf_new()) == रिक्त || (arg = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");

	साठी (i = 0; i < argc; i++) {
		ws = 0;
		sshbuf_reset(arg);
		साठी (j = 0; argv[i][j] != '\0'; j++) {
			r = 0;
			c = argv[i][j];
			निवड (c) {
			स्थिती ' ':
			स्थिती '\t':
				ws = 1;
				r = sshbuf_put_u8(arg, c);
				थांबा;
			स्थिती '\\':
			स्थिती '\'':
			स्थिती '"':
				जर ((r = sshbuf_put_u8(arg, '\\')) != 0)
					थांबा;
				/* FALLTHROUGH */
			पूर्वनिर्धारित:
				r = sshbuf_put_u8(arg, c);
				थांबा;
			}
			जर (r != 0)
				fatal_fr(r, "sshbuf_put_u8");
		}
		जर ((i != 0 && (r = sshbuf_put_u8(buf, ' ')) != 0) ||
		    (ws != 0 && (r = sshbuf_put_u8(buf, '"')) != 0) ||
		    (r = sshbuf_putb(buf, arg)) != 0 ||
		    (ws != 0 && (r = sshbuf_put_u8(buf, '"')) != 0))
			fatal_fr(r, "assemble");
	}
	जर ((ret = दो_स्मृति(sshbuf_len(buf) + 1)) == रिक्त)
		fatal_f("malloc failed");
	स_नकल(ret, sshbuf_ptr(buf), sshbuf_len(buf));
	ret[sshbuf_len(buf)] = '\0';
	sshbuf_free(buf);
	sshbuf_free(arg);
	परत ret;
}

अक्षर *
argv_next(पूर्णांक *argcp, अक्षर ***argvp)
{
	अक्षर *ret = (*argvp)[0];

	जर (*argcp > 0 && ret != रिक्त) {
		(*argcp)--;
		(*argvp)++;
	}
	परत ret;
}

शून्य
argv_consume(पूर्णांक *argcp)
{
	*argcp = 0;
}

शून्य
argv_free(अक्षर **av, पूर्णांक ac)
{
	पूर्णांक i;

	जर (av == रिक्त)
		परत;
	साठी (i = 0; i < ac; i++)
		मुक्त(av[i]);
	मुक्त(av);
}

/* Returns 0 if pid exited cleanly, non-zero otherwise */
पूर्णांक
exited_cleanly(pid_t pid, स्थिरांक अक्षर *tag, स्थिरांक अक्षर *cmd, पूर्णांक quiet)
{
	पूर्णांक status;

	पर्यंत (waitpid(pid, &status, 0) == -1) {
		जर (त्रुटि_सं != EINTR) {
			error("%s waitpid: %s", tag, म_त्रुटि(त्रुटि_सं));
			परत -1;
		}
	}
	जर (WIFSIGNALED(status)) {
		error("%s %s exited on signal %d", tag, cmd, WTERMSIG(status));
		परत -1;
	} अन्यथा जर (WEXITSTATUS(status) != 0) {
		do_log2(quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_INFO,
		    "%s %s failed, status %d", tag, cmd, WEXITSTATUS(status));
		परत -1;
	}
	परत 0;
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
पूर्णांक
safe_path(स्थिरांक अक्षर *name, संरचना stat *stp, स्थिरांक अक्षर *pw_dir,
    uid_t uid, अक्षर *err, माप_प्रकार errlen)
{
	अक्षर buf[PATH_MAX], buf2[PATH_MAX], homedir[PATH_MAX];
	अक्षर *cp;
	पूर्णांक comparehome = 0;
	संरचना stat st;

	जर (realpath(name, buf) == रिक्त) {
		snprintf(err, errlen, "realpath %s failed: %s", name,
		    म_त्रुटि(त्रुटि_सं));
		परत -1;
	}
	जर (pw_dir != रिक्त && realpath(pw_dir, homedir) != रिक्त)
		comparehome = 1;

	जर (!S_ISREG(stp->st_mode)) {
		snprintf(err, errlen, "%s is not a regular file", buf);
		परत -1;
	}
	जर ((!platform_sys_dir_uid(stp->st_uid) && stp->st_uid != uid) ||
	    (stp->st_mode & 022) != 0) {
		snprintf(err, errlen, "bad ownership or modes for file %s",
		    buf);
		परत -1;
	}

	/* for each component of the canonical path, walking upwards */
	साठी (;;) {
		/*
		 * POSIX allows dirname to modify its argument and return a
		 * pointer into it, so make a copy to avoid overlapping strlcpy.
		 */
		strlcpy(buf2, buf, आकार(buf2));
		जर ((cp = स_नाम(buf2)) == रिक्त) {
			snprintf(err, errlen, "dirname() failed");
			परत -1;
		}
		strlcpy(buf, cp, आकार(buf));

		जर (stat(buf, &st) == -1 ||
		    (!platform_sys_dir_uid(st.st_uid) && st.st_uid != uid) ||
		    (st.st_mode & 022) != 0) {
			snprintf(err, errlen,
			    "bad ownership or modes for directory %s", buf);
			परत -1;
		}

		/* If are past the homedir then we can stop */
		जर (comparehome && म_भेद(homedir, buf) == 0)
			थांबा;

		/*
		 * dirname should always complete with a "/" path,
		 * but we can be paranoid and check for "." too
		 */
		जर ((म_भेद("/", buf) == 0) || (म_भेद(".", buf) == 0))
			थांबा;
	}
	परत 0;
}

/*
 * Version of safe_path() that accepts an open file descriptor to
 * avoid races.
 *
 * Returns 0 on success and -1 on failure
 */
पूर्णांक
safe_path_fd(पूर्णांक fd, स्थिरांक अक्षर *file, संरचना passwd *pw,
    अक्षर *err, माप_प्रकार errlen)
{
	संरचना stat st;

	/* check the open file to avoid races */
	जर (ख_स्थिति(fd, &st) == -1) {
		snprintf(err, errlen, "cannot stat file %s: %s",
		    file, म_त्रुटि(त्रुटि_सं));
		परत -1;
	}
	परत safe_path(file, &st, pw->pw_dir, pw->pw_uid, err, errlen);
}

/*
 * Sets the value of the given variable in the environment.  If the variable
 * already exists, its value is overridden.
 */
शून्य
child_set_env(अक्षर ***envp, u_int *envsizep, स्थिरांक अक्षर *name,
	स्थिरांक अक्षर *मूल्य)
{
	अक्षर **env;
	u_int envsize;
	u_int i, namelen;

	जर (म_अक्षर(name, '=') != रिक्त) {
		error("Invalid environment variable \"%.100s\"", name);
		परत;
	}

	/*
	 * If we're passed an uninitialized list, allocate a single null
	 * entry before continuing.
	 */
	जर ((*envp == रिक्त) != (*envsizep == 0))
		fatal_f("environment size mismatch");
	जर (*envp == रिक्त && *envsizep == 0) {
		*envp = xmalloc(आकार(अक्षर *));
		*envp[0] = रिक्त;
		*envsizep = 1;
	}

	/*
	 * Find the slot where the value should be stored.  If the variable
	 * already exists, we reuse the slot; otherwise we append a new slot
	 * at the end of the array, expanding if necessary.
	 */
	env = *envp;
	namelen = म_माप(name);
	साठी (i = 0; env[i]; i++)
		जर (म_भेदन(env[i], name, namelen) == 0 && env[i][namelen] == '=')
			थांबा;
	जर (env[i]) {
		/* Reuse the slot. */
		मुक्त(env[i]);
	} अन्यथा {
		/* New variable.  Expand if necessary. */
		envsize = *envsizep;
		जर (i >= envsize - 1) {
			जर (envsize >= 1000)
				fatal("child_set_env: too many env vars");
			envsize += 50;
			env = (*envp) = xreallocarray(env, envsize, आकार(अक्षर *));
			*envsizep = envsize;
		}
		/* Need to set the NULL pointer at end of array beyond the new slot. */
		env[i + 1] = रिक्त;
	}

	/* Allocate space and format the variable in the appropriate slot. */
	/* XXX xasprintf */
	env[i] = xmalloc(म_माप(name) + 1 + म_माप(मूल्य) + 1);
	snprintf(env[i], म_माप(name) + 1 + म_माप(मूल्य) + 1, "%s=%s", name, मूल्य);
}

/*
 * Check and optionally lowercase a domain name, also removes trailing '.'
 * Returns 1 on success and 0 on failure, storing an error message in errstr.
 */
पूर्णांक
valid_domain(अक्षर *name, पूर्णांक makelower, स्थिरांक अक्षर **errstr)
{
	माप_प्रकार i, l = म_माप(name);
	u_char c, last = '\0';
	स्थिर अक्षर errbuf[256];

	जर (l == 0) {
		strlcpy(errbuf, "empty domain name", आकार(errbuf));
		जा bad;
	}
	जर (!है_अक्षर((u_char)name[0]) && !है_अंक((u_char)name[0]) &&
	   name[0] != '_' /* technically invalid, but common */) {
		snprintf(errbuf, आकार(errbuf), "domain name \"%.100s\" "
		    "starts with invalid character", name);
		जा bad;
	}
	साठी (i = 0; i < l; i++) {
		c = छोटे((u_char)name[i]);
		जर (makelower)
			name[i] = (अक्षर)c;
		जर (last == '.' && c == '.') {
			snprintf(errbuf, आकार(errbuf), "domain name "
			    "\"%.100s\" contains consecutive separators", name);
			जा bad;
		}
		जर (c != '.' && c != '-' && !है_अक्षर_अंक(c) &&
		    c != '_') /* technically invalid, but common */ {
			snprintf(errbuf, आकार(errbuf), "domain name "
			    "\"%.100s\" contains invalid characters", name);
			जा bad;
		}
		last = c;
	}
	जर (name[l - 1] == '.')
		name[l - 1] = '\0';
	जर (errstr != रिक्त)
		*errstr = रिक्त;
	परत 1;
bad:
	जर (errstr != रिक्त)
		*errstr = errbuf;
	परत 0;
}

/*
 * Verify that a environment variable name (not including initial '$') is
 * valid; consisting of one or more alphanumeric or underscore characters only.
 * Returns 1 on valid, 0 otherwise.
 */
पूर्णांक
valid_env_name(स्थिरांक अक्षर *name)
{
	स्थिरांक अक्षर *cp;

	जर (name[0] == '\0')
		परत 0;
	साठी (cp = name; *cp != '\0'; cp++) {
		जर (!है_अक्षर_अंक((u_char)*cp) && *cp != '_')
			परत 0;
	}
	परत 1;
}

स्थिरांक अक्षर *
atoi_err(स्थिरांक अक्षर *nptr, पूर्णांक *val)
{
	स्थिरांक अक्षर *errstr = रिक्त;

	जर (nptr == रिक्त || *nptr == '\0')
		परत "missing";
	*val = strtonum(nptr, 0, पूर्णांक_उच्च, &errstr);
	परत errstr;
}

पूर्णांक
parse_absolute_time(स्थिरांक अक्षर *s, uint64_t *tp)
{
	संरचना पंचांग पंचांग;
	समय_प्रकार tt;
	अक्षर buf[32], *fmt;
	स्थिरांक अक्षर *cp;
	माप_प्रकार l;
	पूर्णांक is_utc = 0;

	*tp = 0;

	l = म_माप(s);
	जर (l > 1 && strcasecmp(s + l - 1, "Z") == 0) {
		is_utc = 1;
		l--;
	} अन्यथा जर (l > 3 && strcasecmp(s + l - 3, "UTC") == 0) {
		is_utc = 1;
		l -= 3;
	}
	/*
	 * POSIX strptime says "The application shall ensure that there
	 * is white-space or other non-alphanumeric characters between
	 * any two conversion specifications" so arrange things this way.
	 */
	निवड (l) {
	स्थिती 8: /* YYYYMMDD */
		fmt = "%Y-%m-%d";
		snprintf(buf, आकार(buf), "%.4s-%.2s-%.2s", s, s + 4, s + 6);
		थांबा;
	स्थिती 12: /* YYYYMMDDHHMM */
		fmt = "%Y-%m-%dT%H:%M";
		snprintf(buf, आकार(buf), "%.4s-%.2s-%.2sT%.2s:%.2s",
		    s, s + 4, s + 6, s + 8, s + 10);
		थांबा;
	स्थिती 14: /* YYYYMMDDHHMMSS */
		fmt = "%Y-%m-%dT%H:%M:%S";
		snprintf(buf, आकार(buf), "%.4s-%.2s-%.2sT%.2s:%.2s:%.2s",
		    s, s + 4, s + 6, s + 8, s + 10, s + 12);
		थांबा;
	पूर्वनिर्धारित:
		परत SSH_ERR_INVALID_FORMAT;
	}

	स_रखो(&पंचांग, 0, आकार(पंचांग));
	जर ((cp = strptime(buf, fmt, &पंचांग)) == रिक्त || *cp != '\0')
		परत SSH_ERR_INVALID_FORMAT;
	जर (is_utc) {
		पंचांग.tm_wday = -1;	/* sentinel for error */
		जर ((tt = timegm(&पंचांग)) == -1 && पंचांग.tm_wday == -1)
			परत SSH_ERR_INVALID_FORMAT;
	} अन्यथा {
		पंचांग.tm_wday = -1;	/* sentinel for error */
		पंचांग.tm_isdst = -1;	/* mktime decides DST */
		जर ((tt = स_गढ़ो(&पंचांग)) == -1 && पंचांग.tm_wday == -1)
			परत SSH_ERR_INVALID_FORMAT;
	}
	/* success */
	*tp = (uint64_t)tt;
	परत 0;
}

शून्य
format_absolute_time(uint64_t t, अक्षर *buf, माप_प्रकार len)
{
	समय_प्रकार tt = t > SSH_TIME_T_MAX ? SSH_TIME_T_MAX : t;
	संरचना पंचांग पंचांग;

	जर (localtime_r(&tt, &पंचांग) == रिक्त)
		strlcpy(buf, "UNKNOWN-TIME", len);
	अन्यथा
		स_माला(buf, len, "%Y-%m-%dT%H:%M:%S", &पंचांग);
}

/*
 * Parse a "pattern=interval" clause (e.g. a ChannelTimeout).
 * Returns 0 on success or non-zero on failure.
 * Caller must free *typep.
 */
पूर्णांक
parse_pattern_interval(स्थिरांक अक्षर *s, अक्षर **typep, द्विगुण *secsp)
{
	अक्षर *cp, *sdup;
	द्विगुण secs;

	जर (typep != रिक्त)
		*typep = रिक्त;
	जर (secsp != रिक्त)
		*secsp = 0;
	जर (s == रिक्त)
		परत -1;
	sdup = xstrdup(s);

	जर ((cp = म_अक्षर(sdup, '=')) == रिक्त || cp == sdup) {
		मुक्त(sdup);
		परत -1;
	}
	*cp++ = '\0';
	जर ((secs = convtime_double(cp)) < 0.0) {
		मुक्त(sdup);
		परत -1;
	}
	/* success */
	जर (typep != रिक्त)
		*typep = xstrdup(sdup);
	जर (secsp != रिक्त)
		*secsp = secs;
	मुक्त(sdup);
	परत 0;
}

/* check if path is absolute */
पूर्णांक
path_absolute(स्थिरांक अक्षर *path)
{
	परत (*path == '/') ? 1 : 0;
}

शून्य
skip_space(अक्षर **cpp)
{
	अक्षर *cp;

	साठी (cp = *cpp; *cp == ' ' || *cp == '\t'; cp++)
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
पूर्णांक
opt_flag(स्थिरांक अक्षर *opt, पूर्णांक allow_negate, स्थिरांक अक्षर **optsp)
{
	माप_प्रकार opt_len = म_माप(opt);
	स्थिरांक अक्षर *opts = *optsp;
	पूर्णांक negate = 0;

	जर (allow_negate && strncasecmp(opts, "no-", 3) == 0) {
		opts += 3;
		negate = 1;
	}
	जर (strncasecmp(opts, opt, opt_len) == 0) {
		*optsp = opts + opt_len;
		परत negate ? 0 : 1;
	}
	परत -1;
}

अक्षर *
opt_dequote(स्थिरांक अक्षर **sp, स्थिरांक अक्षर **errstrp)
{
	स्थिरांक अक्षर *s = *sp;
	अक्षर *ret;
	माप_प्रकार i;

	*errstrp = रिक्त;
	जर (*s != '"') {
		*errstrp = "missing start quote";
		परत रिक्त;
	}
	s++;
	जर ((ret = दो_स्मृति(म_माप((s)) + 1)) == रिक्त) {
		*errstrp = "memory allocation failed";
		परत रिक्त;
	}
	साठी (i = 0; *s != '\0' && *s != '"';) {
		जर (s[0] == '\\' && s[1] == '"')
			s++;
		ret[i++] = *s++;
	}
	जर (*s == '\0') {
		*errstrp = "missing end quote";
		मुक्त(ret);
		परत रिक्त;
	}
	ret[i] = '\0';
	s++;
	*sp = s;
	परत ret;
}

पूर्णांक
opt_match(स्थिरांक अक्षर **opts, स्थिरांक अक्षर *term)
{
	जर (strncasecmp((*opts), term, म_माप(term)) == 0 &&
	    (*opts)[म_माप(term)] == '=') {
		*opts += म_माप(term) + 1;
		परत 1;
	}
	परत 0;
}

शून्य
opt_array_append2(स्थिरांक अक्षर *file, स्थिरांक पूर्णांक ओळ, स्थिरांक अक्षर *directive,
    अक्षर ***array, पूर्णांक **iarray, u_int *lp, स्थिरांक अक्षर *s, पूर्णांक i)
{

	जर (*lp >= पूर्णांक_उच्च)
		fatal("%s line %d: Too many %s entries", file, ओळ, directive);

	जर (iarray != रिक्त) {
		*iarray = xrecallocarray(*iarray, *lp, *lp + 1,
		    आकार(**iarray));
		(*iarray)[*lp] = i;
	}

	*array = xrecallocarray(*array, *lp, *lp + 1, आकार(**array));
	(*array)[*lp] = xstrdup(s);
	(*lp)++;
}

शून्य
opt_array_append(स्थिरांक अक्षर *file, स्थिरांक पूर्णांक ओळ, स्थिरांक अक्षर *directive,
    अक्षर ***array, u_int *lp, स्थिरांक अक्षर *s)
{
	opt_array_append2(file, ओळ, directive, array, रिक्त, lp, s, 0);
}

शून्य
opt_array_free2(अक्षर **array, पूर्णांक **iarray, u_int l)
{
	u_int i;

	जर (array == रिक्त || l == 0)
		परत;
	साठी (i = 0; i < l; i++)
		मुक्त(array[i]);
	मुक्त(array);
	मुक्त(iarray);
}

sshsig_t
ssh_signal(पूर्णांक signum, sshsig_t handler)
{
	संरचना sigaction sa, osa;

	/* mask all other signals while in handler */
	स_रखो(&sa, 0, आकार(sa));
	sa.sa_handler = handler;
	sigfillset(&sa.sa_mask);
#जर defined(SA_RESTART) && !defined(NO_SA_RESTART)
	जर (signum != SIGALRM)
		sa.sa_flags = SA_RESTART;
#endif
	जर (sigaction(signum, &sa, &osa) == -1) {
		debug3("sigaction(%s): %s", strsignal(signum), म_त्रुटि(त्रुटि_सं));
		परत संक_त्रुटि;
	}
	परत osa.sa_handler;
}

पूर्णांक
stdfd_devnull(पूर्णांक do_stdin, पूर्णांक do_stdout, पूर्णांक do_stderr)
{
	पूर्णांक devnull, ret = 0;

	जर ((devnull = खोलो(_PATH_DEVNULL, O_RDWR)) == -1) {
		error_f("open %s: %s", _PATH_DEVNULL,
		    म_त्रुटि(त्रुटि_सं));
		परत -1;
	}
	जर ((do_stdin && dup2(devnull, STDIN_FILENO) == -1) ||
	    (do_stdout && dup2(devnull, STDOUT_FILENO) == -1) ||
	    (do_stderr && dup2(devnull, STDERR_FILENO) == -1)) {
		error_f("dup2: %s", म_त्रुटि(त्रुटि_सं));
		ret = -1;
	}
	जर (devnull > STDERR_FILENO)
		बंद(devnull);
	परत ret;
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
subprocess(स्थिरांक अक्षर *tag, स्थिरांक अक्षर *command,
    पूर्णांक ac, अक्षर **av, खाता **child, u_int flags,
    संरचना passwd *pw, privdrop_fn *drop_privs, privrestore_fn *restore_privs)
{
	खाता *f = रिक्त;
	संरचना stat st;
	पूर्णांक fd, devnull, p[2], i;
	pid_t pid;
	अक्षर *cp, errmsg[512];
	u_int nenv = 0;
	अक्षर **env = रिक्त;

	/* If dropping privs, then must specify user and restore function */
	जर (drop_privs != रिक्त && (pw == रिक्त || restore_privs == रिक्त)) {
		error("%s: inconsistent arguments", tag); /* XXX fatal? */
		परत 0;
	}
	जर (pw == रिक्त && (pw = getpwuid(getuid())) == रिक्त) {
		error("%s: no user for current uid", tag);
		परत 0;
	}
	जर (child != रिक्त)
		*child = रिक्त;

	debug3_f("%s command \"%s\" running as %s (flags 0x%x)",
	    tag, command, pw->pw_name, flags);

	/* Check consistency */
	जर ((flags & SSH_SUBPROCESS_STDOUT_DISCARD) != 0 &&
	    (flags & SSH_SUBPROCESS_STDOUT_CAPTURE) != 0) {
		error_f("inconsistent flags");
		परत 0;
	}
	जर (((flags & SSH_SUBPROCESS_STDOUT_CAPTURE) == 0) != (child == रिक्त)) {
		error_f("inconsistent flags/output");
		परत 0;
	}

	/*
	 * If executing an explicit binary, then verify the it exists
	 * and appears safe-ish to execute
	 */
	जर (!path_absolute(av[0])) {
		error("%s path is not absolute", tag);
		परत 0;
	}
	जर (drop_privs != रिक्त)
		drop_privs(pw);
	जर (stat(av[0], &st) == -1) {
		error("Could not stat %s \"%s\": %s", tag,
		    av[0], म_त्रुटि(त्रुटि_सं));
		जा restore_return;
	}
	जर ((flags & SSH_SUBPROCESS_UNSAFE_PATH) == 0 &&
	    safe_path(av[0], &st, रिक्त, 0, errmsg, आकार(errmsg)) != 0) {
		error("Unsafe %s \"%s\": %s", tag, av[0], errmsg);
		जा restore_return;
	}
	/* Prepare to keep the child's stdout if requested */
	जर (pipe(p) == -1) {
		error("%s: pipe: %s", tag, म_त्रुटि(त्रुटि_सं));
 restore_return:
		जर (restore_privs != रिक्त)
			restore_privs();
		परत 0;
	}
	जर (restore_privs != रिक्त)
		restore_privs();

	निवड ((pid = विभाजन())) {
	स्थिती -1: /* error */
		error("%s: fork: %s", tag, म_त्रुटि(त्रुटि_सं));
		बंद(p[0]);
		बंद(p[1]);
		परत 0;
	स्थिती 0: /* child */
		/* Prepare a minimal environment for the child. */
		जर ((flags & SSH_SUBPROCESS_PRESERVE_ENV) == 0) {
			nenv = 5;
			env = xcalloc(आकार(*env), nenv);
			child_set_env(&env, &nenv, "PATH", _PATH_STDPATH);
			child_set_env(&env, &nenv, "USER", pw->pw_name);
			child_set_env(&env, &nenv, "LOGNAME", pw->pw_name);
			child_set_env(&env, &nenv, "HOME", pw->pw_dir);
			जर ((cp = दो_पर्या("LANG")) != रिक्त)
				child_set_env(&env, &nenv, "LANG", cp);
		}

		साठी (i = 1; i < NSIG; i++)
			ssh_signal(i, संक_पूर्व);

		जर ((devnull = खोलो(_PATH_DEVNULL, O_RDWR)) == -1) {
			error("%s: open %s: %s", tag, _PATH_DEVNULL,
			    म_त्रुटि(त्रुटि_सं));
			_exit(1);
		}
		जर (dup2(devnull, STDIN_FILENO) == -1) {
			error("%s: dup2: %s", tag, म_त्रुटि(त्रुटि_सं));
			_exit(1);
		}

		/* Set up stdout as requested; leave stderr in place for now. */
		fd = -1;
		जर ((flags & SSH_SUBPROCESS_STDOUT_CAPTURE) != 0)
			fd = p[1];
		अन्यथा जर ((flags & SSH_SUBPROCESS_STDOUT_DISCARD) != 0)
			fd = devnull;
		जर (fd != -1 && dup2(fd, STDOUT_FILENO) == -1) {
			error("%s: dup2: %s", tag, म_त्रुटि(त्रुटि_सं));
			_exit(1);
		}
		closefrom(STDERR_FILENO + 1);

		जर (geteuid() == 0 &&
		    initgroups(pw->pw_name, pw->pw_gid) == -1) {
			error("%s: initgroups(%s, %u): %s", tag,
			    pw->pw_name, (u_int)pw->pw_gid, म_त्रुटि(त्रुटि_सं));
			_exit(1);
		}
		जर (setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) == -1) {
			error("%s: setresgid %u: %s", tag, (u_int)pw->pw_gid,
			    म_त्रुटि(त्रुटि_सं));
			_exit(1);
		}
		जर (setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) == -1) {
			error("%s: setresuid %u: %s", tag, (u_int)pw->pw_uid,
			    म_त्रुटि(त्रुटि_सं));
			_exit(1);
		}
		/* stdin is pointed to /dev/null at this point */
		जर ((flags & SSH_SUBPROCESS_STDOUT_DISCARD) != 0 &&
		    dup2(STDIN_FILENO, STDERR_FILENO) == -1) {
			error("%s: dup2: %s", tag, म_त्रुटि(त्रुटि_सं));
			_exit(1);
		}
		जर (env != रिक्त)
			execve(av[0], av, env);
		अन्यथा
			execv(av[0], av);
		error("%s %s \"%s\": %s", tag, env == रिक्त ? "execv" : "execve",
		    command, म_त्रुटि(त्रुटि_सं));
		_exit(127);
	पूर्वनिर्धारित: /* parent */
		थांबा;
	}

	बंद(p[1]);
	जर ((flags & SSH_SUBPROCESS_STDOUT_CAPTURE) == 0)
		बंद(p[0]);
	अन्यथा जर ((f = fdopen(p[0], "r")) == रिक्त) {
		error("%s: fdopen: %s", tag, म_त्रुटि(त्रुटि_सं));
		बंद(p[0]);
		/* Don't leave zombie child */
		समाप्त(pid, संक_इति);
		पर्यंत (waitpid(pid, रिक्त, 0) == -1 && त्रुटि_सं == EINTR)
			;
		परत 0;
	}
	/* Success */
	debug3_f("%s pid %ld", tag, (दीर्घ)pid);
	जर (child != रिक्त)
		*child = f;
	परत pid;
}

स्थिरांक अक्षर *
lookup_env_in_list(स्थिरांक अक्षर *env, अक्षर * स्थिरांक *envs, माप_प्रकार nenvs)
{
	माप_प्रकार i, envlen;

	envlen = म_माप(env);
	साठी (i = 0; i < nenvs; i++) {
		जर (म_भेदन(envs[i], env, envlen) == 0 &&
		    envs[i][envlen] == '=') {
			परत envs[i] + envlen + 1;
		}
	}
	परत रिक्त;
}

स्थिरांक अक्षर *
lookup_setenv_in_list(स्थिरांक अक्षर *env, अक्षर * स्थिरांक *envs, माप_प्रकार nenvs)
{
	अक्षर *name, *cp;
	स्थिरांक अक्षर *ret;

	name = xstrdup(env);
	जर ((cp = म_अक्षर(name, '=')) == रिक्त) {
		मुक्त(name);
		परत रिक्त; /* not env=val */
	}
	*cp = '\0';
	ret = lookup_env_in_list(name, envs, nenvs);
	मुक्त(name);
	परत ret;
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
ptimeout_deadline_sec(संरचना timespec *pt, दीर्घ sec)
{
	जर (pt->tv_sec == -1 || pt->tv_sec >= sec) {
		pt->tv_sec = sec;
		pt->tv_nsec = 0;
	}
}

/* Specify a poll/ppoll deadline of at most 'p' (timespec) */
स्थिर शून्य
ptimeout_deadline_tsp(संरचना timespec *pt, संरचना timespec *p)
{
	जर (pt->tv_sec == -1 || timespeccmp(pt, p, >=))
		*pt = *p;
}

/* Specify a poll/ppoll deadline of at most 'ms' milliseconds */
शून्य
ptimeout_deadline_ms(संरचना timespec *pt, दीर्घ ms)
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

	स_रखो(&t, 0, आकार(t));
	जर ((int64_t)sec >= SSH_TIME_T_MAX)
		t.tv_sec = SSH_TIME_T_MAX;
	अन्यथा जर (sec > 0) {
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

	जर (timespeccmp(&now, when, >=)) {
		/* 'when' is now or in the past. Timeout ASAP */
		pt->tv_sec = 0;
		pt->tv_nsec = 0;
	} अन्यथा {
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
ptimeout_deadline_monotime(संरचना timespec *pt, समय_प्रकार when)
{
	संरचना timespec t;

	t.tv_sec = when;
	t.tv_nsec = 0;
	ptimeout_deadline_monotime_tsp(pt, &t);
}

/* Get a poll(2) timeout value in milliseconds */
पूर्णांक
ptimeout_get_ms(संरचना timespec *pt)
{
	जर (pt->tv_sec == -1)
		परत -1;
	जर (pt->tv_sec >= (पूर्णांक_उच्च - (pt->tv_nsec / 1000000)) / 1000)
		परत पूर्णांक_उच्च;
	परत (pt->tv_sec * 1000) + (pt->tv_nsec / 1000000);
}

/* Get a ppoll(2) timeout value as a timespec pointer */
संरचना timespec *
ptimeout_get_tsp(संरचना timespec *pt)
{
	परत pt->tv_sec == -1 ? रिक्त : pt;
}

/* Returns non-zero if a timeout has been set (i.e. is not indefinite) */
पूर्णांक
ptimeout_isset(संरचना timespec *pt)
{
	परत pt->tv_sec != -1;
}

/*
 * Returns zero if the library at 'path' contains symbol 's', nonzero
 * otherwise.
 */
पूर्णांक
lib_contains_चिन्ह(स्थिरांक अक्षर *path, स्थिरांक अक्षर *s)
{
#ifdef HAVE_NLIST
	संरचना nlist nl[2];
	पूर्णांक ret = -1, r;

	स_रखो(nl, 0, आकार(nl));
	nl[0].n_name = xstrdup(s);
	nl[1].n_name = रिक्त;
	जर ((r = nlist(path, nl)) == -1) {
		error_f("nlist failed for %s", path);
		जा out;
	}
	जर (r != 0 || nl[0].n_मूल्य == 0 || nl[0].n_type == 0) {
		error_f("library %s does not contain symbol %s", path, s);
		जा out;
	}
	/* success */
	ret = 0;
 out:
	मुक्त(nl[0].n_name);
	परत ret;
#अन्यथा /* HAVE_NLIST */
	पूर्णांक fd, ret = -1;
	संरचना stat st;
	शून्य *m = रिक्त;
	माप_प्रकार sz = 0;

	स_रखो(&st, 0, आकार(st));
	जर ((fd = खोलो(path, O_RDONLY)) < 0) {
		error_f("open %s: %s", path, म_त्रुटि(त्रुटि_सं));
		परत -1;
	}
	जर (ख_स्थिति(fd, &st) != 0) {
		error_f("fstat %s: %s", path, म_त्रुटि(त्रुटि_सं));
		जा out;
	}
	जर (!S_ISREG(st.st_mode)) {
		error_f("%s is not a regular file", path);
		जा out;
	}
	जर (st.st_size < 0 ||
	    (माप_प्रकार)st.st_size < म_माप(s) ||
	    st.st_size >= पूर्णांक_उच्च/2) {
		error_f("%s bad size %lld", path, (दीर्घ दीर्घ)st.st_size);
		जा out;
	}
	sz = (माप_प्रकार)st.st_size;
	जर ((m = mmap(रिक्त, sz, PROT_READ, MAP_PRIVATE, fd, 0)) == MAP_FAILED ||
	    m == रिक्त) {
		error_f("mmap %s: %s", path, म_त्रुटि(त्रुटि_सं));
		जा out;
	}
	जर (memmem(m, sz, s, म_माप(s)) == रिक्त) {
		error_f("%s does not contain expected string %s", path, s);
		जा out;
	}
	/* success */
	ret = 0;
 out:
	जर (m != रिक्त && m != MAP_FAILED)
		munmap(m, sz);
	बंद(fd);
	परत ret;
#endif /* HAVE_NLIST */
}

पूर्णांक
signal_is_crash(पूर्णांक sig)
{
	निवड (sig) {
	स्थिती संक_अंश:
	स्थिती SIGBUS:
	स्थिती SIGTRAP:
	स्थिती SIGSYS:
	स्थिती संक_भ_त्रुटि:
	स्थिती संक_अवैध:
	स्थिती SIGABRT:
		परत 1;
	}
	परत 0;
}

अक्षर *
get_homedir(शून्य)
{
	अक्षर *cp;
	संरचना passwd *pw;

	जर ((cp = दो_पर्या("HOME")) != रिक्त && *cp != '\0')
		परत xstrdup(cp);

	जर ((pw = getpwuid(getuid())) != रिक्त && *pw->pw_dir != '\0')
		परत xstrdup(pw->pw_dir);

	परत रिक्त;
}

पूर्णांक
mkdir_path(स्थिरांक अक्षर *target, mode_t mode)
{
#जर defined(HAVE_OPENAT) && defined(O_DIRECTORY)
	अक्षर *dir, *odir = रिक्त, *next;
	पूर्णांक fd = AT_FDCWD, fd2, subpath_len, ret = -1;

	dir = odir = xstrdup(target);

	जर (*dir == '/' &&
	    (fd = खोलो("/", O_RDONLY|O_DIRECTORY)) == -1) {
		error_f("open(\"/\"): %s", म_त्रुटि(त्रुटि_सं));
		मुक्त(odir);
		परत -1;
	}
	/* Work through the path, component-wise */
	साठी (; dir != रिक्त && *dir != '\0'; dir = next) {
		जर ((next = म_अक्षर(dir, '/')) != रिक्त)
			*(next++) = '\0';
		जर (*dir == '\0')
			सुरूठेवा;
		subpath_len = (next == रिक्त) ? पूर्णांक_उच्च : next - odir - 1;
		जर (mkdirat(fd, dir, mode) == 0)
			debug_f("created directory %.*s", subpath_len, target);
		अन्यथा जर (त्रुटि_सं != EEXIST) {
			error_f("mkdir(\"%.*s\"): %s",
			    subpath_len, target, म_त्रुटि(त्रुटि_सं));
			जा out;
		}

		/* descend */
		जर ((fd2 = openat(fd, dir, O_RDONLY|O_DIRECTORY)) == -1) {
			error_f("open(\"%.*s\"): %s",
			    subpath_len, target, म_त्रुटि(त्रुटि_सं));
			जा out;
		}
		जर (fd != AT_FDCWD)
			बंद(fd);
		fd = fd2;
	}
	/* success */
	ret = 0;
 out:
	मुक्त(odir);
	जर (fd != AT_FDCWD)
		बंद(fd);
	परत ret;
#अन्यथा
	/*
	 * If we don't have openat (which was added in POSIX.1-2008), fall back
	 * to the possibly racy way.
	 */
	अक्षर *dir, *odir, *p, path[PATH_MAX] = "";
	पूर्णांक ret = -1;
	माप_प्रकार plen = आकार(path);

	dir = odir = xstrdup(target);

	/* If the dir is relative, start with cwd. */
	जर (*dir != '/' && getcwd(path, plen) == रिक्त) {
		error_f("getcwd: %s", म_त्रुटि(त्रुटि_सं));
		जा out;
	}

	/* Work through the path, component-wise */
	पर्यंत ((p = strsep(&dir, "/"))) {
		जर (*p == '\0')
			सुरूठेवा;
		जर (strlcat(path, "/", plen) >= plen ||
		    strlcat(path, p, plen) >= plen)
			जा out;
		जर (सूची_गढ़ो(path, mode) == 0)
			debug_f("created directory %s", path);
		अन्यथा जर (त्रुटि_सं != EEXIST && त्रुटि_सं != EISDIR) {
			error_f("mkdir(\"%s\"): %s", path, म_त्रुटि(त्रुटि_सं));
			जा out;
		}
	}
	/* success */
	ret = 0;
 out:
	मुक्त(odir);
	परत ret;
#endif
}
