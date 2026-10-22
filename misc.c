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


#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <sys/ioctl.h>
#समावेश <sys/mman.h>
#समावेश <sys/socket.h>
#समावेश <sys/stat.h>
#समावेश <sys/time.h>
#समावेश <sys/wait.h>
#समावेश <sys/un.h>

#समावेश <limits.h>
#समावेश <libgen.h>
#समावेश <poll.h>
#समावेश <nlist.h>
#समावेश <signal.h>
#समावेश <stdarg.h>
#समावेश <stdio.h>
#समावेश <stdint.h>
#समावेश <stdlib.h>
#समावेश <string.h>
#समावेश <time.h>
#समावेश <unistd.h>

#समावेश <netinet/in.h>
#समावेश <netinet/ip.h>
#समावेश <netinet/tcp.h>
#समावेश <arpa/inet.h>

#समावेश <ctype.h>
#समावेश <errno.h>
#समावेश <fcntl.h>
#समावेश <netdb.h>
#समावेश <paths.h>
#समावेश <pwd.h>
#समावेश <grp.h>
#अगर_घोषित SSH_TUN_OPENBSD
#समावेश <net/if.h>
#पूर्ण_अगर

#समावेश "xmalloc.h"
#समावेश "misc.h"
#समावेश "log.h"
#समावेश "ssh.h"
#समावेश "sshbuf.h"
#समावेश "ssherr.h"
#समावेश "platform.h"

/* remove newline at end of string */
अक्षर *
chop(अक्षर *s)
{
	अक्षर *t = s;
	जबतक (*t) {
		अगर (*t == '\n' || *t == '\r') {
			*t = '\0';
			वापस s;
		}
		t++;
	}
	वापस s;

}

/* remove whitespace from end of string */
व्योम
rtrim(अक्षर *s)
{
	माप_प्रकार i;

	अगर ((i = म_माप(s)) == 0)
		वापस;
	करो {
		i--;
		अगर (है_खाली((अचिन्हित अक्षर)s[i]))
			s[i] = '\0';
		अन्यथा
			अवरोध;
	} जबतक (i > 0);
}

/*
 * returns pointer to character after 'prefix' in 's' or otherwise NULL
 * if the prefix is not present.
 */
स्थिर अक्षर *
strprefix(स्थिर अक्षर *s, स्थिर अक्षर *prefix, पूर्णांक ignorecase)
{
	माप_प्रकार prefixlen;

	अगर ((prefixlen = म_माप(prefix)) == 0)
		वापस s;
	अगर (ignorecase) {
		अगर (strncasecmp(s, prefix, prefixlen) != 0)
			वापस शून्य;
	} अन्यथा {
		अगर (म_भेदन(s, prefix, prefixlen) != 0)
			वापस शून्य;
	}
	वापस s + prefixlen;
}

/* Append string 's' to a NULL-terminated array of strings */
व्योम
stringlist_append(अक्षर ***listp, स्थिर अक्षर *s)
{
	माप_प्रकार i = 0;

	अगर (*listp == शून्य)
		*listp = xcalloc(2, माप(**listp));
	अन्यथा {
		क्रम (i = 0; (*listp)[i] != शून्य; i++)
			; /* count */
		*listp = xrecallocarray(*listp, i + 1, i + 2, माप(**listp));
	}
	(*listp)[i] = xstrdup(s);
}

व्योम
stringlist_free(अक्षर **list)
{
	माप_प्रकार i = 0;

	अगर (list == शून्य)
		वापस;
	क्रम (i = 0; list[i] != शून्य; i++)
		मुक्त(list[i]);
	मुक्त(list);
}

/* set/unset filedescriptor to non-blocking */
पूर्णांक
set_nonblock(पूर्णांक fd)
{
	पूर्णांक val;

	val = fcntl(fd, F_GETFL);
	अगर (val == -1) {
		error("fcntl(%d, F_GETFL): %s", fd, म_त्रुटि(त्रुटि_सं));
		वापस (-1);
	}
	अगर (val & O_NONBLOCK) {
		debug3("fd %d is O_NONBLOCK", fd);
		वापस (0);
	}
	debug2("fd %d setting O_NONBLOCK", fd);
	val |= O_NONBLOCK;
	अगर (fcntl(fd, F_SETFL, val) == -1) {
		debug("fcntl(%d, F_SETFL, O_NONBLOCK): %s", fd,
		    म_त्रुटि(त्रुटि_सं));
		वापस (-1);
	}
	वापस (0);
}

पूर्णांक
unset_nonblock(पूर्णांक fd)
{
	पूर्णांक val;

	val = fcntl(fd, F_GETFL);
	अगर (val == -1) {
		error("fcntl(%d, F_GETFL): %s", fd, म_त्रुटि(त्रुटि_सं));
		वापस (-1);
	}
	अगर (!(val & O_NONBLOCK)) {
		debug3("fd %d is not O_NONBLOCK", fd);
		वापस (0);
	}
	debug("fd %d clearing O_NONBLOCK", fd);
	val &= ~O_NONBLOCK;
	अगर (fcntl(fd, F_SETFL, val) == -1) {
		debug("fcntl(%d, F_SETFL, ~O_NONBLOCK): %s",
		    fd, म_त्रुटि(त्रुटि_सं));
		वापस (-1);
	}
	वापस (0);
}

स्थिर अक्षर *
ssh_gai_strerror(पूर्णांक gaierr)
{
	अगर (gaierr == EAI_SYSTEM && त्रुटि_सं != 0)
		वापस म_त्रुटि(त्रुटि_सं);
	वापस gai_strerror(gaierr);
}

/* disable nagle on socket */
व्योम
set_nodelay(पूर्णांक fd)
{
	पूर्णांक opt;
	socklen_t optlen;

	optlen = माप opt;
	अगर (getsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, &optlen) == -1) {
		debug("getsockopt TCP_NODELAY: %.100s", म_त्रुटि(त्रुटि_सं));
		वापस;
	}
	अगर (opt == 1) {
		debug2("fd %d is TCP_NODELAY", fd);
		वापस;
	}
	opt = 1;
	debug2("fd %d setting TCP_NODELAY", fd);
	अगर (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, माप opt) == -1)
		error("setsockopt TCP_NODELAY: %.100s", म_त्रुटि(त्रुटि_सं));
}

/* Allow local port reuse in TIME_WAIT */
पूर्णांक
set_reuseaddr(पूर्णांक fd)
{
	पूर्णांक on = 1;

	अगर (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, माप(on)) == -1) {
		error("setsockopt SO_REUSEADDR fd %d: %s", fd, म_त्रुटि(त्रुटि_सं));
		वापस -1;
	}
	वापस 0;
}

/* Set TCP keepalives */
पूर्णांक
set_keepalive(पूर्णांक fd)
{
	पूर्णांक on = 1;

	अगर (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, माप(on)) == -1) {
		error("setsockopt SO_KEEPALIVE fd %d: %s", fd, म_त्रुटि(त्रुटि_सं));
		वापस -1;
	}
	वापस 0;
}

/* Get/set routing domain */
अक्षर *
get_rdomain(पूर्णांक fd)
{
#अगर defined(HAVE_SYS_GET_RDOMAIN)
	वापस sys_get_rdomain(fd);
#या_अगर defined(__OpenBSD__)
	पूर्णांक rtable;
	अक्षर *ret;
	socklen_t len = माप(rtable);

	अगर (getsockopt(fd, SOL_SOCKET, SO_RTABLE, &rtable, &len) == -1) {
		error("Failed to get routing domain for fd %d: %s",
		    fd, म_त्रुटि(त्रुटि_सं));
		वापस शून्य;
	}
	xasprintf(&ret, "%d", rtable);
	वापस ret;
#अन्यथा /* defined(__OpenBSD__) */
	वापस शून्य;
#पूर्ण_अगर
}

पूर्णांक
set_rdomain(पूर्णांक fd, स्थिर अक्षर *name)
{
#अगर defined(HAVE_SYS_SET_RDOMAIN)
	वापस sys_set_rdomain(fd, name);
#या_अगर defined(__OpenBSD__)
	पूर्णांक rtable;
	स्थिर अक्षर *errstr;

	अगर (name == शून्य)
		वापस 0; /* default table */

	rtable = (पूर्णांक)strtonum(name, 0, 255, &errstr);
	अगर (errstr != शून्य) {
		/* Shouldn't happen */
		error("Invalid routing domain \"%s\": %s", name, errstr);
		वापस -1;
	}
	अगर (setsockopt(fd, SOL_SOCKET, SO_RTABLE,
	    &rtable, माप(rtable)) == -1) {
		error("Failed to set routing domain %d on fd %d: %s",
		    rtable, fd, म_त्रुटि(त्रुटि_सं));
		वापस -1;
	}
	वापस 0;
#अन्यथा /* defined(__OpenBSD__) */
	error("Setting routing domain is not supported on this platform");
	वापस -1;
#पूर्ण_अगर
}

पूर्णांक
get_sock_af(पूर्णांक fd)
{
	काष्ठा sockaddr_storage to;
	socklen_t tolen = माप(to);

	स_रखो(&to, 0, माप(to));
	अगर (getsockname(fd, (काष्ठा sockaddr *)&to, &tolen) == -1)
		वापस -1;
#अगर_घोषित IPV4_IN_IPV6
	अगर (to.ss_family == AF_INET6 &&
	    IN6_IS_ADDR_V4MAPPED(&((काष्ठा sockaddr_in6 *)&to)->sin6_addr))
		वापस AF_INET;
#पूर्ण_अगर
	वापस to.ss_family;
}

व्योम
set_sock_tos(पूर्णांक fd, पूर्णांक tos)
{
#अगर_अघोषित IP_TOS_IS_BROKEN
	पूर्णांक af;

	अगर (tos < 0 || tos == पूर्णांक_उच्च) {
		debug_f("invalid TOS %d", tos);
		वापस;
	}
	चयन ((af = get_sock_af(fd))) {
	हाल -1:
		/* assume not a socket */
		अवरोध;
	हाल AF_INET:
# ifdef IP_TOS
		debug3_f("set socket %d IP_TOS 0x%02x", fd, tos);
		अगर (setsockopt(fd, IPPROTO_IP, IP_TOS,
		    &tos, माप(tos)) == -1) {
			error("setsockopt socket %d IP_TOS %d: %s",
			    fd, tos, म_त्रुटि(त्रुटि_सं));
		}
# endif /* IP_TOS */
		अवरोध;
	हाल AF_INET6:
# ifdef IPV6_TCLASS
		debug3_f("set socket %d IPV6_TCLASS 0x%02x", fd, tos);
		अगर (setsockopt(fd, IPPROTO_IPV6, IPV6_TCLASS,
		    &tos, माप(tos)) == -1) {
			error("setsockopt socket %d IPV6_TCLASS %d: %s",
			    fd, tos, म_त्रुटि(त्रुटि_सं));
		}
# endif /* IPV6_TCLASS */
		अवरोध;
	शेष:
		debug2_f("unsupported socket family %d", af);
		अवरोध;
	}
#पूर्ण_अगर /* IP_TOS_IS_BROKEN */
}

/*
 * Wait up to *timeoutp milliseconds for events on fd. Updates
 * *timeoutp with time remaining.
 * Returns 0 if fd ready or -1 on timeout or error (see errno).
 */
अटल पूर्णांक
waitfd(पूर्णांक fd, पूर्णांक *timeoutp, लघु events, अस्थिर संक_पूर्ण_प्रकार *stop)
{
	काष्ठा pollfd pfd;
	काष्ठा timespec timeout;
	पूर्णांक oerrno, r;
	sigset_t nsigset, osigset;

	अगर (timeoutp && *timeoutp == -1)
		timeoutp = शून्य;
	pfd.fd = fd;
	pfd.events = events;
	ptimeout_init(&timeout);
	अगर (timeoutp != शून्य)
		ptimeout_deadline_ms(&timeout, *timeoutp);
	अगर (stop != शून्य)
		sigfillset(&nsigset);
	क्रम (; timeoutp == शून्य || *timeoutp >= 0;) {
		अगर (stop != शून्य) {
			sigprocmask(SIG_BLOCK, &nsigset, &osigset);
			अगर (*stop) {
				sigprocmask(SIG_SETMASK, &osigset, शून्य);
				त्रुटि_सं = EINTR;
				वापस -1;
			}
		}
		r = ppoll(&pfd, 1, ptimeout_get_tsp(&timeout),
		    stop != शून्य ? &osigset : शून्य);
		oerrno = त्रुटि_सं;
		अगर (stop != शून्य)
			sigprocmask(SIG_SETMASK, &osigset, शून्य);
		अगर (timeoutp)
			*timeoutp = ptimeout_get_ms(&timeout);
		त्रुटि_सं = oerrno;
		अगर (r > 0)
			वापस 0;
		अन्यथा अगर (r == -1 && त्रुटि_सं != EAGAIN && त्रुटि_सं != EINTR)
			वापस -1;
		अन्यथा अगर (r == 0)
			अवरोध;
	}
	/* timeout */
	त्रुटि_सं = ETIMEDOUT;
	वापस -1;
}

/*
 * Wait up to *timeoutp milliseconds for fd to be readable. Updates
 * *timeoutp with time remaining.
 * Returns 0 if fd ready or -1 on timeout or error (see errno).
 */
पूर्णांक
waitrfd(पूर्णांक fd, पूर्णांक *timeoutp, अस्थिर संक_पूर्ण_प्रकार *stop) {
	वापस waitfd(fd, timeoutp, POLLIN, stop);
}

/*
 * Attempt a non-blocking connect(2) to the specified address, waiting up to
 * *timeoutp milliseconds for the connection to complete. If the timeout is
 * <=0, then wait indefinitely.
 *
 * Returns 0 on success or -1 on failure.
 */
पूर्णांक
timeout_connect(पूर्णांक sockfd, स्थिर काष्ठा sockaddr *serv_addr,
    socklen_t addrlen, पूर्णांक *timeoutp)
{
	पूर्णांक optval = 0;
	socklen_t optlen = माप(optval);

	/* No timeout: just do a blocking connect() */
	अगर (timeoutp == शून्य || *timeoutp <= 0)
		वापस connect(sockfd, serv_addr, addrlen);

	set_nonblock(sockfd);
	क्रम (;;) {
		अगर (connect(sockfd, serv_addr, addrlen) == 0) {
			/* Succeeded already? */
			unset_nonblock(sockfd);
			वापस 0;
		} अन्यथा अगर (त्रुटि_सं == EINTR)
			जारी;
		अन्यथा अगर (त्रुटि_सं != EINPROGRESS)
			वापस -1;
		अवरोध;
	}

	अगर (waitfd(sockfd, timeoutp, POLLIN | POLLOUT, शून्य) == -1)
		वापस -1;

	/* Completed or failed */
	अगर (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &optval, &optlen) == -1) {
		debug("getsockopt: %s", म_त्रुटि(त्रुटि_सं));
		वापस -1;
	}
	अगर (optval != 0) {
		त्रुटि_सं = optval;
		वापस -1;
	}
	unset_nonblock(sockfd);
	वापस 0;
}

/* Characters considered whitespace in strsep calls. */
#घोषणा WHITESPACE " \t\r\n"
#घोषणा QUOTE	"\""

/* return next token in configuration line */
अटल अक्षर *
strdelim_internal(अक्षर **s, पूर्णांक split_equals)
{
	अक्षर *old;
	पूर्णांक wspace = 0;

	अगर (*s == शून्य)
		वापस शून्य;

	old = *s;

	*s = strpbrk(*s,
	    split_equals ? WHITESPACE QUOTE "=" : WHITESPACE QUOTE);
	अगर (*s == शून्य)
		वापस (old);

	अगर (*s[0] == '\"') {
		स_हटाओ(*s, *s + 1, म_माप(*s)); /* move nul too */
		/* Find matching quote */
		अगर ((*s = strpbrk(*s, QUOTE)) == शून्य) {
			वापस (शून्य);		/* no matching quote */
		} अन्यथा {
			*s[0] = '\0';
			*s += म_अखोज(*s + 1, WHITESPACE) + 1;
			वापस (old);
		}
	}

	/* Allow only one '=' to be skipped */
	अगर (split_equals && *s[0] == '=')
		wspace = 1;
	*s[0] = '\0';

	/* Skip any extra whitespace after first token */
	*s += म_अखोज(*s + 1, WHITESPACE) + 1;
	अगर (split_equals && *s[0] == '=' && !wspace)
		*s += म_अखोज(*s + 1, WHITESPACE) + 1;

	वापस (old);
}

/*
 * Return next token in configuration line; splits on whitespace or a
 * single '=' character.
 */
अक्षर *
strdelim(अक्षर **s)
{
	वापस strdelim_internal(s, 1);
}

/*
 * Return next token in configuration line; splits on whitespace only.
 */
अक्षर *
strdelimw(अक्षर **s)
{
	वापस strdelim_internal(s, 0);
}

काष्ठा passwd *
pwcopy(काष्ठा passwd *pw)
{
	काष्ठा passwd *copy = xcalloc(1, माप(*copy));

	copy->pw_name = xstrdup(pw->pw_name);
	copy->pw_passwd = xstrdup(pw->pw_passwd == शून्य ? "*" : pw->pw_passwd);
#अगर_घोषित HAVE_STRUCT_PASSWD_PW_GECOS
	copy->pw_gecos = xstrdup(pw->pw_gecos == शून्य ? "" : pw->pw_gecos);
#पूर्ण_अगर
	copy->pw_uid = pw->pw_uid;
	copy->pw_gid = pw->pw_gid;
#अगर_घोषित HAVE_STRUCT_PASSWD_PW_EXPIRE
	copy->pw_expire = pw->pw_expire;
#पूर्ण_अगर
#अगर_घोषित HAVE_STRUCT_PASSWD_PW_CHANGE
	copy->pw_change = pw->pw_change;
#पूर्ण_अगर
#अगर_घोषित HAVE_STRUCT_PASSWD_PW_CLASS
	copy->pw_class = xstrdup(pw->pw_class == शून्य ? "" : pw->pw_class);
#पूर्ण_अगर
	copy->pw_dir = xstrdup(pw->pw_dir == शून्य ? "" : pw->pw_dir);
	copy->pw_shell = xstrdup(pw->pw_shell == शून्य ? "" : pw->pw_shell);
	वापस copy;
}

व्योम
pwfree(काष्ठा passwd *pw)
{
	अगर (pw == शून्य)
		वापस;
	मुक्त(pw->pw_name);
	freezero(pw->pw_passwd,
	    pw->pw_passwd == शून्य ? 0 : म_माप(pw->pw_passwd));
#अगर_घोषित HAVE_STRUCT_PASSWD_PW_GECOS
	मुक्त(pw->pw_gecos);
#पूर्ण_अगर
#अगर_घोषित HAVE_STRUCT_PASSWD_PW_CLASS
	मुक्त(pw->pw_class);
#पूर्ण_अगर
	मुक्त(pw->pw_dir);
	मुक्त(pw->pw_shell);
	freezero(pw, माप(*pw));
}

/*
 * Convert ASCII string to TCP/IP port number.
 * Port must be >=0 and <=65535.
 * Return -1 if invalid.
 */
पूर्णांक
a2port(स्थिर अक्षर *s)
{
	काष्ठा servent *se;
	दीर्घ दीर्घ port;
	स्थिर अक्षर *errstr;

	port = strtonum(s, 0, 65535, &errstr);
	अगर (errstr == शून्य)
		वापस (पूर्णांक)port;
	अगर ((se = getservbyname(s, "tcp")) != शून्य)
		वापस ntohs(se->s_port);
	वापस -1;
}

पूर्णांक
a2tun(स्थिर अक्षर *s, पूर्णांक *remote)
{
	स्थिर अक्षर *errstr = शून्य;
	अक्षर *sp, *ep;
	पूर्णांक tun;

	अगर (remote != शून्य) {
		*remote = SSH_TUNID_ANY;
		sp = xstrdup(s);
		अगर ((ep = म_अक्षर(sp, ':')) == शून्य) {
			मुक्त(sp);
			वापस (a2tun(s, शून्य));
		}
		ep[0] = '\0'; ep++;
		*remote = a2tun(ep, शून्य);
		tun = a2tun(sp, शून्य);
		मुक्त(sp);
		वापस (*remote == SSH_TUNID_ERR ? *remote : tun);
	}

	अगर (strcasecmp(s, "any") == 0)
		वापस (SSH_TUNID_ANY);

	tun = strtonum(s, 0, SSH_TUNID_MAX, &errstr);
	अगर (errstr != शून्य)
		वापस (SSH_TUNID_ERR);

	वापस (tun);
}

#घोषणा SECONDS		1.0
#घोषणा MINUTES		(SECONDS * 60)
#घोषणा HOURS		(MINUTES * 60)
#घोषणा DAYS		(HOURS * 24)
#घोषणा WEEKS		(DAYS * 7)

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
द्विगुन
convtime_double(स्थिर अक्षर *s)
{
	द्विगुन val, योग_sec = 0.0, multiplier;
	स्थिर अक्षर *p, *start_p;
	अक्षर *endp;
	पूर्णांक seen_seconds = 0;

	अगर (s == शून्य || *s == '\0')
		वापस -1.0;

	क्रम (p = s; *p != '\0';) {
		अगर (!है_अंक((अचिन्हित अक्षर)*p) && *p != '.')
			वापस -1.0;

		त्रुटि_सं = 0;
		अगर ((val = म_से_भग्न(p, &endp)) < 0 || त्रुटि_सं != 0 || p == endp)
			वापस -1.0;
		/* Allow only decimal forms */
		अगर (p + म_अखोज(p, "0123456789.") != endp)
			वापस -1.0;
		start_p = p;
		p = endp;

		चयन (*p) {
		हाल '\0':
			/* FALLTHROUGH */
		हाल 's':
		हाल 'S':
			अगर (seen_seconds++)
				वापस -1.0;
			multiplier = SECONDS;
			अवरोध;
		हाल 'm':
		हाल 'M':
			multiplier = MINUTES;
			अवरोध;
		हाल 'h':
		हाल 'H':
			multiplier = HOURS;
			अवरोध;
		हाल 'd':
		हाल 'D':
			multiplier = DAYS;
			अवरोध;
		हाल 'w':
		हाल 'W':
			multiplier = WEEKS;
			अवरोध;
		शेष:
			वापस -1.0;
		}

		/* Special handling if this was a decimal */
		अगर (स_प्रथम(start_p, '.', endp - start_p) != शून्य) {
			/* Decimal point present */
			अगर (multiplier > 1.0)
				वापस -1.0; /* No fractionals for non-seconds */
			/* For seconds, ensure digits follow */
			अगर (!है_अंक((अचिन्हित अक्षर)*(endp - 1)))
				वापस -1.0;
		}

		योग_sec += val * multiplier;

		अगर (*p != '\0')
			p++;
	}
	वापस योग_sec;
}

/*
 * Same as convtime_double() above but fractional seconds are ignored.
 * Return -1 if time string is invalid.
 */
पूर्णांक
convtime(स्थिर अक्षर *s)
{
	द्विगुन sec_val;

	अगर ((sec_val = convtime_double(s)) < 0.0)
		वापस -1;

	/* Check for overflow into int */
	अगर (sec_val < 0 || sec_val > पूर्णांक_उच्च)
		वापस -1;

	वापस (पूर्णांक)sec_val;
}

#घोषणा TF_BUFS	8
#घोषणा TF_LEN	9

स्थिर अक्षर *
fmt_timeframe(समय_प्रकार t)
{
	अक्षर		*buf;
	अटल अक्षर	 tfbuf[TF_BUFS][TF_LEN];	/* ring buffer */
	अटल पूर्णांक	 idx = 0;
	अचिन्हित पूर्णांक	 sec, min, hrs, day;
	अचिन्हित दीर्घ दीर्घ	week;

	buf = tfbuf[idx++];
	अगर (idx == TF_BUFS)
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

	अगर (week > 0)
		snprintf(buf, TF_LEN, "%02lluw%01ud%02uh", week, day, hrs);
	अन्यथा अगर (day > 0)
		snprintf(buf, TF_LEN, "%01ud%02uh%02um", day, hrs, min);
	अन्यथा
		snprintf(buf, TF_LEN, "%02u:%02u:%02u", hrs, min, sec);

	वापस (buf);
}

/*
 * Returns a standardized host+port identifier string.
 * Caller must free returned string.
 */
अक्षर *
put_host_port(स्थिर अक्षर *host, u_short port)
{
	अक्षर *hoststr;

	अगर (port == 0 || port == SSH_DEFAULT_PORT)
		वापस(xstrdup(host));
	अगर (asprintf(&hoststr, "[%s]:%d", host, (पूर्णांक)port) == -1)
		fatal("put_host_port: asprintf: %s", म_त्रुटि(त्रुटि_सं));
	debug3("put_host_port: %s", hoststr);
	वापस hoststr;
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

	अगर (cp == शून्य || *cp == शून्य)
		वापस शून्य;

	old = s = *cp;
	अगर (*s == '[') {
		अगर ((s = म_अक्षर(s, ']')) == शून्य)
			वापस शून्य;
		अन्यथा
			s++;
	} अन्यथा अगर ((s = strpbrk(s, ":/")) == शून्य)
		s = *cp + म_माप(*cp); /* skip to end (see first case below) */

	चयन (*s) {
	हाल '\0':
		*cp = शून्य;	/* no more fields*/
		अवरोध;

	हाल ':':
	हाल '/':
		अगर (delim != शून्य)
			*delim = *s;
		*s = '\0';	/* terminate */
		*cp = s + 1;
		अवरोध;

	शेष:
		वापस शून्य;
	}

	वापस old;
}

/* The common case: only accept colon as delimiter. */
अक्षर *
hpdelim(अक्षर **cp)
{
	अक्षर *r, delim = '\0';

	r =  hpdelim2(cp, &delim);
	अगर (delim == '/')
		वापस शून्य;
	वापस r;
}

अक्षर *
cleanhostname(अक्षर *host)
{
	अगर (*host == '[' && host[म_माप(host) - 1] == ']') {
		host[म_माप(host) - 1] = '\0';
		वापस (host + 1);
	} अन्यथा
		वापस host;
}

अक्षर *
colon(अक्षर *cp)
{
	पूर्णांक flag = 0;

	अगर (*cp == ':')		/* Leading colon is part of file name. */
		वापस शून्य;
	अगर (*cp == '[')
		flag = 1;

	क्रम (; *cp; ++cp) {
		अगर (*cp == '@' && *(cp+1) == '[')
			flag = 1;
		अगर (*cp == ']' && *(cp+1) == ':' && flag)
			वापस (cp+1);
		अगर (*cp == ':' && !flag)
			वापस (cp);
		अगर (*cp == '/')
			वापस शून्य;
	}
	वापस शून्य;
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
parse_user_host_path(स्थिर अक्षर *s, अक्षर **userp, अक्षर **hostp, अक्षर **pathp)
{
	अक्षर *user = शून्य, *host = शून्य, *path = शून्य;
	अक्षर *sdup, *tmp;
	पूर्णांक ret = -1;

	अगर (userp != शून्य)
		*userp = शून्य;
	अगर (hostp != शून्य)
		*hostp = शून्य;
	अगर (pathp != शून्य)
		*pathp = शून्य;

	sdup = xstrdup(s);

	/* Check for remote syntax: [user@]host:[path] */
	अगर ((tmp = colon(sdup)) == शून्य)
		जाओ out;

	/* Extract optional path */
	*tmp++ = '\0';
	अगर (*tmp == '\0')
		tmp = ".";
	path = xstrdup(tmp);

	/* Extract optional user and mandatory host */
	tmp = म_खोजप(sdup, '@');
	अगर (tmp != शून्य) {
		*tmp++ = '\0';
		host = xstrdup(cleanhostname(tmp));
		अगर (*sdup != '\0')
			user = xstrdup(sdup);
	} अन्यथा {
		host = xstrdup(cleanhostname(sdup));
		user = शून्य;
	}

	/* Success */
	अगर (userp != शून्य) {
		*userp = user;
		user = शून्य;
	}
	अगर (hostp != शून्य) {
		*hostp = host;
		host = शून्य;
	}
	अगर (pathp != शून्य) {
		*pathp = path;
		path = शून्य;
	}
	ret = 0;
out:
	मुक्त(sdup);
	मुक्त(user);
	मुक्त(host);
	मुक्त(path);
	वापस ret;
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
parse_user_host_port(स्थिर अक्षर *s, अक्षर **userp, अक्षर **hostp, पूर्णांक *portp)
{
	अक्षर *sdup, *cp, *tmp;
	अक्षर *user = शून्य, *host = शून्य;
	पूर्णांक port = -1, ret = -1;

	अगर (userp != शून्य)
		*userp = शून्य;
	अगर (hostp != शून्य)
		*hostp = शून्य;
	अगर (portp != शून्य)
		*portp = -1;

	अगर ((sdup = tmp = strdup(s)) == शून्य)
		वापस -1;
	/* Extract optional username */
	अगर ((cp = म_खोजप(tmp, '@')) != शून्य) {
		*cp = '\0';
		अगर (*tmp == '\0')
			जाओ out;
		अगर ((user = strdup(tmp)) == शून्य)
			जाओ out;
		tmp = cp + 1;
	}
	/* Extract mandatory hostname */
	अगर ((cp = hpdelim(&tmp)) == शून्य || *cp == '\0')
		जाओ out;
	host = xstrdup(cleanhostname(cp));
	/* Convert and verify optional port */
	अगर (tmp != शून्य && *tmp != '\0') {
		अगर ((port = a2port(tmp)) <= 0)
			जाओ out;
	}
	/* Success */
	अगर (userp != शून्य) {
		*userp = user;
		user = शून्य;
	}
	अगर (hostp != शून्य) {
		*hostp = host;
		host = शून्य;
	}
	अगर (portp != शून्य)
		*portp = port;
	ret = 0;
 out:
	मुक्त(sdup);
	मुक्त(user);
	मुक्त(host);
	वापस ret;
}

/*
 * Converts a two-byte hex string to decimal.
 * Returns the decimal value or -1 for invalid input.
 */
अटल पूर्णांक
hexchar(स्थिर अक्षर *s)
{
	अचिन्हित अक्षर परिणाम[2];
	पूर्णांक i;

	क्रम (i = 0; i < 2; i++) {
		अगर (s[i] >= '0' && s[i] <= '9')
			परिणाम[i] = (अचिन्हित अक्षर)(s[i] - '0');
		अन्यथा अगर (s[i] >= 'a' && s[i] <= 'f')
			परिणाम[i] = (अचिन्हित अक्षर)(s[i] - 'a') + 10;
		अन्यथा अगर (s[i] >= 'A' && s[i] <= 'F')
			परिणाम[i] = (अचिन्हित अक्षर)(s[i] - 'A') + 10;
		अन्यथा
			वापस -1;
	}
	वापस (परिणाम[0] << 4) | परिणाम[1];
}

/*
 * Decode an url-encoded string.
 * Returns a newly allocated string on success or NULL on failure.
 */
अटल अक्षर *
urldecode(स्थिर अक्षर *src)
{
	अक्षर *ret, *dst;
	पूर्णांक ch;
	माप_प्रकार srclen;

	अगर ((srclen = म_माप(src)) >= SIZE_MAX)
		वापस शून्य;
	ret = xmalloc(srclen + 1);
	क्रम (dst = ret; *src != '\0'; src++) {
		चयन (*src) {
		हाल '+':
			*dst++ = ' ';
			अवरोध;
		हाल '%':
			/* note: don't allow \0 characters */
			अगर (!है_षष्ठादशक((अचिन्हित अक्षर)src[1]) ||
			    !है_षष्ठादशक((अचिन्हित अक्षर)src[2]) ||
			    (ch = hexchar(src + 1)) == -1 || ch == 0) {
				मुक्त(ret);
				वापस शून्य;
			}
			*dst++ = ch;
			src += 2;
			अवरोध;
		शेष:
			*dst++ = *src;
			अवरोध;
		}
	}
	*dst = '\0';

	वापस ret;
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
parse_uri(स्थिर अक्षर *scheme, स्थिर अक्षर *uri, अक्षर **userp, अक्षर **hostp,
    पूर्णांक *portp, अक्षर **pathp)
{
	अक्षर *uridup, *cp, *tmp, ch;
	अक्षर *user = शून्य, *host = शून्य, *path = शून्य;
	पूर्णांक port = -1, ret = -1;
	माप_प्रकार len;

	len = म_माप(scheme);
	अगर (म_भेदन(uri, scheme, len) != 0 || म_भेदन(uri + len, "://", 3) != 0)
		वापस 1;
	uri += len + 3;

	अगर (userp != शून्य)
		*userp = शून्य;
	अगर (hostp != शून्य)
		*hostp = शून्य;
	अगर (portp != शून्य)
		*portp = -1;
	अगर (pathp != शून्य)
		*pathp = शून्य;

	uridup = tmp = xstrdup(uri);

	/* Extract optional ssh-info (username + connection params) */
	अगर ((cp = म_अक्षर(tmp, '@')) != शून्य) {
		अक्षर *delim;

		*cp = '\0';
		/* Extract username and connection params */
		अगर ((delim = म_अक्षर(tmp, ';')) != शून्य) {
			/* Just ignore connection params for now */
			*delim = '\0';
		}
		अगर (*tmp == '\0') {
			/* Empty username */
			जाओ out;
		}
		अगर ((user = urldecode(tmp)) == शून्य)
			जाओ out;
		tmp = cp + 1;
	}

	/* Extract mandatory hostname */
	अगर ((cp = hpdelim2(&tmp, &ch)) == शून्य || *cp == '\0')
		जाओ out;
	host = xstrdup(cleanhostname(cp));
	अगर (!valid_domain(host, 0, शून्य))
		जाओ out;

	अगर (tmp != शून्य && *tmp != '\0') {
		अगर (ch == ':') {
			/* Convert and verify port. */
			अगर ((cp = म_अक्षर(tmp, '/')) != शून्य)
				*cp = '\0';
			अगर ((port = a2port(tmp)) <= 0)
				जाओ out;
			tmp = cp ? cp + 1 : शून्य;
		}
		अगर (tmp != शून्य && *tmp != '\0') {
			/* Extract optional path */
			अगर ((path = urldecode(tmp)) == शून्य)
				जाओ out;
		}
	}

	/* Success */
	अगर (userp != शून्य) {
		*userp = user;
		user = शून्य;
	}
	अगर (hostp != शून्य) {
		*hostp = host;
		host = शून्य;
	}
	अगर (portp != शून्य)
		*portp = port;
	अगर (pathp != शून्य) {
		*pathp = path;
		path = शून्य;
	}
	ret = 0;
 out:
	मुक्त(uridup);
	मुक्त(user);
	मुक्त(host);
	मुक्त(path);
	वापस ret;
}

/* function to assist building execv() arguments */
व्योम
addargs(arglist *args, अक्षर *fmt, ...)
{
	बहु_सूची ap;
	अक्षर *cp;
	u_int nalloc;
	पूर्णांक r;

	बहु_शुरू(ap, fmt);
	r = vasprintf(&cp, fmt, ap);
	बहु_पूर्ण(ap);
	अगर (r == -1)
		fatal_f("argument too long");

	nalloc = args->nalloc;
	अगर (args->list == शून्य) {
		nalloc = 32;
		args->अंक = 0;
	} अन्यथा अगर (args->अंक > (256 * 1024))
		fatal_f("too many arguments");
	अन्यथा अगर (args->अंक >= args->nalloc)
		fatal_f("arglist corrupt");
	अन्यथा अगर (args->अंक+2 >= nalloc)
		nalloc *= 2;

	args->list = xrecallocarray(args->list, args->nalloc,
	    nalloc, माप(अक्षर *));
	args->nalloc = nalloc;
	args->list[args->अंक++] = cp;
	args->list[args->अंक] = शून्य;
}

व्योम
replacearg(arglist *args, u_int which, अक्षर *fmt, ...)
{
	बहु_सूची ap;
	अक्षर *cp;
	पूर्णांक r;

	बहु_शुरू(ap, fmt);
	r = vasprintf(&cp, fmt, ap);
	बहु_पूर्ण(ap);
	अगर (r == -1)
		fatal_f("argument too long");
	अगर (args->list == शून्य || args->अंक >= args->nalloc)
		fatal_f("arglist corrupt");

	अगर (which >= args->अंक)
		fatal_f("tried to replace invalid arg %d >= %d",
		    which, args->अंक);
	मुक्त(args->list[which]);
	args->list[which] = cp;
}

व्योम
freeargs(arglist *args)
{
	u_int i;

	अगर (args == शून्य)
		वापस;
	अगर (args->list != शून्य && args->अंक < args->nalloc) {
		क्रम (i = 0; i < args->अंक; i++)
			मुक्त(args->list[i]);
		मुक्त(args->list);
	}
	args->nalloc = args->अंक = 0;
	args->list = शून्य;
}

/*
 * Expands tildes in the file name.  Returns data allocated by xmalloc.
 * Warning: this calls getpw*.
 */
पूर्णांक
tilde_expand(स्थिर अक्षर *filename, uid_t uid, अक्षर **retp)
{
	अक्षर *ocopy = शून्य, *copy, *s = शून्य;
	स्थिर अक्षर *path = शून्य, *user = शून्य;
	काष्ठा passwd *pw;
	माप_प्रकार len;
	पूर्णांक ret = -1, r, slash;

	*retp = शून्य;
	अगर (*filename != '~') {
		*retp = xstrdup(filename);
		वापस 0;
	}
	ocopy = copy = xstrdup(filename + 1);

	अगर (*copy == '\0')				/* ~ */
		path = शून्य;
	अन्यथा अगर (*copy == '/') {
		copy += म_अखोज(copy, "/");
		अगर (*copy == '\0')
			path = शून्य;			/* ~/ */
		अन्यथा
			path = copy;			/* ~/path */
	} अन्यथा {
		user = copy;
		अगर ((path = म_अक्षर(copy, '/')) != शून्य) {
			copy[path - copy] = '\0';
			path++;
			path += म_अखोज(path, "/");
			अगर (*path == '\0')		/* ~user/ */
				path = शून्य;
			/* else				 ~user/path */
		}
		/* else					~user */
	}
	अगर (user != शून्य) {
		अगर ((pw = getpwnam(user)) == शून्य) {
			error_f("No such user %s", user);
			जाओ out;
		}
	} अन्यथा अगर ((pw = getpwuid(uid)) == शून्य) {
		error_f("No such uid %ld", (दीर्घ)uid);
		जाओ out;
	}

	/* Make sure directory has a trailing '/' */
	slash = (len = म_माप(pw->pw_dir)) == 0 || pw->pw_dir[len - 1] != '/';

	अगर ((r = xasprintf(&s, "%s%s%s", pw->pw_dir,
	    slash ? "/" : "", path != शून्य ? path : "")) <= 0) {
		error_f("xasprintf failed");
		जाओ out;
	}
	अगर (r >= PATH_MAX) {
		error_f("Path too long");
		जाओ out;
	}
	/* success */
	ret = 0;
	*retp = s;
	s = शून्य;
 out:
	मुक्त(s);
	मुक्त(ocopy);
	वापस ret;
}

अक्षर *
tilde_expand_filename(स्थिर अक्षर *filename, uid_t uid)
{
	अक्षर *ret;

	अगर (tilde_expand(filename, uid, &ret) != 0)
		cleanup_exit(255);
	वापस ret;
}

/*
 * Expand a string with a set of %[char] escapes and/or ${ENVIRONMENT}
 * substitutions.  A number of escapes may be specified as
 * (char *escape_chars, char *replacement) pairs. The list must be terminated
 * by a NULL escape_char. Returns replaced string in memory allocated by
 * xmalloc which the caller must free.
 */
अटल अक्षर *
vdollar_percent_expand(पूर्णांक *parseerror, पूर्णांक dollar, पूर्णांक percent,
    स्थिर अक्षर *string, बहु_सूची ap)
{
#घोषणा EXPAND_MAX_कुंजियाँ	64
	u_int अंक_कुंजियाँ = 0, i;
	काष्ठा {
		स्थिर अक्षर *कुंजी;
		स्थिर अक्षर *repl;
	} कुंजियाँ[EXPAND_MAX_कुंजियाँ];
	काष्ठा sshbuf *buf;
	पूर्णांक r, missingvar = 0;
	अक्षर *ret = शून्य, *var, *varend, *val;
	माप_प्रकार len;

	अगर ((buf = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	अगर (parseerror == शून्य)
		fatal_f("null parseerror arg");
	*parseerror = 1;

	/* Gather keys if we're doing percent expansion. */
	अगर (percent) {
		क्रम (अंक_कुंजियाँ = 0; अंक_कुंजियाँ < EXPAND_MAX_कुंजियाँ; अंक_कुंजियाँ++) {
			कुंजियाँ[अंक_कुंजियाँ].कुंजी = बहु_तर्क(ap, अक्षर *);
			अगर (कुंजियाँ[अंक_कुंजियाँ].कुंजी == शून्य)
				अवरोध;
			कुंजियाँ[अंक_कुंजियाँ].repl = बहु_तर्क(ap, अक्षर *);
			अगर (कुंजियाँ[अंक_कुंजियाँ].repl == शून्य) {
				fatal_f("NULL replacement for token %s",
				    कुंजियाँ[अंक_कुंजियाँ].कुंजी);
			}
		}
		अगर (अंक_कुंजियाँ == EXPAND_MAX_कुंजियाँ && बहु_तर्क(ap, अक्षर *) != शून्य)
			fatal_f("too many keys");
		अगर (अंक_कुंजियाँ == 0)
			fatal_f("percent expansion without token list");
	}

	/* Expand string */
	क्रम (i = 0; *string != '\0'; string++) {
		/* Optionally process ${ENVIRONMENT} expansions. */
		अगर (dollar && string[0] == '$' && string[1] == '{') {
			string += 2;  /* skip over '${' */
			अगर ((varend = म_अक्षर(string, '}')) == शून्य) {
				error_f("environment variable '%s' missing "
				    "closing '}'", string);
				जाओ out;
			}
			len = varend - string;
			अगर (len == 0) {
				error_f("zero-length environment variable");
				जाओ out;
			}
			var = xmalloc(len + 1);
			(व्योम)strlcpy(var, string, len + 1);
			अगर ((val = दो_पर्या(var)) == शून्य) {
				error_f("env var ${%s} has no value", var);
				missingvar = 1;
			} अन्यथा {
				debug3_f("expand ${%s} -> '%s'", var, val);
				अगर ((r = sshbuf_put(buf, val, म_माप(val))) !=0)
					fatal_fr(r, "sshbuf_put ${}");
			}
			मुक्त(var);
			string += len;
			जारी;
		}

		/*
		 * Process percent expansions if we have a list of TOKENs.
		 * If we're not doing percent expansion everything just gets
		 * appended here.
		 */
		अगर (*string != '%' || !percent) {
 append:
			अगर ((r = sshbuf_put_u8(buf, *string)) != 0)
				fatal_fr(r, "sshbuf_put_u8 %%");
			जारी;
		}
		string++;
		/* %% case */
		अगर (*string == '%')
			जाओ append;
		अगर (*string == '\0') {
			error_f("invalid format");
			जाओ out;
		}
		क्रम (i = 0; i < अंक_कुंजियाँ; i++) {
			अगर (म_अक्षर(कुंजियाँ[i].कुंजी, *string) != शून्य) {
				अगर ((r = sshbuf_put(buf, कुंजियाँ[i].repl,
				    म_माप(कुंजियाँ[i].repl))) != 0)
					fatal_fr(r, "sshbuf_put %%-repl");
				अवरोध;
			}
		}
		अगर (i >= अंक_कुंजियाँ) {
			error_f("unknown key %%%c", *string);
			जाओ out;
		}
	}
	अगर (!missingvar && (ret = sshbuf_dup_string(buf)) == शून्य)
		fatal_f("sshbuf_dup_string failed");
	*parseerror = 0;
 out:
	sshbuf_free(buf);
	वापस *parseerror ? शून्य : ret;
#अघोषित EXPAND_MAX_कुंजियाँ
}

/*
 * Expand only environment variables.
 * Note that although this function is variadic like the other similar
 * functions, any such arguments will be unused.
 */

अक्षर *
dollar_expand(पूर्णांक *parseerr, स्थिर अक्षर *string, ...)
{
	अक्षर *ret;
	पूर्णांक err;
	बहु_सूची ap;

	बहु_शुरू(ap, string);
	ret = vdollar_percent_expand(&err, 1, 0, string, ap);
	बहु_पूर्ण(ap);
	अगर (parseerr != शून्य)
		*parseerr = err;
	वापस ret;
}

/*
 * Returns expanded string or NULL if a specified environment variable is
 * not defined, or calls fatal if the string is invalid.
 */
अक्षर *
percent_expand(स्थिर अक्षर *string, ...)
{
	अक्षर *ret;
	पूर्णांक err;
	बहु_सूची ap;

	बहु_शुरू(ap, string);
	ret = vdollar_percent_expand(&err, 0, 1, string, ap);
	बहु_पूर्ण(ap);
	अगर (err)
		fatal_f("failed");
	वापस ret;
}

/*
 * Returns expanded string or NULL if a specified environment variable is
 * not defined, or calls fatal if the string is invalid.
 */
अक्षर *
percent_dollar_expand(स्थिर अक्षर *string, ...)
{
	अक्षर *ret;
	पूर्णांक err;
	बहु_सूची ap;

	बहु_शुरू(ap, string);
	ret = vdollar_percent_expand(&err, 1, 1, string, ap);
	बहु_पूर्ण(ap);
	अगर (err)
		fatal_f("failed");
	वापस ret;
}

पूर्णांक
tun_open(पूर्णांक tun, पूर्णांक mode, अक्षर **ifname)
{
#अगर defined(CUSTOM_SYS_TUN_OPEN)
	वापस (sys_tun_open(tun, mode, ifname));
#या_अगर defined(SSH_TUN_OPENBSD)
	काष्ठा ifreq ifr;
	अक्षर name[100];
	पूर्णांक fd = -1, sock;
	स्थिर अक्षर *tunbase = "tun";

	अगर (ifname != शून्य)
		*ifname = शून्य;

	अगर (mode == SSH_TUNMODE_ETHERNET)
		tunbase = "tap";

	/* Open the tunnel device */
	अगर (tun <= SSH_TUNID_MAX) {
		snprintf(name, माप(name), "/dev/%s%d", tunbase, tun);
		fd = खोलो(name, O_RDWR);
	} अन्यथा अगर (tun == SSH_TUNID_ANY) {
		क्रम (tun = 100; tun >= 0; tun--) {
			snprintf(name, माप(name), "/dev/%s%d",
			    tunbase, tun);
			अगर ((fd = खोलो(name, O_RDWR)) >= 0)
				अवरोध;
		}
	} अन्यथा {
		debug_f("invalid tunnel %u", tun);
		वापस -1;
	}

	अगर (fd == -1) {
		debug_f("%s open: %s", name, म_त्रुटि(त्रुटि_सं));
		वापस -1;
	}

	debug_f("%s mode %d fd %d", name, mode, fd);

	/* Bring interface up if it is not already */
	snprintf(ifr.ifr_name, माप(ifr.ifr_name), "%s%d", tunbase, tun);
	अगर ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
		जाओ failed;

	अगर (ioctl(sock, SIOCGIFFLAGS, &ifr) == -1) {
		debug_f("get interface %s flags: %s", ifr.ifr_name,
		    म_त्रुटि(त्रुटि_सं));
		जाओ failed;
	}

	अगर (!(ifr.ifr_flags & IFF_UP)) {
		ifr.ifr_flags |= IFF_UP;
		अगर (ioctl(sock, SIOCSIFFLAGS, &ifr) == -1) {
			debug_f("activate interface %s: %s", ifr.ifr_name,
			    म_त्रुटि(त्रुटि_सं));
			जाओ failed;
		}
	}

	अगर (ifname != शून्य)
		*ifname = xstrdup(ifr.ifr_name);

	बंद(sock);
	वापस fd;

 failed:
	अगर (fd >= 0)
		बंद(fd);
	अगर (sock >= 0)
		बंद(sock);
	वापस -1;
#अन्यथा
	error("Tunnel interfaces are not supported on this platform");
	वापस (-1);
#पूर्ण_अगर
}

व्योम
sanitise_stdfd(व्योम)
{
	पूर्णांक nullfd, dupfd;

	अगर ((nullfd = dupfd = खोलो(_PATH_DEVNULL, O_RDWR)) == -1) {
		ख_लिखो(मानक_त्रुटि, "Couldn't open /dev/null: %s\n",
		    म_त्रुटि(त्रुटि_सं));
		निकास(1);
	}
	जबतक (++dupfd <= STDERR_FILENO) {
		/* Only populate closed fds. */
		अगर (fcntl(dupfd, F_GETFL) == -1 && त्रुटि_सं == EBADF) {
			अगर (dup2(nullfd, dupfd) == -1) {
				ख_लिखो(मानक_त्रुटि, "dup2: %s\n", म_त्रुटि(त्रुटि_सं));
				निकास(1);
			}
		}
	}
	अगर (nullfd > STDERR_FILENO)
		बंद(nullfd);
}

अक्षर *
tohex(स्थिर व्योम *vp, माप_प्रकार l)
{
	स्थिर u_char *p = (स्थिर u_char *)vp;
	अक्षर b[3], *r;
	माप_प्रकार i, hl;

	अगर (l > 65536)
		वापस xstrdup("tohex: length > 65536");

	hl = l * 2 + 1;
	r = xcalloc(1, hl);
	क्रम (i = 0; i < l; i++) {
		snprintf(b, माप(b), "%02x", p[i]);
		strlcat(r, b, hl);
	}
	वापस (r);
}

/*
 * Extend string *sp by the specified format. If *sp is not NULL (or empty),
 * then the separator 'sep' will be prepended before the formatted arguments.
 * Extended strings are heap allocated.
 */
व्योम
xextendf(अक्षर **sp, स्थिर अक्षर *sep, स्थिर अक्षर *fmt, ...)
{
	बहु_सूची ap;
	अक्षर *tmp1, *tmp2;

	बहु_शुरू(ap, fmt);
	xvasprintf(&tmp1, fmt, ap);
	बहु_पूर्ण(ap);

	अगर (*sp == शून्य || **sp == '\0') {
		मुक्त(*sp);
		*sp = tmp1;
		वापस;
	}
	xasprintf(&tmp2, "%s%s%s", *sp, sep == शून्य ? "" : sep, tmp1);
	मुक्त(tmp1);
	मुक्त(*sp);
	*sp = tmp2;
}


uint64_t
get_u64(स्थिर व्योम *vp)
{
	स्थिर u_char *p = (स्थिर u_char *)vp;
	uint64_t v;

	v  = (uint64_t)p[0] << 56;
	v |= (uint64_t)p[1] << 48;
	v |= (uint64_t)p[2] << 40;
	v |= (uint64_t)p[3] << 32;
	v |= (uint64_t)p[4] << 24;
	v |= (uint64_t)p[5] << 16;
	v |= (uint64_t)p[6] << 8;
	v |= (uint64_t)p[7];

	वापस (v);
}

uint32_t
get_u32(स्थिर व्योम *vp)
{
	स्थिर u_char *p = (स्थिर u_char *)vp;
	uint32_t v;

	v  = (uint32_t)p[0] << 24;
	v |= (uint32_t)p[1] << 16;
	v |= (uint32_t)p[2] << 8;
	v |= (uint32_t)p[3];

	वापस (v);
}

uint32_t
get_u32_le(स्थिर व्योम *vp)
{
	स्थिर u_char *p = (स्थिर u_char *)vp;
	uint32_t v;

	v  = (uint32_t)p[0];
	v |= (uint32_t)p[1] << 8;
	v |= (uint32_t)p[2] << 16;
	v |= (uint32_t)p[3] << 24;

	वापस (v);
}

uint16_t
get_u16(स्थिर व्योम *vp)
{
	स्थिर u_char *p = (स्थिर u_char *)vp;
	uint16_t v;

	v  = (uint16_t)p[0] << 8;
	v |= (uint16_t)p[1];

	वापस (v);
}

व्योम
put_u64(व्योम *vp, uint64_t v)
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

व्योम
put_u32(व्योम *vp, uint32_t v)
{
	u_char *p = (u_char *)vp;

	p[0] = (u_char)(v >> 24) & 0xff;
	p[1] = (u_char)(v >> 16) & 0xff;
	p[2] = (u_char)(v >> 8) & 0xff;
	p[3] = (u_char)v & 0xff;
}

व्योम
put_u32_le(व्योम *vp, uint32_t v)
{
	u_char *p = (u_char *)vp;

	p[0] = (u_char)v & 0xff;
	p[1] = (u_char)(v >> 8) & 0xff;
	p[2] = (u_char)(v >> 16) & 0xff;
	p[3] = (u_char)(v >> 24) & 0xff;
}

व्योम
put_u16(व्योम *vp, uint16_t v)
{
	u_char *p = (u_char *)vp;

	p[0] = (u_char)(v >> 8) & 0xff;
	p[1] = (u_char)v & 0xff;
}

व्योम
ms_subtract_diff(काष्ठा timeval *start, पूर्णांक *ms)
{
	काष्ठा timeval diff, finish;

	monotime_tv(&finish);
	timersub(&finish, start, &diff);
	*ms -= (diff.tv_sec * 1000) + (diff.tv_usec / 1000);
}

व्योम
ms_to_timespec(काष्ठा timespec *ts, पूर्णांक ms)
{
	अगर (ms < 0)
		ms = 0;
	ts->tv_sec = ms / 1000;
	ts->tv_nsec = (ms % 1000) * 1000 * 1000;
}

व्योम
monotime_ts(काष्ठा timespec *ts)
{
	काष्ठा timeval tv;
#अगर defined(HAVE_CLOCK_GETTIME) && (defined(CLOCK_BOOTTIME) || \
    defined(CLOCK_MONOTONIC) || defined(CLOCK_REALTIME))
	अटल पूर्णांक gettime_failed = 0;

	अगर (!gettime_failed) {
# ifdef CLOCK_BOOTTIME
		अगर (clock_gettime(CLOCK_BOOTTIME, ts) == 0)
			वापस;
# endif /* CLOCK_BOOTTIME */
# ifdef CLOCK_MONOTONIC
		अगर (clock_gettime(CLOCK_MONOTONIC, ts) == 0)
			वापस;
# endif /* CLOCK_MONOTONIC */
# ifdef CLOCK_REALTIME
		/* Not monotonic, but we're almost out of options here. */
		अगर (clock_gettime(CLOCK_REALTIME, ts) == 0)
			वापस;
# endif /* CLOCK_REALTIME */
		debug3("clock_gettime: %s", म_त्रुटि(त्रुटि_सं));
		gettime_failed = 1;
	}
#पूर्ण_अगर /* HAVE_CLOCK_GETTIME && (BOOTTIME || MONOTONIC || REALTIME) */
	gettimeofday(&tv, शून्य);
	ts->tv_sec = tv.tv_sec;
	ts->tv_nsec = (दीर्घ)tv.tv_usec * 1000;
}

व्योम
monotime_tv(काष्ठा timeval *tv)
{
	काष्ठा timespec ts;

	monotime_ts(&ts);
	tv->tv_sec = ts.tv_sec;
	tv->tv_usec = ts.tv_nsec / 1000;
}

समय_प्रकार
monotime(व्योम)
{
	काष्ठा timespec ts;

	monotime_ts(&ts);
	वापस (ts.tv_sec);
}

द्विगुन
monotime_double(व्योम)
{
	काष्ठा timespec ts;

	monotime_ts(&ts);
	वापस (द्विगुन)ts.tv_sec + (द्विगुन)ts.tv_nsec / 1000000000.0;
}

व्योम
bandwidth_limit_init(काष्ठा bwlimit *bw, uint64_t kbps, माप_प्रकार buflen)
{
	bw->buflen = buflen;
	bw->rate = kbps;
	bw->thresh = buflen;
	bw->lamt = 0;
	timerclear(&bw->bwstart);
	timerclear(&bw->bwend);
}

/* Callback from read/write loop to insert bandwidth-limiting delays */
व्योम
bandwidth_limit(काष्ठा bwlimit *bw, माप_प्रकार read_len)
{
	uint64_t waitlen;
	काष्ठा timespec ts, rm;

	bw->lamt += read_len;
	अगर (!timerisset(&bw->bwstart)) {
		monotime_tv(&bw->bwstart);
		वापस;
	}
	अगर (bw->lamt < bw->thresh)
		वापस;

	monotime_tv(&bw->bwend);
	timersub(&bw->bwend, &bw->bwstart, &bw->bwend);
	अगर (!timerisset(&bw->bwend))
		वापस;

	bw->lamt *= 8;
	waitlen = (द्विगुन)1000000L * bw->lamt / bw->rate;

	bw->bwstart.tv_sec = waitlen / 1000000L;
	bw->bwstart.tv_usec = waitlen % 1000000L;

	अगर (timercmp(&bw->bwstart, &bw->bwend, >)) {
		timersub(&bw->bwstart, &bw->bwend, &bw->bwend);

		/* Adjust the wait time */
		अगर (bw->bwend.tv_sec) {
			bw->thresh /= 2;
			अगर (bw->thresh < bw->buflen / 4)
				bw->thresh = bw->buflen / 4;
		} अन्यथा अगर (bw->bwend.tv_usec < 10000) {
			bw->thresh *= 2;
			अगर (bw->thresh > bw->buflen * 8)
				bw->thresh = bw->buflen * 8;
		}

		TIMEVAL_TO_TIMESPEC(&bw->bwend, &ts);
		जबतक (nanosleep(&ts, &rm) == -1) {
			अगर (त्रुटि_सं != EINTR)
				अवरोध;
			ts = rm;
		}
	}

	bw->lamt = 0;
	monotime_tv(&bw->bwstart);
}

/* Make a template filename for mk[sd]temp() */
व्योम
mktemp_proto(अक्षर *s, माप_प्रकार len)
{
	स्थिर अक्षर *tmpdir;
	पूर्णांक r;

	अगर ((tmpdir = दो_पर्या("TMPDIR")) != शून्य) {
		r = snprintf(s, len, "%s/ssh-XXXXXXXXXXXX", tmpdir);
		अगर (r > 0 && (माप_प्रकार)r < len)
			वापस;
	}
	r = snprintf(s, len, "/tmp/ssh-XXXXXXXXXXXX");
	अगर (r < 0 || (माप_प्रकार)r >= len)
		fatal_f("template string too short");
}

अटल स्थिर काष्ठा {
	स्थिर अक्षर *name;
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
	{ शून्य, -1 }
};

पूर्णांक
parse_ipqos(स्थिर अक्षर *cp)
{
	स्थिर अक्षर *errstr;
	u_int i;
	पूर्णांक val;

	अगर (cp == शून्य)
		वापस -1;
	क्रम (i = 0; ipqos[i].name != शून्य; i++) {
		अगर (strcasecmp(cp, ipqos[i].name) == 0)
			वापस ipqos[i].मूल्य;
	}
	/* Try parsing as an integer */
	val = (पूर्णांक)strtonum(cp, 0, 255, &errstr);
	अगर (errstr)
		वापस -1;
	वापस val;
}

स्थिर अक्षर *
iptos2str(पूर्णांक iptos)
{
	पूर्णांक i;
	अटल अक्षर iptos_str[माप "0xff"];

	क्रम (i = 0; ipqos[i].name != शून्य; i++) {
		अगर (ipqos[i].मूल्य == iptos)
			वापस ipqos[i].name;
	}
	snprintf(iptos_str, माप iptos_str, "0x%02x", iptos);
	वापस iptos_str;
}

व्योम
lowercase(अक्षर *s)
{
	क्रम (; *s; s++)
		*s = छोटे((u_char)*s);
}

पूर्णांक
unix_listener(स्थिर अक्षर *path, पूर्णांक backlog, पूर्णांक unlink_first)
{
	काष्ठा sockaddr_un sunaddr;
	पूर्णांक saved_errno, sock;

	स_रखो(&sunaddr, 0, माप(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	अगर (strlcpy(sunaddr.sun_path, path,
	    माप(sunaddr.sun_path)) >= माप(sunaddr.sun_path)) {
		error_f("path \"%s\" too long for Unix domain socket", path);
		त्रुटि_सं = ENAMETOOLONG;
		वापस -1;
	}

	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	अगर (sock == -1) {
		saved_errno = त्रुटि_सं;
		error_f("socket: %.100s", म_त्रुटि(त्रुटि_सं));
		त्रुटि_सं = saved_errno;
		वापस -1;
	}
	अगर (unlink_first == 1) {
		अगर (unlink(path) != 0 && त्रुटि_सं != ENOENT)
			error("unlink(%s): %.100s", path, म_त्रुटि(त्रुटि_सं));
	}
	अगर (bind(sock, (काष्ठा sockaddr *)&sunaddr, माप(sunaddr)) == -1) {
		saved_errno = त्रुटि_सं;
		error_f("cannot bind to path %s: %s", path, म_त्रुटि(त्रुटि_सं));
		बंद(sock);
		त्रुटि_सं = saved_errno;
		वापस -1;
	}
	अगर (listen(sock, backlog) == -1) {
		saved_errno = त्रुटि_सं;
		error_f("cannot listen on path %s: %s", path, म_त्रुटि(त्रुटि_सं));
		बंद(sock);
		unlink(path);
		त्रुटि_सं = saved_errno;
		वापस -1;
	}
	वापस sock;
}

व्योम
sock_set_v6only(पूर्णांक s)
{
#अगर defined(IPV6_V6ONLY) && !defined(__OpenBSD__)
	पूर्णांक on = 1;

	debug3_f("set socket %d IPV6_V6ONLY", s);
	अगर (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &on, माप(on)) == -1)
		error("setsockopt IPV6_V6ONLY: %s", म_त्रुटि(त्रुटि_सं));
#पूर्ण_अगर
}

/*
 * Compares two strings that maybe be NULL. Returns non-zero if strings
 * are both NULL or are identical, returns zero otherwise.
 */
अटल पूर्णांक
strcmp_maybe_null(स्थिर अक्षर *a, स्थिर अक्षर *b)
{
	अगर ((a == शून्य && b != शून्य) || (a != शून्य && b == शून्य))
		वापस 0;
	अगर (a != शून्य && म_भेद(a, b) != 0)
		वापस 0;
	वापस 1;
}

/*
 * Compare two forwards, returning non-zero if they are identical or
 * zero otherwise.
 */
पूर्णांक
forward_equals(स्थिर काष्ठा Forward *a, स्थिर काष्ठा Forward *b)
{
	अगर (strcmp_maybe_null(a->listen_host, b->listen_host) == 0)
		वापस 0;
	अगर (a->listen_port != b->listen_port)
		वापस 0;
	अगर (strcmp_maybe_null(a->listen_path, b->listen_path) == 0)
		वापस 0;
	अगर (strcmp_maybe_null(a->connect_host, b->connect_host) == 0)
		वापस 0;
	अगर (a->connect_port != b->connect_port)
		वापस 0;
	अगर (strcmp_maybe_null(a->connect_path, b->connect_path) == 0)
		वापस 0;
	/* allocated_port and handle are not checked */
	वापस 1;
}

/* returns port number, FWD_PERMIT_ANY_PORT or -1 on error */
पूर्णांक
permitopen_port(स्थिर अक्षर *p)
{
	पूर्णांक port;

	अगर (म_भेद(p, "*") == 0)
		वापस FWD_PERMIT_ANY_PORT;
	अगर ((port = a2port(p)) > 0)
		वापस port;
	वापस -1;
}

/* returns 1 if process is already daemonized, 0 otherwise */
पूर्णांक
daemonized(व्योम)
{
	पूर्णांक fd;

	अगर ((fd = खोलो(_PATH_TTY, O_RDONLY | O_NOCTTY)) >= 0) {
		बंद(fd);
		वापस 0;	/* have controlling terminal */
	}
	अगर (getppid() != 1)
		वापस 0;	/* parent is not init */
	अगर (getsid(0) != getpid())
		वापस 0;	/* not session leader */
	debug3("already daemonized");
	वापस 1;
}

/*
 * Splits 's' into an argument vector. Handles quoted string and basic
 * escape characters (\\, \", \'). Caller must free the argument vector
 * and its members.
 */
पूर्णांक
argv_split(स्थिर अक्षर *s, पूर्णांक *argcp, अक्षर ***argvp, पूर्णांक terminate_on_comment)
{
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;
	पूर्णांक argc = 0, quote, i, j;
	अक्षर *arg, **argv = xcalloc(1, माप(*argv));

	*argvp = शून्य;
	*argcp = 0;

	क्रम (i = 0; s[i] != '\0'; i++) {
		/* Skip leading whitespace */
		अगर (s[i] == ' ' || s[i] == '\t')
			जारी;
		अगर (terminate_on_comment && s[i] == '#')
			अवरोध;
		/* Start of a token */
		quote = 0;

		argv = xreallocarray(argv, (argc + 2), माप(*argv));
		arg = argv[argc++] = xcalloc(1, म_माप(s + i) + 1);
		argv[argc] = शून्य;

		/* Copy the token in, removing escapes */
		क्रम (j = 0; s[i] != '\0'; i++) {
			अगर (s[i] == '\\') {
				अगर (s[i + 1] == '\'' ||
				    s[i + 1] == '\"' ||
				    s[i + 1] == '\\' ||
				    (quote == 0 && s[i + 1] == ' ')) {
					i++; /* Skip '\' */
					arg[j++] = s[i];
				} अन्यथा {
					/* Unrecognised escape */
					arg[j++] = s[i];
				}
			} अन्यथा अगर (quote == 0 && (s[i] == ' ' || s[i] == '\t'))
				अवरोध; /* done */
			अन्यथा अगर (quote == 0 && (s[i] == '\"' || s[i] == '\''))
				quote = s[i]; /* quote start */
			अन्यथा अगर (quote != 0 && s[i] == quote)
				quote = 0; /* quote end */
			अन्यथा
				arg[j++] = s[i];
		}
		अगर (s[i] == '\0') {
			अगर (quote != 0) {
				/* Ran out of string looking for close quote */
				r = SSH_ERR_INVALID_FORMAT;
				जाओ out;
			}
			अवरोध;
		}
	}
	/* Success */
	*argcp = argc;
	*argvp = argv;
	argc = 0;
	argv = शून्य;
	r = 0;
 out:
	अगर (argc != 0 && argv != शून्य) {
		क्रम (i = 0; i < argc; i++)
			मुक्त(argv[i]);
		मुक्त(argv);
	}
	वापस r;
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
	काष्ठा sshbuf *buf, *arg;

	अगर ((buf = sshbuf_new()) == शून्य || (arg = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");

	क्रम (i = 0; i < argc; i++) {
		ws = 0;
		sshbuf_reset(arg);
		क्रम (j = 0; argv[i][j] != '\0'; j++) {
			r = 0;
			c = argv[i][j];
			चयन (c) {
			हाल ' ':
			हाल '\t':
				ws = 1;
				r = sshbuf_put_u8(arg, c);
				अवरोध;
			हाल '\\':
			हाल '\'':
			हाल '"':
				अगर ((r = sshbuf_put_u8(arg, '\\')) != 0)
					अवरोध;
				/* FALLTHROUGH */
			शेष:
				r = sshbuf_put_u8(arg, c);
				अवरोध;
			}
			अगर (r != 0)
				fatal_fr(r, "sshbuf_put_u8");
		}
		अगर ((i != 0 && (r = sshbuf_put_u8(buf, ' ')) != 0) ||
		    (ws != 0 && (r = sshbuf_put_u8(buf, '"')) != 0) ||
		    (r = sshbuf_putb(buf, arg)) != 0 ||
		    (ws != 0 && (r = sshbuf_put_u8(buf, '"')) != 0))
			fatal_fr(r, "assemble");
	}
	अगर ((ret = दो_स्मृति(sshbuf_len(buf) + 1)) == शून्य)
		fatal_f("malloc failed");
	स_नकल(ret, sshbuf_ptr(buf), sshbuf_len(buf));
	ret[sshbuf_len(buf)] = '\0';
	sshbuf_free(buf);
	sshbuf_free(arg);
	वापस ret;
}

अक्षर *
argv_अग्र(पूर्णांक *argcp, अक्षर ***argvp)
{
	अक्षर *ret = (*argvp)[0];

	अगर (*argcp > 0 && ret != शून्य) {
		(*argcp)--;
		(*argvp)++;
	}
	वापस ret;
}

व्योम
argv_consume(पूर्णांक *argcp)
{
	*argcp = 0;
}

व्योम
argv_free(अक्षर **av, पूर्णांक ac)
{
	पूर्णांक i;

	अगर (av == शून्य)
		वापस;
	क्रम (i = 0; i < ac; i++)
		मुक्त(av[i]);
	मुक्त(av);
}

/* Returns 0 if pid exited cleanly, non-zero otherwise */
पूर्णांक
exited_cleanly(pid_t pid, स्थिर अक्षर *tag, स्थिर अक्षर *cmd, पूर्णांक quiet)
{
	पूर्णांक status;

	जबतक (waitpid(pid, &status, 0) == -1) {
		अगर (त्रुटि_सं != EINTR) {
			error("%s waitpid: %s", tag, म_त्रुटि(त्रुटि_सं));
			वापस -1;
		}
	}
	अगर (WIFSIGNALED(status)) {
		error("%s %s exited on signal %d", tag, cmd, WTERMSIG(status));
		वापस -1;
	} अन्यथा अगर (WEXITSTATUS(status) != 0) {
		do_log2(quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_INFO,
		    "%s %s failed, status %d", tag, cmd, WEXITSTATUS(status));
		वापस -1;
	}
	वापस 0;
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
safe_path(स्थिर अक्षर *name, काष्ठा stat *stp, स्थिर अक्षर *pw_dir,
    uid_t uid, अक्षर *err, माप_प्रकार errlen)
{
	अक्षर buf[PATH_MAX], buf2[PATH_MAX], homedir[PATH_MAX];
	अक्षर *cp;
	पूर्णांक comparehome = 0;
	काष्ठा stat st;

	अगर (realpath(name, buf) == शून्य) {
		snprintf(err, errlen, "realpath %s failed: %s", name,
		    म_त्रुटि(त्रुटि_सं));
		वापस -1;
	}
	अगर (pw_dir != शून्य && realpath(pw_dir, homedir) != शून्य)
		comparehome = 1;

	अगर (!S_ISREG(stp->st_mode)) {
		snprintf(err, errlen, "%s is not a regular file", buf);
		वापस -1;
	}
	अगर ((!platform_sys_dir_uid(stp->st_uid) && stp->st_uid != uid) ||
	    (stp->st_mode & 022) != 0) {
		snprintf(err, errlen, "bad ownership or modes for file %s",
		    buf);
		वापस -1;
	}

	/* for each component of the canonical path, walking upwards */
	क्रम (;;) {
		/*
		 * POSIX allows dirname to modify its argument and return a
		 * pointer into it, so make a copy to avoid overlapping strlcpy.
		 */
		strlcpy(buf2, buf, माप(buf2));
		अगर ((cp = स_नाम(buf2)) == शून्य) {
			snprintf(err, errlen, "dirname() failed");
			वापस -1;
		}
		strlcpy(buf, cp, माप(buf));

		अगर (stat(buf, &st) == -1 ||
		    (!platform_sys_dir_uid(st.st_uid) && st.st_uid != uid) ||
		    (st.st_mode & 022) != 0) {
			snprintf(err, errlen,
			    "bad ownership or modes for directory %s", buf);
			वापस -1;
		}

		/* If are past the homedir then we can stop */
		अगर (comparehome && म_भेद(homedir, buf) == 0)
			अवरोध;

		/*
		 * dirname should always complete with a "/" path,
		 * but we can be paranoid and check for "." too
		 */
		अगर ((म_भेद("/", buf) == 0) || (म_भेद(".", buf) == 0))
			अवरोध;
	}
	वापस 0;
}

/*
 * Version of safe_path() that accepts an open file descriptor to
 * avoid races.
 *
 * Returns 0 on success and -1 on failure
 */
पूर्णांक
safe_path_fd(पूर्णांक fd, स्थिर अक्षर *file, काष्ठा passwd *pw,
    अक्षर *err, माप_प्रकार errlen)
{
	काष्ठा stat st;

	/* check the open file to avoid races */
	अगर (ख_स्थिति(fd, &st) == -1) {
		snprintf(err, errlen, "cannot stat file %s: %s",
		    file, म_त्रुटि(त्रुटि_सं));
		वापस -1;
	}
	वापस safe_path(file, &st, pw->pw_dir, pw->pw_uid, err, errlen);
}

/*
 * Sets the value of the given variable in the environment.  If the variable
 * already exists, its value is overridden.
 */
व्योम
child_set_env(अक्षर ***envp, u_int *envsizep, स्थिर अक्षर *name,
	स्थिर अक्षर *मूल्य)
{
	अक्षर **env;
	u_int envsize;
	u_int i, namelen;

	अगर (म_अक्षर(name, '=') != शून्य) {
		error("Invalid environment variable \"%.100s\"", name);
		वापस;
	}

	/*
	 * If we're passed an uninitialized list, allocate a single null
	 * entry before continuing.
	 */
	अगर ((*envp == शून्य) != (*envsizep == 0))
		fatal_f("environment size mismatch");
	अगर (*envp == शून्य && *envsizep == 0) {
		*envp = xmalloc(माप(अक्षर *));
		*envp[0] = शून्य;
		*envsizep = 1;
	}

	/*
	 * Find the slot where the value should be stored.  If the variable
	 * already exists, we reuse the slot; otherwise we append a new slot
	 * at the end of the array, expanding if necessary.
	 */
	env = *envp;
	namelen = म_माप(name);
	क्रम (i = 0; env[i]; i++)
		अगर (म_भेदन(env[i], name, namelen) == 0 && env[i][namelen] == '=')
			अवरोध;
	अगर (env[i]) {
		/* Reuse the slot. */
		मुक्त(env[i]);
	} अन्यथा {
		/* New variable.  Expand if necessary. */
		envsize = *envsizep;
		अगर (i >= envsize - 1) {
			अगर (envsize >= 1000)
				fatal("child_set_env: too many env vars");
			envsize += 50;
			env = (*envp) = xreallocarray(env, envsize, माप(अक्षर *));
			*envsizep = envsize;
		}
		/* Need to set the NULL pointer at end of array beyond the new slot. */
		env[i + 1] = शून्य;
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
valid_domain(अक्षर *name, पूर्णांक makelower, स्थिर अक्षर **errstr)
{
	माप_प्रकार i, l = म_माप(name);
	u_char c, last = '\0';
	अटल अक्षर errbuf[256];

	अगर (l == 0) {
		strlcpy(errbuf, "empty domain name", माप(errbuf));
		जाओ bad;
	}
	अगर (!है_अक्षर((u_char)name[0]) && !है_अंक((u_char)name[0]) &&
	   name[0] != '_' /* technically invalid, but common */) {
		snprintf(errbuf, माप(errbuf), "domain name \"%.100s\" "
		    "starts with invalid character", name);
		जाओ bad;
	}
	क्रम (i = 0; i < l; i++) {
		c = छोटे((u_char)name[i]);
		अगर (makelower)
			name[i] = (अक्षर)c;
		अगर (last == '.' && c == '.') {
			snprintf(errbuf, माप(errbuf), "domain name "
			    "\"%.100s\" contains consecutive separators", name);
			जाओ bad;
		}
		अगर (c != '.' && c != '-' && !है_अक्षर_अंक(c) &&
		    c != '_') /* technically invalid, but common */ {
			snprintf(errbuf, माप(errbuf), "domain name "
			    "\"%.100s\" contains invalid characters", name);
			जाओ bad;
		}
		last = c;
	}
	अगर (name[l - 1] == '.')
		name[l - 1] = '\0';
	अगर (errstr != शून्य)
		*errstr = शून्य;
	वापस 1;
bad:
	अगर (errstr != शून्य)
		*errstr = errbuf;
	वापस 0;
}

/*
 * Verify that a environment variable name (not including initial '$') is
 * valid; consisting of one or more alphanumeric or underscore characters only.
 * Returns 1 on valid, 0 otherwise.
 */
पूर्णांक
valid_env_name(स्थिर अक्षर *name)
{
	स्थिर अक्षर *cp;

	अगर (name[0] == '\0')
		वापस 0;
	क्रम (cp = name; *cp != '\0'; cp++) {
		अगर (!है_अक्षर_अंक((u_char)*cp) && *cp != '_')
			वापस 0;
	}
	वापस 1;
}

स्थिर अक्षर *
atoi_err(स्थिर अक्षर *nptr, पूर्णांक *val)
{
	स्थिर अक्षर *errstr = शून्य;

	अगर (nptr == शून्य || *nptr == '\0')
		वापस "missing";
	*val = strtonum(nptr, 0, पूर्णांक_उच्च, &errstr);
	वापस errstr;
}

पूर्णांक
parse_absolute_time(स्थिर अक्षर *s, uint64_t *tp)
{
	काष्ठा पंचांग पंचांग;
	समय_प्रकार tt;
	अक्षर buf[32], *fmt;
	स्थिर अक्षर *cp;
	माप_प्रकार l;
	पूर्णांक is_utc = 0;

	*tp = 0;

	l = म_माप(s);
	अगर (l > 1 && strcasecmp(s + l - 1, "Z") == 0) {
		is_utc = 1;
		l--;
	} अन्यथा अगर (l > 3 && strcasecmp(s + l - 3, "UTC") == 0) {
		is_utc = 1;
		l -= 3;
	}
	/*
	 * POSIX strptime says "The application shall ensure that there
	 * is white-space or other non-alphanumeric characters between
	 * any two conversion specifications" so arrange things this way.
	 */
	चयन (l) {
	हाल 8: /* YYYYMMDD */
		fmt = "%Y-%m-%d";
		snprintf(buf, माप(buf), "%.4s-%.2s-%.2s", s, s + 4, s + 6);
		अवरोध;
	हाल 12: /* YYYYMMDDHHMM */
		fmt = "%Y-%m-%dT%H:%M";
		snprintf(buf, माप(buf), "%.4s-%.2s-%.2sT%.2s:%.2s",
		    s, s + 4, s + 6, s + 8, s + 10);
		अवरोध;
	हाल 14: /* YYYYMMDDHHMMSS */
		fmt = "%Y-%m-%dT%H:%M:%S";
		snprintf(buf, माप(buf), "%.4s-%.2s-%.2sT%.2s:%.2s:%.2s",
		    s, s + 4, s + 6, s + 8, s + 10, s + 12);
		अवरोध;
	शेष:
		वापस SSH_ERR_INVALID_FORMAT;
	}

	स_रखो(&पंचांग, 0, माप(पंचांग));
	अगर ((cp = strptime(buf, fmt, &पंचांग)) == शून्य || *cp != '\0')
		वापस SSH_ERR_INVALID_FORMAT;
	अगर (is_utc) {
		पंचांग.tm_wday = -1;	/* sentinel for error */
		अगर ((tt = timegm(&पंचांग)) == -1 && पंचांग.tm_wday == -1)
			वापस SSH_ERR_INVALID_FORMAT;
	} अन्यथा {
		पंचांग.tm_wday = -1;	/* sentinel for error */
		पंचांग.tm_isdst = -1;	/* mktime decides DST */
		अगर ((tt = स_गढ़ो(&पंचांग)) == -1 && पंचांग.tm_wday == -1)
			वापस SSH_ERR_INVALID_FORMAT;
	}
	/* success */
	*tp = (uint64_t)tt;
	वापस 0;
}

व्योम
format_absolute_time(uint64_t t, अक्षर *buf, माप_प्रकार len)
{
	समय_प्रकार tt = t > SSH_TIME_T_MAX ? SSH_TIME_T_MAX : t;
	काष्ठा पंचांग पंचांग;

	अगर (localtime_r(&tt, &पंचांग) == शून्य)
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
parse_pattern_interval(स्थिर अक्षर *s, अक्षर **typep, द्विगुन *secsp)
{
	अक्षर *cp, *sdup;
	द्विगुन secs;

	अगर (typep != शून्य)
		*typep = शून्य;
	अगर (secsp != शून्य)
		*secsp = 0;
	अगर (s == शून्य)
		वापस -1;
	sdup = xstrdup(s);

	अगर ((cp = म_अक्षर(sdup, '=')) == शून्य || cp == sdup) {
		मुक्त(sdup);
		वापस -1;
	}
	*cp++ = '\0';
	अगर ((secs = convtime_double(cp)) < 0.0) {
		मुक्त(sdup);
		वापस -1;
	}
	/* success */
	अगर (typep != शून्य)
		*typep = xstrdup(sdup);
	अगर (secsp != शून्य)
		*secsp = secs;
	मुक्त(sdup);
	वापस 0;
}

/* check if path is absolute */
पूर्णांक
path_absolute(स्थिर अक्षर *path)
{
	वापस (*path == '/') ? 1 : 0;
}

व्योम
skip_space(अक्षर **cpp)
{
	अक्षर *cp;

	क्रम (cp = *cpp; *cp == ' ' || *cp == '\t'; cp++)
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
opt_flag(स्थिर अक्षर *opt, पूर्णांक allow_negate, स्थिर अक्षर **optsp)
{
	माप_प्रकार opt_len = म_माप(opt);
	स्थिर अक्षर *opts = *optsp;
	पूर्णांक negate = 0;

	अगर (allow_negate && strncasecmp(opts, "no-", 3) == 0) {
		opts += 3;
		negate = 1;
	}
	अगर (strncasecmp(opts, opt, opt_len) == 0) {
		*optsp = opts + opt_len;
		वापस negate ? 0 : 1;
	}
	वापस -1;
}

अक्षर *
opt_dequote(स्थिर अक्षर **sp, स्थिर अक्षर **errstrp)
{
	स्थिर अक्षर *s = *sp;
	अक्षर *ret;
	माप_प्रकार i;

	*errstrp = शून्य;
	अगर (*s != '"') {
		*errstrp = "missing start quote";
		वापस शून्य;
	}
	s++;
	अगर ((ret = दो_स्मृति(म_माप((s)) + 1)) == शून्य) {
		*errstrp = "memory allocation failed";
		वापस शून्य;
	}
	क्रम (i = 0; *s != '\0' && *s != '"';) {
		अगर (s[0] == '\\' && s[1] == '"')
			s++;
		ret[i++] = *s++;
	}
	अगर (*s == '\0') {
		*errstrp = "missing end quote";
		मुक्त(ret);
		वापस शून्य;
	}
	ret[i] = '\0';
	s++;
	*sp = s;
	वापस ret;
}

पूर्णांक
opt_match(स्थिर अक्षर **opts, स्थिर अक्षर *term)
{
	अगर (strncasecmp((*opts), term, म_माप(term)) == 0 &&
	    (*opts)[म_माप(term)] == '=') {
		*opts += म_माप(term) + 1;
		वापस 1;
	}
	वापस 0;
}

व्योम
opt_array_append2(स्थिर अक्षर *file, स्थिर पूर्णांक पंक्ति, स्थिर अक्षर *directive,
    अक्षर ***array, पूर्णांक **iarray, u_int *lp, स्थिर अक्षर *s, पूर्णांक i)
{

	अगर (*lp >= पूर्णांक_उच्च)
		fatal("%s line %d: Too many %s entries", file, पंक्ति, directive);

	अगर (iarray != शून्य) {
		*iarray = xrecallocarray(*iarray, *lp, *lp + 1,
		    माप(**iarray));
		(*iarray)[*lp] = i;
	}

	*array = xrecallocarray(*array, *lp, *lp + 1, माप(**array));
	(*array)[*lp] = xstrdup(s);
	(*lp)++;
}

व्योम
opt_array_append(स्थिर अक्षर *file, स्थिर पूर्णांक पंक्ति, स्थिर अक्षर *directive,
    अक्षर ***array, u_int *lp, स्थिर अक्षर *s)
{
	opt_array_append2(file, पंक्ति, directive, array, शून्य, lp, s, 0);
}

व्योम
opt_array_free2(अक्षर **array, पूर्णांक **iarray, u_int l)
{
	u_int i;

	अगर (array == शून्य || l == 0)
		वापस;
	क्रम (i = 0; i < l; i++)
		मुक्त(array[i]);
	मुक्त(array);
	मुक्त(iarray);
}

sshsig_t
ssh_signal(पूर्णांक signum, sshsig_t handler)
{
	काष्ठा sigaction sa, osa;

	/* mask all other signals while in handler */
	स_रखो(&sa, 0, माप(sa));
	sa.sa_handler = handler;
	sigfillset(&sa.sa_mask);
#अगर defined(SA_RESTART) && !defined(NO_SA_RESTART)
	अगर (signum != SIGALRM)
		sa.sa_flags = SA_RESTART;
#पूर्ण_अगर
	अगर (sigaction(signum, &sa, &osa) == -1) {
		debug3("sigaction(%s): %s", strsignal(signum), म_त्रुटि(त्रुटि_सं));
		वापस संक_त्रुटि;
	}
	वापस osa.sa_handler;
}

पूर्णांक
stdfd_devnull(पूर्णांक do_stdin, पूर्णांक do_stdout, पूर्णांक do_stderr)
{
	पूर्णांक devnull, ret = 0;

	अगर ((devnull = खोलो(_PATH_DEVNULL, O_RDWR)) == -1) {
		error_f("open %s: %s", _PATH_DEVNULL,
		    म_त्रुटि(त्रुटि_सं));
		वापस -1;
	}
	अगर ((do_stdin && dup2(devnull, STDIN_FILENO) == -1) ||
	    (do_stdout && dup2(devnull, STDOUT_FILENO) == -1) ||
	    (do_stderr && dup2(devnull, STDERR_FILENO) == -1)) {
		error_f("dup2: %s", म_त्रुटि(त्रुटि_सं));
		ret = -1;
	}
	अगर (devnull > STDERR_FILENO)
		बंद(devnull);
	वापस ret;
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
subprocess(स्थिर अक्षर *tag, स्थिर अक्षर *command,
    पूर्णांक ac, अक्षर **av, खाता **child, u_int flags,
    काष्ठा passwd *pw, privdrop_fn *drop_privs, privrestore_fn *restore_privs)
{
	खाता *f = शून्य;
	काष्ठा stat st;
	पूर्णांक fd, devnull, p[2], i;
	pid_t pid;
	अक्षर *cp, errmsg[512];
	u_int nenv = 0;
	अक्षर **env = शून्य;

	/* If dropping privs, then must specify user and restore function */
	अगर (drop_privs != शून्य && (pw == शून्य || restore_privs == शून्य)) {
		error("%s: inconsistent arguments", tag); /* XXX fatal? */
		वापस 0;
	}
	अगर (pw == शून्य && (pw = getpwuid(getuid())) == शून्य) {
		error("%s: no user for current uid", tag);
		वापस 0;
	}
	अगर (child != शून्य)
		*child = शून्य;

	debug3_f("%s command \"%s\" running as %s (flags 0x%x)",
	    tag, command, pw->pw_name, flags);

	/* Check consistency */
	अगर ((flags & SSH_SUBPROCESS_STDOUT_DISCARD) != 0 &&
	    (flags & SSH_SUBPROCESS_STDOUT_CAPTURE) != 0) {
		error_f("inconsistent flags");
		वापस 0;
	}
	अगर (((flags & SSH_SUBPROCESS_STDOUT_CAPTURE) == 0) != (child == शून्य)) {
		error_f("inconsistent flags/output");
		वापस 0;
	}

	/*
	 * If executing an explicit binary, then verify the it exists
	 * and appears safe-ish to execute
	 */
	अगर (!path_absolute(av[0])) {
		error("%s path is not absolute", tag);
		वापस 0;
	}
	अगर (drop_privs != शून्य)
		drop_privs(pw);
	अगर (stat(av[0], &st) == -1) {
		error("Could not stat %s \"%s\": %s", tag,
		    av[0], म_त्रुटि(त्रुटि_सं));
		जाओ restore_return;
	}
	अगर ((flags & SSH_SUBPROCESS_UNSAFE_PATH) == 0 &&
	    safe_path(av[0], &st, शून्य, 0, errmsg, माप(errmsg)) != 0) {
		error("Unsafe %s \"%s\": %s", tag, av[0], errmsg);
		जाओ restore_return;
	}
	/* Prepare to keep the child's stdout if requested */
	अगर (pipe(p) == -1) {
		error("%s: pipe: %s", tag, म_त्रुटि(त्रुटि_सं));
 restore_return:
		अगर (restore_privs != शून्य)
			restore_privs();
		वापस 0;
	}
	अगर (restore_privs != शून्य)
		restore_privs();

	चयन ((pid = विभाजन())) {
	हाल -1: /* error */
		error("%s: fork: %s", tag, म_त्रुटि(त्रुटि_सं));
		बंद(p[0]);
		बंद(p[1]);
		वापस 0;
	हाल 0: /* child */
		/* Prepare a minimal environment for the child. */
		अगर ((flags & SSH_SUBPROCESS_PRESERVE_ENV) == 0) {
			nenv = 5;
			env = xcalloc(माप(*env), nenv);
			child_set_env(&env, &nenv, "PATH", _PATH_STDPATH);
			child_set_env(&env, &nenv, "USER", pw->pw_name);
			child_set_env(&env, &nenv, "LOGNAME", pw->pw_name);
			child_set_env(&env, &nenv, "HOME", pw->pw_dir);
			अगर ((cp = दो_पर्या("LANG")) != शून्य)
				child_set_env(&env, &nenv, "LANG", cp);
		}

		क्रम (i = 1; i < NSIG; i++)
			ssh_signal(i, संक_पूर्व);

		अगर ((devnull = खोलो(_PATH_DEVNULL, O_RDWR)) == -1) {
			error("%s: open %s: %s", tag, _PATH_DEVNULL,
			    म_त्रुटि(त्रुटि_सं));
			_निकास(1);
		}
		अगर (dup2(devnull, STDIN_FILENO) == -1) {
			error("%s: dup2: %s", tag, म_त्रुटि(त्रुटि_सं));
			_निकास(1);
		}

		/* Set up stdout as requested; leave stderr in place for now. */
		fd = -1;
		अगर ((flags & SSH_SUBPROCESS_STDOUT_CAPTURE) != 0)
			fd = p[1];
		अन्यथा अगर ((flags & SSH_SUBPROCESS_STDOUT_DISCARD) != 0)
			fd = devnull;
		अगर (fd != -1 && dup2(fd, STDOUT_FILENO) == -1) {
			error("%s: dup2: %s", tag, म_त्रुटि(त्रुटि_सं));
			_निकास(1);
		}
		closefrom(STDERR_FILENO + 1);

		अगर (geteuid() == 0 &&
		    initgroups(pw->pw_name, pw->pw_gid) == -1) {
			error("%s: initgroups(%s, %u): %s", tag,
			    pw->pw_name, (u_int)pw->pw_gid, म_त्रुटि(त्रुटि_सं));
			_निकास(1);
		}
		अगर (setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) == -1) {
			error("%s: setresgid %u: %s", tag, (u_int)pw->pw_gid,
			    म_त्रुटि(त्रुटि_सं));
			_निकास(1);
		}
		अगर (setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) == -1) {
			error("%s: setresuid %u: %s", tag, (u_int)pw->pw_uid,
			    म_त्रुटि(त्रुटि_सं));
			_निकास(1);
		}
		/* stdin is pointed to /dev/null at this point */
		अगर ((flags & SSH_SUBPROCESS_STDOUT_DISCARD) != 0 &&
		    dup2(STDIN_FILENO, STDERR_FILENO) == -1) {
			error("%s: dup2: %s", tag, म_त्रुटि(त्रुटि_सं));
			_निकास(1);
		}
		अगर (env != शून्य)
			execve(av[0], av, env);
		अन्यथा
			execv(av[0], av);
		error("%s %s \"%s\": %s", tag, env == शून्य ? "execv" : "execve",
		    command, म_त्रुटि(त्रुटि_सं));
		_निकास(127);
	शेष: /* parent */
		अवरोध;
	}

	बंद(p[1]);
	अगर ((flags & SSH_SUBPROCESS_STDOUT_CAPTURE) == 0)
		बंद(p[0]);
	अन्यथा अगर ((f = fdopen(p[0], "r")) == शून्य) {
		error("%s: fdopen: %s", tag, म_त्रुटि(त्रुटि_सं));
		बंद(p[0]);
		/* Don't leave zombie child */
		समाप्त(pid, संक_इति);
		जबतक (waitpid(pid, शून्य, 0) == -1 && त्रुटि_सं == EINTR)
			;
		वापस 0;
	}
	/* Success */
	debug3_f("%s pid %ld", tag, (दीर्घ)pid);
	अगर (child != शून्य)
		*child = f;
	वापस pid;
}

स्थिर अक्षर *
lookup_env_in_list(स्थिर अक्षर *env, अक्षर * स्थिर *envs, माप_प्रकार nenvs)
{
	माप_प्रकार i, envlen;

	envlen = म_माप(env);
	क्रम (i = 0; i < nenvs; i++) {
		अगर (म_भेदन(envs[i], env, envlen) == 0 &&
		    envs[i][envlen] == '=') {
			वापस envs[i] + envlen + 1;
		}
	}
	वापस शून्य;
}

स्थिर अक्षर *
lookup_setenv_in_list(स्थिर अक्षर *env, अक्षर * स्थिर *envs, माप_प्रकार nenvs)
{
	अक्षर *name, *cp;
	स्थिर अक्षर *ret;

	name = xstrdup(env);
	अगर ((cp = म_अक्षर(name, '=')) == शून्य) {
		मुक्त(name);
		वापस शून्य; /* not env=val */
	}
	*cp = '\0';
	ret = lookup_env_in_list(name, envs, nenvs);
	मुक्त(name);
	वापस ret;
}

/*
 * Helpers for managing poll(2)/ppoll(2) timeouts
 * Will remember the earliest deadline and return it for use in poll/ppoll.
 */

/* Initialise a poll/ppoll timeout with an indefinite deadline */
व्योम
ptimeout_init(काष्ठा timespec *pt)
{
	/*
	 * Deliberately invalid for ppoll(2).
	 * Will be converted to NULL in ptimeout_get_tspec() later.
	 */
	pt->tv_sec = -1;
	pt->tv_nsec = 0;
}

/* Specify a poll/ppoll deadline of at most 'sec' seconds */
व्योम
ptimeout_deadline_sec(काष्ठा timespec *pt, दीर्घ sec)
{
	अगर (pt->tv_sec == -1 || pt->tv_sec >= sec) {
		pt->tv_sec = sec;
		pt->tv_nsec = 0;
	}
}

/* Specify a poll/ppoll deadline of at most 'p' (timespec) */
अटल व्योम
ptimeout_deadline_tsp(काष्ठा timespec *pt, काष्ठा timespec *p)
{
	अगर (pt->tv_sec == -1 || timespeccmp(pt, p, >=))
		*pt = *p;
}

/* Specify a poll/ppoll deadline of at most 'ms' milliseconds */
व्योम
ptimeout_deadline_ms(काष्ठा timespec *pt, दीर्घ ms)
{
	काष्ठा timespec p;

	p.tv_sec = ms / 1000;
	p.tv_nsec = (ms % 1000) * 1000000;
	ptimeout_deadline_tsp(pt, &p);
}

/* Specify a poll/ppoll deadline of at most 'sec' seconds (double) */
व्योम
ptimeout_deadline_sec_double(काष्ठा timespec *pt, द्विगुन sec)
{
	काष्ठा timespec t;

	स_रखो(&t, 0, माप(t));
	अगर ((int64_t)sec >= SSH_TIME_T_MAX)
		t.tv_sec = SSH_TIME_T_MAX;
	अन्यथा अगर (sec > 0) {
		t.tv_sec = sec;
		t.tv_nsec = (sec - (द्विगुन)t.tv_sec) * 1000000000.0;
	}
	ptimeout_deadline_tsp(pt, &t);
}

/* Specify a poll/ppoll deadline at wall clock monotime 'when' (timespec) */
व्योम
ptimeout_deadline_monotime_tsp(काष्ठा timespec *pt, काष्ठा timespec *when)
{
	काष्ठा timespec now, t;

	monotime_ts(&now);

	अगर (timespeccmp(&now, when, >=)) {
		/* 'when' is now or in the past. Timeout ASAP */
		pt->tv_sec = 0;
		pt->tv_nsec = 0;
	} अन्यथा {
		timespecsub(when, &now, &t);
		ptimeout_deadline_tsp(pt, &t);
	}
}

/* Specify a poll/ppoll deadline at wall clock monotime 'when' (double) */
व्योम
ptimeout_deadline_monotime_double(काष्ठा timespec *pt, द्विगुन when)
{
	ptimeout_deadline_sec_double(pt, when - monotime_double());
}

/* Specify a poll/ppoll deadline at wall clock monotime 'when' */
व्योम
ptimeout_deadline_monotime(काष्ठा timespec *pt, समय_प्रकार when)
{
	काष्ठा timespec t;

	t.tv_sec = when;
	t.tv_nsec = 0;
	ptimeout_deadline_monotime_tsp(pt, &t);
}

/* Get a poll(2) timeout value in milliseconds */
पूर्णांक
ptimeout_get_ms(काष्ठा timespec *pt)
{
	अगर (pt->tv_sec == -1)
		वापस -1;
	अगर (pt->tv_sec >= (पूर्णांक_उच्च - (pt->tv_nsec / 1000000)) / 1000)
		वापस पूर्णांक_उच्च;
	वापस (pt->tv_sec * 1000) + (pt->tv_nsec / 1000000);
}

/* Get a ppoll(2) timeout value as a timespec pointer */
काष्ठा timespec *
ptimeout_get_tsp(काष्ठा timespec *pt)
{
	वापस pt->tv_sec == -1 ? शून्य : pt;
}

/* Returns non-zero if a timeout has been set (i.e. is not indefinite) */
पूर्णांक
ptimeout_isset(काष्ठा timespec *pt)
{
	वापस pt->tv_sec != -1;
}

/*
 * Returns zero if the library at 'path' contains symbol 's', nonzero
 * otherwise.
 */
पूर्णांक
lib_contains_प्रतीक(स्थिर अक्षर *path, स्थिर अक्षर *s)
{
#अगर_घोषित HAVE_NLIST
	काष्ठा nlist nl[2];
	पूर्णांक ret = -1, r;

	स_रखो(nl, 0, माप(nl));
	nl[0].n_name = xstrdup(s);
	nl[1].n_name = शून्य;
	अगर ((r = nlist(path, nl)) == -1) {
		error_f("nlist failed for %s", path);
		जाओ out;
	}
	अगर (r != 0 || nl[0].n_मूल्य == 0 || nl[0].n_type == 0) {
		error_f("library %s does not contain symbol %s", path, s);
		जाओ out;
	}
	/* success */
	ret = 0;
 out:
	मुक्त(nl[0].n_name);
	वापस ret;
#अन्यथा /* HAVE_NLIST */
	पूर्णांक fd, ret = -1;
	काष्ठा stat st;
	व्योम *m = शून्य;
	माप_प्रकार sz = 0;

	स_रखो(&st, 0, माप(st));
	अगर ((fd = खोलो(path, O_RDONLY)) < 0) {
		error_f("open %s: %s", path, म_त्रुटि(त्रुटि_सं));
		वापस -1;
	}
	अगर (ख_स्थिति(fd, &st) != 0) {
		error_f("fstat %s: %s", path, म_त्रुटि(त्रुटि_सं));
		जाओ out;
	}
	अगर (!S_ISREG(st.st_mode)) {
		error_f("%s is not a regular file", path);
		जाओ out;
	}
	अगर (st.st_size < 0 ||
	    (माप_प्रकार)st.st_size < म_माप(s) ||
	    st.st_size >= पूर्णांक_उच्च/2) {
		error_f("%s bad size %lld", path, (दीर्घ दीर्घ)st.st_size);
		जाओ out;
	}
	sz = (माप_प्रकार)st.st_size;
	अगर ((m = mmap(शून्य, sz, PROT_READ, MAP_PRIVATE, fd, 0)) == MAP_FAILED ||
	    m == शून्य) {
		error_f("mmap %s: %s", path, म_त्रुटि(त्रुटि_सं));
		जाओ out;
	}
	अगर (memmem(m, sz, s, म_माप(s)) == शून्य) {
		error_f("%s does not contain expected string %s", path, s);
		जाओ out;
	}
	/* success */
	ret = 0;
 out:
	अगर (m != शून्य && m != MAP_FAILED)
		munmap(m, sz);
	बंद(fd);
	वापस ret;
#पूर्ण_अगर /* HAVE_NLIST */
}

पूर्णांक
signal_is_crash(पूर्णांक sig)
{
	चयन (sig) {
	हाल संक_अंश:
	हाल SIGBUS:
	हाल SIGTRAP:
	हाल SIGSYS:
	हाल संक_भ_त्रुटि:
	हाल संक_अवैध:
	हाल SIGABRT:
		वापस 1;
	}
	वापस 0;
}

अक्षर *
get_homedir(व्योम)
{
	अक्षर *cp;
	काष्ठा passwd *pw;

	अगर ((cp = दो_पर्या("HOME")) != शून्य && *cp != '\0')
		वापस xstrdup(cp);

	अगर ((pw = getpwuid(getuid())) != शून्य && *pw->pw_dir != '\0')
		वापस xstrdup(pw->pw_dir);

	वापस शून्य;
}

पूर्णांक
mkdir_path(स्थिर अक्षर *target, mode_t mode)
{
#अगर defined(HAVE_OPENAT) && defined(O_DIRECTORY)
	अक्षर *dir, *odir = शून्य, *अग्र;
	पूर्णांक fd = AT_FDCWD, fd2, subpath_len, ret = -1;

	dir = odir = xstrdup(target);

	अगर (*dir == '/' &&
	    (fd = खोलो("/", O_RDONLY|O_DIRECTORY)) == -1) {
		error_f("open(\"/\"): %s", म_त्रुटि(त्रुटि_सं));
		मुक्त(odir);
		वापस -1;
	}
	/* Work through the path, component-wise */
	क्रम (; dir != शून्य && *dir != '\0'; dir = अग्र) {
		अगर ((अग्र = म_अक्षर(dir, '/')) != शून्य)
			*(अग्र++) = '\0';
		अगर (*dir == '\0')
			जारी;
		subpath_len = (अग्र == शून्य) ? पूर्णांक_उच्च : अग्र - odir - 1;
		अगर (mkdirat(fd, dir, mode) == 0)
			debug_f("created directory %.*s", subpath_len, target);
		अन्यथा अगर (त्रुटि_सं != EEXIST) {
			error_f("mkdir(\"%.*s\"): %s",
			    subpath_len, target, म_त्रुटि(त्रुटि_सं));
			जाओ out;
		}

		/* descend */
		अगर ((fd2 = openat(fd, dir, O_RDONLY|O_DIRECTORY)) == -1) {
			error_f("open(\"%.*s\"): %s",
			    subpath_len, target, म_त्रुटि(त्रुटि_सं));
			जाओ out;
		}
		अगर (fd != AT_FDCWD)
			बंद(fd);
		fd = fd2;
	}
	/* success */
	ret = 0;
 out:
	मुक्त(odir);
	अगर (fd != AT_FDCWD)
		बंद(fd);
	वापस ret;
#अन्यथा
	/*
	 * If we don't have openat (which was added in POSIX.1-2008), fall back
	 * to the possibly racy way.
	 */
	अक्षर *dir, *odir, *p, path[PATH_MAX] = "";
	पूर्णांक ret = -1;
	माप_प्रकार plen = माप(path);

	dir = odir = xstrdup(target);

	/* If the dir is relative, start with cwd. */
	अगर (*dir != '/' && getcwd(path, plen) == शून्य) {
		error_f("getcwd: %s", म_त्रुटि(त्रुटि_सं));
		जाओ out;
	}

	/* Work through the path, component-wise */
	जबतक ((p = strsep(&dir, "/"))) {
		अगर (*p == '\0')
			जारी;
		अगर (strlcat(path, "/", plen) >= plen ||
		    strlcat(path, p, plen) >= plen)
			जाओ out;
		अगर (सूची_गढ़ो(path, mode) == 0)
			debug_f("created directory %s", path);
		अन्यथा अगर (त्रुटि_सं != EEXIST && त्रुटि_सं != EISDIR) {
			error_f("mkdir(\"%s\"): %s", path, म_त्रुटि(त्रुटि_सं));
			जाओ out;
		}
	}
	/* success */
	ret = 0;
 out:
	मुक्त(odir);
	वापस ret;
#पूर्ण_अगर
}
