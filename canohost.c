/* $OpenBSD: canohost.c,v 1.78 2026/02/14 00:18:34 jsg Exp $ */
/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Functions for returning the canonical host name of the remote site.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <sys/socket.h>
#ضمن <sys/un.h>

#ضمن <netinet/in.h>
#ضمن <arpa/inet.h>

#ضمن <errno.h>
#ضمن <netdb.h>
#ضمن <stdio.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <stdarg.h>
#ضمن <unistd.h>

#ضمن "xmalloc.h"
#ضمن "log.h"
#ضمن "canohost.h"
#ضمن "misc.h"

فراغ
ipv64_normalise_mapped(بنية sockaddr_storage *addr, socklen_t *len)
{
	بنية sockaddr_in6 *a6 = (بنية sockaddr_in6 *)addr;
	بنية sockaddr_in *a4 = (بنية sockaddr_in *)addr;
	بنية in_addr inaddr;
	uint16_t port;

	إذا (addr->ss_family != AF_INET6 ||
	    !IN6_IS_ADDR_V4MAPPED(&a6->sin6_addr))
		إرجاع;

	debug3("Normalising mapped IPv4 in IPv6 address");

	memcpy(&inaddr, ((حرف *)&a6->sin6_addr) + 12, حجم(inaddr));
	port = a6->sin6_port;

	memset(a4, 0, حجم(*a4));

	a4->sin_family = AF_INET;
	*len = حجم(*a4);
	memcpy(&a4->sin_addr, &inaddr, حجم(inaddr));
	a4->sin_port = port;
}

/*
 * Returns the local/remote IP-address/hostname of socket as a string.
 * The returned string must be freed.
 */
ساكن حرف *
get_socket_address(صحيح sock, صحيح remote, صحيح flags)
{
	بنية sockaddr_storage addr;
	socklen_t addrlen;
	حرف ntop[NI_MAXHOST];
	صحيح r;

	إذا (sock < 0)
		إرجاع عدم;

	/* Get IP address of client. */
	addrlen = حجم(addr);
	memset(&addr, 0, حجم(addr));

	إذا (remote) {
		إذا (getpeername(sock, (بنية sockaddr *)&addr, &addrlen) != 0)
			إرجاع عدم;
	} وإلا {
		إذا (getsockname(sock, (بنية sockaddr *)&addr, &addrlen) != 0)
			إرجاع عدم;
	}

	/* Work around Linux IPv6 weirdness */
	إذا (addr.ss_family == AF_INET6) {
		addrlen = حجم(بنية sockaddr_in6);
		ipv64_normalise_mapped(&addr, &addrlen);
	}

	بدل (addr.ss_family) {
	حالة AF_INET:
	حالة AF_INET6:
		/* Get the address in ascii. */
		إذا ((r = getnameinfo((بنية sockaddr *)&addr, addrlen, ntop,
		    حجم(ntop), عدم, 0, flags)) != 0) {
			error_f("getnameinfo %d failed: %s",
			    flags, ssh_gai_strerror(r));
			إرجاع عدم;
		}
		إرجاع xstrdup(ntop);
	حالة AF_UNIX:
		/* Get the Unix domain socket path. */
		إرجاع xstrdup(((بنية sockaddr_un *)&addr)->sun_path);
	افتراضي:
		/* We can't look up remote Unix domain sockets. */
		إرجاع عدم;
	}
}

حرف *
get_peer_ipaddr(صحيح sock)
{
	حرف *p;

	إذا ((p = get_socket_address(sock, 1, NI_NUMERICHOST)) != عدم)
		إرجاع p;
	إرجاع xstrdup("UNKNOWN");
}

حرف *
get_local_ipaddr(صحيح sock)
{
	حرف *p;

	إذا ((p = get_socket_address(sock, 0, NI_NUMERICHOST)) != عدم)
		إرجاع p;
	إرجاع xstrdup("UNKNOWN");
}

حرف *
get_local_name(صحيح fd)
{
	حرف *host, myname[NI_MAXHOST];

	/* Assume we were passed a socket */
	إذا ((host = get_socket_address(fd, 0, NI_NAMEREQD)) != عدم)
		إرجاع host;

	/* Handle the case where we were passed a pipe */
	إذا (gethostname(myname, حجم(myname)) == -1) {
		verbose_f("gethostname: %s", strerror(errno));
		host = xstrdup("UNKNOWN");
	} وإلا {
		host = xstrdup(myname);
	}

	إرجاع host;
}

/* Returns the local/remote port for the socket. */

ساكن صحيح
get_sock_port(صحيح sock, صحيح local)
{
	بنية sockaddr_storage from;
	socklen_t fromlen;
	حرف strport[NI_MAXSERV];
	صحيح r;

	إذا (sock < 0)
		إرجاع -1;
	/* Get IP address of client. */
	fromlen = حجم(from);
	memset(&from, 0, حجم(from));
	إذا (local) {
		إذا (getsockname(sock, (بنية sockaddr *)&from, &fromlen) == -1) {
			error("getsockname failed: %.100s", strerror(errno));
			إرجاع 0;
		}
	} وإلا {
		إذا (getpeername(sock, (بنية sockaddr *)&from, &fromlen) == -1) {
			debug("getpeername failed: %.100s", strerror(errno));
			إرجاع -1;
		}
	}

	/* Work around Linux IPv6 weirdness */
	إذا (from.ss_family == AF_INET6)
		fromlen = حجم(بنية sockaddr_in6);

	/* Non-inet sockets don't have a port number. */
	إذا (from.ss_family != AF_INET && from.ss_family != AF_INET6)
		إرجاع 0;

	/* Return port number. */
	إذا ((r = getnameinfo((بنية sockaddr *)&from, fromlen, عدم, 0,
	    strport, حجم(strport), NI_NUMERICSERV)) != 0)
		fatal_f("getnameinfo NI_NUMERICSERV failed: %s",
		    ssh_gai_strerror(r));
	إرجاع atoi(strport);
}

صحيح
get_peer_port(صحيح sock)
{
	إرجاع get_sock_port(sock, 0);
}

صحيح
get_local_port(صحيح sock)
{
	إرجاع get_sock_port(sock, 1);
}
