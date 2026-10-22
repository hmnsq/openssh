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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/socket.h>
#شامل <sys/un.h>

#شامل <netinet/in.h>
#شامل <arpa/inet.h>

#شامل <errno.h>
#شامل <netdb.h>
#شامل <stdio.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <stdarg.h>
#شامل <unistd.h>

#شامل "xmalloc.h"
#شامل "log.h"
#شامل "canohost.h"
#شامل "misc.h"

خالی
ipv64_normalise_mapped(ساخت sockaddr_storage *addr, socklen_t *len)
{
	ساخت sockaddr_in6 *a6 = (ساخت sockaddr_in6 *)addr;
	ساخت sockaddr_in *a4 = (ساخت sockaddr_in *)addr;
	ساخت in_addr inaddr;
	uint16_t پورٹ;

	اگر (addr->ss_family != AF_INET6 ||
	    !IN6_IS_ADDR_V4MAPPED(&a6->sin6_addr))
		واپس;

	debug3("Normalising mapped IPv4 in IPv6 address");

	حافظہ_نقل(&inaddr, ((حرف *)&a6->sin6_addr) + 12, حجم(inaddr));
	پورٹ = a6->sin6_port;

	memset(a4, 0, حجم(*a4));

	a4->sin_family = AF_INET;
	*len = حجم(*a4);
	حافظہ_نقل(&a4->sin_addr, &inaddr, حجم(inaddr));
	a4->sin_port = پورٹ;
}

/*
 * Returns the local/remote IP-address/hostname of socket as a string.
 * The returned string must be freed.
 */
ساکن حرف *
get_socket_پتہ(صحیح sock, صحیح remote, صحیح flags)
{
	ساخت sockaddr_storage addr;
	socklen_t addrlen;
	حرف ntop[NI_MAXHOST];
	صحیح r;

	اگر (sock < 0)
		واپس تہی;

	/* Get IP address of client. */
	addrlen = حجم(addr);
	memset(&addr, 0, حجم(addr));

	اگر (remote) {
		اگر (getpeername(sock, (ساخت sockaddr *)&addr, &addrlen) != 0)
			واپس تہی;
	} ورنہ {
		اگر (getsockname(sock, (ساخت sockaddr *)&addr, &addrlen) != 0)
			واپس تہی;
	}

	/* Work around Linux IPv6 weirdness */
	اگر (addr.ss_family == AF_INET6) {
		addrlen = حجم(ساخت sockaddr_in6);
		ipv64_normalise_mapped(&addr, &addrlen);
	}

	انتخاب (addr.ss_family) {
	حالت AF_INET:
	حالت AF_INET6:
		/* Get the address in ascii. */
		اگر ((r = getnameinfo((ساخت sockaddr *)&addr, addrlen, ntop,
		    حجم(ntop), تہی, 0, flags)) != 0) {
			error_f("getnameinfo %d failed: %s",
			    flags, ssh_gai_strerror(r));
			واپس تہی;
		}
		واپس xstrdup(ntop);
	حالت AF_UNIX:
		/* Get the Unix domain socket path. */
		واپس xstrdup(((ساخت sockaddr_un *)&addr)->sun_راستہ);
	طےشدہ:
		/* We can't look up remote Unix domain sockets. */
		واپس تہی;
	}
}

حرف *
get_peer_ipaddr(صحیح sock)
{
	حرف *p;

	اگر ((p = get_socket_پتہ(sock, 1, NI_NUMERICHOST)) != تہی)
		واپس p;
	واپس xstrdup("UNKNOWN");
}

حرف *
get_local_ipaddr(صحیح sock)
{
	حرف *p;

	اگر ((p = get_socket_پتہ(sock, 0, NI_NUMERICHOST)) != تہی)
		واپس p;
	واپس xstrdup("UNKNOWN");
}

حرف *
get_local_name(صحیح fd)
{
	حرف *host, myname[NI_MAXHOST];

	/* Assume we were passed a socket */
	اگر ((host = get_socket_پتہ(fd, 0, NI_NAMEREQD)) != تہی)
		واپس host;

	/* Handle the case where we were passed a pipe */
	اگر (gethostname(myname, حجم(myname)) == -1) {
		verbose_f("gethostname: %s", strerror(errno));
		host = xstrdup("UNKNOWN");
	} ورنہ {
		host = xstrdup(myname);
	}

	واپس host;
}

/* Returns the local/remote port for the socket. */

ساکن صحیح
get_sock_پورٹ(صحیح sock, صحیح local)
{
	ساخت sockaddr_storage from;
	socklen_t fromlen;
	حرف strport[NI_MAXSERV];
	صحیح r;

	اگر (sock < 0)
		واپس -1;
	/* Get IP address of client. */
	fromlen = حجم(from);
	memset(&from, 0, حجم(from));
	اگر (local) {
		اگر (getsockname(sock, (ساخت sockaddr *)&from, &fromlen) == -1) {
			error("getsockname failed: %.100s", strerror(errno));
			واپس 0;
		}
	} ورنہ {
		اگر (getpeername(sock, (ساخت sockaddr *)&from, &fromlen) == -1) {
			debug("getpeername failed: %.100s", strerror(errno));
			واپس -1;
		}
	}

	/* Work around Linux IPv6 weirdness */
	اگر (from.ss_family == AF_INET6)
		fromlen = حجم(ساخت sockaddr_in6);

	/* Non-inet sockets don't have a port number. */
	اگر (from.ss_family != AF_INET && from.ss_family != AF_INET6)
		واپس 0;

	/* Return port number. */
	اگر ((r = getnameinfo((ساخت sockaddr *)&from, fromlen, تہی, 0,
	    strport, حجم(strport), NI_NUMERICSERV)) != 0)
		fatal_f("getnameinfo NI_NUMERICSERV failed: %s",
		    ssh_gai_strerror(r));
	واپس atoi(strport);
}

صحیح
get_peer_پورٹ(صحیح sock)
{
	واپس get_sock_پورٹ(sock, 0);
}

صحیح
get_local_پورٹ(صحیح sock)
{
	واپس get_sock_پورٹ(sock, 1);
}
