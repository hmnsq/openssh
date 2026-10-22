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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/socket.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/un.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <netinet/in.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <arpa/inet.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <netdb.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "canohost.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"

ਖਾਲੀ
ipv64_normalise_mapped(ਬਣਤਰ sockaddr_storage *addr, socklen_t *len)
{
	ਬਣਤਰ sockaddr_in6 *a6 = (ਬਣਤਰ sockaddr_in6 *)addr;
	ਬਣਤਰ sockaddr_in *a4 = (ਬਣਤਰ sockaddr_in *)addr;
	ਬਣਤਰ in_addr inaddr;
	uint16_t ਪੋਰਟ;

	ਜੇ (addr->ss_family != AF_INET6 ||
	    !IN6_IS_ADDR_V4MAPPED(&a6->sin6_addr))
		ਵਾਪਸ;

	debug3("Normalising mapped IPv4 in IPv6 address");

	ਸਮ੍ਰਿਤੀ_ਨਕਲ(&inaddr, ((ਅੱਖਰ *)&a6->sin6_addr) + 12, ਆਕਾਰ(inaddr));
	ਪੋਰਟ = a6->sin6_port;

	memset(a4, 0, ਆਕਾਰ(*a4));

	a4->sin_family = AF_INET;
	*len = ਆਕਾਰ(*a4);
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(&a4->sin_addr, &inaddr, ਆਕਾਰ(inaddr));
	a4->sin_port = ਪੋਰਟ;
}

/*
 * Returns the local/remote IP-address/hostname of socket as a string.
 * The returned string must be freed.
 */
ਸਥਿਰ ਅੱਖਰ *
get_socket_ਪਤਾ(ਪੂਰਨ sock, ਪੂਰਨ remote, ਪੂਰਨ flags)
{
	ਬਣਤਰ sockaddr_storage addr;
	socklen_t addrlen;
	ਅੱਖਰ ntop[NI_MAXHOST];
	ਪੂਰਨ r;

	ਜੇ (sock < 0)
		ਵਾਪਸ ਨਿਰਾ;

	/* Get IP address of client. */
	addrlen = ਆਕਾਰ(addr);
	memset(&addr, 0, ਆਕਾਰ(addr));

	ਜੇ (remote) {
		ਜੇ (getpeername(sock, (ਬਣਤਰ sockaddr *)&addr, &addrlen) != 0)
			ਵਾਪਸ ਨਿਰਾ;
	} ਨਹੀਂਤਾਂ {
		ਜੇ (getsockname(sock, (ਬਣਤਰ sockaddr *)&addr, &addrlen) != 0)
			ਵਾਪਸ ਨਿਰਾ;
	}

	/* Work around Linux IPv6 weirdness */
	ਜੇ (addr.ss_family == AF_INET6) {
		addrlen = ਆਕਾਰ(ਬਣਤਰ sockaddr_in6);
		ipv64_normalise_mapped(&addr, &addrlen);
	}

	ਚੋਣ (addr.ss_family) {
	ਹਾਲਤ AF_INET:
	ਹਾਲਤ AF_INET6:
		/* Get the address in ascii. */
		ਜੇ ((r = getnameinfo((ਬਣਤਰ sockaddr *)&addr, addrlen, ntop,
		    ਆਕਾਰ(ntop), ਨਿਰਾ, 0, flags)) != 0) {
			error_f("getnameinfo %d failed: %s",
			    flags, ssh_gai_strerror(r));
			ਵਾਪਸ ਨਿਰਾ;
		}
		ਵਾਪਸ xstrdup(ntop);
	ਹਾਲਤ AF_UNIX:
		/* Get the Unix domain socket path. */
		ਵਾਪਸ xstrdup(((ਬਣਤਰ sockaddr_un *)&addr)->sun_ਰਸਤਾ);
	ਮੂਲ:
		/* We can't look up remote Unix domain sockets. */
		ਵਾਪਸ ਨਿਰਾ;
	}
}

ਅੱਖਰ *
get_peer_ipaddr(ਪੂਰਨ sock)
{
	ਅੱਖਰ *p;

	ਜੇ ((p = get_socket_ਪਤਾ(sock, 1, NI_NUMERICHOST)) != ਨਿਰਾ)
		ਵਾਪਸ p;
	ਵਾਪਸ xstrdup("UNKNOWN");
}

ਅੱਖਰ *
get_local_ipaddr(ਪੂਰਨ sock)
{
	ਅੱਖਰ *p;

	ਜੇ ((p = get_socket_ਪਤਾ(sock, 0, NI_NUMERICHOST)) != ਨਿਰਾ)
		ਵਾਪਸ p;
	ਵਾਪਸ xstrdup("UNKNOWN");
}

ਅੱਖਰ *
get_local_name(ਪੂਰਨ fd)
{
	ਅੱਖਰ *host, myname[NI_MAXHOST];

	/* Assume we were passed a socket */
	ਜੇ ((host = get_socket_ਪਤਾ(fd, 0, NI_NAMEREQD)) != ਨਿਰਾ)
		ਵਾਪਸ host;

	/* Handle the case where we were passed a pipe */
	ਜੇ (gethostname(myname, ਆਕਾਰ(myname)) == -1) {
		verbose_f("gethostname: %s", strerror(errno));
		host = xstrdup("UNKNOWN");
	} ਨਹੀਂਤਾਂ {
		host = xstrdup(myname);
	}

	ਵਾਪਸ host;
}

/* Returns the local/remote port for the socket. */

ਸਥਿਰ ਪੂਰਨ
get_sock_ਪੋਰਟ(ਪੂਰਨ sock, ਪੂਰਨ local)
{
	ਬਣਤਰ sockaddr_storage from;
	socklen_t fromlen;
	ਅੱਖਰ strport[NI_MAXSERV];
	ਪੂਰਨ r;

	ਜੇ (sock < 0)
		ਵਾਪਸ -1;
	/* Get IP address of client. */
	fromlen = ਆਕਾਰ(from);
	memset(&from, 0, ਆਕਾਰ(from));
	ਜੇ (local) {
		ਜੇ (getsockname(sock, (ਬਣਤਰ sockaddr *)&from, &fromlen) == -1) {
			error("getsockname failed: %.100s", strerror(errno));
			ਵਾਪਸ 0;
		}
	} ਨਹੀਂਤਾਂ {
		ਜੇ (getpeername(sock, (ਬਣਤਰ sockaddr *)&from, &fromlen) == -1) {
			debug("getpeername failed: %.100s", strerror(errno));
			ਵਾਪਸ -1;
		}
	}

	/* Work around Linux IPv6 weirdness */
	ਜੇ (from.ss_family == AF_INET6)
		fromlen = ਆਕਾਰ(ਬਣਤਰ sockaddr_in6);

	/* Non-inet sockets don't have a port number. */
	ਜੇ (from.ss_family != AF_INET && from.ss_family != AF_INET6)
		ਵਾਪਸ 0;

	/* Return port number. */
	ਜੇ ((r = getnameinfo((ਬਣਤਰ sockaddr *)&from, fromlen, ਨਿਰਾ, 0,
	    strport, ਆਕਾਰ(strport), NI_NUMERICSERV)) != 0)
		fatal_f("getnameinfo NI_NUMERICSERV failed: %s",
		    ssh_gai_strerror(r));
	ਵਾਪਸ atoi(strport);
}

ਪੂਰਨ
get_peer_ਪੋਰਟ(ਪੂਰਨ sock)
{
	ਵਾਪਸ get_sock_ਪੋਰਟ(sock, 0);
}

ਪੂਰਨ
get_local_ਪੋਰਟ(ਪੂਰਨ sock)
{
	ਵਾਪਸ get_sock_ਪੋਰਟ(sock, 1);
}
