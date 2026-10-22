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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/socket.h>
#அந்தர்பாவ <sys/un.h>

#அந்தர்பாவ <netinet/in.h>
#அந்தர்பாவ <arpa/inet.h>

#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <netdb.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <unistd.h>

#அந்தர்பாவ "xmalloc.h"
#அந்தர்பாவ "log.h"
#அந்தர்பாவ "canohost.h"
#அந்தர்பாவ "misc.h"

வெறுமை
ipv64_normalise_mapped(கட்டமைப்பு sockaddr_storage *addr, socklen_t *len)
{
	கட்டமைப்பு sockaddr_in6 *a6 = (கட்டமைப்பு sockaddr_in6 *)addr;
	கட்டமைப்பு sockaddr_in *a4 = (கட்டமைப்பு sockaddr_in *)addr;
	கட்டமைப்பு in_addr inaddr;
	uint16_t port;

	எனில் (addr->ss_family != AF_INET6 ||
	    !IN6_IS_ADDR_V4MAPPED(&a6->sin6_addr))
		திரும்பு;

	debug3("Normalising mapped IPv4 in IPv6 address");

	memcpy(&inaddr, ((எழுத்து *)&a6->sin6_addr) + 12, அளவு(inaddr));
	port = a6->sin6_port;

	memset(a4, 0, அளவு(*a4));

	a4->sin_family = AF_INET;
	*len = அளவு(*a4);
	memcpy(&a4->sin_addr, &inaddr, அளவு(inaddr));
	a4->sin_port = port;
}

/*
 * Returns the local/remote IP-address/hostname of socket as a string.
 * The returned string must be freed.
 */
நிலையான எழுத்து *
get_socket_address(முழு sock, முழு remote, முழு flags)
{
	கட்டமைப்பு sockaddr_storage addr;
	socklen_t addrlen;
	எழுத்து ntop[NI_MAXHOST];
	முழு r;

	எனில் (sock < 0)
		திரும்பு வெற்று;

	/* Get IP address of client. */
	addrlen = அளவு(addr);
	memset(&addr, 0, அளவு(addr));

	எனில் (remote) {
		எனில் (getpeername(sock, (கட்டமைப்பு sockaddr *)&addr, &addrlen) != 0)
			திரும்பு வெற்று;
	} இல்லையெனில் {
		எனில் (getsockname(sock, (கட்டமைப்பு sockaddr *)&addr, &addrlen) != 0)
			திரும்பு வெற்று;
	}

	/* Work around Linux IPv6 weirdness */
	எனில் (addr.ss_family == AF_INET6) {
		addrlen = அளவு(கட்டமைப்பு sockaddr_in6);
		ipv64_normalise_mapped(&addr, &addrlen);
	}

	தேர்வு (addr.ss_family) {
	நிலை AF_INET:
	நிலை AF_INET6:
		/* Get the address in ascii. */
		எனில் ((r = getnameinfo((கட்டமைப்பு sockaddr *)&addr, addrlen, ntop,
		    அளவு(ntop), வெற்று, 0, flags)) != 0) {
			error_f("getnameinfo %d failed: %s",
			    flags, ssh_gai_strerror(r));
			திரும்பு வெற்று;
		}
		திரும்பு xstrdup(ntop);
	நிலை AF_UNIX:
		/* Get the Unix domain socket path. */
		திரும்பு xstrdup(((கட்டமைப்பு sockaddr_un *)&addr)->sun_path);
	இயல்பு:
		/* We can't look up remote Unix domain sockets. */
		திரும்பு வெற்று;
	}
}

எழுத்து *
get_peer_ipaddr(முழு sock)
{
	எழுத்து *p;

	எனில் ((p = get_socket_address(sock, 1, NI_NUMERICHOST)) != வெற்று)
		திரும்பு p;
	திரும்பு xstrdup("UNKNOWN");
}

எழுத்து *
get_local_ipaddr(முழு sock)
{
	எழுத்து *p;

	எனில் ((p = get_socket_address(sock, 0, NI_NUMERICHOST)) != வெற்று)
		திரும்பு p;
	திரும்பு xstrdup("UNKNOWN");
}

எழுத்து *
get_local_name(முழு fd)
{
	எழுத்து *host, myname[NI_MAXHOST];

	/* Assume we were passed a socket */
	எனில் ((host = get_socket_address(fd, 0, NI_NAMEREQD)) != வெற்று)
		திரும்பு host;

	/* Handle the case where we were passed a pipe */
	எனில் (gethostname(myname, அளவு(myname)) == -1) {
		verbose_f("gethostname: %s", strerror(errno));
		host = xstrdup("UNKNOWN");
	} இல்லையெனில் {
		host = xstrdup(myname);
	}

	திரும்பு host;
}

/* Returns the local/remote port for the socket. */

நிலையான முழு
get_sock_port(முழு sock, முழு local)
{
	கட்டமைப்பு sockaddr_storage from;
	socklen_t fromlen;
	எழுத்து strport[NI_MAXSERV];
	முழு r;

	எனில் (sock < 0)
		திரும்பு -1;
	/* Get IP address of client. */
	fromlen = அளவு(from);
	memset(&from, 0, அளவு(from));
	எனில் (local) {
		எனில் (getsockname(sock, (கட்டமைப்பு sockaddr *)&from, &fromlen) == -1) {
			error("getsockname failed: %.100s", strerror(errno));
			திரும்பு 0;
		}
	} இல்லையெனில் {
		எனில் (getpeername(sock, (கட்டமைப்பு sockaddr *)&from, &fromlen) == -1) {
			debug("getpeername failed: %.100s", strerror(errno));
			திரும்பு -1;
		}
	}

	/* Work around Linux IPv6 weirdness */
	எனில் (from.ss_family == AF_INET6)
		fromlen = அளவு(கட்டமைப்பு sockaddr_in6);

	/* Non-inet sockets don't have a port number. */
	எனில் (from.ss_family != AF_INET && from.ss_family != AF_INET6)
		திரும்பு 0;

	/* Return port number. */
	எனில் ((r = getnameinfo((கட்டமைப்பு sockaddr *)&from, fromlen, வெற்று, 0,
	    strport, அளவு(strport), NI_NUMERICSERV)) != 0)
		fatal_f("getnameinfo NI_NUMERICSERV failed: %s",
		    ssh_gai_strerror(r));
	திரும்பு atoi(strport);
}

முழு
get_peer_port(முழு sock)
{
	திரும்பு get_sock_port(sock, 0);
}

முழு
get_local_port(முழு sock)
{
	திரும்பு get_sock_port(sock, 1);
}
