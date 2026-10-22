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

#include "includes.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>

#include "xmalloc.h"
#include "log.h"
#include "canohost.h"
#include "misc.h"

void
ipv64_normalise_mapped(struct sockaddr_storage *addr, socklen_t *len)
{
	struct sockaddr_in6 *a6 = (struct sockaddr_in6 *)addr;
	struct sockaddr_in *a4 = (struct sockaddr_in *)addr;
	struct in_addr inaddr;
	uint16_t port;

	nếu (addr->ss_family != AF_INET6 ||
	    !IN6_IS_ADDR_V4MAPPED(&a6->sin6_addr))
		trả_về;

	debug3("Normalising mapped IPv4 in IPv6 address");

	memcpy(&inaddr, ((char *)&a6->sin6_addr) + 12, sizeof(inaddr));
	port = a6->sin6_port;

	memset(a4, 0, sizeof(*a4));

	a4->sin_family = AF_INET;
	*len = sizeof(*a4);
	memcpy(&a4->sin_addr, &inaddr, sizeof(inaddr));
	a4->sin_port = port;
}

/*
 * Returns the local/remote IP-address/hostname of socket as a string.
 * The returned string must be freed.
 */
static char *
get_socket_address(số_nguyên sock, số_nguyên remote, số_nguyên flags)
{
	struct sockaddr_storage addr;
	socklen_t addrlen;
	char ntop[NI_MAXHOST];
	số_nguyên r;

	nếu (sock < 0)
		trả_về NULL;

	/* Get IP address of client. */
	addrlen = sizeof(addr);
	memset(&addr, 0, sizeof(addr));

	nếu (remote) {
		nếu (getpeername(sock, (struct sockaddr *)&addr, &addrlen) != 0)
			trả_về NULL;
	} không_thì {
		nếu (getsockname(sock, (struct sockaddr *)&addr, &addrlen) != 0)
			trả_về NULL;
	}

	/* Work around Linux IPv6 weirdness */
	nếu (addr.ss_family == AF_INET6) {
		addrlen = sizeof(struct sockaddr_in6);
		ipv64_normalise_mapped(&addr, &addrlen);
	}

	switch (addr.ss_family) {
	case AF_INET:
	case AF_INET6:
		/* Get the address in ascii. */
		nếu ((r = getnameinfo((struct sockaddr *)&addr, addrlen, ntop,
		    sizeof(ntop), NULL, 0, flags)) != 0) {
			error_f("getnameinfo %d failed: %s",
			    flags, ssh_gai_strerror(r));
			trả_về NULL;
		}
		trả_về xstrdup(ntop);
	case AF_UNIX:
		/* Get the Unix domain socket path. */
		trả_về xstrdup(((struct sockaddr_un *)&addr)->sun_path);
	default:
		/* We can't look up remote Unix domain sockets. */
		trả_về NULL;
	}
}

char *
get_peer_ipaddr(số_nguyên sock)
{
	char *p;

	nếu ((p = get_socket_address(sock, 1, NI_NUMERICHOST)) != NULL)
		trả_về p;
	trả_về xstrdup("UNKNOWN");
}

char *
get_local_ipaddr(số_nguyên sock)
{
	char *p;

	nếu ((p = get_socket_address(sock, 0, NI_NUMERICHOST)) != NULL)
		trả_về p;
	trả_về xstrdup("UNKNOWN");
}

char *
get_local_name(số_nguyên fd)
{
	char *host, myname[NI_MAXHOST];

	/* Assume we were passed a socket */
	nếu ((host = get_socket_address(fd, 0, NI_NAMEREQD)) != NULL)
		trả_về host;

	/* Handle the case where we were passed a pipe */
	nếu (gethostname(myname, sizeof(myname)) == -1) {
		verbose_f("gethostname: %s", strerror(errno));
		host = xstrdup("UNKNOWN");
	} không_thì {
		host = xstrdup(myname);
	}

	trả_về host;
}

/* Returns the local/remote port for the socket. */

static số_nguyên
get_sock_port(số_nguyên sock, số_nguyên local)
{
	struct sockaddr_storage from;
	socklen_t fromlen;
	char strport[NI_MAXSERV];
	số_nguyên r;

	nếu (sock < 0)
		trả_về -1;
	/* Get IP address of client. */
	fromlen = sizeof(from);
	memset(&from, 0, sizeof(from));
	nếu (local) {
		nếu (getsockname(sock, (struct sockaddr *)&from, &fromlen) == -1) {
			error("getsockname failed: %.100s", strerror(errno));
			trả_về 0;
		}
	} không_thì {
		nếu (getpeername(sock, (struct sockaddr *)&from, &fromlen) == -1) {
			debug("getpeername failed: %.100s", strerror(errno));
			trả_về -1;
		}
	}

	/* Work around Linux IPv6 weirdness */
	nếu (from.ss_family == AF_INET6)
		fromlen = sizeof(struct sockaddr_in6);

	/* Non-inet sockets don't have a port number. */
	nếu (from.ss_family != AF_INET && from.ss_family != AF_INET6)
		trả_về 0;

	/* Return port number. */
	nếu ((r = getnameinfo((struct sockaddr *)&from, fromlen, NULL, 0,
	    strport, sizeof(strport), NI_NUMERICSERV)) != 0)
		fatal_f("getnameinfo NI_NUMERICSERV failed: %s",
		    ssh_gai_strerror(r));
	trả_về atoi(strport);
}

số_nguyên
get_peer_port(số_nguyên sock)
{
	trả_về get_sock_port(sock, 0);
}

số_nguyên
get_local_port(số_nguyên sock)
{
	trả_về get_sock_port(sock, 1);
}
