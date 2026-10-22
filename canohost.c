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
ipv64_normalise_mapped(sa_nracanaa sockaddr_storage *addr, socklen_t *len)
{
	sa_nracanaa sockaddr_in6 *a6 = (sa_nracanaa sockaddr_in6 *)addr;
	sa_nracanaa sockaddr_in *a4 = (sa_nracanaa sockaddr_in *)addr;
	sa_nracanaa in_addr inaddr;
	uint16_t port;

	ᰀᰧ (addr->ss_family != AF_INET6 ||
	    !IN6_IS_ADDR_V4MAPPED(&a6->sin6_addr))
		ᰀᰧᰌ;

	debug3("Normalising mapped IPv4 in IPv6 address");

	memcpy(&inaddr, ((var_na *)&a6->sin6_addr) + 12, parimaa_na(inaddr));
	port = a6->sin6_port;

	memset(a4, 0, parimaa_na(*a4));

	a4->sin_family = AF_INET;
	*len = parimaa_na(*a4);
	memcpy(&a4->sin_addr, &inaddr, parimaa_na(inaddr));
	a4->sin_port = port;
}

/*
 * Returns the local/remote IP-address/hostname of socket as a string.
 * The returned string must be freed.
 */
static var_na *
get_socket_address(puur_naa_nka sock, puur_naa_nka remote, puur_naa_nka flags)
{
	sa_nracanaa sockaddr_storage addr;
	socklen_t addrlen;
	var_na ntop[NI_MAXHOST];
	puur_naa_nka r;

	ᰀᰧ (sock < 0)
		ᰀᰧᰌ NULL;

	/* Get IP address of client. */
	addrlen = parimaa_na(addr);
	memset(&addr, 0, parimaa_na(addr));

	ᰀᰧ (remote) {
		ᰀᰧ (getpeername(sock, (sa_nracanaa sockaddr *)&addr, &addrlen) != 0)
			ᰀᰧᰌ NULL;
	} ᰀᰧᰀ {
		ᰀᰧ (getsockname(sock, (sa_nracanaa sockaddr *)&addr, &addrlen) != 0)
			ᰀᰧᰌ NULL;
	}

	/* Work around Linux IPv6 weirdness */
	ᰀᰧ (addr.ss_family == AF_INET6) {
		addrlen = parimaa_na(sa_nracanaa sockaddr_in6);
		ipv64_normalise_mapped(&addr, &addrlen);
	}

	switch (addr.ss_family) {
	pak_sa AF_INET:
	pak_sa AF_INET6:
		/* Get the address in ascii. */
		ᰀᰧ ((r = getnameinfo((sa_nracanaa sockaddr *)&addr, addrlen, ntop,
		    parimaa_na(ntop), NULL, 0, flags)) != 0) {
			error_f("getnameinfo %d failed: %s",
			    flags, ssh_gai_strerror(r));
			ᰀᰧᰌ NULL;
		}
		ᰀᰧᰌ xstrdup(ntop);
	pak_sa AF_UNIX:
		/* Get the Unix domain socket path. */
		ᰀᰧᰌ xstrdup(((sa_nracanaa sockaddr_un *)&addr)->sun_path);
	default:
		/* We can't look up remote Unix domain sockets. */
		ᰀᰧᰌ NULL;
	}
}

var_na *
get_peer_ipaddr(puur_naa_nka sock)
{
	var_na *p;

	ᰀᰧ ((p = get_socket_address(sock, 1, NI_NUMERICHOST)) != NULL)
		ᰀᰧᰌ p;
	ᰀᰧᰌ xstrdup("UNKNOWN");
}

var_na *
get_local_ipaddr(puur_naa_nka sock)
{
	var_na *p;

	ᰀᰧ ((p = get_socket_address(sock, 0, NI_NUMERICHOST)) != NULL)
		ᰀᰧᰌ p;
	ᰀᰧᰌ xstrdup("UNKNOWN");
}

var_na *
get_local_name(puur_naa_nka fd)
{
	var_na *host, myname[NI_MAXHOST];

	/* Assume we were passed a socket */
	ᰀᰧ ((host = get_socket_address(fd, 0, NI_NAMEREQD)) != NULL)
		ᰀᰧᰌ host;

	/* Handle the case where we were passed a pipe */
	ᰀᰧ (gethostname(myname, parimaa_na(myname)) == -1) {
		verbose_f("gethostname: %s", strerror(errno));
		host = xstrdup("UNKNOWN");
	} ᰀᰧᰀ {
		host = xstrdup(myname);
	}

	ᰀᰧᰌ host;
}

/* Returns the local/remote port for the socket. */

static puur_naa_nka
get_sock_port(puur_naa_nka sock, puur_naa_nka local)
{
	sa_nracanaa sockaddr_storage from;
	socklen_t fromlen;
	var_na strport[NI_MAXSERV];
	puur_naa_nka r;

	ᰀᰧ (sock < 0)
		ᰀᰧᰌ -1;
	/* Get IP address of client. */
	fromlen = parimaa_na(from);
	memset(&from, 0, parimaa_na(from));
	ᰀᰧ (local) {
		ᰀᰧ (getsockname(sock, (sa_nracanaa sockaddr *)&from, &fromlen) == -1) {
			error("getsockname failed: %.100s", strerror(errno));
			ᰀᰧᰌ 0;
		}
	} ᰀᰧᰀ {
		ᰀᰧ (getpeername(sock, (sa_nracanaa sockaddr *)&from, &fromlen) == -1) {
			debug("getpeername failed: %.100s", strerror(errno));
			ᰀᰧᰌ -1;
		}
	}

	/* Work around Linux IPv6 weirdness */
	ᰀᰧ (from.ss_family == AF_INET6)
		fromlen = parimaa_na(sa_nracanaa sockaddr_in6);

	/* Non-inet sockets don't have a port number. */
	ᰀᰧ (from.ss_family != AF_INET && from.ss_family != AF_INET6)
		ᰀᰧᰌ 0;

	/* Return port number. */
	ᰀᰧ ((r = getnameinfo((sa_nracanaa sockaddr *)&from, fromlen, NULL, 0,
	    strport, parimaa_na(strport), NI_NUMERICSERV)) != 0)
		fatal_f("getnameinfo NI_NUMERICSERV failed: %s",
		    ssh_gai_strerror(r));
	ᰀᰧᰌ atoi(strport);
}

puur_naa_nka
get_peer_port(puur_naa_nka sock)
{
	ᰀᰧᰌ get_sock_port(sock, 0);
}

puur_naa_nka
get_local_port(puur_naa_nka sock)
{
	ᰀᰧᰌ get_sock_port(sock, 1);
}
