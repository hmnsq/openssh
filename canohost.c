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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/socket.h>
#അന്തര്ഭാവ <sys/un.h>

#അന്തര്ഭാവ <netinet/in.h>
#അന്തര്ഭാവ <arpa/inet.h>

#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <netdb.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <unistd.h>

#അന്തര്ഭാവ "xmalloc.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "canohost.h"
#അന്തര്ഭാവ "misc.h"

ശൂന്യം
ipv64_normalise_mapped(ഘടന sockaddr_storage *addr, socklen_t *len)
{
	ഘടന sockaddr_in6 *a6 = (ഘടന sockaddr_in6 *)addr;
	ഘടന sockaddr_in *a4 = (ഘടന sockaddr_in *)addr;
	ഘടന in_addr inaddr;
	uint16_t port;

	എങ്കിൽ (addr->ss_family != AF_INET6 ||
	    !IN6_IS_ADDR_V4MAPPED(&a6->sin6_addr))
		തിരികെ;

	debug3("Normalising mapped IPv4 in IPv6 address");

	memcpy(&inaddr, ((അക്ഷരം *)&a6->sin6_addr) + 12, വലുപ്പം(inaddr));
	port = a6->sin6_port;

	memset(a4, 0, വലുപ്പം(*a4));

	a4->sin_family = AF_INET;
	*len = വലുപ്പം(*a4);
	memcpy(&a4->sin_addr, &inaddr, വലുപ്പം(inaddr));
	a4->sin_port = port;
}

/*
 * Returns the local/remote IP-address/hostname of socket as a string.
 * The returned string must be freed.
 */
സ്ഥിതം അക്ഷരം *
get_socket_address(പൂർണ്ണസംഖ്യ sock, പൂർണ്ണസംഖ്യ remote, പൂർണ്ണസംഖ്യ flags)
{
	ഘടന sockaddr_storage addr;
	socklen_t addrlen;
	അക്ഷരം ntop[NI_MAXHOST];
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (sock < 0)
		തിരികെ ശൂന്യ;

	/* Get IP address of client. */
	addrlen = വലുപ്പം(addr);
	memset(&addr, 0, വലുപ്പം(addr));

	എങ്കിൽ (remote) {
		എങ്കിൽ (getpeername(sock, (ഘടന sockaddr *)&addr, &addrlen) != 0)
			തിരികെ ശൂന്യ;
	} അല്ലെങ്കിൽ {
		എങ്കിൽ (getsockname(sock, (ഘടന sockaddr *)&addr, &addrlen) != 0)
			തിരികെ ശൂന്യ;
	}

	/* Work around Linux IPv6 weirdness */
	എങ്കിൽ (addr.ss_family == AF_INET6) {
		addrlen = വലുപ്പം(ഘടന sockaddr_in6);
		ipv64_normalise_mapped(&addr, &addrlen);
	}

	തിരഞ്ഞെടുപ്പ് (addr.ss_family) {
	അവസ്ഥ AF_INET:
	അവസ്ഥ AF_INET6:
		/* Get the address in ascii. */
		എങ്കിൽ ((r = getnameinfo((ഘടന sockaddr *)&addr, addrlen, ntop,
		    വലുപ്പം(ntop), ശൂന്യ, 0, flags)) != 0) {
			error_f("getnameinfo %d failed: %s",
			    flags, ssh_gai_strerror(r));
			തിരികെ ശൂന്യ;
		}
		തിരികെ xstrdup(ntop);
	അവസ്ഥ AF_UNIX:
		/* Get the Unix domain socket path. */
		തിരികെ xstrdup(((ഘടന sockaddr_un *)&addr)->sun_path);
	സ്ഥിരസ്ഥിതി:
		/* We can't look up remote Unix domain sockets. */
		തിരികെ ശൂന്യ;
	}
}

അക്ഷരം *
get_peer_ipaddr(പൂർണ്ണസംഖ്യ sock)
{
	അക്ഷരം *p;

	എങ്കിൽ ((p = get_socket_address(sock, 1, NI_NUMERICHOST)) != ശൂന്യ)
		തിരികെ p;
	തിരികെ xstrdup("UNKNOWN");
}

അക്ഷരം *
get_local_ipaddr(പൂർണ്ണസംഖ്യ sock)
{
	അക്ഷരം *p;

	എങ്കിൽ ((p = get_socket_address(sock, 0, NI_NUMERICHOST)) != ശൂന്യ)
		തിരികെ p;
	തിരികെ xstrdup("UNKNOWN");
}

അക്ഷരം *
get_local_name(പൂർണ്ണസംഖ്യ fd)
{
	അക്ഷരം *host, myname[NI_MAXHOST];

	/* Assume we were passed a socket */
	എങ്കിൽ ((host = get_socket_address(fd, 0, NI_NAMEREQD)) != ശൂന്യ)
		തിരികെ host;

	/* Handle the case where we were passed a pipe */
	എങ്കിൽ (gethostname(myname, വലുപ്പം(myname)) == -1) {
		verbose_f("gethostname: %s", strerror(errno));
		host = xstrdup("UNKNOWN");
	} അല്ലെങ്കിൽ {
		host = xstrdup(myname);
	}

	തിരികെ host;
}

/* Returns the local/remote port for the socket. */

സ്ഥിതം പൂർണ്ണസംഖ്യ
get_sock_port(പൂർണ്ണസംഖ്യ sock, പൂർണ്ണസംഖ്യ local)
{
	ഘടന sockaddr_storage from;
	socklen_t fromlen;
	അക്ഷരം strport[NI_MAXSERV];
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (sock < 0)
		തിരികെ -1;
	/* Get IP address of client. */
	fromlen = വലുപ്പം(from);
	memset(&from, 0, വലുപ്പം(from));
	എങ്കിൽ (local) {
		എങ്കിൽ (getsockname(sock, (ഘടന sockaddr *)&from, &fromlen) == -1) {
			error("getsockname failed: %.100s", strerror(errno));
			തിരികെ 0;
		}
	} അല്ലെങ്കിൽ {
		എങ്കിൽ (getpeername(sock, (ഘടന sockaddr *)&from, &fromlen) == -1) {
			debug("getpeername failed: %.100s", strerror(errno));
			തിരികെ -1;
		}
	}

	/* Work around Linux IPv6 weirdness */
	എങ്കിൽ (from.ss_family == AF_INET6)
		fromlen = വലുപ്പം(ഘടന sockaddr_in6);

	/* Non-inet sockets don't have a port number. */
	എങ്കിൽ (from.ss_family != AF_INET && from.ss_family != AF_INET6)
		തിരികെ 0;

	/* Return port number. */
	എങ്കിൽ ((r = getnameinfo((ഘടന sockaddr *)&from, fromlen, ശൂന്യ, 0,
	    strport, വലുപ്പം(strport), NI_NUMERICSERV)) != 0)
		fatal_f("getnameinfo NI_NUMERICSERV failed: %s",
		    ssh_gai_strerror(r));
	തിരികെ atoi(strport);
}

പൂർണ്ണസംഖ്യ
get_peer_port(പൂർണ്ണസംഖ്യ sock)
{
	തിരികെ get_sock_port(sock, 0);
}

പൂർണ്ണസംഖ്യ
get_local_port(പൂർണ്ണസംഖ്യ sock)
{
	തിരികെ get_sock_port(sock, 1);
}
