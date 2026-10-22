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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/socket.h>
#ಅನ್ತರ್ಭಾವ <sys/un.h>

#ಅನ್ತರ್ಭಾವ <netinet/in.h>
#ಅನ್ತರ್ಭಾವ <arpa/inet.h>

#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <netdb.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>

#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "canohost.h"
#ಅನ್ತರ್ಭಾವ "misc.h"

ಶೂನ್ಯ
ipv64_normalise_mapped(ಸಂರಚನಾ sockaddr_storage *addr, socklen_t *len)
{
	ಸಂರಚನಾ sockaddr_in6 *a6 = (ಸಂರಚನಾ sockaddr_in6 *)addr;
	ಸಂರಚನಾ sockaddr_in *a4 = (ಸಂರಚನಾ sockaddr_in *)addr;
	ಸಂರಚನಾ in_addr inaddr;
	uint16_t port;

	ಯದಿ (addr->ss_family != AF_INET6 ||
	    !IN6_IS_ADDR_V4MAPPED(&a6->sin6_addr))
		ಪ್ರತ್ಯಾಗಮ;

	debug3("Normalising mapped IPv4 in IPv6 address");

	memcpy(&inaddr, ((ವರ್ಣ *)&a6->sin6_addr) + 12, ಪರಿಮಾಣ(inaddr));
	port = a6->sin6_port;

	memset(a4, 0, ಪರಿಮಾಣ(*a4));

	a4->sin_family = AF_INET;
	*len = ಪರಿಮಾಣ(*a4);
	memcpy(&a4->sin_addr, &inaddr, ಪರಿಮಾಣ(inaddr));
	a4->sin_port = port;
}

/*
 * Returns the local/remote IP-address/hostname of socket as a string.
 * The returned string must be freed.
 */
ಸ್ಥಿರ ವರ್ಣ *
get_socket_address(ಪೂರ್ಣಾಙ್ಕ sock, ಪೂರ್ಣಾಙ್ಕ remote, ಪೂರ್ಣಾಙ್ಕ flags)
{
	ಸಂರಚನಾ sockaddr_storage addr;
	socklen_t addrlen;
	ವರ್ಣ ntop[NI_MAXHOST];
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (sock < 0)
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;

	/* Get IP address of client. */
	addrlen = ಪರಿಮಾಣ(addr);
	memset(&addr, 0, ಪರಿಮಾಣ(addr));

	ಯದಿ (remote) {
		ಯದಿ (getpeername(sock, (ಸಂರಚನಾ sockaddr *)&addr, &addrlen) != 0)
			ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	} ಅನ್ಯಥಾ {
		ಯದಿ (getsockname(sock, (ಸಂರಚನಾ sockaddr *)&addr, &addrlen) != 0)
			ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}

	/* Work around Linux IPv6 weirdness */
	ಯದಿ (addr.ss_family == AF_INET6) {
		addrlen = ಪರಿಮಾಣ(ಸಂರಚನಾ sockaddr_in6);
		ipv64_normalise_mapped(&addr, &addrlen);
	}

	ವಿಕಲ್ಪ (addr.ss_family) {
	ಪಕ್ಷ AF_INET:
	ಪಕ್ಷ AF_INET6:
		/* Get the address in ascii. */
		ಯದಿ ((r = getnameinfo((ಸಂರಚನಾ sockaddr *)&addr, addrlen, ntop,
		    ಪರಿಮಾಣ(ntop), ರಿಕ್ತ, 0, flags)) != 0) {
			error_f("getnameinfo %d failed: %s",
			    flags, ssh_gai_strerror(r));
			ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
		}
		ಪ್ರತ್ಯಾಗಮ xstrdup(ntop);
	ಪಕ್ಷ AF_UNIX:
		/* Get the Unix domain socket path. */
		ಪ್ರತ್ಯಾಗಮ xstrdup(((ಸಂರಚನಾ sockaddr_un *)&addr)->sun_path);
	ಸ್ವಭಾವ:
		/* We can't look up remote Unix domain sockets. */
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}
}

ವರ್ಣ *
get_peer_ipaddr(ಪೂರ್ಣಾಙ್ಕ sock)
{
	ವರ್ಣ *p;

	ಯದಿ ((p = get_socket_address(sock, 1, NI_NUMERICHOST)) != ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ p;
	ಪ್ರತ್ಯಾಗಮ xstrdup("UNKNOWN");
}

ವರ್ಣ *
get_local_ipaddr(ಪೂರ್ಣಾಙ್ಕ sock)
{
	ವರ್ಣ *p;

	ಯದಿ ((p = get_socket_address(sock, 0, NI_NUMERICHOST)) != ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ p;
	ಪ್ರತ್ಯಾಗಮ xstrdup("UNKNOWN");
}

ವರ್ಣ *
get_local_name(ಪೂರ್ಣಾಙ್ಕ fd)
{
	ವರ್ಣ *host, myname[NI_MAXHOST];

	/* Assume we were passed a socket */
	ಯದಿ ((host = get_socket_address(fd, 0, NI_NAMEREQD)) != ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ host;

	/* Handle the case where we were passed a pipe */
	ಯದಿ (gethostname(myname, ಪರಿಮಾಣ(myname)) == -1) {
		verbose_f("gethostname: %s", strerror(errno));
		host = xstrdup("UNKNOWN");
	} ಅನ್ಯಥಾ {
		host = xstrdup(myname);
	}

	ಪ್ರತ್ಯಾಗಮ host;
}

/* Returns the local/remote port for the socket. */

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
get_sock_port(ಪೂರ್ಣಾಙ್ಕ sock, ಪೂರ್ಣಾಙ್ಕ local)
{
	ಸಂರಚನಾ sockaddr_storage from;
	socklen_t fromlen;
	ವರ್ಣ strport[NI_MAXSERV];
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (sock < 0)
		ಪ್ರತ್ಯಾಗಮ -1;
	/* Get IP address of client. */
	fromlen = ಪರಿಮಾಣ(from);
	memset(&from, 0, ಪರಿಮಾಣ(from));
	ಯದಿ (local) {
		ಯದಿ (getsockname(sock, (ಸಂರಚನಾ sockaddr *)&from, &fromlen) == -1) {
			error("getsockname failed: %.100s", strerror(errno));
			ಪ್ರತ್ಯಾಗಮ 0;
		}
	} ಅನ್ಯಥಾ {
		ಯದಿ (getpeername(sock, (ಸಂರಚನಾ sockaddr *)&from, &fromlen) == -1) {
			debug("getpeername failed: %.100s", strerror(errno));
			ಪ್ರತ್ಯಾಗಮ -1;
		}
	}

	/* Work around Linux IPv6 weirdness */
	ಯದಿ (from.ss_family == AF_INET6)
		fromlen = ಪರಿಮಾಣ(ಸಂರಚನಾ sockaddr_in6);

	/* Non-inet sockets don't have a port number. */
	ಯದಿ (from.ss_family != AF_INET && from.ss_family != AF_INET6)
		ಪ್ರತ್ಯಾಗಮ 0;

	/* Return port number. */
	ಯದಿ ((r = getnameinfo((ಸಂರಚನಾ sockaddr *)&from, fromlen, ರಿಕ್ತ, 0,
	    strport, ಪರಿಮಾಣ(strport), NI_NUMERICSERV)) != 0)
		fatal_f("getnameinfo NI_NUMERICSERV failed: %s",
		    ssh_gai_strerror(r));
	ಪ್ರತ್ಯಾಗಮ atoi(strport);
}

ಪೂರ್ಣಾಙ್ಕ
get_peer_port(ಪೂರ್ಣಾಙ್ಕ sock)
{
	ಪ್ರತ್ಯಾಗಮ get_sock_port(sock, 0);
}

ಪೂರ್ಣಾಙ್ಕ
get_local_port(ಪೂರ್ಣಾಙ್ಕ sock)
{
	ಪ್ರತ್ಯಾಗಮ get_sock_port(sock, 1);
}
