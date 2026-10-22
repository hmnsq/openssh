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
ipv64_normalise_mapped(ರಚನೆ sockaddr_storage *addr, socklen_t *len)
{
	ರಚನೆ sockaddr_in6 *a6 = (ರಚನೆ sockaddr_in6 *)addr;
	ರಚನೆ sockaddr_in *a4 = (ರಚನೆ sockaddr_in *)addr;
	ರಚನೆ in_addr inaddr;
	uint16_t ಪೋರ್ಟ್;

	ಆದರೆ (addr->ss_family != AF_INET6 ||
	    !IN6_IS_ADDR_V4MAPPED(&a6->sin6_addr))
		ಹಿಂತಿರುಗಿ;

	debug3("Normalising mapped IPv4 in IPv6 address");

	ಸ್ಮರಣೆ_ನಕಲು(&inaddr, ((ಅಕ್ಷರ *)&a6->sin6_addr) + 12, ಗಾತ್ರ(inaddr));
	ಪೋರ್ಟ್ = a6->sin6_port;

	memset(a4, 0, ಗಾತ್ರ(*a4));

	a4->sin_family = AF_INET;
	*len = ಗಾತ್ರ(*a4);
	ಸ್ಮರಣೆ_ನಕಲು(&a4->sin_addr, &inaddr, ಗಾತ್ರ(inaddr));
	a4->sin_port = ಪೋರ್ಟ್;
}

/*
 * Returns the local/remote IP-address/hostname of socket as a string.
 * The returned string must be freed.
 */
ಸ್ಥಿರ ಅಕ್ಷರ *
get_socket_ವಿಳಾಸ(ಪೂರ್ಣಾಂಕ sock, ಪೂರ್ಣಾಂಕ remote, ಪೂರ್ಣಾಂಕ flags)
{
	ರಚನೆ sockaddr_storage addr;
	socklen_t addrlen;
	ಅಕ್ಷರ ntop[NI_MAXHOST];
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (sock < 0)
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;

	/* Get IP address of client. */
	addrlen = ಗಾತ್ರ(addr);
	memset(&addr, 0, ಗಾತ್ರ(addr));

	ಆದರೆ (remote) {
		ಆದರೆ (getpeername(sock, (ರಚನೆ sockaddr *)&addr, &addrlen) != 0)
			ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	} ಇಲ್ಲದಿದ್ದರೆ {
		ಆದರೆ (getsockname(sock, (ರಚನೆ sockaddr *)&addr, &addrlen) != 0)
			ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}

	/* Work around Linux IPv6 weirdness */
	ಆದರೆ (addr.ss_family == AF_INET6) {
		addrlen = ಗಾತ್ರ(ರಚನೆ sockaddr_in6);
		ipv64_normalise_mapped(&addr, &addrlen);
	}

	ಆಯ್ಕೆ (addr.ss_family) {
	ಸ್ಥಿತಿ AF_INET:
	ಸ್ಥಿತಿ AF_INET6:
		/* Get the address in ascii. */
		ಆದರೆ ((r = getnameinfo((ರಚನೆ sockaddr *)&addr, addrlen, ntop,
		    ಗಾತ್ರ(ntop), ಖಾಲಿ, 0, flags)) != 0) {
			error_f("getnameinfo %d failed: %s",
			    flags, ssh_gai_strerror(r));
			ಹಿಂತಿರುಗಿ ಖಾಲಿ;
		}
		ಹಿಂತಿರುಗಿ xstrdup(ntop);
	ಸ್ಥಿತಿ AF_UNIX:
		/* Get the Unix domain socket path. */
		ಹಿಂತಿರುಗಿ xstrdup(((ರಚನೆ sockaddr_un *)&addr)->sun_ಮಾರ್ಗ);
	ಪೂರ್ವನಿಯೋಜಿತ:
		/* We can't look up remote Unix domain sockets. */
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
}

ಅಕ್ಷರ *
get_peer_ipaddr(ಪೂರ್ಣಾಂಕ sock)
{
	ಅಕ್ಷರ *p;

	ಆದರೆ ((p = get_socket_ವಿಳಾಸ(sock, 1, NI_NUMERICHOST)) != ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ p;
	ಹಿಂತಿರುಗಿ xstrdup("UNKNOWN");
}

ಅಕ್ಷರ *
get_local_ipaddr(ಪೂರ್ಣಾಂಕ sock)
{
	ಅಕ್ಷರ *p;

	ಆದರೆ ((p = get_socket_ವಿಳಾಸ(sock, 0, NI_NUMERICHOST)) != ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ p;
	ಹಿಂತಿರುಗಿ xstrdup("UNKNOWN");
}

ಅಕ್ಷರ *
get_local_name(ಪೂರ್ಣಾಂಕ fd)
{
	ಅಕ್ಷರ *host, myname[NI_MAXHOST];

	/* Assume we were passed a socket */
	ಆದರೆ ((host = get_socket_ವಿಳಾಸ(fd, 0, NI_NAMEREQD)) != ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ host;

	/* Handle the case where we were passed a pipe */
	ಆದರೆ (gethostname(myname, ಗಾತ್ರ(myname)) == -1) {
		verbose_f("gethostname: %s", strerror(errno));
		host = xstrdup("UNKNOWN");
	} ಇಲ್ಲದಿದ್ದರೆ {
		host = xstrdup(myname);
	}

	ಹಿಂತಿರುಗಿ host;
}

/* Returns the local/remote port for the socket. */

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
get_sock_ಪೋರ್ಟ್(ಪೂರ್ಣಾಂಕ sock, ಪೂರ್ಣಾಂಕ local)
{
	ರಚನೆ sockaddr_storage from;
	socklen_t fromlen;
	ಅಕ್ಷರ strport[NI_MAXSERV];
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (sock < 0)
		ಹಿಂತಿರುಗಿ -1;
	/* Get IP address of client. */
	fromlen = ಗಾತ್ರ(from);
	memset(&from, 0, ಗಾತ್ರ(from));
	ಆದರೆ (local) {
		ಆದರೆ (getsockname(sock, (ರಚನೆ sockaddr *)&from, &fromlen) == -1) {
			error("getsockname failed: %.100s", strerror(errno));
			ಹಿಂತಿರುಗಿ 0;
		}
	} ಇಲ್ಲದಿದ್ದರೆ {
		ಆದರೆ (getpeername(sock, (ರಚನೆ sockaddr *)&from, &fromlen) == -1) {
			debug("getpeername failed: %.100s", strerror(errno));
			ಹಿಂತಿರುಗಿ -1;
		}
	}

	/* Work around Linux IPv6 weirdness */
	ಆದರೆ (from.ss_family == AF_INET6)
		fromlen = ಗಾತ್ರ(ರಚನೆ sockaddr_in6);

	/* Non-inet sockets don't have a port number. */
	ಆದರೆ (from.ss_family != AF_INET && from.ss_family != AF_INET6)
		ಹಿಂತಿರುಗಿ 0;

	/* Return port number. */
	ಆದರೆ ((r = getnameinfo((ರಚನೆ sockaddr *)&from, fromlen, ಖಾಲಿ, 0,
	    strport, ಗಾತ್ರ(strport), NI_NUMERICSERV)) != 0)
		fatal_f("getnameinfo NI_NUMERICSERV failed: %s",
		    ssh_gai_strerror(r));
	ಹಿಂತಿರುಗಿ atoi(strport);
}

ಪೂರ್ಣಾಂಕ
get_peer_ಪೋರ್ಟ್(ಪೂರ್ಣಾಂಕ sock)
{
	ಹಿಂತಿರುಗಿ get_sock_ಪೋರ್ಟ್(sock, 0);
}

ಪೂರ್ಣಾಂಕ
get_local_ಪೋರ್ಟ್(ಪೂರ್ಣಾಂಕ sock)
{
	ಹಿಂತಿರುಗಿ get_sock_ಪೋರ್ಟ್(sock, 1);
}
