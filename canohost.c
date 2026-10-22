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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/socket.h>
#అన్తర్భావ <sys/un.h>

#అన్తర్భావ <netinet/in.h>
#అన్తర్భావ <arpa/inet.h>

#అన్తర్భావ <errno.h>
#అన్తర్భావ <netdb.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <unistd.h>

#అన్తర్భావ "xmalloc.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "canohost.h"
#అన్తర్భావ "misc.h"

శూన్య
ipv64_normalise_mapped(నిర్మాణం sockaddr_storage *addr, socklen_t *len)
{
	నిర్మాణం sockaddr_in6 *a6 = (నిర్మాణం sockaddr_in6 *)addr;
	నిర్మాణం sockaddr_in *a4 = (నిర్మాణం sockaddr_in *)addr;
	నిర్మాణం in_addr inaddr;
	uint16_t పోర్టు;

	ఒకవేళ (addr->ss_family != AF_INET6 ||
	    !IN6_IS_ADDR_V4MAPPED(&a6->sin6_addr))
		తిరిగి;

	debug3("Normalising mapped IPv4 in IPv6 address");

	జ్ఞాపకం_నకలు(&inaddr, ((అక్షరం *)&a6->sin6_addr) + 12, పరిమాణం(inaddr));
	పోర్టు = a6->sin6_port;

	memset(a4, 0, పరిమాణం(*a4));

	a4->sin_family = AF_INET;
	*len = పరిమాణం(*a4);
	జ్ఞాపకం_నకలు(&a4->sin_addr, &inaddr, పరిమాణం(inaddr));
	a4->sin_port = పోర్టు;
}

/*
 * Returns the local/remote IP-address/hostname of socket as a string.
 * The returned string must be freed.
 */
స్థిర అక్షరం *
get_socket_చిరునామా(పూర్ణాంకం sock, పూర్ణాంకం remote, పూర్ణాంకం flags)
{
	నిర్మాణం sockaddr_storage addr;
	socklen_t addrlen;
	అక్షరం ntop[NI_MAXHOST];
	పూర్ణాంకం r;

	ఒకవేళ (sock < 0)
		తిరిగి ఖాళీ;

	/* Get IP address of client. */
	addrlen = పరిమాణం(addr);
	memset(&addr, 0, పరిమాణం(addr));

	ఒకవేళ (remote) {
		ఒకవేళ (getpeername(sock, (నిర్మాణం sockaddr *)&addr, &addrlen) != 0)
			తిరిగి ఖాళీ;
	} లేకపోతే {
		ఒకవేళ (getsockname(sock, (నిర్మాణం sockaddr *)&addr, &addrlen) != 0)
			తిరిగి ఖాళీ;
	}

	/* Work around Linux IPv6 weirdness */
	ఒకవేళ (addr.ss_family == AF_INET6) {
		addrlen = పరిమాణం(నిర్మాణం sockaddr_in6);
		ipv64_normalise_mapped(&addr, &addrlen);
	}

	ఎంపిక (addr.ss_family) {
	స్థితి AF_INET:
	స్థితి AF_INET6:
		/* Get the address in ascii. */
		ఒకవేళ ((r = getnameinfo((నిర్మాణం sockaddr *)&addr, addrlen, ntop,
		    పరిమాణం(ntop), ఖాళీ, 0, flags)) != 0) {
			error_f("getnameinfo %d failed: %s",
			    flags, ssh_gai_strerror(r));
			తిరిగి ఖాళీ;
		}
		తిరిగి xstrdup(ntop);
	స్థితి AF_UNIX:
		/* Get the Unix domain socket path. */
		తిరిగి xstrdup(((నిర్మాణం sockaddr_un *)&addr)->sun_మార్గం);
	అప్రమేయ:
		/* We can't look up remote Unix domain sockets. */
		తిరిగి ఖాళీ;
	}
}

అక్షరం *
get_peer_ipaddr(పూర్ణాంకం sock)
{
	అక్షరం *p;

	ఒకవేళ ((p = get_socket_చిరునామా(sock, 1, NI_NUMERICHOST)) != ఖాళీ)
		తిరిగి p;
	తిరిగి xstrdup("UNKNOWN");
}

అక్షరం *
get_local_ipaddr(పూర్ణాంకం sock)
{
	అక్షరం *p;

	ఒకవేళ ((p = get_socket_చిరునామా(sock, 0, NI_NUMERICHOST)) != ఖాళీ)
		తిరిగి p;
	తిరిగి xstrdup("UNKNOWN");
}

అక్షరం *
get_local_name(పూర్ణాంకం fd)
{
	అక్షరం *host, myname[NI_MAXHOST];

	/* Assume we were passed a socket */
	ఒకవేళ ((host = get_socket_చిరునామా(fd, 0, NI_NAMEREQD)) != ఖాళీ)
		తిరిగి host;

	/* Handle the case where we were passed a pipe */
	ఒకవేళ (gethostname(myname, పరిమాణం(myname)) == -1) {
		verbose_f("gethostname: %s", strerror(errno));
		host = xstrdup("UNKNOWN");
	} లేకపోతే {
		host = xstrdup(myname);
	}

	తిరిగి host;
}

/* Returns the local/remote port for the socket. */

స్థిర పూర్ణాంకం
get_sock_పోర్టు(పూర్ణాంకం sock, పూర్ణాంకం local)
{
	నిర్మాణం sockaddr_storage from;
	socklen_t fromlen;
	అక్షరం strport[NI_MAXSERV];
	పూర్ణాంకం r;

	ఒకవేళ (sock < 0)
		తిరిగి -1;
	/* Get IP address of client. */
	fromlen = పరిమాణం(from);
	memset(&from, 0, పరిమాణం(from));
	ఒకవేళ (local) {
		ఒకవేళ (getsockname(sock, (నిర్మాణం sockaddr *)&from, &fromlen) == -1) {
			error("getsockname failed: %.100s", strerror(errno));
			తిరిగి 0;
		}
	} లేకపోతే {
		ఒకవేళ (getpeername(sock, (నిర్మాణం sockaddr *)&from, &fromlen) == -1) {
			debug("getpeername failed: %.100s", strerror(errno));
			తిరిగి -1;
		}
	}

	/* Work around Linux IPv6 weirdness */
	ఒకవేళ (from.ss_family == AF_INET6)
		fromlen = పరిమాణం(నిర్మాణం sockaddr_in6);

	/* Non-inet sockets don't have a port number. */
	ఒకవేళ (from.ss_family != AF_INET && from.ss_family != AF_INET6)
		తిరిగి 0;

	/* Return port number. */
	ఒకవేళ ((r = getnameinfo((నిర్మాణం sockaddr *)&from, fromlen, ఖాళీ, 0,
	    strport, పరిమాణం(strport), NI_NUMERICSERV)) != 0)
		fatal_f("getnameinfo NI_NUMERICSERV failed: %s",
		    ssh_gai_strerror(r));
	తిరిగి atoi(strport);
}

పూర్ణాంకం
get_peer_పోర్టు(పూర్ణాంకం sock)
{
	తిరిగి get_sock_పోర్టు(sock, 0);
}

పూర్ణాంకం
get_local_పోర్టు(పూర్ణాంకం sock)
{
	తిరిగి get_sock_పోర్టు(sock, 1);
}
