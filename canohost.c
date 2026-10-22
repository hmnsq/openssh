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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <sys/socket.h>
#অন্তর্ভাব <sys/un.h>

#অন্তর্ভাব <netinet/in.h>
#অন্তর্ভাব <arpa/inet.h>

#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <netdb.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <unistd.h>

#অন্তর্ভাব "xmalloc.h"
#অন্তর্ভাব "log.h"
#অন্তর্ভাব "canohost.h"
#অন্তর্ভাব "misc.h"

শূন্য
ipv64_normalise_mapped(কাঠামো sockaddr_storage *addr, socklen_t *len)
{
	কাঠামো sockaddr_in6 *a6 = (কাঠামো sockaddr_in6 *)addr;
	কাঠামো sockaddr_in *a4 = (কাঠামো sockaddr_in *)addr;
	কাঠামো in_addr inaddr;
	uint16_t port;

	যদি (addr->ss_family != AF_INET6 ||
	    !IN6_IS_ADDR_V4MAPPED(&a6->sin6_addr))
		ফেরত;

	debug3("Normalising mapped IPv4 in IPv6 address");

	memcpy(&inaddr, ((অক্ষর *)&a6->sin6_addr) + 12, আকার(inaddr));
	port = a6->sin6_port;

	memset(a4, 0, আকার(*a4));

	a4->sin_family = AF_INET;
	*len = আকার(*a4);
	memcpy(&a4->sin_addr, &inaddr, আকার(inaddr));
	a4->sin_port = port;
}

/*
 * Returns the local/remote IP-address/hostname of socket as a string.
 * The returned string must be freed.
 */
স্থির অক্ষর *
get_socket_address(পূর্ণসংখ্যা sock, পূর্ণসংখ্যা remote, পূর্ণসংখ্যা flags)
{
	কাঠামো sockaddr_storage addr;
	socklen_t addrlen;
	অক্ষর ntop[NI_MAXHOST];
	পূর্ণসংখ্যা r;

	যদি (sock < 0)
		ফেরত ফাঁকা;

	/* Get IP address of client. */
	addrlen = আকার(addr);
	memset(&addr, 0, আকার(addr));

	যদি (remote) {
		যদি (getpeername(sock, (কাঠামো sockaddr *)&addr, &addrlen) != 0)
			ফেরত ফাঁকা;
	} অন্যথা {
		যদি (getsockname(sock, (কাঠামো sockaddr *)&addr, &addrlen) != 0)
			ফেরত ফাঁকা;
	}

	/* Work around Linux IPv6 weirdness */
	যদি (addr.ss_family == AF_INET6) {
		addrlen = আকার(কাঠামো sockaddr_in6);
		ipv64_normalise_mapped(&addr, &addrlen);
	}

	নির্বাচন (addr.ss_family) {
	ক্ষেত্র AF_INET:
	ক্ষেত্র AF_INET6:
		/* Get the address in ascii. */
		যদি ((r = getnameinfo((কাঠামো sockaddr *)&addr, addrlen, ntop,
		    আকার(ntop), ফাঁকা, 0, flags)) != 0) {
			error_f("getnameinfo %d failed: %s",
			    flags, ssh_gai_strerror(r));
			ফেরত ফাঁকা;
		}
		ফেরত xstrdup(ntop);
	ক্ষেত্র AF_UNIX:
		/* Get the Unix domain socket path. */
		ফেরত xstrdup(((কাঠামো sockaddr_un *)&addr)->sun_path);
	পূর্বনির্ধারিত:
		/* We can't look up remote Unix domain sockets. */
		ফেরত ফাঁকা;
	}
}

অক্ষর *
get_peer_ipaddr(পূর্ণসংখ্যা sock)
{
	অক্ষর *p;

	যদি ((p = get_socket_address(sock, 1, NI_NUMERICHOST)) != ফাঁকা)
		ফেরত p;
	ফেরত xstrdup("UNKNOWN");
}

অক্ষর *
get_local_ipaddr(পূর্ণসংখ্যা sock)
{
	অক্ষর *p;

	যদি ((p = get_socket_address(sock, 0, NI_NUMERICHOST)) != ফাঁকা)
		ফেরত p;
	ফেরত xstrdup("UNKNOWN");
}

অক্ষর *
get_local_name(পূর্ণসংখ্যা fd)
{
	অক্ষর *host, myname[NI_MAXHOST];

	/* Assume we were passed a socket */
	যদি ((host = get_socket_address(fd, 0, NI_NAMEREQD)) != ফাঁকা)
		ফেরত host;

	/* Handle the case where we were passed a pipe */
	যদি (gethostname(myname, আকার(myname)) == -1) {
		verbose_f("gethostname: %s", strerror(errno));
		host = xstrdup("UNKNOWN");
	} অন্যথা {
		host = xstrdup(myname);
	}

	ফেরত host;
}

/* Returns the local/remote port for the socket. */

স্থির পূর্ণসংখ্যা
get_sock_port(পূর্ণসংখ্যা sock, পূর্ণসংখ্যা local)
{
	কাঠামো sockaddr_storage from;
	socklen_t fromlen;
	অক্ষর strport[NI_MAXSERV];
	পূর্ণসংখ্যা r;

	যদি (sock < 0)
		ফেরত -1;
	/* Get IP address of client. */
	fromlen = আকার(from);
	memset(&from, 0, আকার(from));
	যদি (local) {
		যদি (getsockname(sock, (কাঠামো sockaddr *)&from, &fromlen) == -1) {
			error("getsockname failed: %.100s", strerror(errno));
			ফেরত 0;
		}
	} অন্যথা {
		যদি (getpeername(sock, (কাঠামো sockaddr *)&from, &fromlen) == -1) {
			debug("getpeername failed: %.100s", strerror(errno));
			ফেরত -1;
		}
	}

	/* Work around Linux IPv6 weirdness */
	যদি (from.ss_family == AF_INET6)
		fromlen = আকার(কাঠামো sockaddr_in6);

	/* Non-inet sockets don't have a port number. */
	যদি (from.ss_family != AF_INET && from.ss_family != AF_INET6)
		ফেরত 0;

	/* Return port number. */
	যদি ((r = getnameinfo((কাঠামো sockaddr *)&from, fromlen, ফাঁকা, 0,
	    strport, আকার(strport), NI_NUMERICSERV)) != 0)
		fatal_f("getnameinfo NI_NUMERICSERV failed: %s",
		    ssh_gai_strerror(r));
	ফেরত atoi(strport);
}

পূর্ণসংখ্যা
get_peer_port(পূর্ণসংখ্যা sock)
{
	ফেরত get_sock_port(sock, 0);
}

পূর্ণসংখ্যা
get_local_port(পূর্ণসংখ্যা sock)
{
	ফেরত get_sock_port(sock, 1);
}
