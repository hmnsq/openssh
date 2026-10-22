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
ipv64_normalise_mapped(সংরচনা sockaddr_storage *addr, socklen_t *len)
{
	সংরচনা sockaddr_in6 *a6 = (সংরচনা sockaddr_in6 *)addr;
	সংরচনা sockaddr_in *a4 = (সংরচনা sockaddr_in *)addr;
	সংরচনা in_addr inaddr;
	uint16_t port;

	যদি (addr->ss_family != AF_INET6 ||
	    !IN6_IS_ADDR_V4MAPPED(&a6->sin6_addr))
		প্রত্যাগম;

	debug3("Normalising mapped IPv4 in IPv6 address");

	memcpy(&inaddr, ((বর্ণ *)&a6->sin6_addr) + 12, পরিমাণ(inaddr));
	port = a6->sin6_port;

	memset(a4, 0, পরিমাণ(*a4));

	a4->sin_family = AF_INET;
	*len = পরিমাণ(*a4);
	memcpy(&a4->sin_addr, &inaddr, পরিমাণ(inaddr));
	a4->sin_port = port;
}

/*
 * Returns the local/remote IP-address/hostname of socket as a string.
 * The returned string must be freed.
 */
স্থির বর্ণ *
get_socket_address(পূর্ণাঙ্ক sock, পূর্ণাঙ্ক remote, পূর্ণাঙ্ক flags)
{
	সংরচনা sockaddr_storage addr;
	socklen_t addrlen;
	বর্ণ ntop[NI_MAXHOST];
	পূর্ণাঙ্ক r;

	যদি (sock < 0)
		প্রত্যাগম রিক্ত;

	/* Get IP address of client. */
	addrlen = পরিমাণ(addr);
	memset(&addr, 0, পরিমাণ(addr));

	যদি (remote) {
		যদি (getpeername(sock, (সংরচনা sockaddr *)&addr, &addrlen) != 0)
			প্রত্যাগম রিক্ত;
	} অন্যথা {
		যদি (getsockname(sock, (সংরচনা sockaddr *)&addr, &addrlen) != 0)
			প্রত্যাগম রিক্ত;
	}

	/* Work around Linux IPv6 weirdness */
	যদি (addr.ss_family == AF_INET6) {
		addrlen = পরিমাণ(সংরচনা sockaddr_in6);
		ipv64_normalise_mapped(&addr, &addrlen);
	}

	বিকল্প (addr.ss_family) {
	পক্ষ AF_INET:
	পক্ষ AF_INET6:
		/* Get the address in ascii. */
		যদি ((r = getnameinfo((সংরচনা sockaddr *)&addr, addrlen, ntop,
		    পরিমাণ(ntop), রিক্ত, 0, flags)) != 0) {
			error_f("getnameinfo %d failed: %s",
			    flags, ssh_gai_strerror(r));
			প্রত্যাগম রিক্ত;
		}
		প্রত্যাগম xstrdup(ntop);
	পক্ষ AF_UNIX:
		/* Get the Unix domain socket path. */
		প্রত্যাগম xstrdup(((সংরচনা sockaddr_un *)&addr)->sun_path);
	স্বভাব:
		/* We can't look up remote Unix domain sockets. */
		প্রত্যাগম রিক্ত;
	}
}

বর্ণ *
get_peer_ipaddr(পূর্ণাঙ্ক sock)
{
	বর্ণ *p;

	যদি ((p = get_socket_address(sock, 1, NI_NUMERICHOST)) != রিক্ত)
		প্রত্যাগম p;
	প্রত্যাগম xstrdup("UNKNOWN");
}

বর্ণ *
get_local_ipaddr(পূর্ণাঙ্ক sock)
{
	বর্ণ *p;

	যদি ((p = get_socket_address(sock, 0, NI_NUMERICHOST)) != রিক্ত)
		প্রত্যাগম p;
	প্রত্যাগম xstrdup("UNKNOWN");
}

বর্ণ *
get_local_name(পূর্ণাঙ্ক fd)
{
	বর্ণ *host, myname[NI_MAXHOST];

	/* Assume we were passed a socket */
	যদি ((host = get_socket_address(fd, 0, NI_NAMEREQD)) != রিক্ত)
		প্রত্যাগম host;

	/* Handle the case where we were passed a pipe */
	যদি (gethostname(myname, পরিমাণ(myname)) == -1) {
		verbose_f("gethostname: %s", strerror(errno));
		host = xstrdup("UNKNOWN");
	} অন্যথা {
		host = xstrdup(myname);
	}

	প্রত্যাগম host;
}

/* Returns the local/remote port for the socket. */

স্থির পূর্ণাঙ্ক
get_sock_port(পূর্ণাঙ্ক sock, পূর্ণাঙ্ক local)
{
	সংরচনা sockaddr_storage from;
	socklen_t fromlen;
	বর্ণ strport[NI_MAXSERV];
	পূর্ণাঙ্ক r;

	যদি (sock < 0)
		প্রত্যাগম -1;
	/* Get IP address of client. */
	fromlen = পরিমাণ(from);
	memset(&from, 0, পরিমাণ(from));
	যদি (local) {
		যদি (getsockname(sock, (সংরচনা sockaddr *)&from, &fromlen) == -1) {
			error("getsockname failed: %.100s", strerror(errno));
			প্রত্যাগম 0;
		}
	} অন্যথা {
		যদি (getpeername(sock, (সংরচনা sockaddr *)&from, &fromlen) == -1) {
			debug("getpeername failed: %.100s", strerror(errno));
			প্রত্যাগম -1;
		}
	}

	/* Work around Linux IPv6 weirdness */
	যদি (from.ss_family == AF_INET6)
		fromlen = পরিমাণ(সংরচনা sockaddr_in6);

	/* Non-inet sockets don't have a port number. */
	যদি (from.ss_family != AF_INET && from.ss_family != AF_INET6)
		প্রত্যাগম 0;

	/* Return port number. */
	যদি ((r = getnameinfo((সংরচনা sockaddr *)&from, fromlen, রিক্ত, 0,
	    strport, পরিমাণ(strport), NI_NUMERICSERV)) != 0)
		fatal_f("getnameinfo NI_NUMERICSERV failed: %s",
		    ssh_gai_strerror(r));
	প্রত্যাগম atoi(strport);
}

পূর্ণাঙ্ক
get_peer_port(পূর্ণাঙ্ক sock)
{
	প্রত্যাগম get_sock_port(sock, 0);
}

পূর্ণাঙ্ক
get_local_port(পূর্ণাঙ্ক sock)
{
	প্রত্যাগম get_sock_port(sock, 1);
}
