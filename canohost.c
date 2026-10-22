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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/socket.h>
#شامل <sys/un.h>

#شامل <netinet/in.h>
#شامل <arpa/inet.h>

#شامل <errno.h>
#شامل <netdb.h>
#شامل <stdio.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <stdarg.h>
#شامل <unistd.h>

#شامل "xmalloc.h"
#شامل "log.h"
#شامل "canohost.h"
#شامل "misc.h"

تهی
ipv64_normalise_mapped(ساختار sockaddr_storage *addr, socklen_t *len)
{
	ساختار sockaddr_in6 *a6 = (ساختار sockaddr_in6 *)addr;
	ساختار sockaddr_in *a4 = (ساختار sockaddr_in *)addr;
	ساختار in_addr inaddr;
	uint16_t port;

	اگر (addr->ss_family != AF_INET6 ||
	    !IN6_IS_ADDR_V4MAPPED(&a6->sin6_addr))
		بازگشت;

	debug3("Normalising mapped IPv4 in IPv6 address");

	memcpy(&inaddr, ((نویسه *)&a6->sin6_addr) + 12, اندازه(inaddr));
	port = a6->sin6_port;

	memset(a4, 0, اندازه(*a4));

	a4->sin_family = AF_INET;
	*len = اندازه(*a4);
	memcpy(&a4->sin_addr, &inaddr, اندازه(inaddr));
	a4->sin_port = port;
}

/*
 * Returns the local/remote IP-address/hostname of socket as a string.
 * The returned string must be freed.
 */
ایستا نویسه *
get_socket_address(صحیح sock, صحیح remote, صحیح flags)
{
	ساختار sockaddr_storage addr;
	socklen_t addrlen;
	نویسه ntop[NI_MAXHOST];
	صحیح r;

	اگر (sock < 0)
		بازگشت پوچ;

	/* Get IP address of client. */
	addrlen = اندازه(addr);
	memset(&addr, 0, اندازه(addr));

	اگر (remote) {
		اگر (getpeername(sock, (ساختار sockaddr *)&addr, &addrlen) != 0)
			بازگشت پوچ;
	} وگرنه {
		اگر (getsockname(sock, (ساختار sockaddr *)&addr, &addrlen) != 0)
			بازگشت پوچ;
	}

	/* Work around Linux IPv6 weirdness */
	اگر (addr.ss_family == AF_INET6) {
		addrlen = اندازه(ساختار sockaddr_in6);
		ipv64_normalise_mapped(&addr, &addrlen);
	}

	انتخاب (addr.ss_family) {
	حالت AF_INET:
	حالت AF_INET6:
		/* Get the address in ascii. */
		اگر ((r = getnameinfo((ساختار sockaddr *)&addr, addrlen, ntop,
		    اندازه(ntop), پوچ, 0, flags)) != 0) {
			error_f("getnameinfo %d failed: %s",
			    flags, ssh_gai_strerror(r));
			بازگشت پوچ;
		}
		بازگشت xstrdup(ntop);
	حالت AF_UNIX:
		/* Get the Unix domain socket path. */
		بازگشت xstrdup(((ساختار sockaddr_un *)&addr)->sun_path);
	پیشفرض:
		/* We can't look up remote Unix domain sockets. */
		بازگشت پوچ;
	}
}

نویسه *
get_peer_ipaddr(صحیح sock)
{
	نویسه *p;

	اگر ((p = get_socket_address(sock, 1, NI_NUMERICHOST)) != پوچ)
		بازگشت p;
	بازگشت xstrdup("UNKNOWN");
}

نویسه *
get_local_ipaddr(صحیح sock)
{
	نویسه *p;

	اگر ((p = get_socket_address(sock, 0, NI_NUMERICHOST)) != پوچ)
		بازگشت p;
	بازگشت xstrdup("UNKNOWN");
}

نویسه *
get_local_name(صحیح fd)
{
	نویسه *host, myname[NI_MAXHOST];

	/* Assume we were passed a socket */
	اگر ((host = get_socket_address(fd, 0, NI_NAMEREQD)) != پوچ)
		بازگشت host;

	/* Handle the case where we were passed a pipe */
	اگر (gethostname(myname, اندازه(myname)) == -1) {
		verbose_f("gethostname: %s", strerror(errno));
		host = xstrdup("UNKNOWN");
	} وگرنه {
		host = xstrdup(myname);
	}

	بازگشت host;
}

/* Returns the local/remote port for the socket. */

ایستا صحیح
get_sock_port(صحیح sock, صحیح local)
{
	ساختار sockaddr_storage from;
	socklen_t fromlen;
	نویسه strport[NI_MAXSERV];
	صحیح r;

	اگر (sock < 0)
		بازگشت -1;
	/* Get IP address of client. */
	fromlen = اندازه(from);
	memset(&from, 0, اندازه(from));
	اگر (local) {
		اگر (getsockname(sock, (ساختار sockaddr *)&from, &fromlen) == -1) {
			error("getsockname failed: %.100s", strerror(errno));
			بازگشت 0;
		}
	} وگرنه {
		اگر (getpeername(sock, (ساختار sockaddr *)&from, &fromlen) == -1) {
			debug("getpeername failed: %.100s", strerror(errno));
			بازگشت -1;
		}
	}

	/* Work around Linux IPv6 weirdness */
	اگر (from.ss_family == AF_INET6)
		fromlen = اندازه(ساختار sockaddr_in6);

	/* Non-inet sockets don't have a port number. */
	اگر (from.ss_family != AF_INET && from.ss_family != AF_INET6)
		بازگشت 0;

	/* Return port number. */
	اگر ((r = getnameinfo((ساختار sockaddr *)&from, fromlen, پوچ, 0,
	    strport, اندازه(strport), NI_NUMERICSERV)) != 0)
		fatal_f("getnameinfo NI_NUMERICSERV failed: %s",
		    ssh_gai_strerror(r));
	بازگشت atoi(strport);
}

صحیح
get_peer_port(صحیح sock)
{
	بازگشت get_sock_port(sock, 0);
}

صحیح
get_local_port(صحیح sock)
{
	بازگشت get_sock_port(sock, 1);
}
