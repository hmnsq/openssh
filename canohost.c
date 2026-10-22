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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/socket.h>
#ଅନ୍ତର୍ଭାଵ <sys/un.h>

#ଅନ୍ତର୍ଭାଵ <netinet/in.h>
#ଅନ୍ତର୍ଭାଵ <arpa/inet.h>

#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <netdb.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>

#ଅନ୍ତର୍ଭାଵ "xmalloc.h"
#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "canohost.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"

ଶୂନ୍ୟ
ipv64_normalise_mapped(ସଂରଚନା sockaddr_storage *addr, socklen_t *len)
{
	ସଂରଚନା sockaddr_in6 *a6 = (ସଂରଚନା sockaddr_in6 *)addr;
	ସଂରଚନା sockaddr_in *a4 = (ସଂରଚନା sockaddr_in *)addr;
	ସଂରଚନା in_addr inaddr;
	uint16_t port;

	ଯଦି (addr->ss_family != AF_INET6 ||
	    !IN6_IS_ADDR_V4MAPPED(&a6->sin6_addr))
		ଫେରନ୍ତୁ;

	debug3("Normalising mapped IPv4 in IPv6 address");

	memcpy(&inaddr, ((ଅକ୍ଷର *)&a6->sin6_addr) + 12, ଆକାର(inaddr));
	port = a6->sin6_port;

	memset(a4, 0, ଆକାର(*a4));

	a4->sin_family = AF_INET;
	*len = ଆକାର(*a4);
	memcpy(&a4->sin_addr, &inaddr, ଆକାର(inaddr));
	a4->sin_port = port;
}

/*
 * Returns the local/remote IP-address/hostname of socket as a string.
 * The returned string must be freed.
 */
ସ୍ଥିର ଅକ୍ଷର *
get_socket_address(ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock, ପୂର୍ଣ୍ଣସଂଖ୍ୟା remote, ପୂର୍ଣ୍ଣସଂଖ୍ୟା flags)
{
	ସଂରଚନା sockaddr_storage addr;
	socklen_t addrlen;
	ଅକ୍ଷର ntop[NI_MAXHOST];
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (sock < 0)
		ଫେରନ୍ତୁ ଖାଲି;

	/* Get IP address of client. */
	addrlen = ଆକାର(addr);
	memset(&addr, 0, ଆକାର(addr));

	ଯଦି (remote) {
		ଯଦି (getpeername(sock, (ସଂରଚନା sockaddr *)&addr, &addrlen) != 0)
			ଫେରନ୍ତୁ ଖାଲି;
	} ଅନ୍ୟଥା {
		ଯଦି (getsockname(sock, (ସଂରଚନା sockaddr *)&addr, &addrlen) != 0)
			ଫେରନ୍ତୁ ଖାଲି;
	}

	/* Work around Linux IPv6 weirdness */
	ଯଦି (addr.ss_family == AF_INET6) {
		addrlen = ଆକାର(ସଂରଚନା sockaddr_in6);
		ipv64_normalise_mapped(&addr, &addrlen);
	}

	ବାଛ (addr.ss_family) {
	ସ୍ଥିତି AF_INET:
	ସ୍ଥିତି AF_INET6:
		/* Get the address in ascii. */
		ଯଦି ((r = getnameinfo((ସଂରଚନା sockaddr *)&addr, addrlen, ntop,
		    ଆକାର(ntop), ଖାଲି, 0, flags)) != 0) {
			error_f("getnameinfo %d failed: %s",
			    flags, ssh_gai_strerror(r));
			ଫେରନ୍ତୁ ଖାଲି;
		}
		ଫେରନ୍ତୁ xstrdup(ntop);
	ସ୍ଥିତି AF_UNIX:
		/* Get the Unix domain socket path. */
		ଫେରନ୍ତୁ xstrdup(((ସଂରଚନା sockaddr_un *)&addr)->sun_path);
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		/* We can't look up remote Unix domain sockets. */
		ଫେରନ୍ତୁ ଖାଲି;
	}
}

ଅକ୍ଷର *
get_peer_ipaddr(ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock)
{
	ଅକ୍ଷର *p;

	ଯଦି ((p = get_socket_address(sock, 1, NI_NUMERICHOST)) != ଖାଲି)
		ଫେରନ୍ତୁ p;
	ଫେରନ୍ତୁ xstrdup("UNKNOWN");
}

ଅକ୍ଷର *
get_local_ipaddr(ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock)
{
	ଅକ୍ଷର *p;

	ଯଦି ((p = get_socket_address(sock, 0, NI_NUMERICHOST)) != ଖାଲି)
		ଫେରନ୍ତୁ p;
	ଫେରନ୍ତୁ xstrdup("UNKNOWN");
}

ଅକ୍ଷର *
get_local_name(ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd)
{
	ଅକ୍ଷର *host, myname[NI_MAXHOST];

	/* Assume we were passed a socket */
	ଯଦି ((host = get_socket_address(fd, 0, NI_NAMEREQD)) != ଖାଲି)
		ଫେରନ୍ତୁ host;

	/* Handle the case where we were passed a pipe */
	ଯଦି (gethostname(myname, ଆକାର(myname)) == -1) {
		verbose_f("gethostname: %s", strerror(errno));
		host = xstrdup("UNKNOWN");
	} ଅନ୍ୟଥା {
		host = xstrdup(myname);
	}

	ଫେରନ୍ତୁ host;
}

/* Returns the local/remote port for the socket. */

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
get_sock_port(ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock, ପୂର୍ଣ୍ଣସଂଖ୍ୟା local)
{
	ସଂରଚନା sockaddr_storage from;
	socklen_t fromlen;
	ଅକ୍ଷର strport[NI_MAXSERV];
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (sock < 0)
		ଫେରନ୍ତୁ -1;
	/* Get IP address of client. */
	fromlen = ଆକାର(from);
	memset(&from, 0, ଆକାର(from));
	ଯଦି (local) {
		ଯଦି (getsockname(sock, (ସଂରଚନା sockaddr *)&from, &fromlen) == -1) {
			error("getsockname failed: %.100s", strerror(errno));
			ଫେରନ୍ତୁ 0;
		}
	} ଅନ୍ୟଥା {
		ଯଦି (getpeername(sock, (ସଂରଚନା sockaddr *)&from, &fromlen) == -1) {
			debug("getpeername failed: %.100s", strerror(errno));
			ଫେରନ୍ତୁ -1;
		}
	}

	/* Work around Linux IPv6 weirdness */
	ଯଦି (from.ss_family == AF_INET6)
		fromlen = ଆକାର(ସଂରଚନା sockaddr_in6);

	/* Non-inet sockets don't have a port number. */
	ଯଦି (from.ss_family != AF_INET && from.ss_family != AF_INET6)
		ଫେରନ୍ତୁ 0;

	/* Return port number. */
	ଯଦି ((r = getnameinfo((ସଂରଚନା sockaddr *)&from, fromlen, ଖାଲି, 0,
	    strport, ଆକାର(strport), NI_NUMERICSERV)) != 0)
		fatal_f("getnameinfo NI_NUMERICSERV failed: %s",
		    ssh_gai_strerror(r));
	ଫେରନ୍ତୁ atoi(strport);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
get_peer_port(ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock)
{
	ଫେରନ୍ତୁ get_sock_port(sock, 0);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
get_local_port(ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock)
{
	ଫେରନ୍ତୁ get_sock_port(sock, 1);
}
