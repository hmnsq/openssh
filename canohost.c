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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/socket.h>
#અન્તર્ભાવ <sys/un.h>

#અન્તર્ભાવ <netinet/in.h>
#અન્તર્ભાવ <arpa/inet.h>

#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <netdb.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <unistd.h>

#અન્તર્ભાવ "xmalloc.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "canohost.h"
#અન્તર્ભાવ "misc.h"

શૂન્ય
ipv64_normalise_mapped(સંરચના sockaddr_storage *addr, socklen_t *len)
{
	સંરચના sockaddr_in6 *a6 = (સંરચના sockaddr_in6 *)addr;
	સંરચના sockaddr_in *a4 = (સંરચના sockaddr_in *)addr;
	સંરચના in_addr inaddr;
	uint16_t port;

	જો (addr->ss_family != AF_INET6 ||
	    !IN6_IS_ADDR_V4MAPPED(&a6->sin6_addr))
		પાછા;

	debug3("Normalising mapped IPv4 in IPv6 address");

	memcpy(&inaddr, ((અક્ષર *)&a6->sin6_addr) + 12, કદ(inaddr));
	port = a6->sin6_port;

	memset(a4, 0, કદ(*a4));

	a4->sin_family = AF_INET;
	*len = કદ(*a4);
	memcpy(&a4->sin_addr, &inaddr, કદ(inaddr));
	a4->sin_port = port;
}

/*
 * Returns the local/remote IP-address/hostname of socket as a string.
 * The returned string must be freed.
 */
સ્થિર અક્ષર *
get_socket_address(પૂર્ણાંક sock, પૂર્ણાંક remote, પૂર્ણાંક flags)
{
	સંરચના sockaddr_storage addr;
	socklen_t addrlen;
	અક્ષર ntop[NI_MAXHOST];
	પૂર્ણાંક r;

	જો (sock < 0)
		પાછા ખાલી;

	/* Get IP address of client. */
	addrlen = કદ(addr);
	memset(&addr, 0, કદ(addr));

	જો (remote) {
		જો (getpeername(sock, (સંરચના sockaddr *)&addr, &addrlen) != 0)
			પાછા ખાલી;
	} નહીંતર {
		જો (getsockname(sock, (સંરચના sockaddr *)&addr, &addrlen) != 0)
			પાછા ખાલી;
	}

	/* Work around Linux IPv6 weirdness */
	જો (addr.ss_family == AF_INET6) {
		addrlen = કદ(સંરચના sockaddr_in6);
		ipv64_normalise_mapped(&addr, &addrlen);
	}

	પસંદગી (addr.ss_family) {
	સ્થિતિ AF_INET:
	સ્થિતિ AF_INET6:
		/* Get the address in ascii. */
		જો ((r = getnameinfo((સંરચના sockaddr *)&addr, addrlen, ntop,
		    કદ(ntop), ખાલી, 0, flags)) != 0) {
			error_f("getnameinfo %d failed: %s",
			    flags, ssh_gai_strerror(r));
			પાછા ખાલી;
		}
		પાછા xstrdup(ntop);
	સ્થિતિ AF_UNIX:
		/* Get the Unix domain socket path. */
		પાછા xstrdup(((સંરચના sockaddr_un *)&addr)->sun_path);
	મૂળભૂત:
		/* We can't look up remote Unix domain sockets. */
		પાછા ખાલી;
	}
}

અક્ષર *
get_peer_ipaddr(પૂર્ણાંક sock)
{
	અક્ષર *p;

	જો ((p = get_socket_address(sock, 1, NI_NUMERICHOST)) != ખાલી)
		પાછા p;
	પાછા xstrdup("UNKNOWN");
}

અક્ષર *
get_local_ipaddr(પૂર્ણાંક sock)
{
	અક્ષર *p;

	જો ((p = get_socket_address(sock, 0, NI_NUMERICHOST)) != ખાલી)
		પાછા p;
	પાછા xstrdup("UNKNOWN");
}

અક્ષર *
get_local_name(પૂર્ણાંક fd)
{
	અક્ષર *host, myname[NI_MAXHOST];

	/* Assume we were passed a socket */
	જો ((host = get_socket_address(fd, 0, NI_NAMEREQD)) != ખાલી)
		પાછા host;

	/* Handle the case where we were passed a pipe */
	જો (gethostname(myname, કદ(myname)) == -1) {
		verbose_f("gethostname: %s", strerror(errno));
		host = xstrdup("UNKNOWN");
	} નહીંતર {
		host = xstrdup(myname);
	}

	પાછા host;
}

/* Returns the local/remote port for the socket. */

સ્થિર પૂર્ણાંક
get_sock_port(પૂર્ણાંક sock, પૂર્ણાંક local)
{
	સંરચના sockaddr_storage from;
	socklen_t fromlen;
	અક્ષર strport[NI_MAXSERV];
	પૂર્ણાંક r;

	જો (sock < 0)
		પાછા -1;
	/* Get IP address of client. */
	fromlen = કદ(from);
	memset(&from, 0, કદ(from));
	જો (local) {
		જો (getsockname(sock, (સંરચના sockaddr *)&from, &fromlen) == -1) {
			error("getsockname failed: %.100s", strerror(errno));
			પાછા 0;
		}
	} નહીંતર {
		જો (getpeername(sock, (સંરચના sockaddr *)&from, &fromlen) == -1) {
			debug("getpeername failed: %.100s", strerror(errno));
			પાછા -1;
		}
	}

	/* Work around Linux IPv6 weirdness */
	જો (from.ss_family == AF_INET6)
		fromlen = કદ(સંરચના sockaddr_in6);

	/* Non-inet sockets don't have a port number. */
	જો (from.ss_family != AF_INET && from.ss_family != AF_INET6)
		પાછા 0;

	/* Return port number. */
	જો ((r = getnameinfo((સંરચના sockaddr *)&from, fromlen, ખાલી, 0,
	    strport, કદ(strport), NI_NUMERICSERV)) != 0)
		fatal_f("getnameinfo NI_NUMERICSERV failed: %s",
		    ssh_gai_strerror(r));
	પાછા atoi(strport);
}

પૂર્ણાંક
get_peer_port(પૂર્ણાંક sock)
{
	પાછા get_sock_port(sock, 0);
}

પૂર્ણાંક
get_local_port(પૂર્ણાંક sock)
{
	પાછા get_sock_port(sock, 1);
}
