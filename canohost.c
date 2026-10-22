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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/socket.h>
#अन्तर्भाव <sys/un.h>

#अन्तर्भाव <netinet/in.h>
#अन्तर्भाव <arpa/inet.h>

#अन्तर्भाव <errno.h>
#अन्तर्भाव <netdb.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <unistd.h>

#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "canohost.h"
#अन्तर्भाव "misc.h"

शून्य
ipv64_normalise_mapped(संरचना sockaddr_storage *addr, socklen_t *len)
{
	संरचना sockaddr_in6 *a6 = (संरचना sockaddr_in6 *)addr;
	संरचना sockaddr_in *a4 = (संरचना sockaddr_in *)addr;
	संरचना in_addr inaddr;
	uint16_t port;

	सचे (addr->ss_family != AF_INET6 ||
	    !IN6_IS_ADDR_V4MAPPED(&a6->sin6_addr))
		पटिनिवत्त;

	debug3("Normalising mapped IPv4 in IPv6 address");

	memcpy(&inaddr, ((वर्ण *)&a6->sin6_addr) + 12, परिमाण(inaddr));
	port = a6->sin6_port;

	memset(a4, 0, परिमाण(*a4));

	a4->sin_family = AF_INET;
	*len = परिमाण(*a4);
	memcpy(&a4->sin_addr, &inaddr, परिमाण(inaddr));
	a4->sin_port = port;
}

/*
 * Returns the local/remote IP-address/hostname of socket as a string.
 * The returned string must be freed.
 */
स्थिर वर्ण *
get_socket_address(पूर्णाङ्क sock, पूर्णाङ्क remote, पूर्णाङ्क flags)
{
	संरचना sockaddr_storage addr;
	socklen_t addrlen;
	वर्ण ntop[NI_MAXHOST];
	पूर्णाङ्क r;

	सचे (sock < 0)
		पटिनिवत्त रिक्त;

	/* Get IP address of client. */
	addrlen = परिमाण(addr);
	memset(&addr, 0, परिमाण(addr));

	सचे (remote) {
		सचे (getpeername(sock, (संरचना sockaddr *)&addr, &addrlen) != 0)
			पटिनिवत्त रिक्त;
	} अञ्ञथा {
		सचे (getsockname(sock, (संरचना sockaddr *)&addr, &addrlen) != 0)
			पटिनिवत्त रिक्त;
	}

	/* Work around Linux IPv6 weirdness */
	सचे (addr.ss_family == AF_INET6) {
		addrlen = परिमाण(संरचना sockaddr_in6);
		ipv64_normalise_mapped(&addr, &addrlen);
	}

	विकल्प (addr.ss_family) {
	पक्ष AF_INET:
	पक्ष AF_INET6:
		/* Get the address in ascii. */
		सचे ((r = getnameinfo((संरचना sockaddr *)&addr, addrlen, ntop,
		    परिमाण(ntop), रिक्त, 0, flags)) != 0) {
			error_f("getnameinfo %d failed: %s",
			    flags, ssh_gai_strerror(r));
			पटिनिवत्त रिक्त;
		}
		पटिनिवत्त xstrdup(ntop);
	पक्ष AF_UNIX:
		/* Get the Unix domain socket path. */
		पटिनिवत्त xstrdup(((संरचना sockaddr_un *)&addr)->sun_path);
	स्वभाव:
		/* We can't look up remote Unix domain sockets. */
		पटिनिवत्त रिक्त;
	}
}

वर्ण *
get_peer_ipaddr(पूर्णाङ्क sock)
{
	वर्ण *p;

	सचे ((p = get_socket_address(sock, 1, NI_NUMERICHOST)) != रिक्त)
		पटिनिवत्त p;
	पटिनिवत्त xstrdup("UNKNOWN");
}

वर्ण *
get_local_ipaddr(पूर्णाङ्क sock)
{
	वर्ण *p;

	सचे ((p = get_socket_address(sock, 0, NI_NUMERICHOST)) != रिक्त)
		पटिनिवत्त p;
	पटिनिवत्त xstrdup("UNKNOWN");
}

वर्ण *
get_local_name(पूर्णाङ्क fd)
{
	वर्ण *host, myname[NI_MAXHOST];

	/* Assume we were passed a socket */
	सचे ((host = get_socket_address(fd, 0, NI_NAMEREQD)) != रिक्त)
		पटिनिवत्त host;

	/* Handle the case where we were passed a pipe */
	सचे (gethostname(myname, परिमाण(myname)) == -1) {
		verbose_f("gethostname: %s", strerror(errno));
		host = xstrdup("UNKNOWN");
	} अञ्ञथा {
		host = xstrdup(myname);
	}

	पटिनिवत्त host;
}

/* Returns the local/remote port for the socket. */

स्थिर पूर्णाङ्क
get_sock_port(पूर्णाङ्क sock, पूर्णाङ्क local)
{
	संरचना sockaddr_storage from;
	socklen_t fromlen;
	वर्ण strport[NI_MAXSERV];
	पूर्णाङ्क r;

	सचे (sock < 0)
		पटिनिवत्त -1;
	/* Get IP address of client. */
	fromlen = परिमाण(from);
	memset(&from, 0, परिमाण(from));
	सचे (local) {
		सचे (getsockname(sock, (संरचना sockaddr *)&from, &fromlen) == -1) {
			error("getsockname failed: %.100s", strerror(errno));
			पटिनिवत्त 0;
		}
	} अञ्ञथा {
		सचे (getpeername(sock, (संरचना sockaddr *)&from, &fromlen) == -1) {
			debug("getpeername failed: %.100s", strerror(errno));
			पटिनिवत्त -1;
		}
	}

	/* Work around Linux IPv6 weirdness */
	सचे (from.ss_family == AF_INET6)
		fromlen = परिमाण(संरचना sockaddr_in6);

	/* Non-inet sockets don't have a port number. */
	सचे (from.ss_family != AF_INET && from.ss_family != AF_INET6)
		पटिनिवत्त 0;

	/* Return port number. */
	सचे ((r = getnameinfo((संरचना sockaddr *)&from, fromlen, रिक्त, 0,
	    strport, परिमाण(strport), NI_NUMERICSERV)) != 0)
		fatal_f("getnameinfo NI_NUMERICSERV failed: %s",
		    ssh_gai_strerror(r));
	पटिनिवत्त atoi(strport);
}

पूर्णाङ्क
get_peer_port(पूर्णाङ्क sock)
{
	पटिनिवत्त get_sock_port(sock, 0);
}

पूर्णाङ्क
get_local_port(पूर्णाङ्क sock)
{
	पटिनिवत्त get_sock_port(sock, 1);
}
