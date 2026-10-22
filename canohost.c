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

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <sys/socket.h>
#समावेश <sys/un.h>

#समावेश <netinet/in.h>
#समावेश <arpa/inet.h>

#समावेश <errno.h>
#समावेश <netdb.h>
#समावेश <stdio.h>
#समावेश <stdlib.h>
#समावेश <string.h>
#समावेश <stdarg.h>
#समावेश <unistd.h>

#समावेश "xmalloc.h"
#समावेश "log.h"
#समावेश "canohost.h"
#समावेश "misc.h"

व्योम
ipv64_normalise_mapped(काष्ठा sockaddr_storage *addr, socklen_t *len)
{
	काष्ठा sockaddr_in6 *a6 = (काष्ठा sockaddr_in6 *)addr;
	काष्ठा sockaddr_in *a4 = (काष्ठा sockaddr_in *)addr;
	काष्ठा in_addr inaddr;
	uint16_t port;

	अगर (addr->ss_family != AF_INET6 ||
	    !IN6_IS_ADDR_V4MAPPED(&a6->sin6_addr))
		वापस;

	debug3("Normalising mapped IPv4 in IPv6 address");

	स_नकल(&inaddr, ((अक्षर *)&a6->sin6_addr) + 12, माप(inaddr));
	port = a6->sin6_port;

	स_रखो(a4, 0, माप(*a4));

	a4->sin_family = AF_INET;
	*len = माप(*a4);
	स_नकल(&a4->sin_addr, &inaddr, माप(inaddr));
	a4->sin_port = port;
}

/*
 * Returns the local/remote IP-address/hostname of socket as a string.
 * The returned string must be freed.
 */
अटल अक्षर *
get_socket_address(पूर्णांक sock, पूर्णांक remote, पूर्णांक flags)
{
	काष्ठा sockaddr_storage addr;
	socklen_t addrlen;
	अक्षर ntop[NI_MAXHOST];
	पूर्णांक r;

	अगर (sock < 0)
		वापस शून्य;

	/* Get IP address of client. */
	addrlen = माप(addr);
	स_रखो(&addr, 0, माप(addr));

	अगर (remote) {
		अगर (getpeername(sock, (काष्ठा sockaddr *)&addr, &addrlen) != 0)
			वापस शून्य;
	} अन्यथा {
		अगर (getsockname(sock, (काष्ठा sockaddr *)&addr, &addrlen) != 0)
			वापस शून्य;
	}

	/* Work around Linux IPv6 weirdness */
	अगर (addr.ss_family == AF_INET6) {
		addrlen = माप(काष्ठा sockaddr_in6);
		ipv64_normalise_mapped(&addr, &addrlen);
	}

	चयन (addr.ss_family) {
	हाल AF_INET:
	हाल AF_INET6:
		/* Get the address in ascii. */
		अगर ((r = getnameinfo((काष्ठा sockaddr *)&addr, addrlen, ntop,
		    माप(ntop), शून्य, 0, flags)) != 0) {
			error_f("getnameinfo %d failed: %s",
			    flags, ssh_gai_strerror(r));
			वापस शून्य;
		}
		वापस xstrdup(ntop);
	हाल AF_UNIX:
		/* Get the Unix domain socket path. */
		वापस xstrdup(((काष्ठा sockaddr_un *)&addr)->sun_path);
	शेष:
		/* We can't look up remote Unix domain sockets. */
		वापस शून्य;
	}
}

अक्षर *
get_peer_ipaddr(पूर्णांक sock)
{
	अक्षर *p;

	अगर ((p = get_socket_address(sock, 1, NI_NUMERICHOST)) != शून्य)
		वापस p;
	वापस xstrdup("UNKNOWN");
}

अक्षर *
get_local_ipaddr(पूर्णांक sock)
{
	अक्षर *p;

	अगर ((p = get_socket_address(sock, 0, NI_NUMERICHOST)) != शून्य)
		वापस p;
	वापस xstrdup("UNKNOWN");
}

अक्षर *
get_local_name(पूर्णांक fd)
{
	अक्षर *host, myname[NI_MAXHOST];

	/* Assume we were passed a socket */
	अगर ((host = get_socket_address(fd, 0, NI_NAMEREQD)) != शून्य)
		वापस host;

	/* Handle the case where we were passed a pipe */
	अगर (gethostname(myname, माप(myname)) == -1) {
		verbose_f("gethostname: %s", म_त्रुटि(त्रुटि_सं));
		host = xstrdup("UNKNOWN");
	} अन्यथा {
		host = xstrdup(myname);
	}

	वापस host;
}

/* Returns the local/remote port for the socket. */

अटल पूर्णांक
get_sock_port(पूर्णांक sock, पूर्णांक local)
{
	काष्ठा sockaddr_storage from;
	socklen_t fromlen;
	अक्षर strport[NI_MAXSERV];
	पूर्णांक r;

	अगर (sock < 0)
		वापस -1;
	/* Get IP address of client. */
	fromlen = माप(from);
	स_रखो(&from, 0, माप(from));
	अगर (local) {
		अगर (getsockname(sock, (काष्ठा sockaddr *)&from, &fromlen) == -1) {
			error("getsockname failed: %.100s", म_त्रुटि(त्रुटि_सं));
			वापस 0;
		}
	} अन्यथा {
		अगर (getpeername(sock, (काष्ठा sockaddr *)&from, &fromlen) == -1) {
			debug("getpeername failed: %.100s", म_त्रुटि(त्रुटि_सं));
			वापस -1;
		}
	}

	/* Work around Linux IPv6 weirdness */
	अगर (from.ss_family == AF_INET6)
		fromlen = माप(काष्ठा sockaddr_in6);

	/* Non-inet sockets don't have a port number. */
	अगर (from.ss_family != AF_INET && from.ss_family != AF_INET6)
		वापस 0;

	/* Return port number. */
	अगर ((r = getnameinfo((काष्ठा sockaddr *)&from, fromlen, शून्य, 0,
	    strport, माप(strport), NI_NUMERICSERV)) != 0)
		fatal_f("getnameinfo NI_NUMERICSERV failed: %s",
		    ssh_gai_strerror(r));
	वापस म_से_प(strport);
}

पूर्णांक
get_peer_port(पूर्णांक sock)
{
	वापस get_sock_port(sock, 0);
}

पूर्णांक
get_local_port(पूर्णांक sock)
{
	वापस get_sock_port(sock, 1);
}
