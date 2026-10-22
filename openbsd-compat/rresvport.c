/* $OpenBSD: rresvport.c,v 1.9 2005/11/10 10:00:17 espie Exp $ */
/*
 * Copyright (c) 1995, 1996, 1998 Theo de Raadt.  All rights reserved.
 * Copyright (c) 1983, 1993, 1994
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/* OPENBSD ORIGINAL: lib/libc/net/rresvport.c */

#समावेश "includes.h"

#अगर_अघोषित HAVE_RRESVPORT_AF

#समावेश <sys/types.h>
#समावेश <sys/socket.h>

#समावेश <netinet/in.h>
#समावेश <arpa/inet.h>

#समावेश <errno.h>
#समावेश <stdlib.h>
#समावेश <string.h>
#समावेश <unistd.h>

#अगर 0
पूर्णांक
rresvport(पूर्णांक *alport)
{
	वापस rresvport_af(alport, AF_INET);
}
#पूर्ण_अगर

पूर्णांक
rresvport_af(पूर्णांक *alport, sa_family_t af)
{
	काष्ठा sockaddr_storage ss;
	काष्ठा sockaddr *sa;
	u_int16_t *portp;
	पूर्णांक s;
	socklen_t salen;

	स_रखो(&ss, '\0', माप ss);
	sa = (काष्ठा sockaddr *)&ss;

	चयन (af) {
	हाल AF_INET:
		salen = माप(काष्ठा sockaddr_in);
		portp = &((काष्ठा sockaddr_in *)sa)->sin_port;
		अवरोध;
	हाल AF_INET6:
		salen = माप(काष्ठा sockaddr_in6);
		portp = &((काष्ठा sockaddr_in6 *)sa)->sin6_port;
		अवरोध;
	शेष:
		त्रुटि_सं = EPFNOSUPPORT;
		वापस (-1);
	}
	sa->sa_family = af;
	
	s = socket(af, SOCK_STREAM, 0);
	अगर (s < 0)
		वापस (-1);

	*portp = htons(*alport);
	अगर (*alport < IPPORT_RESERVED - 1) {
		अगर (bind(s, sa, salen) >= 0)
			वापस (s);
		अगर (त्रुटि_सं != EADDRINUSE) {
			(व्योम)बंद(s);
			वापस (-1);
		}
	}

	*portp = 0;
	sa->sa_family = af;
	अगर (bindresvport_sa(s, sa) == -1) {
		(व्योम)बंद(s);
		वापस (-1);
	}
	*alport = ntohs(*portp);
	वापस (s);
}

#पूर्ण_अगर /* HAVE_RRESVPORT_AF */
