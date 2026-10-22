/* This file has be substantially modified from the original OpenBSD source */

/*	$OpenBSD: bindresvport.c,v 1.17 2005/12/21 01:40:22 millert Exp $	*/

/*
 * Copyright 1996, Jason Downs.  All rights reserved.
 * Copyright 1998, Theo de Raadt.  All rights reserved.
 * Copyright 2000, Damien Miller.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* OPENBSD ORIGINAL: lib/libc/rpc/bindresvport.c */

#समावेश "includes.h"

#अगर_अघोषित HAVE_BINDRESVPORT_SA
#समावेश <sys/types.h>
#समावेश <sys/socket.h>

#समावेश <netinet/in.h>
#समावेश <arpa/inet.h>

#समावेश <errno.h>
#समावेश <stdlib.h>
#समावेश <string.h>

#घोषणा STARTPORT 600
#घोषणा ENDPORT (IPPORT_RESERVED - 1)
#घोषणा NPORTS	(ENDPORT - STARTPORT + 1)

/*
 * Bind a socket to a privileged IP port
 */
पूर्णांक
bindresvport_sa(पूर्णांक sd, काष्ठा sockaddr *sa)
{
	पूर्णांक error, af;
	काष्ठा sockaddr_storage myaddr;
	काष्ठा sockaddr_in *in;
	काष्ठा sockaddr_in6 *in6;
	u_int16_t *portp;
	u_int16_t port;
	socklen_t salen;
	पूर्णांक i;

	अगर (sa == शून्य) {
		स_रखो(&myaddr, 0, माप(myaddr));
		sa = (काष्ठा sockaddr *)&myaddr;
		salen = माप(myaddr);

		अगर (getsockname(sd, sa, &salen) == -1)
			वापस -1;	/* errno is correctly set */

		af = sa->sa_family;
		स_रखो(&myaddr, 0, salen);
	} अन्यथा
		af = sa->sa_family;

	अगर (af == AF_INET) {
		in = (काष्ठा sockaddr_in *)sa;
		salen = माप(काष्ठा sockaddr_in);
		portp = &in->sin_port;
	} अन्यथा अगर (af == AF_INET6) {
		in6 = (काष्ठा sockaddr_in6 *)sa;
		salen = माप(काष्ठा sockaddr_in6);
		portp = &in6->sin6_port;
	} अन्यथा {
		त्रुटि_सं = EPFNOSUPPORT;
		वापस (-1);
	}
	sa->sa_family = af;

	port = ntohs(*portp);
	अगर (port == 0)
		port = arc4random_uniform(NPORTS) + STARTPORT;

	/* Avoid warning */
	error = -1;

	क्रम(i = 0; i < NPORTS; i++) {
		*portp = htons(port);
		
		error = bind(sd, sa, salen);

		/* Terminate on success */
		अगर (error == 0)
			अवरोध;
			
		/* Terminate on errors, except "address already in use" */
		अगर ((error < 0) && !((त्रुटि_सं == EADDRINUSE) || (त्रुटि_सं == EINVAL)))
			अवरोध;
			
		port++;
		अगर (port > ENDPORT)
			port = STARTPORT;
	}

	वापस (error);
}

#पूर्ण_अगर /* HAVE_BINDRESVPORT_SA */
