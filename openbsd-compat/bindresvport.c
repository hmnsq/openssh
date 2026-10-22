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

#अन्तर्भाव "includes.h"

#ifndef HAVE_BINDRESVPORT_SA
#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/socket.h>

#अन्तर्भाव <netinet/in.h>
#अन्तर्भाव <arpa/inet.h>

#अन्तर्भाव <errno.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>

#define STARTPORT 600
#define ENDPORT (IPPORT_RESERVED - 1)
#define NPORTS	(ENDPORT - STARTPORT + 1)

/*
 * Bind a socket to a privileged IP port
 */
पूर्णांक
bindresvport_sa(पूर्णांक sd, संरचना sockaddr *sa)
{
	पूर्णांक error, af;
	संरचना sockaddr_storage myaddr;
	संरचना sockaddr_in *in;
	संरचना sockaddr_in6 *in6;
	u_int16_t *portp;
	u_int16_t port;
	socklen_t salen;
	पूर्णांक i;

	जर (sa == रिक्त) {
		स_रखो(&myaddr, 0, आकार(myaddr));
		sa = (संरचना sockaddr *)&myaddr;
		salen = आकार(myaddr);

		जर (getsockname(sd, sa, &salen) == -1)
			परत -1;	/* errno is correctly set */

		af = sa->sa_family;
		स_रखो(&myaddr, 0, salen);
	} अन्यथा
		af = sa->sa_family;

	जर (af == AF_INET) {
		in = (संरचना sockaddr_in *)sa;
		salen = आकार(संरचना sockaddr_in);
		portp = &in->sin_port;
	} अन्यथा जर (af == AF_INET6) {
		in6 = (संरचना sockaddr_in6 *)sa;
		salen = आकार(संरचना sockaddr_in6);
		portp = &in6->sin6_port;
	} अन्यथा {
		त्रुटि_सं = EPFNOSUPPORT;
		परत (-1);
	}
	sa->sa_family = af;

	port = ntohs(*portp);
	जर (port == 0)
		port = arc4random_uniform(NPORTS) + STARTPORT;

	/* Avoid warning */
	error = -1;

	साठी(i = 0; i < NPORTS; i++) {
		*portp = htons(port);
		
		error = bind(sd, sa, salen);

		/* Terminate on success */
		जर (error == 0)
			थांबा;
			
		/* Terminate on errors, except "address already in use" */
		जर ((error < 0) && !((त्रुटि_सं == EADDRINUSE) || (त्रुटि_सं == EINVAL)))
			थांबा;
			
		port++;
		जर (port > ENDPORT)
			port = STARTPORT;
	}

	परत (error);
}

#endif /* HAVE_BINDRESVPORT_SA */
