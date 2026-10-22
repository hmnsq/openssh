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

#include "includes.h"

#ifndef HAVE_BINDRESVPORT_SA
#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define STARTPORT 600
#define ENDPORT (IPPORT_RESERVED - 1)
#define NPORTS	(ENDPORT - STARTPORT + 1)

/*
 * Bind a socket to a privileged IP port
 */
정수
bindresvport_sa(정수 sd, struct sockaddr *sa)
{
	정수 error, af;
	struct sockaddr_storage myaddr;
	struct sockaddr_in *in;
	struct sockaddr_in6 *in6;
	u_int16_t *portp;
	u_int16_t port;
	socklen_t salen;
	정수 i;

	만약 (sa == NULL) {
		memset(&myaddr, 0, sizeof(myaddr));
		sa = (struct sockaddr *)&myaddr;
		salen = sizeof(myaddr);

		만약 (getsockname(sd, sa, &salen) == -1)
			반환 -1;	/* errno is correctly set */

		af = sa->sa_family;
		memset(&myaddr, 0, salen);
	} 아니면
		af = sa->sa_family;

	만약 (af == AF_INET) {
		in = (struct sockaddr_in *)sa;
		salen = sizeof(struct sockaddr_in);
		portp = &in->sin_port;
	} 아니면 만약 (af == AF_INET6) {
		in6 = (struct sockaddr_in6 *)sa;
		salen = sizeof(struct sockaddr_in6);
		portp = &in6->sin6_port;
	} 아니면 {
		errno = EPFNOSUPPORT;
		반환 (-1);
	}
	sa->sa_family = af;

	port = ntohs(*portp);
	만약 (port == 0)
		port = arc4random_uniform(NPORTS) + STARTPORT;

	/* Avoid warning */
	error = -1;

	위해(i = 0; i < NPORTS; i++) {
		*portp = htons(port);
		
		error = bind(sd, sa, salen);

		/* Terminate on success */
		만약 (error == 0)
			break;
			
		/* Terminate on errors, except "address already in use" */
		만약 ((error < 0) && !((errno == EADDRINUSE) || (errno == EINVAL)))
			break;
			
		port++;
		만약 (port > ENDPORT)
			port = STARTPORT;
	}

	반환 (error);
}

#endif /* HAVE_BINDRESVPORT_SA */
