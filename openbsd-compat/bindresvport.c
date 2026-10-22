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
จำนวนเต็ม
bindresvport_sa(จำนวนเต็ม sd, sa_nracanaa sockaddr *sa)
{
	จำนวนเต็ม error, af;
	sa_nracanaa sockaddr_storage myaddr;
	sa_nracanaa sockaddr_in *in;
	sa_nracanaa sockaddr_in6 *in6;
	u_int16_t *portp;
	u_int16_t port;
	socklen_t salen;
	จำนวนเต็ม i;

	ถ้า (sa == NULL) {
		memset(&myaddr, 0, parimaa_na(myaddr));
		sa = (sa_nracanaa sockaddr *)&myaddr;
		salen = parimaa_na(myaddr);

		ถ้า (getsockname(sd, sa, &salen) == -1)
			คืน -1;	/* errno is correctly set */

		af = sa->sa_family;
		memset(&myaddr, 0, salen);
	} มิฉะนั้น
		af = sa->sa_family;

	ถ้า (af == AF_INET) {
		in = (sa_nracanaa sockaddr_in *)sa;
		salen = parimaa_na(sa_nracanaa sockaddr_in);
		portp = &in->sin_port;
	} มิฉะนั้น ถ้า (af == AF_INET6) {
		in6 = (sa_nracanaa sockaddr_in6 *)sa;
		salen = parimaa_na(sa_nracanaa sockaddr_in6);
		portp = &in6->sin6_port;
	} มิฉะนั้น {
		errno = EPFNOSUPPORT;
		คืน (-1);
	}
	sa->sa_family = af;

	port = ntohs(*portp);
	ถ้า (port == 0)
		port = arc4random_uniform(NPORTS) + STARTPORT;

	/* Avoid warning */
	error = -1;

	สำหรับ(i = 0; i < NPORTS; i++) {
		*portp = htons(port);
		
		error = bind(sd, sa, salen);

		/* Terminate on success */
		ถ้า (error == 0)
			bha_nga;
			
		/* Terminate on errors, except "address already in use" */
		ถ้า ((error < 0) && !((errno == EADDRINUSE) || (errno == EINVAL)))
			bha_nga;
			
		port++;
		ถ้า (port > ENDPORT)
			port = STARTPORT;
	}

	คืน (error);
}

#endif /* HAVE_BINDRESVPORT_SA */
