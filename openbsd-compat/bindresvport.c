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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ifndef HAVE_BINDRESVPORT_SA
#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/socket.h>

#ಅನ್ತರ್ಭಾವ <netinet/in.h>
#ಅನ್ತರ್ಭಾವ <arpa/inet.h>

#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>

#define STARTPORT 600
#define ENDPORT (IPPORT_RESERVED - 1)
#define NPORTS	(ENDPORT - STARTPORT + 1)

/*
 * Bind a socket to a privileged IP port
 */
ಪೂರ್ಣಾಙ್ಕ
bindresvport_sa(ಪೂರ್ಣಾಙ್ಕ sd, ಸಂರಚನಾ sockaddr *sa)
{
	ಪೂರ್ಣಾಙ್ಕ error, af;
	ಸಂರಚನಾ sockaddr_storage myaddr;
	ಸಂರಚನಾ sockaddr_in *in;
	ಸಂರಚನಾ sockaddr_in6 *in6;
	u_int16_t *portp;
	u_int16_t port;
	socklen_t salen;
	ಪೂರ್ಣಾಙ್ಕ i;

	ಯದಿ (sa == ರಿಕ್ತ) {
		memset(&myaddr, 0, ಪರಿಮಾಣ(myaddr));
		sa = (ಸಂರಚನಾ sockaddr *)&myaddr;
		salen = ಪರಿಮಾಣ(myaddr);

		ಯದಿ (getsockname(sd, sa, &salen) == -1)
			ಪ್ರತ್ಯಾಗಮ -1;	/* errno is correctly set */

		af = sa->sa_family;
		memset(&myaddr, 0, salen);
	} ಅನ್ಯಥಾ
		af = sa->sa_family;

	ಯದಿ (af == AF_INET) {
		in = (ಸಂರಚನಾ sockaddr_in *)sa;
		salen = ಪರಿಮಾಣ(ಸಂರಚನಾ sockaddr_in);
		portp = &in->sin_port;
	} ಅನ್ಯಥಾ ಯದಿ (af == AF_INET6) {
		in6 = (ಸಂರಚನಾ sockaddr_in6 *)sa;
		salen = ಪರಿಮಾಣ(ಸಂರಚನಾ sockaddr_in6);
		portp = &in6->sin6_port;
	} ಅನ್ಯಥಾ {
		errno = EPFNOSUPPORT;
		ಪ್ರತ್ಯಾಗಮ (-1);
	}
	sa->sa_family = af;

	port = ntohs(*portp);
	ಯದಿ (port == 0)
		port = arc4random_uniform(NPORTS) + STARTPORT;

	/* Avoid warning */
	error = -1;

	ಪ್ರತಿ(i = 0; i < NPORTS; i++) {
		*portp = htons(port);
		
		error = bind(sd, sa, salen);

		/* Terminate on success */
		ಯದಿ (error == 0)
			ಭಙ್ಗ;
			
		/* Terminate on errors, except "address already in use" */
		ಯದಿ ((error < 0) && !((errno == EADDRINUSE) || (errno == EINVAL)))
			ಭಙ್ಗ;
			
		port++;
		ಯದಿ (port > ENDPORT)
			port = STARTPORT;
	}

	ಪ್ರತ್ಯಾಗಮ (error);
}

#endif /* HAVE_BINDRESVPORT_SA */
