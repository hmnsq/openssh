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

#அந்தர்பாவ "includes.h"

#ifndef HAVE_BINDRESVPORT_SA
#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/socket.h>

#அந்தர்பாவ <netinet/in.h>
#அந்தர்பாவ <arpa/inet.h>

#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>

#define STARTPORT 600
#define ENDPORT (IPPORT_RESERVED - 1)
#define NPORTS	(ENDPORT - STARTPORT + 1)

/*
 * Bind a socket to a privileged IP port
 */
முழு
bindresvport_sa(முழு sd, கட்டமைப்பு sockaddr *sa)
{
	முழு error, af;
	கட்டமைப்பு sockaddr_storage myaddr;
	கட்டமைப்பு sockaddr_in *in;
	கட்டமைப்பு sockaddr_in6 *in6;
	u_int16_t *portp;
	u_int16_t port;
	socklen_t salen;
	முழு i;

	எனில் (sa == வெற்று) {
		memset(&myaddr, 0, அளவு(myaddr));
		sa = (கட்டமைப்பு sockaddr *)&myaddr;
		salen = அளவு(myaddr);

		எனில் (getsockname(sd, sa, &salen) == -1)
			திரும்பு -1;	/* errno is correctly set */

		af = sa->sa_family;
		memset(&myaddr, 0, salen);
	} இல்லையெனில்
		af = sa->sa_family;

	எனில் (af == AF_INET) {
		in = (கட்டமைப்பு sockaddr_in *)sa;
		salen = அளவு(கட்டமைப்பு sockaddr_in);
		portp = &in->sin_port;
	} இல்லையெனில் எனில் (af == AF_INET6) {
		in6 = (கட்டமைப்பு sockaddr_in6 *)sa;
		salen = அளவு(கட்டமைப்பு sockaddr_in6);
		portp = &in6->sin6_port;
	} இல்லையெனில் {
		errno = EPFNOSUPPORT;
		திரும்பு (-1);
	}
	sa->sa_family = af;

	port = ntohs(*portp);
	எனில் (port == 0)
		port = arc4random_uniform(NPORTS) + STARTPORT;

	/* Avoid warning */
	error = -1;

	க்கு(i = 0; i < NPORTS; i++) {
		*portp = htons(port);
		
		error = bind(sd, sa, salen);

		/* Terminate on success */
		எனில் (error == 0)
			நிறுத்து;
			
		/* Terminate on errors, except "address already in use" */
		எனில் ((error < 0) && !((errno == EADDRINUSE) || (errno == EINVAL)))
			நிறுத்து;
			
		port++;
		எனில் (port > ENDPORT)
			port = STARTPORT;
	}

	திரும்பு (error);
}

#endif /* HAVE_BINDRESVPORT_SA */
