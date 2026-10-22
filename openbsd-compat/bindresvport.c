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

#અન્તર્ભાવ "includes.h"

#ifndef HAVE_BINDRESVPORT_SA
#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/socket.h>

#અન્તર્ભાવ <netinet/in.h>
#અન્તર્ભાવ <arpa/inet.h>

#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>

#define STARTPORT 600
#define ENDPORT (IPPORT_RESERVED - 1)
#define NPORTS	(ENDPORT - STARTPORT + 1)

/*
 * Bind a socket to a privileged IP port
 */
પૂર્ણાંક
bindresvport_sa(પૂર્ણાંક sd, સંરચના sockaddr *sa)
{
	પૂર્ણાંક error, af;
	સંરચના sockaddr_storage myaddr;
	સંરચના sockaddr_in *in;
	સંરચના sockaddr_in6 *in6;
	u_int16_t *portp;
	u_int16_t port;
	socklen_t salen;
	પૂર્ણાંક i;

	જો (sa == ખાલી) {
		memset(&myaddr, 0, કદ(myaddr));
		sa = (સંરચના sockaddr *)&myaddr;
		salen = કદ(myaddr);

		જો (getsockname(sd, sa, &salen) == -1)
			પાછા -1;	/* errno is correctly set */

		af = sa->sa_family;
		memset(&myaddr, 0, salen);
	} નહીંતર
		af = sa->sa_family;

	જો (af == AF_INET) {
		in = (સંરચના sockaddr_in *)sa;
		salen = કદ(સંરચના sockaddr_in);
		portp = &in->sin_port;
	} નહીંતર જો (af == AF_INET6) {
		in6 = (સંરચના sockaddr_in6 *)sa;
		salen = કદ(સંરચના sockaddr_in6);
		portp = &in6->sin6_port;
	} નહીંતર {
		errno = EPFNOSUPPORT;
		પાછા (-1);
	}
	sa->sa_family = af;

	port = ntohs(*portp);
	જો (port == 0)
		port = arc4random_uniform(NPORTS) + STARTPORT;

	/* Avoid warning */
	error = -1;

	માટે(i = 0; i < NPORTS; i++) {
		*portp = htons(port);
		
		error = bind(sd, sa, salen);

		/* Terminate on success */
		જો (error == 0)
			તોડો;
			
		/* Terminate on errors, except "address already in use" */
		જો ((error < 0) && !((errno == EADDRINUSE) || (errno == EINVAL)))
			તોડો;
			
		port++;
		જો (port > ENDPORT)
			port = STARTPORT;
	}

	પાછા (error);
}

#endif /* HAVE_BINDRESVPORT_SA */
