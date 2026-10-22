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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ifndef HAVE_BINDRESVPORT_SA
#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/socket.h>

#ଅନ୍ତର୍ଭାଵ <netinet/in.h>
#ଅନ୍ତର୍ଭାଵ <arpa/inet.h>

#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>

#define STARTPORT 600
#define ENDPORT (IPPORT_RESERVED - 1)
#define NPORTS	(ENDPORT - STARTPORT + 1)

/*
 * Bind a socket to a privileged IP port
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
bindresvport_sa(ପୂର୍ଣ୍ଣସଂଖ୍ୟା sd, ସଂରଚନା sockaddr *sa)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା error, af;
	ସଂରଚନା sockaddr_storage myaddr;
	ସଂରଚନା sockaddr_in *in;
	ସଂରଚନା sockaddr_in6 *in6;
	u_int16_t *portp;
	u_int16_t port;
	socklen_t salen;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;

	ଯଦି (sa == ଖାଲି) {
		memset(&myaddr, 0, ଆକାର(myaddr));
		sa = (ସଂରଚନା sockaddr *)&myaddr;
		salen = ଆକାର(myaddr);

		ଯଦି (getsockname(sd, sa, &salen) == -1)
			ଫେରନ୍ତୁ -1;	/* errno is correctly set */

		af = sa->sa_family;
		memset(&myaddr, 0, salen);
	} ଅନ୍ୟଥା
		af = sa->sa_family;

	ଯଦି (af == AF_INET) {
		in = (ସଂରଚନା sockaddr_in *)sa;
		salen = ଆକାର(ସଂରଚନା sockaddr_in);
		portp = &in->sin_port;
	} ଅନ୍ୟଥା ଯଦି (af == AF_INET6) {
		in6 = (ସଂରଚନା sockaddr_in6 *)sa;
		salen = ଆକାର(ସଂରଚନା sockaddr_in6);
		portp = &in6->sin6_port;
	} ଅନ୍ୟଥା {
		errno = EPFNOSUPPORT;
		ଫେରନ୍ତୁ (-1);
	}
	sa->sa_family = af;

	port = ntohs(*portp);
	ଯଦି (port == 0)
		port = arc4random_uniform(NPORTS) + STARTPORT;

	/* Avoid warning */
	error = -1;

	ପାଇଁ(i = 0; i < NPORTS; i++) {
		*portp = htons(port);
		
		error = bind(sd, sa, salen);

		/* Terminate on success */
		ଯଦି (error == 0)
			ଭାଙ୍ଗ;
			
		/* Terminate on errors, except "address already in use" */
		ଯଦି ((error < 0) && !((errno == EADDRINUSE) || (errno == EINVAL)))
			ଭାଙ୍ଗ;
			
		port++;
		ଯଦି (port > ENDPORT)
			port = STARTPORT;
	}

	ଫେରନ୍ତୁ (error);
}

#endif /* HAVE_BINDRESVPORT_SA */
