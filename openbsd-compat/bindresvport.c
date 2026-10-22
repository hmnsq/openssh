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

#অন্তর্ভাৱ "includes.h"

#ifndef HAVE_BINDRESVPORT_SA
#অন্তর্ভাৱ <sys/types.h>
#অন্তর্ভাৱ <sys/socket.h>

#অন্তর্ভাৱ <netinet/in.h>
#অন্তর্ভাৱ <arpa/inet.h>

#অন্তর্ভাৱ <errno.h>
#অন্তর্ভাৱ <stdlib.h>
#অন্তর্ভাৱ <string.h>

#define STARTPORT 600
#define ENDPORT (IPPORT_RESERVED - 1)
#define NPORTS	(ENDPORT - STARTPORT + 1)

/*
 * Bind a socket to a privileged IP port
 */
পূর্ণাঙ্ক
bindresvport_sa(পূর্ণাঙ্ক sd, সংরচনা sockaddr *sa)
{
	পূর্ণাঙ্ক error, af;
	সংরচনা sockaddr_storage myaddr;
	সংরচনা sockaddr_in *in;
	সংরচনা sockaddr_in6 *in6;
	u_int16_t *portp;
	u_int16_t port;
	socklen_t salen;
	পূর্ণাঙ্ক i;

	যদি (sa == রিক্ত) {
		memset(&myaddr, 0, পরিমাণ(myaddr));
		sa = (সংরচনা sockaddr *)&myaddr;
		salen = পরিমাণ(myaddr);

		যদি (getsockname(sd, sa, &salen) == -1)
			ঘূৰাই -1;	/* errno is correctly set */

		af = sa->sa_family;
		memset(&myaddr, 0, salen);
	} অন্যথা
		af = sa->sa_family;

	যদি (af == AF_INET) {
		in = (সংরচনা sockaddr_in *)sa;
		salen = পরিমাণ(সংরচনা sockaddr_in);
		portp = &in->sin_port;
	} অন্যথা যদি (af == AF_INET6) {
		in6 = (সংরচনা sockaddr_in6 *)sa;
		salen = পরিমাণ(সংরচনা sockaddr_in6);
		portp = &in6->sin6_port;
	} অন্যথা {
		errno = EPFNOSUPPORT;
		ঘূৰাই (-1);
	}
	sa->sa_family = af;

	port = ntohs(*portp);
	যদি (port == 0)
		port = arc4random_uniform(NPORTS) + STARTPORT;

	/* Avoid warning */
	error = -1;

	বাবে(i = 0; i < NPORTS; i++) {
		*portp = htons(port);
		
		error = bind(sd, sa, salen);

		/* Terminate on success */
		যদি (error == 0)
			ভঙ্গ;
			
		/* Terminate on errors, except "address already in use" */
		যদি ((error < 0) && !((errno == EADDRINUSE) || (errno == EINVAL)))
			ভঙ্গ;
			
		port++;
		যদি (port > ENDPORT)
			port = STARTPORT;
	}

	ঘূৰাই (error);
}

#endif /* HAVE_BINDRESVPORT_SA */
