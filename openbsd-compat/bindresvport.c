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

#অন্তর্ভাব "includes.h"

#ifndef HAVE_BINDRESVPORT_SA
#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <sys/socket.h>

#অন্তর্ভাব <netinet/in.h>
#অন্তর্ভাব <arpa/inet.h>

#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>

#define STARTPORT 600
#define ENDPORT (IPPORT_RESERVED - 1)
#define NPORTS	(ENDPORT - STARTPORT + 1)

/*
 * Bind a socket to a privileged IP port
 */
পূর্ণসংখ্যা
bindresvport_sa(পূর্ণসংখ্যা sd, কাঠামো sockaddr *sa)
{
	পূর্ণসংখ্যা error, af;
	কাঠামো sockaddr_storage myaddr;
	কাঠামো sockaddr_in *in;
	কাঠামো sockaddr_in6 *in6;
	u_int16_t *portp;
	u_int16_t port;
	socklen_t salen;
	পূর্ণসংখ্যা i;

	যদি (sa == ফাঁকা) {
		memset(&myaddr, 0, আকার(myaddr));
		sa = (কাঠামো sockaddr *)&myaddr;
		salen = আকার(myaddr);

		যদি (getsockname(sd, sa, &salen) == -1)
			ফেরত -1;	/* errno is correctly set */

		af = sa->sa_family;
		memset(&myaddr, 0, salen);
	} অন্যথা
		af = sa->sa_family;

	যদি (af == AF_INET) {
		in = (কাঠামো sockaddr_in *)sa;
		salen = আকার(কাঠামো sockaddr_in);
		portp = &in->sin_port;
	} অন্যথা যদি (af == AF_INET6) {
		in6 = (কাঠামো sockaddr_in6 *)sa;
		salen = আকার(কাঠামো sockaddr_in6);
		portp = &in6->sin6_port;
	} অন্যথা {
		errno = EPFNOSUPPORT;
		ফেরত (-1);
	}
	sa->sa_family = af;

	port = ntohs(*portp);
	যদি (port == 0)
		port = arc4random_uniform(NPORTS) + STARTPORT;

	/* Avoid warning */
	error = -1;

	জন্য(i = 0; i < NPORTS; i++) {
		*portp = htons(port);
		
		error = bind(sd, sa, salen);

		/* Terminate on success */
		যদি (error == 0)
			বিরতি;
			
		/* Terminate on errors, except "address already in use" */
		যদি ((error < 0) && !((errno == EADDRINUSE) || (errno == EINVAL)))
			বিরতি;
			
		port++;
		যদি (port > ENDPORT)
			port = STARTPORT;
	}

	ফেরত (error);
}

#endif /* HAVE_BINDRESVPORT_SA */
