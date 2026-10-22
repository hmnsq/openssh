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

#അന്തര്ഭാവ "includes.h"

#ifndef HAVE_BINDRESVPORT_SA
#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/socket.h>

#അന്തര്ഭാവ <netinet/in.h>
#അന്തര്ഭാവ <arpa/inet.h>

#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>

#define STARTPORT 600
#define ENDPORT (IPPORT_RESERVED - 1)
#define NPORTS	(ENDPORT - STARTPORT + 1)

/*
 * Bind a socket to a privileged IP port
 */
പൂർണ്ണസംഖ്യ
bindresvport_sa(പൂർണ്ണസംഖ്യ sd, ഘടന sockaddr *sa)
{
	പൂർണ്ണസംഖ്യ error, af;
	ഘടന sockaddr_storage myaddr;
	ഘടന sockaddr_in *in;
	ഘടന sockaddr_in6 *in6;
	u_int16_t *portp;
	u_int16_t port;
	socklen_t salen;
	പൂർണ്ണസംഖ്യ i;

	എങ്കിൽ (sa == ശൂന്യ) {
		memset(&myaddr, 0, വലുപ്പം(myaddr));
		sa = (ഘടന sockaddr *)&myaddr;
		salen = വലുപ്പം(myaddr);

		എങ്കിൽ (getsockname(sd, sa, &salen) == -1)
			തിരികെ -1;	/* errno is correctly set */

		af = sa->sa_family;
		memset(&myaddr, 0, salen);
	} അല്ലെങ്കിൽ
		af = sa->sa_family;

	എങ്കിൽ (af == AF_INET) {
		in = (ഘടന sockaddr_in *)sa;
		salen = വലുപ്പം(ഘടന sockaddr_in);
		portp = &in->sin_port;
	} അല്ലെങ്കിൽ എങ്കിൽ (af == AF_INET6) {
		in6 = (ഘടന sockaddr_in6 *)sa;
		salen = വലുപ്പം(ഘടന sockaddr_in6);
		portp = &in6->sin6_port;
	} അല്ലെങ്കിൽ {
		errno = EPFNOSUPPORT;
		തിരികെ (-1);
	}
	sa->sa_family = af;

	port = ntohs(*portp);
	എങ്കിൽ (port == 0)
		port = arc4random_uniform(NPORTS) + STARTPORT;

	/* Avoid warning */
	error = -1;

	വേണ്ടി(i = 0; i < NPORTS; i++) {
		*portp = htons(port);
		
		error = bind(sd, sa, salen);

		/* Terminate on success */
		എങ്കിൽ (error == 0)
			നിർത്തുക;
			
		/* Terminate on errors, except "address already in use" */
		എങ്കിൽ ((error < 0) && !((errno == EADDRINUSE) || (errno == EINVAL)))
			നിർത്തുക;
			
		port++;
		എങ്കിൽ (port > ENDPORT)
			port = STARTPORT;
	}

	തിരികെ (error);
}

#endif /* HAVE_BINDRESVPORT_SA */
