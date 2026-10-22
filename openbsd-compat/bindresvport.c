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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_BINDRESVPORT_SA
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/socket.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <netinet/in.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <arpa/inet.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ STARTPORT 600
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ENDPORT (IPPORT_RESERVED - 1)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ NPORTS	(ENDPORT - STARTPORT + 1)

/*
 * Bind a socket to a privileged IP port
 */
ਪੂਰਨ
bindresvport_sa(ਪੂਰਨ sd, ਬਣਤਰ sockaddr *sa)
{
	ਪੂਰਨ error, af;
	ਬਣਤਰ sockaddr_storage myaddr;
	ਬਣਤਰ sockaddr_in *ਵਿੱਚ;
	ਬਣਤਰ sockaddr_in6 *in6;
	u_int16_t *portp;
	u_int16_t ਪੋਰਟ;
	socklen_t salen;
	ਪੂਰਨ i;

	ਜੇ (sa == ਨਿਰਾ) {
		memset(&myaddr, 0, ਆਕਾਰ(myaddr));
		sa = (ਬਣਤਰ sockaddr *)&myaddr;
		salen = ਆਕਾਰ(myaddr);

		ਜੇ (getsockname(sd, sa, &salen) == -1)
			ਵਾਪਸ -1;	/* errno is correctly set */

		af = sa->sa_family;
		memset(&myaddr, 0, salen);
	} ਨਹੀਂਤਾਂ
		af = sa->sa_family;

	ਜੇ (af == AF_INET) {
		ਵਿੱਚ = (ਬਣਤਰ sockaddr_in *)sa;
		salen = ਆਕਾਰ(ਬਣਤਰ sockaddr_in);
		portp = &ਵਿੱਚ->sin_port;
	} ਨਹੀਂਤਾਂ ਜੇ (af == AF_INET6) {
		in6 = (ਬਣਤਰ sockaddr_in6 *)sa;
		salen = ਆਕਾਰ(ਬਣਤਰ sockaddr_in6);
		portp = &in6->sin6_port;
	} ਨਹੀਂਤਾਂ {
		errno = EPFNOSUPPORT;
		ਵਾਪਸ (-1);
	}
	sa->sa_family = af;

	ਪੋਰਟ = ntohs(*portp);
	ਜੇ (ਪੋਰਟ == 0)
		ਪੋਰਟ = arc4random_ਇਕਸਾਰ(NPORTS) + STARTPORT;

	/* Avoid warning */
	error = -1;

	ਲਈ(i = 0; i < NPORTS; i++) {
		*portp = htons(ਪੋਰਟ);
		
		error = bind(sd, sa, salen);

		/* Terminate on success */
		ਜੇ (error == 0)
			ਰੋਕੋ;
			
		/* Terminate on errors, except "address already in use" */
		ਜੇ ((error < 0) && !((errno == EADDRINUSE) || (errno == EINVAL)))
			ਰੋਕੋ;
			
		ਪੋਰਟ++;
		ਜੇ (ਪੋਰਟ > ENDPORT)
			ਪੋਰਟ = STARTPORT;
	}

	ਵਾਪਸ (error);
}

#ਜੇ_ਅੰਤ /* HAVE_BINDRESVPORT_SA */
