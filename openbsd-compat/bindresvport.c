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

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_BINDRESVPORT_SA
#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/socket.h>

#ಅನ್ತರ್ಭಾವ <netinet/in.h>
#ಅನ್ತರ್ಭಾವ <arpa/inet.h>

#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>

#ವ್ಯಾಖ್ಯಾನಿಸು STARTPORT 600
#ವ್ಯಾಖ್ಯಾನಿಸು ENDPORT (IPPORT_RESERVED - 1)
#ವ್ಯಾಖ್ಯಾನಿಸು NPORTS	(ENDPORT - STARTPORT + 1)

/*
 * Bind a socket to a privileged IP port
 */
ಪೂರ್ಣಾಂಕ
bindresvport_sa(ಪೂರ್ಣಾಂಕ sd, ರಚನೆ sockaddr *sa)
{
	ಪೂರ್ಣಾಂಕ error, af;
	ರಚನೆ sockaddr_storage myaddr;
	ರಚನೆ sockaddr_in *ಒಳ;
	ರಚನೆ sockaddr_in6 *in6;
	u_int16_t *portp;
	u_int16_t ಪೋರ್ಟ್;
	socklen_t salen;
	ಪೂರ್ಣಾಂಕ i;

	ಆದರೆ (sa == ಖಾಲಿ) {
		memset(&myaddr, 0, ಗಾತ್ರ(myaddr));
		sa = (ರಚನೆ sockaddr *)&myaddr;
		salen = ಗಾತ್ರ(myaddr);

		ಆದರೆ (getsockname(sd, sa, &salen) == -1)
			ಹಿಂತಿರುಗಿ -1;	/* errno is correctly set */

		af = sa->sa_family;
		memset(&myaddr, 0, salen);
	} ಇಲ್ಲದಿದ್ದರೆ
		af = sa->sa_family;

	ಆದರೆ (af == AF_INET) {
		ಒಳ = (ರಚನೆ sockaddr_in *)sa;
		salen = ಗಾತ್ರ(ರಚನೆ sockaddr_in);
		portp = &ಒಳ->sin_port;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (af == AF_INET6) {
		in6 = (ರಚನೆ sockaddr_in6 *)sa;
		salen = ಗಾತ್ರ(ರಚನೆ sockaddr_in6);
		portp = &in6->sin6_port;
	} ಇಲ್ಲದಿದ್ದರೆ {
		errno = EPFNOSUPPORT;
		ಹಿಂತಿರುಗಿ (-1);
	}
	sa->sa_family = af;

	ಪೋರ್ಟ್ = ntohs(*portp);
	ಆದರೆ (ಪೋರ್ಟ್ == 0)
		ಪೋರ್ಟ್ = arc4random_ಏಕರೂಪ(NPORTS) + STARTPORT;

	/* Avoid warning */
	error = -1;

	ಗಾಗಿ(i = 0; i < NPORTS; i++) {
		*portp = htons(ಪೋರ್ಟ್);
		
		error = bind(sd, sa, salen);

		/* Terminate on success */
		ಆದರೆ (error == 0)
			ನಿಲ್ಲಿಸು;
			
		/* Terminate on errors, except "address already in use" */
		ಆದರೆ ((error < 0) && !((errno == EADDRINUSE) || (errno == EINVAL)))
			ನಿಲ್ಲಿಸು;
			
		ಪೋರ್ಟ್++;
		ಆದರೆ (ಪೋರ್ಟ್ > ENDPORT)
			ಪೋರ್ಟ್ = STARTPORT;
	}

	ಹಿಂತಿರುಗಿ (error);
}

#ಆದರೆ_ಅಂತ್ಯ /* HAVE_BINDRESVPORT_SA */
