/* $OpenBSD: rresvport.c,v 1.9 2005/11/10 10:00:17 espie Exp $ */
/*
 * Copyright (c) 1995, 1996, 1998 Theo de Raadt.  All rights reserved.
 * Copyright (c) 1983, 1993, 1994
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/* OPENBSD ORIGINAL: lib/libc/net/rresvport.c */

#ಅನ್ತರ್ಭಾವ "includes.h"

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_RRESVPORT_AF

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/socket.h>

#ಅನ್ತರ್ಭಾವ <netinet/in.h>
#ಅನ್ತರ್ಭಾವ <arpa/inet.h>

#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>

#ಆದರೆ 0
ಪೂರ್ಣಾಂಕ
rresvport(ಪೂರ್ಣಾಂಕ *alport)
{
	ಹಿಂತಿರುಗಿ rresvport_af(alport, AF_INET);
}
#ಆದರೆ_ಅಂತ್ಯ

ಪೂರ್ಣಾಂಕ
rresvport_af(ಪೂರ್ಣಾಂಕ *alport, sa_family_t af)
{
	ರಚನೆ sockaddr_storage ss;
	ರಚನೆ sockaddr *sa;
	u_int16_t *portp;
	ಪೂರ್ಣಾಂಕ s;
	socklen_t salen;

	memset(&ss, '\0', ಗಾತ್ರ ss);
	sa = (ರಚನೆ sockaddr *)&ss;

	ಆಯ್ಕೆ (af) {
	ಸ್ಥಿತಿ AF_INET:
		salen = ಗಾತ್ರ(ರಚನೆ sockaddr_in);
		portp = &((ರಚನೆ sockaddr_in *)sa)->sin_port;
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ AF_INET6:
		salen = ಗಾತ್ರ(ರಚನೆ sockaddr_in6);
		portp = &((ರಚನೆ sockaddr_in6 *)sa)->sin6_port;
		ನಿಲ್ಲಿಸು;
	ಪೂರ್ವನಿಯೋಜಿತ:
		errno = EPFNOSUPPORT;
		ಹಿಂತಿರುಗಿ (-1);
	}
	sa->sa_family = af;
	
	s = socket(af, SOCK_STREAM, 0);
	ಆದರೆ (s < 0)
		ಹಿಂತಿರುಗಿ (-1);

	*portp = htons(*alport);
	ಆದರೆ (*alport < IPPORT_RESERVED - 1) {
		ಆದರೆ (bind(s, sa, salen) >= 0)
			ಹಿಂತಿರುಗಿ (s);
		ಆದರೆ (errno != EADDRINUSE) {
			(ಶೂನ್ಯ)close(s);
			ಹಿಂತಿರುಗಿ (-1);
		}
	}

	*portp = 0;
	sa->sa_family = af;
	ಆದರೆ (bindresvport_sa(s, sa) == -1) {
		(ಶೂನ್ಯ)close(s);
		ಹಿಂತಿರುಗಿ (-1);
	}
	*alport = ntohs(*portp);
	ಹಿಂತಿರುಗಿ (s);
}

#ಆದರೆ_ಅಂತ್ಯ /* HAVE_RRESVPORT_AF */
