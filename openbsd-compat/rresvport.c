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

#ifndef HAVE_RRESVPORT_AF

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/socket.h>

#ಅನ್ತರ್ಭಾವ <netinet/in.h>
#ಅನ್ತರ್ಭಾವ <arpa/inet.h>

#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>

#ಯದಿ 0
ಪೂರ್ಣಾಙ್ಕ
rresvport(ಪೂರ್ಣಾಙ್ಕ *alport)
{
	ಪ್ರತ್ಯಾಗಮ rresvport_af(alport, AF_INET);
}
#endif

ಪೂರ್ಣಾಙ್ಕ
rresvport_af(ಪೂರ್ಣಾಙ್ಕ *alport, sa_family_t af)
{
	ಸಂರಚನಾ sockaddr_storage ss;
	ಸಂರಚನಾ sockaddr *sa;
	u_int16_t *portp;
	ಪೂರ್ಣಾಙ್ಕ s;
	socklen_t salen;

	memset(&ss, '\0', ಪರಿಮಾಣ ss);
	sa = (ಸಂರಚನಾ sockaddr *)&ss;

	ವಿಕಲ್ಪ (af) {
	ಪಕ್ಷ AF_INET:
		salen = ಪರಿಮಾಣ(ಸಂರಚನಾ sockaddr_in);
		portp = &((ಸಂರಚನಾ sockaddr_in *)sa)->sin_port;
		ಭಙ್ಗ;
	ಪಕ್ಷ AF_INET6:
		salen = ಪರಿಮಾಣ(ಸಂರಚನಾ sockaddr_in6);
		portp = &((ಸಂರಚನಾ sockaddr_in6 *)sa)->sin6_port;
		ಭಙ್ಗ;
	ಸ್ವಭಾವ:
		errno = EPFNOSUPPORT;
		ಪ್ರತ್ಯಾಗಮ (-1);
	}
	sa->sa_family = af;
	
	s = socket(af, SOCK_STREAM, 0);
	ಯದಿ (s < 0)
		ಪ್ರತ್ಯಾಗಮ (-1);

	*portp = htons(*alport);
	ಯದಿ (*alport < IPPORT_RESERVED - 1) {
		ಯದಿ (bind(s, sa, salen) >= 0)
			ಪ್ರತ್ಯಾಗಮ (s);
		ಯದಿ (errno != EADDRINUSE) {
			(ಶೂನ್ಯ)close(s);
			ಪ್ರತ್ಯಾಗಮ (-1);
		}
	}

	*portp = 0;
	sa->sa_family = af;
	ಯದಿ (bindresvport_sa(s, sa) == -1) {
		(ಶೂನ್ಯ)close(s);
		ಪ್ರತ್ಯಾಗಮ (-1);
	}
	*alport = ntohs(*portp);
	ಪ್ರತ್ಯಾಗಮ (s);
}

#endif /* HAVE_RRESVPORT_AF */
