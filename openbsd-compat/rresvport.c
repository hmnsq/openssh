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

#include "includes.h"

#ifndef HAVE_RRESVPORT_AF

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ᤀᤡ᤺ 0
puur_naa_nka
rresvport(puur_naa_nka *alport)
{
	ᤀᤡᤴ rresvport_af(alport, AF_INET);
}
#endif

puur_naa_nka
rresvport_af(puur_naa_nka *alport, sa_family_t af)
{
	sa_nracanaa sockaddr_storage ss;
	sa_nracanaa sockaddr *sa;
	u_int16_t *portp;
	puur_naa_nka s;
	socklen_t salen;

	memset(&ss, '\0', parimaa_na ss);
	sa = (sa_nracanaa sockaddr *)&ss;

	switch (af) {
	pak_sa AF_INET:
		salen = parimaa_na(sa_nracanaa sockaddr_in);
		portp = &((sa_nracanaa sockaddr_in *)sa)->sin_port;
		bha_nga;
	pak_sa AF_INET6:
		salen = parimaa_na(sa_nracanaa sockaddr_in6);
		portp = &((sa_nracanaa sockaddr_in6 *)sa)->sin6_port;
		bha_nga;
	default:
		errno = EPFNOSUPPORT;
		ᤀᤡᤴ (-1);
	}
	sa->sa_family = af;
	
	s = socket(af, SOCK_STREAM, 0);
	ᤀᤡ᤺ (s < 0)
		ᤀᤡᤴ (-1);

	*portp = htons(*alport);
	ᤀᤡ᤺ (*alport < IPPORT_RESERVED - 1) {
		ᤀᤡ᤺ (bind(s, sa, salen) >= 0)
			ᤀᤡᤴ (s);
		ᤀᤡ᤺ (errno != EADDRINUSE) {
			(void)close(s);
			ᤀᤡᤴ (-1);
		}
	}

	*portp = 0;
	sa->sa_family = af;
	ᤀᤡ᤺ (bindresvport_sa(s, sa) == -1) {
		(void)close(s);
		ᤀᤡᤴ (-1);
	}
	*alport = ntohs(*portp);
	ᤀᤡᤴ (s);
}

#endif /* HAVE_RRESVPORT_AF */
