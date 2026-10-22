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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_RRESVPORT_AF

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/socket.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <netinet/in.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <arpa/inet.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>

#ਜੇ 0
ਪੂਰਨ
rresvport(ਪੂਰਨ *alport)
{
	ਵਾਪਸ rresvport_af(alport, AF_INET);
}
#ਜੇ_ਅੰਤ

ਪੂਰਨ
rresvport_af(ਪੂਰਨ *alport, sa_family_t af)
{
	ਬਣਤਰ sockaddr_storage ss;
	ਬਣਤਰ sockaddr *sa;
	u_int16_t *portp;
	ਪੂਰਨ s;
	socklen_t salen;

	memset(&ss, '\0', ਆਕਾਰ ss);
	sa = (ਬਣਤਰ sockaddr *)&ss;

	ਚੋਣ (af) {
	ਹਾਲਤ AF_INET:
		salen = ਆਕਾਰ(ਬਣਤਰ sockaddr_in);
		portp = &((ਬਣਤਰ sockaddr_in *)sa)->sin_port;
		ਰੋਕੋ;
	ਹਾਲਤ AF_INET6:
		salen = ਆਕਾਰ(ਬਣਤਰ sockaddr_in6);
		portp = &((ਬਣਤਰ sockaddr_in6 *)sa)->sin6_port;
		ਰੋਕੋ;
	ਮੂਲ:
		errno = EPFNOSUPPORT;
		ਵਾਪਸ (-1);
	}
	sa->sa_family = af;
	
	s = socket(af, SOCK_STREAM, 0);
	ਜੇ (s < 0)
		ਵਾਪਸ (-1);

	*portp = htons(*alport);
	ਜੇ (*alport < IPPORT_RESERVED - 1) {
		ਜੇ (bind(s, sa, salen) >= 0)
			ਵਾਪਸ (s);
		ਜੇ (errno != EADDRINUSE) {
			(ਖਾਲੀ)close(s);
			ਵਾਪਸ (-1);
		}
	}

	*portp = 0;
	sa->sa_family = af;
	ਜੇ (bindresvport_sa(s, sa) == -1) {
		(ਖਾਲੀ)close(s);
		ਵਾਪਸ (-1);
	}
	*alport = ntohs(*portp);
	ਵਾਪਸ (s);
}

#ਜੇ_ਅੰਤ /* HAVE_RRESVPORT_AF */
