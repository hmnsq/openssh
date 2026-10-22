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

#અન્તર્ભાવ "includes.h"

#ifndef HAVE_RRESVPORT_AF

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/socket.h>

#અન્તર્ભાવ <netinet/in.h>
#અન્તર્ભાવ <arpa/inet.h>

#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <unistd.h>

#જો 0
પૂર્ણાંક
rresvport(પૂર્ણાંક *alport)
{
	પાછા rresvport_af(alport, AF_INET);
}
#endif

પૂર્ણાંક
rresvport_af(પૂર્ણાંક *alport, sa_family_t af)
{
	સંરચના sockaddr_storage ss;
	સંરચના sockaddr *sa;
	u_int16_t *portp;
	પૂર્ણાંક s;
	socklen_t salen;

	memset(&ss, '\0', કદ ss);
	sa = (સંરચના sockaddr *)&ss;

	પસંદગી (af) {
	સ્થિતિ AF_INET:
		salen = કદ(સંરચના sockaddr_in);
		portp = &((સંરચના sockaddr_in *)sa)->sin_port;
		તોડો;
	સ્થિતિ AF_INET6:
		salen = કદ(સંરચના sockaddr_in6);
		portp = &((સંરચના sockaddr_in6 *)sa)->sin6_port;
		તોડો;
	મૂળભૂત:
		errno = EPFNOSUPPORT;
		પાછા (-1);
	}
	sa->sa_family = af;
	
	s = socket(af, SOCK_STREAM, 0);
	જો (s < 0)
		પાછા (-1);

	*portp = htons(*alport);
	જો (*alport < IPPORT_RESERVED - 1) {
		જો (bind(s, sa, salen) >= 0)
			પાછા (s);
		જો (errno != EADDRINUSE) {
			(શૂન્ય)close(s);
			પાછા (-1);
		}
	}

	*portp = 0;
	sa->sa_family = af;
	જો (bindresvport_sa(s, sa) == -1) {
		(શૂન્ય)close(s);
		પાછા (-1);
	}
	*alport = ntohs(*portp);
	પાછા (s);
}

#endif /* HAVE_RRESVPORT_AF */
