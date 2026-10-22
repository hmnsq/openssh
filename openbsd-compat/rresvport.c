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

#அந்தர்பாவ "includes.h"

#ifndef HAVE_RRESVPORT_AF

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/socket.h>

#அந்தர்பாவ <netinet/in.h>
#அந்தர்பாவ <arpa/inet.h>

#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <unistd.h>

#எனில் 0
முழு
rresvport(முழு *alport)
{
	திரும்பு rresvport_af(alport, AF_INET);
}
#endif

முழு
rresvport_af(முழு *alport, sa_family_t af)
{
	கட்டமைப்பு sockaddr_storage ss;
	கட்டமைப்பு sockaddr *sa;
	u_int16_t *portp;
	முழு s;
	socklen_t salen;

	memset(&ss, '\0', அளவு ss);
	sa = (கட்டமைப்பு sockaddr *)&ss;

	தேர்வு (af) {
	நிலை AF_INET:
		salen = அளவு(கட்டமைப்பு sockaddr_in);
		portp = &((கட்டமைப்பு sockaddr_in *)sa)->sin_port;
		நிறுத்து;
	நிலை AF_INET6:
		salen = அளவு(கட்டமைப்பு sockaddr_in6);
		portp = &((கட்டமைப்பு sockaddr_in6 *)sa)->sin6_port;
		நிறுத்து;
	இயல்பு:
		errno = EPFNOSUPPORT;
		திரும்பு (-1);
	}
	sa->sa_family = af;
	
	s = socket(af, SOCK_STREAM, 0);
	எனில் (s < 0)
		திரும்பு (-1);

	*portp = htons(*alport);
	எனில் (*alport < IPPORT_RESERVED - 1) {
		எனில் (bind(s, sa, salen) >= 0)
			திரும்பு (s);
		எனில் (errno != EADDRINUSE) {
			(வெறுமை)close(s);
			திரும்பு (-1);
		}
	}

	*portp = 0;
	sa->sa_family = af;
	எனில் (bindresvport_sa(s, sa) == -1) {
		(வெறுமை)close(s);
		திரும்பு (-1);
	}
	*alport = ntohs(*portp);
	திரும்பு (s);
}

#endif /* HAVE_RRESVPORT_AF */
