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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ifndef HAVE_RRESVPORT_AF

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/socket.h>

#ଅନ୍ତର୍ଭାଵ <netinet/in.h>
#ଅନ୍ତର୍ଭାଵ <arpa/inet.h>

#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>

#ଯଦି 0
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
rresvport(ପୂର୍ଣ୍ଣସଂଖ୍ୟା *alport)
{
	ଫେରନ୍ତୁ rresvport_af(alport, AF_INET);
}
#endif

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
rresvport_af(ପୂର୍ଣ୍ଣସଂଖ୍ୟା *alport, sa_family_t af)
{
	ସଂରଚନା sockaddr_storage ss;
	ସଂରଚନା sockaddr *sa;
	u_int16_t *portp;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା s;
	socklen_t salen;

	memset(&ss, '\0', ଆକାର ss);
	sa = (ସଂରଚନା sockaddr *)&ss;

	ବାଛ (af) {
	ସ୍ଥିତି AF_INET:
		salen = ଆକାର(ସଂରଚନା sockaddr_in);
		portp = &((ସଂରଚନା sockaddr_in *)sa)->sin_port;
		ଭାଙ୍ଗ;
	ସ୍ଥିତି AF_INET6:
		salen = ଆକାର(ସଂରଚନା sockaddr_in6);
		portp = &((ସଂରଚନା sockaddr_in6 *)sa)->sin6_port;
		ଭାଙ୍ଗ;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		errno = EPFNOSUPPORT;
		ଫେରନ୍ତୁ (-1);
	}
	sa->sa_family = af;
	
	s = socket(af, SOCK_STREAM, 0);
	ଯଦି (s < 0)
		ଫେରନ୍ତୁ (-1);

	*portp = htons(*alport);
	ଯଦି (*alport < IPPORT_RESERVED - 1) {
		ଯଦି (bind(s, sa, salen) >= 0)
			ଫେରନ୍ତୁ (s);
		ଯଦି (errno != EADDRINUSE) {
			(ଶୂନ୍ୟ)close(s);
			ଫେରନ୍ତୁ (-1);
		}
	}

	*portp = 0;
	sa->sa_family = af;
	ଯଦି (bindresvport_sa(s, sa) == -1) {
		(ଶୂନ୍ୟ)close(s);
		ଫେରନ୍ତୁ (-1);
	}
	*alport = ntohs(*portp);
	ଫେରନ୍ତୁ (s);
}

#endif /* HAVE_RRESVPORT_AF */
