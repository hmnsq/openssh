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

#అన్తర్భావ "includes.h"

#నిర్వచితం_కాకపోతే HAVE_RRESVPORT_AF

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/socket.h>

#అన్తర్భావ <netinet/in.h>
#అన్తర్భావ <arpa/inet.h>

#అన్తర్భావ <errno.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <unistd.h>

#ఒకవేళ 0
పూర్ణాంకం
rresvport(పూర్ణాంకం *alport)
{
	తిరిగి rresvport_af(alport, AF_INET);
}
#అయితే_ముగింపు

పూర్ణాంకం
rresvport_af(పూర్ణాంకం *alport, sa_family_t af)
{
	నిర్మాణం sockaddr_storage ss;
	నిర్మాణం sockaddr *sa;
	u_int16_t *portp;
	పూర్ణాంకం s;
	socklen_t salen;

	memset(&ss, '\0', పరిమాణం ss);
	sa = (నిర్మాణం sockaddr *)&ss;

	ఎంపిక (af) {
	స్థితి AF_INET:
		salen = పరిమాణం(నిర్మాణం sockaddr_in);
		portp = &((నిర్మాణం sockaddr_in *)sa)->sin_port;
		ఆపు;
	స్థితి AF_INET6:
		salen = పరిమాణం(నిర్మాణం sockaddr_in6);
		portp = &((నిర్మాణం sockaddr_in6 *)sa)->sin6_port;
		ఆపు;
	అప్రమేయ:
		errno = EPFNOSUPPORT;
		తిరిగి (-1);
	}
	sa->sa_family = af;
	
	s = socket(af, SOCK_STREAM, 0);
	ఒకవేళ (s < 0)
		తిరిగి (-1);

	*portp = htons(*alport);
	ఒకవేళ (*alport < IPPORT_RESERVED - 1) {
		ఒకవేళ (bind(s, sa, salen) >= 0)
			తిరిగి (s);
		ఒకవేళ (errno != EADDRINUSE) {
			(శూన్య)close(s);
			తిరిగి (-1);
		}
	}

	*portp = 0;
	sa->sa_family = af;
	ఒకవేళ (bindresvport_sa(s, sa) == -1) {
		(శూన్య)close(s);
		తిరిగి (-1);
	}
	*alport = ntohs(*portp);
	తిరిగి (s);
}

#అయితే_ముగింపు /* HAVE_RRESVPORT_AF */
