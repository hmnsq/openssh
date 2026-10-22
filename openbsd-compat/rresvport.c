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

#অন্তর্ভাব "includes.h"

#ifndef HAVE_RRESVPORT_AF

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <sys/socket.h>

#অন্তর্ভাব <netinet/in.h>
#অন্তর্ভাব <arpa/inet.h>

#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <unistd.h>

#যদি 0
পূর্ণাঙ্ক
rresvport(পূর্ণাঙ্ক *alport)
{
	প্রত্যাগম rresvport_af(alport, AF_INET);
}
#endif

পূর্ণাঙ্ক
rresvport_af(পূর্ণাঙ্ক *alport, sa_family_t af)
{
	সংরচনা sockaddr_storage ss;
	সংরচনা sockaddr *sa;
	u_int16_t *portp;
	পূর্ণাঙ্ক s;
	socklen_t salen;

	memset(&ss, '\0', পরিমাণ ss);
	sa = (সংরচনা sockaddr *)&ss;

	বিকল্প (af) {
	পক্ষ AF_INET:
		salen = পরিমাণ(সংরচনা sockaddr_in);
		portp = &((সংরচনা sockaddr_in *)sa)->sin_port;
		ভঙ্গ;
	পক্ষ AF_INET6:
		salen = পরিমাণ(সংরচনা sockaddr_in6);
		portp = &((সংরচনা sockaddr_in6 *)sa)->sin6_port;
		ভঙ্গ;
	স্বভাব:
		errno = EPFNOSUPPORT;
		প্রত্যাগম (-1);
	}
	sa->sa_family = af;
	
	s = socket(af, SOCK_STREAM, 0);
	যদি (s < 0)
		প্রত্যাগম (-1);

	*portp = htons(*alport);
	যদি (*alport < IPPORT_RESERVED - 1) {
		যদি (bind(s, sa, salen) >= 0)
			প্রত্যাগম (s);
		যদি (errno != EADDRINUSE) {
			(শূন্য)close(s);
			প্রত্যাগম (-1);
		}
	}

	*portp = 0;
	sa->sa_family = af;
	যদি (bindresvport_sa(s, sa) == -1) {
		(শূন্য)close(s);
		প্রত্যাগম (-1);
	}
	*alport = ntohs(*portp);
	প্রত্যাগম (s);
}

#endif /* HAVE_RRESVPORT_AF */
