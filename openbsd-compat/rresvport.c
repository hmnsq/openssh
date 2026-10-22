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

#ضمن "includes.h"

#ifndef HAVE_RRESVPORT_AF

#ضمن <sys/types.h>
#ضمن <sys/socket.h>

#ضمن <netinet/in.h>
#ضمن <arpa/inet.h>

#ضمن <errno.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <unistd.h>

#إذا 0
صحيح
rresvport(صحيح *alport)
{
	أرجع rresvport_af(alport, AF_INET);
}
#endif

صحيح
rresvport_af(صحيح *alport, sa_family_t af)
{
	بنية sockaddr_storage ss;
	بنية sockaddr *sa;
	u_int16_t *portp;
	صحيح s;
	socklen_t salen;

	memset(&ss, '\0', حجم ss);
	sa = (بنية sockaddr *)&ss;

	بدل (af) {
	حالة AF_INET:
		salen = حجم(بنية sockaddr_in);
		portp = &((بنية sockaddr_in *)sa)->sin_port;
		اكسر;
	حالة AF_INET6:
		salen = حجم(بنية sockaddr_in6);
		portp = &((بنية sockaddr_in6 *)sa)->sin6_port;
		اكسر;
	افتراضي:
		errno = EPFNOSUPPORT;
		أرجع (-1);
	}
	sa->sa_family = af;
	
	s = socket(af, SOCK_STREAM, 0);
	إذا (s < 0)
		أرجع (-1);

	*portp = htons(*alport);
	إذا (*alport < IPPORT_RESERVED - 1) {
		إذا (bind(s, sa, salen) >= 0)
			أرجع (s);
		إذا (errno != EADDRINUSE) {
			(فراغ)close(s);
			أرجع (-1);
		}
	}

	*portp = 0;
	sa->sa_family = af;
	إذا (bindresvport_sa(s, sa) == -1) {
		(فراغ)close(s);
		أرجع (-1);
	}
	*alport = ntohs(*portp);
	أرجع (s);
}

#endif /* HAVE_RRESVPORT_AF */
