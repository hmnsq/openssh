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

#अन्तर्भाव "includes.h"

#यदि_अपरिभाषितम् HAVE_RRESVPORT_AF

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/socket.h>

#अन्तर्भाव <netinet/in.h>
#अन्तर्भाव <arpa/inet.h>

#अन्तर्भाव <errno.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <unistd.h>

#यदि 0
पूर्णाङ्क
rresvport(पूर्णाङ्क *alport)
{
	प्रत्यागम rresvport_af(alport, AF_INET);
}
#यदि_अन्तः

पूर्णाङ्क
rresvport_af(पूर्णाङ्क *alport, sa_family_t af)
{
	संरचना sockaddr_storage ss;
	संरचना sockaddr *sa;
	u_int16_t *portp;
	पूर्णाङ्क s;
	socklen_t salen;

	स्मृतिं_पूरय(&ss, '\0', परिमाण ss);
	sa = (संरचना sockaddr *)&ss;

	विकल्प (af) {
	पक्ष AF_INET:
		salen = परिमाण(संरचना sockaddr_in);
		portp = &((संरचना sockaddr_in *)sa)->sin_port;
		भङ्ग;
	पक्ष AF_INET6:
		salen = परिमाण(संरचना sockaddr_in6);
		portp = &((संरचना sockaddr_in6 *)sa)->sin6_port;
		भङ्ग;
	स्वभाव:
		errno = EPFNOSUPPORT;
		प्रत्यागम (-1);
	}
	sa->sa_family = af;
	
	s = socket(af, SOCK_STREAM, 0);
	यदि (s < 0)
		प्रत्यागम (-1);

	*portp = htons(*alport);
	यदि (*alport < IPPORT_RESERVED - 1) {
		यदि (bind(s, sa, salen) >= 0)
			प्रत्यागम (s);
		यदि (errno != EADDRINUSE) {
			(शून्य)close(s);
			प्रत्यागम (-1);
		}
	}

	*portp = 0;
	sa->sa_family = af;
	यदि (bindresvport_sa(s, sa) == -1) {
		(शून्य)close(s);
		प्रत्यागम (-1);
	}
	*alport = ntohs(*portp);
	प्रत्यागम (s);
}

#यदि_अन्तः /* HAVE_RRESVPORT_AF */
