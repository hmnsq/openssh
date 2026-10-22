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

#അന്തര്ഭാവ "includes.h"

#ifndef HAVE_RRESVPORT_AF

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/socket.h>

#അന്തര്ഭാവ <netinet/in.h>
#അന്തര്ഭാവ <arpa/inet.h>

#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <unistd.h>

#എങ്കിൽ 0
പൂർണ്ണസംഖ്യ
rresvport(പൂർണ്ണസംഖ്യ *alport)
{
	തിരികെ rresvport_af(alport, AF_INET);
}
#endif

പൂർണ്ണസംഖ്യ
rresvport_af(പൂർണ്ണസംഖ്യ *alport, sa_family_t af)
{
	ഘടന sockaddr_storage ss;
	ഘടന sockaddr *sa;
	u_int16_t *portp;
	പൂർണ്ണസംഖ്യ s;
	socklen_t salen;

	memset(&ss, '\0', വലുപ്പം ss);
	sa = (ഘടന sockaddr *)&ss;

	തിരഞ്ഞെടുപ്പ് (af) {
	അവസ്ഥ AF_INET:
		salen = വലുപ്പം(ഘടന sockaddr_in);
		portp = &((ഘടന sockaddr_in *)sa)->sin_port;
		നിർത്തുക;
	അവസ്ഥ AF_INET6:
		salen = വലുപ്പം(ഘടന sockaddr_in6);
		portp = &((ഘടന sockaddr_in6 *)sa)->sin6_port;
		നിർത്തുക;
	സ്ഥിരസ്ഥിതി:
		errno = EPFNOSUPPORT;
		തിരികെ (-1);
	}
	sa->sa_family = af;
	
	s = socket(af, SOCK_STREAM, 0);
	എങ്കിൽ (s < 0)
		തിരികെ (-1);

	*portp = htons(*alport);
	എങ്കിൽ (*alport < IPPORT_RESERVED - 1) {
		എങ്കിൽ (bind(s, sa, salen) >= 0)
			തിരികെ (s);
		എങ്കിൽ (errno != EADDRINUSE) {
			(ശൂന്യം)close(s);
			തിരികെ (-1);
		}
	}

	*portp = 0;
	sa->sa_family = af;
	എങ്കിൽ (bindresvport_sa(s, sa) == -1) {
		(ശൂന്യം)close(s);
		തിരികെ (-1);
	}
	*alport = ntohs(*portp);
	തിരികെ (s);
}

#endif /* HAVE_RRESVPORT_AF */
