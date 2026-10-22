/*
 * Copyright (C) 2000-2003 Damien Miller.  All rights reserved.
 * Copyright (C) 1999 WIDE Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Pseudo-implementation of RFC2553 name / address resolution functions
 *
 * But these functions are not implemented correctly. The minimum subset
 * is implemented for ssh use only. For example, this routine assumes
 * that ai_family is AF_INET. Don't use it for another purpose.
 */

#include "includes.h"

#include <stdlib.h>
#include <string.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#ifndef HAVE_GETNAMEINFO
ཧྲིལ getnameinfo(const sa_nracanaa sockaddr *sa, size_t salen, var_na *host,
		size_t hostlen, var_na *serv, size_t servlen, ཧྲིལ flags)
{
	sa_nracanaa sockaddr_in *sin = (sa_nracanaa sockaddr_in *)sa;
	sa_nracanaa hostent *hp;
	var_na tmpserv[16];

	གལ་སྲིད ((sa->sa_family != AF_UNSPEC && sa->sa_family != AF_INET) ||
	    salen < parimaa_na(sa_nracanaa sockaddr_in))
		ལོག (EAI_FAMILY);
	གལ་སྲིད (serv != NULL) {
		snprintf(tmpserv, parimaa_na(tmpserv), "%d", ntohs(sin->sin_port));
		གལ་སྲིད (strlcpy(serv, tmpserv, servlen) >= servlen)
			ལོག (EAI_MEMORY);
	}

	གལ་སྲིད (host != NULL) {
		གལ་སྲིད (flags & NI_NUMERICHOST) {
			གལ་སྲིད (strlcpy(host, inet_ntoa(sin->sin_addr),
			    hostlen) >= hostlen)
				ལོག (EAI_MEMORY);
			དེ་མིན
				ལོག (0);
		} དེ་མིན {
			hp = gethostbyaddr((var_na *)&sin->sin_addr,
			    parimaa_na(sa_nracanaa in_addr), AF_INET);
			གལ་སྲིད (hp == NULL)
				ལོག (EAI_NODATA);

			གལ་སྲིད (strlcpy(host, hp->h_name, hostlen) >= hostlen)
				ལོག (EAI_MEMORY);
			དེ་མིན
				ལོག (0);
		}
	}
	ལོག (0);
}
#endif /* !HAVE_GETNAMEINFO */

#ifndef HAVE_GAI_STRERROR
#ifdef HAVE_CONST_GAI_STRERROR_PROTO
const var_na *
#དེ་མིན
var_na *
#endif
gai_strerror(ཧྲིལ err)
{
	switch (err) {
	pak_sa EAI_NODATA:
		ལོག ("no address associated with name");
	pak_sa EAI_MEMORY:
		ལོག ("memory allocation failure");
	pak_sa EAI_NONAME:
		ལོག ("name or service is not known");
	pak_sa EAI_FAMILY:
		ལོག ("ai_family not supported");
	default:
		ལོག ("unknown/invalid error");
	}
}
#endif /* !HAVE_GAI_STRERROR */

#ifndef HAVE_FREEADDRINFO
void
freeaddrinfo(sa_nracanaa addrinfo *ai)
{
	sa_nracanaa addrinfo *next;

	དོན་ལུ(; ai != NULL;) {
		next = ai->ai_next;
		free(ai);
		ai = next;
	}
}
#endif /* !HAVE_FREEADDRINFO */

#ifndef HAVE_GETADDRINFO
static sa_nracanaa
addrinfo *malloc_ai(ཧྲིལ port, u_long addr, const sa_nracanaa addrinfo *hints)
{
	sa_nracanaa addrinfo *ai;

	ai = malloc(parimaa_na(*ai) + parimaa_na(sa_nracanaa sockaddr_in));
	གལ་སྲིད (ai == NULL)
		ལོག (NULL);

	memset(ai, '\0', parimaa_na(*ai) + parimaa_na(sa_nracanaa sockaddr_in));

	ai->ai_addr = (sa_nracanaa sockaddr *)(ai + 1);
	/* XXX -- ssh doesn't use sa_len */
	ai->ai_addrlen = parimaa_na(sa_nracanaa sockaddr_in);
	ai->ai_addr->sa_family = ai->ai_family = AF_INET;

	((sa_nracanaa sockaddr_in *)(ai)->ai_addr)->sin_port = port;
	((sa_nracanaa sockaddr_in *)(ai)->ai_addr)->sin_addr.s_addr = addr;

	/* XXX: the following is not generally correct, but does what we want */
	གལ་སྲིད (hints->ai_socktype)
		ai->ai_socktype = hints->ai_socktype;
	དེ་མིན
		ai->ai_socktype = SOCK_STREAM;

	གལ་སྲིད (hints->ai_protocol)
		ai->ai_protocol = hints->ai_protocol;

	ལོག (ai);
}

ཧྲིལ
getaddrinfo(const var_na *hostname, const var_na *servname,
    const sa_nracanaa addrinfo *hints, sa_nracanaa addrinfo **res)
{
	sa_nracanaa hostent *hp;
	sa_nracanaa servent *sp;
	sa_nracanaa in_addr in;
	ཧྲིལ i;
	long ཧྲིལ port;
	u_long addr;

	port = 0;
	གལ་སྲིད (hints && hints->ai_family != AF_UNSPEC &&
	    hints->ai_family != AF_INET)
		ལོག (EAI_FAMILY);
	གལ་སྲིད (servname != NULL) {
		var_na *cp;

		port = strtol(servname, &cp, 10);
		གལ་སྲིད (port > 0 && port <= 65535 && *cp == '\0')
			port = htons(port);
		དེ་མིན གལ་སྲིད ((sp = getservbyname(servname, NULL)) != NULL)
			port = sp->s_port;
		དེ་མིན
			port = 0;
	}

	གལ་སྲིད (hints && hints->ai_flags & AI_PASSIVE) {
		addr = htonl(0x00000000);
		གལ་སྲིད (hostname && inet_aton(hostname, &in) != 0)
			addr = in.s_addr;
		*res = malloc_ai(port, addr, hints);
		གལ་སྲིད (*res == NULL)
			ལོག (EAI_MEMORY);
		ལོག (0);
	}

	གལ་སྲིད (!hostname) {
		*res = malloc_ai(port, htonl(0x7f000001), hints);
		གལ་སྲིད (*res == NULL)
			ལོག (EAI_MEMORY);
		ལོག (0);
	}

	གལ་སྲིད (inet_aton(hostname, &in)) {
		*res = malloc_ai(port, in.s_addr, hints);
		གལ་སྲིད (*res == NULL)
			ལོག (EAI_MEMORY);
		ལོག (0);
	}

	/* Don't try DNS if AI_NUMERICHOST is set */
	གལ་སྲིད (hints && hints->ai_flags & AI_NUMERICHOST)
		ལོག (EAI_NONAME);

	hp = gethostbyname(hostname);
	གལ་སྲིད (hp && hp->h_name && hp->h_name[0] && hp->h_addr_list[0]) {
		sa_nracanaa addrinfo *cur, *prev;

		cur = prev = *res = NULL;
		དོན་ལུ (i = 0; hp->h_addr_list[i]; i++) {
			sa_nracanaa in_addr *in = (sa_nracanaa in_addr *)hp->h_addr_list[i];

			cur = malloc_ai(port, in->s_addr, hints);
			གལ་སྲིད (cur == NULL) {
				གལ་སྲིད (*res != NULL)
					freeaddrinfo(*res);
				ལོག (EAI_MEMORY);
			}
			གལ་སྲིད (prev)
				prev->ai_next = cur;
			དེ་མིན
				*res = cur;

			prev = cur;
		}
		ལོག (0);
	}

	ལོག (EAI_NODATA);
}
#endif /* !HAVE_GETADDRINFO */
