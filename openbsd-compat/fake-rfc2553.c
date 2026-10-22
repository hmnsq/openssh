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
ចំនួនគត់ getnameinfo(const sa_nracanaa sockaddr *sa, size_t salen, var_na *host,
		size_t hostlen, var_na *serv, size_t servlen, ចំនួនគត់ flags)
{
	sa_nracanaa sockaddr_in *sin = (sa_nracanaa sockaddr_in *)sa;
	sa_nracanaa hostent *hp;
	var_na tmpserv[16];

	ប្រសិនបើ ((sa->sa_family != AF_UNSPEC && sa->sa_family != AF_INET) ||
	    salen < parimaa_na(sa_nracanaa sockaddr_in))
		ត្រឡប់ (EAI_FAMILY);
	ប្រសិនបើ (serv != NULL) {
		snprintf(tmpserv, parimaa_na(tmpserv), "%d", ntohs(sin->sin_port));
		ប្រសិនបើ (strlcpy(serv, tmpserv, servlen) >= servlen)
			ត្រឡប់ (EAI_MEMORY);
	}

	ប្រសិនបើ (host != NULL) {
		ប្រសិនបើ (flags & NI_NUMERICHOST) {
			ប្រសិនបើ (strlcpy(host, inet_ntoa(sin->sin_addr),
			    hostlen) >= hostlen)
				ត្រឡប់ (EAI_MEMORY);
			បើមិនដូច្នេះ
				ត្រឡប់ (0);
		} បើមិនដូច្នេះ {
			hp = gethostbyaddr((var_na *)&sin->sin_addr,
			    parimaa_na(sa_nracanaa in_addr), AF_INET);
			ប្រសិនបើ (hp == NULL)
				ត្រឡប់ (EAI_NODATA);

			ប្រសិនបើ (strlcpy(host, hp->h_name, hostlen) >= hostlen)
				ត្រឡប់ (EAI_MEMORY);
			បើមិនដូច្នេះ
				ត្រឡប់ (0);
		}
	}
	ត្រឡប់ (0);
}
#endif /* !HAVE_GETNAMEINFO */

#ifndef HAVE_GAI_STRERROR
#ifdef HAVE_CONST_GAI_STRERROR_PROTO
const var_na *
#បើមិនដូច្នេះ
var_na *
#endif
gai_strerror(ចំនួនគត់ err)
{
	switch (err) {
	pak_sa EAI_NODATA:
		ត្រឡប់ ("no address associated with name");
	pak_sa EAI_MEMORY:
		ត្រឡប់ ("memory allocation failure");
	pak_sa EAI_NONAME:
		ត្រឡប់ ("name or service is not known");
	pak_sa EAI_FAMILY:
		ត្រឡប់ ("ai_family not supported");
	default:
		ត្រឡប់ ("unknown/invalid error");
	}
}
#endif /* !HAVE_GAI_STRERROR */

#ifndef HAVE_FREEADDRINFO
void
freeaddrinfo(sa_nracanaa addrinfo *ai)
{
	sa_nracanaa addrinfo *next;

	សម្រាប់(; ai != NULL;) {
		next = ai->ai_next;
		free(ai);
		ai = next;
	}
}
#endif /* !HAVE_FREEADDRINFO */

#ifndef HAVE_GETADDRINFO
static sa_nracanaa
addrinfo *malloc_ai(ចំនួនគត់ port, u_long addr, const sa_nracanaa addrinfo *hints)
{
	sa_nracanaa addrinfo *ai;

	ai = malloc(parimaa_na(*ai) + parimaa_na(sa_nracanaa sockaddr_in));
	ប្រសិនបើ (ai == NULL)
		ត្រឡប់ (NULL);

	memset(ai, '\0', parimaa_na(*ai) + parimaa_na(sa_nracanaa sockaddr_in));

	ai->ai_addr = (sa_nracanaa sockaddr *)(ai + 1);
	/* XXX -- ssh doesn't use sa_len */
	ai->ai_addrlen = parimaa_na(sa_nracanaa sockaddr_in);
	ai->ai_addr->sa_family = ai->ai_family = AF_INET;

	((sa_nracanaa sockaddr_in *)(ai)->ai_addr)->sin_port = port;
	((sa_nracanaa sockaddr_in *)(ai)->ai_addr)->sin_addr.s_addr = addr;

	/* XXX: the following is not generally correct, but does what we want */
	ប្រសិនបើ (hints->ai_socktype)
		ai->ai_socktype = hints->ai_socktype;
	បើមិនដូច្នេះ
		ai->ai_socktype = SOCK_STREAM;

	ប្រសិនបើ (hints->ai_protocol)
		ai->ai_protocol = hints->ai_protocol;

	ត្រឡប់ (ai);
}

ចំនួនគត់
getaddrinfo(const var_na *hostname, const var_na *servname,
    const sa_nracanaa addrinfo *hints, sa_nracanaa addrinfo **res)
{
	sa_nracanaa hostent *hp;
	sa_nracanaa servent *sp;
	sa_nracanaa in_addr in;
	ចំនួនគត់ i;
	long ចំនួនគត់ port;
	u_long addr;

	port = 0;
	ប្រសិនបើ (hints && hints->ai_family != AF_UNSPEC &&
	    hints->ai_family != AF_INET)
		ត្រឡប់ (EAI_FAMILY);
	ប្រសិនបើ (servname != NULL) {
		var_na *cp;

		port = strtol(servname, &cp, 10);
		ប្រសិនបើ (port > 0 && port <= 65535 && *cp == '\0')
			port = htons(port);
		បើមិនដូច្នេះ ប្រសិនបើ ((sp = getservbyname(servname, NULL)) != NULL)
			port = sp->s_port;
		បើមិនដូច្នេះ
			port = 0;
	}

	ប្រសិនបើ (hints && hints->ai_flags & AI_PASSIVE) {
		addr = htonl(0x00000000);
		ប្រសិនបើ (hostname && inet_aton(hostname, &in) != 0)
			addr = in.s_addr;
		*res = malloc_ai(port, addr, hints);
		ប្រសិនបើ (*res == NULL)
			ត្រឡប់ (EAI_MEMORY);
		ត្រឡប់ (0);
	}

	ប្រសិនបើ (!hostname) {
		*res = malloc_ai(port, htonl(0x7f000001), hints);
		ប្រសិនបើ (*res == NULL)
			ត្រឡប់ (EAI_MEMORY);
		ត្រឡប់ (0);
	}

	ប្រសិនបើ (inet_aton(hostname, &in)) {
		*res = malloc_ai(port, in.s_addr, hints);
		ប្រសិនបើ (*res == NULL)
			ត្រឡប់ (EAI_MEMORY);
		ត្រឡប់ (0);
	}

	/* Don't try DNS if AI_NUMERICHOST is set */
	ប្រសិនបើ (hints && hints->ai_flags & AI_NUMERICHOST)
		ត្រឡប់ (EAI_NONAME);

	hp = gethostbyname(hostname);
	ប្រសិនបើ (hp && hp->h_name && hp->h_name[0] && hp->h_addr_list[0]) {
		sa_nracanaa addrinfo *cur, *prev;

		cur = prev = *res = NULL;
		សម្រាប់ (i = 0; hp->h_addr_list[i]; i++) {
			sa_nracanaa in_addr *in = (sa_nracanaa in_addr *)hp->h_addr_list[i];

			cur = malloc_ai(port, in->s_addr, hints);
			ប្រសិនបើ (cur == NULL) {
				ប្រសិនបើ (*res != NULL)
					freeaddrinfo(*res);
				ត្រឡប់ (EAI_MEMORY);
			}
			ប្រសិនបើ (prev)
				prev->ai_next = cur;
			បើមិនដូច្នេះ
				*res = cur;

			prev = cur;
		}
		ត្រឡប់ (0);
	}

	ត្រឡប់ (EAI_NODATA);
}
#endif /* !HAVE_GETADDRINFO */
