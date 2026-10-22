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
цяло getnameinfo(const struct sockaddr *sa, size_t salen, char *host,
		size_t hostlen, char *serv, size_t servlen, цяло flags)
{
	struct sockaddr_in *sin = (struct sockaddr_in *)sa;
	struct hostent *hp;
	char tmpserv[16];

	ако ((sa->sa_family != AF_UNSPEC && sa->sa_family != AF_INET) ||
	    salen < sizeof(struct sockaddr_in))
		върни (EAI_FAMILY);
	ако (serv != NULL) {
		snprintf(tmpserv, sizeof(tmpserv), "%d", ntohs(sin->sin_port));
		ако (strlcpy(serv, tmpserv, servlen) >= servlen)
			върни (EAI_MEMORY);
	}

	ако (host != NULL) {
		ако (flags & NI_NUMERICHOST) {
			ако (strlcpy(host, inet_ntoa(sin->sin_addr),
			    hostlen) >= hostlen)
				върни (EAI_MEMORY);
			иначе
				върни (0);
		} иначе {
			hp = gethostbyaddr((char *)&sin->sin_addr,
			    sizeof(struct in_addr), AF_INET);
			ако (hp == NULL)
				върни (EAI_NODATA);

			ако (strlcpy(host, hp->h_name, hostlen) >= hostlen)
				върни (EAI_MEMORY);
			иначе
				върни (0);
		}
	}
	върни (0);
}
#endif /* !HAVE_GETNAMEINFO */

#ifndef HAVE_GAI_STRERROR
#ifdef HAVE_CONST_GAI_STRERROR_PROTO
const char *
#иначе
char *
#endif
gai_strerror(цяло err)
{
	switch (err) {
	case EAI_NODATA:
		върни ("no address associated with name");
	case EAI_MEMORY:
		върни ("memory allocation failure");
	case EAI_NONAME:
		върни ("name or service is not known");
	case EAI_FAMILY:
		върни ("ai_family not supported");
	default:
		върни ("unknown/invalid error");
	}
}
#endif /* !HAVE_GAI_STRERROR */

#ifndef HAVE_FREEADDRINFO
void
freeaddrinfo(struct addrinfo *ai)
{
	struct addrinfo *next;

	за(; ai != NULL;) {
		next = ai->ai_next;
		free(ai);
		ai = next;
	}
}
#endif /* !HAVE_FREEADDRINFO */

#ifndef HAVE_GETADDRINFO
static struct
addrinfo *malloc_ai(цяло port, u_long addr, const struct addrinfo *hints)
{
	struct addrinfo *ai;

	ai = malloc(sizeof(*ai) + sizeof(struct sockaddr_in));
	ако (ai == NULL)
		върни (NULL);

	memset(ai, '\0', sizeof(*ai) + sizeof(struct sockaddr_in));

	ai->ai_addr = (struct sockaddr *)(ai + 1);
	/* XXX -- ssh doesn't use sa_len */
	ai->ai_addrlen = sizeof(struct sockaddr_in);
	ai->ai_addr->sa_family = ai->ai_family = AF_INET;

	((struct sockaddr_in *)(ai)->ai_addr)->sin_port = port;
	((struct sockaddr_in *)(ai)->ai_addr)->sin_addr.s_addr = addr;

	/* XXX: the following is not generally correct, but does what we want */
	ако (hints->ai_socktype)
		ai->ai_socktype = hints->ai_socktype;
	иначе
		ai->ai_socktype = SOCK_STREAM;

	ако (hints->ai_protocol)
		ai->ai_protocol = hints->ai_protocol;

	върни (ai);
}

цяло
getaddrinfo(const char *hostname, const char *servname,
    const struct addrinfo *hints, struct addrinfo **res)
{
	struct hostent *hp;
	struct servent *sp;
	struct in_addr in;
	цяло i;
	long цяло port;
	u_long addr;

	port = 0;
	ако (hints && hints->ai_family != AF_UNSPEC &&
	    hints->ai_family != AF_INET)
		върни (EAI_FAMILY);
	ако (servname != NULL) {
		char *cp;

		port = strtol(servname, &cp, 10);
		ако (port > 0 && port <= 65535 && *cp == '\0')
			port = htons(port);
		иначе ако ((sp = getservbyname(servname, NULL)) != NULL)
			port = sp->s_port;
		иначе
			port = 0;
	}

	ако (hints && hints->ai_flags & AI_PASSIVE) {
		addr = htonl(0x00000000);
		ако (hostname && inet_aton(hostname, &in) != 0)
			addr = in.s_addr;
		*res = malloc_ai(port, addr, hints);
		ако (*res == NULL)
			върни (EAI_MEMORY);
		върни (0);
	}

	ако (!hostname) {
		*res = malloc_ai(port, htonl(0x7f000001), hints);
		ако (*res == NULL)
			върни (EAI_MEMORY);
		върни (0);
	}

	ако (inet_aton(hostname, &in)) {
		*res = malloc_ai(port, in.s_addr, hints);
		ако (*res == NULL)
			върни (EAI_MEMORY);
		върни (0);
	}

	/* Don't try DNS if AI_NUMERICHOST is set */
	ако (hints && hints->ai_flags & AI_NUMERICHOST)
		върни (EAI_NONAME);

	hp = gethostbyname(hostname);
	ако (hp && hp->h_name && hp->h_name[0] && hp->h_addr_list[0]) {
		struct addrinfo *cur, *prev;

		cur = prev = *res = NULL;
		за (i = 0; hp->h_addr_list[i]; i++) {
			struct in_addr *in = (struct in_addr *)hp->h_addr_list[i];

			cur = malloc_ai(port, in->s_addr, hints);
			ако (cur == NULL) {
				ако (*res != NULL)
					freeaddrinfo(*res);
				върни (EAI_MEMORY);
			}
			ако (prev)
				prev->ai_next = cur;
			иначе
				*res = cur;

			prev = cur;
		}
		върни (0);
	}

	върни (EAI_NODATA);
}
#endif /* !HAVE_GETADDRINFO */
