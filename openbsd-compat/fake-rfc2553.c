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
số_nguyên getnameinfo(const struct sockaddr *sa, size_t salen, char *host,
		size_t hostlen, char *serv, size_t servlen, số_nguyên flags)
{
	struct sockaddr_in *sin = (struct sockaddr_in *)sa;
	struct hostent *hp;
	char tmpserv[16];

	nếu ((sa->sa_family != AF_UNSPEC && sa->sa_family != AF_INET) ||
	    salen < sizeof(struct sockaddr_in))
		trả_về (EAI_FAMILY);
	nếu (serv != NULL) {
		snprintf(tmpserv, sizeof(tmpserv), "%d", ntohs(sin->sin_port));
		nếu (strlcpy(serv, tmpserv, servlen) >= servlen)
			trả_về (EAI_MEMORY);
	}

	nếu (host != NULL) {
		nếu (flags & NI_NUMERICHOST) {
			nếu (strlcpy(host, inet_ntoa(sin->sin_addr),
			    hostlen) >= hostlen)
				trả_về (EAI_MEMORY);
			không_thì
				trả_về (0);
		} không_thì {
			hp = gethostbyaddr((char *)&sin->sin_addr,
			    sizeof(struct in_addr), AF_INET);
			nếu (hp == NULL)
				trả_về (EAI_NODATA);

			nếu (strlcpy(host, hp->h_name, hostlen) >= hostlen)
				trả_về (EAI_MEMORY);
			không_thì
				trả_về (0);
		}
	}
	trả_về (0);
}
#endif /* !HAVE_GETNAMEINFO */

#ifndef HAVE_GAI_STRERROR
#ifdef HAVE_CONST_GAI_STRERROR_PROTO
const char *
#không_thì
char *
#endif
gai_strerror(số_nguyên err)
{
	switch (err) {
	case EAI_NODATA:
		trả_về ("no address associated with name");
	case EAI_MEMORY:
		trả_về ("memory allocation failure");
	case EAI_NONAME:
		trả_về ("name or service is not known");
	case EAI_FAMILY:
		trả_về ("ai_family not supported");
	default:
		trả_về ("unknown/invalid error");
	}
}
#endif /* !HAVE_GAI_STRERROR */

#ifndef HAVE_FREEADDRINFO
void
freeaddrinfo(struct addrinfo *ai)
{
	struct addrinfo *next;

	cho(; ai != NULL;) {
		next = ai->ai_next;
		free(ai);
		ai = next;
	}
}
#endif /* !HAVE_FREEADDRINFO */

#ifndef HAVE_GETADDRINFO
static struct
addrinfo *malloc_ai(số_nguyên port, u_long addr, const struct addrinfo *hints)
{
	struct addrinfo *ai;

	ai = malloc(sizeof(*ai) + sizeof(struct sockaddr_in));
	nếu (ai == NULL)
		trả_về (NULL);

	memset(ai, '\0', sizeof(*ai) + sizeof(struct sockaddr_in));

	ai->ai_addr = (struct sockaddr *)(ai + 1);
	/* XXX -- ssh doesn't use sa_len */
	ai->ai_addrlen = sizeof(struct sockaddr_in);
	ai->ai_addr->sa_family = ai->ai_family = AF_INET;

	((struct sockaddr_in *)(ai)->ai_addr)->sin_port = port;
	((struct sockaddr_in *)(ai)->ai_addr)->sin_addr.s_addr = addr;

	/* XXX: the following is not generally correct, but does what we want */
	nếu (hints->ai_socktype)
		ai->ai_socktype = hints->ai_socktype;
	không_thì
		ai->ai_socktype = SOCK_STREAM;

	nếu (hints->ai_protocol)
		ai->ai_protocol = hints->ai_protocol;

	trả_về (ai);
}

số_nguyên
getaddrinfo(const char *hostname, const char *servname,
    const struct addrinfo *hints, struct addrinfo **res)
{
	struct hostent *hp;
	struct servent *sp;
	struct in_addr in;
	số_nguyên i;
	long số_nguyên port;
	u_long addr;

	port = 0;
	nếu (hints && hints->ai_family != AF_UNSPEC &&
	    hints->ai_family != AF_INET)
		trả_về (EAI_FAMILY);
	nếu (servname != NULL) {
		char *cp;

		port = strtol(servname, &cp, 10);
		nếu (port > 0 && port <= 65535 && *cp == '\0')
			port = htons(port);
		không_thì nếu ((sp = getservbyname(servname, NULL)) != NULL)
			port = sp->s_port;
		không_thì
			port = 0;
	}

	nếu (hints && hints->ai_flags & AI_PASSIVE) {
		addr = htonl(0x00000000);
		nếu (hostname && inet_aton(hostname, &in) != 0)
			addr = in.s_addr;
		*res = malloc_ai(port, addr, hints);
		nếu (*res == NULL)
			trả_về (EAI_MEMORY);
		trả_về (0);
	}

	nếu (!hostname) {
		*res = malloc_ai(port, htonl(0x7f000001), hints);
		nếu (*res == NULL)
			trả_về (EAI_MEMORY);
		trả_về (0);
	}

	nếu (inet_aton(hostname, &in)) {
		*res = malloc_ai(port, in.s_addr, hints);
		nếu (*res == NULL)
			trả_về (EAI_MEMORY);
		trả_về (0);
	}

	/* Don't try DNS if AI_NUMERICHOST is set */
	nếu (hints && hints->ai_flags & AI_NUMERICHOST)
		trả_về (EAI_NONAME);

	hp = gethostbyname(hostname);
	nếu (hp && hp->h_name && hp->h_name[0] && hp->h_addr_list[0]) {
		struct addrinfo *cur, *prev;

		cur = prev = *res = NULL;
		cho (i = 0; hp->h_addr_list[i]; i++) {
			struct in_addr *in = (struct in_addr *)hp->h_addr_list[i];

			cur = malloc_ai(port, in->s_addr, hints);
			nếu (cur == NULL) {
				nếu (*res != NULL)
					freeaddrinfo(*res);
				trả_về (EAI_MEMORY);
			}
			nếu (prev)
				prev->ai_next = cur;
			không_thì
				*res = cur;

			prev = cur;
		}
		trả_về (0);
	}

	trả_về (EAI_NODATA);
}
#endif /* !HAVE_GETADDRINFO */
