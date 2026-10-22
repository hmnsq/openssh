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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>

#अन्तर्भाव <netinet/in.h>
#अन्तर्भाव <arpa/inet.h>

#ifndef HAVE_GETNAMEINFO
पूर्णाङ्क getnameinfo(ध्रुव संरचना sockaddr *sa, size_t salen, वर्ण *host,
		size_t hostlen, वर्ण *serv, size_t servlen, पूर्णाङ्क flags)
{
	संरचना sockaddr_in *sin = (संरचना sockaddr_in *)sa;
	संरचना hostent *hp;
	वर्ण tmpserv[16];

	जइ ((sa->sa_family != AF_UNSPEC && sa->sa_family != AF_INET) ||
	    salen < परिमाण(संरचना sockaddr_in))
		प्रत्यागम (EAI_FAMILY);
	जइ (serv != रिक्त) {
		snprintf(tmpserv, परिमाण(tmpserv), "%d", ntohs(sin->sin_port));
		जइ (strlcpy(serv, tmpserv, servlen) >= servlen)
			प्रत्यागम (EAI_MEMORY);
	}

	जइ (host != रिक्त) {
		जइ (flags & NI_NUMERICHOST) {
			जइ (strlcpy(host, inet_ntoa(sin->sin_addr),
			    hostlen) >= hostlen)
				प्रत्यागम (EAI_MEMORY);
			अण्णहा
				प्रत्यागम (0);
		} अण्णहा {
			hp = gethostbyaddr((वर्ण *)&sin->sin_addr,
			    परिमाण(संरचना in_addr), AF_INET);
			जइ (hp == रिक्त)
				प्रत्यागम (EAI_NODATA);

			जइ (strlcpy(host, hp->h_name, hostlen) >= hostlen)
				प्रत्यागम (EAI_MEMORY);
			अण्णहा
				प्रत्यागम (0);
		}
	}
	प्रत्यागम (0);
}
#endif /* !HAVE_GETNAMEINFO */

#ifndef HAVE_GAI_STRERROR
#ifdef HAVE_CONST_GAI_STRERROR_PROTO
ध्रुव वर्ण *
#अण्णहा
वर्ण *
#endif
gai_strerror(पूर्णाङ्क err)
{
	विकल्प (err) {
	पक्ष EAI_NODATA:
		प्रत्यागम ("no address associated with name");
	पक्ष EAI_MEMORY:
		प्रत्यागम ("memory allocation failure");
	पक्ष EAI_NONAME:
		प्रत्यागम ("name or service is not known");
	पक्ष EAI_FAMILY:
		प्रत्यागम ("ai_family not supported");
	स्वभाव:
		प्रत्यागम ("unknown/invalid error");
	}
}
#endif /* !HAVE_GAI_STRERROR */

#ifndef HAVE_FREEADDRINFO
शून्य
freeaddrinfo(संरचना addrinfo *ai)
{
	संरचना addrinfo *next;

	प्रति(; ai != रिक्त;) {
		next = ai->ai_next;
		मुक्त(ai);
		ai = next;
	}
}
#endif /* !HAVE_FREEADDRINFO */

#ifndef HAVE_GETADDRINFO
स्थिर संरचना
addrinfo *malloc_ai(पूर्णाङ्क port, u_long addr, ध्रुव संरचना addrinfo *hints)
{
	संरचना addrinfo *ai;

	ai = malloc(परिमाण(*ai) + परिमाण(संरचना sockaddr_in));
	जइ (ai == रिक्त)
		प्रत्यागम (रिक्त);

	memset(ai, '\0', परिमाण(*ai) + परिमाण(संरचना sockaddr_in));

	ai->ai_addr = (संरचना sockaddr *)(ai + 1);
	/* XXX -- ssh doesn't use sa_len */
	ai->ai_addrlen = परिमाण(संरचना sockaddr_in);
	ai->ai_addr->sa_family = ai->ai_family = AF_INET;

	((संरचना sockaddr_in *)(ai)->ai_addr)->sin_port = port;
	((संरचना sockaddr_in *)(ai)->ai_addr)->sin_addr.s_addr = addr;

	/* XXX: the following is not generally correct, but does what we want */
	जइ (hints->ai_socktype)
		ai->ai_socktype = hints->ai_socktype;
	अण्णहा
		ai->ai_socktype = SOCK_STREAM;

	जइ (hints->ai_protocol)
		ai->ai_protocol = hints->ai_protocol;

	प्रत्यागम (ai);
}

पूर्णाङ्क
getaddrinfo(ध्रुव वर्ण *hostname, ध्रुव वर्ण *servname,
    ध्रुव संरचना addrinfo *hints, संरचना addrinfo **res)
{
	संरचना hostent *hp;
	संरचना servent *sp;
	संरचना in_addr in;
	पूर्णाङ्क i;
	long पूर्णाङ्क port;
	u_long addr;

	port = 0;
	जइ (hints && hints->ai_family != AF_UNSPEC &&
	    hints->ai_family != AF_INET)
		प्रत्यागम (EAI_FAMILY);
	जइ (servname != रिक्त) {
		वर्ण *cp;

		port = strtol(servname, &cp, 10);
		जइ (port > 0 && port <= 65535 && *cp == '\0')
			port = htons(port);
		अण्णहा जइ ((sp = getservbyname(servname, रिक्त)) != रिक्त)
			port = sp->s_port;
		अण्णहा
			port = 0;
	}

	जइ (hints && hints->ai_flags & AI_PASSIVE) {
		addr = htonl(0x00000000);
		जइ (hostname && inet_aton(hostname, &in) != 0)
			addr = in.s_addr;
		*res = malloc_ai(port, addr, hints);
		जइ (*res == रिक्त)
			प्रत्यागम (EAI_MEMORY);
		प्रत्यागम (0);
	}

	जइ (!hostname) {
		*res = malloc_ai(port, htonl(0x7f000001), hints);
		जइ (*res == रिक्त)
			प्रत्यागम (EAI_MEMORY);
		प्रत्यागम (0);
	}

	जइ (inet_aton(hostname, &in)) {
		*res = malloc_ai(port, in.s_addr, hints);
		जइ (*res == रिक्त)
			प्रत्यागम (EAI_MEMORY);
		प्रत्यागम (0);
	}

	/* Don't try DNS if AI_NUMERICHOST is set */
	जइ (hints && hints->ai_flags & AI_NUMERICHOST)
		प्रत्यागम (EAI_NONAME);

	hp = gethostbyname(hostname);
	जइ (hp && hp->h_name && hp->h_name[0] && hp->h_addr_list[0]) {
		संरचना addrinfo *cur, *prev;

		cur = prev = *res = रिक्त;
		प्रति (i = 0; hp->h_addr_list[i]; i++) {
			संरचना in_addr *in = (संरचना in_addr *)hp->h_addr_list[i];

			cur = malloc_ai(port, in->s_addr, hints);
			जइ (cur == रिक्त) {
				जइ (*res != रिक्त)
					freeaddrinfo(*res);
				प्रत्यागम (EAI_MEMORY);
			}
			जइ (prev)
				prev->ai_next = cur;
			अण्णहा
				*res = cur;

			prev = cur;
		}
		प्रत्यागम (0);
	}

	प्रत्यागम (EAI_NODATA);
}
#endif /* !HAVE_GETADDRINFO */
