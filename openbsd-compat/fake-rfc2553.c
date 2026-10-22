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

	सचे ((sa->sa_family != AF_UNSPEC && sa->sa_family != AF_INET) ||
	    salen < परिमाण(संरचना sockaddr_in))
		पटिनिवत्त (EAI_FAMILY);
	सचे (serv != रिक्त) {
		snprintf(tmpserv, परिमाण(tmpserv), "%d", ntohs(sin->sin_port));
		सचे (strlcpy(serv, tmpserv, servlen) >= servlen)
			पटिनिवत्त (EAI_MEMORY);
	}

	सचे (host != रिक्त) {
		सचे (flags & NI_NUMERICHOST) {
			सचे (strlcpy(host, inet_ntoa(sin->sin_addr),
			    hostlen) >= hostlen)
				पटिनिवत्त (EAI_MEMORY);
			अञ्ञथा
				पटिनिवत्त (0);
		} अञ्ञथा {
			hp = gethostbyaddr((वर्ण *)&sin->sin_addr,
			    परिमाण(संरचना in_addr), AF_INET);
			सचे (hp == रिक्त)
				पटिनिवत्त (EAI_NODATA);

			सचे (strlcpy(host, hp->h_name, hostlen) >= hostlen)
				पटिनिवत्त (EAI_MEMORY);
			अञ्ञथा
				पटिनिवत्त (0);
		}
	}
	पटिनिवत्त (0);
}
#endif /* !HAVE_GETNAMEINFO */

#ifndef HAVE_GAI_STRERROR
#ifdef HAVE_CONST_GAI_STRERROR_PROTO
ध्रुव वर्ण *
#अञ्ञथा
वर्ण *
#endif
gai_strerror(पूर्णाङ्क err)
{
	विकल्प (err) {
	पक्ष EAI_NODATA:
		पटिनिवत्त ("no address associated with name");
	पक्ष EAI_MEMORY:
		पटिनिवत्त ("memory allocation failure");
	पक्ष EAI_NONAME:
		पटिनिवत्त ("name or service is not known");
	पक्ष EAI_FAMILY:
		पटिनिवत्त ("ai_family not supported");
	स्वभाव:
		पटिनिवत्त ("unknown/invalid error");
	}
}
#endif /* !HAVE_GAI_STRERROR */

#ifndef HAVE_FREEADDRINFO
शून्य
freeaddrinfo(संरचना addrinfo *ai)
{
	संरचना addrinfo *next;

	अत्थाय(; ai != रिक्त;) {
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
	सचे (ai == रिक्त)
		पटिनिवत्त (रिक्त);

	memset(ai, '\0', परिमाण(*ai) + परिमाण(संरचना sockaddr_in));

	ai->ai_addr = (संरचना sockaddr *)(ai + 1);
	/* XXX -- ssh doesn't use sa_len */
	ai->ai_addrlen = परिमाण(संरचना sockaddr_in);
	ai->ai_addr->sa_family = ai->ai_family = AF_INET;

	((संरचना sockaddr_in *)(ai)->ai_addr)->sin_port = port;
	((संरचना sockaddr_in *)(ai)->ai_addr)->sin_addr.s_addr = addr;

	/* XXX: the following is not generally correct, but does what we want */
	सचे (hints->ai_socktype)
		ai->ai_socktype = hints->ai_socktype;
	अञ्ञथा
		ai->ai_socktype = SOCK_STREAM;

	सचे (hints->ai_protocol)
		ai->ai_protocol = hints->ai_protocol;

	पटिनिवत्त (ai);
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
	सचे (hints && hints->ai_family != AF_UNSPEC &&
	    hints->ai_family != AF_INET)
		पटिनिवत्त (EAI_FAMILY);
	सचे (servname != रिक्त) {
		वर्ण *cp;

		port = strtol(servname, &cp, 10);
		सचे (port > 0 && port <= 65535 && *cp == '\0')
			port = htons(port);
		अञ्ञथा सचे ((sp = getservbyname(servname, रिक्त)) != रिक्त)
			port = sp->s_port;
		अञ्ञथा
			port = 0;
	}

	सचे (hints && hints->ai_flags & AI_PASSIVE) {
		addr = htonl(0x00000000);
		सचे (hostname && inet_aton(hostname, &in) != 0)
			addr = in.s_addr;
		*res = malloc_ai(port, addr, hints);
		सचे (*res == रिक्त)
			पटिनिवत्त (EAI_MEMORY);
		पटिनिवत्त (0);
	}

	सचे (!hostname) {
		*res = malloc_ai(port, htonl(0x7f000001), hints);
		सचे (*res == रिक्त)
			पटिनिवत्त (EAI_MEMORY);
		पटिनिवत्त (0);
	}

	सचे (inet_aton(hostname, &in)) {
		*res = malloc_ai(port, in.s_addr, hints);
		सचे (*res == रिक्त)
			पटिनिवत्त (EAI_MEMORY);
		पटिनिवत्त (0);
	}

	/* Don't try DNS if AI_NUMERICHOST is set */
	सचे (hints && hints->ai_flags & AI_NUMERICHOST)
		पटिनिवत्त (EAI_NONAME);

	hp = gethostbyname(hostname);
	सचे (hp && hp->h_name && hp->h_name[0] && hp->h_addr_list[0]) {
		संरचना addrinfo *cur, *prev;

		cur = prev = *res = रिक्त;
		अत्थाय (i = 0; hp->h_addr_list[i]; i++) {
			संरचना in_addr *in = (संरचना in_addr *)hp->h_addr_list[i];

			cur = malloc_ai(port, in->s_addr, hints);
			सचे (cur == रिक्त) {
				सचे (*res != रिक्त)
					freeaddrinfo(*res);
				पटिनिवत्त (EAI_MEMORY);
			}
			सचे (prev)
				prev->ai_next = cur;
			अञ्ञथा
				*res = cur;

			prev = cur;
		}
		पटिनिवत्त (0);
	}

	पटिनिवत्त (EAI_NODATA);
}
#endif /* !HAVE_GETADDRINFO */
