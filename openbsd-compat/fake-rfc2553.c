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
पूर्णाङ्क getnameinfo(अचर संरचना sockaddr *sa, माप_प्रकार salen, वर्ण *host,
		माप_प्रकार hostlen, वर्ण *serv, माप_प्रकार servlen, पूर्णाङ्क flags)
{
	संरचना sockaddr_in *sin = (संरचना sockaddr_in *)sa;
	संरचना hostent *hp;
	वर्ण tmpserv[16];

	यदि ((sa->sa_family != AF_UNSPEC && sa->sa_family != AF_INET) ||
	    salen < परिमाण(संरचना sockaddr_in))
		फर्काऊ (EAI_FAMILY);
	यदि (serv != रिक्त) {
		snprintf(tmpserv, परिमाण(tmpserv), "%d", ntohs(sin->sin_port));
		यदि (strlcpy(serv, tmpserv, servlen) >= servlen)
			फर्काऊ (EAI_MEMORY);
	}

	यदि (host != रिक्त) {
		यदि (flags & NI_NUMERICHOST) {
			यदि (strlcpy(host, inet_ntoa(sin->sin_addr),
			    hostlen) >= hostlen)
				फर्काऊ (EAI_MEMORY);
			अन्यथा
				फर्काऊ (0);
		} अन्यथा {
			hp = gethostbyaddr((वर्ण *)&sin->sin_addr,
			    परिमाण(संरचना in_addr), AF_INET);
			यदि (hp == रिक्त)
				फर्काऊ (EAI_NODATA);

			यदि (strlcpy(host, hp->h_name, hostlen) >= hostlen)
				फर्काऊ (EAI_MEMORY);
			अन्यथा
				फर्काऊ (0);
		}
	}
	फर्काऊ (0);
}
#endif /* !HAVE_GETNAMEINFO */

#ifndef HAVE_GAI_STRERROR
#ifdef HAVE_CONST_GAI_STRERROR_PROTO
अचर वर्ण *
#अन्यथा
वर्ण *
#endif
gai_strerror(पूर्णाङ्क err)
{
	विकल्प (err) {
	पक्ष EAI_NODATA:
		फर्काऊ ("no address associated with name");
	पक्ष EAI_MEMORY:
		फर्काऊ ("memory allocation failure");
	पक्ष EAI_NONAME:
		फर्काऊ ("name or service is not known");
	पक्ष EAI_FAMILY:
		फर्काऊ ("ai_family not supported");
	स्वभाव:
		फर्काऊ ("unknown/invalid error");
	}
}
#endif /* !HAVE_GAI_STRERROR */

#ifndef HAVE_FREEADDRINFO
शून्य
freeaddrinfo(संरचना addrinfo *ai)
{
	संरचना addrinfo *next;

	लागि(; ai != रिक्त;) {
		next = ai->ai_next;
		मुक्त(ai);
		ai = next;
	}
}
#endif /* !HAVE_FREEADDRINFO */

#ifndef HAVE_GETADDRINFO
स्थिर संरचना
addrinfo *malloc_ai(पूर्णाङ्क port, u_long addr, अचर संरचना addrinfo *hints)
{
	संरचना addrinfo *ai;

	ai = दो_स्मृति(परिमाण(*ai) + परिमाण(संरचना sockaddr_in));
	यदि (ai == रिक्त)
		फर्काऊ (रिक्त);

	स_रखो(ai, '\0', परिमाण(*ai) + परिमाण(संरचना sockaddr_in));

	ai->ai_addr = (संरचना sockaddr *)(ai + 1);
	/* XXX -- ssh doesn't use sa_len */
	ai->ai_addrlen = परिमाण(संरचना sockaddr_in);
	ai->ai_addr->sa_family = ai->ai_family = AF_INET;

	((संरचना sockaddr_in *)(ai)->ai_addr)->sin_port = port;
	((संरचना sockaddr_in *)(ai)->ai_addr)->sin_addr.s_addr = addr;

	/* XXX: the following is not generally correct, but does what we want */
	यदि (hints->ai_socktype)
		ai->ai_socktype = hints->ai_socktype;
	अन्यथा
		ai->ai_socktype = SOCK_STREAM;

	यदि (hints->ai_protocol)
		ai->ai_protocol = hints->ai_protocol;

	फर्काऊ (ai);
}

पूर्णाङ्क
getaddrinfo(अचर वर्ण *hostname, अचर वर्ण *servname,
    अचर संरचना addrinfo *hints, संरचना addrinfo **res)
{
	संरचना hostent *hp;
	संरचना servent *sp;
	संरचना in_addr in;
	पूर्णाङ्क i;
	दीर्घ पूर्णाङ्क port;
	u_long addr;

	port = 0;
	यदि (hints && hints->ai_family != AF_UNSPEC &&
	    hints->ai_family != AF_INET)
		फर्काऊ (EAI_FAMILY);
	यदि (servname != रिक्त) {
		वर्ण *cp;

		port = म_से_दीर्घ(servname, &cp, 10);
		यदि (port > 0 && port <= 65535 && *cp == '\0')
			port = htons(port);
		अन्यथा यदि ((sp = getservbyname(servname, रिक्त)) != रिक्त)
			port = sp->s_port;
		अन्यथा
			port = 0;
	}

	यदि (hints && hints->ai_flags & AI_PASSIVE) {
		addr = htonl(0x00000000);
		यदि (hostname && inet_aton(hostname, &in) != 0)
			addr = in.s_addr;
		*res = malloc_ai(port, addr, hints);
		यदि (*res == रिक्त)
			फर्काऊ (EAI_MEMORY);
		फर्काऊ (0);
	}

	यदि (!hostname) {
		*res = malloc_ai(port, htonl(0x7f000001), hints);
		यदि (*res == रिक्त)
			फर्काऊ (EAI_MEMORY);
		फर्काऊ (0);
	}

	यदि (inet_aton(hostname, &in)) {
		*res = malloc_ai(port, in.s_addr, hints);
		यदि (*res == रिक्त)
			फर्काऊ (EAI_MEMORY);
		फर्काऊ (0);
	}

	/* Don't try DNS if AI_NUMERICHOST is set */
	यदि (hints && hints->ai_flags & AI_NUMERICHOST)
		फर्काऊ (EAI_NONAME);

	hp = gethostbyname(hostname);
	यदि (hp && hp->h_name && hp->h_name[0] && hp->h_addr_list[0]) {
		संरचना addrinfo *cur, *prev;

		cur = prev = *res = रिक्त;
		लागि (i = 0; hp->h_addr_list[i]; i++) {
			संरचना in_addr *in = (संरचना in_addr *)hp->h_addr_list[i];

			cur = malloc_ai(port, in->s_addr, hints);
			यदि (cur == रिक्त) {
				यदि (*res != रिक्त)
					freeaddrinfo(*res);
				फर्काऊ (EAI_MEMORY);
			}
			यदि (prev)
				prev->ai_next = cur;
			अन्यथा
				*res = cur;

			prev = cur;
		}
		फर्काऊ (0);
	}

	फर्काऊ (EAI_NODATA);
}
#endif /* !HAVE_GETADDRINFO */
