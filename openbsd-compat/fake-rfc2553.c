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
पूर्णांक getnameinfo(स्थिरांक संरचना sockaddr *sa, माप_प्रकार salen, अक्षर *host,
		माप_प्रकार hostlen, अक्षर *serv, माप_प्रकार servlen, पूर्णांक flags)
{
	संरचना sockaddr_in *sin = (संरचना sockaddr_in *)sa;
	संरचना hostent *hp;
	अक्षर tmpserv[16];

	जर ((sa->sa_family != AF_UNSPEC && sa->sa_family != AF_INET) ||
	    salen < आकार(संरचना sockaddr_in))
		परत (EAI_FAMILY);
	जर (serv != रिक्त) {
		snprintf(tmpserv, आकार(tmpserv), "%d", ntohs(sin->sin_port));
		जर (strlcpy(serv, tmpserv, servlen) >= servlen)
			परत (EAI_MEMORY);
	}

	जर (host != रिक्त) {
		जर (flags & NI_NUMERICHOST) {
			जर (strlcpy(host, inet_ntoa(sin->sin_addr),
			    hostlen) >= hostlen)
				परत (EAI_MEMORY);
			अन्यथा
				परत (0);
		} अन्यथा {
			hp = gethostbyaddr((अक्षर *)&sin->sin_addr,
			    आकार(संरचना in_addr), AF_INET);
			जर (hp == रिक्त)
				परत (EAI_NODATA);

			जर (strlcpy(host, hp->h_name, hostlen) >= hostlen)
				परत (EAI_MEMORY);
			अन्यथा
				परत (0);
		}
	}
	परत (0);
}
#endif /* !HAVE_GETNAMEINFO */

#ifndef HAVE_GAI_STRERROR
#ifdef HAVE_CONST_GAI_STRERROR_PROTO
स्थिरांक अक्षर *
#अन्यथा
अक्षर *
#endif
gai_strerror(पूर्णांक err)
{
	निवड (err) {
	स्थिती EAI_NODATA:
		परत ("no address associated with name");
	स्थिती EAI_MEMORY:
		परत ("memory allocation failure");
	स्थिती EAI_NONAME:
		परत ("name or service is not known");
	स्थिती EAI_FAMILY:
		परत ("ai_family not supported");
	पूर्वनिर्धारित:
		परत ("unknown/invalid error");
	}
}
#endif /* !HAVE_GAI_STRERROR */

#ifndef HAVE_FREEADDRINFO
शून्य
freeaddrinfo(संरचना addrinfo *ai)
{
	संरचना addrinfo *next;

	साठी(; ai != रिक्त;) {
		next = ai->ai_next;
		मुक्त(ai);
		ai = next;
	}
}
#endif /* !HAVE_FREEADDRINFO */

#ifndef HAVE_GETADDRINFO
स्थिर संरचना
addrinfo *malloc_ai(पूर्णांक port, u_long addr, स्थिरांक संरचना addrinfo *hints)
{
	संरचना addrinfo *ai;

	ai = दो_स्मृति(आकार(*ai) + आकार(संरचना sockaddr_in));
	जर (ai == रिक्त)
		परत (रिक्त);

	स_रखो(ai, '\0', आकार(*ai) + आकार(संरचना sockaddr_in));

	ai->ai_addr = (संरचना sockaddr *)(ai + 1);
	/* XXX -- ssh doesn't use sa_len */
	ai->ai_addrlen = आकार(संरचना sockaddr_in);
	ai->ai_addr->sa_family = ai->ai_family = AF_INET;

	((संरचना sockaddr_in *)(ai)->ai_addr)->sin_port = port;
	((संरचना sockaddr_in *)(ai)->ai_addr)->sin_addr.s_addr = addr;

	/* XXX: the following is not generally correct, but does what we want */
	जर (hints->ai_socktype)
		ai->ai_socktype = hints->ai_socktype;
	अन्यथा
		ai->ai_socktype = SOCK_STREAM;

	जर (hints->ai_protocol)
		ai->ai_protocol = hints->ai_protocol;

	परत (ai);
}

पूर्णांक
getaddrinfo(स्थिरांक अक्षर *hostname, स्थिरांक अक्षर *servname,
    स्थिरांक संरचना addrinfo *hints, संरचना addrinfo **res)
{
	संरचना hostent *hp;
	संरचना servent *sp;
	संरचना in_addr in;
	पूर्णांक i;
	दीर्घ पूर्णांक port;
	u_long addr;

	port = 0;
	जर (hints && hints->ai_family != AF_UNSPEC &&
	    hints->ai_family != AF_INET)
		परत (EAI_FAMILY);
	जर (servname != रिक्त) {
		अक्षर *cp;

		port = म_से_दीर्घ(servname, &cp, 10);
		जर (port > 0 && port <= 65535 && *cp == '\0')
			port = htons(port);
		अन्यथा जर ((sp = getservbyname(servname, रिक्त)) != रिक्त)
			port = sp->s_port;
		अन्यथा
			port = 0;
	}

	जर (hints && hints->ai_flags & AI_PASSIVE) {
		addr = htonl(0x00000000);
		जर (hostname && inet_aton(hostname, &in) != 0)
			addr = in.s_addr;
		*res = malloc_ai(port, addr, hints);
		जर (*res == रिक्त)
			परत (EAI_MEMORY);
		परत (0);
	}

	जर (!hostname) {
		*res = malloc_ai(port, htonl(0x7f000001), hints);
		जर (*res == रिक्त)
			परत (EAI_MEMORY);
		परत (0);
	}

	जर (inet_aton(hostname, &in)) {
		*res = malloc_ai(port, in.s_addr, hints);
		जर (*res == रिक्त)
			परत (EAI_MEMORY);
		परत (0);
	}

	/* Don't try DNS if AI_NUMERICHOST is set */
	जर (hints && hints->ai_flags & AI_NUMERICHOST)
		परत (EAI_NONAME);

	hp = gethostbyname(hostname);
	जर (hp && hp->h_name && hp->h_name[0] && hp->h_addr_list[0]) {
		संरचना addrinfo *cur, *prev;

		cur = prev = *res = रिक्त;
		साठी (i = 0; hp->h_addr_list[i]; i++) {
			संरचना in_addr *in = (संरचना in_addr *)hp->h_addr_list[i];

			cur = malloc_ai(port, in->s_addr, hints);
			जर (cur == रिक्त) {
				जर (*res != रिक्त)
					freeaddrinfo(*res);
				परत (EAI_MEMORY);
			}
			जर (prev)
				prev->ai_next = cur;
			अन्यथा
				*res = cur;

			prev = cur;
		}
		परत (0);
	}

	परत (EAI_NODATA);
}
#endif /* !HAVE_GETADDRINFO */
