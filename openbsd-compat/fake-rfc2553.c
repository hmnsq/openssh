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

#यदि_अपरिभाषितम् HAVE_GETNAMEINFO
पूर्णाङ्क getnameinfo(ध्रुव संरचना sockaddr *sa, आकार_t salen, वर्ण *host,
		आकार_t hostlen, वर्ण *serv, आकार_t servlen, पूर्णाङ्क flags)
{
	संरचना sockaddr_in *ज्या = (संरचना sockaddr_in *)sa;
	संरचना hostent *hp;
	वर्ण tmpserv[16];

	यदि ((sa->sa_family != AF_UNSPEC && sa->sa_family != AF_INET) ||
	    salen < परिमाण(संरचना sockaddr_in))
		प्रत्यागम (EAI_FAMILY);
	यदि (serv != रिक्त) {
		snprintf(tmpserv, परिमाण(tmpserv), "%d", ntohs(ज्या->sin_port));
		यदि (strlcpy(serv, tmpserv, servlen) >= servlen)
			प्रत्यागम (EAI_MEMORY);
	}

	यदि (host != रिक्त) {
		यदि (flags & NI_NUMERICHOST) {
			यदि (strlcpy(host, inet_ntoa(ज्या->sin_addr),
			    hostlen) >= hostlen)
				प्रत्यागम (EAI_MEMORY);
			अन्यथा
				प्रत्यागम (0);
		} अन्यथा {
			hp = gethostbyaddr((वर्ण *)&ज्या->sin_addr,
			    परिमाण(संरचना in_addr), AF_INET);
			यदि (hp == रिक्त)
				प्रत्यागम (EAI_NODATA);

			यदि (strlcpy(host, hp->h_name, hostlen) >= hostlen)
				प्रत्यागम (EAI_MEMORY);
			अन्यथा
				प्रत्यागम (0);
		}
	}
	प्रत्यागम (0);
}
#यदि_अन्तः /* !HAVE_GETNAMEINFO */

#यदि_अपरिभाषितम् HAVE_GAI_STRERROR
#यदि_परिभाषितम् HAVE_CONST_GAI_STRERROR_PROTO
ध्रुव वर्ण *
#अन्यथा
वर्ण *
#यदि_अन्तः
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
#यदि_अन्तः /* !HAVE_GAI_STRERROR */

#यदि_अपरिभाषितम् HAVE_FREEADDRINFO
शून्य
freeaddrinfo(संरचना addrinfo *ai)
{
	संरचना addrinfo *अग्र;

	प्रति(; ai != रिक्त;) {
		अग्र = ai->ai_next;
		मुक्त(ai);
		ai = अग्र;
	}
}
#यदि_अन्तः /* !HAVE_FREEADDRINFO */

#यदि_अपरिभाषितम् HAVE_GETADDRINFO
स्थिर संरचना
addrinfo *malloc_ai(पूर्णाङ्क पत्तनम्, u_long addr, ध्रुव संरचना addrinfo *hints)
{
	संरचना addrinfo *ai;

	ai = स्मृतिं_देहि(परिमाण(*ai) + परिमाण(संरचना sockaddr_in));
	यदि (ai == रिक्त)
		प्रत्यागम (रिक्त);

	स्मृतिं_पूरय(ai, '\0', परिमाण(*ai) + परिमाण(संरचना sockaddr_in));

	ai->ai_addr = (संरचना sockaddr *)(ai + 1);
	/* XXX -- ssh doesn't use sa_len */
	ai->ai_addrlen = परिमाण(संरचना sockaddr_in);
	ai->ai_addr->sa_family = ai->ai_family = AF_INET;

	((संरचना sockaddr_in *)(ai)->ai_addr)->sin_port = पत्तनम्;
	((संरचना sockaddr_in *)(ai)->ai_addr)->sin_addr.s_addr = addr;

	/* XXX: the following is not generally correct, but does what we want */
	यदि (hints->ai_socktype)
		ai->ai_socktype = hints->ai_socktype;
	अन्यथा
		ai->ai_socktype = SOCK_STREAM;

	यदि (hints->ai_protocol)
		ai->ai_protocol = hints->ai_protocol;

	प्रत्यागम (ai);
}

पूर्णाङ्क
getaddrinfo(ध्रुव वर्ण *hostname, ध्रुव वर्ण *servname,
    ध्रुव संरचना addrinfo *hints, संरचना addrinfo **res)
{
	संरचना hostent *hp;
	संरचना servent *sp;
	संरचना in_addr अन्तर्;
	पूर्णाङ्क i;
	दीर्घ पूर्णाङ्क पत्तनम्;
	u_long addr;

	पत्तनम् = 0;
	यदि (hints && hints->ai_family != AF_UNSPEC &&
	    hints->ai_family != AF_INET)
		प्रत्यागम (EAI_FAMILY);
	यदि (servname != रिक्त) {
		वर्ण *cp;

		पत्तनम् = strtol(servname, &cp, 10);
		यदि (पत्तनम् > 0 && पत्तनम् <= 65535 && *cp == '\0')
			पत्तनम् = htons(पत्तनम्);
		अन्यथा यदि ((sp = getservbyname(servname, रिक्त)) != रिक्त)
			पत्तनम् = sp->s_port;
		अन्यथा
			पत्तनम् = 0;
	}

	यदि (hints && hints->ai_flags & AI_PASSIVE) {
		addr = htonl(0x00000000);
		यदि (hostname && inet_aton(hostname, &अन्तर्) != 0)
			addr = अन्तर्.s_addr;
		*res = malloc_ai(पत्तनम्, addr, hints);
		यदि (*res == रिक्त)
			प्रत्यागम (EAI_MEMORY);
		प्रत्यागम (0);
	}

	यदि (!hostname) {
		*res = malloc_ai(पत्तनम्, htonl(0x7f000001), hints);
		यदि (*res == रिक्त)
			प्रत्यागम (EAI_MEMORY);
		प्रत्यागम (0);
	}

	यदि (inet_aton(hostname, &अन्तर्)) {
		*res = malloc_ai(पत्तनम्, अन्तर्.s_addr, hints);
		यदि (*res == रिक्त)
			प्रत्यागम (EAI_MEMORY);
		प्रत्यागम (0);
	}

	/* Don't try DNS if AI_NUMERICHOST is set */
	यदि (hints && hints->ai_flags & AI_NUMERICHOST)
		प्रत्यागम (EAI_NONAME);

	hp = gethostbyname(hostname);
	यदि (hp && hp->h_name && hp->h_name[0] && hp->h_addr_list[0]) {
		संरचना addrinfo *cur, *पूर्व;

		cur = पूर्व = *res = रिक्त;
		प्रति (i = 0; hp->h_addr_list[i]; i++) {
			संरचना in_addr *अन्तर् = (संरचना in_addr *)hp->h_addr_list[i];

			cur = malloc_ai(पत्तनम्, अन्तर्->s_addr, hints);
			यदि (cur == रिक्त) {
				यदि (*res != रिक्त)
					freeaddrinfo(*res);
				प्रत्यागम (EAI_MEMORY);
			}
			यदि (पूर्व)
				पूर्व->ai_next = cur;
			अन्यथा
				*res = cur;

			पूर्व = cur;
		}
		प्रत्यागम (0);
	}

	प्रत्यागम (EAI_NODATA);
}
#यदि_अन्तः /* !HAVE_GETADDRINFO */
