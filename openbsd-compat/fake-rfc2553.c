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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>

#অন্তর্ভাব <netinet/in.h>
#অন্তর্ভাব <arpa/inet.h>

#ifndef HAVE_GETNAMEINFO
পূর্ণসংখ্যা getnameinfo(ধ্রুবক কাঠামো sockaddr *sa, আকার_t salen, অক্ষর *host,
		আকার_t hostlen, অক্ষর *serv, আকার_t servlen, পূর্ণসংখ্যা flags)
{
	কাঠামো sockaddr_in *sin = (কাঠামো sockaddr_in *)sa;
	কাঠামো hostent *hp;
	অক্ষর tmpserv[16];

	যদি ((sa->sa_family != AF_UNSPEC && sa->sa_family != AF_INET) ||
	    salen < আকার(কাঠামো sockaddr_in))
		ফেরত (EAI_FAMILY);
	যদি (serv != ফাঁকা) {
		snprintf(tmpserv, আকার(tmpserv), "%d", ntohs(sin->sin_port));
		যদি (strlcpy(serv, tmpserv, servlen) >= servlen)
			ফেরত (EAI_MEMORY);
	}

	যদি (host != ফাঁকা) {
		যদি (flags & NI_NUMERICHOST) {
			যদি (strlcpy(host, inet_ntoa(sin->sin_addr),
			    hostlen) >= hostlen)
				ফেরত (EAI_MEMORY);
			অন্যথা
				ফেরত (0);
		} অন্যথা {
			hp = gethostbyaddr((অক্ষর *)&sin->sin_addr,
			    আকার(কাঠামো in_addr), AF_INET);
			যদি (hp == ফাঁকা)
				ফেরত (EAI_NODATA);

			যদি (strlcpy(host, hp->h_name, hostlen) >= hostlen)
				ফেরত (EAI_MEMORY);
			অন্যথা
				ফেরত (0);
		}
	}
	ফেরত (0);
}
#endif /* !HAVE_GETNAMEINFO */

#ifndef HAVE_GAI_STRERROR
#ifdef HAVE_CONST_GAI_STRERROR_PROTO
ধ্রুবক অক্ষর *
#অন্যথা
অক্ষর *
#endif
gai_strerror(পূর্ণসংখ্যা err)
{
	নির্বাচন (err) {
	ক্ষেত্র EAI_NODATA:
		ফেরত ("no address associated with name");
	ক্ষেত্র EAI_MEMORY:
		ফেরত ("memory allocation failure");
	ক্ষেত্র EAI_NONAME:
		ফেরত ("name or service is not known");
	ক্ষেত্র EAI_FAMILY:
		ফেরত ("ai_family not supported");
	পূর্বনির্ধারিত:
		ফেরত ("unknown/invalid error");
	}
}
#endif /* !HAVE_GAI_STRERROR */

#ifndef HAVE_FREEADDRINFO
শূন্য
freeaddrinfo(কাঠামো addrinfo *ai)
{
	কাঠামো addrinfo *পরবর্তী;

	জন্য(; ai != ফাঁকা;) {
		পরবর্তী = ai->ai_next;
		মুক্ত(ai);
		ai = পরবর্তী;
	}
}
#endif /* !HAVE_FREEADDRINFO */

#ifndef HAVE_GETADDRINFO
স্থির কাঠামো
addrinfo *malloc_ai(পূর্ণসংখ্যা port, u_long addr, ধ্রুবক কাঠামো addrinfo *hints)
{
	কাঠামো addrinfo *ai;

	ai = malloc(আকার(*ai) + আকার(কাঠামো sockaddr_in));
	যদি (ai == ফাঁকা)
		ফেরত (ফাঁকা);

	memset(ai, '\0', আকার(*ai) + আকার(কাঠামো sockaddr_in));

	ai->ai_addr = (কাঠামো sockaddr *)(ai + 1);
	/* XXX -- ssh doesn't use sa_len */
	ai->ai_addrlen = আকার(কাঠামো sockaddr_in);
	ai->ai_addr->sa_family = ai->ai_family = AF_INET;

	((কাঠামো sockaddr_in *)(ai)->ai_addr)->sin_port = port;
	((কাঠামো sockaddr_in *)(ai)->ai_addr)->sin_addr.s_addr = addr;

	/* XXX: the following is not generally correct, but does what we want */
	যদি (hints->ai_socktype)
		ai->ai_socktype = hints->ai_socktype;
	অন্যথা
		ai->ai_socktype = SOCK_STREAM;

	যদি (hints->ai_protocol)
		ai->ai_protocol = hints->ai_protocol;

	ফেরত (ai);
}

পূর্ণসংখ্যা
getaddrinfo(ধ্রুবক অক্ষর *hostname, ধ্রুবক অক্ষর *servname,
    ধ্রুবক কাঠামো addrinfo *hints, কাঠামো addrinfo **res)
{
	কাঠামো hostent *hp;
	কাঠামো servent *sp;
	কাঠামো in_addr in;
	পূর্ণসংখ্যা i;
	long পূর্ণসংখ্যা port;
	u_long addr;

	port = 0;
	যদি (hints && hints->ai_family != AF_UNSPEC &&
	    hints->ai_family != AF_INET)
		ফেরত (EAI_FAMILY);
	যদি (servname != ফাঁকা) {
		অক্ষর *cp;

		port = strtol(servname, &cp, 10);
		যদি (port > 0 && port <= 65535 && *cp == '\0')
			port = htons(port);
		অন্যথা যদি ((sp = getservbyname(servname, ফাঁকা)) != ফাঁকা)
			port = sp->s_port;
		অন্যথা
			port = 0;
	}

	যদি (hints && hints->ai_flags & AI_PASSIVE) {
		addr = htonl(0x00000000);
		যদি (hostname && inet_aton(hostname, &in) != 0)
			addr = in.s_addr;
		*res = malloc_ai(port, addr, hints);
		যদি (*res == ফাঁকা)
			ফেরত (EAI_MEMORY);
		ফেরত (0);
	}

	যদি (!hostname) {
		*res = malloc_ai(port, htonl(0x7f000001), hints);
		যদি (*res == ফাঁকা)
			ফেরত (EAI_MEMORY);
		ফেরত (0);
	}

	যদি (inet_aton(hostname, &in)) {
		*res = malloc_ai(port, in.s_addr, hints);
		যদি (*res == ফাঁকা)
			ফেরত (EAI_MEMORY);
		ফেরত (0);
	}

	/* Don't try DNS if AI_NUMERICHOST is set */
	যদি (hints && hints->ai_flags & AI_NUMERICHOST)
		ফেরত (EAI_NONAME);

	hp = gethostbyname(hostname);
	যদি (hp && hp->h_name && hp->h_name[0] && hp->h_addr_list[0]) {
		কাঠামো addrinfo *cur, *পূর্ব;

		cur = পূর্ব = *res = ফাঁকা;
		জন্য (i = 0; hp->h_addr_list[i]; i++) {
			কাঠামো in_addr *in = (কাঠামো in_addr *)hp->h_addr_list[i];

			cur = malloc_ai(port, in->s_addr, hints);
			যদি (cur == ফাঁকা) {
				যদি (*res != ফাঁকা)
					freeaddrinfo(*res);
				ফেরত (EAI_MEMORY);
			}
			যদি (পূর্ব)
				পূর্ব->ai_next = cur;
			অন্যথা
				*res = cur;

			পূর্ব = cur;
		}
		ফেরত (0);
	}

	ফেরত (EAI_NODATA);
}
#endif /* !HAVE_GETADDRINFO */
