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
পূর্ণাঙ্ক getnameinfo(ধ্রুব সংরচনা sockaddr *sa, size_t salen, বর্ণ *host,
		size_t hostlen, বর্ণ *serv, size_t servlen, পূর্ণাঙ্ক flags)
{
	সংরচনা sockaddr_in *sin = (সংরচনা sockaddr_in *)sa;
	সংরচনা hostent *hp;
	বর্ণ tmpserv[16];

	যদি ((sa->sa_family != AF_UNSPEC && sa->sa_family != AF_INET) ||
	    salen < পরিমাণ(সংরচনা sockaddr_in))
		প্রত্যাগম (EAI_FAMILY);
	যদি (serv != রিক্ত) {
		snprintf(tmpserv, পরিমাণ(tmpserv), "%d", ntohs(sin->sin_port));
		যদি (strlcpy(serv, tmpserv, servlen) >= servlen)
			প্রত্যাগম (EAI_MEMORY);
	}

	যদি (host != রিক্ত) {
		যদি (flags & NI_NUMERICHOST) {
			যদি (strlcpy(host, inet_ntoa(sin->sin_addr),
			    hostlen) >= hostlen)
				প্রত্যাগম (EAI_MEMORY);
			অন্যথা
				প্রত্যাগম (0);
		} অন্যথা {
			hp = gethostbyaddr((বর্ণ *)&sin->sin_addr,
			    পরিমাণ(সংরচনা in_addr), AF_INET);
			যদি (hp == রিক্ত)
				প্রত্যাগম (EAI_NODATA);

			যদি (strlcpy(host, hp->h_name, hostlen) >= hostlen)
				প্রত্যাগম (EAI_MEMORY);
			অন্যথা
				প্রত্যাগম (0);
		}
	}
	প্রত্যাগম (0);
}
#endif /* !HAVE_GETNAMEINFO */

#ifndef HAVE_GAI_STRERROR
#ifdef HAVE_CONST_GAI_STRERROR_PROTO
ধ্রুব বর্ণ *
#অন্যথা
বর্ণ *
#endif
gai_strerror(পূর্ণাঙ্ক err)
{
	বিকল্প (err) {
	পক্ষ EAI_NODATA:
		প্রত্যাগম ("no address associated with name");
	পক্ষ EAI_MEMORY:
		প্রত্যাগম ("memory allocation failure");
	পক্ষ EAI_NONAME:
		প্রত্যাগম ("name or service is not known");
	পক্ষ EAI_FAMILY:
		প্রত্যাগম ("ai_family not supported");
	স্বভাব:
		প্রত্যাগম ("unknown/invalid error");
	}
}
#endif /* !HAVE_GAI_STRERROR */

#ifndef HAVE_FREEADDRINFO
শূন্য
freeaddrinfo(সংরচনা addrinfo *ai)
{
	সংরচনা addrinfo *next;

	প্রতি(; ai != রিক্ত;) {
		next = ai->ai_next;
		মুক্ত(ai);
		ai = next;
	}
}
#endif /* !HAVE_FREEADDRINFO */

#ifndef HAVE_GETADDRINFO
স্থির সংরচনা
addrinfo *malloc_ai(পূর্ণাঙ্ক port, u_long addr, ধ্রুব সংরচনা addrinfo *hints)
{
	সংরচনা addrinfo *ai;

	ai = malloc(পরিমাণ(*ai) + পরিমাণ(সংরচনা sockaddr_in));
	যদি (ai == রিক্ত)
		প্রত্যাগম (রিক্ত);

	memset(ai, '\0', পরিমাণ(*ai) + পরিমাণ(সংরচনা sockaddr_in));

	ai->ai_addr = (সংরচনা sockaddr *)(ai + 1);
	/* XXX -- ssh doesn't use sa_len */
	ai->ai_addrlen = পরিমাণ(সংরচনা sockaddr_in);
	ai->ai_addr->sa_family = ai->ai_family = AF_INET;

	((সংরচনা sockaddr_in *)(ai)->ai_addr)->sin_port = port;
	((সংরচনা sockaddr_in *)(ai)->ai_addr)->sin_addr.s_addr = addr;

	/* XXX: the following is not generally correct, but does what we want */
	যদি (hints->ai_socktype)
		ai->ai_socktype = hints->ai_socktype;
	অন্যথা
		ai->ai_socktype = SOCK_STREAM;

	যদি (hints->ai_protocol)
		ai->ai_protocol = hints->ai_protocol;

	প্রত্যাগম (ai);
}

পূর্ণাঙ্ক
getaddrinfo(ধ্রুব বর্ণ *hostname, ধ্রুব বর্ণ *servname,
    ধ্রুব সংরচনা addrinfo *hints, সংরচনা addrinfo **res)
{
	সংরচনা hostent *hp;
	সংরচনা servent *sp;
	সংরচনা in_addr in;
	পূর্ণাঙ্ক i;
	long পূর্ণাঙ্ক port;
	u_long addr;

	port = 0;
	যদি (hints && hints->ai_family != AF_UNSPEC &&
	    hints->ai_family != AF_INET)
		প্রত্যাগম (EAI_FAMILY);
	যদি (servname != রিক্ত) {
		বর্ণ *cp;

		port = strtol(servname, &cp, 10);
		যদি (port > 0 && port <= 65535 && *cp == '\0')
			port = htons(port);
		অন্যথা যদি ((sp = getservbyname(servname, রিক্ত)) != রিক্ত)
			port = sp->s_port;
		অন্যথা
			port = 0;
	}

	যদি (hints && hints->ai_flags & AI_PASSIVE) {
		addr = htonl(0x00000000);
		যদি (hostname && inet_aton(hostname, &in) != 0)
			addr = in.s_addr;
		*res = malloc_ai(port, addr, hints);
		যদি (*res == রিক্ত)
			প্রত্যাগম (EAI_MEMORY);
		প্রত্যাগম (0);
	}

	যদি (!hostname) {
		*res = malloc_ai(port, htonl(0x7f000001), hints);
		যদি (*res == রিক্ত)
			প্রত্যাগম (EAI_MEMORY);
		প্রত্যাগম (0);
	}

	যদি (inet_aton(hostname, &in)) {
		*res = malloc_ai(port, in.s_addr, hints);
		যদি (*res == রিক্ত)
			প্রত্যাগম (EAI_MEMORY);
		প্রত্যাগম (0);
	}

	/* Don't try DNS if AI_NUMERICHOST is set */
	যদি (hints && hints->ai_flags & AI_NUMERICHOST)
		প্রত্যাগম (EAI_NONAME);

	hp = gethostbyname(hostname);
	যদি (hp && hp->h_name && hp->h_name[0] && hp->h_addr_list[0]) {
		সংরচনা addrinfo *cur, *prev;

		cur = prev = *res = রিক্ত;
		প্রতি (i = 0; hp->h_addr_list[i]; i++) {
			সংরচনা in_addr *in = (সংরচনা in_addr *)hp->h_addr_list[i];

			cur = malloc_ai(port, in->s_addr, hints);
			যদি (cur == রিক্ত) {
				যদি (*res != রিক্ত)
					freeaddrinfo(*res);
				প্রত্যাগম (EAI_MEMORY);
			}
			যদি (prev)
				prev->ai_next = cur;
			অন্যথা
				*res = cur;

			prev = cur;
		}
		প্রত্যাগম (0);
	}

	প্রত্যাগম (EAI_NODATA);
}
#endif /* !HAVE_GETADDRINFO */
