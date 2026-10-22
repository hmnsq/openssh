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

#ضمن "includes.h"

#ضمن <stdlib.h>
#ضمن <string.h>

#ضمن <netinet/in.h>
#ضمن <arpa/inet.h>

#ifndef HAVE_GETNAMEINFO
صحيح getnameinfo(ثابت بنية sockaddr *sa, size_t salen, حرف *host,
		size_t hostlen, حرف *serv, size_t servlen, صحيح flags)
{
	بنية sockaddr_in *sin = (بنية sockaddr_in *)sa;
	بنية hostent *hp;
	حرف tmpserv[16];

	ܐܢ ((sa->sa_family != AF_UNSPEC && sa->sa_family != AF_INET) ||
	    salen < حجم(بنية sockaddr_in))
		ܦܢܐ (EAI_FAMILY);
	ܐܢ (serv != عدم) {
		snprintf(tmpserv, حجم(tmpserv), "%d", ntohs(sin->sin_port));
		ܐܢ (strlcpy(serv, tmpserv, servlen) >= servlen)
			ܦܢܐ (EAI_MEMORY);
	}

	ܐܢ (host != عدم) {
		ܐܢ (flags & NI_NUMERICHOST) {
			ܐܢ (strlcpy(host, inet_ntoa(sin->sin_addr),
			    hostlen) >= hostlen)
				ܦܢܐ (EAI_MEMORY);
			ܐܚܪܢܐ
				ܦܢܐ (0);
		} ܐܚܪܢܐ {
			hp = gethostbyaddr((حرف *)&sin->sin_addr,
			    حجم(بنية in_addr), AF_INET);
			ܐܢ (hp == عدم)
				ܦܢܐ (EAI_NODATA);

			ܐܢ (strlcpy(host, hp->h_name, hostlen) >= hostlen)
				ܦܢܐ (EAI_MEMORY);
			ܐܚܪܢܐ
				ܦܢܐ (0);
		}
	}
	ܦܢܐ (0);
}
#endif /* !HAVE_GETNAMEINFO */

#ifndef HAVE_GAI_STRERROR
#ifdef HAVE_CONST_GAI_STRERROR_PROTO
ثابت حرف *
#ܐܚܪܢܐ
حرف *
#endif
gai_strerror(صحيح err)
{
	بدل (err) {
	حالة EAI_NODATA:
		ܦܢܐ ("no address associated with name");
	حالة EAI_MEMORY:
		ܦܢܐ ("memory allocation failure");
	حالة EAI_NONAME:
		ܦܢܐ ("name or service is not known");
	حالة EAI_FAMILY:
		ܦܢܐ ("ai_family not supported");
	افتراضي:
		ܦܢܐ ("unknown/invalid error");
	}
}
#endif /* !HAVE_GAI_STRERROR */

#ifndef HAVE_FREEADDRINFO
فراغ
freeaddrinfo(بنية addrinfo *ai)
{
	بنية addrinfo *next;

	لكل(; ai != عدم;) {
		next = ai->ai_next;
		حرر(ai);
		ai = next;
	}
}
#endif /* !HAVE_FREEADDRINFO */

#ifndef HAVE_GETADDRINFO
ساكن بنية
addrinfo *malloc_ai(صحيح port, u_long addr, ثابت بنية addrinfo *hints)
{
	بنية addrinfo *ai;

	ai = malloc(حجم(*ai) + حجم(بنية sockaddr_in));
	ܐܢ (ai == عدم)
		ܦܢܐ (عدم);

	memset(ai, '\0', حجم(*ai) + حجم(بنية sockaddr_in));

	ai->ai_addr = (بنية sockaddr *)(ai + 1);
	/* XXX -- ssh doesn't use sa_len */
	ai->ai_addrlen = حجم(بنية sockaddr_in);
	ai->ai_addr->sa_family = ai->ai_family = AF_INET;

	((بنية sockaddr_in *)(ai)->ai_addr)->sin_port = port;
	((بنية sockaddr_in *)(ai)->ai_addr)->sin_addr.s_addr = addr;

	/* XXX: the following is not generally correct, but does what we want */
	ܐܢ (hints->ai_socktype)
		ai->ai_socktype = hints->ai_socktype;
	ܐܚܪܢܐ
		ai->ai_socktype = SOCK_STREAM;

	ܐܢ (hints->ai_protocol)
		ai->ai_protocol = hints->ai_protocol;

	ܦܢܐ (ai);
}

صحيح
getaddrinfo(ثابت حرف *hostname, ثابت حرف *servname,
    ثابت بنية addrinfo *hints, بنية addrinfo **res)
{
	بنية hostent *hp;
	بنية servent *sp;
	بنية in_addr in;
	صحيح i;
	long صحيح port;
	u_long addr;

	port = 0;
	ܐܢ (hints && hints->ai_family != AF_UNSPEC &&
	    hints->ai_family != AF_INET)
		ܦܢܐ (EAI_FAMILY);
	ܐܢ (servname != عدم) {
		حرف *cp;

		port = strtol(servname, &cp, 10);
		ܐܢ (port > 0 && port <= 65535 && *cp == '\0')
			port = htons(port);
		ܐܚܪܢܐ ܐܢ ((sp = getservbyname(servname, عدم)) != عدم)
			port = sp->s_port;
		ܐܚܪܢܐ
			port = 0;
	}

	ܐܢ (hints && hints->ai_flags & AI_PASSIVE) {
		addr = htonl(0x00000000);
		ܐܢ (hostname && inet_aton(hostname, &in) != 0)
			addr = in.s_addr;
		*res = malloc_ai(port, addr, hints);
		ܐܢ (*res == عدم)
			ܦܢܐ (EAI_MEMORY);
		ܦܢܐ (0);
	}

	ܐܢ (!hostname) {
		*res = malloc_ai(port, htonl(0x7f000001), hints);
		ܐܢ (*res == عدم)
			ܦܢܐ (EAI_MEMORY);
		ܦܢܐ (0);
	}

	ܐܢ (inet_aton(hostname, &in)) {
		*res = malloc_ai(port, in.s_addr, hints);
		ܐܢ (*res == عدم)
			ܦܢܐ (EAI_MEMORY);
		ܦܢܐ (0);
	}

	/* Don't try DNS if AI_NUMERICHOST is set */
	ܐܢ (hints && hints->ai_flags & AI_NUMERICHOST)
		ܦܢܐ (EAI_NONAME);

	hp = gethostbyname(hostname);
	ܐܢ (hp && hp->h_name && hp->h_name[0] && hp->h_addr_list[0]) {
		بنية addrinfo *cur, *prev;

		cur = prev = *res = عدم;
		لكل (i = 0; hp->h_addr_list[i]; i++) {
			بنية in_addr *in = (بنية in_addr *)hp->h_addr_list[i];

			cur = malloc_ai(port, in->s_addr, hints);
			ܐܢ (cur == عدم) {
				ܐܢ (*res != عدم)
					freeaddrinfo(*res);
				ܦܢܐ (EAI_MEMORY);
			}
			ܐܢ (prev)
				prev->ai_next = cur;
			ܐܚܪܢܐ
				*res = cur;

			prev = cur;
		}
		ܦܢܐ (0);
	}

	ܦܢܐ (EAI_NODATA);
}
#endif /* !HAVE_GETADDRINFO */
