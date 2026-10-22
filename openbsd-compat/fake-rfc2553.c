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

#شامل "includes.h"

#شامل <stdlib.h>
#شامل <string.h>

#شامل <netinet/in.h>
#شامل <arpa/inet.h>

#ifndef HAVE_GETNAMEINFO
صحیح getnameinfo(ثابت ساختار sockaddr *sa, size_t salen, نویسه *host,
		size_t hostlen, نویسه *serv, size_t servlen, صحیح flags)
{
	ساختار sockaddr_in *sin = (ساختار sockaddr_in *)sa;
	ساختار hostent *hp;
	نویسه tmpserv[16];

	اگر ((sa->sa_family != AF_UNSPEC && sa->sa_family != AF_INET) ||
	    salen < اندازه(ساختار sockaddr_in))
		بازگشت (EAI_FAMILY);
	اگر (serv != پوچ) {
		snprintf(tmpserv, اندازه(tmpserv), "%d", ntohs(sin->sin_port));
		اگر (strlcpy(serv, tmpserv, servlen) >= servlen)
			بازگشت (EAI_MEMORY);
	}

	اگر (host != پوچ) {
		اگر (flags & NI_NUMERICHOST) {
			اگر (strlcpy(host, inet_ntoa(sin->sin_addr),
			    hostlen) >= hostlen)
				بازگشت (EAI_MEMORY);
			وگرنه
				بازگشت (0);
		} وگرنه {
			hp = gethostbyaddr((نویسه *)&sin->sin_addr,
			    اندازه(ساختار in_addr), AF_INET);
			اگر (hp == پوچ)
				بازگشت (EAI_NODATA);

			اگر (strlcpy(host, hp->h_name, hostlen) >= hostlen)
				بازگشت (EAI_MEMORY);
			وگرنه
				بازگشت (0);
		}
	}
	بازگشت (0);
}
#endif /* !HAVE_GETNAMEINFO */

#ifndef HAVE_GAI_STRERROR
#ifdef HAVE_CONST_GAI_STRERROR_PROTO
ثابت نویسه *
#وگرنه
نویسه *
#endif
gai_strerror(صحیح err)
{
	انتخاب (err) {
	حالت EAI_NODATA:
		بازگشت ("no address associated with name");
	حالت EAI_MEMORY:
		بازگشت ("memory allocation failure");
	حالت EAI_NONAME:
		بازگشت ("name or service is not known");
	حالت EAI_FAMILY:
		بازگشت ("ai_family not supported");
	پیشفرض:
		بازگشت ("unknown/invalid error");
	}
}
#endif /* !HAVE_GAI_STRERROR */

#ifndef HAVE_FREEADDRINFO
تهی
freeaddrinfo(ساختار addrinfo *ai)
{
	ساختار addrinfo *next;

	برای(; ai != پوچ;) {
		next = ai->ai_next;
		آزاد(ai);
		ai = next;
	}
}
#endif /* !HAVE_FREEADDRINFO */

#ifndef HAVE_GETADDRINFO
ایستا ساختار
addrinfo *malloc_ai(صحیح port, u_long addr, ثابت ساختار addrinfo *hints)
{
	ساختار addrinfo *ai;

	ai = malloc(اندازه(*ai) + اندازه(ساختار sockaddr_in));
	اگر (ai == پوچ)
		بازگشت (پوچ);

	memset(ai, '\0', اندازه(*ai) + اندازه(ساختار sockaddr_in));

	ai->ai_addr = (ساختار sockaddr *)(ai + 1);
	/* XXX -- ssh doesn't use sa_len */
	ai->ai_addrlen = اندازه(ساختار sockaddr_in);
	ai->ai_addr->sa_family = ai->ai_family = AF_INET;

	((ساختار sockaddr_in *)(ai)->ai_addr)->sin_port = port;
	((ساختار sockaddr_in *)(ai)->ai_addr)->sin_addr.s_addr = addr;

	/* XXX: the following is not generally correct, but does what we want */
	اگر (hints->ai_socktype)
		ai->ai_socktype = hints->ai_socktype;
	وگرنه
		ai->ai_socktype = SOCK_STREAM;

	اگر (hints->ai_protocol)
		ai->ai_protocol = hints->ai_protocol;

	بازگشت (ai);
}

صحیح
getaddrinfo(ثابت نویسه *hostname, ثابت نویسه *servname,
    ثابت ساختار addrinfo *hints, ساختار addrinfo **res)
{
	ساختار hostent *hp;
	ساختار servent *sp;
	ساختار in_addr in;
	صحیح i;
	long صحیح port;
	u_long addr;

	port = 0;
	اگر (hints && hints->ai_family != AF_UNSPEC &&
	    hints->ai_family != AF_INET)
		بازگشت (EAI_FAMILY);
	اگر (servname != پوچ) {
		نویسه *cp;

		port = strtol(servname, &cp, 10);
		اگر (port > 0 && port <= 65535 && *cp == '\0')
			port = htons(port);
		وگرنه اگر ((sp = getservbyname(servname, پوچ)) != پوچ)
			port = sp->s_port;
		وگرنه
			port = 0;
	}

	اگر (hints && hints->ai_flags & AI_PASSIVE) {
		addr = htonl(0x00000000);
		اگر (hostname && inet_aton(hostname, &in) != 0)
			addr = in.s_addr;
		*res = malloc_ai(port, addr, hints);
		اگر (*res == پوچ)
			بازگشت (EAI_MEMORY);
		بازگشت (0);
	}

	اگر (!hostname) {
		*res = malloc_ai(port, htonl(0x7f000001), hints);
		اگر (*res == پوچ)
			بازگشت (EAI_MEMORY);
		بازگشت (0);
	}

	اگر (inet_aton(hostname, &in)) {
		*res = malloc_ai(port, in.s_addr, hints);
		اگر (*res == پوچ)
			بازگشت (EAI_MEMORY);
		بازگشت (0);
	}

	/* Don't try DNS if AI_NUMERICHOST is set */
	اگر (hints && hints->ai_flags & AI_NUMERICHOST)
		بازگشت (EAI_NONAME);

	hp = gethostbyname(hostname);
	اگر (hp && hp->h_name && hp->h_name[0] && hp->h_addr_list[0]) {
		ساختار addrinfo *cur, *prev;

		cur = prev = *res = پوچ;
		برای (i = 0; hp->h_addr_list[i]; i++) {
			ساختار in_addr *in = (ساختار in_addr *)hp->h_addr_list[i];

			cur = malloc_ai(port, in->s_addr, hints);
			اگر (cur == پوچ) {
				اگر (*res != پوچ)
					freeaddrinfo(*res);
				بازگشت (EAI_MEMORY);
			}
			اگر (prev)
				prev->ai_next = cur;
			وگرنه
				*res = cur;

			prev = cur;
		}
		بازگشت (0);
	}

	بازگشت (EAI_NODATA);
}
#endif /* !HAVE_GETADDRINFO */
