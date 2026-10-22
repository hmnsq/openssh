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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>

#அந்தர்பாவ <netinet/in.h>
#அந்தர்பாவ <arpa/inet.h>

#ifndef HAVE_GETNAMEINFO
முழு getnameinfo(மாறிலி கட்டமைப்பு sockaddr *sa, size_t salen, எழுத்து *host,
		size_t hostlen, எழுத்து *serv, size_t servlen, முழு flags)
{
	கட்டமைப்பு sockaddr_in *sin = (கட்டமைப்பு sockaddr_in *)sa;
	கட்டமைப்பு hostent *hp;
	எழுத்து tmpserv[16];

	எனில் ((sa->sa_family != AF_UNSPEC && sa->sa_family != AF_INET) ||
	    salen < அளவு(கட்டமைப்பு sockaddr_in))
		திரும்பு (EAI_FAMILY);
	எனில் (serv != வெற்று) {
		snprintf(tmpserv, அளவு(tmpserv), "%d", ntohs(sin->sin_port));
		எனில் (strlcpy(serv, tmpserv, servlen) >= servlen)
			திரும்பு (EAI_MEMORY);
	}

	எனில் (host != வெற்று) {
		எனில் (flags & NI_NUMERICHOST) {
			எனில் (strlcpy(host, inet_ntoa(sin->sin_addr),
			    hostlen) >= hostlen)
				திரும்பு (EAI_MEMORY);
			இல்லையெனில்
				திரும்பு (0);
		} இல்லையெனில் {
			hp = gethostbyaddr((எழுத்து *)&sin->sin_addr,
			    அளவு(கட்டமைப்பு in_addr), AF_INET);
			எனில் (hp == வெற்று)
				திரும்பு (EAI_NODATA);

			எனில் (strlcpy(host, hp->h_name, hostlen) >= hostlen)
				திரும்பு (EAI_MEMORY);
			இல்லையெனில்
				திரும்பு (0);
		}
	}
	திரும்பு (0);
}
#endif /* !HAVE_GETNAMEINFO */

#ifndef HAVE_GAI_STRERROR
#ifdef HAVE_CONST_GAI_STRERROR_PROTO
மாறிலி எழுத்து *
#இல்லையெனில்
எழுத்து *
#endif
gai_strerror(முழு err)
{
	தேர்வு (err) {
	நிலை EAI_NODATA:
		திரும்பு ("no address associated with name");
	நிலை EAI_MEMORY:
		திரும்பு ("memory allocation failure");
	நிலை EAI_NONAME:
		திரும்பு ("name or service is not known");
	நிலை EAI_FAMILY:
		திரும்பு ("ai_family not supported");
	இயல்பு:
		திரும்பு ("unknown/invalid error");
	}
}
#endif /* !HAVE_GAI_STRERROR */

#ifndef HAVE_FREEADDRINFO
வெறுமை
freeaddrinfo(கட்டமைப்பு addrinfo *ai)
{
	கட்டமைப்பு addrinfo *next;

	க்கு(; ai != வெற்று;) {
		next = ai->ai_next;
		விடுவி(ai);
		ai = next;
	}
}
#endif /* !HAVE_FREEADDRINFO */

#ifndef HAVE_GETADDRINFO
நிலையான கட்டமைப்பு
addrinfo *malloc_ai(முழு port, u_long addr, மாறிலி கட்டமைப்பு addrinfo *hints)
{
	கட்டமைப்பு addrinfo *ai;

	ai = malloc(அளவு(*ai) + அளவு(கட்டமைப்பு sockaddr_in));
	எனில் (ai == வெற்று)
		திரும்பு (வெற்று);

	memset(ai, '\0', அளவு(*ai) + அளவு(கட்டமைப்பு sockaddr_in));

	ai->ai_addr = (கட்டமைப்பு sockaddr *)(ai + 1);
	/* XXX -- ssh doesn't use sa_len */
	ai->ai_addrlen = அளவு(கட்டமைப்பு sockaddr_in);
	ai->ai_addr->sa_family = ai->ai_family = AF_INET;

	((கட்டமைப்பு sockaddr_in *)(ai)->ai_addr)->sin_port = port;
	((கட்டமைப்பு sockaddr_in *)(ai)->ai_addr)->sin_addr.s_addr = addr;

	/* XXX: the following is not generally correct, but does what we want */
	எனில் (hints->ai_socktype)
		ai->ai_socktype = hints->ai_socktype;
	இல்லையெனில்
		ai->ai_socktype = SOCK_STREAM;

	எனில் (hints->ai_protocol)
		ai->ai_protocol = hints->ai_protocol;

	திரும்பு (ai);
}

முழு
getaddrinfo(மாறிலி எழுத்து *hostname, மாறிலி எழுத்து *servname,
    மாறிலி கட்டமைப்பு addrinfo *hints, கட்டமைப்பு addrinfo **res)
{
	கட்டமைப்பு hostent *hp;
	கட்டமைப்பு servent *sp;
	கட்டமைப்பு in_addr in;
	முழு i;
	long முழு port;
	u_long addr;

	port = 0;
	எனில் (hints && hints->ai_family != AF_UNSPEC &&
	    hints->ai_family != AF_INET)
		திரும்பு (EAI_FAMILY);
	எனில் (servname != வெற்று) {
		எழுத்து *cp;

		port = strtol(servname, &cp, 10);
		எனில் (port > 0 && port <= 65535 && *cp == '\0')
			port = htons(port);
		இல்லையெனில் எனில் ((sp = getservbyname(servname, வெற்று)) != வெற்று)
			port = sp->s_port;
		இல்லையெனில்
			port = 0;
	}

	எனில் (hints && hints->ai_flags & AI_PASSIVE) {
		addr = htonl(0x00000000);
		எனில் (hostname && inet_aton(hostname, &in) != 0)
			addr = in.s_addr;
		*res = malloc_ai(port, addr, hints);
		எனில் (*res == வெற்று)
			திரும்பு (EAI_MEMORY);
		திரும்பு (0);
	}

	எனில் (!hostname) {
		*res = malloc_ai(port, htonl(0x7f000001), hints);
		எனில் (*res == வெற்று)
			திரும்பு (EAI_MEMORY);
		திரும்பு (0);
	}

	எனில் (inet_aton(hostname, &in)) {
		*res = malloc_ai(port, in.s_addr, hints);
		எனில் (*res == வெற்று)
			திரும்பு (EAI_MEMORY);
		திரும்பு (0);
	}

	/* Don't try DNS if AI_NUMERICHOST is set */
	எனில் (hints && hints->ai_flags & AI_NUMERICHOST)
		திரும்பு (EAI_NONAME);

	hp = gethostbyname(hostname);
	எனில் (hp && hp->h_name && hp->h_name[0] && hp->h_addr_list[0]) {
		கட்டமைப்பு addrinfo *cur, *prev;

		cur = prev = *res = வெற்று;
		க்கு (i = 0; hp->h_addr_list[i]; i++) {
			கட்டமைப்பு in_addr *in = (கட்டமைப்பு in_addr *)hp->h_addr_list[i];

			cur = malloc_ai(port, in->s_addr, hints);
			எனில் (cur == வெற்று) {
				எனில் (*res != வெற்று)
					freeaddrinfo(*res);
				திரும்பு (EAI_MEMORY);
			}
			எனில் (prev)
				prev->ai_next = cur;
			இல்லையெனில்
				*res = cur;

			prev = cur;
		}
		திரும்பு (0);
	}

	திரும்பு (EAI_NODATA);
}
#endif /* !HAVE_GETADDRINFO */
