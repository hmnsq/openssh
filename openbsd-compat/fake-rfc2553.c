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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <netinet/in.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <arpa/inet.h>

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_GETNAMEINFO
ਪੂਰਨ getnameinfo(ਅਚਲ ਬਣਤਰ sockaddr *sa, ਮਾਪ_t salen, ਅੱਖਰ *host,
		ਮਾਪ_t hostlen, ਅੱਖਰ *serv, ਮਾਪ_t servlen, ਪੂਰਨ flags)
{
	ਬਣਤਰ sockaddr_in *ਜੀਵਾ = (ਬਣਤਰ sockaddr_in *)sa;
	ਬਣਤਰ hostent *hp;
	ਅੱਖਰ tmpserv[16];

	ਜੇ ((sa->sa_family != AF_UNSPEC && sa->sa_family != AF_INET) ||
	    salen < ਆਕਾਰ(ਬਣਤਰ sockaddr_in))
		ਵਾਪਸ (EAI_FAMILY);
	ਜੇ (serv != ਨਿਰਾ) {
		snprintf(tmpserv, ਆਕਾਰ(tmpserv), "%d", ntohs(ਜੀਵਾ->sin_port));
		ਜੇ (strlcpy(serv, tmpserv, servlen) >= servlen)
			ਵਾਪਸ (EAI_MEMORY);
	}

	ਜੇ (host != ਨਿਰਾ) {
		ਜੇ (flags & NI_NUMERICHOST) {
			ਜੇ (strlcpy(host, inet_ntoa(ਜੀਵਾ->sin_addr),
			    hostlen) >= hostlen)
				ਵਾਪਸ (EAI_MEMORY);
			ਨਹੀਂਤਾਂ
				ਵਾਪਸ (0);
		} ਨਹੀਂਤਾਂ {
			hp = gethostbyaddr((ਅੱਖਰ *)&ਜੀਵਾ->sin_addr,
			    ਆਕਾਰ(ਬਣਤਰ in_addr), AF_INET);
			ਜੇ (hp == ਨਿਰਾ)
				ਵਾਪਸ (EAI_NODATA);

			ਜੇ (strlcpy(host, hp->h_name, hostlen) >= hostlen)
				ਵਾਪਸ (EAI_MEMORY);
			ਨਹੀਂਤਾਂ
				ਵਾਪਸ (0);
		}
	}
	ਵਾਪਸ (0);
}
#ਜੇ_ਅੰਤ /* !HAVE_GETNAMEINFO */

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_GAI_STRERROR
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_CONST_GAI_STRERROR_PROTO
ਅਚਲ ਅੱਖਰ *
#ਨਹੀਂਤਾਂ
ਅੱਖਰ *
#ਜੇ_ਅੰਤ
gai_strerror(ਪੂਰਨ err)
{
	ਚੋਣ (err) {
	ਹਾਲਤ EAI_NODATA:
		ਵਾਪਸ ("no address associated with name");
	ਹਾਲਤ EAI_MEMORY:
		ਵਾਪਸ ("memory allocation failure");
	ਹਾਲਤ EAI_NONAME:
		ਵਾਪਸ ("name or service is not known");
	ਹਾਲਤ EAI_FAMILY:
		ਵਾਪਸ ("ai_family not supported");
	ਮੂਲ:
		ਵਾਪਸ ("unknown/invalid error");
	}
}
#ਜੇ_ਅੰਤ /* !HAVE_GAI_STRERROR */

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_FREEADDRINFO
ਖਾਲੀ
freeaddrinfo(ਬਣਤਰ addrinfo *ai)
{
	ਬਣਤਰ addrinfo *ਅਗਲਾ;

	ਲਈ(; ai != ਨਿਰਾ;) {
		ਅਗਲਾ = ai->ai_next;
		ਮੁਕਤ(ai);
		ai = ਅਗਲਾ;
	}
}
#ਜੇ_ਅੰਤ /* !HAVE_FREEADDRINFO */

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_GETADDRINFO
ਸਥਿਰ ਬਣਤਰ
addrinfo *malloc_ai(ਪੂਰਨ ਪੋਰਟ, u_long addr, ਅਚਲ ਬਣਤਰ addrinfo *hints)
{
	ਬਣਤਰ addrinfo *ai;

	ai = ਸਮ੍ਰਿਤੀ_ਦਿਓ(ਆਕਾਰ(*ai) + ਆਕਾਰ(ਬਣਤਰ sockaddr_in));
	ਜੇ (ai == ਨਿਰਾ)
		ਵਾਪਸ (ਨਿਰਾ);

	memset(ai, '\0', ਆਕਾਰ(*ai) + ਆਕਾਰ(ਬਣਤਰ sockaddr_in));

	ai->ai_addr = (ਬਣਤਰ sockaddr *)(ai + 1);
	/* XXX -- ssh doesn't use sa_len */
	ai->ai_addrlen = ਆਕਾਰ(ਬਣਤਰ sockaddr_in);
	ai->ai_addr->sa_family = ai->ai_family = AF_INET;

	((ਬਣਤਰ sockaddr_in *)(ai)->ai_addr)->sin_port = ਪੋਰਟ;
	((ਬਣਤਰ sockaddr_in *)(ai)->ai_addr)->sin_addr.s_addr = addr;

	/* XXX: the following is not generally correct, but does what we want */
	ਜੇ (hints->ai_socktype)
		ai->ai_socktype = hints->ai_socktype;
	ਨਹੀਂਤਾਂ
		ai->ai_socktype = SOCK_STREAM;

	ਜੇ (hints->ai_protocol)
		ai->ai_protocol = hints->ai_protocol;

	ਵਾਪਸ (ai);
}

ਪੂਰਨ
getaddrinfo(ਅਚਲ ਅੱਖਰ *hostname, ਅਚਲ ਅੱਖਰ *servname,
    ਅਚਲ ਬਣਤਰ addrinfo *hints, ਬਣਤਰ addrinfo **res)
{
	ਬਣਤਰ hostent *hp;
	ਬਣਤਰ servent *sp;
	ਬਣਤਰ in_addr ਵਿੱਚ;
	ਪੂਰਨ i;
	ਲੰਮਾ ਪੂਰਨ ਪੋਰਟ;
	u_long addr;

	ਪੋਰਟ = 0;
	ਜੇ (hints && hints->ai_family != AF_UNSPEC &&
	    hints->ai_family != AF_INET)
		ਵਾਪਸ (EAI_FAMILY);
	ਜੇ (servname != ਨਿਰਾ) {
		ਅੱਖਰ *cp;

		ਪੋਰਟ = strtol(servname, &cp, 10);
		ਜੇ (ਪੋਰਟ > 0 && ਪੋਰਟ <= 65535 && *cp == '\0')
			ਪੋਰਟ = htons(ਪੋਰਟ);
		ਨਹੀਂਤਾਂ ਜੇ ((sp = getservbyname(servname, ਨਿਰਾ)) != ਨਿਰਾ)
			ਪੋਰਟ = sp->s_port;
		ਨਹੀਂਤਾਂ
			ਪੋਰਟ = 0;
	}

	ਜੇ (hints && hints->ai_flags & AI_PASSIVE) {
		addr = htonl(0x00000000);
		ਜੇ (hostname && inet_aton(hostname, &ਵਿੱਚ) != 0)
			addr = ਵਿੱਚ.s_addr;
		*res = malloc_ai(ਪੋਰਟ, addr, hints);
		ਜੇ (*res == ਨਿਰਾ)
			ਵਾਪਸ (EAI_MEMORY);
		ਵਾਪਸ (0);
	}

	ਜੇ (!hostname) {
		*res = malloc_ai(ਪੋਰਟ, htonl(0x7f000001), hints);
		ਜੇ (*res == ਨਿਰਾ)
			ਵਾਪਸ (EAI_MEMORY);
		ਵਾਪਸ (0);
	}

	ਜੇ (inet_aton(hostname, &ਵਿੱਚ)) {
		*res = malloc_ai(ਪੋਰਟ, ਵਿੱਚ.s_addr, hints);
		ਜੇ (*res == ਨਿਰਾ)
			ਵਾਪਸ (EAI_MEMORY);
		ਵਾਪਸ (0);
	}

	/* Don't try DNS if AI_NUMERICHOST is set */
	ਜੇ (hints && hints->ai_flags & AI_NUMERICHOST)
		ਵਾਪਸ (EAI_NONAME);

	hp = gethostbyname(hostname);
	ਜੇ (hp && hp->h_name && hp->h_name[0] && hp->h_addr_list[0]) {
		ਬਣਤਰ addrinfo *cur, *prev;

		cur = prev = *res = ਨਿਰਾ;
		ਲਈ (i = 0; hp->h_addr_list[i]; i++) {
			ਬਣਤਰ in_addr *ਵਿੱਚ = (ਬਣਤਰ in_addr *)hp->h_addr_list[i];

			cur = malloc_ai(ਪੋਰਟ, ਵਿੱਚ->s_addr, hints);
			ਜੇ (cur == ਨਿਰਾ) {
				ਜੇ (*res != ਨਿਰਾ)
					freeaddrinfo(*res);
				ਵਾਪਸ (EAI_MEMORY);
			}
			ਜੇ (prev)
				prev->ai_next = cur;
			ਨਹੀਂਤਾਂ
				*res = cur;

			prev = cur;
		}
		ਵਾਪਸ (0);
	}

	ਵਾਪਸ (EAI_NODATA);
}
#ਜੇ_ਅੰਤ /* !HAVE_GETADDRINFO */
