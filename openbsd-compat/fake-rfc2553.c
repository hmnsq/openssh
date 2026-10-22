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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>

#ಅನ್ತರ್ಭಾವ <netinet/in.h>
#ಅನ್ತರ್ಭಾವ <arpa/inet.h>

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_GETNAMEINFO
ಪೂರ್ಣಾಂಕ getnameinfo(ಸ್ಥಿರಾಂಕ ರಚನೆ sockaddr *sa, ಗಾತ್ರ_t salen, ಅಕ್ಷರ *host,
		ಗಾತ್ರ_t hostlen, ಅಕ್ಷರ *serv, ಗಾತ್ರ_t servlen, ಪೂರ್ಣಾಂಕ flags)
{
	ರಚನೆ sockaddr_in *ಜ್ಯಾ = (ರಚನೆ sockaddr_in *)sa;
	ರಚನೆ hostent *hp;
	ಅಕ್ಷರ tmpserv[16];

	ಆದರೆ ((sa->sa_family != AF_UNSPEC && sa->sa_family != AF_INET) ||
	    salen < ಗಾತ್ರ(ರಚನೆ sockaddr_in))
		ಹಿಂತಿರುಗಿ (EAI_FAMILY);
	ಆದರೆ (serv != ಖಾಲಿ) {
		snprintf(tmpserv, ಗಾತ್ರ(tmpserv), "%d", ntohs(ಜ್ಯಾ->sin_port));
		ಆದರೆ (strlcpy(serv, tmpserv, servlen) >= servlen)
			ಹಿಂತಿರುಗಿ (EAI_MEMORY);
	}

	ಆದರೆ (host != ಖಾಲಿ) {
		ಆದರೆ (flags & NI_NUMERICHOST) {
			ಆದರೆ (strlcpy(host, inet_ntoa(ಜ್ಯಾ->sin_addr),
			    hostlen) >= hostlen)
				ಹಿಂತಿರುಗಿ (EAI_MEMORY);
			ಇಲ್ಲದಿದ್ದರೆ
				ಹಿಂತಿರುಗಿ (0);
		} ಇಲ್ಲದಿದ್ದರೆ {
			hp = gethostbyaddr((ಅಕ್ಷರ *)&ಜ್ಯಾ->sin_addr,
			    ಗಾತ್ರ(ರಚನೆ in_addr), AF_INET);
			ಆದರೆ (hp == ಖಾಲಿ)
				ಹಿಂತಿರುಗಿ (EAI_NODATA);

			ಆದರೆ (strlcpy(host, hp->h_name, hostlen) >= hostlen)
				ಹಿಂತಿರುಗಿ (EAI_MEMORY);
			ಇಲ್ಲದಿದ್ದರೆ
				ಹಿಂತಿರುಗಿ (0);
		}
	}
	ಹಿಂತಿರುಗಿ (0);
}
#ಆದರೆ_ಅಂತ್ಯ /* !HAVE_GETNAMEINFO */

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_GAI_STRERROR
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_CONST_GAI_STRERROR_PROTO
ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *
#ಇಲ್ಲದಿದ್ದರೆ
ಅಕ್ಷರ *
#ಆದರೆ_ಅಂತ್ಯ
gai_strerror(ಪೂರ್ಣಾಂಕ err)
{
	ಆಯ್ಕೆ (err) {
	ಸ್ಥಿತಿ EAI_NODATA:
		ಹಿಂತಿರುಗಿ ("no address associated with name");
	ಸ್ಥಿತಿ EAI_MEMORY:
		ಹಿಂತಿರುಗಿ ("memory allocation failure");
	ಸ್ಥಿತಿ EAI_NONAME:
		ಹಿಂತಿರುಗಿ ("name or service is not known");
	ಸ್ಥಿತಿ EAI_FAMILY:
		ಹಿಂತಿರುಗಿ ("ai_family not supported");
	ಪೂರ್ವನಿಯೋಜಿತ:
		ಹಿಂತಿರುಗಿ ("unknown/invalid error");
	}
}
#ಆದರೆ_ಅಂತ್ಯ /* !HAVE_GAI_STRERROR */

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_FREEADDRINFO
ಶೂನ್ಯ
freeaddrinfo(ರಚನೆ addrinfo *ai)
{
	ರಚನೆ addrinfo *ಮುಂದಿನ;

	ಗಾಗಿ(; ai != ಖಾಲಿ;) {
		ಮುಂದಿನ = ai->ai_next;
		ಬಿಡುಗಡೆ(ai);
		ai = ಮುಂದಿನ;
	}
}
#ಆದರೆ_ಅಂತ್ಯ /* !HAVE_FREEADDRINFO */

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_GETADDRINFO
ಸ್ಥಿರ ರಚನೆ
addrinfo *malloc_ai(ಪೂರ್ಣಾಂಕ ಪೋರ್ಟ್, u_long addr, ಸ್ಥಿರಾಂಕ ರಚನೆ addrinfo *hints)
{
	ರಚನೆ addrinfo *ai;

	ai = ಸ್ಮರಣೆ_ಕೊಡು(ಗಾತ್ರ(*ai) + ಗಾತ್ರ(ರಚನೆ sockaddr_in));
	ಆದರೆ (ai == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ (ಖಾಲಿ);

	memset(ai, '\0', ಗಾತ್ರ(*ai) + ಗಾತ್ರ(ರಚನೆ sockaddr_in));

	ai->ai_addr = (ರಚನೆ sockaddr *)(ai + 1);
	/* XXX -- ssh doesn't use sa_len */
	ai->ai_addrlen = ಗಾತ್ರ(ರಚನೆ sockaddr_in);
	ai->ai_addr->sa_family = ai->ai_family = AF_INET;

	((ರಚನೆ sockaddr_in *)(ai)->ai_addr)->sin_port = ಪೋರ್ಟ್;
	((ರಚನೆ sockaddr_in *)(ai)->ai_addr)->sin_addr.s_addr = addr;

	/* XXX: the following is not generally correct, but does what we want */
	ಆದರೆ (hints->ai_socktype)
		ai->ai_socktype = hints->ai_socktype;
	ಇಲ್ಲದಿದ್ದರೆ
		ai->ai_socktype = SOCK_STREAM;

	ಆದರೆ (hints->ai_protocol)
		ai->ai_protocol = hints->ai_protocol;

	ಹಿಂತಿರುಗಿ (ai);
}

ಪೂರ್ಣಾಂಕ
getaddrinfo(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *hostname, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *servname,
    ಸ್ಥಿರಾಂಕ ರಚನೆ addrinfo *hints, ರಚನೆ addrinfo **res)
{
	ರಚನೆ hostent *hp;
	ರಚನೆ servent *sp;
	ರಚನೆ in_addr ಒಳ;
	ಪೂರ್ಣಾಂಕ i;
	ದೀರ್ಘ ಪೂರ್ಣಾಂಕ ಪೋರ್ಟ್;
	u_long addr;

	ಪೋರ್ಟ್ = 0;
	ಆದರೆ (hints && hints->ai_family != AF_UNSPEC &&
	    hints->ai_family != AF_INET)
		ಹಿಂತಿರುಗಿ (EAI_FAMILY);
	ಆದರೆ (servname != ಖಾಲಿ) {
		ಅಕ್ಷರ *cp;

		ಪೋರ್ಟ್ = strtol(servname, &cp, 10);
		ಆದರೆ (ಪೋರ್ಟ್ > 0 && ಪೋರ್ಟ್ <= 65535 && *cp == '\0')
			ಪೋರ್ಟ್ = htons(ಪೋರ್ಟ್);
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((sp = getservbyname(servname, ಖಾಲಿ)) != ಖಾಲಿ)
			ಪೋರ್ಟ್ = sp->s_port;
		ಇಲ್ಲದಿದ್ದರೆ
			ಪೋರ್ಟ್ = 0;
	}

	ಆದರೆ (hints && hints->ai_flags & AI_PASSIVE) {
		addr = htonl(0x00000000);
		ಆದರೆ (hostname && inet_aton(hostname, &ಒಳ) != 0)
			addr = ಒಳ.s_addr;
		*res = malloc_ai(ಪೋರ್ಟ್, addr, hints);
		ಆದರೆ (*res == ಖಾಲಿ)
			ಹಿಂತಿರುಗಿ (EAI_MEMORY);
		ಹಿಂತಿರುಗಿ (0);
	}

	ಆದರೆ (!hostname) {
		*res = malloc_ai(ಪೋರ್ಟ್, htonl(0x7f000001), hints);
		ಆದರೆ (*res == ಖಾಲಿ)
			ಹಿಂತಿರುಗಿ (EAI_MEMORY);
		ಹಿಂತಿರುಗಿ (0);
	}

	ಆದರೆ (inet_aton(hostname, &ಒಳ)) {
		*res = malloc_ai(ಪೋರ್ಟ್, ಒಳ.s_addr, hints);
		ಆದರೆ (*res == ಖಾಲಿ)
			ಹಿಂತಿರುಗಿ (EAI_MEMORY);
		ಹಿಂತಿರುಗಿ (0);
	}

	/* Don't try DNS if AI_NUMERICHOST is set */
	ಆದರೆ (hints && hints->ai_flags & AI_NUMERICHOST)
		ಹಿಂತಿರುಗಿ (EAI_NONAME);

	hp = gethostbyname(hostname);
	ಆದರೆ (hp && hp->h_name && hp->h_name[0] && hp->h_addr_list[0]) {
		ರಚನೆ addrinfo *cur, *prev;

		cur = prev = *res = ಖಾಲಿ;
		ಗಾಗಿ (i = 0; hp->h_addr_list[i]; i++) {
			ರಚನೆ in_addr *ಒಳ = (ರಚನೆ in_addr *)hp->h_addr_list[i];

			cur = malloc_ai(ಪೋರ್ಟ್, ಒಳ->s_addr, hints);
			ಆದರೆ (cur == ಖಾಲಿ) {
				ಆದರೆ (*res != ಖಾಲಿ)
					freeaddrinfo(*res);
				ಹಿಂತಿರುಗಿ (EAI_MEMORY);
			}
			ಆದರೆ (prev)
				prev->ai_next = cur;
			ಇಲ್ಲದಿದ್ದರೆ
				*res = cur;

			prev = cur;
		}
		ಹಿಂತಿರುಗಿ (0);
	}

	ಹಿಂತಿರುಗಿ (EAI_NODATA);
}
#ಆದರೆ_ಅಂತ್ಯ /* !HAVE_GETADDRINFO */
