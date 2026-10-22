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

#ifndef HAVE_GETNAMEINFO
ಪೂರ್ಣಾಙ್ಕ getnameinfo(ಧ್ರುವ ಸಂರಚನಾ sockaddr *sa, size_t salen, ವರ್ಣ *host,
		size_t hostlen, ವರ್ಣ *serv, size_t servlen, ಪೂರ್ಣಾಙ್ಕ flags)
{
	ಸಂರಚನಾ sockaddr_in *sin = (ಸಂರಚನಾ sockaddr_in *)sa;
	ಸಂರಚನಾ hostent *hp;
	ವರ್ಣ tmpserv[16];

	ಯದಿ ((sa->sa_family != AF_UNSPEC && sa->sa_family != AF_INET) ||
	    salen < ಪರಿಮಾಣ(ಸಂರಚನಾ sockaddr_in))
		ಪ್ರತ್ಯಾಗಮ (EAI_FAMILY);
	ಯದಿ (serv != ರಿಕ್ತ) {
		snprintf(tmpserv, ಪರಿಮಾಣ(tmpserv), "%d", ntohs(sin->sin_port));
		ಯದಿ (strlcpy(serv, tmpserv, servlen) >= servlen)
			ಪ್ರತ್ಯಾಗಮ (EAI_MEMORY);
	}

	ಯದಿ (host != ರಿಕ್ತ) {
		ಯದಿ (flags & NI_NUMERICHOST) {
			ಯದಿ (strlcpy(host, inet_ntoa(sin->sin_addr),
			    hostlen) >= hostlen)
				ಪ್ರತ್ಯಾಗಮ (EAI_MEMORY);
			ಅನ್ಯಥಾ
				ಪ್ರತ್ಯಾಗಮ (0);
		} ಅನ್ಯಥಾ {
			hp = gethostbyaddr((ವರ್ಣ *)&sin->sin_addr,
			    ಪರಿಮಾಣ(ಸಂರಚನಾ in_addr), AF_INET);
			ಯದಿ (hp == ರಿಕ್ತ)
				ಪ್ರತ್ಯಾಗಮ (EAI_NODATA);

			ಯದಿ (strlcpy(host, hp->h_name, hostlen) >= hostlen)
				ಪ್ರತ್ಯಾಗಮ (EAI_MEMORY);
			ಅನ್ಯಥಾ
				ಪ್ರತ್ಯಾಗಮ (0);
		}
	}
	ಪ್ರತ್ಯಾಗಮ (0);
}
#endif /* !HAVE_GETNAMEINFO */

#ifndef HAVE_GAI_STRERROR
#ifdef HAVE_CONST_GAI_STRERROR_PROTO
ಧ್ರುವ ವರ್ಣ *
#ಅನ್ಯಥಾ
ವರ್ಣ *
#endif
gai_strerror(ಪೂರ್ಣಾಙ್ಕ err)
{
	ವಿಕಲ್ಪ (err) {
	ಪಕ್ಷ EAI_NODATA:
		ಪ್ರತ್ಯಾಗಮ ("no address associated with name");
	ಪಕ್ಷ EAI_MEMORY:
		ಪ್ರತ್ಯಾಗಮ ("memory allocation failure");
	ಪಕ್ಷ EAI_NONAME:
		ಪ್ರತ್ಯಾಗಮ ("name or service is not known");
	ಪಕ್ಷ EAI_FAMILY:
		ಪ್ರತ್ಯಾಗಮ ("ai_family not supported");
	ಸ್ವಭಾವ:
		ಪ್ರತ್ಯಾಗಮ ("unknown/invalid error");
	}
}
#endif /* !HAVE_GAI_STRERROR */

#ifndef HAVE_FREEADDRINFO
ಶೂನ್ಯ
freeaddrinfo(ಸಂರಚನಾ addrinfo *ai)
{
	ಸಂರಚನಾ addrinfo *next;

	ಪ್ರತಿ(; ai != ರಿಕ್ತ;) {
		next = ai->ai_next;
		ಮುಕ್ತ(ai);
		ai = next;
	}
}
#endif /* !HAVE_FREEADDRINFO */

#ifndef HAVE_GETADDRINFO
ಸ್ಥಿರ ಸಂರಚನಾ
addrinfo *malloc_ai(ಪೂರ್ಣಾಙ್ಕ port, u_long addr, ಧ್ರುವ ಸಂರಚನಾ addrinfo *hints)
{
	ಸಂರಚನಾ addrinfo *ai;

	ai = malloc(ಪರಿಮಾಣ(*ai) + ಪರಿಮಾಣ(ಸಂರಚನಾ sockaddr_in));
	ಯದಿ (ai == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);

	memset(ai, '\0', ಪರಿಮಾಣ(*ai) + ಪರಿಮಾಣ(ಸಂರಚನಾ sockaddr_in));

	ai->ai_addr = (ಸಂರಚನಾ sockaddr *)(ai + 1);
	/* XXX -- ssh doesn't use sa_len */
	ai->ai_addrlen = ಪರಿಮಾಣ(ಸಂರಚನಾ sockaddr_in);
	ai->ai_addr->sa_family = ai->ai_family = AF_INET;

	((ಸಂರಚನಾ sockaddr_in *)(ai)->ai_addr)->sin_port = port;
	((ಸಂರಚನಾ sockaddr_in *)(ai)->ai_addr)->sin_addr.s_addr = addr;

	/* XXX: the following is not generally correct, but does what we want */
	ಯದಿ (hints->ai_socktype)
		ai->ai_socktype = hints->ai_socktype;
	ಅನ್ಯಥಾ
		ai->ai_socktype = SOCK_STREAM;

	ಯದಿ (hints->ai_protocol)
		ai->ai_protocol = hints->ai_protocol;

	ಪ್ರತ್ಯಾಗಮ (ai);
}

ಪೂರ್ಣಾಙ್ಕ
getaddrinfo(ಧ್ರುವ ವರ್ಣ *hostname, ಧ್ರುವ ವರ್ಣ *servname,
    ಧ್ರುವ ಸಂರಚನಾ addrinfo *hints, ಸಂರಚನಾ addrinfo **res)
{
	ಸಂರಚನಾ hostent *hp;
	ಸಂರಚನಾ servent *sp;
	ಸಂರಚನಾ in_addr in;
	ಪೂರ್ಣಾಙ್ಕ i;
	long ಪೂರ್ಣಾಙ್ಕ port;
	u_long addr;

	port = 0;
	ಯದಿ (hints && hints->ai_family != AF_UNSPEC &&
	    hints->ai_family != AF_INET)
		ಪ್ರತ್ಯಾಗಮ (EAI_FAMILY);
	ಯದಿ (servname != ರಿಕ್ತ) {
		ವರ್ಣ *cp;

		port = strtol(servname, &cp, 10);
		ಯದಿ (port > 0 && port <= 65535 && *cp == '\0')
			port = htons(port);
		ಅನ್ಯಥಾ ಯದಿ ((sp = getservbyname(servname, ರಿಕ್ತ)) != ರಿಕ್ತ)
			port = sp->s_port;
		ಅನ್ಯಥಾ
			port = 0;
	}

	ಯದಿ (hints && hints->ai_flags & AI_PASSIVE) {
		addr = htonl(0x00000000);
		ಯದಿ (hostname && inet_aton(hostname, &in) != 0)
			addr = in.s_addr;
		*res = malloc_ai(port, addr, hints);
		ಯದಿ (*res == ರಿಕ್ತ)
			ಪ್ರತ್ಯಾಗಮ (EAI_MEMORY);
		ಪ್ರತ್ಯಾಗಮ (0);
	}

	ಯದಿ (!hostname) {
		*res = malloc_ai(port, htonl(0x7f000001), hints);
		ಯದಿ (*res == ರಿಕ್ತ)
			ಪ್ರತ್ಯಾಗಮ (EAI_MEMORY);
		ಪ್ರತ್ಯಾಗಮ (0);
	}

	ಯದಿ (inet_aton(hostname, &in)) {
		*res = malloc_ai(port, in.s_addr, hints);
		ಯದಿ (*res == ರಿಕ್ತ)
			ಪ್ರತ್ಯಾಗಮ (EAI_MEMORY);
		ಪ್ರತ್ಯಾಗಮ (0);
	}

	/* Don't try DNS if AI_NUMERICHOST is set */
	ಯದಿ (hints && hints->ai_flags & AI_NUMERICHOST)
		ಪ್ರತ್ಯಾಗಮ (EAI_NONAME);

	hp = gethostbyname(hostname);
	ಯದಿ (hp && hp->h_name && hp->h_name[0] && hp->h_addr_list[0]) {
		ಸಂರಚನಾ addrinfo *cur, *prev;

		cur = prev = *res = ರಿಕ್ತ;
		ಪ್ರತಿ (i = 0; hp->h_addr_list[i]; i++) {
			ಸಂರಚನಾ in_addr *in = (ಸಂರಚನಾ in_addr *)hp->h_addr_list[i];

			cur = malloc_ai(port, in->s_addr, hints);
			ಯದಿ (cur == ರಿಕ್ತ) {
				ಯದಿ (*res != ರಿಕ್ತ)
					freeaddrinfo(*res);
				ಪ್ರತ್ಯಾಗಮ (EAI_MEMORY);
			}
			ಯದಿ (prev)
				prev->ai_next = cur;
			ಅನ್ಯಥಾ
				*res = cur;

			prev = cur;
		}
		ಪ್ರತ್ಯಾಗಮ (0);
	}

	ಪ್ರತ್ಯಾಗಮ (EAI_NODATA);
}
#endif /* !HAVE_GETADDRINFO */
