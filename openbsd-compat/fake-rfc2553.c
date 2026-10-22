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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>

#അന്തര്ഭാവ <netinet/in.h>
#അന്തര്ഭാവ <arpa/inet.h>

#ifndef HAVE_GETNAMEINFO
പൂർണ്ണസംഖ്യ getnameinfo(സ്ഥിരം ഘടന sockaddr *sa, size_t salen, അക്ഷരം *host,
		size_t hostlen, അക്ഷരം *serv, size_t servlen, പൂർണ്ണസംഖ്യ flags)
{
	ഘടന sockaddr_in *sin = (ഘടന sockaddr_in *)sa;
	ഘടന hostent *hp;
	അക്ഷരം tmpserv[16];

	എങ്കിൽ ((sa->sa_family != AF_UNSPEC && sa->sa_family != AF_INET) ||
	    salen < വലുപ്പം(ഘടന sockaddr_in))
		തിരികെ (EAI_FAMILY);
	എങ്കിൽ (serv != ശൂന്യ) {
		snprintf(tmpserv, വലുപ്പം(tmpserv), "%d", ntohs(sin->sin_port));
		എങ്കിൽ (strlcpy(serv, tmpserv, servlen) >= servlen)
			തിരികെ (EAI_MEMORY);
	}

	എങ്കിൽ (host != ശൂന്യ) {
		എങ്കിൽ (flags & NI_NUMERICHOST) {
			എങ്കിൽ (strlcpy(host, inet_ntoa(sin->sin_addr),
			    hostlen) >= hostlen)
				തിരികെ (EAI_MEMORY);
			അല്ലെങ്കിൽ
				തിരികെ (0);
		} അല്ലെങ്കിൽ {
			hp = gethostbyaddr((അക്ഷരം *)&sin->sin_addr,
			    വലുപ്പം(ഘടന in_addr), AF_INET);
			എങ്കിൽ (hp == ശൂന്യ)
				തിരികെ (EAI_NODATA);

			എങ്കിൽ (strlcpy(host, hp->h_name, hostlen) >= hostlen)
				തിരികെ (EAI_MEMORY);
			അല്ലെങ്കിൽ
				തിരികെ (0);
		}
	}
	തിരികെ (0);
}
#endif /* !HAVE_GETNAMEINFO */

#ifndef HAVE_GAI_STRERROR
#ifdef HAVE_CONST_GAI_STRERROR_PROTO
സ്ഥിരം അക്ഷരം *
#അല്ലെങ്കിൽ
അക്ഷരം *
#endif
gai_strerror(പൂർണ്ണസംഖ്യ err)
{
	തിരഞ്ഞെടുപ്പ് (err) {
	അവസ്ഥ EAI_NODATA:
		തിരികെ ("no address associated with name");
	അവസ്ഥ EAI_MEMORY:
		തിരികെ ("memory allocation failure");
	അവസ്ഥ EAI_NONAME:
		തിരികെ ("name or service is not known");
	അവസ്ഥ EAI_FAMILY:
		തിരികെ ("ai_family not supported");
	സ്ഥിരസ്ഥിതി:
		തിരികെ ("unknown/invalid error");
	}
}
#endif /* !HAVE_GAI_STRERROR */

#ifndef HAVE_FREEADDRINFO
ശൂന്യം
freeaddrinfo(ഘടന addrinfo *ai)
{
	ഘടന addrinfo *next;

	വേണ്ടി(; ai != ശൂന്യ;) {
		next = ai->ai_next;
		സ്വതന്ത്രം(ai);
		ai = next;
	}
}
#endif /* !HAVE_FREEADDRINFO */

#ifndef HAVE_GETADDRINFO
സ്ഥിതം ഘടന
addrinfo *malloc_ai(പൂർണ്ണസംഖ്യ port, u_long addr, സ്ഥിരം ഘടന addrinfo *hints)
{
	ഘടന addrinfo *ai;

	ai = malloc(വലുപ്പം(*ai) + വലുപ്പം(ഘടന sockaddr_in));
	എങ്കിൽ (ai == ശൂന്യ)
		തിരികെ (ശൂന്യ);

	memset(ai, '\0', വലുപ്പം(*ai) + വലുപ്പം(ഘടന sockaddr_in));

	ai->ai_addr = (ഘടന sockaddr *)(ai + 1);
	/* XXX -- ssh doesn't use sa_len */
	ai->ai_addrlen = വലുപ്പം(ഘടന sockaddr_in);
	ai->ai_addr->sa_family = ai->ai_family = AF_INET;

	((ഘടന sockaddr_in *)(ai)->ai_addr)->sin_port = port;
	((ഘടന sockaddr_in *)(ai)->ai_addr)->sin_addr.s_addr = addr;

	/* XXX: the following is not generally correct, but does what we want */
	എങ്കിൽ (hints->ai_socktype)
		ai->ai_socktype = hints->ai_socktype;
	അല്ലെങ്കിൽ
		ai->ai_socktype = SOCK_STREAM;

	എങ്കിൽ (hints->ai_protocol)
		ai->ai_protocol = hints->ai_protocol;

	തിരികെ (ai);
}

പൂർണ്ണസംഖ്യ
getaddrinfo(സ്ഥിരം അക്ഷരം *hostname, സ്ഥിരം അക്ഷരം *servname,
    സ്ഥിരം ഘടന addrinfo *hints, ഘടന addrinfo **res)
{
	ഘടന hostent *hp;
	ഘടന servent *sp;
	ഘടന in_addr in;
	പൂർണ്ണസംഖ്യ i;
	long പൂർണ്ണസംഖ്യ port;
	u_long addr;

	port = 0;
	എങ്കിൽ (hints && hints->ai_family != AF_UNSPEC &&
	    hints->ai_family != AF_INET)
		തിരികെ (EAI_FAMILY);
	എങ്കിൽ (servname != ശൂന്യ) {
		അക്ഷരം *cp;

		port = strtol(servname, &cp, 10);
		എങ്കിൽ (port > 0 && port <= 65535 && *cp == '\0')
			port = htons(port);
		അല്ലെങ്കിൽ എങ്കിൽ ((sp = getservbyname(servname, ശൂന്യ)) != ശൂന്യ)
			port = sp->s_port;
		അല്ലെങ്കിൽ
			port = 0;
	}

	എങ്കിൽ (hints && hints->ai_flags & AI_PASSIVE) {
		addr = htonl(0x00000000);
		എങ്കിൽ (hostname && inet_aton(hostname, &in) != 0)
			addr = in.s_addr;
		*res = malloc_ai(port, addr, hints);
		എങ്കിൽ (*res == ശൂന്യ)
			തിരികെ (EAI_MEMORY);
		തിരികെ (0);
	}

	എങ്കിൽ (!hostname) {
		*res = malloc_ai(port, htonl(0x7f000001), hints);
		എങ്കിൽ (*res == ശൂന്യ)
			തിരികെ (EAI_MEMORY);
		തിരികെ (0);
	}

	എങ്കിൽ (inet_aton(hostname, &in)) {
		*res = malloc_ai(port, in.s_addr, hints);
		എങ്കിൽ (*res == ശൂന്യ)
			തിരികെ (EAI_MEMORY);
		തിരികെ (0);
	}

	/* Don't try DNS if AI_NUMERICHOST is set */
	എങ്കിൽ (hints && hints->ai_flags & AI_NUMERICHOST)
		തിരികെ (EAI_NONAME);

	hp = gethostbyname(hostname);
	എങ്കിൽ (hp && hp->h_name && hp->h_name[0] && hp->h_addr_list[0]) {
		ഘടന addrinfo *cur, *prev;

		cur = prev = *res = ശൂന്യ;
		വേണ്ടി (i = 0; hp->h_addr_list[i]; i++) {
			ഘടന in_addr *in = (ഘടന in_addr *)hp->h_addr_list[i];

			cur = malloc_ai(port, in->s_addr, hints);
			എങ്കിൽ (cur == ശൂന്യ) {
				എങ്കിൽ (*res != ശൂന്യ)
					freeaddrinfo(*res);
				തിരികെ (EAI_MEMORY);
			}
			എങ്കിൽ (prev)
				prev->ai_next = cur;
			അല്ലെങ്കിൽ
				*res = cur;

			prev = cur;
		}
		തിരികെ (0);
	}

	തിരികെ (EAI_NODATA);
}
#endif /* !HAVE_GETADDRINFO */
