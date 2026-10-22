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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>

#અન્તર્ભાવ <netinet/in.h>
#અન્તર્ભાવ <arpa/inet.h>

#ifndef HAVE_GETNAMEINFO
પૂર્ણાંક getnameinfo(અચલ સંરચના sockaddr *sa, size_t salen, અક્ષર *host,
		size_t hostlen, અક્ષર *serv, size_t servlen, પૂર્ણાંક flags)
{
	સંરચના sockaddr_in *sin = (સંરચના sockaddr_in *)sa;
	સંરચના hostent *hp;
	અક્ષર tmpserv[16];

	જો ((sa->sa_family != AF_UNSPEC && sa->sa_family != AF_INET) ||
	    salen < કદ(સંરચના sockaddr_in))
		પાછા (EAI_FAMILY);
	જો (serv != ખાલી) {
		snprintf(tmpserv, કદ(tmpserv), "%d", ntohs(sin->sin_port));
		જો (strlcpy(serv, tmpserv, servlen) >= servlen)
			પાછા (EAI_MEMORY);
	}

	જો (host != ખાલી) {
		જો (flags & NI_NUMERICHOST) {
			જો (strlcpy(host, inet_ntoa(sin->sin_addr),
			    hostlen) >= hostlen)
				પાછા (EAI_MEMORY);
			નહીંતર
				પાછા (0);
		} નહીંતર {
			hp = gethostbyaddr((અક્ષર *)&sin->sin_addr,
			    કદ(સંરચના in_addr), AF_INET);
			જો (hp == ખાલી)
				પાછા (EAI_NODATA);

			જો (strlcpy(host, hp->h_name, hostlen) >= hostlen)
				પાછા (EAI_MEMORY);
			નહીંતર
				પાછા (0);
		}
	}
	પાછા (0);
}
#endif /* !HAVE_GETNAMEINFO */

#ifndef HAVE_GAI_STRERROR
#ifdef HAVE_CONST_GAI_STRERROR_PROTO
અચલ અક્ષર *
#નહીંતર
અક્ષર *
#endif
gai_strerror(પૂર્ણાંક err)
{
	પસંદગી (err) {
	સ્થિતિ EAI_NODATA:
		પાછા ("no address associated with name");
	સ્થિતિ EAI_MEMORY:
		પાછા ("memory allocation failure");
	સ્થિતિ EAI_NONAME:
		પાછા ("name or service is not known");
	સ્થિતિ EAI_FAMILY:
		પાછા ("ai_family not supported");
	મૂળભૂત:
		પાછા ("unknown/invalid error");
	}
}
#endif /* !HAVE_GAI_STRERROR */

#ifndef HAVE_FREEADDRINFO
શૂન્ય
freeaddrinfo(સંરચના addrinfo *ai)
{
	સંરચના addrinfo *next;

	માટે(; ai != ખાલી;) {
		next = ai->ai_next;
		મુક્ત(ai);
		ai = next;
	}
}
#endif /* !HAVE_FREEADDRINFO */

#ifndef HAVE_GETADDRINFO
સ્થિર સંરચના
addrinfo *malloc_ai(પૂર્ણાંક port, u_long addr, અચલ સંરચના addrinfo *hints)
{
	સંરચના addrinfo *ai;

	ai = malloc(કદ(*ai) + કદ(સંરચના sockaddr_in));
	જો (ai == ખાલી)
		પાછા (ખાલી);

	memset(ai, '\0', કદ(*ai) + કદ(સંરચના sockaddr_in));

	ai->ai_addr = (સંરચના sockaddr *)(ai + 1);
	/* XXX -- ssh doesn't use sa_len */
	ai->ai_addrlen = કદ(સંરચના sockaddr_in);
	ai->ai_addr->sa_family = ai->ai_family = AF_INET;

	((સંરચના sockaddr_in *)(ai)->ai_addr)->sin_port = port;
	((સંરચના sockaddr_in *)(ai)->ai_addr)->sin_addr.s_addr = addr;

	/* XXX: the following is not generally correct, but does what we want */
	જો (hints->ai_socktype)
		ai->ai_socktype = hints->ai_socktype;
	નહીંતર
		ai->ai_socktype = SOCK_STREAM;

	જો (hints->ai_protocol)
		ai->ai_protocol = hints->ai_protocol;

	પાછા (ai);
}

પૂર્ણાંક
getaddrinfo(અચલ અક્ષર *hostname, અચલ અક્ષર *servname,
    અચલ સંરચના addrinfo *hints, સંરચના addrinfo **res)
{
	સંરચના hostent *hp;
	સંરચના servent *sp;
	સંરચના in_addr in;
	પૂર્ણાંક i;
	long પૂર્ણાંક port;
	u_long addr;

	port = 0;
	જો (hints && hints->ai_family != AF_UNSPEC &&
	    hints->ai_family != AF_INET)
		પાછા (EAI_FAMILY);
	જો (servname != ખાલી) {
		અક્ષર *cp;

		port = strtol(servname, &cp, 10);
		જો (port > 0 && port <= 65535 && *cp == '\0')
			port = htons(port);
		નહીંતર જો ((sp = getservbyname(servname, ખાલી)) != ખાલી)
			port = sp->s_port;
		નહીંતર
			port = 0;
	}

	જો (hints && hints->ai_flags & AI_PASSIVE) {
		addr = htonl(0x00000000);
		જો (hostname && inet_aton(hostname, &in) != 0)
			addr = in.s_addr;
		*res = malloc_ai(port, addr, hints);
		જો (*res == ખાલી)
			પાછા (EAI_MEMORY);
		પાછા (0);
	}

	જો (!hostname) {
		*res = malloc_ai(port, htonl(0x7f000001), hints);
		જો (*res == ખાલી)
			પાછા (EAI_MEMORY);
		પાછા (0);
	}

	જો (inet_aton(hostname, &in)) {
		*res = malloc_ai(port, in.s_addr, hints);
		જો (*res == ખાલી)
			પાછા (EAI_MEMORY);
		પાછા (0);
	}

	/* Don't try DNS if AI_NUMERICHOST is set */
	જો (hints && hints->ai_flags & AI_NUMERICHOST)
		પાછા (EAI_NONAME);

	hp = gethostbyname(hostname);
	જો (hp && hp->h_name && hp->h_name[0] && hp->h_addr_list[0]) {
		સંરચના addrinfo *cur, *prev;

		cur = prev = *res = ખાલી;
		માટે (i = 0; hp->h_addr_list[i]; i++) {
			સંરચના in_addr *in = (સંરચના in_addr *)hp->h_addr_list[i];

			cur = malloc_ai(port, in->s_addr, hints);
			જો (cur == ખાલી) {
				જો (*res != ખાલી)
					freeaddrinfo(*res);
				પાછા (EAI_MEMORY);
			}
			જો (prev)
				prev->ai_next = cur;
			નહીંતર
				*res = cur;

			prev = cur;
		}
		પાછા (0);
	}

	પાછા (EAI_NODATA);
}
#endif /* !HAVE_GETADDRINFO */
