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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>

#ଅନ୍ତର୍ଭାଵ <netinet/in.h>
#ଅନ୍ତର୍ଭାଵ <arpa/inet.h>

#ifndef HAVE_GETNAMEINFO
ପୂର୍ଣ୍ଣସଂଖ୍ୟା getnameinfo(ଅଚଳ ସଂରଚନା sockaddr *sa, size_t salen, ଅକ୍ଷର *host,
		size_t hostlen, ଅକ୍ଷର *serv, size_t servlen, ପୂର୍ଣ୍ଣସଂଖ୍ୟା flags)
{
	ସଂରଚନା sockaddr_in *sin = (ସଂରଚନା sockaddr_in *)sa;
	ସଂରଚନା hostent *hp;
	ଅକ୍ଷର tmpserv[16];

	ଯଦି ((sa->sa_family != AF_UNSPEC && sa->sa_family != AF_INET) ||
	    salen < ଆକାର(ସଂରଚନା sockaddr_in))
		ଫେରନ୍ତୁ (EAI_FAMILY);
	ଯଦି (serv != ଖାଲି) {
		snprintf(tmpserv, ଆକାର(tmpserv), "%d", ntohs(sin->sin_port));
		ଯଦି (strlcpy(serv, tmpserv, servlen) >= servlen)
			ଫେରନ୍ତୁ (EAI_MEMORY);
	}

	ଯଦି (host != ଖାଲି) {
		ଯଦି (flags & NI_NUMERICHOST) {
			ଯଦି (strlcpy(host, inet_ntoa(sin->sin_addr),
			    hostlen) >= hostlen)
				ଫେରନ୍ତୁ (EAI_MEMORY);
			ଅନ୍ୟଥା
				ଫେରନ୍ତୁ (0);
		} ଅନ୍ୟଥା {
			hp = gethostbyaddr((ଅକ୍ଷର *)&sin->sin_addr,
			    ଆକାର(ସଂରଚନା in_addr), AF_INET);
			ଯଦି (hp == ଖାଲି)
				ଫେରନ୍ତୁ (EAI_NODATA);

			ଯଦି (strlcpy(host, hp->h_name, hostlen) >= hostlen)
				ଫେରନ୍ତୁ (EAI_MEMORY);
			ଅନ୍ୟଥା
				ଫେରନ୍ତୁ (0);
		}
	}
	ଫେରନ୍ତୁ (0);
}
#endif /* !HAVE_GETNAMEINFO */

#ifndef HAVE_GAI_STRERROR
#ifdef HAVE_CONST_GAI_STRERROR_PROTO
ଅଚଳ ଅକ୍ଷର *
#ଅନ୍ୟଥା
ଅକ୍ଷର *
#endif
gai_strerror(ପୂର୍ଣ୍ଣସଂଖ୍ୟା err)
{
	ବାଛ (err) {
	ସ୍ଥିତି EAI_NODATA:
		ଫେରନ୍ତୁ ("no address associated with name");
	ସ୍ଥିତି EAI_MEMORY:
		ଫେରନ୍ତୁ ("memory allocation failure");
	ସ୍ଥିତି EAI_NONAME:
		ଫେରନ୍ତୁ ("name or service is not known");
	ସ୍ଥିତି EAI_FAMILY:
		ଫେରନ୍ତୁ ("ai_family not supported");
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		ଫେରନ୍ତୁ ("unknown/invalid error");
	}
}
#endif /* !HAVE_GAI_STRERROR */

#ifndef HAVE_FREEADDRINFO
ଶୂନ୍ୟ
freeaddrinfo(ସଂରଚନା addrinfo *ai)
{
	ସଂରଚନା addrinfo *next;

	ପାଇଁ(; ai != ଖାଲି;) {
		next = ai->ai_next;
		ମୁକ୍ତ(ai);
		ai = next;
	}
}
#endif /* !HAVE_FREEADDRINFO */

#ifndef HAVE_GETADDRINFO
ସ୍ଥିର ସଂରଚନା
addrinfo *malloc_ai(ପୂର୍ଣ୍ଣସଂଖ୍ୟା port, u_long addr, ଅଚଳ ସଂରଚନା addrinfo *hints)
{
	ସଂରଚନା addrinfo *ai;

	ai = malloc(ଆକାର(*ai) + ଆକାର(ସଂରଚନା sockaddr_in));
	ଯଦି (ai == ଖାଲି)
		ଫେରନ୍ତୁ (ଖାଲି);

	memset(ai, '\0', ଆକାର(*ai) + ଆକାର(ସଂରଚନା sockaddr_in));

	ai->ai_addr = (ସଂରଚନା sockaddr *)(ai + 1);
	/* XXX -- ssh doesn't use sa_len */
	ai->ai_addrlen = ଆକାର(ସଂରଚନା sockaddr_in);
	ai->ai_addr->sa_family = ai->ai_family = AF_INET;

	((ସଂରଚନା sockaddr_in *)(ai)->ai_addr)->sin_port = port;
	((ସଂରଚନା sockaddr_in *)(ai)->ai_addr)->sin_addr.s_addr = addr;

	/* XXX: the following is not generally correct, but does what we want */
	ଯଦି (hints->ai_socktype)
		ai->ai_socktype = hints->ai_socktype;
	ଅନ୍ୟଥା
		ai->ai_socktype = SOCK_STREAM;

	ଯଦି (hints->ai_protocol)
		ai->ai_protocol = hints->ai_protocol;

	ଫେରନ୍ତୁ (ai);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
getaddrinfo(ଅଚଳ ଅକ୍ଷର *hostname, ଅଚଳ ଅକ୍ଷର *servname,
    ଅଚଳ ସଂରଚନା addrinfo *hints, ସଂରଚନା addrinfo **res)
{
	ସଂରଚନା hostent *hp;
	ସଂରଚନା servent *sp;
	ସଂରଚନା in_addr in;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;
	long ପୂର୍ଣ୍ଣସଂଖ୍ୟା port;
	u_long addr;

	port = 0;
	ଯଦି (hints && hints->ai_family != AF_UNSPEC &&
	    hints->ai_family != AF_INET)
		ଫେରନ୍ତୁ (EAI_FAMILY);
	ଯଦି (servname != ଖାଲି) {
		ଅକ୍ଷର *cp;

		port = strtol(servname, &cp, 10);
		ଯଦି (port > 0 && port <= 65535 && *cp == '\0')
			port = htons(port);
		ଅନ୍ୟଥା ଯଦି ((sp = getservbyname(servname, ଖାଲି)) != ଖାଲି)
			port = sp->s_port;
		ଅନ୍ୟଥା
			port = 0;
	}

	ଯଦି (hints && hints->ai_flags & AI_PASSIVE) {
		addr = htonl(0x00000000);
		ଯଦି (hostname && inet_aton(hostname, &in) != 0)
			addr = in.s_addr;
		*res = malloc_ai(port, addr, hints);
		ଯଦି (*res == ଖାଲି)
			ଫେରନ୍ତୁ (EAI_MEMORY);
		ଫେରନ୍ତୁ (0);
	}

	ଯଦି (!hostname) {
		*res = malloc_ai(port, htonl(0x7f000001), hints);
		ଯଦି (*res == ଖାଲି)
			ଫେରନ୍ତୁ (EAI_MEMORY);
		ଫେରନ୍ତୁ (0);
	}

	ଯଦି (inet_aton(hostname, &in)) {
		*res = malloc_ai(port, in.s_addr, hints);
		ଯଦି (*res == ଖାଲି)
			ଫେରନ୍ତୁ (EAI_MEMORY);
		ଫେରନ୍ତୁ (0);
	}

	/* Don't try DNS if AI_NUMERICHOST is set */
	ଯଦି (hints && hints->ai_flags & AI_NUMERICHOST)
		ଫେରନ୍ତୁ (EAI_NONAME);

	hp = gethostbyname(hostname);
	ଯଦି (hp && hp->h_name && hp->h_name[0] && hp->h_addr_list[0]) {
		ସଂରଚନା addrinfo *cur, *prev;

		cur = prev = *res = ଖାଲି;
		ପାଇଁ (i = 0; hp->h_addr_list[i]; i++) {
			ସଂରଚନା in_addr *in = (ସଂରଚନା in_addr *)hp->h_addr_list[i];

			cur = malloc_ai(port, in->s_addr, hints);
			ଯଦି (cur == ଖାଲି) {
				ଯଦି (*res != ଖାଲି)
					freeaddrinfo(*res);
				ଫେରନ୍ତୁ (EAI_MEMORY);
			}
			ଯଦି (prev)
				prev->ai_next = cur;
			ଅନ୍ୟଥା
				*res = cur;

			prev = cur;
		}
		ଫେରନ୍ତୁ (0);
	}

	ଫେରନ୍ତୁ (EAI_NODATA);
}
#endif /* !HAVE_GETADDRINFO */
