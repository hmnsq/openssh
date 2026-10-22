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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>

#అన్తర్భావ <netinet/in.h>
#అన్తర్భావ <arpa/inet.h>

#నిర్వచితం_కాకపోతే HAVE_GETNAMEINFO
పూర్ణాంకం getnameinfo(స్థిరరాశి నిర్మాణం sockaddr *sa, కొలత_t salen, అక్షరం *host,
		కొలత_t hostlen, అక్షరం *serv, కొలత_t servlen, పూర్ణాంకం flags)
{
	నిర్మాణం sockaddr_in *జ్యా = (నిర్మాణం sockaddr_in *)sa;
	నిర్మాణం hostent *hp;
	అక్షరం tmpserv[16];

	ఒకవేళ ((sa->sa_family != AF_UNSPEC && sa->sa_family != AF_INET) ||
	    salen < పరిమాణం(నిర్మాణం sockaddr_in))
		తిరిగి (EAI_FAMILY);
	ఒకవేళ (serv != ఖాళీ) {
		snprintf(tmpserv, పరిమాణం(tmpserv), "%d", ntohs(జ్యా->sin_port));
		ఒకవేళ (strlcpy(serv, tmpserv, servlen) >= servlen)
			తిరిగి (EAI_MEMORY);
	}

	ఒకవేళ (host != ఖాళీ) {
		ఒకవేళ (flags & NI_NUMERICHOST) {
			ఒకవేళ (strlcpy(host, inet_ntoa(జ్యా->sin_addr),
			    hostlen) >= hostlen)
				తిరిగి (EAI_MEMORY);
			లేకపోతే
				తిరిగి (0);
		} లేకపోతే {
			hp = gethostbyaddr((అక్షరం *)&జ్యా->sin_addr,
			    పరిమాణం(నిర్మాణం in_addr), AF_INET);
			ఒకవేళ (hp == ఖాళీ)
				తిరిగి (EAI_NODATA);

			ఒకవేళ (strlcpy(host, hp->h_name, hostlen) >= hostlen)
				తిరిగి (EAI_MEMORY);
			లేకపోతే
				తిరిగి (0);
		}
	}
	తిరిగి (0);
}
#అయితే_ముగింపు /* !HAVE_GETNAMEINFO */

#నిర్వచితం_కాకపోతే HAVE_GAI_STRERROR
#నిర్వచితమైతే HAVE_CONST_GAI_STRERROR_PROTO
స్థిరరాశి అక్షరం *
#లేకపోతే
అక్షరం *
#అయితే_ముగింపు
gai_strerror(పూర్ణాంకం err)
{
	ఎంపిక (err) {
	స్థితి EAI_NODATA:
		తిరిగి ("no address associated with name");
	స్థితి EAI_MEMORY:
		తిరిగి ("memory allocation failure");
	స్థితి EAI_NONAME:
		తిరిగి ("name or service is not known");
	స్థితి EAI_FAMILY:
		తిరిగి ("ai_family not supported");
	అప్రమేయ:
		తిరిగి ("unknown/invalid error");
	}
}
#అయితే_ముగింపు /* !HAVE_GAI_STRERROR */

#నిర్వచితం_కాకపోతే HAVE_FREEADDRINFO
శూన్య
freeaddrinfo(నిర్మాణం addrinfo *ai)
{
	నిర్మాణం addrinfo *తదుపరి;

	కొరకు(; ai != ఖాళీ;) {
		తదుపరి = ai->ai_next;
		విడుదల(ai);
		ai = తదుపరి;
	}
}
#అయితే_ముగింపు /* !HAVE_FREEADDRINFO */

#నిర్వచితం_కాకపోతే HAVE_GETADDRINFO
స్థిర నిర్మాణం
addrinfo *malloc_ai(పూర్ణాంకం పోర్టు, u_long addr, స్థిరరాశి నిర్మాణం addrinfo *hints)
{
	నిర్మాణం addrinfo *ai;

	ai = జ్ఞాపకం_ఇవ్వు(పరిమాణం(*ai) + పరిమాణం(నిర్మాణం sockaddr_in));
	ఒకవేళ (ai == ఖాళీ)
		తిరిగి (ఖాళీ);

	memset(ai, '\0', పరిమాణం(*ai) + పరిమాణం(నిర్మాణం sockaddr_in));

	ai->ai_addr = (నిర్మాణం sockaddr *)(ai + 1);
	/* XXX -- ssh doesn't use sa_len */
	ai->ai_addrlen = పరిమాణం(నిర్మాణం sockaddr_in);
	ai->ai_addr->sa_family = ai->ai_family = AF_INET;

	((నిర్మాణం sockaddr_in *)(ai)->ai_addr)->sin_port = పోర్టు;
	((నిర్మాణం sockaddr_in *)(ai)->ai_addr)->sin_addr.s_addr = addr;

	/* XXX: the following is not generally correct, but does what we want */
	ఒకవేళ (hints->ai_socktype)
		ai->ai_socktype = hints->ai_socktype;
	లేకపోతే
		ai->ai_socktype = SOCK_STREAM;

	ఒకవేళ (hints->ai_protocol)
		ai->ai_protocol = hints->ai_protocol;

	తిరిగి (ai);
}

పూర్ణాంకం
getaddrinfo(స్థిరరాశి అక్షరం *hostname, స్థిరరాశి అక్షరం *servname,
    స్థిరరాశి నిర్మాణం addrinfo *hints, నిర్మాణం addrinfo **res)
{
	నిర్మాణం hostent *hp;
	నిర్మాణం servent *sp;
	నిర్మాణం in_addr లోపల;
	పూర్ణాంకం i;
	దీర్ఘ పూర్ణాంకం పోర్టు;
	u_long addr;

	పోర్టు = 0;
	ఒకవేళ (hints && hints->ai_family != AF_UNSPEC &&
	    hints->ai_family != AF_INET)
		తిరిగి (EAI_FAMILY);
	ఒకవేళ (servname != ఖాళీ) {
		అక్షరం *cp;

		పోర్టు = strtol(servname, &cp, 10);
		ఒకవేళ (పోర్టు > 0 && పోర్టు <= 65535 && *cp == '\0')
			పోర్టు = htons(పోర్టు);
		లేకపోతే ఒకవేళ ((sp = getservbyname(servname, ఖాళీ)) != ఖాళీ)
			పోర్టు = sp->s_port;
		లేకపోతే
			పోర్టు = 0;
	}

	ఒకవేళ (hints && hints->ai_flags & AI_PASSIVE) {
		addr = htonl(0x00000000);
		ఒకవేళ (hostname && inet_aton(hostname, &లోపల) != 0)
			addr = లోపల.s_addr;
		*res = malloc_ai(పోర్టు, addr, hints);
		ఒకవేళ (*res == ఖాళీ)
			తిరిగి (EAI_MEMORY);
		తిరిగి (0);
	}

	ఒకవేళ (!hostname) {
		*res = malloc_ai(పోర్టు, htonl(0x7f000001), hints);
		ఒకవేళ (*res == ఖాళీ)
			తిరిగి (EAI_MEMORY);
		తిరిగి (0);
	}

	ఒకవేళ (inet_aton(hostname, &లోపల)) {
		*res = malloc_ai(పోర్టు, లోపల.s_addr, hints);
		ఒకవేళ (*res == ఖాళీ)
			తిరిగి (EAI_MEMORY);
		తిరిగి (0);
	}

	/* Don't try DNS if AI_NUMERICHOST is set */
	ఒకవేళ (hints && hints->ai_flags & AI_NUMERICHOST)
		తిరిగి (EAI_NONAME);

	hp = gethostbyname(hostname);
	ఒకవేళ (hp && hp->h_name && hp->h_name[0] && hp->h_addr_list[0]) {
		నిర్మాణం addrinfo *cur, *prev;

		cur = prev = *res = ఖాళీ;
		కొరకు (i = 0; hp->h_addr_list[i]; i++) {
			నిర్మాణం in_addr *లోపల = (నిర్మాణం in_addr *)hp->h_addr_list[i];

			cur = malloc_ai(పోర్టు, లోపల->s_addr, hints);
			ఒకవేళ (cur == ఖాళీ) {
				ఒకవేళ (*res != ఖాళీ)
					freeaddrinfo(*res);
				తిరిగి (EAI_MEMORY);
			}
			ఒకవేళ (prev)
				prev->ai_next = cur;
			లేకపోతే
				*res = cur;

			prev = cur;
		}
		తిరిగి (0);
	}

	తిరిగి (EAI_NODATA);
}
#అయితే_ముగింపు /* !HAVE_GETADDRINFO */
