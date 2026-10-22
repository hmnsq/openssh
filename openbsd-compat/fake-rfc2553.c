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

#که_نه_تعریف_شوی HAVE_GETNAMEINFO
صحيح getnameinfo(ثابت بنية sockaddr *sa, اندازه_t salen, حرف *host,
		اندازه_t hostlen, حرف *serv, اندازه_t servlen, صحيح flags)
{
	بنية sockaddr_in *ساین = (بنية sockaddr_in *)sa;
	بنية hostent *hp;
	حرف tmpserv[16];

	إذا ((sa->sa_family != AF_UNSPEC && sa->sa_family != AF_INET) ||
	    salen < حجم(بنية sockaddr_in))
		أرجع (EAI_FAMILY);
	إذا (serv != عدم) {
		snprintf(tmpserv, حجم(tmpserv), "%d", ntohs(ساین->sin_port));
		إذا (strlcpy(serv, tmpserv, servlen) >= servlen)
			أرجع (EAI_MEMORY);
	}

	إذا (host != عدم) {
		إذا (flags & NI_NUMERICHOST) {
			إذا (strlcpy(host, inet_ntoa(ساین->sin_addr),
			    hostlen) >= hostlen)
				أرجع (EAI_MEMORY);
			وإلا
				أرجع (0);
		} وإلا {
			hp = gethostbyaddr((حرف *)&ساین->sin_addr,
			    حجم(بنية in_addr), AF_INET);
			إذا (hp == عدم)
				أرجع (EAI_NODATA);

			إذا (strlcpy(host, hp->h_name, hostlen) >= hostlen)
				أرجع (EAI_MEMORY);
			وإلا
				أرجع (0);
		}
	}
	أرجع (0);
}
#د_که_پای /* !HAVE_GETNAMEINFO */

#که_نه_تعریف_شوی HAVE_GAI_STRERROR
#که_تعریف_شوی HAVE_CONST_GAI_STRERROR_PROTO
ثابت حرف *
#وإلا
حرف *
#د_که_پای
gai_strerror(صحيح err)
{
	بدل (err) {
	حالة EAI_NODATA:
		أرجع ("no address associated with name");
	حالة EAI_MEMORY:
		أرجع ("memory allocation failure");
	حالة EAI_NONAME:
		أرجع ("name or service is not known");
	حالة EAI_FAMILY:
		أرجع ("ai_family not supported");
	افتراضي:
		أرجع ("unknown/invalid error");
	}
}
#د_که_پای /* !HAVE_GAI_STRERROR */

#که_نه_تعریف_شوی HAVE_FREEADDRINFO
فراغ
freeaddrinfo(بنية addrinfo *ai)
{
	بنية addrinfo *بل;

	لكل(; ai != عدم;) {
		بل = ai->ai_next;
		حرر(ai);
		ai = بل;
	}
}
#د_که_پای /* !HAVE_FREEADDRINFO */

#که_نه_تعریف_شوی HAVE_GETADDRINFO
ساكن بنية
addrinfo *malloc_ai(صحيح پورټ, u_long addr, ثابت بنية addrinfo *hints)
{
	بنية addrinfo *ai;

	ai = حافظه_ورکړه(حجم(*ai) + حجم(بنية sockaddr_in));
	إذا (ai == عدم)
		أرجع (عدم);

	memset(ai, '\0', حجم(*ai) + حجم(بنية sockaddr_in));

	ai->ai_addr = (بنية sockaddr *)(ai + 1);
	/* XXX -- ssh doesn't use sa_len */
	ai->ai_addrlen = حجم(بنية sockaddr_in);
	ai->ai_addr->sa_family = ai->ai_family = AF_INET;

	((بنية sockaddr_in *)(ai)->ai_addr)->sin_port = پورټ;
	((بنية sockaddr_in *)(ai)->ai_addr)->sin_addr.s_addr = addr;

	/* XXX: the following is not generally correct, but does what we want */
	إذا (hints->ai_socktype)
		ai->ai_socktype = hints->ai_socktype;
	وإلا
		ai->ai_socktype = SOCK_STREAM;

	إذا (hints->ai_protocol)
		ai->ai_protocol = hints->ai_protocol;

	أرجع (ai);
}

صحيح
getaddrinfo(ثابت حرف *hostname, ثابت حرف *servname,
    ثابت بنية addrinfo *hints, بنية addrinfo **res)
{
	بنية hostent *hp;
	بنية servent *sp;
	بنية in_addr دننه;
	صحيح i;
	اوږد صحيح پورټ;
	u_long addr;

	پورټ = 0;
	إذا (hints && hints->ai_family != AF_UNSPEC &&
	    hints->ai_family != AF_INET)
		أرجع (EAI_FAMILY);
	إذا (servname != عدم) {
		حرف *cp;

		پورټ = strtol(servname, &cp, 10);
		إذا (پورټ > 0 && پورټ <= 65535 && *cp == '\0')
			پورټ = htons(پورټ);
		وإلا إذا ((sp = getservbyname(servname, عدم)) != عدم)
			پورټ = sp->s_port;
		وإلا
			پورټ = 0;
	}

	إذا (hints && hints->ai_flags & AI_PASSIVE) {
		addr = htonl(0x00000000);
		إذا (hostname && inet_aton(hostname, &دننه) != 0)
			addr = دننه.s_addr;
		*res = malloc_ai(پورټ, addr, hints);
		إذا (*res == عدم)
			أرجع (EAI_MEMORY);
		أرجع (0);
	}

	إذا (!hostname) {
		*res = malloc_ai(پورټ, htonl(0x7f000001), hints);
		إذا (*res == عدم)
			أرجع (EAI_MEMORY);
		أرجع (0);
	}

	إذا (inet_aton(hostname, &دننه)) {
		*res = malloc_ai(پورټ, دننه.s_addr, hints);
		إذا (*res == عدم)
			أرجع (EAI_MEMORY);
		أرجع (0);
	}

	/* Don't try DNS if AI_NUMERICHOST is set */
	إذا (hints && hints->ai_flags & AI_NUMERICHOST)
		أرجع (EAI_NONAME);

	hp = gethostbyname(hostname);
	إذا (hp && hp->h_name && hp->h_name[0] && hp->h_addr_list[0]) {
		بنية addrinfo *cur, *prev;

		cur = prev = *res = عدم;
		لكل (i = 0; hp->h_addr_list[i]; i++) {
			بنية in_addr *دننه = (بنية in_addr *)hp->h_addr_list[i];

			cur = malloc_ai(پورټ, دننه->s_addr, hints);
			إذا (cur == عدم) {
				إذا (*res != عدم)
					freeaddrinfo(*res);
				أرجع (EAI_MEMORY);
			}
			إذا (prev)
				prev->ai_next = cur;
			وإلا
				*res = cur;

			prev = cur;
		}
		أرجع (0);
	}

	أرجع (EAI_NODATA);
}
#د_که_پای /* !HAVE_GETADDRINFO */
