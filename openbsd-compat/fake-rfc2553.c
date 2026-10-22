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

#اگر_غیر_تعریف_شدہ HAVE_GETNAMEINFO
صحیح getnameinfo(ثابت ساخت sockaddr *sa, سائز_t salen, حرف *host,
		سائز_t hostlen, حرف *serv, سائز_t servlen, صحیح flags)
{
	ساخت sockaddr_in *جیب = (ساخت sockaddr_in *)sa;
	ساخت hostent *hp;
	حرف tmpserv[16];

	اگر ((sa->sa_family != AF_UNSPEC && sa->sa_family != AF_INET) ||
	    salen < حجم(ساخت sockaddr_in))
		واپس (EAI_FAMILY);
	اگر (serv != تہی) {
		snprintf(tmpserv, حجم(tmpserv), "%d", ntohs(جیب->sin_port));
		اگر (strlcpy(serv, tmpserv, servlen) >= servlen)
			واپس (EAI_MEMORY);
	}

	اگر (host != تہی) {
		اگر (flags & NI_NUMERICHOST) {
			اگر (strlcpy(host, inet_ntoa(جیب->sin_addr),
			    hostlen) >= hostlen)
				واپس (EAI_MEMORY);
			ورنہ
				واپس (0);
		} ورنہ {
			hp = gethostbyaddr((حرف *)&جیب->sin_addr,
			    حجم(ساخت in_addr), AF_INET);
			اگر (hp == تہی)
				واپس (EAI_NODATA);

			اگر (strlcpy(host, hp->h_name, hostlen) >= hostlen)
				واپس (EAI_MEMORY);
			ورنہ
				واپس (0);
		}
	}
	واپس (0);
}
#اگر_ختم /* !HAVE_GETNAMEINFO */

#اگر_غیر_تعریف_شدہ HAVE_GAI_STRERROR
#اگر_تعریف_شدہ HAVE_CONST_GAI_STRERROR_PROTO
ثابت حرف *
#ورنہ
حرف *
#اگر_ختم
gai_strerror(صحیح err)
{
	انتخاب (err) {
	حالت EAI_NODATA:
		واپس ("no address associated with name");
	حالت EAI_MEMORY:
		واپس ("memory allocation failure");
	حالت EAI_NONAME:
		واپس ("name or service is not known");
	حالت EAI_FAMILY:
		واپس ("ai_family not supported");
	طےشدہ:
		واپس ("unknown/invalid error");
	}
}
#اگر_ختم /* !HAVE_GAI_STRERROR */

#اگر_غیر_تعریف_شدہ HAVE_FREEADDRINFO
خالی
freeaddrinfo(ساخت addrinfo *ai)
{
	ساخت addrinfo *اگلا;

	برائے(; ai != تہی;) {
		اگلا = ai->ai_next;
		آزاد(ai);
		ai = اگلا;
	}
}
#اگر_ختم /* !HAVE_FREEADDRINFO */

#اگر_غیر_تعریف_شدہ HAVE_GETADDRINFO
ساکن ساخت
addrinfo *malloc_ai(صحیح پورٹ, u_long addr, ثابت ساخت addrinfo *hints)
{
	ساخت addrinfo *ai;

	ai = حافظہ_دو(حجم(*ai) + حجم(ساخت sockaddr_in));
	اگر (ai == تہی)
		واپس (تہی);

	memset(ai, '\0', حجم(*ai) + حجم(ساخت sockaddr_in));

	ai->ai_addr = (ساخت sockaddr *)(ai + 1);
	/* XXX -- ssh doesn't use sa_len */
	ai->ai_addrlen = حجم(ساخت sockaddr_in);
	ai->ai_addr->sa_family = ai->ai_family = AF_INET;

	((ساخت sockaddr_in *)(ai)->ai_addr)->sin_port = پورٹ;
	((ساخت sockaddr_in *)(ai)->ai_addr)->sin_addr.s_addr = addr;

	/* XXX: the following is not generally correct, but does what we want */
	اگر (hints->ai_socktype)
		ai->ai_socktype = hints->ai_socktype;
	ورنہ
		ai->ai_socktype = SOCK_STREAM;

	اگر (hints->ai_protocol)
		ai->ai_protocol = hints->ai_protocol;

	واپس (ai);
}

صحیح
getaddrinfo(ثابت حرف *hostname, ثابت حرف *servname,
    ثابت ساخت addrinfo *hints, ساخت addrinfo **res)
{
	ساخت hostent *hp;
	ساخت servent *sp;
	ساخت in_addr اندر;
	صحیح i;
	طویل صحیح پورٹ;
	u_long addr;

	پورٹ = 0;
	اگر (hints && hints->ai_family != AF_UNSPEC &&
	    hints->ai_family != AF_INET)
		واپس (EAI_FAMILY);
	اگر (servname != تہی) {
		حرف *cp;

		پورٹ = strtol(servname, &cp, 10);
		اگر (پورٹ > 0 && پورٹ <= 65535 && *cp == '\0')
			پورٹ = htons(پورٹ);
		ورنہ اگر ((sp = getservbyname(servname, تہی)) != تہی)
			پورٹ = sp->s_port;
		ورنہ
			پورٹ = 0;
	}

	اگر (hints && hints->ai_flags & AI_PASSIVE) {
		addr = htonl(0x00000000);
		اگر (hostname && inet_aton(hostname, &اندر) != 0)
			addr = اندر.s_addr;
		*res = malloc_ai(پورٹ, addr, hints);
		اگر (*res == تہی)
			واپس (EAI_MEMORY);
		واپس (0);
	}

	اگر (!hostname) {
		*res = malloc_ai(پورٹ, htonl(0x7f000001), hints);
		اگر (*res == تہی)
			واپس (EAI_MEMORY);
		واپس (0);
	}

	اگر (inet_aton(hostname, &اندر)) {
		*res = malloc_ai(پورٹ, اندر.s_addr, hints);
		اگر (*res == تہی)
			واپس (EAI_MEMORY);
		واپس (0);
	}

	/* Don't try DNS if AI_NUMERICHOST is set */
	اگر (hints && hints->ai_flags & AI_NUMERICHOST)
		واپس (EAI_NONAME);

	hp = gethostbyname(hostname);
	اگر (hp && hp->h_name && hp->h_name[0] && hp->h_addr_list[0]) {
		ساخت addrinfo *cur, *پچھلا;

		cur = پچھلا = *res = تہی;
		برائے (i = 0; hp->h_addr_list[i]; i++) {
			ساخت in_addr *اندر = (ساخت in_addr *)hp->h_addr_list[i];

			cur = malloc_ai(پورٹ, اندر->s_addr, hints);
			اگر (cur == تہی) {
				اگر (*res != تہی)
					freeaddrinfo(*res);
				واپس (EAI_MEMORY);
			}
			اگر (پچھلا)
				پچھلا->ai_next = cur;
			ورنہ
				*res = cur;

			پچھلا = cur;
		}
		واپس (0);
	}

	واپس (EAI_NODATA);
}
#اگر_ختم /* !HAVE_GETADDRINFO */
