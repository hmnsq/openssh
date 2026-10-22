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

#నిర్వచితం_కాకపోతే _FAKE_RFC2553_H
#నిర్వచించు _FAKE_RFC2553_H

#అన్తర్భావ "includes.h"
#అన్తర్భావ <sys/types.h>
#ఒకవేళ defined(HAVE_NETDB_H)
# include <netdb.h>
#అయితే_ముగింపు

/*
 * First, socket and INET6 related definitions
 */
#నిర్వచితం_కాకపోతే HAVE_STRUCT_SOCKADDR_STORAGE
# define	_SS_MAXSIZE	128	/* Implementation specific max size */
# define       _SS_PADSIZE     (_SS_MAXSIZE - పరిమాణం (నిర్మాణం sockaddr))
నిర్మాణం sockaddr_storage {
	నిర్మాణం sockaddr	ss_sa;
	అక్షరం		__ss_pad2[_SS_PADSIZE];
};
# define ss_family ss_sa.sa_family
#అయితే_ముగింపు /* !HAVE_STRUCT_SOCKADDR_STORAGE */

#నిర్వచితం_కాకపోతే IN6_IS_ADDR_LOOPBACK
# define IN6_IS_ADDR_LOOPBACK(a) \
	(((u_int32_t *)(a))[0] == 0 && ((u_int32_t *)(a))[1] == 0 && \
	 ((u_int32_t *)(a))[2] == 0 && ((u_int32_t *)(a))[3] == htonl(1))
#అయితే_ముగింపు /* !IN6_IS_ADDR_LOOPBACK */

#నిర్వచితం_కాకపోతే HAVE_STRUCT_IN6_ADDR
నిర్మాణం in6_addr {
	u_int8_t	s6_addr[16];
};
#అయితే_ముగింపు /* !HAVE_STRUCT_IN6_ADDR */

#నిర్వచితం_కాకపోతే HAVE_STRUCT_SOCKADDR_IN6
నిర్మాణం sockaddr_in6 {
	గుర్తులేని పొట్టి	sin6_family;
	u_int16_t	sin6_port;
	u_int32_t	sin6_flowinfo;
	నిర్మాణం in6_addr	sin6_addr;
	u_int32_t	sin6_scope_id;
};
#అయితే_ముగింపు /* !HAVE_STRUCT_SOCKADDR_IN6 */

#నిర్వచితం_కాకపోతే AF_INET6
/* Define it to something that should never appear */
#నిర్వచించు AF_INET6 AF_MAX
#అయితే_ముగింపు

/*
 * Next, RFC2553 name / address resolution API
 */

#నిర్వచితం_కాకపోతే NI_NUMERICHOST
# define NI_NUMERICHOST    (1)
#అయితే_ముగింపు
#నిర్వచితం_కాకపోతే NI_NAMEREQD
# define NI_NAMEREQD       (1<<1)
#అయితే_ముగింపు
#నిర్వచితం_కాకపోతే NI_NUMERICSERV
# define NI_NUMERICSERV    (1<<2)
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే AI_PASSIVE
# define AI_PASSIVE		(1)
#అయితే_ముగింపు
#నిర్వచితం_కాకపోతే AI_CANONNAME
# define AI_CANONNAME		(1<<1)
#అయితే_ముగింపు
#నిర్వచితం_కాకపోతే AI_NUMERICHOST
# define AI_NUMERICHOST		(1<<2)
#అయితే_ముగింపు
#నిర్వచితం_కాకపోతే AI_NUMERICSERV
# define AI_NUMERICSERV		(1<<3)
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే NI_MAXSERV
# define NI_MAXSERV 32
#అయితే_ముగింపు /* !NI_MAXSERV */
#నిర్వచితం_కాకపోతే NI_MAXHOST
# define NI_MAXHOST 1025
#అయితే_ముగింపు /* !NI_MAXHOST */

#నిర్వచితం_కాకపోతే EAI_NODATA
# define EAI_NODATA	(గరిష్ఠ_పూర్ణాంకం - 1)
#అయితే_ముగింపు
#నిర్వచితం_కాకపోతే EAI_MEMORY
# define EAI_MEMORY	(గరిష్ఠ_పూర్ణాంకం - 2)
#అయితే_ముగింపు
#నిర్వచితం_కాకపోతే EAI_NONAME
# define EAI_NONAME	(గరిష్ఠ_పూర్ణాంకం - 3)
#అయితే_ముగింపు
#నిర్వచితం_కాకపోతే EAI_SYSTEM
# define EAI_SYSTEM	(గరిష్ఠ_పూర్ణాంకం - 4)
#అయితే_ముగింపు
#నిర్వచితం_కాకపోతే EAI_FAMILY
# define EAI_FAMILY	(గరిష్ఠ_పూర్ణాంకం - 5)
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_STRUCT_ADDRINFO
నిర్మాణం addrinfo {
	పూర్ణాంకం	ai_flags;	/* AI_PASSIVE, AI_CANONNAME */
	పూర్ణాంకం	ai_family;	/* PF_xxx */
	పూర్ణాంకం	ai_socktype;	/* SOCK_xxx */
	పూర్ణాంకం	ai_protocol;	/* 0 or IPPROTO_xxx for IPv4 and IPv6 */
	కొలత_t	ai_addrlen;	/* length of ai_addr */
	అక్షరం	*ai_canonname;	/* canonical name for hostname */
	నిర్మాణం sockaddr *ai_addr;	/* binary address */
	నిర్మాణం addrinfo *ai_next;	/* next structure in linked list */
};
#అయితే_ముగింపు /* !HAVE_STRUCT_ADDRINFO */

#నిర్వచితం_కాకపోతే HAVE_GETADDRINFO
#నిర్వచితమైతే getaddrinfo
# undef getaddrinfo
#అయితే_ముగింపు
#నిర్వచించు getaddrinfo(a,b,c,d)	(ssh_getaddrinfo(a,b,c,d))
పూర్ణాంకం getaddrinfo(స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *,
    స్థిరరాశి నిర్మాణం addrinfo *, నిర్మాణం addrinfo **);
#అయితే_ముగింపు /* !HAVE_GETADDRINFO */

#ఒకవేళ !defined(HAVE_GAI_STRERROR) && !defined(HAVE_CONST_GAI_STRERROR_PROTO)
#నిర్వచించు gai_strerror(a)		(_ssh_compat_gai_strerror(a))
అక్షరం *gai_strerror(పూర్ణాంకం);
#అయితే_ముగింపు /* !HAVE_GAI_STRERROR */

#నిర్వచితం_కాకపోతే HAVE_FREEADDRINFO
#నిర్వచించు freeaddrinfo(a)		(ssh_freeaddrinfo(a))
శూన్య freeaddrinfo(నిర్మాణం addrinfo *);
#అయితే_ముగింపు /* !HAVE_FREEADDRINFO */

#నిర్వచితం_కాకపోతే HAVE_GETNAMEINFO
#నిర్వచించు getnameinfo(a,b,c,d,e,f,g) (ssh_getnameinfo(a,b,c,d,e,f,g))
పూర్ణాంకం getnameinfo(స్థిరరాశి నిర్మాణం sockaddr *, కొలత_t, అక్షరం *, కొలత_t,
    అక్షరం *, కొలత_t, పూర్ణాంకం);
#అయితే_ముగింపు /* !HAVE_GETNAMEINFO */

#అయితే_ముగింపు /* !_FAKE_RFC2553_H */

