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

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ _FAKE_RFC2553_H
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ _FAKE_RFC2553_H

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਜੇ defined(HAVE_NETDB_H)
# include <netdb.h>
#ਜੇ_ਅੰਤ

/*
 * First, socket and INET6 related definitions
 */
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_STRUCT_SOCKADDR_STORAGE
# define	_SS_MAXSIZE	128	/* Implementation specific max size */
# define       _SS_PADSIZE     (_SS_MAXSIZE - ਆਕਾਰ (ਬਣਤਰ sockaddr))
ਬਣਤਰ sockaddr_storage {
	ਬਣਤਰ sockaddr	ss_sa;
	ਅੱਖਰ		__ss_pad2[_SS_PADSIZE];
};
# define ss_family ss_sa.sa_family
#ਜੇ_ਅੰਤ /* !HAVE_STRUCT_SOCKADDR_STORAGE */

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ IN6_IS_ADDR_LOOPBACK
# define IN6_IS_ADDR_LOOPBACK(a) \
	(((u_int32_t *)(a))[0] == 0 && ((u_int32_t *)(a))[1] == 0 && \
	 ((u_int32_t *)(a))[2] == 0 && ((u_int32_t *)(a))[3] == htonl(1))
#ਜੇ_ਅੰਤ /* !IN6_IS_ADDR_LOOPBACK */

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_STRUCT_IN6_ADDR
ਬਣਤਰ in6_addr {
	u_int8_t	s6_addr[16];
};
#ਜੇ_ਅੰਤ /* !HAVE_STRUCT_IN6_ADDR */

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_STRUCT_SOCKADDR_IN6
ਬਣਤਰ sockaddr_in6 {
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਛੋਟਾ	sin6_family;
	u_int16_t	sin6_port;
	u_int32_t	sin6_flowinfo;
	ਬਣਤਰ in6_addr	sin6_addr;
	u_int32_t	sin6_scope_id;
};
#ਜੇ_ਅੰਤ /* !HAVE_STRUCT_SOCKADDR_IN6 */

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ AF_INET6
/* Define it to something that should never appear */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ AF_INET6 AF_MAX
#ਜੇ_ਅੰਤ

/*
 * Next, RFC2553 name / address resolution API
 */

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ NI_NUMERICHOST
# define NI_NUMERICHOST    (1)
#ਜੇ_ਅੰਤ
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ NI_NAMEREQD
# define NI_NAMEREQD       (1<<1)
#ਜੇ_ਅੰਤ
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ NI_NUMERICSERV
# define NI_NUMERICSERV    (1<<2)
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ AI_PASSIVE
# define AI_PASSIVE		(1)
#ਜੇ_ਅੰਤ
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ AI_CANONNAME
# define AI_CANONNAME		(1<<1)
#ਜੇ_ਅੰਤ
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ AI_NUMERICHOST
# define AI_NUMERICHOST		(1<<2)
#ਜੇ_ਅੰਤ
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ AI_NUMERICSERV
# define AI_NUMERICSERV		(1<<3)
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ NI_MAXSERV
# define NI_MAXSERV 32
#ਜੇ_ਅੰਤ /* !NI_MAXSERV */
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ NI_MAXHOST
# define NI_MAXHOST 1025
#ਜੇ_ਅੰਤ /* !NI_MAXHOST */

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ EAI_NODATA
# define EAI_NODATA	(ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ - 1)
#ਜੇ_ਅੰਤ
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ EAI_MEMORY
# define EAI_MEMORY	(ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ - 2)
#ਜੇ_ਅੰਤ
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ EAI_NONAME
# define EAI_NONAME	(ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ - 3)
#ਜੇ_ਅੰਤ
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ EAI_SYSTEM
# define EAI_SYSTEM	(ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ - 4)
#ਜੇ_ਅੰਤ
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ EAI_FAMILY
# define EAI_FAMILY	(ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ - 5)
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_STRUCT_ADDRINFO
ਬਣਤਰ addrinfo {
	ਪੂਰਨ	ai_flags;	/* AI_PASSIVE, AI_CANONNAME */
	ਪੂਰਨ	ai_family;	/* PF_xxx */
	ਪੂਰਨ	ai_socktype;	/* SOCK_xxx */
	ਪੂਰਨ	ai_protocol;	/* 0 or IPPROTO_xxx for IPv4 and IPv6 */
	ਮਾਪ_t	ai_addrlen;	/* length of ai_addr */
	ਅੱਖਰ	*ai_canonname;	/* canonical name for hostname */
	ਬਣਤਰ sockaddr *ai_addr;	/* binary address */
	ਬਣਤਰ addrinfo *ai_next;	/* next structure in linked list */
};
#ਜੇ_ਅੰਤ /* !HAVE_STRUCT_ADDRINFO */

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_GETADDRINFO
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ getaddrinfo
# undef getaddrinfo
#ਜੇ_ਅੰਤ
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ getaddrinfo(a,b,c,d)	(ssh_getaddrinfo(a,b,c,d))
ਪੂਰਨ getaddrinfo(ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *,
    ਅਚਲ ਬਣਤਰ addrinfo *, ਬਣਤਰ addrinfo **);
#ਜੇ_ਅੰਤ /* !HAVE_GETADDRINFO */

#ਜੇ !defined(HAVE_GAI_STRERROR) && !defined(HAVE_CONST_GAI_STRERROR_PROTO)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ gai_strerror(a)		(_ssh_compat_gai_strerror(a))
ਅੱਖਰ *gai_strerror(ਪੂਰਨ);
#ਜੇ_ਅੰਤ /* !HAVE_GAI_STRERROR */

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_FREEADDRINFO
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ freeaddrinfo(a)		(ssh_freeaddrinfo(a))
ਖਾਲੀ freeaddrinfo(ਬਣਤਰ addrinfo *);
#ਜੇ_ਅੰਤ /* !HAVE_FREEADDRINFO */

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_GETNAMEINFO
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ getnameinfo(a,b,c,d,e,f,g) (ssh_getnameinfo(a,b,c,d,e,f,g))
ਪੂਰਨ getnameinfo(ਅਚਲ ਬਣਤਰ sockaddr *, ਮਾਪ_t, ਅੱਖਰ *, ਮਾਪ_t,
    ਅੱਖਰ *, ਮਾਪ_t, ਪੂਰਨ);
#ਜੇ_ਅੰਤ /* !HAVE_GETNAMEINFO */

#ਜੇ_ਅੰਤ /* !_FAKE_RFC2553_H */

