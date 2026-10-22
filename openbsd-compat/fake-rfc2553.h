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

#جيڪڏهن_وصف_نه_ٿيل _FAKE_RFC2553_H
#وصف_ڪريو _FAKE_RFC2553_H

#ضمن "includes.h"
#ضمن <sys/types.h>
#إذا defined(HAVE_NETDB_H)
# include <netdb.h>
#جيڪڏهن_پورو

/*
 * First, socket and INET6 related definitions
 */
#جيڪڏهن_وصف_نه_ٿيل HAVE_STRUCT_SOCKADDR_STORAGE
# define	_SS_MAXSIZE	128	/* Implementation specific max size */
# define       _SS_PADSIZE     (_SS_MAXSIZE - حجم (بنية sockaddr))
بنية sockaddr_storage {
	بنية sockaddr	ss_sa;
	حرف		__ss_pad2[_SS_PADSIZE];
};
# define ss_family ss_sa.sa_family
#جيڪڏهن_پورو /* !HAVE_STRUCT_SOCKADDR_STORAGE */

#جيڪڏهن_وصف_نه_ٿيل IN6_IS_ADDR_LOOPBACK
# define IN6_IS_ADDR_LOOPBACK(a) \
	(((u_int32_t *)(a))[0] == 0 && ((u_int32_t *)(a))[1] == 0 && \
	 ((u_int32_t *)(a))[2] == 0 && ((u_int32_t *)(a))[3] == htonl(1))
#جيڪڏهن_پورو /* !IN6_IS_ADDR_LOOPBACK */

#جيڪڏهن_وصف_نه_ٿيل HAVE_STRUCT_IN6_ADDR
بنية in6_addr {
	u_int8_t	s6_addr[16];
};
#جيڪڏهن_پورو /* !HAVE_STRUCT_IN6_ADDR */

#جيڪڏهن_وصف_نه_ٿيل HAVE_STRUCT_SOCKADDR_IN6
بنية sockaddr_in6 {
	بنانشان ننڍو	sin6_family;
	u_int16_t	sin6_port;
	u_int32_t	sin6_flowinfo;
	بنية in6_addr	sin6_addr;
	u_int32_t	sin6_scope_id;
};
#جيڪڏهن_پورو /* !HAVE_STRUCT_SOCKADDR_IN6 */

#جيڪڏهن_وصف_نه_ٿيل AF_INET6
/* Define it to something that should never appear */
#وصف_ڪريو AF_INET6 AF_MAX
#جيڪڏهن_پورو

/*
 * Next, RFC2553 name / address resolution API
 */

#جيڪڏهن_وصف_نه_ٿيل NI_NUMERICHOST
# define NI_NUMERICHOST    (1)
#جيڪڏهن_پورو
#جيڪڏهن_وصف_نه_ٿيل NI_NAMEREQD
# define NI_NAMEREQD       (1<<1)
#جيڪڏهن_پورو
#جيڪڏهن_وصف_نه_ٿيل NI_NUMERICSERV
# define NI_NUMERICSERV    (1<<2)
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل AI_PASSIVE
# define AI_PASSIVE		(1)
#جيڪڏهن_پورو
#جيڪڏهن_وصف_نه_ٿيل AI_CANONNAME
# define AI_CANONNAME		(1<<1)
#جيڪڏهن_پورو
#جيڪڏهن_وصف_نه_ٿيل AI_NUMERICHOST
# define AI_NUMERICHOST		(1<<2)
#جيڪڏهن_پورو
#جيڪڏهن_وصف_نه_ٿيل AI_NUMERICSERV
# define AI_NUMERICSERV		(1<<3)
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل NI_MAXSERV
# define NI_MAXSERV 32
#جيڪڏهن_پورو /* !NI_MAXSERV */
#جيڪڏهن_وصف_نه_ٿيل NI_MAXHOST
# define NI_MAXHOST 1025
#جيڪڏهن_پورو /* !NI_MAXHOST */

#جيڪڏهن_وصف_نه_ٿيل EAI_NODATA
# define EAI_NODATA	(وڌ_کان_وڌ_عدد - 1)
#جيڪڏهن_پورو
#جيڪڏهن_وصف_نه_ٿيل EAI_MEMORY
# define EAI_MEMORY	(وڌ_کان_وڌ_عدد - 2)
#جيڪڏهن_پورو
#جيڪڏهن_وصف_نه_ٿيل EAI_NONAME
# define EAI_NONAME	(وڌ_کان_وڌ_عدد - 3)
#جيڪڏهن_پورو
#جيڪڏهن_وصف_نه_ٿيل EAI_SYSTEM
# define EAI_SYSTEM	(وڌ_کان_وڌ_عدد - 4)
#جيڪڏهن_پورو
#جيڪڏهن_وصف_نه_ٿيل EAI_FAMILY
# define EAI_FAMILY	(وڌ_کان_وڌ_عدد - 5)
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_STRUCT_ADDRINFO
بنية addrinfo {
	صحيح	ai_flags;	/* AI_PASSIVE, AI_CANONNAME */
	صحيح	ai_family;	/* PF_xxx */
	صحيح	ai_socktype;	/* SOCK_xxx */
	صحيح	ai_protocol;	/* 0 or IPPROTO_xxx for IPv4 and IPv6 */
	سائيز_t	ai_addrlen;	/* length of ai_addr */
	حرف	*ai_canonname;	/* canonical name for hostname */
	بنية sockaddr *ai_addr;	/* binary address */
	بنية addrinfo *ai_next;	/* next structure in linked list */
};
#جيڪڏهن_پورو /* !HAVE_STRUCT_ADDRINFO */

#جيڪڏهن_وصف_نه_ٿيل HAVE_GETADDRINFO
#جيڪڏهن_وصف_ٿيل getaddrinfo
# undef getaddrinfo
#جيڪڏهن_پورو
#وصف_ڪريو getaddrinfo(a,b,c,d)	(ssh_getaddrinfo(a,b,c,d))
صحيح getaddrinfo(ثابت حرف *, ثابت حرف *,
    ثابت بنية addrinfo *, بنية addrinfo **);
#جيڪڏهن_پورو /* !HAVE_GETADDRINFO */

#إذا !defined(HAVE_GAI_STRERROR) && !defined(HAVE_CONST_GAI_STRERROR_PROTO)
#وصف_ڪريو gai_strerror(a)		(_ssh_compat_gai_strerror(a))
حرف *gai_strerror(صحيح);
#جيڪڏهن_پورو /* !HAVE_GAI_STRERROR */

#جيڪڏهن_وصف_نه_ٿيل HAVE_FREEADDRINFO
#وصف_ڪريو freeaddrinfo(a)		(ssh_freeaddrinfo(a))
فراغ freeaddrinfo(بنية addrinfo *);
#جيڪڏهن_پورو /* !HAVE_FREEADDRINFO */

#جيڪڏهن_وصف_نه_ٿيل HAVE_GETNAMEINFO
#وصف_ڪريو getnameinfo(a,b,c,d,e,f,g) (ssh_getnameinfo(a,b,c,d,e,f,g))
صحيح getnameinfo(ثابت بنية sockaddr *, سائيز_t, حرف *, سائيز_t,
    حرف *, سائيز_t, صحيح);
#جيڪڏهن_پورو /* !HAVE_GETNAMEINFO */

#جيڪڏهن_پورو /* !_FAKE_RFC2553_H */

