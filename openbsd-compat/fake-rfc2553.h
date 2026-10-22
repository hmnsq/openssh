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

#यदि_अपरिभाषितम् _FAKE_RFC2553_H
#परिभाषय _FAKE_RFC2553_H

#अन्तर्भाव "includes.h"
#अन्तर्भाव <sys/types.h>
#यदि defined(HAVE_NETDB_H)
# include <netdb.h>
#यदि_अन्तः

/*
 * First, socket and INET6 related definitions
 */
#यदि_अपरिभाषितम् HAVE_STRUCT_SOCKADDR_STORAGE
# define	_SS_MAXSIZE	128	/* Implementation specific max size */
# define       _SS_PADSIZE     (_SS_MAXSIZE - परिमाण (संरचना sockaddr))
संरचना sockaddr_storage {
	संरचना sockaddr	ss_sa;
	वर्ण		__ss_pad2[_SS_PADSIZE];
};
# define ss_family ss_sa.sa_family
#यदि_अन्तः /* !HAVE_STRUCT_SOCKADDR_STORAGE */

#यदि_अपरिभाषितम् IN6_IS_ADDR_LOOPBACK
# define IN6_IS_ADDR_LOOPBACK(a) \
	(((u_int32_t *)(a))[0] == 0 && ((u_int32_t *)(a))[1] == 0 && \
	 ((u_int32_t *)(a))[2] == 0 && ((u_int32_t *)(a))[3] == htonl(1))
#यदि_अन्तः /* !IN6_IS_ADDR_LOOPBACK */

#यदि_अपरिभाषितम् HAVE_STRUCT_IN6_ADDR
संरचना in6_addr {
	u_int8_t	s6_addr[16];
};
#यदि_अन्तः /* !HAVE_STRUCT_IN6_ADDR */

#यदि_अपरिभाषितम् HAVE_STRUCT_SOCKADDR_IN6
संरचना sockaddr_in6 {
	अचिह्नित ह्रस्व	sin6_family;
	u_int16_t	sin6_port;
	u_int32_t	sin6_flowinfo;
	संरचना in6_addr	sin6_addr;
	u_int32_t	sin6_scope_id;
};
#यदि_अन्तः /* !HAVE_STRUCT_SOCKADDR_IN6 */

#यदि_अपरिभाषितम् AF_INET6
/* Define it to something that should never appear */
#परिभाषय AF_INET6 AF_MAX
#यदि_अन्तः

/*
 * Next, RFC2553 name / address resolution API
 */

#यदि_अपरिभाषितम् NI_NUMERICHOST
# define NI_NUMERICHOST    (1)
#यदि_अन्तः
#यदि_अपरिभाषितम् NI_NAMEREQD
# define NI_NAMEREQD       (1<<1)
#यदि_अन्तः
#यदि_अपरिभाषितम् NI_NUMERICSERV
# define NI_NUMERICSERV    (1<<2)
#यदि_अन्तः

#यदि_अपरिभाषितम् AI_PASSIVE
# define AI_PASSIVE		(1)
#यदि_अन्तः
#यदि_अपरिभाषितम् AI_CANONNAME
# define AI_CANONNAME		(1<<1)
#यदि_अन्तः
#यदि_अपरिभाषितम् AI_NUMERICHOST
# define AI_NUMERICHOST		(1<<2)
#यदि_अन्तः
#यदि_अपरिभाषितम् AI_NUMERICSERV
# define AI_NUMERICSERV		(1<<3)
#यदि_अन्तः

#यदि_अपरिभाषितम् NI_MAXSERV
# define NI_MAXSERV 32
#यदि_अन्तः /* !NI_MAXSERV */
#यदि_अपरिभाषितम् NI_MAXHOST
# define NI_MAXHOST 1025
#यदि_अन्तः /* !NI_MAXHOST */

#यदि_अपरिभाषितम् EAI_NODATA
# define EAI_NODATA	(अधिकतम_पूर्णाङ्कः - 1)
#यदि_अन्तः
#यदि_अपरिभाषितम् EAI_MEMORY
# define EAI_MEMORY	(अधिकतम_पूर्णाङ्कः - 2)
#यदि_अन्तः
#यदि_अपरिभाषितम् EAI_NONAME
# define EAI_NONAME	(अधिकतम_पूर्णाङ्कः - 3)
#यदि_अन्तः
#यदि_अपरिभाषितम् EAI_SYSTEM
# define EAI_SYSTEM	(अधिकतम_पूर्णाङ्कः - 4)
#यदि_अन्तः
#यदि_अपरिभाषितम् EAI_FAMILY
# define EAI_FAMILY	(अधिकतम_पूर्णाङ्कः - 5)
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_STRUCT_ADDRINFO
संरचना addrinfo {
	पूर्णाङ्क	ai_flags;	/* AI_PASSIVE, AI_CANONNAME */
	पूर्णाङ्क	ai_family;	/* PF_xxx */
	पूर्णाङ्क	ai_socktype;	/* SOCK_xxx */
	पूर्णाङ्क	ai_protocol;	/* 0 or IPPROTO_xxx for IPv4 and IPv6 */
	आकार_t	ai_addrlen;	/* length of ai_addr */
	वर्ण	*ai_canonname;	/* canonical name for hostname */
	संरचना sockaddr *ai_addr;	/* binary address */
	संरचना addrinfo *ai_next;	/* next structure in linked list */
};
#यदि_अन्तः /* !HAVE_STRUCT_ADDRINFO */

#यदि_अपरिभाषितम् HAVE_GETADDRINFO
#यदि_परिभाषितम् getaddrinfo
# undef getaddrinfo
#यदि_अन्तः
#परिभाषय getaddrinfo(a,b,c,d)	(ssh_getaddrinfo(a,b,c,d))
पूर्णाङ्क getaddrinfo(ध्रुव वर्ण *, ध्रुव वर्ण *,
    ध्रुव संरचना addrinfo *, संरचना addrinfo **);
#यदि_अन्तः /* !HAVE_GETADDRINFO */

#यदि !defined(HAVE_GAI_STRERROR) && !defined(HAVE_CONST_GAI_STRERROR_PROTO)
#परिभाषय gai_strerror(a)		(_ssh_compat_gai_strerror(a))
वर्ण *gai_strerror(पूर्णाङ्क);
#यदि_अन्तः /* !HAVE_GAI_STRERROR */

#यदि_अपरिभाषितम् HAVE_FREEADDRINFO
#परिभाषय freeaddrinfo(a)		(ssh_freeaddrinfo(a))
शून्य freeaddrinfo(संरचना addrinfo *);
#यदि_अन्तः /* !HAVE_FREEADDRINFO */

#यदि_अपरिभाषितम् HAVE_GETNAMEINFO
#परिभाषय getnameinfo(a,b,c,d,e,f,g) (ssh_getnameinfo(a,b,c,d,e,f,g))
पूर्णाङ्क getnameinfo(ध्रुव संरचना sockaddr *, आकार_t, वर्ण *, आकार_t,
    वर्ण *, आकार_t, पूर्णाङ्क);
#यदि_अन्तः /* !HAVE_GETNAMEINFO */

#यदि_अन्तः /* !_FAKE_RFC2553_H */

