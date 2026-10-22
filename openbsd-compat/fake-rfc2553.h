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

#अगर_अघोषित _FAKE_RFC2553_H
#घोषणा _FAKE_RFC2553_H

#समावेश "includes.h"
#समावेश <sys/types.h>
#अगर defined(HAVE_NETDB_H)
# include <netdb.h>
#पूर्ण_अगर

/*
 * First, socket and INET6 related definitions
 */
#अगर_अघोषित HAVE_STRUCT_SOCKADDR_STORAGE
# define	_SS_MAXSIZE	128	/* Implementation specific max size */
# define       _SS_PADSIZE     (_SS_MAXSIZE - माप (काष्ठा sockaddr))
काष्ठा sockaddr_storage {
	काष्ठा sockaddr	ss_sa;
	अक्षर		__ss_pad2[_SS_PADSIZE];
};
# define ss_family ss_sa.sa_family
#पूर्ण_अगर /* !HAVE_STRUCT_SOCKADDR_STORAGE */

#अगर_अघोषित IN6_IS_ADDR_LOOPBACK
# define IN6_IS_ADDR_LOOPBACK(a) \
	(((u_int32_t *)(a))[0] == 0 && ((u_int32_t *)(a))[1] == 0 && \
	 ((u_int32_t *)(a))[2] == 0 && ((u_int32_t *)(a))[3] == htonl(1))
#पूर्ण_अगर /* !IN6_IS_ADDR_LOOPBACK */

#अगर_अघोषित HAVE_STRUCT_IN6_ADDR
काष्ठा in6_addr {
	u_int8_t	s6_addr[16];
};
#पूर्ण_अगर /* !HAVE_STRUCT_IN6_ADDR */

#अगर_अघोषित HAVE_STRUCT_SOCKADDR_IN6
काष्ठा sockaddr_in6 {
	अचिन्हित लघु	sin6_family;
	u_int16_t	sin6_port;
	u_int32_t	sin6_flowinfo;
	काष्ठा in6_addr	sin6_addr;
	u_int32_t	sin6_scope_id;
};
#पूर्ण_अगर /* !HAVE_STRUCT_SOCKADDR_IN6 */

#अगर_अघोषित AF_INET6
/* Define it to something that should never appear */
#घोषणा AF_INET6 AF_MAX
#पूर्ण_अगर

/*
 * Next, RFC2553 name / address resolution API
 */

#अगर_अघोषित NI_NUMERICHOST
# define NI_NUMERICHOST    (1)
#पूर्ण_अगर
#अगर_अघोषित NI_NAMEREQD
# define NI_NAMEREQD       (1<<1)
#पूर्ण_अगर
#अगर_अघोषित NI_NUMERICSERV
# define NI_NUMERICSERV    (1<<2)
#पूर्ण_अगर

#अगर_अघोषित AI_PASSIVE
# define AI_PASSIVE		(1)
#पूर्ण_अगर
#अगर_अघोषित AI_CANONNAME
# define AI_CANONNAME		(1<<1)
#पूर्ण_अगर
#अगर_अघोषित AI_NUMERICHOST
# define AI_NUMERICHOST		(1<<2)
#पूर्ण_अगर
#अगर_अघोषित AI_NUMERICSERV
# define AI_NUMERICSERV		(1<<3)
#पूर्ण_अगर

#अगर_अघोषित NI_MAXSERV
# define NI_MAXSERV 32
#पूर्ण_अगर /* !NI_MAXSERV */
#अगर_अघोषित NI_MAXHOST
# define NI_MAXHOST 1025
#पूर्ण_अगर /* !NI_MAXHOST */

#अगर_अघोषित EAI_NODATA
# define EAI_NODATA	(पूर्णांक_उच्च - 1)
#पूर्ण_अगर
#अगर_अघोषित EAI_MEMORY
# define EAI_MEMORY	(पूर्णांक_उच्च - 2)
#पूर्ण_अगर
#अगर_अघोषित EAI_NONAME
# define EAI_NONAME	(पूर्णांक_उच्च - 3)
#पूर्ण_अगर
#अगर_अघोषित EAI_SYSTEM
# define EAI_SYSTEM	(पूर्णांक_उच्च - 4)
#पूर्ण_अगर
#अगर_अघोषित EAI_FAMILY
# define EAI_FAMILY	(पूर्णांक_उच्च - 5)
#पूर्ण_अगर

#अगर_अघोषित HAVE_STRUCT_ADDRINFO
काष्ठा addrinfo {
	पूर्णांक	ai_flags;	/* AI_PASSIVE, AI_CANONNAME */
	पूर्णांक	ai_family;	/* PF_xxx */
	पूर्णांक	ai_socktype;	/* SOCK_xxx */
	पूर्णांक	ai_protocol;	/* 0 or IPPROTO_xxx for IPv4 and IPv6 */
	माप_प्रकार	ai_addrlen;	/* length of ai_addr */
	अक्षर	*ai_canonname;	/* canonical name for hostname */
	काष्ठा sockaddr *ai_addr;	/* binary address */
	काष्ठा addrinfo *ai_next;	/* next structure in linked list */
};
#पूर्ण_अगर /* !HAVE_STRUCT_ADDRINFO */

#अगर_अघोषित HAVE_GETADDRINFO
#अगर_घोषित getaddrinfo
# undef getaddrinfo
#पूर्ण_अगर
#घोषणा getaddrinfo(a,b,c,d)	(ssh_getaddrinfo(a,b,c,d))
पूर्णांक getaddrinfo(स्थिर अक्षर *, स्थिर अक्षर *,
    स्थिर काष्ठा addrinfo *, काष्ठा addrinfo **);
#पूर्ण_अगर /* !HAVE_GETADDRINFO */

#अगर !defined(HAVE_GAI_STRERROR) && !defined(HAVE_CONST_GAI_STRERROR_PROTO)
#घोषणा gai_strerror(a)		(_ssh_compat_gai_strerror(a))
अक्षर *gai_strerror(पूर्णांक);
#पूर्ण_अगर /* !HAVE_GAI_STRERROR */

#अगर_अघोषित HAVE_FREEADDRINFO
#घोषणा freeaddrinfo(a)		(ssh_freeaddrinfo(a))
व्योम freeaddrinfo(काष्ठा addrinfo *);
#पूर्ण_अगर /* !HAVE_FREEADDRINFO */

#अगर_अघोषित HAVE_GETNAMEINFO
#घोषणा getnameinfo(a,b,c,d,e,f,g) (ssh_getnameinfo(a,b,c,d,e,f,g))
पूर्णांक getnameinfo(स्थिर काष्ठा sockaddr *, माप_प्रकार, अक्षर *, माप_प्रकार,
    अक्षर *, माप_प्रकार, पूर्णांक);
#पूर्ण_अगर /* !HAVE_GETNAMEINFO */

#पूर्ण_अगर /* !_FAKE_RFC2553_H */

