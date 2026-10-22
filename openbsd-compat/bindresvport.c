/* This file has be substantially modified from the original OpenBSD source */

/*	$OpenBSD: bindresvport.c,v 1.17 2005/12/21 01:40:22 millert Exp $	*/

/*
 * Copyright 1996, Jason Downs.  All rights reserved.
 * Copyright 1998, Theo de Raadt.  All rights reserved.
 * Copyright 2000, Damien Miller.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* OPENBSD ORIGINAL: lib/libc/rpc/bindresvport.c */

#شامل "includes.h"

#اگر_غیر_تعریف_شدہ HAVE_BINDRESVPORT_SA
#شامل <sys/types.h>
#شامل <sys/socket.h>

#شامل <netinet/in.h>
#شامل <arpa/inet.h>

#شامل <errno.h>
#شامل <stdlib.h>
#شامل <string.h>

#تعریف_کرو STARTPORT 600
#تعریف_کرو ENDPORT (IPPORT_RESERVED - 1)
#تعریف_کرو NPORTS	(ENDPORT - STARTPORT + 1)

/*
 * Bind a socket to a privileged IP port
 */
صحیح
bindresvport_sa(صحیح sd, ساخت sockaddr *sa)
{
	صحیح error, af;
	ساخت sockaddr_storage myaddr;
	ساخت sockaddr_in *اندر;
	ساخت sockaddr_in6 *in6;
	u_int16_t *portp;
	u_int16_t پورٹ;
	socklen_t salen;
	صحیح i;

	اگر (sa == تہی) {
		memset(&myaddr, 0, حجم(myaddr));
		sa = (ساخت sockaddr *)&myaddr;
		salen = حجم(myaddr);

		اگر (getsockname(sd, sa, &salen) == -1)
			واپس -1;	/* errno is correctly set */

		af = sa->sa_family;
		memset(&myaddr, 0, salen);
	} ورنہ
		af = sa->sa_family;

	اگر (af == AF_INET) {
		اندر = (ساخت sockaddr_in *)sa;
		salen = حجم(ساخت sockaddr_in);
		portp = &اندر->sin_port;
	} ورنہ اگر (af == AF_INET6) {
		in6 = (ساخت sockaddr_in6 *)sa;
		salen = حجم(ساخت sockaddr_in6);
		portp = &in6->sin6_port;
	} ورنہ {
		errno = EPFNOSUPPORT;
		واپس (-1);
	}
	sa->sa_family = af;

	پورٹ = ntohs(*portp);
	اگر (پورٹ == 0)
		پورٹ = arc4random_یکساں(NPORTS) + STARTPORT;

	/* Avoid warning */
	error = -1;

	برائے(i = 0; i < NPORTS; i++) {
		*portp = htons(پورٹ);
		
		error = bind(sd, sa, salen);

		/* Terminate on success */
		اگر (error == 0)
			توڑو;
			
		/* Terminate on errors, except "address already in use" */
		اگر ((error < 0) && !((errno == EADDRINUSE) || (errno == EINVAL)))
			توڑو;
			
		پورٹ++;
		اگر (پورٹ > ENDPORT)
			پورٹ = STARTPORT;
	}

	واپس (error);
}

#اگر_ختم /* HAVE_BINDRESVPORT_SA */
