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

#అన్తర్భావ "includes.h"

#నిర్వచితం_కాకపోతే HAVE_BINDRESVPORT_SA
#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/socket.h>

#అన్తర్భావ <netinet/in.h>
#అన్తర్భావ <arpa/inet.h>

#అన్తర్భావ <errno.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>

#నిర్వచించు STARTPORT 600
#నిర్వచించు ENDPORT (IPPORT_RESERVED - 1)
#నిర్వచించు NPORTS	(ENDPORT - STARTPORT + 1)

/*
 * Bind a socket to a privileged IP port
 */
పూర్ణాంకం
bindresvport_sa(పూర్ణాంకం sd, నిర్మాణం sockaddr *sa)
{
	పూర్ణాంకం error, af;
	నిర్మాణం sockaddr_storage myaddr;
	నిర్మాణం sockaddr_in *లోపల;
	నిర్మాణం sockaddr_in6 *in6;
	u_int16_t *portp;
	u_int16_t పోర్టు;
	socklen_t salen;
	పూర్ణాంకం i;

	ఒకవేళ (sa == ఖాళీ) {
		memset(&myaddr, 0, పరిమాణం(myaddr));
		sa = (నిర్మాణం sockaddr *)&myaddr;
		salen = పరిమాణం(myaddr);

		ఒకవేళ (getsockname(sd, sa, &salen) == -1)
			తిరిగి -1;	/* errno is correctly set */

		af = sa->sa_family;
		memset(&myaddr, 0, salen);
	} లేకపోతే
		af = sa->sa_family;

	ఒకవేళ (af == AF_INET) {
		లోపల = (నిర్మాణం sockaddr_in *)sa;
		salen = పరిమాణం(నిర్మాణం sockaddr_in);
		portp = &లోపల->sin_port;
	} లేకపోతే ఒకవేళ (af == AF_INET6) {
		in6 = (నిర్మాణం sockaddr_in6 *)sa;
		salen = పరిమాణం(నిర్మాణం sockaddr_in6);
		portp = &in6->sin6_port;
	} లేకపోతే {
		errno = EPFNOSUPPORT;
		తిరిగి (-1);
	}
	sa->sa_family = af;

	పోర్టు = ntohs(*portp);
	ఒకవేళ (పోర్టు == 0)
		పోర్టు = arc4random_ఏకరీతి(NPORTS) + STARTPORT;

	/* Avoid warning */
	error = -1;

	కొరకు(i = 0; i < NPORTS; i++) {
		*portp = htons(పోర్టు);
		
		error = bind(sd, sa, salen);

		/* Terminate on success */
		ఒకవేళ (error == 0)
			ఆపు;
			
		/* Terminate on errors, except "address already in use" */
		ఒకవేళ ((error < 0) && !((errno == EADDRINUSE) || (errno == EINVAL)))
			ఆపు;
			
		పోర్టు++;
		ఒకవేళ (పోర్టు > ENDPORT)
			పోర్టు = STARTPORT;
	}

	తిరిగి (error);
}

#అయితే_ముగింపు /* HAVE_BINDRESVPORT_SA */
