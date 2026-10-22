/*	$OpenBSD: poll.h,v 1.11 2003/12/10 23:10:08 millert Exp $ */

/*
 * Copyright (c) 1996 Theo de Raadt
 * All rights reserved.
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

/* OPENBSD ORIGINAL: sys/sys/poll.h */

#నిర్వచితం_కాకపోతే	_COMPAT_POLL_H_
#నిర్వచించు	_COMPAT_POLL_H_

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <poll.h>

#నిర్వచితం_కాకపోతే HAVE_STRUCT_POLLFD_FD
రకనిర్వచనం నిర్మాణం pollfd {
	పూర్ణాంకం	fd;
	పొట్టి	events;
	పొట్టి	revents;
} pollfd_t;

#నిర్వచితం_కాకపోతే POLLIN
# define POLLIN		0x0001
#అయితే_ముగింపు
#నిర్వచితం_కాకపోతే POLLPRI
# define POLLPRI	0x0002
#అయితే_ముగింపు
#నిర్వచితం_కాకపోతే POLLOUT
# define POLLOUT	0x0004
#అయితే_ముగింపు
#నిర్వచితం_కాకపోతే POLLERR
# define POLLERR	0x0008
#అయితే_ముగింపు
#నిర్వచితం_కాకపోతే POLLHUP
# define POLLHUP	0x0010
#అయితే_ముగింపు
#నిర్వచితం_కాకపోతే POLLNVAL
# define POLLNVAL	0x0020
#అయితే_ముగింపు

#ఒకవేళ 0
/* the following are currently not implemented */
#నిర్వచించు	POLLRDNORM	0x0040
#నిర్వచించు POLLNORM	POLLRDNORM
#నిర్వచించు POLLWRNORM      POLLOUT
#నిర్వచించు	POLLRDBAND	0x0080
#నిర్వచించు	POLLWRBAND	0x0100
#అయితే_ముగింపు

#నిర్వచించు INFTIM		(-1)	/* not standard */
#అయితే_ముగింపు /* !HAVE_STRUCT_POLLFD_FD */

#నిర్వచితం_కాకపోతే HAVE_NFDS_T
# ifdef POLL_NFDS_T_ULONG
రకనిర్వచనం గుర్తులేని దీర్ఘ	nfds_t;
# లేకపోతే
రకనిర్వచనం గుర్తులేని పూర్ణాంకం	nfds_t;
# endif
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_POLL
పూర్ణాంకం   poll(నిర్మాణం pollfd *, nfds_t, పూర్ణాంకం);
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_PPOLL
పూర్ణాంకం   ppoll(నిర్మాణం pollfd *, nfds_t, స్థిరరాశి నిర్మాణం timespec *, స్థిరరాశి sigset_t *);
#అయితే_ముగింపు

#అయితే_ముగింపు /* !_COMPAT_POLL_H_ */
