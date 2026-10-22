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

#ifndef	_COMPAT_POLL_H_
#define	_COMPAT_POLL_H_

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <poll.h>

#ifndef HAVE_STRUCT_POLLFD_FD
ପ୍ରକାରବ୍ୟାଖ୍ୟା ସଂରଚନା pollfd {
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	fd;
	short	events;
	short	revents;
} pollfd_t;

#ifndef POLLIN
# define POLLIN		0x0001
#endif
#ifndef POLLPRI
# define POLLPRI	0x0002
#endif
#ifndef POLLOUT
# define POLLOUT	0x0004
#endif
#ifndef POLLERR
# define POLLERR	0x0008
#endif
#ifndef POLLHUP
# define POLLHUP	0x0010
#endif
#ifndef POLLNVAL
# define POLLNVAL	0x0020
#endif

#ଯଦି 0
/* the following are currently not implemented */
#define	POLLRDNORM	0x0040
#define POLLNORM	POLLRDNORM
#define POLLWRNORM      POLLOUT
#define	POLLRDBAND	0x0080
#define	POLLWRBAND	0x0100
#endif

#define INFTIM		(-1)	/* not standard */
#endif /* !HAVE_STRUCT_POLLFD_FD */

#ifndef HAVE_NFDS_T
# ifdef POLL_NFDS_T_ULONG
ପ୍ରକାରବ୍ୟାଖ୍ୟା unsigned long	nfds_t;
# ଅନ୍ୟଥା
ପ୍ରକାରବ୍ୟାଖ୍ୟା unsigned ପୂର୍ଣ୍ଣସଂଖ୍ୟା	nfds_t;
# endif
#endif

#ifndef HAVE_POLL
ପୂର୍ଣ୍ଣସଂଖ୍ୟା   poll(ସଂରଚନା pollfd *, nfds_t, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
#endif

#ifndef HAVE_PPOLL
ପୂର୍ଣ୍ଣସଂଖ୍ୟା   ppoll(ସଂରଚନା pollfd *, nfds_t, ଅଚଳ ସଂରଚନା timespec *, ଅଚଳ sigset_t *);
#endif

#endif /* !_COMPAT_POLL_H_ */
