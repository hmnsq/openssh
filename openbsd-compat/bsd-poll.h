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

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <poll.h>

#ifndef HAVE_STRUCT_POLLFD_FD
প্রকারনির্দেশ সংরচনা pollfd {
	পূর্ণাঙ্ক	fd;
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

#যদি 0
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
প্রকারনির্দেশ unsigned long	nfds_t;
# অন্যথা
প্রকারনির্দেশ unsigned পূর্ণাঙ্ক	nfds_t;
# endif
#endif

#ifndef HAVE_POLL
পূর্ণাঙ্ক   poll(সংরচনা pollfd *, nfds_t, পূর্ণাঙ্ক);
#endif

#ifndef HAVE_PPOLL
পূর্ণাঙ্ক   ppoll(সংরচনা pollfd *, nfds_t, ধ্রুব সংরচনা timespec *, ধ্রুব sigset_t *);
#endif

#endif /* !_COMPAT_POLL_H_ */
