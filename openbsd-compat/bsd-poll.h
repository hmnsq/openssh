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

#اگر_تعریف_نشده	_COMPAT_POLL_H_
#تعریف_کن	_COMPAT_POLL_H_

#ضمن <sys/types.h>
#ضمن <poll.h>

#اگر_تعریف_نشده HAVE_STRUCT_POLLFD_FD
تعريفنوع بنية pollfd {
	صحيح	fd;
	کوتاه	events;
	کوتاه	revents;
} pollfd_t;

#اگر_تعریف_نشده POLLIN
# define POLLIN		0x0001
#پایان_اگر
#اگر_تعریف_نشده POLLPRI
# define POLLPRI	0x0002
#پایان_اگر
#اگر_تعریف_نشده POLLOUT
# define POLLOUT	0x0004
#پایان_اگر
#اگر_تعریف_نشده POLLERR
# define POLLERR	0x0008
#پایان_اگر
#اگر_تعریف_نشده POLLHUP
# define POLLHUP	0x0010
#پایان_اگر
#اگر_تعریف_نشده POLLNVAL
# define POLLNVAL	0x0020
#پایان_اگر

#إذا 0
/* the following are currently not implemented */
#تعریف_کن	POLLRDNORM	0x0040
#تعریف_کن POLLNORM	POLLRDNORM
#تعریف_کن POLLWRNORM      POLLOUT
#تعریف_کن	POLLRDBAND	0x0080
#تعریف_کن	POLLWRBAND	0x0100
#پایان_اگر

#تعریف_کن INFTIM		(-1)	/* not standard */
#پایان_اگر /* !HAVE_STRUCT_POLLFD_FD */

#اگر_تعریف_نشده HAVE_NFDS_T
# ifdef POLL_NFDS_T_ULONG
تعريفنوع بیعلامت دراز	nfds_t;
# وإلا
تعريفنوع بیعلامت صحيح	nfds_t;
# endif
#پایان_اگر

#اگر_تعریف_نشده HAVE_POLL
صحيح   poll(بنية pollfd *, nfds_t, صحيح);
#پایان_اگر

#اگر_تعریف_نشده HAVE_PPOLL
صحيح   ppoll(بنية pollfd *, nfds_t, ثابت بنية timespec *, ثابت sigset_t *);
#پایان_اگر

#پایان_اگر /* !_COMPAT_POLL_H_ */
