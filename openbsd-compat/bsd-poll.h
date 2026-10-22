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

#اگر_غیر_تعریف_شدہ	_COMPAT_POLL_H_
#تعریف_کرو	_COMPAT_POLL_H_

#شامل <sys/types.h>
#شامل <poll.h>

#اگر_غیر_تعریف_شدہ HAVE_STRUCT_POLLFD_FD
قسمتعریف ساخت pollfd {
	صحیح	fd;
	مختصر	events;
	مختصر	revents;
} pollfd_t;

#اگر_غیر_تعریف_شدہ POLLIN
# define POLLIN		0x0001
#اگر_ختم
#اگر_غیر_تعریف_شدہ POLLPRI
# define POLLPRI	0x0002
#اگر_ختم
#اگر_غیر_تعریف_شدہ POLLOUT
# define POLLOUT	0x0004
#اگر_ختم
#اگر_غیر_تعریف_شدہ POLLERR
# define POLLERR	0x0008
#اگر_ختم
#اگر_غیر_تعریف_شدہ POLLHUP
# define POLLHUP	0x0010
#اگر_ختم
#اگر_غیر_تعریف_شدہ POLLNVAL
# define POLLNVAL	0x0020
#اگر_ختم

#اگر 0
/* the following are currently not implemented */
#تعریف_کرو	POLLRDNORM	0x0040
#تعریف_کرو POLLNORM	POLLRDNORM
#تعریف_کرو POLLWRNORM      POLLOUT
#تعریف_کرو	POLLRDBAND	0x0080
#تعریف_کرو	POLLWRBAND	0x0100
#اگر_ختم

#تعریف_کرو INFTIM		(-1)	/* not standard */
#اگر_ختم /* !HAVE_STRUCT_POLLFD_FD */

#اگر_غیر_تعریف_شدہ HAVE_NFDS_T
# ifdef POLL_NFDS_T_ULONG
قسمتعریف غیرعلامتی طویل	nfds_t;
# ورنہ
قسمتعریف غیرعلامتی صحیح	nfds_t;
# endif
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_POLL
صحیح   poll(ساخت pollfd *, nfds_t, صحیح);
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_PPOLL
صحیح   ppoll(ساخت pollfd *, nfds_t, ثابت ساخت timespec *, ثابت sigset_t *);
#اگر_ختم

#اگر_ختم /* !_COMPAT_POLL_H_ */
