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

#جے_بنا_تعریف	_COMPAT_POLL_H_
#تعریف_کرو	_COMPAT_POLL_H_

#ضمن <sys/types.h>
#ضمن <poll.h>

#جے_بنا_تعریف HAVE_STRUCT_POLLFD_FD
تعريفنوع بنية pollfd {
	صحيح	fd;
	چھوٹا	events;
	چھوٹا	revents;
} pollfd_t;

#جے_بنا_تعریف POLLIN
# define POLLIN		0x0001
#جے_انت
#جے_بنا_تعریف POLLPRI
# define POLLPRI	0x0002
#جے_انت
#جے_بنا_تعریف POLLOUT
# define POLLOUT	0x0004
#جے_انت
#جے_بنا_تعریف POLLERR
# define POLLERR	0x0008
#جے_انت
#جے_بنا_تعریف POLLHUP
# define POLLHUP	0x0010
#جے_انت
#جے_بنا_تعریف POLLNVAL
# define POLLNVAL	0x0020
#جے_انت

#إذا 0
/* the following are currently not implemented */
#تعریف_کرو	POLLRDNORM	0x0040
#تعریف_کرو POLLNORM	POLLRDNORM
#تعریف_کرو POLLWRNORM      POLLOUT
#تعریف_کرو	POLLRDBAND	0x0080
#تعریف_کرو	POLLWRBAND	0x0100
#جے_انت

#تعریف_کرو INFTIM		(-1)	/* not standard */
#جے_انت /* !HAVE_STRUCT_POLLFD_FD */

#جے_بنا_تعریف HAVE_NFDS_T
# ifdef POLL_NFDS_T_ULONG
تعريفنوع بنانشانی لما	nfds_t;
# وإلا
تعريفنوع بنانشانی صحيح	nfds_t;
# endif
#جے_انت

#جے_بنا_تعریف HAVE_POLL
صحيح   poll(بنية pollfd *, nfds_t, صحيح);
#جے_انت

#جے_بنا_تعریف HAVE_PPOLL
صحيح   ppoll(بنية pollfd *, nfds_t, ثابت بنية timespec *, ثابت sigset_t *);
#جے_انت

#جے_انت /* !_COMPAT_POLL_H_ */
