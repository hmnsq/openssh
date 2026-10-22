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

#جيڪڏهن_وصف_نه_ٿيل	_COMPAT_POLL_H_
#وصف_ڪريو	_COMPAT_POLL_H_

#ضمن <sys/types.h>
#ضمن <poll.h>

#جيڪڏهن_وصف_نه_ٿيل HAVE_STRUCT_POLLFD_FD
تعريفنوع بنية pollfd {
	صحيح	fd;
	ننڍو	events;
	ننڍو	revents;
} pollfd_t;

#جيڪڏهن_وصف_نه_ٿيل POLLIN
# define POLLIN		0x0001
#جيڪڏهن_پورو
#جيڪڏهن_وصف_نه_ٿيل POLLPRI
# define POLLPRI	0x0002
#جيڪڏهن_پورو
#جيڪڏهن_وصف_نه_ٿيل POLLOUT
# define POLLOUT	0x0004
#جيڪڏهن_پورو
#جيڪڏهن_وصف_نه_ٿيل POLLERR
# define POLLERR	0x0008
#جيڪڏهن_پورو
#جيڪڏهن_وصف_نه_ٿيل POLLHUP
# define POLLHUP	0x0010
#جيڪڏهن_پورو
#جيڪڏهن_وصف_نه_ٿيل POLLNVAL
# define POLLNVAL	0x0020
#جيڪڏهن_پورو

#إذا 0
/* the following are currently not implemented */
#وصف_ڪريو	POLLRDNORM	0x0040
#وصف_ڪريو POLLNORM	POLLRDNORM
#وصف_ڪريو POLLWRNORM      POLLOUT
#وصف_ڪريو	POLLRDBAND	0x0080
#وصف_ڪريو	POLLWRBAND	0x0100
#جيڪڏهن_پورو

#وصف_ڪريو INFTIM		(-1)	/* not standard */
#جيڪڏهن_پورو /* !HAVE_STRUCT_POLLFD_FD */

#جيڪڏهن_وصف_نه_ٿيل HAVE_NFDS_T
# ifdef POLL_NFDS_T_ULONG
تعريفنوع بنانشان ڊگهو	nfds_t;
# وإلا
تعريفنوع بنانشان صحيح	nfds_t;
# endif
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_POLL
صحيح   poll(بنية pollfd *, nfds_t, صحيح);
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_PPOLL
صحيح   ppoll(بنية pollfd *, nfds_t, ثابت بنية timespec *, ثابت sigset_t *);
#جيڪڏهن_پورو

#جيڪڏهن_پورو /* !_COMPAT_POLL_H_ */
