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

#که_نه_تعریف_شوی	_COMPAT_POLL_H_
#تعریف_کړه	_COMPAT_POLL_H_

#ضمن <sys/types.h>
#ضمن <poll.h>

#که_نه_تعریف_شوی HAVE_STRUCT_POLLFD_FD
تعريفنوع بنية pollfd {
	صحيح	fd;
	لنډ	events;
	لنډ	revents;
} pollfd_t;

#که_نه_تعریف_شوی POLLIN
# define POLLIN		0x0001
#د_که_پای
#که_نه_تعریف_شوی POLLPRI
# define POLLPRI	0x0002
#د_که_پای
#که_نه_تعریف_شوی POLLOUT
# define POLLOUT	0x0004
#د_که_پای
#که_نه_تعریف_شوی POLLERR
# define POLLERR	0x0008
#د_که_پای
#که_نه_تعریف_شوی POLLHUP
# define POLLHUP	0x0010
#د_که_پای
#که_نه_تعریف_شوی POLLNVAL
# define POLLNVAL	0x0020
#د_که_پای

#إذا 0
/* the following are currently not implemented */
#تعریف_کړه	POLLRDNORM	0x0040
#تعریف_کړه POLLNORM	POLLRDNORM
#تعریف_کړه POLLWRNORM      POLLOUT
#تعریف_کړه	POLLRDBAND	0x0080
#تعریف_کړه	POLLWRBAND	0x0100
#د_که_پای

#تعریف_کړه INFTIM		(-1)	/* not standard */
#د_که_پای /* !HAVE_STRUCT_POLLFD_FD */

#که_نه_تعریف_شوی HAVE_NFDS_T
# ifdef POLL_NFDS_T_ULONG
تعريفنوع بینښه اوږد	nfds_t;
# وإلا
تعريفنوع بینښه صحيح	nfds_t;
# endif
#د_که_پای

#که_نه_تعریف_شوی HAVE_POLL
صحيح   poll(بنية pollfd *, nfds_t, صحيح);
#د_که_پای

#که_نه_تعریف_شوی HAVE_PPOLL
صحيح   ppoll(بنية pollfd *, nfds_t, ثابت بنية timespec *, ثابت sigset_t *);
#د_که_پای

#د_که_پای /* !_COMPAT_POLL_H_ */
