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

#यदि_अपरिभाषितम्	_COMPAT_POLL_H_
#परिभाषय	_COMPAT_POLL_H_

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <poll.h>

#यदि_अपरिभाषितम् HAVE_STRUCT_POLLFD_FD
प्रकारनिर्देश संरचना pollfd {
	पूर्णाङ्क	fd;
	ह्रस्व	events;
	ह्रस्व	revents;
} pollfd_t;

#यदि_अपरिभाषितम् POLLIN
# define POLLIN		0x0001
#यदि_अन्तः
#यदि_अपरिभाषितम् POLLPRI
# define POLLPRI	0x0002
#यदि_अन्तः
#यदि_अपरिभाषितम् POLLOUT
# define POLLOUT	0x0004
#यदि_अन्तः
#यदि_अपरिभाषितम् POLLERR
# define POLLERR	0x0008
#यदि_अन्तः
#यदि_अपरिभाषितम् POLLHUP
# define POLLHUP	0x0010
#यदि_अन्तः
#यदि_अपरिभाषितम् POLLNVAL
# define POLLNVAL	0x0020
#यदि_अन्तः

#यदि 0
/* the following are currently not implemented */
#परिभाषय	POLLRDNORM	0x0040
#परिभाषय POLLNORM	POLLRDNORM
#परिभाषय POLLWRNORM      POLLOUT
#परिभाषय	POLLRDBAND	0x0080
#परिभाषय	POLLWRBAND	0x0100
#यदि_अन्तः

#परिभाषय INFTIM		(-1)	/* not standard */
#यदि_अन्तः /* !HAVE_STRUCT_POLLFD_FD */

#यदि_अपरिभाषितम् HAVE_NFDS_T
# ifdef POLL_NFDS_T_ULONG
प्रकारनिर्देश अचिह्नित दीर्घ	nfds_t;
# अन्यथा
प्रकारनिर्देश अचिह्नित पूर्णाङ्क	nfds_t;
# endif
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_POLL
पूर्णाङ्क   poll(संरचना pollfd *, nfds_t, पूर्णाङ्क);
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_PPOLL
पूर्णाङ्क   ppoll(संरचना pollfd *, nfds_t, ध्रुव संरचना timespec *, ध्रुव sigset_t *);
#यदि_अन्तः

#यदि_अन्तः /* !_COMPAT_POLL_H_ */
