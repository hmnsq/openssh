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

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ	_COMPAT_POLL_H_
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	_COMPAT_POLL_H_

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <poll.h>

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_STRUCT_POLLFD_FD
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ pollfd {
	ਪੂਰਨ	fd;
	ਛੋਟਾ	events;
	ਛੋਟਾ	revents;
} pollfd_t;

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ POLLIN
# define POLLIN		0x0001
#ਜੇ_ਅੰਤ
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ POLLPRI
# define POLLPRI	0x0002
#ਜੇ_ਅੰਤ
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ POLLOUT
# define POLLOUT	0x0004
#ਜੇ_ਅੰਤ
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ POLLERR
# define POLLERR	0x0008
#ਜੇ_ਅੰਤ
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ POLLHUP
# define POLLHUP	0x0010
#ਜੇ_ਅੰਤ
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ POLLNVAL
# define POLLNVAL	0x0020
#ਜੇ_ਅੰਤ

#ਜੇ 0
/* the following are currently not implemented */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	POLLRDNORM	0x0040
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ POLLNORM	POLLRDNORM
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ POLLWRNORM      POLLOUT
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	POLLRDBAND	0x0080
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	POLLWRBAND	0x0100
#ਜੇ_ਅੰਤ

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ INFTIM		(-1)	/* not standard */
#ਜੇ_ਅੰਤ /* !HAVE_STRUCT_POLLFD_FD */

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_NFDS_T
# ifdef POLL_NFDS_T_ULONG
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ	nfds_t;
# ਨਹੀਂਤਾਂ
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ	nfds_t;
# endif
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_POLL
ਪੂਰਨ   poll(ਬਣਤਰ pollfd *, nfds_t, ਪੂਰਨ);
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_PPOLL
ਪੂਰਨ   ppoll(ਬਣਤਰ pollfd *, nfds_t, ਅਚਲ ਬਣਤਰ timespec *, ਅਚਲ sigset_t *);
#ਜੇ_ਅੰਤ

#ਜੇ_ਅੰਤ /* !_COMPAT_POLL_H_ */
