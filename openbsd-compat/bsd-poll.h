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

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ	_COMPAT_POLL_H_
#ವ್ಯಾಖ್ಯಾನಿಸು	_COMPAT_POLL_H_

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <poll.h>

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_STRUCT_POLLFD_FD
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ pollfd {
	ಪೂರ್ಣಾಂಕ	fd;
	ಗಿಡ್ಡ	events;
	ಗಿಡ್ಡ	revents;
} pollfd_t;

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ POLLIN
# define POLLIN		0x0001
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ POLLPRI
# define POLLPRI	0x0002
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ POLLOUT
# define POLLOUT	0x0004
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ POLLERR
# define POLLERR	0x0008
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ POLLHUP
# define POLLHUP	0x0010
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ POLLNVAL
# define POLLNVAL	0x0020
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ 0
/* the following are currently not implemented */
#ವ್ಯಾಖ್ಯಾನಿಸು	POLLRDNORM	0x0040
#ವ್ಯಾಖ್ಯಾನಿಸು POLLNORM	POLLRDNORM
#ವ್ಯಾಖ್ಯಾನಿಸು POLLWRNORM      POLLOUT
#ವ್ಯಾಖ್ಯಾನಿಸು	POLLRDBAND	0x0080
#ವ್ಯಾಖ್ಯಾನಿಸು	POLLWRBAND	0x0100
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿಸು INFTIM		(-1)	/* not standard */
#ಆದರೆ_ಅಂತ್ಯ /* !HAVE_STRUCT_POLLFD_FD */

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_NFDS_T
# ifdef POLL_NFDS_T_ULONG
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ	nfds_t;
# ಇಲ್ಲದಿದ್ದರೆ
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಚಿಹ್ನೆರಹಿತ ಪೂರ್ಣಾಂಕ	nfds_t;
# endif
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_POLL
ಪೂರ್ಣಾಂಕ   poll(ರಚನೆ pollfd *, nfds_t, ಪೂರ್ಣಾಂಕ);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_PPOLL
ಪೂರ್ಣಾಂಕ   ppoll(ರಚನೆ pollfd *, nfds_t, ಸ್ಥಿರಾಂಕ ರಚನೆ timespec *, ಸ್ಥಿರಾಂಕ sigset_t *);
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ_ಅಂತ್ಯ /* !_COMPAT_POLL_H_ */
