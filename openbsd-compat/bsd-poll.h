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

#अगर_अघोषित	_COMPAT_POLL_H_
#घोषणा	_COMPAT_POLL_H_

#समावेश <sys/types.h>
#समावेश <poll.h>

#अगर_अघोषित HAVE_STRUCT_POLLFD_FD
प्रकार काष्ठा pollfd {
	पूर्णांक	fd;
	लघु	events;
	लघु	revents;
} pollfd_t;

#अगर_अघोषित POLLIN
# define POLLIN		0x0001
#पूर्ण_अगर
#अगर_अघोषित POLLPRI
# define POLLPRI	0x0002
#पूर्ण_अगर
#अगर_अघोषित POLLOUT
# define POLLOUT	0x0004
#पूर्ण_अगर
#अगर_अघोषित POLLERR
# define POLLERR	0x0008
#पूर्ण_अगर
#अगर_अघोषित POLLHUP
# define POLLHUP	0x0010
#पूर्ण_अगर
#अगर_अघोषित POLLNVAL
# define POLLNVAL	0x0020
#पूर्ण_अगर

#अगर 0
/* the following are currently not implemented */
#घोषणा	POLLRDNORM	0x0040
#घोषणा POLLNORM	POLLRDNORM
#घोषणा POLLWRNORM      POLLOUT
#घोषणा	POLLRDBAND	0x0080
#घोषणा	POLLWRBAND	0x0100
#पूर्ण_अगर

#घोषणा INFTIM		(-1)	/* not standard */
#पूर्ण_अगर /* !HAVE_STRUCT_POLLFD_FD */

#अगर_अघोषित HAVE_NFDS_T
# ifdef POLL_NFDS_T_ULONG
प्रकार अचिन्हित दीर्घ	nfds_t;
# अन्यथा
प्रकार अचिन्हित पूर्णांक	nfds_t;
# endif
#पूर्ण_अगर

#अगर_अघोषित HAVE_POLL
पूर्णांक   poll(काष्ठा pollfd *, nfds_t, पूर्णांक);
#पूर्ण_अगर

#अगर_अघोषित HAVE_PPOLL
पूर्णांक   ppoll(काष्ठा pollfd *, nfds_t, स्थिर काष्ठा timespec *, स्थिर sigset_t *);
#पूर्ण_अगर

#पूर्ण_अगर /* !_COMPAT_POLL_H_ */
