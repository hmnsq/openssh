/* $OpenBSD: atomicio.c,v 1.30 2019/01/24 02:42:23 dtucker Exp $ */
/*
 * Copyright (c) 2006 Damien Miller. All rights reserved.
 * Copyright (c) 2005 Anil Madhavapeddy. All rights reserved.
 * Copyright (c) 1995,1999 Theo de Raadt.  All rights reserved.
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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/uio.h>

#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <poll.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <unistd.h>
#અન્તર્ભાવ <limits.h>

#અન્તર્ભાવ "atomicio.h"

/*
 * ensure all of data on socket comes through. f==read || f==vwrite
 */
size_t
atomicio6(ssize_t (*f) (પૂર્ણાંક, શૂન્ય *, size_t), પૂર્ણાંક fd, શૂન્ય *_s, size_t n,
    પૂર્ણાંક (*cb)(શૂન્ય *, size_t), શૂન્ય *cb_arg)
{
	અક્ષર *s = _s;
	size_t pos = 0;
	ssize_t res;
	સંરચના pollfd pfd;

	pfd.fd = fd;
	pfd.events = f == પઠ ? POLLIN : POLLOUT;
	જ્યારે (n > pos) {
		res = (f) (fd, s + pos, n - pos);
		પસંદગી (res) {
		સ્થિતિ -1:
			જો (errno == EINTR) {
				/* possible SIGALARM, update callback */
				જો (cb != ખાલી && cb(cb_arg, 0) == -1) {
					errno = EINTR;
					પાછા pos;
				}
				ચાલુ;
			} નહીંતર જો (errno == EAGAIN || errno == EWOULDBLOCK) {
				(શૂન્ય)poll(&pfd, 1, -1);
				ચાલુ;
			}
			પાછા 0;
		સ્થિતિ 0:
			errno = EPIPE;
			પાછા pos;
		મૂળભૂત:
			pos += (size_t)res;
			જો (cb != ખાલી && cb(cb_arg, (size_t)res) == -1) {
				errno = EINTR;
				પાછા pos;
			}
		}
	}
	પાછા pos;
}

size_t
atomicio(ssize_t (*f) (પૂર્ણાંક, શૂન્ય *, size_t), પૂર્ણાંક fd, શૂન્ય *_s, size_t n)
{
	પાછા atomicio6(f, fd, _s, n, ખાલી, ખાલી);
}

/*
 * ensure all of data on socket comes through. f==readv || f==writev
 */
size_t
atomiciov6(ssize_t (*f) (પૂર્ણાંક, અચલ સંરચના iovec *, પૂર્ણાંક), પૂર્ણાંક fd,
    અચલ સંરચના iovec *_iov, પૂર્ણાંક iovcnt,
    પૂર્ણાંક (*cb)(શૂન્ય *, size_t), શૂન્ય *cb_arg)
{
	size_t pos = 0, rem;
	ssize_t res;
	સંરચના iovec iov_array[IOV_MAX], *iov = iov_array;
	સંરચના pollfd pfd;

	જો (iovcnt < 0 || iovcnt > IOV_MAX) {
		errno = EINVAL;
		પાછા 0;
	}
	/* Make a copy of the iov array because we may modify it below */
	memcpy(iov, _iov, (size_t)iovcnt * કદ(*_iov));

	pfd.fd = fd;
#ifndef BROKEN_READV_COMPARISON
	pfd.events = f == readv ? POLLIN : POLLOUT;
#નહીંતર
	pfd.events = POLLIN|POLLOUT;
#endif
	માટે (; iovcnt > 0 && iov[0].iov_len > 0;) {
		res = (f) (fd, iov, iovcnt);
		પસંદગી (res) {
		સ્થિતિ -1:
			જો (errno == EINTR) {
				/* possible SIGALARM, update callback */
				જો (cb != ખાલી && cb(cb_arg, 0) == -1) {
					errno = EINTR;
					પાછા pos;
				}
				ચાલુ;
			} નહીંતર જો (errno == EAGAIN || errno == EWOULDBLOCK) {
				(શૂન્ય)poll(&pfd, 1, -1);
				ચાલુ;
			}
			પાછા 0;
		સ્થિતિ 0:
			errno = EPIPE;
			પાછા pos;
		મૂળભૂત:
			rem = (size_t)res;
			pos += rem;
			/* skip completed iov entries */
			જ્યારે (iovcnt > 0 && rem >= iov[0].iov_len) {
				rem -= iov[0].iov_len;
				iov++;
				iovcnt--;
			}
			/* This shouldn't happen... */
			જો (rem > 0 && (iovcnt <= 0 || rem > iov[0].iov_len)) {
				errno = EFAULT;
				પાછા 0;
			}
			જો (iovcnt == 0)
				તોડો;
			/* update pointer in partially complete iov */
			iov[0].iov_base = ((અક્ષર *)iov[0].iov_base) + rem;
			iov[0].iov_len -= rem;
		}
		જો (cb != ખાલી && cb(cb_arg, (size_t)res) == -1) {
			errno = EINTR;
			પાછા pos;
		}
	}
	પાછા pos;
}

size_t
atomiciov(ssize_t (*f) (પૂર્ણાંક, અચલ સંરચના iovec *, પૂર્ણાંક), પૂર્ણાંક fd,
    અચલ સંરચના iovec *_iov, પૂર્ણાંક iovcnt)
{
	પાછા atomiciov6(f, fd, _iov, iovcnt, ખાલી, ખાલી);
}
