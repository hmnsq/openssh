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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/uio.h>

#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <poll.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಅನ್ತರ್ಭಾವ <limits.h>

#ಅನ್ತರ್ಭಾವ "atomicio.h"

/*
 * ensure all of data on socket comes through. f==read || f==vwrite
 */
size_t
atomicio6(ssize_t (*f) (ಪೂರ್ಣಾಙ್ಕ, ಶೂನ್ಯ *, size_t), ಪೂರ್ಣಾಙ್ಕ fd, ಶೂನ್ಯ *_s, size_t n,
    ಪೂರ್ಣಾಙ್ಕ (*cb)(ಶೂನ್ಯ *, size_t), ಶೂನ್ಯ *cb_arg)
{
	ವರ್ಣ *s = _s;
	size_t pos = 0;
	ssize_t res;
	ಸಂರಚನಾ pollfd pfd;

	pfd.fd = fd;
	pfd.events = f == ಪಠ ? POLLIN : POLLOUT;
	ಯಾವತ್ (n > pos) {
		res = (f) (fd, s + pos, n - pos);
		ವಿಕಲ್ಪ (res) {
		ಪಕ್ಷ -1:
			ಯದಿ (errno == EINTR) {
				/* possible SIGALARM, update callback */
				ಯದಿ (cb != ರಿಕ್ತ && cb(cb_arg, 0) == -1) {
					errno = EINTR;
					ಪ್ರತ್ಯಾಗಮ pos;
				}
				ಅನುವರ್ತ;
			} ಅನ್ಯಥಾ ಯದಿ (errno == EAGAIN || errno == EWOULDBLOCK) {
				(ಶೂನ್ಯ)poll(&pfd, 1, -1);
				ಅನುವರ್ತ;
			}
			ಪ್ರತ್ಯಾಗಮ 0;
		ಪಕ್ಷ 0:
			errno = EPIPE;
			ಪ್ರತ್ಯಾಗಮ pos;
		ಸ್ವಭಾವ:
			pos += (size_t)res;
			ಯದಿ (cb != ರಿಕ್ತ && cb(cb_arg, (size_t)res) == -1) {
				errno = EINTR;
				ಪ್ರತ್ಯಾಗಮ pos;
			}
		}
	}
	ಪ್ರತ್ಯಾಗಮ pos;
}

size_t
atomicio(ssize_t (*f) (ಪೂರ್ಣಾಙ್ಕ, ಶೂನ್ಯ *, size_t), ಪೂರ್ಣಾಙ್ಕ fd, ಶೂನ್ಯ *_s, size_t n)
{
	ಪ್ರತ್ಯಾಗಮ atomicio6(f, fd, _s, n, ರಿಕ್ತ, ರಿಕ್ತ);
}

/*
 * ensure all of data on socket comes through. f==readv || f==writev
 */
size_t
atomiciov6(ssize_t (*f) (ಪೂರ್ಣಾಙ್ಕ, ಧ್ರುವ ಸಂರಚನಾ iovec *, ಪೂರ್ಣಾಙ್ಕ), ಪೂರ್ಣಾಙ್ಕ fd,
    ಧ್ರುವ ಸಂರಚನಾ iovec *_iov, ಪೂರ್ಣಾಙ್ಕ iovcnt,
    ಪೂರ್ಣಾಙ್ಕ (*cb)(ಶೂನ್ಯ *, size_t), ಶೂನ್ಯ *cb_arg)
{
	size_t pos = 0, rem;
	ssize_t res;
	ಸಂರಚನಾ iovec iov_array[IOV_MAX], *iov = iov_array;
	ಸಂರಚನಾ pollfd pfd;

	ಯದಿ (iovcnt < 0 || iovcnt > IOV_MAX) {
		errno = EINVAL;
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	/* Make a copy of the iov array because we may modify it below */
	memcpy(iov, _iov, (size_t)iovcnt * ಪರಿಮಾಣ(*_iov));

	pfd.fd = fd;
#ifndef BROKEN_READV_COMPARISON
	pfd.events = f == readv ? POLLIN : POLLOUT;
#ಅನ್ಯಥಾ
	pfd.events = POLLIN|POLLOUT;
#endif
	ಪ್ರತಿ (; iovcnt > 0 && iov[0].iov_len > 0;) {
		res = (f) (fd, iov, iovcnt);
		ವಿಕಲ್ಪ (res) {
		ಪಕ್ಷ -1:
			ಯದಿ (errno == EINTR) {
				/* possible SIGALARM, update callback */
				ಯದಿ (cb != ರಿಕ್ತ && cb(cb_arg, 0) == -1) {
					errno = EINTR;
					ಪ್ರತ್ಯಾಗಮ pos;
				}
				ಅನುವರ್ತ;
			} ಅನ್ಯಥಾ ಯದಿ (errno == EAGAIN || errno == EWOULDBLOCK) {
				(ಶೂನ್ಯ)poll(&pfd, 1, -1);
				ಅನುವರ್ತ;
			}
			ಪ್ರತ್ಯಾಗಮ 0;
		ಪಕ್ಷ 0:
			errno = EPIPE;
			ಪ್ರತ್ಯಾಗಮ pos;
		ಸ್ವಭಾವ:
			rem = (size_t)res;
			pos += rem;
			/* skip completed iov entries */
			ಯಾವತ್ (iovcnt > 0 && rem >= iov[0].iov_len) {
				rem -= iov[0].iov_len;
				iov++;
				iovcnt--;
			}
			/* This shouldn't happen... */
			ಯದಿ (rem > 0 && (iovcnt <= 0 || rem > iov[0].iov_len)) {
				errno = EFAULT;
				ಪ್ರತ್ಯಾಗಮ 0;
			}
			ಯದಿ (iovcnt == 0)
				ಭಙ್ಗ;
			/* update pointer in partially complete iov */
			iov[0].iov_base = ((ವರ್ಣ *)iov[0].iov_base) + rem;
			iov[0].iov_len -= rem;
		}
		ಯದಿ (cb != ರಿಕ್ತ && cb(cb_arg, (size_t)res) == -1) {
			errno = EINTR;
			ಪ್ರತ್ಯಾಗಮ pos;
		}
	}
	ಪ್ರತ್ಯಾಗಮ pos;
}

size_t
atomiciov(ssize_t (*f) (ಪೂರ್ಣಾಙ್ಕ, ಧ್ರುವ ಸಂರಚನಾ iovec *, ಪೂರ್ಣಾಙ್ಕ), ಪೂರ್ಣಾಙ್ಕ fd,
    ಧ್ರುವ ಸಂರಚನಾ iovec *_iov, ಪೂರ್ಣಾಙ್ಕ iovcnt)
{
	ಪ್ರತ್ಯಾಗಮ atomiciov6(f, fd, _iov, iovcnt, ರಿಕ್ತ, ರಿಕ್ತ);
}
