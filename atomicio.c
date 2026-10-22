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
ಗಾತ್ರ_t
atomicio6(ssize_t (*f) (ಪೂರ್ಣಾಂಕ, ಶೂನ್ಯ *, ಗಾತ್ರ_t), ಪೂರ್ಣಾಂಕ fd, ಶೂನ್ಯ *_s, ಗಾತ್ರ_t n,
    ಪೂರ್ಣಾಂಕ (*cb)(ಶೂನ್ಯ *, ಗಾತ್ರ_t), ಶೂನ್ಯ *cb_arg)
{
	ಅಕ್ಷರ *s = _s;
	ಗಾತ್ರ_t pos = 0;
	ssize_t res;
	ರಚನೆ pollfd pfd;

	pfd.fd = fd;
	pfd.events = f == ಪಠ ? POLLIN : POLLOUT;
	ಆಗ (n > pos) {
		res = (f) (fd, s + pos, n - pos);
		ಆಯ್ಕೆ (res) {
		ಸ್ಥಿತಿ -1:
			ಆದರೆ (errno == EINTR) {
				/* possible SIGALARM, update callback */
				ಆದರೆ (cb != ಖಾಲಿ && cb(cb_arg, 0) == -1) {
					errno = EINTR;
					ಹಿಂತಿರುಗಿ pos;
				}
				ಮುಂದುವರಿ;
			} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (errno == EAGAIN || errno == EWOULDBLOCK) {
				(ಶೂನ್ಯ)poll(&pfd, 1, -1);
				ಮುಂದುವರಿ;
			}
			ಹಿಂತಿರುಗಿ 0;
		ಸ್ಥಿತಿ 0:
			errno = EPIPE;
			ಹಿಂತಿರುಗಿ pos;
		ಪೂರ್ವನಿಯೋಜಿತ:
			pos += (ಗಾತ್ರ_t)res;
			ಆದರೆ (cb != ಖಾಲಿ && cb(cb_arg, (ಗಾತ್ರ_t)res) == -1) {
				errno = EINTR;
				ಹಿಂತಿರುಗಿ pos;
			}
		}
	}
	ಹಿಂತಿರುಗಿ pos;
}

ಗಾತ್ರ_t
atomicio(ssize_t (*f) (ಪೂರ್ಣಾಂಕ, ಶೂನ್ಯ *, ಗಾತ್ರ_t), ಪೂರ್ಣಾಂಕ fd, ಶೂನ್ಯ *_s, ಗಾತ್ರ_t n)
{
	ಹಿಂತಿರುಗಿ atomicio6(f, fd, _s, n, ಖಾಲಿ, ಖಾಲಿ);
}

/*
 * ensure all of data on socket comes through. f==readv || f==writev
 */
ಗಾತ್ರ_t
atomiciov6(ssize_t (*f) (ಪೂರ್ಣಾಂಕ, ಸ್ಥಿರಾಂಕ ರಚನೆ iovec *, ಪೂರ್ಣಾಂಕ), ಪೂರ್ಣಾಂಕ fd,
    ಸ್ಥಿರಾಂಕ ರಚನೆ iovec *_iov, ಪೂರ್ಣಾಂಕ iovcnt,
    ಪೂರ್ಣಾಂಕ (*cb)(ಶೂನ್ಯ *, ಗಾತ್ರ_t), ಶೂನ್ಯ *cb_arg)
{
	ಗಾತ್ರ_t pos = 0, rem;
	ssize_t res;
	ರಚನೆ iovec iov_array[IOV_MAX], *iov = iov_array;
	ರಚನೆ pollfd pfd;

	ಆದರೆ (iovcnt < 0 || iovcnt > IOV_MAX) {
		errno = EINVAL;
		ಹಿಂತಿರುಗಿ 0;
	}
	/* Make a copy of the iov array because we may modify it below */
	ಸ್ಮರಣೆ_ನಕಲು(iov, _iov, (ಗಾತ್ರ_t)iovcnt * ಗಾತ್ರ(*_iov));

	pfd.fd = fd;
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ BROKEN_READV_COMPARISON
	pfd.events = f == readv ? POLLIN : POLLOUT;
#ಇಲ್ಲದಿದ್ದರೆ
	pfd.events = POLLIN|POLLOUT;
#ಆದರೆ_ಅಂತ್ಯ
	ಗಾಗಿ (; iovcnt > 0 && iov[0].iov_len > 0;) {
		res = (f) (fd, iov, iovcnt);
		ಆಯ್ಕೆ (res) {
		ಸ್ಥಿತಿ -1:
			ಆದರೆ (errno == EINTR) {
				/* possible SIGALARM, update callback */
				ಆದರೆ (cb != ಖಾಲಿ && cb(cb_arg, 0) == -1) {
					errno = EINTR;
					ಹಿಂತಿರುಗಿ pos;
				}
				ಮುಂದುವರಿ;
			} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (errno == EAGAIN || errno == EWOULDBLOCK) {
				(ಶೂನ್ಯ)poll(&pfd, 1, -1);
				ಮುಂದುವರಿ;
			}
			ಹಿಂತಿರುಗಿ 0;
		ಸ್ಥಿತಿ 0:
			errno = EPIPE;
			ಹಿಂತಿರುಗಿ pos;
		ಪೂರ್ವನಿಯೋಜಿತ:
			rem = (ಗಾತ್ರ_t)res;
			pos += rem;
			/* skip completed iov entries */
			ಆಗ (iovcnt > 0 && rem >= iov[0].iov_len) {
				rem -= iov[0].iov_len;
				iov++;
				iovcnt--;
			}
			/* This shouldn't happen... */
			ಆದರೆ (rem > 0 && (iovcnt <= 0 || rem > iov[0].iov_len)) {
				errno = EFAULT;
				ಹಿಂತಿರುಗಿ 0;
			}
			ಆದರೆ (iovcnt == 0)
				ನಿಲ್ಲಿಸು;
			/* update pointer in partially complete iov */
			iov[0].iov_base = ((ಅಕ್ಷರ *)iov[0].iov_base) + rem;
			iov[0].iov_len -= rem;
		}
		ಆದರೆ (cb != ಖಾಲಿ && cb(cb_arg, (ಗಾತ್ರ_t)res) == -1) {
			errno = EINTR;
			ಹಿಂತಿರುಗಿ pos;
		}
	}
	ಹಿಂತಿರುಗಿ pos;
}

ಗಾತ್ರ_t
atomiciov(ssize_t (*f) (ಪೂರ್ಣಾಂಕ, ಸ್ಥಿರಾಂಕ ರಚನೆ iovec *, ಪೂರ್ಣಾಂಕ), ಪೂರ್ಣಾಂಕ fd,
    ಸ್ಥಿರಾಂಕ ರಚನೆ iovec *_iov, ಪೂರ್ಣಾಂಕ iovcnt)
{
	ಹಿಂತಿರುಗಿ atomiciov6(f, fd, _iov, iovcnt, ಖಾಲಿ, ಖಾಲಿ);
}
