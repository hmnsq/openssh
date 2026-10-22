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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/uio.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <poll.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <limits.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "atomicio.h"

/*
 * ensure all of data on socket comes through. f==read || f==vwrite
 */
ਮਾਪ_t
atomicio6(ssize_t (*f) (ਪੂਰਨ, ਖਾਲੀ *, ਮਾਪ_t), ਪੂਰਨ fd, ਖਾਲੀ *_s, ਮਾਪ_t n,
    ਪੂਰਨ (*cb)(ਖਾਲੀ *, ਮਾਪ_t), ਖਾਲੀ *cb_arg)
{
	ਅੱਖਰ *s = _s;
	ਮਾਪ_t pos = 0;
	ssize_t res;
	ਬਣਤਰ pollfd pfd;

	pfd.fd = fd;
	pfd.events = f == ਪਠ ? POLLIN : POLLOUT;
	ਜਦੋਂ (n > pos) {
		res = (f) (fd, s + pos, n - pos);
		ਚੋਣ (res) {
		ਹਾਲਤ -1:
			ਜੇ (errno == EINTR) {
				/* possible SIGALARM, update callback */
				ਜੇ (cb != ਨਿਰਾ && cb(cb_arg, 0) == -1) {
					errno = EINTR;
					ਵਾਪਸ pos;
				}
				ਜਾਰੀ;
			} ਨਹੀਂਤਾਂ ਜੇ (errno == EAGAIN || errno == EWOULDBLOCK) {
				(ਖਾਲੀ)poll(&pfd, 1, -1);
				ਜਾਰੀ;
			}
			ਵਾਪਸ 0;
		ਹਾਲਤ 0:
			errno = EPIPE;
			ਵਾਪਸ pos;
		ਮੂਲ:
			pos += (ਮਾਪ_t)res;
			ਜੇ (cb != ਨਿਰਾ && cb(cb_arg, (ਮਾਪ_t)res) == -1) {
				errno = EINTR;
				ਵਾਪਸ pos;
			}
		}
	}
	ਵਾਪਸ pos;
}

ਮਾਪ_t
atomicio(ssize_t (*f) (ਪੂਰਨ, ਖਾਲੀ *, ਮਾਪ_t), ਪੂਰਨ fd, ਖਾਲੀ *_s, ਮਾਪ_t n)
{
	ਵਾਪਸ atomicio6(f, fd, _s, n, ਨਿਰਾ, ਨਿਰਾ);
}

/*
 * ensure all of data on socket comes through. f==readv || f==writev
 */
ਮਾਪ_t
atomiciov6(ssize_t (*f) (ਪੂਰਨ, ਅਚਲ ਬਣਤਰ iovec *, ਪੂਰਨ), ਪੂਰਨ fd,
    ਅਚਲ ਬਣਤਰ iovec *_iov, ਪੂਰਨ iovcnt,
    ਪੂਰਨ (*cb)(ਖਾਲੀ *, ਮਾਪ_t), ਖਾਲੀ *cb_arg)
{
	ਮਾਪ_t pos = 0, rem;
	ssize_t res;
	ਬਣਤਰ iovec iov_array[IOV_MAX], *iov = iov_array;
	ਬਣਤਰ pollfd pfd;

	ਜੇ (iovcnt < 0 || iovcnt > IOV_MAX) {
		errno = EINVAL;
		ਵਾਪਸ 0;
	}
	/* Make a copy of the iov array because we may modify it below */
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(iov, _iov, (ਮਾਪ_t)iovcnt * ਆਕਾਰ(*_iov));

	pfd.fd = fd;
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ BROKEN_READV_COMPARISON
	pfd.events = f == readv ? POLLIN : POLLOUT;
#ਨਹੀਂਤਾਂ
	pfd.events = POLLIN|POLLOUT;
#ਜੇ_ਅੰਤ
	ਲਈ (; iovcnt > 0 && iov[0].iov_len > 0;) {
		res = (f) (fd, iov, iovcnt);
		ਚੋਣ (res) {
		ਹਾਲਤ -1:
			ਜੇ (errno == EINTR) {
				/* possible SIGALARM, update callback */
				ਜੇ (cb != ਨਿਰਾ && cb(cb_arg, 0) == -1) {
					errno = EINTR;
					ਵਾਪਸ pos;
				}
				ਜਾਰੀ;
			} ਨਹੀਂਤਾਂ ਜੇ (errno == EAGAIN || errno == EWOULDBLOCK) {
				(ਖਾਲੀ)poll(&pfd, 1, -1);
				ਜਾਰੀ;
			}
			ਵਾਪਸ 0;
		ਹਾਲਤ 0:
			errno = EPIPE;
			ਵਾਪਸ pos;
		ਮੂਲ:
			rem = (ਮਾਪ_t)res;
			pos += rem;
			/* skip completed iov entries */
			ਜਦੋਂ (iovcnt > 0 && rem >= iov[0].iov_len) {
				rem -= iov[0].iov_len;
				iov++;
				iovcnt--;
			}
			/* This shouldn't happen... */
			ਜੇ (rem > 0 && (iovcnt <= 0 || rem > iov[0].iov_len)) {
				errno = EFAULT;
				ਵਾਪਸ 0;
			}
			ਜੇ (iovcnt == 0)
				ਰੋਕੋ;
			/* update pointer in partially complete iov */
			iov[0].iov_base = ((ਅੱਖਰ *)iov[0].iov_base) + rem;
			iov[0].iov_len -= rem;
		}
		ਜੇ (cb != ਨਿਰਾ && cb(cb_arg, (ਮਾਪ_t)res) == -1) {
			errno = EINTR;
			ਵਾਪਸ pos;
		}
	}
	ਵਾਪਸ pos;
}

ਮਾਪ_t
atomiciov(ssize_t (*f) (ਪੂਰਨ, ਅਚਲ ਬਣਤਰ iovec *, ਪੂਰਨ), ਪੂਰਨ fd,
    ਅਚਲ ਬਣਤਰ iovec *_iov, ਪੂਰਨ iovcnt)
{
	ਵਾਪਸ atomiciov6(f, fd, _iov, iovcnt, ਨਿਰਾ, ਨਿਰਾ);
}
