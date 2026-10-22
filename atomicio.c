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

#ضمن "includes.h"

#ضمن <sys/uio.h>

#ضمن <errno.h>
#ضمن <poll.h>
#ضمن <string.h>
#ضمن <unistd.h>
#ضمن <limits.h>

#ضمن "atomicio.h"

/*
 * ensure all of data on socket comes through. f==read || f==vwrite
 */
size_t
atomicio6(ssize_t (*f) (صحيح, فراغ *, size_t), صحيح fd, فراغ *_s, size_t n,
    صحيح (*cb)(فراغ *, size_t), فراغ *cb_arg)
{
	حرف *s = _s;
	size_t pos = 0;
	ssize_t res;
	بنية pollfd pfd;

	pfd.fd = fd;
	pfd.events = f == اقرأ ? POLLIN : POLLOUT;
	بينما (n > pos) {
		res = (f) (fd, s + pos, n - pos);
		بدل (res) {
		حالة -1:
			إذا (errno == EINTR) {
				/* possible SIGALARM, update callback */
				إذا (cb != عدم && cb(cb_arg, 0) == -1) {
					errno = EINTR;
					إرجاع pos;
				}
				استمر;
			} وإلا إذا (errno == EAGAIN || errno == EWOULDBLOCK) {
				(فراغ)poll(&pfd, 1, -1);
				استمر;
			}
			إرجاع 0;
		حالة 0:
			errno = EPIPE;
			إرجاع pos;
		افتراضي:
			pos += (size_t)res;
			إذا (cb != عدم && cb(cb_arg, (size_t)res) == -1) {
				errno = EINTR;
				إرجاع pos;
			}
		}
	}
	إرجاع pos;
}

size_t
atomicio(ssize_t (*f) (صحيح, فراغ *, size_t), صحيح fd, فراغ *_s, size_t n)
{
	إرجاع atomicio6(f, fd, _s, n, عدم, عدم);
}

/*
 * ensure all of data on socket comes through. f==readv || f==writev
 */
size_t
atomiciov6(ssize_t (*f) (صحيح, ثابت بنية iovec *, صحيح), صحيح fd,
    ثابت بنية iovec *_iov, صحيح iovcnt,
    صحيح (*cb)(فراغ *, size_t), فراغ *cb_arg)
{
	size_t pos = 0, rem;
	ssize_t res;
	بنية iovec iov_array[IOV_MAX], *iov = iov_array;
	بنية pollfd pfd;

	إذا (iovcnt < 0 || iovcnt > IOV_MAX) {
		errno = EINVAL;
		إرجاع 0;
	}
	/* Make a copy of the iov array because we may modify it below */
	memcpy(iov, _iov, (size_t)iovcnt * حجم(*_iov));

	pfd.fd = fd;
#ifndef BROKEN_READV_COMPARISON
	pfd.events = f == readv ? POLLIN : POLLOUT;
#وإلا
	pfd.events = POLLIN|POLLOUT;
#endif
	لكل (; iovcnt > 0 && iov[0].iov_len > 0;) {
		res = (f) (fd, iov, iovcnt);
		بدل (res) {
		حالة -1:
			إذا (errno == EINTR) {
				/* possible SIGALARM, update callback */
				إذا (cb != عدم && cb(cb_arg, 0) == -1) {
					errno = EINTR;
					إرجاع pos;
				}
				استمر;
			} وإلا إذا (errno == EAGAIN || errno == EWOULDBLOCK) {
				(فراغ)poll(&pfd, 1, -1);
				استمر;
			}
			إرجاع 0;
		حالة 0:
			errno = EPIPE;
			إرجاع pos;
		افتراضي:
			rem = (size_t)res;
			pos += rem;
			/* skip completed iov entries */
			بينما (iovcnt > 0 && rem >= iov[0].iov_len) {
				rem -= iov[0].iov_len;
				iov++;
				iovcnt--;
			}
			/* This shouldn't happen... */
			إذا (rem > 0 && (iovcnt <= 0 || rem > iov[0].iov_len)) {
				errno = EFAULT;
				إرجاع 0;
			}
			إذا (iovcnt == 0)
				اكسر;
			/* update pointer in partially complete iov */
			iov[0].iov_base = ((حرف *)iov[0].iov_base) + rem;
			iov[0].iov_len -= rem;
		}
		إذا (cb != عدم && cb(cb_arg, (size_t)res) == -1) {
			errno = EINTR;
			إرجاع pos;
		}
	}
	إرجاع pos;
}

size_t
atomiciov(ssize_t (*f) (صحيح, ثابت بنية iovec *, صحيح), صحيح fd,
    ثابت بنية iovec *_iov, صحيح iovcnt)
{
	إرجاع atomiciov6(f, fd, _iov, iovcnt, عدم, عدم);
}
