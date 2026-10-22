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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/uio.h>

#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <poll.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <unistd.h>
#অন্তর্ভাব <limits.h>

#অন্তর্ভাব "atomicio.h"

/*
 * ensure all of data on socket comes through. f==read || f==vwrite
 */
size_t
atomicio6(ssize_t (*f) (পূর্ণাঙ্ক, শূন্য *, size_t), পূর্ণাঙ্ক fd, শূন্য *_s, size_t n,
    পূর্ণাঙ্ক (*cb)(শূন্য *, size_t), শূন্য *cb_arg)
{
	বর্ণ *s = _s;
	size_t pos = 0;
	ssize_t res;
	সংরচনা pollfd pfd;

	pfd.fd = fd;
	pfd.events = f == পঠ ? POLLIN : POLLOUT;
	যাবত্ (n > pos) {
		res = (f) (fd, s + pos, n - pos);
		বিকল্প (res) {
		পক্ষ -1:
			যদি (errno == EINTR) {
				/* possible SIGALARM, update callback */
				যদি (cb != রিক্ত && cb(cb_arg, 0) == -1) {
					errno = EINTR;
					প্রত্যাগম pos;
				}
				অনুবর্ত;
			} অন্যথা যদি (errno == EAGAIN || errno == EWOULDBLOCK) {
				(শূন্য)poll(&pfd, 1, -1);
				অনুবর্ত;
			}
			প্রত্যাগম 0;
		পক্ষ 0:
			errno = EPIPE;
			প্রত্যাগম pos;
		স্বভাব:
			pos += (size_t)res;
			যদি (cb != রিক্ত && cb(cb_arg, (size_t)res) == -1) {
				errno = EINTR;
				প্রত্যাগম pos;
			}
		}
	}
	প্রত্যাগম pos;
}

size_t
atomicio(ssize_t (*f) (পূর্ণাঙ্ক, শূন্য *, size_t), পূর্ণাঙ্ক fd, শূন্য *_s, size_t n)
{
	প্রত্যাগম atomicio6(f, fd, _s, n, রিক্ত, রিক্ত);
}

/*
 * ensure all of data on socket comes through. f==readv || f==writev
 */
size_t
atomiciov6(ssize_t (*f) (পূর্ণাঙ্ক, ধ্রুব সংরচনা iovec *, পূর্ণাঙ্ক), পূর্ণাঙ্ক fd,
    ধ্রুব সংরচনা iovec *_iov, পূর্ণাঙ্ক iovcnt,
    পূর্ণাঙ্ক (*cb)(শূন্য *, size_t), শূন্য *cb_arg)
{
	size_t pos = 0, rem;
	ssize_t res;
	সংরচনা iovec iov_array[IOV_MAX], *iov = iov_array;
	সংরচনা pollfd pfd;

	যদি (iovcnt < 0 || iovcnt > IOV_MAX) {
		errno = EINVAL;
		প্রত্যাগম 0;
	}
	/* Make a copy of the iov array because we may modify it below */
	memcpy(iov, _iov, (size_t)iovcnt * পরিমাণ(*_iov));

	pfd.fd = fd;
#ifndef BROKEN_READV_COMPARISON
	pfd.events = f == readv ? POLLIN : POLLOUT;
#অন্যথা
	pfd.events = POLLIN|POLLOUT;
#endif
	প্রতি (; iovcnt > 0 && iov[0].iov_len > 0;) {
		res = (f) (fd, iov, iovcnt);
		বিকল্প (res) {
		পক্ষ -1:
			যদি (errno == EINTR) {
				/* possible SIGALARM, update callback */
				যদি (cb != রিক্ত && cb(cb_arg, 0) == -1) {
					errno = EINTR;
					প্রত্যাগম pos;
				}
				অনুবর্ত;
			} অন্যথা যদি (errno == EAGAIN || errno == EWOULDBLOCK) {
				(শূন্য)poll(&pfd, 1, -1);
				অনুবর্ত;
			}
			প্রত্যাগম 0;
		পক্ষ 0:
			errno = EPIPE;
			প্রত্যাগম pos;
		স্বভাব:
			rem = (size_t)res;
			pos += rem;
			/* skip completed iov entries */
			যাবত্ (iovcnt > 0 && rem >= iov[0].iov_len) {
				rem -= iov[0].iov_len;
				iov++;
				iovcnt--;
			}
			/* This shouldn't happen... */
			যদি (rem > 0 && (iovcnt <= 0 || rem > iov[0].iov_len)) {
				errno = EFAULT;
				প্রত্যাগম 0;
			}
			যদি (iovcnt == 0)
				ভঙ্গ;
			/* update pointer in partially complete iov */
			iov[0].iov_base = ((বর্ণ *)iov[0].iov_base) + rem;
			iov[0].iov_len -= rem;
		}
		যদি (cb != রিক্ত && cb(cb_arg, (size_t)res) == -1) {
			errno = EINTR;
			প্রত্যাগম pos;
		}
	}
	প্রত্যাগম pos;
}

size_t
atomiciov(ssize_t (*f) (পূর্ণাঙ্ক, ধ্রুব সংরচনা iovec *, পূর্ণাঙ্ক), পূর্ণাঙ্ক fd,
    ধ্রুব সংরচনা iovec *_iov, পূর্ণাঙ্ক iovcnt)
{
	প্রত্যাগম atomiciov6(f, fd, _iov, iovcnt, রিক্ত, রিক্ত);
}
