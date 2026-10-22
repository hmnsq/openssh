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

#شامل "includes.h"

#شامل <sys/uio.h>

#شامل <errno.h>
#شامل <poll.h>
#شامل <string.h>
#شامل <unistd.h>
#شامل <limits.h>

#شامل "atomicio.h"

/*
 * ensure all of data on socket comes through. f==read || f==vwrite
 */
size_t
atomicio6(ssize_t (*f) (صحیح, تهی *, size_t), صحیح fd, تهی *_s, size_t n,
    صحیح (*cb)(تهی *, size_t), تهی *cb_arg)
{
	نویسه *s = _s;
	size_t pos = 0;
	ssize_t res;
	ساختار pollfd pfd;

	pfd.fd = fd;
	pfd.events = f == اقرأ ? POLLIN : POLLOUT;
	وقتی (n > pos) {
		res = (f) (fd, s + pos, n - pos);
		انتخاب (res) {
		حالت -1:
			اگر (errno == EINTR) {
				/* possible SIGALARM, update callback */
				اگر (cb != پوچ && cb(cb_arg, 0) == -1) {
					errno = EINTR;
					بازگشت pos;
				}
				ادامه;
			} وگرنه اگر (errno == EAGAIN || errno == EWOULDBLOCK) {
				(تهی)poll(&pfd, 1, -1);
				ادامه;
			}
			بازگشت 0;
		حالت 0:
			errno = EPIPE;
			بازگشت pos;
		پیشفرض:
			pos += (size_t)res;
			اگر (cb != پوچ && cb(cb_arg, (size_t)res) == -1) {
				errno = EINTR;
				بازگشت pos;
			}
		}
	}
	بازگشت pos;
}

size_t
atomicio(ssize_t (*f) (صحیح, تهی *, size_t), صحیح fd, تهی *_s, size_t n)
{
	بازگشت atomicio6(f, fd, _s, n, پوچ, پوچ);
}

/*
 * ensure all of data on socket comes through. f==readv || f==writev
 */
size_t
atomiciov6(ssize_t (*f) (صحیح, ثابت ساختار iovec *, صحیح), صحیح fd,
    ثابت ساختار iovec *_iov, صحیح iovcnt,
    صحیح (*cb)(تهی *, size_t), تهی *cb_arg)
{
	size_t pos = 0, rem;
	ssize_t res;
	ساختار iovec iov_array[IOV_MAX], *iov = iov_array;
	ساختار pollfd pfd;

	اگر (iovcnt < 0 || iovcnt > IOV_MAX) {
		errno = EINVAL;
		بازگشت 0;
	}
	/* Make a copy of the iov array because we may modify it below */
	memcpy(iov, _iov, (size_t)iovcnt * اندازه(*_iov));

	pfd.fd = fd;
#ifndef BROKEN_READV_COMPARISON
	pfd.events = f == readv ? POLLIN : POLLOUT;
#وگرنه
	pfd.events = POLLIN|POLLOUT;
#endif
	برای (; iovcnt > 0 && iov[0].iov_len > 0;) {
		res = (f) (fd, iov, iovcnt);
		انتخاب (res) {
		حالت -1:
			اگر (errno == EINTR) {
				/* possible SIGALARM, update callback */
				اگر (cb != پوچ && cb(cb_arg, 0) == -1) {
					errno = EINTR;
					بازگشت pos;
				}
				ادامه;
			} وگرنه اگر (errno == EAGAIN || errno == EWOULDBLOCK) {
				(تهی)poll(&pfd, 1, -1);
				ادامه;
			}
			بازگشت 0;
		حالت 0:
			errno = EPIPE;
			بازگشت pos;
		پیشفرض:
			rem = (size_t)res;
			pos += rem;
			/* skip completed iov entries */
			وقتی (iovcnt > 0 && rem >= iov[0].iov_len) {
				rem -= iov[0].iov_len;
				iov++;
				iovcnt--;
			}
			/* This shouldn't happen... */
			اگر (rem > 0 && (iovcnt <= 0 || rem > iov[0].iov_len)) {
				errno = EFAULT;
				بازگشت 0;
			}
			اگر (iovcnt == 0)
				بشکن;
			/* update pointer in partially complete iov */
			iov[0].iov_base = ((نویسه *)iov[0].iov_base) + rem;
			iov[0].iov_len -= rem;
		}
		اگر (cb != پوچ && cb(cb_arg, (size_t)res) == -1) {
			errno = EINTR;
			بازگشت pos;
		}
	}
	بازگشت pos;
}

size_t
atomiciov(ssize_t (*f) (صحیح, ثابت ساختار iovec *, صحیح), صحیح fd,
    ثابت ساختار iovec *_iov, صحیح iovcnt)
{
	بازگشت atomiciov6(f, fd, _iov, iovcnt, پوچ, پوچ);
}
