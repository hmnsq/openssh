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
سائز_t
atomicio6(ssize_t (*f) (صحیح, خالی *, سائز_t), صحیح fd, خالی *_s, سائز_t n,
    صحیح (*cb)(خالی *, سائز_t), خالی *cb_arg)
{
	حرف *s = _s;
	سائز_t pos = 0;
	ssize_t res;
	ساخت pollfd pfd;

	pfd.fd = fd;
	pfd.events = f == اقرأ ? POLLIN : POLLOUT;
	جب (n > pos) {
		res = (f) (fd, s + pos, n - pos);
		انتخاب (res) {
		حالت -1:
			اگر (errno == EINTR) {
				/* possible SIGALARM, update callback */
				اگر (cb != تہی && cb(cb_arg, 0) == -1) {
					errno = EINTR;
					واپس pos;
				}
				جاری;
			} ورنہ اگر (errno == EAGAIN || errno == EWOULDBLOCK) {
				(خالی)poll(&pfd, 1, -1);
				جاری;
			}
			واپس 0;
		حالت 0:
			errno = EPIPE;
			واپس pos;
		طےشدہ:
			pos += (سائز_t)res;
			اگر (cb != تہی && cb(cb_arg, (سائز_t)res) == -1) {
				errno = EINTR;
				واپس pos;
			}
		}
	}
	واپس pos;
}

سائز_t
atomicio(ssize_t (*f) (صحیح, خالی *, سائز_t), صحیح fd, خالی *_s, سائز_t n)
{
	واپس atomicio6(f, fd, _s, n, تہی, تہی);
}

/*
 * ensure all of data on socket comes through. f==readv || f==writev
 */
سائز_t
atomiciov6(ssize_t (*f) (صحیح, ثابت ساخت iovec *, صحیح), صحیح fd,
    ثابت ساخت iovec *_iov, صحیح iovcnt,
    صحیح (*cb)(خالی *, سائز_t), خالی *cb_arg)
{
	سائز_t pos = 0, rem;
	ssize_t res;
	ساخت iovec iov_array[IOV_MAX], *iov = iov_array;
	ساخت pollfd pfd;

	اگر (iovcnt < 0 || iovcnt > IOV_MAX) {
		errno = EINVAL;
		واپس 0;
	}
	/* Make a copy of the iov array because we may modify it below */
	حافظہ_نقل(iov, _iov, (سائز_t)iovcnt * حجم(*_iov));

	pfd.fd = fd;
#اگر_غیر_تعریف_شدہ BROKEN_READV_COMPARISON
	pfd.events = f == readv ? POLLIN : POLLOUT;
#ورنہ
	pfd.events = POLLIN|POLLOUT;
#اگر_ختم
	برائے (; iovcnt > 0 && iov[0].iov_len > 0;) {
		res = (f) (fd, iov, iovcnt);
		انتخاب (res) {
		حالت -1:
			اگر (errno == EINTR) {
				/* possible SIGALARM, update callback */
				اگر (cb != تہی && cb(cb_arg, 0) == -1) {
					errno = EINTR;
					واپس pos;
				}
				جاری;
			} ورنہ اگر (errno == EAGAIN || errno == EWOULDBLOCK) {
				(خالی)poll(&pfd, 1, -1);
				جاری;
			}
			واپس 0;
		حالت 0:
			errno = EPIPE;
			واپس pos;
		طےشدہ:
			rem = (سائز_t)res;
			pos += rem;
			/* skip completed iov entries */
			جب (iovcnt > 0 && rem >= iov[0].iov_len) {
				rem -= iov[0].iov_len;
				iov++;
				iovcnt--;
			}
			/* This shouldn't happen... */
			اگر (rem > 0 && (iovcnt <= 0 || rem > iov[0].iov_len)) {
				errno = EFAULT;
				واپس 0;
			}
			اگر (iovcnt == 0)
				توڑو;
			/* update pointer in partially complete iov */
			iov[0].iov_base = ((حرف *)iov[0].iov_base) + rem;
			iov[0].iov_len -= rem;
		}
		اگر (cb != تہی && cb(cb_arg, (سائز_t)res) == -1) {
			errno = EINTR;
			واپس pos;
		}
	}
	واپس pos;
}

سائز_t
atomiciov(ssize_t (*f) (صحیح, ثابت ساخت iovec *, صحیح), صحیح fd,
    ثابت ساخت iovec *_iov, صحیح iovcnt)
{
	واپس atomiciov6(f, fd, _iov, iovcnt, تہی, تہی);
}
