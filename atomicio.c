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
আকার_t
atomicio6(ssize_t (*f) (পূর্ণসংখ্যা, শূন্য *, আকার_t), পূর্ণসংখ্যা fd, শূন্য *_s, আকার_t n,
    পূর্ণসংখ্যা (*cb)(শূন্য *, আকার_t), শূন্য *cb_arg)
{
	অক্ষর *s = _s;
	আকার_t pos = 0;
	ssize_t res;
	কাঠামো pollfd pfd;

	pfd.fd = fd;
	pfd.events = f == পঠ ? POLLIN : POLLOUT;
	যখন (n > pos) {
		res = (f) (fd, s + pos, n - pos);
		নির্বাচন (res) {
		ক্ষেত্র -1:
			যদি (errno == EINTR) {
				/* possible SIGALARM, update callback */
				যদি (cb != ফাঁকা && cb(cb_arg, 0) == -1) {
					errno = EINTR;
					ফেরত pos;
				}
				চালু;
			} অন্যথা যদি (errno == EAGAIN || errno == EWOULDBLOCK) {
				(শূন্য)poll(&pfd, 1, -1);
				চালু;
			}
			ফেরত 0;
		ক্ষেত্র 0:
			errno = EPIPE;
			ফেরত pos;
		পূর্বনির্ধারিত:
			pos += (আকার_t)res;
			যদি (cb != ফাঁকা && cb(cb_arg, (আকার_t)res) == -1) {
				errno = EINTR;
				ফেরত pos;
			}
		}
	}
	ফেরত pos;
}

আকার_t
atomicio(ssize_t (*f) (পূর্ণসংখ্যা, শূন্য *, আকার_t), পূর্ণসংখ্যা fd, শূন্য *_s, আকার_t n)
{
	ফেরত atomicio6(f, fd, _s, n, ফাঁকা, ফাঁকা);
}

/*
 * ensure all of data on socket comes through. f==readv || f==writev
 */
আকার_t
atomiciov6(ssize_t (*f) (পূর্ণসংখ্যা, ধ্রুবক কাঠামো iovec *, পূর্ণসংখ্যা), পূর্ণসংখ্যা fd,
    ধ্রুবক কাঠামো iovec *_iov, পূর্ণসংখ্যা iovcnt,
    পূর্ণসংখ্যা (*cb)(শূন্য *, আকার_t), শূন্য *cb_arg)
{
	আকার_t pos = 0, rem;
	ssize_t res;
	কাঠামো iovec iov_array[IOV_MAX], *iov = iov_array;
	কাঠামো pollfd pfd;

	যদি (iovcnt < 0 || iovcnt > IOV_MAX) {
		errno = EINVAL;
		ফেরত 0;
	}
	/* Make a copy of the iov array because we may modify it below */
	memcpy(iov, _iov, (আকার_t)iovcnt * আকার(*_iov));

	pfd.fd = fd;
#ifndef BROKEN_READV_COMPARISON
	pfd.events = f == readv ? POLLIN : POLLOUT;
#অন্যথা
	pfd.events = POLLIN|POLLOUT;
#endif
	জন্য (; iovcnt > 0 && iov[0].iov_len > 0;) {
		res = (f) (fd, iov, iovcnt);
		নির্বাচন (res) {
		ক্ষেত্র -1:
			যদি (errno == EINTR) {
				/* possible SIGALARM, update callback */
				যদি (cb != ফাঁকা && cb(cb_arg, 0) == -1) {
					errno = EINTR;
					ফেরত pos;
				}
				চালু;
			} অন্যথা যদি (errno == EAGAIN || errno == EWOULDBLOCK) {
				(শূন্য)poll(&pfd, 1, -1);
				চালু;
			}
			ফেরত 0;
		ক্ষেত্র 0:
			errno = EPIPE;
			ফেরত pos;
		পূর্বনির্ধারিত:
			rem = (আকার_t)res;
			pos += rem;
			/* skip completed iov entries */
			যখন (iovcnt > 0 && rem >= iov[0].iov_len) {
				rem -= iov[0].iov_len;
				iov++;
				iovcnt--;
			}
			/* This shouldn't happen... */
			যদি (rem > 0 && (iovcnt <= 0 || rem > iov[0].iov_len)) {
				errno = EFAULT;
				ফেরত 0;
			}
			যদি (iovcnt == 0)
				বিরতি;
			/* update pointer in partially complete iov */
			iov[0].iov_base = ((অক্ষর *)iov[0].iov_base) + rem;
			iov[0].iov_len -= rem;
		}
		যদি (cb != ফাঁকা && cb(cb_arg, (আকার_t)res) == -1) {
			errno = EINTR;
			ফেরত pos;
		}
	}
	ফেরত pos;
}

আকার_t
atomiciov(ssize_t (*f) (পূর্ণসংখ্যা, ধ্রুবক কাঠামো iovec *, পূর্ণসংখ্যা), পূর্ণসংখ্যা fd,
    ধ্রুবক কাঠামো iovec *_iov, পূর্ণসংখ্যা iovcnt)
{
	ফেরত atomiciov6(f, fd, _iov, iovcnt, ফাঁকা, ফাঁকা);
}
