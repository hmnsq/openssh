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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/uio.h>

#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <poll.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <unistd.h>
#அந்தர்பாவ <limits.h>

#அந்தர்பாவ "atomicio.h"

/*
 * ensure all of data on socket comes through. f==read || f==vwrite
 */
size_t
atomicio6(ssize_t (*f) (முழு, வெறுமை *, size_t), முழு fd, வெறுமை *_s, size_t n,
    முழு (*cb)(வெறுமை *, size_t), வெறுமை *cb_arg)
{
	எழுத்து *s = _s;
	size_t pos = 0;
	ssize_t res;
	கட்டமைப்பு pollfd pfd;

	pfd.fd = fd;
	pfd.events = f == பட ? POLLIN : POLLOUT;
	போது (n > pos) {
		res = (f) (fd, s + pos, n - pos);
		தேர்வு (res) {
		நிலை -1:
			எனில் (errno == EINTR) {
				/* possible SIGALARM, update callback */
				எனில் (cb != வெற்று && cb(cb_arg, 0) == -1) {
					errno = EINTR;
					திரும்பு pos;
				}
				தொடர்;
			} இல்லையெனில் எனில் (errno == EAGAIN || errno == EWOULDBLOCK) {
				(வெறுமை)poll(&pfd, 1, -1);
				தொடர்;
			}
			திரும்பு 0;
		நிலை 0:
			errno = EPIPE;
			திரும்பு pos;
		இயல்பு:
			pos += (size_t)res;
			எனில் (cb != வெற்று && cb(cb_arg, (size_t)res) == -1) {
				errno = EINTR;
				திரும்பு pos;
			}
		}
	}
	திரும்பு pos;
}

size_t
atomicio(ssize_t (*f) (முழு, வெறுமை *, size_t), முழு fd, வெறுமை *_s, size_t n)
{
	திரும்பு atomicio6(f, fd, _s, n, வெற்று, வெற்று);
}

/*
 * ensure all of data on socket comes through. f==readv || f==writev
 */
size_t
atomiciov6(ssize_t (*f) (முழு, மாறிலி கட்டமைப்பு iovec *, முழு), முழு fd,
    மாறிலி கட்டமைப்பு iovec *_iov, முழு iovcnt,
    முழு (*cb)(வெறுமை *, size_t), வெறுமை *cb_arg)
{
	size_t pos = 0, rem;
	ssize_t res;
	கட்டமைப்பு iovec iov_array[IOV_MAX], *iov = iov_array;
	கட்டமைப்பு pollfd pfd;

	எனில் (iovcnt < 0 || iovcnt > IOV_MAX) {
		errno = EINVAL;
		திரும்பு 0;
	}
	/* Make a copy of the iov array because we may modify it below */
	memcpy(iov, _iov, (size_t)iovcnt * அளவு(*_iov));

	pfd.fd = fd;
#ifndef BROKEN_READV_COMPARISON
	pfd.events = f == readv ? POLLIN : POLLOUT;
#இல்லையெனில்
	pfd.events = POLLIN|POLLOUT;
#endif
	க்கு (; iovcnt > 0 && iov[0].iov_len > 0;) {
		res = (f) (fd, iov, iovcnt);
		தேர்வு (res) {
		நிலை -1:
			எனில் (errno == EINTR) {
				/* possible SIGALARM, update callback */
				எனில் (cb != வெற்று && cb(cb_arg, 0) == -1) {
					errno = EINTR;
					திரும்பு pos;
				}
				தொடர்;
			} இல்லையெனில் எனில் (errno == EAGAIN || errno == EWOULDBLOCK) {
				(வெறுமை)poll(&pfd, 1, -1);
				தொடர்;
			}
			திரும்பு 0;
		நிலை 0:
			errno = EPIPE;
			திரும்பு pos;
		இயல்பு:
			rem = (size_t)res;
			pos += rem;
			/* skip completed iov entries */
			போது (iovcnt > 0 && rem >= iov[0].iov_len) {
				rem -= iov[0].iov_len;
				iov++;
				iovcnt--;
			}
			/* This shouldn't happen... */
			எனில் (rem > 0 && (iovcnt <= 0 || rem > iov[0].iov_len)) {
				errno = EFAULT;
				திரும்பு 0;
			}
			எனில் (iovcnt == 0)
				நிறுத்து;
			/* update pointer in partially complete iov */
			iov[0].iov_base = ((எழுத்து *)iov[0].iov_base) + rem;
			iov[0].iov_len -= rem;
		}
		எனில் (cb != வெற்று && cb(cb_arg, (size_t)res) == -1) {
			errno = EINTR;
			திரும்பு pos;
		}
	}
	திரும்பு pos;
}

size_t
atomiciov(ssize_t (*f) (முழு, மாறிலி கட்டமைப்பு iovec *, முழு), முழு fd,
    மாறிலி கட்டமைப்பு iovec *_iov, முழு iovcnt)
{
	திரும்பு atomiciov6(f, fd, _iov, iovcnt, வெற்று, வெற்று);
}
