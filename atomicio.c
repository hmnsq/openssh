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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/uio.h>

#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <poll.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>
#ଅନ୍ତର୍ଭାଵ <limits.h>

#ଅନ୍ତର୍ଭାଵ "atomicio.h"

/*
 * ensure all of data on socket comes through. f==read || f==vwrite
 */
size_t
atomicio6(ssize_t (*f) (ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ଶୂନ୍ୟ *, size_t), ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd, ଶୂନ୍ୟ *_s, size_t n,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା (*cb)(ଶୂନ୍ୟ *, size_t), ଶୂନ୍ୟ *cb_arg)
{
	ଅକ୍ଷର *s = _s;
	size_t pos = 0;
	ssize_t res;
	ସଂରଚନା pollfd pfd;

	pfd.fd = fd;
	pfd.events = f == ପଠ ? POLLIN : POLLOUT;
	ଯେତେବେଳେ (n > pos) {
		res = (f) (fd, s + pos, n - pos);
		ବାଛ (res) {
		ସ୍ଥିତି -1:
			ଯଦି (errno == EINTR) {
				/* possible SIGALARM, update callback */
				ଯଦି (cb != ଖାଲି && cb(cb_arg, 0) == -1) {
					errno = EINTR;
					ଫେରନ୍ତୁ pos;
				}
				ଜାରି;
			} ଅନ୍ୟଥା ଯଦି (errno == EAGAIN || errno == EWOULDBLOCK) {
				(ଶୂନ୍ୟ)poll(&pfd, 1, -1);
				ଜାରି;
			}
			ଫେରନ୍ତୁ 0;
		ସ୍ଥିତି 0:
			errno = EPIPE;
			ଫେରନ୍ତୁ pos;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			pos += (size_t)res;
			ଯଦି (cb != ଖାଲି && cb(cb_arg, (size_t)res) == -1) {
				errno = EINTR;
				ଫେରନ୍ତୁ pos;
			}
		}
	}
	ଫେରନ୍ତୁ pos;
}

size_t
atomicio(ssize_t (*f) (ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ଶୂନ୍ୟ *, size_t), ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd, ଶୂନ୍ୟ *_s, size_t n)
{
	ଫେରନ୍ତୁ atomicio6(f, fd, _s, n, ଖାଲି, ଖାଲି);
}

/*
 * ensure all of data on socket comes through. f==readv || f==writev
 */
size_t
atomiciov6(ssize_t (*f) (ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ଅଚଳ ସଂରଚନା iovec *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା), ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd,
    ଅଚଳ ସଂରଚନା iovec *_iov, ପୂର୍ଣ୍ଣସଂଖ୍ୟା iovcnt,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା (*cb)(ଶୂନ୍ୟ *, size_t), ଶୂନ୍ୟ *cb_arg)
{
	size_t pos = 0, rem;
	ssize_t res;
	ସଂରଚନା iovec iov_array[IOV_MAX], *iov = iov_array;
	ସଂରଚନା pollfd pfd;

	ଯଦି (iovcnt < 0 || iovcnt > IOV_MAX) {
		errno = EINVAL;
		ଫେରନ୍ତୁ 0;
	}
	/* Make a copy of the iov array because we may modify it below */
	memcpy(iov, _iov, (size_t)iovcnt * ଆକାର(*_iov));

	pfd.fd = fd;
#ifndef BROKEN_READV_COMPARISON
	pfd.events = f == readv ? POLLIN : POLLOUT;
#ଅନ୍ୟଥା
	pfd.events = POLLIN|POLLOUT;
#endif
	ପାଇଁ (; iovcnt > 0 && iov[0].iov_len > 0;) {
		res = (f) (fd, iov, iovcnt);
		ବାଛ (res) {
		ସ୍ଥିତି -1:
			ଯଦି (errno == EINTR) {
				/* possible SIGALARM, update callback */
				ଯଦି (cb != ଖାଲି && cb(cb_arg, 0) == -1) {
					errno = EINTR;
					ଫେରନ୍ତୁ pos;
				}
				ଜାରି;
			} ଅନ୍ୟଥା ଯଦି (errno == EAGAIN || errno == EWOULDBLOCK) {
				(ଶୂନ୍ୟ)poll(&pfd, 1, -1);
				ଜାରି;
			}
			ଫେରନ୍ତୁ 0;
		ସ୍ଥିତି 0:
			errno = EPIPE;
			ଫେରନ୍ତୁ pos;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			rem = (size_t)res;
			pos += rem;
			/* skip completed iov entries */
			ଯେତେବେଳେ (iovcnt > 0 && rem >= iov[0].iov_len) {
				rem -= iov[0].iov_len;
				iov++;
				iovcnt--;
			}
			/* This shouldn't happen... */
			ଯଦି (rem > 0 && (iovcnt <= 0 || rem > iov[0].iov_len)) {
				errno = EFAULT;
				ଫେରନ୍ତୁ 0;
			}
			ଯଦି (iovcnt == 0)
				ଭାଙ୍ଗ;
			/* update pointer in partially complete iov */
			iov[0].iov_base = ((ଅକ୍ଷର *)iov[0].iov_base) + rem;
			iov[0].iov_len -= rem;
		}
		ଯଦି (cb != ଖାଲି && cb(cb_arg, (size_t)res) == -1) {
			errno = EINTR;
			ଫେରନ୍ତୁ pos;
		}
	}
	ଫେରନ୍ତୁ pos;
}

size_t
atomiciov(ssize_t (*f) (ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ଅଚଳ ସଂରଚନା iovec *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା), ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd,
    ଅଚଳ ସଂରଚନା iovec *_iov, ପୂର୍ଣ୍ଣସଂଖ୍ୟା iovcnt)
{
	ଫେରନ୍ତୁ atomiciov6(f, fd, _iov, iovcnt, ଖାଲି, ଖାଲି);
}
