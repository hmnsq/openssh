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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/uio.h>

#అన్తర్భావ <errno.h>
#అన్తర్భావ <poll.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <unistd.h>
#అన్తర్భావ <limits.h>

#అన్తర్భావ "atomicio.h"

/*
 * ensure all of data on socket comes through. f==read || f==vwrite
 */
కొలత_t
atomicio6(ssize_t (*f) (పూర్ణాంకం, శూన్య *, కొలత_t), పూర్ణాంకం fd, శూన్య *_s, కొలత_t n,
    పూర్ణాంకం (*cb)(శూన్య *, కొలత_t), శూన్య *cb_arg)
{
	అక్షరం *s = _s;
	కొలత_t pos = 0;
	ssize_t res;
	నిర్మాణం pollfd pfd;

	pfd.fd = fd;
	pfd.events = f == పఠ ? POLLIN : POLLOUT;
	అయితే (n > pos) {
		res = (f) (fd, s + pos, n - pos);
		ఎంపిక (res) {
		స్థితి -1:
			ఒకవేళ (errno == EINTR) {
				/* possible SIGALARM, update callback */
				ఒకవేళ (cb != ఖాళీ && cb(cb_arg, 0) == -1) {
					errno = EINTR;
					తిరిగి pos;
				}
				కొనసాగు;
			} లేకపోతే ఒకవేళ (errno == EAGAIN || errno == EWOULDBLOCK) {
				(శూన్య)poll(&pfd, 1, -1);
				కొనసాగు;
			}
			తిరిగి 0;
		స్థితి 0:
			errno = EPIPE;
			తిరిగి pos;
		అప్రమేయ:
			pos += (కొలత_t)res;
			ఒకవేళ (cb != ఖాళీ && cb(cb_arg, (కొలత_t)res) == -1) {
				errno = EINTR;
				తిరిగి pos;
			}
		}
	}
	తిరిగి pos;
}

కొలత_t
atomicio(ssize_t (*f) (పూర్ణాంకం, శూన్య *, కొలత_t), పూర్ణాంకం fd, శూన్య *_s, కొలత_t n)
{
	తిరిగి atomicio6(f, fd, _s, n, ఖాళీ, ఖాళీ);
}

/*
 * ensure all of data on socket comes through. f==readv || f==writev
 */
కొలత_t
atomiciov6(ssize_t (*f) (పూర్ణాంకం, స్థిరరాశి నిర్మాణం iovec *, పూర్ణాంకం), పూర్ణాంకం fd,
    స్థిరరాశి నిర్మాణం iovec *_iov, పూర్ణాంకం iovcnt,
    పూర్ణాంకం (*cb)(శూన్య *, కొలత_t), శూన్య *cb_arg)
{
	కొలత_t pos = 0, rem;
	ssize_t res;
	నిర్మాణం iovec iov_array[IOV_MAX], *iov = iov_array;
	నిర్మాణం pollfd pfd;

	ఒకవేళ (iovcnt < 0 || iovcnt > IOV_MAX) {
		errno = EINVAL;
		తిరిగి 0;
	}
	/* Make a copy of the iov array because we may modify it below */
	జ్ఞాపకం_నకలు(iov, _iov, (కొలత_t)iovcnt * పరిమాణం(*_iov));

	pfd.fd = fd;
#నిర్వచితం_కాకపోతే BROKEN_READV_COMPARISON
	pfd.events = f == readv ? POLLIN : POLLOUT;
#లేకపోతే
	pfd.events = POLLIN|POLLOUT;
#అయితే_ముగింపు
	కొరకు (; iovcnt > 0 && iov[0].iov_len > 0;) {
		res = (f) (fd, iov, iovcnt);
		ఎంపిక (res) {
		స్థితి -1:
			ఒకవేళ (errno == EINTR) {
				/* possible SIGALARM, update callback */
				ఒకవేళ (cb != ఖాళీ && cb(cb_arg, 0) == -1) {
					errno = EINTR;
					తిరిగి pos;
				}
				కొనసాగు;
			} లేకపోతే ఒకవేళ (errno == EAGAIN || errno == EWOULDBLOCK) {
				(శూన్య)poll(&pfd, 1, -1);
				కొనసాగు;
			}
			తిరిగి 0;
		స్థితి 0:
			errno = EPIPE;
			తిరిగి pos;
		అప్రమేయ:
			rem = (కొలత_t)res;
			pos += rem;
			/* skip completed iov entries */
			అయితే (iovcnt > 0 && rem >= iov[0].iov_len) {
				rem -= iov[0].iov_len;
				iov++;
				iovcnt--;
			}
			/* This shouldn't happen... */
			ఒకవేళ (rem > 0 && (iovcnt <= 0 || rem > iov[0].iov_len)) {
				errno = EFAULT;
				తిరిగి 0;
			}
			ఒకవేళ (iovcnt == 0)
				ఆపు;
			/* update pointer in partially complete iov */
			iov[0].iov_base = ((అక్షరం *)iov[0].iov_base) + rem;
			iov[0].iov_len -= rem;
		}
		ఒకవేళ (cb != ఖాళీ && cb(cb_arg, (కొలత_t)res) == -1) {
			errno = EINTR;
			తిరిగి pos;
		}
	}
	తిరిగి pos;
}

కొలత_t
atomiciov(ssize_t (*f) (పూర్ణాంకం, స్థిరరాశి నిర్మాణం iovec *, పూర్ణాంకం), పూర్ణాంకం fd,
    స్థిరరాశి నిర్మాణం iovec *_iov, పూర్ణాంకం iovcnt)
{
	తిరిగి atomiciov6(f, fd, _iov, iovcnt, ఖాళీ, ఖాళీ);
}
