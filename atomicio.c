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

#include "includes.h"

#include <sys/uio.h>

#include <errno.h>
#include <poll.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>

#include "atomicio.h"

/*
 * ensure all of data on socket comes through. f==read || f==vwrite
 */
size_t
atomicio6(ssize_t (*f) (цео, void *, size_t), цео fd, void *_s, size_t n,
    цео (*cb)(void *, size_t), void *cb_arg)
{
	char *s = _s;
	size_t pos = 0;
	ssize_t res;
	struct pollfd pfd;

	pfd.fd = fd;
	pfd.events = f == read ? POLLIN : POLLOUT;
	док (n > pos) {
		res = (f) (fd, s + pos, n - pos);
		switch (res) {
		case -1:
			ако (errno == EINTR) {
				/* possible SIGALARM, update callback */
				ако (cb != NULL && cb(cb_arg, 0) == -1) {
					errno = EINTR;
					врати pos;
				}
				continue;
			} инако ако (errno == EAGAIN || errno == EWOULDBLOCK) {
				(void)poll(&pfd, 1, -1);
				continue;
			}
			врати 0;
		case 0:
			errno = EPIPE;
			врати pos;
		default:
			pos += (size_t)res;
			ако (cb != NULL && cb(cb_arg, (size_t)res) == -1) {
				errno = EINTR;
				врати pos;
			}
		}
	}
	врати pos;
}

size_t
atomicio(ssize_t (*f) (цео, void *, size_t), цео fd, void *_s, size_t n)
{
	врати atomicio6(f, fd, _s, n, NULL, NULL);
}

/*
 * ensure all of data on socket comes through. f==readv || f==writev
 */
size_t
atomiciov6(ssize_t (*f) (цео, const struct iovec *, цео), цео fd,
    const struct iovec *_iov, цео iovcnt,
    цео (*cb)(void *, size_t), void *cb_arg)
{
	size_t pos = 0, rem;
	ssize_t res;
	struct iovec iov_array[IOV_MAX], *iov = iov_array;
	struct pollfd pfd;

	ако (iovcnt < 0 || iovcnt > IOV_MAX) {
		errno = EINVAL;
		врати 0;
	}
	/* Make a copy of the iov array because we may modify it below */
	memcpy(iov, _iov, (size_t)iovcnt * sizeof(*_iov));

	pfd.fd = fd;
#ifndef BROKEN_READV_COMPARISON
	pfd.events = f == readv ? POLLIN : POLLOUT;
#инако
	pfd.events = POLLIN|POLLOUT;
#endif
	за (; iovcnt > 0 && iov[0].iov_len > 0;) {
		res = (f) (fd, iov, iovcnt);
		switch (res) {
		case -1:
			ако (errno == EINTR) {
				/* possible SIGALARM, update callback */
				ако (cb != NULL && cb(cb_arg, 0) == -1) {
					errno = EINTR;
					врати pos;
				}
				continue;
			} инако ако (errno == EAGAIN || errno == EWOULDBLOCK) {
				(void)poll(&pfd, 1, -1);
				continue;
			}
			врати 0;
		case 0:
			errno = EPIPE;
			врати pos;
		default:
			rem = (size_t)res;
			pos += rem;
			/* skip completed iov entries */
			док (iovcnt > 0 && rem >= iov[0].iov_len) {
				rem -= iov[0].iov_len;
				iov++;
				iovcnt--;
			}
			/* This shouldn't happen... */
			ако (rem > 0 && (iovcnt <= 0 || rem > iov[0].iov_len)) {
				errno = EFAULT;
				врати 0;
			}
			ако (iovcnt == 0)
				break;
			/* update pointer in partially complete iov */
			iov[0].iov_base = ((char *)iov[0].iov_base) + rem;
			iov[0].iov_len -= rem;
		}
		ако (cb != NULL && cb(cb_arg, (size_t)res) == -1) {
			errno = EINTR;
			врати pos;
		}
	}
	врати pos;
}

size_t
atomiciov(ssize_t (*f) (цео, const struct iovec *, цео), цео fd,
    const struct iovec *_iov, цео iovcnt)
{
	врати atomiciov6(f, fd, _iov, iovcnt, NULL, NULL);
}
