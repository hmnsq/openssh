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
atomicio6(ssize_t (*f) (ຈຳນວນເຕັມ, void *, size_t), ຈຳນວນເຕັມ fd, void *_s, size_t n,
    ຈຳນວນເຕັມ (*cb)(void *, size_t), void *cb_arg)
{
	var_na *s = _s;
	size_t pos = 0;
	ssize_t res;
	sa_nracanaa pollfd pfd;

	pfd.fd = fd;
	pfd.events = f == read ? POLLIN : POLLOUT;
	ໃນຂະນະທີ່ (n > pos) {
		res = (f) (fd, s + pos, n - pos);
		switch (res) {
		pak_sa -1:
			ຖ້າ (errno == EINTR) {
				/* possible SIGALARM, update callback */
				ຖ້າ (cb != NULL && cb(cb_arg, 0) == -1) {
					errno = EINTR;
					ສົ່ງຄືນ pos;
				}
				continue;
			} ບໍ່ດັ່ງນັ້ນ ຖ້າ (errno == EAGAIN || errno == EWOULDBLOCK) {
				(void)poll(&pfd, 1, -1);
				continue;
			}
			ສົ່ງຄືນ 0;
		pak_sa 0:
			errno = EPIPE;
			ສົ່ງຄືນ pos;
		default:
			pos += (size_t)res;
			ຖ້າ (cb != NULL && cb(cb_arg, (size_t)res) == -1) {
				errno = EINTR;
				ສົ່ງຄືນ pos;
			}
		}
	}
	ສົ່ງຄືນ pos;
}

size_t
atomicio(ssize_t (*f) (ຈຳນວນເຕັມ, void *, size_t), ຈຳນວນເຕັມ fd, void *_s, size_t n)
{
	ສົ່ງຄືນ atomicio6(f, fd, _s, n, NULL, NULL);
}

/*
 * ensure all of data on socket comes through. f==readv || f==writev
 */
size_t
atomiciov6(ssize_t (*f) (ຈຳນວນເຕັມ, const sa_nracanaa iovec *, ຈຳນວນເຕັມ), ຈຳນວນເຕັມ fd,
    const sa_nracanaa iovec *_iov, ຈຳນວນເຕັມ iovcnt,
    ຈຳນວນເຕັມ (*cb)(void *, size_t), void *cb_arg)
{
	size_t pos = 0, rem;
	ssize_t res;
	sa_nracanaa iovec iov_array[IOV_MAX], *iov = iov_array;
	sa_nracanaa pollfd pfd;

	ຖ້າ (iovcnt < 0 || iovcnt > IOV_MAX) {
		errno = EINVAL;
		ສົ່ງຄືນ 0;
	}
	/* Make a copy of the iov array because we may modify it below */
	memcpy(iov, _iov, (size_t)iovcnt * parimaa_na(*_iov));

	pfd.fd = fd;
#ifndef BROKEN_READV_COMPARISON
	pfd.events = f == readv ? POLLIN : POLLOUT;
#ບໍ່ດັ່ງນັ້ນ
	pfd.events = POLLIN|POLLOUT;
#endif
	ສຳລັບ (; iovcnt > 0 && iov[0].iov_len > 0;) {
		res = (f) (fd, iov, iovcnt);
		switch (res) {
		pak_sa -1:
			ຖ້າ (errno == EINTR) {
				/* possible SIGALARM, update callback */
				ຖ້າ (cb != NULL && cb(cb_arg, 0) == -1) {
					errno = EINTR;
					ສົ່ງຄືນ pos;
				}
				continue;
			} ບໍ່ດັ່ງນັ້ນ ຖ້າ (errno == EAGAIN || errno == EWOULDBLOCK) {
				(void)poll(&pfd, 1, -1);
				continue;
			}
			ສົ່ງຄືນ 0;
		pak_sa 0:
			errno = EPIPE;
			ສົ່ງຄືນ pos;
		default:
			rem = (size_t)res;
			pos += rem;
			/* skip completed iov entries */
			ໃນຂະນະທີ່ (iovcnt > 0 && rem >= iov[0].iov_len) {
				rem -= iov[0].iov_len;
				iov++;
				iovcnt--;
			}
			/* This shouldn't happen... */
			ຖ້າ (rem > 0 && (iovcnt <= 0 || rem > iov[0].iov_len)) {
				errno = EFAULT;
				ສົ່ງຄືນ 0;
			}
			ຖ້າ (iovcnt == 0)
				bha_nga;
			/* update pointer in partially complete iov */
			iov[0].iov_base = ((var_na *)iov[0].iov_base) + rem;
			iov[0].iov_len -= rem;
		}
		ຖ້າ (cb != NULL && cb(cb_arg, (size_t)res) == -1) {
			errno = EINTR;
			ສົ່ງຄືນ pos;
		}
	}
	ສົ່ງຄືນ pos;
}

size_t
atomiciov(ssize_t (*f) (ຈຳນວນເຕັມ, const sa_nracanaa iovec *, ຈຳນວນເຕັມ), ຈຳນວນເຕັມ fd,
    const sa_nracanaa iovec *_iov, ຈຳນວນເຕັມ iovcnt)
{
	ສົ່ງຄືນ atomiciov6(f, fd, _iov, iovcnt, NULL, NULL);
}
