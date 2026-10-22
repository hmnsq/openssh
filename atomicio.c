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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/uio.h>

#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <poll.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <unistd.h>
#അന്തര്ഭാവ <limits.h>

#അന്തര്ഭാവ "atomicio.h"

/*
 * ensure all of data on socket comes through. f==read || f==vwrite
 */
size_t
atomicio6(ssize_t (*f) (പൂർണ്ണസംഖ്യ, ശൂന്യം *, size_t), പൂർണ്ണസംഖ്യ fd, ശൂന്യം *_s, size_t n,
    പൂർണ്ണസംഖ്യ (*cb)(ശൂന്യം *, size_t), ശൂന്യം *cb_arg)
{
	അക്ഷരം *s = _s;
	size_t pos = 0;
	ssize_t res;
	ഘടന pollfd pfd;

	pfd.fd = fd;
	pfd.events = f == പഠ ? POLLIN : POLLOUT;
	ആകുമ്പോൾ (n > pos) {
		res = (f) (fd, s + pos, n - pos);
		തിരഞ്ഞെടുപ്പ് (res) {
		അവസ്ഥ -1:
			എങ്കിൽ (errno == EINTR) {
				/* possible SIGALARM, update callback */
				എങ്കിൽ (cb != ശൂന്യ && cb(cb_arg, 0) == -1) {
					errno = EINTR;
					തിരികെ pos;
				}
				തുടരുക;
			} അല്ലെങ്കിൽ എങ്കിൽ (errno == EAGAIN || errno == EWOULDBLOCK) {
				(ശൂന്യം)poll(&pfd, 1, -1);
				തുടരുക;
			}
			തിരികെ 0;
		അവസ്ഥ 0:
			errno = EPIPE;
			തിരികെ pos;
		സ്ഥിരസ്ഥിതി:
			pos += (size_t)res;
			എങ്കിൽ (cb != ശൂന്യ && cb(cb_arg, (size_t)res) == -1) {
				errno = EINTR;
				തിരികെ pos;
			}
		}
	}
	തിരികെ pos;
}

size_t
atomicio(ssize_t (*f) (പൂർണ്ണസംഖ്യ, ശൂന്യം *, size_t), പൂർണ്ണസംഖ്യ fd, ശൂന്യം *_s, size_t n)
{
	തിരികെ atomicio6(f, fd, _s, n, ശൂന്യ, ശൂന്യ);
}

/*
 * ensure all of data on socket comes through. f==readv || f==writev
 */
size_t
atomiciov6(ssize_t (*f) (പൂർണ്ണസംഖ്യ, സ്ഥിരം ഘടന iovec *, പൂർണ്ണസംഖ്യ), പൂർണ്ണസംഖ്യ fd,
    സ്ഥിരം ഘടന iovec *_iov, പൂർണ്ണസംഖ്യ iovcnt,
    പൂർണ്ണസംഖ്യ (*cb)(ശൂന്യം *, size_t), ശൂന്യം *cb_arg)
{
	size_t pos = 0, rem;
	ssize_t res;
	ഘടന iovec iov_array[IOV_MAX], *iov = iov_array;
	ഘടന pollfd pfd;

	എങ്കിൽ (iovcnt < 0 || iovcnt > IOV_MAX) {
		errno = EINVAL;
		തിരികെ 0;
	}
	/* Make a copy of the iov array because we may modify it below */
	memcpy(iov, _iov, (size_t)iovcnt * വലുപ്പം(*_iov));

	pfd.fd = fd;
#ifndef BROKEN_READV_COMPARISON
	pfd.events = f == readv ? POLLIN : POLLOUT;
#അല്ലെങ്കിൽ
	pfd.events = POLLIN|POLLOUT;
#endif
	വേണ്ടി (; iovcnt > 0 && iov[0].iov_len > 0;) {
		res = (f) (fd, iov, iovcnt);
		തിരഞ്ഞെടുപ്പ് (res) {
		അവസ്ഥ -1:
			എങ്കിൽ (errno == EINTR) {
				/* possible SIGALARM, update callback */
				എങ്കിൽ (cb != ശൂന്യ && cb(cb_arg, 0) == -1) {
					errno = EINTR;
					തിരികെ pos;
				}
				തുടരുക;
			} അല്ലെങ്കിൽ എങ്കിൽ (errno == EAGAIN || errno == EWOULDBLOCK) {
				(ശൂന്യം)poll(&pfd, 1, -1);
				തുടരുക;
			}
			തിരികെ 0;
		അവസ്ഥ 0:
			errno = EPIPE;
			തിരികെ pos;
		സ്ഥിരസ്ഥിതി:
			rem = (size_t)res;
			pos += rem;
			/* skip completed iov entries */
			ആകുമ്പോൾ (iovcnt > 0 && rem >= iov[0].iov_len) {
				rem -= iov[0].iov_len;
				iov++;
				iovcnt--;
			}
			/* This shouldn't happen... */
			എങ്കിൽ (rem > 0 && (iovcnt <= 0 || rem > iov[0].iov_len)) {
				errno = EFAULT;
				തിരികെ 0;
			}
			എങ്കിൽ (iovcnt == 0)
				നിർത്തുക;
			/* update pointer in partially complete iov */
			iov[0].iov_base = ((അക്ഷരം *)iov[0].iov_base) + rem;
			iov[0].iov_len -= rem;
		}
		എങ്കിൽ (cb != ശൂന്യ && cb(cb_arg, (size_t)res) == -1) {
			errno = EINTR;
			തിരികെ pos;
		}
	}
	തിരികെ pos;
}

size_t
atomiciov(ssize_t (*f) (പൂർണ്ണസംഖ്യ, സ്ഥിരം ഘടന iovec *, പൂർണ്ണസംഖ്യ), പൂർണ്ണസംഖ്യ fd,
    സ്ഥിരം ഘടന iovec *_iov, പൂർണ്ണസംഖ്യ iovcnt)
{
	തിരികെ atomiciov6(f, fd, _iov, iovcnt, ശൂന്യ, ശൂന്യ);
}
