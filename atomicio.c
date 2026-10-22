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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/uio.h>

#अन्तर्भाव <errno.h>
#अन्तर्भाव <poll.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <unistd.h>
#अन्तर्भाव <limits.h>

#अन्तर्भाव "atomicio.h"

/*
 * ensure all of data on socket comes through. f==read || f==vwrite
 */
size_t
atomicio6(ssize_t (*f) (पूर्णाङ्क, शून्य *, size_t), पूर्णाङ्क fd, शून्य *_s, size_t n,
    पूर्णाङ्क (*cb)(शून्य *, size_t), शून्य *cb_arg)
{
	वर्ण *s = _s;
	size_t pos = 0;
	ssize_t res;
	संरचना pollfd pfd;

	pfd.fd = fd;
	pfd.events = f == पठ ? POLLIN : POLLOUT;
	जाव (n > pos) {
		res = (f) (fd, s + pos, n - pos);
		विकल्प (res) {
		पक्ष -1:
			जइ (errno == EINTR) {
				/* possible SIGALARM, update callback */
				जइ (cb != रिक्त && cb(cb_arg, 0) == -1) {
					errno = EINTR;
					प्रत्यागम pos;
				}
				अनुवर्त;
			} अण्णहा जइ (errno == EAGAIN || errno == EWOULDBLOCK) {
				(शून्य)poll(&pfd, 1, -1);
				अनुवर्त;
			}
			प्रत्यागम 0;
		पक्ष 0:
			errno = EPIPE;
			प्रत्यागम pos;
		स्वभाव:
			pos += (size_t)res;
			जइ (cb != रिक्त && cb(cb_arg, (size_t)res) == -1) {
				errno = EINTR;
				प्रत्यागम pos;
			}
		}
	}
	प्रत्यागम pos;
}

size_t
atomicio(ssize_t (*f) (पूर्णाङ्क, शून्य *, size_t), पूर्णाङ्क fd, शून्य *_s, size_t n)
{
	प्रत्यागम atomicio6(f, fd, _s, n, रिक्त, रिक्त);
}

/*
 * ensure all of data on socket comes through. f==readv || f==writev
 */
size_t
atomiciov6(ssize_t (*f) (पूर्णाङ्क, ध्रुव संरचना iovec *, पूर्णाङ्क), पूर्णाङ्क fd,
    ध्रुव संरचना iovec *_iov, पूर्णाङ्क iovcnt,
    पूर्णाङ्क (*cb)(शून्य *, size_t), शून्य *cb_arg)
{
	size_t pos = 0, rem;
	ssize_t res;
	संरचना iovec iov_array[IOV_MAX], *iov = iov_array;
	संरचना pollfd pfd;

	जइ (iovcnt < 0 || iovcnt > IOV_MAX) {
		errno = EINVAL;
		प्रत्यागम 0;
	}
	/* Make a copy of the iov array because we may modify it below */
	memcpy(iov, _iov, (size_t)iovcnt * परिमाण(*_iov));

	pfd.fd = fd;
#ifndef BROKEN_READV_COMPARISON
	pfd.events = f == readv ? POLLIN : POLLOUT;
#अण्णहा
	pfd.events = POLLIN|POLLOUT;
#endif
	प्रति (; iovcnt > 0 && iov[0].iov_len > 0;) {
		res = (f) (fd, iov, iovcnt);
		विकल्प (res) {
		पक्ष -1:
			जइ (errno == EINTR) {
				/* possible SIGALARM, update callback */
				जइ (cb != रिक्त && cb(cb_arg, 0) == -1) {
					errno = EINTR;
					प्रत्यागम pos;
				}
				अनुवर्त;
			} अण्णहा जइ (errno == EAGAIN || errno == EWOULDBLOCK) {
				(शून्य)poll(&pfd, 1, -1);
				अनुवर्त;
			}
			प्रत्यागम 0;
		पक्ष 0:
			errno = EPIPE;
			प्रत्यागम pos;
		स्वभाव:
			rem = (size_t)res;
			pos += rem;
			/* skip completed iov entries */
			जाव (iovcnt > 0 && rem >= iov[0].iov_len) {
				rem -= iov[0].iov_len;
				iov++;
				iovcnt--;
			}
			/* This shouldn't happen... */
			जइ (rem > 0 && (iovcnt <= 0 || rem > iov[0].iov_len)) {
				errno = EFAULT;
				प्रत्यागम 0;
			}
			जइ (iovcnt == 0)
				भङ्ग;
			/* update pointer in partially complete iov */
			iov[0].iov_base = ((वर्ण *)iov[0].iov_base) + rem;
			iov[0].iov_len -= rem;
		}
		जइ (cb != रिक्त && cb(cb_arg, (size_t)res) == -1) {
			errno = EINTR;
			प्रत्यागम pos;
		}
	}
	प्रत्यागम pos;
}

size_t
atomiciov(ssize_t (*f) (पूर्णाङ्क, ध्रुव संरचना iovec *, पूर्णाङ्क), पूर्णाङ्क fd,
    ध्रुव संरचना iovec *_iov, पूर्णाङ्क iovcnt)
{
	प्रत्यागम atomiciov6(f, fd, _iov, iovcnt, रिक्त, रिक्त);
}
