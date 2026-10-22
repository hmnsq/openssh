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
माप_प्रकार
atomicio6(ssize_t (*f) (पूर्णाङ्क, शून्य *, माप_प्रकार), पूर्णाङ्क fd, शून्य *_s, माप_प्रकार n,
    पूर्णाङ्क (*cb)(शून्य *, माप_प्रकार), शून्य *cb_arg)
{
	वर्ण *s = _s;
	माप_प्रकार pos = 0;
	ssize_t res;
	संरचना pollfd pfd;

	pfd.fd = fd;
	pfd.events = f == पठ ? POLLIN : POLLOUT;
	यावत् (n > pos) {
		res = (f) (fd, s + pos, n - pos);
		विकल्प (res) {
		पक्ष -1:
			यदि (त्रुटि_सं == EINTR) {
				/* possible SIGALARM, update callback */
				यदि (cb != रिक्त && cb(cb_arg, 0) == -1) {
					त्रुटि_सं = EINTR;
					प्रत्यागम pos;
				}
				अनुवर्त;
			} अन्यथा यदि (त्रुटि_सं == EAGAIN || त्रुटि_सं == EWOULDBLOCK) {
				(शून्य)poll(&pfd, 1, -1);
				अनुवर्त;
			}
			प्रत्यागम 0;
		पक्ष 0:
			त्रुटि_सं = EPIPE;
			प्रत्यागम pos;
		स्वभाव:
			pos += (माप_प्रकार)res;
			यदि (cb != रिक्त && cb(cb_arg, (माप_प्रकार)res) == -1) {
				त्रुटि_सं = EINTR;
				प्रत्यागम pos;
			}
		}
	}
	प्रत्यागम pos;
}

माप_प्रकार
atomicio(ssize_t (*f) (पूर्णाङ्क, शून्य *, माप_प्रकार), पूर्णाङ्क fd, शून्य *_s, माप_प्रकार n)
{
	प्रत्यागम atomicio6(f, fd, _s, n, रिक्त, रिक्त);
}

/*
 * ensure all of data on socket comes through. f==readv || f==writev
 */
माप_प्रकार
atomiciov6(ssize_t (*f) (पूर्णाङ्क, ध्रुव संरचना iovec *, पूर्णाङ्क), पूर्णाङ्क fd,
    ध्रुव संरचना iovec *_iov, पूर्णाङ्क iovcnt,
    पूर्णाङ्क (*cb)(शून्य *, माप_प्रकार), शून्य *cb_arg)
{
	माप_प्रकार pos = 0, rem;
	ssize_t res;
	संरचना iovec iov_array[IOV_MAX], *iov = iov_array;
	संरचना pollfd pfd;

	यदि (iovcnt < 0 || iovcnt > IOV_MAX) {
		त्रुटि_सं = EINVAL;
		प्रत्यागम 0;
	}
	/* Make a copy of the iov array because we may modify it below */
	स_नकल(iov, _iov, (माप_प्रकार)iovcnt * परिमाण(*_iov));

	pfd.fd = fd;
#ifndef BROKEN_READV_COMPARISON
	pfd.events = f == readv ? POLLIN : POLLOUT;
#अन्यथा
	pfd.events = POLLIN|POLLOUT;
#endif
	प्रति (; iovcnt > 0 && iov[0].iov_len > 0;) {
		res = (f) (fd, iov, iovcnt);
		विकल्प (res) {
		पक्ष -1:
			यदि (त्रुटि_सं == EINTR) {
				/* possible SIGALARM, update callback */
				यदि (cb != रिक्त && cb(cb_arg, 0) == -1) {
					त्रुटि_सं = EINTR;
					प्रत्यागम pos;
				}
				अनुवर्त;
			} अन्यथा यदि (त्रुटि_सं == EAGAIN || त्रुटि_सं == EWOULDBLOCK) {
				(शून्य)poll(&pfd, 1, -1);
				अनुवर्त;
			}
			प्रत्यागम 0;
		पक्ष 0:
			त्रुटि_सं = EPIPE;
			प्रत्यागम pos;
		स्वभाव:
			rem = (माप_प्रकार)res;
			pos += rem;
			/* skip completed iov entries */
			यावत् (iovcnt > 0 && rem >= iov[0].iov_len) {
				rem -= iov[0].iov_len;
				iov++;
				iovcnt--;
			}
			/* This shouldn't happen... */
			यदि (rem > 0 && (iovcnt <= 0 || rem > iov[0].iov_len)) {
				त्रुटि_सं = EFAULT;
				प्रत्यागम 0;
			}
			यदि (iovcnt == 0)
				भङ्ग;
			/* update pointer in partially complete iov */
			iov[0].iov_base = ((वर्ण *)iov[0].iov_base) + rem;
			iov[0].iov_len -= rem;
		}
		यदि (cb != रिक्त && cb(cb_arg, (माप_प्रकार)res) == -1) {
			त्रुटि_सं = EINTR;
			प्रत्यागम pos;
		}
	}
	प्रत्यागम pos;
}

माप_प्रकार
atomiciov(ssize_t (*f) (पूर्णाङ्क, ध्रुव संरचना iovec *, पूर्णाङ्क), पूर्णाङ्क fd,
    ध्रुव संरचना iovec *_iov, पूर्णाङ्क iovcnt)
{
	प्रत्यागम atomiciov6(f, fd, _iov, iovcnt, रिक्त, रिक्त);
}
