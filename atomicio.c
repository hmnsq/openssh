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

#समावेश "includes.h"

#समावेश <sys/uio.h>

#समावेश <errno.h>
#समावेश <poll.h>
#समावेश <string.h>
#समावेश <unistd.h>
#समावेश <limits.h>

#समावेश "atomicio.h"

/*
 * ensure all of data on socket comes through. f==read || f==vwrite
 */
माप_प्रकार
atomicio6(ssize_t (*f) (पूर्णांक, व्योम *, माप_प्रकार), पूर्णांक fd, व्योम *_s, माप_प्रकार n,
    पूर्णांक (*cb)(व्योम *, माप_प्रकार), व्योम *cb_arg)
{
	अक्षर *s = _s;
	माप_प्रकार pos = 0;
	ssize_t res;
	काष्ठा pollfd pfd;

	pfd.fd = fd;
	pfd.events = f == पढ़ो ? POLLIN : POLLOUT;
	जबतक (n > pos) {
		res = (f) (fd, s + pos, n - pos);
		चयन (res) {
		हाल -1:
			अगर (त्रुटि_सं == EINTR) {
				/* possible SIGALARM, update callback */
				अगर (cb != शून्य && cb(cb_arg, 0) == -1) {
					त्रुटि_सं = EINTR;
					वापस pos;
				}
				जारी;
			} अन्यथा अगर (त्रुटि_सं == EAGAIN || त्रुटि_सं == EWOULDBLOCK) {
				(व्योम)poll(&pfd, 1, -1);
				जारी;
			}
			वापस 0;
		हाल 0:
			त्रुटि_सं = EPIPE;
			वापस pos;
		शेष:
			pos += (माप_प्रकार)res;
			अगर (cb != शून्य && cb(cb_arg, (माप_प्रकार)res) == -1) {
				त्रुटि_सं = EINTR;
				वापस pos;
			}
		}
	}
	वापस pos;
}

माप_प्रकार
atomicio(ssize_t (*f) (पूर्णांक, व्योम *, माप_प्रकार), पूर्णांक fd, व्योम *_s, माप_प्रकार n)
{
	वापस atomicio6(f, fd, _s, n, शून्य, शून्य);
}

/*
 * ensure all of data on socket comes through. f==readv || f==writev
 */
माप_प्रकार
atomiciov6(ssize_t (*f) (पूर्णांक, स्थिर काष्ठा iovec *, पूर्णांक), पूर्णांक fd,
    स्थिर काष्ठा iovec *_iov, पूर्णांक iovcnt,
    पूर्णांक (*cb)(व्योम *, माप_प्रकार), व्योम *cb_arg)
{
	माप_प्रकार pos = 0, rem;
	ssize_t res;
	काष्ठा iovec iov_array[IOV_MAX], *iov = iov_array;
	काष्ठा pollfd pfd;

	अगर (iovcnt < 0 || iovcnt > IOV_MAX) {
		त्रुटि_सं = EINVAL;
		वापस 0;
	}
	/* Make a copy of the iov array because we may modify it below */
	स_नकल(iov, _iov, (माप_प्रकार)iovcnt * माप(*_iov));

	pfd.fd = fd;
#अगर_अघोषित BROKEN_READV_COMPARISON
	pfd.events = f == readv ? POLLIN : POLLOUT;
#अन्यथा
	pfd.events = POLLIN|POLLOUT;
#पूर्ण_अगर
	क्रम (; iovcnt > 0 && iov[0].iov_len > 0;) {
		res = (f) (fd, iov, iovcnt);
		चयन (res) {
		हाल -1:
			अगर (त्रुटि_सं == EINTR) {
				/* possible SIGALARM, update callback */
				अगर (cb != शून्य && cb(cb_arg, 0) == -1) {
					त्रुटि_सं = EINTR;
					वापस pos;
				}
				जारी;
			} अन्यथा अगर (त्रुटि_सं == EAGAIN || त्रुटि_सं == EWOULDBLOCK) {
				(व्योम)poll(&pfd, 1, -1);
				जारी;
			}
			वापस 0;
		हाल 0:
			त्रुटि_सं = EPIPE;
			वापस pos;
		शेष:
			rem = (माप_प्रकार)res;
			pos += rem;
			/* skip completed iov entries */
			जबतक (iovcnt > 0 && rem >= iov[0].iov_len) {
				rem -= iov[0].iov_len;
				iov++;
				iovcnt--;
			}
			/* This shouldn't happen... */
			अगर (rem > 0 && (iovcnt <= 0 || rem > iov[0].iov_len)) {
				त्रुटि_सं = EFAULT;
				वापस 0;
			}
			अगर (iovcnt == 0)
				अवरोध;
			/* update pointer in partially complete iov */
			iov[0].iov_base = ((अक्षर *)iov[0].iov_base) + rem;
			iov[0].iov_len -= rem;
		}
		अगर (cb != शून्य && cb(cb_arg, (माप_प्रकार)res) == -1) {
			त्रुटि_सं = EINTR;
			वापस pos;
		}
	}
	वापस pos;
}

माप_प्रकार
atomiciov(ssize_t (*f) (पूर्णांक, स्थिर काष्ठा iovec *, पूर्णांक), पूर्णांक fd,
    स्थिर काष्ठा iovec *_iov, पूर्णांक iovcnt)
{
	वापस atomiciov6(f, fd, _iov, iovcnt, शून्य, शून्य);
}
