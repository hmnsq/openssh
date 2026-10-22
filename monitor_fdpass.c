/* $OpenBSD: monitor_fdpass.c,v 1.23 2026/02/08 19:54:31 dtucker Exp $ */
/*
 * Copyright 2001 Niels Provos <provos@citi.umich.edu>
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

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/socket.h>
#अन्तर्भाव <sys/uio.h>
#अन्तर्भाव <sys/un.h>

#अन्तर्भाव <errno.h>
#अन्तर्भाव <poll.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <stdarg.h>

#अन्तर्भाव "log.h"
#अन्तर्भाव "monitor_fdpass.h"

पूर्णांक
mm_send_fd(पूर्णांक sock, पूर्णांक fd)
{
#जर defined(HAVE_SENDMSG) && (defined(HAVE_ACCRIGHTS_IN_MSGHDR) || defined(HAVE_CONTROL_IN_MSGHDR))
	संरचना msghdr संदेश;
#ifndef HAVE_ACCRIGHTS_IN_MSGHDR
	संघ {
		संरचना cmsghdr hdr;
		अक्षर buf[CMSG_SPACE(आकार(पूर्णांक))];
	} cmsgbuf;
	संरचना cmsghdr *cmsg;
#endif
	संरचना iovec vec;
	अक्षर ch = '\0';
	ssize_t n;
	संरचना pollfd pfd;

	स_रखो(&संदेश, 0, आकार(संदेश));
#ifdef HAVE_ACCRIGHTS_IN_MSGHDR
	संदेश.संदेश_accrights = (caddr_t)&fd;
	संदेश.संदेश_accrightslen = आकार(fd);
#अन्यथा
	स_रखो(&cmsgbuf, 0, आकार(cmsgbuf));
	संदेश.msg_control = (caddr_t)&cmsgbuf.buf;
	संदेश.msg_controllen = आकार(cmsgbuf.buf);
	cmsg = CMSG_FIRSTHDR(&संदेश);
	cmsg->cmsg_len = CMSG_LEN(आकार(पूर्णांक));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	*(पूर्णांक *)CMSG_DATA(cmsg) = fd;
#endif

	vec.iov_base = &ch;
	vec.iov_len = 1;
	संदेश.msg_iov = &vec;
	संदेश.msg_iovlen = 1;

	pfd.fd = sock;
	pfd.events = POLLOUT;
	पर्यंत ((n = sendmsg(sock, &संदेश, 0)) == -1 &&
	    (त्रुटि_सं == EAGAIN || त्रुटि_सं == EINTR)) {
		debug3_f("sendmsg(%d): %s", fd, म_त्रुटि(त्रुटि_सं));
		(शून्य)poll(&pfd, 1, -1);
	}
	जर (n == -1) {
		error_f("sendmsg(%d): %s", fd, म_त्रुटि(त्रुटि_सं));
		परत -1;
	}

	जर (n != 1) {
		error_f("sendmsg: expected sent 1 got %zd", n);
		परत -1;
	}
	परत 0;
#अन्यथा
	error_f("file descriptor passing not supported");
	परत -1;
#endif
}

पूर्णांक
mm_receive_fd(पूर्णांक sock)
{
#जर defined(HAVE_RECVMSG) && (defined(HAVE_ACCRIGHTS_IN_MSGHDR) || defined(HAVE_CONTROL_IN_MSGHDR))
	संरचना msghdr संदेश;
#ifndef HAVE_ACCRIGHTS_IN_MSGHDR
	संघ {
		संरचना cmsghdr hdr;
		अक्षर buf[CMSG_SPACE(आकार(पूर्णांक))];
	} cmsgbuf;
	संरचना cmsghdr *cmsg;
#endif
	संरचना iovec vec;
	ssize_t n;
	अक्षर ch;
	पूर्णांक fd;
	संरचना pollfd pfd;

	स_रखो(&संदेश, 0, आकार(संदेश));
	vec.iov_base = &ch;
	vec.iov_len = 1;
	संदेश.msg_iov = &vec;
	संदेश.msg_iovlen = 1;
#ifdef HAVE_ACCRIGHTS_IN_MSGHDR
	संदेश.संदेश_accrights = (caddr_t)&fd;
	संदेश.संदेश_accrightslen = आकार(fd);
#अन्यथा
	स_रखो(&cmsgbuf, 0, आकार(cmsgbuf));
	संदेश.msg_control = &cmsgbuf.buf;
	संदेश.msg_controllen = आकार(cmsgbuf.buf);
#endif

	pfd.fd = sock;
	pfd.events = POLLIN;
	पर्यंत ((n = recvmsg(sock, &संदेश, 0)) == -1 &&
	    (त्रुटि_सं == EAGAIN || त्रुटि_सं == EINTR)) {
		debug3_f("recvmsg: %s", म_त्रुटि(त्रुटि_सं));
		(शून्य)poll(&pfd, 1, -1);
	}
	जर (n == -1) {
		error_f("recvmsg: %s", म_त्रुटि(त्रुटि_सं));
		परत -1;
	}

	जर (n != 1) {
		error_f("recvmsg: expected received 1 got %zd", n);
		परत -1;
	}

#ifdef HAVE_ACCRIGHTS_IN_MSGHDR
	जर (संदेश.संदेश_accrightslen != आकार(fd)) {
		error_f("no fd");
		परत -1;
	}
#अन्यथा
	cmsg = CMSG_FIRSTHDR(&संदेश);
	जर (cmsg == रिक्त) {
		error_f("no message header");
		परत -1;
	}

#ifndef BROKEN_CMSG_TYPE
	जर (cmsg->cmsg_type != SCM_RIGHTS) {
		error_f("expected %d got %d", SCM_RIGHTS, cmsg->cmsg_type);
		परत -1;
	}
#endif
	fd = (*(पूर्णांक *)CMSG_DATA(cmsg));
#endif
	परत fd;
#अन्यथा
	error_f("file descriptor passing not supported");
	परत -1;
#endif
}
