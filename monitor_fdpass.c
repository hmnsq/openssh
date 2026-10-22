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

पूर्णाङ्क
mm_send_fd(पूर्णाङ्क sock, पूर्णाङ्क fd)
{
#जइ defined(HAVE_SENDMSG) && (defined(HAVE_ACCRIGHTS_IN_MSGHDR) || defined(HAVE_CONTROL_IN_MSGHDR))
	संरचना msghdr सन्देशः;
#ifndef HAVE_ACCRIGHTS_IN_MSGHDR
	सङ्घ {
		संरचना cmsghdr hdr;
		वर्ण buf[CMSG_SPACE(परिमाण(पूर्णाङ्क))];
	} cmsgbuf;
	संरचना cmsghdr *cmsg;
#endif
	संरचना iovec vec;
	वर्ण ch = '\0';
	ssize_t n;
	संरचना pollfd pfd;

	memset(&सन्देशः, 0, परिमाण(सन्देशः));
#ifdef HAVE_ACCRIGHTS_IN_MSGHDR
	सन्देशः.सन्देशः_accrights = (caddr_t)&fd;
	सन्देशः.सन्देशः_accrightslen = परिमाण(fd);
#अण्णहा
	memset(&cmsgbuf, 0, परिमाण(cmsgbuf));
	सन्देशः.msg_control = (caddr_t)&cmsgbuf.buf;
	सन्देशः.msg_controllen = परिमाण(cmsgbuf.buf);
	cmsg = CMSG_FIRSTHDR(&सन्देशः);
	cmsg->cmsg_len = CMSG_LEN(परिमाण(पूर्णाङ्क));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	*(पूर्णाङ्क *)CMSG_DATA(cmsg) = fd;
#endif

	vec.iov_base = &ch;
	vec.iov_len = 1;
	सन्देशः.msg_iov = &vec;
	सन्देशः.msg_iovlen = 1;

	pfd.fd = sock;
	pfd.events = POLLOUT;
	जाव ((n = sendmsg(sock, &सन्देशः, 0)) == -1 &&
	    (errno == EAGAIN || errno == EINTR)) {
		debug3_f("sendmsg(%d): %s", fd, strerror(errno));
		(शून्य)poll(&pfd, 1, -1);
	}
	जइ (n == -1) {
		error_f("sendmsg(%d): %s", fd, strerror(errno));
		प्रत्यागम -1;
	}

	जइ (n != 1) {
		error_f("sendmsg: expected sent 1 got %zd", n);
		प्रत्यागम -1;
	}
	प्रत्यागम 0;
#अण्णहा
	error_f("file descriptor passing not supported");
	प्रत्यागम -1;
#endif
}

पूर्णाङ्क
mm_receive_fd(पूर्णाङ्क sock)
{
#जइ defined(HAVE_RECVMSG) && (defined(HAVE_ACCRIGHTS_IN_MSGHDR) || defined(HAVE_CONTROL_IN_MSGHDR))
	संरचना msghdr सन्देशः;
#ifndef HAVE_ACCRIGHTS_IN_MSGHDR
	सङ्घ {
		संरचना cmsghdr hdr;
		वर्ण buf[CMSG_SPACE(परिमाण(पूर्णाङ्क))];
	} cmsgbuf;
	संरचना cmsghdr *cmsg;
#endif
	संरचना iovec vec;
	ssize_t n;
	वर्ण ch;
	पूर्णाङ्क fd;
	संरचना pollfd pfd;

	memset(&सन्देशः, 0, परिमाण(सन्देशः));
	vec.iov_base = &ch;
	vec.iov_len = 1;
	सन्देशः.msg_iov = &vec;
	सन्देशः.msg_iovlen = 1;
#ifdef HAVE_ACCRIGHTS_IN_MSGHDR
	सन्देशः.सन्देशः_accrights = (caddr_t)&fd;
	सन्देशः.सन्देशः_accrightslen = परिमाण(fd);
#अण्णहा
	memset(&cmsgbuf, 0, परिमाण(cmsgbuf));
	सन्देशः.msg_control = &cmsgbuf.buf;
	सन्देशः.msg_controllen = परिमाण(cmsgbuf.buf);
#endif

	pfd.fd = sock;
	pfd.events = POLLIN;
	जाव ((n = recvmsg(sock, &सन्देशः, 0)) == -1 &&
	    (errno == EAGAIN || errno == EINTR)) {
		debug3_f("recvmsg: %s", strerror(errno));
		(शून्य)poll(&pfd, 1, -1);
	}
	जइ (n == -1) {
		error_f("recvmsg: %s", strerror(errno));
		प्रत्यागम -1;
	}

	जइ (n != 1) {
		error_f("recvmsg: expected received 1 got %zd", n);
		प्रत्यागम -1;
	}

#ifdef HAVE_ACCRIGHTS_IN_MSGHDR
	जइ (सन्देशः.सन्देशः_accrightslen != परिमाण(fd)) {
		error_f("no fd");
		प्रत्यागम -1;
	}
#अण्णहा
	cmsg = CMSG_FIRSTHDR(&सन्देशः);
	जइ (cmsg == रिक्त) {
		error_f("no message header");
		प्रत्यागम -1;
	}

#ifndef BROKEN_CMSG_TYPE
	जइ (cmsg->cmsg_type != SCM_RIGHTS) {
		error_f("expected %d got %d", SCM_RIGHTS, cmsg->cmsg_type);
		प्रत्यागम -1;
	}
#endif
	fd = (*(पूर्णाङ्क *)CMSG_DATA(cmsg));
#endif
	प्रत्यागम fd;
#अण्णहा
	error_f("file descriptor passing not supported");
	प्रत्यागम -1;
#endif
}
