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

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <sys/socket.h>
#ضمن <sys/uio.h>
#ضمن <sys/un.h>

#ضمن <errno.h>
#ضمن <poll.h>
#ضمن <string.h>
#ضمن <stdarg.h>

#ضمن "log.h"
#ضمن "monitor_fdpass.h"

صحيح
mm_send_fd(صحيح sock, صحيح fd)
{
#إذا defined(HAVE_SENDMSG) && (defined(HAVE_ACCRIGHTS_اندريون_MSGHDR) || defined(HAVE_CONTROL_اندريون_MSGHDR))
	بنية msghdr نياپو;
#جيڪڏهن_وصف_نه_ٿيل HAVE_ACCRIGHTS_اندريون_MSGHDR
	اتحاد {
		بنية cmsghdr hdr;
		حرف buf[CMSG_SPACE(حجم(صحيح))];
	} cmsgbuf;
	بنية cmsghdr *cmsg;
#جيڪڏهن_پورو
	بنية iovec vec;
	حرف ch = '\0';
	ssize_t n;
	بنية pollfd pfd;

	memset(&نياپو, 0, حجم(نياپو));
#جيڪڏهن_وصف_ٿيل HAVE_ACCRIGHTS_اندريون_MSGHDR
	نياپو.نياپو_accrights = (caddr_t)&fd;
	نياپو.نياپو_accrightslen = حجم(fd);
#وإلا
	memset(&cmsgbuf, 0, حجم(cmsgbuf));
	نياپو.msg_control = (caddr_t)&cmsgbuf.buf;
	نياپو.msg_controllen = حجم(cmsgbuf.buf);
	cmsg = CMSG_FIRSTHDR(&نياپو);
	cmsg->cmsg_len = CMSG_LEN(حجم(صحيح));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	*(صحيح *)CMSG_DATA(cmsg) = fd;
#جيڪڏهن_پورو

	vec.iov_base = &ch;
	vec.iov_len = 1;
	نياپو.msg_iov = &vec;
	نياپو.msg_iovlen = 1;

	pfd.fd = sock;
	pfd.events = POLLOUT;
	طالما ((n = sendmsg(sock, &نياپو, 0)) == -1 &&
	    (errno == EAGAIN || errno == EINTR)) {
		debug3_f("sendmsg(%d): %s", fd, strerror(errno));
		(فراغ)poll(&pfd, 1, -1);
	}
	إذا (n == -1) {
		error_f("sendmsg(%d): %s", fd, strerror(errno));
		أرجع -1;
	}

	إذا (n != 1) {
		error_f("sendmsg: expected sent 1 got %zd", n);
		أرجع -1;
	}
	أرجع 0;
#وإلا
	error_f("file descriptor passing not supported");
	أرجع -1;
#جيڪڏهن_پورو
}

صحيح
mm_receive_fd(صحيح sock)
{
#إذا defined(HAVE_RECVMSG) && (defined(HAVE_ACCRIGHTS_اندريون_MSGHDR) || defined(HAVE_CONTROL_اندريون_MSGHDR))
	بنية msghdr نياپو;
#جيڪڏهن_وصف_نه_ٿيل HAVE_ACCRIGHTS_اندريون_MSGHDR
	اتحاد {
		بنية cmsghdr hdr;
		حرف buf[CMSG_SPACE(حجم(صحيح))];
	} cmsgbuf;
	بنية cmsghdr *cmsg;
#جيڪڏهن_پورو
	بنية iovec vec;
	ssize_t n;
	حرف ch;
	صحيح fd;
	بنية pollfd pfd;

	memset(&نياپو, 0, حجم(نياپو));
	vec.iov_base = &ch;
	vec.iov_len = 1;
	نياپو.msg_iov = &vec;
	نياپو.msg_iovlen = 1;
#جيڪڏهن_وصف_ٿيل HAVE_ACCRIGHTS_اندريون_MSGHDR
	نياپو.نياپو_accrights = (caddr_t)&fd;
	نياپو.نياپو_accrightslen = حجم(fd);
#وإلا
	memset(&cmsgbuf, 0, حجم(cmsgbuf));
	نياپو.msg_control = &cmsgbuf.buf;
	نياپو.msg_controllen = حجم(cmsgbuf.buf);
#جيڪڏهن_پورو

	pfd.fd = sock;
	pfd.events = POLLIN;
	طالما ((n = recvmsg(sock, &نياپو, 0)) == -1 &&
	    (errno == EAGAIN || errno == EINTR)) {
		debug3_f("recvmsg: %s", strerror(errno));
		(فراغ)poll(&pfd, 1, -1);
	}
	إذا (n == -1) {
		error_f("recvmsg: %s", strerror(errno));
		أرجع -1;
	}

	إذا (n != 1) {
		error_f("recvmsg: expected received 1 got %zd", n);
		أرجع -1;
	}

#جيڪڏهن_وصف_ٿيل HAVE_ACCRIGHTS_اندريون_MSGHDR
	إذا (نياپو.نياپو_accrightslen != حجم(fd)) {
		error_f("no fd");
		أرجع -1;
	}
#وإلا
	cmsg = CMSG_FIRSTHDR(&نياپو);
	إذا (cmsg == عدم) {
		error_f("no message header");
		أرجع -1;
	}

#جيڪڏهن_وصف_نه_ٿيل BROKEN_CMSG_TYPE
	إذا (cmsg->cmsg_type != SCM_RIGHTS) {
		error_f("expected %d got %d", SCM_RIGHTS, cmsg->cmsg_type);
		أرجع -1;
	}
#جيڪڏهن_پورو
	fd = (*(صحيح *)CMSG_DATA(cmsg));
#جيڪڏهن_پورو
	أرجع fd;
#وإلا
	error_f("file descriptor passing not supported");
	أرجع -1;
#جيڪڏهن_پورو
}
