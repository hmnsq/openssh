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
#إذا defined(HAVE_SENDMSG) && (defined(HAVE_ACCRIGHTS_درون_MSGHDR) || defined(HAVE_CONTROL_درون_MSGHDR))
	بنية msghdr پیام;
#اگر_تعریف_نشده HAVE_ACCRIGHTS_درون_MSGHDR
	اتحاد {
		بنية cmsghdr hdr;
		حرف buf[CMSG_SPACE(حجم(صحيح))];
	} cmsgbuf;
	بنية cmsghdr *cmsg;
#پایان_اگر
	بنية iovec vec;
	حرف ch = '\0';
	ssize_t n;
	بنية pollfd pfd;

	memset(&پیام, 0, حجم(پیام));
#اگر_تعریف_شده HAVE_ACCRIGHTS_درون_MSGHDR
	پیام.پیام_accrights = (caddr_t)&fd;
	پیام.پیام_accrightslen = حجم(fd);
#وإلا
	memset(&cmsgbuf, 0, حجم(cmsgbuf));
	پیام.msg_control = (caddr_t)&cmsgbuf.buf;
	پیام.msg_controllen = حجم(cmsgbuf.buf);
	cmsg = CMSG_FIRSTHDR(&پیام);
	cmsg->cmsg_len = CMSG_LEN(حجم(صحيح));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	*(صحيح *)CMSG_DATA(cmsg) = fd;
#پایان_اگر

	vec.iov_base = &ch;
	vec.iov_len = 1;
	پیام.msg_iov = &vec;
	پیام.msg_iovlen = 1;

	pfd.fd = sock;
	pfd.events = POLLOUT;
	طالما ((n = sendmsg(sock, &پیام, 0)) == -1 &&
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
#پایان_اگر
}

صحيح
mm_receive_fd(صحيح sock)
{
#إذا defined(HAVE_RECVMSG) && (defined(HAVE_ACCRIGHTS_درون_MSGHDR) || defined(HAVE_CONTROL_درون_MSGHDR))
	بنية msghdr پیام;
#اگر_تعریف_نشده HAVE_ACCRIGHTS_درون_MSGHDR
	اتحاد {
		بنية cmsghdr hdr;
		حرف buf[CMSG_SPACE(حجم(صحيح))];
	} cmsgbuf;
	بنية cmsghdr *cmsg;
#پایان_اگر
	بنية iovec vec;
	ssize_t n;
	حرف ch;
	صحيح fd;
	بنية pollfd pfd;

	memset(&پیام, 0, حجم(پیام));
	vec.iov_base = &ch;
	vec.iov_len = 1;
	پیام.msg_iov = &vec;
	پیام.msg_iovlen = 1;
#اگر_تعریف_شده HAVE_ACCRIGHTS_درون_MSGHDR
	پیام.پیام_accrights = (caddr_t)&fd;
	پیام.پیام_accrightslen = حجم(fd);
#وإلا
	memset(&cmsgbuf, 0, حجم(cmsgbuf));
	پیام.msg_control = &cmsgbuf.buf;
	پیام.msg_controllen = حجم(cmsgbuf.buf);
#پایان_اگر

	pfd.fd = sock;
	pfd.events = POLLIN;
	طالما ((n = recvmsg(sock, &پیام, 0)) == -1 &&
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

#اگر_تعریف_شده HAVE_ACCRIGHTS_درون_MSGHDR
	إذا (پیام.پیام_accrightslen != حجم(fd)) {
		error_f("no fd");
		أرجع -1;
	}
#وإلا
	cmsg = CMSG_FIRSTHDR(&پیام);
	إذا (cmsg == عدم) {
		error_f("no message header");
		أرجع -1;
	}

#اگر_تعریف_نشده BROKEN_CMSG_TYPE
	إذا (cmsg->cmsg_type != SCM_RIGHTS) {
		error_f("expected %d got %d", SCM_RIGHTS, cmsg->cmsg_type);
		أرجع -1;
	}
#پایان_اگر
	fd = (*(صحيح *)CMSG_DATA(cmsg));
#پایان_اگر
	أرجع fd;
#وإلا
	error_f("file descriptor passing not supported");
	أرجع -1;
#پایان_اگر
}
