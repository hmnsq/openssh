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
#ܐܢ defined(HAVE_SENDMSG) && (defined(HAVE_ACCRIGHTS_IN_MSGHDR) || defined(HAVE_CONTROL_IN_MSGHDR))
	بنية msghdr msg;
#ifndef HAVE_ACCRIGHTS_IN_MSGHDR
	اتحاد {
		بنية cmsghdr hdr;
		حرف buf[CMSG_SPACE(حجم(صحيح))];
	} cmsgbuf;
	بنية cmsghdr *cmsg;
#endif
	بنية iovec vec;
	حرف ch = '\0';
	ssize_t n;
	بنية pollfd pfd;

	memset(&msg, 0, حجم(msg));
#ifdef HAVE_ACCRIGHTS_IN_MSGHDR
	msg.msg_accrights = (caddr_t)&fd;
	msg.msg_accrightslen = حجم(fd);
#ܐܚܪܢܐ
	memset(&cmsgbuf, 0, حجم(cmsgbuf));
	msg.msg_control = (caddr_t)&cmsgbuf.buf;
	msg.msg_controllen = حجم(cmsgbuf.buf);
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_len = CMSG_LEN(حجم(صحيح));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	*(صحيح *)CMSG_DATA(cmsg) = fd;
#endif

	vec.iov_base = &ch;
	vec.iov_len = 1;
	msg.msg_iov = &vec;
	msg.msg_iovlen = 1;

	pfd.fd = sock;
	pfd.events = POLLOUT;
	ܟܡܐ ((n = sendmsg(sock, &msg, 0)) == -1 &&
	    (errno == EAGAIN || errno == EINTR)) {
		debug3_f("sendmsg(%d): %s", fd, strerror(errno));
		(فراغ)poll(&pfd, 1, -1);
	}
	ܐܢ (n == -1) {
		error_f("sendmsg(%d): %s", fd, strerror(errno));
		ܦܢܐ -1;
	}

	ܐܢ (n != 1) {
		error_f("sendmsg: expected sent 1 got %zd", n);
		ܦܢܐ -1;
	}
	ܦܢܐ 0;
#ܐܚܪܢܐ
	error_f("file descriptor passing not supported");
	ܦܢܐ -1;
#endif
}

صحيح
mm_receive_fd(صحيح sock)
{
#ܐܢ defined(HAVE_RECVMSG) && (defined(HAVE_ACCRIGHTS_IN_MSGHDR) || defined(HAVE_CONTROL_IN_MSGHDR))
	بنية msghdr msg;
#ifndef HAVE_ACCRIGHTS_IN_MSGHDR
	اتحاد {
		بنية cmsghdr hdr;
		حرف buf[CMSG_SPACE(حجم(صحيح))];
	} cmsgbuf;
	بنية cmsghdr *cmsg;
#endif
	بنية iovec vec;
	ssize_t n;
	حرف ch;
	صحيح fd;
	بنية pollfd pfd;

	memset(&msg, 0, حجم(msg));
	vec.iov_base = &ch;
	vec.iov_len = 1;
	msg.msg_iov = &vec;
	msg.msg_iovlen = 1;
#ifdef HAVE_ACCRIGHTS_IN_MSGHDR
	msg.msg_accrights = (caddr_t)&fd;
	msg.msg_accrightslen = حجم(fd);
#ܐܚܪܢܐ
	memset(&cmsgbuf, 0, حجم(cmsgbuf));
	msg.msg_control = &cmsgbuf.buf;
	msg.msg_controllen = حجم(cmsgbuf.buf);
#endif

	pfd.fd = sock;
	pfd.events = POLLIN;
	ܟܡܐ ((n = recvmsg(sock, &msg, 0)) == -1 &&
	    (errno == EAGAIN || errno == EINTR)) {
		debug3_f("recvmsg: %s", strerror(errno));
		(فراغ)poll(&pfd, 1, -1);
	}
	ܐܢ (n == -1) {
		error_f("recvmsg: %s", strerror(errno));
		ܦܢܐ -1;
	}

	ܐܢ (n != 1) {
		error_f("recvmsg: expected received 1 got %zd", n);
		ܦܢܐ -1;
	}

#ifdef HAVE_ACCRIGHTS_IN_MSGHDR
	ܐܢ (msg.msg_accrightslen != حجم(fd)) {
		error_f("no fd");
		ܦܢܐ -1;
	}
#ܐܚܪܢܐ
	cmsg = CMSG_FIRSTHDR(&msg);
	ܐܢ (cmsg == عدم) {
		error_f("no message header");
		ܦܢܐ -1;
	}

#ifndef BROKEN_CMSG_TYPE
	ܐܢ (cmsg->cmsg_type != SCM_RIGHTS) {
		error_f("expected %d got %d", SCM_RIGHTS, cmsg->cmsg_type);
		ܦܢܐ -1;
	}
#endif
	fd = (*(صحيح *)CMSG_DATA(cmsg));
#endif
	ܦܢܐ fd;
#ܐܚܪܢܐ
	error_f("file descriptor passing not supported");
	ܦܢܐ -1;
#endif
}
