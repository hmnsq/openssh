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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/socket.h>
#شامل <sys/uio.h>
#شامل <sys/un.h>

#شامل <errno.h>
#شامل <poll.h>
#شامل <string.h>
#شامل <stdarg.h>

#شامل "log.h"
#شامل "monitor_fdpass.h"

صحیح
mm_send_fd(صحیح sock, صحیح fd)
{
#اگر defined(HAVE_SENDMSG) && (defined(HAVE_ACCRIGHTS_IN_MSGHDR) || defined(HAVE_CONTROL_IN_MSGHDR))
	ساختار msghdr پیام;
#ifndef HAVE_ACCRIGHTS_IN_MSGHDR
	اجتماع {
		ساختار cmsghdr hdr;
		نویسه buf[CMSG_SPACE(اندازه(صحیح))];
	} cmsgbuf;
	ساختار cmsghdr *cmsg;
#endif
	ساختار iovec vec;
	نویسه ch = '\0';
	ssize_t n;
	ساختار pollfd pfd;

	memset(&پیام, 0, اندازه(پیام));
#ifdef HAVE_ACCRIGHTS_IN_MSGHDR
	پیام.پیام_accrights = (caddr_t)&fd;
	پیام.پیام_accrightslen = اندازه(fd);
#وگرنه
	memset(&cmsgbuf, 0, اندازه(cmsgbuf));
	پیام.msg_control = (caddr_t)&cmsgbuf.buf;
	پیام.msg_controllen = اندازه(cmsgbuf.buf);
	cmsg = CMSG_FIRSTHDR(&پیام);
	cmsg->cmsg_len = CMSG_LEN(اندازه(صحیح));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	*(صحیح *)CMSG_DATA(cmsg) = fd;
#endif

	vec.iov_base = &ch;
	vec.iov_len = 1;
	پیام.msg_iov = &vec;
	پیام.msg_iovlen = 1;

	pfd.fd = sock;
	pfd.events = POLLOUT;
	وقتی ((n = sendmsg(sock, &پیام, 0)) == -1 &&
	    (errno == EAGAIN || errno == EINTR)) {
		debug3_f("sendmsg(%d): %s", fd, strerror(errno));
		(تهی)poll(&pfd, 1, -1);
	}
	اگر (n == -1) {
		error_f("sendmsg(%d): %s", fd, strerror(errno));
		بازگشت -1;
	}

	اگر (n != 1) {
		error_f("sendmsg: expected sent 1 got %zd", n);
		بازگشت -1;
	}
	بازگشت 0;
#وگرنه
	error_f("file descriptor passing not supported");
	بازگشت -1;
#endif
}

صحیح
mm_receive_fd(صحیح sock)
{
#اگر defined(HAVE_RECVMSG) && (defined(HAVE_ACCRIGHTS_IN_MSGHDR) || defined(HAVE_CONTROL_IN_MSGHDR))
	ساختار msghdr پیام;
#ifndef HAVE_ACCRIGHTS_IN_MSGHDR
	اجتماع {
		ساختار cmsghdr hdr;
		نویسه buf[CMSG_SPACE(اندازه(صحیح))];
	} cmsgbuf;
	ساختار cmsghdr *cmsg;
#endif
	ساختار iovec vec;
	ssize_t n;
	نویسه ch;
	صحیح fd;
	ساختار pollfd pfd;

	memset(&پیام, 0, اندازه(پیام));
	vec.iov_base = &ch;
	vec.iov_len = 1;
	پیام.msg_iov = &vec;
	پیام.msg_iovlen = 1;
#ifdef HAVE_ACCRIGHTS_IN_MSGHDR
	پیام.پیام_accrights = (caddr_t)&fd;
	پیام.پیام_accrightslen = اندازه(fd);
#وگرنه
	memset(&cmsgbuf, 0, اندازه(cmsgbuf));
	پیام.msg_control = &cmsgbuf.buf;
	پیام.msg_controllen = اندازه(cmsgbuf.buf);
#endif

	pfd.fd = sock;
	pfd.events = POLLIN;
	وقتی ((n = recvmsg(sock, &پیام, 0)) == -1 &&
	    (errno == EAGAIN || errno == EINTR)) {
		debug3_f("recvmsg: %s", strerror(errno));
		(تهی)poll(&pfd, 1, -1);
	}
	اگر (n == -1) {
		error_f("recvmsg: %s", strerror(errno));
		بازگشت -1;
	}

	اگر (n != 1) {
		error_f("recvmsg: expected received 1 got %zd", n);
		بازگشت -1;
	}

#ifdef HAVE_ACCRIGHTS_IN_MSGHDR
	اگر (پیام.پیام_accrightslen != اندازه(fd)) {
		error_f("no fd");
		بازگشت -1;
	}
#وگرنه
	cmsg = CMSG_FIRSTHDR(&پیام);
	اگر (cmsg == پوچ) {
		error_f("no message header");
		بازگشت -1;
	}

#ifndef BROKEN_CMSG_TYPE
	اگر (cmsg->cmsg_type != SCM_RIGHTS) {
		error_f("expected %d got %d", SCM_RIGHTS, cmsg->cmsg_type);
		بازگشت -1;
	}
#endif
	fd = (*(صحیح *)CMSG_DATA(cmsg));
#endif
	بازگشت fd;
#وگرنه
	error_f("file descriptor passing not supported");
	بازگشت -1;
#endif
}
