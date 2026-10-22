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
#اگر defined(HAVE_SENDMSG) && (defined(HAVE_ACCRIGHTS_اندر_MSGHDR) || defined(HAVE_CONTROL_اندر_MSGHDR))
	ساخت msghdr پیغام;
#اگر_غیر_تعریف_شدہ HAVE_ACCRIGHTS_اندر_MSGHDR
	اتحاد {
		ساخت cmsghdr hdr;
		حرف buf[CMSG_SPACE(حجم(صحیح))];
	} cmsgbuf;
	ساخت cmsghdr *cmsg;
#اگر_ختم
	ساخت iovec vec;
	حرف ch = '\0';
	ssize_t n;
	ساخت pollfd pfd;

	memset(&پیغام, 0, حجم(پیغام));
#اگر_تعریف_شدہ HAVE_ACCRIGHTS_اندر_MSGHDR
	پیغام.پیغام_accrights = (caddr_t)&fd;
	پیغام.پیغام_accrightslen = حجم(fd);
#ورنہ
	memset(&cmsgbuf, 0, حجم(cmsgbuf));
	پیغام.msg_control = (caddr_t)&cmsgbuf.buf;
	پیغام.msg_controllen = حجم(cmsgbuf.buf);
	cmsg = CMSG_FIRSTHDR(&پیغام);
	cmsg->cmsg_len = CMSG_LEN(حجم(صحیح));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	*(صحیح *)CMSG_DATA(cmsg) = fd;
#اگر_ختم

	vec.iov_base = &ch;
	vec.iov_len = 1;
	پیغام.msg_iov = &vec;
	پیغام.msg_iovlen = 1;

	pfd.fd = sock;
	pfd.events = POLLOUT;
	جب ((n = sendmsg(sock, &پیغام, 0)) == -1 &&
	    (errno == EAGAIN || errno == EINTR)) {
		debug3_f("sendmsg(%d): %s", fd, strerror(errno));
		(خالی)poll(&pfd, 1, -1);
	}
	اگر (n == -1) {
		error_f("sendmsg(%d): %s", fd, strerror(errno));
		واپس -1;
	}

	اگر (n != 1) {
		error_f("sendmsg: expected sent 1 got %zd", n);
		واپس -1;
	}
	واپس 0;
#ورنہ
	error_f("file descriptor passing not supported");
	واپس -1;
#اگر_ختم
}

صحیح
mm_receive_fd(صحیح sock)
{
#اگر defined(HAVE_RECVMSG) && (defined(HAVE_ACCRIGHTS_اندر_MSGHDR) || defined(HAVE_CONTROL_اندر_MSGHDR))
	ساخت msghdr پیغام;
#اگر_غیر_تعریف_شدہ HAVE_ACCRIGHTS_اندر_MSGHDR
	اتحاد {
		ساخت cmsghdr hdr;
		حرف buf[CMSG_SPACE(حجم(صحیح))];
	} cmsgbuf;
	ساخت cmsghdr *cmsg;
#اگر_ختم
	ساخت iovec vec;
	ssize_t n;
	حرف ch;
	صحیح fd;
	ساخت pollfd pfd;

	memset(&پیغام, 0, حجم(پیغام));
	vec.iov_base = &ch;
	vec.iov_len = 1;
	پیغام.msg_iov = &vec;
	پیغام.msg_iovlen = 1;
#اگر_تعریف_شدہ HAVE_ACCRIGHTS_اندر_MSGHDR
	پیغام.پیغام_accrights = (caddr_t)&fd;
	پیغام.پیغام_accrightslen = حجم(fd);
#ورنہ
	memset(&cmsgbuf, 0, حجم(cmsgbuf));
	پیغام.msg_control = &cmsgbuf.buf;
	پیغام.msg_controllen = حجم(cmsgbuf.buf);
#اگر_ختم

	pfd.fd = sock;
	pfd.events = POLLIN;
	جب ((n = recvmsg(sock, &پیغام, 0)) == -1 &&
	    (errno == EAGAIN || errno == EINTR)) {
		debug3_f("recvmsg: %s", strerror(errno));
		(خالی)poll(&pfd, 1, -1);
	}
	اگر (n == -1) {
		error_f("recvmsg: %s", strerror(errno));
		واپس -1;
	}

	اگر (n != 1) {
		error_f("recvmsg: expected received 1 got %zd", n);
		واپس -1;
	}

#اگر_تعریف_شدہ HAVE_ACCRIGHTS_اندر_MSGHDR
	اگر (پیغام.پیغام_accrightslen != حجم(fd)) {
		error_f("no fd");
		واپس -1;
	}
#ورنہ
	cmsg = CMSG_FIRSTHDR(&پیغام);
	اگر (cmsg == تہی) {
		error_f("no message header");
		واپس -1;
	}

#اگر_غیر_تعریف_شدہ BROKEN_CMSG_TYPE
	اگر (cmsg->cmsg_type != SCM_RIGHTS) {
		error_f("expected %d got %d", SCM_RIGHTS, cmsg->cmsg_type);
		واپس -1;
	}
#اگر_ختم
	fd = (*(صحیح *)CMSG_DATA(cmsg));
#اگر_ختم
	واپس fd;
#ورنہ
	error_f("file descriptor passing not supported");
	واپس -1;
#اگر_ختم
}
