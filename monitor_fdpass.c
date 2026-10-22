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

#অন্তর্ভাৱ "includes.h"

#অন্তর্ভাৱ <sys/types.h>
#অন্তর্ভাৱ <sys/socket.h>
#অন্তর্ভাৱ <sys/uio.h>
#অন্তর্ভাৱ <sys/un.h>

#অন্তর্ভাৱ <errno.h>
#অন্তর্ভাৱ <poll.h>
#অন্তর্ভাৱ <string.h>
#অন্তর্ভাৱ <stdarg.h>

#অন্তর্ভাৱ "log.h"
#অন্তর্ভাৱ "monitor_fdpass.h"

পূর্ণাঙ্ক
mm_send_fd(পূর্ণাঙ্ক sock, পূর্ণাঙ্ক fd)
{
#যদি defined(HAVE_SENDMSG) && (defined(HAVE_ACCRIGHTS_IN_MSGHDR) || defined(HAVE_CONTROL_IN_MSGHDR))
	সংরচনা msghdr বাৰ্তা;
#ifndef HAVE_ACCRIGHTS_IN_MSGHDR
	সঙ্ঘ {
		সংরচনা cmsghdr hdr;
		ৱর্ণ buf[CMSG_SPACE(পরিমাণ(পূর্ণাঙ্ক))];
	} cmsgbuf;
	সংরচনা cmsghdr *cmsg;
#endif
	সংরচনা iovec vec;
	ৱর্ণ ch = '\0';
	ssize_t n;
	সংরচনা pollfd pfd;

	memset(&বাৰ্তা, 0, পরিমাণ(বাৰ্তা));
#ifdef HAVE_ACCRIGHTS_IN_MSGHDR
	বাৰ্তা.বাৰ্তা_accrights = (caddr_t)&fd;
	বাৰ্তা.বাৰ্তা_accrightslen = পরিমাণ(fd);
#অন্যথা
	memset(&cmsgbuf, 0, পরিমাণ(cmsgbuf));
	বাৰ্তা.msg_control = (caddr_t)&cmsgbuf.buf;
	বাৰ্তা.msg_controllen = পরিমাণ(cmsgbuf.buf);
	cmsg = CMSG_FIRSTHDR(&বাৰ্তা);
	cmsg->cmsg_len = CMSG_LEN(পরিমাণ(পূর্ণাঙ্ক));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	*(পূর্ণাঙ্ক *)CMSG_DATA(cmsg) = fd;
#endif

	vec.iov_base = &ch;
	vec.iov_len = 1;
	বাৰ্তা.msg_iov = &vec;
	বাৰ্তা.msg_iovlen = 1;

	pfd.fd = sock;
	pfd.events = POLLOUT;
	যেতিয়ালৈ ((n = sendmsg(sock, &বাৰ্তা, 0)) == -1 &&
	    (errno == EAGAIN || errno == EINTR)) {
		debug3_f("sendmsg(%d): %s", fd, strerror(errno));
		(শূন্য)poll(&pfd, 1, -1);
	}
	যদি (n == -1) {
		error_f("sendmsg(%d): %s", fd, strerror(errno));
		ঘূৰাই -1;
	}

	যদি (n != 1) {
		error_f("sendmsg: expected sent 1 got %zd", n);
		ঘূৰাই -1;
	}
	ঘূৰাই 0;
#অন্যথা
	error_f("file descriptor passing not supported");
	ঘূৰাই -1;
#endif
}

পূর্ণাঙ্ক
mm_receive_fd(পূর্ণাঙ্ক sock)
{
#যদি defined(HAVE_RECVMSG) && (defined(HAVE_ACCRIGHTS_IN_MSGHDR) || defined(HAVE_CONTROL_IN_MSGHDR))
	সংরচনা msghdr বাৰ্তা;
#ifndef HAVE_ACCRIGHTS_IN_MSGHDR
	সঙ্ঘ {
		সংরচনা cmsghdr hdr;
		ৱর্ণ buf[CMSG_SPACE(পরিমাণ(পূর্ণাঙ্ক))];
	} cmsgbuf;
	সংরচনা cmsghdr *cmsg;
#endif
	সংরচনা iovec vec;
	ssize_t n;
	ৱর্ণ ch;
	পূর্ণাঙ্ক fd;
	সংরচনা pollfd pfd;

	memset(&বাৰ্তা, 0, পরিমাণ(বাৰ্তা));
	vec.iov_base = &ch;
	vec.iov_len = 1;
	বাৰ্তা.msg_iov = &vec;
	বাৰ্তা.msg_iovlen = 1;
#ifdef HAVE_ACCRIGHTS_IN_MSGHDR
	বাৰ্তা.বাৰ্তা_accrights = (caddr_t)&fd;
	বাৰ্তা.বাৰ্তা_accrightslen = পরিমাণ(fd);
#অন্যথা
	memset(&cmsgbuf, 0, পরিমাণ(cmsgbuf));
	বাৰ্তা.msg_control = &cmsgbuf.buf;
	বাৰ্তা.msg_controllen = পরিমাণ(cmsgbuf.buf);
#endif

	pfd.fd = sock;
	pfd.events = POLLIN;
	যেতিয়ালৈ ((n = recvmsg(sock, &বাৰ্তা, 0)) == -1 &&
	    (errno == EAGAIN || errno == EINTR)) {
		debug3_f("recvmsg: %s", strerror(errno));
		(শূন্য)poll(&pfd, 1, -1);
	}
	যদি (n == -1) {
		error_f("recvmsg: %s", strerror(errno));
		ঘূৰাই -1;
	}

	যদি (n != 1) {
		error_f("recvmsg: expected received 1 got %zd", n);
		ঘূৰাই -1;
	}

#ifdef HAVE_ACCRIGHTS_IN_MSGHDR
	যদি (বাৰ্তা.বাৰ্তা_accrightslen != পরিমাণ(fd)) {
		error_f("no fd");
		ঘূৰাই -1;
	}
#অন্যথা
	cmsg = CMSG_FIRSTHDR(&বাৰ্তা);
	যদি (cmsg == রিক্ত) {
		error_f("no message header");
		ঘূৰাই -1;
	}

#ifndef BROKEN_CMSG_TYPE
	যদি (cmsg->cmsg_type != SCM_RIGHTS) {
		error_f("expected %d got %d", SCM_RIGHTS, cmsg->cmsg_type);
		ঘূৰাই -1;
	}
#endif
	fd = (*(পূর্ণাঙ্ক *)CMSG_DATA(cmsg));
#endif
	ঘূৰাই fd;
#অন্যথা
	error_f("file descriptor passing not supported");
	ঘূৰাই -1;
#endif
}
