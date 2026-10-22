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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/socket.h>
#അന്തര്ഭാവ <sys/uio.h>
#അന്തര്ഭാവ <sys/un.h>

#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <poll.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <stdarg.h>

#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "monitor_fdpass.h"

പൂർണ്ണസംഖ്യ
mm_send_fd(പൂർണ്ണസംഖ്യ sock, പൂർണ്ണസംഖ്യ fd)
{
#എങ്കിൽ defined(HAVE_SENDMSG) && (defined(HAVE_ACCRIGHTS_IN_MSGHDR) || defined(HAVE_CONTROL_IN_MSGHDR))
	ഘടന msghdr സന്ദേശം;
#ifndef HAVE_ACCRIGHTS_IN_MSGHDR
	സംഘം {
		ഘടന cmsghdr hdr;
		അക്ഷരം buf[CMSG_SPACE(വലുപ്പം(പൂർണ്ണസംഖ്യ))];
	} cmsgbuf;
	ഘടന cmsghdr *cmsg;
#endif
	ഘടന iovec vec;
	അക്ഷരം ch = '\0';
	ssize_t n;
	ഘടന pollfd pfd;

	memset(&സന്ദേശം, 0, വലുപ്പം(സന്ദേശം));
#ifdef HAVE_ACCRIGHTS_IN_MSGHDR
	സന്ദേശം.സന്ദേശം_accrights = (caddr_t)&fd;
	സന്ദേശം.സന്ദേശം_accrightslen = വലുപ്പം(fd);
#അല്ലെങ്കിൽ
	memset(&cmsgbuf, 0, വലുപ്പം(cmsgbuf));
	സന്ദേശം.msg_control = (caddr_t)&cmsgbuf.buf;
	സന്ദേശം.msg_controllen = വലുപ്പം(cmsgbuf.buf);
	cmsg = CMSG_FIRSTHDR(&സന്ദേശം);
	cmsg->cmsg_len = CMSG_LEN(വലുപ്പം(പൂർണ്ണസംഖ്യ));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	*(പൂർണ്ണസംഖ്യ *)CMSG_DATA(cmsg) = fd;
#endif

	vec.iov_base = &ch;
	vec.iov_len = 1;
	സന്ദേശം.msg_iov = &vec;
	സന്ദേശം.msg_iovlen = 1;

	pfd.fd = sock;
	pfd.events = POLLOUT;
	ആകുമ്പോൾ ((n = sendmsg(sock, &സന്ദേശം, 0)) == -1 &&
	    (errno == EAGAIN || errno == EINTR)) {
		debug3_f("sendmsg(%d): %s", fd, strerror(errno));
		(ശൂന്യം)poll(&pfd, 1, -1);
	}
	എങ്കിൽ (n == -1) {
		error_f("sendmsg(%d): %s", fd, strerror(errno));
		തിരികെ -1;
	}

	എങ്കിൽ (n != 1) {
		error_f("sendmsg: expected sent 1 got %zd", n);
		തിരികെ -1;
	}
	തിരികെ 0;
#അല്ലെങ്കിൽ
	error_f("file descriptor passing not supported");
	തിരികെ -1;
#endif
}

പൂർണ്ണസംഖ്യ
mm_receive_fd(പൂർണ്ണസംഖ്യ sock)
{
#എങ്കിൽ defined(HAVE_RECVMSG) && (defined(HAVE_ACCRIGHTS_IN_MSGHDR) || defined(HAVE_CONTROL_IN_MSGHDR))
	ഘടന msghdr സന്ദേശം;
#ifndef HAVE_ACCRIGHTS_IN_MSGHDR
	സംഘം {
		ഘടന cmsghdr hdr;
		അക്ഷരം buf[CMSG_SPACE(വലുപ്പം(പൂർണ്ണസംഖ്യ))];
	} cmsgbuf;
	ഘടന cmsghdr *cmsg;
#endif
	ഘടന iovec vec;
	ssize_t n;
	അക്ഷരം ch;
	പൂർണ്ണസംഖ്യ fd;
	ഘടന pollfd pfd;

	memset(&സന്ദേശം, 0, വലുപ്പം(സന്ദേശം));
	vec.iov_base = &ch;
	vec.iov_len = 1;
	സന്ദേശം.msg_iov = &vec;
	സന്ദേശം.msg_iovlen = 1;
#ifdef HAVE_ACCRIGHTS_IN_MSGHDR
	സന്ദേശം.സന്ദേശം_accrights = (caddr_t)&fd;
	സന്ദേശം.സന്ദേശം_accrightslen = വലുപ്പം(fd);
#അല്ലെങ്കിൽ
	memset(&cmsgbuf, 0, വലുപ്പം(cmsgbuf));
	സന്ദേശം.msg_control = &cmsgbuf.buf;
	സന്ദേശം.msg_controllen = വലുപ്പം(cmsgbuf.buf);
#endif

	pfd.fd = sock;
	pfd.events = POLLIN;
	ആകുമ്പോൾ ((n = recvmsg(sock, &സന്ദേശം, 0)) == -1 &&
	    (errno == EAGAIN || errno == EINTR)) {
		debug3_f("recvmsg: %s", strerror(errno));
		(ശൂന്യം)poll(&pfd, 1, -1);
	}
	എങ്കിൽ (n == -1) {
		error_f("recvmsg: %s", strerror(errno));
		തിരികെ -1;
	}

	എങ്കിൽ (n != 1) {
		error_f("recvmsg: expected received 1 got %zd", n);
		തിരികെ -1;
	}

#ifdef HAVE_ACCRIGHTS_IN_MSGHDR
	എങ്കിൽ (സന്ദേശം.സന്ദേശം_accrightslen != വലുപ്പം(fd)) {
		error_f("no fd");
		തിരികെ -1;
	}
#അല്ലെങ്കിൽ
	cmsg = CMSG_FIRSTHDR(&സന്ദേശം);
	എങ്കിൽ (cmsg == ശൂന്യ) {
		error_f("no message header");
		തിരികെ -1;
	}

#ifndef BROKEN_CMSG_TYPE
	എങ്കിൽ (cmsg->cmsg_type != SCM_RIGHTS) {
		error_f("expected %d got %d", SCM_RIGHTS, cmsg->cmsg_type);
		തിരികെ -1;
	}
#endif
	fd = (*(പൂർണ്ണസംഖ്യ *)CMSG_DATA(cmsg));
#endif
	തിരികെ fd;
#അല്ലെങ്കിൽ
	error_f("file descriptor passing not supported");
	തിരികെ -1;
#endif
}
