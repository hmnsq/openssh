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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/socket.h>
#ಅನ್ತರ್ಭಾವ <sys/uio.h>
#ಅನ್ತರ್ಭಾವ <sys/un.h>

#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <poll.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>

#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "monitor_fdpass.h"

ಪೂರ್ಣಾಙ್ಕ
mm_send_fd(ಪೂರ್ಣಾಙ್ಕ sock, ಪೂರ್ಣಾಙ್ಕ fd)
{
#ಯದಿ defined(HAVE_SENDMSG) && (defined(HAVE_ACCRIGHTS_IN_MSGHDR) || defined(HAVE_CONTROL_IN_MSGHDR))
	ಸಂರಚನಾ msghdr ಸಂದೇಶ;
#ifndef HAVE_ACCRIGHTS_IN_MSGHDR
	ಸಙ್ಘ {
		ಸಂರಚನಾ cmsghdr hdr;
		ವರ್ಣ buf[CMSG_SPACE(ಪರಿಮಾಣ(ಪೂರ್ಣಾಙ್ಕ))];
	} cmsgbuf;
	ಸಂರಚನಾ cmsghdr *cmsg;
#endif
	ಸಂರಚನಾ iovec vec;
	ವರ್ಣ ch = '\0';
	ssize_t n;
	ಸಂರಚನಾ pollfd pfd;

	memset(&ಸಂದೇಶ, 0, ಪರಿಮಾಣ(ಸಂದೇಶ));
#ifdef HAVE_ACCRIGHTS_IN_MSGHDR
	ಸಂದೇಶ.ಸಂದೇಶ_accrights = (caddr_t)&fd;
	ಸಂದೇಶ.ಸಂದೇಶ_accrightslen = ಪರಿಮಾಣ(fd);
#ಅನ್ಯಥಾ
	memset(&cmsgbuf, 0, ಪರಿಮಾಣ(cmsgbuf));
	ಸಂದೇಶ.msg_control = (caddr_t)&cmsgbuf.buf;
	ಸಂದೇಶ.msg_controllen = ಪರಿಮಾಣ(cmsgbuf.buf);
	cmsg = CMSG_FIRSTHDR(&ಸಂದೇಶ);
	cmsg->cmsg_len = CMSG_LEN(ಪರಿಮಾಣ(ಪೂರ್ಣಾಙ್ಕ));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	*(ಪೂರ್ಣಾಙ್ಕ *)CMSG_DATA(cmsg) = fd;
#endif

	vec.iov_base = &ch;
	vec.iov_len = 1;
	ಸಂದೇಶ.msg_iov = &vec;
	ಸಂದೇಶ.msg_iovlen = 1;

	pfd.fd = sock;
	pfd.events = POLLOUT;
	ಯಾವತ್ ((n = sendmsg(sock, &ಸಂದೇಶ, 0)) == -1 &&
	    (errno == EAGAIN || errno == EINTR)) {
		debug3_f("sendmsg(%d): %s", fd, strerror(errno));
		(ಶೂನ್ಯ)poll(&pfd, 1, -1);
	}
	ಯದಿ (n == -1) {
		error_f("sendmsg(%d): %s", fd, strerror(errno));
		ಪ್ರತ್ಯಾಗಮ -1;
	}

	ಯದಿ (n != 1) {
		error_f("sendmsg: expected sent 1 got %zd", n);
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
#ಅನ್ಯಥಾ
	error_f("file descriptor passing not supported");
	ಪ್ರತ್ಯಾಗಮ -1;
#endif
}

ಪೂರ್ಣಾಙ್ಕ
mm_receive_fd(ಪೂರ್ಣಾಙ್ಕ sock)
{
#ಯದಿ defined(HAVE_RECVMSG) && (defined(HAVE_ACCRIGHTS_IN_MSGHDR) || defined(HAVE_CONTROL_IN_MSGHDR))
	ಸಂರಚನಾ msghdr ಸಂದೇಶ;
#ifndef HAVE_ACCRIGHTS_IN_MSGHDR
	ಸಙ್ಘ {
		ಸಂರಚನಾ cmsghdr hdr;
		ವರ್ಣ buf[CMSG_SPACE(ಪರಿಮಾಣ(ಪೂರ್ಣಾಙ್ಕ))];
	} cmsgbuf;
	ಸಂರಚನಾ cmsghdr *cmsg;
#endif
	ಸಂರಚನಾ iovec vec;
	ssize_t n;
	ವರ್ಣ ch;
	ಪೂರ್ಣಾಙ್ಕ fd;
	ಸಂರಚನಾ pollfd pfd;

	memset(&ಸಂದೇಶ, 0, ಪರಿಮಾಣ(ಸಂದೇಶ));
	vec.iov_base = &ch;
	vec.iov_len = 1;
	ಸಂದೇಶ.msg_iov = &vec;
	ಸಂದೇಶ.msg_iovlen = 1;
#ifdef HAVE_ACCRIGHTS_IN_MSGHDR
	ಸಂದೇಶ.ಸಂದೇಶ_accrights = (caddr_t)&fd;
	ಸಂದೇಶ.ಸಂದೇಶ_accrightslen = ಪರಿಮಾಣ(fd);
#ಅನ್ಯಥಾ
	memset(&cmsgbuf, 0, ಪರಿಮಾಣ(cmsgbuf));
	ಸಂದೇಶ.msg_control = &cmsgbuf.buf;
	ಸಂದೇಶ.msg_controllen = ಪರಿಮಾಣ(cmsgbuf.buf);
#endif

	pfd.fd = sock;
	pfd.events = POLLIN;
	ಯಾವತ್ ((n = recvmsg(sock, &ಸಂದೇಶ, 0)) == -1 &&
	    (errno == EAGAIN || errno == EINTR)) {
		debug3_f("recvmsg: %s", strerror(errno));
		(ಶೂನ್ಯ)poll(&pfd, 1, -1);
	}
	ಯದಿ (n == -1) {
		error_f("recvmsg: %s", strerror(errno));
		ಪ್ರತ್ಯಾಗಮ -1;
	}

	ಯದಿ (n != 1) {
		error_f("recvmsg: expected received 1 got %zd", n);
		ಪ್ರತ್ಯಾಗಮ -1;
	}

#ifdef HAVE_ACCRIGHTS_IN_MSGHDR
	ಯದಿ (ಸಂದೇಶ.ಸಂದೇಶ_accrightslen != ಪರಿಮಾಣ(fd)) {
		error_f("no fd");
		ಪ್ರತ್ಯಾಗಮ -1;
	}
#ಅನ್ಯಥಾ
	cmsg = CMSG_FIRSTHDR(&ಸಂದೇಶ);
	ಯದಿ (cmsg == ರಿಕ್ತ) {
		error_f("no message header");
		ಪ್ರತ್ಯಾಗಮ -1;
	}

#ifndef BROKEN_CMSG_TYPE
	ಯದಿ (cmsg->cmsg_type != SCM_RIGHTS) {
		error_f("expected %d got %d", SCM_RIGHTS, cmsg->cmsg_type);
		ಪ್ರತ್ಯಾಗಮ -1;
	}
#endif
	fd = (*(ಪೂರ್ಣಾಙ್ಕ *)CMSG_DATA(cmsg));
#endif
	ಪ್ರತ್ಯಾಗಮ fd;
#ಅನ್ಯಥಾ
	error_f("file descriptor passing not supported");
	ಪ್ರತ್ಯಾಗಮ -1;
#endif
}
