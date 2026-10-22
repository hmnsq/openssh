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

ಪೂರ್ಣಾಂಕ
mm_send_fd(ಪೂರ್ಣಾಂಕ sock, ಪೂರ್ಣಾಂಕ fd)
{
#ಆದರೆ defined(HAVE_SENDMSG) && (defined(HAVE_ACCRIGHTS_ಒಳ_MSGHDR) || defined(HAVE_CONTROL_ಒಳ_MSGHDR))
	ರಚನೆ msghdr ಸಂದೇಶ;
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_ACCRIGHTS_ಒಳ_MSGHDR
	ಒಕ್ಕೂಟ {
		ರಚನೆ cmsghdr hdr;
		ಅಕ್ಷರ buf[CMSG_SPACE(ಗಾತ್ರ(ಪೂರ್ಣಾಂಕ))];
	} cmsgbuf;
	ರಚನೆ cmsghdr *cmsg;
#ಆದರೆ_ಅಂತ್ಯ
	ರಚನೆ iovec vec;
	ಅಕ್ಷರ ch = '\0';
	ssize_t n;
	ರಚನೆ pollfd pfd;

	memset(&ಸಂದೇಶ, 0, ಗಾತ್ರ(ಸಂದೇಶ));
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_ACCRIGHTS_ಒಳ_MSGHDR
	ಸಂದೇಶ.ಸಂದೇಶ_accrights = (caddr_t)&fd;
	ಸಂದೇಶ.ಸಂದೇಶ_accrightslen = ಗಾತ್ರ(fd);
#ಇಲ್ಲದಿದ್ದರೆ
	memset(&cmsgbuf, 0, ಗಾತ್ರ(cmsgbuf));
	ಸಂದೇಶ.msg_control = (caddr_t)&cmsgbuf.buf;
	ಸಂದೇಶ.msg_controllen = ಗಾತ್ರ(cmsgbuf.buf);
	cmsg = CMSG_FIRSTHDR(&ಸಂದೇಶ);
	cmsg->cmsg_len = CMSG_LEN(ಗಾತ್ರ(ಪೂರ್ಣಾಂಕ));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	*(ಪೂರ್ಣಾಂಕ *)CMSG_DATA(cmsg) = fd;
#ಆದರೆ_ಅಂತ್ಯ

	vec.iov_base = &ch;
	vec.iov_len = 1;
	ಸಂದೇಶ.msg_iov = &vec;
	ಸಂದೇಶ.msg_iovlen = 1;

	pfd.fd = sock;
	pfd.events = POLLOUT;
	ಆಗ ((n = sendmsg(sock, &ಸಂದೇಶ, 0)) == -1 &&
	    (errno == EAGAIN || errno == EINTR)) {
		debug3_f("sendmsg(%d): %s", fd, strerror(errno));
		(ಶೂನ್ಯ)poll(&pfd, 1, -1);
	}
	ಆದರೆ (n == -1) {
		error_f("sendmsg(%d): %s", fd, strerror(errno));
		ಹಿಂತಿರುಗಿ -1;
	}

	ಆದರೆ (n != 1) {
		error_f("sendmsg: expected sent 1 got %zd", n);
		ಹಿಂತಿರುಗಿ -1;
	}
	ಹಿಂತಿರುಗಿ 0;
#ಇಲ್ಲದಿದ್ದರೆ
	error_f("file descriptor passing not supported");
	ಹಿಂತಿರುಗಿ -1;
#ಆದರೆ_ಅಂತ್ಯ
}

ಪೂರ್ಣಾಂಕ
mm_receive_fd(ಪೂರ್ಣಾಂಕ sock)
{
#ಆದರೆ defined(HAVE_RECVMSG) && (defined(HAVE_ACCRIGHTS_ಒಳ_MSGHDR) || defined(HAVE_CONTROL_ಒಳ_MSGHDR))
	ರಚನೆ msghdr ಸಂದೇಶ;
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_ACCRIGHTS_ಒಳ_MSGHDR
	ಒಕ್ಕೂಟ {
		ರಚನೆ cmsghdr hdr;
		ಅಕ್ಷರ buf[CMSG_SPACE(ಗಾತ್ರ(ಪೂರ್ಣಾಂಕ))];
	} cmsgbuf;
	ರಚನೆ cmsghdr *cmsg;
#ಆದರೆ_ಅಂತ್ಯ
	ರಚನೆ iovec vec;
	ssize_t n;
	ಅಕ್ಷರ ch;
	ಪೂರ್ಣಾಂಕ fd;
	ರಚನೆ pollfd pfd;

	memset(&ಸಂದೇಶ, 0, ಗಾತ್ರ(ಸಂದೇಶ));
	vec.iov_base = &ch;
	vec.iov_len = 1;
	ಸಂದೇಶ.msg_iov = &vec;
	ಸಂದೇಶ.msg_iovlen = 1;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_ACCRIGHTS_ಒಳ_MSGHDR
	ಸಂದೇಶ.ಸಂದೇಶ_accrights = (caddr_t)&fd;
	ಸಂದೇಶ.ಸಂದೇಶ_accrightslen = ಗಾತ್ರ(fd);
#ಇಲ್ಲದಿದ್ದರೆ
	memset(&cmsgbuf, 0, ಗಾತ್ರ(cmsgbuf));
	ಸಂದೇಶ.msg_control = &cmsgbuf.buf;
	ಸಂದೇಶ.msg_controllen = ಗಾತ್ರ(cmsgbuf.buf);
#ಆದರೆ_ಅಂತ್ಯ

	pfd.fd = sock;
	pfd.events = POLLIN;
	ಆಗ ((n = recvmsg(sock, &ಸಂದೇಶ, 0)) == -1 &&
	    (errno == EAGAIN || errno == EINTR)) {
		debug3_f("recvmsg: %s", strerror(errno));
		(ಶೂನ್ಯ)poll(&pfd, 1, -1);
	}
	ಆದರೆ (n == -1) {
		error_f("recvmsg: %s", strerror(errno));
		ಹಿಂತಿರುಗಿ -1;
	}

	ಆದರೆ (n != 1) {
		error_f("recvmsg: expected received 1 got %zd", n);
		ಹಿಂತಿರುಗಿ -1;
	}

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_ACCRIGHTS_ಒಳ_MSGHDR
	ಆದರೆ (ಸಂದೇಶ.ಸಂದೇಶ_accrightslen != ಗಾತ್ರ(fd)) {
		error_f("no fd");
		ಹಿಂತಿರುಗಿ -1;
	}
#ಇಲ್ಲದಿದ್ದರೆ
	cmsg = CMSG_FIRSTHDR(&ಸಂದೇಶ);
	ಆದರೆ (cmsg == ಖಾಲಿ) {
		error_f("no message header");
		ಹಿಂತಿರುಗಿ -1;
	}

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ BROKEN_CMSG_TYPE
	ಆದರೆ (cmsg->cmsg_type != SCM_RIGHTS) {
		error_f("expected %d got %d", SCM_RIGHTS, cmsg->cmsg_type);
		ಹಿಂತಿರುಗಿ -1;
	}
#ಆದರೆ_ಅಂತ್ಯ
	fd = (*(ಪೂರ್ಣಾಂಕ *)CMSG_DATA(cmsg));
#ಆದರೆ_ಅಂತ್ಯ
	ಹಿಂತಿರುಗಿ fd;
#ಇಲ್ಲದಿದ್ದರೆ
	error_f("file descriptor passing not supported");
	ಹಿಂತಿರುಗಿ -1;
#ಆದರೆ_ಅಂತ್ಯ
}
