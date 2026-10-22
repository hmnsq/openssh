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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/socket.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/uio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/un.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <poll.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "monitor_fdpass.h"

ਪੂਰਨ
mm_send_fd(ਪੂਰਨ sock, ਪੂਰਨ fd)
{
#ਜੇ defined(HAVE_SENDMSG) && (defined(HAVE_ACCRIGHTS_ਵਿੱਚ_MSGHDR) || defined(HAVE_CONTROL_ਵਿੱਚ_MSGHDR))
	ਬਣਤਰ msghdr ਸੁਨੇਹਾ;
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_ACCRIGHTS_ਵਿੱਚ_MSGHDR
	ਸੰਘ {
		ਬਣਤਰ cmsghdr hdr;
		ਅੱਖਰ buf[CMSG_SPACE(ਆਕਾਰ(ਪੂਰਨ))];
	} cmsgbuf;
	ਬਣਤਰ cmsghdr *cmsg;
#ਜੇ_ਅੰਤ
	ਬਣਤਰ iovec vec;
	ਅੱਖਰ ch = '\0';
	ssize_t n;
	ਬਣਤਰ pollfd pfd;

	memset(&ਸੁਨੇਹਾ, 0, ਆਕਾਰ(ਸੁਨੇਹਾ));
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_ACCRIGHTS_ਵਿੱਚ_MSGHDR
	ਸੁਨੇਹਾ.ਸੁਨੇਹਾ_accrights = (caddr_t)&fd;
	ਸੁਨੇਹਾ.ਸੁਨੇਹਾ_accrightslen = ਆਕਾਰ(fd);
#ਨਹੀਂਤਾਂ
	memset(&cmsgbuf, 0, ਆਕਾਰ(cmsgbuf));
	ਸੁਨੇਹਾ.msg_control = (caddr_t)&cmsgbuf.buf;
	ਸੁਨੇਹਾ.msg_controllen = ਆਕਾਰ(cmsgbuf.buf);
	cmsg = CMSG_FIRSTHDR(&ਸੁਨੇਹਾ);
	cmsg->cmsg_len = CMSG_LEN(ਆਕਾਰ(ਪੂਰਨ));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	*(ਪੂਰਨ *)CMSG_DATA(cmsg) = fd;
#ਜੇ_ਅੰਤ

	vec.iov_base = &ch;
	vec.iov_len = 1;
	ਸੁਨੇਹਾ.msg_iov = &vec;
	ਸੁਨੇਹਾ.msg_iovlen = 1;

	pfd.fd = sock;
	pfd.events = POLLOUT;
	ਜਦੋਂ ((n = sendmsg(sock, &ਸੁਨੇਹਾ, 0)) == -1 &&
	    (errno == EAGAIN || errno == EINTR)) {
		debug3_f("sendmsg(%d): %s", fd, strerror(errno));
		(ਖਾਲੀ)poll(&pfd, 1, -1);
	}
	ਜੇ (n == -1) {
		error_f("sendmsg(%d): %s", fd, strerror(errno));
		ਵਾਪਸ -1;
	}

	ਜੇ (n != 1) {
		error_f("sendmsg: expected sent 1 got %zd", n);
		ਵਾਪਸ -1;
	}
	ਵਾਪਸ 0;
#ਨਹੀਂਤਾਂ
	error_f("file descriptor passing not supported");
	ਵਾਪਸ -1;
#ਜੇ_ਅੰਤ
}

ਪੂਰਨ
mm_receive_fd(ਪੂਰਨ sock)
{
#ਜੇ defined(HAVE_RECVMSG) && (defined(HAVE_ACCRIGHTS_ਵਿੱਚ_MSGHDR) || defined(HAVE_CONTROL_ਵਿੱਚ_MSGHDR))
	ਬਣਤਰ msghdr ਸੁਨੇਹਾ;
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_ACCRIGHTS_ਵਿੱਚ_MSGHDR
	ਸੰਘ {
		ਬਣਤਰ cmsghdr hdr;
		ਅੱਖਰ buf[CMSG_SPACE(ਆਕਾਰ(ਪੂਰਨ))];
	} cmsgbuf;
	ਬਣਤਰ cmsghdr *cmsg;
#ਜੇ_ਅੰਤ
	ਬਣਤਰ iovec vec;
	ssize_t n;
	ਅੱਖਰ ch;
	ਪੂਰਨ fd;
	ਬਣਤਰ pollfd pfd;

	memset(&ਸੁਨੇਹਾ, 0, ਆਕਾਰ(ਸੁਨੇਹਾ));
	vec.iov_base = &ch;
	vec.iov_len = 1;
	ਸੁਨੇਹਾ.msg_iov = &vec;
	ਸੁਨੇਹਾ.msg_iovlen = 1;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_ACCRIGHTS_ਵਿੱਚ_MSGHDR
	ਸੁਨੇਹਾ.ਸੁਨੇਹਾ_accrights = (caddr_t)&fd;
	ਸੁਨੇਹਾ.ਸੁਨੇਹਾ_accrightslen = ਆਕਾਰ(fd);
#ਨਹੀਂਤਾਂ
	memset(&cmsgbuf, 0, ਆਕਾਰ(cmsgbuf));
	ਸੁਨੇਹਾ.msg_control = &cmsgbuf.buf;
	ਸੁਨੇਹਾ.msg_controllen = ਆਕਾਰ(cmsgbuf.buf);
#ਜੇ_ਅੰਤ

	pfd.fd = sock;
	pfd.events = POLLIN;
	ਜਦੋਂ ((n = recvmsg(sock, &ਸੁਨੇਹਾ, 0)) == -1 &&
	    (errno == EAGAIN || errno == EINTR)) {
		debug3_f("recvmsg: %s", strerror(errno));
		(ਖਾਲੀ)poll(&pfd, 1, -1);
	}
	ਜੇ (n == -1) {
		error_f("recvmsg: %s", strerror(errno));
		ਵਾਪਸ -1;
	}

	ਜੇ (n != 1) {
		error_f("recvmsg: expected received 1 got %zd", n);
		ਵਾਪਸ -1;
	}

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_ACCRIGHTS_ਵਿੱਚ_MSGHDR
	ਜੇ (ਸੁਨੇਹਾ.ਸੁਨੇਹਾ_accrightslen != ਆਕਾਰ(fd)) {
		error_f("no fd");
		ਵਾਪਸ -1;
	}
#ਨਹੀਂਤਾਂ
	cmsg = CMSG_FIRSTHDR(&ਸੁਨੇਹਾ);
	ਜੇ (cmsg == ਨਿਰਾ) {
		error_f("no message header");
		ਵਾਪਸ -1;
	}

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ BROKEN_CMSG_TYPE
	ਜੇ (cmsg->cmsg_type != SCM_RIGHTS) {
		error_f("expected %d got %d", SCM_RIGHTS, cmsg->cmsg_type);
		ਵਾਪਸ -1;
	}
#ਜੇ_ਅੰਤ
	fd = (*(ਪੂਰਨ *)CMSG_DATA(cmsg));
#ਜੇ_ਅੰਤ
	ਵਾਪਸ fd;
#ਨਹੀਂਤਾਂ
	error_f("file descriptor passing not supported");
	ਵਾਪਸ -1;
#ਜੇ_ਅੰਤ
}
