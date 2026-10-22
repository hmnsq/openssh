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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/socket.h>
#અન્તર્ભાવ <sys/uio.h>
#અન્તર્ભાવ <sys/un.h>

#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <poll.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <stdarg.h>

#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "monitor_fdpass.h"

પૂર્ણાંક
mm_send_fd(પૂર્ણાંક sock, પૂર્ણાંક fd)
{
#જો defined(HAVE_SENDMSG) && (defined(HAVE_ACCRIGHTS_IN_MSGHDR) || defined(HAVE_CONTROL_IN_MSGHDR))
	સંરચના msghdr સંદેશ;
#ifndef HAVE_ACCRIGHTS_IN_MSGHDR
	સંઘ {
		સંરચના cmsghdr hdr;
		અક્ષર buf[CMSG_SPACE(કદ(પૂર્ણાંક))];
	} cmsgbuf;
	સંરચના cmsghdr *cmsg;
#endif
	સંરચના iovec vec;
	અક્ષર ch = '\0';
	ssize_t n;
	સંરચના pollfd pfd;

	memset(&સંદેશ, 0, કદ(સંદેશ));
#ifdef HAVE_ACCRIGHTS_IN_MSGHDR
	સંદેશ.સંદેશ_accrights = (caddr_t)&fd;
	સંદેશ.સંદેશ_accrightslen = કદ(fd);
#નહીંતર
	memset(&cmsgbuf, 0, કદ(cmsgbuf));
	સંદેશ.msg_control = (caddr_t)&cmsgbuf.buf;
	સંદેશ.msg_controllen = કદ(cmsgbuf.buf);
	cmsg = CMSG_FIRSTHDR(&સંદેશ);
	cmsg->cmsg_len = CMSG_LEN(કદ(પૂર્ણાંક));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	*(પૂર્ણાંક *)CMSG_DATA(cmsg) = fd;
#endif

	vec.iov_base = &ch;
	vec.iov_len = 1;
	સંદેશ.msg_iov = &vec;
	સંદેશ.msg_iovlen = 1;

	pfd.fd = sock;
	pfd.events = POLLOUT;
	જ્યારે ((n = sendmsg(sock, &સંદેશ, 0)) == -1 &&
	    (errno == EAGAIN || errno == EINTR)) {
		debug3_f("sendmsg(%d): %s", fd, strerror(errno));
		(શૂન્ય)poll(&pfd, 1, -1);
	}
	જો (n == -1) {
		error_f("sendmsg(%d): %s", fd, strerror(errno));
		પાછા -1;
	}

	જો (n != 1) {
		error_f("sendmsg: expected sent 1 got %zd", n);
		પાછા -1;
	}
	પાછા 0;
#નહીંતર
	error_f("file descriptor passing not supported");
	પાછા -1;
#endif
}

પૂર્ણાંક
mm_receive_fd(પૂર્ણાંક sock)
{
#જો defined(HAVE_RECVMSG) && (defined(HAVE_ACCRIGHTS_IN_MSGHDR) || defined(HAVE_CONTROL_IN_MSGHDR))
	સંરચના msghdr સંદેશ;
#ifndef HAVE_ACCRIGHTS_IN_MSGHDR
	સંઘ {
		સંરચના cmsghdr hdr;
		અક્ષર buf[CMSG_SPACE(કદ(પૂર્ણાંક))];
	} cmsgbuf;
	સંરચના cmsghdr *cmsg;
#endif
	સંરચના iovec vec;
	ssize_t n;
	અક્ષર ch;
	પૂર્ણાંક fd;
	સંરચના pollfd pfd;

	memset(&સંદેશ, 0, કદ(સંદેશ));
	vec.iov_base = &ch;
	vec.iov_len = 1;
	સંદેશ.msg_iov = &vec;
	સંદેશ.msg_iovlen = 1;
#ifdef HAVE_ACCRIGHTS_IN_MSGHDR
	સંદેશ.સંદેશ_accrights = (caddr_t)&fd;
	સંદેશ.સંદેશ_accrightslen = કદ(fd);
#નહીંતર
	memset(&cmsgbuf, 0, કદ(cmsgbuf));
	સંદેશ.msg_control = &cmsgbuf.buf;
	સંદેશ.msg_controllen = કદ(cmsgbuf.buf);
#endif

	pfd.fd = sock;
	pfd.events = POLLIN;
	જ્યારે ((n = recvmsg(sock, &સંદેશ, 0)) == -1 &&
	    (errno == EAGAIN || errno == EINTR)) {
		debug3_f("recvmsg: %s", strerror(errno));
		(શૂન્ય)poll(&pfd, 1, -1);
	}
	જો (n == -1) {
		error_f("recvmsg: %s", strerror(errno));
		પાછા -1;
	}

	જો (n != 1) {
		error_f("recvmsg: expected received 1 got %zd", n);
		પાછા -1;
	}

#ifdef HAVE_ACCRIGHTS_IN_MSGHDR
	જો (સંદેશ.સંદેશ_accrightslen != કદ(fd)) {
		error_f("no fd");
		પાછા -1;
	}
#નહીંતર
	cmsg = CMSG_FIRSTHDR(&સંદેશ);
	જો (cmsg == ખાલી) {
		error_f("no message header");
		પાછા -1;
	}

#ifndef BROKEN_CMSG_TYPE
	જો (cmsg->cmsg_type != SCM_RIGHTS) {
		error_f("expected %d got %d", SCM_RIGHTS, cmsg->cmsg_type);
		પાછા -1;
	}
#endif
	fd = (*(પૂર્ણાંક *)CMSG_DATA(cmsg));
#endif
	પાછા fd;
#નહીંતર
	error_f("file descriptor passing not supported");
	પાછા -1;
#endif
}
