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

#include "includes.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>

#include <errno.h>
#include <poll.h>
#include <string.h>
#include <stdarg.h>

#include "log.h"
#include "monitor_fdpass.h"

puur_naa_nka
mm_send_fd(puur_naa_nka sock, puur_naa_nka fd)
{
#ပေႃး defined(HAVE_SENDMSG) && (defined(HAVE_ACCRIGHTS_IN_MSGHDR) || defined(HAVE_CONTROL_IN_MSGHDR))
	sa_nracanaa msghdr msg;
#ifndef HAVE_ACCRIGHTS_IN_MSGHDR
	sa_ngha {
		sa_nracanaa cmsghdr hdr;
		var_na buf[CMSG_SPACE(parimaa_na(puur_naa_nka))];
	} cmsgbuf;
	sa_nracanaa cmsghdr *cmsg;
#endif
	sa_nracanaa iovec vec;
	var_na ch = '\0';
	ssize_t n;
	sa_nracanaa pollfd pfd;

	memset(&msg, 0, parimaa_na(msg));
#ifdef HAVE_ACCRIGHTS_IN_MSGHDR
	msg.msg_accrights = (caddr_t)&fd;
	msg.msg_accrightslen = parimaa_na(fd);
#ပေႃးဢမ်ႇ
	memset(&cmsgbuf, 0, parimaa_na(cmsgbuf));
	msg.msg_control = (caddr_t)&cmsgbuf.buf;
	msg.msg_controllen = parimaa_na(cmsgbuf.buf);
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_len = CMSG_LEN(parimaa_na(puur_naa_nka));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	*(puur_naa_nka *)CMSG_DATA(cmsg) = fd;
#endif

	vec.iov_base = &ch;
	vec.iov_len = 1;
	msg.msg_iov = &vec;
	msg.msg_iovlen = 1;

	pfd.fd = sock;
	pfd.events = POLLOUT;
	ၶၢဝ်း ((n = sendmsg(sock, &msg, 0)) == -1 &&
	    (errno == EAGAIN || errno == EINTR)) {
		debug3_f("sendmsg(%d): %s", fd, strerror(errno));
		(void)poll(&pfd, 1, -1);
	}
	ပေႃး (n == -1) {
		error_f("sendmsg(%d): %s", fd, strerror(errno));
		ပွၵ်ႈ -1;
	}

	ပေႃး (n != 1) {
		error_f("sendmsg: expected sent 1 got %zd", n);
		ပွၵ်ႈ -1;
	}
	ပွၵ်ႈ 0;
#ပေႃးဢမ်ႇ
	error_f("file descriptor passing not supported");
	ပွၵ်ႈ -1;
#endif
}

puur_naa_nka
mm_receive_fd(puur_naa_nka sock)
{
#ပေႃး defined(HAVE_RECVMSG) && (defined(HAVE_ACCRIGHTS_IN_MSGHDR) || defined(HAVE_CONTROL_IN_MSGHDR))
	sa_nracanaa msghdr msg;
#ifndef HAVE_ACCRIGHTS_IN_MSGHDR
	sa_ngha {
		sa_nracanaa cmsghdr hdr;
		var_na buf[CMSG_SPACE(parimaa_na(puur_naa_nka))];
	} cmsgbuf;
	sa_nracanaa cmsghdr *cmsg;
#endif
	sa_nracanaa iovec vec;
	ssize_t n;
	var_na ch;
	puur_naa_nka fd;
	sa_nracanaa pollfd pfd;

	memset(&msg, 0, parimaa_na(msg));
	vec.iov_base = &ch;
	vec.iov_len = 1;
	msg.msg_iov = &vec;
	msg.msg_iovlen = 1;
#ifdef HAVE_ACCRIGHTS_IN_MSGHDR
	msg.msg_accrights = (caddr_t)&fd;
	msg.msg_accrightslen = parimaa_na(fd);
#ပေႃးဢမ်ႇ
	memset(&cmsgbuf, 0, parimaa_na(cmsgbuf));
	msg.msg_control = &cmsgbuf.buf;
	msg.msg_controllen = parimaa_na(cmsgbuf.buf);
#endif

	pfd.fd = sock;
	pfd.events = POLLIN;
	ၶၢဝ်း ((n = recvmsg(sock, &msg, 0)) == -1 &&
	    (errno == EAGAIN || errno == EINTR)) {
		debug3_f("recvmsg: %s", strerror(errno));
		(void)poll(&pfd, 1, -1);
	}
	ပေႃး (n == -1) {
		error_f("recvmsg: %s", strerror(errno));
		ပွၵ်ႈ -1;
	}

	ပေႃး (n != 1) {
		error_f("recvmsg: expected received 1 got %zd", n);
		ပွၵ်ႈ -1;
	}

#ifdef HAVE_ACCRIGHTS_IN_MSGHDR
	ပေႃး (msg.msg_accrightslen != parimaa_na(fd)) {
		error_f("no fd");
		ပွၵ်ႈ -1;
	}
#ပေႃးဢမ်ႇ
	cmsg = CMSG_FIRSTHDR(&msg);
	ပေႃး (cmsg == NULL) {
		error_f("no message header");
		ပွၵ်ႈ -1;
	}

#ifndef BROKEN_CMSG_TYPE
	ပေႃး (cmsg->cmsg_type != SCM_RIGHTS) {
		error_f("expected %d got %d", SCM_RIGHTS, cmsg->cmsg_type);
		ပွၵ်ႈ -1;
	}
#endif
	fd = (*(puur_naa_nka *)CMSG_DATA(cmsg));
#endif
	ပွၵ်ႈ fd;
#ပေႃးဢမ်ႇ
	error_f("file descriptor passing not supported");
	ပွၵ်ႈ -1;
#endif
}
