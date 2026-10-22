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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/socket.h>
#ଅନ୍ତର୍ଭାଵ <sys/uio.h>
#ଅନ୍ତର୍ଭାଵ <sys/un.h>

#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <poll.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>

#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "monitor_fdpass.h"

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mm_send_fd(ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock, ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd)
{
#ଯଦି defined(HAVE_SENDMSG) && (defined(HAVE_ACCRIGHTS_IN_MSGHDR) || defined(HAVE_CONTROL_IN_MSGHDR))
	ସଂରଚନା msghdr ସନ୍ଦେଶ;
#ifndef HAVE_ACCRIGHTS_IN_MSGHDR
	ସଂଘ {
		ସଂରଚନା cmsghdr hdr;
		ଅକ୍ଷର buf[CMSG_SPACE(ଆକାର(ପୂର୍ଣ୍ଣସଂଖ୍ୟା))];
	} cmsgbuf;
	ସଂରଚନା cmsghdr *cmsg;
#endif
	ସଂରଚନା iovec vec;
	ଅକ୍ଷର ch = '\0';
	ssize_t n;
	ସଂରଚନା pollfd pfd;

	memset(&ସନ୍ଦେଶ, 0, ଆକାର(ସନ୍ଦେଶ));
#ifdef HAVE_ACCRIGHTS_IN_MSGHDR
	ସନ୍ଦେଶ.ସନ୍ଦେଶ_accrights = (caddr_t)&fd;
	ସନ୍ଦେଶ.ସନ୍ଦେଶ_accrightslen = ଆକାର(fd);
#ଅନ୍ୟଥା
	memset(&cmsgbuf, 0, ଆକାର(cmsgbuf));
	ସନ୍ଦେଶ.msg_control = (caddr_t)&cmsgbuf.buf;
	ସନ୍ଦେଶ.msg_controllen = ଆକାର(cmsgbuf.buf);
	cmsg = CMSG_FIRSTHDR(&ସନ୍ଦେଶ);
	cmsg->cmsg_len = CMSG_LEN(ଆକାର(ପୂର୍ଣ୍ଣସଂଖ୍ୟା));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	*(ପୂର୍ଣ୍ଣସଂଖ୍ୟା *)CMSG_DATA(cmsg) = fd;
#endif

	vec.iov_base = &ch;
	vec.iov_len = 1;
	ସନ୍ଦେଶ.msg_iov = &vec;
	ସନ୍ଦେଶ.msg_iovlen = 1;

	pfd.fd = sock;
	pfd.events = POLLOUT;
	ଯେତେବେଳେ ((n = sendmsg(sock, &ସନ୍ଦେଶ, 0)) == -1 &&
	    (errno == EAGAIN || errno == EINTR)) {
		debug3_f("sendmsg(%d): %s", fd, strerror(errno));
		(ଶୂନ୍ୟ)poll(&pfd, 1, -1);
	}
	ଯଦି (n == -1) {
		error_f("sendmsg(%d): %s", fd, strerror(errno));
		ଫେରନ୍ତୁ -1;
	}

	ଯଦି (n != 1) {
		error_f("sendmsg: expected sent 1 got %zd", n);
		ଫେରନ୍ତୁ -1;
	}
	ଫେରନ୍ତୁ 0;
#ଅନ୍ୟଥା
	error_f("file descriptor passing not supported");
	ଫେରନ୍ତୁ -1;
#endif
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mm_receive_fd(ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock)
{
#ଯଦି defined(HAVE_RECVMSG) && (defined(HAVE_ACCRIGHTS_IN_MSGHDR) || defined(HAVE_CONTROL_IN_MSGHDR))
	ସଂରଚନା msghdr ସନ୍ଦେଶ;
#ifndef HAVE_ACCRIGHTS_IN_MSGHDR
	ସଂଘ {
		ସଂରଚନା cmsghdr hdr;
		ଅକ୍ଷର buf[CMSG_SPACE(ଆକାର(ପୂର୍ଣ୍ଣସଂଖ୍ୟା))];
	} cmsgbuf;
	ସଂରଚନା cmsghdr *cmsg;
#endif
	ସଂରଚନା iovec vec;
	ssize_t n;
	ଅକ୍ଷର ch;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd;
	ସଂରଚନା pollfd pfd;

	memset(&ସନ୍ଦେଶ, 0, ଆକାର(ସନ୍ଦେଶ));
	vec.iov_base = &ch;
	vec.iov_len = 1;
	ସନ୍ଦେଶ.msg_iov = &vec;
	ସନ୍ଦେଶ.msg_iovlen = 1;
#ifdef HAVE_ACCRIGHTS_IN_MSGHDR
	ସନ୍ଦେଶ.ସନ୍ଦେଶ_accrights = (caddr_t)&fd;
	ସନ୍ଦେଶ.ସନ୍ଦେଶ_accrightslen = ଆକାର(fd);
#ଅନ୍ୟଥା
	memset(&cmsgbuf, 0, ଆକାର(cmsgbuf));
	ସନ୍ଦେଶ.msg_control = &cmsgbuf.buf;
	ସନ୍ଦେଶ.msg_controllen = ଆକାର(cmsgbuf.buf);
#endif

	pfd.fd = sock;
	pfd.events = POLLIN;
	ଯେତେବେଳେ ((n = recvmsg(sock, &ସନ୍ଦେଶ, 0)) == -1 &&
	    (errno == EAGAIN || errno == EINTR)) {
		debug3_f("recvmsg: %s", strerror(errno));
		(ଶୂନ୍ୟ)poll(&pfd, 1, -1);
	}
	ଯଦି (n == -1) {
		error_f("recvmsg: %s", strerror(errno));
		ଫେରନ୍ତୁ -1;
	}

	ଯଦି (n != 1) {
		error_f("recvmsg: expected received 1 got %zd", n);
		ଫେରନ୍ତୁ -1;
	}

#ifdef HAVE_ACCRIGHTS_IN_MSGHDR
	ଯଦି (ସନ୍ଦେଶ.ସନ୍ଦେଶ_accrightslen != ଆକାର(fd)) {
		error_f("no fd");
		ଫେରନ୍ତୁ -1;
	}
#ଅନ୍ୟଥା
	cmsg = CMSG_FIRSTHDR(&ସନ୍ଦେଶ);
	ଯଦି (cmsg == ଖାଲି) {
		error_f("no message header");
		ଫେରନ୍ତୁ -1;
	}

#ifndef BROKEN_CMSG_TYPE
	ଯଦି (cmsg->cmsg_type != SCM_RIGHTS) {
		error_f("expected %d got %d", SCM_RIGHTS, cmsg->cmsg_type);
		ଫେରନ୍ତୁ -1;
	}
#endif
	fd = (*(ପୂର୍ଣ୍ଣସଂଖ୍ୟା *)CMSG_DATA(cmsg));
#endif
	ଫେରନ୍ତୁ fd;
#ଅନ୍ୟଥା
	error_f("file descriptor passing not supported");
	ଫେରନ୍ତୁ -1;
#endif
}
