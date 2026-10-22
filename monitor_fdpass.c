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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/socket.h>
#అన్తర్భావ <sys/uio.h>
#అన్తర్భావ <sys/un.h>

#అన్తర్భావ <errno.h>
#అన్తర్భావ <poll.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <stdarg.h>

#అన్తర్భావ "log.h"
#అన్తర్భావ "monitor_fdpass.h"

పూర్ణాంకం
mm_send_fd(పూర్ణాంకం sock, పూర్ణాంకం fd)
{
#ఒకవేళ defined(HAVE_SENDMSG) && (defined(HAVE_ACCRIGHTS_లోపల_MSGHDR) || defined(HAVE_CONTROL_లోపల_MSGHDR))
	నిర్మాణం msghdr సందేశం;
#నిర్వచితం_కాకపోతే HAVE_ACCRIGHTS_లోపల_MSGHDR
	సంఘం {
		నిర్మాణం cmsghdr hdr;
		అక్షరం buf[CMSG_SPACE(పరిమాణం(పూర్ణాంకం))];
	} cmsgbuf;
	నిర్మాణం cmsghdr *cmsg;
#అయితే_ముగింపు
	నిర్మాణం iovec vec;
	అక్షరం ch = '\0';
	ssize_t n;
	నిర్మాణం pollfd pfd;

	memset(&సందేశం, 0, పరిమాణం(సందేశం));
#నిర్వచితమైతే HAVE_ACCRIGHTS_లోపల_MSGHDR
	సందేశం.సందేశం_accrights = (caddr_t)&fd;
	సందేశం.సందేశం_accrightslen = పరిమాణం(fd);
#లేకపోతే
	memset(&cmsgbuf, 0, పరిమాణం(cmsgbuf));
	సందేశం.msg_control = (caddr_t)&cmsgbuf.buf;
	సందేశం.msg_controllen = పరిమాణం(cmsgbuf.buf);
	cmsg = CMSG_FIRSTHDR(&సందేశం);
	cmsg->cmsg_len = CMSG_LEN(పరిమాణం(పూర్ణాంకం));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	*(పూర్ణాంకం *)CMSG_DATA(cmsg) = fd;
#అయితే_ముగింపు

	vec.iov_base = &ch;
	vec.iov_len = 1;
	సందేశం.msg_iov = &vec;
	సందేశం.msg_iovlen = 1;

	pfd.fd = sock;
	pfd.events = POLLOUT;
	అయితే ((n = sendmsg(sock, &సందేశం, 0)) == -1 &&
	    (errno == EAGAIN || errno == EINTR)) {
		debug3_f("sendmsg(%d): %s", fd, strerror(errno));
		(శూన్య)poll(&pfd, 1, -1);
	}
	ఒకవేళ (n == -1) {
		error_f("sendmsg(%d): %s", fd, strerror(errno));
		తిరిగి -1;
	}

	ఒకవేళ (n != 1) {
		error_f("sendmsg: expected sent 1 got %zd", n);
		తిరిగి -1;
	}
	తిరిగి 0;
#లేకపోతే
	error_f("file descriptor passing not supported");
	తిరిగి -1;
#అయితే_ముగింపు
}

పూర్ణాంకం
mm_receive_fd(పూర్ణాంకం sock)
{
#ఒకవేళ defined(HAVE_RECVMSG) && (defined(HAVE_ACCRIGHTS_లోపల_MSGHDR) || defined(HAVE_CONTROL_లోపల_MSGHDR))
	నిర్మాణం msghdr సందేశం;
#నిర్వచితం_కాకపోతే HAVE_ACCRIGHTS_లోపల_MSGHDR
	సంఘం {
		నిర్మాణం cmsghdr hdr;
		అక్షరం buf[CMSG_SPACE(పరిమాణం(పూర్ణాంకం))];
	} cmsgbuf;
	నిర్మాణం cmsghdr *cmsg;
#అయితే_ముగింపు
	నిర్మాణం iovec vec;
	ssize_t n;
	అక్షరం ch;
	పూర్ణాంకం fd;
	నిర్మాణం pollfd pfd;

	memset(&సందేశం, 0, పరిమాణం(సందేశం));
	vec.iov_base = &ch;
	vec.iov_len = 1;
	సందేశం.msg_iov = &vec;
	సందేశం.msg_iovlen = 1;
#నిర్వచితమైతే HAVE_ACCRIGHTS_లోపల_MSGHDR
	సందేశం.సందేశం_accrights = (caddr_t)&fd;
	సందేశం.సందేశం_accrightslen = పరిమాణం(fd);
#లేకపోతే
	memset(&cmsgbuf, 0, పరిమాణం(cmsgbuf));
	సందేశం.msg_control = &cmsgbuf.buf;
	సందేశం.msg_controllen = పరిమాణం(cmsgbuf.buf);
#అయితే_ముగింపు

	pfd.fd = sock;
	pfd.events = POLLIN;
	అయితే ((n = recvmsg(sock, &సందేశం, 0)) == -1 &&
	    (errno == EAGAIN || errno == EINTR)) {
		debug3_f("recvmsg: %s", strerror(errno));
		(శూన్య)poll(&pfd, 1, -1);
	}
	ఒకవేళ (n == -1) {
		error_f("recvmsg: %s", strerror(errno));
		తిరిగి -1;
	}

	ఒకవేళ (n != 1) {
		error_f("recvmsg: expected received 1 got %zd", n);
		తిరిగి -1;
	}

#నిర్వచితమైతే HAVE_ACCRIGHTS_లోపల_MSGHDR
	ఒకవేళ (సందేశం.సందేశం_accrightslen != పరిమాణం(fd)) {
		error_f("no fd");
		తిరిగి -1;
	}
#లేకపోతే
	cmsg = CMSG_FIRSTHDR(&సందేశం);
	ఒకవేళ (cmsg == ఖాళీ) {
		error_f("no message header");
		తిరిగి -1;
	}

#నిర్వచితం_కాకపోతే BROKEN_CMSG_TYPE
	ఒకవేళ (cmsg->cmsg_type != SCM_RIGHTS) {
		error_f("expected %d got %d", SCM_RIGHTS, cmsg->cmsg_type);
		తిరిగి -1;
	}
#అయితే_ముగింపు
	fd = (*(పూర్ణాంకం *)CMSG_DATA(cmsg));
#అయితే_ముగింపు
	తిరిగి fd;
#లేకపోతే
	error_f("file descriptor passing not supported");
	తిరిగి -1;
#అయితే_ముగింపు
}
