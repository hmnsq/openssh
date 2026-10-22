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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/socket.h>
#அந்தர்பாவ <sys/uio.h>
#அந்தர்பாவ <sys/un.h>

#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <poll.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <stdarg.h>

#அந்தர்பாவ "log.h"
#அந்தர்பாவ "monitor_fdpass.h"

முழு
mm_send_fd(முழு sock, முழு fd)
{
#எனில் defined(HAVE_SENDMSG) && (defined(HAVE_ACCRIGHTS_IN_MSGHDR) || defined(HAVE_CONTROL_IN_MSGHDR))
	கட்டமைப்பு msghdr செய்தி;
#ifndef HAVE_ACCRIGHTS_IN_MSGHDR
	ஒன்றிப்பு {
		கட்டமைப்பு cmsghdr hdr;
		எழுத்து buf[CMSG_SPACE(அளவு(முழு))];
	} cmsgbuf;
	கட்டமைப்பு cmsghdr *cmsg;
#endif
	கட்டமைப்பு iovec vec;
	எழுத்து ch = '\0';
	ssize_t n;
	கட்டமைப்பு pollfd pfd;

	memset(&செய்தி, 0, அளவு(செய்தி));
#ifdef HAVE_ACCRIGHTS_IN_MSGHDR
	செய்தி.செய்தி_accrights = (caddr_t)&fd;
	செய்தி.செய்தி_accrightslen = அளவு(fd);
#இல்லையெனில்
	memset(&cmsgbuf, 0, அளவு(cmsgbuf));
	செய்தி.msg_control = (caddr_t)&cmsgbuf.buf;
	செய்தி.msg_controllen = அளவு(cmsgbuf.buf);
	cmsg = CMSG_FIRSTHDR(&செய்தி);
	cmsg->cmsg_len = CMSG_LEN(அளவு(முழு));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	*(முழு *)CMSG_DATA(cmsg) = fd;
#endif

	vec.iov_base = &ch;
	vec.iov_len = 1;
	செய்தி.msg_iov = &vec;
	செய்தி.msg_iovlen = 1;

	pfd.fd = sock;
	pfd.events = POLLOUT;
	போது ((n = sendmsg(sock, &செய்தி, 0)) == -1 &&
	    (errno == EAGAIN || errno == EINTR)) {
		debug3_f("sendmsg(%d): %s", fd, strerror(errno));
		(வெறுமை)poll(&pfd, 1, -1);
	}
	எனில் (n == -1) {
		error_f("sendmsg(%d): %s", fd, strerror(errno));
		திரும்பு -1;
	}

	எனில் (n != 1) {
		error_f("sendmsg: expected sent 1 got %zd", n);
		திரும்பு -1;
	}
	திரும்பு 0;
#இல்லையெனில்
	error_f("file descriptor passing not supported");
	திரும்பு -1;
#endif
}

முழு
mm_receive_fd(முழு sock)
{
#எனில் defined(HAVE_RECVMSG) && (defined(HAVE_ACCRIGHTS_IN_MSGHDR) || defined(HAVE_CONTROL_IN_MSGHDR))
	கட்டமைப்பு msghdr செய்தி;
#ifndef HAVE_ACCRIGHTS_IN_MSGHDR
	ஒன்றிப்பு {
		கட்டமைப்பு cmsghdr hdr;
		எழுத்து buf[CMSG_SPACE(அளவு(முழு))];
	} cmsgbuf;
	கட்டமைப்பு cmsghdr *cmsg;
#endif
	கட்டமைப்பு iovec vec;
	ssize_t n;
	எழுத்து ch;
	முழு fd;
	கட்டமைப்பு pollfd pfd;

	memset(&செய்தி, 0, அளவு(செய்தி));
	vec.iov_base = &ch;
	vec.iov_len = 1;
	செய்தி.msg_iov = &vec;
	செய்தி.msg_iovlen = 1;
#ifdef HAVE_ACCRIGHTS_IN_MSGHDR
	செய்தி.செய்தி_accrights = (caddr_t)&fd;
	செய்தி.செய்தி_accrightslen = அளவு(fd);
#இல்லையெனில்
	memset(&cmsgbuf, 0, அளவு(cmsgbuf));
	செய்தி.msg_control = &cmsgbuf.buf;
	செய்தி.msg_controllen = அளவு(cmsgbuf.buf);
#endif

	pfd.fd = sock;
	pfd.events = POLLIN;
	போது ((n = recvmsg(sock, &செய்தி, 0)) == -1 &&
	    (errno == EAGAIN || errno == EINTR)) {
		debug3_f("recvmsg: %s", strerror(errno));
		(வெறுமை)poll(&pfd, 1, -1);
	}
	எனில் (n == -1) {
		error_f("recvmsg: %s", strerror(errno));
		திரும்பு -1;
	}

	எனில் (n != 1) {
		error_f("recvmsg: expected received 1 got %zd", n);
		திரும்பு -1;
	}

#ifdef HAVE_ACCRIGHTS_IN_MSGHDR
	எனில் (செய்தி.செய்தி_accrightslen != அளவு(fd)) {
		error_f("no fd");
		திரும்பு -1;
	}
#இல்லையெனில்
	cmsg = CMSG_FIRSTHDR(&செய்தி);
	எனில் (cmsg == வெற்று) {
		error_f("no message header");
		திரும்பு -1;
	}

#ifndef BROKEN_CMSG_TYPE
	எனில் (cmsg->cmsg_type != SCM_RIGHTS) {
		error_f("expected %d got %d", SCM_RIGHTS, cmsg->cmsg_type);
		திரும்பு -1;
	}
#endif
	fd = (*(முழு *)CMSG_DATA(cmsg));
#endif
	திரும்பு fd;
#இல்லையெனில்
	error_f("file descriptor passing not supported");
	திரும்பு -1;
#endif
}
