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

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <sys/socket.h>
#समावेश <sys/uio.h>
#समावेश <sys/un.h>

#समावेश <errno.h>
#समावेश <poll.h>
#समावेश <string.h>
#समावेश <stdarg.h>

#समावेश "log.h"
#समावेश "monitor_fdpass.h"

पूर्णांक
mm_send_fd(पूर्णांक sock, पूर्णांक fd)
{
#अगर defined(HAVE_SENDMSG) && (defined(HAVE_ACCRIGHTS_IN_MSGHDR) || defined(HAVE_CONTROL_IN_MSGHDR))
	काष्ठा msghdr संदेश;
#अगर_अघोषित HAVE_ACCRIGHTS_IN_MSGHDR
	जोड़ {
		काष्ठा cmsghdr hdr;
		अक्षर buf[CMSG_SPACE(माप(पूर्णांक))];
	} cmsgbuf;
	काष्ठा cmsghdr *cmsg;
#पूर्ण_अगर
	काष्ठा iovec vec;
	अक्षर ch = '\0';
	ssize_t n;
	काष्ठा pollfd pfd;

	स_रखो(&संदेश, 0, माप(संदेश));
#अगर_घोषित HAVE_ACCRIGHTS_IN_MSGHDR
	संदेश.संदेश_accrights = (caddr_t)&fd;
	संदेश.संदेश_accrightslen = माप(fd);
#अन्यथा
	स_रखो(&cmsgbuf, 0, माप(cmsgbuf));
	संदेश.msg_control = (caddr_t)&cmsgbuf.buf;
	संदेश.msg_controllen = माप(cmsgbuf.buf);
	cmsg = CMSG_FIRSTHDR(&संदेश);
	cmsg->cmsg_len = CMSG_LEN(माप(पूर्णांक));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	*(पूर्णांक *)CMSG_DATA(cmsg) = fd;
#पूर्ण_अगर

	vec.iov_base = &ch;
	vec.iov_len = 1;
	संदेश.msg_iov = &vec;
	संदेश.msg_iovlen = 1;

	pfd.fd = sock;
	pfd.events = POLLOUT;
	जबतक ((n = sendmsg(sock, &संदेश, 0)) == -1 &&
	    (त्रुटि_सं == EAGAIN || त्रुटि_सं == EINTR)) {
		debug3_f("sendmsg(%d): %s", fd, म_त्रुटि(त्रुटि_सं));
		(व्योम)poll(&pfd, 1, -1);
	}
	अगर (n == -1) {
		error_f("sendmsg(%d): %s", fd, म_त्रुटि(त्रुटि_सं));
		वापस -1;
	}

	अगर (n != 1) {
		error_f("sendmsg: expected sent 1 got %zd", n);
		वापस -1;
	}
	वापस 0;
#अन्यथा
	error_f("file descriptor passing not supported");
	वापस -1;
#पूर्ण_अगर
}

पूर्णांक
mm_receive_fd(पूर्णांक sock)
{
#अगर defined(HAVE_RECVMSG) && (defined(HAVE_ACCRIGHTS_IN_MSGHDR) || defined(HAVE_CONTROL_IN_MSGHDR))
	काष्ठा msghdr संदेश;
#अगर_अघोषित HAVE_ACCRIGHTS_IN_MSGHDR
	जोड़ {
		काष्ठा cmsghdr hdr;
		अक्षर buf[CMSG_SPACE(माप(पूर्णांक))];
	} cmsgbuf;
	काष्ठा cmsghdr *cmsg;
#पूर्ण_अगर
	काष्ठा iovec vec;
	ssize_t n;
	अक्षर ch;
	पूर्णांक fd;
	काष्ठा pollfd pfd;

	स_रखो(&संदेश, 0, माप(संदेश));
	vec.iov_base = &ch;
	vec.iov_len = 1;
	संदेश.msg_iov = &vec;
	संदेश.msg_iovlen = 1;
#अगर_घोषित HAVE_ACCRIGHTS_IN_MSGHDR
	संदेश.संदेश_accrights = (caddr_t)&fd;
	संदेश.संदेश_accrightslen = माप(fd);
#अन्यथा
	स_रखो(&cmsgbuf, 0, माप(cmsgbuf));
	संदेश.msg_control = &cmsgbuf.buf;
	संदेश.msg_controllen = माप(cmsgbuf.buf);
#पूर्ण_अगर

	pfd.fd = sock;
	pfd.events = POLLIN;
	जबतक ((n = recvmsg(sock, &संदेश, 0)) == -1 &&
	    (त्रुटि_सं == EAGAIN || त्रुटि_सं == EINTR)) {
		debug3_f("recvmsg: %s", म_त्रुटि(त्रुटि_सं));
		(व्योम)poll(&pfd, 1, -1);
	}
	अगर (n == -1) {
		error_f("recvmsg: %s", म_त्रुटि(त्रुटि_सं));
		वापस -1;
	}

	अगर (n != 1) {
		error_f("recvmsg: expected received 1 got %zd", n);
		वापस -1;
	}

#अगर_घोषित HAVE_ACCRIGHTS_IN_MSGHDR
	अगर (संदेश.संदेश_accrightslen != माप(fd)) {
		error_f("no fd");
		वापस -1;
	}
#अन्यथा
	cmsg = CMSG_FIRSTHDR(&संदेश);
	अगर (cmsg == शून्य) {
		error_f("no message header");
		वापस -1;
	}

#अगर_अघोषित BROKEN_CMSG_TYPE
	अगर (cmsg->cmsg_type != SCM_RIGHTS) {
		error_f("expected %d got %d", SCM_RIGHTS, cmsg->cmsg_type);
		वापस -1;
	}
#पूर्ण_अगर
	fd = (*(पूर्णांक *)CMSG_DATA(cmsg));
#पूर्ण_अगर
	वापस fd;
#अन्यथा
	error_f("file descriptor passing not supported");
	वापस -1;
#पूर्ण_अगर
}
