/* $OpenBSD: msg.c,v 1.22 2026/02/14 00:18:34 jsg Exp $ */
/*
 * Copyright (c) 2002 Markus Friedl.  All rights reserved.
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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>

#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <unistd.h>
#অন্তর্ভাব <stdarg.h>

#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "log.h"
#অন্তর্ভাব "atomicio.h"
#অন্তর্ভাব "msg.h"
#অন্তর্ভাব "misc.h"

পূর্ণসংখ্যা
ssh_বার্তা_send(পূর্ণসংখ্যা fd, u_char type, কাঠামো sshbuf *m)
{
	u_char buf[5];
	u_int mlen = sshbuf_len(m);

	debug3_f("type %u len %zu", (unsigned পূর্ণসংখ্যা)type & 0xff, sshbuf_len(m));

	put_u32(buf, mlen + 1);
	buf[4] = type;		/* 1st byte of payload is mesg-type */
	যদি (atomicio(vwrite, fd, buf, আকার(buf)) != আকার(buf)) {
		error_f("write: %s", strerror(errno));
		ফেরত (-1);
	}
	যদি (atomicio(vwrite, fd, sshbuf_mutable_ptr(m), mlen) != mlen) {
		error_f("write: %s", strerror(errno));
		ফেরত (-1);
	}
	debug3_f("done");
	ফেরত (0);
}

পূর্ণসংখ্যা
ssh_বার্তা_recv(পূর্ণসংখ্যা fd, কাঠামো sshbuf *m)
{
	u_char buf[4], *p;
	u_int বার্তা_len;
	পূর্ণসংখ্যা r;

	debug3("ssh_msg_recv entering");

	যদি (atomicio(পঠ, fd, buf, আকার(buf)) != আকার(buf)) {
		যদি (errno != EPIPE)
			error_f("read header: %s", strerror(errno));
		ফেরত (-1);
	}
	বার্তা_len = get_u32(buf);
	যদি (বার্তা_len > sshbuf_max_আকার(m)) {
		error_f("read: bad msg_len %u", বার্তা_len);
		ফেরত (-1);
	}
	sshbuf_reset(m);
	যদি ((r = sshbuf_reserve(m, বার্তা_len, &p)) != 0) {
		error_fr(r, "reserve");
		ফেরত -1;
	}
	যদি (atomicio(পঠ, fd, p, বার্তা_len) != বার্তা_len) {
		error_f("read: %s", strerror(errno));
		ফেরত (-1);
	}
	ফেরত (0);
}
