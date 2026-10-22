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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>

#अन्तर्भाव <errno.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <unistd.h>
#अन्तर्भाव <stdarg.h>

#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "atomicio.h"
#अन्तर्भाव "msg.h"
#अन्तर्भाव "misc.h"

पूर्णाङ्क
ssh_सन्देशः_send(पूर्णाङ्क fd, u_char type, संरचना sshbuf *m)
{
	u_char buf[5];
	u_int mlen = sshbuf_len(m);

	debug3_f("type %u len %zu", (अचिह्नित पूर्णाङ्क)type & 0xff, sshbuf_len(m));

	put_u32(buf, mlen + 1);
	buf[4] = type;		/* 1st byte of payload is mesg-type */
	यदि (atomicio(vwrite, fd, buf, परिमाण(buf)) != परिमाण(buf)) {
		error_f("write: %s", strerror(errno));
		प्रत्यागम (-1);
	}
	यदि (atomicio(vwrite, fd, sshbuf_mutable_ptr(m), mlen) != mlen) {
		error_f("write: %s", strerror(errno));
		प्रत्यागम (-1);
	}
	debug3_f("done");
	प्रत्यागम (0);
}

पूर्णाङ्क
ssh_सन्देशः_recv(पूर्णाङ्क fd, संरचना sshbuf *m)
{
	u_char buf[4], *p;
	u_int सन्देशः_len;
	पूर्णाङ्क r;

	debug3("ssh_msg_recv entering");

	यदि (atomicio(पठ, fd, buf, परिमाण(buf)) != परिमाण(buf)) {
		यदि (errno != EPIPE)
			error_f("read header: %s", strerror(errno));
		प्रत्यागम (-1);
	}
	सन्देशः_len = get_u32(buf);
	यदि (सन्देशः_len > sshbuf_max_आकार(m)) {
		error_f("read: bad msg_len %u", सन्देशः_len);
		प्रत्यागम (-1);
	}
	sshbuf_reset(m);
	यदि ((r = sshbuf_reserve(m, सन्देशः_len, &p)) != 0) {
		error_fr(r, "reserve");
		प्रत्यागम -1;
	}
	यदि (atomicio(पठ, fd, p, सन्देशः_len) != सन्देशः_len) {
		error_f("read: %s", strerror(errno));
		प्रत्यागम (-1);
	}
	प्रत्यागम (0);
}
