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

#ضمن "includes.h"

#ضمن <sys/types.h>

#ضمن <errno.h>
#ضمن <string.h>
#ضمن <unistd.h>
#ضمن <stdarg.h>

#ضمن "sshbuf.h"
#ضمن "log.h"
#ضمن "atomicio.h"
#ضمن "msg.h"
#ضمن "misc.h"

صحيح
ssh_پیغام_send(صحيح fd, u_char type, بنية sshbuf *m)
{
	u_char buf[5];
	u_int mlen = sshbuf_len(m);

	debug3_f("type %u len %zu", (unsigned صحيح)type & 0xff, sshbuf_len(m));

	put_u32(buf, mlen + 1);
	buf[4] = type;		/* 1st byte of payload is mesg-type */
	إذا (atomicio(vwrite, fd, buf, حجم(buf)) != حجم(buf)) {
		error_f("write: %s", strerror(errno));
		أرجع (-1);
	}
	إذا (atomicio(vwrite, fd, sshbuf_mutable_ptr(m), mlen) != mlen) {
		error_f("write: %s", strerror(errno));
		أرجع (-1);
	}
	debug3_f("done");
	أرجع (0);
}

صحيح
ssh_پیغام_recv(صحيح fd, بنية sshbuf *m)
{
	u_char buf[4], *p;
	u_int پیغام_len;
	صحيح r;

	debug3("ssh_msg_recv entering");

	إذا (atomicio(اقرأ, fd, buf, حجم(buf)) != حجم(buf)) {
		إذا (errno != EPIPE)
			error_f("read header: %s", strerror(errno));
		أرجع (-1);
	}
	پیغام_len = get_u32(buf);
	إذا (پیغام_len > sshbuf_max_size(m)) {
		error_f("read: bad msg_len %u", پیغام_len);
		أرجع (-1);
	}
	sshbuf_reset(m);
	إذا ((r = sshbuf_reserve(m, پیغام_len, &p)) != 0) {
		error_fr(r, "reserve");
		أرجع -1;
	}
	إذا (atomicio(اقرأ, fd, p, پیغام_len) != پیغام_len) {
		error_f("read: %s", strerror(errno));
		أرجع (-1);
	}
	أرجع (0);
}
