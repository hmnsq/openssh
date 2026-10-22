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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>

#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>

#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "atomicio.h"
#ଅନ୍ତର୍ଭାଵ "msg.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_ସନ୍ଦେଶ_send(ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd, u_char type, ସଂରଚନା sshbuf *m)
{
	u_char buf[5];
	u_int mlen = sshbuf_len(m);

	debug3_f("type %u len %zu", (unsigned ପୂର୍ଣ୍ଣସଂଖ୍ୟା)type & 0xff, sshbuf_len(m));

	put_u32(buf, mlen + 1);
	buf[4] = type;		/* 1st byte of payload is mesg-type */
	ଯଦି (atomicio(vwrite, fd, buf, ଆକାର(buf)) != ଆକାର(buf)) {
		error_f("write: %s", strerror(errno));
		ଫେରନ୍ତୁ (-1);
	}
	ଯଦି (atomicio(vwrite, fd, sshbuf_mutable_ptr(m), mlen) != mlen) {
		error_f("write: %s", strerror(errno));
		ଫେରନ୍ତୁ (-1);
	}
	debug3_f("done");
	ଫେରନ୍ତୁ (0);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_ସନ୍ଦେଶ_recv(ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd, ସଂରଚନା sshbuf *m)
{
	u_char buf[4], *p;
	u_int ସନ୍ଦେଶ_len;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	debug3("ssh_msg_recv entering");

	ଯଦି (atomicio(ପଠ, fd, buf, ଆକାର(buf)) != ଆକାର(buf)) {
		ଯଦି (errno != EPIPE)
			error_f("read header: %s", strerror(errno));
		ଫେରନ୍ତୁ (-1);
	}
	ସନ୍ଦେଶ_len = get_u32(buf);
	ଯଦି (ସନ୍ଦେଶ_len > sshbuf_max_size(m)) {
		error_f("read: bad msg_len %u", ସନ୍ଦେଶ_len);
		ଫେରନ୍ତୁ (-1);
	}
	sshbuf_reset(m);
	ଯଦି ((r = sshbuf_reserve(m, ସନ୍ଦେଶ_len, &p)) != 0) {
		error_fr(r, "reserve");
		ଫେରନ୍ତୁ -1;
	}
	ଯଦି (atomicio(ପଠ, fd, p, ସନ୍ଦେଶ_len) != ସନ୍ଦେଶ_len) {
		error_f("read: %s", strerror(errno));
		ଫେରନ୍ତୁ (-1);
	}
	ଫେରନ୍ତୁ (0);
}
