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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>

#అన్తర్భావ <errno.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <unistd.h>
#అన్తర్భావ <stdarg.h>

#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "atomicio.h"
#అన్తర్భావ "msg.h"
#అన్తర్భావ "misc.h"

పూర్ణాంకం
ssh_సందేశం_send(పూర్ణాంకం fd, u_char type, నిర్మాణం sshbuf *m)
{
	u_char buf[5];
	u_int mlen = sshbuf_len(m);

	debug3_f("type %u len %zu", (గుర్తులేని పూర్ణాంకం)type & 0xff, sshbuf_len(m));

	put_u32(buf, mlen + 1);
	buf[4] = type;		/* 1st byte of payload is mesg-type */
	ఒకవేళ (atomicio(vwrite, fd, buf, పరిమాణం(buf)) != పరిమాణం(buf)) {
		error_f("write: %s", strerror(errno));
		తిరిగి (-1);
	}
	ఒకవేళ (atomicio(vwrite, fd, sshbuf_mutable_ptr(m), mlen) != mlen) {
		error_f("write: %s", strerror(errno));
		తిరిగి (-1);
	}
	debug3_f("done");
	తిరిగి (0);
}

పూర్ణాంకం
ssh_సందేశం_recv(పూర్ణాంకం fd, నిర్మాణం sshbuf *m)
{
	u_char buf[4], *p;
	u_int సందేశం_len;
	పూర్ణాంకం r;

	debug3("ssh_msg_recv entering");

	ఒకవేళ (atomicio(పఠ, fd, buf, పరిమాణం(buf)) != పరిమాణం(buf)) {
		ఒకవేళ (errno != EPIPE)
			error_f("read header: %s", strerror(errno));
		తిరిగి (-1);
	}
	సందేశం_len = get_u32(buf);
	ఒకవేళ (సందేశం_len > sshbuf_max_కొలత(m)) {
		error_f("read: bad msg_len %u", సందేశం_len);
		తిరిగి (-1);
	}
	sshbuf_reset(m);
	ఒకవేళ ((r = sshbuf_reserve(m, సందేశం_len, &p)) != 0) {
		error_fr(r, "reserve");
		తిరిగి -1;
	}
	ఒకవేళ (atomicio(పఠ, fd, p, సందేశం_len) != సందేశం_len) {
		error_f("read: %s", strerror(errno));
		తిరిగి (-1);
	}
	తిరిగి (0);
}
