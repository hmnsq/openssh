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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>

#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <unistd.h>
#અન્તર્ભાવ <stdarg.h>

#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "atomicio.h"
#અન્તર્ભાવ "msg.h"
#અન્તર્ભાવ "misc.h"

પૂર્ણાંક
ssh_સંદેશ_send(પૂર્ણાંક fd, u_char type, સંરચના sshbuf *m)
{
	u_char buf[5];
	u_int mlen = sshbuf_len(m);

	debug3_f("type %u len %zu", (unsigned પૂર્ણાંક)type & 0xff, sshbuf_len(m));

	put_u32(buf, mlen + 1);
	buf[4] = type;		/* 1st byte of payload is mesg-type */
	જો (atomicio(vwrite, fd, buf, કદ(buf)) != કદ(buf)) {
		error_f("write: %s", strerror(errno));
		પાછા (-1);
	}
	જો (atomicio(vwrite, fd, sshbuf_mutable_ptr(m), mlen) != mlen) {
		error_f("write: %s", strerror(errno));
		પાછા (-1);
	}
	debug3_f("done");
	પાછા (0);
}

પૂર્ણાંક
ssh_સંદેશ_recv(પૂર્ણાંક fd, સંરચના sshbuf *m)
{
	u_char buf[4], *p;
	u_int સંદેશ_len;
	પૂર્ણાંક r;

	debug3("ssh_msg_recv entering");

	જો (atomicio(પઠ, fd, buf, કદ(buf)) != કદ(buf)) {
		જો (errno != EPIPE)
			error_f("read header: %s", strerror(errno));
		પાછા (-1);
	}
	સંદેશ_len = get_u32(buf);
	જો (સંદેશ_len > sshbuf_max_size(m)) {
		error_f("read: bad msg_len %u", સંદેશ_len);
		પાછા (-1);
	}
	sshbuf_reset(m);
	જો ((r = sshbuf_reserve(m, સંદેશ_len, &p)) != 0) {
		error_fr(r, "reserve");
		પાછા -1;
	}
	જો (atomicio(પઠ, fd, p, સંદેશ_len) != સંદેશ_len) {
		error_f("read: %s", strerror(errno));
		પાછા (-1);
	}
	પાછા (0);
}
