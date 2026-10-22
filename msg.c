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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "atomicio.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "msg.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"

ਪੂਰਨ
ssh_ਸੁਨੇਹਾ_send(ਪੂਰਨ fd, u_char type, ਬਣਤਰ sshbuf *m)
{
	u_char buf[5];
	u_int mlen = sshbuf_len(m);

	debug3_f("type %u len %zu", (ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ)type & 0xff, sshbuf_len(m));

	put_u32(buf, mlen + 1);
	buf[4] = type;		/* 1st byte of payload is mesg-type */
	ਜੇ (atomicio(vwrite, fd, buf, ਆਕਾਰ(buf)) != ਆਕਾਰ(buf)) {
		error_f("write: %s", strerror(errno));
		ਵਾਪਸ (-1);
	}
	ਜੇ (atomicio(vwrite, fd, sshbuf_mutable_ptr(m), mlen) != mlen) {
		error_f("write: %s", strerror(errno));
		ਵਾਪਸ (-1);
	}
	debug3_f("done");
	ਵਾਪਸ (0);
}

ਪੂਰਨ
ssh_ਸੁਨੇਹਾ_recv(ਪੂਰਨ fd, ਬਣਤਰ sshbuf *m)
{
	u_char buf[4], *p;
	u_int ਸੁਨੇਹਾ_len;
	ਪੂਰਨ r;

	debug3("ssh_msg_recv entering");

	ਜੇ (atomicio(ਪਠ, fd, buf, ਆਕਾਰ(buf)) != ਆਕਾਰ(buf)) {
		ਜੇ (errno != EPIPE)
			error_f("read header: %s", strerror(errno));
		ਵਾਪਸ (-1);
	}
	ਸੁਨੇਹਾ_len = get_u32(buf);
	ਜੇ (ਸੁਨੇਹਾ_len > sshbuf_max_ਮਾਪ(m)) {
		error_f("read: bad msg_len %u", ਸੁਨੇਹਾ_len);
		ਵਾਪਸ (-1);
	}
	sshbuf_reset(m);
	ਜੇ ((r = sshbuf_reserve(m, ਸੁਨੇਹਾ_len, &p)) != 0) {
		error_fr(r, "reserve");
		ਵਾਪਸ -1;
	}
	ਜੇ (atomicio(ਪਠ, fd, p, ਸੁਨੇਹਾ_len) != ਸੁਨੇਹਾ_len) {
		error_f("read: %s", strerror(errno));
		ਵਾਪਸ (-1);
	}
	ਵਾਪਸ (0);
}
