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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>

#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <unistd.h>
#அந்தர்பாவ <stdarg.h>

#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "log.h"
#அந்தர்பாவ "atomicio.h"
#அந்தர்பாவ "msg.h"
#அந்தர்பாவ "misc.h"

முழு
ssh_செய்தி_send(முழு fd, u_char type, கட்டமைப்பு sshbuf *m)
{
	u_char buf[5];
	u_int mlen = sshbuf_len(m);

	debug3_f("type %u len %zu", (unsigned முழு)type & 0xff, sshbuf_len(m));

	put_u32(buf, mlen + 1);
	buf[4] = type;		/* 1st byte of payload is mesg-type */
	எனில் (atomicio(vwrite, fd, buf, அளவு(buf)) != அளவு(buf)) {
		error_f("write: %s", strerror(errno));
		திரும்பு (-1);
	}
	எனில் (atomicio(vwrite, fd, sshbuf_mutable_ptr(m), mlen) != mlen) {
		error_f("write: %s", strerror(errno));
		திரும்பு (-1);
	}
	debug3_f("done");
	திரும்பு (0);
}

முழு
ssh_செய்தி_recv(முழு fd, கட்டமைப்பு sshbuf *m)
{
	u_char buf[4], *p;
	u_int செய்தி_len;
	முழு r;

	debug3("ssh_msg_recv entering");

	எனில் (atomicio(பட, fd, buf, அளவு(buf)) != அளவு(buf)) {
		எனில் (errno != EPIPE)
			error_f("read header: %s", strerror(errno));
		திரும்பு (-1);
	}
	செய்தி_len = get_u32(buf);
	எனில் (செய்தி_len > sshbuf_max_size(m)) {
		error_f("read: bad msg_len %u", செய்தி_len);
		திரும்பு (-1);
	}
	sshbuf_reset(m);
	எனில் ((r = sshbuf_reserve(m, செய்தி_len, &p)) != 0) {
		error_fr(r, "reserve");
		திரும்பு -1;
	}
	எனில் (atomicio(பட, fd, p, செய்தி_len) != செய்தி_len) {
		error_f("read: %s", strerror(errno));
		திரும்பு (-1);
	}
	திரும்பு (0);
}
