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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>

#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <unistd.h>
#അന്തര്ഭാവ <stdarg.h>

#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "atomicio.h"
#അന്തര്ഭാവ "msg.h"
#അന്തര്ഭാവ "misc.h"

പൂർണ്ണസംഖ്യ
ssh_സന്ദേശം_send(പൂർണ്ണസംഖ്യ fd, u_char type, ഘടന sshbuf *m)
{
	u_char buf[5];
	u_int mlen = sshbuf_len(m);

	debug3_f("type %u len %zu", (unsigned പൂർണ്ണസംഖ്യ)type & 0xff, sshbuf_len(m));

	put_u32(buf, mlen + 1);
	buf[4] = type;		/* 1st byte of payload is mesg-type */
	എങ്കിൽ (atomicio(vwrite, fd, buf, വലുപ്പം(buf)) != വലുപ്പം(buf)) {
		error_f("write: %s", strerror(errno));
		തിരികെ (-1);
	}
	എങ്കിൽ (atomicio(vwrite, fd, sshbuf_mutable_ptr(m), mlen) != mlen) {
		error_f("write: %s", strerror(errno));
		തിരികെ (-1);
	}
	debug3_f("done");
	തിരികെ (0);
}

പൂർണ്ണസംഖ്യ
ssh_സന്ദേശം_recv(പൂർണ്ണസംഖ്യ fd, ഘടന sshbuf *m)
{
	u_char buf[4], *p;
	u_int സന്ദേശം_len;
	പൂർണ്ണസംഖ്യ r;

	debug3("ssh_msg_recv entering");

	എങ്കിൽ (atomicio(പഠ, fd, buf, വലുപ്പം(buf)) != വലുപ്പം(buf)) {
		എങ്കിൽ (errno != EPIPE)
			error_f("read header: %s", strerror(errno));
		തിരികെ (-1);
	}
	സന്ദേശം_len = get_u32(buf);
	എങ്കിൽ (സന്ദേശം_len > sshbuf_max_size(m)) {
		error_f("read: bad msg_len %u", സന്ദേശം_len);
		തിരികെ (-1);
	}
	sshbuf_reset(m);
	എങ്കിൽ ((r = sshbuf_reserve(m, സന്ദേശം_len, &p)) != 0) {
		error_fr(r, "reserve");
		തിരികെ -1;
	}
	എങ്കിൽ (atomicio(പഠ, fd, p, സന്ദേശം_len) != സന്ദേശം_len) {
		error_f("read: %s", strerror(errno));
		തിരികെ (-1);
	}
	തിരികെ (0);
}
