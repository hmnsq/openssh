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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>

#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>

#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "atomicio.h"
#ಅನ್ತರ್ಭಾವ "msg.h"
#ಅನ್ತರ್ಭಾವ "misc.h"

ಪೂರ್ಣಾಂಕ
ssh_ಸಂದೇಶ_send(ಪೂರ್ಣಾಂಕ fd, u_char type, ರಚನೆ sshbuf *m)
{
	u_char buf[5];
	u_int mlen = sshbuf_len(m);

	debug3_f("type %u len %zu", (ಚಿಹ್ನೆರಹಿತ ಪೂರ್ಣಾಂಕ)type & 0xff, sshbuf_len(m));

	put_u32(buf, mlen + 1);
	buf[4] = type;		/* 1st byte of payload is mesg-type */
	ಆದರೆ (atomicio(vwrite, fd, buf, ಗಾತ್ರ(buf)) != ಗಾತ್ರ(buf)) {
		error_f("write: %s", strerror(errno));
		ಹಿಂತಿರುಗಿ (-1);
	}
	ಆದರೆ (atomicio(vwrite, fd, sshbuf_mutable_ptr(m), mlen) != mlen) {
		error_f("write: %s", strerror(errno));
		ಹಿಂತಿರುಗಿ (-1);
	}
	debug3_f("done");
	ಹಿಂತಿರುಗಿ (0);
}

ಪೂರ್ಣಾಂಕ
ssh_ಸಂದೇಶ_recv(ಪೂರ್ಣಾಂಕ fd, ರಚನೆ sshbuf *m)
{
	u_char buf[4], *p;
	u_int ಸಂದೇಶ_len;
	ಪೂರ್ಣಾಂಕ r;

	debug3("ssh_msg_recv entering");

	ಆದರೆ (atomicio(ಪಠ, fd, buf, ಗಾತ್ರ(buf)) != ಗಾತ್ರ(buf)) {
		ಆದರೆ (errno != EPIPE)
			error_f("read header: %s", strerror(errno));
		ಹಿಂತಿರುಗಿ (-1);
	}
	ಸಂದೇಶ_len = get_u32(buf);
	ಆದರೆ (ಸಂದೇಶ_len > sshbuf_max_ಗಾತ್ರ(m)) {
		error_f("read: bad msg_len %u", ಸಂದೇಶ_len);
		ಹಿಂತಿರುಗಿ (-1);
	}
	sshbuf_reset(m);
	ಆದರೆ ((r = sshbuf_reserve(m, ಸಂದೇಶ_len, &p)) != 0) {
		error_fr(r, "reserve");
		ಹಿಂತಿರುಗಿ -1;
	}
	ಆದರೆ (atomicio(ಪಠ, fd, p, ಸಂದೇಶ_len) != ಸಂದೇಶ_len) {
		error_f("read: %s", strerror(errno));
		ಹಿಂತಿರುಗಿ (-1);
	}
	ಹಿಂತಿರುಗಿ (0);
}
