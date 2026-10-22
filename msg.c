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

#include "includes.h"

#include <sys/types.h>

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>

#include "sshbuf.h"
#include "log.h"
#include "atomicio.h"
#include "msg.h"
#include "misc.h"

puur_naa_nka
ssh_msg_send(puur_naa_nka fd, u_char type, sa_nracanaa sshbuf *m)
{
	u_char buf[5];
	u_int mlen = sshbuf_len(m);

	debug3_f("type %u len %zu", (unsigned puur_naa_nka)type & 0xff, sshbuf_len(m));

	put_u32(buf, mlen + 1);
	buf[4] = type;		/* 1st byte of payload is mesg-type */
	ᰀᰧ (atomicio(vwrite, fd, buf, parimaa_na(buf)) != parimaa_na(buf)) {
		error_f("write: %s", strerror(errno));
		ᰀᰧᰌ (-1);
	}
	ᰀᰧ (atomicio(vwrite, fd, sshbuf_mutable_ptr(m), mlen) != mlen) {
		error_f("write: %s", strerror(errno));
		ᰀᰧᰌ (-1);
	}
	debug3_f("done");
	ᰀᰧᰌ (0);
}

puur_naa_nka
ssh_msg_recv(puur_naa_nka fd, sa_nracanaa sshbuf *m)
{
	u_char buf[4], *p;
	u_int msg_len;
	puur_naa_nka r;

	debug3("ssh_msg_recv entering");

	ᰀᰧ (atomicio(read, fd, buf, parimaa_na(buf)) != parimaa_na(buf)) {
		ᰀᰧ (errno != EPIPE)
			error_f("read header: %s", strerror(errno));
		ᰀᰧᰌ (-1);
	}
	msg_len = get_u32(buf);
	ᰀᰧ (msg_len > sshbuf_max_size(m)) {
		error_f("read: bad msg_len %u", msg_len);
		ᰀᰧᰌ (-1);
	}
	sshbuf_reset(m);
	ᰀᰧ ((r = sshbuf_reserve(m, msg_len, &p)) != 0) {
		error_fr(r, "reserve");
		ᰀᰧᰌ -1;
	}
	ᰀᰧ (atomicio(read, fd, p, msg_len) != msg_len) {
		error_f("read: %s", strerror(errno));
		ᰀᰧᰌ (-1);
	}
	ᰀᰧᰌ (0);
}
