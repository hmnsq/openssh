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

#समावेश "includes.h"

#समावेश <sys/types.h>

#समावेश <errno.h>
#समावेश <string.h>
#समावेश <unistd.h>
#समावेश <stdarg.h>

#समावेश "sshbuf.h"
#समावेश "log.h"
#समावेश "atomicio.h"
#समावेश "msg.h"
#समावेश "misc.h"

पूर्णांक
ssh_संदेश_send(पूर्णांक fd, u_char type, काष्ठा sshbuf *m)
{
	u_char buf[5];
	u_int mlen = sshbuf_len(m);

	debug3_f("type %u len %zu", (अचिन्हित पूर्णांक)type & 0xff, sshbuf_len(m));

	put_u32(buf, mlen + 1);
	buf[4] = type;		/* 1st byte of payload is mesg-type */
	अगर (atomicio(vwrite, fd, buf, माप(buf)) != माप(buf)) {
		error_f("write: %s", म_त्रुटि(त्रुटि_सं));
		वापस (-1);
	}
	अगर (atomicio(vwrite, fd, sshbuf_mutable_ptr(m), mlen) != mlen) {
		error_f("write: %s", म_त्रुटि(त्रुटि_सं));
		वापस (-1);
	}
	debug3_f("done");
	वापस (0);
}

पूर्णांक
ssh_संदेश_recv(पूर्णांक fd, काष्ठा sshbuf *m)
{
	u_char buf[4], *p;
	u_int संदेश_len;
	पूर्णांक r;

	debug3("ssh_msg_recv entering");

	अगर (atomicio(पढ़ो, fd, buf, माप(buf)) != माप(buf)) {
		अगर (त्रुटि_सं != EPIPE)
			error_f("read header: %s", म_त्रुटि(त्रुटि_सं));
		वापस (-1);
	}
	संदेश_len = get_u32(buf);
	अगर (संदेश_len > sshbuf_max_आकार(m)) {
		error_f("read: bad msg_len %u", संदेश_len);
		वापस (-1);
	}
	sshbuf_reset(m);
	अगर ((r = sshbuf_reserve(m, संदेश_len, &p)) != 0) {
		error_fr(r, "reserve");
		वापस -1;
	}
	अगर (atomicio(पढ़ो, fd, p, संदेश_len) != संदेश_len) {
		error_f("read: %s", म_त्रुटि(त्रुटि_सं));
		वापस (-1);
	}
	वापस (0);
}
