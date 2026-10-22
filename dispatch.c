/* $OpenBSD: dispatch.c,v 1.35 2026/03/03 09:57:25 dtucker Exp $ */
/*
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
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

#समावेश <signal.h>
#समावेश <stdarg.h>

#समावेश "ssh2.h"
#समावेश "log.h"
#समावेश "dispatch.h"
#समावेश "packet.h"
#समावेश "ssherr.h"

पूर्णांक
dispatch_protocol_error(पूर्णांक type, uint32_t seq, काष्ठा ssh *ssh)
{
	पूर्णांक r;

	logit_f("type %d seq %u", type, seq);
	अगर ((r = sshpkt_start(ssh, SSH2_संदेश_UNIMPLEMENTED)) != 0 ||
	    (r = sshpkt_put_u32(ssh, seq)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s", __func__);
	वापस 0;
}

पूर्णांक
dispatch_protocol_ignore(पूर्णांक type, uint32_t seq, काष्ठा ssh *ssh)
{
	logit_f("type %d seq %u", type, seq);
	वापस 0;
}

व्योम
ssh_dispatch_init(काष्ठा ssh *ssh, dispatch_fn *dflt)
{
	u_int i;
	क्रम (i = 0; i < DISPATCH_MAX; i++)
		ssh->dispatch[i] = dflt;
}

व्योम
ssh_dispatch_range(काष्ठा ssh *ssh, u_int from, u_int to, dispatch_fn *fn)
{
	u_int i;

	क्रम (i = from; i <= to; i++) {
		अगर (i >= DISPATCH_MAX)
			अवरोध;
		ssh->dispatch[i] = fn;
	}
}

व्योम
ssh_dispatch_set(काष्ठा ssh *ssh, पूर्णांक type, dispatch_fn *fn)
{
	ssh->dispatch[type] = fn;
}

पूर्णांक
ssh_dispatch_run(काष्ठा ssh *ssh, पूर्णांक mode, अस्थिर संक_पूर्ण_प्रकार *done)
{
	पूर्णांक r;
	u_char type;
	uint32_t seqnr;

	क्रम (;;) {
		अगर (mode == DISPATCH_BLOCK) {
			r = ssh_packet_read_seqnr(ssh, &type, &seqnr);
			अगर (r != 0)
				वापस r;
		} अन्यथा {
			r = ssh_packet_read_poll_seqnr(ssh, &type, &seqnr);
			अगर (r != 0)
				वापस r;
			अगर (type == SSH_संदेश_NONE)
				वापस 0;
		}
		अगर (type > 0 && type < DISPATCH_MAX &&
		    ssh->dispatch[type] != शून्य) {
			अगर (ssh->dispatch_skip_packets) {
				debug2("skipped packet (type %u)", type);
				ssh->dispatch_skip_packets--;
				जारी;
			}
			r = (*ssh->dispatch[type])(type, seqnr, ssh);
			अगर (r != 0)
				वापस r;
		} अन्यथा {
			r = sshpkt_disconnect(ssh,
			    "protocol error: rcvd type %d", type);
			अगर (r != 0)
				वापस r;
			वापस SSH_ERR_DISCONNECTED;
		}
		अगर (done != शून्य && *done)
			वापस 0;
	}
}

व्योम
ssh_dispatch_run_fatal(काष्ठा ssh *ssh, पूर्णांक mode, अस्थिर संक_पूर्ण_प्रकार *done)
{
	पूर्णांक r;

	अगर ((r = ssh_dispatch_run(ssh, mode, done)) != 0)
		sshpkt_fatal(ssh, r, "%s", __func__);
}
