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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>

#अन्तर्भाव <signal.h>
#अन्तर्भाव <stdarg.h>

#अन्तर्भाव "ssh2.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "dispatch.h"
#अन्तर्भाव "packet.h"
#अन्तर्भाव "ssherr.h"

पूर्णाङ्क
dispatch_protocol_error(पूर्णाङ्क type, uint32_t seq, संरचना ssh *ssh)
{
	पूर्णाङ्क r;

	logit_f("type %d seq %u", type, seq);
	यदि ((r = sshpkt_start(ssh, SSH2_संदेश_UNIMPLEMENTED)) != 0 ||
	    (r = sshpkt_put_u32(ssh, seq)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s", __func__);
	प्रत्यागम 0;
}

पूर्णाङ्क
dispatch_protocol_ignore(पूर्णाङ्क type, uint32_t seq, संरचना ssh *ssh)
{
	logit_f("type %d seq %u", type, seq);
	प्रत्यागम 0;
}

शून्य
ssh_dispatch_init(संरचना ssh *ssh, dispatch_fn *dflt)
{
	u_int i;
	प्रति (i = 0; i < DISPATCH_MAX; i++)
		ssh->dispatch[i] = dflt;
}

शून्य
ssh_dispatch_range(संरचना ssh *ssh, u_int from, u_int to, dispatch_fn *fn)
{
	u_int i;

	प्रति (i = from; i <= to; i++) {
		यदि (i >= DISPATCH_MAX)
			भङ्ग;
		ssh->dispatch[i] = fn;
	}
}

शून्य
ssh_dispatch_set(संरचना ssh *ssh, पूर्णाङ्क type, dispatch_fn *fn)
{
	ssh->dispatch[type] = fn;
}

पूर्णाङ्क
ssh_dispatch_run(संरचना ssh *ssh, पूर्णाङ्क mode, चञ्चल संक_पूर्ण_प्रकार *done)
{
	पूर्णाङ्क r;
	u_char type;
	uint32_t seqnr;

	प्रति (;;) {
		यदि (mode == DISPATCH_BLOCK) {
			r = ssh_packet_read_seqnr(ssh, &type, &seqnr);
			यदि (r != 0)
				प्रत्यागम r;
		} अन्यथा {
			r = ssh_packet_read_poll_seqnr(ssh, &type, &seqnr);
			यदि (r != 0)
				प्रत्यागम r;
			यदि (type == SSH_संदेश_NONE)
				प्रत्यागम 0;
		}
		यदि (type > 0 && type < DISPATCH_MAX &&
		    ssh->dispatch[type] != रिक्त) {
			यदि (ssh->dispatch_skip_packets) {
				debug2("skipped packet (type %u)", type);
				ssh->dispatch_skip_packets--;
				अनुवर्त;
			}
			r = (*ssh->dispatch[type])(type, seqnr, ssh);
			यदि (r != 0)
				प्रत्यागम r;
		} अन्यथा {
			r = sshpkt_disconnect(ssh,
			    "protocol error: rcvd type %d", type);
			यदि (r != 0)
				प्रत्यागम r;
			प्रत्यागम SSH_ERR_DISCONNECTED;
		}
		यदि (done != रिक्त && *done)
			प्रत्यागम 0;
	}
}

शून्य
ssh_dispatch_run_fatal(संरचना ssh *ssh, पूर्णाङ्क mode, चञ्चल संक_पूर्ण_प्रकार *done)
{
	पूर्णाङ्क r;

	यदि ((r = ssh_dispatch_run(ssh, mode, done)) != 0)
		sshpkt_fatal(ssh, r, "%s", __func__);
}
