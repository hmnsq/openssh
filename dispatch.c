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

#شامل "includes.h"

#شامل <sys/types.h>

#شامل <signal.h>
#شامل <stdarg.h>

#شامل "ssh2.h"
#شامل "log.h"
#شامل "dispatch.h"
#شامل "packet.h"
#شامل "ssherr.h"

صحیح
dispatch_protocol_error(صحیح type, uint32_t seq, ساختار ssh *ssh)
{
	صحیح r;

	logit_f("type %d seq %u", type, seq);
	اگر ((r = sshpkt_start(ssh, SSH2_پیام_UNIMPLEMENTED)) != 0 ||
	    (r = sshpkt_put_u32(ssh, seq)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s", __func__);
	بازگشت 0;
}

صحیح
dispatch_protocol_ignore(صحیح type, uint32_t seq, ساختار ssh *ssh)
{
	logit_f("type %d seq %u", type, seq);
	بازگشت 0;
}

تهی
ssh_dispatch_init(ساختار ssh *ssh, dispatch_fn *dflt)
{
	u_int i;
	برای (i = 0; i < DISPATCH_MAX; i++)
		ssh->dispatch[i] = dflt;
}

تهی
ssh_dispatch_range(ساختار ssh *ssh, u_int from, u_int to, dispatch_fn *fn)
{
	u_int i;

	برای (i = from; i <= to; i++) {
		اگر (i >= DISPATCH_MAX)
			بشکن;
		ssh->dispatch[i] = fn;
	}
}

تهی
ssh_dispatch_set(ساختار ssh *ssh, صحیح type, dispatch_fn *fn)
{
	ssh->dispatch[type] = fn;
}

صحیح
ssh_dispatch_run(ساختار ssh *ssh, صحیح mode, فرار sig_atomic_t *done)
{
	صحیح r;
	u_char type;
	uint32_t seqnr;

	برای (;;) {
		اگر (mode == DISPATCH_BLOCK) {
			r = ssh_packet_read_seqnr(ssh, &type, &seqnr);
			اگر (r != 0)
				بازگشت r;
		} وگرنه {
			r = ssh_packet_read_poll_seqnr(ssh, &type, &seqnr);
			اگر (r != 0)
				بازگشت r;
			اگر (type == SSH_پیام_NONE)
				بازگشت 0;
		}
		اگر (type > 0 && type < DISPATCH_MAX &&
		    ssh->dispatch[type] != پوچ) {
			اگر (ssh->dispatch_skip_packets) {
				debug2("skipped packet (type %u)", type);
				ssh->dispatch_skip_packets--;
				ادامه;
			}
			r = (*ssh->dispatch[type])(type, seqnr, ssh);
			اگر (r != 0)
				بازگشت r;
		} وگرنه {
			r = sshpkt_disconnect(ssh,
			    "protocol error: rcvd type %d", type);
			اگر (r != 0)
				بازگشت r;
			بازگشت SSH_ERR_DISCONNECTED;
		}
		اگر (done != پوچ && *done)
			بازگشت 0;
	}
}

تهی
ssh_dispatch_run_fatal(ساختار ssh *ssh, صحیح mode, فرار sig_atomic_t *done)
{
	صحیح r;

	اگر ((r = ssh_dispatch_run(ssh, mode, done)) != 0)
		sshpkt_fatal(ssh, r, "%s", __func__);
}
