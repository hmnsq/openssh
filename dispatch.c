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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>

#அந்தர்பாவ <signal.h>
#அந்தர்பாவ <stdarg.h>

#அந்தர்பாவ "ssh2.h"
#அந்தர்பாவ "log.h"
#அந்தர்பாவ "dispatch.h"
#அந்தர்பாவ "packet.h"
#அந்தர்பாவ "ssherr.h"

முழு
dispatch_protocol_error(முழு type, uint32_t seq, கட்டமைப்பு ssh *ssh)
{
	முழு r;

	logit_f("type %d seq %u", type, seq);
	எனில் ((r = sshpkt_start(ssh, SSH2_செய்தி_UNIMPLEMENTED)) != 0 ||
	    (r = sshpkt_put_u32(ssh, seq)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s", __func__);
	திரும்பு 0;
}

முழு
dispatch_protocol_ignore(முழு type, uint32_t seq, கட்டமைப்பு ssh *ssh)
{
	logit_f("type %d seq %u", type, seq);
	திரும்பு 0;
}

வெறுமை
ssh_dispatch_init(கட்டமைப்பு ssh *ssh, dispatch_fn *dflt)
{
	u_int i;
	க்கு (i = 0; i < DISPATCH_MAX; i++)
		ssh->dispatch[i] = dflt;
}

வெறுமை
ssh_dispatch_range(கட்டமைப்பு ssh *ssh, u_int from, u_int to, dispatch_fn *fn)
{
	u_int i;

	க்கு (i = from; i <= to; i++) {
		எனில் (i >= DISPATCH_MAX)
			நிறுத்து;
		ssh->dispatch[i] = fn;
	}
}

வெறுமை
ssh_dispatch_set(கட்டமைப்பு ssh *ssh, முழு type, dispatch_fn *fn)
{
	ssh->dispatch[type] = fn;
}

முழு
ssh_dispatch_run(கட்டமைப்பு ssh *ssh, முழு mode, நிலையற்ற sig_atomic_t *done)
{
	முழு r;
	u_char type;
	uint32_t seqnr;

	க்கு (;;) {
		எனில் (mode == DISPATCH_BLOCK) {
			r = ssh_packet_read_seqnr(ssh, &type, &seqnr);
			எனில் (r != 0)
				திரும்பு r;
		} இல்லையெனில் {
			r = ssh_packet_read_poll_seqnr(ssh, &type, &seqnr);
			எனில் (r != 0)
				திரும்பு r;
			எனில் (type == SSH_செய்தி_NONE)
				திரும்பு 0;
		}
		எனில் (type > 0 && type < DISPATCH_MAX &&
		    ssh->dispatch[type] != வெற்று) {
			எனில் (ssh->dispatch_skip_packets) {
				debug2("skipped packet (type %u)", type);
				ssh->dispatch_skip_packets--;
				தொடர்;
			}
			r = (*ssh->dispatch[type])(type, seqnr, ssh);
			எனில் (r != 0)
				திரும்பு r;
		} இல்லையெனில் {
			r = sshpkt_disconnect(ssh,
			    "protocol error: rcvd type %d", type);
			எனில் (r != 0)
				திரும்பு r;
			திரும்பு SSH_ERR_DISCONNECTED;
		}
		எனில் (done != வெற்று && *done)
			திரும்பு 0;
	}
}

வெறுமை
ssh_dispatch_run_fatal(கட்டமைப்பு ssh *ssh, முழு mode, நிலையற்ற sig_atomic_t *done)
{
	முழு r;

	எனில் ((r = ssh_dispatch_run(ssh, mode, done)) != 0)
		sshpkt_fatal(ssh, r, "%s", __func__);
}
