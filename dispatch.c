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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>

#અન્તર્ભાવ <signal.h>
#અન્તર્ભાવ <stdarg.h>

#અન્તર્ભાવ "ssh2.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "dispatch.h"
#અન્તર્ભાવ "packet.h"
#અન્તર્ભાવ "ssherr.h"

પૂર્ણાંક
dispatch_protocol_error(પૂર્ણાંક type, uint32_t seq, સંરચના ssh *ssh)
{
	પૂર્ણાંક r;

	logit_f("type %d seq %u", type, seq);
	જો ((r = sshpkt_start(ssh, SSH2_સંદેશ_UNIMPLEMENTED)) != 0 ||
	    (r = sshpkt_put_u32(ssh, seq)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s", __func__);
	પાછા 0;
}

પૂર્ણાંક
dispatch_protocol_ignore(પૂર્ણાંક type, uint32_t seq, સંરચના ssh *ssh)
{
	logit_f("type %d seq %u", type, seq);
	પાછા 0;
}

શૂન્ય
ssh_dispatch_init(સંરચના ssh *ssh, dispatch_fn *dflt)
{
	u_int i;
	માટે (i = 0; i < DISPATCH_MAX; i++)
		ssh->dispatch[i] = dflt;
}

શૂન્ય
ssh_dispatch_range(સંરચના ssh *ssh, u_int from, u_int to, dispatch_fn *fn)
{
	u_int i;

	માટે (i = from; i <= to; i++) {
		જો (i >= DISPATCH_MAX)
			તોડો;
		ssh->dispatch[i] = fn;
	}
}

શૂન્ય
ssh_dispatch_set(સંરચના ssh *ssh, પૂર્ણાંક type, dispatch_fn *fn)
{
	ssh->dispatch[type] = fn;
}

પૂર્ણાંક
ssh_dispatch_run(સંરચના ssh *ssh, પૂર્ણાંક mode, અસ્થિર sig_atomic_t *done)
{
	પૂર્ણાંક r;
	u_char type;
	uint32_t seqnr;

	માટે (;;) {
		જો (mode == DISPATCH_BLOCK) {
			r = ssh_packet_read_seqnr(ssh, &type, &seqnr);
			જો (r != 0)
				પાછા r;
		} નહીંતર {
			r = ssh_packet_read_poll_seqnr(ssh, &type, &seqnr);
			જો (r != 0)
				પાછા r;
			જો (type == SSH_સંદેશ_NONE)
				પાછા 0;
		}
		જો (type > 0 && type < DISPATCH_MAX &&
		    ssh->dispatch[type] != ખાલી) {
			જો (ssh->dispatch_skip_packets) {
				debug2("skipped packet (type %u)", type);
				ssh->dispatch_skip_packets--;
				ચાલુ;
			}
			r = (*ssh->dispatch[type])(type, seqnr, ssh);
			જો (r != 0)
				પાછા r;
		} નહીંતર {
			r = sshpkt_disconnect(ssh,
			    "protocol error: rcvd type %d", type);
			જો (r != 0)
				પાછા r;
			પાછા SSH_ERR_DISCONNECTED;
		}
		જો (done != ખાલી && *done)
			પાછા 0;
	}
}

શૂન્ય
ssh_dispatch_run_fatal(સંરચના ssh *ssh, પૂર્ણાંક mode, અસ્થિર sig_atomic_t *done)
{
	પૂર્ણાંક r;

	જો ((r = ssh_dispatch_run(ssh, mode, done)) != 0)
		sshpkt_fatal(ssh, r, "%s", __func__);
}
