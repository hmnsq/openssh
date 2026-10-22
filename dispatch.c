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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>

#ଅନ୍ତର୍ଭାଵ <signal.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>

#ଅନ୍ତର୍ଭାଵ "ssh2.h"
#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "dispatch.h"
#ଅନ୍ତର୍ଭାଵ "packet.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
dispatch_protocol_error(ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, uint32_t seq, ସଂରଚନା ssh *ssh)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	logit_f("type %d seq %u", type, seq);
	ଯଦି ((r = sshpkt_start(ssh, SSH2_ସନ୍ଦେଶ_UNIMPLEMENTED)) != 0 ||
	    (r = sshpkt_put_u32(ssh, seq)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s", __func__);
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
dispatch_protocol_ignore(ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, uint32_t seq, ସଂରଚନା ssh *ssh)
{
	logit_f("type %d seq %u", type, seq);
	ଫେରନ୍ତୁ 0;
}

ଶୂନ୍ୟ
ssh_dispatch_init(ସଂରଚନା ssh *ssh, dispatch_fn *dflt)
{
	u_int i;
	ପାଇଁ (i = 0; i < DISPATCH_MAX; i++)
		ssh->dispatch[i] = dflt;
}

ଶୂନ୍ୟ
ssh_dispatch_range(ସଂରଚନା ssh *ssh, u_int from, u_int to, dispatch_fn *fn)
{
	u_int i;

	ପାଇଁ (i = from; i <= to; i++) {
		ଯଦି (i >= DISPATCH_MAX)
			ଭାଙ୍ଗ;
		ssh->dispatch[i] = fn;
	}
}

ଶୂନ୍ୟ
ssh_dispatch_set(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, dispatch_fn *fn)
{
	ssh->dispatch[type] = fn;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_dispatch_run(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା mode, ଅସ୍ଥିର sig_atomic_t *done)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	u_char type;
	uint32_t seqnr;

	ପାଇଁ (;;) {
		ଯଦି (mode == DISPATCH_BLOCK) {
			r = ssh_packet_read_seqnr(ssh, &type, &seqnr);
			ଯଦି (r != 0)
				ଫେରନ୍ତୁ r;
		} ଅନ୍ୟଥା {
			r = ssh_packet_read_poll_seqnr(ssh, &type, &seqnr);
			ଯଦି (r != 0)
				ଫେରନ୍ତୁ r;
			ଯଦି (type == SSH_ସନ୍ଦେଶ_NONE)
				ଫେରନ୍ତୁ 0;
		}
		ଯଦି (type > 0 && type < DISPATCH_MAX &&
		    ssh->dispatch[type] != ଖାଲି) {
			ଯଦି (ssh->dispatch_skip_packets) {
				debug2("skipped packet (type %u)", type);
				ssh->dispatch_skip_packets--;
				ଜାରି;
			}
			r = (*ssh->dispatch[type])(type, seqnr, ssh);
			ଯଦି (r != 0)
				ଫେରନ୍ତୁ r;
		} ଅନ୍ୟଥା {
			r = sshpkt_disconnect(ssh,
			    "protocol error: rcvd type %d", type);
			ଯଦି (r != 0)
				ଫେରନ୍ତୁ r;
			ଫେରନ୍ତୁ SSH_ERR_DISCONNECTED;
		}
		ଯଦି (done != ଖାଲି && *done)
			ଫେରନ୍ତୁ 0;
	}
}

ଶୂନ୍ୟ
ssh_dispatch_run_fatal(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା mode, ଅସ୍ଥିର sig_atomic_t *done)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = ssh_dispatch_run(ssh, mode, done)) != 0)
		sshpkt_fatal(ssh, r, "%s", __func__);
}
