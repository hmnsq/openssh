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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>

#అన్తర్భావ <signal.h>
#అన్తర్భావ <stdarg.h>

#అన్తర్భావ "ssh2.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "dispatch.h"
#అన్తర్భావ "packet.h"
#అన్తర్భావ "ssherr.h"

పూర్ణాంకం
dispatch_protocol_error(పూర్ణాంకం type, uint32_t seq, నిర్మాణం ssh *ssh)
{
	పూర్ణాంకం r;

	logit_f("type %d seq %u", type, seq);
	ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh, SSH2_సందేశం_UNIMPLEMENTED)) != 0 ||
	    (r = sshpkt_put_u32(ssh, seq)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s", __func__);
	తిరిగి 0;
}

పూర్ణాంకం
dispatch_protocol_ignore(పూర్ణాంకం type, uint32_t seq, నిర్మాణం ssh *ssh)
{
	logit_f("type %d seq %u", type, seq);
	తిరిగి 0;
}

శూన్య
ssh_dispatch_init(నిర్మాణం ssh *ssh, dispatch_fn *dflt)
{
	u_int i;
	కొరకు (i = 0; i < DISPATCH_MAX; i++)
		ssh->dispatch[i] = dflt;
}

శూన్య
ssh_dispatch_range(నిర్మాణం ssh *ssh, u_int from, u_int గమ్యం, dispatch_fn *fn)
{
	u_int i;

	కొరకు (i = from; i <= గమ్యం; i++) {
		ఒకవేళ (i >= DISPATCH_MAX)
			ఆపు;
		ssh->dispatch[i] = fn;
	}
}

శూన్య
ssh_dispatch_సమితి(నిర్మాణం ssh *ssh, పూర్ణాంకం type, dispatch_fn *fn)
{
	ssh->dispatch[type] = fn;
}

పూర్ణాంకం
ssh_dispatch_నిరంతరం(నిర్మాణం ssh *ssh, పూర్ణాంకం బహుళకం, అస్థిర sig_atomic_t *పూర్తి)
{
	పూర్ణాంకం r;
	u_char type;
	uint32_t seqnr;

	కొరకు (;;) {
		ఒకవేళ (బహుళకం == DISPATCH_ఖండం) {
			r = ssh_packet_read_seqnr(ssh, &type, &seqnr);
			ఒకవేళ (r != 0)
				తిరిగి r;
		} లేకపోతే {
			r = ssh_packet_read_poll_seqnr(ssh, &type, &seqnr);
			ఒకవేళ (r != 0)
				తిరిగి r;
			ఒకవేళ (type == SSH_సందేశం_NONE)
				తిరిగి 0;
		}
		ఒకవేళ (type > 0 && type < DISPATCH_MAX &&
		    ssh->dispatch[type] != ఖాళీ) {
			ఒకవేళ (ssh->dispatch_skip_packets) {
				debug2("skipped packet (type %u)", type);
				ssh->dispatch_skip_packets--;
				కొనసాగు;
			}
			r = (*ssh->dispatch[type])(type, seqnr, ssh);
			ఒకవేళ (r != 0)
				తిరిగి r;
		} లేకపోతే {
			r = sshpkt_disconnect(ssh,
			    "protocol error: rcvd type %d", type);
			ఒకవేళ (r != 0)
				తిరిగి r;
			తిరిగి SSH_ERR_DISCONNECTED;
		}
		ఒకవేళ (పూర్తి != ఖాళీ && *పూర్తి)
			తిరిగి 0;
	}
}

శూన్య
ssh_dispatch_నిరంతరం_fatal(నిర్మాణం ssh *ssh, పూర్ణాంకం బహుళకం, అస్థిర sig_atomic_t *పూర్తి)
{
	పూర్ణాంకం r;

	ఒకవేళ ((r = ssh_dispatch_నిరంతరం(ssh, బహుళకం, పూర్తి)) != 0)
		sshpkt_fatal(ssh, r, "%s", __func__);
}
