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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>

#ಅನ್ತರ್ಭಾವ <signal.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>

#ಅನ್ತರ್ಭಾವ "ssh2.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "dispatch.h"
#ಅನ್ತರ್ಭಾವ "packet.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"

ಪೂರ್ಣಾಙ್ಕ
dispatch_protocol_error(ಪೂರ್ಣಾಙ್ಕ type, uint32_t seq, ಸಂರಚನಾ ssh *ssh)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	logit_f("type %d seq %u", type, seq);
	ಯದಿ ((r = sshpkt_start(ssh, SSH2_ಸಂದೇಶ_UNIMPLEMENTED)) != 0 ||
	    (r = sshpkt_put_u32(ssh, seq)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s", __func__);
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
dispatch_protocol_ignore(ಪೂರ್ಣಾಙ್ಕ type, uint32_t seq, ಸಂರಚನಾ ssh *ssh)
{
	logit_f("type %d seq %u", type, seq);
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಶೂನ್ಯ
ssh_dispatch_init(ಸಂರಚನಾ ssh *ssh, dispatch_fn *dflt)
{
	u_int i;
	ಪ್ರತಿ (i = 0; i < DISPATCH_MAX; i++)
		ssh->dispatch[i] = dflt;
}

ಶೂನ್ಯ
ssh_dispatch_range(ಸಂರಚನಾ ssh *ssh, u_int from, u_int to, dispatch_fn *fn)
{
	u_int i;

	ಪ್ರತಿ (i = from; i <= to; i++) {
		ಯದಿ (i >= DISPATCH_MAX)
			ಭಙ್ಗ;
		ssh->dispatch[i] = fn;
	}
}

ಶೂನ್ಯ
ssh_dispatch_set(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ type, dispatch_fn *fn)
{
	ssh->dispatch[type] = fn;
}

ಪೂರ್ಣಾಙ್ಕ
ssh_dispatch_run(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ mode, ಚಞ್ಚಲ sig_atomic_t *done)
{
	ಪೂರ್ಣಾಙ್ಕ r;
	u_char type;
	uint32_t seqnr;

	ಪ್ರತಿ (;;) {
		ಯದಿ (mode == DISPATCH_BLOCK) {
			r = ssh_packet_read_seqnr(ssh, &type, &seqnr);
			ಯದಿ (r != 0)
				ಪ್ರತ್ಯಾಗಮ r;
		} ಅನ್ಯಥಾ {
			r = ssh_packet_read_poll_seqnr(ssh, &type, &seqnr);
			ಯದಿ (r != 0)
				ಪ್ರತ್ಯಾಗಮ r;
			ಯದಿ (type == SSH_ಸಂದೇಶ_NONE)
				ಪ್ರತ್ಯಾಗಮ 0;
		}
		ಯದಿ (type > 0 && type < DISPATCH_MAX &&
		    ssh->dispatch[type] != ರಿಕ್ತ) {
			ಯದಿ (ssh->dispatch_skip_packets) {
				debug2("skipped packet (type %u)", type);
				ssh->dispatch_skip_packets--;
				ಅನುವರ್ತ;
			}
			r = (*ssh->dispatch[type])(type, seqnr, ssh);
			ಯದಿ (r != 0)
				ಪ್ರತ್ಯಾಗಮ r;
		} ಅನ್ಯಥಾ {
			r = sshpkt_disconnect(ssh,
			    "protocol error: rcvd type %d", type);
			ಯದಿ (r != 0)
				ಪ್ರತ್ಯಾಗಮ r;
			ಪ್ರತ್ಯಾಗಮ SSH_ERR_DISCONNECTED;
		}
		ಯದಿ (done != ರಿಕ್ತ && *done)
			ಪ್ರತ್ಯಾಗಮ 0;
	}
}

ಶೂನ್ಯ
ssh_dispatch_run_fatal(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ mode, ಚಞ್ಚಲ sig_atomic_t *done)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = ssh_dispatch_run(ssh, mode, done)) != 0)
		sshpkt_fatal(ssh, r, "%s", __func__);
}
