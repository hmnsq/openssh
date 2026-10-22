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

ಪೂರ್ಣಾಂಕ
dispatch_protocol_error(ಪೂರ್ಣಾಂಕ type, uint32_t seq, ರಚನೆ ssh *ssh)
{
	ಪೂರ್ಣಾಂಕ r;

	logit_f("type %d seq %u", type, seq);
	ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh, SSH2_ಸಂದೇಶ_UNIMPLEMENTED)) != 0 ||
	    (r = sshpkt_put_u32(ssh, seq)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s", __func__);
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
dispatch_protocol_ignore(ಪೂರ್ಣಾಂಕ type, uint32_t seq, ರಚನೆ ssh *ssh)
{
	logit_f("type %d seq %u", type, seq);
	ಹಿಂತಿರುಗಿ 0;
}

ಶೂನ್ಯ
ssh_dispatch_init(ರಚನೆ ssh *ssh, dispatch_fn *dflt)
{
	u_int i;
	ಗಾಗಿ (i = 0; i < DISPATCH_MAX; i++)
		ssh->dispatch[i] = dflt;
}

ಶೂನ್ಯ
ssh_dispatch_range(ರಚನೆ ssh *ssh, u_int from, u_int ಗಮ್ಯ, dispatch_fn *fn)
{
	u_int i;

	ಗಾಗಿ (i = from; i <= ಗಮ್ಯ; i++) {
		ಆದರೆ (i >= DISPATCH_MAX)
			ನಿಲ್ಲಿಸು;
		ssh->dispatch[i] = fn;
	}
}

ಶೂನ್ಯ
ssh_dispatch_ಗಣ(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ type, dispatch_fn *fn)
{
	ssh->dispatch[type] = fn;
}

ಪೂರ್ಣಾಂಕ
ssh_dispatch_ಸತತ(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ ಬಹುಲಕ, ಅಸ್ಥಿರ sig_atomic_t *ಮುಗಿದ)
{
	ಪೂರ್ಣಾಂಕ r;
	u_char type;
	uint32_t seqnr;

	ಗಾಗಿ (;;) {
		ಆದರೆ (ಬಹುಲಕ == DISPATCH_ಖಂಡ) {
			r = ssh_packet_read_seqnr(ssh, &type, &seqnr);
			ಆದರೆ (r != 0)
				ಹಿಂತಿರುಗಿ r;
		} ಇಲ್ಲದಿದ್ದರೆ {
			r = ssh_packet_read_poll_seqnr(ssh, &type, &seqnr);
			ಆದರೆ (r != 0)
				ಹಿಂತಿರುಗಿ r;
			ಆದರೆ (type == SSH_ಸಂದೇಶ_NONE)
				ಹಿಂತಿರುಗಿ 0;
		}
		ಆದರೆ (type > 0 && type < DISPATCH_MAX &&
		    ssh->dispatch[type] != ಖಾಲಿ) {
			ಆದರೆ (ssh->dispatch_skip_packets) {
				debug2("skipped packet (type %u)", type);
				ssh->dispatch_skip_packets--;
				ಮುಂದುವರಿ;
			}
			r = (*ssh->dispatch[type])(type, seqnr, ssh);
			ಆದರೆ (r != 0)
				ಹಿಂತಿರುಗಿ r;
		} ಇಲ್ಲದಿದ್ದರೆ {
			r = sshpkt_disconnect(ssh,
			    "protocol error: rcvd type %d", type);
			ಆದರೆ (r != 0)
				ಹಿಂತಿರುಗಿ r;
			ಹಿಂತಿರುಗಿ SSH_ERR_DISCONNECTED;
		}
		ಆದರೆ (ಮುಗಿದ != ಖಾಲಿ && *ಮುಗಿದ)
			ಹಿಂತಿರುಗಿ 0;
	}
}

ಶೂನ್ಯ
ssh_dispatch_ಸತತ_fatal(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ ಬಹುಲಕ, ಅಸ್ಥಿರ sig_atomic_t *ಮುಗಿದ)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = ssh_dispatch_ಸತತ(ssh, ಬಹುಲಕ, ಮುಗಿದ)) != 0)
		sshpkt_fatal(ssh, r, "%s", __func__);
}
