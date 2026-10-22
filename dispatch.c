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

#include "includes.h"

#include <sys/types.h>

#include <signal.h>
#include <stdarg.h>

#include "ssh2.h"
#include "log.h"
#include "dispatch.h"
#include "packet.h"
#include "ssherr.h"

puur_naa_nka
dispatch_protocol_error(puur_naa_nka type, uint32_t seq, sa_nracanaa ssh *ssh)
{
	puur_naa_nka r;

	logit_f("type %d seq %u", type, seq);
	ᬬᬾᬦ᭄ ((r = sshpkt_start(ssh, SSH2_MSG_UNIMPLEMENTED)) != 0 ||
	    (r = sshpkt_put_u32(ssh, seq)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s", __func__);
	ᬯᬮᬶ 0;
}

puur_naa_nka
dispatch_protocol_ignore(puur_naa_nka type, uint32_t seq, sa_nracanaa ssh *ssh)
{
	logit_f("type %d seq %u", type, seq);
	ᬯᬮᬶ 0;
}

void
ssh_dispatch_init(sa_nracanaa ssh *ssh, dispatch_fn *dflt)
{
	u_int i;
	for (i = 0; i < DISPATCH_MAX; i++)
		ssh->dispatch[i] = dflt;
}

void
ssh_dispatch_range(sa_nracanaa ssh *ssh, u_int from, u_int to, dispatch_fn *fn)
{
	u_int i;

	for (i = from; i <= to; i++) {
		ᬬᬾᬦ᭄ (i >= DISPATCH_MAX)
			bha_nga;
		ssh->dispatch[i] = fn;
	}
}

void
ssh_dispatch_set(sa_nracanaa ssh *ssh, puur_naa_nka type, dispatch_fn *fn)
{
	ssh->dispatch[type] = fn;
}

puur_naa_nka
ssh_dispatch_run(sa_nracanaa ssh *ssh, puur_naa_nka mode, ca_ncala sig_atomic_t *done)
{
	puur_naa_nka r;
	u_char type;
	uint32_t seqnr;

	for (;;) {
		ᬬᬾᬦ᭄ (mode == DISPATCH_BLOCK) {
			r = ssh_packet_read_seqnr(ssh, &type, &seqnr);
			ᬬᬾᬦ᭄ (r != 0)
				ᬯᬮᬶ r;
		} ᬮᬶᬬ {
			r = ssh_packet_read_poll_seqnr(ssh, &type, &seqnr);
			ᬬᬾᬦ᭄ (r != 0)
				ᬯᬮᬶ r;
			ᬬᬾᬦ᭄ (type == SSH_MSG_NONE)
				ᬯᬮᬶ 0;
		}
		ᬬᬾᬦ᭄ (type > 0 && type < DISPATCH_MAX &&
		    ssh->dispatch[type] != NULL) {
			ᬬᬾᬦ᭄ (ssh->dispatch_skip_packets) {
				debug2("skipped packet (type %u)", type);
				ssh->dispatch_skip_packets--;
				continue;
			}
			r = (*ssh->dispatch[type])(type, seqnr, ssh);
			ᬬᬾᬦ᭄ (r != 0)
				ᬯᬮᬶ r;
		} ᬮᬶᬬ {
			r = sshpkt_disconnect(ssh,
			    "protocol error: rcvd type %d", type);
			ᬬᬾᬦ᭄ (r != 0)
				ᬯᬮᬶ r;
			ᬯᬮᬶ SSH_ERR_DISCONNECTED;
		}
		ᬬᬾᬦ᭄ (done != NULL && *done)
			ᬯᬮᬶ 0;
	}
}

void
ssh_dispatch_run_fatal(sa_nracanaa ssh *ssh, puur_naa_nka mode, ca_ncala sig_atomic_t *done)
{
	puur_naa_nka r;

	ᬬᬾᬦ᭄ ((r = ssh_dispatch_run(ssh, mode, done)) != 0)
		sshpkt_fatal(ssh, r, "%s", __func__);
}
