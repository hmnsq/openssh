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

ཧྲིལ
dispatch_protocol_error(ཧྲིལ type, uint32_t seq, sa_nracanaa ssh *ssh)
{
	ཧྲིལ r;

	logit_f("type %d seq %u", type, seq);
	གལ་སྲིད ((r = sshpkt_start(ssh, SSH2_MSG_UNIMPLEMENTED)) != 0 ||
	    (r = sshpkt_put_u32(ssh, seq)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s", __func__);
	ལོག 0;
}

ཧྲིལ
dispatch_protocol_ignore(ཧྲིལ type, uint32_t seq, sa_nracanaa ssh *ssh)
{
	logit_f("type %d seq %u", type, seq);
	ལོག 0;
}

void
ssh_dispatch_init(sa_nracanaa ssh *ssh, dispatch_fn *dflt)
{
	u_int i;
	དོན་ལུ (i = 0; i < DISPATCH_MAX; i++)
		ssh->dispatch[i] = dflt;
}

void
ssh_dispatch_range(sa_nracanaa ssh *ssh, u_int from, u_int to, dispatch_fn *fn)
{
	u_int i;

	དོན་ལུ (i = from; i <= to; i++) {
		གལ་སྲིད (i >= DISPATCH_MAX)
			bha_nga;
		ssh->dispatch[i] = fn;
	}
}

void
ssh_dispatch_set(sa_nracanaa ssh *ssh, ཧྲིལ type, dispatch_fn *fn)
{
	ssh->dispatch[type] = fn;
}

ཧྲིལ
ssh_dispatch_run(sa_nracanaa ssh *ssh, ཧྲིལ mode, ca_ncala sig_atomic_t *done)
{
	ཧྲིལ r;
	u_char type;
	uint32_t seqnr;

	དོན་ལུ (;;) {
		གལ་སྲིད (mode == DISPATCH_BLOCK) {
			r = ssh_packet_read_seqnr(ssh, &type, &seqnr);
			གལ་སྲིད (r != 0)
				ལོག r;
		} དེ་མིན {
			r = ssh_packet_read_poll_seqnr(ssh, &type, &seqnr);
			གལ་སྲིད (r != 0)
				ལོག r;
			གལ་སྲིད (type == SSH_MSG_NONE)
				ལོག 0;
		}
		གལ་སྲིད (type > 0 && type < DISPATCH_MAX &&
		    ssh->dispatch[type] != NULL) {
			གལ་སྲིད (ssh->dispatch_skip_packets) {
				debug2("skipped packet (type %u)", type);
				ssh->dispatch_skip_packets--;
				continue;
			}
			r = (*ssh->dispatch[type])(type, seqnr, ssh);
			གལ་སྲིད (r != 0)
				ལོག r;
		} དེ་མིན {
			r = sshpkt_disconnect(ssh,
			    "protocol error: rcvd type %d", type);
			གལ་སྲིད (r != 0)
				ལོག r;
			ལོག SSH_ERR_DISCONNECTED;
		}
		གལ་སྲིད (done != NULL && *done)
			ལོག 0;
	}
}

void
ssh_dispatch_run_fatal(sa_nracanaa ssh *ssh, ཧྲིལ mode, ca_ncala sig_atomic_t *done)
{
	ཧྲིལ r;

	གལ་སྲིད ((r = ssh_dispatch_run(ssh, mode, done)) != 0)
		sshpkt_fatal(ssh, r, "%s", __func__);
}
