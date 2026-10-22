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

පූර්ණ_සංඛ්‍යා
dispatch_protocol_error(පූර්ණ_සංඛ්‍යා type, uint32_t seq, sa_nracanaa ssh *ssh)
{
	පූර්ණ_සංඛ්‍යා r;

	logit_f("type %d seq %u", type, seq);
	නම් ((r = sshpkt_start(ssh, SSH2_MSG_UNIMPLEMENTED)) != 0 ||
	    (r = sshpkt_put_u32(ssh, seq)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s", __func__);
	ආපසු 0;
}

පූර්ණ_සංඛ්‍යා
dispatch_protocol_ignore(පූර්ණ_සංඛ්‍යා type, uint32_t seq, sa_nracanaa ssh *ssh)
{
	logit_f("type %d seq %u", type, seq);
	ආපසු 0;
}

void
ssh_dispatch_init(sa_nracanaa ssh *ssh, dispatch_fn *dflt)
{
	u_int i;
	සඳහා (i = 0; i < DISPATCH_MAX; i++)
		ssh->dispatch[i] = dflt;
}

void
ssh_dispatch_range(sa_nracanaa ssh *ssh, u_int from, u_int to, dispatch_fn *fn)
{
	u_int i;

	සඳහා (i = from; i <= to; i++) {
		නම් (i >= DISPATCH_MAX)
			bha_nga;
		ssh->dispatch[i] = fn;
	}
}

void
ssh_dispatch_set(sa_nracanaa ssh *ssh, පූර්ණ_සංඛ්‍යා type, dispatch_fn *fn)
{
	ssh->dispatch[type] = fn;
}

පූර්ණ_සංඛ්‍යා
ssh_dispatch_run(sa_nracanaa ssh *ssh, පූර්ණ_සංඛ්‍යා mode, ca_ncala sig_atomic_t *done)
{
	පූර්ණ_සංඛ්‍යා r;
	u_char type;
	uint32_t seqnr;

	සඳහා (;;) {
		නම් (mode == DISPATCH_BLOCK) {
			r = ssh_packet_read_seqnr(ssh, &type, &seqnr);
			නම් (r != 0)
				ආපසු r;
		} නැතහොත් {
			r = ssh_packet_read_poll_seqnr(ssh, &type, &seqnr);
			නම් (r != 0)
				ආපසු r;
			නම් (type == SSH_MSG_NONE)
				ආපසු 0;
		}
		නම් (type > 0 && type < DISPATCH_MAX &&
		    ssh->dispatch[type] != NULL) {
			නම් (ssh->dispatch_skip_packets) {
				debug2("skipped packet (type %u)", type);
				ssh->dispatch_skip_packets--;
				continue;
			}
			r = (*ssh->dispatch[type])(type, seqnr, ssh);
			නම් (r != 0)
				ආපසු r;
		} නැතහොත් {
			r = sshpkt_disconnect(ssh,
			    "protocol error: rcvd type %d", type);
			නම් (r != 0)
				ආපසු r;
			ආපසු SSH_ERR_DISCONNECTED;
		}
		නම් (done != NULL && *done)
			ආපසු 0;
	}
}

void
ssh_dispatch_run_fatal(sa_nracanaa ssh *ssh, පූර්ණ_සංඛ්‍යා mode, ca_ncala sig_atomic_t *done)
{
	පූර්ණ_සංඛ්‍යා r;

	නම් ((r = ssh_dispatch_run(ssh, mode, done)) != 0)
		sshpkt_fatal(ssh, r, "%s", __func__);
}
