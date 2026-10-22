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

整数
dispatch_protocol_error(整数 type, uint32_t seq, struct ssh *ssh)
{
	整数 r;

	logit_f("type %d seq %u", type, seq);
	如果 ((r = sshpkt_start(ssh, SSH2_MSG_UNIMPLEMENTED)) != 0 ||
	    (r = sshpkt_put_u32(ssh, seq)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s", __func__);
	返回 0;
}

整数
dispatch_protocol_ignore(整数 type, uint32_t seq, struct ssh *ssh)
{
	logit_f("type %d seq %u", type, seq);
	返回 0;
}

void
ssh_dispatch_init(struct ssh *ssh, dispatch_fn *dflt)
{
	u_int i;
	为 (i = 0; i < DISPATCH_MAX; i++)
		ssh->dispatch[i] = dflt;
}

void
ssh_dispatch_range(struct ssh *ssh, u_int from, u_int to, dispatch_fn *fn)
{
	u_int i;

	为 (i = from; i <= to; i++) {
		如果 (i >= DISPATCH_MAX)
			break;
		ssh->dispatch[i] = fn;
	}
}

void
ssh_dispatch_set(struct ssh *ssh, 整数 type, dispatch_fn *fn)
{
	ssh->dispatch[type] = fn;
}

整数
ssh_dispatch_run(struct ssh *ssh, 整数 mode, volatile sig_atomic_t *done)
{
	整数 r;
	u_char type;
	uint32_t seqnr;

	为 (;;) {
		如果 (mode == DISPATCH_BLOCK) {
			r = ssh_packet_read_seqnr(ssh, &type, &seqnr);
			如果 (r != 0)
				返回 r;
		} 否则 {
			r = ssh_packet_read_poll_seqnr(ssh, &type, &seqnr);
			如果 (r != 0)
				返回 r;
			如果 (type == SSH_MSG_NONE)
				返回 0;
		}
		如果 (type > 0 && type < DISPATCH_MAX &&
		    ssh->dispatch[type] != NULL) {
			如果 (ssh->dispatch_skip_packets) {
				debug2("skipped packet (type %u)", type);
				ssh->dispatch_skip_packets--;
				continue;
			}
			r = (*ssh->dispatch[type])(type, seqnr, ssh);
			如果 (r != 0)
				返回 r;
		} 否则 {
			r = sshpkt_disconnect(ssh,
			    "protocol error: rcvd type %d", type);
			如果 (r != 0)
				返回 r;
			返回 SSH_ERR_DISCONNECTED;
		}
		如果 (done != NULL && *done)
			返回 0;
	}
}

void
ssh_dispatch_run_fatal(struct ssh *ssh, 整数 mode, volatile sig_atomic_t *done)
{
	整数 r;

	如果 ((r = ssh_dispatch_run(ssh, mode, done)) != 0)
		sshpkt_fatal(ssh, r, "%s", __func__);
}
