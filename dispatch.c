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

#অন্তর্ভাৱ "includes.h"

#অন্তর্ভাৱ <sys/types.h>

#অন্তর্ভাৱ <signal.h>
#অন্তর্ভাৱ <stdarg.h>

#অন্তর্ভাৱ "ssh2.h"
#অন্তর্ভাৱ "log.h"
#অন্তর্ভাৱ "dispatch.h"
#অন্তর্ভাৱ "packet.h"
#অন্তর্ভাৱ "ssherr.h"

পূর্ণাঙ্ক
dispatch_protocol_error(পূর্ণাঙ্ক type, uint32_t seq, সংরচনা ssh *ssh)
{
	পূর্ণাঙ্ক r;

	logit_f("type %d seq %u", type, seq);
	যদি ((r = sshpkt_start(ssh, SSH2_বাৰ্তা_UNIMPLEMENTED)) != 0 ||
	    (r = sshpkt_put_u32(ssh, seq)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s", __func__);
	ঘূৰাই 0;
}

পূর্ণাঙ্ক
dispatch_protocol_ignore(পূর্ণাঙ্ক type, uint32_t seq, সংরচনা ssh *ssh)
{
	logit_f("type %d seq %u", type, seq);
	ঘূৰাই 0;
}

শূন্য
ssh_dispatch_init(সংরচনা ssh *ssh, dispatch_fn *dflt)
{
	u_int i;
	বাবে (i = 0; i < DISPATCH_MAX; i++)
		ssh->dispatch[i] = dflt;
}

শূন্য
ssh_dispatch_range(সংরচনা ssh *ssh, u_int from, u_int to, dispatch_fn *fn)
{
	u_int i;

	বাবে (i = from; i <= to; i++) {
		যদি (i >= DISPATCH_MAX)
			ভঙ্গ;
		ssh->dispatch[i] = fn;
	}
}

শূন্য
ssh_dispatch_set(সংরচনা ssh *ssh, পূর্ণাঙ্ক type, dispatch_fn *fn)
{
	ssh->dispatch[type] = fn;
}

পূর্ণাঙ্ক
ssh_dispatch_run(সংরচনা ssh *ssh, পূর্ণাঙ্ক mode, চঞ্চল sig_atomic_t *done)
{
	পূর্ণাঙ্ক r;
	u_char type;
	uint32_t seqnr;

	বাবে (;;) {
		যদি (mode == DISPATCH_BLOCK) {
			r = ssh_packet_read_seqnr(ssh, &type, &seqnr);
			যদি (r != 0)
				ঘূৰাই r;
		} অন্যথা {
			r = ssh_packet_read_poll_seqnr(ssh, &type, &seqnr);
			যদি (r != 0)
				ঘূৰাই r;
			যদি (type == SSH_বাৰ্তা_NONE)
				ঘূৰাই 0;
		}
		যদি (type > 0 && type < DISPATCH_MAX &&
		    ssh->dispatch[type] != রিক্ত) {
			যদি (ssh->dispatch_skip_packets) {
				debug2("skipped packet (type %u)", type);
				ssh->dispatch_skip_packets--;
				অনুৱর্ত;
			}
			r = (*ssh->dispatch[type])(type, seqnr, ssh);
			যদি (r != 0)
				ঘূৰাই r;
		} অন্যথা {
			r = sshpkt_disconnect(ssh,
			    "protocol error: rcvd type %d", type);
			যদি (r != 0)
				ঘূৰাই r;
			ঘূৰাই SSH_ERR_DISCONNECTED;
		}
		যদি (done != রিক্ত && *done)
			ঘূৰাই 0;
	}
}

শূন্য
ssh_dispatch_run_fatal(সংরচনা ssh *ssh, পূর্ণাঙ্ক mode, চঞ্চল sig_atomic_t *done)
{
	পূর্ণাঙ্ক r;

	যদি ((r = ssh_dispatch_run(ssh, mode, done)) != 0)
		sshpkt_fatal(ssh, r, "%s", __func__);
}
