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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>

#অন্তর্ভাব <signal.h>
#অন্তর্ভাব <stdarg.h>

#অন্তর্ভাব "ssh2.h"
#অন্তর্ভাব "log.h"
#অন্তর্ভাব "dispatch.h"
#অন্তর্ভাব "packet.h"
#অন্তর্ভাব "ssherr.h"

পূর্ণসংখ্যা
dispatch_protocol_error(পূর্ণসংখ্যা type, uint32_t seq, কাঠামো ssh *ssh)
{
	পূর্ণসংখ্যা r;

	logit_f("type %d seq %u", type, seq);
	যদি ((r = sshpkt_start(ssh, SSH2_বার্তা_UNIMPLEMENTED)) != 0 ||
	    (r = sshpkt_put_u32(ssh, seq)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s", __func__);
	ফেরত 0;
}

পূর্ণসংখ্যা
dispatch_protocol_ignore(পূর্ণসংখ্যা type, uint32_t seq, কাঠামো ssh *ssh)
{
	logit_f("type %d seq %u", type, seq);
	ফেরত 0;
}

শূন্য
ssh_dispatch_init(কাঠামো ssh *ssh, dispatch_fn *dflt)
{
	u_int i;
	জন্য (i = 0; i < DISPATCH_MAX; i++)
		ssh->dispatch[i] = dflt;
}

শূন্য
ssh_dispatch_range(কাঠামো ssh *ssh, u_int from, u_int to, dispatch_fn *fn)
{
	u_int i;

	জন্য (i = from; i <= to; i++) {
		যদি (i >= DISPATCH_MAX)
			বিরতি;
		ssh->dispatch[i] = fn;
	}
}

শূন্য
ssh_dispatch_set(কাঠামো ssh *ssh, পূর্ণসংখ্যা type, dispatch_fn *fn)
{
	ssh->dispatch[type] = fn;
}

পূর্ণসংখ্যা
ssh_dispatch_run(কাঠামো ssh *ssh, পূর্ণসংখ্যা mode, অস্থির sig_atomic_t *done)
{
	পূর্ণসংখ্যা r;
	u_char type;
	uint32_t seqnr;

	জন্য (;;) {
		যদি (mode == DISPATCH_BLOCK) {
			r = ssh_packet_read_seqnr(ssh, &type, &seqnr);
			যদি (r != 0)
				ফেরত r;
		} অন্যথা {
			r = ssh_packet_read_poll_seqnr(ssh, &type, &seqnr);
			যদি (r != 0)
				ফেরত r;
			যদি (type == SSH_বার্তা_NONE)
				ফেরত 0;
		}
		যদি (type > 0 && type < DISPATCH_MAX &&
		    ssh->dispatch[type] != ফাঁকা) {
			যদি (ssh->dispatch_skip_packets) {
				debug2("skipped packet (type %u)", type);
				ssh->dispatch_skip_packets--;
				চালু;
			}
			r = (*ssh->dispatch[type])(type, seqnr, ssh);
			যদি (r != 0)
				ফেরত r;
		} অন্যথা {
			r = sshpkt_disconnect(ssh,
			    "protocol error: rcvd type %d", type);
			যদি (r != 0)
				ফেরত r;
			ফেরত SSH_ERR_DISCONNECTED;
		}
		যদি (done != ফাঁকা && *done)
			ফেরত 0;
	}
}

শূন্য
ssh_dispatch_run_fatal(কাঠামো ssh *ssh, পূর্ণসংখ্যা mode, অস্থির sig_atomic_t *done)
{
	পূর্ণসংখ্যা r;

	যদি ((r = ssh_dispatch_run(ssh, mode, done)) != 0)
		sshpkt_fatal(ssh, r, "%s", __func__);
}
