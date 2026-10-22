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

#شامل "includes.h"

#شامل <sys/types.h>

#شامل <signal.h>
#شامل <stdarg.h>

#شامل "ssh2.h"
#شامل "log.h"
#شامل "dispatch.h"
#شامل "packet.h"
#شامل "ssherr.h"

صحیح
dispatch_protocol_error(صحیح type, uint32_t seq, ساخت ssh *ssh)
{
	صحیح r;

	logit_f("type %d seq %u", type, seq);
	اگر ((r = sshpkt_آغاز(ssh, SSH2_پیغام_UNIMPLEMENTED)) != 0 ||
	    (r = sshpkt_put_u32(ssh, seq)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s", __func__);
	واپس 0;
}

صحیح
dispatch_protocol_ignore(صحیح type, uint32_t seq, ساخت ssh *ssh)
{
	logit_f("type %d seq %u", type, seq);
	واپس 0;
}

خالی
ssh_dispatch_init(ساخت ssh *ssh, dispatch_fn *dflt)
{
	u_int i;
	برائے (i = 0; i < DISPATCH_MAX; i++)
		ssh->dispatch[i] = dflt;
}

خالی
ssh_dispatch_range(ساخت ssh *ssh, u_int from, u_int مقصد, dispatch_fn *fn)
{
	u_int i;

	برائے (i = from; i <= مقصد; i++) {
		اگر (i >= DISPATCH_MAX)
			توڑو;
		ssh->dispatch[i] = fn;
	}
}

خالی
ssh_dispatch_سیٹ(ساخت ssh *ssh, صحیح type, dispatch_fn *fn)
{
	ssh->dispatch[type] = fn;
}

صحیح
ssh_dispatch_تسلسل(ساخت ssh *ssh, صحیح منوال, متلون sig_atomic_t *مکمل)
{
	صحیح r;
	u_char type;
	uint32_t seqnr;

	برائے (;;) {
		اگر (منوال == DISPATCH_بلاک) {
			r = ssh_packet_read_seqnr(ssh, &type, &seqnr);
			اگر (r != 0)
				واپس r;
		} ورنہ {
			r = ssh_packet_read_poll_seqnr(ssh, &type, &seqnr);
			اگر (r != 0)
				واپس r;
			اگر (type == SSH_پیغام_NONE)
				واپس 0;
		}
		اگر (type > 0 && type < DISPATCH_MAX &&
		    ssh->dispatch[type] != تہی) {
			اگر (ssh->dispatch_skip_packets) {
				debug2("skipped packet (type %u)", type);
				ssh->dispatch_skip_packets--;
				جاری;
			}
			r = (*ssh->dispatch[type])(type, seqnr, ssh);
			اگر (r != 0)
				واپس r;
		} ورنہ {
			r = sshpkt_disconnect(ssh,
			    "protocol error: rcvd type %d", type);
			اگر (r != 0)
				واپس r;
			واپس SSH_ERR_DISCONNECTED;
		}
		اگر (مکمل != تہی && *مکمل)
			واپس 0;
	}
}

خالی
ssh_dispatch_تسلسل_fatal(ساخت ssh *ssh, صحیح منوال, متلون sig_atomic_t *مکمل)
{
	صحیح r;

	اگر ((r = ssh_dispatch_تسلسل(ssh, منوال, مکمل)) != 0)
		sshpkt_fatal(ssh, r, "%s", __func__);
}
