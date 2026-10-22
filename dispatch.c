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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <signal.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "ssh2.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "dispatch.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "packet.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"

ਪੂਰਨ
dispatch_protocol_error(ਪੂਰਨ type, uint32_t seq, ਬਣਤਰ ssh *ssh)
{
	ਪੂਰਨ r;

	logit_f("type %d seq %u", type, seq);
	ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh, SSH2_ਸੁਨੇਹਾ_UNIMPLEMENTED)) != 0 ||
	    (r = sshpkt_put_u32(ssh, seq)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s", __func__);
	ਵਾਪਸ 0;
}

ਪੂਰਨ
dispatch_protocol_ignore(ਪੂਰਨ type, uint32_t seq, ਬਣਤਰ ssh *ssh)
{
	logit_f("type %d seq %u", type, seq);
	ਵਾਪਸ 0;
}

ਖਾਲੀ
ssh_dispatch_init(ਬਣਤਰ ssh *ssh, dispatch_fn *dflt)
{
	u_int i;
	ਲਈ (i = 0; i < DISPATCH_MAX; i++)
		ssh->dispatch[i] = dflt;
}

ਖਾਲੀ
ssh_dispatch_range(ਬਣਤਰ ssh *ssh, u_int from, u_int ਮੰਜ਼ਿਲ, dispatch_fn *fn)
{
	u_int i;

	ਲਈ (i = from; i <= ਮੰਜ਼ਿਲ; i++) {
		ਜੇ (i >= DISPATCH_MAX)
			ਰੋਕੋ;
		ssh->dispatch[i] = fn;
	}
}

ਖਾਲੀ
ssh_dispatch_ਸੈੱਟ(ਬਣਤਰ ssh *ssh, ਪੂਰਨ type, dispatch_fn *fn)
{
	ssh->dispatch[type] = fn;
}

ਪੂਰਨ
ssh_dispatch_ਲੜੀਵਾਰ(ਬਣਤਰ ssh *ssh, ਪੂਰਨ ਬਹੁਲਕ, ਅਸਥਿਰ sig_atomic_t *ਪੂਰਾ)
{
	ਪੂਰਨ r;
	u_char type;
	uint32_t seqnr;

	ਲਈ (;;) {
		ਜੇ (ਬਹੁਲਕ == DISPATCH_ਖੰਡ) {
			r = ssh_packet_read_seqnr(ssh, &type, &seqnr);
			ਜੇ (r != 0)
				ਵਾਪਸ r;
		} ਨਹੀਂਤਾਂ {
			r = ssh_packet_read_poll_seqnr(ssh, &type, &seqnr);
			ਜੇ (r != 0)
				ਵਾਪਸ r;
			ਜੇ (type == SSH_ਸੁਨੇਹਾ_NONE)
				ਵਾਪਸ 0;
		}
		ਜੇ (type > 0 && type < DISPATCH_MAX &&
		    ssh->dispatch[type] != ਨਿਰਾ) {
			ਜੇ (ssh->dispatch_skip_packets) {
				debug2("skipped packet (type %u)", type);
				ssh->dispatch_skip_packets--;
				ਜਾਰੀ;
			}
			r = (*ssh->dispatch[type])(type, seqnr, ssh);
			ਜੇ (r != 0)
				ਵਾਪਸ r;
		} ਨਹੀਂਤਾਂ {
			r = sshpkt_disconnect(ssh,
			    "protocol error: rcvd type %d", type);
			ਜੇ (r != 0)
				ਵਾਪਸ r;
			ਵਾਪਸ SSH_ERR_DISCONNECTED;
		}
		ਜੇ (ਪੂਰਾ != ਨਿਰਾ && *ਪੂਰਾ)
			ਵਾਪਸ 0;
	}
}

ਖਾਲੀ
ssh_dispatch_ਲੜੀਵਾਰ_fatal(ਬਣਤਰ ssh *ssh, ਪੂਰਨ ਬਹੁਲਕ, ਅਸਥਿਰ sig_atomic_t *ਪੂਰਾ)
{
	ਪੂਰਨ r;

	ਜੇ ((r = ssh_dispatch_ਲੜੀਵਾਰ(ssh, ਬਹੁਲਕ, ਪੂਰਾ)) != 0)
		sshpkt_fatal(ssh, r, "%s", __func__);
}
