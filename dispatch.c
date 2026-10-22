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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>

#അന്തര്ഭാവ <signal.h>
#അന്തര്ഭാവ <stdarg.h>

#അന്തര്ഭാവ "ssh2.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "dispatch.h"
#അന്തര്ഭാവ "packet.h"
#അന്തര്ഭാവ "ssherr.h"

പൂർണ്ണസംഖ്യ
dispatch_protocol_error(പൂർണ്ണസംഖ്യ type, uint32_t seq, ഘടന ssh *ssh)
{
	പൂർണ്ണസംഖ്യ r;

	logit_f("type %d seq %u", type, seq);
	എങ്കിൽ ((r = sshpkt_start(ssh, SSH2_സന്ദേശം_UNIMPLEMENTED)) != 0 ||
	    (r = sshpkt_put_u32(ssh, seq)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s", __func__);
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
dispatch_protocol_ignore(പൂർണ്ണസംഖ്യ type, uint32_t seq, ഘടന ssh *ssh)
{
	logit_f("type %d seq %u", type, seq);
	തിരികെ 0;
}

ശൂന്യം
ssh_dispatch_init(ഘടന ssh *ssh, dispatch_fn *dflt)
{
	u_int i;
	വേണ്ടി (i = 0; i < DISPATCH_MAX; i++)
		ssh->dispatch[i] = dflt;
}

ശൂന്യം
ssh_dispatch_range(ഘടന ssh *ssh, u_int from, u_int to, dispatch_fn *fn)
{
	u_int i;

	വേണ്ടി (i = from; i <= to; i++) {
		എങ്കിൽ (i >= DISPATCH_MAX)
			നിർത്തുക;
		ssh->dispatch[i] = fn;
	}
}

ശൂന്യം
ssh_dispatch_set(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ type, dispatch_fn *fn)
{
	ssh->dispatch[type] = fn;
}

പൂർണ്ണസംഖ്യ
ssh_dispatch_run(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ mode, അസ്ഥിര sig_atomic_t *done)
{
	പൂർണ്ണസംഖ്യ r;
	u_char type;
	uint32_t seqnr;

	വേണ്ടി (;;) {
		എങ്കിൽ (mode == DISPATCH_BLOCK) {
			r = ssh_packet_read_seqnr(ssh, &type, &seqnr);
			എങ്കിൽ (r != 0)
				തിരികെ r;
		} അല്ലെങ്കിൽ {
			r = ssh_packet_read_poll_seqnr(ssh, &type, &seqnr);
			എങ്കിൽ (r != 0)
				തിരികെ r;
			എങ്കിൽ (type == SSH_സന്ദേശം_NONE)
				തിരികെ 0;
		}
		എങ്കിൽ (type > 0 && type < DISPATCH_MAX &&
		    ssh->dispatch[type] != ശൂന്യ) {
			എങ്കിൽ (ssh->dispatch_skip_packets) {
				debug2("skipped packet (type %u)", type);
				ssh->dispatch_skip_packets--;
				തുടരുക;
			}
			r = (*ssh->dispatch[type])(type, seqnr, ssh);
			എങ്കിൽ (r != 0)
				തിരികെ r;
		} അല്ലെങ്കിൽ {
			r = sshpkt_disconnect(ssh,
			    "protocol error: rcvd type %d", type);
			എങ്കിൽ (r != 0)
				തിരികെ r;
			തിരികെ SSH_ERR_DISCONNECTED;
		}
		എങ്കിൽ (done != ശൂന്യ && *done)
			തിരികെ 0;
	}
}

ശൂന്യം
ssh_dispatch_run_fatal(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ mode, അസ്ഥിര sig_atomic_t *done)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = ssh_dispatch_run(ssh, mode, done)) != 0)
		sshpkt_fatal(ssh, r, "%s", __func__);
}
