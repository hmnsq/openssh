/* $OpenBSD: nchan.c,v 1.77 2026/02/14 00:18:34 jsg Exp $ */
/*
 * Copyright (c) 1999, 2000, 2001, 2002 Markus Friedl.  All rights reserved.
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
#അന്തര്ഭാവ <sys/socket.h>

#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <stdarg.h>

#അന്തര്ഭാവ "ssh2.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "packet.h"
#അന്തര്ഭാവ "channels.h"
#അന്തര്ഭാവ "compat.h"
#അന്തര്ഭാവ "log.h"

/*
 * SSH Protocol 1.5 aka New Channel Protocol
 * Thanks to Martina, Axel and everyone who left Erlangen, leaving me bored.
 * Written by Markus Friedl in October 1999
 *
 * Protocol versions 1.3 and 1.5 differ in the handshake protocol used for the
 * tear down of channels:
 *
 * 1.3:	strict request-ack-protocol:
 *	CLOSE	->
 *		<-  CLOSE_CONFIRM
 *
 * 1.5:	uses variations of:
 *	IEOF	->
 *		<-  OCLOSE
 *		<-  IEOF
 *	OCLOSE	->
 *	i.e. both sides have to close the channel
 *
 * 2.0: the EOF messages are optional
 *
 * See the debugging output from 'ssh -v' and 'sshd -d' of
 * ssh-1.2.27 as an example.
 *
 */

/* functions manipulating channel states */
/*
 * EVENTS update channel input/output states execute ACTIONS
 */
/*
 * ACTIONS: should never update the channel states
 */
സ്ഥിതം ശൂന്യം	chan_send_eof2(ഘടന ssh *, Channel *);
സ്ഥിതം ശൂന്യം	chan_send_eow2(ഘടന ssh *, Channel *);

/* helper */
സ്ഥിതം ശൂന്യം	chan_shutdown_write(ഘടന ssh *, Channel *);
സ്ഥിതം ശൂന്യം	chan_shutdown_read(ഘടന ssh *, Channel *);
സ്ഥിതം ശൂന്യം	chan_shutdown_extended_read(ഘടന ssh *, Channel *);

സ്ഥിതം സ്ഥിരം അക്ഷരം * സ്ഥിരം ostates[] = {
	"open", "drain", "wait_ieof", "closed",
};
സ്ഥിതം സ്ഥിരം അക്ഷരം * സ്ഥിരം istates[] = {
	"open", "drain", "wait_oclose", "closed",
};

സ്ഥിതം ശൂന്യം
chan_set_istate(Channel *c, u_int next)
{
	എങ്കിൽ (c->istate > CHAN_നിവേശം_CLOSED || next > CHAN_നിവേശം_CLOSED)
		fatal("chan_set_istate: bad state %d -> %d", c->istate, next);
	debug2("channel %d: input %s -> %s", c->self, istates[c->istate],
	    istates[next]);
	c->istate = next;
}

സ്ഥിതം ശൂന്യം
chan_set_ostate(Channel *c, u_int next)
{
	എങ്കിൽ (c->ostate > CHAN_OUTPUT_CLOSED || next > CHAN_OUTPUT_CLOSED)
		fatal("chan_set_ostate: bad state %d -> %d", c->ostate, next);
	debug2("channel %d: output %s -> %s", c->self, ostates[c->ostate],
	    ostates[next]);
	c->ostate = next;
}

ശൂന്യം
chan_read_failed(ഘടന ssh *ssh, Channel *c)
{
	debug2("channel %d: read failed", c->self);
	തിരഞ്ഞെടുപ്പ് (c->istate) {
	അവസ്ഥ CHAN_നിവേശം_OPEN:
		chan_shutdown_read(ssh, c);
		chan_set_istate(c, CHAN_നിവേശം_WAIT_DRAIN);
		നിർത്തുക;
	സ്ഥിരസ്ഥിതി:
		error("channel %d: chan_read_failed for istate %d",
		    c->self, c->istate);
		നിർത്തുക;
	}
}

ശൂന്യം
chan_ibuf_empty(ഘടന ssh *ssh, Channel *c)
{
	debug2("channel %d: ibuf empty", c->self);
	എങ്കിൽ (sshbuf_len(c->നിവേശം)) {
		error("channel %d: chan_ibuf_empty for non empty buffer",
		    c->self);
		തിരികെ;
	}
	തിരഞ്ഞെടുപ്പ് (c->istate) {
	അവസ്ഥ CHAN_നിവേശം_WAIT_DRAIN:
		എങ്കിൽ (!(c->flags & (CHAN_CLOSE_SENT|CHAN_LOCAL)))
			chan_send_eof2(ssh, c);
		chan_set_istate(c, CHAN_നിവേശം_CLOSED);
		നിർത്തുക;
	സ്ഥിരസ്ഥിതി:
		error("channel %d: chan_ibuf_empty for istate %d",
		    c->self, c->istate);
		നിർത്തുക;
	}
}

ശൂന്യം
chan_obuf_empty(ഘടന ssh *ssh, Channel *c)
{
	debug2("channel %d: obuf empty", c->self);
	എങ്കിൽ (sshbuf_len(c->output)) {
		error("channel %d: chan_obuf_empty for non empty buffer",
		    c->self);
		തിരികെ;
	}
	തിരഞ്ഞെടുപ്പ് (c->ostate) {
	അവസ്ഥ CHAN_OUTPUT_WAIT_DRAIN:
		chan_shutdown_write(ssh, c);
		chan_set_ostate(c, CHAN_OUTPUT_CLOSED);
		നിർത്തുക;
	സ്ഥിരസ്ഥിതി:
		error("channel %d: internal error: obuf_empty for ostate %d",
		    c->self, c->ostate);
		നിർത്തുക;
	}
}

ശൂന്യം
chan_rcvd_eow(ഘടന ssh *ssh, Channel *c)
{
	debug2("channel %d: rcvd eow", c->self);
	തിരഞ്ഞെടുപ്പ് (c->istate) {
	അവസ്ഥ CHAN_നിവേശം_OPEN:
		chan_shutdown_read(ssh, c);
		chan_set_istate(c, CHAN_നിവേശം_CLOSED);
		നിർത്തുക;
	}
}

സ്ഥിതം ശൂന്യം
chan_send_eof2(ഘടന ssh *ssh, Channel *c)
{
	പൂർണ്ണസംഖ്യ r;

	debug2("channel %d: send eof", c->self);
	തിരഞ്ഞെടുപ്പ് (c->istate) {
	അവസ്ഥ CHAN_നിവേശം_WAIT_DRAIN:
		എങ്കിൽ (!c->have_remote_id)
			fatal_f("channel %d: no remote_id", c->self);
		എങ്കിൽ ((r = sshpkt_start(ssh, SSH2_സന്ദേശം_CHANNEL_EOF)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send CHANNEL_EOF");
		c->flags |= CHAN_EOF_SENT;
		നിർത്തുക;
	സ്ഥിരസ്ഥിതി:
		error("channel %d: cannot send eof for istate %d",
		    c->self, c->istate);
		നിർത്തുക;
	}
}

സ്ഥിതം ശൂന്യം
chan_send_close2(ഘടന ssh *ssh, Channel *c)
{
	പൂർണ്ണസംഖ്യ r;

	debug2("channel %d: send_close2", c->self);
	എങ്കിൽ (c->ostate != CHAN_OUTPUT_CLOSED ||
	    c->istate != CHAN_നിവേശം_CLOSED) {
		error("channel %d: cannot send close for istate/ostate %d/%d",
		    c->self, c->istate, c->ostate);
	} അല്ലെങ്കിൽ എങ്കിൽ (c->flags & CHAN_CLOSE_SENT) {
		error("channel %d: already sent close", c->self);
	} അല്ലെങ്കിൽ {
		എങ്കിൽ (!c->have_remote_id)
			fatal_f("channel %d: no remote_id", c->self);
		debug2("channel %d: send close for remote id %u", c->self,
		    c->remote_id);
		എങ്കിൽ ((r = sshpkt_start(ssh, SSH2_സന്ദേശം_CHANNEL_CLOSE)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send CHANNEL_EOF");
		c->flags |= CHAN_CLOSE_SENT;
	}
}

സ്ഥിതം ശൂന്യം
chan_send_eow2(ഘടന ssh *ssh, Channel *c)
{
	പൂർണ്ണസംഖ്യ r;

	debug2("channel %d: send eow", c->self);
	എങ്കിൽ (c->ostate == CHAN_OUTPUT_CLOSED) {
		error("channel %d: must not sent eow on closed output",
		    c->self);
		തിരികെ;
	}
	എങ്കിൽ (!(ssh->compat & SSH_NEW_OPENSSH))
		തിരികെ;
	എങ്കിൽ (!c->have_remote_id)
		fatal_f("channel %d: no remote_id", c->self);
	എങ്കിൽ ((r = sshpkt_start(ssh, SSH2_സന്ദേശം_CHANNEL_REQUEST)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "eow@openssh.com")) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send CHANNEL_EOF");
}

/* shared */

ശൂന്യം
chan_rcvd_ieof(ഘടന ssh *ssh, Channel *c)
{
	debug2("channel %d: rcvd eof", c->self);
	c->flags |= CHAN_EOF_RCVD;
	എങ്കിൽ (c->ostate == CHAN_OUTPUT_OPEN)
		chan_set_ostate(c, CHAN_OUTPUT_WAIT_DRAIN);
	എങ്കിൽ (c->ostate == CHAN_OUTPUT_WAIT_DRAIN &&
	    sshbuf_len(c->output) == 0 &&
	    !CHANNEL_EFD_OUTPUT_ACTIVE(c))
		chan_obuf_empty(ssh, c);
}

ശൂന്യം
chan_rcvd_oclose(ഘടന ssh *ssh, Channel *c)
{
	debug2("channel %d: rcvd close", c->self);
	എങ്കിൽ (!(c->flags & CHAN_LOCAL)) {
		എങ്കിൽ (c->flags & CHAN_CLOSE_RCVD)
			error("channel %d: protocol error: close rcvd twice",
			    c->self);
		c->flags |= CHAN_CLOSE_RCVD;
	}
	എങ്കിൽ (c->type == SSH_CHANNEL_LARVAL) {
		/* tear down larval channels immediately */
		chan_set_ostate(c, CHAN_OUTPUT_CLOSED);
		chan_set_istate(c, CHAN_നിവേശം_CLOSED);
		തിരികെ;
	}
	തിരഞ്ഞെടുപ്പ് (c->ostate) {
	അവസ്ഥ CHAN_OUTPUT_OPEN:
		/*
		 * wait until a data from the channel is consumed if a CLOSE
		 * is received
		 */
		chan_set_ostate(c, CHAN_OUTPUT_WAIT_DRAIN);
		നിർത്തുക;
	}
	തിരഞ്ഞെടുപ്പ് (c->istate) {
	അവസ്ഥ CHAN_നിവേശം_OPEN:
		chan_shutdown_read(ssh, c);
		chan_shutdown_extended_read(ssh, c);
		chan_set_istate(c, CHAN_നിവേശം_CLOSED);
		നിർത്തുക;
	അവസ്ഥ CHAN_നിവേശം_WAIT_DRAIN:
		എങ്കിൽ (!(c->flags & CHAN_LOCAL))
			chan_send_eof2(ssh, c);
		chan_shutdown_extended_read(ssh, c);
		chan_set_istate(c, CHAN_നിവേശം_CLOSED);
		നിർത്തുക;
	}
}

ശൂന്യം
chan_write_failed(ഘടന ssh *ssh, Channel *c)
{
	debug2("channel %d: write failed", c->self);
	തിരഞ്ഞെടുപ്പ് (c->ostate) {
	അവസ്ഥ CHAN_OUTPUT_OPEN:
	അവസ്ഥ CHAN_OUTPUT_WAIT_DRAIN:
		chan_shutdown_write(ssh, c);
		എങ്കിൽ (strcmp(c->ctype, "session") == 0)
			chan_send_eow2(ssh, c);
		chan_set_ostate(c, CHAN_OUTPUT_CLOSED);
		നിർത്തുക;
	സ്ഥിരസ്ഥിതി:
		error("channel %d: chan_write_failed for ostate %d",
		    c->self, c->ostate);
		നിർത്തുക;
	}
}

ശൂന്യം
chan_mark_dead(ഘടന ssh *ssh, Channel *c)
{
	c->type = SSH_CHANNEL_ZOMBIE;
}

പൂർണ്ണസംഖ്യ
chan_is_dead(ഘടന ssh *ssh, Channel *c, പൂർണ്ണസംഖ്യ do_send)
{
	എങ്കിൽ (c->type == SSH_CHANNEL_ZOMBIE) {
		debug2("channel %d: zombie", c->self);
		തിരികെ 1;
	}
	എങ്കിൽ (c->istate != CHAN_നിവേശം_CLOSED || c->ostate != CHAN_OUTPUT_CLOSED)
		തിരികെ 0;
	എങ്കിൽ ((ssh->compat & SSH_BUG_EXTEOF) &&
	    c->extended_usage == CHAN_EXTENDED_WRITE &&
	    c->efd != -1 &&
	    sshbuf_len(c->extended) > 0) {
		debug2("channel %d: active efd: %d len %zu",
		    c->self, c->efd, sshbuf_len(c->extended));
		തിരികെ 0;
	}
	എങ്കിൽ (c->flags & CHAN_LOCAL) {
		debug2("channel %d: is dead (local)", c->self);
		തിരികെ 1;
	}
	എങ്കിൽ (!(c->flags & CHAN_CLOSE_SENT)) {
		എങ്കിൽ (do_send) {
			chan_send_close2(ssh, c);
		} അല്ലെങ്കിൽ {
			/* channel would be dead if we sent a close */
			എങ്കിൽ (c->flags & CHAN_CLOSE_RCVD) {
				debug2("channel %d: almost dead",
				    c->self);
				തിരികെ 1;
			}
		}
	}
	എങ്കിൽ ((c->flags & CHAN_CLOSE_SENT) &&
	    (c->flags & CHAN_CLOSE_RCVD)) {
		debug2("channel %d: is dead", c->self);
		തിരികെ 1;
	}
	തിരികെ 0;
}

/* helper */
സ്ഥിതം ശൂന്യം
chan_shutdown_write(ഘടന ssh *ssh, Channel *c)
{
	sshbuf_reset(c->output);
	എങ്കിൽ (c->type == SSH_CHANNEL_LARVAL)
		തിരികെ;
	/* shutdown failure is allowed if write failed already */
	debug2_f("channel %d: (i%d o%d sock %d wfd %d efd %d [%s])",
	    c->self, c->istate, c->ostate, c->sock, c->wfd, c->efd,
	    channel_format_extended_usage(c));
	എങ്കിൽ (c->sock != -1) {
		എങ്കിൽ (shutdown(c->sock, SHUT_WR) == -1) {
			debug2_f("channel %d: shutdown() failed for "
			    "fd %d [i%d o%d]: %.100s", c->self, c->sock,
			    c->istate, c->ostate, strerror(errno));
		}
	} അല്ലെങ്കിൽ {
		എങ്കിൽ (channel_close_fd(ssh, c, &c->wfd) < 0) {
			logit_f("channel %d: close() failed for "
			    "fd %d [i%d o%d]: %.100s", c->self, c->wfd,
			    c->istate, c->ostate, strerror(errno));
		}
	}
}

സ്ഥിതം ശൂന്യം
chan_shutdown_read(ഘടന ssh *ssh, Channel *c)
{
	എങ്കിൽ (c->type == SSH_CHANNEL_LARVAL)
		തിരികെ;
	debug2_f("channel %d: (i%d o%d sock %d wfd %d efd %d [%s])",
	    c->self, c->istate, c->ostate, c->sock, c->rfd, c->efd,
	    channel_format_extended_usage(c));
	എങ്കിൽ (c->sock != -1) {
		/*
		 * shutdown(sock, SHUT_READ) may return ENOTCONN if the
		 * write side has been closed already. (bug on Linux)
		 * HP-UX may return ENOTCONN also.
		 */
		എങ്കിൽ (shutdown(c->sock, SHUT_RD) == -1 && errno != ENOTCONN) {
			error_f("channel %d: shutdown() failed for "
			    "fd %d [i%d o%d]: %.100s", c->self, c->sock,
			    c->istate, c->ostate, strerror(errno));
		}
	} അല്ലെങ്കിൽ {
		എങ്കിൽ (channel_close_fd(ssh, c, &c->rfd) < 0) {
			logit_f("channel %d: close() failed for "
			    "fd %d [i%d o%d]: %.100s", c->self, c->rfd,
			    c->istate, c->ostate, strerror(errno));
		}
	}
}

സ്ഥിതം ശൂന്യം
chan_shutdown_extended_read(ഘടന ssh *ssh, Channel *c)
{
	എങ്കിൽ (c->type == SSH_CHANNEL_LARVAL || c->efd == -1)
		തിരികെ;
	എങ്കിൽ (c->extended_usage != CHAN_EXTENDED_READ &&
	    c->extended_usage != CHAN_EXTENDED_IGNORE)
		തിരികെ;
	debug_f("channel %d: (i%d o%d sock %d wfd %d efd %d [%s])",
	    c->self, c->istate, c->ostate, c->sock, c->rfd, c->efd,
	    channel_format_extended_usage(c));
	എങ്കിൽ (channel_close_fd(ssh, c, &c->efd) < 0) {
		logit_f("channel %d: close() failed for "
		    "extended fd %d [i%d o%d]: %.100s", c->self, c->efd,
		    c->istate, c->ostate, strerror(errno));
	}
}
