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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/socket.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "ssh2.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "packet.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "channels.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "compat.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"

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
ਸਥਿਰ ਖਾਲੀ	chan_send_eof2(ਬਣਤਰ ssh *, Channel *);
ਸਥਿਰ ਖਾਲੀ	chan_send_eow2(ਬਣਤਰ ssh *, Channel *);

/* helper */
ਸਥਿਰ ਖਾਲੀ	chan_shutdown_write(ਬਣਤਰ ssh *, Channel *);
ਸਥਿਰ ਖਾਲੀ	chan_shutdown_read(ਬਣਤਰ ssh *, Channel *);
ਸਥਿਰ ਖਾਲੀ	chan_shutdown_extended_read(ਬਣਤਰ ssh *, Channel *);

ਸਥਿਰ ਅਚਲ ਅੱਖਰ * ਅਚਲ ostates[] = {
	"open", "drain", "wait_ieof", "closed",
};
ਸਥਿਰ ਅਚਲ ਅੱਖਰ * ਅਚਲ istates[] = {
	"open", "drain", "wait_oclose", "closed",
};

ਸਥਿਰ ਖਾਲੀ
chan_ਸੈੱਟ_istate(Channel *c, u_int ਅਗਲਾ)
{
	ਜੇ (c->istate > CHAN_ਨਿਵੇਸ਼_CLOSED || ਅਗਲਾ > CHAN_ਨਿਵੇਸ਼_CLOSED)
		fatal("chan_set_istate: bad state %d -> %d", c->istate, ਅਗਲਾ);
	debug2("channel %d: input %s -> %s", c->self, istates[c->istate],
	    istates[ਅਗਲਾ]);
	c->istate = ਅਗਲਾ;
}

ਸਥਿਰ ਖਾਲੀ
chan_ਸੈੱਟ_ostate(Channel *c, u_int ਅਗਲਾ)
{
	ਜੇ (c->ostate > CHAN_OUTPUT_CLOSED || ਅਗਲਾ > CHAN_OUTPUT_CLOSED)
		fatal("chan_set_ostate: bad state %d -> %d", c->ostate, ਅਗਲਾ);
	debug2("channel %d: output %s -> %s", c->self, ostates[c->ostate],
	    ostates[ਅਗਲਾ]);
	c->ostate = ਅਗਲਾ;
}

ਖਾਲੀ
chan_read_failed(ਬਣਤਰ ssh *ssh, Channel *c)
{
	debug2("channel %d: read failed", c->self);
	ਚੋਣ (c->istate) {
	ਹਾਲਤ CHAN_ਨਿਵੇਸ਼_OPEN:
		chan_shutdown_read(ssh, c);
		chan_ਸੈੱਟ_istate(c, CHAN_ਨਿਵੇਸ਼_WAIT_DRAIN);
		ਰੋਕੋ;
	ਮੂਲ:
		error("channel %d: chan_read_failed for istate %d",
		    c->self, c->istate);
		ਰੋਕੋ;
	}
}

ਖਾਲੀ
chan_ibuf_ਖਾਲੀ_ਥਾਵਾਂ(ਬਣਤਰ ssh *ssh, Channel *c)
{
	debug2("channel %d: ibuf empty", c->self);
	ਜੇ (sshbuf_len(c->ਨਿਵੇਸ਼)) {
		error("channel %d: chan_ibuf_empty for non empty buffer",
		    c->self);
		ਵਾਪਸ;
	}
	ਚੋਣ (c->istate) {
	ਹਾਲਤ CHAN_ਨਿਵੇਸ਼_WAIT_DRAIN:
		ਜੇ (!(c->flags & (CHAN_CLOSE_ਭੇਜਿਆ|CHAN_LOCAL)))
			chan_send_eof2(ssh, c);
		chan_ਸੈੱਟ_istate(c, CHAN_ਨਿਵੇਸ਼_CLOSED);
		ਰੋਕੋ;
	ਮੂਲ:
		error("channel %d: chan_ibuf_empty for istate %d",
		    c->self, c->istate);
		ਰੋਕੋ;
	}
}

ਖਾਲੀ
chan_obuf_ਖਾਲੀ_ਥਾਵਾਂ(ਬਣਤਰ ssh *ssh, Channel *c)
{
	debug2("channel %d: obuf empty", c->self);
	ਜੇ (sshbuf_len(c->output)) {
		error("channel %d: chan_obuf_empty for non empty buffer",
		    c->self);
		ਵਾਪਸ;
	}
	ਚੋਣ (c->ostate) {
	ਹਾਲਤ CHAN_OUTPUT_WAIT_DRAIN:
		chan_shutdown_write(ssh, c);
		chan_ਸੈੱਟ_ostate(c, CHAN_OUTPUT_CLOSED);
		ਰੋਕੋ;
	ਮੂਲ:
		error("channel %d: internal error: obuf_empty for ostate %d",
		    c->self, c->ostate);
		ਰੋਕੋ;
	}
}

ਖਾਲੀ
chan_rcvd_eow(ਬਣਤਰ ssh *ssh, Channel *c)
{
	debug2("channel %d: rcvd eow", c->self);
	ਚੋਣ (c->istate) {
	ਹਾਲਤ CHAN_ਨਿਵੇਸ਼_OPEN:
		chan_shutdown_read(ssh, c);
		chan_ਸੈੱਟ_istate(c, CHAN_ਨਿਵੇਸ਼_CLOSED);
		ਰੋਕੋ;
	}
}

ਸਥਿਰ ਖਾਲੀ
chan_send_eof2(ਬਣਤਰ ssh *ssh, Channel *c)
{
	ਪੂਰਨ r;

	debug2("channel %d: send eof", c->self);
	ਚੋਣ (c->istate) {
	ਹਾਲਤ CHAN_ਨਿਵੇਸ਼_WAIT_DRAIN:
		ਜੇ (!c->have_remote_id)
			fatal_f("channel %d: no remote_id", c->self);
		ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh, SSH2_ਸੁਨੇਹਾ_CHANNEL_EOF)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send CHANNEL_EOF");
		c->flags |= CHAN_EOF_ਭੇਜਿਆ;
		ਰੋਕੋ;
	ਮੂਲ:
		error("channel %d: cannot send eof for istate %d",
		    c->self, c->istate);
		ਰੋਕੋ;
	}
}

ਸਥਿਰ ਖਾਲੀ
chan_send_close2(ਬਣਤਰ ssh *ssh, Channel *c)
{
	ਪੂਰਨ r;

	debug2("channel %d: send_close2", c->self);
	ਜੇ (c->ostate != CHAN_OUTPUT_CLOSED ||
	    c->istate != CHAN_ਨਿਵੇਸ਼_CLOSED) {
		error("channel %d: cannot send close for istate/ostate %d/%d",
		    c->self, c->istate, c->ostate);
	} ਨਹੀਂਤਾਂ ਜੇ (c->flags & CHAN_CLOSE_ਭੇਜਿਆ) {
		error("channel %d: already sent close", c->self);
	} ਨਹੀਂਤਾਂ {
		ਜੇ (!c->have_remote_id)
			fatal_f("channel %d: no remote_id", c->self);
		debug2("channel %d: send close for remote id %u", c->self,
		    c->remote_id);
		ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh, SSH2_ਸੁਨੇਹਾ_CHANNEL_CLOSE)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send CHANNEL_EOF");
		c->flags |= CHAN_CLOSE_ਭੇਜਿਆ;
	}
}

ਸਥਿਰ ਖਾਲੀ
chan_send_eow2(ਬਣਤਰ ssh *ssh, Channel *c)
{
	ਪੂਰਨ r;

	debug2("channel %d: send eow", c->self);
	ਜੇ (c->ostate == CHAN_OUTPUT_CLOSED) {
		error("channel %d: must not sent eow on closed output",
		    c->self);
		ਵਾਪਸ;
	}
	ਜੇ (!(ssh->compat & SSH_NEW_OPENSSH))
		ਵਾਪਸ;
	ਜੇ (!c->have_remote_id)
		fatal_f("channel %d: no remote_id", c->self);
	ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh, SSH2_ਸੁਨੇਹਾ_CHANNEL_REQUEST)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "eow@openssh.com")) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send CHANNEL_EOF");
}

/* shared */

ਖਾਲੀ
chan_rcvd_ieof(ਬਣਤਰ ssh *ssh, Channel *c)
{
	debug2("channel %d: rcvd eof", c->self);
	c->flags |= CHAN_EOF_RCVD;
	ਜੇ (c->ostate == CHAN_OUTPUT_OPEN)
		chan_ਸੈੱਟ_ostate(c, CHAN_OUTPUT_WAIT_DRAIN);
	ਜੇ (c->ostate == CHAN_OUTPUT_WAIT_DRAIN &&
	    sshbuf_len(c->output) == 0 &&
	    !CHANNEL_EFD_OUTPUT_ਸਰਗਰਮ(c))
		chan_obuf_ਖਾਲੀ_ਥਾਵਾਂ(ssh, c);
}

ਖਾਲੀ
chan_rcvd_oclose(ਬਣਤਰ ssh *ssh, Channel *c)
{
	debug2("channel %d: rcvd close", c->self);
	ਜੇ (!(c->flags & CHAN_LOCAL)) {
		ਜੇ (c->flags & CHAN_CLOSE_RCVD)
			error("channel %d: protocol error: close rcvd twice",
			    c->self);
		c->flags |= CHAN_CLOSE_RCVD;
	}
	ਜੇ (c->type == SSH_CHANNEL_LARVAL) {
		/* tear down larval channels immediately */
		chan_ਸੈੱਟ_ostate(c, CHAN_OUTPUT_CLOSED);
		chan_ਸੈੱਟ_istate(c, CHAN_ਨਿਵੇਸ਼_CLOSED);
		ਵਾਪਸ;
	}
	ਚੋਣ (c->ostate) {
	ਹਾਲਤ CHAN_OUTPUT_OPEN:
		/*
		 * wait until a data from the channel is consumed if a CLOSE
		 * is received
		 */
		chan_ਸੈੱਟ_ostate(c, CHAN_OUTPUT_WAIT_DRAIN);
		ਰੋਕੋ;
	}
	ਚੋਣ (c->istate) {
	ਹਾਲਤ CHAN_ਨਿਵੇਸ਼_OPEN:
		chan_shutdown_read(ssh, c);
		chan_shutdown_extended_read(ssh, c);
		chan_ਸੈੱਟ_istate(c, CHAN_ਨਿਵੇਸ਼_CLOSED);
		ਰੋਕੋ;
	ਹਾਲਤ CHAN_ਨਿਵੇਸ਼_WAIT_DRAIN:
		ਜੇ (!(c->flags & CHAN_LOCAL))
			chan_send_eof2(ssh, c);
		chan_shutdown_extended_read(ssh, c);
		chan_ਸੈੱਟ_istate(c, CHAN_ਨਿਵੇਸ਼_CLOSED);
		ਰੋਕੋ;
	}
}

ਖਾਲੀ
chan_write_failed(ਬਣਤਰ ssh *ssh, Channel *c)
{
	debug2("channel %d: write failed", c->self);
	ਚੋਣ (c->ostate) {
	ਹਾਲਤ CHAN_OUTPUT_OPEN:
	ਹਾਲਤ CHAN_OUTPUT_WAIT_DRAIN:
		chan_shutdown_write(ssh, c);
		ਜੇ (strcmp(c->ctype, "session") == 0)
			chan_send_eow2(ssh, c);
		chan_ਸੈੱਟ_ostate(c, CHAN_OUTPUT_CLOSED);
		ਰੋਕੋ;
	ਮੂਲ:
		error("channel %d: chan_write_failed for ostate %d",
		    c->self, c->ostate);
		ਰੋਕੋ;
	}
}

ਖਾਲੀ
chan_mark_dead(ਬਣਤਰ ssh *ssh, Channel *c)
{
	c->type = SSH_CHANNEL_ZOMBIE;
}

ਪੂਰਨ
chan_is_dead(ਬਣਤਰ ssh *ssh, Channel *c, ਪੂਰਨ do_send)
{
	ਜੇ (c->type == SSH_CHANNEL_ZOMBIE) {
		debug2("channel %d: zombie", c->self);
		ਵਾਪਸ 1;
	}
	ਜੇ (c->istate != CHAN_ਨਿਵੇਸ਼_CLOSED || c->ostate != CHAN_OUTPUT_CLOSED)
		ਵਾਪਸ 0;
	ਜੇ ((ssh->compat & SSH_BUG_EXTEOF) &&
	    c->extended_usage == CHAN_EXTENDED_WRITE &&
	    c->efd != -1 &&
	    sshbuf_len(c->extended) > 0) {
		debug2("channel %d: active efd: %d len %zu",
		    c->self, c->efd, sshbuf_len(c->extended));
		ਵਾਪਸ 0;
	}
	ਜੇ (c->flags & CHAN_LOCAL) {
		debug2("channel %d: is dead (local)", c->self);
		ਵਾਪਸ 1;
	}
	ਜੇ (!(c->flags & CHAN_CLOSE_ਭੇਜਿਆ)) {
		ਜੇ (do_send) {
			chan_send_close2(ssh, c);
		} ਨਹੀਂਤਾਂ {
			/* channel would be dead if we sent a close */
			ਜੇ (c->flags & CHAN_CLOSE_RCVD) {
				debug2("channel %d: almost dead",
				    c->self);
				ਵਾਪਸ 1;
			}
		}
	}
	ਜੇ ((c->flags & CHAN_CLOSE_ਭੇਜਿਆ) &&
	    (c->flags & CHAN_CLOSE_RCVD)) {
		debug2("channel %d: is dead", c->self);
		ਵਾਪਸ 1;
	}
	ਵਾਪਸ 0;
}

/* helper */
ਸਥਿਰ ਖਾਲੀ
chan_shutdown_write(ਬਣਤਰ ssh *ssh, Channel *c)
{
	sshbuf_reset(c->output);
	ਜੇ (c->type == SSH_CHANNEL_LARVAL)
		ਵਾਪਸ;
	/* shutdown failure is allowed if write failed already */
	debug2_f("channel %d: (i%d o%d sock %d wfd %d efd %d [%s])",
	    c->self, c->istate, c->ostate, c->sock, c->wfd, c->efd,
	    channel_format_extended_usage(c));
	ਜੇ (c->sock != -1) {
		ਜੇ (shutdown(c->sock, SHUT_WR) == -1) {
			debug2_f("channel %d: shutdown() failed for "
			    "fd %d [i%d o%d]: %.100s", c->self, c->sock,
			    c->istate, c->ostate, strerror(errno));
		}
	} ਨਹੀਂਤਾਂ {
		ਜੇ (channel_close_fd(ssh, c, &c->wfd) < 0) {
			logit_f("channel %d: close() failed for "
			    "fd %d [i%d o%d]: %.100s", c->self, c->wfd,
			    c->istate, c->ostate, strerror(errno));
		}
	}
}

ਸਥਿਰ ਖਾਲੀ
chan_shutdown_read(ਬਣਤਰ ssh *ssh, Channel *c)
{
	ਜੇ (c->type == SSH_CHANNEL_LARVAL)
		ਵਾਪਸ;
	debug2_f("channel %d: (i%d o%d sock %d wfd %d efd %d [%s])",
	    c->self, c->istate, c->ostate, c->sock, c->rfd, c->efd,
	    channel_format_extended_usage(c));
	ਜੇ (c->sock != -1) {
		/*
		 * shutdown(sock, SHUT_READ) may return ENOTCONN if the
		 * write side has been closed already. (bug on Linux)
		 * HP-UX may return ENOTCONN also.
		 */
		ਜੇ (shutdown(c->sock, SHUT_RD) == -1 && errno != ENOTCONN) {
			error_f("channel %d: shutdown() failed for "
			    "fd %d [i%d o%d]: %.100s", c->self, c->sock,
			    c->istate, c->ostate, strerror(errno));
		}
	} ਨਹੀਂਤਾਂ {
		ਜੇ (channel_close_fd(ssh, c, &c->rfd) < 0) {
			logit_f("channel %d: close() failed for "
			    "fd %d [i%d o%d]: %.100s", c->self, c->rfd,
			    c->istate, c->ostate, strerror(errno));
		}
	}
}

ਸਥਿਰ ਖਾਲੀ
chan_shutdown_extended_read(ਬਣਤਰ ssh *ssh, Channel *c)
{
	ਜੇ (c->type == SSH_CHANNEL_LARVAL || c->efd == -1)
		ਵਾਪਸ;
	ਜੇ (c->extended_usage != CHAN_EXTENDED_READ &&
	    c->extended_usage != CHAN_EXTENDED_IGNORE)
		ਵਾਪਸ;
	debug_f("channel %d: (i%d o%d sock %d wfd %d efd %d [%s])",
	    c->self, c->istate, c->ostate, c->sock, c->rfd, c->efd,
	    channel_format_extended_usage(c));
	ਜੇ (channel_close_fd(ssh, c, &c->efd) < 0) {
		logit_f("channel %d: close() failed for "
		    "extended fd %d [i%d o%d]: %.100s", c->self, c->efd,
		    c->istate, c->ostate, strerror(errno));
	}
}
