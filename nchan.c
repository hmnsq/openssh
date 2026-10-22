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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/socket.h>

#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <stdarg.h>

#அந்தர்பாவ "ssh2.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "packet.h"
#அந்தர்பாவ "channels.h"
#அந்தர்பாவ "compat.h"
#அந்தர்பாவ "log.h"

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
நிலையான வெறுமை	chan_send_eof2(கட்டமைப்பு ssh *, Channel *);
நிலையான வெறுமை	chan_send_eow2(கட்டமைப்பு ssh *, Channel *);

/* helper */
நிலையான வெறுமை	chan_shutdown_write(கட்டமைப்பு ssh *, Channel *);
நிலையான வெறுமை	chan_shutdown_read(கட்டமைப்பு ssh *, Channel *);
நிலையான வெறுமை	chan_shutdown_extended_read(கட்டமைப்பு ssh *, Channel *);

நிலையான மாறிலி எழுத்து * மாறிலி ostates[] = {
	"open", "drain", "wait_ieof", "closed",
};
நிலையான மாறிலி எழுத்து * மாறிலி istates[] = {
	"open", "drain", "wait_oclose", "closed",
};

நிலையான வெறுமை
chan_set_istate(Channel *c, u_int next)
{
	எனில் (c->istate > CHAN_உள்ளீடு_CLOSED || next > CHAN_உள்ளீடு_CLOSED)
		fatal("chan_set_istate: bad state %d -> %d", c->istate, next);
	debug2("channel %d: input %s -> %s", c->self, istates[c->istate],
	    istates[next]);
	c->istate = next;
}

நிலையான வெறுமை
chan_set_ostate(Channel *c, u_int next)
{
	எனில் (c->ostate > CHAN_OUTPUT_CLOSED || next > CHAN_OUTPUT_CLOSED)
		fatal("chan_set_ostate: bad state %d -> %d", c->ostate, next);
	debug2("channel %d: output %s -> %s", c->self, ostates[c->ostate],
	    ostates[next]);
	c->ostate = next;
}

வெறுமை
chan_read_failed(கட்டமைப்பு ssh *ssh, Channel *c)
{
	debug2("channel %d: read failed", c->self);
	தேர்வு (c->istate) {
	நிலை CHAN_உள்ளீடு_OPEN:
		chan_shutdown_read(ssh, c);
		chan_set_istate(c, CHAN_உள்ளீடு_WAIT_DRAIN);
		நிறுத்து;
	இயல்பு:
		error("channel %d: chan_read_failed for istate %d",
		    c->self, c->istate);
		நிறுத்து;
	}
}

வெறுமை
chan_ibuf_empty(கட்டமைப்பு ssh *ssh, Channel *c)
{
	debug2("channel %d: ibuf empty", c->self);
	எனில் (sshbuf_len(c->உள்ளீடு)) {
		error("channel %d: chan_ibuf_empty for non empty buffer",
		    c->self);
		திரும்பு;
	}
	தேர்வு (c->istate) {
	நிலை CHAN_உள்ளீடு_WAIT_DRAIN:
		எனில் (!(c->flags & (CHAN_CLOSE_SENT|CHAN_LOCAL)))
			chan_send_eof2(ssh, c);
		chan_set_istate(c, CHAN_உள்ளீடு_CLOSED);
		நிறுத்து;
	இயல்பு:
		error("channel %d: chan_ibuf_empty for istate %d",
		    c->self, c->istate);
		நிறுத்து;
	}
}

வெறுமை
chan_obuf_empty(கட்டமைப்பு ssh *ssh, Channel *c)
{
	debug2("channel %d: obuf empty", c->self);
	எனில் (sshbuf_len(c->output)) {
		error("channel %d: chan_obuf_empty for non empty buffer",
		    c->self);
		திரும்பு;
	}
	தேர்வு (c->ostate) {
	நிலை CHAN_OUTPUT_WAIT_DRAIN:
		chan_shutdown_write(ssh, c);
		chan_set_ostate(c, CHAN_OUTPUT_CLOSED);
		நிறுத்து;
	இயல்பு:
		error("channel %d: internal error: obuf_empty for ostate %d",
		    c->self, c->ostate);
		நிறுத்து;
	}
}

வெறுமை
chan_rcvd_eow(கட்டமைப்பு ssh *ssh, Channel *c)
{
	debug2("channel %d: rcvd eow", c->self);
	தேர்வு (c->istate) {
	நிலை CHAN_உள்ளீடு_OPEN:
		chan_shutdown_read(ssh, c);
		chan_set_istate(c, CHAN_உள்ளீடு_CLOSED);
		நிறுத்து;
	}
}

நிலையான வெறுமை
chan_send_eof2(கட்டமைப்பு ssh *ssh, Channel *c)
{
	முழு r;

	debug2("channel %d: send eof", c->self);
	தேர்வு (c->istate) {
	நிலை CHAN_உள்ளீடு_WAIT_DRAIN:
		எனில் (!c->have_remote_id)
			fatal_f("channel %d: no remote_id", c->self);
		எனில் ((r = sshpkt_start(ssh, SSH2_செய்தி_CHANNEL_EOF)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send CHANNEL_EOF");
		c->flags |= CHAN_EOF_SENT;
		நிறுத்து;
	இயல்பு:
		error("channel %d: cannot send eof for istate %d",
		    c->self, c->istate);
		நிறுத்து;
	}
}

நிலையான வெறுமை
chan_send_close2(கட்டமைப்பு ssh *ssh, Channel *c)
{
	முழு r;

	debug2("channel %d: send_close2", c->self);
	எனில் (c->ostate != CHAN_OUTPUT_CLOSED ||
	    c->istate != CHAN_உள்ளீடு_CLOSED) {
		error("channel %d: cannot send close for istate/ostate %d/%d",
		    c->self, c->istate, c->ostate);
	} இல்லையெனில் எனில் (c->flags & CHAN_CLOSE_SENT) {
		error("channel %d: already sent close", c->self);
	} இல்லையெனில் {
		எனில் (!c->have_remote_id)
			fatal_f("channel %d: no remote_id", c->self);
		debug2("channel %d: send close for remote id %u", c->self,
		    c->remote_id);
		எனில் ((r = sshpkt_start(ssh, SSH2_செய்தி_CHANNEL_CLOSE)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send CHANNEL_EOF");
		c->flags |= CHAN_CLOSE_SENT;
	}
}

நிலையான வெறுமை
chan_send_eow2(கட்டமைப்பு ssh *ssh, Channel *c)
{
	முழு r;

	debug2("channel %d: send eow", c->self);
	எனில் (c->ostate == CHAN_OUTPUT_CLOSED) {
		error("channel %d: must not sent eow on closed output",
		    c->self);
		திரும்பு;
	}
	எனில் (!(ssh->compat & SSH_NEW_OPENSSH))
		திரும்பு;
	எனில் (!c->have_remote_id)
		fatal_f("channel %d: no remote_id", c->self);
	எனில் ((r = sshpkt_start(ssh, SSH2_செய்தி_CHANNEL_REQUEST)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "eow@openssh.com")) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send CHANNEL_EOF");
}

/* shared */

வெறுமை
chan_rcvd_ieof(கட்டமைப்பு ssh *ssh, Channel *c)
{
	debug2("channel %d: rcvd eof", c->self);
	c->flags |= CHAN_EOF_RCVD;
	எனில் (c->ostate == CHAN_OUTPUT_OPEN)
		chan_set_ostate(c, CHAN_OUTPUT_WAIT_DRAIN);
	எனில் (c->ostate == CHAN_OUTPUT_WAIT_DRAIN &&
	    sshbuf_len(c->output) == 0 &&
	    !CHANNEL_EFD_OUTPUT_ACTIVE(c))
		chan_obuf_empty(ssh, c);
}

வெறுமை
chan_rcvd_oclose(கட்டமைப்பு ssh *ssh, Channel *c)
{
	debug2("channel %d: rcvd close", c->self);
	எனில் (!(c->flags & CHAN_LOCAL)) {
		எனில் (c->flags & CHAN_CLOSE_RCVD)
			error("channel %d: protocol error: close rcvd twice",
			    c->self);
		c->flags |= CHAN_CLOSE_RCVD;
	}
	எனில் (c->type == SSH_CHANNEL_LARVAL) {
		/* tear down larval channels immediately */
		chan_set_ostate(c, CHAN_OUTPUT_CLOSED);
		chan_set_istate(c, CHAN_உள்ளீடு_CLOSED);
		திரும்பு;
	}
	தேர்வு (c->ostate) {
	நிலை CHAN_OUTPUT_OPEN:
		/*
		 * wait until a data from the channel is consumed if a CLOSE
		 * is received
		 */
		chan_set_ostate(c, CHAN_OUTPUT_WAIT_DRAIN);
		நிறுத்து;
	}
	தேர்வு (c->istate) {
	நிலை CHAN_உள்ளீடு_OPEN:
		chan_shutdown_read(ssh, c);
		chan_shutdown_extended_read(ssh, c);
		chan_set_istate(c, CHAN_உள்ளீடு_CLOSED);
		நிறுத்து;
	நிலை CHAN_உள்ளீடு_WAIT_DRAIN:
		எனில் (!(c->flags & CHAN_LOCAL))
			chan_send_eof2(ssh, c);
		chan_shutdown_extended_read(ssh, c);
		chan_set_istate(c, CHAN_உள்ளீடு_CLOSED);
		நிறுத்து;
	}
}

வெறுமை
chan_write_failed(கட்டமைப்பு ssh *ssh, Channel *c)
{
	debug2("channel %d: write failed", c->self);
	தேர்வு (c->ostate) {
	நிலை CHAN_OUTPUT_OPEN:
	நிலை CHAN_OUTPUT_WAIT_DRAIN:
		chan_shutdown_write(ssh, c);
		எனில் (strcmp(c->ctype, "session") == 0)
			chan_send_eow2(ssh, c);
		chan_set_ostate(c, CHAN_OUTPUT_CLOSED);
		நிறுத்து;
	இயல்பு:
		error("channel %d: chan_write_failed for ostate %d",
		    c->self, c->ostate);
		நிறுத்து;
	}
}

வெறுமை
chan_mark_dead(கட்டமைப்பு ssh *ssh, Channel *c)
{
	c->type = SSH_CHANNEL_ZOMBIE;
}

முழு
chan_is_dead(கட்டமைப்பு ssh *ssh, Channel *c, முழு do_send)
{
	எனில் (c->type == SSH_CHANNEL_ZOMBIE) {
		debug2("channel %d: zombie", c->self);
		திரும்பு 1;
	}
	எனில் (c->istate != CHAN_உள்ளீடு_CLOSED || c->ostate != CHAN_OUTPUT_CLOSED)
		திரும்பு 0;
	எனில் ((ssh->compat & SSH_BUG_EXTEOF) &&
	    c->extended_usage == CHAN_EXTENDED_WRITE &&
	    c->efd != -1 &&
	    sshbuf_len(c->extended) > 0) {
		debug2("channel %d: active efd: %d len %zu",
		    c->self, c->efd, sshbuf_len(c->extended));
		திரும்பு 0;
	}
	எனில் (c->flags & CHAN_LOCAL) {
		debug2("channel %d: is dead (local)", c->self);
		திரும்பு 1;
	}
	எனில் (!(c->flags & CHAN_CLOSE_SENT)) {
		எனில் (do_send) {
			chan_send_close2(ssh, c);
		} இல்லையெனில் {
			/* channel would be dead if we sent a close */
			எனில் (c->flags & CHAN_CLOSE_RCVD) {
				debug2("channel %d: almost dead",
				    c->self);
				திரும்பு 1;
			}
		}
	}
	எனில் ((c->flags & CHAN_CLOSE_SENT) &&
	    (c->flags & CHAN_CLOSE_RCVD)) {
		debug2("channel %d: is dead", c->self);
		திரும்பு 1;
	}
	திரும்பு 0;
}

/* helper */
நிலையான வெறுமை
chan_shutdown_write(கட்டமைப்பு ssh *ssh, Channel *c)
{
	sshbuf_reset(c->output);
	எனில் (c->type == SSH_CHANNEL_LARVAL)
		திரும்பு;
	/* shutdown failure is allowed if write failed already */
	debug2_f("channel %d: (i%d o%d sock %d wfd %d efd %d [%s])",
	    c->self, c->istate, c->ostate, c->sock, c->wfd, c->efd,
	    channel_format_extended_usage(c));
	எனில் (c->sock != -1) {
		எனில் (shutdown(c->sock, SHUT_WR) == -1) {
			debug2_f("channel %d: shutdown() failed for "
			    "fd %d [i%d o%d]: %.100s", c->self, c->sock,
			    c->istate, c->ostate, strerror(errno));
		}
	} இல்லையெனில் {
		எனில் (channel_close_fd(ssh, c, &c->wfd) < 0) {
			logit_f("channel %d: close() failed for "
			    "fd %d [i%d o%d]: %.100s", c->self, c->wfd,
			    c->istate, c->ostate, strerror(errno));
		}
	}
}

நிலையான வெறுமை
chan_shutdown_read(கட்டமைப்பு ssh *ssh, Channel *c)
{
	எனில் (c->type == SSH_CHANNEL_LARVAL)
		திரும்பு;
	debug2_f("channel %d: (i%d o%d sock %d wfd %d efd %d [%s])",
	    c->self, c->istate, c->ostate, c->sock, c->rfd, c->efd,
	    channel_format_extended_usage(c));
	எனில் (c->sock != -1) {
		/*
		 * shutdown(sock, SHUT_READ) may return ENOTCONN if the
		 * write side has been closed already. (bug on Linux)
		 * HP-UX may return ENOTCONN also.
		 */
		எனில் (shutdown(c->sock, SHUT_RD) == -1 && errno != ENOTCONN) {
			error_f("channel %d: shutdown() failed for "
			    "fd %d [i%d o%d]: %.100s", c->self, c->sock,
			    c->istate, c->ostate, strerror(errno));
		}
	} இல்லையெனில் {
		எனில் (channel_close_fd(ssh, c, &c->rfd) < 0) {
			logit_f("channel %d: close() failed for "
			    "fd %d [i%d o%d]: %.100s", c->self, c->rfd,
			    c->istate, c->ostate, strerror(errno));
		}
	}
}

நிலையான வெறுமை
chan_shutdown_extended_read(கட்டமைப்பு ssh *ssh, Channel *c)
{
	எனில் (c->type == SSH_CHANNEL_LARVAL || c->efd == -1)
		திரும்பு;
	எனில் (c->extended_usage != CHAN_EXTENDED_READ &&
	    c->extended_usage != CHAN_EXTENDED_IGNORE)
		திரும்பு;
	debug_f("channel %d: (i%d o%d sock %d wfd %d efd %d [%s])",
	    c->self, c->istate, c->ostate, c->sock, c->rfd, c->efd,
	    channel_format_extended_usage(c));
	எனில் (channel_close_fd(ssh, c, &c->efd) < 0) {
		logit_f("channel %d: close() failed for "
		    "extended fd %d [i%d o%d]: %.100s", c->self, c->efd,
		    c->istate, c->ostate, strerror(errno));
	}
}
