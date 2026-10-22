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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/socket.h>

#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>

#ಅನ್ತರ್ಭಾವ "ssh2.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "packet.h"
#ಅನ್ತರ್ಭಾವ "channels.h"
#ಅನ್ತರ್ಭಾವ "compat.h"
#ಅನ್ತರ್ಭಾವ "log.h"

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
ಸ್ಥಿರ ಶೂನ್ಯ	chan_send_eof2(ಸಂರಚನಾ ssh *, Channel *);
ಸ್ಥಿರ ಶೂನ್ಯ	chan_send_eow2(ಸಂರಚನಾ ssh *, Channel *);

/* helper */
ಸ್ಥಿರ ಶೂನ್ಯ	chan_shutdown_write(ಸಂರಚನಾ ssh *, Channel *);
ಸ್ಥಿರ ಶೂನ್ಯ	chan_shutdown_read(ಸಂರಚನಾ ssh *, Channel *);
ಸ್ಥಿರ ಶೂನ್ಯ	chan_shutdown_extended_read(ಸಂರಚನಾ ssh *, Channel *);

ಸ್ಥಿರ ಧ್ರುವ ವರ್ಣ * ಧ್ರುವ ostates[] = {
	"open", "drain", "wait_ieof", "closed",
};
ಸ್ಥಿರ ಧ್ರುವ ವರ್ಣ * ಧ್ರುವ istates[] = {
	"open", "drain", "wait_oclose", "closed",
};

ಸ್ಥಿರ ಶೂನ್ಯ
chan_set_istate(Channel *c, u_int next)
{
	ಯದಿ (c->istate > CHAN_ಒಳಹರಿವು_CLOSED || next > CHAN_ಒಳಹರಿವು_CLOSED)
		fatal("chan_set_istate: bad state %d -> %d", c->istate, next);
	debug2("channel %d: input %s -> %s", c->self, istates[c->istate],
	    istates[next]);
	c->istate = next;
}

ಸ್ಥಿರ ಶೂನ್ಯ
chan_set_ostate(Channel *c, u_int next)
{
	ಯದಿ (c->ostate > CHAN_OUTPUT_CLOSED || next > CHAN_OUTPUT_CLOSED)
		fatal("chan_set_ostate: bad state %d -> %d", c->ostate, next);
	debug2("channel %d: output %s -> %s", c->self, ostates[c->ostate],
	    ostates[next]);
	c->ostate = next;
}

ಶೂನ್ಯ
chan_read_failed(ಸಂರಚನಾ ssh *ssh, Channel *c)
{
	debug2("channel %d: read failed", c->self);
	ವಿಕಲ್ಪ (c->istate) {
	ಪಕ್ಷ CHAN_ಒಳಹರಿವು_OPEN:
		chan_shutdown_read(ssh, c);
		chan_set_istate(c, CHAN_ಒಳಹರಿವು_WAIT_DRAIN);
		ಭಙ್ಗ;
	ಸ್ವಭಾವ:
		error("channel %d: chan_read_failed for istate %d",
		    c->self, c->istate);
		ಭಙ್ಗ;
	}
}

ಶೂನ್ಯ
chan_ibuf_empty(ಸಂರಚನಾ ssh *ssh, Channel *c)
{
	debug2("channel %d: ibuf empty", c->self);
	ಯದಿ (sshbuf_len(c->ಒಳಹರಿವು)) {
		error("channel %d: chan_ibuf_empty for non empty buffer",
		    c->self);
		ಪ್ರತ್ಯಾಗಮ;
	}
	ವಿಕಲ್ಪ (c->istate) {
	ಪಕ್ಷ CHAN_ಒಳಹರಿವು_WAIT_DRAIN:
		ಯದಿ (!(c->flags & (CHAN_CLOSE_SENT|CHAN_LOCAL)))
			chan_send_eof2(ssh, c);
		chan_set_istate(c, CHAN_ಒಳಹರಿವು_CLOSED);
		ಭಙ್ಗ;
	ಸ್ವಭಾವ:
		error("channel %d: chan_ibuf_empty for istate %d",
		    c->self, c->istate);
		ಭಙ್ಗ;
	}
}

ಶೂನ್ಯ
chan_obuf_empty(ಸಂರಚನಾ ssh *ssh, Channel *c)
{
	debug2("channel %d: obuf empty", c->self);
	ಯದಿ (sshbuf_len(c->output)) {
		error("channel %d: chan_obuf_empty for non empty buffer",
		    c->self);
		ಪ್ರತ್ಯಾಗಮ;
	}
	ವಿಕಲ್ಪ (c->ostate) {
	ಪಕ್ಷ CHAN_OUTPUT_WAIT_DRAIN:
		chan_shutdown_write(ssh, c);
		chan_set_ostate(c, CHAN_OUTPUT_CLOSED);
		ಭಙ್ಗ;
	ಸ್ವಭಾವ:
		error("channel %d: internal error: obuf_empty for ostate %d",
		    c->self, c->ostate);
		ಭಙ್ಗ;
	}
}

ಶೂನ್ಯ
chan_rcvd_eow(ಸಂರಚನಾ ssh *ssh, Channel *c)
{
	debug2("channel %d: rcvd eow", c->self);
	ವಿಕಲ್ಪ (c->istate) {
	ಪಕ್ಷ CHAN_ಒಳಹರಿವು_OPEN:
		chan_shutdown_read(ssh, c);
		chan_set_istate(c, CHAN_ಒಳಹರಿವು_CLOSED);
		ಭಙ್ಗ;
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
chan_send_eof2(ಸಂರಚನಾ ssh *ssh, Channel *c)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	debug2("channel %d: send eof", c->self);
	ವಿಕಲ್ಪ (c->istate) {
	ಪಕ್ಷ CHAN_ಒಳಹರಿವು_WAIT_DRAIN:
		ಯದಿ (!c->have_remote_id)
			fatal_f("channel %d: no remote_id", c->self);
		ಯದಿ ((r = sshpkt_start(ssh, SSH2_ಸಂದೇಶ_CHANNEL_EOF)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send CHANNEL_EOF");
		c->flags |= CHAN_EOF_SENT;
		ಭಙ್ಗ;
	ಸ್ವಭಾವ:
		error("channel %d: cannot send eof for istate %d",
		    c->self, c->istate);
		ಭಙ್ಗ;
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
chan_send_close2(ಸಂರಚನಾ ssh *ssh, Channel *c)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	debug2("channel %d: send_close2", c->self);
	ಯದಿ (c->ostate != CHAN_OUTPUT_CLOSED ||
	    c->istate != CHAN_ಒಳಹರಿವು_CLOSED) {
		error("channel %d: cannot send close for istate/ostate %d/%d",
		    c->self, c->istate, c->ostate);
	} ಅನ್ಯಥಾ ಯದಿ (c->flags & CHAN_CLOSE_SENT) {
		error("channel %d: already sent close", c->self);
	} ಅನ್ಯಥಾ {
		ಯದಿ (!c->have_remote_id)
			fatal_f("channel %d: no remote_id", c->self);
		debug2("channel %d: send close for remote id %u", c->self,
		    c->remote_id);
		ಯದಿ ((r = sshpkt_start(ssh, SSH2_ಸಂದೇಶ_CHANNEL_CLOSE)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send CHANNEL_EOF");
		c->flags |= CHAN_CLOSE_SENT;
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
chan_send_eow2(ಸಂರಚನಾ ssh *ssh, Channel *c)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	debug2("channel %d: send eow", c->self);
	ಯದಿ (c->ostate == CHAN_OUTPUT_CLOSED) {
		error("channel %d: must not sent eow on closed output",
		    c->self);
		ಪ್ರತ್ಯಾಗಮ;
	}
	ಯದಿ (!(ssh->compat & SSH_NEW_OPENSSH))
		ಪ್ರತ್ಯಾಗಮ;
	ಯದಿ (!c->have_remote_id)
		fatal_f("channel %d: no remote_id", c->self);
	ಯದಿ ((r = sshpkt_start(ssh, SSH2_ಸಂದೇಶ_CHANNEL_REQUEST)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "eow@openssh.com")) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send CHANNEL_EOF");
}

/* shared */

ಶೂನ್ಯ
chan_rcvd_ieof(ಸಂರಚನಾ ssh *ssh, Channel *c)
{
	debug2("channel %d: rcvd eof", c->self);
	c->flags |= CHAN_EOF_RCVD;
	ಯದಿ (c->ostate == CHAN_OUTPUT_OPEN)
		chan_set_ostate(c, CHAN_OUTPUT_WAIT_DRAIN);
	ಯದಿ (c->ostate == CHAN_OUTPUT_WAIT_DRAIN &&
	    sshbuf_len(c->output) == 0 &&
	    !CHANNEL_EFD_OUTPUT_ACTIVE(c))
		chan_obuf_empty(ssh, c);
}

ಶೂನ್ಯ
chan_rcvd_oclose(ಸಂರಚನಾ ssh *ssh, Channel *c)
{
	debug2("channel %d: rcvd close", c->self);
	ಯದಿ (!(c->flags & CHAN_LOCAL)) {
		ಯದಿ (c->flags & CHAN_CLOSE_RCVD)
			error("channel %d: protocol error: close rcvd twice",
			    c->self);
		c->flags |= CHAN_CLOSE_RCVD;
	}
	ಯದಿ (c->type == SSH_CHANNEL_LARVAL) {
		/* tear down larval channels immediately */
		chan_set_ostate(c, CHAN_OUTPUT_CLOSED);
		chan_set_istate(c, CHAN_ಒಳಹರಿವು_CLOSED);
		ಪ್ರತ್ಯಾಗಮ;
	}
	ವಿಕಲ್ಪ (c->ostate) {
	ಪಕ್ಷ CHAN_OUTPUT_OPEN:
		/*
		 * wait until a data from the channel is consumed if a CLOSE
		 * is received
		 */
		chan_set_ostate(c, CHAN_OUTPUT_WAIT_DRAIN);
		ಭಙ್ಗ;
	}
	ವಿಕಲ್ಪ (c->istate) {
	ಪಕ್ಷ CHAN_ಒಳಹರಿವು_OPEN:
		chan_shutdown_read(ssh, c);
		chan_shutdown_extended_read(ssh, c);
		chan_set_istate(c, CHAN_ಒಳಹರಿವು_CLOSED);
		ಭಙ್ಗ;
	ಪಕ್ಷ CHAN_ಒಳಹರಿವು_WAIT_DRAIN:
		ಯದಿ (!(c->flags & CHAN_LOCAL))
			chan_send_eof2(ssh, c);
		chan_shutdown_extended_read(ssh, c);
		chan_set_istate(c, CHAN_ಒಳಹರಿವು_CLOSED);
		ಭಙ್ಗ;
	}
}

ಶೂನ್ಯ
chan_write_failed(ಸಂರಚನಾ ssh *ssh, Channel *c)
{
	debug2("channel %d: write failed", c->self);
	ವಿಕಲ್ಪ (c->ostate) {
	ಪಕ್ಷ CHAN_OUTPUT_OPEN:
	ಪಕ್ಷ CHAN_OUTPUT_WAIT_DRAIN:
		chan_shutdown_write(ssh, c);
		ಯದಿ (strcmp(c->ctype, "session") == 0)
			chan_send_eow2(ssh, c);
		chan_set_ostate(c, CHAN_OUTPUT_CLOSED);
		ಭಙ್ಗ;
	ಸ್ವಭಾವ:
		error("channel %d: chan_write_failed for ostate %d",
		    c->self, c->ostate);
		ಭಙ್ಗ;
	}
}

ಶೂನ್ಯ
chan_mark_dead(ಸಂರಚನಾ ssh *ssh, Channel *c)
{
	c->type = SSH_CHANNEL_ZOMBIE;
}

ಪೂರ್ಣಾಙ್ಕ
chan_is_dead(ಸಂರಚನಾ ssh *ssh, Channel *c, ಪೂರ್ಣಾಙ್ಕ do_send)
{
	ಯದಿ (c->type == SSH_CHANNEL_ZOMBIE) {
		debug2("channel %d: zombie", c->self);
		ಪ್ರತ್ಯಾಗಮ 1;
	}
	ಯದಿ (c->istate != CHAN_ಒಳಹರಿವು_CLOSED || c->ostate != CHAN_OUTPUT_CLOSED)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ ((ssh->compat & SSH_BUG_EXTEOF) &&
	    c->extended_usage == CHAN_EXTENDED_WRITE &&
	    c->efd != -1 &&
	    sshbuf_len(c->extended) > 0) {
		debug2("channel %d: active efd: %d len %zu",
		    c->self, c->efd, sshbuf_len(c->extended));
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	ಯದಿ (c->flags & CHAN_LOCAL) {
		debug2("channel %d: is dead (local)", c->self);
		ಪ್ರತ್ಯಾಗಮ 1;
	}
	ಯದಿ (!(c->flags & CHAN_CLOSE_SENT)) {
		ಯದಿ (do_send) {
			chan_send_close2(ssh, c);
		} ಅನ್ಯಥಾ {
			/* channel would be dead if we sent a close */
			ಯದಿ (c->flags & CHAN_CLOSE_RCVD) {
				debug2("channel %d: almost dead",
				    c->self);
				ಪ್ರತ್ಯಾಗಮ 1;
			}
		}
	}
	ಯದಿ ((c->flags & CHAN_CLOSE_SENT) &&
	    (c->flags & CHAN_CLOSE_RCVD)) {
		debug2("channel %d: is dead", c->self);
		ಪ್ರತ್ಯಾಗಮ 1;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

/* helper */
ಸ್ಥಿರ ಶೂನ್ಯ
chan_shutdown_write(ಸಂರಚನಾ ssh *ssh, Channel *c)
{
	sshbuf_reset(c->output);
	ಯದಿ (c->type == SSH_CHANNEL_LARVAL)
		ಪ್ರತ್ಯಾಗಮ;
	/* shutdown failure is allowed if write failed already */
	debug2_f("channel %d: (i%d o%d sock %d wfd %d efd %d [%s])",
	    c->self, c->istate, c->ostate, c->sock, c->wfd, c->efd,
	    channel_format_extended_usage(c));
	ಯದಿ (c->sock != -1) {
		ಯದಿ (shutdown(c->sock, SHUT_WR) == -1) {
			debug2_f("channel %d: shutdown() failed for "
			    "fd %d [i%d o%d]: %.100s", c->self, c->sock,
			    c->istate, c->ostate, strerror(errno));
		}
	} ಅನ್ಯಥಾ {
		ಯದಿ (channel_close_fd(ssh, c, &c->wfd) < 0) {
			logit_f("channel %d: close() failed for "
			    "fd %d [i%d o%d]: %.100s", c->self, c->wfd,
			    c->istate, c->ostate, strerror(errno));
		}
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
chan_shutdown_read(ಸಂರಚನಾ ssh *ssh, Channel *c)
{
	ಯದಿ (c->type == SSH_CHANNEL_LARVAL)
		ಪ್ರತ್ಯಾಗಮ;
	debug2_f("channel %d: (i%d o%d sock %d wfd %d efd %d [%s])",
	    c->self, c->istate, c->ostate, c->sock, c->rfd, c->efd,
	    channel_format_extended_usage(c));
	ಯದಿ (c->sock != -1) {
		/*
		 * shutdown(sock, SHUT_READ) may return ENOTCONN if the
		 * write side has been closed already. (bug on Linux)
		 * HP-UX may return ENOTCONN also.
		 */
		ಯದಿ (shutdown(c->sock, SHUT_RD) == -1 && errno != ENOTCONN) {
			error_f("channel %d: shutdown() failed for "
			    "fd %d [i%d o%d]: %.100s", c->self, c->sock,
			    c->istate, c->ostate, strerror(errno));
		}
	} ಅನ್ಯಥಾ {
		ಯದಿ (channel_close_fd(ssh, c, &c->rfd) < 0) {
			logit_f("channel %d: close() failed for "
			    "fd %d [i%d o%d]: %.100s", c->self, c->rfd,
			    c->istate, c->ostate, strerror(errno));
		}
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
chan_shutdown_extended_read(ಸಂರಚನಾ ssh *ssh, Channel *c)
{
	ಯದಿ (c->type == SSH_CHANNEL_LARVAL || c->efd == -1)
		ಪ್ರತ್ಯಾಗಮ;
	ಯದಿ (c->extended_usage != CHAN_EXTENDED_READ &&
	    c->extended_usage != CHAN_EXTENDED_IGNORE)
		ಪ್ರತ್ಯಾಗಮ;
	debug_f("channel %d: (i%d o%d sock %d wfd %d efd %d [%s])",
	    c->self, c->istate, c->ostate, c->sock, c->rfd, c->efd,
	    channel_format_extended_usage(c));
	ಯದಿ (channel_close_fd(ssh, c, &c->efd) < 0) {
		logit_f("channel %d: close() failed for "
		    "extended fd %d [i%d o%d]: %.100s", c->self, c->efd,
		    c->istate, c->ostate, strerror(errno));
	}
}
