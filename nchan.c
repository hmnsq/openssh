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
ಸ್ಥಿರ ಶೂನ್ಯ	chan_send_eof2(ರಚನೆ ssh *, Channel *);
ಸ್ಥಿರ ಶೂನ್ಯ	chan_send_eow2(ರಚನೆ ssh *, Channel *);

/* helper */
ಸ್ಥಿರ ಶೂನ್ಯ	chan_shutdown_write(ರಚನೆ ssh *, Channel *);
ಸ್ಥಿರ ಶೂನ್ಯ	chan_shutdown_read(ರಚನೆ ssh *, Channel *);
ಸ್ಥಿರ ಶೂನ್ಯ	chan_shutdown_extended_read(ರಚನೆ ssh *, Channel *);

ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ * ಸ್ಥಿರಾಂಕ ostates[] = {
	"open", "drain", "wait_ieof", "closed",
};
ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ * ಸ್ಥಿರಾಂಕ istates[] = {
	"open", "drain", "wait_oclose", "closed",
};

ಸ್ಥಿರ ಶೂನ್ಯ
chan_ಗಣ_istate(Channel *c, u_int ಮುಂದಿನ)
{
	ಆದರೆ (c->istate > CHAN_ಒಳಹರಿವು_CLOSED || ಮುಂದಿನ > CHAN_ಒಳಹರಿವು_CLOSED)
		fatal("chan_set_istate: bad state %d -> %d", c->istate, ಮುಂದಿನ);
	debug2("channel %d: input %s -> %s", c->self, istates[c->istate],
	    istates[ಮುಂದಿನ]);
	c->istate = ಮುಂದಿನ;
}

ಸ್ಥಿರ ಶೂನ್ಯ
chan_ಗಣ_ostate(Channel *c, u_int ಮುಂದಿನ)
{
	ಆದರೆ (c->ostate > CHAN_OUTPUT_CLOSED || ಮುಂದಿನ > CHAN_OUTPUT_CLOSED)
		fatal("chan_set_ostate: bad state %d -> %d", c->ostate, ಮುಂದಿನ);
	debug2("channel %d: output %s -> %s", c->self, ostates[c->ostate],
	    ostates[ಮುಂದಿನ]);
	c->ostate = ಮುಂದಿನ;
}

ಶೂನ್ಯ
chan_read_failed(ರಚನೆ ssh *ssh, Channel *c)
{
	debug2("channel %d: read failed", c->self);
	ಆಯ್ಕೆ (c->istate) {
	ಸ್ಥಿತಿ CHAN_ಒಳಹರಿವು_OPEN:
		chan_shutdown_read(ssh, c);
		chan_ಗಣ_istate(c, CHAN_ಒಳಹರಿವು_WAIT_DRAIN);
		ನಿಲ್ಲಿಸು;
	ಪೂರ್ವನಿಯೋಜಿತ:
		error("channel %d: chan_read_failed for istate %d",
		    c->self, c->istate);
		ನಿಲ್ಲಿಸು;
	}
}

ಶೂನ್ಯ
chan_ibuf_ಖಾಲಿಗಳು(ರಚನೆ ssh *ssh, Channel *c)
{
	debug2("channel %d: ibuf empty", c->self);
	ಆದರೆ (sshbuf_len(c->ಒಳಹರಿವು)) {
		error("channel %d: chan_ibuf_empty for non empty buffer",
		    c->self);
		ಹಿಂತಿರುಗಿ;
	}
	ಆಯ್ಕೆ (c->istate) {
	ಸ್ಥಿತಿ CHAN_ಒಳಹರಿವು_WAIT_DRAIN:
		ಆದರೆ (!(c->flags & (CHAN_CLOSE_ಕಳುಹಿಸಿದ|CHAN_LOCAL)))
			chan_send_eof2(ssh, c);
		chan_ಗಣ_istate(c, CHAN_ಒಳಹರಿವು_CLOSED);
		ನಿಲ್ಲಿಸು;
	ಪೂರ್ವನಿಯೋಜಿತ:
		error("channel %d: chan_ibuf_empty for istate %d",
		    c->self, c->istate);
		ನಿಲ್ಲಿಸು;
	}
}

ಶೂನ್ಯ
chan_obuf_ಖಾಲಿಗಳು(ರಚನೆ ssh *ssh, Channel *c)
{
	debug2("channel %d: obuf empty", c->self);
	ಆದರೆ (sshbuf_len(c->output)) {
		error("channel %d: chan_obuf_empty for non empty buffer",
		    c->self);
		ಹಿಂತಿರುಗಿ;
	}
	ಆಯ್ಕೆ (c->ostate) {
	ಸ್ಥಿತಿ CHAN_OUTPUT_WAIT_DRAIN:
		chan_shutdown_write(ssh, c);
		chan_ಗಣ_ostate(c, CHAN_OUTPUT_CLOSED);
		ನಿಲ್ಲಿಸು;
	ಪೂರ್ವನಿಯೋಜಿತ:
		error("channel %d: internal error: obuf_empty for ostate %d",
		    c->self, c->ostate);
		ನಿಲ್ಲಿಸು;
	}
}

ಶೂನ್ಯ
chan_rcvd_eow(ರಚನೆ ssh *ssh, Channel *c)
{
	debug2("channel %d: rcvd eow", c->self);
	ಆಯ್ಕೆ (c->istate) {
	ಸ್ಥಿತಿ CHAN_ಒಳಹರಿವು_OPEN:
		chan_shutdown_read(ssh, c);
		chan_ಗಣ_istate(c, CHAN_ಒಳಹರಿವು_CLOSED);
		ನಿಲ್ಲಿಸು;
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
chan_send_eof2(ರಚನೆ ssh *ssh, Channel *c)
{
	ಪೂರ್ಣಾಂಕ r;

	debug2("channel %d: send eof", c->self);
	ಆಯ್ಕೆ (c->istate) {
	ಸ್ಥಿತಿ CHAN_ಒಳಹರಿವು_WAIT_DRAIN:
		ಆದರೆ (!c->have_remote_id)
			fatal_f("channel %d: no remote_id", c->self);
		ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh, SSH2_ಸಂದೇಶ_CHANNEL_EOF)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send CHANNEL_EOF");
		c->flags |= CHAN_EOF_ಕಳುಹಿಸಿದ;
		ನಿಲ್ಲಿಸು;
	ಪೂರ್ವನಿಯೋಜಿತ:
		error("channel %d: cannot send eof for istate %d",
		    c->self, c->istate);
		ನಿಲ್ಲಿಸು;
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
chan_send_close2(ರಚನೆ ssh *ssh, Channel *c)
{
	ಪೂರ್ಣಾಂಕ r;

	debug2("channel %d: send_close2", c->self);
	ಆದರೆ (c->ostate != CHAN_OUTPUT_CLOSED ||
	    c->istate != CHAN_ಒಳಹರಿವು_CLOSED) {
		error("channel %d: cannot send close for istate/ostate %d/%d",
		    c->self, c->istate, c->ostate);
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (c->flags & CHAN_CLOSE_ಕಳುಹಿಸಿದ) {
		error("channel %d: already sent close", c->self);
	} ಇಲ್ಲದಿದ್ದರೆ {
		ಆದರೆ (!c->have_remote_id)
			fatal_f("channel %d: no remote_id", c->self);
		debug2("channel %d: send close for remote id %u", c->self,
		    c->remote_id);
		ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh, SSH2_ಸಂದೇಶ_CHANNEL_CLOSE)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send CHANNEL_EOF");
		c->flags |= CHAN_CLOSE_ಕಳುಹಿಸಿದ;
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
chan_send_eow2(ರಚನೆ ssh *ssh, Channel *c)
{
	ಪೂರ್ಣಾಂಕ r;

	debug2("channel %d: send eow", c->self);
	ಆದರೆ (c->ostate == CHAN_OUTPUT_CLOSED) {
		error("channel %d: must not sent eow on closed output",
		    c->self);
		ಹಿಂತಿರುಗಿ;
	}
	ಆದರೆ (!(ssh->compat & SSH_NEW_OPENSSH))
		ಹಿಂತಿರುಗಿ;
	ಆದರೆ (!c->have_remote_id)
		fatal_f("channel %d: no remote_id", c->self);
	ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh, SSH2_ಸಂದೇಶ_CHANNEL_REQUEST)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "eow@openssh.com")) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send CHANNEL_EOF");
}

/* shared */

ಶೂನ್ಯ
chan_rcvd_ieof(ರಚನೆ ssh *ssh, Channel *c)
{
	debug2("channel %d: rcvd eof", c->self);
	c->flags |= CHAN_EOF_RCVD;
	ಆದರೆ (c->ostate == CHAN_OUTPUT_OPEN)
		chan_ಗಣ_ostate(c, CHAN_OUTPUT_WAIT_DRAIN);
	ಆದರೆ (c->ostate == CHAN_OUTPUT_WAIT_DRAIN &&
	    sshbuf_len(c->output) == 0 &&
	    !CHANNEL_EFD_OUTPUT_ಸಕ್ರಿಯ(c))
		chan_obuf_ಖಾಲಿಗಳು(ssh, c);
}

ಶೂನ್ಯ
chan_rcvd_oclose(ರಚನೆ ssh *ssh, Channel *c)
{
	debug2("channel %d: rcvd close", c->self);
	ಆದರೆ (!(c->flags & CHAN_LOCAL)) {
		ಆದರೆ (c->flags & CHAN_CLOSE_RCVD)
			error("channel %d: protocol error: close rcvd twice",
			    c->self);
		c->flags |= CHAN_CLOSE_RCVD;
	}
	ಆದರೆ (c->type == SSH_CHANNEL_LARVAL) {
		/* tear down larval channels immediately */
		chan_ಗಣ_ostate(c, CHAN_OUTPUT_CLOSED);
		chan_ಗಣ_istate(c, CHAN_ಒಳಹರಿವು_CLOSED);
		ಹಿಂತಿರುಗಿ;
	}
	ಆಯ್ಕೆ (c->ostate) {
	ಸ್ಥಿತಿ CHAN_OUTPUT_OPEN:
		/*
		 * wait until a data from the channel is consumed if a CLOSE
		 * is received
		 */
		chan_ಗಣ_ostate(c, CHAN_OUTPUT_WAIT_DRAIN);
		ನಿಲ್ಲಿಸು;
	}
	ಆಯ್ಕೆ (c->istate) {
	ಸ್ಥಿತಿ CHAN_ಒಳಹರಿವು_OPEN:
		chan_shutdown_read(ssh, c);
		chan_shutdown_extended_read(ssh, c);
		chan_ಗಣ_istate(c, CHAN_ಒಳಹರಿವು_CLOSED);
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ CHAN_ಒಳಹರಿವು_WAIT_DRAIN:
		ಆದರೆ (!(c->flags & CHAN_LOCAL))
			chan_send_eof2(ssh, c);
		chan_shutdown_extended_read(ssh, c);
		chan_ಗಣ_istate(c, CHAN_ಒಳಹರಿವು_CLOSED);
		ನಿಲ್ಲಿಸು;
	}
}

ಶೂನ್ಯ
chan_write_failed(ರಚನೆ ssh *ssh, Channel *c)
{
	debug2("channel %d: write failed", c->self);
	ಆಯ್ಕೆ (c->ostate) {
	ಸ್ಥಿತಿ CHAN_OUTPUT_OPEN:
	ಸ್ಥಿತಿ CHAN_OUTPUT_WAIT_DRAIN:
		chan_shutdown_write(ssh, c);
		ಆದರೆ (strcmp(c->ctype, "session") == 0)
			chan_send_eow2(ssh, c);
		chan_ಗಣ_ostate(c, CHAN_OUTPUT_CLOSED);
		ನಿಲ್ಲಿಸು;
	ಪೂರ್ವನಿಯೋಜಿತ:
		error("channel %d: chan_write_failed for ostate %d",
		    c->self, c->ostate);
		ನಿಲ್ಲಿಸು;
	}
}

ಶೂನ್ಯ
chan_mark_dead(ರಚನೆ ssh *ssh, Channel *c)
{
	c->type = SSH_CHANNEL_ZOMBIE;
}

ಪೂರ್ಣಾಂಕ
chan_is_dead(ರಚನೆ ssh *ssh, Channel *c, ಪೂರ್ಣಾಂಕ do_send)
{
	ಆದರೆ (c->type == SSH_CHANNEL_ZOMBIE) {
		debug2("channel %d: zombie", c->self);
		ಹಿಂತಿರುಗಿ 1;
	}
	ಆದರೆ (c->istate != CHAN_ಒಳಹರಿವು_CLOSED || c->ostate != CHAN_OUTPUT_CLOSED)
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ ((ssh->compat & SSH_BUG_EXTEOF) &&
	    c->extended_usage == CHAN_EXTENDED_WRITE &&
	    c->efd != -1 &&
	    sshbuf_len(c->extended) > 0) {
		debug2("channel %d: active efd: %d len %zu",
		    c->self, c->efd, sshbuf_len(c->extended));
		ಹಿಂತಿರುಗಿ 0;
	}
	ಆದರೆ (c->flags & CHAN_LOCAL) {
		debug2("channel %d: is dead (local)", c->self);
		ಹಿಂತಿರುಗಿ 1;
	}
	ಆದರೆ (!(c->flags & CHAN_CLOSE_ಕಳುಹಿಸಿದ)) {
		ಆದರೆ (do_send) {
			chan_send_close2(ssh, c);
		} ಇಲ್ಲದಿದ್ದರೆ {
			/* channel would be dead if we sent a close */
			ಆದರೆ (c->flags & CHAN_CLOSE_RCVD) {
				debug2("channel %d: almost dead",
				    c->self);
				ಹಿಂತಿರುಗಿ 1;
			}
		}
	}
	ಆದರೆ ((c->flags & CHAN_CLOSE_ಕಳುಹಿಸಿದ) &&
	    (c->flags & CHAN_CLOSE_RCVD)) {
		debug2("channel %d: is dead", c->self);
		ಹಿಂತಿರುಗಿ 1;
	}
	ಹಿಂತಿರುಗಿ 0;
}

/* helper */
ಸ್ಥಿರ ಶೂನ್ಯ
chan_shutdown_write(ರಚನೆ ssh *ssh, Channel *c)
{
	sshbuf_reset(c->output);
	ಆದರೆ (c->type == SSH_CHANNEL_LARVAL)
		ಹಿಂತಿರುಗಿ;
	/* shutdown failure is allowed if write failed already */
	debug2_f("channel %d: (i%d o%d sock %d wfd %d efd %d [%s])",
	    c->self, c->istate, c->ostate, c->sock, c->wfd, c->efd,
	    channel_format_extended_usage(c));
	ಆದರೆ (c->sock != -1) {
		ಆದರೆ (shutdown(c->sock, SHUT_WR) == -1) {
			debug2_f("channel %d: shutdown() failed for "
			    "fd %d [i%d o%d]: %.100s", c->self, c->sock,
			    c->istate, c->ostate, strerror(errno));
		}
	} ಇಲ್ಲದಿದ್ದರೆ {
		ಆದರೆ (channel_close_fd(ssh, c, &c->wfd) < 0) {
			logit_f("channel %d: close() failed for "
			    "fd %d [i%d o%d]: %.100s", c->self, c->wfd,
			    c->istate, c->ostate, strerror(errno));
		}
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
chan_shutdown_read(ರಚನೆ ssh *ssh, Channel *c)
{
	ಆದರೆ (c->type == SSH_CHANNEL_LARVAL)
		ಹಿಂತಿರುಗಿ;
	debug2_f("channel %d: (i%d o%d sock %d wfd %d efd %d [%s])",
	    c->self, c->istate, c->ostate, c->sock, c->rfd, c->efd,
	    channel_format_extended_usage(c));
	ಆದರೆ (c->sock != -1) {
		/*
		 * shutdown(sock, SHUT_READ) may return ENOTCONN if the
		 * write side has been closed already. (bug on Linux)
		 * HP-UX may return ENOTCONN also.
		 */
		ಆದರೆ (shutdown(c->sock, SHUT_RD) == -1 && errno != ENOTCONN) {
			error_f("channel %d: shutdown() failed for "
			    "fd %d [i%d o%d]: %.100s", c->self, c->sock,
			    c->istate, c->ostate, strerror(errno));
		}
	} ಇಲ್ಲದಿದ್ದರೆ {
		ಆದರೆ (channel_close_fd(ssh, c, &c->rfd) < 0) {
			logit_f("channel %d: close() failed for "
			    "fd %d [i%d o%d]: %.100s", c->self, c->rfd,
			    c->istate, c->ostate, strerror(errno));
		}
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
chan_shutdown_extended_read(ರಚನೆ ssh *ssh, Channel *c)
{
	ಆದರೆ (c->type == SSH_CHANNEL_LARVAL || c->efd == -1)
		ಹಿಂತಿರುಗಿ;
	ಆದರೆ (c->extended_usage != CHAN_EXTENDED_READ &&
	    c->extended_usage != CHAN_EXTENDED_IGNORE)
		ಹಿಂತಿರುಗಿ;
	debug_f("channel %d: (i%d o%d sock %d wfd %d efd %d [%s])",
	    c->self, c->istate, c->ostate, c->sock, c->rfd, c->efd,
	    channel_format_extended_usage(c));
	ಆದರೆ (channel_close_fd(ssh, c, &c->efd) < 0) {
		logit_f("channel %d: close() failed for "
		    "extended fd %d [i%d o%d]: %.100s", c->self, c->efd,
		    c->istate, c->ostate, strerror(errno));
	}
}
