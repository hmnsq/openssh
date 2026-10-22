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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/socket.h>

#అన్తర్భావ <errno.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <stdarg.h>

#అన్తర్భావ "ssh2.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "packet.h"
#అన్తర్భావ "channels.h"
#అన్తర్భావ "compat.h"
#అన్తర్భావ "log.h"

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
స్థిర శూన్య	chan_send_eof2(నిర్మాణం ssh *, Channel *);
స్థిర శూన్య	chan_send_eow2(నిర్మాణం ssh *, Channel *);

/* helper */
స్థిర శూన్య	chan_shutdown_write(నిర్మాణం ssh *, Channel *);
స్థిర శూన్య	chan_shutdown_read(నిర్మాణం ssh *, Channel *);
స్థిర శూన్య	chan_shutdown_extended_read(నిర్మాణం ssh *, Channel *);

స్థిర స్థిరరాశి అక్షరం * స్థిరరాశి ostates[] = {
	"open", "drain", "wait_ieof", "closed",
};
స్థిర స్థిరరాశి అక్షరం * స్థిరరాశి istates[] = {
	"open", "drain", "wait_oclose", "closed",
};

స్థిర శూన్య
chan_సమితి_istate(Channel *c, u_int తదుపరి)
{
	ఒకవేళ (c->istate > CHAN_ఆదానం_CLOSED || తదుపరి > CHAN_ఆదానం_CLOSED)
		fatal("chan_set_istate: bad state %d -> %d", c->istate, తదుపరి);
	debug2("channel %d: input %s -> %s", c->self, istates[c->istate],
	    istates[తదుపరి]);
	c->istate = తదుపరి;
}

స్థిర శూన్య
chan_సమితి_ostate(Channel *c, u_int తదుపరి)
{
	ఒకవేళ (c->ostate > CHAN_OUTPUT_CLOSED || తదుపరి > CHAN_OUTPUT_CLOSED)
		fatal("chan_set_ostate: bad state %d -> %d", c->ostate, తదుపరి);
	debug2("channel %d: output %s -> %s", c->self, ostates[c->ostate],
	    ostates[తదుపరి]);
	c->ostate = తదుపరి;
}

శూన్య
chan_read_failed(నిర్మాణం ssh *ssh, Channel *c)
{
	debug2("channel %d: read failed", c->self);
	ఎంపిక (c->istate) {
	స్థితి CHAN_ఆదానం_OPEN:
		chan_shutdown_read(ssh, c);
		chan_సమితి_istate(c, CHAN_ఆదానం_WAIT_DRAIN);
		ఆపు;
	అప్రమేయ:
		error("channel %d: chan_read_failed for istate %d",
		    c->self, c->istate);
		ఆపు;
	}
}

శూన్య
chan_ibuf_ఖాళీలు(నిర్మాణం ssh *ssh, Channel *c)
{
	debug2("channel %d: ibuf empty", c->self);
	ఒకవేళ (sshbuf_len(c->ఆదానం)) {
		error("channel %d: chan_ibuf_empty for non empty buffer",
		    c->self);
		తిరిగి;
	}
	ఎంపిక (c->istate) {
	స్థితి CHAN_ఆదానం_WAIT_DRAIN:
		ఒకవేళ (!(c->flags & (CHAN_CLOSE_పంపిన|CHAN_LOCAL)))
			chan_send_eof2(ssh, c);
		chan_సమితి_istate(c, CHAN_ఆదానం_CLOSED);
		ఆపు;
	అప్రమేయ:
		error("channel %d: chan_ibuf_empty for istate %d",
		    c->self, c->istate);
		ఆపు;
	}
}

శూన్య
chan_obuf_ఖాళీలు(నిర్మాణం ssh *ssh, Channel *c)
{
	debug2("channel %d: obuf empty", c->self);
	ఒకవేళ (sshbuf_len(c->output)) {
		error("channel %d: chan_obuf_empty for non empty buffer",
		    c->self);
		తిరిగి;
	}
	ఎంపిక (c->ostate) {
	స్థితి CHAN_OUTPUT_WAIT_DRAIN:
		chan_shutdown_write(ssh, c);
		chan_సమితి_ostate(c, CHAN_OUTPUT_CLOSED);
		ఆపు;
	అప్రమేయ:
		error("channel %d: internal error: obuf_empty for ostate %d",
		    c->self, c->ostate);
		ఆపు;
	}
}

శూన్య
chan_rcvd_eow(నిర్మాణం ssh *ssh, Channel *c)
{
	debug2("channel %d: rcvd eow", c->self);
	ఎంపిక (c->istate) {
	స్థితి CHAN_ఆదానం_OPEN:
		chan_shutdown_read(ssh, c);
		chan_సమితి_istate(c, CHAN_ఆదానం_CLOSED);
		ఆపు;
	}
}

స్థిర శూన్య
chan_send_eof2(నిర్మాణం ssh *ssh, Channel *c)
{
	పూర్ణాంకం r;

	debug2("channel %d: send eof", c->self);
	ఎంపిక (c->istate) {
	స్థితి CHAN_ఆదానం_WAIT_DRAIN:
		ఒకవేళ (!c->have_remote_id)
			fatal_f("channel %d: no remote_id", c->self);
		ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh, SSH2_సందేశం_CHANNEL_EOF)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send CHANNEL_EOF");
		c->flags |= CHAN_EOF_పంపిన;
		ఆపు;
	అప్రమేయ:
		error("channel %d: cannot send eof for istate %d",
		    c->self, c->istate);
		ఆపు;
	}
}

స్థిర శూన్య
chan_send_close2(నిర్మాణం ssh *ssh, Channel *c)
{
	పూర్ణాంకం r;

	debug2("channel %d: send_close2", c->self);
	ఒకవేళ (c->ostate != CHAN_OUTPUT_CLOSED ||
	    c->istate != CHAN_ఆదానం_CLOSED) {
		error("channel %d: cannot send close for istate/ostate %d/%d",
		    c->self, c->istate, c->ostate);
	} లేకపోతే ఒకవేళ (c->flags & CHAN_CLOSE_పంపిన) {
		error("channel %d: already sent close", c->self);
	} లేకపోతే {
		ఒకవేళ (!c->have_remote_id)
			fatal_f("channel %d: no remote_id", c->self);
		debug2("channel %d: send close for remote id %u", c->self,
		    c->remote_id);
		ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh, SSH2_సందేశం_CHANNEL_CLOSE)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send CHANNEL_EOF");
		c->flags |= CHAN_CLOSE_పంపిన;
	}
}

స్థిర శూన్య
chan_send_eow2(నిర్మాణం ssh *ssh, Channel *c)
{
	పూర్ణాంకం r;

	debug2("channel %d: send eow", c->self);
	ఒకవేళ (c->ostate == CHAN_OUTPUT_CLOSED) {
		error("channel %d: must not sent eow on closed output",
		    c->self);
		తిరిగి;
	}
	ఒకవేళ (!(ssh->compat & SSH_NEW_OPENSSH))
		తిరిగి;
	ఒకవేళ (!c->have_remote_id)
		fatal_f("channel %d: no remote_id", c->self);
	ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh, SSH2_సందేశం_CHANNEL_REQUEST)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "eow@openssh.com")) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send CHANNEL_EOF");
}

/* shared */

శూన్య
chan_rcvd_ieof(నిర్మాణం ssh *ssh, Channel *c)
{
	debug2("channel %d: rcvd eof", c->self);
	c->flags |= CHAN_EOF_RCVD;
	ఒకవేళ (c->ostate == CHAN_OUTPUT_OPEN)
		chan_సమితి_ostate(c, CHAN_OUTPUT_WAIT_DRAIN);
	ఒకవేళ (c->ostate == CHAN_OUTPUT_WAIT_DRAIN &&
	    sshbuf_len(c->output) == 0 &&
	    !CHANNEL_EFD_OUTPUT_చురుకైన(c))
		chan_obuf_ఖాళీలు(ssh, c);
}

శూన్య
chan_rcvd_oclose(నిర్మాణం ssh *ssh, Channel *c)
{
	debug2("channel %d: rcvd close", c->self);
	ఒకవేళ (!(c->flags & CHAN_LOCAL)) {
		ఒకవేళ (c->flags & CHAN_CLOSE_RCVD)
			error("channel %d: protocol error: close rcvd twice",
			    c->self);
		c->flags |= CHAN_CLOSE_RCVD;
	}
	ఒకవేళ (c->type == SSH_CHANNEL_LARVAL) {
		/* tear down larval channels immediately */
		chan_సమితి_ostate(c, CHAN_OUTPUT_CLOSED);
		chan_సమితి_istate(c, CHAN_ఆదానం_CLOSED);
		తిరిగి;
	}
	ఎంపిక (c->ostate) {
	స్థితి CHAN_OUTPUT_OPEN:
		/*
		 * wait until a data from the channel is consumed if a CLOSE
		 * is received
		 */
		chan_సమితి_ostate(c, CHAN_OUTPUT_WAIT_DRAIN);
		ఆపు;
	}
	ఎంపిక (c->istate) {
	స్థితి CHAN_ఆదానం_OPEN:
		chan_shutdown_read(ssh, c);
		chan_shutdown_extended_read(ssh, c);
		chan_సమితి_istate(c, CHAN_ఆదానం_CLOSED);
		ఆపు;
	స్థితి CHAN_ఆదానం_WAIT_DRAIN:
		ఒకవేళ (!(c->flags & CHAN_LOCAL))
			chan_send_eof2(ssh, c);
		chan_shutdown_extended_read(ssh, c);
		chan_సమితి_istate(c, CHAN_ఆదానం_CLOSED);
		ఆపు;
	}
}

శూన్య
chan_write_failed(నిర్మాణం ssh *ssh, Channel *c)
{
	debug2("channel %d: write failed", c->self);
	ఎంపిక (c->ostate) {
	స్థితి CHAN_OUTPUT_OPEN:
	స్థితి CHAN_OUTPUT_WAIT_DRAIN:
		chan_shutdown_write(ssh, c);
		ఒకవేళ (strcmp(c->ctype, "session") == 0)
			chan_send_eow2(ssh, c);
		chan_సమితి_ostate(c, CHAN_OUTPUT_CLOSED);
		ఆపు;
	అప్రమేయ:
		error("channel %d: chan_write_failed for ostate %d",
		    c->self, c->ostate);
		ఆపు;
	}
}

శూన్య
chan_mark_dead(నిర్మాణం ssh *ssh, Channel *c)
{
	c->type = SSH_CHANNEL_ZOMBIE;
}

పూర్ణాంకం
chan_is_dead(నిర్మాణం ssh *ssh, Channel *c, పూర్ణాంకం do_send)
{
	ఒకవేళ (c->type == SSH_CHANNEL_ZOMBIE) {
		debug2("channel %d: zombie", c->self);
		తిరిగి 1;
	}
	ఒకవేళ (c->istate != CHAN_ఆదానం_CLOSED || c->ostate != CHAN_OUTPUT_CLOSED)
		తిరిగి 0;
	ఒకవేళ ((ssh->compat & SSH_BUG_EXTEOF) &&
	    c->extended_usage == CHAN_EXTENDED_WRITE &&
	    c->efd != -1 &&
	    sshbuf_len(c->extended) > 0) {
		debug2("channel %d: active efd: %d len %zu",
		    c->self, c->efd, sshbuf_len(c->extended));
		తిరిగి 0;
	}
	ఒకవేళ (c->flags & CHAN_LOCAL) {
		debug2("channel %d: is dead (local)", c->self);
		తిరిగి 1;
	}
	ఒకవేళ (!(c->flags & CHAN_CLOSE_పంపిన)) {
		ఒకవేళ (do_send) {
			chan_send_close2(ssh, c);
		} లేకపోతే {
			/* channel would be dead if we sent a close */
			ఒకవేళ (c->flags & CHAN_CLOSE_RCVD) {
				debug2("channel %d: almost dead",
				    c->self);
				తిరిగి 1;
			}
		}
	}
	ఒకవేళ ((c->flags & CHAN_CLOSE_పంపిన) &&
	    (c->flags & CHAN_CLOSE_RCVD)) {
		debug2("channel %d: is dead", c->self);
		తిరిగి 1;
	}
	తిరిగి 0;
}

/* helper */
స్థిర శూన్య
chan_shutdown_write(నిర్మాణం ssh *ssh, Channel *c)
{
	sshbuf_reset(c->output);
	ఒకవేళ (c->type == SSH_CHANNEL_LARVAL)
		తిరిగి;
	/* shutdown failure is allowed if write failed already */
	debug2_f("channel %d: (i%d o%d sock %d wfd %d efd %d [%s])",
	    c->self, c->istate, c->ostate, c->sock, c->wfd, c->efd,
	    channel_format_extended_usage(c));
	ఒకవేళ (c->sock != -1) {
		ఒకవేళ (shutdown(c->sock, SHUT_WR) == -1) {
			debug2_f("channel %d: shutdown() failed for "
			    "fd %d [i%d o%d]: %.100s", c->self, c->sock,
			    c->istate, c->ostate, strerror(errno));
		}
	} లేకపోతే {
		ఒకవేళ (channel_close_fd(ssh, c, &c->wfd) < 0) {
			logit_f("channel %d: close() failed for "
			    "fd %d [i%d o%d]: %.100s", c->self, c->wfd,
			    c->istate, c->ostate, strerror(errno));
		}
	}
}

స్థిర శూన్య
chan_shutdown_read(నిర్మాణం ssh *ssh, Channel *c)
{
	ఒకవేళ (c->type == SSH_CHANNEL_LARVAL)
		తిరిగి;
	debug2_f("channel %d: (i%d o%d sock %d wfd %d efd %d [%s])",
	    c->self, c->istate, c->ostate, c->sock, c->rfd, c->efd,
	    channel_format_extended_usage(c));
	ఒకవేళ (c->sock != -1) {
		/*
		 * shutdown(sock, SHUT_READ) may return ENOTCONN if the
		 * write side has been closed already. (bug on Linux)
		 * HP-UX may return ENOTCONN also.
		 */
		ఒకవేళ (shutdown(c->sock, SHUT_RD) == -1 && errno != ENOTCONN) {
			error_f("channel %d: shutdown() failed for "
			    "fd %d [i%d o%d]: %.100s", c->self, c->sock,
			    c->istate, c->ostate, strerror(errno));
		}
	} లేకపోతే {
		ఒకవేళ (channel_close_fd(ssh, c, &c->rfd) < 0) {
			logit_f("channel %d: close() failed for "
			    "fd %d [i%d o%d]: %.100s", c->self, c->rfd,
			    c->istate, c->ostate, strerror(errno));
		}
	}
}

స్థిర శూన్య
chan_shutdown_extended_read(నిర్మాణం ssh *ssh, Channel *c)
{
	ఒకవేళ (c->type == SSH_CHANNEL_LARVAL || c->efd == -1)
		తిరిగి;
	ఒకవేళ (c->extended_usage != CHAN_EXTENDED_READ &&
	    c->extended_usage != CHAN_EXTENDED_IGNORE)
		తిరిగి;
	debug_f("channel %d: (i%d o%d sock %d wfd %d efd %d [%s])",
	    c->self, c->istate, c->ostate, c->sock, c->rfd, c->efd,
	    channel_format_extended_usage(c));
	ఒకవేళ (channel_close_fd(ssh, c, &c->efd) < 0) {
		logit_f("channel %d: close() failed for "
		    "extended fd %d [i%d o%d]: %.100s", c->self, c->efd,
		    c->istate, c->ostate, strerror(errno));
	}
}
