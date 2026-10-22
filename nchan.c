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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/socket.h>

#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>

#ଅନ୍ତର୍ଭାଵ "ssh2.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "packet.h"
#ଅନ୍ତର୍ଭାଵ "channels.h"
#ଅନ୍ତର୍ଭାଵ "compat.h"
#ଅନ୍ତର୍ଭାଵ "log.h"

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
ସ୍ଥିର ଶୂନ୍ୟ	chan_send_eof2(ସଂରଚନା ssh *, Channel *);
ସ୍ଥିର ଶୂନ୍ୟ	chan_send_eow2(ସଂରଚନା ssh *, Channel *);

/* helper */
ସ୍ଥିର ଶୂନ୍ୟ	chan_shutdown_write(ସଂରଚନା ssh *, Channel *);
ସ୍ଥିର ଶୂନ୍ୟ	chan_shutdown_read(ସଂରଚନା ssh *, Channel *);
ସ୍ଥିର ଶୂନ୍ୟ	chan_shutdown_extended_read(ସଂରଚନା ssh *, Channel *);

ସ୍ଥିର ଅଚଳ ଅକ୍ଷର * ଅଚଳ ostates[] = {
	"open", "drain", "wait_ieof", "closed",
};
ସ୍ଥିର ଅଚଳ ଅକ୍ଷର * ଅଚଳ istates[] = {
	"open", "drain", "wait_oclose", "closed",
};

ସ୍ଥିର ଶୂନ୍ୟ
chan_set_istate(Channel *c, u_int next)
{
	ଯଦି (c->istate > CHAN_ନିବେଶ_CLOSED || next > CHAN_ନିବେଶ_CLOSED)
		fatal("chan_set_istate: bad state %d -> %d", c->istate, next);
	debug2("channel %d: input %s -> %s", c->self, istates[c->istate],
	    istates[next]);
	c->istate = next;
}

ସ୍ଥିର ଶୂନ୍ୟ
chan_set_ostate(Channel *c, u_int next)
{
	ଯଦି (c->ostate > CHAN_OUTPUT_CLOSED || next > CHAN_OUTPUT_CLOSED)
		fatal("chan_set_ostate: bad state %d -> %d", c->ostate, next);
	debug2("channel %d: output %s -> %s", c->self, ostates[c->ostate],
	    ostates[next]);
	c->ostate = next;
}

ଶୂନ୍ୟ
chan_read_failed(ସଂରଚନା ssh *ssh, Channel *c)
{
	debug2("channel %d: read failed", c->self);
	ବାଛ (c->istate) {
	ସ୍ଥିତି CHAN_ନିବେଶ_OPEN:
		chan_shutdown_read(ssh, c);
		chan_set_istate(c, CHAN_ନିବେଶ_WAIT_DRAIN);
		ଭାଙ୍ଗ;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		error("channel %d: chan_read_failed for istate %d",
		    c->self, c->istate);
		ଭାଙ୍ଗ;
	}
}

ଶୂନ୍ୟ
chan_ibuf_empty(ସଂରଚନା ssh *ssh, Channel *c)
{
	debug2("channel %d: ibuf empty", c->self);
	ଯଦି (sshbuf_len(c->ନିବେଶ)) {
		error("channel %d: chan_ibuf_empty for non empty buffer",
		    c->self);
		ଫେରନ୍ତୁ;
	}
	ବାଛ (c->istate) {
	ସ୍ଥିତି CHAN_ନିବେଶ_WAIT_DRAIN:
		ଯଦି (!(c->flags & (CHAN_CLOSE_SENT|CHAN_LOCAL)))
			chan_send_eof2(ssh, c);
		chan_set_istate(c, CHAN_ନିବେଶ_CLOSED);
		ଭାଙ୍ଗ;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		error("channel %d: chan_ibuf_empty for istate %d",
		    c->self, c->istate);
		ଭାଙ୍ଗ;
	}
}

ଶୂନ୍ୟ
chan_obuf_empty(ସଂରଚନା ssh *ssh, Channel *c)
{
	debug2("channel %d: obuf empty", c->self);
	ଯଦି (sshbuf_len(c->output)) {
		error("channel %d: chan_obuf_empty for non empty buffer",
		    c->self);
		ଫେରନ୍ତୁ;
	}
	ବାଛ (c->ostate) {
	ସ୍ଥିତି CHAN_OUTPUT_WAIT_DRAIN:
		chan_shutdown_write(ssh, c);
		chan_set_ostate(c, CHAN_OUTPUT_CLOSED);
		ଭାଙ୍ଗ;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		error("channel %d: internal error: obuf_empty for ostate %d",
		    c->self, c->ostate);
		ଭାଙ୍ଗ;
	}
}

ଶୂନ୍ୟ
chan_rcvd_eow(ସଂରଚନା ssh *ssh, Channel *c)
{
	debug2("channel %d: rcvd eow", c->self);
	ବାଛ (c->istate) {
	ସ୍ଥିତି CHAN_ନିବେଶ_OPEN:
		chan_shutdown_read(ssh, c);
		chan_set_istate(c, CHAN_ନିବେଶ_CLOSED);
		ଭାଙ୍ଗ;
	}
}

ସ୍ଥିର ଶୂନ୍ୟ
chan_send_eof2(ସଂରଚନା ssh *ssh, Channel *c)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	debug2("channel %d: send eof", c->self);
	ବାଛ (c->istate) {
	ସ୍ଥିତି CHAN_ନିବେଶ_WAIT_DRAIN:
		ଯଦି (!c->have_remote_id)
			fatal_f("channel %d: no remote_id", c->self);
		ଯଦି ((r = sshpkt_start(ssh, SSH2_ସନ୍ଦେଶ_CHANNEL_EOF)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send CHANNEL_EOF");
		c->flags |= CHAN_EOF_SENT;
		ଭାଙ୍ଗ;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		error("channel %d: cannot send eof for istate %d",
		    c->self, c->istate);
		ଭାଙ୍ଗ;
	}
}

ସ୍ଥିର ଶୂନ୍ୟ
chan_send_close2(ସଂରଚନା ssh *ssh, Channel *c)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	debug2("channel %d: send_close2", c->self);
	ଯଦି (c->ostate != CHAN_OUTPUT_CLOSED ||
	    c->istate != CHAN_ନିବେଶ_CLOSED) {
		error("channel %d: cannot send close for istate/ostate %d/%d",
		    c->self, c->istate, c->ostate);
	} ଅନ୍ୟଥା ଯଦି (c->flags & CHAN_CLOSE_SENT) {
		error("channel %d: already sent close", c->self);
	} ଅନ୍ୟଥା {
		ଯଦି (!c->have_remote_id)
			fatal_f("channel %d: no remote_id", c->self);
		debug2("channel %d: send close for remote id %u", c->self,
		    c->remote_id);
		ଯଦି ((r = sshpkt_start(ssh, SSH2_ସନ୍ଦେଶ_CHANNEL_CLOSE)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send CHANNEL_EOF");
		c->flags |= CHAN_CLOSE_SENT;
	}
}

ସ୍ଥିର ଶୂନ୍ୟ
chan_send_eow2(ସଂରଚନା ssh *ssh, Channel *c)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	debug2("channel %d: send eow", c->self);
	ଯଦି (c->ostate == CHAN_OUTPUT_CLOSED) {
		error("channel %d: must not sent eow on closed output",
		    c->self);
		ଫେରନ୍ତୁ;
	}
	ଯଦି (!(ssh->compat & SSH_NEW_OPENSSH))
		ଫେରନ୍ତୁ;
	ଯଦି (!c->have_remote_id)
		fatal_f("channel %d: no remote_id", c->self);
	ଯଦି ((r = sshpkt_start(ssh, SSH2_ସନ୍ଦେଶ_CHANNEL_REQUEST)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "eow@openssh.com")) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send CHANNEL_EOF");
}

/* shared */

ଶୂନ୍ୟ
chan_rcvd_ieof(ସଂରଚନା ssh *ssh, Channel *c)
{
	debug2("channel %d: rcvd eof", c->self);
	c->flags |= CHAN_EOF_RCVD;
	ଯଦି (c->ostate == CHAN_OUTPUT_OPEN)
		chan_set_ostate(c, CHAN_OUTPUT_WAIT_DRAIN);
	ଯଦି (c->ostate == CHAN_OUTPUT_WAIT_DRAIN &&
	    sshbuf_len(c->output) == 0 &&
	    !CHANNEL_EFD_OUTPUT_ACTIVE(c))
		chan_obuf_empty(ssh, c);
}

ଶୂନ୍ୟ
chan_rcvd_oclose(ସଂରଚନା ssh *ssh, Channel *c)
{
	debug2("channel %d: rcvd close", c->self);
	ଯଦି (!(c->flags & CHAN_LOCAL)) {
		ଯଦି (c->flags & CHAN_CLOSE_RCVD)
			error("channel %d: protocol error: close rcvd twice",
			    c->self);
		c->flags |= CHAN_CLOSE_RCVD;
	}
	ଯଦି (c->type == SSH_CHANNEL_LARVAL) {
		/* tear down larval channels immediately */
		chan_set_ostate(c, CHAN_OUTPUT_CLOSED);
		chan_set_istate(c, CHAN_ନିବେଶ_CLOSED);
		ଫେରନ୍ତୁ;
	}
	ବାଛ (c->ostate) {
	ସ୍ଥିତି CHAN_OUTPUT_OPEN:
		/*
		 * wait until a data from the channel is consumed if a CLOSE
		 * is received
		 */
		chan_set_ostate(c, CHAN_OUTPUT_WAIT_DRAIN);
		ଭାଙ୍ଗ;
	}
	ବାଛ (c->istate) {
	ସ୍ଥିତି CHAN_ନିବେଶ_OPEN:
		chan_shutdown_read(ssh, c);
		chan_shutdown_extended_read(ssh, c);
		chan_set_istate(c, CHAN_ନିବେଶ_CLOSED);
		ଭାଙ୍ଗ;
	ସ୍ଥିତି CHAN_ନିବେଶ_WAIT_DRAIN:
		ଯଦି (!(c->flags & CHAN_LOCAL))
			chan_send_eof2(ssh, c);
		chan_shutdown_extended_read(ssh, c);
		chan_set_istate(c, CHAN_ନିବେଶ_CLOSED);
		ଭାଙ୍ଗ;
	}
}

ଶୂନ୍ୟ
chan_write_failed(ସଂରଚନା ssh *ssh, Channel *c)
{
	debug2("channel %d: write failed", c->self);
	ବାଛ (c->ostate) {
	ସ୍ଥିତି CHAN_OUTPUT_OPEN:
	ସ୍ଥିତି CHAN_OUTPUT_WAIT_DRAIN:
		chan_shutdown_write(ssh, c);
		ଯଦି (strcmp(c->ctype, "session") == 0)
			chan_send_eow2(ssh, c);
		chan_set_ostate(c, CHAN_OUTPUT_CLOSED);
		ଭାଙ୍ଗ;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		error("channel %d: chan_write_failed for ostate %d",
		    c->self, c->ostate);
		ଭାଙ୍ଗ;
	}
}

ଶୂନ୍ୟ
chan_mark_dead(ସଂରଚନା ssh *ssh, Channel *c)
{
	c->type = SSH_CHANNEL_ZOMBIE;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
chan_is_dead(ସଂରଚନା ssh *ssh, Channel *c, ପୂର୍ଣ୍ଣସଂଖ୍ୟା do_send)
{
	ଯଦି (c->type == SSH_CHANNEL_ZOMBIE) {
		debug2("channel %d: zombie", c->self);
		ଫେରନ୍ତୁ 1;
	}
	ଯଦି (c->istate != CHAN_ନିବେଶ_CLOSED || c->ostate != CHAN_OUTPUT_CLOSED)
		ଫେରନ୍ତୁ 0;
	ଯଦି ((ssh->compat & SSH_BUG_EXTEOF) &&
	    c->extended_usage == CHAN_EXTENDED_WRITE &&
	    c->efd != -1 &&
	    sshbuf_len(c->extended) > 0) {
		debug2("channel %d: active efd: %d len %zu",
		    c->self, c->efd, sshbuf_len(c->extended));
		ଫେରନ୍ତୁ 0;
	}
	ଯଦି (c->flags & CHAN_LOCAL) {
		debug2("channel %d: is dead (local)", c->self);
		ଫେରନ୍ତୁ 1;
	}
	ଯଦି (!(c->flags & CHAN_CLOSE_SENT)) {
		ଯଦି (do_send) {
			chan_send_close2(ssh, c);
		} ଅନ୍ୟଥା {
			/* channel would be dead if we sent a close */
			ଯଦି (c->flags & CHAN_CLOSE_RCVD) {
				debug2("channel %d: almost dead",
				    c->self);
				ଫେରନ୍ତୁ 1;
			}
		}
	}
	ଯଦି ((c->flags & CHAN_CLOSE_SENT) &&
	    (c->flags & CHAN_CLOSE_RCVD)) {
		debug2("channel %d: is dead", c->self);
		ଫେରନ୍ତୁ 1;
	}
	ଫେରନ୍ତୁ 0;
}

/* helper */
ସ୍ଥିର ଶୂନ୍ୟ
chan_shutdown_write(ସଂରଚନା ssh *ssh, Channel *c)
{
	sshbuf_reset(c->output);
	ଯଦି (c->type == SSH_CHANNEL_LARVAL)
		ଫେରନ୍ତୁ;
	/* shutdown failure is allowed if write failed already */
	debug2_f("channel %d: (i%d o%d sock %d wfd %d efd %d [%s])",
	    c->self, c->istate, c->ostate, c->sock, c->wfd, c->efd,
	    channel_format_extended_usage(c));
	ଯଦି (c->sock != -1) {
		ଯଦି (shutdown(c->sock, SHUT_WR) == -1) {
			debug2_f("channel %d: shutdown() failed for "
			    "fd %d [i%d o%d]: %.100s", c->self, c->sock,
			    c->istate, c->ostate, strerror(errno));
		}
	} ଅନ୍ୟଥା {
		ଯଦି (channel_close_fd(ssh, c, &c->wfd) < 0) {
			logit_f("channel %d: close() failed for "
			    "fd %d [i%d o%d]: %.100s", c->self, c->wfd,
			    c->istate, c->ostate, strerror(errno));
		}
	}
}

ସ୍ଥିର ଶୂନ୍ୟ
chan_shutdown_read(ସଂରଚନା ssh *ssh, Channel *c)
{
	ଯଦି (c->type == SSH_CHANNEL_LARVAL)
		ଫେରନ୍ତୁ;
	debug2_f("channel %d: (i%d o%d sock %d wfd %d efd %d [%s])",
	    c->self, c->istate, c->ostate, c->sock, c->rfd, c->efd,
	    channel_format_extended_usage(c));
	ଯଦି (c->sock != -1) {
		/*
		 * shutdown(sock, SHUT_READ) may return ENOTCONN if the
		 * write side has been closed already. (bug on Linux)
		 * HP-UX may return ENOTCONN also.
		 */
		ଯଦି (shutdown(c->sock, SHUT_RD) == -1 && errno != ENOTCONN) {
			error_f("channel %d: shutdown() failed for "
			    "fd %d [i%d o%d]: %.100s", c->self, c->sock,
			    c->istate, c->ostate, strerror(errno));
		}
	} ଅନ୍ୟଥା {
		ଯଦି (channel_close_fd(ssh, c, &c->rfd) < 0) {
			logit_f("channel %d: close() failed for "
			    "fd %d [i%d o%d]: %.100s", c->self, c->rfd,
			    c->istate, c->ostate, strerror(errno));
		}
	}
}

ସ୍ଥିର ଶୂନ୍ୟ
chan_shutdown_extended_read(ସଂରଚନା ssh *ssh, Channel *c)
{
	ଯଦି (c->type == SSH_CHANNEL_LARVAL || c->efd == -1)
		ଫେରନ୍ତୁ;
	ଯଦି (c->extended_usage != CHAN_EXTENDED_READ &&
	    c->extended_usage != CHAN_EXTENDED_IGNORE)
		ଫେରନ୍ତୁ;
	debug_f("channel %d: (i%d o%d sock %d wfd %d efd %d [%s])",
	    c->self, c->istate, c->ostate, c->sock, c->rfd, c->efd,
	    channel_format_extended_usage(c));
	ଯଦି (channel_close_fd(ssh, c, &c->efd) < 0) {
		logit_f("channel %d: close() failed for "
		    "extended fd %d [i%d o%d]: %.100s", c->self, c->efd,
		    c->istate, c->ostate, strerror(errno));
	}
}
