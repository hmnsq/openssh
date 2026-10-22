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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <sys/socket.h>

#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <stdarg.h>

#অন্তর্ভাব "ssh2.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "packet.h"
#অন্তর্ভাব "channels.h"
#অন্তর্ভাব "compat.h"
#অন্তর্ভাব "log.h"

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
স্থির শূন্য	chan_send_eof2(কাঠামো ssh *, Channel *);
স্থির শূন্য	chan_send_eow2(কাঠামো ssh *, Channel *);

/* helper */
স্থির শূন্য	chan_shutdown_write(কাঠামো ssh *, Channel *);
স্থির শূন্য	chan_shutdown_read(কাঠামো ssh *, Channel *);
স্থির শূন্য	chan_shutdown_extended_read(কাঠামো ssh *, Channel *);

স্থির ধ্রুবক অক্ষর * ধ্রুবক ostates[] = {
	"open", "drain", "wait_ieof", "closed",
};
স্থির ধ্রুবক অক্ষর * ধ্রুবক istates[] = {
	"open", "drain", "wait_oclose", "closed",
};

স্থির শূন্য
chan_set_istate(Channel *c, u_int পরবর্তী)
{
	যদি (c->istate > CHAN_প্রবেশ_CLOSED || পরবর্তী > CHAN_প্রবেশ_CLOSED)
		fatal("chan_set_istate: bad state %d -> %d", c->istate, পরবর্তী);
	debug2("channel %d: input %s -> %s", c->self, istates[c->istate],
	    istates[পরবর্তী]);
	c->istate = পরবর্তী;
}

স্থির শূন্য
chan_set_ostate(Channel *c, u_int পরবর্তী)
{
	যদি (c->ostate > CHAN_OUTPUT_CLOSED || পরবর্তী > CHAN_OUTPUT_CLOSED)
		fatal("chan_set_ostate: bad state %d -> %d", c->ostate, পরবর্তী);
	debug2("channel %d: output %s -> %s", c->self, ostates[c->ostate],
	    ostates[পরবর্তী]);
	c->ostate = পরবর্তী;
}

শূন্য
chan_read_failed(কাঠামো ssh *ssh, Channel *c)
{
	debug2("channel %d: read failed", c->self);
	নির্বাচন (c->istate) {
	ক্ষেত্র CHAN_প্রবেশ_OPEN:
		chan_shutdown_read(ssh, c);
		chan_set_istate(c, CHAN_প্রবেশ_WAIT_DRAIN);
		বিরতি;
	পূর্বনির্ধারিত:
		error("channel %d: chan_read_failed for istate %d",
		    c->self, c->istate);
		বিরতি;
	}
}

শূন্য
chan_ibuf_empty(কাঠামো ssh *ssh, Channel *c)
{
	debug2("channel %d: ibuf empty", c->self);
	যদি (sshbuf_len(c->প্রবেশ)) {
		error("channel %d: chan_ibuf_empty for non empty buffer",
		    c->self);
		ফেরত;
	}
	নির্বাচন (c->istate) {
	ক্ষেত্র CHAN_প্রবেশ_WAIT_DRAIN:
		যদি (!(c->flags & (CHAN_CLOSE_SENT|CHAN_LOCAL)))
			chan_send_eof2(ssh, c);
		chan_set_istate(c, CHAN_প্রবেশ_CLOSED);
		বিরতি;
	পূর্বনির্ধারিত:
		error("channel %d: chan_ibuf_empty for istate %d",
		    c->self, c->istate);
		বিরতি;
	}
}

শূন্য
chan_obuf_empty(কাঠামো ssh *ssh, Channel *c)
{
	debug2("channel %d: obuf empty", c->self);
	যদি (sshbuf_len(c->output)) {
		error("channel %d: chan_obuf_empty for non empty buffer",
		    c->self);
		ফেরত;
	}
	নির্বাচন (c->ostate) {
	ক্ষেত্র CHAN_OUTPUT_WAIT_DRAIN:
		chan_shutdown_write(ssh, c);
		chan_set_ostate(c, CHAN_OUTPUT_CLOSED);
		বিরতি;
	পূর্বনির্ধারিত:
		error("channel %d: internal error: obuf_empty for ostate %d",
		    c->self, c->ostate);
		বিরতি;
	}
}

শূন্য
chan_rcvd_eow(কাঠামো ssh *ssh, Channel *c)
{
	debug2("channel %d: rcvd eow", c->self);
	নির্বাচন (c->istate) {
	ক্ষেত্র CHAN_প্রবেশ_OPEN:
		chan_shutdown_read(ssh, c);
		chan_set_istate(c, CHAN_প্রবেশ_CLOSED);
		বিরতি;
	}
}

স্থির শূন্য
chan_send_eof2(কাঠামো ssh *ssh, Channel *c)
{
	পূর্ণসংখ্যা r;

	debug2("channel %d: send eof", c->self);
	নির্বাচন (c->istate) {
	ক্ষেত্র CHAN_প্রবেশ_WAIT_DRAIN:
		যদি (!c->have_remote_id)
			fatal_f("channel %d: no remote_id", c->self);
		যদি ((r = sshpkt_start(ssh, SSH2_বার্তা_CHANNEL_EOF)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send CHANNEL_EOF");
		c->flags |= CHAN_EOF_SENT;
		বিরতি;
	পূর্বনির্ধারিত:
		error("channel %d: cannot send eof for istate %d",
		    c->self, c->istate);
		বিরতি;
	}
}

স্থির শূন্য
chan_send_close2(কাঠামো ssh *ssh, Channel *c)
{
	পূর্ণসংখ্যা r;

	debug2("channel %d: send_close2", c->self);
	যদি (c->ostate != CHAN_OUTPUT_CLOSED ||
	    c->istate != CHAN_প্রবেশ_CLOSED) {
		error("channel %d: cannot send close for istate/ostate %d/%d",
		    c->self, c->istate, c->ostate);
	} অন্যথা যদি (c->flags & CHAN_CLOSE_SENT) {
		error("channel %d: already sent close", c->self);
	} অন্যথা {
		যদি (!c->have_remote_id)
			fatal_f("channel %d: no remote_id", c->self);
		debug2("channel %d: send close for remote id %u", c->self,
		    c->remote_id);
		যদি ((r = sshpkt_start(ssh, SSH2_বার্তা_CHANNEL_CLOSE)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send CHANNEL_EOF");
		c->flags |= CHAN_CLOSE_SENT;
	}
}

স্থির শূন্য
chan_send_eow2(কাঠামো ssh *ssh, Channel *c)
{
	পূর্ণসংখ্যা r;

	debug2("channel %d: send eow", c->self);
	যদি (c->ostate == CHAN_OUTPUT_CLOSED) {
		error("channel %d: must not sent eow on closed output",
		    c->self);
		ফেরত;
	}
	যদি (!(ssh->compat & SSH_NEW_OPENSSH))
		ফেরত;
	যদি (!c->have_remote_id)
		fatal_f("channel %d: no remote_id", c->self);
	যদি ((r = sshpkt_start(ssh, SSH2_বার্তা_CHANNEL_REQUEST)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "eow@openssh.com")) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send CHANNEL_EOF");
}

/* shared */

শূন্য
chan_rcvd_ieof(কাঠামো ssh *ssh, Channel *c)
{
	debug2("channel %d: rcvd eof", c->self);
	c->flags |= CHAN_EOF_RCVD;
	যদি (c->ostate == CHAN_OUTPUT_OPEN)
		chan_set_ostate(c, CHAN_OUTPUT_WAIT_DRAIN);
	যদি (c->ostate == CHAN_OUTPUT_WAIT_DRAIN &&
	    sshbuf_len(c->output) == 0 &&
	    !CHANNEL_EFD_OUTPUT_ACTIVE(c))
		chan_obuf_empty(ssh, c);
}

শূন্য
chan_rcvd_oclose(কাঠামো ssh *ssh, Channel *c)
{
	debug2("channel %d: rcvd close", c->self);
	যদি (!(c->flags & CHAN_LOCAL)) {
		যদি (c->flags & CHAN_CLOSE_RCVD)
			error("channel %d: protocol error: close rcvd twice",
			    c->self);
		c->flags |= CHAN_CLOSE_RCVD;
	}
	যদি (c->type == SSH_CHANNEL_LARVAL) {
		/* tear down larval channels immediately */
		chan_set_ostate(c, CHAN_OUTPUT_CLOSED);
		chan_set_istate(c, CHAN_প্রবেশ_CLOSED);
		ফেরত;
	}
	নির্বাচন (c->ostate) {
	ক্ষেত্র CHAN_OUTPUT_OPEN:
		/*
		 * wait until a data from the channel is consumed if a CLOSE
		 * is received
		 */
		chan_set_ostate(c, CHAN_OUTPUT_WAIT_DRAIN);
		বিরতি;
	}
	নির্বাচন (c->istate) {
	ক্ষেত্র CHAN_প্রবেশ_OPEN:
		chan_shutdown_read(ssh, c);
		chan_shutdown_extended_read(ssh, c);
		chan_set_istate(c, CHAN_প্রবেশ_CLOSED);
		বিরতি;
	ক্ষেত্র CHAN_প্রবেশ_WAIT_DRAIN:
		যদি (!(c->flags & CHAN_LOCAL))
			chan_send_eof2(ssh, c);
		chan_shutdown_extended_read(ssh, c);
		chan_set_istate(c, CHAN_প্রবেশ_CLOSED);
		বিরতি;
	}
}

শূন্য
chan_write_failed(কাঠামো ssh *ssh, Channel *c)
{
	debug2("channel %d: write failed", c->self);
	নির্বাচন (c->ostate) {
	ক্ষেত্র CHAN_OUTPUT_OPEN:
	ক্ষেত্র CHAN_OUTPUT_WAIT_DRAIN:
		chan_shutdown_write(ssh, c);
		যদি (strcmp(c->ctype, "session") == 0)
			chan_send_eow2(ssh, c);
		chan_set_ostate(c, CHAN_OUTPUT_CLOSED);
		বিরতি;
	পূর্বনির্ধারিত:
		error("channel %d: chan_write_failed for ostate %d",
		    c->self, c->ostate);
		বিরতি;
	}
}

শূন্য
chan_mark_dead(কাঠামো ssh *ssh, Channel *c)
{
	c->type = SSH_CHANNEL_ZOMBIE;
}

পূর্ণসংখ্যা
chan_is_dead(কাঠামো ssh *ssh, Channel *c, পূর্ণসংখ্যা do_send)
{
	যদি (c->type == SSH_CHANNEL_ZOMBIE) {
		debug2("channel %d: zombie", c->self);
		ফেরত 1;
	}
	যদি (c->istate != CHAN_প্রবেশ_CLOSED || c->ostate != CHAN_OUTPUT_CLOSED)
		ফেরত 0;
	যদি ((ssh->compat & SSH_BUG_EXTEOF) &&
	    c->extended_usage == CHAN_EXTENDED_WRITE &&
	    c->efd != -1 &&
	    sshbuf_len(c->extended) > 0) {
		debug2("channel %d: active efd: %d len %zu",
		    c->self, c->efd, sshbuf_len(c->extended));
		ফেরত 0;
	}
	যদি (c->flags & CHAN_LOCAL) {
		debug2("channel %d: is dead (local)", c->self);
		ফেরত 1;
	}
	যদি (!(c->flags & CHAN_CLOSE_SENT)) {
		যদি (do_send) {
			chan_send_close2(ssh, c);
		} অন্যথা {
			/* channel would be dead if we sent a close */
			যদি (c->flags & CHAN_CLOSE_RCVD) {
				debug2("channel %d: almost dead",
				    c->self);
				ফেরত 1;
			}
		}
	}
	যদি ((c->flags & CHAN_CLOSE_SENT) &&
	    (c->flags & CHAN_CLOSE_RCVD)) {
		debug2("channel %d: is dead", c->self);
		ফেরত 1;
	}
	ফেরত 0;
}

/* helper */
স্থির শূন্য
chan_shutdown_write(কাঠামো ssh *ssh, Channel *c)
{
	sshbuf_reset(c->output);
	যদি (c->type == SSH_CHANNEL_LARVAL)
		ফেরত;
	/* shutdown failure is allowed if write failed already */
	debug2_f("channel %d: (i%d o%d sock %d wfd %d efd %d [%s])",
	    c->self, c->istate, c->ostate, c->sock, c->wfd, c->efd,
	    channel_format_extended_usage(c));
	যদি (c->sock != -1) {
		যদি (shutdown(c->sock, SHUT_WR) == -1) {
			debug2_f("channel %d: shutdown() failed for "
			    "fd %d [i%d o%d]: %.100s", c->self, c->sock,
			    c->istate, c->ostate, strerror(errno));
		}
	} অন্যথা {
		যদি (channel_close_fd(ssh, c, &c->wfd) < 0) {
			logit_f("channel %d: close() failed for "
			    "fd %d [i%d o%d]: %.100s", c->self, c->wfd,
			    c->istate, c->ostate, strerror(errno));
		}
	}
}

স্থির শূন্য
chan_shutdown_read(কাঠামো ssh *ssh, Channel *c)
{
	যদি (c->type == SSH_CHANNEL_LARVAL)
		ফেরত;
	debug2_f("channel %d: (i%d o%d sock %d wfd %d efd %d [%s])",
	    c->self, c->istate, c->ostate, c->sock, c->rfd, c->efd,
	    channel_format_extended_usage(c));
	যদি (c->sock != -1) {
		/*
		 * shutdown(sock, SHUT_READ) may return ENOTCONN if the
		 * write side has been closed already. (bug on Linux)
		 * HP-UX may return ENOTCONN also.
		 */
		যদি (shutdown(c->sock, SHUT_RD) == -1 && errno != ENOTCONN) {
			error_f("channel %d: shutdown() failed for "
			    "fd %d [i%d o%d]: %.100s", c->self, c->sock,
			    c->istate, c->ostate, strerror(errno));
		}
	} অন্যথা {
		যদি (channel_close_fd(ssh, c, &c->rfd) < 0) {
			logit_f("channel %d: close() failed for "
			    "fd %d [i%d o%d]: %.100s", c->self, c->rfd,
			    c->istate, c->ostate, strerror(errno));
		}
	}
}

স্থির শূন্য
chan_shutdown_extended_read(কাঠামো ssh *ssh, Channel *c)
{
	যদি (c->type == SSH_CHANNEL_LARVAL || c->efd == -1)
		ফেরত;
	যদি (c->extended_usage != CHAN_EXTENDED_READ &&
	    c->extended_usage != CHAN_EXTENDED_IGNORE)
		ফেরত;
	debug_f("channel %d: (i%d o%d sock %d wfd %d efd %d [%s])",
	    c->self, c->istate, c->ostate, c->sock, c->rfd, c->efd,
	    channel_format_extended_usage(c));
	যদি (channel_close_fd(ssh, c, &c->efd) < 0) {
		logit_f("channel %d: close() failed for "
		    "extended fd %d [i%d o%d]: %.100s", c->self, c->efd,
		    c->istate, c->ostate, strerror(errno));
	}
}
