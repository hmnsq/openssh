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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/socket.h>

#अन्तर्भाव <errno.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <stdarg.h>

#अन्तर्भाव "ssh2.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "packet.h"
#अन्तर्भाव "channels.h"
#अन्तर्भाव "compat.h"
#अन्तर्भाव "log.h"

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
स्थिर शून्य	chan_send_eof2(संरचना ssh *, Channel *);
स्थिर शून्य	chan_send_eow2(संरचना ssh *, Channel *);

/* helper */
स्थिर शून्य	chan_shutdown_write(संरचना ssh *, Channel *);
स्थिर शून्य	chan_shutdown_read(संरचना ssh *, Channel *);
स्थिर शून्य	chan_shutdown_extended_read(संरचना ssh *, Channel *);

स्थिर ध्रुव वर्ण * ध्रुव ostates[] = {
	"open", "drain", "wait_ieof", "closed",
};
स्थिर ध्रुव वर्ण * ध्रुव istates[] = {
	"open", "drain", "wait_oclose", "closed",
};

स्थिर शून्य
chan_समुच्चयः_istate(Channel *c, u_int अग्र)
{
	यदि (c->istate > CHAN_निवेशः_CLOSED || अग्र > CHAN_निवेशः_CLOSED)
		fatal("chan_set_istate: bad state %d -> %d", c->istate, अग्र);
	debug2("channel %d: input %s -> %s", c->self, istates[c->istate],
	    istates[अग्र]);
	c->istate = अग्र;
}

स्थिर शून्य
chan_समुच्चयः_ostate(Channel *c, u_int अग्र)
{
	यदि (c->ostate > CHAN_OUTPUT_CLOSED || अग्र > CHAN_OUTPUT_CLOSED)
		fatal("chan_set_ostate: bad state %d -> %d", c->ostate, अग्र);
	debug2("channel %d: output %s -> %s", c->self, ostates[c->ostate],
	    ostates[अग्र]);
	c->ostate = अग्र;
}

शून्य
chan_read_failed(संरचना ssh *ssh, Channel *c)
{
	debug2("channel %d: read failed", c->self);
	विकल्प (c->istate) {
	पक्ष CHAN_निवेशः_OPEN:
		chan_shutdown_read(ssh, c);
		chan_समुच्चयः_istate(c, CHAN_निवेशः_WAIT_DRAIN);
		भङ्ग;
	स्वभाव:
		error("channel %d: chan_read_failed for istate %d",
		    c->self, c->istate);
		भङ्ग;
	}
}

शून्य
chan_ibuf_रिक्तानि(संरचना ssh *ssh, Channel *c)
{
	debug2("channel %d: ibuf empty", c->self);
	यदि (sshbuf_len(c->निवेशः)) {
		error("channel %d: chan_ibuf_empty for non empty buffer",
		    c->self);
		प्रत्यागम;
	}
	विकल्प (c->istate) {
	पक्ष CHAN_निवेशः_WAIT_DRAIN:
		यदि (!(c->flags & (CHAN_CLOSE_प्रेषितम्|CHAN_LOCAL)))
			chan_send_eof2(ssh, c);
		chan_समुच्चयः_istate(c, CHAN_निवेशः_CLOSED);
		भङ्ग;
	स्वभाव:
		error("channel %d: chan_ibuf_empty for istate %d",
		    c->self, c->istate);
		भङ्ग;
	}
}

शून्य
chan_obuf_रिक्तानि(संरचना ssh *ssh, Channel *c)
{
	debug2("channel %d: obuf empty", c->self);
	यदि (sshbuf_len(c->output)) {
		error("channel %d: chan_obuf_empty for non empty buffer",
		    c->self);
		प्रत्यागम;
	}
	विकल्प (c->ostate) {
	पक्ष CHAN_OUTPUT_WAIT_DRAIN:
		chan_shutdown_write(ssh, c);
		chan_समुच्चयः_ostate(c, CHAN_OUTPUT_CLOSED);
		भङ्ग;
	स्वभाव:
		error("channel %d: internal error: obuf_empty for ostate %d",
		    c->self, c->ostate);
		भङ्ग;
	}
}

शून्य
chan_rcvd_eow(संरचना ssh *ssh, Channel *c)
{
	debug2("channel %d: rcvd eow", c->self);
	विकल्प (c->istate) {
	पक्ष CHAN_निवेशः_OPEN:
		chan_shutdown_read(ssh, c);
		chan_समुच्चयः_istate(c, CHAN_निवेशः_CLOSED);
		भङ्ग;
	}
}

स्थिर शून्य
chan_send_eof2(संरचना ssh *ssh, Channel *c)
{
	पूर्णाङ्क r;

	debug2("channel %d: send eof", c->self);
	विकल्प (c->istate) {
	पक्ष CHAN_निवेशः_WAIT_DRAIN:
		यदि (!c->have_remote_id)
			fatal_f("channel %d: no remote_id", c->self);
		यदि ((r = sshpkt_start(ssh, SSH2_सन्देशः_CHANNEL_EOF)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send CHANNEL_EOF");
		c->flags |= CHAN_EOF_प्रेषितम्;
		भङ्ग;
	स्वभाव:
		error("channel %d: cannot send eof for istate %d",
		    c->self, c->istate);
		भङ्ग;
	}
}

स्थिर शून्य
chan_send_close2(संरचना ssh *ssh, Channel *c)
{
	पूर्णाङ्क r;

	debug2("channel %d: send_close2", c->self);
	यदि (c->ostate != CHAN_OUTPUT_CLOSED ||
	    c->istate != CHAN_निवेशः_CLOSED) {
		error("channel %d: cannot send close for istate/ostate %d/%d",
		    c->self, c->istate, c->ostate);
	} अन्यथा यदि (c->flags & CHAN_CLOSE_प्रेषितम्) {
		error("channel %d: already sent close", c->self);
	} अन्यथा {
		यदि (!c->have_remote_id)
			fatal_f("channel %d: no remote_id", c->self);
		debug2("channel %d: send close for remote id %u", c->self,
		    c->remote_id);
		यदि ((r = sshpkt_start(ssh, SSH2_सन्देशः_CHANNEL_CLOSE)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send CHANNEL_EOF");
		c->flags |= CHAN_CLOSE_प्रेषितम्;
	}
}

स्थिर शून्य
chan_send_eow2(संरचना ssh *ssh, Channel *c)
{
	पूर्णाङ्क r;

	debug2("channel %d: send eow", c->self);
	यदि (c->ostate == CHAN_OUTPUT_CLOSED) {
		error("channel %d: must not sent eow on closed output",
		    c->self);
		प्रत्यागम;
	}
	यदि (!(ssh->compat & SSH_NEW_OPENSSH))
		प्रत्यागम;
	यदि (!c->have_remote_id)
		fatal_f("channel %d: no remote_id", c->self);
	यदि ((r = sshpkt_start(ssh, SSH2_सन्देशः_CHANNEL_REQUEST)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "eow@openssh.com")) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send CHANNEL_EOF");
}

/* shared */

शून्य
chan_rcvd_ieof(संरचना ssh *ssh, Channel *c)
{
	debug2("channel %d: rcvd eof", c->self);
	c->flags |= CHAN_EOF_RCVD;
	यदि (c->ostate == CHAN_OUTPUT_OPEN)
		chan_समुच्चयः_ostate(c, CHAN_OUTPUT_WAIT_DRAIN);
	यदि (c->ostate == CHAN_OUTPUT_WAIT_DRAIN &&
	    sshbuf_len(c->output) == 0 &&
	    !CHANNEL_EFD_OUTPUT_सक्रिय(c))
		chan_obuf_रिक्तानि(ssh, c);
}

शून्य
chan_rcvd_oclose(संरचना ssh *ssh, Channel *c)
{
	debug2("channel %d: rcvd close", c->self);
	यदि (!(c->flags & CHAN_LOCAL)) {
		यदि (c->flags & CHAN_CLOSE_RCVD)
			error("channel %d: protocol error: close rcvd twice",
			    c->self);
		c->flags |= CHAN_CLOSE_RCVD;
	}
	यदि (c->type == SSH_CHANNEL_LARVAL) {
		/* tear down larval channels immediately */
		chan_समुच्चयः_ostate(c, CHAN_OUTPUT_CLOSED);
		chan_समुच्चयः_istate(c, CHAN_निवेशः_CLOSED);
		प्रत्यागम;
	}
	विकल्प (c->ostate) {
	पक्ष CHAN_OUTPUT_OPEN:
		/*
		 * wait until a data from the channel is consumed if a CLOSE
		 * is received
		 */
		chan_समुच्चयः_ostate(c, CHAN_OUTPUT_WAIT_DRAIN);
		भङ्ग;
	}
	विकल्प (c->istate) {
	पक्ष CHAN_निवेशः_OPEN:
		chan_shutdown_read(ssh, c);
		chan_shutdown_extended_read(ssh, c);
		chan_समुच्चयः_istate(c, CHAN_निवेशः_CLOSED);
		भङ्ग;
	पक्ष CHAN_निवेशः_WAIT_DRAIN:
		यदि (!(c->flags & CHAN_LOCAL))
			chan_send_eof2(ssh, c);
		chan_shutdown_extended_read(ssh, c);
		chan_समुच्चयः_istate(c, CHAN_निवेशः_CLOSED);
		भङ्ग;
	}
}

शून्य
chan_write_failed(संरचना ssh *ssh, Channel *c)
{
	debug2("channel %d: write failed", c->self);
	विकल्प (c->ostate) {
	पक्ष CHAN_OUTPUT_OPEN:
	पक्ष CHAN_OUTPUT_WAIT_DRAIN:
		chan_shutdown_write(ssh, c);
		यदि (वाक्यं_तुलय(c->ctype, "session") == 0)
			chan_send_eow2(ssh, c);
		chan_समुच्चयः_ostate(c, CHAN_OUTPUT_CLOSED);
		भङ्ग;
	स्वभाव:
		error("channel %d: chan_write_failed for ostate %d",
		    c->self, c->ostate);
		भङ्ग;
	}
}

शून्य
chan_mark_dead(संरचना ssh *ssh, Channel *c)
{
	c->type = SSH_CHANNEL_ZOMBIE;
}

पूर्णाङ्क
chan_is_dead(संरचना ssh *ssh, Channel *c, पूर्णाङ्क do_send)
{
	यदि (c->type == SSH_CHANNEL_ZOMBIE) {
		debug2("channel %d: zombie", c->self);
		प्रत्यागम 1;
	}
	यदि (c->istate != CHAN_निवेशः_CLOSED || c->ostate != CHAN_OUTPUT_CLOSED)
		प्रत्यागम 0;
	यदि ((ssh->compat & SSH_BUG_EXTEOF) &&
	    c->extended_usage == CHAN_EXTENDED_WRITE &&
	    c->efd != -1 &&
	    sshbuf_len(c->extended) > 0) {
		debug2("channel %d: active efd: %d len %zu",
		    c->self, c->efd, sshbuf_len(c->extended));
		प्रत्यागम 0;
	}
	यदि (c->flags & CHAN_LOCAL) {
		debug2("channel %d: is dead (local)", c->self);
		प्रत्यागम 1;
	}
	यदि (!(c->flags & CHAN_CLOSE_प्रेषितम्)) {
		यदि (do_send) {
			chan_send_close2(ssh, c);
		} अन्यथा {
			/* channel would be dead if we sent a close */
			यदि (c->flags & CHAN_CLOSE_RCVD) {
				debug2("channel %d: almost dead",
				    c->self);
				प्रत्यागम 1;
			}
		}
	}
	यदि ((c->flags & CHAN_CLOSE_प्रेषितम्) &&
	    (c->flags & CHAN_CLOSE_RCVD)) {
		debug2("channel %d: is dead", c->self);
		प्रत्यागम 1;
	}
	प्रत्यागम 0;
}

/* helper */
स्थिर शून्य
chan_shutdown_write(संरचना ssh *ssh, Channel *c)
{
	sshbuf_reset(c->output);
	यदि (c->type == SSH_CHANNEL_LARVAL)
		प्रत्यागम;
	/* shutdown failure is allowed if write failed already */
	debug2_f("channel %d: (i%d o%d sock %d wfd %d efd %d [%s])",
	    c->self, c->istate, c->ostate, c->sock, c->wfd, c->efd,
	    channel_format_extended_usage(c));
	यदि (c->sock != -1) {
		यदि (shutdown(c->sock, SHUT_WR) == -1) {
			debug2_f("channel %d: shutdown() failed for "
			    "fd %d [i%d o%d]: %.100s", c->self, c->sock,
			    c->istate, c->ostate, strerror(errno));
		}
	} अन्यथा {
		यदि (channel_close_fd(ssh, c, &c->wfd) < 0) {
			logit_f("channel %d: close() failed for "
			    "fd %d [i%d o%d]: %.100s", c->self, c->wfd,
			    c->istate, c->ostate, strerror(errno));
		}
	}
}

स्थिर शून्य
chan_shutdown_read(संरचना ssh *ssh, Channel *c)
{
	यदि (c->type == SSH_CHANNEL_LARVAL)
		प्रत्यागम;
	debug2_f("channel %d: (i%d o%d sock %d wfd %d efd %d [%s])",
	    c->self, c->istate, c->ostate, c->sock, c->rfd, c->efd,
	    channel_format_extended_usage(c));
	यदि (c->sock != -1) {
		/*
		 * shutdown(sock, SHUT_READ) may return ENOTCONN if the
		 * write side has been closed already. (bug on Linux)
		 * HP-UX may return ENOTCONN also.
		 */
		यदि (shutdown(c->sock, SHUT_RD) == -1 && errno != ENOTCONN) {
			error_f("channel %d: shutdown() failed for "
			    "fd %d [i%d o%d]: %.100s", c->self, c->sock,
			    c->istate, c->ostate, strerror(errno));
		}
	} अन्यथा {
		यदि (channel_close_fd(ssh, c, &c->rfd) < 0) {
			logit_f("channel %d: close() failed for "
			    "fd %d [i%d o%d]: %.100s", c->self, c->rfd,
			    c->istate, c->ostate, strerror(errno));
		}
	}
}

स्थिर शून्य
chan_shutdown_extended_read(संरचना ssh *ssh, Channel *c)
{
	यदि (c->type == SSH_CHANNEL_LARVAL || c->efd == -1)
		प्रत्यागम;
	यदि (c->extended_usage != CHAN_EXTENDED_READ &&
	    c->extended_usage != CHAN_EXTENDED_IGNORE)
		प्रत्यागम;
	debug_f("channel %d: (i%d o%d sock %d wfd %d efd %d [%s])",
	    c->self, c->istate, c->ostate, c->sock, c->rfd, c->efd,
	    channel_format_extended_usage(c));
	यदि (channel_close_fd(ssh, c, &c->efd) < 0) {
		logit_f("channel %d: close() failed for "
		    "extended fd %d [i%d o%d]: %.100s", c->self, c->efd,
		    c->istate, c->ostate, strerror(errno));
	}
}
