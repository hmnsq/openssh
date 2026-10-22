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

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <sys/socket.h>

#समावेश <errno.h>
#समावेश <string.h>
#समावेश <stdarg.h>

#समावेश "ssh2.h"
#समावेश "sshbuf.h"
#समावेश "packet.h"
#समावेश "channels.h"
#समावेश "compat.h"
#समावेश "log.h"

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
अटल व्योम	chan_send_eof2(काष्ठा ssh *, Channel *);
अटल व्योम	chan_send_eow2(काष्ठा ssh *, Channel *);

/* helper */
अटल व्योम	chan_shutdown_write(काष्ठा ssh *, Channel *);
अटल व्योम	chan_shutdown_read(काष्ठा ssh *, Channel *);
अटल व्योम	chan_shutdown_extended_read(काष्ठा ssh *, Channel *);

अटल स्थिर अक्षर * स्थिर ostates[] = {
	"open", "drain", "wait_ieof", "closed",
};
अटल स्थिर अक्षर * स्थिर istates[] = {
	"open", "drain", "wait_oclose", "closed",
};

अटल व्योम
chan_set_istate(Channel *c, u_int अग्र)
{
	अगर (c->istate > CHAN_निवेश_CLOSED || अग्र > CHAN_निवेश_CLOSED)
		fatal("chan_set_istate: bad state %d -> %d", c->istate, अग्र);
	debug2("channel %d: input %s -> %s", c->self, istates[c->istate],
	    istates[अग्र]);
	c->istate = अग्र;
}

अटल व्योम
chan_set_ostate(Channel *c, u_int अग्र)
{
	अगर (c->ostate > CHAN_OUTPUT_CLOSED || अग्र > CHAN_OUTPUT_CLOSED)
		fatal("chan_set_ostate: bad state %d -> %d", c->ostate, अग्र);
	debug2("channel %d: output %s -> %s", c->self, ostates[c->ostate],
	    ostates[अग्र]);
	c->ostate = अग्र;
}

व्योम
chan_read_failed(काष्ठा ssh *ssh, Channel *c)
{
	debug2("channel %d: read failed", c->self);
	चयन (c->istate) {
	हाल CHAN_निवेश_OPEN:
		chan_shutdown_read(ssh, c);
		chan_set_istate(c, CHAN_निवेश_WAIT_DRAIN);
		अवरोध;
	शेष:
		error("channel %d: chan_read_failed for istate %d",
		    c->self, c->istate);
		अवरोध;
	}
}

व्योम
chan_ibuf_empty(काष्ठा ssh *ssh, Channel *c)
{
	debug2("channel %d: ibuf empty", c->self);
	अगर (sshbuf_len(c->निवेश)) {
		error("channel %d: chan_ibuf_empty for non empty buffer",
		    c->self);
		वापस;
	}
	चयन (c->istate) {
	हाल CHAN_निवेश_WAIT_DRAIN:
		अगर (!(c->flags & (CHAN_CLOSE_SENT|CHAN_LOCAL)))
			chan_send_eof2(ssh, c);
		chan_set_istate(c, CHAN_निवेश_CLOSED);
		अवरोध;
	शेष:
		error("channel %d: chan_ibuf_empty for istate %d",
		    c->self, c->istate);
		अवरोध;
	}
}

व्योम
chan_obuf_empty(काष्ठा ssh *ssh, Channel *c)
{
	debug2("channel %d: obuf empty", c->self);
	अगर (sshbuf_len(c->output)) {
		error("channel %d: chan_obuf_empty for non empty buffer",
		    c->self);
		वापस;
	}
	चयन (c->ostate) {
	हाल CHAN_OUTPUT_WAIT_DRAIN:
		chan_shutdown_write(ssh, c);
		chan_set_ostate(c, CHAN_OUTPUT_CLOSED);
		अवरोध;
	शेष:
		error("channel %d: internal error: obuf_empty for ostate %d",
		    c->self, c->ostate);
		अवरोध;
	}
}

व्योम
chan_rcvd_eow(काष्ठा ssh *ssh, Channel *c)
{
	debug2("channel %d: rcvd eow", c->self);
	चयन (c->istate) {
	हाल CHAN_निवेश_OPEN:
		chan_shutdown_read(ssh, c);
		chan_set_istate(c, CHAN_निवेश_CLOSED);
		अवरोध;
	}
}

अटल व्योम
chan_send_eof2(काष्ठा ssh *ssh, Channel *c)
{
	पूर्णांक r;

	debug2("channel %d: send eof", c->self);
	चयन (c->istate) {
	हाल CHAN_निवेश_WAIT_DRAIN:
		अगर (!c->have_remote_id)
			fatal_f("channel %d: no remote_id", c->self);
		अगर ((r = sshpkt_start(ssh, SSH2_संदेश_CHANNEL_EOF)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send CHANNEL_EOF");
		c->flags |= CHAN_EOF_SENT;
		अवरोध;
	शेष:
		error("channel %d: cannot send eof for istate %d",
		    c->self, c->istate);
		अवरोध;
	}
}

अटल व्योम
chan_send_close2(काष्ठा ssh *ssh, Channel *c)
{
	पूर्णांक r;

	debug2("channel %d: send_close2", c->self);
	अगर (c->ostate != CHAN_OUTPUT_CLOSED ||
	    c->istate != CHAN_निवेश_CLOSED) {
		error("channel %d: cannot send close for istate/ostate %d/%d",
		    c->self, c->istate, c->ostate);
	} अन्यथा अगर (c->flags & CHAN_CLOSE_SENT) {
		error("channel %d: already sent close", c->self);
	} अन्यथा {
		अगर (!c->have_remote_id)
			fatal_f("channel %d: no remote_id", c->self);
		debug2("channel %d: send close for remote id %u", c->self,
		    c->remote_id);
		अगर ((r = sshpkt_start(ssh, SSH2_संदेश_CHANNEL_CLOSE)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send CHANNEL_EOF");
		c->flags |= CHAN_CLOSE_SENT;
	}
}

अटल व्योम
chan_send_eow2(काष्ठा ssh *ssh, Channel *c)
{
	पूर्णांक r;

	debug2("channel %d: send eow", c->self);
	अगर (c->ostate == CHAN_OUTPUT_CLOSED) {
		error("channel %d: must not sent eow on closed output",
		    c->self);
		वापस;
	}
	अगर (!(ssh->compat & SSH_NEW_OPENSSH))
		वापस;
	अगर (!c->have_remote_id)
		fatal_f("channel %d: no remote_id", c->self);
	अगर ((r = sshpkt_start(ssh, SSH2_संदेश_CHANNEL_REQUEST)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "eow@openssh.com")) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send CHANNEL_EOF");
}

/* shared */

व्योम
chan_rcvd_ieof(काष्ठा ssh *ssh, Channel *c)
{
	debug2("channel %d: rcvd eof", c->self);
	c->flags |= CHAN_EOF_RCVD;
	अगर (c->ostate == CHAN_OUTPUT_OPEN)
		chan_set_ostate(c, CHAN_OUTPUT_WAIT_DRAIN);
	अगर (c->ostate == CHAN_OUTPUT_WAIT_DRAIN &&
	    sshbuf_len(c->output) == 0 &&
	    !CHANNEL_EFD_OUTPUT_ACTIVE(c))
		chan_obuf_empty(ssh, c);
}

व्योम
chan_rcvd_oclose(काष्ठा ssh *ssh, Channel *c)
{
	debug2("channel %d: rcvd close", c->self);
	अगर (!(c->flags & CHAN_LOCAL)) {
		अगर (c->flags & CHAN_CLOSE_RCVD)
			error("channel %d: protocol error: close rcvd twice",
			    c->self);
		c->flags |= CHAN_CLOSE_RCVD;
	}
	अगर (c->type == SSH_CHANNEL_LARVAL) {
		/* tear down larval channels immediately */
		chan_set_ostate(c, CHAN_OUTPUT_CLOSED);
		chan_set_istate(c, CHAN_निवेश_CLOSED);
		वापस;
	}
	चयन (c->ostate) {
	हाल CHAN_OUTPUT_OPEN:
		/*
		 * wait until a data from the channel is consumed if a CLOSE
		 * is received
		 */
		chan_set_ostate(c, CHAN_OUTPUT_WAIT_DRAIN);
		अवरोध;
	}
	चयन (c->istate) {
	हाल CHAN_निवेश_OPEN:
		chan_shutdown_read(ssh, c);
		chan_shutdown_extended_read(ssh, c);
		chan_set_istate(c, CHAN_निवेश_CLOSED);
		अवरोध;
	हाल CHAN_निवेश_WAIT_DRAIN:
		अगर (!(c->flags & CHAN_LOCAL))
			chan_send_eof2(ssh, c);
		chan_shutdown_extended_read(ssh, c);
		chan_set_istate(c, CHAN_निवेश_CLOSED);
		अवरोध;
	}
}

व्योम
chan_write_failed(काष्ठा ssh *ssh, Channel *c)
{
	debug2("channel %d: write failed", c->self);
	चयन (c->ostate) {
	हाल CHAN_OUTPUT_OPEN:
	हाल CHAN_OUTPUT_WAIT_DRAIN:
		chan_shutdown_write(ssh, c);
		अगर (म_भेद(c->ctype, "session") == 0)
			chan_send_eow2(ssh, c);
		chan_set_ostate(c, CHAN_OUTPUT_CLOSED);
		अवरोध;
	शेष:
		error("channel %d: chan_write_failed for ostate %d",
		    c->self, c->ostate);
		अवरोध;
	}
}

व्योम
chan_mark_dead(काष्ठा ssh *ssh, Channel *c)
{
	c->type = SSH_CHANNEL_ZOMBIE;
}

पूर्णांक
chan_is_dead(काष्ठा ssh *ssh, Channel *c, पूर्णांक do_send)
{
	अगर (c->type == SSH_CHANNEL_ZOMBIE) {
		debug2("channel %d: zombie", c->self);
		वापस 1;
	}
	अगर (c->istate != CHAN_निवेश_CLOSED || c->ostate != CHAN_OUTPUT_CLOSED)
		वापस 0;
	अगर ((ssh->compat & SSH_BUG_EXTEOF) &&
	    c->extended_usage == CHAN_EXTENDED_WRITE &&
	    c->efd != -1 &&
	    sshbuf_len(c->extended) > 0) {
		debug2("channel %d: active efd: %d len %zu",
		    c->self, c->efd, sshbuf_len(c->extended));
		वापस 0;
	}
	अगर (c->flags & CHAN_LOCAL) {
		debug2("channel %d: is dead (local)", c->self);
		वापस 1;
	}
	अगर (!(c->flags & CHAN_CLOSE_SENT)) {
		अगर (do_send) {
			chan_send_close2(ssh, c);
		} अन्यथा {
			/* channel would be dead if we sent a close */
			अगर (c->flags & CHAN_CLOSE_RCVD) {
				debug2("channel %d: almost dead",
				    c->self);
				वापस 1;
			}
		}
	}
	अगर ((c->flags & CHAN_CLOSE_SENT) &&
	    (c->flags & CHAN_CLOSE_RCVD)) {
		debug2("channel %d: is dead", c->self);
		वापस 1;
	}
	वापस 0;
}

/* helper */
अटल व्योम
chan_shutdown_write(काष्ठा ssh *ssh, Channel *c)
{
	sshbuf_reset(c->output);
	अगर (c->type == SSH_CHANNEL_LARVAL)
		वापस;
	/* shutdown failure is allowed if write failed already */
	debug2_f("channel %d: (i%d o%d sock %d wfd %d efd %d [%s])",
	    c->self, c->istate, c->ostate, c->sock, c->wfd, c->efd,
	    channel_format_extended_usage(c));
	अगर (c->sock != -1) {
		अगर (shutdown(c->sock, SHUT_WR) == -1) {
			debug2_f("channel %d: shutdown() failed for "
			    "fd %d [i%d o%d]: %.100s", c->self, c->sock,
			    c->istate, c->ostate, म_त्रुटि(त्रुटि_सं));
		}
	} अन्यथा {
		अगर (channel_close_fd(ssh, c, &c->wfd) < 0) {
			logit_f("channel %d: close() failed for "
			    "fd %d [i%d o%d]: %.100s", c->self, c->wfd,
			    c->istate, c->ostate, म_त्रुटि(त्रुटि_सं));
		}
	}
}

अटल व्योम
chan_shutdown_read(काष्ठा ssh *ssh, Channel *c)
{
	अगर (c->type == SSH_CHANNEL_LARVAL)
		वापस;
	debug2_f("channel %d: (i%d o%d sock %d wfd %d efd %d [%s])",
	    c->self, c->istate, c->ostate, c->sock, c->rfd, c->efd,
	    channel_format_extended_usage(c));
	अगर (c->sock != -1) {
		/*
		 * shutdown(sock, SHUT_READ) may return ENOTCONN if the
		 * write side has been closed already. (bug on Linux)
		 * HP-UX may return ENOTCONN also.
		 */
		अगर (shutdown(c->sock, SHUT_RD) == -1 && त्रुटि_सं != ENOTCONN) {
			error_f("channel %d: shutdown() failed for "
			    "fd %d [i%d o%d]: %.100s", c->self, c->sock,
			    c->istate, c->ostate, म_त्रुटि(त्रुटि_सं));
		}
	} अन्यथा {
		अगर (channel_close_fd(ssh, c, &c->rfd) < 0) {
			logit_f("channel %d: close() failed for "
			    "fd %d [i%d o%d]: %.100s", c->self, c->rfd,
			    c->istate, c->ostate, म_त्रुटि(त्रुटि_सं));
		}
	}
}

अटल व्योम
chan_shutdown_extended_read(काष्ठा ssh *ssh, Channel *c)
{
	अगर (c->type == SSH_CHANNEL_LARVAL || c->efd == -1)
		वापस;
	अगर (c->extended_usage != CHAN_EXTENDED_READ &&
	    c->extended_usage != CHAN_EXTENDED_IGNORE)
		वापस;
	debug_f("channel %d: (i%d o%d sock %d wfd %d efd %d [%s])",
	    c->self, c->istate, c->ostate, c->sock, c->rfd, c->efd,
	    channel_format_extended_usage(c));
	अगर (channel_close_fd(ssh, c, &c->efd) < 0) {
		logit_f("channel %d: close() failed for "
		    "extended fd %d [i%d o%d]: %.100s", c->self, c->efd,
		    c->istate, c->ostate, म_त्रुटि(त्रुटि_सं));
	}
}
