/* $OpenBSD: channels.c,v 1.472 2026/10/15 05:50:32 djm Exp $ */
/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * This file contains functions for generic socket connection forwarding.
 * There is also code for initiating connection forwarding for X11 connections,
 * arbitrary tcp/ip connections, and the authentication agent connection.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 *
 * SSH2 support added by Markus Friedl.
 * Copyright (c) 1999, 2000, 2001, 2002 Markus Friedl.  All rights reserved.
 * Copyright (c) 1999 Dug Song.  All rights reserved.
 * Copyright (c) 1999 Theo de Raadt.  All rights reserved.
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
#समावेश <sys/stat.h>
#समावेश <sys/ioctl.h>
#समावेश <sys/un.h>
#समावेश <sys/socket.h>
#समावेश <sys/queue.h>

#समावेश <netinet/in.h>
#समावेश <arpa/inet.h>

#समावेश <errno.h>
#समावेश <fcntl.h>
#समावेश <limits.h>
#समावेश <netdb.h>
#समावेश <poll.h>
#समावेश <stdarg.h>
#समावेश <stdint.h>
#समावेश <stdio.h>
#समावेश <stdlib.h>
#समावेश <string.h>
#समावेश <termios.h>
#समावेश <unistd.h>

#समावेश "xmalloc.h"
#समावेश "ssh.h"
#समावेश "ssh2.h"
#समावेश "ssherr.h"
#समावेश "sshbuf.h"
#समावेश "packet.h"
#समावेश "log.h"
#समावेश "misc.h"
#समावेश "channels.h"
#समावेश "compat.h"
#समावेश "canohost.h"
#समावेश "pathnames.h"
#समावेश "match.h"

/* XXX remove once we're satisfied there's no lurking bugs */
/* #define DEBUG_CHANNEL_POLL 1 */

/* -- agent forwarding */
#घोषणा	अंक_SOCKS	10

/* -- X11 forwarding */
/* X11 port for display :0 */
#घोषणा X11_BASE_PORT	6000
/* Maximum number of fake X11 displays to try. */
#घोषणा MAX_DISPLAYS  1000

/* Per-channel callback for pre/post IO actions */
प्रकार व्योम chan_fn(काष्ठा ssh *, Channel *c);

/*
 * Data structure for storing which hosts are permitted for forward requests.
 * The local sides of any remote forwards are stored in this array to prevent
 * a corrupt remote server from accessing arbitrary TCP/IP ports on our local
 * network (which might be behind a firewall).
 */
/* XXX: streamlocal wants a path instead of host:port */
/*      Overload host_to_connect; we could just make this match Forward */
/*	XXX - can we use listen_host instead of listen_path? */
काष्ठा permission {
	अक्षर *host_to_connect;		/* Connect to 'host'. */
	पूर्णांक port_to_connect;		/* Connect to 'port'. */
	अक्षर *listen_host;		/* Remote side should listen address. */
	अक्षर *listen_path;		/* Remote side should listen path. */
	पूर्णांक listen_port;		/* Remote side should listen port. */
	Channel *downstream;		/* Downstream mux*/
};

/* Context for non-blocking connects */
काष्ठा channel_connect {
	अक्षर *host;
	पूर्णांक port;
	काष्ठा addrinfo *ai, *aitop;
};

/*
 * Stores the forwarding permission state for a single direction (local or
 * remote).
 */
काष्ठा permission_set {
	/*
	 * List of all local permitted host/port pairs to allow for the
	 * user.
	 */
	u_int अंक_permitted_user;
	काष्ठा permission *permitted_user;

	/*
	 * List of all permitted host/port pairs to allow for the admin.
	 */
	u_int अंक_permitted_admin;
	काष्ठा permission *permitted_admin;

	/*
	 * If this is true, all opens/listens are permitted.  This is the
	 * case on the server on which we have to trust the client anyway,
	 * and the user could do anything after logging in.
	 */
	पूर्णांक all_permitted;
};

/* Used to record timeouts per channel type */
काष्ठा ssh_channel_timeout {
	अक्षर *type_pattern;
	द्विगुन timeout_secs;
};

/* Master structure for channels state */
काष्ठा ssh_channels {
	/*
	 * Pointer to an array containing all allocated channels.  The array
	 * is dynamically extended as needed.
	 */
	Channel **channels;

	/*
	 * Size of the channel array.  All slots of the array must always be
	 * initialized (at least the type field); unused slots set to NULL
	 */
	u_int channels_alloc;

	/*
	 * 'channel_pre*' are called just before IO to add any bits
	 * relevant to channels in the c->io_want bitmasks.
	 *
	 * 'channel_post*': perform any appropriate operations for
	 * channels which have c->io_ready events pending.
	 */
	chan_fn **channel_pre;
	chan_fn **channel_post;

	/* -- tcp forwarding */
	काष्ठा permission_set local_perms;
	काष्ठा permission_set remote_perms;

	/* -- X11 forwarding */

	/* Saved X11 local (client) display. */
	अक्षर *x11_saved_display;

	/* Saved X11 authentication protocol name. */
	अक्षर *x11_saved_proto;

	/* Saved X11 authentication data.  This is the real data. */
	अक्षर *x11_saved_तथ्य;
	u_int x11_saved_तथ्य_len;

	/* Deadline after which all X11 connections are refused */
	द्विगुन x11_refuse_time;

	/*
	 * Fake X11 authentication data.  This is what the server will be
	 * sending us; we should replace any occurrences of this by the
	 * real data.
	 */
	u_char *x11_fake_तथ्य;
	u_int x11_fake_तथ्य_len;

	/* AF_UNSPEC or AF_INET or AF_INET6 */
	पूर्णांक IPv4or6;

	/* Set SO_KEEPALIVE on TCP connections */
	पूर्णांक want_tcp_keepalive;

	/* Channel timeouts by type */
	काष्ठा ssh_channel_timeout *timeouts;
	माप_प्रकार ntimeouts;
	/* Global timeout for all OPEN channels */
	द्विगुन global_deadline;
	द्विगुन lastused;
	/* pattern-lists used to classify channels as bulk */
	अक्षर *bulk_classifier_tty, *bulk_classifier_notty;
	/* Number of active bulk channels (set by channel_handler) */
	u_int nbulk;
};

/* helper */
अटल व्योम port_open_helper(काष्ठा ssh *ssh, Channel *c, अक्षर *rtype);
अटल स्थिर अक्षर *channel_rfwd_bind_host(स्थिर अक्षर *listen_host);

/* non-blocking connect helpers */
अटल पूर्णांक connect_अग्र(काष्ठा ssh *, काष्ठा channel_connect *);
अटल Channel *rdynamic_connect_prepare(काष्ठा ssh *, अक्षर *, अक्षर *);
अटल पूर्णांक rdynamic_connect_finish(काष्ठा ssh *, Channel *);

/* Setup helper */
अटल व्योम channel_handler_init(काष्ठा ssh_channels *sc);

/* -- channel core */

व्योम
channel_init_channels(काष्ठा ssh *ssh)
{
	काष्ठा ssh_channels *sc;

	अगर ((sc = सुस्मृति(1, माप(*sc))) == शून्य)
		fatal_f("allocation failed");
	sc->channels_alloc = 10;
	sc->channels = xcalloc(sc->channels_alloc, माप(*sc->channels));
	sc->IPv4or6 = AF_UNSPEC;
	sc->bulk_classifier_tty = xstrdup(CHANNEL_BULK_TTY);
	sc->bulk_classifier_notty = xstrdup(CHANNEL_BULK_NOTTY);
	channel_handler_init(sc);

	ssh->chanctxt = sc;
}

Channel *
channel_by_id(काष्ठा ssh *ssh, पूर्णांक id)
{
	Channel *c;

	अगर (id < 0 || (u_int)id >= ssh->chanctxt->channels_alloc) {
		logit_f("%d: bad id", id);
		वापस शून्य;
	}
	c = ssh->chanctxt->channels[id];
	अगर (c == शून्य) {
		logit_f("%d: bad id: channel free", id);
		वापस शून्य;
	}
	वापस c;
}

Channel *
channel_by_remote_id(काष्ठा ssh *ssh, u_int remote_id)
{
	Channel *c;
	u_int i;

	क्रम (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		अगर (c != शून्य && c->have_remote_id && c->remote_id == remote_id)
			वापस c;
	}
	वापस शून्य;
}

/*
 * Returns the channel if it is allowed to receive protocol messages.
 * Private channels, like listening sockets, may not receive messages.
 */
Channel *
channel_lookup(काष्ठा ssh *ssh, पूर्णांक id)
{
	Channel *c;

	अगर ((c = channel_by_id(ssh, id)) == शून्य)
		वापस शून्य;

	चयन (c->type) {
	हाल SSH_CHANNEL_X11_OPEN:
	हाल SSH_CHANNEL_LARVAL:
	हाल SSH_CHANNEL_CONNECTING:
	हाल SSH_CHANNEL_DYNAMIC:
	हाल SSH_CHANNEL_RDYNAMIC_OPEN:
	हाल SSH_CHANNEL_RDYNAMIC_FINISH:
	हाल SSH_CHANNEL_OPENING:
	हाल SSH_CHANNEL_OPEN:
	हाल SSH_CHANNEL_ABANDONED:
	हाल SSH_CHANNEL_MUX_PROXY:
		वापस c;
	}
	logit("Non-public channel %d, type %d.", id, c->type);
	वापस शून्य;
}

अटल व्योम
free_connect_ctx(काष्ठा channel_connect *cctx)
{
	मुक्त(cctx->host);
	अगर (cctx->aitop) {
		अगर (cctx->aitop->ai_family == AF_UNIX)
			मुक्त(cctx->aitop);
		अन्यथा
			freeaddrinfo(cctx->aitop);
	}
	स_रखो(cctx, 0, माप(*cctx));
}

अटल व्योम
channel_free_connect_ctx(Channel *c)
{
	अगर (c == शून्य || c->connect_ctx == शून्य)
		वापस;
	free_connect_ctx(c->connect_ctx);
	मुक्त(c->connect_ctx);
	c->connect_ctx = शून्य;
}

/* Enable/disable TCP keepalives for X11 and port-forwarding sockets */
व्योम
channel_set_tcp_keepalives(काष्ठा ssh *ssh, पूर्णांक on)
{
	ssh->chanctxt->want_tcp_keepalive = on;
}

/*
 * Add a timeout for open channels whose c->ctype (or c->xctype if it is set)
 * match type_pattern.
 */
व्योम
channel_add_timeout(काष्ठा ssh *ssh, स्थिर अक्षर *type_pattern,
    द्विगुन timeout_secs)
{
	काष्ठा ssh_channels *sc = ssh->chanctxt;

	अगर (म_भेद(type_pattern, "global") == 0) {
		debug2_f("global channel timeout %f seconds", timeout_secs);
		sc->global_deadline = timeout_secs;
		वापस;
	}
	debug2_f("channel type \"%s\" timeout %f seconds",
	    type_pattern, timeout_secs);
	sc->timeouts = xrecallocarray(sc->timeouts, sc->ntimeouts,
	    sc->ntimeouts + 1, माप(*sc->timeouts));
	sc->timeouts[sc->ntimeouts].type_pattern = xstrdup(type_pattern);
	sc->timeouts[sc->ntimeouts].timeout_secs = timeout_secs;
	sc->ntimeouts++;
}

/* Clears all previously-added channel timeouts */
व्योम
channel_clear_timeouts(काष्ठा ssh *ssh)
{
	काष्ठा ssh_channels *sc = ssh->chanctxt;
	माप_प्रकार i;

	debug3_f("clearing");
	क्रम (i = 0; i < sc->ntimeouts; i++)
		मुक्त(sc->timeouts[i].type_pattern);
	मुक्त(sc->timeouts);
	sc->timeouts = शून्य;
	sc->ntimeouts = 0;
}

अटल द्विगुन
lookup_timeout(काष्ठा ssh *ssh, स्थिर अक्षर *type)
{
	काष्ठा ssh_channels *sc = ssh->chanctxt;
	माप_प्रकार i;

	क्रम (i = 0; i < sc->ntimeouts; i++) {
		अगर (match_pattern(type, sc->timeouts[i].type_pattern))
			वापस sc->timeouts[i].timeout_secs;
	}

	वापस 0;
}

अटल व्योम
channel_classify(काष्ठा ssh *ssh, Channel *c)
{
	काष्ठा ssh_channels *sc = ssh->chanctxt;
	स्थिर अक्षर *type = c->xctype == शून्य ? c->ctype : c->xctype;
	स्थिर पूर्णांक has_tty = c->isatty || c->remote_has_tty;
	स्थिर अक्षर *classifier = has_tty ?
	    sc->bulk_classifier_tty : sc->bulk_classifier_notty;

	c->bulk = type != शून्य && match_pattern_list(type, classifier, 0) == 1;
	debug3("channel %d: classify type \"%s\" (%s) as %s", c->self,
	    type ? type : "(null)", has_tty ? "with TTY" : "no TTY",
	    c->bulk ? "bulk" : "interactive");
}

/*
 * Sets "extended type" of a channel; used by session layer to add additional
 * information about channel types (e.g. shell, login, subsystem) that can then
 * be used to select timeouts and DSCP values.
 * Will reset c->inactive_deadline as a side-effect.
 */
व्योम
channel_set_xtype(काष्ठा ssh *ssh, पूर्णांक id, स्थिर अक्षर *xctype)
{
	काष्ठा ssh_channels *sc = ssh->chanctxt;
	Channel *c;

	अगर ((c = channel_by_id(ssh, id)) == शून्य)
		fatal_f("missing channel %d", id);
	अगर (c->xctype != शून्य)
		मुक्त(c->xctype);
	c->xctype = xstrdup(xctype);
	/* Only override deadline if xctype has a more specific match. */
	द्विगुन xtype_deadline = lookup_timeout(ssh, c->xctype);
	अगर (xtype_deadline != 0)
		c->inactive_deadline = xtype_deadline;
	channel_classify(ssh, c);
	/* report effective timeout: per-channel if set, else global */
	debug2_f("labeled channel %d as %s (inactive timeout %f)", id, xctype,
	    c->inactive_deadline != 0.0 ?
	    c->inactive_deadline : sc->global_deadline);
}

/*
 * update "last used" time on a channel.
 * NB. nothing else should update lastused except to clear it.
 */
अटल व्योम
channel_set_used_time(काष्ठा ssh *ssh, Channel *c)
{
	ssh->chanctxt->lastused = monotime_double();
	अगर (c != शून्य)
		c->lastused = ssh->chanctxt->lastused;
}

/*
 * Get the time at which a channel is due to time out for inactivity.
 * Returns 0 if the channel is not due to time out ever.
 */
अटल द्विगुन
channel_get_expiry(काष्ठा ssh *ssh, Channel *c)
{
	काष्ठा ssh_channels *sc = ssh->chanctxt;
	द्विगुन expiry = 0, channel_expiry;

	अगर (sc->lastused != 0 && sc->global_deadline != 0)
		expiry = sc->lastused + sc->global_deadline;
	अगर (c->lastused != 0 && c->inactive_deadline != 0) {
		channel_expiry = c->lastused + c->inactive_deadline;
		अगर (expiry == 0 || channel_expiry < expiry)
			expiry = channel_expiry;
	}
	वापस expiry;
}

/* Returns non-zero if there is an open, non-interactive channel */
पूर्णांक
channel_has_bulk(काष्ठा ssh *ssh)
{
	वापस ssh->chanctxt != शून्य && ssh->chanctxt->nbulk != 0;
}

/*
 * Register filedescriptors for a channel, used when allocating a channel or
 * when the channel consumer/producer is ready, e.g. shell exec'd
 */
अटल व्योम
channel_register_fds(काष्ठा ssh *ssh, Channel *c, पूर्णांक rfd, पूर्णांक wfd, पूर्णांक efd,
    पूर्णांक extusage, पूर्णांक nonblock, पूर्णांक is_tty)
{
	पूर्णांक val;

	अगर (rfd != -1)
		(व्योम)fcntl(rfd, F_SETFD, FD_CLOEXEC);
	अगर (wfd != -1 && wfd != rfd)
		(व्योम)fcntl(wfd, F_SETFD, FD_CLOEXEC);
	अगर (efd != -1 && efd != rfd && efd != wfd)
		(व्योम)fcntl(efd, F_SETFD, FD_CLOEXEC);

	c->rfd = rfd;
	c->wfd = wfd;
	c->sock = (rfd == wfd) ? rfd : -1;
	c->efd = efd;
	c->extended_usage = extusage;

	अगर ((c->isatty = is_tty) != 0)
		debug2("channel %d: rfd %d isatty", c->self, c->rfd);
#अगर_घोषित _AIX
	/* XXX: Later AIX versions can't push as much data to tty */
	c->wfd_isatty = is_tty || isatty(c->wfd);
#पूर्ण_अगर

	/* enable nonblocking mode */
	c->restore_block = 0;
	अगर (nonblock == CHANNEL_NONBLOCK_STDIO) {
		/*
		 * Special handling for stdio file descriptors: do not set
		 * non-blocking mode if they are TTYs. Otherwise prepare to
		 * restore their blocking state on exit to avoid interfering
		 * with other programs that follow.
		 */
		अगर (rfd != -1 && !isatty(rfd) &&
		    (val = fcntl(rfd, F_GETFL)) != -1 && !(val & O_NONBLOCK)) {
			c->restore_flags[0] = val;
			c->restore_block |= CHANNEL_RESTORE_RFD;
			set_nonblock(rfd);
		}
		अगर (wfd != -1 && !isatty(wfd) &&
		    (val = fcntl(wfd, F_GETFL)) != -1 && !(val & O_NONBLOCK)) {
			c->restore_flags[1] = val;
			c->restore_block |= CHANNEL_RESTORE_WFD;
			set_nonblock(wfd);
		}
		अगर (efd != -1 && !isatty(efd) &&
		    (val = fcntl(efd, F_GETFL)) != -1 && !(val & O_NONBLOCK)) {
			c->restore_flags[2] = val;
			c->restore_block |= CHANNEL_RESTORE_EFD;
			set_nonblock(efd);
		}
	} अन्यथा अगर (nonblock) {
		अगर (rfd != -1)
			set_nonblock(rfd);
		अगर (wfd != -1)
			set_nonblock(wfd);
		अगर (efd != -1)
			set_nonblock(efd);
	}
	/* channel might be entering a larval state, so reset global timeout */
	channel_set_used_time(ssh, शून्य);
	channel_classify(ssh, c);
}

/*
 * Allocate a new channel object and set its type and socket.
 */
Channel *
channel_new(काष्ठा ssh *ssh, अक्षर *ctype, पूर्णांक type, पूर्णांक rfd, पूर्णांक wfd, पूर्णांक efd,
    u_int window, u_int maxpack, पूर्णांक extusage, स्थिर अक्षर *remote_name,
    पूर्णांक nonblock)
{
	काष्ठा ssh_channels *sc = ssh->chanctxt;
	u_int i, found = 0;
	Channel *c;
	पूर्णांक r;

	/* Try to find a free slot where to put the new channel. */
	क्रम (i = 0; i < sc->channels_alloc; i++) {
		अगर (sc->channels[i] == शून्य) {
			/* Found a free slot. */
			found = i;
			अवरोध;
		}
	}
	अगर (i >= sc->channels_alloc) {
		/*
		 * There are no free slots. Take last+1 slot and expand
		 * the array.
		 */
		found = sc->channels_alloc;
		अगर (sc->channels_alloc > CHANNELS_MAX_CHANNELS)
			fatal_f("internal error: channels_alloc %d too big",
			    sc->channels_alloc);
		sc->channels = xrecallocarray(sc->channels, sc->channels_alloc,
		    sc->channels_alloc + 10, माप(*sc->channels));
		sc->channels_alloc += 10;
		debug2("channel: expanding %d", sc->channels_alloc);
	}
	/* Initialize and return new channel. */
	c = sc->channels[found] = xcalloc(1, माप(Channel));
	अगर ((c->निवेश = sshbuf_new()) == शून्य ||
	    (c->output = sshbuf_new()) == शून्य ||
	    (c->extended = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	अगर ((r = sshbuf_set_max_आकार(c->निवेश, CHAN_निवेश_MAX)) != 0)
		fatal_fr(r, "sshbuf_set_max_size");
	c->ostate = CHAN_OUTPUT_OPEN;
	c->istate = CHAN_निवेश_OPEN;
	channel_register_fds(ssh, c, rfd, wfd, efd, extusage, nonblock, 0);
	c->self = found;
	c->type = type;
	c->ctype = ctype;
	c->local_window = window;
	c->local_window_max = window;
	c->local_maxpacket = maxpack;
	c->remote_name = xstrdup(remote_name);
	c->ctl_chan = -1;
	c->delayed = 1;		/* prevent call to channel_post handler */
	c->inactive_deadline = lookup_timeout(ssh, c->ctype);
	TAILQ_INIT(&c->status_confirms);
	channel_classify(ssh, c);
	debug("channel %d: new %s [%s] (inactive timeout: %f)",
	    found, c->ctype, remote_name, c->inactive_deadline != 0.0 ?
	    c->inactive_deadline : sc->global_deadline);
	वापस c;
}

व्योम
channel_set_tty(काष्ठा ssh *ssh, Channel *c)
{
	c->remote_has_tty = 1;
	channel_classify(ssh, c);
}

पूर्णांक
channel_close_fd(काष्ठा ssh *ssh, Channel *c, पूर्णांक *fdp)
{
	पूर्णांक ret, fd = *fdp;

	अगर (fd == -1)
		वापस 0;

	/* restore blocking */
	अगर (*fdp == c->rfd &&
	    (c->restore_block & CHANNEL_RESTORE_RFD) != 0)
		(व्योम)fcntl(*fdp, F_SETFL, c->restore_flags[0]);
	अन्यथा अगर (*fdp == c->wfd &&
	    (c->restore_block & CHANNEL_RESTORE_WFD) != 0)
		(व्योम)fcntl(*fdp, F_SETFL, c->restore_flags[1]);
	अन्यथा अगर (*fdp == c->efd &&
	    (c->restore_block & CHANNEL_RESTORE_EFD) != 0)
		(व्योम)fcntl(*fdp, F_SETFL, c->restore_flags[2]);

	अगर (*fdp == c->rfd) {
		c->io_want &= ~SSH_CHAN_IO_RFD;
		c->io_ready &= ~SSH_CHAN_IO_RFD;
		c->rfd = -1;
		c->pfds[0] = -1;
	}
	अगर (*fdp == c->wfd) {
		c->io_want &= ~SSH_CHAN_IO_WFD;
		c->io_ready &= ~SSH_CHAN_IO_WFD;
		c->wfd = -1;
		c->pfds[1] = -1;
	}
	अगर (*fdp == c->efd) {
		c->io_want &= ~SSH_CHAN_IO_EFD;
		c->io_ready &= ~SSH_CHAN_IO_EFD;
		c->efd = -1;
		c->pfds[2] = -1;
	}
	अगर (*fdp == c->sock) {
		c->io_want &= ~SSH_CHAN_IO_SOCK;
		c->io_ready &= ~SSH_CHAN_IO_SOCK;
		c->sock = -1;
		c->pfds[3] = -1;
	}

	ret = बंद(fd);
	*fdp = -1; /* probably redundant */
	वापस ret;
}

/* Close all channel fd/socket. */
अटल व्योम
channel_close_fds(काष्ठा ssh *ssh, Channel *c)
{
	पूर्णांक sock = c->sock, rfd = c->rfd, wfd = c->wfd, efd = c->efd;

	channel_close_fd(ssh, c, &c->sock);
	अगर (rfd != sock)
		channel_close_fd(ssh, c, &c->rfd);
	अगर (wfd != sock && wfd != rfd)
		channel_close_fd(ssh, c, &c->wfd);
	अगर (efd != sock && efd != rfd && efd != wfd)
		channel_close_fd(ssh, c, &c->efd);
}

अटल व्योम
fwd_perm_clear(काष्ठा permission *perm)
{
	मुक्त(perm->host_to_connect);
	मुक्त(perm->listen_host);
	मुक्त(perm->listen_path);
	स_रखो(perm, 0, माप(*perm));
}

/* Returns an printable name for the specified forwarding permission list */
अटल स्थिर अक्षर *
fwd_ident(पूर्णांक who, पूर्णांक where)
{
	अगर (who == FORWARD_ADM) {
		अगर (where == FORWARD_LOCAL)
			वापस "admin local";
		अन्यथा अगर (where == FORWARD_REMOTE)
			वापस "admin remote";
	} अन्यथा अगर (who == FORWARD_USER) {
		अगर (where == FORWARD_LOCAL)
			वापस "user local";
		अन्यथा अगर (where == FORWARD_REMOTE)
			वापस "user remote";
	}
	fatal("Unknown forward permission list %d/%d", who, where);
}

/* Returns the forwarding permission list for the specified direction */
अटल काष्ठा permission_set *
permission_set_get(काष्ठा ssh *ssh, पूर्णांक where)
{
	काष्ठा ssh_channels *sc = ssh->chanctxt;

	चयन (where) {
	हाल FORWARD_LOCAL:
		वापस &sc->local_perms;
		अवरोध;
	हाल FORWARD_REMOTE:
		वापस &sc->remote_perms;
		अवरोध;
	शेष:
		fatal_f("invalid forwarding direction %d", where);
	}
}

/* Returns pointers to the specified forwarding list and its element count */
अटल व्योम
permission_set_get_array(काष्ठा ssh *ssh, पूर्णांक who, पूर्णांक where,
    काष्ठा permission ***permpp, u_int **npermpp)
{
	काष्ठा permission_set *pset = permission_set_get(ssh, where);

	चयन (who) {
	हाल FORWARD_USER:
		*permpp = &pset->permitted_user;
		*npermpp = &pset->अंक_permitted_user;
		अवरोध;
	हाल FORWARD_ADM:
		*permpp = &pset->permitted_admin;
		*npermpp = &pset->अंक_permitted_admin;
		अवरोध;
	शेष:
		fatal_f("invalid forwarding client %d", who);
	}
}

/* Adds an entry to the specified forwarding list */
अटल पूर्णांक
permission_set_add(काष्ठा ssh *ssh, पूर्णांक who, पूर्णांक where,
    स्थिर अक्षर *host_to_connect, पूर्णांक port_to_connect,
    स्थिर अक्षर *listen_host, स्थिर अक्षर *listen_path, पूर्णांक listen_port,
    Channel *downstream)
{
	काष्ठा permission **permp;
	u_int n, *npermp;

	permission_set_get_array(ssh, who, where, &permp, &npermp);

	अगर (*npermp >= पूर्णांक_उच्च)
		fatal_f("%s overflow", fwd_ident(who, where));

	*permp = xrecallocarray(*permp, *npermp, *npermp + 1, माप(**permp));
	n = (*npermp)++;
#घोषणा MAYBE_DUP(s) ((s == शून्य) ? शून्य : xstrdup(s))
	(*permp)[n].host_to_connect = MAYBE_DUP(host_to_connect);
	(*permp)[n].port_to_connect = port_to_connect;
	(*permp)[n].listen_host = MAYBE_DUP(listen_host);
	(*permp)[n].listen_path = MAYBE_DUP(listen_path);
	(*permp)[n].listen_port = listen_port;
	(*permp)[n].downstream = downstream;
#अघोषित MAYBE_DUP
	वापस (पूर्णांक)n;
}

अटल व्योम
mux_remove_remote_forwardings(काष्ठा ssh *ssh, Channel *c)
{
	काष्ठा ssh_channels *sc = ssh->chanctxt;
	काष्ठा permission_set *pset = &sc->local_perms;
	काष्ठा permission *perm;
	पूर्णांक r;
	u_int i;

	क्रम (i = 0; i < pset->अंक_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		अगर (perm->downstream != c)
			जारी;

		/* cancel on the server, since mux client is gone */
		debug("channel %d: cleanup remote forward for %s:%u",
		    c->self, perm->listen_host, perm->listen_port);
		अगर ((r = sshpkt_start(ssh, SSH2_संदेश_GLOBAL_REQUEST)) != 0 ||
		    (r = sshpkt_put_cstring(ssh,
		    "cancel-tcpip-forward")) != 0 ||
		    (r = sshpkt_put_u8(ssh, 0)) != 0 ||
		    (r = sshpkt_put_cstring(ssh,
		    channel_rfwd_bind_host(perm->listen_host))) != 0 ||
		    (r = sshpkt_put_u32(ssh, perm->listen_port)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0) {
			fatal_fr(r, "channel %i", c->self);
		}
		fwd_perm_clear(perm); /* unregister */
	}
}

/* Free the channel and close its fd/socket. */
व्योम
channel_free(काष्ठा ssh *ssh, Channel *c)
{
	काष्ठा ssh_channels *sc = ssh->chanctxt;
	अक्षर *s;
	u_int i, n;
	Channel *other;
	काष्ठा channel_confirm *cc;

	क्रम (n = 0, i = 0; i < sc->channels_alloc; i++) {
		अगर ((other = sc->channels[i]) == शून्य)
			जारी;
		n++;
		/* detach from mux client and prepare for closing */
		अगर (c->type == SSH_CHANNEL_MUX_CLIENT &&
		    other->type == SSH_CHANNEL_MUX_PROXY &&
		    other->mux_ctx == c) {
			other->mux_ctx = शून्य;
			other->type = SSH_CHANNEL_OPEN;
			other->istate = CHAN_निवेश_CLOSED;
			other->ostate = CHAN_OUTPUT_CLOSED;
		}
	}
	debug("channel %d: free: %s, nchannels %u", c->self,
	    c->remote_name ? c->remote_name : "???", n);

	अगर (c->type == SSH_CHANNEL_MUX_CLIENT) {
		mux_remove_remote_forwardings(ssh, c);
		मुक्त(c->mux_ctx);
		c->mux_ctx = शून्य;
	} अन्यथा अगर (c->type == SSH_CHANNEL_MUX_LISTENER) {
		मुक्त(c->mux_ctx);
		c->mux_ctx = शून्य;
	}

	अगर (log_level_get() >= SYSLOG_LEVEL_DEBUG3) {
		s = channel_open_message(ssh);
		debug3("channel %d: status: %s", c->self, s);
		मुक्त(s);
	}

	channel_close_fds(ssh, c);
	sshbuf_free(c->निवेश);
	sshbuf_free(c->output);
	sshbuf_free(c->extended);
	c->निवेश = c->output = c->extended = शून्य;
	मुक्त(c->remote_name);
	c->remote_name = शून्य;
	मुक्त(c->path);
	c->path = शून्य;
	मुक्त(c->listening_addr);
	c->listening_addr = शून्य;
	मुक्त(c->xctype);
	c->xctype = शून्य;
	channel_free_connect_ctx(c);
	जबतक ((cc = TAILQ_FIRST(&c->status_confirms)) != शून्य) {
		अगर (cc->abandon_cb != शून्य)
			cc->abandon_cb(ssh, c, cc->ctx);
		TAILQ_REMOVE(&c->status_confirms, cc, entry);
		freezero(cc, माप(*cc));
	}
	अगर (c->filter_cleanup != शून्य && c->filter_ctx != शून्य)
		c->filter_cleanup(ssh, c->self, c->filter_ctx);
	sc->channels[c->self] = शून्य;
	freezero(c, माप(*c));
}

व्योम
channel_free_all(काष्ठा ssh *ssh)
{
	u_int i;
	काष्ठा ssh_channels *sc = ssh->chanctxt;

	क्रम (i = 0; i < sc->channels_alloc; i++)
		अगर (sc->channels[i] != शून्य)
			channel_free(ssh, sc->channels[i]);

	मुक्त(sc->channels);
	sc->channels = शून्य;
	sc->channels_alloc = 0;

	मुक्त(sc->x11_saved_display);
	sc->x11_saved_display = शून्य;

	मुक्त(sc->x11_saved_proto);
	sc->x11_saved_proto = शून्य;

	मुक्त(sc->x11_saved_तथ्य);
	sc->x11_saved_तथ्य = शून्य;
	sc->x11_saved_तथ्य_len = 0;

	मुक्त(sc->x11_fake_तथ्य);
	sc->x11_fake_तथ्य = शून्य;
	sc->x11_fake_तथ्य_len = 0;
}

व्योम
channel_free_channels(काष्ठा ssh *ssh)
{
	काष्ठा ssh_channels *sc;

	अगर (ssh == शून्य || ssh->chanctxt == शून्य)
		वापस;
	channel_free_all(ssh);
	channel_clear_permission(ssh, FORWARD_USER, FORWARD_LOCAL);
	channel_clear_permission(ssh, FORWARD_USER, FORWARD_REMOTE);
	channel_clear_permission(ssh, FORWARD_ADM, FORWARD_LOCAL);
	channel_clear_permission(ssh, FORWARD_ADM, FORWARD_REMOTE);
	sc = ssh->chanctxt;
	मुक्त(sc->bulk_classifier_tty);
	मुक्त(sc->bulk_classifier_notty);
	मुक्त(sc->channel_pre);
	मुक्त(sc->channel_post);
	freezero(sc, माप(*sc));
	ssh->chanctxt = शून्य;
}

/*
 * Closes the sockets/fds of all channels.  This is used to close extra file
 * descriptors after a fork.
 */
व्योम
channel_close_all(काष्ठा ssh *ssh)
{
	u_int i;

	क्रम (i = 0; i < ssh->chanctxt->channels_alloc; i++)
		अगर (ssh->chanctxt->channels[i] != शून्य)
			channel_close_fds(ssh, ssh->chanctxt->channels[i]);
}

/*
 * Stop listening to channels.
 */
व्योम
channel_stop_listening(काष्ठा ssh *ssh)
{
	u_int i;
	Channel *c;

	क्रम (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		अगर (c != शून्य) {
			चयन (c->type) {
			हाल SSH_CHANNEL_AUTH_SOCKET:
			हाल SSH_CHANNEL_PORT_LISTENER:
			हाल SSH_CHANNEL_RPORT_LISTENER:
			हाल SSH_CHANNEL_X11_LISTENER:
			हाल SSH_CHANNEL_UNIX_LISTENER:
			हाल SSH_CHANNEL_RUNIX_LISTENER:
				channel_close_fd(ssh, c, &c->sock);
				channel_free(ssh, c);
				अवरोध;
			}
		}
	}
}

/*
 * Returns true if no channel has too much buffered data, and false if one or
 * more channel is overfull.
 */
पूर्णांक
channel_not_very_much_buffered_तथ्य(काष्ठा ssh *ssh)
{
	u_int i;
	u_int maxsize = ssh_packet_get_maxsize(ssh);
	Channel *c;

	क्रम (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		अगर (c == शून्य || c->type != SSH_CHANNEL_OPEN)
			जारी;
		अगर (sshbuf_len(c->output) > maxsize) {
			debug2("channel %d: big output buffer %zu > %u",
			    c->self, sshbuf_len(c->output), maxsize);
			वापस 0;
		}
	}
	वापस 1;
}

/* Returns true if any channel is still open. */
पूर्णांक
channel_still_open(काष्ठा ssh *ssh)
{
	u_int i;
	Channel *c;

	क्रम (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		अगर (c == शून्य)
			जारी;
		चयन (c->type) {
		हाल SSH_CHANNEL_X11_LISTENER:
		हाल SSH_CHANNEL_PORT_LISTENER:
		हाल SSH_CHANNEL_RPORT_LISTENER:
		हाल SSH_CHANNEL_MUX_LISTENER:
		हाल SSH_CHANNEL_CLOSED:
		हाल SSH_CHANNEL_AUTH_SOCKET:
		हाल SSH_CHANNEL_DYNAMIC:
		हाल SSH_CHANNEL_RDYNAMIC_OPEN:
		हाल SSH_CHANNEL_CONNECTING:
		हाल SSH_CHANNEL_ZOMBIE:
		हाल SSH_CHANNEL_ABANDONED:
		हाल SSH_CHANNEL_UNIX_LISTENER:
		हाल SSH_CHANNEL_RUNIX_LISTENER:
			जारी;
		हाल SSH_CHANNEL_LARVAL:
			जारी;
		हाल SSH_CHANNEL_OPENING:
		हाल SSH_CHANNEL_OPEN:
		हाल SSH_CHANNEL_RDYNAMIC_FINISH:
		हाल SSH_CHANNEL_X11_OPEN:
		हाल SSH_CHANNEL_MUX_CLIENT:
		हाल SSH_CHANNEL_MUX_PROXY:
			वापस 1;
		शेष:
			fatal_f("bad channel type %d", c->type);
			/* NOTREACHED */
		}
	}
	वापस 0;
}

/* Returns true if a channel with a TTY is open. */
पूर्णांक
channel_tty_open(काष्ठा ssh *ssh)
{
	u_int i;
	Channel *c;

	क्रम (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		अगर (c == शून्य || c->type != SSH_CHANNEL_OPEN)
			जारी;
		अगर (c->client_tty)
			वापस 1;
	}
	वापस 0;
}

/* Returns the id of an open channel suitable for keepaliving */
पूर्णांक
channel_find_open(काष्ठा ssh *ssh)
{
	u_int i;
	Channel *c;

	क्रम (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		अगर (c == शून्य || !c->have_remote_id)
			जारी;
		चयन (c->type) {
		हाल SSH_CHANNEL_CLOSED:
		हाल SSH_CHANNEL_DYNAMIC:
		हाल SSH_CHANNEL_RDYNAMIC_OPEN:
		हाल SSH_CHANNEL_RDYNAMIC_FINISH:
		हाल SSH_CHANNEL_X11_LISTENER:
		हाल SSH_CHANNEL_PORT_LISTENER:
		हाल SSH_CHANNEL_RPORT_LISTENER:
		हाल SSH_CHANNEL_MUX_LISTENER:
		हाल SSH_CHANNEL_MUX_CLIENT:
		हाल SSH_CHANNEL_MUX_PROXY:
		हाल SSH_CHANNEL_OPENING:
		हाल SSH_CHANNEL_CONNECTING:
		हाल SSH_CHANNEL_ZOMBIE:
		हाल SSH_CHANNEL_ABANDONED:
		हाल SSH_CHANNEL_UNIX_LISTENER:
		हाल SSH_CHANNEL_RUNIX_LISTENER:
			जारी;
		हाल SSH_CHANNEL_LARVAL:
		हाल SSH_CHANNEL_AUTH_SOCKET:
		हाल SSH_CHANNEL_OPEN:
		हाल SSH_CHANNEL_X11_OPEN:
			वापस i;
		शेष:
			fatal_f("bad channel type %d", c->type);
			/* NOTREACHED */
		}
	}
	वापस -1;
}

/* Returns the state of the channel's extended usage flag */
स्थिर अक्षर *
channel_format_extended_usage(स्थिर Channel *c)
{
	अगर (c->efd == -1)
		वापस "closed";

	चयन (c->extended_usage) {
	हाल CHAN_EXTENDED_WRITE:
		वापस "write";
	हाल CHAN_EXTENDED_READ:
		वापस "read";
	हाल CHAN_EXTENDED_IGNORE:
		वापस "ignore";
	शेष:
		वापस "UNKNOWN";
	}
}

अटल अक्षर *
channel_format_status(स्थिर Channel *c)
{
	अक्षर *ret = शून्य;

	xasprintf(&ret, "t%d [%s] %s%u %s%u i%u/%zu o%u/%zu e[%s]/%zu "
	    "fd %d/%d/%d sock %d cc %d %s%u io 0x%02x/0x%02x %s%s",
	    c->type, c->xctype != शून्य ? c->xctype : c->ctype,
	    c->have_remote_id ? "r" : "nr", c->remote_id,
	    c->mux_ctx != शून्य ? "m" : "nm", c->mux_downstream_id,
	    c->istate, sshbuf_len(c->निवेश),
	    c->ostate, sshbuf_len(c->output),
	    channel_format_extended_usage(c), sshbuf_len(c->extended),
	    c->rfd, c->wfd, c->efd, c->sock, c->ctl_chan,
	    c->have_ctl_child_id ? "c" : "nc", c->ctl_child_id,
	    c->io_want, c->io_ready,
	    c->isatty ? "T" : (c->remote_has_tty ? "RT" : ""),
	    c->bulk ? "B" : "I");
	वापस ret;
}

/*
 * Returns a message describing the currently open forwarded connections,
 * suitable for sending to the client.  The message contains crlf pairs for
 * newlines.
 */
अक्षर *
channel_open_message(काष्ठा ssh *ssh)
{
	काष्ठा sshbuf *buf;
	Channel *c;
	u_int i;
	पूर्णांक r;
	अक्षर *cp, *ret;

	अगर ((buf = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new");
	अगर ((r = sshbuf_putf(buf,
	    "The following connections are open:\r\n")) != 0)
		fatal_fr(r, "sshbuf_putf");
	क्रम (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		अगर (c == शून्य)
			जारी;
		चयन (c->type) {
		हाल SSH_CHANNEL_X11_LISTENER:
		हाल SSH_CHANNEL_PORT_LISTENER:
		हाल SSH_CHANNEL_RPORT_LISTENER:
		हाल SSH_CHANNEL_CLOSED:
		हाल SSH_CHANNEL_AUTH_SOCKET:
		हाल SSH_CHANNEL_ZOMBIE:
		हाल SSH_CHANNEL_ABANDONED:
		हाल SSH_CHANNEL_MUX_LISTENER:
		हाल SSH_CHANNEL_UNIX_LISTENER:
		हाल SSH_CHANNEL_RUNIX_LISTENER:
			जारी;
		हाल SSH_CHANNEL_LARVAL:
		हाल SSH_CHANNEL_OPENING:
		हाल SSH_CHANNEL_CONNECTING:
		हाल SSH_CHANNEL_DYNAMIC:
		हाल SSH_CHANNEL_RDYNAMIC_OPEN:
		हाल SSH_CHANNEL_RDYNAMIC_FINISH:
		हाल SSH_CHANNEL_OPEN:
		हाल SSH_CHANNEL_X11_OPEN:
		हाल SSH_CHANNEL_MUX_PROXY:
		हाल SSH_CHANNEL_MUX_CLIENT:
			cp = channel_format_status(c);
			अगर ((r = sshbuf_putf(buf, "  #%d %.300s (%s)\r\n",
			    c->self, c->remote_name, cp)) != 0) {
				मुक्त(cp);
				fatal_fr(r, "sshbuf_putf");
			}
			मुक्त(cp);
			जारी;
		शेष:
			fatal_f("bad channel type %d", c->type);
			/* NOTREACHED */
		}
	}
	अगर ((ret = sshbuf_dup_string(buf)) == शून्य)
		fatal_f("sshbuf_dup_string");
	sshbuf_free(buf);
	वापस ret;
}

व्योम
channel_report_open(काष्ठा ssh *ssh, पूर्णांक level)
{
	अक्षर *खोलो, *oopen, *cp, ident[256];

	sshpkt_fmt_connection_id(ssh, ident, माप(ident));
	do_log2(level, "Connection: %s (pid %ld)", ident, (दीर्घ)getpid());
	खोलो = oopen = channel_open_message(ssh);
	जबतक ((cp = strsep(&खोलो, "\r\n")) != शून्य) {
		अगर (*cp != '\0')
			do_log2(level, "%s", cp);
	}
	मुक्त(oopen);
}

अटल व्योम
open_preamble(काष्ठा ssh *ssh, स्थिर अक्षर *where, Channel *c, स्थिर अक्षर *type)
{
	पूर्णांक r;

	अगर ((r = sshpkt_start(ssh, SSH2_संदेश_CHANNEL_OPEN)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, type)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_window)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0) {
		fatal_r(r, "%s: channel %i: open", where, c->self);
	}
}

व्योम
channel_send_open(काष्ठा ssh *ssh, पूर्णांक id)
{
	Channel *c = channel_lookup(ssh, id);
	पूर्णांक r;

	अगर (c == शून्य) {
		logit("channel_send_open: %d: bad id", id);
		वापस;
	}
	debug2("channel %d: send open", id);
	open_preamble(ssh, __func__, c, c->ctype);
	अगर ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i", c->self);
}

व्योम
channel_request_start(काष्ठा ssh *ssh, पूर्णांक id, स्थिर अक्षर *service,
    पूर्णांक wantconfirm)
{
	Channel *c = channel_lookup(ssh, id);
	पूर्णांक r;

	अगर (c == शून्य) {
		logit_f("%d: unknown channel id", id);
		वापस;
	}
	अगर (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);

	debug2("channel %d: request %s confirm %d", id, service, wantconfirm);
	अगर ((r = sshpkt_start(ssh, SSH2_संदेश_CHANNEL_REQUEST)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, service)) != 0 ||
	    (r = sshpkt_put_u8(ssh, wantconfirm)) != 0) {
		fatal_fr(r, "channel %i", c->self);
	}
}

व्योम
channel_register_status_confirm(काष्ठा ssh *ssh, पूर्णांक id,
    channel_confirm_cb *cb, channel_confirm_abandon_cb *abandon_cb, व्योम *ctx)
{
	काष्ठा channel_confirm *cc;
	Channel *c;

	अगर ((c = channel_lookup(ssh, id)) == शून्य)
		fatal_f("%d: bad id", id);

	cc = xcalloc(1, माप(*cc));
	cc->cb = cb;
	cc->abandon_cb = abandon_cb;
	cc->ctx = ctx;
	TAILQ_INSERT_TAIL(&c->status_confirms, cc, entry);
}

व्योम
channel_register_open_confirm(काष्ठा ssh *ssh, पूर्णांक id,
    channel_open_fn *fn, व्योम *ctx)
{
	Channel *c = channel_lookup(ssh, id);

	अगर (c == शून्य) {
		logit_f("%d: bad id", id);
		वापस;
	}
	c->open_confirm = fn;
	c->open_confirm_ctx = ctx;
}

व्योम
channel_register_cleanup(काष्ठा ssh *ssh, पूर्णांक id,
    channel_callback_fn *fn, पूर्णांक do_close)
{
	Channel *c = channel_by_id(ssh, id);

	अगर (c == शून्य) {
		logit_f("%d: bad id", id);
		वापस;
	}
	c->detach_user = fn;
	c->detach_close = do_close;
}

व्योम
channel_cancel_cleanup(काष्ठा ssh *ssh, पूर्णांक id)
{
	Channel *c = channel_by_id(ssh, id);

	अगर (c == शून्य) {
		logit_f("%d: bad id", id);
		वापस;
	}
	c->detach_user = शून्य;
	c->detach_close = 0;
}

व्योम
channel_register_filter(काष्ठा ssh *ssh, पूर्णांक id, channel_infilter_fn *ifn,
    channel_outfilter_fn *ofn, channel_filter_cleanup_fn *cfn, व्योम *ctx)
{
	Channel *c = channel_lookup(ssh, id);

	अगर (c == शून्य) {
		logit_f("%d: bad id", id);
		वापस;
	}
	c->निवेश_filter = ifn;
	c->output_filter = ofn;
	c->filter_ctx = ctx;
	c->filter_cleanup = cfn;
}

व्योम
channel_set_fds(काष्ठा ssh *ssh, पूर्णांक id, पूर्णांक rfd, पूर्णांक wfd, पूर्णांक efd,
    पूर्णांक extusage, पूर्णांक nonblock, पूर्णांक is_tty, u_int window_max)
{
	Channel *c = channel_lookup(ssh, id);
	पूर्णांक r;

	अगर (c == शून्य || c->type != SSH_CHANNEL_LARVAL)
		fatal("channel_activate for non-larval channel %d.", id);
	अगर (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);

	channel_register_fds(ssh, c, rfd, wfd, efd, extusage, nonblock, is_tty);
	c->type = SSH_CHANNEL_OPEN;
	channel_set_used_time(ssh, c);
	c->local_window = c->local_window_max = window_max;

	अगर ((r = sshpkt_start(ssh, SSH2_संदेश_CHANNEL_WINDOW_ADJUST)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_window)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i", c->self);
}

अटल व्योम
channel_pre_listener(काष्ठा ssh *ssh, Channel *c)
{
	c->io_want = SSH_CHAN_IO_SOCK_R;
}

अटल व्योम
channel_pre_connecting(काष्ठा ssh *ssh, Channel *c)
{
	debug3("channel %d: waiting for connection", c->self);
	c->io_want = SSH_CHAN_IO_SOCK_W;
}

अटल व्योम
channel_pre_open(काष्ठा ssh *ssh, Channel *c)
{
	c->io_want = 0;
	अगर (c->istate == CHAN_निवेश_OPEN &&
	    c->remote_window > 0 &&
	    sshbuf_len(c->निवेश) < c->remote_window &&
	    sshbuf_check_reserve(c->निवेश, CHAN_RBUF) == 0)
		c->io_want |= SSH_CHAN_IO_RFD;
	अगर (c->ostate == CHAN_OUTPUT_OPEN ||
	    c->ostate == CHAN_OUTPUT_WAIT_DRAIN) {
		अगर (sshbuf_len(c->output) > 0) {
			c->io_want |= SSH_CHAN_IO_WFD;
		} अन्यथा अगर (c->ostate == CHAN_OUTPUT_WAIT_DRAIN) {
			अगर (CHANNEL_EFD_OUTPUT_ACTIVE(c))
				debug2("channel %d: "
				    "obuf_empty delayed efd %d/(%zu)", c->self,
				    c->efd, sshbuf_len(c->extended));
			अन्यथा
				chan_obuf_empty(ssh, c);
		}
	}
	/** XXX check close conditions, too */
	अगर (c->efd != -1 && !(c->istate == CHAN_निवेश_CLOSED &&
	    c->ostate == CHAN_OUTPUT_CLOSED)) {
		अगर (c->extended_usage == CHAN_EXTENDED_WRITE &&
		    sshbuf_len(c->extended) > 0)
			c->io_want |= SSH_CHAN_IO_EFD_W;
		अन्यथा अगर (c->efd != -1 && !(c->flags & CHAN_EOF_SENT) &&
		    (c->extended_usage == CHAN_EXTENDED_READ ||
		    c->extended_usage == CHAN_EXTENDED_IGNORE) &&
		    sshbuf_len(c->extended) < c->remote_window)
			c->io_want |= SSH_CHAN_IO_EFD_R;
	}
	/* XXX: What about efd? races? */
}

/*
 * This is a special state for X11 authentication spoofing.  An opened X11
 * connection (when authentication spoofing is being done) remains in this
 * state until the first packet has been completely read.  The authentication
 * data in that packet is then substituted by the real data if it matches the
 * fake data, and the channel is put into normal mode.
 * XXX All this happens at the client side.
 * Returns: 0 = need more data, -1 = wrong cookie, 1 = ok
 */
अटल पूर्णांक
x11_open_helper(काष्ठा ssh *ssh, काष्ठा sshbuf *b)
{
	काष्ठा ssh_channels *sc = ssh->chanctxt;
	u_char *ucp;
	u_int proto_len, तथ्य_len;

	अगर (sc->x11_saved_proto == शून्य) {
		error("X11 forwarding opened before X11 forwarding requested");
		वापस -1;
	}

	/* Is this being called after the refusal deadline? */
	अगर (sc->x11_refuse_time != 0.0 &&
	    monotime_double() >= sc->x11_refuse_time) {
		verbose("Rejected X11 connection after ForwardX11Timeout "
		    "expired");
		वापस -1;
	}

	/* Check if the fixed size part of the packet is in buffer. */
	अगर (sshbuf_len(b) < 12)
		वापस 0;

	/* Parse the lengths of variable-length fields. */
	ucp = sshbuf_mutable_ptr(b);
	अगर (ucp[0] == 0x42) {	/* Byte order MSB first. */
		proto_len = 256 * ucp[6] + ucp[7];
		तथ्य_len = 256 * ucp[8] + ucp[9];
	} अन्यथा अगर (ucp[0] == 0x6c) {	/* Byte order LSB first. */
		proto_len = ucp[6] + 256 * ucp[7];
		तथ्य_len = ucp[8] + 256 * ucp[9];
	} अन्यथा {
		debug2("Initial X11 packet contains bad byte order byte: 0x%x",
		    ucp[0]);
		वापस -1;
	}

	/* Check if the whole packet is in buffer. */
	अगर (sshbuf_len(b) <
	    12 + ((proto_len + 3) & ~3) + ((तथ्य_len + 3) & ~3))
		वापस 0;

	/* Check if authentication protocol matches. */
	अगर (proto_len != म_माप(sc->x11_saved_proto) ||
	    स_भेद(ucp + 12, sc->x11_saved_proto, proto_len) != 0) {
		debug2("X11 connection uses different authentication protocol.");
		वापस -1;
	}
	/* Check if authentication data matches our fake data. */
	अगर (तथ्य_len != sc->x11_fake_तथ्य_len ||
	    timingsafe_bcmp(ucp + 12 + ((proto_len + 3) & ~3),
		sc->x11_fake_तथ्य, sc->x11_fake_तथ्य_len) != 0) {
		debug2("X11 auth data does not match fake data.");
		वापस -1;
	}
	/* Check fake data length */
	अगर (sc->x11_fake_तथ्य_len != sc->x11_saved_तथ्य_len) {
		error("X11 fake_data_len %d != saved_data_len %d",
		    sc->x11_fake_तथ्य_len, sc->x11_saved_तथ्य_len);
		वापस -1;
	}
	/*
	 * Received authentication protocol and data match
	 * our fake data. Substitute the fake data with real
	 * data.
	 */
	स_नकल(ucp + 12 + ((proto_len + 3) & ~3),
	    sc->x11_saved_तथ्य, sc->x11_saved_तथ्य_len);
	वापस 1;
}

व्योम
channel_force_close(काष्ठा ssh *ssh, Channel *c, पूर्णांक abandon)
{
	debug3_f("channel %d: forcibly closing", c->self);
	अगर (c->istate == CHAN_निवेश_OPEN)
		chan_read_failed(ssh, c);
	अगर (c->istate == CHAN_निवेश_WAIT_DRAIN) {
		sshbuf_reset(c->निवेश);
		chan_ibuf_empty(ssh, c);
	}
	अगर (c->ostate == CHAN_OUTPUT_OPEN ||
	    c->ostate == CHAN_OUTPUT_WAIT_DRAIN) {
		sshbuf_reset(c->output);
		chan_write_failed(ssh, c);
	}
	अगर (c->detach_user)
		c->detach_user(ssh, c->self, 1, शून्य);
	अगर (c->efd != -1)
		channel_close_fd(ssh, c, &c->efd);
	अगर (abandon)
		c->type = SSH_CHANNEL_ABANDONED;
	/* exempt from inactivity timeouts */
	c->inactive_deadline = 0;
	c->lastused = 0;
}

अटल व्योम
channel_pre_x11_open(काष्ठा ssh *ssh, Channel *c)
{
	पूर्णांक ret = x11_open_helper(ssh, c->output);

	/* c->force_drain = 1; */

	अगर (ret == 1) {
		c->type = SSH_CHANNEL_OPEN;
		channel_set_used_time(ssh, c);
		channel_pre_open(ssh, c);
	} अन्यथा अगर (ret == -1) {
		logit("X11 connection rejected because of wrong "
		    "authentication.");
		debug2("X11 rejected %d i%d/o%d",
		    c->self, c->istate, c->ostate);
		channel_force_close(ssh, c, 0);
	}
}

अटल व्योम
channel_pre_mux_client(काष्ठा ssh *ssh, Channel *c)
{
	c->io_want = 0;
	अगर (c->istate == CHAN_निवेश_OPEN && !c->mux_pause &&
	    sshbuf_check_reserve(c->निवेश, CHAN_RBUF) == 0)
		c->io_want |= SSH_CHAN_IO_RFD;
	अगर (c->istate == CHAN_निवेश_WAIT_DRAIN) {
		/* clear buffer immediately (discard any partial packet) */
		sshbuf_reset(c->निवेश);
		chan_ibuf_empty(ssh, c);
		/* Start output drain. XXX just kill chan? */
		chan_rcvd_oclose(ssh, c);
	}
	अगर (c->ostate == CHAN_OUTPUT_OPEN ||
	    c->ostate == CHAN_OUTPUT_WAIT_DRAIN) {
		अगर (sshbuf_len(c->output) > 0)
			c->io_want |= SSH_CHAN_IO_WFD;
		अन्यथा अगर (c->ostate == CHAN_OUTPUT_WAIT_DRAIN)
			chan_obuf_empty(ssh, c);
	}
}

अटल अंतरभूत पूर्णांक
socks_decode_error(Channel *c, पूर्णांक status, स्थिर अक्षर *func, स्थिर अक्षर *संदेश)
{
	अगर (status == SSH_ERR_MESSAGE_INCOMPLETE)
		वापस 0;
	अन्यथा {
		debug_r(status, "%s: channel %d: decode %s",
		    func, c->self, संदेश);
		वापस -1;
	}
}

/* try to decode a socks4 header */
अटल पूर्णांक
channel_decode_socks4(Channel *c, काष्ठा sshbuf *निवेश, काष्ठा sshbuf *output)
{
	uint8_t socks_ver, socks_cmd, dest_addr[4];
	uint16_t dest_port;
	अक्षर *user = शून्य, *host = शून्य;
	पूर्णांक success = -1, socks4a = 0, r;
	काष्ठा sshbuf *b = शून्य;

	अगर (sshbuf_len(निवेश) < 9)
		वापस 0;

	/* We may not have a complete message, so work on a dup of the buffer */
	अगर ((b = sshbuf_fromb(निवेश)) == शून्य)
		fatal_f("sshbuf_fromb failed");

	debug2("channel %d: decode socks4", c->self);
	अगर ((r = sshbuf_get_u8(b, &socks_ver)) != 0 ||
	    (r = sshbuf_get_u8(b, &socks_cmd)) != 0 ||
	    (r = sshbuf_get_u16(b, &dest_port)) != 0 ||
	    (r = sshbuf_get(b, &dest_addr, माप(dest_addr))) != 0 ||
	    (r = sshbuf_get_nulterminated_string(b, 1024, &user, शून्य)) != 0) {
		success = socks_decode_error(c, r, __func__, "header");
		जाओ out;
	}

	/* Is this a SOCKS4A request? (indicated by an address of 0.0.0.x) */
	अगर (dest_addr[0] == 0 && dest_addr[1] == 0 &&
	    dest_addr[2] == 0 && dest_addr[3] != 0) {
		/* If so, then the hostname follows, also nul-terminated */
		अगर ((r = sshbuf_get_nulterminated_string(b, 1024,
		    &host, शून्य)) != 0) {
			success = socks_decode_error(c, r, __func__, "host");
			जाओ out;
		}
		socks4a = 1;
	} अन्यथा {
		/* Plain SOCKS4 passes an IPv4 binary address; reconstruct */
		xasprintf(&host, "%d.%d.%d.%d",
		    dest_addr[0], dest_addr[1], dest_addr[2], dest_addr[3]);
	}

	/* We have a complete SOCKS4 message; consume it from input */
	अगर ((r = sshbuf_consume_upto_child(निवेश, b)) != 0)
		fatal_fr(r, "channel %d: consume", c->self);

	/* Handle the request */
	debug2("channel %d: %s: user=\"%s\" command=%d destination=[%s]:%d",
	    c->self, socks4a ? "SOCKS4A" : "SOCKS4", user, (पूर्णांक)socks_cmd,
	    host, dest_port);
	अगर (socks_cmd != 1) {
		debug("channel %d: cannot handle %s command 0x%02x",
		    c->self, socks4a ? "SOCKS4A" : "SOCKS4", socks_cmd);
		जाओ out;
	}
	मुक्त(c->path);
	c->path = host;
	host = शून्य; /* transferred */
	c->host_port = dest_port;

	/* Reply to the SOCKS4 client */
	अगर ((r = sshbuf_put_u8(output, 0)) != 0 ||	/* vn: 0 for reply */
	    (r = sshbuf_put_u8(output, 90)) != 0 ||	/* cd: req granted */
	    (r = sshbuf_put_u16(output, 0)) != 0 ||	/* port: ignored */
	    (r = sshbuf_put_u32(output, ntohl(INADDR_ANY))) != 0) /* ignored */
		fatal_fr(r, "channel %d: compose reply", c->self);

	/* success */
	success = 1;
 out:
	sshbuf_free(b);
	मुक्त(user);
	मुक्त(host);
	वापस success;
}

/* try to decode a socks5 header */
#घोषणा SSH_SOCKS5_AUTHDONE	0x1000
#घोषणा SSH_SOCKS5_NOAUTH	0x00
#घोषणा SSH_SOCKS5_IPV4		0x01
#घोषणा SSH_SOCKS5_DOMAIN	0x03
#घोषणा SSH_SOCKS5_IPV6		0x04
#घोषणा SSH_SOCKS5_CONNECT	0x01
#घोषणा SSH_SOCKS5_SUCCESS	0x00

/*
 * Handles SOCKS5 authentication. Note 'b' must be a dup of 'input'
 * Returns 0 on insufficient queued date, 1 on authentication success or
 * -1 on error.
 */
अटल पूर्णांक
channel_socks5_check_auth(Channel *c, काष्ठा sshbuf *b, काष्ठा sshbuf *निवेश,
    काष्ठा sshbuf *output)
{
	uint8_t socks_ver;
	uint8_t nmethods, method;
	पूर्णांक r;
	u_int i, found;

	/* format: ver | nmethods | methods */
	अगर ((r = sshbuf_get_u8(b, &socks_ver)) != 0)
		वापस socks_decode_error(c, r, __func__, "version");
	अगर (socks_ver != 5) /* shouldn't happen; checked by caller^2 */
		fatal_fr(r, "channel %d: internal error: not socks5", c->self);
	अगर ((r = sshbuf_get_u8(b, &nmethods)) != 0)
		वापस socks_decode_error(c, r, __func__, "methods");
	क्रम (found = i = 0; i < nmethods; i++) {
		अगर ((r = sshbuf_get_u8(b, &method)) != 0)
			वापस socks_decode_error(c, r, __func__, "method");
		अगर (method == SSH_SOCKS5_NOAUTH)
			found = 1;
	}
	अगर (!found) {
		debug("channel %d: didn't request SSH_SOCKS5_NOAUTH", c->self);
		वापस -1;
	}
	/* Consume completed request */
	अगर ((r = sshbuf_consume_upto_child(निवेश, b)) != 0)
		fatal_fr(r, "channel %d: consume", c->self);

	/* Compose reply: version, method */
	अगर ((r = sshbuf_put_u8(output, 0x05)) != 0 ||
	    (r = sshbuf_put_u8(output, SSH_SOCKS5_NOAUTH)) != 0)
		fatal_fr(r, "channel %d: append reply", c->self);
	/* success */
	debug2("channel %d: socks5 auth done", c->self);
	वापस 1;
}

अटल पूर्णांक
channel_decode_socks5(Channel *c, काष्ठा sshbuf *निवेश, काष्ठा sshbuf *output)
{
	uint8_t socks_ver, socks_cmd, socks_reserved, socks_atyp, addrlen;
	uint16_t dest_port;
	अक्षर dest_addr[255+1], ntop[INET6_ADDRSTRLEN];
	u_int af;
	पूर्णांक r, success = -1;;
	काष्ठा sshbuf *b = शून्य;

	debug2("channel %d: decode socks5 %s", c->self,
	    (c->flags & SSH_SOCKS5_AUTHDONE) ? "request" : "auth");

	/* We may not have a complete message, so work on a dup of the buffer */
	अगर ((b = sshbuf_fromb(निवेश)) == शून्य)
		fatal_f("sshbuf_fromb failed");

	अगर (!(c->flags & SSH_SOCKS5_AUTHDONE)) {
		अगर ((r = channel_socks5_check_auth(c, b, निवेश, output)) != 1) {
			success = r;
			जाओ out;
		}
		c->flags |= SSH_SOCKS5_AUTHDONE;
		/* Continue to parse request in case client speculated ahead */
	}

	/* Request messages (auth or connect) always start with the version */
	अगर ((r = sshbuf_get_u8(b, &socks_ver)) != 0) {
		success = socks_decode_error(c, r, __func__, "version");
		जाओ out;
	}
	अगर (socks_ver != 5) /* shouldn't happen */
		fatal_fr(r, "channel %d: internal error: not socks5", c->self);

	/* Parse SOCKS5 request header */
	debug2("channel %d: socks5 post auth", c->self);
	अगर ((r = sshbuf_get_u8(b, &socks_cmd)) != 0 ||
	    (r = sshbuf_get_u8(b, &socks_reserved)) != 0 ||
	    (r = sshbuf_get_u8(b, &socks_atyp)) != 0) {
		success = socks_decode_error(c, r, __func__, "request header");
		जाओ out;
	}

	अगर (socks_ver != 0x05 ||
	    socks_cmd != SSH_SOCKS5_CONNECT ||
	    socks_reserved != 0x00) {
		debug2("channel %d: only socks5 connect supported", c->self);
		जाओ out;
	}

	चयन (socks_atyp) {
	हाल SSH_SOCKS5_IPV4:
		addrlen = 4;
		af = AF_INET;
		अवरोध;
	हाल SSH_SOCKS5_DOMAIN:
		अगर ((r = sshbuf_get_u8(b, &addrlen)) != 0) {
			success = socks_decode_error(c, r, __func__, "addrlen");
			जाओ out;
		}
		af = -1;
		अवरोध;
	हाल SSH_SOCKS5_IPV6:
		addrlen = 16;
		af = AF_INET6;
		अवरोध;
	शेष:
		debug2("channel %d: bad socks5 atyp %d", c->self, socks_atyp);
		जाओ out;
	}
	अगर ((r = sshbuf_get(b, &dest_addr, addrlen)) != 0 ||
	    (r = sshbuf_get_u16(b, &dest_port)) != 0) {
		success = socks_decode_error(c, r, __func__, "addr/port");
		जाओ out;
	}
	dest_addr[addrlen] = '\0';

	/* We have a complete SOCKS5 request; consume it from input */
	अगर ((r = sshbuf_consume_upto_child(निवेश, b)) != 0)
		fatal_fr(r, "channel %d: consume", c->self);

	मुक्त(c->path);
	c->path = शून्य;
	अगर (socks_atyp == SSH_SOCKS5_DOMAIN)
		c->path = xstrdup(dest_addr);
	अन्यथा {
		अगर (inet_ntop(af, dest_addr, ntop, माप(ntop)) == शून्य)
			वापस -1;
		c->path = xstrdup(ntop);
	}
	c->host_port = dest_port;

	debug2("channel %d: dynamic request: socks5 host %s port %u command %u",
	    c->self, c->path, c->host_port, socks_cmd);

	/* Reply */
	अगर ((r = sshbuf_put_u8(output, 0x05)) != 0 ||	/* version */
	    (r = sshbuf_put_u8(output, SSH_SOCKS5_SUCCESS)) != 0 || /* cmd */
	    (r = sshbuf_put_u8(output, 0)) != 0 ||	/* reserved, ignored */
	    (r = sshbuf_put_u8(output, SSH_SOCKS5_IPV4)) != 0 || /* addrtype */
	    (r = sshbuf_put_u32(output, ntohl(INADDR_ANY))) != 0 || /* addr */
	    (r = sshbuf_put_u16(output, dest_port)) != 0) /* port */
		fatal_fr(r, "channel %d: append reply", c->self);

	/* success */
	success = 1;
 out:
	sshbuf_free(b);
	वापस success;
}

Channel *
channel_connect_stdio_fwd(काष्ठा ssh *ssh,
    स्थिर अक्षर *host_to_connect, पूर्णांक port_to_connect,
    पूर्णांक in, पूर्णांक out, पूर्णांक nonblock)
{
	Channel *c;

	debug_f("%s:%d", host_to_connect, port_to_connect);

	c = channel_new(ssh, "stdio-forward", SSH_CHANNEL_OPENING, in, out,
	    -1, CHAN_TCP_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT,
	    0, "stdio-forward", nonblock);

	c->path = xstrdup(host_to_connect);
	c->host_port = port_to_connect;
	c->listening_port = 0;
	c->force_drain = 1;

	channel_register_fds(ssh, c, in, out, -1, 0, 1, 0);
	port_open_helper(ssh, c, port_to_connect == PORT_STREAMLOCAL ?
	    "direct-streamlocal@openssh.com" : "direct-tcpip");

	वापस c;
}

/* dynamic port forwarding */
अटल व्योम
channel_pre_dynamic(काष्ठा ssh *ssh, Channel *c)
{
	u_int have;
	u_char ver;
	पूर्णांक r, ret;

	c->io_want = 0;
	have = sshbuf_len(c->निवेश);
	debug2("channel %d: pre_dynamic: have %d", c->self, have);
	/* sshbuf_dump(c->input, stderr); */
	/* check if the fixed size part of the packet is in buffer. */
	अगर (have < 3) {
		/* need more */
		c->io_want |= SSH_CHAN_IO_RFD;
		वापस;
	}
	/* try to guess the protocol */
	अगर ((r = sshbuf_peek_u8(c->निवेश, 0, &ver)) != 0)
		fatal_fr(r, "sshbuf_peek_u8");
	चयन (ver) {
	हाल 0x04:
		ret = channel_decode_socks4(c, c->निवेश, c->output);
		अवरोध;
	हाल 0x05:
		ret = channel_decode_socks5(c, c->निवेश, c->output);
		अवरोध;
	शेष:
		debug2_f("channel %d: unknown SOCKS version %u", c->self, ver);
		ret = -1;
		अवरोध;
	}
	अगर (ret < 0) {
		chan_mark_dead(ssh, c);
	} अन्यथा अगर (ret == 0) {
		debug2("channel %d: pre_dynamic: need more", c->self);
		/* need more */
		c->io_want |= SSH_CHAN_IO_RFD;
		अगर (sshbuf_len(c->output))
			c->io_want |= SSH_CHAN_IO_WFD;
	} अन्यथा {
		/* switch to the next state */
		c->type = SSH_CHANNEL_OPENING;
		port_open_helper(ssh, c, "direct-tcpip");
	}
}

/* simulate read-error */
अटल व्योम
rdynamic_close(काष्ठा ssh *ssh, Channel *c)
{
	c->type = SSH_CHANNEL_OPEN;
	channel_force_close(ssh, c, 0);
}

/* reverse dynamic port forwarding */
अटल व्योम
channel_before_prepare_io_rdynamic(काष्ठा ssh *ssh, Channel *c)
{
	स्थिर u_char *p;
	u_int have, len;
	पूर्णांक r, ret;

	have = sshbuf_len(c->output);
	debug2("channel %d: pre_rdynamic: have %d", c->self, have);
	/* sshbuf_dump(c->output, stderr); */
	/* EOF received */
	अगर (c->flags & CHAN_EOF_RCVD) {
		अगर ((r = sshbuf_consume(c->output, have)) != 0)
			fatal_fr(r, "channel %d: consume", c->self);
		rdynamic_close(ssh, c);
		वापस;
	}
	/* check if the fixed size part of the packet is in buffer. */
	अगर (have < 3)
		वापस;
	/* try to guess the protocol */
	p = sshbuf_ptr(c->output);
	चयन (p[0]) {
	हाल 0x04:
		/* switch input/output for reverse forwarding */
		ret = channel_decode_socks4(c, c->output, c->निवेश);
		अवरोध;
	हाल 0x05:
		ret = channel_decode_socks5(c, c->output, c->निवेश);
		अवरोध;
	शेष:
		ret = -1;
		अवरोध;
	}
	अगर (ret < 0) {
		rdynamic_close(ssh, c);
	} अन्यथा अगर (ret == 0) {
		debug2("channel %d: pre_rdynamic: need more", c->self);
		/* send socks request to peer */
		len = sshbuf_len(c->निवेश);
		अगर (len > 0 && len < c->remote_window) {
			अगर ((r = sshpkt_start(ssh, SSH2_संदेश_CHANNEL_तथ्य)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
			    (r = sshpkt_put_stringb(ssh, c->निवेश)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0) {
				fatal_fr(r, "channel %i: rdynamic", c->self);
			}
			अगर ((r = sshbuf_consume(c->निवेश, len)) != 0)
				fatal_fr(r, "channel %d: consume", c->self);
			c->remote_window -= len;
		}
	} अन्यथा अगर (rdynamic_connect_finish(ssh, c) < 0) {
		/* the connect failed */
		rdynamic_close(ssh, c);
	}
}

/* This is our fake X11 server socket. */
अटल व्योम
channel_post_x11_listener(काष्ठा ssh *ssh, Channel *c)
{
	Channel *nc;
	काष्ठा sockaddr_storage addr;
	पूर्णांक r, newsock, oerrno, remote_port;
	socklen_t addrlen;
	अक्षर buf[16384], *remote_ipaddr;

	अगर ((c->io_ready & SSH_CHAN_IO_SOCK_R) == 0)
		वापस;

	debug("X11 connection requested.");
	addrlen = माप(addr);
	newsock = accept(c->sock, (काष्ठा sockaddr *)&addr, &addrlen);
	अगर (c->single_connection) {
		oerrno = त्रुटि_सं;
		debug2("single_connection: closing X11 listener.");
		channel_close_fd(ssh, c, &c->sock);
		chan_mark_dead(ssh, c);
		त्रुटि_सं = oerrno;
	}
	अगर (newsock == -1) {
		अगर (त्रुटि_सं != EINTR && त्रुटि_सं != EWOULDBLOCK &&
		    त्रुटि_सं != ECONNABORTED)
			error("accept: %.100s", म_त्रुटि(त्रुटि_सं));
		अगर (त्रुटि_सं == EMFILE || त्रुटि_सं == ENFILE)
			c->notbefore = monotime_double() + 1.0;
		वापस;
	}
	set_nodelay(newsock);
	अगर (ssh->chanctxt->want_tcp_keepalive)
		set_keepalive(newsock); /* logs errors */
	remote_ipaddr = get_peer_ipaddr(newsock);
	remote_port = get_peer_port(newsock);
	snprintf(buf, माप buf, "X11 connection from %.200s port %d",
	    remote_ipaddr, remote_port);

	nc = channel_new(ssh, "x11-connection",
	    SSH_CHANNEL_OPENING, newsock, newsock, -1,
	    c->local_window_max, c->local_maxpacket, 0, buf, 1);
	open_preamble(ssh, __func__, nc, "x11");
	अगर ((r = sshpkt_put_cstring(ssh, remote_ipaddr)) != 0 ||
	    (r = sshpkt_put_u32(ssh, remote_port)) != 0) {
		fatal_fr(r, "channel %i: reply", c->self);
	}
	अगर ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i: send", c->self);
	मुक्त(remote_ipaddr);
}

अटल व्योम
port_open_helper(काष्ठा ssh *ssh, Channel *c, अक्षर *rtype)
{
	अक्षर *local_ipaddr = get_local_ipaddr(c->sock);
	पूर्णांक local_port = c->sock == -1 ? 65536 : get_local_port(c->sock);
	अक्षर *remote_ipaddr = get_peer_ipaddr(c->sock);
	पूर्णांक remote_port = get_peer_port(c->sock);
	पूर्णांक r;

	अगर (remote_port == -1) {
		/* Fake addr/port to appease peers that validate it (Tectia) */
		मुक्त(remote_ipaddr);
		remote_ipaddr = xstrdup("127.0.0.1");
		remote_port = 65535;
	}

	मुक्त(c->remote_name);
	xasprintf(&c->remote_name,
	    "%s: listening port %d for %.100s port %d, "
	    "connect from %.200s port %d to %.100s port %d",
	    rtype, c->listening_port, c->path, c->host_port,
	    remote_ipaddr, remote_port, local_ipaddr, local_port);

	open_preamble(ssh, __func__, c, rtype);
	अगर (म_भेद(rtype, "direct-tcpip") == 0) {
		/* target host, port */
		अगर ((r = sshpkt_put_cstring(ssh, c->path)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->host_port)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	} अन्यथा अगर (म_भेद(rtype, "direct-streamlocal@openssh.com") == 0) {
		/* target path */
		अगर ((r = sshpkt_put_cstring(ssh, c->path)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	} अन्यथा अगर (म_भेद(rtype, "forwarded-streamlocal@openssh.com") == 0) {
		/* listen path */
		अगर ((r = sshpkt_put_cstring(ssh, c->path)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	} अन्यथा {
		/* listen address, port */
		अगर ((r = sshpkt_put_cstring(ssh, c->path)) != 0 ||
		    (r = sshpkt_put_u32(ssh, local_port)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	}
	अगर (म_भेद(rtype, "forwarded-streamlocal@openssh.com") == 0) {
		/* reserved for future owner/mode info */
		अगर ((r = sshpkt_put_cstring(ssh, "")) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	} अन्यथा {
		/* originator host and port */
		अगर ((r = sshpkt_put_cstring(ssh, remote_ipaddr)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)remote_port)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	}
	अगर ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i: send", c->self);
	मुक्त(remote_ipaddr);
	मुक्त(local_ipaddr);
}

व्योम
channel_set_x11_refuse_time(काष्ठा ssh *ssh, द्विगुन refuse_time)
{
	ssh->chanctxt->x11_refuse_time = refuse_time;
}

/*
 * This socket is listening for connections to a forwarded TCP/IP port.
 */
अटल व्योम
channel_post_port_listener(काष्ठा ssh *ssh, Channel *c)
{
	Channel *nc;
	काष्ठा sockaddr_storage addr;
	पूर्णांक newsock, nextstate;
	socklen_t addrlen;
	अक्षर *rtype;

	अगर ((c->io_ready & SSH_CHAN_IO_SOCK_R) == 0)
		वापस;

	debug("Connection to port %d forwarding to %.100s port %d requested.",
	    c->listening_port, c->path, c->host_port);

	अगर (c->type == SSH_CHANNEL_RPORT_LISTENER) {
		nextstate = SSH_CHANNEL_OPENING;
		rtype = "forwarded-tcpip";
	} अन्यथा अगर (c->type == SSH_CHANNEL_RUNIX_LISTENER) {
		nextstate = SSH_CHANNEL_OPENING;
		rtype = "forwarded-streamlocal@openssh.com";
	} अन्यथा अगर (c->host_port == PORT_STREAMLOCAL) {
		nextstate = SSH_CHANNEL_OPENING;
		rtype = "direct-streamlocal@openssh.com";
	} अन्यथा अगर (c->host_port == 0) {
		nextstate = SSH_CHANNEL_DYNAMIC;
		rtype = "dynamic-tcpip";
	} अन्यथा {
		nextstate = SSH_CHANNEL_OPENING;
		rtype = "direct-tcpip";
	}

	addrlen = माप(addr);
	newsock = accept(c->sock, (काष्ठा sockaddr *)&addr, &addrlen);
	अगर (newsock == -1) {
		अगर (त्रुटि_सं != EINTR && त्रुटि_सं != EWOULDBLOCK &&
		    त्रुटि_सं != ECONNABORTED)
			error("accept: %.100s", म_त्रुटि(त्रुटि_सं));
		अगर (त्रुटि_सं == EMFILE || त्रुटि_सं == ENFILE)
			c->notbefore = monotime_double() + 1.0;
		वापस;
	}
	अगर (addr.ss_family == AF_INET || addr.ss_family == AF_INET6) {
		set_nodelay(newsock);
		अगर (ssh->chanctxt->want_tcp_keepalive)
			set_keepalive(newsock); /* logs errors */
	}
	nc = channel_new(ssh, rtype, nextstate, newsock, newsock, -1,
	    c->local_window_max, c->local_maxpacket, 0, rtype, 1);
	nc->listening_port = c->listening_port;
	nc->host_port = c->host_port;
	अगर (c->path != शून्य)
		nc->path = xstrdup(c->path);

	अगर (nextstate != SSH_CHANNEL_DYNAMIC)
		port_open_helper(ssh, nc, rtype);
}

/*
 * This is the authentication agent socket listening for connections from
 * clients.
 */
अटल व्योम
channel_post_auth_listener(काष्ठा ssh *ssh, Channel *c)
{
	Channel *nc;
	पूर्णांक r, newsock;
	काष्ठा sockaddr_storage addr;
	socklen_t addrlen;

	अगर ((c->io_ready & SSH_CHAN_IO_SOCK_R) == 0)
		वापस;

	addrlen = माप(addr);
	newsock = accept(c->sock, (काष्ठा sockaddr *)&addr, &addrlen);
	अगर (newsock == -1) {
		error("accept from auth socket: %.100s", म_त्रुटि(त्रुटि_सं));
		अगर (त्रुटि_सं == EMFILE || त्रुटि_सं == ENFILE)
			c->notbefore = monotime_double() + 1.0;
		वापस;
	}
	nc = channel_new(ssh, "agent-connection",
	    SSH_CHANNEL_OPENING, newsock, newsock, -1,
	    c->local_window_max, c->local_maxpacket,
	    0, "accepted auth socket", 1);
	open_preamble(ssh, __func__, nc,
	    c->agent_new ? "agent-connect" : "auth-agent@openssh.com");
	अगर ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i", c->self);
}

अटल व्योम
channel_post_connecting(काष्ठा ssh *ssh, Channel *c)
{
	पूर्णांक err = 0, sock, isopen, r;
	socklen_t sz = माप(err);

	अगर ((c->io_ready & SSH_CHAN_IO_SOCK_W) == 0)
		वापस;
	अगर (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);
	अगर (c->connect_ctx == शून्य)
		fatal_f("channel %d: context missing", c->self);

	/* for rdynamic the OPEN_CONFIRMATION has been sent already */
	isopen = (c->type == SSH_CHANNEL_RDYNAMIC_FINISH);

	अगर (getsockopt(c->sock, SOL_SOCKET, SO_ERROR, &err, &sz) == -1) {
		err = त्रुटि_सं;
		error("getsockopt SO_ERROR failed");
	}

	अगर (err == 0) {
		/* Non-blocking connection completed */
		debug("channel %d: connected to %s port %d",
		    c->self, c->connect_ctx->host, c->connect_ctx->port);
		channel_free_connect_ctx(c);
		c->type = SSH_CHANNEL_OPEN;
		channel_set_used_time(ssh, c);
		अगर (isopen) {
			/* no message necessary */
		} अन्यथा {
			अगर ((r = sshpkt_start(ssh,
			    SSH2_संदेश_CHANNEL_OPEN_CONFIRMATION)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_window)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "channel %i open confirm", c->self);
		}
		वापस;
	}
	अगर (err == EINTR || err == EAGAIN || err == EINPROGRESS)
		वापस;

	/* Non-blocking connection failed */
	debug("channel %d: connection failed: %s", c->self, म_त्रुटि(err));

	/* Try next address, if any */
	अगर ((sock = connect_अग्र(ssh, c->connect_ctx)) == -1) {
		/* Exhausted all addresses for this destination */
		error("connect_to %.100s port %d: failed.",
		    c->connect_ctx->host, c->connect_ctx->port);
		channel_free_connect_ctx(c);
		अगर (isopen) {
			rdynamic_close(ssh, c);
		} अन्यथा {
			अगर ((r = sshpkt_start(ssh,
			    SSH2_संदेश_CHANNEL_OPEN_FAILURE)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
			    (r = sshpkt_put_u32(ssh,
			    SSH2_OPEN_CONNECT_FAILED)) != 0 ||
			    (r = sshpkt_put_cstring(ssh, म_त्रुटि(err))) != 0 ||
			    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "channel %i: failure", c->self);
			chan_mark_dead(ssh, c);
		}
	}

	/* New non-blocking connection in progress */
	बंद(c->sock);
	c->sock = c->rfd = c->wfd = sock;
}

अटल पूर्णांक
channel_handle_rfd(काष्ठा ssh *ssh, Channel *c)
{
	अक्षर buf[CHAN_RBUF];
	ssize_t len;
	पूर्णांक r, force;
	माप_प्रकार nr = 0, have, avail, maxlen = CHANNEL_MAX_READ;
	पूर्णांक pty_zeroread = 0;

#अगर_घोषित PTY_ZEROREAD
	/* Bug on AIX: read(1) can return 0 for a non-closed fd */
	pty_zeroread = c->isatty;
#पूर्ण_अगर

	force = c->isatty && c->detach_close && c->istate != CHAN_निवेश_CLOSED;

	अगर (!force && (c->io_ready & SSH_CHAN_IO_RFD) == 0)
		वापस 1;
	अगर ((avail = sshbuf_avail(c->निवेश)) == 0)
		वापस 1; /* Shouldn't happen */

	/*
	 * For "simple" channels (i.e. not datagram or filtered), we can
	 * read directly to the channel buffer.
	 */
	अगर (!pty_zeroread && c->निवेश_filter == शून्य && !c->datagram) {
		/* Only OPEN channels have valid rwin */
		अगर (c->type == SSH_CHANNEL_OPEN) {
			अगर ((have = sshbuf_len(c->निवेश)) >= c->remote_window)
				वापस 1; /* shouldn't happen */
			अगर (maxlen > c->remote_window - have)
				maxlen = c->remote_window - have;
		}
		अगर (maxlen > avail)
			maxlen = avail;
		अगर ((r = sshbuf_read(c->rfd, c->निवेश, maxlen, &nr)) != 0) {
			अगर (त्रुटि_सं == EINTR || (!force &&
			    (त्रुटि_सं == EAGAIN || त्रुटि_सं == EWOULDBLOCK)))
				वापस 1;
			debug2("channel %d: read failed rfd %d maxlen %zu: %s",
			    c->self, c->rfd, maxlen, ssh_err(r));
			जाओ rfail;
		}
		अगर (nr != 0)
			channel_set_used_time(ssh, c);
		वापस 1;
	}

	त्रुटि_सं = 0;
	len = पढ़ो(c->rfd, buf, माप(buf));
	/* fixup AIX zero-length read with errno set to look more like errors */
	अगर (pty_zeroread && len == 0 && त्रुटि_सं != 0)
		len = -1;
	अगर (len == -1 && (त्रुटि_सं == EINTR ||
	    ((त्रुटि_सं == EAGAIN || त्रुटि_सं == EWOULDBLOCK) && !force)))
		वापस 1;
	अगर (len < 0 || (!pty_zeroread && len == 0)) {
		debug2("channel %d: read<=0 rfd %d len %zd: %s",
		    c->self, c->rfd, len,
		    len == 0 ? "closed" : म_त्रुटि(त्रुटि_सं));
 rfail:
		अगर (c->type != SSH_CHANNEL_OPEN) {
			debug2("channel %d: not open", c->self);
			chan_mark_dead(ssh, c);
			वापस -1;
		} अन्यथा {
			chan_read_failed(ssh, c);
		}
		वापस -1;
	}
	channel_set_used_time(ssh, c);
	अगर (c->निवेश_filter != शून्य) {
		अगर (c->निवेश_filter(ssh, c, buf, len) == -1) {
			debug2("channel %d: filter stops", c->self);
			chan_read_failed(ssh, c);
		}
	} अन्यथा अगर (c->datagram) {
		अगर ((r = sshbuf_put_string(c->निवेश, buf, len)) != 0)
			fatal_fr(r, "channel %i: put datagram", c->self);
	} अन्यथा अगर ((r = sshbuf_put(c->निवेश, buf, len)) != 0)
		fatal_fr(r, "channel %i: put data", c->self);

	वापस 1;
}

अटल पूर्णांक
channel_handle_wfd(काष्ठा ssh *ssh, Channel *c)
{
	काष्ठा termios tio;
	u_char *तथ्य = शून्य, *buf; /* XXX const; need filter API change */
	माप_प्रकार dlen, olen = 0;
	पूर्णांक r, len;

	अगर ((c->io_ready & SSH_CHAN_IO_WFD) == 0)
		वापस 1;
	अगर (sshbuf_len(c->output) == 0)
		वापस 1;

	/* Send buffered output data to the socket. */
	olen = sshbuf_len(c->output);
	अगर (c->output_filter != शून्य) {
		अगर ((buf = c->output_filter(ssh, c, &तथ्य, &dlen)) == शून्य) {
			debug2("channel %d: filter stops", c->self);
			अगर (c->type != SSH_CHANNEL_OPEN)
				chan_mark_dead(ssh, c);
			अन्यथा
				chan_write_failed(ssh, c);
			वापस -1;
		}
	} अन्यथा अगर (c->datagram) {
		अगर ((r = sshbuf_get_string(c->output, &तथ्य, &dlen)) != 0)
			fatal_fr(r, "channel %i: get datagram", c->self);
		buf = तथ्य;
	} अन्यथा {
		buf = तथ्य = sshbuf_mutable_ptr(c->output);
		dlen = sshbuf_len(c->output);
	}

	अगर (c->datagram) {
		/* ignore truncated writes, datagrams might get lost */
		len = ग_लिखो(c->wfd, buf, dlen);
		मुक्त(तथ्य);
		अगर (len == -1 && (त्रुटि_सं == EINTR || त्रुटि_सं == EAGAIN ||
		    त्रुटि_सं == EWOULDBLOCK))
			वापस 1;
		अगर (len <= 0)
			जाओ write_fail;
		जाओ out;
	}

#अगर_घोषित _AIX
	/* XXX: Later AIX versions can't push as much data to tty */
	अगर (c->wfd_isatty)
		dlen = MINIMUM(dlen, 8*1024);
#पूर्ण_अगर

	len = ग_लिखो(c->wfd, buf, dlen);
	अगर (len == -1 &&
	    (त्रुटि_सं == EINTR || त्रुटि_सं == EAGAIN || त्रुटि_सं == EWOULDBLOCK))
		वापस 1;
	अगर (len <= 0) {
 write_fail:
		अगर (c->type != SSH_CHANNEL_OPEN) {
			debug2("channel %d: not open", c->self);
			chan_mark_dead(ssh, c);
			वापस -1;
		} अन्यथा {
			chan_write_failed(ssh, c);
		}
		वापस -1;
	}
	channel_set_used_time(ssh, c);
#अगर_अघोषित BROKEN_TCGETATTR_ICANON
	अगर (c->isatty && dlen >= 1 && buf[0] != '\r') {
		अगर (tcgetattr(c->wfd, &tio) == 0 &&
		    !(tio.c_lflag & ECHO) && (tio.c_lflag & ICANON)) {
			/*
			 * Simulate echo to reduce the impact of
			 * traffic analysis. We need to match the
			 * size of a SSH2_MSG_CHANNEL_DATA message
			 * (4 byte channel id + buf)
			 */
			अगर ((r = sshpkt_संदेश_ignore(ssh, 4+len)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "channel %i: ignore", c->self);
		}
	}
#पूर्ण_अगर /* BROKEN_TCGETATTR_ICANON */
	अगर ((r = sshbuf_consume(c->output, len)) != 0)
		fatal_fr(r, "channel %i: consume", c->self);
 out:
	c->local_consumed += olen - sshbuf_len(c->output);

	वापस 1;
}

अटल पूर्णांक
channel_handle_efd_write(काष्ठा ssh *ssh, Channel *c)
{
	पूर्णांक r;
	ssize_t len;

	अगर ((c->io_ready & SSH_CHAN_IO_EFD_W) == 0)
		वापस 1;
	अगर (sshbuf_len(c->extended) == 0)
		वापस 1;

	len = ग_लिखो(c->efd, sshbuf_ptr(c->extended),
	    sshbuf_len(c->extended));
	debug2("channel %d: written %zd to efd %d", c->self, len, c->efd);
	अगर (len == -1 && (त्रुटि_सं == EINTR || त्रुटि_सं == EAGAIN ||
	    त्रुटि_सं == EWOULDBLOCK))
		वापस 1;
	अगर (len <= 0) {
		debug2("channel %d: closing write-efd %d", c->self, c->efd);
		channel_close_fd(ssh, c, &c->efd);
	} अन्यथा {
		अगर ((r = sshbuf_consume(c->extended, len)) != 0)
			fatal_fr(r, "channel %i: consume", c->self);
		c->local_consumed += len;
		channel_set_used_time(ssh, c);
	}
	वापस 1;
}

अटल पूर्णांक
channel_handle_efd_read(काष्ठा ssh *ssh, Channel *c)
{
	अक्षर buf[CHAN_RBUF];
	ssize_t len;
	पूर्णांक r, force;

	force = c->isatty && c->detach_close && c->istate != CHAN_निवेश_CLOSED;

	अगर (!force && (c->io_ready & SSH_CHAN_IO_EFD_R) == 0)
		वापस 1;

	len = पढ़ो(c->efd, buf, माप(buf));
	debug2("channel %d: read %zd from efd %d", c->self, len, c->efd);
	अगर (len == -1 && (त्रुटि_सं == EINTR || ((त्रुटि_सं == EAGAIN ||
	    त्रुटि_सं == EWOULDBLOCK) && !force)))
		वापस 1;
	अगर (len <= 0) {
		debug2("channel %d: closing read-efd %d", c->self, c->efd);
		channel_close_fd(ssh, c, &c->efd);
		वापस 1;
	}
	channel_set_used_time(ssh, c);
	अगर (c->extended_usage == CHAN_EXTENDED_IGNORE)
		debug3("channel %d: discard efd", c->self);
	अन्यथा अगर ((r = sshbuf_put(c->extended, buf, len)) != 0)
		fatal_fr(r, "channel %i: append", c->self);
	वापस 1;
}

अटल पूर्णांक
channel_handle_efd(काष्ठा ssh *ssh, Channel *c)
{
	अगर (c->efd == -1)
		वापस 1;

	/** XXX handle drain efd, too */

	अगर (c->extended_usage == CHAN_EXTENDED_WRITE)
		वापस channel_handle_efd_write(ssh, c);
	अन्यथा अगर (c->extended_usage == CHAN_EXTENDED_READ ||
	    c->extended_usage == CHAN_EXTENDED_IGNORE)
		वापस channel_handle_efd_read(ssh, c);

	वापस 1;
}

अटल पूर्णांक
channel_check_window(काष्ठा ssh *ssh, Channel *c)
{
	पूर्णांक r;

	अगर (c->type == SSH_CHANNEL_OPEN &&
	    !(c->flags & (CHAN_CLOSE_SENT|CHAN_CLOSE_RCVD)) &&
	    ((c->local_window_max - c->local_window >
	    c->local_maxpacket*3) ||
	    c->local_window < c->local_window_max/2) &&
	    c->local_consumed > 0) {
		अगर (!c->have_remote_id)
			fatal_f("channel %d: no remote id", c->self);
		अगर ((r = sshpkt_start(ssh,
		    SSH2_संदेश_CHANNEL_WINDOW_ADJUST)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->local_consumed)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0) {
			fatal_fr(r, "channel %i", c->self);
		}
		debug2("channel %d: window %d sent adjust %d", c->self,
		    c->local_window, c->local_consumed);
		c->local_window += c->local_consumed;
		c->local_consumed = 0;
	}
	वापस 1;
}

अटल व्योम
channel_post_open(काष्ठा ssh *ssh, Channel *c)
{
	channel_handle_rfd(ssh, c);
	channel_handle_wfd(ssh, c);
	channel_handle_efd(ssh, c);
	channel_check_window(ssh, c);
}

अटल u_int
read_mux(काष्ठा ssh *ssh, Channel *c, u_int need)
{
	अक्षर buf[CHAN_RBUF];
	ssize_t len;
	u_int rlen;
	पूर्णांक r;

	अगर (sshbuf_len(c->निवेश) < need) {
		rlen = need - sshbuf_len(c->निवेश);
		len = पढ़ो(c->rfd, buf, MINIMUM(rlen, CHAN_RBUF));
		अगर (len == -1 && (त्रुटि_सं == EINTR || त्रुटि_सं == EAGAIN))
			वापस sshbuf_len(c->निवेश);
		अगर (len <= 0) {
			debug2("channel %d: ctl read<=0 rfd %d len %zd",
			    c->self, c->rfd, len);
			chan_read_failed(ssh, c);
			वापस 0;
		} अन्यथा अगर ((r = sshbuf_put(c->निवेश, buf, len)) != 0)
			fatal_fr(r, "channel %i: append", c->self);
	}
	वापस sshbuf_len(c->निवेश);
}

अटल व्योम
channel_post_mux_client_read(काष्ठा ssh *ssh, Channel *c)
{
	u_int need;

	अगर ((c->io_ready & SSH_CHAN_IO_RFD) == 0)
		वापस;
	अगर (c->istate != CHAN_निवेश_OPEN && c->istate != CHAN_निवेश_WAIT_DRAIN)
		वापस;
	अगर (c->mux_pause)
		वापस;

	/*
	 * Don't not read past the precise end of packets to
	 * avoid disrupting fd passing.
	 */
	अगर (read_mux(ssh, c, 4) < 4) /* read header */
		वापस;
	/* XXX sshbuf_peek_u32 */
	need = PEEK_U32(sshbuf_ptr(c->निवेश));
#घोषणा CHANNEL_MUX_MAX_PACKET	(256 * 1024)
	अगर (need > CHANNEL_MUX_MAX_PACKET) {
		debug2("channel %d: packet too big %u > %u",
		    c->self, CHANNEL_MUX_MAX_PACKET, need);
		chan_rcvd_oclose(ssh, c);
		वापस;
	}
	अगर (read_mux(ssh, c, need + 4) < need + 4) /* read body */
		वापस;
	अगर (c->mux_rcb(ssh, c) != 0) {
		debug("channel %d: mux_rcb failed", c->self);
		chan_mark_dead(ssh, c);
		वापस;
	}
}

अटल व्योम
channel_post_mux_client_write(काष्ठा ssh *ssh, Channel *c)
{
	ssize_t len;
	पूर्णांक r;

	अगर ((c->io_ready & SSH_CHAN_IO_WFD) == 0)
		वापस;
	अगर (sshbuf_len(c->output) == 0)
		वापस;

	len = ग_लिखो(c->wfd, sshbuf_ptr(c->output), sshbuf_len(c->output));
	अगर (len == -1 && (त्रुटि_सं == EINTR || त्रुटि_सं == EAGAIN))
		वापस;
	अगर (len <= 0) {
		chan_mark_dead(ssh, c);
		वापस;
	}
	अगर ((r = sshbuf_consume(c->output, len)) != 0)
		fatal_fr(r, "channel %i: consume", c->self);
}

अटल व्योम
channel_post_mux_client(काष्ठा ssh *ssh, Channel *c)
{
	channel_post_mux_client_read(ssh, c);
	channel_post_mux_client_write(ssh, c);
}

अटल व्योम
channel_post_mux_listener(काष्ठा ssh *ssh, Channel *c)
{
	Channel *nc;
	काष्ठा sockaddr_storage addr;
	socklen_t addrlen;
	पूर्णांक newsock;
	uid_t euid;
	gid_t egid;

	अगर ((c->io_ready & SSH_CHAN_IO_SOCK_R) == 0)
		वापस;

	debug("multiplexing control connection");

	/*
	 * Accept connection on control socket
	 */
	स_रखो(&addr, 0, माप(addr));
	addrlen = माप(addr);
	अगर ((newsock = accept(c->sock, (काष्ठा sockaddr*)&addr,
	    &addrlen)) == -1) {
		error_f("accept: %s", म_त्रुटि(त्रुटि_सं));
		अगर (त्रुटि_सं == EMFILE || त्रुटि_सं == ENFILE)
			c->notbefore = monotime_double() + 1.0;
		वापस;
	}

	अगर (getpeereid(newsock, &euid, &egid) == -1) {
		error_f("getpeereid failed: %s", म_त्रुटि(त्रुटि_सं));
		बंद(newsock);
		वापस;
	}
	अगर ((euid != 0) && (getuid() != euid)) {
		error("multiplex uid mismatch: peer euid %u != uid %u",
		    (u_int)euid, (u_int)getuid());
		बंद(newsock);
		वापस;
	}
	nc = channel_new(ssh, "mux-control", SSH_CHANNEL_MUX_CLIENT,
	    newsock, newsock, -1, c->local_window_max,
	    c->local_maxpacket, 0, "mux-control", 1);
	nc->mux_rcb = c->mux_rcb;
	debug3_f("new mux channel %d fd %d", nc->self, nc->sock);
	/* establish state */
	nc->mux_rcb(ssh, nc);
	/* mux state transitions must not elicit protocol messages */
	nc->flags |= CHAN_LOCAL;
}

अटल व्योम
channel_handler_init(काष्ठा ssh_channels *sc)
{
	chan_fn **pre, **post;

	अगर ((pre = सुस्मृति(SSH_CHANNEL_MAX_TYPE, माप(*pre))) == शून्य ||
	    (post = सुस्मृति(SSH_CHANNEL_MAX_TYPE, माप(*post))) == शून्य)
		fatal_f("allocation failed");

	pre[SSH_CHANNEL_OPEN] =			&channel_pre_open;
	pre[SSH_CHANNEL_X11_OPEN] =		&channel_pre_x11_open;
	pre[SSH_CHANNEL_PORT_LISTENER] =	&channel_pre_listener;
	pre[SSH_CHANNEL_RPORT_LISTENER] =	&channel_pre_listener;
	pre[SSH_CHANNEL_UNIX_LISTENER] =	&channel_pre_listener;
	pre[SSH_CHANNEL_RUNIX_LISTENER] =	&channel_pre_listener;
	pre[SSH_CHANNEL_X11_LISTENER] =		&channel_pre_listener;
	pre[SSH_CHANNEL_AUTH_SOCKET] =		&channel_pre_listener;
	pre[SSH_CHANNEL_CONNECTING] =		&channel_pre_connecting;
	pre[SSH_CHANNEL_DYNAMIC] =		&channel_pre_dynamic;
	pre[SSH_CHANNEL_RDYNAMIC_FINISH] =	&channel_pre_connecting;
	pre[SSH_CHANNEL_MUX_LISTENER] =		&channel_pre_listener;
	pre[SSH_CHANNEL_MUX_CLIENT] =		&channel_pre_mux_client;

	post[SSH_CHANNEL_OPEN] =		&channel_post_open;
	post[SSH_CHANNEL_PORT_LISTENER] =	&channel_post_port_listener;
	post[SSH_CHANNEL_RPORT_LISTENER] =	&channel_post_port_listener;
	post[SSH_CHANNEL_UNIX_LISTENER] =	&channel_post_port_listener;
	post[SSH_CHANNEL_RUNIX_LISTENER] =	&channel_post_port_listener;
	post[SSH_CHANNEL_X11_LISTENER] =	&channel_post_x11_listener;
	post[SSH_CHANNEL_AUTH_SOCKET] =		&channel_post_auth_listener;
	post[SSH_CHANNEL_CONNECTING] =		&channel_post_connecting;
	post[SSH_CHANNEL_DYNAMIC] =		&channel_post_open;
	post[SSH_CHANNEL_RDYNAMIC_FINISH] =	&channel_post_connecting;
	post[SSH_CHANNEL_MUX_LISTENER] =	&channel_post_mux_listener;
	post[SSH_CHANNEL_MUX_CLIENT] =		&channel_post_mux_client;

	sc->channel_pre = pre;
	sc->channel_post = post;
}

/* gc dead channels */
अटल व्योम
channel_garbage_collect(काष्ठा ssh *ssh, Channel *c)
{
	अगर (c == शून्य)
		वापस;
	अगर (c->detach_user != शून्य) {
		अगर (!chan_is_dead(ssh, c, c->detach_close))
			वापस;

		debug2("channel %d: gc: notify user", c->self);
		c->detach_user(ssh, c->self, 0, शून्य);
		/* if we still have a callback */
		अगर (c->detach_user != शून्य)
			वापस;
		debug2("channel %d: gc: user detached", c->self);
	}
	अगर (!chan_is_dead(ssh, c, 1))
		वापस;
	debug2("channel %d: garbage collecting", c->self);
	channel_free(ssh, c);
}

क्रमागत channel_table { CHAN_PRE, CHAN_POST };

अटल व्योम
channel_handler(काष्ठा ssh *ssh, पूर्णांक table, काष्ठा timespec *timeout)
{
	काष्ठा ssh_channels *sc = ssh->chanctxt;
	chan_fn **ftab = table == CHAN_PRE ? sc->channel_pre : sc->channel_post;
	u_int i, oalloc;
	Channel *c;
	द्विगुन now;

	now = monotime_double();
	क्रम (sc->nbulk = i = 0, oalloc = sc->channels_alloc; i < oalloc; i++) {
		c = sc->channels[i];
		अगर (c == शून्य)
			जारी;
		/* Count open channels in bulk state */
		अगर (c->type == SSH_CHANNEL_OPEN && c->bulk)
			sc->nbulk++;
		/* Try to keep IO going while rekeying */
		अगर (ssh_packet_is_rekeying(ssh) && c->type != SSH_CHANNEL_OPEN)
			जारी;
		अगर (c->delayed) {
			अगर (table == CHAN_PRE)
				c->delayed = 0;
			अन्यथा
				जारी;
		}
		अगर (ftab[c->type] != शून्य) {
			अगर (table == CHAN_PRE && c->type == SSH_CHANNEL_OPEN &&
			    channel_get_expiry(ssh, c) != 0 &&
			    now >= channel_get_expiry(ssh, c)) {
				/* channel closed for inactivity */
				द्विगुन deadline = c->inactive_deadline != 0.0 ?
				    c->inactive_deadline : sc->global_deadline;
				verbose("channel %d: closing after %f seconds "
				    "of inactivity", c->self, deadline);
				channel_force_close(ssh, c, 1);
			} अन्यथा अगर (c->notbefore <= now) {
				/* Run handlers that are not paused. */
				(*ftab[c->type])(ssh, c);
				/* inactivity timeouts must interrupt poll() */
				अगर (timeout != शून्य &&
				    c->type == SSH_CHANNEL_OPEN &&
				    channel_get_expiry(ssh, c) != 0) {
					ptimeout_deadline_monotime_double(timeout,
					    channel_get_expiry(ssh, c));
				}
			} अन्यथा अगर (timeout != शून्य) {
				/*
				 * Arrange for poll() wakeup when channel pause
				 * timer expires.
				 */
				ptimeout_deadline_monotime_double(timeout,
				    c->notbefore);
			}
		}
		channel_garbage_collect(ssh, c);
	}
}

/*
 * Create sockets before preparing IO.
 * This is necessary for things that need to happen after reading
 * the network-input but need to be completed before IO event setup, e.g.
 * because they may create new channels.
 */
अटल व्योम
channel_before_prepare_io(काष्ठा ssh *ssh)
{
	काष्ठा ssh_channels *sc = ssh->chanctxt;
	Channel *c;
	u_int i, oalloc;

	क्रम (i = 0, oalloc = sc->channels_alloc; i < oalloc; i++) {
		c = sc->channels[i];
		अगर (c == शून्य)
			जारी;
		अगर (c->type == SSH_CHANNEL_RDYNAMIC_OPEN)
			channel_before_prepare_io_rdynamic(ssh, c);
	}
}

अटल व्योम
dump_channel_poll(स्थिर अक्षर *func, स्थिर अक्षर *what, Channel *c,
    u_int pollfd_offset, काष्ठा pollfd *pfd)
{
#अगर_घोषित DEBUG_CHANNEL_POLL
	debug3("%s: channel %d: %s r%d w%d e%d s%d c->pfds [ %d %d %d %d ] "
	    "io_want 0x%02x io_ready 0x%02x pfd[%u].fd=%d "
	    "pfd.ev 0x%02x pfd.rev 0x%02x", func, c->self, what,
	    c->rfd, c->wfd, c->efd, c->sock,
	    c->pfds[0], c->pfds[1], c->pfds[2], c->pfds[3],
	    c->io_want, c->io_ready,
	    pollfd_offset, pfd->fd, pfd->events, pfd->revents);
#पूर्ण_अगर
}

/* Prepare pollfd entries for a single channel */
अटल व्योम
channel_prepare_pollfd(Channel *c, u_int *अग्र_pollfd,
    काष्ठा pollfd *pfd, u_int npfd)
{
	u_int ev, p = *अग्र_pollfd;

	अगर (c == शून्य)
		वापस;
	अगर (p + 4 > npfd) {
		/* Shouldn't happen */
		fatal_f("channel %d: bad pfd offset %u (max %u)",
		    c->self, p, npfd);
	}
	c->pfds[0] = c->pfds[1] = c->pfds[2] = c->pfds[3] = -1;
	/*
	 * prepare c->rfd
	 *
	 * This is a special case, since c->rfd might be the same as
	 * c->wfd, c->efd and/or c->sock. Handle those here if they want
	 * IO too.
	 */
	अगर (c->rfd != -1) {
		ev = 0;
		अगर ((c->io_want & SSH_CHAN_IO_RFD) != 0)
			ev |= POLLIN;
		/* rfd == wfd */
		अगर (c->wfd == c->rfd) {
			अगर ((c->io_want & SSH_CHAN_IO_WFD) != 0)
				ev |= POLLOUT;
		}
		/* rfd == efd */
		अगर (c->efd == c->rfd) {
			अगर ((c->io_want & SSH_CHAN_IO_EFD_R) != 0)
				ev |= POLLIN;
			अगर ((c->io_want & SSH_CHAN_IO_EFD_W) != 0)
				ev |= POLLOUT;
		}
		/* rfd == sock */
		अगर (c->sock == c->rfd) {
			अगर ((c->io_want & SSH_CHAN_IO_SOCK_R) != 0)
				ev |= POLLIN;
			अगर ((c->io_want & SSH_CHAN_IO_SOCK_W) != 0)
				ev |= POLLOUT;
		}
		/* Pack a pfd entry if any event armed for this fd */
		अगर (ev != 0) {
			c->pfds[0] = p;
			pfd[p].fd = c->rfd;
			pfd[p].events = ev;
			dump_channel_poll(__func__, "rfd", c, p, &pfd[p]);
			p++;
		}
	}
	/* prepare c->wfd if wanting IO and not already handled above */
	अगर (c->wfd != -1 && c->rfd != c->wfd) {
		ev = 0;
		अगर ((c->io_want & SSH_CHAN_IO_WFD))
			ev |= POLLOUT;
		/* Pack a pfd entry if any event armed for this fd */
		अगर (ev != 0) {
			c->pfds[1] = p;
			pfd[p].fd = c->wfd;
			pfd[p].events = ev;
			dump_channel_poll(__func__, "wfd", c, p, &pfd[p]);
			p++;
		}
	}
	/* prepare c->efd if wanting IO and not already handled above */
	अगर (c->efd != -1 && c->rfd != c->efd) {
		ev = 0;
		अगर ((c->io_want & SSH_CHAN_IO_EFD_R) != 0)
			ev |= POLLIN;
		अगर ((c->io_want & SSH_CHAN_IO_EFD_W) != 0)
			ev |= POLLOUT;
		/* Pack a pfd entry if any event armed for this fd */
		अगर (ev != 0) {
			c->pfds[2] = p;
			pfd[p].fd = c->efd;
			pfd[p].events = ev;
			dump_channel_poll(__func__, "efd", c, p, &pfd[p]);
			p++;
		}
	}
	/* prepare c->sock if wanting IO and not already handled above */
	अगर (c->sock != -1 && c->rfd != c->sock) {
		ev = 0;
		अगर ((c->io_want & SSH_CHAN_IO_SOCK_R) != 0)
			ev |= POLLIN;
		अगर ((c->io_want & SSH_CHAN_IO_SOCK_W) != 0)
			ev |= POLLOUT;
		/* Pack a pfd entry if any event armed for this fd */
		अगर (ev != 0) {
			c->pfds[3] = p;
			pfd[p].fd = c->sock;
			pfd[p].events = ev;
			dump_channel_poll(__func__, "sock", c, p, &pfd[p]);
			p++;
		}
	}
	*अग्र_pollfd = p;
}

/* * Allocate/prepare poll structure */
व्योम
channel_prepare_poll(काष्ठा ssh *ssh, काष्ठा pollfd **pfdp, u_int *npfd_allocp,
    u_int *npfd_activep, u_int npfd_reserved, काष्ठा timespec *timeout)
{
	काष्ठा ssh_channels *sc = ssh->chanctxt;
	u_int i, oalloc, p, npfd = npfd_reserved;

	channel_before_prepare_io(ssh); /* might create a new channel */
	/* clear out I/O flags from last poll */
	क्रम (i = 0; i < sc->channels_alloc; i++) {
		अगर (sc->channels[i] == शून्य)
			जारी;
		sc->channels[i]->io_want = sc->channels[i]->io_ready = 0;
	}
	/* Allocate 4x pollfd for each channel (rfd, wfd, efd, sock) */
	अगर (sc->channels_alloc >= (पूर्णांक_उच्च / 4) - npfd_reserved)
		fatal_f("too many channels"); /* shouldn't happen */
	npfd += sc->channels_alloc * 4;
	अगर (npfd > *npfd_allocp) {
		*pfdp = xrecallocarray(*pfdp, *npfd_allocp,
		    npfd, माप(**pfdp));
		*npfd_allocp = npfd;
	}
	*npfd_activep = npfd_reserved;
	oalloc = sc->channels_alloc;

	channel_handler(ssh, CHAN_PRE, timeout);

	अगर (oalloc != sc->channels_alloc) {
		/* shouldn't happen */
		fatal_f("channels_alloc changed during CHAN_PRE "
		    "(was %u, now %u)", oalloc, sc->channels_alloc);
	}

	/* Prepare pollfd */
	p = npfd_reserved;
	क्रम (i = 0; i < sc->channels_alloc; i++)
		channel_prepare_pollfd(sc->channels[i], &p, *pfdp, npfd);
	*npfd_activep = p;
}

अटल व्योम
fd_ready(Channel *c, पूर्णांक p, काष्ठा pollfd *pfds, u_int npfd, पूर्णांक fd,
    स्थिर अक्षर *what, u_int revents_mask, u_int ready)
{
	काष्ठा pollfd *pfd = &pfds[p];

	अगर (fd == -1)
		वापस;
	अगर (p == -1 || (u_int)p >= npfd)
		fatal_f("channel %d: bad pfd %d (max %u)", c->self, p, npfd);
	dump_channel_poll(__func__, what, c, p, pfd);
	अगर (pfd->fd != fd) {
		fatal("channel %d: inconsistent %s fd=%d pollfd[%u].fd %d "
		    "r%d w%d e%d s%d", c->self, what, fd, p, pfd->fd,
		    c->rfd, c->wfd, c->efd, c->sock);
	}
	अगर ((pfd->revents & POLLNVAL) != 0) {
		fatal("channel %d: invalid %s pollfd[%u].fd %d r%d w%d e%d s%d",
		    c->self, what, p, pfd->fd, c->rfd, c->wfd, c->efd, c->sock);
	}
	अगर ((pfd->revents & (revents_mask|POLLHUP|POLLERR)) != 0)
		c->io_ready |= ready & c->io_want;
}

/*
 * After poll, perform any appropriate operations for channels which have
 * events pending.
 */
व्योम
channel_after_poll(काष्ठा ssh *ssh, काष्ठा pollfd *pfd, u_int npfd)
{
	काष्ठा ssh_channels *sc = ssh->chanctxt;
	u_int i;
	पूर्णांक p;
	Channel *c;

#अगर_घोषित DEBUG_CHANNEL_POLL
	क्रम (p = 0; p < (पूर्णांक)npfd; p++) {
		अगर (pfd[p].revents == 0)
			जारी;
		debug_f("pfd[%u].fd %d rev 0x%04x",
		    p, pfd[p].fd, pfd[p].revents);
	}
#पूर्ण_अगर

	/* Convert pollfd into c->io_ready */
	क्रम (i = 0; i < sc->channels_alloc; i++) {
		c = sc->channels[i];
		अगर (c == शून्य)
			जारी;
		/* if rfd is shared with efd/sock then wfd should be too */
		अगर (c->rfd != -1 && c->wfd != -1 && c->rfd != c->wfd &&
		    (c->rfd == c->efd || c->rfd == c->sock)) {
			/* Shouldn't happen */
			fatal_f("channel %d: unexpected fds r%d w%d e%d s%d",
			    c->self, c->rfd, c->wfd, c->efd, c->sock);
		}
		c->io_ready = 0;
		/* rfd, potentially shared with wfd, efd and sock */
		अगर (c->rfd != -1 && (p = c->pfds[0]) != -1) {
			fd_ready(c, p, pfd, npfd, c->rfd,
			    "rfd", POLLIN, SSH_CHAN_IO_RFD);
			अगर (c->rfd == c->wfd) {
				fd_ready(c, p, pfd, npfd, c->wfd,
				    "wfd/r", POLLOUT, SSH_CHAN_IO_WFD);
			}
			अगर (c->rfd == c->efd) {
				fd_ready(c, p, pfd, npfd, c->efd,
				    "efdr/r", POLLIN, SSH_CHAN_IO_EFD_R);
				fd_ready(c, p, pfd, npfd, c->efd,
				    "efdw/r", POLLOUT, SSH_CHAN_IO_EFD_W);
			}
			अगर (c->rfd == c->sock) {
				fd_ready(c, p, pfd, npfd, c->sock,
				    "sockr/r", POLLIN, SSH_CHAN_IO_SOCK_R);
				fd_ready(c, p, pfd, npfd, c->sock,
				    "sockw/r", POLLOUT, SSH_CHAN_IO_SOCK_W);
			}
			dump_channel_poll(__func__, "rfd", c, p, pfd);
		}
		/* wfd */
		अगर (c->wfd != -1 && c->wfd != c->rfd &&
		    (p = c->pfds[1]) != -1) {
			fd_ready(c, p, pfd, npfd, c->wfd,
			    "wfd", POLLOUT, SSH_CHAN_IO_WFD);
			dump_channel_poll(__func__, "wfd", c, p, pfd);
		}
		/* efd */
		अगर (c->efd != -1 && c->efd != c->rfd &&
		    (p = c->pfds[2]) != -1) {
			fd_ready(c, p, pfd, npfd, c->efd,
			    "efdr", POLLIN, SSH_CHAN_IO_EFD_R);
			fd_ready(c, p, pfd, npfd, c->efd,
			    "efdw", POLLOUT, SSH_CHAN_IO_EFD_W);
			dump_channel_poll(__func__, "efd", c, p, pfd);
		}
		/* sock */
		अगर (c->sock != -1 && c->sock != c->rfd &&
		    (p = c->pfds[3]) != -1) {
			fd_ready(c, p, pfd, npfd, c->sock,
			    "sockr", POLLIN, SSH_CHAN_IO_SOCK_R);
			fd_ready(c, p, pfd, npfd, c->sock,
			    "sockw", POLLOUT, SSH_CHAN_IO_SOCK_W);
			dump_channel_poll(__func__, "sock", c, p, pfd);
		}
	}
	channel_handler(ssh, CHAN_POST, शून्य);
}

/*
 * Enqueue data for channels with open or draining c->input.
 * Returns non-zero if a packet was enqueued.
 */
अटल पूर्णांक
channel_output_poll_निवेश_open(काष्ठा ssh *ssh, Channel *c)
{
	माप_प्रकार len, plen;
	स्थिर u_char *pkt;
	पूर्णांक r;

	अगर ((len = sshbuf_len(c->निवेश)) == 0) {
		अगर (c->istate == CHAN_निवेश_WAIT_DRAIN) {
			/*
			 * input-buffer is empty and read-socket shutdown:
			 * tell peer, that we will not send more data:
			 * send IEOF.
			 * hack for extended data: delay EOF if EFD still
			 * in use.
			 */
			अगर (CHANNEL_EFD_निवेश_ACTIVE(c))
				debug2("channel %d: "
				    "ibuf_empty delayed efd %d/(%zu)",
				    c->self, c->efd, sshbuf_len(c->extended));
			अन्यथा
				chan_ibuf_empty(ssh, c);
		}
		वापस 0;
	}

	अगर (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);

	अगर (c->datagram) {
		/* Check datagram will fit; drop if not */
		अगर ((r = sshbuf_get_string_direct(c->निवेश, &pkt, &plen)) != 0)
			fatal_fr(r, "channel %i: get datagram", c->self);
		/*
		 * XXX this does tail-drop on the datagram queue which is
		 * usually suboptimal compared to head-drop. Better to have
		 * backpressure at read time? (i.e. read + discard)
		 */
		अगर (plen > c->remote_window || plen > c->remote_maxpacket) {
			debug("channel %d: datagram too big", c->self);
			वापस 0;
		}
		/* Enqueue it */
		अगर ((r = sshpkt_start(ssh, SSH2_संदेश_CHANNEL_तथ्य)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
		    (r = sshpkt_put_string(ssh, pkt, plen)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "channel %i: send datagram", c->self);
		c->remote_window -= plen;
		वापस 1;
	}

	/* Enqueue packet for buffered data. */
	अगर (len > c->remote_window)
		len = c->remote_window;
	अगर (len > c->remote_maxpacket)
		len = c->remote_maxpacket;
	अगर (len == 0)
		वापस 0;
	अगर ((r = sshpkt_start(ssh, SSH2_संदेश_CHANNEL_तथ्य)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_string(ssh, sshbuf_ptr(c->निवेश), len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i: send data", c->self);
	अगर ((r = sshbuf_consume(c->निवेश, len)) != 0)
		fatal_fr(r, "channel %i: consume", c->self);
	c->remote_window -= len;
	वापस 1;
}

/*
 * Enqueue data for channels with open c->extended in read mode.
 * Returns non-zero if a packet was enqueued.
 */
अटल पूर्णांक
channel_output_poll_extended_read(काष्ठा ssh *ssh, Channel *c)
{
	माप_प्रकार len;
	पूर्णांक r;

	अगर ((len = sshbuf_len(c->extended)) == 0)
		वापस 0;

	debug2("channel %d: rwin %u elen %zu euse %d", c->self,
	    c->remote_window, sshbuf_len(c->extended), c->extended_usage);
	अगर (len > c->remote_window)
		len = c->remote_window;
	अगर (len > c->remote_maxpacket)
		len = c->remote_maxpacket;
	अगर (len == 0)
		वापस 0;
	अगर (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);
	अगर ((r = sshpkt_start(ssh, SSH2_संदेश_CHANNEL_EXTENDED_तथ्य)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_u32(ssh, SSH2_EXTENDED_तथ्य_STDERR)) != 0 ||
	    (r = sshpkt_put_string(ssh, sshbuf_ptr(c->extended), len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i: data", c->self);
	अगर ((r = sshbuf_consume(c->extended, len)) != 0)
		fatal_fr(r, "channel %i: consume", c->self);
	c->remote_window -= len;
	debug2("channel %d: sent ext data %zu", c->self, len);
	वापस 1;
}

/*
 * If there is data to send to the connection, enqueue some of it now.
 * Returns non-zero if data was enqueued.
 */
पूर्णांक
channel_output_poll(काष्ठा ssh *ssh)
{
	काष्ठा ssh_channels *sc = ssh->chanctxt;
	Channel *c;
	u_int i;
	पूर्णांक ret = 0;

	क्रम (i = 0; i < sc->channels_alloc; i++) {
		c = sc->channels[i];
		अगर (c == शून्य)
			जारी;

		/*
		 * We are only interested in channels that can have buffered
		 * incoming data.
		 */
		अगर (c->type != SSH_CHANNEL_OPEN)
			जारी;
		अगर ((c->flags & (CHAN_CLOSE_SENT|CHAN_CLOSE_RCVD))) {
			/* XXX is this true? */
			debug3("channel %d: will not send data after close",
			    c->self);
			जारी;
		}

		/* Get the amount of buffered data for this channel. */
		अगर (c->istate == CHAN_निवेश_OPEN ||
		    c->istate == CHAN_निवेश_WAIT_DRAIN)
			ret |= channel_output_poll_निवेश_open(ssh, c);
		/* Send extended data, i.e. stderr */
		अगर (!(c->flags & CHAN_EOF_SENT) &&
		    c->extended_usage == CHAN_EXTENDED_READ)
			ret |= channel_output_poll_extended_read(ssh, c);
	}
	वापस ret;
}

/* -- mux proxy support  */

/*
 * When multiplexing channel messages for mux clients we have to deal
 * with downstream messages from the mux client and upstream messages
 * from the ssh server:
 * 1) Handling downstream messages is straightforward and happens
 *    in channel_proxy_downstream():
 *    - We forward all messages (mostly) unmodified to the server.
 *    - However, in order to route messages from upstream to the correct
 *      downstream client, we have to replace the channel IDs used by the
 *      mux clients with a unique channel ID because the mux clients might
 *      use conflicting channel IDs.
 *    - so we inspect and change both SSH2_MSG_CHANNEL_OPEN and
 *      SSH2_MSG_CHANNEL_OPEN_CONFIRMATION messages, create a local
 *      SSH_CHANNEL_MUX_PROXY channel and replace the mux clients ID
 *      with the newly allocated channel ID.
 * 2) Upstream messages are received by matching SSH_CHANNEL_MUX_PROXY
 *    channels and processed by channel_proxy_upstream(). The local channel ID
 *    is then translated back to the original mux client ID.
 * 3) In both cases we need to keep track of matching SSH2_MSG_CHANNEL_CLOSE
 *    messages so we can clean up SSH_CHANNEL_MUX_PROXY channels.
 * 4) The SSH_CHANNEL_MUX_PROXY channels also need to closed when the
 *    downstream mux client are removed.
 * 5) Handling SSH2_MSG_CHANNEL_OPEN messages from the upstream server
 *    requires more work, because they are not addressed to a specific
 *    channel. E.g. client_request_forwarded_tcpip() needs to figure
 *    out whether the request is addressed to the local client or a
 *    specific downstream client based on the listen-address/port.
 * 6) Agent and X11-Forwarding have a similar problem and are currently
 *    not supported as the matching session/channel cannot be identified
 *    easily.
 */

/*
 * receive packets from downstream mux clients:
 * channel callback fired on read from mux client, creates
 * SSH_CHANNEL_MUX_PROXY channels and translates channel IDs
 * on channel creation.
 */
पूर्णांक
channel_proxy_downstream(काष्ठा ssh *ssh, Channel *downstream)
{
	Channel *c = शून्य;
	काष्ठा sshbuf *original = शून्य, *modified = शून्य;
	स्थिर u_char *cp;
	अक्षर *ctype = शून्य, *listen_host = शून्य;
	u_char type;
	माप_प्रकार have;
	पूर्णांक ret = -1, r;
	u_int id, remote_id, listen_port;

	/* sshbuf_dump(downstream->input, stderr); */
	अगर ((r = sshbuf_get_string_direct(downstream->निवेश, &cp, &have))
	    != 0) {
		error_fr(r, "parse");
		वापस -1;
	}
	अगर (have < 2) {
		error_f("short message");
		वापस -1;
	}
	type = cp[1];
	/* skip padlen + type */
	cp += 2;
	have -= 2;
	अगर (ssh_packet_log_type(type))
		debug3_f("channel %u: down->up: type %u",
		    downstream->self, type);

	चयन (type) {
	हाल SSH2_संदेश_CHANNEL_OPEN:
		अगर ((original = sshbuf_from(cp, have)) == शून्य ||
		    (modified = sshbuf_new()) == शून्य) {
			error_f("alloc");
			जाओ out;
		}
		अगर ((r = sshbuf_get_cstring(original, &ctype, शून्य)) != 0 ||
		    (r = sshbuf_get_u32(original, &id)) != 0) {
			error_fr(r, "parse");
			जाओ out;
		}
		c = channel_new(ssh, "mux-proxy", SSH_CHANNEL_MUX_PROXY,
		    -1, -1, -1, 0, 0, 0, ctype, 1);
		c->mux_ctx = downstream;	/* point to mux client */
		c->mux_downstream_id = id;	/* original downstream id */
		अगर ((r = sshbuf_put_cstring(modified, ctype)) != 0 ||
		    (r = sshbuf_put_u32(modified, c->self)) != 0 ||
		    (r = sshbuf_putb(modified, original)) != 0) {
			error_fr(r, "compose");
			channel_free(ssh, c);
			जाओ out;
		}
		अवरोध;
	हाल SSH2_संदेश_CHANNEL_OPEN_CONFIRMATION:
		/*
		 * Almost the same as SSH2_MSG_CHANNEL_OPEN, except then we
		 * need to parse 'remote_id' instead of 'ctype'.
		 */
		अगर ((original = sshbuf_from(cp, have)) == शून्य ||
		    (modified = sshbuf_new()) == शून्य) {
			error_f("alloc");
			जाओ out;
		}
		अगर ((r = sshbuf_get_u32(original, &remote_id)) != 0 ||
		    (r = sshbuf_get_u32(original, &id)) != 0) {
			error_fr(r, "parse");
			जाओ out;
		}
		c = channel_new(ssh, "mux-proxy", SSH_CHANNEL_MUX_PROXY,
		    -1, -1, -1, 0, 0, 0, "mux-down-connect", 1);
		c->mux_ctx = downstream;	/* point to mux client */
		c->mux_downstream_id = id;
		c->remote_id = remote_id;
		c->have_remote_id = 1;
		अगर ((r = sshbuf_put_u32(modified, remote_id)) != 0 ||
		    (r = sshbuf_put_u32(modified, c->self)) != 0 ||
		    (r = sshbuf_putb(modified, original)) != 0) {
			error_fr(r, "compose");
			channel_free(ssh, c);
			जाओ out;
		}
		अवरोध;
	हाल SSH2_संदेश_GLOBAL_REQUEST:
		अगर ((original = sshbuf_from(cp, have)) == शून्य) {
			error_f("alloc");
			जाओ out;
		}
		अगर ((r = sshbuf_get_cstring(original, &ctype, शून्य)) != 0) {
			error_fr(r, "parse");
			जाओ out;
		}
		अगर (म_भेद(ctype, "tcpip-forward") != 0) {
			error_f("unsupported request %s", ctype);
			जाओ out;
		}
		अगर ((r = sshbuf_get_u8(original, शून्य)) != 0 ||
		    (r = sshbuf_get_cstring(original, &listen_host, शून्य)) != 0 ||
		    (r = sshbuf_get_u32(original, &listen_port)) != 0) {
			error_fr(r, "parse");
			जाओ out;
		}
		अगर (listen_port > 65535) {
			error_f("tcpip-forward for %s: bad port %u",
			    listen_host, listen_port);
			जाओ out;
		}
		/* Record that connection to this host/port is permitted. */
		permission_set_add(ssh, FORWARD_USER, FORWARD_LOCAL, "<mux>",
		    -1, listen_host, शून्य, (पूर्णांक)listen_port, downstream);
		अवरोध;
	हाल SSH2_संदेश_CHANNEL_CLOSE:
		अगर (have < 4)
			अवरोध;
		remote_id = PEEK_U32(cp);
		अगर ((c = channel_by_remote_id(ssh, remote_id)) != शून्य) {
			अगर (c->flags & CHAN_CLOSE_RCVD)
				channel_free(ssh, c);
			अन्यथा
				c->flags |= CHAN_CLOSE_SENT;
		}
		अवरोध;
	}
	अगर (modified) {
		अगर ((r = sshpkt_start(ssh, type)) != 0 ||
		    (r = sshpkt_putb(ssh, modified)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0) {
			error_fr(r, "send");
			जाओ out;
		}
	} अन्यथा {
		अगर ((r = sshpkt_start(ssh, type)) != 0 ||
		    (r = sshpkt_put(ssh, cp, have)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0) {
			error_fr(r, "send");
			जाओ out;
		}
	}
	ret = 0;
 out:
	मुक्त(ctype);
	मुक्त(listen_host);
	sshbuf_free(original);
	sshbuf_free(modified);
	वापस ret;
}

/*
 * receive packets from upstream server and de-multiplex packets
 * to correct downstream:
 * implemented as a helper for channel input handlers,
 * replaces local (proxy) channel ID with downstream channel ID.
 */
पूर्णांक
channel_proxy_upstream(Channel *c, पूर्णांक type, uint32_t seq, काष्ठा ssh *ssh)
{
	काष्ठा sshbuf *b = शून्य;
	Channel *downstream;
	स्थिर u_char *cp = शून्य;
	माप_प्रकार len;
	पूर्णांक r;

	/*
	 * When receiving packets from the peer we need to check whether we
	 * need to forward the packets to the mux client. In this case we
	 * restore the original channel id and keep track of CLOSE messages,
	 * so we can cleanup the channel.
	 */
	अगर (c == शून्य || c->type != SSH_CHANNEL_MUX_PROXY)
		वापस 0;
	अगर ((downstream = c->mux_ctx) == शून्य)
		वापस 0;
	चयन (type) {
	हाल SSH2_संदेश_CHANNEL_CLOSE:
	हाल SSH2_संदेश_CHANNEL_तथ्य:
	हाल SSH2_संदेश_CHANNEL_EOF:
	हाल SSH2_संदेश_CHANNEL_EXTENDED_तथ्य:
	हाल SSH2_संदेश_CHANNEL_OPEN_CONFIRMATION:
	हाल SSH2_संदेश_CHANNEL_OPEN_FAILURE:
	हाल SSH2_संदेश_CHANNEL_WINDOW_ADJUST:
	हाल SSH2_संदेश_CHANNEL_SUCCESS:
	हाल SSH2_संदेश_CHANNEL_FAILURE:
	हाल SSH2_संदेश_CHANNEL_REQUEST:
		अवरोध;
	शेष:
		debug2_f("channel %u: unsupported type %u", c->self, type);
		वापस 0;
	}
	अगर ((b = sshbuf_new()) == शून्य) {
		error_f("alloc reply");
		जाओ out;
	}
	/* get remaining payload (after id) */
	cp = sshpkt_ptr(ssh, &len);
	अगर (cp == शून्य) {
		error_f("no packet");
		जाओ out;
	}
	/* translate id and send to muxclient */
	अगर ((r = sshbuf_put_u8(b, 0)) != 0 ||	/* padlen */
	    (r = sshbuf_put_u8(b, type)) != 0 ||
	    (r = sshbuf_put_u32(b, c->mux_downstream_id)) != 0 ||
	    (r = sshbuf_put(b, cp, len)) != 0 ||
	    (r = sshbuf_put_stringb(downstream->output, b)) != 0) {
		error_fr(r, "compose muxclient");
		जाओ out;
	}
	/* sshbuf_dump(b, stderr); */
	अगर (ssh_packet_log_type(type))
		debug3_f("channel %u: up->down: type %u", c->self, type);
 out:
	/* update state */
	चयन (type) {
	हाल SSH2_संदेश_CHANNEL_OPEN_CONFIRMATION:
		/* record remote_id for SSH2_MSG_CHANNEL_CLOSE */
		अगर (cp && len > 4) {
			c->remote_id = PEEK_U32(cp);
			c->have_remote_id = 1;
		}
		अवरोध;
	हाल SSH2_संदेश_CHANNEL_CLOSE:
		अगर (c->flags & CHAN_CLOSE_SENT)
			channel_free(ssh, c);
		अन्यथा
			c->flags |= CHAN_CLOSE_RCVD;
		अवरोध;
	}
	sshbuf_free(b);
	वापस 1;
}

/* -- protocol input */

/* Parse a channel ID from the current packet */
अटल पूर्णांक
channel_parse_id(काष्ठा ssh *ssh, स्थिर अक्षर *where, स्थिर अक्षर *what)
{
	uint32_t id;
	पूर्णांक r;

	अगर ((r = sshpkt_get_u32(ssh, &id)) != 0) {
		error_r(r, "%s: parse id", where);
		ssh_packet_disconnect(ssh, "Invalid %s message", what);
	}
	अगर (id > पूर्णांक_उच्च) {
		error_r(r, "%s: bad channel id %u", where, id);
		ssh_packet_disconnect(ssh, "Invalid %s channel id", what);
	}
	वापस (पूर्णांक)id;
}

/* Lookup a channel from an ID in the current packet */
अटल Channel *
channel_from_packet_id(काष्ठा ssh *ssh, स्थिर अक्षर *where, स्थिर अक्षर *what)
{
	पूर्णांक id = channel_parse_id(ssh, where, what);
	Channel *c;

	अगर ((c = channel_lookup(ssh, id)) == शून्य) {
		ssh_packet_disconnect(ssh,
		    "%s packet referred to nonexistent channel %d", what, id);
	}
	वापस c;
}

पूर्णांक
channel_निवेश_तथ्य(पूर्णांक type, uint32_t seq, काष्ठा ssh *ssh)
{
	स्थिर u_char *तथ्य;
	माप_प्रकार तथ्य_len, win_len;
	Channel *c = channel_from_packet_id(ssh, __func__, "data");
	पूर्णांक r;

	अगर (channel_proxy_upstream(c, type, seq, ssh))
		वापस 0;

	/* Ignore any data for non-open channels (might happen on close) */
	अगर (c->type != SSH_CHANNEL_OPEN &&
	    c->type != SSH_CHANNEL_RDYNAMIC_OPEN &&
	    c->type != SSH_CHANNEL_RDYNAMIC_FINISH &&
	    c->type != SSH_CHANNEL_X11_OPEN)
		वापस 0;

	/* Get the data. */
	अगर ((r = sshpkt_get_string_direct(ssh, &तथ्य, &तथ्य_len)) != 0 ||
            (r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "channel %i: get data", c->self);

	win_len = तथ्य_len;
	अगर (c->datagram)
		win_len += 4;  /* string length header */

	/*
	 * The sending side reduces its window as it sends data, so we
	 * must 'fake' consumption of the data in order to ensure that window
	 * updates are sent back. Otherwise the connection might deadlock.
	 */
	अगर (c->ostate != CHAN_OUTPUT_OPEN) {
		अगर (win_len > c->local_window)
			c->local_window = 0;
		अन्यथा
			c->local_window -= win_len;
		c->local_consumed += win_len;
		वापस 0;
	}

	अगर (win_len > c->local_maxpacket) {
		logit("channel %d: rcvd big packet %zu, maxpack %u",
		    c->self, win_len, c->local_maxpacket);
		वापस 0;
	}
	अगर (win_len > c->local_window) {
		u_int delta = win_len - c->local_window;

		अगर (c->local_window_exceeded > अच_पूर्णांक_उच्च - delta)
			c->local_window_exceeded = अच_पूर्णांक_उच्च;
		अन्यथा
			c->local_window_exceeded += delta;
		logit("channel %d: rcvd too much data %zu, win %u/%u "
		    "(excess %u)", c->self, win_len, c->local_window,
		    c->local_window_max, c->local_window_exceeded);
		c->local_window = 0;
		/* Allow 10% grace before bringing the hammer down */
		अगर (c->local_window_exceeded > (c->local_window_max / 10)) {
			ssh_packet_disconnect(ssh, "channel %d: peer ignored "
			    "channel window", c->self);
		}
	} अन्यथा {
		c->local_window -= win_len;
		c->local_window_exceeded = 0;
	}

	अगर (c->datagram) {
		अगर ((r = sshbuf_put_string(c->output, तथ्य, तथ्य_len)) != 0)
			fatal_fr(r, "channel %i: append datagram", c->self);
	} अन्यथा अगर ((r = sshbuf_put(c->output, तथ्य, तथ्य_len)) != 0)
		fatal_fr(r, "channel %i: append data", c->self);

	वापस 0;
}

पूर्णांक
channel_निवेश_extended_तथ्य(पूर्णांक type, uint32_t seq, काष्ठा ssh *ssh)
{
	स्थिर u_char *तथ्य;
	माप_प्रकार तथ्य_len;
	uint32_t tcode;
	Channel *c = channel_from_packet_id(ssh, __func__, "extended data");
	पूर्णांक r;

	अगर (channel_proxy_upstream(c, type, seq, ssh))
		वापस 0;
	अगर (c->type != SSH_CHANNEL_OPEN) {
		logit("channel %d: ext data for non open", c->self);
		वापस 0;
	}
	अगर (c->flags & CHAN_EOF_RCVD) {
		अगर (ssh->compat & SSH_BUG_EXTEOF)
			debug("channel %d: accepting ext data after eof",
			    c->self);
		अन्यथा
			ssh_packet_disconnect(ssh, "Received extended_data "
			    "after EOF on channel %d.", c->self);
	}

	अगर ((r = sshpkt_get_u32(ssh, &tcode)) != 0) {
		error_fr(r, "parse tcode");
		ssh_packet_disconnect(ssh, "Invalid extended_data message");
	}
	अगर (c->efd == -1 ||
	    c->extended_usage != CHAN_EXTENDED_WRITE ||
	    tcode != SSH2_EXTENDED_तथ्य_STDERR) {
		logit("channel %d: bad ext data", c->self);
		वापस 0;
	}
	अगर ((r = sshpkt_get_string_direct(ssh, &तथ्य, &तथ्य_len)) != 0 ||
            (r = sshpkt_get_end(ssh)) != 0) {
		error_fr(r, "parse data");
		ssh_packet_disconnect(ssh, "Invalid extended_data message");
	}

	अगर (तथ्य_len > c->local_window) {
		logit("channel %d: rcvd too much extended_data %zu, win %u",
		    c->self, तथ्य_len, c->local_window);
		वापस 0;
	}
	debug2("channel %d: rcvd ext data %zu", c->self, तथ्य_len);
	/* XXX sshpkt_getb? */
	अगर ((r = sshbuf_put(c->extended, तथ्य, तथ्य_len)) != 0)
		error_fr(r, "append");
	c->local_window -= तथ्य_len;
	वापस 0;
}

पूर्णांक
channel_निवेश_ieof(पूर्णांक type, uint32_t seq, काष्ठा ssh *ssh)
{
	Channel *c = channel_from_packet_id(ssh, __func__, "ieof");
	पूर्णांक r;

        अगर ((r = sshpkt_get_end(ssh)) != 0) {
		error_fr(r, "parse data");
		ssh_packet_disconnect(ssh, "Invalid ieof message");
	}

	अगर (channel_proxy_upstream(c, type, seq, ssh))
		वापस 0;
	chan_rcvd_ieof(ssh, c);

	/* XXX force input close */
	अगर (c->force_drain && c->istate == CHAN_निवेश_OPEN) {
		debug("channel %d: FORCE input drain", c->self);
		c->istate = CHAN_निवेश_WAIT_DRAIN;
		अगर (sshbuf_len(c->निवेश) == 0)
			chan_ibuf_empty(ssh, c);
	}
	वापस 0;
}

पूर्णांक
channel_निवेश_oclose(पूर्णांक type, uint32_t seq, काष्ठा ssh *ssh)
{
	Channel *c = channel_from_packet_id(ssh, __func__, "oclose");
	पूर्णांक r;

	अगर (channel_proxy_upstream(c, type, seq, ssh))
		वापस 0;
        अगर ((r = sshpkt_get_end(ssh)) != 0) {
		error_fr(r, "parse data");
		ssh_packet_disconnect(ssh, "Invalid oclose message");
	}
	chan_rcvd_oclose(ssh, c);
	वापस 0;
}

पूर्णांक
channel_निवेश_open_confirmation(पूर्णांक type, uint32_t seq, काष्ठा ssh *ssh)
{
	Channel *c = channel_from_packet_id(ssh, __func__, "open confirmation");
	uint32_t remote_window, remote_maxpacket;
	पूर्णांक r;

	अगर (channel_proxy_upstream(c, type, seq, ssh))
		वापस 0;
	अगर (c->type != SSH_CHANNEL_OPENING)
		ssh_packet_disconnect(ssh, "Received open confirmation for "
		    "non-opening channel %d.", c->self);
	/*
	 * Record the remote channel number and mark that the channel
	 * is now open.
	 */
	अगर ((r = sshpkt_get_u32(ssh, &c->remote_id)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &remote_window)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &remote_maxpacket)) != 0 ||
            (r = sshpkt_get_end(ssh)) != 0) {
		error_fr(r, "window/maxpacket");
		ssh_packet_disconnect(ssh, "Invalid open confirmation message");
	}

	c->have_remote_id = 1;
	c->remote_window = remote_window;
	c->remote_maxpacket = remote_maxpacket;
	c->type = SSH_CHANNEL_OPEN;
	अगर (c->open_confirm) {
		debug2_f("channel %d: callback start", c->self);
		c->open_confirm(ssh, c->self, 1, c->open_confirm_ctx);
		debug2_f("channel %d: callback done", c->self);
	}
	channel_set_used_time(ssh, c);
	debug2("channel %d: open confirm rwindow %u rmax %u", c->self,
	    c->remote_window, c->remote_maxpacket);
	वापस 0;
}

अटल अक्षर *
reason2txt(पूर्णांक reason)
{
	चयन (reason) {
	हाल SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED:
		वापस "administratively prohibited";
	हाल SSH2_OPEN_CONNECT_FAILED:
		वापस "connect failed";
	हाल SSH2_OPEN_UNKNOWN_CHANNEL_TYPE:
		वापस "unknown channel type";
	हाल SSH2_OPEN_RESOURCE_SHORTAGE:
		वापस "resource shortage";
	}
	वापस "unknown reason";
}

पूर्णांक
channel_निवेश_open_failure(पूर्णांक type, uint32_t seq, काष्ठा ssh *ssh)
{
	Channel *c = channel_from_packet_id(ssh, __func__, "open failure");
	uint32_t reason;
	अक्षर *संदेश = शून्य;
	पूर्णांक r;

	अगर (channel_proxy_upstream(c, type, seq, ssh))
		वापस 0;
	अगर (c->type != SSH_CHANNEL_OPENING)
		ssh_packet_disconnect(ssh, "Received open failure for "
		    "non-opening channel %d.", c->self);
	अगर ((r = sshpkt_get_u32(ssh, &reason)) != 0) {
		error_fr(r, "parse reason");
		ssh_packet_disconnect(ssh, "Invalid open failure message");
	}
	/* skip language */
	अगर ((r = sshpkt_get_cstring(ssh, &संदेश, शून्य)) != 0 ||
	    (r = sshpkt_get_string_direct(ssh, शून्य, शून्य)) != 0 ||
            (r = sshpkt_get_end(ssh)) != 0) {
		error_fr(r, "parse msg/lang");
		ssh_packet_disconnect(ssh, "Invalid open failure message");
	}
	logit("channel %d: open failed: %s%s%s", c->self,
	    reason2txt(reason), संदेश ? ": ": "", संदेश ? संदेश : "");
	मुक्त(संदेश);
	अगर (c->open_confirm) {
		debug2_f("channel %d: callback start", c->self);
		c->open_confirm(ssh, c->self, 0, c->open_confirm_ctx);
		debug2_f("channel %d: callback done", c->self);
	}
	/* Schedule the channel for cleanup/deletion. */
	chan_mark_dead(ssh, c);
	वापस 0;
}

पूर्णांक
channel_निवेश_window_adjust(पूर्णांक type, uint32_t seq, काष्ठा ssh *ssh)
{
	पूर्णांक id = channel_parse_id(ssh, __func__, "window adjust");
	Channel *c;
	uint32_t adjust;
	u_int new_rwin;
	पूर्णांक r;

	अगर ((c = channel_lookup(ssh, id)) == शून्य) {
		logit("Received window adjust for non-open channel %d.", id);
		वापस 0;
	}

	अगर (channel_proxy_upstream(c, type, seq, ssh))
		वापस 0;
	अगर ((r = sshpkt_get_u32(ssh, &adjust)) != 0 ||
            (r = sshpkt_get_end(ssh)) != 0) {
		error_fr(r, "parse adjust");
		ssh_packet_disconnect(ssh, "Invalid window adjust message");
	}
	debug2("channel %d: rcvd adjust %u", c->self, adjust);
	अगर ((new_rwin = c->remote_window + adjust) < c->remote_window) {
		fatal("channel %d: adjust %u overflows remote window %u",
		    c->self, adjust, c->remote_window);
	}
	c->remote_window = new_rwin;
	वापस 0;
}

पूर्णांक
channel_निवेश_status_confirm(पूर्णांक type, uint32_t seq, काष्ठा ssh *ssh)
{
	पूर्णांक id = channel_parse_id(ssh, __func__, "status confirm");
	Channel *c;
	काष्ठा channel_confirm *cc;

	/* Reset keepalive timeout */
	ssh_packet_set_alive_timeouts(ssh, 0);

	debug2_f("type %d id %d", type, id);

	अगर ((c = channel_lookup(ssh, id)) == शून्य) {
		logit_f("%d: unknown", id);
		वापस 0;
	}
	अगर (channel_proxy_upstream(c, type, seq, ssh))
		वापस 0;
        अगर (sshpkt_get_end(ssh) != 0)
		ssh_packet_disconnect(ssh, "Invalid status confirm message");
	अगर ((cc = TAILQ_FIRST(&c->status_confirms)) == शून्य)
		वापस 0;
	cc->cb(ssh, type, c, cc->ctx);
	TAILQ_REMOVE(&c->status_confirms, cc, entry);
	freezero(cc, माप(*cc));
	वापस 0;
}

/* -- tcp forwarding */

व्योम
channel_set_af(काष्ठा ssh *ssh, पूर्णांक af)
{
	ssh->chanctxt->IPv4or6 = af;
}


/*
 * Determine whether or not a port forward listens to loopback, the
 * specified address or wildcard. On the client, a specified bind
 * address will always override gateway_ports. On the server, a
 * gateway_ports of 1 (``yes'') will override the client's specification
 * and force a wildcard bind, whereas a value of 2 (``clientspecified'')
 * will bind to whatever address the client asked for.
 *
 * Special-case listen_addrs are:
 *
 * "0.0.0.0"               -> wildcard v4/v6 if SSH_OLD_FORWARD_ADDR
 * "" (empty string), "*"  -> wildcard v4/v6
 * "localhost"             -> loopback v4/v6
 * "127.0.0.1" / "::1"     -> accepted even if gateway_ports isn't set
 */
अटल स्थिर अक्षर *
channel_fwd_bind_addr(काष्ठा ssh *ssh, स्थिर अक्षर *listen_addr, पूर्णांक *wildcardp,
    पूर्णांक is_client, काष्ठा ForwardOptions *fwd_opts)
{
	स्थिर अक्षर *addr = शून्य;
	पूर्णांक wildcard = 0;

	अगर (listen_addr == शून्य) {
		/* No address specified: default to gateway_ports setting */
		अगर (fwd_opts->gateway_ports)
			wildcard = 1;
	} अन्यथा अगर (fwd_opts->gateway_ports || is_client) {
		अगर (((ssh->compat & SSH_OLD_FORWARD_ADDR) &&
		    म_भेद(listen_addr, "0.0.0.0") == 0 && is_client == 0) ||
		    *listen_addr == '\0' || म_भेद(listen_addr, "*") == 0 ||
		    (!is_client && fwd_opts->gateway_ports == 1)) {
			wildcard = 1;
			/*
			 * Notify client if they requested a specific listen
			 * address and it was overridden.
			 */
			अगर (*listen_addr != '\0' &&
			    म_भेद(listen_addr, "0.0.0.0") != 0 &&
			    म_भेद(listen_addr, "*") != 0) {
				ssh_packet_send_debug(ssh,
				    "Forwarding listen address "
				    "\"%s\" overridden by server "
				    "GatewayPorts", listen_addr);
			}
		} अन्यथा अगर (म_भेद(listen_addr, "localhost") != 0 ||
		    म_भेद(listen_addr, "127.0.0.1") == 0 ||
		    म_भेद(listen_addr, "::1") == 0) {
			/*
			 * Accept explicit localhost address when
			 * GatewayPorts=yes. The "localhost" hostname is
			 * deliberately skipped here so it will listen on all
			 * available local address families.
			 */
			addr = listen_addr;
		}
	} अन्यथा अगर (म_भेद(listen_addr, "127.0.0.1") == 0 ||
	    म_भेद(listen_addr, "::1") == 0) {
		/*
		 * If a specific IPv4/IPv6 localhost address has been
		 * requested then accept it even if gateway_ports is in
		 * effect. This allows the client to prefer IPv4 or IPv6.
		 */
		addr = listen_addr;
	}
	अगर (wildcardp != शून्य)
		*wildcardp = wildcard;
	वापस addr;
}

अटल पूर्णांक
channel_setup_fwd_listener_tcpip(काष्ठा ssh *ssh, पूर्णांक type,
    काष्ठा Forward *fwd, पूर्णांक *allocated_listen_port,
    काष्ठा ForwardOptions *fwd_opts)
{
	Channel *c;
	पूर्णांक sock, r, success = 0, wildcard = 0, is_client;
	काष्ठा addrinfo hints, *ai, *aitop;
	स्थिर अक्षर *host, *addr;
	अक्षर ntop[NI_MAXHOST], strport[NI_MAXSERV];
	in_port_t *lport_p;

	is_client = (type == SSH_CHANNEL_PORT_LISTENER);

	अगर (is_client && fwd->connect_path != शून्य) {
		host = fwd->connect_path;
	} अन्यथा {
		host = (type == SSH_CHANNEL_RPORT_LISTENER) ?
		    fwd->listen_host : fwd->connect_host;
		अगर (host == शून्य) {
			error("No forward host name.");
			वापस 0;
		}
		अगर (म_माप(host) >= NI_MAXHOST) {
			error("Forward host name too long.");
			वापस 0;
		}
	}

	/* Determine the bind address, cf. channel_fwd_bind_addr() comment */
	addr = channel_fwd_bind_addr(ssh, fwd->listen_host, &wildcard,
	    is_client, fwd_opts);
	debug3_f("type %d wildcard %d addr %s", type, wildcard,
	    (addr == शून्य) ? "NULL" : addr);

	/*
	 * getaddrinfo returns a loopback address if the hostname is
	 * set to NULL and hints.ai_flags is not AI_PASSIVE
	 */
	स_रखो(&hints, 0, माप(hints));
	hints.ai_family = ssh->chanctxt->IPv4or6;
	hints.ai_flags = wildcard ? AI_PASSIVE : 0;
	hints.ai_socktype = SOCK_STREAM;
	snprintf(strport, माप strport, "%d", fwd->listen_port);
	अगर ((r = getaddrinfo(addr, strport, &hints, &aitop)) != 0) {
		अगर (addr == शून्य) {
			/* This really shouldn't happen */
			ssh_packet_disconnect(ssh, "getaddrinfo: fatal error: %s",
			    ssh_gai_strerror(r));
		} अन्यथा {
			error_f("getaddrinfo(%.64s): %s", addr,
			    ssh_gai_strerror(r));
		}
		वापस 0;
	}
	अगर (allocated_listen_port != शून्य)
		*allocated_listen_port = 0;
	क्रम (ai = aitop; ai; ai = ai->ai_next) {
		चयन (ai->ai_family) {
		हाल AF_INET:
			lport_p = &((काष्ठा sockaddr_in *)ai->ai_addr)->
			    sin_port;
			अवरोध;
		हाल AF_INET6:
			lport_p = &((काष्ठा sockaddr_in6 *)ai->ai_addr)->
			    sin6_port;
			अवरोध;
		शेष:
			जारी;
		}
		/*
		 * If allocating a port for -R forwards, then use the
		 * same port for all address families.
		 */
		अगर (type == SSH_CHANNEL_RPORT_LISTENER &&
		    fwd->listen_port == 0 && allocated_listen_port != शून्य &&
		    *allocated_listen_port > 0)
			*lport_p = htons(*allocated_listen_port);

		अगर (getnameinfo(ai->ai_addr, ai->ai_addrlen, ntop, माप(ntop),
		    strport, माप(strport),
		    NI_NUMERICHOST|NI_NUMERICSERV) != 0) {
			error_f("getnameinfo failed");
			जारी;
		}
		/* Create a port to listen for the host. */
		sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		अगर (sock == -1) {
			/* this is no error since kernel may not support ipv6 */
			verbose("socket [%s]:%s: %.100s", ntop, strport,
			    म_त्रुटि(त्रुटि_सं));
			जारी;
		}

		set_reuseaddr(sock);
		अगर (ai->ai_family == AF_INET6)
			sock_set_v6only(sock);

		debug("Local forwarding listening on %s port %s.",
		    ntop, strport);

		/* Bind the socket to the address. */
		अगर (bind(sock, ai->ai_addr, ai->ai_addrlen) == -1) {
			/*
			 * address can be in if use ipv6 address is
			 * already bound
			 */
			अगर (!ai->ai_next)
				error("bind [%s]:%s: %.100s",
				    ntop, strport, म_त्रुटि(त्रुटि_सं));
			अन्यथा
				verbose("bind [%s]:%s: %.100s",
				    ntop, strport, म_त्रुटि(त्रुटि_सं));

			बंद(sock);
			जारी;
		}
		/* Start listening for connections on the socket. */
		अगर (listen(sock, SSH_LISTEN_BACKLOG) == -1) {
			error("listen [%s]:%s: %.100s", ntop, strport,
			    म_त्रुटि(त्रुटि_सं));
			बंद(sock);
			जारी;
		}

		/*
		 * fwd->listen_port == 0 requests a dynamically allocated port -
		 * record what we got.
		 */
		अगर (type == SSH_CHANNEL_RPORT_LISTENER &&
		    fwd->listen_port == 0 &&
		    allocated_listen_port != शून्य &&
		    *allocated_listen_port == 0) {
			*allocated_listen_port = get_local_port(sock);
			debug("Allocated listen port %d",
			    *allocated_listen_port);
		}

		/* Allocate a channel number for the socket. */
		c = channel_new(ssh, "port-listener", type, sock, sock, -1,
		    CHAN_TCP_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT,
		    0, "port listener", 1);
		c->path = xstrdup(host);
		c->host_port = fwd->connect_port;
		c->listening_addr = addr == शून्य ? शून्य : xstrdup(addr);
		अगर (fwd->listen_port == 0 && allocated_listen_port != शून्य &&
		    !(ssh->compat & SSH_BUG_DYNAMIC_RPORT))
			c->listening_port = *allocated_listen_port;
		अन्यथा
			c->listening_port = fwd->listen_port;
		success = 1;
	}
	अगर (success == 0)
		error_f("cannot listen to port: %d", fwd->listen_port);
	freeaddrinfo(aitop);
	वापस success;
}

अटल पूर्णांक
channel_setup_fwd_listener_streamlocal(काष्ठा ssh *ssh, पूर्णांक type,
    काष्ठा Forward *fwd, काष्ठा ForwardOptions *fwd_opts)
{
	काष्ठा sockaddr_un sunaddr;
	स्थिर अक्षर *path;
	Channel *c;
	पूर्णांक port, sock;
	mode_t omask;

	चयन (type) {
	हाल SSH_CHANNEL_UNIX_LISTENER:
		अगर (fwd->connect_path != शून्य) {
			अगर (म_माप(fwd->connect_path) > माप(sunaddr.sun_path)) {
				error("Local connecting path too long: %s",
				    fwd->connect_path);
				वापस 0;
			}
			path = fwd->connect_path;
			port = PORT_STREAMLOCAL;
		} अन्यथा {
			अगर (fwd->connect_host == शून्य) {
				error("No forward host name.");
				वापस 0;
			}
			अगर (म_माप(fwd->connect_host) >= NI_MAXHOST) {
				error("Forward host name too long.");
				वापस 0;
			}
			path = fwd->connect_host;
			port = fwd->connect_port;
		}
		अवरोध;
	हाल SSH_CHANNEL_RUNIX_LISTENER:
		path = fwd->listen_path;
		port = PORT_STREAMLOCAL;
		अवरोध;
	शेष:
		error_f("unexpected channel type %d", type);
		वापस 0;
	}

	अगर (fwd->listen_path == शून्य) {
		error("No forward path name.");
		वापस 0;
	}
	अगर (म_माप(fwd->listen_path) > माप(sunaddr.sun_path)) {
		error("Local listening path too long: %s", fwd->listen_path);
		वापस 0;
	}

	debug3_f("type %d path %s", type, fwd->listen_path);

	/* Start a Unix domain listener. */
	omask = umask(fwd_opts->streamlocal_bind_mask);
	sock = unix_listener(fwd->listen_path, SSH_LISTEN_BACKLOG,
	    fwd_opts->streamlocal_bind_unlink);
	umask(omask);
	अगर (sock < 0)
		वापस 0;

	debug("Local forwarding listening on path %s.", fwd->listen_path);

	/* Allocate a channel number for the socket. */
	c = channel_new(ssh, "unix-listener", type, sock, sock, -1,
	    CHAN_TCP_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT,
	    0, "unix listener", 1);
	c->path = xstrdup(path);
	c->host_port = port;
	c->listening_port = PORT_STREAMLOCAL;
	c->listening_addr = xstrdup(fwd->listen_path);
	वापस 1;
}

अटल पूर्णांक
channel_cancel_rport_listener_tcpip(काष्ठा ssh *ssh,
    स्थिर अक्षर *host, u_short port)
{
	u_int i;
	पूर्णांक found = 0;

	क्रम (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		Channel *c = ssh->chanctxt->channels[i];
		अगर (c == शून्य || c->type != SSH_CHANNEL_RPORT_LISTENER)
			जारी;
		अगर (म_भेद(c->path, host) == 0 && c->listening_port == port) {
			debug2_f("close channel %d", i);
			channel_free(ssh, c);
			found = 1;
		}
	}

	वापस found;
}

अटल पूर्णांक
channel_cancel_rport_listener_streamlocal(काष्ठा ssh *ssh, स्थिर अक्षर *path)
{
	u_int i;
	पूर्णांक found = 0;

	क्रम (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		Channel *c = ssh->chanctxt->channels[i];
		अगर (c == शून्य || c->type != SSH_CHANNEL_RUNIX_LISTENER)
			जारी;
		अगर (c->path == शून्य)
			जारी;
		अगर (म_भेद(c->path, path) == 0) {
			debug2_f("close channel %d", i);
			channel_free(ssh, c);
			found = 1;
		}
	}

	वापस found;
}

पूर्णांक
channel_cancel_rport_listener(काष्ठा ssh *ssh, काष्ठा Forward *fwd)
{
	अगर (fwd->listen_path != शून्य) {
		वापस channel_cancel_rport_listener_streamlocal(ssh,
		    fwd->listen_path);
	} अन्यथा {
		वापस channel_cancel_rport_listener_tcpip(ssh,
		    fwd->listen_host, fwd->listen_port);
	}
}

अटल पूर्णांक
channel_cancel_lport_listener_tcpip(काष्ठा ssh *ssh,
    स्थिर अक्षर *lhost, u_short lport, पूर्णांक cport,
    काष्ठा ForwardOptions *fwd_opts)
{
	u_int i;
	पूर्णांक found = 0;
	स्थिर अक्षर *addr = channel_fwd_bind_addr(ssh, lhost, शून्य, 1, fwd_opts);

	क्रम (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		Channel *c = ssh->chanctxt->channels[i];
		अगर (c == शून्य || c->type != SSH_CHANNEL_PORT_LISTENER)
			जारी;
		अगर (c->listening_port != lport)
			जारी;
		अगर (cport == CHANNEL_CANCEL_PORT_STATIC) {
			/* skip dynamic forwardings */
			अगर (c->host_port == 0)
				जारी;
		} अन्यथा {
			अगर (c->host_port != cport)
				जारी;
		}
		अगर ((c->listening_addr == शून्य && addr != शून्य) ||
		    (c->listening_addr != शून्य && addr == शून्य))
			जारी;
		अगर (addr == शून्य || म_भेद(c->listening_addr, addr) == 0) {
			debug2_f("close channel %d", i);
			channel_free(ssh, c);
			found = 1;
		}
	}

	वापस found;
}

अटल पूर्णांक
channel_cancel_lport_listener_streamlocal(काष्ठा ssh *ssh, स्थिर अक्षर *path)
{
	u_int i;
	पूर्णांक found = 0;

	अगर (path == शून्य) {
		error_f("no path specified.");
		वापस 0;
	}

	क्रम (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		Channel *c = ssh->chanctxt->channels[i];
		अगर (c == शून्य || c->type != SSH_CHANNEL_UNIX_LISTENER)
			जारी;
		अगर (c->listening_addr == शून्य)
			जारी;
		अगर (म_भेद(c->listening_addr, path) == 0) {
			debug2_f("close channel %d", i);
			channel_free(ssh, c);
			found = 1;
		}
	}

	वापस found;
}

पूर्णांक
channel_cancel_lport_listener(काष्ठा ssh *ssh,
    काष्ठा Forward *fwd, पूर्णांक cport, काष्ठा ForwardOptions *fwd_opts)
{
	अगर (fwd->listen_path != शून्य) {
		वापस channel_cancel_lport_listener_streamlocal(ssh,
		    fwd->listen_path);
	} अन्यथा {
		वापस channel_cancel_lport_listener_tcpip(ssh,
		    fwd->listen_host, fwd->listen_port, cport, fwd_opts);
	}
}

/* protocol local port fwd, used by ssh */
पूर्णांक
channel_setup_local_fwd_listener(काष्ठा ssh *ssh,
    काष्ठा Forward *fwd, काष्ठा ForwardOptions *fwd_opts)
{
	अगर (fwd->listen_path != शून्य) {
		वापस channel_setup_fwd_listener_streamlocal(ssh,
		    SSH_CHANNEL_UNIX_LISTENER, fwd, fwd_opts);
	} अन्यथा {
		वापस channel_setup_fwd_listener_tcpip(ssh,
		    SSH_CHANNEL_PORT_LISTENER, fwd, शून्य, fwd_opts);
	}
}

/* Matches a remote forwarding permission against a requested forwarding */
अटल पूर्णांक
remote_open_match(काष्ठा permission *allowed_open, काष्ठा Forward *fwd)
{
	पूर्णांक ret;
	अक्षर *lhost;

	/* XXX add ACLs for streamlocal */
	अगर (fwd->listen_path != शून्य)
		वापस 1;

	अगर (fwd->listen_host == शून्य || allowed_open->listen_host == शून्य)
		वापस 0;

	अगर (allowed_open->listen_port != FWD_PERMIT_ANY_PORT &&
	    allowed_open->listen_port != fwd->listen_port)
		वापस 0;

	/* Match hostnames case-insensitively */
	lhost = xstrdup(fwd->listen_host);
	lowercase(lhost);
	ret = match_pattern(lhost, allowed_open->listen_host);
	मुक्त(lhost);

	वापस ret;
}

/* Checks whether a requested remote forwarding is permitted */
अटल पूर्णांक
check_rfwd_permission(काष्ठा ssh *ssh, काष्ठा Forward *fwd)
{
	काष्ठा ssh_channels *sc = ssh->chanctxt;
	काष्ठा permission_set *pset = &sc->remote_perms;
	u_int i, permit, permit_adm = 1;
	काष्ठा permission *perm;

#अगर_घोषित SKIP_PRIVDROP
	अगर (fwd->listen_path != शून्य)
		वापस 0;
	अगर (fwd->listen_port != 0 && fwd->listen_port < 1024)
		वापस 0;
#पूर्ण_अगर

	/* XXX apply GatewayPorts override before checking? */

	permit = pset->all_permitted;
	अगर (!permit) {
		क्रम (i = 0; i < pset->अंक_permitted_user; i++) {
			perm = &pset->permitted_user[i];
			अगर (remote_open_match(perm, fwd)) {
				permit = 1;
				अवरोध;
			}
		}
	}

	अगर (pset->अंक_permitted_admin > 0) {
		permit_adm = 0;
		क्रम (i = 0; i < pset->अंक_permitted_admin; i++) {
			perm = &pset->permitted_admin[i];
			अगर (remote_open_match(perm, fwd)) {
				permit_adm = 1;
				अवरोध;
			}
		}
	}

	वापस permit && permit_adm;
}

/* protocol v2 remote port fwd, used by sshd */
पूर्णांक
channel_setup_remote_fwd_listener(काष्ठा ssh *ssh, काष्ठा Forward *fwd,
    पूर्णांक *allocated_listen_port, काष्ठा ForwardOptions *fwd_opts)
{
	अगर (!check_rfwd_permission(ssh, fwd)) {
		ssh_packet_send_debug(ssh, "port forwarding refused");
		अगर (fwd->listen_path != शून्य)
			/* XXX always allowed, see remote_open_match() */
			logit("Received request from %.100s port %d to "
			    "remote forward to path \"%.100s\", "
			    "but the request was denied.",
			    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
			    fwd->listen_path);
		अन्यथा अगर(fwd->listen_host != शून्य)
			logit("Received request from %.100s port %d to "
			    "remote forward to host %.100s port %d, "
			    "but the request was denied.",
			    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
			    fwd->listen_host, fwd->listen_port );
		अन्यथा
			logit("Received request from %.100s port %d to remote "
			    "forward, but the request was denied.",
			    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
		वापस 0;
	}
	अगर (fwd->listen_path != शून्य) {
		वापस channel_setup_fwd_listener_streamlocal(ssh,
		    SSH_CHANNEL_RUNIX_LISTENER, fwd, fwd_opts);
	} अन्यथा {
		वापस channel_setup_fwd_listener_tcpip(ssh,
		    SSH_CHANNEL_RPORT_LISTENER, fwd, allocated_listen_port,
		    fwd_opts);
	}
}

/*
 * Translate the requested rfwd listen host to something usable for
 * this server.
 */
अटल स्थिर अक्षर *
channel_rfwd_bind_host(स्थिर अक्षर *listen_host)
{
	अगर (listen_host == शून्य) {
		वापस "localhost";
	} अन्यथा अगर (*listen_host == '\0' || म_भेद(listen_host, "*") == 0) {
		वापस "";
	} अन्यथा
		वापस listen_host;
}

/*
 * Initiate forwarding of connections to port "port" on remote host through
 * the secure channel to host:port from local side.
 * Returns handle (index) for updating the dynamic listen port with
 * channel_update_permission().
 */
पूर्णांक
channel_request_remote_forwarding(काष्ठा ssh *ssh, काष्ठा Forward *fwd)
{
	पूर्णांक r, success = 0, idx = -1;
	स्थिर अक्षर *host_to_connect, *listen_host, *listen_path;
	पूर्णांक port_to_connect, listen_port;

	/* Send the forward request to the remote side. */
	अगर (fwd->listen_path != शून्य) {
		अगर ((r = sshpkt_start(ssh, SSH2_संदेश_GLOBAL_REQUEST)) != 0 ||
		    (r = sshpkt_put_cstring(ssh,
		    "streamlocal-forward@openssh.com")) != 0 ||
		    (r = sshpkt_put_u8(ssh, 1)) != 0 || /* want reply */
		    (r = sshpkt_put_cstring(ssh, fwd->listen_path)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			fatal_fr(r, "request streamlocal");
	} अन्यथा {
		अगर ((r = sshpkt_start(ssh, SSH2_संदेश_GLOBAL_REQUEST)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "tcpip-forward")) != 0 ||
		    (r = sshpkt_put_u8(ssh, 1)) != 0 || /* want reply */
		    (r = sshpkt_put_cstring(ssh,
		    channel_rfwd_bind_host(fwd->listen_host))) != 0 ||
		    (r = sshpkt_put_u32(ssh, fwd->listen_port)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			fatal_fr(r, "request tcpip-forward");
	}
	/* Assume that server accepts the request */
	success = 1;
	अगर (success) {
		/* Record that connection to this host/port is permitted. */
		host_to_connect = listen_host = listen_path = शून्य;
		port_to_connect = listen_port = 0;
		अगर (fwd->connect_path != शून्य) {
			host_to_connect = fwd->connect_path;
			port_to_connect = PORT_STREAMLOCAL;
		} अन्यथा {
			host_to_connect = fwd->connect_host;
			port_to_connect = fwd->connect_port;
		}
		अगर (fwd->listen_path != शून्य) {
			listen_path = fwd->listen_path;
			listen_port = PORT_STREAMLOCAL;
		} अन्यथा {
			listen_host = fwd->listen_host;
			listen_port = fwd->listen_port;
		}
		idx = permission_set_add(ssh, FORWARD_USER, FORWARD_LOCAL,
		    host_to_connect, port_to_connect,
		    listen_host, listen_path, listen_port, शून्य);
	}
	वापस idx;
}

अटल पूर्णांक
open_match(काष्ठा permission *allowed_open, स्थिर अक्षर *requestedhost,
    पूर्णांक requestedport)
{
	अगर (allowed_open->host_to_connect == शून्य)
		वापस 0;
	अगर (allowed_open->port_to_connect != FWD_PERMIT_ANY_PORT &&
	    allowed_open->port_to_connect != requestedport)
		वापस 0;
	अगर (म_भेद(allowed_open->host_to_connect, FWD_PERMIT_ANY_HOST) != 0 &&
	    म_भेद(allowed_open->host_to_connect, requestedhost) != 0)
		वापस 0;
	वापस 1;
}

/*
 * Note that in the listen host/port case
 * we don't support FWD_PERMIT_ANY_PORT and
 * need to translate between the configured-host (listen_host)
 * and what we've sent to the remote server (channel_rfwd_bind_host)
 */
अटल पूर्णांक
open_listen_match_tcpip(काष्ठा permission *allowed_open,
    स्थिर अक्षर *requestedhost, u_short requestedport, पूर्णांक translate)
{
	स्थिर अक्षर *allowed_host;

	अगर (allowed_open->host_to_connect == शून्य)
		वापस 0;
	अगर (allowed_open->listen_port != requestedport)
		वापस 0;
	अगर (!translate && allowed_open->listen_host == शून्य &&
	    requestedhost == शून्य)
		वापस 1;
	allowed_host = translate ?
	    channel_rfwd_bind_host(allowed_open->listen_host) :
	    allowed_open->listen_host;
	अगर (allowed_host == शून्य || requestedhost == शून्य ||
	    म_भेद(allowed_host, requestedhost) != 0)
		वापस 0;
	वापस 1;
}

अटल पूर्णांक
open_listen_match_streamlocal(काष्ठा permission *allowed_open,
    स्थिर अक्षर *requestedpath)
{
	अगर (allowed_open->host_to_connect == शून्य)
		वापस 0;
	अगर (allowed_open->listen_port != PORT_STREAMLOCAL)
		वापस 0;
	अगर (allowed_open->listen_path == शून्य ||
	    म_भेद(allowed_open->listen_path, requestedpath) != 0)
		वापस 0;
	वापस 1;
}

/*
 * Request cancellation of remote forwarding of connection host:port from
 * local side.
 */
अटल पूर्णांक
channel_request_rforward_cancel_tcpip(काष्ठा ssh *ssh,
    स्थिर अक्षर *host, u_short port)
{
	काष्ठा ssh_channels *sc = ssh->chanctxt;
	काष्ठा permission_set *pset = &sc->local_perms;
	पूर्णांक r;
	u_int i;
	काष्ठा permission *perm = शून्य;

	क्रम (i = 0; i < pset->अंक_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		अगर (open_listen_match_tcpip(perm, host, port, 0))
			अवरोध;
		perm = शून्य;
	}
	अगर (perm == शून्य) {
		debug_f("requested forward not found");
		वापस -1;
	}
	अगर ((r = sshpkt_start(ssh, SSH2_संदेश_GLOBAL_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "cancel-tcpip-forward")) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 || /* want reply */
	    (r = sshpkt_put_cstring(ssh, channel_rfwd_bind_host(host))) != 0 ||
	    (r = sshpkt_put_u32(ssh, port)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send cancel");

	fwd_perm_clear(perm); /* unregister */

	वापस 0;
}

/*
 * Request cancellation of remote forwarding of Unix domain socket
 * path from local side.
 */
अटल पूर्णांक
channel_request_rforward_cancel_streamlocal(काष्ठा ssh *ssh, स्थिर अक्षर *path)
{
	काष्ठा ssh_channels *sc = ssh->chanctxt;
	काष्ठा permission_set *pset = &sc->local_perms;
	पूर्णांक r;
	u_int i;
	काष्ठा permission *perm = शून्य;

	क्रम (i = 0; i < pset->अंक_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		अगर (open_listen_match_streamlocal(perm, path))
			अवरोध;
		perm = शून्य;
	}
	अगर (perm == शून्य) {
		debug_f("requested forward not found");
		वापस -1;
	}
	अगर ((r = sshpkt_start(ssh, SSH2_संदेश_GLOBAL_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh,
	    "cancel-streamlocal-forward@openssh.com")) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 || /* want reply */
	    (r = sshpkt_put_cstring(ssh, path)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send cancel");

	fwd_perm_clear(perm); /* unregister */

	वापस 0;
}

/*
 * Request cancellation of remote forwarding of a connection from local side.
 */
पूर्णांक
channel_request_rforward_cancel(काष्ठा ssh *ssh, काष्ठा Forward *fwd)
{
	अगर (fwd->listen_path != शून्य) {
		वापस channel_request_rforward_cancel_streamlocal(ssh,
		    fwd->listen_path);
	} अन्यथा {
		वापस channel_request_rforward_cancel_tcpip(ssh,
		    fwd->listen_host,
		    fwd->listen_port ? fwd->listen_port : fwd->allocated_port);
	}
}

/*
 * Permits opening to any host/port if permitted_user[] is empty.  This is
 * usually called by the server, because the user could connect to any port
 * anyway, and the server has no way to know but to trust the client anyway.
 */
व्योम
channel_permit_all(काष्ठा ssh *ssh, पूर्णांक where)
{
	काष्ठा permission_set *pset = permission_set_get(ssh, where);

	अगर (pset->अंक_permitted_user == 0)
		pset->all_permitted = 1;
}

/*
 * Permit the specified host/port for forwarding.
 */
व्योम
channel_add_permission(काष्ठा ssh *ssh, पूर्णांक who, पूर्णांक where,
    अक्षर *host, पूर्णांक port)
{
	पूर्णांक local = where == FORWARD_LOCAL;
	काष्ठा permission_set *pset = permission_set_get(ssh, where);

	debug("allow %s forwarding to host %s port %d",
	    fwd_ident(who, where), host, port);
	/*
	 * Remote forwards set listen_host/port, local forwards set
	 * host/port_to_connect.
	 */
	permission_set_add(ssh, who, where,
	    local ? host : शून्य, local ? port : 0,
	    local ? शून्य : host, शून्य, local ? 0 : port, शून्य);
	pset->all_permitted = 0;
}

/*
 * Administratively disable forwarding.
 */
व्योम
channel_disable_admin(काष्ठा ssh *ssh, पूर्णांक where)
{
	channel_clear_permission(ssh, FORWARD_ADM, where);
	permission_set_add(ssh, FORWARD_ADM, where,
	    शून्य, 0, शून्य, शून्य, 0, शून्य);
}

/*
 * Clear a list of permitted opens.
 */
व्योम
channel_clear_permission(काष्ठा ssh *ssh, पूर्णांक who, पूर्णांक where)
{
	काष्ठा permission **permp;
	u_int i, *npermp;

	permission_set_get_array(ssh, who, where, &permp, &npermp);
	क्रम (i = 0; i < *npermp; i++)
		fwd_perm_clear((*permp) + i);
	मुक्त(*permp);
	*permp = शून्य;
	*npermp = 0;
}

/*
 * Update the listen port for a dynamic remote forward, after
 * the actual 'newport' has been allocated. If 'newport' < 0 is
 * passed then they entry will be invalidated.
 */
व्योम
channel_update_permission(काष्ठा ssh *ssh, पूर्णांक idx, पूर्णांक newport)
{
	काष्ठा permission_set *pset = &ssh->chanctxt->local_perms;

	अगर (idx < 0 || (u_int)idx >= pset->अंक_permitted_user) {
		debug_f("index out of range: %d num_permitted_user %d",
		    idx, pset->अंक_permitted_user);
		वापस;
	}
	debug("%s allowed port %d for forwarding to host %s port %d",
	    newport > 0 ? "Updating" : "Removing",
	    newport,
	    pset->permitted_user[idx].host_to_connect,
	    pset->permitted_user[idx].port_to_connect);
	अगर (newport <= 0)
		fwd_perm_clear(&pset->permitted_user[idx]);
	अन्यथा {
		pset->permitted_user[idx].listen_port =
		    (ssh->compat & SSH_BUG_DYNAMIC_RPORT) ? 0 : newport;
	}
}

/* Try to start non-blocking connect to next host in cctx list */
अटल पूर्णांक
connect_अग्र(काष्ठा ssh *ssh, काष्ठा channel_connect *cctx)
{
	पूर्णांक sock, sock_is_network, saved_errno;
	काष्ठा sockaddr_un *sunaddr;
	अक्षर ntop[NI_MAXHOST];
	अक्षर strport[MAXIMUM(NI_MAXSERV, माप(sunaddr->sun_path))];

	क्रम (; cctx->ai; cctx->ai = cctx->ai->ai_next) {
		sock_is_network = 0;
		चयन (cctx->ai->ai_family) {
		हाल AF_UNIX:
			/* unix:pathname instead of host:port */
			sunaddr = (काष्ठा sockaddr_un *)cctx->ai->ai_addr;
			strlcpy(ntop, "unix", माप(ntop));
			strlcpy(strport, sunaddr->sun_path, माप(strport));
			अवरोध;
		हाल AF_INET:
		हाल AF_INET6:
			अगर (getnameinfo(cctx->ai->ai_addr, cctx->ai->ai_addrlen,
			    ntop, माप(ntop), strport, माप(strport),
			    NI_NUMERICHOST|NI_NUMERICSERV) != 0) {
				error_f("getnameinfo failed");
				जारी;
			}
			sock_is_network = 1;
			अवरोध;
		शेष:
			जारी;
		}
		debug_f("start for host %.100s ([%.100s]:%s)",
		    cctx->host, ntop, strport);
		अगर ((sock = socket(cctx->ai->ai_family, cctx->ai->ai_socktype,
		    cctx->ai->ai_protocol)) == -1) {
			अगर (cctx->ai->ai_next == शून्य)
				error("socket: %.100s", म_त्रुटि(त्रुटि_सं));
			अन्यथा
				verbose("socket: %.100s", म_त्रुटि(त्रुटि_सं));
			जारी;
		}
		अगर (set_nonblock(sock) == -1)
			fatal_f("set_nonblock(%d)", sock);
		अगर (sock_is_network && ssh->chanctxt->want_tcp_keepalive)
			set_keepalive(sock); /* logs errors */
		अगर (connect(sock, cctx->ai->ai_addr,
		    cctx->ai->ai_addrlen) == -1 && त्रुटि_सं != EINPROGRESS) {
			debug_f("host %.100s ([%.100s]:%s): %.100s",
			    cctx->host, ntop, strport, म_त्रुटि(त्रुटि_सं));
			saved_errno = त्रुटि_सं;
			बंद(sock);
			त्रुटि_सं = saved_errno;
			जारी;	/* fail -- try next */
		}
		अगर (cctx->ai->ai_family != AF_UNIX)
			set_nodelay(sock);
		debug_f("connect host %.100s ([%.100s]:%s) in progress, fd=%d",
		    cctx->host, ntop, strport, sock);
		cctx->ai = cctx->ai->ai_next;
		वापस sock;
	}
	वापस -1;
}

/*
 * Return connecting socket to remote host:port or local socket path,
 * passing back the failure reason if appropriate.
 */
अटल पूर्णांक
connect_to_helper(काष्ठा ssh *ssh, स्थिर अक्षर *name, पूर्णांक port, पूर्णांक socktype,
    अक्षर *ctype, अक्षर *rname, काष्ठा channel_connect *cctx,
    पूर्णांक *reason, स्थिर अक्षर **errmsg)
{
	काष्ठा addrinfo hints;
	पूर्णांक gaierr;
	पूर्णांक sock = -1;
	अक्षर strport[NI_MAXSERV];

	अगर (port == PORT_STREAMLOCAL) {
		काष्ठा sockaddr_un *sunaddr;
		काष्ठा addrinfo *ai;

		अगर (म_माप(name) > माप(sunaddr->sun_path)) {
			error("%.100s: %.100s", name, म_त्रुटि(ENAMETOOLONG));
			वापस -1;
		}

		/*
		 * Fake up a struct addrinfo for AF_UNIX connections.
		 * free_connect_ctx() must check ai_family
		 * and use free() not freeaddrinfo() for AF_UNIX.
		 */
		ai = xcalloc(1, माप(*ai) + माप(*sunaddr));
		ai->ai_addr = (काष्ठा sockaddr *)(ai + 1);
		ai->ai_addrlen = माप(*sunaddr);
		ai->ai_family = AF_UNIX;
		ai->ai_socktype = socktype;
		ai->ai_protocol = PF_UNSPEC;
		sunaddr = (काष्ठा sockaddr_un *)ai->ai_addr;
		sunaddr->sun_family = AF_UNIX;
		strlcpy(sunaddr->sun_path, name, माप(sunaddr->sun_path));
		cctx->aitop = ai;
	} अन्यथा {
		स_रखो(&hints, 0, माप(hints));
		hints.ai_family = ssh->chanctxt->IPv4or6;
		hints.ai_socktype = socktype;
		snprintf(strport, माप strport, "%d", port);
		अगर ((gaierr = getaddrinfo(name, strport, &hints, &cctx->aitop))
		    != 0) {
			अगर (errmsg != शून्य)
				*errmsg = ssh_gai_strerror(gaierr);
			अगर (reason != शून्य)
				*reason = SSH2_OPEN_CONNECT_FAILED;
			error("connect_to %.100s: unknown host (%s)", name,
			    ssh_gai_strerror(gaierr));
			वापस -1;
		}
	}

	cctx->host = xstrdup(name);
	cctx->port = port;
	cctx->ai = cctx->aitop;

	अगर ((sock = connect_अग्र(ssh, cctx)) == -1) {
		error("connect to %.100s port %d failed: %s",
		    name, port, म_त्रुटि(त्रुटि_सं));
		वापस -1;
	}

	वापस sock;
}

/* Return CONNECTING channel to remote host:port or local socket path */
अटल Channel *
connect_to(काष्ठा ssh *ssh, स्थिर अक्षर *host, पूर्णांक port,
    अक्षर *ctype, अक्षर *rname)
{
	काष्ठा channel_connect cctx;
	Channel *c;
	पूर्णांक sock;

	स_रखो(&cctx, 0, माप(cctx));
	sock = connect_to_helper(ssh, host, port, SOCK_STREAM, ctype, rname,
	    &cctx, शून्य, शून्य);
	अगर (sock == -1) {
		free_connect_ctx(&cctx);
		वापस शून्य;
	}
	c = channel_new(ssh, ctype, SSH_CHANNEL_CONNECTING, sock, sock, -1,
	    CHAN_TCP_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, rname, 1);
	c->host_port = port;
	c->path = xstrdup(host);
	c->connect_ctx = xmalloc(माप(cctx));
	स_नकल(c->connect_ctx, &cctx, माप(cctx));

	वापस c;
}

/*
 * returns either the newly connected channel or the downstream channel
 * that needs to deal with this connection.
 */
Channel *
channel_connect_by_listen_address(काष्ठा ssh *ssh, स्थिर अक्षर *listen_host,
    u_short listen_port, अक्षर *ctype, अक्षर *rname)
{
	काष्ठा ssh_channels *sc = ssh->chanctxt;
	काष्ठा permission_set *pset = &sc->local_perms;
	u_int i;
	काष्ठा permission *perm;

	क्रम (i = 0; i < pset->अंक_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		अगर (open_listen_match_tcpip(perm,
		    listen_host, listen_port, 1)) {
			अगर (perm->downstream)
				वापस perm->downstream;
			अगर (perm->port_to_connect == 0)
				वापस rdynamic_connect_prepare(ssh,
				    ctype, rname);
			वापस connect_to(ssh,
			    perm->host_to_connect, perm->port_to_connect,
			    ctype, rname);
		}
	}
	error("WARNING: Server requests forwarding for unknown listen_port %d",
	    listen_port);
	वापस शून्य;
}

Channel *
channel_connect_by_listen_path(काष्ठा ssh *ssh, स्थिर अक्षर *path,
    अक्षर *ctype, अक्षर *rname)
{
	काष्ठा ssh_channels *sc = ssh->chanctxt;
	काष्ठा permission_set *pset = &sc->local_perms;
	u_int i;
	काष्ठा permission *perm;

	क्रम (i = 0; i < pset->अंक_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		अगर (open_listen_match_streamlocal(perm, path)) {
			वापस connect_to(ssh,
			    perm->host_to_connect, perm->port_to_connect,
			    ctype, rname);
		}
	}
	error("WARNING: Server requests forwarding for unknown path %.100s",
	    path);
	वापस शून्य;
}

/* Check if connecting to that port is permitted and connect. */
Channel *
channel_connect_to_port(काष्ठा ssh *ssh, स्थिर अक्षर *host, u_short port,
    अक्षर *ctype, अक्षर *rname, पूर्णांक *reason, स्थिर अक्षर **errmsg)
{
	काष्ठा ssh_channels *sc = ssh->chanctxt;
	काष्ठा permission_set *pset = &sc->local_perms;
	काष्ठा channel_connect cctx;
	Channel *c;
	u_int i, permit, permit_adm = 1;
	पूर्णांक sock;
	काष्ठा permission *perm;

	permit = pset->all_permitted;
	अगर (!permit) {
		क्रम (i = 0; i < pset->अंक_permitted_user; i++) {
			perm = &pset->permitted_user[i];
			अगर (open_match(perm, host, port)) {
				permit = 1;
				अवरोध;
			}
		}
	}

	अगर (pset->अंक_permitted_admin > 0) {
		permit_adm = 0;
		क्रम (i = 0; i < pset->अंक_permitted_admin; i++) {
			perm = &pset->permitted_admin[i];
			अगर (open_match(perm, host, port)) {
				permit_adm = 1;
				अवरोध;
			}
		}
	}

	अगर (!permit || !permit_adm) {
		logit("Received request from %.100s port %d to connect to "
		    "host %.100s port %d, but the request was denied.",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh), host, port);
		अगर (reason != शून्य)
			*reason = SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED;
		वापस शून्य;
	}

	स_रखो(&cctx, 0, माप(cctx));
	sock = connect_to_helper(ssh, host, port, SOCK_STREAM, ctype, rname,
	    &cctx, reason, errmsg);
	अगर (sock == -1) {
		free_connect_ctx(&cctx);
		वापस शून्य;
	}

	c = channel_new(ssh, ctype, SSH_CHANNEL_CONNECTING, sock, sock, -1,
	    CHAN_TCP_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, rname, 1);
	c->host_port = port;
	c->path = xstrdup(host);
	c->connect_ctx = xmalloc(माप(cctx));
	स_नकल(c->connect_ctx, &cctx, माप(cctx));

	वापस c;
}

/* Check if connecting to that path is permitted and connect. */
Channel *
channel_connect_to_path(काष्ठा ssh *ssh, स्थिर अक्षर *path,
    अक्षर *ctype, अक्षर *rname)
{
	काष्ठा ssh_channels *sc = ssh->chanctxt;
	काष्ठा permission_set *pset = &sc->local_perms;
	u_int i, permit, permit_adm = 1;
	काष्ठा permission *perm;

	permit = pset->all_permitted;
	अगर (!permit) {
		क्रम (i = 0; i < pset->अंक_permitted_user; i++) {
			perm = &pset->permitted_user[i];
			अगर (open_match(perm, path, PORT_STREAMLOCAL)) {
				permit = 1;
				अवरोध;
			}
		}
	}

	अगर (pset->अंक_permitted_admin > 0) {
		permit_adm = 0;
		क्रम (i = 0; i < pset->अंक_permitted_admin; i++) {
			perm = &pset->permitted_admin[i];
			अगर (open_match(perm, path, PORT_STREAMLOCAL)) {
				permit_adm = 1;
				अवरोध;
			}
		}
	}

	अगर (!permit || !permit_adm) {
		logit("Received request to connect to path %.100s, "
		    "but the request was denied.", path);
		वापस शून्य;
	}
	वापस connect_to(ssh, path, PORT_STREAMLOCAL, ctype, rname);
}

व्योम
channel_send_window_changes(काष्ठा ssh *ssh)
{
	काष्ठा ssh_channels *sc = ssh->chanctxt;
	काष्ठा winsize ws;
	पूर्णांक r;
	u_int i;

	क्रम (i = 0; i < sc->channels_alloc; i++) {
		अगर (sc->channels[i] == शून्य || !sc->channels[i]->client_tty ||
		    sc->channels[i]->type != SSH_CHANNEL_OPEN)
			जारी;
		अगर (ioctl(sc->channels[i]->rfd, TIOCGWINSZ, &ws) == -1)
			जारी;
		channel_request_start(ssh, i, "window-change", 0);
		अगर ((r = sshpkt_put_u32(ssh, (u_int)ws.ws_col)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_row)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_xpixel)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_ypixel)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "channel %u; send window-change", i);
	}
}

/* Return RDYNAMIC_OPEN channel: channel allows SOCKS, but is not connected */
अटल Channel *
rdynamic_connect_prepare(काष्ठा ssh *ssh, अक्षर *ctype, अक्षर *rname)
{
	Channel *c;
	पूर्णांक r;

	c = channel_new(ssh, ctype, SSH_CHANNEL_RDYNAMIC_OPEN, -1, -1, -1,
	    CHAN_TCP_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, rname, 1);
	c->host_port = 0;
	c->path = शून्य;

	/*
	 * We need to open the channel before we have a FD,
	 * so that we can get SOCKS header from peer.
	 */
	अगर ((r = sshpkt_start(ssh, SSH2_संदेश_CHANNEL_OPEN_CONFIRMATION)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_window)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0)
		fatal_fr(r, "channel %i; confirm", c->self);
	वापस c;
}

/* Return CONNECTING socket to remote host:port or local socket path */
अटल पूर्णांक
rdynamic_connect_finish(काष्ठा ssh *ssh, Channel *c)
{
	काष्ठा ssh_channels *sc = ssh->chanctxt;
	काष्ठा permission_set *pset = &sc->local_perms;
	काष्ठा permission *perm;
	काष्ठा channel_connect cctx;
	u_int i, permit_adm = 1;
	पूर्णांक sock;

	अगर (pset->अंक_permitted_admin > 0) {
		permit_adm = 0;
		क्रम (i = 0; i < pset->अंक_permitted_admin; i++) {
			perm = &pset->permitted_admin[i];
			अगर (open_match(perm, c->path, c->host_port)) {
				permit_adm = 1;
				अवरोध;
			}
		}
	}
	अगर (!permit_adm) {
		debug_f("requested forward not permitted");
		वापस -1;
	}

	स_रखो(&cctx, 0, माप(cctx));
	sock = connect_to_helper(ssh, c->path, c->host_port, SOCK_STREAM, शून्य,
	    शून्य, &cctx, शून्य, शून्य);
	अगर (sock == -1)
		free_connect_ctx(&cctx);
	अन्यथा {
		/* similar to SSH_CHANNEL_CONNECTING but we've already sent the open */
		c->type = SSH_CHANNEL_RDYNAMIC_FINISH;
		c->connect_ctx = xmalloc(माप(cctx));
		स_नकल(c->connect_ctx, &cctx, माप(cctx));
		channel_register_fds(ssh, c, sock, sock, -1, 0, 1, 0);
	}
	वापस sock;
}

/* -- X11 forwarding */

/*
 * Creates an internet domain socket for listening for X11 connections.
 * Returns 0 and a suitable display number for the DISPLAY variable
 * stored in display_numberp , or -1 if an error occurs.
 */
पूर्णांक
x11_create_display_inet(काष्ठा ssh *ssh, पूर्णांक x11_display_offset,
    पूर्णांक x11_use_localhost, पूर्णांक single_connection,
    u_int *display_numberp, पूर्णांक **chanids)
{
	Channel *nc = शून्य;
	पूर्णांक display_संख्या, sock, port;
	काष्ठा addrinfo hints, *ai, *aitop;
	अक्षर strport[NI_MAXSERV];
	पूर्णांक gaierr, n, अंक_socks = 0, socks[अंक_SOCKS];

	अगर (chanids == शून्य || x11_display_offset < 0 ||
	    x11_display_offset > UINT16_MAX - X11_BASE_PORT - MAX_DISPLAYS)
		वापस -1;

	क्रम (display_संख्या = x11_display_offset;
	    display_संख्या < x11_display_offset + MAX_DISPLAYS;
	    display_संख्या++) {
		port = X11_BASE_PORT + display_संख्या;
		स_रखो(&hints, 0, माप(hints));
		hints.ai_family = ssh->chanctxt->IPv4or6;
		hints.ai_flags = x11_use_localhost ? 0: AI_PASSIVE;
		hints.ai_socktype = SOCK_STREAM;
		snprintf(strport, माप strport, "%d", port);
		अगर ((gaierr = getaddrinfo(शून्य, strport,
		    &hints, &aitop)) != 0) {
			error("getaddrinfo: %.100s", ssh_gai_strerror(gaierr));
			वापस -1;
		}
		क्रम (ai = aitop; ai; ai = ai->ai_next) {
			अगर (ai->ai_family != AF_INET &&
			    ai->ai_family != AF_INET6)
				जारी;
			sock = socket(ai->ai_family, ai->ai_socktype,
			    ai->ai_protocol);
			अगर (sock == -1) {
				अगर ((त्रुटि_सं != EINVAL) && (त्रुटि_सं != EAFNOSUPPORT)
#अगर_घोषित EPFNOSUPPORT
				    && (त्रुटि_सं != EPFNOSUPPORT)
#पूर्ण_अगर 
				    ) {
					error("socket: %.100s", म_त्रुटि(त्रुटि_सं));
					freeaddrinfo(aitop);
					वापस -1;
				} अन्यथा {
					debug("x11_create_display_inet: Socket family %d not supported",
						 ai->ai_family);
					जारी;
				}
			}
			अगर (ai->ai_family == AF_INET6)
				sock_set_v6only(sock);
			अगर (x11_use_localhost)
				set_reuseaddr(sock);
			अगर (bind(sock, ai->ai_addr, ai->ai_addrlen) == -1) {
				debug2_f("bind port %d: %.100s", port,
				    म_त्रुटि(त्रुटि_सं));
				बंद(sock);
				क्रम (n = 0; n < अंक_socks; n++)
					बंद(socks[n]);
				अंक_socks = 0;
				अवरोध;
			}
			socks[अंक_socks++] = sock;
			अगर (अंक_socks == अंक_SOCKS)
				अवरोध;
		}
		freeaddrinfo(aitop);
		अगर (अंक_socks > 0)
			अवरोध;
	}
	अगर (display_संख्या >= x11_display_offset + MAX_DISPLAYS) {
		error("Failed to allocate internet-domain X11 display socket.");
		वापस -1;
	}
	/* Start listening for connections on the socket. */
	क्रम (n = 0; n < अंक_socks; n++) {
		sock = socks[n];
		अगर (listen(sock, SSH_LISTEN_BACKLOG) == -1) {
			error("listen: %.100s", म_त्रुटि(त्रुटि_सं));
			बंद(sock);
			वापस -1;
		}
	}

	/* Allocate a channel for each socket. */
	*chanids = xcalloc(अंक_socks + 1, माप(**chanids));
	क्रम (n = 0; n < अंक_socks; n++) {
		sock = socks[n];
		nc = channel_new(ssh, "x11-listener",
		    SSH_CHANNEL_X11_LISTENER, sock, sock, -1,
		    CHAN_X11_WINDOW_DEFAULT, CHAN_X11_PACKET_DEFAULT,
		    0, "X11 inet listener", 1);
		nc->single_connection = single_connection;
		(*chanids)[n] = nc->self;
	}
	(*chanids)[n] = -1;

	/* Return the display number for the DISPLAY environment variable. */
	*display_numberp = display_संख्या;
	वापस 0;
}

अटल पूर्णांक
connect_local_xsocket_path(स्थिर अक्षर *pathname)
{
	पूर्णांक sock;
	काष्ठा sockaddr_un addr;

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	अगर (sock == -1) {
		error("socket: %.100s", म_त्रुटि(त्रुटि_सं));
		वापस -1;
	}
	स_रखो(&addr, 0, माप(addr));
	addr.sun_family = AF_UNIX;
	strlcpy(addr.sun_path, pathname, माप addr.sun_path);
	अगर (connect(sock, (काष्ठा sockaddr *)&addr, माप(addr)) == 0)
		वापस sock;
	बंद(sock);
	error("connect %.100s: %.100s", addr.sun_path, म_त्रुटि(त्रुटि_सं));
	वापस -1;
}

अटल पूर्णांक
connect_local_xsocket(u_int dnr)
{
	अक्षर buf[1024];
	snprintf(buf, माप buf, _PATH_UNIX_X, dnr);
	वापस connect_local_xsocket_path(buf);
}

#अगर_घोषित __APPLE__
अटल पूर्णांक
is_path_to_xsocket(स्थिर अक्षर *display, अक्षर *path, माप_प्रकार pathlen)
{
	काष्ठा stat sbuf;

	अगर (strlcpy(path, display, pathlen) >= pathlen) {
		error_f("display path too long");
		वापस 0;
	}
	अगर (display[0] != '/')
		वापस 0;
	अगर (stat(path, &sbuf) == 0) {
		वापस 1;
	} अन्यथा {
		अक्षर *dot = म_खोजप(path, '.');
		अगर (dot != शून्य) {
			*dot = '\0';
			अगर (stat(path, &sbuf) == 0) {
				वापस 1;
			}
		}
	}
	वापस 0;
}
#पूर्ण_अगर

पूर्णांक
x11_connect_display(काष्ठा ssh *ssh)
{
	u_int display_संख्या;
	स्थिर अक्षर *display;
	अक्षर buf[1024], *cp;
	काष्ठा addrinfo hints, *ai, *aitop;
	अक्षर strport[NI_MAXSERV];
	पूर्णांक gaierr, sock = 0;

	/* Try to open a socket for the local X server. */
	display = दो_पर्या("DISPLAY");
	अगर (!display) {
		error("DISPLAY not set.");
		वापस -1;
	}
	/*
	 * Now we decode the value of the DISPLAY variable and make a
	 * connection to the real X server.
	 */

#अगर_घोषित __APPLE__
	/* Check if display is a path to a socket (as set by launchd). */
	{
		अक्षर path[PATH_MAX];

		अगर (is_path_to_xsocket(display, path, माप(path))) {
			debug("x11_connect_display: $DISPLAY is launchd");

			/* Create a socket. */
			sock = connect_local_xsocket_path(path);
			अगर (sock < 0)
				वापस -1;

			/* OK, we now have a connection to the display. */
			वापस sock;
		}
	}
#पूर्ण_अगर
	/*
	 * Check if it is a unix domain socket.  Unix domain displays are in
	 * one of the following formats: unix:d[.s], :d[.s], ::d[.s]
	 */
	अगर (म_भेदन(display, "unix:", 5) == 0 ||
	    display[0] == ':') {
		/* Connect to the unix domain socket. */
		अगर (माला_पूछो(म_खोजप(display, ':') + 1, "%u",
		    &display_संख्या) != 1) {
			error("Could not parse display number from DISPLAY: "
			    "%.100s", display);
			वापस -1;
		}
		/* Create a socket. */
		sock = connect_local_xsocket(display_संख्या);
		अगर (sock < 0)
			वापस -1;

		/* OK, we now have a connection to the display. */
		वापस sock;
	}
	/*
	 * Connect to an inet socket.  The DISPLAY value is supposedly
	 * hostname:d[.s], where hostname may also be numeric IP address.
	 */
	strlcpy(buf, display, माप(buf));
	cp = म_अक्षर(buf, ':');
	अगर (!cp) {
		error("Could not find ':' in DISPLAY: %.100s", display);
		वापस -1;
	}
	*cp = 0;
	/*
	 * buf now contains the host name.  But first we parse the
	 * display number.
	 */
	अगर (माला_पूछो(cp + 1, "%u", &display_संख्या) != 1 ||
	    display_संख्या > UINT16_MAX - X11_BASE_PORT) {
		error("Could not parse display number from DISPLAY: %.100s",
		    display);
		वापस -1;
	}

	/* Look up the host address */
	स_रखो(&hints, 0, माप(hints));
	hints.ai_family = ssh->chanctxt->IPv4or6;
	hints.ai_socktype = SOCK_STREAM;
	snprintf(strport, माप strport, "%u", X11_BASE_PORT + display_संख्या);
	अगर ((gaierr = getaddrinfo(buf, strport, &hints, &aitop)) != 0) {
		error("%.100s: unknown host. (%s)", buf,
		ssh_gai_strerror(gaierr));
		वापस -1;
	}
	क्रम (ai = aitop; ai; ai = ai->ai_next) {
		/* Create a socket. */
		sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		अगर (sock == -1) {
			debug2("socket: %.100s", म_त्रुटि(त्रुटि_सं));
			जारी;
		}
		/* Connect it to the display. */
		अगर (connect(sock, ai->ai_addr, ai->ai_addrlen) == -1) {
			debug2("connect %.100s port %u: %.100s", buf,
			    X11_BASE_PORT + display_संख्या, म_त्रुटि(त्रुटि_सं));
			बंद(sock);
			जारी;
		}
		/* Success */
		अवरोध;
	}
	freeaddrinfo(aitop);
	अगर (!ai) {
		error("connect %.100s port %u: %.100s", buf,
		    X11_BASE_PORT + display_संख्या, म_त्रुटि(त्रुटि_सं));
		वापस -1;
	}
	set_nodelay(sock);
	वापस sock;
}

/*
 * Requests forwarding of X11 connections, generates fake authentication
 * data, and enables authentication spoofing.
 * This should be called in the client only.
 */
व्योम
x11_request_forwarding_with_spoofing(काष्ठा ssh *ssh, पूर्णांक client_session_id,
    स्थिर अक्षर *disp, स्थिर अक्षर *proto, स्थिर अक्षर *तथ्य, पूर्णांक want_reply)
{
	काष्ठा ssh_channels *sc = ssh->chanctxt;
	u_int तथ्य_len = (u_int) म_माप(तथ्य) / 2;
	u_int i, मूल्य;
	स्थिर अक्षर *cp;
	अक्षर *new_तथ्य;
	पूर्णांक r, screen_संख्या;

	अगर (sc->x11_saved_display == शून्य)
		sc->x11_saved_display = xstrdup(disp);
	अन्यथा अगर (म_भेद(disp, sc->x11_saved_display) != 0) {
		error("x11_request_forwarding_with_spoofing: different "
		    "$DISPLAY already forwarded");
		वापस;
	}

	cp = म_अक्षर(disp, ':');
	अगर (cp)
		cp = म_अक्षर(cp, '.');
	अगर (cp)
		screen_संख्या = (u_int)strtonum(cp + 1, 0, 400, शून्य);
	अन्यथा
		screen_संख्या = 0;

	अगर (sc->x11_saved_proto == शून्य) {
		/* Save protocol name. */
		sc->x11_saved_proto = xstrdup(proto);

		/* Extract real authentication data. */
		sc->x11_saved_तथ्य = xmalloc(तथ्य_len);
		क्रम (i = 0; i < तथ्य_len; i++) {
			अगर (माला_पूछो(तथ्य + 2 * i, "%2x", &मूल्य) != 1) {
				fatal("x11_request_forwarding: bad "
				    "authentication data: %.100s", तथ्य);
			}
			sc->x11_saved_तथ्य[i] = मूल्य;
		}
		sc->x11_saved_तथ्य_len = तथ्य_len;

		/* Generate fake data of the same length. */
		sc->x11_fake_तथ्य = xmalloc(तथ्य_len);
		arc4random_buf(sc->x11_fake_तथ्य, तथ्य_len);
		sc->x11_fake_तथ्य_len = तथ्य_len;
	}

	/* Convert the fake data into hex. */
	new_तथ्य = tohex(sc->x11_fake_तथ्य, तथ्य_len);

	/* Send the request packet. */
	channel_request_start(ssh, client_session_id, "x11-req", want_reply);
	अगर ((r = sshpkt_put_u8(ssh, 0)) != 0 || /* bool: single connection */
	    (r = sshpkt_put_cstring(ssh, proto)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, new_तथ्य)) != 0 ||
	    (r = sshpkt_put_u32(ssh, screen_संख्या)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send x11-req");
	मुक्त(new_तथ्य);
}

/*
 * Returns whether an x11 channel was used recently (less than a second ago)
 */
पूर्णांक
x11_channel_used_recently(काष्ठा ssh *ssh) {
	u_int i;
	Channel *c;
	द्विगुन lastused = 0;

	क्रम (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		अगर (c == शून्य || c->ctype == शून्य || c->lastused == 0.0 ||
		    म_भेद(c->ctype, "x11-connection") != 0)
			जारी;
		अगर (c->lastused > lastused)
			lastused = c->lastused;
	}
	वापस lastused != 0.0 && monotime_double() <= lastused + 1.0;
}
