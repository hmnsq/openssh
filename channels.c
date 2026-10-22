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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/stat.h>
#अन्तर्भाव <sys/ioctl.h>
#अन्तर्भाव <sys/un.h>
#अन्तर्भाव <sys/socket.h>
#अन्तर्भाव <sys/queue.h>

#अन्तर्भाव <netinet/in.h>
#अन्तर्भाव <arpa/inet.h>

#अन्तर्भाव <errno.h>
#अन्तर्भाव <fcntl.h>
#अन्तर्भाव <limits.h>
#अन्तर्भाव <netdb.h>
#अन्तर्भाव <poll.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <stdint.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <termios.h>
#अन्तर्भाव <unistd.h>

#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "ssh.h"
#अन्तर्भाव "ssh2.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "packet.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "channels.h"
#अन्तर्भाव "compat.h"
#अन्तर्भाव "canohost.h"
#अन्तर्भाव "pathnames.h"
#अन्तर्भाव "match.h"

/* XXX remove once we're satisfied there's no lurking bugs */
/* #define DEBUG_CHANNEL_POLL 1 */

/* -- agent forwarding */
#define	अङ्क_SOCKS	10

/* -- X11 forwarding */
/* X11 port for display :0 */
#define X11_BASE_PORT	6000
/* Maximum number of fake X11 displays to try. */
#define MAX_DISPLAYS  1000

/* Per-channel callback for pre/post IO actions */
प्रकारनिर्देश शून्य chan_fn(संरचना ssh *, Channel *c);

/*
 * Data structure for storing which hosts are permitted for forward requests.
 * The local sides of any remote forwards are stored in this array to prevent
 * a corrupt remote server from accessing arbitrary TCP/IP ports on our local
 * network (which might be behind a firewall).
 */
/* XXX: streamlocal wants a path instead of host:port */
/*      Overload host_to_connect; we could just make this match Forward */
/*	XXX - can we use listen_host instead of listen_path? */
संरचना permission {
	वर्ण *host_to_connect;		/* Connect to 'host'. */
	पूर्णाङ्क port_to_connect;		/* Connect to 'port'. */
	वर्ण *listen_host;		/* Remote side should listen address. */
	वर्ण *listen_path;		/* Remote side should listen path. */
	पूर्णाङ्क listen_port;		/* Remote side should listen port. */
	Channel *downstream;		/* Downstream mux*/
};

/* Context for non-blocking connects */
संरचना channel_connect {
	वर्ण *host;
	पूर्णाङ्क port;
	संरचना addrinfo *ai, *aitop;
};

/*
 * Stores the forwarding permission state for a single direction (local or
 * remote).
 */
संरचना permission_set {
	/*
	 * List of all local permitted host/port pairs to allow for the
	 * user.
	 */
	u_int अङ्क_permitted_user;
	संरचना permission *permitted_user;

	/*
	 * List of all permitted host/port pairs to allow for the admin.
	 */
	u_int अङ्क_permitted_admin;
	संरचना permission *permitted_admin;

	/*
	 * If this is true, all opens/listens are permitted.  This is the
	 * case on the server on which we have to trust the client anyway,
	 * and the user could do anything after logging in.
	 */
	पूर्णाङ्क all_permitted;
};

/* Used to record timeouts per channel type */
संरचना ssh_channel_timeout {
	वर्ण *type_pattern;
	द्विगुण timeout_secs;
};

/* Master structure for channels state */
संरचना ssh_channels {
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
	संरचना permission_set local_perms;
	संरचना permission_set remote_perms;

	/* -- X11 forwarding */

	/* Saved X11 local (client) display. */
	वर्ण *x11_saved_display;

	/* Saved X11 authentication protocol name. */
	वर्ण *x11_saved_proto;

	/* Saved X11 authentication data.  This is the real data. */
	वर्ण *x11_saved_data;
	u_int x11_saved_data_len;

	/* Deadline after which all X11 connections are refused */
	द्विगुण x11_refuse_time;

	/*
	 * Fake X11 authentication data.  This is what the server will be
	 * sending us; we should replace any occurrences of this by the
	 * real data.
	 */
	u_char *x11_fake_data;
	u_int x11_fake_data_len;

	/* AF_UNSPEC or AF_INET or AF_INET6 */
	पूर्णाङ्क IPv4or6;

	/* Set SO_KEEPALIVE on TCP connections */
	पूर्णाङ्क want_tcp_keepalive;

	/* Channel timeouts by type */
	संरचना ssh_channel_timeout *timeouts;
	माप_प्रकार ntimeouts;
	/* Global timeout for all OPEN channels */
	द्विगुण global_deadline;
	द्विगुण lastused;
	/* pattern-lists used to classify channels as bulk */
	वर्ण *bulk_classifier_tty, *bulk_classifier_notty;
	/* Number of active bulk channels (set by channel_handler) */
	u_int nbulk;
};

/* helper */
स्थिर शून्य port_open_helper(संरचना ssh *ssh, Channel *c, वर्ण *rtype);
स्थिर अचर वर्ण *channel_rfwd_bind_host(अचर वर्ण *listen_host);

/* non-blocking connect helpers */
स्थिर पूर्णाङ्क connect_next(संरचना ssh *, संरचना channel_connect *);
स्थिर Channel *rdynamic_connect_prepare(संरचना ssh *, वर्ण *, वर्ण *);
स्थिर पूर्णाङ्क rdynamic_connect_finish(संरचना ssh *, Channel *);

/* Setup helper */
स्थिर शून्य channel_handler_init(संरचना ssh_channels *sc);

/* -- channel core */

शून्य
channel_init_channels(संरचना ssh *ssh)
{
	संरचना ssh_channels *sc;

	यदि ((sc = सुस्मृति(1, परिमाण(*sc))) == रिक्त)
		fatal_f("allocation failed");
	sc->channels_alloc = 10;
	sc->channels = xcalloc(sc->channels_alloc, परिमाण(*sc->channels));
	sc->IPv4or6 = AF_UNSPEC;
	sc->bulk_classifier_tty = xstrdup(CHANNEL_BULK_TTY);
	sc->bulk_classifier_notty = xstrdup(CHANNEL_BULK_NOTTY);
	channel_handler_init(sc);

	ssh->chanctxt = sc;
}

Channel *
channel_by_id(संरचना ssh *ssh, पूर्णाङ्क id)
{
	Channel *c;

	यदि (id < 0 || (u_int)id >= ssh->chanctxt->channels_alloc) {
		logit_f("%d: bad id", id);
		फर्काऊ रिक्त;
	}
	c = ssh->chanctxt->channels[id];
	यदि (c == रिक्त) {
		logit_f("%d: bad id: channel free", id);
		फर्काऊ रिक्त;
	}
	फर्काऊ c;
}

Channel *
channel_by_remote_id(संरचना ssh *ssh, u_int remote_id)
{
	Channel *c;
	u_int i;

	लागि (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		यदि (c != रिक्त && c->have_remote_id && c->remote_id == remote_id)
			फर्काऊ c;
	}
	फर्काऊ रिक्त;
}

/*
 * Returns the channel if it is allowed to receive protocol messages.
 * Private channels, like listening sockets, may not receive messages.
 */
Channel *
channel_lookup(संरचना ssh *ssh, पूर्णाङ्क id)
{
	Channel *c;

	यदि ((c = channel_by_id(ssh, id)) == रिक्त)
		फर्काऊ रिक्त;

	विकल्प (c->type) {
	पक्ष SSH_CHANNEL_X11_OPEN:
	पक्ष SSH_CHANNEL_LARVAL:
	पक्ष SSH_CHANNEL_CONNECTING:
	पक्ष SSH_CHANNEL_DYNAMIC:
	पक्ष SSH_CHANNEL_RDYNAMIC_OPEN:
	पक्ष SSH_CHANNEL_RDYNAMIC_FINISH:
	पक्ष SSH_CHANNEL_OPENING:
	पक्ष SSH_CHANNEL_OPEN:
	पक्ष SSH_CHANNEL_ABANDONED:
	पक्ष SSH_CHANNEL_MUX_PROXY:
		फर्काऊ c;
	}
	logit("Non-public channel %d, type %d.", id, c->type);
	फर्काऊ रिक्त;
}

स्थिर शून्य
free_connect_ctx(संरचना channel_connect *cctx)
{
	मुक्त(cctx->host);
	यदि (cctx->aitop) {
		यदि (cctx->aitop->ai_family == AF_UNIX)
			मुक्त(cctx->aitop);
		अन्यथा
			freeaddrinfo(cctx->aitop);
	}
	स_रखो(cctx, 0, परिमाण(*cctx));
}

स्थिर शून्य
channel_free_connect_ctx(Channel *c)
{
	यदि (c == रिक्त || c->connect_ctx == रिक्त)
		फर्काऊ;
	free_connect_ctx(c->connect_ctx);
	मुक्त(c->connect_ctx);
	c->connect_ctx = रिक्त;
}

/* Enable/disable TCP keepalives for X11 and port-forwarding sockets */
शून्य
channel_set_tcp_keepalives(संरचना ssh *ssh, पूर्णाङ्क on)
{
	ssh->chanctxt->want_tcp_keepalive = on;
}

/*
 * Add a timeout for open channels whose c->ctype (or c->xctype if it is set)
 * match type_pattern.
 */
शून्य
channel_add_timeout(संरचना ssh *ssh, अचर वर्ण *type_pattern,
    द्विगुण timeout_secs)
{
	संरचना ssh_channels *sc = ssh->chanctxt;

	यदि (म_भेद(type_pattern, "global") == 0) {
		debug2_f("global channel timeout %f seconds", timeout_secs);
		sc->global_deadline = timeout_secs;
		फर्काऊ;
	}
	debug2_f("channel type \"%s\" timeout %f seconds",
	    type_pattern, timeout_secs);
	sc->timeouts = xrecallocarray(sc->timeouts, sc->ntimeouts,
	    sc->ntimeouts + 1, परिमाण(*sc->timeouts));
	sc->timeouts[sc->ntimeouts].type_pattern = xstrdup(type_pattern);
	sc->timeouts[sc->ntimeouts].timeout_secs = timeout_secs;
	sc->ntimeouts++;
}

/* Clears all previously-added channel timeouts */
शून्य
channel_clear_timeouts(संरचना ssh *ssh)
{
	संरचना ssh_channels *sc = ssh->chanctxt;
	माप_प्रकार i;

	debug3_f("clearing");
	लागि (i = 0; i < sc->ntimeouts; i++)
		मुक्त(sc->timeouts[i].type_pattern);
	मुक्त(sc->timeouts);
	sc->timeouts = रिक्त;
	sc->ntimeouts = 0;
}

स्थिर द्विगुण
lookup_timeout(संरचना ssh *ssh, अचर वर्ण *type)
{
	संरचना ssh_channels *sc = ssh->chanctxt;
	माप_प्रकार i;

	लागि (i = 0; i < sc->ntimeouts; i++) {
		यदि (match_pattern(type, sc->timeouts[i].type_pattern))
			फर्काऊ sc->timeouts[i].timeout_secs;
	}

	फर्काऊ 0;
}

स्थिर शून्य
channel_classify(संरचना ssh *ssh, Channel *c)
{
	संरचना ssh_channels *sc = ssh->chanctxt;
	अचर वर्ण *type = c->xctype == रिक्त ? c->ctype : c->xctype;
	अचर पूर्णाङ्क has_tty = c->isatty || c->remote_has_tty;
	अचर वर्ण *classifier = has_tty ?
	    sc->bulk_classifier_tty : sc->bulk_classifier_notty;

	c->bulk = type != रिक्त && match_pattern_list(type, classifier, 0) == 1;
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
शून्य
channel_set_xtype(संरचना ssh *ssh, पूर्णाङ्क id, अचर वर्ण *xctype)
{
	संरचना ssh_channels *sc = ssh->chanctxt;
	Channel *c;

	यदि ((c = channel_by_id(ssh, id)) == रिक्त)
		fatal_f("missing channel %d", id);
	यदि (c->xctype != रिक्त)
		मुक्त(c->xctype);
	c->xctype = xstrdup(xctype);
	/* Only override deadline if xctype has a more specific match. */
	द्विगुण xtype_deadline = lookup_timeout(ssh, c->xctype);
	यदि (xtype_deadline != 0)
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
स्थिर शून्य
channel_set_used_time(संरचना ssh *ssh, Channel *c)
{
	ssh->chanctxt->lastused = monotime_double();
	यदि (c != रिक्त)
		c->lastused = ssh->chanctxt->lastused;
}

/*
 * Get the time at which a channel is due to time out for inactivity.
 * Returns 0 if the channel is not due to time out ever.
 */
स्थिर द्विगुण
channel_get_expiry(संरचना ssh *ssh, Channel *c)
{
	संरचना ssh_channels *sc = ssh->chanctxt;
	द्विगुण expiry = 0, channel_expiry;

	यदि (sc->lastused != 0 && sc->global_deadline != 0)
		expiry = sc->lastused + sc->global_deadline;
	यदि (c->lastused != 0 && c->inactive_deadline != 0) {
		channel_expiry = c->lastused + c->inactive_deadline;
		यदि (expiry == 0 || channel_expiry < expiry)
			expiry = channel_expiry;
	}
	फर्काऊ expiry;
}

/* Returns non-zero if there is an open, non-interactive channel */
पूर्णाङ्क
channel_has_bulk(संरचना ssh *ssh)
{
	फर्काऊ ssh->chanctxt != रिक्त && ssh->chanctxt->nbulk != 0;
}

/*
 * Register filedescriptors for a channel, used when allocating a channel or
 * when the channel consumer/producer is ready, e.g. shell exec'd
 */
स्थिर शून्य
channel_register_fds(संरचना ssh *ssh, Channel *c, पूर्णाङ्क rfd, पूर्णाङ्क wfd, पूर्णाङ्क efd,
    पूर्णाङ्क extusage, पूर्णाङ्क nonblock, पूर्णाङ्क is_tty)
{
	पूर्णाङ्क val;

	यदि (rfd != -1)
		(शून्य)fcntl(rfd, F_SETFD, FD_CLOEXEC);
	यदि (wfd != -1 && wfd != rfd)
		(शून्य)fcntl(wfd, F_SETFD, FD_CLOEXEC);
	यदि (efd != -1 && efd != rfd && efd != wfd)
		(शून्य)fcntl(efd, F_SETFD, FD_CLOEXEC);

	c->rfd = rfd;
	c->wfd = wfd;
	c->sock = (rfd == wfd) ? rfd : -1;
	c->efd = efd;
	c->extended_usage = extusage;

	यदि ((c->isatty = is_tty) != 0)
		debug2("channel %d: rfd %d isatty", c->self, c->rfd);
#ifdef _AIX
	/* XXX: Later AIX versions can't push as much data to tty */
	c->wfd_isatty = is_tty || isatty(c->wfd);
#endif

	/* enable nonblocking mode */
	c->restore_block = 0;
	यदि (nonblock == CHANNEL_NONBLOCK_STDIO) {
		/*
		 * Special handling for stdio file descriptors: do not set
		 * non-blocking mode if they are TTYs. Otherwise prepare to
		 * restore their blocking state on exit to avoid interfering
		 * with other programs that follow.
		 */
		यदि (rfd != -1 && !isatty(rfd) &&
		    (val = fcntl(rfd, F_GETFL)) != -1 && !(val & O_NONBLOCK)) {
			c->restore_flags[0] = val;
			c->restore_block |= CHANNEL_RESTORE_RFD;
			set_nonblock(rfd);
		}
		यदि (wfd != -1 && !isatty(wfd) &&
		    (val = fcntl(wfd, F_GETFL)) != -1 && !(val & O_NONBLOCK)) {
			c->restore_flags[1] = val;
			c->restore_block |= CHANNEL_RESTORE_WFD;
			set_nonblock(wfd);
		}
		यदि (efd != -1 && !isatty(efd) &&
		    (val = fcntl(efd, F_GETFL)) != -1 && !(val & O_NONBLOCK)) {
			c->restore_flags[2] = val;
			c->restore_block |= CHANNEL_RESTORE_EFD;
			set_nonblock(efd);
		}
	} अन्यथा यदि (nonblock) {
		यदि (rfd != -1)
			set_nonblock(rfd);
		यदि (wfd != -1)
			set_nonblock(wfd);
		यदि (efd != -1)
			set_nonblock(efd);
	}
	/* channel might be entering a larval state, so reset global timeout */
	channel_set_used_time(ssh, रिक्त);
	channel_classify(ssh, c);
}

/*
 * Allocate a new channel object and set its type and socket.
 */
Channel *
channel_new(संरचना ssh *ssh, वर्ण *ctype, पूर्णाङ्क type, पूर्णाङ्क rfd, पूर्णाङ्क wfd, पूर्णाङ्क efd,
    u_int window, u_int maxpack, पूर्णाङ्क extusage, अचर वर्ण *remote_name,
    पूर्णाङ्क nonblock)
{
	संरचना ssh_channels *sc = ssh->chanctxt;
	u_int i, found = 0;
	Channel *c;
	पूर्णाङ्क r;

	/* Try to find a free slot where to put the new channel. */
	लागि (i = 0; i < sc->channels_alloc; i++) {
		यदि (sc->channels[i] == रिक्त) {
			/* Found a free slot. */
			found = i;
			रोक;
		}
	}
	यदि (i >= sc->channels_alloc) {
		/*
		 * There are no free slots. Take last+1 slot and expand
		 * the array.
		 */
		found = sc->channels_alloc;
		यदि (sc->channels_alloc > CHANNELS_MAX_CHANNELS)
			fatal_f("internal error: channels_alloc %d too big",
			    sc->channels_alloc);
		sc->channels = xrecallocarray(sc->channels, sc->channels_alloc,
		    sc->channels_alloc + 10, परिमाण(*sc->channels));
		sc->channels_alloc += 10;
		debug2("channel: expanding %d", sc->channels_alloc);
	}
	/* Initialize and return new channel. */
	c = sc->channels[found] = xcalloc(1, परिमाण(Channel));
	यदि ((c->आगत = sshbuf_new()) == रिक्त ||
	    (c->output = sshbuf_new()) == रिक्त ||
	    (c->extended = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	यदि ((r = sshbuf_set_max_size(c->आगत, CHAN_आगत_MAX)) != 0)
		fatal_fr(r, "sshbuf_set_max_size");
	c->ostate = CHAN_OUTPUT_OPEN;
	c->istate = CHAN_आगत_OPEN;
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
	फर्काऊ c;
}

शून्य
channel_set_tty(संरचना ssh *ssh, Channel *c)
{
	c->remote_has_tty = 1;
	channel_classify(ssh, c);
}

पूर्णाङ्क
channel_close_fd(संरचना ssh *ssh, Channel *c, पूर्णाङ्क *fdp)
{
	पूर्णाङ्क ret, fd = *fdp;

	यदि (fd == -1)
		फर्काऊ 0;

	/* restore blocking */
	यदि (*fdp == c->rfd &&
	    (c->restore_block & CHANNEL_RESTORE_RFD) != 0)
		(शून्य)fcntl(*fdp, F_SETFL, c->restore_flags[0]);
	अन्यथा यदि (*fdp == c->wfd &&
	    (c->restore_block & CHANNEL_RESTORE_WFD) != 0)
		(शून्य)fcntl(*fdp, F_SETFL, c->restore_flags[1]);
	अन्यथा यदि (*fdp == c->efd &&
	    (c->restore_block & CHANNEL_RESTORE_EFD) != 0)
		(शून्य)fcntl(*fdp, F_SETFL, c->restore_flags[2]);

	यदि (*fdp == c->rfd) {
		c->io_want &= ~SSH_CHAN_IO_RFD;
		c->io_ready &= ~SSH_CHAN_IO_RFD;
		c->rfd = -1;
		c->pfds[0] = -1;
	}
	यदि (*fdp == c->wfd) {
		c->io_want &= ~SSH_CHAN_IO_WFD;
		c->io_ready &= ~SSH_CHAN_IO_WFD;
		c->wfd = -1;
		c->pfds[1] = -1;
	}
	यदि (*fdp == c->efd) {
		c->io_want &= ~SSH_CHAN_IO_EFD;
		c->io_ready &= ~SSH_CHAN_IO_EFD;
		c->efd = -1;
		c->pfds[2] = -1;
	}
	यदि (*fdp == c->sock) {
		c->io_want &= ~SSH_CHAN_IO_SOCK;
		c->io_ready &= ~SSH_CHAN_IO_SOCK;
		c->sock = -1;
		c->pfds[3] = -1;
	}

	ret = बंद(fd);
	*fdp = -1; /* probably redundant */
	फर्काऊ ret;
}

/* Close all channel fd/socket. */
स्थिर शून्य
channel_close_fds(संरचना ssh *ssh, Channel *c)
{
	पूर्णाङ्क sock = c->sock, rfd = c->rfd, wfd = c->wfd, efd = c->efd;

	channel_close_fd(ssh, c, &c->sock);
	यदि (rfd != sock)
		channel_close_fd(ssh, c, &c->rfd);
	यदि (wfd != sock && wfd != rfd)
		channel_close_fd(ssh, c, &c->wfd);
	यदि (efd != sock && efd != rfd && efd != wfd)
		channel_close_fd(ssh, c, &c->efd);
}

स्थिर शून्य
fwd_perm_clear(संरचना permission *perm)
{
	मुक्त(perm->host_to_connect);
	मुक्त(perm->listen_host);
	मुक्त(perm->listen_path);
	स_रखो(perm, 0, परिमाण(*perm));
}

/* Returns an printable name for the specified forwarding permission list */
स्थिर अचर वर्ण *
fwd_ident(पूर्णाङ्क who, पूर्णाङ्क where)
{
	यदि (who == FORWARD_ADM) {
		यदि (where == FORWARD_LOCAL)
			फर्काऊ "admin local";
		अन्यथा यदि (where == FORWARD_REMOTE)
			फर्काऊ "admin remote";
	} अन्यथा यदि (who == FORWARD_USER) {
		यदि (where == FORWARD_LOCAL)
			फर्काऊ "user local";
		अन्यथा यदि (where == FORWARD_REMOTE)
			फर्काऊ "user remote";
	}
	fatal("Unknown forward permission list %d/%d", who, where);
}

/* Returns the forwarding permission list for the specified direction */
स्थिर संरचना permission_set *
permission_set_get(संरचना ssh *ssh, पूर्णाङ्क where)
{
	संरचना ssh_channels *sc = ssh->chanctxt;

	विकल्प (where) {
	पक्ष FORWARD_LOCAL:
		फर्काऊ &sc->local_perms;
		रोक;
	पक्ष FORWARD_REMOTE:
		फर्काऊ &sc->remote_perms;
		रोक;
	स्वभाव:
		fatal_f("invalid forwarding direction %d", where);
	}
}

/* Returns pointers to the specified forwarding list and its element count */
स्थिर शून्य
permission_set_get_array(संरचना ssh *ssh, पूर्णाङ्क who, पूर्णाङ्क where,
    संरचना permission ***permpp, u_int **npermpp)
{
	संरचना permission_set *pset = permission_set_get(ssh, where);

	विकल्प (who) {
	पक्ष FORWARD_USER:
		*permpp = &pset->permitted_user;
		*npermpp = &pset->अङ्क_permitted_user;
		रोक;
	पक्ष FORWARD_ADM:
		*permpp = &pset->permitted_admin;
		*npermpp = &pset->अङ्क_permitted_admin;
		रोक;
	स्वभाव:
		fatal_f("invalid forwarding client %d", who);
	}
}

/* Adds an entry to the specified forwarding list */
स्थिर पूर्णाङ्क
permission_set_add(संरचना ssh *ssh, पूर्णाङ्क who, पूर्णाङ्क where,
    अचर वर्ण *host_to_connect, पूर्णाङ्क port_to_connect,
    अचर वर्ण *listen_host, अचर वर्ण *listen_path, पूर्णाङ्क listen_port,
    Channel *downstream)
{
	संरचना permission **permp;
	u_int n, *npermp;

	permission_set_get_array(ssh, who, where, &permp, &npermp);

	यदि (*npermp >= पूर्णांक_उच्च)
		fatal_f("%s overflow", fwd_ident(who, where));

	*permp = xrecallocarray(*permp, *npermp, *npermp + 1, परिमाण(**permp));
	n = (*npermp)++;
#define MAYBE_DUP(s) ((s == रिक्त) ? रिक्त : xstrdup(s))
	(*permp)[n].host_to_connect = MAYBE_DUP(host_to_connect);
	(*permp)[n].port_to_connect = port_to_connect;
	(*permp)[n].listen_host = MAYBE_DUP(listen_host);
	(*permp)[n].listen_path = MAYBE_DUP(listen_path);
	(*permp)[n].listen_port = listen_port;
	(*permp)[n].downstream = downstream;
#undef MAYBE_DUP
	फर्काऊ (पूर्णाङ्क)n;
}

स्थिर शून्य
mux_remove_remote_forwardings(संरचना ssh *ssh, Channel *c)
{
	संरचना ssh_channels *sc = ssh->chanctxt;
	संरचना permission_set *pset = &sc->local_perms;
	संरचना permission *perm;
	पूर्णाङ्क r;
	u_int i;

	लागि (i = 0; i < pset->अङ्क_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		यदि (perm->downstream != c)
			जारी;

		/* cancel on the server, since mux client is gone */
		debug("channel %d: cleanup remote forward for %s:%u",
		    c->self, perm->listen_host, perm->listen_port);
		यदि ((r = sshpkt_start(ssh, SSH2_सन्देश_GLOBAL_REQUEST)) != 0 ||
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
शून्य
channel_free(संरचना ssh *ssh, Channel *c)
{
	संरचना ssh_channels *sc = ssh->chanctxt;
	वर्ण *s;
	u_int i, n;
	Channel *other;
	संरचना channel_confirm *cc;

	लागि (n = 0, i = 0; i < sc->channels_alloc; i++) {
		यदि ((other = sc->channels[i]) == रिक्त)
			जारी;
		n++;
		/* detach from mux client and prepare for closing */
		यदि (c->type == SSH_CHANNEL_MUX_CLIENT &&
		    other->type == SSH_CHANNEL_MUX_PROXY &&
		    other->mux_ctx == c) {
			other->mux_ctx = रिक्त;
			other->type = SSH_CHANNEL_OPEN;
			other->istate = CHAN_आगत_CLOSED;
			other->ostate = CHAN_OUTPUT_CLOSED;
		}
	}
	debug("channel %d: free: %s, nchannels %u", c->self,
	    c->remote_name ? c->remote_name : "???", n);

	यदि (c->type == SSH_CHANNEL_MUX_CLIENT) {
		mux_remove_remote_forwardings(ssh, c);
		मुक्त(c->mux_ctx);
		c->mux_ctx = रिक्त;
	} अन्यथा यदि (c->type == SSH_CHANNEL_MUX_LISTENER) {
		मुक्त(c->mux_ctx);
		c->mux_ctx = रिक्त;
	}

	यदि (log_level_get() >= SYSLOG_LEVEL_DEBUG3) {
		s = channel_open_message(ssh);
		debug3("channel %d: status: %s", c->self, s);
		मुक्त(s);
	}

	channel_close_fds(ssh, c);
	sshbuf_free(c->आगत);
	sshbuf_free(c->output);
	sshbuf_free(c->extended);
	c->आगत = c->output = c->extended = रिक्त;
	मुक्त(c->remote_name);
	c->remote_name = रिक्त;
	मुक्त(c->path);
	c->path = रिक्त;
	मुक्त(c->listening_addr);
	c->listening_addr = रिक्त;
	मुक्त(c->xctype);
	c->xctype = रिक्त;
	channel_free_connect_ctx(c);
	जबसम्म ((cc = TAILQ_FIRST(&c->status_confirms)) != रिक्त) {
		यदि (cc->abandon_cb != रिक्त)
			cc->abandon_cb(ssh, c, cc->ctx);
		TAILQ_REMOVE(&c->status_confirms, cc, entry);
		freezero(cc, परिमाण(*cc));
	}
	यदि (c->filter_cleanup != रिक्त && c->filter_ctx != रिक्त)
		c->filter_cleanup(ssh, c->self, c->filter_ctx);
	sc->channels[c->self] = रिक्त;
	freezero(c, परिमाण(*c));
}

शून्य
channel_free_all(संरचना ssh *ssh)
{
	u_int i;
	संरचना ssh_channels *sc = ssh->chanctxt;

	लागि (i = 0; i < sc->channels_alloc; i++)
		यदि (sc->channels[i] != रिक्त)
			channel_free(ssh, sc->channels[i]);

	मुक्त(sc->channels);
	sc->channels = रिक्त;
	sc->channels_alloc = 0;

	मुक्त(sc->x11_saved_display);
	sc->x11_saved_display = रिक्त;

	मुक्त(sc->x11_saved_proto);
	sc->x11_saved_proto = रिक्त;

	मुक्त(sc->x11_saved_data);
	sc->x11_saved_data = रिक्त;
	sc->x11_saved_data_len = 0;

	मुक्त(sc->x11_fake_data);
	sc->x11_fake_data = रिक्त;
	sc->x11_fake_data_len = 0;
}

शून्य
channel_free_channels(संरचना ssh *ssh)
{
	संरचना ssh_channels *sc;

	यदि (ssh == रिक्त || ssh->chanctxt == रिक्त)
		फर्काऊ;
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
	freezero(sc, परिमाण(*sc));
	ssh->chanctxt = रिक्त;
}

/*
 * Closes the sockets/fds of all channels.  This is used to close extra file
 * descriptors after a fork.
 */
शून्य
channel_close_all(संरचना ssh *ssh)
{
	u_int i;

	लागि (i = 0; i < ssh->chanctxt->channels_alloc; i++)
		यदि (ssh->chanctxt->channels[i] != रिक्त)
			channel_close_fds(ssh, ssh->chanctxt->channels[i]);
}

/*
 * Stop listening to channels.
 */
शून्य
channel_stop_listening(संरचना ssh *ssh)
{
	u_int i;
	Channel *c;

	लागि (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		यदि (c != रिक्त) {
			विकल्प (c->type) {
			पक्ष SSH_CHANNEL_AUTH_SOCKET:
			पक्ष SSH_CHANNEL_PORT_LISTENER:
			पक्ष SSH_CHANNEL_RPORT_LISTENER:
			पक्ष SSH_CHANNEL_X11_LISTENER:
			पक्ष SSH_CHANNEL_UNIX_LISTENER:
			पक्ष SSH_CHANNEL_RUNIX_LISTENER:
				channel_close_fd(ssh, c, &c->sock);
				channel_free(ssh, c);
				रोक;
			}
		}
	}
}

/*
 * Returns true if no channel has too much buffered data, and false if one or
 * more channel is overfull.
 */
पूर्णाङ्क
channel_not_very_much_buffered_data(संरचना ssh *ssh)
{
	u_int i;
	u_int maxsize = ssh_packet_get_maxsize(ssh);
	Channel *c;

	लागि (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		यदि (c == रिक्त || c->type != SSH_CHANNEL_OPEN)
			जारी;
		यदि (sshbuf_len(c->output) > maxsize) {
			debug2("channel %d: big output buffer %zu > %u",
			    c->self, sshbuf_len(c->output), maxsize);
			फर्काऊ 0;
		}
	}
	फर्काऊ 1;
}

/* Returns true if any channel is still open. */
पूर्णाङ्क
channel_still_open(संरचना ssh *ssh)
{
	u_int i;
	Channel *c;

	लागि (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		यदि (c == रिक्त)
			जारी;
		विकल्प (c->type) {
		पक्ष SSH_CHANNEL_X11_LISTENER:
		पक्ष SSH_CHANNEL_PORT_LISTENER:
		पक्ष SSH_CHANNEL_RPORT_LISTENER:
		पक्ष SSH_CHANNEL_MUX_LISTENER:
		पक्ष SSH_CHANNEL_CLOSED:
		पक्ष SSH_CHANNEL_AUTH_SOCKET:
		पक्ष SSH_CHANNEL_DYNAMIC:
		पक्ष SSH_CHANNEL_RDYNAMIC_OPEN:
		पक्ष SSH_CHANNEL_CONNECTING:
		पक्ष SSH_CHANNEL_ZOMBIE:
		पक्ष SSH_CHANNEL_ABANDONED:
		पक्ष SSH_CHANNEL_UNIX_LISTENER:
		पक्ष SSH_CHANNEL_RUNIX_LISTENER:
			जारी;
		पक्ष SSH_CHANNEL_LARVAL:
			जारी;
		पक्ष SSH_CHANNEL_OPENING:
		पक्ष SSH_CHANNEL_OPEN:
		पक्ष SSH_CHANNEL_RDYNAMIC_FINISH:
		पक्ष SSH_CHANNEL_X11_OPEN:
		पक्ष SSH_CHANNEL_MUX_CLIENT:
		पक्ष SSH_CHANNEL_MUX_PROXY:
			फर्काऊ 1;
		स्वभाव:
			fatal_f("bad channel type %d", c->type);
			/* NOTREACHED */
		}
	}
	फर्काऊ 0;
}

/* Returns true if a channel with a TTY is open. */
पूर्णाङ्क
channel_tty_open(संरचना ssh *ssh)
{
	u_int i;
	Channel *c;

	लागि (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		यदि (c == रिक्त || c->type != SSH_CHANNEL_OPEN)
			जारी;
		यदि (c->client_tty)
			फर्काऊ 1;
	}
	फर्काऊ 0;
}

/* Returns the id of an open channel suitable for keepaliving */
पूर्णाङ्क
channel_find_open(संरचना ssh *ssh)
{
	u_int i;
	Channel *c;

	लागि (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		यदि (c == रिक्त || !c->have_remote_id)
			जारी;
		विकल्प (c->type) {
		पक्ष SSH_CHANNEL_CLOSED:
		पक्ष SSH_CHANNEL_DYNAMIC:
		पक्ष SSH_CHANNEL_RDYNAMIC_OPEN:
		पक्ष SSH_CHANNEL_RDYNAMIC_FINISH:
		पक्ष SSH_CHANNEL_X11_LISTENER:
		पक्ष SSH_CHANNEL_PORT_LISTENER:
		पक्ष SSH_CHANNEL_RPORT_LISTENER:
		पक्ष SSH_CHANNEL_MUX_LISTENER:
		पक्ष SSH_CHANNEL_MUX_CLIENT:
		पक्ष SSH_CHANNEL_MUX_PROXY:
		पक्ष SSH_CHANNEL_OPENING:
		पक्ष SSH_CHANNEL_CONNECTING:
		पक्ष SSH_CHANNEL_ZOMBIE:
		पक्ष SSH_CHANNEL_ABANDONED:
		पक्ष SSH_CHANNEL_UNIX_LISTENER:
		पक्ष SSH_CHANNEL_RUNIX_LISTENER:
			जारी;
		पक्ष SSH_CHANNEL_LARVAL:
		पक्ष SSH_CHANNEL_AUTH_SOCKET:
		पक्ष SSH_CHANNEL_OPEN:
		पक्ष SSH_CHANNEL_X11_OPEN:
			फर्काऊ i;
		स्वभाव:
			fatal_f("bad channel type %d", c->type);
			/* NOTREACHED */
		}
	}
	फर्काऊ -1;
}

/* Returns the state of the channel's extended usage flag */
अचर वर्ण *
channel_format_extended_usage(अचर Channel *c)
{
	यदि (c->efd == -1)
		फर्काऊ "closed";

	विकल्प (c->extended_usage) {
	पक्ष CHAN_EXTENDED_WRITE:
		फर्काऊ "write";
	पक्ष CHAN_EXTENDED_READ:
		फर्काऊ "read";
	पक्ष CHAN_EXTENDED_IGNORE:
		फर्काऊ "ignore";
	स्वभाव:
		फर्काऊ "UNKNOWN";
	}
}

स्थिर वर्ण *
channel_format_status(अचर Channel *c)
{
	वर्ण *ret = रिक्त;

	xasprintf(&ret, "t%d [%s] %s%u %s%u i%u/%zu o%u/%zu e[%s]/%zu "
	    "fd %d/%d/%d sock %d cc %d %s%u io 0x%02x/0x%02x %s%s",
	    c->type, c->xctype != रिक्त ? c->xctype : c->ctype,
	    c->have_remote_id ? "r" : "nr", c->remote_id,
	    c->mux_ctx != रिक्त ? "m" : "nm", c->mux_downstream_id,
	    c->istate, sshbuf_len(c->आगत),
	    c->ostate, sshbuf_len(c->output),
	    channel_format_extended_usage(c), sshbuf_len(c->extended),
	    c->rfd, c->wfd, c->efd, c->sock, c->ctl_chan,
	    c->have_ctl_child_id ? "c" : "nc", c->ctl_child_id,
	    c->io_want, c->io_ready,
	    c->isatty ? "T" : (c->remote_has_tty ? "RT" : ""),
	    c->bulk ? "B" : "I");
	फर्काऊ ret;
}

/*
 * Returns a message describing the currently open forwarded connections,
 * suitable for sending to the client.  The message contains crlf pairs for
 * newlines.
 */
वर्ण *
channel_open_message(संरचना ssh *ssh)
{
	संरचना sshbuf *buf;
	Channel *c;
	u_int i;
	पूर्णाङ्क r;
	वर्ण *cp, *ret;

	यदि ((buf = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new");
	यदि ((r = sshbuf_putf(buf,
	    "The following connections are open:\r\n")) != 0)
		fatal_fr(r, "sshbuf_putf");
	लागि (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		यदि (c == रिक्त)
			जारी;
		विकल्प (c->type) {
		पक्ष SSH_CHANNEL_X11_LISTENER:
		पक्ष SSH_CHANNEL_PORT_LISTENER:
		पक्ष SSH_CHANNEL_RPORT_LISTENER:
		पक्ष SSH_CHANNEL_CLOSED:
		पक्ष SSH_CHANNEL_AUTH_SOCKET:
		पक्ष SSH_CHANNEL_ZOMBIE:
		पक्ष SSH_CHANNEL_ABANDONED:
		पक्ष SSH_CHANNEL_MUX_LISTENER:
		पक्ष SSH_CHANNEL_UNIX_LISTENER:
		पक्ष SSH_CHANNEL_RUNIX_LISTENER:
			जारी;
		पक्ष SSH_CHANNEL_LARVAL:
		पक्ष SSH_CHANNEL_OPENING:
		पक्ष SSH_CHANNEL_CONNECTING:
		पक्ष SSH_CHANNEL_DYNAMIC:
		पक्ष SSH_CHANNEL_RDYNAMIC_OPEN:
		पक्ष SSH_CHANNEL_RDYNAMIC_FINISH:
		पक्ष SSH_CHANNEL_OPEN:
		पक्ष SSH_CHANNEL_X11_OPEN:
		पक्ष SSH_CHANNEL_MUX_PROXY:
		पक्ष SSH_CHANNEL_MUX_CLIENT:
			cp = channel_format_status(c);
			यदि ((r = sshbuf_putf(buf, "  #%d %.300s (%s)\r\n",
			    c->self, c->remote_name, cp)) != 0) {
				मुक्त(cp);
				fatal_fr(r, "sshbuf_putf");
			}
			मुक्त(cp);
			जारी;
		स्वभाव:
			fatal_f("bad channel type %d", c->type);
			/* NOTREACHED */
		}
	}
	यदि ((ret = sshbuf_dup_string(buf)) == रिक्त)
		fatal_f("sshbuf_dup_string");
	sshbuf_free(buf);
	फर्काऊ ret;
}

शून्य
channel_report_open(संरचना ssh *ssh, पूर्णाङ्क level)
{
	वर्ण *खोलो, *oopen, *cp, ident[256];

	sshpkt_fmt_connection_id(ssh, ident, परिमाण(ident));
	do_log2(level, "Connection: %s (pid %ld)", ident, (दीर्घ)getpid());
	खोलो = oopen = channel_open_message(ssh);
	जबसम्म ((cp = strsep(&खोलो, "\r\n")) != रिक्त) {
		यदि (*cp != '\0')
			do_log2(level, "%s", cp);
	}
	मुक्त(oopen);
}

स्थिर शून्य
open_preamble(संरचना ssh *ssh, अचर वर्ण *where, Channel *c, अचर वर्ण *type)
{
	पूर्णाङ्क r;

	यदि ((r = sshpkt_start(ssh, SSH2_सन्देश_CHANNEL_OPEN)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, type)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_window)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0) {
		fatal_r(r, "%s: channel %i: open", where, c->self);
	}
}

शून्य
channel_send_open(संरचना ssh *ssh, पूर्णाङ्क id)
{
	Channel *c = channel_lookup(ssh, id);
	पूर्णाङ्क r;

	यदि (c == रिक्त) {
		logit("channel_send_open: %d: bad id", id);
		फर्काऊ;
	}
	debug2("channel %d: send open", id);
	open_preamble(ssh, __func__, c, c->ctype);
	यदि ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i", c->self);
}

शून्य
channel_request_start(संरचना ssh *ssh, पूर्णाङ्क id, अचर वर्ण *service,
    पूर्णाङ्क wantconfirm)
{
	Channel *c = channel_lookup(ssh, id);
	पूर्णाङ्क r;

	यदि (c == रिक्त) {
		logit_f("%d: unknown channel id", id);
		फर्काऊ;
	}
	यदि (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);

	debug2("channel %d: request %s confirm %d", id, service, wantconfirm);
	यदि ((r = sshpkt_start(ssh, SSH2_सन्देश_CHANNEL_REQUEST)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, service)) != 0 ||
	    (r = sshpkt_put_u8(ssh, wantconfirm)) != 0) {
		fatal_fr(r, "channel %i", c->self);
	}
}

शून्य
channel_register_status_confirm(संरचना ssh *ssh, पूर्णाङ्क id,
    channel_confirm_cb *cb, channel_confirm_abandon_cb *abandon_cb, शून्य *ctx)
{
	संरचना channel_confirm *cc;
	Channel *c;

	यदि ((c = channel_lookup(ssh, id)) == रिक्त)
		fatal_f("%d: bad id", id);

	cc = xcalloc(1, परिमाण(*cc));
	cc->cb = cb;
	cc->abandon_cb = abandon_cb;
	cc->ctx = ctx;
	TAILQ_INSERT_TAIL(&c->status_confirms, cc, entry);
}

शून्य
channel_register_open_confirm(संरचना ssh *ssh, पूर्णाङ्क id,
    channel_open_fn *fn, शून्य *ctx)
{
	Channel *c = channel_lookup(ssh, id);

	यदि (c == रिक्त) {
		logit_f("%d: bad id", id);
		फर्काऊ;
	}
	c->open_confirm = fn;
	c->open_confirm_ctx = ctx;
}

शून्य
channel_register_cleanup(संरचना ssh *ssh, पूर्णाङ्क id,
    channel_callback_fn *fn, पूर्णाङ्क do_close)
{
	Channel *c = channel_by_id(ssh, id);

	यदि (c == रिक्त) {
		logit_f("%d: bad id", id);
		फर्काऊ;
	}
	c->detach_user = fn;
	c->detach_close = do_close;
}

शून्य
channel_cancel_cleanup(संरचना ssh *ssh, पूर्णाङ्क id)
{
	Channel *c = channel_by_id(ssh, id);

	यदि (c == रिक्त) {
		logit_f("%d: bad id", id);
		फर्काऊ;
	}
	c->detach_user = रिक्त;
	c->detach_close = 0;
}

शून्य
channel_register_filter(संरचना ssh *ssh, पूर्णाङ्क id, channel_infilter_fn *ifn,
    channel_outfilter_fn *ofn, channel_filter_cleanup_fn *cfn, शून्य *ctx)
{
	Channel *c = channel_lookup(ssh, id);

	यदि (c == रिक्त) {
		logit_f("%d: bad id", id);
		फर्काऊ;
	}
	c->आगत_filter = ifn;
	c->output_filter = ofn;
	c->filter_ctx = ctx;
	c->filter_cleanup = cfn;
}

शून्य
channel_set_fds(संरचना ssh *ssh, पूर्णाङ्क id, पूर्णाङ्क rfd, पूर्णाङ्क wfd, पूर्णाङ्क efd,
    पूर्णाङ्क extusage, पूर्णाङ्क nonblock, पूर्णाङ्क is_tty, u_int window_max)
{
	Channel *c = channel_lookup(ssh, id);
	पूर्णाङ्क r;

	यदि (c == रिक्त || c->type != SSH_CHANNEL_LARVAL)
		fatal("channel_activate for non-larval channel %d.", id);
	यदि (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);

	channel_register_fds(ssh, c, rfd, wfd, efd, extusage, nonblock, is_tty);
	c->type = SSH_CHANNEL_OPEN;
	channel_set_used_time(ssh, c);
	c->local_window = c->local_window_max = window_max;

	यदि ((r = sshpkt_start(ssh, SSH2_सन्देश_CHANNEL_WINDOW_ADJUST)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_window)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i", c->self);
}

स्थिर शून्य
channel_pre_listener(संरचना ssh *ssh, Channel *c)
{
	c->io_want = SSH_CHAN_IO_SOCK_R;
}

स्थिर शून्य
channel_pre_connecting(संरचना ssh *ssh, Channel *c)
{
	debug3("channel %d: waiting for connection", c->self);
	c->io_want = SSH_CHAN_IO_SOCK_W;
}

स्थिर शून्य
channel_pre_open(संरचना ssh *ssh, Channel *c)
{
	c->io_want = 0;
	यदि (c->istate == CHAN_आगत_OPEN &&
	    c->remote_window > 0 &&
	    sshbuf_len(c->आगत) < c->remote_window &&
	    sshbuf_check_reserve(c->आगत, CHAN_RBUF) == 0)
		c->io_want |= SSH_CHAN_IO_RFD;
	यदि (c->ostate == CHAN_OUTPUT_OPEN ||
	    c->ostate == CHAN_OUTPUT_WAIT_DRAIN) {
		यदि (sshbuf_len(c->output) > 0) {
			c->io_want |= SSH_CHAN_IO_WFD;
		} अन्यथा यदि (c->ostate == CHAN_OUTPUT_WAIT_DRAIN) {
			यदि (CHANNEL_EFD_OUTPUT_ACTIVE(c))
				debug2("channel %d: "
				    "obuf_empty delayed efd %d/(%zu)", c->self,
				    c->efd, sshbuf_len(c->extended));
			अन्यथा
				chan_obuf_empty(ssh, c);
		}
	}
	/** XXX check close conditions, too */
	यदि (c->efd != -1 && !(c->istate == CHAN_आगत_CLOSED &&
	    c->ostate == CHAN_OUTPUT_CLOSED)) {
		यदि (c->extended_usage == CHAN_EXTENDED_WRITE &&
		    sshbuf_len(c->extended) > 0)
			c->io_want |= SSH_CHAN_IO_EFD_W;
		अन्यथा यदि (c->efd != -1 && !(c->flags & CHAN_EOF_SENT) &&
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
स्थिर पूर्णाङ्क
x11_open_helper(संरचना ssh *ssh, संरचना sshbuf *b)
{
	संरचना ssh_channels *sc = ssh->chanctxt;
	u_char *ucp;
	u_int proto_len, data_len;

	यदि (sc->x11_saved_proto == रिक्त) {
		error("X11 forwarding opened before X11 forwarding requested");
		फर्काऊ -1;
	}

	/* Is this being called after the refusal deadline? */
	यदि (sc->x11_refuse_time != 0.0 &&
	    monotime_double() >= sc->x11_refuse_time) {
		verbose("Rejected X11 connection after ForwardX11Timeout "
		    "expired");
		फर्काऊ -1;
	}

	/* Check if the fixed size part of the packet is in buffer. */
	यदि (sshbuf_len(b) < 12)
		फर्काऊ 0;

	/* Parse the lengths of variable-length fields. */
	ucp = sshbuf_mutable_ptr(b);
	यदि (ucp[0] == 0x42) {	/* Byte order MSB first. */
		proto_len = 256 * ucp[6] + ucp[7];
		data_len = 256 * ucp[8] + ucp[9];
	} अन्यथा यदि (ucp[0] == 0x6c) {	/* Byte order LSB first. */
		proto_len = ucp[6] + 256 * ucp[7];
		data_len = ucp[8] + 256 * ucp[9];
	} अन्यथा {
		debug2("Initial X11 packet contains bad byte order byte: 0x%x",
		    ucp[0]);
		फर्काऊ -1;
	}

	/* Check if the whole packet is in buffer. */
	यदि (sshbuf_len(b) <
	    12 + ((proto_len + 3) & ~3) + ((data_len + 3) & ~3))
		फर्काऊ 0;

	/* Check if authentication protocol matches. */
	यदि (proto_len != म_माप(sc->x11_saved_proto) ||
	    स_भेद(ucp + 12, sc->x11_saved_proto, proto_len) != 0) {
		debug2("X11 connection uses different authentication protocol.");
		फर्काऊ -1;
	}
	/* Check if authentication data matches our fake data. */
	यदि (data_len != sc->x11_fake_data_len ||
	    timingsafe_bcmp(ucp + 12 + ((proto_len + 3) & ~3),
		sc->x11_fake_data, sc->x11_fake_data_len) != 0) {
		debug2("X11 auth data does not match fake data.");
		फर्काऊ -1;
	}
	/* Check fake data length */
	यदि (sc->x11_fake_data_len != sc->x11_saved_data_len) {
		error("X11 fake_data_len %d != saved_data_len %d",
		    sc->x11_fake_data_len, sc->x11_saved_data_len);
		फर्काऊ -1;
	}
	/*
	 * Received authentication protocol and data match
	 * our fake data. Substitute the fake data with real
	 * data.
	 */
	स_नकल(ucp + 12 + ((proto_len + 3) & ~3),
	    sc->x11_saved_data, sc->x11_saved_data_len);
	फर्काऊ 1;
}

शून्य
channel_force_close(संरचना ssh *ssh, Channel *c, पूर्णाङ्क abandon)
{
	debug3_f("channel %d: forcibly closing", c->self);
	यदि (c->istate == CHAN_आगत_OPEN)
		chan_read_failed(ssh, c);
	यदि (c->istate == CHAN_आगत_WAIT_DRAIN) {
		sshbuf_reset(c->आगत);
		chan_ibuf_empty(ssh, c);
	}
	यदि (c->ostate == CHAN_OUTPUT_OPEN ||
	    c->ostate == CHAN_OUTPUT_WAIT_DRAIN) {
		sshbuf_reset(c->output);
		chan_write_failed(ssh, c);
	}
	यदि (c->detach_user)
		c->detach_user(ssh, c->self, 1, रिक्त);
	यदि (c->efd != -1)
		channel_close_fd(ssh, c, &c->efd);
	यदि (abandon)
		c->type = SSH_CHANNEL_ABANDONED;
	/* exempt from inactivity timeouts */
	c->inactive_deadline = 0;
	c->lastused = 0;
}

स्थिर शून्य
channel_pre_x11_open(संरचना ssh *ssh, Channel *c)
{
	पूर्णाङ्क ret = x11_open_helper(ssh, c->output);

	/* c->force_drain = 1; */

	यदि (ret == 1) {
		c->type = SSH_CHANNEL_OPEN;
		channel_set_used_time(ssh, c);
		channel_pre_open(ssh, c);
	} अन्यथा यदि (ret == -1) {
		logit("X11 connection rejected because of wrong "
		    "authentication.");
		debug2("X11 rejected %d i%d/o%d",
		    c->self, c->istate, c->ostate);
		channel_force_close(ssh, c, 0);
	}
}

स्थिर शून्य
channel_pre_mux_client(संरचना ssh *ssh, Channel *c)
{
	c->io_want = 0;
	यदि (c->istate == CHAN_आगत_OPEN && !c->mux_pause &&
	    sshbuf_check_reserve(c->आगत, CHAN_RBUF) == 0)
		c->io_want |= SSH_CHAN_IO_RFD;
	यदि (c->istate == CHAN_आगत_WAIT_DRAIN) {
		/* clear buffer immediately (discard any partial packet) */
		sshbuf_reset(c->आगत);
		chan_ibuf_empty(ssh, c);
		/* Start output drain. XXX just kill chan? */
		chan_rcvd_oclose(ssh, c);
	}
	यदि (c->ostate == CHAN_OUTPUT_OPEN ||
	    c->ostate == CHAN_OUTPUT_WAIT_DRAIN) {
		यदि (sshbuf_len(c->output) > 0)
			c->io_want |= SSH_CHAN_IO_WFD;
		अन्यथा यदि (c->ostate == CHAN_OUTPUT_WAIT_DRAIN)
			chan_obuf_empty(ssh, c);
	}
}

स्थिर अन्तःस्थ पूर्णाङ्क
socks_decode_error(Channel *c, पूर्णाङ्क status, अचर वर्ण *func, अचर वर्ण *सन्देश)
{
	यदि (status == SSH_ERR_MESSAGE_INCOMPLETE)
		फर्काऊ 0;
	अन्यथा {
		debug_r(status, "%s: channel %d: decode %s",
		    func, c->self, सन्देश);
		फर्काऊ -1;
	}
}

/* try to decode a socks4 header */
स्थिर पूर्णाङ्क
channel_decode_socks4(Channel *c, संरचना sshbuf *आगत, संरचना sshbuf *output)
{
	uint8_t socks_ver, socks_cmd, dest_addr[4];
	uint16_t dest_port;
	वर्ण *user = रिक्त, *host = रिक्त;
	पूर्णाङ्क success = -1, socks4a = 0, r;
	संरचना sshbuf *b = रिक्त;

	यदि (sshbuf_len(आगत) < 9)
		फर्काऊ 0;

	/* We may not have a complete message, so work on a dup of the buffer */
	यदि ((b = sshbuf_fromb(आगत)) == रिक्त)
		fatal_f("sshbuf_fromb failed");

	debug2("channel %d: decode socks4", c->self);
	यदि ((r = sshbuf_get_u8(b, &socks_ver)) != 0 ||
	    (r = sshbuf_get_u8(b, &socks_cmd)) != 0 ||
	    (r = sshbuf_get_u16(b, &dest_port)) != 0 ||
	    (r = sshbuf_get(b, &dest_addr, परिमाण(dest_addr))) != 0 ||
	    (r = sshbuf_get_nulterminated_string(b, 1024, &user, रिक्त)) != 0) {
		success = socks_decode_error(c, r, __func__, "header");
		गच्छ out;
	}

	/* Is this a SOCKS4A request? (indicated by an address of 0.0.0.x) */
	यदि (dest_addr[0] == 0 && dest_addr[1] == 0 &&
	    dest_addr[2] == 0 && dest_addr[3] != 0) {
		/* If so, then the hostname follows, also nul-terminated */
		यदि ((r = sshbuf_get_nulterminated_string(b, 1024,
		    &host, रिक्त)) != 0) {
			success = socks_decode_error(c, r, __func__, "host");
			गच्छ out;
		}
		socks4a = 1;
	} अन्यथा {
		/* Plain SOCKS4 passes an IPv4 binary address; reconstruct */
		xasprintf(&host, "%d.%d.%d.%d",
		    dest_addr[0], dest_addr[1], dest_addr[2], dest_addr[3]);
	}

	/* We have a complete SOCKS4 message; consume it from input */
	यदि ((r = sshbuf_consume_upto_child(आगत, b)) != 0)
		fatal_fr(r, "channel %d: consume", c->self);

	/* Handle the request */
	debug2("channel %d: %s: user=\"%s\" command=%d destination=[%s]:%d",
	    c->self, socks4a ? "SOCKS4A" : "SOCKS4", user, (पूर्णाङ्क)socks_cmd,
	    host, dest_port);
	यदि (socks_cmd != 1) {
		debug("channel %d: cannot handle %s command 0x%02x",
		    c->self, socks4a ? "SOCKS4A" : "SOCKS4", socks_cmd);
		गच्छ out;
	}
	मुक्त(c->path);
	c->path = host;
	host = रिक्त; /* transferred */
	c->host_port = dest_port;

	/* Reply to the SOCKS4 client */
	यदि ((r = sshbuf_put_u8(output, 0)) != 0 ||	/* vn: 0 for reply */
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
	फर्काऊ success;
}

/* try to decode a socks5 header */
#define SSH_SOCKS5_AUTHDONE	0x1000
#define SSH_SOCKS5_NOAUTH	0x00
#define SSH_SOCKS5_IPV4		0x01
#define SSH_SOCKS5_DOMAIN	0x03
#define SSH_SOCKS5_IPV6		0x04
#define SSH_SOCKS5_CONNECT	0x01
#define SSH_SOCKS5_SUCCESS	0x00

/*
 * Handles SOCKS5 authentication. Note 'b' must be a dup of 'input'
 * Returns 0 on insufficient queued date, 1 on authentication success or
 * -1 on error.
 */
स्थिर पूर्णाङ्क
channel_socks5_check_auth(Channel *c, संरचना sshbuf *b, संरचना sshbuf *आगत,
    संरचना sshbuf *output)
{
	uint8_t socks_ver;
	uint8_t nmethods, method;
	पूर्णाङ्क r;
	u_int i, found;

	/* format: ver | nmethods | methods */
	यदि ((r = sshbuf_get_u8(b, &socks_ver)) != 0)
		फर्काऊ socks_decode_error(c, r, __func__, "version");
	यदि (socks_ver != 5) /* shouldn't happen; checked by caller^2 */
		fatal_fr(r, "channel %d: internal error: not socks5", c->self);
	यदि ((r = sshbuf_get_u8(b, &nmethods)) != 0)
		फर्काऊ socks_decode_error(c, r, __func__, "methods");
	लागि (found = i = 0; i < nmethods; i++) {
		यदि ((r = sshbuf_get_u8(b, &method)) != 0)
			फर्काऊ socks_decode_error(c, r, __func__, "method");
		यदि (method == SSH_SOCKS5_NOAUTH)
			found = 1;
	}
	यदि (!found) {
		debug("channel %d: didn't request SSH_SOCKS5_NOAUTH", c->self);
		फर्काऊ -1;
	}
	/* Consume completed request */
	यदि ((r = sshbuf_consume_upto_child(आगत, b)) != 0)
		fatal_fr(r, "channel %d: consume", c->self);

	/* Compose reply: version, method */
	यदि ((r = sshbuf_put_u8(output, 0x05)) != 0 ||
	    (r = sshbuf_put_u8(output, SSH_SOCKS5_NOAUTH)) != 0)
		fatal_fr(r, "channel %d: append reply", c->self);
	/* success */
	debug2("channel %d: socks5 auth done", c->self);
	फर्काऊ 1;
}

स्थिर पूर्णाङ्क
channel_decode_socks5(Channel *c, संरचना sshbuf *आगत, संरचना sshbuf *output)
{
	uint8_t socks_ver, socks_cmd, socks_reserved, socks_atyp, addrlen;
	uint16_t dest_port;
	वर्ण dest_addr[255+1], ntop[INET6_ADDRSTRLEN];
	u_int af;
	पूर्णाङ्क r, success = -1;;
	संरचना sshbuf *b = रिक्त;

	debug2("channel %d: decode socks5 %s", c->self,
	    (c->flags & SSH_SOCKS5_AUTHDONE) ? "request" : "auth");

	/* We may not have a complete message, so work on a dup of the buffer */
	यदि ((b = sshbuf_fromb(आगत)) == रिक्त)
		fatal_f("sshbuf_fromb failed");

	यदि (!(c->flags & SSH_SOCKS5_AUTHDONE)) {
		यदि ((r = channel_socks5_check_auth(c, b, आगत, output)) != 1) {
			success = r;
			गच्छ out;
		}
		c->flags |= SSH_SOCKS5_AUTHDONE;
		/* Continue to parse request in case client speculated ahead */
	}

	/* Request messages (auth or connect) always start with the version */
	यदि ((r = sshbuf_get_u8(b, &socks_ver)) != 0) {
		success = socks_decode_error(c, r, __func__, "version");
		गच्छ out;
	}
	यदि (socks_ver != 5) /* shouldn't happen */
		fatal_fr(r, "channel %d: internal error: not socks5", c->self);

	/* Parse SOCKS5 request header */
	debug2("channel %d: socks5 post auth", c->self);
	यदि ((r = sshbuf_get_u8(b, &socks_cmd)) != 0 ||
	    (r = sshbuf_get_u8(b, &socks_reserved)) != 0 ||
	    (r = sshbuf_get_u8(b, &socks_atyp)) != 0) {
		success = socks_decode_error(c, r, __func__, "request header");
		गच्छ out;
	}

	यदि (socks_ver != 0x05 ||
	    socks_cmd != SSH_SOCKS5_CONNECT ||
	    socks_reserved != 0x00) {
		debug2("channel %d: only socks5 connect supported", c->self);
		गच्छ out;
	}

	विकल्प (socks_atyp) {
	पक्ष SSH_SOCKS5_IPV4:
		addrlen = 4;
		af = AF_INET;
		रोक;
	पक्ष SSH_SOCKS5_DOMAIN:
		यदि ((r = sshbuf_get_u8(b, &addrlen)) != 0) {
			success = socks_decode_error(c, r, __func__, "addrlen");
			गच्छ out;
		}
		af = -1;
		रोक;
	पक्ष SSH_SOCKS5_IPV6:
		addrlen = 16;
		af = AF_INET6;
		रोक;
	स्वभाव:
		debug2("channel %d: bad socks5 atyp %d", c->self, socks_atyp);
		गच्छ out;
	}
	यदि ((r = sshbuf_get(b, &dest_addr, addrlen)) != 0 ||
	    (r = sshbuf_get_u16(b, &dest_port)) != 0) {
		success = socks_decode_error(c, r, __func__, "addr/port");
		गच्छ out;
	}
	dest_addr[addrlen] = '\0';

	/* We have a complete SOCKS5 request; consume it from input */
	यदि ((r = sshbuf_consume_upto_child(आगत, b)) != 0)
		fatal_fr(r, "channel %d: consume", c->self);

	मुक्त(c->path);
	c->path = रिक्त;
	यदि (socks_atyp == SSH_SOCKS5_DOMAIN)
		c->path = xstrdup(dest_addr);
	अन्यथा {
		यदि (inet_ntop(af, dest_addr, ntop, परिमाण(ntop)) == रिक्त)
			फर्काऊ -1;
		c->path = xstrdup(ntop);
	}
	c->host_port = dest_port;

	debug2("channel %d: dynamic request: socks5 host %s port %u command %u",
	    c->self, c->path, c->host_port, socks_cmd);

	/* Reply */
	यदि ((r = sshbuf_put_u8(output, 0x05)) != 0 ||	/* version */
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
	फर्काऊ success;
}

Channel *
channel_connect_stdio_fwd(संरचना ssh *ssh,
    अचर वर्ण *host_to_connect, पूर्णाङ्क port_to_connect,
    पूर्णाङ्क in, पूर्णाङ्क out, पूर्णाङ्क nonblock)
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

	फर्काऊ c;
}

/* dynamic port forwarding */
स्थिर शून्य
channel_pre_dynamic(संरचना ssh *ssh, Channel *c)
{
	u_int have;
	u_char ver;
	पूर्णाङ्क r, ret;

	c->io_want = 0;
	have = sshbuf_len(c->आगत);
	debug2("channel %d: pre_dynamic: have %d", c->self, have);
	/* sshbuf_dump(c->input, stderr); */
	/* check if the fixed size part of the packet is in buffer. */
	यदि (have < 3) {
		/* need more */
		c->io_want |= SSH_CHAN_IO_RFD;
		फर्काऊ;
	}
	/* try to guess the protocol */
	यदि ((r = sshbuf_peek_u8(c->आगत, 0, &ver)) != 0)
		fatal_fr(r, "sshbuf_peek_u8");
	विकल्प (ver) {
	पक्ष 0x04:
		ret = channel_decode_socks4(c, c->आगत, c->output);
		रोक;
	पक्ष 0x05:
		ret = channel_decode_socks5(c, c->आगत, c->output);
		रोक;
	स्वभाव:
		debug2_f("channel %d: unknown SOCKS version %u", c->self, ver);
		ret = -1;
		रोक;
	}
	यदि (ret < 0) {
		chan_mark_dead(ssh, c);
	} अन्यथा यदि (ret == 0) {
		debug2("channel %d: pre_dynamic: need more", c->self);
		/* need more */
		c->io_want |= SSH_CHAN_IO_RFD;
		यदि (sshbuf_len(c->output))
			c->io_want |= SSH_CHAN_IO_WFD;
	} अन्यथा {
		/* switch to the next state */
		c->type = SSH_CHANNEL_OPENING;
		port_open_helper(ssh, c, "direct-tcpip");
	}
}

/* simulate read-error */
स्थिर शून्य
rdynamic_close(संरचना ssh *ssh, Channel *c)
{
	c->type = SSH_CHANNEL_OPEN;
	channel_force_close(ssh, c, 0);
}

/* reverse dynamic port forwarding */
स्थिर शून्य
channel_before_prepare_io_rdynamic(संरचना ssh *ssh, Channel *c)
{
	अचर u_char *p;
	u_int have, len;
	पूर्णाङ्क r, ret;

	have = sshbuf_len(c->output);
	debug2("channel %d: pre_rdynamic: have %d", c->self, have);
	/* sshbuf_dump(c->output, stderr); */
	/* EOF received */
	यदि (c->flags & CHAN_EOF_RCVD) {
		यदि ((r = sshbuf_consume(c->output, have)) != 0)
			fatal_fr(r, "channel %d: consume", c->self);
		rdynamic_close(ssh, c);
		फर्काऊ;
	}
	/* check if the fixed size part of the packet is in buffer. */
	यदि (have < 3)
		फर्काऊ;
	/* try to guess the protocol */
	p = sshbuf_ptr(c->output);
	विकल्प (p[0]) {
	पक्ष 0x04:
		/* switch input/output for reverse forwarding */
		ret = channel_decode_socks4(c, c->output, c->आगत);
		रोक;
	पक्ष 0x05:
		ret = channel_decode_socks5(c, c->output, c->आगत);
		रोक;
	स्वभाव:
		ret = -1;
		रोक;
	}
	यदि (ret < 0) {
		rdynamic_close(ssh, c);
	} अन्यथा यदि (ret == 0) {
		debug2("channel %d: pre_rdynamic: need more", c->self);
		/* send socks request to peer */
		len = sshbuf_len(c->आगत);
		यदि (len > 0 && len < c->remote_window) {
			यदि ((r = sshpkt_start(ssh, SSH2_सन्देश_CHANNEL_DATA)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
			    (r = sshpkt_put_stringb(ssh, c->आगत)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0) {
				fatal_fr(r, "channel %i: rdynamic", c->self);
			}
			यदि ((r = sshbuf_consume(c->आगत, len)) != 0)
				fatal_fr(r, "channel %d: consume", c->self);
			c->remote_window -= len;
		}
	} अन्यथा यदि (rdynamic_connect_finish(ssh, c) < 0) {
		/* the connect failed */
		rdynamic_close(ssh, c);
	}
}

/* This is our fake X11 server socket. */
स्थिर शून्य
channel_post_x11_listener(संरचना ssh *ssh, Channel *c)
{
	Channel *nc;
	संरचना sockaddr_storage addr;
	पूर्णाङ्क r, newsock, oerrno, remote_port;
	socklen_t addrlen;
	वर्ण buf[16384], *remote_ipaddr;

	यदि ((c->io_ready & SSH_CHAN_IO_SOCK_R) == 0)
		फर्काऊ;

	debug("X11 connection requested.");
	addrlen = परिमाण(addr);
	newsock = accept(c->sock, (संरचना sockaddr *)&addr, &addrlen);
	यदि (c->single_connection) {
		oerrno = त्रुटि_सं;
		debug2("single_connection: closing X11 listener.");
		channel_close_fd(ssh, c, &c->sock);
		chan_mark_dead(ssh, c);
		त्रुटि_सं = oerrno;
	}
	यदि (newsock == -1) {
		यदि (त्रुटि_सं != EINTR && त्रुटि_सं != EWOULDBLOCK &&
		    त्रुटि_सं != ECONNABORTED)
			error("accept: %.100s", म_त्रुटि(त्रुटि_सं));
		यदि (त्रुटि_सं == EMFILE || त्रुटि_सं == ENFILE)
			c->notbefore = monotime_double() + 1.0;
		फर्काऊ;
	}
	set_nodelay(newsock);
	यदि (ssh->chanctxt->want_tcp_keepalive)
		set_keepalive(newsock); /* logs errors */
	remote_ipaddr = get_peer_ipaddr(newsock);
	remote_port = get_peer_port(newsock);
	snprintf(buf, परिमाण buf, "X11 connection from %.200s port %d",
	    remote_ipaddr, remote_port);

	nc = channel_new(ssh, "x11-connection",
	    SSH_CHANNEL_OPENING, newsock, newsock, -1,
	    c->local_window_max, c->local_maxpacket, 0, buf, 1);
	open_preamble(ssh, __func__, nc, "x11");
	यदि ((r = sshpkt_put_cstring(ssh, remote_ipaddr)) != 0 ||
	    (r = sshpkt_put_u32(ssh, remote_port)) != 0) {
		fatal_fr(r, "channel %i: reply", c->self);
	}
	यदि ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i: send", c->self);
	मुक्त(remote_ipaddr);
}

स्थिर शून्य
port_open_helper(संरचना ssh *ssh, Channel *c, वर्ण *rtype)
{
	वर्ण *local_ipaddr = get_local_ipaddr(c->sock);
	पूर्णाङ्क local_port = c->sock == -1 ? 65536 : get_local_port(c->sock);
	वर्ण *remote_ipaddr = get_peer_ipaddr(c->sock);
	पूर्णाङ्क remote_port = get_peer_port(c->sock);
	पूर्णाङ्क r;

	यदि (remote_port == -1) {
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
	यदि (म_भेद(rtype, "direct-tcpip") == 0) {
		/* target host, port */
		यदि ((r = sshpkt_put_cstring(ssh, c->path)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->host_port)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	} अन्यथा यदि (म_भेद(rtype, "direct-streamlocal@openssh.com") == 0) {
		/* target path */
		यदि ((r = sshpkt_put_cstring(ssh, c->path)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	} अन्यथा यदि (म_भेद(rtype, "forwarded-streamlocal@openssh.com") == 0) {
		/* listen path */
		यदि ((r = sshpkt_put_cstring(ssh, c->path)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	} अन्यथा {
		/* listen address, port */
		यदि ((r = sshpkt_put_cstring(ssh, c->path)) != 0 ||
		    (r = sshpkt_put_u32(ssh, local_port)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	}
	यदि (म_भेद(rtype, "forwarded-streamlocal@openssh.com") == 0) {
		/* reserved for future owner/mode info */
		यदि ((r = sshpkt_put_cstring(ssh, "")) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	} अन्यथा {
		/* originator host and port */
		यदि ((r = sshpkt_put_cstring(ssh, remote_ipaddr)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)remote_port)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	}
	यदि ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i: send", c->self);
	मुक्त(remote_ipaddr);
	मुक्त(local_ipaddr);
}

शून्य
channel_set_x11_refuse_time(संरचना ssh *ssh, द्विगुण refuse_time)
{
	ssh->chanctxt->x11_refuse_time = refuse_time;
}

/*
 * This socket is listening for connections to a forwarded TCP/IP port.
 */
स्थिर शून्य
channel_post_port_listener(संरचना ssh *ssh, Channel *c)
{
	Channel *nc;
	संरचना sockaddr_storage addr;
	पूर्णाङ्क newsock, nextstate;
	socklen_t addrlen;
	वर्ण *rtype;

	यदि ((c->io_ready & SSH_CHAN_IO_SOCK_R) == 0)
		फर्काऊ;

	debug("Connection to port %d forwarding to %.100s port %d requested.",
	    c->listening_port, c->path, c->host_port);

	यदि (c->type == SSH_CHANNEL_RPORT_LISTENER) {
		nextstate = SSH_CHANNEL_OPENING;
		rtype = "forwarded-tcpip";
	} अन्यथा यदि (c->type == SSH_CHANNEL_RUNIX_LISTENER) {
		nextstate = SSH_CHANNEL_OPENING;
		rtype = "forwarded-streamlocal@openssh.com";
	} अन्यथा यदि (c->host_port == PORT_STREAMLOCAL) {
		nextstate = SSH_CHANNEL_OPENING;
		rtype = "direct-streamlocal@openssh.com";
	} अन्यथा यदि (c->host_port == 0) {
		nextstate = SSH_CHANNEL_DYNAMIC;
		rtype = "dynamic-tcpip";
	} अन्यथा {
		nextstate = SSH_CHANNEL_OPENING;
		rtype = "direct-tcpip";
	}

	addrlen = परिमाण(addr);
	newsock = accept(c->sock, (संरचना sockaddr *)&addr, &addrlen);
	यदि (newsock == -1) {
		यदि (त्रुटि_सं != EINTR && त्रुटि_सं != EWOULDBLOCK &&
		    त्रुटि_सं != ECONNABORTED)
			error("accept: %.100s", म_त्रुटि(त्रुटि_सं));
		यदि (त्रुटि_सं == EMFILE || त्रुटि_सं == ENFILE)
			c->notbefore = monotime_double() + 1.0;
		फर्काऊ;
	}
	यदि (addr.ss_family == AF_INET || addr.ss_family == AF_INET6) {
		set_nodelay(newsock);
		यदि (ssh->chanctxt->want_tcp_keepalive)
			set_keepalive(newsock); /* logs errors */
	}
	nc = channel_new(ssh, rtype, nextstate, newsock, newsock, -1,
	    c->local_window_max, c->local_maxpacket, 0, rtype, 1);
	nc->listening_port = c->listening_port;
	nc->host_port = c->host_port;
	यदि (c->path != रिक्त)
		nc->path = xstrdup(c->path);

	यदि (nextstate != SSH_CHANNEL_DYNAMIC)
		port_open_helper(ssh, nc, rtype);
}

/*
 * This is the authentication agent socket listening for connections from
 * clients.
 */
स्थिर शून्य
channel_post_auth_listener(संरचना ssh *ssh, Channel *c)
{
	Channel *nc;
	पूर्णाङ्क r, newsock;
	संरचना sockaddr_storage addr;
	socklen_t addrlen;

	यदि ((c->io_ready & SSH_CHAN_IO_SOCK_R) == 0)
		फर्काऊ;

	addrlen = परिमाण(addr);
	newsock = accept(c->sock, (संरचना sockaddr *)&addr, &addrlen);
	यदि (newsock == -1) {
		error("accept from auth socket: %.100s", म_त्रुटि(त्रुटि_सं));
		यदि (त्रुटि_सं == EMFILE || त्रुटि_सं == ENFILE)
			c->notbefore = monotime_double() + 1.0;
		फर्काऊ;
	}
	nc = channel_new(ssh, "agent-connection",
	    SSH_CHANNEL_OPENING, newsock, newsock, -1,
	    c->local_window_max, c->local_maxpacket,
	    0, "accepted auth socket", 1);
	open_preamble(ssh, __func__, nc,
	    c->agent_new ? "agent-connect" : "auth-agent@openssh.com");
	यदि ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i", c->self);
}

स्थिर शून्य
channel_post_connecting(संरचना ssh *ssh, Channel *c)
{
	पूर्णाङ्क err = 0, sock, isopen, r;
	socklen_t sz = परिमाण(err);

	यदि ((c->io_ready & SSH_CHAN_IO_SOCK_W) == 0)
		फर्काऊ;
	यदि (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);
	यदि (c->connect_ctx == रिक्त)
		fatal_f("channel %d: context missing", c->self);

	/* for rdynamic the OPEN_CONFIRMATION has been sent already */
	isopen = (c->type == SSH_CHANNEL_RDYNAMIC_FINISH);

	यदि (getsockopt(c->sock, SOL_SOCKET, SO_ERROR, &err, &sz) == -1) {
		err = त्रुटि_सं;
		error("getsockopt SO_ERROR failed");
	}

	यदि (err == 0) {
		/* Non-blocking connection completed */
		debug("channel %d: connected to %s port %d",
		    c->self, c->connect_ctx->host, c->connect_ctx->port);
		channel_free_connect_ctx(c);
		c->type = SSH_CHANNEL_OPEN;
		channel_set_used_time(ssh, c);
		यदि (isopen) {
			/* no message necessary */
		} अन्यथा {
			यदि ((r = sshpkt_start(ssh,
			    SSH2_सन्देश_CHANNEL_OPEN_CONFIRMATION)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_window)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "channel %i open confirm", c->self);
		}
		फर्काऊ;
	}
	यदि (err == EINTR || err == EAGAIN || err == EINPROGRESS)
		फर्काऊ;

	/* Non-blocking connection failed */
	debug("channel %d: connection failed: %s", c->self, म_त्रुटि(err));

	/* Try next address, if any */
	यदि ((sock = connect_next(ssh, c->connect_ctx)) == -1) {
		/* Exhausted all addresses for this destination */
		error("connect_to %.100s port %d: failed.",
		    c->connect_ctx->host, c->connect_ctx->port);
		channel_free_connect_ctx(c);
		यदि (isopen) {
			rdynamic_close(ssh, c);
		} अन्यथा {
			यदि ((r = sshpkt_start(ssh,
			    SSH2_सन्देश_CHANNEL_OPEN_FAILURE)) != 0 ||
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

स्थिर पूर्णाङ्क
channel_handle_rfd(संरचना ssh *ssh, Channel *c)
{
	वर्ण buf[CHAN_RBUF];
	ssize_t len;
	पूर्णाङ्क r, force;
	माप_प्रकार nr = 0, have, avail, maxlen = CHANNEL_MAX_READ;
	पूर्णाङ्क pty_zeroread = 0;

#ifdef PTY_ZEROREAD
	/* Bug on AIX: read(1) can return 0 for a non-closed fd */
	pty_zeroread = c->isatty;
#endif

	force = c->isatty && c->detach_close && c->istate != CHAN_आगत_CLOSED;

	यदि (!force && (c->io_ready & SSH_CHAN_IO_RFD) == 0)
		फर्काऊ 1;
	यदि ((avail = sshbuf_avail(c->आगत)) == 0)
		फर्काऊ 1; /* Shouldn't happen */

	/*
	 * For "simple" channels (i.e. not datagram or filtered), we can
	 * read directly to the channel buffer.
	 */
	यदि (!pty_zeroread && c->आगत_filter == रिक्त && !c->datagram) {
		/* Only OPEN channels have valid rwin */
		यदि (c->type == SSH_CHANNEL_OPEN) {
			यदि ((have = sshbuf_len(c->आगत)) >= c->remote_window)
				फर्काऊ 1; /* shouldn't happen */
			यदि (maxlen > c->remote_window - have)
				maxlen = c->remote_window - have;
		}
		यदि (maxlen > avail)
			maxlen = avail;
		यदि ((r = sshbuf_read(c->rfd, c->आगत, maxlen, &nr)) != 0) {
			यदि (त्रुटि_सं == EINTR || (!force &&
			    (त्रुटि_सं == EAGAIN || त्रुटि_सं == EWOULDBLOCK)))
				फर्काऊ 1;
			debug2("channel %d: read failed rfd %d maxlen %zu: %s",
			    c->self, c->rfd, maxlen, ssh_err(r));
			गच्छ rfail;
		}
		यदि (nr != 0)
			channel_set_used_time(ssh, c);
		फर्काऊ 1;
	}

	त्रुटि_सं = 0;
	len = पठ(c->rfd, buf, परिमाण(buf));
	/* fixup AIX zero-length read with errno set to look more like errors */
	यदि (pty_zeroread && len == 0 && त्रुटि_सं != 0)
		len = -1;
	यदि (len == -1 && (त्रुटि_सं == EINTR ||
	    ((त्रुटि_सं == EAGAIN || त्रुटि_सं == EWOULDBLOCK) && !force)))
		फर्काऊ 1;
	यदि (len < 0 || (!pty_zeroread && len == 0)) {
		debug2("channel %d: read<=0 rfd %d len %zd: %s",
		    c->self, c->rfd, len,
		    len == 0 ? "closed" : म_त्रुटि(त्रुटि_सं));
 rfail:
		यदि (c->type != SSH_CHANNEL_OPEN) {
			debug2("channel %d: not open", c->self);
			chan_mark_dead(ssh, c);
			फर्काऊ -1;
		} अन्यथा {
			chan_read_failed(ssh, c);
		}
		फर्काऊ -1;
	}
	channel_set_used_time(ssh, c);
	यदि (c->आगत_filter != रिक्त) {
		यदि (c->आगत_filter(ssh, c, buf, len) == -1) {
			debug2("channel %d: filter stops", c->self);
			chan_read_failed(ssh, c);
		}
	} अन्यथा यदि (c->datagram) {
		यदि ((r = sshbuf_put_string(c->आगत, buf, len)) != 0)
			fatal_fr(r, "channel %i: put datagram", c->self);
	} अन्यथा यदि ((r = sshbuf_put(c->आगत, buf, len)) != 0)
		fatal_fr(r, "channel %i: put data", c->self);

	फर्काऊ 1;
}

स्थिर पूर्णाङ्क
channel_handle_wfd(संरचना ssh *ssh, Channel *c)
{
	संरचना termios tio;
	u_char *data = रिक्त, *buf; /* XXX const; need filter API change */
	माप_प्रकार dlen, olen = 0;
	पूर्णाङ्क r, len;

	यदि ((c->io_ready & SSH_CHAN_IO_WFD) == 0)
		फर्काऊ 1;
	यदि (sshbuf_len(c->output) == 0)
		फर्काऊ 1;

	/* Send buffered output data to the socket. */
	olen = sshbuf_len(c->output);
	यदि (c->output_filter != रिक्त) {
		यदि ((buf = c->output_filter(ssh, c, &data, &dlen)) == रिक्त) {
			debug2("channel %d: filter stops", c->self);
			यदि (c->type != SSH_CHANNEL_OPEN)
				chan_mark_dead(ssh, c);
			अन्यथा
				chan_write_failed(ssh, c);
			फर्काऊ -1;
		}
	} अन्यथा यदि (c->datagram) {
		यदि ((r = sshbuf_get_string(c->output, &data, &dlen)) != 0)
			fatal_fr(r, "channel %i: get datagram", c->self);
		buf = data;
	} अन्यथा {
		buf = data = sshbuf_mutable_ptr(c->output);
		dlen = sshbuf_len(c->output);
	}

	यदि (c->datagram) {
		/* ignore truncated writes, datagrams might get lost */
		len = लिख(c->wfd, buf, dlen);
		मुक्त(data);
		यदि (len == -1 && (त्रुटि_सं == EINTR || त्रुटि_सं == EAGAIN ||
		    त्रुटि_सं == EWOULDBLOCK))
			फर्काऊ 1;
		यदि (len <= 0)
			गच्छ write_fail;
		गच्छ out;
	}

#ifdef _AIX
	/* XXX: Later AIX versions can't push as much data to tty */
	यदि (c->wfd_isatty)
		dlen = MINIMUM(dlen, 8*1024);
#endif

	len = लिख(c->wfd, buf, dlen);
	यदि (len == -1 &&
	    (त्रुटि_सं == EINTR || त्रुटि_सं == EAGAIN || त्रुटि_सं == EWOULDBLOCK))
		फर्काऊ 1;
	यदि (len <= 0) {
 write_fail:
		यदि (c->type != SSH_CHANNEL_OPEN) {
			debug2("channel %d: not open", c->self);
			chan_mark_dead(ssh, c);
			फर्काऊ -1;
		} अन्यथा {
			chan_write_failed(ssh, c);
		}
		फर्काऊ -1;
	}
	channel_set_used_time(ssh, c);
#ifndef BROKEN_TCGETATTR_ICANON
	यदि (c->isatty && dlen >= 1 && buf[0] != '\r') {
		यदि (tcgetattr(c->wfd, &tio) == 0 &&
		    !(tio.c_lflag & ECHO) && (tio.c_lflag & ICANON)) {
			/*
			 * Simulate echo to reduce the impact of
			 * traffic analysis. We need to match the
			 * size of a SSH2_MSG_CHANNEL_DATA message
			 * (4 byte channel id + buf)
			 */
			यदि ((r = sshpkt_सन्देश_ignore(ssh, 4+len)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "channel %i: ignore", c->self);
		}
	}
#endif /* BROKEN_TCGETATTR_ICANON */
	यदि ((r = sshbuf_consume(c->output, len)) != 0)
		fatal_fr(r, "channel %i: consume", c->self);
 out:
	c->local_consumed += olen - sshbuf_len(c->output);

	फर्काऊ 1;
}

स्थिर पूर्णाङ्क
channel_handle_efd_write(संरचना ssh *ssh, Channel *c)
{
	पूर्णाङ्क r;
	ssize_t len;

	यदि ((c->io_ready & SSH_CHAN_IO_EFD_W) == 0)
		फर्काऊ 1;
	यदि (sshbuf_len(c->extended) == 0)
		फर्काऊ 1;

	len = लिख(c->efd, sshbuf_ptr(c->extended),
	    sshbuf_len(c->extended));
	debug2("channel %d: written %zd to efd %d", c->self, len, c->efd);
	यदि (len == -1 && (त्रुटि_सं == EINTR || त्रुटि_सं == EAGAIN ||
	    त्रुटि_सं == EWOULDBLOCK))
		फर्काऊ 1;
	यदि (len <= 0) {
		debug2("channel %d: closing write-efd %d", c->self, c->efd);
		channel_close_fd(ssh, c, &c->efd);
	} अन्यथा {
		यदि ((r = sshbuf_consume(c->extended, len)) != 0)
			fatal_fr(r, "channel %i: consume", c->self);
		c->local_consumed += len;
		channel_set_used_time(ssh, c);
	}
	फर्काऊ 1;
}

स्थिर पूर्णाङ्क
channel_handle_efd_read(संरचना ssh *ssh, Channel *c)
{
	वर्ण buf[CHAN_RBUF];
	ssize_t len;
	पूर्णाङ्क r, force;

	force = c->isatty && c->detach_close && c->istate != CHAN_आगत_CLOSED;

	यदि (!force && (c->io_ready & SSH_CHAN_IO_EFD_R) == 0)
		फर्काऊ 1;

	len = पठ(c->efd, buf, परिमाण(buf));
	debug2("channel %d: read %zd from efd %d", c->self, len, c->efd);
	यदि (len == -1 && (त्रुटि_सं == EINTR || ((त्रुटि_सं == EAGAIN ||
	    त्रुटि_सं == EWOULDBLOCK) && !force)))
		फर्काऊ 1;
	यदि (len <= 0) {
		debug2("channel %d: closing read-efd %d", c->self, c->efd);
		channel_close_fd(ssh, c, &c->efd);
		फर्काऊ 1;
	}
	channel_set_used_time(ssh, c);
	यदि (c->extended_usage == CHAN_EXTENDED_IGNORE)
		debug3("channel %d: discard efd", c->self);
	अन्यथा यदि ((r = sshbuf_put(c->extended, buf, len)) != 0)
		fatal_fr(r, "channel %i: append", c->self);
	फर्काऊ 1;
}

स्थिर पूर्णाङ्क
channel_handle_efd(संरचना ssh *ssh, Channel *c)
{
	यदि (c->efd == -1)
		फर्काऊ 1;

	/** XXX handle drain efd, too */

	यदि (c->extended_usage == CHAN_EXTENDED_WRITE)
		फर्काऊ channel_handle_efd_write(ssh, c);
	अन्यथा यदि (c->extended_usage == CHAN_EXTENDED_READ ||
	    c->extended_usage == CHAN_EXTENDED_IGNORE)
		फर्काऊ channel_handle_efd_read(ssh, c);

	फर्काऊ 1;
}

स्थिर पूर्णाङ्क
channel_check_window(संरचना ssh *ssh, Channel *c)
{
	पूर्णाङ्क r;

	यदि (c->type == SSH_CHANNEL_OPEN &&
	    !(c->flags & (CHAN_CLOSE_SENT|CHAN_CLOSE_RCVD)) &&
	    ((c->local_window_max - c->local_window >
	    c->local_maxpacket*3) ||
	    c->local_window < c->local_window_max/2) &&
	    c->local_consumed > 0) {
		यदि (!c->have_remote_id)
			fatal_f("channel %d: no remote id", c->self);
		यदि ((r = sshpkt_start(ssh,
		    SSH2_सन्देश_CHANNEL_WINDOW_ADJUST)) != 0 ||
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
	फर्काऊ 1;
}

स्थिर शून्य
channel_post_open(संरचना ssh *ssh, Channel *c)
{
	channel_handle_rfd(ssh, c);
	channel_handle_wfd(ssh, c);
	channel_handle_efd(ssh, c);
	channel_check_window(ssh, c);
}

स्थिर u_int
read_mux(संरचना ssh *ssh, Channel *c, u_int need)
{
	वर्ण buf[CHAN_RBUF];
	ssize_t len;
	u_int rlen;
	पूर्णाङ्क r;

	यदि (sshbuf_len(c->आगत) < need) {
		rlen = need - sshbuf_len(c->आगत);
		len = पठ(c->rfd, buf, MINIMUM(rlen, CHAN_RBUF));
		यदि (len == -1 && (त्रुटि_सं == EINTR || त्रुटि_सं == EAGAIN))
			फर्काऊ sshbuf_len(c->आगत);
		यदि (len <= 0) {
			debug2("channel %d: ctl read<=0 rfd %d len %zd",
			    c->self, c->rfd, len);
			chan_read_failed(ssh, c);
			फर्काऊ 0;
		} अन्यथा यदि ((r = sshbuf_put(c->आगत, buf, len)) != 0)
			fatal_fr(r, "channel %i: append", c->self);
	}
	फर्काऊ sshbuf_len(c->आगत);
}

स्थिर शून्य
channel_post_mux_client_read(संरचना ssh *ssh, Channel *c)
{
	u_int need;

	यदि ((c->io_ready & SSH_CHAN_IO_RFD) == 0)
		फर्काऊ;
	यदि (c->istate != CHAN_आगत_OPEN && c->istate != CHAN_आगत_WAIT_DRAIN)
		फर्काऊ;
	यदि (c->mux_pause)
		फर्काऊ;

	/*
	 * Don't not read past the precise end of packets to
	 * avoid disrupting fd passing.
	 */
	यदि (read_mux(ssh, c, 4) < 4) /* read header */
		फर्काऊ;
	/* XXX sshbuf_peek_u32 */
	need = PEEK_U32(sshbuf_ptr(c->आगत));
#define CHANNEL_MUX_MAX_PACKET	(256 * 1024)
	यदि (need > CHANNEL_MUX_MAX_PACKET) {
		debug2("channel %d: packet too big %u > %u",
		    c->self, CHANNEL_MUX_MAX_PACKET, need);
		chan_rcvd_oclose(ssh, c);
		फर्काऊ;
	}
	यदि (read_mux(ssh, c, need + 4) < need + 4) /* read body */
		फर्काऊ;
	यदि (c->mux_rcb(ssh, c) != 0) {
		debug("channel %d: mux_rcb failed", c->self);
		chan_mark_dead(ssh, c);
		फर्काऊ;
	}
}

स्थिर शून्य
channel_post_mux_client_write(संरचना ssh *ssh, Channel *c)
{
	ssize_t len;
	पूर्णाङ्क r;

	यदि ((c->io_ready & SSH_CHAN_IO_WFD) == 0)
		फर्काऊ;
	यदि (sshbuf_len(c->output) == 0)
		फर्काऊ;

	len = लिख(c->wfd, sshbuf_ptr(c->output), sshbuf_len(c->output));
	यदि (len == -1 && (त्रुटि_सं == EINTR || त्रुटि_सं == EAGAIN))
		फर्काऊ;
	यदि (len <= 0) {
		chan_mark_dead(ssh, c);
		फर्काऊ;
	}
	यदि ((r = sshbuf_consume(c->output, len)) != 0)
		fatal_fr(r, "channel %i: consume", c->self);
}

स्थिर शून्य
channel_post_mux_client(संरचना ssh *ssh, Channel *c)
{
	channel_post_mux_client_read(ssh, c);
	channel_post_mux_client_write(ssh, c);
}

स्थिर शून्य
channel_post_mux_listener(संरचना ssh *ssh, Channel *c)
{
	Channel *nc;
	संरचना sockaddr_storage addr;
	socklen_t addrlen;
	पूर्णाङ्क newsock;
	uid_t euid;
	gid_t egid;

	यदि ((c->io_ready & SSH_CHAN_IO_SOCK_R) == 0)
		फर्काऊ;

	debug("multiplexing control connection");

	/*
	 * Accept connection on control socket
	 */
	स_रखो(&addr, 0, परिमाण(addr));
	addrlen = परिमाण(addr);
	यदि ((newsock = accept(c->sock, (संरचना sockaddr*)&addr,
	    &addrlen)) == -1) {
		error_f("accept: %s", म_त्रुटि(त्रुटि_सं));
		यदि (त्रुटि_सं == EMFILE || त्रुटि_सं == ENFILE)
			c->notbefore = monotime_double() + 1.0;
		फर्काऊ;
	}

	यदि (getpeereid(newsock, &euid, &egid) == -1) {
		error_f("getpeereid failed: %s", म_त्रुटि(त्रुटि_सं));
		बंद(newsock);
		फर्काऊ;
	}
	यदि ((euid != 0) && (getuid() != euid)) {
		error("multiplex uid mismatch: peer euid %u != uid %u",
		    (u_int)euid, (u_int)getuid());
		बंद(newsock);
		फर्काऊ;
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

स्थिर शून्य
channel_handler_init(संरचना ssh_channels *sc)
{
	chan_fn **pre, **post;

	यदि ((pre = सुस्मृति(SSH_CHANNEL_MAX_TYPE, परिमाण(*pre))) == रिक्त ||
	    (post = सुस्मृति(SSH_CHANNEL_MAX_TYPE, परिमाण(*post))) == रिक्त)
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
स्थिर शून्य
channel_garbage_collect(संरचना ssh *ssh, Channel *c)
{
	यदि (c == रिक्त)
		फर्काऊ;
	यदि (c->detach_user != रिक्त) {
		यदि (!chan_is_dead(ssh, c, c->detach_close))
			फर्काऊ;

		debug2("channel %d: gc: notify user", c->self);
		c->detach_user(ssh, c->self, 0, रिक्त);
		/* if we still have a callback */
		यदि (c->detach_user != रिक्त)
			फर्काऊ;
		debug2("channel %d: gc: user detached", c->self);
	}
	यदि (!chan_is_dead(ssh, c, 1))
		फर्काऊ;
	debug2("channel %d: garbage collecting", c->self);
	channel_free(ssh, c);
}

गणना channel_table { CHAN_PRE, CHAN_POST };

स्थिर शून्य
channel_handler(संरचना ssh *ssh, पूर्णाङ्क table, संरचना timespec *timeout)
{
	संरचना ssh_channels *sc = ssh->chanctxt;
	chan_fn **ftab = table == CHAN_PRE ? sc->channel_pre : sc->channel_post;
	u_int i, oalloc;
	Channel *c;
	द्विगुण now;

	now = monotime_double();
	लागि (sc->nbulk = i = 0, oalloc = sc->channels_alloc; i < oalloc; i++) {
		c = sc->channels[i];
		यदि (c == रिक्त)
			जारी;
		/* Count open channels in bulk state */
		यदि (c->type == SSH_CHANNEL_OPEN && c->bulk)
			sc->nbulk++;
		/* Try to keep IO going while rekeying */
		यदि (ssh_packet_is_rekeying(ssh) && c->type != SSH_CHANNEL_OPEN)
			जारी;
		यदि (c->delayed) {
			यदि (table == CHAN_PRE)
				c->delayed = 0;
			अन्यथा
				जारी;
		}
		यदि (ftab[c->type] != रिक्त) {
			यदि (table == CHAN_PRE && c->type == SSH_CHANNEL_OPEN &&
			    channel_get_expiry(ssh, c) != 0 &&
			    now >= channel_get_expiry(ssh, c)) {
				/* channel closed for inactivity */
				द्विगुण deadline = c->inactive_deadline != 0.0 ?
				    c->inactive_deadline : sc->global_deadline;
				verbose("channel %d: closing after %f seconds "
				    "of inactivity", c->self, deadline);
				channel_force_close(ssh, c, 1);
			} अन्यथा यदि (c->notbefore <= now) {
				/* Run handlers that are not paused. */
				(*ftab[c->type])(ssh, c);
				/* inactivity timeouts must interrupt poll() */
				यदि (timeout != रिक्त &&
				    c->type == SSH_CHANNEL_OPEN &&
				    channel_get_expiry(ssh, c) != 0) {
					ptimeout_deadline_monotime_double(timeout,
					    channel_get_expiry(ssh, c));
				}
			} अन्यथा यदि (timeout != रिक्त) {
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
स्थिर शून्य
channel_before_prepare_io(संरचना ssh *ssh)
{
	संरचना ssh_channels *sc = ssh->chanctxt;
	Channel *c;
	u_int i, oalloc;

	लागि (i = 0, oalloc = sc->channels_alloc; i < oalloc; i++) {
		c = sc->channels[i];
		यदि (c == रिक्त)
			जारी;
		यदि (c->type == SSH_CHANNEL_RDYNAMIC_OPEN)
			channel_before_prepare_io_rdynamic(ssh, c);
	}
}

स्थिर शून्य
dump_channel_poll(अचर वर्ण *func, अचर वर्ण *what, Channel *c,
    u_int pollfd_offset, संरचना pollfd *pfd)
{
#ifdef DEBUG_CHANNEL_POLL
	debug3("%s: channel %d: %s r%d w%d e%d s%d c->pfds [ %d %d %d %d ] "
	    "io_want 0x%02x io_ready 0x%02x pfd[%u].fd=%d "
	    "pfd.ev 0x%02x pfd.rev 0x%02x", func, c->self, what,
	    c->rfd, c->wfd, c->efd, c->sock,
	    c->pfds[0], c->pfds[1], c->pfds[2], c->pfds[3],
	    c->io_want, c->io_ready,
	    pollfd_offset, pfd->fd, pfd->events, pfd->revents);
#endif
}

/* Prepare pollfd entries for a single channel */
स्थिर शून्य
channel_prepare_pollfd(Channel *c, u_int *next_pollfd,
    संरचना pollfd *pfd, u_int npfd)
{
	u_int ev, p = *next_pollfd;

	यदि (c == रिक्त)
		फर्काऊ;
	यदि (p + 4 > npfd) {
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
	यदि (c->rfd != -1) {
		ev = 0;
		यदि ((c->io_want & SSH_CHAN_IO_RFD) != 0)
			ev |= POLLIN;
		/* rfd == wfd */
		यदि (c->wfd == c->rfd) {
			यदि ((c->io_want & SSH_CHAN_IO_WFD) != 0)
				ev |= POLLOUT;
		}
		/* rfd == efd */
		यदि (c->efd == c->rfd) {
			यदि ((c->io_want & SSH_CHAN_IO_EFD_R) != 0)
				ev |= POLLIN;
			यदि ((c->io_want & SSH_CHAN_IO_EFD_W) != 0)
				ev |= POLLOUT;
		}
		/* rfd == sock */
		यदि (c->sock == c->rfd) {
			यदि ((c->io_want & SSH_CHAN_IO_SOCK_R) != 0)
				ev |= POLLIN;
			यदि ((c->io_want & SSH_CHAN_IO_SOCK_W) != 0)
				ev |= POLLOUT;
		}
		/* Pack a pfd entry if any event armed for this fd */
		यदि (ev != 0) {
			c->pfds[0] = p;
			pfd[p].fd = c->rfd;
			pfd[p].events = ev;
			dump_channel_poll(__func__, "rfd", c, p, &pfd[p]);
			p++;
		}
	}
	/* prepare c->wfd if wanting IO and not already handled above */
	यदि (c->wfd != -1 && c->rfd != c->wfd) {
		ev = 0;
		यदि ((c->io_want & SSH_CHAN_IO_WFD))
			ev |= POLLOUT;
		/* Pack a pfd entry if any event armed for this fd */
		यदि (ev != 0) {
			c->pfds[1] = p;
			pfd[p].fd = c->wfd;
			pfd[p].events = ev;
			dump_channel_poll(__func__, "wfd", c, p, &pfd[p]);
			p++;
		}
	}
	/* prepare c->efd if wanting IO and not already handled above */
	यदि (c->efd != -1 && c->rfd != c->efd) {
		ev = 0;
		यदि ((c->io_want & SSH_CHAN_IO_EFD_R) != 0)
			ev |= POLLIN;
		यदि ((c->io_want & SSH_CHAN_IO_EFD_W) != 0)
			ev |= POLLOUT;
		/* Pack a pfd entry if any event armed for this fd */
		यदि (ev != 0) {
			c->pfds[2] = p;
			pfd[p].fd = c->efd;
			pfd[p].events = ev;
			dump_channel_poll(__func__, "efd", c, p, &pfd[p]);
			p++;
		}
	}
	/* prepare c->sock if wanting IO and not already handled above */
	यदि (c->sock != -1 && c->rfd != c->sock) {
		ev = 0;
		यदि ((c->io_want & SSH_CHAN_IO_SOCK_R) != 0)
			ev |= POLLIN;
		यदि ((c->io_want & SSH_CHAN_IO_SOCK_W) != 0)
			ev |= POLLOUT;
		/* Pack a pfd entry if any event armed for this fd */
		यदि (ev != 0) {
			c->pfds[3] = p;
			pfd[p].fd = c->sock;
			pfd[p].events = ev;
			dump_channel_poll(__func__, "sock", c, p, &pfd[p]);
			p++;
		}
	}
	*next_pollfd = p;
}

/* * Allocate/prepare poll structure */
शून्य
channel_prepare_poll(संरचना ssh *ssh, संरचना pollfd **pfdp, u_int *npfd_allocp,
    u_int *npfd_activep, u_int npfd_reserved, संरचना timespec *timeout)
{
	संरचना ssh_channels *sc = ssh->chanctxt;
	u_int i, oalloc, p, npfd = npfd_reserved;

	channel_before_prepare_io(ssh); /* might create a new channel */
	/* clear out I/O flags from last poll */
	लागि (i = 0; i < sc->channels_alloc; i++) {
		यदि (sc->channels[i] == रिक्त)
			जारी;
		sc->channels[i]->io_want = sc->channels[i]->io_ready = 0;
	}
	/* Allocate 4x pollfd for each channel (rfd, wfd, efd, sock) */
	यदि (sc->channels_alloc >= (पूर्णांक_उच्च / 4) - npfd_reserved)
		fatal_f("too many channels"); /* shouldn't happen */
	npfd += sc->channels_alloc * 4;
	यदि (npfd > *npfd_allocp) {
		*pfdp = xrecallocarray(*pfdp, *npfd_allocp,
		    npfd, परिमाण(**pfdp));
		*npfd_allocp = npfd;
	}
	*npfd_activep = npfd_reserved;
	oalloc = sc->channels_alloc;

	channel_handler(ssh, CHAN_PRE, timeout);

	यदि (oalloc != sc->channels_alloc) {
		/* shouldn't happen */
		fatal_f("channels_alloc changed during CHAN_PRE "
		    "(was %u, now %u)", oalloc, sc->channels_alloc);
	}

	/* Prepare pollfd */
	p = npfd_reserved;
	लागि (i = 0; i < sc->channels_alloc; i++)
		channel_prepare_pollfd(sc->channels[i], &p, *pfdp, npfd);
	*npfd_activep = p;
}

स्थिर शून्य
fd_ready(Channel *c, पूर्णाङ्क p, संरचना pollfd *pfds, u_int npfd, पूर्णाङ्क fd,
    अचर वर्ण *what, u_int revents_mask, u_int ready)
{
	संरचना pollfd *pfd = &pfds[p];

	यदि (fd == -1)
		फर्काऊ;
	यदि (p == -1 || (u_int)p >= npfd)
		fatal_f("channel %d: bad pfd %d (max %u)", c->self, p, npfd);
	dump_channel_poll(__func__, what, c, p, pfd);
	यदि (pfd->fd != fd) {
		fatal("channel %d: inconsistent %s fd=%d pollfd[%u].fd %d "
		    "r%d w%d e%d s%d", c->self, what, fd, p, pfd->fd,
		    c->rfd, c->wfd, c->efd, c->sock);
	}
	यदि ((pfd->revents & POLLNVAL) != 0) {
		fatal("channel %d: invalid %s pollfd[%u].fd %d r%d w%d e%d s%d",
		    c->self, what, p, pfd->fd, c->rfd, c->wfd, c->efd, c->sock);
	}
	यदि ((pfd->revents & (revents_mask|POLLHUP|POLLERR)) != 0)
		c->io_ready |= ready & c->io_want;
}

/*
 * After poll, perform any appropriate operations for channels which have
 * events pending.
 */
शून्य
channel_after_poll(संरचना ssh *ssh, संरचना pollfd *pfd, u_int npfd)
{
	संरचना ssh_channels *sc = ssh->chanctxt;
	u_int i;
	पूर्णाङ्क p;
	Channel *c;

#ifdef DEBUG_CHANNEL_POLL
	लागि (p = 0; p < (पूर्णाङ्क)npfd; p++) {
		यदि (pfd[p].revents == 0)
			जारी;
		debug_f("pfd[%u].fd %d rev 0x%04x",
		    p, pfd[p].fd, pfd[p].revents);
	}
#endif

	/* Convert pollfd into c->io_ready */
	लागि (i = 0; i < sc->channels_alloc; i++) {
		c = sc->channels[i];
		यदि (c == रिक्त)
			जारी;
		/* if rfd is shared with efd/sock then wfd should be too */
		यदि (c->rfd != -1 && c->wfd != -1 && c->rfd != c->wfd &&
		    (c->rfd == c->efd || c->rfd == c->sock)) {
			/* Shouldn't happen */
			fatal_f("channel %d: unexpected fds r%d w%d e%d s%d",
			    c->self, c->rfd, c->wfd, c->efd, c->sock);
		}
		c->io_ready = 0;
		/* rfd, potentially shared with wfd, efd and sock */
		यदि (c->rfd != -1 && (p = c->pfds[0]) != -1) {
			fd_ready(c, p, pfd, npfd, c->rfd,
			    "rfd", POLLIN, SSH_CHAN_IO_RFD);
			यदि (c->rfd == c->wfd) {
				fd_ready(c, p, pfd, npfd, c->wfd,
				    "wfd/r", POLLOUT, SSH_CHAN_IO_WFD);
			}
			यदि (c->rfd == c->efd) {
				fd_ready(c, p, pfd, npfd, c->efd,
				    "efdr/r", POLLIN, SSH_CHAN_IO_EFD_R);
				fd_ready(c, p, pfd, npfd, c->efd,
				    "efdw/r", POLLOUT, SSH_CHAN_IO_EFD_W);
			}
			यदि (c->rfd == c->sock) {
				fd_ready(c, p, pfd, npfd, c->sock,
				    "sockr/r", POLLIN, SSH_CHAN_IO_SOCK_R);
				fd_ready(c, p, pfd, npfd, c->sock,
				    "sockw/r", POLLOUT, SSH_CHAN_IO_SOCK_W);
			}
			dump_channel_poll(__func__, "rfd", c, p, pfd);
		}
		/* wfd */
		यदि (c->wfd != -1 && c->wfd != c->rfd &&
		    (p = c->pfds[1]) != -1) {
			fd_ready(c, p, pfd, npfd, c->wfd,
			    "wfd", POLLOUT, SSH_CHAN_IO_WFD);
			dump_channel_poll(__func__, "wfd", c, p, pfd);
		}
		/* efd */
		यदि (c->efd != -1 && c->efd != c->rfd &&
		    (p = c->pfds[2]) != -1) {
			fd_ready(c, p, pfd, npfd, c->efd,
			    "efdr", POLLIN, SSH_CHAN_IO_EFD_R);
			fd_ready(c, p, pfd, npfd, c->efd,
			    "efdw", POLLOUT, SSH_CHAN_IO_EFD_W);
			dump_channel_poll(__func__, "efd", c, p, pfd);
		}
		/* sock */
		यदि (c->sock != -1 && c->sock != c->rfd &&
		    (p = c->pfds[3]) != -1) {
			fd_ready(c, p, pfd, npfd, c->sock,
			    "sockr", POLLIN, SSH_CHAN_IO_SOCK_R);
			fd_ready(c, p, pfd, npfd, c->sock,
			    "sockw", POLLOUT, SSH_CHAN_IO_SOCK_W);
			dump_channel_poll(__func__, "sock", c, p, pfd);
		}
	}
	channel_handler(ssh, CHAN_POST, रिक्त);
}

/*
 * Enqueue data for channels with open or draining c->input.
 * Returns non-zero if a packet was enqueued.
 */
स्थिर पूर्णाङ्क
channel_output_poll_आगत_open(संरचना ssh *ssh, Channel *c)
{
	माप_प्रकार len, plen;
	अचर u_char *pkt;
	पूर्णाङ्क r;

	यदि ((len = sshbuf_len(c->आगत)) == 0) {
		यदि (c->istate == CHAN_आगत_WAIT_DRAIN) {
			/*
			 * input-buffer is empty and read-socket shutdown:
			 * tell peer, that we will not send more data:
			 * send IEOF.
			 * hack for extended data: delay EOF if EFD still
			 * in use.
			 */
			यदि (CHANNEL_EFD_आगत_ACTIVE(c))
				debug2("channel %d: "
				    "ibuf_empty delayed efd %d/(%zu)",
				    c->self, c->efd, sshbuf_len(c->extended));
			अन्यथा
				chan_ibuf_empty(ssh, c);
		}
		फर्काऊ 0;
	}

	यदि (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);

	यदि (c->datagram) {
		/* Check datagram will fit; drop if not */
		यदि ((r = sshbuf_get_string_direct(c->आगत, &pkt, &plen)) != 0)
			fatal_fr(r, "channel %i: get datagram", c->self);
		/*
		 * XXX this does tail-drop on the datagram queue which is
		 * usually suboptimal compared to head-drop. Better to have
		 * backpressure at read time? (i.e. read + discard)
		 */
		यदि (plen > c->remote_window || plen > c->remote_maxpacket) {
			debug("channel %d: datagram too big", c->self);
			फर्काऊ 0;
		}
		/* Enqueue it */
		यदि ((r = sshpkt_start(ssh, SSH2_सन्देश_CHANNEL_DATA)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
		    (r = sshpkt_put_string(ssh, pkt, plen)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "channel %i: send datagram", c->self);
		c->remote_window -= plen;
		फर्काऊ 1;
	}

	/* Enqueue packet for buffered data. */
	यदि (len > c->remote_window)
		len = c->remote_window;
	यदि (len > c->remote_maxpacket)
		len = c->remote_maxpacket;
	यदि (len == 0)
		फर्काऊ 0;
	यदि ((r = sshpkt_start(ssh, SSH2_सन्देश_CHANNEL_DATA)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_string(ssh, sshbuf_ptr(c->आगत), len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i: send data", c->self);
	यदि ((r = sshbuf_consume(c->आगत, len)) != 0)
		fatal_fr(r, "channel %i: consume", c->self);
	c->remote_window -= len;
	फर्काऊ 1;
}

/*
 * Enqueue data for channels with open c->extended in read mode.
 * Returns non-zero if a packet was enqueued.
 */
स्थिर पूर्णाङ्क
channel_output_poll_extended_read(संरचना ssh *ssh, Channel *c)
{
	माप_प्रकार len;
	पूर्णाङ्क r;

	यदि ((len = sshbuf_len(c->extended)) == 0)
		फर्काऊ 0;

	debug2("channel %d: rwin %u elen %zu euse %d", c->self,
	    c->remote_window, sshbuf_len(c->extended), c->extended_usage);
	यदि (len > c->remote_window)
		len = c->remote_window;
	यदि (len > c->remote_maxpacket)
		len = c->remote_maxpacket;
	यदि (len == 0)
		फर्काऊ 0;
	यदि (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);
	यदि ((r = sshpkt_start(ssh, SSH2_सन्देश_CHANNEL_EXTENDED_DATA)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_u32(ssh, SSH2_EXTENDED_DATA_STDERR)) != 0 ||
	    (r = sshpkt_put_string(ssh, sshbuf_ptr(c->extended), len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i: data", c->self);
	यदि ((r = sshbuf_consume(c->extended, len)) != 0)
		fatal_fr(r, "channel %i: consume", c->self);
	c->remote_window -= len;
	debug2("channel %d: sent ext data %zu", c->self, len);
	फर्काऊ 1;
}

/*
 * If there is data to send to the connection, enqueue some of it now.
 * Returns non-zero if data was enqueued.
 */
पूर्णाङ्क
channel_output_poll(संरचना ssh *ssh)
{
	संरचना ssh_channels *sc = ssh->chanctxt;
	Channel *c;
	u_int i;
	पूर्णाङ्क ret = 0;

	लागि (i = 0; i < sc->channels_alloc; i++) {
		c = sc->channels[i];
		यदि (c == रिक्त)
			जारी;

		/*
		 * We are only interested in channels that can have buffered
		 * incoming data.
		 */
		यदि (c->type != SSH_CHANNEL_OPEN)
			जारी;
		यदि ((c->flags & (CHAN_CLOSE_SENT|CHAN_CLOSE_RCVD))) {
			/* XXX is this true? */
			debug3("channel %d: will not send data after close",
			    c->self);
			जारी;
		}

		/* Get the amount of buffered data for this channel. */
		यदि (c->istate == CHAN_आगत_OPEN ||
		    c->istate == CHAN_आगत_WAIT_DRAIN)
			ret |= channel_output_poll_आगत_open(ssh, c);
		/* Send extended data, i.e. stderr */
		यदि (!(c->flags & CHAN_EOF_SENT) &&
		    c->extended_usage == CHAN_EXTENDED_READ)
			ret |= channel_output_poll_extended_read(ssh, c);
	}
	फर्काऊ ret;
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
पूर्णाङ्क
channel_proxy_downstream(संरचना ssh *ssh, Channel *downstream)
{
	Channel *c = रिक्त;
	संरचना sshbuf *original = रिक्त, *modified = रिक्त;
	अचर u_char *cp;
	वर्ण *ctype = रिक्त, *listen_host = रिक्त;
	u_char type;
	माप_प्रकार have;
	पूर्णाङ्क ret = -1, r;
	u_int id, remote_id, listen_port;

	/* sshbuf_dump(downstream->input, stderr); */
	यदि ((r = sshbuf_get_string_direct(downstream->आगत, &cp, &have))
	    != 0) {
		error_fr(r, "parse");
		फर्काऊ -1;
	}
	यदि (have < 2) {
		error_f("short message");
		फर्काऊ -1;
	}
	type = cp[1];
	/* skip padlen + type */
	cp += 2;
	have -= 2;
	यदि (ssh_packet_log_type(type))
		debug3_f("channel %u: down->up: type %u",
		    downstream->self, type);

	विकल्प (type) {
	पक्ष SSH2_सन्देश_CHANNEL_OPEN:
		यदि ((original = sshbuf_from(cp, have)) == रिक्त ||
		    (modified = sshbuf_new()) == रिक्त) {
			error_f("alloc");
			गच्छ out;
		}
		यदि ((r = sshbuf_get_cstring(original, &ctype, रिक्त)) != 0 ||
		    (r = sshbuf_get_u32(original, &id)) != 0) {
			error_fr(r, "parse");
			गच्छ out;
		}
		c = channel_new(ssh, "mux-proxy", SSH_CHANNEL_MUX_PROXY,
		    -1, -1, -1, 0, 0, 0, ctype, 1);
		c->mux_ctx = downstream;	/* point to mux client */
		c->mux_downstream_id = id;	/* original downstream id */
		यदि ((r = sshbuf_put_cstring(modified, ctype)) != 0 ||
		    (r = sshbuf_put_u32(modified, c->self)) != 0 ||
		    (r = sshbuf_putb(modified, original)) != 0) {
			error_fr(r, "compose");
			channel_free(ssh, c);
			गच्छ out;
		}
		रोक;
	पक्ष SSH2_सन्देश_CHANNEL_OPEN_CONFIRMATION:
		/*
		 * Almost the same as SSH2_MSG_CHANNEL_OPEN, except then we
		 * need to parse 'remote_id' instead of 'ctype'.
		 */
		यदि ((original = sshbuf_from(cp, have)) == रिक्त ||
		    (modified = sshbuf_new()) == रिक्त) {
			error_f("alloc");
			गच्छ out;
		}
		यदि ((r = sshbuf_get_u32(original, &remote_id)) != 0 ||
		    (r = sshbuf_get_u32(original, &id)) != 0) {
			error_fr(r, "parse");
			गच्छ out;
		}
		c = channel_new(ssh, "mux-proxy", SSH_CHANNEL_MUX_PROXY,
		    -1, -1, -1, 0, 0, 0, "mux-down-connect", 1);
		c->mux_ctx = downstream;	/* point to mux client */
		c->mux_downstream_id = id;
		c->remote_id = remote_id;
		c->have_remote_id = 1;
		यदि ((r = sshbuf_put_u32(modified, remote_id)) != 0 ||
		    (r = sshbuf_put_u32(modified, c->self)) != 0 ||
		    (r = sshbuf_putb(modified, original)) != 0) {
			error_fr(r, "compose");
			channel_free(ssh, c);
			गच्छ out;
		}
		रोक;
	पक्ष SSH2_सन्देश_GLOBAL_REQUEST:
		यदि ((original = sshbuf_from(cp, have)) == रिक्त) {
			error_f("alloc");
			गच्छ out;
		}
		यदि ((r = sshbuf_get_cstring(original, &ctype, रिक्त)) != 0) {
			error_fr(r, "parse");
			गच्छ out;
		}
		यदि (म_भेद(ctype, "tcpip-forward") != 0) {
			error_f("unsupported request %s", ctype);
			गच्छ out;
		}
		यदि ((r = sshbuf_get_u8(original, रिक्त)) != 0 ||
		    (r = sshbuf_get_cstring(original, &listen_host, रिक्त)) != 0 ||
		    (r = sshbuf_get_u32(original, &listen_port)) != 0) {
			error_fr(r, "parse");
			गच्छ out;
		}
		यदि (listen_port > 65535) {
			error_f("tcpip-forward for %s: bad port %u",
			    listen_host, listen_port);
			गच्छ out;
		}
		/* Record that connection to this host/port is permitted. */
		permission_set_add(ssh, FORWARD_USER, FORWARD_LOCAL, "<mux>",
		    -1, listen_host, रिक्त, (पूर्णाङ्क)listen_port, downstream);
		रोक;
	पक्ष SSH2_सन्देश_CHANNEL_CLOSE:
		यदि (have < 4)
			रोक;
		remote_id = PEEK_U32(cp);
		यदि ((c = channel_by_remote_id(ssh, remote_id)) != रिक्त) {
			यदि (c->flags & CHAN_CLOSE_RCVD)
				channel_free(ssh, c);
			अन्यथा
				c->flags |= CHAN_CLOSE_SENT;
		}
		रोक;
	}
	यदि (modified) {
		यदि ((r = sshpkt_start(ssh, type)) != 0 ||
		    (r = sshpkt_putb(ssh, modified)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0) {
			error_fr(r, "send");
			गच्छ out;
		}
	} अन्यथा {
		यदि ((r = sshpkt_start(ssh, type)) != 0 ||
		    (r = sshpkt_put(ssh, cp, have)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0) {
			error_fr(r, "send");
			गच्छ out;
		}
	}
	ret = 0;
 out:
	मुक्त(ctype);
	मुक्त(listen_host);
	sshbuf_free(original);
	sshbuf_free(modified);
	फर्काऊ ret;
}

/*
 * receive packets from upstream server and de-multiplex packets
 * to correct downstream:
 * implemented as a helper for channel input handlers,
 * replaces local (proxy) channel ID with downstream channel ID.
 */
पूर्णाङ्क
channel_proxy_upstream(Channel *c, पूर्णाङ्क type, uint32_t seq, संरचना ssh *ssh)
{
	संरचना sshbuf *b = रिक्त;
	Channel *downstream;
	अचर u_char *cp = रिक्त;
	माप_प्रकार len;
	पूर्णाङ्क r;

	/*
	 * When receiving packets from the peer we need to check whether we
	 * need to forward the packets to the mux client. In this case we
	 * restore the original channel id and keep track of CLOSE messages,
	 * so we can cleanup the channel.
	 */
	यदि (c == रिक्त || c->type != SSH_CHANNEL_MUX_PROXY)
		फर्काऊ 0;
	यदि ((downstream = c->mux_ctx) == रिक्त)
		फर्काऊ 0;
	विकल्प (type) {
	पक्ष SSH2_सन्देश_CHANNEL_CLOSE:
	पक्ष SSH2_सन्देश_CHANNEL_DATA:
	पक्ष SSH2_सन्देश_CHANNEL_EOF:
	पक्ष SSH2_सन्देश_CHANNEL_EXTENDED_DATA:
	पक्ष SSH2_सन्देश_CHANNEL_OPEN_CONFIRMATION:
	पक्ष SSH2_सन्देश_CHANNEL_OPEN_FAILURE:
	पक्ष SSH2_सन्देश_CHANNEL_WINDOW_ADJUST:
	पक्ष SSH2_सन्देश_CHANNEL_SUCCESS:
	पक्ष SSH2_सन्देश_CHANNEL_FAILURE:
	पक्ष SSH2_सन्देश_CHANNEL_REQUEST:
		रोक;
	स्वभाव:
		debug2_f("channel %u: unsupported type %u", c->self, type);
		फर्काऊ 0;
	}
	यदि ((b = sshbuf_new()) == रिक्त) {
		error_f("alloc reply");
		गच्छ out;
	}
	/* get remaining payload (after id) */
	cp = sshpkt_ptr(ssh, &len);
	यदि (cp == रिक्त) {
		error_f("no packet");
		गच्छ out;
	}
	/* translate id and send to muxclient */
	यदि ((r = sshbuf_put_u8(b, 0)) != 0 ||	/* padlen */
	    (r = sshbuf_put_u8(b, type)) != 0 ||
	    (r = sshbuf_put_u32(b, c->mux_downstream_id)) != 0 ||
	    (r = sshbuf_put(b, cp, len)) != 0 ||
	    (r = sshbuf_put_stringb(downstream->output, b)) != 0) {
		error_fr(r, "compose muxclient");
		गच्छ out;
	}
	/* sshbuf_dump(b, stderr); */
	यदि (ssh_packet_log_type(type))
		debug3_f("channel %u: up->down: type %u", c->self, type);
 out:
	/* update state */
	विकल्प (type) {
	पक्ष SSH2_सन्देश_CHANNEL_OPEN_CONFIRMATION:
		/* record remote_id for SSH2_MSG_CHANNEL_CLOSE */
		यदि (cp && len > 4) {
			c->remote_id = PEEK_U32(cp);
			c->have_remote_id = 1;
		}
		रोक;
	पक्ष SSH2_सन्देश_CHANNEL_CLOSE:
		यदि (c->flags & CHAN_CLOSE_SENT)
			channel_free(ssh, c);
		अन्यथा
			c->flags |= CHAN_CLOSE_RCVD;
		रोक;
	}
	sshbuf_free(b);
	फर्काऊ 1;
}

/* -- protocol input */

/* Parse a channel ID from the current packet */
स्थिर पूर्णाङ्क
channel_parse_id(संरचना ssh *ssh, अचर वर्ण *where, अचर वर्ण *what)
{
	uint32_t id;
	पूर्णाङ्क r;

	यदि ((r = sshpkt_get_u32(ssh, &id)) != 0) {
		error_r(r, "%s: parse id", where);
		ssh_packet_disconnect(ssh, "Invalid %s message", what);
	}
	यदि (id > पूर्णांक_उच्च) {
		error_r(r, "%s: bad channel id %u", where, id);
		ssh_packet_disconnect(ssh, "Invalid %s channel id", what);
	}
	फर्काऊ (पूर्णाङ्क)id;
}

/* Lookup a channel from an ID in the current packet */
स्थिर Channel *
channel_from_packet_id(संरचना ssh *ssh, अचर वर्ण *where, अचर वर्ण *what)
{
	पूर्णाङ्क id = channel_parse_id(ssh, where, what);
	Channel *c;

	यदि ((c = channel_lookup(ssh, id)) == रिक्त) {
		ssh_packet_disconnect(ssh,
		    "%s packet referred to nonexistent channel %d", what, id);
	}
	फर्काऊ c;
}

पूर्णाङ्क
channel_आगत_data(पूर्णाङ्क type, uint32_t seq, संरचना ssh *ssh)
{
	अचर u_char *data;
	माप_प्रकार data_len, win_len;
	Channel *c = channel_from_packet_id(ssh, __func__, "data");
	पूर्णाङ्क r;

	यदि (channel_proxy_upstream(c, type, seq, ssh))
		फर्काऊ 0;

	/* Ignore any data for non-open channels (might happen on close) */
	यदि (c->type != SSH_CHANNEL_OPEN &&
	    c->type != SSH_CHANNEL_RDYNAMIC_OPEN &&
	    c->type != SSH_CHANNEL_RDYNAMIC_FINISH &&
	    c->type != SSH_CHANNEL_X11_OPEN)
		फर्काऊ 0;

	/* Get the data. */
	यदि ((r = sshpkt_get_string_direct(ssh, &data, &data_len)) != 0 ||
            (r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "channel %i: get data", c->self);

	win_len = data_len;
	यदि (c->datagram)
		win_len += 4;  /* string length header */

	/*
	 * The sending side reduces its window as it sends data, so we
	 * must 'fake' consumption of the data in order to ensure that window
	 * updates are sent back. Otherwise the connection might deadlock.
	 */
	यदि (c->ostate != CHAN_OUTPUT_OPEN) {
		यदि (win_len > c->local_window)
			c->local_window = 0;
		अन्यथा
			c->local_window -= win_len;
		c->local_consumed += win_len;
		फर्काऊ 0;
	}

	यदि (win_len > c->local_maxpacket) {
		logit("channel %d: rcvd big packet %zu, maxpack %u",
		    c->self, win_len, c->local_maxpacket);
		फर्काऊ 0;
	}
	यदि (win_len > c->local_window) {
		u_int delta = win_len - c->local_window;

		यदि (c->local_window_exceeded > अच_पूर्णांक_उच्च - delta)
			c->local_window_exceeded = अच_पूर्णांक_उच्च;
		अन्यथा
			c->local_window_exceeded += delta;
		logit("channel %d: rcvd too much data %zu, win %u/%u "
		    "(excess %u)", c->self, win_len, c->local_window,
		    c->local_window_max, c->local_window_exceeded);
		c->local_window = 0;
		/* Allow 10% grace before bringing the hammer down */
		यदि (c->local_window_exceeded > (c->local_window_max / 10)) {
			ssh_packet_disconnect(ssh, "channel %d: peer ignored "
			    "channel window", c->self);
		}
	} अन्यथा {
		c->local_window -= win_len;
		c->local_window_exceeded = 0;
	}

	यदि (c->datagram) {
		यदि ((r = sshbuf_put_string(c->output, data, data_len)) != 0)
			fatal_fr(r, "channel %i: append datagram", c->self);
	} अन्यथा यदि ((r = sshbuf_put(c->output, data, data_len)) != 0)
		fatal_fr(r, "channel %i: append data", c->self);

	फर्काऊ 0;
}

पूर्णाङ्क
channel_आगत_extended_data(पूर्णाङ्क type, uint32_t seq, संरचना ssh *ssh)
{
	अचर u_char *data;
	माप_प्रकार data_len;
	uint32_t tcode;
	Channel *c = channel_from_packet_id(ssh, __func__, "extended data");
	पूर्णाङ्क r;

	यदि (channel_proxy_upstream(c, type, seq, ssh))
		फर्काऊ 0;
	यदि (c->type != SSH_CHANNEL_OPEN) {
		logit("channel %d: ext data for non open", c->self);
		फर्काऊ 0;
	}
	यदि (c->flags & CHAN_EOF_RCVD) {
		यदि (ssh->compat & SSH_BUG_EXTEOF)
			debug("channel %d: accepting ext data after eof",
			    c->self);
		अन्यथा
			ssh_packet_disconnect(ssh, "Received extended_data "
			    "after EOF on channel %d.", c->self);
	}

	यदि ((r = sshpkt_get_u32(ssh, &tcode)) != 0) {
		error_fr(r, "parse tcode");
		ssh_packet_disconnect(ssh, "Invalid extended_data message");
	}
	यदि (c->efd == -1 ||
	    c->extended_usage != CHAN_EXTENDED_WRITE ||
	    tcode != SSH2_EXTENDED_DATA_STDERR) {
		logit("channel %d: bad ext data", c->self);
		फर्काऊ 0;
	}
	यदि ((r = sshpkt_get_string_direct(ssh, &data, &data_len)) != 0 ||
            (r = sshpkt_get_end(ssh)) != 0) {
		error_fr(r, "parse data");
		ssh_packet_disconnect(ssh, "Invalid extended_data message");
	}

	यदि (data_len > c->local_window) {
		logit("channel %d: rcvd too much extended_data %zu, win %u",
		    c->self, data_len, c->local_window);
		फर्काऊ 0;
	}
	debug2("channel %d: rcvd ext data %zu", c->self, data_len);
	/* XXX sshpkt_getb? */
	यदि ((r = sshbuf_put(c->extended, data, data_len)) != 0)
		error_fr(r, "append");
	c->local_window -= data_len;
	फर्काऊ 0;
}

पूर्णाङ्क
channel_आगत_ieof(पूर्णाङ्क type, uint32_t seq, संरचना ssh *ssh)
{
	Channel *c = channel_from_packet_id(ssh, __func__, "ieof");
	पूर्णाङ्क r;

        यदि ((r = sshpkt_get_end(ssh)) != 0) {
		error_fr(r, "parse data");
		ssh_packet_disconnect(ssh, "Invalid ieof message");
	}

	यदि (channel_proxy_upstream(c, type, seq, ssh))
		फर्काऊ 0;
	chan_rcvd_ieof(ssh, c);

	/* XXX force input close */
	यदि (c->force_drain && c->istate == CHAN_आगत_OPEN) {
		debug("channel %d: FORCE input drain", c->self);
		c->istate = CHAN_आगत_WAIT_DRAIN;
		यदि (sshbuf_len(c->आगत) == 0)
			chan_ibuf_empty(ssh, c);
	}
	फर्काऊ 0;
}

पूर्णाङ्क
channel_आगत_oclose(पूर्णाङ्क type, uint32_t seq, संरचना ssh *ssh)
{
	Channel *c = channel_from_packet_id(ssh, __func__, "oclose");
	पूर्णाङ्क r;

	यदि (channel_proxy_upstream(c, type, seq, ssh))
		फर्काऊ 0;
        यदि ((r = sshpkt_get_end(ssh)) != 0) {
		error_fr(r, "parse data");
		ssh_packet_disconnect(ssh, "Invalid oclose message");
	}
	chan_rcvd_oclose(ssh, c);
	फर्काऊ 0;
}

पूर्णाङ्क
channel_आगत_open_confirmation(पूर्णाङ्क type, uint32_t seq, संरचना ssh *ssh)
{
	Channel *c = channel_from_packet_id(ssh, __func__, "open confirmation");
	uint32_t remote_window, remote_maxpacket;
	पूर्णाङ्क r;

	यदि (channel_proxy_upstream(c, type, seq, ssh))
		फर्काऊ 0;
	यदि (c->type != SSH_CHANNEL_OPENING)
		ssh_packet_disconnect(ssh, "Received open confirmation for "
		    "non-opening channel %d.", c->self);
	/*
	 * Record the remote channel number and mark that the channel
	 * is now open.
	 */
	यदि ((r = sshpkt_get_u32(ssh, &c->remote_id)) != 0 ||
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
	यदि (c->open_confirm) {
		debug2_f("channel %d: callback start", c->self);
		c->open_confirm(ssh, c->self, 1, c->open_confirm_ctx);
		debug2_f("channel %d: callback done", c->self);
	}
	channel_set_used_time(ssh, c);
	debug2("channel %d: open confirm rwindow %u rmax %u", c->self,
	    c->remote_window, c->remote_maxpacket);
	फर्काऊ 0;
}

स्थिर वर्ण *
reason2txt(पूर्णाङ्क reason)
{
	विकल्प (reason) {
	पक्ष SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED:
		फर्काऊ "administratively prohibited";
	पक्ष SSH2_OPEN_CONNECT_FAILED:
		फर्काऊ "connect failed";
	पक्ष SSH2_OPEN_UNKNOWN_CHANNEL_TYPE:
		फर्काऊ "unknown channel type";
	पक्ष SSH2_OPEN_RESOURCE_SHORTAGE:
		फर्काऊ "resource shortage";
	}
	फर्काऊ "unknown reason";
}

पूर्णाङ्क
channel_आगत_open_failure(पूर्णाङ्क type, uint32_t seq, संरचना ssh *ssh)
{
	Channel *c = channel_from_packet_id(ssh, __func__, "open failure");
	uint32_t reason;
	वर्ण *सन्देश = रिक्त;
	पूर्णाङ्क r;

	यदि (channel_proxy_upstream(c, type, seq, ssh))
		फर्काऊ 0;
	यदि (c->type != SSH_CHANNEL_OPENING)
		ssh_packet_disconnect(ssh, "Received open failure for "
		    "non-opening channel %d.", c->self);
	यदि ((r = sshpkt_get_u32(ssh, &reason)) != 0) {
		error_fr(r, "parse reason");
		ssh_packet_disconnect(ssh, "Invalid open failure message");
	}
	/* skip language */
	यदि ((r = sshpkt_get_cstring(ssh, &सन्देश, रिक्त)) != 0 ||
	    (r = sshpkt_get_string_direct(ssh, रिक्त, रिक्त)) != 0 ||
            (r = sshpkt_get_end(ssh)) != 0) {
		error_fr(r, "parse msg/lang");
		ssh_packet_disconnect(ssh, "Invalid open failure message");
	}
	logit("channel %d: open failed: %s%s%s", c->self,
	    reason2txt(reason), सन्देश ? ": ": "", सन्देश ? सन्देश : "");
	मुक्त(सन्देश);
	यदि (c->open_confirm) {
		debug2_f("channel %d: callback start", c->self);
		c->open_confirm(ssh, c->self, 0, c->open_confirm_ctx);
		debug2_f("channel %d: callback done", c->self);
	}
	/* Schedule the channel for cleanup/deletion. */
	chan_mark_dead(ssh, c);
	फर्काऊ 0;
}

पूर्णाङ्क
channel_आगत_window_adjust(पूर्णाङ्क type, uint32_t seq, संरचना ssh *ssh)
{
	पूर्णाङ्क id = channel_parse_id(ssh, __func__, "window adjust");
	Channel *c;
	uint32_t adjust;
	u_int new_rwin;
	पूर्णाङ्क r;

	यदि ((c = channel_lookup(ssh, id)) == रिक्त) {
		logit("Received window adjust for non-open channel %d.", id);
		फर्काऊ 0;
	}

	यदि (channel_proxy_upstream(c, type, seq, ssh))
		फर्काऊ 0;
	यदि ((r = sshpkt_get_u32(ssh, &adjust)) != 0 ||
            (r = sshpkt_get_end(ssh)) != 0) {
		error_fr(r, "parse adjust");
		ssh_packet_disconnect(ssh, "Invalid window adjust message");
	}
	debug2("channel %d: rcvd adjust %u", c->self, adjust);
	यदि ((new_rwin = c->remote_window + adjust) < c->remote_window) {
		fatal("channel %d: adjust %u overflows remote window %u",
		    c->self, adjust, c->remote_window);
	}
	c->remote_window = new_rwin;
	फर्काऊ 0;
}

पूर्णाङ्क
channel_आगत_status_confirm(पूर्णाङ्क type, uint32_t seq, संरचना ssh *ssh)
{
	पूर्णाङ्क id = channel_parse_id(ssh, __func__, "status confirm");
	Channel *c;
	संरचना channel_confirm *cc;

	/* Reset keepalive timeout */
	ssh_packet_set_alive_timeouts(ssh, 0);

	debug2_f("type %d id %d", type, id);

	यदि ((c = channel_lookup(ssh, id)) == रिक्त) {
		logit_f("%d: unknown", id);
		फर्काऊ 0;
	}
	यदि (channel_proxy_upstream(c, type, seq, ssh))
		फर्काऊ 0;
        यदि (sshpkt_get_end(ssh) != 0)
		ssh_packet_disconnect(ssh, "Invalid status confirm message");
	यदि ((cc = TAILQ_FIRST(&c->status_confirms)) == रिक्त)
		फर्काऊ 0;
	cc->cb(ssh, type, c, cc->ctx);
	TAILQ_REMOVE(&c->status_confirms, cc, entry);
	freezero(cc, परिमाण(*cc));
	फर्काऊ 0;
}

/* -- tcp forwarding */

शून्य
channel_set_af(संरचना ssh *ssh, पूर्णाङ्क af)
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
स्थिर अचर वर्ण *
channel_fwd_bind_addr(संरचना ssh *ssh, अचर वर्ण *listen_addr, पूर्णाङ्क *wildcardp,
    पूर्णाङ्क is_client, संरचना ForwardOptions *fwd_opts)
{
	अचर वर्ण *addr = रिक्त;
	पूर्णाङ्क wildcard = 0;

	यदि (listen_addr == रिक्त) {
		/* No address specified: default to gateway_ports setting */
		यदि (fwd_opts->gateway_ports)
			wildcard = 1;
	} अन्यथा यदि (fwd_opts->gateway_ports || is_client) {
		यदि (((ssh->compat & SSH_OLD_FORWARD_ADDR) &&
		    म_भेद(listen_addr, "0.0.0.0") == 0 && is_client == 0) ||
		    *listen_addr == '\0' || म_भेद(listen_addr, "*") == 0 ||
		    (!is_client && fwd_opts->gateway_ports == 1)) {
			wildcard = 1;
			/*
			 * Notify client if they requested a specific listen
			 * address and it was overridden.
			 */
			यदि (*listen_addr != '\0' &&
			    म_भेद(listen_addr, "0.0.0.0") != 0 &&
			    म_भेद(listen_addr, "*") != 0) {
				ssh_packet_send_debug(ssh,
				    "Forwarding listen address "
				    "\"%s\" overridden by server "
				    "GatewayPorts", listen_addr);
			}
		} अन्यथा यदि (म_भेद(listen_addr, "localhost") != 0 ||
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
	} अन्यथा यदि (म_भेद(listen_addr, "127.0.0.1") == 0 ||
	    म_भेद(listen_addr, "::1") == 0) {
		/*
		 * If a specific IPv4/IPv6 localhost address has been
		 * requested then accept it even if gateway_ports is in
		 * effect. This allows the client to prefer IPv4 or IPv6.
		 */
		addr = listen_addr;
	}
	यदि (wildcardp != रिक्त)
		*wildcardp = wildcard;
	फर्काऊ addr;
}

स्थिर पूर्णाङ्क
channel_setup_fwd_listener_tcpip(संरचना ssh *ssh, पूर्णाङ्क type,
    संरचना Forward *fwd, पूर्णाङ्क *allocated_listen_port,
    संरचना ForwardOptions *fwd_opts)
{
	Channel *c;
	पूर्णाङ्क sock, r, success = 0, wildcard = 0, is_client;
	संरचना addrinfo hints, *ai, *aitop;
	अचर वर्ण *host, *addr;
	वर्ण ntop[NI_MAXHOST], strport[NI_MAXSERV];
	in_port_t *lport_p;

	is_client = (type == SSH_CHANNEL_PORT_LISTENER);

	यदि (is_client && fwd->connect_path != रिक्त) {
		host = fwd->connect_path;
	} अन्यथा {
		host = (type == SSH_CHANNEL_RPORT_LISTENER) ?
		    fwd->listen_host : fwd->connect_host;
		यदि (host == रिक्त) {
			error("No forward host name.");
			फर्काऊ 0;
		}
		यदि (म_माप(host) >= NI_MAXHOST) {
			error("Forward host name too long.");
			फर्काऊ 0;
		}
	}

	/* Determine the bind address, cf. channel_fwd_bind_addr() comment */
	addr = channel_fwd_bind_addr(ssh, fwd->listen_host, &wildcard,
	    is_client, fwd_opts);
	debug3_f("type %d wildcard %d addr %s", type, wildcard,
	    (addr == रिक्त) ? "NULL" : addr);

	/*
	 * getaddrinfo returns a loopback address if the hostname is
	 * set to NULL and hints.ai_flags is not AI_PASSIVE
	 */
	स_रखो(&hints, 0, परिमाण(hints));
	hints.ai_family = ssh->chanctxt->IPv4or6;
	hints.ai_flags = wildcard ? AI_PASSIVE : 0;
	hints.ai_socktype = SOCK_STREAM;
	snprintf(strport, परिमाण strport, "%d", fwd->listen_port);
	यदि ((r = getaddrinfo(addr, strport, &hints, &aitop)) != 0) {
		यदि (addr == रिक्त) {
			/* This really shouldn't happen */
			ssh_packet_disconnect(ssh, "getaddrinfo: fatal error: %s",
			    ssh_gai_strerror(r));
		} अन्यथा {
			error_f("getaddrinfo(%.64s): %s", addr,
			    ssh_gai_strerror(r));
		}
		फर्काऊ 0;
	}
	यदि (allocated_listen_port != रिक्त)
		*allocated_listen_port = 0;
	लागि (ai = aitop; ai; ai = ai->ai_next) {
		विकल्प (ai->ai_family) {
		पक्ष AF_INET:
			lport_p = &((संरचना sockaddr_in *)ai->ai_addr)->
			    sin_port;
			रोक;
		पक्ष AF_INET6:
			lport_p = &((संरचना sockaddr_in6 *)ai->ai_addr)->
			    sin6_port;
			रोक;
		स्वभाव:
			जारी;
		}
		/*
		 * If allocating a port for -R forwards, then use the
		 * same port for all address families.
		 */
		यदि (type == SSH_CHANNEL_RPORT_LISTENER &&
		    fwd->listen_port == 0 && allocated_listen_port != रिक्त &&
		    *allocated_listen_port > 0)
			*lport_p = htons(*allocated_listen_port);

		यदि (getnameinfo(ai->ai_addr, ai->ai_addrlen, ntop, परिमाण(ntop),
		    strport, परिमाण(strport),
		    NI_NUMERICHOST|NI_NUMERICSERV) != 0) {
			error_f("getnameinfo failed");
			जारी;
		}
		/* Create a port to listen for the host. */
		sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		यदि (sock == -1) {
			/* this is no error since kernel may not support ipv6 */
			verbose("socket [%s]:%s: %.100s", ntop, strport,
			    म_त्रुटि(त्रुटि_सं));
			जारी;
		}

		set_reuseaddr(sock);
		यदि (ai->ai_family == AF_INET6)
			sock_set_v6only(sock);

		debug("Local forwarding listening on %s port %s.",
		    ntop, strport);

		/* Bind the socket to the address. */
		यदि (bind(sock, ai->ai_addr, ai->ai_addrlen) == -1) {
			/*
			 * address can be in if use ipv6 address is
			 * already bound
			 */
			यदि (!ai->ai_next)
				error("bind [%s]:%s: %.100s",
				    ntop, strport, म_त्रुटि(त्रुटि_सं));
			अन्यथा
				verbose("bind [%s]:%s: %.100s",
				    ntop, strport, म_त्रुटि(त्रुटि_सं));

			बंद(sock);
			जारी;
		}
		/* Start listening for connections on the socket. */
		यदि (listen(sock, SSH_LISTEN_BACKLOG) == -1) {
			error("listen [%s]:%s: %.100s", ntop, strport,
			    म_त्रुटि(त्रुटि_सं));
			बंद(sock);
			जारी;
		}

		/*
		 * fwd->listen_port == 0 requests a dynamically allocated port -
		 * record what we got.
		 */
		यदि (type == SSH_CHANNEL_RPORT_LISTENER &&
		    fwd->listen_port == 0 &&
		    allocated_listen_port != रिक्त &&
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
		c->listening_addr = addr == रिक्त ? रिक्त : xstrdup(addr);
		यदि (fwd->listen_port == 0 && allocated_listen_port != रिक्त &&
		    !(ssh->compat & SSH_BUG_DYNAMIC_RPORT))
			c->listening_port = *allocated_listen_port;
		अन्यथा
			c->listening_port = fwd->listen_port;
		success = 1;
	}
	यदि (success == 0)
		error_f("cannot listen to port: %d", fwd->listen_port);
	freeaddrinfo(aitop);
	फर्काऊ success;
}

स्थिर पूर्णाङ्क
channel_setup_fwd_listener_streamlocal(संरचना ssh *ssh, पूर्णाङ्क type,
    संरचना Forward *fwd, संरचना ForwardOptions *fwd_opts)
{
	संरचना sockaddr_un sunaddr;
	अचर वर्ण *path;
	Channel *c;
	पूर्णाङ्क port, sock;
	mode_t omask;

	विकल्प (type) {
	पक्ष SSH_CHANNEL_UNIX_LISTENER:
		यदि (fwd->connect_path != रिक्त) {
			यदि (म_माप(fwd->connect_path) > परिमाण(sunaddr.sun_path)) {
				error("Local connecting path too long: %s",
				    fwd->connect_path);
				फर्काऊ 0;
			}
			path = fwd->connect_path;
			port = PORT_STREAMLOCAL;
		} अन्यथा {
			यदि (fwd->connect_host == रिक्त) {
				error("No forward host name.");
				फर्काऊ 0;
			}
			यदि (म_माप(fwd->connect_host) >= NI_MAXHOST) {
				error("Forward host name too long.");
				फर्काऊ 0;
			}
			path = fwd->connect_host;
			port = fwd->connect_port;
		}
		रोक;
	पक्ष SSH_CHANNEL_RUNIX_LISTENER:
		path = fwd->listen_path;
		port = PORT_STREAMLOCAL;
		रोक;
	स्वभाव:
		error_f("unexpected channel type %d", type);
		फर्काऊ 0;
	}

	यदि (fwd->listen_path == रिक्त) {
		error("No forward path name.");
		फर्काऊ 0;
	}
	यदि (म_माप(fwd->listen_path) > परिमाण(sunaddr.sun_path)) {
		error("Local listening path too long: %s", fwd->listen_path);
		फर्काऊ 0;
	}

	debug3_f("type %d path %s", type, fwd->listen_path);

	/* Start a Unix domain listener. */
	omask = umask(fwd_opts->streamlocal_bind_mask);
	sock = unix_listener(fwd->listen_path, SSH_LISTEN_BACKLOG,
	    fwd_opts->streamlocal_bind_unlink);
	umask(omask);
	यदि (sock < 0)
		फर्काऊ 0;

	debug("Local forwarding listening on path %s.", fwd->listen_path);

	/* Allocate a channel number for the socket. */
	c = channel_new(ssh, "unix-listener", type, sock, sock, -1,
	    CHAN_TCP_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT,
	    0, "unix listener", 1);
	c->path = xstrdup(path);
	c->host_port = port;
	c->listening_port = PORT_STREAMLOCAL;
	c->listening_addr = xstrdup(fwd->listen_path);
	फर्काऊ 1;
}

स्थिर पूर्णाङ्क
channel_cancel_rport_listener_tcpip(संरचना ssh *ssh,
    अचर वर्ण *host, u_short port)
{
	u_int i;
	पूर्णाङ्क found = 0;

	लागि (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		Channel *c = ssh->chanctxt->channels[i];
		यदि (c == रिक्त || c->type != SSH_CHANNEL_RPORT_LISTENER)
			जारी;
		यदि (म_भेद(c->path, host) == 0 && c->listening_port == port) {
			debug2_f("close channel %d", i);
			channel_free(ssh, c);
			found = 1;
		}
	}

	फर्काऊ found;
}

स्थिर पूर्णाङ्क
channel_cancel_rport_listener_streamlocal(संरचना ssh *ssh, अचर वर्ण *path)
{
	u_int i;
	पूर्णाङ्क found = 0;

	लागि (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		Channel *c = ssh->chanctxt->channels[i];
		यदि (c == रिक्त || c->type != SSH_CHANNEL_RUNIX_LISTENER)
			जारी;
		यदि (c->path == रिक्त)
			जारी;
		यदि (म_भेद(c->path, path) == 0) {
			debug2_f("close channel %d", i);
			channel_free(ssh, c);
			found = 1;
		}
	}

	फर्काऊ found;
}

पूर्णाङ्क
channel_cancel_rport_listener(संरचना ssh *ssh, संरचना Forward *fwd)
{
	यदि (fwd->listen_path != रिक्त) {
		फर्काऊ channel_cancel_rport_listener_streamlocal(ssh,
		    fwd->listen_path);
	} अन्यथा {
		फर्काऊ channel_cancel_rport_listener_tcpip(ssh,
		    fwd->listen_host, fwd->listen_port);
	}
}

स्थिर पूर्णाङ्क
channel_cancel_lport_listener_tcpip(संरचना ssh *ssh,
    अचर वर्ण *lhost, u_short lport, पूर्णाङ्क cport,
    संरचना ForwardOptions *fwd_opts)
{
	u_int i;
	पूर्णाङ्क found = 0;
	अचर वर्ण *addr = channel_fwd_bind_addr(ssh, lhost, रिक्त, 1, fwd_opts);

	लागि (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		Channel *c = ssh->chanctxt->channels[i];
		यदि (c == रिक्त || c->type != SSH_CHANNEL_PORT_LISTENER)
			जारी;
		यदि (c->listening_port != lport)
			जारी;
		यदि (cport == CHANNEL_CANCEL_PORT_STATIC) {
			/* skip dynamic forwardings */
			यदि (c->host_port == 0)
				जारी;
		} अन्यथा {
			यदि (c->host_port != cport)
				जारी;
		}
		यदि ((c->listening_addr == रिक्त && addr != रिक्त) ||
		    (c->listening_addr != रिक्त && addr == रिक्त))
			जारी;
		यदि (addr == रिक्त || म_भेद(c->listening_addr, addr) == 0) {
			debug2_f("close channel %d", i);
			channel_free(ssh, c);
			found = 1;
		}
	}

	फर्काऊ found;
}

स्थिर पूर्णाङ्क
channel_cancel_lport_listener_streamlocal(संरचना ssh *ssh, अचर वर्ण *path)
{
	u_int i;
	पूर्णाङ्क found = 0;

	यदि (path == रिक्त) {
		error_f("no path specified.");
		फर्काऊ 0;
	}

	लागि (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		Channel *c = ssh->chanctxt->channels[i];
		यदि (c == रिक्त || c->type != SSH_CHANNEL_UNIX_LISTENER)
			जारी;
		यदि (c->listening_addr == रिक्त)
			जारी;
		यदि (म_भेद(c->listening_addr, path) == 0) {
			debug2_f("close channel %d", i);
			channel_free(ssh, c);
			found = 1;
		}
	}

	फर्काऊ found;
}

पूर्णाङ्क
channel_cancel_lport_listener(संरचना ssh *ssh,
    संरचना Forward *fwd, पूर्णाङ्क cport, संरचना ForwardOptions *fwd_opts)
{
	यदि (fwd->listen_path != रिक्त) {
		फर्काऊ channel_cancel_lport_listener_streamlocal(ssh,
		    fwd->listen_path);
	} अन्यथा {
		फर्काऊ channel_cancel_lport_listener_tcpip(ssh,
		    fwd->listen_host, fwd->listen_port, cport, fwd_opts);
	}
}

/* protocol local port fwd, used by ssh */
पूर्णाङ्क
channel_setup_local_fwd_listener(संरचना ssh *ssh,
    संरचना Forward *fwd, संरचना ForwardOptions *fwd_opts)
{
	यदि (fwd->listen_path != रिक्त) {
		फर्काऊ channel_setup_fwd_listener_streamlocal(ssh,
		    SSH_CHANNEL_UNIX_LISTENER, fwd, fwd_opts);
	} अन्यथा {
		फर्काऊ channel_setup_fwd_listener_tcpip(ssh,
		    SSH_CHANNEL_PORT_LISTENER, fwd, रिक्त, fwd_opts);
	}
}

/* Matches a remote forwarding permission against a requested forwarding */
स्थिर पूर्णाङ्क
remote_open_match(संरचना permission *allowed_open, संरचना Forward *fwd)
{
	पूर्णाङ्क ret;
	वर्ण *lhost;

	/* XXX add ACLs for streamlocal */
	यदि (fwd->listen_path != रिक्त)
		फर्काऊ 1;

	यदि (fwd->listen_host == रिक्त || allowed_open->listen_host == रिक्त)
		फर्काऊ 0;

	यदि (allowed_open->listen_port != FWD_PERMIT_ANY_PORT &&
	    allowed_open->listen_port != fwd->listen_port)
		फर्काऊ 0;

	/* Match hostnames case-insensitively */
	lhost = xstrdup(fwd->listen_host);
	lowercase(lhost);
	ret = match_pattern(lhost, allowed_open->listen_host);
	मुक्त(lhost);

	फर्काऊ ret;
}

/* Checks whether a requested remote forwarding is permitted */
स्थिर पूर्णाङ्क
check_rfwd_permission(संरचना ssh *ssh, संरचना Forward *fwd)
{
	संरचना ssh_channels *sc = ssh->chanctxt;
	संरचना permission_set *pset = &sc->remote_perms;
	u_int i, permit, permit_adm = 1;
	संरचना permission *perm;

#ifdef SKIP_PRIVDROP
	यदि (fwd->listen_path != रिक्त)
		फर्काऊ 0;
	यदि (fwd->listen_port != 0 && fwd->listen_port < 1024)
		फर्काऊ 0;
#endif

	/* XXX apply GatewayPorts override before checking? */

	permit = pset->all_permitted;
	यदि (!permit) {
		लागि (i = 0; i < pset->अङ्क_permitted_user; i++) {
			perm = &pset->permitted_user[i];
			यदि (remote_open_match(perm, fwd)) {
				permit = 1;
				रोक;
			}
		}
	}

	यदि (pset->अङ्क_permitted_admin > 0) {
		permit_adm = 0;
		लागि (i = 0; i < pset->अङ्क_permitted_admin; i++) {
			perm = &pset->permitted_admin[i];
			यदि (remote_open_match(perm, fwd)) {
				permit_adm = 1;
				रोक;
			}
		}
	}

	फर्काऊ permit && permit_adm;
}

/* protocol v2 remote port fwd, used by sshd */
पूर्णाङ्क
channel_setup_remote_fwd_listener(संरचना ssh *ssh, संरचना Forward *fwd,
    पूर्णाङ्क *allocated_listen_port, संरचना ForwardOptions *fwd_opts)
{
	यदि (!check_rfwd_permission(ssh, fwd)) {
		ssh_packet_send_debug(ssh, "port forwarding refused");
		यदि (fwd->listen_path != रिक्त)
			/* XXX always allowed, see remote_open_match() */
			logit("Received request from %.100s port %d to "
			    "remote forward to path \"%.100s\", "
			    "but the request was denied.",
			    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
			    fwd->listen_path);
		अन्यथा यदि(fwd->listen_host != रिक्त)
			logit("Received request from %.100s port %d to "
			    "remote forward to host %.100s port %d, "
			    "but the request was denied.",
			    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
			    fwd->listen_host, fwd->listen_port );
		अन्यथा
			logit("Received request from %.100s port %d to remote "
			    "forward, but the request was denied.",
			    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
		फर्काऊ 0;
	}
	यदि (fwd->listen_path != रिक्त) {
		फर्काऊ channel_setup_fwd_listener_streamlocal(ssh,
		    SSH_CHANNEL_RUNIX_LISTENER, fwd, fwd_opts);
	} अन्यथा {
		फर्काऊ channel_setup_fwd_listener_tcpip(ssh,
		    SSH_CHANNEL_RPORT_LISTENER, fwd, allocated_listen_port,
		    fwd_opts);
	}
}

/*
 * Translate the requested rfwd listen host to something usable for
 * this server.
 */
स्थिर अचर वर्ण *
channel_rfwd_bind_host(अचर वर्ण *listen_host)
{
	यदि (listen_host == रिक्त) {
		फर्काऊ "localhost";
	} अन्यथा यदि (*listen_host == '\0' || म_भेद(listen_host, "*") == 0) {
		फर्काऊ "";
	} अन्यथा
		फर्काऊ listen_host;
}

/*
 * Initiate forwarding of connections to port "port" on remote host through
 * the secure channel to host:port from local side.
 * Returns handle (index) for updating the dynamic listen port with
 * channel_update_permission().
 */
पूर्णाङ्क
channel_request_remote_forwarding(संरचना ssh *ssh, संरचना Forward *fwd)
{
	पूर्णाङ्क r, success = 0, idx = -1;
	अचर वर्ण *host_to_connect, *listen_host, *listen_path;
	पूर्णाङ्क port_to_connect, listen_port;

	/* Send the forward request to the remote side. */
	यदि (fwd->listen_path != रिक्त) {
		यदि ((r = sshpkt_start(ssh, SSH2_सन्देश_GLOBAL_REQUEST)) != 0 ||
		    (r = sshpkt_put_cstring(ssh,
		    "streamlocal-forward@openssh.com")) != 0 ||
		    (r = sshpkt_put_u8(ssh, 1)) != 0 || /* want reply */
		    (r = sshpkt_put_cstring(ssh, fwd->listen_path)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			fatal_fr(r, "request streamlocal");
	} अन्यथा {
		यदि ((r = sshpkt_start(ssh, SSH2_सन्देश_GLOBAL_REQUEST)) != 0 ||
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
	यदि (success) {
		/* Record that connection to this host/port is permitted. */
		host_to_connect = listen_host = listen_path = रिक्त;
		port_to_connect = listen_port = 0;
		यदि (fwd->connect_path != रिक्त) {
			host_to_connect = fwd->connect_path;
			port_to_connect = PORT_STREAMLOCAL;
		} अन्यथा {
			host_to_connect = fwd->connect_host;
			port_to_connect = fwd->connect_port;
		}
		यदि (fwd->listen_path != रिक्त) {
			listen_path = fwd->listen_path;
			listen_port = PORT_STREAMLOCAL;
		} अन्यथा {
			listen_host = fwd->listen_host;
			listen_port = fwd->listen_port;
		}
		idx = permission_set_add(ssh, FORWARD_USER, FORWARD_LOCAL,
		    host_to_connect, port_to_connect,
		    listen_host, listen_path, listen_port, रिक्त);
	}
	फर्काऊ idx;
}

स्थिर पूर्णाङ्क
open_match(संरचना permission *allowed_open, अचर वर्ण *requestedhost,
    पूर्णाङ्क requestedport)
{
	यदि (allowed_open->host_to_connect == रिक्त)
		फर्काऊ 0;
	यदि (allowed_open->port_to_connect != FWD_PERMIT_ANY_PORT &&
	    allowed_open->port_to_connect != requestedport)
		फर्काऊ 0;
	यदि (म_भेद(allowed_open->host_to_connect, FWD_PERMIT_ANY_HOST) != 0 &&
	    म_भेद(allowed_open->host_to_connect, requestedhost) != 0)
		फर्काऊ 0;
	फर्काऊ 1;
}

/*
 * Note that in the listen host/port case
 * we don't support FWD_PERMIT_ANY_PORT and
 * need to translate between the configured-host (listen_host)
 * and what we've sent to the remote server (channel_rfwd_bind_host)
 */
स्थिर पूर्णाङ्क
open_listen_match_tcpip(संरचना permission *allowed_open,
    अचर वर्ण *requestedhost, u_short requestedport, पूर्णाङ्क translate)
{
	अचर वर्ण *allowed_host;

	यदि (allowed_open->host_to_connect == रिक्त)
		फर्काऊ 0;
	यदि (allowed_open->listen_port != requestedport)
		फर्काऊ 0;
	यदि (!translate && allowed_open->listen_host == रिक्त &&
	    requestedhost == रिक्त)
		फर्काऊ 1;
	allowed_host = translate ?
	    channel_rfwd_bind_host(allowed_open->listen_host) :
	    allowed_open->listen_host;
	यदि (allowed_host == रिक्त || requestedhost == रिक्त ||
	    म_भेद(allowed_host, requestedhost) != 0)
		फर्काऊ 0;
	फर्काऊ 1;
}

स्थिर पूर्णाङ्क
open_listen_match_streamlocal(संरचना permission *allowed_open,
    अचर वर्ण *requestedpath)
{
	यदि (allowed_open->host_to_connect == रिक्त)
		फर्काऊ 0;
	यदि (allowed_open->listen_port != PORT_STREAMLOCAL)
		फर्काऊ 0;
	यदि (allowed_open->listen_path == रिक्त ||
	    म_भेद(allowed_open->listen_path, requestedpath) != 0)
		फर्काऊ 0;
	फर्काऊ 1;
}

/*
 * Request cancellation of remote forwarding of connection host:port from
 * local side.
 */
स्थिर पूर्णाङ्क
channel_request_rforward_cancel_tcpip(संरचना ssh *ssh,
    अचर वर्ण *host, u_short port)
{
	संरचना ssh_channels *sc = ssh->chanctxt;
	संरचना permission_set *pset = &sc->local_perms;
	पूर्णाङ्क r;
	u_int i;
	संरचना permission *perm = रिक्त;

	लागि (i = 0; i < pset->अङ्क_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		यदि (open_listen_match_tcpip(perm, host, port, 0))
			रोक;
		perm = रिक्त;
	}
	यदि (perm == रिक्त) {
		debug_f("requested forward not found");
		फर्काऊ -1;
	}
	यदि ((r = sshpkt_start(ssh, SSH2_सन्देश_GLOBAL_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "cancel-tcpip-forward")) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 || /* want reply */
	    (r = sshpkt_put_cstring(ssh, channel_rfwd_bind_host(host))) != 0 ||
	    (r = sshpkt_put_u32(ssh, port)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send cancel");

	fwd_perm_clear(perm); /* unregister */

	फर्काऊ 0;
}

/*
 * Request cancellation of remote forwarding of Unix domain socket
 * path from local side.
 */
स्थिर पूर्णाङ्क
channel_request_rforward_cancel_streamlocal(संरचना ssh *ssh, अचर वर्ण *path)
{
	संरचना ssh_channels *sc = ssh->chanctxt;
	संरचना permission_set *pset = &sc->local_perms;
	पूर्णाङ्क r;
	u_int i;
	संरचना permission *perm = रिक्त;

	लागि (i = 0; i < pset->अङ्क_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		यदि (open_listen_match_streamlocal(perm, path))
			रोक;
		perm = रिक्त;
	}
	यदि (perm == रिक्त) {
		debug_f("requested forward not found");
		फर्काऊ -1;
	}
	यदि ((r = sshpkt_start(ssh, SSH2_सन्देश_GLOBAL_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh,
	    "cancel-streamlocal-forward@openssh.com")) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 || /* want reply */
	    (r = sshpkt_put_cstring(ssh, path)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send cancel");

	fwd_perm_clear(perm); /* unregister */

	फर्काऊ 0;
}

/*
 * Request cancellation of remote forwarding of a connection from local side.
 */
पूर्णाङ्क
channel_request_rforward_cancel(संरचना ssh *ssh, संरचना Forward *fwd)
{
	यदि (fwd->listen_path != रिक्त) {
		फर्काऊ channel_request_rforward_cancel_streamlocal(ssh,
		    fwd->listen_path);
	} अन्यथा {
		फर्काऊ channel_request_rforward_cancel_tcpip(ssh,
		    fwd->listen_host,
		    fwd->listen_port ? fwd->listen_port : fwd->allocated_port);
	}
}

/*
 * Permits opening to any host/port if permitted_user[] is empty.  This is
 * usually called by the server, because the user could connect to any port
 * anyway, and the server has no way to know but to trust the client anyway.
 */
शून्य
channel_permit_all(संरचना ssh *ssh, पूर्णाङ्क where)
{
	संरचना permission_set *pset = permission_set_get(ssh, where);

	यदि (pset->अङ्क_permitted_user == 0)
		pset->all_permitted = 1;
}

/*
 * Permit the specified host/port for forwarding.
 */
शून्य
channel_add_permission(संरचना ssh *ssh, पूर्णाङ्क who, पूर्णाङ्क where,
    वर्ण *host, पूर्णाङ्क port)
{
	पूर्णाङ्क local = where == FORWARD_LOCAL;
	संरचना permission_set *pset = permission_set_get(ssh, where);

	debug("allow %s forwarding to host %s port %d",
	    fwd_ident(who, where), host, port);
	/*
	 * Remote forwards set listen_host/port, local forwards set
	 * host/port_to_connect.
	 */
	permission_set_add(ssh, who, where,
	    local ? host : रिक्त, local ? port : 0,
	    local ? रिक्त : host, रिक्त, local ? 0 : port, रिक्त);
	pset->all_permitted = 0;
}

/*
 * Administratively disable forwarding.
 */
शून्य
channel_disable_admin(संरचना ssh *ssh, पूर्णाङ्क where)
{
	channel_clear_permission(ssh, FORWARD_ADM, where);
	permission_set_add(ssh, FORWARD_ADM, where,
	    रिक्त, 0, रिक्त, रिक्त, 0, रिक्त);
}

/*
 * Clear a list of permitted opens.
 */
शून्य
channel_clear_permission(संरचना ssh *ssh, पूर्णाङ्क who, पूर्णाङ्क where)
{
	संरचना permission **permp;
	u_int i, *npermp;

	permission_set_get_array(ssh, who, where, &permp, &npermp);
	लागि (i = 0; i < *npermp; i++)
		fwd_perm_clear((*permp) + i);
	मुक्त(*permp);
	*permp = रिक्त;
	*npermp = 0;
}

/*
 * Update the listen port for a dynamic remote forward, after
 * the actual 'newport' has been allocated. If 'newport' < 0 is
 * passed then they entry will be invalidated.
 */
शून्य
channel_update_permission(संरचना ssh *ssh, पूर्णाङ्क idx, पूर्णाङ्क newport)
{
	संरचना permission_set *pset = &ssh->chanctxt->local_perms;

	यदि (idx < 0 || (u_int)idx >= pset->अङ्क_permitted_user) {
		debug_f("index out of range: %d num_permitted_user %d",
		    idx, pset->अङ्क_permitted_user);
		फर्काऊ;
	}
	debug("%s allowed port %d for forwarding to host %s port %d",
	    newport > 0 ? "Updating" : "Removing",
	    newport,
	    pset->permitted_user[idx].host_to_connect,
	    pset->permitted_user[idx].port_to_connect);
	यदि (newport <= 0)
		fwd_perm_clear(&pset->permitted_user[idx]);
	अन्यथा {
		pset->permitted_user[idx].listen_port =
		    (ssh->compat & SSH_BUG_DYNAMIC_RPORT) ? 0 : newport;
	}
}

/* Try to start non-blocking connect to next host in cctx list */
स्थिर पूर्णाङ्क
connect_next(संरचना ssh *ssh, संरचना channel_connect *cctx)
{
	पूर्णाङ्क sock, sock_is_network, saved_errno;
	संरचना sockaddr_un *sunaddr;
	वर्ण ntop[NI_MAXHOST];
	वर्ण strport[MAXIMUM(NI_MAXSERV, परिमाण(sunaddr->sun_path))];

	लागि (; cctx->ai; cctx->ai = cctx->ai->ai_next) {
		sock_is_network = 0;
		विकल्प (cctx->ai->ai_family) {
		पक्ष AF_UNIX:
			/* unix:pathname instead of host:port */
			sunaddr = (संरचना sockaddr_un *)cctx->ai->ai_addr;
			strlcpy(ntop, "unix", परिमाण(ntop));
			strlcpy(strport, sunaddr->sun_path, परिमाण(strport));
			रोक;
		पक्ष AF_INET:
		पक्ष AF_INET6:
			यदि (getnameinfo(cctx->ai->ai_addr, cctx->ai->ai_addrlen,
			    ntop, परिमाण(ntop), strport, परिमाण(strport),
			    NI_NUMERICHOST|NI_NUMERICSERV) != 0) {
				error_f("getnameinfo failed");
				जारी;
			}
			sock_is_network = 1;
			रोक;
		स्वभाव:
			जारी;
		}
		debug_f("start for host %.100s ([%.100s]:%s)",
		    cctx->host, ntop, strport);
		यदि ((sock = socket(cctx->ai->ai_family, cctx->ai->ai_socktype,
		    cctx->ai->ai_protocol)) == -1) {
			यदि (cctx->ai->ai_next == रिक्त)
				error("socket: %.100s", म_त्रुटि(त्रुटि_सं));
			अन्यथा
				verbose("socket: %.100s", म_त्रुटि(त्रुटि_सं));
			जारी;
		}
		यदि (set_nonblock(sock) == -1)
			fatal_f("set_nonblock(%d)", sock);
		यदि (sock_is_network && ssh->chanctxt->want_tcp_keepalive)
			set_keepalive(sock); /* logs errors */
		यदि (connect(sock, cctx->ai->ai_addr,
		    cctx->ai->ai_addrlen) == -1 && त्रुटि_सं != EINPROGRESS) {
			debug_f("host %.100s ([%.100s]:%s): %.100s",
			    cctx->host, ntop, strport, म_त्रुटि(त्रुटि_सं));
			saved_errno = त्रुटि_सं;
			बंद(sock);
			त्रुटि_सं = saved_errno;
			जारी;	/* fail -- try next */
		}
		यदि (cctx->ai->ai_family != AF_UNIX)
			set_nodelay(sock);
		debug_f("connect host %.100s ([%.100s]:%s) in progress, fd=%d",
		    cctx->host, ntop, strport, sock);
		cctx->ai = cctx->ai->ai_next;
		फर्काऊ sock;
	}
	फर्काऊ -1;
}

/*
 * Return connecting socket to remote host:port or local socket path,
 * passing back the failure reason if appropriate.
 */
स्थिर पूर्णाङ्क
connect_to_helper(संरचना ssh *ssh, अचर वर्ण *name, पूर्णाङ्क port, पूर्णाङ्क socktype,
    वर्ण *ctype, वर्ण *rname, संरचना channel_connect *cctx,
    पूर्णाङ्क *reason, अचर वर्ण **errmsg)
{
	संरचना addrinfo hints;
	पूर्णाङ्क gaierr;
	पूर्णाङ्क sock = -1;
	वर्ण strport[NI_MAXSERV];

	यदि (port == PORT_STREAMLOCAL) {
		संरचना sockaddr_un *sunaddr;
		संरचना addrinfo *ai;

		यदि (म_माप(name) > परिमाण(sunaddr->sun_path)) {
			error("%.100s: %.100s", name, म_त्रुटि(ENAMETOOLONG));
			फर्काऊ -1;
		}

		/*
		 * Fake up a struct addrinfo for AF_UNIX connections.
		 * free_connect_ctx() must check ai_family
		 * and use free() not freeaddrinfo() for AF_UNIX.
		 */
		ai = xcalloc(1, परिमाण(*ai) + परिमाण(*sunaddr));
		ai->ai_addr = (संरचना sockaddr *)(ai + 1);
		ai->ai_addrlen = परिमाण(*sunaddr);
		ai->ai_family = AF_UNIX;
		ai->ai_socktype = socktype;
		ai->ai_protocol = PF_UNSPEC;
		sunaddr = (संरचना sockaddr_un *)ai->ai_addr;
		sunaddr->sun_family = AF_UNIX;
		strlcpy(sunaddr->sun_path, name, परिमाण(sunaddr->sun_path));
		cctx->aitop = ai;
	} अन्यथा {
		स_रखो(&hints, 0, परिमाण(hints));
		hints.ai_family = ssh->chanctxt->IPv4or6;
		hints.ai_socktype = socktype;
		snprintf(strport, परिमाण strport, "%d", port);
		यदि ((gaierr = getaddrinfo(name, strport, &hints, &cctx->aitop))
		    != 0) {
			यदि (errmsg != रिक्त)
				*errmsg = ssh_gai_strerror(gaierr);
			यदि (reason != रिक्त)
				*reason = SSH2_OPEN_CONNECT_FAILED;
			error("connect_to %.100s: unknown host (%s)", name,
			    ssh_gai_strerror(gaierr));
			फर्काऊ -1;
		}
	}

	cctx->host = xstrdup(name);
	cctx->port = port;
	cctx->ai = cctx->aitop;

	यदि ((sock = connect_next(ssh, cctx)) == -1) {
		error("connect to %.100s port %d failed: %s",
		    name, port, म_त्रुटि(त्रुटि_सं));
		फर्काऊ -1;
	}

	फर्काऊ sock;
}

/* Return CONNECTING channel to remote host:port or local socket path */
स्थिर Channel *
connect_to(संरचना ssh *ssh, अचर वर्ण *host, पूर्णाङ्क port,
    वर्ण *ctype, वर्ण *rname)
{
	संरचना channel_connect cctx;
	Channel *c;
	पूर्णाङ्क sock;

	स_रखो(&cctx, 0, परिमाण(cctx));
	sock = connect_to_helper(ssh, host, port, SOCK_STREAM, ctype, rname,
	    &cctx, रिक्त, रिक्त);
	यदि (sock == -1) {
		free_connect_ctx(&cctx);
		फर्काऊ रिक्त;
	}
	c = channel_new(ssh, ctype, SSH_CHANNEL_CONNECTING, sock, sock, -1,
	    CHAN_TCP_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, rname, 1);
	c->host_port = port;
	c->path = xstrdup(host);
	c->connect_ctx = xmalloc(परिमाण(cctx));
	स_नकल(c->connect_ctx, &cctx, परिमाण(cctx));

	फर्काऊ c;
}

/*
 * returns either the newly connected channel or the downstream channel
 * that needs to deal with this connection.
 */
Channel *
channel_connect_by_listen_address(संरचना ssh *ssh, अचर वर्ण *listen_host,
    u_short listen_port, वर्ण *ctype, वर्ण *rname)
{
	संरचना ssh_channels *sc = ssh->chanctxt;
	संरचना permission_set *pset = &sc->local_perms;
	u_int i;
	संरचना permission *perm;

	लागि (i = 0; i < pset->अङ्क_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		यदि (open_listen_match_tcpip(perm,
		    listen_host, listen_port, 1)) {
			यदि (perm->downstream)
				फर्काऊ perm->downstream;
			यदि (perm->port_to_connect == 0)
				फर्काऊ rdynamic_connect_prepare(ssh,
				    ctype, rname);
			फर्काऊ connect_to(ssh,
			    perm->host_to_connect, perm->port_to_connect,
			    ctype, rname);
		}
	}
	error("WARNING: Server requests forwarding for unknown listen_port %d",
	    listen_port);
	फर्काऊ रिक्त;
}

Channel *
channel_connect_by_listen_path(संरचना ssh *ssh, अचर वर्ण *path,
    वर्ण *ctype, वर्ण *rname)
{
	संरचना ssh_channels *sc = ssh->chanctxt;
	संरचना permission_set *pset = &sc->local_perms;
	u_int i;
	संरचना permission *perm;

	लागि (i = 0; i < pset->अङ्क_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		यदि (open_listen_match_streamlocal(perm, path)) {
			फर्काऊ connect_to(ssh,
			    perm->host_to_connect, perm->port_to_connect,
			    ctype, rname);
		}
	}
	error("WARNING: Server requests forwarding for unknown path %.100s",
	    path);
	फर्काऊ रिक्त;
}

/* Check if connecting to that port is permitted and connect. */
Channel *
channel_connect_to_port(संरचना ssh *ssh, अचर वर्ण *host, u_short port,
    वर्ण *ctype, वर्ण *rname, पूर्णाङ्क *reason, अचर वर्ण **errmsg)
{
	संरचना ssh_channels *sc = ssh->chanctxt;
	संरचना permission_set *pset = &sc->local_perms;
	संरचना channel_connect cctx;
	Channel *c;
	u_int i, permit, permit_adm = 1;
	पूर्णाङ्क sock;
	संरचना permission *perm;

	permit = pset->all_permitted;
	यदि (!permit) {
		लागि (i = 0; i < pset->अङ्क_permitted_user; i++) {
			perm = &pset->permitted_user[i];
			यदि (open_match(perm, host, port)) {
				permit = 1;
				रोक;
			}
		}
	}

	यदि (pset->अङ्क_permitted_admin > 0) {
		permit_adm = 0;
		लागि (i = 0; i < pset->अङ्क_permitted_admin; i++) {
			perm = &pset->permitted_admin[i];
			यदि (open_match(perm, host, port)) {
				permit_adm = 1;
				रोक;
			}
		}
	}

	यदि (!permit || !permit_adm) {
		logit("Received request from %.100s port %d to connect to "
		    "host %.100s port %d, but the request was denied.",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh), host, port);
		यदि (reason != रिक्त)
			*reason = SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED;
		फर्काऊ रिक्त;
	}

	स_रखो(&cctx, 0, परिमाण(cctx));
	sock = connect_to_helper(ssh, host, port, SOCK_STREAM, ctype, rname,
	    &cctx, reason, errmsg);
	यदि (sock == -1) {
		free_connect_ctx(&cctx);
		फर्काऊ रिक्त;
	}

	c = channel_new(ssh, ctype, SSH_CHANNEL_CONNECTING, sock, sock, -1,
	    CHAN_TCP_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, rname, 1);
	c->host_port = port;
	c->path = xstrdup(host);
	c->connect_ctx = xmalloc(परिमाण(cctx));
	स_नकल(c->connect_ctx, &cctx, परिमाण(cctx));

	फर्काऊ c;
}

/* Check if connecting to that path is permitted and connect. */
Channel *
channel_connect_to_path(संरचना ssh *ssh, अचर वर्ण *path,
    वर्ण *ctype, वर्ण *rname)
{
	संरचना ssh_channels *sc = ssh->chanctxt;
	संरचना permission_set *pset = &sc->local_perms;
	u_int i, permit, permit_adm = 1;
	संरचना permission *perm;

	permit = pset->all_permitted;
	यदि (!permit) {
		लागि (i = 0; i < pset->अङ्क_permitted_user; i++) {
			perm = &pset->permitted_user[i];
			यदि (open_match(perm, path, PORT_STREAMLOCAL)) {
				permit = 1;
				रोक;
			}
		}
	}

	यदि (pset->अङ्क_permitted_admin > 0) {
		permit_adm = 0;
		लागि (i = 0; i < pset->अङ्क_permitted_admin; i++) {
			perm = &pset->permitted_admin[i];
			यदि (open_match(perm, path, PORT_STREAMLOCAL)) {
				permit_adm = 1;
				रोक;
			}
		}
	}

	यदि (!permit || !permit_adm) {
		logit("Received request to connect to path %.100s, "
		    "but the request was denied.", path);
		फर्काऊ रिक्त;
	}
	फर्काऊ connect_to(ssh, path, PORT_STREAMLOCAL, ctype, rname);
}

शून्य
channel_send_window_changes(संरचना ssh *ssh)
{
	संरचना ssh_channels *sc = ssh->chanctxt;
	संरचना winsize ws;
	पूर्णाङ्क r;
	u_int i;

	लागि (i = 0; i < sc->channels_alloc; i++) {
		यदि (sc->channels[i] == रिक्त || !sc->channels[i]->client_tty ||
		    sc->channels[i]->type != SSH_CHANNEL_OPEN)
			जारी;
		यदि (ioctl(sc->channels[i]->rfd, TIOCGWINSZ, &ws) == -1)
			जारी;
		channel_request_start(ssh, i, "window-change", 0);
		यदि ((r = sshpkt_put_u32(ssh, (u_int)ws.ws_col)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_row)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_xpixel)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_ypixel)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "channel %u; send window-change", i);
	}
}

/* Return RDYNAMIC_OPEN channel: channel allows SOCKS, but is not connected */
स्थिर Channel *
rdynamic_connect_prepare(संरचना ssh *ssh, वर्ण *ctype, वर्ण *rname)
{
	Channel *c;
	पूर्णाङ्क r;

	c = channel_new(ssh, ctype, SSH_CHANNEL_RDYNAMIC_OPEN, -1, -1, -1,
	    CHAN_TCP_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, rname, 1);
	c->host_port = 0;
	c->path = रिक्त;

	/*
	 * We need to open the channel before we have a FD,
	 * so that we can get SOCKS header from peer.
	 */
	यदि ((r = sshpkt_start(ssh, SSH2_सन्देश_CHANNEL_OPEN_CONFIRMATION)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_window)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0)
		fatal_fr(r, "channel %i; confirm", c->self);
	फर्काऊ c;
}

/* Return CONNECTING socket to remote host:port or local socket path */
स्थिर पूर्णाङ्क
rdynamic_connect_finish(संरचना ssh *ssh, Channel *c)
{
	संरचना ssh_channels *sc = ssh->chanctxt;
	संरचना permission_set *pset = &sc->local_perms;
	संरचना permission *perm;
	संरचना channel_connect cctx;
	u_int i, permit_adm = 1;
	पूर्णाङ्क sock;

	यदि (pset->अङ्क_permitted_admin > 0) {
		permit_adm = 0;
		लागि (i = 0; i < pset->अङ्क_permitted_admin; i++) {
			perm = &pset->permitted_admin[i];
			यदि (open_match(perm, c->path, c->host_port)) {
				permit_adm = 1;
				रोक;
			}
		}
	}
	यदि (!permit_adm) {
		debug_f("requested forward not permitted");
		फर्काऊ -1;
	}

	स_रखो(&cctx, 0, परिमाण(cctx));
	sock = connect_to_helper(ssh, c->path, c->host_port, SOCK_STREAM, रिक्त,
	    रिक्त, &cctx, रिक्त, रिक्त);
	यदि (sock == -1)
		free_connect_ctx(&cctx);
	अन्यथा {
		/* similar to SSH_CHANNEL_CONNECTING but we've already sent the open */
		c->type = SSH_CHANNEL_RDYNAMIC_FINISH;
		c->connect_ctx = xmalloc(परिमाण(cctx));
		स_नकल(c->connect_ctx, &cctx, परिमाण(cctx));
		channel_register_fds(ssh, c, sock, sock, -1, 0, 1, 0);
	}
	फर्काऊ sock;
}

/* -- X11 forwarding */

/*
 * Creates an internet domain socket for listening for X11 connections.
 * Returns 0 and a suitable display number for the DISPLAY variable
 * stored in display_numberp , or -1 if an error occurs.
 */
पूर्णाङ्क
x11_create_display_inet(संरचना ssh *ssh, पूर्णाङ्क x11_display_offset,
    पूर्णाङ्क x11_use_localhost, पूर्णाङ्क single_connection,
    u_int *display_numberp, पूर्णाङ्क **chanids)
{
	Channel *nc = रिक्त;
	पूर्णाङ्क display_सङ्ख्या, sock, port;
	संरचना addrinfo hints, *ai, *aitop;
	वर्ण strport[NI_MAXSERV];
	पूर्णाङ्क gaierr, n, अङ्क_socks = 0, socks[अङ्क_SOCKS];

	यदि (chanids == रिक्त || x11_display_offset < 0 ||
	    x11_display_offset > UINT16_MAX - X11_BASE_PORT - MAX_DISPLAYS)
		फर्काऊ -1;

	लागि (display_सङ्ख्या = x11_display_offset;
	    display_सङ्ख्या < x11_display_offset + MAX_DISPLAYS;
	    display_सङ्ख्या++) {
		port = X11_BASE_PORT + display_सङ्ख्या;
		स_रखो(&hints, 0, परिमाण(hints));
		hints.ai_family = ssh->chanctxt->IPv4or6;
		hints.ai_flags = x11_use_localhost ? 0: AI_PASSIVE;
		hints.ai_socktype = SOCK_STREAM;
		snprintf(strport, परिमाण strport, "%d", port);
		यदि ((gaierr = getaddrinfo(रिक्त, strport,
		    &hints, &aitop)) != 0) {
			error("getaddrinfo: %.100s", ssh_gai_strerror(gaierr));
			फर्काऊ -1;
		}
		लागि (ai = aitop; ai; ai = ai->ai_next) {
			यदि (ai->ai_family != AF_INET &&
			    ai->ai_family != AF_INET6)
				जारी;
			sock = socket(ai->ai_family, ai->ai_socktype,
			    ai->ai_protocol);
			यदि (sock == -1) {
				यदि ((त्रुटि_सं != EINVAL) && (त्रुटि_सं != EAFNOSUPPORT)
#ifdef EPFNOSUPPORT
				    && (त्रुटि_सं != EPFNOSUPPORT)
#endif 
				    ) {
					error("socket: %.100s", म_त्रुटि(त्रुटि_सं));
					freeaddrinfo(aitop);
					फर्काऊ -1;
				} अन्यथा {
					debug("x11_create_display_inet: Socket family %d not supported",
						 ai->ai_family);
					जारी;
				}
			}
			यदि (ai->ai_family == AF_INET6)
				sock_set_v6only(sock);
			यदि (x11_use_localhost)
				set_reuseaddr(sock);
			यदि (bind(sock, ai->ai_addr, ai->ai_addrlen) == -1) {
				debug2_f("bind port %d: %.100s", port,
				    म_त्रुटि(त्रुटि_सं));
				बंद(sock);
				लागि (n = 0; n < अङ्क_socks; n++)
					बंद(socks[n]);
				अङ्क_socks = 0;
				रोक;
			}
			socks[अङ्क_socks++] = sock;
			यदि (अङ्क_socks == अङ्क_SOCKS)
				रोक;
		}
		freeaddrinfo(aitop);
		यदि (अङ्क_socks > 0)
			रोक;
	}
	यदि (display_सङ्ख्या >= x11_display_offset + MAX_DISPLAYS) {
		error("Failed to allocate internet-domain X11 display socket.");
		फर्काऊ -1;
	}
	/* Start listening for connections on the socket. */
	लागि (n = 0; n < अङ्क_socks; n++) {
		sock = socks[n];
		यदि (listen(sock, SSH_LISTEN_BACKLOG) == -1) {
			error("listen: %.100s", म_त्रुटि(त्रुटि_सं));
			बंद(sock);
			फर्काऊ -1;
		}
	}

	/* Allocate a channel for each socket. */
	*chanids = xcalloc(अङ्क_socks + 1, परिमाण(**chanids));
	लागि (n = 0; n < अङ्क_socks; n++) {
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
	*display_numberp = display_सङ्ख्या;
	फर्काऊ 0;
}

स्थिर पूर्णाङ्क
connect_local_xsocket_path(अचर वर्ण *pathname)
{
	पूर्णाङ्क sock;
	संरचना sockaddr_un addr;

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	यदि (sock == -1) {
		error("socket: %.100s", म_त्रुटि(त्रुटि_सं));
		फर्काऊ -1;
	}
	स_रखो(&addr, 0, परिमाण(addr));
	addr.sun_family = AF_UNIX;
	strlcpy(addr.sun_path, pathname, परिमाण addr.sun_path);
	यदि (connect(sock, (संरचना sockaddr *)&addr, परिमाण(addr)) == 0)
		फर्काऊ sock;
	बंद(sock);
	error("connect %.100s: %.100s", addr.sun_path, म_त्रुटि(त्रुटि_सं));
	फर्काऊ -1;
}

स्थिर पूर्णाङ्क
connect_local_xsocket(u_int dnr)
{
	वर्ण buf[1024];
	snprintf(buf, परिमाण buf, _PATH_UNIX_X, dnr);
	फर्काऊ connect_local_xsocket_path(buf);
}

#ifdef __APPLE__
स्थिर पूर्णाङ्क
is_path_to_xsocket(अचर वर्ण *display, वर्ण *path, माप_प्रकार pathlen)
{
	संरचना stat sbuf;

	यदि (strlcpy(path, display, pathlen) >= pathlen) {
		error_f("display path too long");
		फर्काऊ 0;
	}
	यदि (display[0] != '/')
		फर्काऊ 0;
	यदि (stat(path, &sbuf) == 0) {
		फर्काऊ 1;
	} अन्यथा {
		वर्ण *dot = म_खोजप(path, '.');
		यदि (dot != रिक्त) {
			*dot = '\0';
			यदि (stat(path, &sbuf) == 0) {
				फर्काऊ 1;
			}
		}
	}
	फर्काऊ 0;
}
#endif

पूर्णाङ्क
x11_connect_display(संरचना ssh *ssh)
{
	u_int display_सङ्ख्या;
	अचर वर्ण *display;
	वर्ण buf[1024], *cp;
	संरचना addrinfo hints, *ai, *aitop;
	वर्ण strport[NI_MAXSERV];
	पूर्णाङ्क gaierr, sock = 0;

	/* Try to open a socket for the local X server. */
	display = दो_पर्या("DISPLAY");
	यदि (!display) {
		error("DISPLAY not set.");
		फर्काऊ -1;
	}
	/*
	 * Now we decode the value of the DISPLAY variable and make a
	 * connection to the real X server.
	 */

#ifdef __APPLE__
	/* Check if display is a path to a socket (as set by launchd). */
	{
		वर्ण path[PATH_MAX];

		यदि (is_path_to_xsocket(display, path, परिमाण(path))) {
			debug("x11_connect_display: $DISPLAY is launchd");

			/* Create a socket. */
			sock = connect_local_xsocket_path(path);
			यदि (sock < 0)
				फर्काऊ -1;

			/* OK, we now have a connection to the display. */
			फर्काऊ sock;
		}
	}
#endif
	/*
	 * Check if it is a unix domain socket.  Unix domain displays are in
	 * one of the following formats: unix:d[.s], :d[.s], ::d[.s]
	 */
	यदि (म_भेदन(display, "unix:", 5) == 0 ||
	    display[0] == ':') {
		/* Connect to the unix domain socket. */
		यदि (माला_पूछो(म_खोजप(display, ':') + 1, "%u",
		    &display_सङ्ख्या) != 1) {
			error("Could not parse display number from DISPLAY: "
			    "%.100s", display);
			फर्काऊ -1;
		}
		/* Create a socket. */
		sock = connect_local_xsocket(display_सङ्ख्या);
		यदि (sock < 0)
			फर्काऊ -1;

		/* OK, we now have a connection to the display. */
		फर्काऊ sock;
	}
	/*
	 * Connect to an inet socket.  The DISPLAY value is supposedly
	 * hostname:d[.s], where hostname may also be numeric IP address.
	 */
	strlcpy(buf, display, परिमाण(buf));
	cp = म_अक्षर(buf, ':');
	यदि (!cp) {
		error("Could not find ':' in DISPLAY: %.100s", display);
		फर्काऊ -1;
	}
	*cp = 0;
	/*
	 * buf now contains the host name.  But first we parse the
	 * display number.
	 */
	यदि (माला_पूछो(cp + 1, "%u", &display_सङ्ख्या) != 1 ||
	    display_सङ्ख्या > UINT16_MAX - X11_BASE_PORT) {
		error("Could not parse display number from DISPLAY: %.100s",
		    display);
		फर्काऊ -1;
	}

	/* Look up the host address */
	स_रखो(&hints, 0, परिमाण(hints));
	hints.ai_family = ssh->chanctxt->IPv4or6;
	hints.ai_socktype = SOCK_STREAM;
	snprintf(strport, परिमाण strport, "%u", X11_BASE_PORT + display_सङ्ख्या);
	यदि ((gaierr = getaddrinfo(buf, strport, &hints, &aitop)) != 0) {
		error("%.100s: unknown host. (%s)", buf,
		ssh_gai_strerror(gaierr));
		फर्काऊ -1;
	}
	लागि (ai = aitop; ai; ai = ai->ai_next) {
		/* Create a socket. */
		sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		यदि (sock == -1) {
			debug2("socket: %.100s", म_त्रुटि(त्रुटि_सं));
			जारी;
		}
		/* Connect it to the display. */
		यदि (connect(sock, ai->ai_addr, ai->ai_addrlen) == -1) {
			debug2("connect %.100s port %u: %.100s", buf,
			    X11_BASE_PORT + display_सङ्ख्या, म_त्रुटि(त्रुटि_सं));
			बंद(sock);
			जारी;
		}
		/* Success */
		रोक;
	}
	freeaddrinfo(aitop);
	यदि (!ai) {
		error("connect %.100s port %u: %.100s", buf,
		    X11_BASE_PORT + display_सङ्ख्या, म_त्रुटि(त्रुटि_सं));
		फर्काऊ -1;
	}
	set_nodelay(sock);
	फर्काऊ sock;
}

/*
 * Requests forwarding of X11 connections, generates fake authentication
 * data, and enables authentication spoofing.
 * This should be called in the client only.
 */
शून्य
x11_request_forwarding_with_spoofing(संरचना ssh *ssh, पूर्णाङ्क client_session_id,
    अचर वर्ण *disp, अचर वर्ण *proto, अचर वर्ण *data, पूर्णाङ्क want_reply)
{
	संरचना ssh_channels *sc = ssh->chanctxt;
	u_int data_len = (u_int) म_माप(data) / 2;
	u_int i, मान;
	अचर वर्ण *cp;
	वर्ण *new_data;
	पूर्णाङ्क r, screen_सङ्ख्या;

	यदि (sc->x11_saved_display == रिक्त)
		sc->x11_saved_display = xstrdup(disp);
	अन्यथा यदि (म_भेद(disp, sc->x11_saved_display) != 0) {
		error("x11_request_forwarding_with_spoofing: different "
		    "$DISPLAY already forwarded");
		फर्काऊ;
	}

	cp = म_अक्षर(disp, ':');
	यदि (cp)
		cp = म_अक्षर(cp, '.');
	यदि (cp)
		screen_सङ्ख्या = (u_int)strtonum(cp + 1, 0, 400, रिक्त);
	अन्यथा
		screen_सङ्ख्या = 0;

	यदि (sc->x11_saved_proto == रिक्त) {
		/* Save protocol name. */
		sc->x11_saved_proto = xstrdup(proto);

		/* Extract real authentication data. */
		sc->x11_saved_data = xmalloc(data_len);
		लागि (i = 0; i < data_len; i++) {
			यदि (माला_पूछो(data + 2 * i, "%2x", &मान) != 1) {
				fatal("x11_request_forwarding: bad "
				    "authentication data: %.100s", data);
			}
			sc->x11_saved_data[i] = मान;
		}
		sc->x11_saved_data_len = data_len;

		/* Generate fake data of the same length. */
		sc->x11_fake_data = xmalloc(data_len);
		arc4random_buf(sc->x11_fake_data, data_len);
		sc->x11_fake_data_len = data_len;
	}

	/* Convert the fake data into hex. */
	new_data = tohex(sc->x11_fake_data, data_len);

	/* Send the request packet. */
	channel_request_start(ssh, client_session_id, "x11-req", want_reply);
	यदि ((r = sshpkt_put_u8(ssh, 0)) != 0 || /* bool: single connection */
	    (r = sshpkt_put_cstring(ssh, proto)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, new_data)) != 0 ||
	    (r = sshpkt_put_u32(ssh, screen_सङ्ख्या)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send x11-req");
	मुक्त(new_data);
}

/*
 * Returns whether an x11 channel was used recently (less than a second ago)
 */
पूर्णाङ्क
x11_channel_used_recently(संरचना ssh *ssh) {
	u_int i;
	Channel *c;
	द्विगुण lastused = 0;

	लागि (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		यदि (c == रिक्त || c->ctype == रिक्त || c->lastused == 0.0 ||
		    म_भेद(c->ctype, "x11-connection") != 0)
			जारी;
		यदि (c->lastused > lastused)
			lastused = c->lastused;
	}
	फर्काऊ lastused != 0.0 && monotime_double() <= lastused + 1.0;
}
