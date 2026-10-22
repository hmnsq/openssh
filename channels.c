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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/stat.h>
#અન્તર્ભાવ <sys/ioctl.h>
#અન્તર્ભાવ <sys/un.h>
#અન્તર્ભાવ <sys/socket.h>
#અન્તર્ભાવ <sys/queue.h>

#અન્તર્ભાવ <netinet/in.h>
#અન્તર્ભાવ <arpa/inet.h>

#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <fcntl.h>
#અન્તર્ભાવ <limits.h>
#અન્તર્ભાવ <netdb.h>
#અન્તર્ભાવ <poll.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <stdint.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <termios.h>
#અન્તર્ભાવ <unistd.h>

#અન્તર્ભાવ "xmalloc.h"
#અન્તર્ભાવ "ssh.h"
#અન્તર્ભાવ "ssh2.h"
#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "packet.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "misc.h"
#અન્તર્ભાવ "channels.h"
#અન્તર્ભાવ "compat.h"
#અન્તર્ભાવ "canohost.h"
#અન્તર્ભાવ "pathnames.h"
#અન્તર્ભાવ "match.h"

/* XXX remove once we're satisfied there's no lurking bugs */
/* #define DEBUG_CHANNEL_POLL 1 */

/* -- agent forwarding */
#define	અંક_SOCKS	10

/* -- X11 forwarding */
/* X11 port for display :0 */
#define X11_BASE_PORT	6000
/* Maximum number of fake X11 displays to try. */
#define MAX_DISPLAYS  1000

/* Per-channel callback for pre/post IO actions */
પ્રકારવ્યાખ્યા શૂન્ય chan_fn(સંરચના ssh *, Channel *c);

/*
 * Data structure for storing which hosts are permitted for forward requests.
 * The local sides of any remote forwards are stored in this array to prevent
 * a corrupt remote server from accessing arbitrary TCP/IP ports on our local
 * network (which might be behind a firewall).
 */
/* XXX: streamlocal wants a path instead of host:port */
/*      Overload host_to_connect; we could just make this match Forward */
/*	XXX - can we use listen_host instead of listen_path? */
સંરચના permission {
	અક્ષર *host_to_connect;		/* Connect to 'host'. */
	પૂર્ણાંક port_to_connect;		/* Connect to 'port'. */
	અક્ષર *listen_host;		/* Remote side should listen address. */
	અક્ષર *listen_path;		/* Remote side should listen path. */
	પૂર્ણાંક listen_port;		/* Remote side should listen port. */
	Channel *downstream;		/* Downstream mux*/
};

/* Context for non-blocking connects */
સંરચના channel_connect {
	અક્ષર *host;
	પૂર્ણાંક port;
	સંરચના addrinfo *ai, *aitop;
};

/*
 * Stores the forwarding permission state for a single direction (local or
 * remote).
 */
સંરચના permission_set {
	/*
	 * List of all local permitted host/port pairs to allow for the
	 * user.
	 */
	u_int અંક_permitted_user;
	સંરચના permission *permitted_user;

	/*
	 * List of all permitted host/port pairs to allow for the admin.
	 */
	u_int અંક_permitted_admin;
	સંરચના permission *permitted_admin;

	/*
	 * If this is true, all opens/listens are permitted.  This is the
	 * case on the server on which we have to trust the client anyway,
	 * and the user could do anything after logging in.
	 */
	પૂર્ણાંક all_permitted;
};

/* Used to record timeouts per channel type */
સંરચના ssh_channel_timeout {
	અક્ષર *type_pattern;
	દ્વિગુણ timeout_secs;
};

/* Master structure for channels state */
સંરચના ssh_channels {
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
	સંરચના permission_set local_perms;
	સંરચના permission_set remote_perms;

	/* -- X11 forwarding */

	/* Saved X11 local (client) display. */
	અક્ષર *x11_saved_display;

	/* Saved X11 authentication protocol name. */
	અક્ષર *x11_saved_proto;

	/* Saved X11 authentication data.  This is the real data. */
	અક્ષર *x11_saved_data;
	u_int x11_saved_data_len;

	/* Deadline after which all X11 connections are refused */
	દ્વિગુણ x11_refuse_time;

	/*
	 * Fake X11 authentication data.  This is what the server will be
	 * sending us; we should replace any occurrences of this by the
	 * real data.
	 */
	u_char *x11_fake_data;
	u_int x11_fake_data_len;

	/* AF_UNSPEC or AF_INET or AF_INET6 */
	પૂર્ણાંક IPv4or6;

	/* Set SO_KEEPALIVE on TCP connections */
	પૂર્ણાંક want_tcp_keepalive;

	/* Channel timeouts by type */
	સંરચના ssh_channel_timeout *timeouts;
	size_t ntimeouts;
	/* Global timeout for all OPEN channels */
	દ્વિગુણ global_deadline;
	દ્વિગુણ lastused;
	/* pattern-lists used to classify channels as bulk */
	અક્ષર *bulk_classifier_tty, *bulk_classifier_notty;
	/* Number of active bulk channels (set by channel_handler) */
	u_int nbulk;
};

/* helper */
સ્થિર શૂન્ય port_open_helper(સંરચના ssh *ssh, Channel *c, અક્ષર *rtype);
સ્થિર અચલ અક્ષર *channel_rfwd_bind_host(અચલ અક્ષર *listen_host);

/* non-blocking connect helpers */
સ્થિર પૂર્ણાંક connect_next(સંરચના ssh *, સંરચના channel_connect *);
સ્થિર Channel *rdynamic_connect_prepare(સંરચના ssh *, અક્ષર *, અક્ષર *);
સ્થિર પૂર્ણાંક rdynamic_connect_finish(સંરચના ssh *, Channel *);

/* Setup helper */
સ્થિર શૂન્ય channel_handler_init(સંરચના ssh_channels *sc);

/* -- channel core */

શૂન્ય
channel_init_channels(સંરચના ssh *ssh)
{
	સંરચના ssh_channels *sc;

	જો ((sc = calloc(1, કદ(*sc))) == ખાલી)
		fatal_f("allocation failed");
	sc->channels_alloc = 10;
	sc->channels = xcalloc(sc->channels_alloc, કદ(*sc->channels));
	sc->IPv4or6 = AF_UNSPEC;
	sc->bulk_classifier_tty = xstrdup(CHANNEL_BULK_TTY);
	sc->bulk_classifier_notty = xstrdup(CHANNEL_BULK_NOTTY);
	channel_handler_init(sc);

	ssh->chanctxt = sc;
}

Channel *
channel_by_id(સંરચના ssh *ssh, પૂર્ણાંક id)
{
	Channel *c;

	જો (id < 0 || (u_int)id >= ssh->chanctxt->channels_alloc) {
		logit_f("%d: bad id", id);
		પાછા ખાલી;
	}
	c = ssh->chanctxt->channels[id];
	જો (c == ખાલી) {
		logit_f("%d: bad id: channel free", id);
		પાછા ખાલી;
	}
	પાછા c;
}

Channel *
channel_by_remote_id(સંરચના ssh *ssh, u_int remote_id)
{
	Channel *c;
	u_int i;

	માટે (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		જો (c != ખાલી && c->have_remote_id && c->remote_id == remote_id)
			પાછા c;
	}
	પાછા ખાલી;
}

/*
 * Returns the channel if it is allowed to receive protocol messages.
 * Private channels, like listening sockets, may not receive messages.
 */
Channel *
channel_lookup(સંરચના ssh *ssh, પૂર્ણાંક id)
{
	Channel *c;

	જો ((c = channel_by_id(ssh, id)) == ખાલી)
		પાછા ખાલી;

	પસંદગી (c->type) {
	સ્થિતિ SSH_CHANNEL_X11_OPEN:
	સ્થિતિ SSH_CHANNEL_LARVAL:
	સ્થિતિ SSH_CHANNEL_CONNECTING:
	સ્થિતિ SSH_CHANNEL_DYNAMIC:
	સ્થિતિ SSH_CHANNEL_RDYNAMIC_OPEN:
	સ્થિતિ SSH_CHANNEL_RDYNAMIC_FINISH:
	સ્થિતિ SSH_CHANNEL_OPENING:
	સ્થિતિ SSH_CHANNEL_OPEN:
	સ્થિતિ SSH_CHANNEL_ABANDONED:
	સ્થિતિ SSH_CHANNEL_MUX_PROXY:
		પાછા c;
	}
	logit("Non-public channel %d, type %d.", id, c->type);
	પાછા ખાલી;
}

સ્થિર શૂન્ય
free_connect_ctx(સંરચના channel_connect *cctx)
{
	મુક્ત(cctx->host);
	જો (cctx->aitop) {
		જો (cctx->aitop->ai_family == AF_UNIX)
			મુક્ત(cctx->aitop);
		નહીંતર
			freeaddrinfo(cctx->aitop);
	}
	memset(cctx, 0, કદ(*cctx));
}

સ્થિર શૂન્ય
channel_free_connect_ctx(Channel *c)
{
	જો (c == ખાલી || c->connect_ctx == ખાલી)
		પાછા;
	free_connect_ctx(c->connect_ctx);
	મુક્ત(c->connect_ctx);
	c->connect_ctx = ખાલી;
}

/* Enable/disable TCP keepalives for X11 and port-forwarding sockets */
શૂન્ય
channel_set_tcp_keepalives(સંરચના ssh *ssh, પૂર્ણાંક on)
{
	ssh->chanctxt->want_tcp_keepalive = on;
}

/*
 * Add a timeout for open channels whose c->ctype (or c->xctype if it is set)
 * match type_pattern.
 */
શૂન્ય
channel_add_timeout(સંરચના ssh *ssh, અચલ અક્ષર *type_pattern,
    દ્વિગુણ timeout_secs)
{
	સંરચના ssh_channels *sc = ssh->chanctxt;

	જો (strcmp(type_pattern, "global") == 0) {
		debug2_f("global channel timeout %f seconds", timeout_secs);
		sc->global_deadline = timeout_secs;
		પાછા;
	}
	debug2_f("channel type \"%s\" timeout %f seconds",
	    type_pattern, timeout_secs);
	sc->timeouts = xrecallocarray(sc->timeouts, sc->ntimeouts,
	    sc->ntimeouts + 1, કદ(*sc->timeouts));
	sc->timeouts[sc->ntimeouts].type_pattern = xstrdup(type_pattern);
	sc->timeouts[sc->ntimeouts].timeout_secs = timeout_secs;
	sc->ntimeouts++;
}

/* Clears all previously-added channel timeouts */
શૂન્ય
channel_clear_timeouts(સંરચના ssh *ssh)
{
	સંરચના ssh_channels *sc = ssh->chanctxt;
	size_t i;

	debug3_f("clearing");
	માટે (i = 0; i < sc->ntimeouts; i++)
		મુક્ત(sc->timeouts[i].type_pattern);
	મુક્ત(sc->timeouts);
	sc->timeouts = ખાલી;
	sc->ntimeouts = 0;
}

સ્થિર દ્વિગુણ
lookup_timeout(સંરચના ssh *ssh, અચલ અક્ષર *type)
{
	સંરચના ssh_channels *sc = ssh->chanctxt;
	size_t i;

	માટે (i = 0; i < sc->ntimeouts; i++) {
		જો (match_pattern(type, sc->timeouts[i].type_pattern))
			પાછા sc->timeouts[i].timeout_secs;
	}

	પાછા 0;
}

સ્થિર શૂન્ય
channel_classify(સંરચના ssh *ssh, Channel *c)
{
	સંરચના ssh_channels *sc = ssh->chanctxt;
	અચલ અક્ષર *type = c->xctype == ખાલી ? c->ctype : c->xctype;
	અચલ પૂર્ણાંક has_tty = c->isatty || c->remote_has_tty;
	અચલ અક્ષર *classifier = has_tty ?
	    sc->bulk_classifier_tty : sc->bulk_classifier_notty;

	c->bulk = type != ખાલી && match_pattern_list(type, classifier, 0) == 1;
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
શૂન્ય
channel_set_xtype(સંરચના ssh *ssh, પૂર્ણાંક id, અચલ અક્ષર *xctype)
{
	સંરચના ssh_channels *sc = ssh->chanctxt;
	Channel *c;

	જો ((c = channel_by_id(ssh, id)) == ખાલી)
		fatal_f("missing channel %d", id);
	જો (c->xctype != ખાલી)
		મુક્ત(c->xctype);
	c->xctype = xstrdup(xctype);
	/* Only override deadline if xctype has a more specific match. */
	દ્વિગુણ xtype_deadline = lookup_timeout(ssh, c->xctype);
	જો (xtype_deadline != 0)
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
સ્થિર શૂન્ય
channel_set_used_time(સંરચના ssh *ssh, Channel *c)
{
	ssh->chanctxt->lastused = monotime_double();
	જો (c != ખાલી)
		c->lastused = ssh->chanctxt->lastused;
}

/*
 * Get the time at which a channel is due to time out for inactivity.
 * Returns 0 if the channel is not due to time out ever.
 */
સ્થિર દ્વિગુણ
channel_get_expiry(સંરચના ssh *ssh, Channel *c)
{
	સંરચના ssh_channels *sc = ssh->chanctxt;
	દ્વિગુણ expiry = 0, channel_expiry;

	જો (sc->lastused != 0 && sc->global_deadline != 0)
		expiry = sc->lastused + sc->global_deadline;
	જો (c->lastused != 0 && c->inactive_deadline != 0) {
		channel_expiry = c->lastused + c->inactive_deadline;
		જો (expiry == 0 || channel_expiry < expiry)
			expiry = channel_expiry;
	}
	પાછા expiry;
}

/* Returns non-zero if there is an open, non-interactive channel */
પૂર્ણાંક
channel_has_bulk(સંરચના ssh *ssh)
{
	પાછા ssh->chanctxt != ખાલી && ssh->chanctxt->nbulk != 0;
}

/*
 * Register filedescriptors for a channel, used when allocating a channel or
 * when the channel consumer/producer is ready, e.g. shell exec'd
 */
સ્થિર શૂન્ય
channel_register_fds(સંરચના ssh *ssh, Channel *c, પૂર્ણાંક rfd, પૂર્ણાંક wfd, પૂર્ણાંક efd,
    પૂર્ણાંક extusage, પૂર્ણાંક nonblock, પૂર્ણાંક is_tty)
{
	પૂર્ણાંક val;

	જો (rfd != -1)
		(શૂન્ય)fcntl(rfd, F_SETFD, FD_CLOEXEC);
	જો (wfd != -1 && wfd != rfd)
		(શૂન્ય)fcntl(wfd, F_SETFD, FD_CLOEXEC);
	જો (efd != -1 && efd != rfd && efd != wfd)
		(શૂન્ય)fcntl(efd, F_SETFD, FD_CLOEXEC);

	c->rfd = rfd;
	c->wfd = wfd;
	c->sock = (rfd == wfd) ? rfd : -1;
	c->efd = efd;
	c->extended_usage = extusage;

	જો ((c->isatty = is_tty) != 0)
		debug2("channel %d: rfd %d isatty", c->self, c->rfd);
#ifdef _AIX
	/* XXX: Later AIX versions can't push as much data to tty */
	c->wfd_isatty = is_tty || isatty(c->wfd);
#endif

	/* enable nonblocking mode */
	c->restore_block = 0;
	જો (nonblock == CHANNEL_NONBLOCK_STDIO) {
		/*
		 * Special handling for stdio file descriptors: do not set
		 * non-blocking mode if they are TTYs. Otherwise prepare to
		 * restore their blocking state on exit to avoid interfering
		 * with other programs that follow.
		 */
		જો (rfd != -1 && !isatty(rfd) &&
		    (val = fcntl(rfd, F_GETFL)) != -1 && !(val & O_NONBLOCK)) {
			c->restore_flags[0] = val;
			c->restore_block |= CHANNEL_RESTORE_RFD;
			set_nonblock(rfd);
		}
		જો (wfd != -1 && !isatty(wfd) &&
		    (val = fcntl(wfd, F_GETFL)) != -1 && !(val & O_NONBLOCK)) {
			c->restore_flags[1] = val;
			c->restore_block |= CHANNEL_RESTORE_WFD;
			set_nonblock(wfd);
		}
		જો (efd != -1 && !isatty(efd) &&
		    (val = fcntl(efd, F_GETFL)) != -1 && !(val & O_NONBLOCK)) {
			c->restore_flags[2] = val;
			c->restore_block |= CHANNEL_RESTORE_EFD;
			set_nonblock(efd);
		}
	} નહીંતર જો (nonblock) {
		જો (rfd != -1)
			set_nonblock(rfd);
		જો (wfd != -1)
			set_nonblock(wfd);
		જો (efd != -1)
			set_nonblock(efd);
	}
	/* channel might be entering a larval state, so reset global timeout */
	channel_set_used_time(ssh, ખાલી);
	channel_classify(ssh, c);
}

/*
 * Allocate a new channel object and set its type and socket.
 */
Channel *
channel_new(સંરચના ssh *ssh, અક્ષર *ctype, પૂર્ણાંક type, પૂર્ણાંક rfd, પૂર્ણાંક wfd, પૂર્ણાંક efd,
    u_int window, u_int maxpack, પૂર્ણાંક extusage, અચલ અક્ષર *remote_name,
    પૂર્ણાંક nonblock)
{
	સંરચના ssh_channels *sc = ssh->chanctxt;
	u_int i, found = 0;
	Channel *c;
	પૂર્ણાંક r;

	/* Try to find a free slot where to put the new channel. */
	માટે (i = 0; i < sc->channels_alloc; i++) {
		જો (sc->channels[i] == ખાલી) {
			/* Found a free slot. */
			found = i;
			તોડો;
		}
	}
	જો (i >= sc->channels_alloc) {
		/*
		 * There are no free slots. Take last+1 slot and expand
		 * the array.
		 */
		found = sc->channels_alloc;
		જો (sc->channels_alloc > CHANNELS_MAX_CHANNELS)
			fatal_f("internal error: channels_alloc %d too big",
			    sc->channels_alloc);
		sc->channels = xrecallocarray(sc->channels, sc->channels_alloc,
		    sc->channels_alloc + 10, કદ(*sc->channels));
		sc->channels_alloc += 10;
		debug2("channel: expanding %d", sc->channels_alloc);
	}
	/* Initialize and return new channel. */
	c = sc->channels[found] = xcalloc(1, કદ(Channel));
	જો ((c->આગત = sshbuf_new()) == ખાલી ||
	    (c->output = sshbuf_new()) == ખાલી ||
	    (c->extended = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	જો ((r = sshbuf_set_max_size(c->આગત, CHAN_આગત_MAX)) != 0)
		fatal_fr(r, "sshbuf_set_max_size");
	c->ostate = CHAN_OUTPUT_OPEN;
	c->istate = CHAN_આગત_OPEN;
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
	પાછા c;
}

શૂન્ય
channel_set_tty(સંરચના ssh *ssh, Channel *c)
{
	c->remote_has_tty = 1;
	channel_classify(ssh, c);
}

પૂર્ણાંક
channel_close_fd(સંરચના ssh *ssh, Channel *c, પૂર્ણાંક *fdp)
{
	પૂર્ણાંક ret, fd = *fdp;

	જો (fd == -1)
		પાછા 0;

	/* restore blocking */
	જો (*fdp == c->rfd &&
	    (c->restore_block & CHANNEL_RESTORE_RFD) != 0)
		(શૂન્ય)fcntl(*fdp, F_SETFL, c->restore_flags[0]);
	નહીંતર જો (*fdp == c->wfd &&
	    (c->restore_block & CHANNEL_RESTORE_WFD) != 0)
		(શૂન્ય)fcntl(*fdp, F_SETFL, c->restore_flags[1]);
	નહીંતર જો (*fdp == c->efd &&
	    (c->restore_block & CHANNEL_RESTORE_EFD) != 0)
		(શૂન્ય)fcntl(*fdp, F_SETFL, c->restore_flags[2]);

	જો (*fdp == c->rfd) {
		c->io_want &= ~SSH_CHAN_IO_RFD;
		c->io_ready &= ~SSH_CHAN_IO_RFD;
		c->rfd = -1;
		c->pfds[0] = -1;
	}
	જો (*fdp == c->wfd) {
		c->io_want &= ~SSH_CHAN_IO_WFD;
		c->io_ready &= ~SSH_CHAN_IO_WFD;
		c->wfd = -1;
		c->pfds[1] = -1;
	}
	જો (*fdp == c->efd) {
		c->io_want &= ~SSH_CHAN_IO_EFD;
		c->io_ready &= ~SSH_CHAN_IO_EFD;
		c->efd = -1;
		c->pfds[2] = -1;
	}
	જો (*fdp == c->sock) {
		c->io_want &= ~SSH_CHAN_IO_SOCK;
		c->io_ready &= ~SSH_CHAN_IO_SOCK;
		c->sock = -1;
		c->pfds[3] = -1;
	}

	ret = close(fd);
	*fdp = -1; /* probably redundant */
	પાછા ret;
}

/* Close all channel fd/socket. */
સ્થિર શૂન્ય
channel_close_fds(સંરચના ssh *ssh, Channel *c)
{
	પૂર્ણાંક sock = c->sock, rfd = c->rfd, wfd = c->wfd, efd = c->efd;

	channel_close_fd(ssh, c, &c->sock);
	જો (rfd != sock)
		channel_close_fd(ssh, c, &c->rfd);
	જો (wfd != sock && wfd != rfd)
		channel_close_fd(ssh, c, &c->wfd);
	જો (efd != sock && efd != rfd && efd != wfd)
		channel_close_fd(ssh, c, &c->efd);
}

સ્થિર શૂન્ય
fwd_perm_clear(સંરચના permission *perm)
{
	મુક્ત(perm->host_to_connect);
	મુક્ત(perm->listen_host);
	મુક્ત(perm->listen_path);
	memset(perm, 0, કદ(*perm));
}

/* Returns an printable name for the specified forwarding permission list */
સ્થિર અચલ અક્ષર *
fwd_ident(પૂર્ણાંક who, પૂર્ણાંક where)
{
	જો (who == FORWARD_ADM) {
		જો (where == FORWARD_LOCAL)
			પાછા "admin local";
		નહીંતર જો (where == FORWARD_REMOTE)
			પાછા "admin remote";
	} નહીંતર જો (who == FORWARD_USER) {
		જો (where == FORWARD_LOCAL)
			પાછા "user local";
		નહીંતર જો (where == FORWARD_REMOTE)
			પાછા "user remote";
	}
	fatal("Unknown forward permission list %d/%d", who, where);
}

/* Returns the forwarding permission list for the specified direction */
સ્થિર સંરચના permission_set *
permission_set_get(સંરચના ssh *ssh, પૂર્ણાંક where)
{
	સંરચના ssh_channels *sc = ssh->chanctxt;

	પસંદગી (where) {
	સ્થિતિ FORWARD_LOCAL:
		પાછા &sc->local_perms;
		તોડો;
	સ્થિતિ FORWARD_REMOTE:
		પાછા &sc->remote_perms;
		તોડો;
	મૂળભૂત:
		fatal_f("invalid forwarding direction %d", where);
	}
}

/* Returns pointers to the specified forwarding list and its element count */
સ્થિર શૂન્ય
permission_set_get_array(સંરચના ssh *ssh, પૂર્ણાંક who, પૂર્ણાંક where,
    સંરચના permission ***permpp, u_int **npermpp)
{
	સંરચના permission_set *pset = permission_set_get(ssh, where);

	પસંદગી (who) {
	સ્થિતિ FORWARD_USER:
		*permpp = &pset->permitted_user;
		*npermpp = &pset->અંક_permitted_user;
		તોડો;
	સ્થિતિ FORWARD_ADM:
		*permpp = &pset->permitted_admin;
		*npermpp = &pset->અંક_permitted_admin;
		તોડો;
	મૂળભૂત:
		fatal_f("invalid forwarding client %d", who);
	}
}

/* Adds an entry to the specified forwarding list */
સ્થિર પૂર્ણાંક
permission_set_add(સંરચના ssh *ssh, પૂર્ણાંક who, પૂર્ણાંક where,
    અચલ અક્ષર *host_to_connect, પૂર્ણાંક port_to_connect,
    અચલ અક્ષર *listen_host, અચલ અક્ષર *listen_path, પૂર્ણાંક listen_port,
    Channel *downstream)
{
	સંરચના permission **permp;
	u_int n, *npermp;

	permission_set_get_array(ssh, who, where, &permp, &npermp);

	જો (*npermp >= INT_MAX)
		fatal_f("%s overflow", fwd_ident(who, where));

	*permp = xrecallocarray(*permp, *npermp, *npermp + 1, કદ(**permp));
	n = (*npermp)++;
#define MAYBE_DUP(s) ((s == ખાલી) ? ખાલી : xstrdup(s))
	(*permp)[n].host_to_connect = MAYBE_DUP(host_to_connect);
	(*permp)[n].port_to_connect = port_to_connect;
	(*permp)[n].listen_host = MAYBE_DUP(listen_host);
	(*permp)[n].listen_path = MAYBE_DUP(listen_path);
	(*permp)[n].listen_port = listen_port;
	(*permp)[n].downstream = downstream;
#undef MAYBE_DUP
	પાછા (પૂર્ણાંક)n;
}

સ્થિર શૂન્ય
mux_remove_remote_forwardings(સંરચના ssh *ssh, Channel *c)
{
	સંરચના ssh_channels *sc = ssh->chanctxt;
	સંરચના permission_set *pset = &sc->local_perms;
	સંરચના permission *perm;
	પૂર્ણાંક r;
	u_int i;

	માટે (i = 0; i < pset->અંક_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		જો (perm->downstream != c)
			ચાલુ;

		/* cancel on the server, since mux client is gone */
		debug("channel %d: cleanup remote forward for %s:%u",
		    c->self, perm->listen_host, perm->listen_port);
		જો ((r = sshpkt_start(ssh, SSH2_સંદેશ_GLOBAL_REQUEST)) != 0 ||
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
શૂન્ય
channel_free(સંરચના ssh *ssh, Channel *c)
{
	સંરચના ssh_channels *sc = ssh->chanctxt;
	અક્ષર *s;
	u_int i, n;
	Channel *other;
	સંરચના channel_confirm *cc;

	માટે (n = 0, i = 0; i < sc->channels_alloc; i++) {
		જો ((other = sc->channels[i]) == ખાલી)
			ચાલુ;
		n++;
		/* detach from mux client and prepare for closing */
		જો (c->type == SSH_CHANNEL_MUX_CLIENT &&
		    other->type == SSH_CHANNEL_MUX_PROXY &&
		    other->mux_ctx == c) {
			other->mux_ctx = ખાલી;
			other->type = SSH_CHANNEL_OPEN;
			other->istate = CHAN_આગત_CLOSED;
			other->ostate = CHAN_OUTPUT_CLOSED;
		}
	}
	debug("channel %d: free: %s, nchannels %u", c->self,
	    c->remote_name ? c->remote_name : "???", n);

	જો (c->type == SSH_CHANNEL_MUX_CLIENT) {
		mux_remove_remote_forwardings(ssh, c);
		મુક્ત(c->mux_ctx);
		c->mux_ctx = ખાલી;
	} નહીંતર જો (c->type == SSH_CHANNEL_MUX_LISTENER) {
		મુક્ત(c->mux_ctx);
		c->mux_ctx = ખાલી;
	}

	જો (log_level_get() >= SYSLOG_LEVEL_DEBUG3) {
		s = channel_open_message(ssh);
		debug3("channel %d: status: %s", c->self, s);
		મુક્ત(s);
	}

	channel_close_fds(ssh, c);
	sshbuf_free(c->આગત);
	sshbuf_free(c->output);
	sshbuf_free(c->extended);
	c->આગત = c->output = c->extended = ખાલી;
	મુક્ત(c->remote_name);
	c->remote_name = ખાલી;
	મુક્ત(c->path);
	c->path = ખાલી;
	મુક્ત(c->listening_addr);
	c->listening_addr = ખાલી;
	મુક્ત(c->xctype);
	c->xctype = ખાલી;
	channel_free_connect_ctx(c);
	જ્યારે ((cc = TAILQ_FIRST(&c->status_confirms)) != ખાલી) {
		જો (cc->abandon_cb != ખાલી)
			cc->abandon_cb(ssh, c, cc->ctx);
		TAILQ_REMOVE(&c->status_confirms, cc, entry);
		freezero(cc, કદ(*cc));
	}
	જો (c->filter_cleanup != ખાલી && c->filter_ctx != ખાલી)
		c->filter_cleanup(ssh, c->self, c->filter_ctx);
	sc->channels[c->self] = ખાલી;
	freezero(c, કદ(*c));
}

શૂન્ય
channel_free_all(સંરચના ssh *ssh)
{
	u_int i;
	સંરચના ssh_channels *sc = ssh->chanctxt;

	માટે (i = 0; i < sc->channels_alloc; i++)
		જો (sc->channels[i] != ખાલી)
			channel_free(ssh, sc->channels[i]);

	મુક્ત(sc->channels);
	sc->channels = ખાલી;
	sc->channels_alloc = 0;

	મુક્ત(sc->x11_saved_display);
	sc->x11_saved_display = ખાલી;

	મુક્ત(sc->x11_saved_proto);
	sc->x11_saved_proto = ખાલી;

	મુક્ત(sc->x11_saved_data);
	sc->x11_saved_data = ખાલી;
	sc->x11_saved_data_len = 0;

	મુક્ત(sc->x11_fake_data);
	sc->x11_fake_data = ખાલી;
	sc->x11_fake_data_len = 0;
}

શૂન્ય
channel_free_channels(સંરચના ssh *ssh)
{
	સંરચના ssh_channels *sc;

	જો (ssh == ખાલી || ssh->chanctxt == ખાલી)
		પાછા;
	channel_free_all(ssh);
	channel_clear_permission(ssh, FORWARD_USER, FORWARD_LOCAL);
	channel_clear_permission(ssh, FORWARD_USER, FORWARD_REMOTE);
	channel_clear_permission(ssh, FORWARD_ADM, FORWARD_LOCAL);
	channel_clear_permission(ssh, FORWARD_ADM, FORWARD_REMOTE);
	sc = ssh->chanctxt;
	મુક્ત(sc->bulk_classifier_tty);
	મુક્ત(sc->bulk_classifier_notty);
	મુક્ત(sc->channel_pre);
	મુક્ત(sc->channel_post);
	freezero(sc, કદ(*sc));
	ssh->chanctxt = ખાલી;
}

/*
 * Closes the sockets/fds of all channels.  This is used to close extra file
 * descriptors after a fork.
 */
શૂન્ય
channel_close_all(સંરચના ssh *ssh)
{
	u_int i;

	માટે (i = 0; i < ssh->chanctxt->channels_alloc; i++)
		જો (ssh->chanctxt->channels[i] != ખાલી)
			channel_close_fds(ssh, ssh->chanctxt->channels[i]);
}

/*
 * Stop listening to channels.
 */
શૂન્ય
channel_stop_listening(સંરચના ssh *ssh)
{
	u_int i;
	Channel *c;

	માટે (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		જો (c != ખાલી) {
			પસંદગી (c->type) {
			સ્થિતિ SSH_CHANNEL_AUTH_SOCKET:
			સ્થિતિ SSH_CHANNEL_PORT_LISTENER:
			સ્થિતિ SSH_CHANNEL_RPORT_LISTENER:
			સ્થિતિ SSH_CHANNEL_X11_LISTENER:
			સ્થિતિ SSH_CHANNEL_UNIX_LISTENER:
			સ્થિતિ SSH_CHANNEL_RUNIX_LISTENER:
				channel_close_fd(ssh, c, &c->sock);
				channel_free(ssh, c);
				તોડો;
			}
		}
	}
}

/*
 * Returns true if no channel has too much buffered data, and false if one or
 * more channel is overfull.
 */
પૂર્ણાંક
channel_not_very_much_buffered_data(સંરચના ssh *ssh)
{
	u_int i;
	u_int maxsize = ssh_packet_get_maxsize(ssh);
	Channel *c;

	માટે (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		જો (c == ખાલી || c->type != SSH_CHANNEL_OPEN)
			ચાલુ;
		જો (sshbuf_len(c->output) > maxsize) {
			debug2("channel %d: big output buffer %zu > %u",
			    c->self, sshbuf_len(c->output), maxsize);
			પાછા 0;
		}
	}
	પાછા 1;
}

/* Returns true if any channel is still open. */
પૂર્ણાંક
channel_still_open(સંરચના ssh *ssh)
{
	u_int i;
	Channel *c;

	માટે (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		જો (c == ખાલી)
			ચાલુ;
		પસંદગી (c->type) {
		સ્થિતિ SSH_CHANNEL_X11_LISTENER:
		સ્થિતિ SSH_CHANNEL_PORT_LISTENER:
		સ્થિતિ SSH_CHANNEL_RPORT_LISTENER:
		સ્થિતિ SSH_CHANNEL_MUX_LISTENER:
		સ્થિતિ SSH_CHANNEL_CLOSED:
		સ્થિતિ SSH_CHANNEL_AUTH_SOCKET:
		સ્થિતિ SSH_CHANNEL_DYNAMIC:
		સ્થિતિ SSH_CHANNEL_RDYNAMIC_OPEN:
		સ્થિતિ SSH_CHANNEL_CONNECTING:
		સ્થિતિ SSH_CHANNEL_ZOMBIE:
		સ્થિતિ SSH_CHANNEL_ABANDONED:
		સ્થિતિ SSH_CHANNEL_UNIX_LISTENER:
		સ્થિતિ SSH_CHANNEL_RUNIX_LISTENER:
			ચાલુ;
		સ્થિતિ SSH_CHANNEL_LARVAL:
			ચાલુ;
		સ્થિતિ SSH_CHANNEL_OPENING:
		સ્થિતિ SSH_CHANNEL_OPEN:
		સ્થિતિ SSH_CHANNEL_RDYNAMIC_FINISH:
		સ્થિતિ SSH_CHANNEL_X11_OPEN:
		સ્થિતિ SSH_CHANNEL_MUX_CLIENT:
		સ્થિતિ SSH_CHANNEL_MUX_PROXY:
			પાછા 1;
		મૂળભૂત:
			fatal_f("bad channel type %d", c->type);
			/* NOTREACHED */
		}
	}
	પાછા 0;
}

/* Returns true if a channel with a TTY is open. */
પૂર્ણાંક
channel_tty_open(સંરચના ssh *ssh)
{
	u_int i;
	Channel *c;

	માટે (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		જો (c == ખાલી || c->type != SSH_CHANNEL_OPEN)
			ચાલુ;
		જો (c->client_tty)
			પાછા 1;
	}
	પાછા 0;
}

/* Returns the id of an open channel suitable for keepaliving */
પૂર્ણાંક
channel_find_open(સંરચના ssh *ssh)
{
	u_int i;
	Channel *c;

	માટે (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		જો (c == ખાલી || !c->have_remote_id)
			ચાલુ;
		પસંદગી (c->type) {
		સ્થિતિ SSH_CHANNEL_CLOSED:
		સ્થિતિ SSH_CHANNEL_DYNAMIC:
		સ્થિતિ SSH_CHANNEL_RDYNAMIC_OPEN:
		સ્થિતિ SSH_CHANNEL_RDYNAMIC_FINISH:
		સ્થિતિ SSH_CHANNEL_X11_LISTENER:
		સ્થિતિ SSH_CHANNEL_PORT_LISTENER:
		સ્થિતિ SSH_CHANNEL_RPORT_LISTENER:
		સ્થિતિ SSH_CHANNEL_MUX_LISTENER:
		સ્થિતિ SSH_CHANNEL_MUX_CLIENT:
		સ્થિતિ SSH_CHANNEL_MUX_PROXY:
		સ્થિતિ SSH_CHANNEL_OPENING:
		સ્થિતિ SSH_CHANNEL_CONNECTING:
		સ્થિતિ SSH_CHANNEL_ZOMBIE:
		સ્થિતિ SSH_CHANNEL_ABANDONED:
		સ્થિતિ SSH_CHANNEL_UNIX_LISTENER:
		સ્થિતિ SSH_CHANNEL_RUNIX_LISTENER:
			ચાલુ;
		સ્થિતિ SSH_CHANNEL_LARVAL:
		સ્થિતિ SSH_CHANNEL_AUTH_SOCKET:
		સ્થિતિ SSH_CHANNEL_OPEN:
		સ્થિતિ SSH_CHANNEL_X11_OPEN:
			પાછા i;
		મૂળભૂત:
			fatal_f("bad channel type %d", c->type);
			/* NOTREACHED */
		}
	}
	પાછા -1;
}

/* Returns the state of the channel's extended usage flag */
અચલ અક્ષર *
channel_format_extended_usage(અચલ Channel *c)
{
	જો (c->efd == -1)
		પાછા "closed";

	પસંદગી (c->extended_usage) {
	સ્થિતિ CHAN_EXTENDED_WRITE:
		પાછા "write";
	સ્થિતિ CHAN_EXTENDED_READ:
		પાછા "read";
	સ્થિતિ CHAN_EXTENDED_IGNORE:
		પાછા "ignore";
	મૂળભૂત:
		પાછા "UNKNOWN";
	}
}

સ્થિર અક્ષર *
channel_format_status(અચલ Channel *c)
{
	અક્ષર *ret = ખાલી;

	xasprintf(&ret, "t%d [%s] %s%u %s%u i%u/%zu o%u/%zu e[%s]/%zu "
	    "fd %d/%d/%d sock %d cc %d %s%u io 0x%02x/0x%02x %s%s",
	    c->type, c->xctype != ખાલી ? c->xctype : c->ctype,
	    c->have_remote_id ? "r" : "nr", c->remote_id,
	    c->mux_ctx != ખાલી ? "m" : "nm", c->mux_downstream_id,
	    c->istate, sshbuf_len(c->આગત),
	    c->ostate, sshbuf_len(c->output),
	    channel_format_extended_usage(c), sshbuf_len(c->extended),
	    c->rfd, c->wfd, c->efd, c->sock, c->ctl_chan,
	    c->have_ctl_child_id ? "c" : "nc", c->ctl_child_id,
	    c->io_want, c->io_ready,
	    c->isatty ? "T" : (c->remote_has_tty ? "RT" : ""),
	    c->bulk ? "B" : "I");
	પાછા ret;
}

/*
 * Returns a message describing the currently open forwarded connections,
 * suitable for sending to the client.  The message contains crlf pairs for
 * newlines.
 */
અક્ષર *
channel_open_message(સંરચના ssh *ssh)
{
	સંરચના sshbuf *buf;
	Channel *c;
	u_int i;
	પૂર્ણાંક r;
	અક્ષર *cp, *ret;

	જો ((buf = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new");
	જો ((r = sshbuf_putf(buf,
	    "The following connections are open:\r\n")) != 0)
		fatal_fr(r, "sshbuf_putf");
	માટે (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		જો (c == ખાલી)
			ચાલુ;
		પસંદગી (c->type) {
		સ્થિતિ SSH_CHANNEL_X11_LISTENER:
		સ્થિતિ SSH_CHANNEL_PORT_LISTENER:
		સ્થિતિ SSH_CHANNEL_RPORT_LISTENER:
		સ્થિતિ SSH_CHANNEL_CLOSED:
		સ્થિતિ SSH_CHANNEL_AUTH_SOCKET:
		સ્થિતિ SSH_CHANNEL_ZOMBIE:
		સ્થિતિ SSH_CHANNEL_ABANDONED:
		સ્થિતિ SSH_CHANNEL_MUX_LISTENER:
		સ્થિતિ SSH_CHANNEL_UNIX_LISTENER:
		સ્થિતિ SSH_CHANNEL_RUNIX_LISTENER:
			ચાલુ;
		સ્થિતિ SSH_CHANNEL_LARVAL:
		સ્થિતિ SSH_CHANNEL_OPENING:
		સ્થિતિ SSH_CHANNEL_CONNECTING:
		સ્થિતિ SSH_CHANNEL_DYNAMIC:
		સ્થિતિ SSH_CHANNEL_RDYNAMIC_OPEN:
		સ્થિતિ SSH_CHANNEL_RDYNAMIC_FINISH:
		સ્થિતિ SSH_CHANNEL_OPEN:
		સ્થિતિ SSH_CHANNEL_X11_OPEN:
		સ્થિતિ SSH_CHANNEL_MUX_PROXY:
		સ્થિતિ SSH_CHANNEL_MUX_CLIENT:
			cp = channel_format_status(c);
			જો ((r = sshbuf_putf(buf, "  #%d %.300s (%s)\r\n",
			    c->self, c->remote_name, cp)) != 0) {
				મુક્ત(cp);
				fatal_fr(r, "sshbuf_putf");
			}
			મુક્ત(cp);
			ચાલુ;
		મૂળભૂત:
			fatal_f("bad channel type %d", c->type);
			/* NOTREACHED */
		}
	}
	જો ((ret = sshbuf_dup_string(buf)) == ખાલી)
		fatal_f("sshbuf_dup_string");
	sshbuf_free(buf);
	પાછા ret;
}

શૂન્ય
channel_report_open(સંરચના ssh *ssh, પૂર્ણાંક level)
{
	અક્ષર *open, *oopen, *cp, ident[256];

	sshpkt_fmt_connection_id(ssh, ident, કદ(ident));
	do_log2(level, "Connection: %s (pid %ld)", ident, (long)getpid());
	open = oopen = channel_open_message(ssh);
	જ્યારે ((cp = strsep(&open, "\r\n")) != ખાલી) {
		જો (*cp != '\0')
			do_log2(level, "%s", cp);
	}
	મુક્ત(oopen);
}

સ્થિર શૂન્ય
open_preamble(સંરચના ssh *ssh, અચલ અક્ષર *where, Channel *c, અચલ અક્ષર *type)
{
	પૂર્ણાંક r;

	જો ((r = sshpkt_start(ssh, SSH2_સંદેશ_CHANNEL_OPEN)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, type)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_window)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0) {
		fatal_r(r, "%s: channel %i: open", where, c->self);
	}
}

શૂન્ય
channel_send_open(સંરચના ssh *ssh, પૂર્ણાંક id)
{
	Channel *c = channel_lookup(ssh, id);
	પૂર્ણાંક r;

	જો (c == ખાલી) {
		logit("channel_send_open: %d: bad id", id);
		પાછા;
	}
	debug2("channel %d: send open", id);
	open_preamble(ssh, __func__, c, c->ctype);
	જો ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i", c->self);
}

શૂન્ય
channel_request_start(સંરચના ssh *ssh, પૂર્ણાંક id, અચલ અક્ષર *service,
    પૂર્ણાંક wantconfirm)
{
	Channel *c = channel_lookup(ssh, id);
	પૂર્ણાંક r;

	જો (c == ખાલી) {
		logit_f("%d: unknown channel id", id);
		પાછા;
	}
	જો (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);

	debug2("channel %d: request %s confirm %d", id, service, wantconfirm);
	જો ((r = sshpkt_start(ssh, SSH2_સંદેશ_CHANNEL_REQUEST)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, service)) != 0 ||
	    (r = sshpkt_put_u8(ssh, wantconfirm)) != 0) {
		fatal_fr(r, "channel %i", c->self);
	}
}

શૂન્ય
channel_register_status_confirm(સંરચના ssh *ssh, પૂર્ણાંક id,
    channel_confirm_cb *cb, channel_confirm_abandon_cb *abandon_cb, શૂન્ય *ctx)
{
	સંરચના channel_confirm *cc;
	Channel *c;

	જો ((c = channel_lookup(ssh, id)) == ખાલી)
		fatal_f("%d: bad id", id);

	cc = xcalloc(1, કદ(*cc));
	cc->cb = cb;
	cc->abandon_cb = abandon_cb;
	cc->ctx = ctx;
	TAILQ_INSERT_TAIL(&c->status_confirms, cc, entry);
}

શૂન્ય
channel_register_open_confirm(સંરચના ssh *ssh, પૂર્ણાંક id,
    channel_open_fn *fn, શૂન્ય *ctx)
{
	Channel *c = channel_lookup(ssh, id);

	જો (c == ખાલી) {
		logit_f("%d: bad id", id);
		પાછા;
	}
	c->open_confirm = fn;
	c->open_confirm_ctx = ctx;
}

શૂન્ય
channel_register_cleanup(સંરચના ssh *ssh, પૂર્ણાંક id,
    channel_callback_fn *fn, પૂર્ણાંક do_close)
{
	Channel *c = channel_by_id(ssh, id);

	જો (c == ખાલી) {
		logit_f("%d: bad id", id);
		પાછા;
	}
	c->detach_user = fn;
	c->detach_close = do_close;
}

શૂન્ય
channel_cancel_cleanup(સંરચના ssh *ssh, પૂર્ણાંક id)
{
	Channel *c = channel_by_id(ssh, id);

	જો (c == ખાલી) {
		logit_f("%d: bad id", id);
		પાછા;
	}
	c->detach_user = ખાલી;
	c->detach_close = 0;
}

શૂન્ય
channel_register_filter(સંરચના ssh *ssh, પૂર્ણાંક id, channel_infilter_fn *ifn,
    channel_outfilter_fn *ofn, channel_filter_cleanup_fn *cfn, શૂન્ય *ctx)
{
	Channel *c = channel_lookup(ssh, id);

	જો (c == ખાલી) {
		logit_f("%d: bad id", id);
		પાછા;
	}
	c->આગત_filter = ifn;
	c->output_filter = ofn;
	c->filter_ctx = ctx;
	c->filter_cleanup = cfn;
}

શૂન્ય
channel_set_fds(સંરચના ssh *ssh, પૂર્ણાંક id, પૂર્ણાંક rfd, પૂર્ણાંક wfd, પૂર્ણાંક efd,
    પૂર્ણાંક extusage, પૂર્ણાંક nonblock, પૂર્ણાંક is_tty, u_int window_max)
{
	Channel *c = channel_lookup(ssh, id);
	પૂર્ણાંક r;

	જો (c == ખાલી || c->type != SSH_CHANNEL_LARVAL)
		fatal("channel_activate for non-larval channel %d.", id);
	જો (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);

	channel_register_fds(ssh, c, rfd, wfd, efd, extusage, nonblock, is_tty);
	c->type = SSH_CHANNEL_OPEN;
	channel_set_used_time(ssh, c);
	c->local_window = c->local_window_max = window_max;

	જો ((r = sshpkt_start(ssh, SSH2_સંદેશ_CHANNEL_WINDOW_ADJUST)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_window)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i", c->self);
}

સ્થિર શૂન્ય
channel_pre_listener(સંરચના ssh *ssh, Channel *c)
{
	c->io_want = SSH_CHAN_IO_SOCK_R;
}

સ્થિર શૂન્ય
channel_pre_connecting(સંરચના ssh *ssh, Channel *c)
{
	debug3("channel %d: waiting for connection", c->self);
	c->io_want = SSH_CHAN_IO_SOCK_W;
}

સ્થિર શૂન્ય
channel_pre_open(સંરચના ssh *ssh, Channel *c)
{
	c->io_want = 0;
	જો (c->istate == CHAN_આગત_OPEN &&
	    c->remote_window > 0 &&
	    sshbuf_len(c->આગત) < c->remote_window &&
	    sshbuf_check_reserve(c->આગત, CHAN_RBUF) == 0)
		c->io_want |= SSH_CHAN_IO_RFD;
	જો (c->ostate == CHAN_OUTPUT_OPEN ||
	    c->ostate == CHAN_OUTPUT_WAIT_DRAIN) {
		જો (sshbuf_len(c->output) > 0) {
			c->io_want |= SSH_CHAN_IO_WFD;
		} નહીંતર જો (c->ostate == CHAN_OUTPUT_WAIT_DRAIN) {
			જો (CHANNEL_EFD_OUTPUT_ACTIVE(c))
				debug2("channel %d: "
				    "obuf_empty delayed efd %d/(%zu)", c->self,
				    c->efd, sshbuf_len(c->extended));
			નહીંતર
				chan_obuf_empty(ssh, c);
		}
	}
	/** XXX check close conditions, too */
	જો (c->efd != -1 && !(c->istate == CHAN_આગત_CLOSED &&
	    c->ostate == CHAN_OUTPUT_CLOSED)) {
		જો (c->extended_usage == CHAN_EXTENDED_WRITE &&
		    sshbuf_len(c->extended) > 0)
			c->io_want |= SSH_CHAN_IO_EFD_W;
		નહીંતર જો (c->efd != -1 && !(c->flags & CHAN_EOF_SENT) &&
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
સ્થિર પૂર્ણાંક
x11_open_helper(સંરચના ssh *ssh, સંરચના sshbuf *b)
{
	સંરચના ssh_channels *sc = ssh->chanctxt;
	u_char *ucp;
	u_int proto_len, data_len;

	જો (sc->x11_saved_proto == ખાલી) {
		error("X11 forwarding opened before X11 forwarding requested");
		પાછા -1;
	}

	/* Is this being called after the refusal deadline? */
	જો (sc->x11_refuse_time != 0.0 &&
	    monotime_double() >= sc->x11_refuse_time) {
		verbose("Rejected X11 connection after ForwardX11Timeout "
		    "expired");
		પાછા -1;
	}

	/* Check if the fixed size part of the packet is in buffer. */
	જો (sshbuf_len(b) < 12)
		પાછા 0;

	/* Parse the lengths of variable-length fields. */
	ucp = sshbuf_mutable_ptr(b);
	જો (ucp[0] == 0x42) {	/* Byte order MSB first. */
		proto_len = 256 * ucp[6] + ucp[7];
		data_len = 256 * ucp[8] + ucp[9];
	} નહીંતર જો (ucp[0] == 0x6c) {	/* Byte order LSB first. */
		proto_len = ucp[6] + 256 * ucp[7];
		data_len = ucp[8] + 256 * ucp[9];
	} નહીંતર {
		debug2("Initial X11 packet contains bad byte order byte: 0x%x",
		    ucp[0]);
		પાછા -1;
	}

	/* Check if the whole packet is in buffer. */
	જો (sshbuf_len(b) <
	    12 + ((proto_len + 3) & ~3) + ((data_len + 3) & ~3))
		પાછા 0;

	/* Check if authentication protocol matches. */
	જો (proto_len != strlen(sc->x11_saved_proto) ||
	    memcmp(ucp + 12, sc->x11_saved_proto, proto_len) != 0) {
		debug2("X11 connection uses different authentication protocol.");
		પાછા -1;
	}
	/* Check if authentication data matches our fake data. */
	જો (data_len != sc->x11_fake_data_len ||
	    timingsafe_bcmp(ucp + 12 + ((proto_len + 3) & ~3),
		sc->x11_fake_data, sc->x11_fake_data_len) != 0) {
		debug2("X11 auth data does not match fake data.");
		પાછા -1;
	}
	/* Check fake data length */
	જો (sc->x11_fake_data_len != sc->x11_saved_data_len) {
		error("X11 fake_data_len %d != saved_data_len %d",
		    sc->x11_fake_data_len, sc->x11_saved_data_len);
		પાછા -1;
	}
	/*
	 * Received authentication protocol and data match
	 * our fake data. Substitute the fake data with real
	 * data.
	 */
	memcpy(ucp + 12 + ((proto_len + 3) & ~3),
	    sc->x11_saved_data, sc->x11_saved_data_len);
	પાછા 1;
}

શૂન્ય
channel_force_close(સંરચના ssh *ssh, Channel *c, પૂર્ણાંક abandon)
{
	debug3_f("channel %d: forcibly closing", c->self);
	જો (c->istate == CHAN_આગત_OPEN)
		chan_read_failed(ssh, c);
	જો (c->istate == CHAN_આગત_WAIT_DRAIN) {
		sshbuf_reset(c->આગત);
		chan_ibuf_empty(ssh, c);
	}
	જો (c->ostate == CHAN_OUTPUT_OPEN ||
	    c->ostate == CHAN_OUTPUT_WAIT_DRAIN) {
		sshbuf_reset(c->output);
		chan_write_failed(ssh, c);
	}
	જો (c->detach_user)
		c->detach_user(ssh, c->self, 1, ખાલી);
	જો (c->efd != -1)
		channel_close_fd(ssh, c, &c->efd);
	જો (abandon)
		c->type = SSH_CHANNEL_ABANDONED;
	/* exempt from inactivity timeouts */
	c->inactive_deadline = 0;
	c->lastused = 0;
}

સ્થિર શૂન્ય
channel_pre_x11_open(સંરચના ssh *ssh, Channel *c)
{
	પૂર્ણાંક ret = x11_open_helper(ssh, c->output);

	/* c->force_drain = 1; */

	જો (ret == 1) {
		c->type = SSH_CHANNEL_OPEN;
		channel_set_used_time(ssh, c);
		channel_pre_open(ssh, c);
	} નહીંતર જો (ret == -1) {
		logit("X11 connection rejected because of wrong "
		    "authentication.");
		debug2("X11 rejected %d i%d/o%d",
		    c->self, c->istate, c->ostate);
		channel_force_close(ssh, c, 0);
	}
}

સ્થિર શૂન્ય
channel_pre_mux_client(સંરચના ssh *ssh, Channel *c)
{
	c->io_want = 0;
	જો (c->istate == CHAN_આગત_OPEN && !c->mux_pause &&
	    sshbuf_check_reserve(c->આગત, CHAN_RBUF) == 0)
		c->io_want |= SSH_CHAN_IO_RFD;
	જો (c->istate == CHAN_આગત_WAIT_DRAIN) {
		/* clear buffer immediately (discard any partial packet) */
		sshbuf_reset(c->આગત);
		chan_ibuf_empty(ssh, c);
		/* Start output drain. XXX just kill chan? */
		chan_rcvd_oclose(ssh, c);
	}
	જો (c->ostate == CHAN_OUTPUT_OPEN ||
	    c->ostate == CHAN_OUTPUT_WAIT_DRAIN) {
		જો (sshbuf_len(c->output) > 0)
			c->io_want |= SSH_CHAN_IO_WFD;
		નહીંતર જો (c->ostate == CHAN_OUTPUT_WAIT_DRAIN)
			chan_obuf_empty(ssh, c);
	}
}

સ્થિર અંતઃરેખ પૂર્ણાંક
socks_decode_error(Channel *c, પૂર્ણાંક status, અચલ અક્ષર *func, અચલ અક્ષર *સંદેશ)
{
	જો (status == SSH_ERR_MESSAGE_INCOMPLETE)
		પાછા 0;
	નહીંતર {
		debug_r(status, "%s: channel %d: decode %s",
		    func, c->self, સંદેશ);
		પાછા -1;
	}
}

/* try to decode a socks4 header */
સ્થિર પૂર્ણાંક
channel_decode_socks4(Channel *c, સંરચના sshbuf *આગત, સંરચના sshbuf *output)
{
	uint8_t socks_ver, socks_cmd, dest_addr[4];
	uint16_t dest_port;
	અક્ષર *user = ખાલી, *host = ખાલી;
	પૂર્ણાંક success = -1, socks4a = 0, r;
	સંરચના sshbuf *b = ખાલી;

	જો (sshbuf_len(આગત) < 9)
		પાછા 0;

	/* We may not have a complete message, so work on a dup of the buffer */
	જો ((b = sshbuf_fromb(આગત)) == ખાલી)
		fatal_f("sshbuf_fromb failed");

	debug2("channel %d: decode socks4", c->self);
	જો ((r = sshbuf_get_u8(b, &socks_ver)) != 0 ||
	    (r = sshbuf_get_u8(b, &socks_cmd)) != 0 ||
	    (r = sshbuf_get_u16(b, &dest_port)) != 0 ||
	    (r = sshbuf_get(b, &dest_addr, કદ(dest_addr))) != 0 ||
	    (r = sshbuf_get_nulterminated_string(b, 1024, &user, ખાલી)) != 0) {
		success = socks_decode_error(c, r, __func__, "header");
		જાઓ out;
	}

	/* Is this a SOCKS4A request? (indicated by an address of 0.0.0.x) */
	જો (dest_addr[0] == 0 && dest_addr[1] == 0 &&
	    dest_addr[2] == 0 && dest_addr[3] != 0) {
		/* If so, then the hostname follows, also nul-terminated */
		જો ((r = sshbuf_get_nulterminated_string(b, 1024,
		    &host, ખાલી)) != 0) {
			success = socks_decode_error(c, r, __func__, "host");
			જાઓ out;
		}
		socks4a = 1;
	} નહીંતર {
		/* Plain SOCKS4 passes an IPv4 binary address; reconstruct */
		xasprintf(&host, "%d.%d.%d.%d",
		    dest_addr[0], dest_addr[1], dest_addr[2], dest_addr[3]);
	}

	/* We have a complete SOCKS4 message; consume it from input */
	જો ((r = sshbuf_consume_upto_child(આગત, b)) != 0)
		fatal_fr(r, "channel %d: consume", c->self);

	/* Handle the request */
	debug2("channel %d: %s: user=\"%s\" command=%d destination=[%s]:%d",
	    c->self, socks4a ? "SOCKS4A" : "SOCKS4", user, (પૂર્ણાંક)socks_cmd,
	    host, dest_port);
	જો (socks_cmd != 1) {
		debug("channel %d: cannot handle %s command 0x%02x",
		    c->self, socks4a ? "SOCKS4A" : "SOCKS4", socks_cmd);
		જાઓ out;
	}
	મુક્ત(c->path);
	c->path = host;
	host = ખાલી; /* transferred */
	c->host_port = dest_port;

	/* Reply to the SOCKS4 client */
	જો ((r = sshbuf_put_u8(output, 0)) != 0 ||	/* vn: 0 for reply */
	    (r = sshbuf_put_u8(output, 90)) != 0 ||	/* cd: req granted */
	    (r = sshbuf_put_u16(output, 0)) != 0 ||	/* port: ignored */
	    (r = sshbuf_put_u32(output, ntohl(INADDR_ANY))) != 0) /* ignored */
		fatal_fr(r, "channel %d: compose reply", c->self);

	/* success */
	success = 1;
 out:
	sshbuf_free(b);
	મુક્ત(user);
	મુક્ત(host);
	પાછા success;
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
સ્થિર પૂર્ણાંક
channel_socks5_check_auth(Channel *c, સંરચના sshbuf *b, સંરચના sshbuf *આગત,
    સંરચના sshbuf *output)
{
	uint8_t socks_ver;
	uint8_t nmethods, method;
	પૂર્ણાંક r;
	u_int i, found;

	/* format: ver | nmethods | methods */
	જો ((r = sshbuf_get_u8(b, &socks_ver)) != 0)
		પાછા socks_decode_error(c, r, __func__, "version");
	જો (socks_ver != 5) /* shouldn't happen; checked by caller^2 */
		fatal_fr(r, "channel %d: internal error: not socks5", c->self);
	જો ((r = sshbuf_get_u8(b, &nmethods)) != 0)
		પાછા socks_decode_error(c, r, __func__, "methods");
	માટે (found = i = 0; i < nmethods; i++) {
		જો ((r = sshbuf_get_u8(b, &method)) != 0)
			પાછા socks_decode_error(c, r, __func__, "method");
		જો (method == SSH_SOCKS5_NOAUTH)
			found = 1;
	}
	જો (!found) {
		debug("channel %d: didn't request SSH_SOCKS5_NOAUTH", c->self);
		પાછા -1;
	}
	/* Consume completed request */
	જો ((r = sshbuf_consume_upto_child(આગત, b)) != 0)
		fatal_fr(r, "channel %d: consume", c->self);

	/* Compose reply: version, method */
	જો ((r = sshbuf_put_u8(output, 0x05)) != 0 ||
	    (r = sshbuf_put_u8(output, SSH_SOCKS5_NOAUTH)) != 0)
		fatal_fr(r, "channel %d: append reply", c->self);
	/* success */
	debug2("channel %d: socks5 auth done", c->self);
	પાછા 1;
}

સ્થિર પૂર્ણાંક
channel_decode_socks5(Channel *c, સંરચના sshbuf *આગત, સંરચના sshbuf *output)
{
	uint8_t socks_ver, socks_cmd, socks_reserved, socks_atyp, addrlen;
	uint16_t dest_port;
	અક્ષર dest_addr[255+1], ntop[INET6_ADDRSTRLEN];
	u_int af;
	પૂર્ણાંક r, success = -1;;
	સંરચના sshbuf *b = ખાલી;

	debug2("channel %d: decode socks5 %s", c->self,
	    (c->flags & SSH_SOCKS5_AUTHDONE) ? "request" : "auth");

	/* We may not have a complete message, so work on a dup of the buffer */
	જો ((b = sshbuf_fromb(આગત)) == ખાલી)
		fatal_f("sshbuf_fromb failed");

	જો (!(c->flags & SSH_SOCKS5_AUTHDONE)) {
		જો ((r = channel_socks5_check_auth(c, b, આગત, output)) != 1) {
			success = r;
			જાઓ out;
		}
		c->flags |= SSH_SOCKS5_AUTHDONE;
		/* Continue to parse request in case client speculated ahead */
	}

	/* Request messages (auth or connect) always start with the version */
	જો ((r = sshbuf_get_u8(b, &socks_ver)) != 0) {
		success = socks_decode_error(c, r, __func__, "version");
		જાઓ out;
	}
	જો (socks_ver != 5) /* shouldn't happen */
		fatal_fr(r, "channel %d: internal error: not socks5", c->self);

	/* Parse SOCKS5 request header */
	debug2("channel %d: socks5 post auth", c->self);
	જો ((r = sshbuf_get_u8(b, &socks_cmd)) != 0 ||
	    (r = sshbuf_get_u8(b, &socks_reserved)) != 0 ||
	    (r = sshbuf_get_u8(b, &socks_atyp)) != 0) {
		success = socks_decode_error(c, r, __func__, "request header");
		જાઓ out;
	}

	જો (socks_ver != 0x05 ||
	    socks_cmd != SSH_SOCKS5_CONNECT ||
	    socks_reserved != 0x00) {
		debug2("channel %d: only socks5 connect supported", c->self);
		જાઓ out;
	}

	પસંદગી (socks_atyp) {
	સ્થિતિ SSH_SOCKS5_IPV4:
		addrlen = 4;
		af = AF_INET;
		તોડો;
	સ્થિતિ SSH_SOCKS5_DOMAIN:
		જો ((r = sshbuf_get_u8(b, &addrlen)) != 0) {
			success = socks_decode_error(c, r, __func__, "addrlen");
			જાઓ out;
		}
		af = -1;
		તોડો;
	સ્થિતિ SSH_SOCKS5_IPV6:
		addrlen = 16;
		af = AF_INET6;
		તોડો;
	મૂળભૂત:
		debug2("channel %d: bad socks5 atyp %d", c->self, socks_atyp);
		જાઓ out;
	}
	જો ((r = sshbuf_get(b, &dest_addr, addrlen)) != 0 ||
	    (r = sshbuf_get_u16(b, &dest_port)) != 0) {
		success = socks_decode_error(c, r, __func__, "addr/port");
		જાઓ out;
	}
	dest_addr[addrlen] = '\0';

	/* We have a complete SOCKS5 request; consume it from input */
	જો ((r = sshbuf_consume_upto_child(આગત, b)) != 0)
		fatal_fr(r, "channel %d: consume", c->self);

	મુક્ત(c->path);
	c->path = ખાલી;
	જો (socks_atyp == SSH_SOCKS5_DOMAIN)
		c->path = xstrdup(dest_addr);
	નહીંતર {
		જો (inet_ntop(af, dest_addr, ntop, કદ(ntop)) == ખાલી)
			પાછા -1;
		c->path = xstrdup(ntop);
	}
	c->host_port = dest_port;

	debug2("channel %d: dynamic request: socks5 host %s port %u command %u",
	    c->self, c->path, c->host_port, socks_cmd);

	/* Reply */
	જો ((r = sshbuf_put_u8(output, 0x05)) != 0 ||	/* version */
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
	પાછા success;
}

Channel *
channel_connect_stdio_fwd(સંરચના ssh *ssh,
    અચલ અક્ષર *host_to_connect, પૂર્ણાંક port_to_connect,
    પૂર્ણાંક in, પૂર્ણાંક out, પૂર્ણાંક nonblock)
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

	પાછા c;
}

/* dynamic port forwarding */
સ્થિર શૂન્ય
channel_pre_dynamic(સંરચના ssh *ssh, Channel *c)
{
	u_int have;
	u_char ver;
	પૂર્ણાંક r, ret;

	c->io_want = 0;
	have = sshbuf_len(c->આગત);
	debug2("channel %d: pre_dynamic: have %d", c->self, have);
	/* sshbuf_dump(c->input, stderr); */
	/* check if the fixed size part of the packet is in buffer. */
	જો (have < 3) {
		/* need more */
		c->io_want |= SSH_CHAN_IO_RFD;
		પાછા;
	}
	/* try to guess the protocol */
	જો ((r = sshbuf_peek_u8(c->આગત, 0, &ver)) != 0)
		fatal_fr(r, "sshbuf_peek_u8");
	પસંદગી (ver) {
	સ્થિતિ 0x04:
		ret = channel_decode_socks4(c, c->આગત, c->output);
		તોડો;
	સ્થિતિ 0x05:
		ret = channel_decode_socks5(c, c->આગત, c->output);
		તોડો;
	મૂળભૂત:
		debug2_f("channel %d: unknown SOCKS version %u", c->self, ver);
		ret = -1;
		તોડો;
	}
	જો (ret < 0) {
		chan_mark_dead(ssh, c);
	} નહીંતર જો (ret == 0) {
		debug2("channel %d: pre_dynamic: need more", c->self);
		/* need more */
		c->io_want |= SSH_CHAN_IO_RFD;
		જો (sshbuf_len(c->output))
			c->io_want |= SSH_CHAN_IO_WFD;
	} નહીંતર {
		/* switch to the next state */
		c->type = SSH_CHANNEL_OPENING;
		port_open_helper(ssh, c, "direct-tcpip");
	}
}

/* simulate read-error */
સ્થિર શૂન્ય
rdynamic_close(સંરચના ssh *ssh, Channel *c)
{
	c->type = SSH_CHANNEL_OPEN;
	channel_force_close(ssh, c, 0);
}

/* reverse dynamic port forwarding */
સ્થિર શૂન્ય
channel_before_prepare_io_rdynamic(સંરચના ssh *ssh, Channel *c)
{
	અચલ u_char *p;
	u_int have, len;
	પૂર્ણાંક r, ret;

	have = sshbuf_len(c->output);
	debug2("channel %d: pre_rdynamic: have %d", c->self, have);
	/* sshbuf_dump(c->output, stderr); */
	/* EOF received */
	જો (c->flags & CHAN_EOF_RCVD) {
		જો ((r = sshbuf_consume(c->output, have)) != 0)
			fatal_fr(r, "channel %d: consume", c->self);
		rdynamic_close(ssh, c);
		પાછા;
	}
	/* check if the fixed size part of the packet is in buffer. */
	જો (have < 3)
		પાછા;
	/* try to guess the protocol */
	p = sshbuf_ptr(c->output);
	પસંદગી (p[0]) {
	સ્થિતિ 0x04:
		/* switch input/output for reverse forwarding */
		ret = channel_decode_socks4(c, c->output, c->આગત);
		તોડો;
	સ્થિતિ 0x05:
		ret = channel_decode_socks5(c, c->output, c->આગત);
		તોડો;
	મૂળભૂત:
		ret = -1;
		તોડો;
	}
	જો (ret < 0) {
		rdynamic_close(ssh, c);
	} નહીંતર જો (ret == 0) {
		debug2("channel %d: pre_rdynamic: need more", c->self);
		/* send socks request to peer */
		len = sshbuf_len(c->આગત);
		જો (len > 0 && len < c->remote_window) {
			જો ((r = sshpkt_start(ssh, SSH2_સંદેશ_CHANNEL_DATA)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
			    (r = sshpkt_put_stringb(ssh, c->આગત)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0) {
				fatal_fr(r, "channel %i: rdynamic", c->self);
			}
			જો ((r = sshbuf_consume(c->આગત, len)) != 0)
				fatal_fr(r, "channel %d: consume", c->self);
			c->remote_window -= len;
		}
	} નહીંતર જો (rdynamic_connect_finish(ssh, c) < 0) {
		/* the connect failed */
		rdynamic_close(ssh, c);
	}
}

/* This is our fake X11 server socket. */
સ્થિર શૂન્ય
channel_post_x11_listener(સંરચના ssh *ssh, Channel *c)
{
	Channel *nc;
	સંરચના sockaddr_storage addr;
	પૂર્ણાંક r, newsock, oerrno, remote_port;
	socklen_t addrlen;
	અક્ષર buf[16384], *remote_ipaddr;

	જો ((c->io_ready & SSH_CHAN_IO_SOCK_R) == 0)
		પાછા;

	debug("X11 connection requested.");
	addrlen = કદ(addr);
	newsock = accept(c->sock, (સંરચના sockaddr *)&addr, &addrlen);
	જો (c->single_connection) {
		oerrno = errno;
		debug2("single_connection: closing X11 listener.");
		channel_close_fd(ssh, c, &c->sock);
		chan_mark_dead(ssh, c);
		errno = oerrno;
	}
	જો (newsock == -1) {
		જો (errno != EINTR && errno != EWOULDBLOCK &&
		    errno != ECONNABORTED)
			error("accept: %.100s", strerror(errno));
		જો (errno == EMFILE || errno == ENFILE)
			c->notbefore = monotime_double() + 1.0;
		પાછા;
	}
	set_nodelay(newsock);
	જો (ssh->chanctxt->want_tcp_keepalive)
		set_keepalive(newsock); /* logs errors */
	remote_ipaddr = get_peer_ipaddr(newsock);
	remote_port = get_peer_port(newsock);
	snprintf(buf, કદ buf, "X11 connection from %.200s port %d",
	    remote_ipaddr, remote_port);

	nc = channel_new(ssh, "x11-connection",
	    SSH_CHANNEL_OPENING, newsock, newsock, -1,
	    c->local_window_max, c->local_maxpacket, 0, buf, 1);
	open_preamble(ssh, __func__, nc, "x11");
	જો ((r = sshpkt_put_cstring(ssh, remote_ipaddr)) != 0 ||
	    (r = sshpkt_put_u32(ssh, remote_port)) != 0) {
		fatal_fr(r, "channel %i: reply", c->self);
	}
	જો ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i: send", c->self);
	મુક્ત(remote_ipaddr);
}

સ્થિર શૂન્ય
port_open_helper(સંરચના ssh *ssh, Channel *c, અક્ષર *rtype)
{
	અક્ષર *local_ipaddr = get_local_ipaddr(c->sock);
	પૂર્ણાંક local_port = c->sock == -1 ? 65536 : get_local_port(c->sock);
	અક્ષર *remote_ipaddr = get_peer_ipaddr(c->sock);
	પૂર્ણાંક remote_port = get_peer_port(c->sock);
	પૂર્ણાંક r;

	જો (remote_port == -1) {
		/* Fake addr/port to appease peers that validate it (Tectia) */
		મુક્ત(remote_ipaddr);
		remote_ipaddr = xstrdup("127.0.0.1");
		remote_port = 65535;
	}

	મુક્ત(c->remote_name);
	xasprintf(&c->remote_name,
	    "%s: listening port %d for %.100s port %d, "
	    "connect from %.200s port %d to %.100s port %d",
	    rtype, c->listening_port, c->path, c->host_port,
	    remote_ipaddr, remote_port, local_ipaddr, local_port);

	open_preamble(ssh, __func__, c, rtype);
	જો (strcmp(rtype, "direct-tcpip") == 0) {
		/* target host, port */
		જો ((r = sshpkt_put_cstring(ssh, c->path)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->host_port)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	} નહીંતર જો (strcmp(rtype, "direct-streamlocal@openssh.com") == 0) {
		/* target path */
		જો ((r = sshpkt_put_cstring(ssh, c->path)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	} નહીંતર જો (strcmp(rtype, "forwarded-streamlocal@openssh.com") == 0) {
		/* listen path */
		જો ((r = sshpkt_put_cstring(ssh, c->path)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	} નહીંતર {
		/* listen address, port */
		જો ((r = sshpkt_put_cstring(ssh, c->path)) != 0 ||
		    (r = sshpkt_put_u32(ssh, local_port)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	}
	જો (strcmp(rtype, "forwarded-streamlocal@openssh.com") == 0) {
		/* reserved for future owner/mode info */
		જો ((r = sshpkt_put_cstring(ssh, "")) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	} નહીંતર {
		/* originator host and port */
		જો ((r = sshpkt_put_cstring(ssh, remote_ipaddr)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)remote_port)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	}
	જો ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i: send", c->self);
	મુક્ત(remote_ipaddr);
	મુક્ત(local_ipaddr);
}

શૂન્ય
channel_set_x11_refuse_time(સંરચના ssh *ssh, દ્વિગુણ refuse_time)
{
	ssh->chanctxt->x11_refuse_time = refuse_time;
}

/*
 * This socket is listening for connections to a forwarded TCP/IP port.
 */
સ્થિર શૂન્ય
channel_post_port_listener(સંરચના ssh *ssh, Channel *c)
{
	Channel *nc;
	સંરચના sockaddr_storage addr;
	પૂર્ણાંક newsock, nextstate;
	socklen_t addrlen;
	અક્ષર *rtype;

	જો ((c->io_ready & SSH_CHAN_IO_SOCK_R) == 0)
		પાછા;

	debug("Connection to port %d forwarding to %.100s port %d requested.",
	    c->listening_port, c->path, c->host_port);

	જો (c->type == SSH_CHANNEL_RPORT_LISTENER) {
		nextstate = SSH_CHANNEL_OPENING;
		rtype = "forwarded-tcpip";
	} નહીંતર જો (c->type == SSH_CHANNEL_RUNIX_LISTENER) {
		nextstate = SSH_CHANNEL_OPENING;
		rtype = "forwarded-streamlocal@openssh.com";
	} નહીંતર જો (c->host_port == PORT_STREAMLOCAL) {
		nextstate = SSH_CHANNEL_OPENING;
		rtype = "direct-streamlocal@openssh.com";
	} નહીંતર જો (c->host_port == 0) {
		nextstate = SSH_CHANNEL_DYNAMIC;
		rtype = "dynamic-tcpip";
	} નહીંતર {
		nextstate = SSH_CHANNEL_OPENING;
		rtype = "direct-tcpip";
	}

	addrlen = કદ(addr);
	newsock = accept(c->sock, (સંરચના sockaddr *)&addr, &addrlen);
	જો (newsock == -1) {
		જો (errno != EINTR && errno != EWOULDBLOCK &&
		    errno != ECONNABORTED)
			error("accept: %.100s", strerror(errno));
		જો (errno == EMFILE || errno == ENFILE)
			c->notbefore = monotime_double() + 1.0;
		પાછા;
	}
	જો (addr.ss_family == AF_INET || addr.ss_family == AF_INET6) {
		set_nodelay(newsock);
		જો (ssh->chanctxt->want_tcp_keepalive)
			set_keepalive(newsock); /* logs errors */
	}
	nc = channel_new(ssh, rtype, nextstate, newsock, newsock, -1,
	    c->local_window_max, c->local_maxpacket, 0, rtype, 1);
	nc->listening_port = c->listening_port;
	nc->host_port = c->host_port;
	જો (c->path != ખાલી)
		nc->path = xstrdup(c->path);

	જો (nextstate != SSH_CHANNEL_DYNAMIC)
		port_open_helper(ssh, nc, rtype);
}

/*
 * This is the authentication agent socket listening for connections from
 * clients.
 */
સ્થિર શૂન્ય
channel_post_auth_listener(સંરચના ssh *ssh, Channel *c)
{
	Channel *nc;
	પૂર્ણાંક r, newsock;
	સંરચના sockaddr_storage addr;
	socklen_t addrlen;

	જો ((c->io_ready & SSH_CHAN_IO_SOCK_R) == 0)
		પાછા;

	addrlen = કદ(addr);
	newsock = accept(c->sock, (સંરચના sockaddr *)&addr, &addrlen);
	જો (newsock == -1) {
		error("accept from auth socket: %.100s", strerror(errno));
		જો (errno == EMFILE || errno == ENFILE)
			c->notbefore = monotime_double() + 1.0;
		પાછા;
	}
	nc = channel_new(ssh, "agent-connection",
	    SSH_CHANNEL_OPENING, newsock, newsock, -1,
	    c->local_window_max, c->local_maxpacket,
	    0, "accepted auth socket", 1);
	open_preamble(ssh, __func__, nc,
	    c->agent_new ? "agent-connect" : "auth-agent@openssh.com");
	જો ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i", c->self);
}

સ્થિર શૂન્ય
channel_post_connecting(સંરચના ssh *ssh, Channel *c)
{
	પૂર્ણાંક err = 0, sock, isopen, r;
	socklen_t sz = કદ(err);

	જો ((c->io_ready & SSH_CHAN_IO_SOCK_W) == 0)
		પાછા;
	જો (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);
	જો (c->connect_ctx == ખાલી)
		fatal_f("channel %d: context missing", c->self);

	/* for rdynamic the OPEN_CONFIRMATION has been sent already */
	isopen = (c->type == SSH_CHANNEL_RDYNAMIC_FINISH);

	જો (getsockopt(c->sock, SOL_SOCKET, SO_ERROR, &err, &sz) == -1) {
		err = errno;
		error("getsockopt SO_ERROR failed");
	}

	જો (err == 0) {
		/* Non-blocking connection completed */
		debug("channel %d: connected to %s port %d",
		    c->self, c->connect_ctx->host, c->connect_ctx->port);
		channel_free_connect_ctx(c);
		c->type = SSH_CHANNEL_OPEN;
		channel_set_used_time(ssh, c);
		જો (isopen) {
			/* no message necessary */
		} નહીંતર {
			જો ((r = sshpkt_start(ssh,
			    SSH2_સંદેશ_CHANNEL_OPEN_CONFIRMATION)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_window)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "channel %i open confirm", c->self);
		}
		પાછા;
	}
	જો (err == EINTR || err == EAGAIN || err == EINPROGRESS)
		પાછા;

	/* Non-blocking connection failed */
	debug("channel %d: connection failed: %s", c->self, strerror(err));

	/* Try next address, if any */
	જો ((sock = connect_next(ssh, c->connect_ctx)) == -1) {
		/* Exhausted all addresses for this destination */
		error("connect_to %.100s port %d: failed.",
		    c->connect_ctx->host, c->connect_ctx->port);
		channel_free_connect_ctx(c);
		જો (isopen) {
			rdynamic_close(ssh, c);
		} નહીંતર {
			જો ((r = sshpkt_start(ssh,
			    SSH2_સંદેશ_CHANNEL_OPEN_FAILURE)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
			    (r = sshpkt_put_u32(ssh,
			    SSH2_OPEN_CONNECT_FAILED)) != 0 ||
			    (r = sshpkt_put_cstring(ssh, strerror(err))) != 0 ||
			    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "channel %i: failure", c->self);
			chan_mark_dead(ssh, c);
		}
	}

	/* New non-blocking connection in progress */
	close(c->sock);
	c->sock = c->rfd = c->wfd = sock;
}

સ્થિર પૂર્ણાંક
channel_handle_rfd(સંરચના ssh *ssh, Channel *c)
{
	અક્ષર buf[CHAN_RBUF];
	ssize_t len;
	પૂર્ણાંક r, force;
	size_t nr = 0, have, avail, maxlen = CHANNEL_MAX_READ;
	પૂર્ણાંક pty_zeroread = 0;

#ifdef PTY_ZEROREAD
	/* Bug on AIX: read(1) can return 0 for a non-closed fd */
	pty_zeroread = c->isatty;
#endif

	force = c->isatty && c->detach_close && c->istate != CHAN_આગત_CLOSED;

	જો (!force && (c->io_ready & SSH_CHAN_IO_RFD) == 0)
		પાછા 1;
	જો ((avail = sshbuf_avail(c->આગત)) == 0)
		પાછા 1; /* Shouldn't happen */

	/*
	 * For "simple" channels (i.e. not datagram or filtered), we can
	 * read directly to the channel buffer.
	 */
	જો (!pty_zeroread && c->આગત_filter == ખાલી && !c->datagram) {
		/* Only OPEN channels have valid rwin */
		જો (c->type == SSH_CHANNEL_OPEN) {
			જો ((have = sshbuf_len(c->આગત)) >= c->remote_window)
				પાછા 1; /* shouldn't happen */
			જો (maxlen > c->remote_window - have)
				maxlen = c->remote_window - have;
		}
		જો (maxlen > avail)
			maxlen = avail;
		જો ((r = sshbuf_read(c->rfd, c->આગત, maxlen, &nr)) != 0) {
			જો (errno == EINTR || (!force &&
			    (errno == EAGAIN || errno == EWOULDBLOCK)))
				પાછા 1;
			debug2("channel %d: read failed rfd %d maxlen %zu: %s",
			    c->self, c->rfd, maxlen, ssh_err(r));
			જાઓ rfail;
		}
		જો (nr != 0)
			channel_set_used_time(ssh, c);
		પાછા 1;
	}

	errno = 0;
	len = પઠ(c->rfd, buf, કદ(buf));
	/* fixup AIX zero-length read with errno set to look more like errors */
	જો (pty_zeroread && len == 0 && errno != 0)
		len = -1;
	જો (len == -1 && (errno == EINTR ||
	    ((errno == EAGAIN || errno == EWOULDBLOCK) && !force)))
		પાછા 1;
	જો (len < 0 || (!pty_zeroread && len == 0)) {
		debug2("channel %d: read<=0 rfd %d len %zd: %s",
		    c->self, c->rfd, len,
		    len == 0 ? "closed" : strerror(errno));
 rfail:
		જો (c->type != SSH_CHANNEL_OPEN) {
			debug2("channel %d: not open", c->self);
			chan_mark_dead(ssh, c);
			પાછા -1;
		} નહીંતર {
			chan_read_failed(ssh, c);
		}
		પાછા -1;
	}
	channel_set_used_time(ssh, c);
	જો (c->આગત_filter != ખાલી) {
		જો (c->આગત_filter(ssh, c, buf, len) == -1) {
			debug2("channel %d: filter stops", c->self);
			chan_read_failed(ssh, c);
		}
	} નહીંતર જો (c->datagram) {
		જો ((r = sshbuf_put_string(c->આગત, buf, len)) != 0)
			fatal_fr(r, "channel %i: put datagram", c->self);
	} નહીંતર જો ((r = sshbuf_put(c->આગત, buf, len)) != 0)
		fatal_fr(r, "channel %i: put data", c->self);

	પાછા 1;
}

સ્થિર પૂર્ણાંક
channel_handle_wfd(સંરચના ssh *ssh, Channel *c)
{
	સંરચના termios tio;
	u_char *data = ખાલી, *buf; /* XXX const; need filter API change */
	size_t dlen, olen = 0;
	પૂર્ણાંક r, len;

	જો ((c->io_ready & SSH_CHAN_IO_WFD) == 0)
		પાછા 1;
	જો (sshbuf_len(c->output) == 0)
		પાછા 1;

	/* Send buffered output data to the socket. */
	olen = sshbuf_len(c->output);
	જો (c->output_filter != ખાલી) {
		જો ((buf = c->output_filter(ssh, c, &data, &dlen)) == ખાલી) {
			debug2("channel %d: filter stops", c->self);
			જો (c->type != SSH_CHANNEL_OPEN)
				chan_mark_dead(ssh, c);
			નહીંતર
				chan_write_failed(ssh, c);
			પાછા -1;
		}
	} નહીંતર જો (c->datagram) {
		જો ((r = sshbuf_get_string(c->output, &data, &dlen)) != 0)
			fatal_fr(r, "channel %i: get datagram", c->self);
		buf = data;
	} નહીંતર {
		buf = data = sshbuf_mutable_ptr(c->output);
		dlen = sshbuf_len(c->output);
	}

	જો (c->datagram) {
		/* ignore truncated writes, datagrams might get lost */
		len = લિખ(c->wfd, buf, dlen);
		મુક્ત(data);
		જો (len == -1 && (errno == EINTR || errno == EAGAIN ||
		    errno == EWOULDBLOCK))
			પાછા 1;
		જો (len <= 0)
			જાઓ write_fail;
		જાઓ out;
	}

#ifdef _AIX
	/* XXX: Later AIX versions can't push as much data to tty */
	જો (c->wfd_isatty)
		dlen = MINIMUM(dlen, 8*1024);
#endif

	len = લિખ(c->wfd, buf, dlen);
	જો (len == -1 &&
	    (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
		પાછા 1;
	જો (len <= 0) {
 write_fail:
		જો (c->type != SSH_CHANNEL_OPEN) {
			debug2("channel %d: not open", c->self);
			chan_mark_dead(ssh, c);
			પાછા -1;
		} નહીંતર {
			chan_write_failed(ssh, c);
		}
		પાછા -1;
	}
	channel_set_used_time(ssh, c);
#ifndef BROKEN_TCGETATTR_ICANON
	જો (c->isatty && dlen >= 1 && buf[0] != '\r') {
		જો (tcgetattr(c->wfd, &tio) == 0 &&
		    !(tio.c_lflag & ECHO) && (tio.c_lflag & ICANON)) {
			/*
			 * Simulate echo to reduce the impact of
			 * traffic analysis. We need to match the
			 * size of a SSH2_MSG_CHANNEL_DATA message
			 * (4 byte channel id + buf)
			 */
			જો ((r = sshpkt_સંદેશ_ignore(ssh, 4+len)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "channel %i: ignore", c->self);
		}
	}
#endif /* BROKEN_TCGETATTR_ICANON */
	જો ((r = sshbuf_consume(c->output, len)) != 0)
		fatal_fr(r, "channel %i: consume", c->self);
 out:
	c->local_consumed += olen - sshbuf_len(c->output);

	પાછા 1;
}

સ્થિર પૂર્ણાંક
channel_handle_efd_write(સંરચના ssh *ssh, Channel *c)
{
	પૂર્ણાંક r;
	ssize_t len;

	જો ((c->io_ready & SSH_CHAN_IO_EFD_W) == 0)
		પાછા 1;
	જો (sshbuf_len(c->extended) == 0)
		પાછા 1;

	len = લિખ(c->efd, sshbuf_ptr(c->extended),
	    sshbuf_len(c->extended));
	debug2("channel %d: written %zd to efd %d", c->self, len, c->efd);
	જો (len == -1 && (errno == EINTR || errno == EAGAIN ||
	    errno == EWOULDBLOCK))
		પાછા 1;
	જો (len <= 0) {
		debug2("channel %d: closing write-efd %d", c->self, c->efd);
		channel_close_fd(ssh, c, &c->efd);
	} નહીંતર {
		જો ((r = sshbuf_consume(c->extended, len)) != 0)
			fatal_fr(r, "channel %i: consume", c->self);
		c->local_consumed += len;
		channel_set_used_time(ssh, c);
	}
	પાછા 1;
}

સ્થિર પૂર્ણાંક
channel_handle_efd_read(સંરચના ssh *ssh, Channel *c)
{
	અક્ષર buf[CHAN_RBUF];
	ssize_t len;
	પૂર્ણાંક r, force;

	force = c->isatty && c->detach_close && c->istate != CHAN_આગત_CLOSED;

	જો (!force && (c->io_ready & SSH_CHAN_IO_EFD_R) == 0)
		પાછા 1;

	len = પઠ(c->efd, buf, કદ(buf));
	debug2("channel %d: read %zd from efd %d", c->self, len, c->efd);
	જો (len == -1 && (errno == EINTR || ((errno == EAGAIN ||
	    errno == EWOULDBLOCK) && !force)))
		પાછા 1;
	જો (len <= 0) {
		debug2("channel %d: closing read-efd %d", c->self, c->efd);
		channel_close_fd(ssh, c, &c->efd);
		પાછા 1;
	}
	channel_set_used_time(ssh, c);
	જો (c->extended_usage == CHAN_EXTENDED_IGNORE)
		debug3("channel %d: discard efd", c->self);
	નહીંતર જો ((r = sshbuf_put(c->extended, buf, len)) != 0)
		fatal_fr(r, "channel %i: append", c->self);
	પાછા 1;
}

સ્થિર પૂર્ણાંક
channel_handle_efd(સંરચના ssh *ssh, Channel *c)
{
	જો (c->efd == -1)
		પાછા 1;

	/** XXX handle drain efd, too */

	જો (c->extended_usage == CHAN_EXTENDED_WRITE)
		પાછા channel_handle_efd_write(ssh, c);
	નહીંતર જો (c->extended_usage == CHAN_EXTENDED_READ ||
	    c->extended_usage == CHAN_EXTENDED_IGNORE)
		પાછા channel_handle_efd_read(ssh, c);

	પાછા 1;
}

સ્થિર પૂર્ણાંક
channel_check_window(સંરચના ssh *ssh, Channel *c)
{
	પૂર્ણાંક r;

	જો (c->type == SSH_CHANNEL_OPEN &&
	    !(c->flags & (CHAN_CLOSE_SENT|CHAN_CLOSE_RCVD)) &&
	    ((c->local_window_max - c->local_window >
	    c->local_maxpacket*3) ||
	    c->local_window < c->local_window_max/2) &&
	    c->local_consumed > 0) {
		જો (!c->have_remote_id)
			fatal_f("channel %d: no remote id", c->self);
		જો ((r = sshpkt_start(ssh,
		    SSH2_સંદેશ_CHANNEL_WINDOW_ADJUST)) != 0 ||
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
	પાછા 1;
}

સ્થિર શૂન્ય
channel_post_open(સંરચના ssh *ssh, Channel *c)
{
	channel_handle_rfd(ssh, c);
	channel_handle_wfd(ssh, c);
	channel_handle_efd(ssh, c);
	channel_check_window(ssh, c);
}

સ્થિર u_int
read_mux(સંરચના ssh *ssh, Channel *c, u_int need)
{
	અક્ષર buf[CHAN_RBUF];
	ssize_t len;
	u_int rlen;
	પૂર્ણાંક r;

	જો (sshbuf_len(c->આગત) < need) {
		rlen = need - sshbuf_len(c->આગત);
		len = પઠ(c->rfd, buf, MINIMUM(rlen, CHAN_RBUF));
		જો (len == -1 && (errno == EINTR || errno == EAGAIN))
			પાછા sshbuf_len(c->આગત);
		જો (len <= 0) {
			debug2("channel %d: ctl read<=0 rfd %d len %zd",
			    c->self, c->rfd, len);
			chan_read_failed(ssh, c);
			પાછા 0;
		} નહીંતર જો ((r = sshbuf_put(c->આગત, buf, len)) != 0)
			fatal_fr(r, "channel %i: append", c->self);
	}
	પાછા sshbuf_len(c->આગત);
}

સ્થિર શૂન્ય
channel_post_mux_client_read(સંરચના ssh *ssh, Channel *c)
{
	u_int need;

	જો ((c->io_ready & SSH_CHAN_IO_RFD) == 0)
		પાછા;
	જો (c->istate != CHAN_આગત_OPEN && c->istate != CHAN_આગત_WAIT_DRAIN)
		પાછા;
	જો (c->mux_pause)
		પાછા;

	/*
	 * Don't not read past the precise end of packets to
	 * avoid disrupting fd passing.
	 */
	જો (read_mux(ssh, c, 4) < 4) /* read header */
		પાછા;
	/* XXX sshbuf_peek_u32 */
	need = PEEK_U32(sshbuf_ptr(c->આગત));
#define CHANNEL_MUX_MAX_PACKET	(256 * 1024)
	જો (need > CHANNEL_MUX_MAX_PACKET) {
		debug2("channel %d: packet too big %u > %u",
		    c->self, CHANNEL_MUX_MAX_PACKET, need);
		chan_rcvd_oclose(ssh, c);
		પાછા;
	}
	જો (read_mux(ssh, c, need + 4) < need + 4) /* read body */
		પાછા;
	જો (c->mux_rcb(ssh, c) != 0) {
		debug("channel %d: mux_rcb failed", c->self);
		chan_mark_dead(ssh, c);
		પાછા;
	}
}

સ્થિર શૂન્ય
channel_post_mux_client_write(સંરચના ssh *ssh, Channel *c)
{
	ssize_t len;
	પૂર્ણાંક r;

	જો ((c->io_ready & SSH_CHAN_IO_WFD) == 0)
		પાછા;
	જો (sshbuf_len(c->output) == 0)
		પાછા;

	len = લિખ(c->wfd, sshbuf_ptr(c->output), sshbuf_len(c->output));
	જો (len == -1 && (errno == EINTR || errno == EAGAIN))
		પાછા;
	જો (len <= 0) {
		chan_mark_dead(ssh, c);
		પાછા;
	}
	જો ((r = sshbuf_consume(c->output, len)) != 0)
		fatal_fr(r, "channel %i: consume", c->self);
}

સ્થિર શૂન્ય
channel_post_mux_client(સંરચના ssh *ssh, Channel *c)
{
	channel_post_mux_client_read(ssh, c);
	channel_post_mux_client_write(ssh, c);
}

સ્થિર શૂન્ય
channel_post_mux_listener(સંરચના ssh *ssh, Channel *c)
{
	Channel *nc;
	સંરચના sockaddr_storage addr;
	socklen_t addrlen;
	પૂર્ણાંક newsock;
	uid_t euid;
	gid_t egid;

	જો ((c->io_ready & SSH_CHAN_IO_SOCK_R) == 0)
		પાછા;

	debug("multiplexing control connection");

	/*
	 * Accept connection on control socket
	 */
	memset(&addr, 0, કદ(addr));
	addrlen = કદ(addr);
	જો ((newsock = accept(c->sock, (સંરચના sockaddr*)&addr,
	    &addrlen)) == -1) {
		error_f("accept: %s", strerror(errno));
		જો (errno == EMFILE || errno == ENFILE)
			c->notbefore = monotime_double() + 1.0;
		પાછા;
	}

	જો (getpeereid(newsock, &euid, &egid) == -1) {
		error_f("getpeereid failed: %s", strerror(errno));
		close(newsock);
		પાછા;
	}
	જો ((euid != 0) && (getuid() != euid)) {
		error("multiplex uid mismatch: peer euid %u != uid %u",
		    (u_int)euid, (u_int)getuid());
		close(newsock);
		પાછા;
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

સ્થિર શૂન્ય
channel_handler_init(સંરચના ssh_channels *sc)
{
	chan_fn **pre, **post;

	જો ((pre = calloc(SSH_CHANNEL_MAX_TYPE, કદ(*pre))) == ખાલી ||
	    (post = calloc(SSH_CHANNEL_MAX_TYPE, કદ(*post))) == ખાલી)
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
સ્થિર શૂન્ય
channel_garbage_collect(સંરચના ssh *ssh, Channel *c)
{
	જો (c == ખાલી)
		પાછા;
	જો (c->detach_user != ખાલી) {
		જો (!chan_is_dead(ssh, c, c->detach_close))
			પાછા;

		debug2("channel %d: gc: notify user", c->self);
		c->detach_user(ssh, c->self, 0, ખાલી);
		/* if we still have a callback */
		જો (c->detach_user != ખાલી)
			પાછા;
		debug2("channel %d: gc: user detached", c->self);
	}
	જો (!chan_is_dead(ssh, c, 1))
		પાછા;
	debug2("channel %d: garbage collecting", c->self);
	channel_free(ssh, c);
}

ગણના channel_table { CHAN_PRE, CHAN_POST };

સ્થિર શૂન્ય
channel_handler(સંરચના ssh *ssh, પૂર્ણાંક table, સંરચના timespec *timeout)
{
	સંરચના ssh_channels *sc = ssh->chanctxt;
	chan_fn **ftab = table == CHAN_PRE ? sc->channel_pre : sc->channel_post;
	u_int i, oalloc;
	Channel *c;
	દ્વિગુણ now;

	now = monotime_double();
	માટે (sc->nbulk = i = 0, oalloc = sc->channels_alloc; i < oalloc; i++) {
		c = sc->channels[i];
		જો (c == ખાલી)
			ચાલુ;
		/* Count open channels in bulk state */
		જો (c->type == SSH_CHANNEL_OPEN && c->bulk)
			sc->nbulk++;
		/* Try to keep IO going while rekeying */
		જો (ssh_packet_is_rekeying(ssh) && c->type != SSH_CHANNEL_OPEN)
			ચાલુ;
		જો (c->delayed) {
			જો (table == CHAN_PRE)
				c->delayed = 0;
			નહીંતર
				ચાલુ;
		}
		જો (ftab[c->type] != ખાલી) {
			જો (table == CHAN_PRE && c->type == SSH_CHANNEL_OPEN &&
			    channel_get_expiry(ssh, c) != 0 &&
			    now >= channel_get_expiry(ssh, c)) {
				/* channel closed for inactivity */
				દ્વિગુણ deadline = c->inactive_deadline != 0.0 ?
				    c->inactive_deadline : sc->global_deadline;
				verbose("channel %d: closing after %f seconds "
				    "of inactivity", c->self, deadline);
				channel_force_close(ssh, c, 1);
			} નહીંતર જો (c->notbefore <= now) {
				/* Run handlers that are not paused. */
				(*ftab[c->type])(ssh, c);
				/* inactivity timeouts must interrupt poll() */
				જો (timeout != ખાલી &&
				    c->type == SSH_CHANNEL_OPEN &&
				    channel_get_expiry(ssh, c) != 0) {
					ptimeout_deadline_monotime_double(timeout,
					    channel_get_expiry(ssh, c));
				}
			} નહીંતર જો (timeout != ખાલી) {
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
સ્થિર શૂન્ય
channel_before_prepare_io(સંરચના ssh *ssh)
{
	સંરચના ssh_channels *sc = ssh->chanctxt;
	Channel *c;
	u_int i, oalloc;

	માટે (i = 0, oalloc = sc->channels_alloc; i < oalloc; i++) {
		c = sc->channels[i];
		જો (c == ખાલી)
			ચાલુ;
		જો (c->type == SSH_CHANNEL_RDYNAMIC_OPEN)
			channel_before_prepare_io_rdynamic(ssh, c);
	}
}

સ્થિર શૂન્ય
dump_channel_poll(અચલ અક્ષર *func, અચલ અક્ષર *what, Channel *c,
    u_int pollfd_offset, સંરચના pollfd *pfd)
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
સ્થિર શૂન્ય
channel_prepare_pollfd(Channel *c, u_int *next_pollfd,
    સંરચના pollfd *pfd, u_int npfd)
{
	u_int ev, p = *next_pollfd;

	જો (c == ખાલી)
		પાછા;
	જો (p + 4 > npfd) {
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
	જો (c->rfd != -1) {
		ev = 0;
		જો ((c->io_want & SSH_CHAN_IO_RFD) != 0)
			ev |= POLLIN;
		/* rfd == wfd */
		જો (c->wfd == c->rfd) {
			જો ((c->io_want & SSH_CHAN_IO_WFD) != 0)
				ev |= POLLOUT;
		}
		/* rfd == efd */
		જો (c->efd == c->rfd) {
			જો ((c->io_want & SSH_CHAN_IO_EFD_R) != 0)
				ev |= POLLIN;
			જો ((c->io_want & SSH_CHAN_IO_EFD_W) != 0)
				ev |= POLLOUT;
		}
		/* rfd == sock */
		જો (c->sock == c->rfd) {
			જો ((c->io_want & SSH_CHAN_IO_SOCK_R) != 0)
				ev |= POLLIN;
			જો ((c->io_want & SSH_CHAN_IO_SOCK_W) != 0)
				ev |= POLLOUT;
		}
		/* Pack a pfd entry if any event armed for this fd */
		જો (ev != 0) {
			c->pfds[0] = p;
			pfd[p].fd = c->rfd;
			pfd[p].events = ev;
			dump_channel_poll(__func__, "rfd", c, p, &pfd[p]);
			p++;
		}
	}
	/* prepare c->wfd if wanting IO and not already handled above */
	જો (c->wfd != -1 && c->rfd != c->wfd) {
		ev = 0;
		જો ((c->io_want & SSH_CHAN_IO_WFD))
			ev |= POLLOUT;
		/* Pack a pfd entry if any event armed for this fd */
		જો (ev != 0) {
			c->pfds[1] = p;
			pfd[p].fd = c->wfd;
			pfd[p].events = ev;
			dump_channel_poll(__func__, "wfd", c, p, &pfd[p]);
			p++;
		}
	}
	/* prepare c->efd if wanting IO and not already handled above */
	જો (c->efd != -1 && c->rfd != c->efd) {
		ev = 0;
		જો ((c->io_want & SSH_CHAN_IO_EFD_R) != 0)
			ev |= POLLIN;
		જો ((c->io_want & SSH_CHAN_IO_EFD_W) != 0)
			ev |= POLLOUT;
		/* Pack a pfd entry if any event armed for this fd */
		જો (ev != 0) {
			c->pfds[2] = p;
			pfd[p].fd = c->efd;
			pfd[p].events = ev;
			dump_channel_poll(__func__, "efd", c, p, &pfd[p]);
			p++;
		}
	}
	/* prepare c->sock if wanting IO and not already handled above */
	જો (c->sock != -1 && c->rfd != c->sock) {
		ev = 0;
		જો ((c->io_want & SSH_CHAN_IO_SOCK_R) != 0)
			ev |= POLLIN;
		જો ((c->io_want & SSH_CHAN_IO_SOCK_W) != 0)
			ev |= POLLOUT;
		/* Pack a pfd entry if any event armed for this fd */
		જો (ev != 0) {
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
શૂન્ય
channel_prepare_poll(સંરચના ssh *ssh, સંરચના pollfd **pfdp, u_int *npfd_allocp,
    u_int *npfd_activep, u_int npfd_reserved, સંરચના timespec *timeout)
{
	સંરચના ssh_channels *sc = ssh->chanctxt;
	u_int i, oalloc, p, npfd = npfd_reserved;

	channel_before_prepare_io(ssh); /* might create a new channel */
	/* clear out I/O flags from last poll */
	માટે (i = 0; i < sc->channels_alloc; i++) {
		જો (sc->channels[i] == ખાલી)
			ચાલુ;
		sc->channels[i]->io_want = sc->channels[i]->io_ready = 0;
	}
	/* Allocate 4x pollfd for each channel (rfd, wfd, efd, sock) */
	જો (sc->channels_alloc >= (INT_MAX / 4) - npfd_reserved)
		fatal_f("too many channels"); /* shouldn't happen */
	npfd += sc->channels_alloc * 4;
	જો (npfd > *npfd_allocp) {
		*pfdp = xrecallocarray(*pfdp, *npfd_allocp,
		    npfd, કદ(**pfdp));
		*npfd_allocp = npfd;
	}
	*npfd_activep = npfd_reserved;
	oalloc = sc->channels_alloc;

	channel_handler(ssh, CHAN_PRE, timeout);

	જો (oalloc != sc->channels_alloc) {
		/* shouldn't happen */
		fatal_f("channels_alloc changed during CHAN_PRE "
		    "(was %u, now %u)", oalloc, sc->channels_alloc);
	}

	/* Prepare pollfd */
	p = npfd_reserved;
	માટે (i = 0; i < sc->channels_alloc; i++)
		channel_prepare_pollfd(sc->channels[i], &p, *pfdp, npfd);
	*npfd_activep = p;
}

સ્થિર શૂન્ય
fd_ready(Channel *c, પૂર્ણાંક p, સંરચના pollfd *pfds, u_int npfd, પૂર્ણાંક fd,
    અચલ અક્ષર *what, u_int revents_mask, u_int ready)
{
	સંરચના pollfd *pfd = &pfds[p];

	જો (fd == -1)
		પાછા;
	જો (p == -1 || (u_int)p >= npfd)
		fatal_f("channel %d: bad pfd %d (max %u)", c->self, p, npfd);
	dump_channel_poll(__func__, what, c, p, pfd);
	જો (pfd->fd != fd) {
		fatal("channel %d: inconsistent %s fd=%d pollfd[%u].fd %d "
		    "r%d w%d e%d s%d", c->self, what, fd, p, pfd->fd,
		    c->rfd, c->wfd, c->efd, c->sock);
	}
	જો ((pfd->revents & POLLNVAL) != 0) {
		fatal("channel %d: invalid %s pollfd[%u].fd %d r%d w%d e%d s%d",
		    c->self, what, p, pfd->fd, c->rfd, c->wfd, c->efd, c->sock);
	}
	જો ((pfd->revents & (revents_mask|POLLHUP|POLLERR)) != 0)
		c->io_ready |= ready & c->io_want;
}

/*
 * After poll, perform any appropriate operations for channels which have
 * events pending.
 */
શૂન્ય
channel_after_poll(સંરચના ssh *ssh, સંરચના pollfd *pfd, u_int npfd)
{
	સંરચના ssh_channels *sc = ssh->chanctxt;
	u_int i;
	પૂર્ણાંક p;
	Channel *c;

#ifdef DEBUG_CHANNEL_POLL
	માટે (p = 0; p < (પૂર્ણાંક)npfd; p++) {
		જો (pfd[p].revents == 0)
			ચાલુ;
		debug_f("pfd[%u].fd %d rev 0x%04x",
		    p, pfd[p].fd, pfd[p].revents);
	}
#endif

	/* Convert pollfd into c->io_ready */
	માટે (i = 0; i < sc->channels_alloc; i++) {
		c = sc->channels[i];
		જો (c == ખાલી)
			ચાલુ;
		/* if rfd is shared with efd/sock then wfd should be too */
		જો (c->rfd != -1 && c->wfd != -1 && c->rfd != c->wfd &&
		    (c->rfd == c->efd || c->rfd == c->sock)) {
			/* Shouldn't happen */
			fatal_f("channel %d: unexpected fds r%d w%d e%d s%d",
			    c->self, c->rfd, c->wfd, c->efd, c->sock);
		}
		c->io_ready = 0;
		/* rfd, potentially shared with wfd, efd and sock */
		જો (c->rfd != -1 && (p = c->pfds[0]) != -1) {
			fd_ready(c, p, pfd, npfd, c->rfd,
			    "rfd", POLLIN, SSH_CHAN_IO_RFD);
			જો (c->rfd == c->wfd) {
				fd_ready(c, p, pfd, npfd, c->wfd,
				    "wfd/r", POLLOUT, SSH_CHAN_IO_WFD);
			}
			જો (c->rfd == c->efd) {
				fd_ready(c, p, pfd, npfd, c->efd,
				    "efdr/r", POLLIN, SSH_CHAN_IO_EFD_R);
				fd_ready(c, p, pfd, npfd, c->efd,
				    "efdw/r", POLLOUT, SSH_CHAN_IO_EFD_W);
			}
			જો (c->rfd == c->sock) {
				fd_ready(c, p, pfd, npfd, c->sock,
				    "sockr/r", POLLIN, SSH_CHAN_IO_SOCK_R);
				fd_ready(c, p, pfd, npfd, c->sock,
				    "sockw/r", POLLOUT, SSH_CHAN_IO_SOCK_W);
			}
			dump_channel_poll(__func__, "rfd", c, p, pfd);
		}
		/* wfd */
		જો (c->wfd != -1 && c->wfd != c->rfd &&
		    (p = c->pfds[1]) != -1) {
			fd_ready(c, p, pfd, npfd, c->wfd,
			    "wfd", POLLOUT, SSH_CHAN_IO_WFD);
			dump_channel_poll(__func__, "wfd", c, p, pfd);
		}
		/* efd */
		જો (c->efd != -1 && c->efd != c->rfd &&
		    (p = c->pfds[2]) != -1) {
			fd_ready(c, p, pfd, npfd, c->efd,
			    "efdr", POLLIN, SSH_CHAN_IO_EFD_R);
			fd_ready(c, p, pfd, npfd, c->efd,
			    "efdw", POLLOUT, SSH_CHAN_IO_EFD_W);
			dump_channel_poll(__func__, "efd", c, p, pfd);
		}
		/* sock */
		જો (c->sock != -1 && c->sock != c->rfd &&
		    (p = c->pfds[3]) != -1) {
			fd_ready(c, p, pfd, npfd, c->sock,
			    "sockr", POLLIN, SSH_CHAN_IO_SOCK_R);
			fd_ready(c, p, pfd, npfd, c->sock,
			    "sockw", POLLOUT, SSH_CHAN_IO_SOCK_W);
			dump_channel_poll(__func__, "sock", c, p, pfd);
		}
	}
	channel_handler(ssh, CHAN_POST, ખાલી);
}

/*
 * Enqueue data for channels with open or draining c->input.
 * Returns non-zero if a packet was enqueued.
 */
સ્થિર પૂર્ણાંક
channel_output_poll_આગત_open(સંરચના ssh *ssh, Channel *c)
{
	size_t len, plen;
	અચલ u_char *pkt;
	પૂર્ણાંક r;

	જો ((len = sshbuf_len(c->આગત)) == 0) {
		જો (c->istate == CHAN_આગત_WAIT_DRAIN) {
			/*
			 * input-buffer is empty and read-socket shutdown:
			 * tell peer, that we will not send more data:
			 * send IEOF.
			 * hack for extended data: delay EOF if EFD still
			 * in use.
			 */
			જો (CHANNEL_EFD_આગત_ACTIVE(c))
				debug2("channel %d: "
				    "ibuf_empty delayed efd %d/(%zu)",
				    c->self, c->efd, sshbuf_len(c->extended));
			નહીંતર
				chan_ibuf_empty(ssh, c);
		}
		પાછા 0;
	}

	જો (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);

	જો (c->datagram) {
		/* Check datagram will fit; drop if not */
		જો ((r = sshbuf_get_string_direct(c->આગત, &pkt, &plen)) != 0)
			fatal_fr(r, "channel %i: get datagram", c->self);
		/*
		 * XXX this does tail-drop on the datagram queue which is
		 * usually suboptimal compared to head-drop. Better to have
		 * backpressure at read time? (i.e. read + discard)
		 */
		જો (plen > c->remote_window || plen > c->remote_maxpacket) {
			debug("channel %d: datagram too big", c->self);
			પાછા 0;
		}
		/* Enqueue it */
		જો ((r = sshpkt_start(ssh, SSH2_સંદેશ_CHANNEL_DATA)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
		    (r = sshpkt_put_string(ssh, pkt, plen)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "channel %i: send datagram", c->self);
		c->remote_window -= plen;
		પાછા 1;
	}

	/* Enqueue packet for buffered data. */
	જો (len > c->remote_window)
		len = c->remote_window;
	જો (len > c->remote_maxpacket)
		len = c->remote_maxpacket;
	જો (len == 0)
		પાછા 0;
	જો ((r = sshpkt_start(ssh, SSH2_સંદેશ_CHANNEL_DATA)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_string(ssh, sshbuf_ptr(c->આગત), len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i: send data", c->self);
	જો ((r = sshbuf_consume(c->આગત, len)) != 0)
		fatal_fr(r, "channel %i: consume", c->self);
	c->remote_window -= len;
	પાછા 1;
}

/*
 * Enqueue data for channels with open c->extended in read mode.
 * Returns non-zero if a packet was enqueued.
 */
સ્થિર પૂર્ણાંક
channel_output_poll_extended_read(સંરચના ssh *ssh, Channel *c)
{
	size_t len;
	પૂર્ણાંક r;

	જો ((len = sshbuf_len(c->extended)) == 0)
		પાછા 0;

	debug2("channel %d: rwin %u elen %zu euse %d", c->self,
	    c->remote_window, sshbuf_len(c->extended), c->extended_usage);
	જો (len > c->remote_window)
		len = c->remote_window;
	જો (len > c->remote_maxpacket)
		len = c->remote_maxpacket;
	જો (len == 0)
		પાછા 0;
	જો (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);
	જો ((r = sshpkt_start(ssh, SSH2_સંદેશ_CHANNEL_EXTENDED_DATA)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_u32(ssh, SSH2_EXTENDED_DATA_STDERR)) != 0 ||
	    (r = sshpkt_put_string(ssh, sshbuf_ptr(c->extended), len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i: data", c->self);
	જો ((r = sshbuf_consume(c->extended, len)) != 0)
		fatal_fr(r, "channel %i: consume", c->self);
	c->remote_window -= len;
	debug2("channel %d: sent ext data %zu", c->self, len);
	પાછા 1;
}

/*
 * If there is data to send to the connection, enqueue some of it now.
 * Returns non-zero if data was enqueued.
 */
પૂર્ણાંક
channel_output_poll(સંરચના ssh *ssh)
{
	સંરચના ssh_channels *sc = ssh->chanctxt;
	Channel *c;
	u_int i;
	પૂર્ણાંક ret = 0;

	માટે (i = 0; i < sc->channels_alloc; i++) {
		c = sc->channels[i];
		જો (c == ખાલી)
			ચાલુ;

		/*
		 * We are only interested in channels that can have buffered
		 * incoming data.
		 */
		જો (c->type != SSH_CHANNEL_OPEN)
			ચાલુ;
		જો ((c->flags & (CHAN_CLOSE_SENT|CHAN_CLOSE_RCVD))) {
			/* XXX is this true? */
			debug3("channel %d: will not send data after close",
			    c->self);
			ચાલુ;
		}

		/* Get the amount of buffered data for this channel. */
		જો (c->istate == CHAN_આગત_OPEN ||
		    c->istate == CHAN_આગત_WAIT_DRAIN)
			ret |= channel_output_poll_આગત_open(ssh, c);
		/* Send extended data, i.e. stderr */
		જો (!(c->flags & CHAN_EOF_SENT) &&
		    c->extended_usage == CHAN_EXTENDED_READ)
			ret |= channel_output_poll_extended_read(ssh, c);
	}
	પાછા ret;
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
પૂર્ણાંક
channel_proxy_downstream(સંરચના ssh *ssh, Channel *downstream)
{
	Channel *c = ખાલી;
	સંરચના sshbuf *original = ખાલી, *modified = ખાલી;
	અચલ u_char *cp;
	અક્ષર *ctype = ખાલી, *listen_host = ખાલી;
	u_char type;
	size_t have;
	પૂર્ણાંક ret = -1, r;
	u_int id, remote_id, listen_port;

	/* sshbuf_dump(downstream->input, stderr); */
	જો ((r = sshbuf_get_string_direct(downstream->આગત, &cp, &have))
	    != 0) {
		error_fr(r, "parse");
		પાછા -1;
	}
	જો (have < 2) {
		error_f("short message");
		પાછા -1;
	}
	type = cp[1];
	/* skip padlen + type */
	cp += 2;
	have -= 2;
	જો (ssh_packet_log_type(type))
		debug3_f("channel %u: down->up: type %u",
		    downstream->self, type);

	પસંદગી (type) {
	સ્થિતિ SSH2_સંદેશ_CHANNEL_OPEN:
		જો ((original = sshbuf_from(cp, have)) == ખાલી ||
		    (modified = sshbuf_new()) == ખાલી) {
			error_f("alloc");
			જાઓ out;
		}
		જો ((r = sshbuf_get_cstring(original, &ctype, ખાલી)) != 0 ||
		    (r = sshbuf_get_u32(original, &id)) != 0) {
			error_fr(r, "parse");
			જાઓ out;
		}
		c = channel_new(ssh, "mux-proxy", SSH_CHANNEL_MUX_PROXY,
		    -1, -1, -1, 0, 0, 0, ctype, 1);
		c->mux_ctx = downstream;	/* point to mux client */
		c->mux_downstream_id = id;	/* original downstream id */
		જો ((r = sshbuf_put_cstring(modified, ctype)) != 0 ||
		    (r = sshbuf_put_u32(modified, c->self)) != 0 ||
		    (r = sshbuf_putb(modified, original)) != 0) {
			error_fr(r, "compose");
			channel_free(ssh, c);
			જાઓ out;
		}
		તોડો;
	સ્થિતિ SSH2_સંદેશ_CHANNEL_OPEN_CONFIRMATION:
		/*
		 * Almost the same as SSH2_MSG_CHANNEL_OPEN, except then we
		 * need to parse 'remote_id' instead of 'ctype'.
		 */
		જો ((original = sshbuf_from(cp, have)) == ખાલી ||
		    (modified = sshbuf_new()) == ખાલી) {
			error_f("alloc");
			જાઓ out;
		}
		જો ((r = sshbuf_get_u32(original, &remote_id)) != 0 ||
		    (r = sshbuf_get_u32(original, &id)) != 0) {
			error_fr(r, "parse");
			જાઓ out;
		}
		c = channel_new(ssh, "mux-proxy", SSH_CHANNEL_MUX_PROXY,
		    -1, -1, -1, 0, 0, 0, "mux-down-connect", 1);
		c->mux_ctx = downstream;	/* point to mux client */
		c->mux_downstream_id = id;
		c->remote_id = remote_id;
		c->have_remote_id = 1;
		જો ((r = sshbuf_put_u32(modified, remote_id)) != 0 ||
		    (r = sshbuf_put_u32(modified, c->self)) != 0 ||
		    (r = sshbuf_putb(modified, original)) != 0) {
			error_fr(r, "compose");
			channel_free(ssh, c);
			જાઓ out;
		}
		તોડો;
	સ્થિતિ SSH2_સંદેશ_GLOBAL_REQUEST:
		જો ((original = sshbuf_from(cp, have)) == ખાલી) {
			error_f("alloc");
			જાઓ out;
		}
		જો ((r = sshbuf_get_cstring(original, &ctype, ખાલી)) != 0) {
			error_fr(r, "parse");
			જાઓ out;
		}
		જો (strcmp(ctype, "tcpip-forward") != 0) {
			error_f("unsupported request %s", ctype);
			જાઓ out;
		}
		જો ((r = sshbuf_get_u8(original, ખાલી)) != 0 ||
		    (r = sshbuf_get_cstring(original, &listen_host, ખાલી)) != 0 ||
		    (r = sshbuf_get_u32(original, &listen_port)) != 0) {
			error_fr(r, "parse");
			જાઓ out;
		}
		જો (listen_port > 65535) {
			error_f("tcpip-forward for %s: bad port %u",
			    listen_host, listen_port);
			જાઓ out;
		}
		/* Record that connection to this host/port is permitted. */
		permission_set_add(ssh, FORWARD_USER, FORWARD_LOCAL, "<mux>",
		    -1, listen_host, ખાલી, (પૂર્ણાંક)listen_port, downstream);
		તોડો;
	સ્થિતિ SSH2_સંદેશ_CHANNEL_CLOSE:
		જો (have < 4)
			તોડો;
		remote_id = PEEK_U32(cp);
		જો ((c = channel_by_remote_id(ssh, remote_id)) != ખાલી) {
			જો (c->flags & CHAN_CLOSE_RCVD)
				channel_free(ssh, c);
			નહીંતર
				c->flags |= CHAN_CLOSE_SENT;
		}
		તોડો;
	}
	જો (modified) {
		જો ((r = sshpkt_start(ssh, type)) != 0 ||
		    (r = sshpkt_putb(ssh, modified)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0) {
			error_fr(r, "send");
			જાઓ out;
		}
	} નહીંતર {
		જો ((r = sshpkt_start(ssh, type)) != 0 ||
		    (r = sshpkt_put(ssh, cp, have)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0) {
			error_fr(r, "send");
			જાઓ out;
		}
	}
	ret = 0;
 out:
	મુક્ત(ctype);
	મુક્ત(listen_host);
	sshbuf_free(original);
	sshbuf_free(modified);
	પાછા ret;
}

/*
 * receive packets from upstream server and de-multiplex packets
 * to correct downstream:
 * implemented as a helper for channel input handlers,
 * replaces local (proxy) channel ID with downstream channel ID.
 */
પૂર્ણાંક
channel_proxy_upstream(Channel *c, પૂર્ણાંક type, uint32_t seq, સંરચના ssh *ssh)
{
	સંરચના sshbuf *b = ખાલી;
	Channel *downstream;
	અચલ u_char *cp = ખાલી;
	size_t len;
	પૂર્ણાંક r;

	/*
	 * When receiving packets from the peer we need to check whether we
	 * need to forward the packets to the mux client. In this case we
	 * restore the original channel id and keep track of CLOSE messages,
	 * so we can cleanup the channel.
	 */
	જો (c == ખાલી || c->type != SSH_CHANNEL_MUX_PROXY)
		પાછા 0;
	જો ((downstream = c->mux_ctx) == ખાલી)
		પાછા 0;
	પસંદગી (type) {
	સ્થિતિ SSH2_સંદેશ_CHANNEL_CLOSE:
	સ્થિતિ SSH2_સંદેશ_CHANNEL_DATA:
	સ્થિતિ SSH2_સંદેશ_CHANNEL_EOF:
	સ્થિતિ SSH2_સંદેશ_CHANNEL_EXTENDED_DATA:
	સ્થિતિ SSH2_સંદેશ_CHANNEL_OPEN_CONFIRMATION:
	સ્થિતિ SSH2_સંદેશ_CHANNEL_OPEN_FAILURE:
	સ્થિતિ SSH2_સંદેશ_CHANNEL_WINDOW_ADJUST:
	સ્થિતિ SSH2_સંદેશ_CHANNEL_SUCCESS:
	સ્થિતિ SSH2_સંદેશ_CHANNEL_FAILURE:
	સ્થિતિ SSH2_સંદેશ_CHANNEL_REQUEST:
		તોડો;
	મૂળભૂત:
		debug2_f("channel %u: unsupported type %u", c->self, type);
		પાછા 0;
	}
	જો ((b = sshbuf_new()) == ખાલી) {
		error_f("alloc reply");
		જાઓ out;
	}
	/* get remaining payload (after id) */
	cp = sshpkt_ptr(ssh, &len);
	જો (cp == ખાલી) {
		error_f("no packet");
		જાઓ out;
	}
	/* translate id and send to muxclient */
	જો ((r = sshbuf_put_u8(b, 0)) != 0 ||	/* padlen */
	    (r = sshbuf_put_u8(b, type)) != 0 ||
	    (r = sshbuf_put_u32(b, c->mux_downstream_id)) != 0 ||
	    (r = sshbuf_put(b, cp, len)) != 0 ||
	    (r = sshbuf_put_stringb(downstream->output, b)) != 0) {
		error_fr(r, "compose muxclient");
		જાઓ out;
	}
	/* sshbuf_dump(b, stderr); */
	જો (ssh_packet_log_type(type))
		debug3_f("channel %u: up->down: type %u", c->self, type);
 out:
	/* update state */
	પસંદગી (type) {
	સ્થિતિ SSH2_સંદેશ_CHANNEL_OPEN_CONFIRMATION:
		/* record remote_id for SSH2_MSG_CHANNEL_CLOSE */
		જો (cp && len > 4) {
			c->remote_id = PEEK_U32(cp);
			c->have_remote_id = 1;
		}
		તોડો;
	સ્થિતિ SSH2_સંદેશ_CHANNEL_CLOSE:
		જો (c->flags & CHAN_CLOSE_SENT)
			channel_free(ssh, c);
		નહીંતર
			c->flags |= CHAN_CLOSE_RCVD;
		તોડો;
	}
	sshbuf_free(b);
	પાછા 1;
}

/* -- protocol input */

/* Parse a channel ID from the current packet */
સ્થિર પૂર્ણાંક
channel_parse_id(સંરચના ssh *ssh, અચલ અક્ષર *where, અચલ અક્ષર *what)
{
	uint32_t id;
	પૂર્ણાંક r;

	જો ((r = sshpkt_get_u32(ssh, &id)) != 0) {
		error_r(r, "%s: parse id", where);
		ssh_packet_disconnect(ssh, "Invalid %s message", what);
	}
	જો (id > INT_MAX) {
		error_r(r, "%s: bad channel id %u", where, id);
		ssh_packet_disconnect(ssh, "Invalid %s channel id", what);
	}
	પાછા (પૂર્ણાંક)id;
}

/* Lookup a channel from an ID in the current packet */
સ્થિર Channel *
channel_from_packet_id(સંરચના ssh *ssh, અચલ અક્ષર *where, અચલ અક્ષર *what)
{
	પૂર્ણાંક id = channel_parse_id(ssh, where, what);
	Channel *c;

	જો ((c = channel_lookup(ssh, id)) == ખાલી) {
		ssh_packet_disconnect(ssh,
		    "%s packet referred to nonexistent channel %d", what, id);
	}
	પાછા c;
}

પૂર્ણાંક
channel_આગત_data(પૂર્ણાંક type, uint32_t seq, સંરચના ssh *ssh)
{
	અચલ u_char *data;
	size_t data_len, win_len;
	Channel *c = channel_from_packet_id(ssh, __func__, "data");
	પૂર્ણાંક r;

	જો (channel_proxy_upstream(c, type, seq, ssh))
		પાછા 0;

	/* Ignore any data for non-open channels (might happen on close) */
	જો (c->type != SSH_CHANNEL_OPEN &&
	    c->type != SSH_CHANNEL_RDYNAMIC_OPEN &&
	    c->type != SSH_CHANNEL_RDYNAMIC_FINISH &&
	    c->type != SSH_CHANNEL_X11_OPEN)
		પાછા 0;

	/* Get the data. */
	જો ((r = sshpkt_get_string_direct(ssh, &data, &data_len)) != 0 ||
            (r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "channel %i: get data", c->self);

	win_len = data_len;
	જો (c->datagram)
		win_len += 4;  /* string length header */

	/*
	 * The sending side reduces its window as it sends data, so we
	 * must 'fake' consumption of the data in order to ensure that window
	 * updates are sent back. Otherwise the connection might deadlock.
	 */
	જો (c->ostate != CHAN_OUTPUT_OPEN) {
		જો (win_len > c->local_window)
			c->local_window = 0;
		નહીંતર
			c->local_window -= win_len;
		c->local_consumed += win_len;
		પાછા 0;
	}

	જો (win_len > c->local_maxpacket) {
		logit("channel %d: rcvd big packet %zu, maxpack %u",
		    c->self, win_len, c->local_maxpacket);
		પાછા 0;
	}
	જો (win_len > c->local_window) {
		u_int delta = win_len - c->local_window;

		જો (c->local_window_exceeded > UINT_MAX - delta)
			c->local_window_exceeded = UINT_MAX;
		નહીંતર
			c->local_window_exceeded += delta;
		logit("channel %d: rcvd too much data %zu, win %u/%u "
		    "(excess %u)", c->self, win_len, c->local_window,
		    c->local_window_max, c->local_window_exceeded);
		c->local_window = 0;
		/* Allow 10% grace before bringing the hammer down */
		જો (c->local_window_exceeded > (c->local_window_max / 10)) {
			ssh_packet_disconnect(ssh, "channel %d: peer ignored "
			    "channel window", c->self);
		}
	} નહીંતર {
		c->local_window -= win_len;
		c->local_window_exceeded = 0;
	}

	જો (c->datagram) {
		જો ((r = sshbuf_put_string(c->output, data, data_len)) != 0)
			fatal_fr(r, "channel %i: append datagram", c->self);
	} નહીંતર જો ((r = sshbuf_put(c->output, data, data_len)) != 0)
		fatal_fr(r, "channel %i: append data", c->self);

	પાછા 0;
}

પૂર્ણાંક
channel_આગત_extended_data(પૂર્ણાંક type, uint32_t seq, સંરચના ssh *ssh)
{
	અચલ u_char *data;
	size_t data_len;
	uint32_t tcode;
	Channel *c = channel_from_packet_id(ssh, __func__, "extended data");
	પૂર્ણાંક r;

	જો (channel_proxy_upstream(c, type, seq, ssh))
		પાછા 0;
	જો (c->type != SSH_CHANNEL_OPEN) {
		logit("channel %d: ext data for non open", c->self);
		પાછા 0;
	}
	જો (c->flags & CHAN_EOF_RCVD) {
		જો (ssh->compat & SSH_BUG_EXTEOF)
			debug("channel %d: accepting ext data after eof",
			    c->self);
		નહીંતર
			ssh_packet_disconnect(ssh, "Received extended_data "
			    "after EOF on channel %d.", c->self);
	}

	જો ((r = sshpkt_get_u32(ssh, &tcode)) != 0) {
		error_fr(r, "parse tcode");
		ssh_packet_disconnect(ssh, "Invalid extended_data message");
	}
	જો (c->efd == -1 ||
	    c->extended_usage != CHAN_EXTENDED_WRITE ||
	    tcode != SSH2_EXTENDED_DATA_STDERR) {
		logit("channel %d: bad ext data", c->self);
		પાછા 0;
	}
	જો ((r = sshpkt_get_string_direct(ssh, &data, &data_len)) != 0 ||
            (r = sshpkt_get_end(ssh)) != 0) {
		error_fr(r, "parse data");
		ssh_packet_disconnect(ssh, "Invalid extended_data message");
	}

	જો (data_len > c->local_window) {
		logit("channel %d: rcvd too much extended_data %zu, win %u",
		    c->self, data_len, c->local_window);
		પાછા 0;
	}
	debug2("channel %d: rcvd ext data %zu", c->self, data_len);
	/* XXX sshpkt_getb? */
	જો ((r = sshbuf_put(c->extended, data, data_len)) != 0)
		error_fr(r, "append");
	c->local_window -= data_len;
	પાછા 0;
}

પૂર્ણાંક
channel_આગત_ieof(પૂર્ણાંક type, uint32_t seq, સંરચના ssh *ssh)
{
	Channel *c = channel_from_packet_id(ssh, __func__, "ieof");
	પૂર્ણાંક r;

        જો ((r = sshpkt_get_end(ssh)) != 0) {
		error_fr(r, "parse data");
		ssh_packet_disconnect(ssh, "Invalid ieof message");
	}

	જો (channel_proxy_upstream(c, type, seq, ssh))
		પાછા 0;
	chan_rcvd_ieof(ssh, c);

	/* XXX force input close */
	જો (c->force_drain && c->istate == CHAN_આગત_OPEN) {
		debug("channel %d: FORCE input drain", c->self);
		c->istate = CHAN_આગત_WAIT_DRAIN;
		જો (sshbuf_len(c->આગત) == 0)
			chan_ibuf_empty(ssh, c);
	}
	પાછા 0;
}

પૂર્ણાંક
channel_આગત_oclose(પૂર્ણાંક type, uint32_t seq, સંરચના ssh *ssh)
{
	Channel *c = channel_from_packet_id(ssh, __func__, "oclose");
	પૂર્ણાંક r;

	જો (channel_proxy_upstream(c, type, seq, ssh))
		પાછા 0;
        જો ((r = sshpkt_get_end(ssh)) != 0) {
		error_fr(r, "parse data");
		ssh_packet_disconnect(ssh, "Invalid oclose message");
	}
	chan_rcvd_oclose(ssh, c);
	પાછા 0;
}

પૂર્ણાંક
channel_આગત_open_confirmation(પૂર્ણાંક type, uint32_t seq, સંરચના ssh *ssh)
{
	Channel *c = channel_from_packet_id(ssh, __func__, "open confirmation");
	uint32_t remote_window, remote_maxpacket;
	પૂર્ણાંક r;

	જો (channel_proxy_upstream(c, type, seq, ssh))
		પાછા 0;
	જો (c->type != SSH_CHANNEL_OPENING)
		ssh_packet_disconnect(ssh, "Received open confirmation for "
		    "non-opening channel %d.", c->self);
	/*
	 * Record the remote channel number and mark that the channel
	 * is now open.
	 */
	જો ((r = sshpkt_get_u32(ssh, &c->remote_id)) != 0 ||
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
	જો (c->open_confirm) {
		debug2_f("channel %d: callback start", c->self);
		c->open_confirm(ssh, c->self, 1, c->open_confirm_ctx);
		debug2_f("channel %d: callback done", c->self);
	}
	channel_set_used_time(ssh, c);
	debug2("channel %d: open confirm rwindow %u rmax %u", c->self,
	    c->remote_window, c->remote_maxpacket);
	પાછા 0;
}

સ્થિર અક્ષર *
reason2txt(પૂર્ણાંક reason)
{
	પસંદગી (reason) {
	સ્થિતિ SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED:
		પાછા "administratively prohibited";
	સ્થિતિ SSH2_OPEN_CONNECT_FAILED:
		પાછા "connect failed";
	સ્થિતિ SSH2_OPEN_UNKNOWN_CHANNEL_TYPE:
		પાછા "unknown channel type";
	સ્થિતિ SSH2_OPEN_RESOURCE_SHORTAGE:
		પાછા "resource shortage";
	}
	પાછા "unknown reason";
}

પૂર્ણાંક
channel_આગત_open_failure(પૂર્ણાંક type, uint32_t seq, સંરચના ssh *ssh)
{
	Channel *c = channel_from_packet_id(ssh, __func__, "open failure");
	uint32_t reason;
	અક્ષર *સંદેશ = ખાલી;
	પૂર્ણાંક r;

	જો (channel_proxy_upstream(c, type, seq, ssh))
		પાછા 0;
	જો (c->type != SSH_CHANNEL_OPENING)
		ssh_packet_disconnect(ssh, "Received open failure for "
		    "non-opening channel %d.", c->self);
	જો ((r = sshpkt_get_u32(ssh, &reason)) != 0) {
		error_fr(r, "parse reason");
		ssh_packet_disconnect(ssh, "Invalid open failure message");
	}
	/* skip language */
	જો ((r = sshpkt_get_cstring(ssh, &સંદેશ, ખાલી)) != 0 ||
	    (r = sshpkt_get_string_direct(ssh, ખાલી, ખાલી)) != 0 ||
            (r = sshpkt_get_end(ssh)) != 0) {
		error_fr(r, "parse msg/lang");
		ssh_packet_disconnect(ssh, "Invalid open failure message");
	}
	logit("channel %d: open failed: %s%s%s", c->self,
	    reason2txt(reason), સંદેશ ? ": ": "", સંદેશ ? સંદેશ : "");
	મુક્ત(સંદેશ);
	જો (c->open_confirm) {
		debug2_f("channel %d: callback start", c->self);
		c->open_confirm(ssh, c->self, 0, c->open_confirm_ctx);
		debug2_f("channel %d: callback done", c->self);
	}
	/* Schedule the channel for cleanup/deletion. */
	chan_mark_dead(ssh, c);
	પાછા 0;
}

પૂર્ણાંક
channel_આગત_window_adjust(પૂર્ણાંક type, uint32_t seq, સંરચના ssh *ssh)
{
	પૂર્ણાંક id = channel_parse_id(ssh, __func__, "window adjust");
	Channel *c;
	uint32_t adjust;
	u_int new_rwin;
	પૂર્ણાંક r;

	જો ((c = channel_lookup(ssh, id)) == ખાલી) {
		logit("Received window adjust for non-open channel %d.", id);
		પાછા 0;
	}

	જો (channel_proxy_upstream(c, type, seq, ssh))
		પાછા 0;
	જો ((r = sshpkt_get_u32(ssh, &adjust)) != 0 ||
            (r = sshpkt_get_end(ssh)) != 0) {
		error_fr(r, "parse adjust");
		ssh_packet_disconnect(ssh, "Invalid window adjust message");
	}
	debug2("channel %d: rcvd adjust %u", c->self, adjust);
	જો ((new_rwin = c->remote_window + adjust) < c->remote_window) {
		fatal("channel %d: adjust %u overflows remote window %u",
		    c->self, adjust, c->remote_window);
	}
	c->remote_window = new_rwin;
	પાછા 0;
}

પૂર્ણાંક
channel_આગત_status_confirm(પૂર્ણાંક type, uint32_t seq, સંરચના ssh *ssh)
{
	પૂર્ણાંક id = channel_parse_id(ssh, __func__, "status confirm");
	Channel *c;
	સંરચના channel_confirm *cc;

	/* Reset keepalive timeout */
	ssh_packet_set_alive_timeouts(ssh, 0);

	debug2_f("type %d id %d", type, id);

	જો ((c = channel_lookup(ssh, id)) == ખાલી) {
		logit_f("%d: unknown", id);
		પાછા 0;
	}
	જો (channel_proxy_upstream(c, type, seq, ssh))
		પાછા 0;
        જો (sshpkt_get_end(ssh) != 0)
		ssh_packet_disconnect(ssh, "Invalid status confirm message");
	જો ((cc = TAILQ_FIRST(&c->status_confirms)) == ખાલી)
		પાછા 0;
	cc->cb(ssh, type, c, cc->ctx);
	TAILQ_REMOVE(&c->status_confirms, cc, entry);
	freezero(cc, કદ(*cc));
	પાછા 0;
}

/* -- tcp forwarding */

શૂન્ય
channel_set_af(સંરચના ssh *ssh, પૂર્ણાંક af)
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
સ્થિર અચલ અક્ષર *
channel_fwd_bind_addr(સંરચના ssh *ssh, અચલ અક્ષર *listen_addr, પૂર્ણાંક *wildcardp,
    પૂર્ણાંક is_client, સંરચના ForwardOptions *fwd_opts)
{
	અચલ અક્ષર *addr = ખાલી;
	પૂર્ણાંક wildcard = 0;

	જો (listen_addr == ખાલી) {
		/* No address specified: default to gateway_ports setting */
		જો (fwd_opts->gateway_ports)
			wildcard = 1;
	} નહીંતર જો (fwd_opts->gateway_ports || is_client) {
		જો (((ssh->compat & SSH_OLD_FORWARD_ADDR) &&
		    strcmp(listen_addr, "0.0.0.0") == 0 && is_client == 0) ||
		    *listen_addr == '\0' || strcmp(listen_addr, "*") == 0 ||
		    (!is_client && fwd_opts->gateway_ports == 1)) {
			wildcard = 1;
			/*
			 * Notify client if they requested a specific listen
			 * address and it was overridden.
			 */
			જો (*listen_addr != '\0' &&
			    strcmp(listen_addr, "0.0.0.0") != 0 &&
			    strcmp(listen_addr, "*") != 0) {
				ssh_packet_send_debug(ssh,
				    "Forwarding listen address "
				    "\"%s\" overridden by server "
				    "GatewayPorts", listen_addr);
			}
		} નહીંતર જો (strcmp(listen_addr, "localhost") != 0 ||
		    strcmp(listen_addr, "127.0.0.1") == 0 ||
		    strcmp(listen_addr, "::1") == 0) {
			/*
			 * Accept explicit localhost address when
			 * GatewayPorts=yes. The "localhost" hostname is
			 * deliberately skipped here so it will listen on all
			 * available local address families.
			 */
			addr = listen_addr;
		}
	} નહીંતર જો (strcmp(listen_addr, "127.0.0.1") == 0 ||
	    strcmp(listen_addr, "::1") == 0) {
		/*
		 * If a specific IPv4/IPv6 localhost address has been
		 * requested then accept it even if gateway_ports is in
		 * effect. This allows the client to prefer IPv4 or IPv6.
		 */
		addr = listen_addr;
	}
	જો (wildcardp != ખાલી)
		*wildcardp = wildcard;
	પાછા addr;
}

સ્થિર પૂર્ણાંક
channel_setup_fwd_listener_tcpip(સંરચના ssh *ssh, પૂર્ણાંક type,
    સંરચના Forward *fwd, પૂર્ણાંક *allocated_listen_port,
    સંરચના ForwardOptions *fwd_opts)
{
	Channel *c;
	પૂર્ણાંક sock, r, success = 0, wildcard = 0, is_client;
	સંરચના addrinfo hints, *ai, *aitop;
	અચલ અક્ષર *host, *addr;
	અક્ષર ntop[NI_MAXHOST], strport[NI_MAXSERV];
	in_port_t *lport_p;

	is_client = (type == SSH_CHANNEL_PORT_LISTENER);

	જો (is_client && fwd->connect_path != ખાલી) {
		host = fwd->connect_path;
	} નહીંતર {
		host = (type == SSH_CHANNEL_RPORT_LISTENER) ?
		    fwd->listen_host : fwd->connect_host;
		જો (host == ખાલી) {
			error("No forward host name.");
			પાછા 0;
		}
		જો (strlen(host) >= NI_MAXHOST) {
			error("Forward host name too long.");
			પાછા 0;
		}
	}

	/* Determine the bind address, cf. channel_fwd_bind_addr() comment */
	addr = channel_fwd_bind_addr(ssh, fwd->listen_host, &wildcard,
	    is_client, fwd_opts);
	debug3_f("type %d wildcard %d addr %s", type, wildcard,
	    (addr == ખાલી) ? "NULL" : addr);

	/*
	 * getaddrinfo returns a loopback address if the hostname is
	 * set to NULL and hints.ai_flags is not AI_PASSIVE
	 */
	memset(&hints, 0, કદ(hints));
	hints.ai_family = ssh->chanctxt->IPv4or6;
	hints.ai_flags = wildcard ? AI_PASSIVE : 0;
	hints.ai_socktype = SOCK_STREAM;
	snprintf(strport, કદ strport, "%d", fwd->listen_port);
	જો ((r = getaddrinfo(addr, strport, &hints, &aitop)) != 0) {
		જો (addr == ખાલી) {
			/* This really shouldn't happen */
			ssh_packet_disconnect(ssh, "getaddrinfo: fatal error: %s",
			    ssh_gai_strerror(r));
		} નહીંતર {
			error_f("getaddrinfo(%.64s): %s", addr,
			    ssh_gai_strerror(r));
		}
		પાછા 0;
	}
	જો (allocated_listen_port != ખાલી)
		*allocated_listen_port = 0;
	માટે (ai = aitop; ai; ai = ai->ai_next) {
		પસંદગી (ai->ai_family) {
		સ્થિતિ AF_INET:
			lport_p = &((સંરચના sockaddr_in *)ai->ai_addr)->
			    sin_port;
			તોડો;
		સ્થિતિ AF_INET6:
			lport_p = &((સંરચના sockaddr_in6 *)ai->ai_addr)->
			    sin6_port;
			તોડો;
		મૂળભૂત:
			ચાલુ;
		}
		/*
		 * If allocating a port for -R forwards, then use the
		 * same port for all address families.
		 */
		જો (type == SSH_CHANNEL_RPORT_LISTENER &&
		    fwd->listen_port == 0 && allocated_listen_port != ખાલી &&
		    *allocated_listen_port > 0)
			*lport_p = htons(*allocated_listen_port);

		જો (getnameinfo(ai->ai_addr, ai->ai_addrlen, ntop, કદ(ntop),
		    strport, કદ(strport),
		    NI_NUMERICHOST|NI_NUMERICSERV) != 0) {
			error_f("getnameinfo failed");
			ચાલુ;
		}
		/* Create a port to listen for the host. */
		sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		જો (sock == -1) {
			/* this is no error since kernel may not support ipv6 */
			verbose("socket [%s]:%s: %.100s", ntop, strport,
			    strerror(errno));
			ચાલુ;
		}

		set_reuseaddr(sock);
		જો (ai->ai_family == AF_INET6)
			sock_set_v6only(sock);

		debug("Local forwarding listening on %s port %s.",
		    ntop, strport);

		/* Bind the socket to the address. */
		જો (bind(sock, ai->ai_addr, ai->ai_addrlen) == -1) {
			/*
			 * address can be in if use ipv6 address is
			 * already bound
			 */
			જો (!ai->ai_next)
				error("bind [%s]:%s: %.100s",
				    ntop, strport, strerror(errno));
			નહીંતર
				verbose("bind [%s]:%s: %.100s",
				    ntop, strport, strerror(errno));

			close(sock);
			ચાલુ;
		}
		/* Start listening for connections on the socket. */
		જો (listen(sock, SSH_LISTEN_BACKLOG) == -1) {
			error("listen [%s]:%s: %.100s", ntop, strport,
			    strerror(errno));
			close(sock);
			ચાલુ;
		}

		/*
		 * fwd->listen_port == 0 requests a dynamically allocated port -
		 * record what we got.
		 */
		જો (type == SSH_CHANNEL_RPORT_LISTENER &&
		    fwd->listen_port == 0 &&
		    allocated_listen_port != ખાલી &&
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
		c->listening_addr = addr == ખાલી ? ખાલી : xstrdup(addr);
		જો (fwd->listen_port == 0 && allocated_listen_port != ખાલી &&
		    !(ssh->compat & SSH_BUG_DYNAMIC_RPORT))
			c->listening_port = *allocated_listen_port;
		નહીંતર
			c->listening_port = fwd->listen_port;
		success = 1;
	}
	જો (success == 0)
		error_f("cannot listen to port: %d", fwd->listen_port);
	freeaddrinfo(aitop);
	પાછા success;
}

સ્થિર પૂર્ણાંક
channel_setup_fwd_listener_streamlocal(સંરચના ssh *ssh, પૂર્ણાંક type,
    સંરચના Forward *fwd, સંરચના ForwardOptions *fwd_opts)
{
	સંરચના sockaddr_un sunaddr;
	અચલ અક્ષર *path;
	Channel *c;
	પૂર્ણાંક port, sock;
	mode_t omask;

	પસંદગી (type) {
	સ્થિતિ SSH_CHANNEL_UNIX_LISTENER:
		જો (fwd->connect_path != ખાલી) {
			જો (strlen(fwd->connect_path) > કદ(sunaddr.sun_path)) {
				error("Local connecting path too long: %s",
				    fwd->connect_path);
				પાછા 0;
			}
			path = fwd->connect_path;
			port = PORT_STREAMLOCAL;
		} નહીંતર {
			જો (fwd->connect_host == ખાલી) {
				error("No forward host name.");
				પાછા 0;
			}
			જો (strlen(fwd->connect_host) >= NI_MAXHOST) {
				error("Forward host name too long.");
				પાછા 0;
			}
			path = fwd->connect_host;
			port = fwd->connect_port;
		}
		તોડો;
	સ્થિતિ SSH_CHANNEL_RUNIX_LISTENER:
		path = fwd->listen_path;
		port = PORT_STREAMLOCAL;
		તોડો;
	મૂળભૂત:
		error_f("unexpected channel type %d", type);
		પાછા 0;
	}

	જો (fwd->listen_path == ખાલી) {
		error("No forward path name.");
		પાછા 0;
	}
	જો (strlen(fwd->listen_path) > કદ(sunaddr.sun_path)) {
		error("Local listening path too long: %s", fwd->listen_path);
		પાછા 0;
	}

	debug3_f("type %d path %s", type, fwd->listen_path);

	/* Start a Unix domain listener. */
	omask = umask(fwd_opts->streamlocal_bind_mask);
	sock = unix_listener(fwd->listen_path, SSH_LISTEN_BACKLOG,
	    fwd_opts->streamlocal_bind_unlink);
	umask(omask);
	જો (sock < 0)
		પાછા 0;

	debug("Local forwarding listening on path %s.", fwd->listen_path);

	/* Allocate a channel number for the socket. */
	c = channel_new(ssh, "unix-listener", type, sock, sock, -1,
	    CHAN_TCP_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT,
	    0, "unix listener", 1);
	c->path = xstrdup(path);
	c->host_port = port;
	c->listening_port = PORT_STREAMLOCAL;
	c->listening_addr = xstrdup(fwd->listen_path);
	પાછા 1;
}

સ્થિર પૂર્ણાંક
channel_cancel_rport_listener_tcpip(સંરચના ssh *ssh,
    અચલ અક્ષર *host, u_short port)
{
	u_int i;
	પૂર્ણાંક found = 0;

	માટે (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		Channel *c = ssh->chanctxt->channels[i];
		જો (c == ખાલી || c->type != SSH_CHANNEL_RPORT_LISTENER)
			ચાલુ;
		જો (strcmp(c->path, host) == 0 && c->listening_port == port) {
			debug2_f("close channel %d", i);
			channel_free(ssh, c);
			found = 1;
		}
	}

	પાછા found;
}

સ્થિર પૂર્ણાંક
channel_cancel_rport_listener_streamlocal(સંરચના ssh *ssh, અચલ અક્ષર *path)
{
	u_int i;
	પૂર્ણાંક found = 0;

	માટે (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		Channel *c = ssh->chanctxt->channels[i];
		જો (c == ખાલી || c->type != SSH_CHANNEL_RUNIX_LISTENER)
			ચાલુ;
		જો (c->path == ખાલી)
			ચાલુ;
		જો (strcmp(c->path, path) == 0) {
			debug2_f("close channel %d", i);
			channel_free(ssh, c);
			found = 1;
		}
	}

	પાછા found;
}

પૂર્ણાંક
channel_cancel_rport_listener(સંરચના ssh *ssh, સંરચના Forward *fwd)
{
	જો (fwd->listen_path != ખાલી) {
		પાછા channel_cancel_rport_listener_streamlocal(ssh,
		    fwd->listen_path);
	} નહીંતર {
		પાછા channel_cancel_rport_listener_tcpip(ssh,
		    fwd->listen_host, fwd->listen_port);
	}
}

સ્થિર પૂર્ણાંક
channel_cancel_lport_listener_tcpip(સંરચના ssh *ssh,
    અચલ અક્ષર *lhost, u_short lport, પૂર્ણાંક cport,
    સંરચના ForwardOptions *fwd_opts)
{
	u_int i;
	પૂર્ણાંક found = 0;
	અચલ અક્ષર *addr = channel_fwd_bind_addr(ssh, lhost, ખાલી, 1, fwd_opts);

	માટે (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		Channel *c = ssh->chanctxt->channels[i];
		જો (c == ખાલી || c->type != SSH_CHANNEL_PORT_LISTENER)
			ચાલુ;
		જો (c->listening_port != lport)
			ચાલુ;
		જો (cport == CHANNEL_CANCEL_PORT_STATIC) {
			/* skip dynamic forwardings */
			જો (c->host_port == 0)
				ચાલુ;
		} નહીંતર {
			જો (c->host_port != cport)
				ચાલુ;
		}
		જો ((c->listening_addr == ખાલી && addr != ખાલી) ||
		    (c->listening_addr != ખાલી && addr == ખાલી))
			ચાલુ;
		જો (addr == ખાલી || strcmp(c->listening_addr, addr) == 0) {
			debug2_f("close channel %d", i);
			channel_free(ssh, c);
			found = 1;
		}
	}

	પાછા found;
}

સ્થિર પૂર્ણાંક
channel_cancel_lport_listener_streamlocal(સંરચના ssh *ssh, અચલ અક્ષર *path)
{
	u_int i;
	પૂર્ણાંક found = 0;

	જો (path == ખાલી) {
		error_f("no path specified.");
		પાછા 0;
	}

	માટે (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		Channel *c = ssh->chanctxt->channels[i];
		જો (c == ખાલી || c->type != SSH_CHANNEL_UNIX_LISTENER)
			ચાલુ;
		જો (c->listening_addr == ખાલી)
			ચાલુ;
		જો (strcmp(c->listening_addr, path) == 0) {
			debug2_f("close channel %d", i);
			channel_free(ssh, c);
			found = 1;
		}
	}

	પાછા found;
}

પૂર્ણાંક
channel_cancel_lport_listener(સંરચના ssh *ssh,
    સંરચના Forward *fwd, પૂર્ણાંક cport, સંરચના ForwardOptions *fwd_opts)
{
	જો (fwd->listen_path != ખાલી) {
		પાછા channel_cancel_lport_listener_streamlocal(ssh,
		    fwd->listen_path);
	} નહીંતર {
		પાછા channel_cancel_lport_listener_tcpip(ssh,
		    fwd->listen_host, fwd->listen_port, cport, fwd_opts);
	}
}

/* protocol local port fwd, used by ssh */
પૂર્ણાંક
channel_setup_local_fwd_listener(સંરચના ssh *ssh,
    સંરચના Forward *fwd, સંરચના ForwardOptions *fwd_opts)
{
	જો (fwd->listen_path != ખાલી) {
		પાછા channel_setup_fwd_listener_streamlocal(ssh,
		    SSH_CHANNEL_UNIX_LISTENER, fwd, fwd_opts);
	} નહીંતર {
		પાછા channel_setup_fwd_listener_tcpip(ssh,
		    SSH_CHANNEL_PORT_LISTENER, fwd, ખાલી, fwd_opts);
	}
}

/* Matches a remote forwarding permission against a requested forwarding */
સ્થિર પૂર્ણાંક
remote_open_match(સંરચના permission *allowed_open, સંરચના Forward *fwd)
{
	પૂર્ણાંક ret;
	અક્ષર *lhost;

	/* XXX add ACLs for streamlocal */
	જો (fwd->listen_path != ખાલી)
		પાછા 1;

	જો (fwd->listen_host == ખાલી || allowed_open->listen_host == ખાલી)
		પાછા 0;

	જો (allowed_open->listen_port != FWD_PERMIT_ANY_PORT &&
	    allowed_open->listen_port != fwd->listen_port)
		પાછા 0;

	/* Match hostnames case-insensitively */
	lhost = xstrdup(fwd->listen_host);
	lowercase(lhost);
	ret = match_pattern(lhost, allowed_open->listen_host);
	મુક્ત(lhost);

	પાછા ret;
}

/* Checks whether a requested remote forwarding is permitted */
સ્થિર પૂર્ણાંક
check_rfwd_permission(સંરચના ssh *ssh, સંરચના Forward *fwd)
{
	સંરચના ssh_channels *sc = ssh->chanctxt;
	સંરચના permission_set *pset = &sc->remote_perms;
	u_int i, permit, permit_adm = 1;
	સંરચના permission *perm;

#ifdef SKIP_PRIVDROP
	જો (fwd->listen_path != ખાલી)
		પાછા 0;
	જો (fwd->listen_port != 0 && fwd->listen_port < 1024)
		પાછા 0;
#endif

	/* XXX apply GatewayPorts override before checking? */

	permit = pset->all_permitted;
	જો (!permit) {
		માટે (i = 0; i < pset->અંક_permitted_user; i++) {
			perm = &pset->permitted_user[i];
			જો (remote_open_match(perm, fwd)) {
				permit = 1;
				તોડો;
			}
		}
	}

	જો (pset->અંક_permitted_admin > 0) {
		permit_adm = 0;
		માટે (i = 0; i < pset->અંક_permitted_admin; i++) {
			perm = &pset->permitted_admin[i];
			જો (remote_open_match(perm, fwd)) {
				permit_adm = 1;
				તોડો;
			}
		}
	}

	પાછા permit && permit_adm;
}

/* protocol v2 remote port fwd, used by sshd */
પૂર્ણાંક
channel_setup_remote_fwd_listener(સંરચના ssh *ssh, સંરચના Forward *fwd,
    પૂર્ણાંક *allocated_listen_port, સંરચના ForwardOptions *fwd_opts)
{
	જો (!check_rfwd_permission(ssh, fwd)) {
		ssh_packet_send_debug(ssh, "port forwarding refused");
		જો (fwd->listen_path != ખાલી)
			/* XXX always allowed, see remote_open_match() */
			logit("Received request from %.100s port %d to "
			    "remote forward to path \"%.100s\", "
			    "but the request was denied.",
			    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
			    fwd->listen_path);
		નહીંતર જો(fwd->listen_host != ખાલી)
			logit("Received request from %.100s port %d to "
			    "remote forward to host %.100s port %d, "
			    "but the request was denied.",
			    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
			    fwd->listen_host, fwd->listen_port );
		નહીંતર
			logit("Received request from %.100s port %d to remote "
			    "forward, but the request was denied.",
			    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
		પાછા 0;
	}
	જો (fwd->listen_path != ખાલી) {
		પાછા channel_setup_fwd_listener_streamlocal(ssh,
		    SSH_CHANNEL_RUNIX_LISTENER, fwd, fwd_opts);
	} નહીંતર {
		પાછા channel_setup_fwd_listener_tcpip(ssh,
		    SSH_CHANNEL_RPORT_LISTENER, fwd, allocated_listen_port,
		    fwd_opts);
	}
}

/*
 * Translate the requested rfwd listen host to something usable for
 * this server.
 */
સ્થિર અચલ અક્ષર *
channel_rfwd_bind_host(અચલ અક્ષર *listen_host)
{
	જો (listen_host == ખાલી) {
		પાછા "localhost";
	} નહીંતર જો (*listen_host == '\0' || strcmp(listen_host, "*") == 0) {
		પાછા "";
	} નહીંતર
		પાછા listen_host;
}

/*
 * Initiate forwarding of connections to port "port" on remote host through
 * the secure channel to host:port from local side.
 * Returns handle (index) for updating the dynamic listen port with
 * channel_update_permission().
 */
પૂર્ણાંક
channel_request_remote_forwarding(સંરચના ssh *ssh, સંરચના Forward *fwd)
{
	પૂર્ણાંક r, success = 0, idx = -1;
	અચલ અક્ષર *host_to_connect, *listen_host, *listen_path;
	પૂર્ણાંક port_to_connect, listen_port;

	/* Send the forward request to the remote side. */
	જો (fwd->listen_path != ખાલી) {
		જો ((r = sshpkt_start(ssh, SSH2_સંદેશ_GLOBAL_REQUEST)) != 0 ||
		    (r = sshpkt_put_cstring(ssh,
		    "streamlocal-forward@openssh.com")) != 0 ||
		    (r = sshpkt_put_u8(ssh, 1)) != 0 || /* want reply */
		    (r = sshpkt_put_cstring(ssh, fwd->listen_path)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			fatal_fr(r, "request streamlocal");
	} નહીંતર {
		જો ((r = sshpkt_start(ssh, SSH2_સંદેશ_GLOBAL_REQUEST)) != 0 ||
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
	જો (success) {
		/* Record that connection to this host/port is permitted. */
		host_to_connect = listen_host = listen_path = ખાલી;
		port_to_connect = listen_port = 0;
		જો (fwd->connect_path != ખાલી) {
			host_to_connect = fwd->connect_path;
			port_to_connect = PORT_STREAMLOCAL;
		} નહીંતર {
			host_to_connect = fwd->connect_host;
			port_to_connect = fwd->connect_port;
		}
		જો (fwd->listen_path != ખાલી) {
			listen_path = fwd->listen_path;
			listen_port = PORT_STREAMLOCAL;
		} નહીંતર {
			listen_host = fwd->listen_host;
			listen_port = fwd->listen_port;
		}
		idx = permission_set_add(ssh, FORWARD_USER, FORWARD_LOCAL,
		    host_to_connect, port_to_connect,
		    listen_host, listen_path, listen_port, ખાલી);
	}
	પાછા idx;
}

સ્થિર પૂર્ણાંક
open_match(સંરચના permission *allowed_open, અચલ અક્ષર *requestedhost,
    પૂર્ણાંક requestedport)
{
	જો (allowed_open->host_to_connect == ખાલી)
		પાછા 0;
	જો (allowed_open->port_to_connect != FWD_PERMIT_ANY_PORT &&
	    allowed_open->port_to_connect != requestedport)
		પાછા 0;
	જો (strcmp(allowed_open->host_to_connect, FWD_PERMIT_ANY_HOST) != 0 &&
	    strcmp(allowed_open->host_to_connect, requestedhost) != 0)
		પાછા 0;
	પાછા 1;
}

/*
 * Note that in the listen host/port case
 * we don't support FWD_PERMIT_ANY_PORT and
 * need to translate between the configured-host (listen_host)
 * and what we've sent to the remote server (channel_rfwd_bind_host)
 */
સ્થિર પૂર્ણાંક
open_listen_match_tcpip(સંરચના permission *allowed_open,
    અચલ અક્ષર *requestedhost, u_short requestedport, પૂર્ણાંક translate)
{
	અચલ અક્ષર *allowed_host;

	જો (allowed_open->host_to_connect == ખાલી)
		પાછા 0;
	જો (allowed_open->listen_port != requestedport)
		પાછા 0;
	જો (!translate && allowed_open->listen_host == ખાલી &&
	    requestedhost == ખાલી)
		પાછા 1;
	allowed_host = translate ?
	    channel_rfwd_bind_host(allowed_open->listen_host) :
	    allowed_open->listen_host;
	જો (allowed_host == ખાલી || requestedhost == ખાલી ||
	    strcmp(allowed_host, requestedhost) != 0)
		પાછા 0;
	પાછા 1;
}

સ્થિર પૂર્ણાંક
open_listen_match_streamlocal(સંરચના permission *allowed_open,
    અચલ અક્ષર *requestedpath)
{
	જો (allowed_open->host_to_connect == ખાલી)
		પાછા 0;
	જો (allowed_open->listen_port != PORT_STREAMLOCAL)
		પાછા 0;
	જો (allowed_open->listen_path == ખાલી ||
	    strcmp(allowed_open->listen_path, requestedpath) != 0)
		પાછા 0;
	પાછા 1;
}

/*
 * Request cancellation of remote forwarding of connection host:port from
 * local side.
 */
સ્થિર પૂર્ણાંક
channel_request_rforward_cancel_tcpip(સંરચના ssh *ssh,
    અચલ અક્ષર *host, u_short port)
{
	સંરચના ssh_channels *sc = ssh->chanctxt;
	સંરચના permission_set *pset = &sc->local_perms;
	પૂર્ણાંક r;
	u_int i;
	સંરચના permission *perm = ખાલી;

	માટે (i = 0; i < pset->અંક_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		જો (open_listen_match_tcpip(perm, host, port, 0))
			તોડો;
		perm = ખાલી;
	}
	જો (perm == ખાલી) {
		debug_f("requested forward not found");
		પાછા -1;
	}
	જો ((r = sshpkt_start(ssh, SSH2_સંદેશ_GLOBAL_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "cancel-tcpip-forward")) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 || /* want reply */
	    (r = sshpkt_put_cstring(ssh, channel_rfwd_bind_host(host))) != 0 ||
	    (r = sshpkt_put_u32(ssh, port)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send cancel");

	fwd_perm_clear(perm); /* unregister */

	પાછા 0;
}

/*
 * Request cancellation of remote forwarding of Unix domain socket
 * path from local side.
 */
સ્થિર પૂર્ણાંક
channel_request_rforward_cancel_streamlocal(સંરચના ssh *ssh, અચલ અક્ષર *path)
{
	સંરચના ssh_channels *sc = ssh->chanctxt;
	સંરચના permission_set *pset = &sc->local_perms;
	પૂર્ણાંક r;
	u_int i;
	સંરચના permission *perm = ખાલી;

	માટે (i = 0; i < pset->અંક_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		જો (open_listen_match_streamlocal(perm, path))
			તોડો;
		perm = ખાલી;
	}
	જો (perm == ખાલી) {
		debug_f("requested forward not found");
		પાછા -1;
	}
	જો ((r = sshpkt_start(ssh, SSH2_સંદેશ_GLOBAL_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh,
	    "cancel-streamlocal-forward@openssh.com")) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 || /* want reply */
	    (r = sshpkt_put_cstring(ssh, path)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send cancel");

	fwd_perm_clear(perm); /* unregister */

	પાછા 0;
}

/*
 * Request cancellation of remote forwarding of a connection from local side.
 */
પૂર્ણાંક
channel_request_rforward_cancel(સંરચના ssh *ssh, સંરચના Forward *fwd)
{
	જો (fwd->listen_path != ખાલી) {
		પાછા channel_request_rforward_cancel_streamlocal(ssh,
		    fwd->listen_path);
	} નહીંતર {
		પાછા channel_request_rforward_cancel_tcpip(ssh,
		    fwd->listen_host,
		    fwd->listen_port ? fwd->listen_port : fwd->allocated_port);
	}
}

/*
 * Permits opening to any host/port if permitted_user[] is empty.  This is
 * usually called by the server, because the user could connect to any port
 * anyway, and the server has no way to know but to trust the client anyway.
 */
શૂન્ય
channel_permit_all(સંરચના ssh *ssh, પૂર્ણાંક where)
{
	સંરચના permission_set *pset = permission_set_get(ssh, where);

	જો (pset->અંક_permitted_user == 0)
		pset->all_permitted = 1;
}

/*
 * Permit the specified host/port for forwarding.
 */
શૂન્ય
channel_add_permission(સંરચના ssh *ssh, પૂર્ણાંક who, પૂર્ણાંક where,
    અક્ષર *host, પૂર્ણાંક port)
{
	પૂર્ણાંક local = where == FORWARD_LOCAL;
	સંરચના permission_set *pset = permission_set_get(ssh, where);

	debug("allow %s forwarding to host %s port %d",
	    fwd_ident(who, where), host, port);
	/*
	 * Remote forwards set listen_host/port, local forwards set
	 * host/port_to_connect.
	 */
	permission_set_add(ssh, who, where,
	    local ? host : ખાલી, local ? port : 0,
	    local ? ખાલી : host, ખાલી, local ? 0 : port, ખાલી);
	pset->all_permitted = 0;
}

/*
 * Administratively disable forwarding.
 */
શૂન્ય
channel_disable_admin(સંરચના ssh *ssh, પૂર્ણાંક where)
{
	channel_clear_permission(ssh, FORWARD_ADM, where);
	permission_set_add(ssh, FORWARD_ADM, where,
	    ખાલી, 0, ખાલી, ખાલી, 0, ખાલી);
}

/*
 * Clear a list of permitted opens.
 */
શૂન્ય
channel_clear_permission(સંરચના ssh *ssh, પૂર્ણાંક who, પૂર્ણાંક where)
{
	સંરચના permission **permp;
	u_int i, *npermp;

	permission_set_get_array(ssh, who, where, &permp, &npermp);
	માટે (i = 0; i < *npermp; i++)
		fwd_perm_clear((*permp) + i);
	મુક્ત(*permp);
	*permp = ખાલી;
	*npermp = 0;
}

/*
 * Update the listen port for a dynamic remote forward, after
 * the actual 'newport' has been allocated. If 'newport' < 0 is
 * passed then they entry will be invalidated.
 */
શૂન્ય
channel_update_permission(સંરચના ssh *ssh, પૂર્ણાંક idx, પૂર્ણાંક newport)
{
	સંરચના permission_set *pset = &ssh->chanctxt->local_perms;

	જો (idx < 0 || (u_int)idx >= pset->અંક_permitted_user) {
		debug_f("index out of range: %d num_permitted_user %d",
		    idx, pset->અંક_permitted_user);
		પાછા;
	}
	debug("%s allowed port %d for forwarding to host %s port %d",
	    newport > 0 ? "Updating" : "Removing",
	    newport,
	    pset->permitted_user[idx].host_to_connect,
	    pset->permitted_user[idx].port_to_connect);
	જો (newport <= 0)
		fwd_perm_clear(&pset->permitted_user[idx]);
	નહીંતર {
		pset->permitted_user[idx].listen_port =
		    (ssh->compat & SSH_BUG_DYNAMIC_RPORT) ? 0 : newport;
	}
}

/* Try to start non-blocking connect to next host in cctx list */
સ્થિર પૂર્ણાંક
connect_next(સંરચના ssh *ssh, સંરચના channel_connect *cctx)
{
	પૂર્ણાંક sock, sock_is_network, saved_errno;
	સંરચના sockaddr_un *sunaddr;
	અક્ષર ntop[NI_MAXHOST];
	અક્ષર strport[MAXIMUM(NI_MAXSERV, કદ(sunaddr->sun_path))];

	માટે (; cctx->ai; cctx->ai = cctx->ai->ai_next) {
		sock_is_network = 0;
		પસંદગી (cctx->ai->ai_family) {
		સ્થિતિ AF_UNIX:
			/* unix:pathname instead of host:port */
			sunaddr = (સંરચના sockaddr_un *)cctx->ai->ai_addr;
			strlcpy(ntop, "unix", કદ(ntop));
			strlcpy(strport, sunaddr->sun_path, કદ(strport));
			તોડો;
		સ્થિતિ AF_INET:
		સ્થિતિ AF_INET6:
			જો (getnameinfo(cctx->ai->ai_addr, cctx->ai->ai_addrlen,
			    ntop, કદ(ntop), strport, કદ(strport),
			    NI_NUMERICHOST|NI_NUMERICSERV) != 0) {
				error_f("getnameinfo failed");
				ચાલુ;
			}
			sock_is_network = 1;
			તોડો;
		મૂળભૂત:
			ચાલુ;
		}
		debug_f("start for host %.100s ([%.100s]:%s)",
		    cctx->host, ntop, strport);
		જો ((sock = socket(cctx->ai->ai_family, cctx->ai->ai_socktype,
		    cctx->ai->ai_protocol)) == -1) {
			જો (cctx->ai->ai_next == ખાલી)
				error("socket: %.100s", strerror(errno));
			નહીંતર
				verbose("socket: %.100s", strerror(errno));
			ચાલુ;
		}
		જો (set_nonblock(sock) == -1)
			fatal_f("set_nonblock(%d)", sock);
		જો (sock_is_network && ssh->chanctxt->want_tcp_keepalive)
			set_keepalive(sock); /* logs errors */
		જો (connect(sock, cctx->ai->ai_addr,
		    cctx->ai->ai_addrlen) == -1 && errno != EINPROGRESS) {
			debug_f("host %.100s ([%.100s]:%s): %.100s",
			    cctx->host, ntop, strport, strerror(errno));
			saved_errno = errno;
			close(sock);
			errno = saved_errno;
			ચાલુ;	/* fail -- try next */
		}
		જો (cctx->ai->ai_family != AF_UNIX)
			set_nodelay(sock);
		debug_f("connect host %.100s ([%.100s]:%s) in progress, fd=%d",
		    cctx->host, ntop, strport, sock);
		cctx->ai = cctx->ai->ai_next;
		પાછા sock;
	}
	પાછા -1;
}

/*
 * Return connecting socket to remote host:port or local socket path,
 * passing back the failure reason if appropriate.
 */
સ્થિર પૂર્ણાંક
connect_to_helper(સંરચના ssh *ssh, અચલ અક્ષર *name, પૂર્ણાંક port, પૂર્ણાંક socktype,
    અક્ષર *ctype, અક્ષર *rname, સંરચના channel_connect *cctx,
    પૂર્ણાંક *reason, અચલ અક્ષર **errmsg)
{
	સંરચના addrinfo hints;
	પૂર્ણાંક gaierr;
	પૂર્ણાંક sock = -1;
	અક્ષર strport[NI_MAXSERV];

	જો (port == PORT_STREAMLOCAL) {
		સંરચના sockaddr_un *sunaddr;
		સંરચના addrinfo *ai;

		જો (strlen(name) > કદ(sunaddr->sun_path)) {
			error("%.100s: %.100s", name, strerror(ENAMETOOLONG));
			પાછા -1;
		}

		/*
		 * Fake up a struct addrinfo for AF_UNIX connections.
		 * free_connect_ctx() must check ai_family
		 * and use free() not freeaddrinfo() for AF_UNIX.
		 */
		ai = xcalloc(1, કદ(*ai) + કદ(*sunaddr));
		ai->ai_addr = (સંરચના sockaddr *)(ai + 1);
		ai->ai_addrlen = કદ(*sunaddr);
		ai->ai_family = AF_UNIX;
		ai->ai_socktype = socktype;
		ai->ai_protocol = PF_UNSPEC;
		sunaddr = (સંરચના sockaddr_un *)ai->ai_addr;
		sunaddr->sun_family = AF_UNIX;
		strlcpy(sunaddr->sun_path, name, કદ(sunaddr->sun_path));
		cctx->aitop = ai;
	} નહીંતર {
		memset(&hints, 0, કદ(hints));
		hints.ai_family = ssh->chanctxt->IPv4or6;
		hints.ai_socktype = socktype;
		snprintf(strport, કદ strport, "%d", port);
		જો ((gaierr = getaddrinfo(name, strport, &hints, &cctx->aitop))
		    != 0) {
			જો (errmsg != ખાલી)
				*errmsg = ssh_gai_strerror(gaierr);
			જો (reason != ખાલી)
				*reason = SSH2_OPEN_CONNECT_FAILED;
			error("connect_to %.100s: unknown host (%s)", name,
			    ssh_gai_strerror(gaierr));
			પાછા -1;
		}
	}

	cctx->host = xstrdup(name);
	cctx->port = port;
	cctx->ai = cctx->aitop;

	જો ((sock = connect_next(ssh, cctx)) == -1) {
		error("connect to %.100s port %d failed: %s",
		    name, port, strerror(errno));
		પાછા -1;
	}

	પાછા sock;
}

/* Return CONNECTING channel to remote host:port or local socket path */
સ્થિર Channel *
connect_to(સંરચના ssh *ssh, અચલ અક્ષર *host, પૂર્ણાંક port,
    અક્ષર *ctype, અક્ષર *rname)
{
	સંરચના channel_connect cctx;
	Channel *c;
	પૂર્ણાંક sock;

	memset(&cctx, 0, કદ(cctx));
	sock = connect_to_helper(ssh, host, port, SOCK_STREAM, ctype, rname,
	    &cctx, ખાલી, ખાલી);
	જો (sock == -1) {
		free_connect_ctx(&cctx);
		પાછા ખાલી;
	}
	c = channel_new(ssh, ctype, SSH_CHANNEL_CONNECTING, sock, sock, -1,
	    CHAN_TCP_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, rname, 1);
	c->host_port = port;
	c->path = xstrdup(host);
	c->connect_ctx = xmalloc(કદ(cctx));
	memcpy(c->connect_ctx, &cctx, કદ(cctx));

	પાછા c;
}

/*
 * returns either the newly connected channel or the downstream channel
 * that needs to deal with this connection.
 */
Channel *
channel_connect_by_listen_address(સંરચના ssh *ssh, અચલ અક્ષર *listen_host,
    u_short listen_port, અક્ષર *ctype, અક્ષર *rname)
{
	સંરચના ssh_channels *sc = ssh->chanctxt;
	સંરચના permission_set *pset = &sc->local_perms;
	u_int i;
	સંરચના permission *perm;

	માટે (i = 0; i < pset->અંક_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		જો (open_listen_match_tcpip(perm,
		    listen_host, listen_port, 1)) {
			જો (perm->downstream)
				પાછા perm->downstream;
			જો (perm->port_to_connect == 0)
				પાછા rdynamic_connect_prepare(ssh,
				    ctype, rname);
			પાછા connect_to(ssh,
			    perm->host_to_connect, perm->port_to_connect,
			    ctype, rname);
		}
	}
	error("WARNING: Server requests forwarding for unknown listen_port %d",
	    listen_port);
	પાછા ખાલી;
}

Channel *
channel_connect_by_listen_path(સંરચના ssh *ssh, અચલ અક્ષર *path,
    અક્ષર *ctype, અક્ષર *rname)
{
	સંરચના ssh_channels *sc = ssh->chanctxt;
	સંરચના permission_set *pset = &sc->local_perms;
	u_int i;
	સંરચના permission *perm;

	માટે (i = 0; i < pset->અંક_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		જો (open_listen_match_streamlocal(perm, path)) {
			પાછા connect_to(ssh,
			    perm->host_to_connect, perm->port_to_connect,
			    ctype, rname);
		}
	}
	error("WARNING: Server requests forwarding for unknown path %.100s",
	    path);
	પાછા ખાલી;
}

/* Check if connecting to that port is permitted and connect. */
Channel *
channel_connect_to_port(સંરચના ssh *ssh, અચલ અક્ષર *host, u_short port,
    અક્ષર *ctype, અક્ષર *rname, પૂર્ણાંક *reason, અચલ અક્ષર **errmsg)
{
	સંરચના ssh_channels *sc = ssh->chanctxt;
	સંરચના permission_set *pset = &sc->local_perms;
	સંરચના channel_connect cctx;
	Channel *c;
	u_int i, permit, permit_adm = 1;
	પૂર્ણાંક sock;
	સંરચના permission *perm;

	permit = pset->all_permitted;
	જો (!permit) {
		માટે (i = 0; i < pset->અંક_permitted_user; i++) {
			perm = &pset->permitted_user[i];
			જો (open_match(perm, host, port)) {
				permit = 1;
				તોડો;
			}
		}
	}

	જો (pset->અંક_permitted_admin > 0) {
		permit_adm = 0;
		માટે (i = 0; i < pset->અંક_permitted_admin; i++) {
			perm = &pset->permitted_admin[i];
			જો (open_match(perm, host, port)) {
				permit_adm = 1;
				તોડો;
			}
		}
	}

	જો (!permit || !permit_adm) {
		logit("Received request from %.100s port %d to connect to "
		    "host %.100s port %d, but the request was denied.",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh), host, port);
		જો (reason != ખાલી)
			*reason = SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED;
		પાછા ખાલી;
	}

	memset(&cctx, 0, કદ(cctx));
	sock = connect_to_helper(ssh, host, port, SOCK_STREAM, ctype, rname,
	    &cctx, reason, errmsg);
	જો (sock == -1) {
		free_connect_ctx(&cctx);
		પાછા ખાલી;
	}

	c = channel_new(ssh, ctype, SSH_CHANNEL_CONNECTING, sock, sock, -1,
	    CHAN_TCP_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, rname, 1);
	c->host_port = port;
	c->path = xstrdup(host);
	c->connect_ctx = xmalloc(કદ(cctx));
	memcpy(c->connect_ctx, &cctx, કદ(cctx));

	પાછા c;
}

/* Check if connecting to that path is permitted and connect. */
Channel *
channel_connect_to_path(સંરચના ssh *ssh, અચલ અક્ષર *path,
    અક્ષર *ctype, અક્ષર *rname)
{
	સંરચના ssh_channels *sc = ssh->chanctxt;
	સંરચના permission_set *pset = &sc->local_perms;
	u_int i, permit, permit_adm = 1;
	સંરચના permission *perm;

	permit = pset->all_permitted;
	જો (!permit) {
		માટે (i = 0; i < pset->અંક_permitted_user; i++) {
			perm = &pset->permitted_user[i];
			જો (open_match(perm, path, PORT_STREAMLOCAL)) {
				permit = 1;
				તોડો;
			}
		}
	}

	જો (pset->અંક_permitted_admin > 0) {
		permit_adm = 0;
		માટે (i = 0; i < pset->અંક_permitted_admin; i++) {
			perm = &pset->permitted_admin[i];
			જો (open_match(perm, path, PORT_STREAMLOCAL)) {
				permit_adm = 1;
				તોડો;
			}
		}
	}

	જો (!permit || !permit_adm) {
		logit("Received request to connect to path %.100s, "
		    "but the request was denied.", path);
		પાછા ખાલી;
	}
	પાછા connect_to(ssh, path, PORT_STREAMLOCAL, ctype, rname);
}

શૂન્ય
channel_send_window_changes(સંરચના ssh *ssh)
{
	સંરચના ssh_channels *sc = ssh->chanctxt;
	સંરચના winsize ws;
	પૂર્ણાંક r;
	u_int i;

	માટે (i = 0; i < sc->channels_alloc; i++) {
		જો (sc->channels[i] == ખાલી || !sc->channels[i]->client_tty ||
		    sc->channels[i]->type != SSH_CHANNEL_OPEN)
			ચાલુ;
		જો (ioctl(sc->channels[i]->rfd, TIOCGWINSZ, &ws) == -1)
			ચાલુ;
		channel_request_start(ssh, i, "window-change", 0);
		જો ((r = sshpkt_put_u32(ssh, (u_int)ws.ws_col)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_row)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_xpixel)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_ypixel)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "channel %u; send window-change", i);
	}
}

/* Return RDYNAMIC_OPEN channel: channel allows SOCKS, but is not connected */
સ્થિર Channel *
rdynamic_connect_prepare(સંરચના ssh *ssh, અક્ષર *ctype, અક્ષર *rname)
{
	Channel *c;
	પૂર્ણાંક r;

	c = channel_new(ssh, ctype, SSH_CHANNEL_RDYNAMIC_OPEN, -1, -1, -1,
	    CHAN_TCP_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, rname, 1);
	c->host_port = 0;
	c->path = ખાલી;

	/*
	 * We need to open the channel before we have a FD,
	 * so that we can get SOCKS header from peer.
	 */
	જો ((r = sshpkt_start(ssh, SSH2_સંદેશ_CHANNEL_OPEN_CONFIRMATION)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_window)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0)
		fatal_fr(r, "channel %i; confirm", c->self);
	પાછા c;
}

/* Return CONNECTING socket to remote host:port or local socket path */
સ્થિર પૂર્ણાંક
rdynamic_connect_finish(સંરચના ssh *ssh, Channel *c)
{
	સંરચના ssh_channels *sc = ssh->chanctxt;
	સંરચના permission_set *pset = &sc->local_perms;
	સંરચના permission *perm;
	સંરચના channel_connect cctx;
	u_int i, permit_adm = 1;
	પૂર્ણાંક sock;

	જો (pset->અંક_permitted_admin > 0) {
		permit_adm = 0;
		માટે (i = 0; i < pset->અંક_permitted_admin; i++) {
			perm = &pset->permitted_admin[i];
			જો (open_match(perm, c->path, c->host_port)) {
				permit_adm = 1;
				તોડો;
			}
		}
	}
	જો (!permit_adm) {
		debug_f("requested forward not permitted");
		પાછા -1;
	}

	memset(&cctx, 0, કદ(cctx));
	sock = connect_to_helper(ssh, c->path, c->host_port, SOCK_STREAM, ખાલી,
	    ખાલી, &cctx, ખાલી, ખાલી);
	જો (sock == -1)
		free_connect_ctx(&cctx);
	નહીંતર {
		/* similar to SSH_CHANNEL_CONNECTING but we've already sent the open */
		c->type = SSH_CHANNEL_RDYNAMIC_FINISH;
		c->connect_ctx = xmalloc(કદ(cctx));
		memcpy(c->connect_ctx, &cctx, કદ(cctx));
		channel_register_fds(ssh, c, sock, sock, -1, 0, 1, 0);
	}
	પાછા sock;
}

/* -- X11 forwarding */

/*
 * Creates an internet domain socket for listening for X11 connections.
 * Returns 0 and a suitable display number for the DISPLAY variable
 * stored in display_numberp , or -1 if an error occurs.
 */
પૂર્ણાંક
x11_create_display_inet(સંરચના ssh *ssh, પૂર્ણાંક x11_display_offset,
    પૂર્ણાંક x11_use_localhost, પૂર્ણાંક single_connection,
    u_int *display_numberp, પૂર્ણાંક **chanids)
{
	Channel *nc = ખાલી;
	પૂર્ણાંક display_સંખ્યા, sock, port;
	સંરચના addrinfo hints, *ai, *aitop;
	અક્ષર strport[NI_MAXSERV];
	પૂર્ણાંક gaierr, n, અંક_socks = 0, socks[અંક_SOCKS];

	જો (chanids == ખાલી || x11_display_offset < 0 ||
	    x11_display_offset > UINT16_MAX - X11_BASE_PORT - MAX_DISPLAYS)
		પાછા -1;

	માટે (display_સંખ્યા = x11_display_offset;
	    display_સંખ્યા < x11_display_offset + MAX_DISPLAYS;
	    display_સંખ્યા++) {
		port = X11_BASE_PORT + display_સંખ્યા;
		memset(&hints, 0, કદ(hints));
		hints.ai_family = ssh->chanctxt->IPv4or6;
		hints.ai_flags = x11_use_localhost ? 0: AI_PASSIVE;
		hints.ai_socktype = SOCK_STREAM;
		snprintf(strport, કદ strport, "%d", port);
		જો ((gaierr = getaddrinfo(ખાલી, strport,
		    &hints, &aitop)) != 0) {
			error("getaddrinfo: %.100s", ssh_gai_strerror(gaierr));
			પાછા -1;
		}
		માટે (ai = aitop; ai; ai = ai->ai_next) {
			જો (ai->ai_family != AF_INET &&
			    ai->ai_family != AF_INET6)
				ચાલુ;
			sock = socket(ai->ai_family, ai->ai_socktype,
			    ai->ai_protocol);
			જો (sock == -1) {
				જો ((errno != EINVAL) && (errno != EAFNOSUPPORT)
#ifdef EPFNOSUPPORT
				    && (errno != EPFNOSUPPORT)
#endif 
				    ) {
					error("socket: %.100s", strerror(errno));
					freeaddrinfo(aitop);
					પાછા -1;
				} નહીંતર {
					debug("x11_create_display_inet: Socket family %d not supported",
						 ai->ai_family);
					ચાલુ;
				}
			}
			જો (ai->ai_family == AF_INET6)
				sock_set_v6only(sock);
			જો (x11_use_localhost)
				set_reuseaddr(sock);
			જો (bind(sock, ai->ai_addr, ai->ai_addrlen) == -1) {
				debug2_f("bind port %d: %.100s", port,
				    strerror(errno));
				close(sock);
				માટે (n = 0; n < અંક_socks; n++)
					close(socks[n]);
				અંક_socks = 0;
				તોડો;
			}
			socks[અંક_socks++] = sock;
			જો (અંક_socks == અંક_SOCKS)
				તોડો;
		}
		freeaddrinfo(aitop);
		જો (અંક_socks > 0)
			તોડો;
	}
	જો (display_સંખ્યા >= x11_display_offset + MAX_DISPLAYS) {
		error("Failed to allocate internet-domain X11 display socket.");
		પાછા -1;
	}
	/* Start listening for connections on the socket. */
	માટે (n = 0; n < અંક_socks; n++) {
		sock = socks[n];
		જો (listen(sock, SSH_LISTEN_BACKLOG) == -1) {
			error("listen: %.100s", strerror(errno));
			close(sock);
			પાછા -1;
		}
	}

	/* Allocate a channel for each socket. */
	*chanids = xcalloc(અંક_socks + 1, કદ(**chanids));
	માટે (n = 0; n < અંક_socks; n++) {
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
	*display_numberp = display_સંખ્યા;
	પાછા 0;
}

સ્થિર પૂર્ણાંક
connect_local_xsocket_path(અચલ અક્ષર *pathname)
{
	પૂર્ણાંક sock;
	સંરચના sockaddr_un addr;

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	જો (sock == -1) {
		error("socket: %.100s", strerror(errno));
		પાછા -1;
	}
	memset(&addr, 0, કદ(addr));
	addr.sun_family = AF_UNIX;
	strlcpy(addr.sun_path, pathname, કદ addr.sun_path);
	જો (connect(sock, (સંરચના sockaddr *)&addr, કદ(addr)) == 0)
		પાછા sock;
	close(sock);
	error("connect %.100s: %.100s", addr.sun_path, strerror(errno));
	પાછા -1;
}

સ્થિર પૂર્ણાંક
connect_local_xsocket(u_int dnr)
{
	અક્ષર buf[1024];
	snprintf(buf, કદ buf, _PATH_UNIX_X, dnr);
	પાછા connect_local_xsocket_path(buf);
}

#ifdef __APPLE__
સ્થિર પૂર્ણાંક
is_path_to_xsocket(અચલ અક્ષર *display, અક્ષર *path, size_t pathlen)
{
	સંરચના stat sbuf;

	જો (strlcpy(path, display, pathlen) >= pathlen) {
		error_f("display path too long");
		પાછા 0;
	}
	જો (display[0] != '/')
		પાછા 0;
	જો (stat(path, &sbuf) == 0) {
		પાછા 1;
	} નહીંતર {
		અક્ષર *dot = strrchr(path, '.');
		જો (dot != ખાલી) {
			*dot = '\0';
			જો (stat(path, &sbuf) == 0) {
				પાછા 1;
			}
		}
	}
	પાછા 0;
}
#endif

પૂર્ણાંક
x11_connect_display(સંરચના ssh *ssh)
{
	u_int display_સંખ્યા;
	અચલ અક્ષર *display;
	અક્ષર buf[1024], *cp;
	સંરચના addrinfo hints, *ai, *aitop;
	અક્ષર strport[NI_MAXSERV];
	પૂર્ણાંક gaierr, sock = 0;

	/* Try to open a socket for the local X server. */
	display = getenv("DISPLAY");
	જો (!display) {
		error("DISPLAY not set.");
		પાછા -1;
	}
	/*
	 * Now we decode the value of the DISPLAY variable and make a
	 * connection to the real X server.
	 */

#ifdef __APPLE__
	/* Check if display is a path to a socket (as set by launchd). */
	{
		અક્ષર path[PATH_MAX];

		જો (is_path_to_xsocket(display, path, કદ(path))) {
			debug("x11_connect_display: $DISPLAY is launchd");

			/* Create a socket. */
			sock = connect_local_xsocket_path(path);
			જો (sock < 0)
				પાછા -1;

			/* OK, we now have a connection to the display. */
			પાછા sock;
		}
	}
#endif
	/*
	 * Check if it is a unix domain socket.  Unix domain displays are in
	 * one of the following formats: unix:d[.s], :d[.s], ::d[.s]
	 */
	જો (strncmp(display, "unix:", 5) == 0 ||
	    display[0] == ':') {
		/* Connect to the unix domain socket. */
		જો (sscanf(strrchr(display, ':') + 1, "%u",
		    &display_સંખ્યા) != 1) {
			error("Could not parse display number from DISPLAY: "
			    "%.100s", display);
			પાછા -1;
		}
		/* Create a socket. */
		sock = connect_local_xsocket(display_સંખ્યા);
		જો (sock < 0)
			પાછા -1;

		/* OK, we now have a connection to the display. */
		પાછા sock;
	}
	/*
	 * Connect to an inet socket.  The DISPLAY value is supposedly
	 * hostname:d[.s], where hostname may also be numeric IP address.
	 */
	strlcpy(buf, display, કદ(buf));
	cp = strchr(buf, ':');
	જો (!cp) {
		error("Could not find ':' in DISPLAY: %.100s", display);
		પાછા -1;
	}
	*cp = 0;
	/*
	 * buf now contains the host name.  But first we parse the
	 * display number.
	 */
	જો (sscanf(cp + 1, "%u", &display_સંખ્યા) != 1 ||
	    display_સંખ્યા > UINT16_MAX - X11_BASE_PORT) {
		error("Could not parse display number from DISPLAY: %.100s",
		    display);
		પાછા -1;
	}

	/* Look up the host address */
	memset(&hints, 0, કદ(hints));
	hints.ai_family = ssh->chanctxt->IPv4or6;
	hints.ai_socktype = SOCK_STREAM;
	snprintf(strport, કદ strport, "%u", X11_BASE_PORT + display_સંખ્યા);
	જો ((gaierr = getaddrinfo(buf, strport, &hints, &aitop)) != 0) {
		error("%.100s: unknown host. (%s)", buf,
		ssh_gai_strerror(gaierr));
		પાછા -1;
	}
	માટે (ai = aitop; ai; ai = ai->ai_next) {
		/* Create a socket. */
		sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		જો (sock == -1) {
			debug2("socket: %.100s", strerror(errno));
			ચાલુ;
		}
		/* Connect it to the display. */
		જો (connect(sock, ai->ai_addr, ai->ai_addrlen) == -1) {
			debug2("connect %.100s port %u: %.100s", buf,
			    X11_BASE_PORT + display_સંખ્યા, strerror(errno));
			close(sock);
			ચાલુ;
		}
		/* Success */
		તોડો;
	}
	freeaddrinfo(aitop);
	જો (!ai) {
		error("connect %.100s port %u: %.100s", buf,
		    X11_BASE_PORT + display_સંખ્યા, strerror(errno));
		પાછા -1;
	}
	set_nodelay(sock);
	પાછા sock;
}

/*
 * Requests forwarding of X11 connections, generates fake authentication
 * data, and enables authentication spoofing.
 * This should be called in the client only.
 */
શૂન્ય
x11_request_forwarding_with_spoofing(સંરચના ssh *ssh, પૂર્ણાંક client_session_id,
    અચલ અક્ષર *disp, અચલ અક્ષર *proto, અચલ અક્ષર *data, પૂર્ણાંક want_reply)
{
	સંરચના ssh_channels *sc = ssh->chanctxt;
	u_int data_len = (u_int) strlen(data) / 2;
	u_int i, કિંમત;
	અચલ અક્ષર *cp;
	અક્ષર *new_data;
	પૂર્ણાંક r, screen_સંખ્યા;

	જો (sc->x11_saved_display == ખાલી)
		sc->x11_saved_display = xstrdup(disp);
	નહીંતર જો (strcmp(disp, sc->x11_saved_display) != 0) {
		error("x11_request_forwarding_with_spoofing: different "
		    "$DISPLAY already forwarded");
		પાછા;
	}

	cp = strchr(disp, ':');
	જો (cp)
		cp = strchr(cp, '.');
	જો (cp)
		screen_સંખ્યા = (u_int)strtonum(cp + 1, 0, 400, ખાલી);
	નહીંતર
		screen_સંખ્યા = 0;

	જો (sc->x11_saved_proto == ખાલી) {
		/* Save protocol name. */
		sc->x11_saved_proto = xstrdup(proto);

		/* Extract real authentication data. */
		sc->x11_saved_data = xmalloc(data_len);
		માટે (i = 0; i < data_len; i++) {
			જો (sscanf(data + 2 * i, "%2x", &કિંમત) != 1) {
				fatal("x11_request_forwarding: bad "
				    "authentication data: %.100s", data);
			}
			sc->x11_saved_data[i] = કિંમત;
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
	જો ((r = sshpkt_put_u8(ssh, 0)) != 0 || /* bool: single connection */
	    (r = sshpkt_put_cstring(ssh, proto)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, new_data)) != 0 ||
	    (r = sshpkt_put_u32(ssh, screen_સંખ્યા)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send x11-req");
	મુક્ત(new_data);
}

/*
 * Returns whether an x11 channel was used recently (less than a second ago)
 */
પૂર્ણાંક
x11_channel_used_recently(સંરચના ssh *ssh) {
	u_int i;
	Channel *c;
	દ્વિગુણ lastused = 0;

	માટે (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		જો (c == ખાલી || c->ctype == ખાલી || c->lastused == 0.0 ||
		    strcmp(c->ctype, "x11-connection") != 0)
			ચાલુ;
		જો (c->lastused > lastused)
			lastused = c->lastused;
	}
	પાછા lastused != 0.0 && monotime_double() <= lastused + 1.0;
}
