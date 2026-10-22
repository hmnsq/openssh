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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/stat.h>
#ಅನ್ತರ್ಭಾವ <sys/ioctl.h>
#ಅನ್ತರ್ಭಾವ <sys/un.h>
#ಅನ್ತರ್ಭಾವ <sys/socket.h>
#ಅನ್ತರ್ಭಾವ <sys/queue.h>

#ಅನ್ತರ್ಭಾವ <netinet/in.h>
#ಅನ್ತರ್ಭಾವ <arpa/inet.h>

#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <fcntl.h>
#ಅನ್ತರ್ಭಾವ <limits.h>
#ಅನ್ತರ್ಭಾವ <netdb.h>
#ಅನ್ತರ್ಭಾವ <poll.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <termios.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>

#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "ssh.h"
#ಅನ್ತರ್ಭಾವ "ssh2.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "packet.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "channels.h"
#ಅನ್ತರ್ಭಾವ "compat.h"
#ಅನ್ತರ್ಭಾವ "canohost.h"
#ಅನ್ತರ್ಭಾವ "pathnames.h"
#ಅನ್ತರ್ಭಾವ "match.h"

/* XXX remove once we're satisfied there's no lurking bugs */
/* #define DEBUG_CHANNEL_POLL 1 */

/* -- agent forwarding */
#define	ಅಂಕೆ_SOCKS	10

/* -- X11 forwarding */
/* X11 port for display :0 */
#define X11_BASE_PORT	6000
/* Maximum number of fake X11 displays to try. */
#define MAX_DISPLAYS  1000

/* Per-channel callback for pre/post IO actions */
ಪ್ರಕಾರನಿರ್ದೇಶ ಶೂನ್ಯ chan_fn(ಸಂರಚನಾ ssh *, Channel *c);

/*
 * Data structure for storing which hosts are permitted for forward requests.
 * The local sides of any remote forwards are stored in this array to prevent
 * a corrupt remote server from accessing arbitrary TCP/IP ports on our local
 * network (which might be behind a firewall).
 */
/* XXX: streamlocal wants a path instead of host:port */
/*      Overload host_to_connect; we could just make this match Forward */
/*	XXX - can we use listen_host instead of listen_path? */
ಸಂರಚನಾ permission {
	ವರ್ಣ *host_to_connect;		/* Connect to 'host'. */
	ಪೂರ್ಣಾಙ್ಕ port_to_connect;		/* Connect to 'port'. */
	ವರ್ಣ *listen_host;		/* Remote side should listen address. */
	ವರ್ಣ *listen_path;		/* Remote side should listen path. */
	ಪೂರ್ಣಾಙ್ಕ listen_port;		/* Remote side should listen port. */
	Channel *downstream;		/* Downstream mux*/
};

/* Context for non-blocking connects */
ಸಂರಚನಾ channel_connect {
	ವರ್ಣ *host;
	ಪೂರ್ಣಾಙ್ಕ port;
	ಸಂರಚನಾ addrinfo *ai, *aitop;
};

/*
 * Stores the forwarding permission state for a single direction (local or
 * remote).
 */
ಸಂರಚನಾ permission_set {
	/*
	 * List of all local permitted host/port pairs to allow for the
	 * user.
	 */
	u_int ಅಂಕೆ_permitted_user;
	ಸಂರಚನಾ permission *permitted_user;

	/*
	 * List of all permitted host/port pairs to allow for the admin.
	 */
	u_int ಅಂಕೆ_permitted_admin;
	ಸಂರಚನಾ permission *permitted_admin;

	/*
	 * If this is true, all opens/listens are permitted.  This is the
	 * case on the server on which we have to trust the client anyway,
	 * and the user could do anything after logging in.
	 */
	ಪೂರ್ಣಾಙ್ಕ all_permitted;
};

/* Used to record timeouts per channel type */
ಸಂರಚನಾ ssh_channel_timeout {
	ವರ್ಣ *type_pattern;
	ದ್ವಿಗುಣ timeout_secs;
};

/* Master structure for channels state */
ಸಂರಚನಾ ssh_channels {
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
	ಸಂರಚನಾ permission_set local_perms;
	ಸಂರಚನಾ permission_set remote_perms;

	/* -- X11 forwarding */

	/* Saved X11 local (client) display. */
	ವರ್ಣ *x11_saved_display;

	/* Saved X11 authentication protocol name. */
	ವರ್ಣ *x11_saved_proto;

	/* Saved X11 authentication data.  This is the real data. */
	ವರ್ಣ *x11_saved_data;
	u_int x11_saved_data_len;

	/* Deadline after which all X11 connections are refused */
	ದ್ವಿಗುಣ x11_refuse_time;

	/*
	 * Fake X11 authentication data.  This is what the server will be
	 * sending us; we should replace any occurrences of this by the
	 * real data.
	 */
	u_char *x11_fake_data;
	u_int x11_fake_data_len;

	/* AF_UNSPEC or AF_INET or AF_INET6 */
	ಪೂರ್ಣಾಙ್ಕ IPv4or6;

	/* Set SO_KEEPALIVE on TCP connections */
	ಪೂರ್ಣಾಙ್ಕ want_tcp_keepalive;

	/* Channel timeouts by type */
	ಸಂರಚನಾ ssh_channel_timeout *timeouts;
	size_t ntimeouts;
	/* Global timeout for all OPEN channels */
	ದ್ವಿಗುಣ global_deadline;
	ದ್ವಿಗುಣ lastused;
	/* pattern-lists used to classify channels as bulk */
	ವರ್ಣ *bulk_classifier_tty, *bulk_classifier_notty;
	/* Number of active bulk channels (set by channel_handler) */
	u_int nbulk;
};

/* helper */
ಸ್ಥಿರ ಶೂನ್ಯ port_open_helper(ಸಂರಚನಾ ssh *ssh, Channel *c, ವರ್ಣ *rtype);
ಸ್ಥಿರ ಧ್ರುವ ವರ್ಣ *channel_rfwd_bind_host(ಧ್ರುವ ವರ್ಣ *listen_host);

/* non-blocking connect helpers */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ connect_next(ಸಂರಚನಾ ssh *, ಸಂರಚನಾ channel_connect *);
ಸ್ಥಿರ Channel *rdynamic_connect_prepare(ಸಂರಚನಾ ssh *, ವರ್ಣ *, ವರ್ಣ *);
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ rdynamic_connect_finish(ಸಂರಚನಾ ssh *, Channel *);

/* Setup helper */
ಸ್ಥಿರ ಶೂನ್ಯ channel_handler_init(ಸಂರಚನಾ ssh_channels *sc);

/* -- channel core */

ಶೂನ್ಯ
channel_init_channels(ಸಂರಚನಾ ssh *ssh)
{
	ಸಂರಚನಾ ssh_channels *sc;

	ಯದಿ ((sc = calloc(1, ಪರಿಮಾಣ(*sc))) == ರಿಕ್ತ)
		fatal_f("allocation failed");
	sc->channels_alloc = 10;
	sc->channels = xcalloc(sc->channels_alloc, ಪರಿಮಾಣ(*sc->channels));
	sc->IPv4or6 = AF_UNSPEC;
	sc->bulk_classifier_tty = xstrdup(CHANNEL_BULK_TTY);
	sc->bulk_classifier_notty = xstrdup(CHANNEL_BULK_NOTTY);
	channel_handler_init(sc);

	ssh->chanctxt = sc;
}

Channel *
channel_by_id(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ id)
{
	Channel *c;

	ಯದಿ (id < 0 || (u_int)id >= ssh->chanctxt->channels_alloc) {
		logit_f("%d: bad id", id);
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}
	c = ssh->chanctxt->channels[id];
	ಯದಿ (c == ರಿಕ್ತ) {
		logit_f("%d: bad id: channel free", id);
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}
	ಪ್ರತ್ಯಾಗಮ c;
}

Channel *
channel_by_remote_id(ಸಂರಚನಾ ssh *ssh, u_int remote_id)
{
	Channel *c;
	u_int i;

	ಪ್ರತಿ (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		ಯದಿ (c != ರಿಕ್ತ && c->have_remote_id && c->remote_id == remote_id)
			ಪ್ರತ್ಯಾಗಮ c;
	}
	ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
}

/*
 * Returns the channel if it is allowed to receive protocol messages.
 * Private channels, like listening sockets, may not receive messages.
 */
Channel *
channel_lookup(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ id)
{
	Channel *c;

	ಯದಿ ((c = channel_by_id(ssh, id)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;

	ವಿಕಲ್ಪ (c->type) {
	ಪಕ್ಷ SSH_CHANNEL_X11_OPEN:
	ಪಕ್ಷ SSH_CHANNEL_LARVAL:
	ಪಕ್ಷ SSH_CHANNEL_CONNECTING:
	ಪಕ್ಷ SSH_CHANNEL_DYNAMIC:
	ಪಕ್ಷ SSH_CHANNEL_RDYNAMIC_OPEN:
	ಪಕ್ಷ SSH_CHANNEL_RDYNAMIC_FINISH:
	ಪಕ್ಷ SSH_CHANNEL_OPENING:
	ಪಕ್ಷ SSH_CHANNEL_OPEN:
	ಪಕ್ಷ SSH_CHANNEL_ABANDONED:
	ಪಕ್ಷ SSH_CHANNEL_MUX_PROXY:
		ಪ್ರತ್ಯಾಗಮ c;
	}
	logit("Non-public channel %d, type %d.", id, c->type);
	ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
}

ಸ್ಥಿರ ಶೂನ್ಯ
free_connect_ctx(ಸಂರಚನಾ channel_connect *cctx)
{
	ಮುಕ್ತ(cctx->host);
	ಯದಿ (cctx->aitop) {
		ಯದಿ (cctx->aitop->ai_family == AF_UNIX)
			ಮುಕ್ತ(cctx->aitop);
		ಅನ್ಯಥಾ
			freeaddrinfo(cctx->aitop);
	}
	memset(cctx, 0, ಪರಿಮಾಣ(*cctx));
}

ಸ್ಥಿರ ಶೂನ್ಯ
channel_free_connect_ctx(Channel *c)
{
	ಯದಿ (c == ರಿಕ್ತ || c->connect_ctx == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;
	free_connect_ctx(c->connect_ctx);
	ಮುಕ್ತ(c->connect_ctx);
	c->connect_ctx = ರಿಕ್ತ;
}

/* Enable/disable TCP keepalives for X11 and port-forwarding sockets */
ಶೂನ್ಯ
channel_set_tcp_keepalives(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ on)
{
	ssh->chanctxt->want_tcp_keepalive = on;
}

/*
 * Add a timeout for open channels whose c->ctype (or c->xctype if it is set)
 * match type_pattern.
 */
ಶೂನ್ಯ
channel_add_timeout(ಸಂರಚನಾ ssh *ssh, ಧ್ರುವ ವರ್ಣ *type_pattern,
    ದ್ವಿಗುಣ timeout_secs)
{
	ಸಂರಚನಾ ssh_channels *sc = ssh->chanctxt;

	ಯದಿ (strcmp(type_pattern, "global") == 0) {
		debug2_f("global channel timeout %f seconds", timeout_secs);
		sc->global_deadline = timeout_secs;
		ಪ್ರತ್ಯಾಗಮ;
	}
	debug2_f("channel type \"%s\" timeout %f seconds",
	    type_pattern, timeout_secs);
	sc->timeouts = xrecallocarray(sc->timeouts, sc->ntimeouts,
	    sc->ntimeouts + 1, ಪರಿಮಾಣ(*sc->timeouts));
	sc->timeouts[sc->ntimeouts].type_pattern = xstrdup(type_pattern);
	sc->timeouts[sc->ntimeouts].timeout_secs = timeout_secs;
	sc->ntimeouts++;
}

/* Clears all previously-added channel timeouts */
ಶೂನ್ಯ
channel_clear_timeouts(ಸಂರಚನಾ ssh *ssh)
{
	ಸಂರಚನಾ ssh_channels *sc = ssh->chanctxt;
	size_t i;

	debug3_f("clearing");
	ಪ್ರತಿ (i = 0; i < sc->ntimeouts; i++)
		ಮುಕ್ತ(sc->timeouts[i].type_pattern);
	ಮುಕ್ತ(sc->timeouts);
	sc->timeouts = ರಿಕ್ತ;
	sc->ntimeouts = 0;
}

ಸ್ಥಿರ ದ್ವಿಗುಣ
lookup_timeout(ಸಂರಚನಾ ssh *ssh, ಧ್ರುವ ವರ್ಣ *type)
{
	ಸಂರಚನಾ ssh_channels *sc = ssh->chanctxt;
	size_t i;

	ಪ್ರತಿ (i = 0; i < sc->ntimeouts; i++) {
		ಯದಿ (match_pattern(type, sc->timeouts[i].type_pattern))
			ಪ್ರತ್ಯಾಗಮ sc->timeouts[i].timeout_secs;
	}

	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಶೂನ್ಯ
channel_classify(ಸಂರಚನಾ ssh *ssh, Channel *c)
{
	ಸಂರಚನಾ ssh_channels *sc = ssh->chanctxt;
	ಧ್ರುವ ವರ್ಣ *type = c->xctype == ರಿಕ್ತ ? c->ctype : c->xctype;
	ಧ್ರುವ ಪೂರ್ಣಾಙ್ಕ has_tty = c->isatty || c->remote_has_tty;
	ಧ್ರುವ ವರ್ಣ *classifier = has_tty ?
	    sc->bulk_classifier_tty : sc->bulk_classifier_notty;

	c->bulk = type != ರಿಕ್ತ && match_pattern_list(type, classifier, 0) == 1;
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
ಶೂನ್ಯ
channel_set_xtype(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ id, ಧ್ರುವ ವರ್ಣ *xctype)
{
	ಸಂರಚನಾ ssh_channels *sc = ssh->chanctxt;
	Channel *c;

	ಯದಿ ((c = channel_by_id(ssh, id)) == ರಿಕ್ತ)
		fatal_f("missing channel %d", id);
	ಯದಿ (c->xctype != ರಿಕ್ತ)
		ಮುಕ್ತ(c->xctype);
	c->xctype = xstrdup(xctype);
	/* Only override deadline if xctype has a more specific match. */
	ದ್ವಿಗುಣ xtype_deadline = lookup_timeout(ssh, c->xctype);
	ಯದಿ (xtype_deadline != 0)
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
ಸ್ಥಿರ ಶೂನ್ಯ
channel_set_used_time(ಸಂರಚನಾ ssh *ssh, Channel *c)
{
	ssh->chanctxt->lastused = monotime_double();
	ಯದಿ (c != ರಿಕ್ತ)
		c->lastused = ssh->chanctxt->lastused;
}

/*
 * Get the time at which a channel is due to time out for inactivity.
 * Returns 0 if the channel is not due to time out ever.
 */
ಸ್ಥಿರ ದ್ವಿಗುಣ
channel_get_expiry(ಸಂರಚನಾ ssh *ssh, Channel *c)
{
	ಸಂರಚನಾ ssh_channels *sc = ssh->chanctxt;
	ದ್ವಿಗುಣ expiry = 0, channel_expiry;

	ಯದಿ (sc->lastused != 0 && sc->global_deadline != 0)
		expiry = sc->lastused + sc->global_deadline;
	ಯದಿ (c->lastused != 0 && c->inactive_deadline != 0) {
		channel_expiry = c->lastused + c->inactive_deadline;
		ಯದಿ (expiry == 0 || channel_expiry < expiry)
			expiry = channel_expiry;
	}
	ಪ್ರತ್ಯಾಗಮ expiry;
}

/* Returns non-zero if there is an open, non-interactive channel */
ಪೂರ್ಣಾಙ್ಕ
channel_has_bulk(ಸಂರಚನಾ ssh *ssh)
{
	ಪ್ರತ್ಯಾಗಮ ssh->chanctxt != ರಿಕ್ತ && ssh->chanctxt->nbulk != 0;
}

/*
 * Register filedescriptors for a channel, used when allocating a channel or
 * when the channel consumer/producer is ready, e.g. shell exec'd
 */
ಸ್ಥಿರ ಶೂನ್ಯ
channel_register_fds(ಸಂರಚನಾ ssh *ssh, Channel *c, ಪೂರ್ಣಾಙ್ಕ rfd, ಪೂರ್ಣಾಙ್ಕ wfd, ಪೂರ್ಣಾಙ್ಕ efd,
    ಪೂರ್ಣಾಙ್ಕ extusage, ಪೂರ್ಣಾಙ್ಕ nonblock, ಪೂರ್ಣಾಙ್ಕ is_tty)
{
	ಪೂರ್ಣಾಙ್ಕ val;

	ಯದಿ (rfd != -1)
		(ಶೂನ್ಯ)fcntl(rfd, F_SETFD, FD_CLOEXEC);
	ಯದಿ (wfd != -1 && wfd != rfd)
		(ಶೂನ್ಯ)fcntl(wfd, F_SETFD, FD_CLOEXEC);
	ಯದಿ (efd != -1 && efd != rfd && efd != wfd)
		(ಶೂನ್ಯ)fcntl(efd, F_SETFD, FD_CLOEXEC);

	c->rfd = rfd;
	c->wfd = wfd;
	c->sock = (rfd == wfd) ? rfd : -1;
	c->efd = efd;
	c->extended_usage = extusage;

	ಯದಿ ((c->isatty = is_tty) != 0)
		debug2("channel %d: rfd %d isatty", c->self, c->rfd);
#ifdef _AIX
	/* XXX: Later AIX versions can't push as much data to tty */
	c->wfd_isatty = is_tty || isatty(c->wfd);
#endif

	/* enable nonblocking mode */
	c->restore_block = 0;
	ಯದಿ (nonblock == CHANNEL_NONBLOCK_STDIO) {
		/*
		 * Special handling for stdio file descriptors: do not set
		 * non-blocking mode if they are TTYs. Otherwise prepare to
		 * restore their blocking state on exit to avoid interfering
		 * with other programs that follow.
		 */
		ಯದಿ (rfd != -1 && !isatty(rfd) &&
		    (val = fcntl(rfd, F_GETFL)) != -1 && !(val & O_NONBLOCK)) {
			c->restore_flags[0] = val;
			c->restore_block |= CHANNEL_RESTORE_RFD;
			set_nonblock(rfd);
		}
		ಯದಿ (wfd != -1 && !isatty(wfd) &&
		    (val = fcntl(wfd, F_GETFL)) != -1 && !(val & O_NONBLOCK)) {
			c->restore_flags[1] = val;
			c->restore_block |= CHANNEL_RESTORE_WFD;
			set_nonblock(wfd);
		}
		ಯದಿ (efd != -1 && !isatty(efd) &&
		    (val = fcntl(efd, F_GETFL)) != -1 && !(val & O_NONBLOCK)) {
			c->restore_flags[2] = val;
			c->restore_block |= CHANNEL_RESTORE_EFD;
			set_nonblock(efd);
		}
	} ಅನ್ಯಥಾ ಯದಿ (nonblock) {
		ಯದಿ (rfd != -1)
			set_nonblock(rfd);
		ಯದಿ (wfd != -1)
			set_nonblock(wfd);
		ಯದಿ (efd != -1)
			set_nonblock(efd);
	}
	/* channel might be entering a larval state, so reset global timeout */
	channel_set_used_time(ssh, ರಿಕ್ತ);
	channel_classify(ssh, c);
}

/*
 * Allocate a new channel object and set its type and socket.
 */
Channel *
channel_new(ಸಂರಚನಾ ssh *ssh, ವರ್ಣ *ctype, ಪೂರ್ಣಾಙ್ಕ type, ಪೂರ್ಣಾಙ್ಕ rfd, ಪೂರ್ಣಾಙ್ಕ wfd, ಪೂರ್ಣಾಙ್ಕ efd,
    u_int window, u_int maxpack, ಪೂರ್ಣಾಙ್ಕ extusage, ಧ್ರುವ ವರ್ಣ *remote_name,
    ಪೂರ್ಣಾಙ್ಕ nonblock)
{
	ಸಂರಚನಾ ssh_channels *sc = ssh->chanctxt;
	u_int i, found = 0;
	Channel *c;
	ಪೂರ್ಣಾಙ್ಕ r;

	/* Try to find a free slot where to put the new channel. */
	ಪ್ರತಿ (i = 0; i < sc->channels_alloc; i++) {
		ಯದಿ (sc->channels[i] == ರಿಕ್ತ) {
			/* Found a free slot. */
			found = i;
			ಭಙ್ಗ;
		}
	}
	ಯದಿ (i >= sc->channels_alloc) {
		/*
		 * There are no free slots. Take last+1 slot and expand
		 * the array.
		 */
		found = sc->channels_alloc;
		ಯದಿ (sc->channels_alloc > CHANNELS_MAX_CHANNELS)
			fatal_f("internal error: channels_alloc %d too big",
			    sc->channels_alloc);
		sc->channels = xrecallocarray(sc->channels, sc->channels_alloc,
		    sc->channels_alloc + 10, ಪರಿಮಾಣ(*sc->channels));
		sc->channels_alloc += 10;
		debug2("channel: expanding %d", sc->channels_alloc);
	}
	/* Initialize and return new channel. */
	c = sc->channels[found] = xcalloc(1, ಪರಿಮಾಣ(Channel));
	ಯದಿ ((c->ಒಳಹರಿವು = sshbuf_new()) == ರಿಕ್ತ ||
	    (c->output = sshbuf_new()) == ರಿಕ್ತ ||
	    (c->extended = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	ಯದಿ ((r = sshbuf_set_max_size(c->ಒಳಹರಿವು, CHAN_ಒಳಹರಿವು_MAX)) != 0)
		fatal_fr(r, "sshbuf_set_max_size");
	c->ostate = CHAN_OUTPUT_OPEN;
	c->istate = CHAN_ಒಳಹರಿವು_OPEN;
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
	ಪ್ರತ್ಯಾಗಮ c;
}

ಶೂನ್ಯ
channel_set_tty(ಸಂರಚನಾ ssh *ssh, Channel *c)
{
	c->remote_has_tty = 1;
	channel_classify(ssh, c);
}

ಪೂರ್ಣಾಙ್ಕ
channel_close_fd(ಸಂರಚನಾ ssh *ssh, Channel *c, ಪೂರ್ಣಾಙ್ಕ *fdp)
{
	ಪೂರ್ಣಾಙ್ಕ ret, fd = *fdp;

	ಯದಿ (fd == -1)
		ಪ್ರತ್ಯಾಗಮ 0;

	/* restore blocking */
	ಯದಿ (*fdp == c->rfd &&
	    (c->restore_block & CHANNEL_RESTORE_RFD) != 0)
		(ಶೂನ್ಯ)fcntl(*fdp, F_SETFL, c->restore_flags[0]);
	ಅನ್ಯಥಾ ಯದಿ (*fdp == c->wfd &&
	    (c->restore_block & CHANNEL_RESTORE_WFD) != 0)
		(ಶೂನ್ಯ)fcntl(*fdp, F_SETFL, c->restore_flags[1]);
	ಅನ್ಯಥಾ ಯದಿ (*fdp == c->efd &&
	    (c->restore_block & CHANNEL_RESTORE_EFD) != 0)
		(ಶೂನ್ಯ)fcntl(*fdp, F_SETFL, c->restore_flags[2]);

	ಯದಿ (*fdp == c->rfd) {
		c->io_want &= ~SSH_CHAN_IO_RFD;
		c->io_ready &= ~SSH_CHAN_IO_RFD;
		c->rfd = -1;
		c->pfds[0] = -1;
	}
	ಯದಿ (*fdp == c->wfd) {
		c->io_want &= ~SSH_CHAN_IO_WFD;
		c->io_ready &= ~SSH_CHAN_IO_WFD;
		c->wfd = -1;
		c->pfds[1] = -1;
	}
	ಯದಿ (*fdp == c->efd) {
		c->io_want &= ~SSH_CHAN_IO_EFD;
		c->io_ready &= ~SSH_CHAN_IO_EFD;
		c->efd = -1;
		c->pfds[2] = -1;
	}
	ಯದಿ (*fdp == c->sock) {
		c->io_want &= ~SSH_CHAN_IO_SOCK;
		c->io_ready &= ~SSH_CHAN_IO_SOCK;
		c->sock = -1;
		c->pfds[3] = -1;
	}

	ret = close(fd);
	*fdp = -1; /* probably redundant */
	ಪ್ರತ್ಯಾಗಮ ret;
}

/* Close all channel fd/socket. */
ಸ್ಥಿರ ಶೂನ್ಯ
channel_close_fds(ಸಂರಚನಾ ssh *ssh, Channel *c)
{
	ಪೂರ್ಣಾಙ್ಕ sock = c->sock, rfd = c->rfd, wfd = c->wfd, efd = c->efd;

	channel_close_fd(ssh, c, &c->sock);
	ಯದಿ (rfd != sock)
		channel_close_fd(ssh, c, &c->rfd);
	ಯದಿ (wfd != sock && wfd != rfd)
		channel_close_fd(ssh, c, &c->wfd);
	ಯದಿ (efd != sock && efd != rfd && efd != wfd)
		channel_close_fd(ssh, c, &c->efd);
}

ಸ್ಥಿರ ಶೂನ್ಯ
fwd_perm_clear(ಸಂರಚನಾ permission *perm)
{
	ಮುಕ್ತ(perm->host_to_connect);
	ಮುಕ್ತ(perm->listen_host);
	ಮುಕ್ತ(perm->listen_path);
	memset(perm, 0, ಪರಿಮಾಣ(*perm));
}

/* Returns an printable name for the specified forwarding permission list */
ಸ್ಥಿರ ಧ್ರುವ ವರ್ಣ *
fwd_ident(ಪೂರ್ಣಾಙ್ಕ who, ಪೂರ್ಣಾಙ್ಕ where)
{
	ಯದಿ (who == FORWARD_ADM) {
		ಯದಿ (where == FORWARD_LOCAL)
			ಪ್ರತ್ಯಾಗಮ "admin local";
		ಅನ್ಯಥಾ ಯದಿ (where == FORWARD_REMOTE)
			ಪ್ರತ್ಯಾಗಮ "admin remote";
	} ಅನ್ಯಥಾ ಯದಿ (who == FORWARD_USER) {
		ಯದಿ (where == FORWARD_LOCAL)
			ಪ್ರತ್ಯಾಗಮ "user local";
		ಅನ್ಯಥಾ ಯದಿ (where == FORWARD_REMOTE)
			ಪ್ರತ್ಯಾಗಮ "user remote";
	}
	fatal("Unknown forward permission list %d/%d", who, where);
}

/* Returns the forwarding permission list for the specified direction */
ಸ್ಥಿರ ಸಂರಚನಾ permission_set *
permission_set_get(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ where)
{
	ಸಂರಚನಾ ssh_channels *sc = ssh->chanctxt;

	ವಿಕಲ್ಪ (where) {
	ಪಕ್ಷ FORWARD_LOCAL:
		ಪ್ರತ್ಯಾಗಮ &sc->local_perms;
		ಭಙ್ಗ;
	ಪಕ್ಷ FORWARD_REMOTE:
		ಪ್ರತ್ಯಾಗಮ &sc->remote_perms;
		ಭಙ್ಗ;
	ಸ್ವಭಾವ:
		fatal_f("invalid forwarding direction %d", where);
	}
}

/* Returns pointers to the specified forwarding list and its element count */
ಸ್ಥಿರ ಶೂನ್ಯ
permission_set_get_array(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ who, ಪೂರ್ಣಾಙ್ಕ where,
    ಸಂರಚನಾ permission ***permpp, u_int **npermpp)
{
	ಸಂರಚನಾ permission_set *pset = permission_set_get(ssh, where);

	ವಿಕಲ್ಪ (who) {
	ಪಕ್ಷ FORWARD_USER:
		*permpp = &pset->permitted_user;
		*npermpp = &pset->ಅಂಕೆ_permitted_user;
		ಭಙ್ಗ;
	ಪಕ್ಷ FORWARD_ADM:
		*permpp = &pset->permitted_admin;
		*npermpp = &pset->ಅಂಕೆ_permitted_admin;
		ಭಙ್ಗ;
	ಸ್ವಭಾವ:
		fatal_f("invalid forwarding client %d", who);
	}
}

/* Adds an entry to the specified forwarding list */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
permission_set_add(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ who, ಪೂರ್ಣಾಙ್ಕ where,
    ಧ್ರುವ ವರ್ಣ *host_to_connect, ಪೂರ್ಣಾಙ್ಕ port_to_connect,
    ಧ್ರುವ ವರ್ಣ *listen_host, ಧ್ರುವ ವರ್ಣ *listen_path, ಪೂರ್ಣಾಙ್ಕ listen_port,
    Channel *downstream)
{
	ಸಂರಚನಾ permission **permp;
	u_int n, *npermp;

	permission_set_get_array(ssh, who, where, &permp, &npermp);

	ಯದಿ (*npermp >= INT_MAX)
		fatal_f("%s overflow", fwd_ident(who, where));

	*permp = xrecallocarray(*permp, *npermp, *npermp + 1, ಪರಿಮಾಣ(**permp));
	n = (*npermp)++;
#define MAYBE_DUP(s) ((s == ರಿಕ್ತ) ? ರಿಕ್ತ : xstrdup(s))
	(*permp)[n].host_to_connect = MAYBE_DUP(host_to_connect);
	(*permp)[n].port_to_connect = port_to_connect;
	(*permp)[n].listen_host = MAYBE_DUP(listen_host);
	(*permp)[n].listen_path = MAYBE_DUP(listen_path);
	(*permp)[n].listen_port = listen_port;
	(*permp)[n].downstream = downstream;
#undef MAYBE_DUP
	ಪ್ರತ್ಯಾಗಮ (ಪೂರ್ಣಾಙ್ಕ)n;
}

ಸ್ಥಿರ ಶೂನ್ಯ
mux_remove_remote_forwardings(ಸಂರಚನಾ ssh *ssh, Channel *c)
{
	ಸಂರಚನಾ ssh_channels *sc = ssh->chanctxt;
	ಸಂರಚನಾ permission_set *pset = &sc->local_perms;
	ಸಂರಚನಾ permission *perm;
	ಪೂರ್ಣಾಙ್ಕ r;
	u_int i;

	ಪ್ರತಿ (i = 0; i < pset->ಅಂಕೆ_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		ಯದಿ (perm->downstream != c)
			ಅನುವರ್ತ;

		/* cancel on the server, since mux client is gone */
		debug("channel %d: cleanup remote forward for %s:%u",
		    c->self, perm->listen_host, perm->listen_port);
		ಯದಿ ((r = sshpkt_start(ssh, SSH2_ಸಂದೇಶ_GLOBAL_REQUEST)) != 0 ||
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
ಶೂನ್ಯ
channel_free(ಸಂರಚನಾ ssh *ssh, Channel *c)
{
	ಸಂರಚನಾ ssh_channels *sc = ssh->chanctxt;
	ವರ್ಣ *s;
	u_int i, n;
	Channel *other;
	ಸಂರಚನಾ channel_confirm *cc;

	ಪ್ರತಿ (n = 0, i = 0; i < sc->channels_alloc; i++) {
		ಯದಿ ((other = sc->channels[i]) == ರಿಕ್ತ)
			ಅನುವರ್ತ;
		n++;
		/* detach from mux client and prepare for closing */
		ಯದಿ (c->type == SSH_CHANNEL_MUX_CLIENT &&
		    other->type == SSH_CHANNEL_MUX_PROXY &&
		    other->mux_ctx == c) {
			other->mux_ctx = ರಿಕ್ತ;
			other->type = SSH_CHANNEL_OPEN;
			other->istate = CHAN_ಒಳಹರಿವು_CLOSED;
			other->ostate = CHAN_OUTPUT_CLOSED;
		}
	}
	debug("channel %d: free: %s, nchannels %u", c->self,
	    c->remote_name ? c->remote_name : "???", n);

	ಯದಿ (c->type == SSH_CHANNEL_MUX_CLIENT) {
		mux_remove_remote_forwardings(ssh, c);
		ಮುಕ್ತ(c->mux_ctx);
		c->mux_ctx = ರಿಕ್ತ;
	} ಅನ್ಯಥಾ ಯದಿ (c->type == SSH_CHANNEL_MUX_LISTENER) {
		ಮುಕ್ತ(c->mux_ctx);
		c->mux_ctx = ರಿಕ್ತ;
	}

	ಯದಿ (log_level_get() >= SYSLOG_LEVEL_DEBUG3) {
		s = channel_open_message(ssh);
		debug3("channel %d: status: %s", c->self, s);
		ಮುಕ್ತ(s);
	}

	channel_close_fds(ssh, c);
	sshbuf_free(c->ಒಳಹರಿವು);
	sshbuf_free(c->output);
	sshbuf_free(c->extended);
	c->ಒಳಹರಿವು = c->output = c->extended = ರಿಕ್ತ;
	ಮುಕ್ತ(c->remote_name);
	c->remote_name = ರಿಕ್ತ;
	ಮುಕ್ತ(c->path);
	c->path = ರಿಕ್ತ;
	ಮುಕ್ತ(c->listening_addr);
	c->listening_addr = ರಿಕ್ತ;
	ಮುಕ್ತ(c->xctype);
	c->xctype = ರಿಕ್ತ;
	channel_free_connect_ctx(c);
	ಯಾವತ್ ((cc = TAILQ_FIRST(&c->status_confirms)) != ರಿಕ್ತ) {
		ಯದಿ (cc->abandon_cb != ರಿಕ್ತ)
			cc->abandon_cb(ssh, c, cc->ctx);
		TAILQ_REMOVE(&c->status_confirms, cc, entry);
		freezero(cc, ಪರಿಮಾಣ(*cc));
	}
	ಯದಿ (c->filter_cleanup != ರಿಕ್ತ && c->filter_ctx != ರಿಕ್ತ)
		c->filter_cleanup(ssh, c->self, c->filter_ctx);
	sc->channels[c->self] = ರಿಕ್ತ;
	freezero(c, ಪರಿಮಾಣ(*c));
}

ಶೂನ್ಯ
channel_free_all(ಸಂರಚನಾ ssh *ssh)
{
	u_int i;
	ಸಂರಚನಾ ssh_channels *sc = ssh->chanctxt;

	ಪ್ರತಿ (i = 0; i < sc->channels_alloc; i++)
		ಯದಿ (sc->channels[i] != ರಿಕ್ತ)
			channel_free(ssh, sc->channels[i]);

	ಮುಕ್ತ(sc->channels);
	sc->channels = ರಿಕ್ತ;
	sc->channels_alloc = 0;

	ಮುಕ್ತ(sc->x11_saved_display);
	sc->x11_saved_display = ರಿಕ್ತ;

	ಮುಕ್ತ(sc->x11_saved_proto);
	sc->x11_saved_proto = ರಿಕ್ತ;

	ಮುಕ್ತ(sc->x11_saved_data);
	sc->x11_saved_data = ರಿಕ್ತ;
	sc->x11_saved_data_len = 0;

	ಮುಕ್ತ(sc->x11_fake_data);
	sc->x11_fake_data = ರಿಕ್ತ;
	sc->x11_fake_data_len = 0;
}

ಶೂನ್ಯ
channel_free_channels(ಸಂರಚನಾ ssh *ssh)
{
	ಸಂರಚನಾ ssh_channels *sc;

	ಯದಿ (ssh == ರಿಕ್ತ || ssh->chanctxt == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;
	channel_free_all(ssh);
	channel_clear_permission(ssh, FORWARD_USER, FORWARD_LOCAL);
	channel_clear_permission(ssh, FORWARD_USER, FORWARD_REMOTE);
	channel_clear_permission(ssh, FORWARD_ADM, FORWARD_LOCAL);
	channel_clear_permission(ssh, FORWARD_ADM, FORWARD_REMOTE);
	sc = ssh->chanctxt;
	ಮುಕ್ತ(sc->bulk_classifier_tty);
	ಮುಕ್ತ(sc->bulk_classifier_notty);
	ಮುಕ್ತ(sc->channel_pre);
	ಮುಕ್ತ(sc->channel_post);
	freezero(sc, ಪರಿಮಾಣ(*sc));
	ssh->chanctxt = ರಿಕ್ತ;
}

/*
 * Closes the sockets/fds of all channels.  This is used to close extra file
 * descriptors after a fork.
 */
ಶೂನ್ಯ
channel_close_all(ಸಂರಚನಾ ssh *ssh)
{
	u_int i;

	ಪ್ರತಿ (i = 0; i < ssh->chanctxt->channels_alloc; i++)
		ಯದಿ (ssh->chanctxt->channels[i] != ರಿಕ್ತ)
			channel_close_fds(ssh, ssh->chanctxt->channels[i]);
}

/*
 * Stop listening to channels.
 */
ಶೂನ್ಯ
channel_stop_listening(ಸಂರಚನಾ ssh *ssh)
{
	u_int i;
	Channel *c;

	ಪ್ರತಿ (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		ಯದಿ (c != ರಿಕ್ತ) {
			ವಿಕಲ್ಪ (c->type) {
			ಪಕ್ಷ SSH_CHANNEL_AUTH_SOCKET:
			ಪಕ್ಷ SSH_CHANNEL_PORT_LISTENER:
			ಪಕ್ಷ SSH_CHANNEL_RPORT_LISTENER:
			ಪಕ್ಷ SSH_CHANNEL_X11_LISTENER:
			ಪಕ್ಷ SSH_CHANNEL_UNIX_LISTENER:
			ಪಕ್ಷ SSH_CHANNEL_RUNIX_LISTENER:
				channel_close_fd(ssh, c, &c->sock);
				channel_free(ssh, c);
				ಭಙ್ಗ;
			}
		}
	}
}

/*
 * Returns true if no channel has too much buffered data, and false if one or
 * more channel is overfull.
 */
ಪೂರ್ಣಾಙ್ಕ
channel_not_very_much_buffered_data(ಸಂರಚನಾ ssh *ssh)
{
	u_int i;
	u_int maxsize = ssh_packet_get_maxsize(ssh);
	Channel *c;

	ಪ್ರತಿ (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		ಯದಿ (c == ರಿಕ್ತ || c->type != SSH_CHANNEL_OPEN)
			ಅನುವರ್ತ;
		ಯದಿ (sshbuf_len(c->output) > maxsize) {
			debug2("channel %d: big output buffer %zu > %u",
			    c->self, sshbuf_len(c->output), maxsize);
			ಪ್ರತ್ಯಾಗಮ 0;
		}
	}
	ಪ್ರತ್ಯಾಗಮ 1;
}

/* Returns true if any channel is still open. */
ಪೂರ್ಣಾಙ್ಕ
channel_still_open(ಸಂರಚನಾ ssh *ssh)
{
	u_int i;
	Channel *c;

	ಪ್ರತಿ (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		ಯದಿ (c == ರಿಕ್ತ)
			ಅನುವರ್ತ;
		ವಿಕಲ್ಪ (c->type) {
		ಪಕ್ಷ SSH_CHANNEL_X11_LISTENER:
		ಪಕ್ಷ SSH_CHANNEL_PORT_LISTENER:
		ಪಕ್ಷ SSH_CHANNEL_RPORT_LISTENER:
		ಪಕ್ಷ SSH_CHANNEL_MUX_LISTENER:
		ಪಕ್ಷ SSH_CHANNEL_CLOSED:
		ಪಕ್ಷ SSH_CHANNEL_AUTH_SOCKET:
		ಪಕ್ಷ SSH_CHANNEL_DYNAMIC:
		ಪಕ್ಷ SSH_CHANNEL_RDYNAMIC_OPEN:
		ಪಕ್ಷ SSH_CHANNEL_CONNECTING:
		ಪಕ್ಷ SSH_CHANNEL_ZOMBIE:
		ಪಕ್ಷ SSH_CHANNEL_ABANDONED:
		ಪಕ್ಷ SSH_CHANNEL_UNIX_LISTENER:
		ಪಕ್ಷ SSH_CHANNEL_RUNIX_LISTENER:
			ಅನುವರ್ತ;
		ಪಕ್ಷ SSH_CHANNEL_LARVAL:
			ಅನುವರ್ತ;
		ಪಕ್ಷ SSH_CHANNEL_OPENING:
		ಪಕ್ಷ SSH_CHANNEL_OPEN:
		ಪಕ್ಷ SSH_CHANNEL_RDYNAMIC_FINISH:
		ಪಕ್ಷ SSH_CHANNEL_X11_OPEN:
		ಪಕ್ಷ SSH_CHANNEL_MUX_CLIENT:
		ಪಕ್ಷ SSH_CHANNEL_MUX_PROXY:
			ಪ್ರತ್ಯಾಗಮ 1;
		ಸ್ವಭಾವ:
			fatal_f("bad channel type %d", c->type);
			/* NOTREACHED */
		}
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

/* Returns true if a channel with a TTY is open. */
ಪೂರ್ಣಾಙ್ಕ
channel_tty_open(ಸಂರಚನಾ ssh *ssh)
{
	u_int i;
	Channel *c;

	ಪ್ರತಿ (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		ಯದಿ (c == ರಿಕ್ತ || c->type != SSH_CHANNEL_OPEN)
			ಅನುವರ್ತ;
		ಯದಿ (c->client_tty)
			ಪ್ರತ್ಯಾಗಮ 1;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

/* Returns the id of an open channel suitable for keepaliving */
ಪೂರ್ಣಾಙ್ಕ
channel_find_open(ಸಂರಚನಾ ssh *ssh)
{
	u_int i;
	Channel *c;

	ಪ್ರತಿ (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		ಯದಿ (c == ರಿಕ್ತ || !c->have_remote_id)
			ಅನುವರ್ತ;
		ವಿಕಲ್ಪ (c->type) {
		ಪಕ್ಷ SSH_CHANNEL_CLOSED:
		ಪಕ್ಷ SSH_CHANNEL_DYNAMIC:
		ಪಕ್ಷ SSH_CHANNEL_RDYNAMIC_OPEN:
		ಪಕ್ಷ SSH_CHANNEL_RDYNAMIC_FINISH:
		ಪಕ್ಷ SSH_CHANNEL_X11_LISTENER:
		ಪಕ್ಷ SSH_CHANNEL_PORT_LISTENER:
		ಪಕ್ಷ SSH_CHANNEL_RPORT_LISTENER:
		ಪಕ್ಷ SSH_CHANNEL_MUX_LISTENER:
		ಪಕ್ಷ SSH_CHANNEL_MUX_CLIENT:
		ಪಕ್ಷ SSH_CHANNEL_MUX_PROXY:
		ಪಕ್ಷ SSH_CHANNEL_OPENING:
		ಪಕ್ಷ SSH_CHANNEL_CONNECTING:
		ಪಕ್ಷ SSH_CHANNEL_ZOMBIE:
		ಪಕ್ಷ SSH_CHANNEL_ABANDONED:
		ಪಕ್ಷ SSH_CHANNEL_UNIX_LISTENER:
		ಪಕ್ಷ SSH_CHANNEL_RUNIX_LISTENER:
			ಅನುವರ್ತ;
		ಪಕ್ಷ SSH_CHANNEL_LARVAL:
		ಪಕ್ಷ SSH_CHANNEL_AUTH_SOCKET:
		ಪಕ್ಷ SSH_CHANNEL_OPEN:
		ಪಕ್ಷ SSH_CHANNEL_X11_OPEN:
			ಪ್ರತ್ಯಾಗಮ i;
		ಸ್ವಭಾವ:
			fatal_f("bad channel type %d", c->type);
			/* NOTREACHED */
		}
	}
	ಪ್ರತ್ಯಾಗಮ -1;
}

/* Returns the state of the channel's extended usage flag */
ಧ್ರುವ ವರ್ಣ *
channel_format_extended_usage(ಧ್ರುವ Channel *c)
{
	ಯದಿ (c->efd == -1)
		ಪ್ರತ್ಯಾಗಮ "closed";

	ವಿಕಲ್ಪ (c->extended_usage) {
	ಪಕ್ಷ CHAN_EXTENDED_WRITE:
		ಪ್ರತ್ಯಾಗಮ "write";
	ಪಕ್ಷ CHAN_EXTENDED_READ:
		ಪ್ರತ್ಯಾಗಮ "read";
	ಪಕ್ಷ CHAN_EXTENDED_IGNORE:
		ಪ್ರತ್ಯಾಗಮ "ignore";
	ಸ್ವಭಾವ:
		ಪ್ರತ್ಯಾಗಮ "UNKNOWN";
	}
}

ಸ್ಥಿರ ವರ್ಣ *
channel_format_status(ಧ್ರುವ Channel *c)
{
	ವರ್ಣ *ret = ರಿಕ್ತ;

	xasprintf(&ret, "t%d [%s] %s%u %s%u i%u/%zu o%u/%zu e[%s]/%zu "
	    "fd %d/%d/%d sock %d cc %d %s%u io 0x%02x/0x%02x %s%s",
	    c->type, c->xctype != ರಿಕ್ತ ? c->xctype : c->ctype,
	    c->have_remote_id ? "r" : "nr", c->remote_id,
	    c->mux_ctx != ರಿಕ್ತ ? "m" : "nm", c->mux_downstream_id,
	    c->istate, sshbuf_len(c->ಒಳಹರಿವು),
	    c->ostate, sshbuf_len(c->output),
	    channel_format_extended_usage(c), sshbuf_len(c->extended),
	    c->rfd, c->wfd, c->efd, c->sock, c->ctl_chan,
	    c->have_ctl_child_id ? "c" : "nc", c->ctl_child_id,
	    c->io_want, c->io_ready,
	    c->isatty ? "T" : (c->remote_has_tty ? "RT" : ""),
	    c->bulk ? "B" : "I");
	ಪ್ರತ್ಯಾಗಮ ret;
}

/*
 * Returns a message describing the currently open forwarded connections,
 * suitable for sending to the client.  The message contains crlf pairs for
 * newlines.
 */
ವರ್ಣ *
channel_open_message(ಸಂರಚನಾ ssh *ssh)
{
	ಸಂರಚನಾ sshbuf *buf;
	Channel *c;
	u_int i;
	ಪೂರ್ಣಾಙ್ಕ r;
	ವರ್ಣ *cp, *ret;

	ಯದಿ ((buf = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new");
	ಯದಿ ((r = sshbuf_putf(buf,
	    "The following connections are open:\r\n")) != 0)
		fatal_fr(r, "sshbuf_putf");
	ಪ್ರತಿ (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		ಯದಿ (c == ರಿಕ್ತ)
			ಅನುವರ್ತ;
		ವಿಕಲ್ಪ (c->type) {
		ಪಕ್ಷ SSH_CHANNEL_X11_LISTENER:
		ಪಕ್ಷ SSH_CHANNEL_PORT_LISTENER:
		ಪಕ್ಷ SSH_CHANNEL_RPORT_LISTENER:
		ಪಕ್ಷ SSH_CHANNEL_CLOSED:
		ಪಕ್ಷ SSH_CHANNEL_AUTH_SOCKET:
		ಪಕ್ಷ SSH_CHANNEL_ZOMBIE:
		ಪಕ್ಷ SSH_CHANNEL_ABANDONED:
		ಪಕ್ಷ SSH_CHANNEL_MUX_LISTENER:
		ಪಕ್ಷ SSH_CHANNEL_UNIX_LISTENER:
		ಪಕ್ಷ SSH_CHANNEL_RUNIX_LISTENER:
			ಅನುವರ್ತ;
		ಪಕ್ಷ SSH_CHANNEL_LARVAL:
		ಪಕ್ಷ SSH_CHANNEL_OPENING:
		ಪಕ್ಷ SSH_CHANNEL_CONNECTING:
		ಪಕ್ಷ SSH_CHANNEL_DYNAMIC:
		ಪಕ್ಷ SSH_CHANNEL_RDYNAMIC_OPEN:
		ಪಕ್ಷ SSH_CHANNEL_RDYNAMIC_FINISH:
		ಪಕ್ಷ SSH_CHANNEL_OPEN:
		ಪಕ್ಷ SSH_CHANNEL_X11_OPEN:
		ಪಕ್ಷ SSH_CHANNEL_MUX_PROXY:
		ಪಕ್ಷ SSH_CHANNEL_MUX_CLIENT:
			cp = channel_format_status(c);
			ಯದಿ ((r = sshbuf_putf(buf, "  #%d %.300s (%s)\r\n",
			    c->self, c->remote_name, cp)) != 0) {
				ಮುಕ್ತ(cp);
				fatal_fr(r, "sshbuf_putf");
			}
			ಮುಕ್ತ(cp);
			ಅನುವರ್ತ;
		ಸ್ವಭಾವ:
			fatal_f("bad channel type %d", c->type);
			/* NOTREACHED */
		}
	}
	ಯದಿ ((ret = sshbuf_dup_string(buf)) == ರಿಕ್ತ)
		fatal_f("sshbuf_dup_string");
	sshbuf_free(buf);
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಶೂನ್ಯ
channel_report_open(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ level)
{
	ವರ್ಣ *open, *oopen, *cp, ident[256];

	sshpkt_fmt_connection_id(ssh, ident, ಪರಿಮಾಣ(ident));
	do_log2(level, "Connection: %s (pid %ld)", ident, (long)getpid());
	open = oopen = channel_open_message(ssh);
	ಯಾವತ್ ((cp = strsep(&open, "\r\n")) != ರಿಕ್ತ) {
		ಯದಿ (*cp != '\0')
			do_log2(level, "%s", cp);
	}
	ಮುಕ್ತ(oopen);
}

ಸ್ಥಿರ ಶೂನ್ಯ
open_preamble(ಸಂರಚನಾ ssh *ssh, ಧ್ರುವ ವರ್ಣ *where, Channel *c, ಧ್ರುವ ವರ್ಣ *type)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = sshpkt_start(ssh, SSH2_ಸಂದೇಶ_CHANNEL_OPEN)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, type)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_window)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0) {
		fatal_r(r, "%s: channel %i: open", where, c->self);
	}
}

ಶೂನ್ಯ
channel_send_open(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ id)
{
	Channel *c = channel_lookup(ssh, id);
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (c == ರಿಕ್ತ) {
		logit("channel_send_open: %d: bad id", id);
		ಪ್ರತ್ಯಾಗಮ;
	}
	debug2("channel %d: send open", id);
	open_preamble(ssh, __func__, c, c->ctype);
	ಯದಿ ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i", c->self);
}

ಶೂನ್ಯ
channel_request_start(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ id, ಧ್ರುವ ವರ್ಣ *service,
    ಪೂರ್ಣಾಙ್ಕ wantconfirm)
{
	Channel *c = channel_lookup(ssh, id);
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (c == ರಿಕ್ತ) {
		logit_f("%d: unknown channel id", id);
		ಪ್ರತ್ಯಾಗಮ;
	}
	ಯದಿ (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);

	debug2("channel %d: request %s confirm %d", id, service, wantconfirm);
	ಯದಿ ((r = sshpkt_start(ssh, SSH2_ಸಂದೇಶ_CHANNEL_REQUEST)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, service)) != 0 ||
	    (r = sshpkt_put_u8(ssh, wantconfirm)) != 0) {
		fatal_fr(r, "channel %i", c->self);
	}
}

ಶೂನ್ಯ
channel_register_status_confirm(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ id,
    channel_confirm_cb *cb, channel_confirm_abandon_cb *abandon_cb, ಶೂನ್ಯ *ctx)
{
	ಸಂರಚನಾ channel_confirm *cc;
	Channel *c;

	ಯದಿ ((c = channel_lookup(ssh, id)) == ರಿಕ್ತ)
		fatal_f("%d: bad id", id);

	cc = xcalloc(1, ಪರಿಮಾಣ(*cc));
	cc->cb = cb;
	cc->abandon_cb = abandon_cb;
	cc->ctx = ctx;
	TAILQ_INSERT_TAIL(&c->status_confirms, cc, entry);
}

ಶೂನ್ಯ
channel_register_open_confirm(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ id,
    channel_open_fn *fn, ಶೂನ್ಯ *ctx)
{
	Channel *c = channel_lookup(ssh, id);

	ಯದಿ (c == ರಿಕ್ತ) {
		logit_f("%d: bad id", id);
		ಪ್ರತ್ಯಾಗಮ;
	}
	c->open_confirm = fn;
	c->open_confirm_ctx = ctx;
}

ಶೂನ್ಯ
channel_register_cleanup(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ id,
    channel_callback_fn *fn, ಪೂರ್ಣಾಙ್ಕ do_close)
{
	Channel *c = channel_by_id(ssh, id);

	ಯದಿ (c == ರಿಕ್ತ) {
		logit_f("%d: bad id", id);
		ಪ್ರತ್ಯಾಗಮ;
	}
	c->detach_user = fn;
	c->detach_close = do_close;
}

ಶೂನ್ಯ
channel_cancel_cleanup(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ id)
{
	Channel *c = channel_by_id(ssh, id);

	ಯದಿ (c == ರಿಕ್ತ) {
		logit_f("%d: bad id", id);
		ಪ್ರತ್ಯಾಗಮ;
	}
	c->detach_user = ರಿಕ್ತ;
	c->detach_close = 0;
}

ಶೂನ್ಯ
channel_register_filter(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ id, channel_infilter_fn *ifn,
    channel_outfilter_fn *ofn, channel_filter_cleanup_fn *cfn, ಶೂನ್ಯ *ctx)
{
	Channel *c = channel_lookup(ssh, id);

	ಯದಿ (c == ರಿಕ್ತ) {
		logit_f("%d: bad id", id);
		ಪ್ರತ್ಯಾಗಮ;
	}
	c->ಒಳಹರಿವು_filter = ifn;
	c->output_filter = ofn;
	c->filter_ctx = ctx;
	c->filter_cleanup = cfn;
}

ಶೂನ್ಯ
channel_set_fds(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ id, ಪೂರ್ಣಾಙ್ಕ rfd, ಪೂರ್ಣಾಙ್ಕ wfd, ಪೂರ್ಣಾಙ್ಕ efd,
    ಪೂರ್ಣಾಙ್ಕ extusage, ಪೂರ್ಣಾಙ್ಕ nonblock, ಪೂರ್ಣಾಙ್ಕ is_tty, u_int window_max)
{
	Channel *c = channel_lookup(ssh, id);
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (c == ರಿಕ್ತ || c->type != SSH_CHANNEL_LARVAL)
		fatal("channel_activate for non-larval channel %d.", id);
	ಯದಿ (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);

	channel_register_fds(ssh, c, rfd, wfd, efd, extusage, nonblock, is_tty);
	c->type = SSH_CHANNEL_OPEN;
	channel_set_used_time(ssh, c);
	c->local_window = c->local_window_max = window_max;

	ಯದಿ ((r = sshpkt_start(ssh, SSH2_ಸಂದೇಶ_CHANNEL_WINDOW_ADJUST)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_window)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i", c->self);
}

ಸ್ಥಿರ ಶೂನ್ಯ
channel_pre_listener(ಸಂರಚನಾ ssh *ssh, Channel *c)
{
	c->io_want = SSH_CHAN_IO_SOCK_R;
}

ಸ್ಥಿರ ಶೂನ್ಯ
channel_pre_connecting(ಸಂರಚನಾ ssh *ssh, Channel *c)
{
	debug3("channel %d: waiting for connection", c->self);
	c->io_want = SSH_CHAN_IO_SOCK_W;
}

ಸ್ಥಿರ ಶೂನ್ಯ
channel_pre_open(ಸಂರಚನಾ ssh *ssh, Channel *c)
{
	c->io_want = 0;
	ಯದಿ (c->istate == CHAN_ಒಳಹರಿವು_OPEN &&
	    c->remote_window > 0 &&
	    sshbuf_len(c->ಒಳಹರಿವು) < c->remote_window &&
	    sshbuf_check_reserve(c->ಒಳಹರಿವು, CHAN_RBUF) == 0)
		c->io_want |= SSH_CHAN_IO_RFD;
	ಯದಿ (c->ostate == CHAN_OUTPUT_OPEN ||
	    c->ostate == CHAN_OUTPUT_WAIT_DRAIN) {
		ಯದಿ (sshbuf_len(c->output) > 0) {
			c->io_want |= SSH_CHAN_IO_WFD;
		} ಅನ್ಯಥಾ ಯದಿ (c->ostate == CHAN_OUTPUT_WAIT_DRAIN) {
			ಯದಿ (CHANNEL_EFD_OUTPUT_ACTIVE(c))
				debug2("channel %d: "
				    "obuf_empty delayed efd %d/(%zu)", c->self,
				    c->efd, sshbuf_len(c->extended));
			ಅನ್ಯಥಾ
				chan_obuf_empty(ssh, c);
		}
	}
	/** XXX check close conditions, too */
	ಯದಿ (c->efd != -1 && !(c->istate == CHAN_ಒಳಹರಿವು_CLOSED &&
	    c->ostate == CHAN_OUTPUT_CLOSED)) {
		ಯದಿ (c->extended_usage == CHAN_EXTENDED_WRITE &&
		    sshbuf_len(c->extended) > 0)
			c->io_want |= SSH_CHAN_IO_EFD_W;
		ಅನ್ಯಥಾ ಯದಿ (c->efd != -1 && !(c->flags & CHAN_EOF_SENT) &&
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
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
x11_open_helper(ಸಂರಚನಾ ssh *ssh, ಸಂರಚನಾ sshbuf *b)
{
	ಸಂರಚನಾ ssh_channels *sc = ssh->chanctxt;
	u_char *ucp;
	u_int proto_len, data_len;

	ಯದಿ (sc->x11_saved_proto == ರಿಕ್ತ) {
		error("X11 forwarding opened before X11 forwarding requested");
		ಪ್ರತ್ಯಾಗಮ -1;
	}

	/* Is this being called after the refusal deadline? */
	ಯದಿ (sc->x11_refuse_time != 0.0 &&
	    monotime_double() >= sc->x11_refuse_time) {
		verbose("Rejected X11 connection after ForwardX11Timeout "
		    "expired");
		ಪ್ರತ್ಯಾಗಮ -1;
	}

	/* Check if the fixed size part of the packet is in buffer. */
	ಯದಿ (sshbuf_len(b) < 12)
		ಪ್ರತ್ಯಾಗಮ 0;

	/* Parse the lengths of variable-length fields. */
	ucp = sshbuf_mutable_ptr(b);
	ಯದಿ (ucp[0] == 0x42) {	/* Byte order MSB first. */
		proto_len = 256 * ucp[6] + ucp[7];
		data_len = 256 * ucp[8] + ucp[9];
	} ಅನ್ಯಥಾ ಯದಿ (ucp[0] == 0x6c) {	/* Byte order LSB first. */
		proto_len = ucp[6] + 256 * ucp[7];
		data_len = ucp[8] + 256 * ucp[9];
	} ಅನ್ಯಥಾ {
		debug2("Initial X11 packet contains bad byte order byte: 0x%x",
		    ucp[0]);
		ಪ್ರತ್ಯಾಗಮ -1;
	}

	/* Check if the whole packet is in buffer. */
	ಯದಿ (sshbuf_len(b) <
	    12 + ((proto_len + 3) & ~3) + ((data_len + 3) & ~3))
		ಪ್ರತ್ಯಾಗಮ 0;

	/* Check if authentication protocol matches. */
	ಯದಿ (proto_len != strlen(sc->x11_saved_proto) ||
	    memcmp(ucp + 12, sc->x11_saved_proto, proto_len) != 0) {
		debug2("X11 connection uses different authentication protocol.");
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	/* Check if authentication data matches our fake data. */
	ಯದಿ (data_len != sc->x11_fake_data_len ||
	    timingsafe_bcmp(ucp + 12 + ((proto_len + 3) & ~3),
		sc->x11_fake_data, sc->x11_fake_data_len) != 0) {
		debug2("X11 auth data does not match fake data.");
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	/* Check fake data length */
	ಯದಿ (sc->x11_fake_data_len != sc->x11_saved_data_len) {
		error("X11 fake_data_len %d != saved_data_len %d",
		    sc->x11_fake_data_len, sc->x11_saved_data_len);
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	/*
	 * Received authentication protocol and data match
	 * our fake data. Substitute the fake data with real
	 * data.
	 */
	memcpy(ucp + 12 + ((proto_len + 3) & ~3),
	    sc->x11_saved_data, sc->x11_saved_data_len);
	ಪ್ರತ್ಯಾಗಮ 1;
}

ಶೂನ್ಯ
channel_force_close(ಸಂರಚನಾ ssh *ssh, Channel *c, ಪೂರ್ಣಾಙ್ಕ abandon)
{
	debug3_f("channel %d: forcibly closing", c->self);
	ಯದಿ (c->istate == CHAN_ಒಳಹರಿವು_OPEN)
		chan_read_failed(ssh, c);
	ಯದಿ (c->istate == CHAN_ಒಳಹರಿವು_WAIT_DRAIN) {
		sshbuf_reset(c->ಒಳಹರಿವು);
		chan_ibuf_empty(ssh, c);
	}
	ಯದಿ (c->ostate == CHAN_OUTPUT_OPEN ||
	    c->ostate == CHAN_OUTPUT_WAIT_DRAIN) {
		sshbuf_reset(c->output);
		chan_write_failed(ssh, c);
	}
	ಯದಿ (c->detach_user)
		c->detach_user(ssh, c->self, 1, ರಿಕ್ತ);
	ಯದಿ (c->efd != -1)
		channel_close_fd(ssh, c, &c->efd);
	ಯದಿ (abandon)
		c->type = SSH_CHANNEL_ABANDONED;
	/* exempt from inactivity timeouts */
	c->inactive_deadline = 0;
	c->lastused = 0;
}

ಸ್ಥಿರ ಶೂನ್ಯ
channel_pre_x11_open(ಸಂರಚನಾ ssh *ssh, Channel *c)
{
	ಪೂರ್ಣಾಙ್ಕ ret = x11_open_helper(ssh, c->output);

	/* c->force_drain = 1; */

	ಯದಿ (ret == 1) {
		c->type = SSH_CHANNEL_OPEN;
		channel_set_used_time(ssh, c);
		channel_pre_open(ssh, c);
	} ಅನ್ಯಥಾ ಯದಿ (ret == -1) {
		logit("X11 connection rejected because of wrong "
		    "authentication.");
		debug2("X11 rejected %d i%d/o%d",
		    c->self, c->istate, c->ostate);
		channel_force_close(ssh, c, 0);
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
channel_pre_mux_client(ಸಂರಚನಾ ssh *ssh, Channel *c)
{
	c->io_want = 0;
	ಯದಿ (c->istate == CHAN_ಒಳಹರಿವು_OPEN && !c->mux_pause &&
	    sshbuf_check_reserve(c->ಒಳಹರಿವು, CHAN_RBUF) == 0)
		c->io_want |= SSH_CHAN_IO_RFD;
	ಯದಿ (c->istate == CHAN_ಒಳಹರಿವು_WAIT_DRAIN) {
		/* clear buffer immediately (discard any partial packet) */
		sshbuf_reset(c->ಒಳಹರಿವು);
		chan_ibuf_empty(ssh, c);
		/* Start output drain. XXX just kill chan? */
		chan_rcvd_oclose(ssh, c);
	}
	ಯದಿ (c->ostate == CHAN_OUTPUT_OPEN ||
	    c->ostate == CHAN_OUTPUT_WAIT_DRAIN) {
		ಯದಿ (sshbuf_len(c->output) > 0)
			c->io_want |= SSH_CHAN_IO_WFD;
		ಅನ್ಯಥಾ ಯದಿ (c->ostate == CHAN_OUTPUT_WAIT_DRAIN)
			chan_obuf_empty(ssh, c);
	}
}

ಸ್ಥಿರ ಅನ್ತಃಸ್ಥ ಪೂರ್ಣಾಙ್ಕ
socks_decode_error(Channel *c, ಪೂರ್ಣಾಙ್ಕ status, ಧ್ರುವ ವರ್ಣ *func, ಧ್ರುವ ವರ್ಣ *ಸಂದೇಶ)
{
	ಯದಿ (status == SSH_ERR_MESSAGE_INCOMPLETE)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಅನ್ಯಥಾ {
		debug_r(status, "%s: channel %d: decode %s",
		    func, c->self, ಸಂದೇಶ);
		ಪ್ರತ್ಯಾಗಮ -1;
	}
}

/* try to decode a socks4 header */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
channel_decode_socks4(Channel *c, ಸಂರಚನಾ sshbuf *ಒಳಹರಿವು, ಸಂರಚನಾ sshbuf *output)
{
	uint8_t socks_ver, socks_cmd, dest_addr[4];
	uint16_t dest_port;
	ವರ್ಣ *user = ರಿಕ್ತ, *host = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ success = -1, socks4a = 0, r;
	ಸಂರಚನಾ sshbuf *b = ರಿಕ್ತ;

	ಯದಿ (sshbuf_len(ಒಳಹರಿವು) < 9)
		ಪ್ರತ್ಯಾಗಮ 0;

	/* We may not have a complete message, so work on a dup of the buffer */
	ಯದಿ ((b = sshbuf_fromb(ಒಳಹರಿವು)) == ರಿಕ್ತ)
		fatal_f("sshbuf_fromb failed");

	debug2("channel %d: decode socks4", c->self);
	ಯದಿ ((r = sshbuf_get_u8(b, &socks_ver)) != 0 ||
	    (r = sshbuf_get_u8(b, &socks_cmd)) != 0 ||
	    (r = sshbuf_get_u16(b, &dest_port)) != 0 ||
	    (r = sshbuf_get(b, &dest_addr, ಪರಿಮಾಣ(dest_addr))) != 0 ||
	    (r = sshbuf_get_nulterminated_string(b, 1024, &user, ರಿಕ್ತ)) != 0) {
		success = socks_decode_error(c, r, __func__, "header");
		ಗಚ್ಛ out;
	}

	/* Is this a SOCKS4A request? (indicated by an address of 0.0.0.x) */
	ಯದಿ (dest_addr[0] == 0 && dest_addr[1] == 0 &&
	    dest_addr[2] == 0 && dest_addr[3] != 0) {
		/* If so, then the hostname follows, also nul-terminated */
		ಯದಿ ((r = sshbuf_get_nulterminated_string(b, 1024,
		    &host, ರಿಕ್ತ)) != 0) {
			success = socks_decode_error(c, r, __func__, "host");
			ಗಚ್ಛ out;
		}
		socks4a = 1;
	} ಅನ್ಯಥಾ {
		/* Plain SOCKS4 passes an IPv4 binary address; reconstruct */
		xasprintf(&host, "%d.%d.%d.%d",
		    dest_addr[0], dest_addr[1], dest_addr[2], dest_addr[3]);
	}

	/* We have a complete SOCKS4 message; consume it from input */
	ಯದಿ ((r = sshbuf_consume_upto_child(ಒಳಹರಿವು, b)) != 0)
		fatal_fr(r, "channel %d: consume", c->self);

	/* Handle the request */
	debug2("channel %d: %s: user=\"%s\" command=%d destination=[%s]:%d",
	    c->self, socks4a ? "SOCKS4A" : "SOCKS4", user, (ಪೂರ್ಣಾಙ್ಕ)socks_cmd,
	    host, dest_port);
	ಯದಿ (socks_cmd != 1) {
		debug("channel %d: cannot handle %s command 0x%02x",
		    c->self, socks4a ? "SOCKS4A" : "SOCKS4", socks_cmd);
		ಗಚ್ಛ out;
	}
	ಮುಕ್ತ(c->path);
	c->path = host;
	host = ರಿಕ್ತ; /* transferred */
	c->host_port = dest_port;

	/* Reply to the SOCKS4 client */
	ಯದಿ ((r = sshbuf_put_u8(output, 0)) != 0 ||	/* vn: 0 for reply */
	    (r = sshbuf_put_u8(output, 90)) != 0 ||	/* cd: req granted */
	    (r = sshbuf_put_u16(output, 0)) != 0 ||	/* port: ignored */
	    (r = sshbuf_put_u32(output, ntohl(INADDR_ANY))) != 0) /* ignored */
		fatal_fr(r, "channel %d: compose reply", c->self);

	/* success */
	success = 1;
 out:
	sshbuf_free(b);
	ಮುಕ್ತ(user);
	ಮುಕ್ತ(host);
	ಪ್ರತ್ಯಾಗಮ success;
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
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
channel_socks5_check_auth(Channel *c, ಸಂರಚನಾ sshbuf *b, ಸಂರಚನಾ sshbuf *ಒಳಹರಿವು,
    ಸಂರಚನಾ sshbuf *output)
{
	uint8_t socks_ver;
	uint8_t nmethods, method;
	ಪೂರ್ಣಾಙ್ಕ r;
	u_int i, found;

	/* format: ver | nmethods | methods */
	ಯದಿ ((r = sshbuf_get_u8(b, &socks_ver)) != 0)
		ಪ್ರತ್ಯಾಗಮ socks_decode_error(c, r, __func__, "version");
	ಯದಿ (socks_ver != 5) /* shouldn't happen; checked by caller^2 */
		fatal_fr(r, "channel %d: internal error: not socks5", c->self);
	ಯದಿ ((r = sshbuf_get_u8(b, &nmethods)) != 0)
		ಪ್ರತ್ಯಾಗಮ socks_decode_error(c, r, __func__, "methods");
	ಪ್ರತಿ (found = i = 0; i < nmethods; i++) {
		ಯದಿ ((r = sshbuf_get_u8(b, &method)) != 0)
			ಪ್ರತ್ಯಾಗಮ socks_decode_error(c, r, __func__, "method");
		ಯದಿ (method == SSH_SOCKS5_NOAUTH)
			found = 1;
	}
	ಯದಿ (!found) {
		debug("channel %d: didn't request SSH_SOCKS5_NOAUTH", c->self);
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	/* Consume completed request */
	ಯದಿ ((r = sshbuf_consume_upto_child(ಒಳಹರಿವು, b)) != 0)
		fatal_fr(r, "channel %d: consume", c->self);

	/* Compose reply: version, method */
	ಯದಿ ((r = sshbuf_put_u8(output, 0x05)) != 0 ||
	    (r = sshbuf_put_u8(output, SSH_SOCKS5_NOAUTH)) != 0)
		fatal_fr(r, "channel %d: append reply", c->self);
	/* success */
	debug2("channel %d: socks5 auth done", c->self);
	ಪ್ರತ್ಯಾಗಮ 1;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
channel_decode_socks5(Channel *c, ಸಂರಚನಾ sshbuf *ಒಳಹರಿವು, ಸಂರಚನಾ sshbuf *output)
{
	uint8_t socks_ver, socks_cmd, socks_reserved, socks_atyp, addrlen;
	uint16_t dest_port;
	ವರ್ಣ dest_addr[255+1], ntop[INET6_ADDRSTRLEN];
	u_int af;
	ಪೂರ್ಣಾಙ್ಕ r, success = -1;;
	ಸಂರಚನಾ sshbuf *b = ರಿಕ್ತ;

	debug2("channel %d: decode socks5 %s", c->self,
	    (c->flags & SSH_SOCKS5_AUTHDONE) ? "request" : "auth");

	/* We may not have a complete message, so work on a dup of the buffer */
	ಯದಿ ((b = sshbuf_fromb(ಒಳಹರಿವು)) == ರಿಕ್ತ)
		fatal_f("sshbuf_fromb failed");

	ಯದಿ (!(c->flags & SSH_SOCKS5_AUTHDONE)) {
		ಯದಿ ((r = channel_socks5_check_auth(c, b, ಒಳಹರಿವು, output)) != 1) {
			success = r;
			ಗಚ್ಛ out;
		}
		c->flags |= SSH_SOCKS5_AUTHDONE;
		/* Continue to parse request in case client speculated ahead */
	}

	/* Request messages (auth or connect) always start with the version */
	ಯದಿ ((r = sshbuf_get_u8(b, &socks_ver)) != 0) {
		success = socks_decode_error(c, r, __func__, "version");
		ಗಚ್ಛ out;
	}
	ಯದಿ (socks_ver != 5) /* shouldn't happen */
		fatal_fr(r, "channel %d: internal error: not socks5", c->self);

	/* Parse SOCKS5 request header */
	debug2("channel %d: socks5 post auth", c->self);
	ಯದಿ ((r = sshbuf_get_u8(b, &socks_cmd)) != 0 ||
	    (r = sshbuf_get_u8(b, &socks_reserved)) != 0 ||
	    (r = sshbuf_get_u8(b, &socks_atyp)) != 0) {
		success = socks_decode_error(c, r, __func__, "request header");
		ಗಚ್ಛ out;
	}

	ಯದಿ (socks_ver != 0x05 ||
	    socks_cmd != SSH_SOCKS5_CONNECT ||
	    socks_reserved != 0x00) {
		debug2("channel %d: only socks5 connect supported", c->self);
		ಗಚ್ಛ out;
	}

	ವಿಕಲ್ಪ (socks_atyp) {
	ಪಕ್ಷ SSH_SOCKS5_IPV4:
		addrlen = 4;
		af = AF_INET;
		ಭಙ್ಗ;
	ಪಕ್ಷ SSH_SOCKS5_DOMAIN:
		ಯದಿ ((r = sshbuf_get_u8(b, &addrlen)) != 0) {
			success = socks_decode_error(c, r, __func__, "addrlen");
			ಗಚ್ಛ out;
		}
		af = -1;
		ಭಙ್ಗ;
	ಪಕ್ಷ SSH_SOCKS5_IPV6:
		addrlen = 16;
		af = AF_INET6;
		ಭಙ್ಗ;
	ಸ್ವಭಾವ:
		debug2("channel %d: bad socks5 atyp %d", c->self, socks_atyp);
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = sshbuf_get(b, &dest_addr, addrlen)) != 0 ||
	    (r = sshbuf_get_u16(b, &dest_port)) != 0) {
		success = socks_decode_error(c, r, __func__, "addr/port");
		ಗಚ್ಛ out;
	}
	dest_addr[addrlen] = '\0';

	/* We have a complete SOCKS5 request; consume it from input */
	ಯದಿ ((r = sshbuf_consume_upto_child(ಒಳಹರಿವು, b)) != 0)
		fatal_fr(r, "channel %d: consume", c->self);

	ಮುಕ್ತ(c->path);
	c->path = ರಿಕ್ತ;
	ಯದಿ (socks_atyp == SSH_SOCKS5_DOMAIN)
		c->path = xstrdup(dest_addr);
	ಅನ್ಯಥಾ {
		ಯದಿ (inet_ntop(af, dest_addr, ntop, ಪರಿಮಾಣ(ntop)) == ರಿಕ್ತ)
			ಪ್ರತ್ಯಾಗಮ -1;
		c->path = xstrdup(ntop);
	}
	c->host_port = dest_port;

	debug2("channel %d: dynamic request: socks5 host %s port %u command %u",
	    c->self, c->path, c->host_port, socks_cmd);

	/* Reply */
	ಯದಿ ((r = sshbuf_put_u8(output, 0x05)) != 0 ||	/* version */
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
	ಪ್ರತ್ಯಾಗಮ success;
}

Channel *
channel_connect_stdio_fwd(ಸಂರಚನಾ ssh *ssh,
    ಧ್ರುವ ವರ್ಣ *host_to_connect, ಪೂರ್ಣಾಙ್ಕ port_to_connect,
    ಪೂರ್ಣಾಙ್ಕ in, ಪೂರ್ಣಾಙ್ಕ out, ಪೂರ್ಣಾಙ್ಕ nonblock)
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

	ಪ್ರತ್ಯಾಗಮ c;
}

/* dynamic port forwarding */
ಸ್ಥಿರ ಶೂನ್ಯ
channel_pre_dynamic(ಸಂರಚನಾ ssh *ssh, Channel *c)
{
	u_int have;
	u_char ver;
	ಪೂರ್ಣಾಙ್ಕ r, ret;

	c->io_want = 0;
	have = sshbuf_len(c->ಒಳಹರಿವು);
	debug2("channel %d: pre_dynamic: have %d", c->self, have);
	/* sshbuf_dump(c->input, stderr); */
	/* check if the fixed size part of the packet is in buffer. */
	ಯದಿ (have < 3) {
		/* need more */
		c->io_want |= SSH_CHAN_IO_RFD;
		ಪ್ರತ್ಯಾಗಮ;
	}
	/* try to guess the protocol */
	ಯದಿ ((r = sshbuf_peek_u8(c->ಒಳಹರಿವು, 0, &ver)) != 0)
		fatal_fr(r, "sshbuf_peek_u8");
	ವಿಕಲ್ಪ (ver) {
	ಪಕ್ಷ 0x04:
		ret = channel_decode_socks4(c, c->ಒಳಹರಿವು, c->output);
		ಭಙ್ಗ;
	ಪಕ್ಷ 0x05:
		ret = channel_decode_socks5(c, c->ಒಳಹರಿವು, c->output);
		ಭಙ್ಗ;
	ಸ್ವಭಾವ:
		debug2_f("channel %d: unknown SOCKS version %u", c->self, ver);
		ret = -1;
		ಭಙ್ಗ;
	}
	ಯದಿ (ret < 0) {
		chan_mark_dead(ssh, c);
	} ಅನ್ಯಥಾ ಯದಿ (ret == 0) {
		debug2("channel %d: pre_dynamic: need more", c->self);
		/* need more */
		c->io_want |= SSH_CHAN_IO_RFD;
		ಯದಿ (sshbuf_len(c->output))
			c->io_want |= SSH_CHAN_IO_WFD;
	} ಅನ್ಯಥಾ {
		/* switch to the next state */
		c->type = SSH_CHANNEL_OPENING;
		port_open_helper(ssh, c, "direct-tcpip");
	}
}

/* simulate read-error */
ಸ್ಥಿರ ಶೂನ್ಯ
rdynamic_close(ಸಂರಚನಾ ssh *ssh, Channel *c)
{
	c->type = SSH_CHANNEL_OPEN;
	channel_force_close(ssh, c, 0);
}

/* reverse dynamic port forwarding */
ಸ್ಥಿರ ಶೂನ್ಯ
channel_before_prepare_io_rdynamic(ಸಂರಚನಾ ssh *ssh, Channel *c)
{
	ಧ್ರುವ u_char *p;
	u_int have, len;
	ಪೂರ್ಣಾಙ್ಕ r, ret;

	have = sshbuf_len(c->output);
	debug2("channel %d: pre_rdynamic: have %d", c->self, have);
	/* sshbuf_dump(c->output, stderr); */
	/* EOF received */
	ಯದಿ (c->flags & CHAN_EOF_RCVD) {
		ಯದಿ ((r = sshbuf_consume(c->output, have)) != 0)
			fatal_fr(r, "channel %d: consume", c->self);
		rdynamic_close(ssh, c);
		ಪ್ರತ್ಯಾಗಮ;
	}
	/* check if the fixed size part of the packet is in buffer. */
	ಯದಿ (have < 3)
		ಪ್ರತ್ಯಾಗಮ;
	/* try to guess the protocol */
	p = sshbuf_ptr(c->output);
	ವಿಕಲ್ಪ (p[0]) {
	ಪಕ್ಷ 0x04:
		/* switch input/output for reverse forwarding */
		ret = channel_decode_socks4(c, c->output, c->ಒಳಹರಿವು);
		ಭಙ್ಗ;
	ಪಕ್ಷ 0x05:
		ret = channel_decode_socks5(c, c->output, c->ಒಳಹರಿವು);
		ಭಙ್ಗ;
	ಸ್ವಭಾವ:
		ret = -1;
		ಭಙ್ಗ;
	}
	ಯದಿ (ret < 0) {
		rdynamic_close(ssh, c);
	} ಅನ್ಯಥಾ ಯದಿ (ret == 0) {
		debug2("channel %d: pre_rdynamic: need more", c->self);
		/* send socks request to peer */
		len = sshbuf_len(c->ಒಳಹರಿವು);
		ಯದಿ (len > 0 && len < c->remote_window) {
			ಯದಿ ((r = sshpkt_start(ssh, SSH2_ಸಂದೇಶ_CHANNEL_DATA)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
			    (r = sshpkt_put_stringb(ssh, c->ಒಳಹರಿವು)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0) {
				fatal_fr(r, "channel %i: rdynamic", c->self);
			}
			ಯದಿ ((r = sshbuf_consume(c->ಒಳಹರಿವು, len)) != 0)
				fatal_fr(r, "channel %d: consume", c->self);
			c->remote_window -= len;
		}
	} ಅನ್ಯಥಾ ಯದಿ (rdynamic_connect_finish(ssh, c) < 0) {
		/* the connect failed */
		rdynamic_close(ssh, c);
	}
}

/* This is our fake X11 server socket. */
ಸ್ಥಿರ ಶೂನ್ಯ
channel_post_x11_listener(ಸಂರಚನಾ ssh *ssh, Channel *c)
{
	Channel *nc;
	ಸಂರಚನಾ sockaddr_storage addr;
	ಪೂರ್ಣಾಙ್ಕ r, newsock, oerrno, remote_port;
	socklen_t addrlen;
	ವರ್ಣ buf[16384], *remote_ipaddr;

	ಯದಿ ((c->io_ready & SSH_CHAN_IO_SOCK_R) == 0)
		ಪ್ರತ್ಯಾಗಮ;

	debug("X11 connection requested.");
	addrlen = ಪರಿಮಾಣ(addr);
	newsock = accept(c->sock, (ಸಂರಚನಾ sockaddr *)&addr, &addrlen);
	ಯದಿ (c->single_connection) {
		oerrno = errno;
		debug2("single_connection: closing X11 listener.");
		channel_close_fd(ssh, c, &c->sock);
		chan_mark_dead(ssh, c);
		errno = oerrno;
	}
	ಯದಿ (newsock == -1) {
		ಯದಿ (errno != EINTR && errno != EWOULDBLOCK &&
		    errno != ECONNABORTED)
			error("accept: %.100s", strerror(errno));
		ಯದಿ (errno == EMFILE || errno == ENFILE)
			c->notbefore = monotime_double() + 1.0;
		ಪ್ರತ್ಯಾಗಮ;
	}
	set_nodelay(newsock);
	ಯದಿ (ssh->chanctxt->want_tcp_keepalive)
		set_keepalive(newsock); /* logs errors */
	remote_ipaddr = get_peer_ipaddr(newsock);
	remote_port = get_peer_port(newsock);
	snprintf(buf, ಪರಿಮಾಣ buf, "X11 connection from %.200s port %d",
	    remote_ipaddr, remote_port);

	nc = channel_new(ssh, "x11-connection",
	    SSH_CHANNEL_OPENING, newsock, newsock, -1,
	    c->local_window_max, c->local_maxpacket, 0, buf, 1);
	open_preamble(ssh, __func__, nc, "x11");
	ಯದಿ ((r = sshpkt_put_cstring(ssh, remote_ipaddr)) != 0 ||
	    (r = sshpkt_put_u32(ssh, remote_port)) != 0) {
		fatal_fr(r, "channel %i: reply", c->self);
	}
	ಯದಿ ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i: send", c->self);
	ಮುಕ್ತ(remote_ipaddr);
}

ಸ್ಥಿರ ಶೂನ್ಯ
port_open_helper(ಸಂರಚನಾ ssh *ssh, Channel *c, ವರ್ಣ *rtype)
{
	ವರ್ಣ *local_ipaddr = get_local_ipaddr(c->sock);
	ಪೂರ್ಣಾಙ್ಕ local_port = c->sock == -1 ? 65536 : get_local_port(c->sock);
	ವರ್ಣ *remote_ipaddr = get_peer_ipaddr(c->sock);
	ಪೂರ್ಣಾಙ್ಕ remote_port = get_peer_port(c->sock);
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (remote_port == -1) {
		/* Fake addr/port to appease peers that validate it (Tectia) */
		ಮುಕ್ತ(remote_ipaddr);
		remote_ipaddr = xstrdup("127.0.0.1");
		remote_port = 65535;
	}

	ಮುಕ್ತ(c->remote_name);
	xasprintf(&c->remote_name,
	    "%s: listening port %d for %.100s port %d, "
	    "connect from %.200s port %d to %.100s port %d",
	    rtype, c->listening_port, c->path, c->host_port,
	    remote_ipaddr, remote_port, local_ipaddr, local_port);

	open_preamble(ssh, __func__, c, rtype);
	ಯದಿ (strcmp(rtype, "direct-tcpip") == 0) {
		/* target host, port */
		ಯದಿ ((r = sshpkt_put_cstring(ssh, c->path)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->host_port)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	} ಅನ್ಯಥಾ ಯದಿ (strcmp(rtype, "direct-streamlocal@openssh.com") == 0) {
		/* target path */
		ಯದಿ ((r = sshpkt_put_cstring(ssh, c->path)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	} ಅನ್ಯಥಾ ಯದಿ (strcmp(rtype, "forwarded-streamlocal@openssh.com") == 0) {
		/* listen path */
		ಯದಿ ((r = sshpkt_put_cstring(ssh, c->path)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	} ಅನ್ಯಥಾ {
		/* listen address, port */
		ಯದಿ ((r = sshpkt_put_cstring(ssh, c->path)) != 0 ||
		    (r = sshpkt_put_u32(ssh, local_port)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	}
	ಯದಿ (strcmp(rtype, "forwarded-streamlocal@openssh.com") == 0) {
		/* reserved for future owner/mode info */
		ಯದಿ ((r = sshpkt_put_cstring(ssh, "")) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	} ಅನ್ಯಥಾ {
		/* originator host and port */
		ಯದಿ ((r = sshpkt_put_cstring(ssh, remote_ipaddr)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)remote_port)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	}
	ಯದಿ ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i: send", c->self);
	ಮುಕ್ತ(remote_ipaddr);
	ಮುಕ್ತ(local_ipaddr);
}

ಶೂನ್ಯ
channel_set_x11_refuse_time(ಸಂರಚನಾ ssh *ssh, ದ್ವಿಗುಣ refuse_time)
{
	ssh->chanctxt->x11_refuse_time = refuse_time;
}

/*
 * This socket is listening for connections to a forwarded TCP/IP port.
 */
ಸ್ಥಿರ ಶೂನ್ಯ
channel_post_port_listener(ಸಂರಚನಾ ssh *ssh, Channel *c)
{
	Channel *nc;
	ಸಂರಚನಾ sockaddr_storage addr;
	ಪೂರ್ಣಾಙ್ಕ newsock, nextstate;
	socklen_t addrlen;
	ವರ್ಣ *rtype;

	ಯದಿ ((c->io_ready & SSH_CHAN_IO_SOCK_R) == 0)
		ಪ್ರತ್ಯಾಗಮ;

	debug("Connection to port %d forwarding to %.100s port %d requested.",
	    c->listening_port, c->path, c->host_port);

	ಯದಿ (c->type == SSH_CHANNEL_RPORT_LISTENER) {
		nextstate = SSH_CHANNEL_OPENING;
		rtype = "forwarded-tcpip";
	} ಅನ್ಯಥಾ ಯದಿ (c->type == SSH_CHANNEL_RUNIX_LISTENER) {
		nextstate = SSH_CHANNEL_OPENING;
		rtype = "forwarded-streamlocal@openssh.com";
	} ಅನ್ಯಥಾ ಯದಿ (c->host_port == PORT_STREAMLOCAL) {
		nextstate = SSH_CHANNEL_OPENING;
		rtype = "direct-streamlocal@openssh.com";
	} ಅನ್ಯಥಾ ಯದಿ (c->host_port == 0) {
		nextstate = SSH_CHANNEL_DYNAMIC;
		rtype = "dynamic-tcpip";
	} ಅನ್ಯಥಾ {
		nextstate = SSH_CHANNEL_OPENING;
		rtype = "direct-tcpip";
	}

	addrlen = ಪರಿಮಾಣ(addr);
	newsock = accept(c->sock, (ಸಂರಚನಾ sockaddr *)&addr, &addrlen);
	ಯದಿ (newsock == -1) {
		ಯದಿ (errno != EINTR && errno != EWOULDBLOCK &&
		    errno != ECONNABORTED)
			error("accept: %.100s", strerror(errno));
		ಯದಿ (errno == EMFILE || errno == ENFILE)
			c->notbefore = monotime_double() + 1.0;
		ಪ್ರತ್ಯಾಗಮ;
	}
	ಯದಿ (addr.ss_family == AF_INET || addr.ss_family == AF_INET6) {
		set_nodelay(newsock);
		ಯದಿ (ssh->chanctxt->want_tcp_keepalive)
			set_keepalive(newsock); /* logs errors */
	}
	nc = channel_new(ssh, rtype, nextstate, newsock, newsock, -1,
	    c->local_window_max, c->local_maxpacket, 0, rtype, 1);
	nc->listening_port = c->listening_port;
	nc->host_port = c->host_port;
	ಯದಿ (c->path != ರಿಕ್ತ)
		nc->path = xstrdup(c->path);

	ಯದಿ (nextstate != SSH_CHANNEL_DYNAMIC)
		port_open_helper(ssh, nc, rtype);
}

/*
 * This is the authentication agent socket listening for connections from
 * clients.
 */
ಸ್ಥಿರ ಶೂನ್ಯ
channel_post_auth_listener(ಸಂರಚನಾ ssh *ssh, Channel *c)
{
	Channel *nc;
	ಪೂರ್ಣಾಙ್ಕ r, newsock;
	ಸಂರಚನಾ sockaddr_storage addr;
	socklen_t addrlen;

	ಯದಿ ((c->io_ready & SSH_CHAN_IO_SOCK_R) == 0)
		ಪ್ರತ್ಯಾಗಮ;

	addrlen = ಪರಿಮಾಣ(addr);
	newsock = accept(c->sock, (ಸಂರಚನಾ sockaddr *)&addr, &addrlen);
	ಯದಿ (newsock == -1) {
		error("accept from auth socket: %.100s", strerror(errno));
		ಯದಿ (errno == EMFILE || errno == ENFILE)
			c->notbefore = monotime_double() + 1.0;
		ಪ್ರತ್ಯಾಗಮ;
	}
	nc = channel_new(ssh, "agent-connection",
	    SSH_CHANNEL_OPENING, newsock, newsock, -1,
	    c->local_window_max, c->local_maxpacket,
	    0, "accepted auth socket", 1);
	open_preamble(ssh, __func__, nc,
	    c->agent_new ? "agent-connect" : "auth-agent@openssh.com");
	ಯದಿ ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i", c->self);
}

ಸ್ಥಿರ ಶೂನ್ಯ
channel_post_connecting(ಸಂರಚನಾ ssh *ssh, Channel *c)
{
	ಪೂರ್ಣಾಙ್ಕ err = 0, sock, isopen, r;
	socklen_t sz = ಪರಿಮಾಣ(err);

	ಯದಿ ((c->io_ready & SSH_CHAN_IO_SOCK_W) == 0)
		ಪ್ರತ್ಯಾಗಮ;
	ಯದಿ (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);
	ಯದಿ (c->connect_ctx == ರಿಕ್ತ)
		fatal_f("channel %d: context missing", c->self);

	/* for rdynamic the OPEN_CONFIRMATION has been sent already */
	isopen = (c->type == SSH_CHANNEL_RDYNAMIC_FINISH);

	ಯದಿ (getsockopt(c->sock, SOL_SOCKET, SO_ERROR, &err, &sz) == -1) {
		err = errno;
		error("getsockopt SO_ERROR failed");
	}

	ಯದಿ (err == 0) {
		/* Non-blocking connection completed */
		debug("channel %d: connected to %s port %d",
		    c->self, c->connect_ctx->host, c->connect_ctx->port);
		channel_free_connect_ctx(c);
		c->type = SSH_CHANNEL_OPEN;
		channel_set_used_time(ssh, c);
		ಯದಿ (isopen) {
			/* no message necessary */
		} ಅನ್ಯಥಾ {
			ಯದಿ ((r = sshpkt_start(ssh,
			    SSH2_ಸಂದೇಶ_CHANNEL_OPEN_CONFIRMATION)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_window)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "channel %i open confirm", c->self);
		}
		ಪ್ರತ್ಯಾಗಮ;
	}
	ಯದಿ (err == EINTR || err == EAGAIN || err == EINPROGRESS)
		ಪ್ರತ್ಯಾಗಮ;

	/* Non-blocking connection failed */
	debug("channel %d: connection failed: %s", c->self, strerror(err));

	/* Try next address, if any */
	ಯದಿ ((sock = connect_next(ssh, c->connect_ctx)) == -1) {
		/* Exhausted all addresses for this destination */
		error("connect_to %.100s port %d: failed.",
		    c->connect_ctx->host, c->connect_ctx->port);
		channel_free_connect_ctx(c);
		ಯದಿ (isopen) {
			rdynamic_close(ssh, c);
		} ಅನ್ಯಥಾ {
			ಯದಿ ((r = sshpkt_start(ssh,
			    SSH2_ಸಂದೇಶ_CHANNEL_OPEN_FAILURE)) != 0 ||
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

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
channel_handle_rfd(ಸಂರಚನಾ ssh *ssh, Channel *c)
{
	ವರ್ಣ buf[CHAN_RBUF];
	ssize_t len;
	ಪೂರ್ಣಾಙ್ಕ r, force;
	size_t nr = 0, have, avail, maxlen = CHANNEL_MAX_READ;
	ಪೂರ್ಣಾಙ್ಕ pty_zeroread = 0;

#ifdef PTY_ZEROREAD
	/* Bug on AIX: read(1) can return 0 for a non-closed fd */
	pty_zeroread = c->isatty;
#endif

	force = c->isatty && c->detach_close && c->istate != CHAN_ಒಳಹರಿವು_CLOSED;

	ಯದಿ (!force && (c->io_ready & SSH_CHAN_IO_RFD) == 0)
		ಪ್ರತ್ಯಾಗಮ 1;
	ಯದಿ ((avail = sshbuf_avail(c->ಒಳಹರಿವು)) == 0)
		ಪ್ರತ್ಯಾಗಮ 1; /* Shouldn't happen */

	/*
	 * For "simple" channels (i.e. not datagram or filtered), we can
	 * read directly to the channel buffer.
	 */
	ಯದಿ (!pty_zeroread && c->ಒಳಹರಿವು_filter == ರಿಕ್ತ && !c->datagram) {
		/* Only OPEN channels have valid rwin */
		ಯದಿ (c->type == SSH_CHANNEL_OPEN) {
			ಯದಿ ((have = sshbuf_len(c->ಒಳಹರಿವು)) >= c->remote_window)
				ಪ್ರತ್ಯಾಗಮ 1; /* shouldn't happen */
			ಯದಿ (maxlen > c->remote_window - have)
				maxlen = c->remote_window - have;
		}
		ಯದಿ (maxlen > avail)
			maxlen = avail;
		ಯದಿ ((r = sshbuf_read(c->rfd, c->ಒಳಹರಿವು, maxlen, &nr)) != 0) {
			ಯದಿ (errno == EINTR || (!force &&
			    (errno == EAGAIN || errno == EWOULDBLOCK)))
				ಪ್ರತ್ಯಾಗಮ 1;
			debug2("channel %d: read failed rfd %d maxlen %zu: %s",
			    c->self, c->rfd, maxlen, ssh_err(r));
			ಗಚ್ಛ rfail;
		}
		ಯದಿ (nr != 0)
			channel_set_used_time(ssh, c);
		ಪ್ರತ್ಯಾಗಮ 1;
	}

	errno = 0;
	len = ಪಠ(c->rfd, buf, ಪರಿಮಾಣ(buf));
	/* fixup AIX zero-length read with errno set to look more like errors */
	ಯದಿ (pty_zeroread && len == 0 && errno != 0)
		len = -1;
	ಯದಿ (len == -1 && (errno == EINTR ||
	    ((errno == EAGAIN || errno == EWOULDBLOCK) && !force)))
		ಪ್ರತ್ಯಾಗಮ 1;
	ಯದಿ (len < 0 || (!pty_zeroread && len == 0)) {
		debug2("channel %d: read<=0 rfd %d len %zd: %s",
		    c->self, c->rfd, len,
		    len == 0 ? "closed" : strerror(errno));
 rfail:
		ಯದಿ (c->type != SSH_CHANNEL_OPEN) {
			debug2("channel %d: not open", c->self);
			chan_mark_dead(ssh, c);
			ಪ್ರತ್ಯಾಗಮ -1;
		} ಅನ್ಯಥಾ {
			chan_read_failed(ssh, c);
		}
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	channel_set_used_time(ssh, c);
	ಯದಿ (c->ಒಳಹರಿವು_filter != ರಿಕ್ತ) {
		ಯದಿ (c->ಒಳಹರಿವು_filter(ssh, c, buf, len) == -1) {
			debug2("channel %d: filter stops", c->self);
			chan_read_failed(ssh, c);
		}
	} ಅನ್ಯಥಾ ಯದಿ (c->datagram) {
		ಯದಿ ((r = sshbuf_put_string(c->ಒಳಹರಿವು, buf, len)) != 0)
			fatal_fr(r, "channel %i: put datagram", c->self);
	} ಅನ್ಯಥಾ ಯದಿ ((r = sshbuf_put(c->ಒಳಹರಿವು, buf, len)) != 0)
		fatal_fr(r, "channel %i: put data", c->self);

	ಪ್ರತ್ಯಾಗಮ 1;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
channel_handle_wfd(ಸಂರಚನಾ ssh *ssh, Channel *c)
{
	ಸಂರಚನಾ termios tio;
	u_char *data = ರಿಕ್ತ, *buf; /* XXX const; need filter API change */
	size_t dlen, olen = 0;
	ಪೂರ್ಣಾಙ್ಕ r, len;

	ಯದಿ ((c->io_ready & SSH_CHAN_IO_WFD) == 0)
		ಪ್ರತ್ಯಾಗಮ 1;
	ಯದಿ (sshbuf_len(c->output) == 0)
		ಪ್ರತ್ಯಾಗಮ 1;

	/* Send buffered output data to the socket. */
	olen = sshbuf_len(c->output);
	ಯದಿ (c->output_filter != ರಿಕ್ತ) {
		ಯದಿ ((buf = c->output_filter(ssh, c, &data, &dlen)) == ರಿಕ್ತ) {
			debug2("channel %d: filter stops", c->self);
			ಯದಿ (c->type != SSH_CHANNEL_OPEN)
				chan_mark_dead(ssh, c);
			ಅನ್ಯಥಾ
				chan_write_failed(ssh, c);
			ಪ್ರತ್ಯಾಗಮ -1;
		}
	} ಅನ್ಯಥಾ ಯದಿ (c->datagram) {
		ಯದಿ ((r = sshbuf_get_string(c->output, &data, &dlen)) != 0)
			fatal_fr(r, "channel %i: get datagram", c->self);
		buf = data;
	} ಅನ್ಯಥಾ {
		buf = data = sshbuf_mutable_ptr(c->output);
		dlen = sshbuf_len(c->output);
	}

	ಯದಿ (c->datagram) {
		/* ignore truncated writes, datagrams might get lost */
		len = ಲಿಖ(c->wfd, buf, dlen);
		ಮುಕ್ತ(data);
		ಯದಿ (len == -1 && (errno == EINTR || errno == EAGAIN ||
		    errno == EWOULDBLOCK))
			ಪ್ರತ್ಯಾಗಮ 1;
		ಯದಿ (len <= 0)
			ಗಚ್ಛ write_fail;
		ಗಚ್ಛ out;
	}

#ifdef _AIX
	/* XXX: Later AIX versions can't push as much data to tty */
	ಯದಿ (c->wfd_isatty)
		dlen = MINIMUM(dlen, 8*1024);
#endif

	len = ಲಿಖ(c->wfd, buf, dlen);
	ಯದಿ (len == -1 &&
	    (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
		ಪ್ರತ್ಯಾಗಮ 1;
	ಯದಿ (len <= 0) {
 write_fail:
		ಯದಿ (c->type != SSH_CHANNEL_OPEN) {
			debug2("channel %d: not open", c->self);
			chan_mark_dead(ssh, c);
			ಪ್ರತ್ಯಾಗಮ -1;
		} ಅನ್ಯಥಾ {
			chan_write_failed(ssh, c);
		}
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	channel_set_used_time(ssh, c);
#ifndef BROKEN_TCGETATTR_ICANON
	ಯದಿ (c->isatty && dlen >= 1 && buf[0] != '\r') {
		ಯದಿ (tcgetattr(c->wfd, &tio) == 0 &&
		    !(tio.c_lflag & ECHO) && (tio.c_lflag & ICANON)) {
			/*
			 * Simulate echo to reduce the impact of
			 * traffic analysis. We need to match the
			 * size of a SSH2_MSG_CHANNEL_DATA message
			 * (4 byte channel id + buf)
			 */
			ಯದಿ ((r = sshpkt_ಸಂದೇಶ_ignore(ssh, 4+len)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "channel %i: ignore", c->self);
		}
	}
#endif /* BROKEN_TCGETATTR_ICANON */
	ಯದಿ ((r = sshbuf_consume(c->output, len)) != 0)
		fatal_fr(r, "channel %i: consume", c->self);
 out:
	c->local_consumed += olen - sshbuf_len(c->output);

	ಪ್ರತ್ಯಾಗಮ 1;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
channel_handle_efd_write(ಸಂರಚನಾ ssh *ssh, Channel *c)
{
	ಪೂರ್ಣಾಙ್ಕ r;
	ssize_t len;

	ಯದಿ ((c->io_ready & SSH_CHAN_IO_EFD_W) == 0)
		ಪ್ರತ್ಯಾಗಮ 1;
	ಯದಿ (sshbuf_len(c->extended) == 0)
		ಪ್ರತ್ಯಾಗಮ 1;

	len = ಲಿಖ(c->efd, sshbuf_ptr(c->extended),
	    sshbuf_len(c->extended));
	debug2("channel %d: written %zd to efd %d", c->self, len, c->efd);
	ಯದಿ (len == -1 && (errno == EINTR || errno == EAGAIN ||
	    errno == EWOULDBLOCK))
		ಪ್ರತ್ಯಾಗಮ 1;
	ಯದಿ (len <= 0) {
		debug2("channel %d: closing write-efd %d", c->self, c->efd);
		channel_close_fd(ssh, c, &c->efd);
	} ಅನ್ಯಥಾ {
		ಯದಿ ((r = sshbuf_consume(c->extended, len)) != 0)
			fatal_fr(r, "channel %i: consume", c->self);
		c->local_consumed += len;
		channel_set_used_time(ssh, c);
	}
	ಪ್ರತ್ಯಾಗಮ 1;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
channel_handle_efd_read(ಸಂರಚನಾ ssh *ssh, Channel *c)
{
	ವರ್ಣ buf[CHAN_RBUF];
	ssize_t len;
	ಪೂರ್ಣಾಙ್ಕ r, force;

	force = c->isatty && c->detach_close && c->istate != CHAN_ಒಳಹರಿವು_CLOSED;

	ಯದಿ (!force && (c->io_ready & SSH_CHAN_IO_EFD_R) == 0)
		ಪ್ರತ್ಯಾಗಮ 1;

	len = ಪಠ(c->efd, buf, ಪರಿಮಾಣ(buf));
	debug2("channel %d: read %zd from efd %d", c->self, len, c->efd);
	ಯದಿ (len == -1 && (errno == EINTR || ((errno == EAGAIN ||
	    errno == EWOULDBLOCK) && !force)))
		ಪ್ರತ್ಯಾಗಮ 1;
	ಯದಿ (len <= 0) {
		debug2("channel %d: closing read-efd %d", c->self, c->efd);
		channel_close_fd(ssh, c, &c->efd);
		ಪ್ರತ್ಯಾಗಮ 1;
	}
	channel_set_used_time(ssh, c);
	ಯದಿ (c->extended_usage == CHAN_EXTENDED_IGNORE)
		debug3("channel %d: discard efd", c->self);
	ಅನ್ಯಥಾ ಯದಿ ((r = sshbuf_put(c->extended, buf, len)) != 0)
		fatal_fr(r, "channel %i: append", c->self);
	ಪ್ರತ್ಯಾಗಮ 1;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
channel_handle_efd(ಸಂರಚನಾ ssh *ssh, Channel *c)
{
	ಯದಿ (c->efd == -1)
		ಪ್ರತ್ಯಾಗಮ 1;

	/** XXX handle drain efd, too */

	ಯದಿ (c->extended_usage == CHAN_EXTENDED_WRITE)
		ಪ್ರತ್ಯಾಗಮ channel_handle_efd_write(ssh, c);
	ಅನ್ಯಥಾ ಯದಿ (c->extended_usage == CHAN_EXTENDED_READ ||
	    c->extended_usage == CHAN_EXTENDED_IGNORE)
		ಪ್ರತ್ಯಾಗಮ channel_handle_efd_read(ssh, c);

	ಪ್ರತ್ಯಾಗಮ 1;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
channel_check_window(ಸಂರಚನಾ ssh *ssh, Channel *c)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (c->type == SSH_CHANNEL_OPEN &&
	    !(c->flags & (CHAN_CLOSE_SENT|CHAN_CLOSE_RCVD)) &&
	    ((c->local_window_max - c->local_window >
	    c->local_maxpacket*3) ||
	    c->local_window < c->local_window_max/2) &&
	    c->local_consumed > 0) {
		ಯದಿ (!c->have_remote_id)
			fatal_f("channel %d: no remote id", c->self);
		ಯದಿ ((r = sshpkt_start(ssh,
		    SSH2_ಸಂದೇಶ_CHANNEL_WINDOW_ADJUST)) != 0 ||
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
	ಪ್ರತ್ಯಾಗಮ 1;
}

ಸ್ಥಿರ ಶೂನ್ಯ
channel_post_open(ಸಂರಚನಾ ssh *ssh, Channel *c)
{
	channel_handle_rfd(ssh, c);
	channel_handle_wfd(ssh, c);
	channel_handle_efd(ssh, c);
	channel_check_window(ssh, c);
}

ಸ್ಥಿರ u_int
read_mux(ಸಂರಚನಾ ssh *ssh, Channel *c, u_int need)
{
	ವರ್ಣ buf[CHAN_RBUF];
	ssize_t len;
	u_int rlen;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (sshbuf_len(c->ಒಳಹರಿವು) < need) {
		rlen = need - sshbuf_len(c->ಒಳಹರಿವು);
		len = ಪಠ(c->rfd, buf, MINIMUM(rlen, CHAN_RBUF));
		ಯದಿ (len == -1 && (errno == EINTR || errno == EAGAIN))
			ಪ್ರತ್ಯಾಗಮ sshbuf_len(c->ಒಳಹರಿವು);
		ಯದಿ (len <= 0) {
			debug2("channel %d: ctl read<=0 rfd %d len %zd",
			    c->self, c->rfd, len);
			chan_read_failed(ssh, c);
			ಪ್ರತ್ಯಾಗಮ 0;
		} ಅನ್ಯಥಾ ಯದಿ ((r = sshbuf_put(c->ಒಳಹರಿವು, buf, len)) != 0)
			fatal_fr(r, "channel %i: append", c->self);
	}
	ಪ್ರತ್ಯಾಗಮ sshbuf_len(c->ಒಳಹರಿವು);
}

ಸ್ಥಿರ ಶೂನ್ಯ
channel_post_mux_client_read(ಸಂರಚನಾ ssh *ssh, Channel *c)
{
	u_int need;

	ಯದಿ ((c->io_ready & SSH_CHAN_IO_RFD) == 0)
		ಪ್ರತ್ಯಾಗಮ;
	ಯದಿ (c->istate != CHAN_ಒಳಹರಿವು_OPEN && c->istate != CHAN_ಒಳಹರಿವು_WAIT_DRAIN)
		ಪ್ರತ್ಯಾಗಮ;
	ಯದಿ (c->mux_pause)
		ಪ್ರತ್ಯಾಗಮ;

	/*
	 * Don't not read past the precise end of packets to
	 * avoid disrupting fd passing.
	 */
	ಯದಿ (read_mux(ssh, c, 4) < 4) /* read header */
		ಪ್ರತ್ಯಾಗಮ;
	/* XXX sshbuf_peek_u32 */
	need = PEEK_U32(sshbuf_ptr(c->ಒಳಹರಿವು));
#define CHANNEL_MUX_MAX_PACKET	(256 * 1024)
	ಯದಿ (need > CHANNEL_MUX_MAX_PACKET) {
		debug2("channel %d: packet too big %u > %u",
		    c->self, CHANNEL_MUX_MAX_PACKET, need);
		chan_rcvd_oclose(ssh, c);
		ಪ್ರತ್ಯಾಗಮ;
	}
	ಯದಿ (read_mux(ssh, c, need + 4) < need + 4) /* read body */
		ಪ್ರತ್ಯಾಗಮ;
	ಯದಿ (c->mux_rcb(ssh, c) != 0) {
		debug("channel %d: mux_rcb failed", c->self);
		chan_mark_dead(ssh, c);
		ಪ್ರತ್ಯಾಗಮ;
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
channel_post_mux_client_write(ಸಂರಚನಾ ssh *ssh, Channel *c)
{
	ssize_t len;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((c->io_ready & SSH_CHAN_IO_WFD) == 0)
		ಪ್ರತ್ಯಾಗಮ;
	ಯದಿ (sshbuf_len(c->output) == 0)
		ಪ್ರತ್ಯಾಗಮ;

	len = ಲಿಖ(c->wfd, sshbuf_ptr(c->output), sshbuf_len(c->output));
	ಯದಿ (len == -1 && (errno == EINTR || errno == EAGAIN))
		ಪ್ರತ್ಯಾಗಮ;
	ಯದಿ (len <= 0) {
		chan_mark_dead(ssh, c);
		ಪ್ರತ್ಯಾಗಮ;
	}
	ಯದಿ ((r = sshbuf_consume(c->output, len)) != 0)
		fatal_fr(r, "channel %i: consume", c->self);
}

ಸ್ಥಿರ ಶೂನ್ಯ
channel_post_mux_client(ಸಂರಚನಾ ssh *ssh, Channel *c)
{
	channel_post_mux_client_read(ssh, c);
	channel_post_mux_client_write(ssh, c);
}

ಸ್ಥಿರ ಶೂನ್ಯ
channel_post_mux_listener(ಸಂರಚನಾ ssh *ssh, Channel *c)
{
	Channel *nc;
	ಸಂರಚನಾ sockaddr_storage addr;
	socklen_t addrlen;
	ಪೂರ್ಣಾಙ್ಕ newsock;
	uid_t euid;
	gid_t egid;

	ಯದಿ ((c->io_ready & SSH_CHAN_IO_SOCK_R) == 0)
		ಪ್ರತ್ಯಾಗಮ;

	debug("multiplexing control connection");

	/*
	 * Accept connection on control socket
	 */
	memset(&addr, 0, ಪರಿಮಾಣ(addr));
	addrlen = ಪರಿಮಾಣ(addr);
	ಯದಿ ((newsock = accept(c->sock, (ಸಂರಚನಾ sockaddr*)&addr,
	    &addrlen)) == -1) {
		error_f("accept: %s", strerror(errno));
		ಯದಿ (errno == EMFILE || errno == ENFILE)
			c->notbefore = monotime_double() + 1.0;
		ಪ್ರತ್ಯಾಗಮ;
	}

	ಯದಿ (getpeereid(newsock, &euid, &egid) == -1) {
		error_f("getpeereid failed: %s", strerror(errno));
		close(newsock);
		ಪ್ರತ್ಯಾಗಮ;
	}
	ಯದಿ ((euid != 0) && (getuid() != euid)) {
		error("multiplex uid mismatch: peer euid %u != uid %u",
		    (u_int)euid, (u_int)getuid());
		close(newsock);
		ಪ್ರತ್ಯಾಗಮ;
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

ಸ್ಥಿರ ಶೂನ್ಯ
channel_handler_init(ಸಂರಚನಾ ssh_channels *sc)
{
	chan_fn **pre, **post;

	ಯದಿ ((pre = calloc(SSH_CHANNEL_MAX_TYPE, ಪರಿಮಾಣ(*pre))) == ರಿಕ್ತ ||
	    (post = calloc(SSH_CHANNEL_MAX_TYPE, ಪರಿಮಾಣ(*post))) == ರಿಕ್ತ)
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
ಸ್ಥಿರ ಶೂನ್ಯ
channel_garbage_collect(ಸಂರಚನಾ ssh *ssh, Channel *c)
{
	ಯದಿ (c == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;
	ಯದಿ (c->detach_user != ರಿಕ್ತ) {
		ಯದಿ (!chan_is_dead(ssh, c, c->detach_close))
			ಪ್ರತ್ಯಾಗಮ;

		debug2("channel %d: gc: notify user", c->self);
		c->detach_user(ssh, c->self, 0, ರಿಕ್ತ);
		/* if we still have a callback */
		ಯದಿ (c->detach_user != ರಿಕ್ತ)
			ಪ್ರತ್ಯಾಗಮ;
		debug2("channel %d: gc: user detached", c->self);
	}
	ಯದಿ (!chan_is_dead(ssh, c, 1))
		ಪ್ರತ್ಯಾಗಮ;
	debug2("channel %d: garbage collecting", c->self);
	channel_free(ssh, c);
}

ಗಣನಾ channel_table { CHAN_PRE, CHAN_POST };

ಸ್ಥಿರ ಶೂನ್ಯ
channel_handler(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ table, ಸಂರಚನಾ timespec *timeout)
{
	ಸಂರಚನಾ ssh_channels *sc = ssh->chanctxt;
	chan_fn **ftab = table == CHAN_PRE ? sc->channel_pre : sc->channel_post;
	u_int i, oalloc;
	Channel *c;
	ದ್ವಿಗುಣ now;

	now = monotime_double();
	ಪ್ರತಿ (sc->nbulk = i = 0, oalloc = sc->channels_alloc; i < oalloc; i++) {
		c = sc->channels[i];
		ಯದಿ (c == ರಿಕ್ತ)
			ಅನುವರ್ತ;
		/* Count open channels in bulk state */
		ಯದಿ (c->type == SSH_CHANNEL_OPEN && c->bulk)
			sc->nbulk++;
		/* Try to keep IO going while rekeying */
		ಯದಿ (ssh_packet_is_rekeying(ssh) && c->type != SSH_CHANNEL_OPEN)
			ಅನುವರ್ತ;
		ಯದಿ (c->delayed) {
			ಯದಿ (table == CHAN_PRE)
				c->delayed = 0;
			ಅನ್ಯಥಾ
				ಅನುವರ್ತ;
		}
		ಯದಿ (ftab[c->type] != ರಿಕ್ತ) {
			ಯದಿ (table == CHAN_PRE && c->type == SSH_CHANNEL_OPEN &&
			    channel_get_expiry(ssh, c) != 0 &&
			    now >= channel_get_expiry(ssh, c)) {
				/* channel closed for inactivity */
				ದ್ವಿಗುಣ deadline = c->inactive_deadline != 0.0 ?
				    c->inactive_deadline : sc->global_deadline;
				verbose("channel %d: closing after %f seconds "
				    "of inactivity", c->self, deadline);
				channel_force_close(ssh, c, 1);
			} ಅನ್ಯಥಾ ಯದಿ (c->notbefore <= now) {
				/* Run handlers that are not paused. */
				(*ftab[c->type])(ssh, c);
				/* inactivity timeouts must interrupt poll() */
				ಯದಿ (timeout != ರಿಕ್ತ &&
				    c->type == SSH_CHANNEL_OPEN &&
				    channel_get_expiry(ssh, c) != 0) {
					ptimeout_deadline_monotime_double(timeout,
					    channel_get_expiry(ssh, c));
				}
			} ಅನ್ಯಥಾ ಯದಿ (timeout != ರಿಕ್ತ) {
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
ಸ್ಥಿರ ಶೂನ್ಯ
channel_before_prepare_io(ಸಂರಚನಾ ssh *ssh)
{
	ಸಂರಚನಾ ssh_channels *sc = ssh->chanctxt;
	Channel *c;
	u_int i, oalloc;

	ಪ್ರತಿ (i = 0, oalloc = sc->channels_alloc; i < oalloc; i++) {
		c = sc->channels[i];
		ಯದಿ (c == ರಿಕ್ತ)
			ಅನುವರ್ತ;
		ಯದಿ (c->type == SSH_CHANNEL_RDYNAMIC_OPEN)
			channel_before_prepare_io_rdynamic(ssh, c);
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
dump_channel_poll(ಧ್ರುವ ವರ್ಣ *func, ಧ್ರುವ ವರ್ಣ *what, Channel *c,
    u_int pollfd_offset, ಸಂರಚನಾ pollfd *pfd)
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
ಸ್ಥಿರ ಶೂನ್ಯ
channel_prepare_pollfd(Channel *c, u_int *next_pollfd,
    ಸಂರಚನಾ pollfd *pfd, u_int npfd)
{
	u_int ev, p = *next_pollfd;

	ಯದಿ (c == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;
	ಯದಿ (p + 4 > npfd) {
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
	ಯದಿ (c->rfd != -1) {
		ev = 0;
		ಯದಿ ((c->io_want & SSH_CHAN_IO_RFD) != 0)
			ev |= POLLIN;
		/* rfd == wfd */
		ಯದಿ (c->wfd == c->rfd) {
			ಯದಿ ((c->io_want & SSH_CHAN_IO_WFD) != 0)
				ev |= POLLOUT;
		}
		/* rfd == efd */
		ಯದಿ (c->efd == c->rfd) {
			ಯದಿ ((c->io_want & SSH_CHAN_IO_EFD_R) != 0)
				ev |= POLLIN;
			ಯದಿ ((c->io_want & SSH_CHAN_IO_EFD_W) != 0)
				ev |= POLLOUT;
		}
		/* rfd == sock */
		ಯದಿ (c->sock == c->rfd) {
			ಯದಿ ((c->io_want & SSH_CHAN_IO_SOCK_R) != 0)
				ev |= POLLIN;
			ಯದಿ ((c->io_want & SSH_CHAN_IO_SOCK_W) != 0)
				ev |= POLLOUT;
		}
		/* Pack a pfd entry if any event armed for this fd */
		ಯದಿ (ev != 0) {
			c->pfds[0] = p;
			pfd[p].fd = c->rfd;
			pfd[p].events = ev;
			dump_channel_poll(__func__, "rfd", c, p, &pfd[p]);
			p++;
		}
	}
	/* prepare c->wfd if wanting IO and not already handled above */
	ಯದಿ (c->wfd != -1 && c->rfd != c->wfd) {
		ev = 0;
		ಯದಿ ((c->io_want & SSH_CHAN_IO_WFD))
			ev |= POLLOUT;
		/* Pack a pfd entry if any event armed for this fd */
		ಯದಿ (ev != 0) {
			c->pfds[1] = p;
			pfd[p].fd = c->wfd;
			pfd[p].events = ev;
			dump_channel_poll(__func__, "wfd", c, p, &pfd[p]);
			p++;
		}
	}
	/* prepare c->efd if wanting IO and not already handled above */
	ಯದಿ (c->efd != -1 && c->rfd != c->efd) {
		ev = 0;
		ಯದಿ ((c->io_want & SSH_CHAN_IO_EFD_R) != 0)
			ev |= POLLIN;
		ಯದಿ ((c->io_want & SSH_CHAN_IO_EFD_W) != 0)
			ev |= POLLOUT;
		/* Pack a pfd entry if any event armed for this fd */
		ಯದಿ (ev != 0) {
			c->pfds[2] = p;
			pfd[p].fd = c->efd;
			pfd[p].events = ev;
			dump_channel_poll(__func__, "efd", c, p, &pfd[p]);
			p++;
		}
	}
	/* prepare c->sock if wanting IO and not already handled above */
	ಯದಿ (c->sock != -1 && c->rfd != c->sock) {
		ev = 0;
		ಯದಿ ((c->io_want & SSH_CHAN_IO_SOCK_R) != 0)
			ev |= POLLIN;
		ಯದಿ ((c->io_want & SSH_CHAN_IO_SOCK_W) != 0)
			ev |= POLLOUT;
		/* Pack a pfd entry if any event armed for this fd */
		ಯದಿ (ev != 0) {
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
ಶೂನ್ಯ
channel_prepare_poll(ಸಂರಚನಾ ssh *ssh, ಸಂರಚನಾ pollfd **pfdp, u_int *npfd_allocp,
    u_int *npfd_activep, u_int npfd_reserved, ಸಂರಚನಾ timespec *timeout)
{
	ಸಂರಚನಾ ssh_channels *sc = ssh->chanctxt;
	u_int i, oalloc, p, npfd = npfd_reserved;

	channel_before_prepare_io(ssh); /* might create a new channel */
	/* clear out I/O flags from last poll */
	ಪ್ರತಿ (i = 0; i < sc->channels_alloc; i++) {
		ಯದಿ (sc->channels[i] == ರಿಕ್ತ)
			ಅನುವರ್ತ;
		sc->channels[i]->io_want = sc->channels[i]->io_ready = 0;
	}
	/* Allocate 4x pollfd for each channel (rfd, wfd, efd, sock) */
	ಯದಿ (sc->channels_alloc >= (INT_MAX / 4) - npfd_reserved)
		fatal_f("too many channels"); /* shouldn't happen */
	npfd += sc->channels_alloc * 4;
	ಯದಿ (npfd > *npfd_allocp) {
		*pfdp = xrecallocarray(*pfdp, *npfd_allocp,
		    npfd, ಪರಿಮಾಣ(**pfdp));
		*npfd_allocp = npfd;
	}
	*npfd_activep = npfd_reserved;
	oalloc = sc->channels_alloc;

	channel_handler(ssh, CHAN_PRE, timeout);

	ಯದಿ (oalloc != sc->channels_alloc) {
		/* shouldn't happen */
		fatal_f("channels_alloc changed during CHAN_PRE "
		    "(was %u, now %u)", oalloc, sc->channels_alloc);
	}

	/* Prepare pollfd */
	p = npfd_reserved;
	ಪ್ರತಿ (i = 0; i < sc->channels_alloc; i++)
		channel_prepare_pollfd(sc->channels[i], &p, *pfdp, npfd);
	*npfd_activep = p;
}

ಸ್ಥಿರ ಶೂನ್ಯ
fd_ready(Channel *c, ಪೂರ್ಣಾಙ್ಕ p, ಸಂರಚನಾ pollfd *pfds, u_int npfd, ಪೂರ್ಣಾಙ್ಕ fd,
    ಧ್ರುವ ವರ್ಣ *what, u_int revents_mask, u_int ready)
{
	ಸಂರಚನಾ pollfd *pfd = &pfds[p];

	ಯದಿ (fd == -1)
		ಪ್ರತ್ಯಾಗಮ;
	ಯದಿ (p == -1 || (u_int)p >= npfd)
		fatal_f("channel %d: bad pfd %d (max %u)", c->self, p, npfd);
	dump_channel_poll(__func__, what, c, p, pfd);
	ಯದಿ (pfd->fd != fd) {
		fatal("channel %d: inconsistent %s fd=%d pollfd[%u].fd %d "
		    "r%d w%d e%d s%d", c->self, what, fd, p, pfd->fd,
		    c->rfd, c->wfd, c->efd, c->sock);
	}
	ಯದಿ ((pfd->revents & POLLNVAL) != 0) {
		fatal("channel %d: invalid %s pollfd[%u].fd %d r%d w%d e%d s%d",
		    c->self, what, p, pfd->fd, c->rfd, c->wfd, c->efd, c->sock);
	}
	ಯದಿ ((pfd->revents & (revents_mask|POLLHUP|POLLERR)) != 0)
		c->io_ready |= ready & c->io_want;
}

/*
 * After poll, perform any appropriate operations for channels which have
 * events pending.
 */
ಶೂನ್ಯ
channel_after_poll(ಸಂರಚನಾ ssh *ssh, ಸಂರಚನಾ pollfd *pfd, u_int npfd)
{
	ಸಂರಚನಾ ssh_channels *sc = ssh->chanctxt;
	u_int i;
	ಪೂರ್ಣಾಙ್ಕ p;
	Channel *c;

#ifdef DEBUG_CHANNEL_POLL
	ಪ್ರತಿ (p = 0; p < (ಪೂರ್ಣಾಙ್ಕ)npfd; p++) {
		ಯದಿ (pfd[p].revents == 0)
			ಅನುವರ್ತ;
		debug_f("pfd[%u].fd %d rev 0x%04x",
		    p, pfd[p].fd, pfd[p].revents);
	}
#endif

	/* Convert pollfd into c->io_ready */
	ಪ್ರತಿ (i = 0; i < sc->channels_alloc; i++) {
		c = sc->channels[i];
		ಯದಿ (c == ರಿಕ್ತ)
			ಅನುವರ್ತ;
		/* if rfd is shared with efd/sock then wfd should be too */
		ಯದಿ (c->rfd != -1 && c->wfd != -1 && c->rfd != c->wfd &&
		    (c->rfd == c->efd || c->rfd == c->sock)) {
			/* Shouldn't happen */
			fatal_f("channel %d: unexpected fds r%d w%d e%d s%d",
			    c->self, c->rfd, c->wfd, c->efd, c->sock);
		}
		c->io_ready = 0;
		/* rfd, potentially shared with wfd, efd and sock */
		ಯದಿ (c->rfd != -1 && (p = c->pfds[0]) != -1) {
			fd_ready(c, p, pfd, npfd, c->rfd,
			    "rfd", POLLIN, SSH_CHAN_IO_RFD);
			ಯದಿ (c->rfd == c->wfd) {
				fd_ready(c, p, pfd, npfd, c->wfd,
				    "wfd/r", POLLOUT, SSH_CHAN_IO_WFD);
			}
			ಯದಿ (c->rfd == c->efd) {
				fd_ready(c, p, pfd, npfd, c->efd,
				    "efdr/r", POLLIN, SSH_CHAN_IO_EFD_R);
				fd_ready(c, p, pfd, npfd, c->efd,
				    "efdw/r", POLLOUT, SSH_CHAN_IO_EFD_W);
			}
			ಯದಿ (c->rfd == c->sock) {
				fd_ready(c, p, pfd, npfd, c->sock,
				    "sockr/r", POLLIN, SSH_CHAN_IO_SOCK_R);
				fd_ready(c, p, pfd, npfd, c->sock,
				    "sockw/r", POLLOUT, SSH_CHAN_IO_SOCK_W);
			}
			dump_channel_poll(__func__, "rfd", c, p, pfd);
		}
		/* wfd */
		ಯದಿ (c->wfd != -1 && c->wfd != c->rfd &&
		    (p = c->pfds[1]) != -1) {
			fd_ready(c, p, pfd, npfd, c->wfd,
			    "wfd", POLLOUT, SSH_CHAN_IO_WFD);
			dump_channel_poll(__func__, "wfd", c, p, pfd);
		}
		/* efd */
		ಯದಿ (c->efd != -1 && c->efd != c->rfd &&
		    (p = c->pfds[2]) != -1) {
			fd_ready(c, p, pfd, npfd, c->efd,
			    "efdr", POLLIN, SSH_CHAN_IO_EFD_R);
			fd_ready(c, p, pfd, npfd, c->efd,
			    "efdw", POLLOUT, SSH_CHAN_IO_EFD_W);
			dump_channel_poll(__func__, "efd", c, p, pfd);
		}
		/* sock */
		ಯದಿ (c->sock != -1 && c->sock != c->rfd &&
		    (p = c->pfds[3]) != -1) {
			fd_ready(c, p, pfd, npfd, c->sock,
			    "sockr", POLLIN, SSH_CHAN_IO_SOCK_R);
			fd_ready(c, p, pfd, npfd, c->sock,
			    "sockw", POLLOUT, SSH_CHAN_IO_SOCK_W);
			dump_channel_poll(__func__, "sock", c, p, pfd);
		}
	}
	channel_handler(ssh, CHAN_POST, ರಿಕ್ತ);
}

/*
 * Enqueue data for channels with open or draining c->input.
 * Returns non-zero if a packet was enqueued.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
channel_output_poll_ಒಳಹರಿವು_open(ಸಂರಚನಾ ssh *ssh, Channel *c)
{
	size_t len, plen;
	ಧ್ರುವ u_char *pkt;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((len = sshbuf_len(c->ಒಳಹರಿವು)) == 0) {
		ಯದಿ (c->istate == CHAN_ಒಳಹರಿವು_WAIT_DRAIN) {
			/*
			 * input-buffer is empty and read-socket shutdown:
			 * tell peer, that we will not send more data:
			 * send IEOF.
			 * hack for extended data: delay EOF if EFD still
			 * in use.
			 */
			ಯದಿ (CHANNEL_EFD_ಒಳಹರಿವು_ACTIVE(c))
				debug2("channel %d: "
				    "ibuf_empty delayed efd %d/(%zu)",
				    c->self, c->efd, sshbuf_len(c->extended));
			ಅನ್ಯಥಾ
				chan_ibuf_empty(ssh, c);
		}
		ಪ್ರತ್ಯಾಗಮ 0;
	}

	ಯದಿ (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);

	ಯದಿ (c->datagram) {
		/* Check datagram will fit; drop if not */
		ಯದಿ ((r = sshbuf_get_string_direct(c->ಒಳಹರಿವು, &pkt, &plen)) != 0)
			fatal_fr(r, "channel %i: get datagram", c->self);
		/*
		 * XXX this does tail-drop on the datagram queue which is
		 * usually suboptimal compared to head-drop. Better to have
		 * backpressure at read time? (i.e. read + discard)
		 */
		ಯದಿ (plen > c->remote_window || plen > c->remote_maxpacket) {
			debug("channel %d: datagram too big", c->self);
			ಪ್ರತ್ಯಾಗಮ 0;
		}
		/* Enqueue it */
		ಯದಿ ((r = sshpkt_start(ssh, SSH2_ಸಂದೇಶ_CHANNEL_DATA)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
		    (r = sshpkt_put_string(ssh, pkt, plen)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "channel %i: send datagram", c->self);
		c->remote_window -= plen;
		ಪ್ರತ್ಯಾಗಮ 1;
	}

	/* Enqueue packet for buffered data. */
	ಯದಿ (len > c->remote_window)
		len = c->remote_window;
	ಯದಿ (len > c->remote_maxpacket)
		len = c->remote_maxpacket;
	ಯದಿ (len == 0)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ ((r = sshpkt_start(ssh, SSH2_ಸಂದೇಶ_CHANNEL_DATA)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_string(ssh, sshbuf_ptr(c->ಒಳಹರಿವು), len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i: send data", c->self);
	ಯದಿ ((r = sshbuf_consume(c->ಒಳಹರಿವು, len)) != 0)
		fatal_fr(r, "channel %i: consume", c->self);
	c->remote_window -= len;
	ಪ್ರತ್ಯಾಗಮ 1;
}

/*
 * Enqueue data for channels with open c->extended in read mode.
 * Returns non-zero if a packet was enqueued.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
channel_output_poll_extended_read(ಸಂರಚನಾ ssh *ssh, Channel *c)
{
	size_t len;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((len = sshbuf_len(c->extended)) == 0)
		ಪ್ರತ್ಯಾಗಮ 0;

	debug2("channel %d: rwin %u elen %zu euse %d", c->self,
	    c->remote_window, sshbuf_len(c->extended), c->extended_usage);
	ಯದಿ (len > c->remote_window)
		len = c->remote_window;
	ಯದಿ (len > c->remote_maxpacket)
		len = c->remote_maxpacket;
	ಯದಿ (len == 0)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);
	ಯದಿ ((r = sshpkt_start(ssh, SSH2_ಸಂದೇಶ_CHANNEL_EXTENDED_DATA)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_u32(ssh, SSH2_EXTENDED_DATA_STDERR)) != 0 ||
	    (r = sshpkt_put_string(ssh, sshbuf_ptr(c->extended), len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i: data", c->self);
	ಯದಿ ((r = sshbuf_consume(c->extended, len)) != 0)
		fatal_fr(r, "channel %i: consume", c->self);
	c->remote_window -= len;
	debug2("channel %d: sent ext data %zu", c->self, len);
	ಪ್ರತ್ಯಾಗಮ 1;
}

/*
 * If there is data to send to the connection, enqueue some of it now.
 * Returns non-zero if data was enqueued.
 */
ಪೂರ್ಣಾಙ್ಕ
channel_output_poll(ಸಂರಚನಾ ssh *ssh)
{
	ಸಂರಚನಾ ssh_channels *sc = ssh->chanctxt;
	Channel *c;
	u_int i;
	ಪೂರ್ಣಾಙ್ಕ ret = 0;

	ಪ್ರತಿ (i = 0; i < sc->channels_alloc; i++) {
		c = sc->channels[i];
		ಯದಿ (c == ರಿಕ್ತ)
			ಅನುವರ್ತ;

		/*
		 * We are only interested in channels that can have buffered
		 * incoming data.
		 */
		ಯದಿ (c->type != SSH_CHANNEL_OPEN)
			ಅನುವರ್ತ;
		ಯದಿ ((c->flags & (CHAN_CLOSE_SENT|CHAN_CLOSE_RCVD))) {
			/* XXX is this true? */
			debug3("channel %d: will not send data after close",
			    c->self);
			ಅನುವರ್ತ;
		}

		/* Get the amount of buffered data for this channel. */
		ಯದಿ (c->istate == CHAN_ಒಳಹರಿವು_OPEN ||
		    c->istate == CHAN_ಒಳಹರಿವು_WAIT_DRAIN)
			ret |= channel_output_poll_ಒಳಹರಿವು_open(ssh, c);
		/* Send extended data, i.e. stderr */
		ಯದಿ (!(c->flags & CHAN_EOF_SENT) &&
		    c->extended_usage == CHAN_EXTENDED_READ)
			ret |= channel_output_poll_extended_read(ssh, c);
	}
	ಪ್ರತ್ಯಾಗಮ ret;
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
ಪೂರ್ಣಾಙ್ಕ
channel_proxy_downstream(ಸಂರಚನಾ ssh *ssh, Channel *downstream)
{
	Channel *c = ರಿಕ್ತ;
	ಸಂರಚನಾ sshbuf *original = ರಿಕ್ತ, *modified = ರಿಕ್ತ;
	ಧ್ರುವ u_char *cp;
	ವರ್ಣ *ctype = ರಿಕ್ತ, *listen_host = ರಿಕ್ತ;
	u_char type;
	size_t have;
	ಪೂರ್ಣಾಙ್ಕ ret = -1, r;
	u_int id, remote_id, listen_port;

	/* sshbuf_dump(downstream->input, stderr); */
	ಯದಿ ((r = sshbuf_get_string_direct(downstream->ಒಳಹರಿವು, &cp, &have))
	    != 0) {
		error_fr(r, "parse");
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	ಯದಿ (have < 2) {
		error_f("short message");
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	type = cp[1];
	/* skip padlen + type */
	cp += 2;
	have -= 2;
	ಯದಿ (ssh_packet_log_type(type))
		debug3_f("channel %u: down->up: type %u",
		    downstream->self, type);

	ವಿಕಲ್ಪ (type) {
	ಪಕ್ಷ SSH2_ಸಂದೇಶ_CHANNEL_OPEN:
		ಯದಿ ((original = sshbuf_from(cp, have)) == ರಿಕ್ತ ||
		    (modified = sshbuf_new()) == ರಿಕ್ತ) {
			error_f("alloc");
			ಗಚ್ಛ out;
		}
		ಯದಿ ((r = sshbuf_get_cstring(original, &ctype, ರಿಕ್ತ)) != 0 ||
		    (r = sshbuf_get_u32(original, &id)) != 0) {
			error_fr(r, "parse");
			ಗಚ್ಛ out;
		}
		c = channel_new(ssh, "mux-proxy", SSH_CHANNEL_MUX_PROXY,
		    -1, -1, -1, 0, 0, 0, ctype, 1);
		c->mux_ctx = downstream;	/* point to mux client */
		c->mux_downstream_id = id;	/* original downstream id */
		ಯದಿ ((r = sshbuf_put_cstring(modified, ctype)) != 0 ||
		    (r = sshbuf_put_u32(modified, c->self)) != 0 ||
		    (r = sshbuf_putb(modified, original)) != 0) {
			error_fr(r, "compose");
			channel_free(ssh, c);
			ಗಚ್ಛ out;
		}
		ಭಙ್ಗ;
	ಪಕ್ಷ SSH2_ಸಂದೇಶ_CHANNEL_OPEN_CONFIRMATION:
		/*
		 * Almost the same as SSH2_MSG_CHANNEL_OPEN, except then we
		 * need to parse 'remote_id' instead of 'ctype'.
		 */
		ಯದಿ ((original = sshbuf_from(cp, have)) == ರಿಕ್ತ ||
		    (modified = sshbuf_new()) == ರಿಕ್ತ) {
			error_f("alloc");
			ಗಚ್ಛ out;
		}
		ಯದಿ ((r = sshbuf_get_u32(original, &remote_id)) != 0 ||
		    (r = sshbuf_get_u32(original, &id)) != 0) {
			error_fr(r, "parse");
			ಗಚ್ಛ out;
		}
		c = channel_new(ssh, "mux-proxy", SSH_CHANNEL_MUX_PROXY,
		    -1, -1, -1, 0, 0, 0, "mux-down-connect", 1);
		c->mux_ctx = downstream;	/* point to mux client */
		c->mux_downstream_id = id;
		c->remote_id = remote_id;
		c->have_remote_id = 1;
		ಯದಿ ((r = sshbuf_put_u32(modified, remote_id)) != 0 ||
		    (r = sshbuf_put_u32(modified, c->self)) != 0 ||
		    (r = sshbuf_putb(modified, original)) != 0) {
			error_fr(r, "compose");
			channel_free(ssh, c);
			ಗಚ್ಛ out;
		}
		ಭಙ್ಗ;
	ಪಕ್ಷ SSH2_ಸಂದೇಶ_GLOBAL_REQUEST:
		ಯದಿ ((original = sshbuf_from(cp, have)) == ರಿಕ್ತ) {
			error_f("alloc");
			ಗಚ್ಛ out;
		}
		ಯದಿ ((r = sshbuf_get_cstring(original, &ctype, ರಿಕ್ತ)) != 0) {
			error_fr(r, "parse");
			ಗಚ್ಛ out;
		}
		ಯದಿ (strcmp(ctype, "tcpip-forward") != 0) {
			error_f("unsupported request %s", ctype);
			ಗಚ್ಛ out;
		}
		ಯದಿ ((r = sshbuf_get_u8(original, ರಿಕ್ತ)) != 0 ||
		    (r = sshbuf_get_cstring(original, &listen_host, ರಿಕ್ತ)) != 0 ||
		    (r = sshbuf_get_u32(original, &listen_port)) != 0) {
			error_fr(r, "parse");
			ಗಚ್ಛ out;
		}
		ಯದಿ (listen_port > 65535) {
			error_f("tcpip-forward for %s: bad port %u",
			    listen_host, listen_port);
			ಗಚ್ಛ out;
		}
		/* Record that connection to this host/port is permitted. */
		permission_set_add(ssh, FORWARD_USER, FORWARD_LOCAL, "<mux>",
		    -1, listen_host, ರಿಕ್ತ, (ಪೂರ್ಣಾಙ್ಕ)listen_port, downstream);
		ಭಙ್ಗ;
	ಪಕ್ಷ SSH2_ಸಂದೇಶ_CHANNEL_CLOSE:
		ಯದಿ (have < 4)
			ಭಙ್ಗ;
		remote_id = PEEK_U32(cp);
		ಯದಿ ((c = channel_by_remote_id(ssh, remote_id)) != ರಿಕ್ತ) {
			ಯದಿ (c->flags & CHAN_CLOSE_RCVD)
				channel_free(ssh, c);
			ಅನ್ಯಥಾ
				c->flags |= CHAN_CLOSE_SENT;
		}
		ಭಙ್ಗ;
	}
	ಯದಿ (modified) {
		ಯದಿ ((r = sshpkt_start(ssh, type)) != 0 ||
		    (r = sshpkt_putb(ssh, modified)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0) {
			error_fr(r, "send");
			ಗಚ್ಛ out;
		}
	} ಅನ್ಯಥಾ {
		ಯದಿ ((r = sshpkt_start(ssh, type)) != 0 ||
		    (r = sshpkt_put(ssh, cp, have)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0) {
			error_fr(r, "send");
			ಗಚ್ಛ out;
		}
	}
	ret = 0;
 out:
	ಮುಕ್ತ(ctype);
	ಮುಕ್ತ(listen_host);
	sshbuf_free(original);
	sshbuf_free(modified);
	ಪ್ರತ್ಯಾಗಮ ret;
}

/*
 * receive packets from upstream server and de-multiplex packets
 * to correct downstream:
 * implemented as a helper for channel input handlers,
 * replaces local (proxy) channel ID with downstream channel ID.
 */
ಪೂರ್ಣಾಙ್ಕ
channel_proxy_upstream(Channel *c, ಪೂರ್ಣಾಙ್ಕ type, uint32_t seq, ಸಂರಚನಾ ssh *ssh)
{
	ಸಂರಚನಾ sshbuf *b = ರಿಕ್ತ;
	Channel *downstream;
	ಧ್ರುವ u_char *cp = ರಿಕ್ತ;
	size_t len;
	ಪೂರ್ಣಾಙ್ಕ r;

	/*
	 * When receiving packets from the peer we need to check whether we
	 * need to forward the packets to the mux client. In this case we
	 * restore the original channel id and keep track of CLOSE messages,
	 * so we can cleanup the channel.
	 */
	ಯದಿ (c == ರಿಕ್ತ || c->type != SSH_CHANNEL_MUX_PROXY)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ ((downstream = c->mux_ctx) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ 0;
	ವಿಕಲ್ಪ (type) {
	ಪಕ್ಷ SSH2_ಸಂದೇಶ_CHANNEL_CLOSE:
	ಪಕ್ಷ SSH2_ಸಂದೇಶ_CHANNEL_DATA:
	ಪಕ್ಷ SSH2_ಸಂದೇಶ_CHANNEL_EOF:
	ಪಕ್ಷ SSH2_ಸಂದೇಶ_CHANNEL_EXTENDED_DATA:
	ಪಕ್ಷ SSH2_ಸಂದೇಶ_CHANNEL_OPEN_CONFIRMATION:
	ಪಕ್ಷ SSH2_ಸಂದೇಶ_CHANNEL_OPEN_FAILURE:
	ಪಕ್ಷ SSH2_ಸಂದೇಶ_CHANNEL_WINDOW_ADJUST:
	ಪಕ್ಷ SSH2_ಸಂದೇಶ_CHANNEL_SUCCESS:
	ಪಕ್ಷ SSH2_ಸಂದೇಶ_CHANNEL_FAILURE:
	ಪಕ್ಷ SSH2_ಸಂದೇಶ_CHANNEL_REQUEST:
		ಭಙ್ಗ;
	ಸ್ವಭಾವ:
		debug2_f("channel %u: unsupported type %u", c->self, type);
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	ಯದಿ ((b = sshbuf_new()) == ರಿಕ್ತ) {
		error_f("alloc reply");
		ಗಚ್ಛ out;
	}
	/* get remaining payload (after id) */
	cp = sshpkt_ptr(ssh, &len);
	ಯದಿ (cp == ರಿಕ್ತ) {
		error_f("no packet");
		ಗಚ್ಛ out;
	}
	/* translate id and send to muxclient */
	ಯದಿ ((r = sshbuf_put_u8(b, 0)) != 0 ||	/* padlen */
	    (r = sshbuf_put_u8(b, type)) != 0 ||
	    (r = sshbuf_put_u32(b, c->mux_downstream_id)) != 0 ||
	    (r = sshbuf_put(b, cp, len)) != 0 ||
	    (r = sshbuf_put_stringb(downstream->output, b)) != 0) {
		error_fr(r, "compose muxclient");
		ಗಚ್ಛ out;
	}
	/* sshbuf_dump(b, stderr); */
	ಯದಿ (ssh_packet_log_type(type))
		debug3_f("channel %u: up->down: type %u", c->self, type);
 out:
	/* update state */
	ವಿಕಲ್ಪ (type) {
	ಪಕ್ಷ SSH2_ಸಂದೇಶ_CHANNEL_OPEN_CONFIRMATION:
		/* record remote_id for SSH2_MSG_CHANNEL_CLOSE */
		ಯದಿ (cp && len > 4) {
			c->remote_id = PEEK_U32(cp);
			c->have_remote_id = 1;
		}
		ಭಙ್ಗ;
	ಪಕ್ಷ SSH2_ಸಂದೇಶ_CHANNEL_CLOSE:
		ಯದಿ (c->flags & CHAN_CLOSE_SENT)
			channel_free(ssh, c);
		ಅನ್ಯಥಾ
			c->flags |= CHAN_CLOSE_RCVD;
		ಭಙ್ಗ;
	}
	sshbuf_free(b);
	ಪ್ರತ್ಯಾಗಮ 1;
}

/* -- protocol input */

/* Parse a channel ID from the current packet */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
channel_parse_id(ಸಂರಚನಾ ssh *ssh, ಧ್ರುವ ವರ್ಣ *where, ಧ್ರುವ ವರ್ಣ *what)
{
	uint32_t id;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = sshpkt_get_u32(ssh, &id)) != 0) {
		error_r(r, "%s: parse id", where);
		ssh_packet_disconnect(ssh, "Invalid %s message", what);
	}
	ಯದಿ (id > INT_MAX) {
		error_r(r, "%s: bad channel id %u", where, id);
		ssh_packet_disconnect(ssh, "Invalid %s channel id", what);
	}
	ಪ್ರತ್ಯಾಗಮ (ಪೂರ್ಣಾಙ್ಕ)id;
}

/* Lookup a channel from an ID in the current packet */
ಸ್ಥಿರ Channel *
channel_from_packet_id(ಸಂರಚನಾ ssh *ssh, ಧ್ರುವ ವರ್ಣ *where, ಧ್ರುವ ವರ್ಣ *what)
{
	ಪೂರ್ಣಾಙ್ಕ id = channel_parse_id(ssh, where, what);
	Channel *c;

	ಯದಿ ((c = channel_lookup(ssh, id)) == ರಿಕ್ತ) {
		ssh_packet_disconnect(ssh,
		    "%s packet referred to nonexistent channel %d", what, id);
	}
	ಪ್ರತ್ಯಾಗಮ c;
}

ಪೂರ್ಣಾಙ್ಕ
channel_ಒಳಹರಿವು_data(ಪೂರ್ಣಾಙ್ಕ type, uint32_t seq, ಸಂರಚನಾ ssh *ssh)
{
	ಧ್ರುವ u_char *data;
	size_t data_len, win_len;
	Channel *c = channel_from_packet_id(ssh, __func__, "data");
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (channel_proxy_upstream(c, type, seq, ssh))
		ಪ್ರತ್ಯಾಗಮ 0;

	/* Ignore any data for non-open channels (might happen on close) */
	ಯದಿ (c->type != SSH_CHANNEL_OPEN &&
	    c->type != SSH_CHANNEL_RDYNAMIC_OPEN &&
	    c->type != SSH_CHANNEL_RDYNAMIC_FINISH &&
	    c->type != SSH_CHANNEL_X11_OPEN)
		ಪ್ರತ್ಯಾಗಮ 0;

	/* Get the data. */
	ಯದಿ ((r = sshpkt_get_string_direct(ssh, &data, &data_len)) != 0 ||
            (r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "channel %i: get data", c->self);

	win_len = data_len;
	ಯದಿ (c->datagram)
		win_len += 4;  /* string length header */

	/*
	 * The sending side reduces its window as it sends data, so we
	 * must 'fake' consumption of the data in order to ensure that window
	 * updates are sent back. Otherwise the connection might deadlock.
	 */
	ಯದಿ (c->ostate != CHAN_OUTPUT_OPEN) {
		ಯದಿ (win_len > c->local_window)
			c->local_window = 0;
		ಅನ್ಯಥಾ
			c->local_window -= win_len;
		c->local_consumed += win_len;
		ಪ್ರತ್ಯಾಗಮ 0;
	}

	ಯದಿ (win_len > c->local_maxpacket) {
		logit("channel %d: rcvd big packet %zu, maxpack %u",
		    c->self, win_len, c->local_maxpacket);
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	ಯದಿ (win_len > c->local_window) {
		u_int delta = win_len - c->local_window;

		ಯದಿ (c->local_window_exceeded > UINT_MAX - delta)
			c->local_window_exceeded = UINT_MAX;
		ಅನ್ಯಥಾ
			c->local_window_exceeded += delta;
		logit("channel %d: rcvd too much data %zu, win %u/%u "
		    "(excess %u)", c->self, win_len, c->local_window,
		    c->local_window_max, c->local_window_exceeded);
		c->local_window = 0;
		/* Allow 10% grace before bringing the hammer down */
		ಯದಿ (c->local_window_exceeded > (c->local_window_max / 10)) {
			ssh_packet_disconnect(ssh, "channel %d: peer ignored "
			    "channel window", c->self);
		}
	} ಅನ್ಯಥಾ {
		c->local_window -= win_len;
		c->local_window_exceeded = 0;
	}

	ಯದಿ (c->datagram) {
		ಯದಿ ((r = sshbuf_put_string(c->output, data, data_len)) != 0)
			fatal_fr(r, "channel %i: append datagram", c->self);
	} ಅನ್ಯಥಾ ಯದಿ ((r = sshbuf_put(c->output, data, data_len)) != 0)
		fatal_fr(r, "channel %i: append data", c->self);

	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
channel_ಒಳಹರಿವು_extended_data(ಪೂರ್ಣಾಙ್ಕ type, uint32_t seq, ಸಂರಚನಾ ssh *ssh)
{
	ಧ್ರುವ u_char *data;
	size_t data_len;
	uint32_t tcode;
	Channel *c = channel_from_packet_id(ssh, __func__, "extended data");
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (channel_proxy_upstream(c, type, seq, ssh))
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ (c->type != SSH_CHANNEL_OPEN) {
		logit("channel %d: ext data for non open", c->self);
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	ಯದಿ (c->flags & CHAN_EOF_RCVD) {
		ಯದಿ (ssh->compat & SSH_BUG_EXTEOF)
			debug("channel %d: accepting ext data after eof",
			    c->self);
		ಅನ್ಯಥಾ
			ssh_packet_disconnect(ssh, "Received extended_data "
			    "after EOF on channel %d.", c->self);
	}

	ಯದಿ ((r = sshpkt_get_u32(ssh, &tcode)) != 0) {
		error_fr(r, "parse tcode");
		ssh_packet_disconnect(ssh, "Invalid extended_data message");
	}
	ಯದಿ (c->efd == -1 ||
	    c->extended_usage != CHAN_EXTENDED_WRITE ||
	    tcode != SSH2_EXTENDED_DATA_STDERR) {
		logit("channel %d: bad ext data", c->self);
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	ಯದಿ ((r = sshpkt_get_string_direct(ssh, &data, &data_len)) != 0 ||
            (r = sshpkt_get_end(ssh)) != 0) {
		error_fr(r, "parse data");
		ssh_packet_disconnect(ssh, "Invalid extended_data message");
	}

	ಯದಿ (data_len > c->local_window) {
		logit("channel %d: rcvd too much extended_data %zu, win %u",
		    c->self, data_len, c->local_window);
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	debug2("channel %d: rcvd ext data %zu", c->self, data_len);
	/* XXX sshpkt_getb? */
	ಯದಿ ((r = sshbuf_put(c->extended, data, data_len)) != 0)
		error_fr(r, "append");
	c->local_window -= data_len;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
channel_ಒಳಹರಿವು_ieof(ಪೂರ್ಣಾಙ್ಕ type, uint32_t seq, ಸಂರಚನಾ ssh *ssh)
{
	Channel *c = channel_from_packet_id(ssh, __func__, "ieof");
	ಪೂರ್ಣಾಙ್ಕ r;

        ಯದಿ ((r = sshpkt_get_end(ssh)) != 0) {
		error_fr(r, "parse data");
		ssh_packet_disconnect(ssh, "Invalid ieof message");
	}

	ಯದಿ (channel_proxy_upstream(c, type, seq, ssh))
		ಪ್ರತ್ಯಾಗಮ 0;
	chan_rcvd_ieof(ssh, c);

	/* XXX force input close */
	ಯದಿ (c->force_drain && c->istate == CHAN_ಒಳಹರಿವು_OPEN) {
		debug("channel %d: FORCE input drain", c->self);
		c->istate = CHAN_ಒಳಹರಿವು_WAIT_DRAIN;
		ಯದಿ (sshbuf_len(c->ಒಳಹರಿವು) == 0)
			chan_ibuf_empty(ssh, c);
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
channel_ಒಳಹರಿವು_oclose(ಪೂರ್ಣಾಙ್ಕ type, uint32_t seq, ಸಂರಚನಾ ssh *ssh)
{
	Channel *c = channel_from_packet_id(ssh, __func__, "oclose");
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (channel_proxy_upstream(c, type, seq, ssh))
		ಪ್ರತ್ಯಾಗಮ 0;
        ಯದಿ ((r = sshpkt_get_end(ssh)) != 0) {
		error_fr(r, "parse data");
		ssh_packet_disconnect(ssh, "Invalid oclose message");
	}
	chan_rcvd_oclose(ssh, c);
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
channel_ಒಳಹರಿವು_open_confirmation(ಪೂರ್ಣಾಙ್ಕ type, uint32_t seq, ಸಂರಚನಾ ssh *ssh)
{
	Channel *c = channel_from_packet_id(ssh, __func__, "open confirmation");
	uint32_t remote_window, remote_maxpacket;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (channel_proxy_upstream(c, type, seq, ssh))
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ (c->type != SSH_CHANNEL_OPENING)
		ssh_packet_disconnect(ssh, "Received open confirmation for "
		    "non-opening channel %d.", c->self);
	/*
	 * Record the remote channel number and mark that the channel
	 * is now open.
	 */
	ಯದಿ ((r = sshpkt_get_u32(ssh, &c->remote_id)) != 0 ||
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
	ಯದಿ (c->open_confirm) {
		debug2_f("channel %d: callback start", c->self);
		c->open_confirm(ssh, c->self, 1, c->open_confirm_ctx);
		debug2_f("channel %d: callback done", c->self);
	}
	channel_set_used_time(ssh, c);
	debug2("channel %d: open confirm rwindow %u rmax %u", c->self,
	    c->remote_window, c->remote_maxpacket);
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ವರ್ಣ *
reason2txt(ಪೂರ್ಣಾಙ್ಕ reason)
{
	ವಿಕಲ್ಪ (reason) {
	ಪಕ್ಷ SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED:
		ಪ್ರತ್ಯಾಗಮ "administratively prohibited";
	ಪಕ್ಷ SSH2_OPEN_CONNECT_FAILED:
		ಪ್ರತ್ಯಾಗಮ "connect failed";
	ಪಕ್ಷ SSH2_OPEN_UNKNOWN_CHANNEL_TYPE:
		ಪ್ರತ್ಯಾಗಮ "unknown channel type";
	ಪಕ್ಷ SSH2_OPEN_RESOURCE_SHORTAGE:
		ಪ್ರತ್ಯಾಗಮ "resource shortage";
	}
	ಪ್ರತ್ಯಾಗಮ "unknown reason";
}

ಪೂರ್ಣಾಙ್ಕ
channel_ಒಳಹರಿವು_open_failure(ಪೂರ್ಣಾಙ್ಕ type, uint32_t seq, ಸಂರಚನಾ ssh *ssh)
{
	Channel *c = channel_from_packet_id(ssh, __func__, "open failure");
	uint32_t reason;
	ವರ್ಣ *ಸಂದೇಶ = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (channel_proxy_upstream(c, type, seq, ssh))
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ (c->type != SSH_CHANNEL_OPENING)
		ssh_packet_disconnect(ssh, "Received open failure for "
		    "non-opening channel %d.", c->self);
	ಯದಿ ((r = sshpkt_get_u32(ssh, &reason)) != 0) {
		error_fr(r, "parse reason");
		ssh_packet_disconnect(ssh, "Invalid open failure message");
	}
	/* skip language */
	ಯದಿ ((r = sshpkt_get_cstring(ssh, &ಸಂದೇಶ, ರಿಕ್ತ)) != 0 ||
	    (r = sshpkt_get_string_direct(ssh, ರಿಕ್ತ, ರಿಕ್ತ)) != 0 ||
            (r = sshpkt_get_end(ssh)) != 0) {
		error_fr(r, "parse msg/lang");
		ssh_packet_disconnect(ssh, "Invalid open failure message");
	}
	logit("channel %d: open failed: %s%s%s", c->self,
	    reason2txt(reason), ಸಂದೇಶ ? ": ": "", ಸಂದೇಶ ? ಸಂದೇಶ : "");
	ಮುಕ್ತ(ಸಂದೇಶ);
	ಯದಿ (c->open_confirm) {
		debug2_f("channel %d: callback start", c->self);
		c->open_confirm(ssh, c->self, 0, c->open_confirm_ctx);
		debug2_f("channel %d: callback done", c->self);
	}
	/* Schedule the channel for cleanup/deletion. */
	chan_mark_dead(ssh, c);
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
channel_ಒಳಹರಿವು_window_adjust(ಪೂರ್ಣಾಙ್ಕ type, uint32_t seq, ಸಂರಚನಾ ssh *ssh)
{
	ಪೂರ್ಣಾಙ್ಕ id = channel_parse_id(ssh, __func__, "window adjust");
	Channel *c;
	uint32_t adjust;
	u_int new_rwin;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((c = channel_lookup(ssh, id)) == ರಿಕ್ತ) {
		logit("Received window adjust for non-open channel %d.", id);
		ಪ್ರತ್ಯಾಗಮ 0;
	}

	ಯದಿ (channel_proxy_upstream(c, type, seq, ssh))
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ ((r = sshpkt_get_u32(ssh, &adjust)) != 0 ||
            (r = sshpkt_get_end(ssh)) != 0) {
		error_fr(r, "parse adjust");
		ssh_packet_disconnect(ssh, "Invalid window adjust message");
	}
	debug2("channel %d: rcvd adjust %u", c->self, adjust);
	ಯದಿ ((new_rwin = c->remote_window + adjust) < c->remote_window) {
		fatal("channel %d: adjust %u overflows remote window %u",
		    c->self, adjust, c->remote_window);
	}
	c->remote_window = new_rwin;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
channel_ಒಳಹರಿವು_status_confirm(ಪೂರ್ಣಾಙ್ಕ type, uint32_t seq, ಸಂರಚನಾ ssh *ssh)
{
	ಪೂರ್ಣಾಙ್ಕ id = channel_parse_id(ssh, __func__, "status confirm");
	Channel *c;
	ಸಂರಚನಾ channel_confirm *cc;

	/* Reset keepalive timeout */
	ssh_packet_set_alive_timeouts(ssh, 0);

	debug2_f("type %d id %d", type, id);

	ಯದಿ ((c = channel_lookup(ssh, id)) == ರಿಕ್ತ) {
		logit_f("%d: unknown", id);
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	ಯದಿ (channel_proxy_upstream(c, type, seq, ssh))
		ಪ್ರತ್ಯಾಗಮ 0;
        ಯದಿ (sshpkt_get_end(ssh) != 0)
		ssh_packet_disconnect(ssh, "Invalid status confirm message");
	ಯದಿ ((cc = TAILQ_FIRST(&c->status_confirms)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ 0;
	cc->cb(ssh, type, c, cc->ctx);
	TAILQ_REMOVE(&c->status_confirms, cc, entry);
	freezero(cc, ಪರಿಮಾಣ(*cc));
	ಪ್ರತ್ಯಾಗಮ 0;
}

/* -- tcp forwarding */

ಶೂನ್ಯ
channel_set_af(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ af)
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
ಸ್ಥಿರ ಧ್ರುವ ವರ್ಣ *
channel_fwd_bind_addr(ಸಂರಚನಾ ssh *ssh, ಧ್ರುವ ವರ್ಣ *listen_addr, ಪೂರ್ಣಾಙ್ಕ *wildcardp,
    ಪೂರ್ಣಾಙ್ಕ is_client, ಸಂರಚನಾ ForwardOptions *fwd_opts)
{
	ಧ್ರುವ ವರ್ಣ *addr = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ wildcard = 0;

	ಯದಿ (listen_addr == ರಿಕ್ತ) {
		/* No address specified: default to gateway_ports setting */
		ಯದಿ (fwd_opts->gateway_ports)
			wildcard = 1;
	} ಅನ್ಯಥಾ ಯದಿ (fwd_opts->gateway_ports || is_client) {
		ಯದಿ (((ssh->compat & SSH_OLD_FORWARD_ADDR) &&
		    strcmp(listen_addr, "0.0.0.0") == 0 && is_client == 0) ||
		    *listen_addr == '\0' || strcmp(listen_addr, "*") == 0 ||
		    (!is_client && fwd_opts->gateway_ports == 1)) {
			wildcard = 1;
			/*
			 * Notify client if they requested a specific listen
			 * address and it was overridden.
			 */
			ಯದಿ (*listen_addr != '\0' &&
			    strcmp(listen_addr, "0.0.0.0") != 0 &&
			    strcmp(listen_addr, "*") != 0) {
				ssh_packet_send_debug(ssh,
				    "Forwarding listen address "
				    "\"%s\" overridden by server "
				    "GatewayPorts", listen_addr);
			}
		} ಅನ್ಯಥಾ ಯದಿ (strcmp(listen_addr, "localhost") != 0 ||
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
	} ಅನ್ಯಥಾ ಯದಿ (strcmp(listen_addr, "127.0.0.1") == 0 ||
	    strcmp(listen_addr, "::1") == 0) {
		/*
		 * If a specific IPv4/IPv6 localhost address has been
		 * requested then accept it even if gateway_ports is in
		 * effect. This allows the client to prefer IPv4 or IPv6.
		 */
		addr = listen_addr;
	}
	ಯದಿ (wildcardp != ರಿಕ್ತ)
		*wildcardp = wildcard;
	ಪ್ರತ್ಯಾಗಮ addr;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
channel_setup_fwd_listener_tcpip(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ type,
    ಸಂರಚನಾ Forward *fwd, ಪೂರ್ಣಾಙ್ಕ *allocated_listen_port,
    ಸಂರಚನಾ ForwardOptions *fwd_opts)
{
	Channel *c;
	ಪೂರ್ಣಾಙ್ಕ sock, r, success = 0, wildcard = 0, is_client;
	ಸಂರಚನಾ addrinfo hints, *ai, *aitop;
	ಧ್ರುವ ವರ್ಣ *host, *addr;
	ವರ್ಣ ntop[NI_MAXHOST], strport[NI_MAXSERV];
	in_port_t *lport_p;

	is_client = (type == SSH_CHANNEL_PORT_LISTENER);

	ಯದಿ (is_client && fwd->connect_path != ರಿಕ್ತ) {
		host = fwd->connect_path;
	} ಅನ್ಯಥಾ {
		host = (type == SSH_CHANNEL_RPORT_LISTENER) ?
		    fwd->listen_host : fwd->connect_host;
		ಯದಿ (host == ರಿಕ್ತ) {
			error("No forward host name.");
			ಪ್ರತ್ಯಾಗಮ 0;
		}
		ಯದಿ (strlen(host) >= NI_MAXHOST) {
			error("Forward host name too long.");
			ಪ್ರತ್ಯಾಗಮ 0;
		}
	}

	/* Determine the bind address, cf. channel_fwd_bind_addr() comment */
	addr = channel_fwd_bind_addr(ssh, fwd->listen_host, &wildcard,
	    is_client, fwd_opts);
	debug3_f("type %d wildcard %d addr %s", type, wildcard,
	    (addr == ರಿಕ್ತ) ? "NULL" : addr);

	/*
	 * getaddrinfo returns a loopback address if the hostname is
	 * set to NULL and hints.ai_flags is not AI_PASSIVE
	 */
	memset(&hints, 0, ಪರಿಮಾಣ(hints));
	hints.ai_family = ssh->chanctxt->IPv4or6;
	hints.ai_flags = wildcard ? AI_PASSIVE : 0;
	hints.ai_socktype = SOCK_STREAM;
	snprintf(strport, ಪರಿಮಾಣ strport, "%d", fwd->listen_port);
	ಯದಿ ((r = getaddrinfo(addr, strport, &hints, &aitop)) != 0) {
		ಯದಿ (addr == ರಿಕ್ತ) {
			/* This really shouldn't happen */
			ssh_packet_disconnect(ssh, "getaddrinfo: fatal error: %s",
			    ssh_gai_strerror(r));
		} ಅನ್ಯಥಾ {
			error_f("getaddrinfo(%.64s): %s", addr,
			    ssh_gai_strerror(r));
		}
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	ಯದಿ (allocated_listen_port != ರಿಕ್ತ)
		*allocated_listen_port = 0;
	ಪ್ರತಿ (ai = aitop; ai; ai = ai->ai_next) {
		ವಿಕಲ್ಪ (ai->ai_family) {
		ಪಕ್ಷ AF_INET:
			lport_p = &((ಸಂರಚನಾ sockaddr_in *)ai->ai_addr)->
			    sin_port;
			ಭಙ್ಗ;
		ಪಕ್ಷ AF_INET6:
			lport_p = &((ಸಂರಚನಾ sockaddr_in6 *)ai->ai_addr)->
			    sin6_port;
			ಭಙ್ಗ;
		ಸ್ವಭಾವ:
			ಅನುವರ್ತ;
		}
		/*
		 * If allocating a port for -R forwards, then use the
		 * same port for all address families.
		 */
		ಯದಿ (type == SSH_CHANNEL_RPORT_LISTENER &&
		    fwd->listen_port == 0 && allocated_listen_port != ರಿಕ್ತ &&
		    *allocated_listen_port > 0)
			*lport_p = htons(*allocated_listen_port);

		ಯದಿ (getnameinfo(ai->ai_addr, ai->ai_addrlen, ntop, ಪರಿಮಾಣ(ntop),
		    strport, ಪರಿಮಾಣ(strport),
		    NI_NUMERICHOST|NI_NUMERICSERV) != 0) {
			error_f("getnameinfo failed");
			ಅನುವರ್ತ;
		}
		/* Create a port to listen for the host. */
		sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		ಯದಿ (sock == -1) {
			/* this is no error since kernel may not support ipv6 */
			verbose("socket [%s]:%s: %.100s", ntop, strport,
			    strerror(errno));
			ಅನುವರ್ತ;
		}

		set_reuseaddr(sock);
		ಯದಿ (ai->ai_family == AF_INET6)
			sock_set_v6only(sock);

		debug("Local forwarding listening on %s port %s.",
		    ntop, strport);

		/* Bind the socket to the address. */
		ಯದಿ (bind(sock, ai->ai_addr, ai->ai_addrlen) == -1) {
			/*
			 * address can be in if use ipv6 address is
			 * already bound
			 */
			ಯದಿ (!ai->ai_next)
				error("bind [%s]:%s: %.100s",
				    ntop, strport, strerror(errno));
			ಅನ್ಯಥಾ
				verbose("bind [%s]:%s: %.100s",
				    ntop, strport, strerror(errno));

			close(sock);
			ಅನುವರ್ತ;
		}
		/* Start listening for connections on the socket. */
		ಯದಿ (listen(sock, SSH_LISTEN_BACKLOG) == -1) {
			error("listen [%s]:%s: %.100s", ntop, strport,
			    strerror(errno));
			close(sock);
			ಅನುವರ್ತ;
		}

		/*
		 * fwd->listen_port == 0 requests a dynamically allocated port -
		 * record what we got.
		 */
		ಯದಿ (type == SSH_CHANNEL_RPORT_LISTENER &&
		    fwd->listen_port == 0 &&
		    allocated_listen_port != ರಿಕ್ತ &&
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
		c->listening_addr = addr == ರಿಕ್ತ ? ರಿಕ್ತ : xstrdup(addr);
		ಯದಿ (fwd->listen_port == 0 && allocated_listen_port != ರಿಕ್ತ &&
		    !(ssh->compat & SSH_BUG_DYNAMIC_RPORT))
			c->listening_port = *allocated_listen_port;
		ಅನ್ಯಥಾ
			c->listening_port = fwd->listen_port;
		success = 1;
	}
	ಯದಿ (success == 0)
		error_f("cannot listen to port: %d", fwd->listen_port);
	freeaddrinfo(aitop);
	ಪ್ರತ್ಯಾಗಮ success;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
channel_setup_fwd_listener_streamlocal(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ type,
    ಸಂರಚನಾ Forward *fwd, ಸಂರಚನಾ ForwardOptions *fwd_opts)
{
	ಸಂರಚನಾ sockaddr_un sunaddr;
	ಧ್ರುವ ವರ್ಣ *path;
	Channel *c;
	ಪೂರ್ಣಾಙ್ಕ port, sock;
	mode_t omask;

	ವಿಕಲ್ಪ (type) {
	ಪಕ್ಷ SSH_CHANNEL_UNIX_LISTENER:
		ಯದಿ (fwd->connect_path != ರಿಕ್ತ) {
			ಯದಿ (strlen(fwd->connect_path) > ಪರಿಮಾಣ(sunaddr.sun_path)) {
				error("Local connecting path too long: %s",
				    fwd->connect_path);
				ಪ್ರತ್ಯಾಗಮ 0;
			}
			path = fwd->connect_path;
			port = PORT_STREAMLOCAL;
		} ಅನ್ಯಥಾ {
			ಯದಿ (fwd->connect_host == ರಿಕ್ತ) {
				error("No forward host name.");
				ಪ್ರತ್ಯಾಗಮ 0;
			}
			ಯದಿ (strlen(fwd->connect_host) >= NI_MAXHOST) {
				error("Forward host name too long.");
				ಪ್ರತ್ಯಾಗಮ 0;
			}
			path = fwd->connect_host;
			port = fwd->connect_port;
		}
		ಭಙ್ಗ;
	ಪಕ್ಷ SSH_CHANNEL_RUNIX_LISTENER:
		path = fwd->listen_path;
		port = PORT_STREAMLOCAL;
		ಭಙ್ಗ;
	ಸ್ವಭಾವ:
		error_f("unexpected channel type %d", type);
		ಪ್ರತ್ಯಾಗಮ 0;
	}

	ಯದಿ (fwd->listen_path == ರಿಕ್ತ) {
		error("No forward path name.");
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	ಯದಿ (strlen(fwd->listen_path) > ಪರಿಮಾಣ(sunaddr.sun_path)) {
		error("Local listening path too long: %s", fwd->listen_path);
		ಪ್ರತ್ಯಾಗಮ 0;
	}

	debug3_f("type %d path %s", type, fwd->listen_path);

	/* Start a Unix domain listener. */
	omask = umask(fwd_opts->streamlocal_bind_mask);
	sock = unix_listener(fwd->listen_path, SSH_LISTEN_BACKLOG,
	    fwd_opts->streamlocal_bind_unlink);
	umask(omask);
	ಯದಿ (sock < 0)
		ಪ್ರತ್ಯಾಗಮ 0;

	debug("Local forwarding listening on path %s.", fwd->listen_path);

	/* Allocate a channel number for the socket. */
	c = channel_new(ssh, "unix-listener", type, sock, sock, -1,
	    CHAN_TCP_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT,
	    0, "unix listener", 1);
	c->path = xstrdup(path);
	c->host_port = port;
	c->listening_port = PORT_STREAMLOCAL;
	c->listening_addr = xstrdup(fwd->listen_path);
	ಪ್ರತ್ಯಾಗಮ 1;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
channel_cancel_rport_listener_tcpip(ಸಂರಚನಾ ssh *ssh,
    ಧ್ರುವ ವರ್ಣ *host, u_short port)
{
	u_int i;
	ಪೂರ್ಣಾಙ್ಕ found = 0;

	ಪ್ರತಿ (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		Channel *c = ssh->chanctxt->channels[i];
		ಯದಿ (c == ರಿಕ್ತ || c->type != SSH_CHANNEL_RPORT_LISTENER)
			ಅನುವರ್ತ;
		ಯದಿ (strcmp(c->path, host) == 0 && c->listening_port == port) {
			debug2_f("close channel %d", i);
			channel_free(ssh, c);
			found = 1;
		}
	}

	ಪ್ರತ್ಯಾಗಮ found;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
channel_cancel_rport_listener_streamlocal(ಸಂರಚನಾ ssh *ssh, ಧ್ರುವ ವರ್ಣ *path)
{
	u_int i;
	ಪೂರ್ಣಾಙ್ಕ found = 0;

	ಪ್ರತಿ (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		Channel *c = ssh->chanctxt->channels[i];
		ಯದಿ (c == ರಿಕ್ತ || c->type != SSH_CHANNEL_RUNIX_LISTENER)
			ಅನುವರ್ತ;
		ಯದಿ (c->path == ರಿಕ್ತ)
			ಅನುವರ್ತ;
		ಯದಿ (strcmp(c->path, path) == 0) {
			debug2_f("close channel %d", i);
			channel_free(ssh, c);
			found = 1;
		}
	}

	ಪ್ರತ್ಯಾಗಮ found;
}

ಪೂರ್ಣಾಙ್ಕ
channel_cancel_rport_listener(ಸಂರಚನಾ ssh *ssh, ಸಂರಚನಾ Forward *fwd)
{
	ಯದಿ (fwd->listen_path != ರಿಕ್ತ) {
		ಪ್ರತ್ಯಾಗಮ channel_cancel_rport_listener_streamlocal(ssh,
		    fwd->listen_path);
	} ಅನ್ಯಥಾ {
		ಪ್ರತ್ಯಾಗಮ channel_cancel_rport_listener_tcpip(ssh,
		    fwd->listen_host, fwd->listen_port);
	}
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
channel_cancel_lport_listener_tcpip(ಸಂರಚನಾ ssh *ssh,
    ಧ್ರುವ ವರ್ಣ *lhost, u_short lport, ಪೂರ್ಣಾಙ್ಕ cport,
    ಸಂರಚನಾ ForwardOptions *fwd_opts)
{
	u_int i;
	ಪೂರ್ಣಾಙ್ಕ found = 0;
	ಧ್ರುವ ವರ್ಣ *addr = channel_fwd_bind_addr(ssh, lhost, ರಿಕ್ತ, 1, fwd_opts);

	ಪ್ರತಿ (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		Channel *c = ssh->chanctxt->channels[i];
		ಯದಿ (c == ರಿಕ್ತ || c->type != SSH_CHANNEL_PORT_LISTENER)
			ಅನುವರ್ತ;
		ಯದಿ (c->listening_port != lport)
			ಅನುವರ್ತ;
		ಯದಿ (cport == CHANNEL_CANCEL_PORT_STATIC) {
			/* skip dynamic forwardings */
			ಯದಿ (c->host_port == 0)
				ಅನುವರ್ತ;
		} ಅನ್ಯಥಾ {
			ಯದಿ (c->host_port != cport)
				ಅನುವರ್ತ;
		}
		ಯದಿ ((c->listening_addr == ರಿಕ್ತ && addr != ರಿಕ್ತ) ||
		    (c->listening_addr != ರಿಕ್ತ && addr == ರಿಕ್ತ))
			ಅನುವರ್ತ;
		ಯದಿ (addr == ರಿಕ್ತ || strcmp(c->listening_addr, addr) == 0) {
			debug2_f("close channel %d", i);
			channel_free(ssh, c);
			found = 1;
		}
	}

	ಪ್ರತ್ಯಾಗಮ found;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
channel_cancel_lport_listener_streamlocal(ಸಂರಚನಾ ssh *ssh, ಧ್ರುವ ವರ್ಣ *path)
{
	u_int i;
	ಪೂರ್ಣಾಙ್ಕ found = 0;

	ಯದಿ (path == ರಿಕ್ತ) {
		error_f("no path specified.");
		ಪ್ರತ್ಯಾಗಮ 0;
	}

	ಪ್ರತಿ (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		Channel *c = ssh->chanctxt->channels[i];
		ಯದಿ (c == ರಿಕ್ತ || c->type != SSH_CHANNEL_UNIX_LISTENER)
			ಅನುವರ್ತ;
		ಯದಿ (c->listening_addr == ರಿಕ್ತ)
			ಅನುವರ್ತ;
		ಯದಿ (strcmp(c->listening_addr, path) == 0) {
			debug2_f("close channel %d", i);
			channel_free(ssh, c);
			found = 1;
		}
	}

	ಪ್ರತ್ಯಾಗಮ found;
}

ಪೂರ್ಣಾಙ್ಕ
channel_cancel_lport_listener(ಸಂರಚನಾ ssh *ssh,
    ಸಂರಚನಾ Forward *fwd, ಪೂರ್ಣಾಙ್ಕ cport, ಸಂರಚನಾ ForwardOptions *fwd_opts)
{
	ಯದಿ (fwd->listen_path != ರಿಕ್ತ) {
		ಪ್ರತ್ಯಾಗಮ channel_cancel_lport_listener_streamlocal(ssh,
		    fwd->listen_path);
	} ಅನ್ಯಥಾ {
		ಪ್ರತ್ಯಾಗಮ channel_cancel_lport_listener_tcpip(ssh,
		    fwd->listen_host, fwd->listen_port, cport, fwd_opts);
	}
}

/* protocol local port fwd, used by ssh */
ಪೂರ್ಣಾಙ್ಕ
channel_setup_local_fwd_listener(ಸಂರಚನಾ ssh *ssh,
    ಸಂರಚನಾ Forward *fwd, ಸಂರಚನಾ ForwardOptions *fwd_opts)
{
	ಯದಿ (fwd->listen_path != ರಿಕ್ತ) {
		ಪ್ರತ್ಯಾಗಮ channel_setup_fwd_listener_streamlocal(ssh,
		    SSH_CHANNEL_UNIX_LISTENER, fwd, fwd_opts);
	} ಅನ್ಯಥಾ {
		ಪ್ರತ್ಯಾಗಮ channel_setup_fwd_listener_tcpip(ssh,
		    SSH_CHANNEL_PORT_LISTENER, fwd, ರಿಕ್ತ, fwd_opts);
	}
}

/* Matches a remote forwarding permission against a requested forwarding */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
remote_open_match(ಸಂರಚನಾ permission *allowed_open, ಸಂರಚನಾ Forward *fwd)
{
	ಪೂರ್ಣಾಙ್ಕ ret;
	ವರ್ಣ *lhost;

	/* XXX add ACLs for streamlocal */
	ಯದಿ (fwd->listen_path != ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ 1;

	ಯದಿ (fwd->listen_host == ರಿಕ್ತ || allowed_open->listen_host == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ 0;

	ಯದಿ (allowed_open->listen_port != FWD_PERMIT_ANY_PORT &&
	    allowed_open->listen_port != fwd->listen_port)
		ಪ್ರತ್ಯಾಗಮ 0;

	/* Match hostnames case-insensitively */
	lhost = xstrdup(fwd->listen_host);
	lowercase(lhost);
	ret = match_pattern(lhost, allowed_open->listen_host);
	ಮುಕ್ತ(lhost);

	ಪ್ರತ್ಯಾಗಮ ret;
}

/* Checks whether a requested remote forwarding is permitted */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
check_rfwd_permission(ಸಂರಚನಾ ssh *ssh, ಸಂರಚನಾ Forward *fwd)
{
	ಸಂರಚನಾ ssh_channels *sc = ssh->chanctxt;
	ಸಂರಚನಾ permission_set *pset = &sc->remote_perms;
	u_int i, permit, permit_adm = 1;
	ಸಂರಚನಾ permission *perm;

#ifdef SKIP_PRIVDROP
	ಯದಿ (fwd->listen_path != ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ (fwd->listen_port != 0 && fwd->listen_port < 1024)
		ಪ್ರತ್ಯಾಗಮ 0;
#endif

	/* XXX apply GatewayPorts override before checking? */

	permit = pset->all_permitted;
	ಯದಿ (!permit) {
		ಪ್ರತಿ (i = 0; i < pset->ಅಂಕೆ_permitted_user; i++) {
			perm = &pset->permitted_user[i];
			ಯದಿ (remote_open_match(perm, fwd)) {
				permit = 1;
				ಭಙ್ಗ;
			}
		}
	}

	ಯದಿ (pset->ಅಂಕೆ_permitted_admin > 0) {
		permit_adm = 0;
		ಪ್ರತಿ (i = 0; i < pset->ಅಂಕೆ_permitted_admin; i++) {
			perm = &pset->permitted_admin[i];
			ಯದಿ (remote_open_match(perm, fwd)) {
				permit_adm = 1;
				ಭಙ್ಗ;
			}
		}
	}

	ಪ್ರತ್ಯಾಗಮ permit && permit_adm;
}

/* protocol v2 remote port fwd, used by sshd */
ಪೂರ್ಣಾಙ್ಕ
channel_setup_remote_fwd_listener(ಸಂರಚನಾ ssh *ssh, ಸಂರಚನಾ Forward *fwd,
    ಪೂರ್ಣಾಙ್ಕ *allocated_listen_port, ಸಂರಚನಾ ForwardOptions *fwd_opts)
{
	ಯದಿ (!check_rfwd_permission(ssh, fwd)) {
		ssh_packet_send_debug(ssh, "port forwarding refused");
		ಯದಿ (fwd->listen_path != ರಿಕ್ತ)
			/* XXX always allowed, see remote_open_match() */
			logit("Received request from %.100s port %d to "
			    "remote forward to path \"%.100s\", "
			    "but the request was denied.",
			    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
			    fwd->listen_path);
		ಅನ್ಯಥಾ ಯದಿ(fwd->listen_host != ರಿಕ್ತ)
			logit("Received request from %.100s port %d to "
			    "remote forward to host %.100s port %d, "
			    "but the request was denied.",
			    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
			    fwd->listen_host, fwd->listen_port );
		ಅನ್ಯಥಾ
			logit("Received request from %.100s port %d to remote "
			    "forward, but the request was denied.",
			    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	ಯದಿ (fwd->listen_path != ರಿಕ್ತ) {
		ಪ್ರತ್ಯಾಗಮ channel_setup_fwd_listener_streamlocal(ssh,
		    SSH_CHANNEL_RUNIX_LISTENER, fwd, fwd_opts);
	} ಅನ್ಯಥಾ {
		ಪ್ರತ್ಯಾಗಮ channel_setup_fwd_listener_tcpip(ssh,
		    SSH_CHANNEL_RPORT_LISTENER, fwd, allocated_listen_port,
		    fwd_opts);
	}
}

/*
 * Translate the requested rfwd listen host to something usable for
 * this server.
 */
ಸ್ಥಿರ ಧ್ರುವ ವರ್ಣ *
channel_rfwd_bind_host(ಧ್ರುವ ವರ್ಣ *listen_host)
{
	ಯದಿ (listen_host == ರಿಕ್ತ) {
		ಪ್ರತ್ಯಾಗಮ "localhost";
	} ಅನ್ಯಥಾ ಯದಿ (*listen_host == '\0' || strcmp(listen_host, "*") == 0) {
		ಪ್ರತ್ಯಾಗಮ "";
	} ಅನ್ಯಥಾ
		ಪ್ರತ್ಯಾಗಮ listen_host;
}

/*
 * Initiate forwarding of connections to port "port" on remote host through
 * the secure channel to host:port from local side.
 * Returns handle (index) for updating the dynamic listen port with
 * channel_update_permission().
 */
ಪೂರ್ಣಾಙ್ಕ
channel_request_remote_forwarding(ಸಂರಚನಾ ssh *ssh, ಸಂರಚನಾ Forward *fwd)
{
	ಪೂರ್ಣಾಙ್ಕ r, success = 0, idx = -1;
	ಧ್ರುವ ವರ್ಣ *host_to_connect, *listen_host, *listen_path;
	ಪೂರ್ಣಾಙ್ಕ port_to_connect, listen_port;

	/* Send the forward request to the remote side. */
	ಯದಿ (fwd->listen_path != ರಿಕ್ತ) {
		ಯದಿ ((r = sshpkt_start(ssh, SSH2_ಸಂದೇಶ_GLOBAL_REQUEST)) != 0 ||
		    (r = sshpkt_put_cstring(ssh,
		    "streamlocal-forward@openssh.com")) != 0 ||
		    (r = sshpkt_put_u8(ssh, 1)) != 0 || /* want reply */
		    (r = sshpkt_put_cstring(ssh, fwd->listen_path)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			fatal_fr(r, "request streamlocal");
	} ಅನ್ಯಥಾ {
		ಯದಿ ((r = sshpkt_start(ssh, SSH2_ಸಂದೇಶ_GLOBAL_REQUEST)) != 0 ||
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
	ಯದಿ (success) {
		/* Record that connection to this host/port is permitted. */
		host_to_connect = listen_host = listen_path = ರಿಕ್ತ;
		port_to_connect = listen_port = 0;
		ಯದಿ (fwd->connect_path != ರಿಕ್ತ) {
			host_to_connect = fwd->connect_path;
			port_to_connect = PORT_STREAMLOCAL;
		} ಅನ್ಯಥಾ {
			host_to_connect = fwd->connect_host;
			port_to_connect = fwd->connect_port;
		}
		ಯದಿ (fwd->listen_path != ರಿಕ್ತ) {
			listen_path = fwd->listen_path;
			listen_port = PORT_STREAMLOCAL;
		} ಅನ್ಯಥಾ {
			listen_host = fwd->listen_host;
			listen_port = fwd->listen_port;
		}
		idx = permission_set_add(ssh, FORWARD_USER, FORWARD_LOCAL,
		    host_to_connect, port_to_connect,
		    listen_host, listen_path, listen_port, ರಿಕ್ತ);
	}
	ಪ್ರತ್ಯಾಗಮ idx;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
open_match(ಸಂರಚನಾ permission *allowed_open, ಧ್ರುವ ವರ್ಣ *requestedhost,
    ಪೂರ್ಣಾಙ್ಕ requestedport)
{
	ಯದಿ (allowed_open->host_to_connect == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ (allowed_open->port_to_connect != FWD_PERMIT_ANY_PORT &&
	    allowed_open->port_to_connect != requestedport)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ (strcmp(allowed_open->host_to_connect, FWD_PERMIT_ANY_HOST) != 0 &&
	    strcmp(allowed_open->host_to_connect, requestedhost) != 0)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಪ್ರತ್ಯಾಗಮ 1;
}

/*
 * Note that in the listen host/port case
 * we don't support FWD_PERMIT_ANY_PORT and
 * need to translate between the configured-host (listen_host)
 * and what we've sent to the remote server (channel_rfwd_bind_host)
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
open_listen_match_tcpip(ಸಂರಚನಾ permission *allowed_open,
    ಧ್ರುವ ವರ್ಣ *requestedhost, u_short requestedport, ಪೂರ್ಣಾಙ್ಕ translate)
{
	ಧ್ರುವ ವರ್ಣ *allowed_host;

	ಯದಿ (allowed_open->host_to_connect == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ (allowed_open->listen_port != requestedport)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ (!translate && allowed_open->listen_host == ರಿಕ್ತ &&
	    requestedhost == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ 1;
	allowed_host = translate ?
	    channel_rfwd_bind_host(allowed_open->listen_host) :
	    allowed_open->listen_host;
	ಯದಿ (allowed_host == ರಿಕ್ತ || requestedhost == ರಿಕ್ತ ||
	    strcmp(allowed_host, requestedhost) != 0)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಪ್ರತ್ಯಾಗಮ 1;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
open_listen_match_streamlocal(ಸಂರಚನಾ permission *allowed_open,
    ಧ್ರುವ ವರ್ಣ *requestedpath)
{
	ಯದಿ (allowed_open->host_to_connect == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ (allowed_open->listen_port != PORT_STREAMLOCAL)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ (allowed_open->listen_path == ರಿಕ್ತ ||
	    strcmp(allowed_open->listen_path, requestedpath) != 0)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಪ್ರತ್ಯಾಗಮ 1;
}

/*
 * Request cancellation of remote forwarding of connection host:port from
 * local side.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
channel_request_rforward_cancel_tcpip(ಸಂರಚನಾ ssh *ssh,
    ಧ್ರುವ ವರ್ಣ *host, u_short port)
{
	ಸಂರಚನಾ ssh_channels *sc = ssh->chanctxt;
	ಸಂರಚನಾ permission_set *pset = &sc->local_perms;
	ಪೂರ್ಣಾಙ್ಕ r;
	u_int i;
	ಸಂರಚನಾ permission *perm = ರಿಕ್ತ;

	ಪ್ರತಿ (i = 0; i < pset->ಅಂಕೆ_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		ಯದಿ (open_listen_match_tcpip(perm, host, port, 0))
			ಭಙ್ಗ;
		perm = ರಿಕ್ತ;
	}
	ಯದಿ (perm == ರಿಕ್ತ) {
		debug_f("requested forward not found");
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	ಯದಿ ((r = sshpkt_start(ssh, SSH2_ಸಂದೇಶ_GLOBAL_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "cancel-tcpip-forward")) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 || /* want reply */
	    (r = sshpkt_put_cstring(ssh, channel_rfwd_bind_host(host))) != 0 ||
	    (r = sshpkt_put_u32(ssh, port)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send cancel");

	fwd_perm_clear(perm); /* unregister */

	ಪ್ರತ್ಯಾಗಮ 0;
}

/*
 * Request cancellation of remote forwarding of Unix domain socket
 * path from local side.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
channel_request_rforward_cancel_streamlocal(ಸಂರಚನಾ ssh *ssh, ಧ್ರುವ ವರ್ಣ *path)
{
	ಸಂರಚನಾ ssh_channels *sc = ssh->chanctxt;
	ಸಂರಚನಾ permission_set *pset = &sc->local_perms;
	ಪೂರ್ಣಾಙ್ಕ r;
	u_int i;
	ಸಂರಚನಾ permission *perm = ರಿಕ್ತ;

	ಪ್ರತಿ (i = 0; i < pset->ಅಂಕೆ_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		ಯದಿ (open_listen_match_streamlocal(perm, path))
			ಭಙ್ಗ;
		perm = ರಿಕ್ತ;
	}
	ಯದಿ (perm == ರಿಕ್ತ) {
		debug_f("requested forward not found");
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	ಯದಿ ((r = sshpkt_start(ssh, SSH2_ಸಂದೇಶ_GLOBAL_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh,
	    "cancel-streamlocal-forward@openssh.com")) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 || /* want reply */
	    (r = sshpkt_put_cstring(ssh, path)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send cancel");

	fwd_perm_clear(perm); /* unregister */

	ಪ್ರತ್ಯಾಗಮ 0;
}

/*
 * Request cancellation of remote forwarding of a connection from local side.
 */
ಪೂರ್ಣಾಙ್ಕ
channel_request_rforward_cancel(ಸಂರಚನಾ ssh *ssh, ಸಂರಚನಾ Forward *fwd)
{
	ಯದಿ (fwd->listen_path != ರಿಕ್ತ) {
		ಪ್ರತ್ಯಾಗಮ channel_request_rforward_cancel_streamlocal(ssh,
		    fwd->listen_path);
	} ಅನ್ಯಥಾ {
		ಪ್ರತ್ಯಾಗಮ channel_request_rforward_cancel_tcpip(ssh,
		    fwd->listen_host,
		    fwd->listen_port ? fwd->listen_port : fwd->allocated_port);
	}
}

/*
 * Permits opening to any host/port if permitted_user[] is empty.  This is
 * usually called by the server, because the user could connect to any port
 * anyway, and the server has no way to know but to trust the client anyway.
 */
ಶೂನ್ಯ
channel_permit_all(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ where)
{
	ಸಂರಚನಾ permission_set *pset = permission_set_get(ssh, where);

	ಯದಿ (pset->ಅಂಕೆ_permitted_user == 0)
		pset->all_permitted = 1;
}

/*
 * Permit the specified host/port for forwarding.
 */
ಶೂನ್ಯ
channel_add_permission(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ who, ಪೂರ್ಣಾಙ್ಕ where,
    ವರ್ಣ *host, ಪೂರ್ಣಾಙ್ಕ port)
{
	ಪೂರ್ಣಾಙ್ಕ local = where == FORWARD_LOCAL;
	ಸಂರಚನಾ permission_set *pset = permission_set_get(ssh, where);

	debug("allow %s forwarding to host %s port %d",
	    fwd_ident(who, where), host, port);
	/*
	 * Remote forwards set listen_host/port, local forwards set
	 * host/port_to_connect.
	 */
	permission_set_add(ssh, who, where,
	    local ? host : ರಿಕ್ತ, local ? port : 0,
	    local ? ರಿಕ್ತ : host, ರಿಕ್ತ, local ? 0 : port, ರಿಕ್ತ);
	pset->all_permitted = 0;
}

/*
 * Administratively disable forwarding.
 */
ಶೂನ್ಯ
channel_disable_admin(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ where)
{
	channel_clear_permission(ssh, FORWARD_ADM, where);
	permission_set_add(ssh, FORWARD_ADM, where,
	    ರಿಕ್ತ, 0, ರಿಕ್ತ, ರಿಕ್ತ, 0, ರಿಕ್ತ);
}

/*
 * Clear a list of permitted opens.
 */
ಶೂನ್ಯ
channel_clear_permission(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ who, ಪೂರ್ಣಾಙ್ಕ where)
{
	ಸಂರಚನಾ permission **permp;
	u_int i, *npermp;

	permission_set_get_array(ssh, who, where, &permp, &npermp);
	ಪ್ರತಿ (i = 0; i < *npermp; i++)
		fwd_perm_clear((*permp) + i);
	ಮುಕ್ತ(*permp);
	*permp = ರಿಕ್ತ;
	*npermp = 0;
}

/*
 * Update the listen port for a dynamic remote forward, after
 * the actual 'newport' has been allocated. If 'newport' < 0 is
 * passed then they entry will be invalidated.
 */
ಶೂನ್ಯ
channel_update_permission(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ idx, ಪೂರ್ಣಾಙ್ಕ newport)
{
	ಸಂರಚನಾ permission_set *pset = &ssh->chanctxt->local_perms;

	ಯದಿ (idx < 0 || (u_int)idx >= pset->ಅಂಕೆ_permitted_user) {
		debug_f("index out of range: %d num_permitted_user %d",
		    idx, pset->ಅಂಕೆ_permitted_user);
		ಪ್ರತ್ಯಾಗಮ;
	}
	debug("%s allowed port %d for forwarding to host %s port %d",
	    newport > 0 ? "Updating" : "Removing",
	    newport,
	    pset->permitted_user[idx].host_to_connect,
	    pset->permitted_user[idx].port_to_connect);
	ಯದಿ (newport <= 0)
		fwd_perm_clear(&pset->permitted_user[idx]);
	ಅನ್ಯಥಾ {
		pset->permitted_user[idx].listen_port =
		    (ssh->compat & SSH_BUG_DYNAMIC_RPORT) ? 0 : newport;
	}
}

/* Try to start non-blocking connect to next host in cctx list */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
connect_next(ಸಂರಚನಾ ssh *ssh, ಸಂರಚನಾ channel_connect *cctx)
{
	ಪೂರ್ಣಾಙ್ಕ sock, sock_is_network, saved_errno;
	ಸಂರಚನಾ sockaddr_un *sunaddr;
	ವರ್ಣ ntop[NI_MAXHOST];
	ವರ್ಣ strport[MAXIMUM(NI_MAXSERV, ಪರಿಮಾಣ(sunaddr->sun_path))];

	ಪ್ರತಿ (; cctx->ai; cctx->ai = cctx->ai->ai_next) {
		sock_is_network = 0;
		ವಿಕಲ್ಪ (cctx->ai->ai_family) {
		ಪಕ್ಷ AF_UNIX:
			/* unix:pathname instead of host:port */
			sunaddr = (ಸಂರಚನಾ sockaddr_un *)cctx->ai->ai_addr;
			strlcpy(ntop, "unix", ಪರಿಮಾಣ(ntop));
			strlcpy(strport, sunaddr->sun_path, ಪರಿಮಾಣ(strport));
			ಭಙ್ಗ;
		ಪಕ್ಷ AF_INET:
		ಪಕ್ಷ AF_INET6:
			ಯದಿ (getnameinfo(cctx->ai->ai_addr, cctx->ai->ai_addrlen,
			    ntop, ಪರಿಮಾಣ(ntop), strport, ಪರಿಮಾಣ(strport),
			    NI_NUMERICHOST|NI_NUMERICSERV) != 0) {
				error_f("getnameinfo failed");
				ಅನುವರ್ತ;
			}
			sock_is_network = 1;
			ಭಙ್ಗ;
		ಸ್ವಭಾವ:
			ಅನುವರ್ತ;
		}
		debug_f("start for host %.100s ([%.100s]:%s)",
		    cctx->host, ntop, strport);
		ಯದಿ ((sock = socket(cctx->ai->ai_family, cctx->ai->ai_socktype,
		    cctx->ai->ai_protocol)) == -1) {
			ಯದಿ (cctx->ai->ai_next == ರಿಕ್ತ)
				error("socket: %.100s", strerror(errno));
			ಅನ್ಯಥಾ
				verbose("socket: %.100s", strerror(errno));
			ಅನುವರ್ತ;
		}
		ಯದಿ (set_nonblock(sock) == -1)
			fatal_f("set_nonblock(%d)", sock);
		ಯದಿ (sock_is_network && ssh->chanctxt->want_tcp_keepalive)
			set_keepalive(sock); /* logs errors */
		ಯದಿ (connect(sock, cctx->ai->ai_addr,
		    cctx->ai->ai_addrlen) == -1 && errno != EINPROGRESS) {
			debug_f("host %.100s ([%.100s]:%s): %.100s",
			    cctx->host, ntop, strport, strerror(errno));
			saved_errno = errno;
			close(sock);
			errno = saved_errno;
			ಅನುವರ್ತ;	/* fail -- try next */
		}
		ಯದಿ (cctx->ai->ai_family != AF_UNIX)
			set_nodelay(sock);
		debug_f("connect host %.100s ([%.100s]:%s) in progress, fd=%d",
		    cctx->host, ntop, strport, sock);
		cctx->ai = cctx->ai->ai_next;
		ಪ್ರತ್ಯಾಗಮ sock;
	}
	ಪ್ರತ್ಯಾಗಮ -1;
}

/*
 * Return connecting socket to remote host:port or local socket path,
 * passing back the failure reason if appropriate.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
connect_to_helper(ಸಂರಚನಾ ssh *ssh, ಧ್ರುವ ವರ್ಣ *name, ಪೂರ್ಣಾಙ್ಕ port, ಪೂರ್ಣಾಙ್ಕ socktype,
    ವರ್ಣ *ctype, ವರ್ಣ *rname, ಸಂರಚನಾ channel_connect *cctx,
    ಪೂರ್ಣಾಙ್ಕ *reason, ಧ್ರುವ ವರ್ಣ **errmsg)
{
	ಸಂರಚನಾ addrinfo hints;
	ಪೂರ್ಣಾಙ್ಕ gaierr;
	ಪೂರ್ಣಾಙ್ಕ sock = -1;
	ವರ್ಣ strport[NI_MAXSERV];

	ಯದಿ (port == PORT_STREAMLOCAL) {
		ಸಂರಚನಾ sockaddr_un *sunaddr;
		ಸಂರಚನಾ addrinfo *ai;

		ಯದಿ (strlen(name) > ಪರಿಮಾಣ(sunaddr->sun_path)) {
			error("%.100s: %.100s", name, strerror(ENAMETOOLONG));
			ಪ್ರತ್ಯಾಗಮ -1;
		}

		/*
		 * Fake up a struct addrinfo for AF_UNIX connections.
		 * free_connect_ctx() must check ai_family
		 * and use free() not freeaddrinfo() for AF_UNIX.
		 */
		ai = xcalloc(1, ಪರಿಮಾಣ(*ai) + ಪರಿಮಾಣ(*sunaddr));
		ai->ai_addr = (ಸಂರಚನಾ sockaddr *)(ai + 1);
		ai->ai_addrlen = ಪರಿಮಾಣ(*sunaddr);
		ai->ai_family = AF_UNIX;
		ai->ai_socktype = socktype;
		ai->ai_protocol = PF_UNSPEC;
		sunaddr = (ಸಂರಚನಾ sockaddr_un *)ai->ai_addr;
		sunaddr->sun_family = AF_UNIX;
		strlcpy(sunaddr->sun_path, name, ಪರಿಮಾಣ(sunaddr->sun_path));
		cctx->aitop = ai;
	} ಅನ್ಯಥಾ {
		memset(&hints, 0, ಪರಿಮಾಣ(hints));
		hints.ai_family = ssh->chanctxt->IPv4or6;
		hints.ai_socktype = socktype;
		snprintf(strport, ಪರಿಮಾಣ strport, "%d", port);
		ಯದಿ ((gaierr = getaddrinfo(name, strport, &hints, &cctx->aitop))
		    != 0) {
			ಯದಿ (errmsg != ರಿಕ್ತ)
				*errmsg = ssh_gai_strerror(gaierr);
			ಯದಿ (reason != ರಿಕ್ತ)
				*reason = SSH2_OPEN_CONNECT_FAILED;
			error("connect_to %.100s: unknown host (%s)", name,
			    ssh_gai_strerror(gaierr));
			ಪ್ರತ್ಯಾಗಮ -1;
		}
	}

	cctx->host = xstrdup(name);
	cctx->port = port;
	cctx->ai = cctx->aitop;

	ಯದಿ ((sock = connect_next(ssh, cctx)) == -1) {
		error("connect to %.100s port %d failed: %s",
		    name, port, strerror(errno));
		ಪ್ರತ್ಯಾಗಮ -1;
	}

	ಪ್ರತ್ಯಾಗಮ sock;
}

/* Return CONNECTING channel to remote host:port or local socket path */
ಸ್ಥಿರ Channel *
connect_to(ಸಂರಚನಾ ssh *ssh, ಧ್ರುವ ವರ್ಣ *host, ಪೂರ್ಣಾಙ್ಕ port,
    ವರ್ಣ *ctype, ವರ್ಣ *rname)
{
	ಸಂರಚನಾ channel_connect cctx;
	Channel *c;
	ಪೂರ್ಣಾಙ್ಕ sock;

	memset(&cctx, 0, ಪರಿಮಾಣ(cctx));
	sock = connect_to_helper(ssh, host, port, SOCK_STREAM, ctype, rname,
	    &cctx, ರಿಕ್ತ, ರಿಕ್ತ);
	ಯದಿ (sock == -1) {
		free_connect_ctx(&cctx);
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}
	c = channel_new(ssh, ctype, SSH_CHANNEL_CONNECTING, sock, sock, -1,
	    CHAN_TCP_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, rname, 1);
	c->host_port = port;
	c->path = xstrdup(host);
	c->connect_ctx = xmalloc(ಪರಿಮಾಣ(cctx));
	memcpy(c->connect_ctx, &cctx, ಪರಿಮಾಣ(cctx));

	ಪ್ರತ್ಯಾಗಮ c;
}

/*
 * returns either the newly connected channel or the downstream channel
 * that needs to deal with this connection.
 */
Channel *
channel_connect_by_listen_address(ಸಂರಚನಾ ssh *ssh, ಧ್ರುವ ವರ್ಣ *listen_host,
    u_short listen_port, ವರ್ಣ *ctype, ವರ್ಣ *rname)
{
	ಸಂರಚನಾ ssh_channels *sc = ssh->chanctxt;
	ಸಂರಚನಾ permission_set *pset = &sc->local_perms;
	u_int i;
	ಸಂರಚನಾ permission *perm;

	ಪ್ರತಿ (i = 0; i < pset->ಅಂಕೆ_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		ಯದಿ (open_listen_match_tcpip(perm,
		    listen_host, listen_port, 1)) {
			ಯದಿ (perm->downstream)
				ಪ್ರತ್ಯಾಗಮ perm->downstream;
			ಯದಿ (perm->port_to_connect == 0)
				ಪ್ರತ್ಯಾಗಮ rdynamic_connect_prepare(ssh,
				    ctype, rname);
			ಪ್ರತ್ಯಾಗಮ connect_to(ssh,
			    perm->host_to_connect, perm->port_to_connect,
			    ctype, rname);
		}
	}
	error("WARNING: Server requests forwarding for unknown listen_port %d",
	    listen_port);
	ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
}

Channel *
channel_connect_by_listen_path(ಸಂರಚನಾ ssh *ssh, ಧ್ರುವ ವರ್ಣ *path,
    ವರ್ಣ *ctype, ವರ್ಣ *rname)
{
	ಸಂರಚನಾ ssh_channels *sc = ssh->chanctxt;
	ಸಂರಚನಾ permission_set *pset = &sc->local_perms;
	u_int i;
	ಸಂರಚನಾ permission *perm;

	ಪ್ರತಿ (i = 0; i < pset->ಅಂಕೆ_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		ಯದಿ (open_listen_match_streamlocal(perm, path)) {
			ಪ್ರತ್ಯಾಗಮ connect_to(ssh,
			    perm->host_to_connect, perm->port_to_connect,
			    ctype, rname);
		}
	}
	error("WARNING: Server requests forwarding for unknown path %.100s",
	    path);
	ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
}

/* Check if connecting to that port is permitted and connect. */
Channel *
channel_connect_to_port(ಸಂರಚನಾ ssh *ssh, ಧ್ರುವ ವರ್ಣ *host, u_short port,
    ವರ್ಣ *ctype, ವರ್ಣ *rname, ಪೂರ್ಣಾಙ್ಕ *reason, ಧ್ರುವ ವರ್ಣ **errmsg)
{
	ಸಂರಚನಾ ssh_channels *sc = ssh->chanctxt;
	ಸಂರಚನಾ permission_set *pset = &sc->local_perms;
	ಸಂರಚನಾ channel_connect cctx;
	Channel *c;
	u_int i, permit, permit_adm = 1;
	ಪೂರ್ಣಾಙ್ಕ sock;
	ಸಂರಚನಾ permission *perm;

	permit = pset->all_permitted;
	ಯದಿ (!permit) {
		ಪ್ರತಿ (i = 0; i < pset->ಅಂಕೆ_permitted_user; i++) {
			perm = &pset->permitted_user[i];
			ಯದಿ (open_match(perm, host, port)) {
				permit = 1;
				ಭಙ್ಗ;
			}
		}
	}

	ಯದಿ (pset->ಅಂಕೆ_permitted_admin > 0) {
		permit_adm = 0;
		ಪ್ರತಿ (i = 0; i < pset->ಅಂಕೆ_permitted_admin; i++) {
			perm = &pset->permitted_admin[i];
			ಯದಿ (open_match(perm, host, port)) {
				permit_adm = 1;
				ಭಙ್ಗ;
			}
		}
	}

	ಯದಿ (!permit || !permit_adm) {
		logit("Received request from %.100s port %d to connect to "
		    "host %.100s port %d, but the request was denied.",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh), host, port);
		ಯದಿ (reason != ರಿಕ್ತ)
			*reason = SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED;
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}

	memset(&cctx, 0, ಪರಿಮಾಣ(cctx));
	sock = connect_to_helper(ssh, host, port, SOCK_STREAM, ctype, rname,
	    &cctx, reason, errmsg);
	ಯದಿ (sock == -1) {
		free_connect_ctx(&cctx);
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}

	c = channel_new(ssh, ctype, SSH_CHANNEL_CONNECTING, sock, sock, -1,
	    CHAN_TCP_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, rname, 1);
	c->host_port = port;
	c->path = xstrdup(host);
	c->connect_ctx = xmalloc(ಪರಿಮಾಣ(cctx));
	memcpy(c->connect_ctx, &cctx, ಪರಿಮಾಣ(cctx));

	ಪ್ರತ್ಯಾಗಮ c;
}

/* Check if connecting to that path is permitted and connect. */
Channel *
channel_connect_to_path(ಸಂರಚನಾ ssh *ssh, ಧ್ರುವ ವರ್ಣ *path,
    ವರ್ಣ *ctype, ವರ್ಣ *rname)
{
	ಸಂರಚನಾ ssh_channels *sc = ssh->chanctxt;
	ಸಂರಚನಾ permission_set *pset = &sc->local_perms;
	u_int i, permit, permit_adm = 1;
	ಸಂರಚನಾ permission *perm;

	permit = pset->all_permitted;
	ಯದಿ (!permit) {
		ಪ್ರತಿ (i = 0; i < pset->ಅಂಕೆ_permitted_user; i++) {
			perm = &pset->permitted_user[i];
			ಯದಿ (open_match(perm, path, PORT_STREAMLOCAL)) {
				permit = 1;
				ಭಙ್ಗ;
			}
		}
	}

	ಯದಿ (pset->ಅಂಕೆ_permitted_admin > 0) {
		permit_adm = 0;
		ಪ್ರತಿ (i = 0; i < pset->ಅಂಕೆ_permitted_admin; i++) {
			perm = &pset->permitted_admin[i];
			ಯದಿ (open_match(perm, path, PORT_STREAMLOCAL)) {
				permit_adm = 1;
				ಭಙ್ಗ;
			}
		}
	}

	ಯದಿ (!permit || !permit_adm) {
		logit("Received request to connect to path %.100s, "
		    "but the request was denied.", path);
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}
	ಪ್ರತ್ಯಾಗಮ connect_to(ssh, path, PORT_STREAMLOCAL, ctype, rname);
}

ಶೂನ್ಯ
channel_send_window_changes(ಸಂರಚನಾ ssh *ssh)
{
	ಸಂರಚನಾ ssh_channels *sc = ssh->chanctxt;
	ಸಂರಚನಾ winsize ws;
	ಪೂರ್ಣಾಙ್ಕ r;
	u_int i;

	ಪ್ರತಿ (i = 0; i < sc->channels_alloc; i++) {
		ಯದಿ (sc->channels[i] == ರಿಕ್ತ || !sc->channels[i]->client_tty ||
		    sc->channels[i]->type != SSH_CHANNEL_OPEN)
			ಅನುವರ್ತ;
		ಯದಿ (ioctl(sc->channels[i]->rfd, TIOCGWINSZ, &ws) == -1)
			ಅನುವರ್ತ;
		channel_request_start(ssh, i, "window-change", 0);
		ಯದಿ ((r = sshpkt_put_u32(ssh, (u_int)ws.ws_col)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_row)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_xpixel)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_ypixel)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "channel %u; send window-change", i);
	}
}

/* Return RDYNAMIC_OPEN channel: channel allows SOCKS, but is not connected */
ಸ್ಥಿರ Channel *
rdynamic_connect_prepare(ಸಂರಚನಾ ssh *ssh, ವರ್ಣ *ctype, ವರ್ಣ *rname)
{
	Channel *c;
	ಪೂರ್ಣಾಙ್ಕ r;

	c = channel_new(ssh, ctype, SSH_CHANNEL_RDYNAMIC_OPEN, -1, -1, -1,
	    CHAN_TCP_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, rname, 1);
	c->host_port = 0;
	c->path = ರಿಕ್ತ;

	/*
	 * We need to open the channel before we have a FD,
	 * so that we can get SOCKS header from peer.
	 */
	ಯದಿ ((r = sshpkt_start(ssh, SSH2_ಸಂದೇಶ_CHANNEL_OPEN_CONFIRMATION)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_window)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0)
		fatal_fr(r, "channel %i; confirm", c->self);
	ಪ್ರತ್ಯಾಗಮ c;
}

/* Return CONNECTING socket to remote host:port or local socket path */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
rdynamic_connect_finish(ಸಂರಚನಾ ssh *ssh, Channel *c)
{
	ಸಂರಚನಾ ssh_channels *sc = ssh->chanctxt;
	ಸಂರಚನಾ permission_set *pset = &sc->local_perms;
	ಸಂರಚನಾ permission *perm;
	ಸಂರಚನಾ channel_connect cctx;
	u_int i, permit_adm = 1;
	ಪೂರ್ಣಾಙ್ಕ sock;

	ಯದಿ (pset->ಅಂಕೆ_permitted_admin > 0) {
		permit_adm = 0;
		ಪ್ರತಿ (i = 0; i < pset->ಅಂಕೆ_permitted_admin; i++) {
			perm = &pset->permitted_admin[i];
			ಯದಿ (open_match(perm, c->path, c->host_port)) {
				permit_adm = 1;
				ಭಙ್ಗ;
			}
		}
	}
	ಯದಿ (!permit_adm) {
		debug_f("requested forward not permitted");
		ಪ್ರತ್ಯಾಗಮ -1;
	}

	memset(&cctx, 0, ಪರಿಮಾಣ(cctx));
	sock = connect_to_helper(ssh, c->path, c->host_port, SOCK_STREAM, ರಿಕ್ತ,
	    ರಿಕ್ತ, &cctx, ರಿಕ್ತ, ರಿಕ್ತ);
	ಯದಿ (sock == -1)
		free_connect_ctx(&cctx);
	ಅನ್ಯಥಾ {
		/* similar to SSH_CHANNEL_CONNECTING but we've already sent the open */
		c->type = SSH_CHANNEL_RDYNAMIC_FINISH;
		c->connect_ctx = xmalloc(ಪರಿಮಾಣ(cctx));
		memcpy(c->connect_ctx, &cctx, ಪರಿಮಾಣ(cctx));
		channel_register_fds(ssh, c, sock, sock, -1, 0, 1, 0);
	}
	ಪ್ರತ್ಯಾಗಮ sock;
}

/* -- X11 forwarding */

/*
 * Creates an internet domain socket for listening for X11 connections.
 * Returns 0 and a suitable display number for the DISPLAY variable
 * stored in display_numberp , or -1 if an error occurs.
 */
ಪೂರ್ಣಾಙ್ಕ
x11_create_display_inet(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ x11_display_offset,
    ಪೂರ್ಣಾಙ್ಕ x11_use_localhost, ಪೂರ್ಣಾಙ್ಕ single_connection,
    u_int *display_numberp, ಪೂರ್ಣಾಙ್ಕ **chanids)
{
	Channel *nc = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ display_ಸಂಖ್ಯೆ, sock, port;
	ಸಂರಚನಾ addrinfo hints, *ai, *aitop;
	ವರ್ಣ strport[NI_MAXSERV];
	ಪೂರ್ಣಾಙ್ಕ gaierr, n, ಅಂಕೆ_socks = 0, socks[ಅಂಕೆ_SOCKS];

	ಯದಿ (chanids == ರಿಕ್ತ || x11_display_offset < 0 ||
	    x11_display_offset > UINT16_MAX - X11_BASE_PORT - MAX_DISPLAYS)
		ಪ್ರತ್ಯಾಗಮ -1;

	ಪ್ರತಿ (display_ಸಂಖ್ಯೆ = x11_display_offset;
	    display_ಸಂಖ್ಯೆ < x11_display_offset + MAX_DISPLAYS;
	    display_ಸಂಖ್ಯೆ++) {
		port = X11_BASE_PORT + display_ಸಂಖ್ಯೆ;
		memset(&hints, 0, ಪರಿಮಾಣ(hints));
		hints.ai_family = ssh->chanctxt->IPv4or6;
		hints.ai_flags = x11_use_localhost ? 0: AI_PASSIVE;
		hints.ai_socktype = SOCK_STREAM;
		snprintf(strport, ಪರಿಮಾಣ strport, "%d", port);
		ಯದಿ ((gaierr = getaddrinfo(ರಿಕ್ತ, strport,
		    &hints, &aitop)) != 0) {
			error("getaddrinfo: %.100s", ssh_gai_strerror(gaierr));
			ಪ್ರತ್ಯಾಗಮ -1;
		}
		ಪ್ರತಿ (ai = aitop; ai; ai = ai->ai_next) {
			ಯದಿ (ai->ai_family != AF_INET &&
			    ai->ai_family != AF_INET6)
				ಅನುವರ್ತ;
			sock = socket(ai->ai_family, ai->ai_socktype,
			    ai->ai_protocol);
			ಯದಿ (sock == -1) {
				ಯದಿ ((errno != EINVAL) && (errno != EAFNOSUPPORT)
#ifdef EPFNOSUPPORT
				    && (errno != EPFNOSUPPORT)
#endif 
				    ) {
					error("socket: %.100s", strerror(errno));
					freeaddrinfo(aitop);
					ಪ್ರತ್ಯಾಗಮ -1;
				} ಅನ್ಯಥಾ {
					debug("x11_create_display_inet: Socket family %d not supported",
						 ai->ai_family);
					ಅನುವರ್ತ;
				}
			}
			ಯದಿ (ai->ai_family == AF_INET6)
				sock_set_v6only(sock);
			ಯದಿ (x11_use_localhost)
				set_reuseaddr(sock);
			ಯದಿ (bind(sock, ai->ai_addr, ai->ai_addrlen) == -1) {
				debug2_f("bind port %d: %.100s", port,
				    strerror(errno));
				close(sock);
				ಪ್ರತಿ (n = 0; n < ಅಂಕೆ_socks; n++)
					close(socks[n]);
				ಅಂಕೆ_socks = 0;
				ಭಙ್ಗ;
			}
			socks[ಅಂಕೆ_socks++] = sock;
			ಯದಿ (ಅಂಕೆ_socks == ಅಂಕೆ_SOCKS)
				ಭಙ್ಗ;
		}
		freeaddrinfo(aitop);
		ಯದಿ (ಅಂಕೆ_socks > 0)
			ಭಙ್ಗ;
	}
	ಯದಿ (display_ಸಂಖ್ಯೆ >= x11_display_offset + MAX_DISPLAYS) {
		error("Failed to allocate internet-domain X11 display socket.");
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	/* Start listening for connections on the socket. */
	ಪ್ರತಿ (n = 0; n < ಅಂಕೆ_socks; n++) {
		sock = socks[n];
		ಯದಿ (listen(sock, SSH_LISTEN_BACKLOG) == -1) {
			error("listen: %.100s", strerror(errno));
			close(sock);
			ಪ್ರತ್ಯಾಗಮ -1;
		}
	}

	/* Allocate a channel for each socket. */
	*chanids = xcalloc(ಅಂಕೆ_socks + 1, ಪರಿಮಾಣ(**chanids));
	ಪ್ರತಿ (n = 0; n < ಅಂಕೆ_socks; n++) {
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
	*display_numberp = display_ಸಂಖ್ಯೆ;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
connect_local_xsocket_path(ಧ್ರುವ ವರ್ಣ *pathname)
{
	ಪೂರ್ಣಾಙ್ಕ sock;
	ಸಂರಚನಾ sockaddr_un addr;

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	ಯದಿ (sock == -1) {
		error("socket: %.100s", strerror(errno));
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	memset(&addr, 0, ಪರಿಮಾಣ(addr));
	addr.sun_family = AF_UNIX;
	strlcpy(addr.sun_path, pathname, ಪರಿಮಾಣ addr.sun_path);
	ಯದಿ (connect(sock, (ಸಂರಚನಾ sockaddr *)&addr, ಪರಿಮಾಣ(addr)) == 0)
		ಪ್ರತ್ಯಾಗಮ sock;
	close(sock);
	error("connect %.100s: %.100s", addr.sun_path, strerror(errno));
	ಪ್ರತ್ಯಾಗಮ -1;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
connect_local_xsocket(u_int dnr)
{
	ವರ್ಣ buf[1024];
	snprintf(buf, ಪರಿಮಾಣ buf, _PATH_UNIX_X, dnr);
	ಪ್ರತ್ಯಾಗಮ connect_local_xsocket_path(buf);
}

#ifdef __APPLE__
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
is_path_to_xsocket(ಧ್ರುವ ವರ್ಣ *display, ವರ್ಣ *path, size_t pathlen)
{
	ಸಂರಚನಾ stat sbuf;

	ಯದಿ (strlcpy(path, display, pathlen) >= pathlen) {
		error_f("display path too long");
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	ಯದಿ (display[0] != '/')
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ (stat(path, &sbuf) == 0) {
		ಪ್ರತ್ಯಾಗಮ 1;
	} ಅನ್ಯಥಾ {
		ವರ್ಣ *dot = strrchr(path, '.');
		ಯದಿ (dot != ರಿಕ್ತ) {
			*dot = '\0';
			ಯದಿ (stat(path, &sbuf) == 0) {
				ಪ್ರತ್ಯಾಗಮ 1;
			}
		}
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}
#endif

ಪೂರ್ಣಾಙ್ಕ
x11_connect_display(ಸಂರಚನಾ ssh *ssh)
{
	u_int display_ಸಂಖ್ಯೆ;
	ಧ್ರುವ ವರ್ಣ *display;
	ವರ್ಣ buf[1024], *cp;
	ಸಂರಚನಾ addrinfo hints, *ai, *aitop;
	ವರ್ಣ strport[NI_MAXSERV];
	ಪೂರ್ಣಾಙ್ಕ gaierr, sock = 0;

	/* Try to open a socket for the local X server. */
	display = getenv("DISPLAY");
	ಯದಿ (!display) {
		error("DISPLAY not set.");
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	/*
	 * Now we decode the value of the DISPLAY variable and make a
	 * connection to the real X server.
	 */

#ifdef __APPLE__
	/* Check if display is a path to a socket (as set by launchd). */
	{
		ವರ್ಣ path[PATH_MAX];

		ಯದಿ (is_path_to_xsocket(display, path, ಪರಿಮಾಣ(path))) {
			debug("x11_connect_display: $DISPLAY is launchd");

			/* Create a socket. */
			sock = connect_local_xsocket_path(path);
			ಯದಿ (sock < 0)
				ಪ್ರತ್ಯಾಗಮ -1;

			/* OK, we now have a connection to the display. */
			ಪ್ರತ್ಯಾಗಮ sock;
		}
	}
#endif
	/*
	 * Check if it is a unix domain socket.  Unix domain displays are in
	 * one of the following formats: unix:d[.s], :d[.s], ::d[.s]
	 */
	ಯದಿ (strncmp(display, "unix:", 5) == 0 ||
	    display[0] == ':') {
		/* Connect to the unix domain socket. */
		ಯದಿ (sscanf(strrchr(display, ':') + 1, "%u",
		    &display_ಸಂಖ್ಯೆ) != 1) {
			error("Could not parse display number from DISPLAY: "
			    "%.100s", display);
			ಪ್ರತ್ಯಾಗಮ -1;
		}
		/* Create a socket. */
		sock = connect_local_xsocket(display_ಸಂಖ್ಯೆ);
		ಯದಿ (sock < 0)
			ಪ್ರತ್ಯಾಗಮ -1;

		/* OK, we now have a connection to the display. */
		ಪ್ರತ್ಯಾಗಮ sock;
	}
	/*
	 * Connect to an inet socket.  The DISPLAY value is supposedly
	 * hostname:d[.s], where hostname may also be numeric IP address.
	 */
	strlcpy(buf, display, ಪರಿಮಾಣ(buf));
	cp = strchr(buf, ':');
	ಯದಿ (!cp) {
		error("Could not find ':' in DISPLAY: %.100s", display);
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	*cp = 0;
	/*
	 * buf now contains the host name.  But first we parse the
	 * display number.
	 */
	ಯದಿ (sscanf(cp + 1, "%u", &display_ಸಂಖ್ಯೆ) != 1 ||
	    display_ಸಂಖ್ಯೆ > UINT16_MAX - X11_BASE_PORT) {
		error("Could not parse display number from DISPLAY: %.100s",
		    display);
		ಪ್ರತ್ಯಾಗಮ -1;
	}

	/* Look up the host address */
	memset(&hints, 0, ಪರಿಮಾಣ(hints));
	hints.ai_family = ssh->chanctxt->IPv4or6;
	hints.ai_socktype = SOCK_STREAM;
	snprintf(strport, ಪರಿಮಾಣ strport, "%u", X11_BASE_PORT + display_ಸಂಖ್ಯೆ);
	ಯದಿ ((gaierr = getaddrinfo(buf, strport, &hints, &aitop)) != 0) {
		error("%.100s: unknown host. (%s)", buf,
		ssh_gai_strerror(gaierr));
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	ಪ್ರತಿ (ai = aitop; ai; ai = ai->ai_next) {
		/* Create a socket. */
		sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		ಯದಿ (sock == -1) {
			debug2("socket: %.100s", strerror(errno));
			ಅನುವರ್ತ;
		}
		/* Connect it to the display. */
		ಯದಿ (connect(sock, ai->ai_addr, ai->ai_addrlen) == -1) {
			debug2("connect %.100s port %u: %.100s", buf,
			    X11_BASE_PORT + display_ಸಂಖ್ಯೆ, strerror(errno));
			close(sock);
			ಅನುವರ್ತ;
		}
		/* Success */
		ಭಙ್ಗ;
	}
	freeaddrinfo(aitop);
	ಯದಿ (!ai) {
		error("connect %.100s port %u: %.100s", buf,
		    X11_BASE_PORT + display_ಸಂಖ್ಯೆ, strerror(errno));
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	set_nodelay(sock);
	ಪ್ರತ್ಯಾಗಮ sock;
}

/*
 * Requests forwarding of X11 connections, generates fake authentication
 * data, and enables authentication spoofing.
 * This should be called in the client only.
 */
ಶೂನ್ಯ
x11_request_forwarding_with_spoofing(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ client_session_id,
    ಧ್ರುವ ವರ್ಣ *disp, ಧ್ರುವ ವರ್ಣ *proto, ಧ್ರುವ ವರ್ಣ *data, ಪೂರ್ಣಾಙ್ಕ want_reply)
{
	ಸಂರಚನಾ ssh_channels *sc = ssh->chanctxt;
	u_int data_len = (u_int) strlen(data) / 2;
	u_int i, ಮೌಲ್ಯ;
	ಧ್ರುವ ವರ್ಣ *cp;
	ವರ್ಣ *new_data;
	ಪೂರ್ಣಾಙ್ಕ r, screen_ಸಂಖ್ಯೆ;

	ಯದಿ (sc->x11_saved_display == ರಿಕ್ತ)
		sc->x11_saved_display = xstrdup(disp);
	ಅನ್ಯಥಾ ಯದಿ (strcmp(disp, sc->x11_saved_display) != 0) {
		error("x11_request_forwarding_with_spoofing: different "
		    "$DISPLAY already forwarded");
		ಪ್ರತ್ಯಾಗಮ;
	}

	cp = strchr(disp, ':');
	ಯದಿ (cp)
		cp = strchr(cp, '.');
	ಯದಿ (cp)
		screen_ಸಂಖ್ಯೆ = (u_int)strtonum(cp + 1, 0, 400, ರಿಕ್ತ);
	ಅನ್ಯಥಾ
		screen_ಸಂಖ್ಯೆ = 0;

	ಯದಿ (sc->x11_saved_proto == ರಿಕ್ತ) {
		/* Save protocol name. */
		sc->x11_saved_proto = xstrdup(proto);

		/* Extract real authentication data. */
		sc->x11_saved_data = xmalloc(data_len);
		ಪ್ರತಿ (i = 0; i < data_len; i++) {
			ಯದಿ (sscanf(data + 2 * i, "%2x", &ಮೌಲ್ಯ) != 1) {
				fatal("x11_request_forwarding: bad "
				    "authentication data: %.100s", data);
			}
			sc->x11_saved_data[i] = ಮೌಲ್ಯ;
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
	ಯದಿ ((r = sshpkt_put_u8(ssh, 0)) != 0 || /* bool: single connection */
	    (r = sshpkt_put_cstring(ssh, proto)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, new_data)) != 0 ||
	    (r = sshpkt_put_u32(ssh, screen_ಸಂಖ್ಯೆ)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send x11-req");
	ಮುಕ್ತ(new_data);
}

/*
 * Returns whether an x11 channel was used recently (less than a second ago)
 */
ಪೂರ್ಣಾಙ್ಕ
x11_channel_used_recently(ಸಂರಚನಾ ssh *ssh) {
	u_int i;
	Channel *c;
	ದ್ವಿಗುಣ lastused = 0;

	ಪ್ರತಿ (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		ಯದಿ (c == ರಿಕ್ತ || c->ctype == ರಿಕ್ತ || c->lastused == 0.0 ||
		    strcmp(c->ctype, "x11-connection") != 0)
			ಅನುವರ್ತ;
		ಯದಿ (c->lastused > lastused)
			lastused = c->lastused;
	}
	ಪ್ರತ್ಯಾಗಮ lastused != 0.0 && monotime_double() <= lastused + 1.0;
}
