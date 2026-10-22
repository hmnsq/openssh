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
#ವ್ಯಾಖ್ಯಾನಿಸು	ಅಂಕೆ_SOCKS	10

/* -- X11 forwarding */
/* X11 port for display :0 */
#ವ್ಯಾಖ್ಯಾನಿಸು X11_ತಳ_ಪೋರ್ಟ್	6000
/* Maximum number of fake X11 displays to try. */
#ವ್ಯಾಖ್ಯಾನಿಸು MAX_DISPLAYS  1000

/* Per-channel callback for pre/post IO actions */
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಶೂನ್ಯ chan_fn(ರಚನೆ ssh *, Channel *c);

/*
 * Data structure for storing which hosts are permitted for forward requests.
 * The local sides of any remote forwards are stored in this array to prevent
 * a corrupt remote server from accessing arbitrary TCP/IP ports on our local
 * network (which might be behind a firewall).
 */
/* XXX: streamlocal wants a path instead of host:port */
/*      Overload host_to_connect; we could just make this match Forward */
/*	XXX - can we use listen_host instead of listen_path? */
ರಚನೆ permission {
	ಅಕ್ಷರ *host_ಗಮ್ಯ_connect;		/* Connect to 'host'. */
	ಪೂರ್ಣಾಂಕ ಪೋರ್ಟ್_ಗಮ್ಯ_connect;		/* Connect to 'port'. */
	ಅಕ್ಷರ *listen_host;		/* Remote side should listen address. */
	ಅಕ್ಷರ *listen_ಮಾರ್ಗ;		/* Remote side should listen path. */
	ಪೂರ್ಣಾಂಕ listen_ಪೋರ್ಟ್;		/* Remote side should listen port. */
	Channel *downstream;		/* Downstream mux*/
};

/* Context for non-blocking connects */
ರಚನೆ channel_connect {
	ಅಕ್ಷರ *host;
	ಪೂರ್ಣಾಂಕ ಪೋರ್ಟ್;
	ರಚನೆ addrinfo *ai, *aitop;
};

/*
 * Stores the forwarding permission state for a single direction (local or
 * remote).
 */
ರಚನೆ permission_ಗಣ {
	/*
	 * List of all local permitted host/port pairs to allow for the
	 * user.
	 */
	u_int ಅಂಕೆ_permitted_user;
	ರಚನೆ permission *permitted_user;

	/*
	 * List of all permitted host/port pairs to allow for the admin.
	 */
	u_int ಅಂಕೆ_permitted_admin;
	ರಚನೆ permission *permitted_admin;

	/*
	 * If this is true, all opens/listens are permitted.  This is the
	 * case on the server on which we have to trust the client anyway,
	 * and the user could do anything after logging in.
	 */
	ಪೂರ್ಣಾಂಕ all_permitted;
};

/* Used to record timeouts per channel type */
ರಚನೆ ssh_channel_timeout {
	ಅಕ್ಷರ *type_ನಮೂನೆ;
	ದ್ವಿಗುಣ timeout_secs;
};

/* Master structure for channels state */
ರಚನೆ ssh_channels {
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
	ರಚನೆ permission_ಗಣ local_perms;
	ರಚನೆ permission_ಗಣ remote_perms;

	/* -- X11 forwarding */

	/* Saved X11 local (client) display. */
	ಅಕ್ಷರ *x11_saved_display;

	/* Saved X11 authentication protocol name. */
	ಅಕ್ಷರ *x11_saved_proto;

	/* Saved X11 authentication data.  This is the real data. */
	ಅಕ್ಷರ *x11_saved_ದತ್ತಾಂಶ;
	u_int x11_saved_ದತ್ತಾಂಶ_len;

	/* Deadline after which all X11 connections are refused */
	ದ್ವಿಗುಣ x11_refuse_ಸಮಯ;

	/*
	 * Fake X11 authentication data.  This is what the server will be
	 * sending us; we should replace any occurrences of this by the
	 * real data.
	 */
	u_char *x11_fake_ದತ್ತಾಂಶ;
	u_int x11_fake_ದತ್ತಾಂಶ_len;

	/* AF_UNSPEC or AF_INET or AF_INET6 */
	ಪೂರ್ಣಾಂಕ IPv4or6;

	/* Set SO_KEEPALIVE on TCP connections */
	ಪೂರ್ಣಾಂಕ want_tcp_keepalive;

	/* Channel timeouts by type */
	ರಚನೆ ssh_channel_timeout *timeouts;
	ಗಾತ್ರ_t ntimeouts;
	/* Global timeout for all OPEN channels */
	ದ್ವಿಗುಣ global_deadline;
	ದ್ವಿಗುಣ lastused;
	/* pattern-lists used to classify channels as bulk */
	ಅಕ್ಷರ *bulk_classifier_tty, *bulk_classifier_notty;
	/* Number of active bulk channels (set by channel_handler) */
	u_int nbulk;
};

/* helper */
ಸ್ಥಿರ ಶೂನ್ಯ ಪೋರ್ಟ್_open_helper(ರಚನೆ ssh *ssh, Channel *c, ಅಕ್ಷರ *rtype);
ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *channel_rfwd_bind_host(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *listen_host);

/* non-blocking connect helpers */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ connect_ಮುಂದಿನ(ರಚನೆ ssh *, ರಚನೆ channel_connect *);
ಸ್ಥಿರ Channel *rdynamic_connect_prepare(ರಚನೆ ssh *, ಅಕ್ಷರ *, ಅಕ್ಷರ *);
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ rdynamic_connect_ಮುಕ್ತಾಯ(ರಚನೆ ssh *, Channel *);

/* Setup helper */
ಸ್ಥಿರ ಶೂನ್ಯ channel_handler_init(ರಚನೆ ssh_channels *sc);

/* -- channel core */

ಶೂನ್ಯ
channel_init_channels(ರಚನೆ ssh *ssh)
{
	ರಚನೆ ssh_channels *sc;

	ಆದರೆ ((sc = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, ಗಾತ್ರ(*sc))) == ಖಾಲಿ)
		fatal_f("allocation failed");
	sc->channels_alloc = 10;
	sc->channels = xcalloc(sc->channels_alloc, ಗಾತ್ರ(*sc->channels));
	sc->IPv4or6 = AF_UNSPEC;
	sc->bulk_classifier_tty = xstrdup(CHANNEL_BULK_TTY);
	sc->bulk_classifier_notty = xstrdup(CHANNEL_BULK_NOTTY);
	channel_handler_init(sc);

	ssh->chanctxt = sc;
}

Channel *
channel_by_id(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ id)
{
	Channel *c;

	ಆದರೆ (id < 0 || (u_int)id >= ssh->chanctxt->channels_alloc) {
		logit_f("%d: bad id", id);
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	c = ssh->chanctxt->channels[id];
	ಆದರೆ (c == ಖಾಲಿ) {
		logit_f("%d: bad id: channel free", id);
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	ಹಿಂತಿರುಗಿ c;
}

Channel *
channel_by_remote_id(ರಚನೆ ssh *ssh, u_int remote_id)
{
	Channel *c;
	u_int i;

	ಗಾಗಿ (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		ಆದರೆ (c != ಖಾಲಿ && c->have_remote_id && c->remote_id == remote_id)
			ಹಿಂತಿರುಗಿ c;
	}
	ಹಿಂತಿರುಗಿ ಖಾಲಿ;
}

/*
 * Returns the channel if it is allowed to receive protocol messages.
 * Private channels, like listening sockets, may not receive messages.
 */
Channel *
channel_lookup(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ id)
{
	Channel *c;

	ಆದರೆ ((c = channel_by_id(ssh, id)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;

	ಆಯ್ಕೆ (c->type) {
	ಸ್ಥಿತಿ SSH_CHANNEL_X11_OPEN:
	ಸ್ಥಿತಿ SSH_CHANNEL_LARVAL:
	ಸ್ಥಿತಿ SSH_CHANNEL_CONNECTING:
	ಸ್ಥಿತಿ SSH_CHANNEL_DYNAMIC:
	ಸ್ಥಿತಿ SSH_CHANNEL_RDYNAMIC_OPEN:
	ಸ್ಥಿತಿ SSH_CHANNEL_RDYNAMIC_ಮುಕ್ತಾಯ:
	ಸ್ಥಿತಿ SSH_CHANNEL_OPENING:
	ಸ್ಥಿತಿ SSH_CHANNEL_OPEN:
	ಸ್ಥಿತಿ SSH_CHANNEL_ABANDONED:
	ಸ್ಥಿತಿ SSH_CHANNEL_MUX_PROXY:
		ಹಿಂತಿರುಗಿ c;
	}
	logit("Non-public channel %d, type %d.", id, c->type);
	ಹಿಂತಿರುಗಿ ಖಾಲಿ;
}

ಸ್ಥಿರ ಶೂನ್ಯ
free_connect_ctx(ರಚನೆ channel_connect *cctx)
{
	ಬಿಡುಗಡೆ(cctx->host);
	ಆದರೆ (cctx->aitop) {
		ಆದರೆ (cctx->aitop->ai_family == AF_UNIX)
			ಬಿಡುಗಡೆ(cctx->aitop);
		ಇಲ್ಲದಿದ್ದರೆ
			freeaddrinfo(cctx->aitop);
	}
	memset(cctx, 0, ಗಾತ್ರ(*cctx));
}

ಸ್ಥಿರ ಶೂನ್ಯ
channel_free_connect_ctx(Channel *c)
{
	ಆದರೆ (c == ಖಾಲಿ || c->connect_ctx == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;
	free_connect_ctx(c->connect_ctx);
	ಬಿಡುಗಡೆ(c->connect_ctx);
	c->connect_ctx = ಖಾಲಿ;
}

/* Enable/disable TCP keepalives for X11 and port-forwarding sockets */
ಶೂನ್ಯ
channel_ಗಣ_tcp_keepalives(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ on)
{
	ssh->chanctxt->want_tcp_keepalive = on;
}

/*
 * Add a timeout for open channels whose c->ctype (or c->xctype if it is set)
 * match type_pattern.
 */
ಶೂನ್ಯ
channel_ಕೂಡಿಸು_timeout(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *type_ನಮೂನೆ,
    ದ್ವಿಗುಣ timeout_secs)
{
	ರಚನೆ ssh_channels *sc = ssh->chanctxt;

	ಆದರೆ (strcmp(type_ನಮೂನೆ, "global") == 0) {
		debug2_f("global channel timeout %f seconds", timeout_secs);
		sc->global_deadline = timeout_secs;
		ಹಿಂತಿರುಗಿ;
	}
	debug2_f("channel type \"%s\" timeout %f seconds",
	    type_ನಮೂನೆ, timeout_secs);
	sc->timeouts = xrecallocarray(sc->timeouts, sc->ntimeouts,
	    sc->ntimeouts + 1, ಗಾತ್ರ(*sc->timeouts));
	sc->timeouts[sc->ntimeouts].type_ನಮೂನೆ = xstrdup(type_ನಮೂನೆ);
	sc->timeouts[sc->ntimeouts].timeout_secs = timeout_secs;
	sc->ntimeouts++;
}

/* Clears all previously-added channel timeouts */
ಶೂನ್ಯ
channel_clear_timeouts(ರಚನೆ ssh *ssh)
{
	ರಚನೆ ssh_channels *sc = ssh->chanctxt;
	ಗಾತ್ರ_t i;

	debug3_f("clearing");
	ಗಾಗಿ (i = 0; i < sc->ntimeouts; i++)
		ಬಿಡುಗಡೆ(sc->timeouts[i].type_ನಮೂನೆ);
	ಬಿಡುಗಡೆ(sc->timeouts);
	sc->timeouts = ಖಾಲಿ;
	sc->ntimeouts = 0;
}

ಸ್ಥಿರ ದ್ವಿಗುಣ
lookup_timeout(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *type)
{
	ರಚನೆ ssh_channels *sc = ssh->chanctxt;
	ಗಾತ್ರ_t i;

	ಗಾಗಿ (i = 0; i < sc->ntimeouts; i++) {
		ಆದರೆ (ಹೊಂದಿಕೆ_ನಮೂನೆ(type, sc->timeouts[i].type_ನಮೂನೆ))
			ಹಿಂತಿರುಗಿ sc->timeouts[i].timeout_secs;
	}

	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಶೂನ್ಯ
channel_classify(ರಚನೆ ssh *ssh, Channel *c)
{
	ರಚನೆ ssh_channels *sc = ssh->chanctxt;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *type = c->xctype == ಖಾಲಿ ? c->ctype : c->xctype;
	ಸ್ಥಿರಾಂಕ ಪೂರ್ಣಾಂಕ has_tty = c->isatty || c->remote_has_tty;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *classifier = has_tty ?
	    sc->bulk_classifier_tty : sc->bulk_classifier_notty;

	c->bulk = type != ಖಾಲಿ && ಹೊಂದಿಕೆ_ನಮೂನೆ_list(type, classifier, 0) == 1;
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
channel_ಗಣ_xtype(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ id, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *xctype)
{
	ರಚನೆ ssh_channels *sc = ssh->chanctxt;
	Channel *c;

	ಆದರೆ ((c = channel_by_id(ssh, id)) == ಖಾಲಿ)
		fatal_f("missing channel %d", id);
	ಆದರೆ (c->xctype != ಖಾಲಿ)
		ಬಿಡುಗಡೆ(c->xctype);
	c->xctype = xstrdup(xctype);
	/* Only override deadline if xctype has a more specific match. */
	ದ್ವಿಗುಣ xtype_deadline = lookup_timeout(ssh, c->xctype);
	ಆದರೆ (xtype_deadline != 0)
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
channel_ಗಣ_ಬಳಸಿದ_ಸಮಯ(ರಚನೆ ssh *ssh, Channel *c)
{
	ssh->chanctxt->lastused = monotime_double();
	ಆದರೆ (c != ಖಾಲಿ)
		c->lastused = ssh->chanctxt->lastused;
}

/*
 * Get the time at which a channel is due to time out for inactivity.
 * Returns 0 if the channel is not due to time out ever.
 */
ಸ್ಥಿರ ದ್ವಿಗುಣ
channel_get_expiry(ರಚನೆ ssh *ssh, Channel *c)
{
	ರಚನೆ ssh_channels *sc = ssh->chanctxt;
	ದ್ವಿಗುಣ expiry = 0, channel_expiry;

	ಆದರೆ (sc->lastused != 0 && sc->global_deadline != 0)
		expiry = sc->lastused + sc->global_deadline;
	ಆದರೆ (c->lastused != 0 && c->inactive_deadline != 0) {
		channel_expiry = c->lastused + c->inactive_deadline;
		ಆದರೆ (expiry == 0 || channel_expiry < expiry)
			expiry = channel_expiry;
	}
	ಹಿಂತಿರುಗಿ expiry;
}

/* Returns non-zero if there is an open, non-interactive channel */
ಪೂರ್ಣಾಂಕ
channel_has_bulk(ರಚನೆ ssh *ssh)
{
	ಹಿಂತಿರುಗಿ ssh->chanctxt != ಖಾಲಿ && ssh->chanctxt->nbulk != 0;
}

/*
 * Register filedescriptors for a channel, used when allocating a channel or
 * when the channel consumer/producer is ready, e.g. shell exec'd
 */
ಸ್ಥಿರ ಶೂನ್ಯ
channel_ರಿಜಿಸ್ಟರ್_fds(ರಚನೆ ssh *ssh, Channel *c, ಪೂರ್ಣಾಂಕ rfd, ಪೂರ್ಣಾಂಕ wfd, ಪೂರ್ಣಾಂಕ efd,
    ಪೂರ್ಣಾಂಕ extusage, ಪೂರ್ಣಾಂಕ nonblock, ಪೂರ್ಣಾಂಕ is_tty)
{
	ಪೂರ್ಣಾಂಕ val;

	ಆದರೆ (rfd != -1)
		(ಶೂನ್ಯ)fcntl(rfd, F_SETFD, FD_CLOEXEC);
	ಆದರೆ (wfd != -1 && wfd != rfd)
		(ಶೂನ್ಯ)fcntl(wfd, F_SETFD, FD_CLOEXEC);
	ಆದರೆ (efd != -1 && efd != rfd && efd != wfd)
		(ಶೂನ್ಯ)fcntl(efd, F_SETFD, FD_CLOEXEC);

	c->rfd = rfd;
	c->wfd = wfd;
	c->sock = (rfd == wfd) ? rfd : -1;
	c->efd = efd;
	c->extended_usage = extusage;

	ಆದರೆ ((c->isatty = is_tty) != 0)
		debug2("channel %d: rfd %d isatty", c->self, c->rfd);
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ _AIX
	/* XXX: Later AIX versions can't push as much data to tty */
	c->wfd_isatty = is_tty || isatty(c->wfd);
#ಆದರೆ_ಅಂತ್ಯ

	/* enable nonblocking mode */
	c->restore_ಖಂಡ = 0;
	ಆದರೆ (nonblock == CHANNEL_NONBLOCK_STDIO) {
		/*
		 * Special handling for stdio file descriptors: do not set
		 * non-blocking mode if they are TTYs. Otherwise prepare to
		 * restore their blocking state on exit to avoid interfering
		 * with other programs that follow.
		 */
		ಆದರೆ (rfd != -1 && !isatty(rfd) &&
		    (val = fcntl(rfd, F_GETFL)) != -1 && !(val & O_NONBLOCK)) {
			c->restore_flags[0] = val;
			c->restore_ಖಂಡ |= CHANNEL_RESTORE_RFD;
			ಗಣ_nonblock(rfd);
		}
		ಆದರೆ (wfd != -1 && !isatty(wfd) &&
		    (val = fcntl(wfd, F_GETFL)) != -1 && !(val & O_NONBLOCK)) {
			c->restore_flags[1] = val;
			c->restore_ಖಂಡ |= CHANNEL_RESTORE_WFD;
			ಗಣ_nonblock(wfd);
		}
		ಆದರೆ (efd != -1 && !isatty(efd) &&
		    (val = fcntl(efd, F_GETFL)) != -1 && !(val & O_NONBLOCK)) {
			c->restore_flags[2] = val;
			c->restore_ಖಂಡ |= CHANNEL_RESTORE_EFD;
			ಗಣ_nonblock(efd);
		}
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (nonblock) {
		ಆದರೆ (rfd != -1)
			ಗಣ_nonblock(rfd);
		ಆದರೆ (wfd != -1)
			ಗಣ_nonblock(wfd);
		ಆದರೆ (efd != -1)
			ಗಣ_nonblock(efd);
	}
	/* channel might be entering a larval state, so reset global timeout */
	channel_ಗಣ_ಬಳಸಿದ_ಸಮಯ(ssh, ಖಾಲಿ);
	channel_classify(ssh, c);
}

/*
 * Allocate a new channel object and set its type and socket.
 */
Channel *
channel_new(ರಚನೆ ssh *ssh, ಅಕ್ಷರ *ctype, ಪೂರ್ಣಾಂಕ type, ಪೂರ್ಣಾಂಕ rfd, ಪೂರ್ಣಾಂಕ wfd, ಪೂರ್ಣಾಂಕ efd,
    u_int ಕಿಟಕಿ, u_int maxpack, ಪೂರ್ಣಾಂಕ extusage, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *remote_name,
    ಪೂರ್ಣಾಂಕ nonblock)
{
	ರಚನೆ ssh_channels *sc = ssh->chanctxt;
	u_int i, ಸಿಕ್ಕಿತು = 0;
	Channel *c;
	ಪೂರ್ಣಾಂಕ r;

	/* Try to find a free slot where to put the new channel. */
	ಗಾಗಿ (i = 0; i < sc->channels_alloc; i++) {
		ಆದರೆ (sc->channels[i] == ಖಾಲಿ) {
			/* Found a free slot. */
			ಸಿಕ್ಕಿತು = i;
			ನಿಲ್ಲಿಸು;
		}
	}
	ಆದರೆ (i >= sc->channels_alloc) {
		/*
		 * There are no free slots. Take last+1 slot and expand
		 * the array.
		 */
		ಸಿಕ್ಕಿತು = sc->channels_alloc;
		ಆದರೆ (sc->channels_alloc > CHANNELS_MAX_CHANNELS)
			fatal_f("internal error: channels_alloc %d too big",
			    sc->channels_alloc);
		sc->channels = xrecallocarray(sc->channels, sc->channels_alloc,
		    sc->channels_alloc + 10, ಗಾತ್ರ(*sc->channels));
		sc->channels_alloc += 10;
		debug2("channel: expanding %d", sc->channels_alloc);
	}
	/* Initialize and return new channel. */
	c = sc->channels[ಸಿಕ್ಕಿತು] = xcalloc(1, ಗಾತ್ರ(Channel));
	ಆದರೆ ((c->ಒಳಹರಿವು = sshbuf_new()) == ಖಾಲಿ ||
	    (c->output = sshbuf_new()) == ಖಾಲಿ ||
	    (c->extended = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	ಆದರೆ ((r = sshbuf_ಗಣ_max_ಗಾತ್ರ(c->ಒಳಹರಿವು, CHAN_ಒಳಹರಿವು_MAX)) != 0)
		fatal_fr(r, "sshbuf_set_max_size");
	c->ostate = CHAN_OUTPUT_OPEN;
	c->istate = CHAN_ಒಳಹರಿವು_OPEN;
	channel_ರಿಜಿಸ್ಟರ್_fds(ssh, c, rfd, wfd, efd, extusage, nonblock, 0);
	c->self = ಸಿಕ್ಕಿತು;
	c->type = type;
	c->ctype = ctype;
	c->local_ಕಿಟಕಿ = ಕಿಟಕಿ;
	c->local_ಕಿಟಕಿ_max = ಕಿಟಕಿ;
	c->local_maxpacket = maxpack;
	c->remote_name = xstrdup(remote_name);
	c->ctl_chan = -1;
	c->delayed = 1;		/* prevent call to channel_post handler */
	c->inactive_deadline = lookup_timeout(ssh, c->ctype);
	TAILQ_INIT(&c->ಸ್ಥಿತಿ_confirms);
	channel_classify(ssh, c);
	debug("channel %d: new %s [%s] (inactive timeout: %f)",
	    ಸಿಕ್ಕಿತು, c->ctype, remote_name, c->inactive_deadline != 0.0 ?
	    c->inactive_deadline : sc->global_deadline);
	ಹಿಂತಿರುಗಿ c;
}

ಶೂನ್ಯ
channel_ಗಣ_tty(ರಚನೆ ssh *ssh, Channel *c)
{
	c->remote_has_tty = 1;
	channel_classify(ssh, c);
}

ಪೂರ್ಣಾಂಕ
channel_close_fd(ರಚನೆ ssh *ssh, Channel *c, ಪೂರ್ಣಾಂಕ *fdp)
{
	ಪೂರ್ಣಾಂಕ ret, fd = *fdp;

	ಆದರೆ (fd == -1)
		ಹಿಂತಿರುಗಿ 0;

	/* restore blocking */
	ಆದರೆ (*fdp == c->rfd &&
	    (c->restore_ಖಂಡ & CHANNEL_RESTORE_RFD) != 0)
		(ಶೂನ್ಯ)fcntl(*fdp, F_SETFL, c->restore_flags[0]);
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (*fdp == c->wfd &&
	    (c->restore_ಖಂಡ & CHANNEL_RESTORE_WFD) != 0)
		(ಶೂನ್ಯ)fcntl(*fdp, F_SETFL, c->restore_flags[1]);
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (*fdp == c->efd &&
	    (c->restore_ಖಂಡ & CHANNEL_RESTORE_EFD) != 0)
		(ಶೂನ್ಯ)fcntl(*fdp, F_SETFL, c->restore_flags[2]);

	ಆದರೆ (*fdp == c->rfd) {
		c->io_want &= ~SSH_CHAN_IO_RFD;
		c->io_ready &= ~SSH_CHAN_IO_RFD;
		c->rfd = -1;
		c->pfds[0] = -1;
	}
	ಆದರೆ (*fdp == c->wfd) {
		c->io_want &= ~SSH_CHAN_IO_WFD;
		c->io_ready &= ~SSH_CHAN_IO_WFD;
		c->wfd = -1;
		c->pfds[1] = -1;
	}
	ಆದರೆ (*fdp == c->efd) {
		c->io_want &= ~SSH_CHAN_IO_EFD;
		c->io_ready &= ~SSH_CHAN_IO_EFD;
		c->efd = -1;
		c->pfds[2] = -1;
	}
	ಆದರೆ (*fdp == c->sock) {
		c->io_want &= ~SSH_CHAN_IO_SOCK;
		c->io_ready &= ~SSH_CHAN_IO_SOCK;
		c->sock = -1;
		c->pfds[3] = -1;
	}

	ret = close(fd);
	*fdp = -1; /* probably redundant */
	ಹಿಂತಿರುಗಿ ret;
}

/* Close all channel fd/socket. */
ಸ್ಥಿರ ಶೂನ್ಯ
channel_close_fds(ರಚನೆ ssh *ssh, Channel *c)
{
	ಪೂರ್ಣಾಂಕ sock = c->sock, rfd = c->rfd, wfd = c->wfd, efd = c->efd;

	channel_close_fd(ssh, c, &c->sock);
	ಆದರೆ (rfd != sock)
		channel_close_fd(ssh, c, &c->rfd);
	ಆದರೆ (wfd != sock && wfd != rfd)
		channel_close_fd(ssh, c, &c->wfd);
	ಆದರೆ (efd != sock && efd != rfd && efd != wfd)
		channel_close_fd(ssh, c, &c->efd);
}

ಸ್ಥಿರ ಶೂನ್ಯ
fwd_perm_clear(ರಚನೆ permission *perm)
{
	ಬಿಡುಗಡೆ(perm->host_ಗಮ್ಯ_connect);
	ಬಿಡುಗಡೆ(perm->listen_host);
	ಬಿಡುಗಡೆ(perm->listen_ಮಾರ್ಗ);
	memset(perm, 0, ಗಾತ್ರ(*perm));
}

/* Returns an printable name for the specified forwarding permission list */
ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *
fwd_ident(ಪೂರ್ಣಾಂಕ who, ಪೂರ್ಣಾಂಕ where)
{
	ಆದರೆ (who == FORWARD_ADM) {
		ಆದರೆ (where == FORWARD_LOCAL)
			ಹಿಂತಿರುಗಿ "admin local";
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (where == FORWARD_REMOTE)
			ಹಿಂತಿರುಗಿ "admin remote";
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (who == FORWARD_USER) {
		ಆದರೆ (where == FORWARD_LOCAL)
			ಹಿಂತಿರುಗಿ "user local";
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (where == FORWARD_REMOTE)
			ಹಿಂತಿರುಗಿ "user remote";
	}
	fatal("Unknown forward permission list %d/%d", who, where);
}

/* Returns the forwarding permission list for the specified direction */
ಸ್ಥಿರ ರಚನೆ permission_ಗಣ *
permission_ಗಣ_get(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ where)
{
	ರಚನೆ ssh_channels *sc = ssh->chanctxt;

	ಆಯ್ಕೆ (where) {
	ಸ್ಥಿತಿ FORWARD_LOCAL:
		ಹಿಂತಿರುಗಿ &sc->local_perms;
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ FORWARD_REMOTE:
		ಹಿಂತಿರುಗಿ &sc->remote_perms;
		ನಿಲ್ಲಿಸು;
	ಪೂರ್ವನಿಯೋಜಿತ:
		fatal_f("invalid forwarding direction %d", where);
	}
}

/* Returns pointers to the specified forwarding list and its element count */
ಸ್ಥಿರ ಶೂನ್ಯ
permission_ಗಣ_get_array(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ who, ಪೂರ್ಣಾಂಕ where,
    ರಚನೆ permission ***permpp, u_int **npermpp)
{
	ರಚನೆ permission_ಗಣ *pset = permission_ಗಣ_get(ssh, where);

	ಆಯ್ಕೆ (who) {
	ಸ್ಥಿತಿ FORWARD_USER:
		*permpp = &pset->permitted_user;
		*npermpp = &pset->ಅಂಕೆ_permitted_user;
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ FORWARD_ADM:
		*permpp = &pset->permitted_admin;
		*npermpp = &pset->ಅಂಕೆ_permitted_admin;
		ನಿಲ್ಲಿಸು;
	ಪೂರ್ವನಿಯೋಜಿತ:
		fatal_f("invalid forwarding client %d", who);
	}
}

/* Adds an entry to the specified forwarding list */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
permission_ಗಣ_ಕೂಡಿಸು(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ who, ಪೂರ್ಣಾಂಕ where,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host_ಗಮ್ಯ_connect, ಪೂರ್ಣಾಂಕ ಪೋರ್ಟ್_ಗಮ್ಯ_connect,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *listen_host, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *listen_ಮಾರ್ಗ, ಪೂರ್ಣಾಂಕ listen_ಪೋರ್ಟ್,
    Channel *downstream)
{
	ರಚನೆ permission **permp;
	u_int n, *npermp;

	permission_ಗಣ_get_array(ssh, who, where, &permp, &npermp);

	ಆದರೆ (*npermp >= ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ)
		fatal_f("%s overflow", fwd_ident(who, where));

	*permp = xrecallocarray(*permp, *npermp, *npermp + 1, ಗಾತ್ರ(**permp));
	n = (*npermp)++;
#ವ್ಯಾಖ್ಯಾನಿಸು MAYBE_DUP(s) ((s == ಖಾಲಿ) ? ಖಾಲಿ : xstrdup(s))
	(*permp)[n].host_ಗಮ್ಯ_connect = MAYBE_DUP(host_ಗಮ್ಯ_connect);
	(*permp)[n].ಪೋರ್ಟ್_ಗಮ್ಯ_connect = ಪೋರ್ಟ್_ಗಮ್ಯ_connect;
	(*permp)[n].listen_host = MAYBE_DUP(listen_host);
	(*permp)[n].listen_ಮಾರ್ಗ = MAYBE_DUP(listen_ಮಾರ್ಗ);
	(*permp)[n].listen_ಪೋರ್ಟ್ = listen_ಪೋರ್ಟ್;
	(*permp)[n].downstream = downstream;
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು MAYBE_DUP
	ಹಿಂತಿರುಗಿ (ಪೂರ್ಣಾಂಕ)n;
}

ಸ್ಥಿರ ಶೂನ್ಯ
mux_remove_remote_forwardings(ರಚನೆ ssh *ssh, Channel *c)
{
	ರಚನೆ ssh_channels *sc = ssh->chanctxt;
	ರಚನೆ permission_ಗಣ *pset = &sc->local_perms;
	ರಚನೆ permission *perm;
	ಪೂರ್ಣಾಂಕ r;
	u_int i;

	ಗಾಗಿ (i = 0; i < pset->ಅಂಕೆ_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		ಆದರೆ (perm->downstream != c)
			ಮುಂದುವರಿ;

		/* cancel on the server, since mux client is gone */
		debug("channel %d: cleanup remote forward for %s:%u",
		    c->self, perm->listen_host, perm->listen_ಪೋರ್ಟ್);
		ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh, SSH2_ಸಂದೇಶ_GLOBAL_REQUEST)) != 0 ||
		    (r = sshpkt_put_cstring(ssh,
		    "cancel-tcpip-forward")) != 0 ||
		    (r = sshpkt_put_u8(ssh, 0)) != 0 ||
		    (r = sshpkt_put_cstring(ssh,
		    channel_rfwd_bind_host(perm->listen_host))) != 0 ||
		    (r = sshpkt_put_u32(ssh, perm->listen_ಪೋರ್ಟ್)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0) {
			fatal_fr(r, "channel %i", c->self);
		}
		fwd_perm_clear(perm); /* unregister */
	}
}

/* Free the channel and close its fd/socket. */
ಶೂನ್ಯ
channel_free(ರಚನೆ ssh *ssh, Channel *c)
{
	ರಚನೆ ssh_channels *sc = ssh->chanctxt;
	ಅಕ್ಷರ *s;
	u_int i, n;
	Channel *other;
	ರಚನೆ channel_confirm *cc;

	ಗಾಗಿ (n = 0, i = 0; i < sc->channels_alloc; i++) {
		ಆದರೆ ((other = sc->channels[i]) == ಖಾಲಿ)
			ಮುಂದುವರಿ;
		n++;
		/* detach from mux client and prepare for closing */
		ಆದರೆ (c->type == SSH_CHANNEL_MUX_CLIENT &&
		    other->type == SSH_CHANNEL_MUX_PROXY &&
		    other->mux_ctx == c) {
			other->mux_ctx = ಖಾಲಿ;
			other->type = SSH_CHANNEL_OPEN;
			other->istate = CHAN_ಒಳಹರಿವು_CLOSED;
			other->ostate = CHAN_OUTPUT_CLOSED;
		}
	}
	debug("channel %d: free: %s, nchannels %u", c->self,
	    c->remote_name ? c->remote_name : "???", n);

	ಆದರೆ (c->type == SSH_CHANNEL_MUX_CLIENT) {
		mux_remove_remote_forwardings(ssh, c);
		ಬಿಡುಗಡೆ(c->mux_ctx);
		c->mux_ctx = ಖಾಲಿ;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (c->type == SSH_CHANNEL_MUX_LISTENER) {
		ಬಿಡುಗಡೆ(c->mux_ctx);
		c->mux_ctx = ಖಾಲಿ;
	}

	ಆದರೆ (log_level_get() >= SYSLOG_LEVEL_DEBUG3) {
		s = channel_open_ಸಂದೇಶ(ssh);
		debug3("channel %d: status: %s", c->self, s);
		ಬಿಡುಗಡೆ(s);
	}

	channel_close_fds(ssh, c);
	sshbuf_free(c->ಒಳಹರಿವು);
	sshbuf_free(c->output);
	sshbuf_free(c->extended);
	c->ಒಳಹರಿವು = c->output = c->extended = ಖಾಲಿ;
	ಬಿಡುಗಡೆ(c->remote_name);
	c->remote_name = ಖಾಲಿ;
	ಬಿಡುಗಡೆ(c->ಮಾರ್ಗ);
	c->ಮಾರ್ಗ = ಖಾಲಿ;
	ಬಿಡುಗಡೆ(c->listening_addr);
	c->listening_addr = ಖಾಲಿ;
	ಬಿಡುಗಡೆ(c->xctype);
	c->xctype = ಖಾಲಿ;
	channel_free_connect_ctx(c);
	ಆಗ ((cc = TAILQ_FIRST(&c->ಸ್ಥಿತಿ_confirms)) != ಖಾಲಿ) {
		ಆದರೆ (cc->abandon_cb != ಖಾಲಿ)
			cc->abandon_cb(ssh, c, cc->ctx);
		TAILQ_REMOVE(&c->ಸ್ಥಿತಿ_confirms, cc, ನಮೂದು);
		freezero(cc, ಗಾತ್ರ(*cc));
	}
	ಆದರೆ (c->filter_cleanup != ಖಾಲಿ && c->filter_ctx != ಖಾಲಿ)
		c->filter_cleanup(ssh, c->self, c->filter_ctx);
	sc->channels[c->self] = ಖಾಲಿ;
	freezero(c, ಗಾತ್ರ(*c));
}

ಶೂನ್ಯ
channel_free_all(ರಚನೆ ssh *ssh)
{
	u_int i;
	ರಚನೆ ssh_channels *sc = ssh->chanctxt;

	ಗಾಗಿ (i = 0; i < sc->channels_alloc; i++)
		ಆದರೆ (sc->channels[i] != ಖಾಲಿ)
			channel_free(ssh, sc->channels[i]);

	ಬಿಡುಗಡೆ(sc->channels);
	sc->channels = ಖಾಲಿ;
	sc->channels_alloc = 0;

	ಬಿಡುಗಡೆ(sc->x11_saved_display);
	sc->x11_saved_display = ಖಾಲಿ;

	ಬಿಡುಗಡೆ(sc->x11_saved_proto);
	sc->x11_saved_proto = ಖಾಲಿ;

	ಬಿಡುಗಡೆ(sc->x11_saved_ದತ್ತಾಂಶ);
	sc->x11_saved_ದತ್ತಾಂಶ = ಖಾಲಿ;
	sc->x11_saved_ದತ್ತಾಂಶ_len = 0;

	ಬಿಡುಗಡೆ(sc->x11_fake_ದತ್ತಾಂಶ);
	sc->x11_fake_ದತ್ತಾಂಶ = ಖಾಲಿ;
	sc->x11_fake_ದತ್ತಾಂಶ_len = 0;
}

ಶೂನ್ಯ
channel_free_channels(ರಚನೆ ssh *ssh)
{
	ರಚನೆ ssh_channels *sc;

	ಆದರೆ (ssh == ಖಾಲಿ || ssh->chanctxt == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;
	channel_free_all(ssh);
	channel_clear_permission(ssh, FORWARD_USER, FORWARD_LOCAL);
	channel_clear_permission(ssh, FORWARD_USER, FORWARD_REMOTE);
	channel_clear_permission(ssh, FORWARD_ADM, FORWARD_LOCAL);
	channel_clear_permission(ssh, FORWARD_ADM, FORWARD_REMOTE);
	sc = ssh->chanctxt;
	ಬಿಡುಗಡೆ(sc->bulk_classifier_tty);
	ಬಿಡುಗಡೆ(sc->bulk_classifier_notty);
	ಬಿಡುಗಡೆ(sc->channel_pre);
	ಬಿಡುಗಡೆ(sc->channel_post);
	freezero(sc, ಗಾತ್ರ(*sc));
	ssh->chanctxt = ಖಾಲಿ;
}

/*
 * Closes the sockets/fds of all channels.  This is used to close extra file
 * descriptors after a fork.
 */
ಶೂನ್ಯ
channel_close_all(ರಚನೆ ssh *ssh)
{
	u_int i;

	ಗಾಗಿ (i = 0; i < ssh->chanctxt->channels_alloc; i++)
		ಆದರೆ (ssh->chanctxt->channels[i] != ಖಾಲಿ)
			channel_close_fds(ssh, ssh->chanctxt->channels[i]);
}

/*
 * Stop listening to channels.
 */
ಶೂನ್ಯ
channel_stop_listening(ರಚನೆ ssh *ssh)
{
	u_int i;
	Channel *c;

	ಗಾಗಿ (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		ಆದರೆ (c != ಖಾಲಿ) {
			ಆಯ್ಕೆ (c->type) {
			ಸ್ಥಿತಿ SSH_CHANNEL_AUTH_SOCKET:
			ಸ್ಥಿತಿ SSH_CHANNEL_ಪೋರ್ಟ್_LISTENER:
			ಸ್ಥಿತಿ SSH_CHANNEL_RPORT_LISTENER:
			ಸ್ಥಿತಿ SSH_CHANNEL_X11_LISTENER:
			ಸ್ಥಿತಿ SSH_CHANNEL_UNIX_LISTENER:
			ಸ್ಥಿತಿ SSH_CHANNEL_RUNIX_LISTENER:
				channel_close_fd(ssh, c, &c->sock);
				channel_free(ssh, c);
				ನಿಲ್ಲಿಸು;
			}
		}
	}
}

/*
 * Returns true if no channel has too much buffered data, and false if one or
 * more channel is overfull.
 */
ಪೂರ್ಣಾಂಕ
channel_not_very_much_buffered_ದತ್ತಾಂಶ(ರಚನೆ ssh *ssh)
{
	u_int i;
	u_int maxsize = ssh_packet_get_maxsize(ssh);
	Channel *c;

	ಗಾಗಿ (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		ಆದರೆ (c == ಖಾಲಿ || c->type != SSH_CHANNEL_OPEN)
			ಮುಂದುವರಿ;
		ಆದರೆ (sshbuf_len(c->output) > maxsize) {
			debug2("channel %d: big output buffer %zu > %u",
			    c->self, sshbuf_len(c->output), maxsize);
			ಹಿಂತಿರುಗಿ 0;
		}
	}
	ಹಿಂತಿರುಗಿ 1;
}

/* Returns true if any channel is still open. */
ಪೂರ್ಣಾಂಕ
channel_still_open(ರಚನೆ ssh *ssh)
{
	u_int i;
	Channel *c;

	ಗಾಗಿ (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		ಆದರೆ (c == ಖಾಲಿ)
			ಮುಂದುವರಿ;
		ಆಯ್ಕೆ (c->type) {
		ಸ್ಥಿತಿ SSH_CHANNEL_X11_LISTENER:
		ಸ್ಥಿತಿ SSH_CHANNEL_ಪೋರ್ಟ್_LISTENER:
		ಸ್ಥಿತಿ SSH_CHANNEL_RPORT_LISTENER:
		ಸ್ಥಿತಿ SSH_CHANNEL_MUX_LISTENER:
		ಸ್ಥಿತಿ SSH_CHANNEL_CLOSED:
		ಸ್ಥಿತಿ SSH_CHANNEL_AUTH_SOCKET:
		ಸ್ಥಿತಿ SSH_CHANNEL_DYNAMIC:
		ಸ್ಥಿತಿ SSH_CHANNEL_RDYNAMIC_OPEN:
		ಸ್ಥಿತಿ SSH_CHANNEL_CONNECTING:
		ಸ್ಥಿತಿ SSH_CHANNEL_ZOMBIE:
		ಸ್ಥಿತಿ SSH_CHANNEL_ABANDONED:
		ಸ್ಥಿತಿ SSH_CHANNEL_UNIX_LISTENER:
		ಸ್ಥಿತಿ SSH_CHANNEL_RUNIX_LISTENER:
			ಮುಂದುವರಿ;
		ಸ್ಥಿತಿ SSH_CHANNEL_LARVAL:
			ಮುಂದುವರಿ;
		ಸ್ಥಿತಿ SSH_CHANNEL_OPENING:
		ಸ್ಥಿತಿ SSH_CHANNEL_OPEN:
		ಸ್ಥಿತಿ SSH_CHANNEL_RDYNAMIC_ಮುಕ್ತಾಯ:
		ಸ್ಥಿತಿ SSH_CHANNEL_X11_OPEN:
		ಸ್ಥಿತಿ SSH_CHANNEL_MUX_CLIENT:
		ಸ್ಥಿತಿ SSH_CHANNEL_MUX_PROXY:
			ಹಿಂತಿರುಗಿ 1;
		ಪೂರ್ವನಿಯೋಜಿತ:
			fatal_f("bad channel type %d", c->type);
			/* NOTREACHED */
		}
	}
	ಹಿಂತಿರುಗಿ 0;
}

/* Returns true if a channel with a TTY is open. */
ಪೂರ್ಣಾಂಕ
channel_tty_open(ರಚನೆ ssh *ssh)
{
	u_int i;
	Channel *c;

	ಗಾಗಿ (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		ಆದರೆ (c == ಖಾಲಿ || c->type != SSH_CHANNEL_OPEN)
			ಮುಂದುವರಿ;
		ಆದರೆ (c->client_tty)
			ಹಿಂತಿರುಗಿ 1;
	}
	ಹಿಂತಿರುಗಿ 0;
}

/* Returns the id of an open channel suitable for keepaliving */
ಪೂರ್ಣಾಂಕ
channel_ಕಂಡುಹಿಡಿ_open(ರಚನೆ ssh *ssh)
{
	u_int i;
	Channel *c;

	ಗಾಗಿ (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		ಆದರೆ (c == ಖಾಲಿ || !c->have_remote_id)
			ಮುಂದುವರಿ;
		ಆಯ್ಕೆ (c->type) {
		ಸ್ಥಿತಿ SSH_CHANNEL_CLOSED:
		ಸ್ಥಿತಿ SSH_CHANNEL_DYNAMIC:
		ಸ್ಥಿತಿ SSH_CHANNEL_RDYNAMIC_OPEN:
		ಸ್ಥಿತಿ SSH_CHANNEL_RDYNAMIC_ಮುಕ್ತಾಯ:
		ಸ್ಥಿತಿ SSH_CHANNEL_X11_LISTENER:
		ಸ್ಥಿತಿ SSH_CHANNEL_ಪೋರ್ಟ್_LISTENER:
		ಸ್ಥಿತಿ SSH_CHANNEL_RPORT_LISTENER:
		ಸ್ಥಿತಿ SSH_CHANNEL_MUX_LISTENER:
		ಸ್ಥಿತಿ SSH_CHANNEL_MUX_CLIENT:
		ಸ್ಥಿತಿ SSH_CHANNEL_MUX_PROXY:
		ಸ್ಥಿತಿ SSH_CHANNEL_OPENING:
		ಸ್ಥಿತಿ SSH_CHANNEL_CONNECTING:
		ಸ್ಥಿತಿ SSH_CHANNEL_ZOMBIE:
		ಸ್ಥಿತಿ SSH_CHANNEL_ABANDONED:
		ಸ್ಥಿತಿ SSH_CHANNEL_UNIX_LISTENER:
		ಸ್ಥಿತಿ SSH_CHANNEL_RUNIX_LISTENER:
			ಮುಂದುವರಿ;
		ಸ್ಥಿತಿ SSH_CHANNEL_LARVAL:
		ಸ್ಥಿತಿ SSH_CHANNEL_AUTH_SOCKET:
		ಸ್ಥಿತಿ SSH_CHANNEL_OPEN:
		ಸ್ಥಿತಿ SSH_CHANNEL_X11_OPEN:
			ಹಿಂತಿರುಗಿ i;
		ಪೂರ್ವನಿಯೋಜಿತ:
			fatal_f("bad channel type %d", c->type);
			/* NOTREACHED */
		}
	}
	ಹಿಂತಿರುಗಿ -1;
}

/* Returns the state of the channel's extended usage flag */
ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *
channel_format_extended_usage(ಸ್ಥಿರಾಂಕ Channel *c)
{
	ಆದರೆ (c->efd == -1)
		ಹಿಂತಿರುಗಿ "closed";

	ಆಯ್ಕೆ (c->extended_usage) {
	ಸ್ಥಿತಿ CHAN_EXTENDED_WRITE:
		ಹಿಂತಿರುಗಿ "write";
	ಸ್ಥಿತಿ CHAN_EXTENDED_READ:
		ಹಿಂತಿರುಗಿ "read";
	ಸ್ಥಿತಿ CHAN_EXTENDED_IGNORE:
		ಹಿಂತಿರುಗಿ "ignore";
	ಪೂರ್ವನಿಯೋಜಿತ:
		ಹಿಂತಿರುಗಿ "UNKNOWN";
	}
}

ಸ್ಥಿರ ಅಕ್ಷರ *
channel_format_ಸ್ಥಿತಿ(ಸ್ಥಿರಾಂಕ Channel *c)
{
	ಅಕ್ಷರ *ret = ಖಾಲಿ;

	xasprintf(&ret, "t%d [%s] %s%u %s%u i%u/%zu o%u/%zu e[%s]/%zu "
	    "fd %d/%d/%d sock %d cc %d %s%u io 0x%02x/0x%02x %s%s",
	    c->type, c->xctype != ಖಾಲಿ ? c->xctype : c->ctype,
	    c->have_remote_id ? "r" : "nr", c->remote_id,
	    c->mux_ctx != ಖಾಲಿ ? "m" : "nm", c->mux_downstream_id,
	    c->istate, sshbuf_len(c->ಒಳಹರಿವು),
	    c->ostate, sshbuf_len(c->output),
	    channel_format_extended_usage(c), sshbuf_len(c->extended),
	    c->rfd, c->wfd, c->efd, c->sock, c->ctl_chan,
	    c->have_ctl_ಮಗು_id ? "c" : "nc", c->ctl_ಮಗು_id,
	    c->io_want, c->io_ready,
	    c->isatty ? "T" : (c->remote_has_tty ? "RT" : ""),
	    c->bulk ? "B" : "I");
	ಹಿಂತಿರುಗಿ ret;
}

/*
 * Returns a message describing the currently open forwarded connections,
 * suitable for sending to the client.  The message contains crlf pairs for
 * newlines.
 */
ಅಕ್ಷರ *
channel_open_ಸಂದೇಶ(ರಚನೆ ssh *ssh)
{
	ರಚನೆ sshbuf *buf;
	Channel *c;
	u_int i;
	ಪೂರ್ಣಾಂಕ r;
	ಅಕ್ಷರ *cp, *ret;

	ಆದರೆ ((buf = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new");
	ಆದರೆ ((r = sshbuf_putf(buf,
	    "The following connections are open:\r\n")) != 0)
		fatal_fr(r, "sshbuf_putf");
	ಗಾಗಿ (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		ಆದರೆ (c == ಖಾಲಿ)
			ಮುಂದುವರಿ;
		ಆಯ್ಕೆ (c->type) {
		ಸ್ಥಿತಿ SSH_CHANNEL_X11_LISTENER:
		ಸ್ಥಿತಿ SSH_CHANNEL_ಪೋರ್ಟ್_LISTENER:
		ಸ್ಥಿತಿ SSH_CHANNEL_RPORT_LISTENER:
		ಸ್ಥಿತಿ SSH_CHANNEL_CLOSED:
		ಸ್ಥಿತಿ SSH_CHANNEL_AUTH_SOCKET:
		ಸ್ಥಿತಿ SSH_CHANNEL_ZOMBIE:
		ಸ್ಥಿತಿ SSH_CHANNEL_ABANDONED:
		ಸ್ಥಿತಿ SSH_CHANNEL_MUX_LISTENER:
		ಸ್ಥಿತಿ SSH_CHANNEL_UNIX_LISTENER:
		ಸ್ಥಿತಿ SSH_CHANNEL_RUNIX_LISTENER:
			ಮುಂದುವರಿ;
		ಸ್ಥಿತಿ SSH_CHANNEL_LARVAL:
		ಸ್ಥಿತಿ SSH_CHANNEL_OPENING:
		ಸ್ಥಿತಿ SSH_CHANNEL_CONNECTING:
		ಸ್ಥಿತಿ SSH_CHANNEL_DYNAMIC:
		ಸ್ಥಿತಿ SSH_CHANNEL_RDYNAMIC_OPEN:
		ಸ್ಥಿತಿ SSH_CHANNEL_RDYNAMIC_ಮುಕ್ತಾಯ:
		ಸ್ಥಿತಿ SSH_CHANNEL_OPEN:
		ಸ್ಥಿತಿ SSH_CHANNEL_X11_OPEN:
		ಸ್ಥಿತಿ SSH_CHANNEL_MUX_PROXY:
		ಸ್ಥಿತಿ SSH_CHANNEL_MUX_CLIENT:
			cp = channel_format_ಸ್ಥಿತಿ(c);
			ಆದರೆ ((r = sshbuf_putf(buf, "  #%d %.300s (%s)\r\n",
			    c->self, c->remote_name, cp)) != 0) {
				ಬಿಡುಗಡೆ(cp);
				fatal_fr(r, "sshbuf_putf");
			}
			ಬಿಡುಗಡೆ(cp);
			ಮುಂದುವರಿ;
		ಪೂರ್ವನಿಯೋಜಿತ:
			fatal_f("bad channel type %d", c->type);
			/* NOTREACHED */
		}
	}
	ಆದರೆ ((ret = sshbuf_dup_string(buf)) == ಖಾಲಿ)
		fatal_f("sshbuf_dup_string");
	sshbuf_free(buf);
	ಹಿಂತಿರುಗಿ ret;
}

ಶೂನ್ಯ
channel_report_open(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ level)
{
	ಅಕ್ಷರ *open, *oopen, *cp, ident[256];

	sshpkt_fmt_connection_id(ssh, ident, ಗಾತ್ರ(ident));
	do_log2(level, "Connection: %s (pid %ld)", ident, (ದೀರ್ಘ)getpid());
	open = oopen = channel_open_ಸಂದೇಶ(ssh);
	ಆಗ ((cp = strsep(&open, "\r\n")) != ಖಾಲಿ) {
		ಆದರೆ (*cp != '\0')
			do_log2(level, "%s", cp);
	}
	ಬಿಡುಗಡೆ(oopen);
}

ಸ್ಥಿರ ಶೂನ್ಯ
open_preamble(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *where, Channel *c, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *type)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh, SSH2_ಸಂದೇಶ_CHANNEL_OPEN)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, type)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_ಕಿಟಕಿ)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0) {
		fatal_r(r, "%s: channel %i: open", where, c->self);
	}
}

ಶೂನ್ಯ
channel_send_open(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ id)
{
	Channel *c = channel_lookup(ssh, id);
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (c == ಖಾಲಿ) {
		logit("channel_send_open: %d: bad id", id);
		ಹಿಂತಿರುಗಿ;
	}
	debug2("channel %d: send open", id);
	open_preamble(ssh, __func__, c, c->ctype);
	ಆದರೆ ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i", c->self);
}

ಶೂನ್ಯ
channel_request_ಆರಂಭ(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ id, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *service,
    ಪೂರ್ಣಾಂಕ wantconfirm)
{
	Channel *c = channel_lookup(ssh, id);
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (c == ಖಾಲಿ) {
		logit_f("%d: unknown channel id", id);
		ಹಿಂತಿರುಗಿ;
	}
	ಆದರೆ (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);

	debug2("channel %d: request %s confirm %d", id, service, wantconfirm);
	ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh, SSH2_ಸಂದೇಶ_CHANNEL_REQUEST)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, service)) != 0 ||
	    (r = sshpkt_put_u8(ssh, wantconfirm)) != 0) {
		fatal_fr(r, "channel %i", c->self);
	}
}

ಶೂನ್ಯ
channel_ರಿಜಿಸ್ಟರ್_ಸ್ಥಿತಿ_confirm(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ id,
    channel_confirm_cb *cb, channel_confirm_abandon_cb *abandon_cb, ಶೂನ್ಯ *ctx)
{
	ರಚನೆ channel_confirm *cc;
	Channel *c;

	ಆದರೆ ((c = channel_lookup(ssh, id)) == ಖಾಲಿ)
		fatal_f("%d: bad id", id);

	cc = xcalloc(1, ಗಾತ್ರ(*cc));
	cc->cb = cb;
	cc->abandon_cb = abandon_cb;
	cc->ctx = ctx;
	TAILQ_INSERT_TAIL(&c->ಸ್ಥಿತಿ_confirms, cc, ನಮೂದು);
}

ಶೂನ್ಯ
channel_ರಿಜಿಸ್ಟರ್_open_confirm(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ id,
    channel_open_fn *fn, ಶೂನ್ಯ *ctx)
{
	Channel *c = channel_lookup(ssh, id);

	ಆದರೆ (c == ಖಾಲಿ) {
		logit_f("%d: bad id", id);
		ಹಿಂತಿರುಗಿ;
	}
	c->open_confirm = fn;
	c->open_confirm_ctx = ctx;
}

ಶೂನ್ಯ
channel_ರಿಜಿಸ್ಟರ್_cleanup(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ id,
    channel_callback_fn *fn, ಪೂರ್ಣಾಂಕ do_close)
{
	Channel *c = channel_by_id(ssh, id);

	ಆದರೆ (c == ಖಾಲಿ) {
		logit_f("%d: bad id", id);
		ಹಿಂತಿರುಗಿ;
	}
	c->detach_user = fn;
	c->detach_close = do_close;
}

ಶೂನ್ಯ
channel_cancel_cleanup(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ id)
{
	Channel *c = channel_by_id(ssh, id);

	ಆದರೆ (c == ಖಾಲಿ) {
		logit_f("%d: bad id", id);
		ಹಿಂತಿರುಗಿ;
	}
	c->detach_user = ಖಾಲಿ;
	c->detach_close = 0;
}

ಶೂನ್ಯ
channel_ರಿಜಿಸ್ಟರ್_filter(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ id, channel_infilter_fn *ifn,
    channel_outfilter_fn *ofn, channel_filter_cleanup_fn *cfn, ಶೂನ್ಯ *ctx)
{
	Channel *c = channel_lookup(ssh, id);

	ಆದರೆ (c == ಖಾಲಿ) {
		logit_f("%d: bad id", id);
		ಹಿಂತಿರುಗಿ;
	}
	c->ಒಳಹರಿವು_filter = ifn;
	c->output_filter = ofn;
	c->filter_ctx = ctx;
	c->filter_cleanup = cfn;
}

ಶೂನ್ಯ
channel_ಗಣ_fds(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ id, ಪೂರ್ಣಾಂಕ rfd, ಪೂರ್ಣಾಂಕ wfd, ಪೂರ್ಣಾಂಕ efd,
    ಪೂರ್ಣಾಂಕ extusage, ಪೂರ್ಣಾಂಕ nonblock, ಪೂರ್ಣಾಂಕ is_tty, u_int ಕಿಟಕಿ_max)
{
	Channel *c = channel_lookup(ssh, id);
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (c == ಖಾಲಿ || c->type != SSH_CHANNEL_LARVAL)
		fatal("channel_activate for non-larval channel %d.", id);
	ಆದರೆ (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);

	channel_ರಿಜಿಸ್ಟರ್_fds(ssh, c, rfd, wfd, efd, extusage, nonblock, is_tty);
	c->type = SSH_CHANNEL_OPEN;
	channel_ಗಣ_ಬಳಸಿದ_ಸಮಯ(ssh, c);
	c->local_ಕಿಟಕಿ = c->local_ಕಿಟಕಿ_max = ಕಿಟಕಿ_max;

	ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh, SSH2_ಸಂದೇಶ_CHANNEL_ಕಿಟಕಿ_ADJUST)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_ಕಿಟಕಿ)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i", c->self);
}

ಸ್ಥಿರ ಶೂನ್ಯ
channel_pre_listener(ರಚನೆ ssh *ssh, Channel *c)
{
	c->io_want = SSH_CHAN_IO_SOCK_R;
}

ಸ್ಥಿರ ಶೂನ್ಯ
channel_pre_connecting(ರಚನೆ ssh *ssh, Channel *c)
{
	debug3("channel %d: waiting for connection", c->self);
	c->io_want = SSH_CHAN_IO_SOCK_W;
}

ಸ್ಥಿರ ಶೂನ್ಯ
channel_pre_open(ರಚನೆ ssh *ssh, Channel *c)
{
	c->io_want = 0;
	ಆದರೆ (c->istate == CHAN_ಒಳಹರಿವು_OPEN &&
	    c->remote_ಕಿಟಕಿ > 0 &&
	    sshbuf_len(c->ಒಳಹರಿವು) < c->remote_ಕಿಟಕಿ &&
	    sshbuf_check_reserve(c->ಒಳಹರಿವು, CHAN_RBUF) == 0)
		c->io_want |= SSH_CHAN_IO_RFD;
	ಆದರೆ (c->ostate == CHAN_OUTPUT_OPEN ||
	    c->ostate == CHAN_OUTPUT_WAIT_DRAIN) {
		ಆದರೆ (sshbuf_len(c->output) > 0) {
			c->io_want |= SSH_CHAN_IO_WFD;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (c->ostate == CHAN_OUTPUT_WAIT_DRAIN) {
			ಆದರೆ (CHANNEL_EFD_OUTPUT_ಸಕ್ರಿಯ(c))
				debug2("channel %d: "
				    "obuf_empty delayed efd %d/(%zu)", c->self,
				    c->efd, sshbuf_len(c->extended));
			ಇಲ್ಲದಿದ್ದರೆ
				chan_obuf_ಖಾಲಿಗಳು(ssh, c);
		}
	}
	/** XXX check close conditions, too */
	ಆದರೆ (c->efd != -1 && !(c->istate == CHAN_ಒಳಹರಿವು_CLOSED &&
	    c->ostate == CHAN_OUTPUT_CLOSED)) {
		ಆದರೆ (c->extended_usage == CHAN_EXTENDED_WRITE &&
		    sshbuf_len(c->extended) > 0)
			c->io_want |= SSH_CHAN_IO_EFD_W;
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (c->efd != -1 && !(c->flags & CHAN_EOF_ಕಳುಹಿಸಿದ) &&
		    (c->extended_usage == CHAN_EXTENDED_READ ||
		    c->extended_usage == CHAN_EXTENDED_IGNORE) &&
		    sshbuf_len(c->extended) < c->remote_ಕಿಟಕಿ)
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
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
x11_open_helper(ರಚನೆ ssh *ssh, ರಚನೆ sshbuf *b)
{
	ರಚನೆ ssh_channels *sc = ssh->chanctxt;
	u_char *ucp;
	u_int proto_len, ದತ್ತಾಂಶ_len;

	ಆದರೆ (sc->x11_saved_proto == ಖಾಲಿ) {
		error("X11 forwarding opened before X11 forwarding requested");
		ಹಿಂತಿರುಗಿ -1;
	}

	/* Is this being called after the refusal deadline? */
	ಆದರೆ (sc->x11_refuse_ಸಮಯ != 0.0 &&
	    monotime_double() >= sc->x11_refuse_ಸಮಯ) {
		verbose("Rejected X11 connection after ForwardX11Timeout "
		    "expired");
		ಹಿಂತಿರುಗಿ -1;
	}

	/* Check if the fixed size part of the packet is in buffer. */
	ಆದರೆ (sshbuf_len(b) < 12)
		ಹಿಂತಿರುಗಿ 0;

	/* Parse the lengths of variable-length fields. */
	ucp = sshbuf_mutable_ptr(b);
	ಆದರೆ (ucp[0] == 0x42) {	/* Byte order MSB first. */
		proto_len = 256 * ucp[6] + ucp[7];
		ದತ್ತಾಂಶ_len = 256 * ucp[8] + ucp[9];
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ucp[0] == 0x6c) {	/* Byte order LSB first. */
		proto_len = ucp[6] + 256 * ucp[7];
		ದತ್ತಾಂಶ_len = ucp[8] + 256 * ucp[9];
	} ಇಲ್ಲದಿದ್ದರೆ {
		debug2("Initial X11 packet contains bad byte order byte: 0x%x",
		    ucp[0]);
		ಹಿಂತಿರುಗಿ -1;
	}

	/* Check if the whole packet is in buffer. */
	ಆದರೆ (sshbuf_len(b) <
	    12 + ((proto_len + 3) & ~3) + ((ದತ್ತಾಂಶ_len + 3) & ~3))
		ಹಿಂತಿರುಗಿ 0;

	/* Check if authentication protocol matches. */
	ಆದರೆ (proto_len != ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(sc->x11_saved_proto) ||
	    memcmp(ucp + 12, sc->x11_saved_proto, proto_len) != 0) {
		debug2("X11 connection uses different authentication protocol.");
		ಹಿಂತಿರುಗಿ -1;
	}
	/* Check if authentication data matches our fake data. */
	ಆದರೆ (ದತ್ತಾಂಶ_len != sc->x11_fake_ದತ್ತಾಂಶ_len ||
	    timingsafe_bcmp(ucp + 12 + ((proto_len + 3) & ~3),
		sc->x11_fake_ದತ್ತಾಂಶ, sc->x11_fake_ದತ್ತಾಂಶ_len) != 0) {
		debug2("X11 auth data does not match fake data.");
		ಹಿಂತಿರುಗಿ -1;
	}
	/* Check fake data length */
	ಆದರೆ (sc->x11_fake_ದತ್ತಾಂಶ_len != sc->x11_saved_ದತ್ತಾಂಶ_len) {
		error("X11 fake_data_len %d != saved_data_len %d",
		    sc->x11_fake_ದತ್ತಾಂಶ_len, sc->x11_saved_ದತ್ತಾಂಶ_len);
		ಹಿಂತಿರುಗಿ -1;
	}
	/*
	 * Received authentication protocol and data match
	 * our fake data. Substitute the fake data with real
	 * data.
	 */
	ಸ್ಮರಣೆ_ನಕಲು(ucp + 12 + ((proto_len + 3) & ~3),
	    sc->x11_saved_ದತ್ತಾಂಶ, sc->x11_saved_ದತ್ತಾಂಶ_len);
	ಹಿಂತಿರುಗಿ 1;
}

ಶೂನ್ಯ
channel_force_close(ರಚನೆ ssh *ssh, Channel *c, ಪೂರ್ಣಾಂಕ abandon)
{
	debug3_f("channel %d: forcibly closing", c->self);
	ಆದರೆ (c->istate == CHAN_ಒಳಹರಿವು_OPEN)
		chan_read_failed(ssh, c);
	ಆದರೆ (c->istate == CHAN_ಒಳಹರಿವು_WAIT_DRAIN) {
		sshbuf_reset(c->ಒಳಹರಿವು);
		chan_ibuf_ಖಾಲಿಗಳು(ssh, c);
	}
	ಆದರೆ (c->ostate == CHAN_OUTPUT_OPEN ||
	    c->ostate == CHAN_OUTPUT_WAIT_DRAIN) {
		sshbuf_reset(c->output);
		chan_write_failed(ssh, c);
	}
	ಆದರೆ (c->detach_user)
		c->detach_user(ssh, c->self, 1, ಖಾಲಿ);
	ಆದರೆ (c->efd != -1)
		channel_close_fd(ssh, c, &c->efd);
	ಆದರೆ (abandon)
		c->type = SSH_CHANNEL_ABANDONED;
	/* exempt from inactivity timeouts */
	c->inactive_deadline = 0;
	c->lastused = 0;
}

ಸ್ಥಿರ ಶೂನ್ಯ
channel_pre_x11_open(ರಚನೆ ssh *ssh, Channel *c)
{
	ಪೂರ್ಣಾಂಕ ret = x11_open_helper(ssh, c->output);

	/* c->force_drain = 1; */

	ಆದರೆ (ret == 1) {
		c->type = SSH_CHANNEL_OPEN;
		channel_ಗಣ_ಬಳಸಿದ_ಸಮಯ(ssh, c);
		channel_pre_open(ssh, c);
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ret == -1) {
		logit("X11 connection rejected because of wrong "
		    "authentication.");
		debug2("X11 rejected %d i%d/o%d",
		    c->self, c->istate, c->ostate);
		channel_force_close(ssh, c, 0);
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
channel_pre_mux_client(ರಚನೆ ssh *ssh, Channel *c)
{
	c->io_want = 0;
	ಆದರೆ (c->istate == CHAN_ಒಳಹರಿವು_OPEN && !c->mux_pause &&
	    sshbuf_check_reserve(c->ಒಳಹರಿವು, CHAN_RBUF) == 0)
		c->io_want |= SSH_CHAN_IO_RFD;
	ಆದರೆ (c->istate == CHAN_ಒಳಹರಿವು_WAIT_DRAIN) {
		/* clear buffer immediately (discard any partial packet) */
		sshbuf_reset(c->ಒಳಹರಿವು);
		chan_ibuf_ಖಾಲಿಗಳು(ssh, c);
		/* Start output drain. XXX just kill chan? */
		chan_rcvd_oclose(ssh, c);
	}
	ಆದರೆ (c->ostate == CHAN_OUTPUT_OPEN ||
	    c->ostate == CHAN_OUTPUT_WAIT_DRAIN) {
		ಆದರೆ (sshbuf_len(c->output) > 0)
			c->io_want |= SSH_CHAN_IO_WFD;
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (c->ostate == CHAN_OUTPUT_WAIT_DRAIN)
			chan_obuf_ಖಾಲಿಗಳು(ssh, c);
	}
}

ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಪೂರ್ಣಾಂಕ
socks_decode_error(Channel *c, ಪೂರ್ಣಾಂಕ ಸ್ಥಿತಿ_2, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *func, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಸಂದೇಶ)
{
	ಆದರೆ (ಸ್ಥಿತಿ_2 == SSH_ERR_ಸಂದೇಶ_INCOMPLETE)
		ಹಿಂತಿರುಗಿ 0;
	ಇಲ್ಲದಿದ್ದರೆ {
		debug_r(ಸ್ಥಿತಿ_2, "%s: channel %d: decode %s",
		    func, c->self, ಸಂದೇಶ);
		ಹಿಂತಿರುಗಿ -1;
	}
}

/* try to decode a socks4 header */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
channel_decode_socks4(Channel *c, ರಚನೆ sshbuf *ಒಳಹರಿವು, ರಚನೆ sshbuf *output)
{
	uint8_t socks_ver, socks_cmd, dest_addr[4];
	uint16_t dest_ಪೋರ್ಟ್;
	ಅಕ್ಷರ *user = ಖಾಲಿ, *host = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ success = -1, socks4a = 0, r;
	ರಚನೆ sshbuf *b = ಖಾಲಿ;

	ಆದರೆ (sshbuf_len(ಒಳಹರಿವು) < 9)
		ಹಿಂತಿರುಗಿ 0;

	/* We may not have a complete message, so work on a dup of the buffer */
	ಆದರೆ ((b = sshbuf_fromb(ಒಳಹರಿವು)) == ಖಾಲಿ)
		fatal_f("sshbuf_fromb failed");

	debug2("channel %d: decode socks4", c->self);
	ಆದರೆ ((r = sshbuf_get_u8(b, &socks_ver)) != 0 ||
	    (r = sshbuf_get_u8(b, &socks_cmd)) != 0 ||
	    (r = sshbuf_get_u16(b, &dest_ಪೋರ್ಟ್)) != 0 ||
	    (r = sshbuf_get(b, &dest_addr, ಗಾತ್ರ(dest_addr))) != 0 ||
	    (r = sshbuf_get_nulterminated_string(b, 1024, &user, ಖಾಲಿ)) != 0) {
		success = socks_decode_error(c, r, __func__, "header");
		ಹೋಗು ಹೊರಹೋಗು;
	}

	/* Is this a SOCKS4A request? (indicated by an address of 0.0.0.x) */
	ಆದರೆ (dest_addr[0] == 0 && dest_addr[1] == 0 &&
	    dest_addr[2] == 0 && dest_addr[3] != 0) {
		/* If so, then the hostname follows, also nul-terminated */
		ಆದರೆ ((r = sshbuf_get_nulterminated_string(b, 1024,
		    &host, ಖಾಲಿ)) != 0) {
			success = socks_decode_error(c, r, __func__, "host");
			ಹೋಗು ಹೊರಹೋಗು;
		}
		socks4a = 1;
	} ಇಲ್ಲದಿದ್ದರೆ {
		/* Plain SOCKS4 passes an IPv4 binary address; reconstruct */
		xasprintf(&host, "%d.%d.%d.%d",
		    dest_addr[0], dest_addr[1], dest_addr[2], dest_addr[3]);
	}

	/* We have a complete SOCKS4 message; consume it from input */
	ಆದರೆ ((r = sshbuf_consume_upto_ಮಗು(ಒಳಹರಿವು, b)) != 0)
		fatal_fr(r, "channel %d: consume", c->self);

	/* Handle the request */
	debug2("channel %d: %s: user=\"%s\" command=%d destination=[%s]:%d",
	    c->self, socks4a ? "SOCKS4A" : "SOCKS4", user, (ಪೂರ್ಣಾಂಕ)socks_cmd,
	    host, dest_ಪೋರ್ಟ್);
	ಆದರೆ (socks_cmd != 1) {
		debug("channel %d: cannot handle %s command 0x%02x",
		    c->self, socks4a ? "SOCKS4A" : "SOCKS4", socks_cmd);
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಬಿಡುಗಡೆ(c->ಮಾರ್ಗ);
	c->ಮಾರ್ಗ = host;
	host = ಖಾಲಿ; /* transferred */
	c->host_ಪೋರ್ಟ್ = dest_ಪೋರ್ಟ್;

	/* Reply to the SOCKS4 client */
	ಆದರೆ ((r = sshbuf_put_u8(output, 0)) != 0 ||	/* vn: 0 for reply */
	    (r = sshbuf_put_u8(output, 90)) != 0 ||	/* cd: req granted */
	    (r = sshbuf_put_u16(output, 0)) != 0 ||	/* port: ignored */
	    (r = sshbuf_put_u32(output, ntohl(INADDR_ANY))) != 0) /* ignored */
		fatal_fr(r, "channel %d: compose reply", c->self);

	/* success */
	success = 1;
 ಹೊರಹೋಗು:
	sshbuf_free(b);
	ಬಿಡುಗಡೆ(user);
	ಬಿಡುಗಡೆ(host);
	ಹಿಂತಿರುಗಿ success;
}

/* try to decode a socks5 header */
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_SOCKS5_AUTHDONE	0x1000
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_SOCKS5_NOAUTH	0x00
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_SOCKS5_IPV4		0x01
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_SOCKS5_DOMAIN	0x03
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_SOCKS5_IPV6		0x04
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_SOCKS5_CONNECT	0x01
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_SOCKS5_SUCCESS	0x00

/*
 * Handles SOCKS5 authentication. Note 'b' must be a dup of 'input'
 * Returns 0 on insufficient queued date, 1 on authentication success or
 * -1 on error.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
channel_socks5_check_auth(Channel *c, ರಚನೆ sshbuf *b, ರಚನೆ sshbuf *ಒಳಹರಿವು,
    ರಚನೆ sshbuf *output)
{
	uint8_t socks_ver;
	uint8_t nmethods, ವಿಧಾನ;
	ಪೂರ್ಣಾಂಕ r;
	u_int i, ಸಿಕ್ಕಿತು;

	/* format: ver | nmethods | methods */
	ಆದರೆ ((r = sshbuf_get_u8(b, &socks_ver)) != 0)
		ಹಿಂತಿರುಗಿ socks_decode_error(c, r, __func__, "version");
	ಆದರೆ (socks_ver != 5) /* shouldn't happen; checked by caller^2 */
		fatal_fr(r, "channel %d: internal error: not socks5", c->self);
	ಆದರೆ ((r = sshbuf_get_u8(b, &nmethods)) != 0)
		ಹಿಂತಿರುಗಿ socks_decode_error(c, r, __func__, "methods");
	ಗಾಗಿ (ಸಿಕ್ಕಿತು = i = 0; i < nmethods; i++) {
		ಆದರೆ ((r = sshbuf_get_u8(b, &ವಿಧಾನ)) != 0)
			ಹಿಂತಿರುಗಿ socks_decode_error(c, r, __func__, "method");
		ಆದರೆ (ವಿಧಾನ == SSH_SOCKS5_NOAUTH)
			ಸಿಕ್ಕಿತು = 1;
	}
	ಆದರೆ (!ಸಿಕ್ಕಿತು) {
		debug("channel %d: didn't request SSH_SOCKS5_NOAUTH", c->self);
		ಹಿಂತಿರುಗಿ -1;
	}
	/* Consume completed request */
	ಆದರೆ ((r = sshbuf_consume_upto_ಮಗು(ಒಳಹರಿವು, b)) != 0)
		fatal_fr(r, "channel %d: consume", c->self);

	/* Compose reply: version, method */
	ಆದರೆ ((r = sshbuf_put_u8(output, 0x05)) != 0 ||
	    (r = sshbuf_put_u8(output, SSH_SOCKS5_NOAUTH)) != 0)
		fatal_fr(r, "channel %d: append reply", c->self);
	/* success */
	debug2("channel %d: socks5 auth done", c->self);
	ಹಿಂತಿರುಗಿ 1;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
channel_decode_socks5(Channel *c, ರಚನೆ sshbuf *ಒಳಹರಿವು, ರಚನೆ sshbuf *output)
{
	uint8_t socks_ver, socks_cmd, socks_reserved, socks_atyp, addrlen;
	uint16_t dest_ಪೋರ್ಟ್;
	ಅಕ್ಷರ dest_addr[255+1], ntop[INET6_ADDRSTRLEN];
	u_int af;
	ಪೂರ್ಣಾಂಕ r, success = -1;;
	ರಚನೆ sshbuf *b = ಖಾಲಿ;

	debug2("channel %d: decode socks5 %s", c->self,
	    (c->flags & SSH_SOCKS5_AUTHDONE) ? "request" : "auth");

	/* We may not have a complete message, so work on a dup of the buffer */
	ಆದರೆ ((b = sshbuf_fromb(ಒಳಹರಿವು)) == ಖಾಲಿ)
		fatal_f("sshbuf_fromb failed");

	ಆದರೆ (!(c->flags & SSH_SOCKS5_AUTHDONE)) {
		ಆದರೆ ((r = channel_socks5_check_auth(c, b, ಒಳಹರಿವು, output)) != 1) {
			success = r;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		c->flags |= SSH_SOCKS5_AUTHDONE;
		/* Continue to parse request in case client speculated ahead */
	}

	/* Request messages (auth or connect) always start with the version */
	ಆದರೆ ((r = sshbuf_get_u8(b, &socks_ver)) != 0) {
		success = socks_decode_error(c, r, __func__, "version");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (socks_ver != 5) /* shouldn't happen */
		fatal_fr(r, "channel %d: internal error: not socks5", c->self);

	/* Parse SOCKS5 request header */
	debug2("channel %d: socks5 post auth", c->self);
	ಆದರೆ ((r = sshbuf_get_u8(b, &socks_cmd)) != 0 ||
	    (r = sshbuf_get_u8(b, &socks_reserved)) != 0 ||
	    (r = sshbuf_get_u8(b, &socks_atyp)) != 0) {
		success = socks_decode_error(c, r, __func__, "request header");
		ಹೋಗು ಹೊರಹೋಗು;
	}

	ಆದರೆ (socks_ver != 0x05 ||
	    socks_cmd != SSH_SOCKS5_CONNECT ||
	    socks_reserved != 0x00) {
		debug2("channel %d: only socks5 connect supported", c->self);
		ಹೋಗು ಹೊರಹೋಗು;
	}

	ಆಯ್ಕೆ (socks_atyp) {
	ಸ್ಥಿತಿ SSH_SOCKS5_IPV4:
		addrlen = 4;
		af = AF_INET;
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ SSH_SOCKS5_DOMAIN:
		ಆದರೆ ((r = sshbuf_get_u8(b, &addrlen)) != 0) {
			success = socks_decode_error(c, r, __func__, "addrlen");
			ಹೋಗು ಹೊರಹೋಗು;
		}
		af = -1;
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ SSH_SOCKS5_IPV6:
		addrlen = 16;
		af = AF_INET6;
		ನಿಲ್ಲಿಸು;
	ಪೂರ್ವನಿಯೋಜಿತ:
		debug2("channel %d: bad socks5 atyp %d", c->self, socks_atyp);
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = sshbuf_get(b, &dest_addr, addrlen)) != 0 ||
	    (r = sshbuf_get_u16(b, &dest_ಪೋರ್ಟ್)) != 0) {
		success = socks_decode_error(c, r, __func__, "addr/port");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	dest_addr[addrlen] = '\0';

	/* We have a complete SOCKS5 request; consume it from input */
	ಆದರೆ ((r = sshbuf_consume_upto_ಮಗು(ಒಳಹರಿವು, b)) != 0)
		fatal_fr(r, "channel %d: consume", c->self);

	ಬಿಡುಗಡೆ(c->ಮಾರ್ಗ);
	c->ಮಾರ್ಗ = ಖಾಲಿ;
	ಆದರೆ (socks_atyp == SSH_SOCKS5_DOMAIN)
		c->ಮಾರ್ಗ = xstrdup(dest_addr);
	ಇಲ್ಲದಿದ್ದರೆ {
		ಆದರೆ (inet_ntop(af, dest_addr, ntop, ಗಾತ್ರ(ntop)) == ಖಾಲಿ)
			ಹಿಂತಿರುಗಿ -1;
		c->ಮಾರ್ಗ = xstrdup(ntop);
	}
	c->host_ಪೋರ್ಟ್ = dest_ಪೋರ್ಟ್;

	debug2("channel %d: dynamic request: socks5 host %s port %u command %u",
	    c->self, c->ಮಾರ್ಗ, c->host_ಪೋರ್ಟ್, socks_cmd);

	/*ಉತ್ತರ*/
	ಆದರೆ ((r = sshbuf_put_u8(output, 0x05)) != 0 ||	/*ಆವೃತ್ತಿ*/
	    (r = sshbuf_put_u8(output, SSH_SOCKS5_SUCCESS)) != 0 || /* cmd */
	    (r = sshbuf_put_u8(output, 0)) != 0 ||	/* reserved, ignored */
	    (r = sshbuf_put_u8(output, SSH_SOCKS5_IPV4)) != 0 || /* addrtype */
	    (r = sshbuf_put_u32(output, ntohl(INADDR_ANY))) != 0 || /* addr */
	    (r = sshbuf_put_u16(output, dest_ಪೋರ್ಟ್)) != 0) /*ಪೋರ್ಟ್*/
		fatal_fr(r, "channel %d: append reply", c->self);

	/* success */
	success = 1;
 ಹೊರಹೋಗು:
	sshbuf_free(b);
	ಹಿಂತಿರುಗಿ success;
}

Channel *
channel_connect_stdio_fwd(ರಚನೆ ssh *ssh,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host_ಗಮ್ಯ_connect, ಪೂರ್ಣಾಂಕ ಪೋರ್ಟ್_ಗಮ್ಯ_connect,
    ಪೂರ್ಣಾಂಕ ಒಳ, ಪೂರ್ಣಾಂಕ ಹೊರಹೋಗು, ಪೂರ್ಣಾಂಕ nonblock)
{
	Channel *c;

	debug_f("%s:%d", host_ಗಮ್ಯ_connect, ಪೋರ್ಟ್_ಗಮ್ಯ_connect);

	c = channel_new(ssh, "stdio-forward", SSH_CHANNEL_OPENING, ಒಳ, ಹೊರಹೋಗು,
	    -1, CHAN_TCP_ಕಿಟಕಿ_DEFAULT, CHAN_TCP_PACKET_DEFAULT,
	    0, "stdio-forward", nonblock);

	c->ಮಾರ್ಗ = xstrdup(host_ಗಮ್ಯ_connect);
	c->host_ಪೋರ್ಟ್ = ಪೋರ್ಟ್_ಗಮ್ಯ_connect;
	c->listening_ಪೋರ್ಟ್ = 0;
	c->force_drain = 1;

	channel_ರಿಜಿಸ್ಟರ್_fds(ssh, c, ಒಳ, ಹೊರಹೋಗು, -1, 0, 1, 0);
	ಪೋರ್ಟ್_open_helper(ssh, c, ಪೋರ್ಟ್_ಗಮ್ಯ_connect == ಪೋರ್ಟ್_STREAMLOCAL ?
	    "direct-streamlocal@openssh.com" : "direct-tcpip");

	ಹಿಂತಿರುಗಿ c;
}

/* dynamic port forwarding */
ಸ್ಥಿರ ಶೂನ್ಯ
channel_pre_dynamic(ರಚನೆ ssh *ssh, Channel *c)
{
	u_int have;
	u_char ver;
	ಪೂರ್ಣಾಂಕ r, ret;

	c->io_want = 0;
	have = sshbuf_len(c->ಒಳಹರಿವು);
	debug2("channel %d: pre_dynamic: have %d", c->self, have);
	/* sshbuf_dump(c->input, stderr); */
	/* check if the fixed size part of the packet is in buffer. */
	ಆದರೆ (have < 3) {
		/* need more */
		c->io_want |= SSH_CHAN_IO_RFD;
		ಹಿಂತಿರುಗಿ;
	}
	/* try to guess the protocol */
	ಆದರೆ ((r = sshbuf_peek_u8(c->ಒಳಹರಿವು, 0, &ver)) != 0)
		fatal_fr(r, "sshbuf_peek_u8");
	ಆಯ್ಕೆ (ver) {
	ಸ್ಥಿತಿ 0x04:
		ret = channel_decode_socks4(c, c->ಒಳಹರಿವು, c->output);
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ 0x05:
		ret = channel_decode_socks5(c, c->ಒಳಹರಿವು, c->output);
		ನಿಲ್ಲಿಸು;
	ಪೂರ್ವನಿಯೋಜಿತ:
		debug2_f("channel %d: unknown SOCKS version %u", c->self, ver);
		ret = -1;
		ನಿಲ್ಲಿಸು;
	}
	ಆದರೆ (ret < 0) {
		chan_mark_dead(ssh, c);
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ret == 0) {
		debug2("channel %d: pre_dynamic: need more", c->self);
		/* need more */
		c->io_want |= SSH_CHAN_IO_RFD;
		ಆದರೆ (sshbuf_len(c->output))
			c->io_want |= SSH_CHAN_IO_WFD;
	} ಇಲ್ಲದಿದ್ದರೆ {
		/* switch to the next state */
		c->type = SSH_CHANNEL_OPENING;
		ಪೋರ್ಟ್_open_helper(ssh, c, "direct-tcpip");
	}
}

/* simulate read-error */
ಸ್ಥಿರ ಶೂನ್ಯ
rdynamic_close(ರಚನೆ ssh *ssh, Channel *c)
{
	c->type = SSH_CHANNEL_OPEN;
	channel_force_close(ssh, c, 0);
}

/* reverse dynamic port forwarding */
ಸ್ಥಿರ ಶೂನ್ಯ
channel_before_prepare_io_rdynamic(ರಚನೆ ssh *ssh, Channel *c)
{
	ಸ್ಥಿರಾಂಕ u_char *p;
	u_int have, len;
	ಪೂರ್ಣಾಂಕ r, ret;

	have = sshbuf_len(c->output);
	debug2("channel %d: pre_rdynamic: have %d", c->self, have);
	/* sshbuf_dump(c->output, stderr); */
	/* EOF received */
	ಆದರೆ (c->flags & CHAN_EOF_RCVD) {
		ಆದರೆ ((r = sshbuf_consume(c->output, have)) != 0)
			fatal_fr(r, "channel %d: consume", c->self);
		rdynamic_close(ssh, c);
		ಹಿಂತಿರುಗಿ;
	}
	/* check if the fixed size part of the packet is in buffer. */
	ಆದರೆ (have < 3)
		ಹಿಂತಿರುಗಿ;
	/* try to guess the protocol */
	p = sshbuf_ptr(c->output);
	ಆಯ್ಕೆ (p[0]) {
	ಸ್ಥಿತಿ 0x04:
		/* switch input/output for reverse forwarding */
		ret = channel_decode_socks4(c, c->output, c->ಒಳಹರಿವು);
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ 0x05:
		ret = channel_decode_socks5(c, c->output, c->ಒಳಹರಿವು);
		ನಿಲ್ಲಿಸು;
	ಪೂರ್ವನಿಯೋಜಿತ:
		ret = -1;
		ನಿಲ್ಲಿಸು;
	}
	ಆದರೆ (ret < 0) {
		rdynamic_close(ssh, c);
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ret == 0) {
		debug2("channel %d: pre_rdynamic: need more", c->self);
		/* send socks request to peer */
		len = sshbuf_len(c->ಒಳಹರಿವು);
		ಆದರೆ (len > 0 && len < c->remote_ಕಿಟಕಿ) {
			ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh, SSH2_ಸಂದೇಶ_CHANNEL_ದತ್ತಾಂಶ)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
			    (r = sshpkt_put_stringb(ssh, c->ಒಳಹರಿವು)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0) {
				fatal_fr(r, "channel %i: rdynamic", c->self);
			}
			ಆದರೆ ((r = sshbuf_consume(c->ಒಳಹರಿವು, len)) != 0)
				fatal_fr(r, "channel %d: consume", c->self);
			c->remote_ಕಿಟಕಿ -= len;
		}
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (rdynamic_connect_ಮುಕ್ತಾಯ(ssh, c) < 0) {
		/* the connect failed */
		rdynamic_close(ssh, c);
	}
}

/* This is our fake X11 server socket. */
ಸ್ಥಿರ ಶೂನ್ಯ
channel_post_x11_listener(ರಚನೆ ssh *ssh, Channel *c)
{
	Channel *nc;
	ರಚನೆ sockaddr_storage addr;
	ಪೂರ್ಣಾಂಕ r, newsock, oerrno, remote_ಪೋರ್ಟ್;
	socklen_t addrlen;
	ಅಕ್ಷರ buf[16384], *remote_ipaddr;

	ಆದರೆ ((c->io_ready & SSH_CHAN_IO_SOCK_R) == 0)
		ಹಿಂತಿರುಗಿ;

	debug("X11 connection requested.");
	addrlen = ಗಾತ್ರ(addr);
	newsock = accept(c->sock, (ರಚನೆ sockaddr *)&addr, &addrlen);
	ಆದರೆ (c->single_connection) {
		oerrno = errno;
		debug2("single_connection: closing X11 listener.");
		channel_close_fd(ssh, c, &c->sock);
		chan_mark_dead(ssh, c);
		errno = oerrno;
	}
	ಆದರೆ (newsock == -1) {
		ಆದರೆ (errno != EINTR && errno != EWOULDBLOCK &&
		    errno != ECONNABORTED)
			error("accept: %.100s", strerror(errno));
		ಆದರೆ (errno == EMFILE || errno == ENFILE)
			c->notbefore = monotime_double() + 1.0;
		ಹಿಂತಿರುಗಿ;
	}
	ಗಣ_nodelay(newsock);
	ಆದರೆ (ssh->chanctxt->want_tcp_keepalive)
		ಗಣ_keepalive(newsock); /* logs errors */
	remote_ipaddr = get_peer_ipaddr(newsock);
	remote_ಪೋರ್ಟ್ = get_peer_ಪೋರ್ಟ್(newsock);
	snprintf(buf, ಗಾತ್ರ buf, "X11 connection from %.200s port %d",
	    remote_ipaddr, remote_ಪೋರ್ಟ್);

	nc = channel_new(ssh, "x11-connection",
	    SSH_CHANNEL_OPENING, newsock, newsock, -1,
	    c->local_ಕಿಟಕಿ_max, c->local_maxpacket, 0, buf, 1);
	open_preamble(ssh, __func__, nc, "x11");
	ಆದರೆ ((r = sshpkt_put_cstring(ssh, remote_ipaddr)) != 0 ||
	    (r = sshpkt_put_u32(ssh, remote_ಪೋರ್ಟ್)) != 0) {
		fatal_fr(r, "channel %i: reply", c->self);
	}
	ಆದರೆ ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i: send", c->self);
	ಬಿಡುಗಡೆ(remote_ipaddr);
}

ಸ್ಥಿರ ಶೂನ್ಯ
ಪೋರ್ಟ್_open_helper(ರಚನೆ ssh *ssh, Channel *c, ಅಕ್ಷರ *rtype)
{
	ಅಕ್ಷರ *local_ipaddr = get_local_ipaddr(c->sock);
	ಪೂರ್ಣಾಂಕ local_ಪೋರ್ಟ್ = c->sock == -1 ? 65536 : get_local_ಪೋರ್ಟ್(c->sock);
	ಅಕ್ಷರ *remote_ipaddr = get_peer_ipaddr(c->sock);
	ಪೂರ್ಣಾಂಕ remote_ಪೋರ್ಟ್ = get_peer_ಪೋರ್ಟ್(c->sock);
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (remote_ಪೋರ್ಟ್ == -1) {
		/* Fake addr/port to appease peers that validate it (Tectia) */
		ಬಿಡುಗಡೆ(remote_ipaddr);
		remote_ipaddr = xstrdup("127.0.0.1");
		remote_ಪೋರ್ಟ್ = 65535;
	}

	ಬಿಡುಗಡೆ(c->remote_name);
	xasprintf(&c->remote_name,
	    "%s: listening port %d for %.100s port %d, "
	    "connect from %.200s port %d to %.100s port %d",
	    rtype, c->listening_ಪೋರ್ಟ್, c->ಮಾರ್ಗ, c->host_ಪೋರ್ಟ್,
	    remote_ipaddr, remote_ಪೋರ್ಟ್, local_ipaddr, local_ಪೋರ್ಟ್);

	open_preamble(ssh, __func__, c, rtype);
	ಆದರೆ (strcmp(rtype, "direct-tcpip") == 0) {
		/* target host, port */
		ಆದರೆ ((r = sshpkt_put_cstring(ssh, c->ಮಾರ್ಗ)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->host_ಪೋರ್ಟ್)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(rtype, "direct-streamlocal@openssh.com") == 0) {
		/* target path */
		ಆದರೆ ((r = sshpkt_put_cstring(ssh, c->ಮಾರ್ಗ)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(rtype, "forwarded-streamlocal@openssh.com") == 0) {
		/* listen path */
		ಆದರೆ ((r = sshpkt_put_cstring(ssh, c->ಮಾರ್ಗ)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	} ಇಲ್ಲದಿದ್ದರೆ {
		/* listen address, port */
		ಆದರೆ ((r = sshpkt_put_cstring(ssh, c->ಮಾರ್ಗ)) != 0 ||
		    (r = sshpkt_put_u32(ssh, local_ಪೋರ್ಟ್)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	}
	ಆದರೆ (strcmp(rtype, "forwarded-streamlocal@openssh.com") == 0) {
		/* reserved for future owner/mode info */
		ಆದರೆ ((r = sshpkt_put_cstring(ssh, "")) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	} ಇಲ್ಲದಿದ್ದರೆ {
		/* originator host and port */
		ಆದರೆ ((r = sshpkt_put_cstring(ssh, remote_ipaddr)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)remote_ಪೋರ್ಟ್)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	}
	ಆದರೆ ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i: send", c->self);
	ಬಿಡುಗಡೆ(remote_ipaddr);
	ಬಿಡುಗಡೆ(local_ipaddr);
}

ಶೂನ್ಯ
channel_ಗಣ_x11_refuse_ಸಮಯ(ರಚನೆ ssh *ssh, ದ್ವಿಗುಣ refuse_ಸಮಯ)
{
	ssh->chanctxt->x11_refuse_ಸಮಯ = refuse_ಸಮಯ;
}

/*
 * This socket is listening for connections to a forwarded TCP/IP port.
 */
ಸ್ಥಿರ ಶೂನ್ಯ
channel_post_ಪೋರ್ಟ್_listener(ರಚನೆ ssh *ssh, Channel *c)
{
	Channel *nc;
	ರಚನೆ sockaddr_storage addr;
	ಪೂರ್ಣಾಂಕ newsock, nextstate;
	socklen_t addrlen;
	ಅಕ್ಷರ *rtype;

	ಆದರೆ ((c->io_ready & SSH_CHAN_IO_SOCK_R) == 0)
		ಹಿಂತಿರುಗಿ;

	debug("Connection to port %d forwarding to %.100s port %d requested.",
	    c->listening_ಪೋರ್ಟ್, c->ಮಾರ್ಗ, c->host_ಪೋರ್ಟ್);

	ಆದರೆ (c->type == SSH_CHANNEL_RPORT_LISTENER) {
		nextstate = SSH_CHANNEL_OPENING;
		rtype = "forwarded-tcpip";
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (c->type == SSH_CHANNEL_RUNIX_LISTENER) {
		nextstate = SSH_CHANNEL_OPENING;
		rtype = "forwarded-streamlocal@openssh.com";
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (c->host_ಪೋರ್ಟ್ == ಪೋರ್ಟ್_STREAMLOCAL) {
		nextstate = SSH_CHANNEL_OPENING;
		rtype = "direct-streamlocal@openssh.com";
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (c->host_ಪೋರ್ಟ್ == 0) {
		nextstate = SSH_CHANNEL_DYNAMIC;
		rtype = "dynamic-tcpip";
	} ಇಲ್ಲದಿದ್ದರೆ {
		nextstate = SSH_CHANNEL_OPENING;
		rtype = "direct-tcpip";
	}

	addrlen = ಗಾತ್ರ(addr);
	newsock = accept(c->sock, (ರಚನೆ sockaddr *)&addr, &addrlen);
	ಆದರೆ (newsock == -1) {
		ಆದರೆ (errno != EINTR && errno != EWOULDBLOCK &&
		    errno != ECONNABORTED)
			error("accept: %.100s", strerror(errno));
		ಆದರೆ (errno == EMFILE || errno == ENFILE)
			c->notbefore = monotime_double() + 1.0;
		ಹಿಂತಿರುಗಿ;
	}
	ಆದರೆ (addr.ss_family == AF_INET || addr.ss_family == AF_INET6) {
		ಗಣ_nodelay(newsock);
		ಆದರೆ (ssh->chanctxt->want_tcp_keepalive)
			ಗಣ_keepalive(newsock); /* logs errors */
	}
	nc = channel_new(ssh, rtype, nextstate, newsock, newsock, -1,
	    c->local_ಕಿಟಕಿ_max, c->local_maxpacket, 0, rtype, 1);
	nc->listening_ಪೋರ್ಟ್ = c->listening_ಪೋರ್ಟ್;
	nc->host_ಪೋರ್ಟ್ = c->host_ಪೋರ್ಟ್;
	ಆದರೆ (c->ಮಾರ್ಗ != ಖಾಲಿ)
		nc->ಮಾರ್ಗ = xstrdup(c->ಮಾರ್ಗ);

	ಆದರೆ (nextstate != SSH_CHANNEL_DYNAMIC)
		ಪೋರ್ಟ್_open_helper(ssh, nc, rtype);
}

/*
 * This is the authentication agent socket listening for connections from
 * clients.
 */
ಸ್ಥಿರ ಶೂನ್ಯ
channel_post_auth_listener(ರಚನೆ ssh *ssh, Channel *c)
{
	Channel *nc;
	ಪೂರ್ಣಾಂಕ r, newsock;
	ರಚನೆ sockaddr_storage addr;
	socklen_t addrlen;

	ಆದರೆ ((c->io_ready & SSH_CHAN_IO_SOCK_R) == 0)
		ಹಿಂತಿರುಗಿ;

	addrlen = ಗಾತ್ರ(addr);
	newsock = accept(c->sock, (ರಚನೆ sockaddr *)&addr, &addrlen);
	ಆದರೆ (newsock == -1) {
		error("accept from auth socket: %.100s", strerror(errno));
		ಆದರೆ (errno == EMFILE || errno == ENFILE)
			c->notbefore = monotime_double() + 1.0;
		ಹಿಂತಿರುಗಿ;
	}
	nc = channel_new(ssh, "agent-connection",
	    SSH_CHANNEL_OPENING, newsock, newsock, -1,
	    c->local_ಕಿಟಕಿ_max, c->local_maxpacket,
	    0, "accepted auth socket", 1);
	open_preamble(ssh, __func__, nc,
	    c->agent_new ? "agent-connect" : "auth-agent@openssh.com");
	ಆದರೆ ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i", c->self);
}

ಸ್ಥಿರ ಶೂನ್ಯ
channel_post_connecting(ರಚನೆ ssh *ssh, Channel *c)
{
	ಪೂರ್ಣಾಂಕ err = 0, sock, isopen, r;
	socklen_t sz = ಗಾತ್ರ(err);

	ಆದರೆ ((c->io_ready & SSH_CHAN_IO_SOCK_W) == 0)
		ಹಿಂತಿರುಗಿ;
	ಆದರೆ (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);
	ಆದರೆ (c->connect_ctx == ಖಾಲಿ)
		fatal_f("channel %d: context missing", c->self);

	/* for rdynamic the OPEN_CONFIRMATION has been sent already */
	isopen = (c->type == SSH_CHANNEL_RDYNAMIC_ಮುಕ್ತಾಯ);

	ಆದರೆ (getsockopt(c->sock, SOL_SOCKET, SO_ERROR, &err, &sz) == -1) {
		err = errno;
		error("getsockopt SO_ERROR failed");
	}

	ಆದರೆ (err == 0) {
		/* Non-blocking connection completed */
		debug("channel %d: connected to %s port %d",
		    c->self, c->connect_ctx->host, c->connect_ctx->ಪೋರ್ಟ್);
		channel_free_connect_ctx(c);
		c->type = SSH_CHANNEL_OPEN;
		channel_ಗಣ_ಬಳಸಿದ_ಸಮಯ(ssh, c);
		ಆದರೆ (isopen) {
			/* no message necessary */
		} ಇಲ್ಲದಿದ್ದರೆ {
			ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh,
			    SSH2_ಸಂದೇಶ_CHANNEL_OPEN_CONFIRMATION)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_ಕಿಟಕಿ)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "channel %i open confirm", c->self);
		}
		ಹಿಂತಿರುಗಿ;
	}
	ಆದರೆ (err == EINTR || err == EAGAIN || err == EINPROGRESS)
		ಹಿಂತಿರುಗಿ;

	/* Non-blocking connection failed */
	debug("channel %d: connection failed: %s", c->self, strerror(err));

	/* Try next address, if any */
	ಆದರೆ ((sock = connect_ಮುಂದಿನ(ssh, c->connect_ctx)) == -1) {
		/* Exhausted all addresses for this destination */
		error("connect_to %.100s port %d: failed.",
		    c->connect_ctx->host, c->connect_ctx->ಪೋರ್ಟ್);
		channel_free_connect_ctx(c);
		ಆದರೆ (isopen) {
			rdynamic_close(ssh, c);
		} ಇಲ್ಲದಿದ್ದರೆ {
			ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh,
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

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
channel_handle_rfd(ರಚನೆ ssh *ssh, Channel *c)
{
	ಅಕ್ಷರ buf[CHAN_RBUF];
	ssize_t len;
	ಪೂರ್ಣಾಂಕ r, force;
	ಗಾತ್ರ_t nr = 0, have, avail, maxlen = CHANNEL_MAX_READ;
	ಪೂರ್ಣಾಂಕ pty_zeroread = 0;

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ PTY_ZEROREAD
	/* Bug on AIX: read(1) can return 0 for a non-closed fd */
	pty_zeroread = c->isatty;
#ಆದರೆ_ಅಂತ್ಯ

	force = c->isatty && c->detach_close && c->istate != CHAN_ಒಳಹರಿವು_CLOSED;

	ಆದರೆ (!force && (c->io_ready & SSH_CHAN_IO_RFD) == 0)
		ಹಿಂತಿರುಗಿ 1;
	ಆದರೆ ((avail = sshbuf_avail(c->ಒಳಹರಿವು)) == 0)
		ಹಿಂತಿರುಗಿ 1; /* Shouldn't happen */

	/*
	 * For "simple" channels (i.e. not datagram or filtered), we can
	 * read directly to the channel buffer.
	 */
	ಆದರೆ (!pty_zeroread && c->ಒಳಹರಿವು_filter == ಖಾಲಿ && !c->datagram) {
		/* Only OPEN channels have valid rwin */
		ಆದರೆ (c->type == SSH_CHANNEL_OPEN) {
			ಆದರೆ ((have = sshbuf_len(c->ಒಳಹರಿವು)) >= c->remote_ಕಿಟಕಿ)
				ಹಿಂತಿರುಗಿ 1; /* shouldn't happen */
			ಆದರೆ (maxlen > c->remote_ಕಿಟಕಿ - have)
				maxlen = c->remote_ಕಿಟಕಿ - have;
		}
		ಆದರೆ (maxlen > avail)
			maxlen = avail;
		ಆದರೆ ((r = sshbuf_read(c->rfd, c->ಒಳಹರಿವು, maxlen, &nr)) != 0) {
			ಆದರೆ (errno == EINTR || (!force &&
			    (errno == EAGAIN || errno == EWOULDBLOCK)))
				ಹಿಂತಿರುಗಿ 1;
			debug2("channel %d: read failed rfd %d maxlen %zu: %s",
			    c->self, c->rfd, maxlen, ssh_err(r));
			ಹೋಗು rfail;
		}
		ಆದರೆ (nr != 0)
			channel_ಗಣ_ಬಳಸಿದ_ಸಮಯ(ssh, c);
		ಹಿಂತಿರುಗಿ 1;
	}

	errno = 0;
	len = ಪಠ(c->rfd, buf, ಗಾತ್ರ(buf));
	/* fixup AIX zero-length read with errno set to look more like errors */
	ಆದರೆ (pty_zeroread && len == 0 && errno != 0)
		len = -1;
	ಆದರೆ (len == -1 && (errno == EINTR ||
	    ((errno == EAGAIN || errno == EWOULDBLOCK) && !force)))
		ಹಿಂತಿರುಗಿ 1;
	ಆದರೆ (len < 0 || (!pty_zeroread && len == 0)) {
		debug2("channel %d: read<=0 rfd %d len %zd: %s",
		    c->self, c->rfd, len,
		    len == 0 ? "closed" : strerror(errno));
 rfail:
		ಆದರೆ (c->type != SSH_CHANNEL_OPEN) {
			debug2("channel %d: not open", c->self);
			chan_mark_dead(ssh, c);
			ಹಿಂತಿರುಗಿ -1;
		} ಇಲ್ಲದಿದ್ದರೆ {
			chan_read_failed(ssh, c);
		}
		ಹಿಂತಿರುಗಿ -1;
	}
	channel_ಗಣ_ಬಳಸಿದ_ಸಮಯ(ssh, c);
	ಆದರೆ (c->ಒಳಹರಿವು_filter != ಖಾಲಿ) {
		ಆದರೆ (c->ಒಳಹರಿವು_filter(ssh, c, buf, len) == -1) {
			debug2("channel %d: filter stops", c->self);
			chan_read_failed(ssh, c);
		}
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (c->datagram) {
		ಆದರೆ ((r = sshbuf_put_string(c->ಒಳಹರಿವು, buf, len)) != 0)
			fatal_fr(r, "channel %i: put datagram", c->self);
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((r = sshbuf_put(c->ಒಳಹರಿವು, buf, len)) != 0)
		fatal_fr(r, "channel %i: put data", c->self);

	ಹಿಂತಿರುಗಿ 1;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
channel_handle_wfd(ರಚನೆ ssh *ssh, Channel *c)
{
	ರಚನೆ termios tio;
	u_char *ದತ್ತಾಂಶ = ಖಾಲಿ, *buf; /* XXX const; need filter API change */
	ಗಾತ್ರ_t dlen, olen = 0;
	ಪೂರ್ಣಾಂಕ r, len;

	ಆದರೆ ((c->io_ready & SSH_CHAN_IO_WFD) == 0)
		ಹಿಂತಿರುಗಿ 1;
	ಆದರೆ (sshbuf_len(c->output) == 0)
		ಹಿಂತಿರುಗಿ 1;

	/* Send buffered output data to the socket. */
	olen = sshbuf_len(c->output);
	ಆದರೆ (c->output_filter != ಖಾಲಿ) {
		ಆದರೆ ((buf = c->output_filter(ssh, c, &ದತ್ತಾಂಶ, &dlen)) == ಖಾಲಿ) {
			debug2("channel %d: filter stops", c->self);
			ಆದರೆ (c->type != SSH_CHANNEL_OPEN)
				chan_mark_dead(ssh, c);
			ಇಲ್ಲದಿದ್ದರೆ
				chan_write_failed(ssh, c);
			ಹಿಂತಿರುಗಿ -1;
		}
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (c->datagram) {
		ಆದರೆ ((r = sshbuf_get_string(c->output, &ದತ್ತಾಂಶ, &dlen)) != 0)
			fatal_fr(r, "channel %i: get datagram", c->self);
		buf = ದತ್ತಾಂಶ;
	} ಇಲ್ಲದಿದ್ದರೆ {
		buf = ದತ್ತಾಂಶ = sshbuf_mutable_ptr(c->output);
		dlen = sshbuf_len(c->output);
	}

	ಆದರೆ (c->datagram) {
		/* ignore truncated writes, datagrams might get lost */
		len = ಲಿಖ(c->wfd, buf, dlen);
		ಬಿಡುಗಡೆ(ದತ್ತಾಂಶ);
		ಆದರೆ (len == -1 && (errno == EINTR || errno == EAGAIN ||
		    errno == EWOULDBLOCK))
			ಹಿಂತಿರುಗಿ 1;
		ಆದರೆ (len <= 0)
			ಹೋಗು write_fail;
		ಹೋಗು ಹೊರಹೋಗು;
	}

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ _AIX
	/* XXX: Later AIX versions can't push as much data to tty */
	ಆದರೆ (c->wfd_isatty)
		dlen = MINIMUM(dlen, 8*1024);
#ಆದರೆ_ಅಂತ್ಯ

	len = ಲಿಖ(c->wfd, buf, dlen);
	ಆದರೆ (len == -1 &&
	    (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
		ಹಿಂತಿರುಗಿ 1;
	ಆದರೆ (len <= 0) {
 write_fail:
		ಆದರೆ (c->type != SSH_CHANNEL_OPEN) {
			debug2("channel %d: not open", c->self);
			chan_mark_dead(ssh, c);
			ಹಿಂತಿರುಗಿ -1;
		} ಇಲ್ಲದಿದ್ದರೆ {
			chan_write_failed(ssh, c);
		}
		ಹಿಂತಿರುಗಿ -1;
	}
	channel_ಗಣ_ಬಳಸಿದ_ಸಮಯ(ssh, c);
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ BROKEN_TCGETATTR_ICANON
	ಆದರೆ (c->isatty && dlen >= 1 && buf[0] != '\r') {
		ಆದರೆ (tcgetattr(c->wfd, &tio) == 0 &&
		    !(tio.c_lflag & ECHO) && (tio.c_lflag & ICANON)) {
			/*
			 * Simulate echo to reduce the impact of
			 * traffic analysis. We need to match the
			 * size of a SSH2_MSG_CHANNEL_DATA message
			 * (4 byte channel id + buf)
			 */
			ಆದರೆ ((r = sshpkt_ಸಂದೇಶ_ignore(ssh, 4+len)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "channel %i: ignore", c->self);
		}
	}
#ಆದರೆ_ಅಂತ್ಯ /* BROKEN_TCGETATTR_ICANON */
	ಆದರೆ ((r = sshbuf_consume(c->output, len)) != 0)
		fatal_fr(r, "channel %i: consume", c->self);
 ಹೊರಹೋಗು:
	c->local_consumed += olen - sshbuf_len(c->output);

	ಹಿಂತಿರುಗಿ 1;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
channel_handle_efd_write(ರಚನೆ ssh *ssh, Channel *c)
{
	ಪೂರ್ಣಾಂಕ r;
	ssize_t len;

	ಆದರೆ ((c->io_ready & SSH_CHAN_IO_EFD_W) == 0)
		ಹಿಂತಿರುಗಿ 1;
	ಆದರೆ (sshbuf_len(c->extended) == 0)
		ಹಿಂತಿರುಗಿ 1;

	len = ಲಿಖ(c->efd, sshbuf_ptr(c->extended),
	    sshbuf_len(c->extended));
	debug2("channel %d: written %zd to efd %d", c->self, len, c->efd);
	ಆದರೆ (len == -1 && (errno == EINTR || errno == EAGAIN ||
	    errno == EWOULDBLOCK))
		ಹಿಂತಿರುಗಿ 1;
	ಆದರೆ (len <= 0) {
		debug2("channel %d: closing write-efd %d", c->self, c->efd);
		channel_close_fd(ssh, c, &c->efd);
	} ಇಲ್ಲದಿದ್ದರೆ {
		ಆದರೆ ((r = sshbuf_consume(c->extended, len)) != 0)
			fatal_fr(r, "channel %i: consume", c->self);
		c->local_consumed += len;
		channel_ಗಣ_ಬಳಸಿದ_ಸಮಯ(ssh, c);
	}
	ಹಿಂತಿರುಗಿ 1;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
channel_handle_efd_read(ರಚನೆ ssh *ssh, Channel *c)
{
	ಅಕ್ಷರ buf[CHAN_RBUF];
	ssize_t len;
	ಪೂರ್ಣಾಂಕ r, force;

	force = c->isatty && c->detach_close && c->istate != CHAN_ಒಳಹರಿವು_CLOSED;

	ಆದರೆ (!force && (c->io_ready & SSH_CHAN_IO_EFD_R) == 0)
		ಹಿಂತಿರುಗಿ 1;

	len = ಪಠ(c->efd, buf, ಗಾತ್ರ(buf));
	debug2("channel %d: read %zd from efd %d", c->self, len, c->efd);
	ಆದರೆ (len == -1 && (errno == EINTR || ((errno == EAGAIN ||
	    errno == EWOULDBLOCK) && !force)))
		ಹಿಂತಿರುಗಿ 1;
	ಆದರೆ (len <= 0) {
		debug2("channel %d: closing read-efd %d", c->self, c->efd);
		channel_close_fd(ssh, c, &c->efd);
		ಹಿಂತಿರುಗಿ 1;
	}
	channel_ಗಣ_ಬಳಸಿದ_ಸಮಯ(ssh, c);
	ಆದರೆ (c->extended_usage == CHAN_EXTENDED_IGNORE)
		debug3("channel %d: discard efd", c->self);
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((r = sshbuf_put(c->extended, buf, len)) != 0)
		fatal_fr(r, "channel %i: append", c->self);
	ಹಿಂತಿರುಗಿ 1;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
channel_handle_efd(ರಚನೆ ssh *ssh, Channel *c)
{
	ಆದರೆ (c->efd == -1)
		ಹಿಂತಿರುಗಿ 1;

	/** XXX handle drain efd, too */

	ಆದರೆ (c->extended_usage == CHAN_EXTENDED_WRITE)
		ಹಿಂತಿರುಗಿ channel_handle_efd_write(ssh, c);
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (c->extended_usage == CHAN_EXTENDED_READ ||
	    c->extended_usage == CHAN_EXTENDED_IGNORE)
		ಹಿಂತಿರುಗಿ channel_handle_efd_read(ssh, c);

	ಹಿಂತಿರುಗಿ 1;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
channel_check_ಕಿಟಕಿ(ರಚನೆ ssh *ssh, Channel *c)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (c->type == SSH_CHANNEL_OPEN &&
	    !(c->flags & (CHAN_CLOSE_ಕಳುಹಿಸಿದ|CHAN_CLOSE_RCVD)) &&
	    ((c->local_ಕಿಟಕಿ_max - c->local_ಕಿಟಕಿ >
	    c->local_maxpacket*3) ||
	    c->local_ಕಿಟಕಿ < c->local_ಕಿಟಕಿ_max/2) &&
	    c->local_consumed > 0) {
		ಆದರೆ (!c->have_remote_id)
			fatal_f("channel %d: no remote id", c->self);
		ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh,
		    SSH2_ಸಂದೇಶ_CHANNEL_ಕಿಟಕಿ_ADJUST)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->local_consumed)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0) {
			fatal_fr(r, "channel %i", c->self);
		}
		debug2("channel %d: window %d sent adjust %d", c->self,
		    c->local_ಕಿಟಕಿ, c->local_consumed);
		c->local_ಕಿಟಕಿ += c->local_consumed;
		c->local_consumed = 0;
	}
	ಹಿಂತಿರುಗಿ 1;
}

ಸ್ಥಿರ ಶೂನ್ಯ
channel_post_open(ರಚನೆ ssh *ssh, Channel *c)
{
	channel_handle_rfd(ssh, c);
	channel_handle_wfd(ssh, c);
	channel_handle_efd(ssh, c);
	channel_check_ಕಿಟಕಿ(ssh, c);
}

ಸ್ಥಿರ u_int
read_mux(ರಚನೆ ssh *ssh, Channel *c, u_int need)
{
	ಅಕ್ಷರ buf[CHAN_RBUF];
	ssize_t len;
	u_int rlen;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (sshbuf_len(c->ಒಳಹರಿವು) < need) {
		rlen = need - sshbuf_len(c->ಒಳಹರಿವು);
		len = ಪಠ(c->rfd, buf, MINIMUM(rlen, CHAN_RBUF));
		ಆದರೆ (len == -1 && (errno == EINTR || errno == EAGAIN))
			ಹಿಂತಿರುಗಿ sshbuf_len(c->ಒಳಹರಿವು);
		ಆದರೆ (len <= 0) {
			debug2("channel %d: ctl read<=0 rfd %d len %zd",
			    c->self, c->rfd, len);
			chan_read_failed(ssh, c);
			ಹಿಂತಿರುಗಿ 0;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((r = sshbuf_put(c->ಒಳಹರಿವು, buf, len)) != 0)
			fatal_fr(r, "channel %i: append", c->self);
	}
	ಹಿಂತಿರುಗಿ sshbuf_len(c->ಒಳಹರಿವು);
}

ಸ್ಥಿರ ಶೂನ್ಯ
channel_post_mux_client_read(ರಚನೆ ssh *ssh, Channel *c)
{
	u_int need;

	ಆದರೆ ((c->io_ready & SSH_CHAN_IO_RFD) == 0)
		ಹಿಂತಿರುಗಿ;
	ಆದರೆ (c->istate != CHAN_ಒಳಹರಿವು_OPEN && c->istate != CHAN_ಒಳಹರಿವು_WAIT_DRAIN)
		ಹಿಂತಿರುಗಿ;
	ಆದರೆ (c->mux_pause)
		ಹಿಂತಿರುಗಿ;

	/*
	 * Don't not read past the precise end of packets to
	 * avoid disrupting fd passing.
	 */
	ಆದರೆ (read_mux(ssh, c, 4) < 4) /* read header */
		ಹಿಂತಿರುಗಿ;
	/* XXX sshbuf_peek_u32 */
	need = PEEK_U32(sshbuf_ptr(c->ಒಳಹರಿವು));
#ವ್ಯಾಖ್ಯಾನಿಸು CHANNEL_MUX_MAX_PACKET	(256 * 1024)
	ಆದರೆ (need > CHANNEL_MUX_MAX_PACKET) {
		debug2("channel %d: packet too big %u > %u",
		    c->self, CHANNEL_MUX_MAX_PACKET, need);
		chan_rcvd_oclose(ssh, c);
		ಹಿಂತಿರುಗಿ;
	}
	ಆದರೆ (read_mux(ssh, c, need + 4) < need + 4) /* read body */
		ಹಿಂತಿರುಗಿ;
	ಆದರೆ (c->mux_rcb(ssh, c) != 0) {
		debug("channel %d: mux_rcb failed", c->self);
		chan_mark_dead(ssh, c);
		ಹಿಂತಿರುಗಿ;
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
channel_post_mux_client_write(ರಚನೆ ssh *ssh, Channel *c)
{
	ssize_t len;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((c->io_ready & SSH_CHAN_IO_WFD) == 0)
		ಹಿಂತಿರುಗಿ;
	ಆದರೆ (sshbuf_len(c->output) == 0)
		ಹಿಂತಿರುಗಿ;

	len = ಲಿಖ(c->wfd, sshbuf_ptr(c->output), sshbuf_len(c->output));
	ಆದರೆ (len == -1 && (errno == EINTR || errno == EAGAIN))
		ಹಿಂತಿರುಗಿ;
	ಆದರೆ (len <= 0) {
		chan_mark_dead(ssh, c);
		ಹಿಂತಿರುಗಿ;
	}
	ಆದರೆ ((r = sshbuf_consume(c->output, len)) != 0)
		fatal_fr(r, "channel %i: consume", c->self);
}

ಸ್ಥಿರ ಶೂನ್ಯ
channel_post_mux_client(ರಚನೆ ssh *ssh, Channel *c)
{
	channel_post_mux_client_read(ssh, c);
	channel_post_mux_client_write(ssh, c);
}

ಸ್ಥಿರ ಶೂನ್ಯ
channel_post_mux_listener(ರಚನೆ ssh *ssh, Channel *c)
{
	Channel *nc;
	ರಚನೆ sockaddr_storage addr;
	socklen_t addrlen;
	ಪೂರ್ಣಾಂಕ newsock;
	uid_t euid;
	gid_t egid;

	ಆದರೆ ((c->io_ready & SSH_CHAN_IO_SOCK_R) == 0)
		ಹಿಂತಿರುಗಿ;

	debug("multiplexing control connection");

	/*
	 * Accept connection on control socket
	 */
	memset(&addr, 0, ಗಾತ್ರ(addr));
	addrlen = ಗಾತ್ರ(addr);
	ಆದರೆ ((newsock = accept(c->sock, (ರಚನೆ sockaddr*)&addr,
	    &addrlen)) == -1) {
		error_f("accept: %s", strerror(errno));
		ಆದರೆ (errno == EMFILE || errno == ENFILE)
			c->notbefore = monotime_double() + 1.0;
		ಹಿಂತಿರುಗಿ;
	}

	ಆದರೆ (getpeereid(newsock, &euid, &egid) == -1) {
		error_f("getpeereid failed: %s", strerror(errno));
		close(newsock);
		ಹಿಂತಿರುಗಿ;
	}
	ಆದರೆ ((euid != 0) && (getuid() != euid)) {
		error("multiplex uid mismatch: peer euid %u != uid %u",
		    (u_int)euid, (u_int)getuid());
		close(newsock);
		ಹಿಂತಿರುಗಿ;
	}
	nc = channel_new(ssh, "mux-control", SSH_CHANNEL_MUX_CLIENT,
	    newsock, newsock, -1, c->local_ಕಿಟಕಿ_max,
	    c->local_maxpacket, 0, "mux-control", 1);
	nc->mux_rcb = c->mux_rcb;
	debug3_f("new mux channel %d fd %d", nc->self, nc->sock);
	/* establish state */
	nc->mux_rcb(ssh, nc);
	/* mux state transitions must not elicit protocol messages */
	nc->flags |= CHAN_LOCAL;
}

ಸ್ಥಿರ ಶೂನ್ಯ
channel_handler_init(ರಚನೆ ssh_channels *sc)
{
	chan_fn **pre, **post;

	ಆದರೆ ((pre = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(SSH_CHANNEL_MAX_TYPE, ಗಾತ್ರ(*pre))) == ಖಾಲಿ ||
	    (post = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(SSH_CHANNEL_MAX_TYPE, ಗಾತ್ರ(*post))) == ಖಾಲಿ)
		fatal_f("allocation failed");

	pre[SSH_CHANNEL_OPEN] =			&channel_pre_open;
	pre[SSH_CHANNEL_X11_OPEN] =		&channel_pre_x11_open;
	pre[SSH_CHANNEL_ಪೋರ್ಟ್_LISTENER] =	&channel_pre_listener;
	pre[SSH_CHANNEL_RPORT_LISTENER] =	&channel_pre_listener;
	pre[SSH_CHANNEL_UNIX_LISTENER] =	&channel_pre_listener;
	pre[SSH_CHANNEL_RUNIX_LISTENER] =	&channel_pre_listener;
	pre[SSH_CHANNEL_X11_LISTENER] =		&channel_pre_listener;
	pre[SSH_CHANNEL_AUTH_SOCKET] =		&channel_pre_listener;
	pre[SSH_CHANNEL_CONNECTING] =		&channel_pre_connecting;
	pre[SSH_CHANNEL_DYNAMIC] =		&channel_pre_dynamic;
	pre[SSH_CHANNEL_RDYNAMIC_ಮುಕ್ತಾಯ] =	&channel_pre_connecting;
	pre[SSH_CHANNEL_MUX_LISTENER] =		&channel_pre_listener;
	pre[SSH_CHANNEL_MUX_CLIENT] =		&channel_pre_mux_client;

	post[SSH_CHANNEL_OPEN] =		&channel_post_open;
	post[SSH_CHANNEL_ಪೋರ್ಟ್_LISTENER] =	&channel_post_ಪೋರ್ಟ್_listener;
	post[SSH_CHANNEL_RPORT_LISTENER] =	&channel_post_ಪೋರ್ಟ್_listener;
	post[SSH_CHANNEL_UNIX_LISTENER] =	&channel_post_ಪೋರ್ಟ್_listener;
	post[SSH_CHANNEL_RUNIX_LISTENER] =	&channel_post_ಪೋರ್ಟ್_listener;
	post[SSH_CHANNEL_X11_LISTENER] =	&channel_post_x11_listener;
	post[SSH_CHANNEL_AUTH_SOCKET] =		&channel_post_auth_listener;
	post[SSH_CHANNEL_CONNECTING] =		&channel_post_connecting;
	post[SSH_CHANNEL_DYNAMIC] =		&channel_post_open;
	post[SSH_CHANNEL_RDYNAMIC_ಮುಕ್ತಾಯ] =	&channel_post_connecting;
	post[SSH_CHANNEL_MUX_LISTENER] =	&channel_post_mux_listener;
	post[SSH_CHANNEL_MUX_CLIENT] =		&channel_post_mux_client;

	sc->channel_pre = pre;
	sc->channel_post = post;
}

/* gc dead channels */
ಸ್ಥಿರ ಶೂನ್ಯ
channel_garbage_collect(ರಚನೆ ssh *ssh, Channel *c)
{
	ಆದರೆ (c == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;
	ಆದರೆ (c->detach_user != ಖಾಲಿ) {
		ಆದರೆ (!chan_is_dead(ssh, c, c->detach_close))
			ಹಿಂತಿರುಗಿ;

		debug2("channel %d: gc: notify user", c->self);
		c->detach_user(ssh, c->self, 0, ಖಾಲಿ);
		/* if we still have a callback */
		ಆದರೆ (c->detach_user != ಖಾಲಿ)
			ಹಿಂತಿರುಗಿ;
		debug2("channel %d: gc: user detached", c->self);
	}
	ಆದರೆ (!chan_is_dead(ssh, c, 1))
		ಹಿಂತಿರುಗಿ;
	debug2("channel %d: garbage collecting", c->self);
	channel_free(ssh, c);
}

ಎಣಿಕೆ channel_ಕೋಷ್ಟಕ { CHAN_PRE, CHAN_POST };

ಸ್ಥಿರ ಶೂನ್ಯ
channel_handler(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ ಕೋಷ್ಟಕ, ರಚನೆ timespec *timeout)
{
	ರಚನೆ ssh_channels *sc = ssh->chanctxt;
	chan_fn **ftab = ಕೋಷ್ಟಕ == CHAN_PRE ? sc->channel_pre : sc->channel_post;
	u_int i, oalloc;
	Channel *c;
	ದ್ವಿಗುಣ now;

	now = monotime_double();
	ಗಾಗಿ (sc->nbulk = i = 0, oalloc = sc->channels_alloc; i < oalloc; i++) {
		c = sc->channels[i];
		ಆದರೆ (c == ಖಾಲಿ)
			ಮುಂದುವರಿ;
		/* Count open channels in bulk state */
		ಆದರೆ (c->type == SSH_CHANNEL_OPEN && c->bulk)
			sc->nbulk++;
		/* Try to keep IO going while rekeying */
		ಆದರೆ (ssh_packet_is_rekeying(ssh) && c->type != SSH_CHANNEL_OPEN)
			ಮುಂದುವರಿ;
		ಆದರೆ (c->delayed) {
			ಆದರೆ (ಕೋಷ್ಟಕ == CHAN_PRE)
				c->delayed = 0;
			ಇಲ್ಲದಿದ್ದರೆ
				ಮುಂದುವರಿ;
		}
		ಆದರೆ (ftab[c->type] != ಖಾಲಿ) {
			ಆದರೆ (ಕೋಷ್ಟಕ == CHAN_PRE && c->type == SSH_CHANNEL_OPEN &&
			    channel_get_expiry(ssh, c) != 0 &&
			    now >= channel_get_expiry(ssh, c)) {
				/* channel closed for inactivity */
				ದ್ವಿಗುಣ deadline = c->inactive_deadline != 0.0 ?
				    c->inactive_deadline : sc->global_deadline;
				verbose("channel %d: closing after %f seconds "
				    "of inactivity", c->self, deadline);
				channel_force_close(ssh, c, 1);
			} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (c->notbefore <= now) {
				/* Run handlers that are not paused. */
				(*ftab[c->type])(ssh, c);
				/* inactivity timeouts must interrupt poll() */
				ಆದರೆ (timeout != ಖಾಲಿ &&
				    c->type == SSH_CHANNEL_OPEN &&
				    channel_get_expiry(ssh, c) != 0) {
					ptimeout_deadline_monotime_double(timeout,
					    channel_get_expiry(ssh, c));
				}
			} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (timeout != ಖಾಲಿ) {
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
channel_before_prepare_io(ರಚನೆ ssh *ssh)
{
	ರಚನೆ ssh_channels *sc = ssh->chanctxt;
	Channel *c;
	u_int i, oalloc;

	ಗಾಗಿ (i = 0, oalloc = sc->channels_alloc; i < oalloc; i++) {
		c = sc->channels[i];
		ಆದರೆ (c == ಖಾಲಿ)
			ಮುಂದುವರಿ;
		ಆದರೆ (c->type == SSH_CHANNEL_RDYNAMIC_OPEN)
			channel_before_prepare_io_rdynamic(ssh, c);
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
dump_channel_poll(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *func, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *what, Channel *c,
    u_int pollfd_ಸ್ಥಾನಾಂತರ, ರಚನೆ pollfd *pfd)
{
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_CHANNEL_POLL
	debug3("%s: channel %d: %s r%d w%d e%d s%d c->pfds [ %d %d %d %d ] "
	    "io_want 0x%02x io_ready 0x%02x pfd[%u].fd=%d "
	    "pfd.ev 0x%02x pfd.rev 0x%02x", func, c->self, what,
	    c->rfd, c->wfd, c->efd, c->sock,
	    c->pfds[0], c->pfds[1], c->pfds[2], c->pfds[3],
	    c->io_want, c->io_ready,
	    pollfd_ಸ್ಥಾನಾಂತರ, pfd->fd, pfd->events, pfd->revents);
#ಆದರೆ_ಅಂತ್ಯ
}

/* Prepare pollfd entries for a single channel */
ಸ್ಥಿರ ಶೂನ್ಯ
channel_prepare_pollfd(Channel *c, u_int *ಮುಂದಿನ_pollfd,
    ರಚನೆ pollfd *pfd, u_int npfd)
{
	u_int ev, p = *ಮುಂದಿನ_pollfd;

	ಆದರೆ (c == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;
	ಆದರೆ (p + 4 > npfd) {
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
	ಆದರೆ (c->rfd != -1) {
		ev = 0;
		ಆದರೆ ((c->io_want & SSH_CHAN_IO_RFD) != 0)
			ev |= POLLIN;
		/* rfd == wfd */
		ಆದರೆ (c->wfd == c->rfd) {
			ಆದರೆ ((c->io_want & SSH_CHAN_IO_WFD) != 0)
				ev |= POLLOUT;
		}
		/* rfd == efd */
		ಆದರೆ (c->efd == c->rfd) {
			ಆದರೆ ((c->io_want & SSH_CHAN_IO_EFD_R) != 0)
				ev |= POLLIN;
			ಆದರೆ ((c->io_want & SSH_CHAN_IO_EFD_W) != 0)
				ev |= POLLOUT;
		}
		/* rfd == sock */
		ಆದರೆ (c->sock == c->rfd) {
			ಆದರೆ ((c->io_want & SSH_CHAN_IO_SOCK_R) != 0)
				ev |= POLLIN;
			ಆದರೆ ((c->io_want & SSH_CHAN_IO_SOCK_W) != 0)
				ev |= POLLOUT;
		}
		/* Pack a pfd entry if any event armed for this fd */
		ಆದರೆ (ev != 0) {
			c->pfds[0] = p;
			pfd[p].fd = c->rfd;
			pfd[p].events = ev;
			dump_channel_poll(__func__, "rfd", c, p, &pfd[p]);
			p++;
		}
	}
	/* prepare c->wfd if wanting IO and not already handled above */
	ಆದರೆ (c->wfd != -1 && c->rfd != c->wfd) {
		ev = 0;
		ಆದರೆ ((c->io_want & SSH_CHAN_IO_WFD))
			ev |= POLLOUT;
		/* Pack a pfd entry if any event armed for this fd */
		ಆದರೆ (ev != 0) {
			c->pfds[1] = p;
			pfd[p].fd = c->wfd;
			pfd[p].events = ev;
			dump_channel_poll(__func__, "wfd", c, p, &pfd[p]);
			p++;
		}
	}
	/* prepare c->efd if wanting IO and not already handled above */
	ಆದರೆ (c->efd != -1 && c->rfd != c->efd) {
		ev = 0;
		ಆದರೆ ((c->io_want & SSH_CHAN_IO_EFD_R) != 0)
			ev |= POLLIN;
		ಆದರೆ ((c->io_want & SSH_CHAN_IO_EFD_W) != 0)
			ev |= POLLOUT;
		/* Pack a pfd entry if any event armed for this fd */
		ಆದರೆ (ev != 0) {
			c->pfds[2] = p;
			pfd[p].fd = c->efd;
			pfd[p].events = ev;
			dump_channel_poll(__func__, "efd", c, p, &pfd[p]);
			p++;
		}
	}
	/* prepare c->sock if wanting IO and not already handled above */
	ಆದರೆ (c->sock != -1 && c->rfd != c->sock) {
		ev = 0;
		ಆದರೆ ((c->io_want & SSH_CHAN_IO_SOCK_R) != 0)
			ev |= POLLIN;
		ಆದರೆ ((c->io_want & SSH_CHAN_IO_SOCK_W) != 0)
			ev |= POLLOUT;
		/* Pack a pfd entry if any event armed for this fd */
		ಆದರೆ (ev != 0) {
			c->pfds[3] = p;
			pfd[p].fd = c->sock;
			pfd[p].events = ev;
			dump_channel_poll(__func__, "sock", c, p, &pfd[p]);
			p++;
		}
	}
	*ಮುಂದಿನ_pollfd = p;
}

/* * Allocate/prepare poll structure */
ಶೂನ್ಯ
channel_prepare_poll(ರಚನೆ ssh *ssh, ರಚನೆ pollfd **pfdp, u_int *npfd_allocp,
    u_int *npfd_activep, u_int npfd_reserved, ರಚನೆ timespec *timeout)
{
	ರಚನೆ ssh_channels *sc = ssh->chanctxt;
	u_int i, oalloc, p, npfd = npfd_reserved;

	channel_before_prepare_io(ssh); /* might create a new channel */
	/* clear out I/O flags from last poll */
	ಗಾಗಿ (i = 0; i < sc->channels_alloc; i++) {
		ಆದರೆ (sc->channels[i] == ಖಾಲಿ)
			ಮುಂದುವರಿ;
		sc->channels[i]->io_want = sc->channels[i]->io_ready = 0;
	}
	/* Allocate 4x pollfd for each channel (rfd, wfd, efd, sock) */
	ಆದರೆ (sc->channels_alloc >= (ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ / 4) - npfd_reserved)
		fatal_f("too many channels"); /* shouldn't happen */
	npfd += sc->channels_alloc * 4;
	ಆದರೆ (npfd > *npfd_allocp) {
		*pfdp = xrecallocarray(*pfdp, *npfd_allocp,
		    npfd, ಗಾತ್ರ(**pfdp));
		*npfd_allocp = npfd;
	}
	*npfd_activep = npfd_reserved;
	oalloc = sc->channels_alloc;

	channel_handler(ssh, CHAN_PRE, timeout);

	ಆದರೆ (oalloc != sc->channels_alloc) {
		/* shouldn't happen */
		fatal_f("channels_alloc changed during CHAN_PRE "
		    "(was %u, now %u)", oalloc, sc->channels_alloc);
	}

	/* Prepare pollfd */
	p = npfd_reserved;
	ಗಾಗಿ (i = 0; i < sc->channels_alloc; i++)
		channel_prepare_pollfd(sc->channels[i], &p, *pfdp, npfd);
	*npfd_activep = p;
}

ಸ್ಥಿರ ಶೂನ್ಯ
fd_ready(Channel *c, ಪೂರ್ಣಾಂಕ p, ರಚನೆ pollfd *pfds, u_int npfd, ಪೂರ್ಣಾಂಕ fd,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *what, u_int revents_ಮುಖವಾಡ, u_int ready)
{
	ರಚನೆ pollfd *pfd = &pfds[p];

	ಆದರೆ (fd == -1)
		ಹಿಂತಿರುಗಿ;
	ಆದರೆ (p == -1 || (u_int)p >= npfd)
		fatal_f("channel %d: bad pfd %d (max %u)", c->self, p, npfd);
	dump_channel_poll(__func__, what, c, p, pfd);
	ಆದರೆ (pfd->fd != fd) {
		fatal("channel %d: inconsistent %s fd=%d pollfd[%u].fd %d "
		    "r%d w%d e%d s%d", c->self, what, fd, p, pfd->fd,
		    c->rfd, c->wfd, c->efd, c->sock);
	}
	ಆದರೆ ((pfd->revents & POLLNVAL) != 0) {
		fatal("channel %d: invalid %s pollfd[%u].fd %d r%d w%d e%d s%d",
		    c->self, what, p, pfd->fd, c->rfd, c->wfd, c->efd, c->sock);
	}
	ಆದರೆ ((pfd->revents & (revents_ಮುಖವಾಡ|POLLHUP|POLLERR)) != 0)
		c->io_ready |= ready & c->io_want;
}

/*
 * After poll, perform any appropriate operations for channels which have
 * events pending.
 */
ಶೂನ್ಯ
channel_after_poll(ರಚನೆ ssh *ssh, ರಚನೆ pollfd *pfd, u_int npfd)
{
	ರಚನೆ ssh_channels *sc = ssh->chanctxt;
	u_int i;
	ಪೂರ್ಣಾಂಕ p;
	Channel *c;

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_CHANNEL_POLL
	ಗಾಗಿ (p = 0; p < (ಪೂರ್ಣಾಂಕ)npfd; p++) {
		ಆದರೆ (pfd[p].revents == 0)
			ಮುಂದುವರಿ;
		debug_f("pfd[%u].fd %d rev 0x%04x",
		    p, pfd[p].fd, pfd[p].revents);
	}
#ಆದರೆ_ಅಂತ್ಯ

	/* Convert pollfd into c->io_ready */
	ಗಾಗಿ (i = 0; i < sc->channels_alloc; i++) {
		c = sc->channels[i];
		ಆದರೆ (c == ಖಾಲಿ)
			ಮುಂದುವರಿ;
		/* if rfd is shared with efd/sock then wfd should be too */
		ಆದರೆ (c->rfd != -1 && c->wfd != -1 && c->rfd != c->wfd &&
		    (c->rfd == c->efd || c->rfd == c->sock)) {
			/* Shouldn't happen */
			fatal_f("channel %d: unexpected fds r%d w%d e%d s%d",
			    c->self, c->rfd, c->wfd, c->efd, c->sock);
		}
		c->io_ready = 0;
		/* rfd, potentially shared with wfd, efd and sock */
		ಆದರೆ (c->rfd != -1 && (p = c->pfds[0]) != -1) {
			fd_ready(c, p, pfd, npfd, c->rfd,
			    "rfd", POLLIN, SSH_CHAN_IO_RFD);
			ಆದರೆ (c->rfd == c->wfd) {
				fd_ready(c, p, pfd, npfd, c->wfd,
				    "wfd/r", POLLOUT, SSH_CHAN_IO_WFD);
			}
			ಆದರೆ (c->rfd == c->efd) {
				fd_ready(c, p, pfd, npfd, c->efd,
				    "efdr/r", POLLIN, SSH_CHAN_IO_EFD_R);
				fd_ready(c, p, pfd, npfd, c->efd,
				    "efdw/r", POLLOUT, SSH_CHAN_IO_EFD_W);
			}
			ಆದರೆ (c->rfd == c->sock) {
				fd_ready(c, p, pfd, npfd, c->sock,
				    "sockr/r", POLLIN, SSH_CHAN_IO_SOCK_R);
				fd_ready(c, p, pfd, npfd, c->sock,
				    "sockw/r", POLLOUT, SSH_CHAN_IO_SOCK_W);
			}
			dump_channel_poll(__func__, "rfd", c, p, pfd);
		}
		/* wfd */
		ಆದರೆ (c->wfd != -1 && c->wfd != c->rfd &&
		    (p = c->pfds[1]) != -1) {
			fd_ready(c, p, pfd, npfd, c->wfd,
			    "wfd", POLLOUT, SSH_CHAN_IO_WFD);
			dump_channel_poll(__func__, "wfd", c, p, pfd);
		}
		/* efd */
		ಆದರೆ (c->efd != -1 && c->efd != c->rfd &&
		    (p = c->pfds[2]) != -1) {
			fd_ready(c, p, pfd, npfd, c->efd,
			    "efdr", POLLIN, SSH_CHAN_IO_EFD_R);
			fd_ready(c, p, pfd, npfd, c->efd,
			    "efdw", POLLOUT, SSH_CHAN_IO_EFD_W);
			dump_channel_poll(__func__, "efd", c, p, pfd);
		}
		/* sock */
		ಆದರೆ (c->sock != -1 && c->sock != c->rfd &&
		    (p = c->pfds[3]) != -1) {
			fd_ready(c, p, pfd, npfd, c->sock,
			    "sockr", POLLIN, SSH_CHAN_IO_SOCK_R);
			fd_ready(c, p, pfd, npfd, c->sock,
			    "sockw", POLLOUT, SSH_CHAN_IO_SOCK_W);
			dump_channel_poll(__func__, "sock", c, p, pfd);
		}
	}
	channel_handler(ssh, CHAN_POST, ಖಾಲಿ);
}

/*
 * Enqueue data for channels with open or draining c->input.
 * Returns non-zero if a packet was enqueued.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
channel_output_poll_ಒಳಹರಿವು_open(ರಚನೆ ssh *ssh, Channel *c)
{
	ಗಾತ್ರ_t len, plen;
	ಸ್ಥಿರಾಂಕ u_char *pkt;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((len = sshbuf_len(c->ಒಳಹರಿವು)) == 0) {
		ಆದರೆ (c->istate == CHAN_ಒಳಹರಿವು_WAIT_DRAIN) {
			/*
			 * input-buffer is empty and read-socket shutdown:
			 * tell peer, that we will not send more data:
			 * send IEOF.
			 * hack for extended data: delay EOF if EFD still
			 * in use.
			 */
			ಆದರೆ (CHANNEL_EFD_ಒಳಹರಿವು_ಸಕ್ರಿಯ(c))
				debug2("channel %d: "
				    "ibuf_empty delayed efd %d/(%zu)",
				    c->self, c->efd, sshbuf_len(c->extended));
			ಇಲ್ಲದಿದ್ದರೆ
				chan_ibuf_ಖಾಲಿಗಳು(ssh, c);
		}
		ಹಿಂತಿರುಗಿ 0;
	}

	ಆದರೆ (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);

	ಆದರೆ (c->datagram) {
		/* Check datagram will fit; drop if not */
		ಆದರೆ ((r = sshbuf_get_string_ನೇರ(c->ಒಳಹರಿವು, &pkt, &plen)) != 0)
			fatal_fr(r, "channel %i: get datagram", c->self);
		/*
		 * XXX this does tail-drop on the datagram queue which is
		 * usually suboptimal compared to head-drop. Better to have
		 * backpressure at read time? (i.e. read + discard)
		 */
		ಆದರೆ (plen > c->remote_ಕಿಟಕಿ || plen > c->remote_maxpacket) {
			debug("channel %d: datagram too big", c->self);
			ಹಿಂತಿರುಗಿ 0;
		}
		/* Enqueue it */
		ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh, SSH2_ಸಂದೇಶ_CHANNEL_ದತ್ತಾಂಶ)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
		    (r = sshpkt_put_string(ssh, pkt, plen)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "channel %i: send datagram", c->self);
		c->remote_ಕಿಟಕಿ -= plen;
		ಹಿಂತಿರುಗಿ 1;
	}

	/* Enqueue packet for buffered data. */
	ಆದರೆ (len > c->remote_ಕಿಟಕಿ)
		len = c->remote_ಕಿಟಕಿ;
	ಆದರೆ (len > c->remote_maxpacket)
		len = c->remote_maxpacket;
	ಆದರೆ (len == 0)
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh, SSH2_ಸಂದೇಶ_CHANNEL_ದತ್ತಾಂಶ)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_string(ssh, sshbuf_ptr(c->ಒಳಹರಿವು), len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i: send data", c->self);
	ಆದರೆ ((r = sshbuf_consume(c->ಒಳಹರಿವು, len)) != 0)
		fatal_fr(r, "channel %i: consume", c->self);
	c->remote_ಕಿಟಕಿ -= len;
	ಹಿಂತಿರುಗಿ 1;
}

/*
 * Enqueue data for channels with open c->extended in read mode.
 * Returns non-zero if a packet was enqueued.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
channel_output_poll_extended_read(ರಚನೆ ssh *ssh, Channel *c)
{
	ಗಾತ್ರ_t len;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((len = sshbuf_len(c->extended)) == 0)
		ಹಿಂತಿರುಗಿ 0;

	debug2("channel %d: rwin %u elen %zu euse %d", c->self,
	    c->remote_ಕಿಟಕಿ, sshbuf_len(c->extended), c->extended_usage);
	ಆದರೆ (len > c->remote_ಕಿಟಕಿ)
		len = c->remote_ಕಿಟಕಿ;
	ಆದರೆ (len > c->remote_maxpacket)
		len = c->remote_maxpacket;
	ಆದರೆ (len == 0)
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);
	ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh, SSH2_ಸಂದೇಶ_CHANNEL_EXTENDED_ದತ್ತಾಂಶ)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_u32(ssh, SSH2_EXTENDED_ದತ್ತಾಂಶ_STDERR)) != 0 ||
	    (r = sshpkt_put_string(ssh, sshbuf_ptr(c->extended), len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i: data", c->self);
	ಆದರೆ ((r = sshbuf_consume(c->extended, len)) != 0)
		fatal_fr(r, "channel %i: consume", c->self);
	c->remote_ಕಿಟಕಿ -= len;
	debug2("channel %d: sent ext data %zu", c->self, len);
	ಹಿಂತಿರುಗಿ 1;
}

/*
 * If there is data to send to the connection, enqueue some of it now.
 * Returns non-zero if data was enqueued.
 */
ಪೂರ್ಣಾಂಕ
channel_output_poll(ರಚನೆ ssh *ssh)
{
	ರಚನೆ ssh_channels *sc = ssh->chanctxt;
	Channel *c;
	u_int i;
	ಪೂರ್ಣಾಂಕ ret = 0;

	ಗಾಗಿ (i = 0; i < sc->channels_alloc; i++) {
		c = sc->channels[i];
		ಆದರೆ (c == ಖಾಲಿ)
			ಮುಂದುವರಿ;

		/*
		 * We are only interested in channels that can have buffered
		 * incoming data.
		 */
		ಆದರೆ (c->type != SSH_CHANNEL_OPEN)
			ಮುಂದುವರಿ;
		ಆದರೆ ((c->flags & (CHAN_CLOSE_ಕಳುಹಿಸಿದ|CHAN_CLOSE_RCVD))) {
			/* XXX is this true? */
			debug3("channel %d: will not send data after close",
			    c->self);
			ಮುಂದುವರಿ;
		}

		/* Get the amount of buffered data for this channel. */
		ಆದರೆ (c->istate == CHAN_ಒಳಹರಿವು_OPEN ||
		    c->istate == CHAN_ಒಳಹರಿವು_WAIT_DRAIN)
			ret |= channel_output_poll_ಒಳಹರಿವು_open(ssh, c);
		/* Send extended data, i.e. stderr */
		ಆದರೆ (!(c->flags & CHAN_EOF_ಕಳುಹಿಸಿದ) &&
		    c->extended_usage == CHAN_EXTENDED_READ)
			ret |= channel_output_poll_extended_read(ssh, c);
	}
	ಹಿಂತಿರುಗಿ ret;
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
ಪೂರ್ಣಾಂಕ
channel_proxy_downstream(ರಚನೆ ssh *ssh, Channel *downstream)
{
	Channel *c = ಖಾಲಿ;
	ರಚನೆ sshbuf *original = ಖಾಲಿ, *modified = ಖಾಲಿ;
	ಸ್ಥಿರಾಂಕ u_char *cp;
	ಅಕ್ಷರ *ctype = ಖಾಲಿ, *listen_host = ಖಾಲಿ;
	u_char type;
	ಗಾತ್ರ_t have;
	ಪೂರ್ಣಾಂಕ ret = -1, r;
	u_int id, remote_id, listen_ಪೋರ್ಟ್;

	/* sshbuf_dump(downstream->input, stderr); */
	ಆದರೆ ((r = sshbuf_get_string_ನೇರ(downstream->ಒಳಹರಿವು, &cp, &have))
	    != 0) {
		error_fr(r, "parse");
		ಹಿಂತಿರುಗಿ -1;
	}
	ಆದರೆ (have < 2) {
		error_f("short message");
		ಹಿಂತಿರುಗಿ -1;
	}
	type = cp[1];
	/* skip padlen + type */
	cp += 2;
	have -= 2;
	ಆದರೆ (ssh_packet_log_type(type))
		debug3_f("channel %u: down->up: type %u",
		    downstream->self, type);

	ಆಯ್ಕೆ (type) {
	ಸ್ಥಿತಿ SSH2_ಸಂದೇಶ_CHANNEL_OPEN:
		ಆದರೆ ((original = sshbuf_from(cp, have)) == ಖಾಲಿ ||
		    (modified = sshbuf_new()) == ಖಾಲಿ) {
			error_f("alloc");
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ ((r = sshbuf_get_cstring(original, &ctype, ಖಾಲಿ)) != 0 ||
		    (r = sshbuf_get_u32(original, &id)) != 0) {
			error_fr(r, "parse");
			ಹೋಗು ಹೊರಹೋಗು;
		}
		c = channel_new(ssh, "mux-proxy", SSH_CHANNEL_MUX_PROXY,
		    -1, -1, -1, 0, 0, 0, ctype, 1);
		c->mux_ctx = downstream;	/* point to mux client */
		c->mux_downstream_id = id;	/* original downstream id */
		ಆದರೆ ((r = sshbuf_put_cstring(modified, ctype)) != 0 ||
		    (r = sshbuf_put_u32(modified, c->self)) != 0 ||
		    (r = sshbuf_putb(modified, original)) != 0) {
			error_fr(r, "compose");
			channel_free(ssh, c);
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ SSH2_ಸಂದೇಶ_CHANNEL_OPEN_CONFIRMATION:
		/*
		 * Almost the same as SSH2_MSG_CHANNEL_OPEN, except then we
		 * need to parse 'remote_id' instead of 'ctype'.
		 */
		ಆದರೆ ((original = sshbuf_from(cp, have)) == ಖಾಲಿ ||
		    (modified = sshbuf_new()) == ಖಾಲಿ) {
			error_f("alloc");
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ ((r = sshbuf_get_u32(original, &remote_id)) != 0 ||
		    (r = sshbuf_get_u32(original, &id)) != 0) {
			error_fr(r, "parse");
			ಹೋಗು ಹೊರಹೋಗು;
		}
		c = channel_new(ssh, "mux-proxy", SSH_CHANNEL_MUX_PROXY,
		    -1, -1, -1, 0, 0, 0, "mux-down-connect", 1);
		c->mux_ctx = downstream;	/* point to mux client */
		c->mux_downstream_id = id;
		c->remote_id = remote_id;
		c->have_remote_id = 1;
		ಆದರೆ ((r = sshbuf_put_u32(modified, remote_id)) != 0 ||
		    (r = sshbuf_put_u32(modified, c->self)) != 0 ||
		    (r = sshbuf_putb(modified, original)) != 0) {
			error_fr(r, "compose");
			channel_free(ssh, c);
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ SSH2_ಸಂದೇಶ_GLOBAL_REQUEST:
		ಆದರೆ ((original = sshbuf_from(cp, have)) == ಖಾಲಿ) {
			error_f("alloc");
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ ((r = sshbuf_get_cstring(original, &ctype, ಖಾಲಿ)) != 0) {
			error_fr(r, "parse");
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ (strcmp(ctype, "tcpip-forward") != 0) {
			error_f("unsupported request %s", ctype);
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ ((r = sshbuf_get_u8(original, ಖಾಲಿ)) != 0 ||
		    (r = sshbuf_get_cstring(original, &listen_host, ಖಾಲಿ)) != 0 ||
		    (r = sshbuf_get_u32(original, &listen_ಪೋರ್ಟ್)) != 0) {
			error_fr(r, "parse");
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ (listen_ಪೋರ್ಟ್ > 65535) {
			error_f("tcpip-forward for %s: bad port %u",
			    listen_host, listen_ಪೋರ್ಟ್);
			ಹೋಗು ಹೊರಹೋಗು;
		}
		/* Record that connection to this host/port is permitted. */
		permission_ಗಣ_ಕೂಡಿಸು(ssh, FORWARD_USER, FORWARD_LOCAL, "<mux>",
		    -1, listen_host, ಖಾಲಿ, (ಪೂರ್ಣಾಂಕ)listen_ಪೋರ್ಟ್, downstream);
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ SSH2_ಸಂದೇಶ_CHANNEL_CLOSE:
		ಆದರೆ (have < 4)
			ನಿಲ್ಲಿಸು;
		remote_id = PEEK_U32(cp);
		ಆದರೆ ((c = channel_by_remote_id(ssh, remote_id)) != ಖಾಲಿ) {
			ಆದರೆ (c->flags & CHAN_CLOSE_RCVD)
				channel_free(ssh, c);
			ಇಲ್ಲದಿದ್ದರೆ
				c->flags |= CHAN_CLOSE_ಕಳುಹಿಸಿದ;
		}
		ನಿಲ್ಲಿಸು;
	}
	ಆದರೆ (modified) {
		ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh, type)) != 0 ||
		    (r = sshpkt_putb(ssh, modified)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0) {
			error_fr(r, "send");
			ಹೋಗು ಹೊರಹೋಗು;
		}
	} ಇಲ್ಲದಿದ್ದರೆ {
		ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh, type)) != 0 ||
		    (r = sshpkt_put(ssh, cp, have)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0) {
			error_fr(r, "send");
			ಹೋಗು ಹೊರಹೋಗು;
		}
	}
	ret = 0;
 ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(ctype);
	ಬಿಡುಗಡೆ(listen_host);
	sshbuf_free(original);
	sshbuf_free(modified);
	ಹಿಂತಿರುಗಿ ret;
}

/*
 * receive packets from upstream server and de-multiplex packets
 * to correct downstream:
 * implemented as a helper for channel input handlers,
 * replaces local (proxy) channel ID with downstream channel ID.
 */
ಪೂರ್ಣಾಂಕ
channel_proxy_upstream(Channel *c, ಪೂರ್ಣಾಂಕ type, uint32_t seq, ರಚನೆ ssh *ssh)
{
	ರಚನೆ sshbuf *b = ಖಾಲಿ;
	Channel *downstream;
	ಸ್ಥಿರಾಂಕ u_char *cp = ಖಾಲಿ;
	ಗಾತ್ರ_t len;
	ಪೂರ್ಣಾಂಕ r;

	/*
	 * When receiving packets from the peer we need to check whether we
	 * need to forward the packets to the mux client. In this case we
	 * restore the original channel id and keep track of CLOSE messages,
	 * so we can cleanup the channel.
	 */
	ಆದರೆ (c == ಖಾಲಿ || c->type != SSH_CHANNEL_MUX_PROXY)
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ ((downstream = c->mux_ctx) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 0;
	ಆಯ್ಕೆ (type) {
	ಸ್ಥಿತಿ SSH2_ಸಂದೇಶ_CHANNEL_CLOSE:
	ಸ್ಥಿತಿ SSH2_ಸಂದೇಶ_CHANNEL_ದತ್ತಾಂಶ:
	ಸ್ಥಿತಿ SSH2_ಸಂದೇಶ_CHANNEL_EOF:
	ಸ್ಥಿತಿ SSH2_ಸಂದೇಶ_CHANNEL_EXTENDED_ದತ್ತಾಂಶ:
	ಸ್ಥಿತಿ SSH2_ಸಂದೇಶ_CHANNEL_OPEN_CONFIRMATION:
	ಸ್ಥಿತಿ SSH2_ಸಂದೇಶ_CHANNEL_OPEN_FAILURE:
	ಸ್ಥಿತಿ SSH2_ಸಂದೇಶ_CHANNEL_ಕಿಟಕಿ_ADJUST:
	ಸ್ಥಿತಿ SSH2_ಸಂದೇಶ_CHANNEL_SUCCESS:
	ಸ್ಥಿತಿ SSH2_ಸಂದೇಶ_CHANNEL_FAILURE:
	ಸ್ಥಿತಿ SSH2_ಸಂದೇಶ_CHANNEL_REQUEST:
		ನಿಲ್ಲಿಸು;
	ಪೂರ್ವನಿಯೋಜಿತ:
		debug2_f("channel %u: unsupported type %u", c->self, type);
		ಹಿಂತಿರುಗಿ 0;
	}
	ಆದರೆ ((b = sshbuf_new()) == ಖಾಲಿ) {
		error_f("alloc reply");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/* get remaining payload (after id) */
	cp = sshpkt_ptr(ssh, &len);
	ಆದರೆ (cp == ಖಾಲಿ) {
		error_f("no packet");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/* translate id and send to muxclient */
	ಆದರೆ ((r = sshbuf_put_u8(b, 0)) != 0 ||	/* padlen */
	    (r = sshbuf_put_u8(b, type)) != 0 ||
	    (r = sshbuf_put_u32(b, c->mux_downstream_id)) != 0 ||
	    (r = sshbuf_put(b, cp, len)) != 0 ||
	    (r = sshbuf_put_stringb(downstream->output, b)) != 0) {
		error_fr(r, "compose muxclient");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/* sshbuf_dump(b, stderr); */
	ಆದರೆ (ssh_packet_log_type(type))
		debug3_f("channel %u: up->down: type %u", c->self, type);
 ಹೊರಹೋಗು:
	/* update state */
	ಆಯ್ಕೆ (type) {
	ಸ್ಥಿತಿ SSH2_ಸಂದೇಶ_CHANNEL_OPEN_CONFIRMATION:
		/* record remote_id for SSH2_MSG_CHANNEL_CLOSE */
		ಆದರೆ (cp && len > 4) {
			c->remote_id = PEEK_U32(cp);
			c->have_remote_id = 1;
		}
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ SSH2_ಸಂದೇಶ_CHANNEL_CLOSE:
		ಆದರೆ (c->flags & CHAN_CLOSE_ಕಳುಹಿಸಿದ)
			channel_free(ssh, c);
		ಇಲ್ಲದಿದ್ದರೆ
			c->flags |= CHAN_CLOSE_RCVD;
		ನಿಲ್ಲಿಸು;
	}
	sshbuf_free(b);
	ಹಿಂತಿರುಗಿ 1;
}

/* -- protocol input */

/* Parse a channel ID from the current packet */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
channel_parse_id(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *where, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *what)
{
	uint32_t id;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = sshpkt_get_u32(ssh, &id)) != 0) {
		error_r(r, "%s: parse id", where);
		ssh_packet_disconnect(ssh, "Invalid %s message", what);
	}
	ಆದರೆ (id > ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ) {
		error_r(r, "%s: bad channel id %u", where, id);
		ssh_packet_disconnect(ssh, "Invalid %s channel id", what);
	}
	ಹಿಂತಿರುಗಿ (ಪೂರ್ಣಾಂಕ)id;
}

/* Lookup a channel from an ID in the current packet */
ಸ್ಥಿರ Channel *
channel_from_packet_id(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *where, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *what)
{
	ಪೂರ್ಣಾಂಕ id = channel_parse_id(ssh, where, what);
	Channel *c;

	ಆದರೆ ((c = channel_lookup(ssh, id)) == ಖಾಲಿ) {
		ssh_packet_disconnect(ssh,
		    "%s packet referred to nonexistent channel %d", what, id);
	}
	ಹಿಂತಿರುಗಿ c;
}

ಪೂರ್ಣಾಂಕ
channel_ಒಳಹರಿವು_ದತ್ತಾಂಶ(ಪೂರ್ಣಾಂಕ type, uint32_t seq, ರಚನೆ ssh *ssh)
{
	ಸ್ಥಿರಾಂಕ u_char *ದತ್ತಾಂಶ;
	ಗಾತ್ರ_t ದತ್ತಾಂಶ_len, win_len;
	Channel *c = channel_from_packet_id(ssh, __func__, "data");
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (channel_proxy_upstream(c, type, seq, ssh))
		ಹಿಂತಿರುಗಿ 0;

	/* Ignore any data for non-open channels (might happen on close) */
	ಆದರೆ (c->type != SSH_CHANNEL_OPEN &&
	    c->type != SSH_CHANNEL_RDYNAMIC_OPEN &&
	    c->type != SSH_CHANNEL_RDYNAMIC_ಮುಕ್ತಾಯ &&
	    c->type != SSH_CHANNEL_X11_OPEN)
		ಹಿಂತಿರುಗಿ 0;

	/* Get the data. */
	ಆದರೆ ((r = sshpkt_get_string_ನೇರ(ssh, &ದತ್ತಾಂಶ, &ದತ್ತಾಂಶ_len)) != 0 ||
            (r = sshpkt_get_ಕೊನೆ(ssh)) != 0)
		fatal_fr(r, "channel %i: get data", c->self);

	win_len = ದತ್ತಾಂಶ_len;
	ಆದರೆ (c->datagram)
		win_len += 4;  /* string length header */

	/*
	 * The sending side reduces its window as it sends data, so we
	 * must 'fake' consumption of the data in order to ensure that window
	 * updates are sent back. Otherwise the connection might deadlock.
	 */
	ಆದರೆ (c->ostate != CHAN_OUTPUT_OPEN) {
		ಆದರೆ (win_len > c->local_ಕಿಟಕಿ)
			c->local_ಕಿಟಕಿ = 0;
		ಇಲ್ಲದಿದ್ದರೆ
			c->local_ಕಿಟಕಿ -= win_len;
		c->local_consumed += win_len;
		ಹಿಂತಿರುಗಿ 0;
	}

	ಆದರೆ (win_len > c->local_maxpacket) {
		logit("channel %d: rcvd big packet %zu, maxpack %u",
		    c->self, win_len, c->local_maxpacket);
		ಹಿಂತಿರುಗಿ 0;
	}
	ಆದರೆ (win_len > c->local_ಕಿಟಕಿ) {
		u_int delta = win_len - c->local_ಕಿಟಕಿ;

		ಆದರೆ (c->local_ಕಿಟಕಿ_exceeded > UINT_MAX - delta)
			c->local_ಕಿಟಕಿ_exceeded = UINT_MAX;
		ಇಲ್ಲದಿದ್ದರೆ
			c->local_ಕಿಟಕಿ_exceeded += delta;
		logit("channel %d: rcvd too much data %zu, win %u/%u "
		    "(excess %u)", c->self, win_len, c->local_ಕಿಟಕಿ,
		    c->local_ಕಿಟಕಿ_max, c->local_ಕಿಟಕಿ_exceeded);
		c->local_ಕಿಟಕಿ = 0;
		/* Allow 10% grace before bringing the hammer down */
		ಆದರೆ (c->local_ಕಿಟಕಿ_exceeded > (c->local_ಕಿಟಕಿ_max / 10)) {
			ssh_packet_disconnect(ssh, "channel %d: peer ignored "
			    "channel window", c->self);
		}
	} ಇಲ್ಲದಿದ್ದರೆ {
		c->local_ಕಿಟಕಿ -= win_len;
		c->local_ಕಿಟಕಿ_exceeded = 0;
	}

	ಆದರೆ (c->datagram) {
		ಆದರೆ ((r = sshbuf_put_string(c->output, ದತ್ತಾಂಶ, ದತ್ತಾಂಶ_len)) != 0)
			fatal_fr(r, "channel %i: append datagram", c->self);
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((r = sshbuf_put(c->output, ದತ್ತಾಂಶ, ದತ್ತಾಂಶ_len)) != 0)
		fatal_fr(r, "channel %i: append data", c->self);

	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
channel_ಒಳಹರಿವು_extended_ದತ್ತಾಂಶ(ಪೂರ್ಣಾಂಕ type, uint32_t seq, ರಚನೆ ssh *ssh)
{
	ಸ್ಥಿರಾಂಕ u_char *ದತ್ತಾಂಶ;
	ಗಾತ್ರ_t ದತ್ತಾಂಶ_len;
	uint32_t tcode;
	Channel *c = channel_from_packet_id(ssh, __func__, "extended data");
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (channel_proxy_upstream(c, type, seq, ssh))
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ (c->type != SSH_CHANNEL_OPEN) {
		logit("channel %d: ext data for non open", c->self);
		ಹಿಂತಿರುಗಿ 0;
	}
	ಆದರೆ (c->flags & CHAN_EOF_RCVD) {
		ಆದರೆ (ssh->compat & SSH_BUG_EXTEOF)
			debug("channel %d: accepting ext data after eof",
			    c->self);
		ಇಲ್ಲದಿದ್ದರೆ
			ssh_packet_disconnect(ssh, "Received extended_data "
			    "after EOF on channel %d.", c->self);
	}

	ಆದರೆ ((r = sshpkt_get_u32(ssh, &tcode)) != 0) {
		error_fr(r, "parse tcode");
		ssh_packet_disconnect(ssh, "Invalid extended_data message");
	}
	ಆದರೆ (c->efd == -1 ||
	    c->extended_usage != CHAN_EXTENDED_WRITE ||
	    tcode != SSH2_EXTENDED_ದತ್ತಾಂಶ_STDERR) {
		logit("channel %d: bad ext data", c->self);
		ಹಿಂತಿರುಗಿ 0;
	}
	ಆದರೆ ((r = sshpkt_get_string_ನೇರ(ssh, &ದತ್ತಾಂಶ, &ದತ್ತಾಂಶ_len)) != 0 ||
            (r = sshpkt_get_ಕೊನೆ(ssh)) != 0) {
		error_fr(r, "parse data");
		ssh_packet_disconnect(ssh, "Invalid extended_data message");
	}

	ಆದರೆ (ದತ್ತಾಂಶ_len > c->local_ಕಿಟಕಿ) {
		logit("channel %d: rcvd too much extended_data %zu, win %u",
		    c->self, ದತ್ತಾಂಶ_len, c->local_ಕಿಟಕಿ);
		ಹಿಂತಿರುಗಿ 0;
	}
	debug2("channel %d: rcvd ext data %zu", c->self, ದತ್ತಾಂಶ_len);
	/* XXX sshpkt_getb? */
	ಆದರೆ ((r = sshbuf_put(c->extended, ದತ್ತಾಂಶ, ದತ್ತಾಂಶ_len)) != 0)
		error_fr(r, "append");
	c->local_ಕಿಟಕಿ -= ದತ್ತಾಂಶ_len;
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
channel_ಒಳಹರಿವು_ieof(ಪೂರ್ಣಾಂಕ type, uint32_t seq, ರಚನೆ ssh *ssh)
{
	Channel *c = channel_from_packet_id(ssh, __func__, "ieof");
	ಪೂರ್ಣಾಂಕ r;

        ಆದರೆ ((r = sshpkt_get_ಕೊನೆ(ssh)) != 0) {
		error_fr(r, "parse data");
		ssh_packet_disconnect(ssh, "Invalid ieof message");
	}

	ಆದರೆ (channel_proxy_upstream(c, type, seq, ssh))
		ಹಿಂತಿರುಗಿ 0;
	chan_rcvd_ieof(ssh, c);

	/* XXX force input close */
	ಆದರೆ (c->force_drain && c->istate == CHAN_ಒಳಹರಿವು_OPEN) {
		debug("channel %d: FORCE input drain", c->self);
		c->istate = CHAN_ಒಳಹರಿವು_WAIT_DRAIN;
		ಆದರೆ (sshbuf_len(c->ಒಳಹರಿವು) == 0)
			chan_ibuf_ಖಾಲಿಗಳು(ssh, c);
	}
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
channel_ಒಳಹರಿವು_oclose(ಪೂರ್ಣಾಂಕ type, uint32_t seq, ರಚನೆ ssh *ssh)
{
	Channel *c = channel_from_packet_id(ssh, __func__, "oclose");
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (channel_proxy_upstream(c, type, seq, ssh))
		ಹಿಂತಿರುಗಿ 0;
        ಆದರೆ ((r = sshpkt_get_ಕೊನೆ(ssh)) != 0) {
		error_fr(r, "parse data");
		ssh_packet_disconnect(ssh, "Invalid oclose message");
	}
	chan_rcvd_oclose(ssh, c);
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
channel_ಒಳಹರಿವು_open_confirmation(ಪೂರ್ಣಾಂಕ type, uint32_t seq, ರಚನೆ ssh *ssh)
{
	Channel *c = channel_from_packet_id(ssh, __func__, "open confirmation");
	uint32_t remote_ಕಿಟಕಿ, remote_maxpacket;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (channel_proxy_upstream(c, type, seq, ssh))
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ (c->type != SSH_CHANNEL_OPENING)
		ssh_packet_disconnect(ssh, "Received open confirmation for "
		    "non-opening channel %d.", c->self);
	/*
	 * Record the remote channel number and mark that the channel
	 * is now open.
	 */
	ಆದರೆ ((r = sshpkt_get_u32(ssh, &c->remote_id)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &remote_ಕಿಟಕಿ)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &remote_maxpacket)) != 0 ||
            (r = sshpkt_get_ಕೊನೆ(ssh)) != 0) {
		error_fr(r, "window/maxpacket");
		ssh_packet_disconnect(ssh, "Invalid open confirmation message");
	}

	c->have_remote_id = 1;
	c->remote_ಕಿಟಕಿ = remote_ಕಿಟಕಿ;
	c->remote_maxpacket = remote_maxpacket;
	c->type = SSH_CHANNEL_OPEN;
	ಆದರೆ (c->open_confirm) {
		debug2_f("channel %d: callback start", c->self);
		c->open_confirm(ssh, c->self, 1, c->open_confirm_ctx);
		debug2_f("channel %d: callback done", c->self);
	}
	channel_ಗಣ_ಬಳಸಿದ_ಸಮಯ(ssh, c);
	debug2("channel %d: open confirm rwindow %u rmax %u", c->self,
	    c->remote_ಕಿಟಕಿ, c->remote_maxpacket);
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಅಕ್ಷರ *
reason2txt(ಪೂರ್ಣಾಂಕ reason)
{
	ಆಯ್ಕೆ (reason) {
	ಸ್ಥಿತಿ SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED:
		ಹಿಂತಿರುಗಿ "administratively prohibited";
	ಸ್ಥಿತಿ SSH2_OPEN_CONNECT_FAILED:
		ಹಿಂತಿರುಗಿ "connect failed";
	ಸ್ಥಿತಿ SSH2_OPEN_UNKNOWN_CHANNEL_TYPE:
		ಹಿಂತಿರುಗಿ "unknown channel type";
	ಸ್ಥಿತಿ SSH2_OPEN_RESOURCE_SHORTAGE:
		ಹಿಂತಿರುಗಿ "resource shortage";
	}
	ಹಿಂತಿರುಗಿ "unknown reason";
}

ಪೂರ್ಣಾಂಕ
channel_ಒಳಹರಿವು_open_failure(ಪೂರ್ಣಾಂಕ type, uint32_t seq, ರಚನೆ ssh *ssh)
{
	Channel *c = channel_from_packet_id(ssh, __func__, "open failure");
	uint32_t reason;
	ಅಕ್ಷರ *ಸಂದೇಶ = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (channel_proxy_upstream(c, type, seq, ssh))
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ (c->type != SSH_CHANNEL_OPENING)
		ssh_packet_disconnect(ssh, "Received open failure for "
		    "non-opening channel %d.", c->self);
	ಆದರೆ ((r = sshpkt_get_u32(ssh, &reason)) != 0) {
		error_fr(r, "parse reason");
		ssh_packet_disconnect(ssh, "Invalid open failure message");
	}
	/* skip language */
	ಆದರೆ ((r = sshpkt_get_cstring(ssh, &ಸಂದೇಶ, ಖಾಲಿ)) != 0 ||
	    (r = sshpkt_get_string_ನೇರ(ssh, ಖಾಲಿ, ಖಾಲಿ)) != 0 ||
            (r = sshpkt_get_ಕೊನೆ(ssh)) != 0) {
		error_fr(r, "parse msg/lang");
		ssh_packet_disconnect(ssh, "Invalid open failure message");
	}
	logit("channel %d: open failed: %s%s%s", c->self,
	    reason2txt(reason), ಸಂದೇಶ ? ": ": "", ಸಂದೇಶ ? ಸಂದೇಶ : "");
	ಬಿಡುಗಡೆ(ಸಂದೇಶ);
	ಆದರೆ (c->open_confirm) {
		debug2_f("channel %d: callback start", c->self);
		c->open_confirm(ssh, c->self, 0, c->open_confirm_ctx);
		debug2_f("channel %d: callback done", c->self);
	}
	/* Schedule the channel for cleanup/deletion. */
	chan_mark_dead(ssh, c);
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
channel_ಒಳಹರಿವು_ಕಿಟಕಿ_adjust(ಪೂರ್ಣಾಂಕ type, uint32_t seq, ರಚನೆ ssh *ssh)
{
	ಪೂರ್ಣಾಂಕ id = channel_parse_id(ssh, __func__, "window adjust");
	Channel *c;
	uint32_t adjust;
	u_int new_rwin;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((c = channel_lookup(ssh, id)) == ಖಾಲಿ) {
		logit("Received window adjust for non-open channel %d.", id);
		ಹಿಂತಿರುಗಿ 0;
	}

	ಆದರೆ (channel_proxy_upstream(c, type, seq, ssh))
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ ((r = sshpkt_get_u32(ssh, &adjust)) != 0 ||
            (r = sshpkt_get_ಕೊನೆ(ssh)) != 0) {
		error_fr(r, "parse adjust");
		ssh_packet_disconnect(ssh, "Invalid window adjust message");
	}
	debug2("channel %d: rcvd adjust %u", c->self, adjust);
	ಆದರೆ ((new_rwin = c->remote_ಕಿಟಕಿ + adjust) < c->remote_ಕಿಟಕಿ) {
		fatal("channel %d: adjust %u overflows remote window %u",
		    c->self, adjust, c->remote_ಕಿಟಕಿ);
	}
	c->remote_ಕಿಟಕಿ = new_rwin;
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
channel_ಒಳಹರಿವು_ಸ್ಥಿತಿ_confirm(ಪೂರ್ಣಾಂಕ type, uint32_t seq, ರಚನೆ ssh *ssh)
{
	ಪೂರ್ಣಾಂಕ id = channel_parse_id(ssh, __func__, "status confirm");
	Channel *c;
	ರಚನೆ channel_confirm *cc;

	/* Reset keepalive timeout */
	ssh_packet_ಗಣ_alive_timeouts(ssh, 0);

	debug2_f("type %d id %d", type, id);

	ಆದರೆ ((c = channel_lookup(ssh, id)) == ಖಾಲಿ) {
		logit_f("%d: unknown", id);
		ಹಿಂತಿರುಗಿ 0;
	}
	ಆದರೆ (channel_proxy_upstream(c, type, seq, ssh))
		ಹಿಂತಿರುಗಿ 0;
        ಆದರೆ (sshpkt_get_ಕೊನೆ(ssh) != 0)
		ssh_packet_disconnect(ssh, "Invalid status confirm message");
	ಆದರೆ ((cc = TAILQ_FIRST(&c->ಸ್ಥಿತಿ_confirms)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 0;
	cc->cb(ssh, type, c, cc->ctx);
	TAILQ_REMOVE(&c->ಸ್ಥಿತಿ_confirms, cc, ನಮೂದು);
	freezero(cc, ಗಾತ್ರ(*cc));
	ಹಿಂತಿರುಗಿ 0;
}

/* -- tcp forwarding */

ಶೂನ್ಯ
channel_ಗಣ_af(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ af)
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
ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *
channel_fwd_bind_addr(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *listen_addr, ಪೂರ್ಣಾಂಕ *wildcardp,
    ಪೂರ್ಣಾಂಕ is_client, ರಚನೆ ForwardOptions *fwd_opts)
{
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *addr = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ wildcard = 0;

	ಆದರೆ (listen_addr == ಖಾಲಿ) {
		/* No address specified: default to gateway_ports setting */
		ಆದರೆ (fwd_opts->gateway_ports)
			wildcard = 1;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (fwd_opts->gateway_ports || is_client) {
		ಆದರೆ (((ssh->compat & SSH_OLD_FORWARD_ADDR) &&
		    strcmp(listen_addr, "0.0.0.0") == 0 && is_client == 0) ||
		    *listen_addr == '\0' || strcmp(listen_addr, "*") == 0 ||
		    (!is_client && fwd_opts->gateway_ports == 1)) {
			wildcard = 1;
			/*
			 * Notify client if they requested a specific listen
			 * address and it was overridden.
			 */
			ಆದರೆ (*listen_addr != '\0' &&
			    strcmp(listen_addr, "0.0.0.0") != 0 &&
			    strcmp(listen_addr, "*") != 0) {
				ssh_packet_send_debug(ssh,
				    "Forwarding listen address "
				    "\"%s\" overridden by server "
				    "GatewayPorts", listen_addr);
			}
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(listen_addr, "localhost") != 0 ||
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
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(listen_addr, "127.0.0.1") == 0 ||
	    strcmp(listen_addr, "::1") == 0) {
		/*
		 * If a specific IPv4/IPv6 localhost address has been
		 * requested then accept it even if gateway_ports is in
		 * effect. This allows the client to prefer IPv4 or IPv6.
		 */
		addr = listen_addr;
	}
	ಆದರೆ (wildcardp != ಖಾಲಿ)
		*wildcardp = wildcard;
	ಹಿಂತಿರುಗಿ addr;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
channel_ಸಿದ್ಧತೆ_fwd_listener_tcpip(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ type,
    ರಚನೆ Forward *fwd, ಪೂರ್ಣಾಂಕ *allocated_listen_ಪೋರ್ಟ್,
    ರಚನೆ ForwardOptions *fwd_opts)
{
	Channel *c;
	ಪೂರ್ಣಾಂಕ sock, r, success = 0, wildcard = 0, is_client;
	ರಚನೆ addrinfo hints, *ai, *aitop;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host, *addr;
	ಅಕ್ಷರ ntop[NI_MAXHOST], strport[NI_MAXSERV];
	in_port_t *lport_p;

	is_client = (type == SSH_CHANNEL_ಪೋರ್ಟ್_LISTENER);

	ಆದರೆ (is_client && fwd->connect_ಮಾರ್ಗ != ಖಾಲಿ) {
		host = fwd->connect_ಮಾರ್ಗ;
	} ಇಲ್ಲದಿದ್ದರೆ {
		host = (type == SSH_CHANNEL_RPORT_LISTENER) ?
		    fwd->listen_host : fwd->connect_host;
		ಆದರೆ (host == ಖಾಲಿ) {
			error("No forward host name.");
			ಹಿಂತಿರುಗಿ 0;
		}
		ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(host) >= NI_MAXHOST) {
			error("Forward host name too long.");
			ಹಿಂತಿರುಗಿ 0;
		}
	}

	/* Determine the bind address, cf. channel_fwd_bind_addr() comment */
	addr = channel_fwd_bind_addr(ssh, fwd->listen_host, &wildcard,
	    is_client, fwd_opts);
	debug3_f("type %d wildcard %d addr %s", type, wildcard,
	    (addr == ಖಾಲಿ) ? "NULL" : addr);

	/*
	 * getaddrinfo returns a loopback address if the hostname is
	 * set to NULL and hints.ai_flags is not AI_PASSIVE
	 */
	memset(&hints, 0, ಗಾತ್ರ(hints));
	hints.ai_family = ssh->chanctxt->IPv4or6;
	hints.ai_flags = wildcard ? AI_PASSIVE : 0;
	hints.ai_socktype = SOCK_STREAM;
	snprintf(strport, ಗಾತ್ರ strport, "%d", fwd->listen_ಪೋರ್ಟ್);
	ಆದರೆ ((r = getaddrinfo(addr, strport, &hints, &aitop)) != 0) {
		ಆದರೆ (addr == ಖಾಲಿ) {
			/* This really shouldn't happen */
			ssh_packet_disconnect(ssh, "getaddrinfo: fatal error: %s",
			    ssh_gai_strerror(r));
		} ಇಲ್ಲದಿದ್ದರೆ {
			error_f("getaddrinfo(%.64s): %s", addr,
			    ssh_gai_strerror(r));
		}
		ಹಿಂತಿರುಗಿ 0;
	}
	ಆದರೆ (allocated_listen_ಪೋರ್ಟ್ != ಖಾಲಿ)
		*allocated_listen_ಪೋರ್ಟ್ = 0;
	ಗಾಗಿ (ai = aitop; ai; ai = ai->ai_next) {
		ಆಯ್ಕೆ (ai->ai_family) {
		ಸ್ಥಿತಿ AF_INET:
			lport_p = &((ರಚನೆ sockaddr_in *)ai->ai_addr)->
			    sin_port;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ AF_INET6:
			lport_p = &((ರಚನೆ sockaddr_in6 *)ai->ai_addr)->
			    sin6_port;
			ನಿಲ್ಲಿಸು;
		ಪೂರ್ವನಿಯೋಜಿತ:
			ಮುಂದುವರಿ;
		}
		/*
		 * If allocating a port for -R forwards, then use the
		 * same port for all address families.
		 */
		ಆದರೆ (type == SSH_CHANNEL_RPORT_LISTENER &&
		    fwd->listen_ಪೋರ್ಟ್ == 0 && allocated_listen_ಪೋರ್ಟ್ != ಖಾಲಿ &&
		    *allocated_listen_ಪೋರ್ಟ್ > 0)
			*lport_p = htons(*allocated_listen_ಪೋರ್ಟ್);

		ಆದರೆ (getnameinfo(ai->ai_addr, ai->ai_addrlen, ntop, ಗಾತ್ರ(ntop),
		    strport, ಗಾತ್ರ(strport),
		    NI_NUMERICHOST|NI_NUMERICSERV) != 0) {
			error_f("getnameinfo failed");
			ಮುಂದುವರಿ;
		}
		/* Create a port to listen for the host. */
		sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		ಆದರೆ (sock == -1) {
			/* this is no error since kernel may not support ipv6 */
			verbose("socket [%s]:%s: %.100s", ntop, strport,
			    strerror(errno));
			ಮುಂದುವರಿ;
		}

		ಗಣ_reuseaddr(sock);
		ಆದರೆ (ai->ai_family == AF_INET6)
			sock_ಗಣ_v6only(sock);

		debug("Local forwarding listening on %s port %s.",
		    ntop, strport);

		/* Bind the socket to the address. */
		ಆದರೆ (bind(sock, ai->ai_addr, ai->ai_addrlen) == -1) {
			/*
			 * address can be in if use ipv6 address is
			 * already bound
			 */
			ಆದರೆ (!ai->ai_next)
				error("bind [%s]:%s: %.100s",
				    ntop, strport, strerror(errno));
			ಇಲ್ಲದಿದ್ದರೆ
				verbose("bind [%s]:%s: %.100s",
				    ntop, strport, strerror(errno));

			close(sock);
			ಮುಂದುವರಿ;
		}
		/* Start listening for connections on the socket. */
		ಆದರೆ (listen(sock, SSH_LISTEN_BACKLOG) == -1) {
			error("listen [%s]:%s: %.100s", ntop, strport,
			    strerror(errno));
			close(sock);
			ಮುಂದುವರಿ;
		}

		/*
		 * fwd->listen_port == 0 requests a dynamically allocated port -
		 * record what we got.
		 */
		ಆದರೆ (type == SSH_CHANNEL_RPORT_LISTENER &&
		    fwd->listen_ಪೋರ್ಟ್ == 0 &&
		    allocated_listen_ಪೋರ್ಟ್ != ಖಾಲಿ &&
		    *allocated_listen_ಪೋರ್ಟ್ == 0) {
			*allocated_listen_ಪೋರ್ಟ್ = get_local_ಪೋರ್ಟ್(sock);
			debug("Allocated listen port %d",
			    *allocated_listen_ಪೋರ್ಟ್);
		}

		/* Allocate a channel number for the socket. */
		c = channel_new(ssh, "port-listener", type, sock, sock, -1,
		    CHAN_TCP_ಕಿಟಕಿ_DEFAULT, CHAN_TCP_PACKET_DEFAULT,
		    0, "port listener", 1);
		c->ಮಾರ್ಗ = xstrdup(host);
		c->host_ಪೋರ್ಟ್ = fwd->connect_ಪೋರ್ಟ್;
		c->listening_addr = addr == ಖಾಲಿ ? ಖಾಲಿ : xstrdup(addr);
		ಆದರೆ (fwd->listen_ಪೋರ್ಟ್ == 0 && allocated_listen_ಪೋರ್ಟ್ != ಖಾಲಿ &&
		    !(ssh->compat & SSH_BUG_DYNAMIC_RPORT))
			c->listening_ಪೋರ್ಟ್ = *allocated_listen_ಪೋರ್ಟ್;
		ಇಲ್ಲದಿದ್ದರೆ
			c->listening_ಪೋರ್ಟ್ = fwd->listen_ಪೋರ್ಟ್;
		success = 1;
	}
	ಆದರೆ (success == 0)
		error_f("cannot listen to port: %d", fwd->listen_ಪೋರ್ಟ್);
	freeaddrinfo(aitop);
	ಹಿಂತಿರುಗಿ success;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
channel_ಸಿದ್ಧತೆ_fwd_listener_streamlocal(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ type,
    ರಚನೆ Forward *fwd, ರಚನೆ ForwardOptions *fwd_opts)
{
	ರಚನೆ sockaddr_un sunaddr;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ;
	Channel *c;
	ಪೂರ್ಣಾಂಕ ಪೋರ್ಟ್, sock;
	ಬಹುಲಕ_t omask;

	ಆಯ್ಕೆ (type) {
	ಸ್ಥಿತಿ SSH_CHANNEL_UNIX_LISTENER:
		ಆದರೆ (fwd->connect_ಮಾರ್ಗ != ಖಾಲಿ) {
			ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(fwd->connect_ಮಾರ್ಗ) > ಗಾತ್ರ(sunaddr.sun_ಮಾರ್ಗ)) {
				error("Local connecting path too long: %s",
				    fwd->connect_ಮಾರ್ಗ);
				ಹಿಂತಿರುಗಿ 0;
			}
			ಮಾರ್ಗ = fwd->connect_ಮಾರ್ಗ;
			ಪೋರ್ಟ್ = ಪೋರ್ಟ್_STREAMLOCAL;
		} ಇಲ್ಲದಿದ್ದರೆ {
			ಆದರೆ (fwd->connect_host == ಖಾಲಿ) {
				error("No forward host name.");
				ಹಿಂತಿರುಗಿ 0;
			}
			ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(fwd->connect_host) >= NI_MAXHOST) {
				error("Forward host name too long.");
				ಹಿಂತಿರುಗಿ 0;
			}
			ಮಾರ್ಗ = fwd->connect_host;
			ಪೋರ್ಟ್ = fwd->connect_ಪೋರ್ಟ್;
		}
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ SSH_CHANNEL_RUNIX_LISTENER:
		ಮಾರ್ಗ = fwd->listen_ಮಾರ್ಗ;
		ಪೋರ್ಟ್ = ಪೋರ್ಟ್_STREAMLOCAL;
		ನಿಲ್ಲಿಸು;
	ಪೂರ್ವನಿಯೋಜಿತ:
		error_f("unexpected channel type %d", type);
		ಹಿಂತಿರುಗಿ 0;
	}

	ಆದರೆ (fwd->listen_ಮಾರ್ಗ == ಖಾಲಿ) {
		error("No forward path name.");
		ಹಿಂತಿರುಗಿ 0;
	}
	ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(fwd->listen_ಮಾರ್ಗ) > ಗಾತ್ರ(sunaddr.sun_ಮಾರ್ಗ)) {
		error("Local listening path too long: %s", fwd->listen_ಮಾರ್ಗ);
		ಹಿಂತಿರುಗಿ 0;
	}

	debug3_f("type %d path %s", type, fwd->listen_ಮಾರ್ಗ);

	/* Start a Unix domain listener. */
	omask = umask(fwd_opts->streamlocal_bind_ಮುಖವಾಡ);
	sock = unix_listener(fwd->listen_ಮಾರ್ಗ, SSH_LISTEN_BACKLOG,
	    fwd_opts->streamlocal_bind_unlink);
	umask(omask);
	ಆದರೆ (sock < 0)
		ಹಿಂತಿರುಗಿ 0;

	debug("Local forwarding listening on path %s.", fwd->listen_ಮಾರ್ಗ);

	/* Allocate a channel number for the socket. */
	c = channel_new(ssh, "unix-listener", type, sock, sock, -1,
	    CHAN_TCP_ಕಿಟಕಿ_DEFAULT, CHAN_TCP_PACKET_DEFAULT,
	    0, "unix listener", 1);
	c->ಮಾರ್ಗ = xstrdup(ಮಾರ್ಗ);
	c->host_ಪೋರ್ಟ್ = ಪೋರ್ಟ್;
	c->listening_ಪೋರ್ಟ್ = ಪೋರ್ಟ್_STREAMLOCAL;
	c->listening_addr = xstrdup(fwd->listen_ಮಾರ್ಗ);
	ಹಿಂತಿರುಗಿ 1;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
channel_cancel_rport_listener_tcpip(ರಚನೆ ssh *ssh,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host, u_short ಪೋರ್ಟ್)
{
	u_int i;
	ಪೂರ್ಣಾಂಕ ಸಿಕ್ಕಿತು = 0;

	ಗಾಗಿ (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		Channel *c = ssh->chanctxt->channels[i];
		ಆದರೆ (c == ಖಾಲಿ || c->type != SSH_CHANNEL_RPORT_LISTENER)
			ಮುಂದುವರಿ;
		ಆದರೆ (strcmp(c->ಮಾರ್ಗ, host) == 0 && c->listening_ಪೋರ್ಟ್ == ಪೋರ್ಟ್) {
			debug2_f("close channel %d", i);
			channel_free(ssh, c);
			ಸಿಕ್ಕಿತು = 1;
		}
	}

	ಹಿಂತಿರುಗಿ ಸಿಕ್ಕಿತು;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
channel_cancel_rport_listener_streamlocal(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ)
{
	u_int i;
	ಪೂರ್ಣಾಂಕ ಸಿಕ್ಕಿತು = 0;

	ಗಾಗಿ (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		Channel *c = ssh->chanctxt->channels[i];
		ಆದರೆ (c == ಖಾಲಿ || c->type != SSH_CHANNEL_RUNIX_LISTENER)
			ಮುಂದುವರಿ;
		ಆದರೆ (c->ಮಾರ್ಗ == ಖಾಲಿ)
			ಮುಂದುವರಿ;
		ಆದರೆ (strcmp(c->ಮಾರ್ಗ, ಮಾರ್ಗ) == 0) {
			debug2_f("close channel %d", i);
			channel_free(ssh, c);
			ಸಿಕ್ಕಿತು = 1;
		}
	}

	ಹಿಂತಿರುಗಿ ಸಿಕ್ಕಿತು;
}

ಪೂರ್ಣಾಂಕ
channel_cancel_rport_listener(ರಚನೆ ssh *ssh, ರಚನೆ Forward *fwd)
{
	ಆದರೆ (fwd->listen_ಮಾರ್ಗ != ಖಾಲಿ) {
		ಹಿಂತಿರುಗಿ channel_cancel_rport_listener_streamlocal(ssh,
		    fwd->listen_ಮಾರ್ಗ);
	} ಇಲ್ಲದಿದ್ದರೆ {
		ಹಿಂತಿರುಗಿ channel_cancel_rport_listener_tcpip(ssh,
		    fwd->listen_host, fwd->listen_ಪೋರ್ಟ್);
	}
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
channel_cancel_lport_listener_tcpip(ರಚನೆ ssh *ssh,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *lhost, u_short lport, ಪೂರ್ಣಾಂಕ cport,
    ರಚನೆ ForwardOptions *fwd_opts)
{
	u_int i;
	ಪೂರ್ಣಾಂಕ ಸಿಕ್ಕಿತು = 0;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *addr = channel_fwd_bind_addr(ssh, lhost, ಖಾಲಿ, 1, fwd_opts);

	ಗಾಗಿ (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		Channel *c = ssh->chanctxt->channels[i];
		ಆದರೆ (c == ಖಾಲಿ || c->type != SSH_CHANNEL_ಪೋರ್ಟ್_LISTENER)
			ಮುಂದುವರಿ;
		ಆದರೆ (c->listening_ಪೋರ್ಟ್ != lport)
			ಮುಂದುವರಿ;
		ಆದರೆ (cport == CHANNEL_CANCEL_ಪೋರ್ಟ್_STATIC) {
			/* skip dynamic forwardings */
			ಆದರೆ (c->host_ಪೋರ್ಟ್ == 0)
				ಮುಂದುವರಿ;
		} ಇಲ್ಲದಿದ್ದರೆ {
			ಆದರೆ (c->host_ಪೋರ್ಟ್ != cport)
				ಮುಂದುವರಿ;
		}
		ಆದರೆ ((c->listening_addr == ಖಾಲಿ && addr != ಖಾಲಿ) ||
		    (c->listening_addr != ಖಾಲಿ && addr == ಖಾಲಿ))
			ಮುಂದುವರಿ;
		ಆದರೆ (addr == ಖಾಲಿ || strcmp(c->listening_addr, addr) == 0) {
			debug2_f("close channel %d", i);
			channel_free(ssh, c);
			ಸಿಕ್ಕಿತು = 1;
		}
	}

	ಹಿಂತಿರುಗಿ ಸಿಕ್ಕಿತು;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
channel_cancel_lport_listener_streamlocal(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ)
{
	u_int i;
	ಪೂರ್ಣಾಂಕ ಸಿಕ್ಕಿತು = 0;

	ಆದರೆ (ಮಾರ್ಗ == ಖಾಲಿ) {
		error_f("no path specified.");
		ಹಿಂತಿರುಗಿ 0;
	}

	ಗಾಗಿ (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		Channel *c = ssh->chanctxt->channels[i];
		ಆದರೆ (c == ಖಾಲಿ || c->type != SSH_CHANNEL_UNIX_LISTENER)
			ಮುಂದುವರಿ;
		ಆದರೆ (c->listening_addr == ಖಾಲಿ)
			ಮುಂದುವರಿ;
		ಆದರೆ (strcmp(c->listening_addr, ಮಾರ್ಗ) == 0) {
			debug2_f("close channel %d", i);
			channel_free(ssh, c);
			ಸಿಕ್ಕಿತು = 1;
		}
	}

	ಹಿಂತಿರುಗಿ ಸಿಕ್ಕಿತು;
}

ಪೂರ್ಣಾಂಕ
channel_cancel_lport_listener(ರಚನೆ ssh *ssh,
    ರಚನೆ Forward *fwd, ಪೂರ್ಣಾಂಕ cport, ರಚನೆ ForwardOptions *fwd_opts)
{
	ಆದರೆ (fwd->listen_ಮಾರ್ಗ != ಖಾಲಿ) {
		ಹಿಂತಿರುಗಿ channel_cancel_lport_listener_streamlocal(ssh,
		    fwd->listen_ಮಾರ್ಗ);
	} ಇಲ್ಲದಿದ್ದರೆ {
		ಹಿಂತಿರುಗಿ channel_cancel_lport_listener_tcpip(ssh,
		    fwd->listen_host, fwd->listen_ಪೋರ್ಟ್, cport, fwd_opts);
	}
}

/* protocol local port fwd, used by ssh */
ಪೂರ್ಣಾಂಕ
channel_ಸಿದ್ಧತೆ_local_fwd_listener(ರಚನೆ ssh *ssh,
    ರಚನೆ Forward *fwd, ರಚನೆ ForwardOptions *fwd_opts)
{
	ಆದರೆ (fwd->listen_ಮಾರ್ಗ != ಖಾಲಿ) {
		ಹಿಂತಿರುಗಿ channel_ಸಿದ್ಧತೆ_fwd_listener_streamlocal(ssh,
		    SSH_CHANNEL_UNIX_LISTENER, fwd, fwd_opts);
	} ಇಲ್ಲದಿದ್ದರೆ {
		ಹಿಂತಿರುಗಿ channel_ಸಿದ್ಧತೆ_fwd_listener_tcpip(ssh,
		    SSH_CHANNEL_ಪೋರ್ಟ್_LISTENER, fwd, ಖಾಲಿ, fwd_opts);
	}
}

/* Matches a remote forwarding permission against a requested forwarding */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
remote_open_ಹೊಂದಿಕೆ(ರಚನೆ permission *allowed_open, ರಚನೆ Forward *fwd)
{
	ಪೂರ್ಣಾಂಕ ret;
	ಅಕ್ಷರ *lhost;

	/* XXX add ACLs for streamlocal */
	ಆದರೆ (fwd->listen_ಮಾರ್ಗ != ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 1;

	ಆದರೆ (fwd->listen_host == ಖಾಲಿ || allowed_open->listen_host == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 0;

	ಆದರೆ (allowed_open->listen_ಪೋರ್ಟ್ != FWD_PERMIT_ANY_ಪೋರ್ಟ್ &&
	    allowed_open->listen_ಪೋರ್ಟ್ != fwd->listen_ಪೋರ್ಟ್)
		ಹಿಂತಿರುಗಿ 0;

	/* Match hostnames case-insensitively */
	lhost = xstrdup(fwd->listen_host);
	lowercase(lhost);
	ret = ಹೊಂದಿಕೆ_ನಮೂನೆ(lhost, allowed_open->listen_host);
	ಬಿಡುಗಡೆ(lhost);

	ಹಿಂತಿರುಗಿ ret;
}

/* Checks whether a requested remote forwarding is permitted */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
check_rfwd_permission(ರಚನೆ ssh *ssh, ರಚನೆ Forward *fwd)
{
	ರಚನೆ ssh_channels *sc = ssh->chanctxt;
	ರಚನೆ permission_ಗಣ *pset = &sc->remote_perms;
	u_int i, permit, permit_adm = 1;
	ರಚನೆ permission *perm;

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ SKIP_PRIVDROP
	ಆದರೆ (fwd->listen_ಮಾರ್ಗ != ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ (fwd->listen_ಪೋರ್ಟ್ != 0 && fwd->listen_ಪೋರ್ಟ್ < 1024)
		ಹಿಂತಿರುಗಿ 0;
#ಆದರೆ_ಅಂತ್ಯ

	/* XXX apply GatewayPorts override before checking? */

	permit = pset->all_permitted;
	ಆದರೆ (!permit) {
		ಗಾಗಿ (i = 0; i < pset->ಅಂಕೆ_permitted_user; i++) {
			perm = &pset->permitted_user[i];
			ಆದರೆ (remote_open_ಹೊಂದಿಕೆ(perm, fwd)) {
				permit = 1;
				ನಿಲ್ಲಿಸು;
			}
		}
	}

	ಆದರೆ (pset->ಅಂಕೆ_permitted_admin > 0) {
		permit_adm = 0;
		ಗಾಗಿ (i = 0; i < pset->ಅಂಕೆ_permitted_admin; i++) {
			perm = &pset->permitted_admin[i];
			ಆದರೆ (remote_open_ಹೊಂದಿಕೆ(perm, fwd)) {
				permit_adm = 1;
				ನಿಲ್ಲಿಸು;
			}
		}
	}

	ಹಿಂತಿರುಗಿ permit && permit_adm;
}

/* protocol v2 remote port fwd, used by sshd */
ಪೂರ್ಣಾಂಕ
channel_ಸಿದ್ಧತೆ_remote_fwd_listener(ರಚನೆ ssh *ssh, ರಚನೆ Forward *fwd,
    ಪೂರ್ಣಾಂಕ *allocated_listen_ಪೋರ್ಟ್, ರಚನೆ ForwardOptions *fwd_opts)
{
	ಆದರೆ (!check_rfwd_permission(ssh, fwd)) {
		ssh_packet_send_debug(ssh, "port forwarding refused");
		ಆದರೆ (fwd->listen_ಮಾರ್ಗ != ಖಾಲಿ)
			/* XXX always allowed, see remote_open_match() */
			logit("Received request from %.100s port %d to "
			    "remote forward to path \"%.100s\", "
			    "but the request was denied.",
			    ssh_remote_ipaddr(ssh), ssh_remote_ಪೋರ್ಟ್(ssh),
			    fwd->listen_ಮಾರ್ಗ);
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ(fwd->listen_host != ಖಾಲಿ)
			logit("Received request from %.100s port %d to "
			    "remote forward to host %.100s port %d, "
			    "but the request was denied.",
			    ssh_remote_ipaddr(ssh), ssh_remote_ಪೋರ್ಟ್(ssh),
			    fwd->listen_host, fwd->listen_ಪೋರ್ಟ್ );
		ಇಲ್ಲದಿದ್ದರೆ
			logit("Received request from %.100s port %d to remote "
			    "forward, but the request was denied.",
			    ssh_remote_ipaddr(ssh), ssh_remote_ಪೋರ್ಟ್(ssh));
		ಹಿಂತಿರುಗಿ 0;
	}
	ಆದರೆ (fwd->listen_ಮಾರ್ಗ != ಖಾಲಿ) {
		ಹಿಂತಿರುಗಿ channel_ಸಿದ್ಧತೆ_fwd_listener_streamlocal(ssh,
		    SSH_CHANNEL_RUNIX_LISTENER, fwd, fwd_opts);
	} ಇಲ್ಲದಿದ್ದರೆ {
		ಹಿಂತಿರುಗಿ channel_ಸಿದ್ಧತೆ_fwd_listener_tcpip(ssh,
		    SSH_CHANNEL_RPORT_LISTENER, fwd, allocated_listen_ಪೋರ್ಟ್,
		    fwd_opts);
	}
}

/*
 * Translate the requested rfwd listen host to something usable for
 * this server.
 */
ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *
channel_rfwd_bind_host(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *listen_host)
{
	ಆದರೆ (listen_host == ಖಾಲಿ) {
		ಹಿಂತಿರುಗಿ "localhost";
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (*listen_host == '\0' || strcmp(listen_host, "*") == 0) {
		ಹಿಂತಿರುಗಿ "";
	} ಇಲ್ಲದಿದ್ದರೆ
		ಹಿಂತಿರುಗಿ listen_host;
}

/*
 * Initiate forwarding of connections to port "port" on remote host through
 * the secure channel to host:port from local side.
 * Returns handle (index) for updating the dynamic listen port with
 * channel_update_permission().
 */
ಪೂರ್ಣಾಂಕ
channel_request_remote_forwarding(ರಚನೆ ssh *ssh, ರಚನೆ Forward *fwd)
{
	ಪೂರ್ಣಾಂಕ r, success = 0, idx = -1;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host_ಗಮ್ಯ_connect, *listen_host, *listen_ಮಾರ್ಗ;
	ಪೂರ್ಣಾಂಕ ಪೋರ್ಟ್_ಗಮ್ಯ_connect, listen_ಪೋರ್ಟ್;

	/* Send the forward request to the remote side. */
	ಆದರೆ (fwd->listen_ಮಾರ್ಗ != ಖಾಲಿ) {
		ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh, SSH2_ಸಂದೇಶ_GLOBAL_REQUEST)) != 0 ||
		    (r = sshpkt_put_cstring(ssh,
		    "streamlocal-forward@openssh.com")) != 0 ||
		    (r = sshpkt_put_u8(ssh, 1)) != 0 || /* want reply */
		    (r = sshpkt_put_cstring(ssh, fwd->listen_ಮಾರ್ಗ)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			fatal_fr(r, "request streamlocal");
	} ಇಲ್ಲದಿದ್ದರೆ {
		ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh, SSH2_ಸಂದೇಶ_GLOBAL_REQUEST)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "tcpip-forward")) != 0 ||
		    (r = sshpkt_put_u8(ssh, 1)) != 0 || /* want reply */
		    (r = sshpkt_put_cstring(ssh,
		    channel_rfwd_bind_host(fwd->listen_host))) != 0 ||
		    (r = sshpkt_put_u32(ssh, fwd->listen_ಪೋರ್ಟ್)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			fatal_fr(r, "request tcpip-forward");
	}
	/* Assume that server accepts the request */
	success = 1;
	ಆದರೆ (success) {
		/* Record that connection to this host/port is permitted. */
		host_ಗಮ್ಯ_connect = listen_host = listen_ಮಾರ್ಗ = ಖಾಲಿ;
		ಪೋರ್ಟ್_ಗಮ್ಯ_connect = listen_ಪೋರ್ಟ್ = 0;
		ಆದರೆ (fwd->connect_ಮಾರ್ಗ != ಖಾಲಿ) {
			host_ಗಮ್ಯ_connect = fwd->connect_ಮಾರ್ಗ;
			ಪೋರ್ಟ್_ಗಮ್ಯ_connect = ಪೋರ್ಟ್_STREAMLOCAL;
		} ಇಲ್ಲದಿದ್ದರೆ {
			host_ಗಮ್ಯ_connect = fwd->connect_host;
			ಪೋರ್ಟ್_ಗಮ್ಯ_connect = fwd->connect_ಪೋರ್ಟ್;
		}
		ಆದರೆ (fwd->listen_ಮಾರ್ಗ != ಖಾಲಿ) {
			listen_ಮಾರ್ಗ = fwd->listen_ಮಾರ್ಗ;
			listen_ಪೋರ್ಟ್ = ಪೋರ್ಟ್_STREAMLOCAL;
		} ಇಲ್ಲದಿದ್ದರೆ {
			listen_host = fwd->listen_host;
			listen_ಪೋರ್ಟ್ = fwd->listen_ಪೋರ್ಟ್;
		}
		idx = permission_ಗಣ_ಕೂಡಿಸು(ssh, FORWARD_USER, FORWARD_LOCAL,
		    host_ಗಮ್ಯ_connect, ಪೋರ್ಟ್_ಗಮ್ಯ_connect,
		    listen_host, listen_ಮಾರ್ಗ, listen_ಪೋರ್ಟ್, ಖಾಲಿ);
	}
	ಹಿಂತಿರುಗಿ idx;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
open_ಹೊಂದಿಕೆ(ರಚನೆ permission *allowed_open, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *requestedhost,
    ಪೂರ್ಣಾಂಕ requestedport)
{
	ಆದರೆ (allowed_open->host_ಗಮ್ಯ_connect == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ (allowed_open->ಪೋರ್ಟ್_ಗಮ್ಯ_connect != FWD_PERMIT_ANY_ಪೋರ್ಟ್ &&
	    allowed_open->ಪೋರ್ಟ್_ಗಮ್ಯ_connect != requestedport)
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ (strcmp(allowed_open->host_ಗಮ್ಯ_connect, FWD_PERMIT_ANY_HOST) != 0 &&
	    strcmp(allowed_open->host_ಗಮ್ಯ_connect, requestedhost) != 0)
		ಹಿಂತಿರುಗಿ 0;
	ಹಿಂತಿರುಗಿ 1;
}

/*
 * Note that in the listen host/port case
 * we don't support FWD_PERMIT_ANY_PORT and
 * need to translate between the configured-host (listen_host)
 * and what we've sent to the remote server (channel_rfwd_bind_host)
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
open_listen_ಹೊಂದಿಕೆ_tcpip(ರಚನೆ permission *allowed_open,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *requestedhost, u_short requestedport, ಪೂರ್ಣಾಂಕ translate)
{
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *allowed_host;

	ಆದರೆ (allowed_open->host_ಗಮ್ಯ_connect == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ (allowed_open->listen_ಪೋರ್ಟ್ != requestedport)
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ (!translate && allowed_open->listen_host == ಖಾಲಿ &&
	    requestedhost == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 1;
	allowed_host = translate ?
	    channel_rfwd_bind_host(allowed_open->listen_host) :
	    allowed_open->listen_host;
	ಆದರೆ (allowed_host == ಖಾಲಿ || requestedhost == ಖಾಲಿ ||
	    strcmp(allowed_host, requestedhost) != 0)
		ಹಿಂತಿರುಗಿ 0;
	ಹಿಂತಿರುಗಿ 1;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
open_listen_ಹೊಂದಿಕೆ_streamlocal(ರಚನೆ permission *allowed_open,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *requestedpath)
{
	ಆದರೆ (allowed_open->host_ಗಮ್ಯ_connect == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ (allowed_open->listen_ಪೋರ್ಟ್ != ಪೋರ್ಟ್_STREAMLOCAL)
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ (allowed_open->listen_ಮಾರ್ಗ == ಖಾಲಿ ||
	    strcmp(allowed_open->listen_ಮಾರ್ಗ, requestedpath) != 0)
		ಹಿಂತಿರುಗಿ 0;
	ಹಿಂತಿರುಗಿ 1;
}

/*
 * Request cancellation of remote forwarding of connection host:port from
 * local side.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
channel_request_rforward_cancel_tcpip(ರಚನೆ ssh *ssh,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host, u_short ಪೋರ್ಟ್)
{
	ರಚನೆ ssh_channels *sc = ssh->chanctxt;
	ರಚನೆ permission_ಗಣ *pset = &sc->local_perms;
	ಪೂರ್ಣಾಂಕ r;
	u_int i;
	ರಚನೆ permission *perm = ಖಾಲಿ;

	ಗಾಗಿ (i = 0; i < pset->ಅಂಕೆ_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		ಆದರೆ (open_listen_ಹೊಂದಿಕೆ_tcpip(perm, host, ಪೋರ್ಟ್, 0))
			ನಿಲ್ಲಿಸು;
		perm = ಖಾಲಿ;
	}
	ಆದರೆ (perm == ಖಾಲಿ) {
		debug_f("requested forward not found");
		ಹಿಂತಿರುಗಿ -1;
	}
	ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh, SSH2_ಸಂದೇಶ_GLOBAL_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "cancel-tcpip-forward")) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 || /* want reply */
	    (r = sshpkt_put_cstring(ssh, channel_rfwd_bind_host(host))) != 0 ||
	    (r = sshpkt_put_u32(ssh, ಪೋರ್ಟ್)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send cancel");

	fwd_perm_clear(perm); /* unregister */

	ಹಿಂತಿರುಗಿ 0;
}

/*
 * Request cancellation of remote forwarding of Unix domain socket
 * path from local side.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
channel_request_rforward_cancel_streamlocal(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ)
{
	ರಚನೆ ssh_channels *sc = ssh->chanctxt;
	ರಚನೆ permission_ಗಣ *pset = &sc->local_perms;
	ಪೂರ್ಣಾಂಕ r;
	u_int i;
	ರಚನೆ permission *perm = ಖಾಲಿ;

	ಗಾಗಿ (i = 0; i < pset->ಅಂಕೆ_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		ಆದರೆ (open_listen_ಹೊಂದಿಕೆ_streamlocal(perm, ಮಾರ್ಗ))
			ನಿಲ್ಲಿಸು;
		perm = ಖಾಲಿ;
	}
	ಆದರೆ (perm == ಖಾಲಿ) {
		debug_f("requested forward not found");
		ಹಿಂತಿರುಗಿ -1;
	}
	ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh, SSH2_ಸಂದೇಶ_GLOBAL_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh,
	    "cancel-streamlocal-forward@openssh.com")) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 || /* want reply */
	    (r = sshpkt_put_cstring(ssh, ಮಾರ್ಗ)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send cancel");

	fwd_perm_clear(perm); /* unregister */

	ಹಿಂತಿರುಗಿ 0;
}

/*
 * Request cancellation of remote forwarding of a connection from local side.
 */
ಪೂರ್ಣಾಂಕ
channel_request_rforward_cancel(ರಚನೆ ssh *ssh, ರಚನೆ Forward *fwd)
{
	ಆದರೆ (fwd->listen_ಮಾರ್ಗ != ಖಾಲಿ) {
		ಹಿಂತಿರುಗಿ channel_request_rforward_cancel_streamlocal(ssh,
		    fwd->listen_ಮಾರ್ಗ);
	} ಇಲ್ಲದಿದ್ದರೆ {
		ಹಿಂತಿರುಗಿ channel_request_rforward_cancel_tcpip(ssh,
		    fwd->listen_host,
		    fwd->listen_ಪೋರ್ಟ್ ? fwd->listen_ಪೋರ್ಟ್ : fwd->allocated_ಪೋರ್ಟ್);
	}
}

/*
 * Permits opening to any host/port if permitted_user[] is empty.  This is
 * usually called by the server, because the user could connect to any port
 * anyway, and the server has no way to know but to trust the client anyway.
 */
ಶೂನ್ಯ
channel_permit_all(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ where)
{
	ರಚನೆ permission_ಗಣ *pset = permission_ಗಣ_get(ssh, where);

	ಆದರೆ (pset->ಅಂಕೆ_permitted_user == 0)
		pset->all_permitted = 1;
}

/*
 * Permit the specified host/port for forwarding.
 */
ಶೂನ್ಯ
channel_ಕೂಡಿಸು_permission(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ who, ಪೂರ್ಣಾಂಕ where,
    ಅಕ್ಷರ *host, ಪೂರ್ಣಾಂಕ ಪೋರ್ಟ್)
{
	ಪೂರ್ಣಾಂಕ local = where == FORWARD_LOCAL;
	ರಚನೆ permission_ಗಣ *pset = permission_ಗಣ_get(ssh, where);

	debug("allow %s forwarding to host %s port %d",
	    fwd_ident(who, where), host, ಪೋರ್ಟ್);
	/*
	 * Remote forwards set listen_host/port, local forwards set
	 * host/port_to_connect.
	 */
	permission_ಗಣ_ಕೂಡಿಸು(ssh, who, where,
	    local ? host : ಖಾಲಿ, local ? ಪೋರ್ಟ್ : 0,
	    local ? ಖಾಲಿ : host, ಖಾಲಿ, local ? 0 : ಪೋರ್ಟ್, ಖಾಲಿ);
	pset->all_permitted = 0;
}

/*
 * Administratively disable forwarding.
 */
ಶೂನ್ಯ
channel_disable_admin(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ where)
{
	channel_clear_permission(ssh, FORWARD_ADM, where);
	permission_ಗಣ_ಕೂಡಿಸು(ssh, FORWARD_ADM, where,
	    ಖಾಲಿ, 0, ಖಾಲಿ, ಖಾಲಿ, 0, ಖಾಲಿ);
}

/*
 * Clear a list of permitted opens.
 */
ಶೂನ್ಯ
channel_clear_permission(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ who, ಪೂರ್ಣಾಂಕ where)
{
	ರಚನೆ permission **permp;
	u_int i, *npermp;

	permission_ಗಣ_get_array(ssh, who, where, &permp, &npermp);
	ಗಾಗಿ (i = 0; i < *npermp; i++)
		fwd_perm_clear((*permp) + i);
	ಬಿಡುಗಡೆ(*permp);
	*permp = ಖಾಲಿ;
	*npermp = 0;
}

/*
 * Update the listen port for a dynamic remote forward, after
 * the actual 'newport' has been allocated. If 'newport' < 0 is
 * passed then they entry will be invalidated.
 */
ಶೂನ್ಯ
channel_update_permission(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ idx, ಪೂರ್ಣಾಂಕ newport)
{
	ರಚನೆ permission_ಗಣ *pset = &ssh->chanctxt->local_perms;

	ಆದರೆ (idx < 0 || (u_int)idx >= pset->ಅಂಕೆ_permitted_user) {
		debug_f("index out of range: %d num_permitted_user %d",
		    idx, pset->ಅಂಕೆ_permitted_user);
		ಹಿಂತಿರುಗಿ;
	}
	debug("%s allowed port %d for forwarding to host %s port %d",
	    newport > 0 ? "Updating" : "Removing",
	    newport,
	    pset->permitted_user[idx].host_ಗಮ್ಯ_connect,
	    pset->permitted_user[idx].ಪೋರ್ಟ್_ಗಮ್ಯ_connect);
	ಆದರೆ (newport <= 0)
		fwd_perm_clear(&pset->permitted_user[idx]);
	ಇಲ್ಲದಿದ್ದರೆ {
		pset->permitted_user[idx].listen_ಪೋರ್ಟ್ =
		    (ssh->compat & SSH_BUG_DYNAMIC_RPORT) ? 0 : newport;
	}
}

/* Try to start non-blocking connect to next host in cctx list */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
connect_ಮುಂದಿನ(ರಚನೆ ssh *ssh, ರಚನೆ channel_connect *cctx)
{
	ಪೂರ್ಣಾಂಕ sock, sock_is_ಜಾಲ, saved_errno;
	ರಚನೆ sockaddr_un *sunaddr;
	ಅಕ್ಷರ ntop[NI_MAXHOST];
	ಅಕ್ಷರ strport[ಗರಿಷ್ಠ(NI_MAXSERV, ಗಾತ್ರ(sunaddr->sun_ಮಾರ್ಗ))];

	ಗಾಗಿ (; cctx->ai; cctx->ai = cctx->ai->ai_next) {
		sock_is_ಜಾಲ = 0;
		ಆಯ್ಕೆ (cctx->ai->ai_family) {
		ಸ್ಥಿತಿ AF_UNIX:
			/* unix:pathname instead of host:port */
			sunaddr = (ರಚನೆ sockaddr_un *)cctx->ai->ai_addr;
			strlcpy(ntop, "unix", ಗಾತ್ರ(ntop));
			strlcpy(strport, sunaddr->sun_ಮಾರ್ಗ, ಗಾತ್ರ(strport));
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ AF_INET:
		ಸ್ಥಿತಿ AF_INET6:
			ಆದರೆ (getnameinfo(cctx->ai->ai_addr, cctx->ai->ai_addrlen,
			    ntop, ಗಾತ್ರ(ntop), strport, ಗಾತ್ರ(strport),
			    NI_NUMERICHOST|NI_NUMERICSERV) != 0) {
				error_f("getnameinfo failed");
				ಮುಂದುವರಿ;
			}
			sock_is_ಜಾಲ = 1;
			ನಿಲ್ಲಿಸು;
		ಪೂರ್ವನಿಯೋಜಿತ:
			ಮುಂದುವರಿ;
		}
		debug_f("start for host %.100s ([%.100s]:%s)",
		    cctx->host, ntop, strport);
		ಆದರೆ ((sock = socket(cctx->ai->ai_family, cctx->ai->ai_socktype,
		    cctx->ai->ai_protocol)) == -1) {
			ಆದರೆ (cctx->ai->ai_next == ಖಾಲಿ)
				error("socket: %.100s", strerror(errno));
			ಇಲ್ಲದಿದ್ದರೆ
				verbose("socket: %.100s", strerror(errno));
			ಮುಂದುವರಿ;
		}
		ಆದರೆ (ಗಣ_nonblock(sock) == -1)
			fatal_f("set_nonblock(%d)", sock);
		ಆದರೆ (sock_is_ಜಾಲ && ssh->chanctxt->want_tcp_keepalive)
			ಗಣ_keepalive(sock); /* logs errors */
		ಆದರೆ (connect(sock, cctx->ai->ai_addr,
		    cctx->ai->ai_addrlen) == -1 && errno != EINPROGRESS) {
			debug_f("host %.100s ([%.100s]:%s): %.100s",
			    cctx->host, ntop, strport, strerror(errno));
			saved_errno = errno;
			close(sock);
			errno = saved_errno;
			ಮುಂದುವರಿ;	/* fail -- try next */
		}
		ಆದರೆ (cctx->ai->ai_family != AF_UNIX)
			ಗಣ_nodelay(sock);
		debug_f("connect host %.100s ([%.100s]:%s) in progress, fd=%d",
		    cctx->host, ntop, strport, sock);
		cctx->ai = cctx->ai->ai_next;
		ಹಿಂತಿರುಗಿ sock;
	}
	ಹಿಂತಿರುಗಿ -1;
}

/*
 * Return connecting socket to remote host:port or local socket path,
 * passing back the failure reason if appropriate.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
connect_ಗಮ್ಯ_helper(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name, ಪೂರ್ಣಾಂಕ ಪೋರ್ಟ್, ಪೂರ್ಣಾಂಕ socktype,
    ಅಕ್ಷರ *ctype, ಅಕ್ಷರ *rname, ರಚನೆ channel_connect *cctx,
    ಪೂರ್ಣಾಂಕ *reason, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ **errmsg)
{
	ರಚನೆ addrinfo hints;
	ಪೂರ್ಣಾಂಕ gaierr;
	ಪೂರ್ಣಾಂಕ sock = -1;
	ಅಕ್ಷರ strport[NI_MAXSERV];

	ಆದರೆ (ಪೋರ್ಟ್ == ಪೋರ್ಟ್_STREAMLOCAL) {
		ರಚನೆ sockaddr_un *sunaddr;
		ರಚನೆ addrinfo *ai;

		ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(name) > ಗಾತ್ರ(sunaddr->sun_ಮಾರ್ಗ)) {
			error("%.100s: %.100s", name, strerror(ENAMETOOLONG));
			ಹಿಂತಿರುಗಿ -1;
		}

		/*
		 * Fake up a struct addrinfo for AF_UNIX connections.
		 * free_connect_ctx() must check ai_family
		 * and use free() not freeaddrinfo() for AF_UNIX.
		 */
		ai = xcalloc(1, ಗಾತ್ರ(*ai) + ಗಾತ್ರ(*sunaddr));
		ai->ai_addr = (ರಚನೆ sockaddr *)(ai + 1);
		ai->ai_addrlen = ಗಾತ್ರ(*sunaddr);
		ai->ai_family = AF_UNIX;
		ai->ai_socktype = socktype;
		ai->ai_protocol = PF_UNSPEC;
		sunaddr = (ರಚನೆ sockaddr_un *)ai->ai_addr;
		sunaddr->sun_family = AF_UNIX;
		strlcpy(sunaddr->sun_ಮಾರ್ಗ, name, ಗಾತ್ರ(sunaddr->sun_ಮಾರ್ಗ));
		cctx->aitop = ai;
	} ಇಲ್ಲದಿದ್ದರೆ {
		memset(&hints, 0, ಗಾತ್ರ(hints));
		hints.ai_family = ssh->chanctxt->IPv4or6;
		hints.ai_socktype = socktype;
		snprintf(strport, ಗಾತ್ರ strport, "%d", ಪೋರ್ಟ್);
		ಆದರೆ ((gaierr = getaddrinfo(name, strport, &hints, &cctx->aitop))
		    != 0) {
			ಆದರೆ (errmsg != ಖಾಲಿ)
				*errmsg = ssh_gai_strerror(gaierr);
			ಆದರೆ (reason != ಖಾಲಿ)
				*reason = SSH2_OPEN_CONNECT_FAILED;
			error("connect_to %.100s: unknown host (%s)", name,
			    ssh_gai_strerror(gaierr));
			ಹಿಂತಿರುಗಿ -1;
		}
	}

	cctx->host = xstrdup(name);
	cctx->ಪೋರ್ಟ್ = ಪೋರ್ಟ್;
	cctx->ai = cctx->aitop;

	ಆದರೆ ((sock = connect_ಮುಂದಿನ(ssh, cctx)) == -1) {
		error("connect to %.100s port %d failed: %s",
		    name, ಪೋರ್ಟ್, strerror(errno));
		ಹಿಂತಿರುಗಿ -1;
	}

	ಹಿಂತಿರುಗಿ sock;
}

/* Return CONNECTING channel to remote host:port or local socket path */
ಸ್ಥಿರ Channel *
connect_ಗಮ್ಯ(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host, ಪೂರ್ಣಾಂಕ ಪೋರ್ಟ್,
    ಅಕ್ಷರ *ctype, ಅಕ್ಷರ *rname)
{
	ರಚನೆ channel_connect cctx;
	Channel *c;
	ಪೂರ್ಣಾಂಕ sock;

	memset(&cctx, 0, ಗಾತ್ರ(cctx));
	sock = connect_ಗಮ್ಯ_helper(ssh, host, ಪೋರ್ಟ್, SOCK_STREAM, ctype, rname,
	    &cctx, ಖಾಲಿ, ಖಾಲಿ);
	ಆದರೆ (sock == -1) {
		free_connect_ctx(&cctx);
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	c = channel_new(ssh, ctype, SSH_CHANNEL_CONNECTING, sock, sock, -1,
	    CHAN_TCP_ಕಿಟಕಿ_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, rname, 1);
	c->host_ಪೋರ್ಟ್ = ಪೋರ್ಟ್;
	c->ಮಾರ್ಗ = xstrdup(host);
	c->connect_ctx = xmalloc(ಗಾತ್ರ(cctx));
	ಸ್ಮರಣೆ_ನಕಲು(c->connect_ctx, &cctx, ಗಾತ್ರ(cctx));

	ಹಿಂತಿರುಗಿ c;
}

/*
 * returns either the newly connected channel or the downstream channel
 * that needs to deal with this connection.
 */
Channel *
channel_connect_by_listen_ವಿಳಾಸ(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *listen_host,
    u_short listen_ಪೋರ್ಟ್, ಅಕ್ಷರ *ctype, ಅಕ್ಷರ *rname)
{
	ರಚನೆ ssh_channels *sc = ssh->chanctxt;
	ರಚನೆ permission_ಗಣ *pset = &sc->local_perms;
	u_int i;
	ರಚನೆ permission *perm;

	ಗಾಗಿ (i = 0; i < pset->ಅಂಕೆ_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		ಆದರೆ (open_listen_ಹೊಂದಿಕೆ_tcpip(perm,
		    listen_host, listen_ಪೋರ್ಟ್, 1)) {
			ಆದರೆ (perm->downstream)
				ಹಿಂತಿರುಗಿ perm->downstream;
			ಆದರೆ (perm->ಪೋರ್ಟ್_ಗಮ್ಯ_connect == 0)
				ಹಿಂತಿರುಗಿ rdynamic_connect_prepare(ssh,
				    ctype, rname);
			ಹಿಂತಿರುಗಿ connect_ಗಮ್ಯ(ssh,
			    perm->host_ಗಮ್ಯ_connect, perm->ಪೋರ್ಟ್_ಗಮ್ಯ_connect,
			    ctype, rname);
		}
	}
	error("WARNING: Server requests forwarding for unknown listen_port %d",
	    listen_ಪೋರ್ಟ್);
	ಹಿಂತಿರುಗಿ ಖಾಲಿ;
}

Channel *
channel_connect_by_listen_ಮಾರ್ಗ(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ,
    ಅಕ್ಷರ *ctype, ಅಕ್ಷರ *rname)
{
	ರಚನೆ ssh_channels *sc = ssh->chanctxt;
	ರಚನೆ permission_ಗಣ *pset = &sc->local_perms;
	u_int i;
	ರಚನೆ permission *perm;

	ಗಾಗಿ (i = 0; i < pset->ಅಂಕೆ_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		ಆದರೆ (open_listen_ಹೊಂದಿಕೆ_streamlocal(perm, ಮಾರ್ಗ)) {
			ಹಿಂತಿರುಗಿ connect_ಗಮ್ಯ(ssh,
			    perm->host_ಗಮ್ಯ_connect, perm->ಪೋರ್ಟ್_ಗಮ್ಯ_connect,
			    ctype, rname);
		}
	}
	error("WARNING: Server requests forwarding for unknown path %.100s",
	    ಮಾರ್ಗ);
	ಹಿಂತಿರುಗಿ ಖಾಲಿ;
}

/* Check if connecting to that port is permitted and connect. */
Channel *
channel_connect_ಗಮ್ಯ_ಪೋರ್ಟ್(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host, u_short ಪೋರ್ಟ್,
    ಅಕ್ಷರ *ctype, ಅಕ್ಷರ *rname, ಪೂರ್ಣಾಂಕ *reason, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ **errmsg)
{
	ರಚನೆ ssh_channels *sc = ssh->chanctxt;
	ರಚನೆ permission_ಗಣ *pset = &sc->local_perms;
	ರಚನೆ channel_connect cctx;
	Channel *c;
	u_int i, permit, permit_adm = 1;
	ಪೂರ್ಣಾಂಕ sock;
	ರಚನೆ permission *perm;

	permit = pset->all_permitted;
	ಆದರೆ (!permit) {
		ಗಾಗಿ (i = 0; i < pset->ಅಂಕೆ_permitted_user; i++) {
			perm = &pset->permitted_user[i];
			ಆದರೆ (open_ಹೊಂದಿಕೆ(perm, host, ಪೋರ್ಟ್)) {
				permit = 1;
				ನಿಲ್ಲಿಸು;
			}
		}
	}

	ಆದರೆ (pset->ಅಂಕೆ_permitted_admin > 0) {
		permit_adm = 0;
		ಗಾಗಿ (i = 0; i < pset->ಅಂಕೆ_permitted_admin; i++) {
			perm = &pset->permitted_admin[i];
			ಆದರೆ (open_ಹೊಂದಿಕೆ(perm, host, ಪೋರ್ಟ್)) {
				permit_adm = 1;
				ನಿಲ್ಲಿಸು;
			}
		}
	}

	ಆದರೆ (!permit || !permit_adm) {
		logit("Received request from %.100s port %d to connect to "
		    "host %.100s port %d, but the request was denied.",
		    ssh_remote_ipaddr(ssh), ssh_remote_ಪೋರ್ಟ್(ssh), host, ಪೋರ್ಟ್);
		ಆದರೆ (reason != ಖಾಲಿ)
			*reason = SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED;
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}

	memset(&cctx, 0, ಗಾತ್ರ(cctx));
	sock = connect_ಗಮ್ಯ_helper(ssh, host, ಪೋರ್ಟ್, SOCK_STREAM, ctype, rname,
	    &cctx, reason, errmsg);
	ಆದರೆ (sock == -1) {
		free_connect_ctx(&cctx);
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}

	c = channel_new(ssh, ctype, SSH_CHANNEL_CONNECTING, sock, sock, -1,
	    CHAN_TCP_ಕಿಟಕಿ_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, rname, 1);
	c->host_ಪೋರ್ಟ್ = ಪೋರ್ಟ್;
	c->ಮಾರ್ಗ = xstrdup(host);
	c->connect_ctx = xmalloc(ಗಾತ್ರ(cctx));
	ಸ್ಮರಣೆ_ನಕಲು(c->connect_ctx, &cctx, ಗಾತ್ರ(cctx));

	ಹಿಂತಿರುಗಿ c;
}

/* Check if connecting to that path is permitted and connect. */
Channel *
channel_connect_ಗಮ್ಯ_ಮಾರ್ಗ(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ,
    ಅಕ್ಷರ *ctype, ಅಕ್ಷರ *rname)
{
	ರಚನೆ ssh_channels *sc = ssh->chanctxt;
	ರಚನೆ permission_ಗಣ *pset = &sc->local_perms;
	u_int i, permit, permit_adm = 1;
	ರಚನೆ permission *perm;

	permit = pset->all_permitted;
	ಆದರೆ (!permit) {
		ಗಾಗಿ (i = 0; i < pset->ಅಂಕೆ_permitted_user; i++) {
			perm = &pset->permitted_user[i];
			ಆದರೆ (open_ಹೊಂದಿಕೆ(perm, ಮಾರ್ಗ, ಪೋರ್ಟ್_STREAMLOCAL)) {
				permit = 1;
				ನಿಲ್ಲಿಸು;
			}
		}
	}

	ಆದರೆ (pset->ಅಂಕೆ_permitted_admin > 0) {
		permit_adm = 0;
		ಗಾಗಿ (i = 0; i < pset->ಅಂಕೆ_permitted_admin; i++) {
			perm = &pset->permitted_admin[i];
			ಆದರೆ (open_ಹೊಂದಿಕೆ(perm, ಮಾರ್ಗ, ಪೋರ್ಟ್_STREAMLOCAL)) {
				permit_adm = 1;
				ನಿಲ್ಲಿಸು;
			}
		}
	}

	ಆದರೆ (!permit || !permit_adm) {
		logit("Received request to connect to path %.100s, "
		    "but the request was denied.", ಮಾರ್ಗ);
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	ಹಿಂತಿರುಗಿ connect_ಗಮ್ಯ(ssh, ಮಾರ್ಗ, ಪೋರ್ಟ್_STREAMLOCAL, ctype, rname);
}

ಶೂನ್ಯ
channel_send_ಕಿಟಕಿ_changes(ರಚನೆ ssh *ssh)
{
	ರಚನೆ ssh_channels *sc = ssh->chanctxt;
	ರಚನೆ winsize ws;
	ಪೂರ್ಣಾಂಕ r;
	u_int i;

	ಗಾಗಿ (i = 0; i < sc->channels_alloc; i++) {
		ಆದರೆ (sc->channels[i] == ಖಾಲಿ || !sc->channels[i]->client_tty ||
		    sc->channels[i]->type != SSH_CHANNEL_OPEN)
			ಮುಂದುವರಿ;
		ಆದರೆ (ioctl(sc->channels[i]->rfd, TIOCGWINSZ, &ws) == -1)
			ಮುಂದುವರಿ;
		channel_request_ಆರಂಭ(ssh, i, "window-change", 0);
		ಆದರೆ ((r = sshpkt_put_u32(ssh, (u_int)ws.ws_ಲಂಬಸಾಲು)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_ಅಡ್ಡಸಾಲು)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_xpixel)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_ypixel)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "channel %u; send window-change", i);
	}
}

/* Return RDYNAMIC_OPEN channel: channel allows SOCKS, but is not connected */
ಸ್ಥಿರ Channel *
rdynamic_connect_prepare(ರಚನೆ ssh *ssh, ಅಕ್ಷರ *ctype, ಅಕ್ಷರ *rname)
{
	Channel *c;
	ಪೂರ್ಣಾಂಕ r;

	c = channel_new(ssh, ctype, SSH_CHANNEL_RDYNAMIC_OPEN, -1, -1, -1,
	    CHAN_TCP_ಕಿಟಕಿ_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, rname, 1);
	c->host_ಪೋರ್ಟ್ = 0;
	c->ಮಾರ್ಗ = ಖಾಲಿ;

	/*
	 * We need to open the channel before we have a FD,
	 * so that we can get SOCKS header from peer.
	 */
	ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh, SSH2_ಸಂದೇಶ_CHANNEL_OPEN_CONFIRMATION)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_ಕಿಟಕಿ)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0)
		fatal_fr(r, "channel %i; confirm", c->self);
	ಹಿಂತಿರುಗಿ c;
}

/* Return CONNECTING socket to remote host:port or local socket path */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
rdynamic_connect_ಮುಕ್ತಾಯ(ರಚನೆ ssh *ssh, Channel *c)
{
	ರಚನೆ ssh_channels *sc = ssh->chanctxt;
	ರಚನೆ permission_ಗಣ *pset = &sc->local_perms;
	ರಚನೆ permission *perm;
	ರಚನೆ channel_connect cctx;
	u_int i, permit_adm = 1;
	ಪೂರ್ಣಾಂಕ sock;

	ಆದರೆ (pset->ಅಂಕೆ_permitted_admin > 0) {
		permit_adm = 0;
		ಗಾಗಿ (i = 0; i < pset->ಅಂಕೆ_permitted_admin; i++) {
			perm = &pset->permitted_admin[i];
			ಆದರೆ (open_ಹೊಂದಿಕೆ(perm, c->ಮಾರ್ಗ, c->host_ಪೋರ್ಟ್)) {
				permit_adm = 1;
				ನಿಲ್ಲಿಸು;
			}
		}
	}
	ಆದರೆ (!permit_adm) {
		debug_f("requested forward not permitted");
		ಹಿಂತಿರುಗಿ -1;
	}

	memset(&cctx, 0, ಗಾತ್ರ(cctx));
	sock = connect_ಗಮ್ಯ_helper(ssh, c->ಮಾರ್ಗ, c->host_ಪೋರ್ಟ್, SOCK_STREAM, ಖಾಲಿ,
	    ಖಾಲಿ, &cctx, ಖಾಲಿ, ಖಾಲಿ);
	ಆದರೆ (sock == -1)
		free_connect_ctx(&cctx);
	ಇಲ್ಲದಿದ್ದರೆ {
		/* similar to SSH_CHANNEL_CONNECTING but we've already sent the open */
		c->type = SSH_CHANNEL_RDYNAMIC_ಮುಕ್ತಾಯ;
		c->connect_ctx = xmalloc(ಗಾತ್ರ(cctx));
		ಸ್ಮರಣೆ_ನಕಲು(c->connect_ctx, &cctx, ಗಾತ್ರ(cctx));
		channel_ರಿಜಿಸ್ಟರ್_fds(ssh, c, sock, sock, -1, 0, 1, 0);
	}
	ಹಿಂತಿರುಗಿ sock;
}

/* -- X11 forwarding */

/*
 * Creates an internet domain socket for listening for X11 connections.
 * Returns 0 and a suitable display number for the DISPLAY variable
 * stored in display_numberp , or -1 if an error occurs.
 */
ಪೂರ್ಣಾಂಕ
x11_create_display_inet(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ x11_display_ಸ್ಥಾನಾಂತರ,
    ಪೂರ್ಣಾಂಕ x11_use_localhost, ಪೂರ್ಣಾಂಕ single_connection,
    u_int *display_numberp, ಪೂರ್ಣಾಂಕ **chanids)
{
	Channel *nc = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ display_ಸಂಖ್ಯೆ, sock, ಪೋರ್ಟ್;
	ರಚನೆ addrinfo hints, *ai, *aitop;
	ಅಕ್ಷರ strport[NI_MAXSERV];
	ಪೂರ್ಣಾಂಕ gaierr, n, ಅಂಕೆ_socks = 0, socks[ಅಂಕೆ_SOCKS];

	ಆದರೆ (chanids == ಖಾಲಿ || x11_display_ಸ್ಥಾನಾಂತರ < 0 ||
	    x11_display_ಸ್ಥಾನಾಂತರ > UINT16_MAX - X11_ತಳ_ಪೋರ್ಟ್ - MAX_DISPLAYS)
		ಹಿಂತಿರುಗಿ -1;

	ಗಾಗಿ (display_ಸಂಖ್ಯೆ = x11_display_ಸ್ಥಾನಾಂತರ;
	    display_ಸಂಖ್ಯೆ < x11_display_ಸ್ಥಾನಾಂತರ + MAX_DISPLAYS;
	    display_ಸಂಖ್ಯೆ++) {
		ಪೋರ್ಟ್ = X11_ತಳ_ಪೋರ್ಟ್ + display_ಸಂಖ್ಯೆ;
		memset(&hints, 0, ಗಾತ್ರ(hints));
		hints.ai_family = ssh->chanctxt->IPv4or6;
		hints.ai_flags = x11_use_localhost ? 0: AI_PASSIVE;
		hints.ai_socktype = SOCK_STREAM;
		snprintf(strport, ಗಾತ್ರ strport, "%d", ಪೋರ್ಟ್);
		ಆದರೆ ((gaierr = getaddrinfo(ಖಾಲಿ, strport,
		    &hints, &aitop)) != 0) {
			error("getaddrinfo: %.100s", ssh_gai_strerror(gaierr));
			ಹಿಂತಿರುಗಿ -1;
		}
		ಗಾಗಿ (ai = aitop; ai; ai = ai->ai_next) {
			ಆದರೆ (ai->ai_family != AF_INET &&
			    ai->ai_family != AF_INET6)
				ಮುಂದುವರಿ;
			sock = socket(ai->ai_family, ai->ai_socktype,
			    ai->ai_protocol);
			ಆದರೆ (sock == -1) {
				ಆದರೆ ((errno != EINVAL) && (errno != EAFNOSUPPORT)
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ EPFNOSUPPORT
				    && (errno != EPFNOSUPPORT)
#ಆದರೆ_ಅಂತ್ಯ 
				    ) {
					error("socket: %.100s", strerror(errno));
					freeaddrinfo(aitop);
					ಹಿಂತಿರುಗಿ -1;
				} ಇಲ್ಲದಿದ್ದರೆ {
					debug("x11_create_display_inet: Socket family %d not supported",
						 ai->ai_family);
					ಮುಂದುವರಿ;
				}
			}
			ಆದರೆ (ai->ai_family == AF_INET6)
				sock_ಗಣ_v6only(sock);
			ಆದರೆ (x11_use_localhost)
				ಗಣ_reuseaddr(sock);
			ಆದರೆ (bind(sock, ai->ai_addr, ai->ai_addrlen) == -1) {
				debug2_f("bind port %d: %.100s", ಪೋರ್ಟ್,
				    strerror(errno));
				close(sock);
				ಗಾಗಿ (n = 0; n < ಅಂಕೆ_socks; n++)
					close(socks[n]);
				ಅಂಕೆ_socks = 0;
				ನಿಲ್ಲಿಸು;
			}
			socks[ಅಂಕೆ_socks++] = sock;
			ಆದರೆ (ಅಂಕೆ_socks == ಅಂಕೆ_SOCKS)
				ನಿಲ್ಲಿಸು;
		}
		freeaddrinfo(aitop);
		ಆದರೆ (ಅಂಕೆ_socks > 0)
			ನಿಲ್ಲಿಸು;
	}
	ಆದರೆ (display_ಸಂಖ್ಯೆ >= x11_display_ಸ್ಥಾನಾಂತರ + MAX_DISPLAYS) {
		error("Failed to allocate internet-domain X11 display socket.");
		ಹಿಂತಿರುಗಿ -1;
	}
	/* Start listening for connections on the socket. */
	ಗಾಗಿ (n = 0; n < ಅಂಕೆ_socks; n++) {
		sock = socks[n];
		ಆದರೆ (listen(sock, SSH_LISTEN_BACKLOG) == -1) {
			error("listen: %.100s", strerror(errno));
			close(sock);
			ಹಿಂತಿರುಗಿ -1;
		}
	}

	/* Allocate a channel for each socket. */
	*chanids = xcalloc(ಅಂಕೆ_socks + 1, ಗಾತ್ರ(**chanids));
	ಗಾಗಿ (n = 0; n < ಅಂಕೆ_socks; n++) {
		sock = socks[n];
		nc = channel_new(ssh, "x11-listener",
		    SSH_CHANNEL_X11_LISTENER, sock, sock, -1,
		    CHAN_X11_ಕಿಟಕಿ_DEFAULT, CHAN_X11_PACKET_DEFAULT,
		    0, "X11 inet listener", 1);
		nc->single_connection = single_connection;
		(*chanids)[n] = nc->self;
	}
	(*chanids)[n] = -1;

	/* Return the display number for the DISPLAY environment variable. */
	*display_numberp = display_ಸಂಖ್ಯೆ;
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
connect_local_xsocket_ಮಾರ್ಗ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *pathname)
{
	ಪೂರ್ಣಾಂಕ sock;
	ರಚನೆ sockaddr_un addr;

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	ಆದರೆ (sock == -1) {
		error("socket: %.100s", strerror(errno));
		ಹಿಂತಿರುಗಿ -1;
	}
	memset(&addr, 0, ಗಾತ್ರ(addr));
	addr.sun_family = AF_UNIX;
	strlcpy(addr.sun_ಮಾರ್ಗ, pathname, ಗಾತ್ರ addr.sun_ಮಾರ್ಗ);
	ಆದರೆ (connect(sock, (ರಚನೆ sockaddr *)&addr, ಗಾತ್ರ(addr)) == 0)
		ಹಿಂತಿರುಗಿ sock;
	close(sock);
	error("connect %.100s: %.100s", addr.sun_ಮಾರ್ಗ, strerror(errno));
	ಹಿಂತಿರುಗಿ -1;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
connect_local_xsocket(u_int dnr)
{
	ಅಕ್ಷರ buf[1024];
	snprintf(buf, ಗಾತ್ರ buf, ಮಾರ್ಗ_UNIX_X, dnr);
	ಹಿಂತಿರುಗಿ connect_local_xsocket_ಮಾರ್ಗ(buf);
}

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ __APPLE__
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
is_ಮಾರ್ಗ_ಗಮ್ಯ_xsocket(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *display, ಅಕ್ಷರ *ಮಾರ್ಗ, ಗಾತ್ರ_t pathlen)
{
	ರಚನೆ stat sbuf;

	ಆದರೆ (strlcpy(ಮಾರ್ಗ, display, pathlen) >= pathlen) {
		error_f("display path too long");
		ಹಿಂತಿರುಗಿ 0;
	}
	ಆದರೆ (display[0] != '/')
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ (stat(ಮಾರ್ಗ, &sbuf) == 0) {
		ಹಿಂತಿರುಗಿ 1;
	} ಇಲ್ಲದಿದ್ದರೆ {
		ಅಕ್ಷರ *dot = strrchr(ಮಾರ್ಗ, '.');
		ಆದರೆ (dot != ಖಾಲಿ) {
			*dot = '\0';
			ಆದರೆ (stat(ಮಾರ್ಗ, &sbuf) == 0) {
				ಹಿಂತಿರುಗಿ 1;
			}
		}
	}
	ಹಿಂತಿರುಗಿ 0;
}
#ಆದರೆ_ಅಂತ್ಯ

ಪೂರ್ಣಾಂಕ
x11_connect_display(ರಚನೆ ssh *ssh)
{
	u_int display_ಸಂಖ್ಯೆ;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *display;
	ಅಕ್ಷರ buf[1024], *cp;
	ರಚನೆ addrinfo hints, *ai, *aitop;
	ಅಕ್ಷರ strport[NI_MAXSERV];
	ಪೂರ್ಣಾಂಕ gaierr, sock = 0;

	/* Try to open a socket for the local X server. */
	display = getenv("DISPLAY");
	ಆದರೆ (!display) {
		error("DISPLAY not set.");
		ಹಿಂತಿರುಗಿ -1;
	}
	/*
	 * Now we decode the value of the DISPLAY variable and make a
	 * connection to the real X server.
	 */

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ __APPLE__
	/* Check if display is a path to a socket (as set by launchd). */
	{
		ಅಕ್ಷರ ಮಾರ್ಗ[PATH_MAX];

		ಆದರೆ (is_ಮಾರ್ಗ_ಗಮ್ಯ_xsocket(display, ಮಾರ್ಗ, ಗಾತ್ರ(ಮಾರ್ಗ))) {
			debug("x11_connect_display: $DISPLAY is launchd");

			/* Create a socket. */
			sock = connect_local_xsocket_ಮಾರ್ಗ(ಮಾರ್ಗ);
			ಆದರೆ (sock < 0)
				ಹಿಂತಿರುಗಿ -1;

			/* OK, we now have a connection to the display. */
			ಹಿಂತಿರುಗಿ sock;
		}
	}
#ಆದರೆ_ಅಂತ್ಯ
	/*
	 * Check if it is a unix domain socket.  Unix domain displays are in
	 * one of the following formats: unix:d[.s], :d[.s], ::d[.s]
	 */
	ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಹೋಲಿಕೆ(display, "unix:", 5) == 0 ||
	    display[0] == ':') {
		/* Connect to the unix domain socket. */
		ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಓದು(strrchr(display, ':') + 1, "%u",
		    &display_ಸಂಖ್ಯೆ) != 1) {
			error("Could not parse display number from DISPLAY: "
			    "%.100s", display);
			ಹಿಂತಿರುಗಿ -1;
		}
		/* Create a socket. */
		sock = connect_local_xsocket(display_ಸಂಖ್ಯೆ);
		ಆದರೆ (sock < 0)
			ಹಿಂತಿರುಗಿ -1;

		/* OK, we now have a connection to the display. */
		ಹಿಂತಿರುಗಿ sock;
	}
	/*
	 * Connect to an inet socket.  The DISPLAY value is supposedly
	 * hostname:d[.s], where hostname may also be numeric IP address.
	 */
	strlcpy(buf, display, ಗಾತ್ರ(buf));
	cp = strchr(buf, ':');
	ಆದರೆ (!cp) {
		error("Could not find ':' in DISPLAY: %.100s", display);
		ಹಿಂತಿರುಗಿ -1;
	}
	*cp = 0;
	/*
	 * buf now contains the host name.  But first we parse the
	 * display number.
	 */
	ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಓದು(cp + 1, "%u", &display_ಸಂಖ್ಯೆ) != 1 ||
	    display_ಸಂಖ್ಯೆ > UINT16_MAX - X11_ತಳ_ಪೋರ್ಟ್) {
		error("Could not parse display number from DISPLAY: %.100s",
		    display);
		ಹಿಂತಿರುಗಿ -1;
	}

	/* Look up the host address */
	memset(&hints, 0, ಗಾತ್ರ(hints));
	hints.ai_family = ssh->chanctxt->IPv4or6;
	hints.ai_socktype = SOCK_STREAM;
	snprintf(strport, ಗಾತ್ರ strport, "%u", X11_ತಳ_ಪೋರ್ಟ್ + display_ಸಂಖ್ಯೆ);
	ಆದರೆ ((gaierr = getaddrinfo(buf, strport, &hints, &aitop)) != 0) {
		error("%.100s: unknown host. (%s)", buf,
		ssh_gai_strerror(gaierr));
		ಹಿಂತಿರುಗಿ -1;
	}
	ಗಾಗಿ (ai = aitop; ai; ai = ai->ai_next) {
		/* Create a socket. */
		sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		ಆದರೆ (sock == -1) {
			debug2("socket: %.100s", strerror(errno));
			ಮುಂದುವರಿ;
		}
		/* Connect it to the display. */
		ಆದರೆ (connect(sock, ai->ai_addr, ai->ai_addrlen) == -1) {
			debug2("connect %.100s port %u: %.100s", buf,
			    X11_ತಳ_ಪೋರ್ಟ್ + display_ಸಂಖ್ಯೆ, strerror(errno));
			close(sock);
			ಮುಂದುವರಿ;
		}
		/* Success */
		ನಿಲ್ಲಿಸು;
	}
	freeaddrinfo(aitop);
	ಆದರೆ (!ai) {
		error("connect %.100s port %u: %.100s", buf,
		    X11_ತಳ_ಪೋರ್ಟ್ + display_ಸಂಖ್ಯೆ, strerror(errno));
		ಹಿಂತಿರುಗಿ -1;
	}
	ಗಣ_nodelay(sock);
	ಹಿಂತಿರುಗಿ sock;
}

/*
 * Requests forwarding of X11 connections, generates fake authentication
 * data, and enables authentication spoofing.
 * This should be called in the client only.
 */
ಶೂನ್ಯ
x11_request_forwarding_with_spoofing(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ client_session_id,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *disp, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *proto, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ದತ್ತಾಂಶ, ಪೂರ್ಣಾಂಕ want_ಉತ್ತರ)
{
	ರಚನೆ ssh_channels *sc = ssh->chanctxt;
	u_int ದತ್ತಾಂಶ_len = (u_int) ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(ದತ್ತಾಂಶ) / 2;
	u_int i, ಮೌಲ್ಯ;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *cp;
	ಅಕ್ಷರ *new_ದತ್ತಾಂಶ;
	ಪೂರ್ಣಾಂಕ r, screen_ಸಂಖ್ಯೆ;

	ಆದರೆ (sc->x11_saved_display == ಖಾಲಿ)
		sc->x11_saved_display = xstrdup(disp);
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(disp, sc->x11_saved_display) != 0) {
		error("x11_request_forwarding_with_spoofing: different "
		    "$DISPLAY already forwarded");
		ಹಿಂತಿರುಗಿ;
	}

	cp = strchr(disp, ':');
	ಆದರೆ (cp)
		cp = strchr(cp, '.');
	ಆದರೆ (cp)
		screen_ಸಂಖ್ಯೆ = (u_int)strtonum(cp + 1, 0, 400, ಖಾಲಿ);
	ಇಲ್ಲದಿದ್ದರೆ
		screen_ಸಂಖ್ಯೆ = 0;

	ಆದರೆ (sc->x11_saved_proto == ಖಾಲಿ) {
		/* Save protocol name. */
		sc->x11_saved_proto = xstrdup(proto);

		/* Extract real authentication data. */
		sc->x11_saved_ದತ್ತಾಂಶ = xmalloc(ದತ್ತಾಂಶ_len);
		ಗಾಗಿ (i = 0; i < ದತ್ತಾಂಶ_len; i++) {
			ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಓದು(ದತ್ತಾಂಶ + 2 * i, "%2x", &ಮೌಲ್ಯ) != 1) {
				fatal("x11_request_forwarding: bad "
				    "authentication data: %.100s", ದತ್ತಾಂಶ);
			}
			sc->x11_saved_ದತ್ತಾಂಶ[i] = ಮೌಲ್ಯ;
		}
		sc->x11_saved_ದತ್ತಾಂಶ_len = ದತ್ತಾಂಶ_len;

		/* Generate fake data of the same length. */
		sc->x11_fake_ದತ್ತಾಂಶ = xmalloc(ದತ್ತಾಂಶ_len);
		arc4random_buf(sc->x11_fake_ದತ್ತಾಂಶ, ದತ್ತಾಂಶ_len);
		sc->x11_fake_ದತ್ತಾಂಶ_len = ದತ್ತಾಂಶ_len;
	}

	/* Convert the fake data into hex. */
	new_ದತ್ತಾಂಶ = tohex(sc->x11_fake_ದತ್ತಾಂಶ, ದತ್ತಾಂಶ_len);

	/* Send the request packet. */
	channel_request_ಆರಂಭ(ssh, client_session_id, "x11-req", want_ಉತ್ತರ);
	ಆದರೆ ((r = sshpkt_put_u8(ssh, 0)) != 0 || /* bool: single connection */
	    (r = sshpkt_put_cstring(ssh, proto)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, new_ದತ್ತಾಂಶ)) != 0 ||
	    (r = sshpkt_put_u32(ssh, screen_ಸಂಖ್ಯೆ)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send x11-req");
	ಬಿಡುಗಡೆ(new_ದತ್ತಾಂಶ);
}

/*
 * Returns whether an x11 channel was used recently (less than a second ago)
 */
ಪೂರ್ಣಾಂಕ
x11_channel_ಬಳಸಿದ_recently(ರಚನೆ ssh *ssh) {
	u_int i;
	Channel *c;
	ದ್ವಿಗುಣ lastused = 0;

	ಗಾಗಿ (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		ಆದರೆ (c == ಖಾಲಿ || c->ctype == ಖಾಲಿ || c->lastused == 0.0 ||
		    strcmp(c->ctype, "x11-connection") != 0)
			ಮುಂದುವರಿ;
		ಆದರೆ (c->lastused > lastused)
			lastused = c->lastused;
	}
	ಹಿಂತಿರುಗಿ lastused != 0.0 && monotime_double() <= lastused + 1.0;
}
