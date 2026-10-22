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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/stat.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/ioctl.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/un.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/socket.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/queue.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <netinet/in.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <arpa/inet.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <fcntl.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <limits.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <netdb.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <poll.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <termios.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh2.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "packet.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "channels.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "compat.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "canohost.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "pathnames.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "match.h"

/* XXX remove once we're satisfied there's no lurking bugs */
/* #define DEBUG_CHANNEL_POLL 1 */

/* -- agent forwarding */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	ਅੰਕ_SOCKS	10

/* -- X11 forwarding */
/* X11 port for display :0 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ X11_ਅਧਾਰ_ਪੋਰਟ	6000
/* Maximum number of fake X11 displays to try. */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MAX_DISPLAYS  1000

/* Per-channel callback for pre/post IO actions */
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਖਾਲੀ chan_fn(ਬਣਤਰ ssh *, Channel *c);

/*
 * Data structure for storing which hosts are permitted for forward requests.
 * The local sides of any remote forwards are stored in this array to prevent
 * a corrupt remote server from accessing arbitrary TCP/IP ports on our local
 * network (which might be behind a firewall).
 */
/* XXX: streamlocal wants a path instead of host:port */
/*      Overload host_to_connect; we could just make this match Forward */
/*	XXX - can we use listen_host instead of listen_path? */
ਬਣਤਰ permission {
	ਅੱਖਰ *host_ਮੰਜ਼ਿਲ_connect;		/* Connect to 'host'. */
	ਪੂਰਨ ਪੋਰਟ_ਮੰਜ਼ਿਲ_connect;		/* Connect to 'port'. */
	ਅੱਖਰ *listen_host;		/* Remote side should listen address. */
	ਅੱਖਰ *listen_ਰਸਤਾ;		/* Remote side should listen path. */
	ਪੂਰਨ listen_ਪੋਰਟ;		/* Remote side should listen port. */
	Channel *downstream;		/* Downstream mux*/
};

/* Context for non-blocking connects */
ਬਣਤਰ channel_connect {
	ਅੱਖਰ *host;
	ਪੂਰਨ ਪੋਰਟ;
	ਬਣਤਰ addrinfo *ai, *aitop;
};

/*
 * Stores the forwarding permission state for a single direction (local or
 * remote).
 */
ਬਣਤਰ permission_ਸੈੱਟ {
	/*
	 * List of all local permitted host/port pairs to allow for the
	 * user.
	 */
	u_int ਅੰਕ_permitted_user;
	ਬਣਤਰ permission *permitted_user;

	/*
	 * List of all permitted host/port pairs to allow for the admin.
	 */
	u_int ਅੰਕ_permitted_admin;
	ਬਣਤਰ permission *permitted_admin;

	/*
	 * If this is true, all opens/listens are permitted.  This is the
	 * case on the server on which we have to trust the client anyway,
	 * and the user could do anything after logging in.
	 */
	ਪੂਰਨ all_permitted;
};

/* Used to record timeouts per channel type */
ਬਣਤਰ ssh_channel_timeout {
	ਅੱਖਰ *type_ਨਮੂਨਾ;
	ਦੁੱਗਣਾ timeout_secs;
};

/* Master structure for channels state */
ਬਣਤਰ ssh_channels {
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
	ਬਣਤਰ permission_ਸੈੱਟ local_perms;
	ਬਣਤਰ permission_ਸੈੱਟ remote_perms;

	/* -- X11 forwarding */

	/* Saved X11 local (client) display. */
	ਅੱਖਰ *x11_saved_display;

	/* Saved X11 authentication protocol name. */
	ਅੱਖਰ *x11_saved_proto;

	/* Saved X11 authentication data.  This is the real data. */
	ਅੱਖਰ *x11_saved_ਅੰਕੜੇ;
	u_int x11_saved_ਅੰਕੜੇ_len;

	/* Deadline after which all X11 connections are refused */
	ਦੁੱਗਣਾ x11_refuse_ਸਮਾਂ;

	/*
	 * Fake X11 authentication data.  This is what the server will be
	 * sending us; we should replace any occurrences of this by the
	 * real data.
	 */
	u_char *x11_fake_ਅੰਕੜੇ;
	u_int x11_fake_ਅੰਕੜੇ_len;

	/* AF_UNSPEC or AF_INET or AF_INET6 */
	ਪੂਰਨ IPv4or6;

	/* Set SO_KEEPALIVE on TCP connections */
	ਪੂਰਨ want_tcp_keepalive;

	/* Channel timeouts by type */
	ਬਣਤਰ ssh_channel_timeout *timeouts;
	ਮਾਪ_t ntimeouts;
	/* Global timeout for all OPEN channels */
	ਦੁੱਗਣਾ global_deadline;
	ਦੁੱਗਣਾ lastused;
	/* pattern-lists used to classify channels as bulk */
	ਅੱਖਰ *bulk_classifier_tty, *bulk_classifier_notty;
	/* Number of active bulk channels (set by channel_handler) */
	u_int nbulk;
};

/* helper */
ਸਥਿਰ ਖਾਲੀ ਪੋਰਟ_open_helper(ਬਣਤਰ ssh *ssh, Channel *c, ਅੱਖਰ *rtype);
ਸਥਿਰ ਅਚਲ ਅੱਖਰ *channel_rfwd_bind_host(ਅਚਲ ਅੱਖਰ *listen_host);

/* non-blocking connect helpers */
ਸਥਿਰ ਪੂਰਨ connect_ਅਗਲਾ(ਬਣਤਰ ssh *, ਬਣਤਰ channel_connect *);
ਸਥਿਰ Channel *rdynamic_connect_prepare(ਬਣਤਰ ssh *, ਅੱਖਰ *, ਅੱਖਰ *);
ਸਥਿਰ ਪੂਰਨ rdynamic_connect_ਅੰਤ(ਬਣਤਰ ssh *, Channel *);

/* Setup helper */
ਸਥਿਰ ਖਾਲੀ channel_handler_init(ਬਣਤਰ ssh_channels *sc);

/* -- channel core */

ਖਾਲੀ
channel_init_channels(ਬਣਤਰ ssh *ssh)
{
	ਬਣਤਰ ssh_channels *sc;

	ਜੇ ((sc = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, ਆਕਾਰ(*sc))) == ਨਿਰਾ)
		fatal_f("allocation failed");
	sc->channels_alloc = 10;
	sc->channels = xcalloc(sc->channels_alloc, ਆਕਾਰ(*sc->channels));
	sc->IPv4or6 = AF_UNSPEC;
	sc->bulk_classifier_tty = xstrdup(CHANNEL_BULK_TTY);
	sc->bulk_classifier_notty = xstrdup(CHANNEL_BULK_NOTTY);
	channel_handler_init(sc);

	ssh->chanctxt = sc;
}

Channel *
channel_by_id(ਬਣਤਰ ssh *ssh, ਪੂਰਨ id)
{
	Channel *c;

	ਜੇ (id < 0 || (u_int)id >= ssh->chanctxt->channels_alloc) {
		logit_f("%d: bad id", id);
		ਵਾਪਸ ਨਿਰਾ;
	}
	c = ssh->chanctxt->channels[id];
	ਜੇ (c == ਨਿਰਾ) {
		logit_f("%d: bad id: channel free", id);
		ਵਾਪਸ ਨਿਰਾ;
	}
	ਵਾਪਸ c;
}

Channel *
channel_by_remote_id(ਬਣਤਰ ssh *ssh, u_int remote_id)
{
	Channel *c;
	u_int i;

	ਲਈ (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		ਜੇ (c != ਨਿਰਾ && c->have_remote_id && c->remote_id == remote_id)
			ਵਾਪਸ c;
	}
	ਵਾਪਸ ਨਿਰਾ;
}

/*
 * Returns the channel if it is allowed to receive protocol messages.
 * Private channels, like listening sockets, may not receive messages.
 */
Channel *
channel_lookup(ਬਣਤਰ ssh *ssh, ਪੂਰਨ id)
{
	Channel *c;

	ਜੇ ((c = channel_by_id(ssh, id)) == ਨਿਰਾ)
		ਵਾਪਸ ਨਿਰਾ;

	ਚੋਣ (c->type) {
	ਹਾਲਤ SSH_CHANNEL_X11_OPEN:
	ਹਾਲਤ SSH_CHANNEL_LARVAL:
	ਹਾਲਤ SSH_CHANNEL_CONNECTING:
	ਹਾਲਤ SSH_CHANNEL_DYNAMIC:
	ਹਾਲਤ SSH_CHANNEL_RDYNAMIC_OPEN:
	ਹਾਲਤ SSH_CHANNEL_RDYNAMIC_ਅੰਤ:
	ਹਾਲਤ SSH_CHANNEL_OPENING:
	ਹਾਲਤ SSH_CHANNEL_OPEN:
	ਹਾਲਤ SSH_CHANNEL_ABANDONED:
	ਹਾਲਤ SSH_CHANNEL_MUX_PROXY:
		ਵਾਪਸ c;
	}
	logit("Non-public channel %d, type %d.", id, c->type);
	ਵਾਪਸ ਨਿਰਾ;
}

ਸਥਿਰ ਖਾਲੀ
free_connect_ctx(ਬਣਤਰ channel_connect *cctx)
{
	ਮੁਕਤ(cctx->host);
	ਜੇ (cctx->aitop) {
		ਜੇ (cctx->aitop->ai_family == AF_UNIX)
			ਮੁਕਤ(cctx->aitop);
		ਨਹੀਂਤਾਂ
			freeaddrinfo(cctx->aitop);
	}
	memset(cctx, 0, ਆਕਾਰ(*cctx));
}

ਸਥਿਰ ਖਾਲੀ
channel_free_connect_ctx(Channel *c)
{
	ਜੇ (c == ਨਿਰਾ || c->connect_ctx == ਨਿਰਾ)
		ਵਾਪਸ;
	free_connect_ctx(c->connect_ctx);
	ਮੁਕਤ(c->connect_ctx);
	c->connect_ctx = ਨਿਰਾ;
}

/* Enable/disable TCP keepalives for X11 and port-forwarding sockets */
ਖਾਲੀ
channel_ਸੈੱਟ_tcp_keepalives(ਬਣਤਰ ssh *ssh, ਪੂਰਨ on)
{
	ssh->chanctxt->want_tcp_keepalive = on;
}

/*
 * Add a timeout for open channels whose c->ctype (or c->xctype if it is set)
 * match type_pattern.
 */
ਖਾਲੀ
channel_ਜੋੜੋ_timeout(ਬਣਤਰ ssh *ssh, ਅਚਲ ਅੱਖਰ *type_ਨਮੂਨਾ,
    ਦੁੱਗਣਾ timeout_secs)
{
	ਬਣਤਰ ssh_channels *sc = ssh->chanctxt;

	ਜੇ (strcmp(type_ਨਮੂਨਾ, "global") == 0) {
		debug2_f("global channel timeout %f seconds", timeout_secs);
		sc->global_deadline = timeout_secs;
		ਵਾਪਸ;
	}
	debug2_f("channel type \"%s\" timeout %f seconds",
	    type_ਨਮੂਨਾ, timeout_secs);
	sc->timeouts = xrecallocarray(sc->timeouts, sc->ntimeouts,
	    sc->ntimeouts + 1, ਆਕਾਰ(*sc->timeouts));
	sc->timeouts[sc->ntimeouts].type_ਨਮੂਨਾ = xstrdup(type_ਨਮੂਨਾ);
	sc->timeouts[sc->ntimeouts].timeout_secs = timeout_secs;
	sc->ntimeouts++;
}

/* Clears all previously-added channel timeouts */
ਖਾਲੀ
channel_clear_timeouts(ਬਣਤਰ ssh *ssh)
{
	ਬਣਤਰ ssh_channels *sc = ssh->chanctxt;
	ਮਾਪ_t i;

	debug3_f("clearing");
	ਲਈ (i = 0; i < sc->ntimeouts; i++)
		ਮੁਕਤ(sc->timeouts[i].type_ਨਮੂਨਾ);
	ਮੁਕਤ(sc->timeouts);
	sc->timeouts = ਨਿਰਾ;
	sc->ntimeouts = 0;
}

ਸਥਿਰ ਦੁੱਗਣਾ
lookup_timeout(ਬਣਤਰ ssh *ssh, ਅਚਲ ਅੱਖਰ *type)
{
	ਬਣਤਰ ssh_channels *sc = ssh->chanctxt;
	ਮਾਪ_t i;

	ਲਈ (i = 0; i < sc->ntimeouts; i++) {
		ਜੇ (ਮੇਲ_ਨਮੂਨਾ(type, sc->timeouts[i].type_ਨਮੂਨਾ))
			ਵਾਪਸ sc->timeouts[i].timeout_secs;
	}

	ਵਾਪਸ 0;
}

ਸਥਿਰ ਖਾਲੀ
channel_classify(ਬਣਤਰ ssh *ssh, Channel *c)
{
	ਬਣਤਰ ssh_channels *sc = ssh->chanctxt;
	ਅਚਲ ਅੱਖਰ *type = c->xctype == ਨਿਰਾ ? c->ctype : c->xctype;
	ਅਚਲ ਪੂਰਨ has_tty = c->isatty || c->remote_has_tty;
	ਅਚਲ ਅੱਖਰ *classifier = has_tty ?
	    sc->bulk_classifier_tty : sc->bulk_classifier_notty;

	c->bulk = type != ਨਿਰਾ && ਮੇਲ_ਨਮੂਨਾ_list(type, classifier, 0) == 1;
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
ਖਾਲੀ
channel_ਸੈੱਟ_xtype(ਬਣਤਰ ssh *ssh, ਪੂਰਨ id, ਅਚਲ ਅੱਖਰ *xctype)
{
	ਬਣਤਰ ssh_channels *sc = ssh->chanctxt;
	Channel *c;

	ਜੇ ((c = channel_by_id(ssh, id)) == ਨਿਰਾ)
		fatal_f("missing channel %d", id);
	ਜੇ (c->xctype != ਨਿਰਾ)
		ਮੁਕਤ(c->xctype);
	c->xctype = xstrdup(xctype);
	/* Only override deadline if xctype has a more specific match. */
	ਦੁੱਗਣਾ xtype_deadline = lookup_timeout(ssh, c->xctype);
	ਜੇ (xtype_deadline != 0)
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
ਸਥਿਰ ਖਾਲੀ
channel_ਸੈੱਟ_ਵਰਤਿਆ_ਸਮਾਂ(ਬਣਤਰ ssh *ssh, Channel *c)
{
	ssh->chanctxt->lastused = monotime_double();
	ਜੇ (c != ਨਿਰਾ)
		c->lastused = ssh->chanctxt->lastused;
}

/*
 * Get the time at which a channel is due to time out for inactivity.
 * Returns 0 if the channel is not due to time out ever.
 */
ਸਥਿਰ ਦੁੱਗਣਾ
channel_get_expiry(ਬਣਤਰ ssh *ssh, Channel *c)
{
	ਬਣਤਰ ssh_channels *sc = ssh->chanctxt;
	ਦੁੱਗਣਾ expiry = 0, channel_expiry;

	ਜੇ (sc->lastused != 0 && sc->global_deadline != 0)
		expiry = sc->lastused + sc->global_deadline;
	ਜੇ (c->lastused != 0 && c->inactive_deadline != 0) {
		channel_expiry = c->lastused + c->inactive_deadline;
		ਜੇ (expiry == 0 || channel_expiry < expiry)
			expiry = channel_expiry;
	}
	ਵਾਪਸ expiry;
}

/* Returns non-zero if there is an open, non-interactive channel */
ਪੂਰਨ
channel_has_bulk(ਬਣਤਰ ssh *ssh)
{
	ਵਾਪਸ ssh->chanctxt != ਨਿਰਾ && ssh->chanctxt->nbulk != 0;
}

/*
 * Register filedescriptors for a channel, used when allocating a channel or
 * when the channel consumer/producer is ready, e.g. shell exec'd
 */
ਸਥਿਰ ਖਾਲੀ
channel_ਰਜਿਸਟਰ_fds(ਬਣਤਰ ssh *ssh, Channel *c, ਪੂਰਨ rfd, ਪੂਰਨ wfd, ਪੂਰਨ efd,
    ਪੂਰਨ extusage, ਪੂਰਨ nonblock, ਪੂਰਨ is_tty)
{
	ਪੂਰਨ val;

	ਜੇ (rfd != -1)
		(ਖਾਲੀ)fcntl(rfd, F_SETFD, FD_CLOEXEC);
	ਜੇ (wfd != -1 && wfd != rfd)
		(ਖਾਲੀ)fcntl(wfd, F_SETFD, FD_CLOEXEC);
	ਜੇ (efd != -1 && efd != rfd && efd != wfd)
		(ਖਾਲੀ)fcntl(efd, F_SETFD, FD_CLOEXEC);

	c->rfd = rfd;
	c->wfd = wfd;
	c->sock = (rfd == wfd) ? rfd : -1;
	c->efd = efd;
	c->extended_usage = extusage;

	ਜੇ ((c->isatty = is_tty) != 0)
		debug2("channel %d: rfd %d isatty", c->self, c->rfd);
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ _AIX
	/* XXX: Later AIX versions can't push as much data to tty */
	c->wfd_isatty = is_tty || isatty(c->wfd);
#ਜੇ_ਅੰਤ

	/* enable nonblocking mode */
	c->restore_ਖੰਡ = 0;
	ਜੇ (nonblock == CHANNEL_NONBLOCK_STDIO) {
		/*
		 * Special handling for stdio file descriptors: do not set
		 * non-blocking mode if they are TTYs. Otherwise prepare to
		 * restore their blocking state on exit to avoid interfering
		 * with other programs that follow.
		 */
		ਜੇ (rfd != -1 && !isatty(rfd) &&
		    (val = fcntl(rfd, F_GETFL)) != -1 && !(val & O_NONBLOCK)) {
			c->restore_flags[0] = val;
			c->restore_ਖੰਡ |= CHANNEL_RESTORE_RFD;
			ਸੈੱਟ_nonblock(rfd);
		}
		ਜੇ (wfd != -1 && !isatty(wfd) &&
		    (val = fcntl(wfd, F_GETFL)) != -1 && !(val & O_NONBLOCK)) {
			c->restore_flags[1] = val;
			c->restore_ਖੰਡ |= CHANNEL_RESTORE_WFD;
			ਸੈੱਟ_nonblock(wfd);
		}
		ਜੇ (efd != -1 && !isatty(efd) &&
		    (val = fcntl(efd, F_GETFL)) != -1 && !(val & O_NONBLOCK)) {
			c->restore_flags[2] = val;
			c->restore_ਖੰਡ |= CHANNEL_RESTORE_EFD;
			ਸੈੱਟ_nonblock(efd);
		}
	} ਨਹੀਂਤਾਂ ਜੇ (nonblock) {
		ਜੇ (rfd != -1)
			ਸੈੱਟ_nonblock(rfd);
		ਜੇ (wfd != -1)
			ਸੈੱਟ_nonblock(wfd);
		ਜੇ (efd != -1)
			ਸੈੱਟ_nonblock(efd);
	}
	/* channel might be entering a larval state, so reset global timeout */
	channel_ਸੈੱਟ_ਵਰਤਿਆ_ਸਮਾਂ(ssh, ਨਿਰਾ);
	channel_classify(ssh, c);
}

/*
 * Allocate a new channel object and set its type and socket.
 */
Channel *
channel_new(ਬਣਤਰ ssh *ssh, ਅੱਖਰ *ctype, ਪੂਰਨ type, ਪੂਰਨ rfd, ਪੂਰਨ wfd, ਪੂਰਨ efd,
    u_int ਖਿੜਕੀ, u_int maxpack, ਪੂਰਨ extusage, ਅਚਲ ਅੱਖਰ *remote_name,
    ਪੂਰਨ nonblock)
{
	ਬਣਤਰ ssh_channels *sc = ssh->chanctxt;
	u_int i, ਮਿਲਿਆ = 0;
	Channel *c;
	ਪੂਰਨ r;

	/* Try to find a free slot where to put the new channel. */
	ਲਈ (i = 0; i < sc->channels_alloc; i++) {
		ਜੇ (sc->channels[i] == ਨਿਰਾ) {
			/* Found a free slot. */
			ਮਿਲਿਆ = i;
			ਰੋਕੋ;
		}
	}
	ਜੇ (i >= sc->channels_alloc) {
		/*
		 * There are no free slots. Take last+1 slot and expand
		 * the array.
		 */
		ਮਿਲਿਆ = sc->channels_alloc;
		ਜੇ (sc->channels_alloc > CHANNELS_MAX_CHANNELS)
			fatal_f("internal error: channels_alloc %d too big",
			    sc->channels_alloc);
		sc->channels = xrecallocarray(sc->channels, sc->channels_alloc,
		    sc->channels_alloc + 10, ਆਕਾਰ(*sc->channels));
		sc->channels_alloc += 10;
		debug2("channel: expanding %d", sc->channels_alloc);
	}
	/* Initialize and return new channel. */
	c = sc->channels[ਮਿਲਿਆ] = xcalloc(1, ਆਕਾਰ(Channel));
	ਜੇ ((c->ਨਿਵੇਸ਼ = sshbuf_new()) == ਨਿਰਾ ||
	    (c->output = sshbuf_new()) == ਨਿਰਾ ||
	    (c->extended = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	ਜੇ ((r = sshbuf_ਸੈੱਟ_max_ਮਾਪ(c->ਨਿਵੇਸ਼, CHAN_ਨਿਵੇਸ਼_MAX)) != 0)
		fatal_fr(r, "sshbuf_set_max_size");
	c->ostate = CHAN_OUTPUT_OPEN;
	c->istate = CHAN_ਨਿਵੇਸ਼_OPEN;
	channel_ਰਜਿਸਟਰ_fds(ssh, c, rfd, wfd, efd, extusage, nonblock, 0);
	c->self = ਮਿਲਿਆ;
	c->type = type;
	c->ctype = ctype;
	c->local_ਖਿੜਕੀ = ਖਿੜਕੀ;
	c->local_ਖਿੜਕੀ_max = ਖਿੜਕੀ;
	c->local_maxpacket = maxpack;
	c->remote_name = xstrdup(remote_name);
	c->ctl_chan = -1;
	c->delayed = 1;		/* prevent call to channel_post handler */
	c->inactive_deadline = lookup_timeout(ssh, c->ctype);
	TAILQ_INIT(&c->ਸਥਿਤੀ_confirms);
	channel_classify(ssh, c);
	debug("channel %d: new %s [%s] (inactive timeout: %f)",
	    ਮਿਲਿਆ, c->ctype, remote_name, c->inactive_deadline != 0.0 ?
	    c->inactive_deadline : sc->global_deadline);
	ਵਾਪਸ c;
}

ਖਾਲੀ
channel_ਸੈੱਟ_tty(ਬਣਤਰ ssh *ssh, Channel *c)
{
	c->remote_has_tty = 1;
	channel_classify(ssh, c);
}

ਪੂਰਨ
channel_close_fd(ਬਣਤਰ ssh *ssh, Channel *c, ਪੂਰਨ *fdp)
{
	ਪੂਰਨ ret, fd = *fdp;

	ਜੇ (fd == -1)
		ਵਾਪਸ 0;

	/* restore blocking */
	ਜੇ (*fdp == c->rfd &&
	    (c->restore_ਖੰਡ & CHANNEL_RESTORE_RFD) != 0)
		(ਖਾਲੀ)fcntl(*fdp, F_SETFL, c->restore_flags[0]);
	ਨਹੀਂਤਾਂ ਜੇ (*fdp == c->wfd &&
	    (c->restore_ਖੰਡ & CHANNEL_RESTORE_WFD) != 0)
		(ਖਾਲੀ)fcntl(*fdp, F_SETFL, c->restore_flags[1]);
	ਨਹੀਂਤਾਂ ਜੇ (*fdp == c->efd &&
	    (c->restore_ਖੰਡ & CHANNEL_RESTORE_EFD) != 0)
		(ਖਾਲੀ)fcntl(*fdp, F_SETFL, c->restore_flags[2]);

	ਜੇ (*fdp == c->rfd) {
		c->io_want &= ~SSH_CHAN_IO_RFD;
		c->io_ready &= ~SSH_CHAN_IO_RFD;
		c->rfd = -1;
		c->pfds[0] = -1;
	}
	ਜੇ (*fdp == c->wfd) {
		c->io_want &= ~SSH_CHAN_IO_WFD;
		c->io_ready &= ~SSH_CHAN_IO_WFD;
		c->wfd = -1;
		c->pfds[1] = -1;
	}
	ਜੇ (*fdp == c->efd) {
		c->io_want &= ~SSH_CHAN_IO_EFD;
		c->io_ready &= ~SSH_CHAN_IO_EFD;
		c->efd = -1;
		c->pfds[2] = -1;
	}
	ਜੇ (*fdp == c->sock) {
		c->io_want &= ~SSH_CHAN_IO_SOCK;
		c->io_ready &= ~SSH_CHAN_IO_SOCK;
		c->sock = -1;
		c->pfds[3] = -1;
	}

	ret = close(fd);
	*fdp = -1; /* probably redundant */
	ਵਾਪਸ ret;
}

/* Close all channel fd/socket. */
ਸਥਿਰ ਖਾਲੀ
channel_close_fds(ਬਣਤਰ ssh *ssh, Channel *c)
{
	ਪੂਰਨ sock = c->sock, rfd = c->rfd, wfd = c->wfd, efd = c->efd;

	channel_close_fd(ssh, c, &c->sock);
	ਜੇ (rfd != sock)
		channel_close_fd(ssh, c, &c->rfd);
	ਜੇ (wfd != sock && wfd != rfd)
		channel_close_fd(ssh, c, &c->wfd);
	ਜੇ (efd != sock && efd != rfd && efd != wfd)
		channel_close_fd(ssh, c, &c->efd);
}

ਸਥਿਰ ਖਾਲੀ
fwd_perm_clear(ਬਣਤਰ permission *perm)
{
	ਮੁਕਤ(perm->host_ਮੰਜ਼ਿਲ_connect);
	ਮੁਕਤ(perm->listen_host);
	ਮੁਕਤ(perm->listen_ਰਸਤਾ);
	memset(perm, 0, ਆਕਾਰ(*perm));
}

/* Returns an printable name for the specified forwarding permission list */
ਸਥਿਰ ਅਚਲ ਅੱਖਰ *
fwd_ident(ਪੂਰਨ who, ਪੂਰਨ where)
{
	ਜੇ (who == FORWARD_ADM) {
		ਜੇ (where == FORWARD_LOCAL)
			ਵਾਪਸ "admin local";
		ਨਹੀਂਤਾਂ ਜੇ (where == FORWARD_REMOTE)
			ਵਾਪਸ "admin remote";
	} ਨਹੀਂਤਾਂ ਜੇ (who == FORWARD_USER) {
		ਜੇ (where == FORWARD_LOCAL)
			ਵਾਪਸ "user local";
		ਨਹੀਂਤਾਂ ਜੇ (where == FORWARD_REMOTE)
			ਵਾਪਸ "user remote";
	}
	fatal("Unknown forward permission list %d/%d", who, where);
}

/* Returns the forwarding permission list for the specified direction */
ਸਥਿਰ ਬਣਤਰ permission_ਸੈੱਟ *
permission_ਸੈੱਟ_get(ਬਣਤਰ ssh *ssh, ਪੂਰਨ where)
{
	ਬਣਤਰ ssh_channels *sc = ssh->chanctxt;

	ਚੋਣ (where) {
	ਹਾਲਤ FORWARD_LOCAL:
		ਵਾਪਸ &sc->local_perms;
		ਰੋਕੋ;
	ਹਾਲਤ FORWARD_REMOTE:
		ਵਾਪਸ &sc->remote_perms;
		ਰੋਕੋ;
	ਮੂਲ:
		fatal_f("invalid forwarding direction %d", where);
	}
}

/* Returns pointers to the specified forwarding list and its element count */
ਸਥਿਰ ਖਾਲੀ
permission_ਸੈੱਟ_get_array(ਬਣਤਰ ssh *ssh, ਪੂਰਨ who, ਪੂਰਨ where,
    ਬਣਤਰ permission ***permpp, u_int **npermpp)
{
	ਬਣਤਰ permission_ਸੈੱਟ *pset = permission_ਸੈੱਟ_get(ssh, where);

	ਚੋਣ (who) {
	ਹਾਲਤ FORWARD_USER:
		*permpp = &pset->permitted_user;
		*npermpp = &pset->ਅੰਕ_permitted_user;
		ਰੋਕੋ;
	ਹਾਲਤ FORWARD_ADM:
		*permpp = &pset->permitted_admin;
		*npermpp = &pset->ਅੰਕ_permitted_admin;
		ਰੋਕੋ;
	ਮੂਲ:
		fatal_f("invalid forwarding client %d", who);
	}
}

/* Adds an entry to the specified forwarding list */
ਸਥਿਰ ਪੂਰਨ
permission_ਸੈੱਟ_ਜੋੜੋ(ਬਣਤਰ ssh *ssh, ਪੂਰਨ who, ਪੂਰਨ where,
    ਅਚਲ ਅੱਖਰ *host_ਮੰਜ਼ਿਲ_connect, ਪੂਰਨ ਪੋਰਟ_ਮੰਜ਼ਿਲ_connect,
    ਅਚਲ ਅੱਖਰ *listen_host, ਅਚਲ ਅੱਖਰ *listen_ਰਸਤਾ, ਪੂਰਨ listen_ਪੋਰਟ,
    Channel *downstream)
{
	ਬਣਤਰ permission **permp;
	u_int n, *npermp;

	permission_ਸੈੱਟ_get_array(ssh, who, where, &permp, &npermp);

	ਜੇ (*npermp >= ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ)
		fatal_f("%s overflow", fwd_ident(who, where));

	*permp = xrecallocarray(*permp, *npermp, *npermp + 1, ਆਕਾਰ(**permp));
	n = (*npermp)++;
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MAYBE_DUP(s) ((s == ਨਿਰਾ) ? ਨਿਰਾ : xstrdup(s))
	(*permp)[n].host_ਮੰਜ਼ਿਲ_connect = MAYBE_DUP(host_ਮੰਜ਼ਿਲ_connect);
	(*permp)[n].ਪੋਰਟ_ਮੰਜ਼ਿਲ_connect = ਪੋਰਟ_ਮੰਜ਼ਿਲ_connect;
	(*permp)[n].listen_host = MAYBE_DUP(listen_host);
	(*permp)[n].listen_ਰਸਤਾ = MAYBE_DUP(listen_ਰਸਤਾ);
	(*permp)[n].listen_ਪੋਰਟ = listen_ਪੋਰਟ;
	(*permp)[n].downstream = downstream;
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ MAYBE_DUP
	ਵਾਪਸ (ਪੂਰਨ)n;
}

ਸਥਿਰ ਖਾਲੀ
mux_remove_remote_forwardings(ਬਣਤਰ ssh *ssh, Channel *c)
{
	ਬਣਤਰ ssh_channels *sc = ssh->chanctxt;
	ਬਣਤਰ permission_ਸੈੱਟ *pset = &sc->local_perms;
	ਬਣਤਰ permission *perm;
	ਪੂਰਨ r;
	u_int i;

	ਲਈ (i = 0; i < pset->ਅੰਕ_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		ਜੇ (perm->downstream != c)
			ਜਾਰੀ;

		/* cancel on the server, since mux client is gone */
		debug("channel %d: cleanup remote forward for %s:%u",
		    c->self, perm->listen_host, perm->listen_ਪੋਰਟ);
		ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh, SSH2_ਸੁਨੇਹਾ_GLOBAL_REQUEST)) != 0 ||
		    (r = sshpkt_put_cstring(ssh,
		    "cancel-tcpip-forward")) != 0 ||
		    (r = sshpkt_put_u8(ssh, 0)) != 0 ||
		    (r = sshpkt_put_cstring(ssh,
		    channel_rfwd_bind_host(perm->listen_host))) != 0 ||
		    (r = sshpkt_put_u32(ssh, perm->listen_ਪੋਰਟ)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0) {
			fatal_fr(r, "channel %i", c->self);
		}
		fwd_perm_clear(perm); /* unregister */
	}
}

/* Free the channel and close its fd/socket. */
ਖਾਲੀ
channel_free(ਬਣਤਰ ssh *ssh, Channel *c)
{
	ਬਣਤਰ ssh_channels *sc = ssh->chanctxt;
	ਅੱਖਰ *s;
	u_int i, n;
	Channel *other;
	ਬਣਤਰ channel_confirm *cc;

	ਲਈ (n = 0, i = 0; i < sc->channels_alloc; i++) {
		ਜੇ ((other = sc->channels[i]) == ਨਿਰਾ)
			ਜਾਰੀ;
		n++;
		/* detach from mux client and prepare for closing */
		ਜੇ (c->type == SSH_CHANNEL_MUX_CLIENT &&
		    other->type == SSH_CHANNEL_MUX_PROXY &&
		    other->mux_ctx == c) {
			other->mux_ctx = ਨਿਰਾ;
			other->type = SSH_CHANNEL_OPEN;
			other->istate = CHAN_ਨਿਵੇਸ਼_CLOSED;
			other->ostate = CHAN_OUTPUT_CLOSED;
		}
	}
	debug("channel %d: free: %s, nchannels %u", c->self,
	    c->remote_name ? c->remote_name : "???", n);

	ਜੇ (c->type == SSH_CHANNEL_MUX_CLIENT) {
		mux_remove_remote_forwardings(ssh, c);
		ਮੁਕਤ(c->mux_ctx);
		c->mux_ctx = ਨਿਰਾ;
	} ਨਹੀਂਤਾਂ ਜੇ (c->type == SSH_CHANNEL_MUX_LISTENER) {
		ਮੁਕਤ(c->mux_ctx);
		c->mux_ctx = ਨਿਰਾ;
	}

	ਜੇ (log_level_get() >= SYSLOG_LEVEL_DEBUG3) {
		s = channel_open_ਸੁਨੇਹਾ(ssh);
		debug3("channel %d: status: %s", c->self, s);
		ਮੁਕਤ(s);
	}

	channel_close_fds(ssh, c);
	sshbuf_free(c->ਨਿਵੇਸ਼);
	sshbuf_free(c->output);
	sshbuf_free(c->extended);
	c->ਨਿਵੇਸ਼ = c->output = c->extended = ਨਿਰਾ;
	ਮੁਕਤ(c->remote_name);
	c->remote_name = ਨਿਰਾ;
	ਮੁਕਤ(c->ਰਸਤਾ);
	c->ਰਸਤਾ = ਨਿਰਾ;
	ਮੁਕਤ(c->listening_addr);
	c->listening_addr = ਨਿਰਾ;
	ਮੁਕਤ(c->xctype);
	c->xctype = ਨਿਰਾ;
	channel_free_connect_ctx(c);
	ਜਦੋਂ ((cc = TAILQ_FIRST(&c->ਸਥਿਤੀ_confirms)) != ਨਿਰਾ) {
		ਜੇ (cc->abandon_cb != ਨਿਰਾ)
			cc->abandon_cb(ssh, c, cc->ctx);
		TAILQ_REMOVE(&c->ਸਥਿਤੀ_confirms, cc, ਇੰਦਰਾਜ);
		freezero(cc, ਆਕਾਰ(*cc));
	}
	ਜੇ (c->filter_cleanup != ਨਿਰਾ && c->filter_ctx != ਨਿਰਾ)
		c->filter_cleanup(ssh, c->self, c->filter_ctx);
	sc->channels[c->self] = ਨਿਰਾ;
	freezero(c, ਆਕਾਰ(*c));
}

ਖਾਲੀ
channel_free_all(ਬਣਤਰ ssh *ssh)
{
	u_int i;
	ਬਣਤਰ ssh_channels *sc = ssh->chanctxt;

	ਲਈ (i = 0; i < sc->channels_alloc; i++)
		ਜੇ (sc->channels[i] != ਨਿਰਾ)
			channel_free(ssh, sc->channels[i]);

	ਮੁਕਤ(sc->channels);
	sc->channels = ਨਿਰਾ;
	sc->channels_alloc = 0;

	ਮੁਕਤ(sc->x11_saved_display);
	sc->x11_saved_display = ਨਿਰਾ;

	ਮੁਕਤ(sc->x11_saved_proto);
	sc->x11_saved_proto = ਨਿਰਾ;

	ਮੁਕਤ(sc->x11_saved_ਅੰਕੜੇ);
	sc->x11_saved_ਅੰਕੜੇ = ਨਿਰਾ;
	sc->x11_saved_ਅੰਕੜੇ_len = 0;

	ਮੁਕਤ(sc->x11_fake_ਅੰਕੜੇ);
	sc->x11_fake_ਅੰਕੜੇ = ਨਿਰਾ;
	sc->x11_fake_ਅੰਕੜੇ_len = 0;
}

ਖਾਲੀ
channel_free_channels(ਬਣਤਰ ssh *ssh)
{
	ਬਣਤਰ ssh_channels *sc;

	ਜੇ (ssh == ਨਿਰਾ || ssh->chanctxt == ਨਿਰਾ)
		ਵਾਪਸ;
	channel_free_all(ssh);
	channel_clear_permission(ssh, FORWARD_USER, FORWARD_LOCAL);
	channel_clear_permission(ssh, FORWARD_USER, FORWARD_REMOTE);
	channel_clear_permission(ssh, FORWARD_ADM, FORWARD_LOCAL);
	channel_clear_permission(ssh, FORWARD_ADM, FORWARD_REMOTE);
	sc = ssh->chanctxt;
	ਮੁਕਤ(sc->bulk_classifier_tty);
	ਮੁਕਤ(sc->bulk_classifier_notty);
	ਮੁਕਤ(sc->channel_pre);
	ਮੁਕਤ(sc->channel_post);
	freezero(sc, ਆਕਾਰ(*sc));
	ssh->chanctxt = ਨਿਰਾ;
}

/*
 * Closes the sockets/fds of all channels.  This is used to close extra file
 * descriptors after a fork.
 */
ਖਾਲੀ
channel_close_all(ਬਣਤਰ ssh *ssh)
{
	u_int i;

	ਲਈ (i = 0; i < ssh->chanctxt->channels_alloc; i++)
		ਜੇ (ssh->chanctxt->channels[i] != ਨਿਰਾ)
			channel_close_fds(ssh, ssh->chanctxt->channels[i]);
}

/*
 * Stop listening to channels.
 */
ਖਾਲੀ
channel_stop_listening(ਬਣਤਰ ssh *ssh)
{
	u_int i;
	Channel *c;

	ਲਈ (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		ਜੇ (c != ਨਿਰਾ) {
			ਚੋਣ (c->type) {
			ਹਾਲਤ SSH_CHANNEL_AUTH_SOCKET:
			ਹਾਲਤ SSH_CHANNEL_ਪੋਰਟ_LISTENER:
			ਹਾਲਤ SSH_CHANNEL_RPORT_LISTENER:
			ਹਾਲਤ SSH_CHANNEL_X11_LISTENER:
			ਹਾਲਤ SSH_CHANNEL_UNIX_LISTENER:
			ਹਾਲਤ SSH_CHANNEL_RUNIX_LISTENER:
				channel_close_fd(ssh, c, &c->sock);
				channel_free(ssh, c);
				ਰੋਕੋ;
			}
		}
	}
}

/*
 * Returns true if no channel has too much buffered data, and false if one or
 * more channel is overfull.
 */
ਪੂਰਨ
channel_not_very_much_buffered_ਅੰਕੜੇ(ਬਣਤਰ ssh *ssh)
{
	u_int i;
	u_int maxsize = ssh_packet_get_maxsize(ssh);
	Channel *c;

	ਲਈ (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		ਜੇ (c == ਨਿਰਾ || c->type != SSH_CHANNEL_OPEN)
			ਜਾਰੀ;
		ਜੇ (sshbuf_len(c->output) > maxsize) {
			debug2("channel %d: big output buffer %zu > %u",
			    c->self, sshbuf_len(c->output), maxsize);
			ਵਾਪਸ 0;
		}
	}
	ਵਾਪਸ 1;
}

/* Returns true if any channel is still open. */
ਪੂਰਨ
channel_still_open(ਬਣਤਰ ssh *ssh)
{
	u_int i;
	Channel *c;

	ਲਈ (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		ਜੇ (c == ਨਿਰਾ)
			ਜਾਰੀ;
		ਚੋਣ (c->type) {
		ਹਾਲਤ SSH_CHANNEL_X11_LISTENER:
		ਹਾਲਤ SSH_CHANNEL_ਪੋਰਟ_LISTENER:
		ਹਾਲਤ SSH_CHANNEL_RPORT_LISTENER:
		ਹਾਲਤ SSH_CHANNEL_MUX_LISTENER:
		ਹਾਲਤ SSH_CHANNEL_CLOSED:
		ਹਾਲਤ SSH_CHANNEL_AUTH_SOCKET:
		ਹਾਲਤ SSH_CHANNEL_DYNAMIC:
		ਹਾਲਤ SSH_CHANNEL_RDYNAMIC_OPEN:
		ਹਾਲਤ SSH_CHANNEL_CONNECTING:
		ਹਾਲਤ SSH_CHANNEL_ZOMBIE:
		ਹਾਲਤ SSH_CHANNEL_ABANDONED:
		ਹਾਲਤ SSH_CHANNEL_UNIX_LISTENER:
		ਹਾਲਤ SSH_CHANNEL_RUNIX_LISTENER:
			ਜਾਰੀ;
		ਹਾਲਤ SSH_CHANNEL_LARVAL:
			ਜਾਰੀ;
		ਹਾਲਤ SSH_CHANNEL_OPENING:
		ਹਾਲਤ SSH_CHANNEL_OPEN:
		ਹਾਲਤ SSH_CHANNEL_RDYNAMIC_ਅੰਤ:
		ਹਾਲਤ SSH_CHANNEL_X11_OPEN:
		ਹਾਲਤ SSH_CHANNEL_MUX_CLIENT:
		ਹਾਲਤ SSH_CHANNEL_MUX_PROXY:
			ਵਾਪਸ 1;
		ਮੂਲ:
			fatal_f("bad channel type %d", c->type);
			/* NOTREACHED */
		}
	}
	ਵਾਪਸ 0;
}

/* Returns true if a channel with a TTY is open. */
ਪੂਰਨ
channel_tty_open(ਬਣਤਰ ssh *ssh)
{
	u_int i;
	Channel *c;

	ਲਈ (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		ਜੇ (c == ਨਿਰਾ || c->type != SSH_CHANNEL_OPEN)
			ਜਾਰੀ;
		ਜੇ (c->client_tty)
			ਵਾਪਸ 1;
	}
	ਵਾਪਸ 0;
}

/* Returns the id of an open channel suitable for keepaliving */
ਪੂਰਨ
channel_ਲੱਭੋ_open(ਬਣਤਰ ssh *ssh)
{
	u_int i;
	Channel *c;

	ਲਈ (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		ਜੇ (c == ਨਿਰਾ || !c->have_remote_id)
			ਜਾਰੀ;
		ਚੋਣ (c->type) {
		ਹਾਲਤ SSH_CHANNEL_CLOSED:
		ਹਾਲਤ SSH_CHANNEL_DYNAMIC:
		ਹਾਲਤ SSH_CHANNEL_RDYNAMIC_OPEN:
		ਹਾਲਤ SSH_CHANNEL_RDYNAMIC_ਅੰਤ:
		ਹਾਲਤ SSH_CHANNEL_X11_LISTENER:
		ਹਾਲਤ SSH_CHANNEL_ਪੋਰਟ_LISTENER:
		ਹਾਲਤ SSH_CHANNEL_RPORT_LISTENER:
		ਹਾਲਤ SSH_CHANNEL_MUX_LISTENER:
		ਹਾਲਤ SSH_CHANNEL_MUX_CLIENT:
		ਹਾਲਤ SSH_CHANNEL_MUX_PROXY:
		ਹਾਲਤ SSH_CHANNEL_OPENING:
		ਹਾਲਤ SSH_CHANNEL_CONNECTING:
		ਹਾਲਤ SSH_CHANNEL_ZOMBIE:
		ਹਾਲਤ SSH_CHANNEL_ABANDONED:
		ਹਾਲਤ SSH_CHANNEL_UNIX_LISTENER:
		ਹਾਲਤ SSH_CHANNEL_RUNIX_LISTENER:
			ਜਾਰੀ;
		ਹਾਲਤ SSH_CHANNEL_LARVAL:
		ਹਾਲਤ SSH_CHANNEL_AUTH_SOCKET:
		ਹਾਲਤ SSH_CHANNEL_OPEN:
		ਹਾਲਤ SSH_CHANNEL_X11_OPEN:
			ਵਾਪਸ i;
		ਮੂਲ:
			fatal_f("bad channel type %d", c->type);
			/* NOTREACHED */
		}
	}
	ਵਾਪਸ -1;
}

/* Returns the state of the channel's extended usage flag */
ਅਚਲ ਅੱਖਰ *
channel_format_extended_usage(ਅਚਲ Channel *c)
{
	ਜੇ (c->efd == -1)
		ਵਾਪਸ "closed";

	ਚੋਣ (c->extended_usage) {
	ਹਾਲਤ CHAN_EXTENDED_WRITE:
		ਵਾਪਸ "write";
	ਹਾਲਤ CHAN_EXTENDED_READ:
		ਵਾਪਸ "read";
	ਹਾਲਤ CHAN_EXTENDED_IGNORE:
		ਵਾਪਸ "ignore";
	ਮੂਲ:
		ਵਾਪਸ "UNKNOWN";
	}
}

ਸਥਿਰ ਅੱਖਰ *
channel_format_ਸਥਿਤੀ(ਅਚਲ Channel *c)
{
	ਅੱਖਰ *ret = ਨਿਰਾ;

	xasprintf(&ret, "t%d [%s] %s%u %s%u i%u/%zu o%u/%zu e[%s]/%zu "
	    "fd %d/%d/%d sock %d cc %d %s%u io 0x%02x/0x%02x %s%s",
	    c->type, c->xctype != ਨਿਰਾ ? c->xctype : c->ctype,
	    c->have_remote_id ? "r" : "nr", c->remote_id,
	    c->mux_ctx != ਨਿਰਾ ? "m" : "nm", c->mux_downstream_id,
	    c->istate, sshbuf_len(c->ਨਿਵੇਸ਼),
	    c->ostate, sshbuf_len(c->output),
	    channel_format_extended_usage(c), sshbuf_len(c->extended),
	    c->rfd, c->wfd, c->efd, c->sock, c->ctl_chan,
	    c->have_ctl_ਬੱਚਾ_id ? "c" : "nc", c->ctl_ਬੱਚਾ_id,
	    c->io_want, c->io_ready,
	    c->isatty ? "T" : (c->remote_has_tty ? "RT" : ""),
	    c->bulk ? "B" : "I");
	ਵਾਪਸ ret;
}

/*
 * Returns a message describing the currently open forwarded connections,
 * suitable for sending to the client.  The message contains crlf pairs for
 * newlines.
 */
ਅੱਖਰ *
channel_open_ਸੁਨੇਹਾ(ਬਣਤਰ ssh *ssh)
{
	ਬਣਤਰ sshbuf *buf;
	Channel *c;
	u_int i;
	ਪੂਰਨ r;
	ਅੱਖਰ *cp, *ret;

	ਜੇ ((buf = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new");
	ਜੇ ((r = sshbuf_putf(buf,
	    "The following connections are open:\r\n")) != 0)
		fatal_fr(r, "sshbuf_putf");
	ਲਈ (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		ਜੇ (c == ਨਿਰਾ)
			ਜਾਰੀ;
		ਚੋਣ (c->type) {
		ਹਾਲਤ SSH_CHANNEL_X11_LISTENER:
		ਹਾਲਤ SSH_CHANNEL_ਪੋਰਟ_LISTENER:
		ਹਾਲਤ SSH_CHANNEL_RPORT_LISTENER:
		ਹਾਲਤ SSH_CHANNEL_CLOSED:
		ਹਾਲਤ SSH_CHANNEL_AUTH_SOCKET:
		ਹਾਲਤ SSH_CHANNEL_ZOMBIE:
		ਹਾਲਤ SSH_CHANNEL_ABANDONED:
		ਹਾਲਤ SSH_CHANNEL_MUX_LISTENER:
		ਹਾਲਤ SSH_CHANNEL_UNIX_LISTENER:
		ਹਾਲਤ SSH_CHANNEL_RUNIX_LISTENER:
			ਜਾਰੀ;
		ਹਾਲਤ SSH_CHANNEL_LARVAL:
		ਹਾਲਤ SSH_CHANNEL_OPENING:
		ਹਾਲਤ SSH_CHANNEL_CONNECTING:
		ਹਾਲਤ SSH_CHANNEL_DYNAMIC:
		ਹਾਲਤ SSH_CHANNEL_RDYNAMIC_OPEN:
		ਹਾਲਤ SSH_CHANNEL_RDYNAMIC_ਅੰਤ:
		ਹਾਲਤ SSH_CHANNEL_OPEN:
		ਹਾਲਤ SSH_CHANNEL_X11_OPEN:
		ਹਾਲਤ SSH_CHANNEL_MUX_PROXY:
		ਹਾਲਤ SSH_CHANNEL_MUX_CLIENT:
			cp = channel_format_ਸਥਿਤੀ(c);
			ਜੇ ((r = sshbuf_putf(buf, "  #%d %.300s (%s)\r\n",
			    c->self, c->remote_name, cp)) != 0) {
				ਮੁਕਤ(cp);
				fatal_fr(r, "sshbuf_putf");
			}
			ਮੁਕਤ(cp);
			ਜਾਰੀ;
		ਮੂਲ:
			fatal_f("bad channel type %d", c->type);
			/* NOTREACHED */
		}
	}
	ਜੇ ((ret = sshbuf_dup_string(buf)) == ਨਿਰਾ)
		fatal_f("sshbuf_dup_string");
	sshbuf_free(buf);
	ਵਾਪਸ ret;
}

ਖਾਲੀ
channel_report_open(ਬਣਤਰ ssh *ssh, ਪੂਰਨ level)
{
	ਅੱਖਰ *open, *oopen, *cp, ident[256];

	sshpkt_fmt_connection_id(ssh, ident, ਆਕਾਰ(ident));
	do_log2(level, "Connection: %s (pid %ld)", ident, (ਲੰਮਾ)getpid());
	open = oopen = channel_open_ਸੁਨੇਹਾ(ssh);
	ਜਦੋਂ ((cp = strsep(&open, "\r\n")) != ਨਿਰਾ) {
		ਜੇ (*cp != '\0')
			do_log2(level, "%s", cp);
	}
	ਮੁਕਤ(oopen);
}

ਸਥਿਰ ਖਾਲੀ
open_preamble(ਬਣਤਰ ssh *ssh, ਅਚਲ ਅੱਖਰ *where, Channel *c, ਅਚਲ ਅੱਖਰ *type)
{
	ਪੂਰਨ r;

	ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh, SSH2_ਸੁਨੇਹਾ_CHANNEL_OPEN)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, type)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_ਖਿੜਕੀ)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0) {
		fatal_r(r, "%s: channel %i: open", where, c->self);
	}
}

ਖਾਲੀ
channel_send_open(ਬਣਤਰ ssh *ssh, ਪੂਰਨ id)
{
	Channel *c = channel_lookup(ssh, id);
	ਪੂਰਨ r;

	ਜੇ (c == ਨਿਰਾ) {
		logit("channel_send_open: %d: bad id", id);
		ਵਾਪਸ;
	}
	debug2("channel %d: send open", id);
	open_preamble(ssh, __func__, c, c->ctype);
	ਜੇ ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i", c->self);
}

ਖਾਲੀ
channel_request_ਸ਼ੁਰੂ(ਬਣਤਰ ssh *ssh, ਪੂਰਨ id, ਅਚਲ ਅੱਖਰ *service,
    ਪੂਰਨ wantconfirm)
{
	Channel *c = channel_lookup(ssh, id);
	ਪੂਰਨ r;

	ਜੇ (c == ਨਿਰਾ) {
		logit_f("%d: unknown channel id", id);
		ਵਾਪਸ;
	}
	ਜੇ (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);

	debug2("channel %d: request %s confirm %d", id, service, wantconfirm);
	ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh, SSH2_ਸੁਨੇਹਾ_CHANNEL_REQUEST)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, service)) != 0 ||
	    (r = sshpkt_put_u8(ssh, wantconfirm)) != 0) {
		fatal_fr(r, "channel %i", c->self);
	}
}

ਖਾਲੀ
channel_ਰਜਿਸਟਰ_ਸਥਿਤੀ_confirm(ਬਣਤਰ ssh *ssh, ਪੂਰਨ id,
    channel_confirm_cb *cb, channel_confirm_abandon_cb *abandon_cb, ਖਾਲੀ *ctx)
{
	ਬਣਤਰ channel_confirm *cc;
	Channel *c;

	ਜੇ ((c = channel_lookup(ssh, id)) == ਨਿਰਾ)
		fatal_f("%d: bad id", id);

	cc = xcalloc(1, ਆਕਾਰ(*cc));
	cc->cb = cb;
	cc->abandon_cb = abandon_cb;
	cc->ctx = ctx;
	TAILQ_INSERT_TAIL(&c->ਸਥਿਤੀ_confirms, cc, ਇੰਦਰਾਜ);
}

ਖਾਲੀ
channel_ਰਜਿਸਟਰ_open_confirm(ਬਣਤਰ ssh *ssh, ਪੂਰਨ id,
    channel_open_fn *fn, ਖਾਲੀ *ctx)
{
	Channel *c = channel_lookup(ssh, id);

	ਜੇ (c == ਨਿਰਾ) {
		logit_f("%d: bad id", id);
		ਵਾਪਸ;
	}
	c->open_confirm = fn;
	c->open_confirm_ctx = ctx;
}

ਖਾਲੀ
channel_ਰਜਿਸਟਰ_cleanup(ਬਣਤਰ ssh *ssh, ਪੂਰਨ id,
    channel_callback_fn *fn, ਪੂਰਨ do_close)
{
	Channel *c = channel_by_id(ssh, id);

	ਜੇ (c == ਨਿਰਾ) {
		logit_f("%d: bad id", id);
		ਵਾਪਸ;
	}
	c->detach_user = fn;
	c->detach_close = do_close;
}

ਖਾਲੀ
channel_cancel_cleanup(ਬਣਤਰ ssh *ssh, ਪੂਰਨ id)
{
	Channel *c = channel_by_id(ssh, id);

	ਜੇ (c == ਨਿਰਾ) {
		logit_f("%d: bad id", id);
		ਵਾਪਸ;
	}
	c->detach_user = ਨਿਰਾ;
	c->detach_close = 0;
}

ਖਾਲੀ
channel_ਰਜਿਸਟਰ_filter(ਬਣਤਰ ssh *ssh, ਪੂਰਨ id, channel_infilter_fn *ifn,
    channel_outfilter_fn *ofn, channel_filter_cleanup_fn *cfn, ਖਾਲੀ *ctx)
{
	Channel *c = channel_lookup(ssh, id);

	ਜੇ (c == ਨਿਰਾ) {
		logit_f("%d: bad id", id);
		ਵਾਪਸ;
	}
	c->ਨਿਵੇਸ਼_filter = ifn;
	c->output_filter = ofn;
	c->filter_ctx = ctx;
	c->filter_cleanup = cfn;
}

ਖਾਲੀ
channel_ਸੈੱਟ_fds(ਬਣਤਰ ssh *ssh, ਪੂਰਨ id, ਪੂਰਨ rfd, ਪੂਰਨ wfd, ਪੂਰਨ efd,
    ਪੂਰਨ extusage, ਪੂਰਨ nonblock, ਪੂਰਨ is_tty, u_int ਖਿੜਕੀ_max)
{
	Channel *c = channel_lookup(ssh, id);
	ਪੂਰਨ r;

	ਜੇ (c == ਨਿਰਾ || c->type != SSH_CHANNEL_LARVAL)
		fatal("channel_activate for non-larval channel %d.", id);
	ਜੇ (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);

	channel_ਰਜਿਸਟਰ_fds(ssh, c, rfd, wfd, efd, extusage, nonblock, is_tty);
	c->type = SSH_CHANNEL_OPEN;
	channel_ਸੈੱਟ_ਵਰਤਿਆ_ਸਮਾਂ(ssh, c);
	c->local_ਖਿੜਕੀ = c->local_ਖਿੜਕੀ_max = ਖਿੜਕੀ_max;

	ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh, SSH2_ਸੁਨੇਹਾ_CHANNEL_ਖਿੜਕੀ_ADJUST)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_ਖਿੜਕੀ)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i", c->self);
}

ਸਥਿਰ ਖਾਲੀ
channel_pre_listener(ਬਣਤਰ ssh *ssh, Channel *c)
{
	c->io_want = SSH_CHAN_IO_SOCK_R;
}

ਸਥਿਰ ਖਾਲੀ
channel_pre_connecting(ਬਣਤਰ ssh *ssh, Channel *c)
{
	debug3("channel %d: waiting for connection", c->self);
	c->io_want = SSH_CHAN_IO_SOCK_W;
}

ਸਥਿਰ ਖਾਲੀ
channel_pre_open(ਬਣਤਰ ssh *ssh, Channel *c)
{
	c->io_want = 0;
	ਜੇ (c->istate == CHAN_ਨਿਵੇਸ਼_OPEN &&
	    c->remote_ਖਿੜਕੀ > 0 &&
	    sshbuf_len(c->ਨਿਵੇਸ਼) < c->remote_ਖਿੜਕੀ &&
	    sshbuf_check_reserve(c->ਨਿਵੇਸ਼, CHAN_RBUF) == 0)
		c->io_want |= SSH_CHAN_IO_RFD;
	ਜੇ (c->ostate == CHAN_OUTPUT_OPEN ||
	    c->ostate == CHAN_OUTPUT_WAIT_DRAIN) {
		ਜੇ (sshbuf_len(c->output) > 0) {
			c->io_want |= SSH_CHAN_IO_WFD;
		} ਨਹੀਂਤਾਂ ਜੇ (c->ostate == CHAN_OUTPUT_WAIT_DRAIN) {
			ਜੇ (CHANNEL_EFD_OUTPUT_ਸਰਗਰਮ(c))
				debug2("channel %d: "
				    "obuf_empty delayed efd %d/(%zu)", c->self,
				    c->efd, sshbuf_len(c->extended));
			ਨਹੀਂਤਾਂ
				chan_obuf_ਖਾਲੀ_ਥਾਵਾਂ(ssh, c);
		}
	}
	/** XXX check close conditions, too */
	ਜੇ (c->efd != -1 && !(c->istate == CHAN_ਨਿਵੇਸ਼_CLOSED &&
	    c->ostate == CHAN_OUTPUT_CLOSED)) {
		ਜੇ (c->extended_usage == CHAN_EXTENDED_WRITE &&
		    sshbuf_len(c->extended) > 0)
			c->io_want |= SSH_CHAN_IO_EFD_W;
		ਨਹੀਂਤਾਂ ਜੇ (c->efd != -1 && !(c->flags & CHAN_EOF_ਭੇਜਿਆ) &&
		    (c->extended_usage == CHAN_EXTENDED_READ ||
		    c->extended_usage == CHAN_EXTENDED_IGNORE) &&
		    sshbuf_len(c->extended) < c->remote_ਖਿੜਕੀ)
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
ਸਥਿਰ ਪੂਰਨ
x11_open_helper(ਬਣਤਰ ssh *ssh, ਬਣਤਰ sshbuf *b)
{
	ਬਣਤਰ ssh_channels *sc = ssh->chanctxt;
	u_char *ucp;
	u_int proto_len, ਅੰਕੜੇ_len;

	ਜੇ (sc->x11_saved_proto == ਨਿਰਾ) {
		error("X11 forwarding opened before X11 forwarding requested");
		ਵਾਪਸ -1;
	}

	/* Is this being called after the refusal deadline? */
	ਜੇ (sc->x11_refuse_ਸਮਾਂ != 0.0 &&
	    monotime_double() >= sc->x11_refuse_ਸਮਾਂ) {
		verbose("Rejected X11 connection after ForwardX11Timeout "
		    "expired");
		ਵਾਪਸ -1;
	}

	/* Check if the fixed size part of the packet is in buffer. */
	ਜੇ (sshbuf_len(b) < 12)
		ਵਾਪਸ 0;

	/* Parse the lengths of variable-length fields. */
	ucp = sshbuf_mutable_ptr(b);
	ਜੇ (ucp[0] == 0x42) {	/* Byte order MSB first. */
		proto_len = 256 * ucp[6] + ucp[7];
		ਅੰਕੜੇ_len = 256 * ucp[8] + ucp[9];
	} ਨਹੀਂਤਾਂ ਜੇ (ucp[0] == 0x6c) {	/* Byte order LSB first. */
		proto_len = ucp[6] + 256 * ucp[7];
		ਅੰਕੜੇ_len = ucp[8] + 256 * ucp[9];
	} ਨਹੀਂਤਾਂ {
		debug2("Initial X11 packet contains bad byte order byte: 0x%x",
		    ucp[0]);
		ਵਾਪਸ -1;
	}

	/* Check if the whole packet is in buffer. */
	ਜੇ (sshbuf_len(b) <
	    12 + ((proto_len + 3) & ~3) + ((ਅੰਕੜੇ_len + 3) & ~3))
		ਵਾਪਸ 0;

	/* Check if authentication protocol matches. */
	ਜੇ (proto_len != ਲੜੀ_ਲੰਬਾਈ(sc->x11_saved_proto) ||
	    memcmp(ucp + 12, sc->x11_saved_proto, proto_len) != 0) {
		debug2("X11 connection uses different authentication protocol.");
		ਵਾਪਸ -1;
	}
	/* Check if authentication data matches our fake data. */
	ਜੇ (ਅੰਕੜੇ_len != sc->x11_fake_ਅੰਕੜੇ_len ||
	    timingsafe_bcmp(ucp + 12 + ((proto_len + 3) & ~3),
		sc->x11_fake_ਅੰਕੜੇ, sc->x11_fake_ਅੰਕੜੇ_len) != 0) {
		debug2("X11 auth data does not match fake data.");
		ਵਾਪਸ -1;
	}
	/* Check fake data length */
	ਜੇ (sc->x11_fake_ਅੰਕੜੇ_len != sc->x11_saved_ਅੰਕੜੇ_len) {
		error("X11 fake_data_len %d != saved_data_len %d",
		    sc->x11_fake_ਅੰਕੜੇ_len, sc->x11_saved_ਅੰਕੜੇ_len);
		ਵਾਪਸ -1;
	}
	/*
	 * Received authentication protocol and data match
	 * our fake data. Substitute the fake data with real
	 * data.
	 */
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(ucp + 12 + ((proto_len + 3) & ~3),
	    sc->x11_saved_ਅੰਕੜੇ, sc->x11_saved_ਅੰਕੜੇ_len);
	ਵਾਪਸ 1;
}

ਖਾਲੀ
channel_force_close(ਬਣਤਰ ssh *ssh, Channel *c, ਪੂਰਨ abandon)
{
	debug3_f("channel %d: forcibly closing", c->self);
	ਜੇ (c->istate == CHAN_ਨਿਵੇਸ਼_OPEN)
		chan_read_failed(ssh, c);
	ਜੇ (c->istate == CHAN_ਨਿਵੇਸ਼_WAIT_DRAIN) {
		sshbuf_reset(c->ਨਿਵੇਸ਼);
		chan_ibuf_ਖਾਲੀ_ਥਾਵਾਂ(ssh, c);
	}
	ਜੇ (c->ostate == CHAN_OUTPUT_OPEN ||
	    c->ostate == CHAN_OUTPUT_WAIT_DRAIN) {
		sshbuf_reset(c->output);
		chan_write_failed(ssh, c);
	}
	ਜੇ (c->detach_user)
		c->detach_user(ssh, c->self, 1, ਨਿਰਾ);
	ਜੇ (c->efd != -1)
		channel_close_fd(ssh, c, &c->efd);
	ਜੇ (abandon)
		c->type = SSH_CHANNEL_ABANDONED;
	/* exempt from inactivity timeouts */
	c->inactive_deadline = 0;
	c->lastused = 0;
}

ਸਥਿਰ ਖਾਲੀ
channel_pre_x11_open(ਬਣਤਰ ssh *ssh, Channel *c)
{
	ਪੂਰਨ ret = x11_open_helper(ssh, c->output);

	/* c->force_drain = 1; */

	ਜੇ (ret == 1) {
		c->type = SSH_CHANNEL_OPEN;
		channel_ਸੈੱਟ_ਵਰਤਿਆ_ਸਮਾਂ(ssh, c);
		channel_pre_open(ssh, c);
	} ਨਹੀਂਤਾਂ ਜੇ (ret == -1) {
		logit("X11 connection rejected because of wrong "
		    "authentication.");
		debug2("X11 rejected %d i%d/o%d",
		    c->self, c->istate, c->ostate);
		channel_force_close(ssh, c, 0);
	}
}

ਸਥਿਰ ਖਾਲੀ
channel_pre_mux_client(ਬਣਤਰ ssh *ssh, Channel *c)
{
	c->io_want = 0;
	ਜੇ (c->istate == CHAN_ਨਿਵੇਸ਼_OPEN && !c->mux_pause &&
	    sshbuf_check_reserve(c->ਨਿਵੇਸ਼, CHAN_RBUF) == 0)
		c->io_want |= SSH_CHAN_IO_RFD;
	ਜੇ (c->istate == CHAN_ਨਿਵੇਸ਼_WAIT_DRAIN) {
		/* clear buffer immediately (discard any partial packet) */
		sshbuf_reset(c->ਨਿਵੇਸ਼);
		chan_ibuf_ਖਾਲੀ_ਥਾਵਾਂ(ssh, c);
		/* Start output drain. XXX just kill chan? */
		chan_rcvd_oclose(ssh, c);
	}
	ਜੇ (c->ostate == CHAN_OUTPUT_OPEN ||
	    c->ostate == CHAN_OUTPUT_WAIT_DRAIN) {
		ਜੇ (sshbuf_len(c->output) > 0)
			c->io_want |= SSH_CHAN_IO_WFD;
		ਨਹੀਂਤਾਂ ਜੇ (c->ostate == CHAN_OUTPUT_WAIT_DRAIN)
			chan_obuf_ਖਾਲੀ_ਥਾਵਾਂ(ssh, c);
	}
}

ਸਥਿਰ ਸਤਰਅੰਦਰ ਪੂਰਨ
socks_decode_error(Channel *c, ਪੂਰਨ ਸਥਿਤੀ, ਅਚਲ ਅੱਖਰ *func, ਅਚਲ ਅੱਖਰ *ਸੁਨੇਹਾ)
{
	ਜੇ (ਸਥਿਤੀ == SSH_ERR_ਸੁਨੇਹਾ_INCOMPLETE)
		ਵਾਪਸ 0;
	ਨਹੀਂਤਾਂ {
		debug_r(ਸਥਿਤੀ, "%s: channel %d: decode %s",
		    func, c->self, ਸੁਨੇਹਾ);
		ਵਾਪਸ -1;
	}
}

/* try to decode a socks4 header */
ਸਥਿਰ ਪੂਰਨ
channel_decode_socks4(Channel *c, ਬਣਤਰ sshbuf *ਨਿਵੇਸ਼, ਬਣਤਰ sshbuf *output)
{
	uint8_t socks_ver, socks_cmd, dest_addr[4];
	uint16_t dest_ਪੋਰਟ;
	ਅੱਖਰ *user = ਨਿਰਾ, *host = ਨਿਰਾ;
	ਪੂਰਨ success = -1, socks4a = 0, r;
	ਬਣਤਰ sshbuf *b = ਨਿਰਾ;

	ਜੇ (sshbuf_len(ਨਿਵੇਸ਼) < 9)
		ਵਾਪਸ 0;

	/* We may not have a complete message, so work on a dup of the buffer */
	ਜੇ ((b = sshbuf_fromb(ਨਿਵੇਸ਼)) == ਨਿਰਾ)
		fatal_f("sshbuf_fromb failed");

	debug2("channel %d: decode socks4", c->self);
	ਜੇ ((r = sshbuf_get_u8(b, &socks_ver)) != 0 ||
	    (r = sshbuf_get_u8(b, &socks_cmd)) != 0 ||
	    (r = sshbuf_get_u16(b, &dest_ਪੋਰਟ)) != 0 ||
	    (r = sshbuf_get(b, &dest_addr, ਆਕਾਰ(dest_addr))) != 0 ||
	    (r = sshbuf_get_nulterminated_string(b, 1024, &user, ਨਿਰਾ)) != 0) {
		success = socks_decode_error(c, r, __func__, "header");
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	/* Is this a SOCKS4A request? (indicated by an address of 0.0.0.x) */
	ਜੇ (dest_addr[0] == 0 && dest_addr[1] == 0 &&
	    dest_addr[2] == 0 && dest_addr[3] != 0) {
		/* If so, then the hostname follows, also nul-terminated */
		ਜੇ ((r = sshbuf_get_nulterminated_string(b, 1024,
		    &host, ਨਿਰਾ)) != 0) {
			success = socks_decode_error(c, r, __func__, "host");
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		socks4a = 1;
	} ਨਹੀਂਤਾਂ {
		/* Plain SOCKS4 passes an IPv4 binary address; reconstruct */
		xasprintf(&host, "%d.%d.%d.%d",
		    dest_addr[0], dest_addr[1], dest_addr[2], dest_addr[3]);
	}

	/* We have a complete SOCKS4 message; consume it from input */
	ਜੇ ((r = sshbuf_consume_upto_ਬੱਚਾ(ਨਿਵੇਸ਼, b)) != 0)
		fatal_fr(r, "channel %d: consume", c->self);

	/* Handle the request */
	debug2("channel %d: %s: user=\"%s\" command=%d destination=[%s]:%d",
	    c->self, socks4a ? "SOCKS4A" : "SOCKS4", user, (ਪੂਰਨ)socks_cmd,
	    host, dest_ਪੋਰਟ);
	ਜੇ (socks_cmd != 1) {
		debug("channel %d: cannot handle %s command 0x%02x",
		    c->self, socks4a ? "SOCKS4A" : "SOCKS4", socks_cmd);
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਮੁਕਤ(c->ਰਸਤਾ);
	c->ਰਸਤਾ = host;
	host = ਨਿਰਾ; /* transferred */
	c->host_ਪੋਰਟ = dest_ਪੋਰਟ;

	/* Reply to the SOCKS4 client */
	ਜੇ ((r = sshbuf_put_u8(output, 0)) != 0 ||	/* vn: 0 for reply */
	    (r = sshbuf_put_u8(output, 90)) != 0 ||	/* cd: req granted */
	    (r = sshbuf_put_u16(output, 0)) != 0 ||	/* port: ignored */
	    (r = sshbuf_put_u32(output, ntohl(INADDR_ANY))) != 0) /* ignored */
		fatal_fr(r, "channel %d: compose reply", c->self);

	/* success */
	success = 1;
 ਬਾਹਰਲਾ:
	sshbuf_free(b);
	ਮੁਕਤ(user);
	ਮੁਕਤ(host);
	ਵਾਪਸ success;
}

/* try to decode a socks5 header */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_SOCKS5_AUTHDONE	0x1000
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_SOCKS5_NOAUTH	0x00
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_SOCKS5_IPV4		0x01
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_SOCKS5_DOMAIN	0x03
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_SOCKS5_IPV6		0x04
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_SOCKS5_CONNECT	0x01
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_SOCKS5_SUCCESS	0x00

/*
 * Handles SOCKS5 authentication. Note 'b' must be a dup of 'input'
 * Returns 0 on insufficient queued date, 1 on authentication success or
 * -1 on error.
 */
ਸਥਿਰ ਪੂਰਨ
channel_socks5_check_auth(Channel *c, ਬਣਤਰ sshbuf *b, ਬਣਤਰ sshbuf *ਨਿਵੇਸ਼,
    ਬਣਤਰ sshbuf *output)
{
	uint8_t socks_ver;
	uint8_t nmethods, ਵਿਧੀ;
	ਪੂਰਨ r;
	u_int i, ਮਿਲਿਆ;

	/* format: ver | nmethods | methods */
	ਜੇ ((r = sshbuf_get_u8(b, &socks_ver)) != 0)
		ਵਾਪਸ socks_decode_error(c, r, __func__, "version");
	ਜੇ (socks_ver != 5) /* shouldn't happen; checked by caller^2 */
		fatal_fr(r, "channel %d: internal error: not socks5", c->self);
	ਜੇ ((r = sshbuf_get_u8(b, &nmethods)) != 0)
		ਵਾਪਸ socks_decode_error(c, r, __func__, "methods");
	ਲਈ (ਮਿਲਿਆ = i = 0; i < nmethods; i++) {
		ਜੇ ((r = sshbuf_get_u8(b, &ਵਿਧੀ)) != 0)
			ਵਾਪਸ socks_decode_error(c, r, __func__, "method");
		ਜੇ (ਵਿਧੀ == SSH_SOCKS5_NOAUTH)
			ਮਿਲਿਆ = 1;
	}
	ਜੇ (!ਮਿਲਿਆ) {
		debug("channel %d: didn't request SSH_SOCKS5_NOAUTH", c->self);
		ਵਾਪਸ -1;
	}
	/* Consume completed request */
	ਜੇ ((r = sshbuf_consume_upto_ਬੱਚਾ(ਨਿਵੇਸ਼, b)) != 0)
		fatal_fr(r, "channel %d: consume", c->self);

	/* Compose reply: version, method */
	ਜੇ ((r = sshbuf_put_u8(output, 0x05)) != 0 ||
	    (r = sshbuf_put_u8(output, SSH_SOCKS5_NOAUTH)) != 0)
		fatal_fr(r, "channel %d: append reply", c->self);
	/* success */
	debug2("channel %d: socks5 auth done", c->self);
	ਵਾਪਸ 1;
}

ਸਥਿਰ ਪੂਰਨ
channel_decode_socks5(Channel *c, ਬਣਤਰ sshbuf *ਨਿਵੇਸ਼, ਬਣਤਰ sshbuf *output)
{
	uint8_t socks_ver, socks_cmd, socks_reserved, socks_atyp, addrlen;
	uint16_t dest_ਪੋਰਟ;
	ਅੱਖਰ dest_addr[255+1], ntop[INET6_ADDRSTRLEN];
	u_int af;
	ਪੂਰਨ r, success = -1;;
	ਬਣਤਰ sshbuf *b = ਨਿਰਾ;

	debug2("channel %d: decode socks5 %s", c->self,
	    (c->flags & SSH_SOCKS5_AUTHDONE) ? "request" : "auth");

	/* We may not have a complete message, so work on a dup of the buffer */
	ਜੇ ((b = sshbuf_fromb(ਨਿਵੇਸ਼)) == ਨਿਰਾ)
		fatal_f("sshbuf_fromb failed");

	ਜੇ (!(c->flags & SSH_SOCKS5_AUTHDONE)) {
		ਜੇ ((r = channel_socks5_check_auth(c, b, ਨਿਵੇਸ਼, output)) != 1) {
			success = r;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		c->flags |= SSH_SOCKS5_AUTHDONE;
		/* Continue to parse request in case client speculated ahead */
	}

	/* Request messages (auth or connect) always start with the version */
	ਜੇ ((r = sshbuf_get_u8(b, &socks_ver)) != 0) {
		success = socks_decode_error(c, r, __func__, "version");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (socks_ver != 5) /* shouldn't happen */
		fatal_fr(r, "channel %d: internal error: not socks5", c->self);

	/* Parse SOCKS5 request header */
	debug2("channel %d: socks5 post auth", c->self);
	ਜੇ ((r = sshbuf_get_u8(b, &socks_cmd)) != 0 ||
	    (r = sshbuf_get_u8(b, &socks_reserved)) != 0 ||
	    (r = sshbuf_get_u8(b, &socks_atyp)) != 0) {
		success = socks_decode_error(c, r, __func__, "request header");
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	ਜੇ (socks_ver != 0x05 ||
	    socks_cmd != SSH_SOCKS5_CONNECT ||
	    socks_reserved != 0x00) {
		debug2("channel %d: only socks5 connect supported", c->self);
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	ਚੋਣ (socks_atyp) {
	ਹਾਲਤ SSH_SOCKS5_IPV4:
		addrlen = 4;
		af = AF_INET;
		ਰੋਕੋ;
	ਹਾਲਤ SSH_SOCKS5_DOMAIN:
		ਜੇ ((r = sshbuf_get_u8(b, &addrlen)) != 0) {
			success = socks_decode_error(c, r, __func__, "addrlen");
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		af = -1;
		ਰੋਕੋ;
	ਹਾਲਤ SSH_SOCKS5_IPV6:
		addrlen = 16;
		af = AF_INET6;
		ਰੋਕੋ;
	ਮੂਲ:
		debug2("channel %d: bad socks5 atyp %d", c->self, socks_atyp);
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = sshbuf_get(b, &dest_addr, addrlen)) != 0 ||
	    (r = sshbuf_get_u16(b, &dest_ਪੋਰਟ)) != 0) {
		success = socks_decode_error(c, r, __func__, "addr/port");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	dest_addr[addrlen] = '\0';

	/* We have a complete SOCKS5 request; consume it from input */
	ਜੇ ((r = sshbuf_consume_upto_ਬੱਚਾ(ਨਿਵੇਸ਼, b)) != 0)
		fatal_fr(r, "channel %d: consume", c->self);

	ਮੁਕਤ(c->ਰਸਤਾ);
	c->ਰਸਤਾ = ਨਿਰਾ;
	ਜੇ (socks_atyp == SSH_SOCKS5_DOMAIN)
		c->ਰਸਤਾ = xstrdup(dest_addr);
	ਨਹੀਂਤਾਂ {
		ਜੇ (inet_ntop(af, dest_addr, ntop, ਆਕਾਰ(ntop)) == ਨਿਰਾ)
			ਵਾਪਸ -1;
		c->ਰਸਤਾ = xstrdup(ntop);
	}
	c->host_ਪੋਰਟ = dest_ਪੋਰਟ;

	debug2("channel %d: dynamic request: socks5 host %s port %u command %u",
	    c->self, c->ਰਸਤਾ, c->host_ਪੋਰਟ, socks_cmd);

	/*ਜਵਾਬ*/
	ਜੇ ((r = sshbuf_put_u8(output, 0x05)) != 0 ||	/*ਸੰਸਕਰਣ*/
	    (r = sshbuf_put_u8(output, SSH_SOCKS5_SUCCESS)) != 0 || /* cmd */
	    (r = sshbuf_put_u8(output, 0)) != 0 ||	/* reserved, ignored */
	    (r = sshbuf_put_u8(output, SSH_SOCKS5_IPV4)) != 0 || /* addrtype */
	    (r = sshbuf_put_u32(output, ntohl(INADDR_ANY))) != 0 || /* addr */
	    (r = sshbuf_put_u16(output, dest_ਪੋਰਟ)) != 0) /*ਪੋਰਟ*/
		fatal_fr(r, "channel %d: append reply", c->self);

	/* success */
	success = 1;
 ਬਾਹਰਲਾ:
	sshbuf_free(b);
	ਵਾਪਸ success;
}

Channel *
channel_connect_stdio_fwd(ਬਣਤਰ ssh *ssh,
    ਅਚਲ ਅੱਖਰ *host_ਮੰਜ਼ਿਲ_connect, ਪੂਰਨ ਪੋਰਟ_ਮੰਜ਼ਿਲ_connect,
    ਪੂਰਨ ਵਿੱਚ, ਪੂਰਨ ਬਾਹਰਲਾ, ਪੂਰਨ nonblock)
{
	Channel *c;

	debug_f("%s:%d", host_ਮੰਜ਼ਿਲ_connect, ਪੋਰਟ_ਮੰਜ਼ਿਲ_connect);

	c = channel_new(ssh, "stdio-forward", SSH_CHANNEL_OPENING, ਵਿੱਚ, ਬਾਹਰਲਾ,
	    -1, CHAN_TCP_ਖਿੜਕੀ_DEFAULT, CHAN_TCP_PACKET_DEFAULT,
	    0, "stdio-forward", nonblock);

	c->ਰਸਤਾ = xstrdup(host_ਮੰਜ਼ਿਲ_connect);
	c->host_ਪੋਰਟ = ਪੋਰਟ_ਮੰਜ਼ਿਲ_connect;
	c->listening_ਪੋਰਟ = 0;
	c->force_drain = 1;

	channel_ਰਜਿਸਟਰ_fds(ssh, c, ਵਿੱਚ, ਬਾਹਰਲਾ, -1, 0, 1, 0);
	ਪੋਰਟ_open_helper(ssh, c, ਪੋਰਟ_ਮੰਜ਼ਿਲ_connect == ਪੋਰਟ_STREAMLOCAL ?
	    "direct-streamlocal@openssh.com" : "direct-tcpip");

	ਵਾਪਸ c;
}

/* dynamic port forwarding */
ਸਥਿਰ ਖਾਲੀ
channel_pre_dynamic(ਬਣਤਰ ssh *ssh, Channel *c)
{
	u_int have;
	u_char ver;
	ਪੂਰਨ r, ret;

	c->io_want = 0;
	have = sshbuf_len(c->ਨਿਵੇਸ਼);
	debug2("channel %d: pre_dynamic: have %d", c->self, have);
	/* sshbuf_dump(c->input, stderr); */
	/* check if the fixed size part of the packet is in buffer. */
	ਜੇ (have < 3) {
		/* need more */
		c->io_want |= SSH_CHAN_IO_RFD;
		ਵਾਪਸ;
	}
	/* try to guess the protocol */
	ਜੇ ((r = sshbuf_peek_u8(c->ਨਿਵੇਸ਼, 0, &ver)) != 0)
		fatal_fr(r, "sshbuf_peek_u8");
	ਚੋਣ (ver) {
	ਹਾਲਤ 0x04:
		ret = channel_decode_socks4(c, c->ਨਿਵੇਸ਼, c->output);
		ਰੋਕੋ;
	ਹਾਲਤ 0x05:
		ret = channel_decode_socks5(c, c->ਨਿਵੇਸ਼, c->output);
		ਰੋਕੋ;
	ਮੂਲ:
		debug2_f("channel %d: unknown SOCKS version %u", c->self, ver);
		ret = -1;
		ਰੋਕੋ;
	}
	ਜੇ (ret < 0) {
		chan_mark_dead(ssh, c);
	} ਨਹੀਂਤਾਂ ਜੇ (ret == 0) {
		debug2("channel %d: pre_dynamic: need more", c->self);
		/* need more */
		c->io_want |= SSH_CHAN_IO_RFD;
		ਜੇ (sshbuf_len(c->output))
			c->io_want |= SSH_CHAN_IO_WFD;
	} ਨਹੀਂਤਾਂ {
		/* switch to the next state */
		c->type = SSH_CHANNEL_OPENING;
		ਪੋਰਟ_open_helper(ssh, c, "direct-tcpip");
	}
}

/* simulate read-error */
ਸਥਿਰ ਖਾਲੀ
rdynamic_close(ਬਣਤਰ ssh *ssh, Channel *c)
{
	c->type = SSH_CHANNEL_OPEN;
	channel_force_close(ssh, c, 0);
}

/* reverse dynamic port forwarding */
ਸਥਿਰ ਖਾਲੀ
channel_before_prepare_io_rdynamic(ਬਣਤਰ ssh *ssh, Channel *c)
{
	ਅਚਲ u_char *p;
	u_int have, len;
	ਪੂਰਨ r, ret;

	have = sshbuf_len(c->output);
	debug2("channel %d: pre_rdynamic: have %d", c->self, have);
	/* sshbuf_dump(c->output, stderr); */
	/* EOF received */
	ਜੇ (c->flags & CHAN_EOF_RCVD) {
		ਜੇ ((r = sshbuf_consume(c->output, have)) != 0)
			fatal_fr(r, "channel %d: consume", c->self);
		rdynamic_close(ssh, c);
		ਵਾਪਸ;
	}
	/* check if the fixed size part of the packet is in buffer. */
	ਜੇ (have < 3)
		ਵਾਪਸ;
	/* try to guess the protocol */
	p = sshbuf_ptr(c->output);
	ਚੋਣ (p[0]) {
	ਹਾਲਤ 0x04:
		/* switch input/output for reverse forwarding */
		ret = channel_decode_socks4(c, c->output, c->ਨਿਵੇਸ਼);
		ਰੋਕੋ;
	ਹਾਲਤ 0x05:
		ret = channel_decode_socks5(c, c->output, c->ਨਿਵੇਸ਼);
		ਰੋਕੋ;
	ਮੂਲ:
		ret = -1;
		ਰੋਕੋ;
	}
	ਜੇ (ret < 0) {
		rdynamic_close(ssh, c);
	} ਨਹੀਂਤਾਂ ਜੇ (ret == 0) {
		debug2("channel %d: pre_rdynamic: need more", c->self);
		/* send socks request to peer */
		len = sshbuf_len(c->ਨਿਵੇਸ਼);
		ਜੇ (len > 0 && len < c->remote_ਖਿੜਕੀ) {
			ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh, SSH2_ਸੁਨੇਹਾ_CHANNEL_ਅੰਕੜੇ)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
			    (r = sshpkt_put_stringb(ssh, c->ਨਿਵੇਸ਼)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0) {
				fatal_fr(r, "channel %i: rdynamic", c->self);
			}
			ਜੇ ((r = sshbuf_consume(c->ਨਿਵੇਸ਼, len)) != 0)
				fatal_fr(r, "channel %d: consume", c->self);
			c->remote_ਖਿੜਕੀ -= len;
		}
	} ਨਹੀਂਤਾਂ ਜੇ (rdynamic_connect_ਅੰਤ(ssh, c) < 0) {
		/* the connect failed */
		rdynamic_close(ssh, c);
	}
}

/* This is our fake X11 server socket. */
ਸਥਿਰ ਖਾਲੀ
channel_post_x11_listener(ਬਣਤਰ ssh *ssh, Channel *c)
{
	Channel *nc;
	ਬਣਤਰ sockaddr_storage addr;
	ਪੂਰਨ r, newsock, oerrno, remote_ਪੋਰਟ;
	socklen_t addrlen;
	ਅੱਖਰ buf[16384], *remote_ipaddr;

	ਜੇ ((c->io_ready & SSH_CHAN_IO_SOCK_R) == 0)
		ਵਾਪਸ;

	debug("X11 connection requested.");
	addrlen = ਆਕਾਰ(addr);
	newsock = accept(c->sock, (ਬਣਤਰ sockaddr *)&addr, &addrlen);
	ਜੇ (c->single_connection) {
		oerrno = errno;
		debug2("single_connection: closing X11 listener.");
		channel_close_fd(ssh, c, &c->sock);
		chan_mark_dead(ssh, c);
		errno = oerrno;
	}
	ਜੇ (newsock == -1) {
		ਜੇ (errno != EINTR && errno != EWOULDBLOCK &&
		    errno != ECONNABORTED)
			error("accept: %.100s", strerror(errno));
		ਜੇ (errno == EMFILE || errno == ENFILE)
			c->notbefore = monotime_double() + 1.0;
		ਵਾਪਸ;
	}
	ਸੈੱਟ_nodelay(newsock);
	ਜੇ (ssh->chanctxt->want_tcp_keepalive)
		ਸੈੱਟ_keepalive(newsock); /* logs errors */
	remote_ipaddr = get_peer_ipaddr(newsock);
	remote_ਪੋਰਟ = get_peer_ਪੋਰਟ(newsock);
	snprintf(buf, ਆਕਾਰ buf, "X11 connection from %.200s port %d",
	    remote_ipaddr, remote_ਪੋਰਟ);

	nc = channel_new(ssh, "x11-connection",
	    SSH_CHANNEL_OPENING, newsock, newsock, -1,
	    c->local_ਖਿੜਕੀ_max, c->local_maxpacket, 0, buf, 1);
	open_preamble(ssh, __func__, nc, "x11");
	ਜੇ ((r = sshpkt_put_cstring(ssh, remote_ipaddr)) != 0 ||
	    (r = sshpkt_put_u32(ssh, remote_ਪੋਰਟ)) != 0) {
		fatal_fr(r, "channel %i: reply", c->self);
	}
	ਜੇ ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i: send", c->self);
	ਮੁਕਤ(remote_ipaddr);
}

ਸਥਿਰ ਖਾਲੀ
ਪੋਰਟ_open_helper(ਬਣਤਰ ssh *ssh, Channel *c, ਅੱਖਰ *rtype)
{
	ਅੱਖਰ *local_ipaddr = get_local_ipaddr(c->sock);
	ਪੂਰਨ local_ਪੋਰਟ = c->sock == -1 ? 65536 : get_local_ਪੋਰਟ(c->sock);
	ਅੱਖਰ *remote_ipaddr = get_peer_ipaddr(c->sock);
	ਪੂਰਨ remote_ਪੋਰਟ = get_peer_ਪੋਰਟ(c->sock);
	ਪੂਰਨ r;

	ਜੇ (remote_ਪੋਰਟ == -1) {
		/* Fake addr/port to appease peers that validate it (Tectia) */
		ਮੁਕਤ(remote_ipaddr);
		remote_ipaddr = xstrdup("127.0.0.1");
		remote_ਪੋਰਟ = 65535;
	}

	ਮੁਕਤ(c->remote_name);
	xasprintf(&c->remote_name,
	    "%s: listening port %d for %.100s port %d, "
	    "connect from %.200s port %d to %.100s port %d",
	    rtype, c->listening_ਪੋਰਟ, c->ਰਸਤਾ, c->host_ਪੋਰਟ,
	    remote_ipaddr, remote_ਪੋਰਟ, local_ipaddr, local_ਪੋਰਟ);

	open_preamble(ssh, __func__, c, rtype);
	ਜੇ (strcmp(rtype, "direct-tcpip") == 0) {
		/* target host, port */
		ਜੇ ((r = sshpkt_put_cstring(ssh, c->ਰਸਤਾ)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->host_ਪੋਰਟ)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	} ਨਹੀਂਤਾਂ ਜੇ (strcmp(rtype, "direct-streamlocal@openssh.com") == 0) {
		/* target path */
		ਜੇ ((r = sshpkt_put_cstring(ssh, c->ਰਸਤਾ)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	} ਨਹੀਂਤਾਂ ਜੇ (strcmp(rtype, "forwarded-streamlocal@openssh.com") == 0) {
		/* listen path */
		ਜੇ ((r = sshpkt_put_cstring(ssh, c->ਰਸਤਾ)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	} ਨਹੀਂਤਾਂ {
		/* listen address, port */
		ਜੇ ((r = sshpkt_put_cstring(ssh, c->ਰਸਤਾ)) != 0 ||
		    (r = sshpkt_put_u32(ssh, local_ਪੋਰਟ)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	}
	ਜੇ (strcmp(rtype, "forwarded-streamlocal@openssh.com") == 0) {
		/* reserved for future owner/mode info */
		ਜੇ ((r = sshpkt_put_cstring(ssh, "")) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	} ਨਹੀਂਤਾਂ {
		/* originator host and port */
		ਜੇ ((r = sshpkt_put_cstring(ssh, remote_ipaddr)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)remote_ਪੋਰਟ)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	}
	ਜੇ ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i: send", c->self);
	ਮੁਕਤ(remote_ipaddr);
	ਮੁਕਤ(local_ipaddr);
}

ਖਾਲੀ
channel_ਸੈੱਟ_x11_refuse_ਸਮਾਂ(ਬਣਤਰ ssh *ssh, ਦੁੱਗਣਾ refuse_ਸਮਾਂ)
{
	ssh->chanctxt->x11_refuse_ਸਮਾਂ = refuse_ਸਮਾਂ;
}

/*
 * This socket is listening for connections to a forwarded TCP/IP port.
 */
ਸਥਿਰ ਖਾਲੀ
channel_post_ਪੋਰਟ_listener(ਬਣਤਰ ssh *ssh, Channel *c)
{
	Channel *nc;
	ਬਣਤਰ sockaddr_storage addr;
	ਪੂਰਨ newsock, nextstate;
	socklen_t addrlen;
	ਅੱਖਰ *rtype;

	ਜੇ ((c->io_ready & SSH_CHAN_IO_SOCK_R) == 0)
		ਵਾਪਸ;

	debug("Connection to port %d forwarding to %.100s port %d requested.",
	    c->listening_ਪੋਰਟ, c->ਰਸਤਾ, c->host_ਪੋਰਟ);

	ਜੇ (c->type == SSH_CHANNEL_RPORT_LISTENER) {
		nextstate = SSH_CHANNEL_OPENING;
		rtype = "forwarded-tcpip";
	} ਨਹੀਂਤਾਂ ਜੇ (c->type == SSH_CHANNEL_RUNIX_LISTENER) {
		nextstate = SSH_CHANNEL_OPENING;
		rtype = "forwarded-streamlocal@openssh.com";
	} ਨਹੀਂਤਾਂ ਜੇ (c->host_ਪੋਰਟ == ਪੋਰਟ_STREAMLOCAL) {
		nextstate = SSH_CHANNEL_OPENING;
		rtype = "direct-streamlocal@openssh.com";
	} ਨਹੀਂਤਾਂ ਜੇ (c->host_ਪੋਰਟ == 0) {
		nextstate = SSH_CHANNEL_DYNAMIC;
		rtype = "dynamic-tcpip";
	} ਨਹੀਂਤਾਂ {
		nextstate = SSH_CHANNEL_OPENING;
		rtype = "direct-tcpip";
	}

	addrlen = ਆਕਾਰ(addr);
	newsock = accept(c->sock, (ਬਣਤਰ sockaddr *)&addr, &addrlen);
	ਜੇ (newsock == -1) {
		ਜੇ (errno != EINTR && errno != EWOULDBLOCK &&
		    errno != ECONNABORTED)
			error("accept: %.100s", strerror(errno));
		ਜੇ (errno == EMFILE || errno == ENFILE)
			c->notbefore = monotime_double() + 1.0;
		ਵਾਪਸ;
	}
	ਜੇ (addr.ss_family == AF_INET || addr.ss_family == AF_INET6) {
		ਸੈੱਟ_nodelay(newsock);
		ਜੇ (ssh->chanctxt->want_tcp_keepalive)
			ਸੈੱਟ_keepalive(newsock); /* logs errors */
	}
	nc = channel_new(ssh, rtype, nextstate, newsock, newsock, -1,
	    c->local_ਖਿੜਕੀ_max, c->local_maxpacket, 0, rtype, 1);
	nc->listening_ਪੋਰਟ = c->listening_ਪੋਰਟ;
	nc->host_ਪੋਰਟ = c->host_ਪੋਰਟ;
	ਜੇ (c->ਰਸਤਾ != ਨਿਰਾ)
		nc->ਰਸਤਾ = xstrdup(c->ਰਸਤਾ);

	ਜੇ (nextstate != SSH_CHANNEL_DYNAMIC)
		ਪੋਰਟ_open_helper(ssh, nc, rtype);
}

/*
 * This is the authentication agent socket listening for connections from
 * clients.
 */
ਸਥਿਰ ਖਾਲੀ
channel_post_auth_listener(ਬਣਤਰ ssh *ssh, Channel *c)
{
	Channel *nc;
	ਪੂਰਨ r, newsock;
	ਬਣਤਰ sockaddr_storage addr;
	socklen_t addrlen;

	ਜੇ ((c->io_ready & SSH_CHAN_IO_SOCK_R) == 0)
		ਵਾਪਸ;

	addrlen = ਆਕਾਰ(addr);
	newsock = accept(c->sock, (ਬਣਤਰ sockaddr *)&addr, &addrlen);
	ਜੇ (newsock == -1) {
		error("accept from auth socket: %.100s", strerror(errno));
		ਜੇ (errno == EMFILE || errno == ENFILE)
			c->notbefore = monotime_double() + 1.0;
		ਵਾਪਸ;
	}
	nc = channel_new(ssh, "agent-connection",
	    SSH_CHANNEL_OPENING, newsock, newsock, -1,
	    c->local_ਖਿੜਕੀ_max, c->local_maxpacket,
	    0, "accepted auth socket", 1);
	open_preamble(ssh, __func__, nc,
	    c->agent_new ? "agent-connect" : "auth-agent@openssh.com");
	ਜੇ ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i", c->self);
}

ਸਥਿਰ ਖਾਲੀ
channel_post_connecting(ਬਣਤਰ ssh *ssh, Channel *c)
{
	ਪੂਰਨ err = 0, sock, isopen, r;
	socklen_t sz = ਆਕਾਰ(err);

	ਜੇ ((c->io_ready & SSH_CHAN_IO_SOCK_W) == 0)
		ਵਾਪਸ;
	ਜੇ (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);
	ਜੇ (c->connect_ctx == ਨਿਰਾ)
		fatal_f("channel %d: context missing", c->self);

	/* for rdynamic the OPEN_CONFIRMATION has been sent already */
	isopen = (c->type == SSH_CHANNEL_RDYNAMIC_ਅੰਤ);

	ਜੇ (getsockopt(c->sock, SOL_SOCKET, SO_ERROR, &err, &sz) == -1) {
		err = errno;
		error("getsockopt SO_ERROR failed");
	}

	ਜੇ (err == 0) {
		/* Non-blocking connection completed */
		debug("channel %d: connected to %s port %d",
		    c->self, c->connect_ctx->host, c->connect_ctx->ਪੋਰਟ);
		channel_free_connect_ctx(c);
		c->type = SSH_CHANNEL_OPEN;
		channel_ਸੈੱਟ_ਵਰਤਿਆ_ਸਮਾਂ(ssh, c);
		ਜੇ (isopen) {
			/* no message necessary */
		} ਨਹੀਂਤਾਂ {
			ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh,
			    SSH2_ਸੁਨੇਹਾ_CHANNEL_OPEN_CONFIRMATION)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_ਖਿੜਕੀ)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "channel %i open confirm", c->self);
		}
		ਵਾਪਸ;
	}
	ਜੇ (err == EINTR || err == EAGAIN || err == EINPROGRESS)
		ਵਾਪਸ;

	/* Non-blocking connection failed */
	debug("channel %d: connection failed: %s", c->self, strerror(err));

	/* Try next address, if any */
	ਜੇ ((sock = connect_ਅਗਲਾ(ssh, c->connect_ctx)) == -1) {
		/* Exhausted all addresses for this destination */
		error("connect_to %.100s port %d: failed.",
		    c->connect_ctx->host, c->connect_ctx->ਪੋਰਟ);
		channel_free_connect_ctx(c);
		ਜੇ (isopen) {
			rdynamic_close(ssh, c);
		} ਨਹੀਂਤਾਂ {
			ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh,
			    SSH2_ਸੁਨੇਹਾ_CHANNEL_OPEN_FAILURE)) != 0 ||
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

ਸਥਿਰ ਪੂਰਨ
channel_handle_rfd(ਬਣਤਰ ssh *ssh, Channel *c)
{
	ਅੱਖਰ buf[CHAN_RBUF];
	ssize_t len;
	ਪੂਰਨ r, force;
	ਮਾਪ_t nr = 0, have, avail, maxlen = CHANNEL_MAX_READ;
	ਪੂਰਨ pty_zeroread = 0;

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ PTY_ZEROREAD
	/* Bug on AIX: read(1) can return 0 for a non-closed fd */
	pty_zeroread = c->isatty;
#ਜੇ_ਅੰਤ

	force = c->isatty && c->detach_close && c->istate != CHAN_ਨਿਵੇਸ਼_CLOSED;

	ਜੇ (!force && (c->io_ready & SSH_CHAN_IO_RFD) == 0)
		ਵਾਪਸ 1;
	ਜੇ ((avail = sshbuf_avail(c->ਨਿਵੇਸ਼)) == 0)
		ਵਾਪਸ 1; /* Shouldn't happen */

	/*
	 * For "simple" channels (i.e. not datagram or filtered), we can
	 * read directly to the channel buffer.
	 */
	ਜੇ (!pty_zeroread && c->ਨਿਵੇਸ਼_filter == ਨਿਰਾ && !c->datagram) {
		/* Only OPEN channels have valid rwin */
		ਜੇ (c->type == SSH_CHANNEL_OPEN) {
			ਜੇ ((have = sshbuf_len(c->ਨਿਵੇਸ਼)) >= c->remote_ਖਿੜਕੀ)
				ਵਾਪਸ 1; /* shouldn't happen */
			ਜੇ (maxlen > c->remote_ਖਿੜਕੀ - have)
				maxlen = c->remote_ਖਿੜਕੀ - have;
		}
		ਜੇ (maxlen > avail)
			maxlen = avail;
		ਜੇ ((r = sshbuf_read(c->rfd, c->ਨਿਵੇਸ਼, maxlen, &nr)) != 0) {
			ਜੇ (errno == EINTR || (!force &&
			    (errno == EAGAIN || errno == EWOULDBLOCK)))
				ਵਾਪਸ 1;
			debug2("channel %d: read failed rfd %d maxlen %zu: %s",
			    c->self, c->rfd, maxlen, ssh_err(r));
			ਜਾਓ rfail;
		}
		ਜੇ (nr != 0)
			channel_ਸੈੱਟ_ਵਰਤਿਆ_ਸਮਾਂ(ssh, c);
		ਵਾਪਸ 1;
	}

	errno = 0;
	len = ਪਠ(c->rfd, buf, ਆਕਾਰ(buf));
	/* fixup AIX zero-length read with errno set to look more like errors */
	ਜੇ (pty_zeroread && len == 0 && errno != 0)
		len = -1;
	ਜੇ (len == -1 && (errno == EINTR ||
	    ((errno == EAGAIN || errno == EWOULDBLOCK) && !force)))
		ਵਾਪਸ 1;
	ਜੇ (len < 0 || (!pty_zeroread && len == 0)) {
		debug2("channel %d: read<=0 rfd %d len %zd: %s",
		    c->self, c->rfd, len,
		    len == 0 ? "closed" : strerror(errno));
 rfail:
		ਜੇ (c->type != SSH_CHANNEL_OPEN) {
			debug2("channel %d: not open", c->self);
			chan_mark_dead(ssh, c);
			ਵਾਪਸ -1;
		} ਨਹੀਂਤਾਂ {
			chan_read_failed(ssh, c);
		}
		ਵਾਪਸ -1;
	}
	channel_ਸੈੱਟ_ਵਰਤਿਆ_ਸਮਾਂ(ssh, c);
	ਜੇ (c->ਨਿਵੇਸ਼_filter != ਨਿਰਾ) {
		ਜੇ (c->ਨਿਵੇਸ਼_filter(ssh, c, buf, len) == -1) {
			debug2("channel %d: filter stops", c->self);
			chan_read_failed(ssh, c);
		}
	} ਨਹੀਂਤਾਂ ਜੇ (c->datagram) {
		ਜੇ ((r = sshbuf_put_string(c->ਨਿਵੇਸ਼, buf, len)) != 0)
			fatal_fr(r, "channel %i: put datagram", c->self);
	} ਨਹੀਂਤਾਂ ਜੇ ((r = sshbuf_put(c->ਨਿਵੇਸ਼, buf, len)) != 0)
		fatal_fr(r, "channel %i: put data", c->self);

	ਵਾਪਸ 1;
}

ਸਥਿਰ ਪੂਰਨ
channel_handle_wfd(ਬਣਤਰ ssh *ssh, Channel *c)
{
	ਬਣਤਰ termios tio;
	u_char *ਅੰਕੜੇ = ਨਿਰਾ, *buf; /* XXX const; need filter API change */
	ਮਾਪ_t dlen, olen = 0;
	ਪੂਰਨ r, len;

	ਜੇ ((c->io_ready & SSH_CHAN_IO_WFD) == 0)
		ਵਾਪਸ 1;
	ਜੇ (sshbuf_len(c->output) == 0)
		ਵਾਪਸ 1;

	/* Send buffered output data to the socket. */
	olen = sshbuf_len(c->output);
	ਜੇ (c->output_filter != ਨਿਰਾ) {
		ਜੇ ((buf = c->output_filter(ssh, c, &ਅੰਕੜੇ, &dlen)) == ਨਿਰਾ) {
			debug2("channel %d: filter stops", c->self);
			ਜੇ (c->type != SSH_CHANNEL_OPEN)
				chan_mark_dead(ssh, c);
			ਨਹੀਂਤਾਂ
				chan_write_failed(ssh, c);
			ਵਾਪਸ -1;
		}
	} ਨਹੀਂਤਾਂ ਜੇ (c->datagram) {
		ਜੇ ((r = sshbuf_get_string(c->output, &ਅੰਕੜੇ, &dlen)) != 0)
			fatal_fr(r, "channel %i: get datagram", c->self);
		buf = ਅੰਕੜੇ;
	} ਨਹੀਂਤਾਂ {
		buf = ਅੰਕੜੇ = sshbuf_mutable_ptr(c->output);
		dlen = sshbuf_len(c->output);
	}

	ਜੇ (c->datagram) {
		/* ignore truncated writes, datagrams might get lost */
		len = ਲਿਖ(c->wfd, buf, dlen);
		ਮੁਕਤ(ਅੰਕੜੇ);
		ਜੇ (len == -1 && (errno == EINTR || errno == EAGAIN ||
		    errno == EWOULDBLOCK))
			ਵਾਪਸ 1;
		ਜੇ (len <= 0)
			ਜਾਓ write_fail;
		ਜਾਓ ਬਾਹਰਲਾ;
	}

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ _AIX
	/* XXX: Later AIX versions can't push as much data to tty */
	ਜੇ (c->wfd_isatty)
		dlen = MINIMUM(dlen, 8*1024);
#ਜੇ_ਅੰਤ

	len = ਲਿਖ(c->wfd, buf, dlen);
	ਜੇ (len == -1 &&
	    (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
		ਵਾਪਸ 1;
	ਜੇ (len <= 0) {
 write_fail:
		ਜੇ (c->type != SSH_CHANNEL_OPEN) {
			debug2("channel %d: not open", c->self);
			chan_mark_dead(ssh, c);
			ਵਾਪਸ -1;
		} ਨਹੀਂਤਾਂ {
			chan_write_failed(ssh, c);
		}
		ਵਾਪਸ -1;
	}
	channel_ਸੈੱਟ_ਵਰਤਿਆ_ਸਮਾਂ(ssh, c);
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ BROKEN_TCGETATTR_ICANON
	ਜੇ (c->isatty && dlen >= 1 && buf[0] != '\r') {
		ਜੇ (tcgetattr(c->wfd, &tio) == 0 &&
		    !(tio.c_lflag & ECHO) && (tio.c_lflag & ICANON)) {
			/*
			 * Simulate echo to reduce the impact of
			 * traffic analysis. We need to match the
			 * size of a SSH2_MSG_CHANNEL_DATA message
			 * (4 byte channel id + buf)
			 */
			ਜੇ ((r = sshpkt_ਸੁਨੇਹਾ_ignore(ssh, 4+len)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "channel %i: ignore", c->self);
		}
	}
#ਜੇ_ਅੰਤ /* BROKEN_TCGETATTR_ICANON */
	ਜੇ ((r = sshbuf_consume(c->output, len)) != 0)
		fatal_fr(r, "channel %i: consume", c->self);
 ਬਾਹਰਲਾ:
	c->local_consumed += olen - sshbuf_len(c->output);

	ਵਾਪਸ 1;
}

ਸਥਿਰ ਪੂਰਨ
channel_handle_efd_write(ਬਣਤਰ ssh *ssh, Channel *c)
{
	ਪੂਰਨ r;
	ssize_t len;

	ਜੇ ((c->io_ready & SSH_CHAN_IO_EFD_W) == 0)
		ਵਾਪਸ 1;
	ਜੇ (sshbuf_len(c->extended) == 0)
		ਵਾਪਸ 1;

	len = ਲਿਖ(c->efd, sshbuf_ptr(c->extended),
	    sshbuf_len(c->extended));
	debug2("channel %d: written %zd to efd %d", c->self, len, c->efd);
	ਜੇ (len == -1 && (errno == EINTR || errno == EAGAIN ||
	    errno == EWOULDBLOCK))
		ਵਾਪਸ 1;
	ਜੇ (len <= 0) {
		debug2("channel %d: closing write-efd %d", c->self, c->efd);
		channel_close_fd(ssh, c, &c->efd);
	} ਨਹੀਂਤਾਂ {
		ਜੇ ((r = sshbuf_consume(c->extended, len)) != 0)
			fatal_fr(r, "channel %i: consume", c->self);
		c->local_consumed += len;
		channel_ਸੈੱਟ_ਵਰਤਿਆ_ਸਮਾਂ(ssh, c);
	}
	ਵਾਪਸ 1;
}

ਸਥਿਰ ਪੂਰਨ
channel_handle_efd_read(ਬਣਤਰ ssh *ssh, Channel *c)
{
	ਅੱਖਰ buf[CHAN_RBUF];
	ssize_t len;
	ਪੂਰਨ r, force;

	force = c->isatty && c->detach_close && c->istate != CHAN_ਨਿਵੇਸ਼_CLOSED;

	ਜੇ (!force && (c->io_ready & SSH_CHAN_IO_EFD_R) == 0)
		ਵਾਪਸ 1;

	len = ਪਠ(c->efd, buf, ਆਕਾਰ(buf));
	debug2("channel %d: read %zd from efd %d", c->self, len, c->efd);
	ਜੇ (len == -1 && (errno == EINTR || ((errno == EAGAIN ||
	    errno == EWOULDBLOCK) && !force)))
		ਵਾਪਸ 1;
	ਜੇ (len <= 0) {
		debug2("channel %d: closing read-efd %d", c->self, c->efd);
		channel_close_fd(ssh, c, &c->efd);
		ਵਾਪਸ 1;
	}
	channel_ਸੈੱਟ_ਵਰਤਿਆ_ਸਮਾਂ(ssh, c);
	ਜੇ (c->extended_usage == CHAN_EXTENDED_IGNORE)
		debug3("channel %d: discard efd", c->self);
	ਨਹੀਂਤਾਂ ਜੇ ((r = sshbuf_put(c->extended, buf, len)) != 0)
		fatal_fr(r, "channel %i: append", c->self);
	ਵਾਪਸ 1;
}

ਸਥਿਰ ਪੂਰਨ
channel_handle_efd(ਬਣਤਰ ssh *ssh, Channel *c)
{
	ਜੇ (c->efd == -1)
		ਵਾਪਸ 1;

	/** XXX handle drain efd, too */

	ਜੇ (c->extended_usage == CHAN_EXTENDED_WRITE)
		ਵਾਪਸ channel_handle_efd_write(ssh, c);
	ਨਹੀਂਤਾਂ ਜੇ (c->extended_usage == CHAN_EXTENDED_READ ||
	    c->extended_usage == CHAN_EXTENDED_IGNORE)
		ਵਾਪਸ channel_handle_efd_read(ssh, c);

	ਵਾਪਸ 1;
}

ਸਥਿਰ ਪੂਰਨ
channel_check_ਖਿੜਕੀ(ਬਣਤਰ ssh *ssh, Channel *c)
{
	ਪੂਰਨ r;

	ਜੇ (c->type == SSH_CHANNEL_OPEN &&
	    !(c->flags & (CHAN_CLOSE_ਭੇਜਿਆ|CHAN_CLOSE_RCVD)) &&
	    ((c->local_ਖਿੜਕੀ_max - c->local_ਖਿੜਕੀ >
	    c->local_maxpacket*3) ||
	    c->local_ਖਿੜਕੀ < c->local_ਖਿੜਕੀ_max/2) &&
	    c->local_consumed > 0) {
		ਜੇ (!c->have_remote_id)
			fatal_f("channel %d: no remote id", c->self);
		ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh,
		    SSH2_ਸੁਨੇਹਾ_CHANNEL_ਖਿੜਕੀ_ADJUST)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->local_consumed)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0) {
			fatal_fr(r, "channel %i", c->self);
		}
		debug2("channel %d: window %d sent adjust %d", c->self,
		    c->local_ਖਿੜਕੀ, c->local_consumed);
		c->local_ਖਿੜਕੀ += c->local_consumed;
		c->local_consumed = 0;
	}
	ਵਾਪਸ 1;
}

ਸਥਿਰ ਖਾਲੀ
channel_post_open(ਬਣਤਰ ssh *ssh, Channel *c)
{
	channel_handle_rfd(ssh, c);
	channel_handle_wfd(ssh, c);
	channel_handle_efd(ssh, c);
	channel_check_ਖਿੜਕੀ(ssh, c);
}

ਸਥਿਰ u_int
read_mux(ਬਣਤਰ ssh *ssh, Channel *c, u_int need)
{
	ਅੱਖਰ buf[CHAN_RBUF];
	ssize_t len;
	u_int rlen;
	ਪੂਰਨ r;

	ਜੇ (sshbuf_len(c->ਨਿਵੇਸ਼) < need) {
		rlen = need - sshbuf_len(c->ਨਿਵੇਸ਼);
		len = ਪਠ(c->rfd, buf, MINIMUM(rlen, CHAN_RBUF));
		ਜੇ (len == -1 && (errno == EINTR || errno == EAGAIN))
			ਵਾਪਸ sshbuf_len(c->ਨਿਵੇਸ਼);
		ਜੇ (len <= 0) {
			debug2("channel %d: ctl read<=0 rfd %d len %zd",
			    c->self, c->rfd, len);
			chan_read_failed(ssh, c);
			ਵਾਪਸ 0;
		} ਨਹੀਂਤਾਂ ਜੇ ((r = sshbuf_put(c->ਨਿਵੇਸ਼, buf, len)) != 0)
			fatal_fr(r, "channel %i: append", c->self);
	}
	ਵਾਪਸ sshbuf_len(c->ਨਿਵੇਸ਼);
}

ਸਥਿਰ ਖਾਲੀ
channel_post_mux_client_read(ਬਣਤਰ ssh *ssh, Channel *c)
{
	u_int need;

	ਜੇ ((c->io_ready & SSH_CHAN_IO_RFD) == 0)
		ਵਾਪਸ;
	ਜੇ (c->istate != CHAN_ਨਿਵੇਸ਼_OPEN && c->istate != CHAN_ਨਿਵੇਸ਼_WAIT_DRAIN)
		ਵਾਪਸ;
	ਜੇ (c->mux_pause)
		ਵਾਪਸ;

	/*
	 * Don't not read past the precise end of packets to
	 * avoid disrupting fd passing.
	 */
	ਜੇ (read_mux(ssh, c, 4) < 4) /* read header */
		ਵਾਪਸ;
	/* XXX sshbuf_peek_u32 */
	need = PEEK_U32(sshbuf_ptr(c->ਨਿਵੇਸ਼));
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CHANNEL_MUX_MAX_PACKET	(256 * 1024)
	ਜੇ (need > CHANNEL_MUX_MAX_PACKET) {
		debug2("channel %d: packet too big %u > %u",
		    c->self, CHANNEL_MUX_MAX_PACKET, need);
		chan_rcvd_oclose(ssh, c);
		ਵਾਪਸ;
	}
	ਜੇ (read_mux(ssh, c, need + 4) < need + 4) /* read body */
		ਵਾਪਸ;
	ਜੇ (c->mux_rcb(ssh, c) != 0) {
		debug("channel %d: mux_rcb failed", c->self);
		chan_mark_dead(ssh, c);
		ਵਾਪਸ;
	}
}

ਸਥਿਰ ਖਾਲੀ
channel_post_mux_client_write(ਬਣਤਰ ssh *ssh, Channel *c)
{
	ssize_t len;
	ਪੂਰਨ r;

	ਜੇ ((c->io_ready & SSH_CHAN_IO_WFD) == 0)
		ਵਾਪਸ;
	ਜੇ (sshbuf_len(c->output) == 0)
		ਵਾਪਸ;

	len = ਲਿਖ(c->wfd, sshbuf_ptr(c->output), sshbuf_len(c->output));
	ਜੇ (len == -1 && (errno == EINTR || errno == EAGAIN))
		ਵਾਪਸ;
	ਜੇ (len <= 0) {
		chan_mark_dead(ssh, c);
		ਵਾਪਸ;
	}
	ਜੇ ((r = sshbuf_consume(c->output, len)) != 0)
		fatal_fr(r, "channel %i: consume", c->self);
}

ਸਥਿਰ ਖਾਲੀ
channel_post_mux_client(ਬਣਤਰ ssh *ssh, Channel *c)
{
	channel_post_mux_client_read(ssh, c);
	channel_post_mux_client_write(ssh, c);
}

ਸਥਿਰ ਖਾਲੀ
channel_post_mux_listener(ਬਣਤਰ ssh *ssh, Channel *c)
{
	Channel *nc;
	ਬਣਤਰ sockaddr_storage addr;
	socklen_t addrlen;
	ਪੂਰਨ newsock;
	uid_t euid;
	gid_t egid;

	ਜੇ ((c->io_ready & SSH_CHAN_IO_SOCK_R) == 0)
		ਵਾਪਸ;

	debug("multiplexing control connection");

	/*
	 * Accept connection on control socket
	 */
	memset(&addr, 0, ਆਕਾਰ(addr));
	addrlen = ਆਕਾਰ(addr);
	ਜੇ ((newsock = accept(c->sock, (ਬਣਤਰ sockaddr*)&addr,
	    &addrlen)) == -1) {
		error_f("accept: %s", strerror(errno));
		ਜੇ (errno == EMFILE || errno == ENFILE)
			c->notbefore = monotime_double() + 1.0;
		ਵਾਪਸ;
	}

	ਜੇ (getpeereid(newsock, &euid, &egid) == -1) {
		error_f("getpeereid failed: %s", strerror(errno));
		close(newsock);
		ਵਾਪਸ;
	}
	ਜੇ ((euid != 0) && (getuid() != euid)) {
		error("multiplex uid mismatch: peer euid %u != uid %u",
		    (u_int)euid, (u_int)getuid());
		close(newsock);
		ਵਾਪਸ;
	}
	nc = channel_new(ssh, "mux-control", SSH_CHANNEL_MUX_CLIENT,
	    newsock, newsock, -1, c->local_ਖਿੜਕੀ_max,
	    c->local_maxpacket, 0, "mux-control", 1);
	nc->mux_rcb = c->mux_rcb;
	debug3_f("new mux channel %d fd %d", nc->self, nc->sock);
	/* establish state */
	nc->mux_rcb(ssh, nc);
	/* mux state transitions must not elicit protocol messages */
	nc->flags |= CHAN_LOCAL;
}

ਸਥਿਰ ਖਾਲੀ
channel_handler_init(ਬਣਤਰ ssh_channels *sc)
{
	chan_fn **pre, **post;

	ਜੇ ((pre = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(SSH_CHANNEL_MAX_TYPE, ਆਕਾਰ(*pre))) == ਨਿਰਾ ||
	    (post = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(SSH_CHANNEL_MAX_TYPE, ਆਕਾਰ(*post))) == ਨਿਰਾ)
		fatal_f("allocation failed");

	pre[SSH_CHANNEL_OPEN] =			&channel_pre_open;
	pre[SSH_CHANNEL_X11_OPEN] =		&channel_pre_x11_open;
	pre[SSH_CHANNEL_ਪੋਰਟ_LISTENER] =	&channel_pre_listener;
	pre[SSH_CHANNEL_RPORT_LISTENER] =	&channel_pre_listener;
	pre[SSH_CHANNEL_UNIX_LISTENER] =	&channel_pre_listener;
	pre[SSH_CHANNEL_RUNIX_LISTENER] =	&channel_pre_listener;
	pre[SSH_CHANNEL_X11_LISTENER] =		&channel_pre_listener;
	pre[SSH_CHANNEL_AUTH_SOCKET] =		&channel_pre_listener;
	pre[SSH_CHANNEL_CONNECTING] =		&channel_pre_connecting;
	pre[SSH_CHANNEL_DYNAMIC] =		&channel_pre_dynamic;
	pre[SSH_CHANNEL_RDYNAMIC_ਅੰਤ] =	&channel_pre_connecting;
	pre[SSH_CHANNEL_MUX_LISTENER] =		&channel_pre_listener;
	pre[SSH_CHANNEL_MUX_CLIENT] =		&channel_pre_mux_client;

	post[SSH_CHANNEL_OPEN] =		&channel_post_open;
	post[SSH_CHANNEL_ਪੋਰਟ_LISTENER] =	&channel_post_ਪੋਰਟ_listener;
	post[SSH_CHANNEL_RPORT_LISTENER] =	&channel_post_ਪੋਰਟ_listener;
	post[SSH_CHANNEL_UNIX_LISTENER] =	&channel_post_ਪੋਰਟ_listener;
	post[SSH_CHANNEL_RUNIX_LISTENER] =	&channel_post_ਪੋਰਟ_listener;
	post[SSH_CHANNEL_X11_LISTENER] =	&channel_post_x11_listener;
	post[SSH_CHANNEL_AUTH_SOCKET] =		&channel_post_auth_listener;
	post[SSH_CHANNEL_CONNECTING] =		&channel_post_connecting;
	post[SSH_CHANNEL_DYNAMIC] =		&channel_post_open;
	post[SSH_CHANNEL_RDYNAMIC_ਅੰਤ] =	&channel_post_connecting;
	post[SSH_CHANNEL_MUX_LISTENER] =	&channel_post_mux_listener;
	post[SSH_CHANNEL_MUX_CLIENT] =		&channel_post_mux_client;

	sc->channel_pre = pre;
	sc->channel_post = post;
}

/* gc dead channels */
ਸਥਿਰ ਖਾਲੀ
channel_garbage_collect(ਬਣਤਰ ssh *ssh, Channel *c)
{
	ਜੇ (c == ਨਿਰਾ)
		ਵਾਪਸ;
	ਜੇ (c->detach_user != ਨਿਰਾ) {
		ਜੇ (!chan_is_dead(ssh, c, c->detach_close))
			ਵਾਪਸ;

		debug2("channel %d: gc: notify user", c->self);
		c->detach_user(ssh, c->self, 0, ਨਿਰਾ);
		/* if we still have a callback */
		ਜੇ (c->detach_user != ਨਿਰਾ)
			ਵਾਪਸ;
		debug2("channel %d: gc: user detached", c->self);
	}
	ਜੇ (!chan_is_dead(ssh, c, 1))
		ਵਾਪਸ;
	debug2("channel %d: garbage collecting", c->self);
	channel_free(ssh, c);
}

ਗਿਣਤੀ channel_ਸਾਰਣੀ { CHAN_PRE, CHAN_POST };

ਸਥਿਰ ਖਾਲੀ
channel_handler(ਬਣਤਰ ssh *ssh, ਪੂਰਨ ਸਾਰਣੀ, ਬਣਤਰ timespec *timeout)
{
	ਬਣਤਰ ssh_channels *sc = ssh->chanctxt;
	chan_fn **ftab = ਸਾਰਣੀ == CHAN_PRE ? sc->channel_pre : sc->channel_post;
	u_int i, oalloc;
	Channel *c;
	ਦੁੱਗਣਾ now;

	now = monotime_double();
	ਲਈ (sc->nbulk = i = 0, oalloc = sc->channels_alloc; i < oalloc; i++) {
		c = sc->channels[i];
		ਜੇ (c == ਨਿਰਾ)
			ਜਾਰੀ;
		/* Count open channels in bulk state */
		ਜੇ (c->type == SSH_CHANNEL_OPEN && c->bulk)
			sc->nbulk++;
		/* Try to keep IO going while rekeying */
		ਜੇ (ssh_packet_is_rekeying(ssh) && c->type != SSH_CHANNEL_OPEN)
			ਜਾਰੀ;
		ਜੇ (c->delayed) {
			ਜੇ (ਸਾਰਣੀ == CHAN_PRE)
				c->delayed = 0;
			ਨਹੀਂਤਾਂ
				ਜਾਰੀ;
		}
		ਜੇ (ftab[c->type] != ਨਿਰਾ) {
			ਜੇ (ਸਾਰਣੀ == CHAN_PRE && c->type == SSH_CHANNEL_OPEN &&
			    channel_get_expiry(ssh, c) != 0 &&
			    now >= channel_get_expiry(ssh, c)) {
				/* channel closed for inactivity */
				ਦੁੱਗਣਾ deadline = c->inactive_deadline != 0.0 ?
				    c->inactive_deadline : sc->global_deadline;
				verbose("channel %d: closing after %f seconds "
				    "of inactivity", c->self, deadline);
				channel_force_close(ssh, c, 1);
			} ਨਹੀਂਤਾਂ ਜੇ (c->notbefore <= now) {
				/* Run handlers that are not paused. */
				(*ftab[c->type])(ssh, c);
				/* inactivity timeouts must interrupt poll() */
				ਜੇ (timeout != ਨਿਰਾ &&
				    c->type == SSH_CHANNEL_OPEN &&
				    channel_get_expiry(ssh, c) != 0) {
					ptimeout_deadline_monotime_double(timeout,
					    channel_get_expiry(ssh, c));
				}
			} ਨਹੀਂਤਾਂ ਜੇ (timeout != ਨਿਰਾ) {
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
ਸਥਿਰ ਖਾਲੀ
channel_before_prepare_io(ਬਣਤਰ ssh *ssh)
{
	ਬਣਤਰ ssh_channels *sc = ssh->chanctxt;
	Channel *c;
	u_int i, oalloc;

	ਲਈ (i = 0, oalloc = sc->channels_alloc; i < oalloc; i++) {
		c = sc->channels[i];
		ਜੇ (c == ਨਿਰਾ)
			ਜਾਰੀ;
		ਜੇ (c->type == SSH_CHANNEL_RDYNAMIC_OPEN)
			channel_before_prepare_io_rdynamic(ssh, c);
	}
}

ਸਥਿਰ ਖਾਲੀ
dump_channel_poll(ਅਚਲ ਅੱਖਰ *func, ਅਚਲ ਅੱਖਰ *what, Channel *c,
    u_int pollfd_ਵਿੱਥ, ਬਣਤਰ pollfd *pfd)
{
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_CHANNEL_POLL
	debug3("%s: channel %d: %s r%d w%d e%d s%d c->pfds [ %d %d %d %d ] "
	    "io_want 0x%02x io_ready 0x%02x pfd[%u].fd=%d "
	    "pfd.ev 0x%02x pfd.rev 0x%02x", func, c->self, what,
	    c->rfd, c->wfd, c->efd, c->sock,
	    c->pfds[0], c->pfds[1], c->pfds[2], c->pfds[3],
	    c->io_want, c->io_ready,
	    pollfd_ਵਿੱਥ, pfd->fd, pfd->events, pfd->revents);
#ਜੇ_ਅੰਤ
}

/* Prepare pollfd entries for a single channel */
ਸਥਿਰ ਖਾਲੀ
channel_prepare_pollfd(Channel *c, u_int *ਅਗਲਾ_pollfd,
    ਬਣਤਰ pollfd *pfd, u_int npfd)
{
	u_int ev, p = *ਅਗਲਾ_pollfd;

	ਜੇ (c == ਨਿਰਾ)
		ਵਾਪਸ;
	ਜੇ (p + 4 > npfd) {
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
	ਜੇ (c->rfd != -1) {
		ev = 0;
		ਜੇ ((c->io_want & SSH_CHAN_IO_RFD) != 0)
			ev |= POLLIN;
		/* rfd == wfd */
		ਜੇ (c->wfd == c->rfd) {
			ਜੇ ((c->io_want & SSH_CHAN_IO_WFD) != 0)
				ev |= POLLOUT;
		}
		/* rfd == efd */
		ਜੇ (c->efd == c->rfd) {
			ਜੇ ((c->io_want & SSH_CHAN_IO_EFD_R) != 0)
				ev |= POLLIN;
			ਜੇ ((c->io_want & SSH_CHAN_IO_EFD_W) != 0)
				ev |= POLLOUT;
		}
		/* rfd == sock */
		ਜੇ (c->sock == c->rfd) {
			ਜੇ ((c->io_want & SSH_CHAN_IO_SOCK_R) != 0)
				ev |= POLLIN;
			ਜੇ ((c->io_want & SSH_CHAN_IO_SOCK_W) != 0)
				ev |= POLLOUT;
		}
		/* Pack a pfd entry if any event armed for this fd */
		ਜੇ (ev != 0) {
			c->pfds[0] = p;
			pfd[p].fd = c->rfd;
			pfd[p].events = ev;
			dump_channel_poll(__func__, "rfd", c, p, &pfd[p]);
			p++;
		}
	}
	/* prepare c->wfd if wanting IO and not already handled above */
	ਜੇ (c->wfd != -1 && c->rfd != c->wfd) {
		ev = 0;
		ਜੇ ((c->io_want & SSH_CHAN_IO_WFD))
			ev |= POLLOUT;
		/* Pack a pfd entry if any event armed for this fd */
		ਜੇ (ev != 0) {
			c->pfds[1] = p;
			pfd[p].fd = c->wfd;
			pfd[p].events = ev;
			dump_channel_poll(__func__, "wfd", c, p, &pfd[p]);
			p++;
		}
	}
	/* prepare c->efd if wanting IO and not already handled above */
	ਜੇ (c->efd != -1 && c->rfd != c->efd) {
		ev = 0;
		ਜੇ ((c->io_want & SSH_CHAN_IO_EFD_R) != 0)
			ev |= POLLIN;
		ਜੇ ((c->io_want & SSH_CHAN_IO_EFD_W) != 0)
			ev |= POLLOUT;
		/* Pack a pfd entry if any event armed for this fd */
		ਜੇ (ev != 0) {
			c->pfds[2] = p;
			pfd[p].fd = c->efd;
			pfd[p].events = ev;
			dump_channel_poll(__func__, "efd", c, p, &pfd[p]);
			p++;
		}
	}
	/* prepare c->sock if wanting IO and not already handled above */
	ਜੇ (c->sock != -1 && c->rfd != c->sock) {
		ev = 0;
		ਜੇ ((c->io_want & SSH_CHAN_IO_SOCK_R) != 0)
			ev |= POLLIN;
		ਜੇ ((c->io_want & SSH_CHAN_IO_SOCK_W) != 0)
			ev |= POLLOUT;
		/* Pack a pfd entry if any event armed for this fd */
		ਜੇ (ev != 0) {
			c->pfds[3] = p;
			pfd[p].fd = c->sock;
			pfd[p].events = ev;
			dump_channel_poll(__func__, "sock", c, p, &pfd[p]);
			p++;
		}
	}
	*ਅਗਲਾ_pollfd = p;
}

/* * Allocate/prepare poll structure */
ਖਾਲੀ
channel_prepare_poll(ਬਣਤਰ ssh *ssh, ਬਣਤਰ pollfd **pfdp, u_int *npfd_allocp,
    u_int *npfd_activep, u_int npfd_reserved, ਬਣਤਰ timespec *timeout)
{
	ਬਣਤਰ ssh_channels *sc = ssh->chanctxt;
	u_int i, oalloc, p, npfd = npfd_reserved;

	channel_before_prepare_io(ssh); /* might create a new channel */
	/* clear out I/O flags from last poll */
	ਲਈ (i = 0; i < sc->channels_alloc; i++) {
		ਜੇ (sc->channels[i] == ਨਿਰਾ)
			ਜਾਰੀ;
		sc->channels[i]->io_want = sc->channels[i]->io_ready = 0;
	}
	/* Allocate 4x pollfd for each channel (rfd, wfd, efd, sock) */
	ਜੇ (sc->channels_alloc >= (ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ / 4) - npfd_reserved)
		fatal_f("too many channels"); /* shouldn't happen */
	npfd += sc->channels_alloc * 4;
	ਜੇ (npfd > *npfd_allocp) {
		*pfdp = xrecallocarray(*pfdp, *npfd_allocp,
		    npfd, ਆਕਾਰ(**pfdp));
		*npfd_allocp = npfd;
	}
	*npfd_activep = npfd_reserved;
	oalloc = sc->channels_alloc;

	channel_handler(ssh, CHAN_PRE, timeout);

	ਜੇ (oalloc != sc->channels_alloc) {
		/* shouldn't happen */
		fatal_f("channels_alloc changed during CHAN_PRE "
		    "(was %u, now %u)", oalloc, sc->channels_alloc);
	}

	/* Prepare pollfd */
	p = npfd_reserved;
	ਲਈ (i = 0; i < sc->channels_alloc; i++)
		channel_prepare_pollfd(sc->channels[i], &p, *pfdp, npfd);
	*npfd_activep = p;
}

ਸਥਿਰ ਖਾਲੀ
fd_ready(Channel *c, ਪੂਰਨ p, ਬਣਤਰ pollfd *pfds, u_int npfd, ਪੂਰਨ fd,
    ਅਚਲ ਅੱਖਰ *what, u_int revents_ਨਕਾਬ, u_int ready)
{
	ਬਣਤਰ pollfd *pfd = &pfds[p];

	ਜੇ (fd == -1)
		ਵਾਪਸ;
	ਜੇ (p == -1 || (u_int)p >= npfd)
		fatal_f("channel %d: bad pfd %d (max %u)", c->self, p, npfd);
	dump_channel_poll(__func__, what, c, p, pfd);
	ਜੇ (pfd->fd != fd) {
		fatal("channel %d: inconsistent %s fd=%d pollfd[%u].fd %d "
		    "r%d w%d e%d s%d", c->self, what, fd, p, pfd->fd,
		    c->rfd, c->wfd, c->efd, c->sock);
	}
	ਜੇ ((pfd->revents & POLLNVAL) != 0) {
		fatal("channel %d: invalid %s pollfd[%u].fd %d r%d w%d e%d s%d",
		    c->self, what, p, pfd->fd, c->rfd, c->wfd, c->efd, c->sock);
	}
	ਜੇ ((pfd->revents & (revents_ਨਕਾਬ|POLLHUP|POLLERR)) != 0)
		c->io_ready |= ready & c->io_want;
}

/*
 * After poll, perform any appropriate operations for channels which have
 * events pending.
 */
ਖਾਲੀ
channel_after_poll(ਬਣਤਰ ssh *ssh, ਬਣਤਰ pollfd *pfd, u_int npfd)
{
	ਬਣਤਰ ssh_channels *sc = ssh->chanctxt;
	u_int i;
	ਪੂਰਨ p;
	Channel *c;

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_CHANNEL_POLL
	ਲਈ (p = 0; p < (ਪੂਰਨ)npfd; p++) {
		ਜੇ (pfd[p].revents == 0)
			ਜਾਰੀ;
		debug_f("pfd[%u].fd %d rev 0x%04x",
		    p, pfd[p].fd, pfd[p].revents);
	}
#ਜੇ_ਅੰਤ

	/* Convert pollfd into c->io_ready */
	ਲਈ (i = 0; i < sc->channels_alloc; i++) {
		c = sc->channels[i];
		ਜੇ (c == ਨਿਰਾ)
			ਜਾਰੀ;
		/* if rfd is shared with efd/sock then wfd should be too */
		ਜੇ (c->rfd != -1 && c->wfd != -1 && c->rfd != c->wfd &&
		    (c->rfd == c->efd || c->rfd == c->sock)) {
			/* Shouldn't happen */
			fatal_f("channel %d: unexpected fds r%d w%d e%d s%d",
			    c->self, c->rfd, c->wfd, c->efd, c->sock);
		}
		c->io_ready = 0;
		/* rfd, potentially shared with wfd, efd and sock */
		ਜੇ (c->rfd != -1 && (p = c->pfds[0]) != -1) {
			fd_ready(c, p, pfd, npfd, c->rfd,
			    "rfd", POLLIN, SSH_CHAN_IO_RFD);
			ਜੇ (c->rfd == c->wfd) {
				fd_ready(c, p, pfd, npfd, c->wfd,
				    "wfd/r", POLLOUT, SSH_CHAN_IO_WFD);
			}
			ਜੇ (c->rfd == c->efd) {
				fd_ready(c, p, pfd, npfd, c->efd,
				    "efdr/r", POLLIN, SSH_CHAN_IO_EFD_R);
				fd_ready(c, p, pfd, npfd, c->efd,
				    "efdw/r", POLLOUT, SSH_CHAN_IO_EFD_W);
			}
			ਜੇ (c->rfd == c->sock) {
				fd_ready(c, p, pfd, npfd, c->sock,
				    "sockr/r", POLLIN, SSH_CHAN_IO_SOCK_R);
				fd_ready(c, p, pfd, npfd, c->sock,
				    "sockw/r", POLLOUT, SSH_CHAN_IO_SOCK_W);
			}
			dump_channel_poll(__func__, "rfd", c, p, pfd);
		}
		/* wfd */
		ਜੇ (c->wfd != -1 && c->wfd != c->rfd &&
		    (p = c->pfds[1]) != -1) {
			fd_ready(c, p, pfd, npfd, c->wfd,
			    "wfd", POLLOUT, SSH_CHAN_IO_WFD);
			dump_channel_poll(__func__, "wfd", c, p, pfd);
		}
		/* efd */
		ਜੇ (c->efd != -1 && c->efd != c->rfd &&
		    (p = c->pfds[2]) != -1) {
			fd_ready(c, p, pfd, npfd, c->efd,
			    "efdr", POLLIN, SSH_CHAN_IO_EFD_R);
			fd_ready(c, p, pfd, npfd, c->efd,
			    "efdw", POLLOUT, SSH_CHAN_IO_EFD_W);
			dump_channel_poll(__func__, "efd", c, p, pfd);
		}
		/* sock */
		ਜੇ (c->sock != -1 && c->sock != c->rfd &&
		    (p = c->pfds[3]) != -1) {
			fd_ready(c, p, pfd, npfd, c->sock,
			    "sockr", POLLIN, SSH_CHAN_IO_SOCK_R);
			fd_ready(c, p, pfd, npfd, c->sock,
			    "sockw", POLLOUT, SSH_CHAN_IO_SOCK_W);
			dump_channel_poll(__func__, "sock", c, p, pfd);
		}
	}
	channel_handler(ssh, CHAN_POST, ਨਿਰਾ);
}

/*
 * Enqueue data for channels with open or draining c->input.
 * Returns non-zero if a packet was enqueued.
 */
ਸਥਿਰ ਪੂਰਨ
channel_output_poll_ਨਿਵੇਸ਼_open(ਬਣਤਰ ssh *ssh, Channel *c)
{
	ਮਾਪ_t len, plen;
	ਅਚਲ u_char *pkt;
	ਪੂਰਨ r;

	ਜੇ ((len = sshbuf_len(c->ਨਿਵੇਸ਼)) == 0) {
		ਜੇ (c->istate == CHAN_ਨਿਵੇਸ਼_WAIT_DRAIN) {
			/*
			 * input-buffer is empty and read-socket shutdown:
			 * tell peer, that we will not send more data:
			 * send IEOF.
			 * hack for extended data: delay EOF if EFD still
			 * in use.
			 */
			ਜੇ (CHANNEL_EFD_ਨਿਵੇਸ਼_ਸਰਗਰਮ(c))
				debug2("channel %d: "
				    "ibuf_empty delayed efd %d/(%zu)",
				    c->self, c->efd, sshbuf_len(c->extended));
			ਨਹੀਂਤਾਂ
				chan_ibuf_ਖਾਲੀ_ਥਾਵਾਂ(ssh, c);
		}
		ਵਾਪਸ 0;
	}

	ਜੇ (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);

	ਜੇ (c->datagram) {
		/* Check datagram will fit; drop if not */
		ਜੇ ((r = sshbuf_get_string_ਸਿੱਧਾ(c->ਨਿਵੇਸ਼, &pkt, &plen)) != 0)
			fatal_fr(r, "channel %i: get datagram", c->self);
		/*
		 * XXX this does tail-drop on the datagram queue which is
		 * usually suboptimal compared to head-drop. Better to have
		 * backpressure at read time? (i.e. read + discard)
		 */
		ਜੇ (plen > c->remote_ਖਿੜਕੀ || plen > c->remote_maxpacket) {
			debug("channel %d: datagram too big", c->self);
			ਵਾਪਸ 0;
		}
		/* Enqueue it */
		ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh, SSH2_ਸੁਨੇਹਾ_CHANNEL_ਅੰਕੜੇ)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
		    (r = sshpkt_put_string(ssh, pkt, plen)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "channel %i: send datagram", c->self);
		c->remote_ਖਿੜਕੀ -= plen;
		ਵਾਪਸ 1;
	}

	/* Enqueue packet for buffered data. */
	ਜੇ (len > c->remote_ਖਿੜਕੀ)
		len = c->remote_ਖਿੜਕੀ;
	ਜੇ (len > c->remote_maxpacket)
		len = c->remote_maxpacket;
	ਜੇ (len == 0)
		ਵਾਪਸ 0;
	ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh, SSH2_ਸੁਨੇਹਾ_CHANNEL_ਅੰਕੜੇ)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_string(ssh, sshbuf_ptr(c->ਨਿਵੇਸ਼), len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i: send data", c->self);
	ਜੇ ((r = sshbuf_consume(c->ਨਿਵੇਸ਼, len)) != 0)
		fatal_fr(r, "channel %i: consume", c->self);
	c->remote_ਖਿੜਕੀ -= len;
	ਵਾਪਸ 1;
}

/*
 * Enqueue data for channels with open c->extended in read mode.
 * Returns non-zero if a packet was enqueued.
 */
ਸਥਿਰ ਪੂਰਨ
channel_output_poll_extended_read(ਬਣਤਰ ssh *ssh, Channel *c)
{
	ਮਾਪ_t len;
	ਪੂਰਨ r;

	ਜੇ ((len = sshbuf_len(c->extended)) == 0)
		ਵਾਪਸ 0;

	debug2("channel %d: rwin %u elen %zu euse %d", c->self,
	    c->remote_ਖਿੜਕੀ, sshbuf_len(c->extended), c->extended_usage);
	ਜੇ (len > c->remote_ਖਿੜਕੀ)
		len = c->remote_ਖਿੜਕੀ;
	ਜੇ (len > c->remote_maxpacket)
		len = c->remote_maxpacket;
	ਜੇ (len == 0)
		ਵਾਪਸ 0;
	ਜੇ (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);
	ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh, SSH2_ਸੁਨੇਹਾ_CHANNEL_EXTENDED_ਅੰਕੜੇ)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_u32(ssh, SSH2_EXTENDED_ਅੰਕੜੇ_STDERR)) != 0 ||
	    (r = sshpkt_put_string(ssh, sshbuf_ptr(c->extended), len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i: data", c->self);
	ਜੇ ((r = sshbuf_consume(c->extended, len)) != 0)
		fatal_fr(r, "channel %i: consume", c->self);
	c->remote_ਖਿੜਕੀ -= len;
	debug2("channel %d: sent ext data %zu", c->self, len);
	ਵਾਪਸ 1;
}

/*
 * If there is data to send to the connection, enqueue some of it now.
 * Returns non-zero if data was enqueued.
 */
ਪੂਰਨ
channel_output_poll(ਬਣਤਰ ssh *ssh)
{
	ਬਣਤਰ ssh_channels *sc = ssh->chanctxt;
	Channel *c;
	u_int i;
	ਪੂਰਨ ret = 0;

	ਲਈ (i = 0; i < sc->channels_alloc; i++) {
		c = sc->channels[i];
		ਜੇ (c == ਨਿਰਾ)
			ਜਾਰੀ;

		/*
		 * We are only interested in channels that can have buffered
		 * incoming data.
		 */
		ਜੇ (c->type != SSH_CHANNEL_OPEN)
			ਜਾਰੀ;
		ਜੇ ((c->flags & (CHAN_CLOSE_ਭੇਜਿਆ|CHAN_CLOSE_RCVD))) {
			/* XXX is this true? */
			debug3("channel %d: will not send data after close",
			    c->self);
			ਜਾਰੀ;
		}

		/* Get the amount of buffered data for this channel. */
		ਜੇ (c->istate == CHAN_ਨਿਵੇਸ਼_OPEN ||
		    c->istate == CHAN_ਨਿਵੇਸ਼_WAIT_DRAIN)
			ret |= channel_output_poll_ਨਿਵੇਸ਼_open(ssh, c);
		/* Send extended data, i.e. stderr */
		ਜੇ (!(c->flags & CHAN_EOF_ਭੇਜਿਆ) &&
		    c->extended_usage == CHAN_EXTENDED_READ)
			ret |= channel_output_poll_extended_read(ssh, c);
	}
	ਵਾਪਸ ret;
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
ਪੂਰਨ
channel_proxy_downstream(ਬਣਤਰ ssh *ssh, Channel *downstream)
{
	Channel *c = ਨਿਰਾ;
	ਬਣਤਰ sshbuf *original = ਨਿਰਾ, *modified = ਨਿਰਾ;
	ਅਚਲ u_char *cp;
	ਅੱਖਰ *ctype = ਨਿਰਾ, *listen_host = ਨਿਰਾ;
	u_char type;
	ਮਾਪ_t have;
	ਪੂਰਨ ret = -1, r;
	u_int id, remote_id, listen_ਪੋਰਟ;

	/* sshbuf_dump(downstream->input, stderr); */
	ਜੇ ((r = sshbuf_get_string_ਸਿੱਧਾ(downstream->ਨਿਵੇਸ਼, &cp, &have))
	    != 0) {
		error_fr(r, "parse");
		ਵਾਪਸ -1;
	}
	ਜੇ (have < 2) {
		error_f("short message");
		ਵਾਪਸ -1;
	}
	type = cp[1];
	/* skip padlen + type */
	cp += 2;
	have -= 2;
	ਜੇ (ssh_packet_log_type(type))
		debug3_f("channel %u: down->up: type %u",
		    downstream->self, type);

	ਚੋਣ (type) {
	ਹਾਲਤ SSH2_ਸੁਨੇਹਾ_CHANNEL_OPEN:
		ਜੇ ((original = sshbuf_from(cp, have)) == ਨਿਰਾ ||
		    (modified = sshbuf_new()) == ਨਿਰਾ) {
			error_f("alloc");
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ ((r = sshbuf_get_cstring(original, &ctype, ਨਿਰਾ)) != 0 ||
		    (r = sshbuf_get_u32(original, &id)) != 0) {
			error_fr(r, "parse");
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		c = channel_new(ssh, "mux-proxy", SSH_CHANNEL_MUX_PROXY,
		    -1, -1, -1, 0, 0, 0, ctype, 1);
		c->mux_ctx = downstream;	/* point to mux client */
		c->mux_downstream_id = id;	/* original downstream id */
		ਜੇ ((r = sshbuf_put_cstring(modified, ctype)) != 0 ||
		    (r = sshbuf_put_u32(modified, c->self)) != 0 ||
		    (r = sshbuf_putb(modified, original)) != 0) {
			error_fr(r, "compose");
			channel_free(ssh, c);
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਰੋਕੋ;
	ਹਾਲਤ SSH2_ਸੁਨੇਹਾ_CHANNEL_OPEN_CONFIRMATION:
		/*
		 * Almost the same as SSH2_MSG_CHANNEL_OPEN, except then we
		 * need to parse 'remote_id' instead of 'ctype'.
		 */
		ਜੇ ((original = sshbuf_from(cp, have)) == ਨਿਰਾ ||
		    (modified = sshbuf_new()) == ਨਿਰਾ) {
			error_f("alloc");
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ ((r = sshbuf_get_u32(original, &remote_id)) != 0 ||
		    (r = sshbuf_get_u32(original, &id)) != 0) {
			error_fr(r, "parse");
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		c = channel_new(ssh, "mux-proxy", SSH_CHANNEL_MUX_PROXY,
		    -1, -1, -1, 0, 0, 0, "mux-down-connect", 1);
		c->mux_ctx = downstream;	/* point to mux client */
		c->mux_downstream_id = id;
		c->remote_id = remote_id;
		c->have_remote_id = 1;
		ਜੇ ((r = sshbuf_put_u32(modified, remote_id)) != 0 ||
		    (r = sshbuf_put_u32(modified, c->self)) != 0 ||
		    (r = sshbuf_putb(modified, original)) != 0) {
			error_fr(r, "compose");
			channel_free(ssh, c);
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਰੋਕੋ;
	ਹਾਲਤ SSH2_ਸੁਨੇਹਾ_GLOBAL_REQUEST:
		ਜੇ ((original = sshbuf_from(cp, have)) == ਨਿਰਾ) {
			error_f("alloc");
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ ((r = sshbuf_get_cstring(original, &ctype, ਨਿਰਾ)) != 0) {
			error_fr(r, "parse");
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ (strcmp(ctype, "tcpip-forward") != 0) {
			error_f("unsupported request %s", ctype);
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ ((r = sshbuf_get_u8(original, ਨਿਰਾ)) != 0 ||
		    (r = sshbuf_get_cstring(original, &listen_host, ਨਿਰਾ)) != 0 ||
		    (r = sshbuf_get_u32(original, &listen_ਪੋਰਟ)) != 0) {
			error_fr(r, "parse");
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ (listen_ਪੋਰਟ > 65535) {
			error_f("tcpip-forward for %s: bad port %u",
			    listen_host, listen_ਪੋਰਟ);
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		/* Record that connection to this host/port is permitted. */
		permission_ਸੈੱਟ_ਜੋੜੋ(ssh, FORWARD_USER, FORWARD_LOCAL, "<mux>",
		    -1, listen_host, ਨਿਰਾ, (ਪੂਰਨ)listen_ਪੋਰਟ, downstream);
		ਰੋਕੋ;
	ਹਾਲਤ SSH2_ਸੁਨੇਹਾ_CHANNEL_CLOSE:
		ਜੇ (have < 4)
			ਰੋਕੋ;
		remote_id = PEEK_U32(cp);
		ਜੇ ((c = channel_by_remote_id(ssh, remote_id)) != ਨਿਰਾ) {
			ਜੇ (c->flags & CHAN_CLOSE_RCVD)
				channel_free(ssh, c);
			ਨਹੀਂਤਾਂ
				c->flags |= CHAN_CLOSE_ਭੇਜਿਆ;
		}
		ਰੋਕੋ;
	}
	ਜੇ (modified) {
		ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh, type)) != 0 ||
		    (r = sshpkt_putb(ssh, modified)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0) {
			error_fr(r, "send");
			ਜਾਓ ਬਾਹਰਲਾ;
		}
	} ਨਹੀਂਤਾਂ {
		ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh, type)) != 0 ||
		    (r = sshpkt_put(ssh, cp, have)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0) {
			error_fr(r, "send");
			ਜਾਓ ਬਾਹਰਲਾ;
		}
	}
	ret = 0;
 ਬਾਹਰਲਾ:
	ਮੁਕਤ(ctype);
	ਮੁਕਤ(listen_host);
	sshbuf_free(original);
	sshbuf_free(modified);
	ਵਾਪਸ ret;
}

/*
 * receive packets from upstream server and de-multiplex packets
 * to correct downstream:
 * implemented as a helper for channel input handlers,
 * replaces local (proxy) channel ID with downstream channel ID.
 */
ਪੂਰਨ
channel_proxy_upstream(Channel *c, ਪੂਰਨ type, uint32_t seq, ਬਣਤਰ ssh *ssh)
{
	ਬਣਤਰ sshbuf *b = ਨਿਰਾ;
	Channel *downstream;
	ਅਚਲ u_char *cp = ਨਿਰਾ;
	ਮਾਪ_t len;
	ਪੂਰਨ r;

	/*
	 * When receiving packets from the peer we need to check whether we
	 * need to forward the packets to the mux client. In this case we
	 * restore the original channel id and keep track of CLOSE messages,
	 * so we can cleanup the channel.
	 */
	ਜੇ (c == ਨਿਰਾ || c->type != SSH_CHANNEL_MUX_PROXY)
		ਵਾਪਸ 0;
	ਜੇ ((downstream = c->mux_ctx) == ਨਿਰਾ)
		ਵਾਪਸ 0;
	ਚੋਣ (type) {
	ਹਾਲਤ SSH2_ਸੁਨੇਹਾ_CHANNEL_CLOSE:
	ਹਾਲਤ SSH2_ਸੁਨੇਹਾ_CHANNEL_ਅੰਕੜੇ:
	ਹਾਲਤ SSH2_ਸੁਨੇਹਾ_CHANNEL_EOF:
	ਹਾਲਤ SSH2_ਸੁਨੇਹਾ_CHANNEL_EXTENDED_ਅੰਕੜੇ:
	ਹਾਲਤ SSH2_ਸੁਨੇਹਾ_CHANNEL_OPEN_CONFIRMATION:
	ਹਾਲਤ SSH2_ਸੁਨੇਹਾ_CHANNEL_OPEN_FAILURE:
	ਹਾਲਤ SSH2_ਸੁਨੇਹਾ_CHANNEL_ਖਿੜਕੀ_ADJUST:
	ਹਾਲਤ SSH2_ਸੁਨੇਹਾ_CHANNEL_SUCCESS:
	ਹਾਲਤ SSH2_ਸੁਨੇਹਾ_CHANNEL_FAILURE:
	ਹਾਲਤ SSH2_ਸੁਨੇਹਾ_CHANNEL_REQUEST:
		ਰੋਕੋ;
	ਮੂਲ:
		debug2_f("channel %u: unsupported type %u", c->self, type);
		ਵਾਪਸ 0;
	}
	ਜੇ ((b = sshbuf_new()) == ਨਿਰਾ) {
		error_f("alloc reply");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/* get remaining payload (after id) */
	cp = sshpkt_ptr(ssh, &len);
	ਜੇ (cp == ਨਿਰਾ) {
		error_f("no packet");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/* translate id and send to muxclient */
	ਜੇ ((r = sshbuf_put_u8(b, 0)) != 0 ||	/* padlen */
	    (r = sshbuf_put_u8(b, type)) != 0 ||
	    (r = sshbuf_put_u32(b, c->mux_downstream_id)) != 0 ||
	    (r = sshbuf_put(b, cp, len)) != 0 ||
	    (r = sshbuf_put_stringb(downstream->output, b)) != 0) {
		error_fr(r, "compose muxclient");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/* sshbuf_dump(b, stderr); */
	ਜੇ (ssh_packet_log_type(type))
		debug3_f("channel %u: up->down: type %u", c->self, type);
 ਬਾਹਰਲਾ:
	/* update state */
	ਚੋਣ (type) {
	ਹਾਲਤ SSH2_ਸੁਨੇਹਾ_CHANNEL_OPEN_CONFIRMATION:
		/* record remote_id for SSH2_MSG_CHANNEL_CLOSE */
		ਜੇ (cp && len > 4) {
			c->remote_id = PEEK_U32(cp);
			c->have_remote_id = 1;
		}
		ਰੋਕੋ;
	ਹਾਲਤ SSH2_ਸੁਨੇਹਾ_CHANNEL_CLOSE:
		ਜੇ (c->flags & CHAN_CLOSE_ਭੇਜਿਆ)
			channel_free(ssh, c);
		ਨਹੀਂਤਾਂ
			c->flags |= CHAN_CLOSE_RCVD;
		ਰੋਕੋ;
	}
	sshbuf_free(b);
	ਵਾਪਸ 1;
}

/* -- protocol input */

/* Parse a channel ID from the current packet */
ਸਥਿਰ ਪੂਰਨ
channel_parse_id(ਬਣਤਰ ssh *ssh, ਅਚਲ ਅੱਖਰ *where, ਅਚਲ ਅੱਖਰ *what)
{
	uint32_t id;
	ਪੂਰਨ r;

	ਜੇ ((r = sshpkt_get_u32(ssh, &id)) != 0) {
		error_r(r, "%s: parse id", where);
		ssh_packet_disconnect(ssh, "Invalid %s message", what);
	}
	ਜੇ (id > ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ) {
		error_r(r, "%s: bad channel id %u", where, id);
		ssh_packet_disconnect(ssh, "Invalid %s channel id", what);
	}
	ਵਾਪਸ (ਪੂਰਨ)id;
}

/* Lookup a channel from an ID in the current packet */
ਸਥਿਰ Channel *
channel_from_packet_id(ਬਣਤਰ ssh *ssh, ਅਚਲ ਅੱਖਰ *where, ਅਚਲ ਅੱਖਰ *what)
{
	ਪੂਰਨ id = channel_parse_id(ssh, where, what);
	Channel *c;

	ਜੇ ((c = channel_lookup(ssh, id)) == ਨਿਰਾ) {
		ssh_packet_disconnect(ssh,
		    "%s packet referred to nonexistent channel %d", what, id);
	}
	ਵਾਪਸ c;
}

ਪੂਰਨ
channel_ਨਿਵੇਸ਼_ਅੰਕੜੇ(ਪੂਰਨ type, uint32_t seq, ਬਣਤਰ ssh *ssh)
{
	ਅਚਲ u_char *ਅੰਕੜੇ;
	ਮਾਪ_t ਅੰਕੜੇ_len, win_len;
	Channel *c = channel_from_packet_id(ssh, __func__, "data");
	ਪੂਰਨ r;

	ਜੇ (channel_proxy_upstream(c, type, seq, ssh))
		ਵਾਪਸ 0;

	/* Ignore any data for non-open channels (might happen on close) */
	ਜੇ (c->type != SSH_CHANNEL_OPEN &&
	    c->type != SSH_CHANNEL_RDYNAMIC_OPEN &&
	    c->type != SSH_CHANNEL_RDYNAMIC_ਅੰਤ &&
	    c->type != SSH_CHANNEL_X11_OPEN)
		ਵਾਪਸ 0;

	/* Get the data. */
	ਜੇ ((r = sshpkt_get_string_ਸਿੱਧਾ(ssh, &ਅੰਕੜੇ, &ਅੰਕੜੇ_len)) != 0 ||
            (r = sshpkt_get_ਸਿਰਾ(ssh)) != 0)
		fatal_fr(r, "channel %i: get data", c->self);

	win_len = ਅੰਕੜੇ_len;
	ਜੇ (c->datagram)
		win_len += 4;  /* string length header */

	/*
	 * The sending side reduces its window as it sends data, so we
	 * must 'fake' consumption of the data in order to ensure that window
	 * updates are sent back. Otherwise the connection might deadlock.
	 */
	ਜੇ (c->ostate != CHAN_OUTPUT_OPEN) {
		ਜੇ (win_len > c->local_ਖਿੜਕੀ)
			c->local_ਖਿੜਕੀ = 0;
		ਨਹੀਂਤਾਂ
			c->local_ਖਿੜਕੀ -= win_len;
		c->local_consumed += win_len;
		ਵਾਪਸ 0;
	}

	ਜੇ (win_len > c->local_maxpacket) {
		logit("channel %d: rcvd big packet %zu, maxpack %u",
		    c->self, win_len, c->local_maxpacket);
		ਵਾਪਸ 0;
	}
	ਜੇ (win_len > c->local_ਖਿੜਕੀ) {
		u_int delta = win_len - c->local_ਖਿੜਕੀ;

		ਜੇ (c->local_ਖਿੜਕੀ_exceeded > UINT_MAX - delta)
			c->local_ਖਿੜਕੀ_exceeded = UINT_MAX;
		ਨਹੀਂਤਾਂ
			c->local_ਖਿੜਕੀ_exceeded += delta;
		logit("channel %d: rcvd too much data %zu, win %u/%u "
		    "(excess %u)", c->self, win_len, c->local_ਖਿੜਕੀ,
		    c->local_ਖਿੜਕੀ_max, c->local_ਖਿੜਕੀ_exceeded);
		c->local_ਖਿੜਕੀ = 0;
		/* Allow 10% grace before bringing the hammer down */
		ਜੇ (c->local_ਖਿੜਕੀ_exceeded > (c->local_ਖਿੜਕੀ_max / 10)) {
			ssh_packet_disconnect(ssh, "channel %d: peer ignored "
			    "channel window", c->self);
		}
	} ਨਹੀਂਤਾਂ {
		c->local_ਖਿੜਕੀ -= win_len;
		c->local_ਖਿੜਕੀ_exceeded = 0;
	}

	ਜੇ (c->datagram) {
		ਜੇ ((r = sshbuf_put_string(c->output, ਅੰਕੜੇ, ਅੰਕੜੇ_len)) != 0)
			fatal_fr(r, "channel %i: append datagram", c->self);
	} ਨਹੀਂਤਾਂ ਜੇ ((r = sshbuf_put(c->output, ਅੰਕੜੇ, ਅੰਕੜੇ_len)) != 0)
		fatal_fr(r, "channel %i: append data", c->self);

	ਵਾਪਸ 0;
}

ਪੂਰਨ
channel_ਨਿਵੇਸ਼_extended_ਅੰਕੜੇ(ਪੂਰਨ type, uint32_t seq, ਬਣਤਰ ssh *ssh)
{
	ਅਚਲ u_char *ਅੰਕੜੇ;
	ਮਾਪ_t ਅੰਕੜੇ_len;
	uint32_t tcode;
	Channel *c = channel_from_packet_id(ssh, __func__, "extended data");
	ਪੂਰਨ r;

	ਜੇ (channel_proxy_upstream(c, type, seq, ssh))
		ਵਾਪਸ 0;
	ਜੇ (c->type != SSH_CHANNEL_OPEN) {
		logit("channel %d: ext data for non open", c->self);
		ਵਾਪਸ 0;
	}
	ਜੇ (c->flags & CHAN_EOF_RCVD) {
		ਜੇ (ssh->compat & SSH_BUG_EXTEOF)
			debug("channel %d: accepting ext data after eof",
			    c->self);
		ਨਹੀਂਤਾਂ
			ssh_packet_disconnect(ssh, "Received extended_data "
			    "after EOF on channel %d.", c->self);
	}

	ਜੇ ((r = sshpkt_get_u32(ssh, &tcode)) != 0) {
		error_fr(r, "parse tcode");
		ssh_packet_disconnect(ssh, "Invalid extended_data message");
	}
	ਜੇ (c->efd == -1 ||
	    c->extended_usage != CHAN_EXTENDED_WRITE ||
	    tcode != SSH2_EXTENDED_ਅੰਕੜੇ_STDERR) {
		logit("channel %d: bad ext data", c->self);
		ਵਾਪਸ 0;
	}
	ਜੇ ((r = sshpkt_get_string_ਸਿੱਧਾ(ssh, &ਅੰਕੜੇ, &ਅੰਕੜੇ_len)) != 0 ||
            (r = sshpkt_get_ਸਿਰਾ(ssh)) != 0) {
		error_fr(r, "parse data");
		ssh_packet_disconnect(ssh, "Invalid extended_data message");
	}

	ਜੇ (ਅੰਕੜੇ_len > c->local_ਖਿੜਕੀ) {
		logit("channel %d: rcvd too much extended_data %zu, win %u",
		    c->self, ਅੰਕੜੇ_len, c->local_ਖਿੜਕੀ);
		ਵਾਪਸ 0;
	}
	debug2("channel %d: rcvd ext data %zu", c->self, ਅੰਕੜੇ_len);
	/* XXX sshpkt_getb? */
	ਜੇ ((r = sshbuf_put(c->extended, ਅੰਕੜੇ, ਅੰਕੜੇ_len)) != 0)
		error_fr(r, "append");
	c->local_ਖਿੜਕੀ -= ਅੰਕੜੇ_len;
	ਵਾਪਸ 0;
}

ਪੂਰਨ
channel_ਨਿਵੇਸ਼_ieof(ਪੂਰਨ type, uint32_t seq, ਬਣਤਰ ssh *ssh)
{
	Channel *c = channel_from_packet_id(ssh, __func__, "ieof");
	ਪੂਰਨ r;

        ਜੇ ((r = sshpkt_get_ਸਿਰਾ(ssh)) != 0) {
		error_fr(r, "parse data");
		ssh_packet_disconnect(ssh, "Invalid ieof message");
	}

	ਜੇ (channel_proxy_upstream(c, type, seq, ssh))
		ਵਾਪਸ 0;
	chan_rcvd_ieof(ssh, c);

	/* XXX force input close */
	ਜੇ (c->force_drain && c->istate == CHAN_ਨਿਵੇਸ਼_OPEN) {
		debug("channel %d: FORCE input drain", c->self);
		c->istate = CHAN_ਨਿਵੇਸ਼_WAIT_DRAIN;
		ਜੇ (sshbuf_len(c->ਨਿਵੇਸ਼) == 0)
			chan_ibuf_ਖਾਲੀ_ਥਾਵਾਂ(ssh, c);
	}
	ਵਾਪਸ 0;
}

ਪੂਰਨ
channel_ਨਿਵੇਸ਼_oclose(ਪੂਰਨ type, uint32_t seq, ਬਣਤਰ ssh *ssh)
{
	Channel *c = channel_from_packet_id(ssh, __func__, "oclose");
	ਪੂਰਨ r;

	ਜੇ (channel_proxy_upstream(c, type, seq, ssh))
		ਵਾਪਸ 0;
        ਜੇ ((r = sshpkt_get_ਸਿਰਾ(ssh)) != 0) {
		error_fr(r, "parse data");
		ssh_packet_disconnect(ssh, "Invalid oclose message");
	}
	chan_rcvd_oclose(ssh, c);
	ਵਾਪਸ 0;
}

ਪੂਰਨ
channel_ਨਿਵੇਸ਼_open_confirmation(ਪੂਰਨ type, uint32_t seq, ਬਣਤਰ ssh *ssh)
{
	Channel *c = channel_from_packet_id(ssh, __func__, "open confirmation");
	uint32_t remote_ਖਿੜਕੀ, remote_maxpacket;
	ਪੂਰਨ r;

	ਜੇ (channel_proxy_upstream(c, type, seq, ssh))
		ਵਾਪਸ 0;
	ਜੇ (c->type != SSH_CHANNEL_OPENING)
		ssh_packet_disconnect(ssh, "Received open confirmation for "
		    "non-opening channel %d.", c->self);
	/*
	 * Record the remote channel number and mark that the channel
	 * is now open.
	 */
	ਜੇ ((r = sshpkt_get_u32(ssh, &c->remote_id)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &remote_ਖਿੜਕੀ)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &remote_maxpacket)) != 0 ||
            (r = sshpkt_get_ਸਿਰਾ(ssh)) != 0) {
		error_fr(r, "window/maxpacket");
		ssh_packet_disconnect(ssh, "Invalid open confirmation message");
	}

	c->have_remote_id = 1;
	c->remote_ਖਿੜਕੀ = remote_ਖਿੜਕੀ;
	c->remote_maxpacket = remote_maxpacket;
	c->type = SSH_CHANNEL_OPEN;
	ਜੇ (c->open_confirm) {
		debug2_f("channel %d: callback start", c->self);
		c->open_confirm(ssh, c->self, 1, c->open_confirm_ctx);
		debug2_f("channel %d: callback done", c->self);
	}
	channel_ਸੈੱਟ_ਵਰਤਿਆ_ਸਮਾਂ(ssh, c);
	debug2("channel %d: open confirm rwindow %u rmax %u", c->self,
	    c->remote_ਖਿੜਕੀ, c->remote_maxpacket);
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਅੱਖਰ *
reason2txt(ਪੂਰਨ reason)
{
	ਚੋਣ (reason) {
	ਹਾਲਤ SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED:
		ਵਾਪਸ "administratively prohibited";
	ਹਾਲਤ SSH2_OPEN_CONNECT_FAILED:
		ਵਾਪਸ "connect failed";
	ਹਾਲਤ SSH2_OPEN_UNKNOWN_CHANNEL_TYPE:
		ਵਾਪਸ "unknown channel type";
	ਹਾਲਤ SSH2_OPEN_RESOURCE_SHORTAGE:
		ਵਾਪਸ "resource shortage";
	}
	ਵਾਪਸ "unknown reason";
}

ਪੂਰਨ
channel_ਨਿਵੇਸ਼_open_failure(ਪੂਰਨ type, uint32_t seq, ਬਣਤਰ ssh *ssh)
{
	Channel *c = channel_from_packet_id(ssh, __func__, "open failure");
	uint32_t reason;
	ਅੱਖਰ *ਸੁਨੇਹਾ = ਨਿਰਾ;
	ਪੂਰਨ r;

	ਜੇ (channel_proxy_upstream(c, type, seq, ssh))
		ਵਾਪਸ 0;
	ਜੇ (c->type != SSH_CHANNEL_OPENING)
		ssh_packet_disconnect(ssh, "Received open failure for "
		    "non-opening channel %d.", c->self);
	ਜੇ ((r = sshpkt_get_u32(ssh, &reason)) != 0) {
		error_fr(r, "parse reason");
		ssh_packet_disconnect(ssh, "Invalid open failure message");
	}
	/* skip language */
	ਜੇ ((r = sshpkt_get_cstring(ssh, &ਸੁਨੇਹਾ, ਨਿਰਾ)) != 0 ||
	    (r = sshpkt_get_string_ਸਿੱਧਾ(ssh, ਨਿਰਾ, ਨਿਰਾ)) != 0 ||
            (r = sshpkt_get_ਸਿਰਾ(ssh)) != 0) {
		error_fr(r, "parse msg/lang");
		ssh_packet_disconnect(ssh, "Invalid open failure message");
	}
	logit("channel %d: open failed: %s%s%s", c->self,
	    reason2txt(reason), ਸੁਨੇਹਾ ? ": ": "", ਸੁਨੇਹਾ ? ਸੁਨੇਹਾ : "");
	ਮੁਕਤ(ਸੁਨੇਹਾ);
	ਜੇ (c->open_confirm) {
		debug2_f("channel %d: callback start", c->self);
		c->open_confirm(ssh, c->self, 0, c->open_confirm_ctx);
		debug2_f("channel %d: callback done", c->self);
	}
	/* Schedule the channel for cleanup/deletion. */
	chan_mark_dead(ssh, c);
	ਵਾਪਸ 0;
}

ਪੂਰਨ
channel_ਨਿਵੇਸ਼_ਖਿੜਕੀ_adjust(ਪੂਰਨ type, uint32_t seq, ਬਣਤਰ ssh *ssh)
{
	ਪੂਰਨ id = channel_parse_id(ssh, __func__, "window adjust");
	Channel *c;
	uint32_t adjust;
	u_int new_rwin;
	ਪੂਰਨ r;

	ਜੇ ((c = channel_lookup(ssh, id)) == ਨਿਰਾ) {
		logit("Received window adjust for non-open channel %d.", id);
		ਵਾਪਸ 0;
	}

	ਜੇ (channel_proxy_upstream(c, type, seq, ssh))
		ਵਾਪਸ 0;
	ਜੇ ((r = sshpkt_get_u32(ssh, &adjust)) != 0 ||
            (r = sshpkt_get_ਸਿਰਾ(ssh)) != 0) {
		error_fr(r, "parse adjust");
		ssh_packet_disconnect(ssh, "Invalid window adjust message");
	}
	debug2("channel %d: rcvd adjust %u", c->self, adjust);
	ਜੇ ((new_rwin = c->remote_ਖਿੜਕੀ + adjust) < c->remote_ਖਿੜਕੀ) {
		fatal("channel %d: adjust %u overflows remote window %u",
		    c->self, adjust, c->remote_ਖਿੜਕੀ);
	}
	c->remote_ਖਿੜਕੀ = new_rwin;
	ਵਾਪਸ 0;
}

ਪੂਰਨ
channel_ਨਿਵੇਸ਼_ਸਥਿਤੀ_confirm(ਪੂਰਨ type, uint32_t seq, ਬਣਤਰ ssh *ssh)
{
	ਪੂਰਨ id = channel_parse_id(ssh, __func__, "status confirm");
	Channel *c;
	ਬਣਤਰ channel_confirm *cc;

	/* Reset keepalive timeout */
	ssh_packet_ਸੈੱਟ_alive_timeouts(ssh, 0);

	debug2_f("type %d id %d", type, id);

	ਜੇ ((c = channel_lookup(ssh, id)) == ਨਿਰਾ) {
		logit_f("%d: unknown", id);
		ਵਾਪਸ 0;
	}
	ਜੇ (channel_proxy_upstream(c, type, seq, ssh))
		ਵਾਪਸ 0;
        ਜੇ (sshpkt_get_ਸਿਰਾ(ssh) != 0)
		ssh_packet_disconnect(ssh, "Invalid status confirm message");
	ਜੇ ((cc = TAILQ_FIRST(&c->ਸਥਿਤੀ_confirms)) == ਨਿਰਾ)
		ਵਾਪਸ 0;
	cc->cb(ssh, type, c, cc->ctx);
	TAILQ_REMOVE(&c->ਸਥਿਤੀ_confirms, cc, ਇੰਦਰਾਜ);
	freezero(cc, ਆਕਾਰ(*cc));
	ਵਾਪਸ 0;
}

/* -- tcp forwarding */

ਖਾਲੀ
channel_ਸੈੱਟ_af(ਬਣਤਰ ssh *ssh, ਪੂਰਨ af)
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
ਸਥਿਰ ਅਚਲ ਅੱਖਰ *
channel_fwd_bind_addr(ਬਣਤਰ ssh *ssh, ਅਚਲ ਅੱਖਰ *listen_addr, ਪੂਰਨ *wildcardp,
    ਪੂਰਨ is_client, ਬਣਤਰ ForwardOptions *fwd_opts)
{
	ਅਚਲ ਅੱਖਰ *addr = ਨਿਰਾ;
	ਪੂਰਨ wildcard = 0;

	ਜੇ (listen_addr == ਨਿਰਾ) {
		/* No address specified: default to gateway_ports setting */
		ਜੇ (fwd_opts->gateway_ports)
			wildcard = 1;
	} ਨਹੀਂਤਾਂ ਜੇ (fwd_opts->gateway_ports || is_client) {
		ਜੇ (((ssh->compat & SSH_OLD_FORWARD_ADDR) &&
		    strcmp(listen_addr, "0.0.0.0") == 0 && is_client == 0) ||
		    *listen_addr == '\0' || strcmp(listen_addr, "*") == 0 ||
		    (!is_client && fwd_opts->gateway_ports == 1)) {
			wildcard = 1;
			/*
			 * Notify client if they requested a specific listen
			 * address and it was overridden.
			 */
			ਜੇ (*listen_addr != '\0' &&
			    strcmp(listen_addr, "0.0.0.0") != 0 &&
			    strcmp(listen_addr, "*") != 0) {
				ssh_packet_send_debug(ssh,
				    "Forwarding listen address "
				    "\"%s\" overridden by server "
				    "GatewayPorts", listen_addr);
			}
		} ਨਹੀਂਤਾਂ ਜੇ (strcmp(listen_addr, "localhost") != 0 ||
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
	} ਨਹੀਂਤਾਂ ਜੇ (strcmp(listen_addr, "127.0.0.1") == 0 ||
	    strcmp(listen_addr, "::1") == 0) {
		/*
		 * If a specific IPv4/IPv6 localhost address has been
		 * requested then accept it even if gateway_ports is in
		 * effect. This allows the client to prefer IPv4 or IPv6.
		 */
		addr = listen_addr;
	}
	ਜੇ (wildcardp != ਨਿਰਾ)
		*wildcardp = wildcard;
	ਵਾਪਸ addr;
}

ਸਥਿਰ ਪੂਰਨ
channel_ਤਿਆਰੀ_fwd_listener_tcpip(ਬਣਤਰ ssh *ssh, ਪੂਰਨ type,
    ਬਣਤਰ Forward *fwd, ਪੂਰਨ *allocated_listen_ਪੋਰਟ,
    ਬਣਤਰ ForwardOptions *fwd_opts)
{
	Channel *c;
	ਪੂਰਨ sock, r, success = 0, wildcard = 0, is_client;
	ਬਣਤਰ addrinfo hints, *ai, *aitop;
	ਅਚਲ ਅੱਖਰ *host, *addr;
	ਅੱਖਰ ntop[NI_MAXHOST], strport[NI_MAXSERV];
	in_port_t *lport_p;

	is_client = (type == SSH_CHANNEL_ਪੋਰਟ_LISTENER);

	ਜੇ (is_client && fwd->connect_ਰਸਤਾ != ਨਿਰਾ) {
		host = fwd->connect_ਰਸਤਾ;
	} ਨਹੀਂਤਾਂ {
		host = (type == SSH_CHANNEL_RPORT_LISTENER) ?
		    fwd->listen_host : fwd->connect_host;
		ਜੇ (host == ਨਿਰਾ) {
			error("No forward host name.");
			ਵਾਪਸ 0;
		}
		ਜੇ (ਲੜੀ_ਲੰਬਾਈ(host) >= NI_MAXHOST) {
			error("Forward host name too long.");
			ਵਾਪਸ 0;
		}
	}

	/* Determine the bind address, cf. channel_fwd_bind_addr() comment */
	addr = channel_fwd_bind_addr(ssh, fwd->listen_host, &wildcard,
	    is_client, fwd_opts);
	debug3_f("type %d wildcard %d addr %s", type, wildcard,
	    (addr == ਨਿਰਾ) ? "NULL" : addr);

	/*
	 * getaddrinfo returns a loopback address if the hostname is
	 * set to NULL and hints.ai_flags is not AI_PASSIVE
	 */
	memset(&hints, 0, ਆਕਾਰ(hints));
	hints.ai_family = ssh->chanctxt->IPv4or6;
	hints.ai_flags = wildcard ? AI_PASSIVE : 0;
	hints.ai_socktype = SOCK_STREAM;
	snprintf(strport, ਆਕਾਰ strport, "%d", fwd->listen_ਪੋਰਟ);
	ਜੇ ((r = getaddrinfo(addr, strport, &hints, &aitop)) != 0) {
		ਜੇ (addr == ਨਿਰਾ) {
			/* This really shouldn't happen */
			ssh_packet_disconnect(ssh, "getaddrinfo: fatal error: %s",
			    ssh_gai_strerror(r));
		} ਨਹੀਂਤਾਂ {
			error_f("getaddrinfo(%.64s): %s", addr,
			    ssh_gai_strerror(r));
		}
		ਵਾਪਸ 0;
	}
	ਜੇ (allocated_listen_ਪੋਰਟ != ਨਿਰਾ)
		*allocated_listen_ਪੋਰਟ = 0;
	ਲਈ (ai = aitop; ai; ai = ai->ai_next) {
		ਚੋਣ (ai->ai_family) {
		ਹਾਲਤ AF_INET:
			lport_p = &((ਬਣਤਰ sockaddr_in *)ai->ai_addr)->
			    sin_port;
			ਰੋਕੋ;
		ਹਾਲਤ AF_INET6:
			lport_p = &((ਬਣਤਰ sockaddr_in6 *)ai->ai_addr)->
			    sin6_port;
			ਰੋਕੋ;
		ਮੂਲ:
			ਜਾਰੀ;
		}
		/*
		 * If allocating a port for -R forwards, then use the
		 * same port for all address families.
		 */
		ਜੇ (type == SSH_CHANNEL_RPORT_LISTENER &&
		    fwd->listen_ਪੋਰਟ == 0 && allocated_listen_ਪੋਰਟ != ਨਿਰਾ &&
		    *allocated_listen_ਪੋਰਟ > 0)
			*lport_p = htons(*allocated_listen_ਪੋਰਟ);

		ਜੇ (getnameinfo(ai->ai_addr, ai->ai_addrlen, ntop, ਆਕਾਰ(ntop),
		    strport, ਆਕਾਰ(strport),
		    NI_NUMERICHOST|NI_NUMERICSERV) != 0) {
			error_f("getnameinfo failed");
			ਜਾਰੀ;
		}
		/* Create a port to listen for the host. */
		sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		ਜੇ (sock == -1) {
			/* this is no error since kernel may not support ipv6 */
			verbose("socket [%s]:%s: %.100s", ntop, strport,
			    strerror(errno));
			ਜਾਰੀ;
		}

		ਸੈੱਟ_reuseaddr(sock);
		ਜੇ (ai->ai_family == AF_INET6)
			sock_ਸੈੱਟ_v6only(sock);

		debug("Local forwarding listening on %s port %s.",
		    ntop, strport);

		/* Bind the socket to the address. */
		ਜੇ (bind(sock, ai->ai_addr, ai->ai_addrlen) == -1) {
			/*
			 * address can be in if use ipv6 address is
			 * already bound
			 */
			ਜੇ (!ai->ai_next)
				error("bind [%s]:%s: %.100s",
				    ntop, strport, strerror(errno));
			ਨਹੀਂਤਾਂ
				verbose("bind [%s]:%s: %.100s",
				    ntop, strport, strerror(errno));

			close(sock);
			ਜਾਰੀ;
		}
		/* Start listening for connections on the socket. */
		ਜੇ (listen(sock, SSH_LISTEN_BACKLOG) == -1) {
			error("listen [%s]:%s: %.100s", ntop, strport,
			    strerror(errno));
			close(sock);
			ਜਾਰੀ;
		}

		/*
		 * fwd->listen_port == 0 requests a dynamically allocated port -
		 * record what we got.
		 */
		ਜੇ (type == SSH_CHANNEL_RPORT_LISTENER &&
		    fwd->listen_ਪੋਰਟ == 0 &&
		    allocated_listen_ਪੋਰਟ != ਨਿਰਾ &&
		    *allocated_listen_ਪੋਰਟ == 0) {
			*allocated_listen_ਪੋਰਟ = get_local_ਪੋਰਟ(sock);
			debug("Allocated listen port %d",
			    *allocated_listen_ਪੋਰਟ);
		}

		/* Allocate a channel number for the socket. */
		c = channel_new(ssh, "port-listener", type, sock, sock, -1,
		    CHAN_TCP_ਖਿੜਕੀ_DEFAULT, CHAN_TCP_PACKET_DEFAULT,
		    0, "port listener", 1);
		c->ਰਸਤਾ = xstrdup(host);
		c->host_ਪੋਰਟ = fwd->connect_ਪੋਰਟ;
		c->listening_addr = addr == ਨਿਰਾ ? ਨਿਰਾ : xstrdup(addr);
		ਜੇ (fwd->listen_ਪੋਰਟ == 0 && allocated_listen_ਪੋਰਟ != ਨਿਰਾ &&
		    !(ssh->compat & SSH_BUG_DYNAMIC_RPORT))
			c->listening_ਪੋਰਟ = *allocated_listen_ਪੋਰਟ;
		ਨਹੀਂਤਾਂ
			c->listening_ਪੋਰਟ = fwd->listen_ਪੋਰਟ;
		success = 1;
	}
	ਜੇ (success == 0)
		error_f("cannot listen to port: %d", fwd->listen_ਪੋਰਟ);
	freeaddrinfo(aitop);
	ਵਾਪਸ success;
}

ਸਥਿਰ ਪੂਰਨ
channel_ਤਿਆਰੀ_fwd_listener_streamlocal(ਬਣਤਰ ssh *ssh, ਪੂਰਨ type,
    ਬਣਤਰ Forward *fwd, ਬਣਤਰ ForwardOptions *fwd_opts)
{
	ਬਣਤਰ sockaddr_un sunaddr;
	ਅਚਲ ਅੱਖਰ *ਰਸਤਾ;
	Channel *c;
	ਪੂਰਨ ਪੋਰਟ, sock;
	ਬਹੁਲਕ_t omask;

	ਚੋਣ (type) {
	ਹਾਲਤ SSH_CHANNEL_UNIX_LISTENER:
		ਜੇ (fwd->connect_ਰਸਤਾ != ਨਿਰਾ) {
			ਜੇ (ਲੜੀ_ਲੰਬਾਈ(fwd->connect_ਰਸਤਾ) > ਆਕਾਰ(sunaddr.sun_ਰਸਤਾ)) {
				error("Local connecting path too long: %s",
				    fwd->connect_ਰਸਤਾ);
				ਵਾਪਸ 0;
			}
			ਰਸਤਾ = fwd->connect_ਰਸਤਾ;
			ਪੋਰਟ = ਪੋਰਟ_STREAMLOCAL;
		} ਨਹੀਂਤਾਂ {
			ਜੇ (fwd->connect_host == ਨਿਰਾ) {
				error("No forward host name.");
				ਵਾਪਸ 0;
			}
			ਜੇ (ਲੜੀ_ਲੰਬਾਈ(fwd->connect_host) >= NI_MAXHOST) {
				error("Forward host name too long.");
				ਵਾਪਸ 0;
			}
			ਰਸਤਾ = fwd->connect_host;
			ਪੋਰਟ = fwd->connect_ਪੋਰਟ;
		}
		ਰੋਕੋ;
	ਹਾਲਤ SSH_CHANNEL_RUNIX_LISTENER:
		ਰਸਤਾ = fwd->listen_ਰਸਤਾ;
		ਪੋਰਟ = ਪੋਰਟ_STREAMLOCAL;
		ਰੋਕੋ;
	ਮੂਲ:
		error_f("unexpected channel type %d", type);
		ਵਾਪਸ 0;
	}

	ਜੇ (fwd->listen_ਰਸਤਾ == ਨਿਰਾ) {
		error("No forward path name.");
		ਵਾਪਸ 0;
	}
	ਜੇ (ਲੜੀ_ਲੰਬਾਈ(fwd->listen_ਰਸਤਾ) > ਆਕਾਰ(sunaddr.sun_ਰਸਤਾ)) {
		error("Local listening path too long: %s", fwd->listen_ਰਸਤਾ);
		ਵਾਪਸ 0;
	}

	debug3_f("type %d path %s", type, fwd->listen_ਰਸਤਾ);

	/* Start a Unix domain listener. */
	omask = umask(fwd_opts->streamlocal_bind_ਨਕਾਬ);
	sock = unix_listener(fwd->listen_ਰਸਤਾ, SSH_LISTEN_BACKLOG,
	    fwd_opts->streamlocal_bind_unlink);
	umask(omask);
	ਜੇ (sock < 0)
		ਵਾਪਸ 0;

	debug("Local forwarding listening on path %s.", fwd->listen_ਰਸਤਾ);

	/* Allocate a channel number for the socket. */
	c = channel_new(ssh, "unix-listener", type, sock, sock, -1,
	    CHAN_TCP_ਖਿੜਕੀ_DEFAULT, CHAN_TCP_PACKET_DEFAULT,
	    0, "unix listener", 1);
	c->ਰਸਤਾ = xstrdup(ਰਸਤਾ);
	c->host_ਪੋਰਟ = ਪੋਰਟ;
	c->listening_ਪੋਰਟ = ਪੋਰਟ_STREAMLOCAL;
	c->listening_addr = xstrdup(fwd->listen_ਰਸਤਾ);
	ਵਾਪਸ 1;
}

ਸਥਿਰ ਪੂਰਨ
channel_cancel_rport_listener_tcpip(ਬਣਤਰ ssh *ssh,
    ਅਚਲ ਅੱਖਰ *host, u_short ਪੋਰਟ)
{
	u_int i;
	ਪੂਰਨ ਮਿਲਿਆ = 0;

	ਲਈ (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		Channel *c = ssh->chanctxt->channels[i];
		ਜੇ (c == ਨਿਰਾ || c->type != SSH_CHANNEL_RPORT_LISTENER)
			ਜਾਰੀ;
		ਜੇ (strcmp(c->ਰਸਤਾ, host) == 0 && c->listening_ਪੋਰਟ == ਪੋਰਟ) {
			debug2_f("close channel %d", i);
			channel_free(ssh, c);
			ਮਿਲਿਆ = 1;
		}
	}

	ਵਾਪਸ ਮਿਲਿਆ;
}

ਸਥਿਰ ਪੂਰਨ
channel_cancel_rport_listener_streamlocal(ਬਣਤਰ ssh *ssh, ਅਚਲ ਅੱਖਰ *ਰਸਤਾ)
{
	u_int i;
	ਪੂਰਨ ਮਿਲਿਆ = 0;

	ਲਈ (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		Channel *c = ssh->chanctxt->channels[i];
		ਜੇ (c == ਨਿਰਾ || c->type != SSH_CHANNEL_RUNIX_LISTENER)
			ਜਾਰੀ;
		ਜੇ (c->ਰਸਤਾ == ਨਿਰਾ)
			ਜਾਰੀ;
		ਜੇ (strcmp(c->ਰਸਤਾ, ਰਸਤਾ) == 0) {
			debug2_f("close channel %d", i);
			channel_free(ssh, c);
			ਮਿਲਿਆ = 1;
		}
	}

	ਵਾਪਸ ਮਿਲਿਆ;
}

ਪੂਰਨ
channel_cancel_rport_listener(ਬਣਤਰ ssh *ssh, ਬਣਤਰ Forward *fwd)
{
	ਜੇ (fwd->listen_ਰਸਤਾ != ਨਿਰਾ) {
		ਵਾਪਸ channel_cancel_rport_listener_streamlocal(ssh,
		    fwd->listen_ਰਸਤਾ);
	} ਨਹੀਂਤਾਂ {
		ਵਾਪਸ channel_cancel_rport_listener_tcpip(ssh,
		    fwd->listen_host, fwd->listen_ਪੋਰਟ);
	}
}

ਸਥਿਰ ਪੂਰਨ
channel_cancel_lport_listener_tcpip(ਬਣਤਰ ssh *ssh,
    ਅਚਲ ਅੱਖਰ *lhost, u_short lport, ਪੂਰਨ cport,
    ਬਣਤਰ ForwardOptions *fwd_opts)
{
	u_int i;
	ਪੂਰਨ ਮਿਲਿਆ = 0;
	ਅਚਲ ਅੱਖਰ *addr = channel_fwd_bind_addr(ssh, lhost, ਨਿਰਾ, 1, fwd_opts);

	ਲਈ (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		Channel *c = ssh->chanctxt->channels[i];
		ਜੇ (c == ਨਿਰਾ || c->type != SSH_CHANNEL_ਪੋਰਟ_LISTENER)
			ਜਾਰੀ;
		ਜੇ (c->listening_ਪੋਰਟ != lport)
			ਜਾਰੀ;
		ਜੇ (cport == CHANNEL_CANCEL_ਪੋਰਟ_STATIC) {
			/* skip dynamic forwardings */
			ਜੇ (c->host_ਪੋਰਟ == 0)
				ਜਾਰੀ;
		} ਨਹੀਂਤਾਂ {
			ਜੇ (c->host_ਪੋਰਟ != cport)
				ਜਾਰੀ;
		}
		ਜੇ ((c->listening_addr == ਨਿਰਾ && addr != ਨਿਰਾ) ||
		    (c->listening_addr != ਨਿਰਾ && addr == ਨਿਰਾ))
			ਜਾਰੀ;
		ਜੇ (addr == ਨਿਰਾ || strcmp(c->listening_addr, addr) == 0) {
			debug2_f("close channel %d", i);
			channel_free(ssh, c);
			ਮਿਲਿਆ = 1;
		}
	}

	ਵਾਪਸ ਮਿਲਿਆ;
}

ਸਥਿਰ ਪੂਰਨ
channel_cancel_lport_listener_streamlocal(ਬਣਤਰ ssh *ssh, ਅਚਲ ਅੱਖਰ *ਰਸਤਾ)
{
	u_int i;
	ਪੂਰਨ ਮਿਲਿਆ = 0;

	ਜੇ (ਰਸਤਾ == ਨਿਰਾ) {
		error_f("no path specified.");
		ਵਾਪਸ 0;
	}

	ਲਈ (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		Channel *c = ssh->chanctxt->channels[i];
		ਜੇ (c == ਨਿਰਾ || c->type != SSH_CHANNEL_UNIX_LISTENER)
			ਜਾਰੀ;
		ਜੇ (c->listening_addr == ਨਿਰਾ)
			ਜਾਰੀ;
		ਜੇ (strcmp(c->listening_addr, ਰਸਤਾ) == 0) {
			debug2_f("close channel %d", i);
			channel_free(ssh, c);
			ਮਿਲਿਆ = 1;
		}
	}

	ਵਾਪਸ ਮਿਲਿਆ;
}

ਪੂਰਨ
channel_cancel_lport_listener(ਬਣਤਰ ssh *ssh,
    ਬਣਤਰ Forward *fwd, ਪੂਰਨ cport, ਬਣਤਰ ForwardOptions *fwd_opts)
{
	ਜੇ (fwd->listen_ਰਸਤਾ != ਨਿਰਾ) {
		ਵਾਪਸ channel_cancel_lport_listener_streamlocal(ssh,
		    fwd->listen_ਰਸਤਾ);
	} ਨਹੀਂਤਾਂ {
		ਵਾਪਸ channel_cancel_lport_listener_tcpip(ssh,
		    fwd->listen_host, fwd->listen_ਪੋਰਟ, cport, fwd_opts);
	}
}

/* protocol local port fwd, used by ssh */
ਪੂਰਨ
channel_ਤਿਆਰੀ_local_fwd_listener(ਬਣਤਰ ssh *ssh,
    ਬਣਤਰ Forward *fwd, ਬਣਤਰ ForwardOptions *fwd_opts)
{
	ਜੇ (fwd->listen_ਰਸਤਾ != ਨਿਰਾ) {
		ਵਾਪਸ channel_ਤਿਆਰੀ_fwd_listener_streamlocal(ssh,
		    SSH_CHANNEL_UNIX_LISTENER, fwd, fwd_opts);
	} ਨਹੀਂਤਾਂ {
		ਵਾਪਸ channel_ਤਿਆਰੀ_fwd_listener_tcpip(ssh,
		    SSH_CHANNEL_ਪੋਰਟ_LISTENER, fwd, ਨਿਰਾ, fwd_opts);
	}
}

/* Matches a remote forwarding permission against a requested forwarding */
ਸਥਿਰ ਪੂਰਨ
remote_open_ਮੇਲ(ਬਣਤਰ permission *allowed_open, ਬਣਤਰ Forward *fwd)
{
	ਪੂਰਨ ret;
	ਅੱਖਰ *lhost;

	/* XXX add ACLs for streamlocal */
	ਜੇ (fwd->listen_ਰਸਤਾ != ਨਿਰਾ)
		ਵਾਪਸ 1;

	ਜੇ (fwd->listen_host == ਨਿਰਾ || allowed_open->listen_host == ਨਿਰਾ)
		ਵਾਪਸ 0;

	ਜੇ (allowed_open->listen_ਪੋਰਟ != FWD_PERMIT_ANY_ਪੋਰਟ &&
	    allowed_open->listen_ਪੋਰਟ != fwd->listen_ਪੋਰਟ)
		ਵਾਪਸ 0;

	/* Match hostnames case-insensitively */
	lhost = xstrdup(fwd->listen_host);
	lowercase(lhost);
	ret = ਮੇਲ_ਨਮੂਨਾ(lhost, allowed_open->listen_host);
	ਮੁਕਤ(lhost);

	ਵਾਪਸ ret;
}

/* Checks whether a requested remote forwarding is permitted */
ਸਥਿਰ ਪੂਰਨ
check_rfwd_permission(ਬਣਤਰ ssh *ssh, ਬਣਤਰ Forward *fwd)
{
	ਬਣਤਰ ssh_channels *sc = ssh->chanctxt;
	ਬਣਤਰ permission_ਸੈੱਟ *pset = &sc->remote_perms;
	u_int i, permit, permit_adm = 1;
	ਬਣਤਰ permission *perm;

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ SKIP_PRIVDROP
	ਜੇ (fwd->listen_ਰਸਤਾ != ਨਿਰਾ)
		ਵਾਪਸ 0;
	ਜੇ (fwd->listen_ਪੋਰਟ != 0 && fwd->listen_ਪੋਰਟ < 1024)
		ਵਾਪਸ 0;
#ਜੇ_ਅੰਤ

	/* XXX apply GatewayPorts override before checking? */

	permit = pset->all_permitted;
	ਜੇ (!permit) {
		ਲਈ (i = 0; i < pset->ਅੰਕ_permitted_user; i++) {
			perm = &pset->permitted_user[i];
			ਜੇ (remote_open_ਮੇਲ(perm, fwd)) {
				permit = 1;
				ਰੋਕੋ;
			}
		}
	}

	ਜੇ (pset->ਅੰਕ_permitted_admin > 0) {
		permit_adm = 0;
		ਲਈ (i = 0; i < pset->ਅੰਕ_permitted_admin; i++) {
			perm = &pset->permitted_admin[i];
			ਜੇ (remote_open_ਮੇਲ(perm, fwd)) {
				permit_adm = 1;
				ਰੋਕੋ;
			}
		}
	}

	ਵਾਪਸ permit && permit_adm;
}

/* protocol v2 remote port fwd, used by sshd */
ਪੂਰਨ
channel_ਤਿਆਰੀ_remote_fwd_listener(ਬਣਤਰ ssh *ssh, ਬਣਤਰ Forward *fwd,
    ਪੂਰਨ *allocated_listen_ਪੋਰਟ, ਬਣਤਰ ForwardOptions *fwd_opts)
{
	ਜੇ (!check_rfwd_permission(ssh, fwd)) {
		ssh_packet_send_debug(ssh, "port forwarding refused");
		ਜੇ (fwd->listen_ਰਸਤਾ != ਨਿਰਾ)
			/* XXX always allowed, see remote_open_match() */
			logit("Received request from %.100s port %d to "
			    "remote forward to path \"%.100s\", "
			    "but the request was denied.",
			    ssh_remote_ipaddr(ssh), ssh_remote_ਪੋਰਟ(ssh),
			    fwd->listen_ਰਸਤਾ);
		ਨਹੀਂਤਾਂ ਜੇ(fwd->listen_host != ਨਿਰਾ)
			logit("Received request from %.100s port %d to "
			    "remote forward to host %.100s port %d, "
			    "but the request was denied.",
			    ssh_remote_ipaddr(ssh), ssh_remote_ਪੋਰਟ(ssh),
			    fwd->listen_host, fwd->listen_ਪੋਰਟ );
		ਨਹੀਂਤਾਂ
			logit("Received request from %.100s port %d to remote "
			    "forward, but the request was denied.",
			    ssh_remote_ipaddr(ssh), ssh_remote_ਪੋਰਟ(ssh));
		ਵਾਪਸ 0;
	}
	ਜੇ (fwd->listen_ਰਸਤਾ != ਨਿਰਾ) {
		ਵਾਪਸ channel_ਤਿਆਰੀ_fwd_listener_streamlocal(ssh,
		    SSH_CHANNEL_RUNIX_LISTENER, fwd, fwd_opts);
	} ਨਹੀਂਤਾਂ {
		ਵਾਪਸ channel_ਤਿਆਰੀ_fwd_listener_tcpip(ssh,
		    SSH_CHANNEL_RPORT_LISTENER, fwd, allocated_listen_ਪੋਰਟ,
		    fwd_opts);
	}
}

/*
 * Translate the requested rfwd listen host to something usable for
 * this server.
 */
ਸਥਿਰ ਅਚਲ ਅੱਖਰ *
channel_rfwd_bind_host(ਅਚਲ ਅੱਖਰ *listen_host)
{
	ਜੇ (listen_host == ਨਿਰਾ) {
		ਵਾਪਸ "localhost";
	} ਨਹੀਂਤਾਂ ਜੇ (*listen_host == '\0' || strcmp(listen_host, "*") == 0) {
		ਵਾਪਸ "";
	} ਨਹੀਂਤਾਂ
		ਵਾਪਸ listen_host;
}

/*
 * Initiate forwarding of connections to port "port" on remote host through
 * the secure channel to host:port from local side.
 * Returns handle (index) for updating the dynamic listen port with
 * channel_update_permission().
 */
ਪੂਰਨ
channel_request_remote_forwarding(ਬਣਤਰ ssh *ssh, ਬਣਤਰ Forward *fwd)
{
	ਪੂਰਨ r, success = 0, idx = -1;
	ਅਚਲ ਅੱਖਰ *host_ਮੰਜ਼ਿਲ_connect, *listen_host, *listen_ਰਸਤਾ;
	ਪੂਰਨ ਪੋਰਟ_ਮੰਜ਼ਿਲ_connect, listen_ਪੋਰਟ;

	/* Send the forward request to the remote side. */
	ਜੇ (fwd->listen_ਰਸਤਾ != ਨਿਰਾ) {
		ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh, SSH2_ਸੁਨੇਹਾ_GLOBAL_REQUEST)) != 0 ||
		    (r = sshpkt_put_cstring(ssh,
		    "streamlocal-forward@openssh.com")) != 0 ||
		    (r = sshpkt_put_u8(ssh, 1)) != 0 || /* want reply */
		    (r = sshpkt_put_cstring(ssh, fwd->listen_ਰਸਤਾ)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			fatal_fr(r, "request streamlocal");
	} ਨਹੀਂਤਾਂ {
		ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh, SSH2_ਸੁਨੇਹਾ_GLOBAL_REQUEST)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "tcpip-forward")) != 0 ||
		    (r = sshpkt_put_u8(ssh, 1)) != 0 || /* want reply */
		    (r = sshpkt_put_cstring(ssh,
		    channel_rfwd_bind_host(fwd->listen_host))) != 0 ||
		    (r = sshpkt_put_u32(ssh, fwd->listen_ਪੋਰਟ)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			fatal_fr(r, "request tcpip-forward");
	}
	/* Assume that server accepts the request */
	success = 1;
	ਜੇ (success) {
		/* Record that connection to this host/port is permitted. */
		host_ਮੰਜ਼ਿਲ_connect = listen_host = listen_ਰਸਤਾ = ਨਿਰਾ;
		ਪੋਰਟ_ਮੰਜ਼ਿਲ_connect = listen_ਪੋਰਟ = 0;
		ਜੇ (fwd->connect_ਰਸਤਾ != ਨਿਰਾ) {
			host_ਮੰਜ਼ਿਲ_connect = fwd->connect_ਰਸਤਾ;
			ਪੋਰਟ_ਮੰਜ਼ਿਲ_connect = ਪੋਰਟ_STREAMLOCAL;
		} ਨਹੀਂਤਾਂ {
			host_ਮੰਜ਼ਿਲ_connect = fwd->connect_host;
			ਪੋਰਟ_ਮੰਜ਼ਿਲ_connect = fwd->connect_ਪੋਰਟ;
		}
		ਜੇ (fwd->listen_ਰਸਤਾ != ਨਿਰਾ) {
			listen_ਰਸਤਾ = fwd->listen_ਰਸਤਾ;
			listen_ਪੋਰਟ = ਪੋਰਟ_STREAMLOCAL;
		} ਨਹੀਂਤਾਂ {
			listen_host = fwd->listen_host;
			listen_ਪੋਰਟ = fwd->listen_ਪੋਰਟ;
		}
		idx = permission_ਸੈੱਟ_ਜੋੜੋ(ssh, FORWARD_USER, FORWARD_LOCAL,
		    host_ਮੰਜ਼ਿਲ_connect, ਪੋਰਟ_ਮੰਜ਼ਿਲ_connect,
		    listen_host, listen_ਰਸਤਾ, listen_ਪੋਰਟ, ਨਿਰਾ);
	}
	ਵਾਪਸ idx;
}

ਸਥਿਰ ਪੂਰਨ
open_ਮੇਲ(ਬਣਤਰ permission *allowed_open, ਅਚਲ ਅੱਖਰ *requestedhost,
    ਪੂਰਨ requestedport)
{
	ਜੇ (allowed_open->host_ਮੰਜ਼ਿਲ_connect == ਨਿਰਾ)
		ਵਾਪਸ 0;
	ਜੇ (allowed_open->ਪੋਰਟ_ਮੰਜ਼ਿਲ_connect != FWD_PERMIT_ANY_ਪੋਰਟ &&
	    allowed_open->ਪੋਰਟ_ਮੰਜ਼ਿਲ_connect != requestedport)
		ਵਾਪਸ 0;
	ਜੇ (strcmp(allowed_open->host_ਮੰਜ਼ਿਲ_connect, FWD_PERMIT_ANY_HOST) != 0 &&
	    strcmp(allowed_open->host_ਮੰਜ਼ਿਲ_connect, requestedhost) != 0)
		ਵਾਪਸ 0;
	ਵਾਪਸ 1;
}

/*
 * Note that in the listen host/port case
 * we don't support FWD_PERMIT_ANY_PORT and
 * need to translate between the configured-host (listen_host)
 * and what we've sent to the remote server (channel_rfwd_bind_host)
 */
ਸਥਿਰ ਪੂਰਨ
open_listen_ਮੇਲ_tcpip(ਬਣਤਰ permission *allowed_open,
    ਅਚਲ ਅੱਖਰ *requestedhost, u_short requestedport, ਪੂਰਨ translate)
{
	ਅਚਲ ਅੱਖਰ *allowed_host;

	ਜੇ (allowed_open->host_ਮੰਜ਼ਿਲ_connect == ਨਿਰਾ)
		ਵਾਪਸ 0;
	ਜੇ (allowed_open->listen_ਪੋਰਟ != requestedport)
		ਵਾਪਸ 0;
	ਜੇ (!translate && allowed_open->listen_host == ਨਿਰਾ &&
	    requestedhost == ਨਿਰਾ)
		ਵਾਪਸ 1;
	allowed_host = translate ?
	    channel_rfwd_bind_host(allowed_open->listen_host) :
	    allowed_open->listen_host;
	ਜੇ (allowed_host == ਨਿਰਾ || requestedhost == ਨਿਰਾ ||
	    strcmp(allowed_host, requestedhost) != 0)
		ਵਾਪਸ 0;
	ਵਾਪਸ 1;
}

ਸਥਿਰ ਪੂਰਨ
open_listen_ਮੇਲ_streamlocal(ਬਣਤਰ permission *allowed_open,
    ਅਚਲ ਅੱਖਰ *requestedpath)
{
	ਜੇ (allowed_open->host_ਮੰਜ਼ਿਲ_connect == ਨਿਰਾ)
		ਵਾਪਸ 0;
	ਜੇ (allowed_open->listen_ਪੋਰਟ != ਪੋਰਟ_STREAMLOCAL)
		ਵਾਪਸ 0;
	ਜੇ (allowed_open->listen_ਰਸਤਾ == ਨਿਰਾ ||
	    strcmp(allowed_open->listen_ਰਸਤਾ, requestedpath) != 0)
		ਵਾਪਸ 0;
	ਵਾਪਸ 1;
}

/*
 * Request cancellation of remote forwarding of connection host:port from
 * local side.
 */
ਸਥਿਰ ਪੂਰਨ
channel_request_rforward_cancel_tcpip(ਬਣਤਰ ssh *ssh,
    ਅਚਲ ਅੱਖਰ *host, u_short ਪੋਰਟ)
{
	ਬਣਤਰ ssh_channels *sc = ssh->chanctxt;
	ਬਣਤਰ permission_ਸੈੱਟ *pset = &sc->local_perms;
	ਪੂਰਨ r;
	u_int i;
	ਬਣਤਰ permission *perm = ਨਿਰਾ;

	ਲਈ (i = 0; i < pset->ਅੰਕ_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		ਜੇ (open_listen_ਮੇਲ_tcpip(perm, host, ਪੋਰਟ, 0))
			ਰੋਕੋ;
		perm = ਨਿਰਾ;
	}
	ਜੇ (perm == ਨਿਰਾ) {
		debug_f("requested forward not found");
		ਵਾਪਸ -1;
	}
	ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh, SSH2_ਸੁਨੇਹਾ_GLOBAL_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "cancel-tcpip-forward")) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 || /* want reply */
	    (r = sshpkt_put_cstring(ssh, channel_rfwd_bind_host(host))) != 0 ||
	    (r = sshpkt_put_u32(ssh, ਪੋਰਟ)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send cancel");

	fwd_perm_clear(perm); /* unregister */

	ਵਾਪਸ 0;
}

/*
 * Request cancellation of remote forwarding of Unix domain socket
 * path from local side.
 */
ਸਥਿਰ ਪੂਰਨ
channel_request_rforward_cancel_streamlocal(ਬਣਤਰ ssh *ssh, ਅਚਲ ਅੱਖਰ *ਰਸਤਾ)
{
	ਬਣਤਰ ssh_channels *sc = ssh->chanctxt;
	ਬਣਤਰ permission_ਸੈੱਟ *pset = &sc->local_perms;
	ਪੂਰਨ r;
	u_int i;
	ਬਣਤਰ permission *perm = ਨਿਰਾ;

	ਲਈ (i = 0; i < pset->ਅੰਕ_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		ਜੇ (open_listen_ਮੇਲ_streamlocal(perm, ਰਸਤਾ))
			ਰੋਕੋ;
		perm = ਨਿਰਾ;
	}
	ਜੇ (perm == ਨਿਰਾ) {
		debug_f("requested forward not found");
		ਵਾਪਸ -1;
	}
	ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh, SSH2_ਸੁਨੇਹਾ_GLOBAL_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh,
	    "cancel-streamlocal-forward@openssh.com")) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 || /* want reply */
	    (r = sshpkt_put_cstring(ssh, ਰਸਤਾ)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send cancel");

	fwd_perm_clear(perm); /* unregister */

	ਵਾਪਸ 0;
}

/*
 * Request cancellation of remote forwarding of a connection from local side.
 */
ਪੂਰਨ
channel_request_rforward_cancel(ਬਣਤਰ ssh *ssh, ਬਣਤਰ Forward *fwd)
{
	ਜੇ (fwd->listen_ਰਸਤਾ != ਨਿਰਾ) {
		ਵਾਪਸ channel_request_rforward_cancel_streamlocal(ssh,
		    fwd->listen_ਰਸਤਾ);
	} ਨਹੀਂਤਾਂ {
		ਵਾਪਸ channel_request_rforward_cancel_tcpip(ssh,
		    fwd->listen_host,
		    fwd->listen_ਪੋਰਟ ? fwd->listen_ਪੋਰਟ : fwd->allocated_ਪੋਰਟ);
	}
}

/*
 * Permits opening to any host/port if permitted_user[] is empty.  This is
 * usually called by the server, because the user could connect to any port
 * anyway, and the server has no way to know but to trust the client anyway.
 */
ਖਾਲੀ
channel_permit_all(ਬਣਤਰ ssh *ssh, ਪੂਰਨ where)
{
	ਬਣਤਰ permission_ਸੈੱਟ *pset = permission_ਸੈੱਟ_get(ssh, where);

	ਜੇ (pset->ਅੰਕ_permitted_user == 0)
		pset->all_permitted = 1;
}

/*
 * Permit the specified host/port for forwarding.
 */
ਖਾਲੀ
channel_ਜੋੜੋ_permission(ਬਣਤਰ ssh *ssh, ਪੂਰਨ who, ਪੂਰਨ where,
    ਅੱਖਰ *host, ਪੂਰਨ ਪੋਰਟ)
{
	ਪੂਰਨ local = where == FORWARD_LOCAL;
	ਬਣਤਰ permission_ਸੈੱਟ *pset = permission_ਸੈੱਟ_get(ssh, where);

	debug("allow %s forwarding to host %s port %d",
	    fwd_ident(who, where), host, ਪੋਰਟ);
	/*
	 * Remote forwards set listen_host/port, local forwards set
	 * host/port_to_connect.
	 */
	permission_ਸੈੱਟ_ਜੋੜੋ(ssh, who, where,
	    local ? host : ਨਿਰਾ, local ? ਪੋਰਟ : 0,
	    local ? ਨਿਰਾ : host, ਨਿਰਾ, local ? 0 : ਪੋਰਟ, ਨਿਰਾ);
	pset->all_permitted = 0;
}

/*
 * Administratively disable forwarding.
 */
ਖਾਲੀ
channel_disable_admin(ਬਣਤਰ ssh *ssh, ਪੂਰਨ where)
{
	channel_clear_permission(ssh, FORWARD_ADM, where);
	permission_ਸੈੱਟ_ਜੋੜੋ(ssh, FORWARD_ADM, where,
	    ਨਿਰਾ, 0, ਨਿਰਾ, ਨਿਰਾ, 0, ਨਿਰਾ);
}

/*
 * Clear a list of permitted opens.
 */
ਖਾਲੀ
channel_clear_permission(ਬਣਤਰ ssh *ssh, ਪੂਰਨ who, ਪੂਰਨ where)
{
	ਬਣਤਰ permission **permp;
	u_int i, *npermp;

	permission_ਸੈੱਟ_get_array(ssh, who, where, &permp, &npermp);
	ਲਈ (i = 0; i < *npermp; i++)
		fwd_perm_clear((*permp) + i);
	ਮੁਕਤ(*permp);
	*permp = ਨਿਰਾ;
	*npermp = 0;
}

/*
 * Update the listen port for a dynamic remote forward, after
 * the actual 'newport' has been allocated. If 'newport' < 0 is
 * passed then they entry will be invalidated.
 */
ਖਾਲੀ
channel_update_permission(ਬਣਤਰ ssh *ssh, ਪੂਰਨ idx, ਪੂਰਨ newport)
{
	ਬਣਤਰ permission_ਸੈੱਟ *pset = &ssh->chanctxt->local_perms;

	ਜੇ (idx < 0 || (u_int)idx >= pset->ਅੰਕ_permitted_user) {
		debug_f("index out of range: %d num_permitted_user %d",
		    idx, pset->ਅੰਕ_permitted_user);
		ਵਾਪਸ;
	}
	debug("%s allowed port %d for forwarding to host %s port %d",
	    newport > 0 ? "Updating" : "Removing",
	    newport,
	    pset->permitted_user[idx].host_ਮੰਜ਼ਿਲ_connect,
	    pset->permitted_user[idx].ਪੋਰਟ_ਮੰਜ਼ਿਲ_connect);
	ਜੇ (newport <= 0)
		fwd_perm_clear(&pset->permitted_user[idx]);
	ਨਹੀਂਤਾਂ {
		pset->permitted_user[idx].listen_ਪੋਰਟ =
		    (ssh->compat & SSH_BUG_DYNAMIC_RPORT) ? 0 : newport;
	}
}

/* Try to start non-blocking connect to next host in cctx list */
ਸਥਿਰ ਪੂਰਨ
connect_ਅਗਲਾ(ਬਣਤਰ ssh *ssh, ਬਣਤਰ channel_connect *cctx)
{
	ਪੂਰਨ sock, sock_is_ਜਾਲ, saved_errno;
	ਬਣਤਰ sockaddr_un *sunaddr;
	ਅੱਖਰ ntop[NI_MAXHOST];
	ਅੱਖਰ strport[ਵੱਧ_ਤੋਂ_ਵੱਧ(NI_MAXSERV, ਆਕਾਰ(sunaddr->sun_ਰਸਤਾ))];

	ਲਈ (; cctx->ai; cctx->ai = cctx->ai->ai_next) {
		sock_is_ਜਾਲ = 0;
		ਚੋਣ (cctx->ai->ai_family) {
		ਹਾਲਤ AF_UNIX:
			/* unix:pathname instead of host:port */
			sunaddr = (ਬਣਤਰ sockaddr_un *)cctx->ai->ai_addr;
			strlcpy(ntop, "unix", ਆਕਾਰ(ntop));
			strlcpy(strport, sunaddr->sun_ਰਸਤਾ, ਆਕਾਰ(strport));
			ਰੋਕੋ;
		ਹਾਲਤ AF_INET:
		ਹਾਲਤ AF_INET6:
			ਜੇ (getnameinfo(cctx->ai->ai_addr, cctx->ai->ai_addrlen,
			    ntop, ਆਕਾਰ(ntop), strport, ਆਕਾਰ(strport),
			    NI_NUMERICHOST|NI_NUMERICSERV) != 0) {
				error_f("getnameinfo failed");
				ਜਾਰੀ;
			}
			sock_is_ਜਾਲ = 1;
			ਰੋਕੋ;
		ਮੂਲ:
			ਜਾਰੀ;
		}
		debug_f("start for host %.100s ([%.100s]:%s)",
		    cctx->host, ntop, strport);
		ਜੇ ((sock = socket(cctx->ai->ai_family, cctx->ai->ai_socktype,
		    cctx->ai->ai_protocol)) == -1) {
			ਜੇ (cctx->ai->ai_next == ਨਿਰਾ)
				error("socket: %.100s", strerror(errno));
			ਨਹੀਂਤਾਂ
				verbose("socket: %.100s", strerror(errno));
			ਜਾਰੀ;
		}
		ਜੇ (ਸੈੱਟ_nonblock(sock) == -1)
			fatal_f("set_nonblock(%d)", sock);
		ਜੇ (sock_is_ਜਾਲ && ssh->chanctxt->want_tcp_keepalive)
			ਸੈੱਟ_keepalive(sock); /* logs errors */
		ਜੇ (connect(sock, cctx->ai->ai_addr,
		    cctx->ai->ai_addrlen) == -1 && errno != EINPROGRESS) {
			debug_f("host %.100s ([%.100s]:%s): %.100s",
			    cctx->host, ntop, strport, strerror(errno));
			saved_errno = errno;
			close(sock);
			errno = saved_errno;
			ਜਾਰੀ;	/* fail -- try next */
		}
		ਜੇ (cctx->ai->ai_family != AF_UNIX)
			ਸੈੱਟ_nodelay(sock);
		debug_f("connect host %.100s ([%.100s]:%s) in progress, fd=%d",
		    cctx->host, ntop, strport, sock);
		cctx->ai = cctx->ai->ai_next;
		ਵਾਪਸ sock;
	}
	ਵਾਪਸ -1;
}

/*
 * Return connecting socket to remote host:port or local socket path,
 * passing back the failure reason if appropriate.
 */
ਸਥਿਰ ਪੂਰਨ
connect_ਮੰਜ਼ਿਲ_helper(ਬਣਤਰ ssh *ssh, ਅਚਲ ਅੱਖਰ *name, ਪੂਰਨ ਪੋਰਟ, ਪੂਰਨ socktype,
    ਅੱਖਰ *ctype, ਅੱਖਰ *rname, ਬਣਤਰ channel_connect *cctx,
    ਪੂਰਨ *reason, ਅਚਲ ਅੱਖਰ **errmsg)
{
	ਬਣਤਰ addrinfo hints;
	ਪੂਰਨ gaierr;
	ਪੂਰਨ sock = -1;
	ਅੱਖਰ strport[NI_MAXSERV];

	ਜੇ (ਪੋਰਟ == ਪੋਰਟ_STREAMLOCAL) {
		ਬਣਤਰ sockaddr_un *sunaddr;
		ਬਣਤਰ addrinfo *ai;

		ਜੇ (ਲੜੀ_ਲੰਬਾਈ(name) > ਆਕਾਰ(sunaddr->sun_ਰਸਤਾ)) {
			error("%.100s: %.100s", name, strerror(ENAMETOOLONG));
			ਵਾਪਸ -1;
		}

		/*
		 * Fake up a struct addrinfo for AF_UNIX connections.
		 * free_connect_ctx() must check ai_family
		 * and use free() not freeaddrinfo() for AF_UNIX.
		 */
		ai = xcalloc(1, ਆਕਾਰ(*ai) + ਆਕਾਰ(*sunaddr));
		ai->ai_addr = (ਬਣਤਰ sockaddr *)(ai + 1);
		ai->ai_addrlen = ਆਕਾਰ(*sunaddr);
		ai->ai_family = AF_UNIX;
		ai->ai_socktype = socktype;
		ai->ai_protocol = PF_UNSPEC;
		sunaddr = (ਬਣਤਰ sockaddr_un *)ai->ai_addr;
		sunaddr->sun_family = AF_UNIX;
		strlcpy(sunaddr->sun_ਰਸਤਾ, name, ਆਕਾਰ(sunaddr->sun_ਰਸਤਾ));
		cctx->aitop = ai;
	} ਨਹੀਂਤਾਂ {
		memset(&hints, 0, ਆਕਾਰ(hints));
		hints.ai_family = ssh->chanctxt->IPv4or6;
		hints.ai_socktype = socktype;
		snprintf(strport, ਆਕਾਰ strport, "%d", ਪੋਰਟ);
		ਜੇ ((gaierr = getaddrinfo(name, strport, &hints, &cctx->aitop))
		    != 0) {
			ਜੇ (errmsg != ਨਿਰਾ)
				*errmsg = ssh_gai_strerror(gaierr);
			ਜੇ (reason != ਨਿਰਾ)
				*reason = SSH2_OPEN_CONNECT_FAILED;
			error("connect_to %.100s: unknown host (%s)", name,
			    ssh_gai_strerror(gaierr));
			ਵਾਪਸ -1;
		}
	}

	cctx->host = xstrdup(name);
	cctx->ਪੋਰਟ = ਪੋਰਟ;
	cctx->ai = cctx->aitop;

	ਜੇ ((sock = connect_ਅਗਲਾ(ssh, cctx)) == -1) {
		error("connect to %.100s port %d failed: %s",
		    name, ਪੋਰਟ, strerror(errno));
		ਵਾਪਸ -1;
	}

	ਵਾਪਸ sock;
}

/* Return CONNECTING channel to remote host:port or local socket path */
ਸਥਿਰ Channel *
connect_ਮੰਜ਼ਿਲ(ਬਣਤਰ ssh *ssh, ਅਚਲ ਅੱਖਰ *host, ਪੂਰਨ ਪੋਰਟ,
    ਅੱਖਰ *ctype, ਅੱਖਰ *rname)
{
	ਬਣਤਰ channel_connect cctx;
	Channel *c;
	ਪੂਰਨ sock;

	memset(&cctx, 0, ਆਕਾਰ(cctx));
	sock = connect_ਮੰਜ਼ਿਲ_helper(ssh, host, ਪੋਰਟ, SOCK_STREAM, ctype, rname,
	    &cctx, ਨਿਰਾ, ਨਿਰਾ);
	ਜੇ (sock == -1) {
		free_connect_ctx(&cctx);
		ਵਾਪਸ ਨਿਰਾ;
	}
	c = channel_new(ssh, ctype, SSH_CHANNEL_CONNECTING, sock, sock, -1,
	    CHAN_TCP_ਖਿੜਕੀ_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, rname, 1);
	c->host_ਪੋਰਟ = ਪੋਰਟ;
	c->ਰਸਤਾ = xstrdup(host);
	c->connect_ctx = xmalloc(ਆਕਾਰ(cctx));
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(c->connect_ctx, &cctx, ਆਕਾਰ(cctx));

	ਵਾਪਸ c;
}

/*
 * returns either the newly connected channel or the downstream channel
 * that needs to deal with this connection.
 */
Channel *
channel_connect_by_listen_ਪਤਾ(ਬਣਤਰ ssh *ssh, ਅਚਲ ਅੱਖਰ *listen_host,
    u_short listen_ਪੋਰਟ, ਅੱਖਰ *ctype, ਅੱਖਰ *rname)
{
	ਬਣਤਰ ssh_channels *sc = ssh->chanctxt;
	ਬਣਤਰ permission_ਸੈੱਟ *pset = &sc->local_perms;
	u_int i;
	ਬਣਤਰ permission *perm;

	ਲਈ (i = 0; i < pset->ਅੰਕ_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		ਜੇ (open_listen_ਮੇਲ_tcpip(perm,
		    listen_host, listen_ਪੋਰਟ, 1)) {
			ਜੇ (perm->downstream)
				ਵਾਪਸ perm->downstream;
			ਜੇ (perm->ਪੋਰਟ_ਮੰਜ਼ਿਲ_connect == 0)
				ਵਾਪਸ rdynamic_connect_prepare(ssh,
				    ctype, rname);
			ਵਾਪਸ connect_ਮੰਜ਼ਿਲ(ssh,
			    perm->host_ਮੰਜ਼ਿਲ_connect, perm->ਪੋਰਟ_ਮੰਜ਼ਿਲ_connect,
			    ctype, rname);
		}
	}
	error("WARNING: Server requests forwarding for unknown listen_port %d",
	    listen_ਪੋਰਟ);
	ਵਾਪਸ ਨਿਰਾ;
}

Channel *
channel_connect_by_listen_ਰਸਤਾ(ਬਣਤਰ ssh *ssh, ਅਚਲ ਅੱਖਰ *ਰਸਤਾ,
    ਅੱਖਰ *ctype, ਅੱਖਰ *rname)
{
	ਬਣਤਰ ssh_channels *sc = ssh->chanctxt;
	ਬਣਤਰ permission_ਸੈੱਟ *pset = &sc->local_perms;
	u_int i;
	ਬਣਤਰ permission *perm;

	ਲਈ (i = 0; i < pset->ਅੰਕ_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		ਜੇ (open_listen_ਮੇਲ_streamlocal(perm, ਰਸਤਾ)) {
			ਵਾਪਸ connect_ਮੰਜ਼ਿਲ(ssh,
			    perm->host_ਮੰਜ਼ਿਲ_connect, perm->ਪੋਰਟ_ਮੰਜ਼ਿਲ_connect,
			    ctype, rname);
		}
	}
	error("WARNING: Server requests forwarding for unknown path %.100s",
	    ਰਸਤਾ);
	ਵਾਪਸ ਨਿਰਾ;
}

/* Check if connecting to that port is permitted and connect. */
Channel *
channel_connect_ਮੰਜ਼ਿਲ_ਪੋਰਟ(ਬਣਤਰ ssh *ssh, ਅਚਲ ਅੱਖਰ *host, u_short ਪੋਰਟ,
    ਅੱਖਰ *ctype, ਅੱਖਰ *rname, ਪੂਰਨ *reason, ਅਚਲ ਅੱਖਰ **errmsg)
{
	ਬਣਤਰ ssh_channels *sc = ssh->chanctxt;
	ਬਣਤਰ permission_ਸੈੱਟ *pset = &sc->local_perms;
	ਬਣਤਰ channel_connect cctx;
	Channel *c;
	u_int i, permit, permit_adm = 1;
	ਪੂਰਨ sock;
	ਬਣਤਰ permission *perm;

	permit = pset->all_permitted;
	ਜੇ (!permit) {
		ਲਈ (i = 0; i < pset->ਅੰਕ_permitted_user; i++) {
			perm = &pset->permitted_user[i];
			ਜੇ (open_ਮੇਲ(perm, host, ਪੋਰਟ)) {
				permit = 1;
				ਰੋਕੋ;
			}
		}
	}

	ਜੇ (pset->ਅੰਕ_permitted_admin > 0) {
		permit_adm = 0;
		ਲਈ (i = 0; i < pset->ਅੰਕ_permitted_admin; i++) {
			perm = &pset->permitted_admin[i];
			ਜੇ (open_ਮੇਲ(perm, host, ਪੋਰਟ)) {
				permit_adm = 1;
				ਰੋਕੋ;
			}
		}
	}

	ਜੇ (!permit || !permit_adm) {
		logit("Received request from %.100s port %d to connect to "
		    "host %.100s port %d, but the request was denied.",
		    ssh_remote_ipaddr(ssh), ssh_remote_ਪੋਰਟ(ssh), host, ਪੋਰਟ);
		ਜੇ (reason != ਨਿਰਾ)
			*reason = SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED;
		ਵਾਪਸ ਨਿਰਾ;
	}

	memset(&cctx, 0, ਆਕਾਰ(cctx));
	sock = connect_ਮੰਜ਼ਿਲ_helper(ssh, host, ਪੋਰਟ, SOCK_STREAM, ctype, rname,
	    &cctx, reason, errmsg);
	ਜੇ (sock == -1) {
		free_connect_ctx(&cctx);
		ਵਾਪਸ ਨਿਰਾ;
	}

	c = channel_new(ssh, ctype, SSH_CHANNEL_CONNECTING, sock, sock, -1,
	    CHAN_TCP_ਖਿੜਕੀ_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, rname, 1);
	c->host_ਪੋਰਟ = ਪੋਰਟ;
	c->ਰਸਤਾ = xstrdup(host);
	c->connect_ctx = xmalloc(ਆਕਾਰ(cctx));
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(c->connect_ctx, &cctx, ਆਕਾਰ(cctx));

	ਵਾਪਸ c;
}

/* Check if connecting to that path is permitted and connect. */
Channel *
channel_connect_ਮੰਜ਼ਿਲ_ਰਸਤਾ(ਬਣਤਰ ssh *ssh, ਅਚਲ ਅੱਖਰ *ਰਸਤਾ,
    ਅੱਖਰ *ctype, ਅੱਖਰ *rname)
{
	ਬਣਤਰ ssh_channels *sc = ssh->chanctxt;
	ਬਣਤਰ permission_ਸੈੱਟ *pset = &sc->local_perms;
	u_int i, permit, permit_adm = 1;
	ਬਣਤਰ permission *perm;

	permit = pset->all_permitted;
	ਜੇ (!permit) {
		ਲਈ (i = 0; i < pset->ਅੰਕ_permitted_user; i++) {
			perm = &pset->permitted_user[i];
			ਜੇ (open_ਮੇਲ(perm, ਰਸਤਾ, ਪੋਰਟ_STREAMLOCAL)) {
				permit = 1;
				ਰੋਕੋ;
			}
		}
	}

	ਜੇ (pset->ਅੰਕ_permitted_admin > 0) {
		permit_adm = 0;
		ਲਈ (i = 0; i < pset->ਅੰਕ_permitted_admin; i++) {
			perm = &pset->permitted_admin[i];
			ਜੇ (open_ਮੇਲ(perm, ਰਸਤਾ, ਪੋਰਟ_STREAMLOCAL)) {
				permit_adm = 1;
				ਰੋਕੋ;
			}
		}
	}

	ਜੇ (!permit || !permit_adm) {
		logit("Received request to connect to path %.100s, "
		    "but the request was denied.", ਰਸਤਾ);
		ਵਾਪਸ ਨਿਰਾ;
	}
	ਵਾਪਸ connect_ਮੰਜ਼ਿਲ(ssh, ਰਸਤਾ, ਪੋਰਟ_STREAMLOCAL, ctype, rname);
}

ਖਾਲੀ
channel_send_ਖਿੜਕੀ_changes(ਬਣਤਰ ssh *ssh)
{
	ਬਣਤਰ ssh_channels *sc = ssh->chanctxt;
	ਬਣਤਰ winsize ws;
	ਪੂਰਨ r;
	u_int i;

	ਲਈ (i = 0; i < sc->channels_alloc; i++) {
		ਜੇ (sc->channels[i] == ਨਿਰਾ || !sc->channels[i]->client_tty ||
		    sc->channels[i]->type != SSH_CHANNEL_OPEN)
			ਜਾਰੀ;
		ਜੇ (ioctl(sc->channels[i]->rfd, TIOCGWINSZ, &ws) == -1)
			ਜਾਰੀ;
		channel_request_ਸ਼ੁਰੂ(ssh, i, "window-change", 0);
		ਜੇ ((r = sshpkt_put_u32(ssh, (u_int)ws.ws_ਖਾਨਾ)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_ਪੰਕਤੀ)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_xpixel)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_ypixel)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "channel %u; send window-change", i);
	}
}

/* Return RDYNAMIC_OPEN channel: channel allows SOCKS, but is not connected */
ਸਥਿਰ Channel *
rdynamic_connect_prepare(ਬਣਤਰ ssh *ssh, ਅੱਖਰ *ctype, ਅੱਖਰ *rname)
{
	Channel *c;
	ਪੂਰਨ r;

	c = channel_new(ssh, ctype, SSH_CHANNEL_RDYNAMIC_OPEN, -1, -1, -1,
	    CHAN_TCP_ਖਿੜਕੀ_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, rname, 1);
	c->host_ਪੋਰਟ = 0;
	c->ਰਸਤਾ = ਨਿਰਾ;

	/*
	 * We need to open the channel before we have a FD,
	 * so that we can get SOCKS header from peer.
	 */
	ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh, SSH2_ਸੁਨੇਹਾ_CHANNEL_OPEN_CONFIRMATION)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_ਖਿੜਕੀ)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0)
		fatal_fr(r, "channel %i; confirm", c->self);
	ਵਾਪਸ c;
}

/* Return CONNECTING socket to remote host:port or local socket path */
ਸਥਿਰ ਪੂਰਨ
rdynamic_connect_ਅੰਤ(ਬਣਤਰ ssh *ssh, Channel *c)
{
	ਬਣਤਰ ssh_channels *sc = ssh->chanctxt;
	ਬਣਤਰ permission_ਸੈੱਟ *pset = &sc->local_perms;
	ਬਣਤਰ permission *perm;
	ਬਣਤਰ channel_connect cctx;
	u_int i, permit_adm = 1;
	ਪੂਰਨ sock;

	ਜੇ (pset->ਅੰਕ_permitted_admin > 0) {
		permit_adm = 0;
		ਲਈ (i = 0; i < pset->ਅੰਕ_permitted_admin; i++) {
			perm = &pset->permitted_admin[i];
			ਜੇ (open_ਮੇਲ(perm, c->ਰਸਤਾ, c->host_ਪੋਰਟ)) {
				permit_adm = 1;
				ਰੋਕੋ;
			}
		}
	}
	ਜੇ (!permit_adm) {
		debug_f("requested forward not permitted");
		ਵਾਪਸ -1;
	}

	memset(&cctx, 0, ਆਕਾਰ(cctx));
	sock = connect_ਮੰਜ਼ਿਲ_helper(ssh, c->ਰਸਤਾ, c->host_ਪੋਰਟ, SOCK_STREAM, ਨਿਰਾ,
	    ਨਿਰਾ, &cctx, ਨਿਰਾ, ਨਿਰਾ);
	ਜੇ (sock == -1)
		free_connect_ctx(&cctx);
	ਨਹੀਂਤਾਂ {
		/* similar to SSH_CHANNEL_CONNECTING but we've already sent the open */
		c->type = SSH_CHANNEL_RDYNAMIC_ਅੰਤ;
		c->connect_ctx = xmalloc(ਆਕਾਰ(cctx));
		ਸਮ੍ਰਿਤੀ_ਨਕਲ(c->connect_ctx, &cctx, ਆਕਾਰ(cctx));
		channel_ਰਜਿਸਟਰ_fds(ssh, c, sock, sock, -1, 0, 1, 0);
	}
	ਵਾਪਸ sock;
}

/* -- X11 forwarding */

/*
 * Creates an internet domain socket for listening for X11 connections.
 * Returns 0 and a suitable display number for the DISPLAY variable
 * stored in display_numberp , or -1 if an error occurs.
 */
ਪੂਰਨ
x11_create_display_inet(ਬਣਤਰ ssh *ssh, ਪੂਰਨ x11_display_ਵਿੱਥ,
    ਪੂਰਨ x11_use_localhost, ਪੂਰਨ single_connection,
    u_int *display_numberp, ਪੂਰਨ **chanids)
{
	Channel *nc = ਨਿਰਾ;
	ਪੂਰਨ display_ਸੰਖਿਆ, sock, ਪੋਰਟ;
	ਬਣਤਰ addrinfo hints, *ai, *aitop;
	ਅੱਖਰ strport[NI_MAXSERV];
	ਪੂਰਨ gaierr, n, ਅੰਕ_socks = 0, socks[ਅੰਕ_SOCKS];

	ਜੇ (chanids == ਨਿਰਾ || x11_display_ਵਿੱਥ < 0 ||
	    x11_display_ਵਿੱਥ > UINT16_MAX - X11_ਅਧਾਰ_ਪੋਰਟ - MAX_DISPLAYS)
		ਵਾਪਸ -1;

	ਲਈ (display_ਸੰਖਿਆ = x11_display_ਵਿੱਥ;
	    display_ਸੰਖਿਆ < x11_display_ਵਿੱਥ + MAX_DISPLAYS;
	    display_ਸੰਖਿਆ++) {
		ਪੋਰਟ = X11_ਅਧਾਰ_ਪੋਰਟ + display_ਸੰਖਿਆ;
		memset(&hints, 0, ਆਕਾਰ(hints));
		hints.ai_family = ssh->chanctxt->IPv4or6;
		hints.ai_flags = x11_use_localhost ? 0: AI_PASSIVE;
		hints.ai_socktype = SOCK_STREAM;
		snprintf(strport, ਆਕਾਰ strport, "%d", ਪੋਰਟ);
		ਜੇ ((gaierr = getaddrinfo(ਨਿਰਾ, strport,
		    &hints, &aitop)) != 0) {
			error("getaddrinfo: %.100s", ssh_gai_strerror(gaierr));
			ਵਾਪਸ -1;
		}
		ਲਈ (ai = aitop; ai; ai = ai->ai_next) {
			ਜੇ (ai->ai_family != AF_INET &&
			    ai->ai_family != AF_INET6)
				ਜਾਰੀ;
			sock = socket(ai->ai_family, ai->ai_socktype,
			    ai->ai_protocol);
			ਜੇ (sock == -1) {
				ਜੇ ((errno != EINVAL) && (errno != EAFNOSUPPORT)
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ EPFNOSUPPORT
				    && (errno != EPFNOSUPPORT)
#ਜੇ_ਅੰਤ 
				    ) {
					error("socket: %.100s", strerror(errno));
					freeaddrinfo(aitop);
					ਵਾਪਸ -1;
				} ਨਹੀਂਤਾਂ {
					debug("x11_create_display_inet: Socket family %d not supported",
						 ai->ai_family);
					ਜਾਰੀ;
				}
			}
			ਜੇ (ai->ai_family == AF_INET6)
				sock_ਸੈੱਟ_v6only(sock);
			ਜੇ (x11_use_localhost)
				ਸੈੱਟ_reuseaddr(sock);
			ਜੇ (bind(sock, ai->ai_addr, ai->ai_addrlen) == -1) {
				debug2_f("bind port %d: %.100s", ਪੋਰਟ,
				    strerror(errno));
				close(sock);
				ਲਈ (n = 0; n < ਅੰਕ_socks; n++)
					close(socks[n]);
				ਅੰਕ_socks = 0;
				ਰੋਕੋ;
			}
			socks[ਅੰਕ_socks++] = sock;
			ਜੇ (ਅੰਕ_socks == ਅੰਕ_SOCKS)
				ਰੋਕੋ;
		}
		freeaddrinfo(aitop);
		ਜੇ (ਅੰਕ_socks > 0)
			ਰੋਕੋ;
	}
	ਜੇ (display_ਸੰਖਿਆ >= x11_display_ਵਿੱਥ + MAX_DISPLAYS) {
		error("Failed to allocate internet-domain X11 display socket.");
		ਵਾਪਸ -1;
	}
	/* Start listening for connections on the socket. */
	ਲਈ (n = 0; n < ਅੰਕ_socks; n++) {
		sock = socks[n];
		ਜੇ (listen(sock, SSH_LISTEN_BACKLOG) == -1) {
			error("listen: %.100s", strerror(errno));
			close(sock);
			ਵਾਪਸ -1;
		}
	}

	/* Allocate a channel for each socket. */
	*chanids = xcalloc(ਅੰਕ_socks + 1, ਆਕਾਰ(**chanids));
	ਲਈ (n = 0; n < ਅੰਕ_socks; n++) {
		sock = socks[n];
		nc = channel_new(ssh, "x11-listener",
		    SSH_CHANNEL_X11_LISTENER, sock, sock, -1,
		    CHAN_X11_ਖਿੜਕੀ_DEFAULT, CHAN_X11_PACKET_DEFAULT,
		    0, "X11 inet listener", 1);
		nc->single_connection = single_connection;
		(*chanids)[n] = nc->self;
	}
	(*chanids)[n] = -1;

	/* Return the display number for the DISPLAY environment variable. */
	*display_numberp = display_ਸੰਖਿਆ;
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
connect_local_xsocket_ਰਸਤਾ(ਅਚਲ ਅੱਖਰ *pathname)
{
	ਪੂਰਨ sock;
	ਬਣਤਰ sockaddr_un addr;

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	ਜੇ (sock == -1) {
		error("socket: %.100s", strerror(errno));
		ਵਾਪਸ -1;
	}
	memset(&addr, 0, ਆਕਾਰ(addr));
	addr.sun_family = AF_UNIX;
	strlcpy(addr.sun_ਰਸਤਾ, pathname, ਆਕਾਰ addr.sun_ਰਸਤਾ);
	ਜੇ (connect(sock, (ਬਣਤਰ sockaddr *)&addr, ਆਕਾਰ(addr)) == 0)
		ਵਾਪਸ sock;
	close(sock);
	error("connect %.100s: %.100s", addr.sun_ਰਸਤਾ, strerror(errno));
	ਵਾਪਸ -1;
}

ਸਥਿਰ ਪੂਰਨ
connect_local_xsocket(u_int dnr)
{
	ਅੱਖਰ buf[1024];
	snprintf(buf, ਆਕਾਰ buf, ਰਸਤਾ_UNIX_X, dnr);
	ਵਾਪਸ connect_local_xsocket_ਰਸਤਾ(buf);
}

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ __APPLE__
ਸਥਿਰ ਪੂਰਨ
is_ਰਸਤਾ_ਮੰਜ਼ਿਲ_xsocket(ਅਚਲ ਅੱਖਰ *display, ਅੱਖਰ *ਰਸਤਾ, ਮਾਪ_t pathlen)
{
	ਬਣਤਰ stat sbuf;

	ਜੇ (strlcpy(ਰਸਤਾ, display, pathlen) >= pathlen) {
		error_f("display path too long");
		ਵਾਪਸ 0;
	}
	ਜੇ (display[0] != '/')
		ਵਾਪਸ 0;
	ਜੇ (stat(ਰਸਤਾ, &sbuf) == 0) {
		ਵਾਪਸ 1;
	} ਨਹੀਂਤਾਂ {
		ਅੱਖਰ *dot = strrchr(ਰਸਤਾ, '.');
		ਜੇ (dot != ਨਿਰਾ) {
			*dot = '\0';
			ਜੇ (stat(ਰਸਤਾ, &sbuf) == 0) {
				ਵਾਪਸ 1;
			}
		}
	}
	ਵਾਪਸ 0;
}
#ਜੇ_ਅੰਤ

ਪੂਰਨ
x11_connect_display(ਬਣਤਰ ssh *ssh)
{
	u_int display_ਸੰਖਿਆ;
	ਅਚਲ ਅੱਖਰ *display;
	ਅੱਖਰ buf[1024], *cp;
	ਬਣਤਰ addrinfo hints, *ai, *aitop;
	ਅੱਖਰ strport[NI_MAXSERV];
	ਪੂਰਨ gaierr, sock = 0;

	/* Try to open a socket for the local X server. */
	display = getenv("DISPLAY");
	ਜੇ (!display) {
		error("DISPLAY not set.");
		ਵਾਪਸ -1;
	}
	/*
	 * Now we decode the value of the DISPLAY variable and make a
	 * connection to the real X server.
	 */

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ __APPLE__
	/* Check if display is a path to a socket (as set by launchd). */
	{
		ਅੱਖਰ ਰਸਤਾ[PATH_MAX];

		ਜੇ (is_ਰਸਤਾ_ਮੰਜ਼ਿਲ_xsocket(display, ਰਸਤਾ, ਆਕਾਰ(ਰਸਤਾ))) {
			debug("x11_connect_display: $DISPLAY is launchd");

			/* Create a socket. */
			sock = connect_local_xsocket_ਰਸਤਾ(ਰਸਤਾ);
			ਜੇ (sock < 0)
				ਵਾਪਸ -1;

			/* OK, we now have a connection to the display. */
			ਵਾਪਸ sock;
		}
	}
#ਜੇ_ਅੰਤ
	/*
	 * Check if it is a unix domain socket.  Unix domain displays are in
	 * one of the following formats: unix:d[.s], :d[.s], ::d[.s]
	 */
	ਜੇ (ਲੜੀ_ਤੁਲਨਾ(display, "unix:", 5) == 0 ||
	    display[0] == ':') {
		/* Connect to the unix domain socket. */
		ਜੇ (ਲੜੀ_ਤੋਂ_ਪੜ੍ਹੋ(strrchr(display, ':') + 1, "%u",
		    &display_ਸੰਖਿਆ) != 1) {
			error("Could not parse display number from DISPLAY: "
			    "%.100s", display);
			ਵਾਪਸ -1;
		}
		/* Create a socket. */
		sock = connect_local_xsocket(display_ਸੰਖਿਆ);
		ਜੇ (sock < 0)
			ਵਾਪਸ -1;

		/* OK, we now have a connection to the display. */
		ਵਾਪਸ sock;
	}
	/*
	 * Connect to an inet socket.  The DISPLAY value is supposedly
	 * hostname:d[.s], where hostname may also be numeric IP address.
	 */
	strlcpy(buf, display, ਆਕਾਰ(buf));
	cp = strchr(buf, ':');
	ਜੇ (!cp) {
		error("Could not find ':' in DISPLAY: %.100s", display);
		ਵਾਪਸ -1;
	}
	*cp = 0;
	/*
	 * buf now contains the host name.  But first we parse the
	 * display number.
	 */
	ਜੇ (ਲੜੀ_ਤੋਂ_ਪੜ੍ਹੋ(cp + 1, "%u", &display_ਸੰਖਿਆ) != 1 ||
	    display_ਸੰਖਿਆ > UINT16_MAX - X11_ਅਧਾਰ_ਪੋਰਟ) {
		error("Could not parse display number from DISPLAY: %.100s",
		    display);
		ਵਾਪਸ -1;
	}

	/* Look up the host address */
	memset(&hints, 0, ਆਕਾਰ(hints));
	hints.ai_family = ssh->chanctxt->IPv4or6;
	hints.ai_socktype = SOCK_STREAM;
	snprintf(strport, ਆਕਾਰ strport, "%u", X11_ਅਧਾਰ_ਪੋਰਟ + display_ਸੰਖਿਆ);
	ਜੇ ((gaierr = getaddrinfo(buf, strport, &hints, &aitop)) != 0) {
		error("%.100s: unknown host. (%s)", buf,
		ssh_gai_strerror(gaierr));
		ਵਾਪਸ -1;
	}
	ਲਈ (ai = aitop; ai; ai = ai->ai_next) {
		/* Create a socket. */
		sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		ਜੇ (sock == -1) {
			debug2("socket: %.100s", strerror(errno));
			ਜਾਰੀ;
		}
		/* Connect it to the display. */
		ਜੇ (connect(sock, ai->ai_addr, ai->ai_addrlen) == -1) {
			debug2("connect %.100s port %u: %.100s", buf,
			    X11_ਅਧਾਰ_ਪੋਰਟ + display_ਸੰਖਿਆ, strerror(errno));
			close(sock);
			ਜਾਰੀ;
		}
		/* Success */
		ਰੋਕੋ;
	}
	freeaddrinfo(aitop);
	ਜੇ (!ai) {
		error("connect %.100s port %u: %.100s", buf,
		    X11_ਅਧਾਰ_ਪੋਰਟ + display_ਸੰਖਿਆ, strerror(errno));
		ਵਾਪਸ -1;
	}
	ਸੈੱਟ_nodelay(sock);
	ਵਾਪਸ sock;
}

/*
 * Requests forwarding of X11 connections, generates fake authentication
 * data, and enables authentication spoofing.
 * This should be called in the client only.
 */
ਖਾਲੀ
x11_request_forwarding_with_spoofing(ਬਣਤਰ ssh *ssh, ਪੂਰਨ client_session_id,
    ਅਚਲ ਅੱਖਰ *disp, ਅਚਲ ਅੱਖਰ *proto, ਅਚਲ ਅੱਖਰ *ਅੰਕੜੇ, ਪੂਰਨ want_ਜਵਾਬ)
{
	ਬਣਤਰ ssh_channels *sc = ssh->chanctxt;
	u_int ਅੰਕੜੇ_len = (u_int) ਲੜੀ_ਲੰਬਾਈ(ਅੰਕੜੇ) / 2;
	u_int i, ਮੁੱਲ;
	ਅਚਲ ਅੱਖਰ *cp;
	ਅੱਖਰ *new_ਅੰਕੜੇ;
	ਪੂਰਨ r, screen_ਸੰਖਿਆ;

	ਜੇ (sc->x11_saved_display == ਨਿਰਾ)
		sc->x11_saved_display = xstrdup(disp);
	ਨਹੀਂਤਾਂ ਜੇ (strcmp(disp, sc->x11_saved_display) != 0) {
		error("x11_request_forwarding_with_spoofing: different "
		    "$DISPLAY already forwarded");
		ਵਾਪਸ;
	}

	cp = strchr(disp, ':');
	ਜੇ (cp)
		cp = strchr(cp, '.');
	ਜੇ (cp)
		screen_ਸੰਖਿਆ = (u_int)strtonum(cp + 1, 0, 400, ਨਿਰਾ);
	ਨਹੀਂਤਾਂ
		screen_ਸੰਖਿਆ = 0;

	ਜੇ (sc->x11_saved_proto == ਨਿਰਾ) {
		/* Save protocol name. */
		sc->x11_saved_proto = xstrdup(proto);

		/* Extract real authentication data. */
		sc->x11_saved_ਅੰਕੜੇ = xmalloc(ਅੰਕੜੇ_len);
		ਲਈ (i = 0; i < ਅੰਕੜੇ_len; i++) {
			ਜੇ (ਲੜੀ_ਤੋਂ_ਪੜ੍ਹੋ(ਅੰਕੜੇ + 2 * i, "%2x", &ਮੁੱਲ) != 1) {
				fatal("x11_request_forwarding: bad "
				    "authentication data: %.100s", ਅੰਕੜੇ);
			}
			sc->x11_saved_ਅੰਕੜੇ[i] = ਮੁੱਲ;
		}
		sc->x11_saved_ਅੰਕੜੇ_len = ਅੰਕੜੇ_len;

		/* Generate fake data of the same length. */
		sc->x11_fake_ਅੰਕੜੇ = xmalloc(ਅੰਕੜੇ_len);
		arc4random_buf(sc->x11_fake_ਅੰਕੜੇ, ਅੰਕੜੇ_len);
		sc->x11_fake_ਅੰਕੜੇ_len = ਅੰਕੜੇ_len;
	}

	/* Convert the fake data into hex. */
	new_ਅੰਕੜੇ = tohex(sc->x11_fake_ਅੰਕੜੇ, ਅੰਕੜੇ_len);

	/* Send the request packet. */
	channel_request_ਸ਼ੁਰੂ(ssh, client_session_id, "x11-req", want_ਜਵਾਬ);
	ਜੇ ((r = sshpkt_put_u8(ssh, 0)) != 0 || /* bool: single connection */
	    (r = sshpkt_put_cstring(ssh, proto)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, new_ਅੰਕੜੇ)) != 0 ||
	    (r = sshpkt_put_u32(ssh, screen_ਸੰਖਿਆ)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send x11-req");
	ਮੁਕਤ(new_ਅੰਕੜੇ);
}

/*
 * Returns whether an x11 channel was used recently (less than a second ago)
 */
ਪੂਰਨ
x11_channel_ਵਰਤਿਆ_recently(ਬਣਤਰ ssh *ssh) {
	u_int i;
	Channel *c;
	ਦੁੱਗਣਾ lastused = 0;

	ਲਈ (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		ਜੇ (c == ਨਿਰਾ || c->ctype == ਨਿਰਾ || c->lastused == 0.0 ||
		    strcmp(c->ctype, "x11-connection") != 0)
			ਜਾਰੀ;
		ਜੇ (c->lastused > lastused)
			lastused = c->lastused;
	}
	ਵਾਪਸ lastused != 0.0 && monotime_double() <= lastused + 1.0;
}
