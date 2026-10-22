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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/stat.h>
#அந்தர்பாவ <sys/ioctl.h>
#அந்தர்பாவ <sys/un.h>
#அந்தர்பாவ <sys/socket.h>
#அந்தர்பாவ <sys/queue.h>

#அந்தர்பாவ <netinet/in.h>
#அந்தர்பாவ <arpa/inet.h>

#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <fcntl.h>
#அந்தர்பாவ <limits.h>
#அந்தர்பாவ <netdb.h>
#அந்தர்பாவ <poll.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <stdint.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <termios.h>
#அந்தர்பாவ <unistd.h>

#அந்தர்பாவ "xmalloc.h"
#அந்தர்பாவ "ssh.h"
#அந்தர்பாவ "ssh2.h"
#அந்தர்பாவ "ssherr.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "packet.h"
#அந்தர்பாவ "log.h"
#அந்தர்பாவ "misc.h"
#அந்தர்பாவ "channels.h"
#அந்தர்பாவ "compat.h"
#அந்தர்பாவ "canohost.h"
#அந்தர்பாவ "pathnames.h"
#அந்தர்பாவ "match.h"

/* XXX remove once we're satisfied there's no lurking bugs */
/* #define DEBUG_CHANNEL_POLL 1 */

/* -- agent forwarding */
#define	இலக்கம்_SOCKS	10

/* -- X11 forwarding */
/* X11 port for display :0 */
#define X11_BASE_PORT	6000
/* Maximum number of fake X11 displays to try. */
#define MAX_DISPLAYS  1000

/* Per-channel callback for pre/post IO actions */
வகைவரை வெறுமை chan_fn(கட்டமைப்பு ssh *, Channel *c);

/*
 * Data structure for storing which hosts are permitted for forward requests.
 * The local sides of any remote forwards are stored in this array to prevent
 * a corrupt remote server from accessing arbitrary TCP/IP ports on our local
 * network (which might be behind a firewall).
 */
/* XXX: streamlocal wants a path instead of host:port */
/*      Overload host_to_connect; we could just make this match Forward */
/*	XXX - can we use listen_host instead of listen_path? */
கட்டமைப்பு permission {
	எழுத்து *host_to_connect;		/* Connect to 'host'. */
	முழு port_to_connect;		/* Connect to 'port'. */
	எழுத்து *listen_host;		/* Remote side should listen address. */
	எழுத்து *listen_path;		/* Remote side should listen path. */
	முழு listen_port;		/* Remote side should listen port. */
	Channel *downstream;		/* Downstream mux*/
};

/* Context for non-blocking connects */
கட்டமைப்பு channel_connect {
	எழுத்து *host;
	முழு port;
	கட்டமைப்பு addrinfo *ai, *aitop;
};

/*
 * Stores the forwarding permission state for a single direction (local or
 * remote).
 */
கட்டமைப்பு permission_set {
	/*
	 * List of all local permitted host/port pairs to allow for the
	 * user.
	 */
	u_int இலக்கம்_permitted_user;
	கட்டமைப்பு permission *permitted_user;

	/*
	 * List of all permitted host/port pairs to allow for the admin.
	 */
	u_int இலக்கம்_permitted_admin;
	கட்டமைப்பு permission *permitted_admin;

	/*
	 * If this is true, all opens/listens are permitted.  This is the
	 * case on the server on which we have to trust the client anyway,
	 * and the user could do anything after logging in.
	 */
	முழு all_permitted;
};

/* Used to record timeouts per channel type */
கட்டமைப்பு ssh_channel_timeout {
	எழுத்து *type_pattern;
	இரட்டை timeout_secs;
};

/* Master structure for channels state */
கட்டமைப்பு ssh_channels {
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
	கட்டமைப்பு permission_set local_perms;
	கட்டமைப்பு permission_set remote_perms;

	/* -- X11 forwarding */

	/* Saved X11 local (client) display. */
	எழுத்து *x11_saved_display;

	/* Saved X11 authentication protocol name. */
	எழுத்து *x11_saved_proto;

	/* Saved X11 authentication data.  This is the real data. */
	எழுத்து *x11_saved_data;
	u_int x11_saved_data_len;

	/* Deadline after which all X11 connections are refused */
	இரட்டை x11_refuse_time;

	/*
	 * Fake X11 authentication data.  This is what the server will be
	 * sending us; we should replace any occurrences of this by the
	 * real data.
	 */
	u_char *x11_fake_data;
	u_int x11_fake_data_len;

	/* AF_UNSPEC or AF_INET or AF_INET6 */
	முழு IPv4or6;

	/* Set SO_KEEPALIVE on TCP connections */
	முழு want_tcp_keepalive;

	/* Channel timeouts by type */
	கட்டமைப்பு ssh_channel_timeout *timeouts;
	size_t ntimeouts;
	/* Global timeout for all OPEN channels */
	இரட்டை global_deadline;
	இரட்டை lastused;
	/* pattern-lists used to classify channels as bulk */
	எழுத்து *bulk_classifier_tty, *bulk_classifier_notty;
	/* Number of active bulk channels (set by channel_handler) */
	u_int nbulk;
};

/* helper */
நிலையான வெறுமை port_open_helper(கட்டமைப்பு ssh *ssh, Channel *c, எழுத்து *rtype);
நிலையான மாறிலி எழுத்து *channel_rfwd_bind_host(மாறிலி எழுத்து *listen_host);

/* non-blocking connect helpers */
நிலையான முழு connect_next(கட்டமைப்பு ssh *, கட்டமைப்பு channel_connect *);
நிலையான Channel *rdynamic_connect_prepare(கட்டமைப்பு ssh *, எழுத்து *, எழுத்து *);
நிலையான முழு rdynamic_connect_finish(கட்டமைப்பு ssh *, Channel *);

/* Setup helper */
நிலையான வெறுமை channel_handler_init(கட்டமைப்பு ssh_channels *sc);

/* -- channel core */

வெறுமை
channel_init_channels(கட்டமைப்பு ssh *ssh)
{
	கட்டமைப்பு ssh_channels *sc;

	எனில் ((sc = calloc(1, அளவு(*sc))) == வெற்று)
		fatal_f("allocation failed");
	sc->channels_alloc = 10;
	sc->channels = xcalloc(sc->channels_alloc, அளவு(*sc->channels));
	sc->IPv4or6 = AF_UNSPEC;
	sc->bulk_classifier_tty = xstrdup(CHANNEL_BULK_TTY);
	sc->bulk_classifier_notty = xstrdup(CHANNEL_BULK_NOTTY);
	channel_handler_init(sc);

	ssh->chanctxt = sc;
}

Channel *
channel_by_id(கட்டமைப்பு ssh *ssh, முழு id)
{
	Channel *c;

	எனில் (id < 0 || (u_int)id >= ssh->chanctxt->channels_alloc) {
		logit_f("%d: bad id", id);
		திரும்பு வெற்று;
	}
	c = ssh->chanctxt->channels[id];
	எனில் (c == வெற்று) {
		logit_f("%d: bad id: channel free", id);
		திரும்பு வெற்று;
	}
	திரும்பு c;
}

Channel *
channel_by_remote_id(கட்டமைப்பு ssh *ssh, u_int remote_id)
{
	Channel *c;
	u_int i;

	க்கு (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		எனில் (c != வெற்று && c->have_remote_id && c->remote_id == remote_id)
			திரும்பு c;
	}
	திரும்பு வெற்று;
}

/*
 * Returns the channel if it is allowed to receive protocol messages.
 * Private channels, like listening sockets, may not receive messages.
 */
Channel *
channel_lookup(கட்டமைப்பு ssh *ssh, முழு id)
{
	Channel *c;

	எனில் ((c = channel_by_id(ssh, id)) == வெற்று)
		திரும்பு வெற்று;

	தேர்வு (c->type) {
	நிலை SSH_CHANNEL_X11_OPEN:
	நிலை SSH_CHANNEL_LARVAL:
	நிலை SSH_CHANNEL_CONNECTING:
	நிலை SSH_CHANNEL_DYNAMIC:
	நிலை SSH_CHANNEL_RDYNAMIC_OPEN:
	நிலை SSH_CHANNEL_RDYNAMIC_FINISH:
	நிலை SSH_CHANNEL_OPENING:
	நிலை SSH_CHANNEL_OPEN:
	நிலை SSH_CHANNEL_ABANDONED:
	நிலை SSH_CHANNEL_MUX_PROXY:
		திரும்பு c;
	}
	logit("Non-public channel %d, type %d.", id, c->type);
	திரும்பு வெற்று;
}

நிலையான வெறுமை
free_connect_ctx(கட்டமைப்பு channel_connect *cctx)
{
	விடுவி(cctx->host);
	எனில் (cctx->aitop) {
		எனில் (cctx->aitop->ai_family == AF_UNIX)
			விடுவி(cctx->aitop);
		இல்லையெனில்
			freeaddrinfo(cctx->aitop);
	}
	memset(cctx, 0, அளவு(*cctx));
}

நிலையான வெறுமை
channel_free_connect_ctx(Channel *c)
{
	எனில் (c == வெற்று || c->connect_ctx == வெற்று)
		திரும்பு;
	free_connect_ctx(c->connect_ctx);
	விடுவி(c->connect_ctx);
	c->connect_ctx = வெற்று;
}

/* Enable/disable TCP keepalives for X11 and port-forwarding sockets */
வெறுமை
channel_set_tcp_keepalives(கட்டமைப்பு ssh *ssh, முழு on)
{
	ssh->chanctxt->want_tcp_keepalive = on;
}

/*
 * Add a timeout for open channels whose c->ctype (or c->xctype if it is set)
 * match type_pattern.
 */
வெறுமை
channel_add_timeout(கட்டமைப்பு ssh *ssh, மாறிலி எழுத்து *type_pattern,
    இரட்டை timeout_secs)
{
	கட்டமைப்பு ssh_channels *sc = ssh->chanctxt;

	எனில் (strcmp(type_pattern, "global") == 0) {
		debug2_f("global channel timeout %f seconds", timeout_secs);
		sc->global_deadline = timeout_secs;
		திரும்பு;
	}
	debug2_f("channel type \"%s\" timeout %f seconds",
	    type_pattern, timeout_secs);
	sc->timeouts = xrecallocarray(sc->timeouts, sc->ntimeouts,
	    sc->ntimeouts + 1, அளவு(*sc->timeouts));
	sc->timeouts[sc->ntimeouts].type_pattern = xstrdup(type_pattern);
	sc->timeouts[sc->ntimeouts].timeout_secs = timeout_secs;
	sc->ntimeouts++;
}

/* Clears all previously-added channel timeouts */
வெறுமை
channel_clear_timeouts(கட்டமைப்பு ssh *ssh)
{
	கட்டமைப்பு ssh_channels *sc = ssh->chanctxt;
	size_t i;

	debug3_f("clearing");
	க்கு (i = 0; i < sc->ntimeouts; i++)
		விடுவி(sc->timeouts[i].type_pattern);
	விடுவி(sc->timeouts);
	sc->timeouts = வெற்று;
	sc->ntimeouts = 0;
}

நிலையான இரட்டை
lookup_timeout(கட்டமைப்பு ssh *ssh, மாறிலி எழுத்து *type)
{
	கட்டமைப்பு ssh_channels *sc = ssh->chanctxt;
	size_t i;

	க்கு (i = 0; i < sc->ntimeouts; i++) {
		எனில் (match_pattern(type, sc->timeouts[i].type_pattern))
			திரும்பு sc->timeouts[i].timeout_secs;
	}

	திரும்பு 0;
}

நிலையான வெறுமை
channel_classify(கட்டமைப்பு ssh *ssh, Channel *c)
{
	கட்டமைப்பு ssh_channels *sc = ssh->chanctxt;
	மாறிலி எழுத்து *type = c->xctype == வெற்று ? c->ctype : c->xctype;
	மாறிலி முழு has_tty = c->isatty || c->remote_has_tty;
	மாறிலி எழுத்து *classifier = has_tty ?
	    sc->bulk_classifier_tty : sc->bulk_classifier_notty;

	c->bulk = type != வெற்று && match_pattern_list(type, classifier, 0) == 1;
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
வெறுமை
channel_set_xtype(கட்டமைப்பு ssh *ssh, முழு id, மாறிலி எழுத்து *xctype)
{
	கட்டமைப்பு ssh_channels *sc = ssh->chanctxt;
	Channel *c;

	எனில் ((c = channel_by_id(ssh, id)) == வெற்று)
		fatal_f("missing channel %d", id);
	எனில் (c->xctype != வெற்று)
		விடுவி(c->xctype);
	c->xctype = xstrdup(xctype);
	/* Only override deadline if xctype has a more specific match. */
	இரட்டை xtype_deadline = lookup_timeout(ssh, c->xctype);
	எனில் (xtype_deadline != 0)
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
நிலையான வெறுமை
channel_set_used_time(கட்டமைப்பு ssh *ssh, Channel *c)
{
	ssh->chanctxt->lastused = monotime_double();
	எனில் (c != வெற்று)
		c->lastused = ssh->chanctxt->lastused;
}

/*
 * Get the time at which a channel is due to time out for inactivity.
 * Returns 0 if the channel is not due to time out ever.
 */
நிலையான இரட்டை
channel_get_expiry(கட்டமைப்பு ssh *ssh, Channel *c)
{
	கட்டமைப்பு ssh_channels *sc = ssh->chanctxt;
	இரட்டை expiry = 0, channel_expiry;

	எனில் (sc->lastused != 0 && sc->global_deadline != 0)
		expiry = sc->lastused + sc->global_deadline;
	எனில் (c->lastused != 0 && c->inactive_deadline != 0) {
		channel_expiry = c->lastused + c->inactive_deadline;
		எனில் (expiry == 0 || channel_expiry < expiry)
			expiry = channel_expiry;
	}
	திரும்பு expiry;
}

/* Returns non-zero if there is an open, non-interactive channel */
முழு
channel_has_bulk(கட்டமைப்பு ssh *ssh)
{
	திரும்பு ssh->chanctxt != வெற்று && ssh->chanctxt->nbulk != 0;
}

/*
 * Register filedescriptors for a channel, used when allocating a channel or
 * when the channel consumer/producer is ready, e.g. shell exec'd
 */
நிலையான வெறுமை
channel_register_fds(கட்டமைப்பு ssh *ssh, Channel *c, முழு rfd, முழு wfd, முழு efd,
    முழு extusage, முழு nonblock, முழு is_tty)
{
	முழு val;

	எனில் (rfd != -1)
		(வெறுமை)fcntl(rfd, F_SETFD, FD_CLOEXEC);
	எனில் (wfd != -1 && wfd != rfd)
		(வெறுமை)fcntl(wfd, F_SETFD, FD_CLOEXEC);
	எனில் (efd != -1 && efd != rfd && efd != wfd)
		(வெறுமை)fcntl(efd, F_SETFD, FD_CLOEXEC);

	c->rfd = rfd;
	c->wfd = wfd;
	c->sock = (rfd == wfd) ? rfd : -1;
	c->efd = efd;
	c->extended_usage = extusage;

	எனில் ((c->isatty = is_tty) != 0)
		debug2("channel %d: rfd %d isatty", c->self, c->rfd);
#ifdef _AIX
	/* XXX: Later AIX versions can't push as much data to tty */
	c->wfd_isatty = is_tty || isatty(c->wfd);
#endif

	/* enable nonblocking mode */
	c->restore_block = 0;
	எனில் (nonblock == CHANNEL_NONBLOCK_STDIO) {
		/*
		 * Special handling for stdio file descriptors: do not set
		 * non-blocking mode if they are TTYs. Otherwise prepare to
		 * restore their blocking state on exit to avoid interfering
		 * with other programs that follow.
		 */
		எனில் (rfd != -1 && !isatty(rfd) &&
		    (val = fcntl(rfd, F_GETFL)) != -1 && !(val & O_NONBLOCK)) {
			c->restore_flags[0] = val;
			c->restore_block |= CHANNEL_RESTORE_RFD;
			set_nonblock(rfd);
		}
		எனில் (wfd != -1 && !isatty(wfd) &&
		    (val = fcntl(wfd, F_GETFL)) != -1 && !(val & O_NONBLOCK)) {
			c->restore_flags[1] = val;
			c->restore_block |= CHANNEL_RESTORE_WFD;
			set_nonblock(wfd);
		}
		எனில் (efd != -1 && !isatty(efd) &&
		    (val = fcntl(efd, F_GETFL)) != -1 && !(val & O_NONBLOCK)) {
			c->restore_flags[2] = val;
			c->restore_block |= CHANNEL_RESTORE_EFD;
			set_nonblock(efd);
		}
	} இல்லையெனில் எனில் (nonblock) {
		எனில் (rfd != -1)
			set_nonblock(rfd);
		எனில் (wfd != -1)
			set_nonblock(wfd);
		எனில் (efd != -1)
			set_nonblock(efd);
	}
	/* channel might be entering a larval state, so reset global timeout */
	channel_set_used_time(ssh, வெற்று);
	channel_classify(ssh, c);
}

/*
 * Allocate a new channel object and set its type and socket.
 */
Channel *
channel_new(கட்டமைப்பு ssh *ssh, எழுத்து *ctype, முழு type, முழு rfd, முழு wfd, முழு efd,
    u_int window, u_int maxpack, முழு extusage, மாறிலி எழுத்து *remote_name,
    முழு nonblock)
{
	கட்டமைப்பு ssh_channels *sc = ssh->chanctxt;
	u_int i, found = 0;
	Channel *c;
	முழு r;

	/* Try to find a free slot where to put the new channel. */
	க்கு (i = 0; i < sc->channels_alloc; i++) {
		எனில் (sc->channels[i] == வெற்று) {
			/* Found a free slot. */
			found = i;
			நிறுத்து;
		}
	}
	எனில் (i >= sc->channels_alloc) {
		/*
		 * There are no free slots. Take last+1 slot and expand
		 * the array.
		 */
		found = sc->channels_alloc;
		எனில் (sc->channels_alloc > CHANNELS_MAX_CHANNELS)
			fatal_f("internal error: channels_alloc %d too big",
			    sc->channels_alloc);
		sc->channels = xrecallocarray(sc->channels, sc->channels_alloc,
		    sc->channels_alloc + 10, அளவு(*sc->channels));
		sc->channels_alloc += 10;
		debug2("channel: expanding %d", sc->channels_alloc);
	}
	/* Initialize and return new channel. */
	c = sc->channels[found] = xcalloc(1, அளவு(Channel));
	எனில் ((c->உள்ளீடு = sshbuf_new()) == வெற்று ||
	    (c->output = sshbuf_new()) == வெற்று ||
	    (c->extended = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	எனில் ((r = sshbuf_set_max_size(c->உள்ளீடு, CHAN_உள்ளீடு_MAX)) != 0)
		fatal_fr(r, "sshbuf_set_max_size");
	c->ostate = CHAN_OUTPUT_OPEN;
	c->istate = CHAN_உள்ளீடு_OPEN;
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
	திரும்பு c;
}

வெறுமை
channel_set_tty(கட்டமைப்பு ssh *ssh, Channel *c)
{
	c->remote_has_tty = 1;
	channel_classify(ssh, c);
}

முழு
channel_close_fd(கட்டமைப்பு ssh *ssh, Channel *c, முழு *fdp)
{
	முழு ret, fd = *fdp;

	எனில் (fd == -1)
		திரும்பு 0;

	/* restore blocking */
	எனில் (*fdp == c->rfd &&
	    (c->restore_block & CHANNEL_RESTORE_RFD) != 0)
		(வெறுமை)fcntl(*fdp, F_SETFL, c->restore_flags[0]);
	இல்லையெனில் எனில் (*fdp == c->wfd &&
	    (c->restore_block & CHANNEL_RESTORE_WFD) != 0)
		(வெறுமை)fcntl(*fdp, F_SETFL, c->restore_flags[1]);
	இல்லையெனில் எனில் (*fdp == c->efd &&
	    (c->restore_block & CHANNEL_RESTORE_EFD) != 0)
		(வெறுமை)fcntl(*fdp, F_SETFL, c->restore_flags[2]);

	எனில் (*fdp == c->rfd) {
		c->io_want &= ~SSH_CHAN_IO_RFD;
		c->io_ready &= ~SSH_CHAN_IO_RFD;
		c->rfd = -1;
		c->pfds[0] = -1;
	}
	எனில் (*fdp == c->wfd) {
		c->io_want &= ~SSH_CHAN_IO_WFD;
		c->io_ready &= ~SSH_CHAN_IO_WFD;
		c->wfd = -1;
		c->pfds[1] = -1;
	}
	எனில் (*fdp == c->efd) {
		c->io_want &= ~SSH_CHAN_IO_EFD;
		c->io_ready &= ~SSH_CHAN_IO_EFD;
		c->efd = -1;
		c->pfds[2] = -1;
	}
	எனில் (*fdp == c->sock) {
		c->io_want &= ~SSH_CHAN_IO_SOCK;
		c->io_ready &= ~SSH_CHAN_IO_SOCK;
		c->sock = -1;
		c->pfds[3] = -1;
	}

	ret = close(fd);
	*fdp = -1; /* probably redundant */
	திரும்பு ret;
}

/* Close all channel fd/socket. */
நிலையான வெறுமை
channel_close_fds(கட்டமைப்பு ssh *ssh, Channel *c)
{
	முழு sock = c->sock, rfd = c->rfd, wfd = c->wfd, efd = c->efd;

	channel_close_fd(ssh, c, &c->sock);
	எனில் (rfd != sock)
		channel_close_fd(ssh, c, &c->rfd);
	எனில் (wfd != sock && wfd != rfd)
		channel_close_fd(ssh, c, &c->wfd);
	எனில் (efd != sock && efd != rfd && efd != wfd)
		channel_close_fd(ssh, c, &c->efd);
}

நிலையான வெறுமை
fwd_perm_clear(கட்டமைப்பு permission *perm)
{
	விடுவி(perm->host_to_connect);
	விடுவி(perm->listen_host);
	விடுவி(perm->listen_path);
	memset(perm, 0, அளவு(*perm));
}

/* Returns an printable name for the specified forwarding permission list */
நிலையான மாறிலி எழுத்து *
fwd_ident(முழு who, முழு where)
{
	எனில் (who == FORWARD_ADM) {
		எனில் (where == FORWARD_LOCAL)
			திரும்பு "admin local";
		இல்லையெனில் எனில் (where == FORWARD_REMOTE)
			திரும்பு "admin remote";
	} இல்லையெனில் எனில் (who == FORWARD_USER) {
		எனில் (where == FORWARD_LOCAL)
			திரும்பு "user local";
		இல்லையெனில் எனில் (where == FORWARD_REMOTE)
			திரும்பு "user remote";
	}
	fatal("Unknown forward permission list %d/%d", who, where);
}

/* Returns the forwarding permission list for the specified direction */
நிலையான கட்டமைப்பு permission_set *
permission_set_get(கட்டமைப்பு ssh *ssh, முழு where)
{
	கட்டமைப்பு ssh_channels *sc = ssh->chanctxt;

	தேர்வு (where) {
	நிலை FORWARD_LOCAL:
		திரும்பு &sc->local_perms;
		நிறுத்து;
	நிலை FORWARD_REMOTE:
		திரும்பு &sc->remote_perms;
		நிறுத்து;
	இயல்பு:
		fatal_f("invalid forwarding direction %d", where);
	}
}

/* Returns pointers to the specified forwarding list and its element count */
நிலையான வெறுமை
permission_set_get_array(கட்டமைப்பு ssh *ssh, முழு who, முழு where,
    கட்டமைப்பு permission ***permpp, u_int **npermpp)
{
	கட்டமைப்பு permission_set *pset = permission_set_get(ssh, where);

	தேர்வு (who) {
	நிலை FORWARD_USER:
		*permpp = &pset->permitted_user;
		*npermpp = &pset->இலக்கம்_permitted_user;
		நிறுத்து;
	நிலை FORWARD_ADM:
		*permpp = &pset->permitted_admin;
		*npermpp = &pset->இலக்கம்_permitted_admin;
		நிறுத்து;
	இயல்பு:
		fatal_f("invalid forwarding client %d", who);
	}
}

/* Adds an entry to the specified forwarding list */
நிலையான முழு
permission_set_add(கட்டமைப்பு ssh *ssh, முழு who, முழு where,
    மாறிலி எழுத்து *host_to_connect, முழு port_to_connect,
    மாறிலி எழுத்து *listen_host, மாறிலி எழுத்து *listen_path, முழு listen_port,
    Channel *downstream)
{
	கட்டமைப்பு permission **permp;
	u_int n, *npermp;

	permission_set_get_array(ssh, who, where, &permp, &npermp);

	எனில் (*npermp >= INT_MAX)
		fatal_f("%s overflow", fwd_ident(who, where));

	*permp = xrecallocarray(*permp, *npermp, *npermp + 1, அளவு(**permp));
	n = (*npermp)++;
#define MAYBE_DUP(s) ((s == வெற்று) ? வெற்று : xstrdup(s))
	(*permp)[n].host_to_connect = MAYBE_DUP(host_to_connect);
	(*permp)[n].port_to_connect = port_to_connect;
	(*permp)[n].listen_host = MAYBE_DUP(listen_host);
	(*permp)[n].listen_path = MAYBE_DUP(listen_path);
	(*permp)[n].listen_port = listen_port;
	(*permp)[n].downstream = downstream;
#undef MAYBE_DUP
	திரும்பு (முழு)n;
}

நிலையான வெறுமை
mux_remove_remote_forwardings(கட்டமைப்பு ssh *ssh, Channel *c)
{
	கட்டமைப்பு ssh_channels *sc = ssh->chanctxt;
	கட்டமைப்பு permission_set *pset = &sc->local_perms;
	கட்டமைப்பு permission *perm;
	முழு r;
	u_int i;

	க்கு (i = 0; i < pset->இலக்கம்_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		எனில் (perm->downstream != c)
			தொடர்;

		/* cancel on the server, since mux client is gone */
		debug("channel %d: cleanup remote forward for %s:%u",
		    c->self, perm->listen_host, perm->listen_port);
		எனில் ((r = sshpkt_start(ssh, SSH2_செய்தி_GLOBAL_REQUEST)) != 0 ||
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
வெறுமை
channel_free(கட்டமைப்பு ssh *ssh, Channel *c)
{
	கட்டமைப்பு ssh_channels *sc = ssh->chanctxt;
	எழுத்து *s;
	u_int i, n;
	Channel *other;
	கட்டமைப்பு channel_confirm *cc;

	க்கு (n = 0, i = 0; i < sc->channels_alloc; i++) {
		எனில் ((other = sc->channels[i]) == வெற்று)
			தொடர்;
		n++;
		/* detach from mux client and prepare for closing */
		எனில் (c->type == SSH_CHANNEL_MUX_CLIENT &&
		    other->type == SSH_CHANNEL_MUX_PROXY &&
		    other->mux_ctx == c) {
			other->mux_ctx = வெற்று;
			other->type = SSH_CHANNEL_OPEN;
			other->istate = CHAN_உள்ளீடு_CLOSED;
			other->ostate = CHAN_OUTPUT_CLOSED;
		}
	}
	debug("channel %d: free: %s, nchannels %u", c->self,
	    c->remote_name ? c->remote_name : "???", n);

	எனில் (c->type == SSH_CHANNEL_MUX_CLIENT) {
		mux_remove_remote_forwardings(ssh, c);
		விடுவி(c->mux_ctx);
		c->mux_ctx = வெற்று;
	} இல்லையெனில் எனில் (c->type == SSH_CHANNEL_MUX_LISTENER) {
		விடுவி(c->mux_ctx);
		c->mux_ctx = வெற்று;
	}

	எனில் (log_level_get() >= SYSLOG_LEVEL_DEBUG3) {
		s = channel_open_message(ssh);
		debug3("channel %d: status: %s", c->self, s);
		விடுவி(s);
	}

	channel_close_fds(ssh, c);
	sshbuf_free(c->உள்ளீடு);
	sshbuf_free(c->output);
	sshbuf_free(c->extended);
	c->உள்ளீடு = c->output = c->extended = வெற்று;
	விடுவி(c->remote_name);
	c->remote_name = வெற்று;
	விடுவி(c->path);
	c->path = வெற்று;
	விடுவி(c->listening_addr);
	c->listening_addr = வெற்று;
	விடுவி(c->xctype);
	c->xctype = வெற்று;
	channel_free_connect_ctx(c);
	போது ((cc = TAILQ_FIRST(&c->status_confirms)) != வெற்று) {
		எனில் (cc->abandon_cb != வெற்று)
			cc->abandon_cb(ssh, c, cc->ctx);
		TAILQ_REMOVE(&c->status_confirms, cc, entry);
		freezero(cc, அளவு(*cc));
	}
	எனில் (c->filter_cleanup != வெற்று && c->filter_ctx != வெற்று)
		c->filter_cleanup(ssh, c->self, c->filter_ctx);
	sc->channels[c->self] = வெற்று;
	freezero(c, அளவு(*c));
}

வெறுமை
channel_free_all(கட்டமைப்பு ssh *ssh)
{
	u_int i;
	கட்டமைப்பு ssh_channels *sc = ssh->chanctxt;

	க்கு (i = 0; i < sc->channels_alloc; i++)
		எனில் (sc->channels[i] != வெற்று)
			channel_free(ssh, sc->channels[i]);

	விடுவி(sc->channels);
	sc->channels = வெற்று;
	sc->channels_alloc = 0;

	விடுவி(sc->x11_saved_display);
	sc->x11_saved_display = வெற்று;

	விடுவி(sc->x11_saved_proto);
	sc->x11_saved_proto = வெற்று;

	விடுவி(sc->x11_saved_data);
	sc->x11_saved_data = வெற்று;
	sc->x11_saved_data_len = 0;

	விடுவி(sc->x11_fake_data);
	sc->x11_fake_data = வெற்று;
	sc->x11_fake_data_len = 0;
}

வெறுமை
channel_free_channels(கட்டமைப்பு ssh *ssh)
{
	கட்டமைப்பு ssh_channels *sc;

	எனில் (ssh == வெற்று || ssh->chanctxt == வெற்று)
		திரும்பு;
	channel_free_all(ssh);
	channel_clear_permission(ssh, FORWARD_USER, FORWARD_LOCAL);
	channel_clear_permission(ssh, FORWARD_USER, FORWARD_REMOTE);
	channel_clear_permission(ssh, FORWARD_ADM, FORWARD_LOCAL);
	channel_clear_permission(ssh, FORWARD_ADM, FORWARD_REMOTE);
	sc = ssh->chanctxt;
	விடுவி(sc->bulk_classifier_tty);
	விடுவி(sc->bulk_classifier_notty);
	விடுவி(sc->channel_pre);
	விடுவி(sc->channel_post);
	freezero(sc, அளவு(*sc));
	ssh->chanctxt = வெற்று;
}

/*
 * Closes the sockets/fds of all channels.  This is used to close extra file
 * descriptors after a fork.
 */
வெறுமை
channel_close_all(கட்டமைப்பு ssh *ssh)
{
	u_int i;

	க்கு (i = 0; i < ssh->chanctxt->channels_alloc; i++)
		எனில் (ssh->chanctxt->channels[i] != வெற்று)
			channel_close_fds(ssh, ssh->chanctxt->channels[i]);
}

/*
 * Stop listening to channels.
 */
வெறுமை
channel_stop_listening(கட்டமைப்பு ssh *ssh)
{
	u_int i;
	Channel *c;

	க்கு (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		எனில் (c != வெற்று) {
			தேர்வு (c->type) {
			நிலை SSH_CHANNEL_AUTH_SOCKET:
			நிலை SSH_CHANNEL_PORT_LISTENER:
			நிலை SSH_CHANNEL_RPORT_LISTENER:
			நிலை SSH_CHANNEL_X11_LISTENER:
			நிலை SSH_CHANNEL_UNIX_LISTENER:
			நிலை SSH_CHANNEL_RUNIX_LISTENER:
				channel_close_fd(ssh, c, &c->sock);
				channel_free(ssh, c);
				நிறுத்து;
			}
		}
	}
}

/*
 * Returns true if no channel has too much buffered data, and false if one or
 * more channel is overfull.
 */
முழு
channel_not_very_much_buffered_data(கட்டமைப்பு ssh *ssh)
{
	u_int i;
	u_int maxsize = ssh_packet_get_maxsize(ssh);
	Channel *c;

	க்கு (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		எனில் (c == வெற்று || c->type != SSH_CHANNEL_OPEN)
			தொடர்;
		எனில் (sshbuf_len(c->output) > maxsize) {
			debug2("channel %d: big output buffer %zu > %u",
			    c->self, sshbuf_len(c->output), maxsize);
			திரும்பு 0;
		}
	}
	திரும்பு 1;
}

/* Returns true if any channel is still open. */
முழு
channel_still_open(கட்டமைப்பு ssh *ssh)
{
	u_int i;
	Channel *c;

	க்கு (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		எனில் (c == வெற்று)
			தொடர்;
		தேர்வு (c->type) {
		நிலை SSH_CHANNEL_X11_LISTENER:
		நிலை SSH_CHANNEL_PORT_LISTENER:
		நிலை SSH_CHANNEL_RPORT_LISTENER:
		நிலை SSH_CHANNEL_MUX_LISTENER:
		நிலை SSH_CHANNEL_CLOSED:
		நிலை SSH_CHANNEL_AUTH_SOCKET:
		நிலை SSH_CHANNEL_DYNAMIC:
		நிலை SSH_CHANNEL_RDYNAMIC_OPEN:
		நிலை SSH_CHANNEL_CONNECTING:
		நிலை SSH_CHANNEL_ZOMBIE:
		நிலை SSH_CHANNEL_ABANDONED:
		நிலை SSH_CHANNEL_UNIX_LISTENER:
		நிலை SSH_CHANNEL_RUNIX_LISTENER:
			தொடர்;
		நிலை SSH_CHANNEL_LARVAL:
			தொடர்;
		நிலை SSH_CHANNEL_OPENING:
		நிலை SSH_CHANNEL_OPEN:
		நிலை SSH_CHANNEL_RDYNAMIC_FINISH:
		நிலை SSH_CHANNEL_X11_OPEN:
		நிலை SSH_CHANNEL_MUX_CLIENT:
		நிலை SSH_CHANNEL_MUX_PROXY:
			திரும்பு 1;
		இயல்பு:
			fatal_f("bad channel type %d", c->type);
			/* NOTREACHED */
		}
	}
	திரும்பு 0;
}

/* Returns true if a channel with a TTY is open. */
முழு
channel_tty_open(கட்டமைப்பு ssh *ssh)
{
	u_int i;
	Channel *c;

	க்கு (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		எனில் (c == வெற்று || c->type != SSH_CHANNEL_OPEN)
			தொடர்;
		எனில் (c->client_tty)
			திரும்பு 1;
	}
	திரும்பு 0;
}

/* Returns the id of an open channel suitable for keepaliving */
முழு
channel_find_open(கட்டமைப்பு ssh *ssh)
{
	u_int i;
	Channel *c;

	க்கு (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		எனில் (c == வெற்று || !c->have_remote_id)
			தொடர்;
		தேர்வு (c->type) {
		நிலை SSH_CHANNEL_CLOSED:
		நிலை SSH_CHANNEL_DYNAMIC:
		நிலை SSH_CHANNEL_RDYNAMIC_OPEN:
		நிலை SSH_CHANNEL_RDYNAMIC_FINISH:
		நிலை SSH_CHANNEL_X11_LISTENER:
		நிலை SSH_CHANNEL_PORT_LISTENER:
		நிலை SSH_CHANNEL_RPORT_LISTENER:
		நிலை SSH_CHANNEL_MUX_LISTENER:
		நிலை SSH_CHANNEL_MUX_CLIENT:
		நிலை SSH_CHANNEL_MUX_PROXY:
		நிலை SSH_CHANNEL_OPENING:
		நிலை SSH_CHANNEL_CONNECTING:
		நிலை SSH_CHANNEL_ZOMBIE:
		நிலை SSH_CHANNEL_ABANDONED:
		நிலை SSH_CHANNEL_UNIX_LISTENER:
		நிலை SSH_CHANNEL_RUNIX_LISTENER:
			தொடர்;
		நிலை SSH_CHANNEL_LARVAL:
		நிலை SSH_CHANNEL_AUTH_SOCKET:
		நிலை SSH_CHANNEL_OPEN:
		நிலை SSH_CHANNEL_X11_OPEN:
			திரும்பு i;
		இயல்பு:
			fatal_f("bad channel type %d", c->type);
			/* NOTREACHED */
		}
	}
	திரும்பு -1;
}

/* Returns the state of the channel's extended usage flag */
மாறிலி எழுத்து *
channel_format_extended_usage(மாறிலி Channel *c)
{
	எனில் (c->efd == -1)
		திரும்பு "closed";

	தேர்வு (c->extended_usage) {
	நிலை CHAN_EXTENDED_WRITE:
		திரும்பு "write";
	நிலை CHAN_EXTENDED_READ:
		திரும்பு "read";
	நிலை CHAN_EXTENDED_IGNORE:
		திரும்பு "ignore";
	இயல்பு:
		திரும்பு "UNKNOWN";
	}
}

நிலையான எழுத்து *
channel_format_status(மாறிலி Channel *c)
{
	எழுத்து *ret = வெற்று;

	xasprintf(&ret, "t%d [%s] %s%u %s%u i%u/%zu o%u/%zu e[%s]/%zu "
	    "fd %d/%d/%d sock %d cc %d %s%u io 0x%02x/0x%02x %s%s",
	    c->type, c->xctype != வெற்று ? c->xctype : c->ctype,
	    c->have_remote_id ? "r" : "nr", c->remote_id,
	    c->mux_ctx != வெற்று ? "m" : "nm", c->mux_downstream_id,
	    c->istate, sshbuf_len(c->உள்ளீடு),
	    c->ostate, sshbuf_len(c->output),
	    channel_format_extended_usage(c), sshbuf_len(c->extended),
	    c->rfd, c->wfd, c->efd, c->sock, c->ctl_chan,
	    c->have_ctl_child_id ? "c" : "nc", c->ctl_child_id,
	    c->io_want, c->io_ready,
	    c->isatty ? "T" : (c->remote_has_tty ? "RT" : ""),
	    c->bulk ? "B" : "I");
	திரும்பு ret;
}

/*
 * Returns a message describing the currently open forwarded connections,
 * suitable for sending to the client.  The message contains crlf pairs for
 * newlines.
 */
எழுத்து *
channel_open_message(கட்டமைப்பு ssh *ssh)
{
	கட்டமைப்பு sshbuf *buf;
	Channel *c;
	u_int i;
	முழு r;
	எழுத்து *cp, *ret;

	எனில் ((buf = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new");
	எனில் ((r = sshbuf_putf(buf,
	    "The following connections are open:\r\n")) != 0)
		fatal_fr(r, "sshbuf_putf");
	க்கு (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		எனில் (c == வெற்று)
			தொடர்;
		தேர்வு (c->type) {
		நிலை SSH_CHANNEL_X11_LISTENER:
		நிலை SSH_CHANNEL_PORT_LISTENER:
		நிலை SSH_CHANNEL_RPORT_LISTENER:
		நிலை SSH_CHANNEL_CLOSED:
		நிலை SSH_CHANNEL_AUTH_SOCKET:
		நிலை SSH_CHANNEL_ZOMBIE:
		நிலை SSH_CHANNEL_ABANDONED:
		நிலை SSH_CHANNEL_MUX_LISTENER:
		நிலை SSH_CHANNEL_UNIX_LISTENER:
		நிலை SSH_CHANNEL_RUNIX_LISTENER:
			தொடர்;
		நிலை SSH_CHANNEL_LARVAL:
		நிலை SSH_CHANNEL_OPENING:
		நிலை SSH_CHANNEL_CONNECTING:
		நிலை SSH_CHANNEL_DYNAMIC:
		நிலை SSH_CHANNEL_RDYNAMIC_OPEN:
		நிலை SSH_CHANNEL_RDYNAMIC_FINISH:
		நிலை SSH_CHANNEL_OPEN:
		நிலை SSH_CHANNEL_X11_OPEN:
		நிலை SSH_CHANNEL_MUX_PROXY:
		நிலை SSH_CHANNEL_MUX_CLIENT:
			cp = channel_format_status(c);
			எனில் ((r = sshbuf_putf(buf, "  #%d %.300s (%s)\r\n",
			    c->self, c->remote_name, cp)) != 0) {
				விடுவி(cp);
				fatal_fr(r, "sshbuf_putf");
			}
			விடுவி(cp);
			தொடர்;
		இயல்பு:
			fatal_f("bad channel type %d", c->type);
			/* NOTREACHED */
		}
	}
	எனில் ((ret = sshbuf_dup_string(buf)) == வெற்று)
		fatal_f("sshbuf_dup_string");
	sshbuf_free(buf);
	திரும்பு ret;
}

வெறுமை
channel_report_open(கட்டமைப்பு ssh *ssh, முழு level)
{
	எழுத்து *open, *oopen, *cp, ident[256];

	sshpkt_fmt_connection_id(ssh, ident, அளவு(ident));
	do_log2(level, "Connection: %s (pid %ld)", ident, (long)getpid());
	open = oopen = channel_open_message(ssh);
	போது ((cp = strsep(&open, "\r\n")) != வெற்று) {
		எனில் (*cp != '\0')
			do_log2(level, "%s", cp);
	}
	விடுவி(oopen);
}

நிலையான வெறுமை
open_preamble(கட்டமைப்பு ssh *ssh, மாறிலி எழுத்து *where, Channel *c, மாறிலி எழுத்து *type)
{
	முழு r;

	எனில் ((r = sshpkt_start(ssh, SSH2_செய்தி_CHANNEL_OPEN)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, type)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_window)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0) {
		fatal_r(r, "%s: channel %i: open", where, c->self);
	}
}

வெறுமை
channel_send_open(கட்டமைப்பு ssh *ssh, முழு id)
{
	Channel *c = channel_lookup(ssh, id);
	முழு r;

	எனில் (c == வெற்று) {
		logit("channel_send_open: %d: bad id", id);
		திரும்பு;
	}
	debug2("channel %d: send open", id);
	open_preamble(ssh, __func__, c, c->ctype);
	எனில் ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i", c->self);
}

வெறுமை
channel_request_start(கட்டமைப்பு ssh *ssh, முழு id, மாறிலி எழுத்து *service,
    முழு wantconfirm)
{
	Channel *c = channel_lookup(ssh, id);
	முழு r;

	எனில் (c == வெற்று) {
		logit_f("%d: unknown channel id", id);
		திரும்பு;
	}
	எனில் (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);

	debug2("channel %d: request %s confirm %d", id, service, wantconfirm);
	எனில் ((r = sshpkt_start(ssh, SSH2_செய்தி_CHANNEL_REQUEST)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, service)) != 0 ||
	    (r = sshpkt_put_u8(ssh, wantconfirm)) != 0) {
		fatal_fr(r, "channel %i", c->self);
	}
}

வெறுமை
channel_register_status_confirm(கட்டமைப்பு ssh *ssh, முழு id,
    channel_confirm_cb *cb, channel_confirm_abandon_cb *abandon_cb, வெறுமை *ctx)
{
	கட்டமைப்பு channel_confirm *cc;
	Channel *c;

	எனில் ((c = channel_lookup(ssh, id)) == வெற்று)
		fatal_f("%d: bad id", id);

	cc = xcalloc(1, அளவு(*cc));
	cc->cb = cb;
	cc->abandon_cb = abandon_cb;
	cc->ctx = ctx;
	TAILQ_INSERT_TAIL(&c->status_confirms, cc, entry);
}

வெறுமை
channel_register_open_confirm(கட்டமைப்பு ssh *ssh, முழு id,
    channel_open_fn *fn, வெறுமை *ctx)
{
	Channel *c = channel_lookup(ssh, id);

	எனில் (c == வெற்று) {
		logit_f("%d: bad id", id);
		திரும்பு;
	}
	c->open_confirm = fn;
	c->open_confirm_ctx = ctx;
}

வெறுமை
channel_register_cleanup(கட்டமைப்பு ssh *ssh, முழு id,
    channel_callback_fn *fn, முழு do_close)
{
	Channel *c = channel_by_id(ssh, id);

	எனில் (c == வெற்று) {
		logit_f("%d: bad id", id);
		திரும்பு;
	}
	c->detach_user = fn;
	c->detach_close = do_close;
}

வெறுமை
channel_cancel_cleanup(கட்டமைப்பு ssh *ssh, முழு id)
{
	Channel *c = channel_by_id(ssh, id);

	எனில் (c == வெற்று) {
		logit_f("%d: bad id", id);
		திரும்பு;
	}
	c->detach_user = வெற்று;
	c->detach_close = 0;
}

வெறுமை
channel_register_filter(கட்டமைப்பு ssh *ssh, முழு id, channel_infilter_fn *ifn,
    channel_outfilter_fn *ofn, channel_filter_cleanup_fn *cfn, வெறுமை *ctx)
{
	Channel *c = channel_lookup(ssh, id);

	எனில் (c == வெற்று) {
		logit_f("%d: bad id", id);
		திரும்பு;
	}
	c->உள்ளீடு_filter = ifn;
	c->output_filter = ofn;
	c->filter_ctx = ctx;
	c->filter_cleanup = cfn;
}

வெறுமை
channel_set_fds(கட்டமைப்பு ssh *ssh, முழு id, முழு rfd, முழு wfd, முழு efd,
    முழு extusage, முழு nonblock, முழு is_tty, u_int window_max)
{
	Channel *c = channel_lookup(ssh, id);
	முழு r;

	எனில் (c == வெற்று || c->type != SSH_CHANNEL_LARVAL)
		fatal("channel_activate for non-larval channel %d.", id);
	எனில் (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);

	channel_register_fds(ssh, c, rfd, wfd, efd, extusage, nonblock, is_tty);
	c->type = SSH_CHANNEL_OPEN;
	channel_set_used_time(ssh, c);
	c->local_window = c->local_window_max = window_max;

	எனில் ((r = sshpkt_start(ssh, SSH2_செய்தி_CHANNEL_WINDOW_ADJUST)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_window)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i", c->self);
}

நிலையான வெறுமை
channel_pre_listener(கட்டமைப்பு ssh *ssh, Channel *c)
{
	c->io_want = SSH_CHAN_IO_SOCK_R;
}

நிலையான வெறுமை
channel_pre_connecting(கட்டமைப்பு ssh *ssh, Channel *c)
{
	debug3("channel %d: waiting for connection", c->self);
	c->io_want = SSH_CHAN_IO_SOCK_W;
}

நிலையான வெறுமை
channel_pre_open(கட்டமைப்பு ssh *ssh, Channel *c)
{
	c->io_want = 0;
	எனில் (c->istate == CHAN_உள்ளீடு_OPEN &&
	    c->remote_window > 0 &&
	    sshbuf_len(c->உள்ளீடு) < c->remote_window &&
	    sshbuf_check_reserve(c->உள்ளீடு, CHAN_RBUF) == 0)
		c->io_want |= SSH_CHAN_IO_RFD;
	எனில் (c->ostate == CHAN_OUTPUT_OPEN ||
	    c->ostate == CHAN_OUTPUT_WAIT_DRAIN) {
		எனில் (sshbuf_len(c->output) > 0) {
			c->io_want |= SSH_CHAN_IO_WFD;
		} இல்லையெனில் எனில் (c->ostate == CHAN_OUTPUT_WAIT_DRAIN) {
			எனில் (CHANNEL_EFD_OUTPUT_ACTIVE(c))
				debug2("channel %d: "
				    "obuf_empty delayed efd %d/(%zu)", c->self,
				    c->efd, sshbuf_len(c->extended));
			இல்லையெனில்
				chan_obuf_empty(ssh, c);
		}
	}
	/** XXX check close conditions, too */
	எனில் (c->efd != -1 && !(c->istate == CHAN_உள்ளீடு_CLOSED &&
	    c->ostate == CHAN_OUTPUT_CLOSED)) {
		எனில் (c->extended_usage == CHAN_EXTENDED_WRITE &&
		    sshbuf_len(c->extended) > 0)
			c->io_want |= SSH_CHAN_IO_EFD_W;
		இல்லையெனில் எனில் (c->efd != -1 && !(c->flags & CHAN_EOF_SENT) &&
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
நிலையான முழு
x11_open_helper(கட்டமைப்பு ssh *ssh, கட்டமைப்பு sshbuf *b)
{
	கட்டமைப்பு ssh_channels *sc = ssh->chanctxt;
	u_char *ucp;
	u_int proto_len, data_len;

	எனில் (sc->x11_saved_proto == வெற்று) {
		error("X11 forwarding opened before X11 forwarding requested");
		திரும்பு -1;
	}

	/* Is this being called after the refusal deadline? */
	எனில் (sc->x11_refuse_time != 0.0 &&
	    monotime_double() >= sc->x11_refuse_time) {
		verbose("Rejected X11 connection after ForwardX11Timeout "
		    "expired");
		திரும்பு -1;
	}

	/* Check if the fixed size part of the packet is in buffer. */
	எனில் (sshbuf_len(b) < 12)
		திரும்பு 0;

	/* Parse the lengths of variable-length fields. */
	ucp = sshbuf_mutable_ptr(b);
	எனில் (ucp[0] == 0x42) {	/* Byte order MSB first. */
		proto_len = 256 * ucp[6] + ucp[7];
		data_len = 256 * ucp[8] + ucp[9];
	} இல்லையெனில் எனில் (ucp[0] == 0x6c) {	/* Byte order LSB first. */
		proto_len = ucp[6] + 256 * ucp[7];
		data_len = ucp[8] + 256 * ucp[9];
	} இல்லையெனில் {
		debug2("Initial X11 packet contains bad byte order byte: 0x%x",
		    ucp[0]);
		திரும்பு -1;
	}

	/* Check if the whole packet is in buffer. */
	எனில் (sshbuf_len(b) <
	    12 + ((proto_len + 3) & ~3) + ((data_len + 3) & ~3))
		திரும்பு 0;

	/* Check if authentication protocol matches. */
	எனில் (proto_len != strlen(sc->x11_saved_proto) ||
	    memcmp(ucp + 12, sc->x11_saved_proto, proto_len) != 0) {
		debug2("X11 connection uses different authentication protocol.");
		திரும்பு -1;
	}
	/* Check if authentication data matches our fake data. */
	எனில் (data_len != sc->x11_fake_data_len ||
	    timingsafe_bcmp(ucp + 12 + ((proto_len + 3) & ~3),
		sc->x11_fake_data, sc->x11_fake_data_len) != 0) {
		debug2("X11 auth data does not match fake data.");
		திரும்பு -1;
	}
	/* Check fake data length */
	எனில் (sc->x11_fake_data_len != sc->x11_saved_data_len) {
		error("X11 fake_data_len %d != saved_data_len %d",
		    sc->x11_fake_data_len, sc->x11_saved_data_len);
		திரும்பு -1;
	}
	/*
	 * Received authentication protocol and data match
	 * our fake data. Substitute the fake data with real
	 * data.
	 */
	memcpy(ucp + 12 + ((proto_len + 3) & ~3),
	    sc->x11_saved_data, sc->x11_saved_data_len);
	திரும்பு 1;
}

வெறுமை
channel_force_close(கட்டமைப்பு ssh *ssh, Channel *c, முழு abandon)
{
	debug3_f("channel %d: forcibly closing", c->self);
	எனில் (c->istate == CHAN_உள்ளீடு_OPEN)
		chan_read_failed(ssh, c);
	எனில் (c->istate == CHAN_உள்ளீடு_WAIT_DRAIN) {
		sshbuf_reset(c->உள்ளீடு);
		chan_ibuf_empty(ssh, c);
	}
	எனில் (c->ostate == CHAN_OUTPUT_OPEN ||
	    c->ostate == CHAN_OUTPUT_WAIT_DRAIN) {
		sshbuf_reset(c->output);
		chan_write_failed(ssh, c);
	}
	எனில் (c->detach_user)
		c->detach_user(ssh, c->self, 1, வெற்று);
	எனில் (c->efd != -1)
		channel_close_fd(ssh, c, &c->efd);
	எனில் (abandon)
		c->type = SSH_CHANNEL_ABANDONED;
	/* exempt from inactivity timeouts */
	c->inactive_deadline = 0;
	c->lastused = 0;
}

நிலையான வெறுமை
channel_pre_x11_open(கட்டமைப்பு ssh *ssh, Channel *c)
{
	முழு ret = x11_open_helper(ssh, c->output);

	/* c->force_drain = 1; */

	எனில் (ret == 1) {
		c->type = SSH_CHANNEL_OPEN;
		channel_set_used_time(ssh, c);
		channel_pre_open(ssh, c);
	} இல்லையெனில் எனில் (ret == -1) {
		logit("X11 connection rejected because of wrong "
		    "authentication.");
		debug2("X11 rejected %d i%d/o%d",
		    c->self, c->istate, c->ostate);
		channel_force_close(ssh, c, 0);
	}
}

நிலையான வெறுமை
channel_pre_mux_client(கட்டமைப்பு ssh *ssh, Channel *c)
{
	c->io_want = 0;
	எனில் (c->istate == CHAN_உள்ளீடு_OPEN && !c->mux_pause &&
	    sshbuf_check_reserve(c->உள்ளீடு, CHAN_RBUF) == 0)
		c->io_want |= SSH_CHAN_IO_RFD;
	எனில் (c->istate == CHAN_உள்ளீடு_WAIT_DRAIN) {
		/* clear buffer immediately (discard any partial packet) */
		sshbuf_reset(c->உள்ளீடு);
		chan_ibuf_empty(ssh, c);
		/* Start output drain. XXX just kill chan? */
		chan_rcvd_oclose(ssh, c);
	}
	எனில் (c->ostate == CHAN_OUTPUT_OPEN ||
	    c->ostate == CHAN_OUTPUT_WAIT_DRAIN) {
		எனில் (sshbuf_len(c->output) > 0)
			c->io_want |= SSH_CHAN_IO_WFD;
		இல்லையெனில் எனில் (c->ostate == CHAN_OUTPUT_WAIT_DRAIN)
			chan_obuf_empty(ssh, c);
	}
}

நிலையான உள்வரி முழு
socks_decode_error(Channel *c, முழு status, மாறிலி எழுத்து *func, மாறிலி எழுத்து *செய்தி)
{
	எனில் (status == SSH_ERR_MESSAGE_INCOMPLETE)
		திரும்பு 0;
	இல்லையெனில் {
		debug_r(status, "%s: channel %d: decode %s",
		    func, c->self, செய்தி);
		திரும்பு -1;
	}
}

/* try to decode a socks4 header */
நிலையான முழு
channel_decode_socks4(Channel *c, கட்டமைப்பு sshbuf *உள்ளீடு, கட்டமைப்பு sshbuf *output)
{
	uint8_t socks_ver, socks_cmd, dest_addr[4];
	uint16_t dest_port;
	எழுத்து *user = வெற்று, *host = வெற்று;
	முழு success = -1, socks4a = 0, r;
	கட்டமைப்பு sshbuf *b = வெற்று;

	எனில் (sshbuf_len(உள்ளீடு) < 9)
		திரும்பு 0;

	/* We may not have a complete message, so work on a dup of the buffer */
	எனில் ((b = sshbuf_fromb(உள்ளீடு)) == வெற்று)
		fatal_f("sshbuf_fromb failed");

	debug2("channel %d: decode socks4", c->self);
	எனில் ((r = sshbuf_get_u8(b, &socks_ver)) != 0 ||
	    (r = sshbuf_get_u8(b, &socks_cmd)) != 0 ||
	    (r = sshbuf_get_u16(b, &dest_port)) != 0 ||
	    (r = sshbuf_get(b, &dest_addr, அளவு(dest_addr))) != 0 ||
	    (r = sshbuf_get_nulterminated_string(b, 1024, &user, வெற்று)) != 0) {
		success = socks_decode_error(c, r, __func__, "header");
		செல் out;
	}

	/* Is this a SOCKS4A request? (indicated by an address of 0.0.0.x) */
	எனில் (dest_addr[0] == 0 && dest_addr[1] == 0 &&
	    dest_addr[2] == 0 && dest_addr[3] != 0) {
		/* If so, then the hostname follows, also nul-terminated */
		எனில் ((r = sshbuf_get_nulterminated_string(b, 1024,
		    &host, வெற்று)) != 0) {
			success = socks_decode_error(c, r, __func__, "host");
			செல் out;
		}
		socks4a = 1;
	} இல்லையெனில் {
		/* Plain SOCKS4 passes an IPv4 binary address; reconstruct */
		xasprintf(&host, "%d.%d.%d.%d",
		    dest_addr[0], dest_addr[1], dest_addr[2], dest_addr[3]);
	}

	/* We have a complete SOCKS4 message; consume it from input */
	எனில் ((r = sshbuf_consume_upto_child(உள்ளீடு, b)) != 0)
		fatal_fr(r, "channel %d: consume", c->self);

	/* Handle the request */
	debug2("channel %d: %s: user=\"%s\" command=%d destination=[%s]:%d",
	    c->self, socks4a ? "SOCKS4A" : "SOCKS4", user, (முழு)socks_cmd,
	    host, dest_port);
	எனில் (socks_cmd != 1) {
		debug("channel %d: cannot handle %s command 0x%02x",
		    c->self, socks4a ? "SOCKS4A" : "SOCKS4", socks_cmd);
		செல் out;
	}
	விடுவி(c->path);
	c->path = host;
	host = வெற்று; /* transferred */
	c->host_port = dest_port;

	/* Reply to the SOCKS4 client */
	எனில் ((r = sshbuf_put_u8(output, 0)) != 0 ||	/* vn: 0 for reply */
	    (r = sshbuf_put_u8(output, 90)) != 0 ||	/* cd: req granted */
	    (r = sshbuf_put_u16(output, 0)) != 0 ||	/* port: ignored */
	    (r = sshbuf_put_u32(output, ntohl(INADDR_ANY))) != 0) /* ignored */
		fatal_fr(r, "channel %d: compose reply", c->self);

	/* success */
	success = 1;
 out:
	sshbuf_free(b);
	விடுவி(user);
	விடுவி(host);
	திரும்பு success;
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
நிலையான முழு
channel_socks5_check_auth(Channel *c, கட்டமைப்பு sshbuf *b, கட்டமைப்பு sshbuf *உள்ளீடு,
    கட்டமைப்பு sshbuf *output)
{
	uint8_t socks_ver;
	uint8_t nmethods, method;
	முழு r;
	u_int i, found;

	/* format: ver | nmethods | methods */
	எனில் ((r = sshbuf_get_u8(b, &socks_ver)) != 0)
		திரும்பு socks_decode_error(c, r, __func__, "version");
	எனில் (socks_ver != 5) /* shouldn't happen; checked by caller^2 */
		fatal_fr(r, "channel %d: internal error: not socks5", c->self);
	எனில் ((r = sshbuf_get_u8(b, &nmethods)) != 0)
		திரும்பு socks_decode_error(c, r, __func__, "methods");
	க்கு (found = i = 0; i < nmethods; i++) {
		எனில் ((r = sshbuf_get_u8(b, &method)) != 0)
			திரும்பு socks_decode_error(c, r, __func__, "method");
		எனில் (method == SSH_SOCKS5_NOAUTH)
			found = 1;
	}
	எனில் (!found) {
		debug("channel %d: didn't request SSH_SOCKS5_NOAUTH", c->self);
		திரும்பு -1;
	}
	/* Consume completed request */
	எனில் ((r = sshbuf_consume_upto_child(உள்ளீடு, b)) != 0)
		fatal_fr(r, "channel %d: consume", c->self);

	/* Compose reply: version, method */
	எனில் ((r = sshbuf_put_u8(output, 0x05)) != 0 ||
	    (r = sshbuf_put_u8(output, SSH_SOCKS5_NOAUTH)) != 0)
		fatal_fr(r, "channel %d: append reply", c->self);
	/* success */
	debug2("channel %d: socks5 auth done", c->self);
	திரும்பு 1;
}

நிலையான முழு
channel_decode_socks5(Channel *c, கட்டமைப்பு sshbuf *உள்ளீடு, கட்டமைப்பு sshbuf *output)
{
	uint8_t socks_ver, socks_cmd, socks_reserved, socks_atyp, addrlen;
	uint16_t dest_port;
	எழுத்து dest_addr[255+1], ntop[INET6_ADDRSTRLEN];
	u_int af;
	முழு r, success = -1;;
	கட்டமைப்பு sshbuf *b = வெற்று;

	debug2("channel %d: decode socks5 %s", c->self,
	    (c->flags & SSH_SOCKS5_AUTHDONE) ? "request" : "auth");

	/* We may not have a complete message, so work on a dup of the buffer */
	எனில் ((b = sshbuf_fromb(உள்ளீடு)) == வெற்று)
		fatal_f("sshbuf_fromb failed");

	எனில் (!(c->flags & SSH_SOCKS5_AUTHDONE)) {
		எனில் ((r = channel_socks5_check_auth(c, b, உள்ளீடு, output)) != 1) {
			success = r;
			செல் out;
		}
		c->flags |= SSH_SOCKS5_AUTHDONE;
		/* Continue to parse request in case client speculated ahead */
	}

	/* Request messages (auth or connect) always start with the version */
	எனில் ((r = sshbuf_get_u8(b, &socks_ver)) != 0) {
		success = socks_decode_error(c, r, __func__, "version");
		செல் out;
	}
	எனில் (socks_ver != 5) /* shouldn't happen */
		fatal_fr(r, "channel %d: internal error: not socks5", c->self);

	/* Parse SOCKS5 request header */
	debug2("channel %d: socks5 post auth", c->self);
	எனில் ((r = sshbuf_get_u8(b, &socks_cmd)) != 0 ||
	    (r = sshbuf_get_u8(b, &socks_reserved)) != 0 ||
	    (r = sshbuf_get_u8(b, &socks_atyp)) != 0) {
		success = socks_decode_error(c, r, __func__, "request header");
		செல் out;
	}

	எனில் (socks_ver != 0x05 ||
	    socks_cmd != SSH_SOCKS5_CONNECT ||
	    socks_reserved != 0x00) {
		debug2("channel %d: only socks5 connect supported", c->self);
		செல் out;
	}

	தேர்வு (socks_atyp) {
	நிலை SSH_SOCKS5_IPV4:
		addrlen = 4;
		af = AF_INET;
		நிறுத்து;
	நிலை SSH_SOCKS5_DOMAIN:
		எனில் ((r = sshbuf_get_u8(b, &addrlen)) != 0) {
			success = socks_decode_error(c, r, __func__, "addrlen");
			செல் out;
		}
		af = -1;
		நிறுத்து;
	நிலை SSH_SOCKS5_IPV6:
		addrlen = 16;
		af = AF_INET6;
		நிறுத்து;
	இயல்பு:
		debug2("channel %d: bad socks5 atyp %d", c->self, socks_atyp);
		செல் out;
	}
	எனில் ((r = sshbuf_get(b, &dest_addr, addrlen)) != 0 ||
	    (r = sshbuf_get_u16(b, &dest_port)) != 0) {
		success = socks_decode_error(c, r, __func__, "addr/port");
		செல் out;
	}
	dest_addr[addrlen] = '\0';

	/* We have a complete SOCKS5 request; consume it from input */
	எனில் ((r = sshbuf_consume_upto_child(உள்ளீடு, b)) != 0)
		fatal_fr(r, "channel %d: consume", c->self);

	விடுவி(c->path);
	c->path = வெற்று;
	எனில் (socks_atyp == SSH_SOCKS5_DOMAIN)
		c->path = xstrdup(dest_addr);
	இல்லையெனில் {
		எனில் (inet_ntop(af, dest_addr, ntop, அளவு(ntop)) == வெற்று)
			திரும்பு -1;
		c->path = xstrdup(ntop);
	}
	c->host_port = dest_port;

	debug2("channel %d: dynamic request: socks5 host %s port %u command %u",
	    c->self, c->path, c->host_port, socks_cmd);

	/* Reply */
	எனில் ((r = sshbuf_put_u8(output, 0x05)) != 0 ||	/* version */
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
	திரும்பு success;
}

Channel *
channel_connect_stdio_fwd(கட்டமைப்பு ssh *ssh,
    மாறிலி எழுத்து *host_to_connect, முழு port_to_connect,
    முழு in, முழு out, முழு nonblock)
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

	திரும்பு c;
}

/* dynamic port forwarding */
நிலையான வெறுமை
channel_pre_dynamic(கட்டமைப்பு ssh *ssh, Channel *c)
{
	u_int have;
	u_char ver;
	முழு r, ret;

	c->io_want = 0;
	have = sshbuf_len(c->உள்ளீடு);
	debug2("channel %d: pre_dynamic: have %d", c->self, have);
	/* sshbuf_dump(c->input, stderr); */
	/* check if the fixed size part of the packet is in buffer. */
	எனில் (have < 3) {
		/* need more */
		c->io_want |= SSH_CHAN_IO_RFD;
		திரும்பு;
	}
	/* try to guess the protocol */
	எனில் ((r = sshbuf_peek_u8(c->உள்ளீடு, 0, &ver)) != 0)
		fatal_fr(r, "sshbuf_peek_u8");
	தேர்வு (ver) {
	நிலை 0x04:
		ret = channel_decode_socks4(c, c->உள்ளீடு, c->output);
		நிறுத்து;
	நிலை 0x05:
		ret = channel_decode_socks5(c, c->உள்ளீடு, c->output);
		நிறுத்து;
	இயல்பு:
		debug2_f("channel %d: unknown SOCKS version %u", c->self, ver);
		ret = -1;
		நிறுத்து;
	}
	எனில் (ret < 0) {
		chan_mark_dead(ssh, c);
	} இல்லையெனில் எனில் (ret == 0) {
		debug2("channel %d: pre_dynamic: need more", c->self);
		/* need more */
		c->io_want |= SSH_CHAN_IO_RFD;
		எனில் (sshbuf_len(c->output))
			c->io_want |= SSH_CHAN_IO_WFD;
	} இல்லையெனில் {
		/* switch to the next state */
		c->type = SSH_CHANNEL_OPENING;
		port_open_helper(ssh, c, "direct-tcpip");
	}
}

/* simulate read-error */
நிலையான வெறுமை
rdynamic_close(கட்டமைப்பு ssh *ssh, Channel *c)
{
	c->type = SSH_CHANNEL_OPEN;
	channel_force_close(ssh, c, 0);
}

/* reverse dynamic port forwarding */
நிலையான வெறுமை
channel_before_prepare_io_rdynamic(கட்டமைப்பு ssh *ssh, Channel *c)
{
	மாறிலி u_char *p;
	u_int have, len;
	முழு r, ret;

	have = sshbuf_len(c->output);
	debug2("channel %d: pre_rdynamic: have %d", c->self, have);
	/* sshbuf_dump(c->output, stderr); */
	/* EOF received */
	எனில் (c->flags & CHAN_EOF_RCVD) {
		எனில் ((r = sshbuf_consume(c->output, have)) != 0)
			fatal_fr(r, "channel %d: consume", c->self);
		rdynamic_close(ssh, c);
		திரும்பு;
	}
	/* check if the fixed size part of the packet is in buffer. */
	எனில் (have < 3)
		திரும்பு;
	/* try to guess the protocol */
	p = sshbuf_ptr(c->output);
	தேர்வு (p[0]) {
	நிலை 0x04:
		/* switch input/output for reverse forwarding */
		ret = channel_decode_socks4(c, c->output, c->உள்ளீடு);
		நிறுத்து;
	நிலை 0x05:
		ret = channel_decode_socks5(c, c->output, c->உள்ளீடு);
		நிறுத்து;
	இயல்பு:
		ret = -1;
		நிறுத்து;
	}
	எனில் (ret < 0) {
		rdynamic_close(ssh, c);
	} இல்லையெனில் எனில் (ret == 0) {
		debug2("channel %d: pre_rdynamic: need more", c->self);
		/* send socks request to peer */
		len = sshbuf_len(c->உள்ளீடு);
		எனில் (len > 0 && len < c->remote_window) {
			எனில் ((r = sshpkt_start(ssh, SSH2_செய்தி_CHANNEL_DATA)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
			    (r = sshpkt_put_stringb(ssh, c->உள்ளீடு)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0) {
				fatal_fr(r, "channel %i: rdynamic", c->self);
			}
			எனில் ((r = sshbuf_consume(c->உள்ளீடு, len)) != 0)
				fatal_fr(r, "channel %d: consume", c->self);
			c->remote_window -= len;
		}
	} இல்லையெனில் எனில் (rdynamic_connect_finish(ssh, c) < 0) {
		/* the connect failed */
		rdynamic_close(ssh, c);
	}
}

/* This is our fake X11 server socket. */
நிலையான வெறுமை
channel_post_x11_listener(கட்டமைப்பு ssh *ssh, Channel *c)
{
	Channel *nc;
	கட்டமைப்பு sockaddr_storage addr;
	முழு r, newsock, oerrno, remote_port;
	socklen_t addrlen;
	எழுத்து buf[16384], *remote_ipaddr;

	எனில் ((c->io_ready & SSH_CHAN_IO_SOCK_R) == 0)
		திரும்பு;

	debug("X11 connection requested.");
	addrlen = அளவு(addr);
	newsock = accept(c->sock, (கட்டமைப்பு sockaddr *)&addr, &addrlen);
	எனில் (c->single_connection) {
		oerrno = errno;
		debug2("single_connection: closing X11 listener.");
		channel_close_fd(ssh, c, &c->sock);
		chan_mark_dead(ssh, c);
		errno = oerrno;
	}
	எனில் (newsock == -1) {
		எனில் (errno != EINTR && errno != EWOULDBLOCK &&
		    errno != ECONNABORTED)
			error("accept: %.100s", strerror(errno));
		எனில் (errno == EMFILE || errno == ENFILE)
			c->notbefore = monotime_double() + 1.0;
		திரும்பு;
	}
	set_nodelay(newsock);
	எனில் (ssh->chanctxt->want_tcp_keepalive)
		set_keepalive(newsock); /* logs errors */
	remote_ipaddr = get_peer_ipaddr(newsock);
	remote_port = get_peer_port(newsock);
	snprintf(buf, அளவு buf, "X11 connection from %.200s port %d",
	    remote_ipaddr, remote_port);

	nc = channel_new(ssh, "x11-connection",
	    SSH_CHANNEL_OPENING, newsock, newsock, -1,
	    c->local_window_max, c->local_maxpacket, 0, buf, 1);
	open_preamble(ssh, __func__, nc, "x11");
	எனில் ((r = sshpkt_put_cstring(ssh, remote_ipaddr)) != 0 ||
	    (r = sshpkt_put_u32(ssh, remote_port)) != 0) {
		fatal_fr(r, "channel %i: reply", c->self);
	}
	எனில் ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i: send", c->self);
	விடுவி(remote_ipaddr);
}

நிலையான வெறுமை
port_open_helper(கட்டமைப்பு ssh *ssh, Channel *c, எழுத்து *rtype)
{
	எழுத்து *local_ipaddr = get_local_ipaddr(c->sock);
	முழு local_port = c->sock == -1 ? 65536 : get_local_port(c->sock);
	எழுத்து *remote_ipaddr = get_peer_ipaddr(c->sock);
	முழு remote_port = get_peer_port(c->sock);
	முழு r;

	எனில் (remote_port == -1) {
		/* Fake addr/port to appease peers that validate it (Tectia) */
		விடுவி(remote_ipaddr);
		remote_ipaddr = xstrdup("127.0.0.1");
		remote_port = 65535;
	}

	விடுவி(c->remote_name);
	xasprintf(&c->remote_name,
	    "%s: listening port %d for %.100s port %d, "
	    "connect from %.200s port %d to %.100s port %d",
	    rtype, c->listening_port, c->path, c->host_port,
	    remote_ipaddr, remote_port, local_ipaddr, local_port);

	open_preamble(ssh, __func__, c, rtype);
	எனில் (strcmp(rtype, "direct-tcpip") == 0) {
		/* target host, port */
		எனில் ((r = sshpkt_put_cstring(ssh, c->path)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->host_port)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	} இல்லையெனில் எனில் (strcmp(rtype, "direct-streamlocal@openssh.com") == 0) {
		/* target path */
		எனில் ((r = sshpkt_put_cstring(ssh, c->path)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	} இல்லையெனில் எனில் (strcmp(rtype, "forwarded-streamlocal@openssh.com") == 0) {
		/* listen path */
		எனில் ((r = sshpkt_put_cstring(ssh, c->path)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	} இல்லையெனில் {
		/* listen address, port */
		எனில் ((r = sshpkt_put_cstring(ssh, c->path)) != 0 ||
		    (r = sshpkt_put_u32(ssh, local_port)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	}
	எனில் (strcmp(rtype, "forwarded-streamlocal@openssh.com") == 0) {
		/* reserved for future owner/mode info */
		எனில் ((r = sshpkt_put_cstring(ssh, "")) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	} இல்லையெனில் {
		/* originator host and port */
		எனில் ((r = sshpkt_put_cstring(ssh, remote_ipaddr)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)remote_port)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	}
	எனில் ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i: send", c->self);
	விடுவி(remote_ipaddr);
	விடுவி(local_ipaddr);
}

வெறுமை
channel_set_x11_refuse_time(கட்டமைப்பு ssh *ssh, இரட்டை refuse_time)
{
	ssh->chanctxt->x11_refuse_time = refuse_time;
}

/*
 * This socket is listening for connections to a forwarded TCP/IP port.
 */
நிலையான வெறுமை
channel_post_port_listener(கட்டமைப்பு ssh *ssh, Channel *c)
{
	Channel *nc;
	கட்டமைப்பு sockaddr_storage addr;
	முழு newsock, nextstate;
	socklen_t addrlen;
	எழுத்து *rtype;

	எனில் ((c->io_ready & SSH_CHAN_IO_SOCK_R) == 0)
		திரும்பு;

	debug("Connection to port %d forwarding to %.100s port %d requested.",
	    c->listening_port, c->path, c->host_port);

	எனில் (c->type == SSH_CHANNEL_RPORT_LISTENER) {
		nextstate = SSH_CHANNEL_OPENING;
		rtype = "forwarded-tcpip";
	} இல்லையெனில் எனில் (c->type == SSH_CHANNEL_RUNIX_LISTENER) {
		nextstate = SSH_CHANNEL_OPENING;
		rtype = "forwarded-streamlocal@openssh.com";
	} இல்லையெனில் எனில் (c->host_port == PORT_STREAMLOCAL) {
		nextstate = SSH_CHANNEL_OPENING;
		rtype = "direct-streamlocal@openssh.com";
	} இல்லையெனில் எனில் (c->host_port == 0) {
		nextstate = SSH_CHANNEL_DYNAMIC;
		rtype = "dynamic-tcpip";
	} இல்லையெனில் {
		nextstate = SSH_CHANNEL_OPENING;
		rtype = "direct-tcpip";
	}

	addrlen = அளவு(addr);
	newsock = accept(c->sock, (கட்டமைப்பு sockaddr *)&addr, &addrlen);
	எனில் (newsock == -1) {
		எனில் (errno != EINTR && errno != EWOULDBLOCK &&
		    errno != ECONNABORTED)
			error("accept: %.100s", strerror(errno));
		எனில் (errno == EMFILE || errno == ENFILE)
			c->notbefore = monotime_double() + 1.0;
		திரும்பு;
	}
	எனில் (addr.ss_family == AF_INET || addr.ss_family == AF_INET6) {
		set_nodelay(newsock);
		எனில் (ssh->chanctxt->want_tcp_keepalive)
			set_keepalive(newsock); /* logs errors */
	}
	nc = channel_new(ssh, rtype, nextstate, newsock, newsock, -1,
	    c->local_window_max, c->local_maxpacket, 0, rtype, 1);
	nc->listening_port = c->listening_port;
	nc->host_port = c->host_port;
	எனில் (c->path != வெற்று)
		nc->path = xstrdup(c->path);

	எனில் (nextstate != SSH_CHANNEL_DYNAMIC)
		port_open_helper(ssh, nc, rtype);
}

/*
 * This is the authentication agent socket listening for connections from
 * clients.
 */
நிலையான வெறுமை
channel_post_auth_listener(கட்டமைப்பு ssh *ssh, Channel *c)
{
	Channel *nc;
	முழு r, newsock;
	கட்டமைப்பு sockaddr_storage addr;
	socklen_t addrlen;

	எனில் ((c->io_ready & SSH_CHAN_IO_SOCK_R) == 0)
		திரும்பு;

	addrlen = அளவு(addr);
	newsock = accept(c->sock, (கட்டமைப்பு sockaddr *)&addr, &addrlen);
	எனில் (newsock == -1) {
		error("accept from auth socket: %.100s", strerror(errno));
		எனில் (errno == EMFILE || errno == ENFILE)
			c->notbefore = monotime_double() + 1.0;
		திரும்பு;
	}
	nc = channel_new(ssh, "agent-connection",
	    SSH_CHANNEL_OPENING, newsock, newsock, -1,
	    c->local_window_max, c->local_maxpacket,
	    0, "accepted auth socket", 1);
	open_preamble(ssh, __func__, nc,
	    c->agent_new ? "agent-connect" : "auth-agent@openssh.com");
	எனில் ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i", c->self);
}

நிலையான வெறுமை
channel_post_connecting(கட்டமைப்பு ssh *ssh, Channel *c)
{
	முழு err = 0, sock, isopen, r;
	socklen_t sz = அளவு(err);

	எனில் ((c->io_ready & SSH_CHAN_IO_SOCK_W) == 0)
		திரும்பு;
	எனில் (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);
	எனில் (c->connect_ctx == வெற்று)
		fatal_f("channel %d: context missing", c->self);

	/* for rdynamic the OPEN_CONFIRMATION has been sent already */
	isopen = (c->type == SSH_CHANNEL_RDYNAMIC_FINISH);

	எனில் (getsockopt(c->sock, SOL_SOCKET, SO_ERROR, &err, &sz) == -1) {
		err = errno;
		error("getsockopt SO_ERROR failed");
	}

	எனில் (err == 0) {
		/* Non-blocking connection completed */
		debug("channel %d: connected to %s port %d",
		    c->self, c->connect_ctx->host, c->connect_ctx->port);
		channel_free_connect_ctx(c);
		c->type = SSH_CHANNEL_OPEN;
		channel_set_used_time(ssh, c);
		எனில் (isopen) {
			/* no message necessary */
		} இல்லையெனில் {
			எனில் ((r = sshpkt_start(ssh,
			    SSH2_செய்தி_CHANNEL_OPEN_CONFIRMATION)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_window)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "channel %i open confirm", c->self);
		}
		திரும்பு;
	}
	எனில் (err == EINTR || err == EAGAIN || err == EINPROGRESS)
		திரும்பு;

	/* Non-blocking connection failed */
	debug("channel %d: connection failed: %s", c->self, strerror(err));

	/* Try next address, if any */
	எனில் ((sock = connect_next(ssh, c->connect_ctx)) == -1) {
		/* Exhausted all addresses for this destination */
		error("connect_to %.100s port %d: failed.",
		    c->connect_ctx->host, c->connect_ctx->port);
		channel_free_connect_ctx(c);
		எனில் (isopen) {
			rdynamic_close(ssh, c);
		} இல்லையெனில் {
			எனில் ((r = sshpkt_start(ssh,
			    SSH2_செய்தி_CHANNEL_OPEN_FAILURE)) != 0 ||
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

நிலையான முழு
channel_handle_rfd(கட்டமைப்பு ssh *ssh, Channel *c)
{
	எழுத்து buf[CHAN_RBUF];
	ssize_t len;
	முழு r, force;
	size_t nr = 0, have, avail, maxlen = CHANNEL_MAX_READ;
	முழு pty_zeroread = 0;

#ifdef PTY_ZEROREAD
	/* Bug on AIX: read(1) can return 0 for a non-closed fd */
	pty_zeroread = c->isatty;
#endif

	force = c->isatty && c->detach_close && c->istate != CHAN_உள்ளீடு_CLOSED;

	எனில் (!force && (c->io_ready & SSH_CHAN_IO_RFD) == 0)
		திரும்பு 1;
	எனில் ((avail = sshbuf_avail(c->உள்ளீடு)) == 0)
		திரும்பு 1; /* Shouldn't happen */

	/*
	 * For "simple" channels (i.e. not datagram or filtered), we can
	 * read directly to the channel buffer.
	 */
	எனில் (!pty_zeroread && c->உள்ளீடு_filter == வெற்று && !c->datagram) {
		/* Only OPEN channels have valid rwin */
		எனில் (c->type == SSH_CHANNEL_OPEN) {
			எனில் ((have = sshbuf_len(c->உள்ளீடு)) >= c->remote_window)
				திரும்பு 1; /* shouldn't happen */
			எனில் (maxlen > c->remote_window - have)
				maxlen = c->remote_window - have;
		}
		எனில் (maxlen > avail)
			maxlen = avail;
		எனில் ((r = sshbuf_read(c->rfd, c->உள்ளீடு, maxlen, &nr)) != 0) {
			எனில் (errno == EINTR || (!force &&
			    (errno == EAGAIN || errno == EWOULDBLOCK)))
				திரும்பு 1;
			debug2("channel %d: read failed rfd %d maxlen %zu: %s",
			    c->self, c->rfd, maxlen, ssh_err(r));
			செல் rfail;
		}
		எனில் (nr != 0)
			channel_set_used_time(ssh, c);
		திரும்பு 1;
	}

	errno = 0;
	len = பட(c->rfd, buf, அளவு(buf));
	/* fixup AIX zero-length read with errno set to look more like errors */
	எனில் (pty_zeroread && len == 0 && errno != 0)
		len = -1;
	எனில் (len == -1 && (errno == EINTR ||
	    ((errno == EAGAIN || errno == EWOULDBLOCK) && !force)))
		திரும்பு 1;
	எனில் (len < 0 || (!pty_zeroread && len == 0)) {
		debug2("channel %d: read<=0 rfd %d len %zd: %s",
		    c->self, c->rfd, len,
		    len == 0 ? "closed" : strerror(errno));
 rfail:
		எனில் (c->type != SSH_CHANNEL_OPEN) {
			debug2("channel %d: not open", c->self);
			chan_mark_dead(ssh, c);
			திரும்பு -1;
		} இல்லையெனில் {
			chan_read_failed(ssh, c);
		}
		திரும்பு -1;
	}
	channel_set_used_time(ssh, c);
	எனில் (c->உள்ளீடு_filter != வெற்று) {
		எனில் (c->உள்ளீடு_filter(ssh, c, buf, len) == -1) {
			debug2("channel %d: filter stops", c->self);
			chan_read_failed(ssh, c);
		}
	} இல்லையெனில் எனில் (c->datagram) {
		எனில் ((r = sshbuf_put_string(c->உள்ளீடு, buf, len)) != 0)
			fatal_fr(r, "channel %i: put datagram", c->self);
	} இல்லையெனில் எனில் ((r = sshbuf_put(c->உள்ளீடு, buf, len)) != 0)
		fatal_fr(r, "channel %i: put data", c->self);

	திரும்பு 1;
}

நிலையான முழு
channel_handle_wfd(கட்டமைப்பு ssh *ssh, Channel *c)
{
	கட்டமைப்பு termios tio;
	u_char *data = வெற்று, *buf; /* XXX const; need filter API change */
	size_t dlen, olen = 0;
	முழு r, len;

	எனில் ((c->io_ready & SSH_CHAN_IO_WFD) == 0)
		திரும்பு 1;
	எனில் (sshbuf_len(c->output) == 0)
		திரும்பு 1;

	/* Send buffered output data to the socket. */
	olen = sshbuf_len(c->output);
	எனில் (c->output_filter != வெற்று) {
		எனில் ((buf = c->output_filter(ssh, c, &data, &dlen)) == வெற்று) {
			debug2("channel %d: filter stops", c->self);
			எனில் (c->type != SSH_CHANNEL_OPEN)
				chan_mark_dead(ssh, c);
			இல்லையெனில்
				chan_write_failed(ssh, c);
			திரும்பு -1;
		}
	} இல்லையெனில் எனில் (c->datagram) {
		எனில் ((r = sshbuf_get_string(c->output, &data, &dlen)) != 0)
			fatal_fr(r, "channel %i: get datagram", c->self);
		buf = data;
	} இல்லையெனில் {
		buf = data = sshbuf_mutable_ptr(c->output);
		dlen = sshbuf_len(c->output);
	}

	எனில் (c->datagram) {
		/* ignore truncated writes, datagrams might get lost */
		len = லிக(c->wfd, buf, dlen);
		விடுவி(data);
		எனில் (len == -1 && (errno == EINTR || errno == EAGAIN ||
		    errno == EWOULDBLOCK))
			திரும்பு 1;
		எனில் (len <= 0)
			செல் write_fail;
		செல் out;
	}

#ifdef _AIX
	/* XXX: Later AIX versions can't push as much data to tty */
	எனில் (c->wfd_isatty)
		dlen = MINIMUM(dlen, 8*1024);
#endif

	len = லிக(c->wfd, buf, dlen);
	எனில் (len == -1 &&
	    (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
		திரும்பு 1;
	எனில் (len <= 0) {
 write_fail:
		எனில் (c->type != SSH_CHANNEL_OPEN) {
			debug2("channel %d: not open", c->self);
			chan_mark_dead(ssh, c);
			திரும்பு -1;
		} இல்லையெனில் {
			chan_write_failed(ssh, c);
		}
		திரும்பு -1;
	}
	channel_set_used_time(ssh, c);
#ifndef BROKEN_TCGETATTR_ICANON
	எனில் (c->isatty && dlen >= 1 && buf[0] != '\r') {
		எனில் (tcgetattr(c->wfd, &tio) == 0 &&
		    !(tio.c_lflag & ECHO) && (tio.c_lflag & ICANON)) {
			/*
			 * Simulate echo to reduce the impact of
			 * traffic analysis. We need to match the
			 * size of a SSH2_MSG_CHANNEL_DATA message
			 * (4 byte channel id + buf)
			 */
			எனில் ((r = sshpkt_செய்தி_ignore(ssh, 4+len)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "channel %i: ignore", c->self);
		}
	}
#endif /* BROKEN_TCGETATTR_ICANON */
	எனில் ((r = sshbuf_consume(c->output, len)) != 0)
		fatal_fr(r, "channel %i: consume", c->self);
 out:
	c->local_consumed += olen - sshbuf_len(c->output);

	திரும்பு 1;
}

நிலையான முழு
channel_handle_efd_write(கட்டமைப்பு ssh *ssh, Channel *c)
{
	முழு r;
	ssize_t len;

	எனில் ((c->io_ready & SSH_CHAN_IO_EFD_W) == 0)
		திரும்பு 1;
	எனில் (sshbuf_len(c->extended) == 0)
		திரும்பு 1;

	len = லிக(c->efd, sshbuf_ptr(c->extended),
	    sshbuf_len(c->extended));
	debug2("channel %d: written %zd to efd %d", c->self, len, c->efd);
	எனில் (len == -1 && (errno == EINTR || errno == EAGAIN ||
	    errno == EWOULDBLOCK))
		திரும்பு 1;
	எனில் (len <= 0) {
		debug2("channel %d: closing write-efd %d", c->self, c->efd);
		channel_close_fd(ssh, c, &c->efd);
	} இல்லையெனில் {
		எனில் ((r = sshbuf_consume(c->extended, len)) != 0)
			fatal_fr(r, "channel %i: consume", c->self);
		c->local_consumed += len;
		channel_set_used_time(ssh, c);
	}
	திரும்பு 1;
}

நிலையான முழு
channel_handle_efd_read(கட்டமைப்பு ssh *ssh, Channel *c)
{
	எழுத்து buf[CHAN_RBUF];
	ssize_t len;
	முழு r, force;

	force = c->isatty && c->detach_close && c->istate != CHAN_உள்ளீடு_CLOSED;

	எனில் (!force && (c->io_ready & SSH_CHAN_IO_EFD_R) == 0)
		திரும்பு 1;

	len = பட(c->efd, buf, அளவு(buf));
	debug2("channel %d: read %zd from efd %d", c->self, len, c->efd);
	எனில் (len == -1 && (errno == EINTR || ((errno == EAGAIN ||
	    errno == EWOULDBLOCK) && !force)))
		திரும்பு 1;
	எனில் (len <= 0) {
		debug2("channel %d: closing read-efd %d", c->self, c->efd);
		channel_close_fd(ssh, c, &c->efd);
		திரும்பு 1;
	}
	channel_set_used_time(ssh, c);
	எனில் (c->extended_usage == CHAN_EXTENDED_IGNORE)
		debug3("channel %d: discard efd", c->self);
	இல்லையெனில் எனில் ((r = sshbuf_put(c->extended, buf, len)) != 0)
		fatal_fr(r, "channel %i: append", c->self);
	திரும்பு 1;
}

நிலையான முழு
channel_handle_efd(கட்டமைப்பு ssh *ssh, Channel *c)
{
	எனில் (c->efd == -1)
		திரும்பு 1;

	/** XXX handle drain efd, too */

	எனில் (c->extended_usage == CHAN_EXTENDED_WRITE)
		திரும்பு channel_handle_efd_write(ssh, c);
	இல்லையெனில் எனில் (c->extended_usage == CHAN_EXTENDED_READ ||
	    c->extended_usage == CHAN_EXTENDED_IGNORE)
		திரும்பு channel_handle_efd_read(ssh, c);

	திரும்பு 1;
}

நிலையான முழு
channel_check_window(கட்டமைப்பு ssh *ssh, Channel *c)
{
	முழு r;

	எனில் (c->type == SSH_CHANNEL_OPEN &&
	    !(c->flags & (CHAN_CLOSE_SENT|CHAN_CLOSE_RCVD)) &&
	    ((c->local_window_max - c->local_window >
	    c->local_maxpacket*3) ||
	    c->local_window < c->local_window_max/2) &&
	    c->local_consumed > 0) {
		எனில் (!c->have_remote_id)
			fatal_f("channel %d: no remote id", c->self);
		எனில் ((r = sshpkt_start(ssh,
		    SSH2_செய்தி_CHANNEL_WINDOW_ADJUST)) != 0 ||
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
	திரும்பு 1;
}

நிலையான வெறுமை
channel_post_open(கட்டமைப்பு ssh *ssh, Channel *c)
{
	channel_handle_rfd(ssh, c);
	channel_handle_wfd(ssh, c);
	channel_handle_efd(ssh, c);
	channel_check_window(ssh, c);
}

நிலையான u_int
read_mux(கட்டமைப்பு ssh *ssh, Channel *c, u_int need)
{
	எழுத்து buf[CHAN_RBUF];
	ssize_t len;
	u_int rlen;
	முழு r;

	எனில் (sshbuf_len(c->உள்ளீடு) < need) {
		rlen = need - sshbuf_len(c->உள்ளீடு);
		len = பட(c->rfd, buf, MINIMUM(rlen, CHAN_RBUF));
		எனில் (len == -1 && (errno == EINTR || errno == EAGAIN))
			திரும்பு sshbuf_len(c->உள்ளீடு);
		எனில் (len <= 0) {
			debug2("channel %d: ctl read<=0 rfd %d len %zd",
			    c->self, c->rfd, len);
			chan_read_failed(ssh, c);
			திரும்பு 0;
		} இல்லையெனில் எனில் ((r = sshbuf_put(c->உள்ளீடு, buf, len)) != 0)
			fatal_fr(r, "channel %i: append", c->self);
	}
	திரும்பு sshbuf_len(c->உள்ளீடு);
}

நிலையான வெறுமை
channel_post_mux_client_read(கட்டமைப்பு ssh *ssh, Channel *c)
{
	u_int need;

	எனில் ((c->io_ready & SSH_CHAN_IO_RFD) == 0)
		திரும்பு;
	எனில் (c->istate != CHAN_உள்ளீடு_OPEN && c->istate != CHAN_உள்ளீடு_WAIT_DRAIN)
		திரும்பு;
	எனில் (c->mux_pause)
		திரும்பு;

	/*
	 * Don't not read past the precise end of packets to
	 * avoid disrupting fd passing.
	 */
	எனில் (read_mux(ssh, c, 4) < 4) /* read header */
		திரும்பு;
	/* XXX sshbuf_peek_u32 */
	need = PEEK_U32(sshbuf_ptr(c->உள்ளீடு));
#define CHANNEL_MUX_MAX_PACKET	(256 * 1024)
	எனில் (need > CHANNEL_MUX_MAX_PACKET) {
		debug2("channel %d: packet too big %u > %u",
		    c->self, CHANNEL_MUX_MAX_PACKET, need);
		chan_rcvd_oclose(ssh, c);
		திரும்பு;
	}
	எனில் (read_mux(ssh, c, need + 4) < need + 4) /* read body */
		திரும்பு;
	எனில் (c->mux_rcb(ssh, c) != 0) {
		debug("channel %d: mux_rcb failed", c->self);
		chan_mark_dead(ssh, c);
		திரும்பு;
	}
}

நிலையான வெறுமை
channel_post_mux_client_write(கட்டமைப்பு ssh *ssh, Channel *c)
{
	ssize_t len;
	முழு r;

	எனில் ((c->io_ready & SSH_CHAN_IO_WFD) == 0)
		திரும்பு;
	எனில் (sshbuf_len(c->output) == 0)
		திரும்பு;

	len = லிக(c->wfd, sshbuf_ptr(c->output), sshbuf_len(c->output));
	எனில் (len == -1 && (errno == EINTR || errno == EAGAIN))
		திரும்பு;
	எனில் (len <= 0) {
		chan_mark_dead(ssh, c);
		திரும்பு;
	}
	எனில் ((r = sshbuf_consume(c->output, len)) != 0)
		fatal_fr(r, "channel %i: consume", c->self);
}

நிலையான வெறுமை
channel_post_mux_client(கட்டமைப்பு ssh *ssh, Channel *c)
{
	channel_post_mux_client_read(ssh, c);
	channel_post_mux_client_write(ssh, c);
}

நிலையான வெறுமை
channel_post_mux_listener(கட்டமைப்பு ssh *ssh, Channel *c)
{
	Channel *nc;
	கட்டமைப்பு sockaddr_storage addr;
	socklen_t addrlen;
	முழு newsock;
	uid_t euid;
	gid_t egid;

	எனில் ((c->io_ready & SSH_CHAN_IO_SOCK_R) == 0)
		திரும்பு;

	debug("multiplexing control connection");

	/*
	 * Accept connection on control socket
	 */
	memset(&addr, 0, அளவு(addr));
	addrlen = அளவு(addr);
	எனில் ((newsock = accept(c->sock, (கட்டமைப்பு sockaddr*)&addr,
	    &addrlen)) == -1) {
		error_f("accept: %s", strerror(errno));
		எனில் (errno == EMFILE || errno == ENFILE)
			c->notbefore = monotime_double() + 1.0;
		திரும்பு;
	}

	எனில் (getpeereid(newsock, &euid, &egid) == -1) {
		error_f("getpeereid failed: %s", strerror(errno));
		close(newsock);
		திரும்பு;
	}
	எனில் ((euid != 0) && (getuid() != euid)) {
		error("multiplex uid mismatch: peer euid %u != uid %u",
		    (u_int)euid, (u_int)getuid());
		close(newsock);
		திரும்பு;
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

நிலையான வெறுமை
channel_handler_init(கட்டமைப்பு ssh_channels *sc)
{
	chan_fn **pre, **post;

	எனில் ((pre = calloc(SSH_CHANNEL_MAX_TYPE, அளவு(*pre))) == வெற்று ||
	    (post = calloc(SSH_CHANNEL_MAX_TYPE, அளவு(*post))) == வெற்று)
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
நிலையான வெறுமை
channel_garbage_collect(கட்டமைப்பு ssh *ssh, Channel *c)
{
	எனில் (c == வெற்று)
		திரும்பு;
	எனில் (c->detach_user != வெற்று) {
		எனில் (!chan_is_dead(ssh, c, c->detach_close))
			திரும்பு;

		debug2("channel %d: gc: notify user", c->self);
		c->detach_user(ssh, c->self, 0, வெற்று);
		/* if we still have a callback */
		எனில் (c->detach_user != வெற்று)
			திரும்பு;
		debug2("channel %d: gc: user detached", c->self);
	}
	எனில் (!chan_is_dead(ssh, c, 1))
		திரும்பு;
	debug2("channel %d: garbage collecting", c->self);
	channel_free(ssh, c);
}

எண்ணிக்கை channel_table { CHAN_PRE, CHAN_POST };

நிலையான வெறுமை
channel_handler(கட்டமைப்பு ssh *ssh, முழு table, கட்டமைப்பு timespec *timeout)
{
	கட்டமைப்பு ssh_channels *sc = ssh->chanctxt;
	chan_fn **ftab = table == CHAN_PRE ? sc->channel_pre : sc->channel_post;
	u_int i, oalloc;
	Channel *c;
	இரட்டை now;

	now = monotime_double();
	க்கு (sc->nbulk = i = 0, oalloc = sc->channels_alloc; i < oalloc; i++) {
		c = sc->channels[i];
		எனில் (c == வெற்று)
			தொடர்;
		/* Count open channels in bulk state */
		எனில் (c->type == SSH_CHANNEL_OPEN && c->bulk)
			sc->nbulk++;
		/* Try to keep IO going while rekeying */
		எனில் (ssh_packet_is_rekeying(ssh) && c->type != SSH_CHANNEL_OPEN)
			தொடர்;
		எனில் (c->delayed) {
			எனில் (table == CHAN_PRE)
				c->delayed = 0;
			இல்லையெனில்
				தொடர்;
		}
		எனில் (ftab[c->type] != வெற்று) {
			எனில் (table == CHAN_PRE && c->type == SSH_CHANNEL_OPEN &&
			    channel_get_expiry(ssh, c) != 0 &&
			    now >= channel_get_expiry(ssh, c)) {
				/* channel closed for inactivity */
				இரட்டை deadline = c->inactive_deadline != 0.0 ?
				    c->inactive_deadline : sc->global_deadline;
				verbose("channel %d: closing after %f seconds "
				    "of inactivity", c->self, deadline);
				channel_force_close(ssh, c, 1);
			} இல்லையெனில் எனில் (c->notbefore <= now) {
				/* Run handlers that are not paused. */
				(*ftab[c->type])(ssh, c);
				/* inactivity timeouts must interrupt poll() */
				எனில் (timeout != வெற்று &&
				    c->type == SSH_CHANNEL_OPEN &&
				    channel_get_expiry(ssh, c) != 0) {
					ptimeout_deadline_monotime_double(timeout,
					    channel_get_expiry(ssh, c));
				}
			} இல்லையெனில் எனில் (timeout != வெற்று) {
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
நிலையான வெறுமை
channel_before_prepare_io(கட்டமைப்பு ssh *ssh)
{
	கட்டமைப்பு ssh_channels *sc = ssh->chanctxt;
	Channel *c;
	u_int i, oalloc;

	க்கு (i = 0, oalloc = sc->channels_alloc; i < oalloc; i++) {
		c = sc->channels[i];
		எனில் (c == வெற்று)
			தொடர்;
		எனில் (c->type == SSH_CHANNEL_RDYNAMIC_OPEN)
			channel_before_prepare_io_rdynamic(ssh, c);
	}
}

நிலையான வெறுமை
dump_channel_poll(மாறிலி எழுத்து *func, மாறிலி எழுத்து *what, Channel *c,
    u_int pollfd_offset, கட்டமைப்பு pollfd *pfd)
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
நிலையான வெறுமை
channel_prepare_pollfd(Channel *c, u_int *next_pollfd,
    கட்டமைப்பு pollfd *pfd, u_int npfd)
{
	u_int ev, p = *next_pollfd;

	எனில் (c == வெற்று)
		திரும்பு;
	எனில் (p + 4 > npfd) {
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
	எனில் (c->rfd != -1) {
		ev = 0;
		எனில் ((c->io_want & SSH_CHAN_IO_RFD) != 0)
			ev |= POLLIN;
		/* rfd == wfd */
		எனில் (c->wfd == c->rfd) {
			எனில் ((c->io_want & SSH_CHAN_IO_WFD) != 0)
				ev |= POLLOUT;
		}
		/* rfd == efd */
		எனில் (c->efd == c->rfd) {
			எனில் ((c->io_want & SSH_CHAN_IO_EFD_R) != 0)
				ev |= POLLIN;
			எனில் ((c->io_want & SSH_CHAN_IO_EFD_W) != 0)
				ev |= POLLOUT;
		}
		/* rfd == sock */
		எனில் (c->sock == c->rfd) {
			எனில் ((c->io_want & SSH_CHAN_IO_SOCK_R) != 0)
				ev |= POLLIN;
			எனில் ((c->io_want & SSH_CHAN_IO_SOCK_W) != 0)
				ev |= POLLOUT;
		}
		/* Pack a pfd entry if any event armed for this fd */
		எனில் (ev != 0) {
			c->pfds[0] = p;
			pfd[p].fd = c->rfd;
			pfd[p].events = ev;
			dump_channel_poll(__func__, "rfd", c, p, &pfd[p]);
			p++;
		}
	}
	/* prepare c->wfd if wanting IO and not already handled above */
	எனில் (c->wfd != -1 && c->rfd != c->wfd) {
		ev = 0;
		எனில் ((c->io_want & SSH_CHAN_IO_WFD))
			ev |= POLLOUT;
		/* Pack a pfd entry if any event armed for this fd */
		எனில் (ev != 0) {
			c->pfds[1] = p;
			pfd[p].fd = c->wfd;
			pfd[p].events = ev;
			dump_channel_poll(__func__, "wfd", c, p, &pfd[p]);
			p++;
		}
	}
	/* prepare c->efd if wanting IO and not already handled above */
	எனில் (c->efd != -1 && c->rfd != c->efd) {
		ev = 0;
		எனில் ((c->io_want & SSH_CHAN_IO_EFD_R) != 0)
			ev |= POLLIN;
		எனில் ((c->io_want & SSH_CHAN_IO_EFD_W) != 0)
			ev |= POLLOUT;
		/* Pack a pfd entry if any event armed for this fd */
		எனில் (ev != 0) {
			c->pfds[2] = p;
			pfd[p].fd = c->efd;
			pfd[p].events = ev;
			dump_channel_poll(__func__, "efd", c, p, &pfd[p]);
			p++;
		}
	}
	/* prepare c->sock if wanting IO and not already handled above */
	எனில் (c->sock != -1 && c->rfd != c->sock) {
		ev = 0;
		எனில் ((c->io_want & SSH_CHAN_IO_SOCK_R) != 0)
			ev |= POLLIN;
		எனில் ((c->io_want & SSH_CHAN_IO_SOCK_W) != 0)
			ev |= POLLOUT;
		/* Pack a pfd entry if any event armed for this fd */
		எனில் (ev != 0) {
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
வெறுமை
channel_prepare_poll(கட்டமைப்பு ssh *ssh, கட்டமைப்பு pollfd **pfdp, u_int *npfd_allocp,
    u_int *npfd_activep, u_int npfd_reserved, கட்டமைப்பு timespec *timeout)
{
	கட்டமைப்பு ssh_channels *sc = ssh->chanctxt;
	u_int i, oalloc, p, npfd = npfd_reserved;

	channel_before_prepare_io(ssh); /* might create a new channel */
	/* clear out I/O flags from last poll */
	க்கு (i = 0; i < sc->channels_alloc; i++) {
		எனில் (sc->channels[i] == வெற்று)
			தொடர்;
		sc->channels[i]->io_want = sc->channels[i]->io_ready = 0;
	}
	/* Allocate 4x pollfd for each channel (rfd, wfd, efd, sock) */
	எனில் (sc->channels_alloc >= (INT_MAX / 4) - npfd_reserved)
		fatal_f("too many channels"); /* shouldn't happen */
	npfd += sc->channels_alloc * 4;
	எனில் (npfd > *npfd_allocp) {
		*pfdp = xrecallocarray(*pfdp, *npfd_allocp,
		    npfd, அளவு(**pfdp));
		*npfd_allocp = npfd;
	}
	*npfd_activep = npfd_reserved;
	oalloc = sc->channels_alloc;

	channel_handler(ssh, CHAN_PRE, timeout);

	எனில் (oalloc != sc->channels_alloc) {
		/* shouldn't happen */
		fatal_f("channels_alloc changed during CHAN_PRE "
		    "(was %u, now %u)", oalloc, sc->channels_alloc);
	}

	/* Prepare pollfd */
	p = npfd_reserved;
	க்கு (i = 0; i < sc->channels_alloc; i++)
		channel_prepare_pollfd(sc->channels[i], &p, *pfdp, npfd);
	*npfd_activep = p;
}

நிலையான வெறுமை
fd_ready(Channel *c, முழு p, கட்டமைப்பு pollfd *pfds, u_int npfd, முழு fd,
    மாறிலி எழுத்து *what, u_int revents_mask, u_int ready)
{
	கட்டமைப்பு pollfd *pfd = &pfds[p];

	எனில் (fd == -1)
		திரும்பு;
	எனில் (p == -1 || (u_int)p >= npfd)
		fatal_f("channel %d: bad pfd %d (max %u)", c->self, p, npfd);
	dump_channel_poll(__func__, what, c, p, pfd);
	எனில் (pfd->fd != fd) {
		fatal("channel %d: inconsistent %s fd=%d pollfd[%u].fd %d "
		    "r%d w%d e%d s%d", c->self, what, fd, p, pfd->fd,
		    c->rfd, c->wfd, c->efd, c->sock);
	}
	எனில் ((pfd->revents & POLLNVAL) != 0) {
		fatal("channel %d: invalid %s pollfd[%u].fd %d r%d w%d e%d s%d",
		    c->self, what, p, pfd->fd, c->rfd, c->wfd, c->efd, c->sock);
	}
	எனில் ((pfd->revents & (revents_mask|POLLHUP|POLLERR)) != 0)
		c->io_ready |= ready & c->io_want;
}

/*
 * After poll, perform any appropriate operations for channels which have
 * events pending.
 */
வெறுமை
channel_after_poll(கட்டமைப்பு ssh *ssh, கட்டமைப்பு pollfd *pfd, u_int npfd)
{
	கட்டமைப்பு ssh_channels *sc = ssh->chanctxt;
	u_int i;
	முழு p;
	Channel *c;

#ifdef DEBUG_CHANNEL_POLL
	க்கு (p = 0; p < (முழு)npfd; p++) {
		எனில் (pfd[p].revents == 0)
			தொடர்;
		debug_f("pfd[%u].fd %d rev 0x%04x",
		    p, pfd[p].fd, pfd[p].revents);
	}
#endif

	/* Convert pollfd into c->io_ready */
	க்கு (i = 0; i < sc->channels_alloc; i++) {
		c = sc->channels[i];
		எனில் (c == வெற்று)
			தொடர்;
		/* if rfd is shared with efd/sock then wfd should be too */
		எனில் (c->rfd != -1 && c->wfd != -1 && c->rfd != c->wfd &&
		    (c->rfd == c->efd || c->rfd == c->sock)) {
			/* Shouldn't happen */
			fatal_f("channel %d: unexpected fds r%d w%d e%d s%d",
			    c->self, c->rfd, c->wfd, c->efd, c->sock);
		}
		c->io_ready = 0;
		/* rfd, potentially shared with wfd, efd and sock */
		எனில் (c->rfd != -1 && (p = c->pfds[0]) != -1) {
			fd_ready(c, p, pfd, npfd, c->rfd,
			    "rfd", POLLIN, SSH_CHAN_IO_RFD);
			எனில் (c->rfd == c->wfd) {
				fd_ready(c, p, pfd, npfd, c->wfd,
				    "wfd/r", POLLOUT, SSH_CHAN_IO_WFD);
			}
			எனில் (c->rfd == c->efd) {
				fd_ready(c, p, pfd, npfd, c->efd,
				    "efdr/r", POLLIN, SSH_CHAN_IO_EFD_R);
				fd_ready(c, p, pfd, npfd, c->efd,
				    "efdw/r", POLLOUT, SSH_CHAN_IO_EFD_W);
			}
			எனில் (c->rfd == c->sock) {
				fd_ready(c, p, pfd, npfd, c->sock,
				    "sockr/r", POLLIN, SSH_CHAN_IO_SOCK_R);
				fd_ready(c, p, pfd, npfd, c->sock,
				    "sockw/r", POLLOUT, SSH_CHAN_IO_SOCK_W);
			}
			dump_channel_poll(__func__, "rfd", c, p, pfd);
		}
		/* wfd */
		எனில் (c->wfd != -1 && c->wfd != c->rfd &&
		    (p = c->pfds[1]) != -1) {
			fd_ready(c, p, pfd, npfd, c->wfd,
			    "wfd", POLLOUT, SSH_CHAN_IO_WFD);
			dump_channel_poll(__func__, "wfd", c, p, pfd);
		}
		/* efd */
		எனில் (c->efd != -1 && c->efd != c->rfd &&
		    (p = c->pfds[2]) != -1) {
			fd_ready(c, p, pfd, npfd, c->efd,
			    "efdr", POLLIN, SSH_CHAN_IO_EFD_R);
			fd_ready(c, p, pfd, npfd, c->efd,
			    "efdw", POLLOUT, SSH_CHAN_IO_EFD_W);
			dump_channel_poll(__func__, "efd", c, p, pfd);
		}
		/* sock */
		எனில் (c->sock != -1 && c->sock != c->rfd &&
		    (p = c->pfds[3]) != -1) {
			fd_ready(c, p, pfd, npfd, c->sock,
			    "sockr", POLLIN, SSH_CHAN_IO_SOCK_R);
			fd_ready(c, p, pfd, npfd, c->sock,
			    "sockw", POLLOUT, SSH_CHAN_IO_SOCK_W);
			dump_channel_poll(__func__, "sock", c, p, pfd);
		}
	}
	channel_handler(ssh, CHAN_POST, வெற்று);
}

/*
 * Enqueue data for channels with open or draining c->input.
 * Returns non-zero if a packet was enqueued.
 */
நிலையான முழு
channel_output_poll_உள்ளீடு_open(கட்டமைப்பு ssh *ssh, Channel *c)
{
	size_t len, plen;
	மாறிலி u_char *pkt;
	முழு r;

	எனில் ((len = sshbuf_len(c->உள்ளீடு)) == 0) {
		எனில் (c->istate == CHAN_உள்ளீடு_WAIT_DRAIN) {
			/*
			 * input-buffer is empty and read-socket shutdown:
			 * tell peer, that we will not send more data:
			 * send IEOF.
			 * hack for extended data: delay EOF if EFD still
			 * in use.
			 */
			எனில் (CHANNEL_EFD_உள்ளீடு_ACTIVE(c))
				debug2("channel %d: "
				    "ibuf_empty delayed efd %d/(%zu)",
				    c->self, c->efd, sshbuf_len(c->extended));
			இல்லையெனில்
				chan_ibuf_empty(ssh, c);
		}
		திரும்பு 0;
	}

	எனில் (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);

	எனில் (c->datagram) {
		/* Check datagram will fit; drop if not */
		எனில் ((r = sshbuf_get_string_direct(c->உள்ளீடு, &pkt, &plen)) != 0)
			fatal_fr(r, "channel %i: get datagram", c->self);
		/*
		 * XXX this does tail-drop on the datagram queue which is
		 * usually suboptimal compared to head-drop. Better to have
		 * backpressure at read time? (i.e. read + discard)
		 */
		எனில் (plen > c->remote_window || plen > c->remote_maxpacket) {
			debug("channel %d: datagram too big", c->self);
			திரும்பு 0;
		}
		/* Enqueue it */
		எனில் ((r = sshpkt_start(ssh, SSH2_செய்தி_CHANNEL_DATA)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
		    (r = sshpkt_put_string(ssh, pkt, plen)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "channel %i: send datagram", c->self);
		c->remote_window -= plen;
		திரும்பு 1;
	}

	/* Enqueue packet for buffered data. */
	எனில் (len > c->remote_window)
		len = c->remote_window;
	எனில் (len > c->remote_maxpacket)
		len = c->remote_maxpacket;
	எனில் (len == 0)
		திரும்பு 0;
	எனில் ((r = sshpkt_start(ssh, SSH2_செய்தி_CHANNEL_DATA)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_string(ssh, sshbuf_ptr(c->உள்ளீடு), len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i: send data", c->self);
	எனில் ((r = sshbuf_consume(c->உள்ளீடு, len)) != 0)
		fatal_fr(r, "channel %i: consume", c->self);
	c->remote_window -= len;
	திரும்பு 1;
}

/*
 * Enqueue data for channels with open c->extended in read mode.
 * Returns non-zero if a packet was enqueued.
 */
நிலையான முழு
channel_output_poll_extended_read(கட்டமைப்பு ssh *ssh, Channel *c)
{
	size_t len;
	முழு r;

	எனில் ((len = sshbuf_len(c->extended)) == 0)
		திரும்பு 0;

	debug2("channel %d: rwin %u elen %zu euse %d", c->self,
	    c->remote_window, sshbuf_len(c->extended), c->extended_usage);
	எனில் (len > c->remote_window)
		len = c->remote_window;
	எனில் (len > c->remote_maxpacket)
		len = c->remote_maxpacket;
	எனில் (len == 0)
		திரும்பு 0;
	எனில் (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);
	எனில் ((r = sshpkt_start(ssh, SSH2_செய்தி_CHANNEL_EXTENDED_DATA)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_u32(ssh, SSH2_EXTENDED_DATA_STDERR)) != 0 ||
	    (r = sshpkt_put_string(ssh, sshbuf_ptr(c->extended), len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i: data", c->self);
	எனில் ((r = sshbuf_consume(c->extended, len)) != 0)
		fatal_fr(r, "channel %i: consume", c->self);
	c->remote_window -= len;
	debug2("channel %d: sent ext data %zu", c->self, len);
	திரும்பு 1;
}

/*
 * If there is data to send to the connection, enqueue some of it now.
 * Returns non-zero if data was enqueued.
 */
முழு
channel_output_poll(கட்டமைப்பு ssh *ssh)
{
	கட்டமைப்பு ssh_channels *sc = ssh->chanctxt;
	Channel *c;
	u_int i;
	முழு ret = 0;

	க்கு (i = 0; i < sc->channels_alloc; i++) {
		c = sc->channels[i];
		எனில் (c == வெற்று)
			தொடர்;

		/*
		 * We are only interested in channels that can have buffered
		 * incoming data.
		 */
		எனில் (c->type != SSH_CHANNEL_OPEN)
			தொடர்;
		எனில் ((c->flags & (CHAN_CLOSE_SENT|CHAN_CLOSE_RCVD))) {
			/* XXX is this true? */
			debug3("channel %d: will not send data after close",
			    c->self);
			தொடர்;
		}

		/* Get the amount of buffered data for this channel. */
		எனில் (c->istate == CHAN_உள்ளீடு_OPEN ||
		    c->istate == CHAN_உள்ளீடு_WAIT_DRAIN)
			ret |= channel_output_poll_உள்ளீடு_open(ssh, c);
		/* Send extended data, i.e. stderr */
		எனில் (!(c->flags & CHAN_EOF_SENT) &&
		    c->extended_usage == CHAN_EXTENDED_READ)
			ret |= channel_output_poll_extended_read(ssh, c);
	}
	திரும்பு ret;
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
முழு
channel_proxy_downstream(கட்டமைப்பு ssh *ssh, Channel *downstream)
{
	Channel *c = வெற்று;
	கட்டமைப்பு sshbuf *original = வெற்று, *modified = வெற்று;
	மாறிலி u_char *cp;
	எழுத்து *ctype = வெற்று, *listen_host = வெற்று;
	u_char type;
	size_t have;
	முழு ret = -1, r;
	u_int id, remote_id, listen_port;

	/* sshbuf_dump(downstream->input, stderr); */
	எனில் ((r = sshbuf_get_string_direct(downstream->உள்ளீடு, &cp, &have))
	    != 0) {
		error_fr(r, "parse");
		திரும்பு -1;
	}
	எனில் (have < 2) {
		error_f("short message");
		திரும்பு -1;
	}
	type = cp[1];
	/* skip padlen + type */
	cp += 2;
	have -= 2;
	எனில் (ssh_packet_log_type(type))
		debug3_f("channel %u: down->up: type %u",
		    downstream->self, type);

	தேர்வு (type) {
	நிலை SSH2_செய்தி_CHANNEL_OPEN:
		எனில் ((original = sshbuf_from(cp, have)) == வெற்று ||
		    (modified = sshbuf_new()) == வெற்று) {
			error_f("alloc");
			செல் out;
		}
		எனில் ((r = sshbuf_get_cstring(original, &ctype, வெற்று)) != 0 ||
		    (r = sshbuf_get_u32(original, &id)) != 0) {
			error_fr(r, "parse");
			செல் out;
		}
		c = channel_new(ssh, "mux-proxy", SSH_CHANNEL_MUX_PROXY,
		    -1, -1, -1, 0, 0, 0, ctype, 1);
		c->mux_ctx = downstream;	/* point to mux client */
		c->mux_downstream_id = id;	/* original downstream id */
		எனில் ((r = sshbuf_put_cstring(modified, ctype)) != 0 ||
		    (r = sshbuf_put_u32(modified, c->self)) != 0 ||
		    (r = sshbuf_putb(modified, original)) != 0) {
			error_fr(r, "compose");
			channel_free(ssh, c);
			செல் out;
		}
		நிறுத்து;
	நிலை SSH2_செய்தி_CHANNEL_OPEN_CONFIRMATION:
		/*
		 * Almost the same as SSH2_MSG_CHANNEL_OPEN, except then we
		 * need to parse 'remote_id' instead of 'ctype'.
		 */
		எனில் ((original = sshbuf_from(cp, have)) == வெற்று ||
		    (modified = sshbuf_new()) == வெற்று) {
			error_f("alloc");
			செல் out;
		}
		எனில் ((r = sshbuf_get_u32(original, &remote_id)) != 0 ||
		    (r = sshbuf_get_u32(original, &id)) != 0) {
			error_fr(r, "parse");
			செல் out;
		}
		c = channel_new(ssh, "mux-proxy", SSH_CHANNEL_MUX_PROXY,
		    -1, -1, -1, 0, 0, 0, "mux-down-connect", 1);
		c->mux_ctx = downstream;	/* point to mux client */
		c->mux_downstream_id = id;
		c->remote_id = remote_id;
		c->have_remote_id = 1;
		எனில் ((r = sshbuf_put_u32(modified, remote_id)) != 0 ||
		    (r = sshbuf_put_u32(modified, c->self)) != 0 ||
		    (r = sshbuf_putb(modified, original)) != 0) {
			error_fr(r, "compose");
			channel_free(ssh, c);
			செல் out;
		}
		நிறுத்து;
	நிலை SSH2_செய்தி_GLOBAL_REQUEST:
		எனில் ((original = sshbuf_from(cp, have)) == வெற்று) {
			error_f("alloc");
			செல் out;
		}
		எனில் ((r = sshbuf_get_cstring(original, &ctype, வெற்று)) != 0) {
			error_fr(r, "parse");
			செல் out;
		}
		எனில் (strcmp(ctype, "tcpip-forward") != 0) {
			error_f("unsupported request %s", ctype);
			செல் out;
		}
		எனில் ((r = sshbuf_get_u8(original, வெற்று)) != 0 ||
		    (r = sshbuf_get_cstring(original, &listen_host, வெற்று)) != 0 ||
		    (r = sshbuf_get_u32(original, &listen_port)) != 0) {
			error_fr(r, "parse");
			செல் out;
		}
		எனில் (listen_port > 65535) {
			error_f("tcpip-forward for %s: bad port %u",
			    listen_host, listen_port);
			செல் out;
		}
		/* Record that connection to this host/port is permitted. */
		permission_set_add(ssh, FORWARD_USER, FORWARD_LOCAL, "<mux>",
		    -1, listen_host, வெற்று, (முழு)listen_port, downstream);
		நிறுத்து;
	நிலை SSH2_செய்தி_CHANNEL_CLOSE:
		எனில் (have < 4)
			நிறுத்து;
		remote_id = PEEK_U32(cp);
		எனில் ((c = channel_by_remote_id(ssh, remote_id)) != வெற்று) {
			எனில் (c->flags & CHAN_CLOSE_RCVD)
				channel_free(ssh, c);
			இல்லையெனில்
				c->flags |= CHAN_CLOSE_SENT;
		}
		நிறுத்து;
	}
	எனில் (modified) {
		எனில் ((r = sshpkt_start(ssh, type)) != 0 ||
		    (r = sshpkt_putb(ssh, modified)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0) {
			error_fr(r, "send");
			செல் out;
		}
	} இல்லையெனில் {
		எனில் ((r = sshpkt_start(ssh, type)) != 0 ||
		    (r = sshpkt_put(ssh, cp, have)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0) {
			error_fr(r, "send");
			செல் out;
		}
	}
	ret = 0;
 out:
	விடுவி(ctype);
	விடுவி(listen_host);
	sshbuf_free(original);
	sshbuf_free(modified);
	திரும்பு ret;
}

/*
 * receive packets from upstream server and de-multiplex packets
 * to correct downstream:
 * implemented as a helper for channel input handlers,
 * replaces local (proxy) channel ID with downstream channel ID.
 */
முழு
channel_proxy_upstream(Channel *c, முழு type, uint32_t seq, கட்டமைப்பு ssh *ssh)
{
	கட்டமைப்பு sshbuf *b = வெற்று;
	Channel *downstream;
	மாறிலி u_char *cp = வெற்று;
	size_t len;
	முழு r;

	/*
	 * When receiving packets from the peer we need to check whether we
	 * need to forward the packets to the mux client. In this case we
	 * restore the original channel id and keep track of CLOSE messages,
	 * so we can cleanup the channel.
	 */
	எனில் (c == வெற்று || c->type != SSH_CHANNEL_MUX_PROXY)
		திரும்பு 0;
	எனில் ((downstream = c->mux_ctx) == வெற்று)
		திரும்பு 0;
	தேர்வு (type) {
	நிலை SSH2_செய்தி_CHANNEL_CLOSE:
	நிலை SSH2_செய்தி_CHANNEL_DATA:
	நிலை SSH2_செய்தி_CHANNEL_EOF:
	நிலை SSH2_செய்தி_CHANNEL_EXTENDED_DATA:
	நிலை SSH2_செய்தி_CHANNEL_OPEN_CONFIRMATION:
	நிலை SSH2_செய்தி_CHANNEL_OPEN_FAILURE:
	நிலை SSH2_செய்தி_CHANNEL_WINDOW_ADJUST:
	நிலை SSH2_செய்தி_CHANNEL_SUCCESS:
	நிலை SSH2_செய்தி_CHANNEL_FAILURE:
	நிலை SSH2_செய்தி_CHANNEL_REQUEST:
		நிறுத்து;
	இயல்பு:
		debug2_f("channel %u: unsupported type %u", c->self, type);
		திரும்பு 0;
	}
	எனில் ((b = sshbuf_new()) == வெற்று) {
		error_f("alloc reply");
		செல் out;
	}
	/* get remaining payload (after id) */
	cp = sshpkt_ptr(ssh, &len);
	எனில் (cp == வெற்று) {
		error_f("no packet");
		செல் out;
	}
	/* translate id and send to muxclient */
	எனில் ((r = sshbuf_put_u8(b, 0)) != 0 ||	/* padlen */
	    (r = sshbuf_put_u8(b, type)) != 0 ||
	    (r = sshbuf_put_u32(b, c->mux_downstream_id)) != 0 ||
	    (r = sshbuf_put(b, cp, len)) != 0 ||
	    (r = sshbuf_put_stringb(downstream->output, b)) != 0) {
		error_fr(r, "compose muxclient");
		செல் out;
	}
	/* sshbuf_dump(b, stderr); */
	எனில் (ssh_packet_log_type(type))
		debug3_f("channel %u: up->down: type %u", c->self, type);
 out:
	/* update state */
	தேர்வு (type) {
	நிலை SSH2_செய்தி_CHANNEL_OPEN_CONFIRMATION:
		/* record remote_id for SSH2_MSG_CHANNEL_CLOSE */
		எனில் (cp && len > 4) {
			c->remote_id = PEEK_U32(cp);
			c->have_remote_id = 1;
		}
		நிறுத்து;
	நிலை SSH2_செய்தி_CHANNEL_CLOSE:
		எனில் (c->flags & CHAN_CLOSE_SENT)
			channel_free(ssh, c);
		இல்லையெனில்
			c->flags |= CHAN_CLOSE_RCVD;
		நிறுத்து;
	}
	sshbuf_free(b);
	திரும்பு 1;
}

/* -- protocol input */

/* Parse a channel ID from the current packet */
நிலையான முழு
channel_parse_id(கட்டமைப்பு ssh *ssh, மாறிலி எழுத்து *where, மாறிலி எழுத்து *what)
{
	uint32_t id;
	முழு r;

	எனில் ((r = sshpkt_get_u32(ssh, &id)) != 0) {
		error_r(r, "%s: parse id", where);
		ssh_packet_disconnect(ssh, "Invalid %s message", what);
	}
	எனில் (id > INT_MAX) {
		error_r(r, "%s: bad channel id %u", where, id);
		ssh_packet_disconnect(ssh, "Invalid %s channel id", what);
	}
	திரும்பு (முழு)id;
}

/* Lookup a channel from an ID in the current packet */
நிலையான Channel *
channel_from_packet_id(கட்டமைப்பு ssh *ssh, மாறிலி எழுத்து *where, மாறிலி எழுத்து *what)
{
	முழு id = channel_parse_id(ssh, where, what);
	Channel *c;

	எனில் ((c = channel_lookup(ssh, id)) == வெற்று) {
		ssh_packet_disconnect(ssh,
		    "%s packet referred to nonexistent channel %d", what, id);
	}
	திரும்பு c;
}

முழு
channel_உள்ளீடு_data(முழு type, uint32_t seq, கட்டமைப்பு ssh *ssh)
{
	மாறிலி u_char *data;
	size_t data_len, win_len;
	Channel *c = channel_from_packet_id(ssh, __func__, "data");
	முழு r;

	எனில் (channel_proxy_upstream(c, type, seq, ssh))
		திரும்பு 0;

	/* Ignore any data for non-open channels (might happen on close) */
	எனில் (c->type != SSH_CHANNEL_OPEN &&
	    c->type != SSH_CHANNEL_RDYNAMIC_OPEN &&
	    c->type != SSH_CHANNEL_RDYNAMIC_FINISH &&
	    c->type != SSH_CHANNEL_X11_OPEN)
		திரும்பு 0;

	/* Get the data. */
	எனில் ((r = sshpkt_get_string_direct(ssh, &data, &data_len)) != 0 ||
            (r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "channel %i: get data", c->self);

	win_len = data_len;
	எனில் (c->datagram)
		win_len += 4;  /* string length header */

	/*
	 * The sending side reduces its window as it sends data, so we
	 * must 'fake' consumption of the data in order to ensure that window
	 * updates are sent back. Otherwise the connection might deadlock.
	 */
	எனில் (c->ostate != CHAN_OUTPUT_OPEN) {
		எனில் (win_len > c->local_window)
			c->local_window = 0;
		இல்லையெனில்
			c->local_window -= win_len;
		c->local_consumed += win_len;
		திரும்பு 0;
	}

	எனில் (win_len > c->local_maxpacket) {
		logit("channel %d: rcvd big packet %zu, maxpack %u",
		    c->self, win_len, c->local_maxpacket);
		திரும்பு 0;
	}
	எனில் (win_len > c->local_window) {
		u_int delta = win_len - c->local_window;

		எனில் (c->local_window_exceeded > UINT_MAX - delta)
			c->local_window_exceeded = UINT_MAX;
		இல்லையெனில்
			c->local_window_exceeded += delta;
		logit("channel %d: rcvd too much data %zu, win %u/%u "
		    "(excess %u)", c->self, win_len, c->local_window,
		    c->local_window_max, c->local_window_exceeded);
		c->local_window = 0;
		/* Allow 10% grace before bringing the hammer down */
		எனில் (c->local_window_exceeded > (c->local_window_max / 10)) {
			ssh_packet_disconnect(ssh, "channel %d: peer ignored "
			    "channel window", c->self);
		}
	} இல்லையெனில் {
		c->local_window -= win_len;
		c->local_window_exceeded = 0;
	}

	எனில் (c->datagram) {
		எனில் ((r = sshbuf_put_string(c->output, data, data_len)) != 0)
			fatal_fr(r, "channel %i: append datagram", c->self);
	} இல்லையெனில் எனில் ((r = sshbuf_put(c->output, data, data_len)) != 0)
		fatal_fr(r, "channel %i: append data", c->self);

	திரும்பு 0;
}

முழு
channel_உள்ளீடு_extended_data(முழு type, uint32_t seq, கட்டமைப்பு ssh *ssh)
{
	மாறிலி u_char *data;
	size_t data_len;
	uint32_t tcode;
	Channel *c = channel_from_packet_id(ssh, __func__, "extended data");
	முழு r;

	எனில் (channel_proxy_upstream(c, type, seq, ssh))
		திரும்பு 0;
	எனில் (c->type != SSH_CHANNEL_OPEN) {
		logit("channel %d: ext data for non open", c->self);
		திரும்பு 0;
	}
	எனில் (c->flags & CHAN_EOF_RCVD) {
		எனில் (ssh->compat & SSH_BUG_EXTEOF)
			debug("channel %d: accepting ext data after eof",
			    c->self);
		இல்லையெனில்
			ssh_packet_disconnect(ssh, "Received extended_data "
			    "after EOF on channel %d.", c->self);
	}

	எனில் ((r = sshpkt_get_u32(ssh, &tcode)) != 0) {
		error_fr(r, "parse tcode");
		ssh_packet_disconnect(ssh, "Invalid extended_data message");
	}
	எனில் (c->efd == -1 ||
	    c->extended_usage != CHAN_EXTENDED_WRITE ||
	    tcode != SSH2_EXTENDED_DATA_STDERR) {
		logit("channel %d: bad ext data", c->self);
		திரும்பு 0;
	}
	எனில் ((r = sshpkt_get_string_direct(ssh, &data, &data_len)) != 0 ||
            (r = sshpkt_get_end(ssh)) != 0) {
		error_fr(r, "parse data");
		ssh_packet_disconnect(ssh, "Invalid extended_data message");
	}

	எனில் (data_len > c->local_window) {
		logit("channel %d: rcvd too much extended_data %zu, win %u",
		    c->self, data_len, c->local_window);
		திரும்பு 0;
	}
	debug2("channel %d: rcvd ext data %zu", c->self, data_len);
	/* XXX sshpkt_getb? */
	எனில் ((r = sshbuf_put(c->extended, data, data_len)) != 0)
		error_fr(r, "append");
	c->local_window -= data_len;
	திரும்பு 0;
}

முழு
channel_உள்ளீடு_ieof(முழு type, uint32_t seq, கட்டமைப்பு ssh *ssh)
{
	Channel *c = channel_from_packet_id(ssh, __func__, "ieof");
	முழு r;

        எனில் ((r = sshpkt_get_end(ssh)) != 0) {
		error_fr(r, "parse data");
		ssh_packet_disconnect(ssh, "Invalid ieof message");
	}

	எனில் (channel_proxy_upstream(c, type, seq, ssh))
		திரும்பு 0;
	chan_rcvd_ieof(ssh, c);

	/* XXX force input close */
	எனில் (c->force_drain && c->istate == CHAN_உள்ளீடு_OPEN) {
		debug("channel %d: FORCE input drain", c->self);
		c->istate = CHAN_உள்ளீடு_WAIT_DRAIN;
		எனில் (sshbuf_len(c->உள்ளீடு) == 0)
			chan_ibuf_empty(ssh, c);
	}
	திரும்பு 0;
}

முழு
channel_உள்ளீடு_oclose(முழு type, uint32_t seq, கட்டமைப்பு ssh *ssh)
{
	Channel *c = channel_from_packet_id(ssh, __func__, "oclose");
	முழு r;

	எனில் (channel_proxy_upstream(c, type, seq, ssh))
		திரும்பு 0;
        எனில் ((r = sshpkt_get_end(ssh)) != 0) {
		error_fr(r, "parse data");
		ssh_packet_disconnect(ssh, "Invalid oclose message");
	}
	chan_rcvd_oclose(ssh, c);
	திரும்பு 0;
}

முழு
channel_உள்ளீடு_open_confirmation(முழு type, uint32_t seq, கட்டமைப்பு ssh *ssh)
{
	Channel *c = channel_from_packet_id(ssh, __func__, "open confirmation");
	uint32_t remote_window, remote_maxpacket;
	முழு r;

	எனில் (channel_proxy_upstream(c, type, seq, ssh))
		திரும்பு 0;
	எனில் (c->type != SSH_CHANNEL_OPENING)
		ssh_packet_disconnect(ssh, "Received open confirmation for "
		    "non-opening channel %d.", c->self);
	/*
	 * Record the remote channel number and mark that the channel
	 * is now open.
	 */
	எனில் ((r = sshpkt_get_u32(ssh, &c->remote_id)) != 0 ||
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
	எனில் (c->open_confirm) {
		debug2_f("channel %d: callback start", c->self);
		c->open_confirm(ssh, c->self, 1, c->open_confirm_ctx);
		debug2_f("channel %d: callback done", c->self);
	}
	channel_set_used_time(ssh, c);
	debug2("channel %d: open confirm rwindow %u rmax %u", c->self,
	    c->remote_window, c->remote_maxpacket);
	திரும்பு 0;
}

நிலையான எழுத்து *
reason2txt(முழு reason)
{
	தேர்வு (reason) {
	நிலை SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED:
		திரும்பு "administratively prohibited";
	நிலை SSH2_OPEN_CONNECT_FAILED:
		திரும்பு "connect failed";
	நிலை SSH2_OPEN_UNKNOWN_CHANNEL_TYPE:
		திரும்பு "unknown channel type";
	நிலை SSH2_OPEN_RESOURCE_SHORTAGE:
		திரும்பு "resource shortage";
	}
	திரும்பு "unknown reason";
}

முழு
channel_உள்ளீடு_open_failure(முழு type, uint32_t seq, கட்டமைப்பு ssh *ssh)
{
	Channel *c = channel_from_packet_id(ssh, __func__, "open failure");
	uint32_t reason;
	எழுத்து *செய்தி = வெற்று;
	முழு r;

	எனில் (channel_proxy_upstream(c, type, seq, ssh))
		திரும்பு 0;
	எனில் (c->type != SSH_CHANNEL_OPENING)
		ssh_packet_disconnect(ssh, "Received open failure for "
		    "non-opening channel %d.", c->self);
	எனில் ((r = sshpkt_get_u32(ssh, &reason)) != 0) {
		error_fr(r, "parse reason");
		ssh_packet_disconnect(ssh, "Invalid open failure message");
	}
	/* skip language */
	எனில் ((r = sshpkt_get_cstring(ssh, &செய்தி, வெற்று)) != 0 ||
	    (r = sshpkt_get_string_direct(ssh, வெற்று, வெற்று)) != 0 ||
            (r = sshpkt_get_end(ssh)) != 0) {
		error_fr(r, "parse msg/lang");
		ssh_packet_disconnect(ssh, "Invalid open failure message");
	}
	logit("channel %d: open failed: %s%s%s", c->self,
	    reason2txt(reason), செய்தி ? ": ": "", செய்தி ? செய்தி : "");
	விடுவி(செய்தி);
	எனில் (c->open_confirm) {
		debug2_f("channel %d: callback start", c->self);
		c->open_confirm(ssh, c->self, 0, c->open_confirm_ctx);
		debug2_f("channel %d: callback done", c->self);
	}
	/* Schedule the channel for cleanup/deletion. */
	chan_mark_dead(ssh, c);
	திரும்பு 0;
}

முழு
channel_உள்ளீடு_window_adjust(முழு type, uint32_t seq, கட்டமைப்பு ssh *ssh)
{
	முழு id = channel_parse_id(ssh, __func__, "window adjust");
	Channel *c;
	uint32_t adjust;
	u_int new_rwin;
	முழு r;

	எனில் ((c = channel_lookup(ssh, id)) == வெற்று) {
		logit("Received window adjust for non-open channel %d.", id);
		திரும்பு 0;
	}

	எனில் (channel_proxy_upstream(c, type, seq, ssh))
		திரும்பு 0;
	எனில் ((r = sshpkt_get_u32(ssh, &adjust)) != 0 ||
            (r = sshpkt_get_end(ssh)) != 0) {
		error_fr(r, "parse adjust");
		ssh_packet_disconnect(ssh, "Invalid window adjust message");
	}
	debug2("channel %d: rcvd adjust %u", c->self, adjust);
	எனில் ((new_rwin = c->remote_window + adjust) < c->remote_window) {
		fatal("channel %d: adjust %u overflows remote window %u",
		    c->self, adjust, c->remote_window);
	}
	c->remote_window = new_rwin;
	திரும்பு 0;
}

முழு
channel_உள்ளீடு_status_confirm(முழு type, uint32_t seq, கட்டமைப்பு ssh *ssh)
{
	முழு id = channel_parse_id(ssh, __func__, "status confirm");
	Channel *c;
	கட்டமைப்பு channel_confirm *cc;

	/* Reset keepalive timeout */
	ssh_packet_set_alive_timeouts(ssh, 0);

	debug2_f("type %d id %d", type, id);

	எனில் ((c = channel_lookup(ssh, id)) == வெற்று) {
		logit_f("%d: unknown", id);
		திரும்பு 0;
	}
	எனில் (channel_proxy_upstream(c, type, seq, ssh))
		திரும்பு 0;
        எனில் (sshpkt_get_end(ssh) != 0)
		ssh_packet_disconnect(ssh, "Invalid status confirm message");
	எனில் ((cc = TAILQ_FIRST(&c->status_confirms)) == வெற்று)
		திரும்பு 0;
	cc->cb(ssh, type, c, cc->ctx);
	TAILQ_REMOVE(&c->status_confirms, cc, entry);
	freezero(cc, அளவு(*cc));
	திரும்பு 0;
}

/* -- tcp forwarding */

வெறுமை
channel_set_af(கட்டமைப்பு ssh *ssh, முழு af)
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
நிலையான மாறிலி எழுத்து *
channel_fwd_bind_addr(கட்டமைப்பு ssh *ssh, மாறிலி எழுத்து *listen_addr, முழு *wildcardp,
    முழு is_client, கட்டமைப்பு ForwardOptions *fwd_opts)
{
	மாறிலி எழுத்து *addr = வெற்று;
	முழு wildcard = 0;

	எனில் (listen_addr == வெற்று) {
		/* No address specified: default to gateway_ports setting */
		எனில் (fwd_opts->gateway_ports)
			wildcard = 1;
	} இல்லையெனில் எனில் (fwd_opts->gateway_ports || is_client) {
		எனில் (((ssh->compat & SSH_OLD_FORWARD_ADDR) &&
		    strcmp(listen_addr, "0.0.0.0") == 0 && is_client == 0) ||
		    *listen_addr == '\0' || strcmp(listen_addr, "*") == 0 ||
		    (!is_client && fwd_opts->gateway_ports == 1)) {
			wildcard = 1;
			/*
			 * Notify client if they requested a specific listen
			 * address and it was overridden.
			 */
			எனில் (*listen_addr != '\0' &&
			    strcmp(listen_addr, "0.0.0.0") != 0 &&
			    strcmp(listen_addr, "*") != 0) {
				ssh_packet_send_debug(ssh,
				    "Forwarding listen address "
				    "\"%s\" overridden by server "
				    "GatewayPorts", listen_addr);
			}
		} இல்லையெனில் எனில் (strcmp(listen_addr, "localhost") != 0 ||
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
	} இல்லையெனில் எனில் (strcmp(listen_addr, "127.0.0.1") == 0 ||
	    strcmp(listen_addr, "::1") == 0) {
		/*
		 * If a specific IPv4/IPv6 localhost address has been
		 * requested then accept it even if gateway_ports is in
		 * effect. This allows the client to prefer IPv4 or IPv6.
		 */
		addr = listen_addr;
	}
	எனில் (wildcardp != வெற்று)
		*wildcardp = wildcard;
	திரும்பு addr;
}

நிலையான முழு
channel_setup_fwd_listener_tcpip(கட்டமைப்பு ssh *ssh, முழு type,
    கட்டமைப்பு Forward *fwd, முழு *allocated_listen_port,
    கட்டமைப்பு ForwardOptions *fwd_opts)
{
	Channel *c;
	முழு sock, r, success = 0, wildcard = 0, is_client;
	கட்டமைப்பு addrinfo hints, *ai, *aitop;
	மாறிலி எழுத்து *host, *addr;
	எழுத்து ntop[NI_MAXHOST], strport[NI_MAXSERV];
	in_port_t *lport_p;

	is_client = (type == SSH_CHANNEL_PORT_LISTENER);

	எனில் (is_client && fwd->connect_path != வெற்று) {
		host = fwd->connect_path;
	} இல்லையெனில் {
		host = (type == SSH_CHANNEL_RPORT_LISTENER) ?
		    fwd->listen_host : fwd->connect_host;
		எனில் (host == வெற்று) {
			error("No forward host name.");
			திரும்பு 0;
		}
		எனில் (strlen(host) >= NI_MAXHOST) {
			error("Forward host name too long.");
			திரும்பு 0;
		}
	}

	/* Determine the bind address, cf. channel_fwd_bind_addr() comment */
	addr = channel_fwd_bind_addr(ssh, fwd->listen_host, &wildcard,
	    is_client, fwd_opts);
	debug3_f("type %d wildcard %d addr %s", type, wildcard,
	    (addr == வெற்று) ? "NULL" : addr);

	/*
	 * getaddrinfo returns a loopback address if the hostname is
	 * set to NULL and hints.ai_flags is not AI_PASSIVE
	 */
	memset(&hints, 0, அளவு(hints));
	hints.ai_family = ssh->chanctxt->IPv4or6;
	hints.ai_flags = wildcard ? AI_PASSIVE : 0;
	hints.ai_socktype = SOCK_STREAM;
	snprintf(strport, அளவு strport, "%d", fwd->listen_port);
	எனில் ((r = getaddrinfo(addr, strport, &hints, &aitop)) != 0) {
		எனில் (addr == வெற்று) {
			/* This really shouldn't happen */
			ssh_packet_disconnect(ssh, "getaddrinfo: fatal error: %s",
			    ssh_gai_strerror(r));
		} இல்லையெனில் {
			error_f("getaddrinfo(%.64s): %s", addr,
			    ssh_gai_strerror(r));
		}
		திரும்பு 0;
	}
	எனில் (allocated_listen_port != வெற்று)
		*allocated_listen_port = 0;
	க்கு (ai = aitop; ai; ai = ai->ai_next) {
		தேர்வு (ai->ai_family) {
		நிலை AF_INET:
			lport_p = &((கட்டமைப்பு sockaddr_in *)ai->ai_addr)->
			    sin_port;
			நிறுத்து;
		நிலை AF_INET6:
			lport_p = &((கட்டமைப்பு sockaddr_in6 *)ai->ai_addr)->
			    sin6_port;
			நிறுத்து;
		இயல்பு:
			தொடர்;
		}
		/*
		 * If allocating a port for -R forwards, then use the
		 * same port for all address families.
		 */
		எனில் (type == SSH_CHANNEL_RPORT_LISTENER &&
		    fwd->listen_port == 0 && allocated_listen_port != வெற்று &&
		    *allocated_listen_port > 0)
			*lport_p = htons(*allocated_listen_port);

		எனில் (getnameinfo(ai->ai_addr, ai->ai_addrlen, ntop, அளவு(ntop),
		    strport, அளவு(strport),
		    NI_NUMERICHOST|NI_NUMERICSERV) != 0) {
			error_f("getnameinfo failed");
			தொடர்;
		}
		/* Create a port to listen for the host. */
		sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		எனில் (sock == -1) {
			/* this is no error since kernel may not support ipv6 */
			verbose("socket [%s]:%s: %.100s", ntop, strport,
			    strerror(errno));
			தொடர்;
		}

		set_reuseaddr(sock);
		எனில் (ai->ai_family == AF_INET6)
			sock_set_v6only(sock);

		debug("Local forwarding listening on %s port %s.",
		    ntop, strport);

		/* Bind the socket to the address. */
		எனில் (bind(sock, ai->ai_addr, ai->ai_addrlen) == -1) {
			/*
			 * address can be in if use ipv6 address is
			 * already bound
			 */
			எனில் (!ai->ai_next)
				error("bind [%s]:%s: %.100s",
				    ntop, strport, strerror(errno));
			இல்லையெனில்
				verbose("bind [%s]:%s: %.100s",
				    ntop, strport, strerror(errno));

			close(sock);
			தொடர்;
		}
		/* Start listening for connections on the socket. */
		எனில் (listen(sock, SSH_LISTEN_BACKLOG) == -1) {
			error("listen [%s]:%s: %.100s", ntop, strport,
			    strerror(errno));
			close(sock);
			தொடர்;
		}

		/*
		 * fwd->listen_port == 0 requests a dynamically allocated port -
		 * record what we got.
		 */
		எனில் (type == SSH_CHANNEL_RPORT_LISTENER &&
		    fwd->listen_port == 0 &&
		    allocated_listen_port != வெற்று &&
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
		c->listening_addr = addr == வெற்று ? வெற்று : xstrdup(addr);
		எனில் (fwd->listen_port == 0 && allocated_listen_port != வெற்று &&
		    !(ssh->compat & SSH_BUG_DYNAMIC_RPORT))
			c->listening_port = *allocated_listen_port;
		இல்லையெனில்
			c->listening_port = fwd->listen_port;
		success = 1;
	}
	எனில் (success == 0)
		error_f("cannot listen to port: %d", fwd->listen_port);
	freeaddrinfo(aitop);
	திரும்பு success;
}

நிலையான முழு
channel_setup_fwd_listener_streamlocal(கட்டமைப்பு ssh *ssh, முழு type,
    கட்டமைப்பு Forward *fwd, கட்டமைப்பு ForwardOptions *fwd_opts)
{
	கட்டமைப்பு sockaddr_un sunaddr;
	மாறிலி எழுத்து *path;
	Channel *c;
	முழு port, sock;
	mode_t omask;

	தேர்வு (type) {
	நிலை SSH_CHANNEL_UNIX_LISTENER:
		எனில் (fwd->connect_path != வெற்று) {
			எனில் (strlen(fwd->connect_path) > அளவு(sunaddr.sun_path)) {
				error("Local connecting path too long: %s",
				    fwd->connect_path);
				திரும்பு 0;
			}
			path = fwd->connect_path;
			port = PORT_STREAMLOCAL;
		} இல்லையெனில் {
			எனில் (fwd->connect_host == வெற்று) {
				error("No forward host name.");
				திரும்பு 0;
			}
			எனில் (strlen(fwd->connect_host) >= NI_MAXHOST) {
				error("Forward host name too long.");
				திரும்பு 0;
			}
			path = fwd->connect_host;
			port = fwd->connect_port;
		}
		நிறுத்து;
	நிலை SSH_CHANNEL_RUNIX_LISTENER:
		path = fwd->listen_path;
		port = PORT_STREAMLOCAL;
		நிறுத்து;
	இயல்பு:
		error_f("unexpected channel type %d", type);
		திரும்பு 0;
	}

	எனில் (fwd->listen_path == வெற்று) {
		error("No forward path name.");
		திரும்பு 0;
	}
	எனில் (strlen(fwd->listen_path) > அளவு(sunaddr.sun_path)) {
		error("Local listening path too long: %s", fwd->listen_path);
		திரும்பு 0;
	}

	debug3_f("type %d path %s", type, fwd->listen_path);

	/* Start a Unix domain listener. */
	omask = umask(fwd_opts->streamlocal_bind_mask);
	sock = unix_listener(fwd->listen_path, SSH_LISTEN_BACKLOG,
	    fwd_opts->streamlocal_bind_unlink);
	umask(omask);
	எனில் (sock < 0)
		திரும்பு 0;

	debug("Local forwarding listening on path %s.", fwd->listen_path);

	/* Allocate a channel number for the socket. */
	c = channel_new(ssh, "unix-listener", type, sock, sock, -1,
	    CHAN_TCP_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT,
	    0, "unix listener", 1);
	c->path = xstrdup(path);
	c->host_port = port;
	c->listening_port = PORT_STREAMLOCAL;
	c->listening_addr = xstrdup(fwd->listen_path);
	திரும்பு 1;
}

நிலையான முழு
channel_cancel_rport_listener_tcpip(கட்டமைப்பு ssh *ssh,
    மாறிலி எழுத்து *host, u_short port)
{
	u_int i;
	முழு found = 0;

	க்கு (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		Channel *c = ssh->chanctxt->channels[i];
		எனில் (c == வெற்று || c->type != SSH_CHANNEL_RPORT_LISTENER)
			தொடர்;
		எனில் (strcmp(c->path, host) == 0 && c->listening_port == port) {
			debug2_f("close channel %d", i);
			channel_free(ssh, c);
			found = 1;
		}
	}

	திரும்பு found;
}

நிலையான முழு
channel_cancel_rport_listener_streamlocal(கட்டமைப்பு ssh *ssh, மாறிலி எழுத்து *path)
{
	u_int i;
	முழு found = 0;

	க்கு (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		Channel *c = ssh->chanctxt->channels[i];
		எனில் (c == வெற்று || c->type != SSH_CHANNEL_RUNIX_LISTENER)
			தொடர்;
		எனில் (c->path == வெற்று)
			தொடர்;
		எனில் (strcmp(c->path, path) == 0) {
			debug2_f("close channel %d", i);
			channel_free(ssh, c);
			found = 1;
		}
	}

	திரும்பு found;
}

முழு
channel_cancel_rport_listener(கட்டமைப்பு ssh *ssh, கட்டமைப்பு Forward *fwd)
{
	எனில் (fwd->listen_path != வெற்று) {
		திரும்பு channel_cancel_rport_listener_streamlocal(ssh,
		    fwd->listen_path);
	} இல்லையெனில் {
		திரும்பு channel_cancel_rport_listener_tcpip(ssh,
		    fwd->listen_host, fwd->listen_port);
	}
}

நிலையான முழு
channel_cancel_lport_listener_tcpip(கட்டமைப்பு ssh *ssh,
    மாறிலி எழுத்து *lhost, u_short lport, முழு cport,
    கட்டமைப்பு ForwardOptions *fwd_opts)
{
	u_int i;
	முழு found = 0;
	மாறிலி எழுத்து *addr = channel_fwd_bind_addr(ssh, lhost, வெற்று, 1, fwd_opts);

	க்கு (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		Channel *c = ssh->chanctxt->channels[i];
		எனில் (c == வெற்று || c->type != SSH_CHANNEL_PORT_LISTENER)
			தொடர்;
		எனில் (c->listening_port != lport)
			தொடர்;
		எனில் (cport == CHANNEL_CANCEL_PORT_STATIC) {
			/* skip dynamic forwardings */
			எனில் (c->host_port == 0)
				தொடர்;
		} இல்லையெனில் {
			எனில் (c->host_port != cport)
				தொடர்;
		}
		எனில் ((c->listening_addr == வெற்று && addr != வெற்று) ||
		    (c->listening_addr != வெற்று && addr == வெற்று))
			தொடர்;
		எனில் (addr == வெற்று || strcmp(c->listening_addr, addr) == 0) {
			debug2_f("close channel %d", i);
			channel_free(ssh, c);
			found = 1;
		}
	}

	திரும்பு found;
}

நிலையான முழு
channel_cancel_lport_listener_streamlocal(கட்டமைப்பு ssh *ssh, மாறிலி எழுத்து *path)
{
	u_int i;
	முழு found = 0;

	எனில் (path == வெற்று) {
		error_f("no path specified.");
		திரும்பு 0;
	}

	க்கு (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		Channel *c = ssh->chanctxt->channels[i];
		எனில் (c == வெற்று || c->type != SSH_CHANNEL_UNIX_LISTENER)
			தொடர்;
		எனில் (c->listening_addr == வெற்று)
			தொடர்;
		எனில் (strcmp(c->listening_addr, path) == 0) {
			debug2_f("close channel %d", i);
			channel_free(ssh, c);
			found = 1;
		}
	}

	திரும்பு found;
}

முழு
channel_cancel_lport_listener(கட்டமைப்பு ssh *ssh,
    கட்டமைப்பு Forward *fwd, முழு cport, கட்டமைப்பு ForwardOptions *fwd_opts)
{
	எனில் (fwd->listen_path != வெற்று) {
		திரும்பு channel_cancel_lport_listener_streamlocal(ssh,
		    fwd->listen_path);
	} இல்லையெனில் {
		திரும்பு channel_cancel_lport_listener_tcpip(ssh,
		    fwd->listen_host, fwd->listen_port, cport, fwd_opts);
	}
}

/* protocol local port fwd, used by ssh */
முழு
channel_setup_local_fwd_listener(கட்டமைப்பு ssh *ssh,
    கட்டமைப்பு Forward *fwd, கட்டமைப்பு ForwardOptions *fwd_opts)
{
	எனில் (fwd->listen_path != வெற்று) {
		திரும்பு channel_setup_fwd_listener_streamlocal(ssh,
		    SSH_CHANNEL_UNIX_LISTENER, fwd, fwd_opts);
	} இல்லையெனில் {
		திரும்பு channel_setup_fwd_listener_tcpip(ssh,
		    SSH_CHANNEL_PORT_LISTENER, fwd, வெற்று, fwd_opts);
	}
}

/* Matches a remote forwarding permission against a requested forwarding */
நிலையான முழு
remote_open_match(கட்டமைப்பு permission *allowed_open, கட்டமைப்பு Forward *fwd)
{
	முழு ret;
	எழுத்து *lhost;

	/* XXX add ACLs for streamlocal */
	எனில் (fwd->listen_path != வெற்று)
		திரும்பு 1;

	எனில் (fwd->listen_host == வெற்று || allowed_open->listen_host == வெற்று)
		திரும்பு 0;

	எனில் (allowed_open->listen_port != FWD_PERMIT_ANY_PORT &&
	    allowed_open->listen_port != fwd->listen_port)
		திரும்பு 0;

	/* Match hostnames case-insensitively */
	lhost = xstrdup(fwd->listen_host);
	lowercase(lhost);
	ret = match_pattern(lhost, allowed_open->listen_host);
	விடுவி(lhost);

	திரும்பு ret;
}

/* Checks whether a requested remote forwarding is permitted */
நிலையான முழு
check_rfwd_permission(கட்டமைப்பு ssh *ssh, கட்டமைப்பு Forward *fwd)
{
	கட்டமைப்பு ssh_channels *sc = ssh->chanctxt;
	கட்டமைப்பு permission_set *pset = &sc->remote_perms;
	u_int i, permit, permit_adm = 1;
	கட்டமைப்பு permission *perm;

#ifdef SKIP_PRIVDROP
	எனில் (fwd->listen_path != வெற்று)
		திரும்பு 0;
	எனில் (fwd->listen_port != 0 && fwd->listen_port < 1024)
		திரும்பு 0;
#endif

	/* XXX apply GatewayPorts override before checking? */

	permit = pset->all_permitted;
	எனில் (!permit) {
		க்கு (i = 0; i < pset->இலக்கம்_permitted_user; i++) {
			perm = &pset->permitted_user[i];
			எனில் (remote_open_match(perm, fwd)) {
				permit = 1;
				நிறுத்து;
			}
		}
	}

	எனில் (pset->இலக்கம்_permitted_admin > 0) {
		permit_adm = 0;
		க்கு (i = 0; i < pset->இலக்கம்_permitted_admin; i++) {
			perm = &pset->permitted_admin[i];
			எனில் (remote_open_match(perm, fwd)) {
				permit_adm = 1;
				நிறுத்து;
			}
		}
	}

	திரும்பு permit && permit_adm;
}

/* protocol v2 remote port fwd, used by sshd */
முழு
channel_setup_remote_fwd_listener(கட்டமைப்பு ssh *ssh, கட்டமைப்பு Forward *fwd,
    முழு *allocated_listen_port, கட்டமைப்பு ForwardOptions *fwd_opts)
{
	எனில் (!check_rfwd_permission(ssh, fwd)) {
		ssh_packet_send_debug(ssh, "port forwarding refused");
		எனில் (fwd->listen_path != வெற்று)
			/* XXX always allowed, see remote_open_match() */
			logit("Received request from %.100s port %d to "
			    "remote forward to path \"%.100s\", "
			    "but the request was denied.",
			    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
			    fwd->listen_path);
		இல்லையெனில் எனில்(fwd->listen_host != வெற்று)
			logit("Received request from %.100s port %d to "
			    "remote forward to host %.100s port %d, "
			    "but the request was denied.",
			    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
			    fwd->listen_host, fwd->listen_port );
		இல்லையெனில்
			logit("Received request from %.100s port %d to remote "
			    "forward, but the request was denied.",
			    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
		திரும்பு 0;
	}
	எனில் (fwd->listen_path != வெற்று) {
		திரும்பு channel_setup_fwd_listener_streamlocal(ssh,
		    SSH_CHANNEL_RUNIX_LISTENER, fwd, fwd_opts);
	} இல்லையெனில் {
		திரும்பு channel_setup_fwd_listener_tcpip(ssh,
		    SSH_CHANNEL_RPORT_LISTENER, fwd, allocated_listen_port,
		    fwd_opts);
	}
}

/*
 * Translate the requested rfwd listen host to something usable for
 * this server.
 */
நிலையான மாறிலி எழுத்து *
channel_rfwd_bind_host(மாறிலி எழுத்து *listen_host)
{
	எனில் (listen_host == வெற்று) {
		திரும்பு "localhost";
	} இல்லையெனில் எனில் (*listen_host == '\0' || strcmp(listen_host, "*") == 0) {
		திரும்பு "";
	} இல்லையெனில்
		திரும்பு listen_host;
}

/*
 * Initiate forwarding of connections to port "port" on remote host through
 * the secure channel to host:port from local side.
 * Returns handle (index) for updating the dynamic listen port with
 * channel_update_permission().
 */
முழு
channel_request_remote_forwarding(கட்டமைப்பு ssh *ssh, கட்டமைப்பு Forward *fwd)
{
	முழு r, success = 0, idx = -1;
	மாறிலி எழுத்து *host_to_connect, *listen_host, *listen_path;
	முழு port_to_connect, listen_port;

	/* Send the forward request to the remote side. */
	எனில் (fwd->listen_path != வெற்று) {
		எனில் ((r = sshpkt_start(ssh, SSH2_செய்தி_GLOBAL_REQUEST)) != 0 ||
		    (r = sshpkt_put_cstring(ssh,
		    "streamlocal-forward@openssh.com")) != 0 ||
		    (r = sshpkt_put_u8(ssh, 1)) != 0 || /* want reply */
		    (r = sshpkt_put_cstring(ssh, fwd->listen_path)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			fatal_fr(r, "request streamlocal");
	} இல்லையெனில் {
		எனில் ((r = sshpkt_start(ssh, SSH2_செய்தி_GLOBAL_REQUEST)) != 0 ||
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
	எனில் (success) {
		/* Record that connection to this host/port is permitted. */
		host_to_connect = listen_host = listen_path = வெற்று;
		port_to_connect = listen_port = 0;
		எனில் (fwd->connect_path != வெற்று) {
			host_to_connect = fwd->connect_path;
			port_to_connect = PORT_STREAMLOCAL;
		} இல்லையெனில் {
			host_to_connect = fwd->connect_host;
			port_to_connect = fwd->connect_port;
		}
		எனில் (fwd->listen_path != வெற்று) {
			listen_path = fwd->listen_path;
			listen_port = PORT_STREAMLOCAL;
		} இல்லையெனில் {
			listen_host = fwd->listen_host;
			listen_port = fwd->listen_port;
		}
		idx = permission_set_add(ssh, FORWARD_USER, FORWARD_LOCAL,
		    host_to_connect, port_to_connect,
		    listen_host, listen_path, listen_port, வெற்று);
	}
	திரும்பு idx;
}

நிலையான முழு
open_match(கட்டமைப்பு permission *allowed_open, மாறிலி எழுத்து *requestedhost,
    முழு requestedport)
{
	எனில் (allowed_open->host_to_connect == வெற்று)
		திரும்பு 0;
	எனில் (allowed_open->port_to_connect != FWD_PERMIT_ANY_PORT &&
	    allowed_open->port_to_connect != requestedport)
		திரும்பு 0;
	எனில் (strcmp(allowed_open->host_to_connect, FWD_PERMIT_ANY_HOST) != 0 &&
	    strcmp(allowed_open->host_to_connect, requestedhost) != 0)
		திரும்பு 0;
	திரும்பு 1;
}

/*
 * Note that in the listen host/port case
 * we don't support FWD_PERMIT_ANY_PORT and
 * need to translate between the configured-host (listen_host)
 * and what we've sent to the remote server (channel_rfwd_bind_host)
 */
நிலையான முழு
open_listen_match_tcpip(கட்டமைப்பு permission *allowed_open,
    மாறிலி எழுத்து *requestedhost, u_short requestedport, முழு translate)
{
	மாறிலி எழுத்து *allowed_host;

	எனில் (allowed_open->host_to_connect == வெற்று)
		திரும்பு 0;
	எனில் (allowed_open->listen_port != requestedport)
		திரும்பு 0;
	எனில் (!translate && allowed_open->listen_host == வெற்று &&
	    requestedhost == வெற்று)
		திரும்பு 1;
	allowed_host = translate ?
	    channel_rfwd_bind_host(allowed_open->listen_host) :
	    allowed_open->listen_host;
	எனில் (allowed_host == வெற்று || requestedhost == வெற்று ||
	    strcmp(allowed_host, requestedhost) != 0)
		திரும்பு 0;
	திரும்பு 1;
}

நிலையான முழு
open_listen_match_streamlocal(கட்டமைப்பு permission *allowed_open,
    மாறிலி எழுத்து *requestedpath)
{
	எனில் (allowed_open->host_to_connect == வெற்று)
		திரும்பு 0;
	எனில் (allowed_open->listen_port != PORT_STREAMLOCAL)
		திரும்பு 0;
	எனில் (allowed_open->listen_path == வெற்று ||
	    strcmp(allowed_open->listen_path, requestedpath) != 0)
		திரும்பு 0;
	திரும்பு 1;
}

/*
 * Request cancellation of remote forwarding of connection host:port from
 * local side.
 */
நிலையான முழு
channel_request_rforward_cancel_tcpip(கட்டமைப்பு ssh *ssh,
    மாறிலி எழுத்து *host, u_short port)
{
	கட்டமைப்பு ssh_channels *sc = ssh->chanctxt;
	கட்டமைப்பு permission_set *pset = &sc->local_perms;
	முழு r;
	u_int i;
	கட்டமைப்பு permission *perm = வெற்று;

	க்கு (i = 0; i < pset->இலக்கம்_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		எனில் (open_listen_match_tcpip(perm, host, port, 0))
			நிறுத்து;
		perm = வெற்று;
	}
	எனில் (perm == வெற்று) {
		debug_f("requested forward not found");
		திரும்பு -1;
	}
	எனில் ((r = sshpkt_start(ssh, SSH2_செய்தி_GLOBAL_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "cancel-tcpip-forward")) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 || /* want reply */
	    (r = sshpkt_put_cstring(ssh, channel_rfwd_bind_host(host))) != 0 ||
	    (r = sshpkt_put_u32(ssh, port)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send cancel");

	fwd_perm_clear(perm); /* unregister */

	திரும்பு 0;
}

/*
 * Request cancellation of remote forwarding of Unix domain socket
 * path from local side.
 */
நிலையான முழு
channel_request_rforward_cancel_streamlocal(கட்டமைப்பு ssh *ssh, மாறிலி எழுத்து *path)
{
	கட்டமைப்பு ssh_channels *sc = ssh->chanctxt;
	கட்டமைப்பு permission_set *pset = &sc->local_perms;
	முழு r;
	u_int i;
	கட்டமைப்பு permission *perm = வெற்று;

	க்கு (i = 0; i < pset->இலக்கம்_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		எனில் (open_listen_match_streamlocal(perm, path))
			நிறுத்து;
		perm = வெற்று;
	}
	எனில் (perm == வெற்று) {
		debug_f("requested forward not found");
		திரும்பு -1;
	}
	எனில் ((r = sshpkt_start(ssh, SSH2_செய்தி_GLOBAL_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh,
	    "cancel-streamlocal-forward@openssh.com")) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 || /* want reply */
	    (r = sshpkt_put_cstring(ssh, path)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send cancel");

	fwd_perm_clear(perm); /* unregister */

	திரும்பு 0;
}

/*
 * Request cancellation of remote forwarding of a connection from local side.
 */
முழு
channel_request_rforward_cancel(கட்டமைப்பு ssh *ssh, கட்டமைப்பு Forward *fwd)
{
	எனில் (fwd->listen_path != வெற்று) {
		திரும்பு channel_request_rforward_cancel_streamlocal(ssh,
		    fwd->listen_path);
	} இல்லையெனில் {
		திரும்பு channel_request_rforward_cancel_tcpip(ssh,
		    fwd->listen_host,
		    fwd->listen_port ? fwd->listen_port : fwd->allocated_port);
	}
}

/*
 * Permits opening to any host/port if permitted_user[] is empty.  This is
 * usually called by the server, because the user could connect to any port
 * anyway, and the server has no way to know but to trust the client anyway.
 */
வெறுமை
channel_permit_all(கட்டமைப்பு ssh *ssh, முழு where)
{
	கட்டமைப்பு permission_set *pset = permission_set_get(ssh, where);

	எனில் (pset->இலக்கம்_permitted_user == 0)
		pset->all_permitted = 1;
}

/*
 * Permit the specified host/port for forwarding.
 */
வெறுமை
channel_add_permission(கட்டமைப்பு ssh *ssh, முழு who, முழு where,
    எழுத்து *host, முழு port)
{
	முழு local = where == FORWARD_LOCAL;
	கட்டமைப்பு permission_set *pset = permission_set_get(ssh, where);

	debug("allow %s forwarding to host %s port %d",
	    fwd_ident(who, where), host, port);
	/*
	 * Remote forwards set listen_host/port, local forwards set
	 * host/port_to_connect.
	 */
	permission_set_add(ssh, who, where,
	    local ? host : வெற்று, local ? port : 0,
	    local ? வெற்று : host, வெற்று, local ? 0 : port, வெற்று);
	pset->all_permitted = 0;
}

/*
 * Administratively disable forwarding.
 */
வெறுமை
channel_disable_admin(கட்டமைப்பு ssh *ssh, முழு where)
{
	channel_clear_permission(ssh, FORWARD_ADM, where);
	permission_set_add(ssh, FORWARD_ADM, where,
	    வெற்று, 0, வெற்று, வெற்று, 0, வெற்று);
}

/*
 * Clear a list of permitted opens.
 */
வெறுமை
channel_clear_permission(கட்டமைப்பு ssh *ssh, முழு who, முழு where)
{
	கட்டமைப்பு permission **permp;
	u_int i, *npermp;

	permission_set_get_array(ssh, who, where, &permp, &npermp);
	க்கு (i = 0; i < *npermp; i++)
		fwd_perm_clear((*permp) + i);
	விடுவி(*permp);
	*permp = வெற்று;
	*npermp = 0;
}

/*
 * Update the listen port for a dynamic remote forward, after
 * the actual 'newport' has been allocated. If 'newport' < 0 is
 * passed then they entry will be invalidated.
 */
வெறுமை
channel_update_permission(கட்டமைப்பு ssh *ssh, முழு idx, முழு newport)
{
	கட்டமைப்பு permission_set *pset = &ssh->chanctxt->local_perms;

	எனில் (idx < 0 || (u_int)idx >= pset->இலக்கம்_permitted_user) {
		debug_f("index out of range: %d num_permitted_user %d",
		    idx, pset->இலக்கம்_permitted_user);
		திரும்பு;
	}
	debug("%s allowed port %d for forwarding to host %s port %d",
	    newport > 0 ? "Updating" : "Removing",
	    newport,
	    pset->permitted_user[idx].host_to_connect,
	    pset->permitted_user[idx].port_to_connect);
	எனில் (newport <= 0)
		fwd_perm_clear(&pset->permitted_user[idx]);
	இல்லையெனில் {
		pset->permitted_user[idx].listen_port =
		    (ssh->compat & SSH_BUG_DYNAMIC_RPORT) ? 0 : newport;
	}
}

/* Try to start non-blocking connect to next host in cctx list */
நிலையான முழு
connect_next(கட்டமைப்பு ssh *ssh, கட்டமைப்பு channel_connect *cctx)
{
	முழு sock, sock_is_network, saved_errno;
	கட்டமைப்பு sockaddr_un *sunaddr;
	எழுத்து ntop[NI_MAXHOST];
	எழுத்து strport[MAXIMUM(NI_MAXSERV, அளவு(sunaddr->sun_path))];

	க்கு (; cctx->ai; cctx->ai = cctx->ai->ai_next) {
		sock_is_network = 0;
		தேர்வு (cctx->ai->ai_family) {
		நிலை AF_UNIX:
			/* unix:pathname instead of host:port */
			sunaddr = (கட்டமைப்பு sockaddr_un *)cctx->ai->ai_addr;
			strlcpy(ntop, "unix", அளவு(ntop));
			strlcpy(strport, sunaddr->sun_path, அளவு(strport));
			நிறுத்து;
		நிலை AF_INET:
		நிலை AF_INET6:
			எனில் (getnameinfo(cctx->ai->ai_addr, cctx->ai->ai_addrlen,
			    ntop, அளவு(ntop), strport, அளவு(strport),
			    NI_NUMERICHOST|NI_NUMERICSERV) != 0) {
				error_f("getnameinfo failed");
				தொடர்;
			}
			sock_is_network = 1;
			நிறுத்து;
		இயல்பு:
			தொடர்;
		}
		debug_f("start for host %.100s ([%.100s]:%s)",
		    cctx->host, ntop, strport);
		எனில் ((sock = socket(cctx->ai->ai_family, cctx->ai->ai_socktype,
		    cctx->ai->ai_protocol)) == -1) {
			எனில் (cctx->ai->ai_next == வெற்று)
				error("socket: %.100s", strerror(errno));
			இல்லையெனில்
				verbose("socket: %.100s", strerror(errno));
			தொடர்;
		}
		எனில் (set_nonblock(sock) == -1)
			fatal_f("set_nonblock(%d)", sock);
		எனில் (sock_is_network && ssh->chanctxt->want_tcp_keepalive)
			set_keepalive(sock); /* logs errors */
		எனில் (connect(sock, cctx->ai->ai_addr,
		    cctx->ai->ai_addrlen) == -1 && errno != EINPROGRESS) {
			debug_f("host %.100s ([%.100s]:%s): %.100s",
			    cctx->host, ntop, strport, strerror(errno));
			saved_errno = errno;
			close(sock);
			errno = saved_errno;
			தொடர்;	/* fail -- try next */
		}
		எனில் (cctx->ai->ai_family != AF_UNIX)
			set_nodelay(sock);
		debug_f("connect host %.100s ([%.100s]:%s) in progress, fd=%d",
		    cctx->host, ntop, strport, sock);
		cctx->ai = cctx->ai->ai_next;
		திரும்பு sock;
	}
	திரும்பு -1;
}

/*
 * Return connecting socket to remote host:port or local socket path,
 * passing back the failure reason if appropriate.
 */
நிலையான முழு
connect_to_helper(கட்டமைப்பு ssh *ssh, மாறிலி எழுத்து *name, முழு port, முழு socktype,
    எழுத்து *ctype, எழுத்து *rname, கட்டமைப்பு channel_connect *cctx,
    முழு *reason, மாறிலி எழுத்து **errmsg)
{
	கட்டமைப்பு addrinfo hints;
	முழு gaierr;
	முழு sock = -1;
	எழுத்து strport[NI_MAXSERV];

	எனில் (port == PORT_STREAMLOCAL) {
		கட்டமைப்பு sockaddr_un *sunaddr;
		கட்டமைப்பு addrinfo *ai;

		எனில் (strlen(name) > அளவு(sunaddr->sun_path)) {
			error("%.100s: %.100s", name, strerror(ENAMETOOLONG));
			திரும்பு -1;
		}

		/*
		 * Fake up a struct addrinfo for AF_UNIX connections.
		 * free_connect_ctx() must check ai_family
		 * and use free() not freeaddrinfo() for AF_UNIX.
		 */
		ai = xcalloc(1, அளவு(*ai) + அளவு(*sunaddr));
		ai->ai_addr = (கட்டமைப்பு sockaddr *)(ai + 1);
		ai->ai_addrlen = அளவு(*sunaddr);
		ai->ai_family = AF_UNIX;
		ai->ai_socktype = socktype;
		ai->ai_protocol = PF_UNSPEC;
		sunaddr = (கட்டமைப்பு sockaddr_un *)ai->ai_addr;
		sunaddr->sun_family = AF_UNIX;
		strlcpy(sunaddr->sun_path, name, அளவு(sunaddr->sun_path));
		cctx->aitop = ai;
	} இல்லையெனில் {
		memset(&hints, 0, அளவு(hints));
		hints.ai_family = ssh->chanctxt->IPv4or6;
		hints.ai_socktype = socktype;
		snprintf(strport, அளவு strport, "%d", port);
		எனில் ((gaierr = getaddrinfo(name, strport, &hints, &cctx->aitop))
		    != 0) {
			எனில் (errmsg != வெற்று)
				*errmsg = ssh_gai_strerror(gaierr);
			எனில் (reason != வெற்று)
				*reason = SSH2_OPEN_CONNECT_FAILED;
			error("connect_to %.100s: unknown host (%s)", name,
			    ssh_gai_strerror(gaierr));
			திரும்பு -1;
		}
	}

	cctx->host = xstrdup(name);
	cctx->port = port;
	cctx->ai = cctx->aitop;

	எனில் ((sock = connect_next(ssh, cctx)) == -1) {
		error("connect to %.100s port %d failed: %s",
		    name, port, strerror(errno));
		திரும்பு -1;
	}

	திரும்பு sock;
}

/* Return CONNECTING channel to remote host:port or local socket path */
நிலையான Channel *
connect_to(கட்டமைப்பு ssh *ssh, மாறிலி எழுத்து *host, முழு port,
    எழுத்து *ctype, எழுத்து *rname)
{
	கட்டமைப்பு channel_connect cctx;
	Channel *c;
	முழு sock;

	memset(&cctx, 0, அளவு(cctx));
	sock = connect_to_helper(ssh, host, port, SOCK_STREAM, ctype, rname,
	    &cctx, வெற்று, வெற்று);
	எனில் (sock == -1) {
		free_connect_ctx(&cctx);
		திரும்பு வெற்று;
	}
	c = channel_new(ssh, ctype, SSH_CHANNEL_CONNECTING, sock, sock, -1,
	    CHAN_TCP_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, rname, 1);
	c->host_port = port;
	c->path = xstrdup(host);
	c->connect_ctx = xmalloc(அளவு(cctx));
	memcpy(c->connect_ctx, &cctx, அளவு(cctx));

	திரும்பு c;
}

/*
 * returns either the newly connected channel or the downstream channel
 * that needs to deal with this connection.
 */
Channel *
channel_connect_by_listen_address(கட்டமைப்பு ssh *ssh, மாறிலி எழுத்து *listen_host,
    u_short listen_port, எழுத்து *ctype, எழுத்து *rname)
{
	கட்டமைப்பு ssh_channels *sc = ssh->chanctxt;
	கட்டமைப்பு permission_set *pset = &sc->local_perms;
	u_int i;
	கட்டமைப்பு permission *perm;

	க்கு (i = 0; i < pset->இலக்கம்_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		எனில் (open_listen_match_tcpip(perm,
		    listen_host, listen_port, 1)) {
			எனில் (perm->downstream)
				திரும்பு perm->downstream;
			எனில் (perm->port_to_connect == 0)
				திரும்பு rdynamic_connect_prepare(ssh,
				    ctype, rname);
			திரும்பு connect_to(ssh,
			    perm->host_to_connect, perm->port_to_connect,
			    ctype, rname);
		}
	}
	error("WARNING: Server requests forwarding for unknown listen_port %d",
	    listen_port);
	திரும்பு வெற்று;
}

Channel *
channel_connect_by_listen_path(கட்டமைப்பு ssh *ssh, மாறிலி எழுத்து *path,
    எழுத்து *ctype, எழுத்து *rname)
{
	கட்டமைப்பு ssh_channels *sc = ssh->chanctxt;
	கட்டமைப்பு permission_set *pset = &sc->local_perms;
	u_int i;
	கட்டமைப்பு permission *perm;

	க்கு (i = 0; i < pset->இலக்கம்_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		எனில் (open_listen_match_streamlocal(perm, path)) {
			திரும்பு connect_to(ssh,
			    perm->host_to_connect, perm->port_to_connect,
			    ctype, rname);
		}
	}
	error("WARNING: Server requests forwarding for unknown path %.100s",
	    path);
	திரும்பு வெற்று;
}

/* Check if connecting to that port is permitted and connect. */
Channel *
channel_connect_to_port(கட்டமைப்பு ssh *ssh, மாறிலி எழுத்து *host, u_short port,
    எழுத்து *ctype, எழுத்து *rname, முழு *reason, மாறிலி எழுத்து **errmsg)
{
	கட்டமைப்பு ssh_channels *sc = ssh->chanctxt;
	கட்டமைப்பு permission_set *pset = &sc->local_perms;
	கட்டமைப்பு channel_connect cctx;
	Channel *c;
	u_int i, permit, permit_adm = 1;
	முழு sock;
	கட்டமைப்பு permission *perm;

	permit = pset->all_permitted;
	எனில் (!permit) {
		க்கு (i = 0; i < pset->இலக்கம்_permitted_user; i++) {
			perm = &pset->permitted_user[i];
			எனில் (open_match(perm, host, port)) {
				permit = 1;
				நிறுத்து;
			}
		}
	}

	எனில் (pset->இலக்கம்_permitted_admin > 0) {
		permit_adm = 0;
		க்கு (i = 0; i < pset->இலக்கம்_permitted_admin; i++) {
			perm = &pset->permitted_admin[i];
			எனில் (open_match(perm, host, port)) {
				permit_adm = 1;
				நிறுத்து;
			}
		}
	}

	எனில் (!permit || !permit_adm) {
		logit("Received request from %.100s port %d to connect to "
		    "host %.100s port %d, but the request was denied.",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh), host, port);
		எனில் (reason != வெற்று)
			*reason = SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED;
		திரும்பு வெற்று;
	}

	memset(&cctx, 0, அளவு(cctx));
	sock = connect_to_helper(ssh, host, port, SOCK_STREAM, ctype, rname,
	    &cctx, reason, errmsg);
	எனில் (sock == -1) {
		free_connect_ctx(&cctx);
		திரும்பு வெற்று;
	}

	c = channel_new(ssh, ctype, SSH_CHANNEL_CONNECTING, sock, sock, -1,
	    CHAN_TCP_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, rname, 1);
	c->host_port = port;
	c->path = xstrdup(host);
	c->connect_ctx = xmalloc(அளவு(cctx));
	memcpy(c->connect_ctx, &cctx, அளவு(cctx));

	திரும்பு c;
}

/* Check if connecting to that path is permitted and connect. */
Channel *
channel_connect_to_path(கட்டமைப்பு ssh *ssh, மாறிலி எழுத்து *path,
    எழுத்து *ctype, எழுத்து *rname)
{
	கட்டமைப்பு ssh_channels *sc = ssh->chanctxt;
	கட்டமைப்பு permission_set *pset = &sc->local_perms;
	u_int i, permit, permit_adm = 1;
	கட்டமைப்பு permission *perm;

	permit = pset->all_permitted;
	எனில் (!permit) {
		க்கு (i = 0; i < pset->இலக்கம்_permitted_user; i++) {
			perm = &pset->permitted_user[i];
			எனில் (open_match(perm, path, PORT_STREAMLOCAL)) {
				permit = 1;
				நிறுத்து;
			}
		}
	}

	எனில் (pset->இலக்கம்_permitted_admin > 0) {
		permit_adm = 0;
		க்கு (i = 0; i < pset->இலக்கம்_permitted_admin; i++) {
			perm = &pset->permitted_admin[i];
			எனில் (open_match(perm, path, PORT_STREAMLOCAL)) {
				permit_adm = 1;
				நிறுத்து;
			}
		}
	}

	எனில் (!permit || !permit_adm) {
		logit("Received request to connect to path %.100s, "
		    "but the request was denied.", path);
		திரும்பு வெற்று;
	}
	திரும்பு connect_to(ssh, path, PORT_STREAMLOCAL, ctype, rname);
}

வெறுமை
channel_send_window_changes(கட்டமைப்பு ssh *ssh)
{
	கட்டமைப்பு ssh_channels *sc = ssh->chanctxt;
	கட்டமைப்பு winsize ws;
	முழு r;
	u_int i;

	க்கு (i = 0; i < sc->channels_alloc; i++) {
		எனில் (sc->channels[i] == வெற்று || !sc->channels[i]->client_tty ||
		    sc->channels[i]->type != SSH_CHANNEL_OPEN)
			தொடர்;
		எனில் (ioctl(sc->channels[i]->rfd, TIOCGWINSZ, &ws) == -1)
			தொடர்;
		channel_request_start(ssh, i, "window-change", 0);
		எனில் ((r = sshpkt_put_u32(ssh, (u_int)ws.ws_col)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_row)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_xpixel)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_ypixel)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "channel %u; send window-change", i);
	}
}

/* Return RDYNAMIC_OPEN channel: channel allows SOCKS, but is not connected */
நிலையான Channel *
rdynamic_connect_prepare(கட்டமைப்பு ssh *ssh, எழுத்து *ctype, எழுத்து *rname)
{
	Channel *c;
	முழு r;

	c = channel_new(ssh, ctype, SSH_CHANNEL_RDYNAMIC_OPEN, -1, -1, -1,
	    CHAN_TCP_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, rname, 1);
	c->host_port = 0;
	c->path = வெற்று;

	/*
	 * We need to open the channel before we have a FD,
	 * so that we can get SOCKS header from peer.
	 */
	எனில் ((r = sshpkt_start(ssh, SSH2_செய்தி_CHANNEL_OPEN_CONFIRMATION)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_window)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0)
		fatal_fr(r, "channel %i; confirm", c->self);
	திரும்பு c;
}

/* Return CONNECTING socket to remote host:port or local socket path */
நிலையான முழு
rdynamic_connect_finish(கட்டமைப்பு ssh *ssh, Channel *c)
{
	கட்டமைப்பு ssh_channels *sc = ssh->chanctxt;
	கட்டமைப்பு permission_set *pset = &sc->local_perms;
	கட்டமைப்பு permission *perm;
	கட்டமைப்பு channel_connect cctx;
	u_int i, permit_adm = 1;
	முழு sock;

	எனில் (pset->இலக்கம்_permitted_admin > 0) {
		permit_adm = 0;
		க்கு (i = 0; i < pset->இலக்கம்_permitted_admin; i++) {
			perm = &pset->permitted_admin[i];
			எனில் (open_match(perm, c->path, c->host_port)) {
				permit_adm = 1;
				நிறுத்து;
			}
		}
	}
	எனில் (!permit_adm) {
		debug_f("requested forward not permitted");
		திரும்பு -1;
	}

	memset(&cctx, 0, அளவு(cctx));
	sock = connect_to_helper(ssh, c->path, c->host_port, SOCK_STREAM, வெற்று,
	    வெற்று, &cctx, வெற்று, வெற்று);
	எனில் (sock == -1)
		free_connect_ctx(&cctx);
	இல்லையெனில் {
		/* similar to SSH_CHANNEL_CONNECTING but we've already sent the open */
		c->type = SSH_CHANNEL_RDYNAMIC_FINISH;
		c->connect_ctx = xmalloc(அளவு(cctx));
		memcpy(c->connect_ctx, &cctx, அளவு(cctx));
		channel_register_fds(ssh, c, sock, sock, -1, 0, 1, 0);
	}
	திரும்பு sock;
}

/* -- X11 forwarding */

/*
 * Creates an internet domain socket for listening for X11 connections.
 * Returns 0 and a suitable display number for the DISPLAY variable
 * stored in display_numberp , or -1 if an error occurs.
 */
முழு
x11_create_display_inet(கட்டமைப்பு ssh *ssh, முழு x11_display_offset,
    முழு x11_use_localhost, முழு single_connection,
    u_int *display_numberp, முழு **chanids)
{
	Channel *nc = வெற்று;
	முழு display_எண், sock, port;
	கட்டமைப்பு addrinfo hints, *ai, *aitop;
	எழுத்து strport[NI_MAXSERV];
	முழு gaierr, n, இலக்கம்_socks = 0, socks[இலக்கம்_SOCKS];

	எனில் (chanids == வெற்று || x11_display_offset < 0 ||
	    x11_display_offset > UINT16_MAX - X11_BASE_PORT - MAX_DISPLAYS)
		திரும்பு -1;

	க்கு (display_எண் = x11_display_offset;
	    display_எண் < x11_display_offset + MAX_DISPLAYS;
	    display_எண்++) {
		port = X11_BASE_PORT + display_எண்;
		memset(&hints, 0, அளவு(hints));
		hints.ai_family = ssh->chanctxt->IPv4or6;
		hints.ai_flags = x11_use_localhost ? 0: AI_PASSIVE;
		hints.ai_socktype = SOCK_STREAM;
		snprintf(strport, அளவு strport, "%d", port);
		எனில் ((gaierr = getaddrinfo(வெற்று, strport,
		    &hints, &aitop)) != 0) {
			error("getaddrinfo: %.100s", ssh_gai_strerror(gaierr));
			திரும்பு -1;
		}
		க்கு (ai = aitop; ai; ai = ai->ai_next) {
			எனில் (ai->ai_family != AF_INET &&
			    ai->ai_family != AF_INET6)
				தொடர்;
			sock = socket(ai->ai_family, ai->ai_socktype,
			    ai->ai_protocol);
			எனில் (sock == -1) {
				எனில் ((errno != EINVAL) && (errno != EAFNOSUPPORT)
#ifdef EPFNOSUPPORT
				    && (errno != EPFNOSUPPORT)
#endif 
				    ) {
					error("socket: %.100s", strerror(errno));
					freeaddrinfo(aitop);
					திரும்பு -1;
				} இல்லையெனில் {
					debug("x11_create_display_inet: Socket family %d not supported",
						 ai->ai_family);
					தொடர்;
				}
			}
			எனில் (ai->ai_family == AF_INET6)
				sock_set_v6only(sock);
			எனில் (x11_use_localhost)
				set_reuseaddr(sock);
			எனில் (bind(sock, ai->ai_addr, ai->ai_addrlen) == -1) {
				debug2_f("bind port %d: %.100s", port,
				    strerror(errno));
				close(sock);
				க்கு (n = 0; n < இலக்கம்_socks; n++)
					close(socks[n]);
				இலக்கம்_socks = 0;
				நிறுத்து;
			}
			socks[இலக்கம்_socks++] = sock;
			எனில் (இலக்கம்_socks == இலக்கம்_SOCKS)
				நிறுத்து;
		}
		freeaddrinfo(aitop);
		எனில் (இலக்கம்_socks > 0)
			நிறுத்து;
	}
	எனில் (display_எண் >= x11_display_offset + MAX_DISPLAYS) {
		error("Failed to allocate internet-domain X11 display socket.");
		திரும்பு -1;
	}
	/* Start listening for connections on the socket. */
	க்கு (n = 0; n < இலக்கம்_socks; n++) {
		sock = socks[n];
		எனில் (listen(sock, SSH_LISTEN_BACKLOG) == -1) {
			error("listen: %.100s", strerror(errno));
			close(sock);
			திரும்பு -1;
		}
	}

	/* Allocate a channel for each socket. */
	*chanids = xcalloc(இலக்கம்_socks + 1, அளவு(**chanids));
	க்கு (n = 0; n < இலக்கம்_socks; n++) {
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
	*display_numberp = display_எண்;
	திரும்பு 0;
}

நிலையான முழு
connect_local_xsocket_path(மாறிலி எழுத்து *pathname)
{
	முழு sock;
	கட்டமைப்பு sockaddr_un addr;

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	எனில் (sock == -1) {
		error("socket: %.100s", strerror(errno));
		திரும்பு -1;
	}
	memset(&addr, 0, அளவு(addr));
	addr.sun_family = AF_UNIX;
	strlcpy(addr.sun_path, pathname, அளவு addr.sun_path);
	எனில் (connect(sock, (கட்டமைப்பு sockaddr *)&addr, அளவு(addr)) == 0)
		திரும்பு sock;
	close(sock);
	error("connect %.100s: %.100s", addr.sun_path, strerror(errno));
	திரும்பு -1;
}

நிலையான முழு
connect_local_xsocket(u_int dnr)
{
	எழுத்து buf[1024];
	snprintf(buf, அளவு buf, _PATH_UNIX_X, dnr);
	திரும்பு connect_local_xsocket_path(buf);
}

#ifdef __APPLE__
நிலையான முழு
is_path_to_xsocket(மாறிலி எழுத்து *display, எழுத்து *path, size_t pathlen)
{
	கட்டமைப்பு stat sbuf;

	எனில் (strlcpy(path, display, pathlen) >= pathlen) {
		error_f("display path too long");
		திரும்பு 0;
	}
	எனில் (display[0] != '/')
		திரும்பு 0;
	எனில் (stat(path, &sbuf) == 0) {
		திரும்பு 1;
	} இல்லையெனில் {
		எழுத்து *dot = strrchr(path, '.');
		எனில் (dot != வெற்று) {
			*dot = '\0';
			எனில் (stat(path, &sbuf) == 0) {
				திரும்பு 1;
			}
		}
	}
	திரும்பு 0;
}
#endif

முழு
x11_connect_display(கட்டமைப்பு ssh *ssh)
{
	u_int display_எண்;
	மாறிலி எழுத்து *display;
	எழுத்து buf[1024], *cp;
	கட்டமைப்பு addrinfo hints, *ai, *aitop;
	எழுத்து strport[NI_MAXSERV];
	முழு gaierr, sock = 0;

	/* Try to open a socket for the local X server. */
	display = getenv("DISPLAY");
	எனில் (!display) {
		error("DISPLAY not set.");
		திரும்பு -1;
	}
	/*
	 * Now we decode the value of the DISPLAY variable and make a
	 * connection to the real X server.
	 */

#ifdef __APPLE__
	/* Check if display is a path to a socket (as set by launchd). */
	{
		எழுத்து path[PATH_MAX];

		எனில் (is_path_to_xsocket(display, path, அளவு(path))) {
			debug("x11_connect_display: $DISPLAY is launchd");

			/* Create a socket. */
			sock = connect_local_xsocket_path(path);
			எனில் (sock < 0)
				திரும்பு -1;

			/* OK, we now have a connection to the display. */
			திரும்பு sock;
		}
	}
#endif
	/*
	 * Check if it is a unix domain socket.  Unix domain displays are in
	 * one of the following formats: unix:d[.s], :d[.s], ::d[.s]
	 */
	எனில் (strncmp(display, "unix:", 5) == 0 ||
	    display[0] == ':') {
		/* Connect to the unix domain socket. */
		எனில் (sscanf(strrchr(display, ':') + 1, "%u",
		    &display_எண்) != 1) {
			error("Could not parse display number from DISPLAY: "
			    "%.100s", display);
			திரும்பு -1;
		}
		/* Create a socket. */
		sock = connect_local_xsocket(display_எண்);
		எனில் (sock < 0)
			திரும்பு -1;

		/* OK, we now have a connection to the display. */
		திரும்பு sock;
	}
	/*
	 * Connect to an inet socket.  The DISPLAY value is supposedly
	 * hostname:d[.s], where hostname may also be numeric IP address.
	 */
	strlcpy(buf, display, அளவு(buf));
	cp = strchr(buf, ':');
	எனில் (!cp) {
		error("Could not find ':' in DISPLAY: %.100s", display);
		திரும்பு -1;
	}
	*cp = 0;
	/*
	 * buf now contains the host name.  But first we parse the
	 * display number.
	 */
	எனில் (sscanf(cp + 1, "%u", &display_எண்) != 1 ||
	    display_எண் > UINT16_MAX - X11_BASE_PORT) {
		error("Could not parse display number from DISPLAY: %.100s",
		    display);
		திரும்பு -1;
	}

	/* Look up the host address */
	memset(&hints, 0, அளவு(hints));
	hints.ai_family = ssh->chanctxt->IPv4or6;
	hints.ai_socktype = SOCK_STREAM;
	snprintf(strport, அளவு strport, "%u", X11_BASE_PORT + display_எண்);
	எனில் ((gaierr = getaddrinfo(buf, strport, &hints, &aitop)) != 0) {
		error("%.100s: unknown host. (%s)", buf,
		ssh_gai_strerror(gaierr));
		திரும்பு -1;
	}
	க்கு (ai = aitop; ai; ai = ai->ai_next) {
		/* Create a socket. */
		sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		எனில் (sock == -1) {
			debug2("socket: %.100s", strerror(errno));
			தொடர்;
		}
		/* Connect it to the display. */
		எனில் (connect(sock, ai->ai_addr, ai->ai_addrlen) == -1) {
			debug2("connect %.100s port %u: %.100s", buf,
			    X11_BASE_PORT + display_எண், strerror(errno));
			close(sock);
			தொடர்;
		}
		/* Success */
		நிறுத்து;
	}
	freeaddrinfo(aitop);
	எனில் (!ai) {
		error("connect %.100s port %u: %.100s", buf,
		    X11_BASE_PORT + display_எண், strerror(errno));
		திரும்பு -1;
	}
	set_nodelay(sock);
	திரும்பு sock;
}

/*
 * Requests forwarding of X11 connections, generates fake authentication
 * data, and enables authentication spoofing.
 * This should be called in the client only.
 */
வெறுமை
x11_request_forwarding_with_spoofing(கட்டமைப்பு ssh *ssh, முழு client_session_id,
    மாறிலி எழுத்து *disp, மாறிலி எழுத்து *proto, மாறிலி எழுத்து *data, முழு want_reply)
{
	கட்டமைப்பு ssh_channels *sc = ssh->chanctxt;
	u_int data_len = (u_int) strlen(data) / 2;
	u_int i, மதிப்பு;
	மாறிலி எழுத்து *cp;
	எழுத்து *new_data;
	முழு r, screen_எண்;

	எனில் (sc->x11_saved_display == வெற்று)
		sc->x11_saved_display = xstrdup(disp);
	இல்லையெனில் எனில் (strcmp(disp, sc->x11_saved_display) != 0) {
		error("x11_request_forwarding_with_spoofing: different "
		    "$DISPLAY already forwarded");
		திரும்பு;
	}

	cp = strchr(disp, ':');
	எனில் (cp)
		cp = strchr(cp, '.');
	எனில் (cp)
		screen_எண் = (u_int)strtonum(cp + 1, 0, 400, வெற்று);
	இல்லையெனில்
		screen_எண் = 0;

	எனில் (sc->x11_saved_proto == வெற்று) {
		/* Save protocol name. */
		sc->x11_saved_proto = xstrdup(proto);

		/* Extract real authentication data. */
		sc->x11_saved_data = xmalloc(data_len);
		க்கு (i = 0; i < data_len; i++) {
			எனில் (sscanf(data + 2 * i, "%2x", &மதிப்பு) != 1) {
				fatal("x11_request_forwarding: bad "
				    "authentication data: %.100s", data);
			}
			sc->x11_saved_data[i] = மதிப்பு;
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
	எனில் ((r = sshpkt_put_u8(ssh, 0)) != 0 || /* bool: single connection */
	    (r = sshpkt_put_cstring(ssh, proto)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, new_data)) != 0 ||
	    (r = sshpkt_put_u32(ssh, screen_எண்)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send x11-req");
	விடுவி(new_data);
}

/*
 * Returns whether an x11 channel was used recently (less than a second ago)
 */
முழு
x11_channel_used_recently(கட்டமைப்பு ssh *ssh) {
	u_int i;
	Channel *c;
	இரட்டை lastused = 0;

	க்கு (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		எனில் (c == வெற்று || c->ctype == வெற்று || c->lastused == 0.0 ||
		    strcmp(c->ctype, "x11-connection") != 0)
			தொடர்;
		எனில் (c->lastused > lastused)
			lastused = c->lastused;
	}
	திரும்பு lastused != 0.0 && monotime_double() <= lastused + 1.0;
}
