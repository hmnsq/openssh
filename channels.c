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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/stat.h>
#അന്തര്ഭാവ <sys/ioctl.h>
#അന്തര്ഭാവ <sys/un.h>
#അന്തര്ഭാവ <sys/socket.h>
#അന്തര്ഭാവ <sys/queue.h>

#അന്തര്ഭാവ <netinet/in.h>
#അന്തര്ഭാവ <arpa/inet.h>

#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <fcntl.h>
#അന്തര്ഭാവ <limits.h>
#അന്തര്ഭാവ <netdb.h>
#അന്തര്ഭാവ <poll.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <stdint.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <termios.h>
#അന്തര്ഭാവ <unistd.h>

#അന്തര്ഭാവ "xmalloc.h"
#അന്തര്ഭാവ "ssh.h"
#അന്തര്ഭാവ "ssh2.h"
#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "packet.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "channels.h"
#അന്തര്ഭാവ "compat.h"
#അന്തര്ഭാവ "canohost.h"
#അന്തര്ഭാവ "pathnames.h"
#അന്തര്ഭാവ "match.h"

/* XXX remove once we're satisfied there's no lurking bugs */
/* #define DEBUG_CHANNEL_POLL 1 */

/* -- agent forwarding */
#define	അക്കം_SOCKS	10

/* -- X11 forwarding */
/* X11 port for display :0 */
#define X11_BASE_PORT	6000
/* Maximum number of fake X11 displays to try. */
#define MAX_DISPLAYS  1000

/* Per-channel callback for pre/post IO actions */
തരനിർവചനം ശൂന്യം chan_fn(ഘടന ssh *, Channel *c);

/*
 * Data structure for storing which hosts are permitted for forward requests.
 * The local sides of any remote forwards are stored in this array to prevent
 * a corrupt remote server from accessing arbitrary TCP/IP ports on our local
 * network (which might be behind a firewall).
 */
/* XXX: streamlocal wants a path instead of host:port */
/*      Overload host_to_connect; we could just make this match Forward */
/*	XXX - can we use listen_host instead of listen_path? */
ഘടന permission {
	അക്ഷരം *host_to_connect;		/* Connect to 'host'. */
	പൂർണ്ണസംഖ്യ port_to_connect;		/* Connect to 'port'. */
	അക്ഷരം *listen_host;		/* Remote side should listen address. */
	അക്ഷരം *listen_path;		/* Remote side should listen path. */
	പൂർണ്ണസംഖ്യ listen_port;		/* Remote side should listen port. */
	Channel *downstream;		/* Downstream mux*/
};

/* Context for non-blocking connects */
ഘടന channel_connect {
	അക്ഷരം *host;
	പൂർണ്ണസംഖ്യ port;
	ഘടന addrinfo *ai, *aitop;
};

/*
 * Stores the forwarding permission state for a single direction (local or
 * remote).
 */
ഘടന permission_set {
	/*
	 * List of all local permitted host/port pairs to allow for the
	 * user.
	 */
	u_int അക്കം_permitted_user;
	ഘടന permission *permitted_user;

	/*
	 * List of all permitted host/port pairs to allow for the admin.
	 */
	u_int അക്കം_permitted_admin;
	ഘടന permission *permitted_admin;

	/*
	 * If this is true, all opens/listens are permitted.  This is the
	 * case on the server on which we have to trust the client anyway,
	 * and the user could do anything after logging in.
	 */
	പൂർണ്ണസംഖ്യ all_permitted;
};

/* Used to record timeouts per channel type */
ഘടന ssh_channel_timeout {
	അക്ഷരം *type_pattern;
	ഇരട്ട timeout_secs;
};

/* Master structure for channels state */
ഘടന ssh_channels {
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
	ഘടന permission_set local_perms;
	ഘടന permission_set remote_perms;

	/* -- X11 forwarding */

	/* Saved X11 local (client) display. */
	അക്ഷരം *x11_saved_display;

	/* Saved X11 authentication protocol name. */
	അക്ഷരം *x11_saved_proto;

	/* Saved X11 authentication data.  This is the real data. */
	അക്ഷരം *x11_saved_data;
	u_int x11_saved_data_len;

	/* Deadline after which all X11 connections are refused */
	ഇരട്ട x11_refuse_time;

	/*
	 * Fake X11 authentication data.  This is what the server will be
	 * sending us; we should replace any occurrences of this by the
	 * real data.
	 */
	u_char *x11_fake_data;
	u_int x11_fake_data_len;

	/* AF_UNSPEC or AF_INET or AF_INET6 */
	പൂർണ്ണസംഖ്യ IPv4or6;

	/* Set SO_KEEPALIVE on TCP connections */
	പൂർണ്ണസംഖ്യ want_tcp_keepalive;

	/* Channel timeouts by type */
	ഘടന ssh_channel_timeout *timeouts;
	size_t ntimeouts;
	/* Global timeout for all OPEN channels */
	ഇരട്ട global_deadline;
	ഇരട്ട lastused;
	/* pattern-lists used to classify channels as bulk */
	അക്ഷരം *bulk_classifier_tty, *bulk_classifier_notty;
	/* Number of active bulk channels (set by channel_handler) */
	u_int nbulk;
};

/* helper */
സ്ഥിതം ശൂന്യം port_open_helper(ഘടന ssh *ssh, Channel *c, അക്ഷരം *rtype);
സ്ഥിതം സ്ഥിരം അക്ഷരം *channel_rfwd_bind_host(സ്ഥിരം അക്ഷരം *listen_host);

/* non-blocking connect helpers */
സ്ഥിതം പൂർണ്ണസംഖ്യ connect_next(ഘടന ssh *, ഘടന channel_connect *);
സ്ഥിതം Channel *rdynamic_connect_prepare(ഘടന ssh *, അക്ഷരം *, അക്ഷരം *);
സ്ഥിതം പൂർണ്ണസംഖ്യ rdynamic_connect_finish(ഘടന ssh *, Channel *);

/* Setup helper */
സ്ഥിതം ശൂന്യം channel_handler_init(ഘടന ssh_channels *sc);

/* -- channel core */

ശൂന്യം
channel_init_channels(ഘടന ssh *ssh)
{
	ഘടന ssh_channels *sc;

	എങ്കിൽ ((sc = calloc(1, വലുപ്പം(*sc))) == ശൂന്യ)
		fatal_f("allocation failed");
	sc->channels_alloc = 10;
	sc->channels = xcalloc(sc->channels_alloc, വലുപ്പം(*sc->channels));
	sc->IPv4or6 = AF_UNSPEC;
	sc->bulk_classifier_tty = xstrdup(CHANNEL_BULK_TTY);
	sc->bulk_classifier_notty = xstrdup(CHANNEL_BULK_NOTTY);
	channel_handler_init(sc);

	ssh->chanctxt = sc;
}

Channel *
channel_by_id(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ id)
{
	Channel *c;

	എങ്കിൽ (id < 0 || (u_int)id >= ssh->chanctxt->channels_alloc) {
		logit_f("%d: bad id", id);
		തിരികെ ശൂന്യ;
	}
	c = ssh->chanctxt->channels[id];
	എങ്കിൽ (c == ശൂന്യ) {
		logit_f("%d: bad id: channel free", id);
		തിരികെ ശൂന്യ;
	}
	തിരികെ c;
}

Channel *
channel_by_remote_id(ഘടന ssh *ssh, u_int remote_id)
{
	Channel *c;
	u_int i;

	വേണ്ടി (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		എങ്കിൽ (c != ശൂന്യ && c->have_remote_id && c->remote_id == remote_id)
			തിരികെ c;
	}
	തിരികെ ശൂന്യ;
}

/*
 * Returns the channel if it is allowed to receive protocol messages.
 * Private channels, like listening sockets, may not receive messages.
 */
Channel *
channel_lookup(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ id)
{
	Channel *c;

	എങ്കിൽ ((c = channel_by_id(ssh, id)) == ശൂന്യ)
		തിരികെ ശൂന്യ;

	തിരഞ്ഞെടുപ്പ് (c->type) {
	അവസ്ഥ SSH_CHANNEL_X11_OPEN:
	അവസ്ഥ SSH_CHANNEL_LARVAL:
	അവസ്ഥ SSH_CHANNEL_CONNECTING:
	അവസ്ഥ SSH_CHANNEL_DYNAMIC:
	അവസ്ഥ SSH_CHANNEL_RDYNAMIC_OPEN:
	അവസ്ഥ SSH_CHANNEL_RDYNAMIC_FINISH:
	അവസ്ഥ SSH_CHANNEL_OPENING:
	അവസ്ഥ SSH_CHANNEL_OPEN:
	അവസ്ഥ SSH_CHANNEL_ABANDONED:
	അവസ്ഥ SSH_CHANNEL_MUX_PROXY:
		തിരികെ c;
	}
	logit("Non-public channel %d, type %d.", id, c->type);
	തിരികെ ശൂന്യ;
}

സ്ഥിതം ശൂന്യം
free_connect_ctx(ഘടന channel_connect *cctx)
{
	സ്വതന്ത്രം(cctx->host);
	എങ്കിൽ (cctx->aitop) {
		എങ്കിൽ (cctx->aitop->ai_family == AF_UNIX)
			സ്വതന്ത്രം(cctx->aitop);
		അല്ലെങ്കിൽ
			freeaddrinfo(cctx->aitop);
	}
	memset(cctx, 0, വലുപ്പം(*cctx));
}

സ്ഥിതം ശൂന്യം
channel_free_connect_ctx(Channel *c)
{
	എങ്കിൽ (c == ശൂന്യ || c->connect_ctx == ശൂന്യ)
		തിരികെ;
	free_connect_ctx(c->connect_ctx);
	സ്വതന്ത്രം(c->connect_ctx);
	c->connect_ctx = ശൂന്യ;
}

/* Enable/disable TCP keepalives for X11 and port-forwarding sockets */
ശൂന്യം
channel_set_tcp_keepalives(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ on)
{
	ssh->chanctxt->want_tcp_keepalive = on;
}

/*
 * Add a timeout for open channels whose c->ctype (or c->xctype if it is set)
 * match type_pattern.
 */
ശൂന്യം
channel_add_timeout(ഘടന ssh *ssh, സ്ഥിരം അക്ഷരം *type_pattern,
    ഇരട്ട timeout_secs)
{
	ഘടന ssh_channels *sc = ssh->chanctxt;

	എങ്കിൽ (strcmp(type_pattern, "global") == 0) {
		debug2_f("global channel timeout %f seconds", timeout_secs);
		sc->global_deadline = timeout_secs;
		തിരികെ;
	}
	debug2_f("channel type \"%s\" timeout %f seconds",
	    type_pattern, timeout_secs);
	sc->timeouts = xrecallocarray(sc->timeouts, sc->ntimeouts,
	    sc->ntimeouts + 1, വലുപ്പം(*sc->timeouts));
	sc->timeouts[sc->ntimeouts].type_pattern = xstrdup(type_pattern);
	sc->timeouts[sc->ntimeouts].timeout_secs = timeout_secs;
	sc->ntimeouts++;
}

/* Clears all previously-added channel timeouts */
ശൂന്യം
channel_clear_timeouts(ഘടന ssh *ssh)
{
	ഘടന ssh_channels *sc = ssh->chanctxt;
	size_t i;

	debug3_f("clearing");
	വേണ്ടി (i = 0; i < sc->ntimeouts; i++)
		സ്വതന്ത്രം(sc->timeouts[i].type_pattern);
	സ്വതന്ത്രം(sc->timeouts);
	sc->timeouts = ശൂന്യ;
	sc->ntimeouts = 0;
}

സ്ഥിതം ഇരട്ട
lookup_timeout(ഘടന ssh *ssh, സ്ഥിരം അക്ഷരം *type)
{
	ഘടന ssh_channels *sc = ssh->chanctxt;
	size_t i;

	വേണ്ടി (i = 0; i < sc->ntimeouts; i++) {
		എങ്കിൽ (match_pattern(type, sc->timeouts[i].type_pattern))
			തിരികെ sc->timeouts[i].timeout_secs;
	}

	തിരികെ 0;
}

സ്ഥിതം ശൂന്യം
channel_classify(ഘടന ssh *ssh, Channel *c)
{
	ഘടന ssh_channels *sc = ssh->chanctxt;
	സ്ഥിരം അക്ഷരം *type = c->xctype == ശൂന്യ ? c->ctype : c->xctype;
	സ്ഥിരം പൂർണ്ണസംഖ്യ has_tty = c->isatty || c->remote_has_tty;
	സ്ഥിരം അക്ഷരം *classifier = has_tty ?
	    sc->bulk_classifier_tty : sc->bulk_classifier_notty;

	c->bulk = type != ശൂന്യ && match_pattern_list(type, classifier, 0) == 1;
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
ശൂന്യം
channel_set_xtype(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ id, സ്ഥിരം അക്ഷരം *xctype)
{
	ഘടന ssh_channels *sc = ssh->chanctxt;
	Channel *c;

	എങ്കിൽ ((c = channel_by_id(ssh, id)) == ശൂന്യ)
		fatal_f("missing channel %d", id);
	എങ്കിൽ (c->xctype != ശൂന്യ)
		സ്വതന്ത്രം(c->xctype);
	c->xctype = xstrdup(xctype);
	/* Only override deadline if xctype has a more specific match. */
	ഇരട്ട xtype_deadline = lookup_timeout(ssh, c->xctype);
	എങ്കിൽ (xtype_deadline != 0)
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
സ്ഥിതം ശൂന്യം
channel_set_used_time(ഘടന ssh *ssh, Channel *c)
{
	ssh->chanctxt->lastused = monotime_double();
	എങ്കിൽ (c != ശൂന്യ)
		c->lastused = ssh->chanctxt->lastused;
}

/*
 * Get the time at which a channel is due to time out for inactivity.
 * Returns 0 if the channel is not due to time out ever.
 */
സ്ഥിതം ഇരട്ട
channel_get_expiry(ഘടന ssh *ssh, Channel *c)
{
	ഘടന ssh_channels *sc = ssh->chanctxt;
	ഇരട്ട expiry = 0, channel_expiry;

	എങ്കിൽ (sc->lastused != 0 && sc->global_deadline != 0)
		expiry = sc->lastused + sc->global_deadline;
	എങ്കിൽ (c->lastused != 0 && c->inactive_deadline != 0) {
		channel_expiry = c->lastused + c->inactive_deadline;
		എങ്കിൽ (expiry == 0 || channel_expiry < expiry)
			expiry = channel_expiry;
	}
	തിരികെ expiry;
}

/* Returns non-zero if there is an open, non-interactive channel */
പൂർണ്ണസംഖ്യ
channel_has_bulk(ഘടന ssh *ssh)
{
	തിരികെ ssh->chanctxt != ശൂന്യ && ssh->chanctxt->nbulk != 0;
}

/*
 * Register filedescriptors for a channel, used when allocating a channel or
 * when the channel consumer/producer is ready, e.g. shell exec'd
 */
സ്ഥിതം ശൂന്യം
channel_register_fds(ഘടന ssh *ssh, Channel *c, പൂർണ്ണസംഖ്യ rfd, പൂർണ്ണസംഖ്യ wfd, പൂർണ്ണസംഖ്യ efd,
    പൂർണ്ണസംഖ്യ extusage, പൂർണ്ണസംഖ്യ nonblock, പൂർണ്ണസംഖ്യ is_tty)
{
	പൂർണ്ണസംഖ്യ val;

	എങ്കിൽ (rfd != -1)
		(ശൂന്യം)fcntl(rfd, F_SETFD, FD_CLOEXEC);
	എങ്കിൽ (wfd != -1 && wfd != rfd)
		(ശൂന്യം)fcntl(wfd, F_SETFD, FD_CLOEXEC);
	എങ്കിൽ (efd != -1 && efd != rfd && efd != wfd)
		(ശൂന്യം)fcntl(efd, F_SETFD, FD_CLOEXEC);

	c->rfd = rfd;
	c->wfd = wfd;
	c->sock = (rfd == wfd) ? rfd : -1;
	c->efd = efd;
	c->extended_usage = extusage;

	എങ്കിൽ ((c->isatty = is_tty) != 0)
		debug2("channel %d: rfd %d isatty", c->self, c->rfd);
#ifdef _AIX
	/* XXX: Later AIX versions can't push as much data to tty */
	c->wfd_isatty = is_tty || isatty(c->wfd);
#endif

	/* enable nonblocking mode */
	c->restore_block = 0;
	എങ്കിൽ (nonblock == CHANNEL_NONBLOCK_STDIO) {
		/*
		 * Special handling for stdio file descriptors: do not set
		 * non-blocking mode if they are TTYs. Otherwise prepare to
		 * restore their blocking state on exit to avoid interfering
		 * with other programs that follow.
		 */
		എങ്കിൽ (rfd != -1 && !isatty(rfd) &&
		    (val = fcntl(rfd, F_GETFL)) != -1 && !(val & O_NONBLOCK)) {
			c->restore_flags[0] = val;
			c->restore_block |= CHANNEL_RESTORE_RFD;
			set_nonblock(rfd);
		}
		എങ്കിൽ (wfd != -1 && !isatty(wfd) &&
		    (val = fcntl(wfd, F_GETFL)) != -1 && !(val & O_NONBLOCK)) {
			c->restore_flags[1] = val;
			c->restore_block |= CHANNEL_RESTORE_WFD;
			set_nonblock(wfd);
		}
		എങ്കിൽ (efd != -1 && !isatty(efd) &&
		    (val = fcntl(efd, F_GETFL)) != -1 && !(val & O_NONBLOCK)) {
			c->restore_flags[2] = val;
			c->restore_block |= CHANNEL_RESTORE_EFD;
			set_nonblock(efd);
		}
	} അല്ലെങ്കിൽ എങ്കിൽ (nonblock) {
		എങ്കിൽ (rfd != -1)
			set_nonblock(rfd);
		എങ്കിൽ (wfd != -1)
			set_nonblock(wfd);
		എങ്കിൽ (efd != -1)
			set_nonblock(efd);
	}
	/* channel might be entering a larval state, so reset global timeout */
	channel_set_used_time(ssh, ശൂന്യ);
	channel_classify(ssh, c);
}

/*
 * Allocate a new channel object and set its type and socket.
 */
Channel *
channel_new(ഘടന ssh *ssh, അക്ഷരം *ctype, പൂർണ്ണസംഖ്യ type, പൂർണ്ണസംഖ്യ rfd, പൂർണ്ണസംഖ്യ wfd, പൂർണ്ണസംഖ്യ efd,
    u_int window, u_int maxpack, പൂർണ്ണസംഖ്യ extusage, സ്ഥിരം അക്ഷരം *remote_name,
    പൂർണ്ണസംഖ്യ nonblock)
{
	ഘടന ssh_channels *sc = ssh->chanctxt;
	u_int i, found = 0;
	Channel *c;
	പൂർണ്ണസംഖ്യ r;

	/* Try to find a free slot where to put the new channel. */
	വേണ്ടി (i = 0; i < sc->channels_alloc; i++) {
		എങ്കിൽ (sc->channels[i] == ശൂന്യ) {
			/* Found a free slot. */
			found = i;
			നിർത്തുക;
		}
	}
	എങ്കിൽ (i >= sc->channels_alloc) {
		/*
		 * There are no free slots. Take last+1 slot and expand
		 * the array.
		 */
		found = sc->channels_alloc;
		എങ്കിൽ (sc->channels_alloc > CHANNELS_MAX_CHANNELS)
			fatal_f("internal error: channels_alloc %d too big",
			    sc->channels_alloc);
		sc->channels = xrecallocarray(sc->channels, sc->channels_alloc,
		    sc->channels_alloc + 10, വലുപ്പം(*sc->channels));
		sc->channels_alloc += 10;
		debug2("channel: expanding %d", sc->channels_alloc);
	}
	/* Initialize and return new channel. */
	c = sc->channels[found] = xcalloc(1, വലുപ്പം(Channel));
	എങ്കിൽ ((c->നിവേശം = sshbuf_new()) == ശൂന്യ ||
	    (c->output = sshbuf_new()) == ശൂന്യ ||
	    (c->extended = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	എങ്കിൽ ((r = sshbuf_set_max_size(c->നിവേശം, CHAN_നിവേശം_MAX)) != 0)
		fatal_fr(r, "sshbuf_set_max_size");
	c->ostate = CHAN_OUTPUT_OPEN;
	c->istate = CHAN_നിവേശം_OPEN;
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
	തിരികെ c;
}

ശൂന്യം
channel_set_tty(ഘടന ssh *ssh, Channel *c)
{
	c->remote_has_tty = 1;
	channel_classify(ssh, c);
}

പൂർണ്ണസംഖ്യ
channel_close_fd(ഘടന ssh *ssh, Channel *c, പൂർണ്ണസംഖ്യ *fdp)
{
	പൂർണ്ണസംഖ്യ ret, fd = *fdp;

	എങ്കിൽ (fd == -1)
		തിരികെ 0;

	/* restore blocking */
	എങ്കിൽ (*fdp == c->rfd &&
	    (c->restore_block & CHANNEL_RESTORE_RFD) != 0)
		(ശൂന്യം)fcntl(*fdp, F_SETFL, c->restore_flags[0]);
	അല്ലെങ്കിൽ എങ്കിൽ (*fdp == c->wfd &&
	    (c->restore_block & CHANNEL_RESTORE_WFD) != 0)
		(ശൂന്യം)fcntl(*fdp, F_SETFL, c->restore_flags[1]);
	അല്ലെങ്കിൽ എങ്കിൽ (*fdp == c->efd &&
	    (c->restore_block & CHANNEL_RESTORE_EFD) != 0)
		(ശൂന്യം)fcntl(*fdp, F_SETFL, c->restore_flags[2]);

	എങ്കിൽ (*fdp == c->rfd) {
		c->io_want &= ~SSH_CHAN_IO_RFD;
		c->io_ready &= ~SSH_CHAN_IO_RFD;
		c->rfd = -1;
		c->pfds[0] = -1;
	}
	എങ്കിൽ (*fdp == c->wfd) {
		c->io_want &= ~SSH_CHAN_IO_WFD;
		c->io_ready &= ~SSH_CHAN_IO_WFD;
		c->wfd = -1;
		c->pfds[1] = -1;
	}
	എങ്കിൽ (*fdp == c->efd) {
		c->io_want &= ~SSH_CHAN_IO_EFD;
		c->io_ready &= ~SSH_CHAN_IO_EFD;
		c->efd = -1;
		c->pfds[2] = -1;
	}
	എങ്കിൽ (*fdp == c->sock) {
		c->io_want &= ~SSH_CHAN_IO_SOCK;
		c->io_ready &= ~SSH_CHAN_IO_SOCK;
		c->sock = -1;
		c->pfds[3] = -1;
	}

	ret = close(fd);
	*fdp = -1; /* probably redundant */
	തിരികെ ret;
}

/* Close all channel fd/socket. */
സ്ഥിതം ശൂന്യം
channel_close_fds(ഘടന ssh *ssh, Channel *c)
{
	പൂർണ്ണസംഖ്യ sock = c->sock, rfd = c->rfd, wfd = c->wfd, efd = c->efd;

	channel_close_fd(ssh, c, &c->sock);
	എങ്കിൽ (rfd != sock)
		channel_close_fd(ssh, c, &c->rfd);
	എങ്കിൽ (wfd != sock && wfd != rfd)
		channel_close_fd(ssh, c, &c->wfd);
	എങ്കിൽ (efd != sock && efd != rfd && efd != wfd)
		channel_close_fd(ssh, c, &c->efd);
}

സ്ഥിതം ശൂന്യം
fwd_perm_clear(ഘടന permission *perm)
{
	സ്വതന്ത്രം(perm->host_to_connect);
	സ്വതന്ത്രം(perm->listen_host);
	സ്വതന്ത്രം(perm->listen_path);
	memset(perm, 0, വലുപ്പം(*perm));
}

/* Returns an printable name for the specified forwarding permission list */
സ്ഥിതം സ്ഥിരം അക്ഷരം *
fwd_ident(പൂർണ്ണസംഖ്യ who, പൂർണ്ണസംഖ്യ where)
{
	എങ്കിൽ (who == FORWARD_ADM) {
		എങ്കിൽ (where == FORWARD_LOCAL)
			തിരികെ "admin local";
		അല്ലെങ്കിൽ എങ്കിൽ (where == FORWARD_REMOTE)
			തിരികെ "admin remote";
	} അല്ലെങ്കിൽ എങ്കിൽ (who == FORWARD_USER) {
		എങ്കിൽ (where == FORWARD_LOCAL)
			തിരികെ "user local";
		അല്ലെങ്കിൽ എങ്കിൽ (where == FORWARD_REMOTE)
			തിരികെ "user remote";
	}
	fatal("Unknown forward permission list %d/%d", who, where);
}

/* Returns the forwarding permission list for the specified direction */
സ്ഥിതം ഘടന permission_set *
permission_set_get(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ where)
{
	ഘടന ssh_channels *sc = ssh->chanctxt;

	തിരഞ്ഞെടുപ്പ് (where) {
	അവസ്ഥ FORWARD_LOCAL:
		തിരികെ &sc->local_perms;
		നിർത്തുക;
	അവസ്ഥ FORWARD_REMOTE:
		തിരികെ &sc->remote_perms;
		നിർത്തുക;
	സ്ഥിരസ്ഥിതി:
		fatal_f("invalid forwarding direction %d", where);
	}
}

/* Returns pointers to the specified forwarding list and its element count */
സ്ഥിതം ശൂന്യം
permission_set_get_array(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ who, പൂർണ്ണസംഖ്യ where,
    ഘടന permission ***permpp, u_int **npermpp)
{
	ഘടന permission_set *pset = permission_set_get(ssh, where);

	തിരഞ്ഞെടുപ്പ് (who) {
	അവസ്ഥ FORWARD_USER:
		*permpp = &pset->permitted_user;
		*npermpp = &pset->അക്കം_permitted_user;
		നിർത്തുക;
	അവസ്ഥ FORWARD_ADM:
		*permpp = &pset->permitted_admin;
		*npermpp = &pset->അക്കം_permitted_admin;
		നിർത്തുക;
	സ്ഥിരസ്ഥിതി:
		fatal_f("invalid forwarding client %d", who);
	}
}

/* Adds an entry to the specified forwarding list */
സ്ഥിതം പൂർണ്ണസംഖ്യ
permission_set_add(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ who, പൂർണ്ണസംഖ്യ where,
    സ്ഥിരം അക്ഷരം *host_to_connect, പൂർണ്ണസംഖ്യ port_to_connect,
    സ്ഥിരം അക്ഷരം *listen_host, സ്ഥിരം അക്ഷരം *listen_path, പൂർണ്ണസംഖ്യ listen_port,
    Channel *downstream)
{
	ഘടന permission **permp;
	u_int n, *npermp;

	permission_set_get_array(ssh, who, where, &permp, &npermp);

	എങ്കിൽ (*npermp >= INT_MAX)
		fatal_f("%s overflow", fwd_ident(who, where));

	*permp = xrecallocarray(*permp, *npermp, *npermp + 1, വലുപ്പം(**permp));
	n = (*npermp)++;
#define MAYBE_DUP(s) ((s == ശൂന്യ) ? ശൂന്യ : xstrdup(s))
	(*permp)[n].host_to_connect = MAYBE_DUP(host_to_connect);
	(*permp)[n].port_to_connect = port_to_connect;
	(*permp)[n].listen_host = MAYBE_DUP(listen_host);
	(*permp)[n].listen_path = MAYBE_DUP(listen_path);
	(*permp)[n].listen_port = listen_port;
	(*permp)[n].downstream = downstream;
#undef MAYBE_DUP
	തിരികെ (പൂർണ്ണസംഖ്യ)n;
}

സ്ഥിതം ശൂന്യം
mux_remove_remote_forwardings(ഘടന ssh *ssh, Channel *c)
{
	ഘടന ssh_channels *sc = ssh->chanctxt;
	ഘടന permission_set *pset = &sc->local_perms;
	ഘടന permission *perm;
	പൂർണ്ണസംഖ്യ r;
	u_int i;

	വേണ്ടി (i = 0; i < pset->അക്കം_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		എങ്കിൽ (perm->downstream != c)
			തുടരുക;

		/* cancel on the server, since mux client is gone */
		debug("channel %d: cleanup remote forward for %s:%u",
		    c->self, perm->listen_host, perm->listen_port);
		എങ്കിൽ ((r = sshpkt_start(ssh, SSH2_സന്ദേശം_GLOBAL_REQUEST)) != 0 ||
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
ശൂന്യം
channel_free(ഘടന ssh *ssh, Channel *c)
{
	ഘടന ssh_channels *sc = ssh->chanctxt;
	അക്ഷരം *s;
	u_int i, n;
	Channel *other;
	ഘടന channel_confirm *cc;

	വേണ്ടി (n = 0, i = 0; i < sc->channels_alloc; i++) {
		എങ്കിൽ ((other = sc->channels[i]) == ശൂന്യ)
			തുടരുക;
		n++;
		/* detach from mux client and prepare for closing */
		എങ്കിൽ (c->type == SSH_CHANNEL_MUX_CLIENT &&
		    other->type == SSH_CHANNEL_MUX_PROXY &&
		    other->mux_ctx == c) {
			other->mux_ctx = ശൂന്യ;
			other->type = SSH_CHANNEL_OPEN;
			other->istate = CHAN_നിവേശം_CLOSED;
			other->ostate = CHAN_OUTPUT_CLOSED;
		}
	}
	debug("channel %d: free: %s, nchannels %u", c->self,
	    c->remote_name ? c->remote_name : "???", n);

	എങ്കിൽ (c->type == SSH_CHANNEL_MUX_CLIENT) {
		mux_remove_remote_forwardings(ssh, c);
		സ്വതന്ത്രം(c->mux_ctx);
		c->mux_ctx = ശൂന്യ;
	} അല്ലെങ്കിൽ എങ്കിൽ (c->type == SSH_CHANNEL_MUX_LISTENER) {
		സ്വതന്ത്രം(c->mux_ctx);
		c->mux_ctx = ശൂന്യ;
	}

	എങ്കിൽ (log_level_get() >= SYSLOG_LEVEL_DEBUG3) {
		s = channel_open_message(ssh);
		debug3("channel %d: status: %s", c->self, s);
		സ്വതന്ത്രം(s);
	}

	channel_close_fds(ssh, c);
	sshbuf_free(c->നിവേശം);
	sshbuf_free(c->output);
	sshbuf_free(c->extended);
	c->നിവേശം = c->output = c->extended = ശൂന്യ;
	സ്വതന്ത്രം(c->remote_name);
	c->remote_name = ശൂന്യ;
	സ്വതന്ത്രം(c->path);
	c->path = ശൂന്യ;
	സ്വതന്ത്രം(c->listening_addr);
	c->listening_addr = ശൂന്യ;
	സ്വതന്ത്രം(c->xctype);
	c->xctype = ശൂന്യ;
	channel_free_connect_ctx(c);
	ആകുമ്പോൾ ((cc = TAILQ_FIRST(&c->status_confirms)) != ശൂന്യ) {
		എങ്കിൽ (cc->abandon_cb != ശൂന്യ)
			cc->abandon_cb(ssh, c, cc->ctx);
		TAILQ_REMOVE(&c->status_confirms, cc, entry);
		freezero(cc, വലുപ്പം(*cc));
	}
	എങ്കിൽ (c->filter_cleanup != ശൂന്യ && c->filter_ctx != ശൂന്യ)
		c->filter_cleanup(ssh, c->self, c->filter_ctx);
	sc->channels[c->self] = ശൂന്യ;
	freezero(c, വലുപ്പം(*c));
}

ശൂന്യം
channel_free_all(ഘടന ssh *ssh)
{
	u_int i;
	ഘടന ssh_channels *sc = ssh->chanctxt;

	വേണ്ടി (i = 0; i < sc->channels_alloc; i++)
		എങ്കിൽ (sc->channels[i] != ശൂന്യ)
			channel_free(ssh, sc->channels[i]);

	സ്വതന്ത്രം(sc->channels);
	sc->channels = ശൂന്യ;
	sc->channels_alloc = 0;

	സ്വതന്ത്രം(sc->x11_saved_display);
	sc->x11_saved_display = ശൂന്യ;

	സ്വതന്ത്രം(sc->x11_saved_proto);
	sc->x11_saved_proto = ശൂന്യ;

	സ്വതന്ത്രം(sc->x11_saved_data);
	sc->x11_saved_data = ശൂന്യ;
	sc->x11_saved_data_len = 0;

	സ്വതന്ത്രം(sc->x11_fake_data);
	sc->x11_fake_data = ശൂന്യ;
	sc->x11_fake_data_len = 0;
}

ശൂന്യം
channel_free_channels(ഘടന ssh *ssh)
{
	ഘടന ssh_channels *sc;

	എങ്കിൽ (ssh == ശൂന്യ || ssh->chanctxt == ശൂന്യ)
		തിരികെ;
	channel_free_all(ssh);
	channel_clear_permission(ssh, FORWARD_USER, FORWARD_LOCAL);
	channel_clear_permission(ssh, FORWARD_USER, FORWARD_REMOTE);
	channel_clear_permission(ssh, FORWARD_ADM, FORWARD_LOCAL);
	channel_clear_permission(ssh, FORWARD_ADM, FORWARD_REMOTE);
	sc = ssh->chanctxt;
	സ്വതന്ത്രം(sc->bulk_classifier_tty);
	സ്വതന്ത്രം(sc->bulk_classifier_notty);
	സ്വതന്ത്രം(sc->channel_pre);
	സ്വതന്ത്രം(sc->channel_post);
	freezero(sc, വലുപ്പം(*sc));
	ssh->chanctxt = ശൂന്യ;
}

/*
 * Closes the sockets/fds of all channels.  This is used to close extra file
 * descriptors after a fork.
 */
ശൂന്യം
channel_close_all(ഘടന ssh *ssh)
{
	u_int i;

	വേണ്ടി (i = 0; i < ssh->chanctxt->channels_alloc; i++)
		എങ്കിൽ (ssh->chanctxt->channels[i] != ശൂന്യ)
			channel_close_fds(ssh, ssh->chanctxt->channels[i]);
}

/*
 * Stop listening to channels.
 */
ശൂന്യം
channel_stop_listening(ഘടന ssh *ssh)
{
	u_int i;
	Channel *c;

	വേണ്ടി (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		എങ്കിൽ (c != ശൂന്യ) {
			തിരഞ്ഞെടുപ്പ് (c->type) {
			അവസ്ഥ SSH_CHANNEL_AUTH_SOCKET:
			അവസ്ഥ SSH_CHANNEL_PORT_LISTENER:
			അവസ്ഥ SSH_CHANNEL_RPORT_LISTENER:
			അവസ്ഥ SSH_CHANNEL_X11_LISTENER:
			അവസ്ഥ SSH_CHANNEL_UNIX_LISTENER:
			അവസ്ഥ SSH_CHANNEL_RUNIX_LISTENER:
				channel_close_fd(ssh, c, &c->sock);
				channel_free(ssh, c);
				നിർത്തുക;
			}
		}
	}
}

/*
 * Returns true if no channel has too much buffered data, and false if one or
 * more channel is overfull.
 */
പൂർണ്ണസംഖ്യ
channel_not_very_much_buffered_data(ഘടന ssh *ssh)
{
	u_int i;
	u_int maxsize = ssh_packet_get_maxsize(ssh);
	Channel *c;

	വേണ്ടി (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		എങ്കിൽ (c == ശൂന്യ || c->type != SSH_CHANNEL_OPEN)
			തുടരുക;
		എങ്കിൽ (sshbuf_len(c->output) > maxsize) {
			debug2("channel %d: big output buffer %zu > %u",
			    c->self, sshbuf_len(c->output), maxsize);
			തിരികെ 0;
		}
	}
	തിരികെ 1;
}

/* Returns true if any channel is still open. */
പൂർണ്ണസംഖ്യ
channel_still_open(ഘടന ssh *ssh)
{
	u_int i;
	Channel *c;

	വേണ്ടി (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		എങ്കിൽ (c == ശൂന്യ)
			തുടരുക;
		തിരഞ്ഞെടുപ്പ് (c->type) {
		അവസ്ഥ SSH_CHANNEL_X11_LISTENER:
		അവസ്ഥ SSH_CHANNEL_PORT_LISTENER:
		അവസ്ഥ SSH_CHANNEL_RPORT_LISTENER:
		അവസ്ഥ SSH_CHANNEL_MUX_LISTENER:
		അവസ്ഥ SSH_CHANNEL_CLOSED:
		അവസ്ഥ SSH_CHANNEL_AUTH_SOCKET:
		അവസ്ഥ SSH_CHANNEL_DYNAMIC:
		അവസ്ഥ SSH_CHANNEL_RDYNAMIC_OPEN:
		അവസ്ഥ SSH_CHANNEL_CONNECTING:
		അവസ്ഥ SSH_CHANNEL_ZOMBIE:
		അവസ്ഥ SSH_CHANNEL_ABANDONED:
		അവസ്ഥ SSH_CHANNEL_UNIX_LISTENER:
		അവസ്ഥ SSH_CHANNEL_RUNIX_LISTENER:
			തുടരുക;
		അവസ്ഥ SSH_CHANNEL_LARVAL:
			തുടരുക;
		അവസ്ഥ SSH_CHANNEL_OPENING:
		അവസ്ഥ SSH_CHANNEL_OPEN:
		അവസ്ഥ SSH_CHANNEL_RDYNAMIC_FINISH:
		അവസ്ഥ SSH_CHANNEL_X11_OPEN:
		അവസ്ഥ SSH_CHANNEL_MUX_CLIENT:
		അവസ്ഥ SSH_CHANNEL_MUX_PROXY:
			തിരികെ 1;
		സ്ഥിരസ്ഥിതി:
			fatal_f("bad channel type %d", c->type);
			/* NOTREACHED */
		}
	}
	തിരികെ 0;
}

/* Returns true if a channel with a TTY is open. */
പൂർണ്ണസംഖ്യ
channel_tty_open(ഘടന ssh *ssh)
{
	u_int i;
	Channel *c;

	വേണ്ടി (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		എങ്കിൽ (c == ശൂന്യ || c->type != SSH_CHANNEL_OPEN)
			തുടരുക;
		എങ്കിൽ (c->client_tty)
			തിരികെ 1;
	}
	തിരികെ 0;
}

/* Returns the id of an open channel suitable for keepaliving */
പൂർണ്ണസംഖ്യ
channel_find_open(ഘടന ssh *ssh)
{
	u_int i;
	Channel *c;

	വേണ്ടി (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		എങ്കിൽ (c == ശൂന്യ || !c->have_remote_id)
			തുടരുക;
		തിരഞ്ഞെടുപ്പ് (c->type) {
		അവസ്ഥ SSH_CHANNEL_CLOSED:
		അവസ്ഥ SSH_CHANNEL_DYNAMIC:
		അവസ്ഥ SSH_CHANNEL_RDYNAMIC_OPEN:
		അവസ്ഥ SSH_CHANNEL_RDYNAMIC_FINISH:
		അവസ്ഥ SSH_CHANNEL_X11_LISTENER:
		അവസ്ഥ SSH_CHANNEL_PORT_LISTENER:
		അവസ്ഥ SSH_CHANNEL_RPORT_LISTENER:
		അവസ്ഥ SSH_CHANNEL_MUX_LISTENER:
		അവസ്ഥ SSH_CHANNEL_MUX_CLIENT:
		അവസ്ഥ SSH_CHANNEL_MUX_PROXY:
		അവസ്ഥ SSH_CHANNEL_OPENING:
		അവസ്ഥ SSH_CHANNEL_CONNECTING:
		അവസ്ഥ SSH_CHANNEL_ZOMBIE:
		അവസ്ഥ SSH_CHANNEL_ABANDONED:
		അവസ്ഥ SSH_CHANNEL_UNIX_LISTENER:
		അവസ്ഥ SSH_CHANNEL_RUNIX_LISTENER:
			തുടരുക;
		അവസ്ഥ SSH_CHANNEL_LARVAL:
		അവസ്ഥ SSH_CHANNEL_AUTH_SOCKET:
		അവസ്ഥ SSH_CHANNEL_OPEN:
		അവസ്ഥ SSH_CHANNEL_X11_OPEN:
			തിരികെ i;
		സ്ഥിരസ്ഥിതി:
			fatal_f("bad channel type %d", c->type);
			/* NOTREACHED */
		}
	}
	തിരികെ -1;
}

/* Returns the state of the channel's extended usage flag */
സ്ഥിരം അക്ഷരം *
channel_format_extended_usage(സ്ഥിരം Channel *c)
{
	എങ്കിൽ (c->efd == -1)
		തിരികെ "closed";

	തിരഞ്ഞെടുപ്പ് (c->extended_usage) {
	അവസ്ഥ CHAN_EXTENDED_WRITE:
		തിരികെ "write";
	അവസ്ഥ CHAN_EXTENDED_READ:
		തിരികെ "read";
	അവസ്ഥ CHAN_EXTENDED_IGNORE:
		തിരികെ "ignore";
	സ്ഥിരസ്ഥിതി:
		തിരികെ "UNKNOWN";
	}
}

സ്ഥിതം അക്ഷരം *
channel_format_status(സ്ഥിരം Channel *c)
{
	അക്ഷരം *ret = ശൂന്യ;

	xasprintf(&ret, "t%d [%s] %s%u %s%u i%u/%zu o%u/%zu e[%s]/%zu "
	    "fd %d/%d/%d sock %d cc %d %s%u io 0x%02x/0x%02x %s%s",
	    c->type, c->xctype != ശൂന്യ ? c->xctype : c->ctype,
	    c->have_remote_id ? "r" : "nr", c->remote_id,
	    c->mux_ctx != ശൂന്യ ? "m" : "nm", c->mux_downstream_id,
	    c->istate, sshbuf_len(c->നിവേശം),
	    c->ostate, sshbuf_len(c->output),
	    channel_format_extended_usage(c), sshbuf_len(c->extended),
	    c->rfd, c->wfd, c->efd, c->sock, c->ctl_chan,
	    c->have_ctl_child_id ? "c" : "nc", c->ctl_child_id,
	    c->io_want, c->io_ready,
	    c->isatty ? "T" : (c->remote_has_tty ? "RT" : ""),
	    c->bulk ? "B" : "I");
	തിരികെ ret;
}

/*
 * Returns a message describing the currently open forwarded connections,
 * suitable for sending to the client.  The message contains crlf pairs for
 * newlines.
 */
അക്ഷരം *
channel_open_message(ഘടന ssh *ssh)
{
	ഘടന sshbuf *buf;
	Channel *c;
	u_int i;
	പൂർണ്ണസംഖ്യ r;
	അക്ഷരം *cp, *ret;

	എങ്കിൽ ((buf = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new");
	എങ്കിൽ ((r = sshbuf_putf(buf,
	    "The following connections are open:\r\n")) != 0)
		fatal_fr(r, "sshbuf_putf");
	വേണ്ടി (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		എങ്കിൽ (c == ശൂന്യ)
			തുടരുക;
		തിരഞ്ഞെടുപ്പ് (c->type) {
		അവസ്ഥ SSH_CHANNEL_X11_LISTENER:
		അവസ്ഥ SSH_CHANNEL_PORT_LISTENER:
		അവസ്ഥ SSH_CHANNEL_RPORT_LISTENER:
		അവസ്ഥ SSH_CHANNEL_CLOSED:
		അവസ്ഥ SSH_CHANNEL_AUTH_SOCKET:
		അവസ്ഥ SSH_CHANNEL_ZOMBIE:
		അവസ്ഥ SSH_CHANNEL_ABANDONED:
		അവസ്ഥ SSH_CHANNEL_MUX_LISTENER:
		അവസ്ഥ SSH_CHANNEL_UNIX_LISTENER:
		അവസ്ഥ SSH_CHANNEL_RUNIX_LISTENER:
			തുടരുക;
		അവസ്ഥ SSH_CHANNEL_LARVAL:
		അവസ്ഥ SSH_CHANNEL_OPENING:
		അവസ്ഥ SSH_CHANNEL_CONNECTING:
		അവസ്ഥ SSH_CHANNEL_DYNAMIC:
		അവസ്ഥ SSH_CHANNEL_RDYNAMIC_OPEN:
		അവസ്ഥ SSH_CHANNEL_RDYNAMIC_FINISH:
		അവസ്ഥ SSH_CHANNEL_OPEN:
		അവസ്ഥ SSH_CHANNEL_X11_OPEN:
		അവസ്ഥ SSH_CHANNEL_MUX_PROXY:
		അവസ്ഥ SSH_CHANNEL_MUX_CLIENT:
			cp = channel_format_status(c);
			എങ്കിൽ ((r = sshbuf_putf(buf, "  #%d %.300s (%s)\r\n",
			    c->self, c->remote_name, cp)) != 0) {
				സ്വതന്ത്രം(cp);
				fatal_fr(r, "sshbuf_putf");
			}
			സ്വതന്ത്രം(cp);
			തുടരുക;
		സ്ഥിരസ്ഥിതി:
			fatal_f("bad channel type %d", c->type);
			/* NOTREACHED */
		}
	}
	എങ്കിൽ ((ret = sshbuf_dup_string(buf)) == ശൂന്യ)
		fatal_f("sshbuf_dup_string");
	sshbuf_free(buf);
	തിരികെ ret;
}

ശൂന്യം
channel_report_open(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ level)
{
	അക്ഷരം *open, *oopen, *cp, ident[256];

	sshpkt_fmt_connection_id(ssh, ident, വലുപ്പം(ident));
	do_log2(level, "Connection: %s (pid %ld)", ident, (long)getpid());
	open = oopen = channel_open_message(ssh);
	ആകുമ്പോൾ ((cp = strsep(&open, "\r\n")) != ശൂന്യ) {
		എങ്കിൽ (*cp != '\0')
			do_log2(level, "%s", cp);
	}
	സ്വതന്ത്രം(oopen);
}

സ്ഥിതം ശൂന്യം
open_preamble(ഘടന ssh *ssh, സ്ഥിരം അക്ഷരം *where, Channel *c, സ്ഥിരം അക്ഷരം *type)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = sshpkt_start(ssh, SSH2_സന്ദേശം_CHANNEL_OPEN)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, type)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_window)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0) {
		fatal_r(r, "%s: channel %i: open", where, c->self);
	}
}

ശൂന്യം
channel_send_open(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ id)
{
	Channel *c = channel_lookup(ssh, id);
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (c == ശൂന്യ) {
		logit("channel_send_open: %d: bad id", id);
		തിരികെ;
	}
	debug2("channel %d: send open", id);
	open_preamble(ssh, __func__, c, c->ctype);
	എങ്കിൽ ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i", c->self);
}

ശൂന്യം
channel_request_start(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ id, സ്ഥിരം അക്ഷരം *service,
    പൂർണ്ണസംഖ്യ wantconfirm)
{
	Channel *c = channel_lookup(ssh, id);
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (c == ശൂന്യ) {
		logit_f("%d: unknown channel id", id);
		തിരികെ;
	}
	എങ്കിൽ (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);

	debug2("channel %d: request %s confirm %d", id, service, wantconfirm);
	എങ്കിൽ ((r = sshpkt_start(ssh, SSH2_സന്ദേശം_CHANNEL_REQUEST)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, service)) != 0 ||
	    (r = sshpkt_put_u8(ssh, wantconfirm)) != 0) {
		fatal_fr(r, "channel %i", c->self);
	}
}

ശൂന്യം
channel_register_status_confirm(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ id,
    channel_confirm_cb *cb, channel_confirm_abandon_cb *abandon_cb, ശൂന്യം *ctx)
{
	ഘടന channel_confirm *cc;
	Channel *c;

	എങ്കിൽ ((c = channel_lookup(ssh, id)) == ശൂന്യ)
		fatal_f("%d: bad id", id);

	cc = xcalloc(1, വലുപ്പം(*cc));
	cc->cb = cb;
	cc->abandon_cb = abandon_cb;
	cc->ctx = ctx;
	TAILQ_INSERT_TAIL(&c->status_confirms, cc, entry);
}

ശൂന്യം
channel_register_open_confirm(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ id,
    channel_open_fn *fn, ശൂന്യം *ctx)
{
	Channel *c = channel_lookup(ssh, id);

	എങ്കിൽ (c == ശൂന്യ) {
		logit_f("%d: bad id", id);
		തിരികെ;
	}
	c->open_confirm = fn;
	c->open_confirm_ctx = ctx;
}

ശൂന്യം
channel_register_cleanup(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ id,
    channel_callback_fn *fn, പൂർണ്ണസംഖ്യ do_close)
{
	Channel *c = channel_by_id(ssh, id);

	എങ്കിൽ (c == ശൂന്യ) {
		logit_f("%d: bad id", id);
		തിരികെ;
	}
	c->detach_user = fn;
	c->detach_close = do_close;
}

ശൂന്യം
channel_cancel_cleanup(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ id)
{
	Channel *c = channel_by_id(ssh, id);

	എങ്കിൽ (c == ശൂന്യ) {
		logit_f("%d: bad id", id);
		തിരികെ;
	}
	c->detach_user = ശൂന്യ;
	c->detach_close = 0;
}

ശൂന്യം
channel_register_filter(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ id, channel_infilter_fn *ifn,
    channel_outfilter_fn *ofn, channel_filter_cleanup_fn *cfn, ശൂന്യം *ctx)
{
	Channel *c = channel_lookup(ssh, id);

	എങ്കിൽ (c == ശൂന്യ) {
		logit_f("%d: bad id", id);
		തിരികെ;
	}
	c->നിവേശം_filter = ifn;
	c->output_filter = ofn;
	c->filter_ctx = ctx;
	c->filter_cleanup = cfn;
}

ശൂന്യം
channel_set_fds(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ id, പൂർണ്ണസംഖ്യ rfd, പൂർണ്ണസംഖ്യ wfd, പൂർണ്ണസംഖ്യ efd,
    പൂർണ്ണസംഖ്യ extusage, പൂർണ്ണസംഖ്യ nonblock, പൂർണ്ണസംഖ്യ is_tty, u_int window_max)
{
	Channel *c = channel_lookup(ssh, id);
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (c == ശൂന്യ || c->type != SSH_CHANNEL_LARVAL)
		fatal("channel_activate for non-larval channel %d.", id);
	എങ്കിൽ (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);

	channel_register_fds(ssh, c, rfd, wfd, efd, extusage, nonblock, is_tty);
	c->type = SSH_CHANNEL_OPEN;
	channel_set_used_time(ssh, c);
	c->local_window = c->local_window_max = window_max;

	എങ്കിൽ ((r = sshpkt_start(ssh, SSH2_സന്ദേശം_CHANNEL_WINDOW_ADJUST)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_window)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i", c->self);
}

സ്ഥിതം ശൂന്യം
channel_pre_listener(ഘടന ssh *ssh, Channel *c)
{
	c->io_want = SSH_CHAN_IO_SOCK_R;
}

സ്ഥിതം ശൂന്യം
channel_pre_connecting(ഘടന ssh *ssh, Channel *c)
{
	debug3("channel %d: waiting for connection", c->self);
	c->io_want = SSH_CHAN_IO_SOCK_W;
}

സ്ഥിതം ശൂന്യം
channel_pre_open(ഘടന ssh *ssh, Channel *c)
{
	c->io_want = 0;
	എങ്കിൽ (c->istate == CHAN_നിവേശം_OPEN &&
	    c->remote_window > 0 &&
	    sshbuf_len(c->നിവേശം) < c->remote_window &&
	    sshbuf_check_reserve(c->നിവേശം, CHAN_RBUF) == 0)
		c->io_want |= SSH_CHAN_IO_RFD;
	എങ്കിൽ (c->ostate == CHAN_OUTPUT_OPEN ||
	    c->ostate == CHAN_OUTPUT_WAIT_DRAIN) {
		എങ്കിൽ (sshbuf_len(c->output) > 0) {
			c->io_want |= SSH_CHAN_IO_WFD;
		} അല്ലെങ്കിൽ എങ്കിൽ (c->ostate == CHAN_OUTPUT_WAIT_DRAIN) {
			എങ്കിൽ (CHANNEL_EFD_OUTPUT_ACTIVE(c))
				debug2("channel %d: "
				    "obuf_empty delayed efd %d/(%zu)", c->self,
				    c->efd, sshbuf_len(c->extended));
			അല്ലെങ്കിൽ
				chan_obuf_empty(ssh, c);
		}
	}
	/** XXX check close conditions, too */
	എങ്കിൽ (c->efd != -1 && !(c->istate == CHAN_നിവേശം_CLOSED &&
	    c->ostate == CHAN_OUTPUT_CLOSED)) {
		എങ്കിൽ (c->extended_usage == CHAN_EXTENDED_WRITE &&
		    sshbuf_len(c->extended) > 0)
			c->io_want |= SSH_CHAN_IO_EFD_W;
		അല്ലെങ്കിൽ എങ്കിൽ (c->efd != -1 && !(c->flags & CHAN_EOF_SENT) &&
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
സ്ഥിതം പൂർണ്ണസംഖ്യ
x11_open_helper(ഘടന ssh *ssh, ഘടന sshbuf *b)
{
	ഘടന ssh_channels *sc = ssh->chanctxt;
	u_char *ucp;
	u_int proto_len, data_len;

	എങ്കിൽ (sc->x11_saved_proto == ശൂന്യ) {
		error("X11 forwarding opened before X11 forwarding requested");
		തിരികെ -1;
	}

	/* Is this being called after the refusal deadline? */
	എങ്കിൽ (sc->x11_refuse_time != 0.0 &&
	    monotime_double() >= sc->x11_refuse_time) {
		verbose("Rejected X11 connection after ForwardX11Timeout "
		    "expired");
		തിരികെ -1;
	}

	/* Check if the fixed size part of the packet is in buffer. */
	എങ്കിൽ (sshbuf_len(b) < 12)
		തിരികെ 0;

	/* Parse the lengths of variable-length fields. */
	ucp = sshbuf_mutable_ptr(b);
	എങ്കിൽ (ucp[0] == 0x42) {	/* Byte order MSB first. */
		proto_len = 256 * ucp[6] + ucp[7];
		data_len = 256 * ucp[8] + ucp[9];
	} അല്ലെങ്കിൽ എങ്കിൽ (ucp[0] == 0x6c) {	/* Byte order LSB first. */
		proto_len = ucp[6] + 256 * ucp[7];
		data_len = ucp[8] + 256 * ucp[9];
	} അല്ലെങ്കിൽ {
		debug2("Initial X11 packet contains bad byte order byte: 0x%x",
		    ucp[0]);
		തിരികെ -1;
	}

	/* Check if the whole packet is in buffer. */
	എങ്കിൽ (sshbuf_len(b) <
	    12 + ((proto_len + 3) & ~3) + ((data_len + 3) & ~3))
		തിരികെ 0;

	/* Check if authentication protocol matches. */
	എങ്കിൽ (proto_len != strlen(sc->x11_saved_proto) ||
	    memcmp(ucp + 12, sc->x11_saved_proto, proto_len) != 0) {
		debug2("X11 connection uses different authentication protocol.");
		തിരികെ -1;
	}
	/* Check if authentication data matches our fake data. */
	എങ്കിൽ (data_len != sc->x11_fake_data_len ||
	    timingsafe_bcmp(ucp + 12 + ((proto_len + 3) & ~3),
		sc->x11_fake_data, sc->x11_fake_data_len) != 0) {
		debug2("X11 auth data does not match fake data.");
		തിരികെ -1;
	}
	/* Check fake data length */
	എങ്കിൽ (sc->x11_fake_data_len != sc->x11_saved_data_len) {
		error("X11 fake_data_len %d != saved_data_len %d",
		    sc->x11_fake_data_len, sc->x11_saved_data_len);
		തിരികെ -1;
	}
	/*
	 * Received authentication protocol and data match
	 * our fake data. Substitute the fake data with real
	 * data.
	 */
	memcpy(ucp + 12 + ((proto_len + 3) & ~3),
	    sc->x11_saved_data, sc->x11_saved_data_len);
	തിരികെ 1;
}

ശൂന്യം
channel_force_close(ഘടന ssh *ssh, Channel *c, പൂർണ്ണസംഖ്യ abandon)
{
	debug3_f("channel %d: forcibly closing", c->self);
	എങ്കിൽ (c->istate == CHAN_നിവേശം_OPEN)
		chan_read_failed(ssh, c);
	എങ്കിൽ (c->istate == CHAN_നിവേശം_WAIT_DRAIN) {
		sshbuf_reset(c->നിവേശം);
		chan_ibuf_empty(ssh, c);
	}
	എങ്കിൽ (c->ostate == CHAN_OUTPUT_OPEN ||
	    c->ostate == CHAN_OUTPUT_WAIT_DRAIN) {
		sshbuf_reset(c->output);
		chan_write_failed(ssh, c);
	}
	എങ്കിൽ (c->detach_user)
		c->detach_user(ssh, c->self, 1, ശൂന്യ);
	എങ്കിൽ (c->efd != -1)
		channel_close_fd(ssh, c, &c->efd);
	എങ്കിൽ (abandon)
		c->type = SSH_CHANNEL_ABANDONED;
	/* exempt from inactivity timeouts */
	c->inactive_deadline = 0;
	c->lastused = 0;
}

സ്ഥിതം ശൂന്യം
channel_pre_x11_open(ഘടന ssh *ssh, Channel *c)
{
	പൂർണ്ണസംഖ്യ ret = x11_open_helper(ssh, c->output);

	/* c->force_drain = 1; */

	എങ്കിൽ (ret == 1) {
		c->type = SSH_CHANNEL_OPEN;
		channel_set_used_time(ssh, c);
		channel_pre_open(ssh, c);
	} അല്ലെങ്കിൽ എങ്കിൽ (ret == -1) {
		logit("X11 connection rejected because of wrong "
		    "authentication.");
		debug2("X11 rejected %d i%d/o%d",
		    c->self, c->istate, c->ostate);
		channel_force_close(ssh, c, 0);
	}
}

സ്ഥിതം ശൂന്യം
channel_pre_mux_client(ഘടന ssh *ssh, Channel *c)
{
	c->io_want = 0;
	എങ്കിൽ (c->istate == CHAN_നിവേശം_OPEN && !c->mux_pause &&
	    sshbuf_check_reserve(c->നിവേശം, CHAN_RBUF) == 0)
		c->io_want |= SSH_CHAN_IO_RFD;
	എങ്കിൽ (c->istate == CHAN_നിവേശം_WAIT_DRAIN) {
		/* clear buffer immediately (discard any partial packet) */
		sshbuf_reset(c->നിവേശം);
		chan_ibuf_empty(ssh, c);
		/* Start output drain. XXX just kill chan? */
		chan_rcvd_oclose(ssh, c);
	}
	എങ്കിൽ (c->ostate == CHAN_OUTPUT_OPEN ||
	    c->ostate == CHAN_OUTPUT_WAIT_DRAIN) {
		എങ്കിൽ (sshbuf_len(c->output) > 0)
			c->io_want |= SSH_CHAN_IO_WFD;
		അല്ലെങ്കിൽ എങ്കിൽ (c->ostate == CHAN_OUTPUT_WAIT_DRAIN)
			chan_obuf_empty(ssh, c);
	}
}

സ്ഥിതം വരിയിൽ പൂർണ്ണസംഖ്യ
socks_decode_error(Channel *c, പൂർണ്ണസംഖ്യ status, സ്ഥിരം അക്ഷരം *func, സ്ഥിരം അക്ഷരം *സന്ദേശം)
{
	എങ്കിൽ (status == SSH_ERR_MESSAGE_INCOMPLETE)
		തിരികെ 0;
	അല്ലെങ്കിൽ {
		debug_r(status, "%s: channel %d: decode %s",
		    func, c->self, സന്ദേശം);
		തിരികെ -1;
	}
}

/* try to decode a socks4 header */
സ്ഥിതം പൂർണ്ണസംഖ്യ
channel_decode_socks4(Channel *c, ഘടന sshbuf *നിവേശം, ഘടന sshbuf *output)
{
	uint8_t socks_ver, socks_cmd, dest_addr[4];
	uint16_t dest_port;
	അക്ഷരം *user = ശൂന്യ, *host = ശൂന്യ;
	പൂർണ്ണസംഖ്യ success = -1, socks4a = 0, r;
	ഘടന sshbuf *b = ശൂന്യ;

	എങ്കിൽ (sshbuf_len(നിവേശം) < 9)
		തിരികെ 0;

	/* We may not have a complete message, so work on a dup of the buffer */
	എങ്കിൽ ((b = sshbuf_fromb(നിവേശം)) == ശൂന്യ)
		fatal_f("sshbuf_fromb failed");

	debug2("channel %d: decode socks4", c->self);
	എങ്കിൽ ((r = sshbuf_get_u8(b, &socks_ver)) != 0 ||
	    (r = sshbuf_get_u8(b, &socks_cmd)) != 0 ||
	    (r = sshbuf_get_u16(b, &dest_port)) != 0 ||
	    (r = sshbuf_get(b, &dest_addr, വലുപ്പം(dest_addr))) != 0 ||
	    (r = sshbuf_get_nulterminated_string(b, 1024, &user, ശൂന്യ)) != 0) {
		success = socks_decode_error(c, r, __func__, "header");
		പോകുക out;
	}

	/* Is this a SOCKS4A request? (indicated by an address of 0.0.0.x) */
	എങ്കിൽ (dest_addr[0] == 0 && dest_addr[1] == 0 &&
	    dest_addr[2] == 0 && dest_addr[3] != 0) {
		/* If so, then the hostname follows, also nul-terminated */
		എങ്കിൽ ((r = sshbuf_get_nulterminated_string(b, 1024,
		    &host, ശൂന്യ)) != 0) {
			success = socks_decode_error(c, r, __func__, "host");
			പോകുക out;
		}
		socks4a = 1;
	} അല്ലെങ്കിൽ {
		/* Plain SOCKS4 passes an IPv4 binary address; reconstruct */
		xasprintf(&host, "%d.%d.%d.%d",
		    dest_addr[0], dest_addr[1], dest_addr[2], dest_addr[3]);
	}

	/* We have a complete SOCKS4 message; consume it from input */
	എങ്കിൽ ((r = sshbuf_consume_upto_child(നിവേശം, b)) != 0)
		fatal_fr(r, "channel %d: consume", c->self);

	/* Handle the request */
	debug2("channel %d: %s: user=\"%s\" command=%d destination=[%s]:%d",
	    c->self, socks4a ? "SOCKS4A" : "SOCKS4", user, (പൂർണ്ണസംഖ്യ)socks_cmd,
	    host, dest_port);
	എങ്കിൽ (socks_cmd != 1) {
		debug("channel %d: cannot handle %s command 0x%02x",
		    c->self, socks4a ? "SOCKS4A" : "SOCKS4", socks_cmd);
		പോകുക out;
	}
	സ്വതന്ത്രം(c->path);
	c->path = host;
	host = ശൂന്യ; /* transferred */
	c->host_port = dest_port;

	/* Reply to the SOCKS4 client */
	എങ്കിൽ ((r = sshbuf_put_u8(output, 0)) != 0 ||	/* vn: 0 for reply */
	    (r = sshbuf_put_u8(output, 90)) != 0 ||	/* cd: req granted */
	    (r = sshbuf_put_u16(output, 0)) != 0 ||	/* port: ignored */
	    (r = sshbuf_put_u32(output, ntohl(INADDR_ANY))) != 0) /* ignored */
		fatal_fr(r, "channel %d: compose reply", c->self);

	/* success */
	success = 1;
 out:
	sshbuf_free(b);
	സ്വതന്ത്രം(user);
	സ്വതന്ത്രം(host);
	തിരികെ success;
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
സ്ഥിതം പൂർണ്ണസംഖ്യ
channel_socks5_check_auth(Channel *c, ഘടന sshbuf *b, ഘടന sshbuf *നിവേശം,
    ഘടന sshbuf *output)
{
	uint8_t socks_ver;
	uint8_t nmethods, method;
	പൂർണ്ണസംഖ്യ r;
	u_int i, found;

	/* format: ver | nmethods | methods */
	എങ്കിൽ ((r = sshbuf_get_u8(b, &socks_ver)) != 0)
		തിരികെ socks_decode_error(c, r, __func__, "version");
	എങ്കിൽ (socks_ver != 5) /* shouldn't happen; checked by caller^2 */
		fatal_fr(r, "channel %d: internal error: not socks5", c->self);
	എങ്കിൽ ((r = sshbuf_get_u8(b, &nmethods)) != 0)
		തിരികെ socks_decode_error(c, r, __func__, "methods");
	വേണ്ടി (found = i = 0; i < nmethods; i++) {
		എങ്കിൽ ((r = sshbuf_get_u8(b, &method)) != 0)
			തിരികെ socks_decode_error(c, r, __func__, "method");
		എങ്കിൽ (method == SSH_SOCKS5_NOAUTH)
			found = 1;
	}
	എങ്കിൽ (!found) {
		debug("channel %d: didn't request SSH_SOCKS5_NOAUTH", c->self);
		തിരികെ -1;
	}
	/* Consume completed request */
	എങ്കിൽ ((r = sshbuf_consume_upto_child(നിവേശം, b)) != 0)
		fatal_fr(r, "channel %d: consume", c->self);

	/* Compose reply: version, method */
	എങ്കിൽ ((r = sshbuf_put_u8(output, 0x05)) != 0 ||
	    (r = sshbuf_put_u8(output, SSH_SOCKS5_NOAUTH)) != 0)
		fatal_fr(r, "channel %d: append reply", c->self);
	/* success */
	debug2("channel %d: socks5 auth done", c->self);
	തിരികെ 1;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
channel_decode_socks5(Channel *c, ഘടന sshbuf *നിവേശം, ഘടന sshbuf *output)
{
	uint8_t socks_ver, socks_cmd, socks_reserved, socks_atyp, addrlen;
	uint16_t dest_port;
	അക്ഷരം dest_addr[255+1], ntop[INET6_ADDRSTRLEN];
	u_int af;
	പൂർണ്ണസംഖ്യ r, success = -1;;
	ഘടന sshbuf *b = ശൂന്യ;

	debug2("channel %d: decode socks5 %s", c->self,
	    (c->flags & SSH_SOCKS5_AUTHDONE) ? "request" : "auth");

	/* We may not have a complete message, so work on a dup of the buffer */
	എങ്കിൽ ((b = sshbuf_fromb(നിവേശം)) == ശൂന്യ)
		fatal_f("sshbuf_fromb failed");

	എങ്കിൽ (!(c->flags & SSH_SOCKS5_AUTHDONE)) {
		എങ്കിൽ ((r = channel_socks5_check_auth(c, b, നിവേശം, output)) != 1) {
			success = r;
			പോകുക out;
		}
		c->flags |= SSH_SOCKS5_AUTHDONE;
		/* Continue to parse request in case client speculated ahead */
	}

	/* Request messages (auth or connect) always start with the version */
	എങ്കിൽ ((r = sshbuf_get_u8(b, &socks_ver)) != 0) {
		success = socks_decode_error(c, r, __func__, "version");
		പോകുക out;
	}
	എങ്കിൽ (socks_ver != 5) /* shouldn't happen */
		fatal_fr(r, "channel %d: internal error: not socks5", c->self);

	/* Parse SOCKS5 request header */
	debug2("channel %d: socks5 post auth", c->self);
	എങ്കിൽ ((r = sshbuf_get_u8(b, &socks_cmd)) != 0 ||
	    (r = sshbuf_get_u8(b, &socks_reserved)) != 0 ||
	    (r = sshbuf_get_u8(b, &socks_atyp)) != 0) {
		success = socks_decode_error(c, r, __func__, "request header");
		പോകുക out;
	}

	എങ്കിൽ (socks_ver != 0x05 ||
	    socks_cmd != SSH_SOCKS5_CONNECT ||
	    socks_reserved != 0x00) {
		debug2("channel %d: only socks5 connect supported", c->self);
		പോകുക out;
	}

	തിരഞ്ഞെടുപ്പ് (socks_atyp) {
	അവസ്ഥ SSH_SOCKS5_IPV4:
		addrlen = 4;
		af = AF_INET;
		നിർത്തുക;
	അവസ്ഥ SSH_SOCKS5_DOMAIN:
		എങ്കിൽ ((r = sshbuf_get_u8(b, &addrlen)) != 0) {
			success = socks_decode_error(c, r, __func__, "addrlen");
			പോകുക out;
		}
		af = -1;
		നിർത്തുക;
	അവസ്ഥ SSH_SOCKS5_IPV6:
		addrlen = 16;
		af = AF_INET6;
		നിർത്തുക;
	സ്ഥിരസ്ഥിതി:
		debug2("channel %d: bad socks5 atyp %d", c->self, socks_atyp);
		പോകുക out;
	}
	എങ്കിൽ ((r = sshbuf_get(b, &dest_addr, addrlen)) != 0 ||
	    (r = sshbuf_get_u16(b, &dest_port)) != 0) {
		success = socks_decode_error(c, r, __func__, "addr/port");
		പോകുക out;
	}
	dest_addr[addrlen] = '\0';

	/* We have a complete SOCKS5 request; consume it from input */
	എങ്കിൽ ((r = sshbuf_consume_upto_child(നിവേശം, b)) != 0)
		fatal_fr(r, "channel %d: consume", c->self);

	സ്വതന്ത്രം(c->path);
	c->path = ശൂന്യ;
	എങ്കിൽ (socks_atyp == SSH_SOCKS5_DOMAIN)
		c->path = xstrdup(dest_addr);
	അല്ലെങ്കിൽ {
		എങ്കിൽ (inet_ntop(af, dest_addr, ntop, വലുപ്പം(ntop)) == ശൂന്യ)
			തിരികെ -1;
		c->path = xstrdup(ntop);
	}
	c->host_port = dest_port;

	debug2("channel %d: dynamic request: socks5 host %s port %u command %u",
	    c->self, c->path, c->host_port, socks_cmd);

	/* Reply */
	എങ്കിൽ ((r = sshbuf_put_u8(output, 0x05)) != 0 ||	/* version */
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
	തിരികെ success;
}

Channel *
channel_connect_stdio_fwd(ഘടന ssh *ssh,
    സ്ഥിരം അക്ഷരം *host_to_connect, പൂർണ്ണസംഖ്യ port_to_connect,
    പൂർണ്ണസംഖ്യ in, പൂർണ്ണസംഖ്യ out, പൂർണ്ണസംഖ്യ nonblock)
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

	തിരികെ c;
}

/* dynamic port forwarding */
സ്ഥിതം ശൂന്യം
channel_pre_dynamic(ഘടന ssh *ssh, Channel *c)
{
	u_int have;
	u_char ver;
	പൂർണ്ണസംഖ്യ r, ret;

	c->io_want = 0;
	have = sshbuf_len(c->നിവേശം);
	debug2("channel %d: pre_dynamic: have %d", c->self, have);
	/* sshbuf_dump(c->input, stderr); */
	/* check if the fixed size part of the packet is in buffer. */
	എങ്കിൽ (have < 3) {
		/* need more */
		c->io_want |= SSH_CHAN_IO_RFD;
		തിരികെ;
	}
	/* try to guess the protocol */
	എങ്കിൽ ((r = sshbuf_peek_u8(c->നിവേശം, 0, &ver)) != 0)
		fatal_fr(r, "sshbuf_peek_u8");
	തിരഞ്ഞെടുപ്പ് (ver) {
	അവസ്ഥ 0x04:
		ret = channel_decode_socks4(c, c->നിവേശം, c->output);
		നിർത്തുക;
	അവസ്ഥ 0x05:
		ret = channel_decode_socks5(c, c->നിവേശം, c->output);
		നിർത്തുക;
	സ്ഥിരസ്ഥിതി:
		debug2_f("channel %d: unknown SOCKS version %u", c->self, ver);
		ret = -1;
		നിർത്തുക;
	}
	എങ്കിൽ (ret < 0) {
		chan_mark_dead(ssh, c);
	} അല്ലെങ്കിൽ എങ്കിൽ (ret == 0) {
		debug2("channel %d: pre_dynamic: need more", c->self);
		/* need more */
		c->io_want |= SSH_CHAN_IO_RFD;
		എങ്കിൽ (sshbuf_len(c->output))
			c->io_want |= SSH_CHAN_IO_WFD;
	} അല്ലെങ്കിൽ {
		/* switch to the next state */
		c->type = SSH_CHANNEL_OPENING;
		port_open_helper(ssh, c, "direct-tcpip");
	}
}

/* simulate read-error */
സ്ഥിതം ശൂന്യം
rdynamic_close(ഘടന ssh *ssh, Channel *c)
{
	c->type = SSH_CHANNEL_OPEN;
	channel_force_close(ssh, c, 0);
}

/* reverse dynamic port forwarding */
സ്ഥിതം ശൂന്യം
channel_before_prepare_io_rdynamic(ഘടന ssh *ssh, Channel *c)
{
	സ്ഥിരം u_char *p;
	u_int have, len;
	പൂർണ്ണസംഖ്യ r, ret;

	have = sshbuf_len(c->output);
	debug2("channel %d: pre_rdynamic: have %d", c->self, have);
	/* sshbuf_dump(c->output, stderr); */
	/* EOF received */
	എങ്കിൽ (c->flags & CHAN_EOF_RCVD) {
		എങ്കിൽ ((r = sshbuf_consume(c->output, have)) != 0)
			fatal_fr(r, "channel %d: consume", c->self);
		rdynamic_close(ssh, c);
		തിരികെ;
	}
	/* check if the fixed size part of the packet is in buffer. */
	എങ്കിൽ (have < 3)
		തിരികെ;
	/* try to guess the protocol */
	p = sshbuf_ptr(c->output);
	തിരഞ്ഞെടുപ്പ് (p[0]) {
	അവസ്ഥ 0x04:
		/* switch input/output for reverse forwarding */
		ret = channel_decode_socks4(c, c->output, c->നിവേശം);
		നിർത്തുക;
	അവസ്ഥ 0x05:
		ret = channel_decode_socks5(c, c->output, c->നിവേശം);
		നിർത്തുക;
	സ്ഥിരസ്ഥിതി:
		ret = -1;
		നിർത്തുക;
	}
	എങ്കിൽ (ret < 0) {
		rdynamic_close(ssh, c);
	} അല്ലെങ്കിൽ എങ്കിൽ (ret == 0) {
		debug2("channel %d: pre_rdynamic: need more", c->self);
		/* send socks request to peer */
		len = sshbuf_len(c->നിവേശം);
		എങ്കിൽ (len > 0 && len < c->remote_window) {
			എങ്കിൽ ((r = sshpkt_start(ssh, SSH2_സന്ദേശം_CHANNEL_DATA)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
			    (r = sshpkt_put_stringb(ssh, c->നിവേശം)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0) {
				fatal_fr(r, "channel %i: rdynamic", c->self);
			}
			എങ്കിൽ ((r = sshbuf_consume(c->നിവേശം, len)) != 0)
				fatal_fr(r, "channel %d: consume", c->self);
			c->remote_window -= len;
		}
	} അല്ലെങ്കിൽ എങ്കിൽ (rdynamic_connect_finish(ssh, c) < 0) {
		/* the connect failed */
		rdynamic_close(ssh, c);
	}
}

/* This is our fake X11 server socket. */
സ്ഥിതം ശൂന്യം
channel_post_x11_listener(ഘടന ssh *ssh, Channel *c)
{
	Channel *nc;
	ഘടന sockaddr_storage addr;
	പൂർണ്ണസംഖ്യ r, newsock, oerrno, remote_port;
	socklen_t addrlen;
	അക്ഷരം buf[16384], *remote_ipaddr;

	എങ്കിൽ ((c->io_ready & SSH_CHAN_IO_SOCK_R) == 0)
		തിരികെ;

	debug("X11 connection requested.");
	addrlen = വലുപ്പം(addr);
	newsock = accept(c->sock, (ഘടന sockaddr *)&addr, &addrlen);
	എങ്കിൽ (c->single_connection) {
		oerrno = errno;
		debug2("single_connection: closing X11 listener.");
		channel_close_fd(ssh, c, &c->sock);
		chan_mark_dead(ssh, c);
		errno = oerrno;
	}
	എങ്കിൽ (newsock == -1) {
		എങ്കിൽ (errno != EINTR && errno != EWOULDBLOCK &&
		    errno != ECONNABORTED)
			error("accept: %.100s", strerror(errno));
		എങ്കിൽ (errno == EMFILE || errno == ENFILE)
			c->notbefore = monotime_double() + 1.0;
		തിരികെ;
	}
	set_nodelay(newsock);
	എങ്കിൽ (ssh->chanctxt->want_tcp_keepalive)
		set_keepalive(newsock); /* logs errors */
	remote_ipaddr = get_peer_ipaddr(newsock);
	remote_port = get_peer_port(newsock);
	snprintf(buf, വലുപ്പം buf, "X11 connection from %.200s port %d",
	    remote_ipaddr, remote_port);

	nc = channel_new(ssh, "x11-connection",
	    SSH_CHANNEL_OPENING, newsock, newsock, -1,
	    c->local_window_max, c->local_maxpacket, 0, buf, 1);
	open_preamble(ssh, __func__, nc, "x11");
	എങ്കിൽ ((r = sshpkt_put_cstring(ssh, remote_ipaddr)) != 0 ||
	    (r = sshpkt_put_u32(ssh, remote_port)) != 0) {
		fatal_fr(r, "channel %i: reply", c->self);
	}
	എങ്കിൽ ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i: send", c->self);
	സ്വതന്ത്രം(remote_ipaddr);
}

സ്ഥിതം ശൂന്യം
port_open_helper(ഘടന ssh *ssh, Channel *c, അക്ഷരം *rtype)
{
	അക്ഷരം *local_ipaddr = get_local_ipaddr(c->sock);
	പൂർണ്ണസംഖ്യ local_port = c->sock == -1 ? 65536 : get_local_port(c->sock);
	അക്ഷരം *remote_ipaddr = get_peer_ipaddr(c->sock);
	പൂർണ്ണസംഖ്യ remote_port = get_peer_port(c->sock);
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (remote_port == -1) {
		/* Fake addr/port to appease peers that validate it (Tectia) */
		സ്വതന്ത്രം(remote_ipaddr);
		remote_ipaddr = xstrdup("127.0.0.1");
		remote_port = 65535;
	}

	സ്വതന്ത്രം(c->remote_name);
	xasprintf(&c->remote_name,
	    "%s: listening port %d for %.100s port %d, "
	    "connect from %.200s port %d to %.100s port %d",
	    rtype, c->listening_port, c->path, c->host_port,
	    remote_ipaddr, remote_port, local_ipaddr, local_port);

	open_preamble(ssh, __func__, c, rtype);
	എങ്കിൽ (strcmp(rtype, "direct-tcpip") == 0) {
		/* target host, port */
		എങ്കിൽ ((r = sshpkt_put_cstring(ssh, c->path)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->host_port)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	} അല്ലെങ്കിൽ എങ്കിൽ (strcmp(rtype, "direct-streamlocal@openssh.com") == 0) {
		/* target path */
		എങ്കിൽ ((r = sshpkt_put_cstring(ssh, c->path)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	} അല്ലെങ്കിൽ എങ്കിൽ (strcmp(rtype, "forwarded-streamlocal@openssh.com") == 0) {
		/* listen path */
		എങ്കിൽ ((r = sshpkt_put_cstring(ssh, c->path)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	} അല്ലെങ്കിൽ {
		/* listen address, port */
		എങ്കിൽ ((r = sshpkt_put_cstring(ssh, c->path)) != 0 ||
		    (r = sshpkt_put_u32(ssh, local_port)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	}
	എങ്കിൽ (strcmp(rtype, "forwarded-streamlocal@openssh.com") == 0) {
		/* reserved for future owner/mode info */
		എങ്കിൽ ((r = sshpkt_put_cstring(ssh, "")) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	} അല്ലെങ്കിൽ {
		/* originator host and port */
		എങ്കിൽ ((r = sshpkt_put_cstring(ssh, remote_ipaddr)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)remote_port)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	}
	എങ്കിൽ ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i: send", c->self);
	സ്വതന്ത്രം(remote_ipaddr);
	സ്വതന്ത്രം(local_ipaddr);
}

ശൂന്യം
channel_set_x11_refuse_time(ഘടന ssh *ssh, ഇരട്ട refuse_time)
{
	ssh->chanctxt->x11_refuse_time = refuse_time;
}

/*
 * This socket is listening for connections to a forwarded TCP/IP port.
 */
സ്ഥിതം ശൂന്യം
channel_post_port_listener(ഘടന ssh *ssh, Channel *c)
{
	Channel *nc;
	ഘടന sockaddr_storage addr;
	പൂർണ്ണസംഖ്യ newsock, nextstate;
	socklen_t addrlen;
	അക്ഷരം *rtype;

	എങ്കിൽ ((c->io_ready & SSH_CHAN_IO_SOCK_R) == 0)
		തിരികെ;

	debug("Connection to port %d forwarding to %.100s port %d requested.",
	    c->listening_port, c->path, c->host_port);

	എങ്കിൽ (c->type == SSH_CHANNEL_RPORT_LISTENER) {
		nextstate = SSH_CHANNEL_OPENING;
		rtype = "forwarded-tcpip";
	} അല്ലെങ്കിൽ എങ്കിൽ (c->type == SSH_CHANNEL_RUNIX_LISTENER) {
		nextstate = SSH_CHANNEL_OPENING;
		rtype = "forwarded-streamlocal@openssh.com";
	} അല്ലെങ്കിൽ എങ്കിൽ (c->host_port == PORT_STREAMLOCAL) {
		nextstate = SSH_CHANNEL_OPENING;
		rtype = "direct-streamlocal@openssh.com";
	} അല്ലെങ്കിൽ എങ്കിൽ (c->host_port == 0) {
		nextstate = SSH_CHANNEL_DYNAMIC;
		rtype = "dynamic-tcpip";
	} അല്ലെങ്കിൽ {
		nextstate = SSH_CHANNEL_OPENING;
		rtype = "direct-tcpip";
	}

	addrlen = വലുപ്പം(addr);
	newsock = accept(c->sock, (ഘടന sockaddr *)&addr, &addrlen);
	എങ്കിൽ (newsock == -1) {
		എങ്കിൽ (errno != EINTR && errno != EWOULDBLOCK &&
		    errno != ECONNABORTED)
			error("accept: %.100s", strerror(errno));
		എങ്കിൽ (errno == EMFILE || errno == ENFILE)
			c->notbefore = monotime_double() + 1.0;
		തിരികെ;
	}
	എങ്കിൽ (addr.ss_family == AF_INET || addr.ss_family == AF_INET6) {
		set_nodelay(newsock);
		എങ്കിൽ (ssh->chanctxt->want_tcp_keepalive)
			set_keepalive(newsock); /* logs errors */
	}
	nc = channel_new(ssh, rtype, nextstate, newsock, newsock, -1,
	    c->local_window_max, c->local_maxpacket, 0, rtype, 1);
	nc->listening_port = c->listening_port;
	nc->host_port = c->host_port;
	എങ്കിൽ (c->path != ശൂന്യ)
		nc->path = xstrdup(c->path);

	എങ്കിൽ (nextstate != SSH_CHANNEL_DYNAMIC)
		port_open_helper(ssh, nc, rtype);
}

/*
 * This is the authentication agent socket listening for connections from
 * clients.
 */
സ്ഥിതം ശൂന്യം
channel_post_auth_listener(ഘടന ssh *ssh, Channel *c)
{
	Channel *nc;
	പൂർണ്ണസംഖ്യ r, newsock;
	ഘടന sockaddr_storage addr;
	socklen_t addrlen;

	എങ്കിൽ ((c->io_ready & SSH_CHAN_IO_SOCK_R) == 0)
		തിരികെ;

	addrlen = വലുപ്പം(addr);
	newsock = accept(c->sock, (ഘടന sockaddr *)&addr, &addrlen);
	എങ്കിൽ (newsock == -1) {
		error("accept from auth socket: %.100s", strerror(errno));
		എങ്കിൽ (errno == EMFILE || errno == ENFILE)
			c->notbefore = monotime_double() + 1.0;
		തിരികെ;
	}
	nc = channel_new(ssh, "agent-connection",
	    SSH_CHANNEL_OPENING, newsock, newsock, -1,
	    c->local_window_max, c->local_maxpacket,
	    0, "accepted auth socket", 1);
	open_preamble(ssh, __func__, nc,
	    c->agent_new ? "agent-connect" : "auth-agent@openssh.com");
	എങ്കിൽ ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i", c->self);
}

സ്ഥിതം ശൂന്യം
channel_post_connecting(ഘടന ssh *ssh, Channel *c)
{
	പൂർണ്ണസംഖ്യ err = 0, sock, isopen, r;
	socklen_t sz = വലുപ്പം(err);

	എങ്കിൽ ((c->io_ready & SSH_CHAN_IO_SOCK_W) == 0)
		തിരികെ;
	എങ്കിൽ (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);
	എങ്കിൽ (c->connect_ctx == ശൂന്യ)
		fatal_f("channel %d: context missing", c->self);

	/* for rdynamic the OPEN_CONFIRMATION has been sent already */
	isopen = (c->type == SSH_CHANNEL_RDYNAMIC_FINISH);

	എങ്കിൽ (getsockopt(c->sock, SOL_SOCKET, SO_ERROR, &err, &sz) == -1) {
		err = errno;
		error("getsockopt SO_ERROR failed");
	}

	എങ്കിൽ (err == 0) {
		/* Non-blocking connection completed */
		debug("channel %d: connected to %s port %d",
		    c->self, c->connect_ctx->host, c->connect_ctx->port);
		channel_free_connect_ctx(c);
		c->type = SSH_CHANNEL_OPEN;
		channel_set_used_time(ssh, c);
		എങ്കിൽ (isopen) {
			/* no message necessary */
		} അല്ലെങ്കിൽ {
			എങ്കിൽ ((r = sshpkt_start(ssh,
			    SSH2_സന്ദേശം_CHANNEL_OPEN_CONFIRMATION)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_window)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "channel %i open confirm", c->self);
		}
		തിരികെ;
	}
	എങ്കിൽ (err == EINTR || err == EAGAIN || err == EINPROGRESS)
		തിരികെ;

	/* Non-blocking connection failed */
	debug("channel %d: connection failed: %s", c->self, strerror(err));

	/* Try next address, if any */
	എങ്കിൽ ((sock = connect_next(ssh, c->connect_ctx)) == -1) {
		/* Exhausted all addresses for this destination */
		error("connect_to %.100s port %d: failed.",
		    c->connect_ctx->host, c->connect_ctx->port);
		channel_free_connect_ctx(c);
		എങ്കിൽ (isopen) {
			rdynamic_close(ssh, c);
		} അല്ലെങ്കിൽ {
			എങ്കിൽ ((r = sshpkt_start(ssh,
			    SSH2_സന്ദേശം_CHANNEL_OPEN_FAILURE)) != 0 ||
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

സ്ഥിതം പൂർണ്ണസംഖ്യ
channel_handle_rfd(ഘടന ssh *ssh, Channel *c)
{
	അക്ഷരം buf[CHAN_RBUF];
	ssize_t len;
	പൂർണ്ണസംഖ്യ r, force;
	size_t nr = 0, have, avail, maxlen = CHANNEL_MAX_READ;
	പൂർണ്ണസംഖ്യ pty_zeroread = 0;

#ifdef PTY_ZEROREAD
	/* Bug on AIX: read(1) can return 0 for a non-closed fd */
	pty_zeroread = c->isatty;
#endif

	force = c->isatty && c->detach_close && c->istate != CHAN_നിവേശം_CLOSED;

	എങ്കിൽ (!force && (c->io_ready & SSH_CHAN_IO_RFD) == 0)
		തിരികെ 1;
	എങ്കിൽ ((avail = sshbuf_avail(c->നിവേശം)) == 0)
		തിരികെ 1; /* Shouldn't happen */

	/*
	 * For "simple" channels (i.e. not datagram or filtered), we can
	 * read directly to the channel buffer.
	 */
	എങ്കിൽ (!pty_zeroread && c->നിവേശം_filter == ശൂന്യ && !c->datagram) {
		/* Only OPEN channels have valid rwin */
		എങ്കിൽ (c->type == SSH_CHANNEL_OPEN) {
			എങ്കിൽ ((have = sshbuf_len(c->നിവേശം)) >= c->remote_window)
				തിരികെ 1; /* shouldn't happen */
			എങ്കിൽ (maxlen > c->remote_window - have)
				maxlen = c->remote_window - have;
		}
		എങ്കിൽ (maxlen > avail)
			maxlen = avail;
		എങ്കിൽ ((r = sshbuf_read(c->rfd, c->നിവേശം, maxlen, &nr)) != 0) {
			എങ്കിൽ (errno == EINTR || (!force &&
			    (errno == EAGAIN || errno == EWOULDBLOCK)))
				തിരികെ 1;
			debug2("channel %d: read failed rfd %d maxlen %zu: %s",
			    c->self, c->rfd, maxlen, ssh_err(r));
			പോകുക rfail;
		}
		എങ്കിൽ (nr != 0)
			channel_set_used_time(ssh, c);
		തിരികെ 1;
	}

	errno = 0;
	len = പഠ(c->rfd, buf, വലുപ്പം(buf));
	/* fixup AIX zero-length read with errno set to look more like errors */
	എങ്കിൽ (pty_zeroread && len == 0 && errno != 0)
		len = -1;
	എങ്കിൽ (len == -1 && (errno == EINTR ||
	    ((errno == EAGAIN || errno == EWOULDBLOCK) && !force)))
		തിരികെ 1;
	എങ്കിൽ (len < 0 || (!pty_zeroread && len == 0)) {
		debug2("channel %d: read<=0 rfd %d len %zd: %s",
		    c->self, c->rfd, len,
		    len == 0 ? "closed" : strerror(errno));
 rfail:
		എങ്കിൽ (c->type != SSH_CHANNEL_OPEN) {
			debug2("channel %d: not open", c->self);
			chan_mark_dead(ssh, c);
			തിരികെ -1;
		} അല്ലെങ്കിൽ {
			chan_read_failed(ssh, c);
		}
		തിരികെ -1;
	}
	channel_set_used_time(ssh, c);
	എങ്കിൽ (c->നിവേശം_filter != ശൂന്യ) {
		എങ്കിൽ (c->നിവേശം_filter(ssh, c, buf, len) == -1) {
			debug2("channel %d: filter stops", c->self);
			chan_read_failed(ssh, c);
		}
	} അല്ലെങ്കിൽ എങ്കിൽ (c->datagram) {
		എങ്കിൽ ((r = sshbuf_put_string(c->നിവേശം, buf, len)) != 0)
			fatal_fr(r, "channel %i: put datagram", c->self);
	} അല്ലെങ്കിൽ എങ്കിൽ ((r = sshbuf_put(c->നിവേശം, buf, len)) != 0)
		fatal_fr(r, "channel %i: put data", c->self);

	തിരികെ 1;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
channel_handle_wfd(ഘടന ssh *ssh, Channel *c)
{
	ഘടന termios tio;
	u_char *data = ശൂന്യ, *buf; /* XXX const; need filter API change */
	size_t dlen, olen = 0;
	പൂർണ്ണസംഖ്യ r, len;

	എങ്കിൽ ((c->io_ready & SSH_CHAN_IO_WFD) == 0)
		തിരികെ 1;
	എങ്കിൽ (sshbuf_len(c->output) == 0)
		തിരികെ 1;

	/* Send buffered output data to the socket. */
	olen = sshbuf_len(c->output);
	എങ്കിൽ (c->output_filter != ശൂന്യ) {
		എങ്കിൽ ((buf = c->output_filter(ssh, c, &data, &dlen)) == ശൂന്യ) {
			debug2("channel %d: filter stops", c->self);
			എങ്കിൽ (c->type != SSH_CHANNEL_OPEN)
				chan_mark_dead(ssh, c);
			അല്ലെങ്കിൽ
				chan_write_failed(ssh, c);
			തിരികെ -1;
		}
	} അല്ലെങ്കിൽ എങ്കിൽ (c->datagram) {
		എങ്കിൽ ((r = sshbuf_get_string(c->output, &data, &dlen)) != 0)
			fatal_fr(r, "channel %i: get datagram", c->self);
		buf = data;
	} അല്ലെങ്കിൽ {
		buf = data = sshbuf_mutable_ptr(c->output);
		dlen = sshbuf_len(c->output);
	}

	എങ്കിൽ (c->datagram) {
		/* ignore truncated writes, datagrams might get lost */
		len = ലിഖ(c->wfd, buf, dlen);
		സ്വതന്ത്രം(data);
		എങ്കിൽ (len == -1 && (errno == EINTR || errno == EAGAIN ||
		    errno == EWOULDBLOCK))
			തിരികെ 1;
		എങ്കിൽ (len <= 0)
			പോകുക write_fail;
		പോകുക out;
	}

#ifdef _AIX
	/* XXX: Later AIX versions can't push as much data to tty */
	എങ്കിൽ (c->wfd_isatty)
		dlen = MINIMUM(dlen, 8*1024);
#endif

	len = ലിഖ(c->wfd, buf, dlen);
	എങ്കിൽ (len == -1 &&
	    (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
		തിരികെ 1;
	എങ്കിൽ (len <= 0) {
 write_fail:
		എങ്കിൽ (c->type != SSH_CHANNEL_OPEN) {
			debug2("channel %d: not open", c->self);
			chan_mark_dead(ssh, c);
			തിരികെ -1;
		} അല്ലെങ്കിൽ {
			chan_write_failed(ssh, c);
		}
		തിരികെ -1;
	}
	channel_set_used_time(ssh, c);
#ifndef BROKEN_TCGETATTR_ICANON
	എങ്കിൽ (c->isatty && dlen >= 1 && buf[0] != '\r') {
		എങ്കിൽ (tcgetattr(c->wfd, &tio) == 0 &&
		    !(tio.c_lflag & ECHO) && (tio.c_lflag & ICANON)) {
			/*
			 * Simulate echo to reduce the impact of
			 * traffic analysis. We need to match the
			 * size of a SSH2_MSG_CHANNEL_DATA message
			 * (4 byte channel id + buf)
			 */
			എങ്കിൽ ((r = sshpkt_സന്ദേശം_ignore(ssh, 4+len)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "channel %i: ignore", c->self);
		}
	}
#endif /* BROKEN_TCGETATTR_ICANON */
	എങ്കിൽ ((r = sshbuf_consume(c->output, len)) != 0)
		fatal_fr(r, "channel %i: consume", c->self);
 out:
	c->local_consumed += olen - sshbuf_len(c->output);

	തിരികെ 1;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
channel_handle_efd_write(ഘടന ssh *ssh, Channel *c)
{
	പൂർണ്ണസംഖ്യ r;
	ssize_t len;

	എങ്കിൽ ((c->io_ready & SSH_CHAN_IO_EFD_W) == 0)
		തിരികെ 1;
	എങ്കിൽ (sshbuf_len(c->extended) == 0)
		തിരികെ 1;

	len = ലിഖ(c->efd, sshbuf_ptr(c->extended),
	    sshbuf_len(c->extended));
	debug2("channel %d: written %zd to efd %d", c->self, len, c->efd);
	എങ്കിൽ (len == -1 && (errno == EINTR || errno == EAGAIN ||
	    errno == EWOULDBLOCK))
		തിരികെ 1;
	എങ്കിൽ (len <= 0) {
		debug2("channel %d: closing write-efd %d", c->self, c->efd);
		channel_close_fd(ssh, c, &c->efd);
	} അല്ലെങ്കിൽ {
		എങ്കിൽ ((r = sshbuf_consume(c->extended, len)) != 0)
			fatal_fr(r, "channel %i: consume", c->self);
		c->local_consumed += len;
		channel_set_used_time(ssh, c);
	}
	തിരികെ 1;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
channel_handle_efd_read(ഘടന ssh *ssh, Channel *c)
{
	അക്ഷരം buf[CHAN_RBUF];
	ssize_t len;
	പൂർണ്ണസംഖ്യ r, force;

	force = c->isatty && c->detach_close && c->istate != CHAN_നിവേശം_CLOSED;

	എങ്കിൽ (!force && (c->io_ready & SSH_CHAN_IO_EFD_R) == 0)
		തിരികെ 1;

	len = പഠ(c->efd, buf, വലുപ്പം(buf));
	debug2("channel %d: read %zd from efd %d", c->self, len, c->efd);
	എങ്കിൽ (len == -1 && (errno == EINTR || ((errno == EAGAIN ||
	    errno == EWOULDBLOCK) && !force)))
		തിരികെ 1;
	എങ്കിൽ (len <= 0) {
		debug2("channel %d: closing read-efd %d", c->self, c->efd);
		channel_close_fd(ssh, c, &c->efd);
		തിരികെ 1;
	}
	channel_set_used_time(ssh, c);
	എങ്കിൽ (c->extended_usage == CHAN_EXTENDED_IGNORE)
		debug3("channel %d: discard efd", c->self);
	അല്ലെങ്കിൽ എങ്കിൽ ((r = sshbuf_put(c->extended, buf, len)) != 0)
		fatal_fr(r, "channel %i: append", c->self);
	തിരികെ 1;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
channel_handle_efd(ഘടന ssh *ssh, Channel *c)
{
	എങ്കിൽ (c->efd == -1)
		തിരികെ 1;

	/** XXX handle drain efd, too */

	എങ്കിൽ (c->extended_usage == CHAN_EXTENDED_WRITE)
		തിരികെ channel_handle_efd_write(ssh, c);
	അല്ലെങ്കിൽ എങ്കിൽ (c->extended_usage == CHAN_EXTENDED_READ ||
	    c->extended_usage == CHAN_EXTENDED_IGNORE)
		തിരികെ channel_handle_efd_read(ssh, c);

	തിരികെ 1;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
channel_check_window(ഘടന ssh *ssh, Channel *c)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (c->type == SSH_CHANNEL_OPEN &&
	    !(c->flags & (CHAN_CLOSE_SENT|CHAN_CLOSE_RCVD)) &&
	    ((c->local_window_max - c->local_window >
	    c->local_maxpacket*3) ||
	    c->local_window < c->local_window_max/2) &&
	    c->local_consumed > 0) {
		എങ്കിൽ (!c->have_remote_id)
			fatal_f("channel %d: no remote id", c->self);
		എങ്കിൽ ((r = sshpkt_start(ssh,
		    SSH2_സന്ദേശം_CHANNEL_WINDOW_ADJUST)) != 0 ||
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
	തിരികെ 1;
}

സ്ഥിതം ശൂന്യം
channel_post_open(ഘടന ssh *ssh, Channel *c)
{
	channel_handle_rfd(ssh, c);
	channel_handle_wfd(ssh, c);
	channel_handle_efd(ssh, c);
	channel_check_window(ssh, c);
}

സ്ഥിതം u_int
read_mux(ഘടന ssh *ssh, Channel *c, u_int need)
{
	അക്ഷരം buf[CHAN_RBUF];
	ssize_t len;
	u_int rlen;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (sshbuf_len(c->നിവേശം) < need) {
		rlen = need - sshbuf_len(c->നിവേശം);
		len = പഠ(c->rfd, buf, MINIMUM(rlen, CHAN_RBUF));
		എങ്കിൽ (len == -1 && (errno == EINTR || errno == EAGAIN))
			തിരികെ sshbuf_len(c->നിവേശം);
		എങ്കിൽ (len <= 0) {
			debug2("channel %d: ctl read<=0 rfd %d len %zd",
			    c->self, c->rfd, len);
			chan_read_failed(ssh, c);
			തിരികെ 0;
		} അല്ലെങ്കിൽ എങ്കിൽ ((r = sshbuf_put(c->നിവേശം, buf, len)) != 0)
			fatal_fr(r, "channel %i: append", c->self);
	}
	തിരികെ sshbuf_len(c->നിവേശം);
}

സ്ഥിതം ശൂന്യം
channel_post_mux_client_read(ഘടന ssh *ssh, Channel *c)
{
	u_int need;

	എങ്കിൽ ((c->io_ready & SSH_CHAN_IO_RFD) == 0)
		തിരികെ;
	എങ്കിൽ (c->istate != CHAN_നിവേശം_OPEN && c->istate != CHAN_നിവേശം_WAIT_DRAIN)
		തിരികെ;
	എങ്കിൽ (c->mux_pause)
		തിരികെ;

	/*
	 * Don't not read past the precise end of packets to
	 * avoid disrupting fd passing.
	 */
	എങ്കിൽ (read_mux(ssh, c, 4) < 4) /* read header */
		തിരികെ;
	/* XXX sshbuf_peek_u32 */
	need = PEEK_U32(sshbuf_ptr(c->നിവേശം));
#define CHANNEL_MUX_MAX_PACKET	(256 * 1024)
	എങ്കിൽ (need > CHANNEL_MUX_MAX_PACKET) {
		debug2("channel %d: packet too big %u > %u",
		    c->self, CHANNEL_MUX_MAX_PACKET, need);
		chan_rcvd_oclose(ssh, c);
		തിരികെ;
	}
	എങ്കിൽ (read_mux(ssh, c, need + 4) < need + 4) /* read body */
		തിരികെ;
	എങ്കിൽ (c->mux_rcb(ssh, c) != 0) {
		debug("channel %d: mux_rcb failed", c->self);
		chan_mark_dead(ssh, c);
		തിരികെ;
	}
}

സ്ഥിതം ശൂന്യം
channel_post_mux_client_write(ഘടന ssh *ssh, Channel *c)
{
	ssize_t len;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((c->io_ready & SSH_CHAN_IO_WFD) == 0)
		തിരികെ;
	എങ്കിൽ (sshbuf_len(c->output) == 0)
		തിരികെ;

	len = ലിഖ(c->wfd, sshbuf_ptr(c->output), sshbuf_len(c->output));
	എങ്കിൽ (len == -1 && (errno == EINTR || errno == EAGAIN))
		തിരികെ;
	എങ്കിൽ (len <= 0) {
		chan_mark_dead(ssh, c);
		തിരികെ;
	}
	എങ്കിൽ ((r = sshbuf_consume(c->output, len)) != 0)
		fatal_fr(r, "channel %i: consume", c->self);
}

സ്ഥിതം ശൂന്യം
channel_post_mux_client(ഘടന ssh *ssh, Channel *c)
{
	channel_post_mux_client_read(ssh, c);
	channel_post_mux_client_write(ssh, c);
}

സ്ഥിതം ശൂന്യം
channel_post_mux_listener(ഘടന ssh *ssh, Channel *c)
{
	Channel *nc;
	ഘടന sockaddr_storage addr;
	socklen_t addrlen;
	പൂർണ്ണസംഖ്യ newsock;
	uid_t euid;
	gid_t egid;

	എങ്കിൽ ((c->io_ready & SSH_CHAN_IO_SOCK_R) == 0)
		തിരികെ;

	debug("multiplexing control connection");

	/*
	 * Accept connection on control socket
	 */
	memset(&addr, 0, വലുപ്പം(addr));
	addrlen = വലുപ്പം(addr);
	എങ്കിൽ ((newsock = accept(c->sock, (ഘടന sockaddr*)&addr,
	    &addrlen)) == -1) {
		error_f("accept: %s", strerror(errno));
		എങ്കിൽ (errno == EMFILE || errno == ENFILE)
			c->notbefore = monotime_double() + 1.0;
		തിരികെ;
	}

	എങ്കിൽ (getpeereid(newsock, &euid, &egid) == -1) {
		error_f("getpeereid failed: %s", strerror(errno));
		close(newsock);
		തിരികെ;
	}
	എങ്കിൽ ((euid != 0) && (getuid() != euid)) {
		error("multiplex uid mismatch: peer euid %u != uid %u",
		    (u_int)euid, (u_int)getuid());
		close(newsock);
		തിരികെ;
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

സ്ഥിതം ശൂന്യം
channel_handler_init(ഘടന ssh_channels *sc)
{
	chan_fn **pre, **post;

	എങ്കിൽ ((pre = calloc(SSH_CHANNEL_MAX_TYPE, വലുപ്പം(*pre))) == ശൂന്യ ||
	    (post = calloc(SSH_CHANNEL_MAX_TYPE, വലുപ്പം(*post))) == ശൂന്യ)
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
സ്ഥിതം ശൂന്യം
channel_garbage_collect(ഘടന ssh *ssh, Channel *c)
{
	എങ്കിൽ (c == ശൂന്യ)
		തിരികെ;
	എങ്കിൽ (c->detach_user != ശൂന്യ) {
		എങ്കിൽ (!chan_is_dead(ssh, c, c->detach_close))
			തിരികെ;

		debug2("channel %d: gc: notify user", c->self);
		c->detach_user(ssh, c->self, 0, ശൂന്യ);
		/* if we still have a callback */
		എങ്കിൽ (c->detach_user != ശൂന്യ)
			തിരികെ;
		debug2("channel %d: gc: user detached", c->self);
	}
	എങ്കിൽ (!chan_is_dead(ssh, c, 1))
		തിരികെ;
	debug2("channel %d: garbage collecting", c->self);
	channel_free(ssh, c);
}

എണ്ണൽ channel_table { CHAN_PRE, CHAN_POST };

സ്ഥിതം ശൂന്യം
channel_handler(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ table, ഘടന timespec *timeout)
{
	ഘടന ssh_channels *sc = ssh->chanctxt;
	chan_fn **ftab = table == CHAN_PRE ? sc->channel_pre : sc->channel_post;
	u_int i, oalloc;
	Channel *c;
	ഇരട്ട now;

	now = monotime_double();
	വേണ്ടി (sc->nbulk = i = 0, oalloc = sc->channels_alloc; i < oalloc; i++) {
		c = sc->channels[i];
		എങ്കിൽ (c == ശൂന്യ)
			തുടരുക;
		/* Count open channels in bulk state */
		എങ്കിൽ (c->type == SSH_CHANNEL_OPEN && c->bulk)
			sc->nbulk++;
		/* Try to keep IO going while rekeying */
		എങ്കിൽ (ssh_packet_is_rekeying(ssh) && c->type != SSH_CHANNEL_OPEN)
			തുടരുക;
		എങ്കിൽ (c->delayed) {
			എങ്കിൽ (table == CHAN_PRE)
				c->delayed = 0;
			അല്ലെങ്കിൽ
				തുടരുക;
		}
		എങ്കിൽ (ftab[c->type] != ശൂന്യ) {
			എങ്കിൽ (table == CHAN_PRE && c->type == SSH_CHANNEL_OPEN &&
			    channel_get_expiry(ssh, c) != 0 &&
			    now >= channel_get_expiry(ssh, c)) {
				/* channel closed for inactivity */
				ഇരട്ട deadline = c->inactive_deadline != 0.0 ?
				    c->inactive_deadline : sc->global_deadline;
				verbose("channel %d: closing after %f seconds "
				    "of inactivity", c->self, deadline);
				channel_force_close(ssh, c, 1);
			} അല്ലെങ്കിൽ എങ്കിൽ (c->notbefore <= now) {
				/* Run handlers that are not paused. */
				(*ftab[c->type])(ssh, c);
				/* inactivity timeouts must interrupt poll() */
				എങ്കിൽ (timeout != ശൂന്യ &&
				    c->type == SSH_CHANNEL_OPEN &&
				    channel_get_expiry(ssh, c) != 0) {
					ptimeout_deadline_monotime_double(timeout,
					    channel_get_expiry(ssh, c));
				}
			} അല്ലെങ്കിൽ എങ്കിൽ (timeout != ശൂന്യ) {
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
സ്ഥിതം ശൂന്യം
channel_before_prepare_io(ഘടന ssh *ssh)
{
	ഘടന ssh_channels *sc = ssh->chanctxt;
	Channel *c;
	u_int i, oalloc;

	വേണ്ടി (i = 0, oalloc = sc->channels_alloc; i < oalloc; i++) {
		c = sc->channels[i];
		എങ്കിൽ (c == ശൂന്യ)
			തുടരുക;
		എങ്കിൽ (c->type == SSH_CHANNEL_RDYNAMIC_OPEN)
			channel_before_prepare_io_rdynamic(ssh, c);
	}
}

സ്ഥിതം ശൂന്യം
dump_channel_poll(സ്ഥിരം അക്ഷരം *func, സ്ഥിരം അക്ഷരം *what, Channel *c,
    u_int pollfd_offset, ഘടന pollfd *pfd)
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
സ്ഥിതം ശൂന്യം
channel_prepare_pollfd(Channel *c, u_int *next_pollfd,
    ഘടന pollfd *pfd, u_int npfd)
{
	u_int ev, p = *next_pollfd;

	എങ്കിൽ (c == ശൂന്യ)
		തിരികെ;
	എങ്കിൽ (p + 4 > npfd) {
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
	എങ്കിൽ (c->rfd != -1) {
		ev = 0;
		എങ്കിൽ ((c->io_want & SSH_CHAN_IO_RFD) != 0)
			ev |= POLLIN;
		/* rfd == wfd */
		എങ്കിൽ (c->wfd == c->rfd) {
			എങ്കിൽ ((c->io_want & SSH_CHAN_IO_WFD) != 0)
				ev |= POLLOUT;
		}
		/* rfd == efd */
		എങ്കിൽ (c->efd == c->rfd) {
			എങ്കിൽ ((c->io_want & SSH_CHAN_IO_EFD_R) != 0)
				ev |= POLLIN;
			എങ്കിൽ ((c->io_want & SSH_CHAN_IO_EFD_W) != 0)
				ev |= POLLOUT;
		}
		/* rfd == sock */
		എങ്കിൽ (c->sock == c->rfd) {
			എങ്കിൽ ((c->io_want & SSH_CHAN_IO_SOCK_R) != 0)
				ev |= POLLIN;
			എങ്കിൽ ((c->io_want & SSH_CHAN_IO_SOCK_W) != 0)
				ev |= POLLOUT;
		}
		/* Pack a pfd entry if any event armed for this fd */
		എങ്കിൽ (ev != 0) {
			c->pfds[0] = p;
			pfd[p].fd = c->rfd;
			pfd[p].events = ev;
			dump_channel_poll(__func__, "rfd", c, p, &pfd[p]);
			p++;
		}
	}
	/* prepare c->wfd if wanting IO and not already handled above */
	എങ്കിൽ (c->wfd != -1 && c->rfd != c->wfd) {
		ev = 0;
		എങ്കിൽ ((c->io_want & SSH_CHAN_IO_WFD))
			ev |= POLLOUT;
		/* Pack a pfd entry if any event armed for this fd */
		എങ്കിൽ (ev != 0) {
			c->pfds[1] = p;
			pfd[p].fd = c->wfd;
			pfd[p].events = ev;
			dump_channel_poll(__func__, "wfd", c, p, &pfd[p]);
			p++;
		}
	}
	/* prepare c->efd if wanting IO and not already handled above */
	എങ്കിൽ (c->efd != -1 && c->rfd != c->efd) {
		ev = 0;
		എങ്കിൽ ((c->io_want & SSH_CHAN_IO_EFD_R) != 0)
			ev |= POLLIN;
		എങ്കിൽ ((c->io_want & SSH_CHAN_IO_EFD_W) != 0)
			ev |= POLLOUT;
		/* Pack a pfd entry if any event armed for this fd */
		എങ്കിൽ (ev != 0) {
			c->pfds[2] = p;
			pfd[p].fd = c->efd;
			pfd[p].events = ev;
			dump_channel_poll(__func__, "efd", c, p, &pfd[p]);
			p++;
		}
	}
	/* prepare c->sock if wanting IO and not already handled above */
	എങ്കിൽ (c->sock != -1 && c->rfd != c->sock) {
		ev = 0;
		എങ്കിൽ ((c->io_want & SSH_CHAN_IO_SOCK_R) != 0)
			ev |= POLLIN;
		എങ്കിൽ ((c->io_want & SSH_CHAN_IO_SOCK_W) != 0)
			ev |= POLLOUT;
		/* Pack a pfd entry if any event armed for this fd */
		എങ്കിൽ (ev != 0) {
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
ശൂന്യം
channel_prepare_poll(ഘടന ssh *ssh, ഘടന pollfd **pfdp, u_int *npfd_allocp,
    u_int *npfd_activep, u_int npfd_reserved, ഘടന timespec *timeout)
{
	ഘടന ssh_channels *sc = ssh->chanctxt;
	u_int i, oalloc, p, npfd = npfd_reserved;

	channel_before_prepare_io(ssh); /* might create a new channel */
	/* clear out I/O flags from last poll */
	വേണ്ടി (i = 0; i < sc->channels_alloc; i++) {
		എങ്കിൽ (sc->channels[i] == ശൂന്യ)
			തുടരുക;
		sc->channels[i]->io_want = sc->channels[i]->io_ready = 0;
	}
	/* Allocate 4x pollfd for each channel (rfd, wfd, efd, sock) */
	എങ്കിൽ (sc->channels_alloc >= (INT_MAX / 4) - npfd_reserved)
		fatal_f("too many channels"); /* shouldn't happen */
	npfd += sc->channels_alloc * 4;
	എങ്കിൽ (npfd > *npfd_allocp) {
		*pfdp = xrecallocarray(*pfdp, *npfd_allocp,
		    npfd, വലുപ്പം(**pfdp));
		*npfd_allocp = npfd;
	}
	*npfd_activep = npfd_reserved;
	oalloc = sc->channels_alloc;

	channel_handler(ssh, CHAN_PRE, timeout);

	എങ്കിൽ (oalloc != sc->channels_alloc) {
		/* shouldn't happen */
		fatal_f("channels_alloc changed during CHAN_PRE "
		    "(was %u, now %u)", oalloc, sc->channels_alloc);
	}

	/* Prepare pollfd */
	p = npfd_reserved;
	വേണ്ടി (i = 0; i < sc->channels_alloc; i++)
		channel_prepare_pollfd(sc->channels[i], &p, *pfdp, npfd);
	*npfd_activep = p;
}

സ്ഥിതം ശൂന്യം
fd_ready(Channel *c, പൂർണ്ണസംഖ്യ p, ഘടന pollfd *pfds, u_int npfd, പൂർണ്ണസംഖ്യ fd,
    സ്ഥിരം അക്ഷരം *what, u_int revents_mask, u_int ready)
{
	ഘടന pollfd *pfd = &pfds[p];

	എങ്കിൽ (fd == -1)
		തിരികെ;
	എങ്കിൽ (p == -1 || (u_int)p >= npfd)
		fatal_f("channel %d: bad pfd %d (max %u)", c->self, p, npfd);
	dump_channel_poll(__func__, what, c, p, pfd);
	എങ്കിൽ (pfd->fd != fd) {
		fatal("channel %d: inconsistent %s fd=%d pollfd[%u].fd %d "
		    "r%d w%d e%d s%d", c->self, what, fd, p, pfd->fd,
		    c->rfd, c->wfd, c->efd, c->sock);
	}
	എങ്കിൽ ((pfd->revents & POLLNVAL) != 0) {
		fatal("channel %d: invalid %s pollfd[%u].fd %d r%d w%d e%d s%d",
		    c->self, what, p, pfd->fd, c->rfd, c->wfd, c->efd, c->sock);
	}
	എങ്കിൽ ((pfd->revents & (revents_mask|POLLHUP|POLLERR)) != 0)
		c->io_ready |= ready & c->io_want;
}

/*
 * After poll, perform any appropriate operations for channels which have
 * events pending.
 */
ശൂന്യം
channel_after_poll(ഘടന ssh *ssh, ഘടന pollfd *pfd, u_int npfd)
{
	ഘടന ssh_channels *sc = ssh->chanctxt;
	u_int i;
	പൂർണ്ണസംഖ്യ p;
	Channel *c;

#ifdef DEBUG_CHANNEL_POLL
	വേണ്ടി (p = 0; p < (പൂർണ്ണസംഖ്യ)npfd; p++) {
		എങ്കിൽ (pfd[p].revents == 0)
			തുടരുക;
		debug_f("pfd[%u].fd %d rev 0x%04x",
		    p, pfd[p].fd, pfd[p].revents);
	}
#endif

	/* Convert pollfd into c->io_ready */
	വേണ്ടി (i = 0; i < sc->channels_alloc; i++) {
		c = sc->channels[i];
		എങ്കിൽ (c == ശൂന്യ)
			തുടരുക;
		/* if rfd is shared with efd/sock then wfd should be too */
		എങ്കിൽ (c->rfd != -1 && c->wfd != -1 && c->rfd != c->wfd &&
		    (c->rfd == c->efd || c->rfd == c->sock)) {
			/* Shouldn't happen */
			fatal_f("channel %d: unexpected fds r%d w%d e%d s%d",
			    c->self, c->rfd, c->wfd, c->efd, c->sock);
		}
		c->io_ready = 0;
		/* rfd, potentially shared with wfd, efd and sock */
		എങ്കിൽ (c->rfd != -1 && (p = c->pfds[0]) != -1) {
			fd_ready(c, p, pfd, npfd, c->rfd,
			    "rfd", POLLIN, SSH_CHAN_IO_RFD);
			എങ്കിൽ (c->rfd == c->wfd) {
				fd_ready(c, p, pfd, npfd, c->wfd,
				    "wfd/r", POLLOUT, SSH_CHAN_IO_WFD);
			}
			എങ്കിൽ (c->rfd == c->efd) {
				fd_ready(c, p, pfd, npfd, c->efd,
				    "efdr/r", POLLIN, SSH_CHAN_IO_EFD_R);
				fd_ready(c, p, pfd, npfd, c->efd,
				    "efdw/r", POLLOUT, SSH_CHAN_IO_EFD_W);
			}
			എങ്കിൽ (c->rfd == c->sock) {
				fd_ready(c, p, pfd, npfd, c->sock,
				    "sockr/r", POLLIN, SSH_CHAN_IO_SOCK_R);
				fd_ready(c, p, pfd, npfd, c->sock,
				    "sockw/r", POLLOUT, SSH_CHAN_IO_SOCK_W);
			}
			dump_channel_poll(__func__, "rfd", c, p, pfd);
		}
		/* wfd */
		എങ്കിൽ (c->wfd != -1 && c->wfd != c->rfd &&
		    (p = c->pfds[1]) != -1) {
			fd_ready(c, p, pfd, npfd, c->wfd,
			    "wfd", POLLOUT, SSH_CHAN_IO_WFD);
			dump_channel_poll(__func__, "wfd", c, p, pfd);
		}
		/* efd */
		എങ്കിൽ (c->efd != -1 && c->efd != c->rfd &&
		    (p = c->pfds[2]) != -1) {
			fd_ready(c, p, pfd, npfd, c->efd,
			    "efdr", POLLIN, SSH_CHAN_IO_EFD_R);
			fd_ready(c, p, pfd, npfd, c->efd,
			    "efdw", POLLOUT, SSH_CHAN_IO_EFD_W);
			dump_channel_poll(__func__, "efd", c, p, pfd);
		}
		/* sock */
		എങ്കിൽ (c->sock != -1 && c->sock != c->rfd &&
		    (p = c->pfds[3]) != -1) {
			fd_ready(c, p, pfd, npfd, c->sock,
			    "sockr", POLLIN, SSH_CHAN_IO_SOCK_R);
			fd_ready(c, p, pfd, npfd, c->sock,
			    "sockw", POLLOUT, SSH_CHAN_IO_SOCK_W);
			dump_channel_poll(__func__, "sock", c, p, pfd);
		}
	}
	channel_handler(ssh, CHAN_POST, ശൂന്യ);
}

/*
 * Enqueue data for channels with open or draining c->input.
 * Returns non-zero if a packet was enqueued.
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
channel_output_poll_നിവേശം_open(ഘടന ssh *ssh, Channel *c)
{
	size_t len, plen;
	സ്ഥിരം u_char *pkt;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((len = sshbuf_len(c->നിവേശം)) == 0) {
		എങ്കിൽ (c->istate == CHAN_നിവേശം_WAIT_DRAIN) {
			/*
			 * input-buffer is empty and read-socket shutdown:
			 * tell peer, that we will not send more data:
			 * send IEOF.
			 * hack for extended data: delay EOF if EFD still
			 * in use.
			 */
			എങ്കിൽ (CHANNEL_EFD_നിവേശം_ACTIVE(c))
				debug2("channel %d: "
				    "ibuf_empty delayed efd %d/(%zu)",
				    c->self, c->efd, sshbuf_len(c->extended));
			അല്ലെങ്കിൽ
				chan_ibuf_empty(ssh, c);
		}
		തിരികെ 0;
	}

	എങ്കിൽ (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);

	എങ്കിൽ (c->datagram) {
		/* Check datagram will fit; drop if not */
		എങ്കിൽ ((r = sshbuf_get_string_direct(c->നിവേശം, &pkt, &plen)) != 0)
			fatal_fr(r, "channel %i: get datagram", c->self);
		/*
		 * XXX this does tail-drop on the datagram queue which is
		 * usually suboptimal compared to head-drop. Better to have
		 * backpressure at read time? (i.e. read + discard)
		 */
		എങ്കിൽ (plen > c->remote_window || plen > c->remote_maxpacket) {
			debug("channel %d: datagram too big", c->self);
			തിരികെ 0;
		}
		/* Enqueue it */
		എങ്കിൽ ((r = sshpkt_start(ssh, SSH2_സന്ദേശം_CHANNEL_DATA)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
		    (r = sshpkt_put_string(ssh, pkt, plen)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "channel %i: send datagram", c->self);
		c->remote_window -= plen;
		തിരികെ 1;
	}

	/* Enqueue packet for buffered data. */
	എങ്കിൽ (len > c->remote_window)
		len = c->remote_window;
	എങ്കിൽ (len > c->remote_maxpacket)
		len = c->remote_maxpacket;
	എങ്കിൽ (len == 0)
		തിരികെ 0;
	എങ്കിൽ ((r = sshpkt_start(ssh, SSH2_സന്ദേശം_CHANNEL_DATA)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_string(ssh, sshbuf_ptr(c->നിവേശം), len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i: send data", c->self);
	എങ്കിൽ ((r = sshbuf_consume(c->നിവേശം, len)) != 0)
		fatal_fr(r, "channel %i: consume", c->self);
	c->remote_window -= len;
	തിരികെ 1;
}

/*
 * Enqueue data for channels with open c->extended in read mode.
 * Returns non-zero if a packet was enqueued.
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
channel_output_poll_extended_read(ഘടന ssh *ssh, Channel *c)
{
	size_t len;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((len = sshbuf_len(c->extended)) == 0)
		തിരികെ 0;

	debug2("channel %d: rwin %u elen %zu euse %d", c->self,
	    c->remote_window, sshbuf_len(c->extended), c->extended_usage);
	എങ്കിൽ (len > c->remote_window)
		len = c->remote_window;
	എങ്കിൽ (len > c->remote_maxpacket)
		len = c->remote_maxpacket;
	എങ്കിൽ (len == 0)
		തിരികെ 0;
	എങ്കിൽ (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);
	എങ്കിൽ ((r = sshpkt_start(ssh, SSH2_സന്ദേശം_CHANNEL_EXTENDED_DATA)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_u32(ssh, SSH2_EXTENDED_DATA_STDERR)) != 0 ||
	    (r = sshpkt_put_string(ssh, sshbuf_ptr(c->extended), len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i: data", c->self);
	എങ്കിൽ ((r = sshbuf_consume(c->extended, len)) != 0)
		fatal_fr(r, "channel %i: consume", c->self);
	c->remote_window -= len;
	debug2("channel %d: sent ext data %zu", c->self, len);
	തിരികെ 1;
}

/*
 * If there is data to send to the connection, enqueue some of it now.
 * Returns non-zero if data was enqueued.
 */
പൂർണ്ണസംഖ്യ
channel_output_poll(ഘടന ssh *ssh)
{
	ഘടന ssh_channels *sc = ssh->chanctxt;
	Channel *c;
	u_int i;
	പൂർണ്ണസംഖ്യ ret = 0;

	വേണ്ടി (i = 0; i < sc->channels_alloc; i++) {
		c = sc->channels[i];
		എങ്കിൽ (c == ശൂന്യ)
			തുടരുക;

		/*
		 * We are only interested in channels that can have buffered
		 * incoming data.
		 */
		എങ്കിൽ (c->type != SSH_CHANNEL_OPEN)
			തുടരുക;
		എങ്കിൽ ((c->flags & (CHAN_CLOSE_SENT|CHAN_CLOSE_RCVD))) {
			/* XXX is this true? */
			debug3("channel %d: will not send data after close",
			    c->self);
			തുടരുക;
		}

		/* Get the amount of buffered data for this channel. */
		എങ്കിൽ (c->istate == CHAN_നിവേശം_OPEN ||
		    c->istate == CHAN_നിവേശം_WAIT_DRAIN)
			ret |= channel_output_poll_നിവേശം_open(ssh, c);
		/* Send extended data, i.e. stderr */
		എങ്കിൽ (!(c->flags & CHAN_EOF_SENT) &&
		    c->extended_usage == CHAN_EXTENDED_READ)
			ret |= channel_output_poll_extended_read(ssh, c);
	}
	തിരികെ ret;
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
പൂർണ്ണസംഖ്യ
channel_proxy_downstream(ഘടന ssh *ssh, Channel *downstream)
{
	Channel *c = ശൂന്യ;
	ഘടന sshbuf *original = ശൂന്യ, *modified = ശൂന്യ;
	സ്ഥിരം u_char *cp;
	അക്ഷരം *ctype = ശൂന്യ, *listen_host = ശൂന്യ;
	u_char type;
	size_t have;
	പൂർണ്ണസംഖ്യ ret = -1, r;
	u_int id, remote_id, listen_port;

	/* sshbuf_dump(downstream->input, stderr); */
	എങ്കിൽ ((r = sshbuf_get_string_direct(downstream->നിവേശം, &cp, &have))
	    != 0) {
		error_fr(r, "parse");
		തിരികെ -1;
	}
	എങ്കിൽ (have < 2) {
		error_f("short message");
		തിരികെ -1;
	}
	type = cp[1];
	/* skip padlen + type */
	cp += 2;
	have -= 2;
	എങ്കിൽ (ssh_packet_log_type(type))
		debug3_f("channel %u: down->up: type %u",
		    downstream->self, type);

	തിരഞ്ഞെടുപ്പ് (type) {
	അവസ്ഥ SSH2_സന്ദേശം_CHANNEL_OPEN:
		എങ്കിൽ ((original = sshbuf_from(cp, have)) == ശൂന്യ ||
		    (modified = sshbuf_new()) == ശൂന്യ) {
			error_f("alloc");
			പോകുക out;
		}
		എങ്കിൽ ((r = sshbuf_get_cstring(original, &ctype, ശൂന്യ)) != 0 ||
		    (r = sshbuf_get_u32(original, &id)) != 0) {
			error_fr(r, "parse");
			പോകുക out;
		}
		c = channel_new(ssh, "mux-proxy", SSH_CHANNEL_MUX_PROXY,
		    -1, -1, -1, 0, 0, 0, ctype, 1);
		c->mux_ctx = downstream;	/* point to mux client */
		c->mux_downstream_id = id;	/* original downstream id */
		എങ്കിൽ ((r = sshbuf_put_cstring(modified, ctype)) != 0 ||
		    (r = sshbuf_put_u32(modified, c->self)) != 0 ||
		    (r = sshbuf_putb(modified, original)) != 0) {
			error_fr(r, "compose");
			channel_free(ssh, c);
			പോകുക out;
		}
		നിർത്തുക;
	അവസ്ഥ SSH2_സന്ദേശം_CHANNEL_OPEN_CONFIRMATION:
		/*
		 * Almost the same as SSH2_MSG_CHANNEL_OPEN, except then we
		 * need to parse 'remote_id' instead of 'ctype'.
		 */
		എങ്കിൽ ((original = sshbuf_from(cp, have)) == ശൂന്യ ||
		    (modified = sshbuf_new()) == ശൂന്യ) {
			error_f("alloc");
			പോകുക out;
		}
		എങ്കിൽ ((r = sshbuf_get_u32(original, &remote_id)) != 0 ||
		    (r = sshbuf_get_u32(original, &id)) != 0) {
			error_fr(r, "parse");
			പോകുക out;
		}
		c = channel_new(ssh, "mux-proxy", SSH_CHANNEL_MUX_PROXY,
		    -1, -1, -1, 0, 0, 0, "mux-down-connect", 1);
		c->mux_ctx = downstream;	/* point to mux client */
		c->mux_downstream_id = id;
		c->remote_id = remote_id;
		c->have_remote_id = 1;
		എങ്കിൽ ((r = sshbuf_put_u32(modified, remote_id)) != 0 ||
		    (r = sshbuf_put_u32(modified, c->self)) != 0 ||
		    (r = sshbuf_putb(modified, original)) != 0) {
			error_fr(r, "compose");
			channel_free(ssh, c);
			പോകുക out;
		}
		നിർത്തുക;
	അവസ്ഥ SSH2_സന്ദേശം_GLOBAL_REQUEST:
		എങ്കിൽ ((original = sshbuf_from(cp, have)) == ശൂന്യ) {
			error_f("alloc");
			പോകുക out;
		}
		എങ്കിൽ ((r = sshbuf_get_cstring(original, &ctype, ശൂന്യ)) != 0) {
			error_fr(r, "parse");
			പോകുക out;
		}
		എങ്കിൽ (strcmp(ctype, "tcpip-forward") != 0) {
			error_f("unsupported request %s", ctype);
			പോകുക out;
		}
		എങ്കിൽ ((r = sshbuf_get_u8(original, ശൂന്യ)) != 0 ||
		    (r = sshbuf_get_cstring(original, &listen_host, ശൂന്യ)) != 0 ||
		    (r = sshbuf_get_u32(original, &listen_port)) != 0) {
			error_fr(r, "parse");
			പോകുക out;
		}
		എങ്കിൽ (listen_port > 65535) {
			error_f("tcpip-forward for %s: bad port %u",
			    listen_host, listen_port);
			പോകുക out;
		}
		/* Record that connection to this host/port is permitted. */
		permission_set_add(ssh, FORWARD_USER, FORWARD_LOCAL, "<mux>",
		    -1, listen_host, ശൂന്യ, (പൂർണ്ണസംഖ്യ)listen_port, downstream);
		നിർത്തുക;
	അവസ്ഥ SSH2_സന്ദേശം_CHANNEL_CLOSE:
		എങ്കിൽ (have < 4)
			നിർത്തുക;
		remote_id = PEEK_U32(cp);
		എങ്കിൽ ((c = channel_by_remote_id(ssh, remote_id)) != ശൂന്യ) {
			എങ്കിൽ (c->flags & CHAN_CLOSE_RCVD)
				channel_free(ssh, c);
			അല്ലെങ്കിൽ
				c->flags |= CHAN_CLOSE_SENT;
		}
		നിർത്തുക;
	}
	എങ്കിൽ (modified) {
		എങ്കിൽ ((r = sshpkt_start(ssh, type)) != 0 ||
		    (r = sshpkt_putb(ssh, modified)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0) {
			error_fr(r, "send");
			പോകുക out;
		}
	} അല്ലെങ്കിൽ {
		എങ്കിൽ ((r = sshpkt_start(ssh, type)) != 0 ||
		    (r = sshpkt_put(ssh, cp, have)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0) {
			error_fr(r, "send");
			പോകുക out;
		}
	}
	ret = 0;
 out:
	സ്വതന്ത്രം(ctype);
	സ്വതന്ത്രം(listen_host);
	sshbuf_free(original);
	sshbuf_free(modified);
	തിരികെ ret;
}

/*
 * receive packets from upstream server and de-multiplex packets
 * to correct downstream:
 * implemented as a helper for channel input handlers,
 * replaces local (proxy) channel ID with downstream channel ID.
 */
പൂർണ്ണസംഖ്യ
channel_proxy_upstream(Channel *c, പൂർണ്ണസംഖ്യ type, uint32_t seq, ഘടന ssh *ssh)
{
	ഘടന sshbuf *b = ശൂന്യ;
	Channel *downstream;
	സ്ഥിരം u_char *cp = ശൂന്യ;
	size_t len;
	പൂർണ്ണസംഖ്യ r;

	/*
	 * When receiving packets from the peer we need to check whether we
	 * need to forward the packets to the mux client. In this case we
	 * restore the original channel id and keep track of CLOSE messages,
	 * so we can cleanup the channel.
	 */
	എങ്കിൽ (c == ശൂന്യ || c->type != SSH_CHANNEL_MUX_PROXY)
		തിരികെ 0;
	എങ്കിൽ ((downstream = c->mux_ctx) == ശൂന്യ)
		തിരികെ 0;
	തിരഞ്ഞെടുപ്പ് (type) {
	അവസ്ഥ SSH2_സന്ദേശം_CHANNEL_CLOSE:
	അവസ്ഥ SSH2_സന്ദേശം_CHANNEL_DATA:
	അവസ്ഥ SSH2_സന്ദേശം_CHANNEL_EOF:
	അവസ്ഥ SSH2_സന്ദേശം_CHANNEL_EXTENDED_DATA:
	അവസ്ഥ SSH2_സന്ദേശം_CHANNEL_OPEN_CONFIRMATION:
	അവസ്ഥ SSH2_സന്ദേശം_CHANNEL_OPEN_FAILURE:
	അവസ്ഥ SSH2_സന്ദേശം_CHANNEL_WINDOW_ADJUST:
	അവസ്ഥ SSH2_സന്ദേശം_CHANNEL_SUCCESS:
	അവസ്ഥ SSH2_സന്ദേശം_CHANNEL_FAILURE:
	അവസ്ഥ SSH2_സന്ദേശം_CHANNEL_REQUEST:
		നിർത്തുക;
	സ്ഥിരസ്ഥിതി:
		debug2_f("channel %u: unsupported type %u", c->self, type);
		തിരികെ 0;
	}
	എങ്കിൽ ((b = sshbuf_new()) == ശൂന്യ) {
		error_f("alloc reply");
		പോകുക out;
	}
	/* get remaining payload (after id) */
	cp = sshpkt_ptr(ssh, &len);
	എങ്കിൽ (cp == ശൂന്യ) {
		error_f("no packet");
		പോകുക out;
	}
	/* translate id and send to muxclient */
	എങ്കിൽ ((r = sshbuf_put_u8(b, 0)) != 0 ||	/* padlen */
	    (r = sshbuf_put_u8(b, type)) != 0 ||
	    (r = sshbuf_put_u32(b, c->mux_downstream_id)) != 0 ||
	    (r = sshbuf_put(b, cp, len)) != 0 ||
	    (r = sshbuf_put_stringb(downstream->output, b)) != 0) {
		error_fr(r, "compose muxclient");
		പോകുക out;
	}
	/* sshbuf_dump(b, stderr); */
	എങ്കിൽ (ssh_packet_log_type(type))
		debug3_f("channel %u: up->down: type %u", c->self, type);
 out:
	/* update state */
	തിരഞ്ഞെടുപ്പ് (type) {
	അവസ്ഥ SSH2_സന്ദേശം_CHANNEL_OPEN_CONFIRMATION:
		/* record remote_id for SSH2_MSG_CHANNEL_CLOSE */
		എങ്കിൽ (cp && len > 4) {
			c->remote_id = PEEK_U32(cp);
			c->have_remote_id = 1;
		}
		നിർത്തുക;
	അവസ്ഥ SSH2_സന്ദേശം_CHANNEL_CLOSE:
		എങ്കിൽ (c->flags & CHAN_CLOSE_SENT)
			channel_free(ssh, c);
		അല്ലെങ്കിൽ
			c->flags |= CHAN_CLOSE_RCVD;
		നിർത്തുക;
	}
	sshbuf_free(b);
	തിരികെ 1;
}

/* -- protocol input */

/* Parse a channel ID from the current packet */
സ്ഥിതം പൂർണ്ണസംഖ്യ
channel_parse_id(ഘടന ssh *ssh, സ്ഥിരം അക്ഷരം *where, സ്ഥിരം അക്ഷരം *what)
{
	uint32_t id;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = sshpkt_get_u32(ssh, &id)) != 0) {
		error_r(r, "%s: parse id", where);
		ssh_packet_disconnect(ssh, "Invalid %s message", what);
	}
	എങ്കിൽ (id > INT_MAX) {
		error_r(r, "%s: bad channel id %u", where, id);
		ssh_packet_disconnect(ssh, "Invalid %s channel id", what);
	}
	തിരികെ (പൂർണ്ണസംഖ്യ)id;
}

/* Lookup a channel from an ID in the current packet */
സ്ഥിതം Channel *
channel_from_packet_id(ഘടന ssh *ssh, സ്ഥിരം അക്ഷരം *where, സ്ഥിരം അക്ഷരം *what)
{
	പൂർണ്ണസംഖ്യ id = channel_parse_id(ssh, where, what);
	Channel *c;

	എങ്കിൽ ((c = channel_lookup(ssh, id)) == ശൂന്യ) {
		ssh_packet_disconnect(ssh,
		    "%s packet referred to nonexistent channel %d", what, id);
	}
	തിരികെ c;
}

പൂർണ്ണസംഖ്യ
channel_നിവേശം_data(പൂർണ്ണസംഖ്യ type, uint32_t seq, ഘടന ssh *ssh)
{
	സ്ഥിരം u_char *data;
	size_t data_len, win_len;
	Channel *c = channel_from_packet_id(ssh, __func__, "data");
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (channel_proxy_upstream(c, type, seq, ssh))
		തിരികെ 0;

	/* Ignore any data for non-open channels (might happen on close) */
	എങ്കിൽ (c->type != SSH_CHANNEL_OPEN &&
	    c->type != SSH_CHANNEL_RDYNAMIC_OPEN &&
	    c->type != SSH_CHANNEL_RDYNAMIC_FINISH &&
	    c->type != SSH_CHANNEL_X11_OPEN)
		തിരികെ 0;

	/* Get the data. */
	എങ്കിൽ ((r = sshpkt_get_string_direct(ssh, &data, &data_len)) != 0 ||
            (r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "channel %i: get data", c->self);

	win_len = data_len;
	എങ്കിൽ (c->datagram)
		win_len += 4;  /* string length header */

	/*
	 * The sending side reduces its window as it sends data, so we
	 * must 'fake' consumption of the data in order to ensure that window
	 * updates are sent back. Otherwise the connection might deadlock.
	 */
	എങ്കിൽ (c->ostate != CHAN_OUTPUT_OPEN) {
		എങ്കിൽ (win_len > c->local_window)
			c->local_window = 0;
		അല്ലെങ്കിൽ
			c->local_window -= win_len;
		c->local_consumed += win_len;
		തിരികെ 0;
	}

	എങ്കിൽ (win_len > c->local_maxpacket) {
		logit("channel %d: rcvd big packet %zu, maxpack %u",
		    c->self, win_len, c->local_maxpacket);
		തിരികെ 0;
	}
	എങ്കിൽ (win_len > c->local_window) {
		u_int delta = win_len - c->local_window;

		എങ്കിൽ (c->local_window_exceeded > UINT_MAX - delta)
			c->local_window_exceeded = UINT_MAX;
		അല്ലെങ്കിൽ
			c->local_window_exceeded += delta;
		logit("channel %d: rcvd too much data %zu, win %u/%u "
		    "(excess %u)", c->self, win_len, c->local_window,
		    c->local_window_max, c->local_window_exceeded);
		c->local_window = 0;
		/* Allow 10% grace before bringing the hammer down */
		എങ്കിൽ (c->local_window_exceeded > (c->local_window_max / 10)) {
			ssh_packet_disconnect(ssh, "channel %d: peer ignored "
			    "channel window", c->self);
		}
	} അല്ലെങ്കിൽ {
		c->local_window -= win_len;
		c->local_window_exceeded = 0;
	}

	എങ്കിൽ (c->datagram) {
		എങ്കിൽ ((r = sshbuf_put_string(c->output, data, data_len)) != 0)
			fatal_fr(r, "channel %i: append datagram", c->self);
	} അല്ലെങ്കിൽ എങ്കിൽ ((r = sshbuf_put(c->output, data, data_len)) != 0)
		fatal_fr(r, "channel %i: append data", c->self);

	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
channel_നിവേശം_extended_data(പൂർണ്ണസംഖ്യ type, uint32_t seq, ഘടന ssh *ssh)
{
	സ്ഥിരം u_char *data;
	size_t data_len;
	uint32_t tcode;
	Channel *c = channel_from_packet_id(ssh, __func__, "extended data");
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (channel_proxy_upstream(c, type, seq, ssh))
		തിരികെ 0;
	എങ്കിൽ (c->type != SSH_CHANNEL_OPEN) {
		logit("channel %d: ext data for non open", c->self);
		തിരികെ 0;
	}
	എങ്കിൽ (c->flags & CHAN_EOF_RCVD) {
		എങ്കിൽ (ssh->compat & SSH_BUG_EXTEOF)
			debug("channel %d: accepting ext data after eof",
			    c->self);
		അല്ലെങ്കിൽ
			ssh_packet_disconnect(ssh, "Received extended_data "
			    "after EOF on channel %d.", c->self);
	}

	എങ്കിൽ ((r = sshpkt_get_u32(ssh, &tcode)) != 0) {
		error_fr(r, "parse tcode");
		ssh_packet_disconnect(ssh, "Invalid extended_data message");
	}
	എങ്കിൽ (c->efd == -1 ||
	    c->extended_usage != CHAN_EXTENDED_WRITE ||
	    tcode != SSH2_EXTENDED_DATA_STDERR) {
		logit("channel %d: bad ext data", c->self);
		തിരികെ 0;
	}
	എങ്കിൽ ((r = sshpkt_get_string_direct(ssh, &data, &data_len)) != 0 ||
            (r = sshpkt_get_end(ssh)) != 0) {
		error_fr(r, "parse data");
		ssh_packet_disconnect(ssh, "Invalid extended_data message");
	}

	എങ്കിൽ (data_len > c->local_window) {
		logit("channel %d: rcvd too much extended_data %zu, win %u",
		    c->self, data_len, c->local_window);
		തിരികെ 0;
	}
	debug2("channel %d: rcvd ext data %zu", c->self, data_len);
	/* XXX sshpkt_getb? */
	എങ്കിൽ ((r = sshbuf_put(c->extended, data, data_len)) != 0)
		error_fr(r, "append");
	c->local_window -= data_len;
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
channel_നിവേശം_ieof(പൂർണ്ണസംഖ്യ type, uint32_t seq, ഘടന ssh *ssh)
{
	Channel *c = channel_from_packet_id(ssh, __func__, "ieof");
	പൂർണ്ണസംഖ്യ r;

        എങ്കിൽ ((r = sshpkt_get_end(ssh)) != 0) {
		error_fr(r, "parse data");
		ssh_packet_disconnect(ssh, "Invalid ieof message");
	}

	എങ്കിൽ (channel_proxy_upstream(c, type, seq, ssh))
		തിരികെ 0;
	chan_rcvd_ieof(ssh, c);

	/* XXX force input close */
	എങ്കിൽ (c->force_drain && c->istate == CHAN_നിവേശം_OPEN) {
		debug("channel %d: FORCE input drain", c->self);
		c->istate = CHAN_നിവേശം_WAIT_DRAIN;
		എങ്കിൽ (sshbuf_len(c->നിവേശം) == 0)
			chan_ibuf_empty(ssh, c);
	}
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
channel_നിവേശം_oclose(പൂർണ്ണസംഖ്യ type, uint32_t seq, ഘടന ssh *ssh)
{
	Channel *c = channel_from_packet_id(ssh, __func__, "oclose");
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (channel_proxy_upstream(c, type, seq, ssh))
		തിരികെ 0;
        എങ്കിൽ ((r = sshpkt_get_end(ssh)) != 0) {
		error_fr(r, "parse data");
		ssh_packet_disconnect(ssh, "Invalid oclose message");
	}
	chan_rcvd_oclose(ssh, c);
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
channel_നിവേശം_open_confirmation(പൂർണ്ണസംഖ്യ type, uint32_t seq, ഘടന ssh *ssh)
{
	Channel *c = channel_from_packet_id(ssh, __func__, "open confirmation");
	uint32_t remote_window, remote_maxpacket;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (channel_proxy_upstream(c, type, seq, ssh))
		തിരികെ 0;
	എങ്കിൽ (c->type != SSH_CHANNEL_OPENING)
		ssh_packet_disconnect(ssh, "Received open confirmation for "
		    "non-opening channel %d.", c->self);
	/*
	 * Record the remote channel number and mark that the channel
	 * is now open.
	 */
	എങ്കിൽ ((r = sshpkt_get_u32(ssh, &c->remote_id)) != 0 ||
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
	എങ്കിൽ (c->open_confirm) {
		debug2_f("channel %d: callback start", c->self);
		c->open_confirm(ssh, c->self, 1, c->open_confirm_ctx);
		debug2_f("channel %d: callback done", c->self);
	}
	channel_set_used_time(ssh, c);
	debug2("channel %d: open confirm rwindow %u rmax %u", c->self,
	    c->remote_window, c->remote_maxpacket);
	തിരികെ 0;
}

സ്ഥിതം അക്ഷരം *
reason2txt(പൂർണ്ണസംഖ്യ reason)
{
	തിരഞ്ഞെടുപ്പ് (reason) {
	അവസ്ഥ SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED:
		തിരികെ "administratively prohibited";
	അവസ്ഥ SSH2_OPEN_CONNECT_FAILED:
		തിരികെ "connect failed";
	അവസ്ഥ SSH2_OPEN_UNKNOWN_CHANNEL_TYPE:
		തിരികെ "unknown channel type";
	അവസ്ഥ SSH2_OPEN_RESOURCE_SHORTAGE:
		തിരികെ "resource shortage";
	}
	തിരികെ "unknown reason";
}

പൂർണ്ണസംഖ്യ
channel_നിവേശം_open_failure(പൂർണ്ണസംഖ്യ type, uint32_t seq, ഘടന ssh *ssh)
{
	Channel *c = channel_from_packet_id(ssh, __func__, "open failure");
	uint32_t reason;
	അക്ഷരം *സന്ദേശം = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (channel_proxy_upstream(c, type, seq, ssh))
		തിരികെ 0;
	എങ്കിൽ (c->type != SSH_CHANNEL_OPENING)
		ssh_packet_disconnect(ssh, "Received open failure for "
		    "non-opening channel %d.", c->self);
	എങ്കിൽ ((r = sshpkt_get_u32(ssh, &reason)) != 0) {
		error_fr(r, "parse reason");
		ssh_packet_disconnect(ssh, "Invalid open failure message");
	}
	/* skip language */
	എങ്കിൽ ((r = sshpkt_get_cstring(ssh, &സന്ദേശം, ശൂന്യ)) != 0 ||
	    (r = sshpkt_get_string_direct(ssh, ശൂന്യ, ശൂന്യ)) != 0 ||
            (r = sshpkt_get_end(ssh)) != 0) {
		error_fr(r, "parse msg/lang");
		ssh_packet_disconnect(ssh, "Invalid open failure message");
	}
	logit("channel %d: open failed: %s%s%s", c->self,
	    reason2txt(reason), സന്ദേശം ? ": ": "", സന്ദേശം ? സന്ദേശം : "");
	സ്വതന്ത്രം(സന്ദേശം);
	എങ്കിൽ (c->open_confirm) {
		debug2_f("channel %d: callback start", c->self);
		c->open_confirm(ssh, c->self, 0, c->open_confirm_ctx);
		debug2_f("channel %d: callback done", c->self);
	}
	/* Schedule the channel for cleanup/deletion. */
	chan_mark_dead(ssh, c);
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
channel_നിവേശം_window_adjust(പൂർണ്ണസംഖ്യ type, uint32_t seq, ഘടന ssh *ssh)
{
	പൂർണ്ണസംഖ്യ id = channel_parse_id(ssh, __func__, "window adjust");
	Channel *c;
	uint32_t adjust;
	u_int new_rwin;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((c = channel_lookup(ssh, id)) == ശൂന്യ) {
		logit("Received window adjust for non-open channel %d.", id);
		തിരികെ 0;
	}

	എങ്കിൽ (channel_proxy_upstream(c, type, seq, ssh))
		തിരികെ 0;
	എങ്കിൽ ((r = sshpkt_get_u32(ssh, &adjust)) != 0 ||
            (r = sshpkt_get_end(ssh)) != 0) {
		error_fr(r, "parse adjust");
		ssh_packet_disconnect(ssh, "Invalid window adjust message");
	}
	debug2("channel %d: rcvd adjust %u", c->self, adjust);
	എങ്കിൽ ((new_rwin = c->remote_window + adjust) < c->remote_window) {
		fatal("channel %d: adjust %u overflows remote window %u",
		    c->self, adjust, c->remote_window);
	}
	c->remote_window = new_rwin;
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
channel_നിവേശം_status_confirm(പൂർണ്ണസംഖ്യ type, uint32_t seq, ഘടന ssh *ssh)
{
	പൂർണ്ണസംഖ്യ id = channel_parse_id(ssh, __func__, "status confirm");
	Channel *c;
	ഘടന channel_confirm *cc;

	/* Reset keepalive timeout */
	ssh_packet_set_alive_timeouts(ssh, 0);

	debug2_f("type %d id %d", type, id);

	എങ്കിൽ ((c = channel_lookup(ssh, id)) == ശൂന്യ) {
		logit_f("%d: unknown", id);
		തിരികെ 0;
	}
	എങ്കിൽ (channel_proxy_upstream(c, type, seq, ssh))
		തിരികെ 0;
        എങ്കിൽ (sshpkt_get_end(ssh) != 0)
		ssh_packet_disconnect(ssh, "Invalid status confirm message");
	എങ്കിൽ ((cc = TAILQ_FIRST(&c->status_confirms)) == ശൂന്യ)
		തിരികെ 0;
	cc->cb(ssh, type, c, cc->ctx);
	TAILQ_REMOVE(&c->status_confirms, cc, entry);
	freezero(cc, വലുപ്പം(*cc));
	തിരികെ 0;
}

/* -- tcp forwarding */

ശൂന്യം
channel_set_af(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ af)
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
സ്ഥിതം സ്ഥിരം അക്ഷരം *
channel_fwd_bind_addr(ഘടന ssh *ssh, സ്ഥിരം അക്ഷരം *listen_addr, പൂർണ്ണസംഖ്യ *wildcardp,
    പൂർണ്ണസംഖ്യ is_client, ഘടന ForwardOptions *fwd_opts)
{
	സ്ഥിരം അക്ഷരം *addr = ശൂന്യ;
	പൂർണ്ണസംഖ്യ wildcard = 0;

	എങ്കിൽ (listen_addr == ശൂന്യ) {
		/* No address specified: default to gateway_ports setting */
		എങ്കിൽ (fwd_opts->gateway_ports)
			wildcard = 1;
	} അല്ലെങ്കിൽ എങ്കിൽ (fwd_opts->gateway_ports || is_client) {
		എങ്കിൽ (((ssh->compat & SSH_OLD_FORWARD_ADDR) &&
		    strcmp(listen_addr, "0.0.0.0") == 0 && is_client == 0) ||
		    *listen_addr == '\0' || strcmp(listen_addr, "*") == 0 ||
		    (!is_client && fwd_opts->gateway_ports == 1)) {
			wildcard = 1;
			/*
			 * Notify client if they requested a specific listen
			 * address and it was overridden.
			 */
			എങ്കിൽ (*listen_addr != '\0' &&
			    strcmp(listen_addr, "0.0.0.0") != 0 &&
			    strcmp(listen_addr, "*") != 0) {
				ssh_packet_send_debug(ssh,
				    "Forwarding listen address "
				    "\"%s\" overridden by server "
				    "GatewayPorts", listen_addr);
			}
		} അല്ലെങ്കിൽ എങ്കിൽ (strcmp(listen_addr, "localhost") != 0 ||
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
	} അല്ലെങ്കിൽ എങ്കിൽ (strcmp(listen_addr, "127.0.0.1") == 0 ||
	    strcmp(listen_addr, "::1") == 0) {
		/*
		 * If a specific IPv4/IPv6 localhost address has been
		 * requested then accept it even if gateway_ports is in
		 * effect. This allows the client to prefer IPv4 or IPv6.
		 */
		addr = listen_addr;
	}
	എങ്കിൽ (wildcardp != ശൂന്യ)
		*wildcardp = wildcard;
	തിരികെ addr;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
channel_setup_fwd_listener_tcpip(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ type,
    ഘടന Forward *fwd, പൂർണ്ണസംഖ്യ *allocated_listen_port,
    ഘടന ForwardOptions *fwd_opts)
{
	Channel *c;
	പൂർണ്ണസംഖ്യ sock, r, success = 0, wildcard = 0, is_client;
	ഘടന addrinfo hints, *ai, *aitop;
	സ്ഥിരം അക്ഷരം *host, *addr;
	അക്ഷരം ntop[NI_MAXHOST], strport[NI_MAXSERV];
	in_port_t *lport_p;

	is_client = (type == SSH_CHANNEL_PORT_LISTENER);

	എങ്കിൽ (is_client && fwd->connect_path != ശൂന്യ) {
		host = fwd->connect_path;
	} അല്ലെങ്കിൽ {
		host = (type == SSH_CHANNEL_RPORT_LISTENER) ?
		    fwd->listen_host : fwd->connect_host;
		എങ്കിൽ (host == ശൂന്യ) {
			error("No forward host name.");
			തിരികെ 0;
		}
		എങ്കിൽ (strlen(host) >= NI_MAXHOST) {
			error("Forward host name too long.");
			തിരികെ 0;
		}
	}

	/* Determine the bind address, cf. channel_fwd_bind_addr() comment */
	addr = channel_fwd_bind_addr(ssh, fwd->listen_host, &wildcard,
	    is_client, fwd_opts);
	debug3_f("type %d wildcard %d addr %s", type, wildcard,
	    (addr == ശൂന്യ) ? "NULL" : addr);

	/*
	 * getaddrinfo returns a loopback address if the hostname is
	 * set to NULL and hints.ai_flags is not AI_PASSIVE
	 */
	memset(&hints, 0, വലുപ്പം(hints));
	hints.ai_family = ssh->chanctxt->IPv4or6;
	hints.ai_flags = wildcard ? AI_PASSIVE : 0;
	hints.ai_socktype = SOCK_STREAM;
	snprintf(strport, വലുപ്പം strport, "%d", fwd->listen_port);
	എങ്കിൽ ((r = getaddrinfo(addr, strport, &hints, &aitop)) != 0) {
		എങ്കിൽ (addr == ശൂന്യ) {
			/* This really shouldn't happen */
			ssh_packet_disconnect(ssh, "getaddrinfo: fatal error: %s",
			    ssh_gai_strerror(r));
		} അല്ലെങ്കിൽ {
			error_f("getaddrinfo(%.64s): %s", addr,
			    ssh_gai_strerror(r));
		}
		തിരികെ 0;
	}
	എങ്കിൽ (allocated_listen_port != ശൂന്യ)
		*allocated_listen_port = 0;
	വേണ്ടി (ai = aitop; ai; ai = ai->ai_next) {
		തിരഞ്ഞെടുപ്പ് (ai->ai_family) {
		അവസ്ഥ AF_INET:
			lport_p = &((ഘടന sockaddr_in *)ai->ai_addr)->
			    sin_port;
			നിർത്തുക;
		അവസ്ഥ AF_INET6:
			lport_p = &((ഘടന sockaddr_in6 *)ai->ai_addr)->
			    sin6_port;
			നിർത്തുക;
		സ്ഥിരസ്ഥിതി:
			തുടരുക;
		}
		/*
		 * If allocating a port for -R forwards, then use the
		 * same port for all address families.
		 */
		എങ്കിൽ (type == SSH_CHANNEL_RPORT_LISTENER &&
		    fwd->listen_port == 0 && allocated_listen_port != ശൂന്യ &&
		    *allocated_listen_port > 0)
			*lport_p = htons(*allocated_listen_port);

		എങ്കിൽ (getnameinfo(ai->ai_addr, ai->ai_addrlen, ntop, വലുപ്പം(ntop),
		    strport, വലുപ്പം(strport),
		    NI_NUMERICHOST|NI_NUMERICSERV) != 0) {
			error_f("getnameinfo failed");
			തുടരുക;
		}
		/* Create a port to listen for the host. */
		sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		എങ്കിൽ (sock == -1) {
			/* this is no error since kernel may not support ipv6 */
			verbose("socket [%s]:%s: %.100s", ntop, strport,
			    strerror(errno));
			തുടരുക;
		}

		set_reuseaddr(sock);
		എങ്കിൽ (ai->ai_family == AF_INET6)
			sock_set_v6only(sock);

		debug("Local forwarding listening on %s port %s.",
		    ntop, strport);

		/* Bind the socket to the address. */
		എങ്കിൽ (bind(sock, ai->ai_addr, ai->ai_addrlen) == -1) {
			/*
			 * address can be in if use ipv6 address is
			 * already bound
			 */
			എങ്കിൽ (!ai->ai_next)
				error("bind [%s]:%s: %.100s",
				    ntop, strport, strerror(errno));
			അല്ലെങ്കിൽ
				verbose("bind [%s]:%s: %.100s",
				    ntop, strport, strerror(errno));

			close(sock);
			തുടരുക;
		}
		/* Start listening for connections on the socket. */
		എങ്കിൽ (listen(sock, SSH_LISTEN_BACKLOG) == -1) {
			error("listen [%s]:%s: %.100s", ntop, strport,
			    strerror(errno));
			close(sock);
			തുടരുക;
		}

		/*
		 * fwd->listen_port == 0 requests a dynamically allocated port -
		 * record what we got.
		 */
		എങ്കിൽ (type == SSH_CHANNEL_RPORT_LISTENER &&
		    fwd->listen_port == 0 &&
		    allocated_listen_port != ശൂന്യ &&
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
		c->listening_addr = addr == ശൂന്യ ? ശൂന്യ : xstrdup(addr);
		എങ്കിൽ (fwd->listen_port == 0 && allocated_listen_port != ശൂന്യ &&
		    !(ssh->compat & SSH_BUG_DYNAMIC_RPORT))
			c->listening_port = *allocated_listen_port;
		അല്ലെങ്കിൽ
			c->listening_port = fwd->listen_port;
		success = 1;
	}
	എങ്കിൽ (success == 0)
		error_f("cannot listen to port: %d", fwd->listen_port);
	freeaddrinfo(aitop);
	തിരികെ success;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
channel_setup_fwd_listener_streamlocal(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ type,
    ഘടന Forward *fwd, ഘടന ForwardOptions *fwd_opts)
{
	ഘടന sockaddr_un sunaddr;
	സ്ഥിരം അക്ഷരം *path;
	Channel *c;
	പൂർണ്ണസംഖ്യ port, sock;
	mode_t omask;

	തിരഞ്ഞെടുപ്പ് (type) {
	അവസ്ഥ SSH_CHANNEL_UNIX_LISTENER:
		എങ്കിൽ (fwd->connect_path != ശൂന്യ) {
			എങ്കിൽ (strlen(fwd->connect_path) > വലുപ്പം(sunaddr.sun_path)) {
				error("Local connecting path too long: %s",
				    fwd->connect_path);
				തിരികെ 0;
			}
			path = fwd->connect_path;
			port = PORT_STREAMLOCAL;
		} അല്ലെങ്കിൽ {
			എങ്കിൽ (fwd->connect_host == ശൂന്യ) {
				error("No forward host name.");
				തിരികെ 0;
			}
			എങ്കിൽ (strlen(fwd->connect_host) >= NI_MAXHOST) {
				error("Forward host name too long.");
				തിരികെ 0;
			}
			path = fwd->connect_host;
			port = fwd->connect_port;
		}
		നിർത്തുക;
	അവസ്ഥ SSH_CHANNEL_RUNIX_LISTENER:
		path = fwd->listen_path;
		port = PORT_STREAMLOCAL;
		നിർത്തുക;
	സ്ഥിരസ്ഥിതി:
		error_f("unexpected channel type %d", type);
		തിരികെ 0;
	}

	എങ്കിൽ (fwd->listen_path == ശൂന്യ) {
		error("No forward path name.");
		തിരികെ 0;
	}
	എങ്കിൽ (strlen(fwd->listen_path) > വലുപ്പം(sunaddr.sun_path)) {
		error("Local listening path too long: %s", fwd->listen_path);
		തിരികെ 0;
	}

	debug3_f("type %d path %s", type, fwd->listen_path);

	/* Start a Unix domain listener. */
	omask = umask(fwd_opts->streamlocal_bind_mask);
	sock = unix_listener(fwd->listen_path, SSH_LISTEN_BACKLOG,
	    fwd_opts->streamlocal_bind_unlink);
	umask(omask);
	എങ്കിൽ (sock < 0)
		തിരികെ 0;

	debug("Local forwarding listening on path %s.", fwd->listen_path);

	/* Allocate a channel number for the socket. */
	c = channel_new(ssh, "unix-listener", type, sock, sock, -1,
	    CHAN_TCP_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT,
	    0, "unix listener", 1);
	c->path = xstrdup(path);
	c->host_port = port;
	c->listening_port = PORT_STREAMLOCAL;
	c->listening_addr = xstrdup(fwd->listen_path);
	തിരികെ 1;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
channel_cancel_rport_listener_tcpip(ഘടന ssh *ssh,
    സ്ഥിരം അക്ഷരം *host, u_short port)
{
	u_int i;
	പൂർണ്ണസംഖ്യ found = 0;

	വേണ്ടി (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		Channel *c = ssh->chanctxt->channels[i];
		എങ്കിൽ (c == ശൂന്യ || c->type != SSH_CHANNEL_RPORT_LISTENER)
			തുടരുക;
		എങ്കിൽ (strcmp(c->path, host) == 0 && c->listening_port == port) {
			debug2_f("close channel %d", i);
			channel_free(ssh, c);
			found = 1;
		}
	}

	തിരികെ found;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
channel_cancel_rport_listener_streamlocal(ഘടന ssh *ssh, സ്ഥിരം അക്ഷരം *path)
{
	u_int i;
	പൂർണ്ണസംഖ്യ found = 0;

	വേണ്ടി (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		Channel *c = ssh->chanctxt->channels[i];
		എങ്കിൽ (c == ശൂന്യ || c->type != SSH_CHANNEL_RUNIX_LISTENER)
			തുടരുക;
		എങ്കിൽ (c->path == ശൂന്യ)
			തുടരുക;
		എങ്കിൽ (strcmp(c->path, path) == 0) {
			debug2_f("close channel %d", i);
			channel_free(ssh, c);
			found = 1;
		}
	}

	തിരികെ found;
}

പൂർണ്ണസംഖ്യ
channel_cancel_rport_listener(ഘടന ssh *ssh, ഘടന Forward *fwd)
{
	എങ്കിൽ (fwd->listen_path != ശൂന്യ) {
		തിരികെ channel_cancel_rport_listener_streamlocal(ssh,
		    fwd->listen_path);
	} അല്ലെങ്കിൽ {
		തിരികെ channel_cancel_rport_listener_tcpip(ssh,
		    fwd->listen_host, fwd->listen_port);
	}
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
channel_cancel_lport_listener_tcpip(ഘടന ssh *ssh,
    സ്ഥിരം അക്ഷരം *lhost, u_short lport, പൂർണ്ണസംഖ്യ cport,
    ഘടന ForwardOptions *fwd_opts)
{
	u_int i;
	പൂർണ്ണസംഖ്യ found = 0;
	സ്ഥിരം അക്ഷരം *addr = channel_fwd_bind_addr(ssh, lhost, ശൂന്യ, 1, fwd_opts);

	വേണ്ടി (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		Channel *c = ssh->chanctxt->channels[i];
		എങ്കിൽ (c == ശൂന്യ || c->type != SSH_CHANNEL_PORT_LISTENER)
			തുടരുക;
		എങ്കിൽ (c->listening_port != lport)
			തുടരുക;
		എങ്കിൽ (cport == CHANNEL_CANCEL_PORT_STATIC) {
			/* skip dynamic forwardings */
			എങ്കിൽ (c->host_port == 0)
				തുടരുക;
		} അല്ലെങ്കിൽ {
			എങ്കിൽ (c->host_port != cport)
				തുടരുക;
		}
		എങ്കിൽ ((c->listening_addr == ശൂന്യ && addr != ശൂന്യ) ||
		    (c->listening_addr != ശൂന്യ && addr == ശൂന്യ))
			തുടരുക;
		എങ്കിൽ (addr == ശൂന്യ || strcmp(c->listening_addr, addr) == 0) {
			debug2_f("close channel %d", i);
			channel_free(ssh, c);
			found = 1;
		}
	}

	തിരികെ found;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
channel_cancel_lport_listener_streamlocal(ഘടന ssh *ssh, സ്ഥിരം അക്ഷരം *path)
{
	u_int i;
	പൂർണ്ണസംഖ്യ found = 0;

	എങ്കിൽ (path == ശൂന്യ) {
		error_f("no path specified.");
		തിരികെ 0;
	}

	വേണ്ടി (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		Channel *c = ssh->chanctxt->channels[i];
		എങ്കിൽ (c == ശൂന്യ || c->type != SSH_CHANNEL_UNIX_LISTENER)
			തുടരുക;
		എങ്കിൽ (c->listening_addr == ശൂന്യ)
			തുടരുക;
		എങ്കിൽ (strcmp(c->listening_addr, path) == 0) {
			debug2_f("close channel %d", i);
			channel_free(ssh, c);
			found = 1;
		}
	}

	തിരികെ found;
}

പൂർണ്ണസംഖ്യ
channel_cancel_lport_listener(ഘടന ssh *ssh,
    ഘടന Forward *fwd, പൂർണ്ണസംഖ്യ cport, ഘടന ForwardOptions *fwd_opts)
{
	എങ്കിൽ (fwd->listen_path != ശൂന്യ) {
		തിരികെ channel_cancel_lport_listener_streamlocal(ssh,
		    fwd->listen_path);
	} അല്ലെങ്കിൽ {
		തിരികെ channel_cancel_lport_listener_tcpip(ssh,
		    fwd->listen_host, fwd->listen_port, cport, fwd_opts);
	}
}

/* protocol local port fwd, used by ssh */
പൂർണ്ണസംഖ്യ
channel_setup_local_fwd_listener(ഘടന ssh *ssh,
    ഘടന Forward *fwd, ഘടന ForwardOptions *fwd_opts)
{
	എങ്കിൽ (fwd->listen_path != ശൂന്യ) {
		തിരികെ channel_setup_fwd_listener_streamlocal(ssh,
		    SSH_CHANNEL_UNIX_LISTENER, fwd, fwd_opts);
	} അല്ലെങ്കിൽ {
		തിരികെ channel_setup_fwd_listener_tcpip(ssh,
		    SSH_CHANNEL_PORT_LISTENER, fwd, ശൂന്യ, fwd_opts);
	}
}

/* Matches a remote forwarding permission against a requested forwarding */
സ്ഥിതം പൂർണ്ണസംഖ്യ
remote_open_match(ഘടന permission *allowed_open, ഘടന Forward *fwd)
{
	പൂർണ്ണസംഖ്യ ret;
	അക്ഷരം *lhost;

	/* XXX add ACLs for streamlocal */
	എങ്കിൽ (fwd->listen_path != ശൂന്യ)
		തിരികെ 1;

	എങ്കിൽ (fwd->listen_host == ശൂന്യ || allowed_open->listen_host == ശൂന്യ)
		തിരികെ 0;

	എങ്കിൽ (allowed_open->listen_port != FWD_PERMIT_ANY_PORT &&
	    allowed_open->listen_port != fwd->listen_port)
		തിരികെ 0;

	/* Match hostnames case-insensitively */
	lhost = xstrdup(fwd->listen_host);
	lowercase(lhost);
	ret = match_pattern(lhost, allowed_open->listen_host);
	സ്വതന്ത്രം(lhost);

	തിരികെ ret;
}

/* Checks whether a requested remote forwarding is permitted */
സ്ഥിതം പൂർണ്ണസംഖ്യ
check_rfwd_permission(ഘടന ssh *ssh, ഘടന Forward *fwd)
{
	ഘടന ssh_channels *sc = ssh->chanctxt;
	ഘടന permission_set *pset = &sc->remote_perms;
	u_int i, permit, permit_adm = 1;
	ഘടന permission *perm;

#ifdef SKIP_PRIVDROP
	എങ്കിൽ (fwd->listen_path != ശൂന്യ)
		തിരികെ 0;
	എങ്കിൽ (fwd->listen_port != 0 && fwd->listen_port < 1024)
		തിരികെ 0;
#endif

	/* XXX apply GatewayPorts override before checking? */

	permit = pset->all_permitted;
	എങ്കിൽ (!permit) {
		വേണ്ടി (i = 0; i < pset->അക്കം_permitted_user; i++) {
			perm = &pset->permitted_user[i];
			എങ്കിൽ (remote_open_match(perm, fwd)) {
				permit = 1;
				നിർത്തുക;
			}
		}
	}

	എങ്കിൽ (pset->അക്കം_permitted_admin > 0) {
		permit_adm = 0;
		വേണ്ടി (i = 0; i < pset->അക്കം_permitted_admin; i++) {
			perm = &pset->permitted_admin[i];
			എങ്കിൽ (remote_open_match(perm, fwd)) {
				permit_adm = 1;
				നിർത്തുക;
			}
		}
	}

	തിരികെ permit && permit_adm;
}

/* protocol v2 remote port fwd, used by sshd */
പൂർണ്ണസംഖ്യ
channel_setup_remote_fwd_listener(ഘടന ssh *ssh, ഘടന Forward *fwd,
    പൂർണ്ണസംഖ്യ *allocated_listen_port, ഘടന ForwardOptions *fwd_opts)
{
	എങ്കിൽ (!check_rfwd_permission(ssh, fwd)) {
		ssh_packet_send_debug(ssh, "port forwarding refused");
		എങ്കിൽ (fwd->listen_path != ശൂന്യ)
			/* XXX always allowed, see remote_open_match() */
			logit("Received request from %.100s port %d to "
			    "remote forward to path \"%.100s\", "
			    "but the request was denied.",
			    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
			    fwd->listen_path);
		അല്ലെങ്കിൽ എങ്കിൽ(fwd->listen_host != ശൂന്യ)
			logit("Received request from %.100s port %d to "
			    "remote forward to host %.100s port %d, "
			    "but the request was denied.",
			    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
			    fwd->listen_host, fwd->listen_port );
		അല്ലെങ്കിൽ
			logit("Received request from %.100s port %d to remote "
			    "forward, but the request was denied.",
			    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
		തിരികെ 0;
	}
	എങ്കിൽ (fwd->listen_path != ശൂന്യ) {
		തിരികെ channel_setup_fwd_listener_streamlocal(ssh,
		    SSH_CHANNEL_RUNIX_LISTENER, fwd, fwd_opts);
	} അല്ലെങ്കിൽ {
		തിരികെ channel_setup_fwd_listener_tcpip(ssh,
		    SSH_CHANNEL_RPORT_LISTENER, fwd, allocated_listen_port,
		    fwd_opts);
	}
}

/*
 * Translate the requested rfwd listen host to something usable for
 * this server.
 */
സ്ഥിതം സ്ഥിരം അക്ഷരം *
channel_rfwd_bind_host(സ്ഥിരം അക്ഷരം *listen_host)
{
	എങ്കിൽ (listen_host == ശൂന്യ) {
		തിരികെ "localhost";
	} അല്ലെങ്കിൽ എങ്കിൽ (*listen_host == '\0' || strcmp(listen_host, "*") == 0) {
		തിരികെ "";
	} അല്ലെങ്കിൽ
		തിരികെ listen_host;
}

/*
 * Initiate forwarding of connections to port "port" on remote host through
 * the secure channel to host:port from local side.
 * Returns handle (index) for updating the dynamic listen port with
 * channel_update_permission().
 */
പൂർണ്ണസംഖ്യ
channel_request_remote_forwarding(ഘടന ssh *ssh, ഘടന Forward *fwd)
{
	പൂർണ്ണസംഖ്യ r, success = 0, idx = -1;
	സ്ഥിരം അക്ഷരം *host_to_connect, *listen_host, *listen_path;
	പൂർണ്ണസംഖ്യ port_to_connect, listen_port;

	/* Send the forward request to the remote side. */
	എങ്കിൽ (fwd->listen_path != ശൂന്യ) {
		എങ്കിൽ ((r = sshpkt_start(ssh, SSH2_സന്ദേശം_GLOBAL_REQUEST)) != 0 ||
		    (r = sshpkt_put_cstring(ssh,
		    "streamlocal-forward@openssh.com")) != 0 ||
		    (r = sshpkt_put_u8(ssh, 1)) != 0 || /* want reply */
		    (r = sshpkt_put_cstring(ssh, fwd->listen_path)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			fatal_fr(r, "request streamlocal");
	} അല്ലെങ്കിൽ {
		എങ്കിൽ ((r = sshpkt_start(ssh, SSH2_സന്ദേശം_GLOBAL_REQUEST)) != 0 ||
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
	എങ്കിൽ (success) {
		/* Record that connection to this host/port is permitted. */
		host_to_connect = listen_host = listen_path = ശൂന്യ;
		port_to_connect = listen_port = 0;
		എങ്കിൽ (fwd->connect_path != ശൂന്യ) {
			host_to_connect = fwd->connect_path;
			port_to_connect = PORT_STREAMLOCAL;
		} അല്ലെങ്കിൽ {
			host_to_connect = fwd->connect_host;
			port_to_connect = fwd->connect_port;
		}
		എങ്കിൽ (fwd->listen_path != ശൂന്യ) {
			listen_path = fwd->listen_path;
			listen_port = PORT_STREAMLOCAL;
		} അല്ലെങ്കിൽ {
			listen_host = fwd->listen_host;
			listen_port = fwd->listen_port;
		}
		idx = permission_set_add(ssh, FORWARD_USER, FORWARD_LOCAL,
		    host_to_connect, port_to_connect,
		    listen_host, listen_path, listen_port, ശൂന്യ);
	}
	തിരികെ idx;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
open_match(ഘടന permission *allowed_open, സ്ഥിരം അക്ഷരം *requestedhost,
    പൂർണ്ണസംഖ്യ requestedport)
{
	എങ്കിൽ (allowed_open->host_to_connect == ശൂന്യ)
		തിരികെ 0;
	എങ്കിൽ (allowed_open->port_to_connect != FWD_PERMIT_ANY_PORT &&
	    allowed_open->port_to_connect != requestedport)
		തിരികെ 0;
	എങ്കിൽ (strcmp(allowed_open->host_to_connect, FWD_PERMIT_ANY_HOST) != 0 &&
	    strcmp(allowed_open->host_to_connect, requestedhost) != 0)
		തിരികെ 0;
	തിരികെ 1;
}

/*
 * Note that in the listen host/port case
 * we don't support FWD_PERMIT_ANY_PORT and
 * need to translate between the configured-host (listen_host)
 * and what we've sent to the remote server (channel_rfwd_bind_host)
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
open_listen_match_tcpip(ഘടന permission *allowed_open,
    സ്ഥിരം അക്ഷരം *requestedhost, u_short requestedport, പൂർണ്ണസംഖ്യ translate)
{
	സ്ഥിരം അക്ഷരം *allowed_host;

	എങ്കിൽ (allowed_open->host_to_connect == ശൂന്യ)
		തിരികെ 0;
	എങ്കിൽ (allowed_open->listen_port != requestedport)
		തിരികെ 0;
	എങ്കിൽ (!translate && allowed_open->listen_host == ശൂന്യ &&
	    requestedhost == ശൂന്യ)
		തിരികെ 1;
	allowed_host = translate ?
	    channel_rfwd_bind_host(allowed_open->listen_host) :
	    allowed_open->listen_host;
	എങ്കിൽ (allowed_host == ശൂന്യ || requestedhost == ശൂന്യ ||
	    strcmp(allowed_host, requestedhost) != 0)
		തിരികെ 0;
	തിരികെ 1;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
open_listen_match_streamlocal(ഘടന permission *allowed_open,
    സ്ഥിരം അക്ഷരം *requestedpath)
{
	എങ്കിൽ (allowed_open->host_to_connect == ശൂന്യ)
		തിരികെ 0;
	എങ്കിൽ (allowed_open->listen_port != PORT_STREAMLOCAL)
		തിരികെ 0;
	എങ്കിൽ (allowed_open->listen_path == ശൂന്യ ||
	    strcmp(allowed_open->listen_path, requestedpath) != 0)
		തിരികെ 0;
	തിരികെ 1;
}

/*
 * Request cancellation of remote forwarding of connection host:port from
 * local side.
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
channel_request_rforward_cancel_tcpip(ഘടന ssh *ssh,
    സ്ഥിരം അക്ഷരം *host, u_short port)
{
	ഘടന ssh_channels *sc = ssh->chanctxt;
	ഘടന permission_set *pset = &sc->local_perms;
	പൂർണ്ണസംഖ്യ r;
	u_int i;
	ഘടന permission *perm = ശൂന്യ;

	വേണ്ടി (i = 0; i < pset->അക്കം_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		എങ്കിൽ (open_listen_match_tcpip(perm, host, port, 0))
			നിർത്തുക;
		perm = ശൂന്യ;
	}
	എങ്കിൽ (perm == ശൂന്യ) {
		debug_f("requested forward not found");
		തിരികെ -1;
	}
	എങ്കിൽ ((r = sshpkt_start(ssh, SSH2_സന്ദേശം_GLOBAL_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "cancel-tcpip-forward")) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 || /* want reply */
	    (r = sshpkt_put_cstring(ssh, channel_rfwd_bind_host(host))) != 0 ||
	    (r = sshpkt_put_u32(ssh, port)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send cancel");

	fwd_perm_clear(perm); /* unregister */

	തിരികെ 0;
}

/*
 * Request cancellation of remote forwarding of Unix domain socket
 * path from local side.
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
channel_request_rforward_cancel_streamlocal(ഘടന ssh *ssh, സ്ഥിരം അക്ഷരം *path)
{
	ഘടന ssh_channels *sc = ssh->chanctxt;
	ഘടന permission_set *pset = &sc->local_perms;
	പൂർണ്ണസംഖ്യ r;
	u_int i;
	ഘടന permission *perm = ശൂന്യ;

	വേണ്ടി (i = 0; i < pset->അക്കം_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		എങ്കിൽ (open_listen_match_streamlocal(perm, path))
			നിർത്തുക;
		perm = ശൂന്യ;
	}
	എങ്കിൽ (perm == ശൂന്യ) {
		debug_f("requested forward not found");
		തിരികെ -1;
	}
	എങ്കിൽ ((r = sshpkt_start(ssh, SSH2_സന്ദേശം_GLOBAL_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh,
	    "cancel-streamlocal-forward@openssh.com")) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 || /* want reply */
	    (r = sshpkt_put_cstring(ssh, path)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send cancel");

	fwd_perm_clear(perm); /* unregister */

	തിരികെ 0;
}

/*
 * Request cancellation of remote forwarding of a connection from local side.
 */
പൂർണ്ണസംഖ്യ
channel_request_rforward_cancel(ഘടന ssh *ssh, ഘടന Forward *fwd)
{
	എങ്കിൽ (fwd->listen_path != ശൂന്യ) {
		തിരികെ channel_request_rforward_cancel_streamlocal(ssh,
		    fwd->listen_path);
	} അല്ലെങ്കിൽ {
		തിരികെ channel_request_rforward_cancel_tcpip(ssh,
		    fwd->listen_host,
		    fwd->listen_port ? fwd->listen_port : fwd->allocated_port);
	}
}

/*
 * Permits opening to any host/port if permitted_user[] is empty.  This is
 * usually called by the server, because the user could connect to any port
 * anyway, and the server has no way to know but to trust the client anyway.
 */
ശൂന്യം
channel_permit_all(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ where)
{
	ഘടന permission_set *pset = permission_set_get(ssh, where);

	എങ്കിൽ (pset->അക്കം_permitted_user == 0)
		pset->all_permitted = 1;
}

/*
 * Permit the specified host/port for forwarding.
 */
ശൂന്യം
channel_add_permission(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ who, പൂർണ്ണസംഖ്യ where,
    അക്ഷരം *host, പൂർണ്ണസംഖ്യ port)
{
	പൂർണ്ണസംഖ്യ local = where == FORWARD_LOCAL;
	ഘടന permission_set *pset = permission_set_get(ssh, where);

	debug("allow %s forwarding to host %s port %d",
	    fwd_ident(who, where), host, port);
	/*
	 * Remote forwards set listen_host/port, local forwards set
	 * host/port_to_connect.
	 */
	permission_set_add(ssh, who, where,
	    local ? host : ശൂന്യ, local ? port : 0,
	    local ? ശൂന്യ : host, ശൂന്യ, local ? 0 : port, ശൂന്യ);
	pset->all_permitted = 0;
}

/*
 * Administratively disable forwarding.
 */
ശൂന്യം
channel_disable_admin(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ where)
{
	channel_clear_permission(ssh, FORWARD_ADM, where);
	permission_set_add(ssh, FORWARD_ADM, where,
	    ശൂന്യ, 0, ശൂന്യ, ശൂന്യ, 0, ശൂന്യ);
}

/*
 * Clear a list of permitted opens.
 */
ശൂന്യം
channel_clear_permission(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ who, പൂർണ്ണസംഖ്യ where)
{
	ഘടന permission **permp;
	u_int i, *npermp;

	permission_set_get_array(ssh, who, where, &permp, &npermp);
	വേണ്ടി (i = 0; i < *npermp; i++)
		fwd_perm_clear((*permp) + i);
	സ്വതന്ത്രം(*permp);
	*permp = ശൂന്യ;
	*npermp = 0;
}

/*
 * Update the listen port for a dynamic remote forward, after
 * the actual 'newport' has been allocated. If 'newport' < 0 is
 * passed then they entry will be invalidated.
 */
ശൂന്യം
channel_update_permission(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ idx, പൂർണ്ണസംഖ്യ newport)
{
	ഘടന permission_set *pset = &ssh->chanctxt->local_perms;

	എങ്കിൽ (idx < 0 || (u_int)idx >= pset->അക്കം_permitted_user) {
		debug_f("index out of range: %d num_permitted_user %d",
		    idx, pset->അക്കം_permitted_user);
		തിരികെ;
	}
	debug("%s allowed port %d for forwarding to host %s port %d",
	    newport > 0 ? "Updating" : "Removing",
	    newport,
	    pset->permitted_user[idx].host_to_connect,
	    pset->permitted_user[idx].port_to_connect);
	എങ്കിൽ (newport <= 0)
		fwd_perm_clear(&pset->permitted_user[idx]);
	അല്ലെങ്കിൽ {
		pset->permitted_user[idx].listen_port =
		    (ssh->compat & SSH_BUG_DYNAMIC_RPORT) ? 0 : newport;
	}
}

/* Try to start non-blocking connect to next host in cctx list */
സ്ഥിതം പൂർണ്ണസംഖ്യ
connect_next(ഘടന ssh *ssh, ഘടന channel_connect *cctx)
{
	പൂർണ്ണസംഖ്യ sock, sock_is_network, saved_errno;
	ഘടന sockaddr_un *sunaddr;
	അക്ഷരം ntop[NI_MAXHOST];
	അക്ഷരം strport[MAXIMUM(NI_MAXSERV, വലുപ്പം(sunaddr->sun_path))];

	വേണ്ടി (; cctx->ai; cctx->ai = cctx->ai->ai_next) {
		sock_is_network = 0;
		തിരഞ്ഞെടുപ്പ് (cctx->ai->ai_family) {
		അവസ്ഥ AF_UNIX:
			/* unix:pathname instead of host:port */
			sunaddr = (ഘടന sockaddr_un *)cctx->ai->ai_addr;
			strlcpy(ntop, "unix", വലുപ്പം(ntop));
			strlcpy(strport, sunaddr->sun_path, വലുപ്പം(strport));
			നിർത്തുക;
		അവസ്ഥ AF_INET:
		അവസ്ഥ AF_INET6:
			എങ്കിൽ (getnameinfo(cctx->ai->ai_addr, cctx->ai->ai_addrlen,
			    ntop, വലുപ്പം(ntop), strport, വലുപ്പം(strport),
			    NI_NUMERICHOST|NI_NUMERICSERV) != 0) {
				error_f("getnameinfo failed");
				തുടരുക;
			}
			sock_is_network = 1;
			നിർത്തുക;
		സ്ഥിരസ്ഥിതി:
			തുടരുക;
		}
		debug_f("start for host %.100s ([%.100s]:%s)",
		    cctx->host, ntop, strport);
		എങ്കിൽ ((sock = socket(cctx->ai->ai_family, cctx->ai->ai_socktype,
		    cctx->ai->ai_protocol)) == -1) {
			എങ്കിൽ (cctx->ai->ai_next == ശൂന്യ)
				error("socket: %.100s", strerror(errno));
			അല്ലെങ്കിൽ
				verbose("socket: %.100s", strerror(errno));
			തുടരുക;
		}
		എങ്കിൽ (set_nonblock(sock) == -1)
			fatal_f("set_nonblock(%d)", sock);
		എങ്കിൽ (sock_is_network && ssh->chanctxt->want_tcp_keepalive)
			set_keepalive(sock); /* logs errors */
		എങ്കിൽ (connect(sock, cctx->ai->ai_addr,
		    cctx->ai->ai_addrlen) == -1 && errno != EINPROGRESS) {
			debug_f("host %.100s ([%.100s]:%s): %.100s",
			    cctx->host, ntop, strport, strerror(errno));
			saved_errno = errno;
			close(sock);
			errno = saved_errno;
			തുടരുക;	/* fail -- try next */
		}
		എങ്കിൽ (cctx->ai->ai_family != AF_UNIX)
			set_nodelay(sock);
		debug_f("connect host %.100s ([%.100s]:%s) in progress, fd=%d",
		    cctx->host, ntop, strport, sock);
		cctx->ai = cctx->ai->ai_next;
		തിരികെ sock;
	}
	തിരികെ -1;
}

/*
 * Return connecting socket to remote host:port or local socket path,
 * passing back the failure reason if appropriate.
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
connect_to_helper(ഘടന ssh *ssh, സ്ഥിരം അക്ഷരം *name, പൂർണ്ണസംഖ്യ port, പൂർണ്ണസംഖ്യ socktype,
    അക്ഷരം *ctype, അക്ഷരം *rname, ഘടന channel_connect *cctx,
    പൂർണ്ണസംഖ്യ *reason, സ്ഥിരം അക്ഷരം **errmsg)
{
	ഘടന addrinfo hints;
	പൂർണ്ണസംഖ്യ gaierr;
	പൂർണ്ണസംഖ്യ sock = -1;
	അക്ഷരം strport[NI_MAXSERV];

	എങ്കിൽ (port == PORT_STREAMLOCAL) {
		ഘടന sockaddr_un *sunaddr;
		ഘടന addrinfo *ai;

		എങ്കിൽ (strlen(name) > വലുപ്പം(sunaddr->sun_path)) {
			error("%.100s: %.100s", name, strerror(ENAMETOOLONG));
			തിരികെ -1;
		}

		/*
		 * Fake up a struct addrinfo for AF_UNIX connections.
		 * free_connect_ctx() must check ai_family
		 * and use free() not freeaddrinfo() for AF_UNIX.
		 */
		ai = xcalloc(1, വലുപ്പം(*ai) + വലുപ്പം(*sunaddr));
		ai->ai_addr = (ഘടന sockaddr *)(ai + 1);
		ai->ai_addrlen = വലുപ്പം(*sunaddr);
		ai->ai_family = AF_UNIX;
		ai->ai_socktype = socktype;
		ai->ai_protocol = PF_UNSPEC;
		sunaddr = (ഘടന sockaddr_un *)ai->ai_addr;
		sunaddr->sun_family = AF_UNIX;
		strlcpy(sunaddr->sun_path, name, വലുപ്പം(sunaddr->sun_path));
		cctx->aitop = ai;
	} അല്ലെങ്കിൽ {
		memset(&hints, 0, വലുപ്പം(hints));
		hints.ai_family = ssh->chanctxt->IPv4or6;
		hints.ai_socktype = socktype;
		snprintf(strport, വലുപ്പം strport, "%d", port);
		എങ്കിൽ ((gaierr = getaddrinfo(name, strport, &hints, &cctx->aitop))
		    != 0) {
			എങ്കിൽ (errmsg != ശൂന്യ)
				*errmsg = ssh_gai_strerror(gaierr);
			എങ്കിൽ (reason != ശൂന്യ)
				*reason = SSH2_OPEN_CONNECT_FAILED;
			error("connect_to %.100s: unknown host (%s)", name,
			    ssh_gai_strerror(gaierr));
			തിരികെ -1;
		}
	}

	cctx->host = xstrdup(name);
	cctx->port = port;
	cctx->ai = cctx->aitop;

	എങ്കിൽ ((sock = connect_next(ssh, cctx)) == -1) {
		error("connect to %.100s port %d failed: %s",
		    name, port, strerror(errno));
		തിരികെ -1;
	}

	തിരികെ sock;
}

/* Return CONNECTING channel to remote host:port or local socket path */
സ്ഥിതം Channel *
connect_to(ഘടന ssh *ssh, സ്ഥിരം അക്ഷരം *host, പൂർണ്ണസംഖ്യ port,
    അക്ഷരം *ctype, അക്ഷരം *rname)
{
	ഘടന channel_connect cctx;
	Channel *c;
	പൂർണ്ണസംഖ്യ sock;

	memset(&cctx, 0, വലുപ്പം(cctx));
	sock = connect_to_helper(ssh, host, port, SOCK_STREAM, ctype, rname,
	    &cctx, ശൂന്യ, ശൂന്യ);
	എങ്കിൽ (sock == -1) {
		free_connect_ctx(&cctx);
		തിരികെ ശൂന്യ;
	}
	c = channel_new(ssh, ctype, SSH_CHANNEL_CONNECTING, sock, sock, -1,
	    CHAN_TCP_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, rname, 1);
	c->host_port = port;
	c->path = xstrdup(host);
	c->connect_ctx = xmalloc(വലുപ്പം(cctx));
	memcpy(c->connect_ctx, &cctx, വലുപ്പം(cctx));

	തിരികെ c;
}

/*
 * returns either the newly connected channel or the downstream channel
 * that needs to deal with this connection.
 */
Channel *
channel_connect_by_listen_address(ഘടന ssh *ssh, സ്ഥിരം അക്ഷരം *listen_host,
    u_short listen_port, അക്ഷരം *ctype, അക്ഷരം *rname)
{
	ഘടന ssh_channels *sc = ssh->chanctxt;
	ഘടന permission_set *pset = &sc->local_perms;
	u_int i;
	ഘടന permission *perm;

	വേണ്ടി (i = 0; i < pset->അക്കം_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		എങ്കിൽ (open_listen_match_tcpip(perm,
		    listen_host, listen_port, 1)) {
			എങ്കിൽ (perm->downstream)
				തിരികെ perm->downstream;
			എങ്കിൽ (perm->port_to_connect == 0)
				തിരികെ rdynamic_connect_prepare(ssh,
				    ctype, rname);
			തിരികെ connect_to(ssh,
			    perm->host_to_connect, perm->port_to_connect,
			    ctype, rname);
		}
	}
	error("WARNING: Server requests forwarding for unknown listen_port %d",
	    listen_port);
	തിരികെ ശൂന്യ;
}

Channel *
channel_connect_by_listen_path(ഘടന ssh *ssh, സ്ഥിരം അക്ഷരം *path,
    അക്ഷരം *ctype, അക്ഷരം *rname)
{
	ഘടന ssh_channels *sc = ssh->chanctxt;
	ഘടന permission_set *pset = &sc->local_perms;
	u_int i;
	ഘടന permission *perm;

	വേണ്ടി (i = 0; i < pset->അക്കം_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		എങ്കിൽ (open_listen_match_streamlocal(perm, path)) {
			തിരികെ connect_to(ssh,
			    perm->host_to_connect, perm->port_to_connect,
			    ctype, rname);
		}
	}
	error("WARNING: Server requests forwarding for unknown path %.100s",
	    path);
	തിരികെ ശൂന്യ;
}

/* Check if connecting to that port is permitted and connect. */
Channel *
channel_connect_to_port(ഘടന ssh *ssh, സ്ഥിരം അക്ഷരം *host, u_short port,
    അക്ഷരം *ctype, അക്ഷരം *rname, പൂർണ്ണസംഖ്യ *reason, സ്ഥിരം അക്ഷരം **errmsg)
{
	ഘടന ssh_channels *sc = ssh->chanctxt;
	ഘടന permission_set *pset = &sc->local_perms;
	ഘടന channel_connect cctx;
	Channel *c;
	u_int i, permit, permit_adm = 1;
	പൂർണ്ണസംഖ്യ sock;
	ഘടന permission *perm;

	permit = pset->all_permitted;
	എങ്കിൽ (!permit) {
		വേണ്ടി (i = 0; i < pset->അക്കം_permitted_user; i++) {
			perm = &pset->permitted_user[i];
			എങ്കിൽ (open_match(perm, host, port)) {
				permit = 1;
				നിർത്തുക;
			}
		}
	}

	എങ്കിൽ (pset->അക്കം_permitted_admin > 0) {
		permit_adm = 0;
		വേണ്ടി (i = 0; i < pset->അക്കം_permitted_admin; i++) {
			perm = &pset->permitted_admin[i];
			എങ്കിൽ (open_match(perm, host, port)) {
				permit_adm = 1;
				നിർത്തുക;
			}
		}
	}

	എങ്കിൽ (!permit || !permit_adm) {
		logit("Received request from %.100s port %d to connect to "
		    "host %.100s port %d, but the request was denied.",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh), host, port);
		എങ്കിൽ (reason != ശൂന്യ)
			*reason = SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED;
		തിരികെ ശൂന്യ;
	}

	memset(&cctx, 0, വലുപ്പം(cctx));
	sock = connect_to_helper(ssh, host, port, SOCK_STREAM, ctype, rname,
	    &cctx, reason, errmsg);
	എങ്കിൽ (sock == -1) {
		free_connect_ctx(&cctx);
		തിരികെ ശൂന്യ;
	}

	c = channel_new(ssh, ctype, SSH_CHANNEL_CONNECTING, sock, sock, -1,
	    CHAN_TCP_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, rname, 1);
	c->host_port = port;
	c->path = xstrdup(host);
	c->connect_ctx = xmalloc(വലുപ്പം(cctx));
	memcpy(c->connect_ctx, &cctx, വലുപ്പം(cctx));

	തിരികെ c;
}

/* Check if connecting to that path is permitted and connect. */
Channel *
channel_connect_to_path(ഘടന ssh *ssh, സ്ഥിരം അക്ഷരം *path,
    അക്ഷരം *ctype, അക്ഷരം *rname)
{
	ഘടന ssh_channels *sc = ssh->chanctxt;
	ഘടന permission_set *pset = &sc->local_perms;
	u_int i, permit, permit_adm = 1;
	ഘടന permission *perm;

	permit = pset->all_permitted;
	എങ്കിൽ (!permit) {
		വേണ്ടി (i = 0; i < pset->അക്കം_permitted_user; i++) {
			perm = &pset->permitted_user[i];
			എങ്കിൽ (open_match(perm, path, PORT_STREAMLOCAL)) {
				permit = 1;
				നിർത്തുക;
			}
		}
	}

	എങ്കിൽ (pset->അക്കം_permitted_admin > 0) {
		permit_adm = 0;
		വേണ്ടി (i = 0; i < pset->അക്കം_permitted_admin; i++) {
			perm = &pset->permitted_admin[i];
			എങ്കിൽ (open_match(perm, path, PORT_STREAMLOCAL)) {
				permit_adm = 1;
				നിർത്തുക;
			}
		}
	}

	എങ്കിൽ (!permit || !permit_adm) {
		logit("Received request to connect to path %.100s, "
		    "but the request was denied.", path);
		തിരികെ ശൂന്യ;
	}
	തിരികെ connect_to(ssh, path, PORT_STREAMLOCAL, ctype, rname);
}

ശൂന്യം
channel_send_window_changes(ഘടന ssh *ssh)
{
	ഘടന ssh_channels *sc = ssh->chanctxt;
	ഘടന winsize ws;
	പൂർണ്ണസംഖ്യ r;
	u_int i;

	വേണ്ടി (i = 0; i < sc->channels_alloc; i++) {
		എങ്കിൽ (sc->channels[i] == ശൂന്യ || !sc->channels[i]->client_tty ||
		    sc->channels[i]->type != SSH_CHANNEL_OPEN)
			തുടരുക;
		എങ്കിൽ (ioctl(sc->channels[i]->rfd, TIOCGWINSZ, &ws) == -1)
			തുടരുക;
		channel_request_start(ssh, i, "window-change", 0);
		എങ്കിൽ ((r = sshpkt_put_u32(ssh, (u_int)ws.ws_col)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_row)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_xpixel)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_ypixel)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "channel %u; send window-change", i);
	}
}

/* Return RDYNAMIC_OPEN channel: channel allows SOCKS, but is not connected */
സ്ഥിതം Channel *
rdynamic_connect_prepare(ഘടന ssh *ssh, അക്ഷരം *ctype, അക്ഷരം *rname)
{
	Channel *c;
	പൂർണ്ണസംഖ്യ r;

	c = channel_new(ssh, ctype, SSH_CHANNEL_RDYNAMIC_OPEN, -1, -1, -1,
	    CHAN_TCP_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, rname, 1);
	c->host_port = 0;
	c->path = ശൂന്യ;

	/*
	 * We need to open the channel before we have a FD,
	 * so that we can get SOCKS header from peer.
	 */
	എങ്കിൽ ((r = sshpkt_start(ssh, SSH2_സന്ദേശം_CHANNEL_OPEN_CONFIRMATION)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_window)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0)
		fatal_fr(r, "channel %i; confirm", c->self);
	തിരികെ c;
}

/* Return CONNECTING socket to remote host:port or local socket path */
സ്ഥിതം പൂർണ്ണസംഖ്യ
rdynamic_connect_finish(ഘടന ssh *ssh, Channel *c)
{
	ഘടന ssh_channels *sc = ssh->chanctxt;
	ഘടന permission_set *pset = &sc->local_perms;
	ഘടന permission *perm;
	ഘടന channel_connect cctx;
	u_int i, permit_adm = 1;
	പൂർണ്ണസംഖ്യ sock;

	എങ്കിൽ (pset->അക്കം_permitted_admin > 0) {
		permit_adm = 0;
		വേണ്ടി (i = 0; i < pset->അക്കം_permitted_admin; i++) {
			perm = &pset->permitted_admin[i];
			എങ്കിൽ (open_match(perm, c->path, c->host_port)) {
				permit_adm = 1;
				നിർത്തുക;
			}
		}
	}
	എങ്കിൽ (!permit_adm) {
		debug_f("requested forward not permitted");
		തിരികെ -1;
	}

	memset(&cctx, 0, വലുപ്പം(cctx));
	sock = connect_to_helper(ssh, c->path, c->host_port, SOCK_STREAM, ശൂന്യ,
	    ശൂന്യ, &cctx, ശൂന്യ, ശൂന്യ);
	എങ്കിൽ (sock == -1)
		free_connect_ctx(&cctx);
	അല്ലെങ്കിൽ {
		/* similar to SSH_CHANNEL_CONNECTING but we've already sent the open */
		c->type = SSH_CHANNEL_RDYNAMIC_FINISH;
		c->connect_ctx = xmalloc(വലുപ്പം(cctx));
		memcpy(c->connect_ctx, &cctx, വലുപ്പം(cctx));
		channel_register_fds(ssh, c, sock, sock, -1, 0, 1, 0);
	}
	തിരികെ sock;
}

/* -- X11 forwarding */

/*
 * Creates an internet domain socket for listening for X11 connections.
 * Returns 0 and a suitable display number for the DISPLAY variable
 * stored in display_numberp , or -1 if an error occurs.
 */
പൂർണ്ണസംഖ്യ
x11_create_display_inet(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ x11_display_offset,
    പൂർണ്ണസംഖ്യ x11_use_localhost, പൂർണ്ണസംഖ്യ single_connection,
    u_int *display_numberp, പൂർണ്ണസംഖ്യ **chanids)
{
	Channel *nc = ശൂന്യ;
	പൂർണ്ണസംഖ്യ display_സംഖ്യ, sock, port;
	ഘടന addrinfo hints, *ai, *aitop;
	അക്ഷരം strport[NI_MAXSERV];
	പൂർണ്ണസംഖ്യ gaierr, n, അക്കം_socks = 0, socks[അക്കം_SOCKS];

	എങ്കിൽ (chanids == ശൂന്യ || x11_display_offset < 0 ||
	    x11_display_offset > UINT16_MAX - X11_BASE_PORT - MAX_DISPLAYS)
		തിരികെ -1;

	വേണ്ടി (display_സംഖ്യ = x11_display_offset;
	    display_സംഖ്യ < x11_display_offset + MAX_DISPLAYS;
	    display_സംഖ്യ++) {
		port = X11_BASE_PORT + display_സംഖ്യ;
		memset(&hints, 0, വലുപ്പം(hints));
		hints.ai_family = ssh->chanctxt->IPv4or6;
		hints.ai_flags = x11_use_localhost ? 0: AI_PASSIVE;
		hints.ai_socktype = SOCK_STREAM;
		snprintf(strport, വലുപ്പം strport, "%d", port);
		എങ്കിൽ ((gaierr = getaddrinfo(ശൂന്യ, strport,
		    &hints, &aitop)) != 0) {
			error("getaddrinfo: %.100s", ssh_gai_strerror(gaierr));
			തിരികെ -1;
		}
		വേണ്ടി (ai = aitop; ai; ai = ai->ai_next) {
			എങ്കിൽ (ai->ai_family != AF_INET &&
			    ai->ai_family != AF_INET6)
				തുടരുക;
			sock = socket(ai->ai_family, ai->ai_socktype,
			    ai->ai_protocol);
			എങ്കിൽ (sock == -1) {
				എങ്കിൽ ((errno != EINVAL) && (errno != EAFNOSUPPORT)
#ifdef EPFNOSUPPORT
				    && (errno != EPFNOSUPPORT)
#endif 
				    ) {
					error("socket: %.100s", strerror(errno));
					freeaddrinfo(aitop);
					തിരികെ -1;
				} അല്ലെങ്കിൽ {
					debug("x11_create_display_inet: Socket family %d not supported",
						 ai->ai_family);
					തുടരുക;
				}
			}
			എങ്കിൽ (ai->ai_family == AF_INET6)
				sock_set_v6only(sock);
			എങ്കിൽ (x11_use_localhost)
				set_reuseaddr(sock);
			എങ്കിൽ (bind(sock, ai->ai_addr, ai->ai_addrlen) == -1) {
				debug2_f("bind port %d: %.100s", port,
				    strerror(errno));
				close(sock);
				വേണ്ടി (n = 0; n < അക്കം_socks; n++)
					close(socks[n]);
				അക്കം_socks = 0;
				നിർത്തുക;
			}
			socks[അക്കം_socks++] = sock;
			എങ്കിൽ (അക്കം_socks == അക്കം_SOCKS)
				നിർത്തുക;
		}
		freeaddrinfo(aitop);
		എങ്കിൽ (അക്കം_socks > 0)
			നിർത്തുക;
	}
	എങ്കിൽ (display_സംഖ്യ >= x11_display_offset + MAX_DISPLAYS) {
		error("Failed to allocate internet-domain X11 display socket.");
		തിരികെ -1;
	}
	/* Start listening for connections on the socket. */
	വേണ്ടി (n = 0; n < അക്കം_socks; n++) {
		sock = socks[n];
		എങ്കിൽ (listen(sock, SSH_LISTEN_BACKLOG) == -1) {
			error("listen: %.100s", strerror(errno));
			close(sock);
			തിരികെ -1;
		}
	}

	/* Allocate a channel for each socket. */
	*chanids = xcalloc(അക്കം_socks + 1, വലുപ്പം(**chanids));
	വേണ്ടി (n = 0; n < അക്കം_socks; n++) {
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
	*display_numberp = display_സംഖ്യ;
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
connect_local_xsocket_path(സ്ഥിരം അക്ഷരം *pathname)
{
	പൂർണ്ണസംഖ്യ sock;
	ഘടന sockaddr_un addr;

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	എങ്കിൽ (sock == -1) {
		error("socket: %.100s", strerror(errno));
		തിരികെ -1;
	}
	memset(&addr, 0, വലുപ്പം(addr));
	addr.sun_family = AF_UNIX;
	strlcpy(addr.sun_path, pathname, വലുപ്പം addr.sun_path);
	എങ്കിൽ (connect(sock, (ഘടന sockaddr *)&addr, വലുപ്പം(addr)) == 0)
		തിരികെ sock;
	close(sock);
	error("connect %.100s: %.100s", addr.sun_path, strerror(errno));
	തിരികെ -1;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
connect_local_xsocket(u_int dnr)
{
	അക്ഷരം buf[1024];
	snprintf(buf, വലുപ്പം buf, _PATH_UNIX_X, dnr);
	തിരികെ connect_local_xsocket_path(buf);
}

#ifdef __APPLE__
സ്ഥിതം പൂർണ്ണസംഖ്യ
is_path_to_xsocket(സ്ഥിരം അക്ഷരം *display, അക്ഷരം *path, size_t pathlen)
{
	ഘടന stat sbuf;

	എങ്കിൽ (strlcpy(path, display, pathlen) >= pathlen) {
		error_f("display path too long");
		തിരികെ 0;
	}
	എങ്കിൽ (display[0] != '/')
		തിരികെ 0;
	എങ്കിൽ (stat(path, &sbuf) == 0) {
		തിരികെ 1;
	} അല്ലെങ്കിൽ {
		അക്ഷരം *dot = strrchr(path, '.');
		എങ്കിൽ (dot != ശൂന്യ) {
			*dot = '\0';
			എങ്കിൽ (stat(path, &sbuf) == 0) {
				തിരികെ 1;
			}
		}
	}
	തിരികെ 0;
}
#endif

പൂർണ്ണസംഖ്യ
x11_connect_display(ഘടന ssh *ssh)
{
	u_int display_സംഖ്യ;
	സ്ഥിരം അക്ഷരം *display;
	അക്ഷരം buf[1024], *cp;
	ഘടന addrinfo hints, *ai, *aitop;
	അക്ഷരം strport[NI_MAXSERV];
	പൂർണ്ണസംഖ്യ gaierr, sock = 0;

	/* Try to open a socket for the local X server. */
	display = getenv("DISPLAY");
	എങ്കിൽ (!display) {
		error("DISPLAY not set.");
		തിരികെ -1;
	}
	/*
	 * Now we decode the value of the DISPLAY variable and make a
	 * connection to the real X server.
	 */

#ifdef __APPLE__
	/* Check if display is a path to a socket (as set by launchd). */
	{
		അക്ഷരം path[PATH_MAX];

		എങ്കിൽ (is_path_to_xsocket(display, path, വലുപ്പം(path))) {
			debug("x11_connect_display: $DISPLAY is launchd");

			/* Create a socket. */
			sock = connect_local_xsocket_path(path);
			എങ്കിൽ (sock < 0)
				തിരികെ -1;

			/* OK, we now have a connection to the display. */
			തിരികെ sock;
		}
	}
#endif
	/*
	 * Check if it is a unix domain socket.  Unix domain displays are in
	 * one of the following formats: unix:d[.s], :d[.s], ::d[.s]
	 */
	എങ്കിൽ (strncmp(display, "unix:", 5) == 0 ||
	    display[0] == ':') {
		/* Connect to the unix domain socket. */
		എങ്കിൽ (sscanf(strrchr(display, ':') + 1, "%u",
		    &display_സംഖ്യ) != 1) {
			error("Could not parse display number from DISPLAY: "
			    "%.100s", display);
			തിരികെ -1;
		}
		/* Create a socket. */
		sock = connect_local_xsocket(display_സംഖ്യ);
		എങ്കിൽ (sock < 0)
			തിരികെ -1;

		/* OK, we now have a connection to the display. */
		തിരികെ sock;
	}
	/*
	 * Connect to an inet socket.  The DISPLAY value is supposedly
	 * hostname:d[.s], where hostname may also be numeric IP address.
	 */
	strlcpy(buf, display, വലുപ്പം(buf));
	cp = strchr(buf, ':');
	എങ്കിൽ (!cp) {
		error("Could not find ':' in DISPLAY: %.100s", display);
		തിരികെ -1;
	}
	*cp = 0;
	/*
	 * buf now contains the host name.  But first we parse the
	 * display number.
	 */
	എങ്കിൽ (sscanf(cp + 1, "%u", &display_സംഖ്യ) != 1 ||
	    display_സംഖ്യ > UINT16_MAX - X11_BASE_PORT) {
		error("Could not parse display number from DISPLAY: %.100s",
		    display);
		തിരികെ -1;
	}

	/* Look up the host address */
	memset(&hints, 0, വലുപ്പം(hints));
	hints.ai_family = ssh->chanctxt->IPv4or6;
	hints.ai_socktype = SOCK_STREAM;
	snprintf(strport, വലുപ്പം strport, "%u", X11_BASE_PORT + display_സംഖ്യ);
	എങ്കിൽ ((gaierr = getaddrinfo(buf, strport, &hints, &aitop)) != 0) {
		error("%.100s: unknown host. (%s)", buf,
		ssh_gai_strerror(gaierr));
		തിരികെ -1;
	}
	വേണ്ടി (ai = aitop; ai; ai = ai->ai_next) {
		/* Create a socket. */
		sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		എങ്കിൽ (sock == -1) {
			debug2("socket: %.100s", strerror(errno));
			തുടരുക;
		}
		/* Connect it to the display. */
		എങ്കിൽ (connect(sock, ai->ai_addr, ai->ai_addrlen) == -1) {
			debug2("connect %.100s port %u: %.100s", buf,
			    X11_BASE_PORT + display_സംഖ്യ, strerror(errno));
			close(sock);
			തുടരുക;
		}
		/* Success */
		നിർത്തുക;
	}
	freeaddrinfo(aitop);
	എങ്കിൽ (!ai) {
		error("connect %.100s port %u: %.100s", buf,
		    X11_BASE_PORT + display_സംഖ്യ, strerror(errno));
		തിരികെ -1;
	}
	set_nodelay(sock);
	തിരികെ sock;
}

/*
 * Requests forwarding of X11 connections, generates fake authentication
 * data, and enables authentication spoofing.
 * This should be called in the client only.
 */
ശൂന്യം
x11_request_forwarding_with_spoofing(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ client_session_id,
    സ്ഥിരം അക്ഷരം *disp, സ്ഥിരം അക്ഷരം *proto, സ്ഥിരം അക്ഷരം *data, പൂർണ്ണസംഖ്യ want_reply)
{
	ഘടന ssh_channels *sc = ssh->chanctxt;
	u_int data_len = (u_int) strlen(data) / 2;
	u_int i, മൂല്യം;
	സ്ഥിരം അക്ഷരം *cp;
	അക്ഷരം *new_data;
	പൂർണ്ണസംഖ്യ r, screen_സംഖ്യ;

	എങ്കിൽ (sc->x11_saved_display == ശൂന്യ)
		sc->x11_saved_display = xstrdup(disp);
	അല്ലെങ്കിൽ എങ്കിൽ (strcmp(disp, sc->x11_saved_display) != 0) {
		error("x11_request_forwarding_with_spoofing: different "
		    "$DISPLAY already forwarded");
		തിരികെ;
	}

	cp = strchr(disp, ':');
	എങ്കിൽ (cp)
		cp = strchr(cp, '.');
	എങ്കിൽ (cp)
		screen_സംഖ്യ = (u_int)strtonum(cp + 1, 0, 400, ശൂന്യ);
	അല്ലെങ്കിൽ
		screen_സംഖ്യ = 0;

	എങ്കിൽ (sc->x11_saved_proto == ശൂന്യ) {
		/* Save protocol name. */
		sc->x11_saved_proto = xstrdup(proto);

		/* Extract real authentication data. */
		sc->x11_saved_data = xmalloc(data_len);
		വേണ്ടി (i = 0; i < data_len; i++) {
			എങ്കിൽ (sscanf(data + 2 * i, "%2x", &മൂല്യം) != 1) {
				fatal("x11_request_forwarding: bad "
				    "authentication data: %.100s", data);
			}
			sc->x11_saved_data[i] = മൂല്യം;
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
	എങ്കിൽ ((r = sshpkt_put_u8(ssh, 0)) != 0 || /* bool: single connection */
	    (r = sshpkt_put_cstring(ssh, proto)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, new_data)) != 0 ||
	    (r = sshpkt_put_u32(ssh, screen_സംഖ്യ)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send x11-req");
	സ്വതന്ത്രം(new_data);
}

/*
 * Returns whether an x11 channel was used recently (less than a second ago)
 */
പൂർണ്ണസംഖ്യ
x11_channel_used_recently(ഘടന ssh *ssh) {
	u_int i;
	Channel *c;
	ഇരട്ട lastused = 0;

	വേണ്ടി (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		എങ്കിൽ (c == ശൂന്യ || c->ctype == ശൂന്യ || c->lastused == 0.0 ||
		    strcmp(c->ctype, "x11-connection") != 0)
			തുടരുക;
		എങ്കിൽ (c->lastused > lastused)
			lastused = c->lastused;
	}
	തിരികെ lastused != 0.0 && monotime_double() <= lastused + 1.0;
}
