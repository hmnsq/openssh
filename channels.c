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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/stat.h>
#ଅନ୍ତର୍ଭାଵ <sys/ioctl.h>
#ଅନ୍ତର୍ଭାଵ <sys/un.h>
#ଅନ୍ତର୍ଭାଵ <sys/socket.h>
#ଅନ୍ତର୍ଭାଵ <sys/queue.h>

#ଅନ୍ତର୍ଭାଵ <netinet/in.h>
#ଅନ୍ତର୍ଭାଵ <arpa/inet.h>

#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <fcntl.h>
#ଅନ୍ତର୍ଭାଵ <limits.h>
#ଅନ୍ତର୍ଭାଵ <netdb.h>
#ଅନ୍ତର୍ଭାଵ <poll.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <stdint.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <termios.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>

#ଅନ୍ତର୍ଭାଵ "xmalloc.h"
#ଅନ୍ତର୍ଭାଵ "ssh.h"
#ଅନ୍ତର୍ଭାଵ "ssh2.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "packet.h"
#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"
#ଅନ୍ତର୍ଭାଵ "channels.h"
#ଅନ୍ତର୍ଭାଵ "compat.h"
#ଅନ୍ତର୍ଭାଵ "canohost.h"
#ଅନ୍ତର୍ଭାଵ "pathnames.h"
#ଅନ୍ତର୍ଭାଵ "match.h"

/* XXX remove once we're satisfied there's no lurking bugs */
/* #define DEBUG_CHANNEL_POLL 1 */

/* -- agent forwarding */
#define	ଅଙ୍କ_SOCKS	10

/* -- X11 forwarding */
/* X11 port for display :0 */
#define X11_BASE_PORT	6000
/* Maximum number of fake X11 displays to try. */
#define MAX_DISPLAYS  1000

/* Per-channel callback for pre/post IO actions */
ପ୍ରକାରବ୍ୟାଖ୍ୟା ଶୂନ୍ୟ chan_fn(ସଂରଚନା ssh *, Channel *c);

/*
 * Data structure for storing which hosts are permitted for forward requests.
 * The local sides of any remote forwards are stored in this array to prevent
 * a corrupt remote server from accessing arbitrary TCP/IP ports on our local
 * network (which might be behind a firewall).
 */
/* XXX: streamlocal wants a path instead of host:port */
/*      Overload host_to_connect; we could just make this match Forward */
/*	XXX - can we use listen_host instead of listen_path? */
ସଂରଚନା permission {
	ଅକ୍ଷର *host_to_connect;		/* Connect to 'host'. */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା port_to_connect;		/* Connect to 'port'. */
	ଅକ୍ଷର *listen_host;		/* Remote side should listen address. */
	ଅକ୍ଷର *listen_path;		/* Remote side should listen path. */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା listen_port;		/* Remote side should listen port. */
	Channel *downstream;		/* Downstream mux*/
};

/* Context for non-blocking connects */
ସଂରଚନା channel_connect {
	ଅକ୍ଷର *host;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା port;
	ସଂରଚନା addrinfo *ai, *aitop;
};

/*
 * Stores the forwarding permission state for a single direction (local or
 * remote).
 */
ସଂରଚନା permission_set {
	/*
	 * List of all local permitted host/port pairs to allow for the
	 * user.
	 */
	u_int ଅଙ୍କ_permitted_user;
	ସଂରଚନା permission *permitted_user;

	/*
	 * List of all permitted host/port pairs to allow for the admin.
	 */
	u_int ଅଙ୍କ_permitted_admin;
	ସଂରଚନା permission *permitted_admin;

	/*
	 * If this is true, all opens/listens are permitted.  This is the
	 * case on the server on which we have to trust the client anyway,
	 * and the user could do anything after logging in.
	 */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା all_permitted;
};

/* Used to record timeouts per channel type */
ସଂରଚନା ssh_channel_timeout {
	ଅକ୍ଷର *type_pattern;
	ଦ୍ୱିଗୁଣ timeout_secs;
};

/* Master structure for channels state */
ସଂରଚନା ssh_channels {
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
	ସଂରଚନା permission_set local_perms;
	ସଂରଚନା permission_set remote_perms;

	/* -- X11 forwarding */

	/* Saved X11 local (client) display. */
	ଅକ୍ଷର *x11_saved_display;

	/* Saved X11 authentication protocol name. */
	ଅକ୍ଷର *x11_saved_proto;

	/* Saved X11 authentication data.  This is the real data. */
	ଅକ୍ଷର *x11_saved_data;
	u_int x11_saved_data_len;

	/* Deadline after which all X11 connections are refused */
	ଦ୍ୱିଗୁଣ x11_refuse_time;

	/*
	 * Fake X11 authentication data.  This is what the server will be
	 * sending us; we should replace any occurrences of this by the
	 * real data.
	 */
	u_char *x11_fake_data;
	u_int x11_fake_data_len;

	/* AF_UNSPEC or AF_INET or AF_INET6 */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା IPv4or6;

	/* Set SO_KEEPALIVE on TCP connections */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା want_tcp_keepalive;

	/* Channel timeouts by type */
	ସଂରଚନା ssh_channel_timeout *timeouts;
	size_t ntimeouts;
	/* Global timeout for all OPEN channels */
	ଦ୍ୱିଗୁଣ global_deadline;
	ଦ୍ୱିଗୁଣ lastused;
	/* pattern-lists used to classify channels as bulk */
	ଅକ୍ଷର *bulk_classifier_tty, *bulk_classifier_notty;
	/* Number of active bulk channels (set by channel_handler) */
	u_int nbulk;
};

/* helper */
ସ୍ଥିର ଶୂନ୍ୟ port_open_helper(ସଂରଚନା ssh *ssh, Channel *c, ଅକ୍ଷର *rtype);
ସ୍ଥିର ଅଚଳ ଅକ୍ଷର *channel_rfwd_bind_host(ଅଚଳ ଅକ୍ଷର *listen_host);

/* non-blocking connect helpers */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା connect_next(ସଂରଚନା ssh *, ସଂରଚନା channel_connect *);
ସ୍ଥିର Channel *rdynamic_connect_prepare(ସଂରଚନା ssh *, ଅକ୍ଷର *, ଅକ୍ଷର *);
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା rdynamic_connect_finish(ସଂରଚନା ssh *, Channel *);

/* Setup helper */
ସ୍ଥିର ଶୂନ୍ୟ channel_handler_init(ସଂରଚନା ssh_channels *sc);

/* -- channel core */

ଶୂନ୍ୟ
channel_init_channels(ସଂରଚନା ssh *ssh)
{
	ସଂରଚନା ssh_channels *sc;

	ଯଦି ((sc = calloc(1, ଆକାର(*sc))) == ଖାଲି)
		fatal_f("allocation failed");
	sc->channels_alloc = 10;
	sc->channels = xcalloc(sc->channels_alloc, ଆକାର(*sc->channels));
	sc->IPv4or6 = AF_UNSPEC;
	sc->bulk_classifier_tty = xstrdup(CHANNEL_BULK_TTY);
	sc->bulk_classifier_notty = xstrdup(CHANNEL_BULK_NOTTY);
	channel_handler_init(sc);

	ssh->chanctxt = sc;
}

Channel *
channel_by_id(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା id)
{
	Channel *c;

	ଯଦି (id < 0 || (u_int)id >= ssh->chanctxt->channels_alloc) {
		logit_f("%d: bad id", id);
		ଫେରନ୍ତୁ ଖାଲି;
	}
	c = ssh->chanctxt->channels[id];
	ଯଦି (c == ଖାଲି) {
		logit_f("%d: bad id: channel free", id);
		ଫେରନ୍ତୁ ଖାଲି;
	}
	ଫେରନ୍ତୁ c;
}

Channel *
channel_by_remote_id(ସଂରଚନା ssh *ssh, u_int remote_id)
{
	Channel *c;
	u_int i;

	ପାଇଁ (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		ଯଦି (c != ଖାଲି && c->have_remote_id && c->remote_id == remote_id)
			ଫେରନ୍ତୁ c;
	}
	ଫେରନ୍ତୁ ଖାଲି;
}

/*
 * Returns the channel if it is allowed to receive protocol messages.
 * Private channels, like listening sockets, may not receive messages.
 */
Channel *
channel_lookup(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା id)
{
	Channel *c;

	ଯଦି ((c = channel_by_id(ssh, id)) == ଖାଲି)
		ଫେରନ୍ତୁ ଖାଲି;

	ବାଛ (c->type) {
	ସ୍ଥିତି SSH_CHANNEL_X11_OPEN:
	ସ୍ଥିତି SSH_CHANNEL_LARVAL:
	ସ୍ଥିତି SSH_CHANNEL_CONNECTING:
	ସ୍ଥିତି SSH_CHANNEL_DYNAMIC:
	ସ୍ଥିତି SSH_CHANNEL_RDYNAMIC_OPEN:
	ସ୍ଥିତି SSH_CHANNEL_RDYNAMIC_FINISH:
	ସ୍ଥିତି SSH_CHANNEL_OPENING:
	ସ୍ଥିତି SSH_CHANNEL_OPEN:
	ସ୍ଥିତି SSH_CHANNEL_ABANDONED:
	ସ୍ଥିତି SSH_CHANNEL_MUX_PROXY:
		ଫେରନ୍ତୁ c;
	}
	logit("Non-public channel %d, type %d.", id, c->type);
	ଫେରନ୍ତୁ ଖାଲି;
}

ସ୍ଥିର ଶୂନ୍ୟ
free_connect_ctx(ସଂରଚନା channel_connect *cctx)
{
	ମୁକ୍ତ(cctx->host);
	ଯଦି (cctx->aitop) {
		ଯଦି (cctx->aitop->ai_family == AF_UNIX)
			ମୁକ୍ତ(cctx->aitop);
		ଅନ୍ୟଥା
			freeaddrinfo(cctx->aitop);
	}
	memset(cctx, 0, ଆକାର(*cctx));
}

ସ୍ଥିର ଶୂନ୍ୟ
channel_free_connect_ctx(Channel *c)
{
	ଯଦି (c == ଖାଲି || c->connect_ctx == ଖାଲି)
		ଫେରନ୍ତୁ;
	free_connect_ctx(c->connect_ctx);
	ମୁକ୍ତ(c->connect_ctx);
	c->connect_ctx = ଖାଲି;
}

/* Enable/disable TCP keepalives for X11 and port-forwarding sockets */
ଶୂନ୍ୟ
channel_set_tcp_keepalives(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା on)
{
	ssh->chanctxt->want_tcp_keepalive = on;
}

/*
 * Add a timeout for open channels whose c->ctype (or c->xctype if it is set)
 * match type_pattern.
 */
ଶୂନ୍ୟ
channel_add_timeout(ସଂରଚନା ssh *ssh, ଅଚଳ ଅକ୍ଷର *type_pattern,
    ଦ୍ୱିଗୁଣ timeout_secs)
{
	ସଂରଚନା ssh_channels *sc = ssh->chanctxt;

	ଯଦି (strcmp(type_pattern, "global") == 0) {
		debug2_f("global channel timeout %f seconds", timeout_secs);
		sc->global_deadline = timeout_secs;
		ଫେରନ୍ତୁ;
	}
	debug2_f("channel type \"%s\" timeout %f seconds",
	    type_pattern, timeout_secs);
	sc->timeouts = xrecallocarray(sc->timeouts, sc->ntimeouts,
	    sc->ntimeouts + 1, ଆକାର(*sc->timeouts));
	sc->timeouts[sc->ntimeouts].type_pattern = xstrdup(type_pattern);
	sc->timeouts[sc->ntimeouts].timeout_secs = timeout_secs;
	sc->ntimeouts++;
}

/* Clears all previously-added channel timeouts */
ଶୂନ୍ୟ
channel_clear_timeouts(ସଂରଚନା ssh *ssh)
{
	ସଂରଚନା ssh_channels *sc = ssh->chanctxt;
	size_t i;

	debug3_f("clearing");
	ପାଇଁ (i = 0; i < sc->ntimeouts; i++)
		ମୁକ୍ତ(sc->timeouts[i].type_pattern);
	ମୁକ୍ତ(sc->timeouts);
	sc->timeouts = ଖାଲି;
	sc->ntimeouts = 0;
}

ସ୍ଥିର ଦ୍ୱିଗୁଣ
lookup_timeout(ସଂରଚନା ssh *ssh, ଅଚଳ ଅକ୍ଷର *type)
{
	ସଂରଚନା ssh_channels *sc = ssh->chanctxt;
	size_t i;

	ପାଇଁ (i = 0; i < sc->ntimeouts; i++) {
		ଯଦି (match_pattern(type, sc->timeouts[i].type_pattern))
			ଫେରନ୍ତୁ sc->timeouts[i].timeout_secs;
	}

	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ଶୂନ୍ୟ
channel_classify(ସଂରଚନା ssh *ssh, Channel *c)
{
	ସଂରଚନା ssh_channels *sc = ssh->chanctxt;
	ଅଚଳ ଅକ୍ଷର *type = c->xctype == ଖାଲି ? c->ctype : c->xctype;
	ଅଚଳ ପୂର୍ଣ୍ଣସଂଖ୍ୟା has_tty = c->isatty || c->remote_has_tty;
	ଅଚଳ ଅକ୍ଷର *classifier = has_tty ?
	    sc->bulk_classifier_tty : sc->bulk_classifier_notty;

	c->bulk = type != ଖାଲି && match_pattern_list(type, classifier, 0) == 1;
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
ଶୂନ୍ୟ
channel_set_xtype(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା id, ଅଚଳ ଅକ୍ଷର *xctype)
{
	ସଂରଚନା ssh_channels *sc = ssh->chanctxt;
	Channel *c;

	ଯଦି ((c = channel_by_id(ssh, id)) == ଖାଲି)
		fatal_f("missing channel %d", id);
	ଯଦି (c->xctype != ଖାଲି)
		ମୁକ୍ତ(c->xctype);
	c->xctype = xstrdup(xctype);
	/* Only override deadline if xctype has a more specific match. */
	ଦ୍ୱିଗୁଣ xtype_deadline = lookup_timeout(ssh, c->xctype);
	ଯଦି (xtype_deadline != 0)
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
ସ୍ଥିର ଶୂନ୍ୟ
channel_set_used_time(ସଂରଚନା ssh *ssh, Channel *c)
{
	ssh->chanctxt->lastused = monotime_double();
	ଯଦି (c != ଖାଲି)
		c->lastused = ssh->chanctxt->lastused;
}

/*
 * Get the time at which a channel is due to time out for inactivity.
 * Returns 0 if the channel is not due to time out ever.
 */
ସ୍ଥିର ଦ୍ୱିଗୁଣ
channel_get_expiry(ସଂରଚନା ssh *ssh, Channel *c)
{
	ସଂରଚନା ssh_channels *sc = ssh->chanctxt;
	ଦ୍ୱିଗୁଣ expiry = 0, channel_expiry;

	ଯଦି (sc->lastused != 0 && sc->global_deadline != 0)
		expiry = sc->lastused + sc->global_deadline;
	ଯଦି (c->lastused != 0 && c->inactive_deadline != 0) {
		channel_expiry = c->lastused + c->inactive_deadline;
		ଯଦି (expiry == 0 || channel_expiry < expiry)
			expiry = channel_expiry;
	}
	ଫେରନ୍ତୁ expiry;
}

/* Returns non-zero if there is an open, non-interactive channel */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
channel_has_bulk(ସଂରଚନା ssh *ssh)
{
	ଫେରନ୍ତୁ ssh->chanctxt != ଖାଲି && ssh->chanctxt->nbulk != 0;
}

/*
 * Register filedescriptors for a channel, used when allocating a channel or
 * when the channel consumer/producer is ready, e.g. shell exec'd
 */
ସ୍ଥିର ଶୂନ୍ୟ
channel_register_fds(ସଂରଚନା ssh *ssh, Channel *c, ପୂର୍ଣ୍ଣସଂଖ୍ୟା rfd, ପୂର୍ଣ୍ଣସଂଖ୍ୟା wfd, ପୂର୍ଣ୍ଣସଂଖ୍ୟା efd,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା extusage, ପୂର୍ଣ୍ଣସଂଖ୍ୟା nonblock, ପୂର୍ଣ୍ଣସଂଖ୍ୟା is_tty)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା val;

	ଯଦି (rfd != -1)
		(ଶୂନ୍ୟ)fcntl(rfd, F_SETFD, FD_CLOEXEC);
	ଯଦି (wfd != -1 && wfd != rfd)
		(ଶୂନ୍ୟ)fcntl(wfd, F_SETFD, FD_CLOEXEC);
	ଯଦି (efd != -1 && efd != rfd && efd != wfd)
		(ଶୂନ୍ୟ)fcntl(efd, F_SETFD, FD_CLOEXEC);

	c->rfd = rfd;
	c->wfd = wfd;
	c->sock = (rfd == wfd) ? rfd : -1;
	c->efd = efd;
	c->extended_usage = extusage;

	ଯଦି ((c->isatty = is_tty) != 0)
		debug2("channel %d: rfd %d isatty", c->self, c->rfd);
#ifdef _AIX
	/* XXX: Later AIX versions can't push as much data to tty */
	c->wfd_isatty = is_tty || isatty(c->wfd);
#endif

	/* enable nonblocking mode */
	c->restore_block = 0;
	ଯଦି (nonblock == CHANNEL_NONBLOCK_STDIO) {
		/*
		 * Special handling for stdio file descriptors: do not set
		 * non-blocking mode if they are TTYs. Otherwise prepare to
		 * restore their blocking state on exit to avoid interfering
		 * with other programs that follow.
		 */
		ଯଦି (rfd != -1 && !isatty(rfd) &&
		    (val = fcntl(rfd, F_GETFL)) != -1 && !(val & O_NONBLOCK)) {
			c->restore_flags[0] = val;
			c->restore_block |= CHANNEL_RESTORE_RFD;
			set_nonblock(rfd);
		}
		ଯଦି (wfd != -1 && !isatty(wfd) &&
		    (val = fcntl(wfd, F_GETFL)) != -1 && !(val & O_NONBLOCK)) {
			c->restore_flags[1] = val;
			c->restore_block |= CHANNEL_RESTORE_WFD;
			set_nonblock(wfd);
		}
		ଯଦି (efd != -1 && !isatty(efd) &&
		    (val = fcntl(efd, F_GETFL)) != -1 && !(val & O_NONBLOCK)) {
			c->restore_flags[2] = val;
			c->restore_block |= CHANNEL_RESTORE_EFD;
			set_nonblock(efd);
		}
	} ଅନ୍ୟଥା ଯଦି (nonblock) {
		ଯଦି (rfd != -1)
			set_nonblock(rfd);
		ଯଦି (wfd != -1)
			set_nonblock(wfd);
		ଯଦି (efd != -1)
			set_nonblock(efd);
	}
	/* channel might be entering a larval state, so reset global timeout */
	channel_set_used_time(ssh, ଖାଲି);
	channel_classify(ssh, c);
}

/*
 * Allocate a new channel object and set its type and socket.
 */
Channel *
channel_new(ସଂରଚନା ssh *ssh, ଅକ୍ଷର *ctype, ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, ପୂର୍ଣ୍ଣସଂଖ୍ୟା rfd, ପୂର୍ଣ୍ଣସଂଖ୍ୟା wfd, ପୂର୍ଣ୍ଣସଂଖ୍ୟା efd,
    u_int window, u_int maxpack, ପୂର୍ଣ୍ଣସଂଖ୍ୟା extusage, ଅଚଳ ଅକ୍ଷର *remote_name,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା nonblock)
{
	ସଂରଚନା ssh_channels *sc = ssh->chanctxt;
	u_int i, found = 0;
	Channel *c;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	/* Try to find a free slot where to put the new channel. */
	ପାଇଁ (i = 0; i < sc->channels_alloc; i++) {
		ଯଦି (sc->channels[i] == ଖାଲି) {
			/* Found a free slot. */
			found = i;
			ଭାଙ୍ଗ;
		}
	}
	ଯଦି (i >= sc->channels_alloc) {
		/*
		 * There are no free slots. Take last+1 slot and expand
		 * the array.
		 */
		found = sc->channels_alloc;
		ଯଦି (sc->channels_alloc > CHANNELS_MAX_CHANNELS)
			fatal_f("internal error: channels_alloc %d too big",
			    sc->channels_alloc);
		sc->channels = xrecallocarray(sc->channels, sc->channels_alloc,
		    sc->channels_alloc + 10, ଆକାର(*sc->channels));
		sc->channels_alloc += 10;
		debug2("channel: expanding %d", sc->channels_alloc);
	}
	/* Initialize and return new channel. */
	c = sc->channels[found] = xcalloc(1, ଆକାର(Channel));
	ଯଦି ((c->ନିବେଶ = sshbuf_new()) == ଖାଲି ||
	    (c->output = sshbuf_new()) == ଖାଲି ||
	    (c->extended = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	ଯଦି ((r = sshbuf_set_max_size(c->ନିବେଶ, CHAN_ନିବେଶ_MAX)) != 0)
		fatal_fr(r, "sshbuf_set_max_size");
	c->ostate = CHAN_OUTPUT_OPEN;
	c->istate = CHAN_ନିବେଶ_OPEN;
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
	ଫେରନ୍ତୁ c;
}

ଶୂନ୍ୟ
channel_set_tty(ସଂରଚନା ssh *ssh, Channel *c)
{
	c->remote_has_tty = 1;
	channel_classify(ssh, c);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
channel_close_fd(ସଂରଚନା ssh *ssh, Channel *c, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *fdp)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret, fd = *fdp;

	ଯଦି (fd == -1)
		ଫେରନ୍ତୁ 0;

	/* restore blocking */
	ଯଦି (*fdp == c->rfd &&
	    (c->restore_block & CHANNEL_RESTORE_RFD) != 0)
		(ଶୂନ୍ୟ)fcntl(*fdp, F_SETFL, c->restore_flags[0]);
	ଅନ୍ୟଥା ଯଦି (*fdp == c->wfd &&
	    (c->restore_block & CHANNEL_RESTORE_WFD) != 0)
		(ଶୂନ୍ୟ)fcntl(*fdp, F_SETFL, c->restore_flags[1]);
	ଅନ୍ୟଥା ଯଦି (*fdp == c->efd &&
	    (c->restore_block & CHANNEL_RESTORE_EFD) != 0)
		(ଶୂନ୍ୟ)fcntl(*fdp, F_SETFL, c->restore_flags[2]);

	ଯଦି (*fdp == c->rfd) {
		c->io_want &= ~SSH_CHAN_IO_RFD;
		c->io_ready &= ~SSH_CHAN_IO_RFD;
		c->rfd = -1;
		c->pfds[0] = -1;
	}
	ଯଦି (*fdp == c->wfd) {
		c->io_want &= ~SSH_CHAN_IO_WFD;
		c->io_ready &= ~SSH_CHAN_IO_WFD;
		c->wfd = -1;
		c->pfds[1] = -1;
	}
	ଯଦି (*fdp == c->efd) {
		c->io_want &= ~SSH_CHAN_IO_EFD;
		c->io_ready &= ~SSH_CHAN_IO_EFD;
		c->efd = -1;
		c->pfds[2] = -1;
	}
	ଯଦି (*fdp == c->sock) {
		c->io_want &= ~SSH_CHAN_IO_SOCK;
		c->io_ready &= ~SSH_CHAN_IO_SOCK;
		c->sock = -1;
		c->pfds[3] = -1;
	}

	ret = close(fd);
	*fdp = -1; /* probably redundant */
	ଫେରନ୍ତୁ ret;
}

/* Close all channel fd/socket. */
ସ୍ଥିର ଶୂନ୍ୟ
channel_close_fds(ସଂରଚନା ssh *ssh, Channel *c)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock = c->sock, rfd = c->rfd, wfd = c->wfd, efd = c->efd;

	channel_close_fd(ssh, c, &c->sock);
	ଯଦି (rfd != sock)
		channel_close_fd(ssh, c, &c->rfd);
	ଯଦି (wfd != sock && wfd != rfd)
		channel_close_fd(ssh, c, &c->wfd);
	ଯଦି (efd != sock && efd != rfd && efd != wfd)
		channel_close_fd(ssh, c, &c->efd);
}

ସ୍ଥିର ଶୂନ୍ୟ
fwd_perm_clear(ସଂରଚନା permission *perm)
{
	ମୁକ୍ତ(perm->host_to_connect);
	ମୁକ୍ତ(perm->listen_host);
	ମୁକ୍ତ(perm->listen_path);
	memset(perm, 0, ଆକାର(*perm));
}

/* Returns an printable name for the specified forwarding permission list */
ସ୍ଥିର ଅଚଳ ଅକ୍ଷର *
fwd_ident(ପୂର୍ଣ୍ଣସଂଖ୍ୟା who, ପୂର୍ଣ୍ଣସଂଖ୍ୟା where)
{
	ଯଦି (who == FORWARD_ADM) {
		ଯଦି (where == FORWARD_LOCAL)
			ଫେରନ୍ତୁ "admin local";
		ଅନ୍ୟଥା ଯଦି (where == FORWARD_REMOTE)
			ଫେରନ୍ତୁ "admin remote";
	} ଅନ୍ୟଥା ଯଦି (who == FORWARD_USER) {
		ଯଦି (where == FORWARD_LOCAL)
			ଫେରନ୍ତୁ "user local";
		ଅନ୍ୟଥା ଯଦି (where == FORWARD_REMOTE)
			ଫେରନ୍ତୁ "user remote";
	}
	fatal("Unknown forward permission list %d/%d", who, where);
}

/* Returns the forwarding permission list for the specified direction */
ସ୍ଥିର ସଂରଚନା permission_set *
permission_set_get(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା where)
{
	ସଂରଚନା ssh_channels *sc = ssh->chanctxt;

	ବାଛ (where) {
	ସ୍ଥିତି FORWARD_LOCAL:
		ଫେରନ୍ତୁ &sc->local_perms;
		ଭାଙ୍ଗ;
	ସ୍ଥିତି FORWARD_REMOTE:
		ଫେରନ୍ତୁ &sc->remote_perms;
		ଭାଙ୍ଗ;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		fatal_f("invalid forwarding direction %d", where);
	}
}

/* Returns pointers to the specified forwarding list and its element count */
ସ୍ଥିର ଶୂନ୍ୟ
permission_set_get_array(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା who, ପୂର୍ଣ୍ଣସଂଖ୍ୟା where,
    ସଂରଚନା permission ***permpp, u_int **npermpp)
{
	ସଂରଚନା permission_set *pset = permission_set_get(ssh, where);

	ବାଛ (who) {
	ସ୍ଥିତି FORWARD_USER:
		*permpp = &pset->permitted_user;
		*npermpp = &pset->ଅଙ୍କ_permitted_user;
		ଭାଙ୍ଗ;
	ସ୍ଥିତି FORWARD_ADM:
		*permpp = &pset->permitted_admin;
		*npermpp = &pset->ଅଙ୍କ_permitted_admin;
		ଭାଙ୍ଗ;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		fatal_f("invalid forwarding client %d", who);
	}
}

/* Adds an entry to the specified forwarding list */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
permission_set_add(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା who, ପୂର୍ଣ୍ଣସଂଖ୍ୟା where,
    ଅଚଳ ଅକ୍ଷର *host_to_connect, ପୂର୍ଣ୍ଣସଂଖ୍ୟା port_to_connect,
    ଅଚଳ ଅକ୍ଷର *listen_host, ଅଚଳ ଅକ୍ଷର *listen_path, ପୂର୍ଣ୍ଣସଂଖ୍ୟା listen_port,
    Channel *downstream)
{
	ସଂରଚନା permission **permp;
	u_int n, *npermp;

	permission_set_get_array(ssh, who, where, &permp, &npermp);

	ଯଦି (*npermp >= INT_MAX)
		fatal_f("%s overflow", fwd_ident(who, where));

	*permp = xrecallocarray(*permp, *npermp, *npermp + 1, ଆକାର(**permp));
	n = (*npermp)++;
#define MAYBE_DUP(s) ((s == ଖାଲି) ? ଖାଲି : xstrdup(s))
	(*permp)[n].host_to_connect = MAYBE_DUP(host_to_connect);
	(*permp)[n].port_to_connect = port_to_connect;
	(*permp)[n].listen_host = MAYBE_DUP(listen_host);
	(*permp)[n].listen_path = MAYBE_DUP(listen_path);
	(*permp)[n].listen_port = listen_port;
	(*permp)[n].downstream = downstream;
#undef MAYBE_DUP
	ଫେରନ୍ତୁ (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)n;
}

ସ୍ଥିର ଶୂନ୍ୟ
mux_remove_remote_forwardings(ସଂରଚନା ssh *ssh, Channel *c)
{
	ସଂରଚନା ssh_channels *sc = ssh->chanctxt;
	ସଂରଚନା permission_set *pset = &sc->local_perms;
	ସଂରଚନା permission *perm;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	u_int i;

	ପାଇଁ (i = 0; i < pset->ଅଙ୍କ_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		ଯଦି (perm->downstream != c)
			ଜାରି;

		/* cancel on the server, since mux client is gone */
		debug("channel %d: cleanup remote forward for %s:%u",
		    c->self, perm->listen_host, perm->listen_port);
		ଯଦି ((r = sshpkt_start(ssh, SSH2_ସନ୍ଦେଶ_GLOBAL_REQUEST)) != 0 ||
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
ଶୂନ୍ୟ
channel_free(ସଂରଚନା ssh *ssh, Channel *c)
{
	ସଂରଚନା ssh_channels *sc = ssh->chanctxt;
	ଅକ୍ଷର *s;
	u_int i, n;
	Channel *other;
	ସଂରଚନା channel_confirm *cc;

	ପାଇଁ (n = 0, i = 0; i < sc->channels_alloc; i++) {
		ଯଦି ((other = sc->channels[i]) == ଖାଲି)
			ଜାରି;
		n++;
		/* detach from mux client and prepare for closing */
		ଯଦି (c->type == SSH_CHANNEL_MUX_CLIENT &&
		    other->type == SSH_CHANNEL_MUX_PROXY &&
		    other->mux_ctx == c) {
			other->mux_ctx = ଖାଲି;
			other->type = SSH_CHANNEL_OPEN;
			other->istate = CHAN_ନିବେଶ_CLOSED;
			other->ostate = CHAN_OUTPUT_CLOSED;
		}
	}
	debug("channel %d: free: %s, nchannels %u", c->self,
	    c->remote_name ? c->remote_name : "???", n);

	ଯଦି (c->type == SSH_CHANNEL_MUX_CLIENT) {
		mux_remove_remote_forwardings(ssh, c);
		ମୁକ୍ତ(c->mux_ctx);
		c->mux_ctx = ଖାଲି;
	} ଅନ୍ୟଥା ଯଦି (c->type == SSH_CHANNEL_MUX_LISTENER) {
		ମୁକ୍ତ(c->mux_ctx);
		c->mux_ctx = ଖାଲି;
	}

	ଯଦି (log_level_get() >= SYSLOG_LEVEL_DEBUG3) {
		s = channel_open_message(ssh);
		debug3("channel %d: status: %s", c->self, s);
		ମୁକ୍ତ(s);
	}

	channel_close_fds(ssh, c);
	sshbuf_free(c->ନିବେଶ);
	sshbuf_free(c->output);
	sshbuf_free(c->extended);
	c->ନିବେଶ = c->output = c->extended = ଖାଲି;
	ମୁକ୍ତ(c->remote_name);
	c->remote_name = ଖାଲି;
	ମୁକ୍ତ(c->path);
	c->path = ଖାଲି;
	ମୁକ୍ତ(c->listening_addr);
	c->listening_addr = ଖାଲି;
	ମୁକ୍ତ(c->xctype);
	c->xctype = ଖାଲି;
	channel_free_connect_ctx(c);
	ଯେତେବେଳେ ((cc = TAILQ_FIRST(&c->status_confirms)) != ଖାଲି) {
		ଯଦି (cc->abandon_cb != ଖାଲି)
			cc->abandon_cb(ssh, c, cc->ctx);
		TAILQ_REMOVE(&c->status_confirms, cc, entry);
		freezero(cc, ଆକାର(*cc));
	}
	ଯଦି (c->filter_cleanup != ଖାଲି && c->filter_ctx != ଖାଲି)
		c->filter_cleanup(ssh, c->self, c->filter_ctx);
	sc->channels[c->self] = ଖାଲି;
	freezero(c, ଆକାର(*c));
}

ଶୂନ୍ୟ
channel_free_all(ସଂରଚନା ssh *ssh)
{
	u_int i;
	ସଂରଚନା ssh_channels *sc = ssh->chanctxt;

	ପାଇଁ (i = 0; i < sc->channels_alloc; i++)
		ଯଦି (sc->channels[i] != ଖାଲି)
			channel_free(ssh, sc->channels[i]);

	ମୁକ୍ତ(sc->channels);
	sc->channels = ଖାଲି;
	sc->channels_alloc = 0;

	ମୁକ୍ତ(sc->x11_saved_display);
	sc->x11_saved_display = ଖାଲି;

	ମୁକ୍ତ(sc->x11_saved_proto);
	sc->x11_saved_proto = ଖାଲି;

	ମୁକ୍ତ(sc->x11_saved_data);
	sc->x11_saved_data = ଖାଲି;
	sc->x11_saved_data_len = 0;

	ମୁକ୍ତ(sc->x11_fake_data);
	sc->x11_fake_data = ଖାଲି;
	sc->x11_fake_data_len = 0;
}

ଶୂନ୍ୟ
channel_free_channels(ସଂରଚନା ssh *ssh)
{
	ସଂରଚନା ssh_channels *sc;

	ଯଦି (ssh == ଖାଲି || ssh->chanctxt == ଖାଲି)
		ଫେରନ୍ତୁ;
	channel_free_all(ssh);
	channel_clear_permission(ssh, FORWARD_USER, FORWARD_LOCAL);
	channel_clear_permission(ssh, FORWARD_USER, FORWARD_REMOTE);
	channel_clear_permission(ssh, FORWARD_ADM, FORWARD_LOCAL);
	channel_clear_permission(ssh, FORWARD_ADM, FORWARD_REMOTE);
	sc = ssh->chanctxt;
	ମୁକ୍ତ(sc->bulk_classifier_tty);
	ମୁକ୍ତ(sc->bulk_classifier_notty);
	ମୁକ୍ତ(sc->channel_pre);
	ମୁକ୍ତ(sc->channel_post);
	freezero(sc, ଆକାର(*sc));
	ssh->chanctxt = ଖାଲି;
}

/*
 * Closes the sockets/fds of all channels.  This is used to close extra file
 * descriptors after a fork.
 */
ଶୂନ୍ୟ
channel_close_all(ସଂରଚନା ssh *ssh)
{
	u_int i;

	ପାଇଁ (i = 0; i < ssh->chanctxt->channels_alloc; i++)
		ଯଦି (ssh->chanctxt->channels[i] != ଖାଲି)
			channel_close_fds(ssh, ssh->chanctxt->channels[i]);
}

/*
 * Stop listening to channels.
 */
ଶୂନ୍ୟ
channel_stop_listening(ସଂରଚନା ssh *ssh)
{
	u_int i;
	Channel *c;

	ପାଇଁ (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		ଯଦି (c != ଖାଲି) {
			ବାଛ (c->type) {
			ସ୍ଥିତି SSH_CHANNEL_AUTH_SOCKET:
			ସ୍ଥିତି SSH_CHANNEL_PORT_LISTENER:
			ସ୍ଥିତି SSH_CHANNEL_RPORT_LISTENER:
			ସ୍ଥିତି SSH_CHANNEL_X11_LISTENER:
			ସ୍ଥିତି SSH_CHANNEL_UNIX_LISTENER:
			ସ୍ଥିତି SSH_CHANNEL_RUNIX_LISTENER:
				channel_close_fd(ssh, c, &c->sock);
				channel_free(ssh, c);
				ଭାଙ୍ଗ;
			}
		}
	}
}

/*
 * Returns true if no channel has too much buffered data, and false if one or
 * more channel is overfull.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
channel_not_very_much_buffered_data(ସଂରଚନା ssh *ssh)
{
	u_int i;
	u_int maxsize = ssh_packet_get_maxsize(ssh);
	Channel *c;

	ପାଇଁ (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		ଯଦି (c == ଖାଲି || c->type != SSH_CHANNEL_OPEN)
			ଜାରି;
		ଯଦି (sshbuf_len(c->output) > maxsize) {
			debug2("channel %d: big output buffer %zu > %u",
			    c->self, sshbuf_len(c->output), maxsize);
			ଫେରନ୍ତୁ 0;
		}
	}
	ଫେରନ୍ତୁ 1;
}

/* Returns true if any channel is still open. */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
channel_still_open(ସଂରଚନା ssh *ssh)
{
	u_int i;
	Channel *c;

	ପାଇଁ (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		ଯଦି (c == ଖାଲି)
			ଜାରି;
		ବାଛ (c->type) {
		ସ୍ଥିତି SSH_CHANNEL_X11_LISTENER:
		ସ୍ଥିତି SSH_CHANNEL_PORT_LISTENER:
		ସ୍ଥିତି SSH_CHANNEL_RPORT_LISTENER:
		ସ୍ଥିତି SSH_CHANNEL_MUX_LISTENER:
		ସ୍ଥିତି SSH_CHANNEL_CLOSED:
		ସ୍ଥିତି SSH_CHANNEL_AUTH_SOCKET:
		ସ୍ଥିତି SSH_CHANNEL_DYNAMIC:
		ସ୍ଥିତି SSH_CHANNEL_RDYNAMIC_OPEN:
		ସ୍ଥିତି SSH_CHANNEL_CONNECTING:
		ସ୍ଥିତି SSH_CHANNEL_ZOMBIE:
		ସ୍ଥିତି SSH_CHANNEL_ABANDONED:
		ସ୍ଥିତି SSH_CHANNEL_UNIX_LISTENER:
		ସ୍ଥିତି SSH_CHANNEL_RUNIX_LISTENER:
			ଜାରି;
		ସ୍ଥିତି SSH_CHANNEL_LARVAL:
			ଜାରି;
		ସ୍ଥିତି SSH_CHANNEL_OPENING:
		ସ୍ଥିତି SSH_CHANNEL_OPEN:
		ସ୍ଥିତି SSH_CHANNEL_RDYNAMIC_FINISH:
		ସ୍ଥିତି SSH_CHANNEL_X11_OPEN:
		ସ୍ଥିତି SSH_CHANNEL_MUX_CLIENT:
		ସ୍ଥିତି SSH_CHANNEL_MUX_PROXY:
			ଫେରନ୍ତୁ 1;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			fatal_f("bad channel type %d", c->type);
			/* NOTREACHED */
		}
	}
	ଫେରନ୍ତୁ 0;
}

/* Returns true if a channel with a TTY is open. */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
channel_tty_open(ସଂରଚନା ssh *ssh)
{
	u_int i;
	Channel *c;

	ପାଇଁ (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		ଯଦି (c == ଖାଲି || c->type != SSH_CHANNEL_OPEN)
			ଜାରି;
		ଯଦି (c->client_tty)
			ଫେରନ୍ତୁ 1;
	}
	ଫେରନ୍ତୁ 0;
}

/* Returns the id of an open channel suitable for keepaliving */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
channel_find_open(ସଂରଚନା ssh *ssh)
{
	u_int i;
	Channel *c;

	ପାଇଁ (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		ଯଦି (c == ଖାଲି || !c->have_remote_id)
			ଜାରି;
		ବାଛ (c->type) {
		ସ୍ଥିତି SSH_CHANNEL_CLOSED:
		ସ୍ଥିତି SSH_CHANNEL_DYNAMIC:
		ସ୍ଥିତି SSH_CHANNEL_RDYNAMIC_OPEN:
		ସ୍ଥିତି SSH_CHANNEL_RDYNAMIC_FINISH:
		ସ୍ଥିତି SSH_CHANNEL_X11_LISTENER:
		ସ୍ଥିତି SSH_CHANNEL_PORT_LISTENER:
		ସ୍ଥିତି SSH_CHANNEL_RPORT_LISTENER:
		ସ୍ଥିତି SSH_CHANNEL_MUX_LISTENER:
		ସ୍ଥିତି SSH_CHANNEL_MUX_CLIENT:
		ସ୍ଥିତି SSH_CHANNEL_MUX_PROXY:
		ସ୍ଥିତି SSH_CHANNEL_OPENING:
		ସ୍ଥିତି SSH_CHANNEL_CONNECTING:
		ସ୍ଥିତି SSH_CHANNEL_ZOMBIE:
		ସ୍ଥିତି SSH_CHANNEL_ABANDONED:
		ସ୍ଥିତି SSH_CHANNEL_UNIX_LISTENER:
		ସ୍ଥିତି SSH_CHANNEL_RUNIX_LISTENER:
			ଜାରି;
		ସ୍ଥିତି SSH_CHANNEL_LARVAL:
		ସ୍ଥିତି SSH_CHANNEL_AUTH_SOCKET:
		ସ୍ଥିତି SSH_CHANNEL_OPEN:
		ସ୍ଥିତି SSH_CHANNEL_X11_OPEN:
			ଫେରନ୍ତୁ i;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			fatal_f("bad channel type %d", c->type);
			/* NOTREACHED */
		}
	}
	ଫେରନ୍ତୁ -1;
}

/* Returns the state of the channel's extended usage flag */
ଅଚଳ ଅକ୍ଷର *
channel_format_extended_usage(ଅଚଳ Channel *c)
{
	ଯଦି (c->efd == -1)
		ଫେରନ୍ତୁ "closed";

	ବାଛ (c->extended_usage) {
	ସ୍ଥିତି CHAN_EXTENDED_WRITE:
		ଫେରନ୍ତୁ "write";
	ସ୍ଥିତି CHAN_EXTENDED_READ:
		ଫେରନ୍ତୁ "read";
	ସ୍ଥିତି CHAN_EXTENDED_IGNORE:
		ଫେରନ୍ତୁ "ignore";
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		ଫେରନ୍ତୁ "UNKNOWN";
	}
}

ସ୍ଥିର ଅକ୍ଷର *
channel_format_status(ଅଚଳ Channel *c)
{
	ଅକ୍ଷର *ret = ଖାଲି;

	xasprintf(&ret, "t%d [%s] %s%u %s%u i%u/%zu o%u/%zu e[%s]/%zu "
	    "fd %d/%d/%d sock %d cc %d %s%u io 0x%02x/0x%02x %s%s",
	    c->type, c->xctype != ଖାଲି ? c->xctype : c->ctype,
	    c->have_remote_id ? "r" : "nr", c->remote_id,
	    c->mux_ctx != ଖାଲି ? "m" : "nm", c->mux_downstream_id,
	    c->istate, sshbuf_len(c->ନିବେଶ),
	    c->ostate, sshbuf_len(c->output),
	    channel_format_extended_usage(c), sshbuf_len(c->extended),
	    c->rfd, c->wfd, c->efd, c->sock, c->ctl_chan,
	    c->have_ctl_child_id ? "c" : "nc", c->ctl_child_id,
	    c->io_want, c->io_ready,
	    c->isatty ? "T" : (c->remote_has_tty ? "RT" : ""),
	    c->bulk ? "B" : "I");
	ଫେରନ୍ତୁ ret;
}

/*
 * Returns a message describing the currently open forwarded connections,
 * suitable for sending to the client.  The message contains crlf pairs for
 * newlines.
 */
ଅକ୍ଷର *
channel_open_message(ସଂରଚନା ssh *ssh)
{
	ସଂରଚନା sshbuf *buf;
	Channel *c;
	u_int i;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	ଅକ୍ଷର *cp, *ret;

	ଯଦି ((buf = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new");
	ଯଦି ((r = sshbuf_putf(buf,
	    "The following connections are open:\r\n")) != 0)
		fatal_fr(r, "sshbuf_putf");
	ପାଇଁ (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		ଯଦି (c == ଖାଲି)
			ଜାରି;
		ବାଛ (c->type) {
		ସ୍ଥିତି SSH_CHANNEL_X11_LISTENER:
		ସ୍ଥିତି SSH_CHANNEL_PORT_LISTENER:
		ସ୍ଥିତି SSH_CHANNEL_RPORT_LISTENER:
		ସ୍ଥିତି SSH_CHANNEL_CLOSED:
		ସ୍ଥିତି SSH_CHANNEL_AUTH_SOCKET:
		ସ୍ଥିତି SSH_CHANNEL_ZOMBIE:
		ସ୍ଥିତି SSH_CHANNEL_ABANDONED:
		ସ୍ଥିତି SSH_CHANNEL_MUX_LISTENER:
		ସ୍ଥିତି SSH_CHANNEL_UNIX_LISTENER:
		ସ୍ଥିତି SSH_CHANNEL_RUNIX_LISTENER:
			ଜାରି;
		ସ୍ଥିତି SSH_CHANNEL_LARVAL:
		ସ୍ଥିତି SSH_CHANNEL_OPENING:
		ସ୍ଥିତି SSH_CHANNEL_CONNECTING:
		ସ୍ଥିତି SSH_CHANNEL_DYNAMIC:
		ସ୍ଥିତି SSH_CHANNEL_RDYNAMIC_OPEN:
		ସ୍ଥିତି SSH_CHANNEL_RDYNAMIC_FINISH:
		ସ୍ଥିତି SSH_CHANNEL_OPEN:
		ସ୍ଥିତି SSH_CHANNEL_X11_OPEN:
		ସ୍ଥିତି SSH_CHANNEL_MUX_PROXY:
		ସ୍ଥିତି SSH_CHANNEL_MUX_CLIENT:
			cp = channel_format_status(c);
			ଯଦି ((r = sshbuf_putf(buf, "  #%d %.300s (%s)\r\n",
			    c->self, c->remote_name, cp)) != 0) {
				ମୁକ୍ତ(cp);
				fatal_fr(r, "sshbuf_putf");
			}
			ମୁକ୍ତ(cp);
			ଜାରି;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			fatal_f("bad channel type %d", c->type);
			/* NOTREACHED */
		}
	}
	ଯଦି ((ret = sshbuf_dup_string(buf)) == ଖାଲି)
		fatal_f("sshbuf_dup_string");
	sshbuf_free(buf);
	ଫେରନ୍ତୁ ret;
}

ଶୂନ୍ୟ
channel_report_open(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା level)
{
	ଅକ୍ଷର *open, *oopen, *cp, ident[256];

	sshpkt_fmt_connection_id(ssh, ident, ଆକାର(ident));
	do_log2(level, "Connection: %s (pid %ld)", ident, (long)getpid());
	open = oopen = channel_open_message(ssh);
	ଯେତେବେଳେ ((cp = strsep(&open, "\r\n")) != ଖାଲି) {
		ଯଦି (*cp != '\0')
			do_log2(level, "%s", cp);
	}
	ମୁକ୍ତ(oopen);
}

ସ୍ଥିର ଶୂନ୍ୟ
open_preamble(ସଂରଚନା ssh *ssh, ଅଚଳ ଅକ୍ଷର *where, Channel *c, ଅଚଳ ଅକ୍ଷର *type)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = sshpkt_start(ssh, SSH2_ସନ୍ଦେଶ_CHANNEL_OPEN)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, type)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_window)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0) {
		fatal_r(r, "%s: channel %i: open", where, c->self);
	}
}

ଶୂନ୍ୟ
channel_send_open(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା id)
{
	Channel *c = channel_lookup(ssh, id);
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (c == ଖାଲି) {
		logit("channel_send_open: %d: bad id", id);
		ଫେରନ୍ତୁ;
	}
	debug2("channel %d: send open", id);
	open_preamble(ssh, __func__, c, c->ctype);
	ଯଦି ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i", c->self);
}

ଶୂନ୍ୟ
channel_request_start(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା id, ଅଚଳ ଅକ୍ଷର *service,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା wantconfirm)
{
	Channel *c = channel_lookup(ssh, id);
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (c == ଖାଲି) {
		logit_f("%d: unknown channel id", id);
		ଫେରନ୍ତୁ;
	}
	ଯଦି (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);

	debug2("channel %d: request %s confirm %d", id, service, wantconfirm);
	ଯଦି ((r = sshpkt_start(ssh, SSH2_ସନ୍ଦେଶ_CHANNEL_REQUEST)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, service)) != 0 ||
	    (r = sshpkt_put_u8(ssh, wantconfirm)) != 0) {
		fatal_fr(r, "channel %i", c->self);
	}
}

ଶୂନ୍ୟ
channel_register_status_confirm(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା id,
    channel_confirm_cb *cb, channel_confirm_abandon_cb *abandon_cb, ଶୂନ୍ୟ *ctx)
{
	ସଂରଚନା channel_confirm *cc;
	Channel *c;

	ଯଦି ((c = channel_lookup(ssh, id)) == ଖାଲି)
		fatal_f("%d: bad id", id);

	cc = xcalloc(1, ଆକାର(*cc));
	cc->cb = cb;
	cc->abandon_cb = abandon_cb;
	cc->ctx = ctx;
	TAILQ_INSERT_TAIL(&c->status_confirms, cc, entry);
}

ଶୂନ୍ୟ
channel_register_open_confirm(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା id,
    channel_open_fn *fn, ଶୂନ୍ୟ *ctx)
{
	Channel *c = channel_lookup(ssh, id);

	ଯଦି (c == ଖାଲି) {
		logit_f("%d: bad id", id);
		ଫେରନ୍ତୁ;
	}
	c->open_confirm = fn;
	c->open_confirm_ctx = ctx;
}

ଶୂନ୍ୟ
channel_register_cleanup(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା id,
    channel_callback_fn *fn, ପୂର୍ଣ୍ଣସଂଖ୍ୟା do_close)
{
	Channel *c = channel_by_id(ssh, id);

	ଯଦି (c == ଖାଲି) {
		logit_f("%d: bad id", id);
		ଫେରନ୍ତୁ;
	}
	c->detach_user = fn;
	c->detach_close = do_close;
}

ଶୂନ୍ୟ
channel_cancel_cleanup(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା id)
{
	Channel *c = channel_by_id(ssh, id);

	ଯଦି (c == ଖାଲି) {
		logit_f("%d: bad id", id);
		ଫେରନ୍ତୁ;
	}
	c->detach_user = ଖାଲି;
	c->detach_close = 0;
}

ଶୂନ୍ୟ
channel_register_filter(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା id, channel_infilter_fn *ifn,
    channel_outfilter_fn *ofn, channel_filter_cleanup_fn *cfn, ଶୂନ୍ୟ *ctx)
{
	Channel *c = channel_lookup(ssh, id);

	ଯଦି (c == ଖାଲି) {
		logit_f("%d: bad id", id);
		ଫେରନ୍ତୁ;
	}
	c->ନିବେଶ_filter = ifn;
	c->output_filter = ofn;
	c->filter_ctx = ctx;
	c->filter_cleanup = cfn;
}

ଶୂନ୍ୟ
channel_set_fds(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା id, ପୂର୍ଣ୍ଣସଂଖ୍ୟା rfd, ପୂର୍ଣ୍ଣସଂଖ୍ୟା wfd, ପୂର୍ଣ୍ଣସଂଖ୍ୟା efd,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା extusage, ପୂର୍ଣ୍ଣସଂଖ୍ୟା nonblock, ପୂର୍ଣ୍ଣସଂଖ୍ୟା is_tty, u_int window_max)
{
	Channel *c = channel_lookup(ssh, id);
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (c == ଖାଲି || c->type != SSH_CHANNEL_LARVAL)
		fatal("channel_activate for non-larval channel %d.", id);
	ଯଦି (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);

	channel_register_fds(ssh, c, rfd, wfd, efd, extusage, nonblock, is_tty);
	c->type = SSH_CHANNEL_OPEN;
	channel_set_used_time(ssh, c);
	c->local_window = c->local_window_max = window_max;

	ଯଦି ((r = sshpkt_start(ssh, SSH2_ସନ୍ଦେଶ_CHANNEL_WINDOW_ADJUST)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_window)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i", c->self);
}

ସ୍ଥିର ଶୂନ୍ୟ
channel_pre_listener(ସଂରଚନା ssh *ssh, Channel *c)
{
	c->io_want = SSH_CHAN_IO_SOCK_R;
}

ସ୍ଥିର ଶୂନ୍ୟ
channel_pre_connecting(ସଂରଚନା ssh *ssh, Channel *c)
{
	debug3("channel %d: waiting for connection", c->self);
	c->io_want = SSH_CHAN_IO_SOCK_W;
}

ସ୍ଥିର ଶୂନ୍ୟ
channel_pre_open(ସଂରଚନା ssh *ssh, Channel *c)
{
	c->io_want = 0;
	ଯଦି (c->istate == CHAN_ନିବେଶ_OPEN &&
	    c->remote_window > 0 &&
	    sshbuf_len(c->ନିବେଶ) < c->remote_window &&
	    sshbuf_check_reserve(c->ନିବେଶ, CHAN_RBUF) == 0)
		c->io_want |= SSH_CHAN_IO_RFD;
	ଯଦି (c->ostate == CHAN_OUTPUT_OPEN ||
	    c->ostate == CHAN_OUTPUT_WAIT_DRAIN) {
		ଯଦି (sshbuf_len(c->output) > 0) {
			c->io_want |= SSH_CHAN_IO_WFD;
		} ଅନ୍ୟଥା ଯଦି (c->ostate == CHAN_OUTPUT_WAIT_DRAIN) {
			ଯଦି (CHANNEL_EFD_OUTPUT_ACTIVE(c))
				debug2("channel %d: "
				    "obuf_empty delayed efd %d/(%zu)", c->self,
				    c->efd, sshbuf_len(c->extended));
			ଅନ୍ୟଥା
				chan_obuf_empty(ssh, c);
		}
	}
	/** XXX check close conditions, too */
	ଯଦି (c->efd != -1 && !(c->istate == CHAN_ନିବେଶ_CLOSED &&
	    c->ostate == CHAN_OUTPUT_CLOSED)) {
		ଯଦି (c->extended_usage == CHAN_EXTENDED_WRITE &&
		    sshbuf_len(c->extended) > 0)
			c->io_want |= SSH_CHAN_IO_EFD_W;
		ଅନ୍ୟଥା ଯଦି (c->efd != -1 && !(c->flags & CHAN_EOF_SENT) &&
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
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
x11_open_helper(ସଂରଚନା ssh *ssh, ସଂରଚନା sshbuf *b)
{
	ସଂରଚନା ssh_channels *sc = ssh->chanctxt;
	u_char *ucp;
	u_int proto_len, data_len;

	ଯଦି (sc->x11_saved_proto == ଖାଲି) {
		error("X11 forwarding opened before X11 forwarding requested");
		ଫେରନ୍ତୁ -1;
	}

	/* Is this being called after the refusal deadline? */
	ଯଦି (sc->x11_refuse_time != 0.0 &&
	    monotime_double() >= sc->x11_refuse_time) {
		verbose("Rejected X11 connection after ForwardX11Timeout "
		    "expired");
		ଫେରନ୍ତୁ -1;
	}

	/* Check if the fixed size part of the packet is in buffer. */
	ଯଦି (sshbuf_len(b) < 12)
		ଫେରନ୍ତୁ 0;

	/* Parse the lengths of variable-length fields. */
	ucp = sshbuf_mutable_ptr(b);
	ଯଦି (ucp[0] == 0x42) {	/* Byte order MSB first. */
		proto_len = 256 * ucp[6] + ucp[7];
		data_len = 256 * ucp[8] + ucp[9];
	} ଅନ୍ୟଥା ଯଦି (ucp[0] == 0x6c) {	/* Byte order LSB first. */
		proto_len = ucp[6] + 256 * ucp[7];
		data_len = ucp[8] + 256 * ucp[9];
	} ଅନ୍ୟଥା {
		debug2("Initial X11 packet contains bad byte order byte: 0x%x",
		    ucp[0]);
		ଫେରନ୍ତୁ -1;
	}

	/* Check if the whole packet is in buffer. */
	ଯଦି (sshbuf_len(b) <
	    12 + ((proto_len + 3) & ~3) + ((data_len + 3) & ~3))
		ଫେରନ୍ତୁ 0;

	/* Check if authentication protocol matches. */
	ଯଦି (proto_len != strlen(sc->x11_saved_proto) ||
	    memcmp(ucp + 12, sc->x11_saved_proto, proto_len) != 0) {
		debug2("X11 connection uses different authentication protocol.");
		ଫେରନ୍ତୁ -1;
	}
	/* Check if authentication data matches our fake data. */
	ଯଦି (data_len != sc->x11_fake_data_len ||
	    timingsafe_bcmp(ucp + 12 + ((proto_len + 3) & ~3),
		sc->x11_fake_data, sc->x11_fake_data_len) != 0) {
		debug2("X11 auth data does not match fake data.");
		ଫେରନ୍ତୁ -1;
	}
	/* Check fake data length */
	ଯଦି (sc->x11_fake_data_len != sc->x11_saved_data_len) {
		error("X11 fake_data_len %d != saved_data_len %d",
		    sc->x11_fake_data_len, sc->x11_saved_data_len);
		ଫେରନ୍ତୁ -1;
	}
	/*
	 * Received authentication protocol and data match
	 * our fake data. Substitute the fake data with real
	 * data.
	 */
	memcpy(ucp + 12 + ((proto_len + 3) & ~3),
	    sc->x11_saved_data, sc->x11_saved_data_len);
	ଫେରନ୍ତୁ 1;
}

ଶୂନ୍ୟ
channel_force_close(ସଂରଚନା ssh *ssh, Channel *c, ପୂର୍ଣ୍ଣସଂଖ୍ୟା abandon)
{
	debug3_f("channel %d: forcibly closing", c->self);
	ଯଦି (c->istate == CHAN_ନିବେଶ_OPEN)
		chan_read_failed(ssh, c);
	ଯଦି (c->istate == CHAN_ନିବେଶ_WAIT_DRAIN) {
		sshbuf_reset(c->ନିବେଶ);
		chan_ibuf_empty(ssh, c);
	}
	ଯଦି (c->ostate == CHAN_OUTPUT_OPEN ||
	    c->ostate == CHAN_OUTPUT_WAIT_DRAIN) {
		sshbuf_reset(c->output);
		chan_write_failed(ssh, c);
	}
	ଯଦି (c->detach_user)
		c->detach_user(ssh, c->self, 1, ଖାଲି);
	ଯଦି (c->efd != -1)
		channel_close_fd(ssh, c, &c->efd);
	ଯଦି (abandon)
		c->type = SSH_CHANNEL_ABANDONED;
	/* exempt from inactivity timeouts */
	c->inactive_deadline = 0;
	c->lastused = 0;
}

ସ୍ଥିର ଶୂନ୍ୟ
channel_pre_x11_open(ସଂରଚନା ssh *ssh, Channel *c)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret = x11_open_helper(ssh, c->output);

	/* c->force_drain = 1; */

	ଯଦି (ret == 1) {
		c->type = SSH_CHANNEL_OPEN;
		channel_set_used_time(ssh, c);
		channel_pre_open(ssh, c);
	} ଅନ୍ୟଥା ଯଦି (ret == -1) {
		logit("X11 connection rejected because of wrong "
		    "authentication.");
		debug2("X11 rejected %d i%d/o%d",
		    c->self, c->istate, c->ostate);
		channel_force_close(ssh, c, 0);
	}
}

ସ୍ଥିର ଶୂନ୍ୟ
channel_pre_mux_client(ସଂରଚନା ssh *ssh, Channel *c)
{
	c->io_want = 0;
	ଯଦି (c->istate == CHAN_ନିବେଶ_OPEN && !c->mux_pause &&
	    sshbuf_check_reserve(c->ନିବେଶ, CHAN_RBUF) == 0)
		c->io_want |= SSH_CHAN_IO_RFD;
	ଯଦି (c->istate == CHAN_ନିବେଶ_WAIT_DRAIN) {
		/* clear buffer immediately (discard any partial packet) */
		sshbuf_reset(c->ନିବେଶ);
		chan_ibuf_empty(ssh, c);
		/* Start output drain. XXX just kill chan? */
		chan_rcvd_oclose(ssh, c);
	}
	ଯଦି (c->ostate == CHAN_OUTPUT_OPEN ||
	    c->ostate == CHAN_OUTPUT_WAIT_DRAIN) {
		ଯଦି (sshbuf_len(c->output) > 0)
			c->io_want |= SSH_CHAN_IO_WFD;
		ଅନ୍ୟଥା ଯଦି (c->ostate == CHAN_OUTPUT_WAIT_DRAIN)
			chan_obuf_empty(ssh, c);
	}
}

ସ୍ଥିର ଧାଡ଼ିଭିତରେ ପୂର୍ଣ୍ଣସଂଖ୍ୟା
socks_decode_error(Channel *c, ପୂର୍ଣ୍ଣସଂଖ୍ୟା status, ଅଚଳ ଅକ୍ଷର *func, ଅଚଳ ଅକ୍ଷର *ସନ୍ଦେଶ)
{
	ଯଦି (status == SSH_ERR_MESSAGE_INCOMPLETE)
		ଫେରନ୍ତୁ 0;
	ଅନ୍ୟଥା {
		debug_r(status, "%s: channel %d: decode %s",
		    func, c->self, ସନ୍ଦେଶ);
		ଫେରନ୍ତୁ -1;
	}
}

/* try to decode a socks4 header */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
channel_decode_socks4(Channel *c, ସଂରଚନା sshbuf *ନିବେଶ, ସଂରଚନା sshbuf *output)
{
	uint8_t socks_ver, socks_cmd, dest_addr[4];
	uint16_t dest_port;
	ଅକ୍ଷର *user = ଖାଲି, *host = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା success = -1, socks4a = 0, r;
	ସଂରଚନା sshbuf *b = ଖାଲି;

	ଯଦି (sshbuf_len(ନିବେଶ) < 9)
		ଫେରନ୍ତୁ 0;

	/* We may not have a complete message, so work on a dup of the buffer */
	ଯଦି ((b = sshbuf_fromb(ନିବେଶ)) == ଖାଲି)
		fatal_f("sshbuf_fromb failed");

	debug2("channel %d: decode socks4", c->self);
	ଯଦି ((r = sshbuf_get_u8(b, &socks_ver)) != 0 ||
	    (r = sshbuf_get_u8(b, &socks_cmd)) != 0 ||
	    (r = sshbuf_get_u16(b, &dest_port)) != 0 ||
	    (r = sshbuf_get(b, &dest_addr, ଆକାର(dest_addr))) != 0 ||
	    (r = sshbuf_get_nulterminated_string(b, 1024, &user, ଖାଲି)) != 0) {
		success = socks_decode_error(c, r, __func__, "header");
		ଯାଅ out;
	}

	/* Is this a SOCKS4A request? (indicated by an address of 0.0.0.x) */
	ଯଦି (dest_addr[0] == 0 && dest_addr[1] == 0 &&
	    dest_addr[2] == 0 && dest_addr[3] != 0) {
		/* If so, then the hostname follows, also nul-terminated */
		ଯଦି ((r = sshbuf_get_nulterminated_string(b, 1024,
		    &host, ଖାଲି)) != 0) {
			success = socks_decode_error(c, r, __func__, "host");
			ଯାଅ out;
		}
		socks4a = 1;
	} ଅନ୍ୟଥା {
		/* Plain SOCKS4 passes an IPv4 binary address; reconstruct */
		xasprintf(&host, "%d.%d.%d.%d",
		    dest_addr[0], dest_addr[1], dest_addr[2], dest_addr[3]);
	}

	/* We have a complete SOCKS4 message; consume it from input */
	ଯଦି ((r = sshbuf_consume_upto_child(ନିବେଶ, b)) != 0)
		fatal_fr(r, "channel %d: consume", c->self);

	/* Handle the request */
	debug2("channel %d: %s: user=\"%s\" command=%d destination=[%s]:%d",
	    c->self, socks4a ? "SOCKS4A" : "SOCKS4", user, (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)socks_cmd,
	    host, dest_port);
	ଯଦି (socks_cmd != 1) {
		debug("channel %d: cannot handle %s command 0x%02x",
		    c->self, socks4a ? "SOCKS4A" : "SOCKS4", socks_cmd);
		ଯାଅ out;
	}
	ମୁକ୍ତ(c->path);
	c->path = host;
	host = ଖାଲି; /* transferred */
	c->host_port = dest_port;

	/* Reply to the SOCKS4 client */
	ଯଦି ((r = sshbuf_put_u8(output, 0)) != 0 ||	/* vn: 0 for reply */
	    (r = sshbuf_put_u8(output, 90)) != 0 ||	/* cd: req granted */
	    (r = sshbuf_put_u16(output, 0)) != 0 ||	/* port: ignored */
	    (r = sshbuf_put_u32(output, ntohl(INADDR_ANY))) != 0) /* ignored */
		fatal_fr(r, "channel %d: compose reply", c->self);

	/* success */
	success = 1;
 out:
	sshbuf_free(b);
	ମୁକ୍ତ(user);
	ମୁକ୍ତ(host);
	ଫେରନ୍ତୁ success;
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
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
channel_socks5_check_auth(Channel *c, ସଂରଚନା sshbuf *b, ସଂରଚନା sshbuf *ନିବେଶ,
    ସଂରଚନା sshbuf *output)
{
	uint8_t socks_ver;
	uint8_t nmethods, method;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	u_int i, found;

	/* format: ver | nmethods | methods */
	ଯଦି ((r = sshbuf_get_u8(b, &socks_ver)) != 0)
		ଫେରନ୍ତୁ socks_decode_error(c, r, __func__, "version");
	ଯଦି (socks_ver != 5) /* shouldn't happen; checked by caller^2 */
		fatal_fr(r, "channel %d: internal error: not socks5", c->self);
	ଯଦି ((r = sshbuf_get_u8(b, &nmethods)) != 0)
		ଫେରନ୍ତୁ socks_decode_error(c, r, __func__, "methods");
	ପାଇଁ (found = i = 0; i < nmethods; i++) {
		ଯଦି ((r = sshbuf_get_u8(b, &method)) != 0)
			ଫେରନ୍ତୁ socks_decode_error(c, r, __func__, "method");
		ଯଦି (method == SSH_SOCKS5_NOAUTH)
			found = 1;
	}
	ଯଦି (!found) {
		debug("channel %d: didn't request SSH_SOCKS5_NOAUTH", c->self);
		ଫେରନ୍ତୁ -1;
	}
	/* Consume completed request */
	ଯଦି ((r = sshbuf_consume_upto_child(ନିବେଶ, b)) != 0)
		fatal_fr(r, "channel %d: consume", c->self);

	/* Compose reply: version, method */
	ଯଦି ((r = sshbuf_put_u8(output, 0x05)) != 0 ||
	    (r = sshbuf_put_u8(output, SSH_SOCKS5_NOAUTH)) != 0)
		fatal_fr(r, "channel %d: append reply", c->self);
	/* success */
	debug2("channel %d: socks5 auth done", c->self);
	ଫେରନ୍ତୁ 1;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
channel_decode_socks5(Channel *c, ସଂରଚନା sshbuf *ନିବେଶ, ସଂରଚନା sshbuf *output)
{
	uint8_t socks_ver, socks_cmd, socks_reserved, socks_atyp, addrlen;
	uint16_t dest_port;
	ଅକ୍ଷର dest_addr[255+1], ntop[INET6_ADDRSTRLEN];
	u_int af;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, success = -1;;
	ସଂରଚନା sshbuf *b = ଖାଲି;

	debug2("channel %d: decode socks5 %s", c->self,
	    (c->flags & SSH_SOCKS5_AUTHDONE) ? "request" : "auth");

	/* We may not have a complete message, so work on a dup of the buffer */
	ଯଦି ((b = sshbuf_fromb(ନିବେଶ)) == ଖାଲି)
		fatal_f("sshbuf_fromb failed");

	ଯଦି (!(c->flags & SSH_SOCKS5_AUTHDONE)) {
		ଯଦି ((r = channel_socks5_check_auth(c, b, ନିବେଶ, output)) != 1) {
			success = r;
			ଯାଅ out;
		}
		c->flags |= SSH_SOCKS5_AUTHDONE;
		/* Continue to parse request in case client speculated ahead */
	}

	/* Request messages (auth or connect) always start with the version */
	ଯଦି ((r = sshbuf_get_u8(b, &socks_ver)) != 0) {
		success = socks_decode_error(c, r, __func__, "version");
		ଯାଅ out;
	}
	ଯଦି (socks_ver != 5) /* shouldn't happen */
		fatal_fr(r, "channel %d: internal error: not socks5", c->self);

	/* Parse SOCKS5 request header */
	debug2("channel %d: socks5 post auth", c->self);
	ଯଦି ((r = sshbuf_get_u8(b, &socks_cmd)) != 0 ||
	    (r = sshbuf_get_u8(b, &socks_reserved)) != 0 ||
	    (r = sshbuf_get_u8(b, &socks_atyp)) != 0) {
		success = socks_decode_error(c, r, __func__, "request header");
		ଯାଅ out;
	}

	ଯଦି (socks_ver != 0x05 ||
	    socks_cmd != SSH_SOCKS5_CONNECT ||
	    socks_reserved != 0x00) {
		debug2("channel %d: only socks5 connect supported", c->self);
		ଯାଅ out;
	}

	ବାଛ (socks_atyp) {
	ସ୍ଥିତି SSH_SOCKS5_IPV4:
		addrlen = 4;
		af = AF_INET;
		ଭାଙ୍ଗ;
	ସ୍ଥିତି SSH_SOCKS5_DOMAIN:
		ଯଦି ((r = sshbuf_get_u8(b, &addrlen)) != 0) {
			success = socks_decode_error(c, r, __func__, "addrlen");
			ଯାଅ out;
		}
		af = -1;
		ଭାଙ୍ଗ;
	ସ୍ଥିତି SSH_SOCKS5_IPV6:
		addrlen = 16;
		af = AF_INET6;
		ଭାଙ୍ଗ;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		debug2("channel %d: bad socks5 atyp %d", c->self, socks_atyp);
		ଯାଅ out;
	}
	ଯଦି ((r = sshbuf_get(b, &dest_addr, addrlen)) != 0 ||
	    (r = sshbuf_get_u16(b, &dest_port)) != 0) {
		success = socks_decode_error(c, r, __func__, "addr/port");
		ଯାଅ out;
	}
	dest_addr[addrlen] = '\0';

	/* We have a complete SOCKS5 request; consume it from input */
	ଯଦି ((r = sshbuf_consume_upto_child(ନିବେଶ, b)) != 0)
		fatal_fr(r, "channel %d: consume", c->self);

	ମୁକ୍ତ(c->path);
	c->path = ଖାଲି;
	ଯଦି (socks_atyp == SSH_SOCKS5_DOMAIN)
		c->path = xstrdup(dest_addr);
	ଅନ୍ୟଥା {
		ଯଦି (inet_ntop(af, dest_addr, ntop, ଆକାର(ntop)) == ଖାଲି)
			ଫେରନ୍ତୁ -1;
		c->path = xstrdup(ntop);
	}
	c->host_port = dest_port;

	debug2("channel %d: dynamic request: socks5 host %s port %u command %u",
	    c->self, c->path, c->host_port, socks_cmd);

	/* Reply */
	ଯଦି ((r = sshbuf_put_u8(output, 0x05)) != 0 ||	/* version */
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
	ଫେରନ୍ତୁ success;
}

Channel *
channel_connect_stdio_fwd(ସଂରଚନା ssh *ssh,
    ଅଚଳ ଅକ୍ଷର *host_to_connect, ପୂର୍ଣ୍ଣସଂଖ୍ୟା port_to_connect,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା in, ପୂର୍ଣ୍ଣସଂଖ୍ୟା out, ପୂର୍ଣ୍ଣସଂଖ୍ୟା nonblock)
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

	ଫେରନ୍ତୁ c;
}

/* dynamic port forwarding */
ସ୍ଥିର ଶୂନ୍ୟ
channel_pre_dynamic(ସଂରଚନା ssh *ssh, Channel *c)
{
	u_int have;
	u_char ver;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, ret;

	c->io_want = 0;
	have = sshbuf_len(c->ନିବେଶ);
	debug2("channel %d: pre_dynamic: have %d", c->self, have);
	/* sshbuf_dump(c->input, stderr); */
	/* check if the fixed size part of the packet is in buffer. */
	ଯଦି (have < 3) {
		/* need more */
		c->io_want |= SSH_CHAN_IO_RFD;
		ଫେରନ୍ତୁ;
	}
	/* try to guess the protocol */
	ଯଦି ((r = sshbuf_peek_u8(c->ନିବେଶ, 0, &ver)) != 0)
		fatal_fr(r, "sshbuf_peek_u8");
	ବାଛ (ver) {
	ସ୍ଥିତି 0x04:
		ret = channel_decode_socks4(c, c->ନିବେଶ, c->output);
		ଭାଙ୍ଗ;
	ସ୍ଥିତି 0x05:
		ret = channel_decode_socks5(c, c->ନିବେଶ, c->output);
		ଭାଙ୍ଗ;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		debug2_f("channel %d: unknown SOCKS version %u", c->self, ver);
		ret = -1;
		ଭାଙ୍ଗ;
	}
	ଯଦି (ret < 0) {
		chan_mark_dead(ssh, c);
	} ଅନ୍ୟଥା ଯଦି (ret == 0) {
		debug2("channel %d: pre_dynamic: need more", c->self);
		/* need more */
		c->io_want |= SSH_CHAN_IO_RFD;
		ଯଦି (sshbuf_len(c->output))
			c->io_want |= SSH_CHAN_IO_WFD;
	} ଅନ୍ୟଥା {
		/* switch to the next state */
		c->type = SSH_CHANNEL_OPENING;
		port_open_helper(ssh, c, "direct-tcpip");
	}
}

/* simulate read-error */
ସ୍ଥିର ଶୂନ୍ୟ
rdynamic_close(ସଂରଚନା ssh *ssh, Channel *c)
{
	c->type = SSH_CHANNEL_OPEN;
	channel_force_close(ssh, c, 0);
}

/* reverse dynamic port forwarding */
ସ୍ଥିର ଶୂନ୍ୟ
channel_before_prepare_io_rdynamic(ସଂରଚନା ssh *ssh, Channel *c)
{
	ଅଚଳ u_char *p;
	u_int have, len;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, ret;

	have = sshbuf_len(c->output);
	debug2("channel %d: pre_rdynamic: have %d", c->self, have);
	/* sshbuf_dump(c->output, stderr); */
	/* EOF received */
	ଯଦି (c->flags & CHAN_EOF_RCVD) {
		ଯଦି ((r = sshbuf_consume(c->output, have)) != 0)
			fatal_fr(r, "channel %d: consume", c->self);
		rdynamic_close(ssh, c);
		ଫେରନ୍ତୁ;
	}
	/* check if the fixed size part of the packet is in buffer. */
	ଯଦି (have < 3)
		ଫେରନ୍ତୁ;
	/* try to guess the protocol */
	p = sshbuf_ptr(c->output);
	ବାଛ (p[0]) {
	ସ୍ଥିତି 0x04:
		/* switch input/output for reverse forwarding */
		ret = channel_decode_socks4(c, c->output, c->ନିବେଶ);
		ଭାଙ୍ଗ;
	ସ୍ଥିତି 0x05:
		ret = channel_decode_socks5(c, c->output, c->ନିବେଶ);
		ଭାଙ୍ଗ;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		ret = -1;
		ଭାଙ୍ଗ;
	}
	ଯଦି (ret < 0) {
		rdynamic_close(ssh, c);
	} ଅନ୍ୟଥା ଯଦି (ret == 0) {
		debug2("channel %d: pre_rdynamic: need more", c->self);
		/* send socks request to peer */
		len = sshbuf_len(c->ନିବେଶ);
		ଯଦି (len > 0 && len < c->remote_window) {
			ଯଦି ((r = sshpkt_start(ssh, SSH2_ସନ୍ଦେଶ_CHANNEL_DATA)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
			    (r = sshpkt_put_stringb(ssh, c->ନିବେଶ)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0) {
				fatal_fr(r, "channel %i: rdynamic", c->self);
			}
			ଯଦି ((r = sshbuf_consume(c->ନିବେଶ, len)) != 0)
				fatal_fr(r, "channel %d: consume", c->self);
			c->remote_window -= len;
		}
	} ଅନ୍ୟଥା ଯଦି (rdynamic_connect_finish(ssh, c) < 0) {
		/* the connect failed */
		rdynamic_close(ssh, c);
	}
}

/* This is our fake X11 server socket. */
ସ୍ଥିର ଶୂନ୍ୟ
channel_post_x11_listener(ସଂରଚନା ssh *ssh, Channel *c)
{
	Channel *nc;
	ସଂରଚନା sockaddr_storage addr;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, newsock, oerrno, remote_port;
	socklen_t addrlen;
	ଅକ୍ଷର buf[16384], *remote_ipaddr;

	ଯଦି ((c->io_ready & SSH_CHAN_IO_SOCK_R) == 0)
		ଫେରନ୍ତୁ;

	debug("X11 connection requested.");
	addrlen = ଆକାର(addr);
	newsock = accept(c->sock, (ସଂରଚନା sockaddr *)&addr, &addrlen);
	ଯଦି (c->single_connection) {
		oerrno = errno;
		debug2("single_connection: closing X11 listener.");
		channel_close_fd(ssh, c, &c->sock);
		chan_mark_dead(ssh, c);
		errno = oerrno;
	}
	ଯଦି (newsock == -1) {
		ଯଦି (errno != EINTR && errno != EWOULDBLOCK &&
		    errno != ECONNABORTED)
			error("accept: %.100s", strerror(errno));
		ଯଦି (errno == EMFILE || errno == ENFILE)
			c->notbefore = monotime_double() + 1.0;
		ଫେରନ୍ତୁ;
	}
	set_nodelay(newsock);
	ଯଦି (ssh->chanctxt->want_tcp_keepalive)
		set_keepalive(newsock); /* logs errors */
	remote_ipaddr = get_peer_ipaddr(newsock);
	remote_port = get_peer_port(newsock);
	snprintf(buf, ଆକାର buf, "X11 connection from %.200s port %d",
	    remote_ipaddr, remote_port);

	nc = channel_new(ssh, "x11-connection",
	    SSH_CHANNEL_OPENING, newsock, newsock, -1,
	    c->local_window_max, c->local_maxpacket, 0, buf, 1);
	open_preamble(ssh, __func__, nc, "x11");
	ଯଦି ((r = sshpkt_put_cstring(ssh, remote_ipaddr)) != 0 ||
	    (r = sshpkt_put_u32(ssh, remote_port)) != 0) {
		fatal_fr(r, "channel %i: reply", c->self);
	}
	ଯଦି ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i: send", c->self);
	ମୁକ୍ତ(remote_ipaddr);
}

ସ୍ଥିର ଶୂନ୍ୟ
port_open_helper(ସଂରଚନା ssh *ssh, Channel *c, ଅକ୍ଷର *rtype)
{
	ଅକ୍ଷର *local_ipaddr = get_local_ipaddr(c->sock);
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା local_port = c->sock == -1 ? 65536 : get_local_port(c->sock);
	ଅକ୍ଷର *remote_ipaddr = get_peer_ipaddr(c->sock);
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା remote_port = get_peer_port(c->sock);
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (remote_port == -1) {
		/* Fake addr/port to appease peers that validate it (Tectia) */
		ମୁକ୍ତ(remote_ipaddr);
		remote_ipaddr = xstrdup("127.0.0.1");
		remote_port = 65535;
	}

	ମୁକ୍ତ(c->remote_name);
	xasprintf(&c->remote_name,
	    "%s: listening port %d for %.100s port %d, "
	    "connect from %.200s port %d to %.100s port %d",
	    rtype, c->listening_port, c->path, c->host_port,
	    remote_ipaddr, remote_port, local_ipaddr, local_port);

	open_preamble(ssh, __func__, c, rtype);
	ଯଦି (strcmp(rtype, "direct-tcpip") == 0) {
		/* target host, port */
		ଯଦି ((r = sshpkt_put_cstring(ssh, c->path)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->host_port)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	} ଅନ୍ୟଥା ଯଦି (strcmp(rtype, "direct-streamlocal@openssh.com") == 0) {
		/* target path */
		ଯଦି ((r = sshpkt_put_cstring(ssh, c->path)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	} ଅନ୍ୟଥା ଯଦି (strcmp(rtype, "forwarded-streamlocal@openssh.com") == 0) {
		/* listen path */
		ଯଦି ((r = sshpkt_put_cstring(ssh, c->path)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	} ଅନ୍ୟଥା {
		/* listen address, port */
		ଯଦି ((r = sshpkt_put_cstring(ssh, c->path)) != 0 ||
		    (r = sshpkt_put_u32(ssh, local_port)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	}
	ଯଦି (strcmp(rtype, "forwarded-streamlocal@openssh.com") == 0) {
		/* reserved for future owner/mode info */
		ଯଦି ((r = sshpkt_put_cstring(ssh, "")) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	} ଅନ୍ୟଥା {
		/* originator host and port */
		ଯଦି ((r = sshpkt_put_cstring(ssh, remote_ipaddr)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)remote_port)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	}
	ଯଦି ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i: send", c->self);
	ମୁକ୍ତ(remote_ipaddr);
	ମୁକ୍ତ(local_ipaddr);
}

ଶୂନ୍ୟ
channel_set_x11_refuse_time(ସଂରଚନା ssh *ssh, ଦ୍ୱିଗୁଣ refuse_time)
{
	ssh->chanctxt->x11_refuse_time = refuse_time;
}

/*
 * This socket is listening for connections to a forwarded TCP/IP port.
 */
ସ୍ଥିର ଶୂନ୍ୟ
channel_post_port_listener(ସଂରଚନା ssh *ssh, Channel *c)
{
	Channel *nc;
	ସଂରଚନା sockaddr_storage addr;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା newsock, nextstate;
	socklen_t addrlen;
	ଅକ୍ଷର *rtype;

	ଯଦି ((c->io_ready & SSH_CHAN_IO_SOCK_R) == 0)
		ଫେରନ୍ତୁ;

	debug("Connection to port %d forwarding to %.100s port %d requested.",
	    c->listening_port, c->path, c->host_port);

	ଯଦି (c->type == SSH_CHANNEL_RPORT_LISTENER) {
		nextstate = SSH_CHANNEL_OPENING;
		rtype = "forwarded-tcpip";
	} ଅନ୍ୟଥା ଯଦି (c->type == SSH_CHANNEL_RUNIX_LISTENER) {
		nextstate = SSH_CHANNEL_OPENING;
		rtype = "forwarded-streamlocal@openssh.com";
	} ଅନ୍ୟଥା ଯଦି (c->host_port == PORT_STREAMLOCAL) {
		nextstate = SSH_CHANNEL_OPENING;
		rtype = "direct-streamlocal@openssh.com";
	} ଅନ୍ୟଥା ଯଦି (c->host_port == 0) {
		nextstate = SSH_CHANNEL_DYNAMIC;
		rtype = "dynamic-tcpip";
	} ଅନ୍ୟଥା {
		nextstate = SSH_CHANNEL_OPENING;
		rtype = "direct-tcpip";
	}

	addrlen = ଆକାର(addr);
	newsock = accept(c->sock, (ସଂରଚନା sockaddr *)&addr, &addrlen);
	ଯଦି (newsock == -1) {
		ଯଦି (errno != EINTR && errno != EWOULDBLOCK &&
		    errno != ECONNABORTED)
			error("accept: %.100s", strerror(errno));
		ଯଦି (errno == EMFILE || errno == ENFILE)
			c->notbefore = monotime_double() + 1.0;
		ଫେରନ୍ତୁ;
	}
	ଯଦି (addr.ss_family == AF_INET || addr.ss_family == AF_INET6) {
		set_nodelay(newsock);
		ଯଦି (ssh->chanctxt->want_tcp_keepalive)
			set_keepalive(newsock); /* logs errors */
	}
	nc = channel_new(ssh, rtype, nextstate, newsock, newsock, -1,
	    c->local_window_max, c->local_maxpacket, 0, rtype, 1);
	nc->listening_port = c->listening_port;
	nc->host_port = c->host_port;
	ଯଦି (c->path != ଖାଲି)
		nc->path = xstrdup(c->path);

	ଯଦି (nextstate != SSH_CHANNEL_DYNAMIC)
		port_open_helper(ssh, nc, rtype);
}

/*
 * This is the authentication agent socket listening for connections from
 * clients.
 */
ସ୍ଥିର ଶୂନ୍ୟ
channel_post_auth_listener(ସଂରଚନା ssh *ssh, Channel *c)
{
	Channel *nc;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, newsock;
	ସଂରଚନା sockaddr_storage addr;
	socklen_t addrlen;

	ଯଦି ((c->io_ready & SSH_CHAN_IO_SOCK_R) == 0)
		ଫେରନ୍ତୁ;

	addrlen = ଆକାର(addr);
	newsock = accept(c->sock, (ସଂରଚନା sockaddr *)&addr, &addrlen);
	ଯଦି (newsock == -1) {
		error("accept from auth socket: %.100s", strerror(errno));
		ଯଦି (errno == EMFILE || errno == ENFILE)
			c->notbefore = monotime_double() + 1.0;
		ଫେରନ୍ତୁ;
	}
	nc = channel_new(ssh, "agent-connection",
	    SSH_CHANNEL_OPENING, newsock, newsock, -1,
	    c->local_window_max, c->local_maxpacket,
	    0, "accepted auth socket", 1);
	open_preamble(ssh, __func__, nc,
	    c->agent_new ? "agent-connect" : "auth-agent@openssh.com");
	ଯଦି ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i", c->self);
}

ସ୍ଥିର ଶୂନ୍ୟ
channel_post_connecting(ସଂରଚନା ssh *ssh, Channel *c)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା err = 0, sock, isopen, r;
	socklen_t sz = ଆକାର(err);

	ଯଦି ((c->io_ready & SSH_CHAN_IO_SOCK_W) == 0)
		ଫେରନ୍ତୁ;
	ଯଦି (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);
	ଯଦି (c->connect_ctx == ଖାଲି)
		fatal_f("channel %d: context missing", c->self);

	/* for rdynamic the OPEN_CONFIRMATION has been sent already */
	isopen = (c->type == SSH_CHANNEL_RDYNAMIC_FINISH);

	ଯଦି (getsockopt(c->sock, SOL_SOCKET, SO_ERROR, &err, &sz) == -1) {
		err = errno;
		error("getsockopt SO_ERROR failed");
	}

	ଯଦି (err == 0) {
		/* Non-blocking connection completed */
		debug("channel %d: connected to %s port %d",
		    c->self, c->connect_ctx->host, c->connect_ctx->port);
		channel_free_connect_ctx(c);
		c->type = SSH_CHANNEL_OPEN;
		channel_set_used_time(ssh, c);
		ଯଦି (isopen) {
			/* no message necessary */
		} ଅନ୍ୟଥା {
			ଯଦି ((r = sshpkt_start(ssh,
			    SSH2_ସନ୍ଦେଶ_CHANNEL_OPEN_CONFIRMATION)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_window)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "channel %i open confirm", c->self);
		}
		ଫେରନ୍ତୁ;
	}
	ଯଦି (err == EINTR || err == EAGAIN || err == EINPROGRESS)
		ଫେରନ୍ତୁ;

	/* Non-blocking connection failed */
	debug("channel %d: connection failed: %s", c->self, strerror(err));

	/* Try next address, if any */
	ଯଦି ((sock = connect_next(ssh, c->connect_ctx)) == -1) {
		/* Exhausted all addresses for this destination */
		error("connect_to %.100s port %d: failed.",
		    c->connect_ctx->host, c->connect_ctx->port);
		channel_free_connect_ctx(c);
		ଯଦି (isopen) {
			rdynamic_close(ssh, c);
		} ଅନ୍ୟଥା {
			ଯଦି ((r = sshpkt_start(ssh,
			    SSH2_ସନ୍ଦେଶ_CHANNEL_OPEN_FAILURE)) != 0 ||
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

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
channel_handle_rfd(ସଂରଚନା ssh *ssh, Channel *c)
{
	ଅକ୍ଷର buf[CHAN_RBUF];
	ssize_t len;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, force;
	size_t nr = 0, have, avail, maxlen = CHANNEL_MAX_READ;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା pty_zeroread = 0;

#ifdef PTY_ZEROREAD
	/* Bug on AIX: read(1) can return 0 for a non-closed fd */
	pty_zeroread = c->isatty;
#endif

	force = c->isatty && c->detach_close && c->istate != CHAN_ନିବେଶ_CLOSED;

	ଯଦି (!force && (c->io_ready & SSH_CHAN_IO_RFD) == 0)
		ଫେରନ୍ତୁ 1;
	ଯଦି ((avail = sshbuf_avail(c->ନିବେଶ)) == 0)
		ଫେରନ୍ତୁ 1; /* Shouldn't happen */

	/*
	 * For "simple" channels (i.e. not datagram or filtered), we can
	 * read directly to the channel buffer.
	 */
	ଯଦି (!pty_zeroread && c->ନିବେଶ_filter == ଖାଲି && !c->datagram) {
		/* Only OPEN channels have valid rwin */
		ଯଦି (c->type == SSH_CHANNEL_OPEN) {
			ଯଦି ((have = sshbuf_len(c->ନିବେଶ)) >= c->remote_window)
				ଫେରନ୍ତୁ 1; /* shouldn't happen */
			ଯଦି (maxlen > c->remote_window - have)
				maxlen = c->remote_window - have;
		}
		ଯଦି (maxlen > avail)
			maxlen = avail;
		ଯଦି ((r = sshbuf_read(c->rfd, c->ନିବେଶ, maxlen, &nr)) != 0) {
			ଯଦି (errno == EINTR || (!force &&
			    (errno == EAGAIN || errno == EWOULDBLOCK)))
				ଫେରନ୍ତୁ 1;
			debug2("channel %d: read failed rfd %d maxlen %zu: %s",
			    c->self, c->rfd, maxlen, ssh_err(r));
			ଯାଅ rfail;
		}
		ଯଦି (nr != 0)
			channel_set_used_time(ssh, c);
		ଫେରନ୍ତୁ 1;
	}

	errno = 0;
	len = ପଠ(c->rfd, buf, ଆକାର(buf));
	/* fixup AIX zero-length read with errno set to look more like errors */
	ଯଦି (pty_zeroread && len == 0 && errno != 0)
		len = -1;
	ଯଦି (len == -1 && (errno == EINTR ||
	    ((errno == EAGAIN || errno == EWOULDBLOCK) && !force)))
		ଫେରନ୍ତୁ 1;
	ଯଦି (len < 0 || (!pty_zeroread && len == 0)) {
		debug2("channel %d: read<=0 rfd %d len %zd: %s",
		    c->self, c->rfd, len,
		    len == 0 ? "closed" : strerror(errno));
 rfail:
		ଯଦି (c->type != SSH_CHANNEL_OPEN) {
			debug2("channel %d: not open", c->self);
			chan_mark_dead(ssh, c);
			ଫେରନ୍ତୁ -1;
		} ଅନ୍ୟଥା {
			chan_read_failed(ssh, c);
		}
		ଫେରନ୍ତୁ -1;
	}
	channel_set_used_time(ssh, c);
	ଯଦି (c->ନିବେଶ_filter != ଖାଲି) {
		ଯଦି (c->ନିବେଶ_filter(ssh, c, buf, len) == -1) {
			debug2("channel %d: filter stops", c->self);
			chan_read_failed(ssh, c);
		}
	} ଅନ୍ୟଥା ଯଦି (c->datagram) {
		ଯଦି ((r = sshbuf_put_string(c->ନିବେଶ, buf, len)) != 0)
			fatal_fr(r, "channel %i: put datagram", c->self);
	} ଅନ୍ୟଥା ଯଦି ((r = sshbuf_put(c->ନିବେଶ, buf, len)) != 0)
		fatal_fr(r, "channel %i: put data", c->self);

	ଫେରନ୍ତୁ 1;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
channel_handle_wfd(ସଂରଚନା ssh *ssh, Channel *c)
{
	ସଂରଚନା termios tio;
	u_char *data = ଖାଲି, *buf; /* XXX const; need filter API change */
	size_t dlen, olen = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, len;

	ଯଦି ((c->io_ready & SSH_CHAN_IO_WFD) == 0)
		ଫେରନ୍ତୁ 1;
	ଯଦି (sshbuf_len(c->output) == 0)
		ଫେରନ୍ତୁ 1;

	/* Send buffered output data to the socket. */
	olen = sshbuf_len(c->output);
	ଯଦି (c->output_filter != ଖାଲି) {
		ଯଦି ((buf = c->output_filter(ssh, c, &data, &dlen)) == ଖାଲି) {
			debug2("channel %d: filter stops", c->self);
			ଯଦି (c->type != SSH_CHANNEL_OPEN)
				chan_mark_dead(ssh, c);
			ଅନ୍ୟଥା
				chan_write_failed(ssh, c);
			ଫେରନ୍ତୁ -1;
		}
	} ଅନ୍ୟଥା ଯଦି (c->datagram) {
		ଯଦି ((r = sshbuf_get_string(c->output, &data, &dlen)) != 0)
			fatal_fr(r, "channel %i: get datagram", c->self);
		buf = data;
	} ଅନ୍ୟଥା {
		buf = data = sshbuf_mutable_ptr(c->output);
		dlen = sshbuf_len(c->output);
	}

	ଯଦି (c->datagram) {
		/* ignore truncated writes, datagrams might get lost */
		len = ଲିଖ(c->wfd, buf, dlen);
		ମୁକ୍ତ(data);
		ଯଦି (len == -1 && (errno == EINTR || errno == EAGAIN ||
		    errno == EWOULDBLOCK))
			ଫେରନ୍ତୁ 1;
		ଯଦି (len <= 0)
			ଯାଅ write_fail;
		ଯାଅ out;
	}

#ifdef _AIX
	/* XXX: Later AIX versions can't push as much data to tty */
	ଯଦି (c->wfd_isatty)
		dlen = MINIMUM(dlen, 8*1024);
#endif

	len = ଲିଖ(c->wfd, buf, dlen);
	ଯଦି (len == -1 &&
	    (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
		ଫେରନ୍ତୁ 1;
	ଯଦି (len <= 0) {
 write_fail:
		ଯଦି (c->type != SSH_CHANNEL_OPEN) {
			debug2("channel %d: not open", c->self);
			chan_mark_dead(ssh, c);
			ଫେରନ୍ତୁ -1;
		} ଅନ୍ୟଥା {
			chan_write_failed(ssh, c);
		}
		ଫେରନ୍ତୁ -1;
	}
	channel_set_used_time(ssh, c);
#ifndef BROKEN_TCGETATTR_ICANON
	ଯଦି (c->isatty && dlen >= 1 && buf[0] != '\r') {
		ଯଦି (tcgetattr(c->wfd, &tio) == 0 &&
		    !(tio.c_lflag & ECHO) && (tio.c_lflag & ICANON)) {
			/*
			 * Simulate echo to reduce the impact of
			 * traffic analysis. We need to match the
			 * size of a SSH2_MSG_CHANNEL_DATA message
			 * (4 byte channel id + buf)
			 */
			ଯଦି ((r = sshpkt_ସନ୍ଦେଶ_ignore(ssh, 4+len)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "channel %i: ignore", c->self);
		}
	}
#endif /* BROKEN_TCGETATTR_ICANON */
	ଯଦି ((r = sshbuf_consume(c->output, len)) != 0)
		fatal_fr(r, "channel %i: consume", c->self);
 out:
	c->local_consumed += olen - sshbuf_len(c->output);

	ଫେରନ୍ତୁ 1;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
channel_handle_efd_write(ସଂରଚନା ssh *ssh, Channel *c)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	ssize_t len;

	ଯଦି ((c->io_ready & SSH_CHAN_IO_EFD_W) == 0)
		ଫେରନ୍ତୁ 1;
	ଯଦି (sshbuf_len(c->extended) == 0)
		ଫେରନ୍ତୁ 1;

	len = ଲିଖ(c->efd, sshbuf_ptr(c->extended),
	    sshbuf_len(c->extended));
	debug2("channel %d: written %zd to efd %d", c->self, len, c->efd);
	ଯଦି (len == -1 && (errno == EINTR || errno == EAGAIN ||
	    errno == EWOULDBLOCK))
		ଫେରନ୍ତୁ 1;
	ଯଦି (len <= 0) {
		debug2("channel %d: closing write-efd %d", c->self, c->efd);
		channel_close_fd(ssh, c, &c->efd);
	} ଅନ୍ୟଥା {
		ଯଦି ((r = sshbuf_consume(c->extended, len)) != 0)
			fatal_fr(r, "channel %i: consume", c->self);
		c->local_consumed += len;
		channel_set_used_time(ssh, c);
	}
	ଫେରନ୍ତୁ 1;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
channel_handle_efd_read(ସଂରଚନା ssh *ssh, Channel *c)
{
	ଅକ୍ଷର buf[CHAN_RBUF];
	ssize_t len;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, force;

	force = c->isatty && c->detach_close && c->istate != CHAN_ନିବେଶ_CLOSED;

	ଯଦି (!force && (c->io_ready & SSH_CHAN_IO_EFD_R) == 0)
		ଫେରନ୍ତୁ 1;

	len = ପଠ(c->efd, buf, ଆକାର(buf));
	debug2("channel %d: read %zd from efd %d", c->self, len, c->efd);
	ଯଦି (len == -1 && (errno == EINTR || ((errno == EAGAIN ||
	    errno == EWOULDBLOCK) && !force)))
		ଫେରନ୍ତୁ 1;
	ଯଦି (len <= 0) {
		debug2("channel %d: closing read-efd %d", c->self, c->efd);
		channel_close_fd(ssh, c, &c->efd);
		ଫେରନ୍ତୁ 1;
	}
	channel_set_used_time(ssh, c);
	ଯଦି (c->extended_usage == CHAN_EXTENDED_IGNORE)
		debug3("channel %d: discard efd", c->self);
	ଅନ୍ୟଥା ଯଦି ((r = sshbuf_put(c->extended, buf, len)) != 0)
		fatal_fr(r, "channel %i: append", c->self);
	ଫେରନ୍ତୁ 1;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
channel_handle_efd(ସଂରଚନା ssh *ssh, Channel *c)
{
	ଯଦି (c->efd == -1)
		ଫେରନ୍ତୁ 1;

	/** XXX handle drain efd, too */

	ଯଦି (c->extended_usage == CHAN_EXTENDED_WRITE)
		ଫେରନ୍ତୁ channel_handle_efd_write(ssh, c);
	ଅନ୍ୟଥା ଯଦି (c->extended_usage == CHAN_EXTENDED_READ ||
	    c->extended_usage == CHAN_EXTENDED_IGNORE)
		ଫେରନ୍ତୁ channel_handle_efd_read(ssh, c);

	ଫେରନ୍ତୁ 1;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
channel_check_window(ସଂରଚନା ssh *ssh, Channel *c)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (c->type == SSH_CHANNEL_OPEN &&
	    !(c->flags & (CHAN_CLOSE_SENT|CHAN_CLOSE_RCVD)) &&
	    ((c->local_window_max - c->local_window >
	    c->local_maxpacket*3) ||
	    c->local_window < c->local_window_max/2) &&
	    c->local_consumed > 0) {
		ଯଦି (!c->have_remote_id)
			fatal_f("channel %d: no remote id", c->self);
		ଯଦି ((r = sshpkt_start(ssh,
		    SSH2_ସନ୍ଦେଶ_CHANNEL_WINDOW_ADJUST)) != 0 ||
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
	ଫେରନ୍ତୁ 1;
}

ସ୍ଥିର ଶୂନ୍ୟ
channel_post_open(ସଂରଚନା ssh *ssh, Channel *c)
{
	channel_handle_rfd(ssh, c);
	channel_handle_wfd(ssh, c);
	channel_handle_efd(ssh, c);
	channel_check_window(ssh, c);
}

ସ୍ଥିର u_int
read_mux(ସଂରଚନା ssh *ssh, Channel *c, u_int need)
{
	ଅକ୍ଷର buf[CHAN_RBUF];
	ssize_t len;
	u_int rlen;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (sshbuf_len(c->ନିବେଶ) < need) {
		rlen = need - sshbuf_len(c->ନିବେଶ);
		len = ପଠ(c->rfd, buf, MINIMUM(rlen, CHAN_RBUF));
		ଯଦି (len == -1 && (errno == EINTR || errno == EAGAIN))
			ଫେରନ୍ତୁ sshbuf_len(c->ନିବେଶ);
		ଯଦି (len <= 0) {
			debug2("channel %d: ctl read<=0 rfd %d len %zd",
			    c->self, c->rfd, len);
			chan_read_failed(ssh, c);
			ଫେରନ୍ତୁ 0;
		} ଅନ୍ୟଥା ଯଦି ((r = sshbuf_put(c->ନିବେଶ, buf, len)) != 0)
			fatal_fr(r, "channel %i: append", c->self);
	}
	ଫେରନ୍ତୁ sshbuf_len(c->ନିବେଶ);
}

ସ୍ଥିର ଶୂନ୍ୟ
channel_post_mux_client_read(ସଂରଚନା ssh *ssh, Channel *c)
{
	u_int need;

	ଯଦି ((c->io_ready & SSH_CHAN_IO_RFD) == 0)
		ଫେରନ୍ତୁ;
	ଯଦି (c->istate != CHAN_ନିବେଶ_OPEN && c->istate != CHAN_ନିବେଶ_WAIT_DRAIN)
		ଫେରନ୍ତୁ;
	ଯଦି (c->mux_pause)
		ଫେରନ୍ତୁ;

	/*
	 * Don't not read past the precise end of packets to
	 * avoid disrupting fd passing.
	 */
	ଯଦି (read_mux(ssh, c, 4) < 4) /* read header */
		ଫେରନ୍ତୁ;
	/* XXX sshbuf_peek_u32 */
	need = PEEK_U32(sshbuf_ptr(c->ନିବେଶ));
#define CHANNEL_MUX_MAX_PACKET	(256 * 1024)
	ଯଦି (need > CHANNEL_MUX_MAX_PACKET) {
		debug2("channel %d: packet too big %u > %u",
		    c->self, CHANNEL_MUX_MAX_PACKET, need);
		chan_rcvd_oclose(ssh, c);
		ଫେରନ୍ତୁ;
	}
	ଯଦି (read_mux(ssh, c, need + 4) < need + 4) /* read body */
		ଫେରନ୍ତୁ;
	ଯଦି (c->mux_rcb(ssh, c) != 0) {
		debug("channel %d: mux_rcb failed", c->self);
		chan_mark_dead(ssh, c);
		ଫେରନ୍ତୁ;
	}
}

ସ୍ଥିର ଶୂନ୍ୟ
channel_post_mux_client_write(ସଂରଚନା ssh *ssh, Channel *c)
{
	ssize_t len;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((c->io_ready & SSH_CHAN_IO_WFD) == 0)
		ଫେରନ୍ତୁ;
	ଯଦି (sshbuf_len(c->output) == 0)
		ଫେରନ୍ତୁ;

	len = ଲିଖ(c->wfd, sshbuf_ptr(c->output), sshbuf_len(c->output));
	ଯଦି (len == -1 && (errno == EINTR || errno == EAGAIN))
		ଫେରନ୍ତୁ;
	ଯଦି (len <= 0) {
		chan_mark_dead(ssh, c);
		ଫେରନ୍ତୁ;
	}
	ଯଦି ((r = sshbuf_consume(c->output, len)) != 0)
		fatal_fr(r, "channel %i: consume", c->self);
}

ସ୍ଥିର ଶୂନ୍ୟ
channel_post_mux_client(ସଂରଚନା ssh *ssh, Channel *c)
{
	channel_post_mux_client_read(ssh, c);
	channel_post_mux_client_write(ssh, c);
}

ସ୍ଥିର ଶୂନ୍ୟ
channel_post_mux_listener(ସଂରଚନା ssh *ssh, Channel *c)
{
	Channel *nc;
	ସଂରଚନା sockaddr_storage addr;
	socklen_t addrlen;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା newsock;
	uid_t euid;
	gid_t egid;

	ଯଦି ((c->io_ready & SSH_CHAN_IO_SOCK_R) == 0)
		ଫେରନ୍ତୁ;

	debug("multiplexing control connection");

	/*
	 * Accept connection on control socket
	 */
	memset(&addr, 0, ଆକାର(addr));
	addrlen = ଆକାର(addr);
	ଯଦି ((newsock = accept(c->sock, (ସଂରଚନା sockaddr*)&addr,
	    &addrlen)) == -1) {
		error_f("accept: %s", strerror(errno));
		ଯଦି (errno == EMFILE || errno == ENFILE)
			c->notbefore = monotime_double() + 1.0;
		ଫେରନ୍ତୁ;
	}

	ଯଦି (getpeereid(newsock, &euid, &egid) == -1) {
		error_f("getpeereid failed: %s", strerror(errno));
		close(newsock);
		ଫେରନ୍ତୁ;
	}
	ଯଦି ((euid != 0) && (getuid() != euid)) {
		error("multiplex uid mismatch: peer euid %u != uid %u",
		    (u_int)euid, (u_int)getuid());
		close(newsock);
		ଫେରନ୍ତୁ;
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

ସ୍ଥିର ଶୂନ୍ୟ
channel_handler_init(ସଂରଚନା ssh_channels *sc)
{
	chan_fn **pre, **post;

	ଯଦି ((pre = calloc(SSH_CHANNEL_MAX_TYPE, ଆକାର(*pre))) == ଖାଲି ||
	    (post = calloc(SSH_CHANNEL_MAX_TYPE, ଆକାର(*post))) == ଖାଲି)
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
ସ୍ଥିର ଶୂନ୍ୟ
channel_garbage_collect(ସଂରଚନା ssh *ssh, Channel *c)
{
	ଯଦି (c == ଖାଲି)
		ଫେରନ୍ତୁ;
	ଯଦି (c->detach_user != ଖାଲି) {
		ଯଦି (!chan_is_dead(ssh, c, c->detach_close))
			ଫେରନ୍ତୁ;

		debug2("channel %d: gc: notify user", c->self);
		c->detach_user(ssh, c->self, 0, ଖାଲି);
		/* if we still have a callback */
		ଯଦି (c->detach_user != ଖାଲି)
			ଫେରନ୍ତୁ;
		debug2("channel %d: gc: user detached", c->self);
	}
	ଯଦି (!chan_is_dead(ssh, c, 1))
		ଫେରନ୍ତୁ;
	debug2("channel %d: garbage collecting", c->self);
	channel_free(ssh, c);
}

ଗଣନା channel_table { CHAN_PRE, CHAN_POST };

ସ୍ଥିର ଶୂନ୍ୟ
channel_handler(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା table, ସଂରଚନା timespec *timeout)
{
	ସଂରଚନା ssh_channels *sc = ssh->chanctxt;
	chan_fn **ftab = table == CHAN_PRE ? sc->channel_pre : sc->channel_post;
	u_int i, oalloc;
	Channel *c;
	ଦ୍ୱିଗୁଣ now;

	now = monotime_double();
	ପାଇଁ (sc->nbulk = i = 0, oalloc = sc->channels_alloc; i < oalloc; i++) {
		c = sc->channels[i];
		ଯଦି (c == ଖାଲି)
			ଜାରି;
		/* Count open channels in bulk state */
		ଯଦି (c->type == SSH_CHANNEL_OPEN && c->bulk)
			sc->nbulk++;
		/* Try to keep IO going while rekeying */
		ଯଦି (ssh_packet_is_rekeying(ssh) && c->type != SSH_CHANNEL_OPEN)
			ଜାରି;
		ଯଦି (c->delayed) {
			ଯଦି (table == CHAN_PRE)
				c->delayed = 0;
			ଅନ୍ୟଥା
				ଜାରି;
		}
		ଯଦି (ftab[c->type] != ଖାଲି) {
			ଯଦି (table == CHAN_PRE && c->type == SSH_CHANNEL_OPEN &&
			    channel_get_expiry(ssh, c) != 0 &&
			    now >= channel_get_expiry(ssh, c)) {
				/* channel closed for inactivity */
				ଦ୍ୱିଗୁଣ deadline = c->inactive_deadline != 0.0 ?
				    c->inactive_deadline : sc->global_deadline;
				verbose("channel %d: closing after %f seconds "
				    "of inactivity", c->self, deadline);
				channel_force_close(ssh, c, 1);
			} ଅନ୍ୟଥା ଯଦି (c->notbefore <= now) {
				/* Run handlers that are not paused. */
				(*ftab[c->type])(ssh, c);
				/* inactivity timeouts must interrupt poll() */
				ଯଦି (timeout != ଖାଲି &&
				    c->type == SSH_CHANNEL_OPEN &&
				    channel_get_expiry(ssh, c) != 0) {
					ptimeout_deadline_monotime_double(timeout,
					    channel_get_expiry(ssh, c));
				}
			} ଅନ୍ୟଥା ଯଦି (timeout != ଖାଲି) {
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
ସ୍ଥିର ଶୂନ୍ୟ
channel_before_prepare_io(ସଂରଚନା ssh *ssh)
{
	ସଂରଚନା ssh_channels *sc = ssh->chanctxt;
	Channel *c;
	u_int i, oalloc;

	ପାଇଁ (i = 0, oalloc = sc->channels_alloc; i < oalloc; i++) {
		c = sc->channels[i];
		ଯଦି (c == ଖାଲି)
			ଜାରି;
		ଯଦି (c->type == SSH_CHANNEL_RDYNAMIC_OPEN)
			channel_before_prepare_io_rdynamic(ssh, c);
	}
}

ସ୍ଥିର ଶୂନ୍ୟ
dump_channel_poll(ଅଚଳ ଅକ୍ଷର *func, ଅଚଳ ଅକ୍ଷର *what, Channel *c,
    u_int pollfd_offset, ସଂରଚନା pollfd *pfd)
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
ସ୍ଥିର ଶୂନ୍ୟ
channel_prepare_pollfd(Channel *c, u_int *next_pollfd,
    ସଂରଚନା pollfd *pfd, u_int npfd)
{
	u_int ev, p = *next_pollfd;

	ଯଦି (c == ଖାଲି)
		ଫେରନ୍ତୁ;
	ଯଦି (p + 4 > npfd) {
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
	ଯଦି (c->rfd != -1) {
		ev = 0;
		ଯଦି ((c->io_want & SSH_CHAN_IO_RFD) != 0)
			ev |= POLLIN;
		/* rfd == wfd */
		ଯଦି (c->wfd == c->rfd) {
			ଯଦି ((c->io_want & SSH_CHAN_IO_WFD) != 0)
				ev |= POLLOUT;
		}
		/* rfd == efd */
		ଯଦି (c->efd == c->rfd) {
			ଯଦି ((c->io_want & SSH_CHAN_IO_EFD_R) != 0)
				ev |= POLLIN;
			ଯଦି ((c->io_want & SSH_CHAN_IO_EFD_W) != 0)
				ev |= POLLOUT;
		}
		/* rfd == sock */
		ଯଦି (c->sock == c->rfd) {
			ଯଦି ((c->io_want & SSH_CHAN_IO_SOCK_R) != 0)
				ev |= POLLIN;
			ଯଦି ((c->io_want & SSH_CHAN_IO_SOCK_W) != 0)
				ev |= POLLOUT;
		}
		/* Pack a pfd entry if any event armed for this fd */
		ଯଦି (ev != 0) {
			c->pfds[0] = p;
			pfd[p].fd = c->rfd;
			pfd[p].events = ev;
			dump_channel_poll(__func__, "rfd", c, p, &pfd[p]);
			p++;
		}
	}
	/* prepare c->wfd if wanting IO and not already handled above */
	ଯଦି (c->wfd != -1 && c->rfd != c->wfd) {
		ev = 0;
		ଯଦି ((c->io_want & SSH_CHAN_IO_WFD))
			ev |= POLLOUT;
		/* Pack a pfd entry if any event armed for this fd */
		ଯଦି (ev != 0) {
			c->pfds[1] = p;
			pfd[p].fd = c->wfd;
			pfd[p].events = ev;
			dump_channel_poll(__func__, "wfd", c, p, &pfd[p]);
			p++;
		}
	}
	/* prepare c->efd if wanting IO and not already handled above */
	ଯଦି (c->efd != -1 && c->rfd != c->efd) {
		ev = 0;
		ଯଦି ((c->io_want & SSH_CHAN_IO_EFD_R) != 0)
			ev |= POLLIN;
		ଯଦି ((c->io_want & SSH_CHAN_IO_EFD_W) != 0)
			ev |= POLLOUT;
		/* Pack a pfd entry if any event armed for this fd */
		ଯଦି (ev != 0) {
			c->pfds[2] = p;
			pfd[p].fd = c->efd;
			pfd[p].events = ev;
			dump_channel_poll(__func__, "efd", c, p, &pfd[p]);
			p++;
		}
	}
	/* prepare c->sock if wanting IO and not already handled above */
	ଯଦି (c->sock != -1 && c->rfd != c->sock) {
		ev = 0;
		ଯଦି ((c->io_want & SSH_CHAN_IO_SOCK_R) != 0)
			ev |= POLLIN;
		ଯଦି ((c->io_want & SSH_CHAN_IO_SOCK_W) != 0)
			ev |= POLLOUT;
		/* Pack a pfd entry if any event armed for this fd */
		ଯଦି (ev != 0) {
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
ଶୂନ୍ୟ
channel_prepare_poll(ସଂରଚନା ssh *ssh, ସଂରଚନା pollfd **pfdp, u_int *npfd_allocp,
    u_int *npfd_activep, u_int npfd_reserved, ସଂରଚନା timespec *timeout)
{
	ସଂରଚନା ssh_channels *sc = ssh->chanctxt;
	u_int i, oalloc, p, npfd = npfd_reserved;

	channel_before_prepare_io(ssh); /* might create a new channel */
	/* clear out I/O flags from last poll */
	ପାଇଁ (i = 0; i < sc->channels_alloc; i++) {
		ଯଦି (sc->channels[i] == ଖାଲି)
			ଜାରି;
		sc->channels[i]->io_want = sc->channels[i]->io_ready = 0;
	}
	/* Allocate 4x pollfd for each channel (rfd, wfd, efd, sock) */
	ଯଦି (sc->channels_alloc >= (INT_MAX / 4) - npfd_reserved)
		fatal_f("too many channels"); /* shouldn't happen */
	npfd += sc->channels_alloc * 4;
	ଯଦି (npfd > *npfd_allocp) {
		*pfdp = xrecallocarray(*pfdp, *npfd_allocp,
		    npfd, ଆକାର(**pfdp));
		*npfd_allocp = npfd;
	}
	*npfd_activep = npfd_reserved;
	oalloc = sc->channels_alloc;

	channel_handler(ssh, CHAN_PRE, timeout);

	ଯଦି (oalloc != sc->channels_alloc) {
		/* shouldn't happen */
		fatal_f("channels_alloc changed during CHAN_PRE "
		    "(was %u, now %u)", oalloc, sc->channels_alloc);
	}

	/* Prepare pollfd */
	p = npfd_reserved;
	ପାଇଁ (i = 0; i < sc->channels_alloc; i++)
		channel_prepare_pollfd(sc->channels[i], &p, *pfdp, npfd);
	*npfd_activep = p;
}

ସ୍ଥିର ଶୂନ୍ୟ
fd_ready(Channel *c, ପୂର୍ଣ୍ଣସଂଖ୍ୟା p, ସଂରଚନା pollfd *pfds, u_int npfd, ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd,
    ଅଚଳ ଅକ୍ଷର *what, u_int revents_mask, u_int ready)
{
	ସଂରଚନା pollfd *pfd = &pfds[p];

	ଯଦି (fd == -1)
		ଫେରନ୍ତୁ;
	ଯଦି (p == -1 || (u_int)p >= npfd)
		fatal_f("channel %d: bad pfd %d (max %u)", c->self, p, npfd);
	dump_channel_poll(__func__, what, c, p, pfd);
	ଯଦି (pfd->fd != fd) {
		fatal("channel %d: inconsistent %s fd=%d pollfd[%u].fd %d "
		    "r%d w%d e%d s%d", c->self, what, fd, p, pfd->fd,
		    c->rfd, c->wfd, c->efd, c->sock);
	}
	ଯଦି ((pfd->revents & POLLNVAL) != 0) {
		fatal("channel %d: invalid %s pollfd[%u].fd %d r%d w%d e%d s%d",
		    c->self, what, p, pfd->fd, c->rfd, c->wfd, c->efd, c->sock);
	}
	ଯଦି ((pfd->revents & (revents_mask|POLLHUP|POLLERR)) != 0)
		c->io_ready |= ready & c->io_want;
}

/*
 * After poll, perform any appropriate operations for channels which have
 * events pending.
 */
ଶୂନ୍ୟ
channel_after_poll(ସଂରଚନା ssh *ssh, ସଂରଚନା pollfd *pfd, u_int npfd)
{
	ସଂରଚନା ssh_channels *sc = ssh->chanctxt;
	u_int i;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା p;
	Channel *c;

#ifdef DEBUG_CHANNEL_POLL
	ପାଇଁ (p = 0; p < (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)npfd; p++) {
		ଯଦି (pfd[p].revents == 0)
			ଜାରି;
		debug_f("pfd[%u].fd %d rev 0x%04x",
		    p, pfd[p].fd, pfd[p].revents);
	}
#endif

	/* Convert pollfd into c->io_ready */
	ପାଇଁ (i = 0; i < sc->channels_alloc; i++) {
		c = sc->channels[i];
		ଯଦି (c == ଖାଲି)
			ଜାରି;
		/* if rfd is shared with efd/sock then wfd should be too */
		ଯଦି (c->rfd != -1 && c->wfd != -1 && c->rfd != c->wfd &&
		    (c->rfd == c->efd || c->rfd == c->sock)) {
			/* Shouldn't happen */
			fatal_f("channel %d: unexpected fds r%d w%d e%d s%d",
			    c->self, c->rfd, c->wfd, c->efd, c->sock);
		}
		c->io_ready = 0;
		/* rfd, potentially shared with wfd, efd and sock */
		ଯଦି (c->rfd != -1 && (p = c->pfds[0]) != -1) {
			fd_ready(c, p, pfd, npfd, c->rfd,
			    "rfd", POLLIN, SSH_CHAN_IO_RFD);
			ଯଦି (c->rfd == c->wfd) {
				fd_ready(c, p, pfd, npfd, c->wfd,
				    "wfd/r", POLLOUT, SSH_CHAN_IO_WFD);
			}
			ଯଦି (c->rfd == c->efd) {
				fd_ready(c, p, pfd, npfd, c->efd,
				    "efdr/r", POLLIN, SSH_CHAN_IO_EFD_R);
				fd_ready(c, p, pfd, npfd, c->efd,
				    "efdw/r", POLLOUT, SSH_CHAN_IO_EFD_W);
			}
			ଯଦି (c->rfd == c->sock) {
				fd_ready(c, p, pfd, npfd, c->sock,
				    "sockr/r", POLLIN, SSH_CHAN_IO_SOCK_R);
				fd_ready(c, p, pfd, npfd, c->sock,
				    "sockw/r", POLLOUT, SSH_CHAN_IO_SOCK_W);
			}
			dump_channel_poll(__func__, "rfd", c, p, pfd);
		}
		/* wfd */
		ଯଦି (c->wfd != -1 && c->wfd != c->rfd &&
		    (p = c->pfds[1]) != -1) {
			fd_ready(c, p, pfd, npfd, c->wfd,
			    "wfd", POLLOUT, SSH_CHAN_IO_WFD);
			dump_channel_poll(__func__, "wfd", c, p, pfd);
		}
		/* efd */
		ଯଦି (c->efd != -1 && c->efd != c->rfd &&
		    (p = c->pfds[2]) != -1) {
			fd_ready(c, p, pfd, npfd, c->efd,
			    "efdr", POLLIN, SSH_CHAN_IO_EFD_R);
			fd_ready(c, p, pfd, npfd, c->efd,
			    "efdw", POLLOUT, SSH_CHAN_IO_EFD_W);
			dump_channel_poll(__func__, "efd", c, p, pfd);
		}
		/* sock */
		ଯଦି (c->sock != -1 && c->sock != c->rfd &&
		    (p = c->pfds[3]) != -1) {
			fd_ready(c, p, pfd, npfd, c->sock,
			    "sockr", POLLIN, SSH_CHAN_IO_SOCK_R);
			fd_ready(c, p, pfd, npfd, c->sock,
			    "sockw", POLLOUT, SSH_CHAN_IO_SOCK_W);
			dump_channel_poll(__func__, "sock", c, p, pfd);
		}
	}
	channel_handler(ssh, CHAN_POST, ଖାଲି);
}

/*
 * Enqueue data for channels with open or draining c->input.
 * Returns non-zero if a packet was enqueued.
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
channel_output_poll_ନିବେଶ_open(ସଂରଚନା ssh *ssh, Channel *c)
{
	size_t len, plen;
	ଅଚଳ u_char *pkt;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((len = sshbuf_len(c->ନିବେଶ)) == 0) {
		ଯଦି (c->istate == CHAN_ନିବେଶ_WAIT_DRAIN) {
			/*
			 * input-buffer is empty and read-socket shutdown:
			 * tell peer, that we will not send more data:
			 * send IEOF.
			 * hack for extended data: delay EOF if EFD still
			 * in use.
			 */
			ଯଦି (CHANNEL_EFD_ନିବେଶ_ACTIVE(c))
				debug2("channel %d: "
				    "ibuf_empty delayed efd %d/(%zu)",
				    c->self, c->efd, sshbuf_len(c->extended));
			ଅନ୍ୟଥା
				chan_ibuf_empty(ssh, c);
		}
		ଫେରନ୍ତୁ 0;
	}

	ଯଦି (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);

	ଯଦି (c->datagram) {
		/* Check datagram will fit; drop if not */
		ଯଦି ((r = sshbuf_get_string_direct(c->ନିବେଶ, &pkt, &plen)) != 0)
			fatal_fr(r, "channel %i: get datagram", c->self);
		/*
		 * XXX this does tail-drop on the datagram queue which is
		 * usually suboptimal compared to head-drop. Better to have
		 * backpressure at read time? (i.e. read + discard)
		 */
		ଯଦି (plen > c->remote_window || plen > c->remote_maxpacket) {
			debug("channel %d: datagram too big", c->self);
			ଫେରନ୍ତୁ 0;
		}
		/* Enqueue it */
		ଯଦି ((r = sshpkt_start(ssh, SSH2_ସନ୍ଦେଶ_CHANNEL_DATA)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
		    (r = sshpkt_put_string(ssh, pkt, plen)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "channel %i: send datagram", c->self);
		c->remote_window -= plen;
		ଫେରନ୍ତୁ 1;
	}

	/* Enqueue packet for buffered data. */
	ଯଦି (len > c->remote_window)
		len = c->remote_window;
	ଯଦି (len > c->remote_maxpacket)
		len = c->remote_maxpacket;
	ଯଦି (len == 0)
		ଫେରନ୍ତୁ 0;
	ଯଦି ((r = sshpkt_start(ssh, SSH2_ସନ୍ଦେଶ_CHANNEL_DATA)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_string(ssh, sshbuf_ptr(c->ନିବେଶ), len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i: send data", c->self);
	ଯଦି ((r = sshbuf_consume(c->ନିବେଶ, len)) != 0)
		fatal_fr(r, "channel %i: consume", c->self);
	c->remote_window -= len;
	ଫେରନ୍ତୁ 1;
}

/*
 * Enqueue data for channels with open c->extended in read mode.
 * Returns non-zero if a packet was enqueued.
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
channel_output_poll_extended_read(ସଂରଚନା ssh *ssh, Channel *c)
{
	size_t len;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((len = sshbuf_len(c->extended)) == 0)
		ଫେରନ୍ତୁ 0;

	debug2("channel %d: rwin %u elen %zu euse %d", c->self,
	    c->remote_window, sshbuf_len(c->extended), c->extended_usage);
	ଯଦି (len > c->remote_window)
		len = c->remote_window;
	ଯଦି (len > c->remote_maxpacket)
		len = c->remote_maxpacket;
	ଯଦି (len == 0)
		ଫେରନ୍ତୁ 0;
	ଯଦି (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);
	ଯଦି ((r = sshpkt_start(ssh, SSH2_ସନ୍ଦେଶ_CHANNEL_EXTENDED_DATA)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_u32(ssh, SSH2_EXTENDED_DATA_STDERR)) != 0 ||
	    (r = sshpkt_put_string(ssh, sshbuf_ptr(c->extended), len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i: data", c->self);
	ଯଦି ((r = sshbuf_consume(c->extended, len)) != 0)
		fatal_fr(r, "channel %i: consume", c->self);
	c->remote_window -= len;
	debug2("channel %d: sent ext data %zu", c->self, len);
	ଫେରନ୍ତୁ 1;
}

/*
 * If there is data to send to the connection, enqueue some of it now.
 * Returns non-zero if data was enqueued.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
channel_output_poll(ସଂରଚନା ssh *ssh)
{
	ସଂରଚନା ssh_channels *sc = ssh->chanctxt;
	Channel *c;
	u_int i;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret = 0;

	ପାଇଁ (i = 0; i < sc->channels_alloc; i++) {
		c = sc->channels[i];
		ଯଦି (c == ଖାଲି)
			ଜାରି;

		/*
		 * We are only interested in channels that can have buffered
		 * incoming data.
		 */
		ଯଦି (c->type != SSH_CHANNEL_OPEN)
			ଜାରି;
		ଯଦି ((c->flags & (CHAN_CLOSE_SENT|CHAN_CLOSE_RCVD))) {
			/* XXX is this true? */
			debug3("channel %d: will not send data after close",
			    c->self);
			ଜାରି;
		}

		/* Get the amount of buffered data for this channel. */
		ଯଦି (c->istate == CHAN_ନିବେଶ_OPEN ||
		    c->istate == CHAN_ନିବେଶ_WAIT_DRAIN)
			ret |= channel_output_poll_ନିବେଶ_open(ssh, c);
		/* Send extended data, i.e. stderr */
		ଯଦି (!(c->flags & CHAN_EOF_SENT) &&
		    c->extended_usage == CHAN_EXTENDED_READ)
			ret |= channel_output_poll_extended_read(ssh, c);
	}
	ଫେରନ୍ତୁ ret;
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
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
channel_proxy_downstream(ସଂରଚନା ssh *ssh, Channel *downstream)
{
	Channel *c = ଖାଲି;
	ସଂରଚନା sshbuf *original = ଖାଲି, *modified = ଖାଲି;
	ଅଚଳ u_char *cp;
	ଅକ୍ଷର *ctype = ଖାଲି, *listen_host = ଖାଲି;
	u_char type;
	size_t have;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret = -1, r;
	u_int id, remote_id, listen_port;

	/* sshbuf_dump(downstream->input, stderr); */
	ଯଦି ((r = sshbuf_get_string_direct(downstream->ନିବେଶ, &cp, &have))
	    != 0) {
		error_fr(r, "parse");
		ଫେରନ୍ତୁ -1;
	}
	ଯଦି (have < 2) {
		error_f("short message");
		ଫେରନ୍ତୁ -1;
	}
	type = cp[1];
	/* skip padlen + type */
	cp += 2;
	have -= 2;
	ଯଦି (ssh_packet_log_type(type))
		debug3_f("channel %u: down->up: type %u",
		    downstream->self, type);

	ବାଛ (type) {
	ସ୍ଥିତି SSH2_ସନ୍ଦେଶ_CHANNEL_OPEN:
		ଯଦି ((original = sshbuf_from(cp, have)) == ଖାଲି ||
		    (modified = sshbuf_new()) == ଖାଲି) {
			error_f("alloc");
			ଯାଅ out;
		}
		ଯଦି ((r = sshbuf_get_cstring(original, &ctype, ଖାଲି)) != 0 ||
		    (r = sshbuf_get_u32(original, &id)) != 0) {
			error_fr(r, "parse");
			ଯାଅ out;
		}
		c = channel_new(ssh, "mux-proxy", SSH_CHANNEL_MUX_PROXY,
		    -1, -1, -1, 0, 0, 0, ctype, 1);
		c->mux_ctx = downstream;	/* point to mux client */
		c->mux_downstream_id = id;	/* original downstream id */
		ଯଦି ((r = sshbuf_put_cstring(modified, ctype)) != 0 ||
		    (r = sshbuf_put_u32(modified, c->self)) != 0 ||
		    (r = sshbuf_putb(modified, original)) != 0) {
			error_fr(r, "compose");
			channel_free(ssh, c);
			ଯାଅ out;
		}
		ଭାଙ୍ଗ;
	ସ୍ଥିତି SSH2_ସନ୍ଦେଶ_CHANNEL_OPEN_CONFIRMATION:
		/*
		 * Almost the same as SSH2_MSG_CHANNEL_OPEN, except then we
		 * need to parse 'remote_id' instead of 'ctype'.
		 */
		ଯଦି ((original = sshbuf_from(cp, have)) == ଖାଲି ||
		    (modified = sshbuf_new()) == ଖାଲି) {
			error_f("alloc");
			ଯାଅ out;
		}
		ଯଦି ((r = sshbuf_get_u32(original, &remote_id)) != 0 ||
		    (r = sshbuf_get_u32(original, &id)) != 0) {
			error_fr(r, "parse");
			ଯାଅ out;
		}
		c = channel_new(ssh, "mux-proxy", SSH_CHANNEL_MUX_PROXY,
		    -1, -1, -1, 0, 0, 0, "mux-down-connect", 1);
		c->mux_ctx = downstream;	/* point to mux client */
		c->mux_downstream_id = id;
		c->remote_id = remote_id;
		c->have_remote_id = 1;
		ଯଦି ((r = sshbuf_put_u32(modified, remote_id)) != 0 ||
		    (r = sshbuf_put_u32(modified, c->self)) != 0 ||
		    (r = sshbuf_putb(modified, original)) != 0) {
			error_fr(r, "compose");
			channel_free(ssh, c);
			ଯାଅ out;
		}
		ଭାଙ୍ଗ;
	ସ୍ଥିତି SSH2_ସନ୍ଦେଶ_GLOBAL_REQUEST:
		ଯଦି ((original = sshbuf_from(cp, have)) == ଖାଲି) {
			error_f("alloc");
			ଯାଅ out;
		}
		ଯଦି ((r = sshbuf_get_cstring(original, &ctype, ଖାଲି)) != 0) {
			error_fr(r, "parse");
			ଯାଅ out;
		}
		ଯଦି (strcmp(ctype, "tcpip-forward") != 0) {
			error_f("unsupported request %s", ctype);
			ଯାଅ out;
		}
		ଯଦି ((r = sshbuf_get_u8(original, ଖାଲି)) != 0 ||
		    (r = sshbuf_get_cstring(original, &listen_host, ଖାଲି)) != 0 ||
		    (r = sshbuf_get_u32(original, &listen_port)) != 0) {
			error_fr(r, "parse");
			ଯାଅ out;
		}
		ଯଦି (listen_port > 65535) {
			error_f("tcpip-forward for %s: bad port %u",
			    listen_host, listen_port);
			ଯାଅ out;
		}
		/* Record that connection to this host/port is permitted. */
		permission_set_add(ssh, FORWARD_USER, FORWARD_LOCAL, "<mux>",
		    -1, listen_host, ଖାଲି, (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)listen_port, downstream);
		ଭାଙ୍ଗ;
	ସ୍ଥିତି SSH2_ସନ୍ଦେଶ_CHANNEL_CLOSE:
		ଯଦି (have < 4)
			ଭାଙ୍ଗ;
		remote_id = PEEK_U32(cp);
		ଯଦି ((c = channel_by_remote_id(ssh, remote_id)) != ଖାଲି) {
			ଯଦି (c->flags & CHAN_CLOSE_RCVD)
				channel_free(ssh, c);
			ଅନ୍ୟଥା
				c->flags |= CHAN_CLOSE_SENT;
		}
		ଭାଙ୍ଗ;
	}
	ଯଦି (modified) {
		ଯଦି ((r = sshpkt_start(ssh, type)) != 0 ||
		    (r = sshpkt_putb(ssh, modified)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0) {
			error_fr(r, "send");
			ଯାଅ out;
		}
	} ଅନ୍ୟଥା {
		ଯଦି ((r = sshpkt_start(ssh, type)) != 0 ||
		    (r = sshpkt_put(ssh, cp, have)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0) {
			error_fr(r, "send");
			ଯାଅ out;
		}
	}
	ret = 0;
 out:
	ମୁକ୍ତ(ctype);
	ମୁକ୍ତ(listen_host);
	sshbuf_free(original);
	sshbuf_free(modified);
	ଫେରନ୍ତୁ ret;
}

/*
 * receive packets from upstream server and de-multiplex packets
 * to correct downstream:
 * implemented as a helper for channel input handlers,
 * replaces local (proxy) channel ID with downstream channel ID.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
channel_proxy_upstream(Channel *c, ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, uint32_t seq, ସଂରଚନା ssh *ssh)
{
	ସଂରଚନା sshbuf *b = ଖାଲି;
	Channel *downstream;
	ଅଚଳ u_char *cp = ଖାଲି;
	size_t len;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	/*
	 * When receiving packets from the peer we need to check whether we
	 * need to forward the packets to the mux client. In this case we
	 * restore the original channel id and keep track of CLOSE messages,
	 * so we can cleanup the channel.
	 */
	ଯଦି (c == ଖାଲି || c->type != SSH_CHANNEL_MUX_PROXY)
		ଫେରନ୍ତୁ 0;
	ଯଦି ((downstream = c->mux_ctx) == ଖାଲି)
		ଫେରନ୍ତୁ 0;
	ବାଛ (type) {
	ସ୍ଥିତି SSH2_ସନ୍ଦେଶ_CHANNEL_CLOSE:
	ସ୍ଥିତି SSH2_ସନ୍ଦେଶ_CHANNEL_DATA:
	ସ୍ଥିତି SSH2_ସନ୍ଦେଶ_CHANNEL_EOF:
	ସ୍ଥିତି SSH2_ସନ୍ଦେଶ_CHANNEL_EXTENDED_DATA:
	ସ୍ଥିତି SSH2_ସନ୍ଦେଶ_CHANNEL_OPEN_CONFIRMATION:
	ସ୍ଥିତି SSH2_ସନ୍ଦେଶ_CHANNEL_OPEN_FAILURE:
	ସ୍ଥିତି SSH2_ସନ୍ଦେଶ_CHANNEL_WINDOW_ADJUST:
	ସ୍ଥିତି SSH2_ସନ୍ଦେଶ_CHANNEL_SUCCESS:
	ସ୍ଥିତି SSH2_ସନ୍ଦେଶ_CHANNEL_FAILURE:
	ସ୍ଥିତି SSH2_ସନ୍ଦେଶ_CHANNEL_REQUEST:
		ଭାଙ୍ଗ;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		debug2_f("channel %u: unsupported type %u", c->self, type);
		ଫେରନ୍ତୁ 0;
	}
	ଯଦି ((b = sshbuf_new()) == ଖାଲି) {
		error_f("alloc reply");
		ଯାଅ out;
	}
	/* get remaining payload (after id) */
	cp = sshpkt_ptr(ssh, &len);
	ଯଦି (cp == ଖାଲି) {
		error_f("no packet");
		ଯାଅ out;
	}
	/* translate id and send to muxclient */
	ଯଦି ((r = sshbuf_put_u8(b, 0)) != 0 ||	/* padlen */
	    (r = sshbuf_put_u8(b, type)) != 0 ||
	    (r = sshbuf_put_u32(b, c->mux_downstream_id)) != 0 ||
	    (r = sshbuf_put(b, cp, len)) != 0 ||
	    (r = sshbuf_put_stringb(downstream->output, b)) != 0) {
		error_fr(r, "compose muxclient");
		ଯାଅ out;
	}
	/* sshbuf_dump(b, stderr); */
	ଯଦି (ssh_packet_log_type(type))
		debug3_f("channel %u: up->down: type %u", c->self, type);
 out:
	/* update state */
	ବାଛ (type) {
	ସ୍ଥିତି SSH2_ସନ୍ଦେଶ_CHANNEL_OPEN_CONFIRMATION:
		/* record remote_id for SSH2_MSG_CHANNEL_CLOSE */
		ଯଦି (cp && len > 4) {
			c->remote_id = PEEK_U32(cp);
			c->have_remote_id = 1;
		}
		ଭାଙ୍ଗ;
	ସ୍ଥିତି SSH2_ସନ୍ଦେଶ_CHANNEL_CLOSE:
		ଯଦି (c->flags & CHAN_CLOSE_SENT)
			channel_free(ssh, c);
		ଅନ୍ୟଥା
			c->flags |= CHAN_CLOSE_RCVD;
		ଭାଙ୍ଗ;
	}
	sshbuf_free(b);
	ଫେରନ୍ତୁ 1;
}

/* -- protocol input */

/* Parse a channel ID from the current packet */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
channel_parse_id(ସଂରଚନା ssh *ssh, ଅଚଳ ଅକ୍ଷର *where, ଅଚଳ ଅକ୍ଷର *what)
{
	uint32_t id;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = sshpkt_get_u32(ssh, &id)) != 0) {
		error_r(r, "%s: parse id", where);
		ssh_packet_disconnect(ssh, "Invalid %s message", what);
	}
	ଯଦି (id > INT_MAX) {
		error_r(r, "%s: bad channel id %u", where, id);
		ssh_packet_disconnect(ssh, "Invalid %s channel id", what);
	}
	ଫେରନ୍ତୁ (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)id;
}

/* Lookup a channel from an ID in the current packet */
ସ୍ଥିର Channel *
channel_from_packet_id(ସଂରଚନା ssh *ssh, ଅଚଳ ଅକ୍ଷର *where, ଅଚଳ ଅକ୍ଷର *what)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା id = channel_parse_id(ssh, where, what);
	Channel *c;

	ଯଦି ((c = channel_lookup(ssh, id)) == ଖାଲି) {
		ssh_packet_disconnect(ssh,
		    "%s packet referred to nonexistent channel %d", what, id);
	}
	ଫେରନ୍ତୁ c;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
channel_ନିବେଶ_data(ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, uint32_t seq, ସଂରଚନା ssh *ssh)
{
	ଅଚଳ u_char *data;
	size_t data_len, win_len;
	Channel *c = channel_from_packet_id(ssh, __func__, "data");
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (channel_proxy_upstream(c, type, seq, ssh))
		ଫେରନ୍ତୁ 0;

	/* Ignore any data for non-open channels (might happen on close) */
	ଯଦି (c->type != SSH_CHANNEL_OPEN &&
	    c->type != SSH_CHANNEL_RDYNAMIC_OPEN &&
	    c->type != SSH_CHANNEL_RDYNAMIC_FINISH &&
	    c->type != SSH_CHANNEL_X11_OPEN)
		ଫେରନ୍ତୁ 0;

	/* Get the data. */
	ଯଦି ((r = sshpkt_get_string_direct(ssh, &data, &data_len)) != 0 ||
            (r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "channel %i: get data", c->self);

	win_len = data_len;
	ଯଦି (c->datagram)
		win_len += 4;  /* string length header */

	/*
	 * The sending side reduces its window as it sends data, so we
	 * must 'fake' consumption of the data in order to ensure that window
	 * updates are sent back. Otherwise the connection might deadlock.
	 */
	ଯଦି (c->ostate != CHAN_OUTPUT_OPEN) {
		ଯଦି (win_len > c->local_window)
			c->local_window = 0;
		ଅନ୍ୟଥା
			c->local_window -= win_len;
		c->local_consumed += win_len;
		ଫେରନ୍ତୁ 0;
	}

	ଯଦି (win_len > c->local_maxpacket) {
		logit("channel %d: rcvd big packet %zu, maxpack %u",
		    c->self, win_len, c->local_maxpacket);
		ଫେରନ୍ତୁ 0;
	}
	ଯଦି (win_len > c->local_window) {
		u_int delta = win_len - c->local_window;

		ଯଦି (c->local_window_exceeded > UINT_MAX - delta)
			c->local_window_exceeded = UINT_MAX;
		ଅନ୍ୟଥା
			c->local_window_exceeded += delta;
		logit("channel %d: rcvd too much data %zu, win %u/%u "
		    "(excess %u)", c->self, win_len, c->local_window,
		    c->local_window_max, c->local_window_exceeded);
		c->local_window = 0;
		/* Allow 10% grace before bringing the hammer down */
		ଯଦି (c->local_window_exceeded > (c->local_window_max / 10)) {
			ssh_packet_disconnect(ssh, "channel %d: peer ignored "
			    "channel window", c->self);
		}
	} ଅନ୍ୟଥା {
		c->local_window -= win_len;
		c->local_window_exceeded = 0;
	}

	ଯଦି (c->datagram) {
		ଯଦି ((r = sshbuf_put_string(c->output, data, data_len)) != 0)
			fatal_fr(r, "channel %i: append datagram", c->self);
	} ଅନ୍ୟଥା ଯଦି ((r = sshbuf_put(c->output, data, data_len)) != 0)
		fatal_fr(r, "channel %i: append data", c->self);

	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
channel_ନିବେଶ_extended_data(ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, uint32_t seq, ସଂରଚନା ssh *ssh)
{
	ଅଚଳ u_char *data;
	size_t data_len;
	uint32_t tcode;
	Channel *c = channel_from_packet_id(ssh, __func__, "extended data");
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (channel_proxy_upstream(c, type, seq, ssh))
		ଫେରନ୍ତୁ 0;
	ଯଦି (c->type != SSH_CHANNEL_OPEN) {
		logit("channel %d: ext data for non open", c->self);
		ଫେରନ୍ତୁ 0;
	}
	ଯଦି (c->flags & CHAN_EOF_RCVD) {
		ଯଦି (ssh->compat & SSH_BUG_EXTEOF)
			debug("channel %d: accepting ext data after eof",
			    c->self);
		ଅନ୍ୟଥା
			ssh_packet_disconnect(ssh, "Received extended_data "
			    "after EOF on channel %d.", c->self);
	}

	ଯଦି ((r = sshpkt_get_u32(ssh, &tcode)) != 0) {
		error_fr(r, "parse tcode");
		ssh_packet_disconnect(ssh, "Invalid extended_data message");
	}
	ଯଦି (c->efd == -1 ||
	    c->extended_usage != CHAN_EXTENDED_WRITE ||
	    tcode != SSH2_EXTENDED_DATA_STDERR) {
		logit("channel %d: bad ext data", c->self);
		ଫେରନ୍ତୁ 0;
	}
	ଯଦି ((r = sshpkt_get_string_direct(ssh, &data, &data_len)) != 0 ||
            (r = sshpkt_get_end(ssh)) != 0) {
		error_fr(r, "parse data");
		ssh_packet_disconnect(ssh, "Invalid extended_data message");
	}

	ଯଦି (data_len > c->local_window) {
		logit("channel %d: rcvd too much extended_data %zu, win %u",
		    c->self, data_len, c->local_window);
		ଫେରନ୍ତୁ 0;
	}
	debug2("channel %d: rcvd ext data %zu", c->self, data_len);
	/* XXX sshpkt_getb? */
	ଯଦି ((r = sshbuf_put(c->extended, data, data_len)) != 0)
		error_fr(r, "append");
	c->local_window -= data_len;
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
channel_ନିବେଶ_ieof(ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, uint32_t seq, ସଂରଚନା ssh *ssh)
{
	Channel *c = channel_from_packet_id(ssh, __func__, "ieof");
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

        ଯଦି ((r = sshpkt_get_end(ssh)) != 0) {
		error_fr(r, "parse data");
		ssh_packet_disconnect(ssh, "Invalid ieof message");
	}

	ଯଦି (channel_proxy_upstream(c, type, seq, ssh))
		ଫେରନ୍ତୁ 0;
	chan_rcvd_ieof(ssh, c);

	/* XXX force input close */
	ଯଦି (c->force_drain && c->istate == CHAN_ନିବେଶ_OPEN) {
		debug("channel %d: FORCE input drain", c->self);
		c->istate = CHAN_ନିବେଶ_WAIT_DRAIN;
		ଯଦି (sshbuf_len(c->ନିବେଶ) == 0)
			chan_ibuf_empty(ssh, c);
	}
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
channel_ନିବେଶ_oclose(ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, uint32_t seq, ସଂରଚନା ssh *ssh)
{
	Channel *c = channel_from_packet_id(ssh, __func__, "oclose");
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (channel_proxy_upstream(c, type, seq, ssh))
		ଫେରନ୍ତୁ 0;
        ଯଦି ((r = sshpkt_get_end(ssh)) != 0) {
		error_fr(r, "parse data");
		ssh_packet_disconnect(ssh, "Invalid oclose message");
	}
	chan_rcvd_oclose(ssh, c);
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
channel_ନିବେଶ_open_confirmation(ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, uint32_t seq, ସଂରଚନା ssh *ssh)
{
	Channel *c = channel_from_packet_id(ssh, __func__, "open confirmation");
	uint32_t remote_window, remote_maxpacket;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (channel_proxy_upstream(c, type, seq, ssh))
		ଫେରନ୍ତୁ 0;
	ଯଦି (c->type != SSH_CHANNEL_OPENING)
		ssh_packet_disconnect(ssh, "Received open confirmation for "
		    "non-opening channel %d.", c->self);
	/*
	 * Record the remote channel number and mark that the channel
	 * is now open.
	 */
	ଯଦି ((r = sshpkt_get_u32(ssh, &c->remote_id)) != 0 ||
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
	ଯଦି (c->open_confirm) {
		debug2_f("channel %d: callback start", c->self);
		c->open_confirm(ssh, c->self, 1, c->open_confirm_ctx);
		debug2_f("channel %d: callback done", c->self);
	}
	channel_set_used_time(ssh, c);
	debug2("channel %d: open confirm rwindow %u rmax %u", c->self,
	    c->remote_window, c->remote_maxpacket);
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ଅକ୍ଷର *
reason2txt(ପୂର୍ଣ୍ଣସଂଖ୍ୟା reason)
{
	ବାଛ (reason) {
	ସ୍ଥିତି SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED:
		ଫେରନ୍ତୁ "administratively prohibited";
	ସ୍ଥିତି SSH2_OPEN_CONNECT_FAILED:
		ଫେରନ୍ତୁ "connect failed";
	ସ୍ଥିତି SSH2_OPEN_UNKNOWN_CHANNEL_TYPE:
		ଫେରନ୍ତୁ "unknown channel type";
	ସ୍ଥିତି SSH2_OPEN_RESOURCE_SHORTAGE:
		ଫେରନ୍ତୁ "resource shortage";
	}
	ଫେରନ୍ତୁ "unknown reason";
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
channel_ନିବେଶ_open_failure(ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, uint32_t seq, ସଂରଚନା ssh *ssh)
{
	Channel *c = channel_from_packet_id(ssh, __func__, "open failure");
	uint32_t reason;
	ଅକ୍ଷର *ସନ୍ଦେଶ = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (channel_proxy_upstream(c, type, seq, ssh))
		ଫେରନ୍ତୁ 0;
	ଯଦି (c->type != SSH_CHANNEL_OPENING)
		ssh_packet_disconnect(ssh, "Received open failure for "
		    "non-opening channel %d.", c->self);
	ଯଦି ((r = sshpkt_get_u32(ssh, &reason)) != 0) {
		error_fr(r, "parse reason");
		ssh_packet_disconnect(ssh, "Invalid open failure message");
	}
	/* skip language */
	ଯଦି ((r = sshpkt_get_cstring(ssh, &ସନ୍ଦେଶ, ଖାଲି)) != 0 ||
	    (r = sshpkt_get_string_direct(ssh, ଖାଲି, ଖାଲି)) != 0 ||
            (r = sshpkt_get_end(ssh)) != 0) {
		error_fr(r, "parse msg/lang");
		ssh_packet_disconnect(ssh, "Invalid open failure message");
	}
	logit("channel %d: open failed: %s%s%s", c->self,
	    reason2txt(reason), ସନ୍ଦେଶ ? ": ": "", ସନ୍ଦେଶ ? ସନ୍ଦେଶ : "");
	ମୁକ୍ତ(ସନ୍ଦେଶ);
	ଯଦି (c->open_confirm) {
		debug2_f("channel %d: callback start", c->self);
		c->open_confirm(ssh, c->self, 0, c->open_confirm_ctx);
		debug2_f("channel %d: callback done", c->self);
	}
	/* Schedule the channel for cleanup/deletion. */
	chan_mark_dead(ssh, c);
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
channel_ନିବେଶ_window_adjust(ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, uint32_t seq, ସଂରଚନା ssh *ssh)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା id = channel_parse_id(ssh, __func__, "window adjust");
	Channel *c;
	uint32_t adjust;
	u_int new_rwin;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((c = channel_lookup(ssh, id)) == ଖାଲି) {
		logit("Received window adjust for non-open channel %d.", id);
		ଫେରନ୍ତୁ 0;
	}

	ଯଦି (channel_proxy_upstream(c, type, seq, ssh))
		ଫେରନ୍ତୁ 0;
	ଯଦି ((r = sshpkt_get_u32(ssh, &adjust)) != 0 ||
            (r = sshpkt_get_end(ssh)) != 0) {
		error_fr(r, "parse adjust");
		ssh_packet_disconnect(ssh, "Invalid window adjust message");
	}
	debug2("channel %d: rcvd adjust %u", c->self, adjust);
	ଯଦି ((new_rwin = c->remote_window + adjust) < c->remote_window) {
		fatal("channel %d: adjust %u overflows remote window %u",
		    c->self, adjust, c->remote_window);
	}
	c->remote_window = new_rwin;
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
channel_ନିବେଶ_status_confirm(ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, uint32_t seq, ସଂରଚନା ssh *ssh)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା id = channel_parse_id(ssh, __func__, "status confirm");
	Channel *c;
	ସଂରଚନା channel_confirm *cc;

	/* Reset keepalive timeout */
	ssh_packet_set_alive_timeouts(ssh, 0);

	debug2_f("type %d id %d", type, id);

	ଯଦି ((c = channel_lookup(ssh, id)) == ଖାଲି) {
		logit_f("%d: unknown", id);
		ଫେରନ୍ତୁ 0;
	}
	ଯଦି (channel_proxy_upstream(c, type, seq, ssh))
		ଫେରନ୍ତୁ 0;
        ଯଦି (sshpkt_get_end(ssh) != 0)
		ssh_packet_disconnect(ssh, "Invalid status confirm message");
	ଯଦି ((cc = TAILQ_FIRST(&c->status_confirms)) == ଖାଲି)
		ଫେରନ୍ତୁ 0;
	cc->cb(ssh, type, c, cc->ctx);
	TAILQ_REMOVE(&c->status_confirms, cc, entry);
	freezero(cc, ଆକାର(*cc));
	ଫେରନ୍ତୁ 0;
}

/* -- tcp forwarding */

ଶୂନ୍ୟ
channel_set_af(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା af)
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
ସ୍ଥିର ଅଚଳ ଅକ୍ଷର *
channel_fwd_bind_addr(ସଂରଚନା ssh *ssh, ଅଚଳ ଅକ୍ଷର *listen_addr, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *wildcardp,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା is_client, ସଂରଚନା ForwardOptions *fwd_opts)
{
	ଅଚଳ ଅକ୍ଷର *addr = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା wildcard = 0;

	ଯଦି (listen_addr == ଖାଲି) {
		/* No address specified: default to gateway_ports setting */
		ଯଦି (fwd_opts->gateway_ports)
			wildcard = 1;
	} ଅନ୍ୟଥା ଯଦି (fwd_opts->gateway_ports || is_client) {
		ଯଦି (((ssh->compat & SSH_OLD_FORWARD_ADDR) &&
		    strcmp(listen_addr, "0.0.0.0") == 0 && is_client == 0) ||
		    *listen_addr == '\0' || strcmp(listen_addr, "*") == 0 ||
		    (!is_client && fwd_opts->gateway_ports == 1)) {
			wildcard = 1;
			/*
			 * Notify client if they requested a specific listen
			 * address and it was overridden.
			 */
			ଯଦି (*listen_addr != '\0' &&
			    strcmp(listen_addr, "0.0.0.0") != 0 &&
			    strcmp(listen_addr, "*") != 0) {
				ssh_packet_send_debug(ssh,
				    "Forwarding listen address "
				    "\"%s\" overridden by server "
				    "GatewayPorts", listen_addr);
			}
		} ଅନ୍ୟଥା ଯଦି (strcmp(listen_addr, "localhost") != 0 ||
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
	} ଅନ୍ୟଥା ଯଦି (strcmp(listen_addr, "127.0.0.1") == 0 ||
	    strcmp(listen_addr, "::1") == 0) {
		/*
		 * If a specific IPv4/IPv6 localhost address has been
		 * requested then accept it even if gateway_ports is in
		 * effect. This allows the client to prefer IPv4 or IPv6.
		 */
		addr = listen_addr;
	}
	ଯଦି (wildcardp != ଖାଲି)
		*wildcardp = wildcard;
	ଫେରନ୍ତୁ addr;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
channel_setup_fwd_listener_tcpip(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା type,
    ସଂରଚନା Forward *fwd, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *allocated_listen_port,
    ସଂରଚନା ForwardOptions *fwd_opts)
{
	Channel *c;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock, r, success = 0, wildcard = 0, is_client;
	ସଂରଚନା addrinfo hints, *ai, *aitop;
	ଅଚଳ ଅକ୍ଷର *host, *addr;
	ଅକ୍ଷର ntop[NI_MAXHOST], strport[NI_MAXSERV];
	in_port_t *lport_p;

	is_client = (type == SSH_CHANNEL_PORT_LISTENER);

	ଯଦି (is_client && fwd->connect_path != ଖାଲି) {
		host = fwd->connect_path;
	} ଅନ୍ୟଥା {
		host = (type == SSH_CHANNEL_RPORT_LISTENER) ?
		    fwd->listen_host : fwd->connect_host;
		ଯଦି (host == ଖାଲି) {
			error("No forward host name.");
			ଫେରନ୍ତୁ 0;
		}
		ଯଦି (strlen(host) >= NI_MAXHOST) {
			error("Forward host name too long.");
			ଫେରନ୍ତୁ 0;
		}
	}

	/* Determine the bind address, cf. channel_fwd_bind_addr() comment */
	addr = channel_fwd_bind_addr(ssh, fwd->listen_host, &wildcard,
	    is_client, fwd_opts);
	debug3_f("type %d wildcard %d addr %s", type, wildcard,
	    (addr == ଖାଲି) ? "NULL" : addr);

	/*
	 * getaddrinfo returns a loopback address if the hostname is
	 * set to NULL and hints.ai_flags is not AI_PASSIVE
	 */
	memset(&hints, 0, ଆକାର(hints));
	hints.ai_family = ssh->chanctxt->IPv4or6;
	hints.ai_flags = wildcard ? AI_PASSIVE : 0;
	hints.ai_socktype = SOCK_STREAM;
	snprintf(strport, ଆକାର strport, "%d", fwd->listen_port);
	ଯଦି ((r = getaddrinfo(addr, strport, &hints, &aitop)) != 0) {
		ଯଦି (addr == ଖାଲି) {
			/* This really shouldn't happen */
			ssh_packet_disconnect(ssh, "getaddrinfo: fatal error: %s",
			    ssh_gai_strerror(r));
		} ଅନ୍ୟଥା {
			error_f("getaddrinfo(%.64s): %s", addr,
			    ssh_gai_strerror(r));
		}
		ଫେରନ୍ତୁ 0;
	}
	ଯଦି (allocated_listen_port != ଖାଲି)
		*allocated_listen_port = 0;
	ପାଇଁ (ai = aitop; ai; ai = ai->ai_next) {
		ବାଛ (ai->ai_family) {
		ସ୍ଥିତି AF_INET:
			lport_p = &((ସଂରଚନା sockaddr_in *)ai->ai_addr)->
			    sin_port;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି AF_INET6:
			lport_p = &((ସଂରଚନା sockaddr_in6 *)ai->ai_addr)->
			    sin6_port;
			ଭାଙ୍ଗ;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			ଜାରି;
		}
		/*
		 * If allocating a port for -R forwards, then use the
		 * same port for all address families.
		 */
		ଯଦି (type == SSH_CHANNEL_RPORT_LISTENER &&
		    fwd->listen_port == 0 && allocated_listen_port != ଖାଲି &&
		    *allocated_listen_port > 0)
			*lport_p = htons(*allocated_listen_port);

		ଯଦି (getnameinfo(ai->ai_addr, ai->ai_addrlen, ntop, ଆକାର(ntop),
		    strport, ଆକାର(strport),
		    NI_NUMERICHOST|NI_NUMERICSERV) != 0) {
			error_f("getnameinfo failed");
			ଜାରି;
		}
		/* Create a port to listen for the host. */
		sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		ଯଦି (sock == -1) {
			/* this is no error since kernel may not support ipv6 */
			verbose("socket [%s]:%s: %.100s", ntop, strport,
			    strerror(errno));
			ଜାରି;
		}

		set_reuseaddr(sock);
		ଯଦି (ai->ai_family == AF_INET6)
			sock_set_v6only(sock);

		debug("Local forwarding listening on %s port %s.",
		    ntop, strport);

		/* Bind the socket to the address. */
		ଯଦି (bind(sock, ai->ai_addr, ai->ai_addrlen) == -1) {
			/*
			 * address can be in if use ipv6 address is
			 * already bound
			 */
			ଯଦି (!ai->ai_next)
				error("bind [%s]:%s: %.100s",
				    ntop, strport, strerror(errno));
			ଅନ୍ୟଥା
				verbose("bind [%s]:%s: %.100s",
				    ntop, strport, strerror(errno));

			close(sock);
			ଜାରି;
		}
		/* Start listening for connections on the socket. */
		ଯଦି (listen(sock, SSH_LISTEN_BACKLOG) == -1) {
			error("listen [%s]:%s: %.100s", ntop, strport,
			    strerror(errno));
			close(sock);
			ଜାରି;
		}

		/*
		 * fwd->listen_port == 0 requests a dynamically allocated port -
		 * record what we got.
		 */
		ଯଦି (type == SSH_CHANNEL_RPORT_LISTENER &&
		    fwd->listen_port == 0 &&
		    allocated_listen_port != ଖାଲି &&
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
		c->listening_addr = addr == ଖାଲି ? ଖାଲି : xstrdup(addr);
		ଯଦି (fwd->listen_port == 0 && allocated_listen_port != ଖାଲି &&
		    !(ssh->compat & SSH_BUG_DYNAMIC_RPORT))
			c->listening_port = *allocated_listen_port;
		ଅନ୍ୟଥା
			c->listening_port = fwd->listen_port;
		success = 1;
	}
	ଯଦି (success == 0)
		error_f("cannot listen to port: %d", fwd->listen_port);
	freeaddrinfo(aitop);
	ଫେରନ୍ତୁ success;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
channel_setup_fwd_listener_streamlocal(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା type,
    ସଂରଚନା Forward *fwd, ସଂରଚନା ForwardOptions *fwd_opts)
{
	ସଂରଚନା sockaddr_un sunaddr;
	ଅଚଳ ଅକ୍ଷର *path;
	Channel *c;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା port, sock;
	mode_t omask;

	ବାଛ (type) {
	ସ୍ଥିତି SSH_CHANNEL_UNIX_LISTENER:
		ଯଦି (fwd->connect_path != ଖାଲି) {
			ଯଦି (strlen(fwd->connect_path) > ଆକାର(sunaddr.sun_path)) {
				error("Local connecting path too long: %s",
				    fwd->connect_path);
				ଫେରନ୍ତୁ 0;
			}
			path = fwd->connect_path;
			port = PORT_STREAMLOCAL;
		} ଅନ୍ୟଥା {
			ଯଦି (fwd->connect_host == ଖାଲି) {
				error("No forward host name.");
				ଫେରନ୍ତୁ 0;
			}
			ଯଦି (strlen(fwd->connect_host) >= NI_MAXHOST) {
				error("Forward host name too long.");
				ଫେରନ୍ତୁ 0;
			}
			path = fwd->connect_host;
			port = fwd->connect_port;
		}
		ଭାଙ୍ଗ;
	ସ୍ଥିତି SSH_CHANNEL_RUNIX_LISTENER:
		path = fwd->listen_path;
		port = PORT_STREAMLOCAL;
		ଭାଙ୍ଗ;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		error_f("unexpected channel type %d", type);
		ଫେରନ୍ତୁ 0;
	}

	ଯଦି (fwd->listen_path == ଖାଲି) {
		error("No forward path name.");
		ଫେରନ୍ତୁ 0;
	}
	ଯଦି (strlen(fwd->listen_path) > ଆକାର(sunaddr.sun_path)) {
		error("Local listening path too long: %s", fwd->listen_path);
		ଫେରନ୍ତୁ 0;
	}

	debug3_f("type %d path %s", type, fwd->listen_path);

	/* Start a Unix domain listener. */
	omask = umask(fwd_opts->streamlocal_bind_mask);
	sock = unix_listener(fwd->listen_path, SSH_LISTEN_BACKLOG,
	    fwd_opts->streamlocal_bind_unlink);
	umask(omask);
	ଯଦି (sock < 0)
		ଫେରନ୍ତୁ 0;

	debug("Local forwarding listening on path %s.", fwd->listen_path);

	/* Allocate a channel number for the socket. */
	c = channel_new(ssh, "unix-listener", type, sock, sock, -1,
	    CHAN_TCP_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT,
	    0, "unix listener", 1);
	c->path = xstrdup(path);
	c->host_port = port;
	c->listening_port = PORT_STREAMLOCAL;
	c->listening_addr = xstrdup(fwd->listen_path);
	ଫେରନ୍ତୁ 1;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
channel_cancel_rport_listener_tcpip(ସଂରଚନା ssh *ssh,
    ଅଚଳ ଅକ୍ଷର *host, u_short port)
{
	u_int i;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା found = 0;

	ପାଇଁ (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		Channel *c = ssh->chanctxt->channels[i];
		ଯଦି (c == ଖାଲି || c->type != SSH_CHANNEL_RPORT_LISTENER)
			ଜାରି;
		ଯଦି (strcmp(c->path, host) == 0 && c->listening_port == port) {
			debug2_f("close channel %d", i);
			channel_free(ssh, c);
			found = 1;
		}
	}

	ଫେରନ୍ତୁ found;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
channel_cancel_rport_listener_streamlocal(ସଂରଚନା ssh *ssh, ଅଚଳ ଅକ୍ଷର *path)
{
	u_int i;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା found = 0;

	ପାଇଁ (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		Channel *c = ssh->chanctxt->channels[i];
		ଯଦି (c == ଖାଲି || c->type != SSH_CHANNEL_RUNIX_LISTENER)
			ଜାରି;
		ଯଦି (c->path == ଖାଲି)
			ଜାରି;
		ଯଦି (strcmp(c->path, path) == 0) {
			debug2_f("close channel %d", i);
			channel_free(ssh, c);
			found = 1;
		}
	}

	ଫେରନ୍ତୁ found;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
channel_cancel_rport_listener(ସଂରଚନା ssh *ssh, ସଂରଚନା Forward *fwd)
{
	ଯଦି (fwd->listen_path != ଖାଲି) {
		ଫେରନ୍ତୁ channel_cancel_rport_listener_streamlocal(ssh,
		    fwd->listen_path);
	} ଅନ୍ୟଥା {
		ଫେରନ୍ତୁ channel_cancel_rport_listener_tcpip(ssh,
		    fwd->listen_host, fwd->listen_port);
	}
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
channel_cancel_lport_listener_tcpip(ସଂରଚନା ssh *ssh,
    ଅଚଳ ଅକ୍ଷର *lhost, u_short lport, ପୂର୍ଣ୍ଣସଂଖ୍ୟା cport,
    ସଂରଚନା ForwardOptions *fwd_opts)
{
	u_int i;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା found = 0;
	ଅଚଳ ଅକ୍ଷର *addr = channel_fwd_bind_addr(ssh, lhost, ଖାଲି, 1, fwd_opts);

	ପାଇଁ (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		Channel *c = ssh->chanctxt->channels[i];
		ଯଦି (c == ଖାଲି || c->type != SSH_CHANNEL_PORT_LISTENER)
			ଜାରି;
		ଯଦି (c->listening_port != lport)
			ଜାରି;
		ଯଦି (cport == CHANNEL_CANCEL_PORT_STATIC) {
			/* skip dynamic forwardings */
			ଯଦି (c->host_port == 0)
				ଜାରି;
		} ଅନ୍ୟଥା {
			ଯଦି (c->host_port != cport)
				ଜାରି;
		}
		ଯଦି ((c->listening_addr == ଖାଲି && addr != ଖାଲି) ||
		    (c->listening_addr != ଖାଲି && addr == ଖାଲି))
			ଜାରି;
		ଯଦି (addr == ଖାଲି || strcmp(c->listening_addr, addr) == 0) {
			debug2_f("close channel %d", i);
			channel_free(ssh, c);
			found = 1;
		}
	}

	ଫେରନ୍ତୁ found;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
channel_cancel_lport_listener_streamlocal(ସଂରଚନା ssh *ssh, ଅଚଳ ଅକ୍ଷର *path)
{
	u_int i;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା found = 0;

	ଯଦି (path == ଖାଲି) {
		error_f("no path specified.");
		ଫେରନ୍ତୁ 0;
	}

	ପାଇଁ (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		Channel *c = ssh->chanctxt->channels[i];
		ଯଦି (c == ଖାଲି || c->type != SSH_CHANNEL_UNIX_LISTENER)
			ଜାରି;
		ଯଦି (c->listening_addr == ଖାଲି)
			ଜାରି;
		ଯଦି (strcmp(c->listening_addr, path) == 0) {
			debug2_f("close channel %d", i);
			channel_free(ssh, c);
			found = 1;
		}
	}

	ଫେରନ୍ତୁ found;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
channel_cancel_lport_listener(ସଂରଚନା ssh *ssh,
    ସଂରଚନା Forward *fwd, ପୂର୍ଣ୍ଣସଂଖ୍ୟା cport, ସଂରଚନା ForwardOptions *fwd_opts)
{
	ଯଦି (fwd->listen_path != ଖାଲି) {
		ଫେରନ୍ତୁ channel_cancel_lport_listener_streamlocal(ssh,
		    fwd->listen_path);
	} ଅନ୍ୟଥା {
		ଫେରନ୍ତୁ channel_cancel_lport_listener_tcpip(ssh,
		    fwd->listen_host, fwd->listen_port, cport, fwd_opts);
	}
}

/* protocol local port fwd, used by ssh */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
channel_setup_local_fwd_listener(ସଂରଚନା ssh *ssh,
    ସଂରଚନା Forward *fwd, ସଂରଚନା ForwardOptions *fwd_opts)
{
	ଯଦି (fwd->listen_path != ଖାଲି) {
		ଫେରନ୍ତୁ channel_setup_fwd_listener_streamlocal(ssh,
		    SSH_CHANNEL_UNIX_LISTENER, fwd, fwd_opts);
	} ଅନ୍ୟଥା {
		ଫେରନ୍ତୁ channel_setup_fwd_listener_tcpip(ssh,
		    SSH_CHANNEL_PORT_LISTENER, fwd, ଖାଲି, fwd_opts);
	}
}

/* Matches a remote forwarding permission against a requested forwarding */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
remote_open_match(ସଂରଚନା permission *allowed_open, ସଂରଚନା Forward *fwd)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret;
	ଅକ୍ଷର *lhost;

	/* XXX add ACLs for streamlocal */
	ଯଦି (fwd->listen_path != ଖାଲି)
		ଫେରନ୍ତୁ 1;

	ଯଦି (fwd->listen_host == ଖାଲି || allowed_open->listen_host == ଖାଲି)
		ଫେରନ୍ତୁ 0;

	ଯଦି (allowed_open->listen_port != FWD_PERMIT_ANY_PORT &&
	    allowed_open->listen_port != fwd->listen_port)
		ଫେରନ୍ତୁ 0;

	/* Match hostnames case-insensitively */
	lhost = xstrdup(fwd->listen_host);
	lowercase(lhost);
	ret = match_pattern(lhost, allowed_open->listen_host);
	ମୁକ୍ତ(lhost);

	ଫେରନ୍ତୁ ret;
}

/* Checks whether a requested remote forwarding is permitted */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
check_rfwd_permission(ସଂରଚନା ssh *ssh, ସଂରଚନା Forward *fwd)
{
	ସଂରଚନା ssh_channels *sc = ssh->chanctxt;
	ସଂରଚନା permission_set *pset = &sc->remote_perms;
	u_int i, permit, permit_adm = 1;
	ସଂରଚନା permission *perm;

#ifdef SKIP_PRIVDROP
	ଯଦି (fwd->listen_path != ଖାଲି)
		ଫେରନ୍ତୁ 0;
	ଯଦି (fwd->listen_port != 0 && fwd->listen_port < 1024)
		ଫେରନ୍ତୁ 0;
#endif

	/* XXX apply GatewayPorts override before checking? */

	permit = pset->all_permitted;
	ଯଦି (!permit) {
		ପାଇଁ (i = 0; i < pset->ଅଙ୍କ_permitted_user; i++) {
			perm = &pset->permitted_user[i];
			ଯଦି (remote_open_match(perm, fwd)) {
				permit = 1;
				ଭାଙ୍ଗ;
			}
		}
	}

	ଯଦି (pset->ଅଙ୍କ_permitted_admin > 0) {
		permit_adm = 0;
		ପାଇଁ (i = 0; i < pset->ଅଙ୍କ_permitted_admin; i++) {
			perm = &pset->permitted_admin[i];
			ଯଦି (remote_open_match(perm, fwd)) {
				permit_adm = 1;
				ଭାଙ୍ଗ;
			}
		}
	}

	ଫେରନ୍ତୁ permit && permit_adm;
}

/* protocol v2 remote port fwd, used by sshd */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
channel_setup_remote_fwd_listener(ସଂରଚନା ssh *ssh, ସଂରଚନା Forward *fwd,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା *allocated_listen_port, ସଂରଚନା ForwardOptions *fwd_opts)
{
	ଯଦି (!check_rfwd_permission(ssh, fwd)) {
		ssh_packet_send_debug(ssh, "port forwarding refused");
		ଯଦି (fwd->listen_path != ଖାଲି)
			/* XXX always allowed, see remote_open_match() */
			logit("Received request from %.100s port %d to "
			    "remote forward to path \"%.100s\", "
			    "but the request was denied.",
			    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
			    fwd->listen_path);
		ଅନ୍ୟଥା ଯଦି(fwd->listen_host != ଖାଲି)
			logit("Received request from %.100s port %d to "
			    "remote forward to host %.100s port %d, "
			    "but the request was denied.",
			    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
			    fwd->listen_host, fwd->listen_port );
		ଅନ୍ୟଥା
			logit("Received request from %.100s port %d to remote "
			    "forward, but the request was denied.",
			    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
		ଫେରନ୍ତୁ 0;
	}
	ଯଦି (fwd->listen_path != ଖାଲି) {
		ଫେରନ୍ତୁ channel_setup_fwd_listener_streamlocal(ssh,
		    SSH_CHANNEL_RUNIX_LISTENER, fwd, fwd_opts);
	} ଅନ୍ୟଥା {
		ଫେରନ୍ତୁ channel_setup_fwd_listener_tcpip(ssh,
		    SSH_CHANNEL_RPORT_LISTENER, fwd, allocated_listen_port,
		    fwd_opts);
	}
}

/*
 * Translate the requested rfwd listen host to something usable for
 * this server.
 */
ସ୍ଥିର ଅଚଳ ଅକ୍ଷର *
channel_rfwd_bind_host(ଅଚଳ ଅକ୍ଷର *listen_host)
{
	ଯଦି (listen_host == ଖାଲି) {
		ଫେରନ୍ତୁ "localhost";
	} ଅନ୍ୟଥା ଯଦି (*listen_host == '\0' || strcmp(listen_host, "*") == 0) {
		ଫେରନ୍ତୁ "";
	} ଅନ୍ୟଥା
		ଫେରନ୍ତୁ listen_host;
}

/*
 * Initiate forwarding of connections to port "port" on remote host through
 * the secure channel to host:port from local side.
 * Returns handle (index) for updating the dynamic listen port with
 * channel_update_permission().
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
channel_request_remote_forwarding(ସଂରଚନା ssh *ssh, ସଂରଚନା Forward *fwd)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, success = 0, idx = -1;
	ଅଚଳ ଅକ୍ଷର *host_to_connect, *listen_host, *listen_path;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା port_to_connect, listen_port;

	/* Send the forward request to the remote side. */
	ଯଦି (fwd->listen_path != ଖାଲି) {
		ଯଦି ((r = sshpkt_start(ssh, SSH2_ସନ୍ଦେଶ_GLOBAL_REQUEST)) != 0 ||
		    (r = sshpkt_put_cstring(ssh,
		    "streamlocal-forward@openssh.com")) != 0 ||
		    (r = sshpkt_put_u8(ssh, 1)) != 0 || /* want reply */
		    (r = sshpkt_put_cstring(ssh, fwd->listen_path)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			fatal_fr(r, "request streamlocal");
	} ଅନ୍ୟଥା {
		ଯଦି ((r = sshpkt_start(ssh, SSH2_ସନ୍ଦେଶ_GLOBAL_REQUEST)) != 0 ||
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
	ଯଦି (success) {
		/* Record that connection to this host/port is permitted. */
		host_to_connect = listen_host = listen_path = ଖାଲି;
		port_to_connect = listen_port = 0;
		ଯଦି (fwd->connect_path != ଖାଲି) {
			host_to_connect = fwd->connect_path;
			port_to_connect = PORT_STREAMLOCAL;
		} ଅନ୍ୟଥା {
			host_to_connect = fwd->connect_host;
			port_to_connect = fwd->connect_port;
		}
		ଯଦି (fwd->listen_path != ଖାଲି) {
			listen_path = fwd->listen_path;
			listen_port = PORT_STREAMLOCAL;
		} ଅନ୍ୟଥା {
			listen_host = fwd->listen_host;
			listen_port = fwd->listen_port;
		}
		idx = permission_set_add(ssh, FORWARD_USER, FORWARD_LOCAL,
		    host_to_connect, port_to_connect,
		    listen_host, listen_path, listen_port, ଖାଲି);
	}
	ଫେରନ୍ତୁ idx;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
open_match(ସଂରଚନା permission *allowed_open, ଅଚଳ ଅକ୍ଷର *requestedhost,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା requestedport)
{
	ଯଦି (allowed_open->host_to_connect == ଖାଲି)
		ଫେରନ୍ତୁ 0;
	ଯଦି (allowed_open->port_to_connect != FWD_PERMIT_ANY_PORT &&
	    allowed_open->port_to_connect != requestedport)
		ଫେରନ୍ତୁ 0;
	ଯଦି (strcmp(allowed_open->host_to_connect, FWD_PERMIT_ANY_HOST) != 0 &&
	    strcmp(allowed_open->host_to_connect, requestedhost) != 0)
		ଫେରନ୍ତୁ 0;
	ଫେରନ୍ତୁ 1;
}

/*
 * Note that in the listen host/port case
 * we don't support FWD_PERMIT_ANY_PORT and
 * need to translate between the configured-host (listen_host)
 * and what we've sent to the remote server (channel_rfwd_bind_host)
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
open_listen_match_tcpip(ସଂରଚନା permission *allowed_open,
    ଅଚଳ ଅକ୍ଷର *requestedhost, u_short requestedport, ପୂର୍ଣ୍ଣସଂଖ୍ୟା translate)
{
	ଅଚଳ ଅକ୍ଷର *allowed_host;

	ଯଦି (allowed_open->host_to_connect == ଖାଲି)
		ଫେରନ୍ତୁ 0;
	ଯଦି (allowed_open->listen_port != requestedport)
		ଫେରନ୍ତୁ 0;
	ଯଦି (!translate && allowed_open->listen_host == ଖାଲି &&
	    requestedhost == ଖାଲି)
		ଫେରନ୍ତୁ 1;
	allowed_host = translate ?
	    channel_rfwd_bind_host(allowed_open->listen_host) :
	    allowed_open->listen_host;
	ଯଦି (allowed_host == ଖାଲି || requestedhost == ଖାଲି ||
	    strcmp(allowed_host, requestedhost) != 0)
		ଫେରନ୍ତୁ 0;
	ଫେରନ୍ତୁ 1;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
open_listen_match_streamlocal(ସଂରଚନା permission *allowed_open,
    ଅଚଳ ଅକ୍ଷର *requestedpath)
{
	ଯଦି (allowed_open->host_to_connect == ଖାଲି)
		ଫେରନ୍ତୁ 0;
	ଯଦି (allowed_open->listen_port != PORT_STREAMLOCAL)
		ଫେରନ୍ତୁ 0;
	ଯଦି (allowed_open->listen_path == ଖାଲି ||
	    strcmp(allowed_open->listen_path, requestedpath) != 0)
		ଫେରନ୍ତୁ 0;
	ଫେରନ୍ତୁ 1;
}

/*
 * Request cancellation of remote forwarding of connection host:port from
 * local side.
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
channel_request_rforward_cancel_tcpip(ସଂରଚନା ssh *ssh,
    ଅଚଳ ଅକ୍ଷର *host, u_short port)
{
	ସଂରଚନା ssh_channels *sc = ssh->chanctxt;
	ସଂରଚନା permission_set *pset = &sc->local_perms;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	u_int i;
	ସଂରଚନା permission *perm = ଖାଲି;

	ପାଇଁ (i = 0; i < pset->ଅଙ୍କ_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		ଯଦି (open_listen_match_tcpip(perm, host, port, 0))
			ଭାଙ୍ଗ;
		perm = ଖାଲି;
	}
	ଯଦି (perm == ଖାଲି) {
		debug_f("requested forward not found");
		ଫେରନ୍ତୁ -1;
	}
	ଯଦି ((r = sshpkt_start(ssh, SSH2_ସନ୍ଦେଶ_GLOBAL_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "cancel-tcpip-forward")) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 || /* want reply */
	    (r = sshpkt_put_cstring(ssh, channel_rfwd_bind_host(host))) != 0 ||
	    (r = sshpkt_put_u32(ssh, port)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send cancel");

	fwd_perm_clear(perm); /* unregister */

	ଫେରନ୍ତୁ 0;
}

/*
 * Request cancellation of remote forwarding of Unix domain socket
 * path from local side.
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
channel_request_rforward_cancel_streamlocal(ସଂରଚନା ssh *ssh, ଅଚଳ ଅକ୍ଷର *path)
{
	ସଂରଚନା ssh_channels *sc = ssh->chanctxt;
	ସଂରଚନା permission_set *pset = &sc->local_perms;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	u_int i;
	ସଂରଚନା permission *perm = ଖାଲି;

	ପାଇଁ (i = 0; i < pset->ଅଙ୍କ_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		ଯଦି (open_listen_match_streamlocal(perm, path))
			ଭାଙ୍ଗ;
		perm = ଖାଲି;
	}
	ଯଦି (perm == ଖାଲି) {
		debug_f("requested forward not found");
		ଫେରନ୍ତୁ -1;
	}
	ଯଦି ((r = sshpkt_start(ssh, SSH2_ସନ୍ଦେଶ_GLOBAL_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh,
	    "cancel-streamlocal-forward@openssh.com")) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 || /* want reply */
	    (r = sshpkt_put_cstring(ssh, path)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send cancel");

	fwd_perm_clear(perm); /* unregister */

	ଫେରନ୍ତୁ 0;
}

/*
 * Request cancellation of remote forwarding of a connection from local side.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
channel_request_rforward_cancel(ସଂରଚନା ssh *ssh, ସଂରଚନା Forward *fwd)
{
	ଯଦି (fwd->listen_path != ଖାଲି) {
		ଫେରନ୍ତୁ channel_request_rforward_cancel_streamlocal(ssh,
		    fwd->listen_path);
	} ଅନ୍ୟଥା {
		ଫେରନ୍ତୁ channel_request_rforward_cancel_tcpip(ssh,
		    fwd->listen_host,
		    fwd->listen_port ? fwd->listen_port : fwd->allocated_port);
	}
}

/*
 * Permits opening to any host/port if permitted_user[] is empty.  This is
 * usually called by the server, because the user could connect to any port
 * anyway, and the server has no way to know but to trust the client anyway.
 */
ଶୂନ୍ୟ
channel_permit_all(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା where)
{
	ସଂରଚନା permission_set *pset = permission_set_get(ssh, where);

	ଯଦି (pset->ଅଙ୍କ_permitted_user == 0)
		pset->all_permitted = 1;
}

/*
 * Permit the specified host/port for forwarding.
 */
ଶୂନ୍ୟ
channel_add_permission(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା who, ପୂର୍ଣ୍ଣସଂଖ୍ୟା where,
    ଅକ୍ଷର *host, ପୂର୍ଣ୍ଣସଂଖ୍ୟା port)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା local = where == FORWARD_LOCAL;
	ସଂରଚନା permission_set *pset = permission_set_get(ssh, where);

	debug("allow %s forwarding to host %s port %d",
	    fwd_ident(who, where), host, port);
	/*
	 * Remote forwards set listen_host/port, local forwards set
	 * host/port_to_connect.
	 */
	permission_set_add(ssh, who, where,
	    local ? host : ଖାଲି, local ? port : 0,
	    local ? ଖାଲି : host, ଖାଲି, local ? 0 : port, ଖାଲି);
	pset->all_permitted = 0;
}

/*
 * Administratively disable forwarding.
 */
ଶୂନ୍ୟ
channel_disable_admin(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା where)
{
	channel_clear_permission(ssh, FORWARD_ADM, where);
	permission_set_add(ssh, FORWARD_ADM, where,
	    ଖାଲି, 0, ଖାଲି, ଖାଲି, 0, ଖାଲି);
}

/*
 * Clear a list of permitted opens.
 */
ଶୂନ୍ୟ
channel_clear_permission(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା who, ପୂର୍ଣ୍ଣସଂଖ୍ୟା where)
{
	ସଂରଚନା permission **permp;
	u_int i, *npermp;

	permission_set_get_array(ssh, who, where, &permp, &npermp);
	ପାଇଁ (i = 0; i < *npermp; i++)
		fwd_perm_clear((*permp) + i);
	ମୁକ୍ତ(*permp);
	*permp = ଖାଲି;
	*npermp = 0;
}

/*
 * Update the listen port for a dynamic remote forward, after
 * the actual 'newport' has been allocated. If 'newport' < 0 is
 * passed then they entry will be invalidated.
 */
ଶୂନ୍ୟ
channel_update_permission(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା idx, ପୂର୍ଣ୍ଣସଂଖ୍ୟା newport)
{
	ସଂରଚନା permission_set *pset = &ssh->chanctxt->local_perms;

	ଯଦି (idx < 0 || (u_int)idx >= pset->ଅଙ୍କ_permitted_user) {
		debug_f("index out of range: %d num_permitted_user %d",
		    idx, pset->ଅଙ୍କ_permitted_user);
		ଫେରନ୍ତୁ;
	}
	debug("%s allowed port %d for forwarding to host %s port %d",
	    newport > 0 ? "Updating" : "Removing",
	    newport,
	    pset->permitted_user[idx].host_to_connect,
	    pset->permitted_user[idx].port_to_connect);
	ଯଦି (newport <= 0)
		fwd_perm_clear(&pset->permitted_user[idx]);
	ଅନ୍ୟଥା {
		pset->permitted_user[idx].listen_port =
		    (ssh->compat & SSH_BUG_DYNAMIC_RPORT) ? 0 : newport;
	}
}

/* Try to start non-blocking connect to next host in cctx list */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
connect_next(ସଂରଚନା ssh *ssh, ସଂରଚନା channel_connect *cctx)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock, sock_is_network, saved_errno;
	ସଂରଚନା sockaddr_un *sunaddr;
	ଅକ୍ଷର ntop[NI_MAXHOST];
	ଅକ୍ଷର strport[MAXIMUM(NI_MAXSERV, ଆକାର(sunaddr->sun_path))];

	ପାଇଁ (; cctx->ai; cctx->ai = cctx->ai->ai_next) {
		sock_is_network = 0;
		ବାଛ (cctx->ai->ai_family) {
		ସ୍ଥିତି AF_UNIX:
			/* unix:pathname instead of host:port */
			sunaddr = (ସଂରଚନା sockaddr_un *)cctx->ai->ai_addr;
			strlcpy(ntop, "unix", ଆକାର(ntop));
			strlcpy(strport, sunaddr->sun_path, ଆକାର(strport));
			ଭାଙ୍ଗ;
		ସ୍ଥିତି AF_INET:
		ସ୍ଥିତି AF_INET6:
			ଯଦି (getnameinfo(cctx->ai->ai_addr, cctx->ai->ai_addrlen,
			    ntop, ଆକାର(ntop), strport, ଆକାର(strport),
			    NI_NUMERICHOST|NI_NUMERICSERV) != 0) {
				error_f("getnameinfo failed");
				ଜାରି;
			}
			sock_is_network = 1;
			ଭାଙ୍ଗ;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			ଜାରି;
		}
		debug_f("start for host %.100s ([%.100s]:%s)",
		    cctx->host, ntop, strport);
		ଯଦି ((sock = socket(cctx->ai->ai_family, cctx->ai->ai_socktype,
		    cctx->ai->ai_protocol)) == -1) {
			ଯଦି (cctx->ai->ai_next == ଖାଲି)
				error("socket: %.100s", strerror(errno));
			ଅନ୍ୟଥା
				verbose("socket: %.100s", strerror(errno));
			ଜାରି;
		}
		ଯଦି (set_nonblock(sock) == -1)
			fatal_f("set_nonblock(%d)", sock);
		ଯଦି (sock_is_network && ssh->chanctxt->want_tcp_keepalive)
			set_keepalive(sock); /* logs errors */
		ଯଦି (connect(sock, cctx->ai->ai_addr,
		    cctx->ai->ai_addrlen) == -1 && errno != EINPROGRESS) {
			debug_f("host %.100s ([%.100s]:%s): %.100s",
			    cctx->host, ntop, strport, strerror(errno));
			saved_errno = errno;
			close(sock);
			errno = saved_errno;
			ଜାରି;	/* fail -- try next */
		}
		ଯଦି (cctx->ai->ai_family != AF_UNIX)
			set_nodelay(sock);
		debug_f("connect host %.100s ([%.100s]:%s) in progress, fd=%d",
		    cctx->host, ntop, strport, sock);
		cctx->ai = cctx->ai->ai_next;
		ଫେରନ୍ତୁ sock;
	}
	ଫେରନ୍ତୁ -1;
}

/*
 * Return connecting socket to remote host:port or local socket path,
 * passing back the failure reason if appropriate.
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
connect_to_helper(ସଂରଚନା ssh *ssh, ଅଚଳ ଅକ୍ଷର *name, ପୂର୍ଣ୍ଣସଂଖ୍ୟା port, ପୂର୍ଣ୍ଣସଂଖ୍ୟା socktype,
    ଅକ୍ଷର *ctype, ଅକ୍ଷର *rname, ସଂରଚନା channel_connect *cctx,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା *reason, ଅଚଳ ଅକ୍ଷର **errmsg)
{
	ସଂରଚନା addrinfo hints;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା gaierr;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock = -1;
	ଅକ୍ଷର strport[NI_MAXSERV];

	ଯଦି (port == PORT_STREAMLOCAL) {
		ସଂରଚନା sockaddr_un *sunaddr;
		ସଂରଚନା addrinfo *ai;

		ଯଦି (strlen(name) > ଆକାର(sunaddr->sun_path)) {
			error("%.100s: %.100s", name, strerror(ENAMETOOLONG));
			ଫେରନ୍ତୁ -1;
		}

		/*
		 * Fake up a struct addrinfo for AF_UNIX connections.
		 * free_connect_ctx() must check ai_family
		 * and use free() not freeaddrinfo() for AF_UNIX.
		 */
		ai = xcalloc(1, ଆକାର(*ai) + ଆକାର(*sunaddr));
		ai->ai_addr = (ସଂରଚନା sockaddr *)(ai + 1);
		ai->ai_addrlen = ଆକାର(*sunaddr);
		ai->ai_family = AF_UNIX;
		ai->ai_socktype = socktype;
		ai->ai_protocol = PF_UNSPEC;
		sunaddr = (ସଂରଚନା sockaddr_un *)ai->ai_addr;
		sunaddr->sun_family = AF_UNIX;
		strlcpy(sunaddr->sun_path, name, ଆକାର(sunaddr->sun_path));
		cctx->aitop = ai;
	} ଅନ୍ୟଥା {
		memset(&hints, 0, ଆକାର(hints));
		hints.ai_family = ssh->chanctxt->IPv4or6;
		hints.ai_socktype = socktype;
		snprintf(strport, ଆକାର strport, "%d", port);
		ଯଦି ((gaierr = getaddrinfo(name, strport, &hints, &cctx->aitop))
		    != 0) {
			ଯଦି (errmsg != ଖାଲି)
				*errmsg = ssh_gai_strerror(gaierr);
			ଯଦି (reason != ଖାଲି)
				*reason = SSH2_OPEN_CONNECT_FAILED;
			error("connect_to %.100s: unknown host (%s)", name,
			    ssh_gai_strerror(gaierr));
			ଫେରନ୍ତୁ -1;
		}
	}

	cctx->host = xstrdup(name);
	cctx->port = port;
	cctx->ai = cctx->aitop;

	ଯଦି ((sock = connect_next(ssh, cctx)) == -1) {
		error("connect to %.100s port %d failed: %s",
		    name, port, strerror(errno));
		ଫେରନ୍ତୁ -1;
	}

	ଫେରନ୍ତୁ sock;
}

/* Return CONNECTING channel to remote host:port or local socket path */
ସ୍ଥିର Channel *
connect_to(ସଂରଚନା ssh *ssh, ଅଚଳ ଅକ୍ଷର *host, ପୂର୍ଣ୍ଣସଂଖ୍ୟା port,
    ଅକ୍ଷର *ctype, ଅକ୍ଷର *rname)
{
	ସଂରଚନା channel_connect cctx;
	Channel *c;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock;

	memset(&cctx, 0, ଆକାର(cctx));
	sock = connect_to_helper(ssh, host, port, SOCK_STREAM, ctype, rname,
	    &cctx, ଖାଲି, ଖାଲି);
	ଯଦି (sock == -1) {
		free_connect_ctx(&cctx);
		ଫେରନ୍ତୁ ଖାଲି;
	}
	c = channel_new(ssh, ctype, SSH_CHANNEL_CONNECTING, sock, sock, -1,
	    CHAN_TCP_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, rname, 1);
	c->host_port = port;
	c->path = xstrdup(host);
	c->connect_ctx = xmalloc(ଆକାର(cctx));
	memcpy(c->connect_ctx, &cctx, ଆକାର(cctx));

	ଫେରନ୍ତୁ c;
}

/*
 * returns either the newly connected channel or the downstream channel
 * that needs to deal with this connection.
 */
Channel *
channel_connect_by_listen_address(ସଂରଚନା ssh *ssh, ଅଚଳ ଅକ୍ଷର *listen_host,
    u_short listen_port, ଅକ୍ଷର *ctype, ଅକ୍ଷର *rname)
{
	ସଂରଚନା ssh_channels *sc = ssh->chanctxt;
	ସଂରଚନା permission_set *pset = &sc->local_perms;
	u_int i;
	ସଂରଚନା permission *perm;

	ପାଇଁ (i = 0; i < pset->ଅଙ୍କ_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		ଯଦି (open_listen_match_tcpip(perm,
		    listen_host, listen_port, 1)) {
			ଯଦି (perm->downstream)
				ଫେରନ୍ତୁ perm->downstream;
			ଯଦି (perm->port_to_connect == 0)
				ଫେରନ୍ତୁ rdynamic_connect_prepare(ssh,
				    ctype, rname);
			ଫେରନ୍ତୁ connect_to(ssh,
			    perm->host_to_connect, perm->port_to_connect,
			    ctype, rname);
		}
	}
	error("WARNING: Server requests forwarding for unknown listen_port %d",
	    listen_port);
	ଫେରନ୍ତୁ ଖାଲି;
}

Channel *
channel_connect_by_listen_path(ସଂରଚନା ssh *ssh, ଅଚଳ ଅକ୍ଷର *path,
    ଅକ୍ଷର *ctype, ଅକ୍ଷର *rname)
{
	ସଂରଚନା ssh_channels *sc = ssh->chanctxt;
	ସଂରଚନା permission_set *pset = &sc->local_perms;
	u_int i;
	ସଂରଚନା permission *perm;

	ପାଇଁ (i = 0; i < pset->ଅଙ୍କ_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		ଯଦି (open_listen_match_streamlocal(perm, path)) {
			ଫେରନ୍ତୁ connect_to(ssh,
			    perm->host_to_connect, perm->port_to_connect,
			    ctype, rname);
		}
	}
	error("WARNING: Server requests forwarding for unknown path %.100s",
	    path);
	ଫେରନ୍ତୁ ଖାଲି;
}

/* Check if connecting to that port is permitted and connect. */
Channel *
channel_connect_to_port(ସଂରଚନା ssh *ssh, ଅଚଳ ଅକ୍ଷର *host, u_short port,
    ଅକ୍ଷର *ctype, ଅକ୍ଷର *rname, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *reason, ଅଚଳ ଅକ୍ଷର **errmsg)
{
	ସଂରଚନା ssh_channels *sc = ssh->chanctxt;
	ସଂରଚନା permission_set *pset = &sc->local_perms;
	ସଂରଚନା channel_connect cctx;
	Channel *c;
	u_int i, permit, permit_adm = 1;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock;
	ସଂରଚନା permission *perm;

	permit = pset->all_permitted;
	ଯଦି (!permit) {
		ପାଇଁ (i = 0; i < pset->ଅଙ୍କ_permitted_user; i++) {
			perm = &pset->permitted_user[i];
			ଯଦି (open_match(perm, host, port)) {
				permit = 1;
				ଭାଙ୍ଗ;
			}
		}
	}

	ଯଦି (pset->ଅଙ୍କ_permitted_admin > 0) {
		permit_adm = 0;
		ପାଇଁ (i = 0; i < pset->ଅଙ୍କ_permitted_admin; i++) {
			perm = &pset->permitted_admin[i];
			ଯଦି (open_match(perm, host, port)) {
				permit_adm = 1;
				ଭାଙ୍ଗ;
			}
		}
	}

	ଯଦି (!permit || !permit_adm) {
		logit("Received request from %.100s port %d to connect to "
		    "host %.100s port %d, but the request was denied.",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh), host, port);
		ଯଦି (reason != ଖାଲି)
			*reason = SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED;
		ଫେରନ୍ତୁ ଖାଲି;
	}

	memset(&cctx, 0, ଆକାର(cctx));
	sock = connect_to_helper(ssh, host, port, SOCK_STREAM, ctype, rname,
	    &cctx, reason, errmsg);
	ଯଦି (sock == -1) {
		free_connect_ctx(&cctx);
		ଫେରନ୍ତୁ ଖାଲି;
	}

	c = channel_new(ssh, ctype, SSH_CHANNEL_CONNECTING, sock, sock, -1,
	    CHAN_TCP_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, rname, 1);
	c->host_port = port;
	c->path = xstrdup(host);
	c->connect_ctx = xmalloc(ଆକାର(cctx));
	memcpy(c->connect_ctx, &cctx, ଆକାର(cctx));

	ଫେରନ୍ତୁ c;
}

/* Check if connecting to that path is permitted and connect. */
Channel *
channel_connect_to_path(ସଂରଚନା ssh *ssh, ଅଚଳ ଅକ୍ଷର *path,
    ଅକ୍ଷର *ctype, ଅକ୍ଷର *rname)
{
	ସଂରଚନା ssh_channels *sc = ssh->chanctxt;
	ସଂରଚନା permission_set *pset = &sc->local_perms;
	u_int i, permit, permit_adm = 1;
	ସଂରଚନା permission *perm;

	permit = pset->all_permitted;
	ଯଦି (!permit) {
		ପାଇଁ (i = 0; i < pset->ଅଙ୍କ_permitted_user; i++) {
			perm = &pset->permitted_user[i];
			ଯଦି (open_match(perm, path, PORT_STREAMLOCAL)) {
				permit = 1;
				ଭାଙ୍ଗ;
			}
		}
	}

	ଯଦି (pset->ଅଙ୍କ_permitted_admin > 0) {
		permit_adm = 0;
		ପାଇଁ (i = 0; i < pset->ଅଙ୍କ_permitted_admin; i++) {
			perm = &pset->permitted_admin[i];
			ଯଦି (open_match(perm, path, PORT_STREAMLOCAL)) {
				permit_adm = 1;
				ଭାଙ୍ଗ;
			}
		}
	}

	ଯଦି (!permit || !permit_adm) {
		logit("Received request to connect to path %.100s, "
		    "but the request was denied.", path);
		ଫେରନ୍ତୁ ଖାଲି;
	}
	ଫେରନ୍ତୁ connect_to(ssh, path, PORT_STREAMLOCAL, ctype, rname);
}

ଶୂନ୍ୟ
channel_send_window_changes(ସଂରଚନା ssh *ssh)
{
	ସଂରଚନା ssh_channels *sc = ssh->chanctxt;
	ସଂରଚନା winsize ws;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	u_int i;

	ପାଇଁ (i = 0; i < sc->channels_alloc; i++) {
		ଯଦି (sc->channels[i] == ଖାଲି || !sc->channels[i]->client_tty ||
		    sc->channels[i]->type != SSH_CHANNEL_OPEN)
			ଜାରି;
		ଯଦି (ioctl(sc->channels[i]->rfd, TIOCGWINSZ, &ws) == -1)
			ଜାରି;
		channel_request_start(ssh, i, "window-change", 0);
		ଯଦି ((r = sshpkt_put_u32(ssh, (u_int)ws.ws_col)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_row)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_xpixel)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_ypixel)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "channel %u; send window-change", i);
	}
}

/* Return RDYNAMIC_OPEN channel: channel allows SOCKS, but is not connected */
ସ୍ଥିର Channel *
rdynamic_connect_prepare(ସଂରଚନା ssh *ssh, ଅକ୍ଷର *ctype, ଅକ୍ଷର *rname)
{
	Channel *c;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	c = channel_new(ssh, ctype, SSH_CHANNEL_RDYNAMIC_OPEN, -1, -1, -1,
	    CHAN_TCP_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, rname, 1);
	c->host_port = 0;
	c->path = ଖାଲି;

	/*
	 * We need to open the channel before we have a FD,
	 * so that we can get SOCKS header from peer.
	 */
	ଯଦି ((r = sshpkt_start(ssh, SSH2_ସନ୍ଦେଶ_CHANNEL_OPEN_CONFIRMATION)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_window)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0)
		fatal_fr(r, "channel %i; confirm", c->self);
	ଫେରନ୍ତୁ c;
}

/* Return CONNECTING socket to remote host:port or local socket path */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
rdynamic_connect_finish(ସଂରଚନା ssh *ssh, Channel *c)
{
	ସଂରଚନା ssh_channels *sc = ssh->chanctxt;
	ସଂରଚନା permission_set *pset = &sc->local_perms;
	ସଂରଚନା permission *perm;
	ସଂରଚନା channel_connect cctx;
	u_int i, permit_adm = 1;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock;

	ଯଦି (pset->ଅଙ୍କ_permitted_admin > 0) {
		permit_adm = 0;
		ପାଇଁ (i = 0; i < pset->ଅଙ୍କ_permitted_admin; i++) {
			perm = &pset->permitted_admin[i];
			ଯଦି (open_match(perm, c->path, c->host_port)) {
				permit_adm = 1;
				ଭାଙ୍ଗ;
			}
		}
	}
	ଯଦି (!permit_adm) {
		debug_f("requested forward not permitted");
		ଫେରନ୍ତୁ -1;
	}

	memset(&cctx, 0, ଆକାର(cctx));
	sock = connect_to_helper(ssh, c->path, c->host_port, SOCK_STREAM, ଖାଲି,
	    ଖାଲି, &cctx, ଖାଲି, ଖାଲି);
	ଯଦି (sock == -1)
		free_connect_ctx(&cctx);
	ଅନ୍ୟଥା {
		/* similar to SSH_CHANNEL_CONNECTING but we've already sent the open */
		c->type = SSH_CHANNEL_RDYNAMIC_FINISH;
		c->connect_ctx = xmalloc(ଆକାର(cctx));
		memcpy(c->connect_ctx, &cctx, ଆକାର(cctx));
		channel_register_fds(ssh, c, sock, sock, -1, 0, 1, 0);
	}
	ଫେରନ୍ତୁ sock;
}

/* -- X11 forwarding */

/*
 * Creates an internet domain socket for listening for X11 connections.
 * Returns 0 and a suitable display number for the DISPLAY variable
 * stored in display_numberp , or -1 if an error occurs.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
x11_create_display_inet(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା x11_display_offset,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା x11_use_localhost, ପୂର୍ଣ୍ଣସଂଖ୍ୟା single_connection,
    u_int *display_numberp, ପୂର୍ଣ୍ଣସଂଖ୍ୟା **chanids)
{
	Channel *nc = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା display_ସଂଖ୍ୟା, sock, port;
	ସଂରଚନା addrinfo hints, *ai, *aitop;
	ଅକ୍ଷର strport[NI_MAXSERV];
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା gaierr, n, ଅଙ୍କ_socks = 0, socks[ଅଙ୍କ_SOCKS];

	ଯଦି (chanids == ଖାଲି || x11_display_offset < 0 ||
	    x11_display_offset > UINT16_MAX - X11_BASE_PORT - MAX_DISPLAYS)
		ଫେରନ୍ତୁ -1;

	ପାଇଁ (display_ସଂଖ୍ୟା = x11_display_offset;
	    display_ସଂଖ୍ୟା < x11_display_offset + MAX_DISPLAYS;
	    display_ସଂଖ୍ୟା++) {
		port = X11_BASE_PORT + display_ସଂଖ୍ୟା;
		memset(&hints, 0, ଆକାର(hints));
		hints.ai_family = ssh->chanctxt->IPv4or6;
		hints.ai_flags = x11_use_localhost ? 0: AI_PASSIVE;
		hints.ai_socktype = SOCK_STREAM;
		snprintf(strport, ଆକାର strport, "%d", port);
		ଯଦି ((gaierr = getaddrinfo(ଖାଲି, strport,
		    &hints, &aitop)) != 0) {
			error("getaddrinfo: %.100s", ssh_gai_strerror(gaierr));
			ଫେରନ୍ତୁ -1;
		}
		ପାଇଁ (ai = aitop; ai; ai = ai->ai_next) {
			ଯଦି (ai->ai_family != AF_INET &&
			    ai->ai_family != AF_INET6)
				ଜାରି;
			sock = socket(ai->ai_family, ai->ai_socktype,
			    ai->ai_protocol);
			ଯଦି (sock == -1) {
				ଯଦି ((errno != EINVAL) && (errno != EAFNOSUPPORT)
#ifdef EPFNOSUPPORT
				    && (errno != EPFNOSUPPORT)
#endif 
				    ) {
					error("socket: %.100s", strerror(errno));
					freeaddrinfo(aitop);
					ଫେରନ୍ତୁ -1;
				} ଅନ୍ୟଥା {
					debug("x11_create_display_inet: Socket family %d not supported",
						 ai->ai_family);
					ଜାରି;
				}
			}
			ଯଦି (ai->ai_family == AF_INET6)
				sock_set_v6only(sock);
			ଯଦି (x11_use_localhost)
				set_reuseaddr(sock);
			ଯଦି (bind(sock, ai->ai_addr, ai->ai_addrlen) == -1) {
				debug2_f("bind port %d: %.100s", port,
				    strerror(errno));
				close(sock);
				ପାଇଁ (n = 0; n < ଅଙ୍କ_socks; n++)
					close(socks[n]);
				ଅଙ୍କ_socks = 0;
				ଭାଙ୍ଗ;
			}
			socks[ଅଙ୍କ_socks++] = sock;
			ଯଦି (ଅଙ୍କ_socks == ଅଙ୍କ_SOCKS)
				ଭାଙ୍ଗ;
		}
		freeaddrinfo(aitop);
		ଯଦି (ଅଙ୍କ_socks > 0)
			ଭାଙ୍ଗ;
	}
	ଯଦି (display_ସଂଖ୍ୟା >= x11_display_offset + MAX_DISPLAYS) {
		error("Failed to allocate internet-domain X11 display socket.");
		ଫେରନ୍ତୁ -1;
	}
	/* Start listening for connections on the socket. */
	ପାଇଁ (n = 0; n < ଅଙ୍କ_socks; n++) {
		sock = socks[n];
		ଯଦି (listen(sock, SSH_LISTEN_BACKLOG) == -1) {
			error("listen: %.100s", strerror(errno));
			close(sock);
			ଫେରନ୍ତୁ -1;
		}
	}

	/* Allocate a channel for each socket. */
	*chanids = xcalloc(ଅଙ୍କ_socks + 1, ଆକାର(**chanids));
	ପାଇଁ (n = 0; n < ଅଙ୍କ_socks; n++) {
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
	*display_numberp = display_ସଂଖ୍ୟା;
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
connect_local_xsocket_path(ଅଚଳ ଅକ୍ଷର *pathname)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock;
	ସଂରଚନା sockaddr_un addr;

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	ଯଦି (sock == -1) {
		error("socket: %.100s", strerror(errno));
		ଫେରନ୍ତୁ -1;
	}
	memset(&addr, 0, ଆକାର(addr));
	addr.sun_family = AF_UNIX;
	strlcpy(addr.sun_path, pathname, ଆକାର addr.sun_path);
	ଯଦି (connect(sock, (ସଂରଚନା sockaddr *)&addr, ଆକାର(addr)) == 0)
		ଫେରନ୍ତୁ sock;
	close(sock);
	error("connect %.100s: %.100s", addr.sun_path, strerror(errno));
	ଫେରନ୍ତୁ -1;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
connect_local_xsocket(u_int dnr)
{
	ଅକ୍ଷର buf[1024];
	snprintf(buf, ଆକାର buf, _PATH_UNIX_X, dnr);
	ଫେରନ୍ତୁ connect_local_xsocket_path(buf);
}

#ifdef __APPLE__
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
is_path_to_xsocket(ଅଚଳ ଅକ୍ଷର *display, ଅକ୍ଷର *path, size_t pathlen)
{
	ସଂରଚନା stat sbuf;

	ଯଦି (strlcpy(path, display, pathlen) >= pathlen) {
		error_f("display path too long");
		ଫେରନ୍ତୁ 0;
	}
	ଯଦି (display[0] != '/')
		ଫେରନ୍ତୁ 0;
	ଯଦି (stat(path, &sbuf) == 0) {
		ଫେରନ୍ତୁ 1;
	} ଅନ୍ୟଥା {
		ଅକ୍ଷର *dot = strrchr(path, '.');
		ଯଦି (dot != ଖାଲି) {
			*dot = '\0';
			ଯଦି (stat(path, &sbuf) == 0) {
				ଫେରନ୍ତୁ 1;
			}
		}
	}
	ଫେରନ୍ତୁ 0;
}
#endif

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
x11_connect_display(ସଂରଚନା ssh *ssh)
{
	u_int display_ସଂଖ୍ୟା;
	ଅଚଳ ଅକ୍ଷର *display;
	ଅକ୍ଷର buf[1024], *cp;
	ସଂରଚନା addrinfo hints, *ai, *aitop;
	ଅକ୍ଷର strport[NI_MAXSERV];
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା gaierr, sock = 0;

	/* Try to open a socket for the local X server. */
	display = getenv("DISPLAY");
	ଯଦି (!display) {
		error("DISPLAY not set.");
		ଫେରନ୍ତୁ -1;
	}
	/*
	 * Now we decode the value of the DISPLAY variable and make a
	 * connection to the real X server.
	 */

#ifdef __APPLE__
	/* Check if display is a path to a socket (as set by launchd). */
	{
		ଅକ୍ଷର path[PATH_MAX];

		ଯଦି (is_path_to_xsocket(display, path, ଆକାର(path))) {
			debug("x11_connect_display: $DISPLAY is launchd");

			/* Create a socket. */
			sock = connect_local_xsocket_path(path);
			ଯଦି (sock < 0)
				ଫେରନ୍ତୁ -1;

			/* OK, we now have a connection to the display. */
			ଫେରନ୍ତୁ sock;
		}
	}
#endif
	/*
	 * Check if it is a unix domain socket.  Unix domain displays are in
	 * one of the following formats: unix:d[.s], :d[.s], ::d[.s]
	 */
	ଯଦି (strncmp(display, "unix:", 5) == 0 ||
	    display[0] == ':') {
		/* Connect to the unix domain socket. */
		ଯଦି (sscanf(strrchr(display, ':') + 1, "%u",
		    &display_ସଂଖ୍ୟା) != 1) {
			error("Could not parse display number from DISPLAY: "
			    "%.100s", display);
			ଫେରନ୍ତୁ -1;
		}
		/* Create a socket. */
		sock = connect_local_xsocket(display_ସଂଖ୍ୟା);
		ଯଦି (sock < 0)
			ଫେରନ୍ତୁ -1;

		/* OK, we now have a connection to the display. */
		ଫେରନ୍ତୁ sock;
	}
	/*
	 * Connect to an inet socket.  The DISPLAY value is supposedly
	 * hostname:d[.s], where hostname may also be numeric IP address.
	 */
	strlcpy(buf, display, ଆକାର(buf));
	cp = strchr(buf, ':');
	ଯଦି (!cp) {
		error("Could not find ':' in DISPLAY: %.100s", display);
		ଫେରନ୍ତୁ -1;
	}
	*cp = 0;
	/*
	 * buf now contains the host name.  But first we parse the
	 * display number.
	 */
	ଯଦି (sscanf(cp + 1, "%u", &display_ସଂଖ୍ୟା) != 1 ||
	    display_ସଂଖ୍ୟା > UINT16_MAX - X11_BASE_PORT) {
		error("Could not parse display number from DISPLAY: %.100s",
		    display);
		ଫେରନ୍ତୁ -1;
	}

	/* Look up the host address */
	memset(&hints, 0, ଆକାର(hints));
	hints.ai_family = ssh->chanctxt->IPv4or6;
	hints.ai_socktype = SOCK_STREAM;
	snprintf(strport, ଆକାର strport, "%u", X11_BASE_PORT + display_ସଂଖ୍ୟା);
	ଯଦି ((gaierr = getaddrinfo(buf, strport, &hints, &aitop)) != 0) {
		error("%.100s: unknown host. (%s)", buf,
		ssh_gai_strerror(gaierr));
		ଫେରନ୍ତୁ -1;
	}
	ପାଇଁ (ai = aitop; ai; ai = ai->ai_next) {
		/* Create a socket. */
		sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		ଯଦି (sock == -1) {
			debug2("socket: %.100s", strerror(errno));
			ଜାରି;
		}
		/* Connect it to the display. */
		ଯଦି (connect(sock, ai->ai_addr, ai->ai_addrlen) == -1) {
			debug2("connect %.100s port %u: %.100s", buf,
			    X11_BASE_PORT + display_ସଂଖ୍ୟା, strerror(errno));
			close(sock);
			ଜାରି;
		}
		/* Success */
		ଭାଙ୍ଗ;
	}
	freeaddrinfo(aitop);
	ଯଦି (!ai) {
		error("connect %.100s port %u: %.100s", buf,
		    X11_BASE_PORT + display_ସଂଖ୍ୟା, strerror(errno));
		ଫେରନ୍ତୁ -1;
	}
	set_nodelay(sock);
	ଫେରନ୍ତୁ sock;
}

/*
 * Requests forwarding of X11 connections, generates fake authentication
 * data, and enables authentication spoofing.
 * This should be called in the client only.
 */
ଶୂନ୍ୟ
x11_request_forwarding_with_spoofing(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା client_session_id,
    ଅଚଳ ଅକ୍ଷର *disp, ଅଚଳ ଅକ୍ଷର *proto, ଅଚଳ ଅକ୍ଷର *data, ପୂର୍ଣ୍ଣସଂଖ୍ୟା want_reply)
{
	ସଂରଚନା ssh_channels *sc = ssh->chanctxt;
	u_int data_len = (u_int) strlen(data) / 2;
	u_int i, ମୂଲ୍ୟ;
	ଅଚଳ ଅକ୍ଷର *cp;
	ଅକ୍ଷର *new_data;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, screen_ସଂଖ୍ୟା;

	ଯଦି (sc->x11_saved_display == ଖାଲି)
		sc->x11_saved_display = xstrdup(disp);
	ଅନ୍ୟଥା ଯଦି (strcmp(disp, sc->x11_saved_display) != 0) {
		error("x11_request_forwarding_with_spoofing: different "
		    "$DISPLAY already forwarded");
		ଫେରନ୍ତୁ;
	}

	cp = strchr(disp, ':');
	ଯଦି (cp)
		cp = strchr(cp, '.');
	ଯଦି (cp)
		screen_ସଂଖ୍ୟା = (u_int)strtonum(cp + 1, 0, 400, ଖାଲି);
	ଅନ୍ୟଥା
		screen_ସଂଖ୍ୟା = 0;

	ଯଦି (sc->x11_saved_proto == ଖାଲି) {
		/* Save protocol name. */
		sc->x11_saved_proto = xstrdup(proto);

		/* Extract real authentication data. */
		sc->x11_saved_data = xmalloc(data_len);
		ପାଇଁ (i = 0; i < data_len; i++) {
			ଯଦି (sscanf(data + 2 * i, "%2x", &ମୂଲ୍ୟ) != 1) {
				fatal("x11_request_forwarding: bad "
				    "authentication data: %.100s", data);
			}
			sc->x11_saved_data[i] = ମୂଲ୍ୟ;
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
	ଯଦି ((r = sshpkt_put_u8(ssh, 0)) != 0 || /* bool: single connection */
	    (r = sshpkt_put_cstring(ssh, proto)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, new_data)) != 0 ||
	    (r = sshpkt_put_u32(ssh, screen_ସଂଖ୍ୟା)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send x11-req");
	ମୁକ୍ତ(new_data);
}

/*
 * Returns whether an x11 channel was used recently (less than a second ago)
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
x11_channel_used_recently(ସଂରଚନା ssh *ssh) {
	u_int i;
	Channel *c;
	ଦ୍ୱିଗୁଣ lastused = 0;

	ପାଇଁ (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		ଯଦି (c == ଖାଲି || c->ctype == ଖାଲି || c->lastused == 0.0 ||
		    strcmp(c->ctype, "x11-connection") != 0)
			ଜାରି;
		ଯଦି (c->lastused > lastused)
			lastused = c->lastused;
	}
	ଫେରନ୍ତୁ lastused != 0.0 && monotime_double() <= lastused + 1.0;
}
