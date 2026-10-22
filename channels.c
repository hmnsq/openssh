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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/stat.h>
#అన్తర్భావ <sys/ioctl.h>
#అన్తర్భావ <sys/un.h>
#అన్తర్భావ <sys/socket.h>
#అన్తర్భావ <sys/queue.h>

#అన్తర్భావ <netinet/in.h>
#అన్తర్భావ <arpa/inet.h>

#అన్తర్భావ <errno.h>
#అన్తర్భావ <fcntl.h>
#అన్తర్భావ <limits.h>
#అన్తర్భావ <netdb.h>
#అన్తర్భావ <poll.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <stdint.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <termios.h>
#అన్తర్భావ <unistd.h>

#అన్తర్భావ "xmalloc.h"
#అన్తర్భావ "ssh.h"
#అన్తర్భావ "ssh2.h"
#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "packet.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "channels.h"
#అన్తర్భావ "compat.h"
#అన్తర్భావ "canohost.h"
#అన్తర్భావ "pathnames.h"
#అన్తర్భావ "match.h"

/* XXX remove once we're satisfied there's no lurking bugs */
/* #define DEBUG_CHANNEL_POLL 1 */

/* -- agent forwarding */
#నిర్వచించు	అంకె_SOCKS	10

/* -- X11 forwarding */
/* X11 port for display :0 */
#నిర్వచించు X11_పునాది_పోర్టు	6000
/* Maximum number of fake X11 displays to try. */
#నిర్వచించు MAX_DISPLAYS  1000

/* Per-channel callback for pre/post IO actions */
రకనిర్వచనం శూన్య chan_fn(నిర్మాణం ssh *, Channel *c);

/*
 * Data structure for storing which hosts are permitted for forward requests.
 * The local sides of any remote forwards are stored in this array to prevent
 * a corrupt remote server from accessing arbitrary TCP/IP ports on our local
 * network (which might be behind a firewall).
 */
/* XXX: streamlocal wants a path instead of host:port */
/*      Overload host_to_connect; we could just make this match Forward */
/*	XXX - can we use listen_host instead of listen_path? */
నిర్మాణం permission {
	అక్షరం *host_గమ్యం_connect;		/* Connect to 'host'. */
	పూర్ణాంకం పోర్టు_గమ్యం_connect;		/* Connect to 'port'. */
	అక్షరం *listen_host;		/* Remote side should listen address. */
	అక్షరం *listen_మార్గం;		/* Remote side should listen path. */
	పూర్ణాంకం listen_పోర్టు;		/* Remote side should listen port. */
	Channel *downstream;		/* Downstream mux*/
};

/* Context for non-blocking connects */
నిర్మాణం channel_connect {
	అక్షరం *host;
	పూర్ణాంకం పోర్టు;
	నిర్మాణం addrinfo *ai, *aitop;
};

/*
 * Stores the forwarding permission state for a single direction (local or
 * remote).
 */
నిర్మాణం permission_సమితి {
	/*
	 * List of all local permitted host/port pairs to allow for the
	 * user.
	 */
	u_int అంకె_permitted_user;
	నిర్మాణం permission *permitted_user;

	/*
	 * List of all permitted host/port pairs to allow for the admin.
	 */
	u_int అంకె_permitted_admin;
	నిర్మాణం permission *permitted_admin;

	/*
	 * If this is true, all opens/listens are permitted.  This is the
	 * case on the server on which we have to trust the client anyway,
	 * and the user could do anything after logging in.
	 */
	పూర్ణాంకం all_permitted;
};

/* Used to record timeouts per channel type */
నిర్మాణం ssh_channel_timeout {
	అక్షరం *type_నమూనా;
	ద్విగుణ timeout_secs;
};

/* Master structure for channels state */
నిర్మాణం ssh_channels {
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
	నిర్మాణం permission_సమితి local_perms;
	నిర్మాణం permission_సమితి remote_perms;

	/* -- X11 forwarding */

	/* Saved X11 local (client) display. */
	అక్షరం *x11_saved_display;

	/* Saved X11 authentication protocol name. */
	అక్షరం *x11_saved_proto;

	/* Saved X11 authentication data.  This is the real data. */
	అక్షరం *x11_saved_దత్తాంశం;
	u_int x11_saved_దత్తాంశం_len;

	/* Deadline after which all X11 connections are refused */
	ద్విగుణ x11_refuse_సమయం;

	/*
	 * Fake X11 authentication data.  This is what the server will be
	 * sending us; we should replace any occurrences of this by the
	 * real data.
	 */
	u_char *x11_fake_దత్తాంశం;
	u_int x11_fake_దత్తాంశం_len;

	/* AF_UNSPEC or AF_INET or AF_INET6 */
	పూర్ణాంకం IPv4or6;

	/* Set SO_KEEPALIVE on TCP connections */
	పూర్ణాంకం want_tcp_keepalive;

	/* Channel timeouts by type */
	నిర్మాణం ssh_channel_timeout *timeouts;
	కొలత_t ntimeouts;
	/* Global timeout for all OPEN channels */
	ద్విగుణ global_deadline;
	ద్విగుణ lastused;
	/* pattern-lists used to classify channels as bulk */
	అక్షరం *bulk_classifier_tty, *bulk_classifier_notty;
	/* Number of active bulk channels (set by channel_handler) */
	u_int nbulk;
};

/* helper */
స్థిర శూన్య పోర్టు_open_helper(నిర్మాణం ssh *ssh, Channel *c, అక్షరం *rtype);
స్థిర స్థిరరాశి అక్షరం *channel_rfwd_bind_host(స్థిరరాశి అక్షరం *listen_host);

/* non-blocking connect helpers */
స్థిర పూర్ణాంకం connect_తదుపరి(నిర్మాణం ssh *, నిర్మాణం channel_connect *);
స్థిర Channel *rdynamic_connect_prepare(నిర్మాణం ssh *, అక్షరం *, అక్షరం *);
స్థిర పూర్ణాంకం rdynamic_connect_ముగింపు(నిర్మాణం ssh *, Channel *);

/* Setup helper */
స్థిర శూన్య channel_handler_init(నిర్మాణం ssh_channels *sc);

/* -- channel core */

శూన్య
channel_init_channels(నిర్మాణం ssh *ssh)
{
	నిర్మాణం ssh_channels *sc;

	ఒకవేళ ((sc = సున్నా_జ్ఞాపకం_ఇవ్వు(1, పరిమాణం(*sc))) == ఖాళీ)
		fatal_f("allocation failed");
	sc->channels_alloc = 10;
	sc->channels = xcalloc(sc->channels_alloc, పరిమాణం(*sc->channels));
	sc->IPv4or6 = AF_UNSPEC;
	sc->bulk_classifier_tty = xstrdup(CHANNEL_BULK_TTY);
	sc->bulk_classifier_notty = xstrdup(CHANNEL_BULK_NOTTY);
	channel_handler_init(sc);

	ssh->chanctxt = sc;
}

Channel *
channel_by_id(నిర్మాణం ssh *ssh, పూర్ణాంకం id)
{
	Channel *c;

	ఒకవేళ (id < 0 || (u_int)id >= ssh->chanctxt->channels_alloc) {
		logit_f("%d: bad id", id);
		తిరిగి ఖాళీ;
	}
	c = ssh->chanctxt->channels[id];
	ఒకవేళ (c == ఖాళీ) {
		logit_f("%d: bad id: channel free", id);
		తిరిగి ఖాళీ;
	}
	తిరిగి c;
}

Channel *
channel_by_remote_id(నిర్మాణం ssh *ssh, u_int remote_id)
{
	Channel *c;
	u_int i;

	కొరకు (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		ఒకవేళ (c != ఖాళీ && c->have_remote_id && c->remote_id == remote_id)
			తిరిగి c;
	}
	తిరిగి ఖాళీ;
}

/*
 * Returns the channel if it is allowed to receive protocol messages.
 * Private channels, like listening sockets, may not receive messages.
 */
Channel *
channel_lookup(నిర్మాణం ssh *ssh, పూర్ణాంకం id)
{
	Channel *c;

	ఒకవేళ ((c = channel_by_id(ssh, id)) == ఖాళీ)
		తిరిగి ఖాళీ;

	ఎంపిక (c->type) {
	స్థితి SSH_CHANNEL_X11_OPEN:
	స్థితి SSH_CHANNEL_LARVAL:
	స్థితి SSH_CHANNEL_CONNECTING:
	స్థితి SSH_CHANNEL_DYNAMIC:
	స్థితి SSH_CHANNEL_RDYNAMIC_OPEN:
	స్థితి SSH_CHANNEL_RDYNAMIC_ముగింపు:
	స్థితి SSH_CHANNEL_OPENING:
	స్థితి SSH_CHANNEL_OPEN:
	స్థితి SSH_CHANNEL_ABANDONED:
	స్థితి SSH_CHANNEL_MUX_PROXY:
		తిరిగి c;
	}
	logit("Non-public channel %d, type %d.", id, c->type);
	తిరిగి ఖాళీ;
}

స్థిర శూన్య
free_connect_ctx(నిర్మాణం channel_connect *cctx)
{
	విడుదల(cctx->host);
	ఒకవేళ (cctx->aitop) {
		ఒకవేళ (cctx->aitop->ai_family == AF_UNIX)
			విడుదల(cctx->aitop);
		లేకపోతే
			freeaddrinfo(cctx->aitop);
	}
	memset(cctx, 0, పరిమాణం(*cctx));
}

స్థిర శూన్య
channel_free_connect_ctx(Channel *c)
{
	ఒకవేళ (c == ఖాళీ || c->connect_ctx == ఖాళీ)
		తిరిగి;
	free_connect_ctx(c->connect_ctx);
	విడుదల(c->connect_ctx);
	c->connect_ctx = ఖాళీ;
}

/* Enable/disable TCP keepalives for X11 and port-forwarding sockets */
శూన్య
channel_సమితి_tcp_keepalives(నిర్మాణం ssh *ssh, పూర్ణాంకం on)
{
	ssh->chanctxt->want_tcp_keepalive = on;
}

/*
 * Add a timeout for open channels whose c->ctype (or c->xctype if it is set)
 * match type_pattern.
 */
శూన్య
channel_కూడు_timeout(నిర్మాణం ssh *ssh, స్థిరరాశి అక్షరం *type_నమూనా,
    ద్విగుణ timeout_secs)
{
	నిర్మాణం ssh_channels *sc = ssh->chanctxt;

	ఒకవేళ (strcmp(type_నమూనా, "global") == 0) {
		debug2_f("global channel timeout %f seconds", timeout_secs);
		sc->global_deadline = timeout_secs;
		తిరిగి;
	}
	debug2_f("channel type \"%s\" timeout %f seconds",
	    type_నమూనా, timeout_secs);
	sc->timeouts = xrecallocarray(sc->timeouts, sc->ntimeouts,
	    sc->ntimeouts + 1, పరిమాణం(*sc->timeouts));
	sc->timeouts[sc->ntimeouts].type_నమూనా = xstrdup(type_నమూనా);
	sc->timeouts[sc->ntimeouts].timeout_secs = timeout_secs;
	sc->ntimeouts++;
}

/* Clears all previously-added channel timeouts */
శూన్య
channel_clear_timeouts(నిర్మాణం ssh *ssh)
{
	నిర్మాణం ssh_channels *sc = ssh->chanctxt;
	కొలత_t i;

	debug3_f("clearing");
	కొరకు (i = 0; i < sc->ntimeouts; i++)
		విడుదల(sc->timeouts[i].type_నమూనా);
	విడుదల(sc->timeouts);
	sc->timeouts = ఖాళీ;
	sc->ntimeouts = 0;
}

స్థిర ద్విగుణ
lookup_timeout(నిర్మాణం ssh *ssh, స్థిరరాశి అక్షరం *type)
{
	నిర్మాణం ssh_channels *sc = ssh->chanctxt;
	కొలత_t i;

	కొరకు (i = 0; i < sc->ntimeouts; i++) {
		ఒకవేళ (సరిపోలిక_నమూనా(type, sc->timeouts[i].type_నమూనా))
			తిరిగి sc->timeouts[i].timeout_secs;
	}

	తిరిగి 0;
}

స్థిర శూన్య
channel_classify(నిర్మాణం ssh *ssh, Channel *c)
{
	నిర్మాణం ssh_channels *sc = ssh->chanctxt;
	స్థిరరాశి అక్షరం *type = c->xctype == ఖాళీ ? c->ctype : c->xctype;
	స్థిరరాశి పూర్ణాంకం has_tty = c->isatty || c->remote_has_tty;
	స్థిరరాశి అక్షరం *classifier = has_tty ?
	    sc->bulk_classifier_tty : sc->bulk_classifier_notty;

	c->bulk = type != ఖాళీ && సరిపోలిక_నమూనా_list(type, classifier, 0) == 1;
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
శూన్య
channel_సమితి_xtype(నిర్మాణం ssh *ssh, పూర్ణాంకం id, స్థిరరాశి అక్షరం *xctype)
{
	నిర్మాణం ssh_channels *sc = ssh->chanctxt;
	Channel *c;

	ఒకవేళ ((c = channel_by_id(ssh, id)) == ఖాళీ)
		fatal_f("missing channel %d", id);
	ఒకవేళ (c->xctype != ఖాళీ)
		విడుదల(c->xctype);
	c->xctype = xstrdup(xctype);
	/* Only override deadline if xctype has a more specific match. */
	ద్విగుణ xtype_deadline = lookup_timeout(ssh, c->xctype);
	ఒకవేళ (xtype_deadline != 0)
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
స్థిర శూన్య
channel_సమితి_వాడిన_సమయం(నిర్మాణం ssh *ssh, Channel *c)
{
	ssh->chanctxt->lastused = monotime_double();
	ఒకవేళ (c != ఖాళీ)
		c->lastused = ssh->chanctxt->lastused;
}

/*
 * Get the time at which a channel is due to time out for inactivity.
 * Returns 0 if the channel is not due to time out ever.
 */
స్థిర ద్విగుణ
channel_get_expiry(నిర్మాణం ssh *ssh, Channel *c)
{
	నిర్మాణం ssh_channels *sc = ssh->chanctxt;
	ద్విగుణ expiry = 0, channel_expiry;

	ఒకవేళ (sc->lastused != 0 && sc->global_deadline != 0)
		expiry = sc->lastused + sc->global_deadline;
	ఒకవేళ (c->lastused != 0 && c->inactive_deadline != 0) {
		channel_expiry = c->lastused + c->inactive_deadline;
		ఒకవేళ (expiry == 0 || channel_expiry < expiry)
			expiry = channel_expiry;
	}
	తిరిగి expiry;
}

/* Returns non-zero if there is an open, non-interactive channel */
పూర్ణాంకం
channel_has_bulk(నిర్మాణం ssh *ssh)
{
	తిరిగి ssh->chanctxt != ఖాళీ && ssh->chanctxt->nbulk != 0;
}

/*
 * Register filedescriptors for a channel, used when allocating a channel or
 * when the channel consumer/producer is ready, e.g. shell exec'd
 */
స్థిర శూన్య
channel_రిజిస్టరు_fds(నిర్మాణం ssh *ssh, Channel *c, పూర్ణాంకం rfd, పూర్ణాంకం wfd, పూర్ణాంకం efd,
    పూర్ణాంకం extusage, పూర్ణాంకం nonblock, పూర్ణాంకం is_tty)
{
	పూర్ణాంకం val;

	ఒకవేళ (rfd != -1)
		(శూన్య)fcntl(rfd, F_SETFD, FD_CLOEXEC);
	ఒకవేళ (wfd != -1 && wfd != rfd)
		(శూన్య)fcntl(wfd, F_SETFD, FD_CLOEXEC);
	ఒకవేళ (efd != -1 && efd != rfd && efd != wfd)
		(శూన్య)fcntl(efd, F_SETFD, FD_CLOEXEC);

	c->rfd = rfd;
	c->wfd = wfd;
	c->sock = (rfd == wfd) ? rfd : -1;
	c->efd = efd;
	c->extended_usage = extusage;

	ఒకవేళ ((c->isatty = is_tty) != 0)
		debug2("channel %d: rfd %d isatty", c->self, c->rfd);
#నిర్వచితమైతే _AIX
	/* XXX: Later AIX versions can't push as much data to tty */
	c->wfd_isatty = is_tty || isatty(c->wfd);
#అయితే_ముగింపు

	/* enable nonblocking mode */
	c->restore_ఖండం = 0;
	ఒకవేళ (nonblock == CHANNEL_NONBLOCK_STDIO) {
		/*
		 * Special handling for stdio file descriptors: do not set
		 * non-blocking mode if they are TTYs. Otherwise prepare to
		 * restore their blocking state on exit to avoid interfering
		 * with other programs that follow.
		 */
		ఒకవేళ (rfd != -1 && !isatty(rfd) &&
		    (val = fcntl(rfd, F_GETFL)) != -1 && !(val & O_NONBLOCK)) {
			c->restore_flags[0] = val;
			c->restore_ఖండం |= CHANNEL_RESTORE_RFD;
			సమితి_nonblock(rfd);
		}
		ఒకవేళ (wfd != -1 && !isatty(wfd) &&
		    (val = fcntl(wfd, F_GETFL)) != -1 && !(val & O_NONBLOCK)) {
			c->restore_flags[1] = val;
			c->restore_ఖండం |= CHANNEL_RESTORE_WFD;
			సమితి_nonblock(wfd);
		}
		ఒకవేళ (efd != -1 && !isatty(efd) &&
		    (val = fcntl(efd, F_GETFL)) != -1 && !(val & O_NONBLOCK)) {
			c->restore_flags[2] = val;
			c->restore_ఖండం |= CHANNEL_RESTORE_EFD;
			సమితి_nonblock(efd);
		}
	} లేకపోతే ఒకవేళ (nonblock) {
		ఒకవేళ (rfd != -1)
			సమితి_nonblock(rfd);
		ఒకవేళ (wfd != -1)
			సమితి_nonblock(wfd);
		ఒకవేళ (efd != -1)
			సమితి_nonblock(efd);
	}
	/* channel might be entering a larval state, so reset global timeout */
	channel_సమితి_వాడిన_సమయం(ssh, ఖాళీ);
	channel_classify(ssh, c);
}

/*
 * Allocate a new channel object and set its type and socket.
 */
Channel *
channel_new(నిర్మాణం ssh *ssh, అక్షరం *ctype, పూర్ణాంకం type, పూర్ణాంకం rfd, పూర్ణాంకం wfd, పూర్ణాంకం efd,
    u_int కిటికీ, u_int maxpack, పూర్ణాంకం extusage, స్థిరరాశి అక్షరం *remote_name,
    పూర్ణాంకం nonblock)
{
	నిర్మాణం ssh_channels *sc = ssh->chanctxt;
	u_int i, దొరికింది = 0;
	Channel *c;
	పూర్ణాంకం r;

	/* Try to find a free slot where to put the new channel. */
	కొరకు (i = 0; i < sc->channels_alloc; i++) {
		ఒకవేళ (sc->channels[i] == ఖాళీ) {
			/* Found a free slot. */
			దొరికింది = i;
			ఆపు;
		}
	}
	ఒకవేళ (i >= sc->channels_alloc) {
		/*
		 * There are no free slots. Take last+1 slot and expand
		 * the array.
		 */
		దొరికింది = sc->channels_alloc;
		ఒకవేళ (sc->channels_alloc > CHANNELS_MAX_CHANNELS)
			fatal_f("internal error: channels_alloc %d too big",
			    sc->channels_alloc);
		sc->channels = xrecallocarray(sc->channels, sc->channels_alloc,
		    sc->channels_alloc + 10, పరిమాణం(*sc->channels));
		sc->channels_alloc += 10;
		debug2("channel: expanding %d", sc->channels_alloc);
	}
	/* Initialize and return new channel. */
	c = sc->channels[దొరికింది] = xcalloc(1, పరిమాణం(Channel));
	ఒకవేళ ((c->ఆదానం = sshbuf_new()) == ఖాళీ ||
	    (c->output = sshbuf_new()) == ఖాళీ ||
	    (c->extended = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	ఒకవేళ ((r = sshbuf_సమితి_max_కొలత(c->ఆదానం, CHAN_ఆదానం_MAX)) != 0)
		fatal_fr(r, "sshbuf_set_max_size");
	c->ostate = CHAN_OUTPUT_OPEN;
	c->istate = CHAN_ఆదానం_OPEN;
	channel_రిజిస్టరు_fds(ssh, c, rfd, wfd, efd, extusage, nonblock, 0);
	c->self = దొరికింది;
	c->type = type;
	c->ctype = ctype;
	c->local_కిటికీ = కిటికీ;
	c->local_కిటికీ_max = కిటికీ;
	c->local_maxpacket = maxpack;
	c->remote_name = xstrdup(remote_name);
	c->ctl_chan = -1;
	c->delayed = 1;		/* prevent call to channel_post handler */
	c->inactive_deadline = lookup_timeout(ssh, c->ctype);
	TAILQ_INIT(&c->స్థితి_confirms);
	channel_classify(ssh, c);
	debug("channel %d: new %s [%s] (inactive timeout: %f)",
	    దొరికింది, c->ctype, remote_name, c->inactive_deadline != 0.0 ?
	    c->inactive_deadline : sc->global_deadline);
	తిరిగి c;
}

శూన్య
channel_సమితి_tty(నిర్మాణం ssh *ssh, Channel *c)
{
	c->remote_has_tty = 1;
	channel_classify(ssh, c);
}

పూర్ణాంకం
channel_close_fd(నిర్మాణం ssh *ssh, Channel *c, పూర్ణాంకం *fdp)
{
	పూర్ణాంకం ret, fd = *fdp;

	ఒకవేళ (fd == -1)
		తిరిగి 0;

	/* restore blocking */
	ఒకవేళ (*fdp == c->rfd &&
	    (c->restore_ఖండం & CHANNEL_RESTORE_RFD) != 0)
		(శూన్య)fcntl(*fdp, F_SETFL, c->restore_flags[0]);
	లేకపోతే ఒకవేళ (*fdp == c->wfd &&
	    (c->restore_ఖండం & CHANNEL_RESTORE_WFD) != 0)
		(శూన్య)fcntl(*fdp, F_SETFL, c->restore_flags[1]);
	లేకపోతే ఒకవేళ (*fdp == c->efd &&
	    (c->restore_ఖండం & CHANNEL_RESTORE_EFD) != 0)
		(శూన్య)fcntl(*fdp, F_SETFL, c->restore_flags[2]);

	ఒకవేళ (*fdp == c->rfd) {
		c->io_want &= ~SSH_CHAN_IO_RFD;
		c->io_ready &= ~SSH_CHAN_IO_RFD;
		c->rfd = -1;
		c->pfds[0] = -1;
	}
	ఒకవేళ (*fdp == c->wfd) {
		c->io_want &= ~SSH_CHAN_IO_WFD;
		c->io_ready &= ~SSH_CHAN_IO_WFD;
		c->wfd = -1;
		c->pfds[1] = -1;
	}
	ఒకవేళ (*fdp == c->efd) {
		c->io_want &= ~SSH_CHAN_IO_EFD;
		c->io_ready &= ~SSH_CHAN_IO_EFD;
		c->efd = -1;
		c->pfds[2] = -1;
	}
	ఒకవేళ (*fdp == c->sock) {
		c->io_want &= ~SSH_CHAN_IO_SOCK;
		c->io_ready &= ~SSH_CHAN_IO_SOCK;
		c->sock = -1;
		c->pfds[3] = -1;
	}

	ret = close(fd);
	*fdp = -1; /* probably redundant */
	తిరిగి ret;
}

/* Close all channel fd/socket. */
స్థిర శూన్య
channel_close_fds(నిర్మాణం ssh *ssh, Channel *c)
{
	పూర్ణాంకం sock = c->sock, rfd = c->rfd, wfd = c->wfd, efd = c->efd;

	channel_close_fd(ssh, c, &c->sock);
	ఒకవేళ (rfd != sock)
		channel_close_fd(ssh, c, &c->rfd);
	ఒకవేళ (wfd != sock && wfd != rfd)
		channel_close_fd(ssh, c, &c->wfd);
	ఒకవేళ (efd != sock && efd != rfd && efd != wfd)
		channel_close_fd(ssh, c, &c->efd);
}

స్థిర శూన్య
fwd_perm_clear(నిర్మాణం permission *perm)
{
	విడుదల(perm->host_గమ్యం_connect);
	విడుదల(perm->listen_host);
	విడుదల(perm->listen_మార్గం);
	memset(perm, 0, పరిమాణం(*perm));
}

/* Returns an printable name for the specified forwarding permission list */
స్థిర స్థిరరాశి అక్షరం *
fwd_ident(పూర్ణాంకం who, పూర్ణాంకం where)
{
	ఒకవేళ (who == FORWARD_ADM) {
		ఒకవేళ (where == FORWARD_LOCAL)
			తిరిగి "admin local";
		లేకపోతే ఒకవేళ (where == FORWARD_REMOTE)
			తిరిగి "admin remote";
	} లేకపోతే ఒకవేళ (who == FORWARD_USER) {
		ఒకవేళ (where == FORWARD_LOCAL)
			తిరిగి "user local";
		లేకపోతే ఒకవేళ (where == FORWARD_REMOTE)
			తిరిగి "user remote";
	}
	fatal("Unknown forward permission list %d/%d", who, where);
}

/* Returns the forwarding permission list for the specified direction */
స్థిర నిర్మాణం permission_సమితి *
permission_సమితి_get(నిర్మాణం ssh *ssh, పూర్ణాంకం where)
{
	నిర్మాణం ssh_channels *sc = ssh->chanctxt;

	ఎంపిక (where) {
	స్థితి FORWARD_LOCAL:
		తిరిగి &sc->local_perms;
		ఆపు;
	స్థితి FORWARD_REMOTE:
		తిరిగి &sc->remote_perms;
		ఆపు;
	అప్రమేయ:
		fatal_f("invalid forwarding direction %d", where);
	}
}

/* Returns pointers to the specified forwarding list and its element count */
స్థిర శూన్య
permission_సమితి_get_array(నిర్మాణం ssh *ssh, పూర్ణాంకం who, పూర్ణాంకం where,
    నిర్మాణం permission ***permpp, u_int **npermpp)
{
	నిర్మాణం permission_సమితి *pset = permission_సమితి_get(ssh, where);

	ఎంపిక (who) {
	స్థితి FORWARD_USER:
		*permpp = &pset->permitted_user;
		*npermpp = &pset->అంకె_permitted_user;
		ఆపు;
	స్థితి FORWARD_ADM:
		*permpp = &pset->permitted_admin;
		*npermpp = &pset->అంకె_permitted_admin;
		ఆపు;
	అప్రమేయ:
		fatal_f("invalid forwarding client %d", who);
	}
}

/* Adds an entry to the specified forwarding list */
స్థిర పూర్ణాంకం
permission_సమితి_కూడు(నిర్మాణం ssh *ssh, పూర్ణాంకం who, పూర్ణాంకం where,
    స్థిరరాశి అక్షరం *host_గమ్యం_connect, పూర్ణాంకం పోర్టు_గమ్యం_connect,
    స్థిరరాశి అక్షరం *listen_host, స్థిరరాశి అక్షరం *listen_మార్గం, పూర్ణాంకం listen_పోర్టు,
    Channel *downstream)
{
	నిర్మాణం permission **permp;
	u_int n, *npermp;

	permission_సమితి_get_array(ssh, who, where, &permp, &npermp);

	ఒకవేళ (*npermp >= గరిష్ఠ_పూర్ణాంకం)
		fatal_f("%s overflow", fwd_ident(who, where));

	*permp = xrecallocarray(*permp, *npermp, *npermp + 1, పరిమాణం(**permp));
	n = (*npermp)++;
#నిర్వచించు MAYBE_DUP(s) ((s == ఖాళీ) ? ఖాళీ : xstrdup(s))
	(*permp)[n].host_గమ్యం_connect = MAYBE_DUP(host_గమ్యం_connect);
	(*permp)[n].పోర్టు_గమ్యం_connect = పోర్టు_గమ్యం_connect;
	(*permp)[n].listen_host = MAYBE_DUP(listen_host);
	(*permp)[n].listen_మార్గం = MAYBE_DUP(listen_మార్గం);
	(*permp)[n].listen_పోర్టు = listen_పోర్టు;
	(*permp)[n].downstream = downstream;
#నిర్వచనం_రద్దు MAYBE_DUP
	తిరిగి (పూర్ణాంకం)n;
}

స్థిర శూన్య
mux_remove_remote_forwardings(నిర్మాణం ssh *ssh, Channel *c)
{
	నిర్మాణం ssh_channels *sc = ssh->chanctxt;
	నిర్మాణం permission_సమితి *pset = &sc->local_perms;
	నిర్మాణం permission *perm;
	పూర్ణాంకం r;
	u_int i;

	కొరకు (i = 0; i < pset->అంకె_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		ఒకవేళ (perm->downstream != c)
			కొనసాగు;

		/* cancel on the server, since mux client is gone */
		debug("channel %d: cleanup remote forward for %s:%u",
		    c->self, perm->listen_host, perm->listen_పోర్టు);
		ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh, SSH2_సందేశం_GLOBAL_REQUEST)) != 0 ||
		    (r = sshpkt_put_cstring(ssh,
		    "cancel-tcpip-forward")) != 0 ||
		    (r = sshpkt_put_u8(ssh, 0)) != 0 ||
		    (r = sshpkt_put_cstring(ssh,
		    channel_rfwd_bind_host(perm->listen_host))) != 0 ||
		    (r = sshpkt_put_u32(ssh, perm->listen_పోర్టు)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0) {
			fatal_fr(r, "channel %i", c->self);
		}
		fwd_perm_clear(perm); /* unregister */
	}
}

/* Free the channel and close its fd/socket. */
శూన్య
channel_free(నిర్మాణం ssh *ssh, Channel *c)
{
	నిర్మాణం ssh_channels *sc = ssh->chanctxt;
	అక్షరం *s;
	u_int i, n;
	Channel *other;
	నిర్మాణం channel_confirm *cc;

	కొరకు (n = 0, i = 0; i < sc->channels_alloc; i++) {
		ఒకవేళ ((other = sc->channels[i]) == ఖాళీ)
			కొనసాగు;
		n++;
		/* detach from mux client and prepare for closing */
		ఒకవేళ (c->type == SSH_CHANNEL_MUX_CLIENT &&
		    other->type == SSH_CHANNEL_MUX_PROXY &&
		    other->mux_ctx == c) {
			other->mux_ctx = ఖాళీ;
			other->type = SSH_CHANNEL_OPEN;
			other->istate = CHAN_ఆదానం_CLOSED;
			other->ostate = CHAN_OUTPUT_CLOSED;
		}
	}
	debug("channel %d: free: %s, nchannels %u", c->self,
	    c->remote_name ? c->remote_name : "???", n);

	ఒకవేళ (c->type == SSH_CHANNEL_MUX_CLIENT) {
		mux_remove_remote_forwardings(ssh, c);
		విడుదల(c->mux_ctx);
		c->mux_ctx = ఖాళీ;
	} లేకపోతే ఒకవేళ (c->type == SSH_CHANNEL_MUX_LISTENER) {
		విడుదల(c->mux_ctx);
		c->mux_ctx = ఖాళీ;
	}

	ఒకవేళ (log_level_get() >= SYSLOG_LEVEL_DEBUG3) {
		s = channel_open_సందేశం(ssh);
		debug3("channel %d: status: %s", c->self, s);
		విడుదల(s);
	}

	channel_close_fds(ssh, c);
	sshbuf_free(c->ఆదానం);
	sshbuf_free(c->output);
	sshbuf_free(c->extended);
	c->ఆదానం = c->output = c->extended = ఖాళీ;
	విడుదల(c->remote_name);
	c->remote_name = ఖాళీ;
	విడుదల(c->మార్గం);
	c->మార్గం = ఖాళీ;
	విడుదల(c->listening_addr);
	c->listening_addr = ఖాళీ;
	విడుదల(c->xctype);
	c->xctype = ఖాళీ;
	channel_free_connect_ctx(c);
	అయితే ((cc = TAILQ_FIRST(&c->స్థితి_confirms)) != ఖాళీ) {
		ఒకవేళ (cc->abandon_cb != ఖాళీ)
			cc->abandon_cb(ssh, c, cc->ctx);
		TAILQ_REMOVE(&c->స్థితి_confirms, cc, నమోదు_2);
		freezero(cc, పరిమాణం(*cc));
	}
	ఒకవేళ (c->filter_cleanup != ఖాళీ && c->filter_ctx != ఖాళీ)
		c->filter_cleanup(ssh, c->self, c->filter_ctx);
	sc->channels[c->self] = ఖాళీ;
	freezero(c, పరిమాణం(*c));
}

శూన్య
channel_free_all(నిర్మాణం ssh *ssh)
{
	u_int i;
	నిర్మాణం ssh_channels *sc = ssh->chanctxt;

	కొరకు (i = 0; i < sc->channels_alloc; i++)
		ఒకవేళ (sc->channels[i] != ఖాళీ)
			channel_free(ssh, sc->channels[i]);

	విడుదల(sc->channels);
	sc->channels = ఖాళీ;
	sc->channels_alloc = 0;

	విడుదల(sc->x11_saved_display);
	sc->x11_saved_display = ఖాళీ;

	విడుదల(sc->x11_saved_proto);
	sc->x11_saved_proto = ఖాళీ;

	విడుదల(sc->x11_saved_దత్తాంశం);
	sc->x11_saved_దత్తాంశం = ఖాళీ;
	sc->x11_saved_దత్తాంశం_len = 0;

	విడుదల(sc->x11_fake_దత్తాంశం);
	sc->x11_fake_దత్తాంశం = ఖాళీ;
	sc->x11_fake_దత్తాంశం_len = 0;
}

శూన్య
channel_free_channels(నిర్మాణం ssh *ssh)
{
	నిర్మాణం ssh_channels *sc;

	ఒకవేళ (ssh == ఖాళీ || ssh->chanctxt == ఖాళీ)
		తిరిగి;
	channel_free_all(ssh);
	channel_clear_permission(ssh, FORWARD_USER, FORWARD_LOCAL);
	channel_clear_permission(ssh, FORWARD_USER, FORWARD_REMOTE);
	channel_clear_permission(ssh, FORWARD_ADM, FORWARD_LOCAL);
	channel_clear_permission(ssh, FORWARD_ADM, FORWARD_REMOTE);
	sc = ssh->chanctxt;
	విడుదల(sc->bulk_classifier_tty);
	విడుదల(sc->bulk_classifier_notty);
	విడుదల(sc->channel_pre);
	విడుదల(sc->channel_post);
	freezero(sc, పరిమాణం(*sc));
	ssh->chanctxt = ఖాళీ;
}

/*
 * Closes the sockets/fds of all channels.  This is used to close extra file
 * descriptors after a fork.
 */
శూన్య
channel_close_all(నిర్మాణం ssh *ssh)
{
	u_int i;

	కొరకు (i = 0; i < ssh->chanctxt->channels_alloc; i++)
		ఒకవేళ (ssh->chanctxt->channels[i] != ఖాళీ)
			channel_close_fds(ssh, ssh->chanctxt->channels[i]);
}

/*
 * Stop listening to channels.
 */
శూన్య
channel_stop_listening(నిర్మాణం ssh *ssh)
{
	u_int i;
	Channel *c;

	కొరకు (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		ఒకవేళ (c != ఖాళీ) {
			ఎంపిక (c->type) {
			స్థితి SSH_CHANNEL_AUTH_SOCKET:
			స్థితి SSH_CHANNEL_పోర్టు_LISTENER:
			స్థితి SSH_CHANNEL_RPORT_LISTENER:
			స్థితి SSH_CHANNEL_X11_LISTENER:
			స్థితి SSH_CHANNEL_UNIX_LISTENER:
			స్థితి SSH_CHANNEL_RUNIX_LISTENER:
				channel_close_fd(ssh, c, &c->sock);
				channel_free(ssh, c);
				ఆపు;
			}
		}
	}
}

/*
 * Returns true if no channel has too much buffered data, and false if one or
 * more channel is overfull.
 */
పూర్ణాంకం
channel_not_very_much_buffered_దత్తాంశం(నిర్మాణం ssh *ssh)
{
	u_int i;
	u_int maxsize = ssh_packet_get_maxsize(ssh);
	Channel *c;

	కొరకు (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		ఒకవేళ (c == ఖాళీ || c->type != SSH_CHANNEL_OPEN)
			కొనసాగు;
		ఒకవేళ (sshbuf_len(c->output) > maxsize) {
			debug2("channel %d: big output buffer %zu > %u",
			    c->self, sshbuf_len(c->output), maxsize);
			తిరిగి 0;
		}
	}
	తిరిగి 1;
}

/* Returns true if any channel is still open. */
పూర్ణాంకం
channel_still_open(నిర్మాణం ssh *ssh)
{
	u_int i;
	Channel *c;

	కొరకు (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		ఒకవేళ (c == ఖాళీ)
			కొనసాగు;
		ఎంపిక (c->type) {
		స్థితి SSH_CHANNEL_X11_LISTENER:
		స్థితి SSH_CHANNEL_పోర్టు_LISTENER:
		స్థితి SSH_CHANNEL_RPORT_LISTENER:
		స్థితి SSH_CHANNEL_MUX_LISTENER:
		స్థితి SSH_CHANNEL_CLOSED:
		స్థితి SSH_CHANNEL_AUTH_SOCKET:
		స్థితి SSH_CHANNEL_DYNAMIC:
		స్థితి SSH_CHANNEL_RDYNAMIC_OPEN:
		స్థితి SSH_CHANNEL_CONNECTING:
		స్థితి SSH_CHANNEL_ZOMBIE:
		స్థితి SSH_CHANNEL_ABANDONED:
		స్థితి SSH_CHANNEL_UNIX_LISTENER:
		స్థితి SSH_CHANNEL_RUNIX_LISTENER:
			కొనసాగు;
		స్థితి SSH_CHANNEL_LARVAL:
			కొనసాగు;
		స్థితి SSH_CHANNEL_OPENING:
		స్థితి SSH_CHANNEL_OPEN:
		స్థితి SSH_CHANNEL_RDYNAMIC_ముగింపు:
		స్థితి SSH_CHANNEL_X11_OPEN:
		స్థితి SSH_CHANNEL_MUX_CLIENT:
		స్థితి SSH_CHANNEL_MUX_PROXY:
			తిరిగి 1;
		అప్రమేయ:
			fatal_f("bad channel type %d", c->type);
			/* NOTREACHED */
		}
	}
	తిరిగి 0;
}

/* Returns true if a channel with a TTY is open. */
పూర్ణాంకం
channel_tty_open(నిర్మాణం ssh *ssh)
{
	u_int i;
	Channel *c;

	కొరకు (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		ఒకవేళ (c == ఖాళీ || c->type != SSH_CHANNEL_OPEN)
			కొనసాగు;
		ఒకవేళ (c->client_tty)
			తిరిగి 1;
	}
	తిరిగి 0;
}

/* Returns the id of an open channel suitable for keepaliving */
పూర్ణాంకం
channel_కనుగొను_open(నిర్మాణం ssh *ssh)
{
	u_int i;
	Channel *c;

	కొరకు (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		ఒకవేళ (c == ఖాళీ || !c->have_remote_id)
			కొనసాగు;
		ఎంపిక (c->type) {
		స్థితి SSH_CHANNEL_CLOSED:
		స్థితి SSH_CHANNEL_DYNAMIC:
		స్థితి SSH_CHANNEL_RDYNAMIC_OPEN:
		స్థితి SSH_CHANNEL_RDYNAMIC_ముగింపు:
		స్థితి SSH_CHANNEL_X11_LISTENER:
		స్థితి SSH_CHANNEL_పోర్టు_LISTENER:
		స్థితి SSH_CHANNEL_RPORT_LISTENER:
		స్థితి SSH_CHANNEL_MUX_LISTENER:
		స్థితి SSH_CHANNEL_MUX_CLIENT:
		స్థితి SSH_CHANNEL_MUX_PROXY:
		స్థితి SSH_CHANNEL_OPENING:
		స్థితి SSH_CHANNEL_CONNECTING:
		స్థితి SSH_CHANNEL_ZOMBIE:
		స్థితి SSH_CHANNEL_ABANDONED:
		స్థితి SSH_CHANNEL_UNIX_LISTENER:
		స్థితి SSH_CHANNEL_RUNIX_LISTENER:
			కొనసాగు;
		స్థితి SSH_CHANNEL_LARVAL:
		స్థితి SSH_CHANNEL_AUTH_SOCKET:
		స్థితి SSH_CHANNEL_OPEN:
		స్థితి SSH_CHANNEL_X11_OPEN:
			తిరిగి i;
		అప్రమేయ:
			fatal_f("bad channel type %d", c->type);
			/* NOTREACHED */
		}
	}
	తిరిగి -1;
}

/* Returns the state of the channel's extended usage flag */
స్థిరరాశి అక్షరం *
channel_format_extended_usage(స్థిరరాశి Channel *c)
{
	ఒకవేళ (c->efd == -1)
		తిరిగి "closed";

	ఎంపిక (c->extended_usage) {
	స్థితి CHAN_EXTENDED_WRITE:
		తిరిగి "write";
	స్థితి CHAN_EXTENDED_READ:
		తిరిగి "read";
	స్థితి CHAN_EXTENDED_IGNORE:
		తిరిగి "ignore";
	అప్రమేయ:
		తిరిగి "UNKNOWN";
	}
}

స్థిర అక్షరం *
channel_format_స్థితి(స్థిరరాశి Channel *c)
{
	అక్షరం *ret = ఖాళీ;

	xasprintf(&ret, "t%d [%s] %s%u %s%u i%u/%zu o%u/%zu e[%s]/%zu "
	    "fd %d/%d/%d sock %d cc %d %s%u io 0x%02x/0x%02x %s%s",
	    c->type, c->xctype != ఖాళీ ? c->xctype : c->ctype,
	    c->have_remote_id ? "r" : "nr", c->remote_id,
	    c->mux_ctx != ఖాళీ ? "m" : "nm", c->mux_downstream_id,
	    c->istate, sshbuf_len(c->ఆదానం),
	    c->ostate, sshbuf_len(c->output),
	    channel_format_extended_usage(c), sshbuf_len(c->extended),
	    c->rfd, c->wfd, c->efd, c->sock, c->ctl_chan,
	    c->have_ctl_బిడ్డ_id ? "c" : "nc", c->ctl_బిడ్డ_id,
	    c->io_want, c->io_ready,
	    c->isatty ? "T" : (c->remote_has_tty ? "RT" : ""),
	    c->bulk ? "B" : "I");
	తిరిగి ret;
}

/*
 * Returns a message describing the currently open forwarded connections,
 * suitable for sending to the client.  The message contains crlf pairs for
 * newlines.
 */
అక్షరం *
channel_open_సందేశం(నిర్మాణం ssh *ssh)
{
	నిర్మాణం sshbuf *buf;
	Channel *c;
	u_int i;
	పూర్ణాంకం r;
	అక్షరం *cp, *ret;

	ఒకవేళ ((buf = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new");
	ఒకవేళ ((r = sshbuf_putf(buf,
	    "The following connections are open:\r\n")) != 0)
		fatal_fr(r, "sshbuf_putf");
	కొరకు (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		ఒకవేళ (c == ఖాళీ)
			కొనసాగు;
		ఎంపిక (c->type) {
		స్థితి SSH_CHANNEL_X11_LISTENER:
		స్థితి SSH_CHANNEL_పోర్టు_LISTENER:
		స్థితి SSH_CHANNEL_RPORT_LISTENER:
		స్థితి SSH_CHANNEL_CLOSED:
		స్థితి SSH_CHANNEL_AUTH_SOCKET:
		స్థితి SSH_CHANNEL_ZOMBIE:
		స్థితి SSH_CHANNEL_ABANDONED:
		స్థితి SSH_CHANNEL_MUX_LISTENER:
		స్థితి SSH_CHANNEL_UNIX_LISTENER:
		స్థితి SSH_CHANNEL_RUNIX_LISTENER:
			కొనసాగు;
		స్థితి SSH_CHANNEL_LARVAL:
		స్థితి SSH_CHANNEL_OPENING:
		స్థితి SSH_CHANNEL_CONNECTING:
		స్థితి SSH_CHANNEL_DYNAMIC:
		స్థితి SSH_CHANNEL_RDYNAMIC_OPEN:
		స్థితి SSH_CHANNEL_RDYNAMIC_ముగింపు:
		స్థితి SSH_CHANNEL_OPEN:
		స్థితి SSH_CHANNEL_X11_OPEN:
		స్థితి SSH_CHANNEL_MUX_PROXY:
		స్థితి SSH_CHANNEL_MUX_CLIENT:
			cp = channel_format_స్థితి(c);
			ఒకవేళ ((r = sshbuf_putf(buf, "  #%d %.300s (%s)\r\n",
			    c->self, c->remote_name, cp)) != 0) {
				విడుదల(cp);
				fatal_fr(r, "sshbuf_putf");
			}
			విడుదల(cp);
			కొనసాగు;
		అప్రమేయ:
			fatal_f("bad channel type %d", c->type);
			/* NOTREACHED */
		}
	}
	ఒకవేళ ((ret = sshbuf_dup_string(buf)) == ఖాళీ)
		fatal_f("sshbuf_dup_string");
	sshbuf_free(buf);
	తిరిగి ret;
}

శూన్య
channel_report_open(నిర్మాణం ssh *ssh, పూర్ణాంకం level)
{
	అక్షరం *open, *oopen, *cp, ident[256];

	sshpkt_fmt_connection_id(ssh, ident, పరిమాణం(ident));
	do_log2(level, "Connection: %s (pid %ld)", ident, (దీర్ఘ)getpid());
	open = oopen = channel_open_సందేశం(ssh);
	అయితే ((cp = strsep(&open, "\r\n")) != ఖాళీ) {
		ఒకవేళ (*cp != '\0')
			do_log2(level, "%s", cp);
	}
	విడుదల(oopen);
}

స్థిర శూన్య
open_preamble(నిర్మాణం ssh *ssh, స్థిరరాశి అక్షరం *where, Channel *c, స్థిరరాశి అక్షరం *type)
{
	పూర్ణాంకం r;

	ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh, SSH2_సందేశం_CHANNEL_OPEN)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, type)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_కిటికీ)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0) {
		fatal_r(r, "%s: channel %i: open", where, c->self);
	}
}

శూన్య
channel_send_open(నిర్మాణం ssh *ssh, పూర్ణాంకం id)
{
	Channel *c = channel_lookup(ssh, id);
	పూర్ణాంకం r;

	ఒకవేళ (c == ఖాళీ) {
		logit("channel_send_open: %d: bad id", id);
		తిరిగి;
	}
	debug2("channel %d: send open", id);
	open_preamble(ssh, __func__, c, c->ctype);
	ఒకవేళ ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i", c->self);
}

శూన్య
channel_request_ప్రారంభం(నిర్మాణం ssh *ssh, పూర్ణాంకం id, స్థిరరాశి అక్షరం *service,
    పూర్ణాంకం wantconfirm)
{
	Channel *c = channel_lookup(ssh, id);
	పూర్ణాంకం r;

	ఒకవేళ (c == ఖాళీ) {
		logit_f("%d: unknown channel id", id);
		తిరిగి;
	}
	ఒకవేళ (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);

	debug2("channel %d: request %s confirm %d", id, service, wantconfirm);
	ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh, SSH2_సందేశం_CHANNEL_REQUEST)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, service)) != 0 ||
	    (r = sshpkt_put_u8(ssh, wantconfirm)) != 0) {
		fatal_fr(r, "channel %i", c->self);
	}
}

శూన్య
channel_రిజిస్టరు_స్థితి_confirm(నిర్మాణం ssh *ssh, పూర్ణాంకం id,
    channel_confirm_cb *cb, channel_confirm_abandon_cb *abandon_cb, శూన్య *ctx)
{
	నిర్మాణం channel_confirm *cc;
	Channel *c;

	ఒకవేళ ((c = channel_lookup(ssh, id)) == ఖాళీ)
		fatal_f("%d: bad id", id);

	cc = xcalloc(1, పరిమాణం(*cc));
	cc->cb = cb;
	cc->abandon_cb = abandon_cb;
	cc->ctx = ctx;
	TAILQ_INSERT_TAIL(&c->స్థితి_confirms, cc, నమోదు_2);
}

శూన్య
channel_రిజిస్టరు_open_confirm(నిర్మాణం ssh *ssh, పూర్ణాంకం id,
    channel_open_fn *fn, శూన్య *ctx)
{
	Channel *c = channel_lookup(ssh, id);

	ఒకవేళ (c == ఖాళీ) {
		logit_f("%d: bad id", id);
		తిరిగి;
	}
	c->open_confirm = fn;
	c->open_confirm_ctx = ctx;
}

శూన్య
channel_రిజిస్టరు_cleanup(నిర్మాణం ssh *ssh, పూర్ణాంకం id,
    channel_callback_fn *fn, పూర్ణాంకం do_close)
{
	Channel *c = channel_by_id(ssh, id);

	ఒకవేళ (c == ఖాళీ) {
		logit_f("%d: bad id", id);
		తిరిగి;
	}
	c->detach_user = fn;
	c->detach_close = do_close;
}

శూన్య
channel_cancel_cleanup(నిర్మాణం ssh *ssh, పూర్ణాంకం id)
{
	Channel *c = channel_by_id(ssh, id);

	ఒకవేళ (c == ఖాళీ) {
		logit_f("%d: bad id", id);
		తిరిగి;
	}
	c->detach_user = ఖాళీ;
	c->detach_close = 0;
}

శూన్య
channel_రిజిస్టరు_filter(నిర్మాణం ssh *ssh, పూర్ణాంకం id, channel_infilter_fn *ifn,
    channel_outfilter_fn *ofn, channel_filter_cleanup_fn *cfn, శూన్య *ctx)
{
	Channel *c = channel_lookup(ssh, id);

	ఒకవేళ (c == ఖాళీ) {
		logit_f("%d: bad id", id);
		తిరిగి;
	}
	c->ఆదానం_filter = ifn;
	c->output_filter = ofn;
	c->filter_ctx = ctx;
	c->filter_cleanup = cfn;
}

శూన్య
channel_సమితి_fds(నిర్మాణం ssh *ssh, పూర్ణాంకం id, పూర్ణాంకం rfd, పూర్ణాంకం wfd, పూర్ణాంకం efd,
    పూర్ణాంకం extusage, పూర్ణాంకం nonblock, పూర్ణాంకం is_tty, u_int కిటికీ_max)
{
	Channel *c = channel_lookup(ssh, id);
	పూర్ణాంకం r;

	ఒకవేళ (c == ఖాళీ || c->type != SSH_CHANNEL_LARVAL)
		fatal("channel_activate for non-larval channel %d.", id);
	ఒకవేళ (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);

	channel_రిజిస్టరు_fds(ssh, c, rfd, wfd, efd, extusage, nonblock, is_tty);
	c->type = SSH_CHANNEL_OPEN;
	channel_సమితి_వాడిన_సమయం(ssh, c);
	c->local_కిటికీ = c->local_కిటికీ_max = కిటికీ_max;

	ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh, SSH2_సందేశం_CHANNEL_కిటికీ_ADJUST)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_కిటికీ)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i", c->self);
}

స్థిర శూన్య
channel_pre_listener(నిర్మాణం ssh *ssh, Channel *c)
{
	c->io_want = SSH_CHAN_IO_SOCK_R;
}

స్థిర శూన్య
channel_pre_connecting(నిర్మాణం ssh *ssh, Channel *c)
{
	debug3("channel %d: waiting for connection", c->self);
	c->io_want = SSH_CHAN_IO_SOCK_W;
}

స్థిర శూన్య
channel_pre_open(నిర్మాణం ssh *ssh, Channel *c)
{
	c->io_want = 0;
	ఒకవేళ (c->istate == CHAN_ఆదానం_OPEN &&
	    c->remote_కిటికీ > 0 &&
	    sshbuf_len(c->ఆదానం) < c->remote_కిటికీ &&
	    sshbuf_check_reserve(c->ఆదానం, CHAN_RBUF) == 0)
		c->io_want |= SSH_CHAN_IO_RFD;
	ఒకవేళ (c->ostate == CHAN_OUTPUT_OPEN ||
	    c->ostate == CHAN_OUTPUT_WAIT_DRAIN) {
		ఒకవేళ (sshbuf_len(c->output) > 0) {
			c->io_want |= SSH_CHAN_IO_WFD;
		} లేకపోతే ఒకవేళ (c->ostate == CHAN_OUTPUT_WAIT_DRAIN) {
			ఒకవేళ (CHANNEL_EFD_OUTPUT_చురుకైన(c))
				debug2("channel %d: "
				    "obuf_empty delayed efd %d/(%zu)", c->self,
				    c->efd, sshbuf_len(c->extended));
			లేకపోతే
				chan_obuf_ఖాళీలు(ssh, c);
		}
	}
	/** XXX check close conditions, too */
	ఒకవేళ (c->efd != -1 && !(c->istate == CHAN_ఆదానం_CLOSED &&
	    c->ostate == CHAN_OUTPUT_CLOSED)) {
		ఒకవేళ (c->extended_usage == CHAN_EXTENDED_WRITE &&
		    sshbuf_len(c->extended) > 0)
			c->io_want |= SSH_CHAN_IO_EFD_W;
		లేకపోతే ఒకవేళ (c->efd != -1 && !(c->flags & CHAN_EOF_పంపిన) &&
		    (c->extended_usage == CHAN_EXTENDED_READ ||
		    c->extended_usage == CHAN_EXTENDED_IGNORE) &&
		    sshbuf_len(c->extended) < c->remote_కిటికీ)
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
స్థిర పూర్ణాంకం
x11_open_helper(నిర్మాణం ssh *ssh, నిర్మాణం sshbuf *b)
{
	నిర్మాణం ssh_channels *sc = ssh->chanctxt;
	u_char *ucp;
	u_int proto_len, దత్తాంశం_len;

	ఒకవేళ (sc->x11_saved_proto == ఖాళీ) {
		error("X11 forwarding opened before X11 forwarding requested");
		తిరిగి -1;
	}

	/* Is this being called after the refusal deadline? */
	ఒకవేళ (sc->x11_refuse_సమయం != 0.0 &&
	    monotime_double() >= sc->x11_refuse_సమయం) {
		verbose("Rejected X11 connection after ForwardX11Timeout "
		    "expired");
		తిరిగి -1;
	}

	/* Check if the fixed size part of the packet is in buffer. */
	ఒకవేళ (sshbuf_len(b) < 12)
		తిరిగి 0;

	/* Parse the lengths of variable-length fields. */
	ucp = sshbuf_mutable_ptr(b);
	ఒకవేళ (ucp[0] == 0x42) {	/* Byte order MSB first. */
		proto_len = 256 * ucp[6] + ucp[7];
		దత్తాంశం_len = 256 * ucp[8] + ucp[9];
	} లేకపోతే ఒకవేళ (ucp[0] == 0x6c) {	/* Byte order LSB first. */
		proto_len = ucp[6] + 256 * ucp[7];
		దత్తాంశం_len = ucp[8] + 256 * ucp[9];
	} లేకపోతే {
		debug2("Initial X11 packet contains bad byte order byte: 0x%x",
		    ucp[0]);
		తిరిగి -1;
	}

	/* Check if the whole packet is in buffer. */
	ఒకవేళ (sshbuf_len(b) <
	    12 + ((proto_len + 3) & ~3) + ((దత్తాంశం_len + 3) & ~3))
		తిరిగి 0;

	/* Check if authentication protocol matches. */
	ఒకవేళ (proto_len != అక్షరశ్రేణి_పొడవు(sc->x11_saved_proto) ||
	    memcmp(ucp + 12, sc->x11_saved_proto, proto_len) != 0) {
		debug2("X11 connection uses different authentication protocol.");
		తిరిగి -1;
	}
	/* Check if authentication data matches our fake data. */
	ఒకవేళ (దత్తాంశం_len != sc->x11_fake_దత్తాంశం_len ||
	    timingsafe_bcmp(ucp + 12 + ((proto_len + 3) & ~3),
		sc->x11_fake_దత్తాంశం, sc->x11_fake_దత్తాంశం_len) != 0) {
		debug2("X11 auth data does not match fake data.");
		తిరిగి -1;
	}
	/* Check fake data length */
	ఒకవేళ (sc->x11_fake_దత్తాంశం_len != sc->x11_saved_దత్తాంశం_len) {
		error("X11 fake_data_len %d != saved_data_len %d",
		    sc->x11_fake_దత్తాంశం_len, sc->x11_saved_దత్తాంశం_len);
		తిరిగి -1;
	}
	/*
	 * Received authentication protocol and data match
	 * our fake data. Substitute the fake data with real
	 * data.
	 */
	జ్ఞాపకం_నకలు(ucp + 12 + ((proto_len + 3) & ~3),
	    sc->x11_saved_దత్తాంశం, sc->x11_saved_దత్తాంశం_len);
	తిరిగి 1;
}

శూన్య
channel_force_close(నిర్మాణం ssh *ssh, Channel *c, పూర్ణాంకం abandon)
{
	debug3_f("channel %d: forcibly closing", c->self);
	ఒకవేళ (c->istate == CHAN_ఆదానం_OPEN)
		chan_read_failed(ssh, c);
	ఒకవేళ (c->istate == CHAN_ఆదానం_WAIT_DRAIN) {
		sshbuf_reset(c->ఆదానం);
		chan_ibuf_ఖాళీలు(ssh, c);
	}
	ఒకవేళ (c->ostate == CHAN_OUTPUT_OPEN ||
	    c->ostate == CHAN_OUTPUT_WAIT_DRAIN) {
		sshbuf_reset(c->output);
		chan_write_failed(ssh, c);
	}
	ఒకవేళ (c->detach_user)
		c->detach_user(ssh, c->self, 1, ఖాళీ);
	ఒకవేళ (c->efd != -1)
		channel_close_fd(ssh, c, &c->efd);
	ఒకవేళ (abandon)
		c->type = SSH_CHANNEL_ABANDONED;
	/* exempt from inactivity timeouts */
	c->inactive_deadline = 0;
	c->lastused = 0;
}

స్థిర శూన్య
channel_pre_x11_open(నిర్మాణం ssh *ssh, Channel *c)
{
	పూర్ణాంకం ret = x11_open_helper(ssh, c->output);

	/* c->force_drain = 1; */

	ఒకవేళ (ret == 1) {
		c->type = SSH_CHANNEL_OPEN;
		channel_సమితి_వాడిన_సమయం(ssh, c);
		channel_pre_open(ssh, c);
	} లేకపోతే ఒకవేళ (ret == -1) {
		logit("X11 connection rejected because of wrong "
		    "authentication.");
		debug2("X11 rejected %d i%d/o%d",
		    c->self, c->istate, c->ostate);
		channel_force_close(ssh, c, 0);
	}
}

స్థిర శూన్య
channel_pre_mux_client(నిర్మాణం ssh *ssh, Channel *c)
{
	c->io_want = 0;
	ఒకవేళ (c->istate == CHAN_ఆదానం_OPEN && !c->mux_pause &&
	    sshbuf_check_reserve(c->ఆదానం, CHAN_RBUF) == 0)
		c->io_want |= SSH_CHAN_IO_RFD;
	ఒకవేళ (c->istate == CHAN_ఆదానం_WAIT_DRAIN) {
		/* clear buffer immediately (discard any partial packet) */
		sshbuf_reset(c->ఆదానం);
		chan_ibuf_ఖాళీలు(ssh, c);
		/* Start output drain. XXX just kill chan? */
		chan_rcvd_oclose(ssh, c);
	}
	ఒకవేళ (c->ostate == CHAN_OUTPUT_OPEN ||
	    c->ostate == CHAN_OUTPUT_WAIT_DRAIN) {
		ఒకవేళ (sshbuf_len(c->output) > 0)
			c->io_want |= SSH_CHAN_IO_WFD;
		లేకపోతే ఒకవేళ (c->ostate == CHAN_OUTPUT_WAIT_DRAIN)
			chan_obuf_ఖాళీలు(ssh, c);
	}
}

స్థిర అంతఃవరుస పూర్ణాంకం
socks_decode_error(Channel *c, పూర్ణాంకం స్థితి_2, స్థిరరాశి అక్షరం *func, స్థిరరాశి అక్షరం *సందేశం)
{
	ఒకవేళ (స్థితి_2 == SSH_ERR_సందేశం_INCOMPLETE)
		తిరిగి 0;
	లేకపోతే {
		debug_r(స్థితి_2, "%s: channel %d: decode %s",
		    func, c->self, సందేశం);
		తిరిగి -1;
	}
}

/* try to decode a socks4 header */
స్థిర పూర్ణాంకం
channel_decode_socks4(Channel *c, నిర్మాణం sshbuf *ఆదానం, నిర్మాణం sshbuf *output)
{
	uint8_t socks_ver, socks_cmd, dest_addr[4];
	uint16_t dest_పోర్టు;
	అక్షరం *user = ఖాళీ, *host = ఖాళీ;
	పూర్ణాంకం success = -1, socks4a = 0, r;
	నిర్మాణం sshbuf *b = ఖాళీ;

	ఒకవేళ (sshbuf_len(ఆదానం) < 9)
		తిరిగి 0;

	/* We may not have a complete message, so work on a dup of the buffer */
	ఒకవేళ ((b = sshbuf_fromb(ఆదానం)) == ఖాళీ)
		fatal_f("sshbuf_fromb failed");

	debug2("channel %d: decode socks4", c->self);
	ఒకవేళ ((r = sshbuf_get_u8(b, &socks_ver)) != 0 ||
	    (r = sshbuf_get_u8(b, &socks_cmd)) != 0 ||
	    (r = sshbuf_get_u16(b, &dest_పోర్టు)) != 0 ||
	    (r = sshbuf_get(b, &dest_addr, పరిమాణం(dest_addr))) != 0 ||
	    (r = sshbuf_get_nulterminated_string(b, 1024, &user, ఖాళీ)) != 0) {
		success = socks_decode_error(c, r, __func__, "header");
		వెళ్ళు బహిర్గతం;
	}

	/* Is this a SOCKS4A request? (indicated by an address of 0.0.0.x) */
	ఒకవేళ (dest_addr[0] == 0 && dest_addr[1] == 0 &&
	    dest_addr[2] == 0 && dest_addr[3] != 0) {
		/* If so, then the hostname follows, also nul-terminated */
		ఒకవేళ ((r = sshbuf_get_nulterminated_string(b, 1024,
		    &host, ఖాళీ)) != 0) {
			success = socks_decode_error(c, r, __func__, "host");
			వెళ్ళు బహిర్గతం;
		}
		socks4a = 1;
	} లేకపోతే {
		/* Plain SOCKS4 passes an IPv4 binary address; reconstruct */
		xasprintf(&host, "%d.%d.%d.%d",
		    dest_addr[0], dest_addr[1], dest_addr[2], dest_addr[3]);
	}

	/* We have a complete SOCKS4 message; consume it from input */
	ఒకవేళ ((r = sshbuf_consume_upto_బిడ్డ(ఆదానం, b)) != 0)
		fatal_fr(r, "channel %d: consume", c->self);

	/* Handle the request */
	debug2("channel %d: %s: user=\"%s\" command=%d destination=[%s]:%d",
	    c->self, socks4a ? "SOCKS4A" : "SOCKS4", user, (పూర్ణాంకం)socks_cmd,
	    host, dest_పోర్టు);
	ఒకవేళ (socks_cmd != 1) {
		debug("channel %d: cannot handle %s command 0x%02x",
		    c->self, socks4a ? "SOCKS4A" : "SOCKS4", socks_cmd);
		వెళ్ళు బహిర్గతం;
	}
	విడుదల(c->మార్గం);
	c->మార్గం = host;
	host = ఖాళీ; /* transferred */
	c->host_పోర్టు = dest_పోర్టు;

	/* Reply to the SOCKS4 client */
	ఒకవేళ ((r = sshbuf_put_u8(output, 0)) != 0 ||	/* vn: 0 for reply */
	    (r = sshbuf_put_u8(output, 90)) != 0 ||	/* cd: req granted */
	    (r = sshbuf_put_u16(output, 0)) != 0 ||	/* port: ignored */
	    (r = sshbuf_put_u32(output, ntohl(INADDR_ANY))) != 0) /* ignored */
		fatal_fr(r, "channel %d: compose reply", c->self);

	/* success */
	success = 1;
 బహిర్గతం:
	sshbuf_free(b);
	విడుదల(user);
	విడుదల(host);
	తిరిగి success;
}

/* try to decode a socks5 header */
#నిర్వచించు SSH_SOCKS5_AUTHDONE	0x1000
#నిర్వచించు SSH_SOCKS5_NOAUTH	0x00
#నిర్వచించు SSH_SOCKS5_IPV4		0x01
#నిర్వచించు SSH_SOCKS5_DOMAIN	0x03
#నిర్వచించు SSH_SOCKS5_IPV6		0x04
#నిర్వచించు SSH_SOCKS5_CONNECT	0x01
#నిర్వచించు SSH_SOCKS5_SUCCESS	0x00

/*
 * Handles SOCKS5 authentication. Note 'b' must be a dup of 'input'
 * Returns 0 on insufficient queued date, 1 on authentication success or
 * -1 on error.
 */
స్థిర పూర్ణాంకం
channel_socks5_check_auth(Channel *c, నిర్మాణం sshbuf *b, నిర్మాణం sshbuf *ఆదానం,
    నిర్మాణం sshbuf *output)
{
	uint8_t socks_ver;
	uint8_t nmethods, పద్ధతి;
	పూర్ణాంకం r;
	u_int i, దొరికింది;

	/* format: ver | nmethods | methods */
	ఒకవేళ ((r = sshbuf_get_u8(b, &socks_ver)) != 0)
		తిరిగి socks_decode_error(c, r, __func__, "version");
	ఒకవేళ (socks_ver != 5) /* shouldn't happen; checked by caller^2 */
		fatal_fr(r, "channel %d: internal error: not socks5", c->self);
	ఒకవేళ ((r = sshbuf_get_u8(b, &nmethods)) != 0)
		తిరిగి socks_decode_error(c, r, __func__, "methods");
	కొరకు (దొరికింది = i = 0; i < nmethods; i++) {
		ఒకవేళ ((r = sshbuf_get_u8(b, &పద్ధతి)) != 0)
			తిరిగి socks_decode_error(c, r, __func__, "method");
		ఒకవేళ (పద్ధతి == SSH_SOCKS5_NOAUTH)
			దొరికింది = 1;
	}
	ఒకవేళ (!దొరికింది) {
		debug("channel %d: didn't request SSH_SOCKS5_NOAUTH", c->self);
		తిరిగి -1;
	}
	/* Consume completed request */
	ఒకవేళ ((r = sshbuf_consume_upto_బిడ్డ(ఆదానం, b)) != 0)
		fatal_fr(r, "channel %d: consume", c->self);

	/* Compose reply: version, method */
	ఒకవేళ ((r = sshbuf_put_u8(output, 0x05)) != 0 ||
	    (r = sshbuf_put_u8(output, SSH_SOCKS5_NOAUTH)) != 0)
		fatal_fr(r, "channel %d: append reply", c->self);
	/* success */
	debug2("channel %d: socks5 auth done", c->self);
	తిరిగి 1;
}

స్థిర పూర్ణాంకం
channel_decode_socks5(Channel *c, నిర్మాణం sshbuf *ఆదానం, నిర్మాణం sshbuf *output)
{
	uint8_t socks_ver, socks_cmd, socks_reserved, socks_atyp, addrlen;
	uint16_t dest_పోర్టు;
	అక్షరం dest_addr[255+1], ntop[INET6_ADDRSTRLEN];
	u_int af;
	పూర్ణాంకం r, success = -1;;
	నిర్మాణం sshbuf *b = ఖాళీ;

	debug2("channel %d: decode socks5 %s", c->self,
	    (c->flags & SSH_SOCKS5_AUTHDONE) ? "request" : "auth");

	/* We may not have a complete message, so work on a dup of the buffer */
	ఒకవేళ ((b = sshbuf_fromb(ఆదానం)) == ఖాళీ)
		fatal_f("sshbuf_fromb failed");

	ఒకవేళ (!(c->flags & SSH_SOCKS5_AUTHDONE)) {
		ఒకవేళ ((r = channel_socks5_check_auth(c, b, ఆదానం, output)) != 1) {
			success = r;
			వెళ్ళు బహిర్గతం;
		}
		c->flags |= SSH_SOCKS5_AUTHDONE;
		/* Continue to parse request in case client speculated ahead */
	}

	/* Request messages (auth or connect) always start with the version */
	ఒకవేళ ((r = sshbuf_get_u8(b, &socks_ver)) != 0) {
		success = socks_decode_error(c, r, __func__, "version");
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (socks_ver != 5) /* shouldn't happen */
		fatal_fr(r, "channel %d: internal error: not socks5", c->self);

	/* Parse SOCKS5 request header */
	debug2("channel %d: socks5 post auth", c->self);
	ఒకవేళ ((r = sshbuf_get_u8(b, &socks_cmd)) != 0 ||
	    (r = sshbuf_get_u8(b, &socks_reserved)) != 0 ||
	    (r = sshbuf_get_u8(b, &socks_atyp)) != 0) {
		success = socks_decode_error(c, r, __func__, "request header");
		వెళ్ళు బహిర్గతం;
	}

	ఒకవేళ (socks_ver != 0x05 ||
	    socks_cmd != SSH_SOCKS5_CONNECT ||
	    socks_reserved != 0x00) {
		debug2("channel %d: only socks5 connect supported", c->self);
		వెళ్ళు బహిర్గతం;
	}

	ఎంపిక (socks_atyp) {
	స్థితి SSH_SOCKS5_IPV4:
		addrlen = 4;
		af = AF_INET;
		ఆపు;
	స్థితి SSH_SOCKS5_DOMAIN:
		ఒకవేళ ((r = sshbuf_get_u8(b, &addrlen)) != 0) {
			success = socks_decode_error(c, r, __func__, "addrlen");
			వెళ్ళు బహిర్గతం;
		}
		af = -1;
		ఆపు;
	స్థితి SSH_SOCKS5_IPV6:
		addrlen = 16;
		af = AF_INET6;
		ఆపు;
	అప్రమేయ:
		debug2("channel %d: bad socks5 atyp %d", c->self, socks_atyp);
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = sshbuf_get(b, &dest_addr, addrlen)) != 0 ||
	    (r = sshbuf_get_u16(b, &dest_పోర్టు)) != 0) {
		success = socks_decode_error(c, r, __func__, "addr/port");
		వెళ్ళు బహిర్గతం;
	}
	dest_addr[addrlen] = '\0';

	/* We have a complete SOCKS5 request; consume it from input */
	ఒకవేళ ((r = sshbuf_consume_upto_బిడ్డ(ఆదానం, b)) != 0)
		fatal_fr(r, "channel %d: consume", c->self);

	విడుదల(c->మార్గం);
	c->మార్గం = ఖాళీ;
	ఒకవేళ (socks_atyp == SSH_SOCKS5_DOMAIN)
		c->మార్గం = xstrdup(dest_addr);
	లేకపోతే {
		ఒకవేళ (inet_ntop(af, dest_addr, ntop, పరిమాణం(ntop)) == ఖాళీ)
			తిరిగి -1;
		c->మార్గం = xstrdup(ntop);
	}
	c->host_పోర్టు = dest_పోర్టు;

	debug2("channel %d: dynamic request: socks5 host %s port %u command %u",
	    c->self, c->మార్గం, c->host_పోర్టు, socks_cmd);

	/*జవాబు*/
	ఒకవేళ ((r = sshbuf_put_u8(output, 0x05)) != 0 ||	/*సంస్కరణ*/
	    (r = sshbuf_put_u8(output, SSH_SOCKS5_SUCCESS)) != 0 || /* cmd */
	    (r = sshbuf_put_u8(output, 0)) != 0 ||	/* reserved, ignored */
	    (r = sshbuf_put_u8(output, SSH_SOCKS5_IPV4)) != 0 || /* addrtype */
	    (r = sshbuf_put_u32(output, ntohl(INADDR_ANY))) != 0 || /* addr */
	    (r = sshbuf_put_u16(output, dest_పోర్టు)) != 0) /*పోర్టు*/
		fatal_fr(r, "channel %d: append reply", c->self);

	/* success */
	success = 1;
 బహిర్గతం:
	sshbuf_free(b);
	తిరిగి success;
}

Channel *
channel_connect_stdio_fwd(నిర్మాణం ssh *ssh,
    స్థిరరాశి అక్షరం *host_గమ్యం_connect, పూర్ణాంకం పోర్టు_గమ్యం_connect,
    పూర్ణాంకం లోపల, పూర్ణాంకం బహిర్గతం, పూర్ణాంకం nonblock)
{
	Channel *c;

	debug_f("%s:%d", host_గమ్యం_connect, పోర్టు_గమ్యం_connect);

	c = channel_new(ssh, "stdio-forward", SSH_CHANNEL_OPENING, లోపల, బహిర్గతం,
	    -1, CHAN_TCP_కిటికీ_DEFAULT, CHAN_TCP_PACKET_DEFAULT,
	    0, "stdio-forward", nonblock);

	c->మార్గం = xstrdup(host_గమ్యం_connect);
	c->host_పోర్టు = పోర్టు_గమ్యం_connect;
	c->listening_పోర్టు = 0;
	c->force_drain = 1;

	channel_రిజిస్టరు_fds(ssh, c, లోపల, బహిర్గతం, -1, 0, 1, 0);
	పోర్టు_open_helper(ssh, c, పోర్టు_గమ్యం_connect == పోర్టు_STREAMLOCAL ?
	    "direct-streamlocal@openssh.com" : "direct-tcpip");

	తిరిగి c;
}

/* dynamic port forwarding */
స్థిర శూన్య
channel_pre_dynamic(నిర్మాణం ssh *ssh, Channel *c)
{
	u_int have;
	u_char ver;
	పూర్ణాంకం r, ret;

	c->io_want = 0;
	have = sshbuf_len(c->ఆదానం);
	debug2("channel %d: pre_dynamic: have %d", c->self, have);
	/* sshbuf_dump(c->input, stderr); */
	/* check if the fixed size part of the packet is in buffer. */
	ఒకవేళ (have < 3) {
		/* need more */
		c->io_want |= SSH_CHAN_IO_RFD;
		తిరిగి;
	}
	/* try to guess the protocol */
	ఒకవేళ ((r = sshbuf_peek_u8(c->ఆదానం, 0, &ver)) != 0)
		fatal_fr(r, "sshbuf_peek_u8");
	ఎంపిక (ver) {
	స్థితి 0x04:
		ret = channel_decode_socks4(c, c->ఆదానం, c->output);
		ఆపు;
	స్థితి 0x05:
		ret = channel_decode_socks5(c, c->ఆదానం, c->output);
		ఆపు;
	అప్రమేయ:
		debug2_f("channel %d: unknown SOCKS version %u", c->self, ver);
		ret = -1;
		ఆపు;
	}
	ఒకవేళ (ret < 0) {
		chan_mark_dead(ssh, c);
	} లేకపోతే ఒకవేళ (ret == 0) {
		debug2("channel %d: pre_dynamic: need more", c->self);
		/* need more */
		c->io_want |= SSH_CHAN_IO_RFD;
		ఒకవేళ (sshbuf_len(c->output))
			c->io_want |= SSH_CHAN_IO_WFD;
	} లేకపోతే {
		/* switch to the next state */
		c->type = SSH_CHANNEL_OPENING;
		పోర్టు_open_helper(ssh, c, "direct-tcpip");
	}
}

/* simulate read-error */
స్థిర శూన్య
rdynamic_close(నిర్మాణం ssh *ssh, Channel *c)
{
	c->type = SSH_CHANNEL_OPEN;
	channel_force_close(ssh, c, 0);
}

/* reverse dynamic port forwarding */
స్థిర శూన్య
channel_before_prepare_io_rdynamic(నిర్మాణం ssh *ssh, Channel *c)
{
	స్థిరరాశి u_char *p;
	u_int have, len;
	పూర్ణాంకం r, ret;

	have = sshbuf_len(c->output);
	debug2("channel %d: pre_rdynamic: have %d", c->self, have);
	/* sshbuf_dump(c->output, stderr); */
	/* EOF received */
	ఒకవేళ (c->flags & CHAN_EOF_RCVD) {
		ఒకవేళ ((r = sshbuf_consume(c->output, have)) != 0)
			fatal_fr(r, "channel %d: consume", c->self);
		rdynamic_close(ssh, c);
		తిరిగి;
	}
	/* check if the fixed size part of the packet is in buffer. */
	ఒకవేళ (have < 3)
		తిరిగి;
	/* try to guess the protocol */
	p = sshbuf_ptr(c->output);
	ఎంపిక (p[0]) {
	స్థితి 0x04:
		/* switch input/output for reverse forwarding */
		ret = channel_decode_socks4(c, c->output, c->ఆదానం);
		ఆపు;
	స్థితి 0x05:
		ret = channel_decode_socks5(c, c->output, c->ఆదానం);
		ఆపు;
	అప్రమేయ:
		ret = -1;
		ఆపు;
	}
	ఒకవేళ (ret < 0) {
		rdynamic_close(ssh, c);
	} లేకపోతే ఒకవేళ (ret == 0) {
		debug2("channel %d: pre_rdynamic: need more", c->self);
		/* send socks request to peer */
		len = sshbuf_len(c->ఆదానం);
		ఒకవేళ (len > 0 && len < c->remote_కిటికీ) {
			ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh, SSH2_సందేశం_CHANNEL_దత్తాంశం)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
			    (r = sshpkt_put_stringb(ssh, c->ఆదానం)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0) {
				fatal_fr(r, "channel %i: rdynamic", c->self);
			}
			ఒకవేళ ((r = sshbuf_consume(c->ఆదానం, len)) != 0)
				fatal_fr(r, "channel %d: consume", c->self);
			c->remote_కిటికీ -= len;
		}
	} లేకపోతే ఒకవేళ (rdynamic_connect_ముగింపు(ssh, c) < 0) {
		/* the connect failed */
		rdynamic_close(ssh, c);
	}
}

/* This is our fake X11 server socket. */
స్థిర శూన్య
channel_post_x11_listener(నిర్మాణం ssh *ssh, Channel *c)
{
	Channel *nc;
	నిర్మాణం sockaddr_storage addr;
	పూర్ణాంకం r, newsock, oerrno, remote_పోర్టు;
	socklen_t addrlen;
	అక్షరం buf[16384], *remote_ipaddr;

	ఒకవేళ ((c->io_ready & SSH_CHAN_IO_SOCK_R) == 0)
		తిరిగి;

	debug("X11 connection requested.");
	addrlen = పరిమాణం(addr);
	newsock = accept(c->sock, (నిర్మాణం sockaddr *)&addr, &addrlen);
	ఒకవేళ (c->single_connection) {
		oerrno = errno;
		debug2("single_connection: closing X11 listener.");
		channel_close_fd(ssh, c, &c->sock);
		chan_mark_dead(ssh, c);
		errno = oerrno;
	}
	ఒకవేళ (newsock == -1) {
		ఒకవేళ (errno != EINTR && errno != EWOULDBLOCK &&
		    errno != ECONNABORTED)
			error("accept: %.100s", strerror(errno));
		ఒకవేళ (errno == EMFILE || errno == ENFILE)
			c->notbefore = monotime_double() + 1.0;
		తిరిగి;
	}
	సమితి_nodelay(newsock);
	ఒకవేళ (ssh->chanctxt->want_tcp_keepalive)
		సమితి_keepalive(newsock); /* logs errors */
	remote_ipaddr = get_peer_ipaddr(newsock);
	remote_పోర్టు = get_peer_పోర్టు(newsock);
	snprintf(buf, పరిమాణం buf, "X11 connection from %.200s port %d",
	    remote_ipaddr, remote_పోర్టు);

	nc = channel_new(ssh, "x11-connection",
	    SSH_CHANNEL_OPENING, newsock, newsock, -1,
	    c->local_కిటికీ_max, c->local_maxpacket, 0, buf, 1);
	open_preamble(ssh, __func__, nc, "x11");
	ఒకవేళ ((r = sshpkt_put_cstring(ssh, remote_ipaddr)) != 0 ||
	    (r = sshpkt_put_u32(ssh, remote_పోర్టు)) != 0) {
		fatal_fr(r, "channel %i: reply", c->self);
	}
	ఒకవేళ ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i: send", c->self);
	విడుదల(remote_ipaddr);
}

స్థిర శూన్య
పోర్టు_open_helper(నిర్మాణం ssh *ssh, Channel *c, అక్షరం *rtype)
{
	అక్షరం *local_ipaddr = get_local_ipaddr(c->sock);
	పూర్ణాంకం local_పోర్టు = c->sock == -1 ? 65536 : get_local_పోర్టు(c->sock);
	అక్షరం *remote_ipaddr = get_peer_ipaddr(c->sock);
	పూర్ణాంకం remote_పోర్టు = get_peer_పోర్టు(c->sock);
	పూర్ణాంకం r;

	ఒకవేళ (remote_పోర్టు == -1) {
		/* Fake addr/port to appease peers that validate it (Tectia) */
		విడుదల(remote_ipaddr);
		remote_ipaddr = xstrdup("127.0.0.1");
		remote_పోర్టు = 65535;
	}

	విడుదల(c->remote_name);
	xasprintf(&c->remote_name,
	    "%s: listening port %d for %.100s port %d, "
	    "connect from %.200s port %d to %.100s port %d",
	    rtype, c->listening_పోర్టు, c->మార్గం, c->host_పోర్టు,
	    remote_ipaddr, remote_పోర్టు, local_ipaddr, local_పోర్టు);

	open_preamble(ssh, __func__, c, rtype);
	ఒకవేళ (strcmp(rtype, "direct-tcpip") == 0) {
		/* target host, port */
		ఒకవేళ ((r = sshpkt_put_cstring(ssh, c->మార్గం)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->host_పోర్టు)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	} లేకపోతే ఒకవేళ (strcmp(rtype, "direct-streamlocal@openssh.com") == 0) {
		/* target path */
		ఒకవేళ ((r = sshpkt_put_cstring(ssh, c->మార్గం)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	} లేకపోతే ఒకవేళ (strcmp(rtype, "forwarded-streamlocal@openssh.com") == 0) {
		/* listen path */
		ఒకవేళ ((r = sshpkt_put_cstring(ssh, c->మార్గం)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	} లేకపోతే {
		/* listen address, port */
		ఒకవేళ ((r = sshpkt_put_cstring(ssh, c->మార్గం)) != 0 ||
		    (r = sshpkt_put_u32(ssh, local_పోర్టు)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	}
	ఒకవేళ (strcmp(rtype, "forwarded-streamlocal@openssh.com") == 0) {
		/* reserved for future owner/mode info */
		ఒకవేళ ((r = sshpkt_put_cstring(ssh, "")) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	} లేకపోతే {
		/* originator host and port */
		ఒకవేళ ((r = sshpkt_put_cstring(ssh, remote_ipaddr)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)remote_పోర్టు)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	}
	ఒకవేళ ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i: send", c->self);
	విడుదల(remote_ipaddr);
	విడుదల(local_ipaddr);
}

శూన్య
channel_సమితి_x11_refuse_సమయం(నిర్మాణం ssh *ssh, ద్విగుణ refuse_సమయం)
{
	ssh->chanctxt->x11_refuse_సమయం = refuse_సమయం;
}

/*
 * This socket is listening for connections to a forwarded TCP/IP port.
 */
స్థిర శూన్య
channel_post_పోర్టు_listener(నిర్మాణం ssh *ssh, Channel *c)
{
	Channel *nc;
	నిర్మాణం sockaddr_storage addr;
	పూర్ణాంకం newsock, nextstate;
	socklen_t addrlen;
	అక్షరం *rtype;

	ఒకవేళ ((c->io_ready & SSH_CHAN_IO_SOCK_R) == 0)
		తిరిగి;

	debug("Connection to port %d forwarding to %.100s port %d requested.",
	    c->listening_పోర్టు, c->మార్గం, c->host_పోర్టు);

	ఒకవేళ (c->type == SSH_CHANNEL_RPORT_LISTENER) {
		nextstate = SSH_CHANNEL_OPENING;
		rtype = "forwarded-tcpip";
	} లేకపోతే ఒకవేళ (c->type == SSH_CHANNEL_RUNIX_LISTENER) {
		nextstate = SSH_CHANNEL_OPENING;
		rtype = "forwarded-streamlocal@openssh.com";
	} లేకపోతే ఒకవేళ (c->host_పోర్టు == పోర్టు_STREAMLOCAL) {
		nextstate = SSH_CHANNEL_OPENING;
		rtype = "direct-streamlocal@openssh.com";
	} లేకపోతే ఒకవేళ (c->host_పోర్టు == 0) {
		nextstate = SSH_CHANNEL_DYNAMIC;
		rtype = "dynamic-tcpip";
	} లేకపోతే {
		nextstate = SSH_CHANNEL_OPENING;
		rtype = "direct-tcpip";
	}

	addrlen = పరిమాణం(addr);
	newsock = accept(c->sock, (నిర్మాణం sockaddr *)&addr, &addrlen);
	ఒకవేళ (newsock == -1) {
		ఒకవేళ (errno != EINTR && errno != EWOULDBLOCK &&
		    errno != ECONNABORTED)
			error("accept: %.100s", strerror(errno));
		ఒకవేళ (errno == EMFILE || errno == ENFILE)
			c->notbefore = monotime_double() + 1.0;
		తిరిగి;
	}
	ఒకవేళ (addr.ss_family == AF_INET || addr.ss_family == AF_INET6) {
		సమితి_nodelay(newsock);
		ఒకవేళ (ssh->chanctxt->want_tcp_keepalive)
			సమితి_keepalive(newsock); /* logs errors */
	}
	nc = channel_new(ssh, rtype, nextstate, newsock, newsock, -1,
	    c->local_కిటికీ_max, c->local_maxpacket, 0, rtype, 1);
	nc->listening_పోర్టు = c->listening_పోర్టు;
	nc->host_పోర్టు = c->host_పోర్టు;
	ఒకవేళ (c->మార్గం != ఖాళీ)
		nc->మార్గం = xstrdup(c->మార్గం);

	ఒకవేళ (nextstate != SSH_CHANNEL_DYNAMIC)
		పోర్టు_open_helper(ssh, nc, rtype);
}

/*
 * This is the authentication agent socket listening for connections from
 * clients.
 */
స్థిర శూన్య
channel_post_auth_listener(నిర్మాణం ssh *ssh, Channel *c)
{
	Channel *nc;
	పూర్ణాంకం r, newsock;
	నిర్మాణం sockaddr_storage addr;
	socklen_t addrlen;

	ఒకవేళ ((c->io_ready & SSH_CHAN_IO_SOCK_R) == 0)
		తిరిగి;

	addrlen = పరిమాణం(addr);
	newsock = accept(c->sock, (నిర్మాణం sockaddr *)&addr, &addrlen);
	ఒకవేళ (newsock == -1) {
		error("accept from auth socket: %.100s", strerror(errno));
		ఒకవేళ (errno == EMFILE || errno == ENFILE)
			c->notbefore = monotime_double() + 1.0;
		తిరిగి;
	}
	nc = channel_new(ssh, "agent-connection",
	    SSH_CHANNEL_OPENING, newsock, newsock, -1,
	    c->local_కిటికీ_max, c->local_maxpacket,
	    0, "accepted auth socket", 1);
	open_preamble(ssh, __func__, nc,
	    c->agent_new ? "agent-connect" : "auth-agent@openssh.com");
	ఒకవేళ ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i", c->self);
}

స్థిర శూన్య
channel_post_connecting(నిర్మాణం ssh *ssh, Channel *c)
{
	పూర్ణాంకం err = 0, sock, isopen, r;
	socklen_t sz = పరిమాణం(err);

	ఒకవేళ ((c->io_ready & SSH_CHAN_IO_SOCK_W) == 0)
		తిరిగి;
	ఒకవేళ (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);
	ఒకవేళ (c->connect_ctx == ఖాళీ)
		fatal_f("channel %d: context missing", c->self);

	/* for rdynamic the OPEN_CONFIRMATION has been sent already */
	isopen = (c->type == SSH_CHANNEL_RDYNAMIC_ముగింపు);

	ఒకవేళ (getsockopt(c->sock, SOL_SOCKET, SO_ERROR, &err, &sz) == -1) {
		err = errno;
		error("getsockopt SO_ERROR failed");
	}

	ఒకవేళ (err == 0) {
		/* Non-blocking connection completed */
		debug("channel %d: connected to %s port %d",
		    c->self, c->connect_ctx->host, c->connect_ctx->పోర్టు);
		channel_free_connect_ctx(c);
		c->type = SSH_CHANNEL_OPEN;
		channel_సమితి_వాడిన_సమయం(ssh, c);
		ఒకవేళ (isopen) {
			/* no message necessary */
		} లేకపోతే {
			ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh,
			    SSH2_సందేశం_CHANNEL_OPEN_CONFIRMATION)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_కిటికీ)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "channel %i open confirm", c->self);
		}
		తిరిగి;
	}
	ఒకవేళ (err == EINTR || err == EAGAIN || err == EINPROGRESS)
		తిరిగి;

	/* Non-blocking connection failed */
	debug("channel %d: connection failed: %s", c->self, strerror(err));

	/* Try next address, if any */
	ఒకవేళ ((sock = connect_తదుపరి(ssh, c->connect_ctx)) == -1) {
		/* Exhausted all addresses for this destination */
		error("connect_to %.100s port %d: failed.",
		    c->connect_ctx->host, c->connect_ctx->పోర్టు);
		channel_free_connect_ctx(c);
		ఒకవేళ (isopen) {
			rdynamic_close(ssh, c);
		} లేకపోతే {
			ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh,
			    SSH2_సందేశం_CHANNEL_OPEN_FAILURE)) != 0 ||
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

స్థిర పూర్ణాంకం
channel_handle_rfd(నిర్మాణం ssh *ssh, Channel *c)
{
	అక్షరం buf[CHAN_RBUF];
	ssize_t len;
	పూర్ణాంకం r, force;
	కొలత_t nr = 0, have, avail, maxlen = CHANNEL_MAX_READ;
	పూర్ణాంకం pty_zeroread = 0;

#నిర్వచితమైతే PTY_ZEROREAD
	/* Bug on AIX: read(1) can return 0 for a non-closed fd */
	pty_zeroread = c->isatty;
#అయితే_ముగింపు

	force = c->isatty && c->detach_close && c->istate != CHAN_ఆదానం_CLOSED;

	ఒకవేళ (!force && (c->io_ready & SSH_CHAN_IO_RFD) == 0)
		తిరిగి 1;
	ఒకవేళ ((avail = sshbuf_avail(c->ఆదానం)) == 0)
		తిరిగి 1; /* Shouldn't happen */

	/*
	 * For "simple" channels (i.e. not datagram or filtered), we can
	 * read directly to the channel buffer.
	 */
	ఒకవేళ (!pty_zeroread && c->ఆదానం_filter == ఖాళీ && !c->datagram) {
		/* Only OPEN channels have valid rwin */
		ఒకవేళ (c->type == SSH_CHANNEL_OPEN) {
			ఒకవేళ ((have = sshbuf_len(c->ఆదానం)) >= c->remote_కిటికీ)
				తిరిగి 1; /* shouldn't happen */
			ఒకవేళ (maxlen > c->remote_కిటికీ - have)
				maxlen = c->remote_కిటికీ - have;
		}
		ఒకవేళ (maxlen > avail)
			maxlen = avail;
		ఒకవేళ ((r = sshbuf_read(c->rfd, c->ఆదానం, maxlen, &nr)) != 0) {
			ఒకవేళ (errno == EINTR || (!force &&
			    (errno == EAGAIN || errno == EWOULDBLOCK)))
				తిరిగి 1;
			debug2("channel %d: read failed rfd %d maxlen %zu: %s",
			    c->self, c->rfd, maxlen, ssh_err(r));
			వెళ్ళు rfail;
		}
		ఒకవేళ (nr != 0)
			channel_సమితి_వాడిన_సమయం(ssh, c);
		తిరిగి 1;
	}

	errno = 0;
	len = పఠ(c->rfd, buf, పరిమాణం(buf));
	/* fixup AIX zero-length read with errno set to look more like errors */
	ఒకవేళ (pty_zeroread && len == 0 && errno != 0)
		len = -1;
	ఒకవేళ (len == -1 && (errno == EINTR ||
	    ((errno == EAGAIN || errno == EWOULDBLOCK) && !force)))
		తిరిగి 1;
	ఒకవేళ (len < 0 || (!pty_zeroread && len == 0)) {
		debug2("channel %d: read<=0 rfd %d len %zd: %s",
		    c->self, c->rfd, len,
		    len == 0 ? "closed" : strerror(errno));
 rfail:
		ఒకవేళ (c->type != SSH_CHANNEL_OPEN) {
			debug2("channel %d: not open", c->self);
			chan_mark_dead(ssh, c);
			తిరిగి -1;
		} లేకపోతే {
			chan_read_failed(ssh, c);
		}
		తిరిగి -1;
	}
	channel_సమితి_వాడిన_సమయం(ssh, c);
	ఒకవేళ (c->ఆదానం_filter != ఖాళీ) {
		ఒకవేళ (c->ఆదానం_filter(ssh, c, buf, len) == -1) {
			debug2("channel %d: filter stops", c->self);
			chan_read_failed(ssh, c);
		}
	} లేకపోతే ఒకవేళ (c->datagram) {
		ఒకవేళ ((r = sshbuf_put_string(c->ఆదానం, buf, len)) != 0)
			fatal_fr(r, "channel %i: put datagram", c->self);
	} లేకపోతే ఒకవేళ ((r = sshbuf_put(c->ఆదానం, buf, len)) != 0)
		fatal_fr(r, "channel %i: put data", c->self);

	తిరిగి 1;
}

స్థిర పూర్ణాంకం
channel_handle_wfd(నిర్మాణం ssh *ssh, Channel *c)
{
	నిర్మాణం termios tio;
	u_char *దత్తాంశం = ఖాళీ, *buf; /* XXX const; need filter API change */
	కొలత_t dlen, olen = 0;
	పూర్ణాంకం r, len;

	ఒకవేళ ((c->io_ready & SSH_CHAN_IO_WFD) == 0)
		తిరిగి 1;
	ఒకవేళ (sshbuf_len(c->output) == 0)
		తిరిగి 1;

	/* Send buffered output data to the socket. */
	olen = sshbuf_len(c->output);
	ఒకవేళ (c->output_filter != ఖాళీ) {
		ఒకవేళ ((buf = c->output_filter(ssh, c, &దత్తాంశం, &dlen)) == ఖాళీ) {
			debug2("channel %d: filter stops", c->self);
			ఒకవేళ (c->type != SSH_CHANNEL_OPEN)
				chan_mark_dead(ssh, c);
			లేకపోతే
				chan_write_failed(ssh, c);
			తిరిగి -1;
		}
	} లేకపోతే ఒకవేళ (c->datagram) {
		ఒకవేళ ((r = sshbuf_get_string(c->output, &దత్తాంశం, &dlen)) != 0)
			fatal_fr(r, "channel %i: get datagram", c->self);
		buf = దత్తాంశం;
	} లేకపోతే {
		buf = దత్తాంశం = sshbuf_mutable_ptr(c->output);
		dlen = sshbuf_len(c->output);
	}

	ఒకవేళ (c->datagram) {
		/* ignore truncated writes, datagrams might get lost */
		len = లిఖ(c->wfd, buf, dlen);
		విడుదల(దత్తాంశం);
		ఒకవేళ (len == -1 && (errno == EINTR || errno == EAGAIN ||
		    errno == EWOULDBLOCK))
			తిరిగి 1;
		ఒకవేళ (len <= 0)
			వెళ్ళు write_fail;
		వెళ్ళు బహిర్గతం;
	}

#నిర్వచితమైతే _AIX
	/* XXX: Later AIX versions can't push as much data to tty */
	ఒకవేళ (c->wfd_isatty)
		dlen = MINIMUM(dlen, 8*1024);
#అయితే_ముగింపు

	len = లిఖ(c->wfd, buf, dlen);
	ఒకవేళ (len == -1 &&
	    (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
		తిరిగి 1;
	ఒకవేళ (len <= 0) {
 write_fail:
		ఒకవేళ (c->type != SSH_CHANNEL_OPEN) {
			debug2("channel %d: not open", c->self);
			chan_mark_dead(ssh, c);
			తిరిగి -1;
		} లేకపోతే {
			chan_write_failed(ssh, c);
		}
		తిరిగి -1;
	}
	channel_సమితి_వాడిన_సమయం(ssh, c);
#నిర్వచితం_కాకపోతే BROKEN_TCGETATTR_ICANON
	ఒకవేళ (c->isatty && dlen >= 1 && buf[0] != '\r') {
		ఒకవేళ (tcgetattr(c->wfd, &tio) == 0 &&
		    !(tio.c_lflag & ECHO) && (tio.c_lflag & ICANON)) {
			/*
			 * Simulate echo to reduce the impact of
			 * traffic analysis. We need to match the
			 * size of a SSH2_MSG_CHANNEL_DATA message
			 * (4 byte channel id + buf)
			 */
			ఒకవేళ ((r = sshpkt_సందేశం_ignore(ssh, 4+len)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "channel %i: ignore", c->self);
		}
	}
#అయితే_ముగింపు /* BROKEN_TCGETATTR_ICANON */
	ఒకవేళ ((r = sshbuf_consume(c->output, len)) != 0)
		fatal_fr(r, "channel %i: consume", c->self);
 బహిర్గతం:
	c->local_consumed += olen - sshbuf_len(c->output);

	తిరిగి 1;
}

స్థిర పూర్ణాంకం
channel_handle_efd_write(నిర్మాణం ssh *ssh, Channel *c)
{
	పూర్ణాంకం r;
	ssize_t len;

	ఒకవేళ ((c->io_ready & SSH_CHAN_IO_EFD_W) == 0)
		తిరిగి 1;
	ఒకవేళ (sshbuf_len(c->extended) == 0)
		తిరిగి 1;

	len = లిఖ(c->efd, sshbuf_ptr(c->extended),
	    sshbuf_len(c->extended));
	debug2("channel %d: written %zd to efd %d", c->self, len, c->efd);
	ఒకవేళ (len == -1 && (errno == EINTR || errno == EAGAIN ||
	    errno == EWOULDBLOCK))
		తిరిగి 1;
	ఒకవేళ (len <= 0) {
		debug2("channel %d: closing write-efd %d", c->self, c->efd);
		channel_close_fd(ssh, c, &c->efd);
	} లేకపోతే {
		ఒకవేళ ((r = sshbuf_consume(c->extended, len)) != 0)
			fatal_fr(r, "channel %i: consume", c->self);
		c->local_consumed += len;
		channel_సమితి_వాడిన_సమయం(ssh, c);
	}
	తిరిగి 1;
}

స్థిర పూర్ణాంకం
channel_handle_efd_read(నిర్మాణం ssh *ssh, Channel *c)
{
	అక్షరం buf[CHAN_RBUF];
	ssize_t len;
	పూర్ణాంకం r, force;

	force = c->isatty && c->detach_close && c->istate != CHAN_ఆదానం_CLOSED;

	ఒకవేళ (!force && (c->io_ready & SSH_CHAN_IO_EFD_R) == 0)
		తిరిగి 1;

	len = పఠ(c->efd, buf, పరిమాణం(buf));
	debug2("channel %d: read %zd from efd %d", c->self, len, c->efd);
	ఒకవేళ (len == -1 && (errno == EINTR || ((errno == EAGAIN ||
	    errno == EWOULDBLOCK) && !force)))
		తిరిగి 1;
	ఒకవేళ (len <= 0) {
		debug2("channel %d: closing read-efd %d", c->self, c->efd);
		channel_close_fd(ssh, c, &c->efd);
		తిరిగి 1;
	}
	channel_సమితి_వాడిన_సమయం(ssh, c);
	ఒకవేళ (c->extended_usage == CHAN_EXTENDED_IGNORE)
		debug3("channel %d: discard efd", c->self);
	లేకపోతే ఒకవేళ ((r = sshbuf_put(c->extended, buf, len)) != 0)
		fatal_fr(r, "channel %i: append", c->self);
	తిరిగి 1;
}

స్థిర పూర్ణాంకం
channel_handle_efd(నిర్మాణం ssh *ssh, Channel *c)
{
	ఒకవేళ (c->efd == -1)
		తిరిగి 1;

	/** XXX handle drain efd, too */

	ఒకవేళ (c->extended_usage == CHAN_EXTENDED_WRITE)
		తిరిగి channel_handle_efd_write(ssh, c);
	లేకపోతే ఒకవేళ (c->extended_usage == CHAN_EXTENDED_READ ||
	    c->extended_usage == CHAN_EXTENDED_IGNORE)
		తిరిగి channel_handle_efd_read(ssh, c);

	తిరిగి 1;
}

స్థిర పూర్ణాంకం
channel_check_కిటికీ(నిర్మాణం ssh *ssh, Channel *c)
{
	పూర్ణాంకం r;

	ఒకవేళ (c->type == SSH_CHANNEL_OPEN &&
	    !(c->flags & (CHAN_CLOSE_పంపిన|CHAN_CLOSE_RCVD)) &&
	    ((c->local_కిటికీ_max - c->local_కిటికీ >
	    c->local_maxpacket*3) ||
	    c->local_కిటికీ < c->local_కిటికీ_max/2) &&
	    c->local_consumed > 0) {
		ఒకవేళ (!c->have_remote_id)
			fatal_f("channel %d: no remote id", c->self);
		ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh,
		    SSH2_సందేశం_CHANNEL_కిటికీ_ADJUST)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->local_consumed)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0) {
			fatal_fr(r, "channel %i", c->self);
		}
		debug2("channel %d: window %d sent adjust %d", c->self,
		    c->local_కిటికీ, c->local_consumed);
		c->local_కిటికీ += c->local_consumed;
		c->local_consumed = 0;
	}
	తిరిగి 1;
}

స్థిర శూన్య
channel_post_open(నిర్మాణం ssh *ssh, Channel *c)
{
	channel_handle_rfd(ssh, c);
	channel_handle_wfd(ssh, c);
	channel_handle_efd(ssh, c);
	channel_check_కిటికీ(ssh, c);
}

స్థిర u_int
read_mux(నిర్మాణం ssh *ssh, Channel *c, u_int need)
{
	అక్షరం buf[CHAN_RBUF];
	ssize_t len;
	u_int rlen;
	పూర్ణాంకం r;

	ఒకవేళ (sshbuf_len(c->ఆదానం) < need) {
		rlen = need - sshbuf_len(c->ఆదానం);
		len = పఠ(c->rfd, buf, MINIMUM(rlen, CHAN_RBUF));
		ఒకవేళ (len == -1 && (errno == EINTR || errno == EAGAIN))
			తిరిగి sshbuf_len(c->ఆదానం);
		ఒకవేళ (len <= 0) {
			debug2("channel %d: ctl read<=0 rfd %d len %zd",
			    c->self, c->rfd, len);
			chan_read_failed(ssh, c);
			తిరిగి 0;
		} లేకపోతే ఒకవేళ ((r = sshbuf_put(c->ఆదానం, buf, len)) != 0)
			fatal_fr(r, "channel %i: append", c->self);
	}
	తిరిగి sshbuf_len(c->ఆదానం);
}

స్థిర శూన్య
channel_post_mux_client_read(నిర్మాణం ssh *ssh, Channel *c)
{
	u_int need;

	ఒకవేళ ((c->io_ready & SSH_CHAN_IO_RFD) == 0)
		తిరిగి;
	ఒకవేళ (c->istate != CHAN_ఆదానం_OPEN && c->istate != CHAN_ఆదానం_WAIT_DRAIN)
		తిరిగి;
	ఒకవేళ (c->mux_pause)
		తిరిగి;

	/*
	 * Don't not read past the precise end of packets to
	 * avoid disrupting fd passing.
	 */
	ఒకవేళ (read_mux(ssh, c, 4) < 4) /* read header */
		తిరిగి;
	/* XXX sshbuf_peek_u32 */
	need = PEEK_U32(sshbuf_ptr(c->ఆదానం));
#నిర్వచించు CHANNEL_MUX_MAX_PACKET	(256 * 1024)
	ఒకవేళ (need > CHANNEL_MUX_MAX_PACKET) {
		debug2("channel %d: packet too big %u > %u",
		    c->self, CHANNEL_MUX_MAX_PACKET, need);
		chan_rcvd_oclose(ssh, c);
		తిరిగి;
	}
	ఒకవేళ (read_mux(ssh, c, need + 4) < need + 4) /* read body */
		తిరిగి;
	ఒకవేళ (c->mux_rcb(ssh, c) != 0) {
		debug("channel %d: mux_rcb failed", c->self);
		chan_mark_dead(ssh, c);
		తిరిగి;
	}
}

స్థిర శూన్య
channel_post_mux_client_write(నిర్మాణం ssh *ssh, Channel *c)
{
	ssize_t len;
	పూర్ణాంకం r;

	ఒకవేళ ((c->io_ready & SSH_CHAN_IO_WFD) == 0)
		తిరిగి;
	ఒకవేళ (sshbuf_len(c->output) == 0)
		తిరిగి;

	len = లిఖ(c->wfd, sshbuf_ptr(c->output), sshbuf_len(c->output));
	ఒకవేళ (len == -1 && (errno == EINTR || errno == EAGAIN))
		తిరిగి;
	ఒకవేళ (len <= 0) {
		chan_mark_dead(ssh, c);
		తిరిగి;
	}
	ఒకవేళ ((r = sshbuf_consume(c->output, len)) != 0)
		fatal_fr(r, "channel %i: consume", c->self);
}

స్థిర శూన్య
channel_post_mux_client(నిర్మాణం ssh *ssh, Channel *c)
{
	channel_post_mux_client_read(ssh, c);
	channel_post_mux_client_write(ssh, c);
}

స్థిర శూన్య
channel_post_mux_listener(నిర్మాణం ssh *ssh, Channel *c)
{
	Channel *nc;
	నిర్మాణం sockaddr_storage addr;
	socklen_t addrlen;
	పూర్ణాంకం newsock;
	uid_t euid;
	gid_t egid;

	ఒకవేళ ((c->io_ready & SSH_CHAN_IO_SOCK_R) == 0)
		తిరిగి;

	debug("multiplexing control connection");

	/*
	 * Accept connection on control socket
	 */
	memset(&addr, 0, పరిమాణం(addr));
	addrlen = పరిమాణం(addr);
	ఒకవేళ ((newsock = accept(c->sock, (నిర్మాణం sockaddr*)&addr,
	    &addrlen)) == -1) {
		error_f("accept: %s", strerror(errno));
		ఒకవేళ (errno == EMFILE || errno == ENFILE)
			c->notbefore = monotime_double() + 1.0;
		తిరిగి;
	}

	ఒకవేళ (getpeereid(newsock, &euid, &egid) == -1) {
		error_f("getpeereid failed: %s", strerror(errno));
		close(newsock);
		తిరిగి;
	}
	ఒకవేళ ((euid != 0) && (getuid() != euid)) {
		error("multiplex uid mismatch: peer euid %u != uid %u",
		    (u_int)euid, (u_int)getuid());
		close(newsock);
		తిరిగి;
	}
	nc = channel_new(ssh, "mux-control", SSH_CHANNEL_MUX_CLIENT,
	    newsock, newsock, -1, c->local_కిటికీ_max,
	    c->local_maxpacket, 0, "mux-control", 1);
	nc->mux_rcb = c->mux_rcb;
	debug3_f("new mux channel %d fd %d", nc->self, nc->sock);
	/* establish state */
	nc->mux_rcb(ssh, nc);
	/* mux state transitions must not elicit protocol messages */
	nc->flags |= CHAN_LOCAL;
}

స్థిర శూన్య
channel_handler_init(నిర్మాణం ssh_channels *sc)
{
	chan_fn **pre, **post;

	ఒకవేళ ((pre = సున్నా_జ్ఞాపకం_ఇవ్వు(SSH_CHANNEL_MAX_TYPE, పరిమాణం(*pre))) == ఖాళీ ||
	    (post = సున్నా_జ్ఞాపకం_ఇవ్వు(SSH_CHANNEL_MAX_TYPE, పరిమాణం(*post))) == ఖాళీ)
		fatal_f("allocation failed");

	pre[SSH_CHANNEL_OPEN] =			&channel_pre_open;
	pre[SSH_CHANNEL_X11_OPEN] =		&channel_pre_x11_open;
	pre[SSH_CHANNEL_పోర్టు_LISTENER] =	&channel_pre_listener;
	pre[SSH_CHANNEL_RPORT_LISTENER] =	&channel_pre_listener;
	pre[SSH_CHANNEL_UNIX_LISTENER] =	&channel_pre_listener;
	pre[SSH_CHANNEL_RUNIX_LISTENER] =	&channel_pre_listener;
	pre[SSH_CHANNEL_X11_LISTENER] =		&channel_pre_listener;
	pre[SSH_CHANNEL_AUTH_SOCKET] =		&channel_pre_listener;
	pre[SSH_CHANNEL_CONNECTING] =		&channel_pre_connecting;
	pre[SSH_CHANNEL_DYNAMIC] =		&channel_pre_dynamic;
	pre[SSH_CHANNEL_RDYNAMIC_ముగింపు] =	&channel_pre_connecting;
	pre[SSH_CHANNEL_MUX_LISTENER] =		&channel_pre_listener;
	pre[SSH_CHANNEL_MUX_CLIENT] =		&channel_pre_mux_client;

	post[SSH_CHANNEL_OPEN] =		&channel_post_open;
	post[SSH_CHANNEL_పోర్టు_LISTENER] =	&channel_post_పోర్టు_listener;
	post[SSH_CHANNEL_RPORT_LISTENER] =	&channel_post_పోర్టు_listener;
	post[SSH_CHANNEL_UNIX_LISTENER] =	&channel_post_పోర్టు_listener;
	post[SSH_CHANNEL_RUNIX_LISTENER] =	&channel_post_పోర్టు_listener;
	post[SSH_CHANNEL_X11_LISTENER] =	&channel_post_x11_listener;
	post[SSH_CHANNEL_AUTH_SOCKET] =		&channel_post_auth_listener;
	post[SSH_CHANNEL_CONNECTING] =		&channel_post_connecting;
	post[SSH_CHANNEL_DYNAMIC] =		&channel_post_open;
	post[SSH_CHANNEL_RDYNAMIC_ముగింపు] =	&channel_post_connecting;
	post[SSH_CHANNEL_MUX_LISTENER] =	&channel_post_mux_listener;
	post[SSH_CHANNEL_MUX_CLIENT] =		&channel_post_mux_client;

	sc->channel_pre = pre;
	sc->channel_post = post;
}

/* gc dead channels */
స్థిర శూన్య
channel_garbage_collect(నిర్మాణం ssh *ssh, Channel *c)
{
	ఒకవేళ (c == ఖాళీ)
		తిరిగి;
	ఒకవేళ (c->detach_user != ఖాళీ) {
		ఒకవేళ (!chan_is_dead(ssh, c, c->detach_close))
			తిరిగి;

		debug2("channel %d: gc: notify user", c->self);
		c->detach_user(ssh, c->self, 0, ఖాళీ);
		/* if we still have a callback */
		ఒకవేళ (c->detach_user != ఖాళీ)
			తిరిగి;
		debug2("channel %d: gc: user detached", c->self);
	}
	ఒకవేళ (!chan_is_dead(ssh, c, 1))
		తిరిగి;
	debug2("channel %d: garbage collecting", c->self);
	channel_free(ssh, c);
}

గణన channel_పట్టిక { CHAN_PRE, CHAN_POST };

స్థిర శూన్య
channel_handler(నిర్మాణం ssh *ssh, పూర్ణాంకం పట్టిక, నిర్మాణం timespec *timeout)
{
	నిర్మాణం ssh_channels *sc = ssh->chanctxt;
	chan_fn **ftab = పట్టిక == CHAN_PRE ? sc->channel_pre : sc->channel_post;
	u_int i, oalloc;
	Channel *c;
	ద్విగుణ now;

	now = monotime_double();
	కొరకు (sc->nbulk = i = 0, oalloc = sc->channels_alloc; i < oalloc; i++) {
		c = sc->channels[i];
		ఒకవేళ (c == ఖాళీ)
			కొనసాగు;
		/* Count open channels in bulk state */
		ఒకవేళ (c->type == SSH_CHANNEL_OPEN && c->bulk)
			sc->nbulk++;
		/* Try to keep IO going while rekeying */
		ఒకవేళ (ssh_packet_is_rekeying(ssh) && c->type != SSH_CHANNEL_OPEN)
			కొనసాగు;
		ఒకవేళ (c->delayed) {
			ఒకవేళ (పట్టిక == CHAN_PRE)
				c->delayed = 0;
			లేకపోతే
				కొనసాగు;
		}
		ఒకవేళ (ftab[c->type] != ఖాళీ) {
			ఒకవేళ (పట్టిక == CHAN_PRE && c->type == SSH_CHANNEL_OPEN &&
			    channel_get_expiry(ssh, c) != 0 &&
			    now >= channel_get_expiry(ssh, c)) {
				/* channel closed for inactivity */
				ద్విగుణ deadline = c->inactive_deadline != 0.0 ?
				    c->inactive_deadline : sc->global_deadline;
				verbose("channel %d: closing after %f seconds "
				    "of inactivity", c->self, deadline);
				channel_force_close(ssh, c, 1);
			} లేకపోతే ఒకవేళ (c->notbefore <= now) {
				/* Run handlers that are not paused. */
				(*ftab[c->type])(ssh, c);
				/* inactivity timeouts must interrupt poll() */
				ఒకవేళ (timeout != ఖాళీ &&
				    c->type == SSH_CHANNEL_OPEN &&
				    channel_get_expiry(ssh, c) != 0) {
					ptimeout_deadline_monotime_double(timeout,
					    channel_get_expiry(ssh, c));
				}
			} లేకపోతే ఒకవేళ (timeout != ఖాళీ) {
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
స్థిర శూన్య
channel_before_prepare_io(నిర్మాణం ssh *ssh)
{
	నిర్మాణం ssh_channels *sc = ssh->chanctxt;
	Channel *c;
	u_int i, oalloc;

	కొరకు (i = 0, oalloc = sc->channels_alloc; i < oalloc; i++) {
		c = sc->channels[i];
		ఒకవేళ (c == ఖాళీ)
			కొనసాగు;
		ఒకవేళ (c->type == SSH_CHANNEL_RDYNAMIC_OPEN)
			channel_before_prepare_io_rdynamic(ssh, c);
	}
}

స్థిర శూన్య
dump_channel_poll(స్థిరరాశి అక్షరం *func, స్థిరరాశి అక్షరం *what, Channel *c,
    u_int pollfd_స్థానభ్రంశం, నిర్మాణం pollfd *pfd)
{
#నిర్వచితమైతే DEBUG_CHANNEL_POLL
	debug3("%s: channel %d: %s r%d w%d e%d s%d c->pfds [ %d %d %d %d ] "
	    "io_want 0x%02x io_ready 0x%02x pfd[%u].fd=%d "
	    "pfd.ev 0x%02x pfd.rev 0x%02x", func, c->self, what,
	    c->rfd, c->wfd, c->efd, c->sock,
	    c->pfds[0], c->pfds[1], c->pfds[2], c->pfds[3],
	    c->io_want, c->io_ready,
	    pollfd_స్థానభ్రంశం, pfd->fd, pfd->events, pfd->revents);
#అయితే_ముగింపు
}

/* Prepare pollfd entries for a single channel */
స్థిర శూన్య
channel_prepare_pollfd(Channel *c, u_int *తదుపరి_pollfd,
    నిర్మాణం pollfd *pfd, u_int npfd)
{
	u_int ev, p = *తదుపరి_pollfd;

	ఒకవేళ (c == ఖాళీ)
		తిరిగి;
	ఒకవేళ (p + 4 > npfd) {
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
	ఒకవేళ (c->rfd != -1) {
		ev = 0;
		ఒకవేళ ((c->io_want & SSH_CHAN_IO_RFD) != 0)
			ev |= POLLIN;
		/* rfd == wfd */
		ఒకవేళ (c->wfd == c->rfd) {
			ఒకవేళ ((c->io_want & SSH_CHAN_IO_WFD) != 0)
				ev |= POLLOUT;
		}
		/* rfd == efd */
		ఒకవేళ (c->efd == c->rfd) {
			ఒకవేళ ((c->io_want & SSH_CHAN_IO_EFD_R) != 0)
				ev |= POLLIN;
			ఒకవేళ ((c->io_want & SSH_CHAN_IO_EFD_W) != 0)
				ev |= POLLOUT;
		}
		/* rfd == sock */
		ఒకవేళ (c->sock == c->rfd) {
			ఒకవేళ ((c->io_want & SSH_CHAN_IO_SOCK_R) != 0)
				ev |= POLLIN;
			ఒకవేళ ((c->io_want & SSH_CHAN_IO_SOCK_W) != 0)
				ev |= POLLOUT;
		}
		/* Pack a pfd entry if any event armed for this fd */
		ఒకవేళ (ev != 0) {
			c->pfds[0] = p;
			pfd[p].fd = c->rfd;
			pfd[p].events = ev;
			dump_channel_poll(__func__, "rfd", c, p, &pfd[p]);
			p++;
		}
	}
	/* prepare c->wfd if wanting IO and not already handled above */
	ఒకవేళ (c->wfd != -1 && c->rfd != c->wfd) {
		ev = 0;
		ఒకవేళ ((c->io_want & SSH_CHAN_IO_WFD))
			ev |= POLLOUT;
		/* Pack a pfd entry if any event armed for this fd */
		ఒకవేళ (ev != 0) {
			c->pfds[1] = p;
			pfd[p].fd = c->wfd;
			pfd[p].events = ev;
			dump_channel_poll(__func__, "wfd", c, p, &pfd[p]);
			p++;
		}
	}
	/* prepare c->efd if wanting IO and not already handled above */
	ఒకవేళ (c->efd != -1 && c->rfd != c->efd) {
		ev = 0;
		ఒకవేళ ((c->io_want & SSH_CHAN_IO_EFD_R) != 0)
			ev |= POLLIN;
		ఒకవేళ ((c->io_want & SSH_CHAN_IO_EFD_W) != 0)
			ev |= POLLOUT;
		/* Pack a pfd entry if any event armed for this fd */
		ఒకవేళ (ev != 0) {
			c->pfds[2] = p;
			pfd[p].fd = c->efd;
			pfd[p].events = ev;
			dump_channel_poll(__func__, "efd", c, p, &pfd[p]);
			p++;
		}
	}
	/* prepare c->sock if wanting IO and not already handled above */
	ఒకవేళ (c->sock != -1 && c->rfd != c->sock) {
		ev = 0;
		ఒకవేళ ((c->io_want & SSH_CHAN_IO_SOCK_R) != 0)
			ev |= POLLIN;
		ఒకవేళ ((c->io_want & SSH_CHAN_IO_SOCK_W) != 0)
			ev |= POLLOUT;
		/* Pack a pfd entry if any event armed for this fd */
		ఒకవేళ (ev != 0) {
			c->pfds[3] = p;
			pfd[p].fd = c->sock;
			pfd[p].events = ev;
			dump_channel_poll(__func__, "sock", c, p, &pfd[p]);
			p++;
		}
	}
	*తదుపరి_pollfd = p;
}

/* * Allocate/prepare poll structure */
శూన్య
channel_prepare_poll(నిర్మాణం ssh *ssh, నిర్మాణం pollfd **pfdp, u_int *npfd_allocp,
    u_int *npfd_activep, u_int npfd_reserved, నిర్మాణం timespec *timeout)
{
	నిర్మాణం ssh_channels *sc = ssh->chanctxt;
	u_int i, oalloc, p, npfd = npfd_reserved;

	channel_before_prepare_io(ssh); /* might create a new channel */
	/* clear out I/O flags from last poll */
	కొరకు (i = 0; i < sc->channels_alloc; i++) {
		ఒకవేళ (sc->channels[i] == ఖాళీ)
			కొనసాగు;
		sc->channels[i]->io_want = sc->channels[i]->io_ready = 0;
	}
	/* Allocate 4x pollfd for each channel (rfd, wfd, efd, sock) */
	ఒకవేళ (sc->channels_alloc >= (గరిష్ఠ_పూర్ణాంకం / 4) - npfd_reserved)
		fatal_f("too many channels"); /* shouldn't happen */
	npfd += sc->channels_alloc * 4;
	ఒకవేళ (npfd > *npfd_allocp) {
		*pfdp = xrecallocarray(*pfdp, *npfd_allocp,
		    npfd, పరిమాణం(**pfdp));
		*npfd_allocp = npfd;
	}
	*npfd_activep = npfd_reserved;
	oalloc = sc->channels_alloc;

	channel_handler(ssh, CHAN_PRE, timeout);

	ఒకవేళ (oalloc != sc->channels_alloc) {
		/* shouldn't happen */
		fatal_f("channels_alloc changed during CHAN_PRE "
		    "(was %u, now %u)", oalloc, sc->channels_alloc);
	}

	/* Prepare pollfd */
	p = npfd_reserved;
	కొరకు (i = 0; i < sc->channels_alloc; i++)
		channel_prepare_pollfd(sc->channels[i], &p, *pfdp, npfd);
	*npfd_activep = p;
}

స్థిర శూన్య
fd_ready(Channel *c, పూర్ణాంకం p, నిర్మాణం pollfd *pfds, u_int npfd, పూర్ణాంకం fd,
    స్థిరరాశి అక్షరం *what, u_int revents_ముసుగు, u_int ready)
{
	నిర్మాణం pollfd *pfd = &pfds[p];

	ఒకవేళ (fd == -1)
		తిరిగి;
	ఒకవేళ (p == -1 || (u_int)p >= npfd)
		fatal_f("channel %d: bad pfd %d (max %u)", c->self, p, npfd);
	dump_channel_poll(__func__, what, c, p, pfd);
	ఒకవేళ (pfd->fd != fd) {
		fatal("channel %d: inconsistent %s fd=%d pollfd[%u].fd %d "
		    "r%d w%d e%d s%d", c->self, what, fd, p, pfd->fd,
		    c->rfd, c->wfd, c->efd, c->sock);
	}
	ఒకవేళ ((pfd->revents & POLLNVAL) != 0) {
		fatal("channel %d: invalid %s pollfd[%u].fd %d r%d w%d e%d s%d",
		    c->self, what, p, pfd->fd, c->rfd, c->wfd, c->efd, c->sock);
	}
	ఒకవేళ ((pfd->revents & (revents_ముసుగు|POLLHUP|POLLERR)) != 0)
		c->io_ready |= ready & c->io_want;
}

/*
 * After poll, perform any appropriate operations for channels which have
 * events pending.
 */
శూన్య
channel_after_poll(నిర్మాణం ssh *ssh, నిర్మాణం pollfd *pfd, u_int npfd)
{
	నిర్మాణం ssh_channels *sc = ssh->chanctxt;
	u_int i;
	పూర్ణాంకం p;
	Channel *c;

#నిర్వచితమైతే DEBUG_CHANNEL_POLL
	కొరకు (p = 0; p < (పూర్ణాంకం)npfd; p++) {
		ఒకవేళ (pfd[p].revents == 0)
			కొనసాగు;
		debug_f("pfd[%u].fd %d rev 0x%04x",
		    p, pfd[p].fd, pfd[p].revents);
	}
#అయితే_ముగింపు

	/* Convert pollfd into c->io_ready */
	కొరకు (i = 0; i < sc->channels_alloc; i++) {
		c = sc->channels[i];
		ఒకవేళ (c == ఖాళీ)
			కొనసాగు;
		/* if rfd is shared with efd/sock then wfd should be too */
		ఒకవేళ (c->rfd != -1 && c->wfd != -1 && c->rfd != c->wfd &&
		    (c->rfd == c->efd || c->rfd == c->sock)) {
			/* Shouldn't happen */
			fatal_f("channel %d: unexpected fds r%d w%d e%d s%d",
			    c->self, c->rfd, c->wfd, c->efd, c->sock);
		}
		c->io_ready = 0;
		/* rfd, potentially shared with wfd, efd and sock */
		ఒకవేళ (c->rfd != -1 && (p = c->pfds[0]) != -1) {
			fd_ready(c, p, pfd, npfd, c->rfd,
			    "rfd", POLLIN, SSH_CHAN_IO_RFD);
			ఒకవేళ (c->rfd == c->wfd) {
				fd_ready(c, p, pfd, npfd, c->wfd,
				    "wfd/r", POLLOUT, SSH_CHAN_IO_WFD);
			}
			ఒకవేళ (c->rfd == c->efd) {
				fd_ready(c, p, pfd, npfd, c->efd,
				    "efdr/r", POLLIN, SSH_CHAN_IO_EFD_R);
				fd_ready(c, p, pfd, npfd, c->efd,
				    "efdw/r", POLLOUT, SSH_CHAN_IO_EFD_W);
			}
			ఒకవేళ (c->rfd == c->sock) {
				fd_ready(c, p, pfd, npfd, c->sock,
				    "sockr/r", POLLIN, SSH_CHAN_IO_SOCK_R);
				fd_ready(c, p, pfd, npfd, c->sock,
				    "sockw/r", POLLOUT, SSH_CHAN_IO_SOCK_W);
			}
			dump_channel_poll(__func__, "rfd", c, p, pfd);
		}
		/* wfd */
		ఒకవేళ (c->wfd != -1 && c->wfd != c->rfd &&
		    (p = c->pfds[1]) != -1) {
			fd_ready(c, p, pfd, npfd, c->wfd,
			    "wfd", POLLOUT, SSH_CHAN_IO_WFD);
			dump_channel_poll(__func__, "wfd", c, p, pfd);
		}
		/* efd */
		ఒకవేళ (c->efd != -1 && c->efd != c->rfd &&
		    (p = c->pfds[2]) != -1) {
			fd_ready(c, p, pfd, npfd, c->efd,
			    "efdr", POLLIN, SSH_CHAN_IO_EFD_R);
			fd_ready(c, p, pfd, npfd, c->efd,
			    "efdw", POLLOUT, SSH_CHAN_IO_EFD_W);
			dump_channel_poll(__func__, "efd", c, p, pfd);
		}
		/* sock */
		ఒకవేళ (c->sock != -1 && c->sock != c->rfd &&
		    (p = c->pfds[3]) != -1) {
			fd_ready(c, p, pfd, npfd, c->sock,
			    "sockr", POLLIN, SSH_CHAN_IO_SOCK_R);
			fd_ready(c, p, pfd, npfd, c->sock,
			    "sockw", POLLOUT, SSH_CHAN_IO_SOCK_W);
			dump_channel_poll(__func__, "sock", c, p, pfd);
		}
	}
	channel_handler(ssh, CHAN_POST, ఖాళీ);
}

/*
 * Enqueue data for channels with open or draining c->input.
 * Returns non-zero if a packet was enqueued.
 */
స్థిర పూర్ణాంకం
channel_output_poll_ఆదానం_open(నిర్మాణం ssh *ssh, Channel *c)
{
	కొలత_t len, plen;
	స్థిరరాశి u_char *pkt;
	పూర్ణాంకం r;

	ఒకవేళ ((len = sshbuf_len(c->ఆదానం)) == 0) {
		ఒకవేళ (c->istate == CHAN_ఆదానం_WAIT_DRAIN) {
			/*
			 * input-buffer is empty and read-socket shutdown:
			 * tell peer, that we will not send more data:
			 * send IEOF.
			 * hack for extended data: delay EOF if EFD still
			 * in use.
			 */
			ఒకవేళ (CHANNEL_EFD_ఆదానం_చురుకైన(c))
				debug2("channel %d: "
				    "ibuf_empty delayed efd %d/(%zu)",
				    c->self, c->efd, sshbuf_len(c->extended));
			లేకపోతే
				chan_ibuf_ఖాళీలు(ssh, c);
		}
		తిరిగి 0;
	}

	ఒకవేళ (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);

	ఒకవేళ (c->datagram) {
		/* Check datagram will fit; drop if not */
		ఒకవేళ ((r = sshbuf_get_string_ప్రత్యక్ష(c->ఆదానం, &pkt, &plen)) != 0)
			fatal_fr(r, "channel %i: get datagram", c->self);
		/*
		 * XXX this does tail-drop on the datagram queue which is
		 * usually suboptimal compared to head-drop. Better to have
		 * backpressure at read time? (i.e. read + discard)
		 */
		ఒకవేళ (plen > c->remote_కిటికీ || plen > c->remote_maxpacket) {
			debug("channel %d: datagram too big", c->self);
			తిరిగి 0;
		}
		/* Enqueue it */
		ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh, SSH2_సందేశం_CHANNEL_దత్తాంశం)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
		    (r = sshpkt_put_string(ssh, pkt, plen)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "channel %i: send datagram", c->self);
		c->remote_కిటికీ -= plen;
		తిరిగి 1;
	}

	/* Enqueue packet for buffered data. */
	ఒకవేళ (len > c->remote_కిటికీ)
		len = c->remote_కిటికీ;
	ఒకవేళ (len > c->remote_maxpacket)
		len = c->remote_maxpacket;
	ఒకవేళ (len == 0)
		తిరిగి 0;
	ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh, SSH2_సందేశం_CHANNEL_దత్తాంశం)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_string(ssh, sshbuf_ptr(c->ఆదానం), len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i: send data", c->self);
	ఒకవేళ ((r = sshbuf_consume(c->ఆదానం, len)) != 0)
		fatal_fr(r, "channel %i: consume", c->self);
	c->remote_కిటికీ -= len;
	తిరిగి 1;
}

/*
 * Enqueue data for channels with open c->extended in read mode.
 * Returns non-zero if a packet was enqueued.
 */
స్థిర పూర్ణాంకం
channel_output_poll_extended_read(నిర్మాణం ssh *ssh, Channel *c)
{
	కొలత_t len;
	పూర్ణాంకం r;

	ఒకవేళ ((len = sshbuf_len(c->extended)) == 0)
		తిరిగి 0;

	debug2("channel %d: rwin %u elen %zu euse %d", c->self,
	    c->remote_కిటికీ, sshbuf_len(c->extended), c->extended_usage);
	ఒకవేళ (len > c->remote_కిటికీ)
		len = c->remote_కిటికీ;
	ఒకవేళ (len > c->remote_maxpacket)
		len = c->remote_maxpacket;
	ఒకవేళ (len == 0)
		తిరిగి 0;
	ఒకవేళ (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);
	ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh, SSH2_సందేశం_CHANNEL_EXTENDED_దత్తాంశం)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_u32(ssh, SSH2_EXTENDED_దత్తాంశం_STDERR)) != 0 ||
	    (r = sshpkt_put_string(ssh, sshbuf_ptr(c->extended), len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i: data", c->self);
	ఒకవేళ ((r = sshbuf_consume(c->extended, len)) != 0)
		fatal_fr(r, "channel %i: consume", c->self);
	c->remote_కిటికీ -= len;
	debug2("channel %d: sent ext data %zu", c->self, len);
	తిరిగి 1;
}

/*
 * If there is data to send to the connection, enqueue some of it now.
 * Returns non-zero if data was enqueued.
 */
పూర్ణాంకం
channel_output_poll(నిర్మాణం ssh *ssh)
{
	నిర్మాణం ssh_channels *sc = ssh->chanctxt;
	Channel *c;
	u_int i;
	పూర్ణాంకం ret = 0;

	కొరకు (i = 0; i < sc->channels_alloc; i++) {
		c = sc->channels[i];
		ఒకవేళ (c == ఖాళీ)
			కొనసాగు;

		/*
		 * We are only interested in channels that can have buffered
		 * incoming data.
		 */
		ఒకవేళ (c->type != SSH_CHANNEL_OPEN)
			కొనసాగు;
		ఒకవేళ ((c->flags & (CHAN_CLOSE_పంపిన|CHAN_CLOSE_RCVD))) {
			/* XXX is this true? */
			debug3("channel %d: will not send data after close",
			    c->self);
			కొనసాగు;
		}

		/* Get the amount of buffered data for this channel. */
		ఒకవేళ (c->istate == CHAN_ఆదానం_OPEN ||
		    c->istate == CHAN_ఆదానం_WAIT_DRAIN)
			ret |= channel_output_poll_ఆదానం_open(ssh, c);
		/* Send extended data, i.e. stderr */
		ఒకవేళ (!(c->flags & CHAN_EOF_పంపిన) &&
		    c->extended_usage == CHAN_EXTENDED_READ)
			ret |= channel_output_poll_extended_read(ssh, c);
	}
	తిరిగి ret;
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
పూర్ణాంకం
channel_proxy_downstream(నిర్మాణం ssh *ssh, Channel *downstream)
{
	Channel *c = ఖాళీ;
	నిర్మాణం sshbuf *original = ఖాళీ, *modified = ఖాళీ;
	స్థిరరాశి u_char *cp;
	అక్షరం *ctype = ఖాళీ, *listen_host = ఖాళీ;
	u_char type;
	కొలత_t have;
	పూర్ణాంకం ret = -1, r;
	u_int id, remote_id, listen_పోర్టు;

	/* sshbuf_dump(downstream->input, stderr); */
	ఒకవేళ ((r = sshbuf_get_string_ప్రత్యక్ష(downstream->ఆదానం, &cp, &have))
	    != 0) {
		error_fr(r, "parse");
		తిరిగి -1;
	}
	ఒకవేళ (have < 2) {
		error_f("short message");
		తిరిగి -1;
	}
	type = cp[1];
	/* skip padlen + type */
	cp += 2;
	have -= 2;
	ఒకవేళ (ssh_packet_log_type(type))
		debug3_f("channel %u: down->up: type %u",
		    downstream->self, type);

	ఎంపిక (type) {
	స్థితి SSH2_సందేశం_CHANNEL_OPEN:
		ఒకవేళ ((original = sshbuf_from(cp, have)) == ఖాళీ ||
		    (modified = sshbuf_new()) == ఖాళీ) {
			error_f("alloc");
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ ((r = sshbuf_get_cstring(original, &ctype, ఖాళీ)) != 0 ||
		    (r = sshbuf_get_u32(original, &id)) != 0) {
			error_fr(r, "parse");
			వెళ్ళు బహిర్గతం;
		}
		c = channel_new(ssh, "mux-proxy", SSH_CHANNEL_MUX_PROXY,
		    -1, -1, -1, 0, 0, 0, ctype, 1);
		c->mux_ctx = downstream;	/* point to mux client */
		c->mux_downstream_id = id;	/* original downstream id */
		ఒకవేళ ((r = sshbuf_put_cstring(modified, ctype)) != 0 ||
		    (r = sshbuf_put_u32(modified, c->self)) != 0 ||
		    (r = sshbuf_putb(modified, original)) != 0) {
			error_fr(r, "compose");
			channel_free(ssh, c);
			వెళ్ళు బహిర్గతం;
		}
		ఆపు;
	స్థితి SSH2_సందేశం_CHANNEL_OPEN_CONFIRMATION:
		/*
		 * Almost the same as SSH2_MSG_CHANNEL_OPEN, except then we
		 * need to parse 'remote_id' instead of 'ctype'.
		 */
		ఒకవేళ ((original = sshbuf_from(cp, have)) == ఖాళీ ||
		    (modified = sshbuf_new()) == ఖాళీ) {
			error_f("alloc");
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ ((r = sshbuf_get_u32(original, &remote_id)) != 0 ||
		    (r = sshbuf_get_u32(original, &id)) != 0) {
			error_fr(r, "parse");
			వెళ్ళు బహిర్గతం;
		}
		c = channel_new(ssh, "mux-proxy", SSH_CHANNEL_MUX_PROXY,
		    -1, -1, -1, 0, 0, 0, "mux-down-connect", 1);
		c->mux_ctx = downstream;	/* point to mux client */
		c->mux_downstream_id = id;
		c->remote_id = remote_id;
		c->have_remote_id = 1;
		ఒకవేళ ((r = sshbuf_put_u32(modified, remote_id)) != 0 ||
		    (r = sshbuf_put_u32(modified, c->self)) != 0 ||
		    (r = sshbuf_putb(modified, original)) != 0) {
			error_fr(r, "compose");
			channel_free(ssh, c);
			వెళ్ళు బహిర్గతం;
		}
		ఆపు;
	స్థితి SSH2_సందేశం_GLOBAL_REQUEST:
		ఒకవేళ ((original = sshbuf_from(cp, have)) == ఖాళీ) {
			error_f("alloc");
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ ((r = sshbuf_get_cstring(original, &ctype, ఖాళీ)) != 0) {
			error_fr(r, "parse");
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ (strcmp(ctype, "tcpip-forward") != 0) {
			error_f("unsupported request %s", ctype);
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ ((r = sshbuf_get_u8(original, ఖాళీ)) != 0 ||
		    (r = sshbuf_get_cstring(original, &listen_host, ఖాళీ)) != 0 ||
		    (r = sshbuf_get_u32(original, &listen_పోర్టు)) != 0) {
			error_fr(r, "parse");
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ (listen_పోర్టు > 65535) {
			error_f("tcpip-forward for %s: bad port %u",
			    listen_host, listen_పోర్టు);
			వెళ్ళు బహిర్గతం;
		}
		/* Record that connection to this host/port is permitted. */
		permission_సమితి_కూడు(ssh, FORWARD_USER, FORWARD_LOCAL, "<mux>",
		    -1, listen_host, ఖాళీ, (పూర్ణాంకం)listen_పోర్టు, downstream);
		ఆపు;
	స్థితి SSH2_సందేశం_CHANNEL_CLOSE:
		ఒకవేళ (have < 4)
			ఆపు;
		remote_id = PEEK_U32(cp);
		ఒకవేళ ((c = channel_by_remote_id(ssh, remote_id)) != ఖాళీ) {
			ఒకవేళ (c->flags & CHAN_CLOSE_RCVD)
				channel_free(ssh, c);
			లేకపోతే
				c->flags |= CHAN_CLOSE_పంపిన;
		}
		ఆపు;
	}
	ఒకవేళ (modified) {
		ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh, type)) != 0 ||
		    (r = sshpkt_putb(ssh, modified)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0) {
			error_fr(r, "send");
			వెళ్ళు బహిర్గతం;
		}
	} లేకపోతే {
		ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh, type)) != 0 ||
		    (r = sshpkt_put(ssh, cp, have)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0) {
			error_fr(r, "send");
			వెళ్ళు బహిర్గతం;
		}
	}
	ret = 0;
 బహిర్గతం:
	విడుదల(ctype);
	విడుదల(listen_host);
	sshbuf_free(original);
	sshbuf_free(modified);
	తిరిగి ret;
}

/*
 * receive packets from upstream server and de-multiplex packets
 * to correct downstream:
 * implemented as a helper for channel input handlers,
 * replaces local (proxy) channel ID with downstream channel ID.
 */
పూర్ణాంకం
channel_proxy_upstream(Channel *c, పూర్ణాంకం type, uint32_t seq, నిర్మాణం ssh *ssh)
{
	నిర్మాణం sshbuf *b = ఖాళీ;
	Channel *downstream;
	స్థిరరాశి u_char *cp = ఖాళీ;
	కొలత_t len;
	పూర్ణాంకం r;

	/*
	 * When receiving packets from the peer we need to check whether we
	 * need to forward the packets to the mux client. In this case we
	 * restore the original channel id and keep track of CLOSE messages,
	 * so we can cleanup the channel.
	 */
	ఒకవేళ (c == ఖాళీ || c->type != SSH_CHANNEL_MUX_PROXY)
		తిరిగి 0;
	ఒకవేళ ((downstream = c->mux_ctx) == ఖాళీ)
		తిరిగి 0;
	ఎంపిక (type) {
	స్థితి SSH2_సందేశం_CHANNEL_CLOSE:
	స్థితి SSH2_సందేశం_CHANNEL_దత్తాంశం:
	స్థితి SSH2_సందేశం_CHANNEL_EOF:
	స్థితి SSH2_సందేశం_CHANNEL_EXTENDED_దత్తాంశం:
	స్థితి SSH2_సందేశం_CHANNEL_OPEN_CONFIRMATION:
	స్థితి SSH2_సందేశం_CHANNEL_OPEN_FAILURE:
	స్థితి SSH2_సందేశం_CHANNEL_కిటికీ_ADJUST:
	స్థితి SSH2_సందేశం_CHANNEL_SUCCESS:
	స్థితి SSH2_సందేశం_CHANNEL_FAILURE:
	స్థితి SSH2_సందేశం_CHANNEL_REQUEST:
		ఆపు;
	అప్రమేయ:
		debug2_f("channel %u: unsupported type %u", c->self, type);
		తిరిగి 0;
	}
	ఒకవేళ ((b = sshbuf_new()) == ఖాళీ) {
		error_f("alloc reply");
		వెళ్ళు బహిర్గతం;
	}
	/* get remaining payload (after id) */
	cp = sshpkt_ptr(ssh, &len);
	ఒకవేళ (cp == ఖాళీ) {
		error_f("no packet");
		వెళ్ళు బహిర్గతం;
	}
	/* translate id and send to muxclient */
	ఒకవేళ ((r = sshbuf_put_u8(b, 0)) != 0 ||	/* padlen */
	    (r = sshbuf_put_u8(b, type)) != 0 ||
	    (r = sshbuf_put_u32(b, c->mux_downstream_id)) != 0 ||
	    (r = sshbuf_put(b, cp, len)) != 0 ||
	    (r = sshbuf_put_stringb(downstream->output, b)) != 0) {
		error_fr(r, "compose muxclient");
		వెళ్ళు బహిర్గతం;
	}
	/* sshbuf_dump(b, stderr); */
	ఒకవేళ (ssh_packet_log_type(type))
		debug3_f("channel %u: up->down: type %u", c->self, type);
 బహిర్గతం:
	/* update state */
	ఎంపిక (type) {
	స్థితి SSH2_సందేశం_CHANNEL_OPEN_CONFIRMATION:
		/* record remote_id for SSH2_MSG_CHANNEL_CLOSE */
		ఒకవేళ (cp && len > 4) {
			c->remote_id = PEEK_U32(cp);
			c->have_remote_id = 1;
		}
		ఆపు;
	స్థితి SSH2_సందేశం_CHANNEL_CLOSE:
		ఒకవేళ (c->flags & CHAN_CLOSE_పంపిన)
			channel_free(ssh, c);
		లేకపోతే
			c->flags |= CHAN_CLOSE_RCVD;
		ఆపు;
	}
	sshbuf_free(b);
	తిరిగి 1;
}

/* -- protocol input */

/* Parse a channel ID from the current packet */
స్థిర పూర్ణాంకం
channel_parse_id(నిర్మాణం ssh *ssh, స్థిరరాశి అక్షరం *where, స్థిరరాశి అక్షరం *what)
{
	uint32_t id;
	పూర్ణాంకం r;

	ఒకవేళ ((r = sshpkt_get_u32(ssh, &id)) != 0) {
		error_r(r, "%s: parse id", where);
		ssh_packet_disconnect(ssh, "Invalid %s message", what);
	}
	ఒకవేళ (id > గరిష్ఠ_పూర్ణాంకం) {
		error_r(r, "%s: bad channel id %u", where, id);
		ssh_packet_disconnect(ssh, "Invalid %s channel id", what);
	}
	తిరిగి (పూర్ణాంకం)id;
}

/* Lookup a channel from an ID in the current packet */
స్థిర Channel *
channel_from_packet_id(నిర్మాణం ssh *ssh, స్థిరరాశి అక్షరం *where, స్థిరరాశి అక్షరం *what)
{
	పూర్ణాంకం id = channel_parse_id(ssh, where, what);
	Channel *c;

	ఒకవేళ ((c = channel_lookup(ssh, id)) == ఖాళీ) {
		ssh_packet_disconnect(ssh,
		    "%s packet referred to nonexistent channel %d", what, id);
	}
	తిరిగి c;
}

పూర్ణాంకం
channel_ఆదానం_దత్తాంశం(పూర్ణాంకం type, uint32_t seq, నిర్మాణం ssh *ssh)
{
	స్థిరరాశి u_char *దత్తాంశం;
	కొలత_t దత్తాంశం_len, win_len;
	Channel *c = channel_from_packet_id(ssh, __func__, "data");
	పూర్ణాంకం r;

	ఒకవేళ (channel_proxy_upstream(c, type, seq, ssh))
		తిరిగి 0;

	/* Ignore any data for non-open channels (might happen on close) */
	ఒకవేళ (c->type != SSH_CHANNEL_OPEN &&
	    c->type != SSH_CHANNEL_RDYNAMIC_OPEN &&
	    c->type != SSH_CHANNEL_RDYNAMIC_ముగింపు &&
	    c->type != SSH_CHANNEL_X11_OPEN)
		తిరిగి 0;

	/* Get the data. */
	ఒకవేళ ((r = sshpkt_get_string_ప్రత్యక్ష(ssh, &దత్తాంశం, &దత్తాంశం_len)) != 0 ||
            (r = sshpkt_get_చివర(ssh)) != 0)
		fatal_fr(r, "channel %i: get data", c->self);

	win_len = దత్తాంశం_len;
	ఒకవేళ (c->datagram)
		win_len += 4;  /* string length header */

	/*
	 * The sending side reduces its window as it sends data, so we
	 * must 'fake' consumption of the data in order to ensure that window
	 * updates are sent back. Otherwise the connection might deadlock.
	 */
	ఒకవేళ (c->ostate != CHAN_OUTPUT_OPEN) {
		ఒకవేళ (win_len > c->local_కిటికీ)
			c->local_కిటికీ = 0;
		లేకపోతే
			c->local_కిటికీ -= win_len;
		c->local_consumed += win_len;
		తిరిగి 0;
	}

	ఒకవేళ (win_len > c->local_maxpacket) {
		logit("channel %d: rcvd big packet %zu, maxpack %u",
		    c->self, win_len, c->local_maxpacket);
		తిరిగి 0;
	}
	ఒకవేళ (win_len > c->local_కిటికీ) {
		u_int delta = win_len - c->local_కిటికీ;

		ఒకవేళ (c->local_కిటికీ_exceeded > UINT_MAX - delta)
			c->local_కిటికీ_exceeded = UINT_MAX;
		లేకపోతే
			c->local_కిటికీ_exceeded += delta;
		logit("channel %d: rcvd too much data %zu, win %u/%u "
		    "(excess %u)", c->self, win_len, c->local_కిటికీ,
		    c->local_కిటికీ_max, c->local_కిటికీ_exceeded);
		c->local_కిటికీ = 0;
		/* Allow 10% grace before bringing the hammer down */
		ఒకవేళ (c->local_కిటికీ_exceeded > (c->local_కిటికీ_max / 10)) {
			ssh_packet_disconnect(ssh, "channel %d: peer ignored "
			    "channel window", c->self);
		}
	} లేకపోతే {
		c->local_కిటికీ -= win_len;
		c->local_కిటికీ_exceeded = 0;
	}

	ఒకవేళ (c->datagram) {
		ఒకవేళ ((r = sshbuf_put_string(c->output, దత్తాంశం, దత్తాంశం_len)) != 0)
			fatal_fr(r, "channel %i: append datagram", c->self);
	} లేకపోతే ఒకవేళ ((r = sshbuf_put(c->output, దత్తాంశం, దత్తాంశం_len)) != 0)
		fatal_fr(r, "channel %i: append data", c->self);

	తిరిగి 0;
}

పూర్ణాంకం
channel_ఆదానం_extended_దత్తాంశం(పూర్ణాంకం type, uint32_t seq, నిర్మాణం ssh *ssh)
{
	స్థిరరాశి u_char *దత్తాంశం;
	కొలత_t దత్తాంశం_len;
	uint32_t tcode;
	Channel *c = channel_from_packet_id(ssh, __func__, "extended data");
	పూర్ణాంకం r;

	ఒకవేళ (channel_proxy_upstream(c, type, seq, ssh))
		తిరిగి 0;
	ఒకవేళ (c->type != SSH_CHANNEL_OPEN) {
		logit("channel %d: ext data for non open", c->self);
		తిరిగి 0;
	}
	ఒకవేళ (c->flags & CHAN_EOF_RCVD) {
		ఒకవేళ (ssh->compat & SSH_BUG_EXTEOF)
			debug("channel %d: accepting ext data after eof",
			    c->self);
		లేకపోతే
			ssh_packet_disconnect(ssh, "Received extended_data "
			    "after EOF on channel %d.", c->self);
	}

	ఒకవేళ ((r = sshpkt_get_u32(ssh, &tcode)) != 0) {
		error_fr(r, "parse tcode");
		ssh_packet_disconnect(ssh, "Invalid extended_data message");
	}
	ఒకవేళ (c->efd == -1 ||
	    c->extended_usage != CHAN_EXTENDED_WRITE ||
	    tcode != SSH2_EXTENDED_దత్తాంశం_STDERR) {
		logit("channel %d: bad ext data", c->self);
		తిరిగి 0;
	}
	ఒకవేళ ((r = sshpkt_get_string_ప్రత్యక్ష(ssh, &దత్తాంశం, &దత్తాంశం_len)) != 0 ||
            (r = sshpkt_get_చివర(ssh)) != 0) {
		error_fr(r, "parse data");
		ssh_packet_disconnect(ssh, "Invalid extended_data message");
	}

	ఒకవేళ (దత్తాంశం_len > c->local_కిటికీ) {
		logit("channel %d: rcvd too much extended_data %zu, win %u",
		    c->self, దత్తాంశం_len, c->local_కిటికీ);
		తిరిగి 0;
	}
	debug2("channel %d: rcvd ext data %zu", c->self, దత్తాంశం_len);
	/* XXX sshpkt_getb? */
	ఒకవేళ ((r = sshbuf_put(c->extended, దత్తాంశం, దత్తాంశం_len)) != 0)
		error_fr(r, "append");
	c->local_కిటికీ -= దత్తాంశం_len;
	తిరిగి 0;
}

పూర్ణాంకం
channel_ఆదానం_ieof(పూర్ణాంకం type, uint32_t seq, నిర్మాణం ssh *ssh)
{
	Channel *c = channel_from_packet_id(ssh, __func__, "ieof");
	పూర్ణాంకం r;

        ఒకవేళ ((r = sshpkt_get_చివర(ssh)) != 0) {
		error_fr(r, "parse data");
		ssh_packet_disconnect(ssh, "Invalid ieof message");
	}

	ఒకవేళ (channel_proxy_upstream(c, type, seq, ssh))
		తిరిగి 0;
	chan_rcvd_ieof(ssh, c);

	/* XXX force input close */
	ఒకవేళ (c->force_drain && c->istate == CHAN_ఆదానం_OPEN) {
		debug("channel %d: FORCE input drain", c->self);
		c->istate = CHAN_ఆదానం_WAIT_DRAIN;
		ఒకవేళ (sshbuf_len(c->ఆదానం) == 0)
			chan_ibuf_ఖాళీలు(ssh, c);
	}
	తిరిగి 0;
}

పూర్ణాంకం
channel_ఆదానం_oclose(పూర్ణాంకం type, uint32_t seq, నిర్మాణం ssh *ssh)
{
	Channel *c = channel_from_packet_id(ssh, __func__, "oclose");
	పూర్ణాంకం r;

	ఒకవేళ (channel_proxy_upstream(c, type, seq, ssh))
		తిరిగి 0;
        ఒకవేళ ((r = sshpkt_get_చివర(ssh)) != 0) {
		error_fr(r, "parse data");
		ssh_packet_disconnect(ssh, "Invalid oclose message");
	}
	chan_rcvd_oclose(ssh, c);
	తిరిగి 0;
}

పూర్ణాంకం
channel_ఆదానం_open_confirmation(పూర్ణాంకం type, uint32_t seq, నిర్మాణం ssh *ssh)
{
	Channel *c = channel_from_packet_id(ssh, __func__, "open confirmation");
	uint32_t remote_కిటికీ, remote_maxpacket;
	పూర్ణాంకం r;

	ఒకవేళ (channel_proxy_upstream(c, type, seq, ssh))
		తిరిగి 0;
	ఒకవేళ (c->type != SSH_CHANNEL_OPENING)
		ssh_packet_disconnect(ssh, "Received open confirmation for "
		    "non-opening channel %d.", c->self);
	/*
	 * Record the remote channel number and mark that the channel
	 * is now open.
	 */
	ఒకవేళ ((r = sshpkt_get_u32(ssh, &c->remote_id)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &remote_కిటికీ)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &remote_maxpacket)) != 0 ||
            (r = sshpkt_get_చివర(ssh)) != 0) {
		error_fr(r, "window/maxpacket");
		ssh_packet_disconnect(ssh, "Invalid open confirmation message");
	}

	c->have_remote_id = 1;
	c->remote_కిటికీ = remote_కిటికీ;
	c->remote_maxpacket = remote_maxpacket;
	c->type = SSH_CHANNEL_OPEN;
	ఒకవేళ (c->open_confirm) {
		debug2_f("channel %d: callback start", c->self);
		c->open_confirm(ssh, c->self, 1, c->open_confirm_ctx);
		debug2_f("channel %d: callback done", c->self);
	}
	channel_సమితి_వాడిన_సమయం(ssh, c);
	debug2("channel %d: open confirm rwindow %u rmax %u", c->self,
	    c->remote_కిటికీ, c->remote_maxpacket);
	తిరిగి 0;
}

స్థిర అక్షరం *
reason2txt(పూర్ణాంకం reason)
{
	ఎంపిక (reason) {
	స్థితి SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED:
		తిరిగి "administratively prohibited";
	స్థితి SSH2_OPEN_CONNECT_FAILED:
		తిరిగి "connect failed";
	స్థితి SSH2_OPEN_UNKNOWN_CHANNEL_TYPE:
		తిరిగి "unknown channel type";
	స్థితి SSH2_OPEN_RESOURCE_SHORTAGE:
		తిరిగి "resource shortage";
	}
	తిరిగి "unknown reason";
}

పూర్ణాంకం
channel_ఆదానం_open_failure(పూర్ణాంకం type, uint32_t seq, నిర్మాణం ssh *ssh)
{
	Channel *c = channel_from_packet_id(ssh, __func__, "open failure");
	uint32_t reason;
	అక్షరం *సందేశం = ఖాళీ;
	పూర్ణాంకం r;

	ఒకవేళ (channel_proxy_upstream(c, type, seq, ssh))
		తిరిగి 0;
	ఒకవేళ (c->type != SSH_CHANNEL_OPENING)
		ssh_packet_disconnect(ssh, "Received open failure for "
		    "non-opening channel %d.", c->self);
	ఒకవేళ ((r = sshpkt_get_u32(ssh, &reason)) != 0) {
		error_fr(r, "parse reason");
		ssh_packet_disconnect(ssh, "Invalid open failure message");
	}
	/* skip language */
	ఒకవేళ ((r = sshpkt_get_cstring(ssh, &సందేశం, ఖాళీ)) != 0 ||
	    (r = sshpkt_get_string_ప్రత్యక్ష(ssh, ఖాళీ, ఖాళీ)) != 0 ||
            (r = sshpkt_get_చివర(ssh)) != 0) {
		error_fr(r, "parse msg/lang");
		ssh_packet_disconnect(ssh, "Invalid open failure message");
	}
	logit("channel %d: open failed: %s%s%s", c->self,
	    reason2txt(reason), సందేశం ? ": ": "", సందేశం ? సందేశం : "");
	విడుదల(సందేశం);
	ఒకవేళ (c->open_confirm) {
		debug2_f("channel %d: callback start", c->self);
		c->open_confirm(ssh, c->self, 0, c->open_confirm_ctx);
		debug2_f("channel %d: callback done", c->self);
	}
	/* Schedule the channel for cleanup/deletion. */
	chan_mark_dead(ssh, c);
	తిరిగి 0;
}

పూర్ణాంకం
channel_ఆదానం_కిటికీ_adjust(పూర్ణాంకం type, uint32_t seq, నిర్మాణం ssh *ssh)
{
	పూర్ణాంకం id = channel_parse_id(ssh, __func__, "window adjust");
	Channel *c;
	uint32_t adjust;
	u_int new_rwin;
	పూర్ణాంకం r;

	ఒకవేళ ((c = channel_lookup(ssh, id)) == ఖాళీ) {
		logit("Received window adjust for non-open channel %d.", id);
		తిరిగి 0;
	}

	ఒకవేళ (channel_proxy_upstream(c, type, seq, ssh))
		తిరిగి 0;
	ఒకవేళ ((r = sshpkt_get_u32(ssh, &adjust)) != 0 ||
            (r = sshpkt_get_చివర(ssh)) != 0) {
		error_fr(r, "parse adjust");
		ssh_packet_disconnect(ssh, "Invalid window adjust message");
	}
	debug2("channel %d: rcvd adjust %u", c->self, adjust);
	ఒకవేళ ((new_rwin = c->remote_కిటికీ + adjust) < c->remote_కిటికీ) {
		fatal("channel %d: adjust %u overflows remote window %u",
		    c->self, adjust, c->remote_కిటికీ);
	}
	c->remote_కిటికీ = new_rwin;
	తిరిగి 0;
}

పూర్ణాంకం
channel_ఆదానం_స్థితి_confirm(పూర్ణాంకం type, uint32_t seq, నిర్మాణం ssh *ssh)
{
	పూర్ణాంకం id = channel_parse_id(ssh, __func__, "status confirm");
	Channel *c;
	నిర్మాణం channel_confirm *cc;

	/* Reset keepalive timeout */
	ssh_packet_సమితి_alive_timeouts(ssh, 0);

	debug2_f("type %d id %d", type, id);

	ఒకవేళ ((c = channel_lookup(ssh, id)) == ఖాళీ) {
		logit_f("%d: unknown", id);
		తిరిగి 0;
	}
	ఒకవేళ (channel_proxy_upstream(c, type, seq, ssh))
		తిరిగి 0;
        ఒకవేళ (sshpkt_get_చివర(ssh) != 0)
		ssh_packet_disconnect(ssh, "Invalid status confirm message");
	ఒకవేళ ((cc = TAILQ_FIRST(&c->స్థితి_confirms)) == ఖాళీ)
		తిరిగి 0;
	cc->cb(ssh, type, c, cc->ctx);
	TAILQ_REMOVE(&c->స్థితి_confirms, cc, నమోదు_2);
	freezero(cc, పరిమాణం(*cc));
	తిరిగి 0;
}

/* -- tcp forwarding */

శూన్య
channel_సమితి_af(నిర్మాణం ssh *ssh, పూర్ణాంకం af)
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
స్థిర స్థిరరాశి అక్షరం *
channel_fwd_bind_addr(నిర్మాణం ssh *ssh, స్థిరరాశి అక్షరం *listen_addr, పూర్ణాంకం *wildcardp,
    పూర్ణాంకం is_client, నిర్మాణం ForwardOptions *fwd_opts)
{
	స్థిరరాశి అక్షరం *addr = ఖాళీ;
	పూర్ణాంకం wildcard = 0;

	ఒకవేళ (listen_addr == ఖాళీ) {
		/* No address specified: default to gateway_ports setting */
		ఒకవేళ (fwd_opts->gateway_ports)
			wildcard = 1;
	} లేకపోతే ఒకవేళ (fwd_opts->gateway_ports || is_client) {
		ఒకవేళ (((ssh->compat & SSH_OLD_FORWARD_ADDR) &&
		    strcmp(listen_addr, "0.0.0.0") == 0 && is_client == 0) ||
		    *listen_addr == '\0' || strcmp(listen_addr, "*") == 0 ||
		    (!is_client && fwd_opts->gateway_ports == 1)) {
			wildcard = 1;
			/*
			 * Notify client if they requested a specific listen
			 * address and it was overridden.
			 */
			ఒకవేళ (*listen_addr != '\0' &&
			    strcmp(listen_addr, "0.0.0.0") != 0 &&
			    strcmp(listen_addr, "*") != 0) {
				ssh_packet_send_debug(ssh,
				    "Forwarding listen address "
				    "\"%s\" overridden by server "
				    "GatewayPorts", listen_addr);
			}
		} లేకపోతే ఒకవేళ (strcmp(listen_addr, "localhost") != 0 ||
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
	} లేకపోతే ఒకవేళ (strcmp(listen_addr, "127.0.0.1") == 0 ||
	    strcmp(listen_addr, "::1") == 0) {
		/*
		 * If a specific IPv4/IPv6 localhost address has been
		 * requested then accept it even if gateway_ports is in
		 * effect. This allows the client to prefer IPv4 or IPv6.
		 */
		addr = listen_addr;
	}
	ఒకవేళ (wildcardp != ఖాళీ)
		*wildcardp = wildcard;
	తిరిగి addr;
}

స్థిర పూర్ణాంకం
channel_అమరిక_fwd_listener_tcpip(నిర్మాణం ssh *ssh, పూర్ణాంకం type,
    నిర్మాణం Forward *fwd, పూర్ణాంకం *allocated_listen_పోర్టు,
    నిర్మాణం ForwardOptions *fwd_opts)
{
	Channel *c;
	పూర్ణాంకం sock, r, success = 0, wildcard = 0, is_client;
	నిర్మాణం addrinfo hints, *ai, *aitop;
	స్థిరరాశి అక్షరం *host, *addr;
	అక్షరం ntop[NI_MAXHOST], strport[NI_MAXSERV];
	in_port_t *lport_p;

	is_client = (type == SSH_CHANNEL_పోర్టు_LISTENER);

	ఒకవేళ (is_client && fwd->connect_మార్గం != ఖాళీ) {
		host = fwd->connect_మార్గం;
	} లేకపోతే {
		host = (type == SSH_CHANNEL_RPORT_LISTENER) ?
		    fwd->listen_host : fwd->connect_host;
		ఒకవేళ (host == ఖాళీ) {
			error("No forward host name.");
			తిరిగి 0;
		}
		ఒకవేళ (అక్షరశ్రేణి_పొడవు(host) >= NI_MAXHOST) {
			error("Forward host name too long.");
			తిరిగి 0;
		}
	}

	/* Determine the bind address, cf. channel_fwd_bind_addr() comment */
	addr = channel_fwd_bind_addr(ssh, fwd->listen_host, &wildcard,
	    is_client, fwd_opts);
	debug3_f("type %d wildcard %d addr %s", type, wildcard,
	    (addr == ఖాళీ) ? "NULL" : addr);

	/*
	 * getaddrinfo returns a loopback address if the hostname is
	 * set to NULL and hints.ai_flags is not AI_PASSIVE
	 */
	memset(&hints, 0, పరిమాణం(hints));
	hints.ai_family = ssh->chanctxt->IPv4or6;
	hints.ai_flags = wildcard ? AI_PASSIVE : 0;
	hints.ai_socktype = SOCK_STREAM;
	snprintf(strport, పరిమాణం strport, "%d", fwd->listen_పోర్టు);
	ఒకవేళ ((r = getaddrinfo(addr, strport, &hints, &aitop)) != 0) {
		ఒకవేళ (addr == ఖాళీ) {
			/* This really shouldn't happen */
			ssh_packet_disconnect(ssh, "getaddrinfo: fatal error: %s",
			    ssh_gai_strerror(r));
		} లేకపోతే {
			error_f("getaddrinfo(%.64s): %s", addr,
			    ssh_gai_strerror(r));
		}
		తిరిగి 0;
	}
	ఒకవేళ (allocated_listen_పోర్టు != ఖాళీ)
		*allocated_listen_పోర్టు = 0;
	కొరకు (ai = aitop; ai; ai = ai->ai_next) {
		ఎంపిక (ai->ai_family) {
		స్థితి AF_INET:
			lport_p = &((నిర్మాణం sockaddr_in *)ai->ai_addr)->
			    sin_port;
			ఆపు;
		స్థితి AF_INET6:
			lport_p = &((నిర్మాణం sockaddr_in6 *)ai->ai_addr)->
			    sin6_port;
			ఆపు;
		అప్రమేయ:
			కొనసాగు;
		}
		/*
		 * If allocating a port for -R forwards, then use the
		 * same port for all address families.
		 */
		ఒకవేళ (type == SSH_CHANNEL_RPORT_LISTENER &&
		    fwd->listen_పోర్టు == 0 && allocated_listen_పోర్టు != ఖాళీ &&
		    *allocated_listen_పోర్టు > 0)
			*lport_p = htons(*allocated_listen_పోర్టు);

		ఒకవేళ (getnameinfo(ai->ai_addr, ai->ai_addrlen, ntop, పరిమాణం(ntop),
		    strport, పరిమాణం(strport),
		    NI_NUMERICHOST|NI_NUMERICSERV) != 0) {
			error_f("getnameinfo failed");
			కొనసాగు;
		}
		/* Create a port to listen for the host. */
		sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		ఒకవేళ (sock == -1) {
			/* this is no error since kernel may not support ipv6 */
			verbose("socket [%s]:%s: %.100s", ntop, strport,
			    strerror(errno));
			కొనసాగు;
		}

		సమితి_reuseaddr(sock);
		ఒకవేళ (ai->ai_family == AF_INET6)
			sock_సమితి_v6only(sock);

		debug("Local forwarding listening on %s port %s.",
		    ntop, strport);

		/* Bind the socket to the address. */
		ఒకవేళ (bind(sock, ai->ai_addr, ai->ai_addrlen) == -1) {
			/*
			 * address can be in if use ipv6 address is
			 * already bound
			 */
			ఒకవేళ (!ai->ai_next)
				error("bind [%s]:%s: %.100s",
				    ntop, strport, strerror(errno));
			లేకపోతే
				verbose("bind [%s]:%s: %.100s",
				    ntop, strport, strerror(errno));

			close(sock);
			కొనసాగు;
		}
		/* Start listening for connections on the socket. */
		ఒకవేళ (listen(sock, SSH_LISTEN_BACKLOG) == -1) {
			error("listen [%s]:%s: %.100s", ntop, strport,
			    strerror(errno));
			close(sock);
			కొనసాగు;
		}

		/*
		 * fwd->listen_port == 0 requests a dynamically allocated port -
		 * record what we got.
		 */
		ఒకవేళ (type == SSH_CHANNEL_RPORT_LISTENER &&
		    fwd->listen_పోర్టు == 0 &&
		    allocated_listen_పోర్టు != ఖాళీ &&
		    *allocated_listen_పోర్టు == 0) {
			*allocated_listen_పోర్టు = get_local_పోర్టు(sock);
			debug("Allocated listen port %d",
			    *allocated_listen_పోర్టు);
		}

		/* Allocate a channel number for the socket. */
		c = channel_new(ssh, "port-listener", type, sock, sock, -1,
		    CHAN_TCP_కిటికీ_DEFAULT, CHAN_TCP_PACKET_DEFAULT,
		    0, "port listener", 1);
		c->మార్గం = xstrdup(host);
		c->host_పోర్టు = fwd->connect_పోర్టు;
		c->listening_addr = addr == ఖాళీ ? ఖాళీ : xstrdup(addr);
		ఒకవేళ (fwd->listen_పోర్టు == 0 && allocated_listen_పోర్టు != ఖాళీ &&
		    !(ssh->compat & SSH_BUG_DYNAMIC_RPORT))
			c->listening_పోర్టు = *allocated_listen_పోర్టు;
		లేకపోతే
			c->listening_పోర్టు = fwd->listen_పోర్టు;
		success = 1;
	}
	ఒకవేళ (success == 0)
		error_f("cannot listen to port: %d", fwd->listen_పోర్టు);
	freeaddrinfo(aitop);
	తిరిగి success;
}

స్థిర పూర్ణాంకం
channel_అమరిక_fwd_listener_streamlocal(నిర్మాణం ssh *ssh, పూర్ణాంకం type,
    నిర్మాణం Forward *fwd, నిర్మాణం ForwardOptions *fwd_opts)
{
	నిర్మాణం sockaddr_un sunaddr;
	స్థిరరాశి అక్షరం *మార్గం;
	Channel *c;
	పూర్ణాంకం పోర్టు, sock;
	బహుళకం_t omask;

	ఎంపిక (type) {
	స్థితి SSH_CHANNEL_UNIX_LISTENER:
		ఒకవేళ (fwd->connect_మార్గం != ఖాళీ) {
			ఒకవేళ (అక్షరశ్రేణి_పొడవు(fwd->connect_మార్గం) > పరిమాణం(sunaddr.sun_మార్గం)) {
				error("Local connecting path too long: %s",
				    fwd->connect_మార్గం);
				తిరిగి 0;
			}
			మార్గం = fwd->connect_మార్గం;
			పోర్టు = పోర్టు_STREAMLOCAL;
		} లేకపోతే {
			ఒకవేళ (fwd->connect_host == ఖాళీ) {
				error("No forward host name.");
				తిరిగి 0;
			}
			ఒకవేళ (అక్షరశ్రేణి_పొడవు(fwd->connect_host) >= NI_MAXHOST) {
				error("Forward host name too long.");
				తిరిగి 0;
			}
			మార్గం = fwd->connect_host;
			పోర్టు = fwd->connect_పోర్టు;
		}
		ఆపు;
	స్థితి SSH_CHANNEL_RUNIX_LISTENER:
		మార్గం = fwd->listen_మార్గం;
		పోర్టు = పోర్టు_STREAMLOCAL;
		ఆపు;
	అప్రమేయ:
		error_f("unexpected channel type %d", type);
		తిరిగి 0;
	}

	ఒకవేళ (fwd->listen_మార్గం == ఖాళీ) {
		error("No forward path name.");
		తిరిగి 0;
	}
	ఒకవేళ (అక్షరశ్రేణి_పొడవు(fwd->listen_మార్గం) > పరిమాణం(sunaddr.sun_మార్గం)) {
		error("Local listening path too long: %s", fwd->listen_మార్గం);
		తిరిగి 0;
	}

	debug3_f("type %d path %s", type, fwd->listen_మార్గం);

	/* Start a Unix domain listener. */
	omask = umask(fwd_opts->streamlocal_bind_ముసుగు);
	sock = unix_listener(fwd->listen_మార్గం, SSH_LISTEN_BACKLOG,
	    fwd_opts->streamlocal_bind_unlink);
	umask(omask);
	ఒకవేళ (sock < 0)
		తిరిగి 0;

	debug("Local forwarding listening on path %s.", fwd->listen_మార్గం);

	/* Allocate a channel number for the socket. */
	c = channel_new(ssh, "unix-listener", type, sock, sock, -1,
	    CHAN_TCP_కిటికీ_DEFAULT, CHAN_TCP_PACKET_DEFAULT,
	    0, "unix listener", 1);
	c->మార్గం = xstrdup(మార్గం);
	c->host_పోర్టు = పోర్టు;
	c->listening_పోర్టు = పోర్టు_STREAMLOCAL;
	c->listening_addr = xstrdup(fwd->listen_మార్గం);
	తిరిగి 1;
}

స్థిర పూర్ణాంకం
channel_cancel_rport_listener_tcpip(నిర్మాణం ssh *ssh,
    స్థిరరాశి అక్షరం *host, u_short పోర్టు)
{
	u_int i;
	పూర్ణాంకం దొరికింది = 0;

	కొరకు (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		Channel *c = ssh->chanctxt->channels[i];
		ఒకవేళ (c == ఖాళీ || c->type != SSH_CHANNEL_RPORT_LISTENER)
			కొనసాగు;
		ఒకవేళ (strcmp(c->మార్గం, host) == 0 && c->listening_పోర్టు == పోర్టు) {
			debug2_f("close channel %d", i);
			channel_free(ssh, c);
			దొరికింది = 1;
		}
	}

	తిరిగి దొరికింది;
}

స్థిర పూర్ణాంకం
channel_cancel_rport_listener_streamlocal(నిర్మాణం ssh *ssh, స్థిరరాశి అక్షరం *మార్గం)
{
	u_int i;
	పూర్ణాంకం దొరికింది = 0;

	కొరకు (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		Channel *c = ssh->chanctxt->channels[i];
		ఒకవేళ (c == ఖాళీ || c->type != SSH_CHANNEL_RUNIX_LISTENER)
			కొనసాగు;
		ఒకవేళ (c->మార్గం == ఖాళీ)
			కొనసాగు;
		ఒకవేళ (strcmp(c->మార్గం, మార్గం) == 0) {
			debug2_f("close channel %d", i);
			channel_free(ssh, c);
			దొరికింది = 1;
		}
	}

	తిరిగి దొరికింది;
}

పూర్ణాంకం
channel_cancel_rport_listener(నిర్మాణం ssh *ssh, నిర్మాణం Forward *fwd)
{
	ఒకవేళ (fwd->listen_మార్గం != ఖాళీ) {
		తిరిగి channel_cancel_rport_listener_streamlocal(ssh,
		    fwd->listen_మార్గం);
	} లేకపోతే {
		తిరిగి channel_cancel_rport_listener_tcpip(ssh,
		    fwd->listen_host, fwd->listen_పోర్టు);
	}
}

స్థిర పూర్ణాంకం
channel_cancel_lport_listener_tcpip(నిర్మాణం ssh *ssh,
    స్థిరరాశి అక్షరం *lhost, u_short lport, పూర్ణాంకం cport,
    నిర్మాణం ForwardOptions *fwd_opts)
{
	u_int i;
	పూర్ణాంకం దొరికింది = 0;
	స్థిరరాశి అక్షరం *addr = channel_fwd_bind_addr(ssh, lhost, ఖాళీ, 1, fwd_opts);

	కొరకు (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		Channel *c = ssh->chanctxt->channels[i];
		ఒకవేళ (c == ఖాళీ || c->type != SSH_CHANNEL_పోర్టు_LISTENER)
			కొనసాగు;
		ఒకవేళ (c->listening_పోర్టు != lport)
			కొనసాగు;
		ఒకవేళ (cport == CHANNEL_CANCEL_పోర్టు_STATIC) {
			/* skip dynamic forwardings */
			ఒకవేళ (c->host_పోర్టు == 0)
				కొనసాగు;
		} లేకపోతే {
			ఒకవేళ (c->host_పోర్టు != cport)
				కొనసాగు;
		}
		ఒకవేళ ((c->listening_addr == ఖాళీ && addr != ఖాళీ) ||
		    (c->listening_addr != ఖాళీ && addr == ఖాళీ))
			కొనసాగు;
		ఒకవేళ (addr == ఖాళీ || strcmp(c->listening_addr, addr) == 0) {
			debug2_f("close channel %d", i);
			channel_free(ssh, c);
			దొరికింది = 1;
		}
	}

	తిరిగి దొరికింది;
}

స్థిర పూర్ణాంకం
channel_cancel_lport_listener_streamlocal(నిర్మాణం ssh *ssh, స్థిరరాశి అక్షరం *మార్గం)
{
	u_int i;
	పూర్ణాంకం దొరికింది = 0;

	ఒకవేళ (మార్గం == ఖాళీ) {
		error_f("no path specified.");
		తిరిగి 0;
	}

	కొరకు (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		Channel *c = ssh->chanctxt->channels[i];
		ఒకవేళ (c == ఖాళీ || c->type != SSH_CHANNEL_UNIX_LISTENER)
			కొనసాగు;
		ఒకవేళ (c->listening_addr == ఖాళీ)
			కొనసాగు;
		ఒకవేళ (strcmp(c->listening_addr, మార్గం) == 0) {
			debug2_f("close channel %d", i);
			channel_free(ssh, c);
			దొరికింది = 1;
		}
	}

	తిరిగి దొరికింది;
}

పూర్ణాంకం
channel_cancel_lport_listener(నిర్మాణం ssh *ssh,
    నిర్మాణం Forward *fwd, పూర్ణాంకం cport, నిర్మాణం ForwardOptions *fwd_opts)
{
	ఒకవేళ (fwd->listen_మార్గం != ఖాళీ) {
		తిరిగి channel_cancel_lport_listener_streamlocal(ssh,
		    fwd->listen_మార్గం);
	} లేకపోతే {
		తిరిగి channel_cancel_lport_listener_tcpip(ssh,
		    fwd->listen_host, fwd->listen_పోర్టు, cport, fwd_opts);
	}
}

/* protocol local port fwd, used by ssh */
పూర్ణాంకం
channel_అమరిక_local_fwd_listener(నిర్మాణం ssh *ssh,
    నిర్మాణం Forward *fwd, నిర్మాణం ForwardOptions *fwd_opts)
{
	ఒకవేళ (fwd->listen_మార్గం != ఖాళీ) {
		తిరిగి channel_అమరిక_fwd_listener_streamlocal(ssh,
		    SSH_CHANNEL_UNIX_LISTENER, fwd, fwd_opts);
	} లేకపోతే {
		తిరిగి channel_అమరిక_fwd_listener_tcpip(ssh,
		    SSH_CHANNEL_పోర్టు_LISTENER, fwd, ఖాళీ, fwd_opts);
	}
}

/* Matches a remote forwarding permission against a requested forwarding */
స్థిర పూర్ణాంకం
remote_open_సరిపోలిక(నిర్మాణం permission *allowed_open, నిర్మాణం Forward *fwd)
{
	పూర్ణాంకం ret;
	అక్షరం *lhost;

	/* XXX add ACLs for streamlocal */
	ఒకవేళ (fwd->listen_మార్గం != ఖాళీ)
		తిరిగి 1;

	ఒకవేళ (fwd->listen_host == ఖాళీ || allowed_open->listen_host == ఖాళీ)
		తిరిగి 0;

	ఒకవేళ (allowed_open->listen_పోర్టు != FWD_PERMIT_ANY_పోర్టు &&
	    allowed_open->listen_పోర్టు != fwd->listen_పోర్టు)
		తిరిగి 0;

	/* Match hostnames case-insensitively */
	lhost = xstrdup(fwd->listen_host);
	lowercase(lhost);
	ret = సరిపోలిక_నమూనా(lhost, allowed_open->listen_host);
	విడుదల(lhost);

	తిరిగి ret;
}

/* Checks whether a requested remote forwarding is permitted */
స్థిర పూర్ణాంకం
check_rfwd_permission(నిర్మాణం ssh *ssh, నిర్మాణం Forward *fwd)
{
	నిర్మాణం ssh_channels *sc = ssh->chanctxt;
	నిర్మాణం permission_సమితి *pset = &sc->remote_perms;
	u_int i, permit, permit_adm = 1;
	నిర్మాణం permission *perm;

#నిర్వచితమైతే SKIP_PRIVDROP
	ఒకవేళ (fwd->listen_మార్గం != ఖాళీ)
		తిరిగి 0;
	ఒకవేళ (fwd->listen_పోర్టు != 0 && fwd->listen_పోర్టు < 1024)
		తిరిగి 0;
#అయితే_ముగింపు

	/* XXX apply GatewayPorts override before checking? */

	permit = pset->all_permitted;
	ఒకవేళ (!permit) {
		కొరకు (i = 0; i < pset->అంకె_permitted_user; i++) {
			perm = &pset->permitted_user[i];
			ఒకవేళ (remote_open_సరిపోలిక(perm, fwd)) {
				permit = 1;
				ఆపు;
			}
		}
	}

	ఒకవేళ (pset->అంకె_permitted_admin > 0) {
		permit_adm = 0;
		కొరకు (i = 0; i < pset->అంకె_permitted_admin; i++) {
			perm = &pset->permitted_admin[i];
			ఒకవేళ (remote_open_సరిపోలిక(perm, fwd)) {
				permit_adm = 1;
				ఆపు;
			}
		}
	}

	తిరిగి permit && permit_adm;
}

/* protocol v2 remote port fwd, used by sshd */
పూర్ణాంకం
channel_అమరిక_remote_fwd_listener(నిర్మాణం ssh *ssh, నిర్మాణం Forward *fwd,
    పూర్ణాంకం *allocated_listen_పోర్టు, నిర్మాణం ForwardOptions *fwd_opts)
{
	ఒకవేళ (!check_rfwd_permission(ssh, fwd)) {
		ssh_packet_send_debug(ssh, "port forwarding refused");
		ఒకవేళ (fwd->listen_మార్గం != ఖాళీ)
			/* XXX always allowed, see remote_open_match() */
			logit("Received request from %.100s port %d to "
			    "remote forward to path \"%.100s\", "
			    "but the request was denied.",
			    ssh_remote_ipaddr(ssh), ssh_remote_పోర్టు(ssh),
			    fwd->listen_మార్గం);
		లేకపోతే ఒకవేళ(fwd->listen_host != ఖాళీ)
			logit("Received request from %.100s port %d to "
			    "remote forward to host %.100s port %d, "
			    "but the request was denied.",
			    ssh_remote_ipaddr(ssh), ssh_remote_పోర్టు(ssh),
			    fwd->listen_host, fwd->listen_పోర్టు );
		లేకపోతే
			logit("Received request from %.100s port %d to remote "
			    "forward, but the request was denied.",
			    ssh_remote_ipaddr(ssh), ssh_remote_పోర్టు(ssh));
		తిరిగి 0;
	}
	ఒకవేళ (fwd->listen_మార్గం != ఖాళీ) {
		తిరిగి channel_అమరిక_fwd_listener_streamlocal(ssh,
		    SSH_CHANNEL_RUNIX_LISTENER, fwd, fwd_opts);
	} లేకపోతే {
		తిరిగి channel_అమరిక_fwd_listener_tcpip(ssh,
		    SSH_CHANNEL_RPORT_LISTENER, fwd, allocated_listen_పోర్టు,
		    fwd_opts);
	}
}

/*
 * Translate the requested rfwd listen host to something usable for
 * this server.
 */
స్థిర స్థిరరాశి అక్షరం *
channel_rfwd_bind_host(స్థిరరాశి అక్షరం *listen_host)
{
	ఒకవేళ (listen_host == ఖాళీ) {
		తిరిగి "localhost";
	} లేకపోతే ఒకవేళ (*listen_host == '\0' || strcmp(listen_host, "*") == 0) {
		తిరిగి "";
	} లేకపోతే
		తిరిగి listen_host;
}

/*
 * Initiate forwarding of connections to port "port" on remote host through
 * the secure channel to host:port from local side.
 * Returns handle (index) for updating the dynamic listen port with
 * channel_update_permission().
 */
పూర్ణాంకం
channel_request_remote_forwarding(నిర్మాణం ssh *ssh, నిర్మాణం Forward *fwd)
{
	పూర్ణాంకం r, success = 0, idx = -1;
	స్థిరరాశి అక్షరం *host_గమ్యం_connect, *listen_host, *listen_మార్గం;
	పూర్ణాంకం పోర్టు_గమ్యం_connect, listen_పోర్టు;

	/* Send the forward request to the remote side. */
	ఒకవేళ (fwd->listen_మార్గం != ఖాళీ) {
		ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh, SSH2_సందేశం_GLOBAL_REQUEST)) != 0 ||
		    (r = sshpkt_put_cstring(ssh,
		    "streamlocal-forward@openssh.com")) != 0 ||
		    (r = sshpkt_put_u8(ssh, 1)) != 0 || /* want reply */
		    (r = sshpkt_put_cstring(ssh, fwd->listen_మార్గం)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			fatal_fr(r, "request streamlocal");
	} లేకపోతే {
		ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh, SSH2_సందేశం_GLOBAL_REQUEST)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "tcpip-forward")) != 0 ||
		    (r = sshpkt_put_u8(ssh, 1)) != 0 || /* want reply */
		    (r = sshpkt_put_cstring(ssh,
		    channel_rfwd_bind_host(fwd->listen_host))) != 0 ||
		    (r = sshpkt_put_u32(ssh, fwd->listen_పోర్టు)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			fatal_fr(r, "request tcpip-forward");
	}
	/* Assume that server accepts the request */
	success = 1;
	ఒకవేళ (success) {
		/* Record that connection to this host/port is permitted. */
		host_గమ్యం_connect = listen_host = listen_మార్గం = ఖాళీ;
		పోర్టు_గమ్యం_connect = listen_పోర్టు = 0;
		ఒకవేళ (fwd->connect_మార్గం != ఖాళీ) {
			host_గమ్యం_connect = fwd->connect_మార్గం;
			పోర్టు_గమ్యం_connect = పోర్టు_STREAMLOCAL;
		} లేకపోతే {
			host_గమ్యం_connect = fwd->connect_host;
			పోర్టు_గమ్యం_connect = fwd->connect_పోర్టు;
		}
		ఒకవేళ (fwd->listen_మార్గం != ఖాళీ) {
			listen_మార్గం = fwd->listen_మార్గం;
			listen_పోర్టు = పోర్టు_STREAMLOCAL;
		} లేకపోతే {
			listen_host = fwd->listen_host;
			listen_పోర్టు = fwd->listen_పోర్టు;
		}
		idx = permission_సమితి_కూడు(ssh, FORWARD_USER, FORWARD_LOCAL,
		    host_గమ్యం_connect, పోర్టు_గమ్యం_connect,
		    listen_host, listen_మార్గం, listen_పోర్టు, ఖాళీ);
	}
	తిరిగి idx;
}

స్థిర పూర్ణాంకం
open_సరిపోలిక(నిర్మాణం permission *allowed_open, స్థిరరాశి అక్షరం *requestedhost,
    పూర్ణాంకం requestedport)
{
	ఒకవేళ (allowed_open->host_గమ్యం_connect == ఖాళీ)
		తిరిగి 0;
	ఒకవేళ (allowed_open->పోర్టు_గమ్యం_connect != FWD_PERMIT_ANY_పోర్టు &&
	    allowed_open->పోర్టు_గమ్యం_connect != requestedport)
		తిరిగి 0;
	ఒకవేళ (strcmp(allowed_open->host_గమ్యం_connect, FWD_PERMIT_ANY_HOST) != 0 &&
	    strcmp(allowed_open->host_గమ్యం_connect, requestedhost) != 0)
		తిరిగి 0;
	తిరిగి 1;
}

/*
 * Note that in the listen host/port case
 * we don't support FWD_PERMIT_ANY_PORT and
 * need to translate between the configured-host (listen_host)
 * and what we've sent to the remote server (channel_rfwd_bind_host)
 */
స్థిర పూర్ణాంకం
open_listen_సరిపోలిక_tcpip(నిర్మాణం permission *allowed_open,
    స్థిరరాశి అక్షరం *requestedhost, u_short requestedport, పూర్ణాంకం translate)
{
	స్థిరరాశి అక్షరం *allowed_host;

	ఒకవేళ (allowed_open->host_గమ్యం_connect == ఖాళీ)
		తిరిగి 0;
	ఒకవేళ (allowed_open->listen_పోర్టు != requestedport)
		తిరిగి 0;
	ఒకవేళ (!translate && allowed_open->listen_host == ఖాళీ &&
	    requestedhost == ఖాళీ)
		తిరిగి 1;
	allowed_host = translate ?
	    channel_rfwd_bind_host(allowed_open->listen_host) :
	    allowed_open->listen_host;
	ఒకవేళ (allowed_host == ఖాళీ || requestedhost == ఖాళీ ||
	    strcmp(allowed_host, requestedhost) != 0)
		తిరిగి 0;
	తిరిగి 1;
}

స్థిర పూర్ణాంకం
open_listen_సరిపోలిక_streamlocal(నిర్మాణం permission *allowed_open,
    స్థిరరాశి అక్షరం *requestedpath)
{
	ఒకవేళ (allowed_open->host_గమ్యం_connect == ఖాళీ)
		తిరిగి 0;
	ఒకవేళ (allowed_open->listen_పోర్టు != పోర్టు_STREAMLOCAL)
		తిరిగి 0;
	ఒకవేళ (allowed_open->listen_మార్గం == ఖాళీ ||
	    strcmp(allowed_open->listen_మార్గం, requestedpath) != 0)
		తిరిగి 0;
	తిరిగి 1;
}

/*
 * Request cancellation of remote forwarding of connection host:port from
 * local side.
 */
స్థిర పూర్ణాంకం
channel_request_rforward_cancel_tcpip(నిర్మాణం ssh *ssh,
    స్థిరరాశి అక్షరం *host, u_short పోర్టు)
{
	నిర్మాణం ssh_channels *sc = ssh->chanctxt;
	నిర్మాణం permission_సమితి *pset = &sc->local_perms;
	పూర్ణాంకం r;
	u_int i;
	నిర్మాణం permission *perm = ఖాళీ;

	కొరకు (i = 0; i < pset->అంకె_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		ఒకవేళ (open_listen_సరిపోలిక_tcpip(perm, host, పోర్టు, 0))
			ఆపు;
		perm = ఖాళీ;
	}
	ఒకవేళ (perm == ఖాళీ) {
		debug_f("requested forward not found");
		తిరిగి -1;
	}
	ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh, SSH2_సందేశం_GLOBAL_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "cancel-tcpip-forward")) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 || /* want reply */
	    (r = sshpkt_put_cstring(ssh, channel_rfwd_bind_host(host))) != 0 ||
	    (r = sshpkt_put_u32(ssh, పోర్టు)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send cancel");

	fwd_perm_clear(perm); /* unregister */

	తిరిగి 0;
}

/*
 * Request cancellation of remote forwarding of Unix domain socket
 * path from local side.
 */
స్థిర పూర్ణాంకం
channel_request_rforward_cancel_streamlocal(నిర్మాణం ssh *ssh, స్థిరరాశి అక్షరం *మార్గం)
{
	నిర్మాణం ssh_channels *sc = ssh->chanctxt;
	నిర్మాణం permission_సమితి *pset = &sc->local_perms;
	పూర్ణాంకం r;
	u_int i;
	నిర్మాణం permission *perm = ఖాళీ;

	కొరకు (i = 0; i < pset->అంకె_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		ఒకవేళ (open_listen_సరిపోలిక_streamlocal(perm, మార్గం))
			ఆపు;
		perm = ఖాళీ;
	}
	ఒకవేళ (perm == ఖాళీ) {
		debug_f("requested forward not found");
		తిరిగి -1;
	}
	ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh, SSH2_సందేశం_GLOBAL_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh,
	    "cancel-streamlocal-forward@openssh.com")) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 || /* want reply */
	    (r = sshpkt_put_cstring(ssh, మార్గం)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send cancel");

	fwd_perm_clear(perm); /* unregister */

	తిరిగి 0;
}

/*
 * Request cancellation of remote forwarding of a connection from local side.
 */
పూర్ణాంకం
channel_request_rforward_cancel(నిర్మాణం ssh *ssh, నిర్మాణం Forward *fwd)
{
	ఒకవేళ (fwd->listen_మార్గం != ఖాళీ) {
		తిరిగి channel_request_rforward_cancel_streamlocal(ssh,
		    fwd->listen_మార్గం);
	} లేకపోతే {
		తిరిగి channel_request_rforward_cancel_tcpip(ssh,
		    fwd->listen_host,
		    fwd->listen_పోర్టు ? fwd->listen_పోర్టు : fwd->allocated_పోర్టు);
	}
}

/*
 * Permits opening to any host/port if permitted_user[] is empty.  This is
 * usually called by the server, because the user could connect to any port
 * anyway, and the server has no way to know but to trust the client anyway.
 */
శూన్య
channel_permit_all(నిర్మాణం ssh *ssh, పూర్ణాంకం where)
{
	నిర్మాణం permission_సమితి *pset = permission_సమితి_get(ssh, where);

	ఒకవేళ (pset->అంకె_permitted_user == 0)
		pset->all_permitted = 1;
}

/*
 * Permit the specified host/port for forwarding.
 */
శూన్య
channel_కూడు_permission(నిర్మాణం ssh *ssh, పూర్ణాంకం who, పూర్ణాంకం where,
    అక్షరం *host, పూర్ణాంకం పోర్టు)
{
	పూర్ణాంకం local = where == FORWARD_LOCAL;
	నిర్మాణం permission_సమితి *pset = permission_సమితి_get(ssh, where);

	debug("allow %s forwarding to host %s port %d",
	    fwd_ident(who, where), host, పోర్టు);
	/*
	 * Remote forwards set listen_host/port, local forwards set
	 * host/port_to_connect.
	 */
	permission_సమితి_కూడు(ssh, who, where,
	    local ? host : ఖాళీ, local ? పోర్టు : 0,
	    local ? ఖాళీ : host, ఖాళీ, local ? 0 : పోర్టు, ఖాళీ);
	pset->all_permitted = 0;
}

/*
 * Administratively disable forwarding.
 */
శూన్య
channel_disable_admin(నిర్మాణం ssh *ssh, పూర్ణాంకం where)
{
	channel_clear_permission(ssh, FORWARD_ADM, where);
	permission_సమితి_కూడు(ssh, FORWARD_ADM, where,
	    ఖాళీ, 0, ఖాళీ, ఖాళీ, 0, ఖాళీ);
}

/*
 * Clear a list of permitted opens.
 */
శూన్య
channel_clear_permission(నిర్మాణం ssh *ssh, పూర్ణాంకం who, పూర్ణాంకం where)
{
	నిర్మాణం permission **permp;
	u_int i, *npermp;

	permission_సమితి_get_array(ssh, who, where, &permp, &npermp);
	కొరకు (i = 0; i < *npermp; i++)
		fwd_perm_clear((*permp) + i);
	విడుదల(*permp);
	*permp = ఖాళీ;
	*npermp = 0;
}

/*
 * Update the listen port for a dynamic remote forward, after
 * the actual 'newport' has been allocated. If 'newport' < 0 is
 * passed then they entry will be invalidated.
 */
శూన్య
channel_update_permission(నిర్మాణం ssh *ssh, పూర్ణాంకం idx, పూర్ణాంకం newport)
{
	నిర్మాణం permission_సమితి *pset = &ssh->chanctxt->local_perms;

	ఒకవేళ (idx < 0 || (u_int)idx >= pset->అంకె_permitted_user) {
		debug_f("index out of range: %d num_permitted_user %d",
		    idx, pset->అంకె_permitted_user);
		తిరిగి;
	}
	debug("%s allowed port %d for forwarding to host %s port %d",
	    newport > 0 ? "Updating" : "Removing",
	    newport,
	    pset->permitted_user[idx].host_గమ్యం_connect,
	    pset->permitted_user[idx].పోర్టు_గమ్యం_connect);
	ఒకవేళ (newport <= 0)
		fwd_perm_clear(&pset->permitted_user[idx]);
	లేకపోతే {
		pset->permitted_user[idx].listen_పోర్టు =
		    (ssh->compat & SSH_BUG_DYNAMIC_RPORT) ? 0 : newport;
	}
}

/* Try to start non-blocking connect to next host in cctx list */
స్థిర పూర్ణాంకం
connect_తదుపరి(నిర్మాణం ssh *ssh, నిర్మాణం channel_connect *cctx)
{
	పూర్ణాంకం sock, sock_is_జాలం, saved_errno;
	నిర్మాణం sockaddr_un *sunaddr;
	అక్షరం ntop[NI_MAXHOST];
	అక్షరం strport[గరిష్ఠ(NI_MAXSERV, పరిమాణం(sunaddr->sun_మార్గం))];

	కొరకు (; cctx->ai; cctx->ai = cctx->ai->ai_next) {
		sock_is_జాలం = 0;
		ఎంపిక (cctx->ai->ai_family) {
		స్థితి AF_UNIX:
			/* unix:pathname instead of host:port */
			sunaddr = (నిర్మాణం sockaddr_un *)cctx->ai->ai_addr;
			strlcpy(ntop, "unix", పరిమాణం(ntop));
			strlcpy(strport, sunaddr->sun_మార్గం, పరిమాణం(strport));
			ఆపు;
		స్థితి AF_INET:
		స్థితి AF_INET6:
			ఒకవేళ (getnameinfo(cctx->ai->ai_addr, cctx->ai->ai_addrlen,
			    ntop, పరిమాణం(ntop), strport, పరిమాణం(strport),
			    NI_NUMERICHOST|NI_NUMERICSERV) != 0) {
				error_f("getnameinfo failed");
				కొనసాగు;
			}
			sock_is_జాలం = 1;
			ఆపు;
		అప్రమేయ:
			కొనసాగు;
		}
		debug_f("start for host %.100s ([%.100s]:%s)",
		    cctx->host, ntop, strport);
		ఒకవేళ ((sock = socket(cctx->ai->ai_family, cctx->ai->ai_socktype,
		    cctx->ai->ai_protocol)) == -1) {
			ఒకవేళ (cctx->ai->ai_next == ఖాళీ)
				error("socket: %.100s", strerror(errno));
			లేకపోతే
				verbose("socket: %.100s", strerror(errno));
			కొనసాగు;
		}
		ఒకవేళ (సమితి_nonblock(sock) == -1)
			fatal_f("set_nonblock(%d)", sock);
		ఒకవేళ (sock_is_జాలం && ssh->chanctxt->want_tcp_keepalive)
			సమితి_keepalive(sock); /* logs errors */
		ఒకవేళ (connect(sock, cctx->ai->ai_addr,
		    cctx->ai->ai_addrlen) == -1 && errno != EINPROGRESS) {
			debug_f("host %.100s ([%.100s]:%s): %.100s",
			    cctx->host, ntop, strport, strerror(errno));
			saved_errno = errno;
			close(sock);
			errno = saved_errno;
			కొనసాగు;	/* fail -- try next */
		}
		ఒకవేళ (cctx->ai->ai_family != AF_UNIX)
			సమితి_nodelay(sock);
		debug_f("connect host %.100s ([%.100s]:%s) in progress, fd=%d",
		    cctx->host, ntop, strport, sock);
		cctx->ai = cctx->ai->ai_next;
		తిరిగి sock;
	}
	తిరిగి -1;
}

/*
 * Return connecting socket to remote host:port or local socket path,
 * passing back the failure reason if appropriate.
 */
స్థిర పూర్ణాంకం
connect_గమ్యం_helper(నిర్మాణం ssh *ssh, స్థిరరాశి అక్షరం *name, పూర్ణాంకం పోర్టు, పూర్ణాంకం socktype,
    అక్షరం *ctype, అక్షరం *rname, నిర్మాణం channel_connect *cctx,
    పూర్ణాంకం *reason, స్థిరరాశి అక్షరం **errmsg)
{
	నిర్మాణం addrinfo hints;
	పూర్ణాంకం gaierr;
	పూర్ణాంకం sock = -1;
	అక్షరం strport[NI_MAXSERV];

	ఒకవేళ (పోర్టు == పోర్టు_STREAMLOCAL) {
		నిర్మాణం sockaddr_un *sunaddr;
		నిర్మాణం addrinfo *ai;

		ఒకవేళ (అక్షరశ్రేణి_పొడవు(name) > పరిమాణం(sunaddr->sun_మార్గం)) {
			error("%.100s: %.100s", name, strerror(ENAMETOOLONG));
			తిరిగి -1;
		}

		/*
		 * Fake up a struct addrinfo for AF_UNIX connections.
		 * free_connect_ctx() must check ai_family
		 * and use free() not freeaddrinfo() for AF_UNIX.
		 */
		ai = xcalloc(1, పరిమాణం(*ai) + పరిమాణం(*sunaddr));
		ai->ai_addr = (నిర్మాణం sockaddr *)(ai + 1);
		ai->ai_addrlen = పరిమాణం(*sunaddr);
		ai->ai_family = AF_UNIX;
		ai->ai_socktype = socktype;
		ai->ai_protocol = PF_UNSPEC;
		sunaddr = (నిర్మాణం sockaddr_un *)ai->ai_addr;
		sunaddr->sun_family = AF_UNIX;
		strlcpy(sunaddr->sun_మార్గం, name, పరిమాణం(sunaddr->sun_మార్గం));
		cctx->aitop = ai;
	} లేకపోతే {
		memset(&hints, 0, పరిమాణం(hints));
		hints.ai_family = ssh->chanctxt->IPv4or6;
		hints.ai_socktype = socktype;
		snprintf(strport, పరిమాణం strport, "%d", పోర్టు);
		ఒకవేళ ((gaierr = getaddrinfo(name, strport, &hints, &cctx->aitop))
		    != 0) {
			ఒకవేళ (errmsg != ఖాళీ)
				*errmsg = ssh_gai_strerror(gaierr);
			ఒకవేళ (reason != ఖాళీ)
				*reason = SSH2_OPEN_CONNECT_FAILED;
			error("connect_to %.100s: unknown host (%s)", name,
			    ssh_gai_strerror(gaierr));
			తిరిగి -1;
		}
	}

	cctx->host = xstrdup(name);
	cctx->పోర్టు = పోర్టు;
	cctx->ai = cctx->aitop;

	ఒకవేళ ((sock = connect_తదుపరి(ssh, cctx)) == -1) {
		error("connect to %.100s port %d failed: %s",
		    name, పోర్టు, strerror(errno));
		తిరిగి -1;
	}

	తిరిగి sock;
}

/* Return CONNECTING channel to remote host:port or local socket path */
స్థిర Channel *
connect_గమ్యం(నిర్మాణం ssh *ssh, స్థిరరాశి అక్షరం *host, పూర్ణాంకం పోర్టు,
    అక్షరం *ctype, అక్షరం *rname)
{
	నిర్మాణం channel_connect cctx;
	Channel *c;
	పూర్ణాంకం sock;

	memset(&cctx, 0, పరిమాణం(cctx));
	sock = connect_గమ్యం_helper(ssh, host, పోర్టు, SOCK_STREAM, ctype, rname,
	    &cctx, ఖాళీ, ఖాళీ);
	ఒకవేళ (sock == -1) {
		free_connect_ctx(&cctx);
		తిరిగి ఖాళీ;
	}
	c = channel_new(ssh, ctype, SSH_CHANNEL_CONNECTING, sock, sock, -1,
	    CHAN_TCP_కిటికీ_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, rname, 1);
	c->host_పోర్టు = పోర్టు;
	c->మార్గం = xstrdup(host);
	c->connect_ctx = xmalloc(పరిమాణం(cctx));
	జ్ఞాపకం_నకలు(c->connect_ctx, &cctx, పరిమాణం(cctx));

	తిరిగి c;
}

/*
 * returns either the newly connected channel or the downstream channel
 * that needs to deal with this connection.
 */
Channel *
channel_connect_by_listen_చిరునామా(నిర్మాణం ssh *ssh, స్థిరరాశి అక్షరం *listen_host,
    u_short listen_పోర్టు, అక్షరం *ctype, అక్షరం *rname)
{
	నిర్మాణం ssh_channels *sc = ssh->chanctxt;
	నిర్మాణం permission_సమితి *pset = &sc->local_perms;
	u_int i;
	నిర్మాణం permission *perm;

	కొరకు (i = 0; i < pset->అంకె_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		ఒకవేళ (open_listen_సరిపోలిక_tcpip(perm,
		    listen_host, listen_పోర్టు, 1)) {
			ఒకవేళ (perm->downstream)
				తిరిగి perm->downstream;
			ఒకవేళ (perm->పోర్టు_గమ్యం_connect == 0)
				తిరిగి rdynamic_connect_prepare(ssh,
				    ctype, rname);
			తిరిగి connect_గమ్యం(ssh,
			    perm->host_గమ్యం_connect, perm->పోర్టు_గమ్యం_connect,
			    ctype, rname);
		}
	}
	error("WARNING: Server requests forwarding for unknown listen_port %d",
	    listen_పోర్టు);
	తిరిగి ఖాళీ;
}

Channel *
channel_connect_by_listen_మార్గం(నిర్మాణం ssh *ssh, స్థిరరాశి అక్షరం *మార్గం,
    అక్షరం *ctype, అక్షరం *rname)
{
	నిర్మాణం ssh_channels *sc = ssh->chanctxt;
	నిర్మాణం permission_సమితి *pset = &sc->local_perms;
	u_int i;
	నిర్మాణం permission *perm;

	కొరకు (i = 0; i < pset->అంకె_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		ఒకవేళ (open_listen_సరిపోలిక_streamlocal(perm, మార్గం)) {
			తిరిగి connect_గమ్యం(ssh,
			    perm->host_గమ్యం_connect, perm->పోర్టు_గమ్యం_connect,
			    ctype, rname);
		}
	}
	error("WARNING: Server requests forwarding for unknown path %.100s",
	    మార్గం);
	తిరిగి ఖాళీ;
}

/* Check if connecting to that port is permitted and connect. */
Channel *
channel_connect_గమ్యం_పోర్టు(నిర్మాణం ssh *ssh, స్థిరరాశి అక్షరం *host, u_short పోర్టు,
    అక్షరం *ctype, అక్షరం *rname, పూర్ణాంకం *reason, స్థిరరాశి అక్షరం **errmsg)
{
	నిర్మాణం ssh_channels *sc = ssh->chanctxt;
	నిర్మాణం permission_సమితి *pset = &sc->local_perms;
	నిర్మాణం channel_connect cctx;
	Channel *c;
	u_int i, permit, permit_adm = 1;
	పూర్ణాంకం sock;
	నిర్మాణం permission *perm;

	permit = pset->all_permitted;
	ఒకవేళ (!permit) {
		కొరకు (i = 0; i < pset->అంకె_permitted_user; i++) {
			perm = &pset->permitted_user[i];
			ఒకవేళ (open_సరిపోలిక(perm, host, పోర్టు)) {
				permit = 1;
				ఆపు;
			}
		}
	}

	ఒకవేళ (pset->అంకె_permitted_admin > 0) {
		permit_adm = 0;
		కొరకు (i = 0; i < pset->అంకె_permitted_admin; i++) {
			perm = &pset->permitted_admin[i];
			ఒకవేళ (open_సరిపోలిక(perm, host, పోర్టు)) {
				permit_adm = 1;
				ఆపు;
			}
		}
	}

	ఒకవేళ (!permit || !permit_adm) {
		logit("Received request from %.100s port %d to connect to "
		    "host %.100s port %d, but the request was denied.",
		    ssh_remote_ipaddr(ssh), ssh_remote_పోర్టు(ssh), host, పోర్టు);
		ఒకవేళ (reason != ఖాళీ)
			*reason = SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED;
		తిరిగి ఖాళీ;
	}

	memset(&cctx, 0, పరిమాణం(cctx));
	sock = connect_గమ్యం_helper(ssh, host, పోర్టు, SOCK_STREAM, ctype, rname,
	    &cctx, reason, errmsg);
	ఒకవేళ (sock == -1) {
		free_connect_ctx(&cctx);
		తిరిగి ఖాళీ;
	}

	c = channel_new(ssh, ctype, SSH_CHANNEL_CONNECTING, sock, sock, -1,
	    CHAN_TCP_కిటికీ_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, rname, 1);
	c->host_పోర్టు = పోర్టు;
	c->మార్గం = xstrdup(host);
	c->connect_ctx = xmalloc(పరిమాణం(cctx));
	జ్ఞాపకం_నకలు(c->connect_ctx, &cctx, పరిమాణం(cctx));

	తిరిగి c;
}

/* Check if connecting to that path is permitted and connect. */
Channel *
channel_connect_గమ్యం_మార్గం(నిర్మాణం ssh *ssh, స్థిరరాశి అక్షరం *మార్గం,
    అక్షరం *ctype, అక్షరం *rname)
{
	నిర్మాణం ssh_channels *sc = ssh->chanctxt;
	నిర్మాణం permission_సమితి *pset = &sc->local_perms;
	u_int i, permit, permit_adm = 1;
	నిర్మాణం permission *perm;

	permit = pset->all_permitted;
	ఒకవేళ (!permit) {
		కొరకు (i = 0; i < pset->అంకె_permitted_user; i++) {
			perm = &pset->permitted_user[i];
			ఒకవేళ (open_సరిపోలిక(perm, మార్గం, పోర్టు_STREAMLOCAL)) {
				permit = 1;
				ఆపు;
			}
		}
	}

	ఒకవేళ (pset->అంకె_permitted_admin > 0) {
		permit_adm = 0;
		కొరకు (i = 0; i < pset->అంకె_permitted_admin; i++) {
			perm = &pset->permitted_admin[i];
			ఒకవేళ (open_సరిపోలిక(perm, మార్గం, పోర్టు_STREAMLOCAL)) {
				permit_adm = 1;
				ఆపు;
			}
		}
	}

	ఒకవేళ (!permit || !permit_adm) {
		logit("Received request to connect to path %.100s, "
		    "but the request was denied.", మార్గం);
		తిరిగి ఖాళీ;
	}
	తిరిగి connect_గమ్యం(ssh, మార్గం, పోర్టు_STREAMLOCAL, ctype, rname);
}

శూన్య
channel_send_కిటికీ_changes(నిర్మాణం ssh *ssh)
{
	నిర్మాణం ssh_channels *sc = ssh->chanctxt;
	నిర్మాణం winsize ws;
	పూర్ణాంకం r;
	u_int i;

	కొరకు (i = 0; i < sc->channels_alloc; i++) {
		ఒకవేళ (sc->channels[i] == ఖాళీ || !sc->channels[i]->client_tty ||
		    sc->channels[i]->type != SSH_CHANNEL_OPEN)
			కొనసాగు;
		ఒకవేళ (ioctl(sc->channels[i]->rfd, TIOCGWINSZ, &ws) == -1)
			కొనసాగు;
		channel_request_ప్రారంభం(ssh, i, "window-change", 0);
		ఒకవేళ ((r = sshpkt_put_u32(ssh, (u_int)ws.ws_నిలువు)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_అడ్డువరుస)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_xpixel)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_ypixel)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "channel %u; send window-change", i);
	}
}

/* Return RDYNAMIC_OPEN channel: channel allows SOCKS, but is not connected */
స్థిర Channel *
rdynamic_connect_prepare(నిర్మాణం ssh *ssh, అక్షరం *ctype, అక్షరం *rname)
{
	Channel *c;
	పూర్ణాంకం r;

	c = channel_new(ssh, ctype, SSH_CHANNEL_RDYNAMIC_OPEN, -1, -1, -1,
	    CHAN_TCP_కిటికీ_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, rname, 1);
	c->host_పోర్టు = 0;
	c->మార్గం = ఖాళీ;

	/*
	 * We need to open the channel before we have a FD,
	 * so that we can get SOCKS header from peer.
	 */
	ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh, SSH2_సందేశం_CHANNEL_OPEN_CONFIRMATION)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_కిటికీ)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0)
		fatal_fr(r, "channel %i; confirm", c->self);
	తిరిగి c;
}

/* Return CONNECTING socket to remote host:port or local socket path */
స్థిర పూర్ణాంకం
rdynamic_connect_ముగింపు(నిర్మాణం ssh *ssh, Channel *c)
{
	నిర్మాణం ssh_channels *sc = ssh->chanctxt;
	నిర్మాణం permission_సమితి *pset = &sc->local_perms;
	నిర్మాణం permission *perm;
	నిర్మాణం channel_connect cctx;
	u_int i, permit_adm = 1;
	పూర్ణాంకం sock;

	ఒకవేళ (pset->అంకె_permitted_admin > 0) {
		permit_adm = 0;
		కొరకు (i = 0; i < pset->అంకె_permitted_admin; i++) {
			perm = &pset->permitted_admin[i];
			ఒకవేళ (open_సరిపోలిక(perm, c->మార్గం, c->host_పోర్టు)) {
				permit_adm = 1;
				ఆపు;
			}
		}
	}
	ఒకవేళ (!permit_adm) {
		debug_f("requested forward not permitted");
		తిరిగి -1;
	}

	memset(&cctx, 0, పరిమాణం(cctx));
	sock = connect_గమ్యం_helper(ssh, c->మార్గం, c->host_పోర్టు, SOCK_STREAM, ఖాళీ,
	    ఖాళీ, &cctx, ఖాళీ, ఖాళీ);
	ఒకవేళ (sock == -1)
		free_connect_ctx(&cctx);
	లేకపోతే {
		/* similar to SSH_CHANNEL_CONNECTING but we've already sent the open */
		c->type = SSH_CHANNEL_RDYNAMIC_ముగింపు;
		c->connect_ctx = xmalloc(పరిమాణం(cctx));
		జ్ఞాపకం_నకలు(c->connect_ctx, &cctx, పరిమాణం(cctx));
		channel_రిజిస్టరు_fds(ssh, c, sock, sock, -1, 0, 1, 0);
	}
	తిరిగి sock;
}

/* -- X11 forwarding */

/*
 * Creates an internet domain socket for listening for X11 connections.
 * Returns 0 and a suitable display number for the DISPLAY variable
 * stored in display_numberp , or -1 if an error occurs.
 */
పూర్ణాంకం
x11_create_display_inet(నిర్మాణం ssh *ssh, పూర్ణాంకం x11_display_స్థానభ్రంశం,
    పూర్ణాంకం x11_use_localhost, పూర్ణాంకం single_connection,
    u_int *display_numberp, పూర్ణాంకం **chanids)
{
	Channel *nc = ఖాళీ;
	పూర్ణాంకం display_సంఖ్య, sock, పోర్టు;
	నిర్మాణం addrinfo hints, *ai, *aitop;
	అక్షరం strport[NI_MAXSERV];
	పూర్ణాంకం gaierr, n, అంకె_socks = 0, socks[అంకె_SOCKS];

	ఒకవేళ (chanids == ఖాళీ || x11_display_స్థానభ్రంశం < 0 ||
	    x11_display_స్థానభ్రంశం > UINT16_MAX - X11_పునాది_పోర్టు - MAX_DISPLAYS)
		తిరిగి -1;

	కొరకు (display_సంఖ్య = x11_display_స్థానభ్రంశం;
	    display_సంఖ్య < x11_display_స్థానభ్రంశం + MAX_DISPLAYS;
	    display_సంఖ్య++) {
		పోర్టు = X11_పునాది_పోర్టు + display_సంఖ్య;
		memset(&hints, 0, పరిమాణం(hints));
		hints.ai_family = ssh->chanctxt->IPv4or6;
		hints.ai_flags = x11_use_localhost ? 0: AI_PASSIVE;
		hints.ai_socktype = SOCK_STREAM;
		snprintf(strport, పరిమాణం strport, "%d", పోర్టు);
		ఒకవేళ ((gaierr = getaddrinfo(ఖాళీ, strport,
		    &hints, &aitop)) != 0) {
			error("getaddrinfo: %.100s", ssh_gai_strerror(gaierr));
			తిరిగి -1;
		}
		కొరకు (ai = aitop; ai; ai = ai->ai_next) {
			ఒకవేళ (ai->ai_family != AF_INET &&
			    ai->ai_family != AF_INET6)
				కొనసాగు;
			sock = socket(ai->ai_family, ai->ai_socktype,
			    ai->ai_protocol);
			ఒకవేళ (sock == -1) {
				ఒకవేళ ((errno != EINVAL) && (errno != EAFNOSUPPORT)
#నిర్వచితమైతే EPFNOSUPPORT
				    && (errno != EPFNOSUPPORT)
#అయితే_ముగింపు 
				    ) {
					error("socket: %.100s", strerror(errno));
					freeaddrinfo(aitop);
					తిరిగి -1;
				} లేకపోతే {
					debug("x11_create_display_inet: Socket family %d not supported",
						 ai->ai_family);
					కొనసాగు;
				}
			}
			ఒకవేళ (ai->ai_family == AF_INET6)
				sock_సమితి_v6only(sock);
			ఒకవేళ (x11_use_localhost)
				సమితి_reuseaddr(sock);
			ఒకవేళ (bind(sock, ai->ai_addr, ai->ai_addrlen) == -1) {
				debug2_f("bind port %d: %.100s", పోర్టు,
				    strerror(errno));
				close(sock);
				కొరకు (n = 0; n < అంకె_socks; n++)
					close(socks[n]);
				అంకె_socks = 0;
				ఆపు;
			}
			socks[అంకె_socks++] = sock;
			ఒకవేళ (అంకె_socks == అంకె_SOCKS)
				ఆపు;
		}
		freeaddrinfo(aitop);
		ఒకవేళ (అంకె_socks > 0)
			ఆపు;
	}
	ఒకవేళ (display_సంఖ్య >= x11_display_స్థానభ్రంశం + MAX_DISPLAYS) {
		error("Failed to allocate internet-domain X11 display socket.");
		తిరిగి -1;
	}
	/* Start listening for connections on the socket. */
	కొరకు (n = 0; n < అంకె_socks; n++) {
		sock = socks[n];
		ఒకవేళ (listen(sock, SSH_LISTEN_BACKLOG) == -1) {
			error("listen: %.100s", strerror(errno));
			close(sock);
			తిరిగి -1;
		}
	}

	/* Allocate a channel for each socket. */
	*chanids = xcalloc(అంకె_socks + 1, పరిమాణం(**chanids));
	కొరకు (n = 0; n < అంకె_socks; n++) {
		sock = socks[n];
		nc = channel_new(ssh, "x11-listener",
		    SSH_CHANNEL_X11_LISTENER, sock, sock, -1,
		    CHAN_X11_కిటికీ_DEFAULT, CHAN_X11_PACKET_DEFAULT,
		    0, "X11 inet listener", 1);
		nc->single_connection = single_connection;
		(*chanids)[n] = nc->self;
	}
	(*chanids)[n] = -1;

	/* Return the display number for the DISPLAY environment variable. */
	*display_numberp = display_సంఖ్య;
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
connect_local_xsocket_మార్గం(స్థిరరాశి అక్షరం *pathname)
{
	పూర్ణాంకం sock;
	నిర్మాణం sockaddr_un addr;

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	ఒకవేళ (sock == -1) {
		error("socket: %.100s", strerror(errno));
		తిరిగి -1;
	}
	memset(&addr, 0, పరిమాణం(addr));
	addr.sun_family = AF_UNIX;
	strlcpy(addr.sun_మార్గం, pathname, పరిమాణం addr.sun_మార్గం);
	ఒకవేళ (connect(sock, (నిర్మాణం sockaddr *)&addr, పరిమాణం(addr)) == 0)
		తిరిగి sock;
	close(sock);
	error("connect %.100s: %.100s", addr.sun_మార్గం, strerror(errno));
	తిరిగి -1;
}

స్థిర పూర్ణాంకం
connect_local_xsocket(u_int dnr)
{
	అక్షరం buf[1024];
	snprintf(buf, పరిమాణం buf, మార్గం_UNIX_X, dnr);
	తిరిగి connect_local_xsocket_మార్గం(buf);
}

#నిర్వచితమైతే __APPLE__
స్థిర పూర్ణాంకం
is_మార్గం_గమ్యం_xsocket(స్థిరరాశి అక్షరం *display, అక్షరం *మార్గం, కొలత_t pathlen)
{
	నిర్మాణం stat sbuf;

	ఒకవేళ (strlcpy(మార్గం, display, pathlen) >= pathlen) {
		error_f("display path too long");
		తిరిగి 0;
	}
	ఒకవేళ (display[0] != '/')
		తిరిగి 0;
	ఒకవేళ (stat(మార్గం, &sbuf) == 0) {
		తిరిగి 1;
	} లేకపోతే {
		అక్షరం *dot = strrchr(మార్గం, '.');
		ఒకవేళ (dot != ఖాళీ) {
			*dot = '\0';
			ఒకవేళ (stat(మార్గం, &sbuf) == 0) {
				తిరిగి 1;
			}
		}
	}
	తిరిగి 0;
}
#అయితే_ముగింపు

పూర్ణాంకం
x11_connect_display(నిర్మాణం ssh *ssh)
{
	u_int display_సంఖ్య;
	స్థిరరాశి అక్షరం *display;
	అక్షరం buf[1024], *cp;
	నిర్మాణం addrinfo hints, *ai, *aitop;
	అక్షరం strport[NI_MAXSERV];
	పూర్ణాంకం gaierr, sock = 0;

	/* Try to open a socket for the local X server. */
	display = getenv("DISPLAY");
	ఒకవేళ (!display) {
		error("DISPLAY not set.");
		తిరిగి -1;
	}
	/*
	 * Now we decode the value of the DISPLAY variable and make a
	 * connection to the real X server.
	 */

#నిర్వచితమైతే __APPLE__
	/* Check if display is a path to a socket (as set by launchd). */
	{
		అక్షరం మార్గం[PATH_MAX];

		ఒకవేళ (is_మార్గం_గమ్యం_xsocket(display, మార్గం, పరిమాణం(మార్గం))) {
			debug("x11_connect_display: $DISPLAY is launchd");

			/* Create a socket. */
			sock = connect_local_xsocket_మార్గం(మార్గం);
			ఒకవేళ (sock < 0)
				తిరిగి -1;

			/* OK, we now have a connection to the display. */
			తిరిగి sock;
		}
	}
#అయితే_ముగింపు
	/*
	 * Check if it is a unix domain socket.  Unix domain displays are in
	 * one of the following formats: unix:d[.s], :d[.s], ::d[.s]
	 */
	ఒకవేళ (అక్షరశ్రేణి_పోలిక(display, "unix:", 5) == 0 ||
	    display[0] == ':') {
		/* Connect to the unix domain socket. */
		ఒకవేళ (అక్షరశ్రేణి_చదువు(strrchr(display, ':') + 1, "%u",
		    &display_సంఖ్య) != 1) {
			error("Could not parse display number from DISPLAY: "
			    "%.100s", display);
			తిరిగి -1;
		}
		/* Create a socket. */
		sock = connect_local_xsocket(display_సంఖ్య);
		ఒకవేళ (sock < 0)
			తిరిగి -1;

		/* OK, we now have a connection to the display. */
		తిరిగి sock;
	}
	/*
	 * Connect to an inet socket.  The DISPLAY value is supposedly
	 * hostname:d[.s], where hostname may also be numeric IP address.
	 */
	strlcpy(buf, display, పరిమాణం(buf));
	cp = strchr(buf, ':');
	ఒకవేళ (!cp) {
		error("Could not find ':' in DISPLAY: %.100s", display);
		తిరిగి -1;
	}
	*cp = 0;
	/*
	 * buf now contains the host name.  But first we parse the
	 * display number.
	 */
	ఒకవేళ (అక్షరశ్రేణి_చదువు(cp + 1, "%u", &display_సంఖ్య) != 1 ||
	    display_సంఖ్య > UINT16_MAX - X11_పునాది_పోర్టు) {
		error("Could not parse display number from DISPLAY: %.100s",
		    display);
		తిరిగి -1;
	}

	/* Look up the host address */
	memset(&hints, 0, పరిమాణం(hints));
	hints.ai_family = ssh->chanctxt->IPv4or6;
	hints.ai_socktype = SOCK_STREAM;
	snprintf(strport, పరిమాణం strport, "%u", X11_పునాది_పోర్టు + display_సంఖ్య);
	ఒకవేళ ((gaierr = getaddrinfo(buf, strport, &hints, &aitop)) != 0) {
		error("%.100s: unknown host. (%s)", buf,
		ssh_gai_strerror(gaierr));
		తిరిగి -1;
	}
	కొరకు (ai = aitop; ai; ai = ai->ai_next) {
		/* Create a socket. */
		sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		ఒకవేళ (sock == -1) {
			debug2("socket: %.100s", strerror(errno));
			కొనసాగు;
		}
		/* Connect it to the display. */
		ఒకవేళ (connect(sock, ai->ai_addr, ai->ai_addrlen) == -1) {
			debug2("connect %.100s port %u: %.100s", buf,
			    X11_పునాది_పోర్టు + display_సంఖ్య, strerror(errno));
			close(sock);
			కొనసాగు;
		}
		/* Success */
		ఆపు;
	}
	freeaddrinfo(aitop);
	ఒకవేళ (!ai) {
		error("connect %.100s port %u: %.100s", buf,
		    X11_పునాది_పోర్టు + display_సంఖ్య, strerror(errno));
		తిరిగి -1;
	}
	సమితి_nodelay(sock);
	తిరిగి sock;
}

/*
 * Requests forwarding of X11 connections, generates fake authentication
 * data, and enables authentication spoofing.
 * This should be called in the client only.
 */
శూన్య
x11_request_forwarding_with_spoofing(నిర్మాణం ssh *ssh, పూర్ణాంకం client_session_id,
    స్థిరరాశి అక్షరం *disp, స్థిరరాశి అక్షరం *proto, స్థిరరాశి అక్షరం *దత్తాంశం, పూర్ణాంకం want_జవాబు)
{
	నిర్మాణం ssh_channels *sc = ssh->chanctxt;
	u_int దత్తాంశం_len = (u_int) అక్షరశ్రేణి_పొడవు(దత్తాంశం) / 2;
	u_int i, విలువ;
	స్థిరరాశి అక్షరం *cp;
	అక్షరం *new_దత్తాంశం;
	పూర్ణాంకం r, screen_సంఖ్య;

	ఒకవేళ (sc->x11_saved_display == ఖాళీ)
		sc->x11_saved_display = xstrdup(disp);
	లేకపోతే ఒకవేళ (strcmp(disp, sc->x11_saved_display) != 0) {
		error("x11_request_forwarding_with_spoofing: different "
		    "$DISPLAY already forwarded");
		తిరిగి;
	}

	cp = strchr(disp, ':');
	ఒకవేళ (cp)
		cp = strchr(cp, '.');
	ఒకవేళ (cp)
		screen_సంఖ్య = (u_int)strtonum(cp + 1, 0, 400, ఖాళీ);
	లేకపోతే
		screen_సంఖ్య = 0;

	ఒకవేళ (sc->x11_saved_proto == ఖాళీ) {
		/* Save protocol name. */
		sc->x11_saved_proto = xstrdup(proto);

		/* Extract real authentication data. */
		sc->x11_saved_దత్తాంశం = xmalloc(దత్తాంశం_len);
		కొరకు (i = 0; i < దత్తాంశం_len; i++) {
			ఒకవేళ (అక్షరశ్రేణి_చదువు(దత్తాంశం + 2 * i, "%2x", &విలువ) != 1) {
				fatal("x11_request_forwarding: bad "
				    "authentication data: %.100s", దత్తాంశం);
			}
			sc->x11_saved_దత్తాంశం[i] = విలువ;
		}
		sc->x11_saved_దత్తాంశం_len = దత్తాంశం_len;

		/* Generate fake data of the same length. */
		sc->x11_fake_దత్తాంశం = xmalloc(దత్తాంశం_len);
		arc4random_buf(sc->x11_fake_దత్తాంశం, దత్తాంశం_len);
		sc->x11_fake_దత్తాంశం_len = దత్తాంశం_len;
	}

	/* Convert the fake data into hex. */
	new_దత్తాంశం = tohex(sc->x11_fake_దత్తాంశం, దత్తాంశం_len);

	/* Send the request packet. */
	channel_request_ప్రారంభం(ssh, client_session_id, "x11-req", want_జవాబు);
	ఒకవేళ ((r = sshpkt_put_u8(ssh, 0)) != 0 || /* bool: single connection */
	    (r = sshpkt_put_cstring(ssh, proto)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, new_దత్తాంశం)) != 0 ||
	    (r = sshpkt_put_u32(ssh, screen_సంఖ్య)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send x11-req");
	విడుదల(new_దత్తాంశం);
}

/*
 * Returns whether an x11 channel was used recently (less than a second ago)
 */
పూర్ణాంకం
x11_channel_వాడిన_recently(నిర్మాణం ssh *ssh) {
	u_int i;
	Channel *c;
	ద్విగుణ lastused = 0;

	కొరకు (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		ఒకవేళ (c == ఖాళీ || c->ctype == ఖాళీ || c->lastused == 0.0 ||
		    strcmp(c->ctype, "x11-connection") != 0)
			కొనసాగు;
		ఒకవేళ (c->lastused > lastused)
			lastused = c->lastused;
	}
	తిరిగి lastused != 0.0 && monotime_double() <= lastused + 1.0;
}
