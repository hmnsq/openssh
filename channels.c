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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/stat.h>
#شامل <sys/ioctl.h>
#شامل <sys/un.h>
#شامل <sys/socket.h>
#شامل <sys/queue.h>

#شامل <netinet/in.h>
#شامل <arpa/inet.h>

#شامل <errno.h>
#شامل <fcntl.h>
#شامل <limits.h>
#شامل <netdb.h>
#شامل <poll.h>
#شامل <stdarg.h>
#شامل <stdint.h>
#شامل <stdio.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <termios.h>
#شامل <unistd.h>

#شامل "xmalloc.h"
#شامل "ssh.h"
#شامل "ssh2.h"
#شامل "ssherr.h"
#شامل "sshbuf.h"
#شامل "packet.h"
#شامل "log.h"
#شامل "misc.h"
#شامل "channels.h"
#شامل "compat.h"
#شامل "canohost.h"
#شامل "pathnames.h"
#شامل "match.h"

/* XXX remove once we're satisfied there's no lurking bugs */
/* #define DEBUG_CHANNEL_POLL 1 */

/* -- agent forwarding */
#تعریف_کرو	عدد_SOCKS	10

/* -- X11 forwarding */
/* X11 port for display :0 */
#تعریف_کرو X11_بنیاد_پورٹ	6000
/* Maximum number of fake X11 displays to try. */
#تعریف_کرو MAX_DISPLAYS  1000

/* Per-channel callback for pre/post IO actions */
قسمتعریف خالی chan_fn(ساخت ssh *, Channel *c);

/*
 * Data structure for storing which hosts are permitted for forward requests.
 * The local sides of any remote forwards are stored in this array to prevent
 * a corrupt remote server from accessing arbitrary TCP/IP ports on our local
 * network (which might be behind a firewall).
 */
/* XXX: streamlocal wants a path instead of host:port */
/*      Overload host_to_connect; we could just make this match Forward */
/*	XXX - can we use listen_host instead of listen_path? */
ساخت permission {
	حرف *host_مقصد_connect;		/* Connect to 'host'. */
	صحیح پورٹ_مقصد_connect;		/* Connect to 'port'. */
	حرف *listen_host;		/* Remote side should listen address. */
	حرف *listen_راستہ;		/* Remote side should listen path. */
	صحیح listen_پورٹ;		/* Remote side should listen port. */
	Channel *downstream;		/* Downstream mux*/
};

/* Context for non-blocking connects */
ساخت channel_connect {
	حرف *host;
	صحیح پورٹ;
	ساخت addrinfo *ai, *aitop;
};

/*
 * Stores the forwarding permission state for a single direction (local or
 * remote).
 */
ساخت permission_سیٹ {
	/*
	 * List of all local permitted host/port pairs to allow for the
	 * user.
	 */
	u_int عدد_permitted_user;
	ساخت permission *permitted_user;

	/*
	 * List of all permitted host/port pairs to allow for the admin.
	 */
	u_int عدد_permitted_admin;
	ساخت permission *permitted_admin;

	/*
	 * If this is true, all opens/listens are permitted.  This is the
	 * case on the server on which we have to trust the client anyway,
	 * and the user could do anything after logging in.
	 */
	صحیح all_permitted;
};

/* Used to record timeouts per channel type */
ساخت ssh_channel_timeout {
	حرف *type_نمونہ;
	دوہرا timeout_secs;
};

/* Master structure for channels state */
ساخت ssh_channels {
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
	ساخت permission_سیٹ local_perms;
	ساخت permission_سیٹ remote_perms;

	/* -- X11 forwarding */

	/* Saved X11 local (client) display. */
	حرف *x11_saved_display;

	/* Saved X11 authentication protocol name. */
	حرف *x11_saved_proto;

	/* Saved X11 authentication data.  This is the real data. */
	حرف *x11_saved_ڈیٹا;
	u_int x11_saved_ڈیٹا_len;

	/* Deadline after which all X11 connections are refused */
	دوہرا x11_refuse_وقت;

	/*
	 * Fake X11 authentication data.  This is what the server will be
	 * sending us; we should replace any occurrences of this by the
	 * real data.
	 */
	u_char *x11_fake_ڈیٹا;
	u_int x11_fake_ڈیٹا_len;

	/* AF_UNSPEC or AF_INET or AF_INET6 */
	صحیح IPv4or6;

	/* Set SO_KEEPALIVE on TCP connections */
	صحیح want_tcp_keepalive;

	/* Channel timeouts by type */
	ساخت ssh_channel_timeout *timeouts;
	سائز_t ntimeouts;
	/* Global timeout for all OPEN channels */
	دوہرا global_deadline;
	دوہرا lastused;
	/* pattern-lists used to classify channels as bulk */
	حرف *bulk_classifier_tty, *bulk_classifier_notty;
	/* Number of active bulk channels (set by channel_handler) */
	u_int nbulk;
};

/* helper */
ساکن خالی پورٹ_open_helper(ساخت ssh *ssh, Channel *c, حرف *rtype);
ساکن ثابت حرف *channel_rfwd_bind_host(ثابت حرف *listen_host);

/* non-blocking connect helpers */
ساکن صحیح connect_اگلا(ساخت ssh *, ساخت channel_connect *);
ساکن Channel *rdynamic_connect_prepare(ساخت ssh *, حرف *, حرف *);
ساکن صحیح rdynamic_connect_اختتام(ساخت ssh *, Channel *);

/* Setup helper */
ساکن خالی channel_handler_init(ساخت ssh_channels *sc);

/* -- channel core */

خالی
channel_init_channels(ساخت ssh *ssh)
{
	ساخت ssh_channels *sc;

	اگر ((sc = صفر_حافظہ_دو(1, حجم(*sc))) == تہی)
		fatal_f("allocation failed");
	sc->channels_alloc = 10;
	sc->channels = xcalloc(sc->channels_alloc, حجم(*sc->channels));
	sc->IPv4or6 = AF_UNSPEC;
	sc->bulk_classifier_tty = xstrdup(CHANNEL_BULK_TTY);
	sc->bulk_classifier_notty = xstrdup(CHANNEL_BULK_NOTTY);
	channel_handler_init(sc);

	ssh->chanctxt = sc;
}

Channel *
channel_by_id(ساخت ssh *ssh, صحیح id)
{
	Channel *c;

	اگر (id < 0 || (u_int)id >= ssh->chanctxt->channels_alloc) {
		logit_f("%d: bad id", id);
		واپس تہی;
	}
	c = ssh->chanctxt->channels[id];
	اگر (c == تہی) {
		logit_f("%d: bad id: channel free", id);
		واپس تہی;
	}
	واپس c;
}

Channel *
channel_by_remote_id(ساخت ssh *ssh, u_int remote_id)
{
	Channel *c;
	u_int i;

	برائے (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		اگر (c != تہی && c->have_remote_id && c->remote_id == remote_id)
			واپس c;
	}
	واپس تہی;
}

/*
 * Returns the channel if it is allowed to receive protocol messages.
 * Private channels, like listening sockets, may not receive messages.
 */
Channel *
channel_lookup(ساخت ssh *ssh, صحیح id)
{
	Channel *c;

	اگر ((c = channel_by_id(ssh, id)) == تہی)
		واپس تہی;

	انتخاب (c->type) {
	حالت SSH_CHANNEL_X11_OPEN:
	حالت SSH_CHANNEL_LARVAL:
	حالت SSH_CHANNEL_CONNECTING:
	حالت SSH_CHANNEL_DYNAMIC:
	حالت SSH_CHANNEL_RDYNAMIC_OPEN:
	حالت SSH_CHANNEL_RDYNAMIC_اختتام:
	حالت SSH_CHANNEL_OPENING:
	حالت SSH_CHANNEL_OPEN:
	حالت SSH_CHANNEL_ABANDONED:
	حالت SSH_CHANNEL_MUX_PROXY:
		واپس c;
	}
	logit("Non-public channel %d, type %d.", id, c->type);
	واپس تہی;
}

ساکن خالی
free_connect_ctx(ساخت channel_connect *cctx)
{
	آزاد(cctx->host);
	اگر (cctx->aitop) {
		اگر (cctx->aitop->ai_family == AF_UNIX)
			آزاد(cctx->aitop);
		ورنہ
			freeaddrinfo(cctx->aitop);
	}
	memset(cctx, 0, حجم(*cctx));
}

ساکن خالی
channel_free_connect_ctx(Channel *c)
{
	اگر (c == تہی || c->connect_ctx == تہی)
		واپس;
	free_connect_ctx(c->connect_ctx);
	آزاد(c->connect_ctx);
	c->connect_ctx = تہی;
}

/* Enable/disable TCP keepalives for X11 and port-forwarding sockets */
خالی
channel_سیٹ_tcp_keepalives(ساخت ssh *ssh, صحیح on)
{
	ssh->chanctxt->want_tcp_keepalive = on;
}

/*
 * Add a timeout for open channels whose c->ctype (or c->xctype if it is set)
 * match type_pattern.
 */
خالی
channel_جوڑو_timeout(ساخت ssh *ssh, ثابت حرف *type_نمونہ,
    دوہرا timeout_secs)
{
	ساخت ssh_channels *sc = ssh->chanctxt;

	اگر (strcmp(type_نمونہ, "global") == 0) {
		debug2_f("global channel timeout %f seconds", timeout_secs);
		sc->global_deadline = timeout_secs;
		واپس;
	}
	debug2_f("channel type \"%s\" timeout %f seconds",
	    type_نمونہ, timeout_secs);
	sc->timeouts = xrecallocarray(sc->timeouts, sc->ntimeouts,
	    sc->ntimeouts + 1, حجم(*sc->timeouts));
	sc->timeouts[sc->ntimeouts].type_نمونہ = xstrdup(type_نمونہ);
	sc->timeouts[sc->ntimeouts].timeout_secs = timeout_secs;
	sc->ntimeouts++;
}

/* Clears all previously-added channel timeouts */
خالی
channel_clear_timeouts(ساخت ssh *ssh)
{
	ساخت ssh_channels *sc = ssh->chanctxt;
	سائز_t i;

	debug3_f("clearing");
	برائے (i = 0; i < sc->ntimeouts; i++)
		آزاد(sc->timeouts[i].type_نمونہ);
	آزاد(sc->timeouts);
	sc->timeouts = تہی;
	sc->ntimeouts = 0;
}

ساکن دوہرا
lookup_timeout(ساخت ssh *ssh, ثابت حرف *type)
{
	ساخت ssh_channels *sc = ssh->chanctxt;
	سائز_t i;

	برائے (i = 0; i < sc->ntimeouts; i++) {
		اگر (مطابقت_نمونہ(type, sc->timeouts[i].type_نمونہ))
			واپس sc->timeouts[i].timeout_secs;
	}

	واپس 0;
}

ساکن خالی
channel_classify(ساخت ssh *ssh, Channel *c)
{
	ساخت ssh_channels *sc = ssh->chanctxt;
	ثابت حرف *type = c->xctype == تہی ? c->ctype : c->xctype;
	ثابت صحیح has_tty = c->isatty || c->remote_has_tty;
	ثابت حرف *classifier = has_tty ?
	    sc->bulk_classifier_tty : sc->bulk_classifier_notty;

	c->bulk = type != تہی && مطابقت_نمونہ_list(type, classifier, 0) == 1;
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
خالی
channel_سیٹ_xtype(ساخت ssh *ssh, صحیح id, ثابت حرف *xctype)
{
	ساخت ssh_channels *sc = ssh->chanctxt;
	Channel *c;

	اگر ((c = channel_by_id(ssh, id)) == تہی)
		fatal_f("missing channel %d", id);
	اگر (c->xctype != تہی)
		آزاد(c->xctype);
	c->xctype = xstrdup(xctype);
	/* Only override deadline if xctype has a more specific match. */
	دوہرا xtype_deadline = lookup_timeout(ssh, c->xctype);
	اگر (xtype_deadline != 0)
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
ساکن خالی
channel_سیٹ_مستعمل_وقت(ساخت ssh *ssh, Channel *c)
{
	ssh->chanctxt->lastused = monotime_double();
	اگر (c != تہی)
		c->lastused = ssh->chanctxt->lastused;
}

/*
 * Get the time at which a channel is due to time out for inactivity.
 * Returns 0 if the channel is not due to time out ever.
 */
ساکن دوہرا
channel_get_expiry(ساخت ssh *ssh, Channel *c)
{
	ساخت ssh_channels *sc = ssh->chanctxt;
	دوہرا expiry = 0, channel_expiry;

	اگر (sc->lastused != 0 && sc->global_deadline != 0)
		expiry = sc->lastused + sc->global_deadline;
	اگر (c->lastused != 0 && c->inactive_deadline != 0) {
		channel_expiry = c->lastused + c->inactive_deadline;
		اگر (expiry == 0 || channel_expiry < expiry)
			expiry = channel_expiry;
	}
	واپس expiry;
}

/* Returns non-zero if there is an open, non-interactive channel */
صحیح
channel_has_bulk(ساخت ssh *ssh)
{
	واپس ssh->chanctxt != تہی && ssh->chanctxt->nbulk != 0;
}

/*
 * Register filedescriptors for a channel, used when allocating a channel or
 * when the channel consumer/producer is ready, e.g. shell exec'd
 */
ساکن خالی
channel_رجسٹر_fds(ساخت ssh *ssh, Channel *c, صحیح rfd, صحیح wfd, صحیح efd,
    صحیح extusage, صحیح nonblock, صحیح is_tty)
{
	صحیح val;

	اگر (rfd != -1)
		(خالی)fcntl(rfd, F_SETFD, FD_CLOEXEC);
	اگر (wfd != -1 && wfd != rfd)
		(خالی)fcntl(wfd, F_SETFD, FD_CLOEXEC);
	اگر (efd != -1 && efd != rfd && efd != wfd)
		(خالی)fcntl(efd, F_SETFD, FD_CLOEXEC);

	c->rfd = rfd;
	c->wfd = wfd;
	c->sock = (rfd == wfd) ? rfd : -1;
	c->efd = efd;
	c->extended_usage = extusage;

	اگر ((c->isatty = is_tty) != 0)
		debug2("channel %d: rfd %d isatty", c->self, c->rfd);
#اگر_تعریف_شدہ _AIX
	/* XXX: Later AIX versions can't push as much data to tty */
	c->wfd_isatty = is_tty || isatty(c->wfd);
#اگر_ختم

	/* enable nonblocking mode */
	c->restore_بلاک = 0;
	اگر (nonblock == CHANNEL_NONBLOCK_STDIO) {
		/*
		 * Special handling for stdio file descriptors: do not set
		 * non-blocking mode if they are TTYs. Otherwise prepare to
		 * restore their blocking state on exit to avoid interfering
		 * with other programs that follow.
		 */
		اگر (rfd != -1 && !isatty(rfd) &&
		    (val = fcntl(rfd, F_GETFL)) != -1 && !(val & O_NONBLOCK)) {
			c->restore_flags[0] = val;
			c->restore_بلاک |= CHANNEL_RESTORE_RFD;
			سیٹ_nonblock(rfd);
		}
		اگر (wfd != -1 && !isatty(wfd) &&
		    (val = fcntl(wfd, F_GETFL)) != -1 && !(val & O_NONBLOCK)) {
			c->restore_flags[1] = val;
			c->restore_بلاک |= CHANNEL_RESTORE_WFD;
			سیٹ_nonblock(wfd);
		}
		اگر (efd != -1 && !isatty(efd) &&
		    (val = fcntl(efd, F_GETFL)) != -1 && !(val & O_NONBLOCK)) {
			c->restore_flags[2] = val;
			c->restore_بلاک |= CHANNEL_RESTORE_EFD;
			سیٹ_nonblock(efd);
		}
	} ورنہ اگر (nonblock) {
		اگر (rfd != -1)
			سیٹ_nonblock(rfd);
		اگر (wfd != -1)
			سیٹ_nonblock(wfd);
		اگر (efd != -1)
			سیٹ_nonblock(efd);
	}
	/* channel might be entering a larval state, so reset global timeout */
	channel_سیٹ_مستعمل_وقت(ssh, تہی);
	channel_classify(ssh, c);
}

/*
 * Allocate a new channel object and set its type and socket.
 */
Channel *
channel_new(ساخت ssh *ssh, حرف *ctype, صحیح type, صحیح rfd, صحیح wfd, صحیح efd,
    u_int کھڑکی, u_int maxpack, صحیح extusage, ثابت حرف *remote_name,
    صحیح nonblock)
{
	ساخت ssh_channels *sc = ssh->chanctxt;
	u_int i, ملا = 0;
	Channel *c;
	صحیح r;

	/* Try to find a free slot where to put the new channel. */
	برائے (i = 0; i < sc->channels_alloc; i++) {
		اگر (sc->channels[i] == تہی) {
			/* Found a free slot. */
			ملا = i;
			توڑو;
		}
	}
	اگر (i >= sc->channels_alloc) {
		/*
		 * There are no free slots. Take last+1 slot and expand
		 * the array.
		 */
		ملا = sc->channels_alloc;
		اگر (sc->channels_alloc > CHANNELS_MAX_CHANNELS)
			fatal_f("internal error: channels_alloc %d too big",
			    sc->channels_alloc);
		sc->channels = xrecallocarray(sc->channels, sc->channels_alloc,
		    sc->channels_alloc + 10, حجم(*sc->channels));
		sc->channels_alloc += 10;
		debug2("channel: expanding %d", sc->channels_alloc);
	}
	/* Initialize and return new channel. */
	c = sc->channels[ملا] = xcalloc(1, حجم(Channel));
	اگر ((c->داخلہ = sshbuf_new()) == تہی ||
	    (c->output = sshbuf_new()) == تہی ||
	    (c->extended = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshbuf_سیٹ_max_سائز(c->داخلہ, CHAN_داخلہ_MAX)) != 0)
		fatal_fr(r, "sshbuf_set_max_size");
	c->ostate = CHAN_OUTPUT_OPEN;
	c->istate = CHAN_داخلہ_OPEN;
	channel_رجسٹر_fds(ssh, c, rfd, wfd, efd, extusage, nonblock, 0);
	c->self = ملا;
	c->type = type;
	c->ctype = ctype;
	c->local_کھڑکی = کھڑکی;
	c->local_کھڑکی_max = کھڑکی;
	c->local_maxpacket = maxpack;
	c->remote_name = xstrdup(remote_name);
	c->ctl_chan = -1;
	c->delayed = 1;		/* prevent call to channel_post handler */
	c->inactive_deadline = lookup_timeout(ssh, c->ctype);
	TAILQ_INIT(&c->حالت_confirms);
	channel_classify(ssh, c);
	debug("channel %d: new %s [%s] (inactive timeout: %f)",
	    ملا, c->ctype, remote_name, c->inactive_deadline != 0.0 ?
	    c->inactive_deadline : sc->global_deadline);
	واپس c;
}

خالی
channel_سیٹ_tty(ساخت ssh *ssh, Channel *c)
{
	c->remote_has_tty = 1;
	channel_classify(ssh, c);
}

صحیح
channel_close_fd(ساخت ssh *ssh, Channel *c, صحیح *fdp)
{
	صحیح ret, fd = *fdp;

	اگر (fd == -1)
		واپس 0;

	/* restore blocking */
	اگر (*fdp == c->rfd &&
	    (c->restore_بلاک & CHANNEL_RESTORE_RFD) != 0)
		(خالی)fcntl(*fdp, F_SETFL, c->restore_flags[0]);
	ورنہ اگر (*fdp == c->wfd &&
	    (c->restore_بلاک & CHANNEL_RESTORE_WFD) != 0)
		(خالی)fcntl(*fdp, F_SETFL, c->restore_flags[1]);
	ورنہ اگر (*fdp == c->efd &&
	    (c->restore_بلاک & CHANNEL_RESTORE_EFD) != 0)
		(خالی)fcntl(*fdp, F_SETFL, c->restore_flags[2]);

	اگر (*fdp == c->rfd) {
		c->io_want &= ~SSH_CHAN_IO_RFD;
		c->io_ready &= ~SSH_CHAN_IO_RFD;
		c->rfd = -1;
		c->pfds[0] = -1;
	}
	اگر (*fdp == c->wfd) {
		c->io_want &= ~SSH_CHAN_IO_WFD;
		c->io_ready &= ~SSH_CHAN_IO_WFD;
		c->wfd = -1;
		c->pfds[1] = -1;
	}
	اگر (*fdp == c->efd) {
		c->io_want &= ~SSH_CHAN_IO_EFD;
		c->io_ready &= ~SSH_CHAN_IO_EFD;
		c->efd = -1;
		c->pfds[2] = -1;
	}
	اگر (*fdp == c->sock) {
		c->io_want &= ~SSH_CHAN_IO_SOCK;
		c->io_ready &= ~SSH_CHAN_IO_SOCK;
		c->sock = -1;
		c->pfds[3] = -1;
	}

	ret = close(fd);
	*fdp = -1; /* probably redundant */
	واپس ret;
}

/* Close all channel fd/socket. */
ساکن خالی
channel_close_fds(ساخت ssh *ssh, Channel *c)
{
	صحیح sock = c->sock, rfd = c->rfd, wfd = c->wfd, efd = c->efd;

	channel_close_fd(ssh, c, &c->sock);
	اگر (rfd != sock)
		channel_close_fd(ssh, c, &c->rfd);
	اگر (wfd != sock && wfd != rfd)
		channel_close_fd(ssh, c, &c->wfd);
	اگر (efd != sock && efd != rfd && efd != wfd)
		channel_close_fd(ssh, c, &c->efd);
}

ساکن خالی
fwd_perm_clear(ساخت permission *perm)
{
	آزاد(perm->host_مقصد_connect);
	آزاد(perm->listen_host);
	آزاد(perm->listen_راستہ);
	memset(perm, 0, حجم(*perm));
}

/* Returns an printable name for the specified forwarding permission list */
ساکن ثابت حرف *
fwd_ident(صحیح who, صحیح where)
{
	اگر (who == FORWARD_ADM) {
		اگر (where == FORWARD_LOCAL)
			واپس "admin local";
		ورنہ اگر (where == FORWARD_REMOTE)
			واپس "admin remote";
	} ورنہ اگر (who == FORWARD_USER) {
		اگر (where == FORWARD_LOCAL)
			واپس "user local";
		ورنہ اگر (where == FORWARD_REMOTE)
			واپس "user remote";
	}
	fatal("Unknown forward permission list %d/%d", who, where);
}

/* Returns the forwarding permission list for the specified direction */
ساکن ساخت permission_سیٹ *
permission_سیٹ_get(ساخت ssh *ssh, صحیح where)
{
	ساخت ssh_channels *sc = ssh->chanctxt;

	انتخاب (where) {
	حالت FORWARD_LOCAL:
		واپس &sc->local_perms;
		توڑو;
	حالت FORWARD_REMOTE:
		واپس &sc->remote_perms;
		توڑو;
	طےشدہ:
		fatal_f("invalid forwarding direction %d", where);
	}
}

/* Returns pointers to the specified forwarding list and its element count */
ساکن خالی
permission_سیٹ_get_array(ساخت ssh *ssh, صحیح who, صحیح where,
    ساخت permission ***permpp, u_int **npermpp)
{
	ساخت permission_سیٹ *pset = permission_سیٹ_get(ssh, where);

	انتخاب (who) {
	حالت FORWARD_USER:
		*permpp = &pset->permitted_user;
		*npermpp = &pset->عدد_permitted_user;
		توڑو;
	حالت FORWARD_ADM:
		*permpp = &pset->permitted_admin;
		*npermpp = &pset->عدد_permitted_admin;
		توڑو;
	طےشدہ:
		fatal_f("invalid forwarding client %d", who);
	}
}

/* Adds an entry to the specified forwarding list */
ساکن صحیح
permission_سیٹ_جوڑو(ساخت ssh *ssh, صحیح who, صحیح where,
    ثابت حرف *host_مقصد_connect, صحیح پورٹ_مقصد_connect,
    ثابت حرف *listen_host, ثابت حرف *listen_راستہ, صحیح listen_پورٹ,
    Channel *downstream)
{
	ساخت permission **permp;
	u_int n, *npermp;

	permission_سیٹ_get_array(ssh, who, where, &permp, &npermp);

	اگر (*npermp >= زیادہ_سے_زیادہ_عدد)
		fatal_f("%s overflow", fwd_ident(who, where));

	*permp = xrecallocarray(*permp, *npermp, *npermp + 1, حجم(**permp));
	n = (*npermp)++;
#تعریف_کرو MAYBE_DUP(s) ((s == تہی) ? تہی : xstrdup(s))
	(*permp)[n].host_مقصد_connect = MAYBE_DUP(host_مقصد_connect);
	(*permp)[n].پورٹ_مقصد_connect = پورٹ_مقصد_connect;
	(*permp)[n].listen_host = MAYBE_DUP(listen_host);
	(*permp)[n].listen_راستہ = MAYBE_DUP(listen_راستہ);
	(*permp)[n].listen_پورٹ = listen_پورٹ;
	(*permp)[n].downstream = downstream;
#تعریف_منسوخ MAYBE_DUP
	واپس (صحیح)n;
}

ساکن خالی
mux_remove_remote_forwardings(ساخت ssh *ssh, Channel *c)
{
	ساخت ssh_channels *sc = ssh->chanctxt;
	ساخت permission_سیٹ *pset = &sc->local_perms;
	ساخت permission *perm;
	صحیح r;
	u_int i;

	برائے (i = 0; i < pset->عدد_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		اگر (perm->downstream != c)
			جاری;

		/* cancel on the server, since mux client is gone */
		debug("channel %d: cleanup remote forward for %s:%u",
		    c->self, perm->listen_host, perm->listen_پورٹ);
		اگر ((r = sshpkt_آغاز(ssh, SSH2_پیغام_GLOBAL_REQUEST)) != 0 ||
		    (r = sshpkt_put_cstring(ssh,
		    "cancel-tcpip-forward")) != 0 ||
		    (r = sshpkt_put_u8(ssh, 0)) != 0 ||
		    (r = sshpkt_put_cstring(ssh,
		    channel_rfwd_bind_host(perm->listen_host))) != 0 ||
		    (r = sshpkt_put_u32(ssh, perm->listen_پورٹ)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0) {
			fatal_fr(r, "channel %i", c->self);
		}
		fwd_perm_clear(perm); /* unregister */
	}
}

/* Free the channel and close its fd/socket. */
خالی
channel_free(ساخت ssh *ssh, Channel *c)
{
	ساخت ssh_channels *sc = ssh->chanctxt;
	حرف *s;
	u_int i, n;
	Channel *other;
	ساخت channel_confirm *cc;

	برائے (n = 0, i = 0; i < sc->channels_alloc; i++) {
		اگر ((other = sc->channels[i]) == تہی)
			جاری;
		n++;
		/* detach from mux client and prepare for closing */
		اگر (c->type == SSH_CHANNEL_MUX_CLIENT &&
		    other->type == SSH_CHANNEL_MUX_PROXY &&
		    other->mux_ctx == c) {
			other->mux_ctx = تہی;
			other->type = SSH_CHANNEL_OPEN;
			other->istate = CHAN_داخلہ_CLOSED;
			other->ostate = CHAN_OUTPUT_CLOSED;
		}
	}
	debug("channel %d: free: %s, nchannels %u", c->self,
	    c->remote_name ? c->remote_name : "???", n);

	اگر (c->type == SSH_CHANNEL_MUX_CLIENT) {
		mux_remove_remote_forwardings(ssh, c);
		آزاد(c->mux_ctx);
		c->mux_ctx = تہی;
	} ورنہ اگر (c->type == SSH_CHANNEL_MUX_LISTENER) {
		آزاد(c->mux_ctx);
		c->mux_ctx = تہی;
	}

	اگر (log_level_get() >= SYSLOG_LEVEL_DEBUG3) {
		s = channel_open_پیغام(ssh);
		debug3("channel %d: status: %s", c->self, s);
		آزاد(s);
	}

	channel_close_fds(ssh, c);
	sshbuf_free(c->داخلہ);
	sshbuf_free(c->output);
	sshbuf_free(c->extended);
	c->داخلہ = c->output = c->extended = تہی;
	آزاد(c->remote_name);
	c->remote_name = تہی;
	آزاد(c->راستہ);
	c->راستہ = تہی;
	آزاد(c->listening_addr);
	c->listening_addr = تہی;
	آزاد(c->xctype);
	c->xctype = تہی;
	channel_free_connect_ctx(c);
	جب ((cc = TAILQ_FIRST(&c->حالت_confirms)) != تہی) {
		اگر (cc->abandon_cb != تہی)
			cc->abandon_cb(ssh, c, cc->ctx);
		TAILQ_REMOVE(&c->حالت_confirms, cc, اندراج_2);
		freezero(cc, حجم(*cc));
	}
	اگر (c->filter_cleanup != تہی && c->filter_ctx != تہی)
		c->filter_cleanup(ssh, c->self, c->filter_ctx);
	sc->channels[c->self] = تہی;
	freezero(c, حجم(*c));
}

خالی
channel_free_all(ساخت ssh *ssh)
{
	u_int i;
	ساخت ssh_channels *sc = ssh->chanctxt;

	برائے (i = 0; i < sc->channels_alloc; i++)
		اگر (sc->channels[i] != تہی)
			channel_free(ssh, sc->channels[i]);

	آزاد(sc->channels);
	sc->channels = تہی;
	sc->channels_alloc = 0;

	آزاد(sc->x11_saved_display);
	sc->x11_saved_display = تہی;

	آزاد(sc->x11_saved_proto);
	sc->x11_saved_proto = تہی;

	آزاد(sc->x11_saved_ڈیٹا);
	sc->x11_saved_ڈیٹا = تہی;
	sc->x11_saved_ڈیٹا_len = 0;

	آزاد(sc->x11_fake_ڈیٹا);
	sc->x11_fake_ڈیٹا = تہی;
	sc->x11_fake_ڈیٹا_len = 0;
}

خالی
channel_free_channels(ساخت ssh *ssh)
{
	ساخت ssh_channels *sc;

	اگر (ssh == تہی || ssh->chanctxt == تہی)
		واپس;
	channel_free_all(ssh);
	channel_clear_permission(ssh, FORWARD_USER, FORWARD_LOCAL);
	channel_clear_permission(ssh, FORWARD_USER, FORWARD_REMOTE);
	channel_clear_permission(ssh, FORWARD_ADM, FORWARD_LOCAL);
	channel_clear_permission(ssh, FORWARD_ADM, FORWARD_REMOTE);
	sc = ssh->chanctxt;
	آزاد(sc->bulk_classifier_tty);
	آزاد(sc->bulk_classifier_notty);
	آزاد(sc->channel_pre);
	آزاد(sc->channel_post);
	freezero(sc, حجم(*sc));
	ssh->chanctxt = تہی;
}

/*
 * Closes the sockets/fds of all channels.  This is used to close extra file
 * descriptors after a fork.
 */
خالی
channel_close_all(ساخت ssh *ssh)
{
	u_int i;

	برائے (i = 0; i < ssh->chanctxt->channels_alloc; i++)
		اگر (ssh->chanctxt->channels[i] != تہی)
			channel_close_fds(ssh, ssh->chanctxt->channels[i]);
}

/*
 * Stop listening to channels.
 */
خالی
channel_stop_listening(ساخت ssh *ssh)
{
	u_int i;
	Channel *c;

	برائے (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		اگر (c != تہی) {
			انتخاب (c->type) {
			حالت SSH_CHANNEL_AUTH_SOCKET:
			حالت SSH_CHANNEL_پورٹ_LISTENER:
			حالت SSH_CHANNEL_RPORT_LISTENER:
			حالت SSH_CHANNEL_X11_LISTENER:
			حالت SSH_CHANNEL_UNIX_LISTENER:
			حالت SSH_CHANNEL_RUNIX_LISTENER:
				channel_close_fd(ssh, c, &c->sock);
				channel_free(ssh, c);
				توڑو;
			}
		}
	}
}

/*
 * Returns true if no channel has too much buffered data, and false if one or
 * more channel is overfull.
 */
صحیح
channel_not_very_much_buffered_ڈیٹا(ساخت ssh *ssh)
{
	u_int i;
	u_int maxsize = ssh_packet_get_maxsize(ssh);
	Channel *c;

	برائے (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		اگر (c == تہی || c->type != SSH_CHANNEL_OPEN)
			جاری;
		اگر (sshbuf_len(c->output) > maxsize) {
			debug2("channel %d: big output buffer %zu > %u",
			    c->self, sshbuf_len(c->output), maxsize);
			واپس 0;
		}
	}
	واپس 1;
}

/* Returns true if any channel is still open. */
صحیح
channel_still_open(ساخت ssh *ssh)
{
	u_int i;
	Channel *c;

	برائے (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		اگر (c == تہی)
			جاری;
		انتخاب (c->type) {
		حالت SSH_CHANNEL_X11_LISTENER:
		حالت SSH_CHANNEL_پورٹ_LISTENER:
		حالت SSH_CHANNEL_RPORT_LISTENER:
		حالت SSH_CHANNEL_MUX_LISTENER:
		حالت SSH_CHANNEL_CLOSED:
		حالت SSH_CHANNEL_AUTH_SOCKET:
		حالت SSH_CHANNEL_DYNAMIC:
		حالت SSH_CHANNEL_RDYNAMIC_OPEN:
		حالت SSH_CHANNEL_CONNECTING:
		حالت SSH_CHANNEL_ZOMBIE:
		حالت SSH_CHANNEL_ABANDONED:
		حالت SSH_CHANNEL_UNIX_LISTENER:
		حالت SSH_CHANNEL_RUNIX_LISTENER:
			جاری;
		حالت SSH_CHANNEL_LARVAL:
			جاری;
		حالت SSH_CHANNEL_OPENING:
		حالت SSH_CHANNEL_OPEN:
		حالت SSH_CHANNEL_RDYNAMIC_اختتام:
		حالت SSH_CHANNEL_X11_OPEN:
		حالت SSH_CHANNEL_MUX_CLIENT:
		حالت SSH_CHANNEL_MUX_PROXY:
			واپس 1;
		طےشدہ:
			fatal_f("bad channel type %d", c->type);
			/* NOTREACHED */
		}
	}
	واپس 0;
}

/* Returns true if a channel with a TTY is open. */
صحیح
channel_tty_open(ساخت ssh *ssh)
{
	u_int i;
	Channel *c;

	برائے (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		اگر (c == تہی || c->type != SSH_CHANNEL_OPEN)
			جاری;
		اگر (c->client_tty)
			واپس 1;
	}
	واپس 0;
}

/* Returns the id of an open channel suitable for keepaliving */
صحیح
channel_ڈھونڈو_open(ساخت ssh *ssh)
{
	u_int i;
	Channel *c;

	برائے (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		اگر (c == تہی || !c->have_remote_id)
			جاری;
		انتخاب (c->type) {
		حالت SSH_CHANNEL_CLOSED:
		حالت SSH_CHANNEL_DYNAMIC:
		حالت SSH_CHANNEL_RDYNAMIC_OPEN:
		حالت SSH_CHANNEL_RDYNAMIC_اختتام:
		حالت SSH_CHANNEL_X11_LISTENER:
		حالت SSH_CHANNEL_پورٹ_LISTENER:
		حالت SSH_CHANNEL_RPORT_LISTENER:
		حالت SSH_CHANNEL_MUX_LISTENER:
		حالت SSH_CHANNEL_MUX_CLIENT:
		حالت SSH_CHANNEL_MUX_PROXY:
		حالت SSH_CHANNEL_OPENING:
		حالت SSH_CHANNEL_CONNECTING:
		حالت SSH_CHANNEL_ZOMBIE:
		حالت SSH_CHANNEL_ABANDONED:
		حالت SSH_CHANNEL_UNIX_LISTENER:
		حالت SSH_CHANNEL_RUNIX_LISTENER:
			جاری;
		حالت SSH_CHANNEL_LARVAL:
		حالت SSH_CHANNEL_AUTH_SOCKET:
		حالت SSH_CHANNEL_OPEN:
		حالت SSH_CHANNEL_X11_OPEN:
			واپس i;
		طےشدہ:
			fatal_f("bad channel type %d", c->type);
			/* NOTREACHED */
		}
	}
	واپس -1;
}

/* Returns the state of the channel's extended usage flag */
ثابت حرف *
channel_format_extended_usage(ثابت Channel *c)
{
	اگر (c->efd == -1)
		واپس "closed";

	انتخاب (c->extended_usage) {
	حالت CHAN_EXTENDED_WRITE:
		واپس "write";
	حالت CHAN_EXTENDED_READ:
		واپس "read";
	حالت CHAN_EXTENDED_IGNORE:
		واپس "ignore";
	طےشدہ:
		واپس "UNKNOWN";
	}
}

ساکن حرف *
channel_format_حالت(ثابت Channel *c)
{
	حرف *ret = تہی;

	xasprintf(&ret, "t%d [%s] %s%u %s%u i%u/%zu o%u/%zu e[%s]/%zu "
	    "fd %d/%d/%d sock %d cc %d %s%u io 0x%02x/0x%02x %s%s",
	    c->type, c->xctype != تہی ? c->xctype : c->ctype,
	    c->have_remote_id ? "r" : "nr", c->remote_id,
	    c->mux_ctx != تہی ? "m" : "nm", c->mux_downstream_id,
	    c->istate, sshbuf_len(c->داخلہ),
	    c->ostate, sshbuf_len(c->output),
	    channel_format_extended_usage(c), sshbuf_len(c->extended),
	    c->rfd, c->wfd, c->efd, c->sock, c->ctl_chan,
	    c->have_ctl_بچہ_id ? "c" : "nc", c->ctl_بچہ_id,
	    c->io_want, c->io_ready,
	    c->isatty ? "T" : (c->remote_has_tty ? "RT" : ""),
	    c->bulk ? "B" : "I");
	واپس ret;
}

/*
 * Returns a message describing the currently open forwarded connections,
 * suitable for sending to the client.  The message contains crlf pairs for
 * newlines.
 */
حرف *
channel_open_پیغام(ساخت ssh *ssh)
{
	ساخت sshbuf *buf;
	Channel *c;
	u_int i;
	صحیح r;
	حرف *cp, *ret;

	اگر ((buf = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new");
	اگر ((r = sshbuf_putf(buf,
	    "The following connections are open:\r\n")) != 0)
		fatal_fr(r, "sshbuf_putf");
	برائے (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		اگر (c == تہی)
			جاری;
		انتخاب (c->type) {
		حالت SSH_CHANNEL_X11_LISTENER:
		حالت SSH_CHANNEL_پورٹ_LISTENER:
		حالت SSH_CHANNEL_RPORT_LISTENER:
		حالت SSH_CHANNEL_CLOSED:
		حالت SSH_CHANNEL_AUTH_SOCKET:
		حالت SSH_CHANNEL_ZOMBIE:
		حالت SSH_CHANNEL_ABANDONED:
		حالت SSH_CHANNEL_MUX_LISTENER:
		حالت SSH_CHANNEL_UNIX_LISTENER:
		حالت SSH_CHANNEL_RUNIX_LISTENER:
			جاری;
		حالت SSH_CHANNEL_LARVAL:
		حالت SSH_CHANNEL_OPENING:
		حالت SSH_CHANNEL_CONNECTING:
		حالت SSH_CHANNEL_DYNAMIC:
		حالت SSH_CHANNEL_RDYNAMIC_OPEN:
		حالت SSH_CHANNEL_RDYNAMIC_اختتام:
		حالت SSH_CHANNEL_OPEN:
		حالت SSH_CHANNEL_X11_OPEN:
		حالت SSH_CHANNEL_MUX_PROXY:
		حالت SSH_CHANNEL_MUX_CLIENT:
			cp = channel_format_حالت(c);
			اگر ((r = sshbuf_putf(buf, "  #%d %.300s (%s)\r\n",
			    c->self, c->remote_name, cp)) != 0) {
				آزاد(cp);
				fatal_fr(r, "sshbuf_putf");
			}
			آزاد(cp);
			جاری;
		طےشدہ:
			fatal_f("bad channel type %d", c->type);
			/* NOTREACHED */
		}
	}
	اگر ((ret = sshbuf_dup_string(buf)) == تہی)
		fatal_f("sshbuf_dup_string");
	sshbuf_free(buf);
	واپس ret;
}

خالی
channel_report_open(ساخت ssh *ssh, صحیح level)
{
	حرف *open, *oopen, *cp, ident[256];

	sshpkt_fmt_connection_id(ssh, ident, حجم(ident));
	do_log2(level, "Connection: %s (pid %ld)", ident, (طویل)getpid());
	open = oopen = channel_open_پیغام(ssh);
	جب ((cp = strsep(&open, "\r\n")) != تہی) {
		اگر (*cp != '\0')
			do_log2(level, "%s", cp);
	}
	آزاد(oopen);
}

ساکن خالی
open_preamble(ساخت ssh *ssh, ثابت حرف *where, Channel *c, ثابت حرف *type)
{
	صحیح r;

	اگر ((r = sshpkt_آغاز(ssh, SSH2_پیغام_CHANNEL_OPEN)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, type)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_کھڑکی)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0) {
		fatal_r(r, "%s: channel %i: open", where, c->self);
	}
}

خالی
channel_send_open(ساخت ssh *ssh, صحیح id)
{
	Channel *c = channel_lookup(ssh, id);
	صحیح r;

	اگر (c == تہی) {
		logit("channel_send_open: %d: bad id", id);
		واپس;
	}
	debug2("channel %d: send open", id);
	open_preamble(ssh, __func__, c, c->ctype);
	اگر ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i", c->self);
}

خالی
channel_request_آغاز(ساخت ssh *ssh, صحیح id, ثابت حرف *service,
    صحیح wantconfirm)
{
	Channel *c = channel_lookup(ssh, id);
	صحیح r;

	اگر (c == تہی) {
		logit_f("%d: unknown channel id", id);
		واپس;
	}
	اگر (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);

	debug2("channel %d: request %s confirm %d", id, service, wantconfirm);
	اگر ((r = sshpkt_آغاز(ssh, SSH2_پیغام_CHANNEL_REQUEST)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, service)) != 0 ||
	    (r = sshpkt_put_u8(ssh, wantconfirm)) != 0) {
		fatal_fr(r, "channel %i", c->self);
	}
}

خالی
channel_رجسٹر_حالت_confirm(ساخت ssh *ssh, صحیح id,
    channel_confirm_cb *cb, channel_confirm_abandon_cb *abandon_cb, خالی *ctx)
{
	ساخت channel_confirm *cc;
	Channel *c;

	اگر ((c = channel_lookup(ssh, id)) == تہی)
		fatal_f("%d: bad id", id);

	cc = xcalloc(1, حجم(*cc));
	cc->cb = cb;
	cc->abandon_cb = abandon_cb;
	cc->ctx = ctx;
	TAILQ_INSERT_TAIL(&c->حالت_confirms, cc, اندراج_2);
}

خالی
channel_رجسٹر_open_confirm(ساخت ssh *ssh, صحیح id,
    channel_open_fn *fn, خالی *ctx)
{
	Channel *c = channel_lookup(ssh, id);

	اگر (c == تہی) {
		logit_f("%d: bad id", id);
		واپس;
	}
	c->open_confirm = fn;
	c->open_confirm_ctx = ctx;
}

خالی
channel_رجسٹر_cleanup(ساخت ssh *ssh, صحیح id,
    channel_callback_fn *fn, صحیح do_close)
{
	Channel *c = channel_by_id(ssh, id);

	اگر (c == تہی) {
		logit_f("%d: bad id", id);
		واپس;
	}
	c->detach_user = fn;
	c->detach_close = do_close;
}

خالی
channel_cancel_cleanup(ساخت ssh *ssh, صحیح id)
{
	Channel *c = channel_by_id(ssh, id);

	اگر (c == تہی) {
		logit_f("%d: bad id", id);
		واپس;
	}
	c->detach_user = تہی;
	c->detach_close = 0;
}

خالی
channel_رجسٹر_filter(ساخت ssh *ssh, صحیح id, channel_infilter_fn *ifn,
    channel_outfilter_fn *ofn, channel_filter_cleanup_fn *cfn, خالی *ctx)
{
	Channel *c = channel_lookup(ssh, id);

	اگر (c == تہی) {
		logit_f("%d: bad id", id);
		واپس;
	}
	c->داخلہ_filter = ifn;
	c->output_filter = ofn;
	c->filter_ctx = ctx;
	c->filter_cleanup = cfn;
}

خالی
channel_سیٹ_fds(ساخت ssh *ssh, صحیح id, صحیح rfd, صحیح wfd, صحیح efd,
    صحیح extusage, صحیح nonblock, صحیح is_tty, u_int کھڑکی_max)
{
	Channel *c = channel_lookup(ssh, id);
	صحیح r;

	اگر (c == تہی || c->type != SSH_CHANNEL_LARVAL)
		fatal("channel_activate for non-larval channel %d.", id);
	اگر (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);

	channel_رجسٹر_fds(ssh, c, rfd, wfd, efd, extusage, nonblock, is_tty);
	c->type = SSH_CHANNEL_OPEN;
	channel_سیٹ_مستعمل_وقت(ssh, c);
	c->local_کھڑکی = c->local_کھڑکی_max = کھڑکی_max;

	اگر ((r = sshpkt_آغاز(ssh, SSH2_پیغام_CHANNEL_کھڑکی_ADJUST)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_کھڑکی)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i", c->self);
}

ساکن خالی
channel_pre_listener(ساخت ssh *ssh, Channel *c)
{
	c->io_want = SSH_CHAN_IO_SOCK_R;
}

ساکن خالی
channel_pre_connecting(ساخت ssh *ssh, Channel *c)
{
	debug3("channel %d: waiting for connection", c->self);
	c->io_want = SSH_CHAN_IO_SOCK_W;
}

ساکن خالی
channel_pre_open(ساخت ssh *ssh, Channel *c)
{
	c->io_want = 0;
	اگر (c->istate == CHAN_داخلہ_OPEN &&
	    c->remote_کھڑکی > 0 &&
	    sshbuf_len(c->داخلہ) < c->remote_کھڑکی &&
	    sshbuf_check_reserve(c->داخلہ, CHAN_RBUF) == 0)
		c->io_want |= SSH_CHAN_IO_RFD;
	اگر (c->ostate == CHAN_OUTPUT_OPEN ||
	    c->ostate == CHAN_OUTPUT_WAIT_DRAIN) {
		اگر (sshbuf_len(c->output) > 0) {
			c->io_want |= SSH_CHAN_IO_WFD;
		} ورنہ اگر (c->ostate == CHAN_OUTPUT_WAIT_DRAIN) {
			اگر (CHANNEL_EFD_OUTPUT_فعال(c))
				debug2("channel %d: "
				    "obuf_empty delayed efd %d/(%zu)", c->self,
				    c->efd, sshbuf_len(c->extended));
			ورنہ
				chan_obuf_خالی_خانے(ssh, c);
		}
	}
	/** XXX check close conditions, too */
	اگر (c->efd != -1 && !(c->istate == CHAN_داخلہ_CLOSED &&
	    c->ostate == CHAN_OUTPUT_CLOSED)) {
		اگر (c->extended_usage == CHAN_EXTENDED_WRITE &&
		    sshbuf_len(c->extended) > 0)
			c->io_want |= SSH_CHAN_IO_EFD_W;
		ورنہ اگر (c->efd != -1 && !(c->flags & CHAN_EOF_بھیجا) &&
		    (c->extended_usage == CHAN_EXTENDED_READ ||
		    c->extended_usage == CHAN_EXTENDED_IGNORE) &&
		    sshbuf_len(c->extended) < c->remote_کھڑکی)
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
ساکن صحیح
x11_open_helper(ساخت ssh *ssh, ساخت sshbuf *b)
{
	ساخت ssh_channels *sc = ssh->chanctxt;
	u_char *ucp;
	u_int proto_len, ڈیٹا_len;

	اگر (sc->x11_saved_proto == تہی) {
		error("X11 forwarding opened before X11 forwarding requested");
		واپس -1;
	}

	/* Is this being called after the refusal deadline? */
	اگر (sc->x11_refuse_وقت != 0.0 &&
	    monotime_double() >= sc->x11_refuse_وقت) {
		verbose("Rejected X11 connection after ForwardX11Timeout "
		    "expired");
		واپس -1;
	}

	/* Check if the fixed size part of the packet is in buffer. */
	اگر (sshbuf_len(b) < 12)
		واپس 0;

	/* Parse the lengths of variable-length fields. */
	ucp = sshbuf_mutable_ptr(b);
	اگر (ucp[0] == 0x42) {	/* Byte order MSB first. */
		proto_len = 256 * ucp[6] + ucp[7];
		ڈیٹا_len = 256 * ucp[8] + ucp[9];
	} ورنہ اگر (ucp[0] == 0x6c) {	/* Byte order LSB first. */
		proto_len = ucp[6] + 256 * ucp[7];
		ڈیٹا_len = ucp[8] + 256 * ucp[9];
	} ورنہ {
		debug2("Initial X11 packet contains bad byte order byte: 0x%x",
		    ucp[0]);
		واپس -1;
	}

	/* Check if the whole packet is in buffer. */
	اگر (sshbuf_len(b) <
	    12 + ((proto_len + 3) & ~3) + ((ڈیٹا_len + 3) & ~3))
		واپس 0;

	/* Check if authentication protocol matches. */
	اگر (proto_len != لڑی_لمبائی(sc->x11_saved_proto) ||
	    memcmp(ucp + 12, sc->x11_saved_proto, proto_len) != 0) {
		debug2("X11 connection uses different authentication protocol.");
		واپس -1;
	}
	/* Check if authentication data matches our fake data. */
	اگر (ڈیٹا_len != sc->x11_fake_ڈیٹا_len ||
	    timingsafe_bcmp(ucp + 12 + ((proto_len + 3) & ~3),
		sc->x11_fake_ڈیٹا, sc->x11_fake_ڈیٹا_len) != 0) {
		debug2("X11 auth data does not match fake data.");
		واپس -1;
	}
	/* Check fake data length */
	اگر (sc->x11_fake_ڈیٹا_len != sc->x11_saved_ڈیٹا_len) {
		error("X11 fake_data_len %d != saved_data_len %d",
		    sc->x11_fake_ڈیٹا_len, sc->x11_saved_ڈیٹا_len);
		واپس -1;
	}
	/*
	 * Received authentication protocol and data match
	 * our fake data. Substitute the fake data with real
	 * data.
	 */
	حافظہ_نقل(ucp + 12 + ((proto_len + 3) & ~3),
	    sc->x11_saved_ڈیٹا, sc->x11_saved_ڈیٹا_len);
	واپس 1;
}

خالی
channel_force_close(ساخت ssh *ssh, Channel *c, صحیح abandon)
{
	debug3_f("channel %d: forcibly closing", c->self);
	اگر (c->istate == CHAN_داخلہ_OPEN)
		chan_read_failed(ssh, c);
	اگر (c->istate == CHAN_داخلہ_WAIT_DRAIN) {
		sshbuf_reset(c->داخلہ);
		chan_ibuf_خالی_خانے(ssh, c);
	}
	اگر (c->ostate == CHAN_OUTPUT_OPEN ||
	    c->ostate == CHAN_OUTPUT_WAIT_DRAIN) {
		sshbuf_reset(c->output);
		chan_write_failed(ssh, c);
	}
	اگر (c->detach_user)
		c->detach_user(ssh, c->self, 1, تہی);
	اگر (c->efd != -1)
		channel_close_fd(ssh, c, &c->efd);
	اگر (abandon)
		c->type = SSH_CHANNEL_ABANDONED;
	/* exempt from inactivity timeouts */
	c->inactive_deadline = 0;
	c->lastused = 0;
}

ساکن خالی
channel_pre_x11_open(ساخت ssh *ssh, Channel *c)
{
	صحیح ret = x11_open_helper(ssh, c->output);

	/* c->force_drain = 1; */

	اگر (ret == 1) {
		c->type = SSH_CHANNEL_OPEN;
		channel_سیٹ_مستعمل_وقت(ssh, c);
		channel_pre_open(ssh, c);
	} ورنہ اگر (ret == -1) {
		logit("X11 connection rejected because of wrong "
		    "authentication.");
		debug2("X11 rejected %d i%d/o%d",
		    c->self, c->istate, c->ostate);
		channel_force_close(ssh, c, 0);
	}
}

ساکن خالی
channel_pre_mux_client(ساخت ssh *ssh, Channel *c)
{
	c->io_want = 0;
	اگر (c->istate == CHAN_داخلہ_OPEN && !c->mux_pause &&
	    sshbuf_check_reserve(c->داخلہ, CHAN_RBUF) == 0)
		c->io_want |= SSH_CHAN_IO_RFD;
	اگر (c->istate == CHAN_داخلہ_WAIT_DRAIN) {
		/* clear buffer immediately (discard any partial packet) */
		sshbuf_reset(c->داخلہ);
		chan_ibuf_خالی_خانے(ssh, c);
		/* Start output drain. XXX just kill chan? */
		chan_rcvd_oclose(ssh, c);
	}
	اگر (c->ostate == CHAN_OUTPUT_OPEN ||
	    c->ostate == CHAN_OUTPUT_WAIT_DRAIN) {
		اگر (sshbuf_len(c->output) > 0)
			c->io_want |= SSH_CHAN_IO_WFD;
		ورنہ اگر (c->ostate == CHAN_OUTPUT_WAIT_DRAIN)
			chan_obuf_خالی_خانے(ssh, c);
	}
}

ساکن اندرونی صحیح
socks_decode_error(Channel *c, صحیح حالت_2, ثابت حرف *func, ثابت حرف *پیغام)
{
	اگر (حالت_2 == SSH_ERR_پیغام_INCOMPLETE)
		واپس 0;
	ورنہ {
		debug_r(حالت_2, "%s: channel %d: decode %s",
		    func, c->self, پیغام);
		واپس -1;
	}
}

/* try to decode a socks4 header */
ساکن صحیح
channel_decode_socks4(Channel *c, ساخت sshbuf *داخلہ, ساخت sshbuf *output)
{
	uint8_t socks_ver, socks_cmd, dest_addr[4];
	uint16_t dest_پورٹ;
	حرف *user = تہی, *host = تہی;
	صحیح success = -1, socks4a = 0, r;
	ساخت sshbuf *b = تہی;

	اگر (sshbuf_len(داخلہ) < 9)
		واپس 0;

	/* We may not have a complete message, so work on a dup of the buffer */
	اگر ((b = sshbuf_fromb(داخلہ)) == تہی)
		fatal_f("sshbuf_fromb failed");

	debug2("channel %d: decode socks4", c->self);
	اگر ((r = sshbuf_get_u8(b, &socks_ver)) != 0 ||
	    (r = sshbuf_get_u8(b, &socks_cmd)) != 0 ||
	    (r = sshbuf_get_u16(b, &dest_پورٹ)) != 0 ||
	    (r = sshbuf_get(b, &dest_addr, حجم(dest_addr))) != 0 ||
	    (r = sshbuf_get_nulterminated_string(b, 1024, &user, تہی)) != 0) {
		success = socks_decode_error(c, r, __func__, "header");
		جاؤ برآمد;
	}

	/* Is this a SOCKS4A request? (indicated by an address of 0.0.0.x) */
	اگر (dest_addr[0] == 0 && dest_addr[1] == 0 &&
	    dest_addr[2] == 0 && dest_addr[3] != 0) {
		/* If so, then the hostname follows, also nul-terminated */
		اگر ((r = sshbuf_get_nulterminated_string(b, 1024,
		    &host, تہی)) != 0) {
			success = socks_decode_error(c, r, __func__, "host");
			جاؤ برآمد;
		}
		socks4a = 1;
	} ورنہ {
		/* Plain SOCKS4 passes an IPv4 binary address; reconstruct */
		xasprintf(&host, "%d.%d.%d.%d",
		    dest_addr[0], dest_addr[1], dest_addr[2], dest_addr[3]);
	}

	/* We have a complete SOCKS4 message; consume it from input */
	اگر ((r = sshbuf_consume_upto_بچہ(داخلہ, b)) != 0)
		fatal_fr(r, "channel %d: consume", c->self);

	/* Handle the request */
	debug2("channel %d: %s: user=\"%s\" command=%d destination=[%s]:%d",
	    c->self, socks4a ? "SOCKS4A" : "SOCKS4", user, (صحیح)socks_cmd,
	    host, dest_پورٹ);
	اگر (socks_cmd != 1) {
		debug("channel %d: cannot handle %s command 0x%02x",
		    c->self, socks4a ? "SOCKS4A" : "SOCKS4", socks_cmd);
		جاؤ برآمد;
	}
	آزاد(c->راستہ);
	c->راستہ = host;
	host = تہی; /* transferred */
	c->host_پورٹ = dest_پورٹ;

	/* Reply to the SOCKS4 client */
	اگر ((r = sshbuf_put_u8(output, 0)) != 0 ||	/* vn: 0 for reply */
	    (r = sshbuf_put_u8(output, 90)) != 0 ||	/* cd: req granted */
	    (r = sshbuf_put_u16(output, 0)) != 0 ||	/* port: ignored */
	    (r = sshbuf_put_u32(output, ntohl(INADDR_ANY))) != 0) /* ignored */
		fatal_fr(r, "channel %d: compose reply", c->self);

	/* success */
	success = 1;
 برآمد:
	sshbuf_free(b);
	آزاد(user);
	آزاد(host);
	واپس success;
}

/* try to decode a socks5 header */
#تعریف_کرو SSH_SOCKS5_AUTHDONE	0x1000
#تعریف_کرو SSH_SOCKS5_NOAUTH	0x00
#تعریف_کرو SSH_SOCKS5_IPV4		0x01
#تعریف_کرو SSH_SOCKS5_DOMAIN	0x03
#تعریف_کرو SSH_SOCKS5_IPV6		0x04
#تعریف_کرو SSH_SOCKS5_CONNECT	0x01
#تعریف_کرو SSH_SOCKS5_SUCCESS	0x00

/*
 * Handles SOCKS5 authentication. Note 'b' must be a dup of 'input'
 * Returns 0 on insufficient queued date, 1 on authentication success or
 * -1 on error.
 */
ساکن صحیح
channel_socks5_check_auth(Channel *c, ساخت sshbuf *b, ساخت sshbuf *داخلہ,
    ساخت sshbuf *output)
{
	uint8_t socks_ver;
	uint8_t nmethods, طریقہ;
	صحیح r;
	u_int i, ملا;

	/* format: ver | nmethods | methods */
	اگر ((r = sshbuf_get_u8(b, &socks_ver)) != 0)
		واپس socks_decode_error(c, r, __func__, "version");
	اگر (socks_ver != 5) /* shouldn't happen; checked by caller^2 */
		fatal_fr(r, "channel %d: internal error: not socks5", c->self);
	اگر ((r = sshbuf_get_u8(b, &nmethods)) != 0)
		واپس socks_decode_error(c, r, __func__, "methods");
	برائے (ملا = i = 0; i < nmethods; i++) {
		اگر ((r = sshbuf_get_u8(b, &طریقہ)) != 0)
			واپس socks_decode_error(c, r, __func__, "method");
		اگر (طریقہ == SSH_SOCKS5_NOAUTH)
			ملا = 1;
	}
	اگر (!ملا) {
		debug("channel %d: didn't request SSH_SOCKS5_NOAUTH", c->self);
		واپس -1;
	}
	/* Consume completed request */
	اگر ((r = sshbuf_consume_upto_بچہ(داخلہ, b)) != 0)
		fatal_fr(r, "channel %d: consume", c->self);

	/* Compose reply: version, method */
	اگر ((r = sshbuf_put_u8(output, 0x05)) != 0 ||
	    (r = sshbuf_put_u8(output, SSH_SOCKS5_NOAUTH)) != 0)
		fatal_fr(r, "channel %d: append reply", c->self);
	/* success */
	debug2("channel %d: socks5 auth done", c->self);
	واپس 1;
}

ساکن صحیح
channel_decode_socks5(Channel *c, ساخت sshbuf *داخلہ, ساخت sshbuf *output)
{
	uint8_t socks_ver, socks_cmd, socks_reserved, socks_atyp, addrlen;
	uint16_t dest_پورٹ;
	حرف dest_addr[255+1], ntop[INET6_ADDRSTRLEN];
	u_int af;
	صحیح r, success = -1;;
	ساخت sshbuf *b = تہی;

	debug2("channel %d: decode socks5 %s", c->self,
	    (c->flags & SSH_SOCKS5_AUTHDONE) ? "request" : "auth");

	/* We may not have a complete message, so work on a dup of the buffer */
	اگر ((b = sshbuf_fromb(داخلہ)) == تہی)
		fatal_f("sshbuf_fromb failed");

	اگر (!(c->flags & SSH_SOCKS5_AUTHDONE)) {
		اگر ((r = channel_socks5_check_auth(c, b, داخلہ, output)) != 1) {
			success = r;
			جاؤ برآمد;
		}
		c->flags |= SSH_SOCKS5_AUTHDONE;
		/* Continue to parse request in case client speculated ahead */
	}

	/* Request messages (auth or connect) always start with the version */
	اگر ((r = sshbuf_get_u8(b, &socks_ver)) != 0) {
		success = socks_decode_error(c, r, __func__, "version");
		جاؤ برآمد;
	}
	اگر (socks_ver != 5) /* shouldn't happen */
		fatal_fr(r, "channel %d: internal error: not socks5", c->self);

	/* Parse SOCKS5 request header */
	debug2("channel %d: socks5 post auth", c->self);
	اگر ((r = sshbuf_get_u8(b, &socks_cmd)) != 0 ||
	    (r = sshbuf_get_u8(b, &socks_reserved)) != 0 ||
	    (r = sshbuf_get_u8(b, &socks_atyp)) != 0) {
		success = socks_decode_error(c, r, __func__, "request header");
		جاؤ برآمد;
	}

	اگر (socks_ver != 0x05 ||
	    socks_cmd != SSH_SOCKS5_CONNECT ||
	    socks_reserved != 0x00) {
		debug2("channel %d: only socks5 connect supported", c->self);
		جاؤ برآمد;
	}

	انتخاب (socks_atyp) {
	حالت SSH_SOCKS5_IPV4:
		addrlen = 4;
		af = AF_INET;
		توڑو;
	حالت SSH_SOCKS5_DOMAIN:
		اگر ((r = sshbuf_get_u8(b, &addrlen)) != 0) {
			success = socks_decode_error(c, r, __func__, "addrlen");
			جاؤ برآمد;
		}
		af = -1;
		توڑو;
	حالت SSH_SOCKS5_IPV6:
		addrlen = 16;
		af = AF_INET6;
		توڑو;
	طےشدہ:
		debug2("channel %d: bad socks5 atyp %d", c->self, socks_atyp);
		جاؤ برآمد;
	}
	اگر ((r = sshbuf_get(b, &dest_addr, addrlen)) != 0 ||
	    (r = sshbuf_get_u16(b, &dest_پورٹ)) != 0) {
		success = socks_decode_error(c, r, __func__, "addr/port");
		جاؤ برآمد;
	}
	dest_addr[addrlen] = '\0';

	/* We have a complete SOCKS5 request; consume it from input */
	اگر ((r = sshbuf_consume_upto_بچہ(داخلہ, b)) != 0)
		fatal_fr(r, "channel %d: consume", c->self);

	آزاد(c->راستہ);
	c->راستہ = تہی;
	اگر (socks_atyp == SSH_SOCKS5_DOMAIN)
		c->راستہ = xstrdup(dest_addr);
	ورنہ {
		اگر (inet_ntop(af, dest_addr, ntop, حجم(ntop)) == تہی)
			واپس -1;
		c->راستہ = xstrdup(ntop);
	}
	c->host_پورٹ = dest_پورٹ;

	debug2("channel %d: dynamic request: socks5 host %s port %u command %u",
	    c->self, c->راستہ, c->host_پورٹ, socks_cmd);

	/*جواب*/
	اگر ((r = sshbuf_put_u8(output, 0x05)) != 0 ||	/*نسخہ*/
	    (r = sshbuf_put_u8(output, SSH_SOCKS5_SUCCESS)) != 0 || /* cmd */
	    (r = sshbuf_put_u8(output, 0)) != 0 ||	/* reserved, ignored */
	    (r = sshbuf_put_u8(output, SSH_SOCKS5_IPV4)) != 0 || /* addrtype */
	    (r = sshbuf_put_u32(output, ntohl(INADDR_ANY))) != 0 || /* addr */
	    (r = sshbuf_put_u16(output, dest_پورٹ)) != 0) /*پورٹ*/
		fatal_fr(r, "channel %d: append reply", c->self);

	/* success */
	success = 1;
 برآمد:
	sshbuf_free(b);
	واپس success;
}

Channel *
channel_connect_stdio_fwd(ساخت ssh *ssh,
    ثابت حرف *host_مقصد_connect, صحیح پورٹ_مقصد_connect,
    صحیح اندر, صحیح برآمد, صحیح nonblock)
{
	Channel *c;

	debug_f("%s:%d", host_مقصد_connect, پورٹ_مقصد_connect);

	c = channel_new(ssh, "stdio-forward", SSH_CHANNEL_OPENING, اندر, برآمد,
	    -1, CHAN_TCP_کھڑکی_DEFAULT, CHAN_TCP_PACKET_DEFAULT,
	    0, "stdio-forward", nonblock);

	c->راستہ = xstrdup(host_مقصد_connect);
	c->host_پورٹ = پورٹ_مقصد_connect;
	c->listening_پورٹ = 0;
	c->force_drain = 1;

	channel_رجسٹر_fds(ssh, c, اندر, برآمد, -1, 0, 1, 0);
	پورٹ_open_helper(ssh, c, پورٹ_مقصد_connect == پورٹ_STREAMLOCAL ?
	    "direct-streamlocal@openssh.com" : "direct-tcpip");

	واپس c;
}

/* dynamic port forwarding */
ساکن خالی
channel_pre_dynamic(ساخت ssh *ssh, Channel *c)
{
	u_int have;
	u_char ver;
	صحیح r, ret;

	c->io_want = 0;
	have = sshbuf_len(c->داخلہ);
	debug2("channel %d: pre_dynamic: have %d", c->self, have);
	/* sshbuf_dump(c->input, stderr); */
	/* check if the fixed size part of the packet is in buffer. */
	اگر (have < 3) {
		/* need more */
		c->io_want |= SSH_CHAN_IO_RFD;
		واپس;
	}
	/* try to guess the protocol */
	اگر ((r = sshbuf_peek_u8(c->داخلہ, 0, &ver)) != 0)
		fatal_fr(r, "sshbuf_peek_u8");
	انتخاب (ver) {
	حالت 0x04:
		ret = channel_decode_socks4(c, c->داخلہ, c->output);
		توڑو;
	حالت 0x05:
		ret = channel_decode_socks5(c, c->داخلہ, c->output);
		توڑو;
	طےشدہ:
		debug2_f("channel %d: unknown SOCKS version %u", c->self, ver);
		ret = -1;
		توڑو;
	}
	اگر (ret < 0) {
		chan_mark_dead(ssh, c);
	} ورنہ اگر (ret == 0) {
		debug2("channel %d: pre_dynamic: need more", c->self);
		/* need more */
		c->io_want |= SSH_CHAN_IO_RFD;
		اگر (sshbuf_len(c->output))
			c->io_want |= SSH_CHAN_IO_WFD;
	} ورنہ {
		/* switch to the next state */
		c->type = SSH_CHANNEL_OPENING;
		پورٹ_open_helper(ssh, c, "direct-tcpip");
	}
}

/* simulate read-error */
ساکن خالی
rdynamic_close(ساخت ssh *ssh, Channel *c)
{
	c->type = SSH_CHANNEL_OPEN;
	channel_force_close(ssh, c, 0);
}

/* reverse dynamic port forwarding */
ساکن خالی
channel_before_prepare_io_rdynamic(ساخت ssh *ssh, Channel *c)
{
	ثابت u_char *p;
	u_int have, len;
	صحیح r, ret;

	have = sshbuf_len(c->output);
	debug2("channel %d: pre_rdynamic: have %d", c->self, have);
	/* sshbuf_dump(c->output, stderr); */
	/* EOF received */
	اگر (c->flags & CHAN_EOF_RCVD) {
		اگر ((r = sshbuf_consume(c->output, have)) != 0)
			fatal_fr(r, "channel %d: consume", c->self);
		rdynamic_close(ssh, c);
		واپس;
	}
	/* check if the fixed size part of the packet is in buffer. */
	اگر (have < 3)
		واپس;
	/* try to guess the protocol */
	p = sshbuf_ptr(c->output);
	انتخاب (p[0]) {
	حالت 0x04:
		/* switch input/output for reverse forwarding */
		ret = channel_decode_socks4(c, c->output, c->داخلہ);
		توڑو;
	حالت 0x05:
		ret = channel_decode_socks5(c, c->output, c->داخلہ);
		توڑو;
	طےشدہ:
		ret = -1;
		توڑو;
	}
	اگر (ret < 0) {
		rdynamic_close(ssh, c);
	} ورنہ اگر (ret == 0) {
		debug2("channel %d: pre_rdynamic: need more", c->self);
		/* send socks request to peer */
		len = sshbuf_len(c->داخلہ);
		اگر (len > 0 && len < c->remote_کھڑکی) {
			اگر ((r = sshpkt_آغاز(ssh, SSH2_پیغام_CHANNEL_ڈیٹا)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
			    (r = sshpkt_put_stringb(ssh, c->داخلہ)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0) {
				fatal_fr(r, "channel %i: rdynamic", c->self);
			}
			اگر ((r = sshbuf_consume(c->داخلہ, len)) != 0)
				fatal_fr(r, "channel %d: consume", c->self);
			c->remote_کھڑکی -= len;
		}
	} ورنہ اگر (rdynamic_connect_اختتام(ssh, c) < 0) {
		/* the connect failed */
		rdynamic_close(ssh, c);
	}
}

/* This is our fake X11 server socket. */
ساکن خالی
channel_post_x11_listener(ساخت ssh *ssh, Channel *c)
{
	Channel *nc;
	ساخت sockaddr_storage addr;
	صحیح r, newsock, oerrno, remote_پورٹ;
	socklen_t addrlen;
	حرف buf[16384], *remote_ipaddr;

	اگر ((c->io_ready & SSH_CHAN_IO_SOCK_R) == 0)
		واپس;

	debug("X11 connection requested.");
	addrlen = حجم(addr);
	newsock = accept(c->sock, (ساخت sockaddr *)&addr, &addrlen);
	اگر (c->single_connection) {
		oerrno = errno;
		debug2("single_connection: closing X11 listener.");
		channel_close_fd(ssh, c, &c->sock);
		chan_mark_dead(ssh, c);
		errno = oerrno;
	}
	اگر (newsock == -1) {
		اگر (errno != EINTR && errno != EWOULDBLOCK &&
		    errno != ECONNABORTED)
			error("accept: %.100s", strerror(errno));
		اگر (errno == EMFILE || errno == ENFILE)
			c->notbefore = monotime_double() + 1.0;
		واپس;
	}
	سیٹ_nodelay(newsock);
	اگر (ssh->chanctxt->want_tcp_keepalive)
		سیٹ_keepalive(newsock); /* logs errors */
	remote_ipaddr = get_peer_ipaddr(newsock);
	remote_پورٹ = get_peer_پورٹ(newsock);
	snprintf(buf, حجم buf, "X11 connection from %.200s port %d",
	    remote_ipaddr, remote_پورٹ);

	nc = channel_new(ssh, "x11-connection",
	    SSH_CHANNEL_OPENING, newsock, newsock, -1,
	    c->local_کھڑکی_max, c->local_maxpacket, 0, buf, 1);
	open_preamble(ssh, __func__, nc, "x11");
	اگر ((r = sshpkt_put_cstring(ssh, remote_ipaddr)) != 0 ||
	    (r = sshpkt_put_u32(ssh, remote_پورٹ)) != 0) {
		fatal_fr(r, "channel %i: reply", c->self);
	}
	اگر ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i: send", c->self);
	آزاد(remote_ipaddr);
}

ساکن خالی
پورٹ_open_helper(ساخت ssh *ssh, Channel *c, حرف *rtype)
{
	حرف *local_ipaddr = get_local_ipaddr(c->sock);
	صحیح local_پورٹ = c->sock == -1 ? 65536 : get_local_پورٹ(c->sock);
	حرف *remote_ipaddr = get_peer_ipaddr(c->sock);
	صحیح remote_پورٹ = get_peer_پورٹ(c->sock);
	صحیح r;

	اگر (remote_پورٹ == -1) {
		/* Fake addr/port to appease peers that validate it (Tectia) */
		آزاد(remote_ipaddr);
		remote_ipaddr = xstrdup("127.0.0.1");
		remote_پورٹ = 65535;
	}

	آزاد(c->remote_name);
	xasprintf(&c->remote_name,
	    "%s: listening port %d for %.100s port %d, "
	    "connect from %.200s port %d to %.100s port %d",
	    rtype, c->listening_پورٹ, c->راستہ, c->host_پورٹ,
	    remote_ipaddr, remote_پورٹ, local_ipaddr, local_پورٹ);

	open_preamble(ssh, __func__, c, rtype);
	اگر (strcmp(rtype, "direct-tcpip") == 0) {
		/* target host, port */
		اگر ((r = sshpkt_put_cstring(ssh, c->راستہ)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->host_پورٹ)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	} ورنہ اگر (strcmp(rtype, "direct-streamlocal@openssh.com") == 0) {
		/* target path */
		اگر ((r = sshpkt_put_cstring(ssh, c->راستہ)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	} ورنہ اگر (strcmp(rtype, "forwarded-streamlocal@openssh.com") == 0) {
		/* listen path */
		اگر ((r = sshpkt_put_cstring(ssh, c->راستہ)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	} ورنہ {
		/* listen address, port */
		اگر ((r = sshpkt_put_cstring(ssh, c->راستہ)) != 0 ||
		    (r = sshpkt_put_u32(ssh, local_پورٹ)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	}
	اگر (strcmp(rtype, "forwarded-streamlocal@openssh.com") == 0) {
		/* reserved for future owner/mode info */
		اگر ((r = sshpkt_put_cstring(ssh, "")) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	} ورنہ {
		/* originator host and port */
		اگر ((r = sshpkt_put_cstring(ssh, remote_ipaddr)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)remote_پورٹ)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	}
	اگر ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i: send", c->self);
	آزاد(remote_ipaddr);
	آزاد(local_ipaddr);
}

خالی
channel_سیٹ_x11_refuse_وقت(ساخت ssh *ssh, دوہرا refuse_وقت)
{
	ssh->chanctxt->x11_refuse_وقت = refuse_وقت;
}

/*
 * This socket is listening for connections to a forwarded TCP/IP port.
 */
ساکن خالی
channel_post_پورٹ_listener(ساخت ssh *ssh, Channel *c)
{
	Channel *nc;
	ساخت sockaddr_storage addr;
	صحیح newsock, nextstate;
	socklen_t addrlen;
	حرف *rtype;

	اگر ((c->io_ready & SSH_CHAN_IO_SOCK_R) == 0)
		واپس;

	debug("Connection to port %d forwarding to %.100s port %d requested.",
	    c->listening_پورٹ, c->راستہ, c->host_پورٹ);

	اگر (c->type == SSH_CHANNEL_RPORT_LISTENER) {
		nextstate = SSH_CHANNEL_OPENING;
		rtype = "forwarded-tcpip";
	} ورنہ اگر (c->type == SSH_CHANNEL_RUNIX_LISTENER) {
		nextstate = SSH_CHANNEL_OPENING;
		rtype = "forwarded-streamlocal@openssh.com";
	} ورنہ اگر (c->host_پورٹ == پورٹ_STREAMLOCAL) {
		nextstate = SSH_CHANNEL_OPENING;
		rtype = "direct-streamlocal@openssh.com";
	} ورنہ اگر (c->host_پورٹ == 0) {
		nextstate = SSH_CHANNEL_DYNAMIC;
		rtype = "dynamic-tcpip";
	} ورنہ {
		nextstate = SSH_CHANNEL_OPENING;
		rtype = "direct-tcpip";
	}

	addrlen = حجم(addr);
	newsock = accept(c->sock, (ساخت sockaddr *)&addr, &addrlen);
	اگر (newsock == -1) {
		اگر (errno != EINTR && errno != EWOULDBLOCK &&
		    errno != ECONNABORTED)
			error("accept: %.100s", strerror(errno));
		اگر (errno == EMFILE || errno == ENFILE)
			c->notbefore = monotime_double() + 1.0;
		واپس;
	}
	اگر (addr.ss_family == AF_INET || addr.ss_family == AF_INET6) {
		سیٹ_nodelay(newsock);
		اگر (ssh->chanctxt->want_tcp_keepalive)
			سیٹ_keepalive(newsock); /* logs errors */
	}
	nc = channel_new(ssh, rtype, nextstate, newsock, newsock, -1,
	    c->local_کھڑکی_max, c->local_maxpacket, 0, rtype, 1);
	nc->listening_پورٹ = c->listening_پورٹ;
	nc->host_پورٹ = c->host_پورٹ;
	اگر (c->راستہ != تہی)
		nc->راستہ = xstrdup(c->راستہ);

	اگر (nextstate != SSH_CHANNEL_DYNAMIC)
		پورٹ_open_helper(ssh, nc, rtype);
}

/*
 * This is the authentication agent socket listening for connections from
 * clients.
 */
ساکن خالی
channel_post_auth_listener(ساخت ssh *ssh, Channel *c)
{
	Channel *nc;
	صحیح r, newsock;
	ساخت sockaddr_storage addr;
	socklen_t addrlen;

	اگر ((c->io_ready & SSH_CHAN_IO_SOCK_R) == 0)
		واپس;

	addrlen = حجم(addr);
	newsock = accept(c->sock, (ساخت sockaddr *)&addr, &addrlen);
	اگر (newsock == -1) {
		error("accept from auth socket: %.100s", strerror(errno));
		اگر (errno == EMFILE || errno == ENFILE)
			c->notbefore = monotime_double() + 1.0;
		واپس;
	}
	nc = channel_new(ssh, "agent-connection",
	    SSH_CHANNEL_OPENING, newsock, newsock, -1,
	    c->local_کھڑکی_max, c->local_maxpacket,
	    0, "accepted auth socket", 1);
	open_preamble(ssh, __func__, nc,
	    c->agent_new ? "agent-connect" : "auth-agent@openssh.com");
	اگر ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i", c->self);
}

ساکن خالی
channel_post_connecting(ساخت ssh *ssh, Channel *c)
{
	صحیح err = 0, sock, isopen, r;
	socklen_t sz = حجم(err);

	اگر ((c->io_ready & SSH_CHAN_IO_SOCK_W) == 0)
		واپس;
	اگر (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);
	اگر (c->connect_ctx == تہی)
		fatal_f("channel %d: context missing", c->self);

	/* for rdynamic the OPEN_CONFIRMATION has been sent already */
	isopen = (c->type == SSH_CHANNEL_RDYNAMIC_اختتام);

	اگر (getsockopt(c->sock, SOL_SOCKET, SO_ERROR, &err, &sz) == -1) {
		err = errno;
		error("getsockopt SO_ERROR failed");
	}

	اگر (err == 0) {
		/* Non-blocking connection completed */
		debug("channel %d: connected to %s port %d",
		    c->self, c->connect_ctx->host, c->connect_ctx->پورٹ);
		channel_free_connect_ctx(c);
		c->type = SSH_CHANNEL_OPEN;
		channel_سیٹ_مستعمل_وقت(ssh, c);
		اگر (isopen) {
			/* no message necessary */
		} ورنہ {
			اگر ((r = sshpkt_آغاز(ssh,
			    SSH2_پیغام_CHANNEL_OPEN_CONFIRMATION)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_کھڑکی)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "channel %i open confirm", c->self);
		}
		واپس;
	}
	اگر (err == EINTR || err == EAGAIN || err == EINPROGRESS)
		واپس;

	/* Non-blocking connection failed */
	debug("channel %d: connection failed: %s", c->self, strerror(err));

	/* Try next address, if any */
	اگر ((sock = connect_اگلا(ssh, c->connect_ctx)) == -1) {
		/* Exhausted all addresses for this destination */
		error("connect_to %.100s port %d: failed.",
		    c->connect_ctx->host, c->connect_ctx->پورٹ);
		channel_free_connect_ctx(c);
		اگر (isopen) {
			rdynamic_close(ssh, c);
		} ورنہ {
			اگر ((r = sshpkt_آغاز(ssh,
			    SSH2_پیغام_CHANNEL_OPEN_FAILURE)) != 0 ||
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

ساکن صحیح
channel_handle_rfd(ساخت ssh *ssh, Channel *c)
{
	حرف buf[CHAN_RBUF];
	ssize_t len;
	صحیح r, force;
	سائز_t nr = 0, have, avail, maxlen = CHANNEL_MAX_READ;
	صحیح pty_zeroread = 0;

#اگر_تعریف_شدہ PTY_ZEROREAD
	/* Bug on AIX: read(1) can return 0 for a non-closed fd */
	pty_zeroread = c->isatty;
#اگر_ختم

	force = c->isatty && c->detach_close && c->istate != CHAN_داخلہ_CLOSED;

	اگر (!force && (c->io_ready & SSH_CHAN_IO_RFD) == 0)
		واپس 1;
	اگر ((avail = sshbuf_avail(c->داخلہ)) == 0)
		واپس 1; /* Shouldn't happen */

	/*
	 * For "simple" channels (i.e. not datagram or filtered), we can
	 * read directly to the channel buffer.
	 */
	اگر (!pty_zeroread && c->داخلہ_filter == تہی && !c->datagram) {
		/* Only OPEN channels have valid rwin */
		اگر (c->type == SSH_CHANNEL_OPEN) {
			اگر ((have = sshbuf_len(c->داخلہ)) >= c->remote_کھڑکی)
				واپس 1; /* shouldn't happen */
			اگر (maxlen > c->remote_کھڑکی - have)
				maxlen = c->remote_کھڑکی - have;
		}
		اگر (maxlen > avail)
			maxlen = avail;
		اگر ((r = sshbuf_read(c->rfd, c->داخلہ, maxlen, &nr)) != 0) {
			اگر (errno == EINTR || (!force &&
			    (errno == EAGAIN || errno == EWOULDBLOCK)))
				واپس 1;
			debug2("channel %d: read failed rfd %d maxlen %zu: %s",
			    c->self, c->rfd, maxlen, ssh_err(r));
			جاؤ rfail;
		}
		اگر (nr != 0)
			channel_سیٹ_مستعمل_وقت(ssh, c);
		واپس 1;
	}

	errno = 0;
	len = اقرأ(c->rfd, buf, حجم(buf));
	/* fixup AIX zero-length read with errno set to look more like errors */
	اگر (pty_zeroread && len == 0 && errno != 0)
		len = -1;
	اگر (len == -1 && (errno == EINTR ||
	    ((errno == EAGAIN || errno == EWOULDBLOCK) && !force)))
		واپس 1;
	اگر (len < 0 || (!pty_zeroread && len == 0)) {
		debug2("channel %d: read<=0 rfd %d len %zd: %s",
		    c->self, c->rfd, len,
		    len == 0 ? "closed" : strerror(errno));
 rfail:
		اگر (c->type != SSH_CHANNEL_OPEN) {
			debug2("channel %d: not open", c->self);
			chan_mark_dead(ssh, c);
			واپس -1;
		} ورنہ {
			chan_read_failed(ssh, c);
		}
		واپس -1;
	}
	channel_سیٹ_مستعمل_وقت(ssh, c);
	اگر (c->داخلہ_filter != تہی) {
		اگر (c->داخلہ_filter(ssh, c, buf, len) == -1) {
			debug2("channel %d: filter stops", c->self);
			chan_read_failed(ssh, c);
		}
	} ورنہ اگر (c->datagram) {
		اگر ((r = sshbuf_put_string(c->داخلہ, buf, len)) != 0)
			fatal_fr(r, "channel %i: put datagram", c->self);
	} ورنہ اگر ((r = sshbuf_put(c->داخلہ, buf, len)) != 0)
		fatal_fr(r, "channel %i: put data", c->self);

	واپس 1;
}

ساکن صحیح
channel_handle_wfd(ساخت ssh *ssh, Channel *c)
{
	ساخت termios tio;
	u_char *ڈیٹا = تہی, *buf; /* XXX const; need filter API change */
	سائز_t dlen, olen = 0;
	صحیح r, len;

	اگر ((c->io_ready & SSH_CHAN_IO_WFD) == 0)
		واپس 1;
	اگر (sshbuf_len(c->output) == 0)
		واپس 1;

	/* Send buffered output data to the socket. */
	olen = sshbuf_len(c->output);
	اگر (c->output_filter != تہی) {
		اگر ((buf = c->output_filter(ssh, c, &ڈیٹا, &dlen)) == تہی) {
			debug2("channel %d: filter stops", c->self);
			اگر (c->type != SSH_CHANNEL_OPEN)
				chan_mark_dead(ssh, c);
			ورنہ
				chan_write_failed(ssh, c);
			واپس -1;
		}
	} ورنہ اگر (c->datagram) {
		اگر ((r = sshbuf_get_string(c->output, &ڈیٹا, &dlen)) != 0)
			fatal_fr(r, "channel %i: get datagram", c->self);
		buf = ڈیٹا;
	} ورنہ {
		buf = ڈیٹا = sshbuf_mutable_ptr(c->output);
		dlen = sshbuf_len(c->output);
	}

	اگر (c->datagram) {
		/* ignore truncated writes, datagrams might get lost */
		len = اكتب(c->wfd, buf, dlen);
		آزاد(ڈیٹا);
		اگر (len == -1 && (errno == EINTR || errno == EAGAIN ||
		    errno == EWOULDBLOCK))
			واپس 1;
		اگر (len <= 0)
			جاؤ write_fail;
		جاؤ برآمد;
	}

#اگر_تعریف_شدہ _AIX
	/* XXX: Later AIX versions can't push as much data to tty */
	اگر (c->wfd_isatty)
		dlen = MINIMUM(dlen, 8*1024);
#اگر_ختم

	len = اكتب(c->wfd, buf, dlen);
	اگر (len == -1 &&
	    (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
		واپس 1;
	اگر (len <= 0) {
 write_fail:
		اگر (c->type != SSH_CHANNEL_OPEN) {
			debug2("channel %d: not open", c->self);
			chan_mark_dead(ssh, c);
			واپس -1;
		} ورنہ {
			chan_write_failed(ssh, c);
		}
		واپس -1;
	}
	channel_سیٹ_مستعمل_وقت(ssh, c);
#اگر_غیر_تعریف_شدہ BROKEN_TCGETATTR_ICANON
	اگر (c->isatty && dlen >= 1 && buf[0] != '\r') {
		اگر (tcgetattr(c->wfd, &tio) == 0 &&
		    !(tio.c_lflag & ECHO) && (tio.c_lflag & ICANON)) {
			/*
			 * Simulate echo to reduce the impact of
			 * traffic analysis. We need to match the
			 * size of a SSH2_MSG_CHANNEL_DATA message
			 * (4 byte channel id + buf)
			 */
			اگر ((r = sshpkt_پیغام_ignore(ssh, 4+len)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "channel %i: ignore", c->self);
		}
	}
#اگر_ختم /* BROKEN_TCGETATTR_ICANON */
	اگر ((r = sshbuf_consume(c->output, len)) != 0)
		fatal_fr(r, "channel %i: consume", c->self);
 برآمد:
	c->local_consumed += olen - sshbuf_len(c->output);

	واپس 1;
}

ساکن صحیح
channel_handle_efd_write(ساخت ssh *ssh, Channel *c)
{
	صحیح r;
	ssize_t len;

	اگر ((c->io_ready & SSH_CHAN_IO_EFD_W) == 0)
		واپس 1;
	اگر (sshbuf_len(c->extended) == 0)
		واپس 1;

	len = اكتب(c->efd, sshbuf_ptr(c->extended),
	    sshbuf_len(c->extended));
	debug2("channel %d: written %zd to efd %d", c->self, len, c->efd);
	اگر (len == -1 && (errno == EINTR || errno == EAGAIN ||
	    errno == EWOULDBLOCK))
		واپس 1;
	اگر (len <= 0) {
		debug2("channel %d: closing write-efd %d", c->self, c->efd);
		channel_close_fd(ssh, c, &c->efd);
	} ورنہ {
		اگر ((r = sshbuf_consume(c->extended, len)) != 0)
			fatal_fr(r, "channel %i: consume", c->self);
		c->local_consumed += len;
		channel_سیٹ_مستعمل_وقت(ssh, c);
	}
	واپس 1;
}

ساکن صحیح
channel_handle_efd_read(ساخت ssh *ssh, Channel *c)
{
	حرف buf[CHAN_RBUF];
	ssize_t len;
	صحیح r, force;

	force = c->isatty && c->detach_close && c->istate != CHAN_داخلہ_CLOSED;

	اگر (!force && (c->io_ready & SSH_CHAN_IO_EFD_R) == 0)
		واپس 1;

	len = اقرأ(c->efd, buf, حجم(buf));
	debug2("channel %d: read %zd from efd %d", c->self, len, c->efd);
	اگر (len == -1 && (errno == EINTR || ((errno == EAGAIN ||
	    errno == EWOULDBLOCK) && !force)))
		واپس 1;
	اگر (len <= 0) {
		debug2("channel %d: closing read-efd %d", c->self, c->efd);
		channel_close_fd(ssh, c, &c->efd);
		واپس 1;
	}
	channel_سیٹ_مستعمل_وقت(ssh, c);
	اگر (c->extended_usage == CHAN_EXTENDED_IGNORE)
		debug3("channel %d: discard efd", c->self);
	ورنہ اگر ((r = sshbuf_put(c->extended, buf, len)) != 0)
		fatal_fr(r, "channel %i: append", c->self);
	واپس 1;
}

ساکن صحیح
channel_handle_efd(ساخت ssh *ssh, Channel *c)
{
	اگر (c->efd == -1)
		واپس 1;

	/** XXX handle drain efd, too */

	اگر (c->extended_usage == CHAN_EXTENDED_WRITE)
		واپس channel_handle_efd_write(ssh, c);
	ورنہ اگر (c->extended_usage == CHAN_EXTENDED_READ ||
	    c->extended_usage == CHAN_EXTENDED_IGNORE)
		واپس channel_handle_efd_read(ssh, c);

	واپس 1;
}

ساکن صحیح
channel_check_کھڑکی(ساخت ssh *ssh, Channel *c)
{
	صحیح r;

	اگر (c->type == SSH_CHANNEL_OPEN &&
	    !(c->flags & (CHAN_CLOSE_بھیجا|CHAN_CLOSE_RCVD)) &&
	    ((c->local_کھڑکی_max - c->local_کھڑکی >
	    c->local_maxpacket*3) ||
	    c->local_کھڑکی < c->local_کھڑکی_max/2) &&
	    c->local_consumed > 0) {
		اگر (!c->have_remote_id)
			fatal_f("channel %d: no remote id", c->self);
		اگر ((r = sshpkt_آغاز(ssh,
		    SSH2_پیغام_CHANNEL_کھڑکی_ADJUST)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->local_consumed)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0) {
			fatal_fr(r, "channel %i", c->self);
		}
		debug2("channel %d: window %d sent adjust %d", c->self,
		    c->local_کھڑکی, c->local_consumed);
		c->local_کھڑکی += c->local_consumed;
		c->local_consumed = 0;
	}
	واپس 1;
}

ساکن خالی
channel_post_open(ساخت ssh *ssh, Channel *c)
{
	channel_handle_rfd(ssh, c);
	channel_handle_wfd(ssh, c);
	channel_handle_efd(ssh, c);
	channel_check_کھڑکی(ssh, c);
}

ساکن u_int
read_mux(ساخت ssh *ssh, Channel *c, u_int need)
{
	حرف buf[CHAN_RBUF];
	ssize_t len;
	u_int rlen;
	صحیح r;

	اگر (sshbuf_len(c->داخلہ) < need) {
		rlen = need - sshbuf_len(c->داخلہ);
		len = اقرأ(c->rfd, buf, MINIMUM(rlen, CHAN_RBUF));
		اگر (len == -1 && (errno == EINTR || errno == EAGAIN))
			واپس sshbuf_len(c->داخلہ);
		اگر (len <= 0) {
			debug2("channel %d: ctl read<=0 rfd %d len %zd",
			    c->self, c->rfd, len);
			chan_read_failed(ssh, c);
			واپس 0;
		} ورنہ اگر ((r = sshbuf_put(c->داخلہ, buf, len)) != 0)
			fatal_fr(r, "channel %i: append", c->self);
	}
	واپس sshbuf_len(c->داخلہ);
}

ساکن خالی
channel_post_mux_client_read(ساخت ssh *ssh, Channel *c)
{
	u_int need;

	اگر ((c->io_ready & SSH_CHAN_IO_RFD) == 0)
		واپس;
	اگر (c->istate != CHAN_داخلہ_OPEN && c->istate != CHAN_داخلہ_WAIT_DRAIN)
		واپس;
	اگر (c->mux_pause)
		واپس;

	/*
	 * Don't not read past the precise end of packets to
	 * avoid disrupting fd passing.
	 */
	اگر (read_mux(ssh, c, 4) < 4) /* read header */
		واپس;
	/* XXX sshbuf_peek_u32 */
	need = PEEK_U32(sshbuf_ptr(c->داخلہ));
#تعریف_کرو CHANNEL_MUX_MAX_PACKET	(256 * 1024)
	اگر (need > CHANNEL_MUX_MAX_PACKET) {
		debug2("channel %d: packet too big %u > %u",
		    c->self, CHANNEL_MUX_MAX_PACKET, need);
		chan_rcvd_oclose(ssh, c);
		واپس;
	}
	اگر (read_mux(ssh, c, need + 4) < need + 4) /* read body */
		واپس;
	اگر (c->mux_rcb(ssh, c) != 0) {
		debug("channel %d: mux_rcb failed", c->self);
		chan_mark_dead(ssh, c);
		واپس;
	}
}

ساکن خالی
channel_post_mux_client_write(ساخت ssh *ssh, Channel *c)
{
	ssize_t len;
	صحیح r;

	اگر ((c->io_ready & SSH_CHAN_IO_WFD) == 0)
		واپس;
	اگر (sshbuf_len(c->output) == 0)
		واپس;

	len = اكتب(c->wfd, sshbuf_ptr(c->output), sshbuf_len(c->output));
	اگر (len == -1 && (errno == EINTR || errno == EAGAIN))
		واپس;
	اگر (len <= 0) {
		chan_mark_dead(ssh, c);
		واپس;
	}
	اگر ((r = sshbuf_consume(c->output, len)) != 0)
		fatal_fr(r, "channel %i: consume", c->self);
}

ساکن خالی
channel_post_mux_client(ساخت ssh *ssh, Channel *c)
{
	channel_post_mux_client_read(ssh, c);
	channel_post_mux_client_write(ssh, c);
}

ساکن خالی
channel_post_mux_listener(ساخت ssh *ssh, Channel *c)
{
	Channel *nc;
	ساخت sockaddr_storage addr;
	socklen_t addrlen;
	صحیح newsock;
	uid_t euid;
	gid_t egid;

	اگر ((c->io_ready & SSH_CHAN_IO_SOCK_R) == 0)
		واپس;

	debug("multiplexing control connection");

	/*
	 * Accept connection on control socket
	 */
	memset(&addr, 0, حجم(addr));
	addrlen = حجم(addr);
	اگر ((newsock = accept(c->sock, (ساخت sockaddr*)&addr,
	    &addrlen)) == -1) {
		error_f("accept: %s", strerror(errno));
		اگر (errno == EMFILE || errno == ENFILE)
			c->notbefore = monotime_double() + 1.0;
		واپس;
	}

	اگر (getpeereid(newsock, &euid, &egid) == -1) {
		error_f("getpeereid failed: %s", strerror(errno));
		close(newsock);
		واپس;
	}
	اگر ((euid != 0) && (getuid() != euid)) {
		error("multiplex uid mismatch: peer euid %u != uid %u",
		    (u_int)euid, (u_int)getuid());
		close(newsock);
		واپس;
	}
	nc = channel_new(ssh, "mux-control", SSH_CHANNEL_MUX_CLIENT,
	    newsock, newsock, -1, c->local_کھڑکی_max,
	    c->local_maxpacket, 0, "mux-control", 1);
	nc->mux_rcb = c->mux_rcb;
	debug3_f("new mux channel %d fd %d", nc->self, nc->sock);
	/* establish state */
	nc->mux_rcb(ssh, nc);
	/* mux state transitions must not elicit protocol messages */
	nc->flags |= CHAN_LOCAL;
}

ساکن خالی
channel_handler_init(ساخت ssh_channels *sc)
{
	chan_fn **pre, **post;

	اگر ((pre = صفر_حافظہ_دو(SSH_CHANNEL_MAX_TYPE, حجم(*pre))) == تہی ||
	    (post = صفر_حافظہ_دو(SSH_CHANNEL_MAX_TYPE, حجم(*post))) == تہی)
		fatal_f("allocation failed");

	pre[SSH_CHANNEL_OPEN] =			&channel_pre_open;
	pre[SSH_CHANNEL_X11_OPEN] =		&channel_pre_x11_open;
	pre[SSH_CHANNEL_پورٹ_LISTENER] =	&channel_pre_listener;
	pre[SSH_CHANNEL_RPORT_LISTENER] =	&channel_pre_listener;
	pre[SSH_CHANNEL_UNIX_LISTENER] =	&channel_pre_listener;
	pre[SSH_CHANNEL_RUNIX_LISTENER] =	&channel_pre_listener;
	pre[SSH_CHANNEL_X11_LISTENER] =		&channel_pre_listener;
	pre[SSH_CHANNEL_AUTH_SOCKET] =		&channel_pre_listener;
	pre[SSH_CHANNEL_CONNECTING] =		&channel_pre_connecting;
	pre[SSH_CHANNEL_DYNAMIC] =		&channel_pre_dynamic;
	pre[SSH_CHANNEL_RDYNAMIC_اختتام] =	&channel_pre_connecting;
	pre[SSH_CHANNEL_MUX_LISTENER] =		&channel_pre_listener;
	pre[SSH_CHANNEL_MUX_CLIENT] =		&channel_pre_mux_client;

	post[SSH_CHANNEL_OPEN] =		&channel_post_open;
	post[SSH_CHANNEL_پورٹ_LISTENER] =	&channel_post_پورٹ_listener;
	post[SSH_CHANNEL_RPORT_LISTENER] =	&channel_post_پورٹ_listener;
	post[SSH_CHANNEL_UNIX_LISTENER] =	&channel_post_پورٹ_listener;
	post[SSH_CHANNEL_RUNIX_LISTENER] =	&channel_post_پورٹ_listener;
	post[SSH_CHANNEL_X11_LISTENER] =	&channel_post_x11_listener;
	post[SSH_CHANNEL_AUTH_SOCKET] =		&channel_post_auth_listener;
	post[SSH_CHANNEL_CONNECTING] =		&channel_post_connecting;
	post[SSH_CHANNEL_DYNAMIC] =		&channel_post_open;
	post[SSH_CHANNEL_RDYNAMIC_اختتام] =	&channel_post_connecting;
	post[SSH_CHANNEL_MUX_LISTENER] =	&channel_post_mux_listener;
	post[SSH_CHANNEL_MUX_CLIENT] =		&channel_post_mux_client;

	sc->channel_pre = pre;
	sc->channel_post = post;
}

/* gc dead channels */
ساکن خالی
channel_garbage_collect(ساخت ssh *ssh, Channel *c)
{
	اگر (c == تہی)
		واپس;
	اگر (c->detach_user != تہی) {
		اگر (!chan_is_dead(ssh, c, c->detach_close))
			واپس;

		debug2("channel %d: gc: notify user", c->self);
		c->detach_user(ssh, c->self, 0, تہی);
		/* if we still have a callback */
		اگر (c->detach_user != تہی)
			واپس;
		debug2("channel %d: gc: user detached", c->self);
	}
	اگر (!chan_is_dead(ssh, c, 1))
		واپس;
	debug2("channel %d: garbage collecting", c->self);
	channel_free(ssh, c);
}

شمار channel_جدول { CHAN_PRE, CHAN_POST };

ساکن خالی
channel_handler(ساخت ssh *ssh, صحیح جدول, ساخت timespec *timeout)
{
	ساخت ssh_channels *sc = ssh->chanctxt;
	chan_fn **ftab = جدول == CHAN_PRE ? sc->channel_pre : sc->channel_post;
	u_int i, oalloc;
	Channel *c;
	دوہرا now;

	now = monotime_double();
	برائے (sc->nbulk = i = 0, oalloc = sc->channels_alloc; i < oalloc; i++) {
		c = sc->channels[i];
		اگر (c == تہی)
			جاری;
		/* Count open channels in bulk state */
		اگر (c->type == SSH_CHANNEL_OPEN && c->bulk)
			sc->nbulk++;
		/* Try to keep IO going while rekeying */
		اگر (ssh_packet_is_rekeying(ssh) && c->type != SSH_CHANNEL_OPEN)
			جاری;
		اگر (c->delayed) {
			اگر (جدول == CHAN_PRE)
				c->delayed = 0;
			ورنہ
				جاری;
		}
		اگر (ftab[c->type] != تہی) {
			اگر (جدول == CHAN_PRE && c->type == SSH_CHANNEL_OPEN &&
			    channel_get_expiry(ssh, c) != 0 &&
			    now >= channel_get_expiry(ssh, c)) {
				/* channel closed for inactivity */
				دوہرا deadline = c->inactive_deadline != 0.0 ?
				    c->inactive_deadline : sc->global_deadline;
				verbose("channel %d: closing after %f seconds "
				    "of inactivity", c->self, deadline);
				channel_force_close(ssh, c, 1);
			} ورنہ اگر (c->notbefore <= now) {
				/* Run handlers that are not paused. */
				(*ftab[c->type])(ssh, c);
				/* inactivity timeouts must interrupt poll() */
				اگر (timeout != تہی &&
				    c->type == SSH_CHANNEL_OPEN &&
				    channel_get_expiry(ssh, c) != 0) {
					ptimeout_deadline_monotime_double(timeout,
					    channel_get_expiry(ssh, c));
				}
			} ورنہ اگر (timeout != تہی) {
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
ساکن خالی
channel_before_prepare_io(ساخت ssh *ssh)
{
	ساخت ssh_channels *sc = ssh->chanctxt;
	Channel *c;
	u_int i, oalloc;

	برائے (i = 0, oalloc = sc->channels_alloc; i < oalloc; i++) {
		c = sc->channels[i];
		اگر (c == تہی)
			جاری;
		اگر (c->type == SSH_CHANNEL_RDYNAMIC_OPEN)
			channel_before_prepare_io_rdynamic(ssh, c);
	}
}

ساکن خالی
dump_channel_poll(ثابت حرف *func, ثابت حرف *what, Channel *c,
    u_int pollfd_انحراف, ساخت pollfd *pfd)
{
#اگر_تعریف_شدہ DEBUG_CHANNEL_POLL
	debug3("%s: channel %d: %s r%d w%d e%d s%d c->pfds [ %d %d %d %d ] "
	    "io_want 0x%02x io_ready 0x%02x pfd[%u].fd=%d "
	    "pfd.ev 0x%02x pfd.rev 0x%02x", func, c->self, what,
	    c->rfd, c->wfd, c->efd, c->sock,
	    c->pfds[0], c->pfds[1], c->pfds[2], c->pfds[3],
	    c->io_want, c->io_ready,
	    pollfd_انحراف, pfd->fd, pfd->events, pfd->revents);
#اگر_ختم
}

/* Prepare pollfd entries for a single channel */
ساکن خالی
channel_prepare_pollfd(Channel *c, u_int *اگلا_pollfd,
    ساخت pollfd *pfd, u_int npfd)
{
	u_int ev, p = *اگلا_pollfd;

	اگر (c == تہی)
		واپس;
	اگر (p + 4 > npfd) {
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
	اگر (c->rfd != -1) {
		ev = 0;
		اگر ((c->io_want & SSH_CHAN_IO_RFD) != 0)
			ev |= POLLIN;
		/* rfd == wfd */
		اگر (c->wfd == c->rfd) {
			اگر ((c->io_want & SSH_CHAN_IO_WFD) != 0)
				ev |= POLLOUT;
		}
		/* rfd == efd */
		اگر (c->efd == c->rfd) {
			اگر ((c->io_want & SSH_CHAN_IO_EFD_R) != 0)
				ev |= POLLIN;
			اگر ((c->io_want & SSH_CHAN_IO_EFD_W) != 0)
				ev |= POLLOUT;
		}
		/* rfd == sock */
		اگر (c->sock == c->rfd) {
			اگر ((c->io_want & SSH_CHAN_IO_SOCK_R) != 0)
				ev |= POLLIN;
			اگر ((c->io_want & SSH_CHAN_IO_SOCK_W) != 0)
				ev |= POLLOUT;
		}
		/* Pack a pfd entry if any event armed for this fd */
		اگر (ev != 0) {
			c->pfds[0] = p;
			pfd[p].fd = c->rfd;
			pfd[p].events = ev;
			dump_channel_poll(__func__, "rfd", c, p, &pfd[p]);
			p++;
		}
	}
	/* prepare c->wfd if wanting IO and not already handled above */
	اگر (c->wfd != -1 && c->rfd != c->wfd) {
		ev = 0;
		اگر ((c->io_want & SSH_CHAN_IO_WFD))
			ev |= POLLOUT;
		/* Pack a pfd entry if any event armed for this fd */
		اگر (ev != 0) {
			c->pfds[1] = p;
			pfd[p].fd = c->wfd;
			pfd[p].events = ev;
			dump_channel_poll(__func__, "wfd", c, p, &pfd[p]);
			p++;
		}
	}
	/* prepare c->efd if wanting IO and not already handled above */
	اگر (c->efd != -1 && c->rfd != c->efd) {
		ev = 0;
		اگر ((c->io_want & SSH_CHAN_IO_EFD_R) != 0)
			ev |= POLLIN;
		اگر ((c->io_want & SSH_CHAN_IO_EFD_W) != 0)
			ev |= POLLOUT;
		/* Pack a pfd entry if any event armed for this fd */
		اگر (ev != 0) {
			c->pfds[2] = p;
			pfd[p].fd = c->efd;
			pfd[p].events = ev;
			dump_channel_poll(__func__, "efd", c, p, &pfd[p]);
			p++;
		}
	}
	/* prepare c->sock if wanting IO and not already handled above */
	اگر (c->sock != -1 && c->rfd != c->sock) {
		ev = 0;
		اگر ((c->io_want & SSH_CHAN_IO_SOCK_R) != 0)
			ev |= POLLIN;
		اگر ((c->io_want & SSH_CHAN_IO_SOCK_W) != 0)
			ev |= POLLOUT;
		/* Pack a pfd entry if any event armed for this fd */
		اگر (ev != 0) {
			c->pfds[3] = p;
			pfd[p].fd = c->sock;
			pfd[p].events = ev;
			dump_channel_poll(__func__, "sock", c, p, &pfd[p]);
			p++;
		}
	}
	*اگلا_pollfd = p;
}

/* * Allocate/prepare poll structure */
خالی
channel_prepare_poll(ساخت ssh *ssh, ساخت pollfd **pfdp, u_int *npfd_allocp,
    u_int *npfd_activep, u_int npfd_reserved, ساخت timespec *timeout)
{
	ساخت ssh_channels *sc = ssh->chanctxt;
	u_int i, oalloc, p, npfd = npfd_reserved;

	channel_before_prepare_io(ssh); /* might create a new channel */
	/* clear out I/O flags from last poll */
	برائے (i = 0; i < sc->channels_alloc; i++) {
		اگر (sc->channels[i] == تہی)
			جاری;
		sc->channels[i]->io_want = sc->channels[i]->io_ready = 0;
	}
	/* Allocate 4x pollfd for each channel (rfd, wfd, efd, sock) */
	اگر (sc->channels_alloc >= (زیادہ_سے_زیادہ_عدد / 4) - npfd_reserved)
		fatal_f("too many channels"); /* shouldn't happen */
	npfd += sc->channels_alloc * 4;
	اگر (npfd > *npfd_allocp) {
		*pfdp = xrecallocarray(*pfdp, *npfd_allocp,
		    npfd, حجم(**pfdp));
		*npfd_allocp = npfd;
	}
	*npfd_activep = npfd_reserved;
	oalloc = sc->channels_alloc;

	channel_handler(ssh, CHAN_PRE, timeout);

	اگر (oalloc != sc->channels_alloc) {
		/* shouldn't happen */
		fatal_f("channels_alloc changed during CHAN_PRE "
		    "(was %u, now %u)", oalloc, sc->channels_alloc);
	}

	/* Prepare pollfd */
	p = npfd_reserved;
	برائے (i = 0; i < sc->channels_alloc; i++)
		channel_prepare_pollfd(sc->channels[i], &p, *pfdp, npfd);
	*npfd_activep = p;
}

ساکن خالی
fd_ready(Channel *c, صحیح p, ساخت pollfd *pfds, u_int npfd, صحیح fd,
    ثابت حرف *what, u_int revents_نقاب, u_int ready)
{
	ساخت pollfd *pfd = &pfds[p];

	اگر (fd == -1)
		واپس;
	اگر (p == -1 || (u_int)p >= npfd)
		fatal_f("channel %d: bad pfd %d (max %u)", c->self, p, npfd);
	dump_channel_poll(__func__, what, c, p, pfd);
	اگر (pfd->fd != fd) {
		fatal("channel %d: inconsistent %s fd=%d pollfd[%u].fd %d "
		    "r%d w%d e%d s%d", c->self, what, fd, p, pfd->fd,
		    c->rfd, c->wfd, c->efd, c->sock);
	}
	اگر ((pfd->revents & POLLNVAL) != 0) {
		fatal("channel %d: invalid %s pollfd[%u].fd %d r%d w%d e%d s%d",
		    c->self, what, p, pfd->fd, c->rfd, c->wfd, c->efd, c->sock);
	}
	اگر ((pfd->revents & (revents_نقاب|POLLHUP|POLLERR)) != 0)
		c->io_ready |= ready & c->io_want;
}

/*
 * After poll, perform any appropriate operations for channels which have
 * events pending.
 */
خالی
channel_after_poll(ساخت ssh *ssh, ساخت pollfd *pfd, u_int npfd)
{
	ساخت ssh_channels *sc = ssh->chanctxt;
	u_int i;
	صحیح p;
	Channel *c;

#اگر_تعریف_شدہ DEBUG_CHANNEL_POLL
	برائے (p = 0; p < (صحیح)npfd; p++) {
		اگر (pfd[p].revents == 0)
			جاری;
		debug_f("pfd[%u].fd %d rev 0x%04x",
		    p, pfd[p].fd, pfd[p].revents);
	}
#اگر_ختم

	/* Convert pollfd into c->io_ready */
	برائے (i = 0; i < sc->channels_alloc; i++) {
		c = sc->channels[i];
		اگر (c == تہی)
			جاری;
		/* if rfd is shared with efd/sock then wfd should be too */
		اگر (c->rfd != -1 && c->wfd != -1 && c->rfd != c->wfd &&
		    (c->rfd == c->efd || c->rfd == c->sock)) {
			/* Shouldn't happen */
			fatal_f("channel %d: unexpected fds r%d w%d e%d s%d",
			    c->self, c->rfd, c->wfd, c->efd, c->sock);
		}
		c->io_ready = 0;
		/* rfd, potentially shared with wfd, efd and sock */
		اگر (c->rfd != -1 && (p = c->pfds[0]) != -1) {
			fd_ready(c, p, pfd, npfd, c->rfd,
			    "rfd", POLLIN, SSH_CHAN_IO_RFD);
			اگر (c->rfd == c->wfd) {
				fd_ready(c, p, pfd, npfd, c->wfd,
				    "wfd/r", POLLOUT, SSH_CHAN_IO_WFD);
			}
			اگر (c->rfd == c->efd) {
				fd_ready(c, p, pfd, npfd, c->efd,
				    "efdr/r", POLLIN, SSH_CHAN_IO_EFD_R);
				fd_ready(c, p, pfd, npfd, c->efd,
				    "efdw/r", POLLOUT, SSH_CHAN_IO_EFD_W);
			}
			اگر (c->rfd == c->sock) {
				fd_ready(c, p, pfd, npfd, c->sock,
				    "sockr/r", POLLIN, SSH_CHAN_IO_SOCK_R);
				fd_ready(c, p, pfd, npfd, c->sock,
				    "sockw/r", POLLOUT, SSH_CHAN_IO_SOCK_W);
			}
			dump_channel_poll(__func__, "rfd", c, p, pfd);
		}
		/* wfd */
		اگر (c->wfd != -1 && c->wfd != c->rfd &&
		    (p = c->pfds[1]) != -1) {
			fd_ready(c, p, pfd, npfd, c->wfd,
			    "wfd", POLLOUT, SSH_CHAN_IO_WFD);
			dump_channel_poll(__func__, "wfd", c, p, pfd);
		}
		/* efd */
		اگر (c->efd != -1 && c->efd != c->rfd &&
		    (p = c->pfds[2]) != -1) {
			fd_ready(c, p, pfd, npfd, c->efd,
			    "efdr", POLLIN, SSH_CHAN_IO_EFD_R);
			fd_ready(c, p, pfd, npfd, c->efd,
			    "efdw", POLLOUT, SSH_CHAN_IO_EFD_W);
			dump_channel_poll(__func__, "efd", c, p, pfd);
		}
		/* sock */
		اگر (c->sock != -1 && c->sock != c->rfd &&
		    (p = c->pfds[3]) != -1) {
			fd_ready(c, p, pfd, npfd, c->sock,
			    "sockr", POLLIN, SSH_CHAN_IO_SOCK_R);
			fd_ready(c, p, pfd, npfd, c->sock,
			    "sockw", POLLOUT, SSH_CHAN_IO_SOCK_W);
			dump_channel_poll(__func__, "sock", c, p, pfd);
		}
	}
	channel_handler(ssh, CHAN_POST, تہی);
}

/*
 * Enqueue data for channels with open or draining c->input.
 * Returns non-zero if a packet was enqueued.
 */
ساکن صحیح
channel_output_poll_داخلہ_open(ساخت ssh *ssh, Channel *c)
{
	سائز_t len, plen;
	ثابت u_char *pkt;
	صحیح r;

	اگر ((len = sshbuf_len(c->داخلہ)) == 0) {
		اگر (c->istate == CHAN_داخلہ_WAIT_DRAIN) {
			/*
			 * input-buffer is empty and read-socket shutdown:
			 * tell peer, that we will not send more data:
			 * send IEOF.
			 * hack for extended data: delay EOF if EFD still
			 * in use.
			 */
			اگر (CHANNEL_EFD_داخلہ_فعال(c))
				debug2("channel %d: "
				    "ibuf_empty delayed efd %d/(%zu)",
				    c->self, c->efd, sshbuf_len(c->extended));
			ورنہ
				chan_ibuf_خالی_خانے(ssh, c);
		}
		واپس 0;
	}

	اگر (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);

	اگر (c->datagram) {
		/* Check datagram will fit; drop if not */
		اگر ((r = sshbuf_get_string_براہ_راست(c->داخلہ, &pkt, &plen)) != 0)
			fatal_fr(r, "channel %i: get datagram", c->self);
		/*
		 * XXX this does tail-drop on the datagram queue which is
		 * usually suboptimal compared to head-drop. Better to have
		 * backpressure at read time? (i.e. read + discard)
		 */
		اگر (plen > c->remote_کھڑکی || plen > c->remote_maxpacket) {
			debug("channel %d: datagram too big", c->self);
			واپس 0;
		}
		/* Enqueue it */
		اگر ((r = sshpkt_آغاز(ssh, SSH2_پیغام_CHANNEL_ڈیٹا)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
		    (r = sshpkt_put_string(ssh, pkt, plen)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "channel %i: send datagram", c->self);
		c->remote_کھڑکی -= plen;
		واپس 1;
	}

	/* Enqueue packet for buffered data. */
	اگر (len > c->remote_کھڑکی)
		len = c->remote_کھڑکی;
	اگر (len > c->remote_maxpacket)
		len = c->remote_maxpacket;
	اگر (len == 0)
		واپس 0;
	اگر ((r = sshpkt_آغاز(ssh, SSH2_پیغام_CHANNEL_ڈیٹا)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_string(ssh, sshbuf_ptr(c->داخلہ), len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i: send data", c->self);
	اگر ((r = sshbuf_consume(c->داخلہ, len)) != 0)
		fatal_fr(r, "channel %i: consume", c->self);
	c->remote_کھڑکی -= len;
	واپس 1;
}

/*
 * Enqueue data for channels with open c->extended in read mode.
 * Returns non-zero if a packet was enqueued.
 */
ساکن صحیح
channel_output_poll_extended_read(ساخت ssh *ssh, Channel *c)
{
	سائز_t len;
	صحیح r;

	اگر ((len = sshbuf_len(c->extended)) == 0)
		واپس 0;

	debug2("channel %d: rwin %u elen %zu euse %d", c->self,
	    c->remote_کھڑکی, sshbuf_len(c->extended), c->extended_usage);
	اگر (len > c->remote_کھڑکی)
		len = c->remote_کھڑکی;
	اگر (len > c->remote_maxpacket)
		len = c->remote_maxpacket;
	اگر (len == 0)
		واپس 0;
	اگر (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);
	اگر ((r = sshpkt_آغاز(ssh, SSH2_پیغام_CHANNEL_EXTENDED_ڈیٹا)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_u32(ssh, SSH2_EXTENDED_ڈیٹا_STDERR)) != 0 ||
	    (r = sshpkt_put_string(ssh, sshbuf_ptr(c->extended), len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i: data", c->self);
	اگر ((r = sshbuf_consume(c->extended, len)) != 0)
		fatal_fr(r, "channel %i: consume", c->self);
	c->remote_کھڑکی -= len;
	debug2("channel %d: sent ext data %zu", c->self, len);
	واپس 1;
}

/*
 * If there is data to send to the connection, enqueue some of it now.
 * Returns non-zero if data was enqueued.
 */
صحیح
channel_output_poll(ساخت ssh *ssh)
{
	ساخت ssh_channels *sc = ssh->chanctxt;
	Channel *c;
	u_int i;
	صحیح ret = 0;

	برائے (i = 0; i < sc->channels_alloc; i++) {
		c = sc->channels[i];
		اگر (c == تہی)
			جاری;

		/*
		 * We are only interested in channels that can have buffered
		 * incoming data.
		 */
		اگر (c->type != SSH_CHANNEL_OPEN)
			جاری;
		اگر ((c->flags & (CHAN_CLOSE_بھیجا|CHAN_CLOSE_RCVD))) {
			/* XXX is this true? */
			debug3("channel %d: will not send data after close",
			    c->self);
			جاری;
		}

		/* Get the amount of buffered data for this channel. */
		اگر (c->istate == CHAN_داخلہ_OPEN ||
		    c->istate == CHAN_داخلہ_WAIT_DRAIN)
			ret |= channel_output_poll_داخلہ_open(ssh, c);
		/* Send extended data, i.e. stderr */
		اگر (!(c->flags & CHAN_EOF_بھیجا) &&
		    c->extended_usage == CHAN_EXTENDED_READ)
			ret |= channel_output_poll_extended_read(ssh, c);
	}
	واپس ret;
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
صحیح
channel_proxy_downstream(ساخت ssh *ssh, Channel *downstream)
{
	Channel *c = تہی;
	ساخت sshbuf *original = تہی, *modified = تہی;
	ثابت u_char *cp;
	حرف *ctype = تہی, *listen_host = تہی;
	u_char type;
	سائز_t have;
	صحیح ret = -1, r;
	u_int id, remote_id, listen_پورٹ;

	/* sshbuf_dump(downstream->input, stderr); */
	اگر ((r = sshbuf_get_string_براہ_راست(downstream->داخلہ, &cp, &have))
	    != 0) {
		error_fr(r, "parse");
		واپس -1;
	}
	اگر (have < 2) {
		error_f("short message");
		واپس -1;
	}
	type = cp[1];
	/* skip padlen + type */
	cp += 2;
	have -= 2;
	اگر (ssh_packet_log_type(type))
		debug3_f("channel %u: down->up: type %u",
		    downstream->self, type);

	انتخاب (type) {
	حالت SSH2_پیغام_CHANNEL_OPEN:
		اگر ((original = sshbuf_from(cp, have)) == تہی ||
		    (modified = sshbuf_new()) == تہی) {
			error_f("alloc");
			جاؤ برآمد;
		}
		اگر ((r = sshbuf_get_cstring(original, &ctype, تہی)) != 0 ||
		    (r = sshbuf_get_u32(original, &id)) != 0) {
			error_fr(r, "parse");
			جاؤ برآمد;
		}
		c = channel_new(ssh, "mux-proxy", SSH_CHANNEL_MUX_PROXY,
		    -1, -1, -1, 0, 0, 0, ctype, 1);
		c->mux_ctx = downstream;	/* point to mux client */
		c->mux_downstream_id = id;	/* original downstream id */
		اگر ((r = sshbuf_put_cstring(modified, ctype)) != 0 ||
		    (r = sshbuf_put_u32(modified, c->self)) != 0 ||
		    (r = sshbuf_putb(modified, original)) != 0) {
			error_fr(r, "compose");
			channel_free(ssh, c);
			جاؤ برآمد;
		}
		توڑو;
	حالت SSH2_پیغام_CHANNEL_OPEN_CONFIRMATION:
		/*
		 * Almost the same as SSH2_MSG_CHANNEL_OPEN, except then we
		 * need to parse 'remote_id' instead of 'ctype'.
		 */
		اگر ((original = sshbuf_from(cp, have)) == تہی ||
		    (modified = sshbuf_new()) == تہی) {
			error_f("alloc");
			جاؤ برآمد;
		}
		اگر ((r = sshbuf_get_u32(original, &remote_id)) != 0 ||
		    (r = sshbuf_get_u32(original, &id)) != 0) {
			error_fr(r, "parse");
			جاؤ برآمد;
		}
		c = channel_new(ssh, "mux-proxy", SSH_CHANNEL_MUX_PROXY,
		    -1, -1, -1, 0, 0, 0, "mux-down-connect", 1);
		c->mux_ctx = downstream;	/* point to mux client */
		c->mux_downstream_id = id;
		c->remote_id = remote_id;
		c->have_remote_id = 1;
		اگر ((r = sshbuf_put_u32(modified, remote_id)) != 0 ||
		    (r = sshbuf_put_u32(modified, c->self)) != 0 ||
		    (r = sshbuf_putb(modified, original)) != 0) {
			error_fr(r, "compose");
			channel_free(ssh, c);
			جاؤ برآمد;
		}
		توڑو;
	حالت SSH2_پیغام_GLOBAL_REQUEST:
		اگر ((original = sshbuf_from(cp, have)) == تہی) {
			error_f("alloc");
			جاؤ برآمد;
		}
		اگر ((r = sshbuf_get_cstring(original, &ctype, تہی)) != 0) {
			error_fr(r, "parse");
			جاؤ برآمد;
		}
		اگر (strcmp(ctype, "tcpip-forward") != 0) {
			error_f("unsupported request %s", ctype);
			جاؤ برآمد;
		}
		اگر ((r = sshbuf_get_u8(original, تہی)) != 0 ||
		    (r = sshbuf_get_cstring(original, &listen_host, تہی)) != 0 ||
		    (r = sshbuf_get_u32(original, &listen_پورٹ)) != 0) {
			error_fr(r, "parse");
			جاؤ برآمد;
		}
		اگر (listen_پورٹ > 65535) {
			error_f("tcpip-forward for %s: bad port %u",
			    listen_host, listen_پورٹ);
			جاؤ برآمد;
		}
		/* Record that connection to this host/port is permitted. */
		permission_سیٹ_جوڑو(ssh, FORWARD_USER, FORWARD_LOCAL, "<mux>",
		    -1, listen_host, تہی, (صحیح)listen_پورٹ, downstream);
		توڑو;
	حالت SSH2_پیغام_CHANNEL_CLOSE:
		اگر (have < 4)
			توڑو;
		remote_id = PEEK_U32(cp);
		اگر ((c = channel_by_remote_id(ssh, remote_id)) != تہی) {
			اگر (c->flags & CHAN_CLOSE_RCVD)
				channel_free(ssh, c);
			ورنہ
				c->flags |= CHAN_CLOSE_بھیجا;
		}
		توڑو;
	}
	اگر (modified) {
		اگر ((r = sshpkt_آغاز(ssh, type)) != 0 ||
		    (r = sshpkt_putb(ssh, modified)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0) {
			error_fr(r, "send");
			جاؤ برآمد;
		}
	} ورنہ {
		اگر ((r = sshpkt_آغاز(ssh, type)) != 0 ||
		    (r = sshpkt_put(ssh, cp, have)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0) {
			error_fr(r, "send");
			جاؤ برآمد;
		}
	}
	ret = 0;
 برآمد:
	آزاد(ctype);
	آزاد(listen_host);
	sshbuf_free(original);
	sshbuf_free(modified);
	واپس ret;
}

/*
 * receive packets from upstream server and de-multiplex packets
 * to correct downstream:
 * implemented as a helper for channel input handlers,
 * replaces local (proxy) channel ID with downstream channel ID.
 */
صحیح
channel_proxy_upstream(Channel *c, صحیح type, uint32_t seq, ساخت ssh *ssh)
{
	ساخت sshbuf *b = تہی;
	Channel *downstream;
	ثابت u_char *cp = تہی;
	سائز_t len;
	صحیح r;

	/*
	 * When receiving packets from the peer we need to check whether we
	 * need to forward the packets to the mux client. In this case we
	 * restore the original channel id and keep track of CLOSE messages,
	 * so we can cleanup the channel.
	 */
	اگر (c == تہی || c->type != SSH_CHANNEL_MUX_PROXY)
		واپس 0;
	اگر ((downstream = c->mux_ctx) == تہی)
		واپس 0;
	انتخاب (type) {
	حالت SSH2_پیغام_CHANNEL_CLOSE:
	حالت SSH2_پیغام_CHANNEL_ڈیٹا:
	حالت SSH2_پیغام_CHANNEL_EOF:
	حالت SSH2_پیغام_CHANNEL_EXTENDED_ڈیٹا:
	حالت SSH2_پیغام_CHANNEL_OPEN_CONFIRMATION:
	حالت SSH2_پیغام_CHANNEL_OPEN_FAILURE:
	حالت SSH2_پیغام_CHANNEL_کھڑکی_ADJUST:
	حالت SSH2_پیغام_CHANNEL_SUCCESS:
	حالت SSH2_پیغام_CHANNEL_FAILURE:
	حالت SSH2_پیغام_CHANNEL_REQUEST:
		توڑو;
	طےشدہ:
		debug2_f("channel %u: unsupported type %u", c->self, type);
		واپس 0;
	}
	اگر ((b = sshbuf_new()) == تہی) {
		error_f("alloc reply");
		جاؤ برآمد;
	}
	/* get remaining payload (after id) */
	cp = sshpkt_ptr(ssh, &len);
	اگر (cp == تہی) {
		error_f("no packet");
		جاؤ برآمد;
	}
	/* translate id and send to muxclient */
	اگر ((r = sshbuf_put_u8(b, 0)) != 0 ||	/* padlen */
	    (r = sshbuf_put_u8(b, type)) != 0 ||
	    (r = sshbuf_put_u32(b, c->mux_downstream_id)) != 0 ||
	    (r = sshbuf_put(b, cp, len)) != 0 ||
	    (r = sshbuf_put_stringb(downstream->output, b)) != 0) {
		error_fr(r, "compose muxclient");
		جاؤ برآمد;
	}
	/* sshbuf_dump(b, stderr); */
	اگر (ssh_packet_log_type(type))
		debug3_f("channel %u: up->down: type %u", c->self, type);
 برآمد:
	/* update state */
	انتخاب (type) {
	حالت SSH2_پیغام_CHANNEL_OPEN_CONFIRMATION:
		/* record remote_id for SSH2_MSG_CHANNEL_CLOSE */
		اگر (cp && len > 4) {
			c->remote_id = PEEK_U32(cp);
			c->have_remote_id = 1;
		}
		توڑو;
	حالت SSH2_پیغام_CHANNEL_CLOSE:
		اگر (c->flags & CHAN_CLOSE_بھیجا)
			channel_free(ssh, c);
		ورنہ
			c->flags |= CHAN_CLOSE_RCVD;
		توڑو;
	}
	sshbuf_free(b);
	واپس 1;
}

/* -- protocol input */

/* Parse a channel ID from the current packet */
ساکن صحیح
channel_parse_id(ساخت ssh *ssh, ثابت حرف *where, ثابت حرف *what)
{
	uint32_t id;
	صحیح r;

	اگر ((r = sshpkt_get_u32(ssh, &id)) != 0) {
		error_r(r, "%s: parse id", where);
		ssh_packet_disconnect(ssh, "Invalid %s message", what);
	}
	اگر (id > زیادہ_سے_زیادہ_عدد) {
		error_r(r, "%s: bad channel id %u", where, id);
		ssh_packet_disconnect(ssh, "Invalid %s channel id", what);
	}
	واپس (صحیح)id;
}

/* Lookup a channel from an ID in the current packet */
ساکن Channel *
channel_from_packet_id(ساخت ssh *ssh, ثابت حرف *where, ثابت حرف *what)
{
	صحیح id = channel_parse_id(ssh, where, what);
	Channel *c;

	اگر ((c = channel_lookup(ssh, id)) == تہی) {
		ssh_packet_disconnect(ssh,
		    "%s packet referred to nonexistent channel %d", what, id);
	}
	واپس c;
}

صحیح
channel_داخلہ_ڈیٹا(صحیح type, uint32_t seq, ساخت ssh *ssh)
{
	ثابت u_char *ڈیٹا;
	سائز_t ڈیٹا_len, win_len;
	Channel *c = channel_from_packet_id(ssh, __func__, "data");
	صحیح r;

	اگر (channel_proxy_upstream(c, type, seq, ssh))
		واپس 0;

	/* Ignore any data for non-open channels (might happen on close) */
	اگر (c->type != SSH_CHANNEL_OPEN &&
	    c->type != SSH_CHANNEL_RDYNAMIC_OPEN &&
	    c->type != SSH_CHANNEL_RDYNAMIC_اختتام &&
	    c->type != SSH_CHANNEL_X11_OPEN)
		واپس 0;

	/* Get the data. */
	اگر ((r = sshpkt_get_string_براہ_راست(ssh, &ڈیٹا, &ڈیٹا_len)) != 0 ||
            (r = sshpkt_get_انتہا(ssh)) != 0)
		fatal_fr(r, "channel %i: get data", c->self);

	win_len = ڈیٹا_len;
	اگر (c->datagram)
		win_len += 4;  /* string length header */

	/*
	 * The sending side reduces its window as it sends data, so we
	 * must 'fake' consumption of the data in order to ensure that window
	 * updates are sent back. Otherwise the connection might deadlock.
	 */
	اگر (c->ostate != CHAN_OUTPUT_OPEN) {
		اگر (win_len > c->local_کھڑکی)
			c->local_کھڑکی = 0;
		ورنہ
			c->local_کھڑکی -= win_len;
		c->local_consumed += win_len;
		واپس 0;
	}

	اگر (win_len > c->local_maxpacket) {
		logit("channel %d: rcvd big packet %zu, maxpack %u",
		    c->self, win_len, c->local_maxpacket);
		واپس 0;
	}
	اگر (win_len > c->local_کھڑکی) {
		u_int delta = win_len - c->local_کھڑکی;

		اگر (c->local_کھڑکی_exceeded > UINT_MAX - delta)
			c->local_کھڑکی_exceeded = UINT_MAX;
		ورنہ
			c->local_کھڑکی_exceeded += delta;
		logit("channel %d: rcvd too much data %zu, win %u/%u "
		    "(excess %u)", c->self, win_len, c->local_کھڑکی,
		    c->local_کھڑکی_max, c->local_کھڑکی_exceeded);
		c->local_کھڑکی = 0;
		/* Allow 10% grace before bringing the hammer down */
		اگر (c->local_کھڑکی_exceeded > (c->local_کھڑکی_max / 10)) {
			ssh_packet_disconnect(ssh, "channel %d: peer ignored "
			    "channel window", c->self);
		}
	} ورنہ {
		c->local_کھڑکی -= win_len;
		c->local_کھڑکی_exceeded = 0;
	}

	اگر (c->datagram) {
		اگر ((r = sshbuf_put_string(c->output, ڈیٹا, ڈیٹا_len)) != 0)
			fatal_fr(r, "channel %i: append datagram", c->self);
	} ورنہ اگر ((r = sshbuf_put(c->output, ڈیٹا, ڈیٹا_len)) != 0)
		fatal_fr(r, "channel %i: append data", c->self);

	واپس 0;
}

صحیح
channel_داخلہ_extended_ڈیٹا(صحیح type, uint32_t seq, ساخت ssh *ssh)
{
	ثابت u_char *ڈیٹا;
	سائز_t ڈیٹا_len;
	uint32_t tcode;
	Channel *c = channel_from_packet_id(ssh, __func__, "extended data");
	صحیح r;

	اگر (channel_proxy_upstream(c, type, seq, ssh))
		واپس 0;
	اگر (c->type != SSH_CHANNEL_OPEN) {
		logit("channel %d: ext data for non open", c->self);
		واپس 0;
	}
	اگر (c->flags & CHAN_EOF_RCVD) {
		اگر (ssh->compat & SSH_BUG_EXTEOF)
			debug("channel %d: accepting ext data after eof",
			    c->self);
		ورنہ
			ssh_packet_disconnect(ssh, "Received extended_data "
			    "after EOF on channel %d.", c->self);
	}

	اگر ((r = sshpkt_get_u32(ssh, &tcode)) != 0) {
		error_fr(r, "parse tcode");
		ssh_packet_disconnect(ssh, "Invalid extended_data message");
	}
	اگر (c->efd == -1 ||
	    c->extended_usage != CHAN_EXTENDED_WRITE ||
	    tcode != SSH2_EXTENDED_ڈیٹا_STDERR) {
		logit("channel %d: bad ext data", c->self);
		واپس 0;
	}
	اگر ((r = sshpkt_get_string_براہ_راست(ssh, &ڈیٹا, &ڈیٹا_len)) != 0 ||
            (r = sshpkt_get_انتہا(ssh)) != 0) {
		error_fr(r, "parse data");
		ssh_packet_disconnect(ssh, "Invalid extended_data message");
	}

	اگر (ڈیٹا_len > c->local_کھڑکی) {
		logit("channel %d: rcvd too much extended_data %zu, win %u",
		    c->self, ڈیٹا_len, c->local_کھڑکی);
		واپس 0;
	}
	debug2("channel %d: rcvd ext data %zu", c->self, ڈیٹا_len);
	/* XXX sshpkt_getb? */
	اگر ((r = sshbuf_put(c->extended, ڈیٹا, ڈیٹا_len)) != 0)
		error_fr(r, "append");
	c->local_کھڑکی -= ڈیٹا_len;
	واپس 0;
}

صحیح
channel_داخلہ_ieof(صحیح type, uint32_t seq, ساخت ssh *ssh)
{
	Channel *c = channel_from_packet_id(ssh, __func__, "ieof");
	صحیح r;

        اگر ((r = sshpkt_get_انتہا(ssh)) != 0) {
		error_fr(r, "parse data");
		ssh_packet_disconnect(ssh, "Invalid ieof message");
	}

	اگر (channel_proxy_upstream(c, type, seq, ssh))
		واپس 0;
	chan_rcvd_ieof(ssh, c);

	/* XXX force input close */
	اگر (c->force_drain && c->istate == CHAN_داخلہ_OPEN) {
		debug("channel %d: FORCE input drain", c->self);
		c->istate = CHAN_داخلہ_WAIT_DRAIN;
		اگر (sshbuf_len(c->داخلہ) == 0)
			chan_ibuf_خالی_خانے(ssh, c);
	}
	واپس 0;
}

صحیح
channel_داخلہ_oclose(صحیح type, uint32_t seq, ساخت ssh *ssh)
{
	Channel *c = channel_from_packet_id(ssh, __func__, "oclose");
	صحیح r;

	اگر (channel_proxy_upstream(c, type, seq, ssh))
		واپس 0;
        اگر ((r = sshpkt_get_انتہا(ssh)) != 0) {
		error_fr(r, "parse data");
		ssh_packet_disconnect(ssh, "Invalid oclose message");
	}
	chan_rcvd_oclose(ssh, c);
	واپس 0;
}

صحیح
channel_داخلہ_open_confirmation(صحیح type, uint32_t seq, ساخت ssh *ssh)
{
	Channel *c = channel_from_packet_id(ssh, __func__, "open confirmation");
	uint32_t remote_کھڑکی, remote_maxpacket;
	صحیح r;

	اگر (channel_proxy_upstream(c, type, seq, ssh))
		واپس 0;
	اگر (c->type != SSH_CHANNEL_OPENING)
		ssh_packet_disconnect(ssh, "Received open confirmation for "
		    "non-opening channel %d.", c->self);
	/*
	 * Record the remote channel number and mark that the channel
	 * is now open.
	 */
	اگر ((r = sshpkt_get_u32(ssh, &c->remote_id)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &remote_کھڑکی)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &remote_maxpacket)) != 0 ||
            (r = sshpkt_get_انتہا(ssh)) != 0) {
		error_fr(r, "window/maxpacket");
		ssh_packet_disconnect(ssh, "Invalid open confirmation message");
	}

	c->have_remote_id = 1;
	c->remote_کھڑکی = remote_کھڑکی;
	c->remote_maxpacket = remote_maxpacket;
	c->type = SSH_CHANNEL_OPEN;
	اگر (c->open_confirm) {
		debug2_f("channel %d: callback start", c->self);
		c->open_confirm(ssh, c->self, 1, c->open_confirm_ctx);
		debug2_f("channel %d: callback done", c->self);
	}
	channel_سیٹ_مستعمل_وقت(ssh, c);
	debug2("channel %d: open confirm rwindow %u rmax %u", c->self,
	    c->remote_کھڑکی, c->remote_maxpacket);
	واپس 0;
}

ساکن حرف *
reason2txt(صحیح reason)
{
	انتخاب (reason) {
	حالت SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED:
		واپس "administratively prohibited";
	حالت SSH2_OPEN_CONNECT_FAILED:
		واپس "connect failed";
	حالت SSH2_OPEN_UNKNOWN_CHANNEL_TYPE:
		واپس "unknown channel type";
	حالت SSH2_OPEN_RESOURCE_SHORTAGE:
		واپس "resource shortage";
	}
	واپس "unknown reason";
}

صحیح
channel_داخلہ_open_failure(صحیح type, uint32_t seq, ساخت ssh *ssh)
{
	Channel *c = channel_from_packet_id(ssh, __func__, "open failure");
	uint32_t reason;
	حرف *پیغام = تہی;
	صحیح r;

	اگر (channel_proxy_upstream(c, type, seq, ssh))
		واپس 0;
	اگر (c->type != SSH_CHANNEL_OPENING)
		ssh_packet_disconnect(ssh, "Received open failure for "
		    "non-opening channel %d.", c->self);
	اگر ((r = sshpkt_get_u32(ssh, &reason)) != 0) {
		error_fr(r, "parse reason");
		ssh_packet_disconnect(ssh, "Invalid open failure message");
	}
	/* skip language */
	اگر ((r = sshpkt_get_cstring(ssh, &پیغام, تہی)) != 0 ||
	    (r = sshpkt_get_string_براہ_راست(ssh, تہی, تہی)) != 0 ||
            (r = sshpkt_get_انتہا(ssh)) != 0) {
		error_fr(r, "parse msg/lang");
		ssh_packet_disconnect(ssh, "Invalid open failure message");
	}
	logit("channel %d: open failed: %s%s%s", c->self,
	    reason2txt(reason), پیغام ? ": ": "", پیغام ? پیغام : "");
	آزاد(پیغام);
	اگر (c->open_confirm) {
		debug2_f("channel %d: callback start", c->self);
		c->open_confirm(ssh, c->self, 0, c->open_confirm_ctx);
		debug2_f("channel %d: callback done", c->self);
	}
	/* Schedule the channel for cleanup/deletion. */
	chan_mark_dead(ssh, c);
	واپس 0;
}

صحیح
channel_داخلہ_کھڑکی_adjust(صحیح type, uint32_t seq, ساخت ssh *ssh)
{
	صحیح id = channel_parse_id(ssh, __func__, "window adjust");
	Channel *c;
	uint32_t adjust;
	u_int new_rwin;
	صحیح r;

	اگر ((c = channel_lookup(ssh, id)) == تہی) {
		logit("Received window adjust for non-open channel %d.", id);
		واپس 0;
	}

	اگر (channel_proxy_upstream(c, type, seq, ssh))
		واپس 0;
	اگر ((r = sshpkt_get_u32(ssh, &adjust)) != 0 ||
            (r = sshpkt_get_انتہا(ssh)) != 0) {
		error_fr(r, "parse adjust");
		ssh_packet_disconnect(ssh, "Invalid window adjust message");
	}
	debug2("channel %d: rcvd adjust %u", c->self, adjust);
	اگر ((new_rwin = c->remote_کھڑکی + adjust) < c->remote_کھڑکی) {
		fatal("channel %d: adjust %u overflows remote window %u",
		    c->self, adjust, c->remote_کھڑکی);
	}
	c->remote_کھڑکی = new_rwin;
	واپس 0;
}

صحیح
channel_داخلہ_حالت_confirm(صحیح type, uint32_t seq, ساخت ssh *ssh)
{
	صحیح id = channel_parse_id(ssh, __func__, "status confirm");
	Channel *c;
	ساخت channel_confirm *cc;

	/* Reset keepalive timeout */
	ssh_packet_سیٹ_alive_timeouts(ssh, 0);

	debug2_f("type %d id %d", type, id);

	اگر ((c = channel_lookup(ssh, id)) == تہی) {
		logit_f("%d: unknown", id);
		واپس 0;
	}
	اگر (channel_proxy_upstream(c, type, seq, ssh))
		واپس 0;
        اگر (sshpkt_get_انتہا(ssh) != 0)
		ssh_packet_disconnect(ssh, "Invalid status confirm message");
	اگر ((cc = TAILQ_FIRST(&c->حالت_confirms)) == تہی)
		واپس 0;
	cc->cb(ssh, type, c, cc->ctx);
	TAILQ_REMOVE(&c->حالت_confirms, cc, اندراج_2);
	freezero(cc, حجم(*cc));
	واپس 0;
}

/* -- tcp forwarding */

خالی
channel_سیٹ_af(ساخت ssh *ssh, صحیح af)
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
ساکن ثابت حرف *
channel_fwd_bind_addr(ساخت ssh *ssh, ثابت حرف *listen_addr, صحیح *wildcardp,
    صحیح is_client, ساخت ForwardOptions *fwd_opts)
{
	ثابت حرف *addr = تہی;
	صحیح wildcard = 0;

	اگر (listen_addr == تہی) {
		/* No address specified: default to gateway_ports setting */
		اگر (fwd_opts->gateway_ports)
			wildcard = 1;
	} ورنہ اگر (fwd_opts->gateway_ports || is_client) {
		اگر (((ssh->compat & SSH_OLD_FORWARD_ADDR) &&
		    strcmp(listen_addr, "0.0.0.0") == 0 && is_client == 0) ||
		    *listen_addr == '\0' || strcmp(listen_addr, "*") == 0 ||
		    (!is_client && fwd_opts->gateway_ports == 1)) {
			wildcard = 1;
			/*
			 * Notify client if they requested a specific listen
			 * address and it was overridden.
			 */
			اگر (*listen_addr != '\0' &&
			    strcmp(listen_addr, "0.0.0.0") != 0 &&
			    strcmp(listen_addr, "*") != 0) {
				ssh_packet_send_debug(ssh,
				    "Forwarding listen address "
				    "\"%s\" overridden by server "
				    "GatewayPorts", listen_addr);
			}
		} ورنہ اگر (strcmp(listen_addr, "localhost") != 0 ||
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
	} ورنہ اگر (strcmp(listen_addr, "127.0.0.1") == 0 ||
	    strcmp(listen_addr, "::1") == 0) {
		/*
		 * If a specific IPv4/IPv6 localhost address has been
		 * requested then accept it even if gateway_ports is in
		 * effect. This allows the client to prefer IPv4 or IPv6.
		 */
		addr = listen_addr;
	}
	اگر (wildcardp != تہی)
		*wildcardp = wildcard;
	واپس addr;
}

ساکن صحیح
channel_تیاری_fwd_listener_tcpip(ساخت ssh *ssh, صحیح type,
    ساخت Forward *fwd, صحیح *allocated_listen_پورٹ,
    ساخت ForwardOptions *fwd_opts)
{
	Channel *c;
	صحیح sock, r, success = 0, wildcard = 0, is_client;
	ساخت addrinfo hints, *ai, *aitop;
	ثابت حرف *host, *addr;
	حرف ntop[NI_MAXHOST], strport[NI_MAXSERV];
	in_port_t *lport_p;

	is_client = (type == SSH_CHANNEL_پورٹ_LISTENER);

	اگر (is_client && fwd->connect_راستہ != تہی) {
		host = fwd->connect_راستہ;
	} ورنہ {
		host = (type == SSH_CHANNEL_RPORT_LISTENER) ?
		    fwd->listen_host : fwd->connect_host;
		اگر (host == تہی) {
			error("No forward host name.");
			واپس 0;
		}
		اگر (لڑی_لمبائی(host) >= NI_MAXHOST) {
			error("Forward host name too long.");
			واپس 0;
		}
	}

	/* Determine the bind address, cf. channel_fwd_bind_addr() comment */
	addr = channel_fwd_bind_addr(ssh, fwd->listen_host, &wildcard,
	    is_client, fwd_opts);
	debug3_f("type %d wildcard %d addr %s", type, wildcard,
	    (addr == تہی) ? "NULL" : addr);

	/*
	 * getaddrinfo returns a loopback address if the hostname is
	 * set to NULL and hints.ai_flags is not AI_PASSIVE
	 */
	memset(&hints, 0, حجم(hints));
	hints.ai_family = ssh->chanctxt->IPv4or6;
	hints.ai_flags = wildcard ? AI_PASSIVE : 0;
	hints.ai_socktype = SOCK_STREAM;
	snprintf(strport, حجم strport, "%d", fwd->listen_پورٹ);
	اگر ((r = getaddrinfo(addr, strport, &hints, &aitop)) != 0) {
		اگر (addr == تہی) {
			/* This really shouldn't happen */
			ssh_packet_disconnect(ssh, "getaddrinfo: fatal error: %s",
			    ssh_gai_strerror(r));
		} ورنہ {
			error_f("getaddrinfo(%.64s): %s", addr,
			    ssh_gai_strerror(r));
		}
		واپس 0;
	}
	اگر (allocated_listen_پورٹ != تہی)
		*allocated_listen_پورٹ = 0;
	برائے (ai = aitop; ai; ai = ai->ai_next) {
		انتخاب (ai->ai_family) {
		حالت AF_INET:
			lport_p = &((ساخت sockaddr_in *)ai->ai_addr)->
			    sin_port;
			توڑو;
		حالت AF_INET6:
			lport_p = &((ساخت sockaddr_in6 *)ai->ai_addr)->
			    sin6_port;
			توڑو;
		طےشدہ:
			جاری;
		}
		/*
		 * If allocating a port for -R forwards, then use the
		 * same port for all address families.
		 */
		اگر (type == SSH_CHANNEL_RPORT_LISTENER &&
		    fwd->listen_پورٹ == 0 && allocated_listen_پورٹ != تہی &&
		    *allocated_listen_پورٹ > 0)
			*lport_p = htons(*allocated_listen_پورٹ);

		اگر (getnameinfo(ai->ai_addr, ai->ai_addrlen, ntop, حجم(ntop),
		    strport, حجم(strport),
		    NI_NUMERICHOST|NI_NUMERICSERV) != 0) {
			error_f("getnameinfo failed");
			جاری;
		}
		/* Create a port to listen for the host. */
		sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		اگر (sock == -1) {
			/* this is no error since kernel may not support ipv6 */
			verbose("socket [%s]:%s: %.100s", ntop, strport,
			    strerror(errno));
			جاری;
		}

		سیٹ_reuseaddr(sock);
		اگر (ai->ai_family == AF_INET6)
			sock_سیٹ_v6only(sock);

		debug("Local forwarding listening on %s port %s.",
		    ntop, strport);

		/* Bind the socket to the address. */
		اگر (bind(sock, ai->ai_addr, ai->ai_addrlen) == -1) {
			/*
			 * address can be in if use ipv6 address is
			 * already bound
			 */
			اگر (!ai->ai_next)
				error("bind [%s]:%s: %.100s",
				    ntop, strport, strerror(errno));
			ورنہ
				verbose("bind [%s]:%s: %.100s",
				    ntop, strport, strerror(errno));

			close(sock);
			جاری;
		}
		/* Start listening for connections on the socket. */
		اگر (listen(sock, SSH_LISTEN_BACKLOG) == -1) {
			error("listen [%s]:%s: %.100s", ntop, strport,
			    strerror(errno));
			close(sock);
			جاری;
		}

		/*
		 * fwd->listen_port == 0 requests a dynamically allocated port -
		 * record what we got.
		 */
		اگر (type == SSH_CHANNEL_RPORT_LISTENER &&
		    fwd->listen_پورٹ == 0 &&
		    allocated_listen_پورٹ != تہی &&
		    *allocated_listen_پورٹ == 0) {
			*allocated_listen_پورٹ = get_local_پورٹ(sock);
			debug("Allocated listen port %d",
			    *allocated_listen_پورٹ);
		}

		/* Allocate a channel number for the socket. */
		c = channel_new(ssh, "port-listener", type, sock, sock, -1,
		    CHAN_TCP_کھڑکی_DEFAULT, CHAN_TCP_PACKET_DEFAULT,
		    0, "port listener", 1);
		c->راستہ = xstrdup(host);
		c->host_پورٹ = fwd->connect_پورٹ;
		c->listening_addr = addr == تہی ? تہی : xstrdup(addr);
		اگر (fwd->listen_پورٹ == 0 && allocated_listen_پورٹ != تہی &&
		    !(ssh->compat & SSH_BUG_DYNAMIC_RPORT))
			c->listening_پورٹ = *allocated_listen_پورٹ;
		ورنہ
			c->listening_پورٹ = fwd->listen_پورٹ;
		success = 1;
	}
	اگر (success == 0)
		error_f("cannot listen to port: %d", fwd->listen_پورٹ);
	freeaddrinfo(aitop);
	واپس success;
}

ساکن صحیح
channel_تیاری_fwd_listener_streamlocal(ساخت ssh *ssh, صحیح type,
    ساخت Forward *fwd, ساخت ForwardOptions *fwd_opts)
{
	ساخت sockaddr_un sunaddr;
	ثابت حرف *راستہ;
	Channel *c;
	صحیح پورٹ, sock;
	منوال_t omask;

	انتخاب (type) {
	حالت SSH_CHANNEL_UNIX_LISTENER:
		اگر (fwd->connect_راستہ != تہی) {
			اگر (لڑی_لمبائی(fwd->connect_راستہ) > حجم(sunaddr.sun_راستہ)) {
				error("Local connecting path too long: %s",
				    fwd->connect_راستہ);
				واپس 0;
			}
			راستہ = fwd->connect_راستہ;
			پورٹ = پورٹ_STREAMLOCAL;
		} ورنہ {
			اگر (fwd->connect_host == تہی) {
				error("No forward host name.");
				واپس 0;
			}
			اگر (لڑی_لمبائی(fwd->connect_host) >= NI_MAXHOST) {
				error("Forward host name too long.");
				واپس 0;
			}
			راستہ = fwd->connect_host;
			پورٹ = fwd->connect_پورٹ;
		}
		توڑو;
	حالت SSH_CHANNEL_RUNIX_LISTENER:
		راستہ = fwd->listen_راستہ;
		پورٹ = پورٹ_STREAMLOCAL;
		توڑو;
	طےشدہ:
		error_f("unexpected channel type %d", type);
		واپس 0;
	}

	اگر (fwd->listen_راستہ == تہی) {
		error("No forward path name.");
		واپس 0;
	}
	اگر (لڑی_لمبائی(fwd->listen_راستہ) > حجم(sunaddr.sun_راستہ)) {
		error("Local listening path too long: %s", fwd->listen_راستہ);
		واپس 0;
	}

	debug3_f("type %d path %s", type, fwd->listen_راستہ);

	/* Start a Unix domain listener. */
	omask = umask(fwd_opts->streamlocal_bind_نقاب);
	sock = unix_listener(fwd->listen_راستہ, SSH_LISTEN_BACKLOG,
	    fwd_opts->streamlocal_bind_unlink);
	umask(omask);
	اگر (sock < 0)
		واپس 0;

	debug("Local forwarding listening on path %s.", fwd->listen_راستہ);

	/* Allocate a channel number for the socket. */
	c = channel_new(ssh, "unix-listener", type, sock, sock, -1,
	    CHAN_TCP_کھڑکی_DEFAULT, CHAN_TCP_PACKET_DEFAULT,
	    0, "unix listener", 1);
	c->راستہ = xstrdup(راستہ);
	c->host_پورٹ = پورٹ;
	c->listening_پورٹ = پورٹ_STREAMLOCAL;
	c->listening_addr = xstrdup(fwd->listen_راستہ);
	واپس 1;
}

ساکن صحیح
channel_cancel_rport_listener_tcpip(ساخت ssh *ssh,
    ثابت حرف *host, u_short پورٹ)
{
	u_int i;
	صحیح ملا = 0;

	برائے (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		Channel *c = ssh->chanctxt->channels[i];
		اگر (c == تہی || c->type != SSH_CHANNEL_RPORT_LISTENER)
			جاری;
		اگر (strcmp(c->راستہ, host) == 0 && c->listening_پورٹ == پورٹ) {
			debug2_f("close channel %d", i);
			channel_free(ssh, c);
			ملا = 1;
		}
	}

	واپس ملا;
}

ساکن صحیح
channel_cancel_rport_listener_streamlocal(ساخت ssh *ssh, ثابت حرف *راستہ)
{
	u_int i;
	صحیح ملا = 0;

	برائے (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		Channel *c = ssh->chanctxt->channels[i];
		اگر (c == تہی || c->type != SSH_CHANNEL_RUNIX_LISTENER)
			جاری;
		اگر (c->راستہ == تہی)
			جاری;
		اگر (strcmp(c->راستہ, راستہ) == 0) {
			debug2_f("close channel %d", i);
			channel_free(ssh, c);
			ملا = 1;
		}
	}

	واپس ملا;
}

صحیح
channel_cancel_rport_listener(ساخت ssh *ssh, ساخت Forward *fwd)
{
	اگر (fwd->listen_راستہ != تہی) {
		واپس channel_cancel_rport_listener_streamlocal(ssh,
		    fwd->listen_راستہ);
	} ورنہ {
		واپس channel_cancel_rport_listener_tcpip(ssh,
		    fwd->listen_host, fwd->listen_پورٹ);
	}
}

ساکن صحیح
channel_cancel_lport_listener_tcpip(ساخت ssh *ssh,
    ثابت حرف *lhost, u_short lport, صحیح cport,
    ساخت ForwardOptions *fwd_opts)
{
	u_int i;
	صحیح ملا = 0;
	ثابت حرف *addr = channel_fwd_bind_addr(ssh, lhost, تہی, 1, fwd_opts);

	برائے (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		Channel *c = ssh->chanctxt->channels[i];
		اگر (c == تہی || c->type != SSH_CHANNEL_پورٹ_LISTENER)
			جاری;
		اگر (c->listening_پورٹ != lport)
			جاری;
		اگر (cport == CHANNEL_CANCEL_پورٹ_STATIC) {
			/* skip dynamic forwardings */
			اگر (c->host_پورٹ == 0)
				جاری;
		} ورنہ {
			اگر (c->host_پورٹ != cport)
				جاری;
		}
		اگر ((c->listening_addr == تہی && addr != تہی) ||
		    (c->listening_addr != تہی && addr == تہی))
			جاری;
		اگر (addr == تہی || strcmp(c->listening_addr, addr) == 0) {
			debug2_f("close channel %d", i);
			channel_free(ssh, c);
			ملا = 1;
		}
	}

	واپس ملا;
}

ساکن صحیح
channel_cancel_lport_listener_streamlocal(ساخت ssh *ssh, ثابت حرف *راستہ)
{
	u_int i;
	صحیح ملا = 0;

	اگر (راستہ == تہی) {
		error_f("no path specified.");
		واپس 0;
	}

	برائے (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		Channel *c = ssh->chanctxt->channels[i];
		اگر (c == تہی || c->type != SSH_CHANNEL_UNIX_LISTENER)
			جاری;
		اگر (c->listening_addr == تہی)
			جاری;
		اگر (strcmp(c->listening_addr, راستہ) == 0) {
			debug2_f("close channel %d", i);
			channel_free(ssh, c);
			ملا = 1;
		}
	}

	واپس ملا;
}

صحیح
channel_cancel_lport_listener(ساخت ssh *ssh,
    ساخت Forward *fwd, صحیح cport, ساخت ForwardOptions *fwd_opts)
{
	اگر (fwd->listen_راستہ != تہی) {
		واپس channel_cancel_lport_listener_streamlocal(ssh,
		    fwd->listen_راستہ);
	} ورنہ {
		واپس channel_cancel_lport_listener_tcpip(ssh,
		    fwd->listen_host, fwd->listen_پورٹ, cport, fwd_opts);
	}
}

/* protocol local port fwd, used by ssh */
صحیح
channel_تیاری_local_fwd_listener(ساخت ssh *ssh,
    ساخت Forward *fwd, ساخت ForwardOptions *fwd_opts)
{
	اگر (fwd->listen_راستہ != تہی) {
		واپس channel_تیاری_fwd_listener_streamlocal(ssh,
		    SSH_CHANNEL_UNIX_LISTENER, fwd, fwd_opts);
	} ورنہ {
		واپس channel_تیاری_fwd_listener_tcpip(ssh,
		    SSH_CHANNEL_پورٹ_LISTENER, fwd, تہی, fwd_opts);
	}
}

/* Matches a remote forwarding permission against a requested forwarding */
ساکن صحیح
remote_open_مطابقت(ساخت permission *allowed_open, ساخت Forward *fwd)
{
	صحیح ret;
	حرف *lhost;

	/* XXX add ACLs for streamlocal */
	اگر (fwd->listen_راستہ != تہی)
		واپس 1;

	اگر (fwd->listen_host == تہی || allowed_open->listen_host == تہی)
		واپس 0;

	اگر (allowed_open->listen_پورٹ != FWD_PERMIT_ANY_پورٹ &&
	    allowed_open->listen_پورٹ != fwd->listen_پورٹ)
		واپس 0;

	/* Match hostnames case-insensitively */
	lhost = xstrdup(fwd->listen_host);
	lowercase(lhost);
	ret = مطابقت_نمونہ(lhost, allowed_open->listen_host);
	آزاد(lhost);

	واپس ret;
}

/* Checks whether a requested remote forwarding is permitted */
ساکن صحیح
check_rfwd_permission(ساخت ssh *ssh, ساخت Forward *fwd)
{
	ساخت ssh_channels *sc = ssh->chanctxt;
	ساخت permission_سیٹ *pset = &sc->remote_perms;
	u_int i, permit, permit_adm = 1;
	ساخت permission *perm;

#اگر_تعریف_شدہ SKIP_PRIVDROP
	اگر (fwd->listen_راستہ != تہی)
		واپس 0;
	اگر (fwd->listen_پورٹ != 0 && fwd->listen_پورٹ < 1024)
		واپس 0;
#اگر_ختم

	/* XXX apply GatewayPorts override before checking? */

	permit = pset->all_permitted;
	اگر (!permit) {
		برائے (i = 0; i < pset->عدد_permitted_user; i++) {
			perm = &pset->permitted_user[i];
			اگر (remote_open_مطابقت(perm, fwd)) {
				permit = 1;
				توڑو;
			}
		}
	}

	اگر (pset->عدد_permitted_admin > 0) {
		permit_adm = 0;
		برائے (i = 0; i < pset->عدد_permitted_admin; i++) {
			perm = &pset->permitted_admin[i];
			اگر (remote_open_مطابقت(perm, fwd)) {
				permit_adm = 1;
				توڑو;
			}
		}
	}

	واپس permit && permit_adm;
}

/* protocol v2 remote port fwd, used by sshd */
صحیح
channel_تیاری_remote_fwd_listener(ساخت ssh *ssh, ساخت Forward *fwd,
    صحیح *allocated_listen_پورٹ, ساخت ForwardOptions *fwd_opts)
{
	اگر (!check_rfwd_permission(ssh, fwd)) {
		ssh_packet_send_debug(ssh, "port forwarding refused");
		اگر (fwd->listen_راستہ != تہی)
			/* XXX always allowed, see remote_open_match() */
			logit("Received request from %.100s port %d to "
			    "remote forward to path \"%.100s\", "
			    "but the request was denied.",
			    ssh_remote_ipaddr(ssh), ssh_remote_پورٹ(ssh),
			    fwd->listen_راستہ);
		ورنہ اگر(fwd->listen_host != تہی)
			logit("Received request from %.100s port %d to "
			    "remote forward to host %.100s port %d, "
			    "but the request was denied.",
			    ssh_remote_ipaddr(ssh), ssh_remote_پورٹ(ssh),
			    fwd->listen_host, fwd->listen_پورٹ );
		ورنہ
			logit("Received request from %.100s port %d to remote "
			    "forward, but the request was denied.",
			    ssh_remote_ipaddr(ssh), ssh_remote_پورٹ(ssh));
		واپس 0;
	}
	اگر (fwd->listen_راستہ != تہی) {
		واپس channel_تیاری_fwd_listener_streamlocal(ssh,
		    SSH_CHANNEL_RUNIX_LISTENER, fwd, fwd_opts);
	} ورنہ {
		واپس channel_تیاری_fwd_listener_tcpip(ssh,
		    SSH_CHANNEL_RPORT_LISTENER, fwd, allocated_listen_پورٹ,
		    fwd_opts);
	}
}

/*
 * Translate the requested rfwd listen host to something usable for
 * this server.
 */
ساکن ثابت حرف *
channel_rfwd_bind_host(ثابت حرف *listen_host)
{
	اگر (listen_host == تہی) {
		واپس "localhost";
	} ورنہ اگر (*listen_host == '\0' || strcmp(listen_host, "*") == 0) {
		واپس "";
	} ورنہ
		واپس listen_host;
}

/*
 * Initiate forwarding of connections to port "port" on remote host through
 * the secure channel to host:port from local side.
 * Returns handle (index) for updating the dynamic listen port with
 * channel_update_permission().
 */
صحیح
channel_request_remote_forwarding(ساخت ssh *ssh, ساخت Forward *fwd)
{
	صحیح r, success = 0, idx = -1;
	ثابت حرف *host_مقصد_connect, *listen_host, *listen_راستہ;
	صحیح پورٹ_مقصد_connect, listen_پورٹ;

	/* Send the forward request to the remote side. */
	اگر (fwd->listen_راستہ != تہی) {
		اگر ((r = sshpkt_آغاز(ssh, SSH2_پیغام_GLOBAL_REQUEST)) != 0 ||
		    (r = sshpkt_put_cstring(ssh,
		    "streamlocal-forward@openssh.com")) != 0 ||
		    (r = sshpkt_put_u8(ssh, 1)) != 0 || /* want reply */
		    (r = sshpkt_put_cstring(ssh, fwd->listen_راستہ)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			fatal_fr(r, "request streamlocal");
	} ورنہ {
		اگر ((r = sshpkt_آغاز(ssh, SSH2_پیغام_GLOBAL_REQUEST)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "tcpip-forward")) != 0 ||
		    (r = sshpkt_put_u8(ssh, 1)) != 0 || /* want reply */
		    (r = sshpkt_put_cstring(ssh,
		    channel_rfwd_bind_host(fwd->listen_host))) != 0 ||
		    (r = sshpkt_put_u32(ssh, fwd->listen_پورٹ)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			fatal_fr(r, "request tcpip-forward");
	}
	/* Assume that server accepts the request */
	success = 1;
	اگر (success) {
		/* Record that connection to this host/port is permitted. */
		host_مقصد_connect = listen_host = listen_راستہ = تہی;
		پورٹ_مقصد_connect = listen_پورٹ = 0;
		اگر (fwd->connect_راستہ != تہی) {
			host_مقصد_connect = fwd->connect_راستہ;
			پورٹ_مقصد_connect = پورٹ_STREAMLOCAL;
		} ورنہ {
			host_مقصد_connect = fwd->connect_host;
			پورٹ_مقصد_connect = fwd->connect_پورٹ;
		}
		اگر (fwd->listen_راستہ != تہی) {
			listen_راستہ = fwd->listen_راستہ;
			listen_پورٹ = پورٹ_STREAMLOCAL;
		} ورنہ {
			listen_host = fwd->listen_host;
			listen_پورٹ = fwd->listen_پورٹ;
		}
		idx = permission_سیٹ_جوڑو(ssh, FORWARD_USER, FORWARD_LOCAL,
		    host_مقصد_connect, پورٹ_مقصد_connect,
		    listen_host, listen_راستہ, listen_پورٹ, تہی);
	}
	واپس idx;
}

ساکن صحیح
open_مطابقت(ساخت permission *allowed_open, ثابت حرف *requestedhost,
    صحیح requestedport)
{
	اگر (allowed_open->host_مقصد_connect == تہی)
		واپس 0;
	اگر (allowed_open->پورٹ_مقصد_connect != FWD_PERMIT_ANY_پورٹ &&
	    allowed_open->پورٹ_مقصد_connect != requestedport)
		واپس 0;
	اگر (strcmp(allowed_open->host_مقصد_connect, FWD_PERMIT_ANY_HOST) != 0 &&
	    strcmp(allowed_open->host_مقصد_connect, requestedhost) != 0)
		واپس 0;
	واپس 1;
}

/*
 * Note that in the listen host/port case
 * we don't support FWD_PERMIT_ANY_PORT and
 * need to translate between the configured-host (listen_host)
 * and what we've sent to the remote server (channel_rfwd_bind_host)
 */
ساکن صحیح
open_listen_مطابقت_tcpip(ساخت permission *allowed_open,
    ثابت حرف *requestedhost, u_short requestedport, صحیح translate)
{
	ثابت حرف *allowed_host;

	اگر (allowed_open->host_مقصد_connect == تہی)
		واپس 0;
	اگر (allowed_open->listen_پورٹ != requestedport)
		واپس 0;
	اگر (!translate && allowed_open->listen_host == تہی &&
	    requestedhost == تہی)
		واپس 1;
	allowed_host = translate ?
	    channel_rfwd_bind_host(allowed_open->listen_host) :
	    allowed_open->listen_host;
	اگر (allowed_host == تہی || requestedhost == تہی ||
	    strcmp(allowed_host, requestedhost) != 0)
		واپس 0;
	واپس 1;
}

ساکن صحیح
open_listen_مطابقت_streamlocal(ساخت permission *allowed_open,
    ثابت حرف *requestedpath)
{
	اگر (allowed_open->host_مقصد_connect == تہی)
		واپس 0;
	اگر (allowed_open->listen_پورٹ != پورٹ_STREAMLOCAL)
		واپس 0;
	اگر (allowed_open->listen_راستہ == تہی ||
	    strcmp(allowed_open->listen_راستہ, requestedpath) != 0)
		واپس 0;
	واپس 1;
}

/*
 * Request cancellation of remote forwarding of connection host:port from
 * local side.
 */
ساکن صحیح
channel_request_rforward_cancel_tcpip(ساخت ssh *ssh,
    ثابت حرف *host, u_short پورٹ)
{
	ساخت ssh_channels *sc = ssh->chanctxt;
	ساخت permission_سیٹ *pset = &sc->local_perms;
	صحیح r;
	u_int i;
	ساخت permission *perm = تہی;

	برائے (i = 0; i < pset->عدد_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		اگر (open_listen_مطابقت_tcpip(perm, host, پورٹ, 0))
			توڑو;
		perm = تہی;
	}
	اگر (perm == تہی) {
		debug_f("requested forward not found");
		واپس -1;
	}
	اگر ((r = sshpkt_آغاز(ssh, SSH2_پیغام_GLOBAL_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "cancel-tcpip-forward")) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 || /* want reply */
	    (r = sshpkt_put_cstring(ssh, channel_rfwd_bind_host(host))) != 0 ||
	    (r = sshpkt_put_u32(ssh, پورٹ)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send cancel");

	fwd_perm_clear(perm); /* unregister */

	واپس 0;
}

/*
 * Request cancellation of remote forwarding of Unix domain socket
 * path from local side.
 */
ساکن صحیح
channel_request_rforward_cancel_streamlocal(ساخت ssh *ssh, ثابت حرف *راستہ)
{
	ساخت ssh_channels *sc = ssh->chanctxt;
	ساخت permission_سیٹ *pset = &sc->local_perms;
	صحیح r;
	u_int i;
	ساخت permission *perm = تہی;

	برائے (i = 0; i < pset->عدد_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		اگر (open_listen_مطابقت_streamlocal(perm, راستہ))
			توڑو;
		perm = تہی;
	}
	اگر (perm == تہی) {
		debug_f("requested forward not found");
		واپس -1;
	}
	اگر ((r = sshpkt_آغاز(ssh, SSH2_پیغام_GLOBAL_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh,
	    "cancel-streamlocal-forward@openssh.com")) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 || /* want reply */
	    (r = sshpkt_put_cstring(ssh, راستہ)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send cancel");

	fwd_perm_clear(perm); /* unregister */

	واپس 0;
}

/*
 * Request cancellation of remote forwarding of a connection from local side.
 */
صحیح
channel_request_rforward_cancel(ساخت ssh *ssh, ساخت Forward *fwd)
{
	اگر (fwd->listen_راستہ != تہی) {
		واپس channel_request_rforward_cancel_streamlocal(ssh,
		    fwd->listen_راستہ);
	} ورنہ {
		واپس channel_request_rforward_cancel_tcpip(ssh,
		    fwd->listen_host,
		    fwd->listen_پورٹ ? fwd->listen_پورٹ : fwd->allocated_پورٹ);
	}
}

/*
 * Permits opening to any host/port if permitted_user[] is empty.  This is
 * usually called by the server, because the user could connect to any port
 * anyway, and the server has no way to know but to trust the client anyway.
 */
خالی
channel_permit_all(ساخت ssh *ssh, صحیح where)
{
	ساخت permission_سیٹ *pset = permission_سیٹ_get(ssh, where);

	اگر (pset->عدد_permitted_user == 0)
		pset->all_permitted = 1;
}

/*
 * Permit the specified host/port for forwarding.
 */
خالی
channel_جوڑو_permission(ساخت ssh *ssh, صحیح who, صحیح where,
    حرف *host, صحیح پورٹ)
{
	صحیح local = where == FORWARD_LOCAL;
	ساخت permission_سیٹ *pset = permission_سیٹ_get(ssh, where);

	debug("allow %s forwarding to host %s port %d",
	    fwd_ident(who, where), host, پورٹ);
	/*
	 * Remote forwards set listen_host/port, local forwards set
	 * host/port_to_connect.
	 */
	permission_سیٹ_جوڑو(ssh, who, where,
	    local ? host : تہی, local ? پورٹ : 0,
	    local ? تہی : host, تہی, local ? 0 : پورٹ, تہی);
	pset->all_permitted = 0;
}

/*
 * Administratively disable forwarding.
 */
خالی
channel_disable_admin(ساخت ssh *ssh, صحیح where)
{
	channel_clear_permission(ssh, FORWARD_ADM, where);
	permission_سیٹ_جوڑو(ssh, FORWARD_ADM, where,
	    تہی, 0, تہی, تہی, 0, تہی);
}

/*
 * Clear a list of permitted opens.
 */
خالی
channel_clear_permission(ساخت ssh *ssh, صحیح who, صحیح where)
{
	ساخت permission **permp;
	u_int i, *npermp;

	permission_سیٹ_get_array(ssh, who, where, &permp, &npermp);
	برائے (i = 0; i < *npermp; i++)
		fwd_perm_clear((*permp) + i);
	آزاد(*permp);
	*permp = تہی;
	*npermp = 0;
}

/*
 * Update the listen port for a dynamic remote forward, after
 * the actual 'newport' has been allocated. If 'newport' < 0 is
 * passed then they entry will be invalidated.
 */
خالی
channel_update_permission(ساخت ssh *ssh, صحیح idx, صحیح newport)
{
	ساخت permission_سیٹ *pset = &ssh->chanctxt->local_perms;

	اگر (idx < 0 || (u_int)idx >= pset->عدد_permitted_user) {
		debug_f("index out of range: %d num_permitted_user %d",
		    idx, pset->عدد_permitted_user);
		واپس;
	}
	debug("%s allowed port %d for forwarding to host %s port %d",
	    newport > 0 ? "Updating" : "Removing",
	    newport,
	    pset->permitted_user[idx].host_مقصد_connect,
	    pset->permitted_user[idx].پورٹ_مقصد_connect);
	اگر (newport <= 0)
		fwd_perm_clear(&pset->permitted_user[idx]);
	ورنہ {
		pset->permitted_user[idx].listen_پورٹ =
		    (ssh->compat & SSH_BUG_DYNAMIC_RPORT) ? 0 : newport;
	}
}

/* Try to start non-blocking connect to next host in cctx list */
ساکن صحیح
connect_اگلا(ساخت ssh *ssh, ساخت channel_connect *cctx)
{
	صحیح sock, sock_is_جال, saved_errno;
	ساخت sockaddr_un *sunaddr;
	حرف ntop[NI_MAXHOST];
	حرف strport[زیادہ_سے_زیادہ(NI_MAXSERV, حجم(sunaddr->sun_راستہ))];

	برائے (; cctx->ai; cctx->ai = cctx->ai->ai_next) {
		sock_is_جال = 0;
		انتخاب (cctx->ai->ai_family) {
		حالت AF_UNIX:
			/* unix:pathname instead of host:port */
			sunaddr = (ساخت sockaddr_un *)cctx->ai->ai_addr;
			strlcpy(ntop, "unix", حجم(ntop));
			strlcpy(strport, sunaddr->sun_راستہ, حجم(strport));
			توڑو;
		حالت AF_INET:
		حالت AF_INET6:
			اگر (getnameinfo(cctx->ai->ai_addr, cctx->ai->ai_addrlen,
			    ntop, حجم(ntop), strport, حجم(strport),
			    NI_NUMERICHOST|NI_NUMERICSERV) != 0) {
				error_f("getnameinfo failed");
				جاری;
			}
			sock_is_جال = 1;
			توڑو;
		طےشدہ:
			جاری;
		}
		debug_f("start for host %.100s ([%.100s]:%s)",
		    cctx->host, ntop, strport);
		اگر ((sock = socket(cctx->ai->ai_family, cctx->ai->ai_socktype,
		    cctx->ai->ai_protocol)) == -1) {
			اگر (cctx->ai->ai_next == تہی)
				error("socket: %.100s", strerror(errno));
			ورنہ
				verbose("socket: %.100s", strerror(errno));
			جاری;
		}
		اگر (سیٹ_nonblock(sock) == -1)
			fatal_f("set_nonblock(%d)", sock);
		اگر (sock_is_جال && ssh->chanctxt->want_tcp_keepalive)
			سیٹ_keepalive(sock); /* logs errors */
		اگر (connect(sock, cctx->ai->ai_addr,
		    cctx->ai->ai_addrlen) == -1 && errno != EINPROGRESS) {
			debug_f("host %.100s ([%.100s]:%s): %.100s",
			    cctx->host, ntop, strport, strerror(errno));
			saved_errno = errno;
			close(sock);
			errno = saved_errno;
			جاری;	/* fail -- try next */
		}
		اگر (cctx->ai->ai_family != AF_UNIX)
			سیٹ_nodelay(sock);
		debug_f("connect host %.100s ([%.100s]:%s) in progress, fd=%d",
		    cctx->host, ntop, strport, sock);
		cctx->ai = cctx->ai->ai_next;
		واپس sock;
	}
	واپس -1;
}

/*
 * Return connecting socket to remote host:port or local socket path,
 * passing back the failure reason if appropriate.
 */
ساکن صحیح
connect_مقصد_helper(ساخت ssh *ssh, ثابت حرف *name, صحیح پورٹ, صحیح socktype,
    حرف *ctype, حرف *rname, ساخت channel_connect *cctx,
    صحیح *reason, ثابت حرف **errmsg)
{
	ساخت addrinfo hints;
	صحیح gaierr;
	صحیح sock = -1;
	حرف strport[NI_MAXSERV];

	اگر (پورٹ == پورٹ_STREAMLOCAL) {
		ساخت sockaddr_un *sunaddr;
		ساخت addrinfo *ai;

		اگر (لڑی_لمبائی(name) > حجم(sunaddr->sun_راستہ)) {
			error("%.100s: %.100s", name, strerror(ENAMETOOLONG));
			واپس -1;
		}

		/*
		 * Fake up a struct addrinfo for AF_UNIX connections.
		 * free_connect_ctx() must check ai_family
		 * and use free() not freeaddrinfo() for AF_UNIX.
		 */
		ai = xcalloc(1, حجم(*ai) + حجم(*sunaddr));
		ai->ai_addr = (ساخت sockaddr *)(ai + 1);
		ai->ai_addrlen = حجم(*sunaddr);
		ai->ai_family = AF_UNIX;
		ai->ai_socktype = socktype;
		ai->ai_protocol = PF_UNSPEC;
		sunaddr = (ساخت sockaddr_un *)ai->ai_addr;
		sunaddr->sun_family = AF_UNIX;
		strlcpy(sunaddr->sun_راستہ, name, حجم(sunaddr->sun_راستہ));
		cctx->aitop = ai;
	} ورنہ {
		memset(&hints, 0, حجم(hints));
		hints.ai_family = ssh->chanctxt->IPv4or6;
		hints.ai_socktype = socktype;
		snprintf(strport, حجم strport, "%d", پورٹ);
		اگر ((gaierr = getaddrinfo(name, strport, &hints, &cctx->aitop))
		    != 0) {
			اگر (errmsg != تہی)
				*errmsg = ssh_gai_strerror(gaierr);
			اگر (reason != تہی)
				*reason = SSH2_OPEN_CONNECT_FAILED;
			error("connect_to %.100s: unknown host (%s)", name,
			    ssh_gai_strerror(gaierr));
			واپس -1;
		}
	}

	cctx->host = xstrdup(name);
	cctx->پورٹ = پورٹ;
	cctx->ai = cctx->aitop;

	اگر ((sock = connect_اگلا(ssh, cctx)) == -1) {
		error("connect to %.100s port %d failed: %s",
		    name, پورٹ, strerror(errno));
		واپس -1;
	}

	واپس sock;
}

/* Return CONNECTING channel to remote host:port or local socket path */
ساکن Channel *
connect_مقصد(ساخت ssh *ssh, ثابت حرف *host, صحیح پورٹ,
    حرف *ctype, حرف *rname)
{
	ساخت channel_connect cctx;
	Channel *c;
	صحیح sock;

	memset(&cctx, 0, حجم(cctx));
	sock = connect_مقصد_helper(ssh, host, پورٹ, SOCK_STREAM, ctype, rname,
	    &cctx, تہی, تہی);
	اگر (sock == -1) {
		free_connect_ctx(&cctx);
		واپس تہی;
	}
	c = channel_new(ssh, ctype, SSH_CHANNEL_CONNECTING, sock, sock, -1,
	    CHAN_TCP_کھڑکی_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, rname, 1);
	c->host_پورٹ = پورٹ;
	c->راستہ = xstrdup(host);
	c->connect_ctx = xmalloc(حجم(cctx));
	حافظہ_نقل(c->connect_ctx, &cctx, حجم(cctx));

	واپس c;
}

/*
 * returns either the newly connected channel or the downstream channel
 * that needs to deal with this connection.
 */
Channel *
channel_connect_by_listen_پتہ(ساخت ssh *ssh, ثابت حرف *listen_host,
    u_short listen_پورٹ, حرف *ctype, حرف *rname)
{
	ساخت ssh_channels *sc = ssh->chanctxt;
	ساخت permission_سیٹ *pset = &sc->local_perms;
	u_int i;
	ساخت permission *perm;

	برائے (i = 0; i < pset->عدد_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		اگر (open_listen_مطابقت_tcpip(perm,
		    listen_host, listen_پورٹ, 1)) {
			اگر (perm->downstream)
				واپس perm->downstream;
			اگر (perm->پورٹ_مقصد_connect == 0)
				واپس rdynamic_connect_prepare(ssh,
				    ctype, rname);
			واپس connect_مقصد(ssh,
			    perm->host_مقصد_connect, perm->پورٹ_مقصد_connect,
			    ctype, rname);
		}
	}
	error("WARNING: Server requests forwarding for unknown listen_port %d",
	    listen_پورٹ);
	واپس تہی;
}

Channel *
channel_connect_by_listen_راستہ(ساخت ssh *ssh, ثابت حرف *راستہ,
    حرف *ctype, حرف *rname)
{
	ساخت ssh_channels *sc = ssh->chanctxt;
	ساخت permission_سیٹ *pset = &sc->local_perms;
	u_int i;
	ساخت permission *perm;

	برائے (i = 0; i < pset->عدد_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		اگر (open_listen_مطابقت_streamlocal(perm, راستہ)) {
			واپس connect_مقصد(ssh,
			    perm->host_مقصد_connect, perm->پورٹ_مقصد_connect,
			    ctype, rname);
		}
	}
	error("WARNING: Server requests forwarding for unknown path %.100s",
	    راستہ);
	واپس تہی;
}

/* Check if connecting to that port is permitted and connect. */
Channel *
channel_connect_مقصد_پورٹ(ساخت ssh *ssh, ثابت حرف *host, u_short پورٹ,
    حرف *ctype, حرف *rname, صحیح *reason, ثابت حرف **errmsg)
{
	ساخت ssh_channels *sc = ssh->chanctxt;
	ساخت permission_سیٹ *pset = &sc->local_perms;
	ساخت channel_connect cctx;
	Channel *c;
	u_int i, permit, permit_adm = 1;
	صحیح sock;
	ساخت permission *perm;

	permit = pset->all_permitted;
	اگر (!permit) {
		برائے (i = 0; i < pset->عدد_permitted_user; i++) {
			perm = &pset->permitted_user[i];
			اگر (open_مطابقت(perm, host, پورٹ)) {
				permit = 1;
				توڑو;
			}
		}
	}

	اگر (pset->عدد_permitted_admin > 0) {
		permit_adm = 0;
		برائے (i = 0; i < pset->عدد_permitted_admin; i++) {
			perm = &pset->permitted_admin[i];
			اگر (open_مطابقت(perm, host, پورٹ)) {
				permit_adm = 1;
				توڑو;
			}
		}
	}

	اگر (!permit || !permit_adm) {
		logit("Received request from %.100s port %d to connect to "
		    "host %.100s port %d, but the request was denied.",
		    ssh_remote_ipaddr(ssh), ssh_remote_پورٹ(ssh), host, پورٹ);
		اگر (reason != تہی)
			*reason = SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED;
		واپس تہی;
	}

	memset(&cctx, 0, حجم(cctx));
	sock = connect_مقصد_helper(ssh, host, پورٹ, SOCK_STREAM, ctype, rname,
	    &cctx, reason, errmsg);
	اگر (sock == -1) {
		free_connect_ctx(&cctx);
		واپس تہی;
	}

	c = channel_new(ssh, ctype, SSH_CHANNEL_CONNECTING, sock, sock, -1,
	    CHAN_TCP_کھڑکی_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, rname, 1);
	c->host_پورٹ = پورٹ;
	c->راستہ = xstrdup(host);
	c->connect_ctx = xmalloc(حجم(cctx));
	حافظہ_نقل(c->connect_ctx, &cctx, حجم(cctx));

	واپس c;
}

/* Check if connecting to that path is permitted and connect. */
Channel *
channel_connect_مقصد_راستہ(ساخت ssh *ssh, ثابت حرف *راستہ,
    حرف *ctype, حرف *rname)
{
	ساخت ssh_channels *sc = ssh->chanctxt;
	ساخت permission_سیٹ *pset = &sc->local_perms;
	u_int i, permit, permit_adm = 1;
	ساخت permission *perm;

	permit = pset->all_permitted;
	اگر (!permit) {
		برائے (i = 0; i < pset->عدد_permitted_user; i++) {
			perm = &pset->permitted_user[i];
			اگر (open_مطابقت(perm, راستہ, پورٹ_STREAMLOCAL)) {
				permit = 1;
				توڑو;
			}
		}
	}

	اگر (pset->عدد_permitted_admin > 0) {
		permit_adm = 0;
		برائے (i = 0; i < pset->عدد_permitted_admin; i++) {
			perm = &pset->permitted_admin[i];
			اگر (open_مطابقت(perm, راستہ, پورٹ_STREAMLOCAL)) {
				permit_adm = 1;
				توڑو;
			}
		}
	}

	اگر (!permit || !permit_adm) {
		logit("Received request to connect to path %.100s, "
		    "but the request was denied.", راستہ);
		واپس تہی;
	}
	واپس connect_مقصد(ssh, راستہ, پورٹ_STREAMLOCAL, ctype, rname);
}

خالی
channel_send_کھڑکی_changes(ساخت ssh *ssh)
{
	ساخت ssh_channels *sc = ssh->chanctxt;
	ساخت winsize ws;
	صحیح r;
	u_int i;

	برائے (i = 0; i < sc->channels_alloc; i++) {
		اگر (sc->channels[i] == تہی || !sc->channels[i]->client_tty ||
		    sc->channels[i]->type != SSH_CHANNEL_OPEN)
			جاری;
		اگر (ioctl(sc->channels[i]->rfd, TIOCGWINSZ, &ws) == -1)
			جاری;
		channel_request_آغاز(ssh, i, "window-change", 0);
		اگر ((r = sshpkt_put_u32(ssh, (u_int)ws.ws_ستون)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_صف)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_xpixel)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_ypixel)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "channel %u; send window-change", i);
	}
}

/* Return RDYNAMIC_OPEN channel: channel allows SOCKS, but is not connected */
ساکن Channel *
rdynamic_connect_prepare(ساخت ssh *ssh, حرف *ctype, حرف *rname)
{
	Channel *c;
	صحیح r;

	c = channel_new(ssh, ctype, SSH_CHANNEL_RDYNAMIC_OPEN, -1, -1, -1,
	    CHAN_TCP_کھڑکی_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, rname, 1);
	c->host_پورٹ = 0;
	c->راستہ = تہی;

	/*
	 * We need to open the channel before we have a FD,
	 * so that we can get SOCKS header from peer.
	 */
	اگر ((r = sshpkt_آغاز(ssh, SSH2_پیغام_CHANNEL_OPEN_CONFIRMATION)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_کھڑکی)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0)
		fatal_fr(r, "channel %i; confirm", c->self);
	واپس c;
}

/* Return CONNECTING socket to remote host:port or local socket path */
ساکن صحیح
rdynamic_connect_اختتام(ساخت ssh *ssh, Channel *c)
{
	ساخت ssh_channels *sc = ssh->chanctxt;
	ساخت permission_سیٹ *pset = &sc->local_perms;
	ساخت permission *perm;
	ساخت channel_connect cctx;
	u_int i, permit_adm = 1;
	صحیح sock;

	اگر (pset->عدد_permitted_admin > 0) {
		permit_adm = 0;
		برائے (i = 0; i < pset->عدد_permitted_admin; i++) {
			perm = &pset->permitted_admin[i];
			اگر (open_مطابقت(perm, c->راستہ, c->host_پورٹ)) {
				permit_adm = 1;
				توڑو;
			}
		}
	}
	اگر (!permit_adm) {
		debug_f("requested forward not permitted");
		واپس -1;
	}

	memset(&cctx, 0, حجم(cctx));
	sock = connect_مقصد_helper(ssh, c->راستہ, c->host_پورٹ, SOCK_STREAM, تہی,
	    تہی, &cctx, تہی, تہی);
	اگر (sock == -1)
		free_connect_ctx(&cctx);
	ورنہ {
		/* similar to SSH_CHANNEL_CONNECTING but we've already sent the open */
		c->type = SSH_CHANNEL_RDYNAMIC_اختتام;
		c->connect_ctx = xmalloc(حجم(cctx));
		حافظہ_نقل(c->connect_ctx, &cctx, حجم(cctx));
		channel_رجسٹر_fds(ssh, c, sock, sock, -1, 0, 1, 0);
	}
	واپس sock;
}

/* -- X11 forwarding */

/*
 * Creates an internet domain socket for listening for X11 connections.
 * Returns 0 and a suitable display number for the DISPLAY variable
 * stored in display_numberp , or -1 if an error occurs.
 */
صحیح
x11_create_display_inet(ساخت ssh *ssh, صحیح x11_display_انحراف,
    صحیح x11_use_localhost, صحیح single_connection,
    u_int *display_numberp, صحیح **chanids)
{
	Channel *nc = تہی;
	صحیح display_نمبر, sock, پورٹ;
	ساخت addrinfo hints, *ai, *aitop;
	حرف strport[NI_MAXSERV];
	صحیح gaierr, n, عدد_socks = 0, socks[عدد_SOCKS];

	اگر (chanids == تہی || x11_display_انحراف < 0 ||
	    x11_display_انحراف > UINT16_MAX - X11_بنیاد_پورٹ - MAX_DISPLAYS)
		واپس -1;

	برائے (display_نمبر = x11_display_انحراف;
	    display_نمبر < x11_display_انحراف + MAX_DISPLAYS;
	    display_نمبر++) {
		پورٹ = X11_بنیاد_پورٹ + display_نمبر;
		memset(&hints, 0, حجم(hints));
		hints.ai_family = ssh->chanctxt->IPv4or6;
		hints.ai_flags = x11_use_localhost ? 0: AI_PASSIVE;
		hints.ai_socktype = SOCK_STREAM;
		snprintf(strport, حجم strport, "%d", پورٹ);
		اگر ((gaierr = getaddrinfo(تہی, strport,
		    &hints, &aitop)) != 0) {
			error("getaddrinfo: %.100s", ssh_gai_strerror(gaierr));
			واپس -1;
		}
		برائے (ai = aitop; ai; ai = ai->ai_next) {
			اگر (ai->ai_family != AF_INET &&
			    ai->ai_family != AF_INET6)
				جاری;
			sock = socket(ai->ai_family, ai->ai_socktype,
			    ai->ai_protocol);
			اگر (sock == -1) {
				اگر ((errno != EINVAL) && (errno != EAFNOSUPPORT)
#اگر_تعریف_شدہ EPFNOSUPPORT
				    && (errno != EPFNOSUPPORT)
#اگر_ختم 
				    ) {
					error("socket: %.100s", strerror(errno));
					freeaddrinfo(aitop);
					واپس -1;
				} ورنہ {
					debug("x11_create_display_inet: Socket family %d not supported",
						 ai->ai_family);
					جاری;
				}
			}
			اگر (ai->ai_family == AF_INET6)
				sock_سیٹ_v6only(sock);
			اگر (x11_use_localhost)
				سیٹ_reuseaddr(sock);
			اگر (bind(sock, ai->ai_addr, ai->ai_addrlen) == -1) {
				debug2_f("bind port %d: %.100s", پورٹ,
				    strerror(errno));
				close(sock);
				برائے (n = 0; n < عدد_socks; n++)
					close(socks[n]);
				عدد_socks = 0;
				توڑو;
			}
			socks[عدد_socks++] = sock;
			اگر (عدد_socks == عدد_SOCKS)
				توڑو;
		}
		freeaddrinfo(aitop);
		اگر (عدد_socks > 0)
			توڑو;
	}
	اگر (display_نمبر >= x11_display_انحراف + MAX_DISPLAYS) {
		error("Failed to allocate internet-domain X11 display socket.");
		واپس -1;
	}
	/* Start listening for connections on the socket. */
	برائے (n = 0; n < عدد_socks; n++) {
		sock = socks[n];
		اگر (listen(sock, SSH_LISTEN_BACKLOG) == -1) {
			error("listen: %.100s", strerror(errno));
			close(sock);
			واپس -1;
		}
	}

	/* Allocate a channel for each socket. */
	*chanids = xcalloc(عدد_socks + 1, حجم(**chanids));
	برائے (n = 0; n < عدد_socks; n++) {
		sock = socks[n];
		nc = channel_new(ssh, "x11-listener",
		    SSH_CHANNEL_X11_LISTENER, sock, sock, -1,
		    CHAN_X11_کھڑکی_DEFAULT, CHAN_X11_PACKET_DEFAULT,
		    0, "X11 inet listener", 1);
		nc->single_connection = single_connection;
		(*chanids)[n] = nc->self;
	}
	(*chanids)[n] = -1;

	/* Return the display number for the DISPLAY environment variable. */
	*display_numberp = display_نمبر;
	واپس 0;
}

ساکن صحیح
connect_local_xsocket_راستہ(ثابت حرف *pathname)
{
	صحیح sock;
	ساخت sockaddr_un addr;

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	اگر (sock == -1) {
		error("socket: %.100s", strerror(errno));
		واپس -1;
	}
	memset(&addr, 0, حجم(addr));
	addr.sun_family = AF_UNIX;
	strlcpy(addr.sun_راستہ, pathname, حجم addr.sun_راستہ);
	اگر (connect(sock, (ساخت sockaddr *)&addr, حجم(addr)) == 0)
		واپس sock;
	close(sock);
	error("connect %.100s: %.100s", addr.sun_راستہ, strerror(errno));
	واپس -1;
}

ساکن صحیح
connect_local_xsocket(u_int dnr)
{
	حرف buf[1024];
	snprintf(buf, حجم buf, راستہ_UNIX_X, dnr);
	واپس connect_local_xsocket_راستہ(buf);
}

#اگر_تعریف_شدہ __APPLE__
ساکن صحیح
is_راستہ_مقصد_xsocket(ثابت حرف *display, حرف *راستہ, سائز_t pathlen)
{
	ساخت stat sbuf;

	اگر (strlcpy(راستہ, display, pathlen) >= pathlen) {
		error_f("display path too long");
		واپس 0;
	}
	اگر (display[0] != '/')
		واپس 0;
	اگر (stat(راستہ, &sbuf) == 0) {
		واپس 1;
	} ورنہ {
		حرف *dot = strrchr(راستہ, '.');
		اگر (dot != تہی) {
			*dot = '\0';
			اگر (stat(راستہ, &sbuf) == 0) {
				واپس 1;
			}
		}
	}
	واپس 0;
}
#اگر_ختم

صحیح
x11_connect_display(ساخت ssh *ssh)
{
	u_int display_نمبر;
	ثابت حرف *display;
	حرف buf[1024], *cp;
	ساخت addrinfo hints, *ai, *aitop;
	حرف strport[NI_MAXSERV];
	صحیح gaierr, sock = 0;

	/* Try to open a socket for the local X server. */
	display = getenv("DISPLAY");
	اگر (!display) {
		error("DISPLAY not set.");
		واپس -1;
	}
	/*
	 * Now we decode the value of the DISPLAY variable and make a
	 * connection to the real X server.
	 */

#اگر_تعریف_شدہ __APPLE__
	/* Check if display is a path to a socket (as set by launchd). */
	{
		حرف راستہ[PATH_MAX];

		اگر (is_راستہ_مقصد_xsocket(display, راستہ, حجم(راستہ))) {
			debug("x11_connect_display: $DISPLAY is launchd");

			/* Create a socket. */
			sock = connect_local_xsocket_راستہ(راستہ);
			اگر (sock < 0)
				واپس -1;

			/* OK, we now have a connection to the display. */
			واپس sock;
		}
	}
#اگر_ختم
	/*
	 * Check if it is a unix domain socket.  Unix domain displays are in
	 * one of the following formats: unix:d[.s], :d[.s], ::d[.s]
	 */
	اگر (لڑی_موازنہ(display, "unix:", 5) == 0 ||
	    display[0] == ':') {
		/* Connect to the unix domain socket. */
		اگر (لڑی_سے_پڑھو(strrchr(display, ':') + 1, "%u",
		    &display_نمبر) != 1) {
			error("Could not parse display number from DISPLAY: "
			    "%.100s", display);
			واپس -1;
		}
		/* Create a socket. */
		sock = connect_local_xsocket(display_نمبر);
		اگر (sock < 0)
			واپس -1;

		/* OK, we now have a connection to the display. */
		واپس sock;
	}
	/*
	 * Connect to an inet socket.  The DISPLAY value is supposedly
	 * hostname:d[.s], where hostname may also be numeric IP address.
	 */
	strlcpy(buf, display, حجم(buf));
	cp = strchr(buf, ':');
	اگر (!cp) {
		error("Could not find ':' in DISPLAY: %.100s", display);
		واپس -1;
	}
	*cp = 0;
	/*
	 * buf now contains the host name.  But first we parse the
	 * display number.
	 */
	اگر (لڑی_سے_پڑھو(cp + 1, "%u", &display_نمبر) != 1 ||
	    display_نمبر > UINT16_MAX - X11_بنیاد_پورٹ) {
		error("Could not parse display number from DISPLAY: %.100s",
		    display);
		واپس -1;
	}

	/* Look up the host address */
	memset(&hints, 0, حجم(hints));
	hints.ai_family = ssh->chanctxt->IPv4or6;
	hints.ai_socktype = SOCK_STREAM;
	snprintf(strport, حجم strport, "%u", X11_بنیاد_پورٹ + display_نمبر);
	اگر ((gaierr = getaddrinfo(buf, strport, &hints, &aitop)) != 0) {
		error("%.100s: unknown host. (%s)", buf,
		ssh_gai_strerror(gaierr));
		واپس -1;
	}
	برائے (ai = aitop; ai; ai = ai->ai_next) {
		/* Create a socket. */
		sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		اگر (sock == -1) {
			debug2("socket: %.100s", strerror(errno));
			جاری;
		}
		/* Connect it to the display. */
		اگر (connect(sock, ai->ai_addr, ai->ai_addrlen) == -1) {
			debug2("connect %.100s port %u: %.100s", buf,
			    X11_بنیاد_پورٹ + display_نمبر, strerror(errno));
			close(sock);
			جاری;
		}
		/* Success */
		توڑو;
	}
	freeaddrinfo(aitop);
	اگر (!ai) {
		error("connect %.100s port %u: %.100s", buf,
		    X11_بنیاد_پورٹ + display_نمبر, strerror(errno));
		واپس -1;
	}
	سیٹ_nodelay(sock);
	واپس sock;
}

/*
 * Requests forwarding of X11 connections, generates fake authentication
 * data, and enables authentication spoofing.
 * This should be called in the client only.
 */
خالی
x11_request_forwarding_with_spoofing(ساخت ssh *ssh, صحیح client_session_id,
    ثابت حرف *disp, ثابت حرف *proto, ثابت حرف *ڈیٹا, صحیح want_جواب)
{
	ساخت ssh_channels *sc = ssh->chanctxt;
	u_int ڈیٹا_len = (u_int) لڑی_لمبائی(ڈیٹا) / 2;
	u_int i, قدر;
	ثابت حرف *cp;
	حرف *new_ڈیٹا;
	صحیح r, screen_نمبر;

	اگر (sc->x11_saved_display == تہی)
		sc->x11_saved_display = xstrdup(disp);
	ورنہ اگر (strcmp(disp, sc->x11_saved_display) != 0) {
		error("x11_request_forwarding_with_spoofing: different "
		    "$DISPLAY already forwarded");
		واپس;
	}

	cp = strchr(disp, ':');
	اگر (cp)
		cp = strchr(cp, '.');
	اگر (cp)
		screen_نمبر = (u_int)strtonum(cp + 1, 0, 400, تہی);
	ورنہ
		screen_نمبر = 0;

	اگر (sc->x11_saved_proto == تہی) {
		/* Save protocol name. */
		sc->x11_saved_proto = xstrdup(proto);

		/* Extract real authentication data. */
		sc->x11_saved_ڈیٹا = xmalloc(ڈیٹا_len);
		برائے (i = 0; i < ڈیٹا_len; i++) {
			اگر (لڑی_سے_پڑھو(ڈیٹا + 2 * i, "%2x", &قدر) != 1) {
				fatal("x11_request_forwarding: bad "
				    "authentication data: %.100s", ڈیٹا);
			}
			sc->x11_saved_ڈیٹا[i] = قدر;
		}
		sc->x11_saved_ڈیٹا_len = ڈیٹا_len;

		/* Generate fake data of the same length. */
		sc->x11_fake_ڈیٹا = xmalloc(ڈیٹا_len);
		arc4random_buf(sc->x11_fake_ڈیٹا, ڈیٹا_len);
		sc->x11_fake_ڈیٹا_len = ڈیٹا_len;
	}

	/* Convert the fake data into hex. */
	new_ڈیٹا = tohex(sc->x11_fake_ڈیٹا, ڈیٹا_len);

	/* Send the request packet. */
	channel_request_آغاز(ssh, client_session_id, "x11-req", want_جواب);
	اگر ((r = sshpkt_put_u8(ssh, 0)) != 0 || /* bool: single connection */
	    (r = sshpkt_put_cstring(ssh, proto)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, new_ڈیٹا)) != 0 ||
	    (r = sshpkt_put_u32(ssh, screen_نمبر)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send x11-req");
	آزاد(new_ڈیٹا);
}

/*
 * Returns whether an x11 channel was used recently (less than a second ago)
 */
صحیح
x11_channel_مستعمل_recently(ساخت ssh *ssh) {
	u_int i;
	Channel *c;
	دوہرا lastused = 0;

	برائے (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		اگر (c == تہی || c->ctype == تہی || c->lastused == 0.0 ||
		    strcmp(c->ctype, "x11-connection") != 0)
			جاری;
		اگر (c->lastused > lastused)
			lastused = c->lastused;
	}
	واپس lastused != 0.0 && monotime_double() <= lastused + 1.0;
}
