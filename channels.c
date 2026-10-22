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

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <sys/stat.h>
#ضمن <sys/ioctl.h>
#ضمن <sys/un.h>
#ضمن <sys/socket.h>
#ضمن <sys/queue.h>

#ضمن <netinet/in.h>
#ضمن <arpa/inet.h>

#ضمن <errno.h>
#ضمن <fcntl.h>
#ضمن <limits.h>
#ضمن <netdb.h>
#ضمن <poll.h>
#ضمن <stdarg.h>
#ضمن <stdint.h>
#ضمن <stdio.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <termios.h>
#ضمن <unistd.h>

#ضمن "xmalloc.h"
#ضمن "ssh.h"
#ضمن "ssh2.h"
#ضمن "ssherr.h"
#ضمن "sshbuf.h"
#ضمن "packet.h"
#ضمن "log.h"
#ضمن "misc.h"
#ضمن "channels.h"
#ضمن "compat.h"
#ضمن "canohost.h"
#ضمن "pathnames.h"
#ضمن "match.h"

/* XXX remove once we're satisfied there's no lurking bugs */
/* #define DEBUG_CHANNEL_POLL 1 */

/* -- agent forwarding */
#تعریف_کن	رقم_SOCKS	10

/* -- X11 forwarding */
/* X11 port for display :0 */
#تعریف_کن X11_پایه_پورت	6000
/* Maximum number of fake X11 displays to try. */
#تعریف_کن MAX_DISPLAYS  1000

/* Per-channel callback for pre/post IO actions */
تعريفنوع فراغ chan_fn(بنية ssh *, Channel *c);

/*
 * Data structure for storing which hosts are permitted for forward requests.
 * The local sides of any remote forwards are stored in this array to prevent
 * a corrupt remote server from accessing arbitrary TCP/IP ports on our local
 * network (which might be behind a firewall).
 */
/* XXX: streamlocal wants a path instead of host:port */
/*      Overload host_to_connect; we could just make this match Forward */
/*	XXX - can we use listen_host instead of listen_path? */
بنية permission {
	حرف *host_مقصد_connect;		/* Connect to 'host'. */
	صحيح پورت_مقصد_connect;		/* Connect to 'port'. */
	حرف *listen_host;		/* Remote side should listen address. */
	حرف *listen_مسیر;		/* Remote side should listen path. */
	صحيح listen_پورت;		/* Remote side should listen port. */
	Channel *downstream;		/* Downstream mux*/
};

/* Context for non-blocking connects */
بنية channel_connect {
	حرف *host;
	صحيح پورت;
	بنية addrinfo *ai, *aitop;
};

/*
 * Stores the forwarding permission state for a single direction (local or
 * remote).
 */
بنية permission_مجموعه {
	/*
	 * List of all local permitted host/port pairs to allow for the
	 * user.
	 */
	u_int رقم_permitted_user;
	بنية permission *permitted_user;

	/*
	 * List of all permitted host/port pairs to allow for the admin.
	 */
	u_int رقم_permitted_admin;
	بنية permission *permitted_admin;

	/*
	 * If this is true, all opens/listens are permitted.  This is the
	 * case on the server on which we have to trust the client anyway,
	 * and the user could do anything after logging in.
	 */
	صحيح all_permitted;
};

/* Used to record timeouts per channel type */
بنية ssh_channel_timeout {
	حرف *type_الگو;
	مزدوج timeout_secs;
};

/* Master structure for channels state */
بنية ssh_channels {
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
	بنية permission_مجموعه local_perms;
	بنية permission_مجموعه remote_perms;

	/* -- X11 forwarding */

	/* Saved X11 local (client) display. */
	حرف *x11_saved_display;

	/* Saved X11 authentication protocol name. */
	حرف *x11_saved_proto;

	/* Saved X11 authentication data.  This is the real data. */
	حرف *x11_saved_داده;
	u_int x11_saved_داده_len;

	/* Deadline after which all X11 connections are refused */
	مزدوج x11_refuse_زمان;

	/*
	 * Fake X11 authentication data.  This is what the server will be
	 * sending us; we should replace any occurrences of this by the
	 * real data.
	 */
	u_char *x11_fake_داده;
	u_int x11_fake_داده_len;

	/* AF_UNSPEC or AF_INET or AF_INET6 */
	صحيح IPv4or6;

	/* Set SO_KEEPALIVE on TCP connections */
	صحيح want_tcp_keepalive;

	/* Channel timeouts by type */
	بنية ssh_channel_timeout *timeouts;
	اندازه_t ntimeouts;
	/* Global timeout for all OPEN channels */
	مزدوج global_deadline;
	مزدوج lastused;
	/* pattern-lists used to classify channels as bulk */
	حرف *bulk_classifier_tty, *bulk_classifier_notty;
	/* Number of active bulk channels (set by channel_handler) */
	u_int nbulk;
};

/* helper */
ساكن فراغ پورت_open_helper(بنية ssh *ssh, Channel *c, حرف *rtype);
ساكن ثابت حرف *channel_rfwd_bind_host(ثابت حرف *listen_host);

/* non-blocking connect helpers */
ساكن صحيح connect_بعدی(بنية ssh *, بنية channel_connect *);
ساكن Channel *rdynamic_connect_prepare(بنية ssh *, حرف *, حرف *);
ساكن صحيح rdynamic_connect_پایان(بنية ssh *, Channel *);

/* Setup helper */
ساكن فراغ channel_handler_init(بنية ssh_channels *sc);

/* -- channel core */

فراغ
channel_init_channels(بنية ssh *ssh)
{
	بنية ssh_channels *sc;

	إذا ((sc = حافظه_صفر_بده(1, حجم(*sc))) == عدم)
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
channel_by_id(بنية ssh *ssh, صحيح id)
{
	Channel *c;

	إذا (id < 0 || (u_int)id >= ssh->chanctxt->channels_alloc) {
		logit_f("%d: bad id", id);
		أرجع عدم;
	}
	c = ssh->chanctxt->channels[id];
	إذا (c == عدم) {
		logit_f("%d: bad id: channel free", id);
		أرجع عدم;
	}
	أرجع c;
}

Channel *
channel_by_remote_id(بنية ssh *ssh, u_int remote_id)
{
	Channel *c;
	u_int i;

	لكل (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		إذا (c != عدم && c->have_remote_id && c->remote_id == remote_id)
			أرجع c;
	}
	أرجع عدم;
}

/*
 * Returns the channel if it is allowed to receive protocol messages.
 * Private channels, like listening sockets, may not receive messages.
 */
Channel *
channel_lookup(بنية ssh *ssh, صحيح id)
{
	Channel *c;

	إذا ((c = channel_by_id(ssh, id)) == عدم)
		أرجع عدم;

	بدل (c->type) {
	حالة SSH_CHANNEL_X11_OPEN:
	حالة SSH_CHANNEL_LARVAL:
	حالة SSH_CHANNEL_CONNECTING:
	حالة SSH_CHANNEL_DYNAMIC:
	حالة SSH_CHANNEL_RDYNAMIC_OPEN:
	حالة SSH_CHANNEL_RDYNAMIC_پایان:
	حالة SSH_CHANNEL_OPENING:
	حالة SSH_CHANNEL_OPEN:
	حالة SSH_CHANNEL_ABANDONED:
	حالة SSH_CHANNEL_MUX_PROXY:
		أرجع c;
	}
	logit("Non-public channel %d, type %d.", id, c->type);
	أرجع عدم;
}

ساكن فراغ
free_connect_ctx(بنية channel_connect *cctx)
{
	حرر(cctx->host);
	إذا (cctx->aitop) {
		إذا (cctx->aitop->ai_family == AF_UNIX)
			حرر(cctx->aitop);
		وإلا
			freeaddrinfo(cctx->aitop);
	}
	memset(cctx, 0, حجم(*cctx));
}

ساكن فراغ
channel_free_connect_ctx(Channel *c)
{
	إذا (c == عدم || c->connect_ctx == عدم)
		أرجع;
	free_connect_ctx(c->connect_ctx);
	حرر(c->connect_ctx);
	c->connect_ctx = عدم;
}

/* Enable/disable TCP keepalives for X11 and port-forwarding sockets */
فراغ
channel_مجموعه_tcp_keepalives(بنية ssh *ssh, صحيح on)
{
	ssh->chanctxt->want_tcp_keepalive = on;
}

/*
 * Add a timeout for open channels whose c->ctype (or c->xctype if it is set)
 * match type_pattern.
 */
فراغ
channel_جمع_کن_timeout(بنية ssh *ssh, ثابت حرف *type_الگو,
    مزدوج timeout_secs)
{
	بنية ssh_channels *sc = ssh->chanctxt;

	إذا (strcmp(type_الگو, "global") == 0) {
		debug2_f("global channel timeout %f seconds", timeout_secs);
		sc->global_deadline = timeout_secs;
		أرجع;
	}
	debug2_f("channel type \"%s\" timeout %f seconds",
	    type_الگو, timeout_secs);
	sc->timeouts = xrecallocarray(sc->timeouts, sc->ntimeouts,
	    sc->ntimeouts + 1, حجم(*sc->timeouts));
	sc->timeouts[sc->ntimeouts].type_الگو = xstrdup(type_الگو);
	sc->timeouts[sc->ntimeouts].timeout_secs = timeout_secs;
	sc->ntimeouts++;
}

/* Clears all previously-added channel timeouts */
فراغ
channel_clear_timeouts(بنية ssh *ssh)
{
	بنية ssh_channels *sc = ssh->chanctxt;
	اندازه_t i;

	debug3_f("clearing");
	لكل (i = 0; i < sc->ntimeouts; i++)
		حرر(sc->timeouts[i].type_الگو);
	حرر(sc->timeouts);
	sc->timeouts = عدم;
	sc->ntimeouts = 0;
}

ساكن مزدوج
lookup_timeout(بنية ssh *ssh, ثابت حرف *type)
{
	بنية ssh_channels *sc = ssh->chanctxt;
	اندازه_t i;

	لكل (i = 0; i < sc->ntimeouts; i++) {
		إذا (تطابق_الگو(type, sc->timeouts[i].type_الگو))
			أرجع sc->timeouts[i].timeout_secs;
	}

	أرجع 0;
}

ساكن فراغ
channel_classify(بنية ssh *ssh, Channel *c)
{
	بنية ssh_channels *sc = ssh->chanctxt;
	ثابت حرف *type = c->xctype == عدم ? c->ctype : c->xctype;
	ثابت صحيح has_tty = c->isatty || c->remote_has_tty;
	ثابت حرف *classifier = has_tty ?
	    sc->bulk_classifier_tty : sc->bulk_classifier_notty;

	c->bulk = type != عدم && تطابق_الگو_list(type, classifier, 0) == 1;
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
فراغ
channel_مجموعه_xtype(بنية ssh *ssh, صحيح id, ثابت حرف *xctype)
{
	بنية ssh_channels *sc = ssh->chanctxt;
	Channel *c;

	إذا ((c = channel_by_id(ssh, id)) == عدم)
		fatal_f("missing channel %d", id);
	إذا (c->xctype != عدم)
		حرر(c->xctype);
	c->xctype = xstrdup(xctype);
	/* Only override deadline if xctype has a more specific match. */
	مزدوج xtype_deadline = lookup_timeout(ssh, c->xctype);
	إذا (xtype_deadline != 0)
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
ساكن فراغ
channel_مجموعه_استفاده_شده_زمان(بنية ssh *ssh, Channel *c)
{
	ssh->chanctxt->lastused = monotime_double();
	إذا (c != عدم)
		c->lastused = ssh->chanctxt->lastused;
}

/*
 * Get the time at which a channel is due to time out for inactivity.
 * Returns 0 if the channel is not due to time out ever.
 */
ساكن مزدوج
channel_get_expiry(بنية ssh *ssh, Channel *c)
{
	بنية ssh_channels *sc = ssh->chanctxt;
	مزدوج expiry = 0, channel_expiry;

	إذا (sc->lastused != 0 && sc->global_deadline != 0)
		expiry = sc->lastused + sc->global_deadline;
	إذا (c->lastused != 0 && c->inactive_deadline != 0) {
		channel_expiry = c->lastused + c->inactive_deadline;
		إذا (expiry == 0 || channel_expiry < expiry)
			expiry = channel_expiry;
	}
	أرجع expiry;
}

/* Returns non-zero if there is an open, non-interactive channel */
صحيح
channel_has_bulk(بنية ssh *ssh)
{
	أرجع ssh->chanctxt != عدم && ssh->chanctxt->nbulk != 0;
}

/*
 * Register filedescriptors for a channel, used when allocating a channel or
 * when the channel consumer/producer is ready, e.g. shell exec'd
 */
ساكن فراغ
channel_ثبات_fds(بنية ssh *ssh, Channel *c, صحيح rfd, صحيح wfd, صحيح efd,
    صحيح extusage, صحيح nonblock, صحيح is_tty)
{
	صحيح val;

	إذا (rfd != -1)
		(فراغ)fcntl(rfd, F_SETFD, FD_CLOEXEC);
	إذا (wfd != -1 && wfd != rfd)
		(فراغ)fcntl(wfd, F_SETFD, FD_CLOEXEC);
	إذا (efd != -1 && efd != rfd && efd != wfd)
		(فراغ)fcntl(efd, F_SETFD, FD_CLOEXEC);

	c->rfd = rfd;
	c->wfd = wfd;
	c->sock = (rfd == wfd) ? rfd : -1;
	c->efd = efd;
	c->extended_usage = extusage;

	إذا ((c->isatty = is_tty) != 0)
		debug2("channel %d: rfd %d isatty", c->self, c->rfd);
#اگر_تعریف_شده _AIX
	/* XXX: Later AIX versions can't push as much data to tty */
	c->wfd_isatty = is_tty || isatty(c->wfd);
#پایان_اگر

	/* enable nonblocking mode */
	c->restore_بلوک = 0;
	إذا (nonblock == CHANNEL_NONBLOCK_STDIO) {
		/*
		 * Special handling for stdio file descriptors: do not set
		 * non-blocking mode if they are TTYs. Otherwise prepare to
		 * restore their blocking state on exit to avoid interfering
		 * with other programs that follow.
		 */
		إذا (rfd != -1 && !isatty(rfd) &&
		    (val = fcntl(rfd, F_GETFL)) != -1 && !(val & O_NONBLOCK)) {
			c->restore_flags[0] = val;
			c->restore_بلوک |= CHANNEL_RESTORE_RFD;
			مجموعه_nonblock(rfd);
		}
		إذا (wfd != -1 && !isatty(wfd) &&
		    (val = fcntl(wfd, F_GETFL)) != -1 && !(val & O_NONBLOCK)) {
			c->restore_flags[1] = val;
			c->restore_بلوک |= CHANNEL_RESTORE_WFD;
			مجموعه_nonblock(wfd);
		}
		إذا (efd != -1 && !isatty(efd) &&
		    (val = fcntl(efd, F_GETFL)) != -1 && !(val & O_NONBLOCK)) {
			c->restore_flags[2] = val;
			c->restore_بلوک |= CHANNEL_RESTORE_EFD;
			مجموعه_nonblock(efd);
		}
	} وإلا إذا (nonblock) {
		إذا (rfd != -1)
			مجموعه_nonblock(rfd);
		إذا (wfd != -1)
			مجموعه_nonblock(wfd);
		إذا (efd != -1)
			مجموعه_nonblock(efd);
	}
	/* channel might be entering a larval state, so reset global timeout */
	channel_مجموعه_استفاده_شده_زمان(ssh, عدم);
	channel_classify(ssh, c);
}

/*
 * Allocate a new channel object and set its type and socket.
 */
Channel *
channel_new(بنية ssh *ssh, حرف *ctype, صحيح type, صحيح rfd, صحيح wfd, صحيح efd,
    u_int پنجره, u_int maxpack, صحيح extusage, ثابت حرف *remote_name,
    صحيح nonblock)
{
	بنية ssh_channels *sc = ssh->chanctxt;
	u_int i, یافت = 0;
	Channel *c;
	صحيح r;

	/* Try to find a free slot where to put the new channel. */
	لكل (i = 0; i < sc->channels_alloc; i++) {
		إذا (sc->channels[i] == عدم) {
			/* Found a free slot. */
			یافت = i;
			اكسر;
		}
	}
	إذا (i >= sc->channels_alloc) {
		/*
		 * There are no free slots. Take last+1 slot and expand
		 * the array.
		 */
		یافت = sc->channels_alloc;
		إذا (sc->channels_alloc > CHANNELS_MAX_CHANNELS)
			fatal_f("internal error: channels_alloc %d too big",
			    sc->channels_alloc);
		sc->channels = xrecallocarray(sc->channels, sc->channels_alloc,
		    sc->channels_alloc + 10, حجم(*sc->channels));
		sc->channels_alloc += 10;
		debug2("channel: expanding %d", sc->channels_alloc);
	}
	/* Initialize and return new channel. */
	c = sc->channels[یافت] = xcalloc(1, حجم(Channel));
	إذا ((c->درون_داد = sshbuf_new()) == عدم ||
	    (c->output = sshbuf_new()) == عدم ||
	    (c->extended = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	إذا ((r = sshbuf_مجموعه_max_اندازه(c->درون_داد, CHAN_درون_داد_MAX)) != 0)
		fatal_fr(r, "sshbuf_set_max_size");
	c->ostate = CHAN_OUTPUT_OPEN;
	c->istate = CHAN_درون_داد_OPEN;
	channel_ثبات_fds(ssh, c, rfd, wfd, efd, extusage, nonblock, 0);
	c->self = یافت;
	c->type = type;
	c->ctype = ctype;
	c->local_پنجره = پنجره;
	c->local_پنجره_max = پنجره;
	c->local_maxpacket = maxpack;
	c->remote_name = xstrdup(remote_name);
	c->ctl_chan = -1;
	c->delayed = 1;		/* prevent call to channel_post handler */
	c->inactive_deadline = lookup_timeout(ssh, c->ctype);
	TAILQ_INIT(&c->وضعیت_confirms);
	channel_classify(ssh, c);
	debug("channel %d: new %s [%s] (inactive timeout: %f)",
	    یافت, c->ctype, remote_name, c->inactive_deadline != 0.0 ?
	    c->inactive_deadline : sc->global_deadline);
	أرجع c;
}

فراغ
channel_مجموعه_tty(بنية ssh *ssh, Channel *c)
{
	c->remote_has_tty = 1;
	channel_classify(ssh, c);
}

صحيح
channel_close_fd(بنية ssh *ssh, Channel *c, صحيح *fdp)
{
	صحيح ret, fd = *fdp;

	إذا (fd == -1)
		أرجع 0;

	/* restore blocking */
	إذا (*fdp == c->rfd &&
	    (c->restore_بلوک & CHANNEL_RESTORE_RFD) != 0)
		(فراغ)fcntl(*fdp, F_SETFL, c->restore_flags[0]);
	وإلا إذا (*fdp == c->wfd &&
	    (c->restore_بلوک & CHANNEL_RESTORE_WFD) != 0)
		(فراغ)fcntl(*fdp, F_SETFL, c->restore_flags[1]);
	وإلا إذا (*fdp == c->efd &&
	    (c->restore_بلوک & CHANNEL_RESTORE_EFD) != 0)
		(فراغ)fcntl(*fdp, F_SETFL, c->restore_flags[2]);

	إذا (*fdp == c->rfd) {
		c->io_want &= ~SSH_CHAN_IO_RFD;
		c->io_ready &= ~SSH_CHAN_IO_RFD;
		c->rfd = -1;
		c->pfds[0] = -1;
	}
	إذا (*fdp == c->wfd) {
		c->io_want &= ~SSH_CHAN_IO_WFD;
		c->io_ready &= ~SSH_CHAN_IO_WFD;
		c->wfd = -1;
		c->pfds[1] = -1;
	}
	إذا (*fdp == c->efd) {
		c->io_want &= ~SSH_CHAN_IO_EFD;
		c->io_ready &= ~SSH_CHAN_IO_EFD;
		c->efd = -1;
		c->pfds[2] = -1;
	}
	إذا (*fdp == c->sock) {
		c->io_want &= ~SSH_CHAN_IO_SOCK;
		c->io_ready &= ~SSH_CHAN_IO_SOCK;
		c->sock = -1;
		c->pfds[3] = -1;
	}

	ret = close(fd);
	*fdp = -1; /* probably redundant */
	أرجع ret;
}

/* Close all channel fd/socket. */
ساكن فراغ
channel_close_fds(بنية ssh *ssh, Channel *c)
{
	صحيح sock = c->sock, rfd = c->rfd, wfd = c->wfd, efd = c->efd;

	channel_close_fd(ssh, c, &c->sock);
	إذا (rfd != sock)
		channel_close_fd(ssh, c, &c->rfd);
	إذا (wfd != sock && wfd != rfd)
		channel_close_fd(ssh, c, &c->wfd);
	إذا (efd != sock && efd != rfd && efd != wfd)
		channel_close_fd(ssh, c, &c->efd);
}

ساكن فراغ
fwd_perm_clear(بنية permission *perm)
{
	حرر(perm->host_مقصد_connect);
	حرر(perm->listen_host);
	حرر(perm->listen_مسیر);
	memset(perm, 0, حجم(*perm));
}

/* Returns an printable name for the specified forwarding permission list */
ساكن ثابت حرف *
fwd_ident(صحيح who, صحيح where)
{
	إذا (who == FORWARD_ADM) {
		إذا (where == FORWARD_LOCAL)
			أرجع "admin local";
		وإلا إذا (where == FORWARD_REMOTE)
			أرجع "admin remote";
	} وإلا إذا (who == FORWARD_USER) {
		إذا (where == FORWARD_LOCAL)
			أرجع "user local";
		وإلا إذا (where == FORWARD_REMOTE)
			أرجع "user remote";
	}
	fatal("Unknown forward permission list %d/%d", who, where);
}

/* Returns the forwarding permission list for the specified direction */
ساكن بنية permission_مجموعه *
permission_مجموعه_get(بنية ssh *ssh, صحيح where)
{
	بنية ssh_channels *sc = ssh->chanctxt;

	بدل (where) {
	حالة FORWARD_LOCAL:
		أرجع &sc->local_perms;
		اكسر;
	حالة FORWARD_REMOTE:
		أرجع &sc->remote_perms;
		اكسر;
	افتراضي:
		fatal_f("invalid forwarding direction %d", where);
	}
}

/* Returns pointers to the specified forwarding list and its element count */
ساكن فراغ
permission_مجموعه_get_array(بنية ssh *ssh, صحيح who, صحيح where,
    بنية permission ***permpp, u_int **npermpp)
{
	بنية permission_مجموعه *pset = permission_مجموعه_get(ssh, where);

	بدل (who) {
	حالة FORWARD_USER:
		*permpp = &pset->permitted_user;
		*npermpp = &pset->رقم_permitted_user;
		اكسر;
	حالة FORWARD_ADM:
		*permpp = &pset->permitted_admin;
		*npermpp = &pset->رقم_permitted_admin;
		اكسر;
	افتراضي:
		fatal_f("invalid forwarding client %d", who);
	}
}

/* Adds an entry to the specified forwarding list */
ساكن صحيح
permission_مجموعه_جمع_کن(بنية ssh *ssh, صحيح who, صحيح where,
    ثابت حرف *host_مقصد_connect, صحيح پورت_مقصد_connect,
    ثابت حرف *listen_host, ثابت حرف *listen_مسیر, صحيح listen_پورت,
    Channel *downstream)
{
	بنية permission **permp;
	u_int n, *npermp;

	permission_مجموعه_get_array(ssh, who, where, &permp, &npermp);

	إذا (*npermp >= بیشترین_صحیح)
		fatal_f("%s overflow", fwd_ident(who, where));

	*permp = xrecallocarray(*permp, *npermp, *npermp + 1, حجم(**permp));
	n = (*npermp)++;
#تعریف_کن MAYBE_DUP(s) ((s == عدم) ? عدم : xstrdup(s))
	(*permp)[n].host_مقصد_connect = MAYBE_DUP(host_مقصد_connect);
	(*permp)[n].پورت_مقصد_connect = پورت_مقصد_connect;
	(*permp)[n].listen_host = MAYBE_DUP(listen_host);
	(*permp)[n].listen_مسیر = MAYBE_DUP(listen_مسیر);
	(*permp)[n].listen_پورت = listen_پورت;
	(*permp)[n].downstream = downstream;
#لغو_تعریف MAYBE_DUP
	أرجع (صحيح)n;
}

ساكن فراغ
mux_remove_remote_forwardings(بنية ssh *ssh, Channel *c)
{
	بنية ssh_channels *sc = ssh->chanctxt;
	بنية permission_مجموعه *pset = &sc->local_perms;
	بنية permission *perm;
	صحيح r;
	u_int i;

	لكل (i = 0; i < pset->رقم_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		إذا (perm->downstream != c)
			استمر;

		/* cancel on the server, since mux client is gone */
		debug("channel %d: cleanup remote forward for %s:%u",
		    c->self, perm->listen_host, perm->listen_پورت);
		إذا ((r = sshpkt_شروع(ssh, SSH2_پیام_GLOBAL_REQUEST)) != 0 ||
		    (r = sshpkt_put_cstring(ssh,
		    "cancel-tcpip-forward")) != 0 ||
		    (r = sshpkt_put_u8(ssh, 0)) != 0 ||
		    (r = sshpkt_put_cstring(ssh,
		    channel_rfwd_bind_host(perm->listen_host))) != 0 ||
		    (r = sshpkt_put_u32(ssh, perm->listen_پورت)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0) {
			fatal_fr(r, "channel %i", c->self);
		}
		fwd_perm_clear(perm); /* unregister */
	}
}

/* Free the channel and close its fd/socket. */
فراغ
channel_free(بنية ssh *ssh, Channel *c)
{
	بنية ssh_channels *sc = ssh->chanctxt;
	حرف *s;
	u_int i, n;
	Channel *other;
	بنية channel_confirm *cc;

	لكل (n = 0, i = 0; i < sc->channels_alloc; i++) {
		إذا ((other = sc->channels[i]) == عدم)
			استمر;
		n++;
		/* detach from mux client and prepare for closing */
		إذا (c->type == SSH_CHANNEL_MUX_CLIENT &&
		    other->type == SSH_CHANNEL_MUX_PROXY &&
		    other->mux_ctx == c) {
			other->mux_ctx = عدم;
			other->type = SSH_CHANNEL_OPEN;
			other->istate = CHAN_درون_داد_CLOSED;
			other->ostate = CHAN_OUTPUT_CLOSED;
		}
	}
	debug("channel %d: free: %s, nchannels %u", c->self,
	    c->remote_name ? c->remote_name : "???", n);

	إذا (c->type == SSH_CHANNEL_MUX_CLIENT) {
		mux_remove_remote_forwardings(ssh, c);
		حرر(c->mux_ctx);
		c->mux_ctx = عدم;
	} وإلا إذا (c->type == SSH_CHANNEL_MUX_LISTENER) {
		حرر(c->mux_ctx);
		c->mux_ctx = عدم;
	}

	إذا (log_level_get() >= SYSLOG_LEVEL_DEBUG3) {
		s = channel_open_پیام(ssh);
		debug3("channel %d: status: %s", c->self, s);
		حرر(s);
	}

	channel_close_fds(ssh, c);
	sshbuf_free(c->درون_داد);
	sshbuf_free(c->output);
	sshbuf_free(c->extended);
	c->درون_داد = c->output = c->extended = عدم;
	حرر(c->remote_name);
	c->remote_name = عدم;
	حرر(c->مسیر);
	c->مسیر = عدم;
	حرر(c->listening_addr);
	c->listening_addr = عدم;
	حرر(c->xctype);
	c->xctype = عدم;
	channel_free_connect_ctx(c);
	طالما ((cc = TAILQ_FIRST(&c->وضعیت_confirms)) != عدم) {
		إذا (cc->abandon_cb != عدم)
			cc->abandon_cb(ssh, c, cc->ctx);
		TAILQ_REMOVE(&c->وضعیت_confirms, cc, مدخل);
		freezero(cc, حجم(*cc));
	}
	إذا (c->filter_cleanup != عدم && c->filter_ctx != عدم)
		c->filter_cleanup(ssh, c->self, c->filter_ctx);
	sc->channels[c->self] = عدم;
	freezero(c, حجم(*c));
}

فراغ
channel_free_all(بنية ssh *ssh)
{
	u_int i;
	بنية ssh_channels *sc = ssh->chanctxt;

	لكل (i = 0; i < sc->channels_alloc; i++)
		إذا (sc->channels[i] != عدم)
			channel_free(ssh, sc->channels[i]);

	حرر(sc->channels);
	sc->channels = عدم;
	sc->channels_alloc = 0;

	حرر(sc->x11_saved_display);
	sc->x11_saved_display = عدم;

	حرر(sc->x11_saved_proto);
	sc->x11_saved_proto = عدم;

	حرر(sc->x11_saved_داده);
	sc->x11_saved_داده = عدم;
	sc->x11_saved_داده_len = 0;

	حرر(sc->x11_fake_داده);
	sc->x11_fake_داده = عدم;
	sc->x11_fake_داده_len = 0;
}

فراغ
channel_free_channels(بنية ssh *ssh)
{
	بنية ssh_channels *sc;

	إذا (ssh == عدم || ssh->chanctxt == عدم)
		أرجع;
	channel_free_all(ssh);
	channel_clear_permission(ssh, FORWARD_USER, FORWARD_LOCAL);
	channel_clear_permission(ssh, FORWARD_USER, FORWARD_REMOTE);
	channel_clear_permission(ssh, FORWARD_ADM, FORWARD_LOCAL);
	channel_clear_permission(ssh, FORWARD_ADM, FORWARD_REMOTE);
	sc = ssh->chanctxt;
	حرر(sc->bulk_classifier_tty);
	حرر(sc->bulk_classifier_notty);
	حرر(sc->channel_pre);
	حرر(sc->channel_post);
	freezero(sc, حجم(*sc));
	ssh->chanctxt = عدم;
}

/*
 * Closes the sockets/fds of all channels.  This is used to close extra file
 * descriptors after a fork.
 */
فراغ
channel_close_all(بنية ssh *ssh)
{
	u_int i;

	لكل (i = 0; i < ssh->chanctxt->channels_alloc; i++)
		إذا (ssh->chanctxt->channels[i] != عدم)
			channel_close_fds(ssh, ssh->chanctxt->channels[i]);
}

/*
 * Stop listening to channels.
 */
فراغ
channel_stop_listening(بنية ssh *ssh)
{
	u_int i;
	Channel *c;

	لكل (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		إذا (c != عدم) {
			بدل (c->type) {
			حالة SSH_CHANNEL_AUTH_SOCKET:
			حالة SSH_CHANNEL_پورت_LISTENER:
			حالة SSH_CHANNEL_RPORT_LISTENER:
			حالة SSH_CHANNEL_X11_LISTENER:
			حالة SSH_CHANNEL_UNIX_LISTENER:
			حالة SSH_CHANNEL_RUNIX_LISTENER:
				channel_close_fd(ssh, c, &c->sock);
				channel_free(ssh, c);
				اكسر;
			}
		}
	}
}

/*
 * Returns true if no channel has too much buffered data, and false if one or
 * more channel is overfull.
 */
صحيح
channel_not_very_much_buffered_داده(بنية ssh *ssh)
{
	u_int i;
	u_int maxsize = ssh_packet_get_maxsize(ssh);
	Channel *c;

	لكل (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		إذا (c == عدم || c->type != SSH_CHANNEL_OPEN)
			استمر;
		إذا (sshbuf_len(c->output) > maxsize) {
			debug2("channel %d: big output buffer %zu > %u",
			    c->self, sshbuf_len(c->output), maxsize);
			أرجع 0;
		}
	}
	أرجع 1;
}

/* Returns true if any channel is still open. */
صحيح
channel_still_open(بنية ssh *ssh)
{
	u_int i;
	Channel *c;

	لكل (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		إذا (c == عدم)
			استمر;
		بدل (c->type) {
		حالة SSH_CHANNEL_X11_LISTENER:
		حالة SSH_CHANNEL_پورت_LISTENER:
		حالة SSH_CHANNEL_RPORT_LISTENER:
		حالة SSH_CHANNEL_MUX_LISTENER:
		حالة SSH_CHANNEL_CLOSED:
		حالة SSH_CHANNEL_AUTH_SOCKET:
		حالة SSH_CHANNEL_DYNAMIC:
		حالة SSH_CHANNEL_RDYNAMIC_OPEN:
		حالة SSH_CHANNEL_CONNECTING:
		حالة SSH_CHANNEL_ZOMBIE:
		حالة SSH_CHANNEL_ABANDONED:
		حالة SSH_CHANNEL_UNIX_LISTENER:
		حالة SSH_CHANNEL_RUNIX_LISTENER:
			استمر;
		حالة SSH_CHANNEL_LARVAL:
			استمر;
		حالة SSH_CHANNEL_OPENING:
		حالة SSH_CHANNEL_OPEN:
		حالة SSH_CHANNEL_RDYNAMIC_پایان:
		حالة SSH_CHANNEL_X11_OPEN:
		حالة SSH_CHANNEL_MUX_CLIENT:
		حالة SSH_CHANNEL_MUX_PROXY:
			أرجع 1;
		افتراضي:
			fatal_f("bad channel type %d", c->type);
			/* NOTREACHED */
		}
	}
	أرجع 0;
}

/* Returns true if a channel with a TTY is open. */
صحيح
channel_tty_open(بنية ssh *ssh)
{
	u_int i;
	Channel *c;

	لكل (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		إذا (c == عدم || c->type != SSH_CHANNEL_OPEN)
			استمر;
		إذا (c->client_tty)
			أرجع 1;
	}
	أرجع 0;
}

/* Returns the id of an open channel suitable for keepaliving */
صحيح
channel_پیدا_کن_open(بنية ssh *ssh)
{
	u_int i;
	Channel *c;

	لكل (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		إذا (c == عدم || !c->have_remote_id)
			استمر;
		بدل (c->type) {
		حالة SSH_CHANNEL_CLOSED:
		حالة SSH_CHANNEL_DYNAMIC:
		حالة SSH_CHANNEL_RDYNAMIC_OPEN:
		حالة SSH_CHANNEL_RDYNAMIC_پایان:
		حالة SSH_CHANNEL_X11_LISTENER:
		حالة SSH_CHANNEL_پورت_LISTENER:
		حالة SSH_CHANNEL_RPORT_LISTENER:
		حالة SSH_CHANNEL_MUX_LISTENER:
		حالة SSH_CHANNEL_MUX_CLIENT:
		حالة SSH_CHANNEL_MUX_PROXY:
		حالة SSH_CHANNEL_OPENING:
		حالة SSH_CHANNEL_CONNECTING:
		حالة SSH_CHANNEL_ZOMBIE:
		حالة SSH_CHANNEL_ABANDONED:
		حالة SSH_CHANNEL_UNIX_LISTENER:
		حالة SSH_CHANNEL_RUNIX_LISTENER:
			استمر;
		حالة SSH_CHANNEL_LARVAL:
		حالة SSH_CHANNEL_AUTH_SOCKET:
		حالة SSH_CHANNEL_OPEN:
		حالة SSH_CHANNEL_X11_OPEN:
			أرجع i;
		افتراضي:
			fatal_f("bad channel type %d", c->type);
			/* NOTREACHED */
		}
	}
	أرجع -1;
}

/* Returns the state of the channel's extended usage flag */
ثابت حرف *
channel_format_extended_usage(ثابت Channel *c)
{
	إذا (c->efd == -1)
		أرجع "closed";

	بدل (c->extended_usage) {
	حالة CHAN_EXTENDED_WRITE:
		أرجع "write";
	حالة CHAN_EXTENDED_READ:
		أرجع "read";
	حالة CHAN_EXTENDED_IGNORE:
		أرجع "ignore";
	افتراضي:
		أرجع "UNKNOWN";
	}
}

ساكن حرف *
channel_format_وضعیت(ثابت Channel *c)
{
	حرف *ret = عدم;

	xasprintf(&ret, "t%d [%s] %s%u %s%u i%u/%zu o%u/%zu e[%s]/%zu "
	    "fd %d/%d/%d sock %d cc %d %s%u io 0x%02x/0x%02x %s%s",
	    c->type, c->xctype != عدم ? c->xctype : c->ctype,
	    c->have_remote_id ? "r" : "nr", c->remote_id,
	    c->mux_ctx != عدم ? "m" : "nm", c->mux_downstream_id,
	    c->istate, sshbuf_len(c->درون_داد),
	    c->ostate, sshbuf_len(c->output),
	    channel_format_extended_usage(c), sshbuf_len(c->extended),
	    c->rfd, c->wfd, c->efd, c->sock, c->ctl_chan,
	    c->have_ctl_فرزند_id ? "c" : "nc", c->ctl_فرزند_id,
	    c->io_want, c->io_ready,
	    c->isatty ? "T" : (c->remote_has_tty ? "RT" : ""),
	    c->bulk ? "B" : "I");
	أرجع ret;
}

/*
 * Returns a message describing the currently open forwarded connections,
 * suitable for sending to the client.  The message contains crlf pairs for
 * newlines.
 */
حرف *
channel_open_پیام(بنية ssh *ssh)
{
	بنية sshbuf *buf;
	Channel *c;
	u_int i;
	صحيح r;
	حرف *cp, *ret;

	إذا ((buf = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new");
	إذا ((r = sshbuf_putf(buf,
	    "The following connections are open:\r\n")) != 0)
		fatal_fr(r, "sshbuf_putf");
	لكل (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		إذا (c == عدم)
			استمر;
		بدل (c->type) {
		حالة SSH_CHANNEL_X11_LISTENER:
		حالة SSH_CHANNEL_پورت_LISTENER:
		حالة SSH_CHANNEL_RPORT_LISTENER:
		حالة SSH_CHANNEL_CLOSED:
		حالة SSH_CHANNEL_AUTH_SOCKET:
		حالة SSH_CHANNEL_ZOMBIE:
		حالة SSH_CHANNEL_ABANDONED:
		حالة SSH_CHANNEL_MUX_LISTENER:
		حالة SSH_CHANNEL_UNIX_LISTENER:
		حالة SSH_CHANNEL_RUNIX_LISTENER:
			استمر;
		حالة SSH_CHANNEL_LARVAL:
		حالة SSH_CHANNEL_OPENING:
		حالة SSH_CHANNEL_CONNECTING:
		حالة SSH_CHANNEL_DYNAMIC:
		حالة SSH_CHANNEL_RDYNAMIC_OPEN:
		حالة SSH_CHANNEL_RDYNAMIC_پایان:
		حالة SSH_CHANNEL_OPEN:
		حالة SSH_CHANNEL_X11_OPEN:
		حالة SSH_CHANNEL_MUX_PROXY:
		حالة SSH_CHANNEL_MUX_CLIENT:
			cp = channel_format_وضعیت(c);
			إذا ((r = sshbuf_putf(buf, "  #%d %.300s (%s)\r\n",
			    c->self, c->remote_name, cp)) != 0) {
				حرر(cp);
				fatal_fr(r, "sshbuf_putf");
			}
			حرر(cp);
			استمر;
		افتراضي:
			fatal_f("bad channel type %d", c->type);
			/* NOTREACHED */
		}
	}
	إذا ((ret = sshbuf_dup_string(buf)) == عدم)
		fatal_f("sshbuf_dup_string");
	sshbuf_free(buf);
	أرجع ret;
}

فراغ
channel_report_open(بنية ssh *ssh, صحيح level)
{
	حرف *open, *oopen, *cp, ident[256];

	sshpkt_fmt_connection_id(ssh, ident, حجم(ident));
	do_log2(level, "Connection: %s (pid %ld)", ident, (دراز)getpid());
	open = oopen = channel_open_پیام(ssh);
	طالما ((cp = strsep(&open, "\r\n")) != عدم) {
		إذا (*cp != '\0')
			do_log2(level, "%s", cp);
	}
	حرر(oopen);
}

ساكن فراغ
open_preamble(بنية ssh *ssh, ثابت حرف *where, Channel *c, ثابت حرف *type)
{
	صحيح r;

	إذا ((r = sshpkt_شروع(ssh, SSH2_پیام_CHANNEL_OPEN)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, type)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_پنجره)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0) {
		fatal_r(r, "%s: channel %i: open", where, c->self);
	}
}

فراغ
channel_send_open(بنية ssh *ssh, صحيح id)
{
	Channel *c = channel_lookup(ssh, id);
	صحيح r;

	إذا (c == عدم) {
		logit("channel_send_open: %d: bad id", id);
		أرجع;
	}
	debug2("channel %d: send open", id);
	open_preamble(ssh, __func__, c, c->ctype);
	إذا ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i", c->self);
}

فراغ
channel_request_شروع(بنية ssh *ssh, صحيح id, ثابت حرف *service,
    صحيح wantconfirm)
{
	Channel *c = channel_lookup(ssh, id);
	صحيح r;

	إذا (c == عدم) {
		logit_f("%d: unknown channel id", id);
		أرجع;
	}
	إذا (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);

	debug2("channel %d: request %s confirm %d", id, service, wantconfirm);
	إذا ((r = sshpkt_شروع(ssh, SSH2_پیام_CHANNEL_REQUEST)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, service)) != 0 ||
	    (r = sshpkt_put_u8(ssh, wantconfirm)) != 0) {
		fatal_fr(r, "channel %i", c->self);
	}
}

فراغ
channel_ثبات_وضعیت_confirm(بنية ssh *ssh, صحيح id,
    channel_confirm_cb *cb, channel_confirm_abandon_cb *abandon_cb, فراغ *ctx)
{
	بنية channel_confirm *cc;
	Channel *c;

	إذا ((c = channel_lookup(ssh, id)) == عدم)
		fatal_f("%d: bad id", id);

	cc = xcalloc(1, حجم(*cc));
	cc->cb = cb;
	cc->abandon_cb = abandon_cb;
	cc->ctx = ctx;
	TAILQ_INSERT_TAIL(&c->وضعیت_confirms, cc, مدخل);
}

فراغ
channel_ثبات_open_confirm(بنية ssh *ssh, صحيح id,
    channel_open_fn *fn, فراغ *ctx)
{
	Channel *c = channel_lookup(ssh, id);

	إذا (c == عدم) {
		logit_f("%d: bad id", id);
		أرجع;
	}
	c->open_confirm = fn;
	c->open_confirm_ctx = ctx;
}

فراغ
channel_ثبات_cleanup(بنية ssh *ssh, صحيح id,
    channel_callback_fn *fn, صحيح do_close)
{
	Channel *c = channel_by_id(ssh, id);

	إذا (c == عدم) {
		logit_f("%d: bad id", id);
		أرجع;
	}
	c->detach_user = fn;
	c->detach_close = do_close;
}

فراغ
channel_cancel_cleanup(بنية ssh *ssh, صحيح id)
{
	Channel *c = channel_by_id(ssh, id);

	إذا (c == عدم) {
		logit_f("%d: bad id", id);
		أرجع;
	}
	c->detach_user = عدم;
	c->detach_close = 0;
}

فراغ
channel_ثبات_filter(بنية ssh *ssh, صحيح id, channel_infilter_fn *ifn,
    channel_outfilter_fn *ofn, channel_filter_cleanup_fn *cfn, فراغ *ctx)
{
	Channel *c = channel_lookup(ssh, id);

	إذا (c == عدم) {
		logit_f("%d: bad id", id);
		أرجع;
	}
	c->درون_داد_filter = ifn;
	c->output_filter = ofn;
	c->filter_ctx = ctx;
	c->filter_cleanup = cfn;
}

فراغ
channel_مجموعه_fds(بنية ssh *ssh, صحيح id, صحيح rfd, صحيح wfd, صحيح efd,
    صحيح extusage, صحيح nonblock, صحيح is_tty, u_int پنجره_max)
{
	Channel *c = channel_lookup(ssh, id);
	صحيح r;

	إذا (c == عدم || c->type != SSH_CHANNEL_LARVAL)
		fatal("channel_activate for non-larval channel %d.", id);
	إذا (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);

	channel_ثبات_fds(ssh, c, rfd, wfd, efd, extusage, nonblock, is_tty);
	c->type = SSH_CHANNEL_OPEN;
	channel_مجموعه_استفاده_شده_زمان(ssh, c);
	c->local_پنجره = c->local_پنجره_max = پنجره_max;

	إذا ((r = sshpkt_شروع(ssh, SSH2_پیام_CHANNEL_پنجره_ADJUST)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_پنجره)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i", c->self);
}

ساكن فراغ
channel_pre_listener(بنية ssh *ssh, Channel *c)
{
	c->io_want = SSH_CHAN_IO_SOCK_R;
}

ساكن فراغ
channel_pre_connecting(بنية ssh *ssh, Channel *c)
{
	debug3("channel %d: waiting for connection", c->self);
	c->io_want = SSH_CHAN_IO_SOCK_W;
}

ساكن فراغ
channel_pre_open(بنية ssh *ssh, Channel *c)
{
	c->io_want = 0;
	إذا (c->istate == CHAN_درون_داد_OPEN &&
	    c->remote_پنجره > 0 &&
	    sshbuf_len(c->درون_داد) < c->remote_پنجره &&
	    sshbuf_check_reserve(c->درون_داد, CHAN_RBUF) == 0)
		c->io_want |= SSH_CHAN_IO_RFD;
	إذا (c->ostate == CHAN_OUTPUT_OPEN ||
	    c->ostate == CHAN_OUTPUT_WAIT_DRAIN) {
		إذا (sshbuf_len(c->output) > 0) {
			c->io_want |= SSH_CHAN_IO_WFD;
		} وإلا إذا (c->ostate == CHAN_OUTPUT_WAIT_DRAIN) {
			إذا (CHANNEL_EFD_OUTPUT_فعال(c))
				debug2("channel %d: "
				    "obuf_empty delayed efd %d/(%zu)", c->self,
				    c->efd, sshbuf_len(c->extended));
			وإلا
				chan_obuf_خالی(ssh, c);
		}
	}
	/** XXX check close conditions, too */
	إذا (c->efd != -1 && !(c->istate == CHAN_درون_داد_CLOSED &&
	    c->ostate == CHAN_OUTPUT_CLOSED)) {
		إذا (c->extended_usage == CHAN_EXTENDED_WRITE &&
		    sshbuf_len(c->extended) > 0)
			c->io_want |= SSH_CHAN_IO_EFD_W;
		وإلا إذا (c->efd != -1 && !(c->flags & CHAN_EOF_فرستاده) &&
		    (c->extended_usage == CHAN_EXTENDED_READ ||
		    c->extended_usage == CHAN_EXTENDED_IGNORE) &&
		    sshbuf_len(c->extended) < c->remote_پنجره)
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
ساكن صحيح
x11_open_helper(بنية ssh *ssh, بنية sshbuf *b)
{
	بنية ssh_channels *sc = ssh->chanctxt;
	u_char *ucp;
	u_int proto_len, داده_len;

	إذا (sc->x11_saved_proto == عدم) {
		error("X11 forwarding opened before X11 forwarding requested");
		أرجع -1;
	}

	/* Is this being called after the refusal deadline? */
	إذا (sc->x11_refuse_زمان != 0.0 &&
	    monotime_double() >= sc->x11_refuse_زمان) {
		verbose("Rejected X11 connection after ForwardX11Timeout "
		    "expired");
		أرجع -1;
	}

	/* Check if the fixed size part of the packet is in buffer. */
	إذا (sshbuf_len(b) < 12)
		أرجع 0;

	/* Parse the lengths of variable-length fields. */
	ucp = sshbuf_mutable_ptr(b);
	إذا (ucp[0] == 0x42) {	/* Byte order MSB first. */
		proto_len = 256 * ucp[6] + ucp[7];
		داده_len = 256 * ucp[8] + ucp[9];
	} وإلا إذا (ucp[0] == 0x6c) {	/* Byte order LSB first. */
		proto_len = ucp[6] + 256 * ucp[7];
		داده_len = ucp[8] + 256 * ucp[9];
	} وإلا {
		debug2("Initial X11 packet contains bad byte order byte: 0x%x",
		    ucp[0]);
		أرجع -1;
	}

	/* Check if the whole packet is in buffer. */
	إذا (sshbuf_len(b) <
	    12 + ((proto_len + 3) & ~3) + ((داده_len + 3) & ~3))
		أرجع 0;

	/* Check if authentication protocol matches. */
	إذا (proto_len != طول_رشته(sc->x11_saved_proto) ||
	    memcmp(ucp + 12, sc->x11_saved_proto, proto_len) != 0) {
		debug2("X11 connection uses different authentication protocol.");
		أرجع -1;
	}
	/* Check if authentication data matches our fake data. */
	إذا (داده_len != sc->x11_fake_داده_len ||
	    timingsafe_bcmp(ucp + 12 + ((proto_len + 3) & ~3),
		sc->x11_fake_داده, sc->x11_fake_داده_len) != 0) {
		debug2("X11 auth data does not match fake data.");
		أرجع -1;
	}
	/* Check fake data length */
	إذا (sc->x11_fake_داده_len != sc->x11_saved_داده_len) {
		error("X11 fake_data_len %d != saved_data_len %d",
		    sc->x11_fake_داده_len, sc->x11_saved_داده_len);
		أرجع -1;
	}
	/*
	 * Received authentication protocol and data match
	 * our fake data. Substitute the fake data with real
	 * data.
	 */
	کپی_حافظه(ucp + 12 + ((proto_len + 3) & ~3),
	    sc->x11_saved_داده, sc->x11_saved_داده_len);
	أرجع 1;
}

فراغ
channel_force_close(بنية ssh *ssh, Channel *c, صحيح abandon)
{
	debug3_f("channel %d: forcibly closing", c->self);
	إذا (c->istate == CHAN_درون_داد_OPEN)
		chan_read_failed(ssh, c);
	إذا (c->istate == CHAN_درون_داد_WAIT_DRAIN) {
		sshbuf_reset(c->درون_داد);
		chan_ibuf_خالی(ssh, c);
	}
	إذا (c->ostate == CHAN_OUTPUT_OPEN ||
	    c->ostate == CHAN_OUTPUT_WAIT_DRAIN) {
		sshbuf_reset(c->output);
		chan_write_failed(ssh, c);
	}
	إذا (c->detach_user)
		c->detach_user(ssh, c->self, 1, عدم);
	إذا (c->efd != -1)
		channel_close_fd(ssh, c, &c->efd);
	إذا (abandon)
		c->type = SSH_CHANNEL_ABANDONED;
	/* exempt from inactivity timeouts */
	c->inactive_deadline = 0;
	c->lastused = 0;
}

ساكن فراغ
channel_pre_x11_open(بنية ssh *ssh, Channel *c)
{
	صحيح ret = x11_open_helper(ssh, c->output);

	/* c->force_drain = 1; */

	إذا (ret == 1) {
		c->type = SSH_CHANNEL_OPEN;
		channel_مجموعه_استفاده_شده_زمان(ssh, c);
		channel_pre_open(ssh, c);
	} وإلا إذا (ret == -1) {
		logit("X11 connection rejected because of wrong "
		    "authentication.");
		debug2("X11 rejected %d i%d/o%d",
		    c->self, c->istate, c->ostate);
		channel_force_close(ssh, c, 0);
	}
}

ساكن فراغ
channel_pre_mux_client(بنية ssh *ssh, Channel *c)
{
	c->io_want = 0;
	إذا (c->istate == CHAN_درون_داد_OPEN && !c->mux_pause &&
	    sshbuf_check_reserve(c->درون_داد, CHAN_RBUF) == 0)
		c->io_want |= SSH_CHAN_IO_RFD;
	إذا (c->istate == CHAN_درون_داد_WAIT_DRAIN) {
		/* clear buffer immediately (discard any partial packet) */
		sshbuf_reset(c->درون_داد);
		chan_ibuf_خالی(ssh, c);
		/* Start output drain. XXX just kill chan? */
		chan_rcvd_oclose(ssh, c);
	}
	إذا (c->ostate == CHAN_OUTPUT_OPEN ||
	    c->ostate == CHAN_OUTPUT_WAIT_DRAIN) {
		إذا (sshbuf_len(c->output) > 0)
			c->io_want |= SSH_CHAN_IO_WFD;
		وإلا إذا (c->ostate == CHAN_OUTPUT_WAIT_DRAIN)
			chan_obuf_خالی(ssh, c);
	}
}

ساكن مضمن صحيح
socks_decode_error(Channel *c, صحيح وضعیت, ثابت حرف *func, ثابت حرف *پیام)
{
	إذا (وضعیت == SSH_ERR_پیام_INCOMPLETE)
		أرجع 0;
	وإلا {
		debug_r(وضعیت, "%s: channel %d: decode %s",
		    func, c->self, پیام);
		أرجع -1;
	}
}

/* try to decode a socks4 header */
ساكن صحيح
channel_decode_socks4(Channel *c, بنية sshbuf *درون_داد, بنية sshbuf *output)
{
	uint8_t socks_ver, socks_cmd, dest_addr[4];
	uint16_t dest_پورت;
	حرف *user = عدم, *host = عدم;
	صحيح success = -1, socks4a = 0, r;
	بنية sshbuf *b = عدم;

	إذا (sshbuf_len(درون_داد) < 9)
		أرجع 0;

	/* We may not have a complete message, so work on a dup of the buffer */
	إذا ((b = sshbuf_fromb(درون_داد)) == عدم)
		fatal_f("sshbuf_fromb failed");

	debug2("channel %d: decode socks4", c->self);
	إذا ((r = sshbuf_get_u8(b, &socks_ver)) != 0 ||
	    (r = sshbuf_get_u8(b, &socks_cmd)) != 0 ||
	    (r = sshbuf_get_u16(b, &dest_پورت)) != 0 ||
	    (r = sshbuf_get(b, &dest_addr, حجم(dest_addr))) != 0 ||
	    (r = sshbuf_get_nulterminated_string(b, 1024, &user, عدم)) != 0) {
		success = socks_decode_error(c, r, __func__, "header");
		اذهب بیرون;
	}

	/* Is this a SOCKS4A request? (indicated by an address of 0.0.0.x) */
	إذا (dest_addr[0] == 0 && dest_addr[1] == 0 &&
	    dest_addr[2] == 0 && dest_addr[3] != 0) {
		/* If so, then the hostname follows, also nul-terminated */
		إذا ((r = sshbuf_get_nulterminated_string(b, 1024,
		    &host, عدم)) != 0) {
			success = socks_decode_error(c, r, __func__, "host");
			اذهب بیرون;
		}
		socks4a = 1;
	} وإلا {
		/* Plain SOCKS4 passes an IPv4 binary address; reconstruct */
		xasprintf(&host, "%d.%d.%d.%d",
		    dest_addr[0], dest_addr[1], dest_addr[2], dest_addr[3]);
	}

	/* We have a complete SOCKS4 message; consume it from input */
	إذا ((r = sshbuf_consume_upto_فرزند(درون_داد, b)) != 0)
		fatal_fr(r, "channel %d: consume", c->self);

	/* Handle the request */
	debug2("channel %d: %s: user=\"%s\" command=%d destination=[%s]:%d",
	    c->self, socks4a ? "SOCKS4A" : "SOCKS4", user, (صحيح)socks_cmd,
	    host, dest_پورت);
	إذا (socks_cmd != 1) {
		debug("channel %d: cannot handle %s command 0x%02x",
		    c->self, socks4a ? "SOCKS4A" : "SOCKS4", socks_cmd);
		اذهب بیرون;
	}
	حرر(c->مسیر);
	c->مسیر = host;
	host = عدم; /* transferred */
	c->host_پورت = dest_پورت;

	/* Reply to the SOCKS4 client */
	إذا ((r = sshbuf_put_u8(output, 0)) != 0 ||	/* vn: 0 for reply */
	    (r = sshbuf_put_u8(output, 90)) != 0 ||	/* cd: req granted */
	    (r = sshbuf_put_u16(output, 0)) != 0 ||	/* port: ignored */
	    (r = sshbuf_put_u32(output, ntohl(INADDR_ANY))) != 0) /* ignored */
		fatal_fr(r, "channel %d: compose reply", c->self);

	/* success */
	success = 1;
 بیرون:
	sshbuf_free(b);
	حرر(user);
	حرر(host);
	أرجع success;
}

/* try to decode a socks5 header */
#تعریف_کن SSH_SOCKS5_AUTHDONE	0x1000
#تعریف_کن SSH_SOCKS5_NOAUTH	0x00
#تعریف_کن SSH_SOCKS5_IPV4		0x01
#تعریف_کن SSH_SOCKS5_DOMAIN	0x03
#تعریف_کن SSH_SOCKS5_IPV6		0x04
#تعریف_کن SSH_SOCKS5_CONNECT	0x01
#تعریف_کن SSH_SOCKS5_SUCCESS	0x00

/*
 * Handles SOCKS5 authentication. Note 'b' must be a dup of 'input'
 * Returns 0 on insufficient queued date, 1 on authentication success or
 * -1 on error.
 */
ساكن صحيح
channel_socks5_check_auth(Channel *c, بنية sshbuf *b, بنية sshbuf *درون_داد,
    بنية sshbuf *output)
{
	uint8_t socks_ver;
	uint8_t nmethods, روش;
	صحيح r;
	u_int i, یافت;

	/* format: ver | nmethods | methods */
	إذا ((r = sshbuf_get_u8(b, &socks_ver)) != 0)
		أرجع socks_decode_error(c, r, __func__, "version");
	إذا (socks_ver != 5) /* shouldn't happen; checked by caller^2 */
		fatal_fr(r, "channel %d: internal error: not socks5", c->self);
	إذا ((r = sshbuf_get_u8(b, &nmethods)) != 0)
		أرجع socks_decode_error(c, r, __func__, "methods");
	لكل (یافت = i = 0; i < nmethods; i++) {
		إذا ((r = sshbuf_get_u8(b, &روش)) != 0)
			أرجع socks_decode_error(c, r, __func__, "method");
		إذا (روش == SSH_SOCKS5_NOAUTH)
			یافت = 1;
	}
	إذا (!یافت) {
		debug("channel %d: didn't request SSH_SOCKS5_NOAUTH", c->self);
		أرجع -1;
	}
	/* Consume completed request */
	إذا ((r = sshbuf_consume_upto_فرزند(درون_داد, b)) != 0)
		fatal_fr(r, "channel %d: consume", c->self);

	/* Compose reply: version, method */
	إذا ((r = sshbuf_put_u8(output, 0x05)) != 0 ||
	    (r = sshbuf_put_u8(output, SSH_SOCKS5_NOAUTH)) != 0)
		fatal_fr(r, "channel %d: append reply", c->self);
	/* success */
	debug2("channel %d: socks5 auth done", c->self);
	أرجع 1;
}

ساكن صحيح
channel_decode_socks5(Channel *c, بنية sshbuf *درون_داد, بنية sshbuf *output)
{
	uint8_t socks_ver, socks_cmd, socks_reserved, socks_atyp, addrlen;
	uint16_t dest_پورت;
	حرف dest_addr[255+1], ntop[INET6_ADDRSTRLEN];
	u_int af;
	صحيح r, success = -1;;
	بنية sshbuf *b = عدم;

	debug2("channel %d: decode socks5 %s", c->self,
	    (c->flags & SSH_SOCKS5_AUTHDONE) ? "request" : "auth");

	/* We may not have a complete message, so work on a dup of the buffer */
	إذا ((b = sshbuf_fromb(درون_داد)) == عدم)
		fatal_f("sshbuf_fromb failed");

	إذا (!(c->flags & SSH_SOCKS5_AUTHDONE)) {
		إذا ((r = channel_socks5_check_auth(c, b, درون_داد, output)) != 1) {
			success = r;
			اذهب بیرون;
		}
		c->flags |= SSH_SOCKS5_AUTHDONE;
		/* Continue to parse request in case client speculated ahead */
	}

	/* Request messages (auth or connect) always start with the version */
	إذا ((r = sshbuf_get_u8(b, &socks_ver)) != 0) {
		success = socks_decode_error(c, r, __func__, "version");
		اذهب بیرون;
	}
	إذا (socks_ver != 5) /* shouldn't happen */
		fatal_fr(r, "channel %d: internal error: not socks5", c->self);

	/* Parse SOCKS5 request header */
	debug2("channel %d: socks5 post auth", c->self);
	إذا ((r = sshbuf_get_u8(b, &socks_cmd)) != 0 ||
	    (r = sshbuf_get_u8(b, &socks_reserved)) != 0 ||
	    (r = sshbuf_get_u8(b, &socks_atyp)) != 0) {
		success = socks_decode_error(c, r, __func__, "request header");
		اذهب بیرون;
	}

	إذا (socks_ver != 0x05 ||
	    socks_cmd != SSH_SOCKS5_CONNECT ||
	    socks_reserved != 0x00) {
		debug2("channel %d: only socks5 connect supported", c->self);
		اذهب بیرون;
	}

	بدل (socks_atyp) {
	حالة SSH_SOCKS5_IPV4:
		addrlen = 4;
		af = AF_INET;
		اكسر;
	حالة SSH_SOCKS5_DOMAIN:
		إذا ((r = sshbuf_get_u8(b, &addrlen)) != 0) {
			success = socks_decode_error(c, r, __func__, "addrlen");
			اذهب بیرون;
		}
		af = -1;
		اكسر;
	حالة SSH_SOCKS5_IPV6:
		addrlen = 16;
		af = AF_INET6;
		اكسر;
	افتراضي:
		debug2("channel %d: bad socks5 atyp %d", c->self, socks_atyp);
		اذهب بیرون;
	}
	إذا ((r = sshbuf_get(b, &dest_addr, addrlen)) != 0 ||
	    (r = sshbuf_get_u16(b, &dest_پورت)) != 0) {
		success = socks_decode_error(c, r, __func__, "addr/port");
		اذهب بیرون;
	}
	dest_addr[addrlen] = '\0';

	/* We have a complete SOCKS5 request; consume it from input */
	إذا ((r = sshbuf_consume_upto_فرزند(درون_داد, b)) != 0)
		fatal_fr(r, "channel %d: consume", c->self);

	حرر(c->مسیر);
	c->مسیر = عدم;
	إذا (socks_atyp == SSH_SOCKS5_DOMAIN)
		c->مسیر = xstrdup(dest_addr);
	وإلا {
		إذا (inet_ntop(af, dest_addr, ntop, حجم(ntop)) == عدم)
			أرجع -1;
		c->مسیر = xstrdup(ntop);
	}
	c->host_پورت = dest_پورت;

	debug2("channel %d: dynamic request: socks5 host %s port %u command %u",
	    c->self, c->مسیر, c->host_پورت, socks_cmd);

	/*پاسخ*/
	إذا ((r = sshbuf_put_u8(output, 0x05)) != 0 ||	/*نسخه*/
	    (r = sshbuf_put_u8(output, SSH_SOCKS5_SUCCESS)) != 0 || /* cmd */
	    (r = sshbuf_put_u8(output, 0)) != 0 ||	/* reserved, ignored */
	    (r = sshbuf_put_u8(output, SSH_SOCKS5_IPV4)) != 0 || /* addrtype */
	    (r = sshbuf_put_u32(output, ntohl(INADDR_ANY))) != 0 || /* addr */
	    (r = sshbuf_put_u16(output, dest_پورت)) != 0) /*پورت*/
		fatal_fr(r, "channel %d: append reply", c->self);

	/* success */
	success = 1;
 بیرون:
	sshbuf_free(b);
	أرجع success;
}

Channel *
channel_connect_stdio_fwd(بنية ssh *ssh,
    ثابت حرف *host_مقصد_connect, صحيح پورت_مقصد_connect,
    صحيح درون, صحيح بیرون, صحيح nonblock)
{
	Channel *c;

	debug_f("%s:%d", host_مقصد_connect, پورت_مقصد_connect);

	c = channel_new(ssh, "stdio-forward", SSH_CHANNEL_OPENING, درون, بیرون,
	    -1, CHAN_TCP_پنجره_DEFAULT, CHAN_TCP_PACKET_DEFAULT,
	    0, "stdio-forward", nonblock);

	c->مسیر = xstrdup(host_مقصد_connect);
	c->host_پورت = پورت_مقصد_connect;
	c->listening_پورت = 0;
	c->force_drain = 1;

	channel_ثبات_fds(ssh, c, درون, بیرون, -1, 0, 1, 0);
	پورت_open_helper(ssh, c, پورت_مقصد_connect == پورت_STREAMLOCAL ?
	    "direct-streamlocal@openssh.com" : "direct-tcpip");

	أرجع c;
}

/* dynamic port forwarding */
ساكن فراغ
channel_pre_dynamic(بنية ssh *ssh, Channel *c)
{
	u_int have;
	u_char ver;
	صحيح r, ret;

	c->io_want = 0;
	have = sshbuf_len(c->درون_داد);
	debug2("channel %d: pre_dynamic: have %d", c->self, have);
	/* sshbuf_dump(c->input, stderr); */
	/* check if the fixed size part of the packet is in buffer. */
	إذا (have < 3) {
		/* need more */
		c->io_want |= SSH_CHAN_IO_RFD;
		أرجع;
	}
	/* try to guess the protocol */
	إذا ((r = sshbuf_peek_u8(c->درون_داد, 0, &ver)) != 0)
		fatal_fr(r, "sshbuf_peek_u8");
	بدل (ver) {
	حالة 0x04:
		ret = channel_decode_socks4(c, c->درون_داد, c->output);
		اكسر;
	حالة 0x05:
		ret = channel_decode_socks5(c, c->درون_داد, c->output);
		اكسر;
	افتراضي:
		debug2_f("channel %d: unknown SOCKS version %u", c->self, ver);
		ret = -1;
		اكسر;
	}
	إذا (ret < 0) {
		chan_mark_dead(ssh, c);
	} وإلا إذا (ret == 0) {
		debug2("channel %d: pre_dynamic: need more", c->self);
		/* need more */
		c->io_want |= SSH_CHAN_IO_RFD;
		إذا (sshbuf_len(c->output))
			c->io_want |= SSH_CHAN_IO_WFD;
	} وإلا {
		/* switch to the next state */
		c->type = SSH_CHANNEL_OPENING;
		پورت_open_helper(ssh, c, "direct-tcpip");
	}
}

/* simulate read-error */
ساكن فراغ
rdynamic_close(بنية ssh *ssh, Channel *c)
{
	c->type = SSH_CHANNEL_OPEN;
	channel_force_close(ssh, c, 0);
}

/* reverse dynamic port forwarding */
ساكن فراغ
channel_before_prepare_io_rdynamic(بنية ssh *ssh, Channel *c)
{
	ثابت u_char *p;
	u_int have, len;
	صحيح r, ret;

	have = sshbuf_len(c->output);
	debug2("channel %d: pre_rdynamic: have %d", c->self, have);
	/* sshbuf_dump(c->output, stderr); */
	/* EOF received */
	إذا (c->flags & CHAN_EOF_RCVD) {
		إذا ((r = sshbuf_consume(c->output, have)) != 0)
			fatal_fr(r, "channel %d: consume", c->self);
		rdynamic_close(ssh, c);
		أرجع;
	}
	/* check if the fixed size part of the packet is in buffer. */
	إذا (have < 3)
		أرجع;
	/* try to guess the protocol */
	p = sshbuf_ptr(c->output);
	بدل (p[0]) {
	حالة 0x04:
		/* switch input/output for reverse forwarding */
		ret = channel_decode_socks4(c, c->output, c->درون_داد);
		اكسر;
	حالة 0x05:
		ret = channel_decode_socks5(c, c->output, c->درون_داد);
		اكسر;
	افتراضي:
		ret = -1;
		اكسر;
	}
	إذا (ret < 0) {
		rdynamic_close(ssh, c);
	} وإلا إذا (ret == 0) {
		debug2("channel %d: pre_rdynamic: need more", c->self);
		/* send socks request to peer */
		len = sshbuf_len(c->درون_داد);
		إذا (len > 0 && len < c->remote_پنجره) {
			إذا ((r = sshpkt_شروع(ssh, SSH2_پیام_CHANNEL_داده)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
			    (r = sshpkt_put_stringb(ssh, c->درون_داد)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0) {
				fatal_fr(r, "channel %i: rdynamic", c->self);
			}
			إذا ((r = sshbuf_consume(c->درون_داد, len)) != 0)
				fatal_fr(r, "channel %d: consume", c->self);
			c->remote_پنجره -= len;
		}
	} وإلا إذا (rdynamic_connect_پایان(ssh, c) < 0) {
		/* the connect failed */
		rdynamic_close(ssh, c);
	}
}

/* This is our fake X11 server socket. */
ساكن فراغ
channel_post_x11_listener(بنية ssh *ssh, Channel *c)
{
	Channel *nc;
	بنية sockaddr_storage addr;
	صحيح r, newsock, oerrno, remote_پورت;
	socklen_t addrlen;
	حرف buf[16384], *remote_ipaddr;

	إذا ((c->io_ready & SSH_CHAN_IO_SOCK_R) == 0)
		أرجع;

	debug("X11 connection requested.");
	addrlen = حجم(addr);
	newsock = accept(c->sock, (بنية sockaddr *)&addr, &addrlen);
	إذا (c->single_connection) {
		oerrno = errno;
		debug2("single_connection: closing X11 listener.");
		channel_close_fd(ssh, c, &c->sock);
		chan_mark_dead(ssh, c);
		errno = oerrno;
	}
	إذا (newsock == -1) {
		إذا (errno != EINTR && errno != EWOULDBLOCK &&
		    errno != ECONNABORTED)
			error("accept: %.100s", strerror(errno));
		إذا (errno == EMFILE || errno == ENFILE)
			c->notbefore = monotime_double() + 1.0;
		أرجع;
	}
	مجموعه_nodelay(newsock);
	إذا (ssh->chanctxt->want_tcp_keepalive)
		مجموعه_keepalive(newsock); /* logs errors */
	remote_ipaddr = get_peer_ipaddr(newsock);
	remote_پورت = get_peer_پورت(newsock);
	snprintf(buf, حجم buf, "X11 connection from %.200s port %d",
	    remote_ipaddr, remote_پورت);

	nc = channel_new(ssh, "x11-connection",
	    SSH_CHANNEL_OPENING, newsock, newsock, -1,
	    c->local_پنجره_max, c->local_maxpacket, 0, buf, 1);
	open_preamble(ssh, __func__, nc, "x11");
	إذا ((r = sshpkt_put_cstring(ssh, remote_ipaddr)) != 0 ||
	    (r = sshpkt_put_u32(ssh, remote_پورت)) != 0) {
		fatal_fr(r, "channel %i: reply", c->self);
	}
	إذا ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i: send", c->self);
	حرر(remote_ipaddr);
}

ساكن فراغ
پورت_open_helper(بنية ssh *ssh, Channel *c, حرف *rtype)
{
	حرف *local_ipaddr = get_local_ipaddr(c->sock);
	صحيح local_پورت = c->sock == -1 ? 65536 : get_local_پورت(c->sock);
	حرف *remote_ipaddr = get_peer_ipaddr(c->sock);
	صحيح remote_پورت = get_peer_پورت(c->sock);
	صحيح r;

	إذا (remote_پورت == -1) {
		/* Fake addr/port to appease peers that validate it (Tectia) */
		حرر(remote_ipaddr);
		remote_ipaddr = xstrdup("127.0.0.1");
		remote_پورت = 65535;
	}

	حرر(c->remote_name);
	xasprintf(&c->remote_name,
	    "%s: listening port %d for %.100s port %d, "
	    "connect from %.200s port %d to %.100s port %d",
	    rtype, c->listening_پورت, c->مسیر, c->host_پورت,
	    remote_ipaddr, remote_پورت, local_ipaddr, local_پورت);

	open_preamble(ssh, __func__, c, rtype);
	إذا (strcmp(rtype, "direct-tcpip") == 0) {
		/* target host, port */
		إذا ((r = sshpkt_put_cstring(ssh, c->مسیر)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->host_پورت)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	} وإلا إذا (strcmp(rtype, "direct-streamlocal@openssh.com") == 0) {
		/* target path */
		إذا ((r = sshpkt_put_cstring(ssh, c->مسیر)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	} وإلا إذا (strcmp(rtype, "forwarded-streamlocal@openssh.com") == 0) {
		/* listen path */
		إذا ((r = sshpkt_put_cstring(ssh, c->مسیر)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	} وإلا {
		/* listen address, port */
		إذا ((r = sshpkt_put_cstring(ssh, c->مسیر)) != 0 ||
		    (r = sshpkt_put_u32(ssh, local_پورت)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	}
	إذا (strcmp(rtype, "forwarded-streamlocal@openssh.com") == 0) {
		/* reserved for future owner/mode info */
		إذا ((r = sshpkt_put_cstring(ssh, "")) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	} وإلا {
		/* originator host and port */
		إذا ((r = sshpkt_put_cstring(ssh, remote_ipaddr)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)remote_پورت)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	}
	إذا ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i: send", c->self);
	حرر(remote_ipaddr);
	حرر(local_ipaddr);
}

فراغ
channel_مجموعه_x11_refuse_زمان(بنية ssh *ssh, مزدوج refuse_زمان)
{
	ssh->chanctxt->x11_refuse_زمان = refuse_زمان;
}

/*
 * This socket is listening for connections to a forwarded TCP/IP port.
 */
ساكن فراغ
channel_post_پورت_listener(بنية ssh *ssh, Channel *c)
{
	Channel *nc;
	بنية sockaddr_storage addr;
	صحيح newsock, nextstate;
	socklen_t addrlen;
	حرف *rtype;

	إذا ((c->io_ready & SSH_CHAN_IO_SOCK_R) == 0)
		أرجع;

	debug("Connection to port %d forwarding to %.100s port %d requested.",
	    c->listening_پورت, c->مسیر, c->host_پورت);

	إذا (c->type == SSH_CHANNEL_RPORT_LISTENER) {
		nextstate = SSH_CHANNEL_OPENING;
		rtype = "forwarded-tcpip";
	} وإلا إذا (c->type == SSH_CHANNEL_RUNIX_LISTENER) {
		nextstate = SSH_CHANNEL_OPENING;
		rtype = "forwarded-streamlocal@openssh.com";
	} وإلا إذا (c->host_پورت == پورت_STREAMLOCAL) {
		nextstate = SSH_CHANNEL_OPENING;
		rtype = "direct-streamlocal@openssh.com";
	} وإلا إذا (c->host_پورت == 0) {
		nextstate = SSH_CHANNEL_DYNAMIC;
		rtype = "dynamic-tcpip";
	} وإلا {
		nextstate = SSH_CHANNEL_OPENING;
		rtype = "direct-tcpip";
	}

	addrlen = حجم(addr);
	newsock = accept(c->sock, (بنية sockaddr *)&addr, &addrlen);
	إذا (newsock == -1) {
		إذا (errno != EINTR && errno != EWOULDBLOCK &&
		    errno != ECONNABORTED)
			error("accept: %.100s", strerror(errno));
		إذا (errno == EMFILE || errno == ENFILE)
			c->notbefore = monotime_double() + 1.0;
		أرجع;
	}
	إذا (addr.ss_family == AF_INET || addr.ss_family == AF_INET6) {
		مجموعه_nodelay(newsock);
		إذا (ssh->chanctxt->want_tcp_keepalive)
			مجموعه_keepalive(newsock); /* logs errors */
	}
	nc = channel_new(ssh, rtype, nextstate, newsock, newsock, -1,
	    c->local_پنجره_max, c->local_maxpacket, 0, rtype, 1);
	nc->listening_پورت = c->listening_پورت;
	nc->host_پورت = c->host_پورت;
	إذا (c->مسیر != عدم)
		nc->مسیر = xstrdup(c->مسیر);

	إذا (nextstate != SSH_CHANNEL_DYNAMIC)
		پورت_open_helper(ssh, nc, rtype);
}

/*
 * This is the authentication agent socket listening for connections from
 * clients.
 */
ساكن فراغ
channel_post_auth_listener(بنية ssh *ssh, Channel *c)
{
	Channel *nc;
	صحيح r, newsock;
	بنية sockaddr_storage addr;
	socklen_t addrlen;

	إذا ((c->io_ready & SSH_CHAN_IO_SOCK_R) == 0)
		أرجع;

	addrlen = حجم(addr);
	newsock = accept(c->sock, (بنية sockaddr *)&addr, &addrlen);
	إذا (newsock == -1) {
		error("accept from auth socket: %.100s", strerror(errno));
		إذا (errno == EMFILE || errno == ENFILE)
			c->notbefore = monotime_double() + 1.0;
		أرجع;
	}
	nc = channel_new(ssh, "agent-connection",
	    SSH_CHANNEL_OPENING, newsock, newsock, -1,
	    c->local_پنجره_max, c->local_maxpacket,
	    0, "accepted auth socket", 1);
	open_preamble(ssh, __func__, nc,
	    c->agent_new ? "agent-connect" : "auth-agent@openssh.com");
	إذا ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i", c->self);
}

ساكن فراغ
channel_post_connecting(بنية ssh *ssh, Channel *c)
{
	صحيح err = 0, sock, isopen, r;
	socklen_t sz = حجم(err);

	إذا ((c->io_ready & SSH_CHAN_IO_SOCK_W) == 0)
		أرجع;
	إذا (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);
	إذا (c->connect_ctx == عدم)
		fatal_f("channel %d: context missing", c->self);

	/* for rdynamic the OPEN_CONFIRMATION has been sent already */
	isopen = (c->type == SSH_CHANNEL_RDYNAMIC_پایان);

	إذا (getsockopt(c->sock, SOL_SOCKET, SO_ERROR, &err, &sz) == -1) {
		err = errno;
		error("getsockopt SO_ERROR failed");
	}

	إذا (err == 0) {
		/* Non-blocking connection completed */
		debug("channel %d: connected to %s port %d",
		    c->self, c->connect_ctx->host, c->connect_ctx->پورت);
		channel_free_connect_ctx(c);
		c->type = SSH_CHANNEL_OPEN;
		channel_مجموعه_استفاده_شده_زمان(ssh, c);
		إذا (isopen) {
			/* no message necessary */
		} وإلا {
			إذا ((r = sshpkt_شروع(ssh,
			    SSH2_پیام_CHANNEL_OPEN_CONFIRMATION)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_پنجره)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "channel %i open confirm", c->self);
		}
		أرجع;
	}
	إذا (err == EINTR || err == EAGAIN || err == EINPROGRESS)
		أرجع;

	/* Non-blocking connection failed */
	debug("channel %d: connection failed: %s", c->self, strerror(err));

	/* Try next address, if any */
	إذا ((sock = connect_بعدی(ssh, c->connect_ctx)) == -1) {
		/* Exhausted all addresses for this destination */
		error("connect_to %.100s port %d: failed.",
		    c->connect_ctx->host, c->connect_ctx->پورت);
		channel_free_connect_ctx(c);
		إذا (isopen) {
			rdynamic_close(ssh, c);
		} وإلا {
			إذا ((r = sshpkt_شروع(ssh,
			    SSH2_پیام_CHANNEL_OPEN_FAILURE)) != 0 ||
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

ساكن صحيح
channel_handle_rfd(بنية ssh *ssh, Channel *c)
{
	حرف buf[CHAN_RBUF];
	ssize_t len;
	صحيح r, force;
	اندازه_t nr = 0, have, avail, maxlen = CHANNEL_MAX_READ;
	صحيح pty_zeroread = 0;

#اگر_تعریف_شده PTY_ZEROREAD
	/* Bug on AIX: read(1) can return 0 for a non-closed fd */
	pty_zeroread = c->isatty;
#پایان_اگر

	force = c->isatty && c->detach_close && c->istate != CHAN_درون_داد_CLOSED;

	إذا (!force && (c->io_ready & SSH_CHAN_IO_RFD) == 0)
		أرجع 1;
	إذا ((avail = sshbuf_avail(c->درون_داد)) == 0)
		أرجع 1; /* Shouldn't happen */

	/*
	 * For "simple" channels (i.e. not datagram or filtered), we can
	 * read directly to the channel buffer.
	 */
	إذا (!pty_zeroread && c->درون_داد_filter == عدم && !c->datagram) {
		/* Only OPEN channels have valid rwin */
		إذا (c->type == SSH_CHANNEL_OPEN) {
			إذا ((have = sshbuf_len(c->درون_داد)) >= c->remote_پنجره)
				أرجع 1; /* shouldn't happen */
			إذا (maxlen > c->remote_پنجره - have)
				maxlen = c->remote_پنجره - have;
		}
		إذا (maxlen > avail)
			maxlen = avail;
		إذا ((r = sshbuf_read(c->rfd, c->درون_داد, maxlen, &nr)) != 0) {
			إذا (errno == EINTR || (!force &&
			    (errno == EAGAIN || errno == EWOULDBLOCK)))
				أرجع 1;
			debug2("channel %d: read failed rfd %d maxlen %zu: %s",
			    c->self, c->rfd, maxlen, ssh_err(r));
			اذهب rfail;
		}
		إذا (nr != 0)
			channel_مجموعه_استفاده_شده_زمان(ssh, c);
		أرجع 1;
	}

	errno = 0;
	len = اقرأ(c->rfd, buf, حجم(buf));
	/* fixup AIX zero-length read with errno set to look more like errors */
	إذا (pty_zeroread && len == 0 && errno != 0)
		len = -1;
	إذا (len == -1 && (errno == EINTR ||
	    ((errno == EAGAIN || errno == EWOULDBLOCK) && !force)))
		أرجع 1;
	إذا (len < 0 || (!pty_zeroread && len == 0)) {
		debug2("channel %d: read<=0 rfd %d len %zd: %s",
		    c->self, c->rfd, len,
		    len == 0 ? "closed" : strerror(errno));
 rfail:
		إذا (c->type != SSH_CHANNEL_OPEN) {
			debug2("channel %d: not open", c->self);
			chan_mark_dead(ssh, c);
			أرجع -1;
		} وإلا {
			chan_read_failed(ssh, c);
		}
		أرجع -1;
	}
	channel_مجموعه_استفاده_شده_زمان(ssh, c);
	إذا (c->درون_داد_filter != عدم) {
		إذا (c->درون_داد_filter(ssh, c, buf, len) == -1) {
			debug2("channel %d: filter stops", c->self);
			chan_read_failed(ssh, c);
		}
	} وإلا إذا (c->datagram) {
		إذا ((r = sshbuf_put_string(c->درون_داد, buf, len)) != 0)
			fatal_fr(r, "channel %i: put datagram", c->self);
	} وإلا إذا ((r = sshbuf_put(c->درون_داد, buf, len)) != 0)
		fatal_fr(r, "channel %i: put data", c->self);

	أرجع 1;
}

ساكن صحيح
channel_handle_wfd(بنية ssh *ssh, Channel *c)
{
	بنية termios tio;
	u_char *داده = عدم, *buf; /* XXX const; need filter API change */
	اندازه_t dlen, olen = 0;
	صحيح r, len;

	إذا ((c->io_ready & SSH_CHAN_IO_WFD) == 0)
		أرجع 1;
	إذا (sshbuf_len(c->output) == 0)
		أرجع 1;

	/* Send buffered output data to the socket. */
	olen = sshbuf_len(c->output);
	إذا (c->output_filter != عدم) {
		إذا ((buf = c->output_filter(ssh, c, &داده, &dlen)) == عدم) {
			debug2("channel %d: filter stops", c->self);
			إذا (c->type != SSH_CHANNEL_OPEN)
				chan_mark_dead(ssh, c);
			وإلا
				chan_write_failed(ssh, c);
			أرجع -1;
		}
	} وإلا إذا (c->datagram) {
		إذا ((r = sshbuf_get_string(c->output, &داده, &dlen)) != 0)
			fatal_fr(r, "channel %i: get datagram", c->self);
		buf = داده;
	} وإلا {
		buf = داده = sshbuf_mutable_ptr(c->output);
		dlen = sshbuf_len(c->output);
	}

	إذا (c->datagram) {
		/* ignore truncated writes, datagrams might get lost */
		len = اكتب(c->wfd, buf, dlen);
		حرر(داده);
		إذا (len == -1 && (errno == EINTR || errno == EAGAIN ||
		    errno == EWOULDBLOCK))
			أرجع 1;
		إذا (len <= 0)
			اذهب write_fail;
		اذهب بیرون;
	}

#اگر_تعریف_شده _AIX
	/* XXX: Later AIX versions can't push as much data to tty */
	إذا (c->wfd_isatty)
		dlen = MINIMUM(dlen, 8*1024);
#پایان_اگر

	len = اكتب(c->wfd, buf, dlen);
	إذا (len == -1 &&
	    (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
		أرجع 1;
	إذا (len <= 0) {
 write_fail:
		إذا (c->type != SSH_CHANNEL_OPEN) {
			debug2("channel %d: not open", c->self);
			chan_mark_dead(ssh, c);
			أرجع -1;
		} وإلا {
			chan_write_failed(ssh, c);
		}
		أرجع -1;
	}
	channel_مجموعه_استفاده_شده_زمان(ssh, c);
#اگر_تعریف_نشده BROKEN_TCGETATTR_ICANON
	إذا (c->isatty && dlen >= 1 && buf[0] != '\r') {
		إذا (tcgetattr(c->wfd, &tio) == 0 &&
		    !(tio.c_lflag & ECHO) && (tio.c_lflag & ICANON)) {
			/*
			 * Simulate echo to reduce the impact of
			 * traffic analysis. We need to match the
			 * size of a SSH2_MSG_CHANNEL_DATA message
			 * (4 byte channel id + buf)
			 */
			إذا ((r = sshpkt_پیام_ignore(ssh, 4+len)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "channel %i: ignore", c->self);
		}
	}
#پایان_اگر /* BROKEN_TCGETATTR_ICANON */
	إذا ((r = sshbuf_consume(c->output, len)) != 0)
		fatal_fr(r, "channel %i: consume", c->self);
 بیرون:
	c->local_consumed += olen - sshbuf_len(c->output);

	أرجع 1;
}

ساكن صحيح
channel_handle_efd_write(بنية ssh *ssh, Channel *c)
{
	صحيح r;
	ssize_t len;

	إذا ((c->io_ready & SSH_CHAN_IO_EFD_W) == 0)
		أرجع 1;
	إذا (sshbuf_len(c->extended) == 0)
		أرجع 1;

	len = اكتب(c->efd, sshbuf_ptr(c->extended),
	    sshbuf_len(c->extended));
	debug2("channel %d: written %zd to efd %d", c->self, len, c->efd);
	إذا (len == -1 && (errno == EINTR || errno == EAGAIN ||
	    errno == EWOULDBLOCK))
		أرجع 1;
	إذا (len <= 0) {
		debug2("channel %d: closing write-efd %d", c->self, c->efd);
		channel_close_fd(ssh, c, &c->efd);
	} وإلا {
		إذا ((r = sshbuf_consume(c->extended, len)) != 0)
			fatal_fr(r, "channel %i: consume", c->self);
		c->local_consumed += len;
		channel_مجموعه_استفاده_شده_زمان(ssh, c);
	}
	أرجع 1;
}

ساكن صحيح
channel_handle_efd_read(بنية ssh *ssh, Channel *c)
{
	حرف buf[CHAN_RBUF];
	ssize_t len;
	صحيح r, force;

	force = c->isatty && c->detach_close && c->istate != CHAN_درون_داد_CLOSED;

	إذا (!force && (c->io_ready & SSH_CHAN_IO_EFD_R) == 0)
		أرجع 1;

	len = اقرأ(c->efd, buf, حجم(buf));
	debug2("channel %d: read %zd from efd %d", c->self, len, c->efd);
	إذا (len == -1 && (errno == EINTR || ((errno == EAGAIN ||
	    errno == EWOULDBLOCK) && !force)))
		أرجع 1;
	إذا (len <= 0) {
		debug2("channel %d: closing read-efd %d", c->self, c->efd);
		channel_close_fd(ssh, c, &c->efd);
		أرجع 1;
	}
	channel_مجموعه_استفاده_شده_زمان(ssh, c);
	إذا (c->extended_usage == CHAN_EXTENDED_IGNORE)
		debug3("channel %d: discard efd", c->self);
	وإلا إذا ((r = sshbuf_put(c->extended, buf, len)) != 0)
		fatal_fr(r, "channel %i: append", c->self);
	أرجع 1;
}

ساكن صحيح
channel_handle_efd(بنية ssh *ssh, Channel *c)
{
	إذا (c->efd == -1)
		أرجع 1;

	/** XXX handle drain efd, too */

	إذا (c->extended_usage == CHAN_EXTENDED_WRITE)
		أرجع channel_handle_efd_write(ssh, c);
	وإلا إذا (c->extended_usage == CHAN_EXTENDED_READ ||
	    c->extended_usage == CHAN_EXTENDED_IGNORE)
		أرجع channel_handle_efd_read(ssh, c);

	أرجع 1;
}

ساكن صحيح
channel_check_پنجره(بنية ssh *ssh, Channel *c)
{
	صحيح r;

	إذا (c->type == SSH_CHANNEL_OPEN &&
	    !(c->flags & (CHAN_CLOSE_فرستاده|CHAN_CLOSE_RCVD)) &&
	    ((c->local_پنجره_max - c->local_پنجره >
	    c->local_maxpacket*3) ||
	    c->local_پنجره < c->local_پنجره_max/2) &&
	    c->local_consumed > 0) {
		إذا (!c->have_remote_id)
			fatal_f("channel %d: no remote id", c->self);
		إذا ((r = sshpkt_شروع(ssh,
		    SSH2_پیام_CHANNEL_پنجره_ADJUST)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->local_consumed)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0) {
			fatal_fr(r, "channel %i", c->self);
		}
		debug2("channel %d: window %d sent adjust %d", c->self,
		    c->local_پنجره, c->local_consumed);
		c->local_پنجره += c->local_consumed;
		c->local_consumed = 0;
	}
	أرجع 1;
}

ساكن فراغ
channel_post_open(بنية ssh *ssh, Channel *c)
{
	channel_handle_rfd(ssh, c);
	channel_handle_wfd(ssh, c);
	channel_handle_efd(ssh, c);
	channel_check_پنجره(ssh, c);
}

ساكن u_int
read_mux(بنية ssh *ssh, Channel *c, u_int need)
{
	حرف buf[CHAN_RBUF];
	ssize_t len;
	u_int rlen;
	صحيح r;

	إذا (sshbuf_len(c->درون_داد) < need) {
		rlen = need - sshbuf_len(c->درون_داد);
		len = اقرأ(c->rfd, buf, MINIMUM(rlen, CHAN_RBUF));
		إذا (len == -1 && (errno == EINTR || errno == EAGAIN))
			أرجع sshbuf_len(c->درون_داد);
		إذا (len <= 0) {
			debug2("channel %d: ctl read<=0 rfd %d len %zd",
			    c->self, c->rfd, len);
			chan_read_failed(ssh, c);
			أرجع 0;
		} وإلا إذا ((r = sshbuf_put(c->درون_داد, buf, len)) != 0)
			fatal_fr(r, "channel %i: append", c->self);
	}
	أرجع sshbuf_len(c->درون_داد);
}

ساكن فراغ
channel_post_mux_client_read(بنية ssh *ssh, Channel *c)
{
	u_int need;

	إذا ((c->io_ready & SSH_CHAN_IO_RFD) == 0)
		أرجع;
	إذا (c->istate != CHAN_درون_داد_OPEN && c->istate != CHAN_درون_داد_WAIT_DRAIN)
		أرجع;
	إذا (c->mux_pause)
		أرجع;

	/*
	 * Don't not read past the precise end of packets to
	 * avoid disrupting fd passing.
	 */
	إذا (read_mux(ssh, c, 4) < 4) /* read header */
		أرجع;
	/* XXX sshbuf_peek_u32 */
	need = PEEK_U32(sshbuf_ptr(c->درون_داد));
#تعریف_کن CHANNEL_MUX_MAX_PACKET	(256 * 1024)
	إذا (need > CHANNEL_MUX_MAX_PACKET) {
		debug2("channel %d: packet too big %u > %u",
		    c->self, CHANNEL_MUX_MAX_PACKET, need);
		chan_rcvd_oclose(ssh, c);
		أرجع;
	}
	إذا (read_mux(ssh, c, need + 4) < need + 4) /* read body */
		أرجع;
	إذا (c->mux_rcb(ssh, c) != 0) {
		debug("channel %d: mux_rcb failed", c->self);
		chan_mark_dead(ssh, c);
		أرجع;
	}
}

ساكن فراغ
channel_post_mux_client_write(بنية ssh *ssh, Channel *c)
{
	ssize_t len;
	صحيح r;

	إذا ((c->io_ready & SSH_CHAN_IO_WFD) == 0)
		أرجع;
	إذا (sshbuf_len(c->output) == 0)
		أرجع;

	len = اكتب(c->wfd, sshbuf_ptr(c->output), sshbuf_len(c->output));
	إذا (len == -1 && (errno == EINTR || errno == EAGAIN))
		أرجع;
	إذا (len <= 0) {
		chan_mark_dead(ssh, c);
		أرجع;
	}
	إذا ((r = sshbuf_consume(c->output, len)) != 0)
		fatal_fr(r, "channel %i: consume", c->self);
}

ساكن فراغ
channel_post_mux_client(بنية ssh *ssh, Channel *c)
{
	channel_post_mux_client_read(ssh, c);
	channel_post_mux_client_write(ssh, c);
}

ساكن فراغ
channel_post_mux_listener(بنية ssh *ssh, Channel *c)
{
	Channel *nc;
	بنية sockaddr_storage addr;
	socklen_t addrlen;
	صحيح newsock;
	uid_t euid;
	gid_t egid;

	إذا ((c->io_ready & SSH_CHAN_IO_SOCK_R) == 0)
		أرجع;

	debug("multiplexing control connection");

	/*
	 * Accept connection on control socket
	 */
	memset(&addr, 0, حجم(addr));
	addrlen = حجم(addr);
	إذا ((newsock = accept(c->sock, (بنية sockaddr*)&addr,
	    &addrlen)) == -1) {
		error_f("accept: %s", strerror(errno));
		إذا (errno == EMFILE || errno == ENFILE)
			c->notbefore = monotime_double() + 1.0;
		أرجع;
	}

	إذا (getpeereid(newsock, &euid, &egid) == -1) {
		error_f("getpeereid failed: %s", strerror(errno));
		close(newsock);
		أرجع;
	}
	إذا ((euid != 0) && (getuid() != euid)) {
		error("multiplex uid mismatch: peer euid %u != uid %u",
		    (u_int)euid, (u_int)getuid());
		close(newsock);
		أرجع;
	}
	nc = channel_new(ssh, "mux-control", SSH_CHANNEL_MUX_CLIENT,
	    newsock, newsock, -1, c->local_پنجره_max,
	    c->local_maxpacket, 0, "mux-control", 1);
	nc->mux_rcb = c->mux_rcb;
	debug3_f("new mux channel %d fd %d", nc->self, nc->sock);
	/* establish state */
	nc->mux_rcb(ssh, nc);
	/* mux state transitions must not elicit protocol messages */
	nc->flags |= CHAN_LOCAL;
}

ساكن فراغ
channel_handler_init(بنية ssh_channels *sc)
{
	chan_fn **pre, **post;

	إذا ((pre = حافظه_صفر_بده(SSH_CHANNEL_MAX_TYPE, حجم(*pre))) == عدم ||
	    (post = حافظه_صفر_بده(SSH_CHANNEL_MAX_TYPE, حجم(*post))) == عدم)
		fatal_f("allocation failed");

	pre[SSH_CHANNEL_OPEN] =			&channel_pre_open;
	pre[SSH_CHANNEL_X11_OPEN] =		&channel_pre_x11_open;
	pre[SSH_CHANNEL_پورت_LISTENER] =	&channel_pre_listener;
	pre[SSH_CHANNEL_RPORT_LISTENER] =	&channel_pre_listener;
	pre[SSH_CHANNEL_UNIX_LISTENER] =	&channel_pre_listener;
	pre[SSH_CHANNEL_RUNIX_LISTENER] =	&channel_pre_listener;
	pre[SSH_CHANNEL_X11_LISTENER] =		&channel_pre_listener;
	pre[SSH_CHANNEL_AUTH_SOCKET] =		&channel_pre_listener;
	pre[SSH_CHANNEL_CONNECTING] =		&channel_pre_connecting;
	pre[SSH_CHANNEL_DYNAMIC] =		&channel_pre_dynamic;
	pre[SSH_CHANNEL_RDYNAMIC_پایان] =	&channel_pre_connecting;
	pre[SSH_CHANNEL_MUX_LISTENER] =		&channel_pre_listener;
	pre[SSH_CHANNEL_MUX_CLIENT] =		&channel_pre_mux_client;

	post[SSH_CHANNEL_OPEN] =		&channel_post_open;
	post[SSH_CHANNEL_پورت_LISTENER] =	&channel_post_پورت_listener;
	post[SSH_CHANNEL_RPORT_LISTENER] =	&channel_post_پورت_listener;
	post[SSH_CHANNEL_UNIX_LISTENER] =	&channel_post_پورت_listener;
	post[SSH_CHANNEL_RUNIX_LISTENER] =	&channel_post_پورت_listener;
	post[SSH_CHANNEL_X11_LISTENER] =	&channel_post_x11_listener;
	post[SSH_CHANNEL_AUTH_SOCKET] =		&channel_post_auth_listener;
	post[SSH_CHANNEL_CONNECTING] =		&channel_post_connecting;
	post[SSH_CHANNEL_DYNAMIC] =		&channel_post_open;
	post[SSH_CHANNEL_RDYNAMIC_پایان] =	&channel_post_connecting;
	post[SSH_CHANNEL_MUX_LISTENER] =	&channel_post_mux_listener;
	post[SSH_CHANNEL_MUX_CLIENT] =		&channel_post_mux_client;

	sc->channel_pre = pre;
	sc->channel_post = post;
}

/* gc dead channels */
ساكن فراغ
channel_garbage_collect(بنية ssh *ssh, Channel *c)
{
	إذا (c == عدم)
		أرجع;
	إذا (c->detach_user != عدم) {
		إذا (!chan_is_dead(ssh, c, c->detach_close))
			أرجع;

		debug2("channel %d: gc: notify user", c->self);
		c->detach_user(ssh, c->self, 0, عدم);
		/* if we still have a callback */
		إذا (c->detach_user != عدم)
			أرجع;
		debug2("channel %d: gc: user detached", c->self);
	}
	إذا (!chan_is_dead(ssh, c, 1))
		أرجع;
	debug2("channel %d: garbage collecting", c->self);
	channel_free(ssh, c);
}

تعداد channel_جدول { CHAN_PRE, CHAN_POST };

ساكن فراغ
channel_handler(بنية ssh *ssh, صحيح جدول, بنية timespec *timeout)
{
	بنية ssh_channels *sc = ssh->chanctxt;
	chan_fn **ftab = جدول == CHAN_PRE ? sc->channel_pre : sc->channel_post;
	u_int i, oalloc;
	Channel *c;
	مزدوج now;

	now = monotime_double();
	لكل (sc->nbulk = i = 0, oalloc = sc->channels_alloc; i < oalloc; i++) {
		c = sc->channels[i];
		إذا (c == عدم)
			استمر;
		/* Count open channels in bulk state */
		إذا (c->type == SSH_CHANNEL_OPEN && c->bulk)
			sc->nbulk++;
		/* Try to keep IO going while rekeying */
		إذا (ssh_packet_is_rekeying(ssh) && c->type != SSH_CHANNEL_OPEN)
			استمر;
		إذا (c->delayed) {
			إذا (جدول == CHAN_PRE)
				c->delayed = 0;
			وإلا
				استمر;
		}
		إذا (ftab[c->type] != عدم) {
			إذا (جدول == CHAN_PRE && c->type == SSH_CHANNEL_OPEN &&
			    channel_get_expiry(ssh, c) != 0 &&
			    now >= channel_get_expiry(ssh, c)) {
				/* channel closed for inactivity */
				مزدوج deadline = c->inactive_deadline != 0.0 ?
				    c->inactive_deadline : sc->global_deadline;
				verbose("channel %d: closing after %f seconds "
				    "of inactivity", c->self, deadline);
				channel_force_close(ssh, c, 1);
			} وإلا إذا (c->notbefore <= now) {
				/* Run handlers that are not paused. */
				(*ftab[c->type])(ssh, c);
				/* inactivity timeouts must interrupt poll() */
				إذا (timeout != عدم &&
				    c->type == SSH_CHANNEL_OPEN &&
				    channel_get_expiry(ssh, c) != 0) {
					ptimeout_deadline_monotime_double(timeout,
					    channel_get_expiry(ssh, c));
				}
			} وإلا إذا (timeout != عدم) {
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
ساكن فراغ
channel_before_prepare_io(بنية ssh *ssh)
{
	بنية ssh_channels *sc = ssh->chanctxt;
	Channel *c;
	u_int i, oalloc;

	لكل (i = 0, oalloc = sc->channels_alloc; i < oalloc; i++) {
		c = sc->channels[i];
		إذا (c == عدم)
			استمر;
		إذا (c->type == SSH_CHANNEL_RDYNAMIC_OPEN)
			channel_before_prepare_io_rdynamic(ssh, c);
	}
}

ساكن فراغ
dump_channel_poll(ثابت حرف *func, ثابت حرف *what, Channel *c,
    u_int pollfd_جابه_جایی, بنية pollfd *pfd)
{
#اگر_تعریف_شده DEBUG_CHANNEL_POLL
	debug3("%s: channel %d: %s r%d w%d e%d s%d c->pfds [ %d %d %d %d ] "
	    "io_want 0x%02x io_ready 0x%02x pfd[%u].fd=%d "
	    "pfd.ev 0x%02x pfd.rev 0x%02x", func, c->self, what,
	    c->rfd, c->wfd, c->efd, c->sock,
	    c->pfds[0], c->pfds[1], c->pfds[2], c->pfds[3],
	    c->io_want, c->io_ready,
	    pollfd_جابه_جایی, pfd->fd, pfd->events, pfd->revents);
#پایان_اگر
}

/* Prepare pollfd entries for a single channel */
ساكن فراغ
channel_prepare_pollfd(Channel *c, u_int *بعدی_pollfd,
    بنية pollfd *pfd, u_int npfd)
{
	u_int ev, p = *بعدی_pollfd;

	إذا (c == عدم)
		أرجع;
	إذا (p + 4 > npfd) {
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
	إذا (c->rfd != -1) {
		ev = 0;
		إذا ((c->io_want & SSH_CHAN_IO_RFD) != 0)
			ev |= POLLIN;
		/* rfd == wfd */
		إذا (c->wfd == c->rfd) {
			إذا ((c->io_want & SSH_CHAN_IO_WFD) != 0)
				ev |= POLLOUT;
		}
		/* rfd == efd */
		إذا (c->efd == c->rfd) {
			إذا ((c->io_want & SSH_CHAN_IO_EFD_R) != 0)
				ev |= POLLIN;
			إذا ((c->io_want & SSH_CHAN_IO_EFD_W) != 0)
				ev |= POLLOUT;
		}
		/* rfd == sock */
		إذا (c->sock == c->rfd) {
			إذا ((c->io_want & SSH_CHAN_IO_SOCK_R) != 0)
				ev |= POLLIN;
			إذا ((c->io_want & SSH_CHAN_IO_SOCK_W) != 0)
				ev |= POLLOUT;
		}
		/* Pack a pfd entry if any event armed for this fd */
		إذا (ev != 0) {
			c->pfds[0] = p;
			pfd[p].fd = c->rfd;
			pfd[p].events = ev;
			dump_channel_poll(__func__, "rfd", c, p, &pfd[p]);
			p++;
		}
	}
	/* prepare c->wfd if wanting IO and not already handled above */
	إذا (c->wfd != -1 && c->rfd != c->wfd) {
		ev = 0;
		إذا ((c->io_want & SSH_CHAN_IO_WFD))
			ev |= POLLOUT;
		/* Pack a pfd entry if any event armed for this fd */
		إذا (ev != 0) {
			c->pfds[1] = p;
			pfd[p].fd = c->wfd;
			pfd[p].events = ev;
			dump_channel_poll(__func__, "wfd", c, p, &pfd[p]);
			p++;
		}
	}
	/* prepare c->efd if wanting IO and not already handled above */
	إذا (c->efd != -1 && c->rfd != c->efd) {
		ev = 0;
		إذا ((c->io_want & SSH_CHAN_IO_EFD_R) != 0)
			ev |= POLLIN;
		إذا ((c->io_want & SSH_CHAN_IO_EFD_W) != 0)
			ev |= POLLOUT;
		/* Pack a pfd entry if any event armed for this fd */
		إذا (ev != 0) {
			c->pfds[2] = p;
			pfd[p].fd = c->efd;
			pfd[p].events = ev;
			dump_channel_poll(__func__, "efd", c, p, &pfd[p]);
			p++;
		}
	}
	/* prepare c->sock if wanting IO and not already handled above */
	إذا (c->sock != -1 && c->rfd != c->sock) {
		ev = 0;
		إذا ((c->io_want & SSH_CHAN_IO_SOCK_R) != 0)
			ev |= POLLIN;
		إذا ((c->io_want & SSH_CHAN_IO_SOCK_W) != 0)
			ev |= POLLOUT;
		/* Pack a pfd entry if any event armed for this fd */
		إذا (ev != 0) {
			c->pfds[3] = p;
			pfd[p].fd = c->sock;
			pfd[p].events = ev;
			dump_channel_poll(__func__, "sock", c, p, &pfd[p]);
			p++;
		}
	}
	*بعدی_pollfd = p;
}

/* * Allocate/prepare poll structure */
فراغ
channel_prepare_poll(بنية ssh *ssh, بنية pollfd **pfdp, u_int *npfd_allocp,
    u_int *npfd_activep, u_int npfd_reserved, بنية timespec *timeout)
{
	بنية ssh_channels *sc = ssh->chanctxt;
	u_int i, oalloc, p, npfd = npfd_reserved;

	channel_before_prepare_io(ssh); /* might create a new channel */
	/* clear out I/O flags from last poll */
	لكل (i = 0; i < sc->channels_alloc; i++) {
		إذا (sc->channels[i] == عدم)
			استمر;
		sc->channels[i]->io_want = sc->channels[i]->io_ready = 0;
	}
	/* Allocate 4x pollfd for each channel (rfd, wfd, efd, sock) */
	إذا (sc->channels_alloc >= (بیشترین_صحیح / 4) - npfd_reserved)
		fatal_f("too many channels"); /* shouldn't happen */
	npfd += sc->channels_alloc * 4;
	إذا (npfd > *npfd_allocp) {
		*pfdp = xrecallocarray(*pfdp, *npfd_allocp,
		    npfd, حجم(**pfdp));
		*npfd_allocp = npfd;
	}
	*npfd_activep = npfd_reserved;
	oalloc = sc->channels_alloc;

	channel_handler(ssh, CHAN_PRE, timeout);

	إذا (oalloc != sc->channels_alloc) {
		/* shouldn't happen */
		fatal_f("channels_alloc changed during CHAN_PRE "
		    "(was %u, now %u)", oalloc, sc->channels_alloc);
	}

	/* Prepare pollfd */
	p = npfd_reserved;
	لكل (i = 0; i < sc->channels_alloc; i++)
		channel_prepare_pollfd(sc->channels[i], &p, *pfdp, npfd);
	*npfd_activep = p;
}

ساكن فراغ
fd_ready(Channel *c, صحيح p, بنية pollfd *pfds, u_int npfd, صحيح fd,
    ثابت حرف *what, u_int revents_ماسک, u_int ready)
{
	بنية pollfd *pfd = &pfds[p];

	إذا (fd == -1)
		أرجع;
	إذا (p == -1 || (u_int)p >= npfd)
		fatal_f("channel %d: bad pfd %d (max %u)", c->self, p, npfd);
	dump_channel_poll(__func__, what, c, p, pfd);
	إذا (pfd->fd != fd) {
		fatal("channel %d: inconsistent %s fd=%d pollfd[%u].fd %d "
		    "r%d w%d e%d s%d", c->self, what, fd, p, pfd->fd,
		    c->rfd, c->wfd, c->efd, c->sock);
	}
	إذا ((pfd->revents & POLLNVAL) != 0) {
		fatal("channel %d: invalid %s pollfd[%u].fd %d r%d w%d e%d s%d",
		    c->self, what, p, pfd->fd, c->rfd, c->wfd, c->efd, c->sock);
	}
	إذا ((pfd->revents & (revents_ماسک|POLLHUP|POLLERR)) != 0)
		c->io_ready |= ready & c->io_want;
}

/*
 * After poll, perform any appropriate operations for channels which have
 * events pending.
 */
فراغ
channel_after_poll(بنية ssh *ssh, بنية pollfd *pfd, u_int npfd)
{
	بنية ssh_channels *sc = ssh->chanctxt;
	u_int i;
	صحيح p;
	Channel *c;

#اگر_تعریف_شده DEBUG_CHANNEL_POLL
	لكل (p = 0; p < (صحيح)npfd; p++) {
		إذا (pfd[p].revents == 0)
			استمر;
		debug_f("pfd[%u].fd %d rev 0x%04x",
		    p, pfd[p].fd, pfd[p].revents);
	}
#پایان_اگر

	/* Convert pollfd into c->io_ready */
	لكل (i = 0; i < sc->channels_alloc; i++) {
		c = sc->channels[i];
		إذا (c == عدم)
			استمر;
		/* if rfd is shared with efd/sock then wfd should be too */
		إذا (c->rfd != -1 && c->wfd != -1 && c->rfd != c->wfd &&
		    (c->rfd == c->efd || c->rfd == c->sock)) {
			/* Shouldn't happen */
			fatal_f("channel %d: unexpected fds r%d w%d e%d s%d",
			    c->self, c->rfd, c->wfd, c->efd, c->sock);
		}
		c->io_ready = 0;
		/* rfd, potentially shared with wfd, efd and sock */
		إذا (c->rfd != -1 && (p = c->pfds[0]) != -1) {
			fd_ready(c, p, pfd, npfd, c->rfd,
			    "rfd", POLLIN, SSH_CHAN_IO_RFD);
			إذا (c->rfd == c->wfd) {
				fd_ready(c, p, pfd, npfd, c->wfd,
				    "wfd/r", POLLOUT, SSH_CHAN_IO_WFD);
			}
			إذا (c->rfd == c->efd) {
				fd_ready(c, p, pfd, npfd, c->efd,
				    "efdr/r", POLLIN, SSH_CHAN_IO_EFD_R);
				fd_ready(c, p, pfd, npfd, c->efd,
				    "efdw/r", POLLOUT, SSH_CHAN_IO_EFD_W);
			}
			إذا (c->rfd == c->sock) {
				fd_ready(c, p, pfd, npfd, c->sock,
				    "sockr/r", POLLIN, SSH_CHAN_IO_SOCK_R);
				fd_ready(c, p, pfd, npfd, c->sock,
				    "sockw/r", POLLOUT, SSH_CHAN_IO_SOCK_W);
			}
			dump_channel_poll(__func__, "rfd", c, p, pfd);
		}
		/* wfd */
		إذا (c->wfd != -1 && c->wfd != c->rfd &&
		    (p = c->pfds[1]) != -1) {
			fd_ready(c, p, pfd, npfd, c->wfd,
			    "wfd", POLLOUT, SSH_CHAN_IO_WFD);
			dump_channel_poll(__func__, "wfd", c, p, pfd);
		}
		/* efd */
		إذا (c->efd != -1 && c->efd != c->rfd &&
		    (p = c->pfds[2]) != -1) {
			fd_ready(c, p, pfd, npfd, c->efd,
			    "efdr", POLLIN, SSH_CHAN_IO_EFD_R);
			fd_ready(c, p, pfd, npfd, c->efd,
			    "efdw", POLLOUT, SSH_CHAN_IO_EFD_W);
			dump_channel_poll(__func__, "efd", c, p, pfd);
		}
		/* sock */
		إذا (c->sock != -1 && c->sock != c->rfd &&
		    (p = c->pfds[3]) != -1) {
			fd_ready(c, p, pfd, npfd, c->sock,
			    "sockr", POLLIN, SSH_CHAN_IO_SOCK_R);
			fd_ready(c, p, pfd, npfd, c->sock,
			    "sockw", POLLOUT, SSH_CHAN_IO_SOCK_W);
			dump_channel_poll(__func__, "sock", c, p, pfd);
		}
	}
	channel_handler(ssh, CHAN_POST, عدم);
}

/*
 * Enqueue data for channels with open or draining c->input.
 * Returns non-zero if a packet was enqueued.
 */
ساكن صحيح
channel_output_poll_درون_داد_open(بنية ssh *ssh, Channel *c)
{
	اندازه_t len, plen;
	ثابت u_char *pkt;
	صحيح r;

	إذا ((len = sshbuf_len(c->درون_داد)) == 0) {
		إذا (c->istate == CHAN_درون_داد_WAIT_DRAIN) {
			/*
			 * input-buffer is empty and read-socket shutdown:
			 * tell peer, that we will not send more data:
			 * send IEOF.
			 * hack for extended data: delay EOF if EFD still
			 * in use.
			 */
			إذا (CHANNEL_EFD_درون_داد_فعال(c))
				debug2("channel %d: "
				    "ibuf_empty delayed efd %d/(%zu)",
				    c->self, c->efd, sshbuf_len(c->extended));
			وإلا
				chan_ibuf_خالی(ssh, c);
		}
		أرجع 0;
	}

	إذا (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);

	إذا (c->datagram) {
		/* Check datagram will fit; drop if not */
		إذا ((r = sshbuf_get_string_مستقیم(c->درون_داد, &pkt, &plen)) != 0)
			fatal_fr(r, "channel %i: get datagram", c->self);
		/*
		 * XXX this does tail-drop on the datagram queue which is
		 * usually suboptimal compared to head-drop. Better to have
		 * backpressure at read time? (i.e. read + discard)
		 */
		إذا (plen > c->remote_پنجره || plen > c->remote_maxpacket) {
			debug("channel %d: datagram too big", c->self);
			أرجع 0;
		}
		/* Enqueue it */
		إذا ((r = sshpkt_شروع(ssh, SSH2_پیام_CHANNEL_داده)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
		    (r = sshpkt_put_string(ssh, pkt, plen)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "channel %i: send datagram", c->self);
		c->remote_پنجره -= plen;
		أرجع 1;
	}

	/* Enqueue packet for buffered data. */
	إذا (len > c->remote_پنجره)
		len = c->remote_پنجره;
	إذا (len > c->remote_maxpacket)
		len = c->remote_maxpacket;
	إذا (len == 0)
		أرجع 0;
	إذا ((r = sshpkt_شروع(ssh, SSH2_پیام_CHANNEL_داده)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_string(ssh, sshbuf_ptr(c->درون_داد), len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i: send data", c->self);
	إذا ((r = sshbuf_consume(c->درون_داد, len)) != 0)
		fatal_fr(r, "channel %i: consume", c->self);
	c->remote_پنجره -= len;
	أرجع 1;
}

/*
 * Enqueue data for channels with open c->extended in read mode.
 * Returns non-zero if a packet was enqueued.
 */
ساكن صحيح
channel_output_poll_extended_read(بنية ssh *ssh, Channel *c)
{
	اندازه_t len;
	صحيح r;

	إذا ((len = sshbuf_len(c->extended)) == 0)
		أرجع 0;

	debug2("channel %d: rwin %u elen %zu euse %d", c->self,
	    c->remote_پنجره, sshbuf_len(c->extended), c->extended_usage);
	إذا (len > c->remote_پنجره)
		len = c->remote_پنجره;
	إذا (len > c->remote_maxpacket)
		len = c->remote_maxpacket;
	إذا (len == 0)
		أرجع 0;
	إذا (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);
	إذا ((r = sshpkt_شروع(ssh, SSH2_پیام_CHANNEL_EXTENDED_داده)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_u32(ssh, SSH2_EXTENDED_داده_STDERR)) != 0 ||
	    (r = sshpkt_put_string(ssh, sshbuf_ptr(c->extended), len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i: data", c->self);
	إذا ((r = sshbuf_consume(c->extended, len)) != 0)
		fatal_fr(r, "channel %i: consume", c->self);
	c->remote_پنجره -= len;
	debug2("channel %d: sent ext data %zu", c->self, len);
	أرجع 1;
}

/*
 * If there is data to send to the connection, enqueue some of it now.
 * Returns non-zero if data was enqueued.
 */
صحيح
channel_output_poll(بنية ssh *ssh)
{
	بنية ssh_channels *sc = ssh->chanctxt;
	Channel *c;
	u_int i;
	صحيح ret = 0;

	لكل (i = 0; i < sc->channels_alloc; i++) {
		c = sc->channels[i];
		إذا (c == عدم)
			استمر;

		/*
		 * We are only interested in channels that can have buffered
		 * incoming data.
		 */
		إذا (c->type != SSH_CHANNEL_OPEN)
			استمر;
		إذا ((c->flags & (CHAN_CLOSE_فرستاده|CHAN_CLOSE_RCVD))) {
			/* XXX is this true? */
			debug3("channel %d: will not send data after close",
			    c->self);
			استمر;
		}

		/* Get the amount of buffered data for this channel. */
		إذا (c->istate == CHAN_درون_داد_OPEN ||
		    c->istate == CHAN_درون_داد_WAIT_DRAIN)
			ret |= channel_output_poll_درون_داد_open(ssh, c);
		/* Send extended data, i.e. stderr */
		إذا (!(c->flags & CHAN_EOF_فرستاده) &&
		    c->extended_usage == CHAN_EXTENDED_READ)
			ret |= channel_output_poll_extended_read(ssh, c);
	}
	أرجع ret;
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
صحيح
channel_proxy_downstream(بنية ssh *ssh, Channel *downstream)
{
	Channel *c = عدم;
	بنية sshbuf *original = عدم, *modified = عدم;
	ثابت u_char *cp;
	حرف *ctype = عدم, *listen_host = عدم;
	u_char type;
	اندازه_t have;
	صحيح ret = -1, r;
	u_int id, remote_id, listen_پورت;

	/* sshbuf_dump(downstream->input, stderr); */
	إذا ((r = sshbuf_get_string_مستقیم(downstream->درون_داد, &cp, &have))
	    != 0) {
		error_fr(r, "parse");
		أرجع -1;
	}
	إذا (have < 2) {
		error_f("short message");
		أرجع -1;
	}
	type = cp[1];
	/* skip padlen + type */
	cp += 2;
	have -= 2;
	إذا (ssh_packet_log_type(type))
		debug3_f("channel %u: down->up: type %u",
		    downstream->self, type);

	بدل (type) {
	حالة SSH2_پیام_CHANNEL_OPEN:
		إذا ((original = sshbuf_from(cp, have)) == عدم ||
		    (modified = sshbuf_new()) == عدم) {
			error_f("alloc");
			اذهب بیرون;
		}
		إذا ((r = sshbuf_get_cstring(original, &ctype, عدم)) != 0 ||
		    (r = sshbuf_get_u32(original, &id)) != 0) {
			error_fr(r, "parse");
			اذهب بیرون;
		}
		c = channel_new(ssh, "mux-proxy", SSH_CHANNEL_MUX_PROXY,
		    -1, -1, -1, 0, 0, 0, ctype, 1);
		c->mux_ctx = downstream;	/* point to mux client */
		c->mux_downstream_id = id;	/* original downstream id */
		إذا ((r = sshbuf_put_cstring(modified, ctype)) != 0 ||
		    (r = sshbuf_put_u32(modified, c->self)) != 0 ||
		    (r = sshbuf_putb(modified, original)) != 0) {
			error_fr(r, "compose");
			channel_free(ssh, c);
			اذهب بیرون;
		}
		اكسر;
	حالة SSH2_پیام_CHANNEL_OPEN_CONFIRMATION:
		/*
		 * Almost the same as SSH2_MSG_CHANNEL_OPEN, except then we
		 * need to parse 'remote_id' instead of 'ctype'.
		 */
		إذا ((original = sshbuf_from(cp, have)) == عدم ||
		    (modified = sshbuf_new()) == عدم) {
			error_f("alloc");
			اذهب بیرون;
		}
		إذا ((r = sshbuf_get_u32(original, &remote_id)) != 0 ||
		    (r = sshbuf_get_u32(original, &id)) != 0) {
			error_fr(r, "parse");
			اذهب بیرون;
		}
		c = channel_new(ssh, "mux-proxy", SSH_CHANNEL_MUX_PROXY,
		    -1, -1, -1, 0, 0, 0, "mux-down-connect", 1);
		c->mux_ctx = downstream;	/* point to mux client */
		c->mux_downstream_id = id;
		c->remote_id = remote_id;
		c->have_remote_id = 1;
		إذا ((r = sshbuf_put_u32(modified, remote_id)) != 0 ||
		    (r = sshbuf_put_u32(modified, c->self)) != 0 ||
		    (r = sshbuf_putb(modified, original)) != 0) {
			error_fr(r, "compose");
			channel_free(ssh, c);
			اذهب بیرون;
		}
		اكسر;
	حالة SSH2_پیام_GLOBAL_REQUEST:
		إذا ((original = sshbuf_from(cp, have)) == عدم) {
			error_f("alloc");
			اذهب بیرون;
		}
		إذا ((r = sshbuf_get_cstring(original, &ctype, عدم)) != 0) {
			error_fr(r, "parse");
			اذهب بیرون;
		}
		إذا (strcmp(ctype, "tcpip-forward") != 0) {
			error_f("unsupported request %s", ctype);
			اذهب بیرون;
		}
		إذا ((r = sshbuf_get_u8(original, عدم)) != 0 ||
		    (r = sshbuf_get_cstring(original, &listen_host, عدم)) != 0 ||
		    (r = sshbuf_get_u32(original, &listen_پورت)) != 0) {
			error_fr(r, "parse");
			اذهب بیرون;
		}
		إذا (listen_پورت > 65535) {
			error_f("tcpip-forward for %s: bad port %u",
			    listen_host, listen_پورت);
			اذهب بیرون;
		}
		/* Record that connection to this host/port is permitted. */
		permission_مجموعه_جمع_کن(ssh, FORWARD_USER, FORWARD_LOCAL, "<mux>",
		    -1, listen_host, عدم, (صحيح)listen_پورت, downstream);
		اكسر;
	حالة SSH2_پیام_CHANNEL_CLOSE:
		إذا (have < 4)
			اكسر;
		remote_id = PEEK_U32(cp);
		إذا ((c = channel_by_remote_id(ssh, remote_id)) != عدم) {
			إذا (c->flags & CHAN_CLOSE_RCVD)
				channel_free(ssh, c);
			وإلا
				c->flags |= CHAN_CLOSE_فرستاده;
		}
		اكسر;
	}
	إذا (modified) {
		إذا ((r = sshpkt_شروع(ssh, type)) != 0 ||
		    (r = sshpkt_putb(ssh, modified)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0) {
			error_fr(r, "send");
			اذهب بیرون;
		}
	} وإلا {
		إذا ((r = sshpkt_شروع(ssh, type)) != 0 ||
		    (r = sshpkt_put(ssh, cp, have)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0) {
			error_fr(r, "send");
			اذهب بیرون;
		}
	}
	ret = 0;
 بیرون:
	حرر(ctype);
	حرر(listen_host);
	sshbuf_free(original);
	sshbuf_free(modified);
	أرجع ret;
}

/*
 * receive packets from upstream server and de-multiplex packets
 * to correct downstream:
 * implemented as a helper for channel input handlers,
 * replaces local (proxy) channel ID with downstream channel ID.
 */
صحيح
channel_proxy_upstream(Channel *c, صحيح type, uint32_t seq, بنية ssh *ssh)
{
	بنية sshbuf *b = عدم;
	Channel *downstream;
	ثابت u_char *cp = عدم;
	اندازه_t len;
	صحيح r;

	/*
	 * When receiving packets from the peer we need to check whether we
	 * need to forward the packets to the mux client. In this case we
	 * restore the original channel id and keep track of CLOSE messages,
	 * so we can cleanup the channel.
	 */
	إذا (c == عدم || c->type != SSH_CHANNEL_MUX_PROXY)
		أرجع 0;
	إذا ((downstream = c->mux_ctx) == عدم)
		أرجع 0;
	بدل (type) {
	حالة SSH2_پیام_CHANNEL_CLOSE:
	حالة SSH2_پیام_CHANNEL_داده:
	حالة SSH2_پیام_CHANNEL_EOF:
	حالة SSH2_پیام_CHANNEL_EXTENDED_داده:
	حالة SSH2_پیام_CHANNEL_OPEN_CONFIRMATION:
	حالة SSH2_پیام_CHANNEL_OPEN_FAILURE:
	حالة SSH2_پیام_CHANNEL_پنجره_ADJUST:
	حالة SSH2_پیام_CHANNEL_SUCCESS:
	حالة SSH2_پیام_CHANNEL_FAILURE:
	حالة SSH2_پیام_CHANNEL_REQUEST:
		اكسر;
	افتراضي:
		debug2_f("channel %u: unsupported type %u", c->self, type);
		أرجع 0;
	}
	إذا ((b = sshbuf_new()) == عدم) {
		error_f("alloc reply");
		اذهب بیرون;
	}
	/* get remaining payload (after id) */
	cp = sshpkt_ptr(ssh, &len);
	إذا (cp == عدم) {
		error_f("no packet");
		اذهب بیرون;
	}
	/* translate id and send to muxclient */
	إذا ((r = sshbuf_put_u8(b, 0)) != 0 ||	/* padlen */
	    (r = sshbuf_put_u8(b, type)) != 0 ||
	    (r = sshbuf_put_u32(b, c->mux_downstream_id)) != 0 ||
	    (r = sshbuf_put(b, cp, len)) != 0 ||
	    (r = sshbuf_put_stringb(downstream->output, b)) != 0) {
		error_fr(r, "compose muxclient");
		اذهب بیرون;
	}
	/* sshbuf_dump(b, stderr); */
	إذا (ssh_packet_log_type(type))
		debug3_f("channel %u: up->down: type %u", c->self, type);
 بیرون:
	/* update state */
	بدل (type) {
	حالة SSH2_پیام_CHANNEL_OPEN_CONFIRMATION:
		/* record remote_id for SSH2_MSG_CHANNEL_CLOSE */
		إذا (cp && len > 4) {
			c->remote_id = PEEK_U32(cp);
			c->have_remote_id = 1;
		}
		اكسر;
	حالة SSH2_پیام_CHANNEL_CLOSE:
		إذا (c->flags & CHAN_CLOSE_فرستاده)
			channel_free(ssh, c);
		وإلا
			c->flags |= CHAN_CLOSE_RCVD;
		اكسر;
	}
	sshbuf_free(b);
	أرجع 1;
}

/* -- protocol input */

/* Parse a channel ID from the current packet */
ساكن صحيح
channel_parse_id(بنية ssh *ssh, ثابت حرف *where, ثابت حرف *what)
{
	uint32_t id;
	صحيح r;

	إذا ((r = sshpkt_get_u32(ssh, &id)) != 0) {
		error_r(r, "%s: parse id", where);
		ssh_packet_disconnect(ssh, "Invalid %s message", what);
	}
	إذا (id > بیشترین_صحیح) {
		error_r(r, "%s: bad channel id %u", where, id);
		ssh_packet_disconnect(ssh, "Invalid %s channel id", what);
	}
	أرجع (صحيح)id;
}

/* Lookup a channel from an ID in the current packet */
ساكن Channel *
channel_from_packet_id(بنية ssh *ssh, ثابت حرف *where, ثابت حرف *what)
{
	صحيح id = channel_parse_id(ssh, where, what);
	Channel *c;

	إذا ((c = channel_lookup(ssh, id)) == عدم) {
		ssh_packet_disconnect(ssh,
		    "%s packet referred to nonexistent channel %d", what, id);
	}
	أرجع c;
}

صحيح
channel_درون_داد_داده(صحيح type, uint32_t seq, بنية ssh *ssh)
{
	ثابت u_char *داده;
	اندازه_t داده_len, win_len;
	Channel *c = channel_from_packet_id(ssh, __func__, "data");
	صحيح r;

	إذا (channel_proxy_upstream(c, type, seq, ssh))
		أرجع 0;

	/* Ignore any data for non-open channels (might happen on close) */
	إذا (c->type != SSH_CHANNEL_OPEN &&
	    c->type != SSH_CHANNEL_RDYNAMIC_OPEN &&
	    c->type != SSH_CHANNEL_RDYNAMIC_پایان &&
	    c->type != SSH_CHANNEL_X11_OPEN)
		أرجع 0;

	/* Get the data. */
	إذا ((r = sshpkt_get_string_مستقیم(ssh, &داده, &داده_len)) != 0 ||
            (r = sshpkt_get_انتها(ssh)) != 0)
		fatal_fr(r, "channel %i: get data", c->self);

	win_len = داده_len;
	إذا (c->datagram)
		win_len += 4;  /* string length header */

	/*
	 * The sending side reduces its window as it sends data, so we
	 * must 'fake' consumption of the data in order to ensure that window
	 * updates are sent back. Otherwise the connection might deadlock.
	 */
	إذا (c->ostate != CHAN_OUTPUT_OPEN) {
		إذا (win_len > c->local_پنجره)
			c->local_پنجره = 0;
		وإلا
			c->local_پنجره -= win_len;
		c->local_consumed += win_len;
		أرجع 0;
	}

	إذا (win_len > c->local_maxpacket) {
		logit("channel %d: rcvd big packet %zu, maxpack %u",
		    c->self, win_len, c->local_maxpacket);
		أرجع 0;
	}
	إذا (win_len > c->local_پنجره) {
		u_int delta = win_len - c->local_پنجره;

		إذا (c->local_پنجره_exceeded > UINT_MAX - delta)
			c->local_پنجره_exceeded = UINT_MAX;
		وإلا
			c->local_پنجره_exceeded += delta;
		logit("channel %d: rcvd too much data %zu, win %u/%u "
		    "(excess %u)", c->self, win_len, c->local_پنجره,
		    c->local_پنجره_max, c->local_پنجره_exceeded);
		c->local_پنجره = 0;
		/* Allow 10% grace before bringing the hammer down */
		إذا (c->local_پنجره_exceeded > (c->local_پنجره_max / 10)) {
			ssh_packet_disconnect(ssh, "channel %d: peer ignored "
			    "channel window", c->self);
		}
	} وإلا {
		c->local_پنجره -= win_len;
		c->local_پنجره_exceeded = 0;
	}

	إذا (c->datagram) {
		إذا ((r = sshbuf_put_string(c->output, داده, داده_len)) != 0)
			fatal_fr(r, "channel %i: append datagram", c->self);
	} وإلا إذا ((r = sshbuf_put(c->output, داده, داده_len)) != 0)
		fatal_fr(r, "channel %i: append data", c->self);

	أرجع 0;
}

صحيح
channel_درون_داد_extended_داده(صحيح type, uint32_t seq, بنية ssh *ssh)
{
	ثابت u_char *داده;
	اندازه_t داده_len;
	uint32_t tcode;
	Channel *c = channel_from_packet_id(ssh, __func__, "extended data");
	صحيح r;

	إذا (channel_proxy_upstream(c, type, seq, ssh))
		أرجع 0;
	إذا (c->type != SSH_CHANNEL_OPEN) {
		logit("channel %d: ext data for non open", c->self);
		أرجع 0;
	}
	إذا (c->flags & CHAN_EOF_RCVD) {
		إذا (ssh->compat & SSH_BUG_EXTEOF)
			debug("channel %d: accepting ext data after eof",
			    c->self);
		وإلا
			ssh_packet_disconnect(ssh, "Received extended_data "
			    "after EOF on channel %d.", c->self);
	}

	إذا ((r = sshpkt_get_u32(ssh, &tcode)) != 0) {
		error_fr(r, "parse tcode");
		ssh_packet_disconnect(ssh, "Invalid extended_data message");
	}
	إذا (c->efd == -1 ||
	    c->extended_usage != CHAN_EXTENDED_WRITE ||
	    tcode != SSH2_EXTENDED_داده_STDERR) {
		logit("channel %d: bad ext data", c->self);
		أرجع 0;
	}
	إذا ((r = sshpkt_get_string_مستقیم(ssh, &داده, &داده_len)) != 0 ||
            (r = sshpkt_get_انتها(ssh)) != 0) {
		error_fr(r, "parse data");
		ssh_packet_disconnect(ssh, "Invalid extended_data message");
	}

	إذا (داده_len > c->local_پنجره) {
		logit("channel %d: rcvd too much extended_data %zu, win %u",
		    c->self, داده_len, c->local_پنجره);
		أرجع 0;
	}
	debug2("channel %d: rcvd ext data %zu", c->self, داده_len);
	/* XXX sshpkt_getb? */
	إذا ((r = sshbuf_put(c->extended, داده, داده_len)) != 0)
		error_fr(r, "append");
	c->local_پنجره -= داده_len;
	أرجع 0;
}

صحيح
channel_درون_داد_ieof(صحيح type, uint32_t seq, بنية ssh *ssh)
{
	Channel *c = channel_from_packet_id(ssh, __func__, "ieof");
	صحيح r;

        إذا ((r = sshpkt_get_انتها(ssh)) != 0) {
		error_fr(r, "parse data");
		ssh_packet_disconnect(ssh, "Invalid ieof message");
	}

	إذا (channel_proxy_upstream(c, type, seq, ssh))
		أرجع 0;
	chan_rcvd_ieof(ssh, c);

	/* XXX force input close */
	إذا (c->force_drain && c->istate == CHAN_درون_داد_OPEN) {
		debug("channel %d: FORCE input drain", c->self);
		c->istate = CHAN_درون_داد_WAIT_DRAIN;
		إذا (sshbuf_len(c->درون_داد) == 0)
			chan_ibuf_خالی(ssh, c);
	}
	أرجع 0;
}

صحيح
channel_درون_داد_oclose(صحيح type, uint32_t seq, بنية ssh *ssh)
{
	Channel *c = channel_from_packet_id(ssh, __func__, "oclose");
	صحيح r;

	إذا (channel_proxy_upstream(c, type, seq, ssh))
		أرجع 0;
        إذا ((r = sshpkt_get_انتها(ssh)) != 0) {
		error_fr(r, "parse data");
		ssh_packet_disconnect(ssh, "Invalid oclose message");
	}
	chan_rcvd_oclose(ssh, c);
	أرجع 0;
}

صحيح
channel_درون_داد_open_confirmation(صحيح type, uint32_t seq, بنية ssh *ssh)
{
	Channel *c = channel_from_packet_id(ssh, __func__, "open confirmation");
	uint32_t remote_پنجره, remote_maxpacket;
	صحيح r;

	إذا (channel_proxy_upstream(c, type, seq, ssh))
		أرجع 0;
	إذا (c->type != SSH_CHANNEL_OPENING)
		ssh_packet_disconnect(ssh, "Received open confirmation for "
		    "non-opening channel %d.", c->self);
	/*
	 * Record the remote channel number and mark that the channel
	 * is now open.
	 */
	إذا ((r = sshpkt_get_u32(ssh, &c->remote_id)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &remote_پنجره)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &remote_maxpacket)) != 0 ||
            (r = sshpkt_get_انتها(ssh)) != 0) {
		error_fr(r, "window/maxpacket");
		ssh_packet_disconnect(ssh, "Invalid open confirmation message");
	}

	c->have_remote_id = 1;
	c->remote_پنجره = remote_پنجره;
	c->remote_maxpacket = remote_maxpacket;
	c->type = SSH_CHANNEL_OPEN;
	إذا (c->open_confirm) {
		debug2_f("channel %d: callback start", c->self);
		c->open_confirm(ssh, c->self, 1, c->open_confirm_ctx);
		debug2_f("channel %d: callback done", c->self);
	}
	channel_مجموعه_استفاده_شده_زمان(ssh, c);
	debug2("channel %d: open confirm rwindow %u rmax %u", c->self,
	    c->remote_پنجره, c->remote_maxpacket);
	أرجع 0;
}

ساكن حرف *
reason2txt(صحيح reason)
{
	بدل (reason) {
	حالة SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED:
		أرجع "administratively prohibited";
	حالة SSH2_OPEN_CONNECT_FAILED:
		أرجع "connect failed";
	حالة SSH2_OPEN_UNKNOWN_CHANNEL_TYPE:
		أرجع "unknown channel type";
	حالة SSH2_OPEN_RESOURCE_SHORTAGE:
		أرجع "resource shortage";
	}
	أرجع "unknown reason";
}

صحيح
channel_درون_داد_open_failure(صحيح type, uint32_t seq, بنية ssh *ssh)
{
	Channel *c = channel_from_packet_id(ssh, __func__, "open failure");
	uint32_t reason;
	حرف *پیام = عدم;
	صحيح r;

	إذا (channel_proxy_upstream(c, type, seq, ssh))
		أرجع 0;
	إذا (c->type != SSH_CHANNEL_OPENING)
		ssh_packet_disconnect(ssh, "Received open failure for "
		    "non-opening channel %d.", c->self);
	إذا ((r = sshpkt_get_u32(ssh, &reason)) != 0) {
		error_fr(r, "parse reason");
		ssh_packet_disconnect(ssh, "Invalid open failure message");
	}
	/* skip language */
	إذا ((r = sshpkt_get_cstring(ssh, &پیام, عدم)) != 0 ||
	    (r = sshpkt_get_string_مستقیم(ssh, عدم, عدم)) != 0 ||
            (r = sshpkt_get_انتها(ssh)) != 0) {
		error_fr(r, "parse msg/lang");
		ssh_packet_disconnect(ssh, "Invalid open failure message");
	}
	logit("channel %d: open failed: %s%s%s", c->self,
	    reason2txt(reason), پیام ? ": ": "", پیام ? پیام : "");
	حرر(پیام);
	إذا (c->open_confirm) {
		debug2_f("channel %d: callback start", c->self);
		c->open_confirm(ssh, c->self, 0, c->open_confirm_ctx);
		debug2_f("channel %d: callback done", c->self);
	}
	/* Schedule the channel for cleanup/deletion. */
	chan_mark_dead(ssh, c);
	أرجع 0;
}

صحيح
channel_درون_داد_پنجره_adjust(صحيح type, uint32_t seq, بنية ssh *ssh)
{
	صحيح id = channel_parse_id(ssh, __func__, "window adjust");
	Channel *c;
	uint32_t adjust;
	u_int new_rwin;
	صحيح r;

	إذا ((c = channel_lookup(ssh, id)) == عدم) {
		logit("Received window adjust for non-open channel %d.", id);
		أرجع 0;
	}

	إذا (channel_proxy_upstream(c, type, seq, ssh))
		أرجع 0;
	إذا ((r = sshpkt_get_u32(ssh, &adjust)) != 0 ||
            (r = sshpkt_get_انتها(ssh)) != 0) {
		error_fr(r, "parse adjust");
		ssh_packet_disconnect(ssh, "Invalid window adjust message");
	}
	debug2("channel %d: rcvd adjust %u", c->self, adjust);
	إذا ((new_rwin = c->remote_پنجره + adjust) < c->remote_پنجره) {
		fatal("channel %d: adjust %u overflows remote window %u",
		    c->self, adjust, c->remote_پنجره);
	}
	c->remote_پنجره = new_rwin;
	أرجع 0;
}

صحيح
channel_درون_داد_وضعیت_confirm(صحيح type, uint32_t seq, بنية ssh *ssh)
{
	صحيح id = channel_parse_id(ssh, __func__, "status confirm");
	Channel *c;
	بنية channel_confirm *cc;

	/* Reset keepalive timeout */
	ssh_packet_مجموعه_alive_timeouts(ssh, 0);

	debug2_f("type %d id %d", type, id);

	إذا ((c = channel_lookup(ssh, id)) == عدم) {
		logit_f("%d: unknown", id);
		أرجع 0;
	}
	إذا (channel_proxy_upstream(c, type, seq, ssh))
		أرجع 0;
        إذا (sshpkt_get_انتها(ssh) != 0)
		ssh_packet_disconnect(ssh, "Invalid status confirm message");
	إذا ((cc = TAILQ_FIRST(&c->وضعیت_confirms)) == عدم)
		أرجع 0;
	cc->cb(ssh, type, c, cc->ctx);
	TAILQ_REMOVE(&c->وضعیت_confirms, cc, مدخل);
	freezero(cc, حجم(*cc));
	أرجع 0;
}

/* -- tcp forwarding */

فراغ
channel_مجموعه_af(بنية ssh *ssh, صحيح af)
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
ساكن ثابت حرف *
channel_fwd_bind_addr(بنية ssh *ssh, ثابت حرف *listen_addr, صحيح *wildcardp,
    صحيح is_client, بنية ForwardOptions *fwd_opts)
{
	ثابت حرف *addr = عدم;
	صحيح wildcard = 0;

	إذا (listen_addr == عدم) {
		/* No address specified: default to gateway_ports setting */
		إذا (fwd_opts->gateway_ports)
			wildcard = 1;
	} وإلا إذا (fwd_opts->gateway_ports || is_client) {
		إذا (((ssh->compat & SSH_OLD_FORWARD_ADDR) &&
		    strcmp(listen_addr, "0.0.0.0") == 0 && is_client == 0) ||
		    *listen_addr == '\0' || strcmp(listen_addr, "*") == 0 ||
		    (!is_client && fwd_opts->gateway_ports == 1)) {
			wildcard = 1;
			/*
			 * Notify client if they requested a specific listen
			 * address and it was overridden.
			 */
			إذا (*listen_addr != '\0' &&
			    strcmp(listen_addr, "0.0.0.0") != 0 &&
			    strcmp(listen_addr, "*") != 0) {
				ssh_packet_send_debug(ssh,
				    "Forwarding listen address "
				    "\"%s\" overridden by server "
				    "GatewayPorts", listen_addr);
			}
		} وإلا إذا (strcmp(listen_addr, "localhost") != 0 ||
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
	} وإلا إذا (strcmp(listen_addr, "127.0.0.1") == 0 ||
	    strcmp(listen_addr, "::1") == 0) {
		/*
		 * If a specific IPv4/IPv6 localhost address has been
		 * requested then accept it even if gateway_ports is in
		 * effect. This allows the client to prefer IPv4 or IPv6.
		 */
		addr = listen_addr;
	}
	إذا (wildcardp != عدم)
		*wildcardp = wildcard;
	أرجع addr;
}

ساكن صحيح
channel_راهاندازی_fwd_listener_tcpip(بنية ssh *ssh, صحيح type,
    بنية Forward *fwd, صحيح *allocated_listen_پورت,
    بنية ForwardOptions *fwd_opts)
{
	Channel *c;
	صحيح sock, r, success = 0, wildcard = 0, is_client;
	بنية addrinfo hints, *ai, *aitop;
	ثابت حرف *host, *addr;
	حرف ntop[NI_MAXHOST], strport[NI_MAXSERV];
	in_port_t *lport_p;

	is_client = (type == SSH_CHANNEL_پورت_LISTENER);

	إذا (is_client && fwd->connect_مسیر != عدم) {
		host = fwd->connect_مسیر;
	} وإلا {
		host = (type == SSH_CHANNEL_RPORT_LISTENER) ?
		    fwd->listen_host : fwd->connect_host;
		إذا (host == عدم) {
			error("No forward host name.");
			أرجع 0;
		}
		إذا (طول_رشته(host) >= NI_MAXHOST) {
			error("Forward host name too long.");
			أرجع 0;
		}
	}

	/* Determine the bind address, cf. channel_fwd_bind_addr() comment */
	addr = channel_fwd_bind_addr(ssh, fwd->listen_host, &wildcard,
	    is_client, fwd_opts);
	debug3_f("type %d wildcard %d addr %s", type, wildcard,
	    (addr == عدم) ? "NULL" : addr);

	/*
	 * getaddrinfo returns a loopback address if the hostname is
	 * set to NULL and hints.ai_flags is not AI_PASSIVE
	 */
	memset(&hints, 0, حجم(hints));
	hints.ai_family = ssh->chanctxt->IPv4or6;
	hints.ai_flags = wildcard ? AI_PASSIVE : 0;
	hints.ai_socktype = SOCK_STREAM;
	snprintf(strport, حجم strport, "%d", fwd->listen_پورت);
	إذا ((r = getaddrinfo(addr, strport, &hints, &aitop)) != 0) {
		إذا (addr == عدم) {
			/* This really shouldn't happen */
			ssh_packet_disconnect(ssh, "getaddrinfo: fatal error: %s",
			    ssh_gai_strerror(r));
		} وإلا {
			error_f("getaddrinfo(%.64s): %s", addr,
			    ssh_gai_strerror(r));
		}
		أرجع 0;
	}
	إذا (allocated_listen_پورت != عدم)
		*allocated_listen_پورت = 0;
	لكل (ai = aitop; ai; ai = ai->ai_next) {
		بدل (ai->ai_family) {
		حالة AF_INET:
			lport_p = &((بنية sockaddr_in *)ai->ai_addr)->
			    sin_port;
			اكسر;
		حالة AF_INET6:
			lport_p = &((بنية sockaddr_in6 *)ai->ai_addr)->
			    sin6_port;
			اكسر;
		افتراضي:
			استمر;
		}
		/*
		 * If allocating a port for -R forwards, then use the
		 * same port for all address families.
		 */
		إذا (type == SSH_CHANNEL_RPORT_LISTENER &&
		    fwd->listen_پورت == 0 && allocated_listen_پورت != عدم &&
		    *allocated_listen_پورت > 0)
			*lport_p = htons(*allocated_listen_پورت);

		إذا (getnameinfo(ai->ai_addr, ai->ai_addrlen, ntop, حجم(ntop),
		    strport, حجم(strport),
		    NI_NUMERICHOST|NI_NUMERICSERV) != 0) {
			error_f("getnameinfo failed");
			استمر;
		}
		/* Create a port to listen for the host. */
		sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		إذا (sock == -1) {
			/* this is no error since kernel may not support ipv6 */
			verbose("socket [%s]:%s: %.100s", ntop, strport,
			    strerror(errno));
			استمر;
		}

		مجموعه_reuseaddr(sock);
		إذا (ai->ai_family == AF_INET6)
			sock_مجموعه_v6only(sock);

		debug("Local forwarding listening on %s port %s.",
		    ntop, strport);

		/* Bind the socket to the address. */
		إذا (bind(sock, ai->ai_addr, ai->ai_addrlen) == -1) {
			/*
			 * address can be in if use ipv6 address is
			 * already bound
			 */
			إذا (!ai->ai_next)
				error("bind [%s]:%s: %.100s",
				    ntop, strport, strerror(errno));
			وإلا
				verbose("bind [%s]:%s: %.100s",
				    ntop, strport, strerror(errno));

			close(sock);
			استمر;
		}
		/* Start listening for connections on the socket. */
		إذا (listen(sock, SSH_LISTEN_BACKLOG) == -1) {
			error("listen [%s]:%s: %.100s", ntop, strport,
			    strerror(errno));
			close(sock);
			استمر;
		}

		/*
		 * fwd->listen_port == 0 requests a dynamically allocated port -
		 * record what we got.
		 */
		إذا (type == SSH_CHANNEL_RPORT_LISTENER &&
		    fwd->listen_پورت == 0 &&
		    allocated_listen_پورت != عدم &&
		    *allocated_listen_پورت == 0) {
			*allocated_listen_پورت = get_local_پورت(sock);
			debug("Allocated listen port %d",
			    *allocated_listen_پورت);
		}

		/* Allocate a channel number for the socket. */
		c = channel_new(ssh, "port-listener", type, sock, sock, -1,
		    CHAN_TCP_پنجره_DEFAULT, CHAN_TCP_PACKET_DEFAULT,
		    0, "port listener", 1);
		c->مسیر = xstrdup(host);
		c->host_پورت = fwd->connect_پورت;
		c->listening_addr = addr == عدم ? عدم : xstrdup(addr);
		إذا (fwd->listen_پورت == 0 && allocated_listen_پورت != عدم &&
		    !(ssh->compat & SSH_BUG_DYNAMIC_RPORT))
			c->listening_پورت = *allocated_listen_پورت;
		وإلا
			c->listening_پورت = fwd->listen_پورت;
		success = 1;
	}
	إذا (success == 0)
		error_f("cannot listen to port: %d", fwd->listen_پورت);
	freeaddrinfo(aitop);
	أرجع success;
}

ساكن صحيح
channel_راهاندازی_fwd_listener_streamlocal(بنية ssh *ssh, صحيح type,
    بنية Forward *fwd, بنية ForwardOptions *fwd_opts)
{
	بنية sockaddr_un sunaddr;
	ثابت حرف *مسیر;
	Channel *c;
	صحيح پورت, sock;
	نما_t omask;

	بدل (type) {
	حالة SSH_CHANNEL_UNIX_LISTENER:
		إذا (fwd->connect_مسیر != عدم) {
			إذا (طول_رشته(fwd->connect_مسیر) > حجم(sunaddr.sun_مسیر)) {
				error("Local connecting path too long: %s",
				    fwd->connect_مسیر);
				أرجع 0;
			}
			مسیر = fwd->connect_مسیر;
			پورت = پورت_STREAMLOCAL;
		} وإلا {
			إذا (fwd->connect_host == عدم) {
				error("No forward host name.");
				أرجع 0;
			}
			إذا (طول_رشته(fwd->connect_host) >= NI_MAXHOST) {
				error("Forward host name too long.");
				أرجع 0;
			}
			مسیر = fwd->connect_host;
			پورت = fwd->connect_پورت;
		}
		اكسر;
	حالة SSH_CHANNEL_RUNIX_LISTENER:
		مسیر = fwd->listen_مسیر;
		پورت = پورت_STREAMLOCAL;
		اكسر;
	افتراضي:
		error_f("unexpected channel type %d", type);
		أرجع 0;
	}

	إذا (fwd->listen_مسیر == عدم) {
		error("No forward path name.");
		أرجع 0;
	}
	إذا (طول_رشته(fwd->listen_مسیر) > حجم(sunaddr.sun_مسیر)) {
		error("Local listening path too long: %s", fwd->listen_مسیر);
		أرجع 0;
	}

	debug3_f("type %d path %s", type, fwd->listen_مسیر);

	/* Start a Unix domain listener. */
	omask = umask(fwd_opts->streamlocal_bind_ماسک);
	sock = unix_listener(fwd->listen_مسیر, SSH_LISTEN_BACKLOG,
	    fwd_opts->streamlocal_bind_unlink);
	umask(omask);
	إذا (sock < 0)
		أرجع 0;

	debug("Local forwarding listening on path %s.", fwd->listen_مسیر);

	/* Allocate a channel number for the socket. */
	c = channel_new(ssh, "unix-listener", type, sock, sock, -1,
	    CHAN_TCP_پنجره_DEFAULT, CHAN_TCP_PACKET_DEFAULT,
	    0, "unix listener", 1);
	c->مسیر = xstrdup(مسیر);
	c->host_پورت = پورت;
	c->listening_پورت = پورت_STREAMLOCAL;
	c->listening_addr = xstrdup(fwd->listen_مسیر);
	أرجع 1;
}

ساكن صحيح
channel_cancel_rport_listener_tcpip(بنية ssh *ssh,
    ثابت حرف *host, u_short پورت)
{
	u_int i;
	صحيح یافت = 0;

	لكل (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		Channel *c = ssh->chanctxt->channels[i];
		إذا (c == عدم || c->type != SSH_CHANNEL_RPORT_LISTENER)
			استمر;
		إذا (strcmp(c->مسیر, host) == 0 && c->listening_پورت == پورت) {
			debug2_f("close channel %d", i);
			channel_free(ssh, c);
			یافت = 1;
		}
	}

	أرجع یافت;
}

ساكن صحيح
channel_cancel_rport_listener_streamlocal(بنية ssh *ssh, ثابت حرف *مسیر)
{
	u_int i;
	صحيح یافت = 0;

	لكل (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		Channel *c = ssh->chanctxt->channels[i];
		إذا (c == عدم || c->type != SSH_CHANNEL_RUNIX_LISTENER)
			استمر;
		إذا (c->مسیر == عدم)
			استمر;
		إذا (strcmp(c->مسیر, مسیر) == 0) {
			debug2_f("close channel %d", i);
			channel_free(ssh, c);
			یافت = 1;
		}
	}

	أرجع یافت;
}

صحيح
channel_cancel_rport_listener(بنية ssh *ssh, بنية Forward *fwd)
{
	إذا (fwd->listen_مسیر != عدم) {
		أرجع channel_cancel_rport_listener_streamlocal(ssh,
		    fwd->listen_مسیر);
	} وإلا {
		أرجع channel_cancel_rport_listener_tcpip(ssh,
		    fwd->listen_host, fwd->listen_پورت);
	}
}

ساكن صحيح
channel_cancel_lport_listener_tcpip(بنية ssh *ssh,
    ثابت حرف *lhost, u_short lport, صحيح cport,
    بنية ForwardOptions *fwd_opts)
{
	u_int i;
	صحيح یافت = 0;
	ثابت حرف *addr = channel_fwd_bind_addr(ssh, lhost, عدم, 1, fwd_opts);

	لكل (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		Channel *c = ssh->chanctxt->channels[i];
		إذا (c == عدم || c->type != SSH_CHANNEL_پورت_LISTENER)
			استمر;
		إذا (c->listening_پورت != lport)
			استمر;
		إذا (cport == CHANNEL_CANCEL_پورت_STATIC) {
			/* skip dynamic forwardings */
			إذا (c->host_پورت == 0)
				استمر;
		} وإلا {
			إذا (c->host_پورت != cport)
				استمر;
		}
		إذا ((c->listening_addr == عدم && addr != عدم) ||
		    (c->listening_addr != عدم && addr == عدم))
			استمر;
		إذا (addr == عدم || strcmp(c->listening_addr, addr) == 0) {
			debug2_f("close channel %d", i);
			channel_free(ssh, c);
			یافت = 1;
		}
	}

	أرجع یافت;
}

ساكن صحيح
channel_cancel_lport_listener_streamlocal(بنية ssh *ssh, ثابت حرف *مسیر)
{
	u_int i;
	صحيح یافت = 0;

	إذا (مسیر == عدم) {
		error_f("no path specified.");
		أرجع 0;
	}

	لكل (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		Channel *c = ssh->chanctxt->channels[i];
		إذا (c == عدم || c->type != SSH_CHANNEL_UNIX_LISTENER)
			استمر;
		إذا (c->listening_addr == عدم)
			استمر;
		إذا (strcmp(c->listening_addr, مسیر) == 0) {
			debug2_f("close channel %d", i);
			channel_free(ssh, c);
			یافت = 1;
		}
	}

	أرجع یافت;
}

صحيح
channel_cancel_lport_listener(بنية ssh *ssh,
    بنية Forward *fwd, صحيح cport, بنية ForwardOptions *fwd_opts)
{
	إذا (fwd->listen_مسیر != عدم) {
		أرجع channel_cancel_lport_listener_streamlocal(ssh,
		    fwd->listen_مسیر);
	} وإلا {
		أرجع channel_cancel_lport_listener_tcpip(ssh,
		    fwd->listen_host, fwd->listen_پورت, cport, fwd_opts);
	}
}

/* protocol local port fwd, used by ssh */
صحيح
channel_راهاندازی_local_fwd_listener(بنية ssh *ssh,
    بنية Forward *fwd, بنية ForwardOptions *fwd_opts)
{
	إذا (fwd->listen_مسیر != عدم) {
		أرجع channel_راهاندازی_fwd_listener_streamlocal(ssh,
		    SSH_CHANNEL_UNIX_LISTENER, fwd, fwd_opts);
	} وإلا {
		أرجع channel_راهاندازی_fwd_listener_tcpip(ssh,
		    SSH_CHANNEL_پورت_LISTENER, fwd, عدم, fwd_opts);
	}
}

/* Matches a remote forwarding permission against a requested forwarding */
ساكن صحيح
remote_open_تطابق(بنية permission *allowed_open, بنية Forward *fwd)
{
	صحيح ret;
	حرف *lhost;

	/* XXX add ACLs for streamlocal */
	إذا (fwd->listen_مسیر != عدم)
		أرجع 1;

	إذا (fwd->listen_host == عدم || allowed_open->listen_host == عدم)
		أرجع 0;

	إذا (allowed_open->listen_پورت != FWD_PERMIT_ANY_پورت &&
	    allowed_open->listen_پورت != fwd->listen_پورت)
		أرجع 0;

	/* Match hostnames case-insensitively */
	lhost = xstrdup(fwd->listen_host);
	lowercase(lhost);
	ret = تطابق_الگو(lhost, allowed_open->listen_host);
	حرر(lhost);

	أرجع ret;
}

/* Checks whether a requested remote forwarding is permitted */
ساكن صحيح
check_rfwd_permission(بنية ssh *ssh, بنية Forward *fwd)
{
	بنية ssh_channels *sc = ssh->chanctxt;
	بنية permission_مجموعه *pset = &sc->remote_perms;
	u_int i, permit, permit_adm = 1;
	بنية permission *perm;

#اگر_تعریف_شده SKIP_PRIVDROP
	إذا (fwd->listen_مسیر != عدم)
		أرجع 0;
	إذا (fwd->listen_پورت != 0 && fwd->listen_پورت < 1024)
		أرجع 0;
#پایان_اگر

	/* XXX apply GatewayPorts override before checking? */

	permit = pset->all_permitted;
	إذا (!permit) {
		لكل (i = 0; i < pset->رقم_permitted_user; i++) {
			perm = &pset->permitted_user[i];
			إذا (remote_open_تطابق(perm, fwd)) {
				permit = 1;
				اكسر;
			}
		}
	}

	إذا (pset->رقم_permitted_admin > 0) {
		permit_adm = 0;
		لكل (i = 0; i < pset->رقم_permitted_admin; i++) {
			perm = &pset->permitted_admin[i];
			إذا (remote_open_تطابق(perm, fwd)) {
				permit_adm = 1;
				اكسر;
			}
		}
	}

	أرجع permit && permit_adm;
}

/* protocol v2 remote port fwd, used by sshd */
صحيح
channel_راهاندازی_remote_fwd_listener(بنية ssh *ssh, بنية Forward *fwd,
    صحيح *allocated_listen_پورت, بنية ForwardOptions *fwd_opts)
{
	إذا (!check_rfwd_permission(ssh, fwd)) {
		ssh_packet_send_debug(ssh, "port forwarding refused");
		إذا (fwd->listen_مسیر != عدم)
			/* XXX always allowed, see remote_open_match() */
			logit("Received request from %.100s port %d to "
			    "remote forward to path \"%.100s\", "
			    "but the request was denied.",
			    ssh_remote_ipaddr(ssh), ssh_remote_پورت(ssh),
			    fwd->listen_مسیر);
		وإلا إذا(fwd->listen_host != عدم)
			logit("Received request from %.100s port %d to "
			    "remote forward to host %.100s port %d, "
			    "but the request was denied.",
			    ssh_remote_ipaddr(ssh), ssh_remote_پورت(ssh),
			    fwd->listen_host, fwd->listen_پورت );
		وإلا
			logit("Received request from %.100s port %d to remote "
			    "forward, but the request was denied.",
			    ssh_remote_ipaddr(ssh), ssh_remote_پورت(ssh));
		أرجع 0;
	}
	إذا (fwd->listen_مسیر != عدم) {
		أرجع channel_راهاندازی_fwd_listener_streamlocal(ssh,
		    SSH_CHANNEL_RUNIX_LISTENER, fwd, fwd_opts);
	} وإلا {
		أرجع channel_راهاندازی_fwd_listener_tcpip(ssh,
		    SSH_CHANNEL_RPORT_LISTENER, fwd, allocated_listen_پورت,
		    fwd_opts);
	}
}

/*
 * Translate the requested rfwd listen host to something usable for
 * this server.
 */
ساكن ثابت حرف *
channel_rfwd_bind_host(ثابت حرف *listen_host)
{
	إذا (listen_host == عدم) {
		أرجع "localhost";
	} وإلا إذا (*listen_host == '\0' || strcmp(listen_host, "*") == 0) {
		أرجع "";
	} وإلا
		أرجع listen_host;
}

/*
 * Initiate forwarding of connections to port "port" on remote host through
 * the secure channel to host:port from local side.
 * Returns handle (index) for updating the dynamic listen port with
 * channel_update_permission().
 */
صحيح
channel_request_remote_forwarding(بنية ssh *ssh, بنية Forward *fwd)
{
	صحيح r, success = 0, idx = -1;
	ثابت حرف *host_مقصد_connect, *listen_host, *listen_مسیر;
	صحيح پورت_مقصد_connect, listen_پورت;

	/* Send the forward request to the remote side. */
	إذا (fwd->listen_مسیر != عدم) {
		إذا ((r = sshpkt_شروع(ssh, SSH2_پیام_GLOBAL_REQUEST)) != 0 ||
		    (r = sshpkt_put_cstring(ssh,
		    "streamlocal-forward@openssh.com")) != 0 ||
		    (r = sshpkt_put_u8(ssh, 1)) != 0 || /* want reply */
		    (r = sshpkt_put_cstring(ssh, fwd->listen_مسیر)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			fatal_fr(r, "request streamlocal");
	} وإلا {
		إذا ((r = sshpkt_شروع(ssh, SSH2_پیام_GLOBAL_REQUEST)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "tcpip-forward")) != 0 ||
		    (r = sshpkt_put_u8(ssh, 1)) != 0 || /* want reply */
		    (r = sshpkt_put_cstring(ssh,
		    channel_rfwd_bind_host(fwd->listen_host))) != 0 ||
		    (r = sshpkt_put_u32(ssh, fwd->listen_پورت)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			fatal_fr(r, "request tcpip-forward");
	}
	/* Assume that server accepts the request */
	success = 1;
	إذا (success) {
		/* Record that connection to this host/port is permitted. */
		host_مقصد_connect = listen_host = listen_مسیر = عدم;
		پورت_مقصد_connect = listen_پورت = 0;
		إذا (fwd->connect_مسیر != عدم) {
			host_مقصد_connect = fwd->connect_مسیر;
			پورت_مقصد_connect = پورت_STREAMLOCAL;
		} وإلا {
			host_مقصد_connect = fwd->connect_host;
			پورت_مقصد_connect = fwd->connect_پورت;
		}
		إذا (fwd->listen_مسیر != عدم) {
			listen_مسیر = fwd->listen_مسیر;
			listen_پورت = پورت_STREAMLOCAL;
		} وإلا {
			listen_host = fwd->listen_host;
			listen_پورت = fwd->listen_پورت;
		}
		idx = permission_مجموعه_جمع_کن(ssh, FORWARD_USER, FORWARD_LOCAL,
		    host_مقصد_connect, پورت_مقصد_connect,
		    listen_host, listen_مسیر, listen_پورت, عدم);
	}
	أرجع idx;
}

ساكن صحيح
open_تطابق(بنية permission *allowed_open, ثابت حرف *requestedhost,
    صحيح requestedport)
{
	إذا (allowed_open->host_مقصد_connect == عدم)
		أرجع 0;
	إذا (allowed_open->پورت_مقصد_connect != FWD_PERMIT_ANY_پورت &&
	    allowed_open->پورت_مقصد_connect != requestedport)
		أرجع 0;
	إذا (strcmp(allowed_open->host_مقصد_connect, FWD_PERMIT_ANY_HOST) != 0 &&
	    strcmp(allowed_open->host_مقصد_connect, requestedhost) != 0)
		أرجع 0;
	أرجع 1;
}

/*
 * Note that in the listen host/port case
 * we don't support FWD_PERMIT_ANY_PORT and
 * need to translate between the configured-host (listen_host)
 * and what we've sent to the remote server (channel_rfwd_bind_host)
 */
ساكن صحيح
open_listen_تطابق_tcpip(بنية permission *allowed_open,
    ثابت حرف *requestedhost, u_short requestedport, صحيح translate)
{
	ثابت حرف *allowed_host;

	إذا (allowed_open->host_مقصد_connect == عدم)
		أرجع 0;
	إذا (allowed_open->listen_پورت != requestedport)
		أرجع 0;
	إذا (!translate && allowed_open->listen_host == عدم &&
	    requestedhost == عدم)
		أرجع 1;
	allowed_host = translate ?
	    channel_rfwd_bind_host(allowed_open->listen_host) :
	    allowed_open->listen_host;
	إذا (allowed_host == عدم || requestedhost == عدم ||
	    strcmp(allowed_host, requestedhost) != 0)
		أرجع 0;
	أرجع 1;
}

ساكن صحيح
open_listen_تطابق_streamlocal(بنية permission *allowed_open,
    ثابت حرف *requestedpath)
{
	إذا (allowed_open->host_مقصد_connect == عدم)
		أرجع 0;
	إذا (allowed_open->listen_پورت != پورت_STREAMLOCAL)
		أرجع 0;
	إذا (allowed_open->listen_مسیر == عدم ||
	    strcmp(allowed_open->listen_مسیر, requestedpath) != 0)
		أرجع 0;
	أرجع 1;
}

/*
 * Request cancellation of remote forwarding of connection host:port from
 * local side.
 */
ساكن صحيح
channel_request_rforward_cancel_tcpip(بنية ssh *ssh,
    ثابت حرف *host, u_short پورت)
{
	بنية ssh_channels *sc = ssh->chanctxt;
	بنية permission_مجموعه *pset = &sc->local_perms;
	صحيح r;
	u_int i;
	بنية permission *perm = عدم;

	لكل (i = 0; i < pset->رقم_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		إذا (open_listen_تطابق_tcpip(perm, host, پورت, 0))
			اكسر;
		perm = عدم;
	}
	إذا (perm == عدم) {
		debug_f("requested forward not found");
		أرجع -1;
	}
	إذا ((r = sshpkt_شروع(ssh, SSH2_پیام_GLOBAL_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "cancel-tcpip-forward")) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 || /* want reply */
	    (r = sshpkt_put_cstring(ssh, channel_rfwd_bind_host(host))) != 0 ||
	    (r = sshpkt_put_u32(ssh, پورت)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send cancel");

	fwd_perm_clear(perm); /* unregister */

	أرجع 0;
}

/*
 * Request cancellation of remote forwarding of Unix domain socket
 * path from local side.
 */
ساكن صحيح
channel_request_rforward_cancel_streamlocal(بنية ssh *ssh, ثابت حرف *مسیر)
{
	بنية ssh_channels *sc = ssh->chanctxt;
	بنية permission_مجموعه *pset = &sc->local_perms;
	صحيح r;
	u_int i;
	بنية permission *perm = عدم;

	لكل (i = 0; i < pset->رقم_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		إذا (open_listen_تطابق_streamlocal(perm, مسیر))
			اكسر;
		perm = عدم;
	}
	إذا (perm == عدم) {
		debug_f("requested forward not found");
		أرجع -1;
	}
	إذا ((r = sshpkt_شروع(ssh, SSH2_پیام_GLOBAL_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh,
	    "cancel-streamlocal-forward@openssh.com")) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 || /* want reply */
	    (r = sshpkt_put_cstring(ssh, مسیر)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send cancel");

	fwd_perm_clear(perm); /* unregister */

	أرجع 0;
}

/*
 * Request cancellation of remote forwarding of a connection from local side.
 */
صحيح
channel_request_rforward_cancel(بنية ssh *ssh, بنية Forward *fwd)
{
	إذا (fwd->listen_مسیر != عدم) {
		أرجع channel_request_rforward_cancel_streamlocal(ssh,
		    fwd->listen_مسیر);
	} وإلا {
		أرجع channel_request_rforward_cancel_tcpip(ssh,
		    fwd->listen_host,
		    fwd->listen_پورت ? fwd->listen_پورت : fwd->allocated_پورت);
	}
}

/*
 * Permits opening to any host/port if permitted_user[] is empty.  This is
 * usually called by the server, because the user could connect to any port
 * anyway, and the server has no way to know but to trust the client anyway.
 */
فراغ
channel_permit_all(بنية ssh *ssh, صحيح where)
{
	بنية permission_مجموعه *pset = permission_مجموعه_get(ssh, where);

	إذا (pset->رقم_permitted_user == 0)
		pset->all_permitted = 1;
}

/*
 * Permit the specified host/port for forwarding.
 */
فراغ
channel_جمع_کن_permission(بنية ssh *ssh, صحيح who, صحيح where,
    حرف *host, صحيح پورت)
{
	صحيح local = where == FORWARD_LOCAL;
	بنية permission_مجموعه *pset = permission_مجموعه_get(ssh, where);

	debug("allow %s forwarding to host %s port %d",
	    fwd_ident(who, where), host, پورت);
	/*
	 * Remote forwards set listen_host/port, local forwards set
	 * host/port_to_connect.
	 */
	permission_مجموعه_جمع_کن(ssh, who, where,
	    local ? host : عدم, local ? پورت : 0,
	    local ? عدم : host, عدم, local ? 0 : پورت, عدم);
	pset->all_permitted = 0;
}

/*
 * Administratively disable forwarding.
 */
فراغ
channel_disable_admin(بنية ssh *ssh, صحيح where)
{
	channel_clear_permission(ssh, FORWARD_ADM, where);
	permission_مجموعه_جمع_کن(ssh, FORWARD_ADM, where,
	    عدم, 0, عدم, عدم, 0, عدم);
}

/*
 * Clear a list of permitted opens.
 */
فراغ
channel_clear_permission(بنية ssh *ssh, صحيح who, صحيح where)
{
	بنية permission **permp;
	u_int i, *npermp;

	permission_مجموعه_get_array(ssh, who, where, &permp, &npermp);
	لكل (i = 0; i < *npermp; i++)
		fwd_perm_clear((*permp) + i);
	حرر(*permp);
	*permp = عدم;
	*npermp = 0;
}

/*
 * Update the listen port for a dynamic remote forward, after
 * the actual 'newport' has been allocated. If 'newport' < 0 is
 * passed then they entry will be invalidated.
 */
فراغ
channel_update_permission(بنية ssh *ssh, صحيح idx, صحيح newport)
{
	بنية permission_مجموعه *pset = &ssh->chanctxt->local_perms;

	إذا (idx < 0 || (u_int)idx >= pset->رقم_permitted_user) {
		debug_f("index out of range: %d num_permitted_user %d",
		    idx, pset->رقم_permitted_user);
		أرجع;
	}
	debug("%s allowed port %d for forwarding to host %s port %d",
	    newport > 0 ? "Updating" : "Removing",
	    newport,
	    pset->permitted_user[idx].host_مقصد_connect,
	    pset->permitted_user[idx].پورت_مقصد_connect);
	إذا (newport <= 0)
		fwd_perm_clear(&pset->permitted_user[idx]);
	وإلا {
		pset->permitted_user[idx].listen_پورت =
		    (ssh->compat & SSH_BUG_DYNAMIC_RPORT) ? 0 : newport;
	}
}

/* Try to start non-blocking connect to next host in cctx list */
ساكن صحيح
connect_بعدی(بنية ssh *ssh, بنية channel_connect *cctx)
{
	صحيح sock, sock_is_شبکه, saved_errno;
	بنية sockaddr_un *sunaddr;
	حرف ntop[NI_MAXHOST];
	حرف strport[بیشینه(NI_MAXSERV, حجم(sunaddr->sun_مسیر))];

	لكل (; cctx->ai; cctx->ai = cctx->ai->ai_next) {
		sock_is_شبکه = 0;
		بدل (cctx->ai->ai_family) {
		حالة AF_UNIX:
			/* unix:pathname instead of host:port */
			sunaddr = (بنية sockaddr_un *)cctx->ai->ai_addr;
			strlcpy(ntop, "unix", حجم(ntop));
			strlcpy(strport, sunaddr->sun_مسیر, حجم(strport));
			اكسر;
		حالة AF_INET:
		حالة AF_INET6:
			إذا (getnameinfo(cctx->ai->ai_addr, cctx->ai->ai_addrlen,
			    ntop, حجم(ntop), strport, حجم(strport),
			    NI_NUMERICHOST|NI_NUMERICSERV) != 0) {
				error_f("getnameinfo failed");
				استمر;
			}
			sock_is_شبکه = 1;
			اكسر;
		افتراضي:
			استمر;
		}
		debug_f("start for host %.100s ([%.100s]:%s)",
		    cctx->host, ntop, strport);
		إذا ((sock = socket(cctx->ai->ai_family, cctx->ai->ai_socktype,
		    cctx->ai->ai_protocol)) == -1) {
			إذا (cctx->ai->ai_next == عدم)
				error("socket: %.100s", strerror(errno));
			وإلا
				verbose("socket: %.100s", strerror(errno));
			استمر;
		}
		إذا (مجموعه_nonblock(sock) == -1)
			fatal_f("set_nonblock(%d)", sock);
		إذا (sock_is_شبکه && ssh->chanctxt->want_tcp_keepalive)
			مجموعه_keepalive(sock); /* logs errors */
		إذا (connect(sock, cctx->ai->ai_addr,
		    cctx->ai->ai_addrlen) == -1 && errno != EINPROGRESS) {
			debug_f("host %.100s ([%.100s]:%s): %.100s",
			    cctx->host, ntop, strport, strerror(errno));
			saved_errno = errno;
			close(sock);
			errno = saved_errno;
			استمر;	/* fail -- try next */
		}
		إذا (cctx->ai->ai_family != AF_UNIX)
			مجموعه_nodelay(sock);
		debug_f("connect host %.100s ([%.100s]:%s) in progress, fd=%d",
		    cctx->host, ntop, strport, sock);
		cctx->ai = cctx->ai->ai_next;
		أرجع sock;
	}
	أرجع -1;
}

/*
 * Return connecting socket to remote host:port or local socket path,
 * passing back the failure reason if appropriate.
 */
ساكن صحيح
connect_مقصد_helper(بنية ssh *ssh, ثابت حرف *name, صحيح پورت, صحيح socktype,
    حرف *ctype, حرف *rname, بنية channel_connect *cctx,
    صحيح *reason, ثابت حرف **errmsg)
{
	بنية addrinfo hints;
	صحيح gaierr;
	صحيح sock = -1;
	حرف strport[NI_MAXSERV];

	إذا (پورت == پورت_STREAMLOCAL) {
		بنية sockaddr_un *sunaddr;
		بنية addrinfo *ai;

		إذا (طول_رشته(name) > حجم(sunaddr->sun_مسیر)) {
			error("%.100s: %.100s", name, strerror(ENAMETOOLONG));
			أرجع -1;
		}

		/*
		 * Fake up a struct addrinfo for AF_UNIX connections.
		 * free_connect_ctx() must check ai_family
		 * and use free() not freeaddrinfo() for AF_UNIX.
		 */
		ai = xcalloc(1, حجم(*ai) + حجم(*sunaddr));
		ai->ai_addr = (بنية sockaddr *)(ai + 1);
		ai->ai_addrlen = حجم(*sunaddr);
		ai->ai_family = AF_UNIX;
		ai->ai_socktype = socktype;
		ai->ai_protocol = PF_UNSPEC;
		sunaddr = (بنية sockaddr_un *)ai->ai_addr;
		sunaddr->sun_family = AF_UNIX;
		strlcpy(sunaddr->sun_مسیر, name, حجم(sunaddr->sun_مسیر));
		cctx->aitop = ai;
	} وإلا {
		memset(&hints, 0, حجم(hints));
		hints.ai_family = ssh->chanctxt->IPv4or6;
		hints.ai_socktype = socktype;
		snprintf(strport, حجم strport, "%d", پورت);
		إذا ((gaierr = getaddrinfo(name, strport, &hints, &cctx->aitop))
		    != 0) {
			إذا (errmsg != عدم)
				*errmsg = ssh_gai_strerror(gaierr);
			إذا (reason != عدم)
				*reason = SSH2_OPEN_CONNECT_FAILED;
			error("connect_to %.100s: unknown host (%s)", name,
			    ssh_gai_strerror(gaierr));
			أرجع -1;
		}
	}

	cctx->host = xstrdup(name);
	cctx->پورت = پورت;
	cctx->ai = cctx->aitop;

	إذا ((sock = connect_بعدی(ssh, cctx)) == -1) {
		error("connect to %.100s port %d failed: %s",
		    name, پورت, strerror(errno));
		أرجع -1;
	}

	أرجع sock;
}

/* Return CONNECTING channel to remote host:port or local socket path */
ساكن Channel *
connect_مقصد(بنية ssh *ssh, ثابت حرف *host, صحيح پورت,
    حرف *ctype, حرف *rname)
{
	بنية channel_connect cctx;
	Channel *c;
	صحيح sock;

	memset(&cctx, 0, حجم(cctx));
	sock = connect_مقصد_helper(ssh, host, پورت, SOCK_STREAM, ctype, rname,
	    &cctx, عدم, عدم);
	إذا (sock == -1) {
		free_connect_ctx(&cctx);
		أرجع عدم;
	}
	c = channel_new(ssh, ctype, SSH_CHANNEL_CONNECTING, sock, sock, -1,
	    CHAN_TCP_پنجره_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, rname, 1);
	c->host_پورت = پورت;
	c->مسیر = xstrdup(host);
	c->connect_ctx = xmalloc(حجم(cctx));
	کپی_حافظه(c->connect_ctx, &cctx, حجم(cctx));

	أرجع c;
}

/*
 * returns either the newly connected channel or the downstream channel
 * that needs to deal with this connection.
 */
Channel *
channel_connect_by_listen_آدرس(بنية ssh *ssh, ثابت حرف *listen_host,
    u_short listen_پورت, حرف *ctype, حرف *rname)
{
	بنية ssh_channels *sc = ssh->chanctxt;
	بنية permission_مجموعه *pset = &sc->local_perms;
	u_int i;
	بنية permission *perm;

	لكل (i = 0; i < pset->رقم_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		إذا (open_listen_تطابق_tcpip(perm,
		    listen_host, listen_پورت, 1)) {
			إذا (perm->downstream)
				أرجع perm->downstream;
			إذا (perm->پورت_مقصد_connect == 0)
				أرجع rdynamic_connect_prepare(ssh,
				    ctype, rname);
			أرجع connect_مقصد(ssh,
			    perm->host_مقصد_connect, perm->پورت_مقصد_connect,
			    ctype, rname);
		}
	}
	error("WARNING: Server requests forwarding for unknown listen_port %d",
	    listen_پورت);
	أرجع عدم;
}

Channel *
channel_connect_by_listen_مسیر(بنية ssh *ssh, ثابت حرف *مسیر,
    حرف *ctype, حرف *rname)
{
	بنية ssh_channels *sc = ssh->chanctxt;
	بنية permission_مجموعه *pset = &sc->local_perms;
	u_int i;
	بنية permission *perm;

	لكل (i = 0; i < pset->رقم_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		إذا (open_listen_تطابق_streamlocal(perm, مسیر)) {
			أرجع connect_مقصد(ssh,
			    perm->host_مقصد_connect, perm->پورت_مقصد_connect,
			    ctype, rname);
		}
	}
	error("WARNING: Server requests forwarding for unknown path %.100s",
	    مسیر);
	أرجع عدم;
}

/* Check if connecting to that port is permitted and connect. */
Channel *
channel_connect_مقصد_پورت(بنية ssh *ssh, ثابت حرف *host, u_short پورت,
    حرف *ctype, حرف *rname, صحيح *reason, ثابت حرف **errmsg)
{
	بنية ssh_channels *sc = ssh->chanctxt;
	بنية permission_مجموعه *pset = &sc->local_perms;
	بنية channel_connect cctx;
	Channel *c;
	u_int i, permit, permit_adm = 1;
	صحيح sock;
	بنية permission *perm;

	permit = pset->all_permitted;
	إذا (!permit) {
		لكل (i = 0; i < pset->رقم_permitted_user; i++) {
			perm = &pset->permitted_user[i];
			إذا (open_تطابق(perm, host, پورت)) {
				permit = 1;
				اكسر;
			}
		}
	}

	إذا (pset->رقم_permitted_admin > 0) {
		permit_adm = 0;
		لكل (i = 0; i < pset->رقم_permitted_admin; i++) {
			perm = &pset->permitted_admin[i];
			إذا (open_تطابق(perm, host, پورت)) {
				permit_adm = 1;
				اكسر;
			}
		}
	}

	إذا (!permit || !permit_adm) {
		logit("Received request from %.100s port %d to connect to "
		    "host %.100s port %d, but the request was denied.",
		    ssh_remote_ipaddr(ssh), ssh_remote_پورت(ssh), host, پورت);
		إذا (reason != عدم)
			*reason = SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED;
		أرجع عدم;
	}

	memset(&cctx, 0, حجم(cctx));
	sock = connect_مقصد_helper(ssh, host, پورت, SOCK_STREAM, ctype, rname,
	    &cctx, reason, errmsg);
	إذا (sock == -1) {
		free_connect_ctx(&cctx);
		أرجع عدم;
	}

	c = channel_new(ssh, ctype, SSH_CHANNEL_CONNECTING, sock, sock, -1,
	    CHAN_TCP_پنجره_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, rname, 1);
	c->host_پورت = پورت;
	c->مسیر = xstrdup(host);
	c->connect_ctx = xmalloc(حجم(cctx));
	کپی_حافظه(c->connect_ctx, &cctx, حجم(cctx));

	أرجع c;
}

/* Check if connecting to that path is permitted and connect. */
Channel *
channel_connect_مقصد_مسیر(بنية ssh *ssh, ثابت حرف *مسیر,
    حرف *ctype, حرف *rname)
{
	بنية ssh_channels *sc = ssh->chanctxt;
	بنية permission_مجموعه *pset = &sc->local_perms;
	u_int i, permit, permit_adm = 1;
	بنية permission *perm;

	permit = pset->all_permitted;
	إذا (!permit) {
		لكل (i = 0; i < pset->رقم_permitted_user; i++) {
			perm = &pset->permitted_user[i];
			إذا (open_تطابق(perm, مسیر, پورت_STREAMLOCAL)) {
				permit = 1;
				اكسر;
			}
		}
	}

	إذا (pset->رقم_permitted_admin > 0) {
		permit_adm = 0;
		لكل (i = 0; i < pset->رقم_permitted_admin; i++) {
			perm = &pset->permitted_admin[i];
			إذا (open_تطابق(perm, مسیر, پورت_STREAMLOCAL)) {
				permit_adm = 1;
				اكسر;
			}
		}
	}

	إذا (!permit || !permit_adm) {
		logit("Received request to connect to path %.100s, "
		    "but the request was denied.", مسیر);
		أرجع عدم;
	}
	أرجع connect_مقصد(ssh, مسیر, پورت_STREAMLOCAL, ctype, rname);
}

فراغ
channel_send_پنجره_changes(بنية ssh *ssh)
{
	بنية ssh_channels *sc = ssh->chanctxt;
	بنية winsize ws;
	صحيح r;
	u_int i;

	لكل (i = 0; i < sc->channels_alloc; i++) {
		إذا (sc->channels[i] == عدم || !sc->channels[i]->client_tty ||
		    sc->channels[i]->type != SSH_CHANNEL_OPEN)
			استمر;
		إذا (ioctl(sc->channels[i]->rfd, TIOCGWINSZ, &ws) == -1)
			استمر;
		channel_request_شروع(ssh, i, "window-change", 0);
		إذا ((r = sshpkt_put_u32(ssh, (u_int)ws.ws_ستون)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_ردیف)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_xpixel)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_ypixel)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "channel %u; send window-change", i);
	}
}

/* Return RDYNAMIC_OPEN channel: channel allows SOCKS, but is not connected */
ساكن Channel *
rdynamic_connect_prepare(بنية ssh *ssh, حرف *ctype, حرف *rname)
{
	Channel *c;
	صحيح r;

	c = channel_new(ssh, ctype, SSH_CHANNEL_RDYNAMIC_OPEN, -1, -1, -1,
	    CHAN_TCP_پنجره_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, rname, 1);
	c->host_پورت = 0;
	c->مسیر = عدم;

	/*
	 * We need to open the channel before we have a FD,
	 * so that we can get SOCKS header from peer.
	 */
	إذا ((r = sshpkt_شروع(ssh, SSH2_پیام_CHANNEL_OPEN_CONFIRMATION)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_پنجره)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0)
		fatal_fr(r, "channel %i; confirm", c->self);
	أرجع c;
}

/* Return CONNECTING socket to remote host:port or local socket path */
ساكن صحيح
rdynamic_connect_پایان(بنية ssh *ssh, Channel *c)
{
	بنية ssh_channels *sc = ssh->chanctxt;
	بنية permission_مجموعه *pset = &sc->local_perms;
	بنية permission *perm;
	بنية channel_connect cctx;
	u_int i, permit_adm = 1;
	صحيح sock;

	إذا (pset->رقم_permitted_admin > 0) {
		permit_adm = 0;
		لكل (i = 0; i < pset->رقم_permitted_admin; i++) {
			perm = &pset->permitted_admin[i];
			إذا (open_تطابق(perm, c->مسیر, c->host_پورت)) {
				permit_adm = 1;
				اكسر;
			}
		}
	}
	إذا (!permit_adm) {
		debug_f("requested forward not permitted");
		أرجع -1;
	}

	memset(&cctx, 0, حجم(cctx));
	sock = connect_مقصد_helper(ssh, c->مسیر, c->host_پورت, SOCK_STREAM, عدم,
	    عدم, &cctx, عدم, عدم);
	إذا (sock == -1)
		free_connect_ctx(&cctx);
	وإلا {
		/* similar to SSH_CHANNEL_CONNECTING but we've already sent the open */
		c->type = SSH_CHANNEL_RDYNAMIC_پایان;
		c->connect_ctx = xmalloc(حجم(cctx));
		کپی_حافظه(c->connect_ctx, &cctx, حجم(cctx));
		channel_ثبات_fds(ssh, c, sock, sock, -1, 0, 1, 0);
	}
	أرجع sock;
}

/* -- X11 forwarding */

/*
 * Creates an internet domain socket for listening for X11 connections.
 * Returns 0 and a suitable display number for the DISPLAY variable
 * stored in display_numberp , or -1 if an error occurs.
 */
صحيح
x11_create_display_inet(بنية ssh *ssh, صحيح x11_display_جابه_جایی,
    صحيح x11_use_localhost, صحيح single_connection,
    u_int *display_numberp, صحيح **chanids)
{
	Channel *nc = عدم;
	صحيح display_عدد, sock, پورت;
	بنية addrinfo hints, *ai, *aitop;
	حرف strport[NI_MAXSERV];
	صحيح gaierr, n, رقم_socks = 0, socks[رقم_SOCKS];

	إذا (chanids == عدم || x11_display_جابه_جایی < 0 ||
	    x11_display_جابه_جایی > UINT16_MAX - X11_پایه_پورت - MAX_DISPLAYS)
		أرجع -1;

	لكل (display_عدد = x11_display_جابه_جایی;
	    display_عدد < x11_display_جابه_جایی + MAX_DISPLAYS;
	    display_عدد++) {
		پورت = X11_پایه_پورت + display_عدد;
		memset(&hints, 0, حجم(hints));
		hints.ai_family = ssh->chanctxt->IPv4or6;
		hints.ai_flags = x11_use_localhost ? 0: AI_PASSIVE;
		hints.ai_socktype = SOCK_STREAM;
		snprintf(strport, حجم strport, "%d", پورت);
		إذا ((gaierr = getaddrinfo(عدم, strport,
		    &hints, &aitop)) != 0) {
			error("getaddrinfo: %.100s", ssh_gai_strerror(gaierr));
			أرجع -1;
		}
		لكل (ai = aitop; ai; ai = ai->ai_next) {
			إذا (ai->ai_family != AF_INET &&
			    ai->ai_family != AF_INET6)
				استمر;
			sock = socket(ai->ai_family, ai->ai_socktype,
			    ai->ai_protocol);
			إذا (sock == -1) {
				إذا ((errno != EINVAL) && (errno != EAFNOSUPPORT)
#اگر_تعریف_شده EPFNOSUPPORT
				    && (errno != EPFNOSUPPORT)
#پایان_اگر 
				    ) {
					error("socket: %.100s", strerror(errno));
					freeaddrinfo(aitop);
					أرجع -1;
				} وإلا {
					debug("x11_create_display_inet: Socket family %d not supported",
						 ai->ai_family);
					استمر;
				}
			}
			إذا (ai->ai_family == AF_INET6)
				sock_مجموعه_v6only(sock);
			إذا (x11_use_localhost)
				مجموعه_reuseaddr(sock);
			إذا (bind(sock, ai->ai_addr, ai->ai_addrlen) == -1) {
				debug2_f("bind port %d: %.100s", پورت,
				    strerror(errno));
				close(sock);
				لكل (n = 0; n < رقم_socks; n++)
					close(socks[n]);
				رقم_socks = 0;
				اكسر;
			}
			socks[رقم_socks++] = sock;
			إذا (رقم_socks == رقم_SOCKS)
				اكسر;
		}
		freeaddrinfo(aitop);
		إذا (رقم_socks > 0)
			اكسر;
	}
	إذا (display_عدد >= x11_display_جابه_جایی + MAX_DISPLAYS) {
		error("Failed to allocate internet-domain X11 display socket.");
		أرجع -1;
	}
	/* Start listening for connections on the socket. */
	لكل (n = 0; n < رقم_socks; n++) {
		sock = socks[n];
		إذا (listen(sock, SSH_LISTEN_BACKLOG) == -1) {
			error("listen: %.100s", strerror(errno));
			close(sock);
			أرجع -1;
		}
	}

	/* Allocate a channel for each socket. */
	*chanids = xcalloc(رقم_socks + 1, حجم(**chanids));
	لكل (n = 0; n < رقم_socks; n++) {
		sock = socks[n];
		nc = channel_new(ssh, "x11-listener",
		    SSH_CHANNEL_X11_LISTENER, sock, sock, -1,
		    CHAN_X11_پنجره_DEFAULT, CHAN_X11_PACKET_DEFAULT,
		    0, "X11 inet listener", 1);
		nc->single_connection = single_connection;
		(*chanids)[n] = nc->self;
	}
	(*chanids)[n] = -1;

	/* Return the display number for the DISPLAY environment variable. */
	*display_numberp = display_عدد;
	أرجع 0;
}

ساكن صحيح
connect_local_xsocket_مسیر(ثابت حرف *pathname)
{
	صحيح sock;
	بنية sockaddr_un addr;

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	إذا (sock == -1) {
		error("socket: %.100s", strerror(errno));
		أرجع -1;
	}
	memset(&addr, 0, حجم(addr));
	addr.sun_family = AF_UNIX;
	strlcpy(addr.sun_مسیر, pathname, حجم addr.sun_مسیر);
	إذا (connect(sock, (بنية sockaddr *)&addr, حجم(addr)) == 0)
		أرجع sock;
	close(sock);
	error("connect %.100s: %.100s", addr.sun_مسیر, strerror(errno));
	أرجع -1;
}

ساكن صحيح
connect_local_xsocket(u_int dnr)
{
	حرف buf[1024];
	snprintf(buf, حجم buf, مسیر_UNIX_X, dnr);
	أرجع connect_local_xsocket_مسیر(buf);
}

#اگر_تعریف_شده __APPLE__
ساكن صحيح
is_مسیر_مقصد_xsocket(ثابت حرف *display, حرف *مسیر, اندازه_t pathlen)
{
	بنية stat sbuf;

	إذا (strlcpy(مسیر, display, pathlen) >= pathlen) {
		error_f("display path too long");
		أرجع 0;
	}
	إذا (display[0] != '/')
		أرجع 0;
	إذا (stat(مسیر, &sbuf) == 0) {
		أرجع 1;
	} وإلا {
		حرف *dot = strrchr(مسیر, '.');
		إذا (dot != عدم) {
			*dot = '\0';
			إذا (stat(مسیر, &sbuf) == 0) {
				أرجع 1;
			}
		}
	}
	أرجع 0;
}
#پایان_اگر

صحيح
x11_connect_display(بنية ssh *ssh)
{
	u_int display_عدد;
	ثابت حرف *display;
	حرف buf[1024], *cp;
	بنية addrinfo hints, *ai, *aitop;
	حرف strport[NI_MAXSERV];
	صحيح gaierr, sock = 0;

	/* Try to open a socket for the local X server. */
	display = getenv("DISPLAY");
	إذا (!display) {
		error("DISPLAY not set.");
		أرجع -1;
	}
	/*
	 * Now we decode the value of the DISPLAY variable and make a
	 * connection to the real X server.
	 */

#اگر_تعریف_شده __APPLE__
	/* Check if display is a path to a socket (as set by launchd). */
	{
		حرف مسیر[PATH_MAX];

		إذا (is_مسیر_مقصد_xsocket(display, مسیر, حجم(مسیر))) {
			debug("x11_connect_display: $DISPLAY is launchd");

			/* Create a socket. */
			sock = connect_local_xsocket_مسیر(مسیر);
			إذا (sock < 0)
				أرجع -1;

			/* OK, we now have a connection to the display. */
			أرجع sock;
		}
	}
#پایان_اگر
	/*
	 * Check if it is a unix domain socket.  Unix domain displays are in
	 * one of the following formats: unix:d[.s], :d[.s], ::d[.s]
	 */
	إذا (مقایسه_رشته(display, "unix:", 5) == 0 ||
	    display[0] == ':') {
		/* Connect to the unix domain socket. */
		إذا (از_رشته_بخوان(strrchr(display, ':') + 1, "%u",
		    &display_عدد) != 1) {
			error("Could not parse display number from DISPLAY: "
			    "%.100s", display);
			أرجع -1;
		}
		/* Create a socket. */
		sock = connect_local_xsocket(display_عدد);
		إذا (sock < 0)
			أرجع -1;

		/* OK, we now have a connection to the display. */
		أرجع sock;
	}
	/*
	 * Connect to an inet socket.  The DISPLAY value is supposedly
	 * hostname:d[.s], where hostname may also be numeric IP address.
	 */
	strlcpy(buf, display, حجم(buf));
	cp = strchr(buf, ':');
	إذا (!cp) {
		error("Could not find ':' in DISPLAY: %.100s", display);
		أرجع -1;
	}
	*cp = 0;
	/*
	 * buf now contains the host name.  But first we parse the
	 * display number.
	 */
	إذا (از_رشته_بخوان(cp + 1, "%u", &display_عدد) != 1 ||
	    display_عدد > UINT16_MAX - X11_پایه_پورت) {
		error("Could not parse display number from DISPLAY: %.100s",
		    display);
		أرجع -1;
	}

	/* Look up the host address */
	memset(&hints, 0, حجم(hints));
	hints.ai_family = ssh->chanctxt->IPv4or6;
	hints.ai_socktype = SOCK_STREAM;
	snprintf(strport, حجم strport, "%u", X11_پایه_پورت + display_عدد);
	إذا ((gaierr = getaddrinfo(buf, strport, &hints, &aitop)) != 0) {
		error("%.100s: unknown host. (%s)", buf,
		ssh_gai_strerror(gaierr));
		أرجع -1;
	}
	لكل (ai = aitop; ai; ai = ai->ai_next) {
		/* Create a socket. */
		sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		إذا (sock == -1) {
			debug2("socket: %.100s", strerror(errno));
			استمر;
		}
		/* Connect it to the display. */
		إذا (connect(sock, ai->ai_addr, ai->ai_addrlen) == -1) {
			debug2("connect %.100s port %u: %.100s", buf,
			    X11_پایه_پورت + display_عدد, strerror(errno));
			close(sock);
			استمر;
		}
		/* Success */
		اكسر;
	}
	freeaddrinfo(aitop);
	إذا (!ai) {
		error("connect %.100s port %u: %.100s", buf,
		    X11_پایه_پورت + display_عدد, strerror(errno));
		أرجع -1;
	}
	مجموعه_nodelay(sock);
	أرجع sock;
}

/*
 * Requests forwarding of X11 connections, generates fake authentication
 * data, and enables authentication spoofing.
 * This should be called in the client only.
 */
فراغ
x11_request_forwarding_with_spoofing(بنية ssh *ssh, صحيح client_session_id,
    ثابت حرف *disp, ثابت حرف *proto, ثابت حرف *داده, صحيح want_پاسخ)
{
	بنية ssh_channels *sc = ssh->chanctxt;
	u_int داده_len = (u_int) طول_رشته(داده) / 2;
	u_int i, مقدار;
	ثابت حرف *cp;
	حرف *new_داده;
	صحيح r, screen_عدد;

	إذا (sc->x11_saved_display == عدم)
		sc->x11_saved_display = xstrdup(disp);
	وإلا إذا (strcmp(disp, sc->x11_saved_display) != 0) {
		error("x11_request_forwarding_with_spoofing: different "
		    "$DISPLAY already forwarded");
		أرجع;
	}

	cp = strchr(disp, ':');
	إذا (cp)
		cp = strchr(cp, '.');
	إذا (cp)
		screen_عدد = (u_int)strtonum(cp + 1, 0, 400, عدم);
	وإلا
		screen_عدد = 0;

	إذا (sc->x11_saved_proto == عدم) {
		/* Save protocol name. */
		sc->x11_saved_proto = xstrdup(proto);

		/* Extract real authentication data. */
		sc->x11_saved_داده = xmalloc(داده_len);
		لكل (i = 0; i < داده_len; i++) {
			إذا (از_رشته_بخوان(داده + 2 * i, "%2x", &مقدار) != 1) {
				fatal("x11_request_forwarding: bad "
				    "authentication data: %.100s", داده);
			}
			sc->x11_saved_داده[i] = مقدار;
		}
		sc->x11_saved_داده_len = داده_len;

		/* Generate fake data of the same length. */
		sc->x11_fake_داده = xmalloc(داده_len);
		arc4random_buf(sc->x11_fake_داده, داده_len);
		sc->x11_fake_داده_len = داده_len;
	}

	/* Convert the fake data into hex. */
	new_داده = tohex(sc->x11_fake_داده, داده_len);

	/* Send the request packet. */
	channel_request_شروع(ssh, client_session_id, "x11-req", want_پاسخ);
	إذا ((r = sshpkt_put_u8(ssh, 0)) != 0 || /* bool: single connection */
	    (r = sshpkt_put_cstring(ssh, proto)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, new_داده)) != 0 ||
	    (r = sshpkt_put_u32(ssh, screen_عدد)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send x11-req");
	حرر(new_داده);
}

/*
 * Returns whether an x11 channel was used recently (less than a second ago)
 */
صحيح
x11_channel_استفاده_شده_recently(بنية ssh *ssh) {
	u_int i;
	Channel *c;
	مزدوج lastused = 0;

	لكل (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		إذا (c == عدم || c->ctype == عدم || c->lastused == 0.0 ||
		    strcmp(c->ctype, "x11-connection") != 0)
			استمر;
		إذا (c->lastused > lastused)
			lastused = c->lastused;
	}
	أرجع lastused != 0.0 && monotime_double() <= lastused + 1.0;
}
